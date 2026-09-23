#!/usr/bin/env python3
"""Evaluate the post-freeze proposal-locked EviGate-Bind cascade.

The binding model is trained only on clean events outside each evaluated fold.
True network/provenance pairs are positives.  Deterministic same-tactic and
different-tactic hard negatives are selected by network-feature similarity.
No test corruption is used for fitting or threshold selection.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


TACTICS = (
    "collection",
    "command_and_control",
    "credential_access",
    "discovery",
    "exfiltration",
)
CORRUPTION_FAMILIES = (
    "process_deletion",
    "socket_type_deletion",
    "time_shift",
    "random_entity_deletion",
    "context_replacement",
)
DEFAULT_EXCLUSIONS = (
    "case_006e5fb8ae17aa011cbb",
    "case_012bac4ea9c61dfbe3ef",
)
FEATURE_MODES = (
    "full",
    "without_network_posterior",
    "network_only",
    "provenance_only",
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def network_features(network: dict[str, Any]) -> dict[str, float]:
    result = {
        key: float(value)
        for key, value in network.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    row_count = max(1.0, float(network.get("row_count", 0.0)))
    for protocol, count in network.get("protocol_counts", {}).items():
        result[f"protocol_fraction::{protocol}"] = float(count) / row_count
    for prefix, field in (
        ("destination_port", "top_destination_ports"),
        ("source_port", "top_source_ports"),
    ):
        for item in network.get(field, []):
            result[f"{prefix}_fraction::{item.get('port', '')}"] = (
                float(item.get("count", 0.0)) / row_count
            )
    return result


def provenance_features(package: dict[str, Any]) -> dict[str, float]:
    summary = package.get("provenance_summary", {})
    result: dict[str, float] = {}
    for key, value in summary.items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            result[f"summary::{key}"] = float(value)
    for kind, count in summary.get("entity_kind_counts", {}).items():
        result[f"entity_kind::{kind}"] = float(count)
    candidates = package.get("ranked_process_candidates", [])
    for candidate in candidates:
        rank = int(candidate.get("rank", 99))
        weight = 1.0 / max(1, rank)
        process = candidate.get("process", {})
        for field in ("name", "executable", "command_line"):
            value = str(process.get(field, "")).lower()
            for token in value.replace("/", " ").replace("-", " ").split():
                if token:
                    result[f"process::{field}::{token}"] = (
                        result.get(f"process::{field}::{token}", 0.0) + weight
                    )
        for anchor in candidate.get("anchors", []):
            kind = str(anchor.get("anchor_type", ""))
            result[f"anchor_type::{kind}"] = result.get(
                f"anchor_type::{kind}", 0.0
            ) + weight
            if kind == "operation":
                fact = str(anchor.get("fact", ""))
                if "=" in fact:
                    for operation in fact.split("=", 1)[1].split(","):
                        operation = operation.strip().lower()
                        if operation:
                            result[f"operation::{operation}"] = result.get(
                                f"operation::{operation}", 0.0
                            ) + weight
    return result


def make_tactic_model(seed: int):
    return make_pipeline(
        DictVectorizer(sparse=False),
        StandardScaler(),
        LogisticRegression(
            C=0.1,
            class_weight="balanced",
            max_iter=3000,
            random_state=seed,
        ),
    )


def probability_dicts(
    model: Any, rows: list[dict[str, float]]
) -> list[dict[str, float]]:
    probabilities = model.predict_proba(rows)
    classes = list(model.classes_)
    return [
        {
            tactic: (
                float(vector[classes.index(tactic)]) if tactic in classes else 0.0
            )
            for tactic in TACTICS
        }
        for vector in probabilities
    ]


def entropy(probabilities: dict[str, float]) -> float:
    values = np.asarray([max(0.0, probabilities[t]) for t in TACTICS], dtype=float)
    total = values.sum()
    if total <= 0:
        return 0.0
    values /= total
    return float(-np.sum(values * np.log(np.maximum(values, 1e-12))))


def posterior_margin(probabilities: dict[str, float]) -> float:
    ordered = sorted((float(probabilities[t]) for t in TACTICS), reverse=True)
    return ordered[0] - ordered[1]


def pair_features(
    network_probability: dict[str, float],
    provenance_probability: dict[str, float],
    network: dict[str, Any],
    package: dict[str, Any],
) -> dict[str, float]:
    left = np.asarray([network_probability[t] for t in TACTICS], dtype=float)
    right = np.asarray([provenance_probability[t] for t in TACTICS], dtype=float)
    left /= max(left.sum(), 1e-12)
    right /= max(right.sum(), 1e-12)
    midpoint = 0.5 * (left + right)
    js = 0.5 * np.sum(left * np.log(np.maximum(left / midpoint, 1e-12)))
    js += 0.5 * np.sum(right * np.log(np.maximum(right / midpoint, 1e-12)))
    result = {
        "affinity": float(np.sum(np.sqrt(left * right))),
        "js_divergence": float(js),
        "posterior_l1": float(np.sum(np.abs(left - right))),
        "top_tactic_agreement": float(int(np.argmax(left) == np.argmax(right))),
        "network_confidence": float(np.max(left)),
        "provenance_confidence": float(np.max(right)),
        "network_margin": posterior_margin(network_probability),
        "provenance_margin": posterior_margin(provenance_probability),
        "network_entropy": entropy(network_probability),
        "provenance_entropy": entropy(provenance_probability),
    }
    for index, tactic in enumerate(TACTICS):
        result[f"network_probability::{tactic}"] = float(left[index])
        result[f"provenance_probability::{tactic}"] = float(right[index])
        result[f"posterior_absdiff::{tactic}"] = float(abs(left[index] - right[index]))
        result[f"posterior_product::{tactic}"] = float(left[index] * right[index])

    summary = package.get("provenance_summary", {})
    network_numeric = {
        "log_rows": math.log1p(float(network.get("row_count", 0.0))),
        "log_bytes": math.log1p(float(network.get("total_bytes", 0.0))),
        "source_ip_hhi": float(network.get("source_ip_hhi", 0.0)),
        "destination_ip_hhi": float(network.get("destination_ip_hhi", 0.0)),
        "source_port_hhi": float(network.get("source_port_hhi", 0.0)),
        "destination_port_hhi": float(network.get("destination_port_hhi", 0.0)),
    }
    provenance_numeric = {
        "log_processes": math.log1p(float(summary.get("process_candidate_count", 0.0))),
        "log_entities": math.log1p(float(summary.get("total_candidate_entity_count", 0.0))),
        "log_relations": math.log1p(float(summary.get("relation_count", 0.0))),
        "top_ranker_score": float(summary.get("top_ranker_score", 0.0)),
        "ranker_margin": float(summary.get("ranker_score_margin", 0.0)),
        "top3_time": float(summary.get("top3_mean_time_proximity", 0.0)),
        "log_top3_sockets": math.log1p(float(summary.get("top3_socket_neighbors", 0.0))),
        "log_top3_files": math.log1p(float(summary.get("top3_file_neighbors", 0.0))),
    }
    result.update({f"network::{k}": v for k, v in network_numeric.items()})
    result.update({f"provenance::{k}": v for k, v in provenance_numeric.items()})
    for network_name, network_value in network_numeric.items():
        for provenance_name, provenance_value in provenance_numeric.items():
            result[f"cross::{network_name}::{provenance_name}"] = (
                network_value * provenance_value
            )
    return result


def filter_pair_features(
    features: dict[str, float], mode: str
) -> dict[str, float]:
    """Apply a prespecified BindGate view ablation.

    The full model is unchanged. ``without_network_posterior`` removes every
    feature computed from the network tactic posterior, including pairwise
    posterior agreement terms, while retaining identity-free raw network
    summaries. The single-view modes are negative controls: they retain only
    one view's posterior and summary features and therefore cannot directly
    measure cross-view compatibility.
    """
    if mode not in FEATURE_MODES:
        raise ValueError(f"unknown binding feature mode: {mode}")
    if mode == "full":
        return dict(features)

    network_posterior_scalars = {
        "network_confidence",
        "network_margin",
        "network_entropy",
    }
    provenance_posterior_scalars = {
        "provenance_confidence",
        "provenance_margin",
        "provenance_entropy",
    }
    pair_posterior_scalars = {
        "affinity",
        "js_divergence",
        "posterior_l1",
        "top_tactic_agreement",
    }

    def is_network_posterior(name: str) -> bool:
        return name in network_posterior_scalars or name.startswith(
            "network_probability::"
        )

    def is_provenance_posterior(name: str) -> bool:
        return name in provenance_posterior_scalars or name.startswith(
            "provenance_probability::"
        )

    def is_pair_posterior(name: str) -> bool:
        return name in pair_posterior_scalars or name.startswith(
            ("posterior_absdiff::", "posterior_product::")
        )

    if mode == "without_network_posterior":
        return {
            name: value
            for name, value in features.items()
            if not is_network_posterior(name) and not is_pair_posterior(name)
        }
    if mode == "network_only":
        return {
            name: value
            for name, value in features.items()
            if is_network_posterior(name) or name.startswith("network::")
        }
    return {
        name: value
        for name, value in features.items()
        if is_provenance_posterior(name) or name.startswith("provenance::")
    }


def vector_rows(rows: list[dict[str, float]]) -> tuple[DictVectorizer, np.ndarray]:
    vectorizer = DictVectorizer(sparse=False)
    return vectorizer, vectorizer.fit_transform(rows)


def normalized_network_matrix(packages: list[dict[str, Any]]) -> np.ndarray:
    _, matrix = vector_rows(
        [network_features(package["network_event"]) for package in packages]
    )
    means = matrix.mean(axis=0)
    scales = matrix.std(axis=0)
    scales[scales == 0] = 1.0
    return (matrix - means) / scales


def hard_negative_donors(
    packages: list[dict[str, Any]],
    labels: list[str],
    mode: str = "both",
) -> dict[int, list[int]]:
    if mode not in {"both", "same_tactic_only", "different_tactic_only"}:
        raise ValueError(f"unknown hard-negative mode: {mode}")
    matrix = normalized_network_matrix(packages)
    distances = np.sqrt(
        np.maximum(
            0.0,
            np.sum((matrix[:, None, :] - matrix[None, :, :]) ** 2, axis=2),
        )
    )
    result: dict[int, list[int]] = {}
    for index, label in enumerate(labels):
        selected: list[int] = []
        tactic_relations = {
            "both": (True, False),
            "same_tactic_only": (True,),
            "different_tactic_only": (False,),
        }[mode]
        for same_tactic in tactic_relations:
            candidates = [
                other
                for other, other_label in enumerate(labels)
                if other != index and ((other_label == label) == same_tactic)
            ]
            if candidates:
                selected.append(min(candidates, key=lambda other: (distances[index, other], other)))
        result[index] = selected
    return result


def make_binding_model(seed: int):
    return make_pipeline(
        StandardScaler(),
        LogisticRegression(
            C=0.5,
            class_weight="balanced",
            max_iter=3000,
            random_state=seed,
        ),
    )


def retention_threshold(scores: Iterable[float], target_retention: float) -> tuple[float, int]:
    values = sorted((float(value) for value in scores), reverse=True)
    if not values:
        raise ValueError("cannot select a threshold from no scores")
    if not 0.0 < target_retention <= 1.0:
        raise ValueError("target_retention must be in (0, 1]")
    count = max(1, math.ceil(target_retention * len(values)))
    return values[count - 1], count


def exact_count_threshold(scores: Iterable[float], target_count: int) -> float:
    values = sorted((float(value) for value in scores), reverse=True)
    if target_count <= 0:
        return math.inf
    if target_count > len(values):
        return -math.inf
    return values[target_count - 1]


def llm_attribute(output: dict[str, Any]) -> tuple[bool, str | None]:
    verification = output.get("verification", {})
    response = output.get("parsed_response")
    accepted = bool(
        isinstance(response, dict)
        and verification.get("contract_valid")
        and verification.get("verifier_decision") == "attribute"
    )
    return accepted, str(response.get("tactic")) if accepted else None


def summarize(rows: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    attributed = [row for row in rows if row[f"{prefix}_attributed"]]
    wrong = [row for row in attributed if not row[f"{prefix}_correct"]]
    return {
        "events": len(rows),
        "accepted": len(attributed),
        "coverage": len(attributed) / len(rows) if rows else None,
        "wrong_labels": len(wrong),
        "wrong_label_rate": len(wrong) / len(rows) if rows else None,
        "selective_risk": len(wrong) / len(attributed) if attributed else None,
        "rejection_rate": 1.0 - len(attributed) / len(rows) if rows else None,
    }


def family_summary(rows: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    return {
        family: summarize(
            [row for row in rows if row["corruption_family"] == family], prefix
        )
        for family in ("clean", *CORRUPTION_FAMILIES)
    }


def macro_wrong(summary: dict[str, Any]) -> float:
    return float(
        np.mean(
            [summary[family]["wrong_label_rate"] for family in CORRUPTION_FAMILIES]
        )
    )


def macro_wrong_without_time_shift(summary: dict[str, Any]) -> float:
    families = [family for family in CORRUPTION_FAMILIES if family != "time_shift"]
    return float(np.mean([summary[family]["wrong_label_rate"] for family in families]))


def quantile_interval(values: np.ndarray) -> list[float]:
    return [float(value) for value in np.quantile(values, [0.025, 0.975])]


def paired_bootstrap(
    rows: list[dict[str, Any]], seed: int, replicates: int
) -> dict[str, Any]:
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_case[row["case_id"]].append(row)
    case_ids = sorted(by_case)
    rng = np.random.default_rng(seed)
    samples = defaultdict(list)
    for _ in range(replicates):
        selected = rng.integers(0, len(case_ids), size=len(case_ids))
        sampled_rows = [row for index in selected for row in by_case[case_ids[index]]]
        cascade = family_summary(sampled_rows, "cascade")
        baseline = family_summary(sampled_rows, "matched_margin")
        samples["macro_wrong_reduction"].append(
            macro_wrong(baseline) - macro_wrong(cascade)
        )
        samples["context_wrong_reduction"].append(
            baseline["context_replacement"]["wrong_label_rate"]
            - cascade["context_replacement"]["wrong_label_rate"]
        )
        samples["clean_coverage_difference"].append(
            cascade["clean"]["coverage"] - baseline["clean"]["coverage"]
        )
        cascade_risk = cascade["clean"]["selective_risk"]
        baseline_risk = baseline["clean"]["selective_risk"]
        samples["clean_risk_reduction"].append(
            (baseline_risk or 0.0) - (cascade_risk or 0.0)
        )
    return {
        "unit": "event cluster",
        "events": len(case_ids),
        "replicates": replicates,
        "seed": seed,
        "estimands": {
            key: {
                "estimate": float(np.mean(values)),
                "interval_95": quantile_interval(np.asarray(values)),
                "probability_positive": float(np.mean(np.asarray(values) > 0.0)),
            }
            for key, values in samples.items()
        },
    }


def paired_bootstrap_methods(
    rows: list[dict[str, Any]],
    reference_prefix: str,
    candidate_prefix: str,
    seed: int,
    replicates: int,
) -> dict[str, Any]:
    """Compare a candidate with a reference over paired event clusters."""
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_case[row["case_id"]].append(row)
    case_ids = sorted(by_case)
    rng = np.random.default_rng(seed)
    samples = defaultdict(list)
    for _ in range(replicates):
        selected = rng.integers(0, len(case_ids), size=len(case_ids))
        sampled_rows = [row for index in selected for row in by_case[case_ids[index]]]
        reference = family_summary(sampled_rows, reference_prefix)
        candidate = family_summary(sampled_rows, candidate_prefix)
        samples["macro_wrong_reduction"].append(
            macro_wrong(reference) - macro_wrong(candidate)
        )
        samples["macro_wrong_without_time_shift_reduction"].append(
            macro_wrong_without_time_shift(reference)
            - macro_wrong_without_time_shift(candidate)
        )
        samples["context_wrong_reduction"].append(
            reference["context_replacement"]["wrong_label_rate"]
            - candidate["context_replacement"]["wrong_label_rate"]
        )
        samples["clean_risk_reduction"].append(
            (reference["clean"]["selective_risk"] or 0.0)
            - (candidate["clean"]["selective_risk"] or 0.0)
        )
    return {
        "unit": "event cluster",
        "events": len(case_ids),
        "replicates": replicates,
        "seed": seed,
        "reference": reference_prefix,
        "candidate": candidate_prefix,
        "estimands": {
            key: {
                "estimate": float(np.mean(values)),
                "interval_95": quantile_interval(np.asarray(values)),
                "probability_positive": float(np.mean(np.asarray(values) > 0.0)),
            }
            for key, values in samples.items()
        },
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--llm-outputs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target-binding-retention", type=float, default=0.9)
    parser.add_argument("--target-clean-coverage", type=float, default=0.67)
    parser.add_argument(
        "--require-positive-time-proximity",
        action="store_true",
        help="Require process evidence and top3_mean_time_proximity > 0 for both cascade and margin baseline.",
    )
    parser.add_argument("--bootstrap-replicates", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260916)
    parser.add_argument("--exclude-case", action="append", default=list(DEFAULT_EXCLUSIONS))
    parser.add_argument(
        "--hard-negative-mode",
        choices=("both", "same_tactic_only", "different_tactic_only"),
        default="both",
        help="Training hard-negative families; default preserves the frozen method.",
    )
    parser.add_argument(
        "--binding-feature-mode",
        choices=FEATURE_MODES,
        default="full",
        help="Prespecified cross-view feature ablation; default preserves the full BindGate.",
    )
    parser.add_argument(
        "--include-reviewer-ablations",
        action="store_true",
        help="Add a count-matched BindGate + margin + temporal comparator without LLM review.",
    )
    parser.add_argument(
        "--benchmark-inference",
        action="store_true",
        help="Record CPU wall-clock latency for the per-package compatibility scoring path.",
    )
    args = parser.parse_args()

    input_rows = load_jsonl(args.inputs)
    truth_rows = load_jsonl(args.truth)
    outputs = load_jsonl(args.llm_outputs)
    if len(input_rows) != len(truth_rows):
        raise ValueError("input and truth row counts differ")
    packages = {row["sample_id"]: row for row in input_rows}
    truths = {row["sample_id"]: row for row in truth_rows}
    llm_outputs = {
        row["sample_id"]: row for row in outputs if row.get("variant") == "contracted"
    }
    excluded = set(args.exclude_case)
    clean = [
        (package, truth)
        for package, truth in zip(input_rows, truth_rows)
        if truth["condition"] == "clean" and truth["case_id"] not in excluded
    ]
    if len(clean) != 51:
        raise ValueError(f"expected 51 retained clean events, found {len(clean)}")
    if len(llm_outputs) != len(input_rows):
        raise ValueError("expected one contracted LLM output per evidence package")

    binding_score: dict[str, float] = {}
    binding_threshold: dict[int, float] = {}
    margin_threshold: dict[int, float] = {}
    fold_audit: dict[str, Any] = {}
    synthetic_binding_rows: list[dict[str, Any]] = []
    binding_inference_seconds: list[float] = []

    for fold in (1, 2, 3):
        train = [row for row in clean if int(row[1]["test_fold"]) != fold]
        test = [row for row in clean if int(row[1]["test_fold"]) == fold]
        train_packages = [package for package, _ in train]
        train_labels = [truth["tactic"] for _, truth in train]

        network_model = make_tactic_model(args.seed)
        provenance_model = make_tactic_model(args.seed + 1)
        network_model.fit(
            [network_features(package["network_event"]) for package in train_packages],
            train_labels,
        )
        provenance_model.fit(
            [provenance_features(package) for package in train_packages], train_labels
        )
        train_network_probabilities = probability_dicts(
            network_model,
            [network_features(package["network_event"]) for package in train_packages],
        )
        train_provenance_probabilities = probability_dicts(
            provenance_model,
            [provenance_features(package) for package in train_packages],
        )
        donors = hard_negative_donors(
            train_packages, train_labels, mode=args.hard_negative_mode
        )

        pair_rows: list[dict[str, float]] = []
        pair_targets: list[int] = []
        pair_groups: list[str] = []
        positive_pair_indices: list[int] = []
        for index, ((package, truth), network_probability) in enumerate(
            zip(train, train_network_probabilities)
        ):
            positive_pair_indices.append(len(pair_rows))
            pair_rows.append(
                filter_pair_features(
                    pair_features(
                        network_probability,
                        train_provenance_probabilities[index],
                        package["network_event"],
                        package,
                    ),
                    args.binding_feature_mode,
                )
            )
            pair_targets.append(1)
            pair_groups.append(truth["case_id"])
            for donor in donors[index]:
                pair_rows.append(
                    filter_pair_features(
                        pair_features(
                            network_probability,
                            train_provenance_probabilities[donor],
                            package["network_event"],
                            train_packages[donor],
                        ),
                        args.binding_feature_mode,
                    )
                )
                pair_targets.append(0)
                pair_groups.append(truth["case_id"])

        vectorizer, pair_matrix = vector_rows(pair_rows)
        pair_targets_array = np.asarray(pair_targets, dtype=int)
        pair_groups_array = np.asarray(pair_groups)
        splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=args.seed)
        oof_probabilities = cross_val_predict(
            make_binding_model(args.seed),
            pair_matrix,
            pair_targets_array,
            groups=pair_groups_array,
            cv=splitter,
            method="predict_proba",
        )[:, 1]
        clean_oof_scores = [float(oof_probabilities[index]) for index in positive_pair_indices]
        fold_binding_threshold, binding_target_count = retention_threshold(
            clean_oof_scores, args.target_binding_retention
        )
        binding_threshold[fold] = fold_binding_threshold
        binding_model = make_binding_model(args.seed)
        binding_model.fit(pair_matrix, pair_targets_array)

        def score_pair(network_package: dict[str, Any], provenance_package: dict[str, Any]) -> float:
            network_probability = probability_dicts(
                network_model,
                [network_features(network_package["network_event"])],
            )[0]
            provenance_probability = probability_dicts(
                provenance_model, [provenance_features(provenance_package)]
            )[0]
            features = filter_pair_features(
                pair_features(
                    network_probability,
                    provenance_probability,
                    network_package["network_event"],
                    provenance_package,
                ),
                args.binding_feature_mode,
            )
            return float(binding_model.predict_proba(vectorizer.transform([features]))[0, 1])

        train_binding_scores: dict[str, float] = {
            truth["case_id"]: clean_oof_scores[index]
            for index, (_, truth) in enumerate(train)
        }
        eligible_margins: list[float] = []
        for package, truth in train:
            llm_ok, _ = llm_attribute(llm_outputs[truth["sample_id"]])
            if llm_ok and train_binding_scores[truth["case_id"]] >= fold_binding_threshold:
                eligible_margins.append(float(package["machine_proposal"]["margin"]))
        desired_joint_count = math.ceil(args.target_clean_coverage * len(train))
        fold_margin_threshold = exact_count_threshold(
            eligible_margins, desired_joint_count
        )
        margin_threshold[fold] = fold_margin_threshold

        fold_packages = [
            (package, truth)
            for package, truth in zip(input_rows, truth_rows)
            if int(truth["test_fold"]) == fold and truth["case_id"] not in excluded
        ]
        for package, truth in fold_packages:
            if args.benchmark_inference:
                inference_started = time.perf_counter()
                binding_score[truth["sample_id"]] = score_pair(package, package)
                binding_inference_seconds.append(time.perf_counter() - inference_started)
            else:
                binding_score[truth["sample_id"]] = score_pair(package, package)

        test_network_matrix = normalized_network_matrix(
            train_packages + [package for package, _ in test]
        )
        train_size = len(train_packages)
        for offset, (test_package, test_truth) in enumerate(test):
            test_index = train_size + offset
            distances = np.sqrt(
                np.sum((test_network_matrix[:train_size] - test_network_matrix[test_index]) ** 2, axis=1)
            )
            for same_tactic, audit_name in (
                (True, "same_tactic_replacement"),
                (False, "different_tactic_replacement"),
            ):
                candidates = [
                    index
                    for index, label in enumerate(train_labels)
                    if (label == test_truth["tactic"]) == same_tactic
                ]
                if not candidates:
                    continue
                donor = min(candidates, key=lambda index: (distances[index], index))
                score = score_pair(test_package, train_packages[donor])
                synthetic_binding_rows.append(
                    {
                        "case_id": test_truth["case_id"],
                        "test_fold": fold,
                        "audit": audit_name,
                        "donor_case_id": train[donor][1]["case_id"],
                        "binding_score": score,
                        "binding_threshold": fold_binding_threshold,
                        "binding_pass": score >= fold_binding_threshold,
                    }
                )

        fold_audit[str(fold)] = {
            "outer_training_clean_events": len(train),
            "outer_test_clean_events": len(test),
            "binding_training_pairs": len(pair_rows),
            "binding_positive_pairs": int(sum(pair_targets_array)),
            "binding_negative_pairs": int(len(pair_targets_array) - sum(pair_targets_array)),
            "binding_feature_mode": args.binding_feature_mode,
            "binding_feature_count": int(pair_matrix.shape[1]),
            "binding_target_retention": args.target_binding_retention,
            "binding_target_count": binding_target_count,
            "binding_threshold": fold_binding_threshold,
            "binding_oof_clean_retention": float(
                np.mean(np.asarray(clean_oof_scores) >= fold_binding_threshold)
            ),
            "joint_clean_target_count": desired_joint_count,
            "eligible_training_events": len(eligible_margins),
            "margin_threshold": fold_margin_threshold,
            "joint_target_attainable": len(eligible_margins) >= desired_joint_count,
        }

    output_rows: list[dict[str, Any]] = []
    for package, truth in zip(input_rows, truth_rows):
        if truth["case_id"] in excluded:
            continue
        sample_id = truth["sample_id"]
        fold = int(truth["test_fold"])
        llm_ok, prediction = llm_attribute(llm_outputs[sample_id])
        bind_score = binding_score[sample_id]
        bind_pass = bind_score >= binding_threshold[fold]
        margin_pass = float(package["machine_proposal"]["margin"]) >= margin_threshold[fold]
        summary = package.get("provenance_summary", {})
        process_present = int(summary.get("process_candidate_count", 0)) > 0
        temporal_pass = bool(
            process_present
            and (
                not args.require_positive_time_proximity
                or float(summary.get("top3_mean_time_proximity", 0.0)) > 0.0
            )
        )
        cascade_attributed = bool(llm_ok and bind_pass and margin_pass and temporal_pass)
        output_rows.append(
            {
                "sample_id": sample_id,
                "case_id": truth["case_id"],
                "test_fold": fold,
                "condition": truth["condition"],
                "corruption_family": truth.get("corruption_family") or "clean",
                "tactic": truth["tactic"],
                "machine_proposal": package["machine_proposal"]["tactic"],
                "proposal_margin": float(package["machine_proposal"]["margin"]),
                "llm_attributed": llm_ok,
                "llm_prediction": prediction,
                "llm_correct": bool(llm_ok and prediction == truth["tactic"]),
                "binding_score": bind_score,
                "binding_threshold": binding_threshold[fold],
                "binding_pass": bind_pass,
                "margin_threshold": margin_threshold[fold],
                "margin_pass": margin_pass,
                "temporal_admissibility_pass": temporal_pass,
                "cascade_attributed": cascade_attributed,
                "cascade_prediction": prediction if cascade_attributed else None,
                "cascade_correct": bool(
                    cascade_attributed and prediction == truth["tactic"]
                ),
            }
        )

    clean_rows = [row for row in output_rows if row["corruption_family"] == "clean"]
    matched_thresholds: dict[int, float] = {}
    for fold in (1, 2, 3):
        fold_rows = [row for row in clean_rows if row["test_fold"] == fold]
        target_count = sum(row["cascade_attributed"] for row in fold_rows)
        matched_thresholds[fold] = exact_count_threshold(
            [row["proposal_margin"] for row in fold_rows], target_count
        )
    for row in output_rows:
        package = packages[row["sample_id"]]
        summary = package.get("provenance_summary", {})
        process_present = int(summary.get("process_candidate_count", 0)) > 0
        temporal_pass = bool(
            process_present
            and (
                not args.require_positive_time_proximity
                or float(summary.get("top3_mean_time_proximity", 0.0)) > 0.0
            )
        )
        accepted = bool(
            temporal_pass
            and row["proposal_margin"] >= matched_thresholds[row["test_fold"]]
        )
        prediction = row["machine_proposal"] if accepted else None
        row["matched_margin_attributed"] = accepted
        row["matched_margin_prediction"] = prediction
        row["matched_margin_correct"] = bool(accepted and prediction == row["tactic"])

    no_llm_thresholds: dict[int, float] = {}
    if args.include_reviewer_ablations:
        for fold in (1, 2, 3):
            fold_rows = [row for row in clean_rows if row["test_fold"] == fold]
            target_count = sum(row["cascade_attributed"] for row in fold_rows)
            eligible = [
                row
                for row in fold_rows
                if row["binding_pass"] and row["temporal_admissibility_pass"]
            ]
            no_llm_thresholds[fold] = exact_count_threshold(
                [row["proposal_margin"] for row in eligible], target_count
            )
        for row in output_rows:
            accepted = bool(
                row["binding_pass"]
                and row["temporal_admissibility_pass"]
                and row["proposal_margin"] >= no_llm_thresholds[row["test_fold"]]
            )
            prediction = row["machine_proposal"] if accepted else None
            row["no_llm_bind_attributed"] = accepted
            row["no_llm_bind_prediction"] = prediction
            row["no_llm_bind_correct"] = bool(
                accepted and prediction == row["tactic"]
            )

    summaries = {
        "proposal_locked_llm": family_summary(output_rows, "llm"),
        "cascade": family_summary(output_rows, "cascade"),
        "matched_margin": family_summary(output_rows, "matched_margin"),
    }
    if args.include_reviewer_ablations:
        summaries["no_llm_bind"] = family_summary(output_rows, "no_llm_bind")
    aggregate = {
        method: {
            "clean": summary["clean"],
            "corruption_macro_wrong_label_rate": macro_wrong(summary),
            "context_replacement": summary["context_replacement"],
            "all_process_deletion": summary["process_deletion"],
        }
        for method, summary in summaries.items()
    }
    success = {
        "clean_coverage_at_least_34_of_51": summaries["cascade"]["clean"]["accepted"] >= 34,
        "clean_risk_at_most_0_333": (
            summaries["cascade"]["clean"]["selective_risk"] is not None
            and summaries["cascade"]["clean"]["selective_risk"] <= 0.333
        ),
        "corruption_macro_wrong_at_most_0_200": macro_wrong(summaries["cascade"]) <= 0.2,
        "context_wrong_below_0_300": (
            summaries["cascade"]["context_replacement"]["wrong_label_rate"] < 0.3
        ),
        "zero_process_deletion_wrong": (
            summaries["cascade"]["process_deletion"]["wrong_label_rate"] == 0.0
        ),
    }
    synthetic_summary = {
        audit: {
            "events": len(rows),
            "binding_pass_rate": float(np.mean([row["binding_pass"] for row in rows])),
            "context_alarm_rate": float(np.mean([not row["binding_pass"] for row in rows])),
        }
        for audit, rows in (
            (name, [row for row in synthetic_binding_rows if row["audit"] == name])
            for name in ("same_tactic_replacement", "different_tactic_replacement")
        )
    }
    bootstrap = paired_bootstrap(output_rows, args.seed, args.bootstrap_replicates)
    summary = {
        "study": "EviGate-Bind proposal-locked post-freeze repair",
        "status": "post-freeze exploratory; test set previously inspected under v6",
        "events": len(clean),
        "packages": len(output_rows),
        "method": {
            "binding_model": "balanced logistic regression over cross-view posterior and identity-free summary interactions",
            "binding_feature_mode": args.binding_feature_mode,
            "hard_negatives": {
                "both": "nearest same-tactic and nearest different-tactic provenance donors from outer training events",
                "same_tactic_only": "nearest same-tactic provenance donor from outer training events",
                "different_tactic_only": "nearest different-tactic provenance donor from outer training events",
            }[args.hard_negative_mode],
            "binding_threshold": "group-cross-fitted clean-pair scores only",
            "margin_threshold": "outer-training clean events eligible after LLM certificate and binding gate",
            "target_binding_retention": args.target_binding_retention,
            "target_clean_coverage": args.target_clean_coverage,
            "positive_time_proximity_required": args.require_positive_time_proximity,
            "test_corruptions_used_for_fitting": False,
            "exclusions": sorted(excluded),
        },
        "input_integrity": {
            "inputs_sha256": sha256_file(args.inputs),
            "truth_sha256": sha256_file(args.truth),
            "llm_outputs_sha256": sha256_file(args.llm_outputs),
        },
        "fold_audit": fold_audit,
        "matched_margin_thresholds": matched_thresholds,
        "family_results": summaries,
        "aggregate": aggregate,
        "synthetic_binding_audit": synthetic_summary,
        "success_targets": success,
        "all_success_targets_met": all(success.values()),
        "bootstrap_vs_matched_margin": bootstrap,
        "limitations": [
            "The method was designed after inspection of the v6 test failure and is exploratory.",
            "Hard-negative pair synthesis tests compatibility rather than packet-to-process causality.",
            "The same-tactic replacement audit has no recomputed Stage C counterfactual proposal.",
            "All events come from one scripted campaign.",
        ],
    }
    if args.benchmark_inference:
        timing = np.asarray(binding_inference_seconds, dtype=float)
        summary["cpu_binding_path_timing"] = {
            "measurements": len(timing),
            "mean_milliseconds": float(np.mean(timing) * 1000.0),
            "median_milliseconds": float(np.median(timing) * 1000.0),
            "p95_milliseconds": float(np.quantile(timing, 0.95) * 1000.0),
            "maximum_milliseconds": float(np.max(timing) * 1000.0),
            "scope": (
                "network/provenance summary vectorization, two tactic-model probability calls, "
                "pair-feature construction, and one BindGate predict_proba call"
            ),
            "device_note": (
                "CPU wall clock on the experiment workstation; not an embedded-device benchmark"
            ),
        }
    if args.include_reviewer_ablations:
        summary["reviewer_ablations"] = {
            "hard_negative_mode": args.hard_negative_mode,
            "no_llm_count_matched_thresholds": no_llm_thresholds,
            "no_llm_bind_family_results": summaries["no_llm_bind"],
            "no_llm_bind_aggregate": aggregate["no_llm_bind"],
            "macro_wrong_without_time_shift": {
                method: macro_wrong_without_time_shift(method_summary)
                for method, method_summary in summaries.items()
            },
            "bootstrap_cascade_vs_no_llm_bind": paired_bootstrap_methods(
                output_rows,
                "no_llm_bind",
                "cascade",
                args.seed + 101,
                args.bootstrap_replicates,
            ),
        }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "evigate_bindgate.per_case.csv", output_rows)
    write_csv(args.output_dir / "evigate_bindgate.synthetic_binding.csv", synthetic_binding_rows)
    (args.output_dir / "evigate_bindgate.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"aggregate": aggregate, "success_targets": success}, indent=2))


if __name__ == "__main__":
    main()
