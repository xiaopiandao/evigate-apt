#!/usr/bin/env python3
"""Evaluate a post-freeze cross-view context-binding gate for EviGate-LLM.

The gate is deliberately lightweight and corruption-blind.  For each outer
fold, a network-only tactic model is trained on the other clean events.  Its
posterior is compared with the provenance-derived machine proposal through
Bhattacharyya affinity.  The threshold is selected from leave-one-event-out
scores on the outer training partition to retain at least a declared fraction
of clean pairs.  No corrupted package is used for fitting or thresholding.

This experiment was designed after inspecting the frozen EviGate-LLM failure
on context replacement and must therefore be reported as exploratory.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
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


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def network_features(network: dict[str, Any]) -> dict[str, float]:
    """Return identity-free, fixed-rule network summary features."""
    features = {
        key: float(value)
        for key, value in network.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    row_count = max(1.0, float(network["row_count"]))
    for protocol, count in network.get("protocol_counts", {}).items():
        features[f"protocol_fraction::{protocol}"] = float(count) / row_count
    for prefix, field in (
        ("destination_port", "top_destination_ports"),
        ("source_port", "top_source_ports"),
    ):
        for item in network.get(field, []):
            features[f"{prefix}_fraction::{item['port']}"] = (
                float(item["count"]) / row_count
            )
    return features


def make_network_model(seed: int):
    return make_pipeline(
        DictVectorizer(sparse=False),
        StandardScaler(),
        LogisticRegression(
            C=0.1,
            class_weight="balanced",
            max_iter=2000,
            random_state=seed,
        ),
    )


def probability_dict(model: Any, feature_rows: list[dict[str, float]]) -> list[dict[str, float]]:
    matrix = model.predict_proba(feature_rows)
    model_classes = list(model.classes_)
    return [
        {
            label: (
                float(probability[model_classes.index(label)])
                if label in model_classes
                else 0.0
            )
            for label in TACTICS
        }
        for probability in matrix
    ]


def bhattacharyya_affinity(
    left: dict[str, float], right: dict[str, float]
) -> float:
    return float(
        sum(
            math.sqrt(max(0.0, float(left[label])) * max(0.0, float(right[label])))
            for label in TACTICS
        )
    )


def retention_threshold(scores: Iterable[float], target_retention: float) -> tuple[float, int]:
    values = sorted((float(score) for score in scores), reverse=True)
    if not values:
        raise ValueError("Cannot select a threshold from an empty score list")
    if not 0.0 < target_retention <= 1.0:
        raise ValueError("target_retention must be in (0, 1]")
    target_count = max(1, math.ceil(target_retention * len(values)))
    return values[target_count - 1], target_count


def parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    return value.strip().lower() == "true"


def summarize_family(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"events": 0}
    base_attributed = [row for row in rows if row["base_attributed"]]
    combined_attributed = [row for row in rows if row["combined_attributed"]]
    base_wrong = [row for row in base_attributed if not row["base_correct"]]
    combined_wrong = [row for row in combined_attributed if not row["combined_correct"]]
    return {
        "events": len(rows),
        "binding_pass_rate": float(np.mean([row["binding_pass"] for row in rows])),
        "context_alarm_rate": float(np.mean([not row["binding_pass"] for row in rows])),
        "base": {
            "coverage": len(base_attributed) / len(rows),
            "wrong_label_rate": len(base_wrong) / len(rows),
            "selective_risk": (
                len(base_wrong) / len(base_attributed) if base_attributed else None
            ),
        },
        "combined": {
            "coverage": len(combined_attributed) / len(rows),
            "wrong_label_rate": len(combined_wrong) / len(rows),
            "selective_risk": (
                len(combined_wrong) / len(combined_attributed)
                if combined_attributed
                else None
            ),
        },
    }


def quantile_interval(values: np.ndarray) -> list[float]:
    return [float(value) for value in np.quantile(values, [0.025, 0.975])]


def paired_bootstrap(
    rows: list[dict[str, Any]], seed: int, replicates: int
) -> dict[str, Any]:
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_case[row["case_id"]].append(row)
    case_ids = sorted(by_case)
    event_vectors: list[dict[str, float]] = []
    for case_id in case_ids:
        event_rows = by_case[case_id]
        clean = next(row for row in event_rows if row["corruption_family"] == "clean")
        corruptions = {
            row["corruption_family"]: row
            for row in event_rows
            if row["corruption_family"] != "clean"
        }
        if set(corruptions) != set(CORRUPTION_FAMILIES):
            raise ValueError(f"Incomplete corruption families for {case_id}")
        event_vectors.append(
            {
                "clean_coverage_reduction": float(clean["base_attributed"])
                - float(clean["combined_attributed"]),
                "macro_wrong_reduction": float(
                    np.mean(
                        [
                            float(row["base_attributed"] and not row["base_correct"])
                            - float(
                                row["combined_attributed"]
                                and not row["combined_correct"]
                            )
                            for row in corruptions.values()
                        ]
                    )
                ),
                "context_wrong_reduction": float(
                    corruptions["context_replacement"]["base_attributed"]
                    and not corruptions["context_replacement"]["base_correct"]
                )
                - float(
                    corruptions["context_replacement"]["combined_attributed"]
                    and not corruptions["context_replacement"]["combined_correct"]
                ),
                "context_alarm_lift_over_clean": float(
                    not corruptions["context_replacement"]["binding_pass"]
                )
                - float(not clean["binding_pass"]),
            }
        )
    matrix = np.asarray(
        [[vector[key] for key in event_vectors[0]] for vector in event_vectors],
        dtype=float,
    )
    keys = list(event_vectors[0])
    rng = np.random.default_rng(seed)
    samples = np.empty((replicates, len(keys)), dtype=float)
    for index in range(replicates):
        sampled = rng.integers(0, len(case_ids), size=len(case_ids))
        samples[index] = matrix[sampled].mean(axis=0)
    return {
        "unit": "event cluster",
        "events": len(case_ids),
        "replicates": replicates,
        "seed": seed,
        "estimands": {
            key: {
                "estimate": float(matrix[:, column].mean()),
                "interval_95": quantile_interval(samples[:, column]),
                "probability_positive": float(np.mean(samples[:, column] > 0.0)),
            }
            for column, key in enumerate(keys)
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--llm-per-case", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target-clean-retention", type=float, default=0.8)
    parser.add_argument("--seed", type=int, default=20260916)
    parser.add_argument("--bootstrap-replicates", type=int, default=10000)
    parser.add_argument(
        "--exclude-case",
        action="append",
        default=list(DEFAULT_EXCLUSIONS),
    )
    args = parser.parse_args()

    inputs = load_jsonl(args.inputs)
    truth = load_jsonl(args.truth)
    if len(inputs) != len(truth):
        raise ValueError("Input and truth row counts differ")
    package_by_sample = {row["sample_id"]: row for row in inputs}
    truth_by_sample = {row["sample_id"]: row for row in truth}
    excluded = set(args.exclude_case)
    clean_rows = [
        (package, target)
        for package, target in zip(inputs, truth)
        if target["condition"] == "clean" and target["case_id"] not in excluded
    ]
    if len(clean_rows) != 51:
        raise ValueError(f"Expected 51 retained clean events, found {len(clean_rows)}")

    score_by_sample: dict[str, float] = {}
    threshold_by_fold: dict[int, float] = {}
    threshold_audit: dict[str, Any] = {}
    network_correct: list[bool] = []

    for fold in (1, 2, 3):
        outer_train = [row for row in clean_rows if int(row[1]["test_fold"]) != fold]
        outer_test = [row for row in clean_rows if int(row[1]["test_fold"]) == fold]
        training_pair_scores: list[float] = []

        for held_package, held_truth in outer_train:
            loo_train = [
                row
                for row in outer_train
                if row[1]["case_id"] != held_truth["case_id"]
            ]
            model = make_network_model(args.seed)
            model.fit(
                [network_features(package["network_event"]) for package, _ in loo_train],
                [target["tactic"] for _, target in loo_train],
            )
            network_probability = probability_dict(
                model, [network_features(held_package["network_event"])]
            )[0]
            training_pair_scores.append(
                bhattacharyya_affinity(
                    network_probability,
                    held_package["machine_proposal"]["probabilities"],
                )
            )

        threshold, target_count = retention_threshold(
            training_pair_scores, args.target_clean_retention
        )
        threshold_by_fold[fold] = threshold
        threshold_audit[str(fold)] = {
            "outer_training_events": len(outer_train),
            "leave_one_event_out_scores": len(training_pair_scores),
            "target_clean_retention": args.target_clean_retention,
            "target_accepted": target_count,
            "threshold": threshold,
            "realized_training_retention": float(
                np.mean(np.asarray(training_pair_scores) >= threshold)
            ),
        }

        outer_model = make_network_model(args.seed)
        outer_model.fit(
            [network_features(package["network_event"]) for package, _ in outer_train],
            [target["tactic"] for _, target in outer_train],
        )
        test_network_probabilities = probability_dict(
            outer_model,
            [network_features(package["network_event"]) for package, _ in outer_test],
        )
        for (_, target), probability in zip(outer_test, test_network_probabilities):
            network_correct.append(max(probability, key=probability.get) == target["tactic"])

        fold_packages = [
            (package, target)
            for package, target in zip(inputs, truth)
            if int(target["test_fold"]) == fold and target["case_id"] not in excluded
        ]
        fold_probabilities = probability_dict(
            outer_model,
            [network_features(package["network_event"]) for package, _ in fold_packages],
        )
        for (package, target), network_probability in zip(
            fold_packages, fold_probabilities
        ):
            score_by_sample[target["sample_id"]] = bhattacharyya_affinity(
                network_probability,
                package["machine_proposal"]["probabilities"],
            )

    llm_rows = [
        row
        for row in load_csv(args.llm_per_case)
        if row["method"] == "evigate_llm" and row["case_id"] not in excluded
    ]
    if len(llm_rows) != 306:
        raise ValueError(f"Expected 306 EviGate-LLM rows, found {len(llm_rows)}")

    output_rows: list[dict[str, Any]] = []
    for row in llm_rows:
        sample_id = row["sample_id"]
        package = package_by_sample[sample_id]
        target = truth_by_sample[sample_id]
        fold = int(row["test_fold"])
        score = score_by_sample[sample_id]
        binding_pass = score >= threshold_by_fold[fold]
        base_attributed = parse_bool(row["attributed"])
        base_correct = parse_bool(row["correct"])
        combined_attributed = base_attributed and binding_pass
        combined_correct = combined_attributed and base_correct
        output_rows.append(
            {
                "sample_id": sample_id,
                "case_id": row["case_id"],
                "test_fold": fold,
                "condition": row["condition"],
                "corruption_family": row["corruption_family"],
                "tactic": row["tactic"],
                "machine_proposal": package["machine_proposal"]["tactic"],
                "base_prediction": row["prediction"],
                "base_attributed": base_attributed,
                "base_correct": base_correct,
                "binding_score": score,
                "binding_threshold": threshold_by_fold[fold],
                "binding_pass": binding_pass,
                "context_alarm": not binding_pass,
                "combined_prediction": row["prediction"] if combined_attributed else None,
                "combined_attributed": combined_attributed,
                "combined_correct": combined_correct,
            }
        )

    by_family = {
        family: summarize_family(
            [row for row in output_rows if row["corruption_family"] == family]
        )
        for family in ("clean", *CORRUPTION_FAMILIES)
    }
    corruption_macro_base = float(
        np.mean([by_family[family]["base"]["wrong_label_rate"] for family in CORRUPTION_FAMILIES])
    )
    corruption_macro_combined = float(
        np.mean(
            [
                by_family[family]["combined"]["wrong_label_rate"]
                for family in CORRUPTION_FAMILIES
            ]
        )
    )
    bootstrap = paired_bootstrap(
        output_rows, seed=args.seed, replicates=args.bootstrap_replicates
    )
    summary = {
        "study": "EviGate-LLM exploratory cross-view context binding",
        "status": "post-freeze exploratory; designed after observing confirmatory context-replacement failure",
        "method": {
            "network_model": "identity-free multinomial logistic regression, C=0.1, balanced classes",
            "compatibility": "Bhattacharyya affinity between network-only and provenance-proposal tactic posteriors",
            "thresholding": "leave-one-event-out outer-training clean pairs only",
            "corruptions_used_for_fitting_or_thresholding": False,
            "target_clean_retention": args.target_clean_retention,
            "exclusions": sorted(excluded),
        },
        "input_integrity": {
            "inputs_sha256": sha256_file(args.inputs),
            "truth_sha256": sha256_file(args.truth),
            "llm_per_case_sha256": sha256_file(args.llm_per_case),
        },
        "events": len(clean_rows),
        "packages": len(output_rows),
        "network_only_outer_fold_accuracy": float(np.mean(network_correct)),
        "threshold_audit": threshold_audit,
        "family_results": by_family,
        "aggregate": {
            "base_corruption_macro_wrong_label_rate": corruption_macro_base,
            "combined_corruption_macro_wrong_label_rate": corruption_macro_combined,
            "corruption_macro_wrong_label_reduction": (
                corruption_macro_base - corruption_macro_combined
            ),
            "base_clean_coverage": by_family["clean"]["base"]["coverage"],
            "combined_clean_coverage": by_family["clean"]["combined"]["coverage"],
            "clean_coverage_reduction": (
                by_family["clean"]["base"]["coverage"]
                - by_family["clean"]["combined"]["coverage"]
            ),
            "base_clean_selective_risk": by_family["clean"]["base"]["selective_risk"],
            "combined_clean_selective_risk": by_family["clean"]["combined"]["selective_risk"],
        },
        "bootstrap": bootstrap,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    per_case_path = args.output_dir / "evigate_context_binding.per_case.csv"
    summary_path = args.output_dir / "evigate_context_binding.summary.json"
    with per_case_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output_rows[0]))
        writer.writeheader()
        writer.writerows(output_rows)
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary["aggregate"], indent=2, sort_keys=True))
    print(f"Wrote {summary_path}")
    print(f"Wrote {per_case_path}")


if __name__ == "__main__":
    main()
