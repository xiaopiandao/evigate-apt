#!/usr/bin/env python3
"""Evaluate EviGate-APT Stage C with event-level, leakage-controlled splits.

The script trains one tactic classifier per outer fold and compares two
selective scores over the same predictions:

    * maximum softmax probability (the pre-specified frozen primary baseline), and
* an evidence-sufficiency controller trained from leave-one-event-out clean
  predictions and synthetic evidence corruptions.

Ground truth is read only from the physically separate truth sidecar.  The
inference representation never includes case labels, malicious PIDs, raw PID
numbers, raw addresses, or raw port identities.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import math
import re
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, median
from typing import Any, Iterable

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from run_stage_b_typed_ranker import (
    entity_features,
    extract_case,
    feature_names,
    fit_ranker,
    load_jsonl,
    process_contexts,
    sha256_file,
)


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
NETWORK_FEATURE_NAMES = (
    "log_row_count",
    "log_total_bytes",
    "trigger_offset_fraction",
    "log_unique_source_ips",
    "log_unique_destination_ips",
    "log_unique_source_ports",
    "log_unique_destination_ports",
    "source_ip_hhi",
    "destination_ip_hhi",
    "source_port_hhi",
    "destination_port_hhi",
    "tcp_fraction",
    "udp_fraction",
    "icmp_fraction",
    "arp_fraction",
)
PROVENANCE_ENTITY_FEATURE_NAMES = tuple(
    name for name in feature_names() if not name.startswith("alert_")
)
PROVENANCE_SUMMARY_NAMES = (
    "log_process_candidates",
    "log_total_entities",
    "log_relations",
    "process_fraction",
    "file_fraction",
    "socket_fraction",
    "top_rank_score",
    "rank_score_margin",
    "rank_score_entropy",
    "top3_score_mass",
    "top3_time_proximity",
    "top3_matched_socket_both",
    "top3_socket_neighbor_count",
    "top3_file_neighbor_count",
    "top3_operation_mass",
    "top3_stability_30s",
)
CONTROLLER_FEATURE_NAMES = (
    "combined_confidence",
    "combined_margin",
    "combined_entropy",
    "network_confidence",
    "network_margin",
    "provenance_confidence",
    "provenance_margin",
    "js_network_provenance",
    "js_combined_network",
    "js_combined_provenance",
    "network_provenance_agreement",
    "all_view_agreement",
) + PROVENANCE_SUMMARY_NAMES


@dataclass
class CaseRepresentation:
    case_id: str
    network: np.ndarray
    provenance: np.ndarray
    combined: np.ndarray
    summary: dict[str, float]
    entity_ids: list[str]
    entity_matrix: np.ndarray
    entity_scores: np.ndarray
    document: str


def stable_int(value: str) -> int:
    return int(hashlib.sha256(value.encode("utf-8")).hexdigest()[:16], 16)


def normalize_process_text(value: str) -> str:
    """Decode inert base64 shell payloads and mask campaign identifiers."""
    text = str(value)
    for match in re.finditer(
        r"echo\s+([A-Za-z0-9+/=]{8,})\s*\|\s*base64", text, flags=re.IGNORECASE
    ):
        try:
            text += " " + base64.b64decode(match.group(1)).decode("utf-8", "ignore")
        except (ValueError, UnicodeError):
            pass
    text = text.lower()
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " <ip> ", text)
    text = re.sub(r"\bt\d{4}(?:\.\d{3})?\b", " <technique> ", text)
    text = re.sub(r"\b\d+\b", " <num> ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def process_document(case_input: dict[str, Any], ranked_ids: list[str], top_k: int = 10) -> str:
    entities = {
        entity["entity_id"]: entity
        for entity in case_input["provenance_candidate_graph"]["entities"]
    }
    fields: list[str] = []
    for entity_id in ranked_ids[:top_k]:
        attributes = entities.get(entity_id, {}).get("attributes", {})
        executable = str(attributes.get("exe", ""))
        fields.extend(
            [
                str(attributes.get("name", "")),
                executable.rsplit("/", 1)[-1],
                str(attributes.get("command_line", "")),
            ]
        )
    return normalize_process_text(" ".join(fields))


def network_features(case_input: dict[str, Any]) -> np.ndarray:
    alert = case_input["network_alert"]
    rows = max(float(alert.get("row_count", 0.0)), 1.0)
    duration = max(float(alert.get("window_seconds", 60.0)), 1.0)
    protocols = alert.get("protocol_counts", {})
    values = [
        math.log1p(float(alert.get("row_count", 0.0))),
        math.log1p(float(alert.get("total_bytes", 0.0))),
        float(alert.get("trigger_offset_seconds", 0.0)) / duration,
        math.log1p(float(alert.get("unique_source_ips", 0.0))),
        math.log1p(float(alert.get("unique_destination_ips", 0.0))),
        math.log1p(float(alert.get("unique_source_ports", 0.0))),
        math.log1p(float(alert.get("unique_destination_ports", 0.0))),
        float(alert.get("source_ip_hhi", 0.0)),
        float(alert.get("destination_ip_hhi", 0.0)),
        float(alert.get("source_port_hhi", 0.0)),
        float(alert.get("destination_port_hhi", 0.0)),
        float(protocols.get("TCP", 0.0)) / rows,
        float(protocols.get("UDP", 0.0)) / rows,
        float(protocols.get("ICMP", 0.0)) / rows,
        float(protocols.get("ARP", 0.0)) / rows,
    ]
    return np.asarray(values, dtype=np.float64)


def entropy(probabilities: np.ndarray) -> float:
    values = np.clip(np.asarray(probabilities, dtype=float), 1e-12, 1.0)
    return float(-np.sum(values * np.log(values)))


def probability_margin(probabilities: np.ndarray) -> float:
    values = np.sort(np.asarray(probabilities, dtype=float))[::-1]
    return float(values[0] - values[1]) if len(values) > 1 else float(values[0])


def js_divergence(left: np.ndarray, right: np.ndarray) -> float:
    p = np.clip(np.asarray(left, dtype=float), 1e-12, 1.0)
    q = np.clip(np.asarray(right, dtype=float), 1e-12, 1.0)
    p /= p.sum()
    q /= q.sum()
    midpoint = 0.5 * (p + q)
    return float(
        0.5 * np.sum(p * np.log(p / midpoint))
        + 0.5 * np.sum(q * np.log(q / midpoint))
    )


def ranked_process_data(
    case_input: dict[str, Any], ranker: Any
) -> tuple[list[str], np.ndarray, np.ndarray]:
    entity_ids, matrix = extract_case(case_input)
    scores = ranker.predict_proba(matrix)[:, 1]
    order = sorted(range(len(entity_ids)), key=lambda i: (-float(scores[i]), entity_ids[i]))
    return (
        [entity_ids[i] for i in order],
        matrix[np.asarray(order, dtype=int)],
        scores[np.asarray(order, dtype=int)],
    )


def perturb_for_stability(matrix: np.ndarray) -> np.ndarray:
    changed = matrix.copy()
    names = feature_names()
    changed[:, names.index("time_proximity")] *= 0.9
    delta_index = names.index("log_closest_abs_time_delta")
    raw_delta = np.maximum(np.expm1(changed[:, delta_index]), 0.0)
    changed[:, delta_index] = np.log1p(raw_delta + 30.0)
    return changed


def transformed_process_data(
    case_input: dict[str, Any],
    ranker: Any,
    corruption: str = "clean",
    replacement: dict[str, Any] | None = None,
    delete_entity_ids: Iterable[str] | None = None,
) -> tuple[list[str], np.ndarray, np.ndarray, dict[str, Any]]:
    source = replacement if corruption == "context_replacement" and replacement else case_input
    entity_ids, matrix = extract_case(source)
    graph = source["provenance_candidate_graph"]
    graph_meta = {
        "candidate_entity_count": int(graph.get("candidate_entity_count", len(graph["entities"]))),
        "relation_count": int(graph.get("relation_count", len(graph["relations"]))),
        "entity_kind_counts": dict(graph.get("entity_kind_counts", {})),
    }
    names = feature_names()

    if corruption == "process_deletion":
        entity_ids = []
        matrix = np.empty((0, len(names)), dtype=np.float64)
        graph_meta["entity_kind_counts"]["process"] = 0
    elif corruption == "socket_type_deletion":
        for name in (
            "log_socket_neighbors",
            "log_matched_socket_address",
            "log_matched_socket_port",
            "log_matched_socket_both",
            "max_socket_time_proximity",
            "operation_connect",
        ):
            matrix[:, names.index(name)] = 0.0
        graph_meta["entity_kind_counts"]["socket"] = 0
    elif corruption == "time_shift":
        matrix[:, names.index("time_proximity")] = 0.0
        delta_index = names.index("log_closest_abs_time_delta")
        raw_delta = np.maximum(np.expm1(matrix[:, delta_index]), 0.0)
        matrix[:, delta_index] = np.log1p(raw_delta + 600.0)
        matrix[:, names.index("max_socket_time_proximity")] = 0.0
    elif corruption == "random_entity_deletion":
        keep = np.asarray(
            [stable_int(f"{case_input['case_id']}:{entity_id}") % 2 == 0 for entity_id in entity_ids],
            dtype=bool,
        )
        if len(keep) and not np.any(keep):
            keep[0] = True
        entity_ids = [entity_id for entity_id, flag in zip(entity_ids, keep) if flag]
        matrix = matrix[keep]
        graph_meta["entity_kind_counts"]["process"] = len(entity_ids)
        graph_meta["candidate_entity_count"] = max(
            len(entity_ids), int(round(graph_meta["candidate_entity_count"] * 0.5))
        )
        graph_meta["relation_count"] = int(round(graph_meta["relation_count"] * 0.5))

    if delete_entity_ids is not None and entity_ids:
        deletion_set = set(delete_entity_ids)
        keep = np.asarray([entity_id not in deletion_set for entity_id in entity_ids], dtype=bool)
        entity_ids = [entity_id for entity_id, flag in zip(entity_ids, keep) if flag]
        matrix = matrix[keep]
        graph_meta["entity_kind_counts"]["process"] = len(entity_ids)

    if not entity_ids:
        return [], matrix, np.empty(0, dtype=np.float64), graph_meta
    scores = ranker.predict_proba(matrix)[:, 1]
    order = sorted(range(len(entity_ids)), key=lambda i: (-float(scores[i]), entity_ids[i]))
    return (
        [entity_ids[i] for i in order],
        matrix[np.asarray(order, dtype=int)],
        scores[np.asarray(order, dtype=int)],
        graph_meta,
    )


def make_representation(
    case_input: dict[str, Any],
    ranker: Any,
    corruption: str = "clean",
    replacement: dict[str, Any] | None = None,
    delete_entity_ids: Iterable[str] | None = None,
) -> CaseRepresentation:
    ids, matrix, scores, graph = transformed_process_data(
        case_input,
        ranker,
        corruption=corruption,
        replacement=replacement,
        delete_entity_ids=delete_entity_ids,
    )
    source = replacement if corruption == "context_replacement" and replacement else case_input
    names = feature_names()
    provenance_indices = [names.index(name) for name in PROVENANCE_ENTITY_FEATURE_NAMES]
    if len(ids):
        top_n = min(3, len(ids))
        top_matrix = matrix[:top_n, :]
        top_scores = scores[:top_n]
        weights = np.clip(top_scores, 1e-6, None)
        aggregate = np.average(top_matrix[:, provenance_indices], axis=0, weights=weights)
        normalized_scores = np.clip(scores, 1e-12, None)
        normalized_scores /= normalized_scores.sum()
        score_entropy = entropy(normalized_scores) / max(math.log(len(scores)), 1.0)
        top_mass = float(normalized_scores[:top_n].sum())
        perturbed_scores = ranker.predict_proba(perturb_for_stability(matrix))[:, 1]
        perturbed_order = sorted(
            range(len(ids)), key=lambda i: (-float(perturbed_scores[i]), ids[i])
        )
        original_top = set(ids[:top_n])
        perturbed_top = {ids[i] for i in perturbed_order[:top_n]}
        stability = len(original_top & perturbed_top) / max(len(original_top | perturbed_top), 1)
        top_score = float(scores[0])
        score_margin = float(scores[0] - scores[1]) if len(scores) > 1 else top_score
        top3_time = float(np.mean(top_matrix[:, names.index("time_proximity")]))
        top3_socket_both = float(
            np.mean(top_matrix[:, names.index("log_matched_socket_both")])
        )
        top3_socket_neighbors = float(
            np.mean(top_matrix[:, names.index("log_socket_neighbors")])
        )
        top3_file_neighbors = float(
            np.mean(top_matrix[:, names.index("log_file_neighbors")])
        )
        operation_indices = [i for i, name in enumerate(names) if name.startswith("operation_")]
        top3_operation_mass = float(np.mean(np.sum(top_matrix[:, operation_indices], axis=1)))
    else:
        aggregate = np.zeros(len(provenance_indices), dtype=np.float64)
        score_entropy = top_mass = stability = top_score = score_margin = 0.0
        top3_time = top3_socket_both = top3_socket_neighbors = 0.0
        top3_file_neighbors = top3_operation_mass = 0.0

    kind_counts = graph.get("entity_kind_counts", {})
    total_entities = max(float(graph.get("candidate_entity_count", 0.0)), 1.0)
    summary_values = [
        math.log1p(len(ids)),
        math.log1p(float(graph.get("candidate_entity_count", 0.0))),
        math.log1p(float(graph.get("relation_count", 0.0))),
        float(kind_counts.get("process", 0.0)) / total_entities,
        float(kind_counts.get("file", 0.0)) / total_entities,
        float(kind_counts.get("socket", 0.0)) / total_entities,
        top_score,
        score_margin,
        score_entropy,
        top_mass,
        top3_time,
        top3_socket_both,
        top3_socket_neighbors,
        top3_file_neighbors,
        top3_operation_mass,
        stability,
    ]
    summary = dict(zip(PROVENANCE_SUMMARY_NAMES, map(float, summary_values)))
    network = network_features(case_input)
    provenance = np.concatenate([aggregate, np.asarray(summary_values, dtype=float)])
    return CaseRepresentation(
        case_id=case_input["case_id"],
        network=network,
        provenance=provenance,
        combined=np.concatenate([network, provenance]),
        summary=summary,
        entity_ids=ids,
        entity_matrix=matrix,
        entity_scores=scores,
        document=process_document(source, ids),
    )


def entity_training_data(
    case_ids: Iterable[str],
    inputs: dict[str, dict[str, Any]],
    truths: dict[str, dict[str, Any]],
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    matrices: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    weights: list[np.ndarray] = []
    for case_id in sorted(case_ids):
        ids, matrix = extract_case(inputs[case_id])
        truth_ids = set(
            truths[case_id]["provenance_ground_truth"]["malicious_candidate_process_ids"]
        )
        y = np.asarray([int(entity_id in truth_ids) for entity_id in ids], dtype=int)
        if not np.any(y):
            continue
        positives = int(np.sum(y == 1))
        negatives = int(np.sum(y == 0))
        sample_weight = np.zeros(len(y), dtype=float)
        sample_weight[y == 1] = 0.5 / positives
        if negatives:
            sample_weight[y == 0] = 0.5 / negatives
        else:
            sample_weight[y == 1] = 1.0 / positives
        matrices.append(matrix)
        labels.append(y)
        weights.append(sample_weight)
    return np.vstack(matrices), np.concatenate(labels), np.concatenate(weights)


def fit_entity_ranker(
    case_ids: Iterable[str],
    inputs: dict[str, dict[str, Any]],
    truths: dict[str, dict[str, Any]],
    seed: int,
) -> Any:
    x, y, weights = entity_training_data(case_ids, inputs, truths)
    return fit_ranker("typed_logistic", x, y, weights, seed)


def fit_tactic_model(matrix: np.ndarray, labels: list[str], seed: int) -> Any:
    model = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    C=0.3,
                    class_weight="balanced",
                    max_iter=5000,
                    solver="lbfgs",
                    random_state=seed,
                ),
            ),
        ]
    )
    model.fit(matrix, labels)
    return model


def fit_tactic_models(
    case_ids: list[str],
    representations: dict[str, CaseRepresentation],
    truths: dict[str, dict[str, Any]],
    seed: int,
) -> dict[str, Any]:
    labels = [truths[case_id]["event"]["tactic"] for case_id in case_ids]
    vectorizer = TfidfVectorizer(
        max_features=500,
        min_df=1,
        ngram_range=(1, 2),
        sublinear_tf=True,
        token_pattern=r"(?u)\b[a-zA-Z_][a-zA-Z0-9_.-]+\b",
    )
    lexical_x = vectorizer.fit_transform(
        [representations[case_id].document for case_id in case_ids]
    )
    lexical_classifier = LogisticRegression(
        C=1.0,
        class_weight="balanced",
        max_iter=5000,
        solver="lbfgs",
        random_state=seed,
    )
    lexical_classifier.fit(lexical_x, labels)
    return {
        "network": fit_tactic_model(
            np.vstack([representations[case_id].network for case_id in case_ids]), labels, seed
        ),
        "provenance": fit_tactic_model(
            np.vstack([representations[case_id].provenance for case_id in case_ids]), labels, seed
        ),
        "lexical": {"vectorizer": vectorizer, "classifier": lexical_classifier},
    }


def aligned_probabilities(model: Any, matrix: np.ndarray) -> np.ndarray:
    probabilities = model.predict_proba(matrix.reshape(1, -1))[0]
    classes = list(model.named_steps["classifier"].classes_)
    aligned = np.zeros(len(TACTICS), dtype=float)
    for label, probability in zip(classes, probabilities):
        if label in TACTICS:
            aligned[TACTICS.index(label)] = float(probability)
    if aligned.sum() <= 0:
        aligned[:] = 1.0 / len(aligned)
    else:
        aligned /= aligned.sum()
    return aligned


def tactic_posteriors(
    models: dict[str, Any], representation: CaseRepresentation
) -> dict[str, np.ndarray]:
    network = aligned_probabilities(models["network"], representation.network)
    provenance = aligned_probabilities(models["provenance"], representation.provenance)
    lexical_bundle = models["lexical"]
    lexical_x = lexical_bundle["vectorizer"].transform([representation.document])
    lexical_raw = lexical_bundle["classifier"].predict_proba(lexical_x)[0]
    lexical = np.zeros(len(TACTICS), dtype=float)
    for label, probability in zip(lexical_bundle["classifier"].classes_, lexical_raw):
        if label in TACTICS:
            lexical[TACTICS.index(label)] = float(probability)
    lexical /= max(lexical.sum(), 1e-12)
    # The attack tactic is inferred from the ranked provenance evidence.  The
    # two structured views remain independent inputs to the sufficiency gate.
    return {"network": network, "provenance": provenance, "combined": lexical}


def controller_features(
    posteriors: dict[str, np.ndarray], representation: CaseRepresentation
) -> np.ndarray:
    network = posteriors["network"]
    provenance = posteriors["provenance"]
    combined = posteriors["combined"]
    values = [
        float(np.max(combined)),
        probability_margin(combined),
        entropy(combined) / math.log(len(TACTICS)),
        float(np.max(network)),
        probability_margin(network),
        float(np.max(provenance)),
        probability_margin(provenance),
        js_divergence(network, provenance),
        js_divergence(combined, network),
        js_divergence(combined, provenance),
        float(np.argmax(network) == np.argmax(provenance)),
        float(
            np.argmax(network) == np.argmax(provenance) == np.argmax(combined)
        ),
    ]
    values.extend(representation.summary[name] for name in PROVENANCE_SUMMARY_NAMES)
    result = np.asarray(values, dtype=np.float64)
    if len(result) != len(CONTROLLER_FEATURE_NAMES):
        raise AssertionError("controller feature length mismatch")
    return result


def replacement_for(
    case_id: str,
    candidate_ids: list[str],
    truths: dict[str, dict[str, Any]],
) -> str:
    tactic = truths[case_id]["event"]["tactic"]
    choices = [
        other
        for other in sorted(candidate_ids)
        if other != case_id and truths[other]["event"]["tactic"] != tactic
    ]
    if not choices:
        choices = [other for other in sorted(candidate_ids) if other != case_id]
    return choices[stable_int(case_id) % len(choices)]


def corruption_representations(
    case_id: str,
    source_ids: list[str],
    inputs: dict[str, dict[str, Any]],
    truths: dict[str, dict[str, Any]],
    ranker: Any,
) -> dict[str, CaseRepresentation]:
    replacement_id = replacement_for(case_id, source_ids, truths)
    return {
        family: make_representation(
            inputs[case_id],
            ranker,
            corruption=family,
            replacement=inputs[replacement_id] if family == "context_replacement" else None,
        )
        for family in CORRUPTION_FAMILIES
    }


def train_controller_rows(
    train_ids: list[str],
    inputs: dict[str, dict[str, Any]],
    truths: dict[str, dict[str, Any]],
    seed: int,
    excluded_corruption: str | None = None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, dict[str, int]]:
    rows: list[np.ndarray] = []
    labels: list[int] = []
    weights: list[float] = []
    families: list[str] = []
    audit = Counter()
    active_corruptions = [
        family for family in CORRUPTION_FAMILIES if family != excluded_corruption
    ]
    for case_id in sorted(train_ids):
        other_ids = [other for other in train_ids if other != case_id]
        ranker = fit_entity_ranker(other_ids, inputs, truths, seed)
        clean_representations = {
            other: make_representation(inputs[other], ranker) for other in other_ids
        }
        models = fit_tactic_models(other_ids, clean_representations, truths, seed)
        clean = make_representation(inputs[case_id], ranker)
        clean_posteriors = tactic_posteriors(models, clean)
        predicted = TACTICS[int(np.argmax(clean_posteriors["combined"]))]
        correct = int(predicted == truths[case_id]["event"]["tactic"])
        rows.append(controller_features(clean_posteriors, clean))
        labels.append(correct)
        weights.append(0.5)
        families.append("clean")
        audit["clean_correct"] += correct
        audit["clean_incorrect"] += 1 - correct
        corruptions = corruption_representations(
            case_id, other_ids, inputs, truths, ranker
        )
        for family in active_corruptions:
            corrupted = corruptions[family]
            posteriors = tactic_posteriors(models, corrupted)
            rows.append(controller_features(posteriors, corrupted))
            labels.append(0)
            weights.append(0.5 / len(active_corruptions))
            families.append(family)
            audit[f"corruption_{family}"] += 1
    return (
        np.vstack(rows),
        np.asarray(labels, dtype=int),
        np.asarray(weights, dtype=float),
        np.asarray(families, dtype=object),
        dict(audit),
    )


def fit_controller(
    x: np.ndarray, y: np.ndarray, weights: np.ndarray, seed: int
) -> Any:
    model = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    C=0.3,
                    class_weight="balanced",
                    max_iter=3000,
                    solver="liblinear",
                    random_state=seed,
                ),
            ),
        ]
    )
    model.fit(x, y, classifier__sample_weight=weights)
    return model


def membership(truth: dict[str, Any], fold: int) -> dict[str, Any]:
    matches = [item for item in truth["split_membership"] if int(item["fold"]) == fold]
    if len(matches) != 1:
        raise ValueError(f"invalid membership for {truth['case_id']} fold {fold}")
    return matches[0]


def partition_ids(
    truths: dict[str, dict[str, Any]], fold: int, partition: str, in_support: bool = True
) -> list[str]:
    return [
        case_id
        for case_id, truth in truths.items()
        if membership(truth, fold)["partition"] == partition
        and (not in_support or bool(membership(truth, fold).get("supervised_eligible", False)))
    ]


def selection_mask(rows: list[dict[str, Any]], score_name: str, count: int) -> set[str]:
    ordered = sorted(rows, key=lambda row: (-float(row[score_name]), row["case_id"]))
    return {row["case_id"] for row in ordered[:count]}


def risk_for(rows: list[dict[str, Any]], accepted: set[str]) -> float:
    selected = [row for row in rows if row["case_id"] in accepted]
    return float(mean(1 - int(row["correct"]) for row in selected)) if selected else math.nan


def percentile_interval(values: list[float]) -> list[float]:
    return [float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5))]


def bootstrap_risk_difference(
    rows: list[dict[str, Any]], coverage: float, iterations: int, seed: int
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    differences: list[float] = []
    controller_risks: list[float] = []
    baseline_risks: list[float] = []
    n = len(rows)
    for _ in range(iterations):
        indices = rng.integers(0, n, size=n)
        sample = [dict(rows[index], case_id=f"{draw}:{rows[index]['case_id']}") for draw, index in enumerate(indices)]
        accepted_count = max(1, int(round(coverage * n)))
        controller_accept = selection_mask(sample, "controller_score", accepted_count)
        baseline_accept = selection_mask(sample, "confidence_score", accepted_count)
        controller_risk = risk_for(sample, controller_accept)
        baseline_risk = risk_for(sample, baseline_accept)
        controller_risks.append(controller_risk)
        baseline_risks.append(baseline_risk)
        differences.append(controller_risk - baseline_risk)
    return {
        "iterations": iterations,
        "unit": "attack_action_cluster",
        "controller_risk_ci95": percentile_interval(controller_risks),
        "max_confidence_risk_ci95": percentile_interval(baseline_risks),
        "risk_difference_ci95": percentile_interval(differences),
        "probability_difference_below_zero": float(np.mean(np.asarray(differences) < 0.0)),
    }


def risk_coverage_curve(rows: list[dict[str, Any]], score_name: str) -> list[dict[str, float]]:
    output = []
    for coverage in np.linspace(0.1, 1.0, 10):
        count = max(1, int(round(float(coverage) * len(rows))))
        accepted = selection_mask(rows, score_name, count)
        output.append(
            {
                "requested_coverage": float(coverage),
                "realized_coverage": count / len(rows),
                "risk": risk_for(rows, accepted),
            }
        )
    return output


def calibration_threshold(values: list[float], coverage: float) -> float:
    ordered = sorted(map(float, values), reverse=True)
    count = max(1, int(round(coverage * len(ordered))))
    return ordered[count - 1]


def expected_calibration_error(rows: list[dict[str, Any]], bins: int = 5) -> float:
    confidences = np.asarray([row["confidence_score"] for row in rows], dtype=float)
    correct = np.asarray([row["correct"] for row in rows], dtype=float)
    edges = np.linspace(0.0, 1.0, bins + 1)
    ece = 0.0
    for lower, upper in zip(edges[:-1], edges[1:]):
        mask = (confidences >= lower) & (
            confidences < upper if upper < 1.0 else confidences <= upper
        )
        if np.any(mask):
            ece += float(np.mean(mask)) * abs(float(np.mean(correct[mask])) - float(np.mean(confidences[mask])))
    return ece


def deletion_lift(
    test_ids: list[str],
    inputs: dict[str, dict[str, Any]],
    truths: dict[str, dict[str, Any]],
    ranker: Any,
    models: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = []
    for case_id in test_ids:
        clean = make_representation(inputs[case_id], ranker)
        if len(clean.entity_ids) < 4:
            continue
        truth_index = TACTICS.index(truths[case_id]["event"]["tactic"])
        clean_probability = tactic_posteriors(models, clean)["combined"][truth_index]
        deletion_k = min(3, len(clean.entity_ids) // 2)
        top_ids = clean.entity_ids[:deletion_k]
        remaining_ids = clean.entity_ids[deletion_k:]
        ordered_random = sorted(
            remaining_ids, key=lambda entity_id: stable_int(f"random-delete:{case_id}:{entity_id}")
        )
        random_ids = ordered_random[:deletion_k]
        top_deleted = make_representation(
            inputs[case_id], ranker, delete_entity_ids=top_ids
        )
        random_deleted = make_representation(
            inputs[case_id], ranker, delete_entity_ids=random_ids
        )
        top_probability = tactic_posteriors(models, top_deleted)["combined"][truth_index]
        random_probability = tactic_posteriors(models, random_deleted)["combined"][truth_index]
        rows.append(
            {
                "case_id": case_id,
                "deletion_k": deletion_k,
                "clean_true_tactic_probability": float(clean_probability),
                "top1_deletion_drop": float(clean_probability - top_probability),
                "random_deletion_drop": float(clean_probability - random_probability),
                "deletion_lift": float(random_probability - top_probability),
            }
        )
    return rows


def reason_code(row: dict[str, Any]) -> str:
    if row["support_role"] != "in_support":
        return "out_of_support"
    if row["process_candidate_count"] <= 0:
        return "missing_evidence"
    if not row["view_agreement"]:
        return "cross_view_conflict"
    if row["top3_stability_30s"] < 2.0 / 3.0:
        return "unstable_evidence"
    return "insufficient_evidence"


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    inputs_list = load_jsonl(args.inputs)
    truths_list = load_jsonl(args.truth)
    inputs = {item["case_id"]: item for item in inputs_list}
    truths = {item["case_id"]: item for item in truths_list}
    if set(inputs) != set(truths):
        raise ValueError("input and truth sidecars have different case IDs")
    test_rows: list[dict[str, Any]] = []
    out_of_support_rows: list[dict[str, Any]] = []
    corruption_rows: list[dict[str, Any]] = []
    deletion_rows: list[dict[str, Any]] = []
    fold_audits: list[dict[str, Any]] = []
    inference_times_ms: list[float] = []

    for fold in (1, 2, 3):
        fold_started = time.perf_counter()
        train_ids = sorted(partition_ids(truths, fold, "train", in_support=True))
        calibration_ids = sorted(partition_ids(truths, fold, "calibration", in_support=True))
        test_ids = sorted(partition_ids(truths, fold, "test", in_support=True))
        test_all_ids = sorted(partition_ids(truths, fold, "test", in_support=False))
        oos_ids = [case_id for case_id in test_all_ids if case_id not in test_ids]
        ranker = fit_entity_ranker(train_ids, inputs, truths, args.seed)
        train_representations = {
            case_id: make_representation(inputs[case_id], ranker) for case_id in train_ids
        }
        tactic_models = fit_tactic_models(
            train_ids, train_representations, truths, args.seed
        )
        controller_x, controller_y, controller_weights, controller_families, controller_audit = train_controller_rows(
            train_ids, inputs, truths, args.seed
        )
        controller = fit_controller(
            controller_x, controller_y, controller_weights, args.seed
        )
        loco_controllers: dict[str, Any] = {}
        for family in CORRUPTION_FAMILIES:
            keep = controller_families != family
            x_loco = controller_x[keep]
            y_loco = controller_y[keep]
            remaining_families = controller_families[keep]
            w_loco = np.where(
                remaining_families == "clean",
                0.5,
                0.5 / (len(CORRUPTION_FAMILIES) - 1),
            )
            loco_controllers[family] = fit_controller(x_loco, y_loco, w_loco, args.seed)

        calibration_records = []
        for case_id in calibration_ids:
            representation = make_representation(inputs[case_id], ranker)
            posteriors = tactic_posteriors(tactic_models, representation)
            c_features = controller_features(posteriors, representation)
            calibration_records.append(
                {
                    "controller": float(controller.predict_proba(c_features.reshape(1, -1))[0, 1]),
                    "confidence": float(np.max(posteriors["combined"])),
                }
            )
        controller_threshold = calibration_threshold(
            [row["controller"] for row in calibration_records], args.coverage
        )
        confidence_threshold = calibration_threshold(
            [row["confidence"] for row in calibration_records], args.coverage
        )

        for case_id in test_ids + oos_ids:
            inference_started = time.perf_counter()
            representation = make_representation(inputs[case_id], ranker)
            posteriors = tactic_posteriors(tactic_models, representation)
            c_features = controller_features(posteriors, representation)
            controller_score = float(
                controller.predict_proba(c_features.reshape(1, -1))[0, 1]
            )
            inference_times_ms.append((time.perf_counter() - inference_started) * 1000.0)
            predicted_index = int(np.argmax(posteriors["combined"]))
            prediction = TACTICS[predicted_index]
            truth_label = truths[case_id]["event"]["tactic"]
            row = {
                "case_id": case_id,
                "test_fold": fold,
                "tactic": truth_label,
                "support_role": truths[case_id]["event"]["support_role"],
                "prediction": prediction,
                "network_prediction": TACTICS[int(np.argmax(posteriors["network"]))],
                "provenance_prediction": TACTICS[int(np.argmax(posteriors["provenance"]))],
                "correct": int(prediction == truth_label),
                "controller_score": controller_score,
                "confidence_score": float(np.max(posteriors["combined"])),
                "network_confidence": float(np.max(posteriors["network"])),
                "provenance_confidence": float(np.max(posteriors["provenance"])),
                "view_agreement": int(np.argmax(posteriors["network"]) == np.argmax(posteriors["provenance"])),
                "process_candidate_count": len(representation.entity_ids),
                "top_rank_score": representation.summary["top_rank_score"],
                "top3_stability_30s": representation.summary["top3_stability_30s"],
                "calibrated_controller_accept": int(controller_score >= controller_threshold),
                "calibrated_confidence_accept": int(float(np.max(posteriors["combined"])) >= confidence_threshold),
                "reason_code_if_rejected": "",
            }
            for tactic_name, probability in zip(TACTICS, posteriors["combined"]):
                row[f"probability_{tactic_name}"] = float(probability)
            row["reason_code_if_rejected"] = (
                "" if row["calibrated_controller_accept"] else reason_code(row)
            )
            if case_id in test_ids:
                test_rows.append(row)
            else:
                out_of_support_rows.append(row)

        deletion_rows.extend(
            dict(item, test_fold=fold)
            for item in deletion_lift(test_ids, inputs, truths, ranker, tactic_models)
        )

        for family in CORRUPTION_FAMILIES:
            loco = loco_controllers[family]
            calibration_loco_scores = []
            for case_id in calibration_ids:
                clean = make_representation(inputs[case_id], ranker)
                posteriors = tactic_posteriors(tactic_models, clean)
                features = controller_features(posteriors, clean)
                calibration_loco_scores.append(
                    float(loco.predict_proba(features.reshape(1, -1))[0, 1])
                )
            loco_threshold = calibration_threshold(calibration_loco_scores, args.coverage)
            for case_id in test_ids:
                replacement_id = replacement_for(case_id, train_ids, truths)
                corrupted = make_representation(
                    inputs[case_id],
                    ranker,
                    corruption=family,
                    replacement=inputs[replacement_id] if family == "context_replacement" else None,
                )
                posteriors = tactic_posteriors(tactic_models, corrupted)
                features = controller_features(posteriors, corrupted)
                score = float(loco.predict_proba(features.reshape(1, -1))[0, 1])
                prediction = TACTICS[int(np.argmax(posteriors["combined"]))]
                confidence = float(np.max(posteriors["combined"]))
                corruption_rows.append(
                    {
                        "case_id": case_id,
                        "test_fold": fold,
                        "corruption_family": family,
                        "prediction": prediction,
                        "tactic": truths[case_id]["event"]["tactic"],
                        "correct": int(prediction == truths[case_id]["event"]["tactic"]),
                        "controller_score": score,
                        "controller_reject": int(score < loco_threshold),
                        "confidence_score": confidence,
                        "confidence_reject": int(confidence < confidence_threshold),
                    }
                )

        fold_audits.append(
            {
                "fold": fold,
                "train_cases": len(train_ids),
                "calibration_cases": len(calibration_ids),
                "test_in_support_cases": len(test_ids),
                "test_out_of_support_cases": len(oos_ids),
                "controller_training": controller_audit,
                "controller_threshold_from_calibration": controller_threshold,
                "confidence_threshold_from_calibration": confidence_threshold,
                "exact_normalized_process_document_overlap_test_in_train": mean(
                    int(
                        make_representation(inputs[case_id], ranker).document
                        in {
                            train_representations[train_id].document
                            for train_id in train_ids
                        }
                    )
                    for case_id in test_ids
                ),
                "fold_runtime_seconds": time.perf_counter() - fold_started,
            }
        )

    accepted_count = max(1, int(round(args.coverage * len(test_rows))))
    controller_accept = selection_mask(test_rows, "controller_score", accepted_count)
    confidence_accept = selection_mask(test_rows, "confidence_score", accepted_count)
    majority_accept = selection_mask(test_rows, "network_confidence", accepted_count)
    majority_predictions = {
        fold: Counter(
            truths[case_id]["event"]["tactic"]
            for case_id in partition_ids(truths, fold, "train", in_support=True)
        ).most_common(1)[0][0]
        for fold in (1, 2, 3)
    }
    majority_selected = [row for row in test_rows if row["case_id"] in majority_accept]
    majority_risk = mean(
        int(majority_predictions[int(row["test_fold"])] != row["tactic"])
        for row in majority_selected
    )
    controller_risk = risk_for(test_rows, controller_accept)
    confidence_risk = risk_for(test_rows, confidence_accept)
    y_true = [row["tactic"] for row in test_rows]
    y_pred = [row["prediction"] for row in test_rows]
    controller_pred = [
        row["prediction"] for row in test_rows if row["case_id"] in controller_accept
    ]
    controller_true = [
        row["tactic"] for row in test_rows if row["case_id"] in controller_accept
    ]

    for row in test_rows:
        row["fixed_coverage_controller_accept"] = int(row["case_id"] in controller_accept)
        row["fixed_coverage_confidence_accept"] = int(row["case_id"] in confidence_accept)

    corruption_summary = {}
    for family in CORRUPTION_FAMILIES:
        family_rows = [row for row in corruption_rows if row["corruption_family"] == family]
        corruption_summary[family] = {
            "cases": len(family_rows),
            "controller_rejection_rate": mean(row["controller_reject"] for row in family_rows),
            "max_confidence_rejection_rate": mean(row["confidence_reject"] for row in family_rows),
            "controller_wrong_attribution_rate": mean(
                int(not row["controller_reject"] and not row["correct"]) for row in family_rows
            ),
            "max_confidence_wrong_attribution_rate": mean(
                int(not row["confidence_reject"] and not row["correct"]) for row in family_rows
            ),
        }

    drops_top = [row["top1_deletion_drop"] for row in deletion_rows]
    drops_random = [row["random_deletion_drop"] for row in deletion_rows]
    lifts = [row["deletion_lift"] for row in deletion_rows]
    rng = np.random.default_rng(args.seed)
    lift_bootstrap = []
    for _ in range(args.bootstrap_iterations):
        indices = rng.integers(0, len(lifts), size=len(lifts))
        lift_bootstrap.append(float(np.mean(np.asarray(lifts)[indices])))

    calibrated_controller_selected = [
        row for row in test_rows if row["calibrated_controller_accept"]
    ]
    calibrated_confidence_selected = [
        row for row in test_rows if row["calibrated_confidence_accept"]
    ]
    parameter_count = 0
    # Parameter counts are stable across folds; report the last fitted models.
    for model in [
        tactic_models["network"],
        tactic_models["provenance"],
        controller,
        ranker,
    ]:
        classifier = model.named_steps.get("classifier") if hasattr(model, "named_steps") else None
        if classifier is not None:
            parameter_count += int(classifier.coef_.size + classifier.intercept_.size)
    lexical_classifier = tactic_models["lexical"]["classifier"]
    parameter_count += int(
        lexical_classifier.coef_.size + lexical_classifier.intercept_.size
    )

    summary = {
        "study": "EviGate-APT Stage C selective tactic attribution",
        "protocol": {
            "statistical_unit": "attack_action_cluster",
            "outer_protocol": "three-fold grouped train/calibration/test",
            "primary_condition": "oracle-alert, in-support events",
            "target_coverage": args.coverage,
            "realized_primary_coverage": accepted_count / len(test_rows),
            "accepted_events": accepted_count,
            "test_events": len(test_rows),
            "derived_event_labels": True,
            "truth_sidecar_separate_from_inference_inputs": True,
            "controller_training": "leave-one-event-out clean correctness plus synthetic corruption negatives",
            "primary_baseline": "maximum-confidence rejection over the same combined tactic classifier",
        },
        "full_coverage_tactic_classifier": {
            "accuracy": mean(row["correct"] for row in test_rows),
            "network_only_accuracy": mean(
                int(row["network_prediction"] == row["tactic"]) for row in test_rows
            ),
            "structured_provenance_accuracy": mean(
                int(row["provenance_prediction"] == row["tactic"]) for row in test_rows
            ),
            "macro_f1": float(f1_score(y_true, y_pred, labels=list(TACTICS), average="macro", zero_division=0)),
            "brier_multiclass_mean": float(
                np.mean(
                    [
                        sum(
                            (
                                float(row[f"probability_{tactic}"])
                                - float(row["tactic"] == tactic)
                            )
                            ** 2
                            for tactic in TACTICS
                        )
                        / len(TACTICS)
                        for row in test_rows
                    ]
                )
            ),
            "ece_5_bin": expected_calibration_error(test_rows, bins=5),
        },
        "primary_fixed_coverage": {
            "controller_attribution_risk": controller_risk,
            "max_confidence_attribution_risk": confidence_risk,
            "absolute_risk_difference_controller_minus_baseline": controller_risk - confidence_risk,
            "relative_risk_reduction": (
                (confidence_risk - controller_risk) / confidence_risk
                if confidence_risk > 0
                else None
            ),
            "coverage_matched_majority_risk": float(majority_risk),
            "controller_selective_macro_f1": float(
                f1_score(
                    controller_true,
                    controller_pred,
                    labels=list(TACTICS),
                    average="macro",
                    zero_division=0,
                )
            ),
            "paired_cluster_bootstrap": bootstrap_risk_difference(
                test_rows, args.coverage, args.bootstrap_iterations, args.seed
            ),
        },
        "calibration_threshold_operating_point": {
            "controller_test_coverage": len(calibrated_controller_selected) / len(test_rows),
            "controller_test_risk": (
                mean(1 - row["correct"] for row in calibrated_controller_selected)
                if calibrated_controller_selected
                else None
            ),
            "max_confidence_test_coverage": len(calibrated_confidence_selected) / len(test_rows),
            "max_confidence_test_risk": (
                mean(1 - row["correct"] for row in calibrated_confidence_selected)
                if calibrated_confidence_selected
                else None
            ),
        },
        "risk_coverage_curves": {
            "controller": risk_coverage_curve(test_rows, "controller_score"),
            "max_confidence": risk_coverage_curve(test_rows, "confidence_score"),
        },
        "out_of_support": {
            "events": len(out_of_support_rows),
            "calibration_threshold_rejection_rate": (
                mean(1 - row["calibrated_controller_accept"] for row in out_of_support_rows)
                if out_of_support_rows
                else None
            ),
        },
        "leave_one_corruption_family_out": corruption_summary,
        "evidence_fidelity": {
            "cases": len(deletion_rows),
            "deletion_k": 3,
            "mean_true_tactic_probability_drop_topk": float(mean(drops_top)),
            "mean_true_tactic_probability_drop_random": float(mean(drops_random)),
            "mean_deletion_lift": float(mean(lifts)),
            "deletion_lift_ci95": percentile_interval(lift_bootstrap),
        },
        "efficiency": {
            "total_runtime_seconds": time.perf_counter() - started,
            "median_clean_case_inference_ms": median(inference_times_ms),
            "p95_clean_case_inference_ms": float(np.percentile(inference_times_ms, 95)),
            "reported_linear_parameter_count_last_fold_models": parameter_count,
        },
        "fold_audits": fold_audits,
        "limitations": [
            "The official Attack_info.csv was unavailable; event labels are union-derived fallback labels.",
            "All events come from one CICAPT-IIoT2024 campaign, so confidence intervals do not establish cross-campaign generalization.",
            "Synthetic corruptions test controlled failure modes and are not a complete model of field evidence loss.",
            "The fixed 80% target is realized at the nearest feasible event count.",
            "Socket matching is used only as a sufficiency feature because Stage B ablation found no retrieval gain.",
        ],
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "stage_c_test_predictions.csv", test_rows)
    write_csv(args.output_dir / "stage_c_out_of_support.csv", out_of_support_rows)
    write_csv(args.output_dir / "stage_c_corruption_results.csv", corruption_rows)
    write_csv(args.output_dir / "stage_c_deletion_lift.csv", deletion_rows)
    with (args.output_dir / "stage_c_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    summary["artifacts"] = {
        path.name: {"sha256": sha256_file(path), "bytes": path.stat().st_size}
        for path in sorted(args.output_dir.iterdir())
        if path.is_file() and path.name != "stage_c_summary.json"
    }
    with (args.output_dir / "stage_c_summary.json").open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return summary


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--coverage", type=float, default=0.8)
    parser.add_argument("--bootstrap-iterations", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260915)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    summary = evaluate(args)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
