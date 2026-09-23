#!/usr/bin/env python3
"""Post-freeze Phase-1 benign-concurrency stress for the Stage-B process ranker.

Donor provenance windows are time-projected into each held-out Phase-2 alert.
This is a synthetic candidate-set stress, not observed multi-host concurrency.
The original graphs, training examples, labels, and fitted ranker are unchanged.
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from statistics import mean, median
from typing import Any

import numpy as np

from build_cicapt_evidence_dataset import (
    NetworkAccumulator,
    candidate_graph,
    load_provenance,
)
from evaluate_stage_b_retrieval_baselines import (
    BASELINES,
    random_expected_mrr,
    random_hit_probability,
)
from run_stage_b_typed_ranker import (
    extract_case,
    fit_ranker,
    load_jsonl,
    membership,
    ranking_row,
    sha256_file,
    training_data,
)


LOAD_BANDS = {"none": None, "small": (5, 12), "busy": (50, 120)}
TOP_K = (1, 5, 10)
SEED = 11


def phase1_centers(
    nodes: dict[str, Any], edges: list[Any], timestamps: list[float],
    *, n_quantiles: int = 64, min_processes: int = 5,
    max_processes: int = 120, radius: int = 300,
) -> list[dict[str, Any]]:
    """Select small, nonoverlapping benign windows without using attack labels."""
    selected: list[dict[str, Any]] = []
    for index in range(1, n_quantiles):
        center = timestamps[int(index * len(timestamps) / n_quantiles)]
        if selected and center - selected[-1]["center"] < 2 * radius:
            continue
        graph, truth = candidate_graph(
            nodes, edges, timestamps, center, radius, NetworkAccumulator()
        )
        process_count = graph["entity_kind_counts"].get("process", 0)
        if not min_processes <= process_count <= max_processes:
            continue
        if truth["malicious_candidate_entity_ids"] or truth["malicious_relation_ids"]:
            raise ValueError("Phase-1 donor window is not wholly benign")
        selected.append(
            {"quantile_index": index, "center": center, "process_count": process_count}
        )
    for band, limits in LOAD_BANDS.items():
        if limits is not None and not any(limits[0] <= x["process_count"] <= limits[1] for x in selected):
            raise ValueError(f"no eligible Phase-1 donor window in {band} band")
    return selected


def case_network_top_five(case_input: dict[str, Any]) -> NetworkAccumulator:
    """Reconstruct only released top-five endpoints for donor socket matches."""
    alert = case_input["network_alert"]
    network = NetworkAccumulator()
    for source_key, target in (
        ("top_source_ips", network.source_ips),
        ("top_destination_ips", network.destination_ips),
        ("top_source_ports", network.source_ports),
        ("top_destination_ports", network.destination_ports),
    ):
        for item in alert.get(source_key, []):
            target[str(item["value"])] += int(item["count"])
    return network


def donor_index(
    case_id: str, band: str, centers: list[dict[str, Any]], assignment_id: int = 0
) -> int:
    """Choose one real benign window per load band, independent of truth."""
    limits = LOAD_BANDS[band]
    if limits is None:
        raise ValueError("no donor exists for the clean condition")
    eligible = [
        index for index, center in enumerate(centers)
        if limits[0] <= center["process_count"] <= limits[1]
    ]
    if assignment_id < 0:
        raise ValueError("assignment_id must be nonnegative")
    key = f"{case_id}|{band}"
    if assignment_id:
        key += f"|{assignment_id}"
    digest = hashlib.sha256(key.encode()).digest()
    return eligible[int.from_bytes(digest[:8], "big") % len(eligible)]


def combine_graphs(
    original: dict[str, Any], donor_graph: tuple[int, dict[str, Any]] | None
) -> dict[str, Any]:
    """Append one real benign window with collision-free, non-semantic IDs."""
    case = copy.deepcopy(original)
    graph = case["provenance_candidate_graph"]
    original_ids = {item["entity_id"] for item in graph["entities"]}
    if donor_graph is not None:
        donor_index, donor = donor_graph
        prefix = f"phase1_donor_{donor_index}_"
        for entity in donor["entities"]:
            appended = copy.deepcopy(entity)
            appended["entity_id"] = prefix + entity["entity_id"]
            if appended["entity_id"] in original_ids:
                raise AssertionError("donor entity ID collision")
            graph["entities"].append(appended)
        for relation in donor["relations"]:
            appended = copy.deepcopy(relation)
            appended["relation_id"] = prefix + relation["relation_id"]
            appended["source_entity_id"] = prefix + relation["source_entity_id"]
            appended["target_entity_id"] = prefix + relation["target_entity_id"]
            graph["relations"].append(appended)
        for field in ("entity_kind_counts", "relation_type_counts", "operation_counts"):
            combined = Counter(graph[field]) + Counter(donor[field])
            graph[field] = dict(sorted(combined.items()))
    graph["candidate_entity_count"] = len(graph["entities"])
    graph["relation_count"] = len(graph["relations"])
    if len({item["entity_id"] for item in graph["entities"]}) != len(graph["entities"]):
        raise AssertionError("duplicate candidate entity after donor injection")
    return case


def summarize_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if len(rows) != 59:
        raise ValueError("expected one held-out ranking per each of 59 cases")
    counts = [int(row["process_candidate_count"]) for row in rows]
    added = [int(row["injected_process_count"]) for row in rows]
    truth_count = [int(row["truth_process_entity_count"]) for row in rows]
    return {
        "cases": len(rows),
        "truth_present": sum(int(row["truth_present"]) for row in rows),
        "median_candidate_processes": median(counts),
        "median_injected_processes": median(added),
        "range_injected_processes": [min(added), max(added)],
        "midrank_mrr": mean(float(row["midrank_reciprocal"]) for row in rows),
        "expected_tie_recall_at_1": mean(float(row["expected_tie_hit_at_1"]) for row in rows),
        "expected_tie_recall_at_5": mean(float(row["expected_tie_hit_at_5"]) for row in rows),
        "expected_tie_recall_at_10": mean(float(row["expected_tie_hit_at_10"]) for row in rows),
        "random_expected_mrr": mean(
            random_expected_mrr(n, t) for n, t in zip(counts, truth_count)
        ),
        "random_expected_recall_at_1": mean(
            random_hit_probability(n, t, 1) for n, t in zip(counts, truth_count)
        ),
        "random_expected_recall_at_10": mean(
            random_hit_probability(n, t, 10) for n, t in zip(counts, truth_count)
        ),
        "truth_at_rank_1": sum(int(row["expected_tie_hit_at_1"] == 1.0) for row in rows),
    }


def run(
    inputs_path: Path, truth_path: Path, provenance_path: Path,
    output_dir: Path, assignment_id: int = 0,
) -> dict[str, Any]:
    inputs = {item["case_id"]: item for item in load_jsonl(inputs_path)}
    truths = {item["case_id"]: item for item in load_jsonl(truth_path)}
    if len(inputs) != 59 or set(inputs) != set(truths):
        raise ValueError("expected the 59-case aligned benchmark")
    extracted = {case_id: extract_case(case) for case_id, case in inputs.items()}
    nodes, edges = load_provenance(provenance_path)
    if any(node.raw_label == "1" for node in nodes.values()) or any(
        edge.raw_label == "1" for edge in edges
    ):
        raise ValueError("Phase-1 provenance must be all benign")
    timestamps = [edge.timestamp for edge in edges]
    centers = phase1_centers(nodes, edges, timestamps)
    rows: list[dict[str, Any]] = []
    training_audit = []
    for fold in (1, 2, 3):
        x_train, y_train, weights, audit = training_data(
            inputs, truths, extracted, fold
        )
        model = fit_ranker("typed_logistic", x_train, y_train, weights, SEED)
        training_audit.append({"fold": fold, **audit})
        for case_id in sorted(inputs):
            if membership(truths[case_id], fold)["partition"] != "test":
                continue
            original_ids, original_matrix = extracted[case_id]
            network = case_network_top_five(inputs[case_id])
            for band in LOAD_BANDS:
                donor_index_value = None
                donor_graph = None
                if band != "none":
                    donor_index_value = donor_index(case_id, band, centers, assignment_id)
                    donor, donor_truth = candidate_graph(
                        nodes, edges, timestamps,
                        centers[donor_index_value]["center"], 300, network,
                    )
                    if donor_truth["malicious_candidate_entity_ids"] or donor_truth["malicious_relation_ids"]:
                        raise AssertionError("injected donor is not benign")
                    donor_graph = (donor_index_value, donor)
                mixed = combine_graphs(inputs[case_id], donor_graph)
                entity_ids, matrix = extract_case(mixed)
                original_by_id = {entity_id: vector for entity_id, vector in zip(original_ids, original_matrix)}
                if not all(
                    np.array_equal(matrix[index], original_by_id[entity_id])
                    for index, entity_id in enumerate(entity_ids)
                    if entity_id in original_by_id
                ):
                    raise AssertionError("injection altered original process features")
                entities = {
                    entity["entity_id"]: entity
                    for entity in mixed["provenance_candidate_graph"]["entities"]
                }
                score_sets = {
                    "typed_logistic": model.predict_proba(matrix)[:, 1],
                    "recency_plus_degree": np.asarray(
                        [BASELINES["recency_plus_degree"](entities[entity_id], case_id)
                         for entity_id in entity_ids],
                        dtype=np.float64,
                    ),
                }
                for model_name, scores in score_sets.items():
                    row = ranking_row(
                        case_id, truths[case_id], entity_ids, scores,
                        model_name, SEED, fold, TOP_K,
                    )
                    row["load_band"] = band
                    row["injected_process_count"] = len(entity_ids) - len(original_ids)
                    row["donor_quantile_index"] = (
                        centers[donor_index_value]["quantile_index"]
                        if donor_index_value is not None else ""
                    )
                    rows.append(row)
    if len(rows) != 59 * len(LOAD_BANDS) * 2:
        raise AssertionError("incomplete held-out stress audit")
    by_band = {
        band: {
            model_name: summarize_rows([
                row for row in rows
                if row["load_band"] == band and row["model"] == model_name
            ])
            for model_name in ("typed_logistic", "recency_plus_degree")
        }
        for band in LOAD_BANDS
    }
    if abs(by_band["none"]["typed_logistic"]["midrank_mrr"] - 0.9519793053151522) > 1e-12:
        raise AssertionError("clean ranking does not reproduce the frozen baseline")
    output_dir.mkdir(parents=True, exist_ok=True)
    csv_path = output_dir / "benign_distractor.per_case.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    result = {
        "schema_version": "1.0",
        "experiment": "post-freeze Stage-B Phase-1 benign-concurrency stress",
        "policy": {
            "phase1_selection": "63 edge-timestamp quantiles; retain disjoint +/-300-s windows with 5-120 benign process candidates",
            "case_assignment": "SHA-256 case-ID-and-band selection of one window per stress band; no truth or labels used",
            "assignment_id": assignment_id,
            "load_bands": LOAD_BANDS,
            "models": "frozen fold-trained typed Logistic Regression, seed 11; recency-plus-degree zero-model comparator",
            "network_match_rule": "donor sockets checked only against released top-five alert addresses and ports",
            "donor_projection": "one donor window's relative timestamps retained and projected into the target alert interval",
            "scope": "synthetic benign candidate-set stress, not naturally co-observed multi-host traffic",
        },
        "eligible_phase1_windows": centers,
        "training_audit": training_audit,
        "results": by_band,
        "source_sha256": {
            "inputs": sha256_file(inputs_path),
            "truth": sha256_file(truth_path),
            "phase1_provenance": sha256_file(provenance_path),
        },
        "per_case": {"path": csv_path.as_posix(), "sha256": sha256_file(csv_path)},
    }
    summary_path = output_dir / "benign_distractor.summary.json"
    summary_path.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"summary": summary_path.as_posix(), "results": by_band}, indent=2))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=Path("data/derived/evigate_phase2_evidence/cases.inputs.jsonl"))
    parser.add_argument("--truth", type=Path, default=Path("data/derived/evigate_phase2_evidence/cases.truth.jsonl"))
    parser.add_argument("--phase1-provenance", type=Path, default=Path("data/raw/cicapt/Phase1_Provenance.csv"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/derived/p1_diagnostics/benign_distractors"))
    parser.add_argument("--assignment-id", type=int, default=0)
    args = parser.parse_args()
    run(args.inputs, args.truth, args.phase1_provenance, args.output_dir, args.assignment_id)


if __name__ == "__main__":
    main()
