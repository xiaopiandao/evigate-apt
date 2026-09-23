#!/usr/bin/env python3
"""Run fixed Stage-B feature ablations to diagnose typed-ranker signal sources."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from evaluate_stage_b_retrieval_baselines import summarize
from run_stage_b_typed_ranker import (
    extract_case,
    feature_names,
    load_jsonl,
    membership,
    ranking_row,
    sha256_file,
    training_data,
)


def feature_groups() -> dict[str, set[str]]:
    names = set(feature_names())
    process_semantics = {
        name
        for name in names
        if name.startswith("utility_")
        or name
        in {
            "process_path_depth",
            "process_name_length_log",
            "process_exe_length_log",
            "is_system_binary",
            "is_user_binary",
            "has_parent_pid",
        }
    }
    socket_bridge = {
        "log_socket_neighbors",
        "log_matched_socket_address",
        "log_matched_socket_port",
        "log_matched_socket_both",
        "max_socket_time_proximity",
        "operation_connect",
    }
    temporal_degree = {
        "time_proximity",
        "log_closest_abs_time_delta",
        "degree_score",
        "recency_degree_score",
        "log_incident_edge_count",
        "log_in_degree",
        "log_out_degree",
        "in_degree_fraction",
    }
    return {
        "process_semantics": process_semantics,
        "socket_bridge": socket_bridge,
        "temporal_degree": temporal_degree,
    }


def configurations() -> dict[str, set[str]]:
    names = set(feature_names())
    groups = feature_groups()
    return {
        "full": names,
        "without_process_semantics": names - groups["process_semantics"],
        "without_socket_bridge": names - groups["socket_bridge"],
        "temporal_degree_only": groups["temporal_degree"],
        "process_semantics_only": groups["process_semantics"],
    }


def fit_logistic(x: np.ndarray, y: np.ndarray, weights: np.ndarray) -> Any:
    model = Pipeline(
        [
            ("scale", StandardScaler()),
            ("classifier", LogisticRegression(C=1.0, max_iter=2000, solver="liblinear", random_state=11)),
        ]
    )
    model.fit(x, y, classifier__sample_weight=weights)
    return model


def run(
    inputs_path: Path,
    truth_path: Path,
    output_dir: Path,
    top_ks: tuple[int, ...],
) -> dict[str, Any]:
    inputs = {item["case_id"]: item for item in load_jsonl(inputs_path)}
    truths = {item["case_id"]: item for item in load_jsonl(truth_path)}
    if set(inputs) != set(truths):
        raise ValueError("input and truth case ID sets differ")
    extracted = {case_id: extract_case(case) for case_id, case in inputs.items()}
    all_names = feature_names()
    configs = configurations()
    rows: list[dict[str, Any]] = []

    for fold in (1, 2, 3):
        x_train, y_train, weights, _ = training_data(inputs, truths, extracted, fold)
        for config_name, selected_names in configs.items():
            indices = [index for index, name in enumerate(all_names) if name in selected_names]
            if not indices:
                raise ValueError(f"empty ablation: {config_name}")
            model = fit_logistic(x_train[:, indices], y_train, weights)
            for case_id in sorted(inputs):
                if membership(truths[case_id], fold)["partition"] != "test":
                    continue
                entity_ids, matrix = extracted[case_id]
                scores = model.predict_proba(matrix[:, indices])[:, 1]
                row = ranking_row(
                    case_id,
                    truths[case_id],
                    entity_ids,
                    scores,
                    config_name,
                    11,
                    fold,
                    top_ks,
                )
                row["configuration"] = config_name
                rows.append(row)

    result_summaries: dict[str, Any] = {}
    for config_name, selected_names in configs.items():
        material = [row for row in rows if row["configuration"] == config_name]
        result_summaries[config_name] = {
            "feature_count": len(selected_names),
            "features": sorted(selected_names),
            "overall": summarize(material, top_ks),
            "in_support": summarize(
                [row for row in material if row["support_role"] == "in_support"], top_ks
            ),
            "by_test_fold": {
                str(fold): summarize(
                    [row for row in material if int(row["test_fold"]) == fold], top_ks
                )
                for fold in (1, 2, 3)
            },
        }

    output_dir.mkdir(parents=True, exist_ok=True)
    per_case_path = output_dir / "stage_b_feature_ablation.per_case.csv"
    with per_case_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    result = {
        "schema_version": "1.0",
        "experiment": "EviGate-APT Stage-B fixed feature ablation",
        "model": "case-balanced logistic ranker",
        "top_ks": list(top_ks),
        "feature_groups": {name: sorted(values) for name, values in feature_groups().items()},
        "results": result_summaries,
        "source_files": {
            "inputs": {"path": inputs_path.as_posix(), "sha256": sha256_file(inputs_path)},
            "truth": {"path": truth_path.as_posix(), "sha256": sha256_file(truth_path)},
        },
        "output_files": {
            "per_case": {"path": per_case_path.as_posix(), "sha256": sha256_file(per_case_path)}
        },
        "interpretation_rule": "Ablations diagnose association, not causal feature importance. Full-minus-group changes are reported without post-hoc retuning.",
    }
    summary_path = output_dir / "stage_b_feature_ablation.summary.json"
    summary_path.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"summary": summary_path.as_posix(), "results": result_summaries}, indent=2))
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--top-k", type=int, nargs="+", default=[1, 5, 10])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run(args.inputs, args.truth, args.output_dir, tuple(sorted(set(args.top_k))))


if __name__ == "__main__":
    main()
