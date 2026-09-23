#!/usr/bin/env python3
"""Run frozen Stage-B semantic masking and malicious-process-family holdout audits."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path, PurePosixPath
from statistics import mean, median
from typing import Any, Iterable

import numpy as np
from sklearn.model_selection import GroupKFold

from evaluate_stage_b_retrieval_baselines import summarize
from run_stage_b_feature_ablation import fit_logistic
from run_stage_b_typed_ranker import (
    extract_case,
    feature_names,
    load_jsonl,
    membership,
    ranking_row,
    sha256_file,
)


DESCRIPTOR_FEATURES = {
    "process_path_depth",
    "process_name_length_log",
    "process_exe_length_log",
    "is_system_binary",
    "is_user_binary",
    "has_parent_pid",
}


def shortcut_configurations() -> dict[str, set[str]]:
    """Return the feature masks frozen in the Stage-4 analysis protocol."""
    names = set(feature_names())
    utility = {name for name in names if name.startswith("utility_")}
    return {
        "full": names,
        "without_utility_indicators": names - utility,
        "without_path_length_parent": names - DESCRIPTOR_FEATURES,
        "without_all_process_semantics": names - utility - DESCRIPTOR_FEATURES,
    }


def truth_process_family(case_input: dict[str, Any], truth: dict[str, Any]) -> str:
    """Build an audit-only family from names/basenames of true candidate processes."""
    truth_ids = set(
        truth["provenance_ground_truth"]["malicious_candidate_process_ids"]
    )
    descriptors: set[str] = set()
    for entity in case_input["provenance_candidate_graph"]["entities"]:
        if entity["entity_id"] not in truth_ids or entity["entity_kind"] != "process":
            continue
        attributes = entity.get("attributes", {})
        name = str(attributes.get("name", "")).strip().lower()
        exe = str(attributes.get("exe", "")).strip().lower()
        basename = PurePosixPath(exe).name if exe else ""
        descriptor = "|".join(part for part in (name, basename) if part)
        if descriptor:
            descriptors.add(descriptor)
    if not descriptors:
        return f"missing_truth:{case_input['case_id']}"
    return ";".join(sorted(descriptors))


def truth_command_line_audit(
    inputs: dict[str, dict[str, Any]], truths: dict[str, dict[str, Any]]
) -> dict[str, int]:
    total = 0
    nonempty = 0
    for case_id, case_input in inputs.items():
        truth_ids = set(
            truths[case_id]["provenance_ground_truth"][
                "malicious_candidate_process_ids"
            ]
        )
        for entity in case_input["provenance_candidate_graph"]["entities"]:
            if entity["entity_id"] in truth_ids and entity["entity_kind"] == "process":
                total += 1
                nonempty += int(bool(str(entity.get("attributes", {}).get("cmdline", "")).strip()))
    return {"truth_process_entities": total, "nonempty_truth_process_cmdlines": nonempty}


def family_test_folds(families: dict[str, str], n_splits: int = 3) -> dict[str, int]:
    """Assign every family to one test fold with no cross-fold family overlap."""
    case_ids = sorted(families)
    groups = np.asarray([families[case_id] for case_id in case_ids], dtype=object)
    splitter = GroupKFold(n_splits=n_splits)
    assignments: dict[str, int] = {}
    dummy = np.zeros((len(case_ids), 1), dtype=float)
    for fold, (_, test_indices) in enumerate(splitter.split(dummy, groups=groups), start=1):
        for index in test_indices:
            assignments[case_ids[int(index)]] = fold
    if len(assignments) != len(case_ids):
        raise AssertionError("each case must receive exactly one family-holdout test fold")
    by_family: dict[str, set[int]] = {}
    for case_id, family in families.items():
        by_family.setdefault(family, set()).add(assignments[case_id])
    if any(len(folds) != 1 for folds in by_family.values()):
        raise AssertionError("a malicious-process family crosses test folds")
    return assignments


def training_data_for_ids(
    case_ids: Iterable[str],
    inputs: dict[str, dict[str, Any]],
    truths: dict[str, dict[str, Any]],
    extracted: dict[str, tuple[list[str], np.ndarray]],
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, int]]:
    matrices: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    weights: list[np.ndarray] = []
    audit = Counter()
    for case_id in sorted(case_ids):
        if truths[case_id]["event"]["support_role"] != "in_support":
            audit["excluded_out_of_support_cases"] += 1
            continue
        entity_ids, matrix = extracted[case_id]
        truth_ids = set(
            truths[case_id]["provenance_ground_truth"][
                "malicious_candidate_process_ids"
            ]
        )
        y = np.asarray([int(entity_id in truth_ids) for entity_id in entity_ids], dtype=int)
        if not np.any(y):
            audit["excluded_cases_without_candidate_truth"] += 1
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
        audit["included_cases"] += 1
        audit["positive_entities"] += positives
        audit["negative_entities"] += negatives
    if not matrices:
        raise ValueError("no eligible process-ranking training cases")
    return np.vstack(matrices), np.concatenate(labels), np.concatenate(weights), dict(audit)


def tie_summary(rows: list[dict[str, Any]]) -> dict[str, float | int]:
    sizes = [int(row["best_truth_score_tie_size"]) for row in rows if int(row["truth_present"])]
    if not sizes:
        return {
            "truth_present_cases": 0,
            "mean_best_truth_tie_size": 0.0,
            "median_best_truth_tie_size": 0.0,
            "p95_best_truth_tie_size": 0.0,
            "fraction_best_truth_tie_size_gt_1": 0.0,
        }
    return {
        "truth_present_cases": len(sizes),
        "mean_best_truth_tie_size": float(mean(sizes)),
        "median_best_truth_tie_size": float(median(sizes)),
        "p95_best_truth_tie_size": float(np.percentile(sizes, 95)),
        "fraction_best_truth_tie_size_gt_1": float(np.mean(np.asarray(sizes) > 1)),
    }


def summarize_protocol(
    rows: list[dict[str, Any]], configurations: Iterable[str], top_ks: tuple[int, ...]
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for configuration in configurations:
        selected = [row for row in rows if row["configuration"] == configuration]
        output[configuration] = {
            "overall": summarize(selected, top_ks),
            "in_support": summarize(
                [row for row in selected if row["support_role"] == "in_support"],
                top_ks,
            ),
            "ties": tie_summary(selected),
            "by_test_fold": {
                str(fold): summarize(
                    [row for row in selected if int(row["test_fold"]) == fold],
                    top_ks,
                )
                for fold in (1, 2, 3)
            },
        }
    return output


def run(
    inputs_path: Path,
    truth_path: Path,
    output_dir: Path,
    top_ks: tuple[int, ...],
    seed: int,
) -> dict[str, Any]:
    inputs = {item["case_id"]: item for item in load_jsonl(inputs_path)}
    truths = {item["case_id"]: item for item in load_jsonl(truth_path)}
    if set(inputs) != set(truths):
        raise ValueError("input and truth case ID sets differ")
    extracted = {case_id: extract_case(case) for case_id, case in inputs.items()}
    all_names = feature_names()
    configs = shortcut_configurations()
    rows: list[dict[str, Any]] = []
    fixed_training_audit: list[dict[str, Any]] = []

    for fold in (1, 2, 3):
        train_ids = [
            case_id
            for case_id in sorted(inputs)
            if membership(truths[case_id], fold)["partition"] == "train"
        ]
        x_train, y_train, weights, audit = training_data_for_ids(
            train_ids, inputs, truths, extracted
        )
        fixed_training_audit.append({"fold": fold, **audit})
        for config_name, selected_names in configs.items():
            indices = [index for index, name in enumerate(all_names) if name in selected_names]
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
                    f"fixed_split:{config_name}",
                    seed,
                    fold,
                    top_ks,
                )
                row.update(
                    {
                        "protocol": "fixed_original_split",
                        "configuration": config_name,
                        "truth_process_family": "",
                    }
                )
                rows.append(row)

    families = {
        case_id: truth_process_family(inputs[case_id], truths[case_id])
        for case_id in sorted(inputs)
    }
    family_folds = family_test_folds(families)
    family_configs = {
        name: configs[name] for name in ("full", "without_all_process_semantics")
    }
    family_training_audit: list[dict[str, Any]] = []
    for fold in (1, 2, 3):
        train_ids = [case_id for case_id in sorted(inputs) if family_folds[case_id] != fold]
        test_ids = [case_id for case_id in sorted(inputs) if family_folds[case_id] == fold]
        x_train, y_train, weights, audit = training_data_for_ids(
            train_ids, inputs, truths, extracted
        )
        train_families = {families[case_id] for case_id in train_ids}
        test_families = {families[case_id] for case_id in test_ids}
        if train_families & test_families:
            raise AssertionError("family holdout leakage")
        family_training_audit.append(
            {
                "fold": fold,
                "train_cases_total": len(train_ids),
                "test_cases_total": len(test_ids),
                "train_families": len(train_families),
                "test_families": len(test_families),
                **audit,
            }
        )
        for config_name, selected_names in family_configs.items():
            indices = [index for index, name in enumerate(all_names) if name in selected_names]
            model = fit_logistic(x_train[:, indices], y_train, weights)
            for case_id in test_ids:
                entity_ids, matrix = extracted[case_id]
                scores = model.predict_proba(matrix[:, indices])[:, 1]
                row = ranking_row(
                    case_id,
                    truths[case_id],
                    entity_ids,
                    scores,
                    f"family_holdout:{config_name}",
                    seed,
                    fold,
                    top_ks,
                )
                row.update(
                    {
                        "protocol": "malicious_process_family_groupkfold",
                        "configuration": config_name,
                        "truth_process_family": families[case_id],
                    }
                )
                rows.append(row)

    fixed_rows = [row for row in rows if row["protocol"] == "fixed_original_split"]
    family_rows = [
        row for row in rows if row["protocol"] == "malicious_process_family_groupkfold"
    ]
    family_counts = Counter(families.values())
    result = {
        "schema_version": "1.0",
        "experiment": "EviGate-APT Stage-B process-semantic shortcut audit",
        "seed": seed,
        "top_ks": list(top_ks),
        "fixed_split": {
            "configurations": {name: sorted(values) for name, values in configs.items()},
            "training_audit": fixed_training_audit,
            "results": summarize_protocol(fixed_rows, configs, top_ks),
        },
        "malicious_process_family_holdout": {
            "definition": "sorted unique lower-cased truth-process name|executable-basename descriptors; audit split only",
            "group_count": len(family_counts),
            "largest_group_cases": max(family_counts.values()),
            "largest_group_fraction": max(family_counts.values()) / len(families),
            "group_counts": dict(sorted(family_counts.items(), key=lambda item: (-item[1], item[0]))),
            "test_fold_case_counts": dict(Counter(map(str, family_folds.values()))),
            "training_audit": family_training_audit,
            "results": summarize_protocol(family_rows, family_configs, top_ks),
        },
        "truth_text_audit": truth_command_line_audit(inputs, truths),
        "source_files": {
            "inputs": {"path": inputs_path.as_posix(), "sha256": sha256_file(inputs_path)},
            "truth": {"path": truth_path.as_posix(), "sha256": sha256_file(truth_path)},
        },
        "interpretation_limits": [
            "The family key uses ground truth only for split construction and is never an inference feature.",
            "Family holdout is a campaign-internal shortcut stress test, not cross-campaign validation.",
            "Command-line family grouping is unavailable when truth-process command lines are empty.",
            "No configuration is selected after viewing test results.",
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    per_case_path = output_dir / "stage_b_shortcut_audit.per_case.csv"
    with per_case_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    result["output_files"] = {
        "per_case": {"path": per_case_path.as_posix(), "sha256": sha256_file(per_case_path)}
    }
    summary_path = output_dir / "stage_b_shortcut_audit.summary.json"
    summary_path.write_text(
        json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"summary": summary_path.as_posix(), "results": result}, indent=2))
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--top-k", type=int, nargs="+", default=[1, 5, 10])
    parser.add_argument("--seed", type=int, default=11)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run(
        args.inputs,
        args.truth,
        args.output_dir,
        tuple(sorted(set(args.top_k))),
        args.seed,
    )


if __name__ == "__main__":
    main()
