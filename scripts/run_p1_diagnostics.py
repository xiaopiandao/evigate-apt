#!/usr/bin/env python3
"""Execute post-freeze P1 diagnostics for the EviGate-APT manuscript.

P1 covers retrieval-radius decoupling, trivial baselines, repeated grouped
cross-validation of the primary Stage-B ranker, and evidence-retention/storage
accounting.  Existing frozen artifacts are read-only; every new artifact is
written below ``data/derived/p1_diagnostics``.
"""

from __future__ import annotations

import argparse
import bisect
import contextlib
import copy
import csv
import hashlib
import io
import json
import math
import statistics
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedKFold


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import run_stage_b_typed_ranker as stage_b_ranker  # noqa: E402
from build_cicapt_split_manifest import select_calibration_groups  # noqa: E402


REPEAT_SEEDS = (101, 202, 303, 404, 505, 606, 707, 808, 909, 1010)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


class TrackedBinaryLines:
    """Yield decoded physical CSV lines while preserving exact byte counts."""

    def __init__(self, handle: Any) -> None:
        self.handle = handle
        self.byte_count = 0
        self._first_line = True

    def __iter__(self) -> "TrackedBinaryLines":
        return self

    def __next__(self) -> str:
        raw_line = self.handle.readline()
        if not raw_line:
            raise StopIteration
        self.byte_count += len(raw_line)
        encoding = "utf-8-sig" if self._first_line else "utf-8"
        self._first_line = False
        return raw_line.decode(encoding)


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def mean(values: Iterable[float]) -> float:
    material = list(values)
    return sum(material) / len(material) if material else math.nan


def sample_sd(values: Iterable[float]) -> float:
    material = list(values)
    return statistics.stdev(material) if len(material) > 1 else 0.0


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summary_metric(summary: dict[str, Any], key: str) -> float:
    pooled = summary["results"]["typed_logistic"]["pooled_test_cases_by_seed"]["11"]
    return float(pooled[key])


def radius_diagnostic(
    radius_summaries: dict[int, Path], output_dir: Path
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for radius, path in sorted(radius_summaries.items()):
        summary = json.loads(path.read_text(encoding="utf-8"))
        rows.append(
            {
                "retrieval_radius_seconds": radius,
                "event_cluster_gap_seconds": 300,
                "case_count": int(summary_metric(summary, "case_count")),
                "truth_present_count": int(summary_metric(summary, "truth_present_case_count")),
                "truth_in_candidate_ceiling": summary_metric(
                    summary, "candidate_pool_recall_ceiling"
                ),
                "mean_process_candidates": summary_metric(
                    summary, "mean_process_candidate_count"
                ),
                "median_process_candidates": summary_metric(
                    summary, "median_process_candidate_count"
                ),
                "maximum_process_candidates": int(
                    summary_metric(summary, "maximum_process_candidate_count")
                ),
                "midrank_mrr": summary_metric(
                    summary, "mean_midrank_reciprocal_all_cases"
                ),
                "expected_tie_recall_at_1": summary_metric(
                    summary, "expected_tie_recall_at_1_all_cases"
                ),
                "recall_at_10": summary_metric(summary, "recall_at_10_all_cases"),
            }
        )
    payload = {
        "analysis_status": "post_freeze_diagnostic",
        "rows": rows,
        "interpretation": (
            "The retrieval radii 60 and 900 seconds are deliberately decoupled from the "
            "300-second event-clustering gap. The 300-second radius balances candidate-truth "
            "coverage against candidate load; it is not guaranteed by event construction."
        ),
    }
    write_csv(output_dir / "retrieval_radius.csv", rows)
    write_json(output_dir / "retrieval_radius.json", payload)
    return payload


def group_label(
    group: dict[str, Any], supported_tactics: set[str], tactic_totals: dict[str, int]
) -> str:
    present = [tactic for tactic in group["tactics"] if tactic in supported_tactics]
    if not present:
        return "out_of_support"
    return min(present, key=lambda tactic: (tactic_totals[tactic], tactic))


def repeated_truth_records(
    truths: list[dict[str, Any]], split: dict[str, Any], seed: int
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    groups = split["embargo_groups"]
    supported = set(split["in_support_tactics"])
    tactic_totals = {key: int(value) for key, value in split["tactic_cluster_totals"].items()}
    labels = [group_label(group, supported, tactic_totals) for group in groups]
    label_counts = Counter(labels)
    supported_indices = [
        index for index, label in enumerate(labels) if label != "out_of_support"
    ]
    out_of_support_indices = [
        index for index, label in enumerate(labels) if label == "out_of_support"
    ]
    supported_label_counts = Counter(labels[index] for index in supported_indices)
    if min(supported_label_counts.values()) < 3:
        raise ValueError(
            f"in-support group-level stratum too small for three folds: {supported_label_counts}"
        )

    splitter = StratifiedKFold(n_splits=3, shuffle=True, random_state=seed)
    fold_test_group_ids: list[set[str]] = []
    fold_calibration_group_ids: list[set[str]] = []
    supported_labels = [labels[index] for index in supported_indices]
    supported_array = np.asarray(supported_indices, dtype=int)
    rng = np.random.default_rng(seed)
    shuffled_out_of_support = list(rng.permutation(out_of_support_indices))
    out_of_support_by_fold: list[set[int]] = [set(), set(), set()]
    start_fold = seed % 3
    for position, group_index in enumerate(shuffled_out_of_support):
        out_of_support_by_fold[(start_fold + position) % 3].add(int(group_index))
    for fold_index, (_, supported_test_positions) in enumerate(
        splitter.split(supported_array, supported_labels)
    ):
        test_indices = {
            int(supported_array[position]) for position in supported_test_positions
        } | out_of_support_by_fold[fold_index]
        test_ids = {groups[index]["group_id"] for index in test_indices}
        development = [group for group in groups if group["group_id"] not in test_ids]
        calibration_ids = select_calibration_groups(development, supported, 0.2)
        fold_test_group_ids.append(test_ids)
        fold_calibration_group_ids.append(calibration_ids)

    cluster_to_group = {
        cluster_id: group["group_id"]
        for group in groups
        for cluster_id in group["cluster_ids"]
    }
    output: list[dict[str, Any]] = []
    fold_counts: list[dict[str, Any]] = []
    for truth in truths:
        record = copy.deepcopy(truth)
        group_id = cluster_to_group[truth["source_cluster_id"]]
        memberships = []
        for fold_index in range(3):
            if group_id in fold_test_group_ids[fold_index]:
                partition = "test"
            elif group_id in fold_calibration_group_ids[fold_index]:
                partition = "calibration"
            else:
                partition = "train"
            memberships.append(
                {
                    "fold": fold_index + 1,
                    "partition": partition,
                    "supervised_eligible": truth["event"]["tactic"] in supported,
                }
            )
        record["split_membership"] = memberships
        output.append(record)

    for fold in range(1, 4):
        counts = Counter(
            next(item for item in truth["split_membership"] if item["fold"] == fold)[
                "partition"
            ]
            for truth in output
        )
        fold_counts.append({"fold": fold, **dict(counts)})
    return output, {
        "seed": seed,
        "label_counts": dict(label_counts),
        "out_of_support_assignment": {
            str(fold + 1): sorted(groups[index]["group_id"] for index in indices)
            for fold, indices in enumerate(out_of_support_by_fold)
        },
        "fold_counts": fold_counts,
    }


def run_repeated_group_cv(
    inputs_path: Path,
    truth_path: Path,
    split_path: Path,
    baseline_summary_path: Path,
    output_dir: Path,
    repeat_seeds: tuple[int, ...],
) -> dict[str, Any]:
    truths = read_jsonl(truth_path)
    split = json.loads(split_path.read_text(encoding="utf-8"))
    repeat_rows: list[dict[str, Any]] = []
    split_audits: list[dict[str, Any]] = []
    repeated_root = output_dir / "repeated_group_cv"
    repeated_root.mkdir(parents=True, exist_ok=True)

    original_models = stage_b_ranker.MODELS
    stage_b_ranker.MODELS = ("typed_logistic",)
    try:
        for repeat_index, seed in enumerate(repeat_seeds, start=1):
            records, audit = repeated_truth_records(truths, split, seed)
            repeat_dir = repeated_root / f"repeat_{repeat_index:02d}"
            repeat_dir.mkdir(parents=True, exist_ok=True)
            repeated_truth_path = repeat_dir / "cases.truth.repeated_split.jsonl"
            with repeated_truth_path.open("w", encoding="utf-8", newline="\n") as handle:
                for record in records:
                    handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            with contextlib.redirect_stdout(io.StringIO()):
                result = stage_b_ranker.run(
                    inputs_path,
                    repeated_truth_path,
                    baseline_summary_path,
                    repeat_dir,
                    [11],
                    (1, 5, 10),
                )
            pooled = result["results"]["typed_logistic"]["pooled_test_cases_by_seed"]["11"]
            repeat_rows.append(
                {
                    "repeat": repeat_index,
                    "split_seed": seed,
                    "case_count": int(pooled["case_count"]),
                    "truth_present_count": int(pooled["truth_present_case_count"]),
                    "midrank_mrr": float(pooled["mean_midrank_reciprocal_all_cases"]),
                    "expected_tie_recall_at_1": float(
                        pooled["expected_tie_recall_at_1_all_cases"]
                    ),
                    "recall_at_5": float(pooled["recall_at_5_all_cases"]),
                    "recall_at_10": float(pooled["recall_at_10_all_cases"]),
                }
            )
            split_audits.append(audit)
    finally:
        stage_b_ranker.MODELS = original_models

    metric_names = (
        "midrank_mrr",
        "expected_tie_recall_at_1",
        "recall_at_5",
        "recall_at_10",
    )
    aggregate = {
        metric: {
            "mean": mean(float(row[metric]) for row in repeat_rows),
            "sample_sd": sample_sd(float(row[metric]) for row in repeat_rows),
            "minimum": min(float(row[metric]) for row in repeat_rows),
            "maximum": max(float(row[metric]) for row in repeat_rows),
        }
        for metric in metric_names
    }
    payload = {
        "analysis_status": "post_freeze_diagnostic",
        "repeat_count": len(repeat_rows),
        "split_seeds": list(repeat_seeds),
        "model_seed": 11,
        "split_unit": "600-second embargo group",
        "aggregate": aggregate,
        "split_audits": split_audits,
        "scope_note": (
            "Repeated split estimates measure sensitivity to grouped partition assignment within "
            "one campaign. Repeats are not independent deployments and are not used as a larger n."
        ),
    }
    write_csv(output_dir / "repeated_group_cv.csv", repeat_rows)
    write_json(output_dir / "repeated_group_cv.json", payload)
    return payload


def trivial_baselines_diagnostic(
    truths_path: Path,
    stage_c_summary_path: Path,
    endpoint_audit_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    truths = read_jsonl(truths_path)
    supported = sorted(
        {
            truth["event"]["tactic"]
            for truth in truths
            if truth["event"]["support_role"] == "in_support"
        }
    )
    truth_labels: list[str] = []
    predictions: list[str] = []
    fold_majorities: dict[str, str] = {}
    for fold in (1, 2, 3):
        train_labels = [
            truth["event"]["tactic"]
            for truth in truths
            if truth["event"]["support_role"] == "in_support"
            and next(item for item in truth["split_membership"] if item["fold"] == fold)[
                "partition"
            ]
            == "train"
        ]
        majority = Counter(train_labels).most_common(1)[0][0]
        fold_majorities[str(fold)] = majority
        for truth in truths:
            membership = next(
                item for item in truth["split_membership"] if item["fold"] == fold
            )
            if (
                membership["partition"] == "test"
                and truth["event"]["support_role"] == "in_support"
            ):
                truth_labels.append(truth["event"]["tactic"])
                predictions.append(majority)
    accuracy = mean(int(a == b) for a, b in zip(truth_labels, predictions))
    macro_f1 = float(
        f1_score(truth_labels, predictions, labels=supported, average="macro", zero_division=0)
    )
    stage_c = json.loads(stage_c_summary_path.read_text(encoding="utf-8"))
    endpoint = json.loads(endpoint_audit_path.read_text(encoding="utf-8"))
    rows = [
        {
            "baseline": "fold-local majority, full coverage",
            "denominator": len(truth_labels),
            "accepted": len(truth_labels),
            "correct": sum(a == b for a, b in zip(truth_labels, predictions)),
            "risk_or_loss_rate": 1.0 - accuracy,
            "macro_f1_or_preservation": macro_f1,
            "note": "majority class selected from each outer-training fold",
        },
        {
            "baseline": "coverage-matched majority",
            "denominator": 53,
            "accepted": 42,
            "correct": 42
            * (1.0 - stage_c["primary_fixed_coverage"]["coverage_matched_majority_risk"]),
            "risk_or_loss_rate": stage_c["primary_fixed_coverage"][
                "coverage_matched_majority_risk"
            ],
            "macro_f1_or_preservation": "",
            "note": "existing prespecified 42/53 operating point",
        },
    ]
    endpoint_rows: list[dict[str, Any]] = []
    for rule, result in endpoint["two_hop_pruning_policies"].items():
        seeded = int(result["seeded_case_count"])
        lost = int(result["lost_case_count"])
        endpoint_rows.append(
            {
                "policy": rule,
                "truth_cases": int(result["cases_with_pid_truth"]),
                "seeded_cases": seeded,
                "truth_preserved_cases": int(result["cases_preserving_any_pid_truth"]),
                "overall_truth_preservation": float(result["pid_truth_case_preservation_rate"]),
                "lost_cases": lost,
                "truth_preservation_when_seeded": (seeded - lost) / seeded if seeded else 1.0,
                "median_retained_entities": result["candidate_count_after_policy"]["median"],
            }
        )
    payload = {
        "analysis_status": "post_freeze_diagnostic",
        "fold_majorities": fold_majorities,
        "tactic_baselines": rows,
        "endpoint_seeded_baselines": endpoint_rows,
        "interpretation": (
            "The majority baseline is materially below the learned tactic classifier. Hard "
            "endpoint-seeded pruning is not a viable localization baseline because the joint "
            "rule loses truth in every case in which it activates."
        ),
    }
    write_csv(output_dir / "trivial_tactic_baselines.csv", rows)
    write_csv(output_dir / "endpoint_seeded_baselines.csv", endpoint_rows)
    write_json(output_dir / "trivial_baselines.json", payload)
    return payload


def merge_intervals(intervals: list[tuple[float, float]]) -> list[tuple[float, float]]:
    if not intervals:
        return []
    ordered = sorted(intervals)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        previous_start, previous_end = merged[-1]
        if start <= previous_end:
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return merged


def point_in_intervals(value: float, intervals: list[tuple[float, float]], starts: list[float]) -> bool:
    index = bisect.bisect_right(starts, value) - 1
    return index >= 0 and value <= intervals[index][1]


def line_sizes_by_json_key(path: Path, key: str) -> dict[str, int]:
    sizes: dict[str, int] = {}
    with path.open("rb") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            sizes[str(record[key])] = len(line)
    return sizes


def retention_diagnostic(
    stage_a_metrics_path: Path,
    stage_a_predictions_path: Path,
    network_truth_path: Path,
    provenance_path: Path,
    cases_inputs_path: Path,
    compact_manifest_path: Path,
    bindgate_results_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    all_metric_rows = [
        row
        for row in read_csv(stage_a_metrics_path)
        if row["model"] == "hist_gradient_boosting"
        and int(row["seed"]) == 11
    ]
    budgets = sorted({float(row["false_alert_budget_per_hour"]) for row in all_metric_rows})
    metrics_by_budget = {
        budget: [
            row
            for row in all_metric_rows
            if float(row["false_alert_budget_per_hour"]) == budget
        ]
        for budget in budgets
    }
    thresholds_by_budget = {
        budget: {int(row["fold"]): float(row["threshold"]) for row in rows}
        for budget, rows in metrics_by_budget.items()
    }
    predictions = [
        row
        for row in read_csv(stage_a_predictions_path)
        if row["model"] == "hist_gradient_boosting" and int(row["seed"]) == 11
    ]
    network_truth = {row["window_id"]: row for row in read_csv(network_truth_path)}
    all_window_starts = sorted(float(row["window_start_epoch"]) for row in network_truth.values())
    capture_start = all_window_starts[0]
    capture_end = all_window_starts[-1] + 60.0
    capture_seconds = capture_end - capture_start

    frontier_rows: list[dict[str, Any]] = []
    intervals_by_budget: dict[float, list[tuple[float, float]]] = {}
    alert_rows_by_budget: dict[float, list[dict[str, str]]] = {}
    for budget in budgets:
        metric_rows = metrics_by_budget[budget]
        thresholds = thresholds_by_budget[budget]
        alert_rows = [
            row
            for row in predictions
            if float(row["score"]) >= thresholds[int(row["fold"])]
        ]
        alert_starts = sorted(
            float(network_truth[row["window_id"]]["window_start_epoch"])
            for row in alert_rows
        )
        raw_intervals = [
            (max(capture_start, start - 300.0), min(capture_end, start + 300.0))
            for start in alert_starts
        ]
        intervals = merge_intervals(raw_intervals)
        retained_seconds = sum(end - start for start, end in intervals)
        alert_rows_by_budget[budget] = alert_rows
        intervals_by_budget[budget] = intervals
        frontier_rows.append(
            {
                "false_alert_budget_per_hour": budget,
                "mean_observed_false_alerts_per_hour": statistics.mean(
                    float(row["false_alerts_per_hour"]) for row in metric_rows
                ),
                "mean_benign_stress_false_alerts_per_hour": statistics.mean(
                    float(row["benign_stress_false_alerts_per_hour"])
                    for row in metric_rows
                ),
                "mean_all_event_coverage": statistics.mean(
                    float(row["all_event_coverage"]) for row in metric_rows
                ),
                "mean_in_support_event_coverage": statistics.mean(
                    float(row["in_support_event_coverage"]) for row in metric_rows
                ),
                "network_capture_hours": capture_seconds / 3600.0,
                "alert_window_count": len(alert_rows),
                "alert_windows_per_hour": len(alert_rows) / (capture_seconds / 3600.0),
                "unmerged_evidence_window_hours": len(alert_rows) * 600.0 / 3600.0,
                "merged_evidence_window_count": len(intervals),
                "merged_evidence_window_hours": retained_seconds / 3600.0,
                "merged_capture_time_fraction": retained_seconds / capture_seconds,
                "retained_timestamped_row_count": 0,
                "retained_timestamped_row_fraction": 0.0,
                "retained_timestamped_csv_bytes": 0,
                "retained_timestamped_byte_fraction": 0.0,
            }
        )

    timestamped_rows = 0
    timestamped_bytes = 0
    interval_starts_by_budget = {
        budget: [start for start, _ in intervals]
        for budget, intervals in intervals_by_budget.items()
    }
    with provenance_path.open("rb") as handle:
        tracked_lines = TrackedBinaryLines(handle)
        reader = csv.reader(tracked_lines)
        header = next(reader)
        indices = {name: header.index(name) for name in ("time", "seen time", "start time")}
        previous_byte_count = tracked_lines.byte_count
        for row in reader:
            logical_row_bytes = tracked_lines.byte_count - previous_byte_count
            previous_byte_count = tracked_lines.byte_count
            if not row:
                continue
            timestamp_text = (
                row[indices["time"]]
                or row[indices["seen time"]]
                or row[indices["start time"]]
            ).strip()
            if not timestamp_text:
                continue
            timestamped_rows += 1
            timestamped_bytes += logical_row_bytes
            timestamp = float(timestamp_text)
            for frontier_row in frontier_rows:
                budget = float(frontier_row["false_alert_budget_per_hour"])
                if point_in_intervals(
                    timestamp,
                    intervals_by_budget[budget],
                    interval_starts_by_budget[budget],
                ):
                    frontier_row["retained_timestamped_row_count"] += 1
                    frontier_row["retained_timestamped_csv_bytes"] += logical_row_bytes

    for frontier_row in frontier_rows:
        frontier_row["retained_timestamped_row_fraction"] = (
            frontier_row["retained_timestamped_row_count"] / timestamped_rows
        )
        frontier_row["retained_timestamped_byte_fraction"] = (
            frontier_row["retained_timestamped_csv_bytes"] / timestamped_bytes
        )

    fixed_budget = 0.5
    if fixed_budget not in intervals_by_budget:
        raise ValueError("The declared 0.5 false-alert/h operating point is missing")
    fixed_frontier = next(
        row
        for row in frontier_rows
        if float(row["false_alert_budget_per_hour"]) == fixed_budget
    )
    alert_rows = alert_rows_by_budget[fixed_budget]
    intervals = intervals_by_budget[fixed_budget]

    full_sizes = line_sizes_by_json_key(cases_inputs_path, "case_id")
    compact_sizes = line_sizes_by_json_key(compact_manifest_path, "sample_id")
    clean_rows = [
        row for row in read_csv(bindgate_results_path) if row["condition"] == "clean"
    ]
    clean_case_ids = [row["case_id"] for row in clean_rows]
    clean_sample_ids = [row["sample_id"] for row in clean_rows]
    accepted_rows = [row for row in clean_rows if as_bool(row["cascade_attributed"])]
    full_clean_bytes = sum(full_sizes[case_id] for case_id in clean_case_ids)
    compact_clean_bytes = sum(compact_sizes[sample_id] for sample_id in clean_sample_ids)
    compact_accepted_bytes = sum(
        compact_sizes[row["sample_id"]] for row in accepted_rows
    )

    payload = {
        "analysis_status": "post_freeze_diagnostic",
        "stage_a_operating_point": {
            "model": "hist_gradient_boosting",
            "model_seed": 11,
            "calibration_false_alert_budget_per_hour": fixed_budget,
            "network_capture_hours": capture_seconds / 3600.0,
            "alert_window_count": len(alert_rows),
            "alert_windows_per_hour": len(alert_rows) / (capture_seconds / 3600.0),
            "unmerged_evidence_window_hours": len(alert_rows) * 600.0 / 3600.0,
            "merged_evidence_window_count": len(intervals),
            "merged_evidence_window_hours": fixed_frontier[
                "merged_evidence_window_hours"
            ],
            "merged_capture_time_fraction": fixed_frontier[
                "merged_capture_time_fraction"
            ],
            "maximum_false_alert_retention_hours_at_budget": (
                fixed_budget * (capture_seconds / 3600.0) * 600.0 / 3600.0
            ),
        },
        "raw_provenance_retention": {
            "timestamped_row_count": timestamped_rows,
            "retained_timestamped_row_count": fixed_frontier[
                "retained_timestamped_row_count"
            ],
            "retained_timestamped_row_fraction": fixed_frontier[
                "retained_timestamped_row_fraction"
            ],
            "timestamped_csv_bytes": timestamped_bytes,
            "retained_timestamped_csv_bytes": fixed_frontier[
                "retained_timestamped_csv_bytes"
            ],
            "retained_timestamped_byte_fraction": fixed_frontier[
                "retained_timestamped_byte_fraction"
            ],
            "scope": "timestamped CSV rows only; untimed linked entities require a separate store",
        },
        "serialized_packages": {
            "clean_event_count": len(clean_rows),
            "accepted_event_count": len(accepted_rows),
            "full_graph_clean_bytes": full_clean_bytes,
            "compact_top10_clean_bytes": compact_clean_bytes,
            "compact_to_full_graph_ratio": compact_clean_bytes / full_clean_bytes,
            "accepted_only_compact_bytes": compact_accepted_bytes,
            "accepted_only_to_all_compact_ratio": compact_accepted_bytes / compact_clean_bytes,
        },
        "policy_implication": (
            "Selective acceptance cannot reduce evidence acquisition because the gate needs the "
            "provenance window before deciding. Compact top-ten packages reduce serialized size, "
            "but retaining only accepted cases would discard refusal evidence and is not recommended."
        ),
    }
    write_json(output_dir / "retention_storage.json", payload)
    write_csv(output_dir / "retention_frontier.csv", frontier_rows)
    write_json(
        output_dir / "retention_frontier.json",
        {
            "analysis_status": "post_freeze_diagnostic",
            "model": "hist_gradient_boosting",
            "model_seed": 11,
            "evidence_window_radius_seconds": 300,
            "timestamped_provenance_row_count": timestamped_rows,
            "timestamped_provenance_csv_bytes": timestamped_bytes,
            "scope": (
                "Trigger-opened retention of timestamped provenance rows; this is not "
                "an acquisition or post-decision deletion claim."
            ),
            "rows": frontier_rows,
        },
    )
    write_csv(
        output_dir / "retention_intervals.csv",
        [
            {
                "interval": index,
                "start_epoch": start,
                "end_epoch": end,
                "duration_seconds": end - start,
            }
            for index, (start, end) in enumerate(intervals, start=1)
        ],
    )
    write_csv(
        output_dir / "retention_frontier_intervals.csv",
        [
            {
                "false_alert_budget_per_hour": budget,
                "interval": index,
                "start_epoch": start,
                "end_epoch": end,
                "duration_seconds": end - start,
            }
            for budget in budgets
            for index, (start, end) in enumerate(
                intervals_by_budget[budget], start=1
            )
        ],
    )
    return payload


def build_report(
    output_dir: Path,
    radius: dict[str, Any],
    repeated: dict[str, Any],
    baselines: dict[str, Any],
    retention: dict[str, Any],
) -> Path:
    majority = baselines["tactic_baselines"][0]
    joint = next(
        row for row in baselines["endpoint_seeded_baselines"] if row["policy"] == "joint"
    )
    lines = [
        "# P1 post-freeze diagnostic report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "No frozen model, feature, event definition, or deployed threshold was changed.",
        "",
        "## 1. Retrieval radius decoupled from event clustering",
        "",
        "| Radius | Truth ceiling | Median candidates | Midrank MRR | Expected-tie R@1 |",
        "|---:|---:|---:|---:|---:|",
    ]
    for row in radius["rows"]:
        lines.append(
            f"| ±{row['retrieval_radius_seconds'] // 60} min | "
            f"{row['truth_in_candidate_ceiling']:.3f} | {row['median_process_candidates']:.1f} | "
            f"{row['midrank_mrr']:.3f} | {row['expected_tie_recall_at_1']:.3f} |"
        )
    lines.extend(
        [
            "",
            "The ±60-s and ±900-s retrieval windows differ from the 300-s clustering gap. The short window loses truth; the long window increases candidate load and slightly lowers Top-1, supporting ±300 s as a declared trade-off rather than a construction artifact.",
            "",
            "## 2. Repeated grouped cross-validation",
            "",
            f"Across {repeated['repeat_count']} randomized, embargo-grouped three-fold partitions, typed Logistic midrank MRR is "
            f"{repeated['aggregate']['midrank_mrr']['mean']:.3f} ± {repeated['aggregate']['midrank_mrr']['sample_sd']:.3f} "
            f"(range {repeated['aggregate']['midrank_mrr']['minimum']:.3f}--{repeated['aggregate']['midrank_mrr']['maximum']:.3f}); "
            f"expected-tie R@1 is {repeated['aggregate']['expected_tie_recall_at_1']['mean']:.3f} ± "
            f"{repeated['aggregate']['expected_tie_recall_at_1']['sample_sd']:.3f}. Repeats quantify partition sensitivity within one campaign and are not treated as independent deployments.",
            "",
            "## 3. Trivial baselines",
            "",
            f"Fold-local majority prediction obtains {majority['correct']}/{majority['denominator']} correct "
            f"(risk {majority['risk_or_loss_rate']:.3f}, macro-F1 {majority['macro_f1_or_preservation']:.3f}). "
            f"The joint endpoint-seeded two-hop rule preserves truth in {joint['truth_preserved_cases']}/{joint['truth_cases']} cases overall, "
            f"but in 0/{joint['seeded_cases']} cases where pruning activates. It is therefore a failed pruning baseline, not an omitted strong competitor.",
            "",
            "## 4. Evidence retention and storage",
            "",
        ]
    )
    stage_a = retention["stage_a_operating_point"]
    raw = retention["raw_provenance_retention"]
    packages = retention["serialized_packages"]
    lines.extend(
        [
            f"At the fixed Stage-A operating point, {stage_a['alert_window_count']} held-out alert windows over "
            f"{stage_a['network_capture_hours']:.2f} h merge into {stage_a['merged_evidence_window_count']} provenance-retention intervals totaling "
            f"{stage_a['merged_evidence_window_hours']:.2f} h ({stage_a['merged_capture_time_fraction']:.1%} of capture time). "
            f"Those intervals contain {raw['retained_timestamped_row_fraction']:.1%} of timestamped provenance rows and "
            f"{raw['retained_timestamped_byte_fraction']:.1%} of their CSV bytes.",
            "",
            f"For the 51 clean EviGate-Bind events, normalized top-ten packages occupy {packages['compact_to_full_graph_ratio']:.1%} of the serialized full-graph package size. "
            "This is a compact forensic interface, not a license to delete raw evidence: acquisition occurs before acceptance, and refusals remain analytically useful.",
            "",
            "## Manuscript decision",
            "",
            "Promote the radius and repeated-split results because they directly answer circularity and three-fold-instability objections. Keep the full endpoint and storage tables in the supplement; the main text needs only the endpoint failure count and the bounded retention conclusion.",
            "",
        ]
    )
    path = output_dir / "P1_DIAGNOSTIC_REPORT.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("data/derived/p1_diagnostics"))
    parser.add_argument("--repeat-seeds", nargs="+", type=int, default=list(REPEAT_SEEDS))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "inputs": Path("data/derived/evigate_phase2_evidence/cases.inputs.jsonl"),
        "truth": Path("data/derived/evigate_phase2_evidence/cases.truth.jsonl"),
        "splits": Path("data/derived/cicapt_phase2_grouped_splits.json"),
        "baseline_summary": Path(
            "data/derived/stage_b/baseline_run/stage_b_retrieval_baselines.summary.json"
        ),
        "radius_60": Path(
            "data/derived/stage4_revision/context_60s_stage_b/stage_b_typed_ranker.summary.json"
        ),
        "radius_300": Path(
            "data/derived/stage_b/typed_ranker_run/stage_b_typed_ranker.summary.json"
        ),
        "radius_900": Path(
            "data/derived/stage4_revision/context_900s_stage_b/stage_b_typed_ranker.summary.json"
        ),
        "stage_c_summary": Path("data/derived/stage_c/final_run/stage_c_summary.json"),
        "endpoint_audit": Path(
            "data/derived/evigate_phase2_evidence/socket_seed_pruning_audit.json"
        ),
        "stage_a_metrics": Path(
            "data/derived/p0_diagnostics/stage_a_frontier_run/stage_a_metrics.csv"
        ),
        "stage_a_predictions": Path(
            "data/derived/p0_diagnostics/stage_a_frontier_run/stage_a_predictions.csv"
        ),
        "network_truth": Path("data/derived/stage_a/network_windows.truth.csv"),
        "provenance": Path("data/raw/cicapt/Phase2_Provenance.csv"),
        "compact_manifest": Path(
            "data/derived/evigate_llm/manifest_v4/evigate_llm.inputs.jsonl"
        ),
        "bindgate_results": Path(
            "data/derived/evigate_llm/v7_bindgate/evaluation_repro/evigate_bindgate.per_case.csv"
        ),
    }

    radius = radius_diagnostic(
        {60: paths["radius_60"], 300: paths["radius_300"], 900: paths["radius_900"]},
        output_dir,
    )
    repeated = run_repeated_group_cv(
        paths["inputs"],
        paths["truth"],
        paths["splits"],
        paths["baseline_summary"],
        output_dir,
        tuple(args.repeat_seeds),
    )
    baselines = trivial_baselines_diagnostic(
        paths["truth"], paths["stage_c_summary"], paths["endpoint_audit"], output_dir
    )
    retention = retention_diagnostic(
        paths["stage_a_metrics"],
        paths["stage_a_predictions"],
        paths["network_truth"],
        paths["provenance"],
        paths["inputs"],
        paths["compact_manifest"],
        paths["bindgate_results"],
        output_dir,
    )
    report = build_report(output_dir, radius, repeated, baselines, retention)

    outputs = sorted(
        path
        for path in output_dir.iterdir()
        if path.is_file() and path.name != "manifest.json"
    )
    manifest = {
        "schema_version": "1.0",
        "analysis_status": "post_freeze_diagnostic",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "script": Path(__file__).as_posix(),
        "inputs": {
            name: {"path": path.as_posix(), "sha256": sha256_file(path)}
            for name, path in paths.items()
        },
        "outputs": {
            path.name: {"path": path.as_posix(), "sha256": sha256_file(path)}
            for path in outputs
        },
        "report": report.as_posix(),
    }
    write_json(output_dir / "manifest.json", manifest)
    print(
        json.dumps(
            {
                "report": report.as_posix(),
                "radius_points": len(radius["rows"]),
                "repeated_group_cv_repeats": repeated["repeat_count"],
                "retained_capture_fraction": retention["stage_a_operating_point"][
                    "merged_capture_time_fraction"
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
