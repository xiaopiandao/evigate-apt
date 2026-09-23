#!/usr/bin/env python3
"""Build fair posterior-margin comparators for the EviGate-LLM study.

The script reuses frozen per-case outputs.  It does not fit a new classifier or
invoke an LLM.  Two posterior-margin operating points are evaluated:

1. the original clean-calibration threshold; and
2. an exact, fold-stratified clean accepted count matched to EviGate-LLM.

Each operating point is also combined with a deterministic missing-process
rule.  In the synthetic corruption benchmark, ``process_deletion`` is exactly
the transformation for which no process candidates remain, so the offline rule
is equivalent to ``reject when process_candidate_count == 0``.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

import numpy as np


FAMILIES = (
    "process_deletion",
    "socket_type_deletion",
    "time_shift",
    "random_entity_deletion",
    "context_replacement",
)
EVI_METHOD = "evigate_llm"


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def matched_thresholds(
    clean_rows: list[dict[str, str]],
    evigate_clean: list[dict[str, str]],
) -> tuple[dict[int, float], dict[int, int]]:
    """Return fold-specific kth-score thresholds matching EviGate counts."""
    target_by_fold: dict[int, int] = defaultdict(int)
    for row in evigate_clean:
        if as_bool(row["attributed"]):
            target_by_fold[int(row["test_fold"])] += 1

    thresholds: dict[int, float] = {}
    for fold, target in sorted(target_by_fold.items()):
        scores = sorted(
            (
                float(row["margin_score"])
                for row in clean_rows
                if int(row["test_fold"]) == fold
            ),
            reverse=True,
        )
        if target < 1 or target > len(scores):
            raise ValueError(
                f"Invalid matched target for fold {fold}: {target}/{len(scores)}"
            )
        threshold = scores[target - 1]
        realized = sum(score >= threshold for score in scores)
        if realized != target:
            raise ValueError(
                "A tied cutoff prevents exact threshold matching for fold "
                f"{fold}: target={target}, realized={realized}, threshold={threshold}"
            )
        thresholds[fold] = threshold
    return thresholds, dict(target_by_fold)


def base_row(
    method: str,
    row: dict[str, str],
    *,
    condition: str,
    family: str,
    accepted: bool,
    score: float | None,
    rule_applied: bool,
) -> dict[str, Any]:
    correct_prediction = as_bool(row["correct"])
    return {
        "method": method,
        "case_id": row["case_id"],
        "test_fold": int(row["test_fold"]),
        "condition": condition,
        "corruption_family": family,
        "tactic": row["tactic"],
        "prediction": row["prediction"] if accepted else "",
        "score": score,
        "accepted": accepted,
        "correct": bool(accepted and correct_prediction),
        "wrong_label": bool(accepted and not correct_prediction),
        "missing_process_rule_applied": rule_applied,
    }


def margin_rows(
    clean_rows: list[dict[str, str]],
    corruption_rows: list[dict[str, str]],
    matched: dict[int, float],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    variants = (
        ("margin_calibrated", False, False),
        ("margin_calibrated_missing_rule", False, True),
        ("margin_matched_count", True, False),
        ("margin_matched_count_missing_rule", True, True),
    )
    for method, use_matched, use_rule in variants:
        for row in clean_rows:
            fold = int(row["test_fold"])
            score = float(row["margin_score"])
            accepted = (
                score >= matched[fold]
                if use_matched
                else as_bool(row["calibrated_margin_accept"])
            )
            result.append(
                base_row(
                    method,
                    row,
                    condition="clean",
                    family="clean",
                    accepted=accepted,
                    score=score,
                    rule_applied=False,
                )
            )
        for row in corruption_rows:
            fold = int(row["test_fold"])
            score = float(row["margin_score"])
            family = row["corruption_family"]
            threshold_accept = (
                score >= matched[fold]
                if use_matched
                else not as_bool(row["margin_reject"])
            )
            missing = family == "process_deletion"
            rule_applied = bool(use_rule and missing and threshold_accept)
            accepted = bool(threshold_accept and not (use_rule and missing))
            result.append(
                base_row(
                    method,
                    row,
                    condition="corrupted",
                    family=family,
                    accepted=accepted,
                    score=score,
                    rule_applied=rule_applied,
                )
            )
    return result


def evigate_rows(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        if row["method"] != EVI_METHOD:
            continue
        accepted = as_bool(row["attributed"])
        result.append(
            {
                "method": EVI_METHOD,
                "case_id": row["case_id"],
                "test_fold": int(row["test_fold"]),
                "condition": row["condition"],
                "corruption_family": row["corruption_family"],
                "tactic": row["tactic"],
                "prediction": row["prediction"] if accepted else "",
                "score": (
                    float(row["confidence"])
                    if row.get("confidence") not in {None, ""}
                    else None
                ),
                "accepted": accepted,
                "correct": as_bool(row["correct"]),
                "wrong_label": bool(accepted and not as_bool(row["correct"])),
                "missing_process_rule_applied": False,
            }
        )
    return result


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    accepted = [row for row in rows if row["accepted"]]
    return {
        "events": len(rows),
        "accepted": len(accepted),
        "correct_accepted": sum(bool(row["correct"]) for row in rows),
        "wrong_labels": sum(bool(row["wrong_label"]) for row in rows),
        "coverage": len(accepted) / len(rows) if rows else None,
        "rejection_rate": 1.0 - len(accepted) / len(rows) if rows else None,
        "unconditional_accuracy": (
            mean(bool(row["correct"]) for row in rows) if rows else None
        ),
        "selective_risk": (
            mean(bool(row["wrong_label"]) for row in accepted) if accepted else None
        ),
        "wrong_label_rate": (
            mean(bool(row["wrong_label"]) for row in rows) if rows else None
        ),
    }


def build_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_method: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_method[row["method"]].append(row)
    result: dict[str, Any] = {}
    for method, method_rows in sorted(by_method.items()):
        clean = [row for row in method_rows if row["condition"] == "clean"]
        corrupt = [row for row in method_rows if row["condition"] == "corrupted"]
        families = {
            family: summarize(
                [row for row in corrupt if row["corruption_family"] == family]
            )
            for family in FAMILIES
        }
        result[method] = {
            "clean": summarize(clean),
            "corruption_families": families,
            "corruption_macro": {
                metric: mean(families[family][metric] for family in FAMILIES)
                for metric in ("coverage", "rejection_rate", "wrong_label_rate")
            },
        }
    return result


def percentile_interval(values: Iterable[float]) -> list[float]:
    array = np.asarray(list(values), dtype=float)
    return [
        float(np.quantile(array, 0.025)),
        float(np.quantile(array, 0.975)),
    ]


def metric_for_cases(
    lookup: dict[tuple[str, str, str], dict[str, Any]],
    sampled_cases: list[str],
    *,
    condition: str,
    family: str | None,
    metric: str,
) -> float:
    selected = [
        lookup[(case_id, condition, family or "clean")] for case_id in sampled_cases
    ]
    value = summarize(selected)[metric]
    if value is None:
        raise ValueError(f"Metric {metric} is undefined for a bootstrap replicate")
    return float(value)


def corruption_macro_for_cases(
    lookup: dict[tuple[str, str, str], dict[str, Any]], sampled_cases: list[str]
) -> float:
    return mean(
        metric_for_cases(
            lookup,
            sampled_cases,
            condition="corrupted",
            family=family,
            metric="wrong_label_rate",
        )
        for family in FAMILIES
    )


def bootstrap_comparisons(
    rows: list[dict[str, Any]], iterations: int, seed: int
) -> dict[str, Any]:
    by_method: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_method[row["method"]].append(row)
    case_ids = sorted(
        row["case_id"]
        for row in by_method[EVI_METHOD]
        if row["condition"] == "clean"
    )
    rng = np.random.default_rng(seed)
    sampled_case_sets = [
        rng.choice(case_ids, size=len(case_ids), replace=True).tolist()
        for _ in range(iterations)
    ]
    indexed = {
        method: {
            (row["case_id"], row["condition"], row["corruption_family"]): row
            for row in method_rows
        }
        for method, method_rows in by_method.items()
    }
    complete_summary = build_summary(rows)
    comparisons: dict[str, Any] = {}
    for method in sorted(name for name in by_method if name != EVI_METHOD):
        macro_advantage: list[float] = []
        context_advantage: list[float] = []
        clean_risk_delta: list[float] = []
        clean_coverage_delta: list[float] = []
        for sampled in sampled_case_sets:
            evigate_macro = corruption_macro_for_cases(indexed[EVI_METHOD], sampled)
            baseline_macro = corruption_macro_for_cases(indexed[method], sampled)
            macro_advantage.append(baseline_macro - evigate_macro)
            evigate_context = metric_for_cases(
                indexed[EVI_METHOD],
                sampled,
                condition="corrupted",
                family="context_replacement",
                metric="wrong_label_rate",
            )
            baseline_context = metric_for_cases(
                indexed[method],
                sampled,
                condition="corrupted",
                family="context_replacement",
                metric="wrong_label_rate",
            )
            context_advantage.append(baseline_context - evigate_context)
            evigate_risk = metric_for_cases(
                indexed[EVI_METHOD],
                sampled,
                condition="clean",
                family=None,
                metric="selective_risk",
            )
            baseline_risk = metric_for_cases(
                indexed[method],
                sampled,
                condition="clean",
                family=None,
                metric="selective_risk",
            )
            clean_risk_delta.append(evigate_risk - baseline_risk)
            evigate_coverage = metric_for_cases(
                indexed[EVI_METHOD],
                sampled,
                condition="clean",
                family=None,
                metric="coverage",
            )
            baseline_coverage = metric_for_cases(
                indexed[method],
                sampled,
                condition="clean",
                family=None,
                metric="coverage",
            )
            clean_coverage_delta.append(evigate_coverage - baseline_coverage)
        comparisons[method] = {
            "iterations": iterations,
            "resampling_unit": "attack_action_event_cluster",
            "baseline_minus_evigate_corruption_macro_wrong_label": {
                "estimate": (
                    by_summary(complete_summary, method, "corruption_macro", "wrong_label_rate")
                    - by_summary(complete_summary, EVI_METHOD, "corruption_macro", "wrong_label_rate")
                ),
                "ci95": percentile_interval(macro_advantage),
                "probability_evigate_lower": mean(value > 0 for value in macro_advantage),
            },
            "baseline_minus_evigate_context_replacement_wrong_label": {
                "estimate": (
                    by_summary(complete_summary, method, "corruption_families", "context_replacement", "wrong_label_rate")
                    - by_summary(complete_summary, EVI_METHOD, "corruption_families", "context_replacement", "wrong_label_rate")
                ),
                "ci95": percentile_interval(context_advantage),
                "probability_evigate_lower": mean(value > 0 for value in context_advantage),
            },
            "evigate_minus_baseline_clean_selective_risk": {
                "estimate": (
                    by_summary(complete_summary, EVI_METHOD, "clean", "selective_risk")
                    - by_summary(complete_summary, method, "clean", "selective_risk")
                ),
                "ci95": percentile_interval(clean_risk_delta),
            },
            "evigate_minus_baseline_clean_coverage": {
                "estimate": (
                    by_summary(complete_summary, EVI_METHOD, "clean", "coverage")
                    - by_summary(complete_summary, method, "clean", "coverage")
                ),
                "ci95": percentile_interval(clean_coverage_delta),
            },
        }
    return comparisons


def by_summary(summary: dict[str, Any], method: str, *keys: str) -> float:
    value: Any = summary[method]
    for key in keys:
        value = value[key]
    return float(value)


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    llm_rows_raw = load_csv(args.llm_per_case)
    evigate = evigate_rows(llm_rows_raw)
    evigate_clean = [row for row in llm_rows_raw if row["method"] == EVI_METHOD and row["condition"] == "clean"]
    included_cases = {row["case_id"] for row in evigate_clean}
    clean = [row for row in load_csv(args.margin_clean) if row["case_id"] in included_cases]
    corrupt = [
        row for row in load_csv(args.margin_corruptions) if row["case_id"] in included_cases
    ]
    if len(clean) != len(included_cases):
        raise ValueError("Margin clean rows do not match the EviGate confirmatory cases")
    expected_corruptions = len(included_cases) * len(FAMILIES)
    if len(corrupt) != expected_corruptions:
        raise ValueError(
            f"Expected {expected_corruptions} corruption rows, found {len(corrupt)}"
        )

    thresholds, target_by_fold = matched_thresholds(clean, evigate_clean)
    rows = evigate + margin_rows(clean, corrupt, thresholds)
    summary = build_summary(rows)
    bootstrap = bootstrap_comparisons(rows, args.bootstrap_iterations, args.seed)
    result = {
        "schema_version": "1.0",
        "study": "EviGate-LLM fair posterior-margin baselines",
        "confirmatory_events": len(included_cases),
        "corruption_families": list(FAMILIES),
        "matched_target_by_fold": {str(key): value for key, value in target_by_fold.items()},
        "matched_margin_threshold_by_fold": {
            str(key): value for key, value in thresholds.items()
        },
        "methods": summary,
        "paired_event_cluster_bootstrap": bootstrap,
        "interpretation_boundary": (
            "Matched-count comparisons are post hoc mechanism analyses. They do not "
            "replace the frozen prospective EviGate-LLM hypotheses."
        ),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "evigate_llm_fair_baselines.per_case.csv", rows)
    (args.output_dir / "evigate_llm_fair_baselines.summary.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llm-per-case", type=Path, required=True)
    parser.add_argument("--margin-clean", type=Path, required=True)
    parser.add_argument("--margin-corruptions", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--bootstrap-iterations", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260916)
    return parser.parse_args()


def main() -> None:
    result = evaluate(parse_args())
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
