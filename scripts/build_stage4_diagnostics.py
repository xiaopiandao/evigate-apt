#!/usr/bin/env python3
"""Build end-to-end accounting, risk curves, and class diagnostics for Stage 4."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any

import numpy as np

from run_stage_b_typed_ranker import sha256_file
from run_stage_c_selective_attribution import percentile_interval, risk_for, selection_mask


RULES = ("confidence", "controller", "integrity", "dual")


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def unique_by_case(rows: list[dict[str, str]], description: str) -> dict[str, dict[str, str]]:
    output: dict[str, dict[str, str]] = {}
    for row in rows:
        case_id = row["case_id"]
        if case_id in output:
            raise ValueError(f"duplicate {description} row for {case_id}")
        output[case_id] = row
    return output


def build_event_accounting(
    stage_a_rows: list[dict[str, str]],
    stage_b_rows: list[dict[str, str]],
    decomposition_rows: list[dict[str, str]],
) -> list[dict[str, Any]]:
    stage_a = unique_by_case(stage_a_rows, "Stage A")
    stage_b = unique_by_case(stage_b_rows, "Stage B")
    stage_c = unique_by_case(decomposition_rows, "Stage C")
    if not set(stage_c) <= set(stage_a) or not set(stage_c) <= set(stage_b):
        raise ValueError("Stage C cases are not fully represented in Stage A/B inputs")
    output: list[dict[str, Any]] = []
    for case_id in sorted(stage_c):
        a = stage_a[case_id]
        b = stage_b[case_id]
        c = stage_c[case_id]
        row: dict[str, Any] = {
            "case_id": case_id,
            "tactic": c["tactic"],
            "stage_a_alerted": int(a["covered"]),
            "stage_a_network_positive_window_present": int(
                a["network_positive_window_present"]
            ),
            "stage_b_candidate_truth_present": int(b["truth_present"]),
            "stage_c_prediction": c["prediction"],
            "stage_c_correct": int(c["correct"]),
        }
        for rule in RULES:
            for operating_point, source_prefix in (
                ("fixed", "fixed_coverage"),
                ("calibrated", "calibrated"),
            ):
                accepted = int(c[f"{source_prefix}_{rule}_accept"])
                end_to_end_attributed = int(row["stage_a_alerted"] and accepted)
                row[f"oracle_{operating_point}_{rule}_accepted"] = accepted
                row[f"end_to_end_{operating_point}_{rule}_attributed"] = (
                    end_to_end_attributed
                )
                row[
                    f"end_to_end_{operating_point}_{rule}_unattributed_after_alert"
                ] = int(row["stage_a_alerted"] and not accepted)
                row[
                    f"end_to_end_{operating_point}_{rule}_correct_attribution"
                ] = int(end_to_end_attributed and row["stage_c_correct"])
                row[
                    f"end_to_end_{operating_point}_{rule}_wrong_attribution"
                ] = int(end_to_end_attributed and not row["stage_c_correct"])
        output.append(row)
    return output


def summarize_accounting(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    stage_a_alerted = sum(row["stage_a_alerted"] for row in rows)
    output: dict[str, Any] = {
        "all_in_support_events": total,
        "stage_a_alerted": stage_a_alerted,
        "stage_a_missed": total - stage_a_alerted,
        "stage_a_coverage": stage_a_alerted / total,
        "candidate_truth_present_all": sum(
            row["stage_b_candidate_truth_present"] for row in rows
        ),
        "candidate_truth_present_after_stage_a": sum(
            row["stage_a_alerted"] and row["stage_b_candidate_truth_present"]
            for row in rows
        ),
        "tactic_correct_oracle_entry": sum(row["stage_c_correct"] for row in rows),
        "tactic_correct_after_stage_a": sum(
            row["stage_a_alerted"] and row["stage_c_correct"] for row in rows
        ),
        "rules": {},
    }
    for rule in RULES:
        output["rules"][rule] = {}
        for operating_point in ("fixed", "calibrated"):
            attributed = sum(
                row[f"end_to_end_{operating_point}_{rule}_attributed"] for row in rows
            )
            correct = sum(
                row[f"end_to_end_{operating_point}_{rule}_correct_attribution"]
                for row in rows
            )
            wrong = sum(
                row[f"end_to_end_{operating_point}_{rule}_wrong_attribution"]
                for row in rows
            )
            output["rules"][rule][operating_point] = {
                "oracle_accepted": sum(
                    row[f"oracle_{operating_point}_{rule}_accepted"] for row in rows
                ),
                "end_to_end_attributed": attributed,
                "end_to_end_unattributed_after_alert": sum(
                    row[
                        f"end_to_end_{operating_point}_{rule}_unattributed_after_alert"
                    ]
                    for row in rows
                ),
                "end_to_end_correct_attribution": correct,
                "end_to_end_wrong_attribution": wrong,
                "end_to_end_wrong_attribution_over_all_events": wrong / total,
                "risk_among_end_to_end_attributions": wrong / attributed
                if attributed
                else None,
            }
    return output


def bootstrap_curve_point(
    rows: list[dict[str, Any]],
    score_name: str,
    accepted_count: int,
    iterations: int,
    seed: int,
) -> list[float]:
    rng = np.random.default_rng(seed)
    values: list[float] = []
    for _ in range(iterations):
        indices = rng.integers(0, len(rows), size=len(rows))
        sample = [
            dict(rows[int(index)], case_id=f"{draw}:{rows[int(index)]['case_id']}")
            for draw, index in enumerate(indices)
        ]
        accepted = selection_mask(sample, score_name, accepted_count)
        values.append(risk_for(sample, accepted))
    return percentile_interval(values)


def build_risk_curves(
    decomposition_rows: list[dict[str, str]], iterations: int, seed: int
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = [
        {
            "case_id": row["case_id"],
            "correct": int(row["correct"]),
            **{f"{rule}_score": float(row[f"{rule}_score"]) for rule in RULES},
        }
        for row in decomposition_rows
    ]
    output: list[dict[str, Any]] = []
    for point_index, requested in enumerate(np.linspace(0.1, 1.0, 10)):
        accepted_count = max(1, int(round(float(requested) * len(rows))))
        for rule_index, rule in enumerate(RULES):
            score_name = f"{rule}_score"
            accepted = selection_mask(rows, score_name, accepted_count)
            interval = bootstrap_curve_point(
                rows,
                score_name,
                accepted_count,
                iterations,
                seed + 1000 * rule_index + point_index,
            )
            output.append(
                {
                    "rule": rule,
                    "requested_coverage": float(requested),
                    "accepted_events": accepted_count,
                    "realized_coverage": accepted_count / len(rows),
                    "risk": risk_for(rows, accepted),
                    "cluster_bootstrap_ci95_lower": interval[0],
                    "cluster_bootstrap_ci95_upper": interval[1],
                    "bootstrap_iterations": iterations,
                }
            )
    return output


def build_class_diagnostics(
    decomposition_rows: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tactics = sorted({row["tactic"] for row in decomposition_rows})
    selective: list[dict[str, Any]] = []
    for rule in RULES:
        for tactic in tactics:
            selected = [row for row in decomposition_rows if row["tactic"] == tactic]
            accepted = [
                row for row in selected if int(row[f"fixed_coverage_{rule}_accept"])
            ]
            wrong = sum(not int(row["correct"]) for row in accepted)
            selective.append(
                {
                    "rule": rule,
                    "tactic": tactic,
                    "events": len(selected),
                    "accepted": len(accepted),
                    "rejected": len(selected) - len(accepted),
                    "correct_accepted": len(accepted) - wrong,
                    "wrong_accepted": wrong,
                    "risk": wrong / len(accepted) if accepted else "",
                }
            )
    confusion_counts = Counter(
        (row["tactic"], row["prediction"]) for row in decomposition_rows
    )
    confusion = [
        {
            "true_tactic": true_tactic,
            "predicted_tactic": predicted_tactic,
            "count": confusion_counts[(true_tactic, predicted_tactic)],
        }
        for true_tactic in tactics
        for predicted_tactic in tactics
    ]
    return selective, confusion


def flatten_corruption_summary(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for family, metrics in summary["leave_one_corruption_family_out"].items():
        for rule in RULES:
            rows.append(
                {
                    "corruption_family": family,
                    "rule": rule,
                    "cases": metrics["cases"],
                    "rejection_rate": metrics[f"{rule}_rejection_rate"],
                    "wrong_attribution_rate": metrics[
                        f"{rule}_wrong_attribution_rate"
                    ],
                }
            )
    return rows


def run(args: argparse.Namespace) -> dict[str, Any]:
    stage_a_all = load_csv(args.stage_a_events)
    stage_a = [
        row
        for row in stage_a_all
        if row["model"] == "hist_gradient_boosting"
        and int(row["seed"]) == args.stage_a_seed
        and math_isclose(float(row["false_alert_budget_per_hour"]), args.false_alert_budget)
        and row["support_role"] == "in_support"
    ]
    stage_b_all = load_csv(args.stage_b_cases)
    stage_b = [
        row
        for row in stage_b_all
        if row["model"] == "typed_logistic"
        and int(row["seed"]) == args.stage_b_seed
        and row["support_role"] == "in_support"
    ]
    decomposition = load_csv(args.decomposition_predictions)
    if len(stage_a) != 53 or len(stage_b) != 53 or len(decomposition) != 53:
        raise ValueError(
            f"expected 53 rows per in-support source, got Stage A={len(stage_a)}, "
            f"Stage B={len(stage_b)}, Stage C={len(decomposition)}"
        )

    event_rows = build_event_accounting(stage_a, stage_b, decomposition)
    accounting = summarize_accounting(event_rows)
    curves = build_risk_curves(decomposition, args.bootstrap_iterations, args.seed)
    selective, confusion = build_class_diagnostics(decomposition)
    decomposition_summary = json.loads(
        args.decomposition_summary.read_text(encoding="utf-8")
    )
    corruptions = flatten_corruption_summary(decomposition_summary)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "event_accounting": args.output_dir / "stage4_event_accounting.csv",
        "risk_curves": args.output_dir / "stage4_risk_coverage.csv",
        "class_diagnostics": args.output_dir / "stage4_class_diagnostics.csv",
        "confusion": args.output_dir / "stage4_full_coverage_confusion.csv",
        "corruptions": args.output_dir / "stage4_corruption_comparison.csv",
    }
    write_csv(files["event_accounting"], event_rows)
    write_csv(files["risk_curves"], curves)
    write_csv(files["class_diagnostics"], selective)
    write_csv(files["confusion"], confusion)
    write_csv(files["corruptions"], corruptions)

    result = {
        "schema_version": "1.0",
        "study": "EviGate-APT Stage-4 end-to-end and operating diagnostics",
        "protocol": {
            "statistical_unit": "union_derived_attack_action_cluster",
            "in_support_events": len(event_rows),
            "stage_a_model": "hist_gradient_boosting",
            "stage_a_seed": args.stage_a_seed,
            "stage_a_false_alert_budget_per_hour": args.false_alert_budget,
            "stage_b_model": "typed_logistic",
            "stage_b_seed": args.stage_b_seed,
            "fixed_selective_coverage": 42 / 53,
            "bootstrap_iterations_per_curve_point": args.bootstrap_iterations,
        },
        "event_accounting": accounting,
        "source_files": {
            "stage_a_events": {
                "path": args.stage_a_events.as_posix(),
                "sha256": sha256_file(args.stage_a_events),
            },
            "stage_b_cases": {
                "path": args.stage_b_cases.as_posix(),
                "sha256": sha256_file(args.stage_b_cases),
            },
            "decomposition_predictions": {
                "path": args.decomposition_predictions.as_posix(),
                "sha256": sha256_file(args.decomposition_predictions),
            },
            "decomposition_summary": {
                "path": args.decomposition_summary.as_posix(),
                "sha256": sha256_file(args.decomposition_summary),
            },
        },
        "artifacts": {
            name: {"path": path.as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size}
            for name, path in files.items()
        },
        "interpretation_limits": [
            "Fixed-count end-to-end accounting is diagnostic and does not replace calibration-only deployment thresholds.",
            "Cluster bootstrap intervals characterize this campaign only.",
            "Stage A misses remain misses even when the oracle-entry tactic classifier would be correct.",
        ],
    }
    summary_path = args.output_dir / "stage4_diagnostics.summary.json"
    summary_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"summary": summary_path.as_posix(), **accounting}, indent=2))
    return result


def math_isclose(left: float, right: float, tolerance: float = 1e-12) -> bool:
    return abs(left - right) <= tolerance


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage-a-events", type=Path, required=True)
    parser.add_argument("--stage-b-cases", type=Path, required=True)
    parser.add_argument("--decomposition-predictions", type=Path, required=True)
    parser.add_argument("--decomposition-summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--stage-a-seed", type=int, default=11)
    parser.add_argument("--stage-b-seed", type=int, default=11)
    parser.add_argument("--false-alert-budget", type=float, default=0.5)
    parser.add_argument("--bootstrap-iterations", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260915)
    return parser.parse_args()


def main() -> None:
    run(parse_args())


if __name__ == "__main__":
    main()
