#!/usr/bin/env python3
"""Count-match reviewer-requested EviGate-Bind component ablations."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from evaluate_evigate_bindgate import (
    exact_count_threshold,
    family_summary,
    macro_wrong,
    macro_wrong_without_time_shift,
    paired_bootstrap_methods,
    sha256_file,
    write_csv,
)


BOOL_FIELDS = {
    "llm_attributed",
    "llm_correct",
    "binding_pass",
    "margin_pass",
    "temporal_admissibility_pass",
    "cascade_attributed",
    "cascade_correct",
    "matched_margin_attributed",
    "matched_margin_correct",
    "no_llm_bind_attributed",
    "no_llm_bind_correct",
}
INT_FIELDS = {"test_fold"}
FLOAT_FIELDS = {
    "proposal_margin",
    "binding_score",
    "binding_threshold",
    "margin_threshold",
}


def load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for raw in csv.DictReader(handle):
            row: dict[str, Any] = dict(raw)
            for field in BOOL_FIELDS & row.keys():
                row[field] = row[field] == "True"
            for field in INT_FIELDS & row.keys():
                row[field] = int(row[field])
            for field in FLOAT_FIELDS & row.keys():
                row[field] = float(row[field])
            rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", type=Path, required=True)
    parser.add_argument("--same-only", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--bootstrap-replicates", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260916)
    args = parser.parse_args()

    full_rows = load_rows(args.full)
    same_rows = load_rows(args.same_only)
    full_by_sample = {row["sample_id"]: row for row in full_rows}
    if {row["sample_id"] for row in same_rows} != set(full_by_sample):
        raise ValueError("full and same-tactic-only runs contain different samples")

    target_counts: dict[int, int] = {}
    thresholds: dict[int, float] = {}
    for fold in (1, 2, 3):
        reference_clean = [
            row
            for row in full_rows
            if row["corruption_family"] == "clean" and row["test_fold"] == fold
        ]
        target_counts[fold] = sum(row["cascade_attributed"] for row in reference_clean)
        eligible = [
            row
            for row in same_rows
            if row["corruption_family"] == "clean"
            and row["test_fold"] == fold
            and row["llm_attributed"]
            and row["binding_pass"]
            and row["temporal_admissibility_pass"]
        ]
        thresholds[fold] = exact_count_threshold(
            [row["proposal_margin"] for row in eligible], target_counts[fold]
        )

    for row in same_rows:
        reference = full_by_sample[row["sample_id"]]
        accepted = bool(
            row["llm_attributed"]
            and row["binding_pass"]
            and row["temporal_admissibility_pass"]
            and row["proposal_margin"] >= thresholds[row["test_fold"]]
        )
        prediction = row["llm_prediction"] if accepted else None
        row["same_only_fixed_attributed"] = accepted
        row["same_only_fixed_prediction"] = prediction
        row["same_only_fixed_correct"] = bool(
            accepted and prediction == row["tactic"]
        )
        for suffix in ("attributed", "prediction", "correct"):
            row[f"reference_margin_{suffix}"] = reference[f"matched_margin_{suffix}"]
            row[f"full_cascade_{suffix}"] = reference[f"cascade_{suffix}"]
            row[f"full_no_llm_{suffix}"] = reference[f"no_llm_bind_{suffix}"]

    summaries = {
        "reference_margin": family_summary(same_rows, "reference_margin"),
        "full_cascade": family_summary(same_rows, "full_cascade"),
        "full_no_llm": family_summary(same_rows, "full_no_llm"),
        "same_only_fixed": family_summary(same_rows, "same_only_fixed"),
    }
    aggregates = {
        name: {
            "clean": values["clean"],
            "corruption_macro_wrong_label_rate": macro_wrong(values),
            "macro_wrong_without_time_shift": macro_wrong_without_time_shift(values),
            "context_replacement": values["context_replacement"],
        }
        for name, values in summaries.items()
    }
    primary_context_improvement = (
        aggregates["reference_margin"]["context_replacement"]["wrong_label_rate"]
        - aggregates["full_cascade"]["context_replacement"]["wrong_label_rate"]
    )
    same_only_context_improvement = (
        aggregates["reference_margin"]["context_replacement"]["wrong_label_rate"]
        - aggregates["same_only_fixed"]["context_replacement"]["wrong_label_rate"]
    )
    summary = {
        "study": "Reviewer-requested EviGate-Bind ablations",
        "status": "post-freeze diagnostic; original method and targets unchanged",
        "target_clean_counts_by_fold": target_counts,
        "same_tactic_only_margin_thresholds": thresholds,
        "aggregate": aggregates,
        "different_tactic_negative_ablation": {
            "primary_context_improvement": primary_context_improvement,
            "same_only_context_improvement": same_only_context_improvement,
            "fraction_of_primary_context_improvement_remaining": (
                same_only_context_improvement / primary_context_improvement
                if primary_context_improvement
                else None
            ),
            "bootstrap_same_only_vs_reference_margin": paired_bootstrap_methods(
                same_rows,
                "reference_margin",
                "same_only_fixed",
                args.seed + 201,
                args.bootstrap_replicates,
            ),
            "bootstrap_full_vs_same_only": paired_bootstrap_methods(
                same_rows,
                "same_only_fixed",
                "full_cascade",
                args.seed + 202,
                args.bootstrap_replicates,
            ),
        },
        "no_llm_ablation": {
            "bootstrap_full_vs_no_llm": paired_bootstrap_methods(
                same_rows,
                "full_no_llm",
                "full_cascade",
                args.seed + 203,
                args.bootstrap_replicates,
            )
        },
        "temporal_rule_sensitivity": {
            "description": (
                "Four-family macro excludes the +600-second time-shift family, "
                "which the positive-time-proximity rule rejects by construction."
            ),
            "bootstrap_full_vs_reference_margin": paired_bootstrap_methods(
                same_rows,
                "reference_margin",
                "full_cascade",
                args.seed + 204,
                args.bootstrap_replicates,
            ),
        },
        "input_integrity": {
            "full_per_case_sha256": sha256_file(args.full).upper(),
            "same_only_per_case_sha256": sha256_file(args.same_only).upper(),
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    per_case_path = args.output_dir / "evigate_bindgate_reviewer_ablations.per_case.csv"
    summary_path = args.output_dir / "evigate_bindgate_reviewer_ablations.summary.json"
    write_csv(per_case_path, same_rows)
    summary["artifacts"] = {
        per_case_path.name: {"sha256": sha256_file(per_case_path).upper()}
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
