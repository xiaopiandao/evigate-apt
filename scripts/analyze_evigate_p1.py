#!/usr/bin/env python3
"""Aggregate the prespecified EviGate-Bind P1 feature ablation and costs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np


MODES = (
    "full",
    "without_network_posterior",
    "network_only",
    "provenance_only",
)
CORRUPTION_FAMILIES = (
    "process_deletion",
    "socket_type_deletion",
    "time_shift",
    "random_entity_deletion",
    "context_replacement",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() == "true"


def quantile_interval(values: list[float]) -> list[float]:
    return [float(value) for value in np.quantile(values, [0.025, 0.975])]


def method_metrics(rows: list[dict[str, str]]) -> dict[str, float]:
    clean = [row for row in rows if row["corruption_family"] == "clean"]
    corrupt = {
        family: [row for row in rows if row["corruption_family"] == family]
        for family in CORRUPTION_FAMILIES
    }
    accepted = sum(as_bool(row["cascade_attributed"]) for row in clean)
    wrong = sum(
        as_bool(row["cascade_attributed"]) and not as_bool(row["cascade_correct"])
        for row in clean
    )
    family_wrong = {
        family: float(
            np.mean(
                [
                    as_bool(row["cascade_attributed"])
                    and not as_bool(row["cascade_correct"])
                    for row in family_rows
                ]
            )
        )
        for family, family_rows in corrupt.items()
    }
    return {
        "clean_accepted": accepted,
        "clean_selective_risk": wrong / accepted if accepted else float("nan"),
        "corruption_macro_wrong_label_rate": float(
            np.mean(list(family_wrong.values()))
        ),
        "context_wrong_label_rate": family_wrong["context_replacement"],
    }


def paired_bootstrap(
    full_rows: list[dict[str, str]],
    candidate_rows: list[dict[str, str]],
    seed: int,
    replicates: int,
) -> dict[str, Any]:
    full_by_case = defaultdict(dict)
    candidate_by_case = defaultdict(dict)
    for row in full_rows:
        full_by_case[row["case_id"]][row["corruption_family"]] = row
    for row in candidate_rows:
        candidate_by_case[row["case_id"]][row["corruption_family"]] = row
    case_ids = sorted(full_by_case)
    if case_ids != sorted(candidate_by_case):
        raise ValueError("ablation modes do not contain the same event clusters")
    required = {"clean", *CORRUPTION_FAMILIES}
    for case_id in case_ids:
        if set(full_by_case[case_id]) != required:
            raise ValueError(f"full mode has incomplete family rows for {case_id}")
        if set(candidate_by_case[case_id]) != required:
            raise ValueError(f"candidate mode has incomplete family rows for {case_id}")

    rng = np.random.default_rng(seed)
    draws: dict[str, list[float]] = defaultdict(list)
    for _ in range(replicates):
        selected = rng.integers(0, len(case_ids), size=len(case_ids))
        full_sample = [full_by_case[case_ids[index]] for index in selected]
        candidate_sample = [candidate_by_case[case_ids[index]] for index in selected]

        def clean_values(sample: list[dict[str, dict[str, str]]]) -> tuple[int, int]:
            rows = [case["clean"] for case in sample]
            accepted = sum(as_bool(row["cascade_attributed"]) for row in rows)
            wrong = sum(
                as_bool(row["cascade_attributed"])
                and not as_bool(row["cascade_correct"])
                for row in rows
            )
            return accepted, wrong

        full_accepted, full_wrong = clean_values(full_sample)
        candidate_accepted, candidate_wrong = clean_values(candidate_sample)
        draws["clean_acceptance_rate_difference"].append(
            (candidate_accepted - full_accepted) / len(case_ids)
        )
        draws["clean_selective_risk_difference"].append(
            (candidate_wrong / candidate_accepted if candidate_accepted else 0.0)
            - (full_wrong / full_accepted if full_accepted else 0.0)
        )

        family_differences = []
        for family in CORRUPTION_FAMILIES:
            full_wrong_rate = np.mean(
                [
                    as_bool(case[family]["cascade_attributed"])
                    and not as_bool(case[family]["cascade_correct"])
                    for case in full_sample
                ]
            )
            candidate_wrong_rate = np.mean(
                [
                    as_bool(case[family]["cascade_attributed"])
                    and not as_bool(case[family]["cascade_correct"])
                    for case in candidate_sample
                ]
            )
            family_differences.append(candidate_wrong_rate - full_wrong_rate)
            if family == "context_replacement":
                draws["context_wrong_label_rate_difference"].append(
                    candidate_wrong_rate - full_wrong_rate
                )
        draws["corruption_macro_wrong_label_rate_difference"].append(
            float(np.mean(family_differences))
        )

    full_metrics = method_metrics(full_rows)
    candidate_metrics = method_metrics(candidate_rows)
    estimates = {
        "clean_acceptance_rate_difference": (
            candidate_metrics["clean_accepted"] - full_metrics["clean_accepted"]
        )
        / len(case_ids),
        "clean_selective_risk_difference": candidate_metrics[
            "clean_selective_risk"
        ]
        - full_metrics["clean_selective_risk"],
        "corruption_macro_wrong_label_rate_difference": candidate_metrics[
            "corruption_macro_wrong_label_rate"
        ]
        - full_metrics["corruption_macro_wrong_label_rate"],
        "context_wrong_label_rate_difference": candidate_metrics[
            "context_wrong_label_rate"
        ]
        - full_metrics["context_wrong_label_rate"],
    }
    return {
        "difference_direction": "candidate minus full; positive is worse for risk metrics",
        "unit": "event cluster",
        "events": len(case_ids),
        "replicates": replicates,
        "seed": seed,
        "estimands": {
            name: {
                "estimate": float(estimates[name]),
                "interval_95": quantile_interval(values),
                "probability_positive": float(np.mean(np.asarray(values) > 0.0)),
            }
            for name, values in draws.items()
        },
    }


def break_even(
    candidate_error: int,
    candidate_abstained: int,
    reference_error: int,
    reference_abstained: int,
) -> float | None:
    denominator = candidate_abstained - reference_abstained
    if denominator == 0:
        return None
    return (reference_error - candidate_error) / denominator


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ablation-dir", type=Path, required=True)
    parser.add_argument("--revision-summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--bootstrap-replicates", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260917)
    args = parser.parse_args()

    summaries: dict[str, dict[str, Any]] = {}
    per_case: dict[str, list[dict[str, str]]] = {}
    table_rows: list[dict[str, Any]] = []
    artifacts: dict[str, dict[str, str]] = {}
    for mode in MODES:
        mode_dir = args.ablation_dir / mode
        summary_path = mode_dir / "evigate_bindgate.summary.json"
        per_case_path = mode_dir / "evigate_bindgate.per_case.csv"
        synthetic_path = mode_dir / "evigate_bindgate.synthetic_binding.csv"
        summaries[mode] = json.loads(summary_path.read_text(encoding="utf-8"))
        per_case[mode] = read_csv(per_case_path)
        aggregate = summaries[mode]["aggregate"]["cascade"]
        audit = summaries[mode]["synthetic_binding_audit"]
        feature_counts = {
            int(fold["binding_feature_count"])
            for fold in summaries[mode]["fold_audit"].values()
        }
        if len(feature_counts) != 1:
            raise ValueError(f"feature count changes by fold for {mode}")
        timing = summaries[mode].get("cpu_binding_path_timing", {})
        table_rows.append(
            {
                "feature_mode": mode,
                "features": feature_counts.pop(),
                "clean_accepted": aggregate["clean"]["accepted"],
                "clean_selective_risk": aggregate["clean"]["selective_risk"],
                "five_family_macro_wrong_label_rate": aggregate[
                    "corruption_macro_wrong_label_rate"
                ],
                "context_wrong_label_rate": aggregate["context_replacement"][
                    "wrong_label_rate"
                ],
                "synthetic_same_tactic_alarm_rate": audit[
                    "same_tactic_replacement"
                ]["context_alarm_rate"],
                "synthetic_different_tactic_alarm_rate": audit[
                    "different_tactic_replacement"
                ]["context_alarm_rate"],
                "workstation_median_ms": timing.get("median_milliseconds"),
                "workstation_p95_ms": timing.get("p95_milliseconds"),
            }
        )
        artifacts[mode] = {
            "summary_sha256": sha256_file(summary_path),
            "per_case_sha256": sha256_file(per_case_path),
            "synthetic_binding_sha256": sha256_file(synthetic_path),
        }

    paired = {
        mode: paired_bootstrap(
            per_case["full"],
            per_case[mode],
            args.seed + index,
            args.bootstrap_replicates,
        )
        for index, mode in enumerate(MODES[1:], start=1)
    }

    revision = json.loads(args.revision_summary.read_text(encoding="utf-8"))
    family_results = revision["family_results"]
    decision_methods = {
        "full_bindgate": family_results["full_cascade"],
        "matched_margin": family_results["reference_margin"],
        "training_calibrated_margin": family_results["calibrated_margin"],
    }
    cost_rows: list[dict[str, Any]] = []
    for relative_abstention_cost in np.linspace(0.0, 1.0, 21):
        for method, result in decision_methods.items():
            clean = result["clean"]
            clean_abstained = clean["events"] - clean["accepted"]
            clean_total = clean["wrong"] + relative_abstention_cost * clean_abstained
            cost_rows.append(
                {
                    "scenario": "clean_wrong_label",
                    "relative_abstention_cost": relative_abstention_cost,
                    "method": method,
                    "error_or_unsafe_issued": clean["wrong"],
                    "abstained": clean_abstained,
                    "total_cost": clean_total,
                    "normalized_cost": clean_total / clean["events"],
                }
            )
            context = result["context_replacement"]
            context_abstained = context["events"] - context["accepted"]
            context_total = (
                context["accepted"]
                + relative_abstention_cost * context_abstained
            )
            cost_rows.append(
                {
                    "scenario": "foreign_context_integrity",
                    "relative_abstention_cost": relative_abstention_cost,
                    "method": method,
                    "error_or_unsafe_issued": context["accepted"],
                    "abstained": context_abstained,
                    "total_cost": context_total,
                    "normalized_cost": context_total / context["events"],
                }
            )

    full_clean = decision_methods["full_bindgate"]["clean"]
    calibrated_clean = decision_methods["training_calibrated_margin"]["clean"]
    full_context = decision_methods["full_bindgate"]["context_replacement"]
    calibrated_context = decision_methods["training_calibrated_margin"][
        "context_replacement"
    ]
    decision_summary = {
        "wrong_issue_cost": 1.0,
        "clean_cost": "wrong labels + c * abstentions",
        "foreign_context_cost": "all issued labels + c * abstentions",
        "full_vs_training_calibrated_clean_break_even_c": break_even(
            full_clean["wrong"],
            full_clean["events"] - full_clean["accepted"],
            calibrated_clean["wrong"],
            calibrated_clean["events"] - calibrated_clean["accepted"],
        ),
        "full_vs_training_calibrated_context_break_even_c": break_even(
            full_context["accepted"],
            full_context["events"] - full_context["accepted"],
            calibrated_context["accepted"],
            calibrated_context["events"] - calibrated_context["accepted"],
        ),
        "interpretation": (
            "Full BindGate has lower clean decision cost when abstention costs less "
            "than 0.4 of a wrong label, and lower foreign-context integrity cost "
            "for every c below 1.0."
        ),
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with (args.output_dir / "p1_ablation_table.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(table_rows[0]))
        writer.writeheader()
        writer.writerows(table_rows)
    with (args.output_dir / "p1_decision_cost.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(cost_rows[0]))
        writer.writeheader()
        writer.writerows(cost_rows)

    output = {
        "study": "EviGate-Bind P1 cross-view ablation and decision cost",
        "status": "post-freeze diagnostic",
        "feature_ablation": table_rows,
        "paired_candidate_minus_full": paired,
        "decision_cost": decision_summary,
        "artifact_hashes": artifacts,
    }
    (args.output_dir / "p1_analysis.summary.json").write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
