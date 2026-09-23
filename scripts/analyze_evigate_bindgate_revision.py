"""Reviewer-facing EviGate-Bind diagnostics from frozen per-case artifacts.

The analysis adds no fitted parameters.  It computes end-to-end accounting,
per-tactic results, deployable training-calibrated comparisons, three-family
macros, grouped bootstrap intervals, and exact paired randomization tests.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
ROBUSTNESS_FAMILIES = (
    "socket_type_deletion",
    "random_entity_deletion",
    "context_replacement",
)
GAP_MERGED_CASES = {
    "case_4ff166f49db1bd9c4d62": "cicapt2_collection_018",
    "case_012bac4ea9c61dfbe3ef": "cicapt2_collection_019",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def as_bool(value: object) -> bool:
    return str(value).strip().lower() == "true"


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: Iterable[dict[str, object]]) -> None:
    material = list(rows)
    if not material:
        raise ValueError("no rows to write")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(material[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(material)


def method_outcomes(rows: Sequence[dict[str, Any]], prefix: str) -> dict[str, float | int | None]:
    accepted = [row for row in rows if bool(row[f"{prefix}_attributed"])]
    correct = [row for row in rows if bool(row[f"{prefix}_correct"])]
    wrong = len(accepted) - len(correct)
    return {
        "events": len(rows),
        "accepted": len(accepted),
        "correct": len(correct),
        "wrong": wrong,
        "coverage": len(accepted) / len(rows) if rows else None,
        "unconditional_accuracy": len(correct) / len(rows) if rows else None,
        "wrong_label_rate": wrong / len(rows) if rows else None,
        "selective_risk": wrong / len(accepted) if accepted else None,
    }


def exact_mcnemar(rows: Sequence[dict[str, Any]], reference: str, candidate: str) -> dict[str, float | int]:
    reference_only_wrong = 0
    candidate_only_wrong = 0
    for row in rows:
        reference_wrong = bool(row[f"{reference}_attributed"] and not row[f"{reference}_correct"])
        candidate_wrong = bool(row[f"{candidate}_attributed"] and not row[f"{candidate}_correct"])
        if reference_wrong and not candidate_wrong:
            reference_only_wrong += 1
        elif candidate_wrong and not reference_wrong:
            candidate_only_wrong += 1
    discordant = reference_only_wrong + candidate_only_wrong
    if discordant == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, k) for k in range(min(reference_only_wrong, candidate_only_wrong) + 1))
        p_value = min(1.0, 2.0 * tail / (2**discordant))
    return {
        "reference_only_wrong": reference_only_wrong,
        "candidate_only_wrong": candidate_only_wrong,
        "discordant_pairs": discordant,
        "two_sided_exact_p": p_value,
    }


def exact_sign_flip(values: Sequence[int]) -> dict[str, float | int]:
    nonzero = [int(value) for value in values if value != 0]
    observed = abs(sum(nonzero))
    distribution = Counter({0: 1})
    for value in nonzero:
        magnitude = abs(value)
        updated: Counter[int] = Counter()
        for total, count in distribution.items():
            updated[total + magnitude] += count
            updated[total - magnitude] += count
        distribution = updated
    total_assignments = 2 ** len(nonzero)
    extreme = sum(count for total, count in distribution.items() if abs(total) >= observed)
    return {
        "nonzero_event_differences": len(nonzero),
        "observed_absolute_sum": observed,
        "sign_assignments": total_assignments,
        "two_sided_exact_p": extreme / total_assignments if total_assignments else 1.0,
    }


def paired_event_values(
    rows: Sequence[dict[str, Any]], reference: str, candidate: str, families: Sequence[str]
) -> dict[str, int]:
    by_case: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        if row["corruption_family"] in families:
            by_case[row["case_id"]][row["corruption_family"]] = row
    output: dict[str, int] = {}
    for case_id, family_rows in by_case.items():
        if set(family_rows) != set(families):
            raise ValueError(f"case {case_id} lacks a robustness family")
        reference_wrong = sum(
            int(row[f"{reference}_attributed"] and not row[f"{reference}_correct"])
            for row in family_rows.values()
        )
        candidate_wrong = sum(
            int(row[f"{candidate}_attributed"] and not row[f"{candidate}_correct"])
            for row in family_rows.values()
        )
        output[case_id] = reference_wrong - candidate_wrong
    return output


def grouped_bootstrap_macro(
    rows: Sequence[dict[str, Any]],
    reference: str,
    candidate: str,
    families: Sequence[str],
    replicates: int,
    seed: int,
) -> dict[str, object]:
    values = paired_event_values(rows, reference, candidate, families)
    case_ids = sorted(values)
    observed = float(np.mean([values[case_id] for case_id in case_ids]) / len(families))
    rng = np.random.default_rng(seed)
    samples = np.empty(replicates, dtype=float)
    for idx in range(replicates):
        selected = rng.choice(case_ids, size=len(case_ids), replace=True)
        samples[idx] = np.mean([values[str(case_id)] for case_id in selected]) / len(families)
    return {
        "estimate": observed,
        "interval_95": [float(np.quantile(samples, 0.025)), float(np.quantile(samples, 0.975))],
        "probability_positive": float(np.mean(samples > 0.0)),
        "events": len(case_ids),
        "families": list(families),
        "replicates": replicates,
        "seed": seed,
        "exact_sign_flip": exact_sign_flip(list(values.values())),
    }


def add_calibrated_margin(
    bind_rows: list[dict[str, Any]], fair_rows: Sequence[dict[str, str]]
) -> None:
    calibrated = {
        (row["case_id"], row["condition"], row["corruption_family"]): row
        for row in fair_rows
        if row["method"] == "margin_calibrated_missing_rule"
    }
    for row in bind_rows:
        key = (row["case_id"], row["condition"], row["corruption_family"])
        source = calibrated[key]
        accepted = as_bool(source["accepted"]) and bool(row["temporal_admissibility_pass"])
        prediction = source["prediction"] if accepted else ""
        row["calibrated_margin_attributed"] = accepted
        row["calibrated_margin_prediction"] = prediction
        row["calibrated_margin_correct"] = accepted and prediction == row["tactic"]


def load_bind_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    bool_fields = {
        "full_cascade_attributed",
        "full_cascade_correct",
        "full_no_llm_attributed",
        "full_no_llm_correct",
        "reference_margin_attributed",
        "reference_margin_correct",
        "temporal_admissibility_pass",
    }
    for raw in load_csv(path):
        row: dict[str, Any] = dict(raw)
        for field in bool_fields:
            row[field] = as_bool(row[field])
        rows.append(row)
    return rows


def stage_a_coverage(path: Path) -> dict[str, bool]:
    selected = [
        row
        for row in load_csv(path)
        if row["model"] == "hist_gradient_boosting"
        and float(row["false_alert_budget_per_hour"]) == 0.5
        and int(row["seed"]) == 11
    ]
    return {row["case_id"]: bool(int(row["covered"])) for row in selected}


def per_tactic(rows: Sequence[dict[str, Any]], prefixes: Sequence[str]) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for tactic in sorted({row["tactic"] for row in rows}):
        tactic_rows = [row for row in rows if row["tactic"] == tactic]
        record: dict[str, object] = {"tactic": tactic, "events": len(tactic_rows)}
        for prefix in prefixes:
            metrics = method_outcomes(tactic_rows, prefix)
            for name in ("accepted", "correct", "wrong", "coverage", "selective_risk"):
                record[f"{prefix}_{name}"] = metrics[name]
        output.append(record)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--bind-rows",
        type=Path,
        default=ROOT
        / "data/derived/evigate_llm/v7_bindgate/reviewer_ablations/evigate_bindgate_reviewer_ablations.per_case.csv",
    )
    parser.add_argument(
        "--fair-rows",
        type=Path,
        default=ROOT
        / "data/derived/evigate_llm/v6_full/fair_baselines/evigate_llm_fair_baselines.per_case.csv",
    )
    parser.add_argument(
        "--stage-a-rows",
        type=Path,
        default=ROOT / "data/derived/stage_a/baseline_run/stage_a_event_results.csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "data/derived/evigate_llm/v7_bindgate/revision_diagnostics",
    )
    parser.add_argument("--bootstrap-replicates", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260919)
    args = parser.parse_args()

    rows = load_bind_rows(args.bind_rows)
    add_calibrated_margin(rows, load_csv(args.fair_rows))
    clean = [row for row in rows if row["corruption_family"] == "clean"]
    coverage = stage_a_coverage(args.stage_a_rows)
    for row in clean:
        row["stage_a_covered"] = coverage[row["case_id"]]
        row["end_to_end_attributed"] = bool(
            row["stage_a_covered"] and row["full_cascade_attributed"]
        )
        row["end_to_end_correct"] = bool(
            row["end_to_end_attributed"] and row["full_cascade_correct"]
        )
        row["end_to_end_prediction"] = (
            row["full_cascade_prediction"] if row["end_to_end_attributed"] else ""
        )

    prefixes = (
        "full_cascade",
        "full_no_llm",
        "reference_margin",
        "calibrated_margin",
    )
    family_results: dict[str, dict[str, object]] = {}
    for prefix in prefixes:
        family_results[prefix] = {
            family: method_outcomes(
                [row for row in rows if row["corruption_family"] == family], prefix
            )
            for family in ("clean", *ROBUSTNESS_FAMILIES, "process_deletion", "time_shift")
        }
        family_results[prefix]["three_family_macro_wrong_label_rate"] = float(
            np.mean(
                [
                    family_results[prefix][family]["wrong_label_rate"]
                    for family in ROBUSTNESS_FAMILIES
                ]
            )
        )

    comparisons = {
        "matched_margin_minus_full": grouped_bootstrap_macro(
            rows,
            "reference_margin",
            "full_cascade",
            ROBUSTNESS_FAMILIES,
            args.bootstrap_replicates,
            args.seed,
        ),
        "no_llm_minus_full": grouped_bootstrap_macro(
            rows,
            "full_no_llm",
            "full_cascade",
            ROBUSTNESS_FAMILIES,
            args.bootstrap_replicates,
            args.seed + 1,
        ),
        "calibrated_margin_minus_full": grouped_bootstrap_macro(
            rows,
            "calibrated_margin",
            "full_cascade",
            ROBUSTNESS_FAMILIES,
            args.bootstrap_replicates,
            args.seed + 2,
        ),
        "context_exact_mcnemar": {
            "matched_margin_vs_full": exact_mcnemar(
                [row for row in rows if row["corruption_family"] == "context_replacement"],
                "reference_margin",
                "full_cascade",
            ),
            "no_llm_vs_full": exact_mcnemar(
                [row for row in rows if row["corruption_family"] == "context_replacement"],
                "full_no_llm",
                "full_cascade",
            ),
        },
    }
    end_to_end = method_outcomes(clean, "end_to_end")
    end_to_end["stage_a_covered"] = sum(bool(row["stage_a_covered"]) for row in clean)
    end_to_end["stage_a_coverage"] = end_to_end["stage_a_covered"] / len(clean)
    end_to_end["denominator_note"] = (
        "51 non-pilot CICAPT attack-action clusters; the two prompt-development exclusions cannot be "
        "scored by the frozen final LLM artifact"
    )

    tactic_rows = per_tactic(clean, ("full_cascade", "full_no_llm", "end_to_end"))
    stable_clean = [row for row in clean if row["case_id"] not in GAP_MERGED_CASES]
    stable_all = [row for row in rows if row["case_id"] not in GAP_MERGED_CASES]
    gap_sensitivity = {
        "120_seconds": {
            "partition_relation_to_300_seconds": "identical",
            "reason": (
                "For every tactic, the 120-second and 300-second single-linkage cluster counts are "
                "identical; lowering a one-dimensional adjacency threshold can only split a cluster, "
                "so equal per-tactic counts imply the same partition."
            ),
            "stage_c_and_bindgate_results": "identical to the primary 300-second results",
        },
        "600_and_900_seconds": {
            "partition_relation_to_300_seconds": "one merge",
            "merged_clusters": list(GAP_MERGED_CASES.values()),
            "inter_cluster_gap_seconds": 329.590,
            "retained_frozen_llm_events_unaffected": len(stable_clean),
            "retained_frozen_llm_events_total": len(clean),
            "unaffected_subset_stage_c_full_coverage_accuracy": float(
                np.mean([row["machine_proposal"] == row["tactic"] for row in stable_clean])
            ),
            "unaffected_subset_bindgate_clean": method_outcomes(stable_clean, "full_cascade"),
            "unaffected_subset_bindgate_three_family_macro_wrong_label_rate": float(
                np.mean(
                    [
                        method_outcomes(
                            [
                                row
                                for row in stable_all
                                if row["corruption_family"] == family
                            ],
                            "full_cascade",
                        )["wrong_label_rate"]
                        for family in ROBUSTNESS_FAMILIES
                    ]
                )
            ),
            "boundary": (
                "The newly merged event is not assigned a synthetic LLM certificate; therefore these "
                "600/900-second figures are an unaffected-subset audit, not a full rerun."
            ),
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    per_tactic_path = args.output_dir / "evigate_bindgate.per_tactic.csv"
    write_csv(per_tactic_path, tactic_rows)
    end_to_end_path = args.output_dir / "evigate_bindgate.end_to_end.csv"
    write_csv(
        end_to_end_path,
        [
            {
                "case_id": row["case_id"],
                "tactic": row["tactic"],
                "stage_a_covered": row["stage_a_covered"],
                "final_attributed_given_oracle_entry": row["full_cascade_attributed"],
                "final_correct_given_oracle_entry": row["full_cascade_correct"],
                "end_to_end_attributed": row["end_to_end_attributed"],
                "end_to_end_correct": row["end_to_end_correct"],
                "end_to_end_prediction": row["end_to_end_prediction"],
            }
            for row in clean
        ],
    )
    summary = {
        "study": "EviGate-Bind reviewer revision diagnostics",
        "status": "post-freeze analysis of frozen per-case artifacts; no refitting",
        "three_family_definition": list(ROBUSTNESS_FAMILIES),
        "family_results": family_results,
        "paired_comparisons": comparisons,
        "end_to_end": end_to_end,
        "per_tactic": tactic_rows,
        "cluster_gap_sensitivity": gap_sensitivity,
        "training_calibrated_comparator": (
            "The original fold-specific clean-calibration margin decision with the same missing-process "
            "and positive-time-proximity rules as the final cascade; unlike count matching, it uses no "
            "test-fold acceptance count."
        ),
        "input_integrity": {
            "bind_rows_sha256": sha256_file(args.bind_rows),
            "fair_rows_sha256": sha256_file(args.fair_rows),
            "stage_a_rows_sha256": sha256_file(args.stage_a_rows),
        },
        "artifacts": {
            per_tactic_path.name: {"sha256": sha256_file(per_tactic_path)},
            end_to_end_path.name: {"sha256": sha256_file(end_to_end_path)},
        },
    }
    summary_path = args.output_dir / "evigate_bindgate_revision.summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
