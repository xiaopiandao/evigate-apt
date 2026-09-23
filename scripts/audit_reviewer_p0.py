#!/usr/bin/env python3
"""Post-freeze tie-metric and embargo-group sensitivity audits.

This script reads frozen per-case predictions; it does not refit, tune, or
replace the primary event-level estimates.  The group bootstrap samples
embargo groups with replacement and retains every event inside a sampled
group, preserving the paired method/family observations for each event.
"""

from __future__ import annotations

import csv
import json
from collections import defaultdict
from math import comb
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "derived" / "reviewer_p0"
STAGE_B = ROOT / "data" / "derived" / "stage_b" / "typed_ranker_run" / "stage_b_typed_ranker.per_case.csv"
BIND = ROOT / "data" / "derived" / "evigate_llm" / "v7_bindgate" / "evaluation_temporal" / "evigate_bindgate.per_case.csv"
TRUTH = ROOT / "data" / "derived" / "evigate_phase2_evidence" / "cases.truth.jsonl"
GROUPS = ROOT / "data" / "derived" / "cicapt_phase2_grouped_splits.json"
FAMILIES = ("socket_type_deletion", "random_entity_deletion", "context_replacement")


def csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def expected_first_hit_reciprocal(row: dict[str, str]) -> float:
    """E[1/rank of first relevant item] under uniform permutation of a tie."""
    if int(row["truth_present"]) == 0:
        return 0.0
    tie = int(row["best_truth_score_tie_size"])
    relevant = int(row["truth_entities_in_best_tie"])
    higher = int(row["optimistic_best_rank"]) - 1
    assert 0 < relevant <= tie
    denominator = comb(tie, relevant)
    return sum(
        comb(tie - position, relevant - 1) / denominator / (higher + position)
        for position in range(1, tie - relevant + 2)
    )


def retrieval_audit() -> dict:
    rows = csv_rows(STAGE_B)
    by_model: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_model[row["model"]].append(row)
    result = {}
    for model, items in sorted(by_model.items()):
        seeds = sorted({int(row["seed"]) for row in items})
        assert all(sum(int(row["seed"]) == seed for row in items) == 59 for seed in seeds)
        all_cases = len(items) // len(seeds)
        support = [row for row in items if row["support_role"] == "in_support"]
        result[model] = {
            "all_cases": all_cases,
            "in_support_cases": len(support) // len(seeds),
            "seeds": seeds,
            "truth_entity_count_more_than_one_per_seed": sum(int(row["truth_process_entity_count"]) > 1 for row in items if int(row["seed"]) == seeds[0]),
            "midrank_mrr_all": float(np.mean([float(row["midrank_reciprocal"]) for row in items])),
            "tie_randomized_mrr_all": float(np.mean([expected_first_hit_reciprocal(row) for row in items])),
            "expected_tie_recall_at_1_all": float(np.mean([float(row["expected_tie_hit_at_1"]) for row in items])),
            "midrank_mrr_in_support": float(np.mean([float(row["midrank_reciprocal"]) for row in support])),
            "tie_randomized_mrr_in_support": float(np.mean([expected_first_hit_reciprocal(row) for row in support])),
        }
    return result


def group_effect_audit() -> dict:
    group_manifest = json.loads(GROUPS.read_text(encoding="utf-8"))
    cluster_to_group = {
        cluster: group["group_id"]
        for group in group_manifest["embargo_groups"]
        for cluster in group["cluster_ids"]
    }
    case_to_group = {}
    for line in TRUTH.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        case_to_group[row["case_id"]] = cluster_to_group[row["source_cluster_id"]]
    predictions = csv_rows(BIND)
    by_case: dict[str, dict[str, dict[str, str]]] = defaultdict(dict)
    for row in predictions:
        family = row["corruption_family"]
        if family in (*FAMILIES, "process_deletion", "time_shift", "clean"):
            assert family not in by_case[row["case_id"]]
            by_case[row["case_id"]][family] = row
    assert len(by_case) == 51
    all_families = (*FAMILIES, "process_deletion", "time_shift", "clean")
    assert all(set(items) == set(all_families) for items in by_case.values())
    group_to_cases: dict[str, list[str]] = defaultdict(list)
    for case_id in sorted(by_case):
        group_to_cases[case_to_group[case_id]].append(case_id)
    group_ids = sorted(group_to_cases)

    def effect(cases: list[str], families: tuple[str, ...]) -> float:
        numerator = sum(
            int(by_case[case][family]["matched_margin_attributed"] == "True" and
                by_case[case][family]["matched_margin_correct"] != "True")
            - int(by_case[case][family]["cascade_attributed"] == "True" and
                  by_case[case][family]["cascade_correct"] != "True")
            for case in cases for family in families
        )
        return numerator / (len(cases) * len(families))

    def clean_risk_effect(cases: list[str]) -> float:
        rows = [by_case[case]["clean"] for case in cases]
        def risk(prefix: str) -> float:
            accepted = [row for row in rows if row[f"{prefix}_attributed"] == "True"]
            return sum(row[f"{prefix}_correct"] != "True" for row in accepted) / len(accepted)
        return risk("matched_margin") - risk("cascade")

    observed = effect(sorted(by_case), FAMILIES)
    assert abs(observed - (0.425 - 0.190)) < 0.001
    rng = np.random.default_rng(20260922)
    draws = {"three_family": [], "five_family": [], "context": [], "clean_risk": []}
    for _ in range(10000):
        selected = rng.choice(group_ids, size=len(group_ids), replace=True)
        cases = [case for group in selected for case in group_to_cases[group]]
        draws["three_family"].append(effect(cases, FAMILIES))
        draws["five_family"].append(effect(cases, (*FAMILIES, "process_deletion", "time_shift")))
        draws["context"].append(effect(cases, ("context_replacement",)))
        draws["clean_risk"].append(clean_risk_effect(cases))
    effects = {
        name: {
            "observed": (clean_risk_effect(sorted(by_case)) if name == "clean_risk" else effect(sorted(by_case), families)),
            "group_bootstrap_ci95": np.quantile(values, [0.025, 0.975]).tolist(),
        }
        for name, values, families in (
            ("three_family", draws["three_family"], FAMILIES),
            ("five_family", draws["five_family"], (*FAMILIES, "process_deletion", "time_shift")),
            ("context", draws["context"], ("context_replacement",)),
            ("clean_risk", draws["clean_risk"], ("clean",)),
        )
    }
    return {
        "families": FAMILIES,
        "events": len(by_case),
        "embargo_groups": len(group_ids),
        "multi_event_groups": sum(len(cases) > 1 for cases in group_to_cases.values()),
        "observed_reduction": observed,
        "group_bootstrap_ci95": effects["three_family"]["group_bootstrap_ci95"],
        "group_bootstrap_probability_positive": float(np.mean(np.asarray(draws["three_family"]) > 0)),
        "effects": effects,
        "resamples": len(draws["three_family"]),
        "seed": 20260922,
    }


def main() -> None:
    report = {"retrieval": retrieval_audit(), "three_family_group_audit": group_effect_audit()}
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "reviewer_p0_audit.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
