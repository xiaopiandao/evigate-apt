#!/usr/bin/env python3
"""Compute Trace2Root ranking and counterfactual metrics from JSON records."""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class CaseResult:
    case_id: str
    first_relevant_rank: int | None
    candidate_count: int
    hits: dict[int, int]
    ndcg: dict[int, float]
    baseline_hits: dict[int, int]
    counterfactual_eligible: bool
    counterfactual_confirmed: bool
    benign_preserved: bool | None

    @property
    def reciprocal_rank(self) -> float:
        return 0.0 if self.first_relevant_rank is None else 1.0 / self.first_relevant_rank

    @property
    def localization_effort(self) -> float:
        if not self.candidate_count:
            return 1.0
        rank = self.first_relevant_rank or self.candidate_count
        return rank / self.candidate_count


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc


def first_rank(ranking: list[str], truth: set[str]) -> int | None:
    for index, candidate_id in enumerate(ranking, start=1):
        if candidate_id in truth:
            return index
    return None


def ndcg_at_k(ranking: list[str], truth: set[str], k: int) -> float:
    dcg = sum(
        1.0 / math.log2(index + 2)
        for index, candidate_id in enumerate(ranking[:k])
        if candidate_id in truth
    )
    ideal_relevant = min(len(truth), k)
    idcg = sum(1.0 / math.log2(index + 2) for index in range(ideal_relevant))
    return 0.0 if idcg == 0 else dcg / idcg


def evaluate_case(
    case: dict[str, object], prediction: dict[str, object], ks: Iterable[int]
) -> CaseResult:
    truth = set(case["ground_truth"]["candidate_ids"])
    candidate_rows = prediction.get("ranked_candidates", [])
    ranking = [row["candidate_id"] for row in candidate_rows]
    if len(ranking) != len(set(ranking)):
        raise ValueError(f"{case['case_id']}: duplicate ranked candidate IDs")

    execution_counts = prediction.get("execution_counts", {})
    baseline_ranking = sorted(
        execution_counts,
        key=lambda candidate_id: (-execution_counts[candidate_id], candidate_id),
    )
    rank = first_rank(ranking, truth)
    baseline_rank = first_rank(baseline_ranking, truth)
    normalized_ks = tuple(sorted(set(ks)))

    return CaseResult(
        case_id=str(case["case_id"]),
        first_relevant_rank=rank,
        candidate_count=len(ranking),
        hits={k: int(rank is not None and rank <= k) for k in normalized_ks},
        ndcg={k: ndcg_at_k(ranking, truth, k) for k in normalized_ks},
        baseline_hits={
            k: int(baseline_rank is not None and baseline_rank <= k)
            for k in normalized_ks
        },
        counterfactual_eligible=bool(prediction.get("counterfactual_eligible", False)),
        counterfactual_confirmed=bool(prediction.get("counterfactual_confirmed", False)),
        benign_preserved=prediction.get("benign_preserved"),
    )


def mean(values: Iterable[float]) -> float:
    values = list(values)
    return 0.0 if not values else sum(values) / len(values)


def aggregate(results: list[CaseResult], ks: Iterable[int]) -> dict[str, object]:
    normalized_ks = tuple(sorted(set(ks)))
    eligible = [row for row in results if row.counterfactual_eligible]
    confirmed = [row for row in results if row.counterfactual_confirmed]
    benign_measured = [row for row in confirmed if row.benign_preserved is not None]
    return {
        "case_count": len(results),
        "hit_at_k": {str(k): mean(row.hits[k] for row in results) for k in normalized_ks},
        "mrr": mean(row.reciprocal_rank for row in results),
        "ndcg_at_k": {str(k): mean(row.ndcg[k] for row in results) for k in normalized_ks},
        "mean_localization_effort": mean(row.localization_effort for row in results),
        "execution_frequency_hit_at_k": {
            str(k): mean(row.baseline_hits[k] for row in results) for k in normalized_ks
        },
        "co_execution_delta_hit_at_k": {
            str(k): mean(row.hits[k] - row.baseline_hits[k] for row in results)
            for k in normalized_ks
        },
        "counterfactual": {
            "eligible_count": len(eligible),
            "confirmed_count": len(confirmed),
            "confirmation_rate_all_cases": len(confirmed) / len(results),
            "confirmation_rate_eligible_cases": (
                0.0 if not eligible else len(confirmed) / len(eligible)
            ),
            "benign_preservation_rate_confirmed": (
                0.0
                if not benign_measured
                else mean(bool(row.benign_preserved) for row in benign_measured)
            ),
            "benign_preservation_measured_count": len(benign_measured),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("cases", type=Path)
    parser.add_argument("predictions", type=Path)
    parser.add_argument("--k", type=int, nargs="+", default=[1, 3, 5])
    args = parser.parse_args()

    if any(k <= 0 for k in args.k):
        parser.error("all k values must be positive")

    try:
        cases = load_json(args.cases)
        predictions = load_json(args.predictions)
        if not isinstance(cases, list) or not isinstance(predictions, list):
            raise ValueError("cases and predictions must both be JSON arrays")
        cases_by_id = {row["case_id"]: row for row in cases}
        predictions_by_id = {row["case_id"]: row for row in predictions}
        missing = sorted(set(cases_by_id) - set(predictions_by_id))
        extra = sorted(set(predictions_by_id) - set(cases_by_id))
        if missing or extra:
            raise ValueError(f"case ID mismatch; missing={missing}, extra={extra}")
        results = [
            evaluate_case(cases_by_id[case_id], predictions_by_id[case_id], args.k)
            for case_id in sorted(cases_by_id)
        ]
    except (KeyError, TypeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    output = {
        "aggregate": aggregate(results, args.k),
        "per_case": [
            {
                "case_id": row.case_id,
                "first_relevant_rank": row.first_relevant_rank,
                "candidate_count": row.candidate_count,
                "reciprocal_rank": row.reciprocal_rank,
                "localization_effort": row.localization_effort,
                "hit_at_k": {str(k): value for k, value in row.hits.items()},
                "ndcg_at_k": {str(k): value for k, value in row.ndcg.items()},
            }
            for row in results
        ],
    }
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
