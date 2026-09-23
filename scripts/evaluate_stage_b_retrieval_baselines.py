#!/usr/bin/env python3
"""Evaluate reproducible zero-model process retrieval for EviGate-APT Stage B."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Any, Callable


BASELINES: dict[str, Callable[[dict[str, Any], str], float]] = {
    "recency": lambda entity, _case_id: float(entity["features"]["time_proximity"]),
    "degree": lambda entity, _case_id: float(entity["features"]["degree_score"]),
    "recency_plus_degree": lambda entity, _case_id: float(
        entity["features"]["recency_degree_score"]
    ),
}


def random_hit_probability(candidate_count: int, truth_count: int, k: int) -> float:
    if truth_count <= 0 or candidate_count <= 0 or k <= 0:
        return 0.0
    k = min(k, candidate_count)
    miss_probability = 1.0
    for draw in range(k):
        miss_probability *= (candidate_count - truth_count - draw) / (candidate_count - draw)
        if miss_probability <= 0:
            return 1.0
    return 1.0 - miss_probability


def random_expected_mrr(candidate_count: int, truth_count: int) -> float:
    if truth_count <= 0 or candidate_count <= 0:
        return 0.0
    log_denominator = (
        math.lgamma(candidate_count + 1)
        - math.lgamma(truth_count + 1)
        - math.lgamma(candidate_count - truth_count + 1)
    )
    total = 0.0
    for rank in range(1, candidate_count - truth_count + 2):
        remaining = candidate_count - rank
        log_numerator = (
            math.lgamma(remaining + 1)
            - math.lgamma(truth_count)
            - math.lgamma(remaining - truth_count + 2)
        )
        total += math.exp(log_numerator - log_denominator) / rank
    return total


def tie_hit_probability(
    higher_count: int, tie_count: int, truth_in_tie_count: int, k: int
) -> float:
    slots = k - higher_count
    if truth_in_tie_count <= 0 or slots <= 0:
        return 0.0
    return random_hit_probability(tie_count, truth_in_tie_count, slots)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def test_fold(case_truth: dict[str, Any]) -> int:
    folds = [
        int(membership["fold"])
        for membership in case_truth["split_membership"]
        if membership["partition"] == "test"
    ]
    if len(folds) != 1:
        raise ValueError(f"case {case_truth['case_id']} must be test in exactly one fold")
    return folds[0]


def rank_case(
    case_input: dict[str, Any],
    case_truth: dict[str, Any],
    baseline: str,
    top_ks: tuple[int, ...],
) -> dict[str, Any]:
    scorer = BASELINES[baseline]
    case_id = case_input["case_id"]
    candidates = [
        entity
        for entity in case_input["provenance_candidate_graph"]["entities"]
        if entity["entity_kind"] == "process"
    ]
    scored = [
        (entity["entity_id"], scorer(entity, case_id), entity["attributes"].get("pid", ""))
        for entity in candidates
    ]
    if not all(math.isfinite(score) for _, score, _ in scored):
        raise ValueError(f"case {case_id}: non-finite {baseline} score")
    ranked = sorted(scored, key=lambda item: (-item[1], item[0]))
    truth_ids = set(case_truth["provenance_ground_truth"]["malicious_candidate_process_ids"])
    truth_positions = [
        index for index, (entity_id, _, _) in enumerate(ranked, start=1) if entity_id in truth_ids
    ]
    truth_present = bool(truth_positions)
    deterministic_rank = min(truth_positions) if truth_positions else None

    if truth_present:
        truth_scores = [score for entity_id, score, _ in ranked if entity_id in truth_ids]
        best_truth_score = max(truth_scores)
        higher = sum(score > best_truth_score for _, score, _ in ranked)
        equal = sum(score == best_truth_score for _, score, _ in ranked)
        truth_in_best_tie = sum(
            entity_id in truth_ids and score == best_truth_score
            for entity_id, score, _ in ranked
        )
        optimistic_rank = higher + 1
        pessimistic_rank = higher + equal
        midrank = (optimistic_rank + pessimistic_rank) / 2.0
    else:
        optimistic_rank = pessimistic_rank = midrank = None
        higher = equal = truth_in_best_tie = 0

    candidate_count = len(ranked)
    normalized_rank = (
        (deterministic_rank - 1) / max(candidate_count - 1, 1)
        if deterministic_rank is not None
        else None
    )
    result = {
        "case_id": case_id,
        "test_fold": test_fold(case_truth),
        "tactic": case_truth["event"]["tactic"],
        "support_role": case_truth["event"]["support_role"],
        "baseline": baseline,
        "process_candidate_count": candidate_count,
        "truth_process_entity_count": len(truth_ids),
        "truth_present": int(truth_present),
        "deterministic_best_rank": deterministic_rank if deterministic_rank is not None else "",
        "optimistic_best_rank": optimistic_rank if optimistic_rank is not None else "",
        "pessimistic_best_rank": pessimistic_rank if pessimistic_rank is not None else "",
        "midrank": midrank if midrank is not None else "",
        "midrank_reciprocal": 1.0 / midrank if midrank is not None else 0.0,
        "best_truth_score_tie_size": equal,
        "truth_entities_in_best_tie": truth_in_best_tie,
        "normalized_best_rank": normalized_rank if normalized_rank is not None else "",
        "reciprocal_rank": 1.0 / deterministic_rank if deterministic_rank is not None else 0.0,
        "top_ranked_entity_id": ranked[0][0] if ranked else "",
        "top_ranked_pid": ranked[0][2] if ranked else "",
    }
    for k in top_ks:
        result[f"hit_at_{k}"] = int(deterministic_rank is not None and deterministic_rank <= k)
        result[f"optimistic_hit_at_{k}"] = int(
            optimistic_rank is not None and optimistic_rank <= k
        )
        result[f"pessimistic_hit_at_{k}"] = int(
            pessimistic_rank is not None and pessimistic_rank <= k
        )
        result[f"expected_tie_hit_at_{k}"] = tie_hit_probability(
            higher, equal, truth_in_best_tie, k
        )
    return result


def analytic_random_case(
    case_input: dict[str, Any], case_truth: dict[str, Any], top_ks: tuple[int, ...]
) -> dict[str, Any]:
    candidates = [
        entity
        for entity in case_input["provenance_candidate_graph"]["entities"]
        if entity["entity_kind"] == "process"
    ]
    candidate_ids = {entity["entity_id"] for entity in candidates}
    truth_ids = set(case_truth["provenance_ground_truth"]["malicious_candidate_process_ids"])
    truth_count = len(candidate_ids & truth_ids)
    candidate_count = len(candidates)
    truth_present = truth_count > 0
    expected_min_rank = (
        (candidate_count + 1) / (truth_count + 1) if truth_present else None
    )
    expected_normalized_rank = (
        (expected_min_rank - 1) / max(candidate_count - 1, 1)
        if expected_min_rank is not None
        else None
    )
    result = {
        "case_id": case_input["case_id"],
        "test_fold": test_fold(case_truth),
        "tactic": case_truth["event"]["tactic"],
        "support_role": case_truth["event"]["support_role"],
        "baseline": "analytic_random_expectation",
        "process_candidate_count": candidate_count,
        "truth_process_entity_count": truth_count,
        "truth_present": int(truth_present),
        "deterministic_best_rank": "",
        "optimistic_best_rank": "",
        "pessimistic_best_rank": "",
        "midrank": expected_min_rank if expected_min_rank is not None else "",
        "midrank_reciprocal": random_expected_mrr(candidate_count, truth_count),
        "best_truth_score_tie_size": "",
        "truth_entities_in_best_tie": "",
        "normalized_best_rank": expected_normalized_rank if expected_normalized_rank is not None else "",
        "reciprocal_rank": random_expected_mrr(candidate_count, truth_count),
        "top_ranked_entity_id": "",
        "top_ranked_pid": "",
    }
    for k in top_ks:
        probability = random_hit_probability(candidate_count, truth_count, k)
        result[f"hit_at_{k}"] = probability
        result[f"optimistic_hit_at_{k}"] = probability
        result[f"pessimistic_hit_at_{k}"] = probability
        result[f"expected_tie_hit_at_{k}"] = probability
    return result


def summarize(rows: list[dict[str, Any]], top_ks: tuple[int, ...]) -> dict[str, Any]:
    if not rows:
        return {"case_count": 0}
    present = [row for row in rows if row["truth_present"]]
    output: dict[str, Any] = {
        "case_count": len(rows),
        "truth_present_case_count": len(present),
        "candidate_pool_recall_ceiling": len(present) / len(rows),
        "mean_process_candidate_count": mean(row["process_candidate_count"] for row in rows),
        "median_process_candidate_count": median(row["process_candidate_count"] for row in rows),
        "maximum_process_candidate_count": max(row["process_candidate_count"] for row in rows),
        "mrr_all_cases": mean(float(row["reciprocal_rank"]) for row in rows),
        "mrr_truth_present": mean(float(row["reciprocal_rank"]) for row in present) if present else math.nan,
        "mean_midrank_reciprocal_all_cases": mean(
            float(row["midrank_reciprocal"]) for row in rows
        ),
        "mean_normalized_best_rank_truth_present": mean(
            float(row["normalized_best_rank"]) for row in present
        )
        if present
        else math.nan,
        "median_normalized_best_rank_truth_present": median(
            float(row["normalized_best_rank"]) for row in present
        )
        if present
        else math.nan,
    }
    for k in top_ks:
        output[f"recall_at_{k}_all_cases"] = mean(row[f"hit_at_{k}"] for row in rows)
        output[f"recall_at_{k}_truth_present"] = (
            mean(row[f"hit_at_{k}"] for row in present) if present else math.nan
        )
        output[f"optimistic_recall_at_{k}_all_cases"] = mean(
            row[f"optimistic_hit_at_{k}"] for row in rows
        )
        output[f"pessimistic_recall_at_{k}_all_cases"] = mean(
            row[f"pessimistic_hit_at_{k}"] for row in rows
        )
        output[f"expected_tie_recall_at_{k}_all_cases"] = mean(
            row[f"expected_tie_hit_at_{k}"] for row in rows
        )
    return output


def evaluate(
    inputs_path: Path,
    truth_path: Path,
    output_dir: Path,
    top_ks: tuple[int, ...] = (1, 5, 10),
) -> dict[str, Any]:
    inputs = {item["case_id"]: item for item in load_jsonl(inputs_path)}
    truths = {item["case_id"]: item for item in load_jsonl(truth_path)}
    if set(inputs) != set(truths):
        raise ValueError("input and truth case ID sets differ")

    rows: list[dict[str, Any]] = []
    for baseline in BASELINES:
        for case_id in sorted(inputs):
            rows.append(rank_case(inputs[case_id], truths[case_id], baseline, top_ks))
    for case_id in sorted(inputs):
        rows.append(analytic_random_case(inputs[case_id], truths[case_id], top_ks))

    by_baseline: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_baseline[row["baseline"]].append(row)
    summaries: dict[str, Any] = {}
    for baseline, material in by_baseline.items():
        summaries[baseline] = {
            "overall": summarize(material, top_ks),
            "in_support": summarize(
                [row for row in material if row["support_role"] == "in_support"], top_ks
            ),
            "out_of_support": summarize(
                [row for row in material if row["support_role"] != "in_support"], top_ks
            ),
            "by_tactic": {
                tactic: summarize([row for row in material if row["tactic"] == tactic], top_ks)
                for tactic in sorted({row["tactic"] for row in material})
            },
            "by_test_fold": {
                str(fold): summarize(
                    [row for row in material if int(row["test_fold"]) == fold], top_ks
                )
                for fold in (1, 2, 3)
            },
        }

    output_dir.mkdir(parents=True, exist_ok=True)
    per_case_path = output_dir / "stage_b_retrieval_baselines.per_case.csv"
    with per_case_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    result = {
        "schema_version": "1.0",
        "experiment": "EviGate-APT Stage-B zero-model process retrieval",
        "candidate_universe": "process entities in the full typed time-window graph",
        "tie_policy": {
            "primary": "score descending, then opaque entity_id ascending",
            "audit": "optimistic and pessimistic hit bounds are reported for score ties",
        },
        "top_ks": list(top_ks),
        "baselines": [*BASELINES, "analytic_random_expectation"],
        "summary": summaries,
        "source_files": {
            "inputs": {"path": inputs_path.as_posix(), "sha256": sha256_file(inputs_path)},
            "truth": {"path": truth_path.as_posix(), "sha256": sha256_file(truth_path)},
        },
        "output_files": {
            "per_case": {"path": per_case_path.as_posix(), "sha256": sha256_file(per_case_path)}
        },
        "warnings": [
            "Truth labels are physically separate from inference inputs and are read only during evaluation.",
            "One of 59 cases has no malicious process entity in the candidate graph; all-case metrics retain this miss.",
            "Several cases have thousands of process candidates, so normalized rank is reported beside Recall@k.",
        ],
    }
    summary_path = output_dir / "stage_b_retrieval_baselines.summary.json"
    summary_path.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"summary": summary_path.as_posix(), "results": summaries}, indent=2))
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
    top_ks = tuple(sorted(set(args.top_k)))
    if not top_ks or top_ks[0] <= 0:
        raise ValueError("top-k values must be positive")
    evaluate(args.inputs, args.truth, args.output_dir, top_ks)


if __name__ == "__main__":
    main()
