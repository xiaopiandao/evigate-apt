#!/usr/bin/env python3
"""Cluster bootstrap the frozen EviGate-LLM H1/H2 contrasts."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def as_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes"}


def index_rows(rows: list[dict[str, str]]) -> dict[str, dict[str, list[dict[str, str]]]]:
    indexed: dict[str, dict[str, list[dict[str, str]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        indexed[row["method"]][row["case_id"]].append(row)
    return indexed


def method_metrics(
    case_rows: dict[str, list[dict[str, str]]], sampled_cases: list[str]
) -> dict[str, float]:
    clean_rows: list[dict[str, str]] = []
    corrupted: dict[str, list[dict[str, str]]] = defaultdict(list)
    for case_id in sampled_cases:
        for row in case_rows[case_id]:
            if row["condition"] == "clean":
                clean_rows.append(row)
            else:
                corrupted[row["corruption_family"]].append(row)
    attributed = [row for row in clean_rows if as_bool(row["attributed"])]
    clean_risk = (
        float(np.mean([not as_bool(row["correct"]) for row in attributed]))
        if attributed
        else float("nan")
    )
    family_wrong = [
        float(
            np.mean(
                [
                    as_bool(row["attributed"]) and not as_bool(row["correct"])
                    for row in family_rows
                ]
            )
        )
        for family_rows in corrupted.values()
    ]
    return {
        "coverage": len(attributed) / len(clean_rows),
        "selective_risk": clean_risk,
        "corruption_macro_wrong_label_rate": float(np.mean(family_wrong)),
    }


def interval(values: list[float]) -> list[float]:
    finite = np.asarray([value for value in values if np.isfinite(value)], dtype=float)
    return [float(np.percentile(finite, 2.5)), float(np.percentile(finite, 97.5))]


def run(
    rows: list[dict[str, str]], iterations: int, seed: int
) -> dict[str, Any]:
    indexed = index_rows(rows)
    method_names = ("evigate_llm", "self_abstaining_llm")
    missing = [method for method in method_names if method not in indexed]
    if missing:
        raise ValueError(f"missing calibrated methods: {missing}")
    cases = sorted(set(indexed[method_names[0]]) & set(indexed[method_names[1]]))
    if not cases:
        raise ValueError("no paired cases")
    observed = {
        method: method_metrics(indexed[method], cases) for method in method_names
    }
    rng = np.random.default_rng(seed)
    h1_reduction: list[float] = []
    h2_coverage_gap: list[float] = []
    h2_risk_increase: list[float] = []
    overall_success: list[bool] = []
    for _ in range(iterations):
        sampled = [cases[index] for index in rng.integers(0, len(cases), len(cases))]
        evigate = method_metrics(indexed["evigate_llm"], sampled)
        self_method = method_metrics(indexed["self_abstaining_llm"], sampled)
        h1 = (
            self_method["corruption_macro_wrong_label_rate"]
            - evigate["corruption_macro_wrong_label_rate"]
        )
        coverage_gap = self_method["coverage"] - evigate["coverage"]
        risk_increase = evigate["selective_risk"] - self_method["selective_risk"]
        h1_reduction.append(h1)
        h2_coverage_gap.append(coverage_gap)
        h2_risk_increase.append(risk_increase)
        overall_success.append(
            h1 >= 0.05
            and evigate["coverage"] >= 0.60
            and coverage_gap <= 0.15
            and risk_increase <= 0.10
        )
    return {
        "schema_version": "1.0",
        "study": "EviGate-LLM paired event-cluster bootstrap",
        "paired_cases": len(cases),
        "iterations": iterations,
        "seed": seed,
        "observed": observed,
        "contrasts": {
            "H1_wrong_label_reduction_self_minus_evigate": {
                "observed": observed["self_abstaining_llm"][
                    "corruption_macro_wrong_label_rate"
                ]
                - observed["evigate_llm"]["corruption_macro_wrong_label_rate"],
                "percentile_95_interval": interval(h1_reduction),
                "bootstrap_probability_at_least_0.05": float(
                    np.mean(np.asarray(h1_reduction) >= 0.05)
                ),
            },
            "H2_clean_coverage_gap_self_minus_evigate": {
                "observed": observed["self_abstaining_llm"]["coverage"]
                - observed["evigate_llm"]["coverage"],
                "percentile_95_interval": interval(h2_coverage_gap),
            },
            "H2_clean_risk_increase_evigate_minus_self": {
                "observed": observed["evigate_llm"]["selective_risk"]
                - observed["self_abstaining_llm"]["selective_risk"],
                "percentile_95_interval": interval(h2_risk_increase),
            },
        },
        "bootstrap_probability_all_frozen_criteria_hold": float(
            np.mean(overall_success)
        ),
        "interpretation": "Percentile intervals resample attack-action clusters and retain all six evidence conditions per draw.",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--per-case", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260915)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    result = run(load_rows(args.per_case), args.iterations, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
