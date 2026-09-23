#!/usr/bin/env python3
"""Post-freeze descriptive discrimination audit for clean and foreign pairs.

This intentionally reports no inferential interval: overlapping event contexts
make an event-wise confidence interval inappropriate until the embargo-group
analysis is revised separately. No model or threshold is refitted here.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path

from sklearn.metrics import roc_auc_score


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_bool(value: str) -> bool:
    if value not in {"True", "False"}:
        raise ValueError(f"expected serialized Boolean, received {value!r}")
    return value == "True"


def summarize(rows: list[dict[str, str]]) -> dict[str, float | int]:
    labels = [int(row["corruption_family"] == "clean") for row in rows]
    scores = [float(row["binding_score"]) for row in rows]
    if set(labels) != {0, 1}:
        raise ValueError("both clean and context-replacement pairs are required")
    clean = [row for row in rows if row["corruption_family"] == "clean"]
    foreign = [row for row in rows if row["corruption_family"] == "context_replacement"]
    clean_ids = {row["case_id"] for row in clean}
    foreign_ids = {row["case_id"] for row in foreign}
    if clean_ids != foreign_ids or len(clean_ids) != len(clean) or len(foreign_ids) != len(foreign):
        raise ValueError("clean and foreign rows must be one-to-one paired by case")
    return {
        "events": len(clean_ids),
        "clean_vs_foreign_score_auroc": float(roc_auc_score(labels, scores)),
        "clean_binding_pass": sum(parse_bool(row["binding_pass"]) for row in clean),
        "foreign_binding_pass": sum(parse_bool(row["binding_pass"]) for row in foreign),
        "foreign_binding_alarm": sum(not parse_bool(row["binding_pass"]) for row in foreign),
        "clean_cascade_accepted": sum(parse_bool(row["cascade_attributed"]) for row in clean),
        "foreign_cascade_accepted": sum(parse_bool(row["cascade_attributed"]) for row in foreign),
    }


def run(input_path: Path) -> dict[str, object]:
    with input_path.open(encoding="utf-8-sig", newline="") as handle:
        source = list(csv.DictReader(handle))
    selected = [
        row for row in source
        if row["corruption_family"] in {"clean", "context_replacement"}
    ]
    by_fold: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in selected:
        by_fold[row["test_fold"]].append(row)
    return {
        "status": "post-freeze descriptive; frozen scores and thresholds; no refitting",
        "input": str(input_path),
        "input_sha256": sha256_file(input_path),
        "scope": "CICAPT-IIoT non-pilot clean versus different-tactic context replacement",
        "pooled": summarize(selected),
        "by_outer_fold": {fold: summarize(rows) for fold, rows in sorted(by_fold.items())},
        "caveat": (
            "AUC describes synthetic donor replacement on this campaign, not "
            "real collection-failure prevalence or cross-campaign discrimination. "
            "Fold-specific scores are pooled only as a diagnostic; fold-level "
            "AUCs avoid treating their scales as calibrated across folds."
        ),
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        type=Path,
        default=root / "data/derived/evigate_llm/v7_bindgate/evaluation/evigate_bindgate.per_case.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=root / "data/derived/p1_diagnostics/gate_discrimination.json",
    )
    args = parser.parse_args()
    report = run(args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["pooled"], indent=2))


if __name__ == "__main__":
    main()
