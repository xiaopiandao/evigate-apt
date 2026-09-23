#!/usr/bin/env python3
"""Summarize exploratory order-debiased LLM selection runs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def classify(entity: str | None, truth: dict[str, Any]) -> str:
    if entity is None:
        return "abstain"
    if entity in set(map(str, truth["malicious_entity_ids"])):
        return "malicious"
    if entity == str(truth["foreign_entity_id"]):
        return "foreign"
    return "other"


def read_run(directory: Path) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    truth_path = directory / "order_debiased.truth.jsonl"
    output_path = directory / "qwen3" / "outputs.jsonl"
    truth_by_sample = {str(row["sample_id"]): row for row in load_jsonl(truth_path)}
    selections: dict[str, dict[str, Any]] = {}
    for output in load_jsonl(output_path):
        truth = truth_by_sample[str(output["sample_id"])]
        response = output.get("parsed_response") or {}
        reference = response.get("support_process_ref")
        entity = truth["reference_to_entity"].get(reference)
        valid = bool(output.get("verification", {}).get("contract_valid"))
        issued = bool(
            valid
            and response.get("evidence_sufficient") is True
            and response.get("tactic") == truth["tactic"]
        )
        selected = entity if issued else None
        selections[str(truth["case_id"])] = {
            "entity": selected,
            "outcome": classify(selected, truth),
        }
    return selections, {
        "directory": str(directory),
        "inputs_sha256": sha256_file(directory / "order_debiased.inputs.jsonl"),
        "truth_sha256": sha256_file(truth_path),
        "outputs_sha256": sha256_file(output_path),
    }


def counts(outcomes: list[str]) -> dict[str, int | float]:
    counter = Counter(outcomes)
    total = len(outcomes)
    issued = total - counter["abstain"]
    return {
        "events": total,
        "issued": issued,
        "abstained": counter["abstain"],
        "malicious": counter["malicious"],
        "foreign": counter["foreign"],
        "other": counter["other"],
        "coverage": issued / total if total else 0.0,
        "malicious_per_event": counter["malicious"] / total if total else 0.0,
        "foreign_per_event": counter["foreign"] / total if total else 0.0,
        "malicious_precision_among_issued": counter["malicious"] / issued if issued else 0.0,
    }


def run(args: argparse.Namespace) -> dict[str, Any]:
    runs = [read_run(path) for path in args.run_dirs]
    case_sets = [set(rows) for rows, _ in runs]
    if not case_sets or any(cases != case_sets[0] for cases in case_sets[1:]):
        raise ValueError("run case sets do not match")
    cases = sorted(case_sets[0])
    per_case: list[dict[str, Any]] = []
    ensemble_metrics: dict[str, Any] = {}
    for threshold in (2, 3):
        outcomes = []
        for case_id in cases:
            entity_counts = Counter(
                rows[case_id]["entity"]
                for rows, _ in runs
                if rows[case_id]["entity"] is not None
            )
            winners = [entity for entity, count in entity_counts.items() if count >= threshold]
            entity = winners[0] if len(winners) == 1 else None
            source = next(
                (rows[case_id] for rows, _ in runs if rows[case_id]["entity"] == entity),
                None,
            )
            outcome = source["outcome"] if source is not None else "abstain"
            outcomes.append(outcome)
            if threshold == 2:
                per_case.append(
                    {
                        "case_id": case_id,
                        "selected_entity": entity or "",
                        "outcome": outcome,
                        "agreement_count": entity_counts.get(entity, 0) if entity else 0,
                    }
                )
        ensemble_metrics[f"agreement_at_least_{threshold}_of_3"] = counts(outcomes)

    args.per_case.parent.mkdir(parents=True, exist_ok=True)
    with args.per_case.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(per_case[0]))
        writer.writeheader()
        writer.writerows(per_case)
    result = {
        "schema_version": "1.0",
        "study": "Exploratory order-debiased LLM selection development",
        "status": "development_not_confirmation",
        "single_runs": [
            {**metadata, "metrics": counts([row[case]["outcome"] for case in cases])}
            for row, metadata in runs
        ],
        "ensembles": ensemble_metrics,
        "per_case_sha256": sha256_file(args.per_case),
    }
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dirs", type=Path, nargs=3, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--per-case", type=Path, required=True)
    return parser.parse_args()


if __name__ == "__main__":
    print(json.dumps(run(parse_args()), ensure_ascii=False, indent=2, sort_keys=True))
