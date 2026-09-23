#!/usr/bin/env python3
"""Build order-debiased LLM process-selection packages for prompt development."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
from pathlib import Path
from typing import Any


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def token(*parts: str, width: int = 12) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:width]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build(
    evidence_rows: list[dict[str, Any]],
    study_truth_rows: list[dict[str, Any]],
    case_truth_rows: list[dict[str, Any]],
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_by_sample = {str(row["sample_id"]): row for row in evidence_rows}
    case_truth = {str(row["case_id"]): row for row in case_truth_rows}
    inputs_out: list[dict[str, Any]] = []
    truth_out: list[dict[str, Any]] = []

    selected_truth = [
        row
        for row in study_truth_rows
        if row.get("condition") == "foreign_distractor_holdout"
        and bool(row.get("proposal_correct"))
    ]
    for truth in sorted(selected_truth, key=lambda row: str(row["case_id"])):
        source = copy.deepcopy(evidence_by_sample[str(truth["sample_id"])])
        candidates = copy.deepcopy(source.get("ranked_process_candidates", []))
        rng = random.Random(int(token(str(seed), str(truth["case_id"]), width=16), 16))
        rng.shuffle(candidates)
        ref_to_entity: dict[str, str] = {}
        for index, candidate in enumerate(candidates, 1):
            # Keep the verifier's P<number> contract, but assign the numbers only
            # after a deterministic shuffle so they encode display order, not the
            # upstream ranker's relevance order.
            ref = f"P{index}"
            candidate["process_ref"] = ref
            candidate["rank"] = index
            candidate.pop("ranker_score", None)
            seen_anchor_types: dict[str, int] = {}
            for anchor in candidate.get("anchors", []):
                anchor_type = str(anchor.get("anchor_type", "evidence"))
                seen_anchor_types[anchor_type] = seen_anchor_types.get(anchor_type, 0) + 1
                suffix = (
                    ""
                    if seen_anchor_types[anchor_type] == 1
                    else f"_{seen_anchor_types[anchor_type]}"
                )
                anchor["anchor_id"] = f"{ref}.{anchor_type}{suffix}"
            ref_to_entity[ref] = str(candidate["entity_id"])
        source["ranked_process_candidates"] = candidates
        summary = source.get("provenance_summary", {})
        summary.pop("top_ranker_score", None)
        summary.pop("ranker_score_margin", None)
        sample_id = "pdev_" + token(str(seed), str(truth["case_id"]), width=20)
        source["sample_id"] = sample_id
        inputs_out.append(source)

        original_truth = case_truth[str(truth["case_id"])]
        malicious = set(
            str(value)
            for value in original_truth["provenance_ground_truth"].get(
                "malicious_candidate_process_ids", []
            )
        )
        visible_entities = {str(item["entity_id"]) for item in candidates}
        truth_out.append(
            {
                "sample_id": sample_id,
                "case_id": truth["case_id"],
                "tactic": truth["tactic"],
                "foreign_entity_id": truth["mutation_metadata"]["foreign_entity_id"],
                "malicious_entity_ids": sorted(malicious & visible_entities),
                "reference_to_entity": ref_to_entity,
                "source_sample_id": truth["sample_id"],
                "seed": seed,
            }
        )

    inputs_out.sort(key=lambda row: str(row["sample_id"]))
    truth_out.sort(key=lambda row: str(row["sample_id"]))
    return inputs_out, truth_out


def run(args: argparse.Namespace) -> dict[str, Any]:
    inputs, truth = build(
        load_jsonl(args.inputs),
        load_jsonl(args.study_truth),
        load_jsonl(args.case_truth),
        args.seed,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    inputs_path = args.output_dir / "order_debiased.inputs.jsonl"
    truth_path = args.output_dir / "order_debiased.truth.jsonl"
    write_jsonl(inputs_path, inputs)
    write_jsonl(truth_path, truth)
    result = {
        "schema_version": "1.0",
        "study": "Order-debiased LLM selector prompt development",
        "seed": args.seed,
        "samples": len(inputs),
        "truth_separated_from_inference": True,
        "inputs_sha256": sha256_file(inputs_path),
        "truth_sha256": sha256_file(truth_path),
    }
    (args.output_dir / "order_debiased.manifest.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--study-truth", type=Path, required=True)
    parser.add_argument("--case-truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260922)
    return parser.parse_args()


if __name__ == "__main__":
    print(json.dumps(run(parse_args()), ensure_ascii=False, indent=2, sort_keys=True))
