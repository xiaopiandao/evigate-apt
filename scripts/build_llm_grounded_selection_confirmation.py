#!/usr/bin/env python3
"""Build the held-out grounded support-process selection confirmation."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any


CONDITIONS = ("clean", "opaque_anchor_control", "foreign_distractor_holdout")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def digest(*parts: str, width: int = 20) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()[:width]


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def clean_bases(
    inputs: list[dict[str, Any]], truths: list[dict[str, Any]]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    truth_map = {str(row["sample_id"]): row for row in truths}
    pairs = []
    for row in inputs:
        truth = truth_map.get(str(row["sample_id"]))
        if truth and truth.get("condition") == "clean" and truth.get("support_role") == "in_support":
            pairs.append((copy.deepcopy(row), copy.deepcopy(truth)))
    return sorted(pairs, key=lambda pair: pair[0]["case_id"])


def add_explicit_refs(row: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(row)
    for candidate in result["ranked_process_candidates"]:
        candidate["process_ref"] = f"P{int(candidate['rank'])}"
    return result


def rename_anchors(row: dict[str, Any], seed: int) -> tuple[dict[str, Any], dict[str, str]]:
    result = add_explicit_refs(row)
    mapping = {}
    for candidate in result["ranked_process_candidates"]:
        for anchor in candidate.get("anchors", []):
            old = str(anchor["anchor_id"])
            new = "A" + digest(str(seed), row["case_id"], old, width=18)
            anchor["anchor_id"] = new
            mapping[old] = new
    return result, mapping


def rerank(candidate: dict[str, Any], rank: int) -> dict[str, Any]:
    result = copy.deepcopy(candidate)
    result["rank"] = rank
    result["process_ref"] = f"P{rank}"
    seen: dict[str, int] = {}
    for anchor in result.get("anchors", []):
        kind = str(anchor.get("anchor_type", "evidence"))
        seen[kind] = seen.get(kind, 0) + 1
        suffix = "" if seen[kind] == 1 else f"_{seen[kind]}"
        anchor["anchor_id"] = f"P{rank}.{kind}{suffix}"
    return result


def donor_for(
    target: dict[str, Any],
    truth: dict[str, Any],
    bases: list[tuple[dict[str, Any], dict[str, Any]]],
    seed: int,
    excluded_donor_case_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    eligible = [
        pair
        for pair in bases
        if pair[0]["case_id"] != target["case_id"]
        and pair[0]["case_id"] != excluded_donor_case_id
        and pair[1]["tactic"] != truth["tactic"]
        and pair[0]["machine_proposal"]["tactic"] != target["machine_proposal"]["tactic"]
        and len(pair[0].get("ranked_process_candidates", [])) >= 2
    ]
    if not eligible:
        raise ValueError(f"no held-out donor for {target['case_id']}")
    index = int(digest(str(seed), target["case_id"], "rank2-donor", width=16), 16)
    return eligible[index % len(eligible)]


def inject_holdout(
    row: dict[str, Any],
    truth: dict[str, Any],
    bases: list[tuple[dict[str, Any], dict[str, Any]]],
    seed: int,
    excluded_donor_case_id: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = copy.deepcopy(row)
    donor_row, donor_truth = donor_for(
        row, truth, bases, seed, excluded_donor_case_id=excluded_donor_case_id
    )
    donor = copy.deepcopy(donor_row["ranked_process_candidates"][1])
    donor["entity_id"] = "F" + digest(
        str(seed), row["case_id"], donor_row["case_id"], str(donor["entity_id"]), width=18
    )
    target_scores = [float(item.get("ranker_score", 0.0)) for item in result["ranked_process_candidates"]]
    donor["ranker_score"] = round((max(target_scores) if target_scores else 0.0) + 0.01, 6)
    candidates = [donor] + result["ranked_process_candidates"][:9]
    result["ranked_process_candidates"] = [rerank(item, rank) for rank, item in enumerate(candidates, 1)]
    summary = result["provenance_summary"]
    summary["presented_process_count"] = len(candidates)
    summary["process_candidate_count"] = int(summary.get("process_candidate_count", len(candidates))) + 1
    summary["top_ranker_score"] = donor["ranker_score"]
    summary["ranker_score_margin"] = round(
        donor["ranker_score"] - float(candidates[1].get("ranker_score", 0.0)), 6
    )
    return result, {
        "foreign_entity_id": donor["entity_id"],
        "foreign_process_ref": "P1",
        "donor_case_id": donor_row["case_id"],
        "donor_candidate_source_rank": 2,
        "donor_truth_tactic": donor_truth["tactic"],
    }


def build(
    input_rows: list[dict[str, Any]],
    truth_rows: list[dict[str, Any]],
    seed: int,
    excluded_donors: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    bases = clean_bases(input_rows, truth_rows)
    excluded_donors = excluded_donors or {}
    evidence_out = []
    truth_out = []
    for base, truth in bases:
        proposal_correct = base["machine_proposal"]["tactic"] == truth["tactic"]
        for condition in CONDITIONS:
            metadata: dict[str, Any] = {}
            if condition == "clean":
                transformed = add_explicit_refs(base)
            elif condition == "opaque_anchor_control":
                transformed, anchor_map = rename_anchors(base, seed)
                metadata = {"anchor_id_map": anchor_map}
            elif condition == "foreign_distractor_holdout":
                transformed, metadata = inject_holdout(
                    base,
                    truth,
                    bases,
                    seed,
                    excluded_donor_case_id=excluded_donors.get(str(base["case_id"])),
                )
            else:
                raise AssertionError(condition)
            sample_id = "gsel_" + digest(base["case_id"], condition, str(seed), width=20)
            transformed["sample_id"] = sample_id
            evidence_out.append(transformed)
            truth_out.append(
                {
                    "sample_id": sample_id,
                    "case_id": base["case_id"],
                    "test_fold": int(truth["test_fold"]),
                    "condition": condition,
                    "tactic": truth["tactic"],
                    "proposal_correct": proposal_correct,
                    "source_sample_id": base["sample_id"],
                    "mutation_metadata": metadata,
                }
            )
    evidence_out.sort(key=lambda row: row["sample_id"])
    truth_out.sort(key=lambda row: row["sample_id"])
    return evidence_out, truth_out


def run(args: argparse.Namespace) -> dict[str, Any]:
    prior_truth = load_jsonl(args.exclude_donors_truth)
    excluded_donors = {
        str(row["case_id"]): str(row["mutation_metadata"]["donor_case_id"])
        for row in prior_truth
        if row.get("condition") == "foreign_candidate_injection"
        and row.get("mutation_metadata", {}).get("donor_case_id")
    }
    evidence, truth = build(
        load_jsonl(args.inputs), load_jsonl(args.truth), args.seed, excluded_donors
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    inputs_path = args.output_dir / "grounded_selection.inputs.jsonl"
    truth_path = args.output_dir / "grounded_selection.truth.jsonl"
    write_jsonl(inputs_path, evidence)
    write_jsonl(truth_path, truth)
    manifest = {
        "schema_version": "1.0",
        "study": "Held-out grounded support-process selection confirmation",
        "seed": args.seed,
        "conditions": list(CONDITIONS),
        "events": len({row["case_id"] for row in truth}),
        "proposal_correct_events": len(
            {row["case_id"] for row in truth if row["proposal_correct"]}
        ),
        "samples": len(evidence),
        "samples_by_condition": {
            condition: sum(row["condition"] == condition for row in truth)
            for condition in CONDITIONS
        },
        "truth_separated_from_inference": True,
        "source_files": {
            "inputs": {"path": str(args.inputs), "sha256": sha256_file(args.inputs)},
            "truth": {"path": str(args.truth), "sha256": sha256_file(args.truth)},
            "excluded_donors_truth": {
                "path": str(args.exclude_donors_truth),
                "sha256": sha256_file(args.exclude_donors_truth),
            },
        },
        "artifacts": {
            inputs_path.name: {"sha256": sha256_file(inputs_path), "bytes": inputs_path.stat().st_size},
            truth_path.name: {"sha256": sha256_file(truth_path), "bytes": truth_path.stat().st_size},
        },
    }
    manifest_path = args.output_dir / "grounded_selection.manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--exclude-donors-truth", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260921)
    return parser.parse_args()


if __name__ == "__main__":
    print(json.dumps(run(parse_args()), ensure_ascii=False, indent=2, sort_keys=True))
