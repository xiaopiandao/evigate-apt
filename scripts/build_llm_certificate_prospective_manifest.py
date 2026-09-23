#!/usr/bin/env python3
"""Build the preregistered prospective LLM certificate mutation suite."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import random
from pathlib import Path
from typing import Any


CONDITIONS = (
    "clean",
    "reference_renaming",
    "semantic_evidence_suppression",
    "false_proposal_contradiction",
    "foreign_candidate_injection",
)
TACTICS = (
    "collection",
    "command_and_control",
    "credential_access",
    "discovery",
    "exfiltration",
)
DIAGNOSTIC_ANCHOR_TYPES = {"identity", "command", "file", "socket", "operation"}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def opaque_id(*parts: str, width: int = 20) -> str:
    payload = "\0".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:width]


def prospective_sample_id(case_id: str, condition: str) -> str:
    return "pcert_" + opaque_id(case_id, condition, width=20)


def clean_base_rows(
    inputs: list[dict[str, Any]], truths: dict[str, dict[str, Any]]
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    result = []
    for row in inputs:
        truth = truths.get(str(row["sample_id"]))
        if not truth:
            continue
        if truth.get("condition") != "clean" or truth.get("support_role") != "in_support":
            continue
        result.append((copy.deepcopy(row), copy.deepcopy(truth)))
    return sorted(result, key=lambda pair: pair[0]["case_id"])


def rename_references(row: dict[str, Any], seed: int) -> tuple[dict[str, Any], dict[str, Any]]:
    result = copy.deepcopy(row)
    entity_map: dict[str, str] = {}
    anchor_map: dict[str, str] = {}
    for candidate in result["ranked_process_candidates"]:
        old_entity = str(candidate["entity_id"])
        new_entity = "E" + opaque_id(str(seed), row["case_id"], "entity", old_entity, width=16)
        candidate["entity_id"] = new_entity
        entity_map[old_entity] = new_entity
        for anchor in candidate.get("anchors", []):
            old_anchor = str(anchor["anchor_id"])
            new_anchor = "A" + opaque_id(
                str(seed), row["case_id"], "anchor", old_anchor, width=16
            )
            anchor["anchor_id"] = new_anchor
            anchor_map[old_anchor] = new_anchor
    return result, {"entity_id_map": entity_map, "anchor_id_map": anchor_map}


def suppress_semantic_evidence(row: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(row)
    for candidate in result["ranked_process_candidates"]:
        candidate["process"] = {"name": "", "executable": "", "command_line": ""}
        candidate["anchors"] = [
            anchor
            for anchor in candidate.get("anchors", [])
            if anchor.get("anchor_type") not in DIAGNOSTIC_ANCHOR_TYPES
        ]
    summary = result.get("provenance_summary", {})
    summary["top3_matched_socket_both"] = 0
    summary["top3_socket_neighbors"] = 0
    summary["top3_file_neighbors"] = 0
    return result


def contradict_proposal(row: dict[str, Any], truth_tactic: str) -> tuple[dict[str, Any], str]:
    result = copy.deepcopy(row)
    proposal = result["machine_proposal"]
    probabilities = {key: float(value) for key, value in proposal["probabilities"].items()}
    alternatives = [tactic for tactic in TACTICS if tactic != truth_tactic]
    false_tactic = min(alternatives, key=lambda tactic: (probabilities[tactic], tactic))
    original_tactic = str(proposal["tactic"])
    probabilities[false_tactic], probabilities[original_tactic] = (
        probabilities[original_tactic],
        probabilities[false_tactic],
    )
    ordered = sorted(probabilities.values(), reverse=True)
    proposal.update(
        {
            "tactic": false_tactic,
            "confidence": round(probabilities[false_tactic], 6),
            "margin": round(ordered[0] - ordered[1], 6),
            "probabilities": {tactic: round(probabilities[tactic], 6) for tactic in TACTICS},
        }
    )
    if proposal["tactic"] == truth_tactic:
        raise AssertionError("contradictory proposal unexpectedly equals truth")
    return result, false_tactic


def rerank_candidate(candidate: dict[str, Any], rank: int) -> dict[str, Any]:
    result = copy.deepcopy(candidate)
    result["rank"] = rank
    seen: dict[str, int] = {}
    for anchor in result.get("anchors", []):
        kind = str(anchor.get("anchor_type", "evidence"))
        seen[kind] = seen.get(kind, 0) + 1
        suffix = "" if seen[kind] == 1 else f"_{seen[kind]}"
        anchor["anchor_id"] = f"P{rank}.{kind}{suffix}"
    return result


def choose_donor(
    target_row: dict[str, Any],
    target_truth: dict[str, Any],
    bases: list[tuple[dict[str, Any], dict[str, Any]]],
    seed: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    eligible = [
        pair
        for pair in bases
        if pair[0]["case_id"] != target_row["case_id"]
        and pair[1]["tactic"] != target_truth["tactic"]
        and pair[0]["machine_proposal"]["tactic"] != target_row["machine_proposal"]["tactic"]
        and pair[0].get("ranked_process_candidates")
    ]
    if not eligible:
        raise ValueError(f"no eligible donor for {target_row['case_id']}")
    selector = int(opaque_id(str(seed), target_row["case_id"], "donor", width=16), 16)
    return eligible[selector % len(eligible)]


def inject_foreign_candidate(
    row: dict[str, Any],
    truth: dict[str, Any],
    bases: list[tuple[dict[str, Any], dict[str, Any]]],
    seed: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    result = copy.deepcopy(row)
    donor_row, donor_truth = choose_donor(row, truth, bases, seed)
    donor = copy.deepcopy(donor_row["ranked_process_candidates"][0])
    donor["entity_id"] = "F" + opaque_id(
        str(seed), row["case_id"], donor_row["case_id"], str(donor["entity_id"]), width=16
    )
    target_scores = [float(item.get("ranker_score", 0.0)) for item in result["ranked_process_candidates"]]
    donor["ranker_score"] = round((max(target_scores) if target_scores else 0.0) + 0.01, 6)
    combined = [donor] + result["ranked_process_candidates"][:9]
    combined = [rerank_candidate(candidate, rank) for rank, candidate in enumerate(combined, 1)]
    result["ranked_process_candidates"] = combined
    summary = result["provenance_summary"]
    summary["presented_process_count"] = len(combined)
    summary["process_candidate_count"] = int(summary.get("process_candidate_count", len(combined))) + 1
    summary["top_ranker_score"] = donor["ranker_score"]
    second = float(combined[1].get("ranker_score", 0.0)) if len(combined) > 1 else 0.0
    summary["ranker_score_margin"] = round(donor["ranker_score"] - second, 6)
    return result, {
        "foreign_entity_id": donor["entity_id"],
        "foreign_process_ref": "P1",
        "donor_case_id": donor_row["case_id"],
        "donor_truth_tactic": donor_truth["tactic"],
        "donor_proposal_tactic": donor_row["machine_proposal"]["tactic"],
    }


def build_suite(
    input_rows: list[dict[str, Any]], truth_rows: list[dict[str, Any]], seed: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    truth_by_sample = {str(row["sample_id"]): row for row in truth_rows}
    bases = clean_base_rows(input_rows, truth_by_sample)
    if not bases:
        raise ValueError("no clean in-support rows found")
    evidence_out: list[dict[str, Any]] = []
    truth_out: list[dict[str, Any]] = []
    for base, truth in bases:
        for condition in CONDITIONS:
            mutation_meta: dict[str, Any] = {}
            if condition == "clean":
                transformed = copy.deepcopy(base)
            elif condition == "reference_renaming":
                transformed, mutation_meta = rename_references(base, seed)
            elif condition == "semantic_evidence_suppression":
                transformed = suppress_semantic_evidence(base)
                mutation_meta = {"behavior_specific_support_removed": True}
            elif condition == "false_proposal_contradiction":
                transformed, false_tactic = contradict_proposal(base, str(truth["tactic"]))
                mutation_meta = {"false_proposal_tactic": false_tactic}
            elif condition == "foreign_candidate_injection":
                transformed, mutation_meta = inject_foreign_candidate(
                    base, truth, bases, seed
                )
            else:
                raise AssertionError(condition)
            sid = prospective_sample_id(str(base["case_id"]), condition)
            transformed["sample_id"] = sid
            evidence_out.append(transformed)
            truth_out.append(
                {
                    "sample_id": sid,
                    "case_id": base["case_id"],
                    "test_fold": int(truth["test_fold"]),
                    "condition": condition,
                    "tactic": truth["tactic"],
                    "support_role": truth["support_role"],
                    "source_sample_id": base["sample_id"],
                    "mutation_metadata": mutation_meta,
                }
            )
    evidence_out.sort(key=lambda row: row["sample_id"])
    truth_out.sort(key=lambda row: row["sample_id"])
    return evidence_out, truth_out


def run(args: argparse.Namespace) -> dict[str, Any]:
    random.seed(args.seed)
    evidence_rows, truth_rows = build_suite(
        load_jsonl(args.inputs), load_jsonl(args.truth), args.seed
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    inputs_path = args.output_dir / "certificate_study.inputs.jsonl"
    truth_path = args.output_dir / "certificate_study.truth.jsonl"
    write_jsonl(inputs_path, evidence_rows)
    write_jsonl(truth_path, truth_rows)
    counts = {condition: sum(row["condition"] == condition for row in truth_rows) for condition in CONDITIONS}
    manifest = {
        "schema_version": "1.0",
        "study": "Prospective grounded LLM evidence-certificate validation",
        "seed": args.seed,
        "conditions": list(CONDITIONS),
        "events": len({row["case_id"] for row in truth_rows}),
        "samples": len(evidence_rows),
        "samples_by_condition": counts,
        "truth_separated_from_inference": True,
        "source_files": {
            "inputs": {"path": str(args.inputs), "sha256": sha256_file(args.inputs)},
            "truth": {"path": str(args.truth), "sha256": sha256_file(args.truth)},
        },
        "artifacts": {
            inputs_path.name: {"sha256": sha256_file(inputs_path), "bytes": inputs_path.stat().st_size},
            truth_path.name: {"sha256": sha256_file(truth_path), "bytes": truth_path.stat().st_size},
        },
    }
    manifest_path = args.output_dir / "certificate_study.manifest.json"
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
    parser.add_argument("--seed", type=int, default=20260919)
    return parser.parse_args()


def main() -> None:
    print(json.dumps(run(parse_args()), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

