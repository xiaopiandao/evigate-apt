#!/usr/bin/env python3
"""Validate paired EviGate-APT inference and evaluation JSONL artifacts."""

from __future__ import annotations

import argparse
import json
import re
import statistics
from pathlib import Path

from build_cicapt_evidence_dataset import assert_input_is_leakage_safe, sha256_file


CASE_ID_PATTERN = re.compile(r"^case_[0-9a-f]{20}$")


def read_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
    return records


def distribution(values: list[int]) -> dict:
    ordered = sorted(values)
    if not ordered:
        return {"min": None, "median": None, "p90": None, "max": None}
    p90_index = round(0.9 * (len(ordered) - 1))
    return {
        "min": ordered[0],
        "median": statistics.median(ordered),
        "p90": ordered[p90_index],
        "max": ordered[-1],
    }


def validate_records(inputs: list[dict], truths: list[dict], expected_count: int | None = None) -> dict:
    errors = []
    if len(inputs) != len(truths):
        errors.append(f"input/truth record count mismatch: {len(inputs)} != {len(truths)}")
    if expected_count is not None and len(inputs) != expected_count:
        errors.append(f"case count differs from index: {len(inputs)} != {expected_count}")

    input_ids = [record.get("case_id") for record in inputs]
    truth_ids = [record.get("case_id") for record in truths]
    if input_ids != truth_ids:
        errors.append("input/truth case order or identifiers differ")
    if len(set(input_ids)) != len(input_ids):
        errors.append("case identifiers are not unique")

    candidate_counts = []
    relation_counts = []
    cases_with_pid_truth = 0
    cases_without_positive_network_rows = 0
    for position, (input_record, truth_record) in enumerate(zip(inputs, truths), start=1):
        case_id = input_record.get("case_id", "")
        if not CASE_ID_PATTERN.fullmatch(case_id):
            errors.append(f"record {position}: non-opaque or malformed case_id")
        try:
            assert_input_is_leakage_safe(
                input_record, truth_record.get("source_cluster_id", "")
            )
        except ValueError as error:
            errors.append(f"{case_id}: leakage assertion failed: {error}")

        graph = input_record.get("provenance_candidate_graph", {})
        entities = graph.get("entities", [])
        relations = graph.get("relations", [])
        entity_ids = [entity.get("entity_id") for entity in entities]
        relation_ids = [relation.get("relation_id") for relation in relations]
        entity_set = set(entity_ids)
        if len(entity_set) != len(entity_ids):
            errors.append(f"{case_id}: duplicate candidate entity identifiers")
        if len(set(relation_ids)) != len(relation_ids):
            errors.append(f"{case_id}: duplicate relation identifiers")
        if graph.get("candidate_entity_count") != len(entities):
            errors.append(f"{case_id}: candidate_entity_count is inconsistent")
        if graph.get("relation_count") != len(relations):
            errors.append(f"{case_id}: relation_count is inconsistent")
        for relation in relations:
            for endpoint_name in ("source_entity_id", "target_entity_id"):
                endpoint = relation.get(endpoint_name)
                if endpoint and endpoint not in entity_set:
                    errors.append(f"{case_id}: relation endpoint is absent from candidates")

        provenance_truth = truth_record.get("provenance_ground_truth", {})
        malicious_entities = set(provenance_truth.get("malicious_candidate_entity_ids", []))
        malicious_processes = set(provenance_truth.get("malicious_candidate_process_ids", []))
        if not malicious_entities <= entity_set:
            errors.append(f"{case_id}: malicious entity truth is outside candidate pool")
        if not malicious_processes <= malicious_entities:
            errors.append(f"{case_id}: malicious process truth is not an entity-truth subset")
        observed_malicious_pids = {
            entity.get("attributes", {}).get("pid")
            for entity in entities
            if entity.get("entity_id") in malicious_processes
            and entity.get("attributes", {}).get("pid")
        }
        if observed_malicious_pids != set(provenance_truth.get("malicious_candidate_pids", [])):
            errors.append(f"{case_id}: malicious PID sidecar does not match candidate attributes")
        if observed_malicious_pids:
            cases_with_pid_truth += 1
        if truth_record.get("network_ground_truth", {}).get("positive_row_count") == 0:
            cases_without_positive_network_rows += 1
        candidate_counts.append(len(entities))
        relation_counts.append(len(relations))

    if errors:
        preview = "\n".join(f"- {error}" for error in errors[:25])
        suffix = f"\n- ... {len(errors) - 25} more" if len(errors) > 25 else ""
        raise ValueError(f"Evidence dataset validation failed:\n{preview}{suffix}")

    return {
        "status": "passed",
        "case_count": len(inputs),
        "unique_case_count": len(set(input_ids)),
        "cases_with_malicious_candidate_pid": cases_with_pid_truth,
        "network_windows_without_positive_rows": cases_without_positive_network_rows,
        "candidate_entity_count": distribution(candidate_counts),
        "relation_count": distribution(relation_counts),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    index = json.loads(args.index.read_text(encoding="utf-8"))
    recorded_input_hash = index["output_files"]["inputs"]["sha256"]
    recorded_truth_hash = index["output_files"]["truth"]["sha256"]
    current_input_hash = sha256_file(args.inputs)
    current_truth_hash = sha256_file(args.truth)
    if recorded_input_hash != current_input_hash:
        raise ValueError("inputs.jsonl hash differs from index")
    if recorded_truth_hash != current_truth_hash:
        raise ValueError("truth.jsonl hash differs from index")

    report = validate_records(
        read_jsonl(args.inputs),
        read_jsonl(args.truth),
        expected_count=index.get("case_count"),
    )
    report["hashes"] = {
        "inputs": current_input_hash,
        "truth": current_truth_hash,
        "index": sha256_file(args.index),
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
