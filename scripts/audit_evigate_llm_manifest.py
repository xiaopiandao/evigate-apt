#!/usr/bin/env python3
"""Audit EviGate-LLM manifest separation, cardinality, and citation anchors."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


FORBIDDEN_INPUT_KEYS = {
    "condition",
    "corruption_family",
    "support_role",
    "replacement_case_id",
    "malicious_candidate_entity_ids",
    "malicious_candidate_process_ids",
}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def nested_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        result = set(map(str, value))
        for child in value.values():
            result.update(nested_keys(child))
        return result
    if isinstance(value, list):
        result: set[str] = set()
        for child in value:
            result.update(nested_keys(child))
        return result
    return set()


def forbidden_tactic_paths(value: Any, path: tuple[str, ...] = ()) -> list[str]:
    result: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + (str(key),)
            if key == "tactic" and child_path != ("machine_proposal", "tactic"):
                result.append(".".join(child_path))
            result.extend(forbidden_tactic_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            result.extend(forbidden_tactic_paths(child, path + (str(index),)))
    return result


def digest_network(row: dict[str, Any]) -> str:
    encoded = json.dumps(
        row["network_event"], ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def audit(inputs_path: Path, truth_path: Path) -> dict[str, Any]:
    inputs = load_jsonl(inputs_path)
    truth = load_jsonl(truth_path)
    input_map = {row["sample_id"]: row for row in inputs}
    truth_map = {row["sample_id"]: row for row in truth}
    errors: list[str] = []
    if len(input_map) != len(inputs):
        errors.append("duplicate_input_sample_id")
    if len(truth_map) != len(truth):
        errors.append("duplicate_truth_sample_id")
    if set(input_map) != set(truth_map):
        errors.append("input_truth_sample_id_mismatch")

    observed_forbidden = sorted(
        FORBIDDEN_INPUT_KEYS
        & set().union(*(nested_keys(row) for row in inputs))
    )
    observed_forbidden_tactic_paths = sorted(
        set(
            path
            for row in inputs
            for path in forbidden_tactic_paths(
                {key: value for key, value in row.items() if key not in {"sample_id", "test_fold"}}
            )
        )
    )
    if observed_forbidden:
        errors.append("forbidden_input_keys:" + ",".join(observed_forbidden))
    if observed_forbidden_tactic_paths:
        errors.append(
            "forbidden_tactic_paths:" + ",".join(observed_forbidden_tactic_paths)
        )

    condition_counts = Counter(row.get("corruption_family") or "clean" for row in truth)
    is_test_manifest = len(condition_counts) > 1
    if is_test_manifest and (set(condition_counts.values()) != {53} or len(condition_counts) != 6):
        errors.append("unexpected_condition_counts")
    if not is_test_manifest and condition_counts != {"clean": len(truth)}:
        errors.append("unexpected_calibration_conditions")
    case_counts = Counter(row["case_id"] for row in truth)
    if is_test_manifest and (set(case_counts.values()) != {6} or len(case_counts) != 53):
        errors.append("unexpected_case_counts")

    network_hashes: dict[str, set[str]] = defaultdict(set)
    invalid_anchor_packages = 0
    nonempty_process_deletions = 0
    for sample, input_row in input_map.items():
        truth_row = truth_map[sample]
        if input_row["case_id"] != truth_row["case_id"]:
            errors.append(f"case_id_mismatch:{sample}")
        network_hashes[input_row["case_id"]].add(digest_network(input_row))
        anchor_ids: set[str] = set()
        for expected_rank, candidate in enumerate(
            input_row.get("ranked_process_candidates", []), start=1
        ):
            if int(candidate.get("rank", -1)) != expected_rank:
                invalid_anchor_packages += 1
            for anchor in candidate.get("anchors", []):
                anchor_id = str(anchor.get("anchor_id", ""))
                if not anchor_id or anchor_id in anchor_ids:
                    invalid_anchor_packages += 1
                anchor_ids.add(anchor_id)
        if truth_row.get("corruption_family") == "process_deletion":
            if input_row.get("ranked_process_candidates") or int(
                input_row["provenance_summary"].get("process_candidate_count", -1)
            ) != 0:
                nonempty_process_deletions += 1
    if any(len(values) != 1 for values in network_hashes.values()):
        errors.append("network_view_changed_across_conditions")
    if invalid_anchor_packages:
        errors.append(f"invalid_anchor_packages:{invalid_anchor_packages}")
    if nonempty_process_deletions:
        errors.append(f"nonempty_process_deletions:{nonempty_process_deletions}")

    return {
        "schema_version": "1.0",
        "study": "EviGate-LLM manifest audit",
        "status": "pass" if not errors else "fail",
        "input_samples": len(inputs),
        "truth_samples": len(truth),
        "cases": len(case_counts),
        "condition_counts": dict(sorted(condition_counts.items())),
        "manifest_role": "test" if is_test_manifest else "calibration",
        "forbidden_input_keys_observed": observed_forbidden,
        "forbidden_tactic_paths_observed": observed_forbidden_tactic_paths,
        "invalid_anchor_packages": invalid_anchor_packages,
        "nonempty_process_deletions": nonempty_process_deletions,
        "errors": sorted(set(errors)),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    report = audit(args.inputs, args.truth)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    if report["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
