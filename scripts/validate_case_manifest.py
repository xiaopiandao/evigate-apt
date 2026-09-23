#!/usr/bin/env python3
"""Validate the minimal Trace2Root case-manifest contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


REQUIRED_TOP_LEVEL = {
    "case_id",
    "status",
    "vendor",
    "device_family",
    "architecture",
    "protocol",
    "cwe",
    "public_sources",
    "firmware",
    "pcap",
    "ground_truth",
    "rehosting",
}
ALLOWED_STATUSES = {
    "ACQUIRED",
    "REHOSTED",
    "ATTACK_REPRODUCED",
    "GROUND_TRUTH_SUPPORTED",
    "RANKED",
    "TAINT_VERIFIED",
    "PREDICATE_VERIFIED",
    "INTERVENTION_ELIGIBLE",
    "COUNTERFACTUALLY_CONFIRMED",
}


def is_sha256(value: object, *, allow_null: bool = False) -> bool:
    if value is None:
        return allow_null
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def validate_case(case: object, index: int) -> list[str]:
    prefix = f"case[{index}]"
    if not isinstance(case, dict):
        return [f"{prefix}: expected an object"]

    errors: list[str] = []
    missing = sorted(REQUIRED_TOP_LEVEL - case.keys())
    if missing:
        errors.append(f"{prefix}: missing fields: {', '.join(missing)}")

    case_id = case.get("case_id")
    if not isinstance(case_id, str) or not case_id.strip():
        errors.append(f"{prefix}.case_id: expected a non-empty string")

    status = case.get("status")
    if not isinstance(status, str) or not (
        status in ALLOWED_STATUSES or status.startswith("FAILED_")
    ):
        errors.append(f"{prefix}.status: unsupported state {status!r}")

    sources = case.get("public_sources")
    if not isinstance(sources, list) or not sources or not all(
        isinstance(item, str) and item.startswith(("https://", "http://"))
        for item in sources
    ):
        errors.append(f"{prefix}.public_sources: expected one or more HTTP(S) URLs")

    firmware = case.get("firmware")
    if not isinstance(firmware, dict):
        errors.append(f"{prefix}.firmware: expected an object")
    else:
        if not is_sha256(firmware.get("vulnerable_sha256")):
            errors.append(f"{prefix}.firmware.vulnerable_sha256: invalid SHA-256")
        if not is_sha256(firmware.get("patched_sha256"), allow_null=True):
            errors.append(f"{prefix}.firmware.patched_sha256: invalid SHA-256 or null")
        if not isinstance(firmware.get("redistributable"), bool):
            errors.append(f"{prefix}.firmware.redistributable: expected boolean")

    pcap = case.get("pcap")
    if not isinstance(pcap, dict):
        errors.append(f"{prefix}.pcap: expected an object")
    else:
        if not is_sha256(pcap.get("sha256")):
            errors.append(f"{prefix}.pcap.sha256: invalid SHA-256")
        if not isinstance(pcap.get("path"), str) or not pcap.get("path"):
            errors.append(f"{prefix}.pcap.path: expected a non-empty path")

    truth = case.get("ground_truth")
    if not isinstance(truth, dict):
        errors.append(f"{prefix}.ground_truth: expected an object")
    else:
        ids = truth.get("candidate_ids")
        if not isinstance(ids, list) or not ids or not all(
            isinstance(item, str) and item for item in ids
        ):
            errors.append(f"{prefix}.ground_truth.candidate_ids: expected non-empty strings")
        if truth.get("granularity") not in {"function", "basic_block"}:
            errors.append(f"{prefix}.ground_truth.granularity: expected function or basic_block")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()

    try:
        cases = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read manifest: {exc}", file=sys.stderr)
        return 2

    if not isinstance(cases, list) or not cases:
        print("ERROR: manifest must be a non-empty JSON array", file=sys.stderr)
        return 2

    errors: list[str] = []
    seen: set[str] = set()
    for index, case in enumerate(cases):
        errors.extend(validate_case(case, index))
        if isinstance(case, dict) and isinstance(case.get("case_id"), str):
            if case["case_id"] in seen:
                errors.append(f"case[{index}].case_id: duplicate {case['case_id']!r}")
            seen.add(case["case_id"])

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    digest = hashlib.sha256(args.manifest.read_bytes()).hexdigest()
    print(f"VALID: {len(cases)} cases; manifest_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
