#!/usr/bin/env python3
"""Build leakage-aware Stage-A window splits for EviGate-APT.

Event-adjacent 15-minute blocks inherit the attack-cluster partition from the
existing grouped split manifest.  The cluster intervals in that manifest are
already expanded by the configured five-minute embargo.  Blocks with no event
embargo are assigned deterministically, with one held-out fold and an
approximately 20% calibration share of the remaining background blocks.

The model feature table and evaluation truth remain physically separate.  This
script reads truth only to audit counts and event membership; it never copies
labels or timestamps into the feature table.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


PARTITIONS = ("train", "calibration", "test")
BACKGROUND_SEED = "evigate-stage-a-background-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_bucket(text: str, modulus: int) -> int:
    value = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:16], 16)
    return value % modulus


def iter_blocks(start_epoch: float, end_epoch: float, block_seconds: int) -> Iterable[int]:
    first = math.floor(start_epoch / block_seconds) * block_seconds
    last = math.floor(end_epoch / block_seconds) * block_seconds
    yield from range(first, last + 1, block_seconds)


def load_feature_ids(path: Path) -> tuple[list[str], list[str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "window_id" not in reader.fieldnames:
            raise ValueError("feature CSV must contain window_id")
        feature_columns = list(reader.fieldnames)
        ids = [row["window_id"] for row in reader]
    if len(ids) != len(set(ids)):
        raise ValueError("feature CSV contains duplicate window_id values")
    return ids, feature_columns


def load_truth(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {
            "window_id",
            "window_start_epoch",
            "network_positive",
            "event_case_ids_json",
        }
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError(f"truth CSV missing required columns: {sorted(required)}")
        for row in reader:
            window_id = row["window_id"]
            if window_id in rows:
                raise ValueError(f"duplicate truth window_id: {window_id}")
            rows[window_id] = {
                "window_start_epoch": int(float(row["window_start_epoch"])),
                "network_positive": int(row["network_positive"]),
                "event_case_ids": json.loads(row["event_case_ids_json"]),
            }
    return rows


def load_case_truth(path: Path) -> dict[str, dict[str, Any]]:
    cases: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            item = json.loads(line)
            cases[item["case_id"]] = item
    return cases


def build_event_block_owners(
    split_manifest: dict[str, Any], block_seconds: int
) -> dict[int, dict[int, str]]:
    groups = {g["group_id"]: g for g in split_manifest["embargo_groups"]}
    owners_by_fold: dict[int, dict[int, str]] = {}
    for fold in split_manifest["outer_folds"]:
        fold_id = int(fold["fold"])
        owners: dict[int, str] = {}
        for partition in PARTITIONS:
            for group_id in fold["partitions"][partition]["embargo_group_ids"]:
                group = groups[group_id]
                for block in iter_blocks(group["start_epoch"], group["end_epoch"], block_seconds):
                    prior = owners.get(block)
                    if prior is not None and prior != partition:
                        raise ValueError(
                            f"fold {fold_id}: embargo block {block} belongs to both "
                            f"{prior} and {partition}"
                        )
                    owners[block] = partition
        owners_by_fold[fold_id] = owners
    return owners_by_fold


def background_partition(block_start: int, fold_id: int) -> str:
    test_fold = 1 + stable_bucket(f"{BACKGROUND_SEED}:test:{block_start}", 3)
    if test_fold == fold_id:
        return "test"
    calibration = stable_bucket(
        f"{BACKGROUND_SEED}:calibration:{fold_id}:{block_start}", 5
    ) == 0
    return "calibration" if calibration else "train"


def expected_case_partitions(cases: dict[str, dict[str, Any]]) -> dict[int, dict[str, str]]:
    result: dict[int, dict[str, str]] = defaultdict(dict)
    for case_id, case in cases.items():
        for membership in case["split_membership"]:
            result[int(membership["fold"])][case_id] = membership["partition"]
    return dict(result)


def build_manifest(
    features_path: Path,
    truth_path: Path,
    cases_truth_path: Path,
    split_path: Path,
    block_seconds: int = 900,
) -> dict[str, Any]:
    feature_ids, feature_columns = load_feature_ids(features_path)
    truth = load_truth(truth_path)
    cases = load_case_truth(cases_truth_path)
    split_manifest = json.loads(split_path.read_text(encoding="utf-8"))

    if set(feature_ids) != set(truth):
        raise ValueError("feature and truth window_id sets differ")
    if block_seconds % 60 != 0:
        raise ValueError("block_seconds must be a multiple of the 60-second window")

    event_owners = build_event_block_owners(split_manifest, block_seconds)
    case_partitions = expected_case_partitions(cases)
    in_support = set(split_manifest["in_support_tactics"])
    folds_out: list[dict[str, Any]] = []

    for fold_id in sorted(event_owners):
        owners = event_owners[fold_id]
        partition_windows: dict[str, list[str]] = {p: [] for p in PARTITIONS}
        partition_blocks: dict[str, set[int]] = {p: set() for p in PARTITIONS}
        assignment_source = Counter()

        for window_id in feature_ids:
            row = truth[window_id]
            block = math.floor(row["window_start_epoch"] / block_seconds) * block_seconds
            if block in owners:
                partition = owners[block]
                assignment_source["event_embargo_block"] += 1
            else:
                partition = background_partition(block, fold_id)
                assignment_source["deterministic_background_block"] += 1
            partition_windows[partition].append(window_id)
            partition_blocks[partition].add(block)

        window_owner = {
            window_id: partition
            for partition, ids in partition_windows.items()
            for window_id in ids
        }
        if len(window_owner) != len(feature_ids):
            raise ValueError(f"fold {fold_id}: window partition overlap or omission")

        event_mismatches: list[dict[str, str]] = []
        for window_id, row in truth.items():
            actual = window_owner[window_id]
            for case_id in row["event_case_ids"]:
                expected = case_partitions.get(fold_id, {}).get(case_id)
                if expected is None:
                    raise ValueError(f"fold {fold_id}: unknown event case {case_id}")
                if actual != expected:
                    event_mismatches.append(
                        {"window_id": window_id, "case_id": case_id, "expected": expected, "actual": actual}
                    )
        if event_mismatches:
            raise ValueError(
                f"fold {fold_id}: {len(event_mismatches)} event-window partition mismatches"
            )

        partitions_out: dict[str, Any] = {}
        for partition in PARTITIONS:
            ids = partition_windows[partition]
            event_ids = sorted(
                {
                    case_id
                    for window_id in ids
                    for case_id in truth[window_id]["event_case_ids"]
                }
            )
            in_support_event_ids = [
                case_id for case_id in event_ids if cases[case_id]["event"]["tactic"] in in_support
            ]
            partitions_out[partition] = {
                "window_ids": ids,
                "summary": {
                    "window_count": len(ids),
                    "block_count": len(partition_blocks[partition]),
                    "network_positive_window_count": sum(
                        truth[window_id]["network_positive"] for window_id in ids
                    ),
                    "event_mapped_window_count": sum(
                        bool(truth[window_id]["event_case_ids"]) for window_id in ids
                    ),
                    "unique_event_case_count": len(event_ids),
                    "in_support_event_case_count": len(in_support_event_ids),
                },
            }

        block_sets = [partition_blocks[p] for p in PARTITIONS]
        block_overlap_count = sum(
            len(block_sets[i] & block_sets[j])
            for i in range(len(block_sets))
            for j in range(i + 1, len(block_sets))
        )
        folds_out.append(
            {
                "fold": fold_id,
                "partitions": partitions_out,
                "audit": {
                    "all_windows_assigned_once": len(window_owner) == len(feature_ids),
                    "block_partition_overlap_count": block_overlap_count,
                    "event_window_partition_mismatch_count": 0,
                    "event_embargo_block_count": len(owners),
                    "assignment_source_window_counts": dict(sorted(assignment_source.items())),
                },
            }
        )

    test_occurrences = Counter(
        window_id
        for fold in folds_out
        for window_id in fold["partitions"]["test"]["window_ids"]
    )
    each_window_test_once = (
        set(test_occurrences) == set(feature_ids)
        and all(count == 1 for count in test_occurrences.values())
    )
    if not each_window_test_once:
        raise ValueError("outer folds do not test every window exactly once")

    return {
        "schema_version": "1.0",
        "dataset": "CICAPT-IIoT2024",
        "phase": 2,
        "protocol": "three-fold event-embargoed 15-minute blocked evaluation",
        "window_seconds": 60,
        "block_seconds": block_seconds,
        "event_embargo_seconds_each_side": split_manifest["embargo_seconds_each_side"],
        "background_assignment_seed": BACKGROUND_SEED,
        "assignment_rules": [
            "Any block intersecting an event embargo group inherits that group's train/calibration/test partition.",
            "Event-free background blocks choose one test fold by a stable SHA-256 bucket.",
            "In each non-test fold, a stable SHA-256 bucket assigns approximately 20% of background blocks to calibration.",
            "All 60-second windows in a 15-minute block remain in one partition.",
            "network_positive and event labels are used only for audits and evaluation summaries, never as model features.",
        ],
        "feature_columns_sha256": hashlib.sha256(
            json.dumps(feature_columns, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "source_files": {
            "features": {"path": str(features_path).replace("\\", "/"), "sha256": sha256_file(features_path)},
            "truth": {"path": str(truth_path).replace("\\", "/"), "sha256": sha256_file(truth_path)},
            "cases_truth": {"path": str(cases_truth_path).replace("\\", "/"), "sha256": sha256_file(cases_truth_path)},
            "event_splits": {"path": str(split_path).replace("\\", "/"), "sha256": sha256_file(split_path)},
        },
        "audit": {
            "feature_window_count": len(feature_ids),
            "truth_window_count": len(truth),
            "feature_truth_id_sets_equal": set(feature_ids) == set(truth),
            "event_case_count": len(cases),
            "fold_count": len(folds_out),
            "each_window_is_test_once_across_outer_folds": each_window_test_once,
            "minimum_test_occurrences_per_window": min(test_occurrences.values()),
            "maximum_test_occurrences_per_window": max(test_occurrences.values()),
        },
        "outer_folds": folds_out,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--cases-truth", type=Path, required=True)
    parser.add_argument("--event-splits", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--block-seconds", type=int, default=900)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    manifest = build_manifest(
        args.features,
        args.truth,
        args.cases_truth,
        args.event_splits,
        args.block_seconds,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    compact = {
        "output": str(args.output),
        "folds": [
            {
                "fold": fold["fold"],
                "partitions": {
                    name: data["summary"]
                    for name, data in fold["partitions"].items()
                },
                "audit": fold["audit"],
            }
            for fold in manifest["outer_folds"]
        ],
    }
    print(json.dumps(compact, indent=2))


if __name__ == "__main__":
    main()
