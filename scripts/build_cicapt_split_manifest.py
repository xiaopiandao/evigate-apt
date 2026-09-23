#!/usr/bin/env python3
"""Create deterministic, embargo-safe outer and calibration splits.

This script consumes an attack-cluster manifest.  Overlapping evidence retrieval
intervals are first collapsed into indivisible groups, then groups are assigned
to three approximately tactic-stratified outer folds.  Rare tactics remain in
the manifest for out-of-support evaluation but are never listed as supervised
training/calibration samples.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def embargo_groups(clusters: list[dict], embargo_seconds: int) -> list[dict]:
    if embargo_seconds < 0:
        raise ValueError("embargo_seconds must not be negative")
    ordered = sorted(clusters, key=lambda item: (item["start_epoch"], item["end_epoch"], item["cluster_id"]))
    runs: list[list[dict]] = []
    current: list[dict] = []
    current_end: float | None = None
    for cluster in ordered:
        start = cluster["start_epoch"] - embargo_seconds
        end = cluster["end_epoch"] + embargo_seconds
        if current and current_end is not None and start > current_end:
            runs.append(current)
            current = []
            current_end = None
        current.append(cluster)
        current_end = end if current_end is None else max(current_end, end)
    if current:
        runs.append(current)

    return [
        {
            "group_id": f"embargo_{index:03d}",
            "start_epoch": min(item["start_epoch"] for item in run),
            "end_epoch": max(item["end_epoch"] for item in run),
            "cluster_ids": [item["cluster_id"] for item in run],
            "tactics": dict(sorted(Counter(item["tactic"] for item in run).items())),
        }
        for index, run in enumerate(runs, start=1)
    ]


def _support_counts(group: dict, supported_tactics: set[str]) -> Counter:
    return Counter(
        {tactic: count for tactic, count in group["tactics"].items() if tactic in supported_tactics}
    )


def assign_outer_folds(
    groups: list[dict], tactic_totals: Counter, supported_tactics: set[str], folds: int
) -> dict[str, int]:
    if folds < 2:
        raise ValueError("folds must be at least two")
    tactic_order = sorted(supported_tactics)
    target = {tactic: tactic_totals[tactic] / folds for tactic in tactic_order}
    expected_size = sum(tactic_totals[tactic] for tactic in tactic_order) / folds
    counts = [Counter() for _ in range(folds)]
    sizes = [0 for _ in range(folds)]

    def rarity(group: dict) -> tuple:
        present = [tactic_totals[tactic] for tactic in group["tactics"] if tactic in supported_tactics]
        return (
            min(present) if present else 10**9,
            -sum(_support_counts(group, supported_tactics).values()),
            group["start_epoch"],
            group["group_id"],
        )

    assignments: dict[str, int] = {}
    for group in sorted(groups, key=rarity):
        contribution = _support_counts(group, supported_tactics)
        candidates = []
        for fold in range(folds):
            proposed_counts = [item.copy() for item in counts]
            proposed_sizes = sizes.copy()
            proposed_counts[fold].update(contribution)
            proposed_sizes[fold] += sum(contribution.values())
            tactic_error = sum(
                ((proposed_counts[index][tactic] - target[tactic]) ** 2)
                / max(target[tactic], 1.0)
                for index in range(folds)
                for tactic in tactic_order
            )
            size_error = sum((size - expected_size) ** 2 for size in proposed_sizes)
            candidates.append((tactic_error + 0.05 * size_error, proposed_sizes[fold], fold))
        selected = min(candidates)[2]
        assignments[group["group_id"]] = selected
        counts[selected].update(contribution)
        sizes[selected] += sum(contribution.values())
    return assignments


def select_calibration_groups(
    candidates: list[dict], supported_tactics: set[str], fraction: float
) -> set[str]:
    if not 0 < fraction < 1:
        raise ValueError("calibration fraction must lie between zero and one")
    available = Counter()
    for group in candidates:
        available.update(_support_counts(group, supported_tactics))
    tactic_order = sorted(supported_tactics)
    targets = {
        tactic: max(1, round(available[tactic] * fraction))
        for tactic in tactic_order
        if available[tactic]
    }
    selected: set[str] = set()
    obtained = Counter()

    while any(obtained[tactic] < target for tactic, target in targets.items()):
        best = None
        for group in candidates:
            if group["group_id"] in selected:
                continue
            contribution = _support_counts(group, supported_tactics)
            gain = sum(
                min(contribution[tactic], max(0, target - obtained[tactic])) / target
                for tactic, target in targets.items()
            )
            if gain <= 0:
                continue
            cost = max(1, sum(contribution.values()))
            key = (gain / cost, gain, -cost, -group["start_epoch"])
            if best is None or key > best[0]:
                best = (key, group)
        if best is None:
            break
        group = best[1]
        selected.add(group["group_id"])
        obtained.update(_support_counts(group, supported_tactics))
    return selected


def _cluster_ids(groups: list[dict]) -> list[str]:
    return sorted(cluster_id for group in groups for cluster_id in group["cluster_ids"])


def _partition_summary(ids: list[str], by_id: dict[str, dict], supported: set[str]) -> dict:
    tactics = Counter(by_id[cluster_id]["tactic"] for cluster_id in ids)
    return {
        "all_cluster_count": len(ids),
        "in_support_cluster_count": sum(count for tactic, count in tactics.items() if tactic in supported),
        "out_of_support_cluster_count": sum(count for tactic, count in tactics.items() if tactic not in supported),
        "clusters_by_tactic": dict(sorted(tactics.items())),
    }


def build_split_manifest(
    cluster_manifest: dict,
    cluster_manifest_sha256: str,
    folds: int = 3,
    embargo_seconds: int = 300,
    min_tactic_support: int = 3,
    calibration_fraction: float = 0.2,
) -> dict:
    clusters = cluster_manifest["clusters"]
    by_id = {cluster["cluster_id"]: cluster for cluster in clusters}
    tactic_totals = Counter(cluster["tactic"] for cluster in clusters)
    supported = {tactic for tactic, count in tactic_totals.items() if count >= min_tactic_support}
    unsupported = set(tactic_totals) - supported
    groups = embargo_groups(clusters, embargo_seconds)
    outer_assignment = assign_outer_folds(groups, tactic_totals, supported, folds)

    outer_folds = []
    for fold in range(folds):
        test_groups = [group for group in groups if outer_assignment[group["group_id"]] == fold]
        development_groups = [group for group in groups if outer_assignment[group["group_id"]] != fold]
        calibration_ids = select_calibration_groups(
            development_groups, supported, calibration_fraction
        )
        calibration_groups = [
            group for group in development_groups if group["group_id"] in calibration_ids
        ]
        train_groups = [
            group for group in development_groups if group["group_id"] not in calibration_ids
        ]

        partitions = {}
        for name, partition_groups in (
            ("train", train_groups),
            ("calibration", calibration_groups),
            ("test", test_groups),
        ):
            all_ids = _cluster_ids(partition_groups)
            in_support_ids = [
                cluster_id for cluster_id in all_ids if by_id[cluster_id]["tactic"] in supported
            ]
            out_ids = [
                cluster_id for cluster_id in all_ids if by_id[cluster_id]["tactic"] in unsupported
            ]
            partitions[name] = {
                "embargo_group_ids": sorted(group["group_id"] for group in partition_groups),
                "all_cluster_ids": all_ids,
                "supervised_in_support_cluster_ids": in_support_ids,
                "out_of_support_cluster_ids": out_ids,
                "summary": _partition_summary(all_ids, by_id, supported),
            }
        outer_folds.append({"fold": fold + 1, "partitions": partitions})

    return {
        "schema_version": "1.0",
        "dataset": cluster_manifest.get("dataset"),
        "phase": cluster_manifest.get("phase"),
        "source_cluster_manifest_sha256": cluster_manifest_sha256,
        "source_cluster_manifest_status": cluster_manifest.get("manifest_status"),
        "source_derived_label": cluster_manifest.get("derived_label"),
        "protocol": "three-fold tactic-stratified, attack-cluster-grouped evaluation",
        "embargo_seconds_each_side": embargo_seconds,
        "calibration_fraction_target": calibration_fraction,
        "min_tactic_support": min_tactic_support,
        "in_support_tactics": sorted(supported),
        "out_of_support_tactics": sorted(unsupported),
        "tactic_cluster_totals": dict(sorted(tactic_totals.items())),
        "embargo_group_count": len(groups),
        "embargo_groups": groups,
        "outer_folds": outer_folds,
        "usage_rules": [
            "Only supervised_in_support_cluster_ids may train or calibrate the tactic classifier.",
            "Out-of-support clusters may be evaluated only for rejection and qualitative analysis.",
            "No embargo group may cross train, calibration, and test within an outer fold.",
            "All preprocessing and threshold fitting must be refit inside each outer fold.",
        ],
    }


def validate_split_manifest(manifest: dict) -> None:
    for fold in manifest["outer_folds"]:
        partitions = fold["partitions"]
        group_sets = [set(partitions[name]["embargo_group_ids"]) for name in ("train", "calibration", "test")]
        cluster_sets = [set(partitions[name]["all_cluster_ids"]) for name in ("train", "calibration", "test")]
        if any(group_sets[i] & group_sets[j] for i in range(3) for j in range(i + 1, 3)):
            raise ValueError(f"embargo-group leakage in fold {fold['fold']}")
        if any(cluster_sets[i] & cluster_sets[j] for i in range(3) for j in range(i + 1, 3)):
            raise ValueError(f"cluster leakage in fold {fold['fold']}")
        for name in ("train", "calibration", "test"):
            observed = set(partitions[name]["summary"]["clusters_by_tactic"])
            if name != "test" and not set(manifest["in_support_tactics"]).issubset(observed):
                raise ValueError(f"missing supported tactic in {name}, fold {fold['fold']}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clusters", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--folds", type=int, default=3)
    parser.add_argument("--embargo-seconds", type=int, default=300)
    parser.add_argument("--min-tactic-support", type=int, default=3)
    parser.add_argument("--calibration-fraction", type=float, default=0.2)
    args = parser.parse_args()

    cluster_manifest = json.loads(args.clusters.read_text(encoding="utf-8"))
    manifest = build_split_manifest(
        cluster_manifest,
        sha256_file(args.clusters),
        folds=args.folds,
        embargo_seconds=args.embargo_seconds,
        min_tactic_support=args.min_tactic_support,
        calibration_fraction=args.calibration_fraction,
    )
    validate_split_manifest(manifest)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                "embargo_group_count": manifest["embargo_group_count"],
                "in_support_tactics": manifest["in_support_tactics"],
                "out_of_support_tactics": manifest["out_of_support_tactics"],
                "folds": [
                    {
                        "fold": fold["fold"],
                        "train": fold["partitions"]["train"]["summary"],
                        "calibration": fold["partitions"]["calibration"]["summary"],
                        "test": fold["partitions"]["test"]["summary"],
                    }
                    for fold in manifest["outer_folds"]
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
