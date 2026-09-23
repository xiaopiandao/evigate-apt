#!/usr/bin/env python3
"""Audit label and time-window alignment between CICAPT-IIoT evidence views."""

from __future__ import annotations

import argparse
import csv
import json
import math
from bisect import bisect_left
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


NETWORK_MAP = {
    "collection": "collection",
    "cleanup": "defence_evasion",
    "discovery": "discovery",
    "credential access": "credential_access",
    "command and control": "command_and_control",
    "persistence": "persistence",
    "exfiltration": "exfiltration",
    "lateral movement": "lateral_movement",
}

PROVENANCE_MAP = {
    "collection": "collection",
    "defenceEvasion": "defence_evasion",
    "discovery": "discovery",
    "credentialAccess": "credential_access",
    "CandC": "command_and_control",
    "persistence": "persistence",
    "exfiltration": "exfiltration",
    "lateralMovement": "lateral_movement",
    "initialAccess": "initial_access",
}


def network_attacks(path: Path) -> list[tuple[float, str]]:
    attacks: list[tuple[float, str]] = []
    with path.open("rb") as handle:
        header = [item.decode() for item in handle.readline().rstrip().split(b",")]
        ts_index = header.index("ts")
        label_index = header.index("label")
        sublabel_index = header.index("subLabel")
        expected = len(header)
        for raw in handle:
            parts = raw.rstrip(b"\r\n").split(b",")
            if len(parts) != expected or parts[label_index] != b"1":
                continue
            timestamp = float(parts[ts_index])
            raw_label = parts[sublabel_index].decode("utf-8", errors="replace")
            attacks.append((timestamp, NETWORK_MAP.get(raw_label, f"unmapped:{raw_label}")))
    return attacks


def provenance_attacks(path: Path) -> tuple[list[tuple[float, str]], dict]:
    attacks: list[tuple[float, str]] = []
    labelled_rows = 0
    timestamped_labelled_rows = 0
    type_counts: Counter[str] = Counter()
    tactic_type_counts: Counter[tuple[str, str]] = Counter()
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            if row.get("label", "").strip() != "1":
                continue
            labelled_rows += 1
            row_type = row.get("type", "").strip()
            raw_label = row.get("subLabel", "").strip()
            canonical_label = PROVENANCE_MAP.get(raw_label, f"unmapped:{raw_label}")
            type_counts[row_type] += 1
            tactic_type_counts[(canonical_label, row_type)] += 1
            timestamp = None
            for field in ("time", "seen time", "start time"):
                value = row.get(field, "").strip()
                if value:
                    try:
                        timestamp = float(value)
                        break
                    except ValueError:
                        pass
            if timestamp is None or not math.isfinite(timestamp):
                continue
            timestamped_labelled_rows += 1
            attacks.append((timestamp, canonical_label))

    node_types = {"Process", "Artifact"}
    labelled_nodes = sum(count for row_type, count in type_counts.items() if row_type in node_types)
    labelled_edges = labelled_rows - labelled_nodes
    paper_eight_tactic_nodes = sum(
        count
        for (tactic, row_type), count in tactic_type_counts.items()
        if tactic != "initial_access" and row_type in node_types
    )
    reconciliation = {
        "labelled_rows": labelled_rows,
        "labelled_nodes": labelled_nodes,
        "labelled_edges": labelled_edges,
        "timestamped_labelled_rows": timestamped_labelled_rows,
        "paper_eight_tactic_nodes": paper_eight_tactic_nodes,
        "type_counts": dict(sorted(type_counts.items())),
        "tactic_type_counts": {
            f"{tactic}:{row_type}": count
            for (tactic, row_type), count in sorted(tactic_type_counts.items())
        },
        "note": (
            "The dataset paper reports 330 attack provenance nodes across eight main tactics. "
            "The local CSV additionally contains two initial_access Process nodes and labelled "
            "WasDerivedFrom edges; only timestamped labelled rows enter temporal clustering."
        ),
    }
    return attacks, reconciliation


def window_labels(events: list[tuple[float, str]], size: int) -> dict[int, set[str]]:
    output: dict[int, set[str]] = defaultdict(set)
    for timestamp, label in events:
        output[int(timestamp // size)].add(label)
    return dict(output)


def quantile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] * (upper - position) + ordered[upper] * (position - lower)


def nearest_same_tactic_distances(
    source: list[tuple[float, str]], target: list[tuple[float, str]]
) -> list[float]:
    by_tactic: dict[str, list[float]] = defaultdict(list)
    for timestamp, tactic in target:
        by_tactic[tactic].append(timestamp)
    for timestamps in by_tactic.values():
        timestamps.sort()

    distances: list[float] = []
    for timestamp, tactic in source:
        candidates = by_tactic.get(tactic, [])
        if not candidates:
            continue
        index = bisect_left(candidates, timestamp)
        near = []
        if index < len(candidates):
            near.append(abs(candidates[index] - timestamp))
        if index:
            near.append(abs(candidates[index - 1] - timestamp))
        distances.append(min(near))
    return distances


def tactic_summary(events: list[tuple[float, str]], cluster_gap: int = 300) -> dict:
    grouped: dict[str, list[float]] = defaultdict(list)
    for timestamp, tactic in events:
        grouped[tactic].append(timestamp)
    summary = {}
    for tactic, timestamps in sorted(grouped.items()):
        timestamps.sort()
        clusters = 1 + sum(
            current - previous > cluster_gap
            for previous, current in zip(timestamps, timestamps[1:])
        )
        by_day: dict[str, int] = defaultdict(int)
        for timestamp in timestamps:
            day = datetime.fromtimestamp(timestamp, tz=timezone.utc).date().isoformat()
            by_day[day] += 1
        summary[tactic] = {
            "event_count": len(timestamps),
            "clusters_at_5min_gap": clusters,
            "first_epoch": timestamps[0],
            "last_epoch": timestamps[-1],
            "events_by_utc_day": dict(sorted(by_day.items())),
        }
    return summary


def union_cluster_sensitivity(
    network: list[tuple[float, str]],
    provenance: list[tuple[float, str]],
    gaps: list[int],
) -> dict:
    """Count tactic-specific clusters after merging timestamped attack rows from both views.

    These are fallback, label-derived evaluation units. They must not be interpreted as
    authoritative attack steps when the dataset's Attack_info.csv is available.
    """
    combined = network + provenance
    tactics = sorted({tactic for _, tactic in combined})
    per_tactic: dict[str, dict[str, int]] = {}
    totals = {str(gap): 0 for gap in gaps}
    for tactic in tactics:
        timestamps = sorted(timestamp for timestamp, label in combined if label == tactic)
        counts: dict[str, int] = {}
        for gap in gaps:
            count = 0 if not timestamps else 1 + sum(
                current - previous > gap
                for previous, current in zip(timestamps, timestamps[1:])
            )
            counts[str(gap)] = count
            totals[str(gap)] += count
        per_tactic[tactic] = counts
    return {
        "gap_seconds": gaps,
        "per_tactic": per_tactic,
        "total_clusters": totals,
        "note": (
            "Fallback clusters derived from the union of timestamped labelled rows. "
            "Fixed-window union counts are a different quantity."
        ),
    }


def audit_windows(
    network: list[tuple[float, str]], provenance: list[tuple[float, str]], size: int
) -> dict:
    network_windows = window_labels(network, size)
    provenance_windows = window_labels(provenance, size)
    network_keys = set(network_windows)
    provenance_keys = set(provenance_windows)
    intersection = network_keys & provenance_keys
    union = network_keys | provenance_keys
    matching = sum(
        bool(network_windows[key] & provenance_windows[key]) for key in intersection
    )
    return {
        "window_seconds": size,
        "network_positive_windows": len(network_keys),
        "provenance_positive_windows": len(provenance_keys),
        "paired_positive_windows": len(intersection),
        "union_positive_windows": len(union),
        "positive_window_jaccard": len(intersection) / len(union) if union else None,
        "paired_windows_with_tactic_agreement": matching,
        "tactic_agreement_given_paired": matching / len(intersection) if intersection else None,
        "paired_examples": [
            {
                "start_epoch": key * size,
                "network": sorted(network_windows[key]),
                "provenance": sorted(provenance_windows[key]),
            }
            for key in sorted(intersection)[:10]
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--windows", type=int, nargs="+", default=[30, 60, 300, 900])
    parser.add_argument(
        "--cluster-gaps", type=int, nargs="+", default=[60, 120, 300, 600, 900]
    )
    args = parser.parse_args()

    network = network_attacks(args.network)
    provenance, provenance_reconciliation = provenance_attacks(args.provenance)
    distances = nearest_same_tactic_distances(network, provenance)
    report = {
        "canonical_label_map": {
            "network": NETWORK_MAP,
            "provenance": PROVENANCE_MAP,
            "note": "network cleanup is mapped to defence_evasion because the dataset paper reports the same 192 network records under Defence Evasion",
        },
        "attack_event_counts": {"network": len(network), "provenance": len(provenance)},
        "provenance_label_reconciliation": provenance_reconciliation,
        "tactic_summary": {
            "network": tactic_summary(network),
            "provenance": tactic_summary(provenance),
        },
        "network_to_nearest_same_tactic_provenance_seconds": {
            "count": len(distances),
            "median": quantile(distances, 0.5),
            "p90": quantile(distances, 0.9),
            "p95": quantile(distances, 0.95),
            "max": max(distances) if distances else None,
        },
        "cross_view_union_cluster_sensitivity": union_cluster_sensitivity(
            network, provenance, args.cluster_gaps
        ),
        "window_audits": [audit_windows(network, provenance, size) for size in args.windows],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
