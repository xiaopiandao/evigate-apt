#!/usr/bin/env python3
"""Build a deterministic fallback event manifest for CICAPT-IIoT Phase 2.

The preferred event source is the dataset's official ``Attack_info.csv``.  This
script is deliberately a fallback: it forms tactic-specific temporal clusters
from the union of timestamped, attack-labelled network and provenance rows.
The resulting labels are for evaluation and split construction only; they must
never be exposed to an inference-time EviGate-APT component.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from audit_cicapt_alignment import NETWORK_MAP, PROVENANCE_MAP


@dataclass(frozen=True)
class Observation:
    timestamp: float
    tactic: str
    view: str
    detail: str = ""
    entity_type: str = ""
    pid: str = ""


def normalise_pid(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    try:
        return str(int(float(value)))
    except ValueError:
        return value


def sha256_file(path: Path, chunk_size: int = 4 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_description(path: Path, include_hash: bool) -> dict:
    description = {
        "path": path.as_posix(),
        "bytes": path.stat().st_size,
    }
    description["sha256"] = sha256_file(path) if include_hash else None
    return description


def read_network_observations(path: Path) -> tuple[list[Observation], dict]:
    observations: list[Observation] = []
    audit = Counter()
    with path.open("rb") as handle:
        header = [item.decode("utf-8-sig") for item in handle.readline().rstrip().split(b",")]
        indexes = {name: header.index(name) for name in ("ts", "label", "subLabel")}
        detail_index = header.index("subLabelCat") if "subLabelCat" in header else None
        expected = len(header)
        for raw in handle:
            audit["rows_total"] += 1
            parts = raw.rstrip(b"\r\n").split(b",")
            if len(parts) != expected:
                audit["rows_malformed"] += 1
                continue
            if parts[indexes["label"]].strip() != b"1":
                continue
            audit["rows_attack_labelled"] += 1
            try:
                timestamp = float(parts[indexes["ts"]])
            except ValueError:
                audit["rows_attack_invalid_timestamp"] += 1
                continue
            if not math.isfinite(timestamp):
                audit["rows_attack_invalid_timestamp"] += 1
                continue
            raw_tactic = parts[indexes["subLabel"]].decode("utf-8", errors="replace").strip()
            tactic = NETWORK_MAP.get(raw_tactic, f"unmapped:{raw_tactic}")
            detail = ""
            if detail_index is not None:
                detail = parts[detail_index].decode("utf-8", errors="replace").strip()
            observations.append(
                Observation(
                    timestamp=timestamp,
                    tactic=tactic,
                    view="network",
                    detail=detail,
                )
            )
            audit["rows_attack_timestamped"] += 1
    return observations, dict(sorted(audit.items()))


def _first_timestamp(row: dict[str, str]) -> float | None:
    for field in ("time", "seen time", "start time"):
        value = row.get(field, "").strip()
        if not value:
            continue
        try:
            timestamp = float(value)
        except ValueError:
            continue
        if math.isfinite(timestamp):
            return timestamp
    return None


def read_provenance_observations(path: Path) -> tuple[list[Observation], dict]:
    observations: list[Observation] = []
    audit = Counter()
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            audit["rows_total"] += 1
            if row.get("label", "").strip() != "1":
                continue
            audit["rows_attack_labelled"] += 1
            timestamp = _first_timestamp(row)
            if timestamp is None:
                audit["rows_attack_missing_timestamp"] += 1
                continue
            raw_tactic = row.get("subLabel", "").strip()
            tactic = PROVENANCE_MAP.get(raw_tactic, f"unmapped:{raw_tactic}")
            observations.append(
                Observation(
                    timestamp=timestamp,
                    tactic=tactic,
                    view="provenance",
                    entity_type=row.get("type", "").strip(),
                    pid=normalise_pid(row.get("pid", "")),
                )
            )
            audit["rows_attack_timestamped"] += 1
    return observations, dict(sorted(audit.items()))


def _range_for_view(observations: Iterable[Observation], view: str) -> dict | None:
    timestamps = [item.timestamp for item in observations if item.view == view]
    if not timestamps:
        return None
    return {"start_epoch": min(timestamps), "end_epoch": max(timestamps)}


def cluster_observations(
    observations: list[Observation], gap_seconds: int
) -> list[dict]:
    if gap_seconds <= 0:
        raise ValueError("gap_seconds must be positive")

    grouped: dict[str, list[Observation]] = defaultdict(list)
    for observation in observations:
        grouped[observation.tactic].append(observation)

    clusters: list[dict] = []
    for tactic in sorted(grouped):
        ordered = sorted(
            grouped[tactic], key=lambda item: (item.timestamp, item.view, item.detail)
        )
        runs: list[list[Observation]] = []
        current: list[Observation] = []
        for observation in ordered:
            if current and observation.timestamp - current[-1].timestamp > gap_seconds:
                runs.append(current)
                current = []
            current.append(observation)
        if current:
            runs.append(current)

        for index, run in enumerate(runs, start=1):
            views = sorted({item.view for item in run})
            view_counts = Counter(item.view for item in run)
            network_details = Counter(
                item.detail for item in run if item.view == "network" and item.detail
            )
            provenance_types = Counter(
                item.entity_type
                for item in run
                if item.view == "provenance" and item.entity_type
            )
            pids = sorted(
                {item.pid for item in run if item.view == "provenance" and item.pid},
                key=lambda value: (not value.isdigit(), int(value) if value.isdigit() else value),
            )
            start = run[0].timestamp
            end = run[-1].timestamp
            clusters.append(
                {
                    "cluster_id": f"cicapt2_{tactic}_{index:03d}",
                    "tactic": tactic,
                    "start_epoch": start,
                    "end_epoch": end,
                    "duration_seconds": end - start,
                    "views_present": views,
                    "view_counts": dict(sorted(view_counts.items())),
                    "network_time_range": _range_for_view(run, "network"),
                    "provenance_time_range": _range_for_view(run, "provenance"),
                    "network_attack_details": dict(sorted(network_details.items())),
                    "provenance_entity_types": dict(sorted(provenance_types.items())),
                    "malicious_pids_directly_observed": pids,
                    "derived_label": True,
                }
            )
    return clusters


def build_manifest(
    network_path: Path,
    provenance_path: Path,
    gap_seconds: int = 300,
    sensitivity_gaps_seconds: tuple[int, ...] = (60, 120, 300, 600, 900),
    include_hashes: bool = True,
    fallback_reason: str = (
        "Official Attack_info.csv was not available without the dataset portal's "
        "registration/download workflow at the time of retrieval."
    ),
) -> dict:
    network, network_audit = read_network_observations(network_path)
    provenance, provenance_audit = read_provenance_observations(provenance_path)
    combined = network + provenance
    clusters = cluster_observations(combined, gap_seconds)
    tactic_counts = Counter(cluster["tactic"] for cluster in clusters)
    view_coverage = Counter(
        "both" if len(cluster["views_present"]) == 2 else cluster["views_present"][0]
        for cluster in clusters
    )
    sensitivity = {}
    for candidate_gap in sensitivity_gaps_seconds:
        candidate_clusters = cluster_observations(combined, candidate_gap)
        candidate_counts = Counter(cluster["tactic"] for cluster in candidate_clusters)
        sensitivity[str(candidate_gap)] = {
            "cluster_count": len(candidate_clusters),
            "clusters_by_tactic": dict(sorted(candidate_counts.items())),
        }
    return {
        "schema_version": "1.0",
        "dataset": "CICAPT-IIoT2024",
        "phase": 2,
        "manifest_status": "provisional_fallback",
        "authoritative_attack_info_used": False,
        "derived_label": True,
        "fallback_reason": fallback_reason,
        "unit_definition": (
            "Within each canonical tactic, a cluster is a maximal timestamp-ordered run "
            f"whose consecutive labelled observations are at most {gap_seconds} seconds apart."
        ),
        "view_policy": "union of timestamped attack-labelled network and provenance rows",
        "intended_use": "evaluation ground truth and leakage-safe split construction only",
        "leakage_warning": (
            "Do not expose label, subLabel, subLabelCat, cluster boundaries, or malicious PID "
            "fields to any inference-time detector, retriever, ranker, or abstention policy."
        ),
        "gap_seconds": gap_seconds,
        "gap_sensitivity": sensitivity,
        "canonical_label_map": {
            "network": NETWORK_MAP,
            "provenance": PROVENANCE_MAP,
        },
        "source_files": {
            "network": source_description(network_path, include_hashes),
            "provenance": source_description(provenance_path, include_hashes),
        },
        "source_audit": {
            "network": network_audit,
            "provenance": provenance_audit,
        },
        "summary": {
            "cluster_count": len(clusters),
            "clusters_by_tactic": dict(sorted(tactic_counts.items())),
            "clusters_by_view_coverage": dict(sorted(view_coverage.items())),
            "timestamped_observations": {
                "network": len(network),
                "provenance": len(provenance),
            },
        },
        "clusters": clusters,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gap-seconds", type=int, default=300)
    parser.add_argument(
        "--sensitivity-gaps-seconds",
        type=int,
        nargs="+",
        default=[60, 120, 300, 600, 900],
    )
    parser.add_argument("--skip-hashes", action="store_true")
    parser.add_argument(
        "--fallback-reason",
        default=(
            "Official Attack_info.csv was not available without the dataset portal's "
            "registration/download workflow at the time of retrieval."
        ),
    )
    args = parser.parse_args()

    manifest = build_manifest(
        args.network,
        args.provenance,
        gap_seconds=args.gap_seconds,
        sensitivity_gaps_seconds=tuple(args.sensitivity_gaps_seconds),
        include_hashes=not args.skip_hashes,
        fallback_reason=args.fallback_reason,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps(manifest["summary"], indent=2))


if __name__ == "__main__":
    main()
