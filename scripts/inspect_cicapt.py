#!/usr/bin/env python3
"""Inspect CICAPT-IIoT network and provenance CSV files without pandas.

The network files are several gigabytes, so the common path uses a byte-level
CSV fast path and falls back to Python's csv parser only for malformed rows.
The script reports label distributions and timestamp ranges needed for the
cross-view data gate.  It never modifies the source data.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def normalise(name: str) -> str:
    return "".join(character for character in name.lower() if character.isalnum())


def iso_utc(value: float | None) -> str | None:
    if value is None or not math.isfinite(value):
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def update_range(current: list[float | None], value: float | None) -> None:
    if value is None or not math.isfinite(value):
        return
    current[0] = value if current[0] is None else min(current[0], value)
    current[1] = value if current[1] is None else max(current[1], value)


def decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace").strip()


def parse_float(value: str | bytes) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def counter_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def scan_network(path: Path) -> dict:
    with path.open("rb") as handle:
        header_bytes = handle.readline().rstrip(b"\r\n").split(b",")
        header = [decode(item) for item in header_bytes]
        indices = {normalise(name): index for index, name in enumerate(header)}
        required = ["ts", "label", "sublabel", "sublabelcat"]
        missing = [name for name in required if name not in indices]
        if missing:
            raise ValueError(f"{path}: missing columns {missing}")

        ts_index = indices["ts"]
        label_index = indices["label"]
        sublabel_index = indices["sublabel"]
        category_index = indices["sublabelcat"]
        expected = len(header)

        rows = 0
        malformed = 0
        timestamps: list[float | None] = [None, None]
        malicious_timestamps: list[float | None] = [None, None]
        labels: Counter[str] = Counter()
        sublabels: Counter[str] = Counter()
        categories: Counter[str] = Counter()

        for raw in handle:
            rows += 1
            parts = raw.rstrip(b"\r\n").split(b",")
            if len(parts) != expected:
                malformed += 1
                try:
                    parsed = next(csv.reader([raw.decode("utf-8", errors="replace")]))
                except (csv.Error, StopIteration):
                    continue
                parts = [item.encode("utf-8") for item in parsed]
                if len(parts) != expected:
                    continue

            timestamp = parse_float(parts[ts_index])
            label = decode(parts[label_index])
            sublabel = decode(parts[sublabel_index])
            category = decode(parts[category_index])
            update_range(timestamps, timestamp)
            labels[label] += 1
            sublabels[sublabel] += 1
            categories[category] += 1
            if label not in {"", "0", "0.0", "benign", "Benign", "normal", "Normal"}:
                update_range(malicious_timestamps, timestamp)

    return {
        "path": str(path.resolve()),
        "bytes": path.stat().st_size,
        "columns": header,
        "row_count": rows,
        "malformed_fast_path_rows": malformed,
        "timestamp_epoch": timestamps,
        "timestamp_utc": [iso_utc(timestamps[0]), iso_utc(timestamps[1])],
        "malicious_timestamp_epoch": malicious_timestamps,
        "malicious_timestamp_utc": [
            iso_utc(malicious_timestamps[0]),
            iso_utc(malicious_timestamps[1]),
        ],
        "label_counts": counter_dict(labels),
        "sub_label_counts": counter_dict(sublabels),
        "sub_label_category_counts": counter_dict(categories),
    }


def first_timestamp(row: list[str], timestamp_indices: Iterable[int]) -> float | None:
    for index in timestamp_indices:
        if index < len(row) and row[index].strip():
            parsed = parse_float(row[index])
            if parsed is not None:
                return parsed
    return None


def scan_provenance(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader)
        indices = {normalise(name): index for index, name in enumerate(header)}
        timestamp_indices = [
            indices[name]
            for name in ("time", "seentime", "starttime")
            if name in indices
        ]
        if not timestamp_indices:
            raise ValueError(f"{path}: no supported timestamp column")

        label_index = indices.get("label")
        sublabel_index = indices.get("sublabel")
        type_index = indices.get("type")
        pid_index = indices.get("pid")

        rows = 0
        timestamps: list[float | None] = [None, None]
        malicious_timestamps: list[float | None] = [None, None]
        labels: Counter[str] = Counter()
        sublabels: Counter[str] = Counter()
        types: Counter[str] = Counter()
        malicious_pids: set[str] = set()

        for row in reader:
            rows += 1
            timestamp = first_timestamp(row, timestamp_indices)
            update_range(timestamps, timestamp)
            label = row[label_index].strip() if label_index is not None else ""
            sublabel = row[sublabel_index].strip() if sublabel_index is not None else ""
            row_type = row[type_index].strip() if type_index is not None else ""
            labels[label] += 1
            sublabels[sublabel] += 1
            types[row_type] += 1
            if label not in {"", "0", "0.0", "benign", "Benign", "normal", "Normal"}:
                update_range(malicious_timestamps, timestamp)
                if pid_index is not None and row[pid_index].strip():
                    malicious_pids.add(row[pid_index].strip())

    return {
        "path": str(path.resolve()),
        "bytes": path.stat().st_size,
        "columns": header,
        "row_count": rows,
        "timestamp_priority": [header[index] for index in timestamp_indices],
        "timestamp_epoch": timestamps,
        "timestamp_utc": [iso_utc(timestamps[0]), iso_utc(timestamps[1])],
        "malicious_timestamp_epoch": malicious_timestamps,
        "malicious_timestamp_utc": [
            iso_utc(malicious_timestamps[0]),
            iso_utc(malicious_timestamps[1]),
        ],
        "label_counts": counter_dict(labels),
        "sub_label_counts": counter_dict(sublabels),
        "type_counts": counter_dict(types),
        "unique_malicious_pids": sorted(malicious_pids),
    }


def phase_overlap(network: dict, provenance: dict) -> dict:
    n_start, n_end = network["timestamp_epoch"]
    p_start, p_end = provenance["timestamp_epoch"]
    if None in {n_start, n_end, p_start, p_end}:
        return {"overlap_seconds": None, "start_offset_seconds": None}
    overlap = max(0.0, min(n_end, p_end) - max(n_start, p_start))
    return {
        "overlap_seconds": overlap,
        "start_offset_seconds": n_start - p_start,
        "end_offset_seconds": n_end - p_end,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase1-network", type=Path)
    parser.add_argument("--phase2-network", type=Path)
    parser.add_argument("--phase1-provenance", type=Path)
    parser.add_argument("--phase2-provenance", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report: dict[str, dict] = {}
    pairs = (
        ("phase1_network", args.phase1_network, scan_network),
        ("phase2_network", args.phase2_network, scan_network),
        ("phase1_provenance", args.phase1_provenance, scan_provenance),
        ("phase2_provenance", args.phase2_provenance, scan_provenance),
    )
    for name, path, scanner in pairs:
        if path is not None:
            report[name] = scanner(path)

    for phase in ("phase1", "phase2"):
        network = report.get(f"{phase}_network")
        provenance = report.get(f"{phase}_provenance")
        if network and provenance:
            report[f"{phase}_cross_view"] = phase_overlap(network, provenance)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
