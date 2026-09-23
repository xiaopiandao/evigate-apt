#!/usr/bin/env python3
"""Build leakage-separated 60-second CICAPT network windows."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from audit_cicapt_alignment import NETWORK_MAP
from build_cicapt_evidence_dataset import opaque_case_id, sha256_file


NUMERIC_COLUMNS = (
    "flow_duration",
    "Header_Length",
    "Rate",
    "Srate",
    "Drate",
    "Duration",
    "Tot size",
    "Number",
    "Magnitue",
    "Radius",
    "Covariance",
    "Variance",
    "flow_active_time",
)

EXCLUDED_RAW_COLUMNS = {
    "IAT": "contains Unix-epoch-scale values and would leak campaign time",
    "flow_idle_time": "contains Unix-epoch-scale values and would leak campaign time",
    "ts": "absolute packet time is metadata, not a model feature",
    "label": "evaluation truth only",
    "subLabel": "evaluation truth only",
    "subLabelCat": "evaluation truth only",
}

FLAG_COLUMNS = (
    "fin_flag_number",
    "syn_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "ack_flag_number",
)

# Fixed before evaluation: no vocabulary or port feature is selected from the
# held-out campaign.  These ports represent common Internet/IIoT services.
PROTOCOL_VOCABULARY = ("ARP", "ICMP", "TCP", "UDP")
FIXED_DESTINATION_PORTS = ("53", "80", "443", "502", "1883", "1900", "8883", "8888")
PORT_BANDS = {
    "well_known": (1, 1023),
    "registered": (1024, 49151),
    "dynamic": (49152, 65535),
}

FORBIDDEN_FEATURE_TOKENS = (
    "label",
    "tactic",
    "attack",
    "epoch",
    "timestamp",
    "sublabel",
)


def safe_name(value: str) -> str:
    text = "".join(character.lower() if character.isalnum() else "_" for character in value)
    return "_".join(part for part in text.split("_") if part)


def window_id(window_start: int, phase: int = 2) -> str:
    digest = hashlib.sha256(f"cicapt-phase{phase}-window:{window_start}".encode()).hexdigest()
    return f"window_{digest[:20]}"


def normalize_port(value: str) -> str:
    try:
        number = int(float(value.strip()))
    except (TypeError, ValueError):
        return ""
    return str(number) if 0 <= number <= 65535 else ""


@dataclass
class WindowStats:
    numeric_sum: list[float] = field(default_factory=lambda: [0.0] * len(NUMERIC_COLUMNS))
    numeric_sum_sq: list[float] = field(default_factory=lambda: [0.0] * len(NUMERIC_COLUMNS))
    numeric_max: list[float] = field(default_factory=lambda: [-math.inf] * len(NUMERIC_COLUMNS))
    numeric_count: list[int] = field(default_factory=lambda: [0] * len(NUMERIC_COLUMNS))
    flag_sum: list[float] = field(default_factory=lambda: [0.0] * len(FLAG_COLUMNS))
    row_count: int = 0
    total_bytes: float = 0.0
    source_ips: Counter[str] = field(default_factory=Counter)
    destination_ips: Counter[str] = field(default_factory=Counter)
    source_ports: Counter[str] = field(default_factory=Counter)
    destination_ports: Counter[str] = field(default_factory=Counter)
    protocols: Counter[str] = field(default_factory=Counter)
    positive_row_count: int = 0
    tactics: Counter[str] = field(default_factory=Counter)
    actions: Counter[str] = field(default_factory=Counter)


def hhi(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if not total:
        return 0.0
    return sum((count / total) ** 2 for count in counter.values())


def update_numeric(stats: WindowStats, parts: list[bytes], indices: list[int]) -> None:
    for position, column_index in enumerate(indices):
        try:
            value = float(parts[column_index])
        except ValueError:
            continue
        if not math.isfinite(value):
            continue
        stats.numeric_sum[position] += value
        stats.numeric_sum_sq[position] += value * value
        stats.numeric_max[position] = max(stats.numeric_max[position], value)
        stats.numeric_count[position] += 1


def scan_network(path: Path, window_seconds: int) -> tuple[dict[int, WindowStats], dict]:
    observed: dict[int, WindowStats] = {}
    malformed_rows = 0
    minimum_timestamp = math.inf
    maximum_timestamp = -math.inf

    with path.open("rb") as handle:
        header = [item.decode("utf-8-sig") for item in handle.readline().rstrip().split(b",")]
        expected = len(header)
        index = {name: header.index(name) for name in header}
        required = {
            "ts", "Source IP", "Destination IP", "Source Port", "Destination Port",
            "Protocol_name", "Tot size", "label", "subLabel", "subLabelCat",
            *NUMERIC_COLUMNS, *FLAG_COLUMNS,
        }
        missing = sorted(required - set(index))
        if missing:
            raise ValueError(f"Network CSV is missing columns: {missing}")
        numeric_indices = [index[name] for name in NUMERIC_COLUMNS]
        flag_indices = [index[name] for name in FLAG_COLUMNS]

        for raw in handle:
            parts = raw.rstrip(b"\r\n").split(b",")
            if len(parts) != expected:
                malformed_rows += 1
                continue
            try:
                timestamp = float(parts[index["ts"]])
            except ValueError:
                malformed_rows += 1
                continue
            if not math.isfinite(timestamp):
                malformed_rows += 1
                continue
            minimum_timestamp = min(minimum_timestamp, timestamp)
            maximum_timestamp = max(maximum_timestamp, timestamp)
            bucket = math.floor(timestamp / window_seconds) * window_seconds
            stats = observed.setdefault(bucket, WindowStats())
            stats.row_count += 1
            update_numeric(stats, parts, numeric_indices)
            for position, column_index in enumerate(flag_indices):
                try:
                    value = float(parts[column_index])
                except ValueError:
                    continue
                if math.isfinite(value):
                    stats.flag_sum[position] += value

            source_ip = parts[index["Source IP"]].decode(errors="replace")
            destination_ip = parts[index["Destination IP"]].decode(errors="replace")
            source_port = normalize_port(parts[index["Source Port"]].decode(errors="replace"))
            destination_port = normalize_port(parts[index["Destination Port"]].decode(errors="replace"))
            protocol = parts[index["Protocol_name"]].decode(errors="replace").strip().upper()
            stats.source_ips[source_ip] += 1
            stats.destination_ips[destination_ip] += 1
            stats.source_ports[source_port] += 1
            stats.destination_ports[destination_port] += 1
            stats.protocols[protocol] += 1
            try:
                stats.total_bytes += float(parts[index["Tot size"]])
            except ValueError:
                pass

            if parts[index["label"]].strip() == b"1":
                stats.positive_row_count += 1
                raw_tactic = parts[index["subLabel"]].decode(errors="replace").strip()
                tactic = NETWORK_MAP.get(raw_tactic, f"unmapped:{raw_tactic}")
                action = parts[index["subLabelCat"]].decode(errors="replace").strip()
                stats.tactics[tactic] += 1
                if action:
                    stats.actions[action] += 1

    if not observed:
        raise ValueError("No valid network rows found")
    first_bucket = math.floor(minimum_timestamp / window_seconds) * window_seconds
    last_bucket = math.floor(maximum_timestamp / window_seconds) * window_seconds
    all_windows = {
        bucket: observed.get(bucket, WindowStats())
        for bucket in range(first_bucket, last_bucket + window_seconds, window_seconds)
    }
    metadata = {
        "malformed_rows": malformed_rows,
        "first_window_start_epoch": first_bucket,
        "last_window_start_epoch": last_bucket,
        "observed_window_count": len(observed),
        "complete_window_count": len(all_windows),
        "empty_window_count": len(all_windows) - len(observed),
        "protocol_vocabulary": list(PROTOCOL_VOCABULARY),
        "protocol_vocabulary_source": "predefined, not selected from evaluation data",
        "destination_port_vocabulary": list(FIXED_DESTINATION_PORTS),
        "destination_port_vocabulary_source": "predefined common Internet/IIoT services, not selected from evaluation data",
        "destination_port_bands": {
            name: {"minimum": bounds[0], "maximum": bounds[1]}
            for name, bounds in PORT_BANDS.items()
        },
    }
    return all_windows, metadata


def event_windows(cluster_manifest: dict, window_seconds: int) -> dict[int, list[dict]]:
    mapping: dict[int, list[dict]] = {}
    for cluster in cluster_manifest["clusters"]:
        first = math.floor(float(cluster["start_epoch"]) / window_seconds) * window_seconds
        last = math.floor(float(cluster["end_epoch"]) / window_seconds) * window_seconds
        event = {
            "case_id": opaque_case_id(cluster["cluster_id"]),
            "tactic": cluster["tactic"],
            "source_cluster_id": cluster["cluster_id"],
        }
        for bucket in range(first, last + window_seconds, window_seconds):
            mapping.setdefault(bucket, []).append(event)
    return mapping


def feature_columns(protocols: list[str], ports: list[str]) -> list[str]:
    columns = [
        "window_id", "row_count", "total_bytes", "unique_source_ips",
        "unique_destination_ips", "unique_source_ports", "unique_destination_ports",
        "source_ip_hhi", "destination_ip_hhi", "source_port_hhi", "destination_port_hhi",
    ]
    for name in NUMERIC_COLUMNS:
        prefix = safe_name(name)
        columns.extend((f"{prefix}_mean", f"{prefix}_std", f"{prefix}_max"))
    columns.extend(f"{safe_name(name)}_mean" for name in FLAG_COLUMNS)
    columns.extend(f"protocol_{safe_name(name)}_fraction" for name in protocols)
    columns.extend(f"destination_port_{safe_name(name)}_fraction" for name in ports)
    columns.extend(f"destination_port_{name}_fraction" for name in PORT_BANDS)
    return columns


def safe_feature_row(
    bucket: int,
    stats: WindowStats,
    protocols: list[str],
    ports: list[str],
    phase: int = 2,
) -> dict:
    denominator = max(stats.row_count, 1)
    row = {
        "window_id": window_id(bucket, phase),
        "row_count": stats.row_count,
        "total_bytes": stats.total_bytes,
        "unique_source_ips": len(stats.source_ips),
        "unique_destination_ips": len(stats.destination_ips),
        "unique_source_ports": len(stats.source_ports),
        "unique_destination_ports": len(stats.destination_ports),
        "source_ip_hhi": hhi(stats.source_ips),
        "destination_ip_hhi": hhi(stats.destination_ips),
        "source_port_hhi": hhi(stats.source_ports),
        "destination_port_hhi": hhi(stats.destination_ports),
    }
    for position, name in enumerate(NUMERIC_COLUMNS):
        count = stats.numeric_count[position]
        mean = stats.numeric_sum[position] / count if count else 0.0
        variance = max(0.0, stats.numeric_sum_sq[position] / count - mean * mean) if count else 0.0
        prefix = safe_name(name)
        row[f"{prefix}_mean"] = mean
        row[f"{prefix}_std"] = math.sqrt(variance)
        row[f"{prefix}_max"] = stats.numeric_max[position] if count else 0.0
    for position, name in enumerate(FLAG_COLUMNS):
        row[f"{safe_name(name)}_mean"] = stats.flag_sum[position] / denominator
    for protocol in protocols:
        row[f"protocol_{safe_name(protocol)}_fraction"] = stats.protocols[protocol] / denominator
    for port in ports:
        row[f"destination_port_{safe_name(port)}_fraction"] = stats.destination_ports[port] / denominator
    for band_name, (minimum, maximum) in PORT_BANDS.items():
        band_count = sum(
            count
            for port, count in stats.destination_ports.items()
            if port and minimum <= int(port) <= maximum
        )
        row[f"destination_port_{band_name}_fraction"] = band_count / denominator
    return row


def assert_feature_columns_are_safe(columns: list[str]) -> None:
    violations = [
        column
        for column in columns
        if column != "window_id" and any(token in column.lower() for token in FORBIDDEN_FEATURE_TOKENS)
    ]
    if violations:
        raise ValueError(f"Forbidden feature names: {violations}")


def build_outputs(
    network_path: Path, cluster_manifest: dict, window_seconds: int, phase: int | None = None
) -> tuple[list[dict], list[dict], dict]:
    phase_id = int(phase if phase is not None else cluster_manifest.get("phase", 2))
    windows, metadata = scan_network(network_path, window_seconds)
    mapped_events = event_windows(cluster_manifest, window_seconds)
    protocols = metadata["protocol_vocabulary"]
    ports = metadata["destination_port_vocabulary"]
    columns = feature_columns(protocols, ports)
    assert_feature_columns_are_safe(columns)

    features = []
    truths = []
    audit = Counter()
    mapped_case_ids = set()
    for bucket, stats in sorted(windows.items()):
        events = sorted(mapped_events.get(bucket, []), key=lambda item: item["case_id"])
        features.append(safe_feature_row(bucket, stats, protocols, ports, phase_id))
        truths.append(
            {
                "window_id": window_id(bucket, phase_id),
                "window_start_epoch": bucket,
                "network_positive": int(stats.positive_row_count > 0),
                "positive_row_count": stats.positive_row_count,
                "network_tactics_json": json.dumps(dict(sorted(stats.tactics.items())), separators=(",", ":")),
                "network_actions_json": json.dumps(dict(sorted(stats.actions.items())), separators=(",", ":")),
                "event_case_ids_json": json.dumps([event["case_id"] for event in events], separators=(",", ":")),
                "event_tactics_json": json.dumps(sorted({event["tactic"] for event in events}), separators=(",", ":")),
            }
        )
        mapped_case_ids.update(event["case_id"] for event in events)
        audit["windows"] += 1
        if stats.row_count == 0:
            audit["empty_windows"] += 1
        if stats.positive_row_count:
            audit["network_positive_windows"] += 1
            if not events:
                audit["positive_windows_without_event_mapping"] += 1
        if events:
            audit["event_mapped_windows"] += 1

    index = {
        "schema_version": "1.0",
        "dataset": cluster_manifest.get("dataset"),
        "phase": phase_id,
        "window_seconds": window_seconds,
        "feature_columns": columns,
        "feature_count": len(columns) - 1,
        "excluded_raw_columns": EXCLUDED_RAW_COLUMNS,
        "truth_columns": list(truths[0]) if truths else [],
        "metadata": metadata,
        "audit": {
            **dict(sorted(audit.items())),
            "mapped_unique_event_cases": len(mapped_case_ids),
            "expected_event_cases": len(cluster_manifest["clusters"]),
        },
    }
    return features, truths, index


def write_csv(path: Path, rows: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", type=Path, required=True)
    parser.add_argument("--clusters", type=Path)
    parser.add_argument("--phase", type=int)
    parser.add_argument("--dataset", default="CICAPT-IIoT2024")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--window-seconds", type=int, default=60)
    args = parser.parse_args()

    if args.clusters:
        cluster_manifest = json.loads(args.clusters.read_text(encoding="utf-8"))
    else:
        if args.phase is None:
            parser.error("--phase is required when --clusters is omitted")
        cluster_manifest = {
            "dataset": args.dataset,
            "phase": args.phase,
            "manifest_status": "no_event_manifest",
            "clusters": [],
        }
    phase = args.phase if args.phase is not None else cluster_manifest.get("phase", 2)
    features, truths, index = build_outputs(
        args.network, cluster_manifest, args.window_seconds, phase
    )
    feature_path = args.output_dir / "network_windows.features.csv"
    truth_path = args.output_dir / "network_windows.truth.csv"
    index_path = args.output_dir / "network_windows.index.json"
    write_csv(feature_path, features, index["feature_columns"])
    write_csv(truth_path, truths, index["truth_columns"])
    index["source_files"] = {
        "network": {"path": args.network.as_posix(), "sha256": sha256_file(args.network)},
    }
    if args.clusters:
        index["source_files"]["clusters"] = {
            "path": args.clusters.as_posix(),
            "sha256": sha256_file(args.clusters),
        }
    index["output_files"] = {
        "features": {"path": feature_path.as_posix(), "sha256": sha256_file(feature_path)},
        "truth": {"path": truth_path.as_posix(), "sha256": sha256_file(truth_path)},
    }
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    print(json.dumps({"audit": index["audit"], "feature_count": index["feature_count"]}, indent=2))


if __name__ == "__main__":
    main()
