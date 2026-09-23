#!/usr/bin/env python3
"""Audit host-level linkage between CICAPT-IIoT provenance and network views.

The audit joins timestamped provenance socket-connect observations to raw
network rows by remote IP, remote port, and time. It is deliberately separate
from model fitting and reports post-hoc subgroup results as diagnostics only.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import ipaddress
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class SocketObservation:
    observation_id: str
    artifact_id: str
    process_id: str
    process_name: str
    process_pid: str
    process_label: str
    timestamp: float
    remote_ip: str
    remote_port: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def canonical_port(value: Any) -> int | None:
    try:
        port = int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def usable_remote_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not (address.is_loopback or address.is_unspecified)


def extract_socket_observations(
    provenance_path: Path,
) -> tuple[list[SocketObservation], dict[str, Any]]:
    processes: dict[str, dict[str, str]] = {}
    sockets: dict[str, dict[str, str]] = {}
    connect_edges: list[tuple[str, str, str]] = []

    with provenance_path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            row_type = row.get("type", "")
            if row_type == "Process" and row.get("id"):
                processes[row["id"]] = row
            elif row_type == "Artifact" and row.get("subtype") == "network socket":
                if row.get("id"):
                    sockets[row["id"]] = row
            elif (
                row_type == "WasGeneratedBy"
                and row.get("operation") == "connect"
                and row.get("from")
                and row.get("to")
                and row.get("time")
            ):
                connect_edges.append((row["from"], row["to"], row["time"]))

    observations_all: list[SocketObservation] = []
    usable: list[SocketObservation] = []
    seen: set[tuple[str, float, str, int | None]] = set()
    missing_links = 0
    for artifact_id, process_id, timestamp_text in connect_edges:
        socket = sockets.get(artifact_id)
        process = processes.get(process_id)
        if socket is None or process is None:
            missing_links += 1
            continue
        try:
            timestamp = float(timestamp_text)
        except ValueError:
            continue
        remote_ip = socket.get("remote address", "").strip()
        remote_port = canonical_port(socket.get("remote port"))
        dedup_key = (process_id, timestamp, remote_ip, remote_port)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        observation = SocketObservation(
            observation_id=f"sock_{len(observations_all):06d}",
            artifact_id=artifact_id,
            process_id=process_id,
            process_name=process.get("name", ""),
            process_pid=str(process.get("pid", "")).removesuffix(".0"),
            process_label=process.get("label", ""),
            timestamp=timestamp,
            remote_ip=remote_ip,
            remote_port=remote_port or 0,
        )
        observations_all.append(observation)
        if remote_port is not None and usable_remote_ip(remote_ip):
            usable.append(observation)

    audit = {
        "process_entity_count": len(processes),
        "network_socket_artifact_count": len(sockets),
        "connect_edge_count": len(connect_edges),
        "deduplicated_socket_observation_count": len(observations_all),
        "usable_socket_observation_count": len(usable),
        "missing_process_or_socket_links": missing_links,
        "malicious_process_socket_observation_count": sum(
            as_bool(item.process_label) for item in observations_all
        ),
        "usable_malicious_process_socket_observation_count": sum(
            as_bool(item.process_label) for item in usable
        ),
    }
    return usable, audit


def _endpoint_index(
    observations: list[SocketObservation],
) -> dict[tuple[str, int], tuple[list[float], list[int]]]:
    material: dict[tuple[str, int], list[tuple[float, int]]] = defaultdict(list)
    for index, observation in enumerate(observations):
        material[(observation.remote_ip, observation.remote_port)].append(
            (observation.timestamp, index)
        )
    result: dict[tuple[str, int], tuple[list[float], list[int]]] = {}
    for key, values in material.items():
        values.sort()
        result[key] = ([item[0] for item in values], [item[1] for item in values])
    return result


def scan_network(
    network_path: Path,
    observations: list[SocketObservation],
    offsets: Iterable[float],
    maximum_tolerance: float,
) -> tuple[dict[float, dict[int, dict[str, Any]]], list[dict[str, Any]], dict[str, Any]]:
    endpoint_index = _endpoint_index(observations)
    offset_values = tuple(float(value) for value in offsets)
    best: dict[float, dict[int, dict[str, Any]]] = {
        offset: {} for offset in offset_values
    }
    attack_rows: list[dict[str, Any]] = []
    rows_scanned = 0
    parse_errors = 0

    with network_path.open(encoding="utf-8-sig", newline="", buffering=16 * 1024 * 1024) as handle:
        reader = csv.reader(handle)
        header = next(reader)
        columns = {name: header.index(name) for name in (
            "ts", "Source IP", "Destination IP", "Source Port", "Destination Port",
            "label", "subLabel", "subLabelCat",
        )}
        for row_number, row in enumerate(reader, start=2):
            rows_scanned += 1
            try:
                timestamp = float(row[columns["ts"]])
                source_ip = row[columns["Source IP"]].strip()
                destination_ip = row[columns["Destination IP"]].strip()
                source_port = canonical_port(row[columns["Source Port"]]) or 0
                destination_port = canonical_port(row[columns["Destination Port"]]) or 0
            except (IndexError, ValueError):
                parse_errors += 1
                continue

            if as_bool(row[columns["label"]]):
                attack_rows.append(
                    {
                        "row_number": row_number,
                        "timestamp": timestamp,
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "sub_label": row[columns["subLabel"]],
                        "sub_label_category": row[columns["subLabelCat"]],
                    }
                )

            candidates = (
                (source_ip, source_port, destination_ip, destination_port, "remote_source"),
                (destination_ip, destination_port, source_ip, source_port, "remote_destination"),
            )
            for remote_ip, remote_port, local_ip, local_port, direction in candidates:
                indexed = endpoint_index.get((remote_ip, remote_port))
                if indexed is None:
                    continue
                times, observation_indices = indexed
                for offset in offset_values:
                    target = timestamp - offset
                    lower = bisect.bisect_left(times, target - maximum_tolerance)
                    upper = bisect.bisect_right(times, target + maximum_tolerance)
                    for position in range(lower, upper):
                        observation_index = observation_indices[position]
                        delta = abs(timestamp - (times[position] + offset))
                        previous = best[offset].get(observation_index)
                        if previous is not None and previous["absolute_delta_seconds"] <= delta:
                            continue
                        best[offset][observation_index] = {
                            "network_row_number": row_number,
                            "network_timestamp": timestamp,
                            "absolute_delta_seconds": delta,
                            "local_ip": local_ip,
                            "local_port": local_port,
                            "direction": direction,
                        }

    scan = {
        "network_rows_scanned": rows_scanned,
        "network_parse_errors": parse_errors,
        "attack_labeled_network_rows": len(attack_rows),
    }
    return best, attack_rows, scan


def summarize_matches(
    observations: list[SocketObservation],
    best: dict[float, dict[int, dict[str, Any]]],
    tolerance: float,
    support_threshold: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    primary = best[0.0]
    match_rows: list[dict[str, Any]] = []
    endpoint_counts: Counter[str] = Counter()
    endpoint_times: dict[str, list[float]] = defaultdict(list)
    endpoint_processes: dict[str, Counter[str]] = defaultdict(Counter)
    for index, match in primary.items():
        if match["absolute_delta_seconds"] > tolerance:
            continue
        observation = observations[index]
        endpoint_counts[match["local_ip"]] += 1
        endpoint_times[match["local_ip"]].append(observation.timestamp)
        endpoint_processes[match["local_ip"]][observation.process_name] += 1
        match_rows.append(
            {
                "observation_id": observation.observation_id,
                "process_id": observation.process_id,
                "process_name": observation.process_name,
                "process_pid": observation.process_pid,
                "process_label": observation.process_label,
                "provenance_timestamp": observation.timestamp,
                "remote_ip": observation.remote_ip,
                "remote_port": observation.remote_port,
                **match,
            }
        )
    match_rows.sort(key=lambda row: (row["provenance_timestamp"], row["observation_id"]))

    endpoint_rows = []
    for local_ip, count in endpoint_counts.most_common():
        process_counts = endpoint_processes[local_ip]
        endpoint_rows.append(
            {
                "inferred_local_ip": local_ip,
                "matched_socket_observations": count,
                "support_threshold": support_threshold,
                "supported": int(count >= support_threshold),
                "first_provenance_timestamp": min(endpoint_times[local_ip]),
                "last_provenance_timestamp": max(endpoint_times[local_ip]),
                "distinct_process_names": len(process_counts),
                "top_process_names": "|".join(
                    f"{name}:{value}" for name, value in process_counts.most_common(5)
                ),
            }
        )
    supported = [
        row["inferred_local_ip"] for row in endpoint_rows if row["supported"]
    ]
    primary = supported[0] if supported else None
    for row in endpoint_rows:
        row["primary_host_link_endpoint"] = int(
            row["inferred_local_ip"] == primary
        )
    return match_rows, endpoint_rows, supported


def endpoint_counts_by_tolerance(
    observations: list[SocketObservation],
    primary_matches: dict[int, dict[str, Any]],
    thresholds: Iterable[float],
) -> dict[str, dict[str, int]]:
    del observations  # indices are retained for an explicit future extension
    output: dict[str, dict[str, int]] = {}
    for threshold in thresholds:
        counts: Counter[str] = Counter(
            match["local_ip"]
            for match in primary_matches.values()
            if match["absolute_delta_seconds"] <= threshold
        )
        output[f"{threshold:g}"] = dict(counts.most_common())
    return output


def canonical_network_tactic(value: str, mapping: dict[str, str]) -> str | None:
    return mapping.get(value.strip().lower())


def classify_cases(
    truths: list[dict[str, Any]],
    cluster_manifest: dict[str, Any],
    attack_rows: list[dict[str, Any]],
    supported_ips: set[str],
) -> list[dict[str, Any]]:
    clusters = {item["cluster_id"]: item for item in cluster_manifest["clusters"]}
    mapping = {
        key.strip().lower(): value
        for key, value in cluster_manifest["canonical_label_map"]["network"].items()
    }
    rows: list[dict[str, Any]] = []
    for truth in truths:
        cluster = clusters[truth["source_cluster_id"]]
        network_range = cluster.get("network_time_range")
        touching = 0
        if network_range:
            for network_row in attack_rows:
                observed_label = canonical_network_tactic(
                    network_row["sub_label"], mapping
                ) or canonical_network_tactic(network_row["sub_label_category"], mapping)
                if observed_label != cluster["tactic"]:
                    continue
                if not (
                    float(network_range["start_epoch"])
                    <= network_row["timestamp"]
                    <= float(network_range["end_epoch"])
                ):
                    continue
                if {
                    network_row["source_ip"], network_row["destination_ip"]
                } & supported_ips:
                    touching += 1
        both_views = set(cluster["views_present"]) == {"network", "provenance"}
        rows.append(
            {
                "case_id": truth["case_id"],
                "source_cluster_id": truth["source_cluster_id"],
                "tactic": truth["event"]["tactic"],
                "support_role": truth["event"]["support_role"],
                "views_present": "|".join(cluster["views_present"]),
                "both_views": int(both_views),
                "attack_rows_touching_supported_host_ip": touching,
                "host_link_supported": int(both_views and touching > 0),
            }
        )
    rows.sort(key=lambda row: row["case_id"])
    return rows


def outcome_summary(
    evaluation_rows: list[dict[str, str]], case_ids: set[str], method: str
) -> dict[str, Any]:
    prefix = "cascade" if method == "EviGate-Bind" else "matched_margin"
    clean = [
        row for row in evaluation_rows
        if row["case_id"] in case_ids and row["condition"] == "clean"
    ]
    context = [
        row for row in evaluation_rows
        if row["case_id"] in case_ids
        and row["condition"] == "corrupted"
        and row["corruption_family"] == "context_replacement"
    ]
    accepted = sum(as_bool(row[f"{prefix}_attributed"]) for row in clean)
    correct = sum(as_bool(row[f"{prefix}_correct"]) for row in clean)
    wrong = accepted - correct
    context_wrong = sum(
        as_bool(row[f"{prefix}_attributed"]) and not as_bool(row[f"{prefix}_correct"])
        for row in context
    )
    return {
        "analysis_status": "post_hoc_host_link_subset",
        "method": method,
        "event_count": len(clean),
        "clean_accepted": accepted,
        "clean_correct": correct,
        "clean_wrong": wrong,
        "clean_selective_risk": wrong / accepted if accepted else math.nan,
        "context_replacement_rows": len(context),
        "context_replacement_wrong_labels": context_wrong,
        "context_replacement_wrong_label_rate": (
            context_wrong / len(context) if context else math.nan
        ),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provenance", type=Path, default=Path("data/raw/cicapt/Phase2_Provenance.csv"))
    parser.add_argument("--network", type=Path, default=Path("data/raw/cicapt/network/phase2_NetworkData.csv"))
    parser.add_argument("--truth", type=Path, default=Path("data/derived/evigate_phase2_evidence/cases.truth.jsonl"))
    parser.add_argument("--clusters", type=Path, default=Path("data/derived/cicapt_phase2_attack_clusters_fallback.json"))
    parser.add_argument(
        "--evaluation",
        type=Path,
        default=Path("data/derived/evigate_llm/v7_bindgate/evaluation_temporal/evigate_bindgate.per_case.csv"),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("data/derived/host_link_audit"))
    parser.add_argument("--tolerance", type=float, default=0.1)
    parser.add_argument("--support-threshold", type=int, default=10)
    parser.add_argument("--offsets", type=float, nargs="+", default=[-60.0, -30.0, 0.0, 30.0, 60.0])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if 0.0 not in args.offsets:
        raise ValueError("offset list must contain zero")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    observations, provenance_audit = extract_socket_observations(args.provenance)
    best, attack_rows, network_audit = scan_network(
        args.network, observations, args.offsets, maximum_tolerance=1.0
    )
    match_rows, endpoint_rows, candidate_ips = summarize_matches(
        observations, best, args.tolerance, args.support_threshold
    )
    primary_ip = candidate_ips[0] if candidate_ips else None
    host_link_ips = {primary_ip} if primary_ip else set()
    truths = read_jsonl(args.truth)
    cluster_manifest = json.loads(args.clusters.read_text(encoding="utf-8"))
    case_rows = classify_cases(
        truths, cluster_manifest, attack_rows, host_link_ips
    )

    with args.evaluation.open(encoding="utf-8-sig", newline="") as handle:
        evaluation_rows = list(csv.DictReader(handle))
    evaluated_cases = {
        row["case_id"] for row in evaluation_rows if row["condition"] == "clean"
    }
    supported_nonpilot = {
        row["case_id"]
        for row in case_rows
        if row["host_link_supported"] and row["case_id"] in evaluated_cases
    }
    outcome_rows = [
        outcome_summary(evaluation_rows, supported_nonpilot, method)
        for method in ("EviGate-Bind", "matched margin")
    ]

    thresholds = (0.01, 0.05, 0.1, 0.5, 1.0)
    match_counts = {
        f"{threshold:g}": sum(
            item["absolute_delta_seconds"] <= threshold
            for item in best[0.0].values()
        )
        for threshold in thresholds
    }
    offset_counts = {
        f"{offset:+g}": sum(
            item["absolute_delta_seconds"] <= args.tolerance
            for item in best[offset].values()
        )
        for offset in sorted(best)
    }
    supported_endpoint_attack_rows = sum(
        bool({row["source_ip"], row["destination_ip"]} & host_link_ips)
        for row in attack_rows
    )
    direct_malicious_matches = sum(as_bool(row["process_label"]) for row in match_rows)
    summary = {
        "schema_version": "1.0",
        "analysis_status": "post_freeze_post_hoc_dataset_audit",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "join_rule": {
            "remote_endpoint_exact": True,
            "absolute_time_tolerance_seconds": args.tolerance,
            "supported_endpoint_minimum_matches": args.support_threshold,
            "time_shift_negative_controls_seconds": sorted(args.offsets),
        },
        "provenance": provenance_audit,
        "network": network_audit,
        "unshifted_match_counts_by_tolerance_seconds": match_counts,
        "match_counts_at_primary_tolerance_by_time_offset_seconds": offset_counts,
        "candidate_local_ips": candidate_ips,
        "primary_host_link_ip": primary_ip,
        "endpoint_match_counts_by_tolerance_seconds": endpoint_counts_by_tolerance(
            observations, best[0.0], (0.05, 0.1)
        ),
        "supported_endpoint_attack_rows": supported_endpoint_attack_rows,
        "supported_endpoint_attack_row_fraction": (
            supported_endpoint_attack_rows / len(attack_rows) if attack_rows else math.nan
        ),
        "case_cohorts": {
            "all_cases": len(case_rows),
            "both_view_cases": sum(row["both_views"] for row in case_rows),
            "host_link_supported_cases": sum(row["host_link_supported"] for row in case_rows),
            "in_support_host_link_supported_cases": sum(
                row["host_link_supported"] and row["support_role"] == "in_support"
                for row in case_rows
            ),
            "evaluated_nonpilot_host_link_supported_cases": len(supported_nonpilot),
        },
        "direct_malicious_process_matches_at_primary_tolerance": direct_malicious_matches,
        "claim_boundary": (
            "The dominant endpoint supports a data-internal, non-authoritative host-membership "
            "argument and event-cohort restriction. Secondary DNS-only candidates remain "
            "ambiguous. Missing local socket address/port prevents packet-to-PID causal attribution."
        ),
        "evaluation_subset": outcome_rows,
    }

    write_csv(args.output_dir / "host_link.matches.csv", match_rows)
    write_csv(args.output_dir / "host_link.endpoints.csv", endpoint_rows)
    write_csv(args.output_dir / "host_link.cases.csv", case_rows)
    write_csv(args.output_dir / "host_link.evaluation_subset.csv", outcome_rows)
    write_json(args.output_dir / "host_link.summary.json", summary)

    input_paths = {
        "script": Path(__file__),
        "provenance": args.provenance,
        "network": args.network,
        "truth": args.truth,
        "clusters": args.clusters,
        "evaluation": args.evaluation,
        "protocol": Path("docs/47_cicapt_host_link_protocol.md"),
    }
    output_paths = sorted(
        path for path in args.output_dir.iterdir()
        if path.is_file() and path.name != "manifest.json"
    )
    manifest = {
        "schema_version": "1.0",
        "analysis_status": summary["analysis_status"],
        "generated_at_utc": summary["generated_at_utc"],
        "script": str(Path(__file__).as_posix()),
        "inputs": {
            name: {"path": str(path.as_posix()), "sha256": sha256_file(path)}
            for name, path in input_paths.items()
        },
        "outputs": {
            path.name: {"path": str(path.as_posix()), "sha256": sha256_file(path)}
            for path in output_paths
        },
    }
    write_json(args.output_dir / "manifest.json", manifest)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
