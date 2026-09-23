#!/usr/bin/env python3
"""Build one network-triggered CICAPT-IIoT forensic evidence package.

This is a preprocessing prototype, not the final detector.  It selects the first
labelled attack only when --auto-first-attack is requested, but never uses labels
to rank provenance evidence.  Ground-truth fields are isolated under
``evaluation_only`` so they can be removed from model inputs mechanically.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


NETWORK_TACTIC_MAP = {
    "collection": "collection",
    "cleanup": "defence_evasion",
    "discovery": "discovery",
    "credential access": "credential_access",
    "command and control": "command_and_control",
    "persistence": "persistence",
    "exfiltration": "exfiltration",
    "lateral movement": "lateral_movement",
}


def iso_utc(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def normalise_pid(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    try:
        return str(int(float(value)))
    except ValueError:
        return value


def first_attack(path: Path) -> tuple[float, str, str]:
    with path.open("rb") as handle:
        header = [item.decode() for item in handle.readline().rstrip().split(b",")]
        expected = len(header)
        ts_i = header.index("ts")
        label_i = header.index("label")
        tactic_i = header.index("subLabel")
        action_i = header.index("subLabelCat")
        for raw in handle:
            parts = raw.rstrip(b"\r\n").split(b",")
            if len(parts) == expected and parts[label_i] == b"1":
                tactic = parts[tactic_i].decode("utf-8", errors="replace")
                action = parts[action_i].decode("utf-8", errors="replace")
                return float(parts[ts_i]), NETWORK_TACTIC_MAP.get(tactic, tactic), action
    raise ValueError(f"No attack-labelled record found in {path}")


def hhi(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if not total:
        return 0.0
    return sum((count / total) ** 2 for count in counter.values())


def network_window(path: Path, start: float, end: float) -> dict:
    with path.open("rb") as handle:
        header = [item.decode() for item in handle.readline().rstrip().split(b",")]
        indices = {name: i for i, name in enumerate(header)}
        expected = len(header)
        required = [
            "ts",
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "Protocol_name",
            "Tot size",
            "label",
            "subLabel",
            "subLabelCat",
        ]
        missing = [name for name in required if name not in indices]
        if missing:
            raise ValueError(f"Network CSV is missing {missing}")

        rows = 0
        attack_rows = 0
        total_bytes = 0.0
        protocols: Counter[str] = Counter()
        sources: Counter[str] = Counter()
        destinations: Counter[str] = Counter()
        destination_ports: Counter[str] = Counter()
        tactics: Counter[str] = Counter()
        actions: Counter[str] = Counter()

        for raw in handle:
            parts = raw.rstrip(b"\r\n").split(b",")
            if len(parts) != expected:
                continue
            timestamp = float(parts[indices["ts"]])
            # The distributed network CSV is not ordered by timestamp, so an
            # early break would silently create empty or incomplete windows.
            if timestamp < start or timestamp >= end:
                continue
            rows += 1
            source = parts[indices["Source IP"]].decode(errors="replace")
            destination = parts[indices["Destination IP"]].decode(errors="replace")
            destination_port = parts[indices["Destination Port"]].decode(errors="replace")
            protocol = parts[indices["Protocol_name"]].decode(errors="replace")
            sources[source] += 1
            destinations[destination] += 1
            destination_ports[destination_port] += 1
            protocols[protocol] += 1
            try:
                total_bytes += float(parts[indices["Tot size"]])
            except ValueError:
                pass
            if parts[indices["label"]] == b"1":
                attack_rows += 1
                raw_tactic = parts[indices["subLabel"]].decode(errors="replace")
                tactic = NETWORK_TACTIC_MAP.get(raw_tactic, raw_tactic)
                tactics[tactic] += 1
                actions[parts[indices["subLabelCat"]].decode(errors="replace")] += 1

    return {
        "row_count": rows,
        "total_bytes": total_bytes,
        "unique_source_ips": len(sources),
        "unique_destination_ips": len(destinations),
        "unique_destination_ports": len(destination_ports),
        "protocol_counts": dict(protocols.most_common()),
        "destination_ip_hhi": hhi(destinations),
        "destination_port_hhi": hhi(destination_ports),
        "top_source_ips": sources.most_common(5),
        "top_destination_ips": destinations.most_common(5),
        "top_destination_ports": destination_ports.most_common(5),
        "evaluation_only": {
            "attack_row_count": attack_rows,
            "tactic_counts": dict(tactics.most_common()),
            "action_counts": dict(actions.most_common()),
        },
    }


def row_timestamp(row: dict[str, str]) -> float | None:
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


def public_entity(node: dict[str, str], score: float, incident_edges: int) -> dict:
    return {
        "id": node.get("id", ""),
        "type": node.get("type", ""),
        "subtype": node.get("subtype", ""),
        "pid": normalise_pid(node.get("pid", "")),
        "name": node.get("name", ""),
        "exe": node.get("exe", ""),
        "command_line": node.get("command line", ""),
        "path": node.get("path", ""),
        "local_address": node.get("local address", ""),
        "local_port": node.get("local port", ""),
        "remote_address": node.get("remote address", ""),
        "remote_port": node.get("remote port", ""),
        "protocol": node.get("protocol", ""),
        "incident_edge_count": incident_edges,
        "retrieval_score": round(score, 6),
    }


def provenance_context(path: Path, center: float, radius: int, top_k: int) -> dict:
    start, end = center - radius, center + radius
    nodes: dict[str, dict[str, str]] = {}
    edges: list[dict[str, str]] = []

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row in csv.DictReader(handle):
            row_type = row.get("type", "")
            node_id = row.get("id", "")
            if row_type in {"Process", "Artifact"} and node_id:
                nodes[node_id] = row
                continue
            timestamp = row_timestamp(row)
            if timestamp is not None and start <= timestamp <= end:
                edges.append(row)

    degree: Counter[str] = Counter()
    closest: dict[str, float] = defaultdict(lambda: float("inf"))
    relation_counts: Counter[str] = Counter()
    operation_counts: Counter[str] = Counter()
    for edge in edges:
        timestamp = row_timestamp(edge)
        if timestamp is None:
            continue
        relation_counts[edge.get("type", "")] += 1
        operation_counts[edge.get("operation", "")] += 1
        for endpoint in (edge.get("from", ""), edge.get("to", "")):
            if endpoint:
                degree[endpoint] += 1
                closest[endpoint] = min(closest[endpoint], abs(timestamp - center))

    ranked: list[tuple[float, dict[str, str], int]] = []
    for node_id, incident_edges in degree.items():
        node = nodes.get(node_id)
        if not node:
            continue
        proximity = max(0.0, 1.0 - closest[node_id] / max(radius, 1))
        score = math.log1p(incident_edges) + proximity
        ranked.append((score, node, incident_edges))
    ranked.sort(key=lambda item: (-item[0], item[1].get("id", "")))

    processes = [item for item in ranked if item[1].get("type") == "Process"]
    artifacts = [item for item in ranked if item[1].get("type") == "Artifact"]
    top_processes = [public_entity(node, score, count) for score, node, count in processes[:top_k]]
    top_artifacts = [public_entity(node, score, count) for score, node, count in artifacts[:top_k]]

    ground_truth_pids = sorted(
        {
            normalise_pid(node.get("pid", ""))
            for _, node, _ in processes
            if node.get("label", "").strip() == "1" and normalise_pid(node.get("pid", ""))
        }
    )
    retrieved_pids = [item["pid"] for item in top_processes if item["pid"]]
    hit_pids = sorted(set(retrieved_pids) & set(ground_truth_pids))
    ground_truth_tactics = sorted(
        {
            node.get("subLabel", "").strip()
            for _, node, _ in ranked
            if node.get("label", "").strip() == "1" and node.get("subLabel", "").strip()
        }
    )

    return {
        "start_epoch": start,
        "end_epoch": end,
        "radius_seconds": radius,
        "edge_count": len(edges),
        "candidate_entity_count": len(ranked),
        "relation_counts": dict(relation_counts.most_common()),
        "operation_counts": dict(operation_counts.most_common(20)),
        "ranked_processes": top_processes,
        "ranked_artifacts": top_artifacts,
        "evaluation_only": {
            "ground_truth_tactics_in_context": ground_truth_tactics,
            "ground_truth_process_pids_in_context": ground_truth_pids,
            "retrieved_pid_hits_at_k": hit_pids,
            "pid_recall_at_k": (
                len(hit_pids) / len(ground_truth_pids) if ground_truth_pids else None
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timestamp", type=float)
    parser.add_argument("--auto-first-attack", action="store_true")
    parser.add_argument("--network-window", type=int, default=60)
    parser.add_argument("--context-radius", type=int, default=300)
    parser.add_argument("--top-k", type=int, default=10)
    args = parser.parse_args()

    if args.timestamp is None and not args.auto_first_attack:
        parser.error("Use --timestamp or --auto-first-attack")
    if args.timestamp is not None and args.auto_first_attack:
        parser.error("Use only one of --timestamp and --auto-first-attack")

    selected_tactic = None
    selected_action = None
    if args.auto_first_attack:
        timestamp, selected_tactic, selected_action = first_attack(args.network)
        selection = "first_attack_label_used_for_case_selection_only"
    else:
        timestamp = args.timestamp
        selection = "user_supplied_timestamp"

    window_start = math.floor(timestamp / args.network_window) * args.network_window
    window_end = window_start + args.network_window
    network = network_window(args.network, window_start, window_end)
    provenance = provenance_context(
        args.provenance, timestamp, args.context_radius, args.top_k
    )
    network_ground_truth = network.pop("evaluation_only")
    provenance_ground_truth = provenance.pop("evaluation_only")

    report = {
        "schema_version": "0.1-prototype",
        "case_selection": selection,
        "trigger_timestamp_epoch": timestamp,
        "trigger_timestamp_utc": iso_utc(timestamp),
        "network_alert_window": {
            "start_epoch": window_start,
            "end_epoch": window_end,
            **network,
        },
        "provenance_evidence_context": provenance,
        "decision": {
            "state": "prototype_unscored",
            "attribution": None,
            "abstention_reason": "model_not_trained",
        },
        "evaluation_only": {
            "selection_tactic": selected_tactic,
            "selection_action": selected_action,
            "network_ground_truth": network_ground_truth,
            "provenance_ground_truth": provenance_ground_truth,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
