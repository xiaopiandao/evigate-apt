#!/usr/bin/env python3
"""Build leakage-separated EviGate-APT evidence cases in one dataset pass.

The output consists of two physically separate JSONL files:

* inputs.jsonl: inference-time network summary and provenance candidate graph;
* truth.jsonl: event labels, malicious-entity annotations, and split membership.

Attack labels are used only to select oracle event anchors and to populate the
truth sidecar.  Candidate construction and baseline scores are label-free.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from audit_cicapt_alignment import NETWORK_MAP, PROVENANCE_MAP


FORBIDDEN_INPUT_KEYS = {
    "label",
    "sublabel",
    "sublabelcat",
    "tactic",
    "attackaction",
    "groundtruth",
    "malicious",
    "maliciouspids",
    "clusterid",
    "sourceclusterid",
    "evaluationonly",
    "derivedlabel",
    "splitmembership",
    "viewspresent",
    "epoch",
    "timestampepoch",
    "startepoch",
    "endepoch",
    "absolutetimestamp",
}


def normalise_key(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def normalise_pid(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    try:
        return str(int(float(value)))
    except ValueError:
        return value


def normalise_port(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    try:
        numeric = int(float(value))
    except ValueError:
        return value
    return "" if numeric == 0 else str(numeric)


def hhi(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if not total:
        return 0.0
    return sum((count / total) ** 2 for count in counter.values())


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def opaque_case_id(cluster_id: str) -> str:
    digest = hashlib.sha256(f"evigate-apt-v1:{cluster_id}".encode("utf-8")).hexdigest()
    return f"case_{digest[:20]}"


def row_timestamp(row: dict[str, str]) -> float | None:
    for field_name in ("time", "seen time", "start time"):
        value = row.get(field_name, "").strip()
        if not value:
            continue
        try:
            timestamp = float(value)
        except ValueError:
            continue
        if math.isfinite(timestamp):
            return timestamp
    return None


@dataclass
class NetworkAccumulator:
    row_count: int = 0
    total_bytes: float = 0.0
    source_ips: Counter[str] = field(default_factory=Counter)
    destination_ips: Counter[str] = field(default_factory=Counter)
    source_ports: Counter[str] = field(default_factory=Counter)
    destination_ports: Counter[str] = field(default_factory=Counter)
    protocols: Counter[str] = field(default_factory=Counter)
    labelled_row_count: int = 0
    labelled_tactics: Counter[str] = field(default_factory=Counter)
    labelled_actions: Counter[str] = field(default_factory=Counter)

    def safe_record(self, window_seconds: int, trigger_offset: float) -> dict:
        return {
            "window_seconds": window_seconds,
            "trigger_offset_seconds": round(trigger_offset, 6),
            "row_count": self.row_count,
            "total_bytes": round(self.total_bytes, 6),
            "unique_source_ips": len(self.source_ips),
            "unique_destination_ips": len(self.destination_ips),
            "unique_source_ports": len(self.source_ports),
            "unique_destination_ports": len(self.destination_ports),
            "protocol_counts": dict(sorted(self.protocols.items())),
            "source_ip_hhi": hhi(self.source_ips),
            "destination_ip_hhi": hhi(self.destination_ips),
            "source_port_hhi": hhi(self.source_ports),
            "destination_port_hhi": hhi(self.destination_ports),
            "top_source_ips": [
                {"value": value, "count": count} for value, count in self.source_ips.most_common(5)
            ],
            "top_destination_ips": [
                {"value": value, "count": count}
                for value, count in self.destination_ips.most_common(5)
            ],
            "top_source_ports": [
                {"value": value, "count": count}
                for value, count in self.source_ports.most_common(5)
            ],
            "top_destination_ports": [
                {"value": value, "count": count}
                for value, count in self.destination_ports.most_common(5)
            ],
        }

    def truth_record(self) -> dict:
        return {
            "positive_row_count": self.labelled_row_count,
            "tactic_counts": dict(sorted(self.labelled_tactics.items())),
            "action_counts": dict(sorted(self.labelled_actions.items())),
        }

    @property
    def addresses(self) -> set[str]:
        return set(self.source_ips) | set(self.destination_ips)

    @property
    def ports(self) -> set[str]:
        return {
            normalised
            for value in set(self.source_ports) | set(self.destination_ports)
            if (normalised := normalise_port(value))
        }


@dataclass(frozen=True)
class ProvenanceNode:
    entity_id: str
    raw_type: str
    subtype: str
    pid: str
    ppid: str
    name: str
    exe: str
    command_line: str
    path: str
    local_address: str
    local_port: str
    remote_address: str
    remote_port: str
    protocol: str
    raw_label: str
    raw_sublabel: str


@dataclass(frozen=True)
class ProvenanceEdge:
    row_number: int
    timestamp: float
    source: str
    target: str
    relation_type: str
    operation: str
    raw_label: str
    raw_sublabel: str


def event_anchor(cluster: dict) -> tuple[float, str]:
    network_range = cluster.get("network_time_range")
    if network_range:
        return float(network_range["start_epoch"]), "first_network_observation"
    return float(cluster["start_epoch"]), "cluster_start_without_network_observation"


def scan_network_windows(
    path: Path, anchors: list[float], window_seconds: int
) -> dict[int, NetworkAccumulator]:
    target_windows = {math.floor(anchor / window_seconds) * window_seconds for anchor in anchors}
    accumulators = {window: NetworkAccumulator() for window in target_windows}
    with path.open("rb") as handle:
        header = [item.decode("utf-8-sig") for item in handle.readline().rstrip().split(b",")]
        required = (
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
        )
        index = {name: header.index(name) for name in required}
        expected = len(header)
        for raw in handle:
            parts = raw.rstrip(b"\r\n").split(b",")
            if len(parts) != expected:
                continue
            try:
                timestamp = float(parts[index["ts"]])
            except ValueError:
                continue
            window = math.floor(timestamp / window_seconds) * window_seconds
            accumulator = accumulators.get(window)
            if accumulator is None:
                continue
            accumulator.row_count += 1
            source_ip = parts[index["Source IP"]].decode(errors="replace")
            destination_ip = parts[index["Destination IP"]].decode(errors="replace")
            source_port = parts[index["Source Port"]].decode(errors="replace")
            destination_port = parts[index["Destination Port"]].decode(errors="replace")
            protocol = parts[index["Protocol_name"]].decode(errors="replace")
            accumulator.source_ips[source_ip] += 1
            accumulator.destination_ips[destination_ip] += 1
            accumulator.source_ports[source_port] += 1
            accumulator.destination_ports[destination_port] += 1
            accumulator.protocols[protocol] += 1
            try:
                accumulator.total_bytes += float(parts[index["Tot size"]])
            except ValueError:
                pass
            if parts[index["label"]].strip() == b"1":
                accumulator.labelled_row_count += 1
                raw_tactic = parts[index["subLabel"]].decode(errors="replace").strip()
                tactic = NETWORK_MAP.get(raw_tactic, f"unmapped:{raw_tactic}")
                action = parts[index["subLabelCat"]].decode(errors="replace").strip()
                accumulator.labelled_tactics[tactic] += 1
                if action:
                    accumulator.labelled_actions[action] += 1
    return accumulators


def load_provenance(path: Path) -> tuple[dict[str, ProvenanceNode], list[ProvenanceEdge]]:
    nodes: dict[str, ProvenanceNode] = {}
    edges: list[ProvenanceEdge] = []
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for row_number, row in enumerate(csv.DictReader(handle), start=2):
            row_type = row.get("type", "").strip()
            entity_id = row.get("id", "").strip()
            if row_type in {"Process", "Artifact"} and entity_id:
                nodes[entity_id] = ProvenanceNode(
                    entity_id=entity_id,
                    raw_type=row_type,
                    subtype=row.get("subtype", "").strip(),
                    pid=normalise_pid(row.get("pid", "")),
                    ppid=normalise_pid(row.get("ppid", "")),
                    name=row.get("name", "").strip(),
                    exe=row.get("exe", "").strip(),
                    command_line=row.get("command line", "").strip(),
                    path=row.get("path", "").strip(),
                    local_address=row.get("local address", "").strip(),
                    local_port=normalise_port(row.get("local port", "")),
                    remote_address=row.get("remote address", "").strip(),
                    remote_port=normalise_port(row.get("remote port", "")),
                    protocol=row.get("protocol", "").strip(),
                    raw_label=row.get("label", "").strip(),
                    raw_sublabel=row.get("subLabel", "").strip(),
                )
                continue
            timestamp = row_timestamp(row)
            if timestamp is None:
                continue
            edges.append(
                ProvenanceEdge(
                    row_number=row_number,
                    timestamp=timestamp,
                    source=row.get("from", "").strip(),
                    target=row.get("to", "").strip(),
                    relation_type=row_type,
                    operation=row.get("operation", "").strip(),
                    raw_label=row.get("label", "").strip(),
                    raw_sublabel=row.get("subLabel", "").strip(),
                )
            )
    edges.sort(key=lambda edge: (edge.timestamp, edge.row_number))
    return nodes, edges


def entity_kind(node: ProvenanceNode) -> str:
    if node.raw_type == "Process":
        return "process"
    mapping = {
        "network socket": "socket",
        "file": "file",
        "directory": "directory",
        "link": "link",
    }
    return mapping.get(node.subtype.lower(), "artifact")


def relation_id(edge: ProvenanceEdge) -> str:
    payload = (
        f"{edge.row_number}|{edge.timestamp}|{edge.source}|{edge.target}|"
        f"{edge.relation_type}|{edge.operation}"
    )
    return "relation_" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def candidate_graph(
    nodes: dict[str, ProvenanceNode],
    edges: list[ProvenanceEdge],
    edge_timestamps: list[float],
    center: float,
    radius_seconds: int,
    network: NetworkAccumulator,
) -> tuple[dict, dict]:
    left = bisect_left(edge_timestamps, center - radius_seconds)
    right = bisect_right(edge_timestamps, center + radius_seconds)
    selected_edges = edges[left:right]

    in_degree: Counter[str] = Counter()
    out_degree: Counter[str] = Counter()
    closest: dict[str, float] = defaultdict(lambda: float("inf"))
    relation_counts: Counter[str] = Counter()
    operation_counts: Counter[str] = Counter()
    for edge in selected_edges:
        relation_counts[edge.relation_type] += 1
        if edge.operation:
            operation_counts[edge.operation] += 1
        delta = abs(edge.timestamp - center)
        if edge.source:
            out_degree[edge.source] += 1
            closest[edge.source] = min(closest[edge.source], delta)
        if edge.target:
            in_degree[edge.target] += 1
            closest[edge.target] = min(closest[edge.target], delta)

    candidate_ids = sorted((set(in_degree) | set(out_degree)) & set(nodes))
    safe_nodes = []
    malicious_entities = []
    malicious_processes = []
    malicious_pids = set()
    malicious_tactics = set()
    kind_counts: Counter[str] = Counter()

    for entity_id in candidate_ids:
        node = nodes[entity_id]
        kind = entity_kind(node)
        kind_counts[kind] += 1
        incident = in_degree[entity_id] + out_degree[entity_id]
        distance = closest[entity_id]
        proximity = max(0.0, 1.0 - distance / max(radius_seconds, 1))
        degree_score = math.log1p(incident)
        attributes = {
            key: value
            for key, value in {
                "pid": node.pid,
                "ppid": node.ppid,
                "name": node.name,
                "exe": node.exe,
                "command_line": node.command_line,
                "path": node.path,
                "local_address": node.local_address,
                "local_port": node.local_port,
                "remote_address": node.remote_address,
                "remote_port": node.remote_port,
                "protocol": node.protocol,
            }.items()
            if value
        }
        safe_nodes.append(
            {
                "entity_id": entity_id,
                "entity_kind": kind,
                "raw_type": node.raw_type,
                "subtype": node.subtype,
                "attributes": attributes,
                "features": {
                    "in_degree": in_degree[entity_id],
                    "out_degree": out_degree[entity_id],
                    "incident_edge_count": incident,
                    "closest_abs_time_delta_seconds": round(distance, 6),
                    "time_proximity": round(proximity, 6),
                    "address_match": bool(
                        ({node.local_address, node.remote_address} - {""})
                        & network.addresses
                    ),
                    "port_match": bool(
                        ({node.local_port, node.remote_port} - {""}) & network.ports
                    ),
                    "degree_score": round(degree_score, 6),
                    "recency_degree_score": round(degree_score + proximity, 6),
                },
            }
        )
        if node.raw_label == "1":
            malicious_entities.append(entity_id)
            if kind == "process":
                malicious_processes.append(entity_id)
                if node.pid:
                    malicious_pids.add(node.pid)
            if node.raw_sublabel:
                malicious_tactics.add(
                    PROVENANCE_MAP.get(node.raw_sublabel, f"unmapped:{node.raw_sublabel}")
                )

    safe_edges = []
    malicious_relations = []
    for edge in selected_edges:
        edge_id = relation_id(edge)
        safe_edges.append(
            {
                "relation_id": edge_id,
                "source_entity_id": edge.source,
                "target_entity_id": edge.target,
                "relation_type": edge.relation_type,
                "operation": edge.operation,
                "time_delta_seconds": round(edge.timestamp - center, 6),
            }
        )
        if edge.raw_label == "1":
            malicious_relations.append(edge_id)
            if edge.raw_sublabel:
                malicious_tactics.add(
                    PROVENANCE_MAP.get(edge.raw_sublabel, f"unmapped:{edge.raw_sublabel}")
                )

    safe = {
        "radius_seconds": radius_seconds,
        "candidate_entity_count": len(safe_nodes),
        "relation_count": len(safe_edges),
        "entity_kind_counts": dict(sorted(kind_counts.items())),
        "relation_type_counts": dict(sorted(relation_counts.items())),
        "operation_counts": dict(sorted(operation_counts.items())),
        "entities": safe_nodes,
        "relations": safe_edges,
    }
    truth = {
        "malicious_candidate_entity_ids": sorted(malicious_entities),
        "malicious_candidate_process_ids": sorted(malicious_processes),
        "malicious_candidate_pids": sorted(malicious_pids),
        "malicious_relation_ids": sorted(malicious_relations),
        "tactics_observed_in_context": sorted(malicious_tactics),
    }
    return safe, truth


def split_membership(split_manifest: dict) -> dict[str, list[dict]]:
    membership: dict[str, list[dict]] = defaultdict(list)
    for fold in split_manifest["outer_folds"]:
        for partition_name, partition in fold["partitions"].items():
            supervised = set(partition["supervised_in_support_cluster_ids"])
            for cluster_id in partition["all_cluster_ids"]:
                membership[cluster_id].append(
                    {
                        "fold": fold["fold"],
                        "partition": partition_name,
                        "supervised_eligible": cluster_id in supervised,
                    }
                )
    return membership


def assert_input_is_leakage_safe(record: dict, source_cluster_id: str) -> None:
    violations = []

    def visit(value, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if normalise_key(key) in FORBIDDEN_INPUT_KEYS:
                    violations.append(f"forbidden key {path}.{key}")
                visit(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]")

    visit(record, "$")
    if source_cluster_id in json.dumps(record, sort_keys=True):
        violations.append("source cluster identifier appears in inference record")
    expected_top_level = {
        "schema_version",
        "case_id",
        "network_alert",
        "provenance_candidate_graph",
        "decision_placeholder",
    }
    if set(record) != expected_top_level:
        violations.append("unexpected top-level inference keys")
    if violations:
        raise ValueError("; ".join(violations))


def build_dataset(
    network_path: Path,
    provenance_path: Path,
    cluster_manifest: dict,
    split_manifest: dict,
    network_window_seconds: int = 60,
    context_radius_seconds: int = 300,
    provenance_clock_offset_seconds: float = 0.0,
) -> tuple[list[dict], list[dict], dict]:
    clusters = sorted(
        cluster_manifest["clusters"],
        key=lambda item: (item["start_epoch"], item["end_epoch"], item["cluster_id"]),
    )
    anchors_with_policy = [event_anchor(cluster) for cluster in clusters]
    anchors = [item[0] for item in anchors_with_policy]
    network_windows = scan_network_windows(network_path, anchors, network_window_seconds)
    nodes, edges = load_provenance(provenance_path)
    edge_timestamps = [edge.timestamp for edge in edges]
    membership = split_membership(split_manifest)
    supported = set(split_manifest["in_support_tactics"])

    inputs = []
    truths = []
    audit = Counter()
    for cluster, (anchor, anchor_policy) in zip(clusters, anchors_with_policy):
        case_id = opaque_case_id(cluster["cluster_id"])
        window_start = math.floor(anchor / network_window_seconds) * network_window_seconds
        network = network_windows[window_start]
        # Shifting every provenance timestamp by ``delta`` relative to the
        # fixed network clock is equivalent to querying the unmodified raw
        # provenance stream around ``anchor - delta``.  Rebuilding here also
        # lets entities enter or leave the hard context boundary.
        provenance_center = anchor - provenance_clock_offset_seconds
        safe_graph, graph_truth = candidate_graph(
            nodes,
            edges,
            edge_timestamps,
            provenance_center,
            context_radius_seconds,
            network,
        )
        input_record = {
            "schema_version": "1.0",
            "case_id": case_id,
            "network_alert": network.safe_record(
                network_window_seconds, anchor - window_start
            ),
            "provenance_candidate_graph": safe_graph,
            "decision_placeholder": {
                "state": "unscored",
                "attribution": None,
                "abstention_reason": "model_not_run",
            },
        }
        assert_input_is_leakage_safe(input_record, cluster["cluster_id"])

        direct_pids = set(cluster.get("malicious_pids_directly_observed", []))
        candidate_pids = set(graph_truth["malicious_candidate_pids"])
        truth_record = {
            "schema_version": "1.0",
            "case_id": case_id,
            "source_cluster_id": cluster["cluster_id"],
            "event": {
                "tactic": cluster["tactic"],
                "start_epoch": cluster["start_epoch"],
                "end_epoch": cluster["end_epoch"],
                "views_present": cluster["views_present"],
                "derived_label": cluster.get("derived_label", False),
                "support_role": "in_support" if cluster["tactic"] in supported else "out_of_support",
            },
            "anchor_selection": {
                "timestamp_epoch": anchor,
                "policy": anchor_policy,
                "oracle_event_selection": True,
            },
            "network_ground_truth": network.truth_record(),
            "provenance_ground_truth": {
                **graph_truth,
                "direct_cluster_pids": sorted(direct_pids),
                "direct_pid_candidate_hits": sorted(direct_pids & candidate_pids),
                "direct_pid_candidate_recall_ceiling": (
                    len(direct_pids & candidate_pids) / len(direct_pids) if direct_pids else None
                ),
            },
            "split_membership": membership[cluster["cluster_id"]],
        }
        inputs.append(input_record)
        truths.append(truth_record)
        audit["cases"] += 1
        if network.row_count == 0:
            audit["empty_network_windows"] += 1
        if network.labelled_row_count == 0:
            audit["network_windows_without_positive_rows"] += 1
        else:
            audit["network_windows_with_positive_rows"] += 1
            if cluster["tactic"] in network.labelled_tactics:
                audit["network_windows_with_event_tactic"] += 1
            else:
                audit["positive_network_windows_without_event_tactic"] += 1
        if len(network.labelled_tactics) > 1:
            audit["network_windows_with_multiple_positive_tactics"] += 1
        if not safe_graph["entities"]:
            audit["empty_candidate_graphs"] += 1
        if graph_truth["malicious_candidate_pids"]:
            audit["cases_with_malicious_candidate_pid"] += 1
        if direct_pids and direct_pids <= candidate_pids:
            audit["cases_with_full_direct_pid_ceiling"] += 1
        if anchor_policy == "cluster_start_without_network_observation":
            audit["provenance_only_anchor_cases"] += 1

    index = {
        "schema_version": "1.0",
        "dataset": cluster_manifest.get("dataset"),
        "phase": cluster_manifest.get("phase"),
        "case_count": len(inputs),
        "network_window_seconds": network_window_seconds,
        "context_radius_seconds": context_radius_seconds,
        "provenance_clock_offset_seconds": provenance_clock_offset_seconds,
        "case_ids": [record["case_id"] for record in inputs],
        "input_truth_separation": "physical_jsonl_sidecar",
        "input_leakage_assertion": "passed",
        "audit": dict(sorted(audit.items())),
    }
    return inputs, truths, index


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--clusters", type=Path, required=True)
    parser.add_argument("--splits", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--network-window-seconds", type=int, default=60)
    parser.add_argument("--context-radius-seconds", type=int, default=300)
    parser.add_argument("--provenance-clock-offset-seconds", type=float, default=0.0)
    args = parser.parse_args()

    cluster_manifest = json.loads(args.clusters.read_text(encoding="utf-8"))
    split_manifest = json.loads(args.splits.read_text(encoding="utf-8"))
    inputs, truths, index = build_dataset(
        args.network,
        args.provenance,
        cluster_manifest,
        split_manifest,
        network_window_seconds=args.network_window_seconds,
        context_radius_seconds=args.context_radius_seconds,
        provenance_clock_offset_seconds=args.provenance_clock_offset_seconds,
    )
    input_path = args.output_dir / "cases.inputs.jsonl"
    truth_path = args.output_dir / "cases.truth.jsonl"
    index_path = args.output_dir / "cases.index.json"
    write_jsonl(input_path, inputs)
    write_jsonl(truth_path, truths)
    index.update(
        {
            "source_files": {
                "cluster_manifest": {
                    "path": args.clusters.as_posix(),
                    "sha256": sha256_file(args.clusters),
                },
                "split_manifest": {
                    "path": args.splits.as_posix(),
                    "sha256": sha256_file(args.splits),
                },
            },
            "output_files": {
                "inputs": {"path": input_path.as_posix(), "sha256": sha256_file(input_path)},
                "truth": {"path": truth_path.as_posix(), "sha256": sha256_file(truth_path)},
            },
        }
    )
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
    print(json.dumps(index, indent=2))


if __name__ == "__main__":
    main()
