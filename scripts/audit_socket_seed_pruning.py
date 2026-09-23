#!/usr/bin/env python3
"""Audit whether socket-seeded two-hop pruning preserves malicious PID evidence."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

from build_cicapt_evidence_dataset import sha256_file


def read_jsonl(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def distribution(values: list[int]) -> dict:
    ordered = sorted(values)
    return {
        "min": min(ordered),
        "median": statistics.median(ordered),
        "p90": ordered[round(0.9 * (len(ordered) - 1))],
        "max": max(ordered),
    }


def two_hop_candidates(graph: dict, rule: str) -> tuple[set[str], int]:
    nodes = {node["entity_id"]: node for node in graph["entities"]}
    seeds = set()
    for entity_id, node in nodes.items():
        if node.get("entity_kind") != "socket":
            continue
        features = node.get("features", {})
        address_match = bool(features.get("address_match"))
        port_match = bool(features.get("port_match"))
        if (
            rule == "joint" and address_match and port_match
        ) or (
            rule == "either" and (address_match or port_match)
        ) or (
            rule == "address" and address_match
        ) or (
            rule == "port" and port_match
        ):
            seeds.add(entity_id)

    if not seeds:
        return set(nodes), 0
    adjacency: dict[str, set[str]] = defaultdict(set)
    for relation in graph["relations"]:
        source = relation.get("source_entity_id", "")
        target = relation.get("target_entity_id", "")
        if source and target:
            adjacency[source].add(target)
            adjacency[target].add(source)
    retained = set(seeds)
    frontier = set(seeds)
    for _ in range(2):
        next_frontier = {
            neighbour for entity_id in frontier for neighbour in adjacency[entity_id]
        } - retained
        retained.update(next_frontier)
        frontier = next_frontier
    return retained & set(nodes), len(seeds)


def audit_policy(inputs: list[dict], truths: list[dict], rule: str) -> dict:
    seeded_cases = 0
    candidate_counts = []
    truth_cases = 0
    preserved_cases = 0
    lost_cases = []
    for input_record, truth_record in zip(inputs, truths):
        graph = input_record["provenance_candidate_graph"]
        nodes = {node["entity_id"]: node for node in graph["entities"]}
        retained, seed_count = two_hop_candidates(graph, rule)
        if seed_count:
            seeded_cases += 1
        candidate_counts.append(len(retained))
        truth_pids = set(
            truth_record["provenance_ground_truth"]["malicious_candidate_pids"]
        )
        if not truth_pids:
            continue
        truth_cases += 1
        retained_pids = {
            nodes[entity_id].get("attributes", {}).get("pid")
            for entity_id in retained
            if nodes[entity_id].get("attributes", {}).get("pid")
        }
        if truth_pids & retained_pids:
            preserved_cases += 1
        else:
            lost_cases.append(
                {
                    "case_id": input_record["case_id"],
                    "source_cluster_id": truth_record["source_cluster_id"],
                    "tactic": truth_record["event"]["tactic"],
                    "full_candidate_count": len(nodes),
                    "retained_candidate_count": len(retained),
                    "seed_count": seed_count,
                }
            )
    return {
        "rule": rule,
        "seeded_case_count": seeded_cases,
        "cases_with_pid_truth": truth_cases,
        "cases_preserving_any_pid_truth": preserved_cases,
        "pid_truth_case_preservation_rate": preserved_cases / truth_cases if truth_cases else None,
        "candidate_count_after_policy": distribution(candidate_counts),
        "lost_case_count": len(lost_cases),
        "lost_cases": lost_cases,
    }


def build_report(inputs: list[dict], truths: list[dict]) -> dict:
    if [item["case_id"] for item in inputs] != [item["case_id"] for item in truths]:
        raise ValueError("Input and truth case identifiers are not aligned")
    policies = {
        rule: audit_policy(inputs, truths, rule)
        for rule in ("joint", "address", "port", "either")
    }
    full_candidate_counts = [
        item["provenance_candidate_graph"]["candidate_entity_count"] for item in inputs
    ]
    full_truth_cases = sum(
        bool(item["provenance_ground_truth"]["malicious_candidate_pids"])
        for item in truths
    )
    return {
        "schema_version": "1.0",
        "case_count": len(inputs),
        "full_window_policy": {
            "cases_with_pid_truth": full_truth_cases,
            "cases_preserving_any_pid_truth": full_truth_cases,
            "pid_truth_case_preservation_rate": 1.0 if full_truth_cases else None,
            "candidate_count": distribution(full_candidate_counts),
        },
        "two_hop_pruning_policies": policies,
        "decision": (
            "Retain the complete typed time-window candidate pool. Use socket address/port "
            "matches as soft ranking features; treat hard two-hop pruning as a diagnostic ablation."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report = build_report(read_jsonl(args.inputs), read_jsonl(args.truth))
    report["source_files"] = {
        "inputs": {"path": args.inputs.as_posix(), "sha256": sha256_file(args.inputs)},
        "truth": {"path": args.truth.as_posix(), "sha256": sha256_file(args.truth)},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
