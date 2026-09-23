#!/usr/bin/env python3
"""Build leakage-controlled EviGate-LLM evidence packages and truth sidecar."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import numpy as np

from run_stage_b_typed_ranker import feature_names, load_jsonl, sha256_file
from run_stage_c_selective_attribution import (
    CORRUPTION_FAMILIES,
    TACTICS,
    fit_entity_ranker,
    fit_tactic_models,
    make_representation,
    partition_ids,
    replacement_for,
    tactic_posteriors,
    transformed_process_data,
)


CONDITIONS = ("clean",) + CORRUPTION_FAMILIES


def sample_id(case_id: str, condition: str) -> str:
    digest = hashlib.sha256(f"{case_id}\0{condition}".encode("utf-8")).hexdigest()[:20]
    return f"sample_{digest}"


def compact_text(value: Any, limit: int = 240) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def count_from_log(value: float) -> int:
    return max(0, int(round(math.expm1(max(float(value), 0.0)))))


def network_event(alert: dict[str, Any]) -> dict[str, Any]:
    def top_ports(name: str) -> list[dict[str, Any]]:
        return [
            {"port": str(item.get("value", "")), "count": int(item.get("count", 0))}
            for item in alert.get(name, [])[:5]
        ]

    return {
        "window_seconds": int(alert.get("window_seconds", 60)),
        "row_count": int(alert.get("row_count", 0)),
        "total_bytes": round(float(alert.get("total_bytes", 0.0)), 3),
        "trigger_offset_seconds": round(float(alert.get("trigger_offset_seconds", 0.0)), 3),
        "protocol_counts": {
            str(key): int(value)
            for key, value in sorted(alert.get("protocol_counts", {}).items())
        },
        "unique_source_ips": int(alert.get("unique_source_ips", 0)),
        "unique_destination_ips": int(alert.get("unique_destination_ips", 0)),
        "unique_source_ports": int(alert.get("unique_source_ports", 0)),
        "unique_destination_ports": int(alert.get("unique_destination_ports", 0)),
        "source_ip_hhi": round(float(alert.get("source_ip_hhi", 0.0)), 6),
        "destination_ip_hhi": round(float(alert.get("destination_ip_hhi", 0.0)), 6),
        "source_port_hhi": round(float(alert.get("source_port_hhi", 0.0)), 6),
        "destination_port_hhi": round(float(alert.get("destination_port_hhi", 0.0)), 6),
        "top_source_ports": top_ports("top_source_ports"),
        "top_destination_ports": top_ports("top_destination_ports"),
    }


def add_anchor(
    anchors: list[dict[str, str]], rank: int, kind: str, fact: str
) -> None:
    if not fact:
        return
    anchors.append(
        {
            "anchor_id": f"P{rank}.{kind}",
            "anchor_type": kind,
            "fact": compact_text(fact),
        }
    )


def candidate_record(
    rank: int,
    entity_id: str,
    score: float,
    row: np.ndarray,
    raw_entity: dict[str, Any],
) -> dict[str, Any]:
    values = dict(zip(feature_names(), map(float, row)))
    attributes = raw_entity.get("attributes", {})
    name = compact_text(attributes.get("name", ""), 80)
    executable = compact_text(attributes.get("exe", ""), 160)
    command_line = compact_text(attributes.get("command_line", ""), 240)
    anchors: list[dict[str, str]] = []
    identity_parts = []
    if name:
        identity_parts.append(f"name={name}")
    if executable:
        identity_parts.append(f"executable={executable}")
    add_anchor(anchors, rank, "identity", "; ".join(identity_parts))
    add_anchor(anchors, rank, "command", f"command_line={command_line}" if command_line else "")
    add_anchor(
        anchors,
        rank,
        "temporal",
        "closest_abs_time_delta_seconds="
        f"{math.expm1(max(values['log_closest_abs_time_delta'], 0.0)):.3f}; "
        f"time_proximity={values['time_proximity']:.6f}",
    )
    add_anchor(
        anchors,
        rank,
        "topology",
        f"incident_edges={count_from_log(values['log_incident_edge_count'])}; "
        f"in_degree={count_from_log(values['log_in_degree'])}; "
        f"out_degree={count_from_log(values['log_out_degree'])}",
    )
    socket_neighbors = count_from_log(values["log_socket_neighbors"])
    socket_both = count_from_log(values["log_matched_socket_both"])
    if socket_neighbors or socket_both:
        add_anchor(
            anchors,
            rank,
            "socket",
            f"socket_neighbors={socket_neighbors}; matched_address_and_port={socket_both}; "
            f"max_socket_time_proximity={values['max_socket_time_proximity']:.6f}",
        )
    file_neighbors = count_from_log(values["log_file_neighbors"])
    if file_neighbors:
        add_anchor(
            anchors,
            rank,
            "file",
            f"file_neighbors={file_neighbors}; "
            f"tmp_neighbors={count_from_log(values['log_tmp_file_neighbors'])}; "
            f"home_neighbors={count_from_log(values['log_home_file_neighbors'])}; "
            f"system_neighbors={count_from_log(values['log_system_file_neighbors'])}",
        )
    operations = [
        name.removeprefix("operation_")
        for name in feature_names()
        if name.startswith("operation_") and values[name] > 0.0
    ]
    if operations:
        add_anchor(anchors, rank, "operation", "observed_operation_groups=" + ",".join(operations))
    return {
        "rank": rank,
        "entity_id": entity_id,
        "ranker_score": round(float(score), 6),
        "process": {
            "name": name,
            "executable": executable,
            "command_line": command_line,
        },
        "anchors": anchors,
    }


def build_evidence_case(
    case_input: dict[str, Any],
    ranker: Any,
    condition: str,
    replacement: dict[str, Any] | None,
    top_k: int,
    machine_proposal: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ids, matrix, scores, graph_meta = transformed_process_data(
        case_input,
        ranker,
        corruption=condition,
        replacement=replacement,
    )
    source = replacement if condition == "context_replacement" and replacement else case_input
    raw_entities = {
        entity["entity_id"]: entity
        for entity in source["provenance_candidate_graph"]["entities"]
    }
    candidates = [
        candidate_record(
            rank=index + 1,
            entity_id=entity_id,
            score=float(scores[index]),
            row=matrix[index],
            raw_entity=raw_entities.get(entity_id, {}),
        )
        for index, entity_id in enumerate(ids[:top_k])
    ]
    names = feature_names()
    top_n = min(3, len(ids))
    if top_n:
        top_matrix = matrix[:top_n]
        top3_mean_time_proximity = float(
            np.mean(top_matrix[:, names.index("time_proximity")])
        )
        top3_matched_socket_both = sum(
            count_from_log(value)
            for value in top_matrix[:, names.index("log_matched_socket_both")]
        )
        top3_socket_neighbors = sum(
            count_from_log(value)
            for value in top_matrix[:, names.index("log_socket_neighbors")]
        )
        top3_file_neighbors = sum(
            count_from_log(value)
            for value in top_matrix[:, names.index("log_file_neighbors")]
        )
    else:
        top3_mean_time_proximity = 0.0
        top3_matched_socket_both = 0
        top3_socket_neighbors = 0
        top3_file_neighbors = 0
    margin = float(scores[0] - scores[1]) if len(scores) > 1 else (float(scores[0]) if len(scores) else 0.0)
    result = {
        "schema_version": "1.0",
        "case_id": case_input["case_id"],
        "network_event": network_event(case_input["network_alert"]),
        "provenance_summary": {
            "context_radius_seconds": int(
                source["provenance_candidate_graph"].get("radius_seconds", 0)
            ),
            "process_candidate_count": len(ids),
            "total_candidate_entity_count": int(
                graph_meta.get("candidate_entity_count", len(ids))
            ),
            "relation_count": int(graph_meta.get("relation_count", 0)),
            "entity_kind_counts": {
                str(key): int(value)
                for key, value in sorted(graph_meta.get("entity_kind_counts", {}).items())
            },
            "top_ranker_score": round(float(scores[0]), 6) if len(scores) else 0.0,
            "ranker_score_margin": round(margin, 6),
            "presented_process_count": len(candidates),
            "top3_mean_time_proximity": round(top3_mean_time_proximity, 6),
            "top3_matched_socket_both": top3_matched_socket_both,
            "top3_socket_neighbors": top3_socket_neighbors,
            "top3_file_neighbors": top3_file_neighbors,
        },
        "ranked_process_candidates": candidates,
    }
    if machine_proposal is not None:
        result["machine_proposal"] = machine_proposal
    return result


def proposal_for(
    case_input: dict[str, Any],
    ranker: Any,
    tactic_models: dict[str, Any],
    condition: str,
    replacement: dict[str, Any] | None,
) -> dict[str, Any]:
    representation = make_representation(
        case_input,
        ranker,
        corruption=condition,
        replacement=replacement,
    )
    probabilities = tactic_posteriors(tactic_models, representation)["combined"]
    ordered = sorted(map(float, probabilities), reverse=True)
    return {
        "tactic": TACTICS[int(np.argmax(probabilities))],
        "confidence": round(float(max(probabilities)), 6),
        "margin": round(ordered[0] - ordered[1], 6),
        "probabilities": {
            tactic: round(float(probability), 6)
            for tactic, probability in zip(TACTICS, probabilities)
        },
    }


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def run(args: argparse.Namespace) -> dict[str, Any]:
    inputs = {item["case_id"]: item for item in load_jsonl(args.inputs)}
    truths = {item["case_id"]: item for item in load_jsonl(args.truth)}
    if set(inputs) != set(truths):
        raise ValueError("input and truth sidecars have different case IDs")
    evidence_rows: list[dict[str, Any]] = []
    truth_rows: list[dict[str, Any]] = []
    calibration_evidence_rows: list[dict[str, Any]] = []
    calibration_truth_rows: list[dict[str, Any]] = []
    fold_counts: dict[str, int] = {}
    calibration_fold_counts: dict[str, int] = {}

    for fold in (1, 2, 3):
        train_ids = sorted(partition_ids(truths, fold, "train", in_support=True))
        calibration_ids = sorted(
            partition_ids(truths, fold, "calibration", in_support=True)
        )
        test_ids = sorted(partition_ids(truths, fold, "test", in_support=True))
        ranker = fit_entity_ranker(train_ids, inputs, truths, args.seed)
        train_representations = {
            case_id: make_representation(inputs[case_id], ranker)
            for case_id in train_ids
        }
        tactic_models = fit_tactic_models(
            train_ids, train_representations, truths, args.seed
        )
        fold_counts[str(fold)] = len(test_ids)
        calibration_fold_counts[str(fold)] = len(calibration_ids)
        for case_id in calibration_ids:
            evidence = build_evidence_case(
                inputs[case_id],
                ranker,
                "clean",
                replacement=None,
                top_k=args.top_k,
                machine_proposal=proposal_for(
                    inputs[case_id], ranker, tactic_models, "clean", None
                ),
            )
            opaque_sample_id = sample_id(
                f"{case_id}:fold_{fold}:calibration", "clean"
            )
            calibration_evidence_rows.append(
                {
                    "sample_id": opaque_sample_id,
                    "test_fold": fold,
                    **evidence,
                }
            )
            calibration_truth_rows.append(
                {
                    "sample_id": opaque_sample_id,
                    "case_id": case_id,
                    "test_fold": fold,
                    "condition": "clean",
                    "corruption_family": None,
                    "tactic": truths[case_id]["event"]["tactic"],
                    "support_role": truths[case_id]["event"]["support_role"],
                    "replacement_case_id": None,
                }
            )
        for case_id in test_ids:
            for condition in CONDITIONS:
                replacement_id = None
                replacement = None
                if condition == "context_replacement":
                    replacement_id = replacement_for(case_id, train_ids, truths)
                    replacement = inputs[replacement_id]
                evidence = build_evidence_case(
                    inputs[case_id],
                    ranker,
                    condition,
                    replacement,
                    args.top_k,
                    machine_proposal=proposal_for(
                        inputs[case_id],
                        ranker,
                        tactic_models,
                        condition,
                        replacement,
                    ),
                )
                opaque_sample_id = sample_id(case_id, condition)
                evidence_rows.append(
                    {
                        "sample_id": opaque_sample_id,
                        "test_fold": fold,
                        **evidence,
                    }
                )
                truth_rows.append(
                    {
                        "sample_id": opaque_sample_id,
                        "case_id": case_id,
                        "test_fold": fold,
                        "condition": "clean" if condition == "clean" else "corrupted",
                        "corruption_family": None if condition == "clean" else condition,
                        "tactic": truths[case_id]["event"]["tactic"],
                        "support_role": truths[case_id]["event"]["support_role"],
                        "replacement_case_id": replacement_id,
                    }
                )

    evidence_rows.sort(key=lambda row: row["sample_id"])
    truth_rows.sort(key=lambda row: row["sample_id"])
    calibration_evidence_rows.sort(key=lambda row: row["sample_id"])
    calibration_truth_rows.sort(key=lambda row: row["sample_id"])
    args.output_dir.mkdir(parents=True, exist_ok=True)
    input_path = args.output_dir / "evigate_llm.inputs.jsonl"
    truth_path = args.output_dir / "evigate_llm.truth.jsonl"
    calibration_input_path = args.output_dir / "evigate_llm.calibration.inputs.jsonl"
    calibration_truth_path = args.output_dir / "evigate_llm.calibration.truth.jsonl"
    write_jsonl(input_path, evidence_rows)
    write_jsonl(truth_path, truth_rows)
    write_jsonl(calibration_input_path, calibration_evidence_rows)
    write_jsonl(calibration_truth_path, calibration_truth_rows)
    summary = {
        "schema_version": "1.0",
        "study": "EviGate-LLM evidence-package manifest",
        "prompt_version": args.prompt_version,
        "seed": args.seed,
        "top_k": args.top_k,
        "conditions": list(CONDITIONS),
        "test_events": sum(fold_counts.values()),
        "samples": len(evidence_rows),
        "samples_per_event": len(CONDITIONS),
        "test_events_by_fold": fold_counts,
        "calibration_samples": len(calibration_evidence_rows),
        "calibration_samples_by_fold": calibration_fold_counts,
        "truth_separated_from_inference": True,
        "source_files": {
            "inputs": {"path": str(args.inputs), "sha256": sha256_file(args.inputs)},
            "truth": {"path": str(args.truth), "sha256": sha256_file(args.truth)},
        },
        "artifacts": {
            input_path.name: {"sha256": sha256_file(input_path), "bytes": input_path.stat().st_size},
            truth_path.name: {"sha256": sha256_file(truth_path), "bytes": truth_path.stat().st_size},
            calibration_input_path.name: {
                "sha256": sha256_file(calibration_input_path),
                "bytes": calibration_input_path.stat().st_size,
            },
            calibration_truth_path.name: {
                "sha256": sha256_file(calibration_truth_path),
                "bytes": calibration_truth_path.stat().st_size,
            },
        },
    }
    summary_path = args.output_dir / "evigate_llm.manifest.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--seed", type=int, default=20260915)
    parser.add_argument("--prompt-version", default="evigate_llm_v1")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(json.dumps(run(args), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
