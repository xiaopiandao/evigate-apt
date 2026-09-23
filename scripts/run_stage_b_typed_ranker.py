#!/usr/bin/env python3
"""Train and evaluate lightweight typed process rankers for EviGate-APT Stage B."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from statistics import mean, stdev
from typing import Any

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from evaluate_stage_b_retrieval_baselines import summarize, tie_hit_probability


MODELS = ("typed_logistic", "typed_hgb")
RELATION_TYPES = ("Used", "WasGeneratedBy", "WasTriggeredBy", "WasDerivedFrom")
OPERATION_GROUPS = (
    "load",
    "execve",
    "connect",
    "unlink",
    "rename",
    "privilege",
    "open_update",
    "other",
)
UTILITY_GROUPS = {
    "shell": {"sh", "dash", "bash", "zsh"},
    "interpreter": {"python", "python3", "python3.8", "perl", "ruby", "php"},
    "network": {"curl", "wget", "nc", "netcat", "ssh", "scp", "ftp", "telnet"},
    "archive_encoding": {"tar", "gzip", "zip", "base64", "openssl"},
    "privilege": {"sudo", "su", "chmod", "chown", "setcap"},
    "search": {"find", "grep", "locate"},
    "copy_move": {"cp", "mv", "rsync"},
    "package": {"apt", "apt-get", "apt-config", "dpkg", "snap"},
}
PRIMARY_METRICS = (
    "mean_midrank_reciprocal_all_cases",
    "mean_normalized_best_rank_truth_present",
    "expected_tie_recall_at_1_all_cases",
    "expected_tie_recall_at_5_all_cases",
    "expected_tie_recall_at_10_all_cases",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def operation_group(operation: str) -> str:
    value = operation.lower().strip()
    if value in {"load", "execve", "connect", "unlink"}:
        return value
    if value.startswith("rename"):
        return "rename"
    if value in {"setuid", "setgid", "chmod"}:
        return "privilege"
    if value in {"open", "update"}:
        return "open_update"
    return "other"


def process_contexts(case_input: dict[str, Any]) -> dict[str, dict[str, Any]]:
    graph = case_input["provenance_candidate_graph"]
    entities = {entity["entity_id"]: entity for entity in graph["entities"]}
    contexts: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "neighbor_kinds": Counter(),
            "relation_types": Counter(),
            "operations": Counter(),
            "matched_socket_address": 0,
            "matched_socket_port": 0,
            "matched_socket_both": 0,
            "max_socket_time_proximity": 0.0,
            "tmp_file_neighbor": 0,
            "home_file_neighbor": 0,
            "system_file_neighbor": 0,
            "relation_abs_delta_min": math.inf,
            "relation_before_count": 0,
            "relation_after_count": 0,
        }
    )
    for relation in graph["relations"]:
        source = relation["source_entity_id"]
        target = relation["target_entity_id"]
        for process_id, neighbor_id in ((source, target), (target, source)):
            process = entities.get(process_id)
            neighbor = entities.get(neighbor_id)
            if not process or process["entity_kind"] != "process" or not neighbor:
                continue
            context = contexts[process_id]
            neighbor_kind = neighbor["entity_kind"]
            context["neighbor_kinds"][neighbor_kind] += 1
            context["relation_types"][relation.get("relation_type", "")] += 1
            context["operations"][operation_group(relation.get("operation", ""))] += 1
            delta = float(relation.get("time_delta_seconds", 0.0))
            context["relation_abs_delta_min"] = min(
                context["relation_abs_delta_min"], abs(delta)
            )
            context["relation_before_count"] += int(delta < 0)
            context["relation_after_count"] += int(delta >= 0)
            if neighbor_kind == "socket":
                features = neighbor["features"]
                address_match = bool(features.get("address_match", False))
                port_match = bool(features.get("port_match", False))
                context["matched_socket_address"] += int(address_match)
                context["matched_socket_port"] += int(port_match)
                context["matched_socket_both"] += int(address_match and port_match)
                context["max_socket_time_proximity"] = max(
                    context["max_socket_time_proximity"],
                    float(features.get("time_proximity", 0.0)),
                )
            elif neighbor_kind == "file":
                path = str(neighbor.get("attributes", {}).get("path", ""))
                context["tmp_file_neighbor"] += int(path.startswith(("/tmp/", "/var/tmp/")))
                context["home_file_neighbor"] += int(path.startswith("/home/"))
                context["system_file_neighbor"] += int(
                    path.startswith(("/bin/", "/sbin/", "/usr/", "/lib", "/etc/"))
                )
    return contexts


def feature_names() -> list[str]:
    names = [
        "time_proximity",
        "log_closest_abs_time_delta",
        "degree_score",
        "recency_degree_score",
        "log_incident_edge_count",
        "log_in_degree",
        "log_out_degree",
        "in_degree_fraction",
        "process_path_depth",
        "process_name_length_log",
        "process_exe_length_log",
        "is_system_binary",
        "is_user_binary",
        "has_parent_pid",
    ]
    names.extend(f"utility_{name}" for name in UTILITY_GROUPS)
    names.extend(
        [
            "log_process_neighbors",
            "log_file_neighbors",
            "log_socket_neighbors",
            "log_matched_socket_address",
            "log_matched_socket_port",
            "log_matched_socket_both",
            "max_socket_time_proximity",
            "log_tmp_file_neighbors",
            "log_home_file_neighbors",
            "log_system_file_neighbors",
            "log_min_relation_abs_delta",
            "relation_before_fraction",
        ]
    )
    names.extend(f"relation_type_{name}" for name in RELATION_TYPES)
    names.extend(f"operation_{name}" for name in OPERATION_GROUPS)
    names.extend(
        [
            "alert_row_count_log",
            "alert_source_ip_hhi",
            "alert_destination_ip_hhi",
            "alert_source_port_hhi",
            "alert_destination_port_hhi",
            "alert_tcp_fraction",
            "alert_udp_fraction",
            "alert_icmp_fraction",
            "alert_arp_fraction",
        ]
    )
    return names


def entity_features(
    case_input: dict[str, Any], entity: dict[str, Any], context: dict[str, Any]
) -> list[float]:
    attributes = entity.get("attributes", {})
    base = entity["features"]
    exe = str(attributes.get("exe", ""))
    name = str(attributes.get("name", ""))
    basename = PurePosixPath(exe).name.lower() if exe else name.lower()
    incident = float(base.get("incident_edge_count", 0.0))
    in_degree = float(base.get("in_degree", 0.0))
    out_degree = float(base.get("out_degree", 0.0))
    relation_total = context["relation_before_count"] + context["relation_after_count"]
    protocol_counts = case_input["network_alert"].get("protocol_counts", {})
    alert_rows = max(float(case_input["network_alert"].get("row_count", 0.0)), 1.0)
    values = [
        float(base.get("time_proximity", 0.0)),
        math.log1p(float(base.get("closest_abs_time_delta_seconds", 0.0))),
        float(base.get("degree_score", 0.0)),
        float(base.get("recency_degree_score", 0.0)),
        math.log1p(incident),
        math.log1p(in_degree),
        math.log1p(out_degree),
        in_degree / max(in_degree + out_degree, 1.0),
        float(max(len(PurePosixPath(exe).parts) - 1, 0)) if exe else 0.0,
        math.log1p(len(name)),
        math.log1p(len(exe)),
        float(exe.startswith(("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib"))),
        float(exe.startswith(("/home/", "/tmp/", "/var/tmp/"))),
        float(bool(str(attributes.get("ppid", "")).strip())),
    ]
    values.extend(float(basename in members) for members in UTILITY_GROUPS.values())
    values.extend(
        [
            math.log1p(context["neighbor_kinds"]["process"]),
            math.log1p(context["neighbor_kinds"]["file"]),
            math.log1p(context["neighbor_kinds"]["socket"]),
            math.log1p(context["matched_socket_address"]),
            math.log1p(context["matched_socket_port"]),
            math.log1p(context["matched_socket_both"]),
            float(context["max_socket_time_proximity"]),
            math.log1p(context["tmp_file_neighbor"]),
            math.log1p(context["home_file_neighbor"]),
            math.log1p(context["system_file_neighbor"]),
            math.log1p(
                context["relation_abs_delta_min"]
                if math.isfinite(context["relation_abs_delta_min"])
                else 0.0
            ),
            context["relation_before_count"] / max(relation_total, 1),
        ]
    )
    values.extend(math.log1p(context["relation_types"][name]) for name in RELATION_TYPES)
    values.extend(math.log1p(context["operations"][name]) for name in OPERATION_GROUPS)
    values.extend(
        [
            math.log1p(alert_rows),
            float(case_input["network_alert"].get("source_ip_hhi", 0.0)),
            float(case_input["network_alert"].get("destination_ip_hhi", 0.0)),
            float(case_input["network_alert"].get("source_port_hhi", 0.0)),
            float(case_input["network_alert"].get("destination_port_hhi", 0.0)),
            float(protocol_counts.get("TCP", 0)) / alert_rows,
            float(protocol_counts.get("UDP", 0)) / alert_rows,
            float(protocol_counts.get("ICMP", 0)) / alert_rows,
            float(protocol_counts.get("ARP", 0)) / alert_rows,
        ]
    )
    if len(values) != len(feature_names()):
        raise AssertionError("typed feature vector length mismatch")
    return values


def extract_case(case_input: dict[str, Any]) -> tuple[list[str], np.ndarray]:
    contexts = process_contexts(case_input)
    processes = sorted(
        (
            entity
            for entity in case_input["provenance_candidate_graph"]["entities"]
            if entity["entity_kind"] == "process"
        ),
        key=lambda entity: entity["entity_id"],
    )
    ids = [entity["entity_id"] for entity in processes]
    matrix = np.asarray(
        [entity_features(case_input, entity, contexts[entity["entity_id"]]) for entity in processes],
        dtype=np.float64,
    )
    if not np.isfinite(matrix).all():
        raise ValueError(f"case {case_input['case_id']} has non-finite typed features")
    return ids, matrix


def membership(case_truth: dict[str, Any], fold: int) -> dict[str, Any]:
    matches = [
        item for item in case_truth["split_membership"] if int(item["fold"]) == fold
    ]
    if len(matches) != 1:
        raise ValueError(f"case {case_truth['case_id']} has invalid fold membership")
    return matches[0]


def training_data(
    inputs: dict[str, dict[str, Any]],
    truths: dict[str, dict[str, Any]],
    extracted: dict[str, tuple[list[str], np.ndarray]],
    fold: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, int]]:
    matrices: list[np.ndarray] = []
    labels: list[np.ndarray] = []
    weights: list[np.ndarray] = []
    audit = Counter()
    for case_id in sorted(inputs):
        member = membership(truths[case_id], fold)
        if member["partition"] != "train" or not member.get("supervised_eligible", False):
            continue
        entity_ids, matrix = extracted[case_id]
        truth_ids = set(
            truths[case_id]["provenance_ground_truth"]["malicious_candidate_process_ids"]
        )
        y = np.asarray([int(entity_id in truth_ids) for entity_id in entity_ids], dtype=int)
        if not np.any(y):
            audit["excluded_train_cases_without_candidate_truth"] += 1
            continue
        negative_count = int(np.sum(y == 0))
        positive_count = int(np.sum(y == 1))
        sample_weight = np.zeros(len(y), dtype=float)
        sample_weight[y == 1] = 0.5 / positive_count
        if negative_count:
            sample_weight[y == 0] = 0.5 / negative_count
        else:
            sample_weight[y == 1] = 1.0 / positive_count
        matrices.append(matrix)
        labels.append(y)
        weights.append(sample_weight)
        audit["included_train_cases"] += 1
        audit["positive_train_entities"] += positive_count
        audit["negative_train_entities"] += negative_count
    return np.vstack(matrices), np.concatenate(labels), np.concatenate(weights), dict(audit)


def fit_ranker(
    name: str, x: np.ndarray, y: np.ndarray, weights: np.ndarray, seed: int
) -> Any:
    if name == "typed_logistic":
        model = Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        C=1.0,
                        max_iter=2000,
                        solver="liblinear",
                        random_state=seed,
                    ),
                ),
            ]
        )
        model.fit(x, y, classifier__sample_weight=weights)
        return model
    if name == "typed_hgb":
        model = HistGradientBoostingClassifier(
            learning_rate=0.05,
            max_iter=120,
            max_leaf_nodes=7,
            min_samples_leaf=20,
            l2_regularization=0.1,
            random_state=seed,
        )
        model.fit(x, y, sample_weight=weights)
        return model
    raise ValueError(name)


def ranking_row(
    case_id: str,
    truth: dict[str, Any],
    entity_ids: list[str],
    scores: np.ndarray,
    model_name: str,
    seed: int,
    fold: int,
    top_ks: tuple[int, ...],
) -> dict[str, Any]:
    ranked = sorted(zip(entity_ids, map(float, scores)), key=lambda item: (-item[1], item[0]))
    truth_ids = set(truth["provenance_ground_truth"]["malicious_candidate_process_ids"])
    positions = [
        index for index, (entity_id, _) in enumerate(ranked, start=1) if entity_id in truth_ids
    ]
    deterministic_rank = min(positions) if positions else None
    if positions:
        best_truth_score = max(score for entity_id, score in ranked if entity_id in truth_ids)
        higher = sum(score > best_truth_score for _, score in ranked)
        equal = sum(score == best_truth_score for _, score in ranked)
        truth_in_tie = sum(
            entity_id in truth_ids and score == best_truth_score for entity_id, score in ranked
        )
        optimistic_rank = higher + 1
        pessimistic_rank = higher + equal
        midrank = (optimistic_rank + pessimistic_rank) / 2.0
    else:
        higher = equal = truth_in_tie = 0
        optimistic_rank = pessimistic_rank = midrank = None
    candidate_count = len(ranked)
    normalized = (
        (deterministic_rank - 1) / max(candidate_count - 1, 1)
        if deterministic_rank is not None
        else None
    )
    row = {
        "case_id": case_id,
        "test_fold": fold,
        "seed": seed,
        "model": model_name,
        "tactic": truth["event"]["tactic"],
        "support_role": truth["event"]["support_role"],
        "baseline": model_name,
        "process_candidate_count": candidate_count,
        "truth_process_entity_count": len(truth_ids),
        "truth_present": int(bool(positions)),
        "deterministic_best_rank": deterministic_rank if deterministic_rank is not None else "",
        "optimistic_best_rank": optimistic_rank if optimistic_rank is not None else "",
        "pessimistic_best_rank": pessimistic_rank if pessimistic_rank is not None else "",
        "midrank": midrank if midrank is not None else "",
        "midrank_reciprocal": 1.0 / midrank if midrank is not None else 0.0,
        "best_truth_score_tie_size": equal,
        "truth_entities_in_best_tie": truth_in_tie,
        "normalized_best_rank": normalized if normalized is not None else "",
        "reciprocal_rank": 1.0 / deterministic_rank if deterministic_rank is not None else 0.0,
        "top_ranked_entity_id": ranked[0][0] if ranked else "",
        "top_ranked_pid": "",
    }
    for k in top_ks:
        row[f"hit_at_{k}"] = int(deterministic_rank is not None and deterministic_rank <= k)
        row[f"optimistic_hit_at_{k}"] = int(
            optimistic_rank is not None and optimistic_rank <= k
        )
        row[f"pessimistic_hit_at_{k}"] = int(
            pessimistic_rank is not None and pessimistic_rank <= k
        )
        row[f"expected_tie_hit_at_{k}"] = tie_hit_probability(
            higher, equal, truth_in_tie, k
        )
    return row


def aggregate_ranker_rows(
    rows: list[dict[str, Any]], top_ks: tuple[int, ...], seeds: list[int]
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for model_name in MODELS:
        model_rows = [row for row in rows if row["model"] == model_name]
        seed_summaries = [
            summarize([row for row in model_rows if int(row["seed"]) == seed], top_ks)
            for seed in seeds
        ]
        fold_summaries = {
            str(fold): summarize(
                [row for row in model_rows if int(row["test_fold"]) == fold], top_ks
            )
            for fold in (1, 2, 3)
        }
        primary: dict[str, Any] = {}
        for metric in PRIMARY_METRICS:
            seed_values = [float(summary[metric]) for summary in seed_summaries]
            fold_values = [float(summary[metric]) for summary in fold_summaries.values()]
            primary[metric] = {
                "mean_across_seeds": mean(seed_values),
                "sample_std_across_seeds": stdev(seed_values) if len(seed_values) > 1 else 0.0,
                "mean_of_fold_means": mean(fold_values),
                "sample_std_across_fold_means": stdev(fold_values),
                "fold_means": fold_values,
            }
        output[model_name] = {
            "primary_metrics": primary,
            "pooled_test_cases_by_seed": {
                str(seed): summary for seed, summary in zip(seeds, seed_summaries)
            },
            "by_test_fold_averaged_over_seeds": fold_summaries,
        }
    return output


def run(
    inputs_path: Path,
    truth_path: Path,
    baseline_summary_path: Path,
    output_dir: Path,
    seeds: list[int],
    top_ks: tuple[int, ...],
) -> dict[str, Any]:
    inputs = {item["case_id"]: item for item in load_jsonl(inputs_path)}
    truths = {item["case_id"]: item for item in load_jsonl(truth_path)}
    if set(inputs) != set(truths):
        raise ValueError("input and truth case ID sets differ")
    extracted = {case_id: extract_case(case) for case_id, case in inputs.items()}
    rows: list[dict[str, Any]] = []
    training_audits: list[dict[str, Any]] = []

    for fold in (1, 2, 3):
        x_train, y_train, weights, audit = training_data(inputs, truths, extracted, fold)
        for seed in seeds:
            for model_name in MODELS:
                model = fit_ranker(model_name, x_train, y_train, weights, seed)
                for case_id in sorted(inputs):
                    member = membership(truths[case_id], fold)
                    if member["partition"] != "test":
                        continue
                    entity_ids, matrix = extracted[case_id]
                    scores = model.predict_proba(matrix)[:, 1]
                    rows.append(
                        ranking_row(
                            case_id,
                            truths[case_id],
                            entity_ids,
                            scores,
                            model_name,
                            seed,
                            fold,
                            top_ks,
                        )
                    )
        training_audits.append({"fold": fold, **audit})

    expected_rows = len(inputs) * len(seeds) * len(MODELS)
    if len(rows) != expected_rows:
        raise ValueError(f"expected {expected_rows} test-case rows, observed {len(rows)}")
    output_dir.mkdir(parents=True, exist_ok=True)
    per_case_path = output_dir / "stage_b_typed_ranker.per_case.csv"
    with per_case_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)

    baseline_summary = json.loads(baseline_summary_path.read_text(encoding="utf-8"))
    result = {
        "schema_version": "1.0",
        "experiment": "EviGate-APT Stage-B typed process ranker",
        "feature_names": feature_names(),
        "feature_count": len(feature_names()),
        "identity_features_excluded": [
            "case_id",
            "entity_id",
            "pid/ppid numeric value",
            "raw executable path/name",
            "raw IP address",
            "raw port",
            "absolute timestamp",
            "tactic label",
        ],
        "models": list(MODELS),
        "seeds": seeds,
        "top_ks": list(top_ks),
        "training_policy": "in-support train cases only; each case has total weight 1 and positive/negative entity classes each receive half its weight; cases without candidate truth are excluded",
        "training_audit": training_audits,
        "results": aggregate_ranker_rows(rows, top_ks, seeds),
        "comparison_baselines": {
            name: baseline_summary["summary"][name]["overall"]
            for name in ("recency", "degree", "recency_plus_degree", "analytic_random_expectation")
        },
        "source_files": {
            "inputs": {"path": inputs_path.as_posix(), "sha256": sha256_file(inputs_path)},
            "truth": {"path": truth_path.as_posix(), "sha256": sha256_file(truth_path)},
            "baselines": {
                "path": baseline_summary_path.as_posix(),
                "sha256": sha256_file(baseline_summary_path),
            },
        },
        "output_files": {
            "per_case": {"path": per_case_path.as_posix(), "sha256": sha256_file(per_case_path)}
        },
        "runtime": {"cpu_count": os.cpu_count(), "parallel_jobs": 1},
        "warnings": [
            "Only 27-28 in-support events train each outer fold; results are campaign-internal and exploratory.",
            "Raw identities and absolute time are excluded; hand-coded utility categories remain a modeling choice requiring ablation.",
            "Tie-aware Recall@k and midrank reciprocal rank are primary because zero-model scores contain large ties.",
        ],
    }
    summary_path = output_dir / "stage_b_typed_ranker.summary.json"
    summary_path.write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps({"summary": summary_path.as_posix(), "results": result["results"]}, indent=2))
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--baselines", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seeds", type=int, nargs="+", default=[11, 23, 37, 53, 71])
    parser.add_argument("--top-k", type=int, nargs="+", default=[1, 5, 10])
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run(
        args.inputs,
        args.truth,
        args.baselines,
        args.output_dir,
        args.seeds,
        tuple(sorted(set(args.top_k))),
    )


if __name__ == "__main__":
    main()
