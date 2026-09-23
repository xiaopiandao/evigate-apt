#!/usr/bin/env python3
"""Run post-freeze P0 diagnostics for the EviGate-APT study.

The script does not fit or alter a model.  It audits four reviewer-facing
questions from immutable inputs: VM1-to-network address evidence, Stage-B
candidate-pool size effects, naturally overlapping evidence contexts, and the
Stage-A alert-budget frontier produced by ``run_stage_a_baselines.py``.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


CONFIGURED_IP_RE = re.compile(
    r"\bip\s+(?:addr|address)\s+add\s+((?:\d{1,3}\.){3}\d{1,3})(?:/\d+)?\b",
    re.IGNORECASE,
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def mean(values: Iterable[float]) -> float:
    material = list(values)
    return sum(material) / len(material) if material else math.nan


def risk(wrong: int, accepted: int) -> float:
    return wrong / accepted if accepted else math.nan


def size_bin(count: int) -> str:
    if count <= 20:
        return "<=20"
    if count <= 100:
        return "21-100"
    return ">100"


def process_entities(case: dict[str, Any]) -> set[str]:
    graph = case["provenance_candidate_graph"]
    return {
        entity["entity_id"]
        for entity in graph["entities"]
        if entity.get("entity_kind") == "process"
    }


def candidate_size_diagnostic(
    typed_path: Path, baseline_path: Path, output_dir: Path
) -> dict[str, Any]:
    typed_all = [
        row for row in read_csv(typed_path) if row["model"] == "typed_logistic"
    ]
    seeds = sorted({int(row["seed"]) for row in typed_all})
    if not seeds:
        raise ValueError("no typed_logistic rows found")

    primary_seed = seeds[0]
    typed = [row for row in typed_all if int(row["seed"]) == primary_seed]
    random_rows = [
        row
        for row in read_csv(baseline_path)
        if row["baseline"] == "analytic_random_expectation"
    ]
    random_by_case = {row["case_id"]: row for row in random_rows}
    if {row["case_id"] for row in typed} != set(random_by_case):
        raise ValueError("typed and analytic-random case sets differ")

    # Confirm that the five nominal seeds do not change the fitted ranking.
    reference = {
        row["case_id"]: (
            row["midrank_reciprocal"],
            row["hit_at_1"],
            row["hit_at_10"],
            row["top_ranked_entity_id"],
        )
        for row in typed
    }
    seed_invariant = all(
        reference[row["case_id"]]
        == (
            row["midrank_reciprocal"],
            row["hit_at_1"],
            row["hit_at_10"],
            row["top_ranked_entity_id"],
        )
        for row in typed_all
    )

    by_bin: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in typed:
        by_bin[size_bin(int(row["process_candidate_count"]))].append(row)

    bin_rows: list[dict[str, Any]] = []
    for label in ("<=20", "21-100", ">100"):
        material = by_bin[label]
        for method, rows in (
            ("typed_logistic", material),
            (
                "analytic_random_expectation",
                [random_by_case[row["case_id"]] for row in material],
            ),
        ):
            counts = [int(row["process_candidate_count"]) for row in rows]
            truth_present = [row for row in rows if as_bool(row["truth_present"])]
            bin_rows.append(
                {
                    "candidate_bin": label,
                    "method": method,
                    "case_count": len(rows),
                    "truth_present_count": len(truth_present),
                    "candidate_min": min(counts),
                    "candidate_median": statistics.median(counts),
                    "candidate_max": max(counts),
                    "mrr_all_cases": mean(float(row["midrank_reciprocal"]) for row in rows),
                    "recall_at_1_all_cases": mean(float(row["hit_at_1"]) for row in rows),
                    "recall_at_10_all_cases": mean(float(row["hit_at_10"]) for row in rows),
                    "mrr_truth_present": mean(
                        float(row["midrank_reciprocal"]) for row in truth_present
                    ),
                }
            )

    large_rows: list[dict[str, Any]] = []
    for row in typed:
        if int(row["process_candidate_count"]) <= 100:
            continue
        large_rows.append(
            {
                "case_id": row["case_id"],
                "test_fold": int(row["test_fold"]),
                "tactic": row["tactic"],
                "process_candidate_count": int(row["process_candidate_count"]),
                "truth_present": int(as_bool(row["truth_present"])),
                "midrank": float(row["midrank"]) if row["midrank"] else "",
                "midrank_reciprocal": float(row["midrank_reciprocal"]),
                "hit_at_1": float(row["hit_at_1"]),
                "hit_at_10": float(row["hit_at_10"]),
            }
        )
    large_rows.sort(key=lambda row: row["process_candidate_count"])

    counts = [int(row["process_candidate_count"]) for row in typed]
    summary = {
        "analysis_status": "post_freeze_diagnostic",
        "primary_seed": primary_seed,
        "seeds_present": seeds,
        "seed_invariant_rankings": seed_invariant,
        "case_count": len(typed),
        "truth_present_count": sum(as_bool(row["truth_present"]) for row in typed),
        "candidate_pool": {
            "minimum": min(counts),
            "median": statistics.median(counts),
            "mean": mean(counts),
            "maximum": max(counts),
        },
        "interpretation": (
            "The high aggregate retrieval score is concentrated in small candidate graphs; "
            "the >100 stratum exposes one truth-absent case and one 8,924-process failure."
        ),
    }
    write_csv(output_dir / "candidate_size.by_bin.csv", bin_rows)
    write_csv(output_dir / "candidate_size.large_cases.csv", large_rows)
    write_json(output_dir / "candidate_size.summary.json", summary)
    return {"summary": summary, "by_bin": bin_rows, "large_cases": large_rows}


def natural_overlap_diagnostic(
    inputs_path: Path,
    truth_path: Path,
    splits_path: Path,
    bindgate_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    inputs = {case["case_id"]: case for case in read_jsonl(inputs_path)}
    truths = {case["case_id"]: case for case in read_jsonl(truth_path)}
    split = json.loads(splits_path.read_text(encoding="utf-8"))
    cluster_to_case = {case["source_cluster_id"]: case_id for case_id, case in truths.items()}
    case_processes = {case_id: process_entities(case) for case_id, case in inputs.items()}
    case_truth_processes = {
        case_id: set(case["provenance_ground_truth"]["malicious_candidate_entity_ids"])
        for case_id, case in truths.items()
    }

    case_to_group: dict[str, dict[str, Any]] = {}
    pair_rows: list[dict[str, Any]] = []
    overlap_groups = [group for group in split["embargo_groups"] if len(group["cluster_ids"]) > 1]
    for group in split["embargo_groups"]:
        for cluster_id in group["cluster_ids"]:
            case_to_group[cluster_to_case[cluster_id]] = group
    for group in overlap_groups:
        case_ids = [cluster_to_case[cluster] for cluster in group["cluster_ids"]]
        for case_a, case_b in itertools.combinations(case_ids, 2):
            proc_a, proc_b = case_processes[case_a], case_processes[case_b]
            union = proc_a | proc_b
            pair_rows.append(
                {
                    "group_id": group["group_id"],
                    "case_a": case_a,
                    "tactic_a": truths[case_a]["event"]["tactic"],
                    "case_b": case_b,
                    "tactic_b": truths[case_b]["event"]["tactic"],
                    "mixed_tactic": int(len(group["tactics"]) > 1),
                    "process_count_a": len(proc_a),
                    "process_count_b": len(proc_b),
                    "process_jaccard": len(proc_a & proc_b) / len(union) if union else 1.0,
                    "truth_a_present_in_b": int(bool(case_truth_processes[case_a] & proc_b)),
                    "truth_b_present_in_a": int(bool(case_truth_processes[case_b] & proc_a)),
                    "bidirectional_truth_overlap": int(
                        bool(case_truth_processes[case_a] & proc_b)
                        and bool(case_truth_processes[case_b] & proc_a)
                    ),
                }
            )

    clean = [row for row in read_csv(bindgate_path) if row["condition"] == "clean"]
    per_case_rows: list[dict[str, Any]] = []
    for row in clean:
        case_id = row["case_id"]
        group = case_to_group[case_id]
        other_tactics = sorted(
            tactic
            for tactic in group["tactics"]
            if tactic != truths[case_id]["event"]["tactic"]
        )
        if len(group["cluster_ids"]) == 1:
            cohort = "singleton"
        elif len(group["tactics"]) == 1:
            cohort = "overlap_same_tactic"
        else:
            cohort = "overlap_mixed_tactic"
        cascade_wrong = as_bool(row["cascade_attributed"]) and not as_bool(row["cascade_correct"])
        margin_wrong = as_bool(row["matched_margin_attributed"]) and not as_bool(
            row["matched_margin_correct"]
        )
        per_case_rows.append(
            {
                "case_id": case_id,
                "group_id": group["group_id"],
                "cohort": cohort,
                "tactic": truths[case_id]["event"]["tactic"],
                "other_group_tactics": "|".join(other_tactics),
                "evigate_accepted": int(as_bool(row["cascade_attributed"])),
                "evigate_correct": int(as_bool(row["cascade_correct"])),
                "evigate_prediction": row["cascade_prediction"],
                "evigate_foreign_tactic_wrong": int(
                    cascade_wrong and row["cascade_prediction"] in other_tactics
                ),
                "margin_accepted": int(as_bool(row["matched_margin_attributed"])),
                "margin_correct": int(as_bool(row["matched_margin_correct"])),
                "margin_prediction": row["matched_margin_prediction"],
                "margin_foreign_tactic_wrong": int(
                    margin_wrong and row["matched_margin_prediction"] in other_tactics
                ),
            }
        )

    cohort_rows: list[dict[str, Any]] = []
    cohorts = ["singleton", "overlap_same_tactic", "overlap_mixed_tactic", "all_overlap"]
    for cohort in cohorts:
        material = (
            [row for row in per_case_rows if row["cohort"].startswith("overlap_")]
            if cohort == "all_overlap"
            else [row for row in per_case_rows if row["cohort"] == cohort]
        )
        for method, prefix in (("EviGate-Bind", "evigate"), ("matched margin", "margin")):
            accepted = sum(int(row[f"{prefix}_accepted"]) for row in material)
            correct = sum(int(row[f"{prefix}_correct"]) for row in material)
            wrong = accepted - correct
            foreign = sum(int(row[f"{prefix}_foreign_tactic_wrong"]) for row in material)
            cohort_rows.append(
                {
                    "cohort": cohort,
                    "method": method,
                    "event_count": len(material),
                    "accepted": accepted,
                    "correct": correct,
                    "wrong": wrong,
                    "abstained": len(material) - accepted,
                    "coverage": accepted / len(material) if material else math.nan,
                    "selective_risk": risk(wrong, accepted),
                    "foreign_tactic_wrong": foreign,
                }
            )

    jaccards = [float(row["process_jaccard"]) for row in pair_rows]
    summary = {
        "analysis_status": "post_freeze_diagnostic",
        "embargo_group_count": len(split["embargo_groups"]),
        "overlap_group_count": len(overlap_groups),
        "overlap_event_count": sum(len(group["cluster_ids"]) for group in overlap_groups),
        "pair_count": len(pair_rows),
        "median_process_jaccard": statistics.median(jaccards),
        "bidirectional_truth_overlap_pair_count": sum(
            int(row["bidirectional_truth_overlap"]) for row in pair_rows
        ),
        "clean_bindgate_event_count": len(clean),
        "scope_note": (
            "This is a natural-overlap stress test, not host-identity ground truth. "
            "It quantifies performance where embargo grouping shows shared temporal context."
        ),
    }
    write_csv(output_dir / "natural_overlap.pairs.csv", pair_rows)
    write_csv(output_dir / "natural_overlap.per_case.csv", per_case_rows)
    write_csv(output_dir / "natural_overlap.cohorts.csv", cohort_rows)
    write_json(output_dir / "natural_overlap.summary.json", summary)
    return {"summary": summary, "cohorts": cohort_rows, "pairs": pair_rows}


def extract_configured_ips(provenance_path: Path) -> dict[str, dict[str, Any]]:
    evidence: dict[str, dict[str, Any]] = {}
    with provenance_path.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            command = (row.get("command line") or "").strip()
            match = CONFIGURED_IP_RE.search(command)
            if not match:
                continue
            ip = match.group(1)
            timestamp = row.get("time") or row.get("seen time") or row.get("start time") or ""
            item = evidence.setdefault(
                ip,
                {"command_count": 0, "first_timestamp": None, "example_command": command},
            )
            item["command_count"] += 1
            if timestamp:
                value = float(timestamp)
                if item["first_timestamp"] is None or value < item["first_timestamp"]:
                    item["first_timestamp"] = value
                    item["example_command"] = command
    return evidence


def scan_network_windows(
    network_path: Path,
    case_windows: dict[int, list[str]],
    configured_ips: set[str],
) -> tuple[dict[str, Counter[str]], Counter[str], dict[str, Any]]:
    case_counts = {case_id: Counter() for ids in case_windows.values() for case_id in ids}
    global_counts: Counter[str] = Counter()
    rows_scanned = 0
    parse_errors = 0
    with network_path.open("rb", buffering=16 * 1024 * 1024) as handle:
        header = handle.readline()
        if not header.lower().startswith(b"ts,"):
            raise ValueError("unexpected network CSV header")
        for line in handle:
            rows_scanned += 1
            parts = line.split(b",", 5)
            if len(parts) < 5:
                parse_errors += 1
                continue
            try:
                timestamp = float(parts[0].strip(b'"'))
            except ValueError:
                parse_errors += 1
                continue
            source = parts[3].strip().strip(b'"').decode("ascii", errors="replace")
            destination = parts[4].strip().strip(b'"').decode("ascii", errors="replace")
            if source in configured_ips:
                global_counts["configured_source_rows"] += 1
                global_counts[f"ip:{source}"] += 1
            if destination in configured_ips:
                global_counts["configured_destination_rows"] += 1
                global_counts[f"ip:{destination}"] += 1
            if source in configured_ips or destination in configured_ips:
                global_counts["configured_endpoint_rows"] += 1
            window_start = math.floor(timestamp / 60) * 60
            case_ids = case_windows.get(window_start)
            if not case_ids:
                continue
            for case_id in case_ids:
                counts = case_counts[case_id]
                counts["window_rows"] += 1
                if source in configured_ips:
                    counts["configured_source_rows"] += 1
                    counts[f"ip:{source}"] += 1
                if destination in configured_ips:
                    counts["configured_destination_rows"] += 1
                    counts[f"ip:{destination}"] += 1
                if source in configured_ips or destination in configured_ips:
                    counts["configured_endpoint_rows"] += 1
    return case_counts, global_counts, {
        "rows_scanned": rows_scanned,
        "parse_errors": parse_errors,
    }


def vm1_ip_diagnostic(
    inputs_path: Path,
    truth_path: Path,
    provenance_path: Path,
    network_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    inputs = {case["case_id"]: case for case in read_jsonl(inputs_path)}
    truths = {case["case_id"]: case for case in read_jsonl(truth_path)}
    configured = extract_configured_ips(provenance_path)
    configured_ips = set(configured)
    if not configured_ips:
        raise ValueError("no VM1 configured-IP commands found")

    case_windows: dict[int, list[str]] = defaultdict(list)
    for case_id, truth in truths.items():
        anchor = float(truth["anchor_selection"]["timestamp_epoch"])
        case_windows[math.floor(anchor / 60) * 60].append(case_id)
    counts_by_case, global_counts, scan = scan_network_windows(
        network_path, case_windows, configured_ips
    )

    per_case: list[dict[str, Any]] = []
    for case_id, truth in truths.items():
        counts = counts_by_case[case_id]
        top_ips = {
            str(item["value"])
            for field in ("top_source_ips", "top_destination_ips")
            for item in inputs[case_id]["network_alert"][field]
        }
        expected_rows = int(inputs[case_id]["network_alert"]["row_count"])
        matched_ips = sorted(
            key.removeprefix("ip:") for key in counts if key.startswith("ip:")
        )
        per_case.append(
            {
                "case_id": case_id,
                "tactic": truth["event"]["tactic"],
                "window_start_epoch": math.floor(
                    float(truth["anchor_selection"]["timestamp_epoch"]) / 60
                )
                * 60,
                "expected_network_rows": expected_rows,
                "scanned_network_rows": counts["window_rows"],
                "row_count_matches_builder": int(expected_rows == counts["window_rows"]),
                "configured_endpoint_rows": counts["configured_endpoint_rows"],
                "configured_source_rows": counts["configured_source_rows"],
                "configured_destination_rows": counts["configured_destination_rows"],
                "configured_ip_present": int(counts["configured_endpoint_rows"] > 0),
                "matched_configured_ips": "|".join(matched_ips),
                "configured_ip_in_top5_summary": int(bool(top_ips & configured_ips)),
            }
        )
    per_case.sort(key=lambda row: (row["window_start_epoch"], row["case_id"]))

    address_rows = [
        {
            "configured_ip": ip,
            "command_count": item["command_count"],
            "first_timestamp": item["first_timestamp"],
            "example_command": item["example_command"],
            "event_window_count": sum(
                ip in row["matched_configured_ips"].split("|") for row in per_case
            ),
            "global_network_row_count": global_counts[f"ip:{ip}"],
        }
        for ip, item in sorted(configured.items())
    ]
    hit_count = sum(int(row["configured_ip_present"]) for row in per_case)
    summary = {
        "analysis_status": "post_freeze_diagnostic",
        "configured_ips_from_vm1_provenance": sorted(configured_ips),
        "case_count": len(per_case),
        "case_count_with_configured_endpoint": hit_count,
        "case_fraction_with_configured_endpoint": hit_count / len(per_case),
        "case_count_with_configured_endpoint_in_top5_summary": sum(
            int(row["configured_ip_in_top5_summary"]) for row in per_case
        ),
        "global_network_rows_with_configured_endpoint": global_counts[
            "configured_endpoint_rows"
        ],
        "global_network_rows_with_configured_source": global_counts[
            "configured_source_rows"
        ],
        "global_network_rows_with_configured_destination": global_counts[
            "configured_destination_rows"
        ],
        "row_count_validation_failures": sum(
            not int(row["row_count_matches_builder"]) for row in per_case
        ),
        **scan,
        "interpretation": (
            "A hit is a data-internal IP-to-host argument: the exact network window contains "
            "an address configured by an 'ip addr add' command in the single provenance host. "
            "It is not an externally documented host-ID mapping and cannot prove incident membership."
        ),
    }
    write_csv(output_dir / "vm1_ip.addresses.csv", address_rows)
    write_csv(output_dir / "vm1_ip.per_case.csv", per_case)
    write_json(output_dir / "vm1_ip.summary.json", summary)
    return {"summary": summary, "per_case": per_case, "addresses": address_rows}


def stage_a_frontier_diagnostic(summary_path: Path, output_dir: Path) -> dict[str, Any]:
    source = json.loads(summary_path.read_text(encoding="utf-8"))
    aggregate = source["aggregate"]["hist_gradient_boosting"]
    rows: list[dict[str, Any]] = []
    for budget_text, result in sorted(aggregate.items(), key=lambda item: float(item[0])):
        metrics = result["metrics"]
        rows.append(
            {
                "requested_false_alert_budget_per_hour": float(budget_text),
                "observed_phase2_false_alerts_per_hour": metrics["false_alerts_per_hour"][
                    "mean_of_fold_means"
                ],
                "observed_phase2_false_alerts_per_hour_sd": metrics["false_alerts_per_hour"][
                    "sample_std_across_fold_means"
                ],
                "window_recall": metrics["window_recall"]["mean_of_fold_means"],
                "all_event_coverage": metrics["all_event_coverage"]["mean_of_fold_means"],
                "all_event_coverage_sd": metrics["all_event_coverage"][
                    "sample_std_across_fold_means"
                ],
                "in_support_event_coverage": metrics["in_support_event_coverage"][
                    "mean_of_fold_means"
                ],
                "benign_stress_false_alerts_per_hour": metrics[
                    "benign_stress_false_alerts_per_hour"
                ]["mean_of_fold_means"],
            }
        )
    diagnostic = {
        "analysis_status": "post_freeze_diagnostic",
        "model": "hist_gradient_boosting",
        "threshold_policy": source["threshold_policy"],
        "frontier": rows,
        "scope_note": (
            "The requested budget constrains calibration folds. Observed Phase-2 and Phase-1 "
            "rates are held-out outcomes, not forced to equal the budget."
        ),
    }
    write_csv(output_dir / "stage_a_budget_frontier.csv", rows)
    write_json(output_dir / "stage_a_budget_frontier.json", diagnostic)
    return diagnostic


def row_for(rows: list[dict[str, Any]], **conditions: Any) -> dict[str, Any]:
    return next(row for row in rows if all(row[key] == value for key, value in conditions.items()))


def build_report(
    output_dir: Path,
    vm1: dict[str, Any],
    candidate: dict[str, Any],
    overlap: dict[str, Any],
    frontier: dict[str, Any],
) -> Path:
    candidate_rows = candidate["by_bin"]
    overlap_rows = overlap["cohorts"]
    lines = [
        "# P0 post-freeze diagnostic report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "All four analyses are diagnostic and post-freeze. No model, split, or frozen threshold was changed.",
        "",
        "## 1. VM1 address-to-network audit",
        "",
        f"The provenance stream contains explicit address-configuration commands for {len(vm1['summary']['configured_ips_from_vm1_provenance'])} addresses. "
        f"Exact raw-window scanning finds at least one configured address in {vm1['summary']['case_count_with_configured_endpoint']}/{vm1['summary']['case_count']} event windows "
        f"({vm1['summary']['case_fraction_with_configured_endpoint']:.1%}); across the full network file, {vm1['summary']['global_network_rows_with_configured_endpoint']} rows contain one of those addresses. "
        "Consequently, the available files do not establish an event-level VM1-to-IP link. The host-membership limitation remains unresolved.",
        "",
        "## 2. Candidate-pool size stratification",
        "",
        "| Candidate processes | Cases | Typed MRR | Typed R@1 | Typed R@10 | Random MRR | Random R@1 | Random R@10 |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for label in ("<=20", "21-100", ">100"):
        typed = row_for(candidate_rows, candidate_bin=label, method="typed_logistic")
        random = row_for(
            candidate_rows, candidate_bin=label, method="analytic_random_expectation"
        )
        lines.append(
            f"| {label} | {typed['case_count']} | {typed['mrr_all_cases']:.3f} | "
            f"{typed['recall_at_1_all_cases']:.3f} | {typed['recall_at_10_all_cases']:.3f} | "
            f"{random['mrr_all_cases']:.3f} | {random['recall_at_1_all_cases']:.3f} | "
            f"{random['recall_at_10_all_cases']:.3f} |"
        )
    lines.extend(
        [
            "",
            "The aggregate retrieval headline is therefore partly a small-candidate-pool result. The learned ranker remains much better than random in the >100 stratum, but this stratum includes the truth-absent 5,119-process case and the 8,924-process failure.",
            "",
            "## 3. Natural-overlap contexts",
            "",
            f"There are {overlap['summary']['overlap_group_count']} multi-event embargo groups ({overlap['summary']['overlap_event_count']} events). "
            f"Across {overlap['summary']['pair_count']} event pairs, median process-set Jaccard is {overlap['summary']['median_process_jaccard']:.3f}, and both events' truth processes occur in the other event's graph for {overlap['summary']['bidirectional_truth_overlap_pair_count']} pairs.",
            "",
            "| Cohort | Method | N | Accepted | Correct | Wrong | Risk | Foreign-tactic wrong |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for cohort in ("singleton", "overlap_same_tactic", "overlap_mixed_tactic", "all_overlap"):
        for method in ("EviGate-Bind", "matched margin"):
            row = row_for(overlap_rows, cohort=cohort, method=method)
            lines.append(
                f"| {cohort} | {method} | {row['event_count']} | {row['accepted']} | "
                f"{row['correct']} | {row['wrong']} | {row['selective_risk']:.3f} | "
                f"{row['foreign_tactic_wrong']} |"
            )
    lines.extend(
        [
            "",
            "This uses naturally overlapping collection contexts rather than injected donor packages. It is still a stress test, not direct host-membership ground truth.",
            "",
            "## 4. Stage-A alert-budget frontier",
            "",
            "| Requested FA/h | Observed Phase-2 FA/h | Window recall | Event coverage | In-support coverage | Phase-1 stress FA/h |",
            "|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in frontier["frontier"]:
        lines.append(
            f"| {row['requested_false_alert_budget_per_hour']:.1f} | "
            f"{row['observed_phase2_false_alerts_per_hour']:.3f} | {row['window_recall']:.3f} | "
            f"{row['all_event_coverage']:.3f} | {row['in_support_event_coverage']:.3f} | "
            f"{row['benign_stress_false_alerts_per_hour']:.3f} |"
        )
    lines.extend(
        [
            "",
            "The frontier is a deployment trade-off, not a new tuned operating point. Each threshold is selected only on its calibration fold under the requested budget.",
            "",
            "## Manuscript decision",
            "",
            "The candidate-size result and natural-overlap result should be reported because they directly answer reviewer objections. The VM1 audit does not recover the missing host-ID map, so the manuscript must narrow the binding claim and retain this limitation. The budget frontier is suitable for the supplement unless it materially improves the operational story.",
            "",
        ]
    )
    report_path = output_dir / "P0_DIAGNOSTIC_REPORT.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path("data/derived/p0_diagnostics"))
    parser.add_argument(
        "--inputs", type=Path, default=Path("data/derived/evigate_phase2_evidence/cases.inputs.jsonl")
    )
    parser.add_argument(
        "--truth", type=Path, default=Path("data/derived/evigate_phase2_evidence/cases.truth.jsonl")
    )
    parser.add_argument(
        "--splits", type=Path, default=Path("data/derived/cicapt_phase2_grouped_splits.json")
    )
    parser.add_argument(
        "--typed-results",
        type=Path,
        default=Path("data/derived/stage_b/typed_ranker_run/stage_b_typed_ranker.per_case.csv"),
    )
    parser.add_argument(
        "--retrieval-baselines",
        type=Path,
        default=Path("data/derived/stage_b/baseline_run/stage_b_retrieval_baselines.per_case.csv"),
    )
    parser.add_argument(
        "--bindgate-results",
        type=Path,
        default=Path(
            "data/derived/evigate_llm/v7_bindgate/evaluation_repro/evigate_bindgate.per_case.csv"
        ),
    )
    parser.add_argument(
        "--provenance", type=Path, default=Path("data/raw/cicapt/Phase2_Provenance.csv")
    )
    parser.add_argument(
        "--network", type=Path, default=Path("data/raw/cicapt/network/phase2_NetworkData.csv")
    )
    parser.add_argument(
        "--stage-a-summary",
        type=Path,
        default=Path("data/derived/p0_diagnostics/stage_a_frontier_run/stage_a_summary.json"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    vm1 = vm1_ip_diagnostic(
        args.inputs, args.truth, args.provenance, args.network, args.output_dir
    )
    candidate = candidate_size_diagnostic(
        args.typed_results, args.retrieval_baselines, args.output_dir
    )
    overlap = natural_overlap_diagnostic(
        args.inputs, args.truth, args.splits, args.bindgate_results, args.output_dir
    )
    frontier = stage_a_frontier_diagnostic(args.stage_a_summary, args.output_dir)
    report_path = build_report(args.output_dir, vm1, candidate, overlap, frontier)

    inputs = {
        "cases_inputs": args.inputs,
        "cases_truth": args.truth,
        "grouped_splits": args.splits,
        "typed_results": args.typed_results,
        "retrieval_baselines": args.retrieval_baselines,
        "bindgate_results": args.bindgate_results,
        "provenance": args.provenance,
        "network": args.network,
        "stage_a_summary": args.stage_a_summary,
    }
    outputs = sorted(
        path for path in args.output_dir.iterdir() if path.is_file() and path.name != "manifest.json"
    )
    manifest = {
        "schema_version": "1.0",
        "analysis_status": "post_freeze_diagnostic",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "script": str(Path(__file__).as_posix()),
        "inputs": {
            name: {"path": str(path.as_posix()), "sha256": sha256_file(path)}
            for name, path in inputs.items()
        },
        "outputs": {
            path.name: {"path": str(path.as_posix()), "sha256": sha256_file(path)}
            for path in outputs
        },
        "report": str(report_path.as_posix()),
    }
    write_json(args.output_dir / "manifest.json", manifest)
    print(
        json.dumps(
            {
                "report": str(report_path),
                "vm1_cases_with_configured_endpoint": vm1["summary"][
                    "case_count_with_configured_endpoint"
                ],
                "candidate_case_count": candidate["summary"]["case_count"],
                "overlap_group_count": overlap["summary"]["overlap_group_count"],
                "frontier_points": len(frontier["frontier"]),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
