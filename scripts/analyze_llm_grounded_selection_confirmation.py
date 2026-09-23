#!/usr/bin/env python3
"""Analyze the frozen grounded support-process selection confirmation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

from evigate_llm_contract import TACTICS, process_reference_index, response_decision


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def sha256_file(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def output_selection(output: dict[str, Any], evidence: dict[str, Any]) -> str | None:
    response = output.get("parsed_response")
    if not isinstance(response, dict):
        return None
    reference = response.get("support_process_ref")
    if not isinstance(reference, str):
        return None
    return process_reference_index(evidence).get(reference)


def llm_row(
    method: str,
    output: dict[str, Any],
    evidence: dict[str, Any],
    truth: dict[str, Any],
    verifier_controls_issuance: bool,
) -> dict[str, Any]:
    response = output.get("parsed_response")
    raw_accepted = bool(
        isinstance(response, dict)
        and response_decision(response) == "attribute"
        and response.get("tactic") in TACTICS
    )
    contract_valid = bool(output.get("verification", {}).get("contract_valid", False))
    accepted = bool(raw_accepted and (contract_valid if verifier_controls_issuance else True))
    prediction = str(response["tactic"]) if raw_accepted else None
    selected_entity = output_selection(output, evidence)
    foreign_entity = truth.get("mutation_metadata", {}).get("foreign_entity_id")
    foreign_citation = bool(raw_accepted and foreign_entity and selected_entity == foreign_entity)
    grounded = bool(
        accepted
        and prediction == truth["tactic"]
        and contract_valid
        and not foreign_citation
        and selected_entity is not None
    )
    return {
        "model": str(output.get("model", "")),
        "method": method,
        "sample_id": truth["sample_id"],
        "case_id": truth["case_id"],
        "condition": truth["condition"],
        "proposal_correct": int(bool(truth["proposal_correct"])),
        "truth_tactic": truth["tactic"],
        "prediction": prediction or "",
        "selected_entity": selected_entity or "",
        "raw_accepted": int(raw_accepted),
        "accepted": int(accepted),
        "contract_valid": int(contract_valid),
        "foreign_citation": int(foreign_citation),
        "grounded_selection": int(grounded),
    }


def extractor_row(evidence: dict[str, Any], truth: dict[str, Any], model: str) -> dict[str, Any]:
    candidates = evidence.get("ranked_process_candidates", [])
    accepted = bool(candidates and candidates[0].get("anchors"))
    selected = str(candidates[0]["entity_id"]) if accepted else None
    prediction = evidence.get("machine_proposal", {}).get("tactic") if accepted else None
    foreign = bool(
        accepted
        and selected == truth.get("mutation_metadata", {}).get("foreign_entity_id")
    )
    grounded = bool(accepted and prediction == truth["tactic"] and not foreign)
    return {
        "model": model,
        "method": "top_p1_extractor",
        "sample_id": truth["sample_id"],
        "case_id": truth["case_id"],
        "condition": truth["condition"],
        "proposal_correct": int(bool(truth["proposal_correct"])),
        "truth_tactic": truth["tactic"],
        "prediction": prediction or "",
        "selected_entity": selected or "",
        "raw_accepted": int(accepted),
        "accepted": int(accepted),
        "contract_valid": int(accepted),
        "foreign_citation": int(foreign),
        "grounded_selection": int(grounded),
    }


def build_rows(
    outputs: list[dict[str, Any]],
    evidence: dict[str, dict[str, Any]],
    truth: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for row in outputs:
        key = (str(row["variant"]), str(row["sample_id"]))
        if key in by_key:
            raise ValueError(f"duplicate output: {key}")
        by_key[key] = row
    expected = {(variant, sid) for variant in ("direct", "contracted") for sid in truth}
    if set(by_key) != expected:
        raise ValueError(
            f"coverage mismatch missing={len(expected-set(by_key))} extra={len(set(by_key)-expected)}"
        )
    rows = []
    for sid, truth_row in sorted(truth.items()):
        evidence_row = evidence[sid]
        rows.append(llm_row("direct_llm", by_key[("direct", sid)], evidence_row, truth_row, False))
        rows.append(
            llm_row(
                "proposal_locked_verified",
                by_key[("contracted", sid)],
                evidence_row,
                truth_row,
                True,
            )
        )
    model = str(outputs[0].get("model", "")) if outputs else ""
    rows.extend(
        extractor_row(evidence[sid], truth_row, model)
        for sid, truth_row in sorted(truth.items())
    )
    return rows


def subset(
    rows: list[dict[str, Any]], method: str, condition: str
) -> list[dict[str, Any]]:
    return [
        row
        for row in rows
        if row["method"] == method
        and row["condition"] == condition
        and row["proposal_correct"] == 1
    ]


def paired_effect(
    rows: list[dict[str, Any]],
    method_a: str,
    method_b: str,
    condition: str,
    field: str,
    seed: int,
    iterations: int,
) -> dict[str, Any]:
    a = {row["case_id"]: float(row[field]) for row in subset(rows, method_a, condition)}
    b = {row["case_id"]: float(row[field]) for row in subset(rows, method_b, condition)}
    cases = sorted(set(a) & set(b))
    differences = [a[case] - b[case] for case in cases]
    rng = random.Random(seed)
    boot = [
        mean(differences[rng.randrange(len(differences))] for _ in cases)
        for _ in range(iterations)
    ]
    boot.sort()
    return {
        "events": len(cases),
        "effect_a_minus_b": mean(differences),
        "bootstrap_95_ci": [
            boot[int(0.025 * iterations)],
            boot[min(iterations - 1, int(0.975 * iterations))],
        ],
        "bootstrap_iterations": iterations,
        "seed": seed,
    }


def rate(rows: list[dict[str, Any]], method: str, condition: str, field: str) -> float:
    values = subset(rows, method, condition)
    return mean(float(row[field]) for row in values)


def paired_control_agreement(rows: list[dict[str, Any]], method: str) -> float:
    grouped: dict[str, dict[str, tuple[Any, ...]]] = defaultdict(dict)
    for row in rows:
        if row["method"] != method or row["proposal_correct"] != 1:
            continue
        if row["condition"] not in {"clean", "opaque_anchor_control"}:
            continue
        grouped[row["case_id"]][row["condition"]] = (
            row["accepted"],
            row["prediction"],
            row["selected_entity"],
        )
    pairs = [pair for pair in grouped.values() if len(pair) == 2]
    return mean(int(pair["clean"] == pair["opaque_anchor_control"]) for pair in pairs)


def metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result = {}
    for method in sorted({row["method"] for row in rows}):
        result[method] = {}
        for condition in sorted({row["condition"] for row in rows}):
            group = subset(rows, method, condition)
            result[method][condition] = {
                "proposal_correct_events": len(group),
                "accepted": sum(row["accepted"] for row in group),
                "contract_valid": sum(row["contract_valid"] for row in group),
                "foreign_citations": sum(row["foreign_citation"] for row in group),
                "grounded_selections": sum(row["grounded_selection"] for row in group),
                "acceptance_rate": mean(row["accepted"] for row in group),
                "foreign_citation_rate": mean(row["foreign_citation"] for row in group),
                "grounded_selection_rate": mean(row["grounded_selection"] for row in group),
            }
    return result


def analyze(
    outputs_path: Path,
    evidence: dict[str, dict[str, Any]],
    truth: dict[str, dict[str, Any]],
    seed: int,
    iterations: int,
    primary: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    outputs = load_jsonl(outputs_path)
    rows = build_rows(outputs, evidence, truth)
    h1 = paired_effect(
        rows,
        "proposal_locked_verified",
        "direct_llm",
        "foreign_distractor_holdout",
        "grounded_selection",
        seed,
        iterations,
    )
    h2 = paired_effect(
        rows,
        "proposal_locked_verified",
        "top_p1_extractor",
        "foreign_distractor_holdout",
        "grounded_selection",
        seed + 1,
        iterations,
    )
    clean_grounded = rate(rows, "proposal_locked_verified", "clean", "grounded_selection")
    foreign_grounded = rate(
        rows, "proposal_locked_verified", "foreign_distractor_holdout", "grounded_selection"
    )
    foreign_citation = rate(
        rows, "proposal_locked_verified", "foreign_distractor_holdout", "foreign_citation"
    )
    control_grounded = rate(
        rows, "proposal_locked_verified", "opaque_anchor_control", "grounded_selection"
    )
    control_agreement = paired_control_agreement(rows, "proposal_locked_verified")
    rules = {
        "h_sel_1": {
            **h1,
            "thresholds": {"point_min": 0.15, "ci_lower_min_exclusive": 0.05},
            "pass": bool(h1["effect_a_minus_b"] >= 0.15 and h1["bootstrap_95_ci"][0] > 0.05),
        },
        "h_sel_2": {
            **h2,
            "thresholds": {"point_min": 0.25, "ci_lower_min_exclusive": 0.15},
            "pass": bool(h2["effect_a_minus_b"] >= 0.25 and h2["bootstrap_95_ci"][0] > 0.15),
        },
        "h_sel_3": {
            "foreign_citation_rate": foreign_citation,
            "clean_grounded_selection_rate": clean_grounded,
            "foreign_grounded_selection_rate": foreign_grounded,
            "foreign_minus_clean": foreign_grounded - clean_grounded,
            "thresholds": {"foreign_citation_max": 0.10, "foreign_minus_clean_min": -0.05},
            "pass": bool(foreign_citation <= 0.10 and foreign_grounded - clean_grounded >= -0.05),
        },
        "h_sel_4": {
            "paired_full_decision_agreement": control_agreement,
            "clean_grounded_selection_rate": clean_grounded,
            "opaque_grounded_selection_rate": control_grounded,
            "opaque_minus_clean": control_grounded - clean_grounded,
            "thresholds": {"agreement_min": 0.90, "absolute_rate_change_max": 0.05},
            "pass": bool(control_agreement >= 0.90 and abs(control_grounded - clean_grounded) <= 0.05),
        },
    }
    rules["confirmation_positive"] = bool(all(rules[key]["pass"] for key in ("h_sel_1", "h_sel_2", "h_sel_3", "h_sel_4")))
    return rows, {
        "role": "primary" if primary else "sensitivity",
        "model": str(outputs[0].get("model", "")) if outputs else "",
        "outputs": {"path": str(outputs_path), "sha256": sha256_file(outputs_path)},
        "metrics": metrics(rows),
        "frozen_rules": rules,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def run(args: argparse.Namespace) -> dict[str, Any]:
    evidence = {row["sample_id"]: row for row in load_jsonl(args.inputs)}
    truth = {row["sample_id"]: row for row in load_jsonl(args.truth)}
    if set(evidence) != set(truth):
        raise ValueError("evidence/truth sample mismatch")
    primary_rows, primary = analyze(
        args.primary_outputs, evidence, truth, args.seed, args.bootstrap_iterations, True
    )
    sensitivity_rows, sensitivity = analyze(
        args.sensitivity_outputs,
        evidence,
        truth,
        args.seed + 100,
        args.bootstrap_iterations,
        False,
    )
    write_csv(args.per_case_output, primary_rows + sensitivity_rows)
    result = {
        "schema_version": "1.0",
        "study": "Held-out grounded support-process selection confirmation",
        "protocol": {"path": str(args.protocol), "sha256": sha256_file(args.protocol)},
        "inputs": {"path": str(args.inputs), "sha256": sha256_file(args.inputs)},
        "truth": {"path": str(args.truth), "sha256": sha256_file(args.truth)},
        "seed": args.seed,
        "bootstrap_iterations": args.bootstrap_iterations,
        "primary": primary,
        "sensitivity": sensitivity,
        "per_case": {"path": str(args.per_case_output), "sha256": sha256_file(args.per_case_output)},
    }
    args.summary_output.parent.mkdir(parents=True, exist_ok=True)
    args.summary_output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--primary-outputs", type=Path, required=True)
    parser.add_argument("--sensitivity-outputs", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--per-case-output", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=20260921)
    parser.add_argument("--bootstrap-iterations", type=int, default=10000)
    return parser.parse_args()


if __name__ == "__main__":
    print(json.dumps(run(parse_args()), ensure_ascii=False, indent=2, sort_keys=True))

