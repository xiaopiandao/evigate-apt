#!/usr/bin/env python3
"""Evaluate LLM variants and the existing posterior-margin baseline."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

from sklearn.metrics import f1_score

from evigate_llm_contract import TACTICS, response_decision


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def method_decision(output: dict[str, Any], method: str) -> tuple[bool, str | None]:
    response = output.get("parsed_response")
    if not isinstance(response, dict):
        return False, None
    raw_attribute = response_decision(response) == "attribute" and response.get("tactic") in TACTICS
    if method.startswith("evigate_llm"):
        accepted = raw_attribute and bool(output.get("verification", {}).get("contract_valid"))
        return accepted, str(response["tactic"]) if accepted else None
    return raw_attribute, str(response["tactic"]) if raw_attribute else None


def response_confidence(output: dict[str, Any]) -> float | None:
    response = output.get("parsed_response")
    if not isinstance(response, dict):
        return None
    value = response.get("confidence")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if 0.0 <= value <= 1.0 else None


def calibration_thresholds(
    outputs: list[dict[str, Any]],
    truth_map: dict[str, dict[str, Any]],
    target_coverage: float,
) -> tuple[dict[tuple[str, int], float | None], dict[str, Any]]:
    by_key = {(row["variant"], row["sample_id"]): row for row in outputs}
    method_variants = {
        "direct_llm": "direct",
        "self_abstaining_llm": "self_abstain",
        "evigate_llm": "contracted",
    }
    thresholds: dict[tuple[str, int], float | None] = {}
    audit: dict[str, Any] = {}
    for method, variant in method_variants.items():
        audit[method] = {}
        for fold in (1, 2, 3):
            fold_truth = [row for row in truth_map.values() if int(row["test_fold"]) == fold]
            eligible_scores: list[float] = []
            for truth in fold_truth:
                output = by_key.get((variant, truth["sample_id"]))
                if output is None:
                    continue
                eligible, _ = method_decision(output, method)
                confidence = response_confidence(output)
                if eligible and confidence is not None:
                    eligible_scores.append(confidence)
            desired = max(1, int(round(target_coverage * len(fold_truth))))
            if len(eligible_scores) < desired:
                threshold = None
                realized = len(eligible_scores)
            else:
                threshold = sorted(eligible_scores, reverse=True)[desired - 1]
                realized = sum(score >= threshold for score in eligible_scores)
            thresholds[(method, fold)] = threshold
            audit[method][str(fold)] = {
                "calibration_events": len(fold_truth),
                "eligible_attributions": len(eligible_scores),
                "target_accepted": desired,
                "threshold": threshold,
                "realized_accepted": realized,
                "realized_coverage": realized / len(fold_truth) if fold_truth else None,
                "target_unattainable": len(eligible_scores) < desired,
            }
    return thresholds, audit


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {"events": 0}
    attributed = [row for row in rows if row["attributed"]]
    y_true = [row["tactic"] for row in rows]
    y_pred = [row["prediction"] or "__abstain__" for row in rows]
    return {
        "events": len(rows),
        "coverage": len(attributed) / len(rows),
        "rejection_rate": 1.0 - len(attributed) / len(rows),
        "unconditional_accuracy": mean(int(row["correct"]) for row in rows),
        "macro_f1": float(
            f1_score(
                y_true,
                y_pred,
                labels=sorted(TACTICS),
                average="macro",
                zero_division=0,
            )
        ),
        "selective_risk": (
            mean(int(not row["correct"]) for row in attributed) if attributed else None
        ),
        "wrong_label_rate": mean(
            int(row["attributed"] and not row["correct"]) for row in rows
        ),
        "parseable_json_rate": mean(int(row["parseable"]) for row in rows),
        "contract_valid_rate": mean(int(row["contract_valid"]) for row in rows),
        "unsupported_label_rate": mean(int(row["unsupported_label"]) for row in rows),
        "hallucinated_entity_record_rate": mean(
            int(row["hallucinated_entity"]) for row in rows
        ),
        "hallucinated_anchor_record_rate": mean(
            int(row["hallucinated_anchor"]) for row in rows
        ),
        "integrity_alarm_rate": mean(int(row["integrity_alarm"]) for row in rows),
    }


def llm_rows(
    outputs: list[dict[str, Any]],
    truth_map: dict[str, dict[str, Any]],
    thresholds: dict[tuple[str, int], float | None] | None = None,
) -> list[dict[str, Any]]:
    result = []
    method_variants = {
        "direct_llm_raw": "direct",
        "self_abstaining_llm_raw": "self_abstain",
        "contracted_raw": "contracted",
        "evigate_llm_raw": "contracted",
    }
    if thresholds is not None:
        method_variants.update(
            {
                "direct_llm": "direct",
                "self_abstaining_llm": "self_abstain",
                "evigate_llm": "contracted",
            }
        )
    by_key = {(row["variant"], row["sample_id"]): row for row in outputs}
    for method, variant in method_variants.items():
        for sample, truth in sorted(truth_map.items()):
            output = by_key.get((variant, sample))
            if output is None:
                continue
            attributed, prediction = method_decision(output, method)
            confidence = response_confidence(output)
            if thresholds is not None and not method.endswith("_raw") and method != "contracted_raw":
                threshold = thresholds[(method, int(truth["test_fold"]))]
                passes_threshold = threshold is None or (
                    confidence is not None and confidence >= threshold
                )
                attributed = bool(attributed and passes_threshold)
                prediction = prediction if attributed else None
            response = output.get("parsed_response")
            verification = output.get("verification", {})
            attempted = isinstance(response, dict) and response_decision(response) == "attribute"
            result.append(
                {
                    "method": method,
                    "variant": variant,
                    "sample_id": sample,
                    "case_id": truth["case_id"],
                    "test_fold": truth["test_fold"],
                    "condition": truth["condition"],
                    "corruption_family": truth.get("corruption_family") or "clean",
                    "tactic": truth["tactic"],
                    "prediction": prediction,
                    "confidence": confidence,
                    "attributed": attributed,
                    "correct": bool(attributed and prediction == truth["tactic"]),
                    "parseable": isinstance(response, dict),
                    "contract_valid": bool(verification.get("contract_valid")),
                    "unsupported_label": bool(
                        attempted and not verification.get("contract_valid", False)
                    ),
                    "hallucinated_entity": bool(
                        verification.get("hallucinated_entity_ids", [])
                    ),
                    "hallucinated_anchor": bool(
                        verification.get("hallucinated_anchor_ids", [])
                    ),
                    "integrity_alarm": bool(
                        verification.get("verifier_integrity_alarm", False)
                        if method.startswith("evigate_llm")
                        else (
                            response.get("integrity_alarm", False)
                            if isinstance(response, dict)
                            else False
                        )
                    ),
                }
            )
    return result


def margin_rows(clean_path: Path, corruption_path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in load_csv(clean_path):
        accepted = bool(int(row["fixed_coverage_margin_accept"]))
        rows.append(
            {
                "method": "posterior_margin",
                "variant": "existing_stage_c",
                "sample_id": "",
                "case_id": row["case_id"],
                "test_fold": int(row["test_fold"]),
                "condition": "clean",
                "corruption_family": "clean",
                "tactic": row["tactic"],
                "prediction": row["prediction"] if accepted else None,
                "confidence": float(row["margin_score"]),
                "attributed": accepted,
                "correct": bool(accepted and int(row["correct"])),
                "parseable": True,
                "contract_valid": True,
                "unsupported_label": False,
                "hallucinated_entity": False,
                "hallucinated_anchor": False,
                "integrity_alarm": False,
            }
        )
    for row in load_csv(corruption_path):
        accepted = not bool(int(row["margin_reject"]))
        rows.append(
            {
                "method": "posterior_margin",
                "variant": "existing_stage_c",
                "sample_id": "",
                "case_id": row["case_id"],
                "test_fold": int(row["test_fold"]),
                "condition": "corrupted",
                "corruption_family": row["corruption_family"],
                "tactic": row["tactic"],
                "prediction": row["prediction"] if accepted else None,
                "confidence": float(row["margin_score"]),
                "attributed": accepted,
                "correct": bool(accepted and int(row["correct"])),
                "parseable": True,
                "contract_valid": True,
                "unsupported_label": False,
                "hallucinated_entity": False,
                "hallucinated_anchor": False,
                "integrity_alarm": False,
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def prospective_hypotheses(methods: dict[str, Any]) -> dict[str, Any] | None:
    """Evaluate only the criteria frozen in the prospective protocol."""
    evigate = methods.get("evigate_llm")
    self_method = methods.get("self_abstaining_llm")
    if not isinstance(evigate, dict) or not isinstance(self_method, dict):
        return None
    evigate_macro = evigate.get("corruption_macro", {})
    self_macro = self_method.get("corruption_macro", {})
    evigate_clean = evigate.get("clean", {})
    self_clean = self_method.get("clean", {})
    values = {
        "evigate_wrong": evigate_macro.get("wrong_label_rate"),
        "self_wrong": self_macro.get("wrong_label_rate"),
        "evigate_coverage": evigate_clean.get("coverage"),
        "self_coverage": self_clean.get("coverage"),
        "evigate_risk": evigate_clean.get("selective_risk"),
        "self_risk": self_clean.get("selective_risk"),
    }
    if any(value is None for value in values.values()):
        return None
    numeric = {key: float(value) for key, value in values.items()}
    corruption_reduction = numeric["self_wrong"] - numeric["evigate_wrong"]
    coverage_gap = numeric["self_coverage"] - numeric["evigate_coverage"]
    risk_increase = numeric["evigate_risk"] - numeric["self_risk"]
    h1_passed = corruption_reduction >= 0.05
    h2_coverage_floor = numeric["evigate_coverage"] >= 0.60
    h2_absolute_coverage_gap = coverage_gap <= 0.15
    h2_risk = risk_increase <= 0.10
    h2_passed = h2_coverage_floor and h2_absolute_coverage_gap and h2_risk
    return {
        "H1": {
            "criterion": "corruption-macro wrong-label reduction >= 0.05",
            "evigate_wrong_label_rate": numeric["evigate_wrong"],
            "self_abstaining_wrong_label_rate": numeric["self_wrong"],
            "absolute_reduction": corruption_reduction,
            "passed": h1_passed,
        },
        "H2": {
            "criterion": "coverage >= 0.60, coverage gap <= 0.15, risk increase <= 0.10",
            "evigate_clean_coverage": numeric["evigate_coverage"],
            "self_abstaining_clean_coverage": numeric["self_coverage"],
            "coverage_gap": coverage_gap,
            "evigate_clean_selective_risk": numeric["evigate_risk"],
            "self_abstaining_clean_selective_risk": numeric["self_risk"],
            "selective_risk_increase": risk_increase,
            "coverage_floor_passed": h2_coverage_floor,
            "absolute_coverage_gap_passed": h2_absolute_coverage_gap,
            "risk_guardrail_passed": h2_risk,
            "passed": h2_passed,
        },
        "overall_method_success": h1_passed and h2_passed,
    }


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    truth_rows = load_jsonl(args.truth)
    truth_map = {row["sample_id"]: row for row in truth_rows}
    outputs = load_jsonl(args.outputs)
    thresholds = None
    calibration_audit = None
    if args.calibration_outputs and args.calibration_truth:
        calibration_output_rows = load_jsonl(args.calibration_outputs)
        calibration_truth_rows = load_jsonl(args.calibration_truth)
        thresholds, calibration_audit = calibration_thresholds(
            calibration_output_rows,
            {row["sample_id"]: row for row in calibration_truth_rows},
            args.target_coverage,
        )
    per_case = llm_rows(outputs, truth_map, thresholds=thresholds)
    excluded_cases = {
        item.strip() for item in args.exclude_cases.split(",") if item.strip()
    }
    if args.margin_clean and args.margin_corruptions:
        per_case.extend(margin_rows(args.margin_clean, args.margin_corruptions))
    if excluded_cases:
        per_case = [row for row in per_case if row["case_id"] not in excluded_cases]

    by_method: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in per_case:
        by_method[row["method"]].append(row)
    methods: dict[str, Any] = {}
    for method, rows in sorted(by_method.items()):
        clean = [row for row in rows if row["condition"] == "clean"]
        corrupted = [row for row in rows if row["condition"] == "corrupted"]
        family_summary = {
            family: summarize(
                [row for row in corrupted if row["corruption_family"] == family]
            )
            for family in sorted({row["corruption_family"] for row in corrupted})
        }
        methods[method] = {
            "clean": summarize(clean),
            "corrupted_all": summarize(corrupted),
            "corruption_families": family_summary,
            "corruption_macro": {
                key: mean(
                    value[key]
                    for value in family_summary.values()
                    if key in value and value[key] is not None
                )
                for key in (
                    "rejection_rate",
                    "wrong_label_rate",
                    "unsupported_label_rate",
                    "hallucinated_entity_record_rate",
                    "hallucinated_anchor_record_rate",
                    "integrity_alarm_rate",
                )
            }
            if family_summary
            else {},
        }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "evigate_llm.per_case.csv", per_case)
    summary = {
        "schema_version": "1.0",
        "study": "EviGate-LLM evaluation",
        "complete_expected_llm_rows": len(outputs) == 3 * len(truth_rows),
        "truth_samples": len(truth_rows),
        "saved_llm_outputs": len(outputs),
        "excluded_development_cases": sorted(excluded_cases),
        "target_calibration_coverage": args.target_coverage,
        "calibration_threshold_audit": calibration_audit,
        "methods": methods,
        "prospective_hypotheses": prospective_hypotheses(methods),
        "limitations": [
            "Synthetic corruption families are equally weighted and do not estimate deployment prevalence.",
            "All events come from one scripted CICAPT-IIoT campaign.",
            "The deterministic verifier validates evidence references and decision consistency, not semantic entailment of the tactic label.",
        ],
    }
    (args.output_dir / "evigate_llm.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--calibration-outputs", type=Path)
    parser.add_argument("--calibration-truth", type=Path)
    parser.add_argument("--target-coverage", type=float, default=0.8)
    parser.add_argument("--exclude-cases", default="")
    parser.add_argument("--margin-clean", type=Path)
    parser.add_argument("--margin-corruptions", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    print(json.dumps(evaluate(args), ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
