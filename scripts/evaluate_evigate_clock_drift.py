#!/usr/bin/env python3
"""Evaluate signed clock offsets with clean-fitted EviGate-Bind components."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict

from evaluate_evigate_bindgate import (
    DEFAULT_EXCLUSIONS,
    exact_count_threshold,
    filter_pair_features,
    hard_negative_donors,
    llm_attribute,
    load_jsonl,
    make_binding_model,
    make_tactic_model,
    network_features,
    pair_features,
    probability_dicts,
    provenance_features,
    retention_threshold,
    sha256_file,
    vector_rows,
)


def support_entity(package: dict[str, Any], output: dict[str, Any]) -> str | None:
    parsed = output.get("parsed_response") or {}
    reference = parsed.get("support_process_ref")
    if not reference or not str(reference).startswith("P"):
        return None
    try:
        rank = int(str(reference)[1:])
    except ValueError:
        return None
    for candidate in package.get("ranked_process_candidates", []):
        if int(candidate.get("rank", -1)) == rank:
            return str(candidate.get("entity_id"))
    return None


def summarize(rows: list[dict[str, Any]], prefix: str) -> dict[str, Any]:
    accepted = sum(bool(row[f"{prefix}_accepted"]) for row in rows)
    correct = sum(bool(row[f"{prefix}_correct"]) for row in rows)
    wrong = accepted - correct
    return {
        "events": len(rows),
        "accepted": accepted,
        "coverage": accepted / len(rows),
        "correct_accepted": correct,
        "unconditional_correct_rate": correct / len(rows),
        "wrong_labels": wrong,
        "wrong_label_rate": wrong / len(rows),
        "selective_risk": wrong / accepted if accepted else None,
        "abstentions": len(rows) - accepted,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-inputs", type=Path, required=True)
    parser.add_argument("--base-truth", type=Path, required=True)
    parser.add_argument("--llm-outputs", type=Path, required=True)
    parser.add_argument("--drift-inputs", type=Path, required=True)
    parser.add_argument("--drift-truth", type=Path, required=True)
    parser.add_argument("--stage-c-summary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target-binding-retention", type=float, default=0.9)
    parser.add_argument("--target-clean-coverage", type=float, default=0.67)
    parser.add_argument("--seed", type=int, default=20260916)
    parser.add_argument("--exclude-case", action="append", default=list(DEFAULT_EXCLUSIONS))
    args = parser.parse_args()

    base_input_rows = load_jsonl(args.base_inputs)
    base_truth_rows = load_jsonl(args.base_truth)
    base_packages = {row["sample_id"]: row for row in base_input_rows}
    base_truths = {row["sample_id"]: row for row in base_truth_rows}
    clean = [
        (package, truth)
        for package, truth in zip(base_input_rows, base_truth_rows)
        if truth["condition"] == "clean"
        and truth["case_id"] not in set(args.exclude_case)
    ]
    if len(clean) != 51:
        raise ValueError(f"expected 51 retained clean events, found {len(clean)}")
    clean_by_case = {truth["case_id"]: (package, truth) for package, truth in clean}
    outputs = {
        row["sample_id"]: row
        for row in load_jsonl(args.llm_outputs)
        if row.get("variant") == "contracted"
    }
    drift_rows = load_jsonl(args.drift_inputs)
    drift_truth_rows = load_jsonl(args.drift_truth)
    if len(drift_rows) != len(drift_truth_rows):
        raise ValueError("drift input and truth row counts differ")
    drift_pairs = [
        (package, truth)
        for package, truth in zip(drift_rows, drift_truth_rows)
        if truth["case_id"] not in set(args.exclude_case)
    ]
    stage_c = json.loads(args.stage_c_summary.read_text(encoding="utf-8"))
    calibrated_margin = {
        int(item["fold"]): float(item["thresholds"]["margin"])
        for item in stage_c["fold_audits"]
    }

    binding_threshold: dict[int, float] = {}
    evigate_margin_threshold: dict[int, float] = {}
    binding_scores: dict[str, float] = {}
    fold_audit: dict[str, Any] = {}

    for fold in (1, 2, 3):
        train = [row for row in clean if int(row[1]["test_fold"]) != fold]
        train_packages = [package for package, _ in train]
        train_labels = [truth["tactic"] for _, truth in train]
        network_model = make_tactic_model(args.seed)
        provenance_model = make_tactic_model(args.seed + 1)
        network_model.fit(
            [network_features(package["network_event"]) for package in train_packages],
            train_labels,
        )
        provenance_model.fit(
            [provenance_features(package) for package in train_packages], train_labels
        )
        train_network_probabilities = probability_dicts(
            network_model,
            [network_features(package["network_event"]) for package in train_packages],
        )
        train_provenance_probabilities = probability_dicts(
            provenance_model, [provenance_features(package) for package in train_packages]
        )
        donors = hard_negative_donors(train_packages, train_labels, mode="both")
        pair_rows: list[dict[str, float]] = []
        pair_targets: list[int] = []
        pair_groups: list[str] = []
        positive_indices: list[int] = []
        for index, ((package, truth), network_probability) in enumerate(
            zip(train, train_network_probabilities)
        ):
            positive_indices.append(len(pair_rows))
            pair_rows.append(
                filter_pair_features(
                    pair_features(
                        network_probability,
                        train_provenance_probabilities[index],
                        package["network_event"],
                        package,
                    ),
                    "full",
                )
            )
            pair_targets.append(1)
            pair_groups.append(truth["case_id"])
            for donor in donors[index]:
                pair_rows.append(
                    filter_pair_features(
                        pair_features(
                            network_probability,
                            train_provenance_probabilities[donor],
                            package["network_event"],
                            train_packages[donor],
                        ),
                        "full",
                    )
                )
                pair_targets.append(0)
                pair_groups.append(truth["case_id"])
        vectorizer, matrix = vector_rows(pair_rows)
        targets = np.asarray(pair_targets, dtype=int)
        groups = np.asarray(pair_groups)
        splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=args.seed)
        oof = cross_val_predict(
            make_binding_model(args.seed),
            matrix,
            targets,
            groups=groups,
            cv=splitter,
            method="predict_proba",
        )[:, 1]
        clean_oof = [float(oof[index]) for index in positive_indices]
        threshold, target_count = retention_threshold(
            clean_oof, args.target_binding_retention
        )
        binding_threshold[fold] = threshold
        model = make_binding_model(args.seed)
        model.fit(matrix, targets)

        def score(package: dict[str, Any]) -> float:
            network_probability = probability_dicts(
                network_model, [network_features(package["network_event"])]
            )[0]
            provenance_probability = probability_dicts(
                provenance_model, [provenance_features(package)]
            )[0]
            features = filter_pair_features(
                pair_features(
                    network_probability,
                    provenance_probability,
                    package["network_event"],
                    package,
                ),
                "full",
            )
            return float(model.predict_proba(vectorizer.transform([features]))[0, 1])

        train_binding_scores = {
            truth["case_id"]: clean_oof[index]
            for index, (_, truth) in enumerate(train)
        }
        eligible_margins: list[float] = []
        for package, truth in train:
            llm_ok, _ = llm_attribute(outputs[truth["sample_id"]])
            if llm_ok and train_binding_scores[truth["case_id"]] >= threshold:
                eligible_margins.append(float(package["machine_proposal"]["margin"]))
        desired = int(np.ceil(args.target_clean_coverage * len(train)))
        evigate_margin_threshold[fold] = exact_count_threshold(eligible_margins, desired)
        for package, truth in drift_pairs:
            if int(truth["test_fold"]) == fold:
                binding_scores[truth["sample_id"]] = score(package)
        fold_audit[str(fold)] = {
            "outer_training_clean_events": len(train),
            "binding_threshold": threshold,
            "binding_target_count": target_count,
            "evigate_margin_threshold": evigate_margin_threshold[fold],
            "stage_c_calibrated_margin_threshold": calibrated_margin[fold],
        }

    output_rows: list[dict[str, Any]] = []
    for package, truth in drift_pairs:
        case_id = truth["case_id"]
        fold = int(truth["test_fold"])
        clean_package, clean_truth = clean_by_case[case_id]
        output = outputs[clean_truth["sample_id"]]
        llm_ok, llm_prediction = llm_attribute(output)
        stable_entity = support_entity(clean_package, output)
        shifted_entities = {
            str(candidate.get("entity_id"))
            for candidate in package.get("ranked_process_candidates", [])
        }
        support_retained = bool(
            llm_ok
            and stable_entity is not None
            and stable_entity in shifted_entities
        )
        summary = package.get("provenance_summary", {})
        temporal_pass = bool(
            int(summary.get("process_candidate_count", 0)) > 0
            and float(summary.get("top3_mean_time_proximity", 0.0)) > 0.0
        )
        bind_score = binding_scores[truth["sample_id"]]
        bind_pass = bind_score >= binding_threshold[fold]
        proposal_margin = float(package["machine_proposal"]["margin"])
        proposal = package["machine_proposal"]["tactic"]
        primary_accepted = bool(
            llm_ok
            and support_retained
            and bind_pass
            and temporal_pass
            and proposal_margin >= evigate_margin_threshold[fold]
        )
        cpu_accepted = bool(
            bind_pass
            and temporal_pass
            and proposal_margin >= calibrated_margin[fold]
        )
        margin_accepted = bool(
            temporal_pass and proposal_margin >= calibrated_margin[fold]
        )
        output_rows.append(
            {
                "sample_id": truth["sample_id"],
                "case_id": case_id,
                "test_fold": fold,
                "clock_offset_seconds": int(truth["clock_offset_seconds"]),
                "tactic": truth["tactic"],
                "machine_proposal": proposal,
                "proposal_margin": proposal_margin,
                "binding_score": bind_score,
                "binding_threshold": binding_threshold[fold],
                "binding_pass": bind_pass,
                "temporal_admissibility_pass": temporal_pass,
                "frozen_llm_attributed": llm_ok,
                "frozen_llm_prediction": llm_prediction,
                "support_entity_retained_top10": support_retained,
                "primary_accepted": primary_accepted,
                "primary_correct": bool(
                    primary_accepted and llm_prediction == truth["tactic"]
                ),
                "cpu_accepted": cpu_accepted,
                "cpu_correct": bool(cpu_accepted and proposal == truth["tactic"]),
                "margin_accepted": margin_accepted,
                "margin_correct": bool(
                    margin_accepted and proposal == truth["tactic"]
                ),
            }
        )

    output_rows.sort(key=lambda row: (row["clock_offset_seconds"], row["case_id"]))
    offsets = sorted({row["clock_offset_seconds"] for row in output_rows})
    by_offset: dict[str, Any] = {}
    for offset in offsets:
        rows = [row for row in output_rows if row["clock_offset_seconds"] == offset]
        by_offset[str(offset)] = {
            "primary_fixed_review": summarize(rows, "primary"),
            "cpu_bindgate": summarize(rows, "cpu"),
            "calibrated_margin": summarize(rows, "margin"),
            "binding_pass": sum(row["binding_pass"] for row in rows),
            "temporal_pass": sum(row["temporal_admissibility_pass"] for row in rows),
            "support_entity_retained_top10": sum(
                row["support_entity_retained_top10"] for row in rows
            ),
            "frozen_positive_certificates": sum(
                row["frozen_llm_attributed"] for row in rows
            ),
        }
    zero = by_offset["0"]
    validation = {
        "primary_zero_offset_matches_published_clean": (
            zero["primary_fixed_review"]["accepted"] == 33
            and zero["primary_fixed_review"]["correct_accepted"] == 25
            and zero["primary_fixed_review"]["wrong_labels"] == 8
        ),
        "margin_zero_offset_matches_published_clean": (
            zero["calibrated_margin"]["accepted"] == 38
            and zero["calibrated_margin"]["correct_accepted"] == 28
            and zero["calibrated_margin"]["wrong_labels"] == 10
        ),
    }
    if not all(validation.values()):
        raise AssertionError(f"zero-offset validation failed: {validation}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    per_case_path = args.output_dir / "clock_drift.per_case.csv"
    with per_case_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output_rows[0]))
        writer.writeheader()
        writer.writerows(output_rows)
    summary = {
        "schema_version": "1.0",
        "study": "EviGate bounded signed clock-drift stress test",
        "status": "post-freeze; no drifted package used for fitting or threshold selection",
        "events_per_offset": 51,
        "offsets_seconds": offsets,
        "results": by_offset,
        "zero_offset_validation": validation,
        "fold_audit": fold_audit,
        "interpretation_boundary": (
            "The fixed-review path reuses the frozen clean LLM decision and requires "
            "its stable support entity to remain in the shifted top-10 package; this "
            "isolates verifier sensitivity and is not fresh LLM inference."
        ),
        "input_integrity": {
            "base_inputs_sha256": sha256_file(args.base_inputs),
            "base_truth_sha256": sha256_file(args.base_truth),
            "llm_outputs_sha256": sha256_file(args.llm_outputs),
            "drift_inputs_sha256": sha256_file(args.drift_inputs),
            "drift_truth_sha256": sha256_file(args.drift_truth),
            "stage_c_summary_sha256": sha256_file(args.stage_c_summary),
        },
    }
    summary_path = args.output_dir / "clock_drift.summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
