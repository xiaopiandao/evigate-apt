#!/usr/bin/env python3
"""Evaluate a separate integrity detector and transparent dual rejection rule."""

from __future__ import annotations

import argparse
import csv
import json
import math
import time
from pathlib import Path
from statistics import mean
from typing import Any

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

import run_stage_c_selective_attribution as base


INTEGRITY_FEATURE_NAMES = (
    "js_network_provenance",
    "js_combined_network",
    "js_combined_provenance",
    "network_provenance_agreement",
    "all_view_agreement",
    "log_process_candidates",
    "log_total_entities",
    "log_relations",
    "socket_fraction",
    "top3_stability_30s",
)


def integrity_feature_indices() -> list[int]:
    missing = set(INTEGRITY_FEATURE_NAMES) - set(base.CONTROLLER_FEATURE_NAMES)
    if missing:
        raise AssertionError(f"unknown integrity features: {sorted(missing)}")
    return [base.CONTROLLER_FEATURE_NAMES.index(name) for name in INTEGRITY_FEATURE_NAMES]


def fit_integrity_detector(
    x: np.ndarray, families: np.ndarray, weights: np.ndarray, seed: int
) -> Any:
    indices = integrity_feature_indices()
    labels = np.asarray(families == "clean", dtype=int)
    model = Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "classifier",
                LogisticRegression(
                    C=0.3,
                    class_weight="balanced",
                    max_iter=3000,
                    solver="liblinear",
                    random_state=seed,
                ),
            ),
        ]
    )
    model.fit(x[:, indices], labels, classifier__sample_weight=weights)
    return model


def integrity_probability(model: Any, features: np.ndarray) -> float:
    indices = integrity_feature_indices()
    return float(model.predict_proba(features[indices].reshape(1, -1))[0, 1])


def empirical_percentile(value: float, reference: list[float]) -> float:
    """Midrank empirical percentile against clean calibration values."""
    values = np.asarray(reference, dtype=float)
    if values.size == 0:
        raise ValueError("calibration reference must not be empty")
    below = float(np.sum(values < value))
    equal = float(np.sum(values == value))
    return (below + 0.5 * equal) / float(values.size)


def dual_gate_score(
    confidence: float,
    integrity: float,
    calibration_confidence: list[float],
    calibration_integrity: list[float],
) -> float:
    """Score the logical-OR rejector as the worse calibrated percentile."""
    return min(
        empirical_percentile(confidence, calibration_confidence),
        empirical_percentile(integrity, calibration_integrity),
    )


def balanced_family_weights(families: np.ndarray) -> np.ndarray:
    clean = families == "clean"
    corruption_names = sorted(set(map(str, families[~clean])))
    if not corruption_names:
        raise ValueError("integrity detector requires at least one corruption family")
    return np.where(clean, 0.5, 0.5 / len(corruption_names)).astype(float)


def bootstrap_difference(
    rows: list[dict[str, Any]],
    left_score: str,
    right_score: str,
    coverage: float,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    differences: list[float] = []
    left_risks: list[float] = []
    right_risks: list[float] = []
    count = max(1, int(round(coverage * len(rows))))
    for _ in range(iterations):
        indices = rng.integers(0, len(rows), size=len(rows))
        sample = [
            dict(rows[int(index)], case_id=f"{draw}:{rows[int(index)]['case_id']}")
            for draw, index in enumerate(indices)
        ]
        left_accept = base.selection_mask(sample, left_score, count)
        right_accept = base.selection_mask(sample, right_score, count)
        left_risk = base.risk_for(sample, left_accept)
        right_risk = base.risk_for(sample, right_accept)
        left_risks.append(left_risk)
        right_risks.append(right_risk)
        differences.append(left_risk - right_risk)
    return {
        "iterations": iterations,
        "unit": "attack_action_cluster",
        "left_score": left_score,
        "right_score": right_score,
        "left_risk_ci95": base.percentile_interval(left_risks),
        "right_risk_ci95": base.percentile_interval(right_risks),
        "difference_ci95": base.percentile_interval(differences),
        "probability_difference_below_zero": float(
            np.mean(np.asarray(differences) < 0.0)
        ),
    }


def summarize_corruptions(rows: list[dict[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for family in base.CORRUPTION_FAMILIES:
        selected = [row for row in rows if row["corruption_family"] == family]
        metrics: dict[str, Any] = {"cases": len(selected)}
        for rule in ("controller", "confidence", "integrity", "dual"):
            reject_key = f"{rule}_reject"
            metrics[f"{rule}_rejection_rate"] = float(
                mean(int(row[reject_key]) for row in selected)
            )
            metrics[f"{rule}_wrong_attribution_rate"] = float(
                mean(
                    int(not int(row[reject_key]) and not int(row["correct"]))
                    for row in selected
                )
            )
        output[family] = metrics
    return output


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def frozen_reproducibility_check(
    test_rows: list[dict[str, Any]],
    corruption_rows: list[dict[str, Any]],
    reference_dir: Path | None,
) -> dict[str, Any]:
    if reference_dir is None:
        return {"status": "not_requested"}
    reference_test = {
        row["case_id"]: row
        for row in load_csv(reference_dir / "stage_c_test_predictions.csv")
    }
    reference_corruption = {
        (row["case_id"], row["corruption_family"]): row
        for row in load_csv(reference_dir / "stage_c_corruption_results.csv")
    }
    test_differences = [
        abs(float(row["controller_score"]) - float(reference_test[row["case_id"]]["controller_score"]))
        for row in test_rows
    ]
    corruption_differences = [
        abs(
            float(row["controller_score"])
            - float(reference_corruption[(row["case_id"], row["corruption_family"])]["controller_score"])
        )
        for row in corruption_rows
    ]
    prediction_mismatches = sum(
        row["prediction"] != reference_test[row["case_id"]]["prediction"]
        for row in test_rows
    )
    maximum = max(test_differences + corruption_differences, default=0.0)
    return {
        "status": "exact" if maximum == 0.0 and prediction_mismatches == 0 else "mismatch",
        "reference_dir": reference_dir.as_posix(),
        "test_rows": len(test_rows),
        "corruption_rows": len(corruption_rows),
        "maximum_absolute_controller_score_difference": maximum,
        "prediction_mismatches": prediction_mismatches,
    }


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    started = time.perf_counter()
    inputs = {item["case_id"]: item for item in base.load_jsonl(args.inputs)}
    truths = {item["case_id"]: item for item in base.load_jsonl(args.truth)}
    if set(inputs) != set(truths):
        raise ValueError("input and truth sidecars have different case IDs")

    test_rows: list[dict[str, Any]] = []
    corruption_rows: list[dict[str, Any]] = []
    fold_audits: list[dict[str, Any]] = []

    for fold in (1, 2, 3):
        train_ids = sorted(base.partition_ids(truths, fold, "train", in_support=True))
        calibration_ids = sorted(
            base.partition_ids(truths, fold, "calibration", in_support=True)
        )
        test_ids = sorted(base.partition_ids(truths, fold, "test", in_support=True))
        ranker = base.fit_entity_ranker(train_ids, inputs, truths, args.seed)
        train_representations = {
            case_id: base.make_representation(inputs[case_id], ranker)
            for case_id in train_ids
        }
        tactic_models = base.fit_tactic_models(
            train_ids, train_representations, truths, args.seed
        )
        controller_x, controller_y, _, controller_families, controller_audit = (
            base.train_controller_rows(train_ids, inputs, truths, args.seed)
        )
        full_weights = balanced_family_weights(controller_families)
        controller = base.fit_controller(
            controller_x, controller_y, full_weights, args.seed
        )
        integrity = fit_integrity_detector(
            controller_x, controller_families, full_weights, args.seed
        )

        loco_controllers: dict[str, Any] = {}
        loco_integrity: dict[str, Any] = {}
        for family in base.CORRUPTION_FAMILIES:
            keep = controller_families != family
            loco_x = controller_x[keep]
            loco_y = controller_y[keep]
            loco_families = controller_families[keep]
            loco_weights = balanced_family_weights(loco_families)
            loco_controllers[family] = base.fit_controller(
                loco_x, loco_y, loco_weights, args.seed
            )
            loco_integrity[family] = fit_integrity_detector(
                loco_x, loco_families, loco_weights, args.seed
            )

        calibration_records: list[dict[str, Any]] = []
        for case_id in calibration_ids:
            representation = base.make_representation(inputs[case_id], ranker)
            posteriors = base.tactic_posteriors(tactic_models, representation)
            features = base.controller_features(posteriors, representation)
            calibration_records.append(
                {
                    "case_id": case_id,
                    "features": features,
                    "confidence": float(np.max(posteriors["combined"])),
                    "controller": float(
                        controller.predict_proba(features.reshape(1, -1))[0, 1]
                    ),
                    "integrity": integrity_probability(integrity, features),
                }
            )
        calibration_confidence = [row["confidence"] for row in calibration_records]
        calibration_integrity = [row["integrity"] for row in calibration_records]
        for row in calibration_records:
            row["dual"] = dual_gate_score(
                row["confidence"],
                row["integrity"],
                calibration_confidence,
                calibration_integrity,
            )
        thresholds = {
            name: base.calibration_threshold(
                [float(row[name]) for row in calibration_records], args.coverage
            )
            for name in ("controller", "confidence", "integrity", "dual")
        }

        for case_id in test_ids:
            representation = base.make_representation(inputs[case_id], ranker)
            posteriors = base.tactic_posteriors(tactic_models, representation)
            features = base.controller_features(posteriors, representation)
            confidence_score = float(np.max(posteriors["combined"]))
            controller_score = float(
                controller.predict_proba(features.reshape(1, -1))[0, 1]
            )
            integrity_score = integrity_probability(integrity, features)
            dual_score = dual_gate_score(
                confidence_score,
                integrity_score,
                calibration_confidence,
                calibration_integrity,
            )
            prediction = base.TACTICS[int(np.argmax(posteriors["combined"]))]
            row = {
                "case_id": case_id,
                "test_fold": fold,
                "tactic": truths[case_id]["event"]["tactic"],
                "prediction": prediction,
                "correct": int(prediction == truths[case_id]["event"]["tactic"]),
                "controller_score": controller_score,
                "confidence_score": confidence_score,
                "integrity_score": integrity_score,
                "dual_score": dual_score,
            }
            for name in ("controller", "confidence", "integrity", "dual"):
                row[f"calibrated_{name}_accept"] = int(
                    float(row[f"{name}_score"]) >= thresholds[name]
                )
            test_rows.append(row)

        for family in base.CORRUPTION_FAMILIES:
            family_controller = loco_controllers[family]
            family_integrity = loco_integrity[family]
            family_calibration: list[dict[str, float]] = []
            for record in calibration_records:
                features = record["features"]
                family_calibration.append(
                    {
                        "confidence": float(record["confidence"]),
                        "controller": float(
                            family_controller.predict_proba(features.reshape(1, -1))[0, 1]
                        ),
                        "integrity": integrity_probability(family_integrity, features),
                    }
                )
            family_confidence = [row["confidence"] for row in family_calibration]
            family_integrity_reference = [row["integrity"] for row in family_calibration]
            for row in family_calibration:
                row["dual"] = dual_gate_score(
                    row["confidence"],
                    row["integrity"],
                    family_confidence,
                    family_integrity_reference,
                )
            family_thresholds = {
                name: base.calibration_threshold(
                    [float(row[name]) for row in family_calibration], args.coverage
                )
                for name in ("controller", "confidence", "integrity", "dual")
            }
            for case_id in test_ids:
                replacement_id = base.replacement_for(case_id, train_ids, truths)
                representation = base.make_representation(
                    inputs[case_id],
                    ranker,
                    corruption=family,
                    replacement=(
                        inputs[replacement_id]
                        if family == "context_replacement"
                        else None
                    ),
                )
                posteriors = base.tactic_posteriors(tactic_models, representation)
                features = base.controller_features(posteriors, representation)
                scores = {
                    "controller": float(
                        family_controller.predict_proba(features.reshape(1, -1))[0, 1]
                    ),
                    "confidence": float(np.max(posteriors["combined"])),
                    "integrity": integrity_probability(family_integrity, features),
                }
                scores["dual"] = dual_gate_score(
                    scores["confidence"],
                    scores["integrity"],
                    family_confidence,
                    family_integrity_reference,
                )
                prediction = base.TACTICS[int(np.argmax(posteriors["combined"]))]
                row = {
                    "case_id": case_id,
                    "test_fold": fold,
                    "corruption_family": family,
                    "tactic": truths[case_id]["event"]["tactic"],
                    "prediction": prediction,
                    "correct": int(prediction == truths[case_id]["event"]["tactic"]),
                }
                for name, value in scores.items():
                    row[f"{name}_score"] = value
                    row[f"{name}_reject"] = int(value < family_thresholds[name])
                corruption_rows.append(row)

        fold_audits.append(
            {
                "fold": fold,
                "train_cases": len(train_ids),
                "calibration_cases": len(calibration_ids),
                "test_cases": len(test_ids),
                "controller_training": controller_audit,
                "thresholds": thresholds,
                "calibration_dual_score_unique_values": len(
                    set(float(row["dual"]) for row in calibration_records)
                ),
            }
        )

    accepted_count = max(1, int(round(args.coverage * len(test_rows))))
    fixed_masks: dict[str, set[str]] = {}
    fixed_risks: dict[str, float] = {}
    for name in ("controller", "confidence", "integrity", "dual"):
        score_name = f"{name}_score"
        fixed_masks[name] = base.selection_mask(test_rows, score_name, accepted_count)
        fixed_risks[name] = base.risk_for(test_rows, fixed_masks[name])
        for row in test_rows:
            row[f"fixed_coverage_{name}_accept"] = int(
                row["case_id"] in fixed_masks[name]
            )

    calibrated = {}
    for name in ("controller", "confidence", "integrity", "dual"):
        selected = [row for row in test_rows if row[f"calibrated_{name}_accept"]]
        calibrated[name] = {
            "accepted": len(selected),
            "coverage": len(selected) / len(test_rows),
            "risk": float(mean(1 - int(row["correct"]) for row in selected))
            if selected
            else None,
        }

    reproducibility = frozen_reproducibility_check(
        test_rows, corruption_rows, args.reference_dir
    )
    result = {
        "schema_version": "1.0",
        "study": "EviGate-APT Stage C decomposed selective gate",
        "protocol": {
            "statistical_unit": "attack_action_cluster",
            "events": len(test_rows),
            "target_coverage": args.coverage,
            "fixed_accepted_events": accepted_count,
            "integrity_target": "clean evidence versus synthetic corruption; no clean correctness labels",
            "dual_rule": "reject if confidence or integrity is low; score=min(clean-calibration percentile confidence, clean-calibration percentile integrity)",
            "integrity_features": list(INTEGRITY_FEATURE_NAMES),
            "derived_event_labels": True,
        },
        "fixed_coverage": {
            "accepted_events": accepted_count,
            "realized_coverage": accepted_count / len(test_rows),
            **{f"{name}_risk": value for name, value in fixed_risks.items()},
            "dual_minus_confidence_risk_difference": fixed_risks["dual"]
            - fixed_risks["confidence"],
            "dual_vs_confidence_bootstrap": bootstrap_difference(
                test_rows,
                "dual_score",
                "confidence_score",
                args.coverage,
                args.bootstrap_iterations,
                args.seed,
            ),
        },
        "calibration_threshold_operating_points": calibrated,
        "risk_coverage_curves": {
            name: base.risk_coverage_curve(test_rows, f"{name}_score")
            for name in ("controller", "confidence", "integrity", "dual")
        },
        "leave_one_corruption_family_out": summarize_corruptions(corruption_rows),
        "fold_audits": fold_audits,
        "frozen_controller_reproducibility": reproducibility,
        "limitations": [
            "The integrity detector is trained on synthetic transformations, not field collection failures.",
            "Calibration uses only 7-8 clean events per fold, so empirical percentiles are coarse.",
            "The dual rule is evaluated on one scripted campaign and is not a deployment threshold recommendation.",
            "The original controller-versus-confidence endpoint remains the primary frozen comparison.",
        ],
        "runtime_seconds": time.perf_counter() - started,
        "source_files": {
            "inputs": {"path": args.inputs.as_posix(), "sha256": base.sha256_file(args.inputs)},
            "truth": {"path": args.truth.as_posix(), "sha256": base.sha256_file(args.truth)},
        },
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    test_path = args.output_dir / "stage_c_gate_decomposition.test_predictions.csv"
    corruption_path = args.output_dir / "stage_c_gate_decomposition.corruptions.csv"
    base.write_csv(test_path, test_rows)
    base.write_csv(corruption_path, corruption_rows)
    result["artifacts"] = {
        test_path.name: {"sha256": base.sha256_file(test_path), "bytes": test_path.stat().st_size},
        corruption_path.name: {
            "sha256": base.sha256_file(corruption_path),
            "bytes": corruption_path.stat().st_size,
        },
    }
    summary_path = args.output_dir / "stage_c_gate_decomposition.summary.json"
    summary_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "summary": summary_path.as_posix(),
                "fixed_coverage": result["fixed_coverage"],
                "calibration": calibrated,
                "corruption": result["leave_one_corruption_family_out"],
                "reproducibility": reproducibility,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--reference-dir", type=Path)
    parser.add_argument("--coverage", type=float, default=0.8)
    parser.add_argument("--bootstrap-iterations", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260915)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    evaluate(args)


if __name__ == "__main__":
    main()
