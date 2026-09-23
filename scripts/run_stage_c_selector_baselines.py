#!/usr/bin/env python3
"""Evaluate five matched selective-labeling baselines for EviGate-APT Stage C.

The frozen controller-versus-maximum-confidence endpoint remains unchanged.  This
extension compares post-hoc selectors on the same tactic classifier and the same
grouped train/calibration/test folds.  It also retains the integrity-only and
dual diagnostic rules from the Stage-4 decomposition audit.
"""

from __future__ import annotations

import argparse
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

import run_stage_c_gate_decomposition as decomposition
import run_stage_c_selective_attribution as base


BASELINE_RULES = (
    "confidence",
    "entropy",
    "margin",
    "posterior_lr",
    "cross_view",
)
METHOD_RULES = ("controller", "integrity", "dual")
ALL_RULES = BASELINE_RULES + METHOD_RULES
POSTERIOR_FEATURE_NAMES = (
    "combined_confidence",
    "combined_margin",
    "combined_entropy",
)


def posterior_feature_indices() -> list[int]:
    missing = set(POSTERIOR_FEATURE_NAMES) - set(base.CONTROLLER_FEATURE_NAMES)
    if missing:
        raise AssertionError(f"unknown posterior features: {sorted(missing)}")
    return [base.CONTROLLER_FEATURE_NAMES.index(name) for name in POSTERIOR_FEATURE_NAMES]


def fit_posterior_correctness_model(
    x: np.ndarray,
    y: np.ndarray,
    families: np.ndarray,
    seed: int,
) -> Any:
    """Fit a clean-only learned correctness baseline from posterior summaries."""
    clean = families == "clean"
    clean_y = np.asarray(y[clean], dtype=int)
    if len(np.unique(clean_y)) != 2:
        raise ValueError("posterior-only correctness model requires both clean classes")
    indices = posterior_feature_indices()
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
    model.fit(x[clean][:, indices], clean_y)
    return model


def posterior_correctness_probability(model: Any, features: np.ndarray) -> float:
    indices = posterior_feature_indices()
    return float(model.predict_proba(features[indices].reshape(1, -1))[0, 1])


def normalized_entropy_score(probabilities: np.ndarray) -> float:
    """Return one minus normalized predictive entropy; larger is more certain."""
    if len(probabilities) <= 1:
        return 1.0
    return float(1.0 - base.entropy(probabilities) / math.log(len(probabilities)))


def agreement_level(posteriors: dict[str, np.ndarray]) -> int:
    predictions = [
        int(np.argmax(posteriors[view]))
        for view in ("combined", "network", "provenance")
    ]
    unique = len(set(predictions))
    if unique == 1:
        return 2
    if unique == 2:
        return 1
    return 0


def selector_scores(
    posteriors: dict[str, np.ndarray],
    features: np.ndarray,
    posterior_model: Any,
    controller_model: Any,
    integrity_model: Any,
    calibration_confidence: list[float],
    calibration_integrity: list[float],
) -> dict[str, float]:
    combined = posteriors["combined"]
    confidence = float(np.max(combined))
    integrity = decomposition.integrity_probability(integrity_model, features)
    # Agreement levels occupy non-overlapping unit intervals.  Half-confidence
    # provides a deterministic, interpretable tie-break within each level.
    cross_view = float(agreement_level(posteriors) + 0.5 * confidence)
    return {
        "confidence": confidence,
        "entropy": normalized_entropy_score(combined),
        "margin": float(base.probability_margin(combined)),
        "posterior_lr": posterior_correctness_probability(posterior_model, features),
        "cross_view": cross_view,
        "controller": float(
            controller_model.predict_proba(features.reshape(1, -1))[0, 1]
        ),
        "integrity": integrity,
        "dual": decomposition.dual_gate_score(
            confidence,
            integrity,
            calibration_confidence,
            calibration_integrity,
        ),
    }


def exact_aurc(rows: list[dict[str, Any]], score_name: str) -> float:
    """Area under the empirical risk-coverage curve over accepted counts 1..n."""
    ordered = sorted(rows, key=lambda row: (-float(row[score_name]), row["case_id"]))
    cumulative_errors = 0
    risks: list[float] = []
    for index, row in enumerate(ordered, start=1):
        cumulative_errors += 1 - int(row["correct"])
        risks.append(cumulative_errors / index)
    return float(mean(risks))


def bootstrap_fixed_comparison(
    rows: list[dict[str, Any]],
    coverage: float,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    rng = np.random.default_rng(seed)
    accepted_count = max(1, int(round(coverage * len(rows))))
    risks = {name: [] for name in ALL_RULES}
    controller_differences = {name: [] for name in BASELINE_RULES}
    for _ in range(iterations):
        indices = rng.integers(0, len(rows), size=len(rows))
        sample = [
            dict(rows[int(index)], case_id=f"{draw}:{rows[int(index)]['case_id']}")
            for draw, index in enumerate(indices)
        ]
        sample_risks: dict[str, float] = {}
        for name in ALL_RULES:
            accepted = base.selection_mask(sample, f"{name}_score", accepted_count)
            sample_risks[name] = base.risk_for(sample, accepted)
            risks[name].append(sample_risks[name])
        for name in BASELINE_RULES:
            controller_differences[name].append(
                sample_risks["controller"] - sample_risks[name]
            )
    return {
        "iterations": iterations,
        "unit": "attack_action_cluster",
        "risk_ci95": {
            name: base.percentile_interval(values) for name, values in risks.items()
        },
        "controller_minus_baseline": {
            name: {
                "difference_ci95": base.percentile_interval(values),
                "probability_controller_lower_risk": float(
                    np.mean(np.asarray(values) < 0.0)
                ),
            }
            for name, values in controller_differences.items()
        },
    }


def summarize_corruptions(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_family: dict[str, Any] = {}
    for family in base.CORRUPTION_FAMILIES:
        selected = [row for row in rows if row["corruption_family"] == family]
        metrics: dict[str, Any] = {"cases": len(selected)}
        for name in ALL_RULES:
            metrics[f"{name}_rejection_rate"] = float(
                mean(int(row[f"{name}_reject"]) for row in selected)
            )
            metrics[f"{name}_wrong_attribution_rate"] = float(
                mean(
                    int(
                        not int(row[f"{name}_reject"])
                        and not int(row["correct"])
                    )
                    for row in selected
                )
            )
        by_family[family] = metrics

    macro: dict[str, Any] = {}
    for name in ALL_RULES:
        macro[f"{name}_mean_rejection_rate"] = float(
            mean(by_family[f][f"{name}_rejection_rate"] for f in base.CORRUPTION_FAMILIES)
        )
        macro[f"{name}_mean_wrong_attribution_rate"] = float(
            mean(
                by_family[f][f"{name}_wrong_attribution_rate"]
                for f in base.CORRUPTION_FAMILIES
            )
        )
    return {"by_family": by_family, "macro_average": macro}


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
        full_weights = decomposition.balanced_family_weights(controller_families)
        controller = base.fit_controller(
            controller_x, controller_y, full_weights, args.seed
        )
        integrity = decomposition.fit_integrity_detector(
            controller_x, controller_families, full_weights, args.seed
        )
        posterior_model = fit_posterior_correctness_model(
            controller_x, controller_y, controller_families, args.seed
        )

        loco_controllers: dict[str, Any] = {}
        loco_integrity: dict[str, Any] = {}
        for family in base.CORRUPTION_FAMILIES:
            keep = controller_families != family
            loco_x = controller_x[keep]
            loco_y = controller_y[keep]
            loco_families = controller_families[keep]
            loco_weights = decomposition.balanced_family_weights(loco_families)
            loco_controllers[family] = base.fit_controller(
                loco_x, loco_y, loco_weights, args.seed
            )
            loco_integrity[family] = decomposition.fit_integrity_detector(
                loco_x, loco_families, loco_weights, args.seed
            )

        calibration_raw: list[dict[str, Any]] = []
        for case_id in calibration_ids:
            representation = base.make_representation(inputs[case_id], ranker)
            posteriors = base.tactic_posteriors(tactic_models, representation)
            features = base.controller_features(posteriors, representation)
            calibration_raw.append(
                {
                    "case_id": case_id,
                    "features": features,
                    "posteriors": posteriors,
                    "confidence": float(np.max(posteriors["combined"])),
                    "integrity": decomposition.integrity_probability(integrity, features),
                }
            )
        calibration_confidence = [float(row["confidence"]) for row in calibration_raw]
        calibration_integrity = [float(row["integrity"]) for row in calibration_raw]
        calibration_scores = []
        for row in calibration_raw:
            calibration_scores.append(
                selector_scores(
                    row["posteriors"],
                    row["features"],
                    posterior_model,
                    controller,
                    integrity,
                    calibration_confidence,
                    calibration_integrity,
                )
            )
        thresholds = {
            name: base.calibration_threshold(
                [float(scores[name]) for scores in calibration_scores], args.coverage
            )
            for name in ALL_RULES
        }

        for case_id in test_ids:
            representation = base.make_representation(inputs[case_id], ranker)
            posteriors = base.tactic_posteriors(tactic_models, representation)
            features = base.controller_features(posteriors, representation)
            scores = selector_scores(
                posteriors,
                features,
                posterior_model,
                controller,
                integrity,
                calibration_confidence,
                calibration_integrity,
            )
            prediction = base.TACTICS[int(np.argmax(posteriors["combined"]))]
            row: dict[str, Any] = {
                "case_id": case_id,
                "test_fold": fold,
                "tactic": truths[case_id]["event"]["tactic"],
                "prediction": prediction,
                "correct": int(prediction == truths[case_id]["event"]["tactic"]),
            }
            for name, value in scores.items():
                row[f"{name}_score"] = value
                row[f"calibrated_{name}_accept"] = int(value >= thresholds[name])
            test_rows.append(row)

        for family in base.CORRUPTION_FAMILIES:
            family_controller = loco_controllers[family]
            family_integrity = loco_integrity[family]
            family_calibration_confidence = calibration_confidence
            family_calibration_integrity = [
                decomposition.integrity_probability(family_integrity, row["features"])
                for row in calibration_raw
            ]
            family_calibration_scores = [
                selector_scores(
                    row["posteriors"],
                    row["features"],
                    posterior_model,
                    family_controller,
                    family_integrity,
                    family_calibration_confidence,
                    family_calibration_integrity,
                )
                for row in calibration_raw
            ]
            family_thresholds = {
                name: base.calibration_threshold(
                    [float(scores[name]) for scores in family_calibration_scores],
                    args.coverage,
                )
                for name in ALL_RULES
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
                scores = selector_scores(
                    posteriors,
                    features,
                    posterior_model,
                    family_controller,
                    family_integrity,
                    family_calibration_confidence,
                    family_calibration_integrity,
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
                "posterior_lr_clean_training_cases": int(
                    np.sum(controller_families == "clean")
                ),
                "thresholds": thresholds,
            }
        )

    accepted_count = max(1, int(round(args.coverage * len(test_rows))))
    fixed_coverage: dict[str, Any] = {
        "accepted_events": accepted_count,
        "realized_coverage": accepted_count / len(test_rows),
    }
    calibration_operating_points: dict[str, Any] = {}
    exact_aurcs: dict[str, float] = {}
    for name in ALL_RULES:
        accepted = base.selection_mask(test_rows, f"{name}_score", accepted_count)
        fixed_coverage[f"{name}_risk"] = base.risk_for(test_rows, accepted)
        exact_aurcs[name] = exact_aurc(test_rows, f"{name}_score")
        for row in test_rows:
            row[f"fixed_coverage_{name}_accept"] = int(row["case_id"] in accepted)
        calibrated_rows = [
            row for row in test_rows if int(row[f"calibrated_{name}_accept"])
        ]
        calibration_operating_points[name] = {
            "accepted": len(calibrated_rows),
            "coverage": len(calibrated_rows) / len(test_rows),
            "risk": (
                float(mean(1 - int(row["correct"]) for row in calibrated_rows))
                if calibrated_rows
                else None
            ),
        }

    fixed_coverage["controller_minus_margin_risk_difference"] = (
        fixed_coverage["controller_risk"] - fixed_coverage["margin_risk"]
    )
    bootstrap = bootstrap_fixed_comparison(
        test_rows,
        args.coverage,
        args.bootstrap_iterations,
        args.seed,
    )

    result = {
        "schema_version": "1.0",
        "study": "EviGate-APT Stage C matched selector baselines",
        "protocol": {
            "statistical_unit": "attack_action_cluster",
            "events": len(test_rows),
            "target_coverage": args.coverage,
            "fixed_accepted_events": accepted_count,
            "outer_protocol": "three-fold grouped train/calibration/test",
            "baseline_rules": list(BASELINE_RULES),
            "method_and_ablation_rules": list(METHOD_RULES),
            "posterior_lr_features": list(POSTERIOR_FEATURE_NAMES),
            "posterior_lr_training": "clean leave-one-event-out correctness targets only; no corruption rows",
            "cross_view_score": "agreement level (all=2, any pair=1, all different=0) plus 0.5*maximum confidence",
            "primary_endpoint_unchanged": True,
            "derived_event_labels": True,
        },
        "fixed_coverage": fixed_coverage,
        "exact_aurc": exact_aurcs,
        "calibration_threshold_operating_points": calibration_operating_points,
        "risk_coverage_curves": {
            name: base.risk_coverage_curve(test_rows, f"{name}_score")
            for name in ALL_RULES
        },
        "paired_cluster_bootstrap": bootstrap,
        "leave_one_corruption_family_out": summarize_corruptions(corruption_rows),
        "fold_audits": fold_audits,
        "limitations": [
            "The baseline extension is secondary to the frozen controller-versus-confidence endpoint.",
            "All 53 events come from one scripted CICAPT-IIoT2024 campaign.",
            "The posterior-only model has only 27-28 independent clean training events per outer fold.",
            "Entropy, margin, and maximum confidence are correlated summaries of the same tactic posterior.",
            "Cross-view agreement uses diagnostic network/provenance models and does not establish causal corroboration.",
        ],
        "runtime_seconds": time.perf_counter() - started,
        "source_files": {
            "inputs": {"path": args.inputs.as_posix(), "sha256": base.sha256_file(args.inputs)},
            "truth": {"path": args.truth.as_posix(), "sha256": base.sha256_file(args.truth)},
        },
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    test_path = args.output_dir / "stage_c_selector_baselines.test_predictions.csv"
    corruption_path = args.output_dir / "stage_c_selector_baselines.corruptions.csv"
    base.write_csv(test_path, test_rows)
    base.write_csv(corruption_path, corruption_rows)
    result["artifacts"] = {
        test_path.name: {
            "sha256": base.sha256_file(test_path),
            "bytes": test_path.stat().st_size,
        },
        corruption_path.name: {
            "sha256": base.sha256_file(corruption_path),
            "bytes": corruption_path.stat().st_size,
        },
    }
    summary_path = args.output_dir / "stage_c_selector_baselines.summary.json"
    summary_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "summary": summary_path.as_posix(),
                "fixed_coverage": fixed_coverage,
                "exact_aurc": exact_aurcs,
                "calibration": calibration_operating_points,
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
    parser.add_argument("--coverage", type=float, default=0.8)
    parser.add_argument("--bootstrap-iterations", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20260915)
    return parser.parse_args()


def main() -> None:
    evaluate(parse_args())


if __name__ == "__main__":
    main()
