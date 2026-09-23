#!/usr/bin/env python3
"""Run reproducible Stage-A network-window baselines for EviGate-APT."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import sys
import warnings
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any, Iterable

import joblib
import numpy as np
import scipy
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


MODELS = ("logistic_regression", "hist_gradient_boosting", "light_mlp")
METRICS_TO_SUMMARIZE = (
    "window_average_precision",
    "window_roc_auc",
    "window_precision",
    "window_recall",
    "false_alerts_per_hour",
    "all_event_coverage",
    "in_support_event_coverage",
    "network_visible_event_coverage",
    "network_absent_event_coverage",
    "benign_stress_false_alerts_per_hour",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_features(path: Path) -> tuple[list[str], list[str], np.ndarray]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or reader.fieldnames[0] != "window_id":
            raise ValueError("feature CSV must start with window_id")
        feature_names = reader.fieldnames[1:]
        forbidden_tokens = {"label", "tactic", "action", "epoch", "timestamp"}
        bad = []
        for name in feature_names:
            lowered = name.lower()
            tokens = set(lowered.split("_"))
            if tokens & forbidden_tokens or "case_id" in lowered:
                bad.append(name)
        if bad:
            raise ValueError(f"forbidden feature columns: {bad}")
        ids: list[str] = []
        values: list[list[float]] = []
        for row in reader:
            ids.append(row["window_id"])
            values.append([float(row[name]) for name in feature_names])
    matrix = np.asarray(values, dtype=np.float64)
    if not np.isfinite(matrix).all():
        raise ValueError("feature matrix contains non-finite values")
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate window_id in feature CSV")
    return ids, feature_names, matrix


def load_truth(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            result[row["window_id"]] = {
                "window_start_epoch": int(float(row["window_start_epoch"])),
                "network_positive": int(row["network_positive"]),
                "event_case_ids": json.loads(row["event_case_ids_json"]),
            }
    return result


def load_cases(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                item = json.loads(line)
                result[item["case_id"]] = item
    return result


def balanced_sample_weights(y: np.ndarray) -> np.ndarray:
    counts = np.bincount(y.astype(int), minlength=2)
    if not counts[0] or not counts[1]:
        raise ValueError("both classes are required in training")
    n = len(y)
    weights = np.asarray([n / (2.0 * counts[int(label)]) for label in y], dtype=float)
    return weights


def oversample_minority(
    x: np.ndarray, y: np.ndarray, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    negative = np.flatnonzero(y == 0)
    positive = np.flatnonzero(y == 1)
    if not len(negative) or not len(positive):
        raise ValueError("both classes are required for oversampling")
    rng = np.random.default_rng(seed)
    if len(positive) < len(negative):
        extra = rng.choice(positive, size=len(negative) - len(positive), replace=True)
        indices = np.concatenate([negative, positive, extra])
    elif len(negative) < len(positive):
        extra = rng.choice(negative, size=len(positive) - len(negative), replace=True)
        indices = np.concatenate([negative, positive, extra])
    else:
        indices = np.arange(len(y))
    rng.shuffle(indices)
    return x[indices], y[indices]


def fit_model(name: str, x: np.ndarray, y: np.ndarray, seed: int) -> Any:
    if name == "logistic_regression":
        model = Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    LogisticRegression(
                        class_weight="balanced",
                        max_iter=2000,
                        random_state=seed,
                        solver="liblinear",
                    ),
                ),
            ]
        )
        model.fit(x, y)
        return model
    if name == "hist_gradient_boosting":
        model = HistGradientBoostingClassifier(
            learning_rate=0.05,
            max_iter=150,
            max_leaf_nodes=15,
            l2_regularization=1e-3,
            random_state=seed,
        )
        model.fit(x, y, sample_weight=balanced_sample_weights(y))
        return model
    if name == "light_mlp":
        x_balanced, y_balanced = oversample_minority(x, y, seed)
        model = Pipeline(
            [
                ("scale", StandardScaler()),
                (
                    "classifier",
                    MLPClassifier(
                        hidden_layer_sizes=(64, 32),
                        activation="relu",
                        alpha=1e-4,
                        batch_size=64,
                        learning_rate_init=1e-3,
                        max_iter=400,
                        early_stopping=True,
                        validation_fraction=0.15,
                        n_iter_no_change=20,
                        random_state=seed,
                    ),
                ),
            ]
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ConvergenceWarning)
            model.fit(x_balanced, y_balanced)
        return model
    raise ValueError(f"unknown model: {name}")


def positive_scores(model: Any, x: np.ndarray) -> np.ndarray:
    return np.asarray(model.predict_proba(x)[:, 1], dtype=float)


def select_threshold(
    y_true: np.ndarray,
    scores: np.ndarray,
    false_alert_budget_per_hour: float,
    window_seconds: int,
) -> dict[str, float | int]:
    negative_count = int(np.sum(y_true == 0))
    positive_count = int(np.sum(y_true == 1))
    negative_hours = negative_count * window_seconds / 3600.0
    allowed_fp = math.floor(false_alert_budget_per_hour * negative_hours + 1e-12)
    max_score = float(np.max(scores))
    candidates = [float(np.nextafter(max_score, math.inf))] + sorted(
        {float(score) for score in scores}, reverse=True
    )
    best: tuple[tuple[int, int, float], float, int, int] | None = None
    for threshold in candidates:
        predicted = scores >= threshold
        fp = int(np.sum(predicted & (y_true == 0)))
        if fp > allowed_fp:
            continue
        tp = int(np.sum(predicted & (y_true == 1)))
        key = (tp, -fp, threshold)
        if best is None or key > best[0]:
            best = (key, threshold, tp, fp)
    if best is None:
        raise RuntimeError("no feasible calibration threshold")
    _, threshold, tp, fp = best
    return {
        "threshold": float(threshold),
        "allowed_false_positives": allowed_fp,
        "calibration_false_positives": fp,
        "calibration_true_positives": tp,
        "calibration_positive_count": positive_count,
        "calibration_negative_hours": negative_hours,
        "calibration_recall": tp / positive_count if positive_count else 0.0,
        "calibration_false_alerts_per_hour": fp / negative_hours if negative_hours else 0.0,
    }


def safe_auc(y_true: np.ndarray, scores: np.ndarray, kind: str) -> float:
    if len(np.unique(y_true)) < 2:
        return math.nan
    if kind == "roc":
        return float(roc_auc_score(y_true, scores))
    return float(average_precision_score(y_true, scores))


def window_metrics(
    y_true: np.ndarray, scores: np.ndarray, threshold: float, window_seconds: int
) -> dict[str, float | int]:
    predicted = scores >= threshold
    negative = y_true == 0
    fp = int(np.sum(predicted & negative))
    negative_hours = int(np.sum(negative)) * window_seconds / 3600.0
    return {
        "window_average_precision": safe_auc(y_true, scores, "pr"),
        "window_roc_auc": safe_auc(y_true, scores, "roc"),
        "window_precision": float(precision_score(y_true, predicted, zero_division=0)),
        "window_recall": float(recall_score(y_true, predicted, zero_division=0)),
        "false_positive_count": fp,
        "alert_count": int(np.sum(predicted)),
        "negative_window_hours": negative_hours,
        "false_alerts_per_hour": fp / negative_hours if negative_hours else 0.0,
    }


def benign_stress_metrics(
    scores: np.ndarray, threshold: float, window_seconds: int
) -> dict[str, float | int]:
    hours = len(scores) * window_seconds / 3600.0
    alert_count = int(np.sum(scores >= threshold))
    return {
        "benign_stress_alert_count": alert_count,
        "benign_stress_window_hours": hours,
        "benign_stress_false_alerts_per_hour": alert_count / hours if hours else math.nan,
    }


def test_cases_for_fold(cases: dict[str, dict[str, Any]], fold_id: int) -> list[str]:
    selected: list[str] = []
    for case_id, case in cases.items():
        if any(
            int(membership["fold"]) == fold_id and membership["partition"] == "test"
            for membership in case["split_membership"]
        ):
            selected.append(case_id)
    return sorted(selected)


def event_results(
    test_ids: list[str],
    scores: np.ndarray,
    threshold: float,
    truth: dict[str, dict[str, Any]],
    cases: dict[str, dict[str, Any]],
    fold_id: int,
) -> tuple[list[dict[str, Any]], dict[str, float | int]]:
    by_case: dict[str, list[int]] = defaultdict(list)
    for index, window_id in enumerate(test_ids):
        for case_id in truth[window_id]["event_case_ids"]:
            by_case[case_id].append(index)

    rows: list[dict[str, Any]] = []
    for case_id in test_cases_for_fold(cases, fold_id):
        positions = by_case.get(case_id, [])
        triggered = [index for index in positions if scores[index] >= threshold]
        network_visible = any(
            truth[test_ids[index]]["network_positive"] == 1 for index in positions
        )
        rows.append(
            {
                "case_id": case_id,
                "tactic": cases[case_id]["event"]["tactic"],
                "support_role": cases[case_id]["event"]["support_role"],
                "mapped_test_window_count": len(positions),
                "network_positive_window_present": int(network_visible),
                "covered": int(bool(triggered)),
                "max_score": float(max((scores[index] for index in positions), default=math.nan)),
            }
        )

    def coverage(subset: Iterable[dict[str, Any]]) -> tuple[float, int]:
        material = list(subset)
        return (
            (sum(row["covered"] for row in material) / len(material) if material else math.nan),
            len(material),
        )

    all_coverage, all_count = coverage(rows)
    support_coverage, support_count = coverage(
        row for row in rows if row["support_role"] == "in_support"
    )
    rare_coverage, rare_count = coverage(
        row for row in rows if row["support_role"] != "in_support"
    )
    visible_coverage, visible_count = coverage(
        row for row in rows if row["network_positive_window_present"]
    )
    absent_coverage, absent_count = coverage(
        row for row in rows if not row["network_positive_window_present"]
    )
    summary = {
        "all_event_coverage": all_coverage,
        "all_event_count": all_count,
        "in_support_event_coverage": support_coverage,
        "in_support_event_count": support_count,
        "out_of_support_event_coverage": rare_coverage,
        "out_of_support_event_count": rare_count,
        "network_visible_event_coverage": visible_coverage,
        "network_visible_event_count": visible_count,
        "network_absent_event_coverage": absent_coverage,
        "network_absent_event_count": absent_count,
        "event_without_mapped_test_window_count": sum(
            row["mapped_test_window_count"] == 0 for row in rows
        ),
    }
    return rows, summary


def aggregate_results(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[tuple[str, float], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(row["model"], row["false_alert_budget_per_hour"])].append(row)
    output: dict[str, Any] = {}
    for (model, budget), material in sorted(grouped.items()):
        fold_ids = sorted({int(row["fold"]) for row in material})
        metrics: dict[str, Any] = {}
        for metric in METRICS_TO_SUMMARIZE:
            fold_means = []
            for fold_id in fold_ids:
                values_in_fold = [
                    float(row[metric])
                    for row in material
                    if int(row["fold"]) == fold_id and math.isfinite(float(row[metric]))
                ]
                if values_in_fold:
                    fold_means.append(mean(values_in_fold))
            metrics[metric] = {
                "mean_of_fold_means": mean(fold_means) if fold_means else math.nan,
                "sample_std_across_fold_means": stdev(fold_means) if len(fold_means) > 1 else 0.0,
                "independent_fold_count": len(fold_means),
                "fold_means": fold_means,
            }
        output.setdefault(model, {})[str(budget)] = {
            "configuration_rows": len(material),
            "independent_fold_count": len(fold_ids),
            "seeds_per_fold": len({int(row["seed"]) for row in material}),
            "metrics": metrics,
        }
    return output


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_experiment(
    features_path: Path,
    truth_path: Path,
    cases_path: Path,
    splits_path: Path,
    output_dir: Path,
    seeds: list[int],
    budgets: list[float],
    benign_stress_features_path: Path | None = None,
    benign_stress_truth_path: Path | None = None,
) -> dict[str, Any]:
    ids, feature_names, x = load_features(features_path)
    truth = load_truth(truth_path)
    cases = load_cases(cases_path)
    splits = json.loads(splits_path.read_text(encoding="utf-8"))
    if set(ids) != set(truth):
        raise ValueError("feature and truth IDs differ")
    id_to_index = {window_id: index for index, window_id in enumerate(ids)}
    y = np.asarray([truth[window_id]["network_positive"] for window_id in ids], dtype=int)
    window_seconds = int(splits["window_seconds"])

    stress_ids: list[str] = []
    stress_x: np.ndarray | None = None
    if (benign_stress_features_path is None) != (benign_stress_truth_path is None):
        raise ValueError("benign stress features and truth must be provided together")
    if benign_stress_features_path is not None and benign_stress_truth_path is not None:
        stress_ids, stress_feature_names, stress_x = load_features(benign_stress_features_path)
        stress_truth = load_truth(benign_stress_truth_path)
        if stress_feature_names != feature_names:
            raise ValueError("benign stress feature schema differs from Phase 2")
        if set(stress_ids) != set(stress_truth):
            raise ValueError("benign stress feature and truth IDs differ")
        stress_positive = sum(stress_truth[window_id]["network_positive"] for window_id in stress_ids)
        if stress_positive:
            raise ValueError(f"benign stress set contains {stress_positive} positive windows")

    metric_rows: list[dict[str, Any]] = []
    prediction_rows: list[dict[str, Any]] = []
    event_rows_out: list[dict[str, Any]] = []
    stress_prediction_rows: list[dict[str, Any]] = []

    for fold in splits["outer_folds"]:
        fold_id = int(fold["fold"])
        partition_ids = {
            name: fold["partitions"][name]["window_ids"] for name in ("train", "calibration", "test")
        }
        index_sets = {
            name: np.asarray([id_to_index[window_id] for window_id in window_ids], dtype=int)
            for name, window_ids in partition_ids.items()
        }
        combined = [window_id for name in partition_ids for window_id in partition_ids[name]]
        if len(combined) != len(ids) or len(combined) != len(set(combined)):
            raise ValueError(f"fold {fold_id}: partitions are not exhaustive and disjoint")

        for seed in seeds:
            for model_name in MODELS:
                train_index = index_sets["train"]
                calibration_index = index_sets["calibration"]
                test_index = index_sets["test"]
                model = fit_model(model_name, x[train_index], y[train_index], seed)
                calibration_scores = positive_scores(model, x[calibration_index])
                test_scores = positive_scores(model, x[test_index])
                stress_scores = positive_scores(model, stress_x) if stress_x is not None else None
                test_ids = partition_ids["test"]

                for position, window_id in enumerate(test_ids):
                    prediction_rows.append(
                        {
                            "fold": fold_id,
                            "seed": seed,
                            "model": model_name,
                            "window_id": window_id,
                            "network_positive": int(y[test_index[position]]),
                            "score": float(test_scores[position]),
                        }
                    )
                if stress_scores is not None:
                    for position, window_id in enumerate(stress_ids):
                        stress_prediction_rows.append(
                            {
                                "fold": fold_id,
                                "seed": seed,
                                "model": model_name,
                                "window_id": window_id,
                                "score": float(stress_scores[position]),
                            }
                        )

                for budget in budgets:
                    calibration = select_threshold(
                        y[calibration_index], calibration_scores, budget, window_seconds
                    )
                    threshold = float(calibration["threshold"])
                    metrics = window_metrics(y[test_index], test_scores, threshold, window_seconds)
                    stress_metrics = (
                        benign_stress_metrics(stress_scores, threshold, window_seconds)
                        if stress_scores is not None
                        else {
                            "benign_stress_alert_count": 0,
                            "benign_stress_window_hours": 0.0,
                            "benign_stress_false_alerts_per_hour": math.nan,
                        }
                    )
                    per_event, event_summary = event_results(
                        test_ids, test_scores, threshold, truth, cases, fold_id
                    )
                    run_key = {
                        "fold": fold_id,
                        "seed": seed,
                        "model": model_name,
                        "false_alert_budget_per_hour": budget,
                    }
                    metric_rows.append(
                        {**run_key, **calibration, **metrics, **event_summary, **stress_metrics}
                    )
                    for event_row in per_event:
                        event_rows_out.append({**run_key, **event_row})

    output_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = output_dir / "stage_a_metrics.csv"
    predictions_path = output_dir / "stage_a_predictions.csv"
    events_path = output_dir / "stage_a_event_results.csv"
    stress_predictions_path = output_dir / "stage_a_benign_stress_predictions.csv"
    write_csv(metrics_path, metric_rows, list(metric_rows[0]))
    write_csv(predictions_path, prediction_rows, list(prediction_rows[0]))
    write_csv(events_path, event_rows_out, list(event_rows_out[0]))
    if stress_prediction_rows:
        write_csv(
            stress_predictions_path,
            stress_prediction_rows,
            list(stress_prediction_rows[0]),
        )

    summary = {
        "schema_version": "1.0",
        "experiment": "EviGate-APT Stage-A network alert baselines",
        "seeds": seeds,
        "false_alert_budgets_per_hour": budgets,
        "models": list(MODELS),
        "feature_count": len(feature_names),
        "window_count": len(ids),
        "network_positive_window_count": int(np.sum(y)),
        "benign_stress_window_count": len(stress_ids),
        "evaluation_unit": "60-second network window; event coverage is a secondary grouped endpoint",
        "threshold_policy": "calibration-only threshold maximizing positive-window true positives, then minimizing false positives, under the requested false-alert budget",
        "aggregate": aggregate_results(metric_rows),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "numpy": np.__version__,
            "scipy": scipy.__version__,
            "scikit_learn": sklearn.__version__,
            "joblib": joblib.__version__,
        },
        "source_files": {
            "features": {"path": str(features_path).replace("\\", "/"), "sha256": sha256_file(features_path)},
            "truth": {"path": str(truth_path).replace("\\", "/"), "sha256": sha256_file(truth_path)},
            "cases": {"path": str(cases_path).replace("\\", "/"), "sha256": sha256_file(cases_path)},
            "splits": {"path": str(splits_path).replace("\\", "/"), "sha256": sha256_file(splits_path)},
        },
        "output_files": {},
        "warnings": [
            "Phase-2 event labels are provisional union-derived labels because the official Attack_info.csv was unavailable.",
            "Only 83 of 4325 windows are network-positive; calibration folds contain 9-14 positives, so threshold stability must be reported.",
            "Event coverage includes network-absent cases as a separately named stress-test stratum, not as ordinary detector positives.",
            "Phase 1 benign stress results measure both false alerts and cross-phase distribution shift; they are not an IID estimate of Phase 2 specificity.",
        ],
    }
    for name, path in (
        ("metrics", metrics_path),
        ("predictions", predictions_path),
        ("event_results", events_path),
    ):
        summary["output_files"][name] = {
            "path": str(path).replace("\\", "/"),
            "sha256": sha256_file(path),
        }
    if benign_stress_features_path is not None and benign_stress_truth_path is not None:
        summary["source_files"]["benign_stress_features"] = {
            "path": str(benign_stress_features_path).replace("\\", "/"),
            "sha256": sha256_file(benign_stress_features_path),
        }
        summary["source_files"]["benign_stress_truth"] = {
            "path": str(benign_stress_truth_path).replace("\\", "/"),
            "sha256": sha256_file(benign_stress_truth_path),
        }
        summary["output_files"]["benign_stress_predictions"] = {
            "path": str(stress_predictions_path).replace("\\", "/"),
            "sha256": sha256_file(stress_predictions_path),
        }
    summary_path = output_dir / "stage_a_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, allow_nan=True) + "\n", encoding="utf-8")
    print(json.dumps({"summary": str(summary_path), "aggregate": summary["aggregate"]}, indent=2))
    return summary


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--features", type=Path, required=True)
    parser.add_argument("--truth", type=Path, required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--splits", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seeds", type=int, nargs="+", default=[11, 23, 37, 53, 71])
    parser.add_argument("--budgets", type=float, nargs="+", default=[0.5, 1.0])
    parser.add_argument("--benign-stress-features", type=Path)
    parser.add_argument("--benign-stress-truth", type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_experiment(
        args.features,
        args.truth,
        args.cases,
        args.splits,
        args.output_dir,
        args.seeds,
        args.budgets,
        args.benign_stress_features,
        args.benign_stress_truth,
    )


if __name__ == "__main__":
    main()
