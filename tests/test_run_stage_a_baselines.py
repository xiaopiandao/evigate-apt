import csv
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_stage_a_baselines import (  # noqa: E402
    aggregate_results,
    benign_stress_metrics,
    load_features,
    oversample_minority,
    select_threshold,
)


class StageABaselineTests(unittest.TestCase):
    def test_benign_stress_rate_uses_exposure_hours(self):
        scores = np.asarray([0.9, 0.8, 0.1, 0.0])
        result = benign_stress_metrics(scores, 0.5, 60)
        self.assertEqual(result["benign_stress_alert_count"], 2)
        self.assertAlmostEqual(result["benign_stress_false_alerts_per_hour"], 30.0)

    def test_feature_guard_accepts_fraction_but_rejects_label_token(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "features.csv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["window_id", "tcp_fraction"])
                writer.writeheader()
                writer.writerow({"window_id": "w1", "tcp_fraction": 0.5})
            _, names, _ = load_features(path)
            self.assertEqual(names, ["tcp_fraction"])

            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["window_id", "attack_label"])
                writer.writeheader()
                writer.writerow({"window_id": "w1", "attack_label": 1})
            with self.assertRaises(ValueError):
                load_features(path)

    def test_threshold_respects_false_alert_budget(self):
        y = np.asarray([0, 0, 0, 0, 1, 1])
        scores = np.asarray([0.9, 0.8, 0.1, 0.0, 0.85, 0.2])
        # Four negative one-minute windows = 1/15 hour; budget 15/h permits one FP.
        selected = select_threshold(y, scores, 15.0, 60)
        self.assertEqual(selected["allowed_false_positives"], 1)
        self.assertEqual(selected["calibration_false_positives"], 1)
        self.assertEqual(selected["calibration_true_positives"], 1)
        self.assertAlmostEqual(selected["threshold"], 0.85)

    def test_threshold_is_conservative_when_true_positive_count_ties(self):
        y = np.asarray([0, 0, 1])
        scores = np.asarray([0.8, 0.2, 0.9])
        selected = select_threshold(y, scores, 30.0, 60)
        self.assertEqual(selected["calibration_true_positives"], 1)
        self.assertEqual(selected["calibration_false_positives"], 0)
        self.assertAlmostEqual(selected["threshold"], 0.9)

    def test_oversampling_is_seeded_and_balanced(self):
        x = np.arange(10, dtype=float).reshape(5, 2)
        y = np.asarray([0, 0, 0, 0, 1])
        x1, y1 = oversample_minority(x, y, 7)
        x2, y2 = oversample_minority(x, y, 7)
        self.assertTrue(np.array_equal(x1, x2))
        self.assertTrue(np.array_equal(y1, y2))
        self.assertEqual(int(np.sum(y1 == 0)), int(np.sum(y1 == 1)))

    def test_aggregation_uses_fold_means_not_seed_rows_as_independent_n(self):
        rows = []
        for fold, value in ((1, 0.2), (2, 0.8), (3, 0.5)):
            for seed in (11, 23):
                row = {
                    "fold": fold,
                    "seed": seed,
                    "model": "m",
                    "false_alert_budget_per_hour": 0.5,
                }
                row.update({metric: value for metric in (
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
                )})
                rows.append(row)
        result = aggregate_results(rows)["m"]["0.5"]
        self.assertEqual(result["configuration_rows"], 6)
        self.assertEqual(result["independent_fold_count"], 3)
        metric = result["metrics"]["window_recall"]
        self.assertEqual(metric["independent_fold_count"], 3)
        self.assertAlmostEqual(metric["mean_of_fold_means"], 0.5)


if __name__ == "__main__":
    unittest.main()
