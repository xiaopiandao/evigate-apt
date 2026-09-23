import sys
import unittest
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from run_stage_c_selector_baselines import (  # noqa: E402
    agreement_level,
    exact_aurc,
    normalized_entropy_score,
    posterior_feature_indices,
)


class StageCSelectorBaselineTests(unittest.TestCase):
    def test_entropy_score_orders_certain_above_uniform(self):
        certain = normalized_entropy_score(np.asarray([1.0, 0.0, 0.0]))
        uniform = normalized_entropy_score(np.asarray([1 / 3, 1 / 3, 1 / 3]))
        self.assertAlmostEqual(certain, 1.0)
        self.assertAlmostEqual(uniform, 0.0)
        self.assertGreater(certain, uniform)

    def test_agreement_levels(self):
        all_same = {
            "combined": np.asarray([0.8, 0.2, 0.0]),
            "network": np.asarray([0.6, 0.3, 0.1]),
            "provenance": np.asarray([0.7, 0.2, 0.1]),
        }
        pair = dict(all_same, provenance=np.asarray([0.1, 0.2, 0.7]))
        all_different = {
            "combined": np.asarray([0.8, 0.1, 0.1]),
            "network": np.asarray([0.1, 0.8, 0.1]),
            "provenance": np.asarray([0.1, 0.1, 0.8]),
        }
        self.assertEqual(agreement_level(all_same), 2)
        self.assertEqual(agreement_level(pair), 1)
        self.assertEqual(agreement_level(all_different), 0)

    def test_posterior_features_are_the_first_three_controller_features(self):
        self.assertEqual(posterior_feature_indices(), [0, 1, 2])

    def test_exact_aurc_uses_every_accepted_count(self):
        rows = [
            {"case_id": "a", "score": 0.9, "correct": 1},
            {"case_id": "b", "score": 0.8, "correct": 0},
            {"case_id": "c", "score": 0.7, "correct": 1},
        ]
        expected = (0.0 + 0.5 + 1 / 3) / 3
        self.assertAlmostEqual(exact_aurc(rows, "score"), expected)


if __name__ == "__main__":
    unittest.main()
