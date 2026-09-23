import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_stage_c_gate_decomposition import (  # noqa: E402
    INTEGRITY_FEATURE_NAMES,
    dual_gate_score,
    empirical_percentile,
    integrity_feature_indices,
)


class StageCGateDecompositionTests(unittest.TestCase):
    def test_integrity_features_exclude_direct_classifier_confidence(self):
        self.assertNotIn("combined_confidence", INTEGRITY_FEATURE_NAMES)
        self.assertNotIn("combined_margin", INTEGRITY_FEATURE_NAMES)
        self.assertEqual(len(integrity_feature_indices()), len(INTEGRITY_FEATURE_NAMES))

    def test_empirical_percentile_uses_midrank_for_ties(self):
        self.assertAlmostEqual(empirical_percentile(2.0, [1.0, 2.0, 2.0, 3.0]), 0.5)
        self.assertAlmostEqual(empirical_percentile(0.0, [1.0, 2.0]), 0.0)
        self.assertAlmostEqual(empirical_percentile(4.0, [1.0, 2.0]), 1.0)

    def test_dual_gate_is_limited_by_weaker_percentile(self):
        score = dual_gate_score(0.9, 0.15, [0.2, 0.4, 0.6], [0.1, 0.2, 0.3])
        self.assertAlmostEqual(score, 1.0 / 3.0)


if __name__ == "__main__":
    unittest.main()
