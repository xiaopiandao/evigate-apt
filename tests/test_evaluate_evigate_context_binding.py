import unittest

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_evigate_context_binding import (  # noqa: E402
    TACTICS,
    bhattacharyya_affinity,
    network_features,
    retention_threshold,
)


class ContextBindingTests(unittest.TestCase):
    def test_affinity_is_one_for_identical_distribution(self):
        distribution = {label: 0.2 for label in TACTICS}
        self.assertAlmostEqual(bhattacharyya_affinity(distribution, distribution), 1.0)

    def test_affinity_is_zero_for_disjoint_distribution(self):
        left = {label: 0.0 for label in TACTICS}
        right = {label: 0.0 for label in TACTICS}
        left[TACTICS[0]] = 1.0
        right[TACTICS[1]] = 1.0
        self.assertEqual(bhattacharyya_affinity(left, right), 0.0)

    def test_retention_threshold_uses_ceiling_target(self):
        threshold, target = retention_threshold([0.9, 0.8, 0.8, 0.4], 0.75)
        self.assertEqual(target, 3)
        self.assertEqual(threshold, 0.8)

    def test_network_features_are_normalized_and_identity_free(self):
        features = network_features(
            {
                "row_count": 10,
                "total_bytes": 100,
                "protocol_counts": {"TCP": 7, "UDP": 3},
                "top_destination_ports": [{"port": "80", "count": 5}],
                "top_source_ports": [{"port": "50000", "count": 2}],
            }
        )
        self.assertEqual(features["protocol_fraction::TCP"], 0.7)
        self.assertEqual(features["destination_port_fraction::80"], 0.5)
        self.assertFalse(any("case" in name or "sample" in name for name in features))


if __name__ == "__main__":
    unittest.main()
