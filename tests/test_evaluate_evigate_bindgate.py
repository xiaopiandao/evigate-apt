import math
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from evaluate_evigate_bindgate import (  # noqa: E402
    exact_count_threshold,
    filter_pair_features,
    hard_negative_donors,
    posterior_margin,
    retention_threshold,
)


class EviGateBindGateTests(unittest.TestCase):
    def test_retention_threshold_uses_ceiling_count(self):
        threshold, count = retention_threshold([0.9, 0.8, 0.2], 0.67)
        self.assertEqual(count, 3)
        self.assertEqual(threshold, 0.2)

    def test_exact_count_threshold_handles_unattainable_target(self):
        self.assertEqual(exact_count_threshold([0.9, 0.2], 1), 0.9)
        self.assertEqual(exact_count_threshold([0.9, 0.2], 3), -math.inf)
        self.assertEqual(exact_count_threshold([0.9, 0.2], 0), math.inf)

    def test_posterior_margin(self):
        values = {
            "collection": 0.5,
            "command_and_control": 0.2,
            "credential_access": 0.1,
            "discovery": 0.1,
            "exfiltration": 0.1,
        }
        self.assertAlmostEqual(posterior_margin(values), 0.3)

    def test_hard_negative_family_ablation(self):
        packages = [
            {"network_event": {"x": 0.0}},
            {"network_event": {"x": 1.0}},
            {"network_event": {"x": 2.0}},
        ]
        labels = ["A", "A", "B"]
        same_only = hard_negative_donors(packages, labels, "same_tactic_only")
        different_only = hard_negative_donors(
            packages, labels, "different_tactic_only"
        )
        self.assertEqual(same_only[0], [1])
        self.assertEqual(different_only[0], [2])

    def test_binding_feature_ablation_contracts(self):
        features = {
            "affinity": 0.9,
            "network_confidence": 0.8,
            "network_probability::collection": 0.7,
            "provenance_confidence": 0.6,
            "provenance_probability::collection": 0.5,
            "posterior_absdiff::collection": 0.2,
            "posterior_product::collection": 0.4,
            "network::log_rows": 1.0,
            "provenance::log_processes": 2.0,
            "cross::log_rows::log_processes": 2.0,
        }
        without_network_posterior = filter_pair_features(
            features, "without_network_posterior"
        )
        self.assertNotIn("network_confidence", without_network_posterior)
        self.assertNotIn("affinity", without_network_posterior)
        self.assertIn("network::log_rows", without_network_posterior)
        self.assertIn("provenance_confidence", without_network_posterior)
        self.assertIn(
            "cross::log_rows::log_processes", without_network_posterior
        )

        network_only = filter_pair_features(features, "network_only")
        self.assertEqual(
            set(network_only),
            {
                "network_confidence",
                "network_probability::collection",
                "network::log_rows",
            },
        )

        provenance_only = filter_pair_features(features, "provenance_only")
        self.assertEqual(
            set(provenance_only),
            {
                "provenance_confidence",
                "provenance_probability::collection",
                "provenance::log_processes",
            },
        )

    def test_unknown_binding_feature_mode_fails_closed(self):
        with self.assertRaises(ValueError):
            filter_pair_features({"affinity": 1.0}, "not-a-mode")


if __name__ == "__main__":
    unittest.main()
