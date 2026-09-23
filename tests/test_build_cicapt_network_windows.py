import csv
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_cicapt_network_windows as builder


class BuildCicaptNetworkWindowsTests(unittest.TestCase):
    def test_unsorted_rows_are_aggregated_and_truth_is_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "network.csv"
            columns = [
                "ts", "Source IP", "Destination IP", "Source Port", "Destination Port",
                "Protocol_name", "label", "subLabel", "subLabelCat",
                *builder.NUMERIC_COLUMNS, *builder.FLAG_COLUMNS,
            ]
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=columns)
                writer.writeheader()
                base = {name: "1" for name in builder.NUMERIC_COLUMNS + builder.FLAG_COLUMNS}
                writer.writerows(
                    [
                        {**base, "ts": "125", "Source IP": "a", "Destination IP": "b", "Source Port": "1", "Destination Port": "80", "Protocol_name": "TCP", "label": "1", "subLabel": "collection", "subLabelCat": "stage", "Tot size": "100"},
                        {**base, "ts": "65", "Source IP": "a", "Destination IP": "c", "Source Port": "2", "Destination Port": "53", "Protocol_name": "UDP", "label": "0", "subLabel": "0", "subLabelCat": "0", "Tot size": "50"},
                        {**base, "ts": "121", "Source IP": "a", "Destination IP": "b", "Source Port": "1", "Destination Port": "80", "Protocol_name": "TCP", "label": "0", "subLabel": "0", "subLabelCat": "0", "Tot size": "50"},
                    ]
                )
            clusters = {
                "dataset": "test",
                "phase": 2,
                "clusters": [
                    {"cluster_id": "cicapt2_collection_001", "tactic": "collection", "start_epoch": 125, "end_epoch": 125}
                ],
            }
            features, truths, index = builder.build_outputs(path, clusters, 60)

        self.assertEqual(len(features), 2)
        self.assertEqual(features[1]["row_count"], 2)
        self.assertEqual(features[1]["tot_size_mean"], 75)
        self.assertEqual(features[1]["destination_port_80_fraction"], 1.0)
        self.assertEqual(features[1]["destination_port_well_known_fraction"], 1.0)
        self.assertNotIn("network_positive", features[1])
        self.assertNotIn("iat_mean", features[1])
        self.assertNotIn("flow_idle_time_mean", features[1])
        self.assertEqual(truths[1]["network_positive"], 1)
        self.assertEqual(index["audit"]["network_positive_windows"], 1)
        self.assertEqual(index["audit"]["mapped_unique_event_cases"], 1)
        self.assertEqual(
            index["metadata"]["destination_port_vocabulary_source"],
            "predefined common Internet/IIoT services, not selected from evaluation data",
        )

    def test_port_normalisation_and_fixed_vocabulary(self):
        self.assertEqual(builder.normalize_port("502.0"), "502")
        self.assertEqual(builder.normalize_port("70000"), "")
        self.assertIn("502", builder.FIXED_DESTINATION_PORTS)
        self.assertNotIn("52053", builder.FIXED_DESTINATION_PORTS)

    def test_window_ids_are_phase_specific(self):
        self.assertNotEqual(builder.window_id(60, 1), builder.window_id(60, 2))

    def test_feature_column_guard_rejects_labels(self):
        with self.assertRaises(ValueError):
            builder.assert_feature_columns_are_safe(["window_id", "attack_label"])


if __name__ == "__main__":
    unittest.main()
