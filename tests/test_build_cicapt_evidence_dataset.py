import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_cicapt_evidence_dataset as builder


class BuildCicaptEvidenceDatasetTests(unittest.TestCase):
    def test_batch_builder_separates_truth_and_keeps_untimed_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            network_path = root / "network.csv"
            provenance_path = root / "provenance.csv"
            with network_path.open("w", encoding="utf-8", newline="") as handle:
                fields = [
                    "ts", "Source IP", "Destination IP", "Source Port",
                    "Destination Port", "Protocol_name", "Tot size", "label",
                    "subLabel", "subLabelCat",
                ]
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(
                    [
                        {"ts": "125", "Source IP": "10.0.0.1", "Destination IP": "10.0.0.2", "Source Port": "123", "Destination Port": "80", "Protocol_name": "TCP", "Tot size": "50", "label": "0", "subLabel": "0", "subLabelCat": "0"},
                        {"ts": "121", "Source IP": "10.0.0.1", "Destination IP": "10.0.0.2", "Source Port": "123", "Destination Port": "80", "Protocol_name": "TCP", "Tot size": "100", "label": "1", "subLabel": "collection", "subLabelCat": "stage"},
                    ]
                )
            provenance_fields = [
                "id", "type", "from", "to", "pid", "ppid", "name", "exe",
                "command line", "path", "subtype", "local address", "local port",
                "remote address", "remote port", "protocol", "time", "seen time",
                "start time", "operation", "label", "subLabel",
            ]
            with provenance_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=provenance_fields)
                writer.writeheader()
                writer.writerows(
                    [
                        {"id": "proc1", "type": "Process", "pid": "42", "name": "tool", "label": "1", "subLabel": "collection"},
                        {"id": "sock1", "type": "Artifact", "subtype": "network socket", "local address": "10.0.0.2", "local port": "80", "label": "0"},
                        {"type": "Used", "from": "proc1", "to": "sock1", "time": "122", "operation": "connect", "label": "1", "subLabel": "collection"},
                    ]
                )
            clusters = {
                "dataset": "test",
                "phase": 2,
                "clusters": [
                    {
                        "cluster_id": "cicapt2_collection_001",
                        "tactic": "collection",
                        "start_epoch": 121,
                        "end_epoch": 122,
                        "network_time_range": {"start_epoch": 121, "end_epoch": 121},
                        "views_present": ["network", "provenance"],
                        "malicious_pids_directly_observed": ["42"],
                        "derived_label": True,
                    }
                ],
            }
            splits = {
                "in_support_tactics": ["collection"],
                "outer_folds": [
                    {
                        "fold": 1,
                        "partitions": {
                            "train": {"all_cluster_ids": ["cicapt2_collection_001"], "supervised_in_support_cluster_ids": ["cicapt2_collection_001"]},
                            "calibration": {"all_cluster_ids": [], "supervised_in_support_cluster_ids": []},
                            "test": {"all_cluster_ids": [], "supervised_in_support_cluster_ids": []},
                        },
                    }
                ],
            }
            inputs, truths, index = builder.build_dataset(
                network_path,
                provenance_path,
                clusters,
                splits,
                network_window_seconds=60,
                context_radius_seconds=300,
            )
            shifted_inputs, _, shifted_index = builder.build_dataset(
                network_path,
                provenance_path,
                clusters,
                splits,
                network_window_seconds=60,
                context_radius_seconds=300,
                provenance_clock_offset_seconds=30,
            )

        self.assertEqual(index["case_count"], 1)
        self.assertEqual(index["provenance_clock_offset_seconds"], 0.0)
        self.assertEqual(shifted_index["provenance_clock_offset_seconds"], 30)
        shifted_relation = shifted_inputs[0]["provenance_candidate_graph"]["relations"][0]
        self.assertEqual(shifted_relation["time_delta_seconds"], 31.0)
        self.assertEqual(index["audit"]["network_windows_with_event_tactic"], 1)
        self.assertEqual(inputs[0]["network_alert"]["row_count"], 2)
        self.assertEqual(inputs[0]["network_alert"]["total_bytes"], 150)
        self.assertEqual(inputs[0]["provenance_candidate_graph"]["candidate_entity_count"], 2)
        self.assertEqual(
            truths[0]["provenance_ground_truth"]["malicious_candidate_pids"], ["42"]
        )
        self.assertEqual(
            truths[0]["provenance_ground_truth"]["direct_pid_candidate_recall_ceiling"], 1.0
        )
        serialized = json.dumps(inputs[0])
        self.assertNotIn("cicapt2_collection_001", serialized)
        self.assertNotIn('"tactic"', serialized)
        self.assertNotIn('"label"', serialized)
        self.assertIn('"pid": "42"', serialized)

    def test_leakage_assertion_rejects_truth_key(self):
        record = {
            "schema_version": "1.0",
            "case_id": "case_x",
            "network_alert": {"label": 1},
            "provenance_candidate_graph": {},
            "decision_placeholder": {},
        }
        with self.assertRaises(ValueError):
            builder.assert_input_is_leakage_safe(record, "cluster_secret")

    def test_port_normalisation_aligns_views_and_rejects_zero(self):
        self.assertEqual(builder.normalise_port("80.0"), "80")
        self.assertEqual(builder.normalise_port("80"), "80")
        self.assertEqual(builder.normalise_port("0.0"), "")

    def test_leakage_assertion_rejects_absolute_dataset_time(self):
        record = {
            "schema_version": "1.0",
            "case_id": "case_x",
            "network_alert": {"start_epoch": 123},
            "provenance_candidate_graph": {},
            "decision_placeholder": {},
        }
        with self.assertRaises(ValueError):
            builder.assert_input_is_leakage_safe(record, "cluster_secret")


if __name__ == "__main__":
    unittest.main()
