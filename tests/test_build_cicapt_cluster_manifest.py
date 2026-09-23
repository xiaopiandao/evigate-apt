import csv
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_cicapt_cluster_manifest as builder


class BuildCicaptClusterManifestTests(unittest.TestCase):
    def test_union_clusters_are_tactic_specific_and_view_auditable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            network_path = root / "network.csv"
            provenance_path = root / "provenance.csv"

            with network_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=["ts", "label", "subLabel", "subLabelCat"]
                )
                writer.writeheader()
                writer.writerows(
                    [
                        {"ts": "10", "label": "1", "subLabel": "collection", "subLabelCat": "stage"},
                        {"ts": "20", "label": "1", "subLabel": "collection", "subLabelCat": "stage"},
                        {"ts": "25", "label": "0", "subLabel": "collection", "subLabelCat": "ignored"},
                        {"ts": "800", "label": "1", "subLabel": "discovery", "subLabelCat": "scan"},
                    ]
                )

            fields = ["label", "subLabel", "type", "pid", "time", "seen time", "start time"]
            with provenance_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerows(
                    [
                        {"label": "1", "subLabel": "collection", "type": "Process", "pid": "7", "time": "15"},
                        {"label": "1", "subLabel": "collection", "type": "Artifact", "pid": "", "time": "400"},
                        {"label": "1", "subLabel": "discovery", "type": "Process", "pid": "8", "seen time": "805"},
                        {"label": "1", "subLabel": "collection", "type": "Artifact", "pid": "", "time": ""},
                    ]
                )

            manifest = builder.build_manifest(
                network_path,
                provenance_path,
                gap_seconds=300,
                sensitivity_gaps_seconds=(60, 300, 600),
                include_hashes=False,
                fallback_reason="test",
            )

        self.assertTrue(manifest["derived_label"])
        self.assertEqual(manifest["summary"]["cluster_count"], 3)
        self.assertEqual(
            manifest["summary"]["clusters_by_tactic"],
            {"collection": 2, "discovery": 1},
        )
        first = manifest["clusters"][0]
        self.assertEqual(first["cluster_id"], "cicapt2_collection_001")
        self.assertEqual(first["views_present"], ["network", "provenance"])
        self.assertEqual(first["view_counts"], {"network": 2, "provenance": 1})
        self.assertEqual(first["malicious_pids_directly_observed"], ["7"])
        self.assertEqual(manifest["source_audit"]["provenance"]["rows_attack_missing_timestamp"], 1)
        self.assertEqual(
            {gap: result["cluster_count"] for gap, result in manifest["gap_sensitivity"].items()},
            {"60": 3, "300": 3, "600": 2},
        )

    def test_gap_must_be_positive(self):
        with self.assertRaises(ValueError):
            builder.cluster_observations([], 0)

    def test_pid_normalisation_removes_float_formatting(self):
        self.assertEqual(builder.normalise_pid("4133.0"), "4133")
        self.assertEqual(builder.normalise_pid("non-numeric"), "non-numeric")


if __name__ == "__main__":
    unittest.main()
