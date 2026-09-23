import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import build_cicapt_split_manifest as splitter


class BuildCicaptSplitManifestTests(unittest.TestCase):
    def test_embargo_groups_merge_overlapping_context(self):
        clusters = [
            {"cluster_id": "a", "tactic": "x", "start_epoch": 100, "end_epoch": 110},
            {"cluster_id": "b", "tactic": "y", "start_epoch": 190, "end_epoch": 200},
            {"cluster_id": "c", "tactic": "x", "start_epoch": 500, "end_epoch": 510},
        ]
        groups = splitter.embargo_groups(clusters, embargo_seconds=50)
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0]["cluster_ids"], ["a", "b"])

    def test_realistic_small_manifest_has_disjoint_partitions(self):
        clusters = []
        timestamp = 0
        for tactic, count in (("a", 9), ("b", 6), ("c", 3), ("rare", 1)):
            for index in range(count):
                clusters.append(
                    {
                        "cluster_id": f"{tactic}_{index}",
                        "tactic": tactic,
                        "start_epoch": timestamp,
                        "end_epoch": timestamp + 1,
                    }
                )
                timestamp += 1000
        source = {
            "dataset": "test",
            "phase": 2,
            "manifest_status": "test",
            "derived_label": True,
            "clusters": clusters,
        }
        manifest = splitter.build_split_manifest(
            source,
            "hash",
            folds=3,
            embargo_seconds=10,
            min_tactic_support=3,
            calibration_fraction=0.2,
        )
        splitter.validate_split_manifest(manifest)
        self.assertEqual(manifest["in_support_tactics"], ["a", "b", "c"])
        self.assertEqual(manifest["out_of_support_tactics"], ["rare"])
        for fold in manifest["outer_folds"]:
            partitions = fold["partitions"]
            train = set(partitions["train"]["all_cluster_ids"])
            calibration = set(partitions["calibration"]["all_cluster_ids"])
            test = set(partitions["test"]["all_cluster_ids"])
            self.assertFalse(train & calibration)
            self.assertFalse(train & test)
            self.assertFalse(calibration & test)


if __name__ == "__main__":
    unittest.main()
