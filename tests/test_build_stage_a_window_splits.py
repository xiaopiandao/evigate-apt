import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_stage_a_window_splits import (  # noqa: E402
    background_partition,
    build_event_block_owners,
    build_manifest,
)


class StageAWindowSplitTests(unittest.TestCase):
    def test_background_has_one_test_fold(self):
        for block in (0, 900, 1800, 99900):
            parts = [background_partition(block, fold) for fold in (1, 2, 3)]
            self.assertEqual(parts.count("test"), 1)

    def test_event_block_conflict_is_rejected(self):
        split = {
            "embargo_groups": [
                {"group_id": "a", "start_epoch": 100, "end_epoch": 200},
                {"group_id": "b", "start_epoch": 300, "end_epoch": 400},
            ],
            "outer_folds": [
                {
                    "fold": 1,
                    "partitions": {
                        "train": {"embargo_group_ids": ["a"]},
                        "calibration": {"embargo_group_ids": []},
                        "test": {"embargo_group_ids": ["b"]},
                    },
                }
            ],
        }
        with self.assertRaises(ValueError):
            build_event_block_owners(split, 900)

    def test_manifest_keeps_event_window_in_expected_partition(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            features = root / "features.csv"
            truth = root / "truth.csv"
            cases = root / "cases.jsonl"
            splits = root / "splits.json"

            with features.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["window_id", "x"])
                writer.writeheader()
                writer.writerows([{"window_id": "w1", "x": 1}, {"window_id": "w2", "x": 2}])
            with truth.open("w", encoding="utf-8", newline="") as handle:
                fields = ["window_id", "window_start_epoch", "network_positive", "event_case_ids_json"]
                writer = csv.DictWriter(handle, fieldnames=fields)
                writer.writeheader()
                writer.writerow(
                    {
                        "window_id": "w1",
                        "window_start_epoch": 60,
                        "network_positive": 1,
                        "event_case_ids_json": '["case1"]',
                    }
                )
                writer.writerow(
                    {
                        "window_id": "w2",
                        "window_start_epoch": 1800,
                        "network_positive": 0,
                        "event_case_ids_json": "[]",
                    }
                )
            cases.write_text(
                json.dumps(
                    {
                        "case_id": "case1",
                        "event": {"tactic": "collection"},
                        "split_membership": [
                            {"fold": 1, "partition": "test", "supervised_eligible": True},
                            {"fold": 2, "partition": "train", "supervised_eligible": True},
                            {"fold": 3, "partition": "calibration", "supervised_eligible": True},
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            splits.write_text(
                json.dumps(
                    {
                        "embargo_seconds_each_side": 300,
                        "in_support_tactics": ["collection"],
                        "embargo_groups": [
                            {"group_id": "g1", "start_epoch": 0, "end_epoch": 120}
                        ],
                        "outer_folds": [
                            {
                                "fold": 1,
                                "partitions": {
                                    "train": {"embargo_group_ids": []},
                                    "calibration": {"embargo_group_ids": []},
                                    "test": {"embargo_group_ids": ["g1"]},
                                },
                            },
                            {
                                "fold": 2,
                                "partitions": {
                                    "train": {"embargo_group_ids": ["g1"]},
                                    "calibration": {"embargo_group_ids": []},
                                    "test": {"embargo_group_ids": []},
                                },
                            },
                            {
                                "fold": 3,
                                "partitions": {
                                    "train": {"embargo_group_ids": []},
                                    "calibration": {"embargo_group_ids": ["g1"]},
                                    "test": {"embargo_group_ids": []},
                                },
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            manifest = build_manifest(features, truth, cases, splits)
            fold = manifest["outer_folds"][0]
            self.assertIn("w1", fold["partitions"]["test"]["window_ids"])
            self.assertEqual(fold["audit"]["event_window_partition_mismatch_count"], 0)
            self.assertEqual(fold["audit"]["block_partition_overlap_count"], 0)
            self.assertTrue(manifest["audit"]["each_window_is_test_once_across_outer_folds"])


if __name__ == "__main__":
    unittest.main()
