import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_stage_b_feature_ablation import configurations, feature_groups  # noqa: E402


class StageBFeatureAblationTests(unittest.TestCase):
    def test_groups_and_configurations_are_nonempty(self):
        groups = feature_groups()
        configs = configurations()
        self.assertTrue(all(groups.values()))
        self.assertTrue(all(configs.values()))
        self.assertTrue(groups["process_semantics"].isdisjoint(configs["without_process_semantics"]))
        self.assertTrue(groups["socket_bridge"].isdisjoint(configs["without_socket_bridge"]))
        self.assertEqual(configs["temporal_degree_only"], groups["temporal_degree"])
        self.assertEqual(configs["process_semantics_only"], groups["process_semantics"])


if __name__ == "__main__":
    unittest.main()
