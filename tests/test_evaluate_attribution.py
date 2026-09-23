import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "evaluate_attribution.py"
SPEC = importlib.util.spec_from_file_location("evaluate_attribution", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class EvaluateAttributionTests(unittest.TestCase):
    def test_single_ground_truth_metrics(self):
        case = {
            "case_id": "c1",
            "ground_truth": {"candidate_ids": ["target"]},
        }
        prediction = {
            "ranked_candidates": [
                {"candidate_id": "other", "score": 1.0},
                {"candidate_id": "target", "score": 0.9},
            ],
            "execution_counts": {"target": 1, "other": 10},
            "counterfactual_eligible": True,
            "counterfactual_confirmed": True,
            "benign_preserved": True,
        }
        result = MODULE.evaluate_case(case, prediction, [1, 3])
        self.assertEqual(result.first_relevant_rank, 2)
        self.assertEqual(result.hits, {1: 0, 3: 1})
        self.assertAlmostEqual(result.reciprocal_rank, 0.5)
        self.assertAlmostEqual(result.localization_effort, 1.0)

    def test_aggregate_co_execution_delta(self):
        case = {
            "case_id": "c1",
            "ground_truth": {"candidate_ids": ["target"]},
        }
        prediction = {
            "ranked_candidates": [
                {"candidate_id": "target", "score": 1.0},
                {"candidate_id": "other", "score": 0.5},
            ],
            "execution_counts": {"target": 1, "other": 10},
            "counterfactual_eligible": False,
            "counterfactual_confirmed": False,
            "benign_preserved": None,
        }
        result = MODULE.evaluate_case(case, prediction, [1])
        aggregate = MODULE.aggregate([result], [1])
        self.assertEqual(aggregate["hit_at_k"]["1"], 1.0)
        self.assertEqual(aggregate["execution_frequency_hit_at_k"]["1"], 0.0)
        self.assertEqual(aggregate["co_execution_delta_hit_at_k"]["1"], 1.0)


if __name__ == "__main__":
    unittest.main()
