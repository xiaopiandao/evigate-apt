import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from evaluate_stage_b_retrieval_baselines import (  # noqa: E402
    analytic_random_case,
    rank_case,
    random_expected_mrr,
    random_hit_probability,
    summarize,
)


def entity(entity_id, recency, degree):
    return {
        "entity_id": entity_id,
        "entity_kind": "process",
        "attributes": {"pid": entity_id},
        "features": {
            "time_proximity": recency,
            "degree_score": degree,
            "recency_degree_score": recency + degree,
        },
    }


class StageBRetrievalBaselineTests(unittest.TestCase):
    def setUp(self):
        self.case_input = {
            "case_id": "case1",
            "provenance_candidate_graph": {
                "entities": [
                    entity("a", 0.9, 0.1),
                    entity("b", 0.8, 0.8),
                    entity("c", 0.7, 0.8),
                    {"entity_id": "f", "entity_kind": "file", "attributes": {}, "features": {}},
                ]
            },
        }
        self.case_truth = {
            "case_id": "case1",
            "event": {"tactic": "collection", "support_role": "in_support"},
            "split_membership": [
                {"fold": 1, "partition": "train"},
                {"fold": 2, "partition": "test"},
                {"fold": 3, "partition": "calibration"},
            ],
            "provenance_ground_truth": {"malicious_candidate_process_ids": ["b"]},
        }

    def test_recency_and_combined_rank_expected_process(self):
        recency = rank_case(self.case_input, self.case_truth, "recency", (1, 2))
        combined = rank_case(
            self.case_input, self.case_truth, "recency_plus_degree", (1, 2)
        )
        self.assertEqual(recency["deterministic_best_rank"], 2)
        self.assertEqual(recency["hit_at_1"], 0)
        self.assertEqual(combined["deterministic_best_rank"], 1)
        self.assertEqual(combined["hit_at_1"], 1)
        self.assertEqual(combined["process_candidate_count"], 3)
        self.assertEqual(combined["test_fold"], 2)

    def test_tie_bounds_are_explicit(self):
        tied = rank_case(self.case_input, self.case_truth, "degree", (1, 2))
        self.assertEqual(tied["optimistic_best_rank"], 1)
        self.assertEqual(tied["pessimistic_best_rank"], 2)
        self.assertEqual(tied["optimistic_hit_at_1"], 1)
        self.assertEqual(tied["pessimistic_hit_at_1"], 0)
        self.assertAlmostEqual(tied["expected_tie_hit_at_1"], 0.5)

    def test_missing_truth_reduces_all_case_ceiling(self):
        missing_truth = {**self.case_truth, "provenance_ground_truth": {"malicious_candidate_process_ids": []}}
        present = rank_case(self.case_input, self.case_truth, "recency", (1,))
        absent = rank_case(self.case_input, missing_truth, "recency", (1,))
        result = summarize([present, absent], (1,))
        self.assertEqual(result["candidate_pool_recall_ceiling"], 0.5)
        self.assertEqual(result["mrr_all_cases"], 0.25)

    def test_analytic_random_accounts_for_multiple_truth_entities(self):
        self.assertAlmostEqual(random_hit_probability(3, 1, 1), 1 / 3)
        self.assertAlmostEqual(random_hit_probability(3, 1, 2), 2 / 3)
        self.assertAlmostEqual(random_expected_mrr(3, 1), (1 + 1 / 2 + 1 / 3) / 3)
        row = analytic_random_case(self.case_input, self.case_truth, (1, 2))
        self.assertAlmostEqual(row["hit_at_1"], 1 / 3)


if __name__ == "__main__":
    unittest.main()
