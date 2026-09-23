import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_llm_permutation_debiased_inputs import build  # noqa: E402


class OrderDebiasedBuilderTests(unittest.TestCase):
    def test_shuffle_reassigns_verifiable_refs_and_separates_truth(self):
        evidence = [
            {
                "sample_id": "source-1",
                "case_id": "case-1",
                "machine_proposal": {"tactic": "collection"},
                "provenance_summary": {
                    "top_ranker_score": 0.9,
                    "ranker_score_margin": 0.2,
                },
                "ranked_process_candidates": [
                    {
                        "rank": 1,
                        "ranker_score": 0.9,
                        "entity_id": "malicious",
                        "anchors": [
                            {
                                "anchor_id": "P1.command",
                                "anchor_type": "command",
                                "fact": "tar /tmp/stage",
                            }
                        ],
                    },
                    {
                        "rank": 2,
                        "ranker_score": 0.7,
                        "entity_id": "foreign",
                        "anchors": [
                            {
                                "anchor_id": "P2.command",
                                "anchor_type": "command",
                                "fact": "whoami",
                            }
                        ],
                    },
                ],
            }
        ]
        study_truth = [
            {
                "sample_id": "source-1",
                "case_id": "case-1",
                "condition": "foreign_distractor_holdout",
                "proposal_correct": True,
                "tactic": "collection",
                "mutation_metadata": {"foreign_entity_id": "foreign"},
            }
        ]
        case_truth = [
            {
                "case_id": "case-1",
                "provenance_ground_truth": {
                    "malicious_candidate_process_ids": ["malicious"]
                },
            }
        ]

        inputs, truth = build(evidence, study_truth, case_truth, seed=9)

        self.assertEqual(len(inputs), 1)
        candidates = inputs[0]["ranked_process_candidates"]
        for index, candidate in enumerate(candidates, 1):
            self.assertEqual(candidate["rank"], index)
            self.assertEqual(candidate["process_ref"], f"P{index}")
            self.assertNotIn("ranker_score", candidate)
            for anchor in candidate["anchors"]:
                self.assertTrue(anchor["anchor_id"].startswith(f"P{index}."))
        self.assertNotIn("top_ranker_score", inputs[0]["provenance_summary"])
        self.assertNotIn("ranker_score_margin", inputs[0]["provenance_summary"])
        self.assertNotIn("malicious_entity_ids", inputs[0])
        self.assertEqual(truth[0]["malicious_entity_ids"], ["malicious"])


if __name__ == "__main__":
    unittest.main()
