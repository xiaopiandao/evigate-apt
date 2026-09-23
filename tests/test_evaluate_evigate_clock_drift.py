import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from evaluate_evigate_clock_drift import summarize, support_entity


class ClockDriftEvaluationTests(unittest.TestCase):
    def test_support_entity_resolves_package_local_rank(self):
        package = {
            "ranked_process_candidates": [
                {"rank": 1, "entity_id": "entity-a"},
                {"rank": 2, "entity_id": "entity-b"},
            ]
        }
        output = {"parsed_response": {"support_process_ref": "P2"}}
        self.assertEqual(support_entity(package, output), "entity-b")

    def test_summary_uses_event_denominator(self):
        rows = [
            {"x_accepted": True, "x_correct": True},
            {"x_accepted": True, "x_correct": False},
            {"x_accepted": False, "x_correct": False},
        ]
        result = summarize(rows, "x")
        self.assertEqual(result["accepted"], 2)
        self.assertEqual(result["correct_accepted"], 1)
        self.assertEqual(result["wrong_labels"], 1)
        self.assertAlmostEqual(result["wrong_label_rate"], 1 / 3)
        self.assertAlmostEqual(result["selective_risk"], 0.5)


if __name__ == "__main__":
    unittest.main()
