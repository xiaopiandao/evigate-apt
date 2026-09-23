import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from analyze_llm_grounded_selection_confirmation import paired_effect  # noqa: E402


class GroundedSelectionAnalysisTests(unittest.TestCase):
    def test_paired_effect_uses_only_proposal_correct_pairs(self):
        rows = [
            {"case_id": "a", "method": "m1", "condition": "f", "proposal_correct": 1, "x": 1},
            {"case_id": "a", "method": "m2", "condition": "f", "proposal_correct": 1, "x": 0},
            {"case_id": "b", "method": "m1", "condition": "f", "proposal_correct": 0, "x": 0},
            {"case_id": "b", "method": "m2", "condition": "f", "proposal_correct": 0, "x": 1},
        ]
        result = paired_effect(rows, "m1", "m2", "f", "x", 1, 100)
        self.assertEqual(result["events"], 1)
        self.assertEqual(result["effect_a_minus_b"], 1.0)


if __name__ == "__main__":
    unittest.main()
