import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from analyze_llm_certificate_prospective import paired_effect  # noqa: E402


class ProspectiveAnalysisTests(unittest.TestCase):
    def test_paired_effect_clusters_conditions_within_case(self):
        rows = []
        for case in ("a", "b"):
            for condition in ("x", "y"):
                rows.extend(
                    [
                        {"case_id": case, "method": "a", "condition": condition, "m": 1},
                        {"case_id": case, "method": "b", "condition": condition, "m": 0},
                    ]
                )
        result = paired_effect(rows, "a", "b", "m", {"x", "y"}, 1, 100)
        self.assertEqual(result["events"], 2)
        self.assertEqual(result["effect_a_minus_b"], 1.0)
        self.assertEqual(result["bootstrap_95_ci"], [1.0, 1.0])


if __name__ == "__main__":
    unittest.main()
