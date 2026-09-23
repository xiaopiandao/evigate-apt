import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from bootstrap_evigate_llm import run  # noqa: E402


class BootstrapEviGateLlmTests(unittest.TestCase):
    def test_cluster_bootstrap_keeps_method_pairs(self):
        rows = []
        for case_id, self_correct, evigate_correct in (
            ("c1", False, True),
            ("c2", True, True),
        ):
            for method, correct in (
                ("self_abstaining_llm", self_correct),
                ("evigate_llm", evigate_correct),
            ):
                rows.append(
                    {
                        "method": method,
                        "case_id": case_id,
                        "condition": "clean",
                        "corruption_family": "clean",
                        "attributed": "True",
                        "correct": str(correct),
                    }
                )
                for family in ("deletion", "shift"):
                    rows.append(
                        {
                            "method": method,
                            "case_id": case_id,
                            "condition": "corrupted",
                            "corruption_family": family,
                            "attributed": "True",
                            "correct": str(correct),
                        }
                    )
        result = run(rows, iterations=100, seed=7)
        self.assertEqual(result["paired_cases"], 2)
        self.assertAlmostEqual(
            result["contrasts"]["H1_wrong_label_reduction_self_minus_evigate"][
                "observed"
            ],
            0.5,
        )


if __name__ == "__main__":
    unittest.main()
