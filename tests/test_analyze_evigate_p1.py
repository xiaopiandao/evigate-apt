import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from analyze_evigate_p1 import break_even, method_metrics  # noqa: E402


class EviGateP1AnalysisTests(unittest.TestCase):
    def test_clean_break_even_matches_declared_cost_model(self):
        self.assertAlmostEqual(break_even(8, 18, 10, 13), 0.4)

    def test_context_break_even_counts_all_foreign_issues_as_unsafe(self):
        self.assertAlmostEqual(break_even(18, 33, 48, 3), 1.0)

    def test_method_metrics_uses_event_level_wrong_labels(self):
        rows = []
        for family in (
            "clean",
            "process_deletion",
            "socket_type_deletion",
            "time_shift",
            "random_entity_deletion",
            "context_replacement",
        ):
            rows.append(
                {
                    "corruption_family": family,
                    "cascade_attributed": "True",
                    "cascade_correct": "False" if family == "context_replacement" else "True",
                }
            )
        metrics = method_metrics(rows)
        self.assertEqual(metrics["clean_accepted"], 1)
        self.assertEqual(metrics["clean_selective_risk"], 0.0)
        self.assertAlmostEqual(metrics["corruption_macro_wrong_label_rate"], 0.2)
        self.assertEqual(metrics["context_wrong_label_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
