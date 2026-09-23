from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from analyze_evigate_p1_gate_discrimination import summarize  # noqa: E402


class GateDiscriminationTests(unittest.TestCase):
    def test_perfect_paired_auc_and_pass_counts(self) -> None:
        rows = [
            {"case_id": "a", "corruption_family": "clean", "binding_score": "0.9", "binding_pass": "True", "cascade_attributed": "True"},
            {"case_id": "b", "corruption_family": "clean", "binding_score": "0.8", "binding_pass": "True", "cascade_attributed": "False"},
            {"case_id": "a", "corruption_family": "context_replacement", "binding_score": "0.2", "binding_pass": "False", "cascade_attributed": "False"},
            {"case_id": "b", "corruption_family": "context_replacement", "binding_score": "0.1", "binding_pass": "False", "cascade_attributed": "False"},
        ]
        result = summarize(rows)
        self.assertEqual(result["events"], 2)
        self.assertEqual(result["clean_vs_foreign_score_auroc"], 1.0)
        self.assertEqual(result["foreign_binding_alarm"], 2)
        self.assertEqual(result["clean_cascade_accepted"], 1)

    def test_requires_one_to_one_pairing(self) -> None:
        rows = [
            {"case_id": "a", "corruption_family": "clean", "binding_score": "0.9", "binding_pass": "True", "cascade_attributed": "True"},
            {"case_id": "b", "corruption_family": "context_replacement", "binding_score": "0.1", "binding_pass": "False", "cascade_attributed": "False"},
        ]
        with self.assertRaises(ValueError):
            summarize(rows)


if __name__ == "__main__":
    unittest.main()
