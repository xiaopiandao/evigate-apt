import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_stage4_diagnostics import (  # noqa: E402
    build_event_accounting,
    summarize_accounting,
)


class Stage4DiagnosticsTests(unittest.TestCase):
    def test_end_to_end_requires_stage_a_and_acceptance(self):
        stage_a = [
            {"case_id": "a", "covered": "1", "network_positive_window_present": "1"},
            {"case_id": "b", "covered": "0", "network_positive_window_present": "1"},
        ]
        stage_b = [
            {"case_id": "a", "truth_present": "1"},
            {"case_id": "b", "truth_present": "1"},
        ]
        template = {
            "tactic": "collection",
            "prediction": "collection",
            "correct": "1",
            "fixed_coverage_confidence_accept": "1",
            "fixed_coverage_controller_accept": "1",
            "fixed_coverage_integrity_accept": "1",
            "fixed_coverage_dual_accept": "1",
            "calibrated_confidence_accept": "1",
            "calibrated_controller_accept": "1",
            "calibrated_integrity_accept": "1",
            "calibrated_dual_accept": "1",
        }
        stage_c = [
            {"case_id": "a", **template},
            {"case_id": "b", **template},
        ]
        rows = build_event_accounting(stage_a, stage_b, stage_c)
        self.assertEqual(rows[0]["end_to_end_fixed_confidence_attributed"], 1)
        self.assertEqual(rows[1]["end_to_end_fixed_confidence_attributed"], 0)
        summary = summarize_accounting(rows)
        self.assertEqual(
            summary["rules"]["confidence"]["fixed"]["oracle_accepted"], 2
        )
        self.assertEqual(
            summary["rules"]["confidence"]["fixed"]["end_to_end_attributed"], 1
        )


if __name__ == "__main__":
    unittest.main()
