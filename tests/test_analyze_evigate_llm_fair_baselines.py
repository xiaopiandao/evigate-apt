from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from analyze_evigate_llm_fair_baselines import (  # noqa: E402
    build_summary,
    margin_rows,
    matched_thresholds,
)


def clean_row(case: str, fold: int, score: float, correct: int = 1) -> dict[str, str]:
    return {
        "case_id": case,
        "test_fold": str(fold),
        "tactic": "collection",
        "prediction": "collection" if correct else "discovery",
        "correct": str(correct),
        "margin_score": str(score),
        "calibrated_margin_accept": "1" if score >= 0.2 else "0",
    }


def corruption_row(
    case: str, fold: int, score: float, family: str, correct: int
) -> dict[str, str]:
    row = clean_row(case, fold, score, correct)
    row.update(
        {
            "corruption_family": family,
            "margin_reject": "1" if score < 0.2 else "0",
        }
    )
    return row


class FairBaselineTests(unittest.TestCase):
    def test_matched_thresholds_follow_evigate_accept_counts(self) -> None:
        clean = [
            clean_row("a", 1, 0.4),
            clean_row("b", 1, 0.3),
            clean_row("c", 1, 0.1),
            clean_row("d", 2, 0.5),
            clean_row("e", 2, 0.2),
        ]
        evigate = [
            {"test_fold": "1", "attributed": "True"},
            {"test_fold": "1", "attributed": "False"},
            {"test_fold": "1", "attributed": "False"},
            {"test_fold": "2", "attributed": "True"},
            {"test_fold": "2", "attributed": "True"},
        ]
        thresholds, targets = matched_thresholds(clean, evigate)
        self.assertEqual(targets, {1: 1, 2: 2})
        self.assertEqual(thresholds, {1: 0.4, 2: 0.2})

    def test_missing_process_rule_rejects_only_process_deletion(self) -> None:
        clean = [clean_row("a", 1, 0.4), clean_row("b", 1, 0.3)]
        corrupt = [
            corruption_row("a", 1, 0.4, "process_deletion", 0),
            corruption_row("b", 1, 0.3, "process_deletion", 0),
            corruption_row("a", 1, 0.4, "context_replacement", 0),
            corruption_row("b", 1, 0.3, "context_replacement", 0),
        ]
        rows = margin_rows(clean, corrupt, {1: 0.3})
        rule_rows = [
            row
            for row in rows
            if row["method"] == "margin_matched_count_missing_rule"
            and row["condition"] == "corrupted"
        ]
        process = [row for row in rule_rows if row["corruption_family"] == "process_deletion"]
        context = [row for row in rule_rows if row["corruption_family"] == "context_replacement"]
        self.assertFalse(any(row["accepted"] for row in process))
        self.assertTrue(all(row["accepted"] for row in context))

    def test_summary_reports_event_level_wrong_labels(self) -> None:
        rows = [
            {
                "method": "m",
                "condition": "clean",
                "corruption_family": "clean",
                "accepted": True,
                "correct": True,
                "wrong_label": False,
            },
            {
                "method": "m",
                "condition": "clean",
                "corruption_family": "clean",
                "accepted": True,
                "correct": False,
                "wrong_label": True,
            },
        ]
        for family in (
            "process_deletion",
            "socket_type_deletion",
            "time_shift",
            "random_entity_deletion",
            "context_replacement",
        ):
            rows.append(
                {
                    "method": "m",
                    "condition": "corrupted",
                    "corruption_family": family,
                    "accepted": False,
                    "correct": False,
                    "wrong_label": False,
                }
            )
        summary = build_summary(rows)["m"]
        self.assertEqual(summary["clean"]["coverage"], 1.0)
        self.assertEqual(summary["clean"]["selective_risk"], 0.5)
        self.assertEqual(summary["corruption_macro"]["wrong_label_rate"], 0.0)


if __name__ == "__main__":
    unittest.main()
