import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from evaluate_evigate_llm import (  # noqa: E402
    calibration_thresholds,
    method_decision,
    prospective_hypotheses,
    summarize,
)


class EvaluateEviGateLlmTests(unittest.TestCase):
    def test_verifier_converts_invalid_contracted_attribution_to_abstention(self):
        output = {
            "parsed_response": {
                "decision": "attribute",
                "tactic": "collection",
            },
            "verification": {"contract_valid": False},
        }
        self.assertEqual(method_decision(output, "contracted_raw"), (True, "collection"))
        self.assertEqual(method_decision(output, "evigate_llm"), (False, None))

    def test_summary_counts_wrong_attributed_label_over_all_events(self):
        rows = [
            {
                "tactic": "collection",
                "prediction": "collection",
                "attributed": True,
                "correct": True,
                "parseable": True,
                "contract_valid": True,
                "unsupported_label": False,
                "hallucinated_entity": False,
                "hallucinated_anchor": False,
                "integrity_alarm": False,
            },
            {
                "tactic": "discovery",
                "prediction": "collection",
                "attributed": True,
                "correct": False,
                "parseable": True,
                "contract_valid": True,
                "unsupported_label": False,
                "hallucinated_entity": False,
                "hallucinated_anchor": False,
                "integrity_alarm": False,
            },
            {
                "tactic": "exfiltration",
                "prediction": None,
                "attributed": False,
                "correct": False,
                "parseable": True,
                "contract_valid": True,
                "unsupported_label": False,
                "hallucinated_entity": False,
                "hallucinated_anchor": False,
                "integrity_alarm": True,
            },
        ]
        result = summarize(rows)
        self.assertAlmostEqual(result["coverage"], 2 / 3)
        self.assertAlmostEqual(result["selective_risk"], 0.5)
        self.assertAlmostEqual(result["wrong_label_rate"], 1 / 3)

    def test_calibration_threshold_uses_only_eligible_attributions(self):
        truth = {
            f"s{i}": {"sample_id": f"s{i}", "test_fold": 1} for i in range(5)
        }
        outputs = []
        for i, confidence in enumerate((0.9, 0.8, 0.7, 0.6, 0.5)):
            outputs.append(
                {
                    "variant": "direct",
                    "sample_id": f"s{i}",
                    "parsed_response": {
                        "decision": "attribute",
                        "tactic": "collection",
                        "confidence": confidence,
                    },
                    "verification": {"contract_valid": True},
                }
            )
        thresholds, audit = calibration_thresholds(outputs, truth, 0.8)
        self.assertAlmostEqual(thresholds[("direct_llm", 1)], 0.6)
        self.assertEqual(audit["direct_llm"]["1"]["realized_accepted"], 4)

    def test_prospective_hypotheses_preserve_frozen_guardrails(self):
        methods = {
            "evigate_llm": {
                "clean": {"coverage": 0.65, "selective_risk": 0.20},
                "corruption_macro": {"wrong_label_rate": 0.10},
            },
            "self_abstaining_llm": {
                "clean": {"coverage": 0.90, "selective_risk": 0.18},
                "corruption_macro": {"wrong_label_rate": 0.18},
            },
        }
        result = prospective_hypotheses(methods)
        self.assertTrue(result["H1"]["passed"])
        self.assertFalse(result["H2"]["passed"])
        self.assertFalse(result["overall_method_success"])


if __name__ == "__main__":
    unittest.main()
