import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from evigate_llm_contract import (  # noqa: E402
    build_user_prompt,
    extract_json_object,
    verify_response,
)


class EviGateLlmContractTests(unittest.TestCase):
    def setUp(self):
        self.case = {
            "case_id": "case_0123456789abcdef0123",
            "provenance_summary": {"process_candidate_count": 1},
            "ranked_process_candidates": [
                {
                    "entity_id": "entity-a",
                    "rank": 1,
                    "anchors": [
                        {"anchor_id": "P1.identity", "anchor_type": "identity", "fact": "name=curl"},
                        {"anchor_id": "P1.socket", "anchor_type": "socket", "fact": "socket_neighbors=1"},
                    ],
                }
            ],
        }

    def valid_response(self):
        return {
            "schema_version": "1.0",
            "case_id": self.case["case_id"],
            "decision": "attribute",
            "tactic": "command_and_control",
            "evidence_sufficient": True,
            "integrity_alarm": False,
            "confidence": 0.8,
            "cited_entity_ids": ["entity-a"],
            "cited_anchor_ids": ["P1.socket"],
            "reason_codes": ["sufficient_observed_support"],
        }

    def test_valid_grounded_attribution_passes(self):
        report = verify_response(self.valid_response(), self.case)
        self.assertTrue(report["contract_valid"])
        self.assertEqual(report["verifier_decision"], "attribute")

    def test_fabricated_anchor_is_rejected(self):
        response = self.valid_response()
        response["cited_anchor_ids"] = ["P9.fabricated"]
        report = verify_response(response, self.case)
        self.assertFalse(report["contract_valid"])
        self.assertIn("hallucinated_anchor_id", report["errors"])
        self.assertEqual(report["verifier_decision"], "abstain")

    def test_anchor_must_belong_to_cited_entity(self):
        response = self.valid_response()
        response["cited_entity_ids"] = ["entity-a", "entity-b"]
        self.case["ranked_process_candidates"].append(
            {
                "entity_id": "entity-b",
                "anchors": [{"anchor_id": "P2.identity", "anchor_type": "identity", "fact": "name=sh"}],
            }
        )
        response["cited_entity_ids"] = ["entity-a"]
        response["cited_anchor_ids"] = ["P2.identity"]
        report = verify_response(response, self.case)
        self.assertIn("anchor_owner_not_cited", report["errors"])

    def test_consistent_abstention_passes_without_citations(self):
        response = self.valid_response()
        response.update(
            {
                "decision": "abstain",
                "tactic": None,
                "evidence_sufficient": False,
                "integrity_alarm": True,
                "cited_entity_ids": [],
                "cited_anchor_ids": [],
                "reason_codes": ["missing_process_evidence"],
            }
        )
        report = verify_response(response, self.case)
        self.assertTrue(report["contract_valid"])
        self.assertEqual(report["verifier_decision"], "abstain")

    def test_json_extractor_rejects_trailing_prose(self):
        parsed, error = extract_json_object('{"a": 1} trailing')
        self.assertEqual(parsed, {"a": 1})
        self.assertEqual(error, "trailing_text")

    def test_missing_process_evidence_forces_integrity_alarm(self):
        response = self.valid_response()
        response.update(
            {
                "decision": "abstain",
                "tactic": None,
                "evidence_sufficient": False,
                "integrity_alarm": False,
                "cited_entity_ids": [],
                "cited_anchor_ids": [],
                "reason_codes": ["missing_process_evidence"],
            }
        )
        case = {
            "case_id": self.case["case_id"],
            "provenance_summary": {"process_candidate_count": 0},
            "ranked_process_candidates": [],
        }
        report = verify_response(response, case)
        self.assertFalse(report["contract_valid"])
        self.assertTrue(report["verifier_integrity_alarm"])
        self.assertIn("missing_process_without_integrity_alarm", report["errors"])

    def test_attribution_must_match_machine_proposal(self):
        response = self.valid_response()
        self.case["machine_proposal"] = {"tactic": "collection"}
        report = verify_response(response, self.case)
        self.assertIn("tactic_differs_from_machine_proposal", report["errors"])

    def test_direct_prompt_can_hide_machine_proposal(self):
        case = {
            **self.case,
            "network_event": {},
            "machine_proposal": {"tactic": "collection"},
        }
        hidden = build_user_prompt(case, include_machine_proposal=False)
        shown = build_user_prompt(case, include_machine_proposal=True)
        self.assertNotIn("machine_proposal", hidden)
        self.assertIn("machine_proposal", shown)

    def test_v2_contract_infers_decision_from_nullable_tactic(self):
        response = self.valid_response()
        response.pop("decision")
        response["schema_version"] = "2.0"
        report = verify_response(response, self.case)
        self.assertTrue(report["contract_valid"])
        self.assertEqual(report["verifier_decision"], "attribute")

        response.update(
            {
                "tactic": None,
                "evidence_sufficient": False,
                "cited_entity_ids": [],
                "cited_anchor_ids": [],
                "reason_codes": ["insufficient_process_evidence"],
            }
        )
        report = verify_response(response, self.case)
        self.assertTrue(report["contract_valid"])
        self.assertEqual(report["verifier_decision"], "abstain")

    def test_v3_compact_certificate_maps_process_reference(self):
        response = {
            "schema_version": "3.0",
            "case_id": self.case["case_id"],
            "tactic": "command_and_control",
            "evidence_sufficient": True,
            "integrity_alarm": False,
            "confidence": 0.8,
            "support_process_ref": "P1",
            "cited_anchor_ids": ["P1.socket"],
            "reason_codes": ["sufficient_observed_support"],
        }
        report = verify_response(response, self.case)
        self.assertTrue(report["contract_valid"])
        self.assertEqual(report["verifier_decision"], "attribute")

    def test_v3_rejects_unknown_process_reference(self):
        response = {
            "schema_version": "3.0",
            "case_id": self.case["case_id"],
            "tactic": "command_and_control",
            "evidence_sufficient": True,
            "integrity_alarm": False,
            "confidence": 0.8,
            "support_process_ref": "P9",
            "cited_anchor_ids": ["P1.socket"],
            "reason_codes": ["sufficient_observed_support"],
        }
        report = verify_response(response, self.case)
        self.assertFalse(report["contract_valid"])
        self.assertIn("hallucinated_process_ref", report["errors"])

    def test_v3_abstention_requires_empty_certificate(self):
        response = {
            "schema_version": "3.0",
            "case_id": self.case["case_id"],
            "tactic": None,
            "evidence_sufficient": False,
            "integrity_alarm": False,
            "confidence": 0.7,
            "support_process_ref": "P1",
            "cited_anchor_ids": ["P1.socket"],
            "reason_codes": ["insufficient_process_evidence"],
        }
        report = verify_response(response, self.case)
        self.assertFalse(report["contract_valid"])
        self.assertIn("abstain_with_support_citation", report["errors"])


if __name__ == "__main__":
    unittest.main()
