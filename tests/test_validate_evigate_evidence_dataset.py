import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import validate_evigate_evidence_dataset as validator


class ValidateEviGateEvidenceDatasetTests(unittest.TestCase):
    def safe_pair(self):
        input_record = {
            "schema_version": "1.0",
            "case_id": "case_0123456789abcdef0123",
            "network_alert": {"row_count": 1},
            "provenance_candidate_graph": {
                "candidate_entity_count": 1,
                "relation_count": 0,
                "entities": [
                    {"entity_id": "p1", "attributes": {"pid": "42"}}
                ],
                "relations": [],
            },
            "decision_placeholder": {},
        }
        truth_record = {
            "case_id": input_record["case_id"],
            "source_cluster_id": "secret_cluster",
            "network_ground_truth": {"positive_row_count": 1},
            "provenance_ground_truth": {
                "malicious_candidate_entity_ids": ["p1"],
                "malicious_candidate_process_ids": ["p1"],
                "malicious_candidate_pids": ["42"],
            },
        }
        return input_record, truth_record

    def test_valid_pair_passes(self):
        input_record, truth_record = self.safe_pair()
        report = validator.validate_records([input_record], [truth_record], expected_count=1)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["cases_with_malicious_candidate_pid"], 1)

    def test_orphan_truth_entity_fails(self):
        input_record, truth_record = self.safe_pair()
        truth_record["provenance_ground_truth"]["malicious_candidate_entity_ids"] = ["missing"]
        with self.assertRaises(ValueError):
            validator.validate_records([input_record], [truth_record])


if __name__ == "__main__":
    unittest.main()
