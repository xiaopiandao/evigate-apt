from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from audit_stage_b_benign_distractors import (  # noqa: E402
    case_network_top_five,
    combine_graphs,
    donor_index,
)


class BenignDistractorAuditTests(unittest.TestCase):
    def test_single_donor_is_prefixed_and_original_is_unchanged(self) -> None:
        original = {
            "provenance_candidate_graph": {
                "entities": [{"entity_id": "p", "entity_kind": "process"}],
                "relations": [],
                "candidate_entity_count": 1,
                "relation_count": 0,
                "entity_kind_counts": {"process": 1},
                "relation_type_counts": {},
                "operation_counts": {},
            }
        }
        donor = {
            "entities": [
                {"entity_id": "p", "entity_kind": "process"},
                {"entity_id": "f", "entity_kind": "file"},
            ],
            "relations": [{
                "relation_id": "r", "source_entity_id": "p", "target_entity_id": "f"
            }],
            "entity_kind_counts": {"process": 1, "file": 1},
            "relation_type_counts": {"Used": 1},
            "operation_counts": {"load": 1},
        }
        untouched = copy.deepcopy(original)
        combined = combine_graphs(original, (3, donor))["provenance_candidate_graph"]
        self.assertEqual(original, untouched)
        self.assertEqual(combined["candidate_entity_count"], 3)
        self.assertEqual(combined["relation_count"], 1)
        self.assertEqual(combined["entity_kind_counts"]["process"], 2)
        self.assertEqual(combined["relations"][0]["source_entity_id"], "phase1_donor_3_p")
        self.assertEqual(combined["relations"][0]["target_entity_id"], "phase1_donor_3_f")

    def test_case_network_uses_only_released_top_five(self) -> None:
        case = {"network_alert": {
            "top_source_ips": [{"value": "10.0.0.1", "count": 5}],
            "top_destination_ips": [{"value": "10.0.0.2", "count": 3}],
            "top_source_ports": [{"value": "80", "count": 5}],
            "top_destination_ports": [{"value": "443", "count": 3}],
        }}
        network = case_network_top_five(case)
        self.assertEqual(network.addresses, {"10.0.0.1", "10.0.0.2"})
        self.assertEqual(network.ports, {"80", "443"})

    def test_donor_selection_is_deterministic_and_band_limited(self) -> None:
        centers = [
            {"process_count": 7},
            {"process_count": 80},
            {"process_count": 10},
            {"process_count": 100},
        ]
        self.assertIn(donor_index("case-a", "small", centers), {0, 2})
        self.assertIn(donor_index("case-a", "busy", centers), {1, 3})
        self.assertEqual(
            donor_index("case-a", "busy", centers),
            donor_index("case-a", "busy", centers),
        )
        with self.assertRaises(ValueError):
            donor_index("case-a", "busy", centers, -1)


if __name__ == "__main__":
    unittest.main()
