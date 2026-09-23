import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import audit_socket_seed_pruning as audit


class AuditSocketSeedPruningTests(unittest.TestCase):
    def test_joint_two_hop_can_exclude_disconnected_truth(self):
        graph = {
            "entities": [
                {"entity_id": "socket", "entity_kind": "socket", "attributes": {}, "features": {"address_match": True, "port_match": True}},
                {"entity_id": "near", "entity_kind": "process", "attributes": {"pid": "1"}, "features": {}},
                {"entity_id": "far", "entity_kind": "process", "attributes": {"pid": "2"}, "features": {}},
            ],
            "relations": [
                {"source_entity_id": "near", "target_entity_id": "socket"}
            ],
        }
        retained, seed_count = audit.two_hop_candidates(graph, "joint")
        self.assertEqual(seed_count, 1)
        self.assertEqual(retained, {"socket", "near"})
        self.assertNotIn("far", retained)

    def test_no_seed_preserves_full_pool(self):
        graph = {
            "entities": [
                {"entity_id": "p", "entity_kind": "process", "attributes": {}, "features": {}}
            ],
            "relations": [],
        }
        retained, seed_count = audit.two_hop_candidates(graph, "joint")
        self.assertEqual(seed_count, 0)
        self.assertEqual(retained, {"p"})


if __name__ == "__main__":
    unittest.main()
