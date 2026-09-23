import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_stage_b_typed_ranker import (  # noqa: E402
    entity_features,
    feature_names,
    operation_group,
    process_contexts,
)


class StageBTypedRankerTests(unittest.TestCase):
    def test_operation_groups_are_coarse_and_fixed(self):
        self.assertEqual(operation_group("rename (read)"), "rename")
        self.assertEqual(operation_group("setuid"), "privilege")
        self.assertEqual(operation_group("unknown"), "other")

    def test_neighbor_socket_match_reaches_process_features(self):
        process = {
            "entity_id": "p",
            "entity_kind": "process",
            "attributes": {"exe": "/usr/bin/curl", "name": "curl", "ppid": "1"},
            "features": {
                "time_proximity": 0.9,
                "closest_abs_time_delta_seconds": 3,
                "degree_score": 1,
                "recency_degree_score": 1.9,
                "incident_edge_count": 1,
                "in_degree": 0,
                "out_degree": 1,
            },
        }
        socket = {
            "entity_id": "s",
            "entity_kind": "socket",
            "attributes": {"remote_address": "redacted", "remote_port": "443"},
            "features": {"address_match": True, "port_match": True, "time_proximity": 0.8},
        }
        case = {
            "network_alert": {
                "row_count": 10,
                "protocol_counts": {"TCP": 10},
                "source_ip_hhi": 0.2,
                "destination_ip_hhi": 0.3,
                "source_port_hhi": 0.4,
                "destination_port_hhi": 0.5,
            },
            "provenance_candidate_graph": {
                "entities": [process, socket],
                "relations": [
                    {
                        "source_entity_id": "p",
                        "target_entity_id": "s",
                        "relation_type": "WasGeneratedBy",
                        "operation": "connect",
                        "time_delta_seconds": -2,
                    }
                ],
            },
        }
        contexts = process_contexts(case)
        values = entity_features(case, process, contexts["p"])
        mapped = dict(zip(feature_names(), values))
        self.assertGreater(mapped["log_matched_socket_both"], 0)
        self.assertEqual(mapped["utility_network"], 1)
        self.assertGreater(mapped["operation_connect"], 0)

    def test_feature_names_exclude_raw_identity_tokens(self):
        forbidden = {"pid", "entity_id", "case_id", "raw_ip", "raw_port", "absolute_time"}
        self.assertFalse(forbidden & set(feature_names()))


if __name__ == "__main__":
    unittest.main()
