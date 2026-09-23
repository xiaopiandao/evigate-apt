import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_llm_certificate_prospective_manifest import (  # noqa: E402
    contradict_proposal,
    inject_foreign_candidate,
    rename_references,
    suppress_semantic_evidence,
)


def case(case_id, proposal, truth, entity, rank=1):
    row = {
        "case_id": case_id,
        "machine_proposal": {
            "tactic": proposal,
            "confidence": 0.4,
            "margin": 0.1,
            "probabilities": {
                "collection": 0.4 if proposal == "collection" else 0.1,
                "command_and_control": 0.4 if proposal == "command_and_control" else 0.2,
                "credential_access": 0.4 if proposal == "credential_access" else 0.15,
                "discovery": 0.4 if proposal == "discovery" else 0.08,
                "exfiltration": 0.4 if proposal == "exfiltration" else 0.07,
            },
        },
        "provenance_summary": {
            "process_candidate_count": 1,
            "presented_process_count": 1,
            "top_ranker_score": 0.2,
            "ranker_score_margin": 0.2,
            "top3_matched_socket_both": 1,
            "top3_socket_neighbors": 1,
            "top3_file_neighbors": 1,
        },
        "ranked_process_candidates": [
            {
                "rank": rank,
                "entity_id": entity,
                "ranker_score": 0.2,
                "process": {"name": "nmap", "executable": "/usr/bin/nmap", "command_line": "nmap -sV"},
                "anchors": [
                    {"anchor_id": "P1.identity", "anchor_type": "identity", "fact": "name=nmap"},
                    {"anchor_id": "P1.command", "anchor_type": "command", "fact": "nmap -sV"},
                    {"anchor_id": "P1.temporal", "anchor_type": "temporal", "fact": "delta=1"},
                ],
            }
        ],
    }
    sidecar = {"case_id": case_id, "tactic": truth}
    return row, sidecar


class ProspectiveManifestTests(unittest.TestCase):
    def test_reference_renaming_preserves_facts(self):
        row, _ = case("a", "discovery", "discovery", "e1")
        renamed, maps = rename_references(row, 7)
        self.assertNotEqual(renamed["ranked_process_candidates"][0]["entity_id"], "e1")
        self.assertEqual(renamed["ranked_process_candidates"][0]["anchors"][0]["fact"], "name=nmap")
        self.assertEqual(len(maps["anchor_id_map"]), 3)

    def test_suppression_leaves_only_nondiagnostic_anchors(self):
        row, _ = case("a", "discovery", "discovery", "e1")
        suppressed = suppress_semantic_evidence(row)
        candidate = suppressed["ranked_process_candidates"][0]
        self.assertEqual(candidate["process"]["name"], "")
        self.assertEqual([a["anchor_type"] for a in candidate["anchors"]], ["temporal"])

    def test_contradiction_never_equals_truth_and_is_top_posterior(self):
        row, _ = case("a", "collection", "collection", "e1")
        changed, false_tactic = contradict_proposal(row, "collection")
        self.assertNotEqual(false_tactic, "collection")
        self.assertEqual(changed["machine_proposal"]["tactic"], false_tactic)
        self.assertEqual(
            changed["machine_proposal"]["confidence"],
            max(changed["machine_proposal"]["probabilities"].values()),
        )

    def test_foreign_injection_is_deterministic_and_marks_p1(self):
        target = case("a", "collection", "collection", "e1")
        donor = case("b", "discovery", "discovery", "e2")
        result1, meta1 = inject_foreign_candidate(target[0], target[1], [target, donor], 9)
        result2, meta2 = inject_foreign_candidate(target[0], target[1], [copy.deepcopy(target), copy.deepcopy(donor)], 9)
        self.assertEqual(result1, result2)
        self.assertEqual(meta1, meta2)
        self.assertEqual(meta1["foreign_process_ref"], "P1")
        self.assertEqual(result1["ranked_process_candidates"][0]["entity_id"], meta1["foreign_entity_id"])


if __name__ == "__main__":
    unittest.main()
