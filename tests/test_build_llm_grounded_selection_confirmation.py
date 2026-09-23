import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_llm_grounded_selection_confirmation import add_explicit_refs, rename_anchors  # noqa: E402


class GroundedSelectionBuilderTests(unittest.TestCase):
    def setUp(self):
        self.row = {
            "case_id": "case-a",
            "ranked_process_candidates": [
                {
                    "rank": 1,
                    "entity_id": "e1",
                    "anchors": [
                        {"anchor_id": "P1.command", "anchor_type": "command", "fact": "nmap -sV"}
                    ],
                }
            ],
        }

    def test_explicit_process_ref_is_visible(self):
        result = add_explicit_refs(self.row)
        self.assertEqual(result["ranked_process_candidates"][0]["process_ref"], "P1")

    def test_anchor_renaming_preserves_fact_and_process_ref(self):
        result, mapping = rename_anchors(self.row, 3)
        candidate = result["ranked_process_candidates"][0]
        self.assertEqual(candidate["process_ref"], "P1")
        self.assertEqual(candidate["anchors"][0]["fact"], "nmap -sV")
        self.assertEqual(candidate["anchors"][0]["anchor_id"], mapping["P1.command"])


if __name__ == "__main__":
    unittest.main()
