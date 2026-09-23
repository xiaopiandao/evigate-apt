import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_stage_b_shortcut_audit import (  # noqa: E402
    family_test_folds,
    shortcut_configurations,
    truth_process_family,
)


class StageBShortcutAuditTests(unittest.TestCase):
    def test_feature_masks_are_nested_and_nonempty(self):
        configs = shortcut_configurations()
        self.assertTrue(configs["without_all_process_semantics"])
        self.assertLess(
            len(configs["without_all_process_semantics"]), len(configs["full"])
        )
        self.assertFalse(
            any(
                name.startswith("utility_")
                for name in configs["without_utility_indicators"]
            )
        )
        self.assertNotIn(
            "process_path_depth", configs["without_path_length_parent"]
        )

    def test_truth_process_family_is_order_invariant(self):
        truth = {
            "provenance_ground_truth": {
                "malicious_candidate_process_ids": ["p1", "p2"]
            }
        }
        entities = [
            {
                "entity_id": "p1",
                "entity_kind": "process",
                "attributes": {"name": "Bash", "exe": "/usr/bin/bash"},
            },
            {
                "entity_id": "p2",
                "entity_kind": "process",
                "attributes": {"name": "Curl", "exe": "/usr/bin/curl"},
            },
        ]
        case_a = {
            "case_id": "a",
            "provenance_candidate_graph": {"entities": entities},
        }
        case_b = {
            "case_id": "b",
            "provenance_candidate_graph": {"entities": list(reversed(entities))},
        }
        self.assertEqual(
            truth_process_family(case_a, truth), truth_process_family(case_b, truth)
        )

    def test_group_folds_never_split_a_family(self):
        families = {
            "a": "large",
            "b": "large",
            "c": "x",
            "d": "y",
            "e": "z",
            "f": "w",
        }
        folds = family_test_folds(families, n_splits=3)
        self.assertEqual(set(folds), set(families))
        observed = {}
        for case_id, family in families.items():
            observed.setdefault(family, set()).add(folds[case_id])
        self.assertTrue(all(len(values) == 1 for values in observed.values()))


if __name__ == "__main__":
    unittest.main()
