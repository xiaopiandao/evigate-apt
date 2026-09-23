import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from run_stage_c_selective_attribution import (  # noqa: E402
    CONTROLLER_FEATURE_NAMES,
    TACTICS,
    CaseRepresentation,
    controller_features,
    normalize_process_text,
    selection_mask,
)


class StageCSelectiveAttributionTests(unittest.TestCase):
    def test_text_normalization_masks_identity_and_decodes_payload(self):
        encoded = "dW5hbWUgLWE="  # uname -a
        value = normalize_process_text(
            f"sh -c echo {encoded} | base64 --decode 172.16.65.128 T1082 4133"
        )
        self.assertIn("uname -a", value)
        self.assertIn("<ip>", value)
        self.assertIn("<technique>", value)
        self.assertNotIn("172.16.65.128", value)
        self.assertNotIn("t1082", value)
        self.assertNotIn("4133", value)

    def test_fixed_coverage_selection_has_exact_count(self):
        rows = [
            {"case_id": f"c{i}", "score": score}
            for i, score in enumerate([0.2, 0.9, 0.4, 0.7])
        ]
        selected = selection_mask(rows, "score", 2)
        self.assertEqual(selected, {"c1", "c3"})

    def test_controller_vector_has_declared_dimension(self):
        summary_names = CONTROLLER_FEATURE_NAMES[12:]
        representation = CaseRepresentation(
            case_id="case",
            network=np.zeros(15),
            provenance=np.zeros(1),
            combined=np.zeros(1),
            summary={name: 0.0 for name in summary_names},
            entity_ids=[],
            entity_matrix=np.empty((0, 1)),
            entity_scores=np.empty(0),
            document="",
        )
        posterior = np.full(len(TACTICS), 1.0 / len(TACTICS))
        vector = controller_features(
            {"network": posterior, "provenance": posterior, "combined": posterior},
            representation,
        )
        self.assertEqual(len(vector), len(CONTROLLER_FEATURE_NAMES))
        self.assertTrue(np.isfinite(vector).all())

    def test_controller_names_exclude_truth_identity(self):
        forbidden = {"pid", "case_id", "label", "tactic", "ip", "port", "timestamp"}
        joined = " ".join(CONTROLLER_FEATURE_NAMES).lower()
        for token in forbidden:
            self.assertNotIn(token, joined)


if __name__ == "__main__":
    unittest.main()
