import csv
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import audit_cicapt_alignment as audit


class AuditCicaptAlignmentTests(unittest.TestCase):
    def test_provenance_label_reconciliation_separates_nodes_edges_and_time(self):
        fieldnames = [
            "label",
            "type",
            "subLabel",
            "time",
            "seen time",
            "start time",
        ]
        rows = [
            {
                "label": "1",
                "type": "Process",
                "subLabel": "collection",
                "seen time": "1",
            },
            {
                "label": "1",
                "type": "Artifact",
                "subLabel": "collection",
            },
            {
                "label": "1",
                "type": "WasDerivedFrom",
                "subLabel": "collection",
                "time": "2",
            },
            {
                "label": "1",
                "type": "Process",
                "subLabel": "initialAccess",
                "start time": "3",
            },
            {
                "label": "0",
                "type": "Process",
                "subLabel": "",
                "time": "4",
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provenance.csv"
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)
            events, reconciliation = audit.provenance_attacks(path)

        self.assertEqual(len(events), 3)
        self.assertEqual(reconciliation["labelled_rows"], 4)
        self.assertEqual(reconciliation["labelled_nodes"], 3)
        self.assertEqual(reconciliation["labelled_edges"], 1)
        self.assertEqual(reconciliation["timestamped_labelled_rows"], 3)
        self.assertEqual(reconciliation["paper_eight_tactic_nodes"], 2)

    def test_union_cluster_sensitivity_is_tactic_specific(self):
        network = [(0.0, "collection"), (30.0, "collection"), (400.0, "collection")]
        provenance = [(10.0, "collection"), (800.0, "discovery")]

        result = audit.union_cluster_sensitivity(network, provenance, [60, 300, 600])

        self.assertEqual(result["per_tactic"]["collection"], {"60": 2, "300": 2, "600": 1})
        self.assertEqual(result["per_tactic"]["discovery"], {"60": 1, "300": 1, "600": 1})
        self.assertEqual(result["total_clusters"], {"60": 3, "300": 3, "600": 2})


if __name__ == "__main__":
    unittest.main()
