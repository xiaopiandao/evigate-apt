import csv
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "audit_cicapt_host_link.py"
SPEC = importlib.util.spec_from_file_location("audit_cicapt_host_link", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class HostLinkAuditHelpersTest(unittest.TestCase):
    def test_port_parser_accepts_csv_float_and_rejects_zero(self):
        self.assertEqual(MODULE.canonical_port("53.0"), 53)
        self.assertEqual(MODULE.canonical_port("65535"), 65535)
        self.assertIsNone(MODULE.canonical_port("0.0"))
        self.assertIsNone(MODULE.canonical_port("not-a-port"))

    def test_remote_ip_filter_rejects_loopback(self):
        self.assertFalse(MODULE.usable_remote_ip("127.0.0.1"))
        self.assertFalse(MODULE.usable_remote_ip("::1"))
        self.assertTrue(MODULE.usable_remote_ip("8.8.8.8"))

    def test_outcome_summary_uses_wrong_over_accepted(self):
        rows = [
            {
                "case_id": "a", "condition": "clean", "corruption_family": "",
                "cascade_attributed": "True", "cascade_correct": "True",
                "matched_margin_attributed": "True", "matched_margin_correct": "False",
            },
            {
                "case_id": "b", "condition": "clean", "corruption_family": "",
                "cascade_attributed": "True", "cascade_correct": "False",
                "matched_margin_attributed": "False", "matched_margin_correct": "False",
            },
            {
                "case_id": "a", "condition": "corrupted",
                "corruption_family": "context_replacement",
                "cascade_attributed": "True", "cascade_correct": "False",
                "matched_margin_attributed": "True", "matched_margin_correct": "False",
            },
            {
                "case_id": "b", "condition": "corrupted",
                "corruption_family": "context_replacement",
                "cascade_attributed": "False", "cascade_correct": "False",
                "matched_margin_attributed": "True", "matched_margin_correct": "False",
            },
        ]
        result = MODULE.outcome_summary(rows, {"a", "b"}, "EviGate-Bind")
        self.assertEqual(result["clean_accepted"], 2)
        self.assertEqual(result["clean_wrong"], 1)
        self.assertEqual(result["clean_selective_risk"], 0.5)
        self.assertEqual(result["context_replacement_wrong_label_rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
