import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "run_p0_diagnostics.py"
SPEC = importlib.util.spec_from_file_location("run_p0_diagnostics", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class P0DiagnosticHelpersTest(unittest.TestCase):
    def test_candidate_size_bins_are_closed_as_documented(self):
        self.assertEqual(MODULE.size_bin(20), "<=20")
        self.assertEqual(MODULE.size_bin(21), "21-100")
        self.assertEqual(MODULE.size_bin(100), "21-100")
        self.assertEqual(MODULE.size_bin(101), ">100")

    def test_boolean_csv_parser(self):
        for value in ("True", "true", "1", 1, "yes"):
            self.assertTrue(MODULE.as_bool(value))
        for value in ("False", "0", 0, "", None):
            self.assertFalse(MODULE.as_bool(value))

    def test_configured_ip_regex_is_specific_to_address_add(self):
        match = MODULE.CONFIGURED_IP_RE.search(
            "sudo ip addr add 172.16.63.2/24 dev ens33"
        )
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), "172.16.63.2")
        self.assertIsNone(MODULE.CONFIGURED_IP_RE.search("curl 172.16.63.2"))

    def test_selective_risk(self):
        self.assertAlmostEqual(MODULE.risk(8, 33), 8 / 33)
        self.assertTrue(MODULE.math.isnan(MODULE.risk(0, 0)))


if __name__ == "__main__":
    unittest.main()
