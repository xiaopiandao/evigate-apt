import importlib.util
import csv
import io
import unittest
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "run_p1_diagnostics.py"
SPEC = importlib.util.spec_from_file_location("run_p1_diagnostics", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class P1DiagnosticHelpersTest(unittest.TestCase):
    def test_merge_intervals_merges_touching_ranges(self):
        self.assertEqual(
            MODULE.merge_intervals([(5, 7), (1, 3), (3, 4), (8, 9)]),
            [(1, 4), (5, 7), (8, 9)],
        )

    def test_interval_membership_uses_closed_endpoints(self):
        intervals = [(1.0, 4.0), (7.0, 9.0)]
        starts = [1.0, 7.0]
        self.assertTrue(MODULE.point_in_intervals(4.0, intervals, starts))
        self.assertFalse(MODULE.point_in_intervals(5.0, intervals, starts))
        self.assertTrue(MODULE.point_in_intervals(7.0, intervals, starts))

    def test_group_label_prefers_rarest_supported_tactic(self):
        group = {"tactics": {"collection": 1, "exfiltration": 1}}
        label = MODULE.group_label(
            group,
            {"collection", "exfiltration"},
            {"collection": 26, "exfiltration": 4},
        )
        self.assertEqual(label, "exfiltration")

    def test_boolean_parser(self):
        self.assertTrue(MODULE.as_bool("True"))
        self.assertFalse(MODULE.as_bool("False"))

    def test_tracked_csv_reader_preserves_embedded_newline_bytes(self):
        payload = b'a,b\r\n1,"two\r\nlines"\r\n3,four\r\n'
        tracked = MODULE.TrackedBinaryLines(io.BytesIO(payload))
        reader = csv.reader(tracked)
        self.assertEqual(next(reader), ["a", "b"])
        previous = tracked.byte_count
        self.assertEqual(next(reader), ["1", "two\r\nlines"])
        self.assertEqual(tracked.byte_count - previous, len(b'1,"two\r\nlines"\r\n'))


if __name__ == "__main__":
    unittest.main()
