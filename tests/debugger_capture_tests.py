"""Verify debugger capture capability negotiation and v3 event pagination."""

import sys
import unittest

sys.dont_write_bytecode = True
from run_debugger_fixture_tests import capture_available, fetch_records


class DebuggerCaptureTests(unittest.TestCase):
    def test_current_event_version_is_required(self):
        self.assertTrue(capture_available({"matrixhv_protocol": 10, "memory_event_v3": True,
                                           "memory_event_v2": False}))
        for status in ({}, {"matrixhv_protocol": 9, "memory_event_v3": True},
                       {"matrixhv_protocol": 10, "memory_event_v2": True},
                       {"matrixhv_protocol": 10, "memory_event_v3": False}):
            self.assertFalse(capture_available(status))

    def test_single_record_pages_drain_a_full_ring_and_empty_cpus(self):
        calls = []

        def neo(*operands):
            _, _, token, cpu, cursor, count = operands
            self.assertEqual(token, 42)
            self.assertEqual(count, 1)
            calls.append((cpu, cursor))
            head = 16 if cpu == 0 else 0
            return {"records": [{"sequence": cursor + 1}] if cursor < head else [],
                    "next": hex(cursor + 1 if cursor < head else cursor),
                    "head": hex(head), "dropped": "0x0"}

        records = fetch_records(neo, 42, 2)
        self.assertEqual([record["sequence"] for record in records], list(range(1, 17)))
        self.assertEqual(len(calls), 17)
        self.assertEqual(calls[-1], (1, 0))

    def test_stale_cursor_and_dropped_records_fail_the_fixture(self):
        def stale(*operands):
            return {"records": [{}], "next": "0x0", "head": "0x1", "dropped": "0x0"}

        with self.assertRaisesRegex(RuntimeError, "advance"):
            fetch_records(stale, 42, 1)

        def dropped(*operands):
            return {"records": [], "next": "0x0", "head": "0x0", "dropped": "0x1"}

        with self.assertRaises(AssertionError):
            fetch_records(dropped, 42, 1)


if __name__ == "__main__":
    unittest.main()
