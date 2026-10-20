"""Tests for port-state change detection."""

import copy
import unittest

from labscope.compare import compare_results


def snapshot(state):
    return {
        "schema_version": 1,
        "scan_coverage": [{
            "type": "connect",
            "protocol": "tcp",
            "numservices": "1",
            "services": "8002",
        }],
        "hosts": [{
            "address": "127.0.0.1",
            "status": "up",
            "ports": [{
                "protocol": "tcp",
                "port": 8002,
                "state": state,
            }],
            "port_summaries": [],
        }],
    }


class CompareTests(unittest.TestCase):
    def test_detects_open_to_closed(self):
        changes = compare_results(snapshot("open"), snapshot("closed"))

        self.assertEqual(changes, [{
            "address": "127.0.0.1",
            "protocol": "tcp",
            "port": 8002,
            "before": "open",
            "after": "closed",
        }])

    def test_unchanged_snapshot_has_no_changes(self):
        before = snapshot("open")
        self.assertEqual(compare_results(before, copy.deepcopy(before)), [])

    def test_different_scan_coverage_is_rejected(self):
        after = snapshot("closed")
        after["scan_coverage"][0]["services"] = "3000"

        with self.assertRaises(ValueError):
            compare_results(snapshot("open"), after)

    def test_missing_port_is_not_treated_as_closed(self):
        after = snapshot("closed")
        after["hosts"][0]["ports"] = []

        with self.assertRaises(ValueError):
            compare_results(snapshot("open"), after)

    def test_grouped_states_are_rejected(self):
        after = snapshot("closed")
        after["hosts"][0]["port_summaries"] = [
            {"state": "closed", "count": "1"}
        ]

        with self.assertRaises(ValueError):
            compare_results(snapshot("open"), after)


if __name__ == "__main__":
    unittest.main()
