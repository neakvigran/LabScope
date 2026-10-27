"""Tests for Markdown report generation."""

import json
import tempfile
import unittest
from pathlib import Path

from labscope.report import write_report


def snapshot(state):
    """Create a small, valid scan snapshot for testing."""
    return {
        "schema_version": 1,
        "started_at_unix": "1792466727",
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


class ReportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)

        self.directory = Path(directory.name)
        self.before = self.directory / "before.json"
        self.after = self.directory / "after.json"
        self.output = self.directory / "reports" / "comparison.md"

        self.save_snapshot(self.before, "open")
        self.save_snapshot(self.after, "closed")

    def save_snapshot(self, path, state):
        path.write_text(
            json.dumps(snapshot(state)),
            encoding="utf-8",
        )

    def test_changed_port_appears_in_report(self):
        write_report(self.before, self.after, self.output)

        content = self.output.read_text(encoding="utf-8")

        self.assertIn("Detected port-state changes: **1**.", content)
        self.assertIn(
            "| 127.0.0.1 | tcp | 8002 | open | closed |",
            content,
        )
        self.assertIn(str(self.before), content)
        self.assertIn(str(self.after), content)
        self.assertIn("2026-10-20T03:25:27+00:00", content)

    def test_unchanged_snapshots_produce_no_change_report(self):
        self.save_snapshot(self.after, "open")

        write_report(self.before, self.after, self.output)

        content = self.output.read_text(encoding="utf-8")

        self.assertIn("Detected port-state changes: **0**.", content)
        self.assertIn("No port-state changes detected.", content)
        self.assertNotIn("| open | closed |", content)

    def test_existing_report_is_preserved(self):
        self.output.parent.mkdir(parents=True)
        self.output.write_text("Original evidence\n", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            write_report(self.before, self.after, self.output)

        self.assertEqual(
            self.output.read_text(encoding="utf-8"),
            "Original evidence\n",
        )


if __name__ == "__main__":
    unittest.main()
