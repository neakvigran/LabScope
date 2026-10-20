"""Tests for scope validation and dry-run behavior."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from labscope.cli import load_scope, main


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.scope_path = Path(self.temp_dir.name) / "scope.json"
        self.write_scope()

    def write_scope(self, **changes):
        data = {
            "allowed_targets": ["127.0.0.1"],
            "ports": [3000],
        }
        data.update(changes)
        self.scope_path.write_text(json.dumps(data), encoding="utf-8")

    def run_cli(self, *arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch("sys.argv", ["labscope", *arguments]),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            try:
                main()
                code = 0
            except SystemExit as error:
                code = error.code

        return code, stdout.getvalue(), stderr.getvalue()

    def test_valid_scope_loads(self):
        targets, ports = load_scope(self.scope_path)
        self.assertEqual(targets, ["127.0.0.1"])
        self.assertEqual(ports, [3000])

    def test_invalid_ports_are_rejected(self):
        for invalid in [0, 65536, True, "3000"]:
            with self.subTest(port=invalid):
                self.write_scope(ports=[invalid])
                with self.assertRaises(ValueError):
                    load_scope(self.scope_path)

    def test_empty_allowlist_is_rejected(self):
        self.write_scope(allowed_targets=[])
        with self.assertRaises(ValueError):
            load_scope(self.scope_path)

    def test_approved_dry_run_succeeds(self):
        code, stdout, stderr = self.run_cli(
            "scan", "--scope", str(self.scope_path), "--dry-run"
        )
        self.assertEqual(code, 0)
        self.assertIn("Targets: 127.0.0.1", stdout)
        self.assertIn("TCP ports: 3000", stdout)
        self.assertEqual(stderr, "")

    def test_mixed_targets_reject_entire_request(self):
        code, stdout, stderr = self.run_cli(
            "scan",
            "--scope", str(self.scope_path),
            "--target", "127.0.0.1",
            "--target", "192.0.2.10",
            "--dry-run",
        )
        self.assertEqual(code, 2)
        self.assertIn("Out-of-scope targets: 192.0.2.10", stderr)
        self.assertEqual(stdout, "")

    def test_invalid_target_is_rejected(self):
        code, stdout, stderr = self.run_cli(
            "scan",
            "--scope", str(self.scope_path),
            "--target", "invalid",
            "--dry-run",
        )
        self.assertEqual(code, 2)
        self.assertTrue(stderr)
        self.assertEqual(stdout, "")


if __name__ == "__main__":
    unittest.main()
