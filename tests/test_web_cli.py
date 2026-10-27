"""Test the HTTP CLI without making network requests."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from labscope.cli import main


class WebCliTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)

        self.directory = Path(directory.name)
        self.scope = self.directory / "scope.json"
        self.output = self.directory / "evidence" / "web.json"

        self.scope.write_text(
            json.dumps({
                "allowed_targets": ["127.0.0.1"],
                "ports": [8002],
            }),
            encoding="utf-8",
        )

        inspection_patch = patch("labscope.cli.inspect_http")
        self.inspector = inspection_patch.start()
        self.addCleanup(inspection_patch.stop)

        self.inspector.return_value = {
            "url": "http://127.0.0.1:8002/",
            "status": 200,
            "reason": "OK",
            "title": "Test Shop",
            "headers": [],
        }

    def run_cli(self, url="http://127.0.0.1:8002/"):
        stdout = io.StringIO()
        stderr = io.StringIO()

        arguments = [
            "labscope", "web",
            "--scope", str(self.scope),
            "--url", url,
            "--output", str(self.output),
        ]

        with (
            patch("sys.argv", arguments),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            try:
                main()
                code = 0
            except SystemExit as error:
                code = error.code

        return code, stdout.getvalue(), stderr.getvalue()

    def test_authorized_request_saves_json(self):
        code, stdout, stderr = self.run_cli()

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("HTTP status: 200 OK", stdout)
        self.assertIn("Title: Test Shop", stdout)

        saved = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(saved, self.inspector.return_value)

        self.inspector.assert_called_once_with(
            "http://127.0.0.1:8002/",
            ["127.0.0.1"],
            [8002],
        )

    def test_unapproved_port_never_invokes_inspector(self):
        code, stdout, stderr = self.run_cli(
            "http://127.0.0.1:9000/"
        )

        self.assertEqual(code, 2)
        self.assertIn("Out-of-scope port", stderr)
        self.assertEqual(stdout, "")
        self.inspector.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_unapproved_ip_never_invokes_inspector(self):
        code, stdout, stderr = self.run_cli(
            "http://192.0.2.10:8002/"
        )

        self.assertEqual(code, 2)
        self.assertIn("Out-of-scope target", stderr)
        self.inspector.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_existing_evidence_is_preserved_without_request(self):
        self.output.parent.mkdir(parents=True)
        self.output.write_text("Original evidence\n", encoding="utf-8")

        code, stdout, stderr = self.run_cli()

        self.assertEqual(code, 2)
        self.assertIn("Output already exists", stderr)
        self.inspector.assert_not_called()
        self.assertEqual(
            self.output.read_text(encoding="utf-8"),
            "Original evidence\n",
        )

    def test_failed_inspection_does_not_save_success_result(self):
        self.inspector.side_effect = RuntimeError(
            "HTTP inspection failed: timed out"
        )

        code, stdout, stderr = self.run_cli()

        self.assertEqual(code, 2)
        self.assertIn("timed out", stderr)
        self.assertEqual(stdout, "")
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
