"""Test scanner execution and failure handling without network traffic."""

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from labscope.scanner import run_nmap


SUCCESS_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap" version="test" start="1792466727">
  <scaninfo type="connect" protocol="tcp"
            numservices="1" services="8002"/>
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="8002">
        <state state="open" reason="syn-ack"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished exit="success" time="1792466728"/>
  </runstats>
</nmaprun>
"""


class ScannerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.output = Path(directory.name) / "scan"

        # Replace the external process for every test in this class.
        process_patch = patch("labscope.scanner.subprocess.run")
        self.process = process_patch.start()
        self.addCleanup(process_patch.stop)

    def scan(self):
        return run_nmap(["127.0.0.1"], [8002], self.output)

    def test_success_saves_raw_and_structured_evidence(self):
        self.process.return_value = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout=SUCCESS_XML,
            stderr="",
        )

        xml_path = self.scan()

        self.assertEqual(xml_path, self.output / "nmap.xml")
        self.assertEqual(
            xml_path.read_text(encoding="utf-8"),
            SUCCESS_XML,
        )

        results = json.loads(
            (self.output / "results.json").read_text(encoding="utf-8")
        )
        port = results["hosts"][0]["ports"][0]

        self.assertEqual(port["port"], 8002)
        self.assertEqual(port["state"], "open")
        self.assertTrue((self.output / "command.json").exists())
        self.assertTrue((self.output / "stderr.txt").exists())

    def test_nonzero_exit_preserves_error_evidence(self):
        self.process.return_value = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=1,
            stdout="Partial output",
            stderr="Simulated Nmap failure",
        )

        with self.assertRaisesRegex(RuntimeError, "status 1"):
            self.scan()

        self.assertEqual(
            (self.output / "stderr.txt").read_text(encoding="utf-8"),
            "Simulated Nmap failure",
        )
        self.assertEqual(
            (self.output / "nmap.xml").read_text(encoding="utf-8"),
            "Partial output",
        )
        self.assertFalse((self.output / "results.json").exists())

    def test_missing_nmap_produces_clear_error(self):
        self.process.side_effect = FileNotFoundError("nmap")

        with self.assertRaisesRegex(RuntimeError, "Nmap was not found"):
            self.scan()

        self.assertFalse((self.output / "results.json").exists())

    def test_timeout_produces_clear_error(self):
        self.process.side_effect = subprocess.TimeoutExpired(
            cmd=["nmap"],
            timeout=60,
        )

        with self.assertRaisesRegex(RuntimeError, "exceeded 60 seconds"):
            self.scan()

        self.assertFalse((self.output / "results.json").exists())

    def test_invalid_xml_does_not_produce_structured_results(self):
        self.process.return_value = subprocess.CompletedProcess(
            args=["nmap"],
            returncode=0,
            stdout="<broken",
            stderr="",
        )

        with self.assertRaisesRegex(RuntimeError, "could not be parsed"):
            self.scan()

        self.assertEqual(
            (self.output / "nmap.xml").read_text(encoding="utf-8"),
            "<broken",
        )
        self.assertFalse((self.output / "results.json").exists())

    def test_existing_output_directory_prevents_execution(self):
        self.output.mkdir()
        evidence = self.output / "nmap.xml"
        evidence.write_text("Original evidence", encoding="utf-8")

        with self.assertRaises(FileExistsError):
            self.scan()

        self.process.assert_not_called()
        self.assertEqual(
            evidence.read_text(encoding="utf-8"),
            "Original evidence",
        )


if __name__ == "__main__":
    unittest.main()
