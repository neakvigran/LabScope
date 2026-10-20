"""Tests for Nmap evidence parsing."""

import tempfile
import unittest
from pathlib import Path

from labscope.parser import parse_nmap


class ParserTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "scan.xml"

    def write_xml(self, content):
        self.path.write_text(content, encoding="utf-8")

    def test_preserves_state_and_service_source(self):
        self.write_xml("""
        <nmaprun scanner="nmap" version="test">
          <host>
            <status state="up"/>
            <address addr="127.0.0.1" addrtype="ipv4"/>
            <ports>
              <port protocol="tcp" portid="8002">
                <state state="open" reason="syn-ack"/>
                <service name="teradataordbms" method="table" conf="3"/>
              </port>
            </ports>
          </host>
          <runstats><finished exit="success"/></runstats>
        </nmaprun>
        """)

        result = parse_nmap(self.path)
        host = result["hosts"][0]
        port = host["ports"][0]

        self.assertEqual(host["address"], "127.0.0.1")
        self.assertEqual(port["port"], 8002)
        self.assertEqual(port["state"], "open")
        self.assertEqual(port["service"]["method"], "table")

    def test_rejects_unfinished_scan(self):
        self.write_xml("<nmaprun><runstats/></nmaprun>")

        with self.assertRaises(ValueError):
            parse_nmap(self.path)

    def test_preserves_grouped_port_states(self):
        self.write_xml("""
        <nmaprun>
          <host>
            <status state="up"/>
            <address addr="127.0.0.1" addrtype="ipv4"/>
            <ports><extraports state="closed" count="10"/></ports>
          </host>
          <runstats><finished exit="success"/></runstats>
        </nmaprun>
        """)

        result = parse_nmap(self.path)
        host = result["hosts"][0]

        self.assertEqual(host["ports"], [])
        self.assertEqual(
            host["port_summaries"],
            [{"state": "closed", "count": "10"}],
        )


if __name__ == "__main__":
    unittest.main()
