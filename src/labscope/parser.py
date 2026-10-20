"""Convert completed Nmap XML scans into structured JSON."""

import argparse
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap(path: Path) -> dict:
    """Read Nmap XML while preserving states and service-label sources."""
    root = ET.parse(path).getroot()

    if root.tag != "nmaprun":
        raise ValueError("The input is not an Nmap XML document.")

    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("The XML does not describe a successfully finished scan.")

    hosts = []

    for host in root.findall("host"):
        if host.get("timedout") == "true":
            raise ValueError("A host timed out; this scan is incomplete.")

        address = host.find("address[@addrtype='ipv4']")
        if address is None or not address.get("addr"):
            raise ValueError("A host is missing its IPv4 address.")

        status = host.find("status")
        ports = []

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or not state.get("state"):
                raise ValueError("A port is missing its state.")

            service = port.find("service")

            ports.append({
                "protocol": port.attrib["protocol"],
                "port": int(port.attrib["portid"]),
                "state": state.attrib["state"],
                "reason": state.get("reason"),
                "service": dict(service.attrib) if service is not None else None,
            })

        hosts.append({
            "address": address.attrib["addr"],
            "status": status.get("state") if status is not None else None,
            "ports": sorted(
                ports,
                key=lambda item: (item["protocol"], item["port"]),
            ),
            "port_summaries": [
                dict(summary.attrib)
                for summary in host.findall("ports/extraports")
            ],
        })

    return {
        "schema_version": 1,
        "scanner": {
            "name": root.get("scanner"),
            "version": root.get("version"),
        },
        "started_at_unix": root.get("start"),
        "finished_at_unix": finished.get("time"),
        "scan_coverage": [
            dict(info.attrib) for info in root.findall("scaninfo")
        ],
        "hosts": sorted(hosts, key=lambda item: item["address"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert Nmap XML evidence into structured JSON."
    )
    parser.add_argument("input", type=Path, help="Nmap XML file.")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        results = parse_nmap(args.input)
        content = json.dumps(results, indent=2) + "\n"

        # Exclusive creation prevents overwriting an existing result.
        with args.output.open("x", encoding="utf-8") as output:
            output.write(content)

    except (OSError, ValueError, KeyError, ET.ParseError) as error:
        parser.error(str(error))

    print(f"Structured results saved: {args.output}")


if __name__ == "__main__":
    main()
