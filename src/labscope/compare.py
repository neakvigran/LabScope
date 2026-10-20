"""Compare explicit port states from two LabScope JSON snapshots."""

import argparse
import json
from pathlib import Path


def index_snapshot(snapshot: dict) -> dict:
    """Index results by host, protocol, and port."""
    if snapshot.get("schema_version") != 1:
        raise ValueError("Only schema_version 1 is supported.")

    indexed = {}

    for host in snapshot["hosts"]:
        if host["status"] != "up":
            raise ValueError("Comparison requires all hosts to have status up.")

        if host.get("port_summaries"):
            raise ValueError(
                "Grouped port states are not supported by this comparator yet."
            )

        for port in host["ports"]:
            key = (host["address"], port["protocol"], port["port"])

            if key in indexed:
                raise ValueError(f"Duplicate port record: {key}")

            indexed[key] = port["state"]

    return indexed


def coverage(snapshot: dict) -> list:
    """Return a consistent representation of the declared scan coverage."""
    return sorted(
        (
            item["protocol"],
            item["services"],
            item["numservices"],
            item["type"],
        )
        for item in snapshot["scan_coverage"]
    )


def compare_results(before: dict, after: dict) -> list[dict]:
    """Return state changes only when snapshots have matching coverage."""
    if coverage(before) != coverage(after):
        raise ValueError("Scan coverage differs. Scan the same ports and protocol.")

    before_hosts = sorted(host["address"] for host in before["hosts"])
    after_hosts = sorted(host["address"] for host in after["hosts"])

    if before_hosts != after_hosts:
        raise ValueError("Host lists differ. Scan the same targets.")

    old = index_snapshot(before)
    new = index_snapshot(after)

    if old.keys() != new.keys():
        raise ValueError(
            "Explicit port records differ. Missing records are not closed ports."
        )

    changes = []

    for key in sorted(old):
        if old[key] != new[key]:
            address, protocol, port = key
            changes.append({
                "address": address,
                "protocol": protocol,
                "port": port,
                "before": old[key],
                "after": new[key],
            })

    return changes


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare port states in two LabScope JSON snapshots."
    )
    parser.add_argument("before", type=Path, help="Earlier results.json.")
    parser.add_argument("after", type=Path, help="Later results.json.")
    args = parser.parse_args()

    try:
        before = json.loads(args.before.read_text(encoding="utf-8"))
        after = json.loads(args.after.read_text(encoding="utf-8"))
        changes = compare_results(before, after)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        parser.error(str(error))

    if not changes:
        print("No port-state changes detected.")
        return

    print(f"Port-state changes: {len(changes)}")

    for change in changes:
        print(
            f"{change['address']} "
            f"{change['protocol']}/{change['port']}: "
            f"{change['before']} -> {change['after']}"
        )


if __name__ == "__main__":
    main()
