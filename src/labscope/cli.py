"""Command-line interface for LabScope."""

import argparse
import ipaddress
import json
from pathlib import Path

from labscope.compare import compare_results
from labscope.report import write_report
from labscope.scanner import run_nmap
from labscope.web import inspect_http, validate_url


def ipv4(value: str) -> str:
    """Validate an IPv4 address and return its standard representation."""
    return str(ipaddress.IPv4Address(value))


def load_scope(path: Path) -> tuple[list[str], list[int]]:
    """Read and validate the authorized targets and ports."""
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Scope must be a JSON object.")

    targets = data.get("allowed_targets")
    ports = data.get("ports")

    if (
        not isinstance(targets, list)
        or not targets
        or any(not isinstance(target, str) for target in targets)
    ):
        raise ValueError(
            "allowed_targets must be a nonempty list of IPv4 strings."
        )

    allowed = sorted({ipv4(target) for target in targets})

    if (
        not isinstance(ports, list)
        or not ports
        or any(
            type(port) is not int or not 1 <= port <= 65535
            for port in ports
        )
    ):
        raise ValueError("ports must contain integers between 1 and 65535.")

    return allowed, sorted(set(ports))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="labscope",
        description=(
            "Scoped reconnaissance and change detection "
            "for explicitly authorized lab targets."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version="%(prog)s 0.1.0",
    )

    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser(
        "scan",
        help="Prepare or run a scoped scan.",
    )
    scan.add_argument(
        "--scope",
        type=Path,
        required=True,
        help="Path to the JSON scope file.",
    )
    scan.add_argument(
        "--target",
        action="append",
        help="Requested IPv4 address; repeat for multiple targets.",
    )
    scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the approved plan without sending network traffic.",
    )
    scan.add_argument(
        "--output",
        type=Path,
        help="New directory for scan evidence; required for real scans.",
    )

    compare = commands.add_parser(
        "compare",
        help="Compare port states in two saved JSON snapshots.",
    )
    compare.add_argument(
        "before",
        type=Path,
        help="Earlier results.json file.",
    )
    compare.add_argument(
        "after",
        type=Path,
        help="Later results.json file.",
    )
    compare.add_argument(
        "--report",
        type=Path,
        help="Save a Markdown report to a new file.",
    )

    web = commands.add_parser(
        "web",
        help="Collect HTTP metadata from an approved endpoint.",
    )
    web.add_argument(
        "--scope",
        type=Path,
        required=True,
        help="Path to the JSON scope file.",
    )
    web.add_argument(
        "--url",
        required=True,
        help="HTTP or HTTPS URL containing an authorized IPv4 address.",
    )
    web.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New JSON file for HTTP evidence.",
    )

    args = parser.parse_args()

    if args.command == "web":
        try:
            allowed, ports = load_scope(args.scope)

            # Reject invalid destinations before creating output or connecting.
            validate_url(args.url, allowed, ports)

            if args.output.exists():
                raise FileExistsError(
                    f"Output already exists: {args.output}. "
                    "Choose a new filename."
                )

            result = inspect_http(args.url, allowed, ports)
            content = json.dumps(result, indent=2) + "\n"

            args.output.parent.mkdir(parents=True, exist_ok=True)

            # Exclusive creation also protects against concurrent writers.
            with args.output.open("x", encoding="utf-8") as evidence:
                evidence.write(content)

        except (OSError, ValueError, RuntimeError) as error:
            parser.error(str(error))

        print(f"HTTP status: {result['status']} {result['reason']}")
        print(f"Title: {result['title'] or '(not found)'}")
        print(f"HTTP evidence saved: {args.output}")
        return

    if args.command == "compare":
        try:
            before = json.loads(args.before.read_text(encoding="utf-8"))
            after = json.loads(args.after.read_text(encoding="utf-8"))
            changes = compare_results(before, after)

            if args.report is not None:
                write_report(args.before, args.after, args.report)

        except (
            OSError,
            ValueError,
            KeyError,
            TypeError,
            AttributeError,
        ) as error:
            parser.error(str(error))

        if args.report is not None:
            print(f"Markdown report saved: {args.report}")

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

        return

    try:
        allowed, ports = load_scope(args.scope)

        requested = (
            sorted({ipv4(target) for target in args.target})
            if args.target
            else allowed
        )

        outside_scope = set(requested) - set(allowed)

        if outside_scope:
            raise ValueError(
                "Out-of-scope targets: " + ", ".join(sorted(outside_scope))
            )

    except (OSError, ValueError) as error:
        parser.error(str(error))

    if args.dry_run:
        print("DRY RUN — no network traffic sent")
        print("Targets:", ", ".join(requested))
        print("TCP ports:", ", ".join(str(port) for port in ports))
        return

    if args.output is None:
        parser.error("--output is required for real scans.")

    try:
        xml_path = run_nmap(requested, ports, args.output)
    except (OSError, RuntimeError) as error:
        parser.error(str(error))

    print(f"Scan complete. XML evidence: {xml_path}")
    print(f"Structured results: {args.output / 'results.json'}")


if __name__ == "__main__":
    main()
