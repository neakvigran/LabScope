"""Command-line interface for LabScope."""

import argparse
import ipaddress
import json
from pathlib import Path


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
        raise ValueError("allowed_targets must be a nonempty list of IPv4 strings.")

    allowed = sorted({ipv4(target) for target in targets})

    if (
        not isinstance(ports, list)
        or not ports
        or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)
    ):
        raise ValueError("ports must contain integers between 1 and 65535.")

    return allowed, sorted(set(ports))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="labscope",
        description="Scoped reconnaissance for explicitly authorized lab targets.",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Prepare a scoped scan.")
    scan.add_argument("--scope", type=Path, required=True)
    scan.add_argument(
        "--target",
        action="append",
        help="Requested IPv4 address; repeat for multiple targets.",
    )
    scan.add_argument("--dry-run", action="store_true")

    args = parser.parse_args()

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

    if not args.dry_run:
        parser.error("Scanning is not implemented yet. Use --dry-run.")

    print("DRY RUN — no network traffic sent")
    print("Targets:", ", ".join(requested))
    print("TCP ports:", ", ".join(str(port) for port in ports))


if __name__ == "__main__":
    main()
