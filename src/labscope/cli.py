"""Command-line interface for LabScope."""

import argparse


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

    parser.parse_args()
    parser.print_help()


if __name__ == "__main__":
    main()
