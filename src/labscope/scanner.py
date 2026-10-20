"""Run controlled Nmap scans and preserve XML and JSON evidence."""

import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from labscope.parser import parse_nmap


def run_nmap(
    targets: list[str],
    ports: list[int],
    output: Path,
) -> Path:
    """Scan validated targets and save raw and structured evidence."""
    command = [
        "nmap",
        "-sT",
        "-Pn",
        "-n",
        "-T3",
        "--scan-delay", "100ms",
        "--max-retries", "1",
        "-p", ",".join(str(port) for port in ports),
        "-oX", "-",
        *targets,
    ]

    # Each run gets a new directory to preserve earlier evidence.
    output.mkdir(parents=True, exist_ok=False)

    (output / "command.json").write_text(
        json.dumps(command, indent=2) + "\n",
        encoding="utf-8",
    )

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except FileNotFoundError as error:
        raise RuntimeError("Nmap was not found. Install it first.") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "Nmap exceeded 60 seconds. The scan did not complete."
        ) from error

    (output / "stderr.txt").write_text(
        result.stderr,
        encoding="utf-8",
    )

    xml_path = output / "nmap.xml"
    xml_path.write_text(result.stdout, encoding="utf-8")

    if result.returncode != 0:
        raise RuntimeError(
            f"Nmap exited with status {result.returncode}. "
            f"Review {output / 'stderr.txt'}."
        )

    try:
        results = parse_nmap(xml_path)
    except (ValueError, KeyError, ET.ParseError) as error:
        raise RuntimeError(
            f"Nmap XML could not be parsed: {error}. "
            f"Raw evidence remains in {xml_path}."
        ) from error

    json_path = output / "results.json"
    with json_path.open("x", encoding="utf-8") as evidence:
        evidence.write(json.dumps(results, indent=2) + "\n")

    return xml_path
