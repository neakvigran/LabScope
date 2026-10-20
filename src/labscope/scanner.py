"""Run controlled Nmap scans and preserve their output."""

import json
import subprocess
from pathlib import Path


def run_nmap(
    targets: list[str],
    ports: list[int],
    output: Path,
) -> Path:
    """Scan targets already validated by the CLI."""
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

    # Refuse to overwrite evidence from an earlier run.
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

    (output / "stderr.txt").write_text(result.stderr, encoding="utf-8")
    xml_path = output / "nmap.xml"
    xml_path.write_text(result.stdout, encoding="utf-8")

    if result.returncode != 0:
        raise RuntimeError(
            f"Nmap exited with status {result.returncode}. "
            f"Review {output / 'stderr.txt'}."
        )

    return xml_path
