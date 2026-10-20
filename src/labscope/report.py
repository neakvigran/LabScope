"""Generate Markdown reports from saved LabScope snapshots."""

import json
from datetime import datetime, timezone
from pathlib import Path

from labscope.compare import compare_results


def format_time(value) -> str:
    """Convert a Unix timestamp to a readable UTC time."""
    if value is None:
        return "Unknown"

    return datetime.fromtimestamp(
        int(value),
        tz=timezone.utc,
    ).isoformat()


def cell(value) -> str:
    """Keep values from breaking Markdown table cells."""
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def write_report(before_path: Path, after_path: Path, output: Path) -> None:
    """Compare snapshots and save a report without overwriting a file."""
    before = json.loads(before_path.read_text(encoding="utf-8"))
    after = json.loads(after_path.read_text(encoding="utf-8"))
    changes = compare_results(before, after)

    lines = [
        "# LabScope Port-State Comparison",
        "",
        "## Source evidence",
        "",
        "| Snapshot | File | Scan started (UTC) |",
        "|---|---|---|",
        (
            f"| Before | {cell(before_path)} | "
            f"{cell(format_time(before.get('started_at_unix')))} |"
        ),
        (
            f"| After | {cell(after_path)} | "
            f"{cell(format_time(after.get('started_at_unix')))} |"
        ),
        "",
        "## Results",
        "",
        f"Detected port-state changes: **{len(changes)}**.",
        "",
    ]

    if changes:
        lines.extend([
            "| Host | Protocol | Port | Before | After |",
            "|---|---|---|---|---|",
        ])

        for change in changes:
            lines.append(
                f"| {cell(change['address'])} "
                f"| {cell(change['protocol'])} "
                f"| {cell(change['port'])} "
                f"| {cell(change['before'])} "
                f"| {cell(change['after'])} |"
            )
    else:
        lines.append("No port-state changes detected.")

    lines.extend([
        "",
        "## Interpretation and limitations",
        "",
        "- This report compares saved evidence; it performs no new scan.",
        "- Port-state changes are observations, not confirmed vulnerabilities.",
        "- Service metadata changes are not compared in this version.",
        "- Matching scan coverage and explicit port records are required.",
        "- Grouped port-state summaries are not supported yet.",
        "",
    ])

    content = "\n".join(lines)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("x", encoding="utf-8") as report:
        report.write(content)

