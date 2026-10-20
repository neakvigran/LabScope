# LabScope

A Python CLI for scoped reconnaissance and service-change detection
in explicitly authorized lab environments.

## Current functionality

- Command-line help
- Version output

## Planned functionality

- Explicit target allowlists and dry-run validation
- Controlled Nmap execution and XML parsing
- HTTP metadata collection
- Comparison of saved scan results
- JSON evidence and Markdown reports

## Development setup

Requires Python 3.11 or newer.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
labscope --help
