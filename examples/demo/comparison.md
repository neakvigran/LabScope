# LabScope Port-State Comparison

## Source evidence

| Snapshot | File | Scan started (UTC) |
|---|---|---|
| Before | examples/demo/before.json | 2026-10-20T03:33:54+00:00 |
| After | examples/demo/after.json | 2026-10-20T03:40:26+00:00 |

## Results

Detected port-state changes: **1**.

| Host | Protocol | Port | Before | After |
|---|---|---|---|---|
| 127.0.0.1 | tcp | 8002 | open | closed |

## Interpretation and limitations

- This report compares saved evidence; it performs no new scan.
- Port-state changes are observations, not confirmed vulnerabilities.
- Service metadata changes are not compared in this version.
- Matching scan coverage and explicit port records are required.
- Grouped port-state summaries are not supported yet.
