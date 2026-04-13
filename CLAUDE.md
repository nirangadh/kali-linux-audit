# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the Audit

The tool requires root and must be run from the repo directory:

```bash
sudo ./kali_audit.sh                          # full audit
sudo ./kali_audit.sh --skip-network           # skip firewall/port checks
sudo ./kali_audit.sh --output-dir /tmp/out    # custom report directory
sudo ./kali_audit.sh --quiet --plain          # no ANSI colour, no stdout banner
```

Python core standalone (rarely needed):
```bash
sudo python3 core_audit.py --json-out report.json [--skip-network 0|1] [--plain]
```

Each run produces two files in `audit_reports/` (or `--output-dir`):
- `audit_<timestamp>.log` — full human-readable log
- `audit_<timestamp>.json` — machine-readable findings + score

## Architecture

**Two-layer design:**

1. **`kali_audit.sh`** — Bash wrapper responsible for sections 1–7:
   - System identity, users/auth, filesystem permissions, network/firewall, services, kernel sysctl, package status.
   - Manages the log file, ANSI colour mode, `BASH_WARNS`/`BASH_FAILS` counters, and the ERR trap.
   - At the end (section 8), forks `core_audit.py` and pipes its stdout into `log()`.

2. **`core_audit.py`** — Python deep-audit engine:
   - Produces the JSON report (`--json-out`). The bash wrapper reads `summary.warn` and `summary.fail` from this JSON to build the combined totals without double-counting.
   - Key types: `Finding(category, title, severity, detail, recommendation)` and `AuditReport` (collects findings, computes the percentage score).
   - `emit(report, finding)` is the single point that both prints a finding to stdout and appends it to the report.
   - Score formula: `(PASS×1 + WARN×0.5) / total_scored × 100` — INFO findings are excluded from scoring.

**Severity levels:** `PASS`, `INFO`, `WARN`, `FAIL` — only the last three affect the score.

**Colour/plain mode:** Both scripts respect `--plain` flag and `NO_COLOR=1` env var, and auto-disable ANSI when stdout is not a TTY.

## JSON Schema

```json
{
  "version": "1.1.0",
  "hostname": "...",
  "timestamp": "...",
  "kernel": "...",
  "score": 85,
  "summary": { "pass": N, "info": N, "warn": N, "fail": N },
  "findings": [
    { "category": "...", "title": "...", "severity": "WARN",
      "detail": "...", "recommendation": "..." }
  ]
}
```

Bump `AUDIT_VERSION` in `core_audit.py` when changing the JSON schema (MAJOR) or adding/changing checks (MINOR).
