# kali-linux-audit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A non-invasive, read-only security posture audit tool for Kali Linux. It performs a structured series of informational checks across system identity, authentication, filesystem permissions, network configuration, services, kernel hardening parameters, and package currency — producing both a human-readable log and a machine-readable JSON report with a quantified security score.

> **No modifications are made to the system.** The tool is strictly observational.

---

## Usage

Root privileges are required. Run from the repository directory:

```bash
sudo ./kali_audit.sh
```

### Options

| Flag | Description |
|---|---|
| `--output-dir DIR` | Write reports to `DIR` instead of `./audit_reports` |
| `--skip-network` | Omit the firewall, listening-port, and IP-forwarding checks |
| `--quiet` | Suppress the banner and per-finding output to stdout (log file is still written) |
| `--plain` | Disable ANSI colour output; also honoured via `NO_COLOR=1` or when stdout is not a TTY |

### Output

Each run writes two files to `audit_reports/` (or the directory specified by `--output-dir`):

- `audit_<timestamp>.log` — full human-readable log, suitable for archiving or review
- `audit_<timestamp>.json` — machine-readable findings and summary score, suitable for automated comparison between runs

---

## Architecture

The tool is composed of two cooperating layers.

### Layer 1 — Bash wrapper (`kali_audit.sh`)

The wrapper orchestrates seven of the eight audit sections and is responsible for the runtime environment:

| Section | Scope |
|---|---|
| 1 — System Identity | OS release, architecture, kernel, CPU, RAM, uptime |
| 2 — User & Authentication | SSH root login policy, password authentication, UID-0 accounts, empty passwords, sudo group membership, NOPASSWD sudoers entries, login shells |
| 3 — Filesystem & Permissions | World-writable directories, SUID/SGID binaries, critical file permission checks (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`) |
| 4 — Network & Firewall | Listening TCP/UDP services, iptables and nftables rule counts, UFW status and default inbound policy, IPv4 forwarding |
| 5 — Service Hardening | Enabled and running systemd services, detection of legacy insecure services (telnet, rsh, rlogin) |
| 6 — Kernel Hardening | Key `sysctl` parameters covering ASLR, dmesg/kptr restrictions, ICMP redirects, source routing, SYN cookies |
| 7 — Package & Update Status | Age of the apt cache, count of upgradable packages, presence of `unattended-upgrades` |

The wrapper maintains per-severity counters (`BASH_WARNS`, `BASH_FAILS`) independently from the Python core to avoid double-counting findings in the final summary. At the end of each run it reads `summary.warn` and `summary.fail` from the JSON report produced by the Python core and combines them with its own counters.

### Layer 2 — Python deep-audit engine (`core_audit.py`)

Section 8 is delegated to the Python core, which performs more structured checks and is solely responsible for producing the JSON report. The core may also be invoked directly:

```bash
sudo python3 core_audit.py --json-out report.json [--skip-network 0|1] [--plain]
```

Key design elements:

- Each finding is represented as a `Finding(category, title, severity, detail, recommendation)` dataclass.
- All findings are collected in an `AuditReport`, which computes the security score on demand.
- The single `emit(report, finding)` function is the only code path that both prints a finding to stdout and records it — this eliminates the possibility of output and data diverging.

### Security Score

The score is a percentage computed at read time from the collected findings:

```
score = (PASS × 1  +  WARN × 0.5) / total_scored × 100
```

`INFO` findings are excluded from scoring as they are purely informational. This proportional formula ensures the score reflects the fraction of passing checks regardless of how many audit modules are active.

### Severity Levels

| Level | Meaning |
|---|---|
| `PASS` | Control is in the expected secure state |
| `INFO` | Informational observation; no scoring impact |
| `WARN` | Deviation from recommended hardening; partial score deduction |
| `FAIL` | Control is in an insecure state; full score deduction |

### JSON Report Schema

```json
{
  "version": "1.1.0",
  "hostname": "...",
  "timestamp": "...",
  "kernel": "...",
  "score": 85,
  "summary": { "pass": 0, "info": 0, "warn": 0, "fail": 0 },
  "findings": [
    {
      "category": "...",
      "title": "...",
      "severity": "WARN",
      "detail": "...",
      "recommendation": "..."
    }
  ]
}
```

`AUDIT_VERSION` in `core_audit.py` follows semantic versioning: increment the major component for breaking JSON schema changes, the minor component for new or changed checks, and the patch component for bug-fix-only releases.

---

## License

This project is released under the [MIT License](LICENSE).
