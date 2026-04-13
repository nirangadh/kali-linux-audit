#!/usr/bin/env python3
"""
Kali Linux Security Posture Audit — Python Core Engine
NON-INVASIVE: read-only checks, no modifications, no exploitation.

Called by kali_audit.sh or standalone:
    sudo python3 core_audit.py --json-out report.json [--skip-network 0|1]
"""

import argparse
import datetime
import grp
import hashlib
import json
import os
import pathlib
import platform
import pwd
import re
import shutil
import socket
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional

# ════════════════════════════════════════════════════════════════════════════
#  Data Structures
# ════════════════════════════════════════════════════════════════════════════

SEVERITY_PASS = "PASS"
SEVERITY_INFO = "INFO"
SEVERITY_WARN = "WARN"
SEVERITY_FAIL = "FAIL"

ICONS = {
    SEVERITY_PASS: "\033[0;32m[✔ PASS]\033[0m",
    SEVERITY_INFO: "\033[0;36m[i INFO]\033[0m",
    SEVERITY_WARN: "\033[1;33m[⚠ WARN]\033[0m",
    SEVERITY_FAIL: "\033[0;31m[✘ FAIL]\033[0m",
}


@dataclass
class Finding:
    category: str
    title: str
    severity: str  # PASS / INFO / WARN / FAIL
    detail: str
    recommendation: str = ""


@dataclass
class AuditReport:
    hostname: str = ""
    timestamp: str = ""
    kernel: str = ""
    findings: list = field(default_factory=list)
    score: int = 100  # starts perfect, deductions applied

    def add(self, f: Finding):
        self.findings.append(f)
        if f.severity == SEVERITY_FAIL:
            self.score = max(0, self.score - 5)
        elif f.severity == SEVERITY_WARN:
            self.score = max(0, self.score - 2)

    def to_dict(self):
        return {
            "hostname": self.hostname,
            "timestamp": self.timestamp,
            "kernel": self.kernel,
            "score": self.score,
            "summary": {
                "pass": sum(1 for f in self.findings if f.severity == SEVERITY_PASS),
                "info": sum(1 for f in self.findings if f.severity == SEVERITY_INFO),
                "warn": sum(1 for f in self.findings if f.severity == SEVERITY_WARN),
                "fail": sum(1 for f in self.findings if f.severity == SEVERITY_FAIL),
            },
            "findings": [asdict(f) for f in self.findings],
        }


report = AuditReport()


# ════════════════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════════════════

def run(cmd: str, timeout: int = 30) -> str:
    """Run a shell command and return stdout (empty string on failure)."""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout.strip()
    except Exception:
        return ""


def safe_int(value: str, default: int = 0) -> int:
    """
    Parse an integer from a config string value.

    login.defs and pwquality.conf values should always be integers, but
    malformed files (e.g. trailing comments, stray characters) can cause
    int() to raise ValueError and crash the entire audit run.  This helper
    returns *default* instead, so auditing continues and the bad value is
    surfaced to the caller for reporting.
    """
    try:
        return int(str(value).strip())
    except (ValueError, TypeError):
        return default


def emit(finding: Finding):
    """Print a finding to stdout and record it."""
    icon = ICONS.get(finding.severity, "[?]")
    print(f"  {icon} [{finding.category}] {finding.title}")
    if finding.detail:
        for line in finding.detail.split("\n"):
            print(f"           {line}")
    report.add(finding)


def heading(title: str):
    print(f"\n  \033[1m── {title} ──\033[0m")


# ════════════════════════════════════════════════════════════════════════════
#  Audit Modules
# ════════════════════════════════════════════════════════════════════════════

# ── 1. SSH Configuration Deep Dive ──────────────────────────────────────────

def audit_ssh():
    heading("SSH Configuration Deep Dive")
    config_path = "/etc/ssh/sshd_config"
    config_dir = "/etc/ssh/sshd_config.d"

    if not os.path.isfile(config_path):
        emit(Finding("SSH", "sshd_config not found", SEVERITY_INFO,
                      "OpenSSH server may not be installed."))
        return

    # On Debian/Kali the main sshd_config starts with:
    #   Include /etc/ssh/sshd_config.d/*.conf
    # sshd honours the FIRST occurrence of each directive, so files in
    # sshd_config.d/ that appear via that Include take precedence over the
    # main config.  We must therefore read drop-in files BEFORE the main
    # config so that cfg.setdefault() correctly keeps the highest-priority
    # (drop-in) value.  Previously drop-in lines were appended after the
    # main config, causing main-config values to silently win.
    dropin_lines: list = []
    if os.path.isdir(config_dir):
        for p in sorted(pathlib.Path(config_dir).glob("*.conf")):
            try:
                with open(p) as f:
                    dropin_lines += f.readlines()
            except PermissionError:
                pass

    main_lines: list = []
    try:
        with open(config_path) as f:
            main_lines = f.readlines()
    except PermissionError:
        emit(Finding("SSH", "Cannot read sshd_config", SEVERITY_WARN,
                      "Permission denied.", "Run as root."))
        return

    # Drop-in directives first so they take precedence via setdefault()
    lines = dropin_lines + main_lines

    cfg = {}
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            cfg.setdefault(parts[0].lower(), parts[1])

    # Checks
    checks = {
        "protocol": ("2", "Use SSH protocol 2 only."),
        "x11forwarding": ("no", "Disable X11 forwarding unless needed."),
        "maxauthtries": (None, "Recommended: 3-5"),
        "logingracetime": (None, "Recommended: 30-60 seconds"),
        "clientaliveinterval": (None, "Set to disconnect idle sessions (e.g. 300)."),
        "clientalivecountmax": (None, "Recommended: 2-3"),
        "allowtcpforwarding": ("no", "Disable unless required."),
        "permitemptypasswords": ("no", "Never allow empty passwords."),
        "usepam": ("yes", "PAM provides additional auth controls."),
    }

    for key, (expected, rec) in checks.items():
        val = cfg.get(key)
        if val is None:
            emit(Finding("SSH", f"{key} not set", SEVERITY_INFO,
                          "Using default.", rec))
        elif expected and val.lower() != expected:
            emit(Finding("SSH", f"{key} = {val}", SEVERITY_WARN,
                          f"Expected: {expected}", rec))
        elif expected:
            emit(Finding("SSH", f"{key} = {val}", SEVERITY_PASS, ""))

    # Host key algorithms
    host_keys = list(pathlib.Path("/etc/ssh").glob("ssh_host_*_key.pub"))
    algos = [k.stem.replace("ssh_host_", "").replace("_key", "") for k in host_keys]
    if "dsa" in algos:
        emit(Finding("SSH", "DSA host key present", SEVERITY_WARN,
                      "DSA keys are deprecated and weak.",
                      "Remove /etc/ssh/ssh_host_dsa_key*"))
    if "ed25519" in algos:
        emit(Finding("SSH", "Ed25519 host key present", SEVERITY_PASS, "Strong algorithm."))
    elif "rsa" in algos:
        emit(Finding("SSH", "RSA host key present (no Ed25519)", SEVERITY_INFO,
                      "Consider generating an Ed25519 key as well."))


# ── 2. PAM & Password Policy ───────────────────────────────────────────────

def audit_pam():
    heading("PAM & Password Policy")

    # Password aging from login.defs
    defs = {}
    if os.path.isfile("/etc/login.defs"):
        with open("/etc/login.defs") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if len(parts) >= 2:
                        defs[parts[0]] = parts[1]

    max_days = defs.get("PASS_MAX_DAYS", "99999")
    min_days = defs.get("PASS_MIN_DAYS", "0")
    min_len  = defs.get("PASS_MIN_LEN", "5")
    warn_age = defs.get("PASS_WARN_AGE", "7")

    # safe_int() avoids a ValueError crash if login.defs contains a
    # non-integer value (e.g. trailing comment or corrupted entry).
    if safe_int(max_days, default=99999) > 365:
        emit(Finding("PAM", f"PASS_MAX_DAYS = {max_days}", SEVERITY_WARN,
                      "Passwords never/rarely expire.",
                      "Set PASS_MAX_DAYS to 90 in /etc/login.defs"))
    else:
        emit(Finding("PAM", f"PASS_MAX_DAYS = {max_days}", SEVERITY_PASS, ""))

    if safe_int(min_len, default=5) < 8:
        emit(Finding("PAM", f"PASS_MIN_LEN = {min_len}", SEVERITY_WARN,
                      "Minimum password length is low.",
                      "Set to 12+ in /etc/login.defs"))

    # pam_pwquality / pam_cracklib
    pwq_installed = os.path.isfile("/etc/security/pwquality.conf")
    if pwq_installed:
        emit(Finding("PAM", "pam_pwquality installed", SEVERITY_PASS,
                      "Password complexity enforcement is available."))
        # Parse pwquality.conf
        with open("/etc/security/pwquality.conf") as f:
            for line in f:
                line = line.strip()
                if line.startswith("minlen"):
                    val = line.split("=")[-1].strip()
                    if safe_int(val, default=8) < 12:
                        emit(Finding("PAM", f"pwquality minlen = {val}", SEVERITY_WARN,
                                      "", "Set minlen = 12 or higher."))
                    else:
                        emit(Finding("PAM", f"pwquality minlen = {val}", SEVERITY_PASS, ""))
    else:
        emit(Finding("PAM", "pam_pwquality not found", SEVERITY_WARN,
                      "No password complexity enforcement.",
                      "apt install libpam-pwquality"))

    # pam_faillock / pam_tally2
    faillock = run("grep -r 'pam_faillock\\|pam_tally2' /etc/pam.d/ 2>/dev/null")
    if faillock:
        emit(Finding("PAM", "Account lockout configured", SEVERITY_PASS,
                      "pam_faillock or pam_tally2 is active."))
    else:
        emit(Finding("PAM", "No account lockout policy", SEVERITY_WARN,
                      "Brute-force attacks are not rate-limited by PAM.",
                      "Configure pam_faillock in /etc/pam.d/common-auth"))


# ── 3. Cron & Scheduled Tasks ──────────────────────────────────────────────

def audit_cron():
    heading("Cron & Scheduled Tasks")

    cron_dirs = [
        "/etc/crontab", "/etc/cron.d", "/etc/cron.daily",
        "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly",
        "/var/spool/cron/crontabs"
    ]

    for path in cron_dirs:
        p = pathlib.Path(path)
        if p.is_file():
            perms = oct(p.stat().st_mode)[-3:]
            if int(perms, 8) & 0o002:
                emit(Finding("CRON", f"{path} is world-writable", SEVERITY_FAIL,
                              f"Permissions: {perms}",
                              f"chmod o-w {path}"))
            else:
                emit(Finding("CRON", f"{path} perms OK ({perms})", SEVERITY_PASS, ""))
        elif p.is_dir():
            for child in p.iterdir():
                if child.is_file():
                    cperms = oct(child.stat().st_mode)[-3:]
                    if int(cperms, 8) & 0o002:
                        emit(Finding("CRON", f"{child} is world-writable", SEVERITY_FAIL,
                                      f"Permissions: {cperms}",
                                      f"chmod o-w {child}"))

    # Systemd timers
    timers = run("systemctl list-timers --all --no-pager 2>/dev/null")
    timer_count = len([l for l in timers.splitlines() if "timer" in l.lower()])
    emit(Finding("CRON", f"{timer_count} systemd timer(s) found", SEVERITY_INFO, ""))


# ── 4. Disk Encryption & Mount Options ─────────────────────────────────────

def audit_disk():
    heading("Disk Encryption & Mount Options")

    # LUKS volumes
    luks_devs = run("lsblk -o NAME,FSTYPE,TYPE 2>/dev/null | grep -i crypt")
    if luks_devs:
        emit(Finding("DISK", "Encrypted volumes detected", SEVERITY_PASS,
                      luks_devs))
    else:
        emit(Finding("DISK", "No LUKS encryption detected", SEVERITY_WARN,
                      "Disk is likely unencrypted.",
                      "Consider full-disk encryption for sensitive machines."))

    # Mount options
    try:
        with open("/proc/mounts") as f:
            mounts = f.readlines()
    except Exception:
        mounts = []

    risky = {"/tmp": ["noexec", "nosuid", "nodev"],
             "/var/tmp": ["noexec", "nosuid", "nodev"],
             "/dev/shm": ["noexec", "nosuid", "nodev"],
             "/home": ["nosuid", "nodev"]}

    for mountpoint, expected_opts in risky.items():
        found = [l for l in mounts if f" {mountpoint} " in l]
        if not found:
            emit(Finding("DISK", f"{mountpoint} not a separate mount", SEVERITY_INFO,
                          "", f"Consider a separate partition for {mountpoint}."))
            continue
        opts = found[0].split()[3]
        missing = [o for o in expected_opts if o not in opts]
        if missing:
            emit(Finding("DISK", f"{mountpoint} missing: {', '.join(missing)}", SEVERITY_WARN,
                          f"Current options: {opts}",
                          f"Add {', '.join(missing)} to /etc/fstab for {mountpoint}."))
        else:
            emit(Finding("DISK", f"{mountpoint} mount options OK", SEVERITY_PASS, ""))


# ── 5. Logging & Auditd ────────────────────────────────────────────────────

def audit_logging():
    heading("Logging & Auditd")

    # rsyslog / syslog-ng
    for svc in ["rsyslog", "syslog-ng"]:
        status = run(f"systemctl is-active {svc} 2>/dev/null")
        if status == "active":
            emit(Finding("LOG", f"{svc} is running", SEVERITY_PASS, ""))
            break
    else:
        emit(Finding("LOG", "No syslog daemon running", SEVERITY_WARN,
                      "", "Enable rsyslog or syslog-ng."))

    # journald persistence
    journal_conf = "/etc/systemd/journald.conf"
    if os.path.isfile(journal_conf):
        with open(journal_conf) as f:
            content = f.read()
        if re.search(r"^\s*Storage\s*=\s*persistent", content, re.MULTILINE | re.IGNORECASE):
            emit(Finding("LOG", "journald Storage=persistent", SEVERITY_PASS, ""))
        else:
            emit(Finding("LOG", "journald may use volatile storage", SEVERITY_WARN,
                          "", "Set Storage=persistent in journald.conf"))

    # auditd
    auditd_active = run("systemctl is-active auditd 2>/dev/null")
    if auditd_active == "active":
        emit(Finding("LOG", "auditd is running", SEVERITY_PASS, ""))
        rule_count = run("auditctl -l 2>/dev/null | wc -l")
        emit(Finding("LOG", f"auditd rules loaded: {rule_count}", SEVERITY_INFO, ""))
    else:
        emit(Finding("LOG", "auditd is NOT running", SEVERITY_WARN,
                      "System call auditing is disabled.",
                      "apt install auditd && systemctl enable --now auditd"))


# ── 6. Integrity & Rootkit Indicators ──────────────────────────────────────

def audit_integrity():
    heading("Integrity & Rootkit Indicators (lightweight)")

    # /etc/ld.so.preload — often used by rootkits
    preload = pathlib.Path("/etc/ld.so.preload")
    if preload.exists():
        content = preload.read_text().strip()
        if content:
            emit(Finding("INTEGRITY", "/etc/ld.so.preload has entries", SEVERITY_FAIL,
                          content, "Investigate — this is a common rootkit vector."))
        else:
            emit(Finding("INTEGRITY", "/etc/ld.so.preload is empty", SEVERITY_PASS, ""))
    else:
        emit(Finding("INTEGRITY", "/etc/ld.so.preload absent", SEVERITY_PASS, ""))

    # Hidden files in /
    hidden_root = [str(p) for p in pathlib.Path("/").iterdir()
                   if p.name.startswith(".") and p.name not in (".", "..")]
    if hidden_root:
        emit(Finding("INTEGRITY", f"Hidden items in /: {len(hidden_root)}", SEVERITY_WARN,
                      "\n".join(hidden_root[:10]),
                      "Review — hidden files in / are unusual."))
    else:
        emit(Finding("INTEGRITY", "No hidden files in /", SEVERITY_PASS, ""))

    # Kernel modules — look for suspicious ones
    lsmod = run("lsmod 2>/dev/null")
    suspicious = ["diamorphine", "reptile", "lime", "khook", "bdvl"]
    flagged = [m for m in suspicious if m in lsmod.lower()]
    if flagged:
        emit(Finding("INTEGRITY", f"Suspicious kernel modules: {', '.join(flagged)}",
                      SEVERITY_FAIL, "", "Investigate immediately."))
    else:
        emit(Finding("INTEGRITY", "No known-bad kernel modules detected", SEVERITY_PASS, ""))

    # /etc/hosts anomalies
    try:
        with open("/etc/hosts") as f:
            hosts = f.readlines()
        non_comment = [l.strip() for l in hosts if l.strip() and not l.startswith("#")]
        if len(non_comment) > 10:
            emit(Finding("INTEGRITY", f"/etc/hosts has {len(non_comment)} entries", SEVERITY_WARN,
                          "Large hosts file may indicate DNS hijack.",
                          "Review /etc/hosts for unexpected entries."))
        else:
            emit(Finding("INTEGRITY", f"/etc/hosts entries: {len(non_comment)}", SEVERITY_PASS, ""))
    except Exception:
        pass

    # Check AIDE / Tripwire presence
    for tool in ["aide", "tripwire"]:
        if shutil.which(tool):
            emit(Finding("INTEGRITY", f"{tool} is installed", SEVERITY_PASS,
                          "File integrity monitoring tool available."))
            break
    else:
        emit(Finding("INTEGRITY", "No file integrity tool (AIDE/Tripwire)", SEVERITY_WARN,
                      "", "Install aide or tripwire for change detection."))


# ── 7. Container & Virtualisation Detection ────────────────────────────────

def audit_virtualisation():
    heading("Container / Virtualisation Detection")

    virt = run("systemd-detect-virt 2>/dev/null") or "none/bare-metal"
    emit(Finding("VIRT", f"Virtualisation: {virt}", SEVERITY_INFO, ""))

    if os.path.isfile("/.dockerenv"):
        emit(Finding("VIRT", "Running inside Docker", SEVERITY_INFO, ""))
    if os.path.isfile("/run/.containerenv"):
        emit(Finding("VIRT", "Running inside Podman container", SEVERITY_INFO, ""))


# ── 8. Interesting Files Scan ───────────────────────────────────────────────

def audit_interesting_files():
    heading("Interesting Files Scan")

    # Private keys
    key_patterns = ["*.pem", "*.key", "id_rsa", "id_ecdsa", "id_ed25519"]
    found_keys = []
    search_dirs = ["/home", "/root", "/etc/ssl", "/etc/pki", "/tmp", "/var/tmp"]
    for d in search_dirs:
        for pat in key_patterns:
            found_keys += [
                str(p)
                for p in pathlib.Path(d).rglob(pat)
                if p.is_file()
            ][:5]

    if found_keys:
        emit(Finding("FILES", f"Private keys found: {len(found_keys)}", SEVERITY_WARN,
                      "\n".join(found_keys[:15]),
                      "Ensure private keys have 600 perms and are needed."))
    else:
        emit(Finding("FILES", "No stray private keys found", SEVERITY_PASS, ""))

    # .bash_history readable
    for home in pathlib.Path("/home").iterdir():
        hist = home / ".bash_history"
        if hist.exists():
            perms = oct(hist.stat().st_mode)[-3:]
            if int(perms, 8) & 0o044:
                emit(Finding("FILES", f"{hist} is world/group-readable ({perms})",
                              SEVERITY_WARN, "",
                              f"chmod 600 {hist}"))

    # Core dumps enabled?
    core_pattern = run("cat /proc/sys/kernel/core_pattern 2>/dev/null")
    core_limit = run("ulimit -c 2>/dev/null")
    if core_limit and core_limit != "0":
        emit(Finding("FILES", f"Core dumps enabled (pattern: {core_pattern})", SEVERITY_WARN,
                      "", "Disable with 'ulimit -c 0' or fs.suid_dumpable=0"))
    else:
        emit(Finding("FILES", "Core dumps appear disabled", SEVERITY_PASS, ""))


# ── 9. Network Deep Dive (optional) ────────────────────────────────────────

def audit_network_deep():
    heading("Network Deep Dive")

    # ARP table size (anomaly indicator)
    arp_entries = run("ip neigh show 2>/dev/null").splitlines()
    emit(Finding("NET", f"ARP table entries: {len(arp_entries)}", SEVERITY_INFO, ""))

    # DNS config
    resolv = pathlib.Path("/etc/resolv.conf")
    if resolv.exists():
        nameservers = [l.strip() for l in resolv.read_text().splitlines()
                       if l.strip().startswith("nameserver")]
        emit(Finding("NET", f"DNS nameservers: {len(nameservers)}", SEVERITY_INFO,
                      "\n".join(nameservers)))

    # Promiscuous mode
    promisc = run("ip link show 2>/dev/null | grep PROMISC")
    if promisc:
        emit(Finding("NET", "Interface(s) in PROMISCUOUS mode", SEVERITY_WARN,
                      promisc, "May indicate packet sniffing — verify intent."))
    else:
        emit(Finding("NET", "No interfaces in promiscuous mode", SEVERITY_PASS, ""))

    # IPv6 status
    ipv6_disable = run("sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null")
    if ipv6_disable == "1":
        emit(Finding("NET", "IPv6 is disabled", SEVERITY_INFO, ""))
    else:
        emit(Finding("NET", "IPv6 is enabled", SEVERITY_INFO,
                      "Ensure IPv6 firewall rules are also configured."))


# ── 10. Security Tool Inventory ─────────────────────────────────────────────

def audit_tools():
    heading("Security Tool Inventory")

    tools = {
        "apparmor_status": ("AppArmor", SEVERITY_PASS),
        "aa-status": ("AppArmor (aa-status)", SEVERITY_PASS),
        "getenforce": ("SELinux", SEVERITY_PASS),
        "ufw": ("UFW firewall", SEVERITY_PASS),
        "fail2ban-client": ("Fail2Ban", SEVERITY_PASS),
        "rkhunter": ("Rootkit Hunter", SEVERITY_PASS),
        "chkrootkit": ("chkrootkit", SEVERITY_PASS),
        "clamdscan": ("ClamAV", SEVERITY_INFO),
        "lynis": ("Lynis auditor", SEVERITY_INFO),
    }

    installed = []
    missing = []
    for cmd, (label, sev) in tools.items():
        if shutil.which(cmd):
            installed.append(label)
            emit(Finding("TOOLS", f"{label} — installed", sev, ""))
        else:
            missing.append(label)

    if missing:
        emit(Finding("TOOLS", f"{len(missing)} security tool(s) not found", SEVERITY_INFO,
                      ", ".join(missing),
                      "Consider installing for defense-in-depth."))

    # AppArmor / SELinux enforcement
    aa = run("apparmor_status 2>/dev/null | head -5")
    if "profiles are in enforce" in (aa or ""):
        emit(Finding("TOOLS", "AppArmor has enforcing profiles", SEVERITY_PASS, ""))
    elif shutil.which("apparmor_status"):
        emit(Finding("TOOLS", "AppArmor installed but no enforcing profiles", SEVERITY_WARN,
                      "", "Set profiles to enforce mode."))

    se = run("getenforce 2>/dev/null")
    if se and se.lower() == "enforcing":
        emit(Finding("TOOLS", "SELinux is Enforcing", SEVERITY_PASS, ""))
    elif se and se.lower() == "permissive":
        emit(Finding("TOOLS", "SELinux is Permissive (logging only)", SEVERITY_WARN,
                      "", "Set to Enforcing for full protection."))

    # Fail2Ban jails
    if shutil.which("fail2ban-client"):
        jails = run("fail2ban-client status 2>/dev/null")
        emit(Finding("TOOLS", "Fail2Ban status", SEVERITY_INFO, jails or "Could not query."))


# ════════════════════════════════════════════════════════════════════════════
#  Score & Final Report
# ════════════════════════════════════════════════════════════════════════════

def compute_grade(score: int) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    return "F"


def print_scorecard():
    s = report.to_dict()["summary"]
    grade = compute_grade(report.score)
    color = "\033[0;32m" if report.score >= 80 else (
            "\033[1;33m" if report.score >= 60 else "\033[0;31m")
    print(f"""
  ╔════════════════════════════════════════════════════╗
  ║  SECURITY POSTURE SCORE: {color}{report.score:>3}/100  Grade: {grade}\033[0m          ║
  ╠════════════════════════════════════════════════════╣
  ║  PASS: {s['pass']:<5}  INFO: {s['info']:<5}  WARN: {s['warn']:<5}  FAIL: {s['fail']:<5}║
  ╚════════════════════════════════════════════════════╝
""")


# ════════════════════════════════════════════════════════════════════════════
#  Main
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Kali Security Audit — Core Engine")
    parser.add_argument("--json-out", default="audit_report.json",
                        help="Path for JSON output")
    parser.add_argument("--skip-network", default="0",
                        help="1 to skip network checks")
    args = parser.parse_args()

    report.hostname = socket.gethostname()
    report.timestamp = datetime.datetime.now().isoformat()
    report.kernel = platform.release()

    # Run all audit modules
    audit_ssh()
    audit_pam()
    audit_cron()
    audit_disk()
    audit_logging()
    audit_integrity()
    audit_virtualisation()
    audit_interesting_files()

    if args.skip_network != "1":
        audit_network_deep()

    audit_tools()

    # Scorecard
    print_scorecard()

    # Write JSON
    try:
        with open(args.json_out, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"  [i] JSON report written → {args.json_out}")
    except Exception as e:
        print(f"  [!] Failed to write JSON: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
