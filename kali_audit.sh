#!/usr/bin/env bash
# ============================================================================
#  Kali Linux Security Posture Audit — Bash Wrapper
#  NON-INVASIVE: read-only checks, no modifications, no exploitation.
#  Usage:  sudo ./kali_audit.sh [--output-dir /path] [--quiet] [--skip-network]
# ============================================================================
set -euo pipefail

# ── Colours & Symbols ───────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[1;33m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'
PASS="${GRN}[✔ PASS]${RST}"
WARN="${YEL}[⚠ WARN]${RST}"
FAIL="${RED}[✘ FAIL]${RST}"
INFO="${CYN}[i INFO]${RST}"

# ── Defaults ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT_DIR="${SCRIPT_DIR}/audit_reports"
LOG_FILE=""
QUIET=0
SKIP_NETWORK=0
PYTHON_CORE="${SCRIPT_DIR}/core_audit.py"

# ── Argument Parsing ────────────────────────────────────────────────────────
usage() {
    cat <<EOF
${BLD}Kali Linux Security Posture Audit${RST}
Non-invasive, informational-only security checks.

Usage: sudo $0 [OPTIONS]

Options:
  --output-dir DIR   Directory for reports (default: ./audit_reports)
  --quiet            Suppress banner & progress to stdout (logs still written)
  --skip-network     Skip network / firewall / listening-port checks
  -h, --help         Show this help

Reports are written to:
  <output-dir>/audit_<timestamp>.log   (full log)
  <output-dir>/audit_<timestamp>.json  (machine-readable summary)
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
        --quiet)        QUIET=1; shift ;;
        --skip-network) SKIP_NETWORK=1; shift ;;
        -h|--help)      usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# ── Pre-flight Checks ──────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${FAIL} This script must be run as root (sudo)."
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"
LOG_FILE="${OUTPUT_DIR}/audit_${TIMESTAMP}.log"
JSON_FILE="${OUTPUT_DIR}/audit_${TIMESTAMP}.json"
touch "${LOG_FILE}"

# Tee helper: write to both log and (optionally) screen
log() {
    local msg="$1"
    echo -e "$msg" >> "${LOG_FILE}"
    [[ $QUIET -eq 0 ]] && echo -e "$msg"
}

banner() {
    local b
    b=$(cat <<'ART'
 ╔══════════════════════════════════════════════════════════════╗
 ║       Kali Linux — Security Posture Audit Tool              ║
 ║       NON-INVASIVE  •  INFORMATIONAL ONLY                   ║
 ╚══════════════════════════════════════════════════════════════╝
ART
    )
    log "${CYN}${b}${RST}"
    log ""
    log " ${INFO} Audit started : $(date)"
    log " ${INFO} Hostname      : $(hostname)"
    log " ${INFO} Kernel        : $(uname -r)"
    log " ${INFO} Log file      : ${LOG_FILE}"
    log " ${INFO} JSON report   : ${JSON_FILE}"
    log ""
}

separator() {
    log "────────────────────────────────────────────────────────────────"
}

# ── Section 1: System Identity ──────────────────────────────────────────────
section_system_identity() {
    separator
    log "${BLD}[1/8] SYSTEM IDENTITY${RST}"
    separator
    log " OS            : $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"')"
    log " Architecture  : $(uname -m)"
    log " Uptime        : $(uptime -p 2>/dev/null || uptime)"
    log " CPU           : $(lscpu 2>/dev/null | awk -F: '/Model name/{gsub(/^[ \t]+/,"",$2); print $2}')"
    log " RAM           : $(free -h | awk '/Mem:/{print $2}') total"
    log ""
}

# ── Section 2: User & Auth Checks ──────────────────────────────────────────
section_users() {
    separator
    log "${BLD}[2/8] USER & AUTHENTICATION AUDIT${RST}"
    separator

    # Root login via SSH
    if [[ -f /etc/ssh/sshd_config ]]; then
        local root_login
        root_login=$(grep -iE '^\s*PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print $2}')
        if [[ "$root_login" == "yes" ]]; then
            log " ${FAIL} SSH PermitRootLogin is ${RED}yes${RST}"
        elif [[ "$root_login" == "prohibit-password" || "$root_login" == "without-password" ]]; then
            log " ${WARN} SSH PermitRootLogin is ${YEL}${root_login}${RST} (key-only)"
        elif [[ "$root_login" == "no" ]]; then
            log " ${PASS} SSH PermitRootLogin is disabled"
        else
            log " ${INFO} SSH PermitRootLogin not explicitly set (default applies)"
        fi
    else
        log " ${INFO} sshd_config not found — SSH may not be installed"
    fi

    # Password-based SSH
    if [[ -f /etc/ssh/sshd_config ]]; then
        local pw_auth
        pw_auth=$(grep -iE '^\s*PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print $2}')
        if [[ "$pw_auth" == "yes" ]]; then
            log " ${WARN} SSH PasswordAuthentication is ${YEL}enabled${RST}"
        elif [[ "$pw_auth" == "no" ]]; then
            log " ${PASS} SSH PasswordAuthentication is disabled (key-only)"
        else
            log " ${INFO} SSH PasswordAuthentication not explicitly set"
        fi
    fi

    # Users with UID 0
    local uid0_users
    uid0_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    local count
    count=$(echo "$uid0_users" | wc -l)
    if [[ $count -gt 1 ]]; then
        log " ${FAIL} Multiple UID-0 accounts: ${RED}${uid0_users//$'\n'/, }${RST}"
    else
        log " ${PASS} Only 'root' has UID 0"
    fi

    # Users with empty passwords
    # In /etc/shadow the password field meanings are:
    #   ""   — truly empty password (no authentication required — CRITICAL)
    #   "!"  — account is locked (cannot log in with a password)
    #   "!!" — password never set / account locked (common for service accounts)
    #   "*"  — account disabled
    # Only a genuinely empty field ("") is a security failure; "!" means locked
    # and was incorrectly flagged as empty in the previous version.
    local empty_pw
    empty_pw=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null)
    if [[ -n "$empty_pw" ]]; then
        log " ${FAIL} Accounts with truly empty passwords: ${RED}${empty_pw//$'\n'/, }${RST}"
    else
        log " ${PASS} No accounts with empty passwords"
    fi

    # Sudo group members
    local sudo_users
    sudo_users=$(getent group sudo 2>/dev/null | cut -d: -f4)
    log " ${INFO} Sudo group members: ${sudo_users:-none}"

    # Login shells
    log " ${INFO} Users with login shells:"
    awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)/ {printf "          %-20s %s\n", $1, $7}' /etc/passwd | while read -r line; do
        log "  $line"
    done
    log ""
}

# ── Section 3: File-System Permissions ──────────────────────────────────────
section_filesystem() {
    separator
    log "${BLD}[3/8] FILE-SYSTEM & PERMISSIONS${RST}"
    separator

    # World-writable dirs outside /tmp /var/tmp /dev/shm
    log " ${INFO} World-writable directories (excl. /tmp, /proc, /sys, /dev):"
    find / -maxdepth 4 -type d -perm -0002 \
        ! -path '/tmp/*' ! -path '/var/tmp/*' ! -path '/dev/*' \
        ! -path '/proc/*' ! -path '/sys/*' ! -path '/run/*' \
        2>/dev/null | head -20 | while read -r d; do
        log "          ${YEL}${d}${RST}"
    done

    # SUID binaries
    log " ${INFO} SUID binaries (top 30):"
    find / -maxdepth 5 -perm -4000 -type f \
        ! -path '/proc/*' ! -path '/sys/*' \
        2>/dev/null | head -30 | while read -r f; do
        log "          ${f}"
    done

    # SGID binaries
    log " ${INFO} SGID binaries (top 20):"
    find / -maxdepth 5 -perm -2000 -type f \
        ! -path '/proc/*' ! -path '/sys/*' \
        2>/dev/null | head -20 | while read -r f; do
        log "          ${f}"
    done

    # Sensitive file permissions — evaluate with PASS / WARN / FAIL
    # Expected values:
    #   /etc/shadow, /etc/gshadow : 640 or 000 (never world-readable)
    #   /etc/passwd               : 644 (world-readable is correct and required)
    #   /etc/sudoers              : 440 (owner/group read-only, no write)
    local f perms octal world_bit
    for f in /etc/shadow /etc/gshadow /etc/passwd /etc/sudoers; do
        [[ -e "$f" ]] || continue
        perms=$(stat -c '%a' "$f" 2>/dev/null)
        octal=$(( 8#$perms ))          # convert octal string → decimal for bit-tests
        world_bit=$(( octal & 7 ))     # last three bits = world rwx

        case "$f" in
            /etc/shadow|/etc/gshadow)
                if (( world_bit & 4 )); then
                    log " ${FAIL} ${f} is world-readable (permissions: ${RED}${perms}${RST}) — hashed passwords exposed"
                elif [[ "$perms" == "640" || "$perms" == "600" || "$perms" == "000" ]]; then
                    log " ${PASS} ${f} permissions OK (${perms})"
                else
                    log " ${WARN} ${f} permissions ${YEL}${perms}${RST} — expected 640 or 000"
                fi
                ;;
            /etc/passwd)
                if [[ "$perms" == "644" ]]; then
                    log " ${PASS} ${f} permissions OK (${perms})"
                elif (( world_bit & 2 )); then
                    log " ${FAIL} ${f} is world-writable (permissions: ${RED}${perms}${RST})"
                else
                    log " ${WARN} ${f} permissions ${YEL}${perms}${RST} — expected 644"
                fi
                ;;
            /etc/sudoers)
                if [[ "$perms" == "440" || "$perms" == "400" ]]; then
                    log " ${PASS} ${f} permissions OK (${perms})"
                elif (( world_bit & 2 )); then
                    log " ${FAIL} ${f} is world-writable (permissions: ${RED}${perms}${RST})"
                else
                    log " ${WARN} ${f} permissions ${YEL}${perms}${RST} — expected 440"
                fi
                ;;
        esac
    done
    log ""
}

# ── Section 4: Network / Firewall ───────────────────────────────────────────
section_network() {
    if [[ $SKIP_NETWORK -eq 1 ]]; then
        separator
        log "${BLD}[4/8] NETWORK & FIREWALL — SKIPPED (--skip-network)${RST}"
        separator
        log ""
        return
    fi

    separator
    log "${BLD}[4/8] NETWORK & FIREWALL${RST}"
    separator

    # Listening services
    log " ${INFO} Listening TCP/UDP services:"
    ss -tulnp 2>/dev/null | while read -r line; do
        log "          ${line}"
    done

    # iptables rules
    log ""
    local ipt_rules
    ipt_rules=$(iptables -L -n 2>/dev/null | grep -cv '^Chain\|^target\|^$' || true)
    if [[ "$ipt_rules" -eq 0 ]]; then
        log " ${WARN} iptables has ${YEL}no active rules${RST} (wide open)"
    else
        log " ${PASS} iptables has ${ipt_rules} active rule(s)"
    fi

    # nftables
    if command -v nft &>/dev/null; then
        local nft_rules
        nft_rules=$(nft list ruleset 2>/dev/null | wc -l || true)
        if [[ "$nft_rules" -le 1 ]]; then
            log " ${WARN} nftables ruleset is ${YEL}empty${RST}"
        else
            log " ${PASS} nftables has ${nft_rules} line(s) of rules"
        fi
    fi

    # IP forwarding
    local fwd
    fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [[ "$fwd" == "1" ]]; then
        log " ${WARN} IPv4 forwarding is ${YEL}enabled${RST}"
    else
        log " ${PASS} IPv4 forwarding is disabled"
    fi
    log ""
}

# ── Section 5: Service Hardening ────────────────────────────────────────────
section_services() {
    separator
    log "${BLD}[5/8] SERVICE HARDENING${RST}"
    separator

    # Enabled services
    log " ${INFO} Enabled systemd services:"
    systemctl list-unit-files --type=service --state=enabled 2>/dev/null | \
        grep -v '^UNIT' | head -30 | while read -r line; do
        log "          ${line}"
    done

    # Running services
    log " ${INFO} Currently running services:"
    systemctl list-units --type=service --state=running 2>/dev/null | \
        grep '\.service' | head -30 | while read -r line; do
        log "          ${line}"
    done

    # Dangerous defaults
    for svc in telnet.socket rsh.socket rlogin.socket rexec.socket; do
        if systemctl is-enabled "$svc" &>/dev/null; then
            log " ${FAIL} Legacy insecure service enabled: ${RED}${svc}${RST}"
        fi
    done
    log ""
}

# ── Section 6: Kernel Hardening ─────────────────────────────────────────────
section_kernel() {
    separator
    log "${BLD}[6/8] KERNEL HARDENING (sysctl)${RST}"
    separator

    declare -A SYSCTL_CHECKS=(
        ["kernel.randomize_va_space"]="2"
        ["kernel.dmesg_restrict"]="1"
        ["kernel.kptr_restrict"]="1"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv6.conf.all.accept_redirects"]="0"
    )

    for key in $(echo "${!SYSCTL_CHECKS[@]}" | tr ' ' '\n' | sort); do
        local expected="${SYSCTL_CHECKS[$key]}"
        local actual
        actual=$(sysctl -n "$key" 2>/dev/null || echo "N/A")
        if [[ "$actual" == "$expected" ]]; then
            log " ${PASS} ${key} = ${actual}"
        elif [[ "$actual" == "N/A" ]]; then
            log " ${INFO} ${key} — parameter not found"
        else
            log " ${WARN} ${key} = ${YEL}${actual}${RST} (recommended: ${expected})"
        fi
    done
    log ""
}

# ── Section 7: Package & Update Status ──────────────────────────────────────
section_packages() {
    separator
    log "${BLD}[7/8] PACKAGE & UPDATE STATUS${RST}"
    separator

    # Last apt update
    if [[ -f /var/cache/apt/pkgcache.bin ]]; then
        local last_update
        last_update=$(stat -c '%Y' /var/cache/apt/pkgcache.bin)
        local now
        now=$(date +%s)
        local days_ago=$(( (now - last_update) / 86400 ))
        if [[ $days_ago -gt 30 ]]; then
            log " ${FAIL} apt cache is ${RED}${days_ago} days old${RST} — run apt update"
        elif [[ $days_ago -gt 7 ]]; then
            log " ${WARN} apt cache is ${YEL}${days_ago} days old${RST}"
        else
            log " ${PASS} apt cache updated ${days_ago} day(s) ago"
        fi
    fi

    # Upgradable packages
    local upgradable
    upgradable=$(apt list --upgradable 2>/dev/null | grep -c 'upgradable' || true)
    if [[ "$upgradable" -gt 0 ]]; then
        log " ${WARN} ${YEL}${upgradable}${RST} package(s) can be upgraded"
    else
        log " ${PASS} All packages are up to date"
    fi

    # Unattended upgrades
    if dpkg -l unattended-upgrades &>/dev/null; then
        log " ${PASS} unattended-upgrades is installed"
    else
        log " ${WARN} unattended-upgrades is ${YEL}not installed${RST}"
    fi
    log ""
}

# ── Section 8: Hand off to Python Core ──────────────────────────────────────
section_python_deep_audit() {
    separator
    log "${BLD}[8/8] DEEP AUDIT (Python Core)${RST}"
    separator

    if ! command -v python3 &>/dev/null; then
        log " ${FAIL} python3 not found — skipping deep audit"
        return
    fi

    if [[ ! -f "${PYTHON_CORE}" ]]; then
        log " ${FAIL} Core audit script not found at ${PYTHON_CORE}"
        return
    fi

    log " ${INFO} Launching Python deep-audit engine..."
    log ""

    # Run Python core; it writes JSON and streams output to stdout.
    # Capture its exit code via PIPESTATUS[0] — the while loop's exit
    # code is always 0 (reads to EOF), so we must inspect the left side
    # of the pipe.  Without this check, a Python crash (ImportError,
    # syntax error, permission problem) would be silently swallowed and
    # the wrapper would report "JSON written" even though no JSON exists.
    python3 "${PYTHON_CORE}" \
        --json-out "${JSON_FILE}" \
        --skip-network "${SKIP_NETWORK}" \
        2>&1 | while IFS= read -r line; do
        log "  ${line}"
    done
    local py_exit="${PIPESTATUS[0]}"

    if [[ "$py_exit" -ne 0 ]]; then
        log " ${FAIL} Python core engine exited with error (exit code: ${py_exit})"
        log "         Check that all Python imports are available and re-run as root."
        return 1
    fi

    log ""
    # Verify JSON was actually produced before advertising it
    if [[ -f "${JSON_FILE}" ]]; then
        log " ${INFO} JSON report written to ${JSON_FILE}"
    else
        log " ${WARN} Python core completed but JSON report was not created at ${JSON_FILE}"
    fi
}

# ── Summary ─────────────────────────────────────────────────────────────────
summary() {
    separator
    log ""
    log "${BLD}AUDIT COMPLETE${RST}"
    log " ${INFO} Full log   : ${LOG_FILE}"
    log " ${INFO} JSON report: ${JSON_FILE}"
    log " ${INFO} Finished   : $(date)"
    log ""
    local warns fails
    warns=$(grep -c '⚠ WARN' "${LOG_FILE}" 2>/dev/null || true)
    fails=$(grep -c '✘ FAIL' "${LOG_FILE}" 2>/dev/null || true)
    log " Totals → ${WARN} ${warns} warning(s)   ${FAIL} ${fails} failure(s)"
    log ""
}

# ── Main ────────────────────────────────────────────────────────────────────
main() {
    banner
    section_system_identity
    section_users
    section_filesystem
    section_network
    section_services
    section_kernel
    section_packages
    section_python_deep_audit
    summary
}

main
