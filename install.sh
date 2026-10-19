#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)
# TestOps Gate installer — TestOps Center (https://testopscenter.com)
#
#   curl -fsSL https://testopscenter.com/install.sh | sudo sh
#
# Downloads the TestOps Gate package from testopscenter.com, checks its SHA-256
# checksum, installs it with apt and opens the setup wizard. Arguments after
# `sh -s --` are passed to `testops-gate install` for an unattended setup:
#
#   curl -fsSL https://testopscenter.com/install.sh | sudo sh -s -- \
#       --endpoint vpn.example.com --user alice --yes
#
# Environment:
#   TESTOPS_GATE_VERSION   version to install, e.g. 0.1.1 (default: latest release)
#   TESTOPS_GATE_RELEASES  release root of a mirror (with latest/ and v<version>/ below it)
#   TESTOPS_GATE_BASE_URL  download from this directory instead (it serves testops-gate_all.deb
#                         and SHA256SUMS)
#   NO_COLOR               plain output
set -eu

# Names start with TG_: /etc/os-release defines VERSION, NAME, ID, ... and must not clash
TG_RELEASES="${TESTOPS_GATE_RELEASES:-https://testopscenter.com/testops-gate}"
TG_RELEASES="${TG_RELEASES%/}"
TG_WANTED="${TESTOPS_GATE_VERSION:-latest}"
TG_ASSET="testops-gate_all.deb"

# --- output ------------------------------------------------------------------

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
    B=$(printf '\033[1m') D=$(printf '\033[2m') R=$(printf '\033[0m')
    BLUE=$(printf '\033[38;5;75m') GREEN=$(printf '\033[32m') RED=$(printf '\033[31m')
    TTY=1
else
    B='' D='' R='' BLUE='' GREEN='' RED='' TTY=''
fi

banner() {
    printf '\n  %s◆ TestOps Gate%s\n' "$BLUE$B" "$R"
    printf '    %sPrivate OpenVPN network · by TestOps Center™ · testopscenter.com%s\n\n' "$D" "$R"
}
# step LABEL TEXT: a running step (shown on a terminal, replaced by ok/fail)
step() { [ -z "$TTY" ] || printf '  %s…%s %-10s %s%s%s' "$D" "$R" "$1" "$D" "$2" "$R"; }
ok() { [ -z "$TTY" ] || printf '\r\033[K'; printf '  %s✓%s %-10s %s\n' "$GREEN" "$R" "$1" "$2"; }
fail() {  # fail LABEL MESSAGE [HINT...]
    [ -z "$TTY" ] || printf '\r\033[K'
    printf '  %s✗%s %-10s %s\n' "$RED" "$R" "$1" "$2" >&2
    shift 2
    for hint in "$@"; do printf '    %s%s%s\n' "$D" "$hint" "$R" >&2; done
    printf '\n' >&2
    exit 1
}
note() { printf '\n  %s→%s %s\n\n' "$BLUE" "$R" "$*"; }

banner

# --- system ------------------------------------------------------------------

[ "$(id -u)" -eq 0 ] || fail "System" "root required" "run: curl -fsSL https://testopscenter.com/install.sh | sudo sh"
[ -r /etc/os-release ] || fail "System" "cannot detect the operating system (/etc/os-release missing)"
os_field() { (. /etc/os-release && eval "printf '%s' \"\${$1:-}\""); }  # read in a subshell
TG_OS_ID=$(os_field ID)
TG_OS_LIKE=$(os_field ID_LIKE)
TG_OS_VERSION=$(os_field VERSION_ID)
TG_OS_NAME=$(os_field PRETTY_NAME)
TG_SUPPORTED="supported: Debian 12 or later, Ubuntu 22.04 or later and their derivatives"

version_at_least() {  # version_at_least 22.04 22.04
    awk -v a="$1" -v b="$2" 'BEGIN { split(a, x, "."); split(b, y, ".")
        for (i = 1; i <= 2; i++) { if (x[i] + 0 > y[i] + 0) exit 0; if (x[i] + 0 < y[i] + 0) exit 1 }
        exit 0 }'
}
case "$TG_OS_ID" in
    debian) TG_MIN=12 ;;
    ubuntu) TG_MIN=22.04 ;;
    *)  # derivatives (Raspberry Pi OS, Linux Mint, Pop!_OS, ...): the package dependencies decide
        case " $TG_OS_LIKE " in
            *" debian "* | *" ubuntu "*) TG_MIN="" ;;
            *) fail "System" "unsupported: $TG_OS_NAME" "$TG_SUPPORTED" ;;
        esac ;;
esac
# testing/sid have no VERSION_ID
if [ -n "$TG_MIN" ] && [ -n "$TG_OS_VERSION" ] && ! version_at_least "$TG_OS_VERSION" "$TG_MIN"; then
    fail "System" "too old: $TG_OS_NAME" "$TG_SUPPORTED"
fi
command -v apt-get >/dev/null 2>&1 || fail "System" "apt-get not found" "$TG_SUPPORTED"
[ -e /dev/net/tun ] || fail "System" "the TUN device (/dev/net/tun) is not available" \
    "on a VPS or container, enable TUN/TAP in the provider's control panel"
case "$TG_OS_ID:$TG_OS_VERSION" in
    debian:12 | debian:13 | ubuntu:22.04 | ubuntu:24.04 | ubuntu:25.10 | ubuntu:26.04) TG_TESTED=1 ;;
    *) TG_TESTED="" ;;
esac
ok "System" "$TG_OS_NAME · $(dpkg --print-architecture)"
[ -n "$TG_TESTED" ] || printf '    %snot tested on this release yet; problems: https://github.com/Utku-A/testops-gate/issues%s\n' "$D" "$R"

# --- download ----------------------------------------------------------------

fetch() {  # fetch URL FILE
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1" 2>"$TG_TMP/fetch.err"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1" 2>"$TG_TMP/fetch.err"
    else
        fail "Download" "curl or wget is required" "install one: apt-get install -y curl"
    fi
}
download_failed() {  # download_failed URL
    if grep -q '403' "$TG_TMP/fetch.err" 2>/dev/null; then
        fail "Download" "refused (HTTP 403): $1" "the site's firewall blocked this server; try again later or download the" \
            ".deb from https://github.com/Utku-A/testops-gate/releases"
    fi
    fail "Download" "failed: $1" "$(head -c 300 "$TG_TMP/fetch.err" 2>/dev/null)"
}

if [ -n "${TESTOPS_GATE_BASE_URL:-}" ]; then
    TG_BASE="${TESTOPS_GATE_BASE_URL%/}"
elif [ "$TG_WANTED" = latest ]; then
    TG_BASE="$TG_RELEASES/latest"
else
    TG_BASE="$TG_RELEASES/v$TG_WANTED"
fi

TG_TMP=$(mktemp -d)
chmod 755 "$TG_TMP"  # apt reads the package as the _apt user
trap 'rm -rf "$TG_TMP"' EXIT INT TERM

step "Download" "$TG_BASE"
# VERSION is optional on a mirror; it is only shown
TG_VERSION=""
if fetch "$TG_BASE/VERSION" "$TG_TMP/VERSION"; then
    TG_VERSION=$(head -c 32 "$TG_TMP/VERSION" | tr -cd '0-9.')
fi
fetch "$TG_BASE/$TG_ASSET" "$TG_TMP/$TG_ASSET" || download_failed "$TG_BASE/$TG_ASSET"
fetch "$TG_BASE/SHA256SUMS" "$TG_TMP/SHA256SUMS" || download_failed "$TG_BASE/SHA256SUMS"
TG_SIZE=$(wc -c <"$TG_TMP/$TG_ASSET" | LC_ALL=C awk '{ printf "%.1f MB", $1 / 1048576 }')
ok "Download" "TestOps Gate ${TG_VERSION:-package} · $TG_SIZE"

step "Checksum" "SHA-256"
(cd "$TG_TMP" && grep " $TG_ASSET\$" SHA256SUMS | sha256sum -c - >/dev/null 2>&1) ||
    fail "Checksum" "mismatch for $TG_ASSET" "the download was corrupted or altered; nothing was installed"
ok "Checksum" "SHA-256 verified"

# --- install -----------------------------------------------------------------

TG_BEFORE=$(dpkg-query -W -f='${Version}' testops-gate 2>/dev/null || true)
step "Install" "apt-get install (dependencies: OpenVPN, Unbound, nftables, …)"
export DEBIAN_FRONTEND=noninteractive
if ! { apt-get update -qq && apt-get install -y -qq "$TG_TMP/$TG_ASSET"; } >"$TG_TMP/apt.log" 2>&1; then
    [ -z "$TTY" ] || printf '\r\033[K'
    printf '  %s✗%s %-10s %s\n\n' "$RED" "$R" "Install" "apt-get failed:" >&2
    tail -n 20 "$TG_TMP/apt.log" | sed 's/^/    /' >&2
    printf '\n' >&2
    exit 1
fi
TG_AFTER=$(dpkg-query -W -f='${Version}' testops-gate 2>/dev/null || echo "?")
if [ -n "$TG_BEFORE" ] && [ "$TG_BEFORE" != "$TG_AFTER" ]; then
    ok "Install" "testops-gate $TG_BEFORE → $TG_AFTER"
else
    ok "Install" "testops-gate $TG_AFTER"
fi

# --- next --------------------------------------------------------------------

cmd() { printf '      %s%s%s\n' "$B" "$*" "$R"; }
text() { printf '    %s\n' "$*"; }

if [ "$#" -gt 0 ]; then
    note "Setting up: testops-gate install $*"
    exec testops-gate install "$@"
fi

if [ -f /etc/testops-gate/config.yaml ]; then
    printf '\n  %s✓ Updated to TestOps Gate %s.%s Users, certificates and settings are kept.\n\n' "$GREEN" "$TG_AFTER" "$R"
    text "Open the dashboard:"
    printf '\n'; cmd "sudo testops-gate"; printf '\n'
    exit 0
fi

# Piped (`curl | sudo sh`): the wizard cannot take over the terminal from inside the pipe
# (sudo would suspend the job), so print what to run. From a file it starts directly.
if [ -t 0 ] && [ -t 1 ]; then
    note "Starting the setup wizard…"
    exec testops-gate
fi

printf '\n  %s✓ TestOps Gate %s is installed.%s Next, set up the VPN server:\n\n' "$GREEN" "$TG_AFTER" "$R"
cmd "sudo testops-gate"
printf '\n'
text "The setup wizard asks for the public address, port, tunnel mode and the first user,"
text "then opens the dashboard. The same command opens the dashboard afterwards."
printf '\n'
text "Unattended setup instead:"
printf '\n'; cmd "sudo testops-gate install --endpoint vpn.example.com --user alice --yes"; printf '\n'
text "${D}Guide: https://github.com/Utku-A/testops-gate#readme${R}"
printf '\n'
