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
#   TESTOPS_GATE_VERSION   version to install, e.g. 0.1.0 (default: latest release)
#   TESTOPS_GATE_BASE_URL  download from this mirror instead (it serves testops-gate_all.deb
#                         and SHA256SUMS)
set -eu

RELEASES="https://testopscenter.com/testops-gate"
VERSION="${TESTOPS_GATE_VERSION:-latest}"
ASSET="testops-gate_all.deb"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: curl -fsSL <url>/install.sh | sudo sh"

[ -r /etc/os-release ] || die "cannot detect the operating system (/etc/os-release missing)"
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
    debian:12 | debian:13 | ubuntu:22.04 | ubuntu:24.04) ;;
    *) die "unsupported system: ${PRETTY_NAME:-unknown}. Supported: Debian 12/13, Ubuntu 22.04/24.04" ;;
esac
[ -e /dev/net/tun ] || die "the TUN device (/dev/net/tun) is not available on this machine"

fetch() {  # fetch URL FILE
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        die "curl or wget is required"
    fi
}

if [ -n "${TESTOPS_GATE_BASE_URL:-}" ]; then
    BASE="${TESTOPS_GATE_BASE_URL%/}"
elif [ "$VERSION" = latest ]; then
    BASE="$RELEASES/latest"
else
    BASE="$RELEASES/v$VERSION"
fi

TMP=$(mktemp -d)
chmod 755 "$TMP"  # apt reads the package as the _apt user
trap 'rm -rf "$TMP"' EXIT INT TERM

say "TestOps Gate by TestOps Center — https://testopscenter.com"
say "Downloading TestOps Gate from $BASE"
fetch "$BASE/$ASSET" "$TMP/$ASSET" || die "download failed: $BASE/$ASSET"
fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" || die "download failed: $BASE/SHA256SUMS"

say "Verifying checksum"
(cd "$TMP" && grep " $ASSET\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "checksum mismatch for $ASSET"

say "Installing package"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq "$TMP/$ASSET" >/dev/null

if [ "$#" -gt 0 ]; then
    say "Setting up: testops-gate install $*"
    exec testops-gate install "$@"
fi

if [ -f /etc/testops-gate/config.yaml ]; then
    say "testops-gate upgraded. Open the dashboard with: sudo testops-gate"
elif [ -t 1 ] && [ -r /dev/tty ]; then
    say "Starting the setup wizard"
    exec testops-gate </dev/tty
else
    say "Installed. Set up the VPN server with: sudo testops-gate"
fi
