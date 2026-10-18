# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Host and network detection used by the installer."""

from __future__ import annotations

import ipaddress
import os
import re
import urllib.request
from dataclasses import dataclass

from testops_gate.paths import P
from testops_gate.system.runner import run

SUPPORTED_OS = {"debian": {"12", "13"}, "ubuntu": {"22.04", "24.04"}}
PUBLIC_IP_SERVICES = ["https://api.ipify.org", "https://ifconfig.me/ip", "https://api.seeip.org"]


@dataclass
class OsInfo:
    id: str
    version: str
    pretty: str

    @property
    def supported(self) -> bool:
        return self.version in SUPPORTED_OS.get(self.id, set())


def os_info() -> OsInfo:
    data: dict[str, str] = {}
    if P.os_release.exists():
        for line in P.os_release.read_text().splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                data[key] = value.strip().strip('"')
    return OsInfo(data.get("ID", ""), data.get("VERSION_ID", ""), data.get("PRETTY_NAME", "unknown"))


def is_root() -> bool:
    return os.geteuid() == 0


def tun_available() -> bool:
    return os.path.exists("/dev/net/tun")


def default_interface() -> str:
    out = run(["ip", "-4", "route", "show", "default"], check=False).stdout
    match = re.search(r"\bdev (\S+)", out)
    return match.group(1) if match else ""


def interface_address(interface: str) -> str:
    out = run(["ip", "-4", "-o", "addr", "show", "dev", interface], check=False).stdout
    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    return match.group(1) if match else ""


def is_private(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def public_ip(timeout: float = 4) -> str:
    for url in PUBLIC_IP_SERVICES:
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                text = resp.read(64).decode().strip()
            ipaddress.ip_address(text)
            return text
        except Exception:
            continue
    return ""


def suggest_endpoint() -> str:
    """Address clients should connect to: the interface address, or the public IP behind NAT."""
    local = interface_address(default_interface())
    if local and not is_private(local):
        return local
    return public_ip() or local


def total_memory_mb() -> int:
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 0
