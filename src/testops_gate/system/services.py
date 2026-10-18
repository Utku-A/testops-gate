# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""systemd and package helpers."""

from __future__ import annotations

from testops_gate.paths import P
from testops_gate.system.runner import run

OPENVPN_UNIT = "openvpn-server@server.service"
UNBOUND_UNIT = "unbound.service"
FIREWALL_UNIT = "testops-gate-firewall.service"
DAEMON_UNIT = "testops-gated.service"
SURICATA_UNIT = "suricata.service"
SURICATA_UPDATE_TIMER = "testops-gate-suricata-update.timer"

CORE_UNITS = [OPENVPN_UNIT, UNBOUND_UNIT, FIREWALL_UNIT, DAEMON_UNIT]
IDS_PACKAGES = ["suricata", "suricata-update"]


def systemctl(*args: str, check: bool = True) -> bool:
    return run(["systemctl", *args], check=check).ok


def daemon_reload() -> None:
    systemctl("daemon-reload")


def enable_now(unit: str) -> None:
    systemctl("enable", "--now", unit)


def disable_now(unit: str) -> None:
    systemctl("disable", "--now", unit, check=False)


def restart(unit: str) -> None:
    systemctl("restart", unit)


def reload_or_restart(unit: str) -> None:
    systemctl("reload-or-restart", unit)


def is_active(units: list[str]) -> dict[str, bool]:
    result = run(["systemctl", "is-active", *units], check=False)
    states = result.stdout.split()
    return {unit: (states[i] == "active" if i < len(states) else False) for i, unit in enumerate(units)}


_apt_updated = False


APT_ENV = {"DEBIAN_FRONTEND": "noninteractive"}


def apt_update() -> None:
    global _apt_updated
    run(["apt-get", "update"], env=APT_ENV, timeout=900)
    _apt_updated = True


def apt_install(packages: list[str], target_release: str = "") -> list[str]:
    """Install the missing packages; returns the ones actually installed.

    Packages that are already present are left alone: re-installing them would mark
    packages pulled in as dependencies of testops-gate as manually installed, and
    `apt-get autoremove` would then keep them after testops-gate is removed.
    """
    missing = [p for p in packages if not package_installed(p)]
    if not missing:
        return []
    if not _apt_updated:
        apt_update()
    release = ["-t", target_release] if target_release else []
    run(["apt-get", "install", "-y", "--no-install-recommends", *release, *missing], env=APT_ENV, timeout=1800)
    return missing


def apt_candidate(package: str) -> bool:
    out = run(["apt-cache", "policy", package], check=False).stdout
    return "Candidate:" in out and "Candidate: (none)" not in out


# Debian 12 ships Suricata only in bookworm-backports
BACKPORTS = {("debian", "12"): "bookworm-backports"}


def install_ids() -> list[str]:
    """Install Suricata, enabling the release's backports repository when it is only there."""
    from testops_gate.system import netinfo

    if package_installed("suricata"):
        return apt_install(IDS_PACKAGES)
    if not _apt_updated:
        apt_update()
    release = ""
    if not apt_candidate("suricata"):
        info = netinfo.os_info()
        release = BACKPORTS.get((info.id, info.version), "")
        if not release:
            raise RuntimeError(f"suricata is not available for {info.pretty}")
        P.backports_list.parent.mkdir(parents=True, exist_ok=True)
        P.backports_list.write_text(f"# Added by testops-gate for Suricata\n"
                                    f"deb http://deb.debian.org/debian {release} main\n")
        apt_update()
    return apt_install(IDS_PACKAGES, target_release=release)


def apt_purge(packages: list[str]) -> None:
    installed = [p for p in packages if package_installed(p)]
    if installed:
        run(["apt-get", "purge", "-y", *installed], env=APT_ENV, timeout=1800, check=False)
        run(["apt-get", "autoremove", "-y"], env=APT_ENV, timeout=1800, check=False)


def package_installed(package: str) -> bool:
    result = run(["dpkg-query", "-W", "-f=${Status}", package], check=False)
    return "install ok installed" in result.stdout
