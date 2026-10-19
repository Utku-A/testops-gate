# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Filesystem layout.

All paths hang off a root (default "/") so tests can run against a temporary
directory by setting TESTOPS_GATE_ROOT or calling set_root().
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Paths:
    root: Path

    def _p(self, path: str) -> Path:
        return self.root / path.lstrip("/")

    # testops-gate
    @property
    def config_dir(self) -> Path:
        return self._p("/etc/testops-gate")

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.yaml"

    @property
    def secrets_file(self) -> Path:
        return self.config_dir / "secrets.yaml"

    @property
    def pki_dir(self) -> Path:
        return self.config_dir / "pki"

    @property
    def nft_file(self) -> Path:
        return self.config_dir / "nftables.nft"

    @property
    def state_dir(self) -> Path:
        return self._p("/var/lib/testops-gate")

    @property
    def db_file(self) -> Path:
        return self.state_dir / "state.db"

    @property
    def profiles_dir(self) -> Path:
        return self.state_dir / "profiles"

    @property
    def update_state(self) -> Path:
        return self.state_dir / "update.json"

    @property
    def updates_dir(self) -> Path:
        return self.state_dir / "updates"

    @property
    def backups_dir(self) -> Path:
        return self.state_dir / "backups"

    @property
    def log_dir(self) -> Path:
        return self._p("/var/log/testops-gate")

    @property
    def users_log_dir(self) -> Path:
        return self.log_dir / "users"

    @property
    def security_log_dir(self) -> Path:
        return self.log_dir / "security"

    @property
    def audit_log_dir(self) -> Path:
        return self.log_dir / "audit"

    @property
    def daemon_log_file(self) -> Path:
        return self.log_dir / "testops-gate.log"

    # OpenVPN
    @property
    def openvpn_dir(self) -> Path:
        return self._p("/etc/openvpn/server")

    @property
    def server_conf(self) -> Path:
        return self.openvpn_dir / "server.conf"

    @property
    def ccd_dir(self) -> Path:
        return self.openvpn_dir / "ccd"

    @property
    def auth_script(self) -> Path:
        return self.openvpn_dir / "testops-gate-auth"

    @property
    def auth_passwords(self) -> Path:
        return self.openvpn_dir / "testops-gate-passwords"

    @property
    def mgmt_socket(self) -> Path:
        return self._p("/run/openvpn-server/testops-gate.sock")

    @property
    def status_file(self) -> Path:
        return self._p("/run/openvpn-server/testops-gate-status.log")

    @property
    def unbound_rpz_zone(self) -> Path:
        return self._p("/var/lib/unbound/tg-rpz.zone")

    # Unbound
    @property
    def unbound_conf(self) -> Path:
        return self._p("/etc/unbound/unbound.conf.d/testops-gate.conf")

    @property
    def unbound_hosts_conf(self) -> Path:
        return self._p("/etc/unbound/unbound.conf.d/testops-gate-hosts.conf")

    # System
    @property
    def sysctl_file(self) -> Path:
        return self._p("/etc/sysctl.d/99-testops-gate.conf")

    @property
    def easyrsa_dir(self) -> Path:
        return self._p("/usr/share/easy-rsa")

    @property
    def suricata_dropin(self) -> Path:
        return self._p("/etc/systemd/system/suricata.service.d/testops-gate.conf")

    @property
    def suricata_eve(self) -> Path:
        return self._p("/var/log/suricata/eve.json")

    @property
    def backports_list(self) -> Path:
        return self._p("/etc/apt/sources.list.d/testops-gate-backports.list")

    @property
    def os_release(self) -> Path:
        return self._p("/etc/os-release")


P = Paths(Path(os.environ.get("TESTOPS_GATE_ROOT", "/")))


def set_root(root: str | Path) -> None:
    """Point every path at a different root (used by tests)."""
    P.root = Path(root)
