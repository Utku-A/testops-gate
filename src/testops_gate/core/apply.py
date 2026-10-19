# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Write every generated file from settings + state and reload what changed.

Idempotent: unchanged files are not rewritten and their services are left alone.
Per-user files (ccd) are read by OpenVPN when a client connects, so user,
host and tunnel-mode changes never need an OpenVPN restart.
"""

from __future__ import annotations

import grp
import logging
import os
from pathlib import Path

from testops_gate.config import Config
from testops_gate.db import Store
from testops_gate.paths import P
from testops_gate.render import openvpn, system, unbound
from testops_gate.system import nft, services
from testops_gate.system.runner import CommandError, run

log = logging.getLogger(__name__)


class ServiceError(RuntimeError):
    """The files were written, but a service did not take them (it failed to reload or start)."""


def write_if_changed(path: Path, content: str, mode: int = 0o644) -> bool:
    if path.exists() and path.read_text() == content:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return True


def write_ccd(cfg: Config, store: Store) -> bool:
    hosts = store.hosts()
    users = store.users()
    nodes = store.nodes()
    changed = False
    P.ccd_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(P.ccd_dir, 0o755)
    for user in users:
        changed |= write_if_changed(P.ccd_dir / user.name, openvpn.ccd(cfg, user, hosts))
    for node in nodes:
        changed |= write_if_changed(P.ccd_dir / node.cn, openvpn.node_ccd(cfg, node))
    # ccd-exclusive: a client without a file here is refused, so stale files go
    names = {u.name for u in users} | {n.cn for n in nodes}
    for entry in P.ccd_dir.iterdir():
        if entry.is_file() and entry.name not in names:
            entry.unlink()
            changed = True
    return changed


def write_auth(cfg: Config, store: Store) -> bool:
    """Verify script and password hashes for username + password sign-in (removed in other modes).

    OpenVPN reads them per sign-in as nobody:nogroup, so a password change needs no restart.
    """
    if cfg.auth.mode != "user-password":
        changed = False
        for path in (P.auth_script, P.auth_passwords):
            if path.exists():
                path.unlink()
                changed = True
        return changed
    changed = write_if_changed(P.auth_script, openvpn.AUTH_SCRIPT, 0o755)
    changed |= write_if_changed(P.auth_passwords, openvpn.passwords_file(store.users(), store.nodes()), 0o640)
    if os.geteuid() == 0:
        try:
            os.chown(P.auth_passwords, 0, grp.getgrnam("nogroup").gr_gid)
        except KeyError:
            pass
    return changed


def apply_all(cfg: Config, store: Store, *, reload: bool = True) -> set[str]:
    """Regenerate all files; returns the names of the parts that changed."""
    changed: set[str] = set()
    if write_if_changed(P.server_conf, openvpn.server_conf(cfg)):
        changed.add("openvpn")
    if write_ccd(cfg, store):
        changed.add("ccd")
    if write_auth(cfg, store):
        changed.add("auth")
    if write_if_changed(P.unbound_conf, unbound.main_conf(cfg)):
        changed.add("unbound")
    node_names = [(f"{n.name}.{cfg.nodes.domain}", n.vpn_ip) for n in store.nodes() if n.enabled]
    if write_if_changed(P.unbound_hosts_conf, unbound.hosts_conf(store.hosts(), node_names)):
        changed.add("hosts")
    if write_if_changed(P.nft_file, system.nftables(cfg, [n.vpn_ip for n in store.nodes()]), 0o640):
        changed.add("nftables")
    if write_if_changed(P.sysctl_file, system.sysctl()):
        changed.add("sysctl")

    # Suricata runs only while the IDS category is on; the drop-in marks it as managed by us
    if cfg.security.category_enabled("ids") and services.package_installed("suricata"):
        if write_if_changed(P.suricata_dropin, system.suricata_dropin()):
            changed.add("suricata-on")
    elif P.suricata_dropin.exists():
        P.suricata_dropin.unlink()
        changed.add("suricata-off")

    if reload:
        reload_changed(changed)
    return changed


def reload_changed(changed: set[str]) -> None:
    """Reload what changed. Every service is tried; failures are reported together, with the
    reason from the service's journal (systemctl itself only says that it failed)."""
    failed: list[tuple[str, str]] = []

    def attempt(name: str, unit: str, action) -> None:
        try:
            action()
        except CommandError:
            failed.append((name, unit))

    if "sysctl" in changed:
        run(["sysctl", "-p", str(P.sysctl_file)], check=False)
    if "nftables" in changed:
        attempt("firewall", services.FIREWALL_UNIT, nft.load)
    if "unbound" in changed:
        attempt("unbound", services.UNBOUND_UNIT, lambda: services.restart(services.UNBOUND_UNIT))
    elif "hosts" in changed:
        attempt("unbound", services.UNBOUND_UNIT, lambda: services.reload_or_restart(services.UNBOUND_UNIT))
    if "openvpn" in changed:
        attempt("openvpn", services.OPENVPN_UNIT, lambda: services.restart(services.OPENVPN_UNIT))
    if "suricata-on" in changed:
        services.daemon_reload()
        services.systemctl("enable", services.SURICATA_UNIT, check=False)
        services.systemctl("restart", services.SURICATA_UNIT, check=False)
        services.systemctl("enable", "--now", services.SURICATA_UPDATE_TIMER, check=False)
    if "suricata-off" in changed:
        services.disable_now(services.SURICATA_UNIT)
    if failed:
        from testops_gate.core.doctor import journal_reason
        from testops_gate.i18n import T

        reasons = "\n".join(f"{name}: {journal_reason(unit, limit=2) or T('not running')}" for name, unit in failed)
        raise ServiceError(T("Saved, but {services} did not start:\n{reasons}\nFind out why: sudo testops-gate doctor "
                             "(r on the Dashboard)", services=", ".join(name for name, _ in failed), reasons=reasons))
