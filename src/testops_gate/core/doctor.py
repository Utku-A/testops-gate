# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Find out why services are not running, and put the installation back together.

diagnose() only reads; repair() reinstalls missing packages, rewrites every generated file,
clears failed service states and restarts the services in order, then diagnoses again.
Users, certificates and settings are kept.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass

from testops_gate.config import Config
from testops_gate.i18n import T
from testops_gate.paths import P
from testops_gate.render import TUN_DEVICE
from testops_gate.system import netinfo, nft, services
from testops_gate.system.runner import CommandError, run

Log = Callable[[str], None]

BASE_PACKAGES = ["openvpn", "easy-rsa", "unbound", "nftables", "conntrack", "openssl", "iproute2", "ca-certificates"]
OPENVPN_FILES = ["server.conf", "ca.crt", "server.crt", "server.key", "tls-crypt.key", "crl.pem"]
# Journal lines worth showing when a service is down
ERROR_RE = re.compile(r"error|fail|cannot|can't|denied|not permitted|already in use|no such|exiting|invalid",
                      re.IGNORECASE)
OWNER_RE = re.compile(r'\("([^"]+)",pid=(\d+)')
SERVICE_NAMES = {
    services.OPENVPN_UNIT: "openvpn",
    services.UNBOUND_UNIT: "unbound",
    services.FIREWALL_UNIT: "firewall",
    services.DAEMON_UNIT: "testops-gated",
    services.SURICATA_UNIT: "suricata",
}


@dataclass
class Finding:
    key: str  # stable id: service:<unit>, port, tun, packages, files
    ok: bool
    title: str
    detail: str = ""


def units(cfg: Config) -> list[str]:
    result = list(services.CORE_UNITS)
    if cfg.security.category_enabled("ids") and services.package_installed("suricata"):
        result.append(services.SURICATA_UNIT)
    return result


def journal_reason(unit: str, limit: int = 3) -> str:
    """The last error-looking lines of a unit's journal (or its last lines)."""
    out = run(["journalctl", "-u", unit, "-n", "60", "--no-pager", "-o", "cat"], check=False).stdout
    lines = [line.strip() for line in out.splitlines() if line.strip()]
    errors = [line for line in lines if ERROR_RE.search(line)]
    return "\n".join((errors or lines)[-limit:])


def port_owners(cfg: Config) -> list[str]:
    """Programs other than OpenVPN listening on the VPN port, as "name (pid N)"."""
    flag = "-t" if cfg.server.protocol == "tcp" else "-u"
    out = run(["ss", "-H", "-lnp", flag, "sport", "=", f":{cfg.server.port}"], check=False).stdout
    owners = []
    for name, pid in OWNER_RE.findall(out):
        label = T("{name} (pid {pid})", name=name, pid=pid)
        if name != "openvpn" and label not in owners:
            owners.append(label)
    return owners


def port_hint(cfg: Config, owners: list[str]) -> str:
    return T("Port {port}/{proto} is used by {owners}. Stop it, or install on another port "
             "(testops-gate uninstall --keep-data, then testops-gate install --port N).",
             port=cfg.server.port, proto=cfg.server.protocol, owners=", ".join(owners))


def diagnose(cfg: Config) -> list[Finding]:
    findings = []
    missing = [p for p in BASE_PACKAGES if not services.package_installed(p)]
    findings.append(Finding("packages", not missing, T("Packages"),
                            T("missing: {packages}", packages=", ".join(missing)) if missing else ""))
    files = [name for name in OPENVPN_FILES if not (P.openvpn_dir / name).exists()]
    findings.append(Finding("files", not files, T("OpenVPN configuration"),
                            T("missing: {files}", files=", ".join(files)) if files else ""))
    findings.append(Finding("tun", netinfo.tun_available(), T("TUN device"),
                            "" if netinfo.tun_available() else T("/dev/net/tun is not available")))
    states = services.is_active(units(cfg))
    owners = [] if states.get(services.OPENVPN_UNIT) else port_owners(cfg)
    findings.append(Finding("port", not owners, T("Port {port}/{proto}", port=cfg.server.port,
                                                    proto=cfg.server.protocol),
                            port_hint(cfg, owners) if owners else ""))
    for unit, active in states.items():
        findings.append(Finding(f"service:{unit}", active, SERVICE_NAMES.get(unit, unit),
                                "" if active else (journal_reason(unit) or T("not running"))))
    return findings


def problems(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if not f.ok]


def repair(ctx, log: Log = print) -> list[Finding]:
    """Reinstall what is missing, regenerate everything and restart; returns a fresh diagnosis."""
    from testops_gate.core.apply import apply_all
    from testops_gate.core.install import _ensure_dirs, _setup_pki

    cfg = ctx.cfg
    log(T("Checking packages"))
    try:
        installed = services.apt_install(BASE_PACKAGES)
        if installed:
            log(T("Installed: {packages}", packages=", ".join(installed)))
    except CommandError as exc:
        log(T("Warning: {error}", error=exc))

    log(T("Stopping OpenVPN and removing a leftover {device} interface", device=TUN_DEVICE))
    services.systemctl("stop", services.OPENVPN_UNIT, check=False)
    run(["ip", "link", "delete", TUN_DEVICE], check=False)

    log(T("Restoring directories, certificates and keys"))
    tls_key_missing = not (P.openvpn_dir / "tls-crypt.key").exists()
    _ensure_dirs()
    _setup_pki(cfg, log)
    ctx.refresh_crl()
    if tls_key_missing:
        # Profiles carry the tls-crypt key: the ones issued with the lost key no longer connect
        if cfg.auth.mode == "profile-password":
            log(T("The tls-crypt key was recreated: give every user a new password and profile "
                  "(testops-gate user passwd NAME)"))
        else:
            for user in ctx.store.users():
                ctx.write_profile(user.name)
            log(T("The tls-crypt key was recreated: send every user their new profile"))

    log(T("Writing configuration"))
    apply_all(cfg, ctx.store, reload=False)

    log(T("Restarting services"))
    run(["sysctl", "-p", str(P.sysctl_file)], check=False)
    services.daemon_reload()
    run(["systemctl", "reset-failed", *units(cfg)], check=False)
    for unit in (services.FIREWALL_UNIT, services.UNBOUND_UNIT, services.OPENVPN_UNIT, services.DAEMON_UNIT):
        services.systemctl("enable", unit, check=False)
        services.systemctl("restart", unit, check=False)
    try:
        nft.load()
    except CommandError as exc:
        log(T("Warning: {error}", error=exc))
    if services.SURICATA_UNIT in units(cfg) and P.suricata_dropin.exists():
        services.systemctl("restart", services.SURICATA_UNIT, check=False)

    # OpenVPN reports "active" only after it has opened the port and the TUN device
    for _ in range(10):
        if services.is_active([services.OPENVPN_UNIT])[services.OPENVPN_UNIT]:
            break
        time.sleep(1)
    findings = diagnose(cfg)
    log(T("Done: everything is running") if not problems(findings)
        else T("Still not working: {items}", items=", ".join(f.title for f in problems(findings))))
    return findings
