# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""First-time setup and removal."""

from __future__ import annotations

import grp
import os
import secrets
import shutil
from collections.abc import Callable
from dataclasses import dataclass

from testops_gate import config as config_mod
from testops_gate import logs
from testops_gate.config import PROTOCOLS, TUNNEL_MODES, UPSTREAMS, Config
from testops_gate.core.context import Context, ValidationError
from testops_gate.db import Store
from testops_gate.i18n import T, set_language
from testops_gate.paths import P
from testops_gate.system import netinfo, nft, services
from testops_gate.system.easyrsa import EasyRSA
from testops_gate.system.runner import CommandError, run

BASE_PACKAGES = ["openvpn", "easy-rsa", "unbound", "nftables", "conntrack", "openssl", "iproute2", "ca-certificates"]
IDS_PACKAGES = services.IDS_PACKAGES
IDS_MIN_MEMORY_MB = 2048
GROUP = "testops-gate"

Log = Callable[[str], None]


@dataclass
class InstallOptions:
    endpoint: str
    port: int = 1194
    protocol: str = "udp"
    tunnel_mode: str = "split"
    upstream: str = "cloudflare"
    language: str = "en"
    security: bool = True
    ids: bool = True
    first_user: str = ""
    first_user_email: str = ""
    install_packages: bool = True


def preflight() -> list[str]:
    """Problems that prevent installation (translated)."""
    problems = []
    if not netinfo.is_root():
        problems.append(T("testops-gate must be run as root (sudo testops-gate)"))
    if not netinfo.tun_available():
        problems.append(T("The TUN device (/dev/net/tun) is not available"))
    info = netinfo.os_info()
    if not info.supported:
        problems.append(T("Unsupported system: {os}. Supported: Debian 12 or later, Ubuntu 22.04 or later and their derivatives",
                           os=info.pretty))
    return problems


def validate(opts: InstallOptions) -> None:
    if not opts.endpoint.strip():
        raise ValidationError(T("Enter the public address or hostname clients connect to"))
    if not 1 <= opts.port <= 65535:
        raise ValidationError(T("Port must be between 1 and 65535"))
    if opts.protocol not in PROTOCOLS:
        raise ValidationError(T("Protocol must be udp or tcp"))
    if opts.tunnel_mode not in TUNNEL_MODES:
        raise ValidationError(T("Unknown tunnel mode: {mode}", mode=opts.tunnel_mode))
    if opts.upstream not in UPSTREAMS:
        raise ValidationError(T("Unknown DNS upstream: {value}", value=opts.upstream))


def _ensure_dirs() -> None:
    for path, mode in [
        (P.config_dir, 0o750),
        (P.state_dir, 0o750),
        (P.profiles_dir, 0o700),
        (P.log_dir, 0o750),
        (P.users_log_dir, 0o750),
        (P.security_log_dir, 0o750),
        (P.audit_log_dir, 0o750),
        (P.openvpn_dir, 0o755),
    ]:
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
    try:
        gid = grp.getgrnam(GROUP).gr_gid
    except KeyError:
        return
    for path in (P.config_dir, P.state_dir, P.log_dir, P.users_log_dir, P.security_log_dir, P.audit_log_dir):
        try:
            os.chown(path, 0, gid)
        except PermissionError:
            pass


def _setup_pki(cfg: Config, log: Log) -> None:
    pki = EasyRSA()
    if not pki.initialised():
        log(T("Creating certificate authority"))
        pki.init(f"TestOps Gate CA {cfg.server.server_name}")
        pki.build_server(cfg.server.server_name)
        pki.gen_crl()
    tls_key = P.openvpn_dir / "tls-crypt.key"
    if not tls_key.exists():
        run(["openvpn", "--genkey", "secret", str(tls_key)])
    os.chmod(tls_key, 0o600)
    for source, name, mode in [
        (pki.ca_cert, "ca.crt", 0o644),
        (pki.cert(cfg.server.server_name), "server.crt", 0o644),
        (pki.key(cfg.server.server_name), "server.key", 0o600),
        (pki.crl, "crl.pem", 0o644),
    ]:
        target = P.openvpn_dir / name
        shutil.copyfile(source, target)
        os.chmod(target, mode)


def install(opts: InstallOptions, log: Log = print) -> Context:
    validate(opts)
    set_language(opts.language)
    want_ids = opts.security and opts.ids

    new_packages: list[str] = []
    if opts.install_packages:
        log(T("Installing packages: {packages}", packages=", ".join(BASE_PACKAGES)))
        new_packages += services.apt_install(BASE_PACKAGES)
        if want_ids:
            if 0 < netinfo.total_memory_mb() < IDS_MIN_MEMORY_MB:
                log(T("Warning: less than 2 GB RAM; Suricata may be slow. You can turn it off under Security."))
            log(T("Installing Suricata (IDS)"))
            try:
                new_packages += services.install_ids()
            except (CommandError, RuntimeError) as exc:
                log(T("Warning: Suricata could not be installed ({error}); continuing without IDS. "
                      "You can turn it on later under Security.", error=exc))
                want_ids = False

    _ensure_dirs()
    if config_mod.exists():
        cfg = config_mod.load()
        log(T("Existing configuration found; keeping users, hosts and certificates"))
    else:
        cfg = Config()
        cfg.server.server_name = "tg-" + secrets.token_hex(6)
    cfg.language = opts.language
    cfg.server.endpoint = opts.endpoint.strip()
    cfg.server.port = opts.port
    cfg.server.protocol = opts.protocol
    cfg.server.interface = netinfo.default_interface()
    cfg.tunnel.mode = opts.tunnel_mode
    cfg.dns.upstream = opts.upstream
    cfg.security.enabled = opts.security
    cfg.security.categories["ids"] = want_ids
    cfg.installed_packages = sorted(set(cfg.installed_packages) | set(new_packages))
    config_mod.save(cfg)

    _setup_pki(cfg, log)
    ctx = Context(cfg, Store(), reload=False)

    if want_ids:
        log(T("Downloading Suricata rules (ET Open)"))
        try:
            run(["suricata-update", "--no-test"], timeout=900)
        except CommandError as exc:
            log(T("Warning: rule download failed ({error}); it will be retried daily", error=exc))

    log(T("Writing configuration"))
    ctx.apply()
    ctx.reload = True

    log(T("Starting services"))
    run(["sysctl", "-p", str(P.sysctl_file)], check=False)
    services.daemon_reload()
    services.enable_now(services.FIREWALL_UNIT)
    nft.load()
    services.restart(services.UNBOUND_UNIT)
    services.systemctl("enable", services.UNBOUND_UNIT)
    services.enable_now(services.OPENVPN_UNIT)
    services.restart(services.OPENVPN_UNIT)
    if want_ids and P.suricata_dropin.exists():
        services.systemctl("enable", services.SURICATA_UNIT, check=False)
        services.systemctl("restart", services.SURICATA_UNIT, check=False)
        services.systemctl("enable", "--now", services.SURICATA_UPDATE_TIMER, check=False)
    services.enable_now(services.DAEMON_UNIT)
    services.restart(services.DAEMON_UNIT)

    logs.audit("install", f"endpoint={cfg.server.endpoint} port={cfg.server.port}/{cfg.server.protocol}")
    if opts.first_user and not ctx.store.user(opts.first_user):
        user = ctx.add_user(opts.first_user, opts.first_user_email)
        log(T("User {name} created: {path}", name=user.name, path=P.profiles_dir / f"{user.name}.ovpn"))
    log(T("Installation complete"))
    return ctx


PACKAGE = "testops-gate"


def uninstall(purge: bool = False, remove_packages: bool = False, log: Log = print) -> list[str]:
    """Stop and remove testops-gate.

    purge: also delete certificates, users, state and logs.
    remove_packages: also purge the packages `install` added. The testops-gate package
    itself cannot be removed by the running program, so the apt command that removes it
    (and the dependencies it pulled in) is returned for the caller to run last.
    """
    packages = config_mod.load().installed_packages if config_mod.exists() else []
    log(T("Stopping services"))
    for unit in (services.DAEMON_UNIT, services.OPENVPN_UNIT, services.FIREWALL_UNIT, services.SURICATA_UPDATE_TIMER):
        services.disable_now(unit)
    if P.suricata_dropin.exists():
        services.disable_now(services.SURICATA_UNIT)
        P.suricata_dropin.unlink()
    nft.delete_table()

    log(T("Removing generated configuration"))
    for path in (P.unbound_conf, P.unbound_hosts_conf, P.sysctl_file):
        path.unlink(missing_ok=True)
    for name in ("server.conf", "ca.crt", "server.crt", "server.key", "crl.pem", "tls-crypt.key"):
        (P.openvpn_dir / name).unlink(missing_ok=True)
    shutil.rmtree(P.ccd_dir, ignore_errors=True)
    for path in (P.status_file, P.unbound_rpz_zone, P.backports_list):
        path.unlink(missing_ok=True)
    services.daemon_reload()
    if not (remove_packages and "unbound" in packages):
        services.systemctl("restart", services.UNBOUND_UNIT, check=False)

    if purge:
        log(T("Deleting certificates, state and logs"))
        for path in (P.config_dir, P.state_dir, P.log_dir):
            shutil.rmtree(path, ignore_errors=True)
    else:
        logs.audit("uninstall", "configuration kept")

    final: list[str] = []
    if remove_packages:
        if packages:
            log(T("Removing packages: {packages}", packages=", ".join(packages)))
            services.apt_purge(packages)
        if services.package_installed(PACKAGE):
            final = ["apt-get", "purge" if purge else "remove", "-y", "--autoremove", PACKAGE]
    log(T("TestOps Gate removed"))
    return final


def run_final(command: list[str]) -> None:
    """Replace the current process with an apt command (package removal or update; does not return)."""
    os.execvpe(command[0], command, {**os.environ, **services.APT_ENV})
