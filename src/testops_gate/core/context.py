# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Management operations shared by the CLI, the TUI and the daemon.

A Context bundles the loaded settings and the state database. Every change
saves what it touched and calls apply() so the generated files follow.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import time
from dataclasses import dataclass

from testops_gate import config as config_mod
from testops_gate import logs
from testops_gate.config import SEVERITIES, TUNNEL_MODES, UPSTREAMS, Channel, Config, new_channel_id
from testops_gate.core.apply import apply_all, write_ccd
from testops_gate.db import Host, Store, User
from testops_gate.i18n import T, set_language
from testops_gate.paths import P
from testops_gate.render import openvpn
from testops_gate.system import services
from testops_gate.system.easyrsa import EasyRSA
from testops_gate.system.openvpn import Management, ManagementError
from testops_gate.system.runner import run

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
FIRST_CLIENT_OFFSET = 10  # 10.8.0.1 is the server; users start at .10
CERT_DAYS_DEFAULT = 365
USER_MODES = ("default", *TUNNEL_MODES)


class ValidationError(ValueError):
    """Invalid input; the message is already translated for display."""


def is_hostname(name: str, allow_wildcard: bool = False) -> bool:
    if allow_wildcard and name.startswith("*."):
        name = name[2:]
    labels = name.rstrip(".").split(".")
    return len(labels) >= 2 and all(LABEL_RE.match(label) for label in labels)


@dataclass
class Context:
    cfg: Config
    store: Store
    reload: bool = True  # False in tests: write files but do not touch services

    @classmethod
    def open(cls, reload: bool = True) -> Context:
        cfg = config_mod.load()
        set_language(cfg.language)
        return cls(cfg, Store(), reload)

    def save(self) -> None:
        config_mod.save(self.cfg)

    def apply(self) -> set[str]:
        return apply_all(self.cfg, self.store, reload=self.reload)

    def kick(self, name: str) -> bool:
        if not self.reload:
            return False
        try:
            return Management().kill(name)
        except ManagementError:
            return False

    # --- users ---------------------------------------------------------------

    def allocate_ip(self) -> str:
        net = openvpn.network(self.cfg)
        used = {u.vpn_ip for u in self.store.users()}
        for index, address in enumerate(net.hosts()):
            if index + 1 >= FIRST_CLIENT_OFFSET and str(address) not in used:
                return str(address)
        raise ValidationError(T("No free VPN addresses left in {net}", net=net))

    def _validate_user_ip(self, vpn_ip: str, name: str) -> None:
        net = openvpn.network(self.cfg)
        try:
            address = ipaddress.IPv4Address(vpn_ip)
        except ValueError:
            raise ValidationError(T("Enter a valid IPv4 address")) from None
        if address not in net or address in (net.network_address, net.broadcast_address, next(net.hosts())):
            raise ValidationError(T("The address must be a client address inside {net}", net=net))
        other = next((u for u in self.store.users() if u.vpn_ip == vpn_ip and u.name != name), None)
        if other:
            raise ValidationError(T("{ip} is already used by {name}", ip=vpn_ip, name=other.name))

    def add_user(self, name: str, email: str = "", mode: str = "default", days: int = CERT_DAYS_DEFAULT,
                 vpn_ip: str = "") -> User:
        name = name.strip()
        if not USER_RE.match(name):
            raise ValidationError(T("Username may only contain letters, digits, '-' and '_' (max 32)"))
        if self.store.user(name):
            raise ValidationError(T("'{name}' already exists", name=name))
        if email and "@" not in email:
            raise ValidationError(T("Enter a valid email"))
        if mode not in USER_MODES:
            raise ValidationError(T("Unknown tunnel mode: {mode}", mode=mode))
        if vpn_ip:
            self._validate_user_ip(vpn_ip, name)
        pki = EasyRSA()
        if pki.cert(name).exists():
            # left over from an earlier user with the same name: retire it first
            pki.revoke(name)
            self._publish_crl(pki)
        pki.remove_issued(name)
        pki.build_client(name, days)
        now = time.time()
        user = User(name, email.strip(), vpn_ip or self.allocate_ip(), mode, True, now, now + days * 86400)
        self.store.add_user(user)
        self.write_profile(name)
        logs.ensure_user_dir(name)
        write_ccd(self.cfg, self.store)
        logs.audit("user.add", f"{name} vpn_ip={user.vpn_ip} mode={mode} days={days}")
        return user

    def update_user(self, name: str, *, email: str | None = None, mode: str | None = None,
                    vpn_ip: str | None = None, note: str | None = None) -> User:
        user = self._user(name)
        fields: dict[str, object] = {}
        if email is not None:
            if email and "@" not in email:
                raise ValidationError(T("Enter a valid email"))
            fields["email"] = email.strip()
        if mode is not None:
            if mode not in USER_MODES:
                raise ValidationError(T("Unknown tunnel mode: {mode}", mode=mode))
            fields["mode"] = mode
        if vpn_ip is not None and vpn_ip != user.vpn_ip:
            self._validate_user_ip(vpn_ip, name)
            fields["vpn_ip"] = vpn_ip
        if note is not None:
            fields["note"] = note
        if fields:
            self.store.update_user(name, **fields)
            write_ccd(self.cfg, self.store)
            logs.audit("user.edit", f"{name} " + " ".join(f"{k}={v}" for k, v in fields.items()))
        return self._user(name)

    def set_user_enabled(self, name: str, enabled: bool) -> bool:
        """Enable or disable a user; returns True if an active session was dropped."""
        self._user(name)
        self.store.update_user(name, enabled=enabled, blocked_until=0)
        write_ccd(self.cfg, self.store)
        kicked = False if enabled else self.kick(name)
        logs.audit("user.enable" if enabled else "user.disable", name)
        return kicked

    def block_user(self, name: str, minutes: int) -> None:
        """Temporary block (automatic blocking): cleared by the daemon when it expires."""
        self.store.update_user(name, blocked_until=time.time() + minutes * 60)
        write_ccd(self.cfg, self.store)
        self.kick(name)
        logs.audit("user.block", f"{name} minutes={minutes}", actor="testops-gated")

    def delete_user(self, name: str) -> None:
        self._user(name)
        pki = EasyRSA()
        if pki.cert(name).exists():
            pki.revoke(name)
            self._publish_crl(pki)
        pki.remove_issued(name)
        self.store.delete_user(name)
        (P.profiles_dir / f"{name}.ovpn").unlink(missing_ok=True)
        write_ccd(self.cfg, self.store)
        self.kick(name)
        logs.audit("user.delete", name)

    def renew_user(self, name: str, days: int = CERT_DAYS_DEFAULT) -> None:
        self._user(name)
        pki = EasyRSA()
        if pki.cert(name).exists():
            pki.revoke(name)
            self._publish_crl(pki)
        pki.remove_issued(name)
        pki.build_client(name, days)
        self.store.update_user(name, cert_expires=time.time() + days * 86400)
        self.write_profile(name)
        self.kick(name)
        logs.audit("user.renew", f"{name} days={days}")

    def profile(self, name: str) -> str:
        self._user(name)
        path = P.profiles_dir / f"{name}.ovpn"
        if not path.exists():
            self.write_profile(name)
        return path.read_text()

    def export_profile(self, name: str, destination: str) -> str:
        """Copy a profile to destination (a file or a directory); returns the written path."""
        content = self.profile(name)
        target = os.path.expanduser(destination)
        if os.path.isdir(target):
            target = os.path.join(target, f"{name}.ovpn")
        with open(target, "w") as fh:
            fh.write(content)
        os.chmod(target, 0o600)
        owner = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
        if all(owner) and os.geteuid() == 0:
            os.chown(target, int(owner[0]), int(owner[1]))
        logs.audit("user.export", f"{name} -> {target}")
        return target

    def write_profile(self, name: str) -> None:
        pki = EasyRSA()
        content = openvpn.client_profile(
            self.cfg,
            ca=pki.ca_cert.read_text(),
            cert=pki.client_pem(name),
            key=pki.key(name).read_text(),
            tls_crypt=(P.openvpn_dir / "tls-crypt.key").read_text(),
        )
        P.profiles_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(P.profiles_dir, 0o700)
        path = P.profiles_dir / f"{name}.ovpn"
        path.write_text(content)
        os.chmod(path, 0o600)

    def _publish_crl(self, pki: EasyRSA) -> None:
        pki.gen_crl()
        target = P.openvpn_dir / "crl.pem"
        shutil.copyfile(pki.crl, target)
        os.chmod(target, 0o644)

    def refresh_crl(self) -> None:
        self._publish_crl(EasyRSA())

    def _user(self, name: str) -> User:
        user = self.store.user(name)
        if not user:
            raise ValidationError(T("No such user: {name}", name=name))
        return user

    # --- hosts ---------------------------------------------------------------

    def save_host(self, name: str, rtype: str, value: str, note: str = "", old_name: str | None = None) -> Host:
        name = name.strip().lower().rstrip(".")
        value = value.strip().rstrip(".")
        rtype = rtype.upper()
        if not is_hostname(name, allow_wildcard=True):
            raise ValidationError(T("Enter a valid domain (e.g. stage.internal)"))
        existing = self.store.host(name)
        if existing and name != old_name:
            raise ValidationError(T("'{name}' is already defined", name=name))
        if rtype == "A":
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                raise ValidationError(T("Enter a valid IPv4 address for an A record")) from None
        elif rtype == "CNAME":
            if not is_hostname(value.lower()):
                raise ValidationError(T("Enter a valid domain as the CNAME target"))
            value = value.lower()
        else:
            raise ValidationError(T("Record type must be A or CNAME"))
        host = Host(name, rtype, value, note.strip())
        self.store.upsert_host(host, old_name=old_name)
        self.apply()
        logs.audit("host.edit" if old_name else "host.add", f"{name} {rtype} {value}")
        return host

    def delete_host(self, name: str) -> None:
        if not self.store.host(name):
            raise ValidationError(T("No such host: {name}", name=name))
        self.store.delete_host(name)
        self.apply()
        logs.audit("host.delete", name)

    # --- settings ------------------------------------------------------------

    def set_tunnel_mode(self, mode: str) -> None:
        if mode not in TUNNEL_MODES:
            raise ValidationError(T("Unknown tunnel mode: {mode}", mode=mode))
        self.cfg.tunnel.mode = mode
        self.save()
        self.apply()
        logs.audit("tunnel.mode", mode)

    def set_extra_routes(self, routes: list[str]) -> None:
        clean = []
        for route in routes:
            try:
                clean.append(str(ipaddress.IPv4Network(route.strip(), strict=False)))
            except ValueError:
                raise ValidationError(T("Invalid network: {value}", value=route)) from None
        self.cfg.tunnel.extra_routes = clean
        self.save()
        self.apply()
        logs.audit("tunnel.routes", ",".join(clean))

    def set_retention(self, days: int) -> None:
        if not 1 <= days <= 3650:
            raise ValidationError(T("Retention must be between 1 and 3650 days"))
        self.cfg.logging.retention_days = days
        self.save()
        logs.audit("logging.retention", str(days))

    def set_upstream(self, upstream: str) -> None:
        if upstream not in UPSTREAMS:
            raise ValidationError(T("Unknown DNS upstream: {value}", value=upstream))
        self.cfg.dns.upstream = upstream
        self.save()
        self.apply()
        logs.audit("dns.upstream", upstream)

    def set_update_check(self, check: bool) -> None:
        self.cfg.updates.check = check
        self.save()
        logs.audit("updates.check", str(check))

    def set_update_url(self, url: str) -> None:
        url = url.strip()
        if url and not url.startswith(("https://", "http://")):
            raise ValidationError(T("The update URL must be an http(s) URL"))
        self.cfg.updates.base_url = url
        self.save()
        logs.audit("updates.url", url or "default")

    def set_dns_enforce(self, enforce: bool) -> None:
        self.cfg.dns.enforce = enforce
        self.save()
        self.apply()
        logs.audit("dns.enforce", str(enforce))

    def set_language(self, language: str) -> None:
        self.cfg.language = language
        set_language(language)
        self.save()
        logs.audit("ui.language", language)

    def set_security(self, enabled: bool | None = None, **categories: bool) -> None:
        sec = self.cfg.security
        if enabled is not None:
            sec.enabled = enabled
        for key, value in categories.items():
            if key not in sec.categories:
                raise ValidationError(T("Unknown security category: {value}", value=key))
            sec.categories[key] = value
        if sec.category_enabled("ids"):
            try:
                self.ensure_ids_installed()
            except Exception:
                sec.categories["ids"] = False  # stays off until Suricata can be installed
                raise
        self.save()
        self.apply()
        detail = " ".join([*([f"enabled={enabled}"] if enabled is not None else []),
                           *(f"{k}={v}" for k, v in categories.items())])
        logs.audit("security.set", detail)

    def ensure_ids_installed(self) -> None:
        """Install Suricata the first time the IDS category is turned on (can take minutes)."""
        if not self.reload or services.package_installed("suricata"):
            return
        new = services.install_ids()
        self.cfg.installed_packages = sorted(set(self.cfg.installed_packages) | set(new))
        run(["suricata-update", "--no-test"], check=False, timeout=900)
        logs.audit("security.ids", "suricata installed")

    def set_security_lists(self, blocked_networks: list[str] | None = None,
                           forbidden_ports: list[str] | None = None) -> None:
        sec = self.cfg.security
        if blocked_networks is not None:
            clean = []
            for value in blocked_networks:
                try:
                    clean.append(str(ipaddress.IPv4Network(value.strip(), strict=False)))
                except ValueError:
                    raise ValidationError(T("Invalid network: {value}", value=value)) from None
            sec.blocked_networks = clean
        if forbidden_ports is not None:
            clean_ports = []
            for value in forbidden_ports:
                value = value.strip()
                parts = value.split("-")
                if not all(p.isdigit() and 1 <= int(p) <= 65535 for p in parts) or len(parts) > 2:
                    raise ValidationError(T("Invalid port or range: {value}", value=value))
                clean_ports.append(value)
            sec.forbidden_ports = clean_ports
        self.save()
        self.apply()
        logs.audit("security.lists", f"blocked={sec.blocked_networks} ports={sec.forbidden_ports}")

    def set_rpz_url(self, url: str) -> None:
        url = url.strip()
        if not url.startswith(("https://", "http://")):
            raise ValidationError(T("The RPZ feed must be an http(s) URL"))
        if url != self.cfg.security.rpz_url:
            P.unbound_rpz_zone.unlink(missing_ok=True)  # cached copy of the old feed
        self.cfg.security.rpz_url = url
        self.save()
        self.apply()
        logs.audit("security.rpz", url)

    # --- notification channels -----------------------------------------------

    def save_channel(self, channel: Channel) -> Channel:
        if channel.kind not in ("slack", "email"):
            raise ValidationError(T("Channel type must be slack or email"))
        if channel.min_severity not in SEVERITIES:
            raise ValidationError(T("Unknown severity: {value}", value=channel.min_severity))
        if channel.kind == "slack":
            url = channel.webhook.strip()
            local = url.startswith(("http://127.0.0.1", "http://localhost"))
            if not (url.startswith("https://") or local):
                raise ValidationError(T("Webhook URL must start with https://"))
            channel.webhook = url
        else:
            channel.recipients = [r.strip() for r in channel.recipients if r.strip()]
            if not channel.recipients or any("@" not in r for r in channel.recipients):
                raise ValidationError(T("Enter at least one valid recipient email"))
            if not channel.smtp_host:
                raise ValidationError(T("SMTP server cannot be empty"))
            if not 1 <= int(channel.smtp_port) <= 65535:
                raise ValidationError(T("Port must be between 1 and 65535"))
            channel.sender = channel.sender or channel.smtp_user
            if "@" not in channel.sender:
                raise ValidationError(T("Sender must contain a valid email address"))
        if not channel.id:
            channel.id = new_channel_id()
        existing = self.cfg.channel(channel.id)
        if existing:
            self.cfg.channels[self.cfg.channels.index(existing)] = channel
        else:
            self.cfg.channels.append(channel)
        self.save()
        logs.audit("notify.save", f"{channel.id} {channel.kind} {channel.name}")
        return channel

    def delete_channel(self, channel_id: str) -> None:
        channel = self.cfg.channel(channel_id)
        if not channel:
            raise ValidationError(T("No such channel: {value}", value=channel_id))
        self.cfg.channels.remove(channel)
        self.save()
        logs.audit("notify.delete", f"{channel_id} {channel.name}")

    def set_channel_enabled(self, channel_id: str, enabled: bool) -> None:
        channel = self.cfg.channel(channel_id)
        if not channel:
            raise ValidationError(T("No such channel: {value}", value=channel_id))
        channel.enabled = enabled
        self.save()
        logs.audit("notify.enable" if enabled else "notify.disable", channel_id)
