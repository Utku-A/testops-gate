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
from dataclasses import dataclass, field, replace

from testops_gate import config as config_mod
from testops_gate import logs
from testops_gate.config import (
    AUTH_MODES,
    PROTOCOLS,
    SEVERITIES,
    TUNNEL_MODES,
    UPSTREAMS,
    Channel,
    Config,
    new_channel_id,
)
from testops_gate.core import passwords
from testops_gate.core.apply import apply_all, write_auth, write_ccd
from testops_gate.db import Host, Store, User
from testops_gate.i18n import T, set_language
from testops_gate.paths import P
from testops_gate.render import openvpn
from testops_gate.system import forwarding, services
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
    new_user: User | None = field(default=None, repr=False)  # set by install(): the first user

    @classmethod
    def open(cls, reload: bool = True) -> Context:
        cfg = config_mod.load()
        set_language(cfg.language)
        return cls(cfg, Store(), reload)

    def save(self) -> None:
        config_mod.save(self.cfg)

    def apply(self) -> set[str]:
        return apply_all(self.cfg, self.store, reload=self.reload)

    def reconnect(self, names: list[str]) -> list[str]:
        """Make connected users reconnect so new per-user settings apply; returns who reconnected."""
        if not self.reload or not names:
            return []
        try:
            management = Management()
            return [name for name in names if management.restart(name)]
        except ManagementError:
            return []

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

    def _write_user_files(self) -> None:
        """Per-user files OpenVPN reads on each connection: ccd and the password hashes."""
        write_ccd(self.cfg, self.store)
        write_auth(self.cfg, self.store)

    @property
    def uses_passwords(self) -> bool:
        return self.cfg.auth.mode != "certificate"

    def _new_password(self, password: str | None) -> str:
        if not password:
            return passwords.generate()
        try:
            passwords.validate(password)
        except passwords.PasswordError as exc:
            raise ValidationError(str(exc)) from None
        return password

    def add_user(self, name: str, email: str = "", mode: str = "default", days: int = CERT_DAYS_DEFAULT,
                 vpn_ip: str = "", password: str | None = None) -> User:
        """Create a user. With passwords on, `password` (generated when empty) is returned once
        in the result's `password` attribute; it is not stored in plain text anywhere."""
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
        password = self._new_password(password) if self.uses_passwords else ""
        pki = EasyRSA()
        if pki.cert(name).exists():
            # left over from an earlier user with the same name: retire it first
            pki.revoke(name)
            self._publish_crl(pki)
        pki.remove_issued(name)
        pki.build_client(name, days)
        now = time.time()
        user = User(name, email.strip(), vpn_ip or self.allocate_ip(), mode, True, now, now + days * 86400,
                    password_hash=passwords.hash_password(password) if self.cfg.auth.mode == "user-password" else "")
        self.store.add_user(user)
        self.write_profile(name, key_password=password)
        logs.ensure_user_dir(name)
        self._write_user_files()
        logs.audit("user.add", f"{name} vpn_ip={user.vpn_ip} mode={mode} days={days}")
        user.password = password
        return user

    def set_password(self, name: str, password: str | None = None) -> str:
        """Set (or generate) a user's password; returns it.

        user-password: the server checks the new password from now on; the session is dropped.
        profile-password: the profile is re-encrypted; the user needs the new profile.
        """
        self._user(name)
        if not self.uses_passwords:
            raise ValidationError(T("Passwords are off (Settings → Authentication)"))
        password = self._new_password(password)
        if self.cfg.auth.mode == "user-password":
            self.store.update_user(name, password_hash=passwords.hash_password(password))
            self._write_user_files()
            self.kick(name)
        else:
            self.write_profile(name, key_password=password)
        logs.audit("user.password", name)
        return password

    def set_auth_mode(self, mode: str) -> dict[str, str]:
        """Switch how users sign in; returns the passwords it had to create (user: password).

        Every profile is rewritten (the sign-in settings are part of it), so users need their
        profile again; with profile passwords each profile gets a new password.
        """
        if mode not in AUTH_MODES:
            raise ValidationError(T("Unknown sign-in mode: {mode}", mode=mode))
        self.cfg.auth.mode = mode
        self.save()
        created: dict[str, str] = {}
        for user in self.store.users():
            password = None
            if mode == "profile-password" or (mode == "user-password" and not user.has_password):
                password = created[user.name] = passwords.generate()
            if mode == "user-password" and password:
                self.store.update_user(user.name, password_hash=passwords.hash_password(password))
            self.write_profile(user.name, key_password=password)
        self.apply()
        logs.audit("auth.mode", mode)
        return created

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
            self._write_user_files()
            logs.audit("user.edit", f"{name} " + " ".join(f"{k}={v}" for k, v in fields.items()))
            if "mode" in fields or "vpn_ip" in fields:
                self.reconnect([name])  # its ccd changed: apply it now if connected
        return self._user(name)

    def set_user_enabled(self, name: str, enabled: bool) -> bool:
        """Enable or disable a user; returns True if an active session was dropped."""
        self._user(name)
        self.store.update_user(name, enabled=enabled, blocked_until=0)
        self._write_user_files()
        kicked = False if enabled else self.kick(name)
        logs.audit("user.enable" if enabled else "user.disable", name)
        return kicked

    def block_user(self, name: str, minutes: int) -> None:
        """Temporary block (automatic blocking): cleared by the daemon when it expires."""
        self.store.update_user(name, blocked_until=time.time() + minutes * 60)
        self._write_user_files()
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
        self._write_user_files()
        self.kick(name)
        logs.audit("user.delete", name)

    def renew_user(self, name: str, days: int = CERT_DAYS_DEFAULT) -> str:
        """New certificate and profile; returns the new profile password with profile passwords, else ""."""
        self._user(name)
        pki = EasyRSA()
        if pki.cert(name).exists():
            pki.revoke(name)
            self._publish_crl(pki)
        pki.remove_issued(name)
        pki.build_client(name, days)
        self.store.update_user(name, cert_expires=time.time() + days * 86400)
        password = passwords.generate() if self.cfg.auth.mode == "profile-password" else ""
        self.write_profile(name, key_password=password)
        self.kick(name)
        logs.audit("user.renew", f"{name} days={days}")
        return password

    def profile(self, name: str) -> str:
        self._user(name)
        path = P.profiles_dir / f"{name}.ovpn"
        if not path.exists():
            if self.cfg.auth.mode == "profile-password":
                raise ValidationError(T("The profile of {name} is missing; set a new password to create it: "
                                        "testops-gate user passwd {name}", name=name))
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

    # --- profile emails --------------------------------------------------------

    def mail_channel(self) -> Channel | None:
        """The email notification channel whose SMTP settings send profiles."""
        return next((c for c in self.cfg.channels if c.kind == "email" and c.enabled), None)

    def send_profile(self, name: str) -> str:
        """Email a user their profile with setup steps (never the password); returns the address."""
        from testops_gate.notify import profile_mail
        from testops_gate.notify.send import smtp_send

        user = self._user(name)
        if not user.email:
            raise ValidationError(T("{name} has no email address", name=name))
        channel = self.mail_channel()
        if channel is None:
            raise ValidationError(T("Add an email notification channel first (Settings → Notification channels); "
                                    "its SMTP server sends the profiles"))
        smtp_send(channel, profile_mail.build(self.cfg, channel, user, self.profile(name)))
        logs.audit("user.send-profile", f"{name} -> {user.email}")
        return user.email

    def send_profiles(self, names: list[str] | None = None) -> tuple[list[str], list[tuple[str, str]]]:
        """Email profiles to the given users (default: all); returns (sent, [(skipped, reason)])."""
        if self.mail_channel() is None:
            raise ValidationError(T("Add an email notification channel first (Settings → Notification channels); "
                                    "its SMTP server sends the profiles"))
        sent, skipped = [], []
        for user in self.store.users() if names is None else [self._user(n) for n in names]:
            try:
                self.send_profile(user.name)
                sent.append(user.name)
            except (ValidationError, RuntimeError) as exc:  # RuntimeError includes DeliveryError
                skipped.append((user.name, str(exc)))
        return sent, skipped

    def write_profile(self, name: str, key_password: str | None = None) -> None:
        pki = EasyRSA()
        key = pki.key(name).read_text()
        if self.cfg.auth.mode == "profile-password":
            if not key_password:
                raise ValidationError(T("A profile password is required"))
            # The password goes through the environment, not the command line (visible in ps)
            key = run(["openssl", "pkey", "-in", str(pki.key(name)), "-aes-256-cbc", "-passout", "env:TG_KEY_PASS"],
                      env={"TG_KEY_PASS": key_password}).stdout
        content = openvpn.client_profile(
            self.cfg,
            ca=pki.ca_cert.read_text(),
            cert=pki.client_pem(name),
            key=key,
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

    def set_server(self, *, endpoint: str | None = None, port: int | None = None,
                   protocol: str | None = None) -> dict[str, str]:
        """Change the address, port or protocol clients connect to.

        All three are written into every profile, so every profile is renewed (users need it
        again); with profile passwords each one gets a new password, returned as user: password.
        OpenVPN restarts and the firewall opens the new port.
        """
        from testops_gate.core import doctor

        server = self.cfg.server
        new_endpoint = server.endpoint if endpoint is None else endpoint.strip()
        new_port = server.port if port is None else port
        new_protocol = protocol or server.protocol
        if not new_endpoint or any(ch.isspace() for ch in new_endpoint):
            raise ValidationError(T("Enter the public address or hostname clients connect to"))
        if not 1 <= new_port <= 65535:
            raise ValidationError(T("Port must be between 1 and 65535"))
        if new_protocol not in PROTOCOLS:
            raise ValidationError(T("Protocol must be udp or tcp"))
        if (new_endpoint, new_port, new_protocol) == (server.endpoint, server.port, server.protocol):
            return {}
        if (new_port, new_protocol) != (server.port, server.protocol):
            probe = replace(self.cfg, server=replace(server, port=new_port, protocol=new_protocol))
            owners = doctor.port_owners(probe)
            if owners:
                raise ValidationError(T("Port {port}/{proto} is used by {owners}", port=new_port,
                                        proto=new_protocol, owners=", ".join(owners)))
        server.endpoint, server.port, server.protocol = new_endpoint, new_port, new_protocol
        self.save()
        created: dict[str, str] = {}
        for user in self.store.users():
            password = None
            if self.cfg.auth.mode == "profile-password":
                password = created[user.name] = passwords.generate()
            self.write_profile(user.name, key_password=password)
        self.apply()
        logs.audit("server.change", f"{new_endpoint}:{new_port}/{new_protocol}")
        return created

    def set_tunnel_mode(self, mode: str, reconnect: bool = True) -> list[str]:
        """Change the global tunnel mode; connected users it affects reconnect at once (returned)."""
        if mode not in TUNNEL_MODES:
            raise ValidationError(T("Unknown tunnel mode: {mode}", mode=mode))
        before = {u.name: openvpn.effective_mode(self.cfg, u) for u in self.store.users()}
        self.cfg.tunnel.mode = mode
        self.save()
        self.apply()
        affected = [u.name for u in self.store.users() if openvpn.effective_mode(self.cfg, u) != before.get(u.name)]
        if self.reload:
            forwarding.ensure()  # full tunnel forwards everything: other firewalls must let it through
        logs.audit("tunnel.mode", mode)
        return self.reconnect(affected) if reconnect else []

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
