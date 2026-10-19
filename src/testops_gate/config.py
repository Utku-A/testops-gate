# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Settings stored in /etc/testops-gate/config.yaml and secrets.yaml.

config.yaml holds everything an operator may read or version; secrets.yaml
(mode 0600) holds webhook URLs and SMTP passwords, keyed by channel id.
"""

from __future__ import annotations

import dataclasses
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, get_type_hints

import yaml

from testops_gate.paths import P

TUNNEL_MODES = ("split", "full")
SEVERITIES = ("low", "medium", "high")
PROTOCOLS = ("udp", "tcp")
# How VPN users sign in, on top of their certificate:
#   user-password     username + password, checked by the server
#   profile-password  the private key in the .ovpn profile is encrypted with a password
#   certificate       the certificate alone
AUTH_MODES = ("user-password", "profile-password", "certificate")

UPSTREAMS: dict[str, tuple[str, list[str]]] = {
    "cloudflare": ("Cloudflare", ["1.1.1.1", "1.0.0.1"]),
    "quad9": ("Quad9", ["9.9.9.9", "149.112.112.112"]),
    "google": ("Google", ["8.8.8.8", "8.8.4.4"]),
    "adguard": ("AdGuard", ["94.140.14.14", "94.140.15.15"]),
    "recursive": ("Unbound recursive", []),
}

# Public resolvers clients may be configured to use directly (DNS, DoT, DoH). With
# dns.enforce their DNS is answered by Unbound and their DoT/DoH endpoints are refused.
PUBLIC_RESOLVERS = [
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",  # Cloudflare
    "8.8.8.8", "8.8.4.4",  # Google
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",  # Quad9
    "94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16",  # AdGuard
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "45.90.28.0", "45.90.30.0",  # NextDNS anycast
    "76.76.2.0", "76.76.10.0",  # Control D
    "185.228.168.9", "185.228.169.9",  # CleanBrowsing
    "77.88.8.8", "77.88.8.1",  # Yandex
]

# Security category key -> alert category name used in logs and notifications
SECURITY_CATEGORIES: dict[str, str] = {
    "scan": "port-scan",
    "unauth": "unauthorized-target",
    "ports": "forbidden-port",
    "rpz": "malicious-domain",
    "ids": "ids-signature",
    "volume": "abnormal-volume",
    "auth": "auth-failure",
}
CATEGORY_KEYS = {name: key for key, name in SECURITY_CATEGORIES.items()}


def _default_categories() -> dict[str, bool]:
    return {**{key: True for key in SECURITY_CATEGORIES}, "autoblock": False}


@dataclass
class ServerConfig:
    endpoint: str = ""
    port: int = 1194
    protocol: str = "udp"
    network: str = "10.8.0.0/24"
    server_name: str = ""
    interface: str = ""  # public interface used for NAT


@dataclass
class TunnelConfig:
    mode: str = "split"
    extra_routes: list[str] = field(default_factory=list)  # CIDRs routed via VPN in split mode


@dataclass
class AuthConfig:
    mode: str = "user-password"


@dataclass
class DnsConfig:
    upstream: str = "cloudflare"
    # Force VPN clients onto the VPN resolver: plain DNS to any server is redirected to
    # Unbound, DNS-over-TLS and DNS-over-HTTPS to well-known resolvers are rejected.
    enforce: bool = True


@dataclass
class LoggingConfig:
    retention_days: int = 14


@dataclass
class UpdatesConfig:
    check: bool = True  # look for a new release once a day
    base_url: str = ""  # release mirror (VERSION, testops-gate_all.deb, SHA256SUMS); empty = testopscenter.com


@dataclass
class SecurityConfig:
    enabled: bool = True
    categories: dict[str, bool] = field(default_factory=_default_categories)
    blocked_networks: list[str] = field(default_factory=list)
    forbidden_ports: list[str] = field(default_factory=lambda: ["25", "6881-6889"])
    scan_threshold: int = 100  # distinct destination ports/hosts ...
    scan_window: int = 60  # ... within this many seconds
    volume_threshold_mb: int = 2048  # upload per user ...
    volume_window: int = 600  # ... within this many seconds
    auth_fail_threshold: int = 5  # failed handshakes per source IP within 5 minutes
    autoblock_minutes: int = 30
    rpz_url: str = "https://urlhaus.abuse.ch/downloads/rpz/"

    def category_enabled(self, key: str) -> bool:
        return self.enabled and self.categories.get(key, False)


@dataclass
class Channel:
    id: str
    kind: str  # slack | email
    name: str
    min_severity: str = "medium"
    mute_minutes: int = 15
    enabled: bool = True
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"  # starttls | ssl | none
    smtp_user: str = ""
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    # Secrets: kept out of config.yaml
    webhook: str = field(default="", metadata={"secret": True})
    smtp_password: str = field(default="", metadata={"secret": True})

    @property
    def target(self) -> str:
        return ", ".join(self.recipients) if self.kind == "email" else self.name


@dataclass
class Config:
    language: str = "en"
    server: ServerConfig = field(default_factory=ServerConfig)
    tunnel: TunnelConfig = field(default_factory=TunnelConfig)
    dns: DnsConfig = field(default_factory=DnsConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    updates: UpdatesConfig = field(default_factory=UpdatesConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    channels: list[Channel] = field(default_factory=list)
    # Packages installed by `testops-gate install` itself (removed by `uninstall --remove-packages`)
    installed_packages: list[str] = field(default_factory=list)

    def channel(self, channel_id: str) -> Channel | None:
        return next((c for c in self.channels if c.id == channel_id), None)


def new_channel_id() -> str:
    return "ch-" + secrets.token_hex(4)


def _secret_fields(cls: type) -> set[str]:
    return {f.name for f in dataclasses.fields(cls) if f.metadata.get("secret")}


def _from_dict(cls: type, data: Any) -> Any:
    """Build a dataclass from a (possibly partial) dict, ignoring unknown keys."""
    if not isinstance(data, dict):
        return cls()
    hints = get_type_hints(cls)
    kwargs = {}
    for f in dataclasses.fields(cls):
        if f.name not in data:
            continue
        value = data[f.name]
        hint = hints[f.name]
        if dataclasses.is_dataclass(hint):
            value = _from_dict(hint, value)
        elif f.name == "channels":
            value = [_from_dict(Channel, item) for item in value or []]
        elif f.name == "categories":
            value = {**_default_categories(), **(value or {})}
        kwargs[f.name] = value
    return cls(**kwargs)


def _to_dict(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        secret = _secret_fields(type(obj))
        return {f.name: _to_dict(getattr(obj, f.name)) for f in dataclasses.fields(obj) if f.name not in secret}
    if isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {key: _to_dict(value) for key, value in obj.items()}
    return obj


def exists() -> bool:
    return P.config_file.exists()


def load() -> Config:
    data = yaml.safe_load(P.config_file.read_text()) if P.config_file.exists() else {}
    cfg = _from_dict(Config, data or {})
    if data and "auth" not in data:
        # Installed before passwords existed: keep certificate-only so issued profiles keep working
        cfg.auth.mode = "certificate"
    if P.secrets_file.exists():
        secret_data = yaml.safe_load(P.secrets_file.read_text()) or {}
        for channel in cfg.channels:
            for name, value in (secret_data.get("channels", {}).get(channel.id) or {}).items():
                if name in _secret_fields(Channel):
                    setattr(channel, name, value)
    return cfg


def _write(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def save(cfg: Config) -> None:
    header = "# testops-gate configuration. Edit with `testops-gate` (TUI) or the CLI.\n"
    _write(P.config_file, header + yaml.safe_dump(_to_dict(cfg), sort_keys=False, allow_unicode=True), 0o640)
    secret_data = {
        "channels": {
            c.id: {name: getattr(c, name) for name in sorted(_secret_fields(Channel)) if getattr(c, name)}
            for c in cfg.channels
        }
    }
    _write(P.secrets_file, yaml.safe_dump(secret_data, sort_keys=True), 0o600)
