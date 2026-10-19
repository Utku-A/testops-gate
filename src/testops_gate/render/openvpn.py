# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""OpenVPN server.conf, per-user ccd files and client profiles."""

from __future__ import annotations

import ipaddress

from testops_gate.config import PUBLIC_RESOLVERS, Config
from testops_gate.db import Host, Node, User
from testops_gate.render import HEADER, MGMT_SOCKET, STATUS_FILE, TUN_DEVICE

DATA_CIPHERS = "AES-128-GCM:AES-256-GCM:CHACHA20-POLY1305"
TLS_CIPHERS = "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384"

AUTH_SCRIPT_PATH = "/etc/openvpn/server/testops-gate-auth"
AUTH_PASSWORDS_PATH = "/etc/openvpn/server/testops-gate-passwords"

# auth-user-pass-verify via-file: argv[1] holds "username\npassword". OpenVPN runs it as
# nobody, so it reads only the hash file (0640 root:nogroup) and imports nothing of ours.
# The hash check repeats core/passwords.py:verify().
AUTH_SCRIPT = f'''#!/usr/bin/python3 -I
"""TestOps Gate: username + password check for OpenVPN (auth-user-pass-verify via-file)."""
import base64
import hashlib
import hmac
import os
import sys

PASSWORDS = "{AUTH_PASSWORDS_PATH}"


def check() -> bool:
    with open(sys.argv[1]) as f:
        username, password = (f.read().split("\\n") + ["", ""])[:2]
    # Only the certificate's owner can sign in with its password
    if not username or username != os.environ.get("common_name"):
        return False
    with open(PASSWORDS) as f:
        for line in f:
            name, _, stored = line.rstrip("\\n").partition(":")
            if name != username:
                continue
            scheme, n, r, p, salt, digest = stored.split("$")
            expected = base64.b64decode(digest)
            actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r),
                                    p=int(p), dklen=len(expected))
            return scheme == "scrypt" and hmac.compare_digest(actual, expected)
    return False


try:
    sys.exit(0 if check() else 1)
except Exception:
    sys.exit(1)
'''


def network(cfg: Config) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(cfg.server.network)


def server_ip(cfg: Config) -> str:
    return str(next(network(cfg).hosts()))


def server_conf(cfg: Config) -> str:
    net = network(cfg)
    lines = [
        f"port {cfg.server.port}",
        f"proto {cfg.server.protocol}",
        f"dev {TUN_DEVICE}",
        "dev-type tun",
        "topology subnet",
        f"server {net.network_address} {net.netmask}",
        "",
        "# Every user has a ccd file with a fixed address; users without one are rejected",
        "client-config-dir ccd",
        "ccd-exclusive",
        f'push "dhcp-option DNS {server_ip(cfg)}"',
        "",
        "user nobody",
        "group nogroup",
        "persist-key",
        "persist-tun",
        "keepalive 10 120",
        "",
        "ca ca.crt",
        "cert server.crt",
        "key server.key",
        "dh none",
        "ecdh-curve prime256v1",
        "tls-crypt tls-crypt.key",
        "crl-verify crl.pem",
        "remote-cert-tls client",
        "auth SHA256",
        f"data-ciphers {DATA_CIPHERS}",
        "tls-server",
        "tls-version-min 1.2",
        f"tls-cipher {TLS_CIPHERS}",
        *_server_auth(cfg),
        "",
        f"management {MGMT_SOCKET} unix",
        "# Client list for testops-gated, rewritten every 2 seconds (overrides the unit's --status)",
        f"status {STATUS_FILE} 2",
        "status-version 3",
        "verb 3",
    ]
    if cfg.server.protocol == "udp":
        lines.append("explicit-exit-notify 1")
    return HEADER + "\n".join(lines) + "\n"


def effective_mode(cfg: Config, user: User) -> str:
    return cfg.tunnel.mode if user.mode == "default" else user.mode


def split_routes(cfg: Config, hosts: list[Host]) -> list[ipaddress.IPv4Network]:
    """Networks pushed to clients in split mode: every A record, configured extra routes and,
    with dns.enforce, the public resolvers (so their traffic reaches the DNS rules on the server)."""
    vpn = network(cfg)
    routes: list[ipaddress.IPv4Network] = []
    candidates = [h.value for h in hosts if h.rtype == "A"] + list(cfg.tunnel.extra_routes)
    if cfg.dns.enforce:
        candidates += PUBLIC_RESOLVERS
    for value in candidates:
        try:
            net = ipaddress.IPv4Network(value, strict=False)
        except ValueError:
            continue
        if net.overlaps(vpn) or net in routes:
            continue
        routes.append(net)
    return sorted(routes, key=lambda n: (int(n.network_address), n.prefixlen))


def ccd(cfg: Config, user: User, hosts: list[Host]) -> str:
    lines = [f"# testops-gate user: {user.name}", f"ifconfig-push {user.vpn_ip} {network(cfg).netmask}"]
    if not user.active:
        lines.append("disable")
    if effective_mode(cfg, user) == "full":
        lines.append('push "redirect-gateway def1 bypass-dhcp"')
    else:
        lines += [f'push "route {net.network_address} {net.netmask}"' for net in split_routes(cfg, hosts)]
    return HEADER + "\n".join(lines) + "\n"


def _server_auth(cfg: Config) -> list[str]:
    if cfg.auth.mode != "user-password":
        return []
    return [
        "",
        "# Username + password on top of the certificate",
        "script-security 2",
        f"auth-user-pass-verify {AUTH_SCRIPT_PATH} via-file",
        "# Session token: renegotiations do not ask for the password again",
        "auth-gen-token 0",
    ]


def passwords_file(users: list[User], nodes: list[Node] = ()) -> str:
    """name:hash per user and node (by CN). Disabled ones stay listed: their ccd `disable` rejects
    them, and the log then says why instead of reporting a wrong password."""
    lines = [f"{u.name}:{u.password_hash}\n" for u in users if u.password_hash]
    lines += [f"{n.cn}:{n.password_hash}\n" for n in nodes if n.password_hash]
    return "".join(lines)


def node_ccd(cfg: Config, node: Node) -> str:
    """A server: fixed address and nothing pushed (its own traffic stays off the VPN)."""
    lines = [f"# testops-gate node: {node.name}", f"ifconfig-push {node.vpn_ip} {network(cfg).netmask}"]
    if not node.enabled:
        lines.append("disable")
    return HEADER + "\n".join(lines) + "\n"


def client_profile(cfg: Config, ca: str, cert: str, key: str, tls_crypt: str) -> str:
    proto = "udp" if cfg.server.protocol == "udp" else "tcp-client"
    lines = [
        "client",
        "dev tun",
        f"proto {proto}",
        f"remote {cfg.server.endpoint} {cfg.server.port}",
        "resolv-retry infinite",
        "nobind",
        "persist-key",
        "persist-tun",
        "remote-cert-tls server",
        f"verify-x509-name {cfg.server.server_name} name",
        "auth SHA256",
        f"data-ciphers {DATA_CIPHERS}",
        "tls-client",
        "tls-version-min 1.2",
        f"tls-cipher {TLS_CIPHERS}",
        "ignore-unknown-option block-outside-dns",
        "setenv opt block-outside-dns",
        *(["auth-user-pass", "auth-nocache"] if cfg.auth.mode == "user-password" else []),
        "verb 3",
        "<ca>",
        ca.strip(),
        "</ca>",
        "<cert>",
        cert.strip(),
        "</cert>",
        "<key>",
        key.strip(),
        "</key>",
        "<tls-crypt>",
        tls_crypt.strip(),
        "</tls-crypt>",
    ]
    return "\n".join(lines) + "\n"
