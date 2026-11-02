# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Servers that join the VPN with a one-time command.

`testops-gate node add web-01` creates a join token and prints one line to run on that server:

    curl -fsSL https://testopscenter.com/install.sh | sudo sh -s -- join tgj1_<blob>

The blob holds the address of the join service (HTTPS on cfg.nodes.enroll_port), the token and the
SHA-256 of our CA certificate. The server makes its own key, checks the join service against that
hash and sends a certificate request; enroll() signs it, so the private key never leaves the
server. The token works once, for one name, until it expires; only a hash of its secret is kept.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import tempfile
import time
from dataclasses import replace

from testops_gate import logs
from testops_gate.core import passwords
from testops_gate.core.context import LABEL_RE, Context, ValidationError
from testops_gate.db import JoinToken, Node, node_cn
from testops_gate.i18n import T
from testops_gate.paths import P
from testops_gate.render import openvpn
from testops_gate.system import services
from testops_gate.system.easyrsa import EasyRSA
from testops_gate.system.runner import CommandError, run

ENROLL_UNIT = "testops-gate-enroll.service"
NODE_CERT_DAYS = 1825
BLOB_PREFIX = "tgj1_"
SUBJECT_RE = re.compile(r"subject=\s*CN\s*=\s*(\S+)\s*$")


class EnrollError(Exception):
    """A join request that is refused; the message goes back to the joining server."""


def ca_sha256(pem: str) -> str:
    block = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(block.group(0) if block else pem)).hexdigest()


def _hash(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def validate_name(ctx: Context, name: str) -> str:
    name = name.strip().lower()
    if len(name) > 32 or not LABEL_RE.match(name):
        raise ValidationError(T("Server name may only contain lowercase letters, digits and '-' (max 32)"))
    if ctx.store.node(name):
        raise ValidationError(T("'{name}' already exists", name=name))
    if ctx.store.host(f"{name}.{ctx.cfg.nodes.domain}"):
        raise ValidationError(T("{fqdn} is already a host record", fqdn=f"{name}.{ctx.cfg.nodes.domain}"))
    return name


def create_join_token(ctx: Context, name: str, minutes: int | None = None) -> tuple[JoinToken, str]:
    """A new token for `name` (earlier unused ones for it are dropped); returns it and its secret
    as "id.secret". Starts the join service."""
    name = validate_name(ctx, name)
    minutes = minutes or ctx.cfg.nodes.token_minutes
    if not 1 <= minutes <= 7 * 24 * 60:
        raise ValidationError(T("Token lifetime must be between 1 minute and 7 days"))
    if ctx.reload and not services.is_active([ENROLL_UNIT])[ENROLL_UNIT]:
        from testops_gate.core.doctor import port_owners

        owners = port_owners(_with_port(ctx.cfg, ctx.cfg.nodes.enroll_port))
        if owners:
            raise ValidationError(T("Port {port}/tcp for joining is used by {owners}", port=ctx.cfg.nodes.enroll_port,
                                    owners=", ".join(owners)))
    now = time.time()
    with ctx.store.tx() as c:
        c.execute("DELETE FROM join_tokens WHERE node = ? AND used_at = 0", (name,))
    token_id, secret = secrets.token_hex(4), secrets.token_urlsafe(24)
    token = JoinToken(token_id, _hash(secret), name, now, now + minutes * 60)
    ctx.store.add_token(token)
    if ctx.reload:
        services.systemctl("start", ENROLL_UNIT, check=False)
    logs.audit("node.token", f"{name} expires={time.strftime('%Y-%m-%d %H:%M', time.localtime(token.expires))}")
    return token, f"{token_id}.{secret}"


def join_service_problem(ctx: Context, wait: float = 5.0) -> str:
    """Why the join service is not listening after a token was created ("" when it is)."""
    if not ctx.reload:
        return ""
    from testops_gate.core.doctor import journal_reason

    port = ctx.cfg.nodes.enroll_port
    deadline = time.time() + wait
    while True:
        if run(["ss", "-H", "-ltn", "sport", "=", f":{port}"], check=False).stdout.strip():
            return ""
        if time.time() >= deadline:
            break
        time.sleep(0.25)
    return journal_reason(ENROLL_UNIT, limit=2) or T("not running")


def ensure_join_service(ctx: Context) -> bool:
    """Start the join service when a join command is waiting but the service is not running (the
    server rebooted, or it stopped); True if it was started."""
    if not ctx.reload or not pending_tokens(ctx) or services.is_active([ENROLL_UNIT])[ENROLL_UNIT]:
        return False
    services.systemctl("start", ENROLL_UNIT, check=False)
    return True


def _with_port(cfg, port: int):
    return replace(cfg, server=replace(cfg.server, port=port, protocol="tcp"))


def join_blob(ctx: Context, token: JoinToken, token_string: str) -> str:
    data = {
        "e": f"{ctx.cfg.server.endpoint}:{ctx.cfg.nodes.enroll_port}",
        "t": token_string,
        "h": ca_sha256(EasyRSA().ca_cert.read_text()),
        "n": token.node,
    }
    raw = json.dumps(data, separators=(",", ":")).encode()
    return BLOB_PREFIX + base64.urlsafe_b64encode(raw).decode().rstrip("=")


def join_command(ctx: Context, token: JoinToken, token_string: str) -> str:
    return f"curl -fsSL https://testopscenter.com/install.sh | sudo sh -s -- join {join_blob(ctx, token, token_string)}"


def pending_tokens(ctx: Context) -> list[JoinToken]:
    return [t for t in ctx.store.tokens() if t.usable() and not ctx.store.node(t.node)]


def expired_tokens(ctx: Context) -> list[JoinToken]:
    """The latest join command of each server that never joined and whose command expired."""
    latest: dict[str, JoinToken] = {}
    for token in ctx.store.tokens():  # oldest first
        latest[token.node] = token
    return [t for t in latest.values() if not t.used_at and not t.usable() and not ctx.store.node(t.node)]


def update_node(ctx: Context, name: str, *, vpn_ip: str | None = None, note: str | None = None) -> Node:
    """Change a joined server's VPN address or note; a new address applies when it reconnects,
    which it is told to do at once."""
    node = ctx.store.node(name)
    if not node:
        raise ValidationError(T("No such server: {name}", name=name))
    fields: dict[str, object] = {}
    if vpn_ip is not None and vpn_ip.strip() != node.vpn_ip:
        vpn_ip = vpn_ip.strip()
        ctx._validate_user_ip(vpn_ip, name, node=True)
        fields["vpn_ip"] = vpn_ip
    if note is not None and note.strip() != node.note:
        fields["note"] = note.strip()
    if fields:
        ctx.store.update_node(name, **fields)
        if "vpn_ip" in fields:
            ctx.apply()  # ccd, DNS name and firewall set
            ctx.reconnect([node.cn])
        logs.audit("node.edit", f"{name} " + " ".join(f"{k}={v}" for k, v in fields.items()))
    return ctx.store.node(name)


def rename_waiting(ctx: Context, name: str, new_name: str, minutes: int | None = None) -> tuple[JoinToken, str]:
    """A server that has not joined yet under another name: its old join command stops working."""
    if ctx.store.node(name):
        raise ValidationError(T("{name} has already joined; remove it and add it again under the new name",
                                name=name))
    token = create_join_token(ctx, new_name, minutes)
    if new_name.strip().lower() != name:
        ctx.store.delete_node(name)  # drops its join tokens
        logs.audit("node.rename", f"{name} -> {token[0].node}")
    return token


def _csr_subject(path: str) -> str:
    try:
        run(["openssl", "req", "-in", path, "-noout", "-verify"])
        out = run(["openssl", "req", "-in", path, "-noout", "-subject", "-nameopt", "RFC2253"]).stdout
    except CommandError:
        raise EnrollError("invalid certificate request") from None
    match = SUBJECT_RE.search(out.strip())
    return match.group(1) if match else ""


def enroll(ctx: Context, token_string: str, csr_pem: str) -> dict:
    """Sign a joining server's certificate request and add it; returns its connection settings."""
    token_id, _, secret = token_string.partition(".")
    token = ctx.store.token(token_id) if token_id else None
    # one answer for every kind of bad token: nothing to learn by probing
    if not token or not secret or not hmac.compare_digest(_hash(secret), token.secret_hash) or not token.usable():
        raise EnrollError("invalid or expired join token")
    name = token.node
    if ctx.store.node(name):
        raise EnrollError(f"{name} has already joined")
    cn = node_cn(name)
    with tempfile.NamedTemporaryFile("w", suffix=".req", dir=P.state_dir, delete=False) as fh:
        fh.write(csr_pem)
        csr_path = fh.name
    try:
        if _csr_subject(csr_path) != cn:
            raise EnrollError(f"the certificate request must be for CN={cn}")
        if not ctx.store.use_token(token_id):
            raise EnrollError("invalid or expired join token")
        pki = EasyRSA()
        if pki.cert(cn).exists():
            pki.revoke(cn)
        pki.remove_issued(cn)
        pki.sign_request(cn, csr_path, NODE_CERT_DAYS)
    finally:
        os.unlink(csr_path)
    ctx.refresh_crl()
    now = time.time()
    password = passwords.generate(32)
    node = Node(name, ctx.allocate_ip(), True, now, now + NODE_CERT_DAYS * 86400, passwords.hash_password(password))
    ctx.store.add_node(node)
    ctx.apply()
    logs.audit("node.join", f"{name} vpn_ip={node.vpn_ip}", actor="testops-gate-enroll")
    server = ctx.cfg.server
    return {
        "name": name,
        "cn": cn,
        "vpn_ip": node.vpn_ip,
        "netmask": str(openvpn.network(ctx.cfg).netmask),
        "remote": server.endpoint,
        "port": server.port,
        "proto": server.protocol,
        "server_name": server.server_name,
        "data_ciphers": openvpn.DATA_CIPHERS,
        "tls_cipher": openvpn.TLS_CIPHERS,
        "ca": pki.ca_cert.read_text(),
        "cert": pki.client_pem(cn),
        "tls_crypt": (P.openvpn_dir / "tls-crypt.key").read_text(),
        "username": cn,
        "password": password,
        "dns": openvpn.server_ip(ctx.cfg),
        "domain": ctx.cfg.nodes.domain,
        "fqdn": f"{name}.{ctx.cfg.nodes.domain}",
    }


def remove_node(ctx: Context, name: str) -> None:
    """Take a server out (or cancel its join token): its certificate is revoked."""
    node = ctx.store.node(name)
    if not node and not any(t.node == name for t in ctx.store.tokens()):
        raise ValidationError(T("No such server: {name}", name=name))
    cn = node_cn(name)
    pki = EasyRSA()
    if pki.cert(cn).exists():
        pki.revoke(cn)
        ctx.refresh_crl()
    pki.remove_issued(cn)
    ctx.store.delete_node(name)
    ctx.apply()
    ctx.kick(cn)
    logs.audit("node.remove", name)


def node_rows(ctx: Context) -> list[dict]:
    """Every server, joined or waiting to join, with its state."""
    live = ctx.store.live_clients()
    rows = []
    for node in ctx.store.nodes():
        client = live.get(node.cn)
        rows.append({"name": node.name, "vpn_ip": node.vpn_ip, "fqdn": f"{node.name}.{ctx.cfg.nodes.domain}",
                     "state": "online" if client else "offline", "real_ip": client.real_ip if client else "",
                     "since": client.connected_since if client else 0.0, "expires": 0.0, "note": node.note})
    for state, tokens in (("waiting", pending_tokens(ctx)), ("expired", expired_tokens(ctx))):
        for token in tokens:
            rows.append({"name": token.node, "vpn_ip": "", "fqdn": f"{token.node}.{ctx.cfg.nodes.domain}",
                         "state": state, "real_ip": "", "since": 0.0, "expires": token.expires, "note": ""})
    return sorted(rows, key=lambda r: r["name"])
