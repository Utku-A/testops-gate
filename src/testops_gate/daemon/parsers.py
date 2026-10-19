# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Parsers for the event sources read by testops-gated (pure functions)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

IP = r"\d{1,3}(?:\.\d{1,3}){3}"


@dataclass
class ConnEvent:
    proto: str
    src: str
    dst: str
    dport: int  # 0 when the protocol has no ports


CONNTRACK_RE = re.compile(rf"\[NEW\]\s+(\w+)\s+\d+\s+(?:\d+\s+)?(?:\w+\s+)?src=({IP}) dst=({IP})(?: sport=\d+ dport=(\d+))?")


def parse_conntrack(line: str) -> ConnEvent | None:
    """`conntrack -E -e NEW` line -> original-direction tuple."""
    match = CONNTRACK_RE.search(line)
    if not match:
        return None
    proto, src, dst, dport = match.groups()
    return ConnEvent(proto, src, dst, int(dport or 0))


@dataclass
class DnsEvent:
    client: str
    name: str
    qtype: str
    rcode: str


DNS_RE = re.compile(rf"info: ({IP}) (\S+?)\.? (\S+) IN (\S+)")


def parse_unbound_reply(line: str) -> DnsEvent | None:
    """Unbound `log-replies` line: client, name, type, class, rcode, ..."""
    if "rpz applied" in line.lower() or "rpz: applied" in line.lower():
        return None
    match = DNS_RE.search(line)
    if not match:
        return None
    client, name, qtype, rcode = match.groups()
    return DnsEvent(client, name or ".", qtype, rcode)


@dataclass
class RpzEvent:
    client: str
    name: str
    action: str


# Unbound >= 1.14: "rpz: applied [name] qname action ip@port ..."; 1.13: "RPZ applied [name] ..."
RPZ_RE = re.compile(rf"rpz:? applied (?:\[[^\]]*\] )?(\S+?)\.? (\S+) ({IP})@\d+", re.IGNORECASE)


def parse_unbound_rpz(line: str) -> RpzEvent | None:
    match = RPZ_RE.search(line)
    if not match:
        return None
    name, action, client = match.groups()
    return RpzEvent(client, name, action)


@dataclass
class AuthFailure:
    real_ip: str
    name: str  # common name if OpenVPN logged one, else ""
    reason: str


AUTH_MARKERS = (
    "TLS Error",
    "VERIFY ERROR",
    "unwrapping failed",
    "client-config-dir authentication failed",
    "verification failed for peer",  # wrong username or password
    "rejected due to 'disable'",
    "AUTH_FAILED",
    "certificate revoked",
)
REAL_IP_RE = re.compile(rf"(?:\[AF_INET\]|^|\s|/)({IP}):\d+")
CN_RE = re.compile(r"(?:CN=|common name ')([A-Za-z0-9_.-]+)")
PEER_NAME_RE = re.compile(rf"^([A-Za-z0-9_.-]+)/{IP}:\d+ ")  # "alice/88.1.2.3:5000 ..."


def parse_openvpn_auth(line: str) -> AuthFailure | None:
    if not any(marker in line for marker in AUTH_MARKERS):
        return None
    if "TLS Error: TLS object -> incoming plaintext read error" in line:
        return None  # follows a VERIFY ERROR that was already counted
    if "SENT CONTROL" in line:
        return None  # the AUTH_FAILED sent to the client follows the line that says why
    ip_match = REAL_IP_RE.search(line)
    if not ip_match:
        return None
    name_match = CN_RE.search(line) or PEER_NAME_RE.search(line)
    reason = next(marker for marker in AUTH_MARKERS if marker in line)
    return AuthFailure(ip_match.group(1), name_match.group(1) if name_match else "", reason)


@dataclass
class IdsEvent:
    src: str
    dst: str
    src_port: int
    dst_port: int
    proto: str
    signature: str
    sid: int
    severity: str


def parse_eve(line: str) -> IdsEvent | None:
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None
    if event.get("event_type") != "alert":
        return None
    alert = event.get("alert", {})
    level = int(alert.get("severity", 3))
    return IdsEvent(
        src=event.get("src_ip", ""),
        dst=event.get("dest_ip", ""),
        src_port=int(event.get("src_port") or 0),
        dst_port=int(event.get("dest_port") or 0),
        proto=str(event.get("proto", "")).lower(),
        signature=alert.get("signature", "unknown"),
        sid=int(alert.get("signature_id") or 0),
        severity="high" if level <= 1 else "medium" if level == 2 else "low",
    )
