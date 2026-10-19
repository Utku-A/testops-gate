# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Unbound resolver configuration and host records."""

from __future__ import annotations

from testops_gate.config import UPSTREAMS, Config
from testops_gate.db import Host
from testops_gate.render import HEADER, RPZ_ZONEFILE
from testops_gate.render.openvpn import network, server_ip

RPZ_NAME = "tg-rpz"

PRIVATE_RANGES = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "fd00::/8", "fe80::/10", "::ffff:0:0/96",
]


def main_conf(cfg: Config) -> str:
    rpz = cfg.security.category_enabled("rpz")
    lines = [
        "server:",
        "    interface: 127.0.0.1",
        f"    interface: {server_ip(cfg)}",
        "    ip-freebind: yes  # bind before the VPN interface exists",
        "    access-control: 127.0.0.0/8 allow",
        f"    access-control: {network(cfg)} allow",
        "    hide-identity: yes",
        "    hide-version: yes",
        "    qname-minimisation: yes",
        "    prefetch: yes",
        "    # One log line per answer (client IP, name, type, rcode): read by testops-gated",
        "    log-replies: yes",
        "    log-servfail: yes",
        "    # DNS rebinding protection for upstream answers (local host records are not affected)",
        *[f"    private-address: {r}" for r in PRIVATE_RANGES],
    ]
    if cfg.dns.enforce:
        lines += [
            "    # Firefox turns its DNS-over-HTTPS off when this canary name does not resolve",
            '    local-zone: "use-application-dns.net." always_nxdomain',
        ]
    if rpz:
        lines += [
            '    module-config: "respip validator iterator"',
            "    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt  # for https RPZ downloads",
            "",
            "rpz:",
            f"    name: {RPZ_NAME}",
            f"    url: {cfg.security.rpz_url}",
            f"    zonefile: {RPZ_ZONEFILE}",
            "    rpz-log: yes",
            f"    rpz-log-name: {RPZ_NAME}",
        ]
    _, addresses = UPSTREAMS.get(cfg.dns.upstream, UPSTREAMS["cloudflare"])
    if addresses:
        lines += ["", "forward-zone:", '    name: "."', *[f"    forward-addr: {a}" for a in addresses]]
    return HEADER + "\n".join(lines) + "\n"


def _fqdn(name: str) -> str:
    return name.rstrip(".") + "."


def hosts_conf(hosts: list[Host], nodes: list[tuple[str, str]] = ()) -> str:
    """nodes: (fqdn, vpn ip) of the servers in the VPN, e.g. ("web-01.internal", "10.8.0.50")."""
    lines = ["server:"]
    for name, ip in nodes:
        owner = _fqdn(name)
        lines.append(f'    local-zone: "{owner}" transparent')
        lines.append(f'    local-data: "{owner} 300 IN A {ip}"')
    for host in hosts:
        if host.wildcard:
            # *.preview.internal: the apex and every name below it get the same answer
            zone = _fqdn(host.name[2:])
            lines.append(f'    local-zone: "{zone}" redirect')
            owner = zone
        else:
            # transparent: other names resolve normally; other types of this name get NODATA
            owner = _fqdn(host.name)
            lines.append(f'    local-zone: "{owner}" transparent')
        if host.rtype == "A":
            lines.append(f'    local-data: "{owner} 300 IN A {host.value}"')
        else:
            lines.append(f'    local-data: "{owner} 300 IN CNAME {_fqdn(host.value)}"')
    if len(lines) == 1:
        lines.append("    # no host records")
    return HEADER + "\n".join(lines) + "\n"
