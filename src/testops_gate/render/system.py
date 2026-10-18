# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""nftables ruleset, sysctl and Suricata unit drop-in."""

from __future__ import annotations

from testops_gate.config import PUBLIC_RESOLVERS, Config
from testops_gate.render import HEADER, TUN_DEVICE
from testops_gate.render.openvpn import network, server_ip

DENY_TIMEOUT = "10m"


def _elements(values: list[str]) -> str:
    return f" elements = {{ {', '.join(values)} }};" if values else ""


def nftables(cfg: Config) -> str:
    sec = cfg.security
    unauth = sec.category_enabled("unauth") and sec.blocked_networks
    ports = sec.category_enabled("ports") and sec.forbidden_ports
    proto = cfg.server.protocol
    enforce = cfg.dns.enforce
    dns = server_ip(cfg)
    lines = [
        "#!/usr/sbin/nft -f",
        HEADER.rstrip(),
        "# Replaced atomically: create, delete and recreate the table in one transaction.",
        "table inet testops_gate {}",
        "delete table inet testops_gate",
        "",
        "table inet testops_gate {",
        f"    set blocked_nets {{ type ipv4_addr; flags interval;{_elements(sec.blocked_networks if unauth else [])} }}",
        f"    set forbidden_ports {{ type inet_service; flags interval;{_elements(sec.forbidden_ports if ports else [])} }}",
        "    # Sets filled by the rules below and read by testops-gated for alerts",
        f"    set denied {{ type ipv4_addr . ipv4_addr . inet_service; flags dynamic, timeout; timeout {DENY_TIMEOUT}; }}",
        f"    set forbidden {{ type ipv4_addr . ipv4_addr . inet_service; flags dynamic, timeout; timeout {DENY_TIMEOUT}; }}",
        f"    set doh_resolvers {{ type ipv4_addr; flags interval;{_elements(PUBLIC_RESOLVERS if enforce else [])} }}",
        "",
        "    chain input {",
        "        type filter hook input priority filter; policy accept;",
        f"        {proto} dport {cfg.server.port} accept",
        f'        iifname "{TUN_DEVICE}" accept',
        "    }",
        "",
        "    # Runs before routing, so it sees traffic to the server itself as well as forwarded traffic",
        "    chain prerouting {",
        "        type filter hook prerouting priority -5; policy accept;",
    ]
    if unauth:
        lines += [
            f'        iifname "{TUN_DEVICE}" ip daddr @blocked_nets meta l4proto {{ tcp, udp }}'
            " add @denied { ip saddr . ip daddr . th dport }",
            f'        iifname "{TUN_DEVICE}" ip daddr @blocked_nets drop',
        ]
    if ports:
        lines += [
            f'        iifname "{TUN_DEVICE}" meta l4proto {{ tcp, udp }} th dport @forbidden_ports'
            " add @forbidden { ip saddr . ip daddr . th dport } drop",
        ]
    lines += [
        "    }",
        "",
        "    chain forward {",
        "        type filter hook forward priority filter; policy accept;",
    ]
    if enforce:
        lines += [
            "        # DNS-over-TLS and DNS-over-HTTPS would bypass the VPN resolver: refuse, clients fall back",
            f'        iifname "{TUN_DEVICE}" tcp dport 853 reject with tcp reset',
            f'        iifname "{TUN_DEVICE}" ip daddr @doh_resolvers tcp dport 443 reject with tcp reset',
            f'        iifname "{TUN_DEVICE}" ip daddr @doh_resolvers udp dport {{ 443, 853 }} drop',
        ]
    lines += [
        "        ct state established,related accept",
        f'        iifname "{TUN_DEVICE}" accept',
        "    }",
        "",
        *([
            "    # Plain DNS to any server is answered by the VPN resolver",
            "    chain dns_redirect {",
            "        type nat hook prerouting priority dstnat; policy accept;",
            f'        iifname "{TUN_DEVICE}" ip daddr != {dns} meta l4proto {{ tcp, udp }} th dport 53 dnat ip to {dns}',
            "    }",
            "",
        ] if enforce else []),
        "    chain postrouting {",
        "        type nat hook postrouting priority srcnat; policy accept;",
    ]
    nat_out = f' oifname "{cfg.server.interface}"' if cfg.server.interface else ""
    lines += [
        f"        ip saddr {network(cfg)}{nat_out} masquerade",
        "    }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def sysctl() -> str:
    return HEADER + "net.ipv4.ip_forward = 1\n"


def suricata_dropin() -> str:
    return HEADER + f"""[Unit]
After=openvpn-server@server.service

[Service]
Type=simple
PIDFile=
ExecStart=
ExecStart=/usr/bin/suricata --af-packet={TUN_DEVICE} -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules
ExecReload=
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
RestartSec=15
"""
