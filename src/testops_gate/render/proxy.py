# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""HAProxy configuration for web hosts: https://dev.internal -> 127.0.0.1:4422.

HAProxy runs as its own instance (testops-gate-proxy.service) on two ports of the VPN address;
the firewall redirects ports 80 and 443 of that address to them for traffic from the tunnel
(render/system.py). Only VPN clients reach it, and nothing else on the server that uses 80 or 443
is in its way.
"""

from __future__ import annotations

import re

from testops_gate.config import Config
from testops_gate.db import Host
from testops_gate.paths import P
from testops_gate.render import HEADER
from testops_gate.render.openvpn import server_ip


def backend_name(host: Host) -> str:
    return "h_" + re.sub(r"[^a-z0-9]", "_", host.name)


def hosts_map(hosts: list[Host]) -> str:
    return HEADER + "".join(f"{h.name} {backend_name(h)}\n" for h in hosts)


def haproxy_cfg(cfg: Config, hosts: list[Host]) -> str:
    ip = server_ip(cfg)
    lines = [
        "global",
        "    user haproxy",
        "    group haproxy",
        "    maxconn 4096",
        "    ssl-default-bind-options ssl-min-ver TLSv1.2",
        "",
        "defaults",
        "    mode http",
        "    option forwardfor",
        "    timeout connect 5s",
        "    timeout client 60s",
        "    timeout server 60s",
        "    timeout tunnel 1h  # WebSocket connections",
        "",
        "frontend tg_http",
        "    # transparent: bind before the VPN interface exists",
        f"    bind {ip}:{cfg.proxy.http_port} transparent",
        "    # http://<any web host>/ca.crt: the certificate VPN users install once per device",
        f"    http-request return status 200 content-type application/x-x509-ca-cert file {P.webca_cert}"
        " if { path /ca.crt }",
        "    http-request redirect location https://%[req.hdr(host),field(1,:)]%[pathq] code 308",
        "",
        "frontend tg_https",
        f"    bind {ip}:{cfg.proxy.https_port} transparent ssl crt {P.proxy_cert} alpn h2,http/1.1",
        "    http-request set-header X-Forwarded-Proto https",
        f"    use_backend %[req.hdr(host),field(1,:),lower,map({P.proxy_map},tg_unknown)]",
        "",
        "backend tg_unknown",
        '    http-request return status 404 content-type text/plain string "TestOps Gate: no such web host\\n"',
    ]
    for host in hosts:
        scheme, target, port = host.target
        tls = " ssl verify none" if scheme == "https" else ""
        lines += ["", f"backend {backend_name(host)}", f"    server target {target}:{port}{tls}"]
    return HEADER + "\n".join(lines) + "\n"
