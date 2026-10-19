# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Join service: HTTPS on cfg.nodes.enroll_port while a join token is waiting.

    GET  /ca     our CA certificate; the joining server checks it against the hash in its token
    POST /join   {"token": "id.secret", "csr": "<PEM>"} -> connection settings (core/nodes.enroll)

TLS uses the OpenVPN server certificate (issued by our CA). Started by `testops-gate node add`
(testops-gate-enroll.service); stops by itself once no token is waiting.
"""

from __future__ import annotations

import json
import logging
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from testops_gate.core import nodes
from testops_gate.core.context import Context
from testops_gate.paths import P
from testops_gate.system.easyrsa import EasyRSA

log = logging.getLogger("testops-gate-enroll")
MAX_BODY = 16 * 1024
IDLE_CHECK = 15.0
_lock = threading.Lock()  # one join at a time: certificate signing and address allocation


class Handler(BaseHTTPRequestHandler):
    server_version = "testops-gate-enroll"
    sys_version = ""

    def log_message(self, fmt: str, *args) -> None:
        log.info("%s %s", self.client_address[0], fmt % args)

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: dict) -> None:
        self._send(status, json.dumps(data).encode())

    def do_GET(self) -> None:  # noqa: N802 (http.server naming)
        if self.path == "/ca":
            self._send(200, EasyRSA().ca_cert.read_bytes(), "application/x-pem-file")
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/join":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if not 0 < length <= MAX_BODY:
            self._json(413, {"error": "request too large"})
            return
        try:
            data = json.loads(self.rfile.read(length))
            token, csr = str(data["token"]), str(data["csr"])
        except (ValueError, KeyError, TypeError):
            self._json(400, {"error": "expected JSON with token and csr"})
            return
        with _lock:
            ctx = Context.open()
            try:
                settings = nodes.enroll(ctx, token, csr)
            except nodes.EnrollError as exc:
                log.warning("join refused from %s: %s", self.client_address[0], exc)
                self._json(403, {"error": str(exc)})
                return
            except Exception:  # noqa: BLE001 - report, never leak details
                log.exception("join failed")
                self._json(500, {"error": "join failed on the VPN server; see its journal"})
                return
            finally:
                ctx.store.close()
        log.info("%s joined from %s as %s", settings["name"], self.client_address[0], settings["vpn_ip"])
        self._json(200, settings)


def _has_waiting_tokens() -> bool:
    ctx = Context.open(reload=False)
    try:
        return bool(nodes.pending_tokens(ctx))
    finally:
        ctx.store.close()


def serve(port: int | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ctx = Context.open(reload=False)
    port = port or ctx.cfg.nodes.enroll_port
    ctx.store.close()
    if not _has_waiting_tokens():
        log.info("no join token is waiting; not starting")
        return 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(P.openvpn_dir / "server.crt", P.openvpn_dir / "server.key")
    httpd = ThreadingHTTPServer(("", port), Handler)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    def stop_when_idle() -> None:
        while True:
            time.sleep(IDLE_CHECK)
            if not _has_waiting_tokens():
                log.info("no join token is waiting anymore; stopping")
                httpd.shutdown()
                return

    threading.Thread(target=stop_when_idle, daemon=True).start()
    log.info("join service listening on %d/tcp", port)
    httpd.serve_forever()
    httpd.server_close()
    return 0
