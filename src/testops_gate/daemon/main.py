# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""testops-gated: collects per-user logs and runs security monitoring.

Sources:
  * OpenVPN status file (polled): sessions, traffic, live client list
  * conntrack event stream: new connections -> [CONN] lines, port-scan detection
  * Unbound journal: DNS replies -> [DNS] lines, RPZ hits -> malicious-domain
  * OpenVPN journal: failed handshakes -> auth-failure
  * nftables dynamic sets (polled): blocked destinations / forbidden ports
  * Suricata eve.json (tailed): IDS alerts
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import logging.handlers
import os
import signal
import sys
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone

from testops_gate import __version__, logs
from testops_gate import config as config_mod
from testops_gate.core.apply import write_ccd
from testops_gate.core.context import Context
from testops_gate.daemon import parsers
from testops_gate.daemon.detectors import AuthFailureCounter, Deduper, FlowAggregator, ScanDetector, VolumeDetector
from testops_gate.daemon.security import SecurityEngine
from testops_gate.db import LiveClient
from testops_gate.i18n import set_language
from testops_gate.paths import P
from testops_gate.render.openvpn import network, server_ip
from testops_gate.system import forwarding, nft
from testops_gate.system.easyrsa import crl_next_update
from testops_gate.system.openvpn import ClientStatus, read_status_file

log = logging.getLogger("testops-gated")

POLL_OPENVPN = 2.0
STATUS_STALE = 15.0  # seconds without a status file update: OpenVPN is not running
CONFIG_WATCH = 3.0
POLL_NFT = 5.0
NFT_REPORTED_AGE = 30.0
HOUSEKEEPING = 60.0
CRL_RENEW_BEFORE = timedelta(days=30)
DNS_DEDUPE = 5.0


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}GB"


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}h{minutes:02d}m" if hours else f"{minutes}m{secs:02d}s"


class Daemon:
    def __init__(self) -> None:
        self.ctx = Context.open(reload=True)
        self.config_mtime = self._config_mtime()
        self.users_by_ip: dict[str, str] = {}
        self.real_ips: dict[str, str] = {}
        self.engine = SecurityEngine(self.ctx, self.real_ips)
        self.clients: dict[str, ClientStatus] = {}
        self._apply_settings()
        self.flows = FlowAggregator()
        self.dns_dedupe = Deduper(DNS_DEDUPE)
        self.nft_seen: dict[str, set[tuple[str, ...]]] = {"denied": set(), "forbidden": set()}
        self.stopping = asyncio.Event()
        self.last_cleanup = 0.0
        self.last_crl_check = 0.0

    # --- settings ------------------------------------------------------------

    def _config_mtime(self) -> float:
        paths = (P.config_file, P.secrets_file)
        return max((p.stat().st_mtime for p in paths if p.exists()), default=0.0)

    def _apply_settings(self) -> None:
        sec = self.ctx.cfg.security
        self.scan = ScanDetector(sec.scan_threshold, sec.scan_window)
        self.volume = VolumeDetector(sec.volume_threshold_mb, sec.volume_window)
        self.auth = AuthFailureCounter(sec.auth_fail_threshold, 300)
        self.vpn_net = network(self.ctx.cfg)
        self.server_ip = server_ip(self.ctx.cfg)
        self.refresh_users()

    def refresh_users(self) -> None:
        self.users_by_ip = {u.vpn_ip: u.name for u in self.ctx.store.users()}
        self._last_user_refresh = time.monotonic()

    def reload_config_if_changed(self) -> None:
        mtime = self._config_mtime()
        if mtime == self.config_mtime:
            return
        self.config_mtime = mtime
        self.ctx.cfg = config_mod.load()
        set_language(self.ctx.cfg.language)
        self._apply_settings()
        log.info("configuration reloaded")

    def user_for(self, address: str) -> str | None:
        user = self.users_by_ip.get(address)
        if user is None and self._in_vpn(address) and time.monotonic() - self._last_user_refresh > 1:
            # a user added moments ago: look again instead of dropping the event
            self.refresh_users()
            user = self.users_by_ip.get(address)
        return user

    def _in_vpn(self, address: str) -> bool:
        try:
            return ipaddress.IPv4Address(address) in self.vpn_net
        except ValueError:
            return False

    # --- runner --------------------------------------------------------------

    async def supervise(self, name: str, factory: Callable[[], Awaitable[None]]) -> None:
        delay = 2.0
        while not self.stopping.is_set():
            started = time.monotonic()
            try:
                await factory()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("%s failed", name)
            if self.stopping.is_set():
                return
            delay = 2.0 if time.monotonic() - started > 60 else min(delay * 2, 60.0)
            await asyncio.sleep(delay)

    async def run(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, self.stopping.set)
        sources: dict[str, Callable[[], Awaitable[None]]] = {
            "openvpn-status": self.poll_openvpn,
            "conntrack": self.read_conntrack,
            "unbound-journal": lambda: self.read_journal("unbound.service", self.on_unbound_line),
            "openvpn-journal": lambda: self.read_journal("openvpn-server@server.service", self.on_openvpn_line),
            "nft-sets": self.poll_nft,
            "suricata": self.tail_suricata,
            "config": self.watch_config,
            "housekeeping": self.housekeeping,
            "updates": self.check_updates,
        }
        tasks = [asyncio.create_task(self.supervise(name, factory), name=name) for name, factory in sources.items()]
        log.info("testops-gated %s started", __version__)
        await self.stopping.wait()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for record in self.flows.flush(time.time(), force=True):
            self.write_flow(record)
        log.info("testops-gated stopped")

    # --- OpenVPN sessions and traffic ----------------------------------------

    async def poll_openvpn(self) -> None:
        # The status file is used instead of the management socket: polling the socket
        # makes OpenVPN log four lines every time.
        while True:
            result = await asyncio.to_thread(read_status_file)
            if result is None or result[1] > STATUS_STALE:
                if self.clients:  # OpenVPN stopped
                    self.end_sessions(list(self.clients), reason="server unavailable")
                self.ctx.store.set_live_clients([])
            else:
                self.process_status(result[0], time.time())
            await asyncio.sleep(POLL_OPENVPN)

    async def watch_config(self) -> None:
        while True:
            await asyncio.sleep(CONFIG_WATCH)
            self.reload_config_if_changed()
            self.refresh_users()
            for record in self.flows.flush(time.time()):  # also when no new connections arrive
                self.write_flow(record)

    def process_status(self, status: list[ClientStatus], now: float) -> None:
        current = {c.name: c for c in status}
        day = logs.day_of(logs.now())
        for name, client in current.items():
            previous = self.clients.get(name)
            if previous is None or client.connected_since != previous.connected_since:
                if previous is not None:
                    self.end_sessions([name], reason="reconnect")
                logs.write_event(name, "SESSION", f"{'connect':<10} real_ip={client.real_ip} vpn_ip={client.vpn_ip}")
                previous = None
            d_rx = client.bytes_sent - (previous.bytes_sent if previous else 0)
            d_tx = client.bytes_received - (previous.bytes_received if previous else 0)
            self.ctx.store.add_traffic(name, day, d_rx, d_tx)
            total = self.volume.add(name, d_tx, now)
            if total:
                self.engine.raise_alert(
                    "abnormal-volume", "medium", name,
                    f"uploaded={human_bytes(total)} window={self.ctx.cfg.security.volume_window}s",
                    real_ip=client.real_ip,
                )
            self.real_ips[name] = client.real_ip
        gone = [name for name in self.clients if name not in current]
        self.end_sessions(gone)
        self.clients = current
        self.ctx.store.set_live_clients([
            LiveClient(c.name, c.real_ip, c.vpn_ip, c.connected_since, c.bytes_sent, c.bytes_received, now)
            for c in status
        ])

    def end_sessions(self, names: list[str], reason: str = "") -> None:
        for name in names:
            client = self.clients.pop(name, None)
            if not client:
                continue
            duration = human_duration(time.time() - client.connected_since)
            extra = f" reason={reason}" if reason else ""
            logs.write_event(name, "SESSION", f"{'disconnect':<10} duration={duration} "
                                              f"rx={human_bytes(client.bytes_sent)} tx={human_bytes(client.bytes_received)}{extra}")
            self.real_ips.pop(name, None)

    # --- conntrack -----------------------------------------------------------

    async def read_conntrack(self) -> None:
        proc = await asyncio.create_subprocess_exec(
            "conntrack", "-E", "-e", "NEW", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
        try:
            assert proc.stdout
            while line := await proc.stdout.readline():
                self.on_conntrack_line(line.decode(errors="replace"), time.time())
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()

    def on_conntrack_line(self, line: str, now: float) -> None:
        event = parsers.parse_conntrack(line)
        if event:
            self.on_connection(event, now)
        for record in self.flows.flush(now):
            self.write_flow(record)

    def on_connection(self, event: parsers.ConnEvent, now: float) -> None:
        user = self.user_for(event.src)
        if not user:
            return
        if event.dst == self.server_ip and event.dport == 53:
            return  # DNS queries are logged from Unbound with names
        self.flows.add(user, event.proto, event.dst, event.dport, now)
        if event.dport:
            finding = self.scan.add(user, event.dst, event.dport, now)
            if finding:
                self.engine.raise_alert(
                    "port-scan", "high", user,
                    f"dst={finding.target} ports={finding.ports} hosts={finding.hosts} "
                    f"window={self.ctx.cfg.security.scan_window}s",
                    key=finding.target,
                )

    def write_flow(self, record) -> None:
        port = f" dport={record.dport}" if record.dport else ""
        logs.write_event(record.user, "CONN", f"{record.proto:<10} dst={record.dst}{port} count={record.count}",
                         datetime.fromtimestamp(record.first).astimezone())

    # --- journal sources -----------------------------------------------------

    async def read_journal(self, unit: str, handler: Callable[[str], None]) -> None:
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-f", "-n", "0", "-o", "cat", "-u", unit,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            assert proc.stdout
            while line := await proc.stdout.readline():
                handler(line.decode(errors="replace").rstrip("\n"))
        finally:
            if proc.returncode is None:
                proc.kill()
            await proc.wait()

    def on_unbound_line(self, line: str) -> None:
        rpz = parsers.parse_unbound_rpz(line)
        if rpz:
            user = self.user_for(rpz.client)
            if user:
                logs.write_event(user, "DNS", f"{'blocked':<10} name={rpz.name} action={rpz.action}")
                self.engine.raise_alert("malicious-domain", "medium", user, f"name={rpz.name} action={rpz.action}",
                                        key=rpz.name)
            return
        reply = parsers.parse_unbound_reply(line)
        if not reply:
            return
        user = self.user_for(reply.client)
        if user and self.dns_dedupe.fresh((user, reply.name, reply.qtype), time.time()):
            logs.write_event(user, "DNS", f"{'query':<10} name={reply.name} type={reply.qtype} rcode={reply.rcode}")

    def on_openvpn_line(self, line: str) -> None:
        failure = parsers.parse_openvpn_auth(line)
        if not failure:
            return
        count = self.auth.add(failure.real_ip, time.time())
        if count:
            user = failure.name if failure.name and self.ctx.store.user(failure.name) else "-"
            self.engine.raise_alert(
                "auth-failure", "medium", user,
                f"real_ip={failure.real_ip} failures={count} window=300s reason={failure.reason.replace(' ', '_')}",
                key=failure.real_ip, real_ip=failure.real_ip,
            )

    # --- nftables sets -------------------------------------------------------

    async def poll_nft(self) -> None:
        for name in self.nft_seen:
            # Elements older than this were reported by an earlier run; newer ones are reported now
            current = await asyncio.to_thread(nft.set_elements_with_age, name)
            self.nft_seen[name] = {element for element, age in current if age > NFT_REPORTED_AGE}
        while True:
            await asyncio.sleep(POLL_NFT)
            for name in self.nft_seen:
                elements = set(await asyncio.to_thread(nft.set_elements, name))
                self.on_nft_elements(name, elements)

    def on_nft_elements(self, set_name: str, elements: set[tuple[str, ...]]) -> None:
        new = elements - self.nft_seen[set_name]
        self.nft_seen[set_name] = elements
        for element in sorted(new):
            if len(element) != 3:
                continue
            src, dst, port = element
            user = self.user_for(src) or "-"
            if set_name == "denied":
                self.engine.raise_alert("unauthorized-target", "medium", user, f"dst={dst} dport={port} action=dropped",
                                        key=f"{dst}:{port}")
            else:
                self.engine.raise_alert("forbidden-port", "low", user, f"dst={dst} dport={port} action=dropped",
                                        key=port)

    # --- Suricata ------------------------------------------------------------

    async def tail_suricata(self) -> None:
        path = P.suricata_eve
        handle = None
        inode = None
        while True:
            if not self.ctx.cfg.security.category_enabled("ids"):
                if handle:
                    handle.close()
                    handle = None
                await asyncio.sleep(10)
                continue
            if handle is None:
                if not path.exists():
                    await asyncio.sleep(10)
                    continue
                handle = open(path, encoding="utf-8", errors="replace")
                handle.seek(0, os.SEEK_END)
                inode = os.fstat(handle.fileno()).st_ino
            line = handle.readline()
            if line:
                self.on_eve_line(line)
                continue
            await asyncio.sleep(1)
            try:
                stat = path.stat()
                if stat.st_ino != inode or stat.st_size < handle.tell():
                    handle.close()
                    handle = None  # rotated or truncated: reopen
            except FileNotFoundError:
                handle.close()
                handle = None

    def on_eve_line(self, line: str) -> None:
        event = parsers.parse_eve(line)
        if not event:
            return
        user = self.user_for(event.src) or self.user_for(event.dst)
        if not user:
            return
        detail = (f"sid={event.sid} \"{event.signature}\" {event.proto} "
                  f"{event.src}:{event.src_port} -> {event.dst}:{event.dst_port}")
        self.engine.raise_alert("ids-signature", event.severity, user, detail, key=str(event.sid))

    # --- updates -------------------------------------------------------------

    async def check_updates(self) -> None:
        from testops_gate.core import update

        while True:
            state = await asyncio.to_thread(update.check, self.ctx.cfg)  # at most once a day
            if state.available and state.latest != getattr(self, "_announced", ""):
                self._announced = state.latest
                log.info("update available: %s -> %s (sudo testops-gate update)", state.current, state.latest)
            await asyncio.sleep(3600)

    # --- housekeeping --------------------------------------------------------

    async def housekeeping(self) -> None:
        while True:
            self.housekeeping_once(time.time())
            await asyncio.sleep(HOUSEKEEPING)

    def housekeeping_once(self, now: float) -> None:
        self.reload_config_if_changed()
        self.refresh_users()
        for record in self.flows.flush(now):
            self.write_flow(record)
        expired = [u for u in self.ctx.store.users() if 0 < u.blocked_until <= now]
        for user in expired:
            self.ctx.store.update_user(user.name, blocked_until=0)
            logs.audit("user.unblock", user.name, actor="testops-gated")
        if expired:
            write_ccd(self.ctx.cfg, self.ctx.store)
        # Docker and ufw rebuild their rules on restart: keep VPN traffic allowed through them
        added = forwarding.ensure()
        if added:
            log.info("allowed VPN traffic through %s", ", ".join(added))
            logs.audit("firewall.allow", ", ".join(added), actor="testops-gated")
        if now - self.last_cleanup >= 3600:
            self.last_cleanup = now
            retention = self.ctx.cfg.logging.retention_days
            removed = logs.cleanup(retention)
            self.ctx.store.prune_alerts(now - retention * 86400)
            if removed:
                log.info("retention: removed %d log files older than %d days", len(removed), retention)
        if now - self.last_crl_check >= 86400:
            self.last_crl_check = now
            self.check_crl()

    def check_crl(self) -> None:
        next_update = crl_next_update(P.openvpn_dir / "crl.pem")
        if next_update and next_update - datetime.now(timezone.utc) < CRL_RENEW_BEFORE:
            self.ctx.refresh_crl()
            logs.audit("crl.renew", f"previous next_update={next_update:%Y-%m-%d}", actor="testops-gated")


def setup_logging(foreground: bool) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    stream = logging.StreamHandler(sys.stderr)
    stream.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s") if not foreground else fmt)
    root.addHandler(stream)
    try:
        P.log_dir.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.TimedRotatingFileHandler(P.daemon_log_file, when="midnight", backupCount=14)
        handler.setFormatter(fmt)
        root.addHandler(handler)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="testops-gated", description="testops-gate log collector and security monitor")
    parser.add_argument("--cleanup", action="store_true", help="delete logs older than the retention period and exit")
    parser.add_argument("--foreground", action="store_true", help="log with timestamps to stderr")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    if not config_mod.exists():
        print("testops-gate is not installed yet; run `sudo testops-gate`", file=sys.stderr)
        return 1
    setup_logging(args.foreground)
    if args.cleanup:
        ctx = Context.open()
        removed = logs.cleanup(ctx.cfg.logging.retention_days)
        print(f"removed {len(removed)} files")
        return 0
    try:
        ipaddress.IPv4Network(config_mod.load().server.network)
    except ValueError as exc:
        log.error("invalid server.network: %s", exc)
        return 1
    asyncio.run(Daemon().run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
