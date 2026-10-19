# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Dashboard pages."""

from __future__ import annotations

import asyncio
import os
import pwd
import time
from datetime import date, datetime
from typing import TYPE_CHECKING

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.widgets import (
    Button,
    DataTable,
    Input,
    Label,
    OptionList,
    RadioButton,
    RadioSet,
    RichLog,
    Select,
    Sparkline,
    Static,
    Switch,
)
from textual.widgets.option_list import Option

from testops_gate import __version__, logs
from testops_gate.config import SECURITY_CATEGORIES, UPSTREAMS
from testops_gate.i18n import LANGUAGES, T
from testops_gate.render.openvpn import effective_mode, server_ip
from testops_gate.system import dnsquery, services
from testops_gate.tui.forms import (
    AccessDialog,
    ChannelForm,
    ExportForm,
    HostForm,
    ListForm,
    PasswordForm,
    RepairDialog,
    UninstallDialog,
    UserForm,
    auth_options,
)
from testops_gate.tui.theme import GREEN, KIND_STYLE, RED, SEVERITY_STYLE, YELLOW
from testops_gate.tui.widgets import ConfirmDialog, FormSelect, StatCard, ToggleRow, panel

if TYPE_CHECKING:
    from testops_gate.tui.app import GateApp

SEVERITY_LABEL = {"high": "▲ high", "medium": "■ medium", "low": "● low"}
SERVICE_NAMES = {
    services.OPENVPN_UNIT: "openvpn",
    services.UNBOUND_UNIT: "unbound",
    services.FIREWALL_UNIT: "firewall",
    services.DAEMON_UNIT: "testops-gated",
    services.SURICATA_UNIT: "suricata",
}
CATEGORY_TEXT = {
    "scan": ("Network scan detection", "connection tracking · many ports/hosts in a short time"),
    "unauth": ("Unauthorized target access", "nftables · blocked networks"),
    "ports": ("Forbidden port / protocol", "nftables · forbidden ports"),
    "rpz": ("Malicious domain blocking", "Unbound RPZ · phishing / malware lists"),
    "ids": ("Attack signatures", "Suricata · ET Open ruleset"),
    "volume": ("Abnormal data volume", "upload thresholds · possible exfiltration"),
    "auth": ("Failed VPN attempts", "OpenVPN · invalid / revoked certificate"),
    "autoblock": ("Automatic blocking", "disable + disconnect on high-severity alerts"),
}


def severity_text(severity: str) -> Text:
    return Text(T(SEVERITY_LABEL[severity]).ljust(9), SEVERITY_STYLE[severity])


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB", "MB") else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} TB"


def hhmm(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M") if ts else "—"


def default_export_dir() -> str:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


class Page(Vertical):
    FOCUS_TARGET = ""

    @property
    def tg(self) -> GateApp:
        return self.app  # type: ignore[return-value]

    def focus_default(self) -> None:
        if self.FOCUS_TARGET:
            self.query_one(self.FOCUS_TARGET).focus()

    def refresh_data(self) -> None:
        pass

    def keep_cursor(self, table: DataTable, count: int, cursor: int) -> None:
        if count:
            table.move_cursor(row=min(cursor, count - 1))


# --- Dashboard ------------------------------------------------------------------


class DashboardPage(Page):
    FOCUS_TARGET = "#online-table"

    def compose(self) -> ComposeResult:
        with Horizontal(id="stats"):
            yield StatCard(T("CONNECTED USERS"), "0", id="st-online")
            yield StatCard(T("TODAY'S TRAFFIC"), "0", id="st-traffic")
            yield StatCard(T("SECURITY ALERTS"), "0", id="st-alerts")
            yield StatCard(T("TUNNEL MODE"), "", digits=False, id="st-mode")
        with Horizontal(id="dash-body"):
            with panel(T("Connected users"), id="dash-left"):
                yield DataTable(id="online-table", cursor_type="row", zebra_stripes=True)
            with Vertical(id="dash-right"):
                with panel(T("Services"), id="p-services"):
                    yield Static(id="services")
                with panel(T("Traffic · last 2 min"), id="p-traffic"):
                    yield Sparkline([0.0], id="spark")
                with panel(T("Recent alerts"), id="p-alerts"):
                    yield Static(id="recent-alerts")

    def on_mount(self) -> None:
        self.query_one("#online-table", DataTable).add_columns(
            T("User"), "VPN IP", T("Login"), "↓", "↑", T("Tunnel"), T("Alert"))
        self.refresh_data()

    def refresh_data(self) -> None:
        snap = self.tg.snapshot
        cfg = self.tg.ctx.cfg
        users = {u.name: u for u in snap.users}
        last_alert = {}
        for alert in reversed(snap.alerts):
            last_alert[alert.user] = alert.category
        table = self.query_one("#online-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for client in sorted(snap.live.values(), key=lambda c: c.name):
            user = users.get(client.name)
            mode = effective_mode(cfg, user) if user else cfg.tunnel.mode
            alert = last_alert.get(client.name, "—")
            table.add_row(
                Text(client.name, "bold"), client.vpn_ip, hhmm(client.connected_since),
                fmt_bytes(client.rx), fmt_bytes(client.tx),
                Text(mode, "bold " + YELLOW) if user and user.mode != "default" else Text(mode, "dim"),
                Text(alert, RED if alert != "—" else "dim"), key=client.name,
            )
        self.keep_cursor(table, len(snap.live), cursor)

        rx = sum(v[0] for v in snap.traffic.values())
        tx = sum(v[1] for v in snap.traffic.values())
        high = sum(a.severity == "high" for a in snap.alerts)
        gb = 1024 ** 3
        self.query_one("#st-online", StatCard).set(str(len(snap.live)), T("/ {n} registered users", n=len(snap.users)))
        self.query_one("#st-traffic", StatCard).set(f"{(rx + tx) / gb:.2f}", f"GB  ↓ {rx / gb:.2f}  ↑ {tx / gb:.2f}")
        self.query_one("#st-alerts", StatCard).set(
            str(len(snap.alerts)),
            T("last 24 h · {n} high", n=high) if cfg.security.enabled else T("monitoring off"),
        )
        mode_card = self.query_one("#st-mode", StatCard)
        mode_card.set(cfg.tunnel.mode.upper(),
                      T("defined hosts only") if cfg.tunnel.mode == "split" else T("all traffic via VPN"))
        mode_card.set_class(cfg.tunnel.mode == "full", "full")

        details = {
            services.OPENVPN_UNIT: T("{n} connections · {proto}/{port}", n=len(snap.live),
                                     proto=cfg.server.protocol, port=cfg.server.port),
            services.UNBOUND_UNIT: T("{n} host records", n=len(snap.hosts)),
            services.FIREWALL_UNIT: "nftables",
            services.DAEMON_UNIT: T("log collector · security"),
            services.SURICATA_UNIT: "IDS · ET Open",
        }
        text = Text()
        for i, (unit, active) in enumerate(snap.services.items()):
            if i:
                text.append("\n")
            text.append("● " if active else "○ ", f"bold {GREEN}" if active else f"bold {RED}")
            text.append(f"{SERVICE_NAMES.get(unit, unit):<14}", "bold" if active else RED)
            text.append(details.get(unit, "") if active else T("not running"), "dim")
        if not all(snap.services.values()):
            text.append("\n\n" + T("r: diagnose and repair"), f"bold {YELLOW}")
        self.query_one("#services", Static).update(text)

        self.query_one("#spark", Sparkline).data = list(snap.throughput) or [0.0]
        rate = snap.throughput[-1] if snap.throughput else 0
        self.query_one("#p-traffic").border_subtitle = f"{fmt_bytes(rate)}/s"

        recent = Text()
        for i, a in enumerate(snap.alerts[:8]):
            if i:
                recent.append("\n")
            recent.append(f"{hhmm(a.ts)}  ", "dim")
            recent.append_text(severity_text(a.severity))
            recent.append(f" {a.user:<10} ", "bold")
            recent.append(a.category)
        if not snap.alerts:
            recent.append(T("No alerts"), "dim")
        self.query_one("#recent-alerts", Static).update(recent)

    def action_repair(self) -> None:
        def done(repaired: bool | None) -> None:
            if repaired:
                self.tg.refresh_snapshot(services_too=True)

        self.app.push_screen(RepairDialog(self.tg.ctx), done)


# --- Users ----------------------------------------------------------------------


class UsersPage(Page):
    FOCUS_TARGET = "#users-table"
    BINDINGS = [
        Binding("a", "add", "Add"),
        Binding("e", "edit", "Edit"),
        Binding("space", "toggle", "Enable/Disable"),
        Binding("x,delete", "delete", "Delete"),
        Binding("o", "export", "Profile"),
        Binding("r", "renew", "Renew"),
        Binding("p", "password", "Password"),
        Binding("slash", "search", "Search"),
        Binding("down", "focus_table", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Horizontal(classes="toolbar"):
            yield Label(T("Users"), classes="page-title")
            yield Input(placeholder=T("🔍 Search…  ( / )"), id="user-search")
        with panel(T("VPN users"), id="users-panel"):
            yield DataTable(id="users-table", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        self.query_one("#users-table", DataTable).add_columns(
            T("Status"), T("User"), T("Email"), "VPN IP", T("Tunnel"), T("Today ↓ / ↑"), T("Expires"), T("Last alert"))
        self.refresh_data()

    def visible(self) -> list:
        term = self.query_one("#user-search", Input).value.lower()
        return [u for u in self.tg.snapshot.users if term in u.name.lower() or term in u.email.lower()]

    def status_text(self, user) -> Text:
        if not user.enabled:
            return Text(T("⊘ disabled"), RED)
        if user.blocked:
            return Text(T("⊘ blocked"), RED)
        if user.name in self.tg.snapshot.live:
            return Text(T("● online"), f"bold {GREEN}")
        return Text(T("○ offline"), "dim")

    def refresh_data(self) -> None:
        snap = self.tg.snapshot
        cfg = self.tg.ctx.cfg
        last_alert = {}
        for alert in reversed(snap.alerts):
            last_alert[alert.user] = alert.category
        table = self.query_one("#users-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        users = self.visible()
        soon = time.time() + 30 * 86400
        for u in users:
            rx, tx = snap.traffic.get(u.name, (0, 0))
            mode = effective_mode(cfg, u)
            expires = Text(datetime.fromtimestamp(u.cert_expires).strftime("%Y-%m-%d"),
                           YELLOW if u.cert_expires < soon else "")
            alert = last_alert.get(u.name, "—")
            table.add_row(
                self.status_text(u), Text(u.name, "bold"), u.email or "—", u.vpn_ip,
                Text(f"{mode} ★", "bold " + YELLOW) if u.mode != "default" else Text(mode, "dim"),
                f"{fmt_bytes(rx)} / {fmt_bytes(tx)}" if rx or tx else "—", expires,
                Text(alert, RED if alert != "—" else "dim"), key=u.name,
            )
        self.keep_cursor(table, len(users), cursor)
        self.query_one("#users-panel").border_subtitle = T("{n} users · enter: edit · space: disable", n=len(users))

    def selected(self):
        users = self.visible()
        row = self.query_one("#users-table", DataTable).cursor_row
        return users[row] if users and 0 <= row < len(users) else None

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "user-search":
            self.refresh_data()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id == "users-table":
            self.action_edit()

    def action_search(self) -> None:
        self.query_one("#user-search", Input).focus()

    def action_focus_table(self) -> None:
        self.query_one("#users-table", DataTable).focus()

    def action_add(self) -> None:
        ctx = self.tg.ctx

        def submit(data: dict):
            return ctx.add_user(data["name"], data["email"], data["mode"], data["days"], data["vpn_ip"],
                                data.get("password"))

        def done(user) -> None:
            if user:
                self.tg.refresh_snapshot()
                self.app.push_screen(AccessDialog(T("✓ {name} added · {ip}", name=user.name, ip=user.vpn_ip),
                                                  ctx.cfg, [(user.name, user.password)]))

        self.app.push_screen(UserForm(submit, ask_password=ctx.uses_passwords), done)

    def action_password(self) -> None:
        user = self.selected()
        if not user:
            return
        ctx = self.tg.ctx
        if not ctx.uses_passwords:
            self.notify(T("Passwords are off (Settings → Authentication)"), severity="warning")
            return

        def submit(data: dict):
            return ctx.set_password(user.name, data["password"])

        def done(password) -> None:
            if password:
                self.app.push_screen(AccessDialog(T("✓ New password · {name}", name=user.name), ctx.cfg,
                                                  [(user.name, password)]))

        self.app.push_screen(PasswordForm(submit, user.name, ctx.cfg.auth.mode == "profile-password"), done)

    def action_edit(self) -> None:
        user = self.selected()
        if not user:
            return
        ctx = self.tg.ctx

        def submit(data: dict):
            return ctx.update_user(user.name, email=data["email"], mode=data["mode"], vpn_ip=data["vpn_ip"] or None)

        def done(result) -> None:
            if result:
                self.tg.refresh_snapshot()
                self.notify(T("{name} updated", name=user.name))

        self.app.push_screen(UserForm(submit, user), done)

    async def action_toggle(self) -> None:
        user = self.selected()
        if not user:
            return
        enable = not user.enabled or user.blocked
        kicked = await self.tg.run_op(self.tg.ctx.set_user_enabled, user.name, enable)
        if kicked is None:
            return
        if enable:
            self.notify(T("{name} enabled", name=user.name))
        else:
            self.notify(T("{name} disabled", name=user.name) + (T(" · disconnected") if kicked else ""),
                        severity="warning")
        self.tg.refresh_snapshot()

    def action_delete(self) -> None:
        user = self.selected()
        if not user:
            return

        async def done(confirmed: bool | None) -> None:
            if confirmed and await self.tg.run_op(self.tg.ctx.delete_user, user.name) is not None:
                self.tg.refresh_snapshot()
                self.notify(T("{name} deleted · certificate revoked", name=user.name), severity="warning")

        self.app.push_screen(ConfirmDialog(T("Delete user"), T(
            "Delete [b]{name}[/b]?\n\n"
            "• The certificate is revoked and the session is dropped\n"
            "• The .ovpn profile is deleted\n"
            "• Logs are kept for {days} days",
            name=user.name, days=self.tg.ctx.cfg.logging.retention_days,
        )), done)

    def action_export(self) -> None:
        user = self.selected()
        if not user:
            return
        ctx = self.tg.ctx

        def submit(data: dict):
            return ctx.export_profile(user.name, data["path"])

        def done(path) -> None:
            if path:
                self.notify(str(path), title=T("✓ Profile saved"))

        self.app.push_screen(ExportForm(submit, user.name, default_export_dir()), done)

    def action_renew(self) -> None:
        user = self.selected()
        if not user:
            return

        async def done(confirmed: bool | None) -> None:
            if not confirmed:
                return
            password = await self.tg.run_op(self.tg.ctx.renew_user, user.name)
            if password is None:
                return
            self.tg.refresh_snapshot()
            self.notify(T("New certificate issued for {name}; send the user the new profile.", name=user.name))
            if isinstance(password, str) and password:
                self.app.push_screen(AccessDialog(T("✓ New profile · {name}", name=user.name), self.tg.ctx.cfg,
                                                  [(user.name, password)]))

        self.app.push_screen(ConfirmDialog(
            T("Renew certificate"),
            T("Issue a new certificate for [b]{name}[/b]? The current profile stops working.", name=user.name),
            confirm_label="Renew",
        ), done)


# --- Hosts ----------------------------------------------------------------------


class HostsPage(Page):
    FOCUS_TARGET = "#hosts-table"
    BINDINGS = [
        Binding("a", "add", "Add"),
        Binding("e", "edit", "Edit"),
        Binding("x,delete", "delete", "Delete"),
        Binding("t", "test", "DNS test"),
    ]

    def compose(self) -> ComposeResult:
        yield Label(T("Hosts · internal DNS"), classes="page-title")
        with panel(T("Unbound records"), id="hosts-panel"):
            yield DataTable(id="hosts-table", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        self.query_one("#hosts-table", DataTable).add_columns(T("Domain"), T("Type"), T("Target"), T("Note"))
        self.refresh_data()

    def refresh_data(self) -> None:
        hosts = self.tg.snapshot.hosts
        table = self.query_one("#hosts-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        for h in hosts:
            table.add_row(Text(h.name, "bold"), Text(h.rtype, "#39c5cf"), h.value, Text(h.note or "—", "dim"),
                          key=h.name)
        self.keep_cursor(table, len(hosts), cursor)
        cfg = self.tg.ctx.cfg
        self.query_one("#hosts-panel").border_subtitle = T(
            "{n} records · DNS {dns} · mode: {mode}", n=len(hosts), dns=server_ip(cfg), mode=cfg.tunnel.mode)

    def selected(self):
        hosts = self.tg.snapshot.hosts
        row = self.query_one("#hosts-table", DataTable).cursor_row
        return hosts[row] if hosts and 0 <= row < len(hosts) else None

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self.action_edit()

    def _form(self, host=None) -> None:
        ctx = self.tg.ctx

        def submit(data: dict):
            return ctx.save_host(data["name"], data["rtype"], data["value"], data["note"], old_name=data["old_name"])

        def done(result) -> None:
            if result:
                self.tg.refresh_snapshot()
                self.notify(f"{result.name} → {result.value}",
                            title=T("✓ Host saved · unbound reloaded"))
                if ctx.cfg.tunnel.mode == "split":
                    self.notify(T("Split-mode routes are updated for users when they reconnect."))

        self.app.push_screen(HostForm(submit, host), done)

    def action_add(self) -> None:
        self._form()

    def action_edit(self) -> None:
        host = self.selected()
        if host:
            self._form(host)

    def action_delete(self) -> None:
        host = self.selected()
        if not host:
            return

        async def done(confirmed: bool | None) -> None:
            if confirmed and await self.tg.run_op(self.tg.ctx.delete_host, host.name) is not None:
                self.tg.refresh_snapshot()
                self.notify(T("{name} deleted", name=host.name), severity="warning")

        self.app.push_screen(ConfirmDialog(
            T("Delete host record"), T("Delete record [b]{name}[/b] → {value}?", name=host.name, value=host.value)
        ), done)

    async def action_test(self) -> None:
        host = self.selected()
        if not host:
            return
        name = host.name.replace("*", "test", 1)
        dns = server_ip(self.tg.ctx.cfg)
        try:
            answer = await asyncio.to_thread(dnsquery.query, dns, name)
        except OSError as exc:
            self.notify(f"{dns}: {exc}", title=T("✗ DNS test failed"), severity="error")
            return
        values = ", ".join(v for _, v in answer.records) or "—"
        ok = answer.rcode == "NOERROR" and answer.records
        self.notify(f"{name} → {values}   ({answer.rcode}, {answer.elapsed_ms:.0f} ms)",
                    title=T("✓ DNS test passed") if ok else T("✗ DNS test failed"),
                    severity="information" if ok else "error")


# --- Security -------------------------------------------------------------------


class SecurityPage(Page):
    FOCUS_TARGET = "#sw-master"
    BINDINGS = [
        Binding("down", "app.focus_next", show=False),
        Binding("up", "app.focus_previous", show=False),
        Binding("b", "blocked", "Blocked networks"),
        Binding("p", "ports", "Forbidden ports"),
    ]

    def compose(self) -> ComposeResult:
        sec = self.tg.ctx.cfg.security
        yield Label(T("Security monitoring"), classes="page-title")
        with Horizontal(id="sec-body"):
            with Vertical(id="sec-left"):
                with panel(T("Categories"), id="toggles"):
                    with VerticalScroll():
                        yield ToggleRow("master", T("Security monitoring"), T("All detection and notifications"),
                                        sec.enabled, master=True)
                        for key in [*SECURITY_CATEGORIES, "autoblock"]:
                            title, desc = CATEGORY_TEXT[key]
                            yield ToggleRow(key, T(title), T(desc), sec.categories.get(key, False),
                                            disabled=not sec.enabled)
                with panel(T("Rules"), id="sec-lists"):
                    yield Static(id="sec-lists-text")
            with panel(T("Alerts · /var/log/testops-gate/security/"), id="sec-alerts"):
                yield DataTable(id="alerts-table", cursor_type="row", zebra_stripes=True)

    def on_mount(self) -> None:
        self.query_one("#alerts-table", DataTable).add_columns(
            T("Time"), T("Severity"), T("User"), T("Category"), T("Detail"))
        self.refresh_data()

    def refresh_data(self) -> None:
        table = self.query_one("#alerts-table", DataTable)
        cursor = table.cursor_row
        table.clear()
        alerts = self.tg.snapshot.alerts
        for a in alerts:
            table.add_row(hhmm(a.ts), severity_text(a.severity), Text(a.user, "bold"), a.category, Text(a.detail, "dim"))
        self.keep_cursor(table, len(alerts), cursor)
        sec = self.tg.ctx.cfg.security
        text = Text()
        text.append(f"{T('Blocked networks')} (b): ", "dim")
        text.append(", ".join(sec.blocked_networks) or "—")
        text.append(f"\n{T('Forbidden ports')} (p): ", "dim")
        text.append(", ".join(sec.forbidden_ports) or "—")
        self.query_one("#sec-lists-text", Static).update(text)

    async def on_switch_changed(self, event: Switch.Changed) -> None:
        key = (event.switch.id or "").removeprefix("sw-")
        sec = self.tg.ctx.cfg.security
        current = sec.enabled if key == "master" else sec.categories.get(key)
        if current == event.value:
            return  # programmatic update
        row = event.switch.parent
        if isinstance(row, ToggleRow):
            row.set_class(not event.value, "-off")
        if key == "master":
            result = await self.tg.run_op(self.tg.ctx.set_security, enabled=event.value)
            if result is None:
                return
            for toggle in self.query(ToggleRow):
                if toggle.key != "master":
                    toggle.query_one(Switch).disabled = not event.value
                    toggle.set_class(not event.value, "-disabled")
            self.notify(T("Security monitoring enabled") if event.value
                        else T("Security monitoring disabled · connection/DNS logs continue"),
                        severity="information" if event.value else "warning")
        else:
            if key == "ids" and event.value and not await asyncio.to_thread(services.package_installed, "suricata"):
                self.notify(T("Installing Suricata (IDS) and downloading rules…"), timeout=15)
            if await self.tg.run_op(self.tg.ctx.set_security, **{key: event.value}) is None:
                return
            self.notify(f"{T(CATEGORY_TEXT[key][0])}: {T('on') if event.value else T('off')}")
        self.tg.refresh_snapshot()

    def _list_form(self, title: str, label: str, values: list[str], placeholder: str, hint: str, field: str) -> None:
        ctx = self.tg.ctx

        def submit(data: dict):
            ctx.set_security_lists(**{field: data["values"]})
            return True

        def done(result) -> None:
            if result:
                self.refresh_data()
                self.notify(T("✓ Firewall rules updated"))

        self.app.push_screen(ListForm(submit, title, label, values, placeholder, hint), done)

    def action_blocked(self) -> None:
        self._list_form(T("Blocked networks"), T("Networks VPN users may not reach (CIDR, comma-separated)"),
                        self.tg.ctx.cfg.security.blocked_networks, "10.0.1.0/24, 192.168.100.5/32",
                        T("Attempts are dropped and reported as unauthorized-target."), "blocked_networks")

    def action_ports(self) -> None:
        self._list_form(T("Forbidden ports"), T("Ports or ranges VPN users may not use (comma-separated)"),
                        self.tg.ctx.cfg.security.forbidden_ports, "25, 6881-6889",
                        T("Attempts are dropped and reported as forbidden-port."), "forbidden_ports")


# --- Logs -----------------------------------------------------------------------


class LogsPage(Page):
    FOCUS_TARGET = "#log-users-list"
    FILTERS = ["ALL", "SESSION", "DNS", "CONN", "SECURITY"]
    BINDINGS = [
        Binding("f", "follow", "Live follow"),
        Binding("t", "cycle_filter", "Filter"),
        Binding("left_square_bracket", "day(1)", "Older day"),
        Binding("right_square_bracket", "day(-1)", "Newer day"),
    ]

    follow = reactive(True)

    def compose(self) -> ComposeResult:
        yield Label(T("Logs"), classes="page-title")
        with Horizontal(id="log-body"):
            with panel(T("Source"), id="log-users"):
                yield OptionList(id="log-users-list")
            with panel("", id="log-view"):
                yield RichLog(id="log", max_lines=5000, wrap=False)

    def on_mount(self) -> None:
        self.current = ""
        self.filter_index = 0
        self.day = date.today().isoformat()
        self.position = 0
        self.refresh_data()
        self.query_one("#log-users-list", OptionList).highlighted = 0

    def sources(self) -> list[tuple[str, Text]]:
        snap = self.tg.snapshot
        items = [("__security__", Text(T("▲ security (all)"), f"bold {RED}")),
                 ("__audit__", Text(T("✎ audit"), f"bold {YELLOW}"))]
        names = {u.name for u in snap.users}
        if logs.P.users_log_dir.exists():
            names |= {d.name for d in logs.P.users_log_dir.iterdir() if d.is_dir()}
        for name in sorted(names):
            online = name in snap.live
            items.append((name, Text.assemble(("● " if online else "○ ", GREEN if online else "dim"), name)))
        return items

    def refresh_data(self) -> None:
        options = self.query_one("#log-users-list", OptionList)
        items = self.sources()
        if [o.id for o in options.options] != [key for key, _ in items]:
            highlighted = options.highlighted
            options.clear_options()
            options.add_options([Option(label, id=key) for key, label in items])
            if highlighted is not None:
                options.highlighted = min(highlighted, options.option_count - 1)

    def path(self, day: str | None = None):
        day = day or self.day
        if self.current == "__security__":
            return logs.security_log(day)
        if self.current == "__audit__":
            return logs.audit_log(day)
        return logs.user_log(self.current, day)

    def days(self) -> list[str]:
        directory = self.path().parent
        days = logs.available_days(directory)
        today = date.today().isoformat()
        return days if today in days else [today, *days]

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        if event.option.id and event.option.id != self.current:
            self.current = event.option.id
            self.day = date.today().isoformat()
            self.load()

    def matches(self, line: str) -> bool:
        kind = self.FILTERS[self.filter_index]
        return kind == "ALL" or f"[{kind}]" in line

    def format_log_line(self, line: str) -> Text:
        parts = line.split(" ", 2)
        if len(parts) < 3 or not parts[1].startswith("["):
            return Text(line)
        kind = parts[1].strip("[]")
        text = Text(no_wrap=True)
        text.append(parts[0][:19], "dim")
        text.append("  ")
        text.append(f"{parts[1]:<11}", KIND_STYLE.get(kind, ""))
        rest = parts[2].lstrip()
        user, _, message = rest.partition(" ")
        text.append(f"{user:<11}", "bold")
        text.append(message.lstrip())
        return text

    def load(self) -> None:
        log = self.query_one("#log", RichLog)
        log.clear()
        path = self.path()
        written = 0
        for line in logs.tail(path, 4000):
            if self.matches(line):
                log.write(self.format_log_line(line))
                written += 1
        if not written:
            log.write(Text(T("No entries for {day}", day=self.day), "dim"))
        self.position = path.stat().st_size if path.exists() else 0
        self.update_title()

    def update_title(self) -> None:
        live = T("● live") if self.follow and self.day == date.today().isoformat() else T("❚❚ paused")
        view = self.query_one("#log-view")
        view.border_title = str(self.path())
        view.border_subtitle = T("filter: {f} · {live} · [ ] day", f=T(self.FILTERS[self.filter_index]), live=live)

    def action_follow(self) -> None:
        self.follow = not self.follow
        self.update_title()

    def action_cycle_filter(self) -> None:
        self.filter_index = (self.filter_index + 1) % len(self.FILTERS)
        self.load()

    def action_day(self, step: int) -> None:
        days = self.days()
        index = days.index(self.day) if self.day in days else 0
        index = max(0, min(len(days) - 1, index + step))
        if days[index] != self.day:
            self.day = days[index]
            self.load()

    def tick(self) -> None:
        if not self.follow or not self.display or not self.current or self.day != date.today().isoformat():
            return
        path = self.path()
        if not path.exists():
            return
        size = path.stat().st_size
        if size < self.position:
            self.position = 0
        if size == self.position:
            return
        log = self.query_one("#log", RichLog)
        with open(path, encoding="utf-8", errors="replace") as fh:
            fh.seek(self.position)
            for line in fh:
                if self.matches(line):
                    log.write(self.format_log_line(line.rstrip("\n")))
            self.position = fh.tell()


# --- Settings -------------------------------------------------------------------


class ChannelTable(DataTable):
    """Notification channels; shortcuts work while the table is focused."""

    BINDINGS = [
        Binding("n", "add", "Add channel"),
        Binding("e", "edit", "Edit"),
        Binding("space", "toggle", "Enable/Disable"),
        Binding("x,delete", "delete", "Delete"),
        Binding("t", "test", "Test"),
    ]

    def settings(self) -> SettingsPage:
        return next(a for a in self.ancestors if isinstance(a, SettingsPage))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        event.stop()
        self.settings().edit_channel()

    def action_add(self) -> None:
        self.settings().edit_channel(new=True)

    def action_edit(self) -> None:
        self.settings().edit_channel()

    async def action_toggle(self) -> None:
        await self.settings().toggle_channel()

    def action_delete(self) -> None:
        self.settings().delete_channel()

    async def action_test(self) -> None:
        await self.settings().test_channels(only_selected=True)


class SettingsPage(Page):
    FOCUS_TARGET = "#language"
    BINDINGS = [
        Binding("down", "app.focus_next", show=False),
        Binding("up", "app.focus_previous", show=False),
    ]

    def compose(self) -> ComposeResult:
        cfg = self.tg.ctx.cfg
        yield Label(T("Settings"), classes="page-title")
        with VerticalScroll(id="settings-form"):
            with panel(T("Language"), classes="settings-panel"):
                with Horizontal(classes="field"):
                    yield Label(T("Interface language"), classes="field-name")
                    yield FormSelect(LANGUAGES, value=cfg.language, allow_blank=False, id="language")
            with panel(T("Tunnel mode"), classes="settings-panel"):
                yield Label(T("Global default. Per-user exceptions are set on the Users screen."), classes="hint")
                with RadioSet(id="tunnel-mode"):
                    yield RadioButton(T("split  ·  only defined hosts via VPN"), value=cfg.tunnel.mode == "split",
                                      id="mode-split")
                    yield RadioButton(T("full   ·  all traffic via VPN"), value=cfg.tunnel.mode == "full",
                                      id="mode-full")
                with Horizontal(classes="field"):
                    yield Label(T("Extra routes (split)"), classes="field-name")
                    yield Label(", ".join(cfg.tunnel.extra_routes) or "—", classes="field-value", id="routes-value")
                    yield Button(T("Edit"), id="edit-routes")
            with panel(T("Logging"), classes="settings-panel"):
                with Horizontal(classes="field"):
                    yield Label(T("Retention (days)"), classes="field-name")
                    yield Input(str(cfg.logging.retention_days), type="integer", id="retention")
                with Horizontal(classes="field"):
                    yield Label(T("Log directory"), classes="field-name")
                    yield Label("/var/log/testops-gate", classes="field-value")
            with panel("DNS", classes="settings-panel"):
                with Horizontal(classes="field"):
                    yield Label(T("Upstream resolver"), classes="field-name")
                    yield FormSelect([(f"{label} · {', '.join(addrs) or T('no forwarder')}", key)
                                      for key, (label, addrs) in UPSTREAMS.items()],
                                     value=cfg.dns.upstream, allow_blank=False, id="upstream")
                with Horizontal(classes="field"):
                    yield Label(T("Force VPN DNS"), classes="field-name")
                    yield Label(T("Other DNS servers, DNS-over-TLS and DNS-over-HTTPS are redirected or refused"),
                                classes="field-value hint")
                    yield Switch(cfg.dns.enforce, id="dns-enforce")
            with panel(T("Authentication"), classes="settings-panel"):
                with Horizontal(classes="field"):
                    yield Label(T("Sign-in"), classes="field-name")
                    yield FormSelect(auth_options(), value=cfg.auth.mode, allow_blank=False, id="auth-mode")
                yield Label(T("On top of the certificate. Username + password: checked by the server, a stolen "
                              "profile is not enough. Profile password: the key in the .ovpn file is encrypted."),
                            classes="hint")
            with panel(T("Notification channels"), classes="settings-panel"):
                yield ChannelTable(id="channels", cursor_type="row", zebra_stripes=True)
                yield Label(T("n: add · enter/e: edit · space: on/off · x: delete · t: test   (when the table is focused)"),
                            classes="hint")
            with panel(T("Server"), classes="settings-panel"):
                yield Static(id="server-info")
            with panel(T("Updates"), classes="settings-panel"):
                yield Static(id="update-info")
                with Horizontal(classes="field"):
                    yield Label(T("Check for updates daily"), classes="field-name")
                    yield Switch(cfg.updates.check, id="update-check")
                with Horizontal(classes="buttons"):
                    yield Button(T("Check now"), id="update-check-now")
                    yield Button(T("Update"), variant="primary", id="update-run", disabled=True)
            with Horizontal(classes="buttons"):
                yield Button(T("Save retention"), variant="primary", id="save")
                yield Button(T("＋ Add channel"), id="add-channel")
                yield Button(T("Test notification"), id="test")
            with panel(T("Uninstall"), classes="settings-panel danger"):
                with Horizontal(classes="field"):
                    yield Label(T("Remove the VPN server from this machine"), classes="field-value")
                    yield Button(T("Uninstall…"), variant="error", id="uninstall")

    def on_mount(self) -> None:
        self.query_one("#channels", DataTable).add_columns(
            T("Channel"), T("Name"), T("Target"), T("Min. severity"), T("Mute"), T("Status"))
        self.refresh_data()
        self.refresh_update_panel()

    def refresh_data(self) -> None:
        cfg = self.tg.ctx.cfg
        table = self.query_one("#channels", DataTable)
        cursor = table.cursor_row
        table.clear()
        for c in cfg.channels:
            table.add_row(
                Text("Slack" if c.kind == "slack" else T("Email"), "bold"), c.name,
                Text(c.target if c.kind == "email" else "webhook ✓", "dim"), severity_text(c.min_severity),
                T("{n} min", n=c.mute_minutes) if c.mute_minutes else T("none"),
                Text(T("● on"), GREEN) if c.enabled else Text(T("○ off"), "dim"),
            )
        self.keep_cursor(table, len(cfg.channels), cursor)
        self.query_one("#routes-value", Label).update(", ".join(cfg.tunnel.extra_routes) or "—")
        info = Text()
        for label, value in [
            (T("Endpoint"), f"{cfg.server.endpoint}:{cfg.server.port}/{cfg.server.protocol}"),
            (T("VPN network"), f"{cfg.server.network} · DNS {server_ip(cfg)}"),
            (T("Public interface"), cfg.server.interface or "—"),
        ]:
            info.append(f"{label:<24}", "dim")
            info.append(f"{value}\n")
        self.query_one("#server-info", Static).update(info)

    def selected_channel(self):
        channels = self.tg.ctx.cfg.channels
        row = self.query_one("#channels", DataTable).cursor_row
        return channels[row] if channels and 0 <= row < len(channels) else None

    def edit_channel(self, new: bool = False) -> None:
        channel = None if new else self.selected_channel()
        if not new and not channel:
            return
        ctx = self.tg.ctx

        def submit(data: dict):
            return ctx.save_channel(data["channel"])

        def done(result) -> None:
            if result:
                self.refresh_data()
                self.notify(T("{name} saved", name=result.name), title=T("✓ Notification channel saved"))

        self.app.push_screen(ChannelForm(submit, channel), done)

    async def toggle_channel(self) -> None:
        channel = self.selected_channel()
        if channel and await self.tg.run_op(self.tg.ctx.set_channel_enabled, channel.id, not channel.enabled) is not None:
            self.refresh_data()
            self.notify(f"{channel.name}: {T('on') if channel.enabled else T('off')}")

    def delete_channel(self) -> None:
        channel = self.selected_channel()
        if not channel:
            return

        async def done(confirmed: bool | None) -> None:
            if confirmed and await self.tg.run_op(self.tg.ctx.delete_channel, channel.id) is not None:
                self.refresh_data()
                self.notify(T("{name} deleted", name=channel.name), severity="warning")

        self.app.push_screen(ConfirmDialog(
            T("Delete channel"), T("Delete notification channel [b]{name}[/b]?", name=channel.name)), done)

    async def test_channels(self, only_selected: bool = False) -> None:
        from testops_gate.notify.send import DeliveryError, send
        from testops_gate.notify.testing import test_alert

        cfg = self.tg.ctx.cfg
        channels = [self.selected_channel()] if only_selected else [c for c in cfg.channels if c.enabled]
        channels = [c for c in channels if c]
        if not channels:
            self.notify(T("No enabled notification channels"), severity="warning")
            return
        results = []
        for channel in channels:
            try:
                await asyncio.to_thread(send, channel, test_alert(cfg))
                results.append(f"✓ {channel.name}")
            except DeliveryError as exc:
                results.append(f"✗ {channel.name}: {exc}")
        failed = any(r.startswith("✗") for r in results)
        self.notify("\n".join(results), title=T("Test notification sent"), severity="error" if failed else "information",
                    timeout=10)

    async def on_select_changed(self, event: Select.Changed) -> None:
        cfg = self.tg.ctx.cfg
        if event.select.id == "language" and event.value != cfg.language:
            if await self.tg.run_op(self.tg.ctx.set_language, str(event.value)) is not None:
                self.app.call_after_refresh(self.tg.rebuild)
        elif event.select.id == "upstream" and event.value != cfg.dns.upstream:
            if await self.tg.run_op(self.tg.ctx.set_upstream, str(event.value)) is not None:
                self.notify(T("DNS upstream: {value}", value=UPSTREAMS[str(event.value)][0]))
        elif event.select.id == "auth-mode" and event.value != cfg.auth.mode:
            self.change_auth_mode(str(event.value))

    def change_auth_mode(self, mode: str) -> None:
        ctx = self.tg.ctx
        label = dict((key, text) for text, key in auth_options())[mode]

        async def done(confirmed: bool | None) -> None:
            if not confirmed:
                self.query_one("#auth-mode", Select).value = ctx.cfg.auth.mode
                return
            created = await self.tg.run_op(ctx.set_auth_mode, mode)
            if created is None:
                self.query_one("#auth-mode", Select).value = ctx.cfg.auth.mode
                return
            if isinstance(created, dict) and created:
                self.app.push_screen(AccessDialog(T("✓ Sign-in: {mode}", mode=label), ctx.cfg, list(created.items())))
            else:
                self.notify(T("Every profile was renewed: send users their profile again."),
                            title=T("✓ Sign-in: {mode}", mode=label))

        self.app.push_screen(ConfirmDialog(T("Sign-in: {mode}", mode=label), T(
            "Change how users sign in to [b]{mode}[/b]?\n\n"
            "• Every .ovpn profile is renewed; users need their new profile\n"
            "• OpenVPN restarts and connected users reconnect\n"
            "• Passwords that are needed are generated and shown once",
            mode=label,
        ), confirm_label="Change"), done)

    async def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "update-check" and event.value != self.tg.ctx.cfg.updates.check:
            await self.tg.run_op(self.tg.ctx.set_update_check, event.value)
            return
        if event.switch.id == "dns-enforce" and event.value != self.tg.ctx.cfg.dns.enforce:
            if await self.tg.run_op(self.tg.ctx.set_dns_enforce, event.value) is not None:
                self.notify(T("Force VPN DNS: {state}", state=T("on") if event.value else T("off")))

    async def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        mode = "full" if event.pressed.id == "mode-full" else "split"
        if mode == self.tg.ctx.cfg.tunnel.mode:
            return
        if await self.tg.run_op(self.tg.ctx.set_tunnel_mode, mode) is not None:
            self.tg.tunnel_changed()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            await self.save_retention()
        elif event.button.id == "add-channel":
            self.edit_channel(new=True)
        elif event.button.id == "edit-routes":
            self.edit_routes()
        elif event.button.id == "test":
            await self.test_channels()
        elif event.button.id == "uninstall":
            self.uninstall()
        elif event.button.id == "update-check-now":
            await self.tg.check_updates(force=True)
        elif event.button.id == "update-run":
            self.run_update()

    def refresh_update_panel(self) -> None:
        state = self.tg.update_state
        info = Text()
        rows = [(T("Installed version"), __version__)]
        if state:
            checked = datetime.fromtimestamp(state.checked_at).strftime("%Y-%m-%d %H:%M") if state.checked_at else "—"
            latest = state.latest or "—"
            rows += [(T("Latest version"), latest), (T("Last check"), checked)]
        for label, value in rows:
            info.append(f"{label:<24}", "dim")
            info.append(f"{value}\n")
        if state and state.error:
            info.append(f"{T('Could not check for updates')}: {state.error}\n", RED)
        elif state and state.available:
            info.append(T("⬆ Version {version} is available", version=state.latest) + "\n", f"bold {GREEN}")
        elif state and state.latest:
            info.append(T("TestOps Gate is up to date") + "\n", "dim")
        self.query_one("#update-info", Static).update(info)
        button = self.query_one("#update-run", Button)
        button.disabled = not (state and state.available)
        button.label = T("Update to {version}", version=state.latest) if state and state.available else T("Update")

    def run_update(self) -> None:
        state = self.tg.update_state
        if not state or not state.available:
            return

        async def done(confirmed: bool | None) -> None:
            if not confirmed:
                return
            from testops_gate.core import update

            self.notify(T("Downloading and verifying {version}…", version=state.latest), timeout=15)
            command = await self.tg.run_op(update.prepare, self.tg.ctx.cfg, lambda line: None)
            if command:
                self.app.exit(("update", command))

        self.app.push_screen(ConfirmDialog(
            T("Update TestOps Gate"),
            T("Update from {current} to {latest}? The configuration and the database are backed up first; "
              "the dashboard reopens with the new version.", current=state.current, latest=state.latest),
            confirm_label="Update",
        ), done)

    def uninstall(self) -> None:
        def done(final) -> None:
            if final is not None:
                self.app.exit(("uninstalled", final))

        self.app.push_screen(UninstallDialog(self.tg.ctx.cfg.installed_packages), done)

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "retention":
            await self.save_retention()

    async def save_retention(self) -> None:
        try:
            days = int(self.query_one("#retention", Input).value)
        except ValueError:
            self.notify(T("Retention must be between 1 and 3650 days"), severity="error")
            return
        if await self.tg.run_op(self.tg.ctx.set_retention, days) is not None:
            self.notify(T("Logs are kept for {n} days", n=days), title=T("✓ Settings saved"))

    def edit_routes(self) -> None:
        ctx = self.tg.ctx

        def submit(data: dict):
            ctx.set_extra_routes(data["values"])
            return True

        def done(result) -> None:
            if result:
                self.refresh_data()
                self.notify(T("Split-mode routes are updated for users when they reconnect."))

        self.app.push_screen(ListForm(
            submit, T("Extra routes"), T("Networks routed via the VPN in split mode (CIDR, comma-separated)"),
            ctx.cfg.tunnel.extra_routes, "10.0.0.0/16, 172.20.0.0/24",
            T("Host records are routed automatically; add whole networks here."),
        ), done)

