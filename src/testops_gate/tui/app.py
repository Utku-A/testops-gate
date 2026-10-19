# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Terminal dashboard (`testops-gate`)."""

from __future__ import annotations

import asyncio
import os
import shlex
import sys
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.css.query import NoMatches
from textual.widgets import ContentSwitcher, Footer, Label, ListItem, ListView

from testops_gate import BRAND
from testops_gate import config as config_mod
from testops_gate.core.context import Context, ValidationError
from testops_gate.db import Alert, Host, LiveClient, User
from testops_gate.i18n import T, current_language, set_language
from testops_gate.system import netinfo, services
from testops_gate.tui.pages import DashboardPage, HostsPage, LogsPage, Page, SecurityPage, SettingsPage, UsersPage
from testops_gate.tui.theme import CSS, GITHUB_DARK
from testops_gate.tui.widgets import HelpScreen, all_dom_subclasses, localize_classes, localized_bindings
from testops_gate.tui.wizard import InstallScreen

NAV = [
    ("dashboard", "1", "Dashboard"),
    ("users", "2", "Users"),
    ("hosts", "3", "Hosts"),
    ("security", "4", "Security"),
    ("logs", "5", "Logs"),
    ("settings", "6", "Settings"),
]
TICK = 2.0
SERVICES_EVERY = 3  # ticks
THROUGHPUT_SAMPLES = 60


@dataclass
class Snapshot:
    users: list[User] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)  # last 24 h, newest first
    live: dict[str, LiveClient] = field(default_factory=dict)
    traffic: dict[str, tuple[int, int]] = field(default_factory=dict)  # today
    services: dict[str, bool] = field(default_factory=dict)
    throughput: deque = field(default_factory=lambda: deque(maxlen=THROUGHPUT_SAMPLES))  # bytes/s


class Shell(Vertical):
    """Everything except the footer; rebuilt when the language changes."""

    @property
    def tg(self) -> GateApp:
        return self.app  # type: ignore[return-value]

    def compose(self) -> ComposeResult:
        cfg = self.tg.ctx.cfg
        mode = cfg.tunnel.mode
        with Horizontal(id="topbar"):
            yield Label("◆ TestOps Gate", id="brand")
            yield Label(f"{cfg.server.endpoint} · {cfg.server.protocol}/{cfg.server.port}", id="server")
            yield Label("", id="spacer")
            yield Label("", id="update-badge")
            yield Label(f" {mode.upper()} ", id="mode-badge", classes="full" if mode == "full" else "")
            yield Label("", id="clock")
        with Horizontal(id="body"):
            with Vertical(id="sidebar"):
                yield ListView(
                    *[ListItem(Label(Text.assemble((f"{icon}  ", "dim"), T(title))), id=f"nav-{key}")
                      for key, icon, title in NAV],
                    initial_index=[k for k, _, _ in NAV].index(self.tg.page),
                    id="nav",
                )
                with Vertical(id="sidebar-bottom"):
                    yield Label(T("↑↓   move\n↵ →  open\nesc  menu\n1-6  jump\n?    help"), id="sidebar-help")
                    yield Label(Text.assemble(("⌕ ", "bold #58a6ff"), (f"{BRAND}™", "bold"), ("\ntestopscenter.com", "dim")),
                                id="sidebar-brand")
            with ContentSwitcher(id="content", initial=self.tg.page):
                yield DashboardPage(id="dashboard")
                yield UsersPage(id="users")
                yield HostsPage(id="hosts")
                yield SecurityPage(id="security")
                yield LogsPage(id="logs")
                yield SettingsPage(id="settings")


class GateApp(App):
    TITLE = "TestOps Gate"
    CSS = CSS
    BINDINGS = [
        Binding("escape", "focus_sidebar", "Menu", show=False),
        Binding("left", "focus_sidebar", show=False),
        Binding("right", "focus_content", show=False),
        *[Binding(str(i + 1), f"goto('{key}')", show=False) for i, (key, _, _) in enumerate(NAV)],
        Binding("question_mark", "help", "Help"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self, ctx: Context | None = None) -> None:
        super().__init__()
        self.ctx: Context | None = ctx
        self.page = "dashboard"
        self.snapshot = Snapshot()
        self._ticks = 0
        self._rebuilding = False
        self._config_mtime = 0.0
        self._ops = 0  # management operations running in threads
        self._last_bytes: tuple[float, int] | None = None
        self.update_state = None
        self.apply_language(ctx.cfg.language if ctx else current_language())

    # --- lifecycle -----------------------------------------------------------

    def compose(self) -> ComposeResult:
        if self.ctx:
            yield Shell()
        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(GITHUB_DARK)
        self.theme = "github-dark"
        if self.ctx is None:
            self.push_screen(InstallScreen(current_language()))
            return
        self.start()

    def start(self) -> None:
        self._config_mtime = self.config_mtime()
        self.refresh_snapshot(services_too=True)
        self.query_one("#nav", ListView).focus()
        self.update_clock()
        self.set_interval(TICK, self.tick)
        self.run_worker(self.check_updates(), exclusive=True, group="updates")

    async def check_updates(self, force: bool = False) -> None:
        """Ask for the latest release (cached for a day) and show the badge when one is newer."""
        from testops_gate.core import update

        announce = self.update_state is None
        self.update_state = await asyncio.to_thread(update.check, self.ctx.cfg, force)
        self.show_update_badge()
        state = self.update_state
        if state.available and (announce or force):
            self.notify(T("Version {version} is available. Settings → Updates", version=state.latest),
                        title=T("⬆ Update available"), timeout=10)
        elif force and not state.error:
            self.notify(T("TestOps Gate is up to date"))
        elif force and state.error:
            self.notify(state.error, title=T("✗ Could not check for updates"), severity="error")
        try:
            self.query_one(SettingsPage).refresh_update_panel()
        except NoMatches:
            pass

    def show_update_badge(self) -> None:
        try:
            badge = self.query_one("#update-badge", Label)
        except NoMatches:
            return
        state = self.update_state
        badge.update(f" ⬆ v{state.latest} " if state and state.available else "")
        badge.display = bool(state and state.available)

    def finish_install(self, ctx: Context) -> None:
        self.ctx = ctx
        self.apply_language(ctx.cfg.language)
        self.pop_screen()
        self.mount(Shell(), before=self.query_one(Footer))
        self.call_after_refresh(self.start)

    def restart_wizard(self, language: str) -> None:
        self.apply_language(language)
        self.pop_screen()
        self.push_screen(InstallScreen(language))

    # --- language ------------------------------------------------------------

    def pause_updates(self) -> None:
        """Stop the periodic refresh (used while uninstalling: the state is going away)."""
        self._rebuilding = True

    def apply_language(self, language: str) -> None:
        set_language(language)
        localize_classes(all_dom_subclasses())
        self._bindings = localized_bindings(type(self))

    async def rebuild(self) -> None:
        """Re-create the interface in the current language, keeping the open page."""
        self._rebuilding = True
        self.apply_language(self.ctx.cfg.language)
        await self.query_one(Shell).recompose()
        self._rebuilding = False
        self.update_clock()
        self.refresh_bindings()
        try:
            self.query_one("#language").focus()
        except NoMatches:
            pass
        self.notify(T("Interface language changed"))

    # --- data ----------------------------------------------------------------

    def config_mtime(self) -> float:
        from testops_gate.paths import P

        paths = (P.config_file, P.secrets_file)
        return max((p.stat().st_mtime for p in paths if p.exists()), default=0.0)

    def units(self) -> list[str]:
        units = list(services.CORE_UNITS)
        if self.ctx.cfg.security.category_enabled("ids"):
            units.append(services.SURICATA_UNIT)
        return units

    def refresh_snapshot(self, services_too: bool = False) -> None:
        store = self.ctx.store
        snap = self.snapshot
        snap.users = store.users()
        snap.hosts = store.hosts()
        snap.alerts = store.alerts(since=time.time() - 86400, limit=500)
        snap.live = store.live_clients()
        snap.traffic = store.traffic(date.today().isoformat())
        total = sum(c.rx + c.tx for c in snap.live.values())
        now = time.monotonic()
        if self._last_bytes:
            elapsed = now - self._last_bytes[0]
            if elapsed > 0:
                snap.throughput.append(max(total - self._last_bytes[1], 0) / elapsed)
        self._last_bytes = (now, total)
        if services_too:
            snap.services = services.is_active(self.units())
        self.refresh_pages()

    def refresh_pages(self) -> None:
        for page in self.query(Page):
            page.refresh_data()

    async def tick(self) -> None:
        if self._rebuilding or self.ctx is None:
            return
        self._ticks += 1
        mtime = self.config_mtime()
        # Changed by the CLI or another dashboard. Not while an operation runs: it is changing
        # ctx.cfg, and replacing the object under it would lose that change.
        if mtime != self._config_mtime and not self._ops:
            self._config_mtime = mtime
            self.ctx.cfg = config_mod.load()
        if self._ticks % SERVICES_EVERY == 0:
            self.snapshot.services = await asyncio.to_thread(services.is_active, self.units())
        try:
            self.update_clock()
            self.refresh_snapshot()
            self.query_one(LogsPage).tick()
        except NoMatches:
            pass

    def update_clock(self) -> None:
        fmt = "%d.%m.%Y  %H:%M:%S" if current_language() == "tr" else "%Y-%m-%d  %H:%M:%S"
        try:
            self.query_one("#clock", Label).update(time.strftime(fmt))
        except NoMatches:
            pass

    async def run_op(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run a management operation off the UI thread; errors become notifications.

        Returns the operation's result, True if it returned None, or None if it failed.
        """
        try:
            result = await self.run_in_thread(fn, *args, **kwargs)
        except (ValidationError, RuntimeError, OSError) as exc:  # RuntimeError includes CommandError
            self.notify(str(exc), title=T("✗ Failed"), severity="error", timeout=8)
            return None
        return True if result is None else result

    async def run_in_thread(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run a management operation in a thread; its own config writes are not taken for outside edits."""
        self._ops += 1
        try:
            return await asyncio.to_thread(fn, *args, **kwargs)
        finally:
            self._ops -= 1
            self._config_mtime = self.config_mtime()

    def tunnel_changed(self) -> None:
        mode = self.ctx.cfg.tunnel.mode
        badge = self.query_one("#mode-badge", Label)
        badge.update(f" {mode.upper()} ")
        badge.set_class(mode == "full", "full")
        self.refresh_snapshot()
        self.notify(T("Applied to connected users when they reconnect."), title=T("Tunnel mode: {mode}", mode=mode))

    # --- navigation ----------------------------------------------------------

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.list_view.id == "nav" and event.item and event.item.id:
            self.page = event.item.id.removeprefix("nav-")
            self.query_one("#content", ContentSwitcher).current = self.page

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "nav":
            self.action_focus_content()

    def current_page(self) -> Page:
        switcher = self.query_one("#content", ContentSwitcher)
        return switcher.query_one(f"#{switcher.current}", Page)

    def action_focus_content(self) -> None:
        try:
            if self.focused is self.query_one("#nav"):
                self.current_page().focus_default()
        except NoMatches:
            pass

    def action_focus_sidebar(self) -> None:
        try:
            self.query_one("#nav", ListView).focus()
        except NoMatches:
            pass

    def action_goto(self, key: str) -> None:
        try:
            nav = self.query_one("#nav", ListView)
        except NoMatches:
            return
        nav.index = [k for k, _, _ in NAV].index(key)
        self.page = key
        self.query_one("#content", ContentSwitcher).current = key
        self.call_after_refresh(self.current_page().focus_default)

    def action_help(self) -> None:
        self.push_screen(HelpScreen())


def run_tui() -> int:
    if not os.environ.get("TESTOPS_GATE_ROOT") and not netinfo.is_root():
        print(T("testops-gate must be run as root (sudo testops-gate)"), file=sys.stderr)
        return 1
    ctx = Context.open(reload=not os.environ.get("TESTOPS_GATE_ROOT")) if config_mod.exists() else None
    result = GateApp(ctx).run()
    if isinstance(result, tuple) and result[0] == "update":
        from testops_gate.core.install import run_final

        command = result[1]
        print(f"{T('Installing')}: {' '.join(command)}", flush=True)
        if not os.environ.get("TESTOPS_GATE_ROOT"):
            # install, then reopen the dashboard with the new version
            run_final(["sh", "-c", f"{shlex.join(command)} && exec testops-gate"])
        return 0
    if isinstance(result, tuple) and result[0] == "uninstalled":
        from testops_gate.core.install import run_final

        print(T("TestOps Gate removed"))
        final = result[1]
        if final:
            print(f"{T('Removing the testops-gate package')}: {' '.join(final)}", flush=True)
            if not os.environ.get("TESTOPS_GATE_ROOT"):
                run_final(final)
    return 0
