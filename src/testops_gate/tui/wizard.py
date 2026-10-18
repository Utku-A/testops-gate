# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""First-run installation wizard."""

from __future__ import annotations

import asyncio

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Input, Label, RichLog, Select, Static, Switch

from testops_gate.config import UPSTREAMS
from testops_gate.core.context import ValidationError
from testops_gate.core.install import IDS_MIN_MEMORY_MB, InstallOptions, install, preflight
from testops_gate.i18n import LANGUAGES, T
from testops_gate.system import netinfo
from testops_gate.system.runner import CommandError
from testops_gate.tui.widgets import FormSelect


class InstallScreen(Screen):
    BINDINGS = [
        Binding("ctrl+s", "install", "Install"),
        Binding("down", "app.focus_next", show=False),
        Binding("up", "app.focus_previous", show=False),
        Binding("ctrl+q", "app.quit", "Quit"),
    ]

    def __init__(self, language: str = "en") -> None:
        super().__init__()
        self.language = language
        self.running = False
        self.problems = preflight()

    def compose(self) -> ComposeResult:
        memory = netinfo.total_memory_mb()
        with VerticalScroll(id="wizard"):
            yield Label(T("◆ TestOps Gate · installation"), id="wizard-title")
            yield Label(T("Set up the OpenVPN server, internal DNS and security monitoring on this machine."),
                        classes="hint")
            if self.problems:
                yield Static("\n".join(f"✗ {p}" for p in self.problems), id="wizard-problems")
            with Vertical(id="wizard-form"):
                with Horizontal(classes="row"):
                    with Vertical():
                        yield Label(T("Interface language"), classes="field-label")
                        yield FormSelect(LANGUAGES, value=self.language, allow_blank=False, id="w-language")
                    with Vertical():
                        yield Label(T("Public address clients connect to"), classes="field-label")
                        yield Input(placeholder=T("detecting…"), id="w-endpoint")
                with Horizontal(classes="row"):
                    with Vertical(classes="narrow"):
                        yield Label("Port", classes="field-label")
                        yield Input("1194", type="integer", id="w-port")
                    with Vertical():
                        yield Label(T("Protocol"), classes="field-label")
                        yield FormSelect([(T("UDP (recommended)"), "udp"), ("TCP", "tcp")], value="udp",
                                         allow_blank=False, id="w-protocol")
                    with Vertical():
                        yield Label(T("Tunnel mode"), classes="field-label")
                        yield FormSelect([(T("split · defined hosts only"), "split"), (T("full · all traffic"), "full")],
                                         value="split", allow_blank=False, id="w-mode")
                with Horizontal(classes="row"):
                    with Vertical():
                        yield Label(T("Upstream resolver"), classes="field-label")
                        yield FormSelect([(label, key) for key, (label, _) in UPSTREAMS.items()], value="cloudflare",
                                         allow_blank=False, id="w-dns")
                    with Vertical():
                        yield Label(T("First user (optional)"), classes="field-label")
                        yield Input(placeholder=T("e.g. alice"), restrict=r"[a-zA-Z0-9_-]*", max_length=32,
                                    id="w-user")
                with Horizontal(classes="switch-row"):
                    yield Label(T("Security monitoring"))
                    yield Switch(True, id="w-security")
                with Horizontal(classes="switch-row"):
                    hint = "" if not memory or memory >= IDS_MIN_MEMORY_MB else T(" · less than 2 GB RAM")
                    yield Label(T("Suricata IDS (attack signatures, ~400 MB RAM)") + hint)
                    yield Switch(memory == 0 or memory >= IDS_MIN_MEMORY_MB, id="w-ids")
                yield Label("", id="f-error")
                with Horizontal(classes="dialog-buttons"):
                    yield Button(T("Install  ^S"), variant="primary", id="w-install", disabled=bool(self.problems))
            yield RichLog(id="wizard-log", wrap=True)
        yield Footer()

    async def on_mount(self) -> None:
        self.query_one("#w-endpoint").focus()
        endpoint = await asyncio.to_thread(netinfo.suggest_endpoint)
        field = self.query_one("#w-endpoint", Input)
        if not field.value:
            field.value = endpoint
        field.placeholder = "vpn.example.com"

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "w-language" and event.value != self.language:
            self.app.call_after_refresh(self.app.restart_wizard, str(event.value))  # type: ignore[attr-defined]

    def on_switch_changed(self, event: Switch.Changed) -> None:
        if event.switch.id == "w-security":
            self.query_one("#w-ids", Switch).disabled = not event.value

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "w-install":
            await self.action_install()

    def options(self) -> InstallOptions:
        try:
            port = int(self.query_one("#w-port", Input).value)
        except ValueError:
            raise ValidationError(T("Port must be between 1 and 65535")) from None
        security = self.query_one("#w-security", Switch).value
        return InstallOptions(
            endpoint=self.query_one("#w-endpoint", Input).value.strip(),
            port=port,
            protocol=str(self.query_one("#w-protocol", Select).value),
            tunnel_mode=str(self.query_one("#w-mode", Select).value),
            upstream=str(self.query_one("#w-dns", Select).value),
            language=self.language,
            security=security,
            ids=security and self.query_one("#w-ids", Switch).value,
            first_user=self.query_one("#w-user", Input).value.strip(),
        )

    async def action_install(self) -> None:
        if self.running or self.problems:
            return
        error = self.query_one("#f-error", Label)
        try:
            opts = self.options()
            from testops_gate.core.install import validate

            validate(opts)
        except ValidationError as exc:
            error.update(f"✗ {exc}")
            return
        error.update("")
        self.running = True
        self.query_one("#w-install", Button).disabled = True
        log = self.query_one("#wizard-log", RichLog)
        log.focus()

        def progress(line: str) -> None:
            self.app.call_from_thread(log.write, f"• {line}")

        try:
            ctx = await asyncio.to_thread(install, opts, progress)
        except (ValidationError, CommandError, OSError) as exc:
            log.write(f"[bold red]✗ {exc}[/]")
            self.running = False
            self.query_one("#w-install", Button).disabled = False
            return
        log.write(f"[bold green]✓ {T('Installation complete')}[/]")
        await asyncio.sleep(1.5)
        self.app.finish_install(ctx)  # type: ignore[attr-defined]
