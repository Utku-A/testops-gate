# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Modal forms for users, hosts, notification channels and lists."""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Callable
from typing import Any

from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, RichLog, Select, Static, Switch

from testops_gate.config import Channel, Config
from testops_gate.core import access
from testops_gate.core.context import ValidationError
from testops_gate.db import Host, User
from testops_gate.i18n import T
from testops_gate.system.runner import CommandError
from testops_gate.tui.widgets import FormScreen, FormSelect


def auth_options() -> list[tuple[str, str]]:
    return [(T("Username + password"), "user-password"), (T("Profile password"), "profile-password"),
            (T("Certificate only"), "certificate")]


def severity_options() -> list[tuple[str, str]]:
    return [(T("▲ high and above"), "high"), (T("■ medium and above"), "medium"), (T("● all (incl. low)"), "low")]


def _int(value: str, label: str) -> int:
    try:
        return int(value)
    except ValueError:
        raise ValidationError(T("{field} must be a number", field=label)) from None


class UserForm(FormScreen):
    def __init__(self, submit: Callable[[dict], Any], user: User | None = None, ask_password: bool = False) -> None:
        super().__init__(submit)
        self.user = user
        self.ask_password = ask_password and user is None

    def compose(self) -> ComposeResult:
        u = self.user
        with Vertical(classes="dialog") as dialog:
            dialog.border_title = T("Edit user · {name}", name=u.name) if u else T("New VPN user")
            yield Label(T("Username"), classes="field-label")
            yield Input(u.name if u else "", placeholder=T("e.g. alice"), restrict=r"[a-zA-Z0-9_-]*",
                        max_length=32, disabled=u is not None, id="f-name")
            yield Label(T("Email"), classes="field-label")
            yield Input(u.email if u else "", placeholder="alice@example.com", id="f-email")
            yield Label(T("Tunnel mode"), classes="field-label")
            yield FormSelect(
                [(T("Default (global setting)"), "default"), (T("split · defined hosts only"), "split"),
                 (T("full · all traffic"), "full")],
                value=u.mode if u else "default", allow_blank=False, id="f-mode",
            )
            yield Label(T("VPN address"), classes="field-label")
            yield Input(u.vpn_ip if u else "", placeholder=T("automatic"), id="f-ip")
            if u is None:
                yield Label(T("Certificate validity"), classes="field-label")
                yield FormSelect([(T("1 year"), "365"), (T("2 years"), "730"), (T("5 years"), "1825")],
                                 value="365", allow_blank=False, id="f-days")
                if self.ask_password:
                    yield Label(T("Password"), classes="field-label")
                    yield Input(password=True, placeholder=T("empty: generate a strong password"), id="f-password")
            else:
                yield Label(T("Changes apply when the user reconnects."), classes="hint")
            yield Label("", id="f-error")
            yield self.buttons()

    def collect(self) -> dict:
        data = {
            "name": self.query_one("#f-name", Input).value.strip(),
            "email": self.query_one("#f-email", Input).value.strip(),
            "mode": self.query_one("#f-mode", Select).value,
            "vpn_ip": self.query_one("#f-ip", Input).value.strip(),
        }
        if not data["name"]:
            raise ValidationError(T("Username cannot be empty"))
        if self.user is None:
            data["days"] = int(self.query_one("#f-days", Select).value)
        if self.ask_password:
            data["password"] = self.query_one("#f-password", Input).value or None
        return data


class PasswordForm(FormScreen):
    def __init__(self, submit: Callable[[dict], Any], name: str, profile_password: bool) -> None:
        super().__init__(submit)
        self._name, self._profile_password = name, profile_password

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog") as dialog:
            dialog.border_title = T("New password · {name}", name=self._name)
            yield Label(T("Password"), classes="field-label")
            yield Input(password=True, placeholder=T("empty: generate a strong password"), id="f-password")
            yield Label(T("A new profile is created; send it to the user.") if self._profile_password
                        else T("The user's current session is closed."), classes="hint")
            yield Label("", id="f-error")
            yield self.buttons()

    def collect(self) -> dict:
        return {"password": self.query_one("#f-password", Input).value or None}


class AccessDialog(ModalScreen[None]):
    """What to hand a user, shown once after a user or password was created.

    `users` holds (name, password) pairs; one user gets the full details (profile path,
    how to download it), several get a name/password list.
    """

    BINDINGS = [Binding("escape", "close", "Close")]

    def __init__(self, title: str, cfg: Config, users: list[tuple[str, str]]) -> None:
        super().__init__()
        self._title, self._cfg, self._users = title, cfg, users

    def compose(self) -> ComposeResult:
        cfg = self._cfg
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="#8b949e", no_wrap=True)
        grid.add_column()
        secret = access.password_label(cfg)
        if len(self._users) == 1:
            name, password = self._users[0]
            for label, value in access.details(cfg, name, password):
                grid.add_row(label, Text(value, style="bold #3fb950") if label == secret else value)
        else:
            for name, password in self._users:
                grid.add_row(name, Text(password, style="bold #3fb950"))
            grid.add_row(T("Profiles"), str(access.profile_path("*")))
        with Vertical(classes="dialog wide") as dialog:
            dialog.border_title = self._title
            yield Static(grid, id="access-details")
            if any(password for _, password in self._users):
                yield Label(access.password_note(cfg), classes="hint")
            yield Label(access.connect_hint(cfg), classes="hint")
            with Horizontal(classes="dialog-buttons"):
                yield Button(T("Close"), variant="primary", id="close")

    def on_mount(self) -> None:
        self.query_one("#close", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(None)

    def action_close(self) -> None:
        self.dismiss(None)


class HostForm(FormScreen):
    def __init__(self, submit: Callable[[dict], Any], host: Host | None = None) -> None:
        super().__init__(submit)
        self.host = host

    def compose(self) -> ComposeResult:
        h = self.host
        with Vertical(classes="dialog") as dialog:
            dialog.border_title = T("Edit host · {name}", name=h.name) if h else T("New host record")
            yield Label(T("Domain"), classes="field-label")
            yield Input(h.name if h else "", placeholder="stage.internal  ·  *.preview.internal", id="f-name")
            yield Label(T("Record type"), classes="field-label")
            yield FormSelect([(T("A · IPv4 address"), "A"), (T("CNAME · another domain"), "CNAME")],
                             value=h.rtype if h else "A", allow_blank=False, id="f-type")
            yield Label(T("Target"), classes="field-label")
            yield Input(h.value if h else "", placeholder="10.0.5.20", id="f-value")
            yield Label(T("Note"), classes="field-label")
            yield Input(h.note if h else "", placeholder=T("Staging web server"), id="f-note")
            yield Label(T("In split mode a route to the target IP is pushed to clients automatically."), classes="hint")
            yield Label("", id="f-error")
            yield self.buttons()

    def collect(self) -> dict:
        return {
            "name": self.query_one("#f-name", Input).value,
            "rtype": self.query_one("#f-type", Select).value,
            "value": self.query_one("#f-value", Input).value,
            "note": self.query_one("#f-note", Input).value,
            "old_name": self.host.name if self.host else None,
        }


class ChannelForm(FormScreen):
    def __init__(self, submit: Callable[[dict], Any], channel: Channel | None = None) -> None:
        super().__init__(submit)
        self.channel = channel

    def compose(self) -> ComposeResult:
        c = self.channel or Channel(id="", kind="slack", name="")
        with VerticalScroll(classes="dialog wide") as dialog:
            dialog.can_focus = False
            dialog.border_title = T("Edit channel · {name}", name=c.name) if self.channel else T("New notification channel")
            yield Label(T("Channel type"), classes="field-label")
            yield FormSelect([("Slack", "slack"), (T("Email (SMTP)"), "email")], value=c.kind, allow_blank=False,
                             id="f-kind")

            with Vertical(id="slack-fields", classes="field-group"):
                yield Label(T("Display name"), classes="field-label")
                yield Input(c.name if c.kind == "slack" else "", placeholder="#vpn-alerts", id="f-slack-name")
                yield Label("Incoming webhook URL", classes="field-label")
                yield Input(c.webhook, placeholder="https://hooks.slack.com/services/…", password=bool(c.webhook),
                            id="f-webhook")

            with Vertical(id="email-fields", classes="field-group"):
                with Horizontal(classes="row"):
                    with Vertical():
                        yield Label(T("Channel name"), classes="field-label")
                        yield Input(c.name if c.kind == "email" else "", placeholder=T("Ops team"), id="f-email-name")
                    with Vertical():
                        yield Label(T("Recipients (comma-separated)"), classes="field-label")
                        yield Input(", ".join(c.recipients), placeholder="ops@example.com, sec@example.com",
                                    id="f-recipients")
                with Horizontal(classes="row"):
                    with Vertical():
                        yield Label(T("SMTP server"), classes="field-label")
                        yield Input(c.smtp_host, placeholder="smtp.example.com", id="f-smtp-host")
                    with Vertical(classes="narrow"):
                        yield Label("Port", classes="field-label")
                        yield Input(str(c.smtp_port), type="integer", id="f-smtp-port")
                    with Vertical():
                        yield Label(T("Security"), classes="field-label")
                        yield FormSelect([("STARTTLS", "starttls"), ("SSL/TLS", "ssl"), (T("None"), "none")],
                                         value=c.smtp_security, allow_blank=False, id="f-smtp-security")
                with Horizontal(classes="row"):
                    with Vertical():
                        yield Label(T("Username"), classes="field-label")
                        yield Input(c.smtp_user, placeholder="vpn@example.com", id="f-smtp-user")
                    with Vertical():
                        yield Label(T("Password"), classes="field-label")
                        yield Input(c.smtp_password, password=True, id="f-smtp-password")
                yield Label(T("Sender"), classes="field-label")
                yield Input(c.sender, placeholder="testops-gate <vpn@example.com>", id="f-sender")

            with Horizontal(classes="row"):
                with Vertical():
                    yield Label(T("Minimum severity"), classes="field-label")
                    yield FormSelect(severity_options(), value=c.min_severity, allow_blank=False, id="f-severity")
                with Vertical(classes="narrow"):
                    yield Label(T("Mute (min)"), classes="field-label")
                    yield Input(str(c.mute_minutes), type="integer", id="f-mute")
            yield Label(T("Webhook and SMTP password are stored in /etc/testops-gate/secrets.yaml (0600)."),
                        classes="hint")
            yield Label("", id="f-error")
            yield self.buttons()

    def on_mount(self) -> None:
        self.show_fields(self.query_one("#f-kind", Select).value)
        self.query_one("#f-kind").focus()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "f-kind":
            self.show_fields(event.value)

    def show_fields(self, kind: object) -> None:
        self.query_one("#slack-fields").display = kind == "slack"
        self.query_one("#email-fields").display = kind == "email"

    def value(self, selector: str) -> str:
        return self.query_one(selector, Input).value.strip()

    def collect(self) -> dict:
        base = self.channel or Channel(id="", kind="slack", name="")
        channel = dataclasses.replace(base)
        channel.kind = str(self.query_one("#f-kind", Select).value)
        channel.min_severity = str(self.query_one("#f-severity", Select).value)
        channel.mute_minutes = _int(self.value("#f-mute") or "0", T("Mute (min)"))
        if channel.kind == "slack":
            channel.name = self.value("#f-slack-name") or "#slack"
            channel.webhook = self.value("#f-webhook")
        else:
            channel.name = self.value("#f-email-name") or T("Email")
            channel.recipients = [r.strip() for r in self.value("#f-recipients").split(",") if r.strip()]
            channel.smtp_host = self.value("#f-smtp-host")
            channel.smtp_port = _int(self.value("#f-smtp-port") or "0", "Port")
            channel.smtp_security = str(self.query_one("#f-smtp-security", Select).value)
            channel.smtp_user = self.value("#f-smtp-user")
            channel.smtp_password = self.query_one("#f-smtp-password", Input).value
            channel.sender = self.value("#f-sender")
        return {"channel": channel}


class ListForm(FormScreen):
    """Edit a comma-separated list (blocked networks, forbidden ports, extra routes)."""

    def __init__(self, submit: Callable[[dict], Any], title: str, label: str, values: list[str],
                 placeholder: str, hint: str) -> None:
        super().__init__(submit)
        self._title, self._label, self._values, self._placeholder, self._hint = title, label, values, placeholder, hint

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide") as dialog:
            dialog.border_title = self._title
            yield Label(self._label, classes="field-label")
            yield Input(", ".join(self._values), placeholder=self._placeholder, id="f-values")
            yield Label(self._hint, classes="hint")
            yield Label("", id="f-error")
            yield self.buttons()

    def collect(self) -> dict:
        raw = self.query_one("#f-values", Input).value
        return {"values": [v.strip() for v in raw.split(",") if v.strip()]}


class ExportForm(FormScreen):
    def __init__(self, submit: Callable[[dict], Any], name: str, default_dir: str) -> None:
        super().__init__(submit)
        self._name, self._dir = name, default_dir

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide") as dialog:
            dialog.border_title = T("Export profile · {name}", name=self._name)
            yield Label(T("Save to (file or directory)"), classes="field-label")
            yield Input(self._dir, id="f-path")
            yield Label(T("Or on the server: sudo testops-gate user export {name} > {name}.ovpn", name=self._name),
                        classes="hint")
            yield Label("", id="f-error")
            yield self.buttons()

    def collect(self) -> dict:
        path = self.query_one("#f-path", Input).value.strip()
        if not path:
            raise ValidationError(T("Enter a path"))
        return {"path": path}


class UninstallDialog(ModalScreen[list[str] | None]):
    """Confirm and run `uninstall`; dismisses with the final package removal command."""

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("down", "app.focus_next", show=False),
        Binding("up", "app.focus_previous", show=False),
    ]

    def __init__(self, packages: list[str]) -> None:
        super().__init__()
        self.packages = packages
        self.running = False

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide") as dialog:
            dialog.border_title = T("Uninstall TestOps Gate")
            yield Static(T("Stops the VPN and removes its configuration and firewall rules. "
                           "Connected users are disconnected."), classes="dialog-message")
            with Horizontal(classes="switch-row"):
                yield Label(T("Also delete certificates, users, state and logs"))
                yield Switch(True, id="u-purge")
            with Horizontal(classes="switch-row"):
                yield Label(T("Also remove installed packages ({packages}) and TestOps Gate itself",
                              packages=", ".join(self.packages) or T("dependencies only")))
                yield Switch(True, id="u-packages")
            yield Label(T("Type {word} to confirm", word=T("uninstall")), classes="field-label")
            yield Input(id="u-confirm")
            yield RichLog(id="u-log", wrap=True)
            yield Label("", id="f-error")
            with Horizontal(classes="dialog-buttons"):
                yield Button(T("Cancel"), id="cancel")
                yield Button(T("Uninstall"), variant="error", id="u-run", disabled=True)

    def on_mount(self) -> None:
        self.query_one("#u-log").display = False
        self.query_one("#u-purge").focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self.query_one("#u-run", Button).disabled = event.value.strip().lower() != T("uninstall").lower()

    async def on_input_submitted(self) -> None:
        if not self.query_one("#u-run", Button).disabled:
            await self.run_uninstall()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "u-run":
            await self.run_uninstall()
        else:
            self.action_cancel()

    def action_cancel(self) -> None:
        if not self.running:
            self.dismiss(None)

    async def run_uninstall(self) -> None:
        if self.running:
            return
        from testops_gate.core.install import uninstall

        self.running = True
        self.app.pause_updates()  # type: ignore[attr-defined]
        purge = self.query_one("#u-purge", Switch).value
        packages = self.query_one("#u-packages", Switch).value
        for widget_id in ("#u-purge", "#u-packages", "#u-confirm", "#u-run", "#cancel"):
            self.query_one(widget_id).disabled = True
        log = self.query_one("#u-log", RichLog)
        log.display = True

        def progress(line: str) -> None:
            self.app.call_from_thread(log.write, f"• {line}")

        try:
            final = await asyncio.to_thread(uninstall, purge, packages, progress)
        except (CommandError, OSError) as exc:
            self.query_one("#f-error", Label).update(f"✗ {exc}")
            self.query_one("#cancel").disabled = False
            self.running = False
            return
        log.write(f"[bold green]✓ {T('TestOps Gate removed')}[/]")
        await asyncio.sleep(1.5)
        self.dismiss(final)


class RepairDialog(ModalScreen[bool]):
    """Diagnose the services and, on request, repair them; dismisses True if something was repaired."""

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("left", "app.focus_previous", show=False),
        Binding("right", "app.focus_next", show=False),
    ]

    def __init__(self, ctx) -> None:
        super().__init__()
        self.ctx = ctx
        self.running = False
        self.repaired = False

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide") as dialog:
            dialog.border_title = T("Diagnose and repair")
            yield Static(T("Checking…"), id="r-findings")
            yield RichLog(id="r-log", wrap=True)
            yield Label(T("Repair reinstalls missing packages, regenerates the configuration and restarts the "
                          "services. Users, certificates and settings are kept."), classes="hint")
            with Horizontal(classes="dialog-buttons"):
                yield Button(T("Close"), id="close")
                yield Button(T("Repair"), variant="warning", id="r-run", disabled=True)

    async def on_mount(self) -> None:
        self.query_one("#r-log").display = False
        self.query_one("#close", Button).focus()
        from testops_gate.core import doctor

        self.show(await asyncio.to_thread(doctor.diagnose, self.ctx.cfg))
        self.query_one("#r-run", Button).disabled = False

    def show(self, findings) -> None:
        text = Text()
        for i, f in enumerate(findings):
            if i:
                text.append("\n")
            text.append("✓ " if f.ok else "✗ ", "bold #3fb950" if f.ok else "bold #f85149")
            text.append(f.title, "" if f.ok else "bold")
            for line in f.detail.splitlines():
                text.append(f"\n    {line}", "#8b949e")
        self.query_one("#r-findings", Static).update(text)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "r-run":
            await self.run_repair()
        else:
            self.action_close()

    def action_close(self) -> None:
        if not self.running:
            self.dismiss(self.repaired)

    async def run_repair(self) -> None:
        if self.running:
            return
        from testops_gate.core import doctor

        self.running = True
        for widget_id in ("#r-run", "#close"):
            self.query_one(widget_id).disabled = True
        log = self.query_one("#r-log", RichLog)
        log.clear()
        log.display = True

        def progress(line: str) -> None:
            self.app.call_from_thread(log.write, f"• {line}")

        try:
            findings = await self.app.run_in_thread(doctor.repair, self.ctx, progress)  # type: ignore[attr-defined]
        except (ValidationError, CommandError, OSError) as exc:
            log.write(f"[bold red]✗ {exc}[/]")
        else:
            self.show(findings)
            self.repaired = True
        self.running = False
        self.query_one("#close", Button).disabled = False
        self.query_one("#r-run", Button).disabled = False
        self.query_one("#close", Button).focus()
