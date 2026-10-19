# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Shared dashboard widgets and dialogs."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from typing import Any

from rich.table import Table
from textual.app import ComposeResult
from textual.binding import Binding, BindingsMap
from textual.containers import Horizontal, Vertical
from textual.dom import DOMNode
from textual.screen import ModalScreen
from textual.widgets import Button, Digits, Label, Select, Static, Switch

from testops_gate.core.context import ValidationError
from testops_gate.i18n import T


def localized_bindings(cls: type[DOMNode]) -> BindingsMap:
    """The class's key bindings with descriptions translated to the current language."""
    bindings = BindingsMap()
    bindings.key_to_bindings = {
        key: [replace(b, description=T(b.description)) if b.description else b for b in group]
        for key, group in cls._merge_bindings().key_to_bindings.items()
    }
    return bindings


def localize_classes(classes: list[type[DOMNode]]) -> None:
    for cls in classes:
        cls._merged_bindings = localized_bindings(cls)


def all_dom_subclasses(base: type = DOMNode) -> list[type[DOMNode]]:
    """Every widget/screen class defined in testops_gate.tui (bindings to translate)."""
    found, stack = [], [base]
    while stack:
        cls = stack.pop()
        for sub in cls.__subclasses__():
            stack.append(sub)
            if sub.__module__.startswith("testops_gate.tui"):
                found.append(sub)
    return found


def panel(title: str, *, classes: str = "", **kwargs: Any) -> Vertical:
    container = Vertical(classes=f"panel {classes}".strip(), **kwargs)
    container.border_title = title
    return container


class FormSelect(Select):
    """In forms ↑↓ move between fields; the list opens with enter/space."""

    BINDINGS = [
        Binding("enter,space", "show_overlay", "Select", show=False),
        Binding("down", "app.focus_next", show=False),
        Binding("up", "app.focus_previous", show=False),
    ]


class StatCard(Vertical):
    def __init__(self, title: str, value: str, sub: str = "", *, digits: bool = True, id: str | None = None) -> None:
        super().__init__(id=id, classes="stat")
        self._title, self._value, self._sub, self._digits = title, value, sub, digits

    def compose(self) -> ComposeResult:
        yield Label(self._title, classes="stat-title")
        if self._digits:
            yield Digits(self._value, classes="stat-value")
        else:
            yield Label(self._value, classes="stat-text")
        yield Label(self._sub, classes="stat-sub")

    def set(self, value: str, sub: str | None = None) -> None:
        if self._digits:
            self.query_one(Digits).update(value)
        else:
            self.query_one(".stat-text", Label).update(value)
        if sub is not None:
            self.query_one(".stat-sub", Label).update(sub)


class ToggleRow(Horizontal):
    def __init__(self, key: str, title: str, desc: str, value: bool, *, master: bool = False,
                 disabled: bool = False) -> None:
        classes = "toggle-row master" if master else "toggle-row"
        if not value:
            classes += " -off"
        if disabled:
            classes += " -disabled"
        super().__init__(classes=classes)
        self.key, self._title, self._desc, self._value, self._disabled = key, title, desc, value, disabled

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Label(self._title, classes="t-title")
            yield Label(self._desc, classes="t-desc")
        yield Switch(self._value, id=f"sw-{self.key}", disabled=self._disabled)


class ConfirmDialog(ModalScreen[bool]):
    BINDINGS = [
        Binding("y", "answer(True)", "Yes"),
        Binding("n,escape", "answer(False)", "No"),
        Binding("left", "app.focus_previous", show=False),
        Binding("right", "app.focus_next", show=False),
    ]

    def __init__(self, title: str, message: str, confirm_label: str = "Yes, delete") -> None:
        super().__init__()
        self._title, self._message, self._confirm = title, message, confirm_label

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog") as dialog:
            dialog.border_title = self._title
            yield Static(self._message, classes="dialog-message")
            with Horizontal(classes="dialog-buttons"):
                yield Button(T("No"), id="no")
                yield Button(T(self._confirm), variant="error", id="yes")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_answer(self, value: bool) -> None:
        self.dismiss(value)


class FormScreen(ModalScreen[Any]):
    """Modal form: ↑↓ move between fields, ctrl+s saves, esc cancels.

    `submit` receives the collected values and does the work in a thread; a
    ValidationError or failed command is shown inside the form.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("ctrl+s", "save", "Save"),
        Binding("down", "app.focus_next", show=False),
        Binding("up", "app.focus_previous", show=False),
    ]

    def __init__(self, submit: Callable[[dict], Any]) -> None:
        super().__init__()
        self.submit = submit
        self.busy = False

    def buttons(self) -> Horizontal:
        return Horizontal(
            Button(T("Cancel"), id="cancel"),
            Button(T("Save  ^S"), variant="primary", id="save"),
            classes="dialog-buttons",
        )

    def collect(self) -> dict:
        raise NotImplementedError

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save":
            await self.action_save()
        else:
            self.action_cancel()

    async def on_input_submitted(self) -> None:
        await self.action_save()

    def action_cancel(self) -> None:
        if not self.busy:
            self.dismiss(None)

    async def action_save(self) -> None:
        if self.busy:
            return
        try:
            data = self.collect()
        except ValidationError as exc:
            self.show_error(str(exc))
            return
        self.busy = True
        self.show_error("")
        try:
            result = await self.app.run_in_thread(self.submit, data)
        except (ValidationError, RuntimeError, OSError) as exc:  # RuntimeError includes CommandError
            self.show_error(str(exc))
            return
        finally:
            self.busy = False
        self.dismiss(result if result is not None else True)

    def show_error(self, message: str) -> None:
        self.query_one("#f-error", Label).update(f"✗ {message}" if message else "")


class HelpScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,question_mark,q", "app.pop_screen", "Close")]

    def compose(self) -> ComposeResult:
        table = Table.grid(padding=(0, 3))
        table.add_column(style="bold #39c5cf")
        table.add_column()
        rows = [
            ("↑ ↓", "Move in menu / list"),
            ("enter · →", "Open selected section"),
            ("esc · ←", "Back to menu"),
            ("1 – 6", "Jump to section"),
            ("tab", "Next field"),
            ("a · e · x", "Add · edit · delete"),
            ("space", "Toggle on / off"),
            ("/", "Search"),
            ("ctrl+p", "Command palette (incl. theme)"),
            ("q", "Quit"),
        ]
        for key, desc in rows:
            table.add_row(key, T(desc))
        with Vertical(classes="dialog") as dialog:
            dialog.border_title = T("Keyboard shortcuts")
            yield Static(table)
