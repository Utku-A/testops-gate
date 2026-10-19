# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""GitHub Dark theme and the dashboard stylesheet."""

from textual.theme import Theme

# VS Code "GitHub Dark Default" palette
GITHUB_DARK = Theme(
    name="github-dark",
    dark=True,
    primary="#2f81f7",
    secondary="#bc8cff",
    accent="#58a6ff",
    foreground="#e6edf3",
    background="#0d1117",
    surface="#0d1117",
    panel="#010409",
    boost="#161b22",
    success="#3fb950",
    warning="#d29922",
    error="#f85149",
    variables={
        "border": "#1f6feb",  # focused field
        "border-blurred": "#30363d",  # regular border
        "text-muted": "#7d8590",
        "block-cursor-background": "#1f6feb",
        "block-cursor-foreground": "#ffffff",
        "block-cursor-blurred-background": "#1f6feb40",
        "block-hover-background": "#161b22",
        "footer-background": "#010409",
        "footer-key-foreground": "#58a6ff",
        "footer-description-foreground": "#7d8590",
        "input-selection-background": "#1f6feb66",
        "input-cursor-background": "#e6edf3",
        "scrollbar": "#30363d",
        "scrollbar-hover": "#484f58",
        "scrollbar-active": "#6e7681",
        "scrollbar-background": "#0d1117",
        "scrollbar-corner-color": "#0d1117",
        "datatable--header-background": "#161b22",
    },
)

# Text colours used in Rich renderables (same palette)
GREEN, RED, YELLOW, BLUE, CYAN, PURPLE = "#3fb950", "#f85149", "#d29922", "#58a6ff", "#39c5cf", "#bc8cff"
KIND_STYLE = {"SESSION": f"bold {CYAN}", "DNS": PURPLE, "CONN": BLUE, "SECURITY": f"bold {RED}", "AUDIT": YELLOW}
SEVERITY_STYLE = {"high": f"bold {RED}", "medium": YELLOW, "low": BLUE}

CSS = """
Screen { background: $background; }
Shell { height: 1fr; }

/* Top bar */
#topbar { dock: top; height: 1; background: $panel; padding: 0 1; color: $text-muted; }
#brand { color: $accent; text-style: bold; padding-right: 2; }
#server { color: $text-muted; }
#spacer { width: 1fr; }
#mode-badge { background: $success; color: $background; text-style: bold; margin-right: 2; }
#mode-badge.full { background: $warning; }
#update-run { width: auto; min-width: 16; }
#update-badge { background: $primary; color: #ffffff; text-style: bold; margin-right: 2; display: none; }
#clock { color: $text-muted; }

/* Sidebar */
#body { height: 1fr; }
#sidebar { width: 24; background: $panel; padding: 1 0; border-right: solid $border-blurred; }
#nav { background: transparent; height: auto; }
#nav > ListItem { height: 1; margin-bottom: 1; padding: 0 1; background: transparent; border-left: tall $panel; }
#nav > ListItem.-highlight { background: $boost; border-left: tall $border-blurred; }
#nav:focus > ListItem.-highlight { background: $primary 20%; border-left: tall $primary; text-style: bold; }
#sidebar-bottom { dock: bottom; height: auto; }
#sidebar-help { color: $text-muted; padding: 0 2; }
#sidebar-brand { margin-top: 1; padding: 1 2 0 2; border-top: solid $border-blurred; height: auto; }

/* Content */
#content { width: 1fr; padding: 1 2 0 2; }
.page-title { text-style: bold; height: 1; margin-bottom: 1; }
.panel {
    border: round $border-blurred; border-title-color: $text-muted; border-title-style: bold;
    border-subtitle-color: $text-muted; padding: 0 1; height: 1fr; background: $surface;
}
.panel:focus-within { border: round $primary; border-title-color: $accent; }
.panel DataTable { height: 1fr; background: $surface; }
.hint { color: $text-muted; }

/* Dashboard */
#stats { height: 7; margin-bottom: 1; }
.stat { width: 1fr; height: 7; border: round $border-blurred; background: $surface; padding: 0 2; margin-right: 1; }
#st-mode { margin-right: 0; }
.stat-title { color: $text-muted; text-style: bold; }
.stat-value { color: $accent; width: auto; }
.stat-text { color: $success; text-style: bold; height: 3; content-align: left middle; }
#st-mode.full .stat-text { color: $warning; }
.stat-sub { color: $text-muted; }
#dash-body { height: 1fr; }
#dash-left { width: 1fr; margin-right: 1; }
#dash-right { width: 48; }
#p-services { height: auto; }
#p-traffic { height: 5; }
#spark { height: 1fr; }
#spark > .sparkline--max-color { color: $accent; }
#spark > .sparkline--min-color { color: $primary 50%; }

/* Users */
.toolbar { height: 3; margin-bottom: 0; }
.toolbar .page-title { width: 1fr; height: 3; content-align: left middle; margin: 0; }
#user-search { width: 40; }

/* Security */
#sec-body { height: 1fr; }
#sec-left { width: 5fr; margin-right: 1; }
#toggles { height: 1fr; }
#sec-lists { height: auto; margin-top: 1; }
#sec-alerts { width: 6fr; }
.toggle-row { height: 3; padding: 0 1; }
.toggle-row > Vertical { width: 1fr; }
.toggle-row .t-title { text-style: bold; }
.toggle-row .t-desc { color: $text-muted; }
.toggle-row:focus-within { background: $primary 20%; }
.toggle-row.-off .t-title, .toggle-row.-disabled .t-title { color: $text-muted; text-style: none; }
.toggle-row.master { height: 4; border-bottom: solid $border-blurred; margin-bottom: 1; }
.toggle-row.master .t-title { color: $accent; }

/* Logs */
#log-body { height: 1fr; }
#log-users { width: 26; margin-right: 1; }
#log-users-list { height: 1fr; border: none; background: $surface; padding: 0; }
#log-view { width: 1fr; }
#log { height: 1fr; background: $surface; }

/* Settings */
#settings-form { height: 1fr; }
.settings-panel { height: auto; margin-bottom: 1; padding: 0 2 1 2; }
.field { height: 3; }
.field-name { width: 26; height: 3; content-align: left middle; color: $text-muted; }
.field-value { height: 3; content-align: left middle; width: 1fr; }
#retention, #srv-port { width: 12; }
#nodes-hint { width: 100%; height: auto; margin-top: 1; }
#srv-protocol { width: 16; margin-right: 2; }
#srv-endpoint { width: 40; }
#upstream, #language { width: 40; }
#tunnel-mode { border: none; background: transparent; margin-top: 1; }
#channels { height: auto; max-height: 8; }
.buttons { height: auto; margin-bottom: 1; }
.buttons Button { margin-right: 2; }

/* Dialogs */
ConfirmDialog, UserForm, HostForm, ChannelForm, ListForm, ExportForm, PasswordForm, AccessDialog, HelpScreen,
UninstallDialog, RepairDialog, NodeForm, JoinDialog { align: center middle; }
#r-log { height: 10; border: round $border-blurred; margin-top: 1; }
.settings-panel.danger { border: round $error 60%; }
.settings-panel.danger:focus-within { border: round $error; }
#u-log { height: 10; border: round $border-blurred; margin-top: 1; }
.dialog {
    width: 64; height: auto; max-height: 95%; overflow-y: auto; background: $boost; padding: 1 2;
    border: round $border-blurred; border-title-color: $accent; border-title-style: bold;
}
.dialog.wide { width: 84; }
.field-group { height: auto; }
.row { height: auto; }
.row > Vertical { width: 1fr; height: auto; margin-right: 2; }
.row > Vertical:last-of-type { margin-right: 0; }
.row > Vertical.narrow { width: 16; }
.dialog .field-label { color: $text-muted; margin-top: 1; }
.dialog Input, .dialog Select { width: 100%; }
.dialog .hint { margin-top: 1; width: 100%; }
.dialog .hint.warning { color: $warning; }
.dialog-message { margin-bottom: 1; }
#f-error { color: $error; text-style: bold; margin-top: 1; height: auto; }
.dialog-buttons { height: auto; margin-top: 1; align-horizontal: right; }
.dialog-buttons Button { margin-left: 2; }

/* Install wizard */
InstallScreen { align: center top; }
#wizard { width: 96; height: 1fr; padding: 1 2; }
#wizard-title { color: $accent; text-style: bold; height: 1; }
#wizard-problems { color: $error; height: auto; margin: 1 0; }
#wizard-form { height: auto; border: round $border-blurred; padding: 0 2 1 2; background: $surface; }
#wizard-form .row > Vertical { margin-right: 2; }
#wizard-log { height: 1fr; min-height: 8; border: round $border-blurred; background: $surface; margin-top: 1; }
#wizard .field-label { color: $text-muted; margin-top: 1; }
/* Switches: Textual draws the off knob in $panel, which is black in this theme: give both states
   a visible track, grey off and green on */
Switch .switch--slider { color: #6e7681; background: #21262d; }
Switch:hover > .switch--slider { color: #8b949e; }
Switch.-on .switch--slider { color: $success; background: #23863640; }
Switch.-on:hover > .switch--slider { color: #56d364; }
Switch:disabled .switch--slider { color: #484f58; background: #161b22; }
.switch-row { height: 3; margin-top: 1; }
.switch-row Label { height: 3; content-align: left middle; width: 1fr; }
"""
