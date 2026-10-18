# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Slack Block Kit payload for incoming webhooks.

Incoming webhooks cannot carry interactive buttons (that needs a Slack app),
so the follow-up steps are given as commands.
"""

from __future__ import annotations

import re

from testops_gate import BRAND, BRAND_ICON_URL, BRAND_URL
from testops_gate.i18n import T
from testops_gate.notify import AlertInfo

SEVERITY_COLORS = {"high": "#cf222e", "medium": "#d29922", "low": "#2f81f7"}
SEVERITY_EMOJI = {"high": ":red_circle:", "medium": ":large_orange_circle:", "low": ":large_blue_circle:"}
LINE_RE = re.compile(r"^\S+T(\d\d:\d\d:\d\d)\S*\s+(\[\w+\])\s+\S+\s+(.*)$")
MAX_TEXT = 2900  # Slack section text limit is 3000 characters


def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def payload(a: AlertInfo) -> dict:
    who = a.user if a.user and a.user != "-" else a.real_ip
    when = f"<!date^{int(a.ts.timestamp())}^{{date_short_pretty}} {{time_secs}}|{a.ts.isoformat(sep=' ', timespec='seconds')}>"

    def field(label: str, value: str) -> dict:
        return {"type": "mrkdwn", "text": f"*{label}*\n{value}"}

    fields = [field(T("Severity"), f"*{a.severity_label}*"), field(T("Category"), f"`{a.category}`")]
    if a.user and a.user != "-":
        fields.append(field(T("User"), esc(a.user + (f" ({a.email})" if a.email else ""))))
    if a.vpn_ip:
        fields.append(field("VPN IP", f"`{a.vpn_ip}`"))
    if a.real_ip:
        fields.append(field(T("Real IP"), f"`{a.real_ip}`"))
    fields += [field(T("Time"), when), field(T("Detected by"), esc(a.source)), field(T("Action taken"), esc(a.action_text))]

    blocks: list[dict] = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{SEVERITY_EMOJI[a.severity]} {a.title}"[:150], "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{esc(who)}* · {esc(a.detail)}"[:MAX_TEXT]}},
        {"type": "section", "fields": fields[:10]},
    ]
    if a.recent:
        recent = "\n".join(
            f"{m.group(1)}  {m.group(2):<10} {m.group(3)}" if (m := LINE_RE.match(line)) else line for line in a.recent
        )
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
                                                   "text": f"*{T('Recent activity')}*\n```{esc(recent)[:MAX_TEXT - 60]}```"}})
    if a.user and a.user != "-":
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": (
            f"*{T('What you can do')}*\n"
            f"`sudo testops-gate user disable {esc(a.user)}`\n"
            f"`sudo testops-gate logs {esc(a.user)} --security --since 1h`"
        )}})
    blocks += [
        {"type": "divider"},
        {"type": "context", "elements": [
            {"type": "image", "image_url": BRAND_ICON_URL, "alt_text": BRAND},
            {"type": "mrkdwn", "text": f"{esc(a.server)} · {T('Alert ID')} `{a.uid}` · "
                                       f"TestOps Gate by <{BRAND_URL}|{BRAND}\u2122>"},
        ]},
    ]
    return {
        "text": f"[{a.severity_label}] {a.category} · {who} · {a.detail}"[:300],
        "attachments": [{"color": SEVERITY_COLORS[a.severity], "blocks": blocks}],
    }
