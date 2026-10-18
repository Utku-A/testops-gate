# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""HTML and plain-text alert emails.

Table-based layout with inline styles: Gmail, Outlook and Apple Mail do not
reliably support <style> blocks, flexbox or grid.
"""

from __future__ import annotations

import re
from html import escape
from pathlib import Path

from testops_gate import BRAND, BRAND_LINE, BRAND_URL
from testops_gate.i18n import T
from testops_gate.notify import AlertInfo

C = {
    "page": "#f6f8fa", "card": "#ffffff", "border": "#d0d7de", "text": "#1f2328", "muted": "#656d76",
    "header": "#0d1117", "accent": "#58a6ff", "code_bg": "#0d1117", "code_text": "#e6edf3",
}
SEVERITY_COLORS = {"high": ("#cf222e", "#ffebe9"), "medium": ("#9a6700", "#fff8c5"), "low": ("#0969da", "#ddf4ff")}
KIND_COLORS = {"SESSION": "#39c5cf", "DNS": "#bc8cff", "CONN": "#58a6ff", "SECURITY": "#f85149"}
MONO = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,'Liberation Mono',monospace"
SANS = "-apple-system,BlinkMacSystemFont,'Segoe UI','Noto Sans',Helvetica,Arial,sans-serif"
SECTION = f"font-size:12px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:{C['muted']};margin-bottom:8px;"
CMD = (f"margin:0 0 12px 0;padding:8px 12px;background:{C['page']};border:1px solid {C['border']};"
       f"border-radius:6px;font-family:{MONO};font-size:13px;color:{C['text']};")
LOGO = Path(__file__).parent / "assets" / "logo-white.png"  # white logo for the dark header


def logo_png() -> bytes:
    return LOGO.read_bytes()


LINE_RE = re.compile(r"^(\S+)\s+\[(\w+)\]\s+(\S+)\s+(.*)$")


def _mono(text: str) -> str:
    return f'<span style="font-family:{MONO};">{escape(text)}</span>'


def _rows(a: AlertInfo) -> list[tuple[str, str]]:
    color, bg = SEVERITY_COLORS[a.severity]
    rows = []
    if a.user and a.user != "-":
        user = f"<b>{escape(a.user)}</b>"
        if a.email:
            user += f' &nbsp;<span style="color:{C["muted"]};">{escape(a.email)}</span>'
        rows.append((T("User"), user))
    if a.vpn_ip:
        rows.append(("VPN IP", _mono(a.vpn_ip)))
    if a.real_ip:
        rows.append((T("Real IP"), _mono(a.real_ip)))
    rows += [
        (T("Time"), escape(a.ts.isoformat(sep=" ", timespec="seconds"))),
        (T("Category"), f'<span style="font-family:{MONO};background:{bg};color:{color};padding:1px 6px;'
                        f'border-radius:4px;">{escape(a.category)}</span>'),
        (T("Detail"), _mono(a.detail)),
        (T("Detected by"), escape(a.source)),
        (T("Action taken"), escape(a.action_text)),
    ]
    return rows


def _recent_html(lines: list[str]) -> str:
    out = []
    for line in lines:
        match = LINE_RE.match(line)
        if not match:
            out.append(escape(line))
            continue
        stamp, kind, _user, rest = match.groups()
        time_part = stamp[11:19] if len(stamp) >= 19 else stamp
        out.append(
            f'<span style="color:#7d8590;">{escape(time_part)}</span>  '
            f'<span style="color:{KIND_COLORS.get(kind, C["code_text"])};font-weight:700;">'
            f'{escape(f"[{kind}]"):<10}</span> {escape(rest)}'
        )
    return "<br>".join(out)


def html(a: AlertInfo, logo_cid: str = "") -> str:
    """logo_cid: Content-ID of the inline logo image; without it the brand is shown as text."""
    color, bg = SEVERITY_COLORS[a.severity]
    who = escape(a.user if a.user and a.user != "-" else a.real_ip)
    if logo_cid:
        brand = (f'<img src="cid:{logo_cid}" width="108" height="30" alt="{BRAND}" '
                 f'style="display:block;border:0;outline:none;">')
    else:
        brand = f"&#9670; {BRAND}"
    divider = f"border-top:1px solid {C['border']};"
    rows = "\n".join(
        f'<tr><td width="34%" style="{divider if i else ""}padding:9px 12px;'
        f'color:{C["muted"]};vertical-align:top;">{label}</td>'
        f'<td style="{divider if i else ""}padding:9px 12px;'
        f'vertical-align:top;overflow-wrap:anywhere;">{value}</td></tr>'
        for i, (label, value) in enumerate(_rows(a))
    )
    recent = ""
    if a.recent:
        recent = f"""
    <tr><td style="padding:16px 24px 8px 24px;">
      <div style="{SECTION}">{escape(T("Recent activity"))}</div>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{C['code_bg']};border-radius:6px;">
        <tr><td style="padding:12px 14px;font-family:{MONO};font-size:12px;line-height:1.7;color:{C['code_text']};white-space:pre-wrap;overflow-wrap:anywhere;">{_recent_html(a.recent)}</td></tr>
      </table>
    </td></tr>"""
    todo = ""
    if a.user and a.user != "-":
        todo = f"""
    <tr><td style="padding:16px 24px 8px 24px;">
      <div style="{SECTION}">{escape(T("What you can do"))}</div>
      <p style="margin:0 0 4px 0;font-size:14px;">{escape(T("Disable the user and drop the session"))}</p>
      <div style="{CMD}">sudo testops-gate user disable {escape(a.user)}</div>
      <p style="margin:0 0 4px 0;font-size:14px;">{escape(T("Review this user's security log"))}</p>
      <div style="{CMD}">sudo testops-gate logs {escape(a.user)} --security --since 1h</div>
      <p style="margin:0;font-size:13px;color:{C['muted']};">{escape(T("Run on the VPN server, or use the Users screen in TestOps Gate."))}</p>
    </td></tr>"""
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light">
<title>{escape(a.subject)}</title></head>
<body style="margin:0;padding:0;background:{C['page']};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">{who} · {escape(a.detail)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{C['page']};">
<tr><td align="center" style="padding:24px 12px;">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;background:{C['card']};border:1px solid {C['border']};border-radius:8px;overflow:hidden;font-family:{SANS};color:{C['text']};">
    <tr><td style="background:{C['header']};padding:14px 24px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="font-family:{MONO};font-size:15px;font-weight:700;color:{C['accent']};">{brand}</td>
        <td align="right" style="font-family:{MONO};font-size:12px;color:#7d8590;">TestOps Gate &middot; {escape(a.server)}</td>
      </tr></table>
    </td></tr>
    <tr><td style="background:{bg};border-left:4px solid {color};padding:10px 20px;font-size:12px;font-weight:700;letter-spacing:.06em;color:{color};">
      {escape(T("{level} SEVERITY", level=a.severity_label))}
    </td></tr>
    <tr><td style="padding:24px 24px 8px 24px;">
      <h1 style="margin:0 0 8px 0;font-size:22px;line-height:1.3;">{escape(a.title)}</h1>
      <p style="margin:0;font-size:15px;line-height:1.6;"><b>{who}</b> · {escape(a.detail)}</p>
    </td></tr>
    <tr><td style="padding:16px 24px 8px 24px;">
      <div style="{SECTION}">{escape(T("Details"))}</div>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid {C['border']};border-radius:6px;border-collapse:separate;font-size:14px;">
{rows}
      </table>
    </td></tr>{recent}{todo}
    <tr><td style="padding:20px 24px 24px 24px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-top:1px solid {C['border']};">
        <tr><td style="padding-top:16px;font-size:12px;line-height:1.6;color:{C['muted']};overflow-wrap:anywhere;">
          {escape(T("Alert ID"))}: <span style="font-family:{MONO};">{escape(a.uid)}</span><br><br>
          <a href="{BRAND_URL}" style="color:{C['muted']};text-decoration:none;">{escape(BRAND_LINE)}</a>
        </td></tr>
      </table>
    </td></tr>
  </table>
</td></tr>
</table>
</body>
</html>
"""


def text(a: AlertInfo) -> str:
    lines = [
        f"{a.title} [{a.severity_label}]",
        "",
        f"{a.user if a.user != '-' else a.real_ip} · {a.detail}",
        "",
        f"{T('Server')}: {a.server}",
    ]
    if a.user and a.user != "-":
        lines.append(f"{T('User')}: {a.user}" + (f" <{a.email}>" if a.email else ""))
    if a.vpn_ip:
        lines.append(f"VPN IP: {a.vpn_ip}")
    if a.real_ip:
        lines.append(f"{T('Real IP')}: {a.real_ip}")
    lines += [
        f"{T('Time')}: {a.ts.isoformat(sep=' ', timespec='seconds')}",
        f"{T('Category')}: {a.category}",
        f"{T('Detected by')}: {a.source}",
        f"{T('Action taken')}: {a.action_text}",
    ]
    if a.recent:
        lines += ["", f"{T('Recent activity')}:", *[f"  {line}" for line in a.recent]]
    if a.user and a.user != "-":
        lines += [
            "",
            f"{T('What you can do')}:",
            f"  sudo testops-gate user disable {a.user}",
            f"  sudo testops-gate logs {a.user} --security --since 1h",
        ]
    lines += ["", f"{T('Alert ID')}: {a.uid}", "", f"{BRAND_LINE} ({BRAND_URL})"]
    return "\n".join(lines) + "\n"
