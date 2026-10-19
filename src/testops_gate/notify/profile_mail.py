# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""The email that brings a user their .ovpn profile.

The password never goes in it: with username + password or a profile password the user gets it
from the administrator another way, so the email alone is not enough to connect. Same table
layout and inline styles as the alert emails (notify/email.py).
"""

from __future__ import annotations

from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from html import escape

from testops_gate import BRAND, BRAND_LINE, BRAND_URL
from testops_gate.config import Channel, Config
from testops_gate.db import User
from testops_gate.i18n import T
from testops_gate.notify.email import MONO, SANS, SECTION, C, logo_png
from testops_gate.render.openvpn import effective_mode

CLIENT_URL = "https://openvpn.net/client/"
WARN = ("#9a6700", "#fff8c5")


def subject(cfg: Config) -> str:
    return T("Your VPN access to {server}", server=cfg.server.endpoint)


def _steps(cfg: Config, user: User) -> list[tuple[str, str]]:
    """(title, html body) per step."""
    install = T("OpenVPN Connect for Windows, macOS, iOS and Android:") + \
        f' <a href="{CLIENT_URL}" style="color:#0969da;">{CLIENT_URL}</a>' + \
        f'<br><span style="color:{C["muted"]};">{escape(T("Linux:"))}</span> ' \
        f'<span style="font-family:{MONO};font-size:13px;">sudo apt install openvpn</span>'
    attach = escape(T("Open the attached {file} with OpenVPN Connect (or drag it into the app). On a phone, "
                      "open the attachment and choose OpenVPN.", file=f"{user.name}.ovpn"))
    if cfg.auth.mode == "user-password":
        sign_in = escape(T("Connect and sign in with the username {name} and the password your administrator "
                           "gives you separately.", name=user.name))
    elif cfg.auth.mode == "profile-password":
        sign_in = escape(T("Connect and enter the profile password your administrator gives you separately."))
    else:
        sign_in = escape(T("Connect. No password is needed."))
    return [(T("Install the app"), install), (T("Import the profile"), attach), (T("Connect"), sign_in)]


def _details(cfg: Config, user: User) -> list[tuple[str, str]]:
    mode = effective_mode(cfg, user)
    return [
        (T("Username"), f'<span style="font-family:{MONO};font-weight:700;">{escape(user.name)}</span>'),
        (T("Server"), f'<span style="font-family:{MONO};">{escape(cfg.server.endpoint)}</span>'),
        (T("Port"), f'<span style="font-family:{MONO};">{cfg.server.port}/{cfg.server.protocol}</span>'),
        (T("VPN address"), f'<span style="font-family:{MONO};">{escape(user.vpn_ip)}</span>'),
        (T("Traffic"), escape(T("only company services go through the VPN") if mode == "split"
                              else T("all internet traffic goes through the VPN"))),
    ]


def html(cfg: Config, user: User, logo_cid: str = "") -> str:
    brand = (f'<img src="cid:{logo_cid}" width="108" height="30" alt="{BRAND}" style="display:block;border:0;outline:none;">'
             if logo_cid else f"&#9670; {BRAND}")
    divider = f"border-top:1px solid {C['border']};"
    steps = "\n".join(
        f'<tr><td width="34" valign="top" style="padding:0 0 16px 0;">'
        f'<div style="width:24px;height:24px;line-height:24px;border-radius:12px;background:{C["header"]};'
        f'color:#ffffff;font-size:13px;font-weight:700;text-align:center;">{i}</div></td>'
        f'<td valign="top" style="padding:2px 0 16px 0;font-size:14px;line-height:1.6;">'
        f'<b>{escape(title)}</b><br>{body}</td></tr>'
        for i, (title, body) in enumerate(_steps(cfg, user), start=1)
    )
    details = "\n".join(
        f'<tr><td width="34%" style="{divider if i else ""}padding:9px 12px;color:{C["muted"]};">{label}</td>'
        f'<td style="{divider if i else ""}padding:9px 12px;overflow-wrap:anywhere;">{value}</td></tr>'
        for i, (label, value) in enumerate(_details(cfg, user))
    )
    if cfg.auth.mode == "certificate":
        color, bg = WARN
        notice = (f'<tr><td style="padding:8px 24px 0 24px;"><div style="background:{bg};border-left:4px solid {color};'
                  f'padding:10px 14px;font-size:13px;line-height:1.6;color:{color};">'
                  f'<b>{escape(T("This file alone is enough to connect."))}</b> '
                  f'{escape(T("Do not forward it, and delete this email after importing the profile."))}</div></td></tr>')
    else:
        notice = ""
    greeting = T("Hi {name},", name=user.name)
    return f"""<!DOCTYPE html>
<html lang="{cfg.language}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light">
<title>{escape(subject(cfg))}</title></head>
<body style="margin:0;padding:0;background:{C['page']};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;">{escape(T("Your VPN profile is attached, with setup steps."))}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:{C['page']};">
<tr><td align="center" style="padding:24px 12px;">
  <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;background:{C['card']};border:1px solid {C['border']};border-radius:8px;overflow:hidden;font-family:{SANS};color:{C['text']};">
    <tr><td style="background:{C['header']};padding:14px 24px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"><tr>
        <td style="font-family:{MONO};font-size:15px;font-weight:700;color:{C['accent']};">{brand}</td>
        <td align="right" style="font-family:{MONO};font-size:12px;color:#7d8590;">TestOps Gate &middot; {escape(cfg.server.endpoint)}</td>
      </tr></table>
    </td></tr>
    <tr><td style="padding:28px 24px 4px 24px;">
      <h1 style="margin:0 0 12px 0;font-size:22px;line-height:1.3;">{escape(T("Your VPN profile is ready"))}</h1>
      <p style="margin:0;font-size:15px;line-height:1.6;">{escape(greeting)}<br>
      {escape(T("You now have access to the private network at {server}. Your personal profile is attached to this email.", server=cfg.server.endpoint))}</p>
    </td></tr>{notice}
    <tr><td style="padding:20px 24px 4px 24px;">
      <div style="{SECTION}">{escape(T("Set up in three steps"))}</div>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
{steps}
      </table>
    </td></tr>
    <tr><td style="padding:4px 24px 8px 24px;">
      <div style="{SECTION}">{escape(T("Your connection"))}</div>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border:1px solid {C['border']};border-radius:6px;border-collapse:separate;font-size:14px;">
{details}
      </table>
    </td></tr>
    <tr><td style="padding:16px 24px 8px 24px;">
      <div style="{SECTION}">{escape(T("Keep it safe"))}</div>
      <p style="margin:0;font-size:14px;line-height:1.6;">{escape(T("The profile is personal: do not share it. If you lose it or your device, tell your administrator; it can be revoked at any time."))}</p>
    </td></tr>
    <tr><td style="padding:20px 24px 24px 24px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-top:1px solid {C['border']};">
        <tr><td style="padding-top:16px;font-size:12px;line-height:1.6;color:{C['muted']};">
          {escape(T("Sent by the VPN server {server}. Questions? Contact your administrator.", server=cfg.server.endpoint))}<br><br>
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


def text(cfg: Config, user: User) -> str:
    lines = [T("Your VPN profile is ready"), "", T("Hi {name},", name=user.name),
             T("You now have access to the private network at {server}. Your personal profile is attached to this "
               "email.", server=cfg.server.endpoint), ""]
    if cfg.auth.mode == "certificate":
        lines += [T("This file alone is enough to connect.") + " " +
                  T("Do not forward it, and delete this email after importing the profile."), ""]
    lines.append(T("Set up in three steps"))
    for i, (title, _body) in enumerate(_steps(cfg, user), start=1):
        lines.append(f"  {i}. {title}")
    lines += [
        f"     {CLIENT_URL}  ·  Linux: sudo apt install openvpn",
        f"     {T('Open the attached {file} with OpenVPN Connect (or drag it into the app). On a phone, open the attachment and choose OpenVPN.', file=f'{user.name}.ovpn')}",
        "",
        T("Your connection"),
        f"  {T('Username')}: {user.name}",
        f"  {T('Server')}: {cfg.server.endpoint}  {cfg.server.port}/{cfg.server.protocol}",
        f"  {T('VPN address')}: {user.vpn_ip}",
        "",
        T("The profile is personal: do not share it. If you lose it or your device, tell your administrator; it can "
          "be revoked at any time."),
        "",
        f"{BRAND_LINE} ({BRAND_URL})",
    ]
    return "\n".join(lines) + "\n"


def build(cfg: Config, channel: Channel, user: User, profile: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject(cfg)
    msg["From"] = channel.sender
    msg["To"] = user.email
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=cfg.server.endpoint or None)
    msg.set_content(text(cfg, user))
    logo_cid = make_msgid(domain="testopscenter.com")
    msg.add_alternative(html(cfg, user, logo_cid=logo_cid[1:-1]), subtype="html")
    msg.get_payload()[1].add_related(logo_png(), maintype="image", subtype="png", cid=logo_cid,
                                     filename="testopscenter.png", disposition="inline")
    msg.add_attachment(profile.encode(), maintype="application", subtype="x-openvpn-profile",
                       filename=f"{user.name}.ovpn")
    return msg
