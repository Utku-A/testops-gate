# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Delivering alerts to the configured channels."""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import time
import urllib.request
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from testops_gate.config import Channel, Config
from testops_gate.db import Store
from testops_gate.notify import SEVERITY_RANK, AlertInfo, email, slack

log = logging.getLogger(__name__)
TIMEOUT = 15


class DeliveryError(RuntimeError):
    pass


def send_slack(channel: Channel, alert: AlertInfo) -> None:
    body = json.dumps(slack.payload(alert)).encode()
    request = urllib.request.Request(channel.webhook, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as resp:
            if resp.status >= 300:
                raise DeliveryError(f"Slack returned HTTP {resp.status}")
    except OSError as exc:
        raise DeliveryError(f"Slack: {exc}") from exc


def build_email(channel: Channel, alert: AlertInfo) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = alert.subject
    msg["From"] = channel.sender
    msg["To"] = ", ".join(channel.recipients)
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=alert.server or None)
    msg.set_content(email.text(alert))
    logo_cid = make_msgid(domain="testopscenter.com")
    msg.add_alternative(email.html(alert, logo_cid=logo_cid[1:-1]), subtype="html")
    # the logo travels inside the email: remote images are blocked by many mail clients
    msg.get_payload()[1].add_related(email.logo_png(), maintype="image", subtype="png", cid=logo_cid,
                                     filename="testopscenter.png", disposition="inline")
    return msg


def send_email(channel: Channel, alert: AlertInfo) -> None:
    smtp_send(channel, build_email(channel, alert))


def smtp_send(channel: Channel, msg: EmailMessage) -> None:
    """Send a message through an email channel's SMTP server."""
    context = ssl.create_default_context()
    try:
        if channel.smtp_security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(channel.smtp_host, channel.smtp_port, timeout=TIMEOUT, context=context)
        else:
            server = smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=TIMEOUT)
        with server:
            if channel.smtp_security == "starttls":
                server.starttls(context=context)
            if channel.smtp_user:
                server.login(channel.smtp_user, channel.smtp_password)
            server.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise DeliveryError(f"SMTP {channel.smtp_host}: {exc}") from exc


def send(channel: Channel, alert: AlertInfo) -> None:
    if channel.kind == "slack":
        send_slack(channel, alert)
    else:
        send_email(channel, alert)


def wants(channel: Channel, alert: AlertInfo) -> bool:
    return channel.enabled and SEVERITY_RANK[alert.severity] >= SEVERITY_RANK.get(channel.min_severity, 1)


def dispatch(cfg: Config, store: Store, alert: AlertInfo) -> list[str]:
    """Send alert to every matching channel not muted for this user and category.

    Returns one status line per channel considered.
    """
    results = []
    now = time.time()
    for channel in cfg.channels:
        if not wants(channel, alert):
            continue
        last = store.last_notified(channel.id, alert.user, alert.category)
        if channel.mute_minutes and now - last < channel.mute_minutes * 60:
            results.append(f"{channel.name}: muted")
            continue
        try:
            send(channel, alert)
        except DeliveryError as exc:
            log.warning("notification to %s failed: %s", channel.name, exc)
            results.append(f"{channel.name}: failed ({exc})")
            continue
        store.mark_notified(channel.id, alert.user, alert.category, now)
        results.append(f"{channel.name}: sent")
    return results
