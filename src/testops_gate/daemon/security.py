# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Security engine: turns detector findings into alerts, logs and notifications."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from typing import TYPE_CHECKING

from testops_gate import logs
from testops_gate.config import CATEGORY_KEYS
from testops_gate.daemon.detectors import Deduper
from testops_gate.i18n import T
from testops_gate.notify import SEVERITY_RANK, AlertInfo
from testops_gate.notify.send import dispatch

if TYPE_CHECKING:
    from testops_gate.core.context import Context

log = logging.getLogger(__name__)
# The same alert (user, category, key) is recorded again only after this many seconds
DEDUPE_SECONDS = 300
DEDUPE_BY_CATEGORY = {"auth-failure": 3600, "port-scan": 600, "abnormal-volume": 600}
RECENT_LINES = 6


class SecurityEngine:
    def __init__(self, ctx: Context, live_ips: dict[str, str] | None = None) -> None:
        self.ctx = ctx
        self.live_real_ips = live_ips if live_ips is not None else {}  # user -> real ip
        self.dedupe = Deduper(DEDUPE_SECONDS)
        self.pending: set[asyncio.Task] = set()

    def enabled(self, category: str) -> bool:
        key = CATEGORY_KEYS.get(category)
        return bool(key) and self.ctx.cfg.security.category_enabled(key)

    def raise_alert(self, category: str, severity: str, user: str, detail: str, *,
                    key: str = "", real_ip: str = "", notify: bool = True) -> AlertInfo | None:
        if not self.enabled(category):
            return None
        now = time.time()
        if not self.dedupe.fresh((user, category, key or detail), now, DEDUPE_BY_CATEGORY.get(category)):
            return None
        ts = logs.now()
        uid = f"a-{ts:%Y%m%d-%H%M%S}-{secrets.token_hex(2)}"
        self.ctx.store.add_alert(now, user, category, severity, detail, uid)
        logs.write_security(user, f"{category:<20} severity={severity} {detail}", ts)
        log.info("alert %s %s %s %s", severity, category, user, detail)

        account = self.ctx.store.user(user) if user and user != "-" else None
        action = ""
        cfg = self.ctx.cfg
        if (account and SEVERITY_RANK[severity] >= SEVERITY_RANK["high"]
                and cfg.security.category_enabled("autoblock")):
            self.ctx.block_user(user, cfg.security.autoblock_minutes)
            action = T("Disabled for {n} minutes and disconnected", n=cfg.security.autoblock_minutes)
            logs.write_security(user, f"{'autoblock':<20} severity={severity} minutes={cfg.security.autoblock_minutes}")

        alert = AlertInfo(
            uid=uid,
            ts=ts,
            server=cfg.server.endpoint,
            user=user or "-",
            category=category,
            severity=severity,
            detail=detail,
            email=account.email if account else "",
            vpn_ip=account.vpn_ip if account else "",
            real_ip=real_ip or self.live_real_ips.get(user, ""),
            action=action,
            recent=logs.tail(logs.user_log(user, logs.day_of(ts)), RECENT_LINES) if account else [],
        )
        if notify and cfg.channels:
            self._notify(alert)
        return alert

    def _notify(self, alert: AlertInfo) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            dispatch(self.ctx.cfg, self.ctx.store, alert)
            return
        task = loop.create_task(asyncio.to_thread(dispatch, self.ctx.cfg, self.ctx.store, alert))
        self.pending.add(task)
        task.add_done_callback(self.pending.discard)
