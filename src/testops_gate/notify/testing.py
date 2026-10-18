# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Test notification content."""

from __future__ import annotations

import secrets

from testops_gate import logs
from testops_gate.config import Config
from testops_gate.i18n import T
from testops_gate.notify import AlertInfo


def test_alert(cfg: Config) -> AlertInfo:
    ts = logs.now()
    return AlertInfo(
        uid=f"test-{ts:%Y%m%d-%H%M%S}-{secrets.token_hex(2)}",
        ts=ts,
        server=cfg.server.endpoint,
        user="-",
        category="test",
        severity="low",
        detail=T("This is a test message from TestOps Gate. Delivery works."),
        real_ip="—",
        action=T("None"),
    )
