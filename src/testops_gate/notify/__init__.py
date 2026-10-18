# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Alert notifications: Slack (incoming webhook) and email (SMTP)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from testops_gate.i18n import T

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}

CATEGORY_TITLES = {
    "port-scan": "Port scan detected",
    "unauthorized-target": "Unauthorized target access",
    "forbidden-port": "Forbidden port or protocol used",
    "malicious-domain": "Malicious domain blocked",
    "ids-signature": "Attack signature matched",
    "abnormal-volume": "Abnormal data volume",
    "auth-failure": "Repeated failed VPN connections",
    "test": "Test notification",
}

CATEGORY_SOURCES = {
    "port-scan": "testops-gated (connection tracking)",
    "unauthorized-target": "nftables",
    "forbidden-port": "nftables",
    "malicious-domain": "Unbound RPZ",
    "ids-signature": "Suricata (ET Open)",
    "abnormal-volume": "testops-gated (traffic counters)",
    "auth-failure": "OpenVPN",
    "test": "TestOps Gate",
}


@dataclass
class AlertInfo:
    uid: str
    ts: datetime
    server: str
    user: str
    category: str
    severity: str
    detail: str
    email: str = ""
    vpn_ip: str = ""
    real_ip: str = ""
    action: str = ""  # what testops-gated did about it; empty = nothing
    recent: list[str] = field(default_factory=list)  # recent log lines of this user

    @property
    def title(self) -> str:
        return T(CATEGORY_TITLES.get(self.category, self.category))

    @property
    def source(self) -> str:
        return T(CATEGORY_SOURCES.get(self.category, "testops-gated"))

    @property
    def severity_label(self) -> str:
        return T({"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}[self.severity])

    @property
    def subject(self) -> str:
        who = self.user if self.user and self.user != "-" else self.real_ip
        return f"[TestOps Gate] {self.severity_label} · {self.category} · {who}"

    @property
    def action_text(self) -> str:
        return self.action or T("None (automatic blocking is off)")
