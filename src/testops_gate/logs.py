# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Per-user log files under /var/log/testops-gate.

    users/<user>/<YYYY-MM-DD>.log            sessions, DNS queries, connections
    users/<user>/security-<YYYY-MM-DD>.log   this user's security alerts
    security/<YYYY-MM-DD>.log                all security alerts
    audit/<YYYY-MM-DD>.log                   management actions (who did what)

One event per line, plain text:
    2026-11-02T10:03:11+03:00 [SESSION]  mehmet     connect    real_ip=88.1.2.3 vpn_ip=10.8.0.11
Files older than the retention period are deleted by testops-gated.
"""

from __future__ import annotations

import os
import re
import shutil
from datetime import date, datetime, timedelta
from pathlib import Path

from testops_gate.paths import P

DATED_FILE = re.compile(r"^(?:security-)?(\d{4}-\d{2}-\d{2})\.log$")
LOG_DIR_MODE = 0o750
LOG_FILE_MODE = 0o640


def now() -> datetime:
    return datetime.now().astimezone()


def day_of(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d")


def format_line(ts: datetime, kind: str, user: str, message: str) -> str:
    stamp = ts.astimezone().isoformat(timespec="seconds")
    return f"{stamp} {f'[{kind}]':<11}{user:<11}{message}"


def user_log(user: str, day: str) -> Path:
    return P.users_log_dir / user / f"{day}.log"


def user_security_log(user: str, day: str) -> Path:
    return P.users_log_dir / user / f"security-{day}.log"


def security_log(day: str) -> Path:
    return P.security_log_dir / f"{day}.log"


def audit_log(day: str) -> Path:
    return P.audit_log_dir / f"{day}.log"


def append(path: Path, line: str) -> None:
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, LOG_DIR_MODE)
    new = not path.exists()
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    if new:
        os.chmod(path, LOG_FILE_MODE)


def write_event(user: str, kind: str, message: str, ts: datetime | None = None) -> None:
    ts = ts or now()
    append(user_log(user, day_of(ts)), format_line(ts, kind, user, message))


def write_security(user: str, message: str, ts: datetime | None = None) -> None:
    ts = ts or now()
    line = format_line(ts, "SECURITY", user, message)
    day = day_of(ts)
    append(security_log(day), line)
    if user and user != "-":
        append(user_security_log(user, day), line)
        append(user_log(user, day), line)


def audit(action: str, detail: str = "", actor: str | None = None) -> None:
    actor = actor or os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"
    ts = now()
    append(audit_log(day_of(ts)), format_line(ts, "AUDIT", actor, f"{action:<16} {detail}".rstrip()))


def ensure_user_dir(user: str) -> None:
    path = P.users_log_dir / user
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, LOG_DIR_MODE)


def available_days(directory: Path, prefix: str = "") -> list[str]:
    """Dates that have a log file in directory, newest first."""
    if not directory.exists():
        return []
    days = []
    for entry in directory.iterdir():
        match = DATED_FILE.match(entry.name)
        if match and entry.name.startswith(prefix) and (prefix or not entry.name.startswith("security-")):
            days.append(match.group(1))
    return sorted(set(days), reverse=True)


def tail(path: Path, lines: int = 500) -> list[str]:
    if not path.exists():
        return []
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        block = min(size, max(lines * 200, 65536))
        fh.seek(size - block)
        data = fh.read().decode("utf-8", errors="replace")
    result = data.splitlines()
    if block < size:
        result = result[1:]  # first line may be partial
    return result[-lines:]


def cleanup(retention_days: int, today: date | None = None) -> list[Path]:
    """Delete dated log files older than retention_days; returns the removed paths."""
    today = today or date.today()
    cutoff = (today - timedelta(days=retention_days)).isoformat()
    removed: list[Path] = []
    for directory in [P.security_log_dir, P.audit_log_dir, *_user_dirs()]:
        if not directory.exists():
            continue
        for entry in directory.iterdir():
            match = DATED_FILE.match(entry.name)
            if match and match.group(1) < cutoff:
                entry.unlink(missing_ok=True)
                removed.append(entry)
    for directory in _user_dirs():
        if directory.exists() and not any(directory.iterdir()):
            shutil.rmtree(directory, ignore_errors=True)
    return removed


def _user_dirs() -> list[Path]:
    if not P.users_log_dir.exists():
        return []
    return [d for d in P.users_log_dir.iterdir() if d.is_dir()]
