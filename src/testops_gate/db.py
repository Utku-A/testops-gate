# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""State database (/var/lib/testops-gate/state.db).

Holds users, host records, alerts, live session data written by the daemon
and per-day traffic counters. The TUI, CLI and daemon all open it; SQLite in
WAL mode handles the concurrent readers and the occasional writer.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from testops_gate.paths import P

SCHEMA = [
    # v1
    """
    CREATE TABLE users (
        name TEXT PRIMARY KEY,
        email TEXT NOT NULL DEFAULT '',
        vpn_ip TEXT NOT NULL UNIQUE,
        mode TEXT NOT NULL DEFAULT 'default',
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at REAL NOT NULL,
        cert_expires REAL NOT NULL DEFAULT 0,
        blocked_until REAL NOT NULL DEFAULT 0,
        note TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE hosts (
        name TEXT PRIMARY KEY,
        rtype TEXT NOT NULL,
        value TEXT NOT NULL,
        note TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL NOT NULL,
        user TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        detail TEXT NOT NULL,
        uid TEXT NOT NULL
    );
    CREATE INDEX alerts_ts ON alerts(ts);
    CREATE TABLE live_clients (
        name TEXT PRIMARY KEY,
        real_ip TEXT NOT NULL,
        vpn_ip TEXT NOT NULL,
        connected_since REAL NOT NULL,
        rx INTEGER NOT NULL,
        tx INTEGER NOT NULL,
        updated_at REAL NOT NULL
    );
    CREATE TABLE traffic (
        user TEXT NOT NULL,
        day TEXT NOT NULL,
        rx INTEGER NOT NULL DEFAULT 0,
        tx INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user, day)
    );
    CREATE TABLE notify_state (
        channel TEXT NOT NULL,
        user TEXT NOT NULL,
        category TEXT NOT NULL,
        last_sent REAL NOT NULL,
        PRIMARY KEY (channel, user, category)
    );
    """,
    # v2: password for username + password sign-in (scrypt hash, empty: none set)
    """
    ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';
    """,
    # v3: servers that join the VPN, and their one-time join tokens (secret stored as a hash)
    """
    CREATE TABLE nodes (
        name TEXT PRIMARY KEY,
        vpn_ip TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at REAL NOT NULL,
        cert_expires REAL NOT NULL DEFAULT 0,
        password_hash TEXT NOT NULL DEFAULT '',
        note TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE join_tokens (
        id TEXT PRIMARY KEY,
        secret_hash TEXT NOT NULL,
        node TEXT NOT NULL,
        created_at REAL NOT NULL,
        expires REAL NOT NULL,
        used_at REAL NOT NULL DEFAULT 0
    );
    """,
]

LIVE_TTL = 10.0  # seconds after which a live_clients row is considered stale


@dataclass
class User:
    name: str
    email: str
    vpn_ip: str
    mode: str  # default | split | full
    enabled: bool
    created_at: float
    cert_expires: float
    blocked_until: float = 0.0
    note: str = ""
    password_hash: str = ""
    # Plain password, only on the object add_user() returns when it set one; never stored
    password: str = field(default="", repr=False, compare=False)

    @property
    def has_password(self) -> bool:
        return bool(self.password_hash)

    @property
    def blocked(self) -> bool:
        return self.blocked_until > time.time()

    @property
    def active(self) -> bool:
        """Allowed to connect: enabled and not temporarily blocked."""
        return self.enabled and not self.blocked


@dataclass
class Node:
    """A server in the VPN. Its OpenVPN certificate CN is "<name>.node" (user names have no dots)."""
    name: str
    vpn_ip: str
    enabled: bool
    created_at: float
    cert_expires: float = 0.0
    password_hash: str = ""
    note: str = ""

    @property
    def cn(self) -> str:
        return node_cn(self.name)


def node_cn(name: str) -> str:
    return f"{name}.node"


@dataclass
class JoinToken:
    id: str
    secret_hash: str
    node: str
    created_at: float
    expires: float
    used_at: float = 0.0

    def usable(self, now: float | None = None) -> bool:
        return not self.used_at and (now or time.time()) < self.expires


@dataclass
class Host:
    name: str
    rtype: str  # A | CNAME
    value: str
    note: str = ""

    @property
    def wildcard(self) -> bool:
        return self.name.startswith("*.")


@dataclass
class Alert:
    id: int
    ts: float
    user: str
    category: str
    severity: str
    detail: str
    uid: str


@dataclass
class LiveClient:
    name: str
    real_ip: str
    vpn_ip: str
    connected_since: float
    rx: int  # bytes sent to the client (download)
    tx: int  # bytes received from the client (upload)
    updated_at: float


class Store:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or P.db_file
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=10000")
        self._migrate()

    def close(self) -> None:
        self.conn.close()

    def _migrate(self) -> None:
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        for index, script in enumerate(SCHEMA[version:], start=version + 1):
            # executescript commits any open transaction itself, so the script carries its own
            self.conn.executescript(f"BEGIN IMMEDIATE;\n{script}\nPRAGMA user_version = {index};\nCOMMIT;")

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            yield self.conn
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise
        self.conn.execute("COMMIT")

    # --- users -------------------------------------------------------------

    def users(self) -> list[User]:
        rows = self.conn.execute("SELECT * FROM users ORDER BY name").fetchall()
        return [User(**{**dict(r), "enabled": bool(r["enabled"])}) for r in rows]

    def user(self, name: str) -> User | None:
        row = self.conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()
        return User(**{**dict(row), "enabled": bool(row["enabled"])}) if row else None

    def add_user(self, user: User) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO users (name, email, vpn_ip, mode, enabled, created_at, cert_expires, blocked_until, note,"
                " password_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (user.name, user.email, user.vpn_ip, user.mode, int(user.enabled), user.created_at,
                 user.cert_expires, user.blocked_until, user.note, user.password_hash),
            )

    def update_user(self, name: str, **fields: object) -> None:
        if "enabled" in fields:
            fields["enabled"] = int(bool(fields["enabled"]))
        assignments = ", ".join(f"{key} = ?" for key in fields)
        with self.tx() as c:
            c.execute(f"UPDATE users SET {assignments} WHERE name = ?", (*fields.values(), name))

    def delete_user(self, name: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM users WHERE name = ?", (name,))
            c.execute("DELETE FROM live_clients WHERE name = ?", (name,))

    # --- hosts -------------------------------------------------------------

    # --- nodes -------------------------------------------------------------

    def nodes(self) -> list[Node]:
        rows = self.conn.execute("SELECT * FROM nodes ORDER BY name").fetchall()
        return [Node(**{**dict(r), "enabled": bool(r["enabled"])}) for r in rows]

    def node(self, name: str) -> Node | None:
        row = self.conn.execute("SELECT * FROM nodes WHERE name = ?", (name,)).fetchone()
        return Node(**{**dict(row), "enabled": bool(row["enabled"])}) if row else None

    def add_node(self, node: Node) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO nodes (name, vpn_ip, enabled, created_at, cert_expires, password_hash, note)"
                      " VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (node.name, node.vpn_ip, int(node.enabled), node.created_at, node.cert_expires,
                       node.password_hash, node.note))

    def delete_node(self, name: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM nodes WHERE name = ?", (name,))
            c.execute("DELETE FROM join_tokens WHERE node = ?", (name,))
            c.execute("DELETE FROM live_clients WHERE name = ?", (node_cn(name),))

    def add_token(self, token: JoinToken) -> None:
        with self.tx() as c:
            c.execute("INSERT INTO join_tokens (id, secret_hash, node, created_at, expires, used_at)"
                      " VALUES (?, ?, ?, ?, ?, ?)",
                      (token.id, token.secret_hash, token.node, token.created_at, token.expires, token.used_at))

    def token(self, token_id: str) -> JoinToken | None:
        row = self.conn.execute("SELECT * FROM join_tokens WHERE id = ?", (token_id,)).fetchone()
        return JoinToken(**dict(row)) if row else None

    def tokens(self) -> list[JoinToken]:
        return [JoinToken(**dict(r)) for r in self.conn.execute("SELECT * FROM join_tokens ORDER BY created_at")]

    def use_token(self, token_id: str) -> bool:
        """Mark a token used; False if it was already used (two joins racing for one token)."""
        with self.tx() as c:
            return c.execute("UPDATE join_tokens SET used_at = ? WHERE id = ? AND used_at = 0",
                             (time.time(), token_id)).rowcount == 1

    # --- hosts -------------------------------------------------------------

    def hosts(self) -> list[Host]:
        return [Host(**dict(r)) for r in self.conn.execute("SELECT * FROM hosts ORDER BY name")]

    def host(self, name: str) -> Host | None:
        row = self.conn.execute("SELECT * FROM hosts WHERE name = ?", (name,)).fetchone()
        return Host(**dict(row)) if row else None

    def upsert_host(self, host: Host, old_name: str | None = None) -> None:
        with self.tx() as c:
            if old_name and old_name != host.name:
                c.execute("DELETE FROM hosts WHERE name = ?", (old_name,))
            c.execute(
                "INSERT INTO hosts (name, rtype, value, note) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(name) DO UPDATE SET rtype = excluded.rtype, value = excluded.value, note = excluded.note",
                (host.name, host.rtype, host.value, host.note),
            )

    def delete_host(self, name: str) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM hosts WHERE name = ?", (name,))

    # --- alerts ------------------------------------------------------------

    def add_alert(self, ts: float, user: str, category: str, severity: str, detail: str, uid: str) -> int:
        with self.tx() as c:
            cur = c.execute(
                "INSERT INTO alerts (ts, user, category, severity, detail, uid) VALUES (?, ?, ?, ?, ?, ?)",
                (ts, user, category, severity, detail, uid),
            )
            return int(cur.lastrowid or 0)

    def alerts(self, since: float = 0, limit: int = 500, user: str | None = None) -> list[Alert]:
        query = "SELECT * FROM alerts WHERE ts >= ?"
        args: list[object] = [since]
        if user:
            query += " AND user = ?"
            args.append(user)
        query += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        return [Alert(**dict(r)) for r in self.conn.execute(query, args)]

    def prune_alerts(self, before: float) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM alerts WHERE ts < ?", (before,))
            c.execute("DELETE FROM traffic WHERE day < date(?, 'unixepoch', 'localtime')", (before,))

    # --- live data (written by the daemon) ---------------------------------

    def set_live_clients(self, clients: list[LiveClient]) -> None:
        with self.tx() as c:
            c.execute("DELETE FROM live_clients")
            c.executemany(
                "INSERT INTO live_clients VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(x.name, x.real_ip, x.vpn_ip, x.connected_since, x.rx, x.tx, x.updated_at) for x in clients],
            )

    def live_clients(self, max_age: float = LIVE_TTL) -> dict[str, LiveClient]:
        rows = self.conn.execute("SELECT * FROM live_clients WHERE updated_at >= ?", (time.time() - max_age,))
        return {r["name"]: LiveClient(**dict(r)) for r in rows}

    def add_traffic(self, user: str, day: str, rx: int, tx: int) -> None:
        if rx <= 0 and tx <= 0:
            return
        with self.tx() as c:
            c.execute(
                "INSERT INTO traffic (user, day, rx, tx) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(user, day) DO UPDATE SET rx = rx + excluded.rx, tx = tx + excluded.tx",
                (user, day, max(rx, 0), max(tx, 0)),
            )

    def traffic(self, day: str) -> dict[str, tuple[int, int]]:
        rows = self.conn.execute("SELECT user, rx, tx FROM traffic WHERE day = ?", (day,))
        return {r["user"]: (r["rx"], r["tx"]) for r in rows}

    # --- notification mute state -------------------------------------------

    def last_notified(self, channel: str, user: str, category: str) -> float:
        row = self.conn.execute(
            "SELECT last_sent FROM notify_state WHERE channel = ? AND user = ? AND category = ?",
            (channel, user, category),
        ).fetchone()
        return float(row[0]) if row else 0.0

    def mark_notified(self, channel: str, user: str, category: str, ts: float) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO notify_state VALUES (?, ?, ?, ?)"
                " ON CONFLICT(channel, user, category) DO UPDATE SET last_sent = excluded.last_sent",
                (channel, user, category, ts),
            )
