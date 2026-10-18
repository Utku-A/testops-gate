# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Stateful detectors fed by the parsers (pure, time passed in for tests)."""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict, deque
from dataclasses import dataclass


@dataclass
class FlowRecord:
    user: str
    proto: str
    dst: str
    dport: int
    count: int
    first: float


class FlowAggregator:
    """Merges repeated connections to the same destination into one log line per window."""

    def __init__(self, window: float = 30.0) -> None:
        self.window = window
        self.pending: dict[tuple[str, str, str, int], FlowRecord] = {}
        self.last_flush = 0.0

    def add(self, user: str, proto: str, dst: str, dport: int, ts: float) -> None:
        if not self.pending and not self.last_flush:
            self.last_flush = ts  # the first window starts with the first connection
        key = (user, proto, dst, dport)
        record = self.pending.get(key)
        if record:
            record.count += 1
        else:
            self.pending[key] = FlowRecord(user, proto, dst, dport, 1, ts)

    def flush(self, ts: float, force: bool = False) -> list[FlowRecord]:
        if not force and ts - self.last_flush < self.window:
            return []
        self.last_flush = ts
        records = sorted(self.pending.values(), key=lambda r: r.first)
        self.pending.clear()
        return records


@dataclass
class ScanFinding:
    user: str
    ports: int
    hosts: int
    target: str  # most probed host or /24


class ScanDetector:
    """Flags a user who opens connections to many distinct (host, port) pairs in a short window."""

    def __init__(self, threshold: int = 100, window: float = 60.0) -> None:
        self.threshold = threshold
        self.window = window
        self.events: dict[str, deque[tuple[float, str, int]]] = defaultdict(deque)

    def add(self, user: str, dst: str, dport: int, ts: float) -> ScanFinding | None:
        events = self.events[user]
        events.append((ts, dst, dport))
        while events and ts - events[0][0] > self.window:
            events.popleft()
        pairs = {(d, p) for _, d, p in events}
        if len(pairs) < self.threshold:
            return None
        hosts = {d for d, _ in pairs}
        if len(hosts) == 1:
            target = next(iter(hosts))
        else:
            nets = Counter(str(ipaddress.IPv4Network(f"{d}/24", strict=False)) for d in hosts)
            target = nets.most_common(1)[0][0]
        events.clear()  # start over so one scan raises one alert
        return ScanFinding(user, len({p for _, p in pairs}), len(hosts), target)


class VolumeDetector:
    """Flags a user whose upload within the window exceeds the threshold."""

    def __init__(self, threshold_mb: int = 2048, window: float = 600.0) -> None:
        self.threshold = threshold_mb * 1024 * 1024
        self.window = window
        self.samples: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self.alerted: dict[str, float] = {}

    def add(self, user: str, uploaded: int, ts: float) -> int | None:
        """Returns the uploaded byte total when the threshold is crossed."""
        samples = self.samples[user]
        samples.append((ts, max(uploaded, 0)))
        while samples and ts - samples[0][0] > self.window:
            samples.popleft()
        total = sum(b for _, b in samples)
        last = self.alerted.get(user)
        if total >= self.threshold and (last is None or ts - last > self.window):
            self.alerted[user] = ts
            return total
        return None


class AuthFailureCounter:
    """Counts failed handshakes per source address within a window."""

    def __init__(self, threshold: int = 5, window: float = 300.0) -> None:
        self.threshold = threshold
        self.window = window
        self.events: dict[str, deque[float]] = defaultdict(deque)

    def add(self, real_ip: str, ts: float) -> int | None:
        events = self.events[real_ip]
        events.append(ts)
        while events and ts - events[0] > self.window:
            events.popleft()
        if len(events) >= self.threshold:
            count = len(events)
            events.clear()
            return count
        return None


class Deduper:
    """Suppresses identical events seen again within ttl seconds."""

    def __init__(self, ttl: float) -> None:
        self.ttl = ttl
        self.seen: dict[tuple, float] = {}

    def fresh(self, key: tuple, ts: float, ttl: float | None = None) -> bool:
        ttl = self.ttl if ttl is None else ttl
        last = self.seen.get(key)
        if last is not None and ts - last < ttl:
            return False
        self.seen[key] = ts
        if len(self.seen) > 10000:
            self.seen = {k: v for k, v in self.seen.items() if ts - v < max(self.ttl, ttl)}
        return True
