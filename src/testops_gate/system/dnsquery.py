# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Minimal DNS client used for the "DNS test" in the dashboard (no dig needed)."""

from __future__ import annotations

import secrets
import socket
import struct
import time
from dataclasses import dataclass

TYPE_A, TYPE_CNAME = 1, 5
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


@dataclass
class Answer:
    rcode: str
    records: list[tuple[str, str]]  # (type, value)
    elapsed_ms: float


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("idna")
    return out + b"\x00"


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped_end = None
    for _ in range(128):
        length = data[offset]
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            jumped_end = jumped_end or offset + 2
            offset = pointer
            continue
        if length == 0:
            offset += 1
            break
        labels.append(data[offset + 1:offset + 1 + length].decode("idna", errors="replace"))
        offset += 1 + length
    return ".".join(labels), (jumped_end or offset)


def query(server: str, name: str, qtype: int = TYPE_A, timeout: float = 2.0) -> Answer:
    ident = secrets.randbelow(65536)
    packet = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + _encode_name(name) + struct.pack("!HH", qtype, 1)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        while True:
            data, _ = sock.recvfrom(4096)
            if len(data) >= 12 and struct.unpack("!H", data[:2])[0] == ident:
                break
    elapsed = (time.monotonic() - started) * 1000
    _, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4
    records = []
    for _ in range(ancount):
        _, offset = _read_name(data, offset)
        rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        if rtype == TYPE_A and rdlength == 4:
            records.append(("A", socket.inet_ntoa(data[offset:offset + 4])))
        elif rtype == TYPE_CNAME:
            records.append(("CNAME", _read_name(data, offset)[0]))
        offset += rdlength
    return Answer(RCODES.get(flags & 0x0F, str(flags & 0x0F)), records, elapsed)
