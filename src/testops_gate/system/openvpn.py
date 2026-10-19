# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""OpenVPN management interface client.

The server listens on a unix socket (see render.openvpn). We use `status 3`
for the connected client list, `kill <cn>` to drop a session and
`client-kill <id> RESTART` to make a client reconnect at once (its new ccd
settings apply; with username + password it signs in again with its session token).
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path

from testops_gate.paths import P


@dataclass
class ClientStatus:
    name: str
    real_ip: str
    vpn_ip: str
    bytes_received: int  # from the client (upload)
    bytes_sent: int  # to the client (download)
    connected_since: float
    client_id: int = -1


class ManagementError(RuntimeError):
    pass


class Management:
    def __init__(self, path: Path | None = None, timeout: float = 3.0) -> None:
        self.path = path or P.mgmt_socket
        self.timeout = timeout

    def command(self, cmd: str) -> list[str]:
        """Send one command and return its response lines."""
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(str(self.path))
                reader = sock.makefile("r", encoding="utf-8", errors="replace")
                sock.sendall(f"{cmd}\n".encode())
                lines: list[str] = []
                for raw in reader:
                    line = raw.rstrip("\r\n")
                    if line.startswith(">"):  # real-time notifications, e.g. the >INFO banner
                        continue
                    lines.append(line)
                    if line == "END" or line.startswith(("SUCCESS:", "ERROR:")):
                        break
                sock.sendall(b"quit\n")
                return lines
        except OSError as exc:
            raise ManagementError(str(exc)) from exc

    def kill(self, name: str) -> bool:
        lines = self.command(f"kill {name}")
        return any(line.startswith("SUCCESS") for line in lines)

    def status(self) -> list[ClientStatus]:
        return parse_status(self.command("status 3"))

    def restart(self, name: str) -> bool:
        """Tell a connected user's client to reconnect now; False if not connected."""
        done = False
        for client in self.status():
            if client.name == name and client.client_id >= 0:
                lines = self.command(f"client-kill {client.client_id} RESTART")
                done |= any(line.startswith("SUCCESS") for line in lines)
        return done


def read_status_file(path: Path | None = None) -> tuple[list[ClientStatus], float] | None:
    """Clients from the status file OpenVPN rewrites every few seconds, and its age in seconds."""
    import time

    path = path or P.status_file
    try:
        text = path.read_text(errors="replace")
        age = time.time() - path.stat().st_mtime
    except OSError:
        return None
    return parse_status(text.splitlines()), age


def parse_status(lines: list[str]) -> list[ClientStatus]:
    clients = []
    for line in lines:
        if not line.startswith("CLIENT_LIST\t"):
            continue
        cols = line.split("\t")
        # CLIENT_LIST, CN, Real Address, Virtual Address, Virtual IPv6, Bytes Received, Bytes Sent,
        # Connected Since, Connected Since (time_t), Username, Client ID, Peer ID, Cipher
        if len(cols) < 9 or cols[1] == "UNDEF":
            continue
        clients.append(
            ClientStatus(
                name=cols[1],
                real_ip=cols[2].rsplit(":", 1)[0],
                vpn_ip=cols[3],
                bytes_received=int(cols[5] or 0),
                bytes_sent=int(cols[6] or 0),
                connected_since=float(cols[8] or 0),
                client_id=int(cols[10]) if len(cols) > 10 and cols[10].isdigit() else -1,
            )
        )
    return clients
