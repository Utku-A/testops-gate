# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""What to hand a VPN user: sign-in details, where the profile is and how to get it."""

from __future__ import annotations

from testops_gate.config import Config
from testops_gate.i18n import T
from testops_gate.paths import P


def profile_path(name: str) -> str:
    return str(P.profiles_dir / f"{name}.ovpn")


def password_label(cfg: Config) -> str:
    return T("Profile password") if cfg.auth.mode == "profile-password" else T("Password")


def details(cfg: Config, name: str, password: str = "") -> list[tuple[str, str]]:
    """(label, value) rows; an empty label continues the previous row."""
    rows = [(T("User"), name)]
    if password:
        rows.append((password_label(cfg), password))
    rows += [
        (T("Profile"), profile_path(name)),
        (T("Get it"), f"sudo testops-gate user export {name} -o ~/"),
        ("", f"scp <you>@{cfg.server.endpoint}:{name}.ovpn ."),
    ]
    return rows


def connect_hint(cfg: Config) -> str:
    clients = "OpenVPN Connect, openvpn, Tunnelblick"
    if cfg.auth.mode == "user-password":
        return T("Import the profile into an OpenVPN client ({clients}); it asks for the username and password.",
                 clients=clients)
    if cfg.auth.mode == "profile-password":
        return T("Import the profile into an OpenVPN client ({clients}); it asks for the profile password.",
                 clients=clients)
    return T("Import the profile into an OpenVPN client ({clients}).", clients=clients)


def password_note(cfg: Config) -> str:
    if cfg.auth.mode == "profile-password":
        return T("Shown once. The password is needed to use the profile; a new password means a new profile.")
    return T("Shown once: the server keeps only a hash. Set a new one with: testops-gate user passwd NAME")
