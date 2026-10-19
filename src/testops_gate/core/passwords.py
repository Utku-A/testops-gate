# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""VPN passwords: generation, validation and scrypt hashes.

The hash format is read by the OpenVPN verify script (render/openvpn.py: AUTH_SCRIPT),
which repeats verify() without importing this package.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from testops_gate.i18n import T

# scrypt cost: ~16 MB and a few tens of milliseconds per check
N, R, PARALLEL = 2**14, 8, 1
MIN_LENGTH, MAX_LENGTH = 8, 128
# No look-alike characters (0/O, 1/l/I): the password is read off a screen and typed
ALPHABET = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class PasswordError(ValueError):
    pass


def generate(length: int = 16) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def validate(password: str) -> None:
    if len(password) < MIN_LENGTH:
        raise PasswordError(T("Password must be at least {n} characters", n=MIN_LENGTH))
    if len(password) > MAX_LENGTH:
        raise PasswordError(T("Password must be at most {n} characters", n=MAX_LENGTH))
    if any(ch in password for ch in "\r\n\0"):
        raise PasswordError(T("Password must not contain line breaks"))


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=N, r=R, p=PARALLEL, dklen=32)
    return f"scrypt${N}${R}${PARALLEL}${_b64(salt)}${_b64(digest)}"


def verify(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                                dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)
