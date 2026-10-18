# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""PKI management with the distribution's easy-rsa package.

The PKI lives in /etc/testops-gate/pki; easy-rsa itself is run from
/usr/share/easy-rsa. ECDSA (prime256v1) keys, as in the original script.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from testops_gate.paths import P
from testops_gate.system.runner import run

CA_DAYS = 3650
SERVER_DAYS = 3650
CRL_DAYS = 180


class EasyRSA:
    def __init__(self, pki: Path | None = None) -> None:
        self.pki = pki or P.pki_dir

    def _env(self, **extra: str) -> dict[str, str]:
        return {
            "EASYRSA": str(P.easyrsa_dir),
            "EASYRSA_PKI": str(self.pki),
            "EASYRSA_BATCH": "1",
            "EASYRSA_ALGO": "ec",
            "EASYRSA_CURVE": "prime256v1",
            "EASYRSA_DIGEST": "sha256",
            **extra,
        }

    def _run(self, *args: str, **env: str) -> None:
        run([str(P.easyrsa_dir / "easyrsa"), *args], env=self._env(**env), cwd=str(P.easyrsa_dir))

    # --- files ---------------------------------------------------------------

    @property
    def ca_cert(self) -> Path:
        return self.pki / "ca.crt"

    @property
    def crl(self) -> Path:
        return self.pki / "crl.pem"

    def cert(self, name: str) -> Path:
        return self.pki / "issued" / f"{name}.crt"

    def key(self, name: str) -> Path:
        return self.pki / "private" / f"{name}.key"

    # --- operations ----------------------------------------------------------

    def initialised(self) -> bool:
        return self.ca_cert.exists()

    def init(self, ca_cn: str) -> None:
        self._run("init-pki")
        self._run("build-ca", "nopass", EASYRSA_REQ_CN=ca_cn, EASYRSA_CA_EXPIRE=str(CA_DAYS))

    def build_server(self, name: str) -> None:
        self._run("build-server-full", name, "nopass", EASYRSA_CERT_EXPIRE=str(SERVER_DAYS))

    def build_client(self, name: str, days: int) -> None:
        self._run("build-client-full", name, "nopass", EASYRSA_CERT_EXPIRE=str(days))

    def revoke(self, name: str) -> None:
        self._run("revoke", name)

    def gen_crl(self) -> None:
        self._run("gen-crl", EASYRSA_CRL_DAYS=str(CRL_DAYS))

    def remove_issued(self, name: str) -> None:
        """Drop the files of a revoked certificate so the name can be issued again."""
        for path in (self.cert(name), self.key(name), self.pki / "reqs" / f"{name}.req"):
            path.unlink(missing_ok=True)

    def client_pem(self, name: str) -> str:
        """Certificate block only (issued files may contain a text dump before it)."""
        text = self.cert(name).read_text()
        match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
        return match.group(0) if match else text


def _openssl_date(cmd: list[str], field: str) -> datetime | None:
    out = run(cmd, check=False).stdout
    match = re.search(rf"{field}=(.+)", out)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1).strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def crl_next_update(path: Path) -> datetime | None:
    return _openssl_date(["openssl", "crl", "-noout", "-nextupdate", "-in", str(path)], "nextUpdate")
