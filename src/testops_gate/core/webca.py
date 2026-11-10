# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Certificate authority for web hosts (HTTPS on names such as dev.internal).

No public CA issues certificates for private names, so the VPN has its own: VPN users install its
certificate once per device and every web host is then trusted. It is separate from the OpenVPN
CA and constrained to the VPN domain (X.509 name constraints): a device that trusts it does not
trust it for any other site, whatever happens to its key.

One certificate covers every web host (subjectAltName); it is issued again when the set of names
changes and before it expires.
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import tempfile
import time
from pathlib import Path

from testops_gate.config import Config
from testops_gate.i18n import T
from testops_gate.paths import P
from testops_gate.system.runner import run

CA_DAYS = 3650
CERT_DAYS = 397  # browsers refuse server certificates valid for longer
RENEW_BEFORE = 30 * 86400

CA_CNF = """[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
O = TestOps Gate
CN = {cn}
[v3]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
nameConstraints = critical, permitted;DNS:{domain}
"""

CERT_CNF = """[req]
distinguished_name = dn
prompt = no
[dn]
CN = {cn}
[leaf]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = {sans}
"""


def _key(path: Path) -> None:
    run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(path)])
    os.chmod(path, 0o600)


def ensure_ca(cfg: Config) -> bool:
    """Create the web CA on first use; True if it was created."""
    if P.webca_cert.exists() and P.webca_key.exists():
        return False
    P.webca_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(P.webca_dir, 0o700)
    cnf = P.webca_dir / "ca.cnf"
    cnf.write_text(CA_CNF.format(cn=f"TestOps Gate Web CA ({cfg.server.endpoint})"[:64], domain=cfg.nodes.domain))
    _key(P.webca_key)
    run(["openssl", "req", "-x509", "-new", "-sha256", "-key", str(P.webca_key), "-days", str(CA_DAYS),
         "-config", str(cnf), "-out", str(P.webca_cert)])
    os.chmod(P.webca_cert, 0o644)
    return True


def issue(names: list[str]) -> None:
    """One certificate for all `names`, written with its key as HAProxy reads it."""
    P.proxy_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(P.proxy_dir, 0o750)
    with tempfile.TemporaryDirectory(dir=P.proxy_dir) as tmp:
        work = Path(tmp)
        key, csr, crt, cnf = work / "key.pem", work / "req.csr", work / "cert.crt", work / "cert.cnf"
        cnf.write_text(CERT_CNF.format(cn=names[0][:64], sans=", ".join(f"DNS:{n}" for n in names)))
        _key(key)
        run(["openssl", "req", "-new", "-key", str(key), "-config", str(cnf), "-out", str(csr)])
        run(["openssl", "x509", "-req", "-sha256", "-in", str(csr), "-CA", str(P.webca_cert), "-CAkey",
             str(P.webca_key), "-CAcreateserial", "-days", str(CERT_DAYS), "-extfile", str(cnf), "-extensions",
             "leaf", "-out", str(crt)])
        pem = P.proxy_cert.with_name(".cert.pem.tmp")
        fd = os.open(pem, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(crt.read_text() + key.read_text())
        os.replace(pem, P.proxy_cert)
    P.proxy_cert_info.write_text(json.dumps({"names": names, "not_after": time.time() + CERT_DAYS * 86400}))


def info() -> dict:
    try:
        return json.loads(P.proxy_cert_info.read_text())
    except (OSError, ValueError):
        return {}


def expiring(now: float | None = None) -> bool:
    current = info()
    return bool(current) and current.get("not_after", 0) - (now or time.time()) < RENEW_BEFORE


def sync(cfg: Config, names: list[str]) -> bool:
    """Make the certificate cover exactly `names`; True if a new one was issued."""
    names = sorted(names)
    created = ensure_ca(cfg)
    if not created and P.proxy_cert.exists() and info().get("names") == names and not expiring():
        return False
    issue(names)
    return True


def fingerprint() -> str:
    """SHA-256 of the web CA certificate, as devices show it: AB:CD:..."""
    pem = P.webca_cert.read_text()
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem[pem.index("-----BEGIN"):])).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def install_steps() -> list[str]:
    """How a VPN user makes a device trust the web CA (once per device)."""
    return [
        T("Windows: double-click the file → Install Certificate → Local Machine → Trusted Root Certification "
          "Authorities"),
        T("macOS: double-click (Keychain Access) → open the certificate → Trust → Always Trust"),
        T("Linux: sudo cp testops-gate-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates"),
        T("Firefox (its own list): Settings → Certificates → View Certificates → Authorities → Import"),
        T("iOS: open the file → install the profile → Settings → General → About → Certificate Trust Settings"),
        T("Android: Settings → Security → Encryption & credentials → Install a certificate → CA certificate"),
    ]
