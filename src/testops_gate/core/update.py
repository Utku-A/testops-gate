# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Checking for and installing new releases.

A release publishes three files: VERSION (e.g. "0.2.0"), testops-gate_all.deb and
SHA256SUMS. They are read from testopscenter.com or from a mirror (updates.base_url).
The package is installed by apt, which replaces the running program, so the
caller runs the returned command last (CLI: exec, dashboard: after exiting).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tarfile
import time
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

from testops_gate import RELEASE_URL, __version__, logs
from testops_gate.config import Config
from testops_gate.i18n import T
from testops_gate.paths import P

ASSET = "testops-gate_all.deb"
CHECK_INTERVAL = 86400
TIMEOUT = 20
KEEP_BACKUPS = 5
USER_AGENT = f"testops-gate/{__version__}"


class UpdateError(RuntimeError):
    pass


@dataclass
class UpdateState:
    current: str
    latest: str = ""
    checked_at: float = 0.0
    error: str = ""

    @property
    def available(self) -> bool:
        return bool(self.latest) and parse_version(self.latest) > parse_version(self.current)


def parse_version(text: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", text.strip().lstrip("v"))
    return tuple(int(n) for n in numbers[:3]) or (0,)


def base_url(cfg: Config) -> str:
    if cfg.updates.base_url:
        return cfg.updates.base_url.rstrip("/")
    return f"{RELEASE_URL}/latest"


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as resp:
            return resp.read()
    except OSError as exc:
        raise UpdateError(f"{url}: {exc}") from exc


def load_state() -> UpdateState:
    try:
        data = json.loads(P.update_state.read_text())
        state = UpdateState(**{k: data[k] for k in ("current", "latest", "checked_at", "error") if k in data})
    except (OSError, ValueError, TypeError):
        state = UpdateState(current=__version__)
    state.current = __version__  # the installed program, not what was recorded
    return state


def save_state(state: UpdateState) -> None:
    P.update_state.parent.mkdir(parents=True, exist_ok=True)
    P.update_state.write_text(json.dumps(asdict(state)))


def check(cfg: Config, force: bool = False) -> UpdateState:
    """Look up the latest release (at most once a day unless forced)."""
    state = load_state()
    if not force and (not cfg.updates.check or time.time() - state.checked_at < CHECK_INTERVAL):
        return state
    state.checked_at = time.time()
    try:
        latest = _fetch(f"{base_url(cfg)}/VERSION").decode().strip()
        if not re.fullmatch(r"v?\d+(\.\d+){0,2}", latest):
            raise UpdateError(f"unexpected VERSION content: {latest[:40]!r}")
        state.latest, state.error = latest.lstrip("v"), ""
    except UpdateError as exc:
        state.error = str(exc)
    save_state(state)
    return state


def download(cfg: Config) -> Path:
    """Download the latest package and verify it against SHA256SUMS."""
    base = base_url(cfg)
    package = _fetch(f"{base}/{ASSET}")
    sums = _fetch(f"{base}/SHA256SUMS").decode(errors="replace")
    expected = next((line.split()[0] for line in sums.splitlines()
                     if line.strip().endswith(f" {ASSET}") or line.strip().endswith(f"*{ASSET}")), "")
    if not expected:
        raise UpdateError(T("SHA256SUMS has no entry for {asset}", asset=ASSET))
    if hashlib.sha256(package).hexdigest() != expected.lower():
        raise UpdateError(T("Checksum mismatch: the downloaded package was not installed"))
    P.updates_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(P.updates_dir, 0o755)  # apt reads the file as the _apt user
    target = P.updates_dir / ASSET
    target.write_bytes(package)
    os.chmod(target, 0o644)
    return target


def backup() -> Path:
    """Archive the configuration, PKI and state database before an update."""
    P.backups_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(P.backups_dir, 0o700)
    target = P.backups_dir / f"{time.strftime('%Y%m%d-%H%M%S')}-v{__version__}.tar.gz"
    with tarfile.open(target, "w:gz") as tar:
        if P.config_dir.exists():
            tar.add(P.config_dir, arcname="etc/testops-gate")
        if P.db_file.exists():
            tar.add(P.db_file, arcname="var/lib/testops-gate/state.db")
    os.chmod(target, 0o600)
    for old in sorted(P.backups_dir.glob("*.tar.gz"))[:-KEEP_BACKUPS]:
        old.unlink(missing_ok=True)
    return target


def prepare(cfg: Config, log=print) -> list[str]:
    """Download, verify and back up; returns the command that installs the update."""
    log(T("Downloading {asset}", asset=ASSET))
    package = download(cfg)
    log(T("Checksum verified"))
    archive = backup()
    log(T("Backup: {path}", path=archive))
    logs.audit("update", f"from={__version__} package={package}")
    return ["apt-get", "install", "-y", "--allow-downgrades", str(package)]
