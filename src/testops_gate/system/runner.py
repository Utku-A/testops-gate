# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Halis Utku Aladağ (TestOps Center, https://testopscenter.com)

"""Running external commands.

Everything that touches the system goes through run(); tests swap in a runner
that records commands instead of executing them (set_runner).
"""

from __future__ import annotations

import os
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass


@dataclass
class Result:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class CommandError(RuntimeError):
    def __init__(self, cmd: Sequence[str], result: Result) -> None:
        self.cmd = list(cmd)
        self.result = result
        detail = (result.stderr or result.stdout).strip().splitlines()
        super().__init__(f"{' '.join(self.cmd)} failed ({result.returncode}): {detail[-1] if detail else ''}")


class Runner:
    def run(
        self,
        cmd: Sequence[str],
        *,
        check: bool = True,
        input: str | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout: float | None = 600,
    ) -> Result:
        raise NotImplementedError


class SystemRunner(Runner):
    def run(self, cmd, *, check=True, input=None, env=None, cwd=None, timeout=600) -> Result:
        try:
            proc = subprocess.run(
                list(cmd),
                input=input,
                capture_output=True,
                text=True,
                env={**os.environ, **env} if env else None,
                cwd=cwd,
                timeout=timeout,
            )
            result = Result(proc.returncode, proc.stdout, proc.stderr)
        except FileNotFoundError as exc:
            result = Result(127, "", str(exc))
        except subprocess.TimeoutExpired:
            result = Result(124, "", "timeout")
        if check and not result.ok:
            raise CommandError(cmd, result)
        return result


_runner: Runner = SystemRunner()


def set_runner(runner: Runner) -> None:
    global _runner
    _runner = runner


def run(cmd: Sequence[str], **kwargs) -> Result:
    return _runner.run(cmd, **kwargs)
