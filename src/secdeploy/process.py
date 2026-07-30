"""Small subprocess + logging helpers shared by the CLI and targets."""

from __future__ import annotations

import shlex
import subprocess
import sys
from shutil import which as _which

_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_RESET = "\033[0m"


def log(msg: str) -> None:
    print(f"{_CYAN}▸{_RESET} {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"{_YELLOW}!{_RESET} {msg}", file=sys.stderr)


def die(msg: str, code: int = 1) -> "NoReturn":  # type: ignore[name-defined]
    print(f"{_RED}✗{_RESET} {msg}", file=sys.stderr)
    raise SystemExit(code)


def which(name: str) -> str | None:
    return _which(name)


def run(
    cmd: list[str],
    cwd=None,
    check: bool = True,
    capture: bool = False,
    env=None,
) -> subprocess.CompletedProcess:
    log(" ".join(shlex.quote(c) for c in cmd))
    return subprocess.run(
        cmd, cwd=cwd, check=check, text=True, capture_output=capture, env=env
    )
