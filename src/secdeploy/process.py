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


def confirm(prompt: str, assume_yes: bool = False) -> bool:
    """Ask before a step that needs sudo / touches shared system state (/etc/hosts, the
    System keychain). `assume_yes` (CLI: -y/--yes) grants blanket consent up front for
    unattended runs — it doesn't touch sudo's own password prompt, just this ask."""
    if assume_yes:
        log(f"{prompt} — proceeding (--yes)")
        return True
    try:
        reply = input(f"{_YELLOW}?{_RESET} {prompt} [y/N] ").strip().lower()
    except EOFError:
        warn(f"{prompt} — no TTY to ask; declining (pass -y/--yes to skip this ask)")
        return False
    return reply in ("y", "yes")


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
