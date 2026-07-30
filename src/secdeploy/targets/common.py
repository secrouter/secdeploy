"""Shared target helpers — fetching pinned component checkouts."""

from __future__ import annotations

from pathlib import Path

from .. import process as P
from ..manifest import Manifest


def fetch(manifest: Manifest, work_dir: Path, only: str | None = None) -> Path:
    """Clone/checkout every component at its pinned ref into ``work_dir/<name>``.

    Run this on a network-connected build host; the resulting checkouts (and the
    artifacts built from them) are what get bundled for air-gapped transfer.
    """
    if not P.which("git"):
        P.die("git is required to fetch components")
    work_dir.mkdir(parents=True, exist_ok=True)
    for name, c in manifest.components.items():
        if only and name != only:
            continue
        dest = work_dir / name
        if (dest / ".git").exists():
            P.run(["git", "-C", str(dest), "fetch", "--tags", "--quiet", "origin"])
        else:
            P.run(["git", "clone", "--quiet", c.url, str(dest)])
        P.run(["git", "-C", str(dest), "-c", "advice.detachedHead=false", "checkout", "--quiet", c.ref])
        sha = P.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture=True).stdout.strip()
        P.log(f"{name} @ {c.ref} → {sha[:12]}")
    return work_dir


def resolved_shas(manifest: Manifest, work_dir: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in manifest.components:
        dest = work_dir / name
        if (dest / ".git").exists():
            out[name] = P.run(
                ["git", "-C", str(dest), "rev-parse", "HEAD"], capture=True
            ).stdout.strip()
    return out


def require_checkouts(manifest: Manifest, work_dir: Path) -> None:
    missing = [n for n in manifest.components if not (work_dir / n).exists()]
    if missing:
        P.die(f"missing checkouts: {', '.join(missing)} — run `secdeploy fetch` first")
