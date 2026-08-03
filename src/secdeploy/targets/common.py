"""Shared target helpers — fetching pinned component checkouts + bringing up stacks."""

from __future__ import annotations

import shutil
from pathlib import Path

from .. import process as P
from ..manifest import Manifest


def deploy_stacks(work: Path, stacks: list[str], dry_run: bool = False) -> None:
    """Bring up ``stack`` components via each checkout's ``bootstrap/<name>.sh up``.

    Stack components (SecSSO/SecChat) carry their own Compose topology + a bootstrap script.
    Their ``.env`` holds operator secrets, so the first deploy writes it from ``.env.example``
    and stops — you set the secrets, then re-run (or run the bootstrap yourself). Once the
    ``.env`` exists we invoke the bootstrap, which does the compose up + wiring.
    """
    for name in stacks:
        proj = work / name
        boot = proj / "bootstrap" / f"{name}.sh"
        env, example = proj / ".env", proj / ".env.example"
        if dry_run:
            print(f"  · stack {name}: ensure {proj}/.env (from .env.example if absent), "
                  f"then bootstrap/{name}.sh up")
            continue
        if not boot.exists():
            P.warn(f"stack {name}: no bootstrap/{name}.sh in {proj} — skipping")
            continue
        if not env.exists():
            if example.exists():
                shutil.copy(example, env)
                P.warn(f"stack {name}: wrote {env} from .env.example — set its secrets, "
                       f"then bring it up:  bash {boot} up")
            else:
                P.warn(f"stack {name}: no .env / .env.example in {proj} — configure it, "
                       f"then run:  bash {boot} up")
            continue
        P.log(f"stack {name}: bringing up via bootstrap/{name}.sh up")
        P.run(["bash", str(boot), "up"], check=False)


def fetch(
    manifest: Manifest,
    work_dir: Path,
    only: str | None = None,
    include: set[str] | None = None,
) -> Path:
    """Clone/checkout every component at its pinned ref into ``work_dir/<name>``.

    ``include`` (if given) restricts to that set of component names — used by ``--without``.
    Run this on a network-connected build host; the resulting checkouts (and the
    artifacts built from them) are what get bundled for air-gapped transfer.
    """
    if not P.which("git"):
        P.die("git is required to fetch components")
    work_dir.mkdir(parents=True, exist_ok=True)
    for name, c in manifest.components.items():
        if only and name != only:
            continue
        if include is not None and name not in include:
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


def require_checkouts(
    manifest: Manifest, work_dir: Path, include: set[str] | None = None
) -> None:
    names = include if include is not None else set(manifest.components)
    missing = [n for n in names if not (work_dir / n).exists()]
    if missing:
        P.die(f"missing checkouts: {', '.join(missing)} — run `secdeploy fetch` first")
