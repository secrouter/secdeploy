"""Shared target helpers — fetching pinned component checkouts + bringing up stacks."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import NamedTuple

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


# ── teardown plan/render/execute — shared by targets/fedora_fips.py + targets/macos.py ─────
#
# Both targets split their `teardown` the same way (see each module's own teardown section):
# a `_discover()` that probes the live host (host-dependent, not unit-tested directly), a pure
# `teardown_plan(found, purge)` that turns that discovery into an ORDERED list of `Step`s (unit-
# tested with synthetic `found` values — no host probing needed to test the plan/ordering/
# gating logic), and a `teardown()` that wires the two together with the print-plan/confirm/
# execute flow below. Neither target drives its plan off topology.toml/deploy flags/the audit
# JSON — see each module's teardown docstring for why (deploy is purely additive, so the live
# host may be a superset of any one of those).
class Step(NamedTuple):
    """One line of a teardown plan: a human description, the exact reverse command (``None``
    for a print-only note — nothing to execute, e.g. macOS's native-service guidance or the
    "NOT removed" packages list), and a category. Categories group the printed plan and let
    ``execute_teardown_plan`` gate a subset of them behind their own extra confirmation."""

    description: str
    command: list[str] | None
    category: str


def render_teardown_plan(steps: list[Step]) -> None:
    """Print an ordered teardown plan, grouped by category as it changes — the discovered
    fact plus the exact reverse command for each step (or just the note, when there's nothing
    to run). Mirrors the dry-run step printing every target's own ``deploy()`` already uses."""
    prev_category: str | None = None
    for desc, cmd, category in steps:
        if category != prev_category:
            print(f"\n[{category.replace('_', ' ')}]")
            prev_category = category
        print(f"  · {desc}" + (f"\n      {' '.join(cmd)}" if cmd else ""))


def execute_teardown_plan(
    steps: list[Step], assume_yes: bool = False, gated: dict[str, str] | None = None,
) -> None:
    """Run each step's command in order (note-only entries — ``command is None`` — were
    already rendered by :func:`render_teardown_plan`; there's nothing to execute for them).

    ``gated`` maps a category name to an extra confirmation prompt that must be answered
    (via :func:`secdeploy.process.confirm`) before THAT step's command runs, layered on top
    of whatever confirmation the caller already obtained for the plan as a whole — e.g.
    macOS's ``/etc/hosts`` line, which another program may also own. ``assume_yes`` bypasses
    these too, same as every other ``P.confirm`` call in secdeploy.

    Tolerates a failing step (``P.run(..., check=False)``): teardown is inherently best-
    effort (the host may already be partway torn down by a prior run, or by hand), so one
    already-gone piece shouldn't abort everything after it — the failure is reported and
    execution continues.
    """
    for desc, cmd, category in steps:
        if not cmd:
            continue
        prompt = (gated or {}).get(category)
        if prompt and not P.confirm(prompt, assume_yes):
            P.warn(f"skipped: {desc}")
            continue
        P.log(desc)
        result = P.run(cmd, check=False)
        if result.returncode != 0:
            P.warn(f"non-zero exit, continuing teardown: {desc}")


def audit_drift_note(out_dir: Path, target: str) -> str | None:
    """Best-effort ONLY: if a prior deploy's audit artifact (:mod:`secdeploy.audit`) exists
    under ``out_dir``, return a short courtesy note naming what IT recorded, for a target's
    ``teardown()`` to print ALONGSIDE its own discovery. This NEVER decides what's in the
    teardown plan — it only annotates it, since deploy is purely additive and the audit only
    ever describes ONE past deploy invocation, never the live host's actual superset state
    (see each target's teardown docstring). Any problem reading/parsing it (``out_dir``
    doesn't exist, no audit was ever written, a stale or malformed file) just means no note —
    never an error; teardown must never depend on this file being present or well-formed.
    """
    try:
        matches = sorted(Path(out_dir).glob(f"audit/deploy-{target}-*.json"))
        if not matches:
            return None
        latest = matches[-1]
        record = json.loads(latest.read_text())
        names = sorted(c["name"] for c in record.get("components", []))
        return (
            f"audit drift note (informational only, never the driver): {latest} recorded "
            f"components {names or '(none)'} as of {record.get('generated_at', '?')} — "
            "compare against what teardown discovered above."
        )
    except (OSError, ValueError, KeyError, TypeError):
        return None
