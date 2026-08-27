"""Shared target helpers — fetching pinned component checkouts + bringing up stacks."""

from __future__ import annotations

import json
import re
import secrets
import shutil
from pathlib import Path
from typing import NamedTuple

from .. import process as P
from ..manifest import Manifest

# A ``KEY=`` line whose value is empty (ignoring trailing whitespace) — the convention every
# stack ``.env.example`` uses to mark a REQUIRED secret the operator must fill (see
# ``secsso/.env.example``'s ``PG_PASS=``/``AUTHENTIK_SECRET_KEY=`` and ``secchat``'s
# ``POSTGRES_PASSWORD=``). :func:`_seed_env_secrets` fills exactly these; a key with any default
# value (``PG_USER=authentik``, ``MM_GITLAB_ENABLE=false``) is config, not a secret, and is left
# alone.
_ENV_BLANK_SECRET_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=[ \t]*$")


def _seed_env_secrets(text: str) -> tuple[str, list[str]]:
    """Fill every blank-valued ``KEY=`` line (see :data:`_ENV_BLANK_SECRET_RE`) with a strong
    random token, returning ``(new_text, generated_keys)``.

    Idempotent and non-destructive: a key that already has a value — an operator-set one, or a
    value THIS function generated on a prior deploy — is never touched, so re-running a deploy
    reads the same file back unchanged and a live stack's DB password/secret-key is never
    rotated out from under it. Comments and every other line pass through verbatim. Tokens use
    :func:`secrets.token_urlsafe` (``[A-Za-z0-9_-]`` only — no ``$`` or ``;`` that would break
    docker-compose ``.env`` interpolation, unlike an operator-typed value might).
    """
    lines = text.splitlines()
    generated: list[str] = []
    for i, line in enumerate(lines):
        m = _ENV_BLANK_SECRET_RE.match(line)
        if m:
            lines[i] = f"{m.group(1)}={secrets.token_urlsafe(36)}"
            generated.append(m.group(1))
    new_text = "\n".join(lines)
    if text.endswith("\n") or not text:
        new_text += "\n"
    return new_text, generated


def ensure_stack_secrets(work: Path, stacks: list[str]) -> None:
    """Ensure each stack's ``.env`` exists (from ``.env.example``) and every blank required
    secret in it is filled — the seeding half of :func:`deploy_stacks`, split out so a caller
    that needs a stack's generated secret BEFORE that stack's own bring-up runs later in the
    same deploy (e.g. SecAgent deriving its client secret from SecSSO's generated
    ``SECAGENT_SVC_APP_PASSWORD`` — see targets/macos.py/fedora_fips.py) can seed it early without
    duplicating :func:`deploy_stacks`'s secret-generation logic. :func:`deploy_stacks` calls
    this too, so its own seeding pass is then just a no-op (values are already non-blank) —
    every value still originates from exactly one place.
    """
    for name in stacks:
        proj = work / name
        env, example = proj / ".env", proj / ".env.example"
        if not env.exists():
            if not example.exists():
                continue  # deploy_stacks' own pass below warns; nothing to seed yet
            shutil.copy(example, env)
            env.chmod(0o600)
            P.log(f"stack {name}: created {env} from .env.example")
        new_text, generated = _seed_env_secrets(env.read_text())
        if generated:
            env.write_text(new_text)
            env.chmod(0o600)
            P.log(f"stack {name}: generated {len(generated)} secret(s) in {env} "
                  f"({', '.join(generated)}) — stored 0600, gitignored, kept across redeploys "
                  f"(read them back from {env} if you need e.g. the Authentik admin credentials)")


def deploy_stacks(work: Path, stacks: list[str], dry_run: bool = False) -> None:
    """Bring up ``stack`` components via each checkout's ``bootstrap/<name>.sh up``.

    Stack components (SecSSO/SecChat) carry their own Compose topology + a bootstrap script.
    Their ``.env`` holds secrets (Postgres passwords, Authentik's secret key/bootstrap token).
    The first deploy writes ``.env`` from ``.env.example`` and then **auto-generates a strong
    random value for every required secret left blank** (the ``KEY=`` markers in the example —
    see :func:`_seed_env_secrets`), so the bootstrap's ``compose up`` doesn't fail on a
    ``required variable … is missing`` interpolation error. The filled ``.env`` is written
    ``0600`` and is gitignored; generation is idempotent (a value already set — by the operator
    or a prior deploy — is kept), so redeploys are stable and never rotate a live stack's
    password. An operator who wants specific values (a known Authentik admin password, a
    SecAgent client secret shared with SecAgent's own env) can still pre-fill ``.env`` before
    deploying; only blank keys are generated.
    """
    if not dry_run:
        ensure_stack_secrets(work, stacks)
    for name in stacks:
        proj = work / name
        boot = proj / "bootstrap" / f"{name}.sh"
        env, example = proj / ".env", proj / ".env.example"
        if dry_run:
            print(f"  · stack {name}: ensure {proj}/.env (from .env.example; auto-generate a "
                  f"strong secret for each blank required key), then bootstrap/{name}.sh up")
            continue
        if not boot.exists():
            P.warn(f"stack {name}: no bootstrap/{name}.sh in {proj} — skipping")
            continue
        if not env.exists():
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


# ── backup/restore scaffold — shared by targets/fedora_fips.py + targets/macos.py ─────────
#
# Reuses the `Step`/`render_teardown_plan` primitives above (a plan line is a plan line). Two
# differences from teardown: (1) stacks are derived DYNAMICALLY from the Manifest's declared
# `kind == "stack"`, not the hardcoded teardown `STACK_NAMES`, so a stack added to a future
# manifest is picked up for backup automatically; and
# (2) execution is FAIL-FAST (:func:`execute_capture_plan`) — a failed dump or a failed restore
# must abort, never leave a partial archive or a half-restored host, unlike teardown's
# tolerate-absence best-effort. Each target populates a throwaway staging dir via these steps,
# then hands it to :func:`secdeploy.backup.stage_to_encrypted_archive`.
def stack_checkouts(manifest: Manifest, work: Path) -> list[tuple[str, Path]]:
    """Every ``kind == "stack"`` component with a checkout present, as ``(name, bootstrap.sh)``.

    Derived from the Manifest's declared kinds — deliberately NOT the hardcoded teardown
    ``STACK_NAMES`` — so a stack added to a future manifest is picked up for backup
    automatically. Order follows the manifest's declaration order."""
    out: list[tuple[str, Path]] = []
    for name, c in manifest.components.items():
        if c.kind != "stack":
            continue
        boot = work / name / "bootstrap" / f"{name}.sh"
        if boot.exists():
            out.append((name, boot))
    return out


def stack_backup_steps(stacks: list[tuple[str, Path]], staging: Path) -> list[Step]:
    """One capture Step per stack: ``bash bootstrap/<name>.sh backup <staging>/stacks/<name>``
    (the verb dumps that stack's DB + uploads + ``.env`` into the dir — see each bootstrap)."""
    return [
        Step(f"stack {name}: dump DB + uploads + .env via bootstrap/{name}.sh backup",
             ["bash", str(boot), "backup", str(Path(staging) / "stacks" / name)], "stacks")
        for name, boot in stacks
    ]


def stack_restore_steps(stacks: list[tuple[str, Path]], unpacked: Path) -> list[Step]:
    """The inverse: ``bash bootstrap/<name>.sh restore <unpacked>/stacks/<name>`` per stack,
    skipping any whose dir isn't in the archive (that stack wasn't captured / wasn't placed)."""
    steps: list[Step] = []
    for name, boot in stacks:
        src = Path(unpacked) / "stacks" / name
        if not src.exists():
            continue
        steps.append(Step(
            f"stack {name}: load DB + uploads + .env via bootstrap/{name}.sh restore",
            ["bash", str(boot), "restore", str(src)], "stacks"))
    return steps


def execute_capture_plan(steps: list[Step]) -> None:
    """Run a backup CAPTURE or RESTORE plan **fail-fast** — the opposite of
    :func:`execute_teardown_plan`'s tolerate-absence. A failed ``pg_dump``/``mongodump`` or a
    failed load raises (``P.run(check=True)``) so the caller aborts and wipes staging rather
    than writing a partial, un-restorable archive or leaving a host half-restored. Note-only
    steps (``command is None``) are display-only, already shown by ``render_teardown_plan``."""
    for desc, cmd, _category in steps:
        if not cmd:
            continue
        P.log(desc)
        P.run(cmd, check=True)


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
