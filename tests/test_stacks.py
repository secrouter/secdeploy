"""Stack (.env) secret auto-seeding — see targets/common._seed_env_secrets / deploy_stacks.

Regression guard for the macOS/fedora deploy failing with `required variable POSTGRES_PASSWORD
is missing a value` when a stack's .env carried blank required secrets. deploy_stacks now
generates a strong random value for each blank required key before the bootstrap `compose up`.
"""

from __future__ import annotations

import stat
from pathlib import Path

from secdeploy.targets import common


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _val(body: str, key: str) -> str:
    line = next(ln for ln in body.splitlines() if ln.startswith(f"{key}="))
    return line.split("=", 1)[1]


# ── _seed_env_secrets (pure) ─────────────────────────────────────────────────────────────
def test_seed_fills_only_blank_keys_leaving_config_and_comments():
    text = (
        "# SecSSO — copy to .env\n"
        "PG_USER=authentik\n"       # has a default → config, untouched
        "PG_PASS=\n"                # blank → secret, filled
        "AUTHENTIK_SECRET_KEY=   \n"  # blank + trailing whitespace → still filled
        "MM_GITLAB_ENABLE=false\n"  # untouched
    )
    new, generated = common._seed_env_secrets(text)

    assert generated == ["PG_PASS", "AUTHENTIK_SECRET_KEY"]
    assert "# SecSSO — copy to .env" in new
    assert "PG_USER=authentik" in new
    assert "MM_GITLAB_ENABLE=false" in new
    assert _val(new, "PG_PASS")            # non-empty now
    assert _val(new, "AUTHENTIK_SECRET_KEY")


def test_seed_tokens_are_compose_safe():
    # token_urlsafe is [A-Za-z0-9_-] only — no $ (compose interpolation) / ; / whitespace.
    new, generated = common._seed_env_secrets("A=\nB=\nC=\n")
    assert generated == ["A", "B", "C"]
    for key in generated:
        v = _val(new, key)
        assert v and not any(ch in v for ch in "$; \t")


def test_seed_is_idempotent():
    once, gen1 = common._seed_env_secrets("PG_PASS=\nPG_USER=authentik\n")
    twice, gen2 = common._seed_env_secrets(once)
    assert gen1 == ["PG_PASS"]
    assert gen2 == []          # nothing blank the second time
    assert once == twice       # stable text — a live password is never rotated


# ── deploy_stacks (creates .env, seeds, brings up) ───────────────────────────────────────
def _stack(work: Path, name: str, example: str) -> Path:
    boot = work / name / "bootstrap" / f"{name}.sh"
    _write(boot, "#!/bin/bash\nexit 0\n")   # no-op bootstrap so `up` is harmless
    boot.chmod(0o755)
    _write(work / name / ".env.example", example)
    return work / name / ".env"


def test_deploy_stacks_creates_and_seeds_env_0600(tmp_path):
    work = tmp_path / "work"
    env = _stack(work, "secchat", "POSTGRES_USER=mmuser\nPOSTGRES_PASSWORD=\n")

    common.deploy_stacks(work, ["secchat"], dry_run=False)

    assert env.exists()
    assert _val(env.read_text(), "POSTGRES_PASSWORD")               # the failing var, now filled
    assert stat.S_IMODE(env.stat().st_mode) == 0o600               # gitignored + owner-only


def test_deploy_stacks_preserves_operator_set_values(tmp_path):
    work = tmp_path / "work"
    env = _stack(work, "secsso", "PG_PASS=\n")
    env.write_text("PG_PASS=operator-chosen\n")   # operator pre-filled

    common.deploy_stacks(work, ["secsso"], dry_run=False)

    assert "PG_PASS=operator-chosen" in env.read_text()


def test_deploy_stacks_stable_across_redeploys(tmp_path):
    work = tmp_path / "work"
    env = _stack(work, "secsso", "PG_PASS=\nAUTHENTIK_SECRET_KEY=\n")

    common.deploy_stacks(work, ["secsso"], dry_run=False)
    first = env.read_text()
    common.deploy_stacks(work, ["secsso"], dry_run=False)   # redeploy
    assert env.read_text() == first                         # no rotation


def test_deploy_stacks_dry_run_writes_nothing(tmp_path, capsys):
    work = tmp_path / "work"
    env = _stack(work, "secsso", "PG_PASS=\n")

    common.deploy_stacks(work, ["secsso"], dry_run=True)

    assert not env.exists()
    assert "auto-generate" in capsys.readouterr().out


# ── ensure_stack_secrets: deploy_stacks' seeding half, callable standalone ───────────────
def test_ensure_stack_secrets_creates_and_seeds_without_bringing_up(tmp_path):
    work = tmp_path / "work"
    env = _stack(work, "secsso", "SECAGENT_SERVICE_CLIENT_SECRET=\nPG_USER=authentik\n")

    common.ensure_stack_secrets(work, ["secsso"])

    assert env.exists()
    assert _val(env.read_text(), "SECAGENT_SERVICE_CLIENT_SECRET")
    assert stat.S_IMODE(env.stat().st_mode) == 0o600


def test_deploy_stacks_seeding_is_a_noop_after_ensure_stack_secrets(tmp_path):
    """A caller that seeds early (see targets/macos.py's secagent block) must not have
    deploy_stacks' own later pass generate a SECOND, different value — the whole point of
    reading the secret back before bring-up is that it's already the final one."""
    work = tmp_path / "work"
    env = _stack(work, "secsso", "SECAGENT_SERVICE_CLIENT_SECRET=\n")

    common.ensure_stack_secrets(work, ["secsso"])
    seeded = _val(env.read_text(), "SECAGENT_SERVICE_CLIENT_SECRET")

    common.deploy_stacks(work, ["secsso"], dry_run=False)
    assert _val(env.read_text(), "SECAGENT_SERVICE_CLIENT_SECRET") == seeded
