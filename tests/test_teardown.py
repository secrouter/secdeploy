"""Tests for `secdeploy teardown` — the reverse of deploy().

Split to match the module's own (discover, teardown_plan, teardown) structure:

  * `teardown_plan()` is a PURE function (FedoraFound/MacosFound + purge -> ordered
    `common.Step`s), so most of this file exercises it directly with synthetic "found" values
    — no host probing, no subprocess calls, no real Fedora/macOS host needed.
  * A handful of CLI-level tests drive `main([...])` with `_discover` monkeypatched to a
    synthetic value, to prove the wiring (argument parsing -> target dispatch -> plan
    rendering) end to end, the same way test_cli.py exercises `deploy`/`plan`.
  * Confirm/--yes/--purge gating tests monkeypatch `builtins.input` (never rely on pytest's
    own stdin-capture behavior — see the module's own P.confirm) and `secdeploy.process.run`
    (never let a test invoke a REAL systemctl/userdel/rm/docker/sudo command).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from secdeploy.cli import main
from secdeploy.targets import common, fedora_fips, macos

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = str(ROOT / "suite.toml")


# ── synthetic "found" fixtures (no host probing) ────────────────────────────────────────
def _fedora_found_everything() -> fedora_fips.FedoraFound:
    return fedora_fips.FedoraFound(
        units=list(fedora_fips.ALL_UNIT_NAMES),
        users=list(fedora_fips.SERVICES),
        opt_dirs=list(fedora_fips.SERVICES),
        opt_root_exists=True,
        etc_exists=True,
        var_dirs=list(fedora_fips.SERVICES),
        var_root_exists=True,
        anchor_exists=True,
        resolver_dropin_exists=True,
        stacks=[
            ("secsso", Path("work/secsso/bootstrap/secsso.sh")),
            ("secchat", Path("work/secchat/bootstrap/secchat.sh")),
        ],
    )


def _fedora_found_nothing() -> fedora_fips.FedoraFound:
    return fedora_fips.FedoraFound(
        units=[], users=[], opt_dirs=[], opt_root_exists=False, etc_exists=False,
        var_dirs=[], var_root_exists=False, anchor_exists=False,
        resolver_dropin_exists=False, stacks=[],
    )


def _macos_found_everything(**overrides) -> macos.MacosFound:
    base = dict(
        docker_present=True,
        compose_cmd=["docker", "compose"],
        compose_file=Path("deploy/macos/compose.yaml"),
        compose_containers=True,
        compose_volumes=True,
        images=["secrouter/seccert:1.6.0", "secrouter/secrouter:1.6.0"],
        resolver_domains=["sec.internal"],
        domain_hint=None,
        hosts_line_present=True,
        keychain_cn="SecCert Root CA",
        out_exists=True,
        root=Path("/tmp/secdeploy-test-root"),
        stacks=[
            ("secsso", Path("work/secsso/bootstrap/secsso.sh")),
            ("secchat", Path("work/secchat/bootstrap/secchat.sh")),
        ],
    )
    base.update(overrides)
    return macos.MacosFound(**base)


def _macos_found_nothing() -> macos.MacosFound:
    return macos.MacosFound(
        docker_present=False, compose_cmd=["docker", "compose"], compose_file=None,
        compose_containers=False, compose_volumes=False, images=[],
        resolver_domains=[], domain_hint=None, hosts_line_present=False,
        keychain_cn=None, out_exists=False, root=Path("/tmp/secdeploy-test-root"),
        stacks=[],
    )


def _rendered(plan: list[common.Step]) -> str:
    """Flatten a plan to one searchable string (description + command), mirroring what
    render_teardown_plan actually prints."""
    return "\n".join(f"{d} {' '.join(c) if c else ''}" for d, c, _ in plan)


def _answers(*replies: str):
    """A fake `input()` that returns `replies` in sequence — mirrors test_configure.py's own
    `_driver` helper, adapted for confirm()'s `[y/N]` prompts instead of configure's wizard."""
    it = iter(replies)

    def _fake(_prompt: str = "") -> str:
        return next(it)

    return _fake


def _recorder():
    """A fake `process.run` that records every command instead of executing it, and returns
    a struct with `.returncode` (execute_teardown_plan inspects that field)."""
    calls: list[list[str]] = []

    def _fake_run(cmd, *_a, **_k):
        calls.append(cmd)
        return SimpleNamespace(returncode=0)

    return calls, _fake_run


# ═════════════════════════════════════════════════════════════════════════════════════════
# fedora-fips teardown_plan() — pure function tests
# ═════════════════════════════════════════════════════════════════════════════════════════
def test_fedora_plan_found_everything_names_every_reverse_action():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=False)
    text = _rendered(plan)
    # 1. services
    assert "secsuite.target" in text
    assert "systemctl disable --now secsuite.target" in text
    assert "systemctl stop secdns" in text
    assert "systemctl unmask secdns" in text
    assert "rm -f /etc/systemd/system/secdns.service" in text
    assert "systemctl daemon-reload" in text
    # 2. users
    assert "userdel secsuite-seccert" in text
    assert "userdel secsuite-secdns" in text
    # 3. code
    assert "rm -rf /opt/secsuite/secrouter" in text
    assert "rmdir /opt/secsuite" in text
    # 4. config
    assert "rm -rf /etc/secsuite" in text
    assert "SECCERT_CA_PASSPHRASE" in text  # the operator-secrets warning
    # 6. trust anchor
    assert "rm -f /etc/pki/ca-trust/source/anchors/secsuite-seccert-root.pem" in text
    assert "update-ca-trust extract" in text
    # 7. resolver
    assert "rm -f /etc/systemd/resolved.conf.d/secsuite.conf" in text
    assert "systemctl restart systemd-resolved" in text
    # 8. stacks
    assert "bootstrap/secsso.sh down" in text
    assert "bootstrap/secchat.sh down" in text
    # packages — NOT removed, only mentioned as a note
    assert "NOT removed" in text
    assert plan[-1].category == "packages"
    assert plan[-1].command is None


def test_fedora_plan_without_purge_never_mentions_var_lib():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=False)
    text = _rendered(plan)
    assert "/var/lib" not in text
    assert not any(s.category == "data" for s in plan)


def test_fedora_plan_with_purge_shows_data_and_ca_audit_warning():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=True)
    text = _rendered(plan)
    assert "/var/lib/secsuite" in text
    assert "rm -rf /var/lib/secsuite/seccert" in text
    assert "rm -rf /var/lib/secsuite/secagent" in text
    assert "rmdir /var/lib/secsuite" in text
    # the extra-loud CA/audit callouts
    assert "CA private key" in text
    assert "passphrase" in text
    assert "audit.jsonl" in text
    # secdns.zone note (regenerable, not precious)
    assert "secdns.zone" in text and "regenerable" in text
    # under --purge, stacks also wipe their data volume
    assert "bootstrap/secsso.sh down -v" in text


def test_fedora_plan_packages_note_lists_pi_and_never_a_command():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=False)
    packages = [s for s in plan if s.category == "packages"]
    assert len(packages) == 1
    assert packages[0].command is None
    assert "@earendil-works/pi-coding-agent" in packages[0].description
    assert "nginx" in packages[0].description


def test_fedora_plan_nothing_found_is_just_the_packages_note():
    plan = fedora_fips.teardown_plan(_fedora_found_nothing(), purge=True)
    assert len(plan) == 1
    assert plan[0].category == "packages"
    assert plan[0].command is None


# ── ORDER assertions (the explicit safety-critical sequencing) ─────────────────────────
def test_fedora_plan_order_stop_before_userdel_before_data():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=True)
    categories = [s.category for s in plan]
    last_services = max(i for i, c in enumerate(categories) if c == "services")
    first_users = min(i for i, c in enumerate(categories) if c == "users")
    first_data = min(i for i, c in enumerate(categories) if c == "data")
    assert last_services < first_users < first_data


def test_fedora_plan_order_rm_units_before_daemon_reload():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=False)
    rm_unit_indices = [
        i for i, s in enumerate(plan)
        if s.category == "services" and s.command and s.command[:2] == ["rm", "-f"]
    ]
    reload_idx = next(i for i, s in enumerate(plan) if s.command == ["systemctl", "daemon-reload"])
    assert rm_unit_indices  # sanity: some unit rm's actually happened
    assert all(i < reload_idx for i in rm_unit_indices)


def test_fedora_plan_order_rm_anchor_before_update_ca_trust():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=False)
    anchor_idx = next(
        i for i, s in enumerate(plan)
        if s.command and s.command[:2] == ["rm", "-f"] and "seccert-root.pem" in s.command[-1]
    )
    trust_idx = next(i for i, s in enumerate(plan) if s.command == ["update-ca-trust", "extract"])
    assert anchor_idx < trust_idx


def test_fedora_plan_order_services_before_code_before_config():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=False)
    categories_seen_order = []
    for s in plan:
        if not categories_seen_order or categories_seen_order[-1] != s.category:
            categories_seen_order.append(s.category)
    # exact top-level ordering from docs/fedora-fips.md#teardown
    assert categories_seen_order == [
        "services", "users", "code", "config", "trust anchor", "resolver", "stacks", "packages",
    ]


def test_fedora_plan_order_with_purge_inserts_data_between_config_and_trust_anchor():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=True)
    categories_seen_order = []
    for s in plan:
        if not categories_seen_order or categories_seen_order[-1] != s.category:
            categories_seen_order.append(s.category)
    assert categories_seen_order == [
        "services", "users", "code", "config", "data", "trust anchor", "resolver", "stacks",
        "packages",
    ]


def test_fedora_plan_userdel_has_no_dash_r():
    plan = fedora_fips.teardown_plan(_fedora_found_everything(), purge=True)
    userdels = [s.command for s in plan if s.command and s.command[0] == "userdel"]
    assert userdels
    for cmd in userdels:
        assert "-r" not in cmd


def test_fedora_plan_only_found_units_appear():
    found = fedora_fips.FedoraFound(
        units=["secrouter"],  # only ONE unit found — not secsuite.target, not the rest
        users=[], opt_dirs=[], opt_root_exists=False, etc_exists=False,
        var_dirs=[], var_root_exists=False, anchor_exists=False,
        resolver_dropin_exists=False, stacks=[],
    )
    plan = fedora_fips.teardown_plan(found, purge=False)
    text = _rendered(plan)
    assert "systemctl stop secrouter" in text
    assert "systemctl disable --now secsuite.target" not in text  # not found -> not planned
    assert "systemctl stop secdns" not in text
    assert "systemctl stop seccert" not in text


# ═════════════════════════════════════════════════════════════════════════════════════════
# macOS teardown_plan() — pure function tests
# ═════════════════════════════════════════════════════════════════════════════════════════
def test_macos_plan_found_everything_names_every_reverse_action():
    plan = macos.teardown_plan(_macos_found_everything(), purge=False)
    text = _rendered(plan)
    assert "docker compose -f deploy/macos/compose.yaml down" in text
    assert "down -v" not in text
    assert "docker rmi" not in text
    assert "/etc/resolver/sec.internal" in text
    assert "/etc/hosts" in text and "host.docker.internal" in text
    assert "System keychain" in text and "SecCert Root CA" in text
    assert "native" in text.lower() and "pkill" in text
    assert "IRREVERSIBLE" not in text  # --purge-only artifacts warning absent
    assert "NOT removed" in text


def test_macos_plan_with_purge_shows_downv_rmi_and_artifacts():
    plan = macos.teardown_plan(_macos_found_everything(), purge=True)
    text = _rendered(plan)
    assert "docker compose -f deploy/macos/compose.yaml down -v" in text
    assert "docker rmi secrouter/seccert:1.6.0" in text
    assert "docker rmi secrouter/secrouter:1.6.0" in text
    assert "IRREVERSIBLE" in text
    assert "secllm-shared-token" in text or "secagent-webhook-secret" in text


def test_macos_plan_without_purge_never_mentions_out_artifacts():
    plan = macos.teardown_plan(_macos_found_everything(), purge=False)
    assert not any(s.category == "artifacts" for s in plan)


def test_macos_plan_native_services_never_a_real_pkill_command():
    plan = macos.teardown_plan(_macos_found_everything(), purge=False)
    native = [s for s in plan if s.category == "native_services"]
    assert native
    assert all(s.command is None for s in native)  # documentation only — never auto-run
    assert any("secproxy" in s.description and "sudo pkill" in s.description for s in native)
    assert any("port" in s.description.lower() for s in native)  # the shared-port warning


def test_macos_plan_hosts_step_targets_exact_line_only():
    plan = macos.teardown_plan(_macos_found_everything(), purge=False)
    hosts_steps = [s for s in plan if s.category == "hosts"]
    assert len(hosts_steps) == 1
    cmd = hosts_steps[0].command
    assert cmd[:3] == ["sudo", "sed", "-i"]
    assert "/etc/hosts" == cmd[-1]
    # anchored whole-line match — never a bare substring strip
    assert cmd[-2].startswith("/^127\\.0\\.0\\.1") and cmd[-2].endswith("$/d")


def test_macos_plan_no_hosts_line_found_means_no_hosts_step():
    found = _macos_found_everything(hosts_line_present=False)
    plan = macos.teardown_plan(found, purge=False)
    assert not any(s.category == "hosts" for s in plan)


def test_macos_plan_keychain_absent_when_not_trusted():
    found = _macos_found_everything(keychain_cn=None)
    plan = macos.teardown_plan(found, purge=False)
    assert not any(s.category == "keychain" for s in plan)


def test_macos_plan_no_compose_step_when_nothing_docker_found():
    found = _macos_found_everything(compose_containers=False, compose_volumes=False)
    plan = macos.teardown_plan(found, purge=False)
    assert not any(s.category == "compose" and s.command for s in plan)


def test_macos_plan_resolver_single_entry_unambiguous_no_hint_needed():
    found = _macos_found_everything(domain_hint=None, resolver_domains=["sec.internal"])
    plan = macos.teardown_plan(found, purge=False)
    resolver_cmds = [s.command for s in plan if s.category == "resolver" and s.command]
    assert resolver_cmds == [["sudo", "rm", "-f", "/etc/resolver/sec.internal"]]


def test_macos_plan_resolver_ambiguous_prints_candidates_and_does_not_guess():
    found = _macos_found_everything(domain_hint=None,
                                    resolver_domains=["sec.internal", "other.example"])
    plan = macos.teardown_plan(found, purge=False)
    resolver_steps = [s for s in plan if s.category == "resolver"]
    assert all(s.command is None for s in resolver_steps)  # never guesses
    text = _rendered(resolver_steps)
    assert "sec.internal" in text and "other.example" in text
    assert "not guessing" in text


def test_macos_plan_resolver_hint_disambiguates():
    found = _macos_found_everything(domain_hint="other.example",
                                    resolver_domains=["sec.internal", "other.example"])
    plan = macos.teardown_plan(found, purge=False)
    resolver_cmds = [s.command for s in plan if s.category == "resolver" and s.command]
    assert resolver_cmds == [["sudo", "rm", "-f", "/etc/resolver/other.example"]]


def test_macos_plan_resolver_no_entries_means_no_resolver_step():
    found = _macos_found_everything(domain_hint=None, resolver_domains=[])
    plan = macos.teardown_plan(found, purge=False)
    assert not any(s.category == "resolver" for s in plan)


def test_macos_plan_nothing_found_is_native_services_note_plus_packages():
    plan = macos.teardown_plan(_macos_found_nothing(), purge=True)
    categories = {s.category for s in plan}
    assert categories == {"native_services", "packages"}
    assert all(s.command is None for s in plan)


def test_macos_plan_packages_note_is_brew_only_no_pi():
    plan = macos.teardown_plan(_macos_found_everything(), purge=False)
    packages = [s for s in plan if s.category == "packages"]
    assert len(packages) == 1
    assert "colima" in packages[0].description
    assert "pi-coding-agent" not in packages[0].description  # macOS never installs pi


# ═════════════════════════════════════════════════════════════════════════════════════════
# CLI-level dry-run tests — full wiring: argument parsing -> target dispatch -> rendering
# ═════════════════════════════════════════════════════════════════════════════════════════
def test_cli_teardown_fedora_dry_run(monkeypatch, capsys):
    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_everything())
    assert main(["--manifest", MANIFEST, "teardown", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "secsuite.target" in out
    assert "userdel secsuite-seccert" in out
    assert "rm -rf /opt/secsuite" in out
    assert "update-ca-trust" in out
    assert "resolved.conf.d/secsuite.conf" in out
    assert "bootstrap/secsso.sh down" in out
    assert "/var/lib" not in out
    assert "NOT removed" in out


def test_cli_teardown_fedora_dry_run_purge(monkeypatch, capsys):
    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_everything())
    assert main(["--manifest", MANIFEST, "teardown", "fedora-fips", "--dry-run", "--purge"]) == 0
    out = capsys.readouterr().out
    assert "/var/lib/secsuite" in out
    assert "CA private key" in out
    assert "audit.jsonl" in out


def test_cli_teardown_macos_dry_run(monkeypatch, capsys):
    monkeypatch.setattr(macos, "_discover", lambda root, work, topology_path=None: _macos_found_everything())
    assert main(["--manifest", MANIFEST, "teardown", "macos", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "docker compose" in out and "down" in out
    assert "/etc/resolver/sec.internal" in out
    assert "/etc/hosts" in out
    assert "System keychain" in out
    assert "native" in out.lower()
    assert "down -v" not in out
    assert "docker rmi" not in out


def test_cli_teardown_macos_dry_run_purge(monkeypatch, capsys):
    monkeypatch.setattr(macos, "_discover", lambda root, work, topology_path=None: _macos_found_everything())
    assert main(["--manifest", MANIFEST, "teardown", "macos", "--dry-run", "--purge"]) == 0
    out = capsys.readouterr().out
    assert "down -v" in out
    assert "docker rmi secrouter/seccert" in out
    assert "docker rmi secrouter/secrouter" in out
    assert "IRREVERSIBLE" in out


def test_cli_teardown_unknown_target_exits():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "teardown", "nope"])


# ═════════════════════════════════════════════════════════════════════════════════════════
# Confirm / --yes / --purge gating
# ═════════════════════════════════════════════════════════════════════════════════════════
def test_dry_run_never_prompts_fedora(monkeypatch, capsys):
    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_everything())

    def _boom(_prompt: str = "") -> str:
        raise AssertionError("--dry-run must never call input()")

    monkeypatch.setattr("builtins.input", _boom)
    assert main(["--manifest", MANIFEST, "teardown", "fedora-fips", "--dry-run", "--purge"]) == 0


def test_dry_run_never_prompts_macos(monkeypatch, capsys):
    monkeypatch.setattr(macos, "_discover", lambda root, work, topology_path=None: _macos_found_everything())

    def _boom(_prompt: str = "") -> str:
        raise AssertionError("--dry-run must never call input()")

    monkeypatch.setattr("builtins.input", _boom)
    assert main(["--manifest", MANIFEST, "teardown", "macos", "--dry-run", "--purge"]) == 0


def test_nothing_found_skips_the_confirm_entirely(monkeypatch, capsys):
    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_nothing())

    def _boom(_prompt: str = "") -> str:
        raise AssertionError("must not prompt when nothing was found to tear down")

    monkeypatch.setattr("builtins.input", _boom)
    assert main(["--manifest", MANIFEST, "teardown", "fedora-fips"]) == 0
    assert "nothing found" in capsys.readouterr().err.lower()


def test_fedora_real_run_requires_linux(monkeypatch, capsys):
    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_everything())
    monkeypatch.setattr(fedora_fips.platform, "system", lambda: "Darwin")
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "teardown", "fedora-fips", "--yes"])
    assert "must run on the Fedora host" in capsys.readouterr().err


def test_fedora_real_run_requires_root(monkeypatch, capsys):
    import os as os_module

    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_everything())
    monkeypatch.setattr(fedora_fips.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_module, "geteuid", lambda: 1000)
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "teardown", "fedora-fips", "--yes"])
    assert "must run as root" in capsys.readouterr().err


def test_fedora_real_run_without_yes_prompts_and_aborts_on_decline(monkeypatch, capsys):
    import os as os_module
    from secdeploy import process as P

    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_everything())
    monkeypatch.setattr(fedora_fips.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_module, "geteuid", lambda: 0)
    calls, fake_run = _recorder()
    monkeypatch.setattr(P, "run", fake_run)
    monkeypatch.setattr("builtins.input", _answers("n"))  # decline the main confirm

    assert main(["--manifest", MANIFEST, "teardown", "fedora-fips"]) == 0
    assert calls == []  # nothing executed
    assert "aborted" in capsys.readouterr().err.lower()


def test_fedora_real_run_with_yes_bypasses_every_confirm_and_executes(monkeypatch, capsys):
    import os as os_module
    from secdeploy import process as P

    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_everything())
    monkeypatch.setattr(fedora_fips.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_module, "geteuid", lambda: 0)
    calls, fake_run = _recorder()
    monkeypatch.setattr(P, "run", fake_run)

    def _boom(_prompt: str = "") -> str:
        raise AssertionError("--yes must bypass every confirm prompt, including --purge's")

    monkeypatch.setattr("builtins.input", _boom)

    assert main(["--manifest", MANIFEST, "teardown", "fedora-fips", "--yes", "--purge"]) == 0
    assert any(c[:2] == ["systemctl", "stop"] for c in calls)
    assert any(c[:2] == ["rm", "-rf"] and "/var/lib/secsuite" in c[-1] for c in calls)


def test_fedora_purge_declined_downgrades_but_rest_still_executes(monkeypatch, capsys):
    import os as os_module
    from secdeploy import process as P

    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_everything())
    monkeypatch.setattr(fedora_fips.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_module, "geteuid", lambda: 0)
    calls, fake_run = _recorder()
    monkeypatch.setattr(P, "run", fake_run)
    monkeypatch.setattr("builtins.input", _answers("y", "n"))  # main: yes, --purge: no

    assert main(["--manifest", MANIFEST, "teardown", "fedora-fips", "--purge"]) == 0
    assert not any("/var/lib/secsuite" in c[-1] for c in calls)  # purge honored the decline
    assert any(c[:2] == ["systemctl", "stop"] for c in calls)  # but the rest still ran
    assert any(c[:2] == ["rm", "-rf"] and c[-1] == "/etc/secsuite" for c in calls)
    assert "purge declined" in capsys.readouterr().err.lower()


def test_macos_real_run_with_yes_executes_everything(monkeypatch, capsys):
    from secdeploy import process as P

    monkeypatch.setattr(macos, "_discover", lambda root, work, topology_path=None: _macos_found_everything())
    calls, fake_run = _recorder()
    monkeypatch.setattr(P, "run", fake_run)

    def _boom(_prompt: str = "") -> str:
        raise AssertionError("--yes must bypass every confirm prompt, including the hosts one")

    monkeypatch.setattr("builtins.input", _boom)

    assert main(["--manifest", MANIFEST, "teardown", "macos", "--yes", "--purge"]) == 0
    assert any(c[:2] == ["sudo", "sed"] for c in calls)  # /etc/hosts line WAS removed
    assert any(c[:2] == ["docker", "rmi"] for c in calls)


def test_macos_hosts_line_needs_its_own_confirm_even_after_the_main_one(monkeypatch, capsys):
    from secdeploy import process as P

    monkeypatch.setattr(macos, "_discover", lambda root, work, topology_path=None: _macos_found_everything())
    calls, fake_run = _recorder()
    monkeypatch.setattr(P, "run", fake_run)
    # main confirm: yes; no --purge, so no purge confirm; the hosts-specific confirm: no
    monkeypatch.setattr("builtins.input", _answers("y", "n"))

    assert main(["--manifest", MANIFEST, "teardown", "macos"]) == 0
    assert not any(c[:2] == ["sudo", "sed"] for c in calls)  # declined -> skipped
    assert any(c[:2] == ["docker", "compose"] for c in calls)  # everything else still ran
    assert any(c[:2] == ["sudo", "security"] for c in calls)  # keychain isn't separately gated


def test_macos_purge_declined_downgrades_but_rest_still_executes(monkeypatch, capsys):
    from secdeploy import process as P

    monkeypatch.setattr(macos, "_discover", lambda root, work, topology_path=None: _macos_found_everything())
    calls, fake_run = _recorder()
    monkeypatch.setattr(P, "run", fake_run)
    # main: yes, --purge: no, hosts: yes
    monkeypatch.setattr("builtins.input", _answers("y", "n", "y"))

    assert main(["--manifest", MANIFEST, "teardown", "macos", "--purge"]) == 0
    assert not any(c[:2] == ["docker", "rmi"] for c in calls)
    assert not any(c[:2] == ["docker", "compose"] and "-v" in c for c in calls)
    assert any(c[:2] == ["docker", "compose"] for c in calls)  # plain `down` still ran
    assert any(c[:2] == ["sudo", "sed"] for c in calls)  # hosts line still honored its OWN yes


# ═════════════════════════════════════════════════════════════════════════════════════════
# Audit-drift note — best-effort annotation only, never the plan's driver
# ═════════════════════════════════════════════════════════════════════════════════════════
def test_audit_drift_note_prints_when_a_prior_audit_exists(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_nothing())
    out_dir = tmp_path / "out"
    audit_dir = out_dir / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / "deploy-fedora-fips-local.json").write_text(json.dumps({
        "generated_at": "2026-01-01T00:00:00+00:00",
        "components": [{"name": "seccert"}, {"name": "secrouter"}],
    }))
    assert main(["--manifest", MANIFEST, "--out", str(out_dir),
                 "teardown", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "audit drift note" in out
    assert "seccert" in out and "secrouter" in out


def test_audit_drift_note_silent_when_no_prior_audit(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found_nothing())
    assert main(["--manifest", MANIFEST, "--out", str(tmp_path / "does-not-exist"),
                 "teardown", "fedora-fips", "--dry-run"]) == 0
    assert "audit drift note" not in capsys.readouterr().out


def test_audit_drift_note_tolerates_malformed_json(tmp_path):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(parents=True)
    (audit_dir / "deploy-fedora-fips-local.json").write_text("{ not valid json")
    assert common.audit_drift_note(tmp_path, "fedora-fips") is None


# ── macOS stacks (SecSSO/SecChat) — brought down like fedora-fips ───────────────────────
def test_macos_plan_brings_down_stacks():
    text = _rendered(macos.teardown_plan(_macos_found_everything(), purge=False))
    assert "stack secsso: bring down via bootstrap/secsso.sh down" in text
    assert "stack secchat: bring down via bootstrap/secchat.sh down" in text
    assert "down -v" not in text  # no volume wipe without --purge


def test_macos_plan_purge_wipes_stack_volumes():
    text = _rendered(macos.teardown_plan(_macos_found_everything(), purge=True))
    assert "bootstrap/secsso.sh down -v" in text
    assert "bootstrap/secchat.sh down -v" in text
