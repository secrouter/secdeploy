"""Tests for the `ubuntu` target — mirrors tests/test_teardown.py, tests/test_backup_targets.py,
and tests/test_cli.py's own fedora-fips test style, adapted for the distro deltas:

  * `teardown_plan()` is exercised directly with synthetic `UbuntuFound` values (pure, no host
    probing) — same split as fedora-fips's own tests.
  * Deploy/plan/teardown/backup/restore CLI-level tests drive `main([...])` with `--dry-run`
    (no real apt/systemctl — this all runs on a macOS dev box) or with the target's own
    `_discover`/`backup`/`restore` monkeypatched, exactly like test_teardown.py/
    test_backup_targets.py do for fedora-fips.
  * Every test here is isolated into its own `tmp_path` cwd (see the module's autouse
    `_isolated_cwd` fixture) — the same pre-existing workaround test_cli.py's own
    `test_deploy_macos_with_agent_dry_run_shows_secagent_init` documents: `active_site` prefers
    a `secsite.toml` in the CURRENT directory over `--topology`/single-host, so a stray one
    sitting in the repo root (this dev checkout has one) would otherwise silently override
    every topology/single-host case here.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from secdeploy.cli import main
from secdeploy.manifest import Manifest
from secdeploy.targets import common, fedora_fips, ubuntu

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = str(ROOT / "suite.toml")
MANIFEST = Manifest.load(MANIFEST_PATH)

UBUNTU_GPU_SPLIT = """
domain = "sec.internal"
[resources.core]
target = "ubuntu"
address = "10.0.0.5"
[resources.gpu]
target = "ubuntu"
address = "10.0.0.6"
capabilities = ["gpu"]
[groups.identity]
resource = "core"
[groups.gateway]
resource = "core"
[groups.collab]
resource = "core"
[groups.inference]
resource = "gpu"
"""

UBUNTU_EDGE_SPLIT = UBUNTU_GPU_SPLIT + """
[groups.edge]
resource = "core"
"""

UBUNTU_MULTI_INFERENCE = """
domain = "sec.internal"
[resources.core]
target = "ubuntu"
address = "10.0.0.5"
[resources.gpu1]
target = "ubuntu"
address = "10.0.0.6"
capabilities = ["gpu"]
[resources.gpu2]
target = "ubuntu"
address = "10.0.0.7"
capabilities = ["gpu"]
[groups.identity]
resource = "core"
[groups.gateway]
resource = "core"
[groups.collab]
resource = "core"
[groups.inference]
resources = ["gpu1", "gpu2"]
"""


@pytest.fixture(autouse=True)
def _isolated_cwd(monkeypatch, tmp_path):
    """Every test in this file drives `main([...])`, which resolves the active site config via
    `wiring.active_site` — that prefers a `secsite.toml` in the CURRENT directory over any
    `--topology`/single-host default (see test_cli.py's own documented workaround for the exact
    same trap, on `test_deploy_macos_with_agent_dry_run_shows_secagent_init`). This dev checkout
    has a stray `secsite.toml` sitting at the repo root, so isolate every test here from it
    unconditionally — auto-applied, so no test has to remember to chdir itself."""
    monkeypatch.chdir(tmp_path)


# ═════════════════════════════════════════════════════════════════════════════════════════
# Registration: suite.toml, cli.py target dispatch, help strings
# ═════════════════════════════════════════════════════════════════════════════════════════
def test_suite_toml_defines_ubuntu_target():
    assert "ubuntu" in MANIFEST.targets
    t = MANIFEST.targets["ubuntu"]
    assert t.kind == "systemd-native"


def test_cli_target_help_lists_ubuntu(capsys):
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST_PATH, "deploy", "--help"])
    out = capsys.readouterr().out
    assert "macos, fedora-fips, ubuntu" in out


def test_cli_unknown_target_error_lists_ubuntu(capsys):
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST_PATH, "deploy", "bogus-target", "--dry-run"])
    err = capsys.readouterr().err
    assert "ubuntu" in err


def test_stack_names_shared_with_fedora_fips():
    # ubuntu.py imports STACK_NAMES from fedora_fips rather than redefining it — one definition,
    # both native-systemd targets (see targets/ubuntu.py's top-of-file comment).
    assert ubuntu.STACK_NAMES is fedora_fips.STACK_NAMES
    assert ubuntu.STACK_NAMES == ("secsso", "secchat")


def test_verify_lists_ubuntu_target_assets_present(capsys):
    assert main(["--manifest", MANIFEST_PATH, "verify"]) == 0
    out = capsys.readouterr().out
    assert "targets:" in out and "ubuntu" in out
    assert "target assets present" in out  # would list "missing" instead if any asset were absent


# ═════════════════════════════════════════════════════════════════════════════════════════
# Deploy dry-run — apt package step, FIPS advisory (not fail-closed), .crt CA trust, reused units
# ═════════════════════════════════════════════════════════════════════════════════════════
def test_ubuntu_deploy_dry_run_single_host(capsys):
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "FIPS advisory check" in out
    assert "fail-closed" not in out  # unlike fedora-fips's preflight step
    assert "deploy/ubuntu/fips-check.sh" in out
    assert "seccert.service" in out
    assert "secsuite.target" in out


def test_ubuntu_fips_check_is_advisory_never_abort(capsys):
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "FIPS advisory check (WARN-only, never aborts)" in out


def test_ubuntu_env_files_come_from_own_deploy_dir(capsys):
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "deploy/ubuntu/seccert.env.example" in out
    assert "deploy/fedora-fips/seccert.env" not in out


def test_ubuntu_systemd_units_reused_from_fedora_fips_dir(capsys):
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run"]) == 0
    out = capsys.readouterr().out
    # the unit FILES themselves are reused directly, not duplicated under deploy/ubuntu/
    assert "deploy/fedora-fips/systemd/seccert.service" in out
    assert "deploy/fedora-fips/systemd/secsuite.target" in out


def test_ubuntu_deploy_without_seccert_skips_it(capsys):
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run",
                 "--without", "seccert"]) == 0
    out = capsys.readouterr().out
    assert "seccert.service" not in out
    assert "SecCert root" not in out
    assert "secrouter.service" in out


def test_ubuntu_deploy_single_host_excludes_secdns_and_secproxy(capsys):
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "secdns.service" not in out
    assert "secproxy.service" not in out
    assert "seccert.service" in out


def test_ubuntu_deploy_topology_stands_up_secdns(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    tp = tmp_path / "topology.toml"
    tp.write_text(UBUNTU_GPU_SPLIT)
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "secdns.service" in out
    assert "generated secdns zone" in out
    assert "secsuite-secdns" in out


def test_ubuntu_deploy_topology_stands_up_secproxy(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    tp = tmp_path / "topology.toml"
    tp.write_text(UBUNTU_EDGE_SPLIT)
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "secproxy.service" in out
    assert "secsuite-secproxy" in out
    # the apt package step (fedora-fips's dnf equivalent) — no dnf anywhere in ubuntu's plan
    assert "apt-get install -y nginx certbot" in out
    assert "dnf" not in out
    # certbot SAN-cert issuance — identical mechanism to fedora-fips
    assert "certbot certonly --standalone" in out
    assert "--cert-name secproxy" in out


def test_ubuntu_deploy_with_inference_stands_up_secllm(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    tp = tmp_path / "topology.toml"
    tp.write_text(UBUNTU_MULTI_INFERENCE)
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run",
                 "--with-inference", "--topology", str(tp), "--resource", "gpu1"]) == 0
    out = capsys.readouterr().out
    assert "secllm.service" in out
    assert "secllm.env" in out
    assert "secsuite-secllm" in out
    assert "seccert.service" not in out  # gpu1 hosts only the inference tier


def test_ubuntu_deploy_without_with_inference_omits_secllm(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    tp = tmp_path / "topology.toml"
    tp.write_text(UBUNTU_MULTI_INFERENCE)
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run",
                 "--topology", str(tp), "--resource", "gpu1"]) == 0
    out = capsys.readouterr().out
    assert "secllm.service" not in out


def test_ubuntu_ca_trust_uses_crt_extension_and_update_ca_certificates(capsys):
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "/usr/local/share/ca-certificates/secsuite-seccert-root.crt" in out
    assert "update-ca-certificates" in out
    assert "update-ca-trust" not in out  # fedora's tool, never invoked here
    assert "secsuite-seccert-root.pem" not in out  # wrong extension for Debian-family trust


def test_ubuntu_macos_only_flags_warn_and_are_ignored(capsys):
    assert main(["--manifest", MANIFEST_PATH, "deploy", "ubuntu", "--dry-run", "--tls"]) == 0
    err = capsys.readouterr().err
    assert "macOS-only" in err and "ubuntu" in err


# ═════════════════════════════════════════════════════════════════════════════════════════
# teardown_plan() — pure function tests (synthetic UbuntuFound, no host probing)
# ═════════════════════════════════════════════════════════════════════════════════════════
def _ubuntu_found_everything() -> ubuntu.UbuntuFound:
    return ubuntu.UbuntuFound(
        units=list(ubuntu.ALL_UNIT_NAMES),
        users=list(ubuntu.SERVICES),
        opt_dirs=list(ubuntu.SERVICES),
        opt_root_exists=True,
        etc_exists=True,
        var_dirs=list(ubuntu.SERVICES),
        var_root_exists=True,
        anchor_exists=True,
        resolver_dropin_exists=True,
        stacks=[
            ("secsso", Path("work/secsso/bootstrap/secsso.sh")),
            ("secchat", Path("work/secchat/bootstrap/secchat.sh")),
        ],
    )


def _ubuntu_found_nothing() -> ubuntu.UbuntuFound:
    return ubuntu.UbuntuFound(
        units=[], users=[], opt_dirs=[], opt_root_exists=False, etc_exists=False,
        var_dirs=[], var_root_exists=False, anchor_exists=False,
        resolver_dropin_exists=False, stacks=[],
    )


def _rendered(plan: list[common.Step]) -> str:
    return "\n".join(f"{d} {' '.join(c) if c else ''}" for d, c, _ in plan)


def test_ubuntu_plan_found_everything_names_every_reverse_action():
    plan = ubuntu.teardown_plan(_ubuntu_found_everything(), purge=False)
    text = _rendered(plan)
    assert "secsuite.target" in text
    assert "systemctl disable --now secsuite.target" in text
    assert "systemctl stop secdns" in text
    assert "rm -f /etc/systemd/system/secdns.service" in text
    assert "systemctl daemon-reload" in text
    assert "userdel secsuite-seccert" in text
    assert "rm -rf /opt/secsuite/secrouter" in text
    assert "rmdir /opt/secsuite" in text
    assert "rm -rf /etc/secsuite" in text
    assert "SECCERT_CA_PASSPHRASE" in text
    # trust anchor — the .crt path + update-ca-certificates (NOT fedora's .pem/update-ca-trust)
    assert "rm -f /usr/local/share/ca-certificates/secsuite-seccert-root.crt" in text
    assert "update-ca-certificates" in text
    assert "update-ca-trust" not in text
    assert "rm -f /etc/systemd/resolved.conf.d/secsuite.conf" in text
    assert "systemctl restart systemd-resolved" in text
    assert "bootstrap/secsso.sh down" in text
    assert "bootstrap/secchat.sh down" in text
    assert "NOT removed" in text
    assert plan[-1].category == "packages"
    assert plan[-1].command is None


def test_ubuntu_plan_without_purge_never_mentions_var_lib():
    plan = ubuntu.teardown_plan(_ubuntu_found_everything(), purge=False)
    text = _rendered(plan)
    assert "/var/lib" not in text
    assert not any(s.category == "data" for s in plan)


def test_ubuntu_plan_with_purge_shows_data_and_ca_audit_warning():
    plan = ubuntu.teardown_plan(_ubuntu_found_everything(), purge=True)
    text = _rendered(plan)
    assert "/var/lib/secsuite" in text
    assert "rm -rf /var/lib/secsuite/seccert" in text
    assert "rm -rf /var/lib/secsuite/secagent" in text
    assert "CA private key" in text
    assert "audit.jsonl" in text
    assert "secdns.zone" in text and "regenerable" in text
    assert "bootstrap/secsso.sh down -v" in text


def test_ubuntu_plan_packages_note_never_a_command():
    plan = ubuntu.teardown_plan(_ubuntu_found_everything(), purge=False)
    packages = [s for s in plan if s.category == "packages"]
    assert len(packages) == 1
    assert packages[0].command is None
    assert "@earendil-works/pi-coding-agent" in packages[0].description
    assert "nginx" in packages[0].description


def test_ubuntu_plan_nothing_found_is_just_the_packages_note():
    plan = ubuntu.teardown_plan(_ubuntu_found_nothing(), purge=True)
    assert len(plan) == 1
    assert plan[0].category == "packages"


def test_ubuntu_plan_order_matches_fedora_fips():
    plan = ubuntu.teardown_plan(_ubuntu_found_everything(), purge=True)
    categories_seen_order = []
    for s in plan:
        if not categories_seen_order or categories_seen_order[-1] != s.category:
            categories_seen_order.append(s.category)
    assert categories_seen_order == [
        "services", "users", "code", "config", "data", "trust anchor", "resolver", "stacks",
        "packages",
    ]


def test_ubuntu_plan_userdel_has_no_dash_r():
    plan = ubuntu.teardown_plan(_ubuntu_found_everything(), purge=True)
    userdels = [s.command for s in plan if s.command and s.command[0] == "userdel"]
    assert userdels
    for cmd in userdels:
        assert "-r" not in cmd


def test_ubuntu_plan_only_found_units_appear():
    found = ubuntu.UbuntuFound(
        units=["secrouter"], users=[], opt_dirs=[], opt_root_exists=False, etc_exists=False,
        var_dirs=[], var_root_exists=False, anchor_exists=False,
        resolver_dropin_exists=False, stacks=[],
    )
    plan = ubuntu.teardown_plan(found, purge=False)
    text = _rendered(plan)
    assert "systemctl stop secrouter" in text
    assert "systemctl disable --now secsuite.target" not in text
    assert "systemctl stop secdns" not in text


# ═════════════════════════════════════════════════════════════════════════════════════════
# CLI-level teardown — main([...]) with _discover monkeypatched (mirrors test_teardown.py)
# ═════════════════════════════════════════════════════════════════════════════════════════
def test_cli_ubuntu_teardown_dry_run(monkeypatch, capsys):
    monkeypatch.setattr(ubuntu, "_discover", lambda work: _ubuntu_found_everything())
    assert main(["--manifest", MANIFEST_PATH, "teardown", "ubuntu", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "ubuntu teardown plan" in out
    assert "secsuite-seccert" in out


def test_cli_ubuntu_teardown_purge_dry_run(monkeypatch, capsys):
    monkeypatch.setattr(ubuntu, "_discover", lambda work: _ubuntu_found_everything())
    assert main(["--manifest", MANIFEST_PATH, "teardown", "ubuntu", "--dry-run", "--purge"]) == 0
    out = capsys.readouterr().out
    assert "/var/lib/secsuite" in out


def test_cli_ubuntu_teardown_nothing_found_no_prompt(monkeypatch, capsys):
    def _boom(*a, **k):
        raise AssertionError("nothing to tear down must never prompt")

    monkeypatch.setattr(ubuntu, "_discover", lambda work: _ubuntu_found_nothing())
    monkeypatch.setattr("builtins.input", _boom)
    assert main(["--manifest", MANIFEST_PATH, "teardown", "ubuntu"]) == 0


def test_cli_ubuntu_teardown_requires_linux(monkeypatch):
    monkeypatch.setattr(ubuntu, "_discover", lambda work: _ubuntu_found_everything())
    monkeypatch.setattr(ubuntu.platform, "system", lambda: "Darwin")
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST_PATH, "teardown", "ubuntu", "--yes"])


# ═════════════════════════════════════════════════════════════════════════════════════════
# Backup/restore — pure step builders (mirrors test_backup_targets.py's fedora block)
# ═════════════════════════════════════════════════════════════════════════════════════════
def _ubuntu_found(*, etc=True, var_dirs=("secrouter", "seccert", "secagent")) -> ubuntu.UbuntuFound:
    return ubuntu.UbuntuFound(
        units=[], users=[], opt_dirs=[], opt_root_exists=False, etc_exists=etc,
        var_dirs=list(var_dirs), var_root_exists=True, anchor_exists=False,
        resolver_dropin_exists=False, stacks=[])


def test_ubuntu_backup_native_steps_config_then_data_seccert_first():
    steps = ubuntu.backup_native_steps(_ubuntu_found(), Path("/stg"))
    cmds = [s.command for s in steps]
    assert cmds[0] == ["tar", "czf", "/stg/native/etc-secsuite.tar.gz", "-C", "/etc/secsuite", "."]
    data = [c for c in cmds if "/var/lib/secsuite" in " ".join(c)]
    assert data[0] == ["tar", "czf", "/stg/native/var-seccert.tar.gz", "-C",
                       "/var/lib/secsuite/seccert", "."]


def test_ubuntu_restore_native_steps_order_seccert_etc_rest():
    files = ["etc-secsuite.tar.gz", "var-secrouter.tar.gz", "var-seccert.tar.gz"]
    steps = ubuntu.restore_native_steps(files, Path("/u"))
    extract_targets = [s.command[-1] for s in steps if s.command[0] == "tar"]
    assert extract_targets == ["/var/lib/secsuite/seccert", "/etc/secsuite", "/var/lib/secsuite/secrouter"]


def test_ubuntu_backup_components_meta_no_secret_values():
    stacks = [("secsso", Path("b")), ("secchat", Path("b"))]
    meta = ubuntu._backup_components_meta(_ubuntu_found(), stacks)
    names = [c["name"] for c in meta]
    assert "config" in names and "seccert" in names and "secchat" in names
    blob = json.dumps(meta)
    assert "PASSPHRASE" not in blob and "PASSWORD" not in blob


def test_cli_ubuntu_backup_dispatch_and_flags(monkeypatch):
    captured = {}

    def fake_backup(m, work, root, *, recipient_cert, resource, dry_run, assume_yes, out):
        captured.update(recipient_cert=recipient_cert, dry_run=dry_run, yes=assume_yes)

    monkeypatch.setattr(ubuntu, "backup", fake_backup)
    assert main(["--manifest", MANIFEST_PATH, "backup", "ubuntu",
                 "--recipient", "/c.pem", "--dry-run", "-y"]) == 0
    assert captured == {"recipient_cert": "/c.pem", "dry_run": True, "yes": True}


def test_cli_ubuntu_restore_dispatch_and_flags(monkeypatch):
    captured = {}

    def fake_restore(m, work, root, archive, *, key, recipient_cert, resource, dry_run, assume_yes, out):
        captured.update(archive=archive, key=key, dry_run=dry_run)

    monkeypatch.setattr(ubuntu, "restore", fake_restore)
    assert main(["--manifest", MANIFEST_PATH, "restore", "ubuntu",
                 "/a.tar.cms", "--key", "/k.pem", "--dry-run"]) == 0
    assert captured == {"archive": "/a.tar.cms", "key": "/k.pem", "dry_run": True}


def test_cli_ubuntu_backup_dry_run_lists_stacks(monkeypatch, capsys):
    monkeypatch.setattr(ubuntu, "_discover", lambda work: _ubuntu_found())
    monkeypatch.setattr(common, "stack_checkouts",
                        lambda m, w: [("secsso", Path("b")), ("secchat", Path("b"))])
    assert main(["--manifest", MANIFEST_PATH, "backup", "ubuntu", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "var-seccert.tar.gz" in out and "secchat" in out


def test_cli_ubuntu_restore_dry_run_touches_nothing(monkeypatch, capsys):
    def _boom(*a, **k):
        raise AssertionError("dry-run restore must not prompt or run anything")

    monkeypatch.setattr("builtins.input", _boom)
    assert main(["--manifest", MANIFEST_PATH, "restore", "ubuntu",
                 "/nope.tar.cms", "--dry-run"]) == 0
    assert "restore plan" in capsys.readouterr().out
