"""Tests for the per-target backup/restore — mirrors test_teardown.py's split:

  * The PURE step builders (backup_native_steps / restore_native_steps / the macOS volume+host
    builders / common.stack_* ) are exercised directly with synthetic inputs — no host probing.
  * One fedora backup→restore INTEGRATION test drives the real target functions against a fake
    /var + /etc (module path constants monkeypatched) with a real openssl recipient keypair and
    real tar, proving the encrypt→decrypt→restore round-trip AND that no plaintext secret ever
    lands in the archive or the manifest.
  * CLI-level tests drive `main([...])` with the target's backup/restore monkeypatched, to prove
    argument parsing → dispatch, the same way test_cli.py does for deploy/teardown.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import secdeploy.process as PROC
from secdeploy.cli import main
from secdeploy.manifest import Manifest
from secdeploy.targets import common, fedora_fips, macos

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = str(ROOT / "suite.toml")
MANIFEST = Manifest.load(MANIFEST_PATH)
FIXED_NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)


def _recipient_keypair(tmp_path, name="bkp"):
    cert, key = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(key), "-out", str(cert),
         "-days", "1", "-nodes", "-subj", f"/CN=test-{name}"],
        check=True, capture_output=True,
    )
    return cert, key


# ── common: dynamic stack derivation (the secassist gotcha) ─────────────────────────────────
def test_stack_checkouts_is_dynamic_and_includes_secassist(tmp_path):
    work = tmp_path / "work"
    for name in ("secsso", "secchat", "secassist"):
        b = work / name / "bootstrap" / f"{name}.sh"
        b.parent.mkdir(parents=True)
        b.write_text("#!/usr/bin/env bash\n")
    names = [n for n, _ in common.stack_checkouts(MANIFEST, work)]
    assert set(names) == {"secsso", "secchat", "secassist"}
    # the whole point: this picks up secassist, which the hardcoded teardown list omits
    assert "secassist" not in fedora_fips.STACK_NAMES


def test_stack_checkouts_skips_absent_checkouts(tmp_path):
    work = tmp_path / "work"
    b = work / "secsso" / "bootstrap" / "secsso.sh"
    b.parent.mkdir(parents=True)
    b.write_text("x")
    assert [n for n, _ in common.stack_checkouts(MANIFEST, work)] == ["secsso"]


def test_stack_backup_and_restore_step_shape(tmp_path):
    stacks = [("secsso", Path("work/secsso/bootstrap/secsso.sh"))]
    bs = common.stack_backup_steps(stacks, Path("/stg"))
    assert bs[0].command == ["bash", "work/secsso/bootstrap/secsso.sh", "backup", "/stg/stacks/secsso"]
    # restore only emits a step for stacks actually present in the archive
    unpacked = tmp_path / "u"
    (unpacked / "stacks" / "secsso").mkdir(parents=True)
    rs = common.stack_restore_steps(stacks, unpacked)
    assert rs and rs[0].command == [
        "bash", "work/secsso/bootstrap/secsso.sh", "restore", str(unpacked / "stacks" / "secsso")]
    assert common.stack_restore_steps([("secchat", Path("b"))], unpacked) == []  # absent → skipped


def test_execute_capture_plan_is_fail_fast(monkeypatch):
    seen = []

    def fake_run(cmd, check=True, **kw):
        seen.append(cmd[-1])
        if cmd[-1] == "boom":
            raise subprocess.CalledProcessError(1, cmd)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(PROC, "run", fake_run)
    steps = [common.Step("a", ["ok"], "x"), common.Step("boom", ["boom"], "x"),
             common.Step("c", ["never"], "x")]
    with pytest.raises(subprocess.CalledProcessError):
        common.execute_capture_plan(steps)
    assert seen == ["ok", "boom"]  # stopped at the failure — "never" was never run


# ── fedora-fips: pure plans ─────────────────────────────────────────────────────────────────
def _fedora_found(*, etc=True, var_dirs=("secrouter", "seccert", "secagent")) -> fedora_fips.FedoraFound:
    return fedora_fips.FedoraFound(
        units=[], users=[], opt_dirs=[], opt_root_exists=False, etc_exists=etc,
        var_dirs=list(var_dirs), var_root_exists=True, anchor_exists=False,
        resolver_dropin_exists=False, stacks=[])


def test_fedora_backup_native_steps_config_then_data_seccert_first():
    steps = fedora_fips.backup_native_steps(_fedora_found(), Path("/stg"))
    cmds = [s.command for s in steps]
    assert cmds[0] == ["tar", "czf", "/stg/native/etc-secsuite.tar.gz", "-C", "/etc/secsuite", "."]
    data = [c for c in cmds if "/var/lib/secsuite" in " ".join(c)]
    assert data[0] == ["tar", "czf", "/stg/native/var-seccert.tar.gz", "-C",
                       "/var/lib/secsuite/seccert", "."]  # crown jewels lead


def test_fedora_restore_native_steps_order_seccert_etc_rest():
    files = ["etc-secsuite.tar.gz", "var-secrouter.tar.gz", "var-seccert.tar.gz"]
    steps = fedora_fips.restore_native_steps(files, Path("/u"))
    extract_targets = [s.command[-1] for s in steps if s.command[0] == "tar"]
    assert extract_targets == ["/var/lib/secsuite/seccert", "/etc/secsuite", "/var/lib/secsuite/secrouter"]


def test_fedora_backup_components_meta_no_secret_values():
    stacks = [("secsso", Path("b")), ("secassist", Path("b"))]
    meta = fedora_fips._backup_components_meta(_fedora_found(), stacks)
    names = [c["name"] for c in meta]
    assert "config" in names and "seccert" in names and "secassist" in names
    blob = json.dumps(meta)
    assert "PASSPHRASE" not in blob and "PASSWORD" not in blob  # names only, never values


# ── fedora-fips: full backup → restore integration (real openssl + tar, fake host paths) ─────
def test_fedora_backup_restore_integration(tmp_path, monkeypatch):
    var, etc = tmp_path / "var", tmp_path / "etc"
    (var / "seccert").mkdir(parents=True)
    (var / "seccert" / "ca.key").write_text("SUPER-SECRET-CA-KEY")
    (var / "secrouter").mkdir(parents=True)
    (var / "secrouter" / "secrouter.db").write_text("hash-chained-audit")
    etc.mkdir()
    (etc / "seccert.env").write_text("SECCERT_CA_PASSPHRASE=hunter2\n")
    monkeypatch.setattr(fedora_fips, "VAR", var)
    monkeypatch.setattr(fedora_fips, "ETC", etc)
    monkeypatch.setattr(fedora_fips, "_require_root_linux", lambda action: None)
    monkeypatch.setattr(common, "stack_checkouts", lambda m, w: [])  # no stacks in this test

    cert, key = _recipient_keypair(tmp_path)
    out = tmp_path / "out"
    fedora_fips.backup(MANIFEST, tmp_path / "work", tmp_path, recipient_cert=str(cert),
                       resource="core", dry_run=False, assume_yes=True, out=out, now=FIXED_NOW)
    archives = list((out / "backups").glob("*.tar.cms"))
    assert len(archives) == 1
    # the secret is really encrypted — plaintext never appears in the archive OR the manifest
    assert b"SUPER-SECRET-CA-KEY" not in archives[0].read_bytes()
    manifest_blob = next((out / "backups").glob("*.manifest.json")).read_text() \
        + next((out / "backups").glob("*.manifest.txt")).read_text()
    assert "SUPER-SECRET-CA-KEY" not in manifest_blob and "hunter2" not in manifest_blob

    # restore into a FRESH fake host; swallow systemctl but let tar/mkdir/openssl run for real
    var2, etc2 = tmp_path / "var2", tmp_path / "etc2"
    monkeypatch.setattr(fedora_fips, "VAR", var2)
    monkeypatch.setattr(fedora_fips, "ETC", etc2)
    real_run = PROC.run

    def guarded(cmd, **kw):
        if cmd and cmd[0] == "systemctl":
            return SimpleNamespace(returncode=0)
        return real_run(cmd, **kw)

    monkeypatch.setattr(PROC, "run", guarded)
    fedora_fips.restore(MANIFEST, tmp_path / "work", tmp_path, str(archives[0]), key=str(key),
                        recipient_cert=str(cert), dry_run=False, assume_yes=True, out=out)
    assert (var2 / "seccert" / "ca.key").read_text() == "SUPER-SECRET-CA-KEY"
    assert (var2 / "secrouter" / "secrouter.db").read_text() == "hash-chained-audit"
    assert (etc2 / "seccert.env").read_text().strip() == "SECCERT_CA_PASSPHRASE=hunter2"


# ── macOS: discovery + pure plans ────────────────────────────────────────────────────────────
def test_macos_root_secret_paths_picks_secrets_not_bulk(tmp_path):
    root = tmp_path
    (root / "out").mkdir()
    for f in ("seccert-root.pem", "secllm-shared-token", "secagent-webhook-secret"):
        (root / "out" / f).write_text("x")
    (root / "out" / "models").mkdir()          # bulk/rebuildable — not a secret
    (root / "out" / "addressing").mkdir()
    (root / "deploy" / "macos").mkdir(parents=True)
    (root / "deploy" / "macos" / "secrets.env").write_text("HF_TOKEN=x")
    rels = macos._macos_root_secret_paths(root)
    assert {"out/seccert-root.pem", "out/secllm-shared-token", "out/secagent-webhook-secret",
            "out/addressing", "deploy/macos/secrets.env"} <= set(rels)
    assert "out/models" not in rels


def test_macos_home_secret_paths(tmp_path):
    (tmp_path / ".secagent").mkdir()
    (tmp_path / ".config" / "secrouter").mkdir(parents=True)
    assert set(macos._macos_home_secret_paths(tmp_path)) == {".secagent", ".config/secrouter"}


def test_macos_volume_and_host_step_shape():
    vs = macos.backup_volume_steps(["secsuite_seccert-data", "secsuite_x"], Path("/stg"), "alpine:3")
    c0 = vs[0].command
    assert c0[:5] == ["docker", "run", "--rm", "-v", "secsuite_seccert-data:/v:ro"]
    assert "/backup/vol-secsuite_seccert-data.tar.gz" in c0
    assert c0[-3:] == ["-C", "/v", "."]
    hs = macos.backup_host_steps(Path("/root"), Path("/home"),
                                 ["out/x", "deploy/macos/secrets.env"], [".secagent"], Path("/stg"))
    root_cmd = hs[0].command
    assert root_cmd[:4] == ["tar", "czf", "/stg/native/host-root.tar.gz", "-C"]
    assert root_cmd[4] == "/root" and root_cmd[5:] == ["out/x", "deploy/macos/secrets.env"]
    assert hs[1].command[4] == "/home" and hs[1].command[5:] == [".secagent"]


def test_macos_restore_step_shape(tmp_path):
    unpacked = tmp_path / "u"
    (unpacked / "native").mkdir(parents=True)
    (unpacked / "native" / "vol-secsuite_seccert-data.tar.gz").write_bytes(b"x")
    (unpacked / "native" / "host-root.tar.gz").write_bytes(b"x")
    vs = macos.restore_volume_steps(["vol-secsuite_seccert-data.tar.gz"], unpacked, "alpine:3")
    assert "cd /v && tar xzf /backup/vol-secsuite_seccert-data.tar.gz" in vs[0].command
    hs = macos.restore_host_steps(Path("/root"), Path("/home"), unpacked)
    assert hs == [common.Step(hs[0].description, ["tar", "xzf",
                  str(unpacked / "native" / "host-root.tar.gz"), "-C", "/root"], "host")]


# ── CLI dispatch ─────────────────────────────────────────────────────────────────────────────
def test_cli_backup_dispatch_and_flags(monkeypatch):
    captured = {}

    def fake_backup(m, work, root, *, recipient_cert, resource, dry_run, assume_yes, out):
        captured.update(recipient_cert=recipient_cert, dry_run=dry_run, yes=assume_yes)

    monkeypatch.setattr(fedora_fips, "backup", fake_backup)
    assert main(["--manifest", MANIFEST_PATH, "backup", "fedora-fips",
                 "--recipient", "/c.pem", "--dry-run", "-y"]) == 0
    assert captured == {"recipient_cert": "/c.pem", "dry_run": True, "yes": True}


def test_cli_restore_dispatch_and_flags(monkeypatch):
    captured = {}

    def fake_restore(m, work, root, archive, *, key, recipient_cert, resource, dry_run, assume_yes, out):
        captured.update(archive=archive, key=key, dry_run=dry_run)

    monkeypatch.setattr(macos, "restore", fake_restore)
    assert main(["--manifest", MANIFEST_PATH, "restore", "macos",
                 "/a.tar.cms", "--key", "/k.pem", "--dry-run"]) == 0
    assert captured == {"archive": "/a.tar.cms", "key": "/k.pem", "dry_run": True}


def test_cli_backup_dry_run_lists_stacks_incl_secassist(monkeypatch, capsys):
    monkeypatch.setattr(fedora_fips, "_discover", lambda work: _fedora_found())
    monkeypatch.setattr(common, "stack_checkouts",
                        lambda m, w: [("secsso", Path("b")), ("secchat", Path("b")), ("secassist", Path("b"))])
    assert main(["--manifest", MANIFEST_PATH, "backup", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "var-seccert.tar.gz" in out and "secassist" in out


def test_cli_restore_dry_run_touches_nothing(monkeypatch, capsys):
    def _boom(*a, **k):
        raise AssertionError("dry-run restore must not prompt or run anything")

    monkeypatch.setattr("builtins.input", _boom)
    assert main(["--manifest", MANIFEST_PATH, "restore", "fedora-fips",
                 "/nope.tar.cms", "--dry-run"]) == 0
    assert "restore plan" in capsys.readouterr().out
