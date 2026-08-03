"""Tests for the secdeploy CLI (offline: verify / plan / dry-run / --without)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secdeploy.cli import main

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = str(ROOT / "suite.toml")


def test_verify_ok(capsys):
    assert main(["--manifest", MANIFEST, "verify"]) == 0
    out = capsys.readouterr().out
    assert "suite 1.2.0" in out
    assert "optional: seccert, secsso, secdns" in out
    assert "target assets present" in out


def test_plan_macos_lists_all(capsys):
    assert main(["--manifest", MANIFEST, "plan", "macos"]) == 0
    out = capsys.readouterr().out
    assert "compose" in out.lower()
    assert "seccert @ v1.0.0" in out
    assert "secchat @ v1.0.0" in out


def test_plan_without_drops_optionals(capsys):
    assert main(["--manifest", MANIFEST, "plan", "macos", "--without", "seccert,secsso"]) == 0
    out = capsys.readouterr().out
    components, _, dropped = out.partition("dropped (--without):")
    assert "seccert, secsso" in dropped
    assert "seccert @" not in components and "secsso @" not in components
    assert "secrouter @" in components


def test_deploy_fedora_dry_run(capsys):
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "FIPS preflight" in out
    assert "seccert.service" in out
    assert "secsuite.target" in out


def test_deploy_without_seccert_skips_it(capsys):
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run", "--without", "seccert"]) == 0
    out = capsys.readouterr().out
    assert "seccert.service" not in out
    assert "SecCert root" not in out  # trust-anchor step skipped
    assert "secrouter.service" in out


def test_without_required_component_errors():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "macos", "--without", "secrouter"])


def test_roadmap_target_rejected():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "fedora-fips-image"])


def test_unknown_target_exits():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "nope"])
