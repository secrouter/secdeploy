"""Tests for the secdeploy CLI (offline: verify / plan / dry-run)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secdeploy.cli import main

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = str(ROOT / "suite.toml")


def test_verify_ok(capsys):
    assert main(["--manifest", MANIFEST, "verify"]) == 0
    out = capsys.readouterr().out
    assert "suite 1.0.0" in out
    assert "target assets present" in out


def test_plan_macos(capsys):
    assert main(["--manifest", MANIFEST, "plan", "macos"]) == 0
    out = capsys.readouterr().out
    assert "compose" in out.lower()
    assert "seccert @ v1.0.0" in out


def test_plan_fedora(capsys):
    assert main(["--manifest", MANIFEST, "plan", "fedora-fips"]) == 0
    assert "systemd-native" in capsys.readouterr().out


def test_deploy_fedora_dry_run_is_a_runbook(capsys):
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "FIPS preflight" in out
    assert "secsuite.target" in out


def test_roadmap_target_is_rejected_clearly():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "fedora-fips-image"])


def test_unknown_target_exits():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "nope"])
