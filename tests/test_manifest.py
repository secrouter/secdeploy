"""Tests for the release manifest loader/validator."""

from __future__ import annotations

from pathlib import Path

import pytest

from secdeploy.manifest import Manifest

ROOT = Path(__file__).resolve().parents[1]


def test_load_shipped_manifest():
    m = Manifest.load(ROOT / "suite.toml")
    assert m.suite == "1.0.0"
    assert set(m.components) == {"seccert", "secrouter", "secrecorder"}
    assert m.components["seccert"].ref == "v1.0.0"
    assert m.components["secrecorder"].ref == "b76cb4af16509e3cffb4e2982c92e8eb51167d55"
    assert m.components["secrouter"].url == "https://github.com/secrouter/secrouter.git"
    assert set(m.targets) == {"macos", "fedora-fips"}
    assert m.target("fedora-fips").kind == "systemd-native"


def test_roundtrip_serialization(tmp_path):
    m = Manifest.load(ROOT / "suite.toml")
    out = tmp_path / "suite.toml"
    out.write_text(m.to_toml())
    reloaded = Manifest.load(out)
    assert reloaded.suite == m.suite
    assert list(reloaded.components) == list(m.components)
    assert reloaded.components["secrecorder"].ref == "b76cb4af16509e3cffb4e2982c92e8eb51167d55"
    assert list(reloaded.targets) == list(m.targets)


def test_invalid_repo_and_ref_rejected(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text('suite = "1"\n[components.x]\nrepo = "noslash"\nref = ""\n')
    with pytest.raises(ValueError):
        Manifest.load(bad)


def test_unknown_target_kind_rejected(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text(
        'suite = "1"\n[components.x]\nrepo = "a/b"\nref = "v1"\n[targets.t]\nkind = "weird"\n'
    )
    with pytest.raises(ValueError):
        Manifest.load(bad)


def test_unknown_target_lookup_raises():
    m = Manifest.load(ROOT / "suite.toml")
    with pytest.raises(KeyError):
        m.target("nope")
