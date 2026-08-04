"""Tests for the release manifest loader/validator."""

from __future__ import annotations

from pathlib import Path

import pytest

from secdeploy.manifest import Manifest

ROOT = Path(__file__).resolve().parents[1]
ALL = {"seccert", "secsso", "secdns", "secllm", "secrouter", "secagent", "secchat", "secrecorder"}


def test_load_shipped_manifest():
    m = Manifest.load(ROOT / "suite.toml")
    assert m.suite == "1.3.0"
    assert ALL <= set(m.components)
    assert m.components["secrecorder"].ref == "v0.8.2"
    assert m.components["secagent"].ref == "v0.1.0"
    assert set(m.targets) == {"macos", "fedora-fips"}


def test_kinds_and_optional_flags():
    m = Manifest.load(ROOT / "suite.toml")
    assert m.components["secsso"].kind == "stack"
    assert m.components["secchat"].kind == "stack"
    assert m.components["secrouter"].kind == "service"
    assert m.optionals() == ["seccert", "secsso", "secdns"]
    assert m.components["seccert"].optional and m.components["secsso"].optional
    assert m.components["secdns"].optional and m.components["secdns"].kind == "service"
    assert not m.components["secrouter"].optional


def test_select_drops_optionals():
    m = Manifest.load(ROOT / "suite.toml")
    selected = m.select(["seccert", "secsso"])
    assert "seccert" not in selected and "secsso" not in selected
    assert "secrouter" in selected and "secllm" in selected


def test_select_rejects_required_component():
    m = Manifest.load(ROOT / "suite.toml")
    with pytest.raises(ValueError):
        m.select(["secrouter"])


def test_select_rejects_unknown_component():
    m = Manifest.load(ROOT / "suite.toml")
    with pytest.raises(KeyError):
        m.select(["nope"])


def test_tiers_and_ports():
    m = Manifest.load(ROOT / "suite.toml")
    assert m.components["secrouter"].tier == "gateway"
    assert m.components["secrouter"].port == 47002
    assert m.components["secllm"].tier == "inference"
    assert m.components["seccert"].tier == "identity"
    assert m.components["seccert"].port == 47001
    assert m.components["secdns"].tier == "identity"
    assert m.components["secdns"].port == 53
    assert m.components["secchat"].tier == "collab"
    # every component is tiered
    assert all(c.tier for c in m.components.values())


def test_roundtrip_serialization(tmp_path):
    m = Manifest.load(ROOT / "suite.toml")
    out = tmp_path / "suite.toml"
    out.write_text(m.to_toml())
    reloaded = Manifest.load(out)
    assert reloaded.suite == m.suite
    assert list(reloaded.components) == list(m.components)
    assert reloaded.components["secsso"].kind == "stack"
    assert reloaded.components["seccert"].optional
    assert reloaded.components["secrecorder"].ref == "v0.8.2"
    assert reloaded.components["secrouter"].tier == "gateway"
    assert reloaded.components["secrouter"].port == 47002
    assert reloaded.components["seccert"].port == 47001


def test_invalid_repo_and_ref_rejected(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text('suite = "1"\n[components.x]\nrepo = "noslash"\nref = ""\ntier = "gateway"\n')
    with pytest.raises(ValueError):
        Manifest.load(bad)


def test_unknown_component_kind_rejected(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text('suite = "1"\n[components.x]\nrepo = "a/b"\nref = "v1"\ntier = "gateway"\nkind = "weird"\n')
    with pytest.raises(ValueError):
        Manifest.load(bad)


def test_unknown_tier_rejected(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text('suite = "1"\n[components.x]\nrepo = "a/b"\nref = "v1"\ntier = "weird"\n')
    with pytest.raises(ValueError):
        Manifest.load(bad)


def test_unknown_target_kind_rejected(tmp_path):
    bad = tmp_path / "bad.toml"
    bad.write_text(
        'suite = "1"\n[components.x]\nrepo = "a/b"\nref = "v1"\ntier = "gateway"\n'
        '[targets.t]\nkind = "weird"\n'
    )
    with pytest.raises(ValueError):
        Manifest.load(bad)


def test_unknown_target_lookup_raises():
    m = Manifest.load(ROOT / "suite.toml")
    with pytest.raises(KeyError):
        m.target("nope")
