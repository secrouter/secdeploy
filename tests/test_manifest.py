"""Tests for the release manifest loader/validator."""

from __future__ import annotations

from pathlib import Path

import pytest

from secdeploy.manifest import Manifest

ROOT = Path(__file__).resolve().parents[1]
ALL = {"seccert", "secsso", "secdns", "secllm", "secrouter", "secagent", "secchat", "secrecorder",
       "secproxy"}
FRONTED = {"secsso", "secrouter", "secchat", "secrecorder"}


def test_load_shipped_manifest():
    m = Manifest.load(ROOT / "suite.toml")
    assert m.suite == "2.0.0"
    assert set(m.components) == ALL  # exactly these — the two retired chat components are gone
    assert m.components["secrecorder"].ref == "v0.8.2"
    assert m.components["secagent"].ref == "main"           # bridge-free harness, pre-release ref
    assert m.components["secchat"].ref == "rearchitecture"  # native SecChat rebuild
    assert set(m.targets) == {"macos", "fedora-fips"}


def test_kinds_and_optional_flags():
    m = Manifest.load(ROOT / "suite.toml")
    assert m.components["secsso"].kind == "stack"
    assert m.components["secchat"].kind == "stack"
    assert m.components["secrouter"].kind == "service"
    assert m.optionals() == ["seccert", "secsso", "secdns", "secproxy"]
    assert m.components["seccert"].optional and m.components["secsso"].optional
    assert m.components["secdns"].optional and m.components["secdns"].kind == "service"
    assert not m.components["secrouter"].optional
    assert m.components["secproxy"].optional and m.components["secproxy"].kind == "service"
    # SecChat (the native rebuild) is a required collab-tier stack, fronted at :443.
    assert not m.components["secchat"].optional
    assert m.components["secchat"].tier == "collab" and m.components["secchat"].port == 47010


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


# A crafted manifest with an experimental component — the shipped suite has none after the
# SecChat cutover, but the --with/experimental machinery is generic and still needs coverage.
_EXPERIMENTAL_MANIFEST = (
    'suite = "1"\n'
    '[components.secrouter]\nrepo = "o/secrouter"\nref = "v1"\ntier = "gateway"\nport = 47002\n'
    '[components.labthing]\nrepo = "o/labthing"\nref = "v1"\ntier = "collab"\nexperimental = true\n'
    '[targets.fedora-fips]\nkind = "systemd-native"\n'
)


def test_no_experimental_components_shipped_by_default():
    # After the SecChat cutover no shipped component is experimental — the native SecChat is now
    # the canonical, default-on `secchat` stack, not an opt-in rebuild.
    m = Manifest.load(ROOT / "suite.toml")
    assert m.experimentals() == []
    assert "secchat" in m.select()
    assert m.components["secchat"].experimental is False


def test_include_opts_experimental_in(tmp_path):
    p = tmp_path / "suite.toml"; p.write_text(_EXPERIMENTAL_MANIFEST)
    m = Manifest.load(p)
    assert "labthing" not in m.select()   # experimental → off by default
    assert m.include(["labthing"]) is m   # chainable
    assert "labthing" in m.select()
    assert m.included == {"labthing"}


def test_include_rejects_non_experimental():
    m = Manifest.load(ROOT / "suite.toml")
    with pytest.raises(ValueError):  # secrouter isn't experimental — --with it is meaningless
        m.include(["secrouter"])


def test_include_rejects_unknown():
    m = Manifest.load(ROOT / "suite.toml")
    with pytest.raises(KeyError):
        m.include(["nope"])


def test_experimental_survives_toml_roundtrip(tmp_path):
    src = tmp_path / "src.toml"; src.write_text(_EXPERIMENTAL_MANIFEST)
    m = Manifest.load(src)
    out = tmp_path / "suite.toml"
    out.write_text(m.to_toml())
    reloaded = Manifest.load(out)
    assert reloaded.components["labthing"].experimental is True
    assert "labthing" not in reloaded.select()  # still off by default after a round-trip


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
    assert m.components["secproxy"].tier == "edge"
    assert m.components["secproxy"].port == 443
    # every component is tiered
    assert all(c.tier for c in m.components.values())


# ── fronted axis: which components secproxy (nginx) puts behind :443 ────────────────────
def test_fronted_flags_exactly_the_fronted_set():
    m = Manifest.load(ROOT / "suite.toml")
    assert {name for name, c in m.components.items() if c.fronted} == FRONTED
    # never fronted: inference dials direct, secdns isn't HTTP, secproxy is the fronter itself,
    # and secagent is an installed harness with no inbound listener at all.
    for name in ("secllm", "secdns", "secproxy", "secagent"):
        assert not m.components[name].fronted


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
    # the fronted axis and the new edge component round-trip too
    assert reloaded.components["secrouter"].fronted
    assert not reloaded.components["secllm"].fronted
    assert reloaded.components["secproxy"].tier == "edge"
    assert reloaded.components["secproxy"].port == 443
    assert reloaded.components["secproxy"].optional
    assert not reloaded.components["secproxy"].fronted


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
