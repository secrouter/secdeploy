"""Tests for the site topology loader/validator and its derivations."""

from __future__ import annotations

from pathlib import Path

import pytest

from secdeploy.manifest import Manifest
from secdeploy.topology import Topology

ROOT = Path(__file__).resolve().parents[1]

GPU_SPLIT = """
domain = "sec.internal"
upstream_dns = ["1.1.1.1"]
[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
capabilities = ["fips"]
[resources.gpu]
target = "fedora-fips"
address = "10.0.0.6"
capabilities = ["fips", "gpu"]
[groups.identity]
resource = "core"
[groups.gateway]
resource = "core"
[groups.collab]
resource = "core"
[groups.inference]
resource = "gpu"
"""


def _manifest() -> Manifest:
    return Manifest.load(ROOT / "suite.toml")


def _topo(tmp_path, text: str, manifest: Manifest | None = None) -> Topology:
    p = tmp_path / "topology.toml"
    p.write_text(text)
    return Topology.load(p, manifest or _manifest())


# ── placement ───────────────────────────────────────────────────────────────────────
def test_single_host_places_everything():
    m = _manifest()
    topo = Topology.single_host(m, "macos", address="127.0.0.1")
    placement = topo.placement()
    assert set(placement) == set(m.components)  # all components land on the one host
    assert set(placement.values()) == {"local"}
    assert set(topo.components_on("local")) == set(m.components)


def test_gpu_split_placement(tmp_path):
    topo = _topo(tmp_path, GPU_SPLIT)
    placement = topo.placement()
    assert placement["secllm"] == "gpu"
    assert placement["secrouter"] == "core"
    assert set(topo.components_on("gpu")) == {"secllm"}
    assert "secllm" not in topo.components_on("core")
    assert not topo.warnings  # gpu resource has the 'gpu' capability → no warning


def test_gpu_split_with_without(tmp_path):
    topo = _topo(tmp_path, GPU_SPLIT)
    on_core = topo.components_on("core", without=["seccert", "secsso"])
    assert "seccert" not in on_core and "secsso" not in on_core
    assert "secrouter" in on_core


# ── addressing derivations ──────────────────────────────────────────────────────────
def test_fqdn_and_zone(tmp_path):
    topo = _topo(tmp_path, GPU_SPLIT)
    assert topo.fqdn("secllm") == "secllm.sec.internal"
    zone = topo.zone()
    assert ("secllm.sec.internal", "A", "10.0.0.6") in zone
    assert ("secrouter.sec.internal", "A", "10.0.0.5") in zone


def test_env_for_wires_peers_not_self(tmp_path):
    topo = _topo(tmp_path, GPU_SPLIT)
    env = topo.env_for("secrouter")
    assert env["SELF_FQDN"] == "secrouter.sec.internal"
    assert env["SEC_DOMAIN"] == "sec.internal"
    assert env["SELF_PORT"] == "47002"
    # peers get URLs pointing at their hosting resource; self is excluded
    assert env["SECLLM_URL"] == "https://secllm.sec.internal:47004"
    assert env["SECCERT_URL"] == "https://seccert.sec.internal:47001"
    assert "SECROUTER_URL" not in env


# ── validation: errors ──────────────────────────────────────────────────────────────
def test_unknown_resource_rejected(tmp_path):
    bad = GPU_SPLIT.replace('[groups.gateway]\nresource = "core"',
                            '[groups.gateway]\nresource = "nope"')
    with pytest.raises(ValueError):
        _topo(tmp_path, bad)


def test_unplaced_required_component_rejected(tmp_path):
    # drop the gateway group entirely — secrouter (required) is now unplaced
    missing_gateway = """
domain = "sec.internal"
[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
capabilities = ["gpu"]
[groups.identity]
resource = "core"
[groups.collab]
resource = "core"
[groups.inference]
resource = "core"
"""
    with pytest.raises(ValueError):
        _topo(tmp_path, missing_gateway)


def test_unknown_target_rejected(tmp_path):
    bad = GPU_SPLIT.replace('target = "fedora-fips"\naddress = "10.0.0.5"',
                            'target = "windows"\naddress = "10.0.0.5"')
    with pytest.raises(ValueError):
        _topo(tmp_path, bad)


def test_port_collision_rejected(tmp_path):
    crafted = """
suite = "1"
[components.a]
repo = "o/a"
ref = "v1"
tier = "gateway"
port = 8000
[components.b]
repo = "o/b"
ref = "v1"
tier = "gateway"
port = 8000
[targets.fedora-fips]
kind = "systemd-native"
"""
    mpath = tmp_path / "suite.toml"
    mpath.write_text(crafted)
    m = Manifest.load(mpath)
    topo_text = """
domain = "sec.internal"
[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
[groups.gateway]
resource = "core"
"""
    with pytest.raises(ValueError, match="port 8000"):
        _topo(tmp_path, topo_text, manifest=m)


# ── validation: warnings (non-fatal) ────────────────────────────────────────────────
def test_optional_unplaced_is_allowed(tmp_path):
    # identity group omitted; seccert/secsso are optional, so this is legal, not an error
    no_identity = """
domain = "sec.internal"
[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
capabilities = ["gpu"]
[groups.gateway]
resource = "core"
[groups.collab]
resource = "core"
[groups.inference]
resource = "core"
"""
    topo = _topo(tmp_path, no_identity)
    placement = topo.placement()
    assert "seccert" not in placement and "secsso" not in placement
    assert "secrouter" in placement


def test_inference_without_gpu_warns(tmp_path):
    cpu_only = """
domain = "sec.internal"
[resources.core]
target = "macos"
address = "127.0.0.1"
capabilities = []
[groups.identity]
resource = "core"
[groups.gateway]
resource = "core"
[groups.collab]
resource = "core"
[groups.inference]
resource = "core"
"""
    topo = _topo(tmp_path, cpu_only)  # no exception
    assert any("gpu" in w for w in topo.warnings)


# ── serialization ───────────────────────────────────────────────────────────────────
def test_roundtrip(tmp_path):
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "rt.toml"
    out.write_text(topo.to_toml())
    reloaded = Topology.load(out, _manifest())
    assert reloaded.domain == topo.domain
    assert set(reloaded.resources) == set(topo.resources)
    assert reloaded.groups == topo.groups
    assert reloaded.resources["gpu"].capabilities == ["fips", "gpu"]
