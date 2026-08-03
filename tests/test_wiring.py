"""Tests for topology-driven deploy wiring."""

from __future__ import annotations

from pathlib import Path

import pytest

from secdeploy import wiring
from secdeploy.manifest import Manifest
from secdeploy.topology import Topology

ROOT = Path(__file__).resolve().parents[1]

GPU_SPLIT = """
domain = "sec.internal"
[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
capabilities = ["fips"]
[resources.gpu]
target = "macos"
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


def _manifest() -> Manifest:
    return Manifest.load(ROOT / "suite.toml")


def _topo(tmp_path) -> Topology:
    p = tmp_path / "topology.toml"
    p.write_text(GPU_SPLIT)
    return Topology.load(p, _manifest())


# ── active_topology ──────────────────────────────────────────────────────────────────
def test_active_topology_synthesizes_single_host(tmp_path):
    m = _manifest()
    topo, from_file = wiring.active_topology(m, tmp_path / "nope.toml", "macos")
    assert from_file is False
    assert list(topo.resources) == ["local"]
    assert set(topo.placement()) == set(m.components)  # everything on the one host


def test_active_topology_loads_file(tmp_path):
    p = tmp_path / "topology.toml"
    p.write_text(GPU_SPLIT)
    topo, from_file = wiring.active_topology(_manifest(), p, "fedora-fips")
    assert from_file is True
    assert set(topo.resources) == {"core", "gpu"}


# ── resource_for ─────────────────────────────────────────────────────────────────────
def test_resource_for_explicit(tmp_path):
    topo = _topo(tmp_path)
    assert wiring.resource_for(topo, "fedora-fips", "gpu") == "gpu"


def test_resource_for_unique_by_target(tmp_path):
    topo = _topo(tmp_path)
    # only 'gpu' is a macos resource; only 'core' is fedora-fips
    assert wiring.resource_for(topo, "macos", None) == "gpu"
    assert wiring.resource_for(topo, "fedora-fips", None) == "core"


def test_resource_for_unknown_raises(tmp_path):
    topo = _topo(tmp_path)
    with pytest.raises(KeyError):
        wiring.resource_for(topo, "fedora-fips", "ghost")


def test_resource_for_ambiguous_raises(tmp_path):
    ambiguous = GPU_SPLIT.replace('target = "macos"', 'target = "fedora-fips"')
    p = tmp_path / "t.toml"
    p.write_text(ambiguous)
    topo = Topology.load(p, _manifest())
    with pytest.raises(ValueError):
        wiring.resource_for(topo, "fedora-fips", None)  # core and gpu both match


# ── addressing artifacts ─────────────────────────────────────────────────────────────
def test_zone_text_has_all_placed_components(tmp_path):
    topo = _topo(tmp_path)
    text = wiring.zone_text(topo)
    assert "secrouter" in text and "10.0.0.5" in text
    assert "secllm" in text and "10.0.0.6" in text  # on the gpu host
    # short names (relative to domain), not FQDNs
    assert "secrouter.sec.internal" not in text


def test_env_text_wires_peers(tmp_path):
    topo = _topo(tmp_path)
    text = wiring.env_text(topo, "secrouter")
    assert "SEC_DOMAIN=sec.internal" in text
    assert "SECLLM_URL=https://secllm.sec.internal:47004" in text
    assert "SECROUTER_URL" not in text  # no self-reference


def test_write_addressing(tmp_path):
    topo = _topo(tmp_path)
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "gpu")
    zone = Path(written["zone"])
    assert zone.exists() and "secllm" in zone.read_text()
    # only components placed on 'gpu' get an env file → just secllm
    env = written["env"]
    assert set(env) == {"secllm"}
    assert Path(env["secllm"]).exists()
