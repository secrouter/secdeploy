"""Tests for the interactive `secdeploy configure` wizard (driven with scripted input)."""

from __future__ import annotations

from pathlib import Path

from secdeploy import configure
from secdeploy.manifest import Manifest
from secdeploy.topology import Topology

ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> Manifest:
    return Manifest.load(ROOT / "suite.toml")


def _driver(answers: list[str]):
    it = iter(answers)
    return lambda _prompt="": next(it)


def test_single_host_preset(tmp_path):
    dest = tmp_path / "topology.toml"
    answers = [
        "sec.internal",  # domain
        "1.1.1.1",       # upstream
        "single-host",   # layout
        "local",         # resource name
        "macos",         # target
        "127.0.0.1",     # address
        "",              # ssh
        "",              # capabilities
    ]
    result = configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert result == dest
    topo = Topology.load(dest, _manifest())
    assert topo.domain == "sec.internal" and topo.upstream_dns == ["1.1.1.1"]
    assert list(topo.resources) == ["local"]
    assert topo.groups == {
        t: ["local"] for t in ("identity", "inference", "gateway", "collab", "edge")
    }


def test_gpu_split_preset(tmp_path):
    dest = tmp_path / "topology.toml"
    answers = [
        "sec.internal", "",           # domain, (closed) upstream
        "gpu-split",
        "core", "fedora-fips", "10.0.0.5", "", "fips",       # core resource
        "gpu", "fedora-fips", "10.0.0.6", "", "fips,gpu",    # gpu resource
    ]
    result = configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert result == dest
    topo = Topology.load(dest, _manifest())
    assert set(topo.resources) == {"core", "gpu"}
    assert topo.upstream_dns == []  # closed network
    assert topo.groups["inference"] == ["gpu"]
    assert topo.groups["gateway"] == ["core"]
    assert topo.resources["gpu"].capabilities == ["fips", "gpu"]


def test_custom_preset(tmp_path):
    dest = tmp_path / "topology.toml"
    answers = [
        "sec.internal", "1.1.1.1",
        "custom", "2",
        "a", "fedora-fips", "10.0.0.1", "", "",       # resource a
        "b", "macos", "10.0.0.2", "", "gpu",          # resource b (has gpu)
        "a", "b", "a", "b", "a",  # identity→a inference→b gateway→a collab→b edge→a
    ]
    result = configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert result == dest
    topo = Topology.load(dest, _manifest())
    assert topo.groups == {
        "identity": ["a"], "inference": ["b"], "gateway": ["a"], "collab": ["b"], "edge": ["a"],
    }


def test_aborts_without_overwrite(tmp_path):
    dest = tmp_path / "topology.toml"
    dest.write_text("# existing\n")
    answers = [
        "sec.internal", "1.1.1.1", "single-host",
        "local", "macos", "127.0.0.1", "", "",
        "N",  # do not overwrite
    ]
    result = configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert result is None
    assert dest.read_text() == "# existing\n"  # untouched


def test_output_via_verify_roundtrip(tmp_path):
    """The wizard's output must pass `verify --topology`."""
    from secdeploy.cli import main

    dest = tmp_path / "topology.toml"
    answers = [
        "sec.internal", "1.1.1.1", "gpu-split",
        "core", "fedora-fips", "10.0.0.5", "", "fips",
        "gpu", "fedora-fips", "10.0.0.6", "", "fips,gpu",
    ]
    configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert main(["--manifest", str(ROOT / "suite.toml"), "verify", "--topology", str(dest)]) == 0
