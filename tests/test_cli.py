"""Tests for the secdeploy CLI (offline: verify / plan / dry-run / --without)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secdeploy.cli import main

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = str(ROOT / "suite.toml")

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


def test_plan_with_topology_shows_placement(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)
    assert main(["--manifest", MANIFEST, "plan", "fedora-fips", "--topology", str(tp)]) == 0
    out = capsys.readouterr().out
    assert "resource 'core'" in out and "placement:" in out
    # secllm lives on the gpu resource → not on this (core) host
    assert "secllm" in out
    assert "not on this resource" in out


def test_bundle_per_resource(tmp_path):
    work = tmp_path / "work"
    (work / "secllm").mkdir(parents=True)  # only the placed component needs a checkout
    out = tmp_path / "out"
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)
    rc = main(["--manifest", MANIFEST, "--work", str(work), "--out", str(out),
               "bundle", "macos", "--topology", str(tp), "--resource", "gpu"])
    assert rc == 0
    import tarfile

    tarball = out / "secsuite-1.2.0-macos-gpu.tar.gz"
    assert tarball.exists()
    names = tarfile.open(tarball).getnames()
    assert any(n.endswith("addressing/secdns.zone") for n in names)
    assert any("/work/secllm" in n for n in names)
    assert not any("/work/secrouter" in n for n in names)  # secrouter is on 'core', not here


def test_deploy_topology_filters_macos_resource(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)  # gpu (macos) holds only secllm
    assert main(["--manifest", MANIFEST, "deploy", "macos", "--dry-run",
                 "--topology", str(tp), "--resource", "gpu"]) == 0
    out = capsys.readouterr().out
    assert "resource 'gpu'" in out
    assert "components here: (none)" in out  # no macOS-native service is placed on gpu
    assert "start SecCert" not in out


def test_deploy_topology_fedora_core_gets_services(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)  # core (fedora-fips) holds the identity/gateway/collab tiers
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "resource 'core'" in out
    assert "seccert.service" in out and "secrouter.service" in out


def test_without_required_component_errors():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "macos", "--without", "secrouter"])


def test_roadmap_target_rejected():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "fedora-fips-image"])


def test_unknown_target_exits():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "nope"])
