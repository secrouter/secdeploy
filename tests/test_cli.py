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

# inference spread across TWO fedora-fips resources — N SecLLM instances for --with-inference.
MULTI_INFERENCE = """
domain = "sec.internal"
[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
capabilities = ["fips"]
[resources.gpu1]
target = "fedora-fips"
address = "10.0.0.6"
capabilities = ["fips", "gpu"]
[resources.gpu2]
target = "fedora-fips"
address = "10.0.0.7"
capabilities = ["fips", "gpu"]
[groups.identity]
resource = "core"
[groups.gateway]
resource = "core"
[groups.collab]
resource = "core"
[groups.inference]
resources = ["gpu1", "gpu2"]
"""


def test_verify_ok(capsys):
    assert main(["--manifest", MANIFEST, "verify"]) == 0
    out = capsys.readouterr().out
    assert "suite 1.3.0" in out
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

    tarball = out / "secsuite-1.3.0-macos-gpu.tar.gz"
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


GPU_SPLIT_SSH = GPU_SPLIT.replace(
    '[resources.core]\ntarget = "fedora-fips"\naddress = "10.0.0.5"',
    '[resources.core]\ntarget = "fedora-fips"\naddress = "10.0.0.5"\nssh = "root@10.0.0.5"',
).replace(
    '[resources.gpu]\ntarget = "macos"\naddress = "10.0.0.6"',
    '[resources.gpu]\ntarget = "fedora-fips"\naddress = "10.0.0.6"\nssh = "root@10.0.0.6"',
)


def test_deploy_ssh_dry_run_runbook(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT_SSH)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--ssh", "--dry-run",
                 "--topology", str(tp)]) == 0
    out = capsys.readouterr().out
    assert "root@10.0.0.5" in out and "root@10.0.0.6" in out
    assert "rsync -az" in out
    assert "--resource core" in out and "--resource gpu" in out


def test_deploy_fedora_topology_stands_up_secdns(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)  # core (fedora-fips) holds the identity tier → secdns
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "secdns.service" in out
    assert "generated secdns zone" in out
    assert "secsuite-secdns" in out


def test_deploy_fedora_single_host_excludes_secdns(capsys):
    # no topology → single-host → secdns is NOT stood up (byte-identical to before)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "secdns.service" not in out
    assert "seccert.service" in out
    assert "secllm.service" not in out  # --with-inference wasn't passed


def test_deploy_with_inference_stands_up_secllm(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(MULTI_INFERENCE)  # gpu1/gpu2 (fedora-fips) hold the inference tier
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--with-inference", "--topology", str(tp), "--resource", "gpu1"]) == 0
    out = capsys.readouterr().out
    assert "secllm.service" in out
    assert "secllm.env" in out
    assert "secsuite-secllm" in out
    # gpu1 hosts only the inference tier — no other resource's services leak in
    assert "seccert.service" not in out
    assert "secrouter.service" not in out


def test_deploy_without_with_inference_omits_secllm(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(MULTI_INFERENCE)  # same topology/resource as above, flag just omitted
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--topology", str(tp), "--resource", "gpu1"]) == 0
    out = capsys.readouterr().out
    assert "secllm.service" not in out


def test_deploy_with_inference_needs_a_topology(capsys):
    # --with-inference without a topology.toml is still single-host mode — secllm stays opt-out
    # (steps 1-3's DNS/env wiring has nothing to generate without a topology either)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--with-inference"]) == 0
    out = capsys.readouterr().out
    assert "secllm.service" not in out


def test_deploy_macos_topology_secdns_native(tmp_path, capsys):
    topo = """
domain = "sec.internal"
[resources.mac]
target = "macos"
address = "127.0.0.1"
[groups.identity]
resource = "mac"
[groups.inference]
resource = "mac"
[groups.gateway]
resource = "mac"
[groups.collab]
resource = "mac"
"""
    tp = tmp_path / "t.toml"
    tp.write_text(topo)
    assert main(["--manifest", MANIFEST, "deploy", "macos", "--dry-run",
                 "--topology", str(tp), "--resource", "mac"]) == 0
    out = capsys.readouterr().out
    assert "secdns: run natively" in out


def test_deploy_fedora_configure_resolver_local(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)  # secdns (identity) on core
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--configure-resolver", "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "systemd-resolved" in out
    assert "127.0.0.1" in out  # secdns is local on core → loopback


def test_deploy_macos_configure_resolver_remote(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)  # secdns on core (10.0.0.5); gpu is a macos resource
    assert main(["--manifest", MANIFEST, "deploy", "macos", "--dry-run",
                 "--configure-resolver", "--topology", str(tp), "--resource", "gpu"]) == 0
    out = capsys.readouterr().out
    assert "/etc/resolver/sec.internal" in out
    assert "10.0.0.5" in out  # points at the secdns host's address


def test_deploy_fedora_topology_brings_up_stacks(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)  # core holds identity (secsso) + collab (secchat)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "stack secsso" in out and "stack secchat" in out
    assert "bootstrap/secsso.sh up" in out


def test_deploy_fedora_single_host_no_stacks(capsys):
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "stack secsso" not in out and "stack secchat" not in out


def test_deploy_ssh_requires_endpoint(tmp_path):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)  # no ssh endpoints
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--ssh", "--dry-run",
              "--topology", str(tp)])


def test_without_required_component_errors():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "macos", "--without", "secrouter"])


def test_roadmap_target_rejected():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "fedora-fips-image"])


def test_unknown_target_exits():
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "plan", "nope"])


# ── deploy audit artifacts (CMMC audit evidence — see secdeploy.audit) ──────────────────
def test_deploy_dry_run_mentions_audit_artifact_fedora_single_host(capsys):
    # no --topology → single-host mode → resource label is "local" (Topology.single_host's
    # conventional name — see secdeploy.audit.SINGLE_HOST_RESOURCE)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "audit:" in out
    assert "deploy-fedora-fips-local.json" in out


def test_deploy_dry_run_mentions_audit_artifact_macos_single_host(capsys):
    assert main(["--manifest", MANIFEST, "deploy", "macos", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "audit:" in out
    assert "deploy-macos-local.json" in out


def test_deploy_dry_run_mentions_audit_artifact_with_topology_resource(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "deploy-fedora-fips-core.json" in out


def test_deploy_dry_run_audit_note_reflects_trust_anchor_flag(capsys):
    # seccert is on this (single-host) resource → the trust-anchor step is in the fedora-fips
    # plan → the audit preview should say so.
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "trust_anchor=yes" in out


def test_deploy_dry_run_audit_note_no_trust_anchor_without_seccert(capsys):
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--without", "seccert"]) == 0
    out = capsys.readouterr().out
    assert "trust_anchor=no" in out


def test_deploy_dry_run_no_file_written(tmp_path, capsys):
    # --dry-run must stay side-effect-light: no out/ directory (let alone out/audit/) appears.
    out_dir = tmp_path / "out"
    assert main(["--manifest", MANIFEST, "--out", str(out_dir),
                 "deploy", "fedora-fips", "--dry-run"]) == 0
    assert not out_dir.exists()


# ── secrouter-addressing.env: layering the generated pool/token/egress wiring onto the live
#    secrouter.env via secrouter.service's second EnvironmentFile= ──────────────────────
def test_deploy_fedora_dry_run_pool_topology_shows_secrouter_addressing_env_install(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(MULTI_INFERENCE)  # 'core' hosts the gateway tier (secrouter)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "install generated secrouter addressing env" in out
    assert "install -m 640" in out
    # both the source (staged addressing env) and the destination (installed, DISTINCT from
    # /etc/secsuite/secrouter.env) appear in the printed command
    assert "addressing/env/secrouter.env" in out
    assert "/etc/secsuite/secrouter-addressing.env" in out


def test_deploy_fedora_dry_run_single_host_no_secrouter_addressing_env_install(capsys):
    # no topology.toml → single-host mode → no generated addressing at all (unchanged)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "secrouter-addressing.env" not in out


def test_deploy_fedora_dry_run_secllm_only_resource_no_secrouter_addressing_env_install(tmp_path, capsys):
    # topology IS active, but SecRouter isn't placed on THIS resource (gpu1 hosts only secllm)
    # — the addressing-env install is gated on "secrouter in services", same as the egress file.
    tp = tmp_path / "topology.toml"
    tp.write_text(MULTI_INFERENCE)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--with-inference", "--topology", str(tp), "--resource", "gpu1"]) == 0
    out = capsys.readouterr().out
    assert "secrouter-addressing.env" not in out
