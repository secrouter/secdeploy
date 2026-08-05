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

# GPU_SPLIT plus secproxy (edge tier) on 'core' — exercises the fedora-fips secproxy standup
# (mirrors test_wiring.py's own EDGE_SPLIT fixture for the topology-derivation-level tests).
EDGE_SPLIT = GPU_SPLIT + """
[groups.edge]
resource = "core"
"""

# GPU_SPLIT plus secproxy (edge tier) on 'gpu' — the MACOS resource this time (EDGE_SPLIT above
# puts it on 'core', a fedora-fips resource) — exercises the macOS native-nginx standup.
MACOS_EDGE_SPLIT = GPU_SPLIT + """
[groups.edge]
resource = "gpu"
"""


def test_verify_ok(capsys):
    assert main(["--manifest", MANIFEST, "verify"]) == 0
    out = capsys.readouterr().out
    assert "suite 1.6.0" in out
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

    tarball = out / "secsuite-1.6.0-macos-gpu.tar.gz"
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


# ── secproxy (edge tier — nginx reverse proxy on fedora-fips): topology-gated, like secdns ──
def test_deploy_fedora_topology_stands_up_secproxy(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(EDGE_SPLIT)  # core (fedora-fips) holds the edge tier → secproxy
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    # the unit
    assert "secproxy.service" in out
    assert "secsuite-secproxy" in out
    # the nginx runtime step (+ certbot) — no COPR/binary-runtime install anymore
    assert "install the secproxy runtime (nginx" in out
    assert "dnf install -y nginx certbot" in out
    assert "copr" not in out.lower()  # the old COPR binary-runtime install step is gone
    # the certbot SAN-cert issuance from SecCert — one --cert-name, one -d per fronted FQDN
    assert "certbot certonly --standalone" in out
    assert "--cert-name secproxy" in out
    for name in ("secsso", "secrouter", "secagent", "secchat", "secrecorder"):
        assert f"-d {name}.sec.internal" in out
    assert "http://seccert.sec.internal:47001/acme/directory" in out
    # the cert install (0600 key, owned by the service user) + the generated nginx config install
    assert "/etc/secsuite/secproxy/fullchain.pem" in out
    assert "/etc/secsuite/secproxy/privkey.pem" in out
    assert "install generated nginx config" in out
    assert "/etc/secsuite/nginx-secproxy.conf" in out


def test_deploy_fedora_single_host_excludes_secproxy(capsys):
    # no topology → single-host → secproxy is NOT stood up (secproxy is topology-gated, same
    # rule as secdns — byte-identical to every pre-secproxy single-host deploy)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "secproxy.service" not in out
    assert "secproxy runtime (nginx" not in out
    assert "install generated nginx config" not in out
    assert "certbot certonly" not in out
    assert "seccert.service" in out


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


# ── secproxy on macOS: native nginx (not a container — see targets/macos.py's module
#    docstring), gated on topology placement only, exactly like secdns above ─────────────
def test_deploy_macos_topology_secproxy_native(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(MACOS_EDGE_SPLIT)  # gpu (macos) holds the edge tier → secproxy
    assert main(["--manifest", MANIFEST, "deploy", "macos", "--dry-run",
                 "--topology", str(tp), "--resource", "gpu"]) == 0
    out = capsys.readouterr().out
    assert "run nginx natively on :443/:80" in out
    assert "issue a SecCert SAN cert" in out       # the certbot SAN issuance note
    assert "sudo nginx -c" in out
    assert "addressing/secproxy.nginx.conf" in out


def test_deploy_macos_plain_dry_run_shows_no_secproxy(capsys):
    # no topology → single-host mode → secproxy is topology-gated, same rule as secdns —
    # byte-identical to every pre-secproxy macOS deploy.
    assert main(["--manifest", MANIFEST, "deploy", "macos", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "secproxy" not in out.lower()
    assert "nginx" not in out.lower()


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


# ── --with-agent: SecAgent + Mattermost chat-ops turnkey standup ────────────────────────
def test_deploy_fedora_with_agent_dry_run_shows_the_whole_turnkey(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)  # 'core' hosts identity (secsso) + gateway (secrouter) + collab (secagent, secchat)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--with-agent", "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    # 1. the secagent unit
    assert "install secagent.service" in out
    # 2. pi install
    assert "install pi (coding agent runtime) globally" in out
    assert "npm install -g @earendil-works/pi-coding-agent" in out
    # 3. the generated addressing env
    assert "install generated secagent addressing env" in out
    assert "addressing/env/secagent.env" in out
    assert "/etc/secsuite/secagent-addressing.env" in out
    # pi's models.json install step
    assert "install pi models.json" in out
    assert "/var/lib/secsuite/secagent/.pi/agent/models.json" in out
    # 4. the secchat.sh bot mint step
    assert "bootstrap/secchat.sh bot" in out
    assert "SECAGENT_MATTERMOST__BOT_TOKEN" in out
    # 5. the secrouter oidc config
    assert "SecRouter OIDC config fragment" in out
    assert "secrouter-oidc.json" in out
    assert "svc-secagent" in out


def test_deploy_fedora_plain_dry_run_shows_none_of_the_agent_turnkey(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)  # same topology, --with-agent simply omitted
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "secagent.service" not in out
    assert "pi-coding-agent" not in out
    assert "secagent-addressing.env" not in out
    assert "secagent-pi-models" not in out
    assert "secchat.sh bot" not in out
    assert "SecRouter OIDC config fragment" not in out


def test_deploy_fedora_with_agent_single_host_unchanged(capsys):
    # --with-agent without a topology.toml is still single-host mode — secagent stays opt-out,
    # exactly like --with-inference/secllm (steps 1-3's wiring has nothing to generate either).
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--with-agent"]) == 0
    out = capsys.readouterr().out
    assert "secagent.service" not in out
    assert "pi-coding-agent" not in out


def test_deploy_fedora_with_agent_needs_secagent_placed_here(tmp_path, capsys):
    # --with-agent set, topology active, but secagent isn't placed on THIS resource (gpu hosts
    # only the inference tier in GPU_SPLIT) — the whole turnkey stays off here.
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)
    assert main(["--manifest", MANIFEST, "deploy", "macos", "--dry-run",
                 "--with-agent", "--topology", str(tp), "--resource", "gpu"]) == 0
    out = capsys.readouterr().out
    assert "secagent" not in out.lower()


def test_deploy_fedora_with_agent_verify_lists_secagent_service(capsys):
    assert main(["--manifest", MANIFEST, "verify"]) == 0
    out = capsys.readouterr().out
    assert "target assets present" in out  # secagent.service ships, so verify still passes clean


# ── secproxy.service is a fedora-fips expected asset ────────────────────────────────────
def test_expected_assets_fedora_includes_secproxy_service():
    from secdeploy.cli import _expected_assets

    assets = _expected_assets(ROOT, "fedora-fips")
    assert any(p.name == "secproxy.service" for p in assets)


def test_verify_fedora_topology_reports_secproxy_placement(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(EDGE_SPLIT)  # core holds the edge tier → secproxy
    assert main(["--manifest", MANIFEST, "verify", "--topology", str(tp)]) == 0
    out = capsys.readouterr().out
    assert "target assets present" in out  # secproxy.service ships, so verify passes clean
    assert "secproxy" in out  # listed among 'core's placed components


# ── secsite.toml: unified site config (placement + deploy options) ─────────────────────
# 'core' (identity/gateway/collab), 'gpu1'+'gpu2' (inference, N-way). [deploy].without drops
# secdns; only gpu1 sets with_inference — gpu2 deliberately leaves it at its default (False),
# to prove both directions of the tri-state CLI/site override.
SITE_WITH_INFERENCE = """
domain = "sec.internal"

[deploy]
without = ["secdns"]

[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
capabilities = ["fips"]

[resources.gpu1]
target = "fedora-fips"
address = "10.0.0.6"
capabilities = ["fips", "gpu"]
with_inference = true

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

# Same shape, but 'core' also carries an ssh endpoint and [deploy].ssh = true — for proving
# the suite-wide ssh-push toggle takes effect from the file without passing --ssh.
SITE_SSH = """
domain = "sec.internal"

[deploy]
ssh = true

[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
ssh = "root@10.0.0.5"
capabilities = ["fips"]

[groups.identity]
resource = "core"
[groups.gateway]
resource = "core"
[groups.collab]
resource = "core"
[groups.inference]
resource = "core"
"""


def test_deploy_site_with_inference_stands_up_secllm_without_the_flag(tmp_path, capsys):
    """The headline behavior: with_inference=true on gpu1's secsite.toml block stands up
    secllm on --dry-run WITHOUT --with-inference ever appearing on the command line."""
    tp = tmp_path / "secsite.toml"
    tp.write_text(SITE_WITH_INFERENCE)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--site", str(tp), "--resource", "gpu1"]) == 0
    out = capsys.readouterr().out
    assert "secllm.service" in out
    assert "secllm.env" in out
    assert "secsuite-secllm" in out
    # gpu1 hosts only the inference tier — no other resource's services leak in
    assert "seccert.service" not in out
    assert "secrouter.service" not in out


def test_deploy_site_without_drops_secdns_on_its_own_resource(tmp_path, capsys):
    """[deploy].without = ["secdns"] takes effect from the file — secdns is absent even on
    'core' (its own identity-tier resource), not merely absent because it's unplaced."""
    tp = tmp_path / "secsite.toml"
    tp.write_text(SITE_WITH_INFERENCE)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--site", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "secdns.service" not in out
    assert "generated secdns zone" not in out
    assert "seccert.service" in out
    assert "secrouter.service" in out


def test_deploy_site_gpu2_omits_secllm_when_not_set_there(tmp_path, capsys):
    # gpu2 never sets with_inference — defaults False, same as no secsite.toml at all.
    tp = tmp_path / "secsite.toml"
    tp.write_text(SITE_WITH_INFERENCE)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--site", str(tp), "--resource", "gpu2"]) == 0
    out = capsys.readouterr().out
    assert "secllm.service" not in out


def test_deploy_cli_with_inference_overrides_site_false(tmp_path, capsys):
    # gpu2's secsite.toml leaves with_inference at its default (False) — an explicit
    # --with-inference on the CLI still wins (an explicit flag always overrides the file).
    tp = tmp_path / "secsite.toml"
    tp.write_text(SITE_WITH_INFERENCE)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--site", str(tp), "--resource", "gpu2", "--with-inference"]) == 0
    out = capsys.readouterr().out
    assert "secllm.service" in out


def test_deploy_cli_without_overrides_site_without(tmp_path, capsys):
    # an explicit (even empty) --without on the CLI is "given" — distinguishable from "absent"
    # by the tri-state None sentinel — so it overrides the file's without = ["secdns"] entirely.
    tp = tmp_path / "secsite.toml"
    tp.write_text(SITE_WITH_INFERENCE)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--site", str(tp), "--resource", "core", "--without", ""]) == 0
    out = capsys.readouterr().out
    assert "secdns.service" in out


def test_deploy_site_ssh_true_without_the_flag(tmp_path, capsys):
    tp = tmp_path / "secsite.toml"
    tp.write_text(SITE_SSH)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--site", str(tp)]) == 0
    out = capsys.readouterr().out
    assert "rsync -az" in out and "root@10.0.0.5" in out  # ssh-push runbook, no --ssh passed


def test_deploy_cli_ssh_false_not_representable_but_absence_uses_site(tmp_path, capsys):
    # store_true tri-state means there is no CLI way to force ssh OFF when the site says on —
    # only "pass --ssh" (True) or "don't" (None → falls back to site.ssh). Document that by
    # showing the only override direction that exists: explicit --ssh when the file is silent.
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT_SSH)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--ssh", "--dry-run",
                 "--topology", str(tp)]) == 0
    out = capsys.readouterr().out
    assert "rsync -az" in out


def test_deploy_secsite_toml_autodetected_in_cwd(tmp_path, monkeypatch, capsys):
    """No --site, no --topology override — secsite.toml sitting in the current directory is
    picked up automatically (the precedence tier active_site adds ahead of --topology)."""
    (tmp_path / "secsite.toml").write_text(SITE_WITH_INFERENCE)
    monkeypatch.chdir(tmp_path)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--resource", "gpu1"]) == 0
    out = capsys.readouterr().out
    assert "secllm.service" in out
    assert "secdns.service" not in out


def test_deploy_explicit_site_missing_file_fails_loud(tmp_path):
    missing = tmp_path / "nope.toml"
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
              "--site", str(missing)])


def test_deploy_site_with_bad_deploy_key_fails_loud(tmp_path):
    bad = SITE_WITH_INFERENCE.replace('without = ["secdns"]', 'without = ["secdns"]\nbogus = 1')
    tp = tmp_path / "secsite.toml"
    tp.write_text(bad)
    with pytest.raises(SystemExit):
        main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run", "--site", str(tp)])


# ── back-compat: a topology.toml with no [deploy]/per-resource-deploy keys must dry-run
#    byte-identically to before secsite.toml existed (same file GPU_SPLIT always was) ────
def test_deploy_topology_only_file_matches_pre_secsite_behavior(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)
    assert main(["--manifest", MANIFEST, "deploy", "fedora-fips", "--dry-run",
                 "--topology", str(tp), "--resource", "core"]) == 0
    out = capsys.readouterr().out
    assert "seccert.service" in out
    assert "secrouter.service" in out
    assert "secllm.service" not in out
    assert "secagent.service" not in out
    assert "secproxy.service" not in out


def test_plan_topology_only_file_unaffected_by_site_loader_swap(tmp_path, capsys):
    tp = tmp_path / "topology.toml"
    tp.write_text(GPU_SPLIT)
    assert main(["--manifest", MANIFEST, "plan", "fedora-fips", "--topology", str(tp)]) == 0
    out = capsys.readouterr().out
    assert "resource 'core'" in out and "placement:" in out


# ── verify/plan/bundle also resolve --site (secsite.toml awareness "where sensible") ────
def test_verify_picks_up_explicit_site(tmp_path, capsys):
    tp = tmp_path / "secsite.toml"
    tp.write_text(SITE_WITH_INFERENCE)
    assert main(["--manifest", MANIFEST, "verify", "--site", str(tp)]) == 0
    out = capsys.readouterr().out
    assert "topology valid" in out
    assert "gpu1" in out and "gpu2" in out


def test_plan_picks_up_explicit_site(tmp_path, capsys):
    tp = tmp_path / "secsite.toml"
    tp.write_text(SITE_WITH_INFERENCE)
    assert main(["--manifest", MANIFEST, "plan", "fedora-fips", "--site", str(tp),
                 "--resource", "gpu1"]) == 0
    out = capsys.readouterr().out
    assert "resource 'gpu1'" in out


def test_bundle_picks_up_explicit_site(tmp_path):
    import tarfile

    work = tmp_path / "work"
    (work / "secllm").mkdir(parents=True)
    out_dir = tmp_path / "out"
    tp = tmp_path / "secsite.toml"
    tp.write_text(SITE_WITH_INFERENCE)
    rc = main(["--manifest", MANIFEST, "--work", str(work), "--out", str(out_dir),
               "bundle", "fedora-fips", "--site", str(tp), "--resource", "gpu1"])
    assert rc == 0
    tarball = out_dir / "secsuite-1.6.0-fedora-fips-gpu1.tar.gz"
    assert tarball.exists()
    names = tarfile.open(tarball).getnames()
    assert any("/work/secllm" in n for n in names)
