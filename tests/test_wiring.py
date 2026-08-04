"""Tests for topology-driven deploy wiring."""

from __future__ import annotations

import json
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

# inference spread across TWO resources — N SecLLM instances behind SecRouter's backend pool.
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


def _manifest() -> Manifest:
    return Manifest.load(ROOT / "suite.toml")


def _topo(tmp_path) -> Topology:
    p = tmp_path / "topology.toml"
    p.write_text(GPU_SPLIT)
    return Topology.load(p, _manifest())


def _multi_topo(tmp_path) -> Topology:
    p = tmp_path / "topology-multi.toml"
    p.write_text(MULTI_INFERENCE)
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
    assert "SECLLM_URL=https://secllm.sec.internal:11400" in text
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


# ── multi-instance inference: SecRouter's backend pool (SECROUTER_SECLLM_ENDPOINTS) ─────
def test_secllm_endpoints_single_instance(tmp_path):
    topo = _topo(tmp_path)
    assert wiring.secllm_endpoints(topo) == ["https://secllm.sec.internal:11400/v1"]


def test_secllm_endpoints_multi_instance(tmp_path):
    topo = _multi_topo(tmp_path)
    assert wiring.secllm_endpoints(topo) == [
        "https://secllm-gpu1.sec.internal:11400/v1",
        "https://secllm-gpu2.sec.internal:11400/v1",
    ]


def test_env_for_secrouter_gets_secllm_endpoints_pool(tmp_path):
    topo = _multi_topo(tmp_path)
    env = topo.env_for("secrouter")
    assert env["SECROUTER_SECLLM_ENDPOINTS"] == (
        "https://secllm-gpu1.sec.internal:11400/v1,https://secllm-gpu2.sec.internal:11400/v1"
    )
    # a single URL can't represent a 2-instance pool, so the generic peer URL is absent
    assert "SECLLM_URL" not in env


def test_env_text_secrouter_gets_secllm_endpoints_pool(tmp_path):
    topo = _multi_topo(tmp_path)
    text = wiring.env_text(topo, "secrouter")
    assert ("SECROUTER_SECLLM_ENDPOINTS=https://secllm-gpu1.sec.internal:11400/v1,"
            "https://secllm-gpu2.sec.internal:11400/v1") in text


def test_zone_text_has_both_secllm_instances(tmp_path):
    topo = _multi_topo(tmp_path)
    text = wiring.zone_text(topo)
    assert "secllm-gpu1" in text and "10.0.0.6" in text
    assert "secllm-gpu2" in text and "10.0.0.7" in text


def test_write_addressing_multi_instance(tmp_path):
    topo = _multi_topo(tmp_path)
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "gpu1")
    zone = Path(written["zone"]).read_text()
    assert "secllm-gpu1" in zone and "secllm-gpu2" in zone
    # gpu1 hosts one secllm instance; its generic peer-env file is still keyed by the bare
    # component name (the per-service systemd env is a separate, target-specific artifact)
    assert set(written["env"]) == {"secllm"}


def test_secllm_env_text_carries_fixed_fields_and_token():
    text = wiring.secllm_env_text(admin_token="test-token-123")
    assert "SECLLM_HOST=0.0.0.0" in text
    assert "SECLLM_PORT=11400" in text
    assert "SECLLM_BACKEND=vllm" in text
    assert "SECLLM_ADMIN_TOKEN=test-token-123" in text


# ── host_port: the checkEgress-matching form (host:port, not the full URL) ──────────────
def test_host_port_keeps_port():
    assert wiring.host_port("https://secllm.sec.internal:11400/v1") == "secllm.sec.internal:11400"
    assert wiring.host_port("https://seccert.sec.internal:47001") == "seccert.sec.internal:47001"


def test_host_port_no_explicit_port():
    assert wiring.host_port("https://example.com/path") == "example.com"


# ── secrouter_egress_rules: the SecRouter EgressRule artifact (secrouter-egress.json) ───
def test_secrouter_egress_rules_single_instance_shape(tmp_path):
    topo = _topo(tmp_path)  # GPU_SPLIT: one secllm instance
    rules = wiring.secrouter_egress_rules(topo)
    assert len(rules) == 1
    rule = rules[0]
    # exact EgressRule shape (secrouter/src/security/types.ts): provider, allowedHost,
    # authorizedClassifications, authorization — nothing more, nothing less.
    assert set(rule) == {"provider", "allowedHost", "authorizedClassifications", "authorization"}
    assert rule["provider"] == "secllm"
    assert rule["allowedHost"] == ["secllm.sec.internal:11400"]  # host:port, matches checkEgress
    assert rule["authorizedClassifications"] == ["CUI"]  # this suite's internal-CUI level
    assert isinstance(rule["authorization"], str) and rule["authorization"]


def test_secrouter_egress_rules_multi_instance_pool_hosts(tmp_path):
    topo = _multi_topo(tmp_path)  # MULTI_INFERENCE: two secllm instances
    rules = wiring.secrouter_egress_rules(topo)
    assert len(rules) == 1
    assert rules[0]["allowedHost"] == [
        "secllm-gpu1.sec.internal:11400",
        "secllm-gpu2.sec.internal:11400",
    ]


def test_secrouter_egress_rules_classifications_overridable(tmp_path):
    topo = _topo(tmp_path)
    rules = wiring.secrouter_egress_rules(
        topo, classifications=["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"]
    )
    assert rules[0]["authorizedClassifications"] == ["UNCLASSIFIED", "CUI", "CUI//SP-PRVCY"]
    # the default wasn't mutated by the override
    assert wiring.secrouter_egress_rules(topo)[0]["authorizedClassifications"] == ["CUI"]


def test_secrouter_egress_rules_json_round_trips(tmp_path):
    topo = _multi_topo(tmp_path)
    rules = wiring.secrouter_egress_rules(topo)
    assert json.loads(json.dumps(rules)) == rules


def test_secrouter_egress_rules_empty_without_secllm(tmp_path):
    crafted = (
        'suite = "1"\n'
        '[components.secrouter]\nrepo = "o/secrouter"\nref = "v1"\ntier = "gateway"\nport = 47002\n'
        '[targets.fedora-fips]\nkind = "systemd-native"\n'
    )
    mpath = tmp_path / "suite.toml"
    mpath.write_text(crafted)
    m = Manifest.load(mpath)
    topo_text = (
        'domain = "sec.internal"\n'
        '[resources.core]\ntarget = "fedora-fips"\naddress = "10.0.0.5"\n'
        '[groups.gateway]\nresource = "core"\n'
    )
    tp = tmp_path / "topology.toml"
    tp.write_text(topo_text)
    topo = Topology.load(tp, m)
    assert wiring.secrouter_egress_rules(topo) == []


# ── secllm_shared_token: cached-on-disk coordination across independent deploy calls ────
def test_secllm_shared_token_persists_and_is_reused(tmp_path):
    out = tmp_path / "out"
    t1 = wiring.secllm_shared_token(out)
    t2 = wiring.secllm_shared_token(out)
    assert t1 == t2
    assert (out / "secllm-shared-token").read_text().strip() == t1


def test_secllm_shared_token_scoped_per_out_dir(tmp_path):
    t1 = wiring.secllm_shared_token(tmp_path / "a")
    t2 = wiring.secllm_shared_token(tmp_path / "b")
    assert t1 != t2  # coordination is only guaranteed within one shared --out tree


# ── secllm_env_text: the shared SECLLM_API_TOKEN alongside the per-instance admin token ──
def test_secllm_env_text_carries_api_token():
    text = wiring.secllm_env_text(admin_token="admin-tok", api_token="shared-tok")
    assert "SECLLM_ADMIN_TOKEN=admin-tok" in text
    assert "SECLLM_API_TOKEN=shared-tok" in text


def test_secllm_env_text_generates_api_token_if_absent():
    text = wiring.secllm_env_text(admin_token="admin-tok")
    line = next(ln for ln in text.splitlines() if ln.startswith("SECLLM_API_TOKEN="))
    assert len(line.split("=", 1)[1]) > 10


# ── Topology.env_for: SECROUTER_EGRESS_FILE / SECROUTER_SECLLM_TOKEN passthrough ────────
def test_env_for_secrouter_gets_egress_file_and_token_when_given(tmp_path):
    topo = _topo(tmp_path)
    env = topo.env_for(
        "secrouter", secllm_token="tok-123",
        secrouter_egress_file="/etc/secsuite/secrouter-egress.json",
    )
    assert env["SECROUTER_SECLLM_TOKEN"] == "tok-123"
    assert env["SECROUTER_EGRESS_FILE"] == "/etc/secsuite/secrouter-egress.json"


def test_env_for_secrouter_omits_them_by_default(tmp_path):
    topo = _topo(tmp_path)
    env = topo.env_for("secrouter")
    assert "SECROUTER_SECLLM_TOKEN" not in env
    assert "SECROUTER_EGRESS_FILE" not in env


def test_env_for_non_secrouter_never_gets_secrouter_only_keys(tmp_path):
    topo = _topo(tmp_path)
    env = topo.env_for(
        "secllm", secllm_token="tok-123",
        secrouter_egress_file="/etc/secsuite/secrouter-egress.json",
    )
    assert "SECROUTER_SECLLM_TOKEN" not in env
    assert "SECROUTER_EGRESS_FILE" not in env


# ── write_addressing: installs the egress artifact + wires SecRouter's/SecLLM's env ─────
def test_write_addressing_writes_egress_file_when_secrouter_here(tmp_path):
    topo = _topo(tmp_path)  # GPU_SPLIT: secrouter is on 'core'
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "core")
    assert "egress" in written
    egress_path = Path(written["egress"])
    assert egress_path == out / "secrouter-egress.json"
    assert json.loads(egress_path.read_text()) == wiring.secrouter_egress_rules(topo)


def test_write_addressing_no_egress_file_when_secrouter_not_here(tmp_path):
    topo = _topo(tmp_path)
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "gpu")  # secllm here, not secrouter
    assert "egress" not in written
    assert not (out / "secrouter-egress.json").exists()


def test_write_addressing_secrouter_env_gets_egress_file_default_staging_path(tmp_path):
    topo = _topo(tmp_path)
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "core")
    text = Path(written["env"]["secrouter"]).read_text()
    assert f"SECROUTER_EGRESS_FILE={out / 'secrouter-egress.json'}" in text
    assert "SECROUTER_SECLLM_TOKEN=" in text


def test_write_addressing_secrouter_egress_path_override(tmp_path):
    topo = _topo(tmp_path)
    out = tmp_path / "out"
    written = wiring.write_addressing(
        topo, out, "core", secrouter_egress_path="/etc/secsuite/secrouter-egress.json"
    )
    text = Path(written["env"]["secrouter"]).read_text()
    assert "SECROUTER_EGRESS_FILE=/etc/secsuite/secrouter-egress.json" in text
    # staging copy is still written regardless of where SECROUTER_EGRESS_FILE points
    assert Path(written["egress"]).exists()


def test_write_addressing_shared_token_matches_secllm_and_secrouter(tmp_path):
    topo = _topo(tmp_path)  # secrouter on 'core', secllm on 'gpu'
    out = tmp_path / "out"
    written_core = wiring.write_addressing(topo, out, "core")
    written_gpu = wiring.write_addressing(topo, out, "gpu")

    secrouter_text = Path(written_core["env"]["secrouter"]).read_text()
    token_line = next(
        ln for ln in secrouter_text.splitlines() if ln.startswith("SECROUTER_SECLLM_TOKEN=")
    )
    secrouter_token = token_line.split("=", 1)[1]

    # the caller (a target's deploy()) obtains the SAME value this way for secllm_env_text
    api_token = wiring.secllm_shared_token(out)
    assert secrouter_token == api_token

    secllm_env = wiring.secllm_env_text(api_token=api_token)
    assert f"SECLLM_API_TOKEN={api_token}" in secllm_env
    # sanity: write_addressing("gpu") didn't mint a second, different token
    assert wiring.secllm_shared_token(out) == api_token
