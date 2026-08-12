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

# GPU_SPLIT plus secproxy (edge tier) on 'core' — the fronting axis in play.
EDGE_SPLIT = """
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
[groups.edge]
resource = "core"
[groups.inference]
resource = "gpu"
"""

# MULTI_INFERENCE plus secproxy on 'core' — fronting alongside a multi-resource (2-instance)
# SecLLM pool, to confirm the nginx config generator isn't confused by a multi-resource tier
# elsewhere in the same topology.
EDGE_MULTI_INFERENCE = """
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
[groups.edge]
resource = "core"
[groups.inference]
resources = ["gpu1", "gpu2"]
"""

# The fronted axis: secproxy puts these HTTP services behind :443. secagent is NOT here — it's
# an installed pi harness with no inbound listener (no port), so it's never fronted.
FRONTED = ("secsso", "secrouter", "secchat", "secrecorder")


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


def _edge_topo(tmp_path) -> Topology:
    p = tmp_path / "topology-edge.toml"
    p.write_text(EDGE_SPLIT)
    return Topology.load(p, _manifest())


def _edge_multi_topo(tmp_path) -> Topology:
    p = tmp_path / "topology-edge-multi.toml"
    p.write_text(EDGE_MULTI_INFERENCE)
    return Topology.load(p, _manifest())


# ── active_topology ──────────────────────────────────────────────────────────────────
def test_active_topology_synthesizes_single_host(tmp_path):
    m = _manifest()
    topo, from_file = wiring.active_topology(m, tmp_path / "nope.toml", "macos")
    assert from_file is False
    assert list(topo.resources) == ["local"]
    assert set(topo.placement()) == set(m.select())  # everything selected on the one host (experimental off)


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
    assert "SECLLM_URL=http://secllm.sec.internal:11400" in text
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


# ── nginx_conf_text: secproxy's reverse-proxy config (fronts the HTTP services on :443) ──
CERT_DIR = "/etc/secsuite/secproxy"


def test_nginx_conf_text_server_blocks_for_exactly_the_fronted_set(tmp_path):
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    for name in FRONTED:
        assert f"server_name {name}.sec.internal;" in text
    # never fronted, regardless of placement — no :443 server_name for the direct-dial services
    assert "server_name seccert.sec.internal;" not in text
    assert "server_name secllm.sec.internal;" not in text
    assert "server_name secdns.sec.internal;" not in text
    assert "server_name secproxy.sec.internal;" not in text


def test_nginx_conf_text_proxy_pass_targets_are_correct(tmp_path):
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    assert "proxy_pass http://10.0.0.5:9000;" in text      # secsso
    assert "proxy_pass http://10.0.0.5:47002;" in text     # secrouter
    assert "proxy_pass http://10.0.0.5:47010;" in text     # secchat (native)
    assert "proxy_pass http://10.0.0.5:47003;" in text     # secrecorder


def test_nginx_conf_text_ssl_cert_paths_use_cert_dir(tmp_path):
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    # one SAN cert covers them all — every :443 block reads the SAME cert_dir
    assert f"ssl_certificate {CERT_DIR}/fullchain.pem;" in text
    assert f"ssl_certificate_key {CERT_DIR}/privkey.pem;" in text
    # one per fronted server block, plus one for the bare-domain landing page
    assert text.count("ssl_certificate ") == len(FRONTED) + 1
    # cert_dir is a parameter
    other = wiring.nginx_conf_text(topo, "/opt/tls")
    assert "ssl_certificate /opt/tls/fullchain.pem;" in other
    assert CERT_DIR + "/fullchain.pem" not in other


def test_nginx_conf_text_websocket_map_and_upgrade_headers(tmp_path):
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    assert "map $http_upgrade $connection_upgrade {" in text
    assert "proxy_set_header Upgrade $http_upgrade;" in text
    assert "proxy_set_header Connection $connection_upgrade;" in text
    # standard reverse-proxy headers on every fronted block
    assert text.count("proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;") == len(FRONTED)
    assert text.count("proxy_set_header X-Forwarded-Proto $scheme;") == len(FRONTED)
    assert text.count("proxy_set_header Host $host;") == len(FRONTED)


def test_nginx_conf_text_port_80_acme_webroot_and_redirect(tmp_path):
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    assert "listen 80;" in text and "listen [::]:80;" in text
    # the bare domain + every fronted name share the one :80 server (ACME webroot + redirect)
    assert ("server_name sec.internal secsso.sec.internal secrouter.sec.internal "
            "secchat.sec.internal secrecorder.sec.internal;") in text
    assert "location /.well-known/acme-challenge/ {" in text
    assert "root /var/lib/secsuite/secproxy/acme;" in text
    assert "return 301 https://$host$request_uri;" in text


def test_nginx_conf_text_is_a_complete_config_with_http2(tmp_path):
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    # complete config (runnable via `nginx -c`): events + http blocks, writable paths in the
    # state dir (ProtectSystem=strict), and the header pointing at topology.toml
    assert "events {" in text and "http {" in text
    assert "pid /var/lib/secsuite/secproxy/nginx.pid;" in text
    assert "proxy_temp_path /var/lib/secsuite/secproxy/tmp/proxy;" in text
    assert "edit topology.toml, not this file" in text
    # one :443 server per fronted service, plus one for the bare-domain landing page
    assert text.count("listen 443 ssl;") == len(FRONTED) + 1
    assert text.count("http2 on;") == len(FRONTED) + 1


def test_nginx_conf_text_deterministic_manifest_order(tmp_path):
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    positions = [text.index(f"server_name {name}.sec.internal;") for name in FRONTED]
    assert positions == sorted(positions)  # manifest order, same as fronted_instances


def test_nginx_conf_text_multi_resource_topology_handled(tmp_path):
    # secproxy fronts the 5 the same way alongside a 2-instance SecLLM pool elsewhere — the
    # multi-resource inference tier doesn't leak into the nginx config (secllm is never fronted).
    topo = _edge_multi_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    for name in FRONTED:
        assert f"server_name {name}.sec.internal;" in text
    assert "secllm" not in text
    assert "secllm-gpu1" not in text and "secllm-gpu2" not in text


def test_write_addressing_writes_nginx_conf_when_secproxy_placed_here(tmp_path):
    topo = _edge_topo(tmp_path)  # secproxy is on 'core' (edge tier)
    out = tmp_path / "out"
    written_core = wiring.write_addressing(topo, out, "core")
    assert "nginx_conf" in written_core
    nginx_path = Path(written_core["nginx_conf"])
    assert nginx_path == out / "secproxy.nginx.conf"
    # write_addressing hardcodes the fedora cert dir /etc/secsuite/secproxy
    assert nginx_path.read_text() == wiring.nginx_conf_text(topo, "/etc/secsuite/secproxy")
    # the nginx conf is the ONLY reverse-proxy artifact written (secproxy runs nginx on both
    # targets — there is no separate per-target proxy config)
    assert set(written_core) == {"zone", "env", "egress", "oidc", "nginx_conf"}

    written_gpu = wiring.write_addressing(topo, out, "gpu")  # secllm only, not secproxy
    assert "nginx_conf" not in written_gpu


def test_write_addressing_no_nginx_conf_when_secproxy_not_in_topology(tmp_path):
    topo = _topo(tmp_path)  # GPU_SPLIT: no edge group at all
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "core")
    assert "nginx_conf" not in written
    assert not (out / "secproxy.nginx.conf").exists()


# ── multi-instance inference: SecRouter's backend pool (SECROUTER_SECLLM_ENDPOINTS) ─────
def test_secllm_endpoints_single_instance(tmp_path):
    topo = _topo(tmp_path)
    assert wiring.secllm_endpoints(topo) == ["http://secllm.sec.internal:11400/v1"]


def test_secllm_endpoints_multi_instance(tmp_path):
    topo = _multi_topo(tmp_path)
    assert wiring.secllm_endpoints(topo) == [
        "http://secllm-gpu1.sec.internal:11400/v1",
        "http://secllm-gpu2.sec.internal:11400/v1",
    ]


def test_env_for_secrouter_gets_secllm_endpoints_pool(tmp_path):
    topo = _multi_topo(tmp_path)
    env = topo.env_for("secrouter")
    assert env["SECROUTER_SECLLM_ENDPOINTS"] == (
        "http://secllm-gpu1.sec.internal:11400/v1,http://secllm-gpu2.sec.internal:11400/v1"
    )
    # a single URL can't represent a 2-instance pool, so the generic peer URL is absent
    assert "SECLLM_URL" not in env


def test_env_text_secrouter_gets_secllm_endpoints_pool(tmp_path):
    topo = _multi_topo(tmp_path)
    text = wiring.env_text(topo, "secrouter")
    assert ("SECROUTER_SECLLM_ENDPOINTS=http://secllm-gpu1.sec.internal:11400/v1,"
            "http://secllm-gpu2.sec.internal:11400/v1") in text


# ── custom-catalog remap: secsite.toml [inference.models] → SECROUTER_SECLLM_MODELS ─────
def test_env_for_secrouter_emits_secllm_models_remap(tmp_path):
    topo = _topo(tmp_path)
    env = topo.env_for("secrouter", secllm_models={"balanced": "org/gemma-26b", "fast": "org/llama-3b"})
    assert env["SECROUTER_SECLLM_MODELS"] == "balanced=org/gemma-26b,fast=org/llama-3b"


def test_env_for_secrouter_no_secllm_models_when_unset(tmp_path):
    assert "SECROUTER_SECLLM_MODELS" not in _topo(tmp_path).env_for("secrouter")


def test_write_addressing_threads_secllm_models_into_secrouter_env(tmp_path):
    topo = _topo(tmp_path)
    out = tmp_path / "addr"
    wiring.write_addressing(topo, out, "core", secllm_models={"balanced": "org/gemma-26b"})
    assert "SECROUTER_SECLLM_MODELS=balanced=org/gemma-26b" in (out / "env" / "secrouter.env").read_text()


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


# ── secrouter_oidc_config: security.oidc fragment for SecSSO issuer_mode: global ────────
def test_secrouter_oidc_config_shape(tmp_path):
    topo = _topo(tmp_path)  # secsso is on 'core' (identity tier)
    oidc = wiring.secrouter_oidc_config(topo)
    assert oidc == {
        "issuer": "http://secsso.sec.internal:9000/",
        "audience": "secrouter",
        "jwksUri": "http://secsso.sec.internal:9000/application/o/secrouter/jwks/",
        # svc-secagent is SecAgent's non-interactive service account (client_credentials tokens
        # can't carry an MFA assertion, so it's trusted to skip requireMfa).
        "serviceSubjects": ["svc-secagent"],
    }


def test_secrouter_oidc_config_empty_without_secsso(tmp_path):
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
    assert wiring.secrouter_oidc_config(topo) == {}


def test_secrouter_oidc_config_json_serializable(tmp_path):
    topo = _topo(tmp_path)
    oidc = wiring.secrouter_oidc_config(topo)
    assert json.loads(json.dumps(oidc)) == oidc


# ── secagent_pi_models_json: adapt the example for pi's service (api-key) auth mode ─────
def test_secagent_pi_models_json_substitutes_base_url_and_api_key():
    example = {
        "_comment": ["KIMI GUARD: registers ONLY the secrouter provider"],
        "providers": {
            "secrouter": {
                "baseUrl": "https://secrouter.<domain>:47002/v1",
                "models": [{"id": "gemma-3-12b-it", "name": "Gemma 3 12B (SecRouter)"}],
            }
        },
    }
    result = wiring.secagent_pi_models_json(example, "https://secrouter.sec.internal:47002/v1")
    provider = result["providers"]["secrouter"]
    assert provider["baseUrl"] == "https://secrouter.sec.internal:47002/v1"
    assert provider["apiKey"] == "!secagent token"
    # model catalog + comment pass through unchanged
    assert provider["models"] == example["providers"]["secrouter"]["models"]
    assert result["_comment"] == example["_comment"]
    # pure function — the input is untouched
    assert "apiKey" not in example["providers"]["secrouter"]


def test_secagent_pi_models_json_never_introduces_kimi():
    example = {"providers": {"secrouter": {"baseUrl": "https://secrouter.<domain>:47002/v1"}}}
    result = wiring.secagent_pi_models_json(example, "https://secrouter.sec.internal:47002/v1")
    assert "kimi" not in json.dumps(result).lower()
    assert set(result["providers"]) == {"secrouter"}  # no provider added, none removed


def test_secagent_pi_models_json_handles_multiple_providers():
    example = {"providers": {
        "a": {"baseUrl": "https://a.example/v1"},
        "b": {"baseUrl": "https://b.example/v1"},
    }}
    result = wiring.secagent_pi_models_json(example, "https://secrouter.sec.internal:47002/v1")
    assert result["providers"]["a"]["baseUrl"] == "https://secrouter.sec.internal:47002/v1"
    assert result["providers"]["b"]["baseUrl"] == "https://secrouter.sec.internal:47002/v1"
    assert result["providers"]["a"]["apiKey"] == "!secagent token"
    assert result["providers"]["b"]["apiKey"] == "!secagent token"


def test_secagent_pi_models_json_against_real_shipped_example():
    # Exercises the REAL file from the sibling secagent checkout (not a hardcoded fixture),
    # so this catches drift if that file's shape ever changes. Skips gracefully if the
    # sibling checkout isn't present.
    example_path = ROOT.parent / "secagent" / "pi" / "models.secrouter.example.json"
    if not example_path.exists():
        pytest.skip("secagent checkout not present alongside secdeploy")
    example = json.loads(example_path.read_text())
    result = wiring.secagent_pi_models_json(example, "https://secrouter.sec.internal:47002/v1")
    assert result["providers"]["secrouter"]["baseUrl"] == "https://secrouter.sec.internal:47002/v1"
    assert result["providers"]["secrouter"]["apiKey"] == "!secagent token"
    # No provider named/keyed "kimi" was ADDED (the real example's _comment legitimately
    # *mentions* Kimi, by name, to document that it's excluded — that's expected pass-through
    # text, not a provider entry, so this checks provider KEYS specifically, not the raw dump).
    assert "kimi" not in {k.lower() for k in result.get("providers", {})}


# ── sync_secagent_service_secret: mirrors SecSSO's generated secret into secagent's env ──
def test_sync_secagent_service_secret_fills_blank_value(tmp_path):
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECAGENT_SERVICE_CLIENT_SECRET=abc123\nOTHER=x\n")
    secrets_env = tmp_path / "secrets.env"
    secrets_env.write_text("SECAGENT_CLIENT_SECRET=\nOTHER_KEY=y\n")
    synced = wiring.sync_secagent_service_secret(secsso_env, secrets_env)
    assert synced == "abc123"
    assert "SECAGENT_CLIENT_SECRET=abc123" in secrets_env.read_text()
    assert "OTHER_KEY=y" in secrets_env.read_text()  # untouched lines survive


def test_sync_secagent_service_secret_never_overwrites_non_blank_value(tmp_path):
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECAGENT_SERVICE_CLIENT_SECRET=abc123\n")
    secrets_env = tmp_path / "secrets.env"
    secrets_env.write_text("SECAGENT_CLIENT_SECRET=already-set\n")
    synced = wiring.sync_secagent_service_secret(secsso_env, secrets_env)
    assert synced is None
    assert "SECAGENT_CLIENT_SECRET=already-set" in secrets_env.read_text()


def test_sync_secagent_service_secret_missing_secsso_secret_is_a_noop(tmp_path):
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("OTHER=x\n")  # no SECAGENT_SERVICE_CLIENT_SECRET line at all
    secrets_env = tmp_path / "secrets.env"
    secrets_env.write_text("SECAGENT_CLIENT_SECRET=\n")
    assert wiring.sync_secagent_service_secret(secsso_env, secrets_env) is None
    assert "SECAGENT_CLIENT_SECRET=\n" in secrets_env.read_text()


# ── env_for secchat branch + sync_secchat_env / sync_secsso_secchat_redirect: turnkey native
#    SecChat stack env. secchat is the canonical chat component (a default-on stack) — the native
#    rebuild that replaced BOTH prior chat components (team chat + governed AI chat) at cutover.
#    Its OIDC client id stays `secchatng` (the retained Authentik client — users see "SecChat"). ──
def test_env_for_secchat_branch_full(tmp_path):
    # GPU_SPLIT (no secproxy/edge) → plain ported http URLs, including secchat's OWN url
    # (SECCHAT_PUBLIC_URL) — the same peer_urls-by-self-key source every other peer URL uses.
    topo = _topo(tmp_path)
    env = topo.env_for("secchat")
    assert env["SECCHAT_OIDC_ISSUER"] == "http://secsso.sec.internal:9000/application/o/secchatng/"
    assert env["SECCHAT_OIDC_AUDIENCE"] == "secchatng"
    assert env["SECCHAT_OIDC_CLIENT_ID"] == "secchatng"
    assert env["SECROUTER_URL"] == "http://secrouter.sec.internal:47002"
    assert env["SECCHAT_PUBLIC_URL"] == "http://secchat.sec.internal:47010"
    # the client secret is never topology-derived — sync_secchat_env mirrors it from SecSSO
    assert "SECCHAT_OIDC_CLIENT_SECRET" not in env


def _env_dict(path):
    return {ln.split("=", 1)[0]: ln.split("=", 1)[1]
            for ln in path.read_text().splitlines() if "=" in ln and not ln.startswith("#")}


def test_sync_secchat_env_mirrors_secret_and_writes_topology(tmp_path):
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    # SecSSO keeps the retained secchatng-named client secret (its Authentik client id stays
    # secchatng even though the app is now "SecChat").
    secsso_env.write_text("SECCHATNG_OIDC_CLIENT_SECRET=login-abc\n")
    # As the stack .env looks right after the generic seed randomized the blank mirror-target; a
    # topology key still at its .env.example placeholder; a per-instance secret to preserve.
    secchat_env = tmp_path / "secchat.env"
    secchat_env.write_text(
        "SECCHAT_OIDC_CLIENT_SECRET=RANDOMSEED\n"
        "SECCHAT_OIDC_ISSUER=https://secsso.sec.internal/application/o/secchatng/\n"
        "SECCHAT_SESSION_SECRET=keep-me\n"
    )
    written = wiring.sync_secchat_env(secsso_env, secchat_env, topo)
    assert written is not None and "SECCHAT_OIDC_CLIENT_SECRET" in written
    assert written == sorted(wiring._SECCHAT_MANAGED_KEYS)
    vals = _env_dict(secchat_env)
    # the mirrored secret OVERWRITES the randomized seed — the whole reason this isn't blank-only
    assert vals["SECCHAT_OIDC_CLIENT_SECRET"] == "login-abc"
    # topology env written (placeholder domain corrected to the real one + port)
    assert vals["SECCHAT_OIDC_ISSUER"] == "http://secsso.sec.internal:9000/application/o/secchatng/"
    assert vals["SECCHAT_OIDC_AUDIENCE"] == "secchatng"
    assert vals["SECCHAT_OIDC_CLIENT_ID"] == "secchatng"
    assert vals["SECCHAT_PUBLIC_URL"] == "http://secchat.sec.internal:47010"
    assert vals["SECROUTER_URL"] == "http://secrouter.sec.internal:47002"
    # non-managed keys survive untouched
    assert vals["SECCHAT_SESSION_SECRET"] == "keep-me"


def test_sync_secchat_env_noop_without_secsso_secret(tmp_path):
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("PG_PASS=x\n")  # no SECCHATNG_OIDC_CLIENT_SECRET provisioned yet
    secchat_env = tmp_path / "secchat.env"
    secchat_env.write_text("SECCHAT_OIDC_CLIENT_SECRET=\n")
    assert wiring.sync_secchat_env(secsso_env, secchat_env, topo) is None


def test_sync_secchat_env_noop_when_files_missing(tmp_path):
    topo = _topo(tmp_path)
    assert wiring.sync_secchat_env(tmp_path / "nope-a", tmp_path / "nope-b", topo) is None


def test_sync_secsso_secchat_redirect_points_at_the_topology_callback(tmp_path):
    # SecSSO's blueprint must register SecChat's redirect_uri for wherever SecChat ACTUALLY lives
    # in this topology — not the sec.internal .env.example default. Overwrites both keys in
    # secsso's .env from SecChat's own topology URL (the same one env_for gives SECCHAT_PUBLIC_URL,
    # so the two sides agree by construction), and leaves everything else alone. The SecSSO-side
    # env var names stay SECCHATNG_* (the retained Authentik client).
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text(
        "SECCHATNG_REDIRECT_URI=https://secchat.sec.internal/auth/callback\n"  # .env.example default
        "SECCHATNG_LAUNCH_URL=https://secchat.sec.internal\n"
        "AUTHENTIK_SECRET_KEY=keep-me\n"
    )
    written = wiring.sync_secsso_secchat_redirect(secsso_env, topo)
    assert written == ["SECCHATNG_LAUNCH_URL", "SECCHATNG_REDIRECT_URI"]
    vals = _env_dict(secsso_env)
    assert vals["SECCHATNG_REDIRECT_URI"] == "http://secchat.sec.internal:47010/auth/callback"
    assert vals["SECCHATNG_LAUNCH_URL"] == "http://secchat.sec.internal:47010"
    # exactly SecChat's SECCHAT_PUBLIC_URL + /auth/callback — the SecChat side builds the identical
    # callback, so redirect_uri matches by construction (this is the whole point)
    assert f'{vals["SECCHATNG_LAUNCH_URL"]}/auth/callback' == vals["SECCHATNG_REDIRECT_URI"]
    assert vals["AUTHENTIK_SECRET_KEY"] == "keep-me"  # untouched


def test_sync_secsso_secchat_redirect_noops_when_absent_or_env_missing(tmp_path):
    # A manifest with no secchat at all → nothing to point the SSO redirect at.
    crafted = (
        'suite = "1"\n'
        '[components.secrouter]\nrepo = "o/secrouter"\nref = "v1"\ntier = "gateway"\nport = 47002\n'
        '[targets.fedora-fips]\nkind = "systemd-native"\n'
    )
    mpath = tmp_path / "suite.toml"; mpath.write_text(crafted)
    tp = tmp_path / "topology.toml"
    tp.write_text('domain = "sec.internal"\n[resources.core]\ntarget = "fedora-fips"\n'
                  'address = "10.0.0.5"\n[groups.gateway]\nresource = "core"\n')
    topo = Topology.load(tp, Manifest.load(mpath))
    secsso_env = tmp_path / "secsso.env"; secsso_env.write_text("X=1\n")
    assert wiring.sync_secsso_secchat_redirect(secsso_env, topo) is None  # nothing to point at
    topo2 = _topo(tmp_path)
    assert wiring.sync_secsso_secchat_redirect(tmp_path / "nope.env", topo2) is None  # no secsso .env


def test_sync_secchat_env_refreshes_managed_keys_on_rerun_and_keeps_operator_extra(tmp_path):
    # A redeploy must REFRESH every managed key (not just fill it once) while an operator-added
    # key outside the managed set survives untouched across both runs.
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECCHATNG_OIDC_CLIENT_SECRET=first-secret\n")
    secchat_env = tmp_path / "secchat.env"
    secchat_env.write_text(
        "SECCHAT_OIDC_CLIENT_SECRET=\n"
        "SECCHAT_OIDC_ISSUER=https://stale.example/wrong\n"
        "OPERATOR_EXTRA=do-not-touch\n"
    )
    first = wiring.sync_secchat_env(secsso_env, secchat_env, topo)
    assert first is not None
    vals1 = _env_dict(secchat_env)
    assert vals1["SECCHAT_OIDC_CLIENT_SECRET"] == "first-secret"
    assert vals1["SECCHAT_OIDC_ISSUER"] == "http://secsso.sec.internal:9000/application/o/secchatng/"
    # SecSSO rotates/regenerates its secret (e.g. a fresh secsso deploy) between the two syncs —
    # the re-run must pick up the NEW value, not leave the stale mirrored one in place.
    secsso_env.write_text("SECCHATNG_OIDC_CLIENT_SECRET=rotated-secret\n")
    second = wiring.sync_secchat_env(secsso_env, secchat_env, topo)
    assert second == first  # same key set both times
    vals2 = _env_dict(secchat_env)
    assert vals2["SECCHAT_OIDC_CLIENT_SECRET"] == "rotated-secret"
    assert vals2["SECCHAT_OIDC_ISSUER"] == vals1["SECCHAT_OIDC_ISSUER"]  # refreshed, still correct
    assert vals2["OPERATOR_EXTRA"] == "do-not-touch"  # untouched across both runs


# ── env_for secrecorder branch + sync_secrecorder_env / sync_secsso_secrecorder_redirect: turnkey
#    SecRecorder SSO + summarization. SecRecorder is a NATIVE service (not a stack like secchat), so
#    its managed env is the topology-generated addressing env (env/secrecorder.env) the targets layer
#    onto the running service — launchd env on macOS, a second EnvironmentFile= on fedora-fips. Its
#    OIDC client id is a brand-new "secrecorder" (no retained-name subtlety like secchatng). ──
def test_env_for_secrecorder_branch_full(tmp_path):
    # GPU_SPLIT (no secproxy/edge) → plain ported http URLs, including secrecorder's OWN url
    # (SECRECORDER_PUBLIC_URL) — the same peer_urls-by-self-key source every other peer URL uses.
    topo = _topo(tmp_path)
    env = topo.env_for("secrecorder")
    assert env["SECRECORDER_OIDC_ISSUER"] == "http://secsso.sec.internal:9000/application/o/secrecorder/"
    assert env["SECRECORDER_OIDC_AUDIENCE"] == "secrecorder"
    assert env["SECRECORDER_OIDC_CLIENT_ID"] == "secrecorder"
    assert env["SECRECORDER_SUMMARIZE_ENDPOINT"] == "http://secrouter.sec.internal:47002/v1"
    assert env["SECRECORDER_PUBLIC_URL"] == "http://secrecorder.sec.internal:47003"
    # the client secret is never topology-derived — sync_secrecorder_env mirrors it from SecSSO
    assert "SECRECORDER_OIDC_CLIENT_SECRET" not in env


def test_sync_secrecorder_env_mirrors_secret_and_writes_topology(tmp_path):
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECRECORDER_OIDC_CLIENT_SECRET=login-xyz\n")
    # As env/secrecorder.env looks right after write_addressing wrote the topology env; a stale
    # placeholder issuer to prove the refresh; a local session secret + operator knob to preserve.
    secrecorder_env = tmp_path / "secrecorder.env"
    secrecorder_env.write_text(
        "SECRECORDER_OIDC_ISSUER=https://stale.example/wrong\n"
        "SECRECORDER_SESSION_SECRET=keep-me\n"
        "SECRECORDER_SUMMARIZE_ENABLED=true\n"
    )
    written = wiring.sync_secrecorder_env(secsso_env, secrecorder_env, topo)
    assert written is not None and "SECRECORDER_OIDC_CLIENT_SECRET" in written
    assert written == sorted(wiring._SECRECORDER_MANAGED_KEYS)
    vals = _env_dict(secrecorder_env)
    # the mirrored secret is the whole reason this exists (never topology-derived)
    assert vals["SECRECORDER_OIDC_CLIENT_SECRET"] == "login-xyz"
    # topology env written (stale placeholder corrected to the real issuer + the governed endpoint)
    assert vals["SECRECORDER_OIDC_ISSUER"] == "http://secsso.sec.internal:9000/application/o/secrecorder/"
    assert vals["SECRECORDER_OIDC_AUDIENCE"] == "secrecorder"
    assert vals["SECRECORDER_OIDC_CLIENT_ID"] == "secrecorder"
    assert vals["SECRECORDER_PUBLIC_URL"] == "http://secrecorder.sec.internal:47003"
    assert vals["SECRECORDER_SUMMARIZE_ENDPOINT"] == "http://secrouter.sec.internal:47002/v1"
    # non-managed keys survive untouched: the local session secret + the operator-set summarize knob
    assert vals["SECRECORDER_SESSION_SECRET"] == "keep-me"
    assert vals["SECRECORDER_SUMMARIZE_ENABLED"] == "true"


def test_sync_secrecorder_env_noop_without_secsso_secret(tmp_path):
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("PG_PASS=x\n")  # no SECRECORDER_OIDC_CLIENT_SECRET provisioned yet
    secrecorder_env = tmp_path / "secrecorder.env"
    secrecorder_env.write_text("SECRECORDER_OIDC_ISSUER=x\n")
    assert wiring.sync_secrecorder_env(secsso_env, secrecorder_env, topo) is None


def test_sync_secrecorder_env_noop_when_files_missing(tmp_path):
    topo = _topo(tmp_path)
    assert wiring.sync_secrecorder_env(tmp_path / "nope-a", tmp_path / "nope-b", topo) is None


def test_sync_secsso_secrecorder_redirect_points_at_the_topology_callback(tmp_path):
    # SecSSO's blueprint must register SecRecorder's redirect_uri for wherever SecRecorder ACTUALLY
    # lives in this topology — not the sec.internal .env.example default. Overwrites both keys in
    # secsso's .env from SecRecorder's own topology URL (the same one env_for gives
    # SECRECORDER_PUBLIC_URL, so the two sides agree by construction), leaving everything else alone.
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text(
        "SECRECORDER_REDIRECT_URI=https://secrecorder.sec.internal/auth/callback\n"  # .env.example default
        "SECRECORDER_LAUNCH_URL=https://secrecorder.sec.internal\n"
        "AUTHENTIK_SECRET_KEY=keep-me\n"
    )
    written = wiring.sync_secsso_secrecorder_redirect(secsso_env, topo)
    assert written == ["SECRECORDER_LAUNCH_URL", "SECRECORDER_REDIRECT_URI"]
    vals = _env_dict(secsso_env)
    assert vals["SECRECORDER_REDIRECT_URI"] == "http://secrecorder.sec.internal:47003/auth/callback"
    assert vals["SECRECORDER_LAUNCH_URL"] == "http://secrecorder.sec.internal:47003"
    # exactly SecRecorder's SECRECORDER_PUBLIC_URL + /auth/callback — the SecRecorder side builds the
    # identical callback, so redirect_uri matches by construction (this is the whole point)
    assert f'{vals["SECRECORDER_LAUNCH_URL"]}/auth/callback' == vals["SECRECORDER_REDIRECT_URI"]
    assert vals["AUTHENTIK_SECRET_KEY"] == "keep-me"  # untouched


def test_sync_secsso_secrecorder_redirect_noops_when_absent_or_env_missing(tmp_path):
    # A manifest with no secrecorder at all → nothing to point the SSO redirect at.
    crafted = (
        'suite = "1"\n'
        '[components.secrouter]\nrepo = "o/secrouter"\nref = "v1"\ntier = "gateway"\nport = 47002\n'
        '[targets.fedora-fips]\nkind = "systemd-native"\n'
    )
    mpath = tmp_path / "suite.toml"; mpath.write_text(crafted)
    tp = tmp_path / "topology.toml"
    tp.write_text('domain = "sec.internal"\n[resources.core]\ntarget = "fedora-fips"\n'
                  'address = "10.0.0.5"\n[groups.gateway]\nresource = "core"\n')
    topo = Topology.load(tp, Manifest.load(mpath))
    secsso_env = tmp_path / "secsso.env"; secsso_env.write_text("X=1\n")
    assert wiring.sync_secsso_secrecorder_redirect(secsso_env, topo) is None  # nothing to point at
    topo2 = _topo(tmp_path)
    assert wiring.sync_secsso_secrecorder_redirect(tmp_path / "nope.env", topo2) is None  # no secsso .env


def test_sync_secrecorder_env_refreshes_managed_keys_on_rerun_and_keeps_operator_extra(tmp_path):
    # A redeploy must REFRESH every managed key (not just fill it once) while an operator-added key
    # outside the managed set — e.g. the local session secret — survives untouched across both runs.
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECRECORDER_OIDC_CLIENT_SECRET=first-secret\n")
    secrecorder_env = tmp_path / "secrecorder.env"
    secrecorder_env.write_text(
        "SECRECORDER_OIDC_ISSUER=https://stale.example/wrong\n"
        "SECRECORDER_SESSION_SECRET=do-not-touch\n"
    )
    first = wiring.sync_secrecorder_env(secsso_env, secrecorder_env, topo)
    assert first is not None
    vals1 = _env_dict(secrecorder_env)
    assert vals1["SECRECORDER_OIDC_CLIENT_SECRET"] == "first-secret"
    assert vals1["SECRECORDER_OIDC_ISSUER"] == "http://secsso.sec.internal:9000/application/o/secrecorder/"
    # SecSSO regenerates its secret (a fresh secsso deploy) between the two syncs — the re-run must
    # pick up the NEW value, not leave the stale mirrored one in place.
    secsso_env.write_text("SECRECORDER_OIDC_CLIENT_SECRET=rotated-secret\n")
    second = wiring.sync_secrecorder_env(secsso_env, secrecorder_env, topo)
    assert second == first  # same key set both times
    vals2 = _env_dict(secrecorder_env)
    assert vals2["SECRECORDER_OIDC_CLIENT_SECRET"] == "rotated-secret"
    assert vals2["SECRECORDER_OIDC_ISSUER"] == vals1["SECRECORDER_OIDC_ISSUER"]  # refreshed, still correct
    assert vals2["SECRECORDER_SESSION_SECRET"] == "do-not-touch"  # untouched across both runs


# ── env_for secllm branch + sync_secllm_env / sync_secsso_secllm_redirect: turnkey SecLLM ADMIN
#    SSO (inference keeps its shared token). Like SecRecorder, SecLLM is a NATIVE service whose managed
#    env is the topology-generated addressing env (env/secllm.env). It is NEVER fronted (inference must
#    dial direct), so its own URL is the direct host:port, which also serves /admin. ──
def test_env_for_secllm_admin_oidc_branch(tmp_path):
    topo = _topo(tmp_path)
    env = topo.env_for("secllm")
    assert env["SECLLM_OIDC_ISSUER"] == "http://secsso.sec.internal:9000/application/o/secllm/"
    assert env["SECLLM_OIDC_AUDIENCE"] == "secllm"
    assert env["SECLLM_OIDC_CLIENT_ID"] == "secllm"
    assert env["SECLLM_PUBLIC_URL"] == "http://secllm.sec.internal:11400"  # direct — never fronted
    # inference identity is NOT here (the shared token path is separate); nor the client secret.
    assert "SECLLM_OIDC_CLIENT_SECRET" not in env
    assert "SECLLM_API_TOKEN" not in env and "SECROUTER_SECLLM_TOKEN" not in env


def test_sync_secllm_env_mirrors_secret_and_writes_topology(tmp_path):
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECLLM_OIDC_CLIENT_SECRET=admin-login-xyz\n")
    secllm_env = tmp_path / "secllm.env"
    secllm_env.write_text(
        "SECLLM_OIDC_ISSUER=https://stale.example/wrong\n"
        "SECLLM_SESSION_SECRET=keep-me\n"        # local session-cookie secret — must survive
        "SECLLM_ADMIN_TOKEN=break-glass\n"       # the break-glass token — never managed here
    )
    written = wiring.sync_secllm_env(secsso_env, secllm_env, topo)
    assert written is not None and written == sorted(wiring._SECLLM_MANAGED_KEYS)
    vals = _env_dict(secllm_env)
    assert vals["SECLLM_OIDC_CLIENT_SECRET"] == "admin-login-xyz"  # the mirrored secret
    assert vals["SECLLM_OIDC_ISSUER"] == "http://secsso.sec.internal:9000/application/o/secllm/"  # refreshed
    assert vals["SECLLM_OIDC_AUDIENCE"] == "secllm" and vals["SECLLM_OIDC_CLIENT_ID"] == "secllm"
    assert vals["SECLLM_PUBLIC_URL"] == "http://secllm.sec.internal:11400"
    # non-managed keys survive untouched: the local session secret + the break-glass admin token
    assert vals["SECLLM_SESSION_SECRET"] == "keep-me"
    assert vals["SECLLM_ADMIN_TOKEN"] == "break-glass"


def test_sync_secllm_env_noop_without_secret_or_files(tmp_path):
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"; secsso_env.write_text("PG_PASS=x\n")  # secret not provisioned yet
    secllm_env = tmp_path / "secllm.env"; secllm_env.write_text("SECLLM_OIDC_ISSUER=x\n")
    assert wiring.sync_secllm_env(secsso_env, secllm_env, topo) is None
    assert wiring.sync_secllm_env(tmp_path / "nope-a", tmp_path / "nope-b", topo) is None


def test_sync_secsso_secllm_redirect_points_at_admin_callback(tmp_path):
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text(
        "SECLLM_REDIRECT_URI=https://secllm.sec.internal/auth/callback\n"  # .env.example default
        "SECLLM_LAUNCH_URL=https://secllm.sec.internal/admin\n"
        "AUTHENTIK_SECRET_KEY=keep-me\n"
    )
    written = wiring.sync_secsso_secllm_redirect(secsso_env, topo)
    assert written == ["SECLLM_LAUNCH_URL", "SECLLM_REDIRECT_URI"]
    vals = _env_dict(secsso_env)
    assert vals["SECLLM_REDIRECT_URI"] == "http://secllm.sec.internal:11400/auth/callback"
    assert vals["SECLLM_LAUNCH_URL"] == "http://secllm.sec.internal:11400/admin"  # tile → console
    # callback = SECLLM_PUBLIC_URL + /auth/callback, so redirect_uri matches the SecLLM side by construction
    assert vals["SECLLM_REDIRECT_URI"].startswith("http://secllm.sec.internal:11400")
    assert vals["AUTHENTIK_SECRET_KEY"] == "keep-me"  # untouched
    # noop when secsso .env is missing
    assert wiring.sync_secsso_secllm_redirect(tmp_path / "nope.env", topo) is None


def test_sync_secagent_service_secret_missing_files_is_a_noop(tmp_path):
    assert wiring.sync_secagent_service_secret(
        tmp_path / "nope.env", tmp_path / "also-nope.env",
    ) is None


# ── Topology.env_for: the secagent branch ────────────────────────────────────────────────
def test_env_for_secagent_llm_points_at_secrouter(tmp_path):
    topo = _topo(tmp_path)
    env = topo.env_for("secagent")
    assert env["SECAGENT_LLM__BASE_URL"] == "http://secrouter.sec.internal:47002/v1"
    assert env["SECAGENT_LLM__API_KEY"] == "!secagent token"
    assert env["SECAGENT_LLM__MODEL"] == "auto"


def test_env_for_secagent_secsso(tmp_path):
    topo = _topo(tmp_path)
    env = topo.env_for("secagent")
    assert env["SECAGENT_SECSSO__TOKEN_URL"] == \
        "http://secsso.sec.internal:9000/application/o/token/"
    assert env["SECAGENT_SECSSO__CLIENT_ID"] == "secagent"
    assert env["SECAGENT_AUDIT__ENABLED"] == "true"
    # secagent is an installed pi harness with no standing chat listener — no chat-bridge wiring
    assert not any(k.startswith("SECAGENT_CHAT") or "__BOT_TOKEN" in k for k in env)


def test_env_for_non_secagent_never_gets_secagent_only_keys(tmp_path):
    topo = _topo(tmp_path)
    # secagent has no inbound port now (an installed harness, not a service), so it isn't even a
    # peer URL — and the double-underscore secagent pydantic keys must never leak onto another
    # component regardless.
    env = topo.env_for("secrouter")
    assert "SECAGENT_URL" not in env
    assert not any("__" in k and k.startswith("SECAGENT_") for k in env)


# ── write_addressing: secagent env + secrouter-oidc.json integration ────────────────────
def test_write_addressing_secagent_env_has_llm_wiring(tmp_path):
    topo = _topo(tmp_path)  # secagent + secrouter + secsso all on 'core'
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "core")
    text = Path(written["env"]["secagent"]).read_text()
    assert "SECAGENT_LLM__BASE_URL=http://secrouter.sec.internal:47002/v1" in text
    assert "SECAGENT_LLM__API_KEY=!secagent token" in text
    assert "SECAGENT_SECSSO__TOKEN_URL=http://secsso.sec.internal:9000/application/o/token/" in text
    # no chat-bridge wiring, no webhook secret — secagent is an on-demand harness
    assert "__WEBHOOK_SECRET=" not in text and "__BOT_TOKEN=" not in text
    assert not (out / "secagent-webhook-secret").exists()


def test_write_addressing_writes_secrouter_oidc_json(tmp_path):
    topo = _topo(tmp_path)
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "core")
    assert "oidc" in written
    oidc_path = Path(written["oidc"])
    assert oidc_path == out / "secrouter-oidc.json"
    assert json.loads(oidc_path.read_text()) == wiring.secrouter_oidc_config(topo)


def test_write_addressing_no_oidc_json_when_secrouter_not_here(tmp_path):
    topo = _topo(tmp_path)
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "gpu")  # secllm-only resource
    assert "oidc" not in written


def test_write_addressing_secagent_env_absent_when_secagent_not_here(tmp_path):
    topo = _topo(tmp_path)
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "gpu")
    assert "secagent" not in written["env"]
    assert not (out / "secagent-webhook-secret").exists()


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


# ── generate_secsso_users_blueprint: declared users → SecSSO users blueprint ───────────
def test_generate_secsso_users_blueprint(tmp_path):
    from secdeploy.site import UserSpec
    users = [
        UserSpec(username="alice", email="alice@x.mil", name="Alice", groups=["analysts"]),
        UserSpec(username="bob"),  # no name/email/groups → those keys omitted
    ]
    dest = tmp_path / "users.generated.yaml"
    creds = wiring.generate_secsso_users_blueprint(users, dest)
    assert set(creds) == {"alice", "bob"}
    assert all(len(pw) >= 12 for pw in creds.values())  # strong-ish random
    text = dest.read_text()
    assert "model: authentik_core.group" in text
    assert 'name: "analysts"' in text
    assert "model: authentik_core.user" in text
    assert "state: created" in text          # create-once, never clobber a changed password
    assert "reset_password: true" in text    # forced first-login reset
    assert '!Find [authentik_core.group, [name, "analysts"]]' in text
    assert 'username: "bob"' in text
    # bob's password is written even though he has no name/email
    assert f'password: "{creds["bob"]}"' in text


def test_generate_secsso_users_blueprint_is_idempotent(tmp_path):
    from secdeploy.site import UserSpec
    dest = tmp_path / "users.generated.yaml"
    first = wiring.generate_secsso_users_blueprint([UserSpec(username="alice")], dest)
    # re-run with alice + a NEW user carol → alice's password is REUSED, only carol is "new"
    second = wiring.generate_secsso_users_blueprint(
        [UserSpec(username="alice"), UserSpec(username="carol")], dest)
    assert set(second) == {"carol"}                   # only the newly-added user is returned
    assert f'password: "{first["alice"]}"' in dest.read_text()  # alice's original survives
