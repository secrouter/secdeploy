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

FRONTED = ("secsso", "secrouter", "secagent", "secchat", "secrecorder")


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


# ── nginx_conf_text: secproxy's reverse-proxy config (fronts the 5 HTTP services on :443) ──
CERT_DIR = "/etc/secsuite/secproxy"


def test_nginx_conf_text_server_blocks_for_exactly_the_five(tmp_path):
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
    assert "proxy_pass http://10.0.0.5:47007;" in text     # secagent
    assert "proxy_pass http://10.0.0.5:8065;" in text      # secchat
    assert "proxy_pass http://10.0.0.5:47003;" in text     # secrecorder


def test_nginx_conf_text_ssl_cert_paths_use_cert_dir(tmp_path):
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    # one SAN cert covers all five — every :443 block reads the SAME cert_dir
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
    # the bare domain + all five fronted names share the one :80 server (ACME webroot + redirect)
    assert ("server_name sec.internal secsso.sec.internal secrouter.sec.internal "
            "secagent.sec.internal secchat.sec.internal secrecorder.sec.internal;") in text
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


# ── secrouter_oidc_config: security.oidc fragment for SecSSO issuer_mode: global ────────
def test_secrouter_oidc_config_shape(tmp_path):
    topo = _topo(tmp_path)  # secsso is on 'core' (identity tier)
    oidc = wiring.secrouter_oidc_config(topo)
    assert oidc == {
        "issuer": "https://secsso.sec.internal:9000/",
        "audience": "secrouter",
        "jwksUri": "https://secsso.sec.internal:9000/application/o/secrouter/jwks/",
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


# ── secagent_webhook_secret: cached-on-disk, redeploy-stable ─────────────────────────────
def test_secagent_webhook_secret_persists_and_is_reused(tmp_path):
    out = tmp_path / "out"
    t1 = wiring.secagent_webhook_secret(out)
    t2 = wiring.secagent_webhook_secret(out)
    assert t1 == t2
    assert (out / "secagent-webhook-secret").read_text().strip() == t1


def test_secagent_webhook_secret_distinct_from_secllm_shared_token(tmp_path):
    out = tmp_path / "out"
    assert wiring.secagent_webhook_secret(out) != wiring.secllm_shared_token(out)


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


def test_sync_secagent_service_secret_missing_files_is_a_noop(tmp_path):
    assert wiring.sync_secagent_service_secret(
        tmp_path / "nope.env", tmp_path / "also-nope.env",
    ) is None


# ── Topology.env_for: the secagent branch ────────────────────────────────────────────────
def test_env_for_secagent_llm_points_at_secrouter(tmp_path):
    topo = _topo(tmp_path)
    env = topo.env_for("secagent")
    assert env["SECAGENT_LLM__BASE_URL"] == "https://secrouter.sec.internal:47002/v1"
    assert env["SECAGENT_LLM__API_KEY"] == "!secagent token"
    assert env["SECAGENT_LLM__MODEL"] == "balanced"


def test_env_for_secagent_secsso_and_mattermost(tmp_path):
    topo = _topo(tmp_path)
    env = topo.env_for("secagent")
    assert env["SECAGENT_SECSSO__TOKEN_URL"] == \
        "https://secsso.sec.internal:9000/application/o/token/"
    assert env["SECAGENT_SECSSO__CLIENT_ID"] == "secagent"
    assert env["SECAGENT_MATTERMOST__URL"] == "https://secchat.sec.internal:8065"
    assert env["SECAGENT_MATTERMOST__TEAM"] == "secrouter"
    assert env["SECAGENT_AUDIT__ENABLED"] == "true"


def test_env_for_secagent_webhook_secret_only_when_given(tmp_path):
    topo = _topo(tmp_path)
    assert "SECAGENT_MATTERMOST__WEBHOOK_SECRET" not in topo.env_for("secagent")
    env = topo.env_for("secagent", secagent_webhook_secret="whs-123")
    assert env["SECAGENT_MATTERMOST__WEBHOOK_SECRET"] == "whs-123"


def test_env_for_non_secagent_never_gets_secagent_only_keys(tmp_path):
    topo = _topo(tmp_path)
    # NOTE: secrouter's env legitimately gets a generic "SECAGENT_URL" peer entry (secagent
    # is just another addressable peer) — that's pre-existing, unrelated behavior. What must
    # NOT leak onto a non-secagent component is the double-underscore-delimited, secagent
    # pydantic-settings keys this feature adds.
    env = topo.env_for("secrouter", secagent_webhook_secret="whs-123")
    assert "SECAGENT_URL" in env  # sanity: the generic peer entry IS present
    assert not any("__" in k and k.startswith("SECAGENT_") for k in env)
    assert "SECAGENT_MATTERMOST__WEBHOOK_SECRET" not in env


# ── write_addressing: secagent env + secrouter-oidc.json integration ────────────────────
def test_write_addressing_secagent_env_has_full_wiring(tmp_path):
    topo = _topo(tmp_path)  # secagent + secrouter + secsso + secchat all on 'core'
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "core")
    text = Path(written["env"]["secagent"]).read_text()
    assert "SECAGENT_LLM__BASE_URL=https://secrouter.sec.internal:47002/v1" in text
    assert "SECAGENT_MATTERMOST__WEBHOOK_SECRET=" in text
    token_line = next(
        ln for ln in text.splitlines() if ln.startswith("SECAGENT_MATTERMOST__WEBHOOK_SECRET=")
    )
    assert token_line.split("=", 1)[1] == wiring.secagent_webhook_secret(out)


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
