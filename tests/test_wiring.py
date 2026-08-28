"""Tests for topology-driven deploy wiring."""

from __future__ import annotations

import base64
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
    # +1: secsso's extra well-known rewrite location also carries `Host $host;` and
    # `X-Forwarded-Proto $scheme;` (Authentik derives the doc's URL scheme from the latter) —
    # see test_nginx_conf_text_secsso_well_known_openid_configuration_rewrite below.
    assert text.count("proxy_set_header X-Forwarded-Proto $scheme;") == len(FRONTED) + 1
    assert text.count("proxy_set_header Host $host;") == len(FRONTED) + 1


def test_nginx_conf_text_secsso_well_known_openid_configuration_rewrite(tmp_path):
    # With issuer_mode: global (secrouter-admin-console.yaml et al.), a client's OIDC discovery
    # fetch off the root issuer (SecRouter's admin-ui.ts login()) hits
    # https://secsso.sec.internal/.well-known/openid-configuration — a path Authentik never
    # serves at the root (only under /application/o/<slug>/...). secsso's own :443 block must
    # rewrite that one path to the secrouter-admin-console application's real discovery doc, or
    # every admin console sign-in 404s at the very first fetch.
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    secsso_block = text[text.index("server_name secsso.sec.internal;"):]
    secsso_block = secsso_block[:secsso_block.index("\n\tserver {")]
    assert "location = /.well-known/openid-configuration {" in secsso_block
    assert (
        "/application/o/secrouter-admin-console/.well-known/openid-configuration;"
    ) in secsso_block
    # Rewritten to the SAME backend secsso's own `location /` proxies to (its real addr:port),
    # not a hardcoded loopback — this topology's core resource sits at 10.0.0.5.
    assert "proxy_pass http://10.0.0.5:9000/application/o/secrouter-admin-console" in secsso_block
    # Only secsso's block gets it — every other fronted server stays exactly as before.
    assert text.count("location = /.well-known/openid-configuration {") == 1


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


def test_nginx_conf_text_error_pages_on_every_server_block(tmp_path):
    # Branded 502/503/504/404 pages (wiring.error_page_html) on EVERY :443 server block — the
    # landing page's and each fronted proxy's — not just some of them.
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    assert text.count("error_page 502 503 504 /5xx.html;") == len(FRONTED) + 1
    assert text.count("error_page 404 /404.html;") == len(FRONTED) + 1
    assert text.count("location = /5xx.html {") == len(FRONTED) + 1
    assert text.count("location = /404.html {") == len(FRONTED) + 1
    # internal — never reachable except via the error_page rewrite (the tab-indented directive,
    # not the "sec.internal;" domain suffix that appears on every server_name line)
    assert text.count("\t\t\tinternal;") == 2 * (len(FRONTED) + 1)
    # deliberately no proxy_intercept_errors anywhere — see nginx_conf_text's docstring: an
    # upstream's own error body (e.g. secchat's JSON error) must pass through unbranded.
    assert "proxy_intercept_errors" not in text
    # state_dir is a parameter, same as cert_dir
    other = wiring.nginx_conf_text(topo, CERT_DIR, state_dir="/opt/secproxy")
    assert "root /opt/secproxy/www;" in other
    assert f"root {wiring._NGINX_STATE_DIR}/www;" not in other


def test_write_addressing_writes_nginx_conf_when_secproxy_placed_here(tmp_path):
    topo = _edge_topo(tmp_path)  # secproxy is on 'core' (edge tier)
    out = tmp_path / "out"
    written_core = wiring.write_addressing(topo, out, "core")
    assert "nginx_conf" in written_core
    nginx_path = Path(written_core["nginx_conf"])
    assert nginx_path == out / "secproxy.nginx.conf"
    # write_addressing hardcodes the fedora cert dir /etc/secsuite/secproxy
    assert nginx_path.read_text() == wiring.nginx_conf_text(topo, "/etc/secsuite/secproxy")
    # the logrotate config for the same nginx logs is written alongside it
    assert "logrotate_conf" in written_core
    logrotate_path = Path(written_core["logrotate_conf"])
    assert logrotate_path == out / "secproxy.logrotate.conf"
    assert logrotate_path.read_text() == wiring.logrotate_conf_text()
    assert set(written_core) == {"zone", "env", "egress", "oidc", "nginx_conf", "logrotate_conf"}

    written_gpu = wiring.write_addressing(topo, out, "gpu")  # secllm only, not secproxy
    assert "nginx_conf" not in written_gpu


def test_write_addressing_no_nginx_conf_when_secproxy_not_in_topology(tmp_path):
    topo = _topo(tmp_path)  # GPU_SPLIT: no edge group at all
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "core")
    assert "nginx_conf" not in written
    assert not (out / "secproxy.nginx.conf").exists()
    assert "logrotate_conf" not in written
    assert not (out / "secproxy.logrotate.conf").exists()


# ── error_page_html: the branded 5xx/404 pages nginx_conf_text's error_page directives target ──
def test_error_page_html_5xx_and_404_are_distinct_self_contained_pages():
    for kind, must_contain in (("5xx", "didn&#x27;t respond"), ("404", "Nothing is served")):
        text = wiring.error_page_html(kind)
        assert "<!doctype html>" in text.lower()
        assert "<link" not in text and "<script" not in text  # no CDN, no behavior
        assert "--accent:#4f6a2e" in text  # same field-console tokens as the rest of the suite
        assert '<span class="sec">SEC</span>PROXY' in text
        assert must_contain in text
    assert wiring.error_page_html("5xx") != wiring.error_page_html("404")


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


def test_secllm_endpoints_replicated_single_host(tmp_path):
    # [groups.inference] instances = 2 on ONE resource: one endpoint per replica, consecutive
    # ports, first replica's URL byte-identical to the pre-replica single-instance form.
    p = tmp_path / "topology.toml"
    p.write_text(GPU_SPLIT.replace(
        '[groups.inference]\nresource = "gpu"',
        '[groups.inference]\nresource = "gpu"\ninstances = 2'))
    topo = Topology.load(p, Manifest.load(ROOT / "suite.toml"))
    assert wiring.secllm_endpoints(topo) == [
        "http://secllm.sec.internal:11400/v1",
        "http://secllm-2.sec.internal:11401/v1",
    ]
    # the egress rule authorizes every replica's host:port
    rules = wiring.secrouter_egress_rules(topo)
    assert rules[0]["allowedHost"] == [
        "secllm.sec.internal:11400", "secllm-2.sec.internal:11401"]


def test_secllm_container_endpoints_readdress_local_and_remote(tmp_path):
    # The containerized macOS SecRouter's view of the pool: local instances via
    # host.docker.internal (suite DNS is host-only), remote ones via their raw address.
    p = tmp_path / "topology.toml"
    p.write_text(GPU_SPLIT.replace(
        '[groups.inference]\nresource = "gpu"',
        '[groups.inference]\nresources = ["core", "gpu"]\ninstances = 2'))
    topo = Topology.load(p, Manifest.load(ROOT / "suite.toml"))
    assert wiring.secllm_container_endpoints(topo, "core") == [
        "http://host.docker.internal:11400/v1",
        "http://host.docker.internal:11401/v1",
        "http://10.0.0.6:11400/v1",
        "http://10.0.0.6:11401/v1",
    ]
    # same order as the FQDN form — SecRouter's round-robin cursor is positional
    assert len(wiring.secllm_container_endpoints(topo, "core")) == \
        len(wiring.secllm_endpoints(topo))


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
    assert rule["authorizedClassifications"] == ["UNCLASSIFIED", "CUI"]  # internal-CUI level + everything below
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
    assert wiring.secrouter_egress_rules(topo)[0]["authorizedClassifications"] == ["UNCLASSIFIED", "CUI"]


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
    topo = _topo(tmp_path)  # secsso is on 'core' (identity tier); secchat on 'core' (collab)
    oidc = wiring.secrouter_oidc_config(topo)
    assert oidc == {
        "issuer": "http://secsso.sec.internal:9000/",
        "audience": "secrouter",
        "jwksUri": "http://secsso.sec.internal:9000/application/o/secrouter/jwks/",
        # svc-secagent (SecAgent) and svc-secchat (SecChat's shared service identity) are both
        # non-interactive service accounts — client_credentials tokens can't carry an MFA
        # assertion, so both are trusted to skip requireMfa. These are the exact subs the
        # secsso blueprints' creds-path grants issue (sub_mode: user_username against the
        # pre-provisioned svc-* users); svc-secchat appears only when secchat is placed.
        "serviceSubjects": ["svc-secagent", "svc-secchat"],
        # SecChat forwards the acting end-user via X-Sec-Acting-User, so it is also a delegator.
        "delegatingSubjects": ["svc-secchat"],
    }


def test_secrouter_oidc_config_without_secchat_has_no_delegators(tmp_path):
    # A crafted manifest with no secchat at all (it's required in the real suite, so it can't
    # be dropped via --without): the fragment names only svc-secagent, and no delegators.
    crafted = (
        'suite = "1"\n'
        '[components.secrouter]\nrepo = "o/secrouter"\nref = "v1"\ntier = "gateway"\nport = 47002\n'
        '[components.secsso]\nrepo = "o/secsso"\nref = "v1"\ntier = "identity"\nport = 9000\n'
        'optional = true\n'
        '[targets.fedora-fips]\nkind = "systemd-native"\n'
    )
    mpath = tmp_path / "suite.toml"
    mpath.write_text(crafted)
    m = Manifest.load(mpath)
    topo_text = (
        'domain = "sec.internal"\n'
        '[resources.core]\ntarget = "fedora-fips"\naddress = "10.0.0.5"\n'
        '[groups.gateway]\nresource = "core"\n'
        '[groups.identity]\nresource = "core"\n'
    )
    tp = tmp_path / "topology.toml"
    tp.write_text(topo_text)
    topo = Topology.load(tp, m)
    oidc = wiring.secrouter_oidc_config(topo)
    assert oidc["serviceSubjects"] == ["svc-secagent"]
    assert "delegatingSubjects" not in oidc


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


# ── secrouter_audit_syslog_config: security.audit fragment (AU-3.3.x syslog forwarding) ─────
def test_secrouter_audit_syslog_config_empty_without_opts():
    assert wiring.secrouter_audit_syslog_config(None) == {}


def test_secrouter_audit_syslog_config_empty_when_syslog_host_unset():
    from secdeploy.site import AuditOptions

    assert wiring.secrouter_audit_syslog_config(AuditOptions()) == {}


def test_secrouter_audit_syslog_config_shape():
    from secdeploy.site import AuditOptions

    opts = AuditOptions(syslog_host="siem.internal", syslog_port=6514,
                        syslog_proto="tcp", syslog_format="cef")
    assert wiring.secrouter_audit_syslog_config(opts) == {
        "sink": "both",
        "syslog": {"host": "siem.internal", "port": 6514, "protocol": "tcp", "format": "cef"},
    }


def test_secrouter_audit_syslog_config_json_serializable():
    from secdeploy.site import AuditOptions

    opts = AuditOptions(syslog_host="siem.internal")
    fragment = wiring.secrouter_audit_syslog_config(opts)
    assert json.loads(json.dumps(fragment)) == fragment


def test_write_addressing_writes_audit_fragment_when_secrouter_placed_and_syslog_set(tmp_path):
    from secdeploy.site import AuditOptions

    topo = _topo(tmp_path)  # secrouter is on 'core' (gateway tier)
    out = tmp_path / "out"
    opts = AuditOptions(syslog_host="siem.internal")
    written = wiring.write_addressing(topo, out, "core", audit_opts=opts)
    assert "audit" in written
    audit_path = Path(written["audit"])
    assert audit_path == out / "secrouter-audit.json"
    assert json.loads(audit_path.read_text()) == wiring.secrouter_audit_syslog_config(opts)


def test_write_addressing_no_audit_fragment_without_syslog_host(tmp_path):
    topo = _topo(tmp_path)
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "core")  # no audit_opts at all
    assert "audit" not in written
    assert not (out / "secrouter-audit.json").exists()


def test_write_addressing_no_audit_fragment_when_secrouter_not_here(tmp_path):
    from secdeploy.site import AuditOptions

    topo = _topo(tmp_path)  # 'gpu' hosts only secllm, not secrouter
    out = tmp_path / "out"
    written = wiring.write_addressing(topo, out, "gpu", audit_opts=AuditOptions(syslog_host="siem.internal"))
    assert "audit" not in written


# ── nginx_conf_text: 'secproxy' log_format (log hygiene — AU-3.3.x correlation fields) ──────
def test_nginx_conf_log_format_and_access_log(tmp_path):
    topo = _edge_topo(tmp_path)
    text = wiring.nginx_conf_text(topo, CERT_DIR)
    assert "log_format secproxy" in text
    assert "$request_id" in text
    assert "$request_time" in text
    assert "$upstream_response_time" in text
    assert "access_log " in text and " secproxy;" in text
    # the access_log directive actually references the named format, not the stock default
    assert f"access_log {wiring._NGINX_STATE_DIR}/access.log secproxy;" in text


# ── logrotate_conf_text: secproxy nginx access/error log rotation (fedora-fips only) ────────
def test_logrotate_conf_text_default_paths_and_service():
    text = wiring.logrotate_conf_text()
    assert f"{wiring._NGINX_STATE_DIR}/access.log {wiring._NGINX_STATE_DIR}/error.log {{" in text
    assert "daily" in text
    assert "rotate 14" in text
    assert "systemctl reload secproxy.service" in text
    assert "create 0640 secsuite-secproxy secsuite-secproxy" in text


def test_logrotate_conf_text_custom_state_dir_and_service():
    text = wiring.logrotate_conf_text("/opt/secproxy", service_name="secproxy2", owner="svc-proxy")
    assert "/opt/secproxy/access.log /opt/secproxy/error.log {" in text
    assert "systemctl reload secproxy2.service" in text
    assert "create 0640 svc-proxy svc-proxy" in text


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


# ── sync_secagent_service_secret: derives secagent's composite client_secret from SecSSO's
#    svc-secagent app-password (base64("svc-secagent:<pw>") — the creds-path grant that makes
#    the issued sub exactly "svc-secagent"; see secsso/blueprints/secagent-service.yaml). ──
def test_service_client_secret_is_the_authentik_creds_composite():
    composite = wiring.service_client_secret("svc-secagent", "pw123")
    assert base64.b64decode(composite).decode() == "svc-secagent:pw123"


def test_sync_secagent_service_secret_fills_blank_value(tmp_path):
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECAGENT_SVC_APP_PASSWORD=abc123\nOTHER=x\n")
    secrets_env = tmp_path / "secrets.env"
    secrets_env.write_text("SECAGENT_CLIENT_SECRET=\nOTHER_KEY=y\n")
    synced = wiring.sync_secagent_service_secret(secsso_env, secrets_env)
    expected = wiring.service_client_secret("svc-secagent", "abc123")
    assert synced == expected
    assert f"SECAGENT_CLIENT_SECRET={expected}" in secrets_env.read_text()
    assert "OTHER_KEY=y" in secrets_env.read_text()  # untouched lines survive


def test_sync_secagent_service_secret_never_overwrites_non_blank_value(tmp_path):
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECAGENT_SVC_APP_PASSWORD=abc123\n")
    secrets_env = tmp_path / "secrets.env"
    secrets_env.write_text("SECAGENT_CLIENT_SECRET=already-set\n")
    synced = wiring.sync_secagent_service_secret(secsso_env, secrets_env)
    assert synced is None
    assert "SECAGENT_CLIENT_SECRET=already-set" in secrets_env.read_text()


def test_sync_secagent_service_secret_missing_secsso_secret_is_a_noop(tmp_path):
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("OTHER=x\n")  # no SECAGENT_SVC_APP_PASSWORD line at all
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
    secsso_env.write_text(
        "SECCHATNG_OIDC_CLIENT_SECRET=login-abc\n"
        "SECCHAT_SVC_APP_PASSWORD=svcpw\n"
    )
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
    # the SecRouter service identity (client_credentials): token endpoint + the svc-secchat
    # creds-path composite — never the raw app-password (see secchat-service.yaml's header)
    assert vals["SECCHAT_SECROUTER_TOKEN_URL"] == \
        "http://secsso.sec.internal:9000/application/o/token/"
    assert vals["SECCHAT_SECROUTER_CLIENT_ID"] == "secchat-service"
    assert vals["SECCHAT_SECROUTER_CLIENT_SECRET"] == \
        wiring.service_client_secret("svc-secchat", "svcpw")
    # non-managed keys survive untouched
    assert vals["SECCHAT_SESSION_SECRET"] == "keep-me"


def test_sync_secchat_env_older_secsso_env_skips_service_identity(tmp_path):
    # A SecSSO .env from before secchat-service.yaml existed has no SECCHAT_SVC_APP_PASSWORD —
    # the login sync must still run, just without the three SECCHAT_SECROUTER_* keys.
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECCHATNG_OIDC_CLIENT_SECRET=login-abc\n")
    secchat_env = tmp_path / "secchat.env"
    secchat_env.write_text("SECCHAT_OIDC_CLIENT_SECRET=\n")
    written = wiring.sync_secchat_env(secsso_env, secchat_env, topo)
    assert written is not None and "SECCHAT_OIDC_CLIENT_SECRET" in written
    assert not any(k.startswith("SECCHAT_SECROUTER_") for k in written)
    assert "SECCHAT_SECROUTER_CLIENT_SECRET" not in _env_dict(secchat_env)


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
        UserSpec(username="bob"),  # no name/email/groups → email/groups omitted, name defaulted
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
    # `name` is required by authentik_core.user: always emitted, defaulting to the username.
    # Without it authentik rejects the WHOLE blueprint and no declared user is created.
    assert 'name: "Alice"' in text
    assert 'name: "bob"' in text
    user_blocks = text.split("  - model: authentik_core.user")[1:]
    assert len(user_blocks) == len(users)
    assert all("      name: " in block for block in user_blocks)


def test_generate_secsso_users_blueprint_is_idempotent(tmp_path):
    from secdeploy.site import UserSpec
    dest = tmp_path / "users.generated.yaml"
    first = wiring.generate_secsso_users_blueprint([UserSpec(username="alice")], dest)
    # re-run with alice + a NEW user carol → alice's password is REUSED, only carol is "new"
    second = wiring.generate_secsso_users_blueprint(
        [UserSpec(username="alice"), UserSpec(username="carol")], dest)
    assert set(second) == {"carol"}                   # only the newly-added user is returned
    assert f'password: "{first["alice"]}"' in dest.read_text()  # alice's original survives


# ── Kubernetes agent pool (Part C) ────────────────────────────────────────────────────
from secdeploy.site import PoolOptions  # noqa: E402


def _pool(**kw) -> PoolOptions:
    base = dict(enabled=True, image="reg/secchat-runnerd:1", namespace="chat-pool",
                service_account="secchat", service_account_namespace="chat",
                git_host="git.sec.internal", secchat_url="http://secchat.chat.svc:47010",
                max_pods=7, ttl_seconds=1800)
    base.update(kw)
    return PoolOptions(**base)


def test_secchat_pool_env_disabled_is_empty(tmp_path):
    assert wiring.secchat_pool_env(PoolOptions(), _topo(tmp_path)) == {}


def test_secchat_pool_env_carries_the_pool_settings(tmp_path):
    env = wiring.secchat_pool_env(_pool(), _topo(tmp_path))
    assert env["SECCHAT_POOL_IMAGE"] == "reg/secchat-runnerd:1"
    assert env["SECCHAT_POOL_NAMESPACE"] == "chat-pool"
    assert env["SECCHAT_POOL_SECCHAT_URL"] == "http://secchat.chat.svc:47010"
    assert env["SECCHAT_POOL_TTL"] == "1800"
    # Admission caps flow to the backend (SecChat rejects a burst fast, same numbers as the quota).
    assert env["SECCHAT_POOL_MAX_PODS"] == "7"
    assert env["SECCHAT_POOL_MAX_PER_OWNER"] == "3"  # PoolOptions default


def test_secchat_pool_env_defaults_secchat_url_from_topology(tmp_path):
    # No explicit secchat_url ⇒ derived from SecChat's own address in the topology.
    env = wiring.secchat_pool_env(_pool(secchat_url=""), _topo(tmp_path))
    assert env["SECCHAT_POOL_SECCHAT_URL"].startswith("http")


def test_k8s_pool_manifests_shape_and_rbac(tmp_path):
    m = wiring.k8s_pool_manifests(_pool())
    assert m["kind"] == "List"
    kinds = [i["kind"] for i in m["items"]]
    # Two NetworkPolicies: the restricted base (all pods) + the opt-in open-egress one (label-selected).
    assert kinds == ["Namespace", "Role", "RoleBinding", "ResourceQuota", "NetworkPolicy", "NetworkPolicy"]
    by = {i["kind"]: i for i in m["items"] if i["kind"] != "NetworkPolicy"}
    by["NetworkPolicy"] = next(i for i in m["items"] if i["metadata"]["name"] == "secchat-pool-egress")
    assert by["Namespace"]["metadata"]["name"] == "chat-pool"
    # The RoleBinding references SecChat's ServiceAccount (create/delete pods), not a created SA.
    assert by["RoleBinding"]["subjects"][0] == {"kind": "ServiceAccount", "name": "secchat", "namespace": "chat"}
    assert "pods" in by["Role"]["rules"][0]["resources"]
    assert by["ResourceQuota"]["spec"]["hard"]["pods"] == "7"
    # NetworkPolicy denies all ingress; no ServiceAccount is created here; no secrets leak.
    assert by["NetworkPolicy"]["spec"]["ingress"] == []
    assert "ServiceAccount" not in kinds
    assert "TOKEN" not in json.dumps(m) and "PRIVATE" not in json.dumps(m)
    # git_host surfaces as a NetworkPolicy annotation (a plain NetworkPolicy can't match hosts, so an
    # FQDN-aware layer / the operator consumes it) — kept meaningful, not silently dropped.
    assert by["NetworkPolicy"]["metadata"]["annotations"]["secchat.io/git-host"] == "git.sec.internal"


def test_k8s_pool_manifests_omits_git_host_annotation_when_unset():
    m = wiring.k8s_pool_manifests(_pool(git_host=""))
    np = next(i for i in m["items"] if i["kind"] == "NetworkPolicy")
    assert "annotations" not in np["metadata"]


def test_k8s_pool_manifests_open_egress_policy_is_label_scoped():
    # The internet toggle: a pod labeled `secchat.io/egress: open` (only when its agent explicitly
    # opted in — SecChat's default label is "restricted") gets allow-all egress ON TOP of the base
    # allowlist. Unlabeled pods never match this policy.
    m = wiring.k8s_pool_manifests(_pool())
    open_np = next(i for i in m["items"]
                   if i["kind"] == "NetworkPolicy" and i["metadata"]["name"] == "secchat-pool-egress-open")
    assert open_np["spec"]["podSelector"] == {"matchLabels": {"secchat.io/egress": "open"}}
    assert open_np["spec"]["policyTypes"] == ["Egress"]
    assert open_np["spec"]["egress"] == [{}]  # allow-all for opted-in pods only


def test_k8s_pool_manifests_role_grants_pod_logs():
    # The one-shot task API reads a task pod's report via the log subresource.
    m = wiring.k8s_pool_manifests(_pool())
    role = next(i for i in m["items"] if i["kind"] == "Role")
    assert {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]} in role["rules"]


def test_secchat_pool_env_carries_task_image_when_set(tmp_path):
    env = wiring.secchat_pool_env(_pool(task_image="secagent-agent:local"), _topo(tmp_path))
    assert env["SECCHAT_POOL_TASK_IMAGE"] == "secagent-agent:local"
    assert "SECCHAT_POOL_TASK_IMAGE" not in wiring.secchat_pool_env(_pool(), _topo(tmp_path))


def test_secchat_pool_env_carries_the_analysis_catalog(tmp_path):
    env = wiring.secchat_pool_env(
        _pool(analysis_images={"rust": "secagent-analyzer-rust:1", "ikos": "secagent-analysis:1"}),
        _topo(tmp_path))
    assert env["SECCHAT_POOL_ANALYSIS_IMAGES"] == "ikos=secagent-analysis:1,rust=secagent-analyzer-rust:1"
    assert "SECCHAT_POOL_ANALYSIS_IMAGES" not in wiring.secchat_pool_env(_pool(), _topo(tmp_path))


def test_k8s_pool_manifests_egress_allows_the_secchat_dialback_port():
    # The pod must dial back to SecChat (/runner + /agent-llm) — its port belongs in the egress
    # allowlist, else an enforcing CNI (k3s) breaks every pool attach.
    m = wiring.k8s_pool_manifests(_pool(secchat_url="http://192.168.5.1:47010"))
    np = next(i for i in m["items"] if i["kind"] == "NetworkPolicy")
    ports = [p["port"] for rule in np["spec"]["egress"] for p in rule["ports"]]
    assert 47010 in ports
    # No secchat_url ⇒ the suite's default secchat port is still allowed.
    m2 = wiring.k8s_pool_manifests(_pool(secchat_url=""))
    np2 = next(i for i in m2["items"] if i["kind"] == "NetworkPolicy")
    assert 47010 in [p["port"] for rule in np2["spec"]["egress"] for p in rule["ports"]]


def test_k8s_pool_manifests_create_service_account_emits_sa_and_token_secret():
    m = wiring.k8s_pool_manifests(_pool(create_service_account=True))
    kinds = [i["kind"] for i in m["items"]]
    assert "ServiceAccount" in kinds and "Secret" in kinds
    sa = next(i for i in m["items"] if i["kind"] == "ServiceAccount")
    assert sa["metadata"] == {"name": "secchat", "namespace": "chat",
                             "labels": {"app.kubernetes.io/part-of": "secchat", "app.kubernetes.io/component": "agent-pool"}}
    secret = next(i for i in m["items"] if i["kind"] == "Secret")
    assert secret["type"] == "kubernetes.io/service-account-token"
    assert secret["metadata"]["annotations"] == {"kubernetes.io/service-account.name": "secchat"}
    # The SA namespace ("chat") differs from the pool namespace → it is ALSO created.
    ns_names = [i["metadata"]["name"] for i in m["items"] if i["kind"] == "Namespace"]
    assert ns_names == ["chat-pool", "chat"]
    # Default (no create_service_account): no SA/Secret, exactly as before.
    kinds_default = [i["kind"] for i in wiring.k8s_pool_manifests(_pool())["items"]]
    assert "ServiceAccount" not in kinds_default and "Secret" not in kinds_default


def test_secchat_pool_env_carries_api_server_when_set(tmp_path):
    env = wiring.secchat_pool_env(_pool(api_server="https://192.168.5.1:6443"), _topo(tmp_path))
    assert env["SECCHAT_POOL_APISERVER"] == "https://192.168.5.1:6443"
    assert "SECCHAT_POOL_APISERVER" not in wiring.secchat_pool_env(_pool(), _topo(tmp_path))


def test_pool_credential_helpers():
    p = _pool(create_service_account=True, kube_context="colima")
    assert wiring.pool_token_secret_name(p) == "secchat-pool-token"
    assert wiring.pool_secret_read_argv(p, "{.data.token}") == [
        "kubectl", "--context", "colima", "-n", "chat", "get", "secret",
        "secchat-pool-token", "-o", "jsonpath={.data.token}",
    ]
    override = wiring.pool_compose_override(p)
    assert "services:" in override and "  secchat:" in override
    assert "./pool-sa/token:/var/run/secrets/kubernetes.io/serviceaccount/token:ro" in override


def test_image_build_argv_construction():
    assert wiring.image_build_argv("/w/secagent", "/w/secagent/docker/x.Dockerfile", "img:local") == \
        ["docker", "build", "-f", "/w/secagent/docker/x.Dockerfile", "-t", "img:local", "/w/secagent"]
    assert wiring.image_build_argv("/c", "/c/D", "i:1", platform="linux/arm64")[:3] == \
        ["docker", "build", "--platform"]
    assert wiring.image_push_argv("r/i:1") == ["docker", "push", "r/i:1"]
    assert wiring.image_tag_argv("i:local", "r/i:local") == ["docker", "tag", "i:local", "r/i:local"]


def test_run_site_builds_dry_run_prints_and_builds_nothing(tmp_path, capsys):
    from secdeploy.site import BuildSpec
    from secdeploy.targets import common as tcommon

    builds = [
        BuildSpec(name="a", component="secchat", dockerfile="Dockerfile.runnerd"),
        BuildSpec(name="b", component="secagent", dockerfile="docker/x.Dockerfile",
                  push=True, registry="reg.io"),
    ]
    assert tcommon.run_site_builds(builds, tmp_path, dry_run=True) == []
    out = capsys.readouterr().out
    assert "build a:local" in out and "(local only, no push)" in out
    assert "build b:local" in out and "push → reg.io/b:local" in out
    # Empty list: a no-op either way.
    assert tcommon.run_site_builds([], tmp_path, dry_run=False) == []


def test_pool_turnkey_command_construction():
    # Pure argv builders (execution lives in the target, so these stay testable without docker/kubectl).
    assert wiring.runnerd_image_ref("reg.io/", "abc123") == "reg.io/secchat-runnerd:abc123"
    assert wiring.runnerd_build_argv("/w/secchat", "reg.io/secchat-runnerd:abc") == \
        ["docker", "build", "-f", "/w/secchat/Dockerfile.runnerd", "-t", "reg.io/secchat-runnerd:abc", "/w/secchat"]
    assert wiring.runnerd_push_argv("reg.io/secchat-runnerd:abc") == ["docker", "push", "reg.io/secchat-runnerd:abc"]
    assert wiring.kubectl_apply_argv("/o/pool.json") == ["kubectl", "apply", "-f", "/o/pool.json"]
    assert wiring.kubectl_apply_argv("/o/pool.json", "enclave") == \
        ["kubectl", "--context", "enclave", "apply", "-f", "/o/pool.json"]


def test_write_pool_manifests_writes_json_when_enabled_else_none(tmp_path):
    out = tmp_path / "addressing"
    path = wiring.write_pool_manifests(_pool(), out)
    assert path == str(out / "secchat-pool.k8s.json")
    assert json.loads(Path(path).read_text()) == wiring.k8s_pool_manifests(_pool())
    # Disabled ⇒ nothing written.
    assert wiring.write_pool_manifests(PoolOptions(), out / "off") is None
    assert not (out / "off").exists()


def test_sync_secchat_env_adds_pool_keys_when_configured(tmp_path):
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECCHATNG_OIDC_CLIENT_SECRET=login-abc\n")
    secchat_env = tmp_path / "secchat.env"
    secchat_env.write_text("SECCHAT_OIDC_CLIENT_SECRET=SEED\nSECCHAT_SESSION_SECRET=keep\n")
    written = wiring.sync_secchat_env(secsso_env, secchat_env, topo, pool=_pool())
    vals = _env_dict(secchat_env)
    assert vals["SECCHAT_POOL_IMAGE"] == "reg/secchat-runnerd:1"
    assert vals["SECCHAT_SESSION_SECRET"] == "keep"  # non-managed still untouched
    assert "SECCHAT_POOL_IMAGE" in written


# ── secchat_voice_env / sync_secchat_env(voice=)/mediad_compose_override/secchat_compose_override:
#    the 1:1 voice-call media relay (secchat-mediad) — plan §2.5/§3.5, docs/voice.md. ──────────────
from secdeploy.site import VoiceOptions  # noqa: E402


def _voice(**kw) -> VoiceOptions:
    base = dict(enabled=True, advertise_addr="192.168.5.1")
    base.update(kw)
    return VoiceOptions(**base)


def test_secchat_voice_env_disabled_is_empty(tmp_path):
    assert wiring.secchat_voice_env(VoiceOptions(), _topo(tmp_path)) == {}


def test_secchat_voice_env_carries_transcribe_url_mediad_url_and_stun(tmp_path):
    env = wiring.secchat_voice_env(_voice(), _topo(tmp_path))
    # SecRecorder is placed (collab tier) in GPU_SPLIT ⇒ a real topology URL, not a stub.
    assert env["SECCHAT_TRANSCRIBE_URL"] == "http://secrecorder.sec.internal:47003"
    assert env["SECCHAT_MEDIAD_URL"] == "http://mediad:47021"
    assert env["SECCHAT_MEDIAD_ADVERTISE_ADDR"] == "192.168.5.1"
    # STUN default is empty — never a public server (CUI/air-gap posture, plan §2.5 point 4).
    assert env["SECCHAT_CALL_STUN"] == ""
    assert env["SECCHAT_MEDIAD_TOKEN"]  # generated, non-empty


def test_secchat_voice_env_omits_transcribe_url_when_secrecorder_withheld(tmp_path):
    env = wiring.secchat_voice_env(_voice(), _topo(tmp_path), without=["secrecorder"])
    assert "SECCHAT_TRANSCRIBE_URL" not in env
    # Everything else voice still needs is unaffected by secrecorder being withheld.
    assert env["SECCHAT_MEDIAD_URL"] == "http://mediad:47021"


def test_secchat_voice_env_uses_configured_control_port_and_stun(tmp_path):
    env = wiring.secchat_voice_env(_voice(control_port=48000, stun="stun.internal:3478"), _topo(tmp_path))
    assert env["SECCHAT_MEDIAD_URL"] == "http://mediad:48000"
    assert env["SECCHAT_CALL_STUN"] == "stun.internal:3478"


def test_secchat_voice_env_token_idempotent_across_calls(tmp_path):
    # No operator-set token, nothing existing yet ⇒ a fresh one is minted.
    topo = _topo(tmp_path)
    first = wiring.secchat_voice_env(_voice(), topo)
    # A second call with the FIRST call's env as `existing` (redeploy shape) must keep it —
    # a live mediad's bearer must never rotate out from under it on a routine redeploy.
    second = wiring.secchat_voice_env(_voice(), topo, existing=first)
    assert second["SECCHAT_MEDIAD_TOKEN"] == first["SECCHAT_MEDIAD_TOKEN"]
    # An operator-set token always wins over both the existing value and generation.
    explicit = wiring.secchat_voice_env(_voice(token="operator-set-token"), topo, existing=first)
    assert explicit["SECCHAT_MEDIAD_TOKEN"] == "operator-set-token"


def test_sync_secchat_env_adds_voice_keys_and_keeps_token_stable_across_redeploys(tmp_path):
    topo = _topo(tmp_path)
    secsso_env = tmp_path / "secsso.env"
    secsso_env.write_text("SECCHATNG_OIDC_CLIENT_SECRET=login-abc\n")
    secchat_env = tmp_path / "secchat.env"
    secchat_env.write_text("SECCHAT_OIDC_CLIENT_SECRET=SEED\nSECCHAT_SESSION_SECRET=keep\n")
    first = wiring.sync_secchat_env(secsso_env, secchat_env, topo, voice=_voice())
    vals1 = _env_dict(secchat_env)
    assert vals1["SECCHAT_MEDIAD_ADVERTISE_ADDR"] == "192.168.5.1"
    assert vals1["SECCHAT_TRANSCRIBE_URL"] == "http://secrecorder.sec.internal:47003"
    assert "SECCHAT_MEDIAD_TOKEN" in first
    token1 = vals1["SECCHAT_MEDIAD_TOKEN"]
    # Redeploy: the token already on disk must survive, not rotate.
    wiring.sync_secchat_env(secsso_env, secchat_env, topo, voice=_voice())
    vals2 = _env_dict(secchat_env)
    assert vals2["SECCHAT_MEDIAD_TOKEN"] == token1
    assert vals2["SECCHAT_SESSION_SECRET"] == "keep"  # non-managed still untouched


def test_mediad_compose_override_shape():
    override = wiring.mediad_compose_override(_voice())
    assert "  mediad:\n" in override
    assert "image: secchat-mediad:local\n" in override
    assert '"47020:47020/udp"' in override and '"47020:47020/tcp"' in override
    assert "MEDIAD_TOKEN: ${SECCHAT_MEDIAD_TOKEN}" in override
    assert "MEDIAD_ADVERTISE_ADDR: ${SECCHAT_MEDIAD_ADVERTISE_ADDR}" in override
    # mediad's config.go reads *_ADDR (":<port>"), not *_PORT — these must match or the
    # container binds the defaults while the compose ports/env silently disagree.
    assert 'MEDIAD_MEDIA_ADDR: ":47020"' in override
    assert 'MEDIAD_CONTROL_ADDR: ":47021"' in override
    assert 'MEDIAD_MAX_LEGS_PER_SESSION: "8"' in override  # mediad's own default, emitted explicitly
    # The control API (:47021) is never PUBLISHED (no "47021:..." port mapping) — it's
    # compose-internal only, reached via SECCHAT_MEDIAD_URL, not a host port.
    assert '"47021:' not in override
    assert "recordings:/var/lib/mediad/recordings" in override
    assert "recordings:/var/lib/secchat/recordings" in override
    assert "recordings: {}" in override


def test_mediad_compose_override_custom_ports_match_published_ports():
    # An operator-configured voice.media_port/control_port must reach mediad's actual bind addrs
    # (MEDIAD_MEDIA_ADDR/MEDIAD_CONTROL_ADDR), not silently diverge from the published ports.
    override = wiring.mediad_compose_override(_voice(media_port=48000, control_port=48001))
    assert 'MEDIAD_MEDIA_ADDR: ":48000"' in override
    assert 'MEDIAD_CONTROL_ADDR: ":48001"' in override
    assert '"48000:48000/udp"' in override and '"48000:48000/tcp"' in override
    assert '"47020:' not in override


def test_mediad_compose_override_carries_configured_max_legs():
    # A larger group-call cap must reach mediad's MEDIAD_MAX_LEGS_PER_SESSION, not stay at 8.
    override = wiring.mediad_compose_override(_voice(max_legs_per_session=16))
    assert 'MEDIAD_MAX_LEGS_PER_SESSION: "16"' in override


def test_secchat_compose_override_empty_when_neither_active():
    assert wiring.secchat_compose_override(None, None) == ""
    assert wiring.secchat_compose_override(_pool(), VoiceOptions()) == ""  # pool w/o create_service_account


def test_secchat_compose_override_pool_only_matches_pool_compose_override():
    p = _pool(create_service_account=True)
    combined = wiring.secchat_compose_override(p, None)
    assert "./pool-sa/token:/var/run/secrets/kubernetes.io/serviceaccount/token:ro" in combined
    assert "mediad:" not in combined
    assert "recordings" not in combined


def test_secchat_compose_override_merges_pool_and_voice_into_one_file():
    # Compose only auto-merges ONE compose.override.yaml — both features' content must coexist
    # in a single `services:`/`volumes:` document, not clobber one another.
    p = _pool(create_service_account=True)
    v = _voice()
    combined = wiring.secchat_compose_override(p, v)
    assert "  mediad:\n" in combined
    assert "./pool-sa/token:/var/run/secrets/kubernetes.io/serviceaccount/token:ro" in combined
    assert "recordings:/var/lib/secchat/recordings" in combined
    assert combined.count("services:") == 1
    assert combined.count("secchat:") == 1  # ONE secchat entry carrying both volume sets
