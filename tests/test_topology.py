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

# inference spread across TWO resources — N SecLLM instances, one per GPU host.
MULTI_INFERENCE = """
domain = "sec.internal"
upstream_dns = ["1.1.1.1"]
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

# identity + gateway + collab + edge (secproxy) all on 'core'; inference on 'gpu' — the
# fronting axis in play: the 5 fronted components should resolve/address via the proxy.
EDGE_SPLIT = """
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
[groups.edge]
resource = "core"
[groups.inference]
resource = "gpu"
"""

FRONTED = ("secsso", "secrouter", "secagent", "secchat", "secrecorder")


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


# ── multi-resource tiers (N SecLLM instances) ────────────────────────────────────────
def test_multi_resource_inference_yields_two_instances(tmp_path):
    topo = _topo(tmp_path, MULTI_INFERENCE)
    instances = topo.instances("secllm")
    assert len(instances) == 2
    by_name = {name: (res, addr) for name, res, addr in instances}
    assert by_name == {
        "secllm-gpu1": ("gpu1", "10.0.0.6"),
        "secllm-gpu2": ("gpu2", "10.0.0.7"),
    }


def test_multi_resource_inference_components_on_each_resource(tmp_path):
    topo = _topo(tmp_path, MULTI_INFERENCE)
    assert set(topo.components_on("gpu1")) == {"secllm"}
    assert set(topo.components_on("gpu2")) == {"secllm"}
    assert "secllm" not in topo.components_on("core")
    assert not topo.warnings  # both gpu resources declare the 'gpu' capability


def test_multi_resource_inference_zone_has_distinct_fqdns(tmp_path):
    topo = _topo(tmp_path, MULTI_INFERENCE)
    zone = topo.zone()
    assert ("secllm-gpu1.sec.internal", "A", "10.0.0.6") in zone
    assert ("secllm-gpu2.sec.internal", "A", "10.0.0.7") in zone
    # the bare (unsuffixed) component name is not a record of its own when there are 2+ instances
    assert not any(fqdn == "secllm.sec.internal" for fqdn, _rtype, _addr in zone)
    assert topo.fqdn("secllm-gpu1") == "secllm-gpu1.sec.internal"
    assert topo.fqdn("secllm-gpu2") == "secllm-gpu2.sec.internal"


def test_multi_resource_inference_single_instance_naming_unchanged(tmp_path):
    """One resource still yields the bare, unsuffixed instance name (byte-identical FQDN)."""
    topo = _topo(tmp_path, GPU_SPLIT)
    assert topo.instances("secllm") == [("secllm", "gpu", "10.0.0.6")]


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
    # peers get URLs pointing at their hosting resource; self is excluded. SecLLM is never
    # fronted/TLS-terminated (inference dials direct) — http, not https, regardless of the
    # default scheme every other (fronted) peer URL uses.
    assert env["SECLLM_URL"] == "http://secllm.sec.internal:11400"
    assert env["SECCERT_URL"] == "http://seccert.sec.internal:47001"
    assert "SECROUTER_URL" not in env


# ── fronting axis: secproxy (edge tier) fronts the 5 HTTP services on :443 ──────────────
def test_proxy_address_none_when_edge_unplaced(tmp_path):
    # GPU_SPLIT has no [groups.edge] at all — the common case today, and every fixture that
    # predates secproxy.
    topo = _topo(tmp_path, GPU_SPLIT)
    assert topo._proxy_address() is None


def test_proxy_address_resolves_the_edge_resource(tmp_path):
    topo = _topo(tmp_path, EDGE_SPLIT)
    assert topo._proxy_address() == "10.0.0.5"


def test_is_fronted_true_for_the_five_when_secproxy_placed(tmp_path):
    topo = _topo(tmp_path, EDGE_SPLIT)
    for name in FRONTED:
        assert topo.is_fronted(name)
    # never fronted, regardless of placement: the CA must stay a direct trust anchor (secproxy
    # bootstraps its certs from it), inference must dial direct, secdns isn't HTTP, and secproxy
    # doesn't front itself
    for name in ("seccert", "secllm", "secdns", "secproxy"):
        assert not topo.is_fronted(name)


def test_is_fronted_false_for_everyone_when_secproxy_unplaced(tmp_path):
    # GPU_SPLIT: same manifest (fronted flags still set), but secproxy/edge isn't placed here —
    # fronting only takes effect once secproxy is actually deployed.
    topo = _topo(tmp_path, GPU_SPLIT)
    for name in FRONTED:
        assert not topo.is_fronted(name)


def test_zone_fronted_components_resolve_to_the_proxy(tmp_path):
    topo = _topo(tmp_path, EDGE_SPLIT)
    zone = {fqdn: addr for fqdn, _rtype, addr in topo.zone()}
    for name in FRONTED:
        assert zone[f"{name}.sec.internal"] == "10.0.0.5"  # the proxy's resource (core)
    # never-fronted components keep their OWN resource address
    assert zone["secllm.sec.internal"] == "10.0.0.6"  # gpu — direct, unaffected by fronting
    assert zone["secdns.sec.internal"] == "10.0.0.5"  # happens to be on core too, but DIRECT
    assert zone["secproxy.sec.internal"] == "10.0.0.5"  # secproxy addresses itself directly


def test_urls_fronted_components_drop_the_port(tmp_path):
    topo = _topo(tmp_path, EDGE_SPLIT)
    urls = topo.urls()
    assert urls["SECROUTER"] == "https://secrouter.sec.internal"
    assert urls["SECSSO"] == "https://secsso.sec.internal"
    assert urls["SECAGENT"] == "https://secagent.sec.internal"
    assert urls["SECCHAT"] == "https://secchat.sec.internal"
    assert urls["SECRECORDER"] == "https://secrecorder.sec.internal"
    # never fronted — keep their explicit port (seccert = the CA, a direct trust anchor).
    # http, not https: none of these terminate TLS themselves — confirmed live (a direct
    # https:// curl to seccert/secllm fails outright; only plain http answers).
    assert urls["SECCERT"] == "http://seccert.sec.internal:47001"
    assert urls["SECLLM"] == "http://secllm.sec.internal:11400"
    assert urls["SECDNS"] == "http://secdns.sec.internal:53"
    # secproxy is the ONE exception: never "fronted" (nothing fronts the fronter) but it IS
    # the suite's real TLS terminator — confirmed live (https answers directly, http 301s to
    # it) — so it keeps the caller's scheme instead of being forced to http like the others.
    assert urls["SECPROXY"] == "https://secproxy.sec.internal:443"


def test_instance_urls_secllm_stays_direct_and_ported_when_fronting_is_active(tmp_path):
    """CRITICAL: SecLLM must NEVER be addressed through secproxy — inference traffic has to
    dial SecRouter directly, even when everything else in this same topology is fronted. Plain
    http, not https — confirmed live SecLLM never terminates TLS itself, and SecRouter's
    turnkey routing to it FATALs with a bare "fetch failed" against an https URL."""
    topo = _topo(tmp_path, EDGE_SPLIT)
    assert topo.instance_urls("secllm", path="/v1") == ["http://secllm.sec.internal:11400/v1"]


def test_env_for_secrouter_peers_are_bare_fronted_urls_but_secllm_pool_stays_direct(tmp_path):
    topo = _topo(tmp_path, EDGE_SPLIT)
    env = topo.env_for("secrouter")
    # CA is direct, not fronted — and plain http, confirmed live it never terminates TLS itself
    assert env["SECCERT_URL"] == "http://seccert.sec.internal:47001"
    assert env["SECAGENT_URL"] == "https://secagent.sec.internal"
    # SECROUTER_SECLLM_ENDPOINTS (the backend pool) stays DIRECT + ported + plain-http no
    # matter what — confirmed live an https URL here FATALs SecRouter's turnkey routing
    assert env["SECROUTER_SECLLM_ENDPOINTS"] == "http://secllm.sec.internal:11400/v1"


def test_backward_compat_no_edge_group_zone_and_urls_unchanged(tmp_path):
    """A topology.toml with no ``[groups.edge]`` section (every fixture/site that predates
    secproxy) must produce EXACTLY the same zone + urls secdeploy generated before secproxy
    existed — is_fronted() is False for everyone, so nothing routes through a proxy that
    isn't placed. Pinned to the literal pre-secproxy values (captured from this same GPU_SPLIT
    fixture before the fronting axis existed), not just a handful of ``in`` checks."""
    topo = _topo(tmp_path, GPU_SPLIT)
    assert topo.zone() == [
        ("seccert.sec.internal", "A", "10.0.0.5"),
        ("secsso.sec.internal", "A", "10.0.0.5"),
        ("secdns.sec.internal", "A", "10.0.0.5"),
        ("secllm.sec.internal", "A", "10.0.0.6"),
        ("secrouter.sec.internal", "A", "10.0.0.5"),
        ("secagent.sec.internal", "A", "10.0.0.5"),
        ("secchat.sec.internal", "A", "10.0.0.5"),
        ("secrecorder.sec.internal", "A", "10.0.0.5"),
    ]
    # http, not the originally-pinned https: none of these terminate TLS themselves when
    # nothing fronts them (confirmed live for seccert/secllm; the same reasoning applies
    # uniformly here — every manifest port in this no-secproxy topology is a plain listener,
    # not a TLS one) — see Topology.urls()'s docstring. Updated deliberately, not a stale
    # snapshot: this pinned value predates that fix and was never actually live-verified.
    assert topo.urls() == {
        "SECCERT": "http://seccert.sec.internal:47001",
        "SECSSO": "http://secsso.sec.internal:9000",
        "SECDNS": "http://secdns.sec.internal:53",
        "SECLLM": "http://secllm.sec.internal:11400",
        "SECROUTER": "http://secrouter.sec.internal:47002",
        "SECAGENT": "http://secagent.sec.internal:47007",
        "SECCHAT": "http://secchat.sec.internal:8065",
        "SECRECORDER": "http://secrecorder.sec.internal:47003",
    }


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


def test_secproxy_unplaced_edge_group_omitted_is_allowed(tmp_path):
    # GPU_SPLIT never declares [groups.edge] — secproxy (optional) is simply unplaced, exactly
    # like the optional identity components above; still legal, not an error.
    topo = _topo(tmp_path, GPU_SPLIT)
    placement = topo.placement()
    assert "secproxy" not in placement
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
