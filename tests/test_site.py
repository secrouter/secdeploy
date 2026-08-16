"""Tests for the unified site config (secsite.toml) model/loader — SiteConfig/DeployOptions."""

from __future__ import annotations

from pathlib import Path

import pytest

from secdeploy.manifest import Manifest
from secdeploy.site import DeployOptions, SiteConfig
from secdeploy.topology import Topology

ROOT = Path(__file__).resolve().parents[1]

# A full secsite.toml: placement (identical shape to topology.toml) + [deploy] + every
# per-resource deploy toggle, spread across three resources (two placed, one declared-but-
# unplaced — legal, same as an extra topology.toml resource today) so every DeployOptions
# field gets exercised somewhere.
SITE_FULL = """
domain = "sec.internal"
upstream_dns = ["1.1.1.1"]

[deploy]
without = ["seccert", "secsso"]
ssh = true

[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
capabilities = ["fips"]
configure_resolver = true
with_agent = true

[resources.gpu]
target = "fedora-fips"
address = "10.0.0.6"
capabilities = ["fips", "gpu"]
with_inference = true
model_dir = "/models"

[resources.mac]
target = "macos"
address = "10.0.0.7"
capabilities = []
tls = true
configure_hosts = true
trust_ca = true

[groups.identity]
resource = "core"
[groups.gateway]
resource = "core"
[groups.collab]
resource = "core"
[groups.inference]
resource = "gpu"
"""

# Shaped exactly like a pre-secsite.toml topology.toml: no [deploy] table, no per-resource
# deploy keys at all.
BARE = """
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


def _manifest() -> Manifest:
    return Manifest.load(ROOT / "suite.toml")


def _site(tmp_path, text: str, manifest: Manifest | None = None) -> SiteConfig:
    p = tmp_path / "secsite.toml"
    p.write_text(text)
    return SiteConfig.load(p, manifest or _manifest())


# ── DeployOptions defaults ───────────────────────────────────────────────────────────
def test_deploy_options_defaults_are_all_off():
    opts = DeployOptions()
    assert opts.with_inference is False
    assert opts.with_agent is False
    assert opts.configure_resolver is False
    assert opts.tls is False
    assert opts.configure_hosts is False
    assert opts.trust_ca is False
    assert opts.model_dir == ""


# ── parsing: placement + [deploy] + per-resource toggles ─────────────────────────────
def test_load_parses_placement(tmp_path):
    site = _site(tmp_path, SITE_FULL)
    assert site.topology.domain == "sec.internal"
    assert site.topology.upstream_dns == ["1.1.1.1"]
    assert set(site.topology.resources) == {"core", "gpu", "mac"}
    assert site.topology.resources["gpu"].capabilities == ["fips", "gpu"]
    assert site.topology.groups["inference"] == ["gpu"]


def test_load_parses_deploy_table(tmp_path):
    site = _site(tmp_path, SITE_FULL)
    assert site.without == ["seccert", "secsso"]
    assert site.ssh is True


def test_deploy_for_returns_the_right_per_resource_options(tmp_path):
    site = _site(tmp_path, SITE_FULL)

    core = site.deploy_for("core")
    assert core.configure_resolver is True
    assert core.with_agent is True
    assert core.with_inference is False  # untouched keys stay at their default
    assert core.model_dir == ""

    gpu = site.deploy_for("gpu")
    assert gpu.with_inference is True
    assert gpu.model_dir == "/models"
    assert gpu.with_agent is False

    mac = site.deploy_for("mac")
    assert mac.tls is True
    assert mac.configure_hosts is True
    assert mac.trust_ca is True
    assert mac.with_inference is False


def test_deploy_for_unknown_or_undeclared_resource_returns_defaults(tmp_path):
    site = _site(tmp_path, SITE_FULL)
    assert site.deploy_for("nope") == DeployOptions()


# ── back-compat: a bare topology.toml-shaped file ─────────────────────────────────────
def test_load_bare_topology_shaped_file_yields_all_default_deploy_options(tmp_path):
    """A file with no [deploy] table and no per-resource deploy keys — i.e. exactly what
    topology.toml has always looked like — loads through SiteConfig.load directly (not just
    via from_topology) and reads back with every deploy option at its default."""
    site = _site(tmp_path, BARE)
    assert site.without == []
    assert site.ssh is False
    assert site.deploy_for("core") == DeployOptions()
    assert site.deploy_for("gpu") == DeployOptions()


def test_from_topology_wraps_with_all_default_deploy_options(tmp_path):
    m = _manifest()
    tpath = tmp_path / "topology.toml"
    tpath.write_text(BARE)
    topo = Topology.load(tpath, m)
    site = SiteConfig.from_topology(topo)
    assert site.topology is topo
    assert site.without == []
    assert site.ssh is False
    assert site.deploy_for("core") == DeployOptions()
    assert site.deploy_for("gpu") == DeployOptions()


def test_single_host_all_default(tmp_path):
    m = _manifest()
    site = SiteConfig.single_host(m, "macos", address="127.0.0.1")
    assert set(site.topology.resources) == {"local"}
    assert site.without == []
    assert site.ssh is False
    assert site.deploy_for("local") == DeployOptions()


# ── validation: unknown keys (fail-loud) ──────────────────────────────────────────────
def test_unknown_deploy_table_key_rejected(tmp_path):
    bad = SITE_FULL.replace("ssh = true", "ssh = true\nbogus = 1")
    with pytest.raises(ValueError, match=r"\[deploy\]"):
        _site(tmp_path, bad)


def test_unknown_resource_deploy_key_rejected(tmp_path):
    bad = SITE_FULL.replace("with_inference = true", "with_infernce = true")
    with pytest.raises(ValueError, match="gpu"):
        _site(tmp_path, bad)


def test_unknown_resource_placement_key_typo_rejected(tmp_path):
    # a typo'd PLACEMENT key (not a deploy key either) is caught the same way
    bad = SITE_FULL.replace("address = \"10.0.0.7\"", "addres = \"10.0.0.7\"")
    with pytest.raises(ValueError, match="mac"):
        _site(tmp_path, bad)


# ── validation: without (mirrors Manifest.select) ─────────────────────────────────────
def test_without_of_required_component_rejected(tmp_path):
    bad = SITE_FULL.replace('without = ["seccert", "secsso"]', 'without = ["secrouter"]')
    with pytest.raises(ValueError, match="secrouter"):
        _site(tmp_path, bad)


def test_without_of_unknown_component_rejected(tmp_path):
    bad = SITE_FULL.replace('without = ["seccert", "secsso"]', 'without = ["nope"]')
    with pytest.raises(ValueError, match="nope"):
        _site(tmp_path, bad)


def test_without_optional_components_is_fine(tmp_path):
    site = _site(tmp_path, SITE_FULL)  # without = ["seccert", "secsso"], both optional
    assert site.without == ["seccert", "secsso"]


# ── validation: placement (reuses Topology.validate) ──────────────────────────────────
def test_invalid_topology_placement_rejected(tmp_path):
    bad = SITE_FULL.replace('target = "fedora-fips"\naddress = "10.0.0.5"',
                            'target = "windows"\naddress = "10.0.0.5"')
    with pytest.raises(ValueError):
        _site(tmp_path, bad)


def test_unplaced_required_component_rejected(tmp_path):
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
        _site(tmp_path, missing_gateway)


# ── serialization: round-trip ──────────────────────────────────────────────────────────
def test_roundtrip(tmp_path):
    site = _site(tmp_path, SITE_FULL)
    out = tmp_path / "rt.toml"
    out.write_text(site.to_toml())
    reloaded = SiteConfig.load(out, _manifest())

    assert reloaded.topology.domain == site.topology.domain
    assert reloaded.topology.upstream_dns == site.topology.upstream_dns
    assert set(reloaded.topology.resources) == set(site.topology.resources)
    assert reloaded.topology.groups == site.topology.groups
    assert reloaded.without == site.without
    assert reloaded.ssh == site.ssh
    for rname in ("core", "gpu", "mac"):
        assert reloaded.deploy_for(rname) == site.deploy_for(rname)


def test_roundtrip_bare_file_stays_all_default(tmp_path):
    site = _site(tmp_path, BARE)
    out = tmp_path / "rt.toml"
    out.write_text(site.to_toml())
    reloaded = SiteConfig.load(out, _manifest())
    assert reloaded.without == []
    assert reloaded.ssh is False
    assert reloaded.deploy_for("core") == DeployOptions()
    assert reloaded.deploy_for("gpu") == DeployOptions()


# ── [[users]] declared accounts (SecDeploy → SecSSO onboarding) ───────────────────────
SITE_USERS = BARE + """
[[users]]
username = "alice"
email = "alice@example.mil"
name = "Alice Analyst"
groups = ["analysts", "cui-cleared"]

[[users]]
username = "bob"
email = "bob@example.mil"
"""


def test_load_parses_users(tmp_path):
    site = _site(tmp_path, SITE_USERS)
    assert [u.username for u in site.users] == ["alice", "bob"]
    alice = site.users[0]
    assert alice.email == "alice@example.mil"
    assert alice.name == "Alice Analyst"
    assert alice.groups == ["analysts", "cui-cleared"]
    assert site.users[1].groups == []  # optional — absent means no group membership


def test_no_users_section_yields_empty_list(tmp_path):
    assert _site(tmp_path, BARE).users == []


def test_users_missing_username_rejected(tmp_path):
    with pytest.raises(ValueError, match="username is required"):
        _site(tmp_path, BARE + '\n[[users]]\nemail = "x@y.z"\n')


def test_users_duplicate_username_rejected(tmp_path):
    with pytest.raises(ValueError, match="duplicate username"):
        _site(tmp_path, BARE + '\n[[users]]\nusername = "a"\n[[users]]\nusername = "a"\n')


def test_users_unknown_key_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown key"):
        _site(tmp_path, BARE + '\n[[users]]\nusername = "a"\nrole = "admin"\n')


def test_users_round_trip(tmp_path):
    site = _site(tmp_path, SITE_USERS)
    reloaded = _site(tmp_path, site.to_toml())
    assert [(u.username, u.email, u.name, u.groups) for u in reloaded.users] == \
           [(u.username, u.email, u.name, u.groups) for u in site.users]


# ── Named site profiles (sites/<name>.toml) ──────────────────────────────────────────

def test_resolve_site_ref_paths_and_profiles(tmp_path):
    from secdeploy.site import list_site_profiles, resolve_site_ref, site_profile_path

    # No value → None; a real path → unchanged.
    assert resolve_site_ref(None, tmp_path) is None
    real = tmp_path / "somewhere.toml"
    real.write_text("x = 1\n")
    assert resolve_site_ref(str(real), tmp_path) == str(real)

    # A bare name resolves to sites/<name>.toml when saved…
    p = site_profile_path("colima-test", tmp_path)
    p.parent.mkdir(parents=True)
    p.write_text("domain = 'sec.internal'\n")
    assert resolve_site_ref("colima-test", tmp_path) == str(p)
    assert list_site_profiles(tmp_path) == ["colima-test"]

    # …an unsaved name / an explicit .toml path pass through unchanged (downstream errors name
    # what the caller typed).
    assert resolve_site_ref("nope", tmp_path) == "nope"
    assert resolve_site_ref("missing.toml", tmp_path) == "missing.toml"


# ── Optional container builds ([[builds]]) ───────────────────────────────────────────
SITE_BUILDS = BARE + """
[[builds]]
name = "secchat-runnerd"
component = "secchat"
dockerfile = "Dockerfile.runnerd"

[[builds]]
name = "secagent-analyzer-rust"
component = "secagent"
dockerfile = "docker/analyzer-rust.Dockerfile"
tag = "v1"
push = true
registry = "registry.internal"
platform = "linux/arm64"
"""


def test_builds_default_empty_when_absent(tmp_path):
    assert _site(tmp_path, BARE).builds == []


def test_builds_parse_all_fields_and_refs(tmp_path):
    builds = _site(tmp_path, SITE_BUILDS).builds
    assert [b.name for b in builds] == ["secchat-runnerd", "secagent-analyzer-rust"]
    first = builds[0]
    assert (first.component, first.dockerfile, first.tag, first.context, first.push) == \
        ("secchat", "Dockerfile.runnerd", "local", ".", False)
    assert first.local_ref == "secchat-runnerd:local"
    second = builds[1]
    assert second.push is True and second.registry == "registry.internal"
    assert second.platform == "linux/arm64"
    assert second.local_ref == "secagent-analyzer-rust:v1"
    assert second.push_ref == "registry.internal/secagent-analyzer-rust:v1"


def test_builds_missing_required_fields_rejected(tmp_path):
    with pytest.raises(ValueError, match="name, component, and dockerfile are required"):
        _site(tmp_path, BARE + '\n[[builds]]\nname = "x"\n')


def test_builds_unknown_component_rejected(tmp_path):
    with pytest.raises(ValueError, match="unknown component 'nope'"):
        _site(tmp_path, BARE + '\n[[builds]]\nname = "x"\ncomponent = "nope"\ndockerfile = "Dockerfile"\n')


def test_builds_push_without_registry_rejected(tmp_path):
    with pytest.raises(ValueError, match="registry is required when push"):
        _site(tmp_path, BARE + '\n[[builds]]\nname = "x"\ncomponent = "secchat"\ndockerfile = "Dockerfile"\npush = true\n')


def test_builds_duplicate_name_rejected(tmp_path):
    dup = ('\n[[builds]]\nname = "x"\ncomponent = "secchat"\ndockerfile = "Dockerfile"\n' * 2)
    with pytest.raises(ValueError, match="duplicate name 'x'"):
        _site(tmp_path, BARE + dup)


def test_builds_unknown_key_rejected(tmp_path):
    with pytest.raises(ValueError, match=r"\[\[builds\]\]\[0\]: unknown key"):
        _site(tmp_path, BARE + '\n[[builds]]\nname = "x"\ncomponent = "secchat"\ndockerfile = "D"\nbogus = 1\n')


def test_builds_round_trip_through_to_toml(tmp_path):
    site = _site(tmp_path, SITE_BUILDS)
    reloaded = _site(tmp_path, site.to_toml())
    assert reloaded.builds == site.builds


# ── Kubernetes agent pool ([secchat.pool]) ───────────────────────────────────────────
SITE_POOL = BARE + """
[secchat.pool]
enabled = true
image = "registry.internal/secchat-runnerd:1.0.0"
namespace = "chat-pool"
service_account = "secchat"
service_account_namespace = "chat"
git_host = "git.sec.internal"
secchat_url = "http://secchat.chat.svc:47010"
max_pods = 12
max_per_owner = 4
ttl_seconds = 1800
build_image = true
registry = "registry.internal"
apply = true
kube_context = "enclave"
api_server = "https://192.168.5.1:6443"
create_service_account = true

[secchat.pool.analysis_images]
rust = "secagent-analyzer-rust:1"
ikos = "secagent-analysis:1"
"""


def test_secchat_pool_defaults_off_when_absent(tmp_path):
    site = _site(tmp_path, BARE)
    assert site.secchat_pool.enabled is False
    assert site.secchat_pool.image == ""
    assert site.secchat_pool.namespace == "secchat-pool"  # the default


def test_secchat_pool_parses_all_fields(tmp_path):
    pool = _site(tmp_path, SITE_POOL).secchat_pool
    assert pool.enabled is True
    assert pool.image == "registry.internal/secchat-runnerd:1.0.0"
    assert pool.namespace == "chat-pool"
    assert pool.service_account == "secchat"
    assert pool.service_account_namespace == "chat"
    assert pool.git_host == "git.sec.internal"
    assert pool.secchat_url == "http://secchat.chat.svc:47010"
    assert pool.max_pods == 12
    assert pool.max_per_owner == 4
    assert pool.ttl_seconds == 1800
    assert pool.build_image is True
    assert pool.registry == "registry.internal"
    assert pool.apply is True
    assert pool.kube_context == "enclave"
    assert pool.api_server == "https://192.168.5.1:6443"
    assert pool.create_service_account is True
    assert pool.analysis_images == {"rust": "secagent-analyzer-rust:1", "ikos": "secagent-analysis:1"}


def test_secchat_pool_enabled_without_image_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="image is required"):
        _site(tmp_path, BARE + "\n[secchat.pool]\nenabled = true\n")


def test_secchat_pool_enabled_without_image_ok_when_build_image(tmp_path):
    # build_image produces the image, so an explicit image isn't required (registry must be set).
    pool = _site(tmp_path, BARE + '\n[secchat.pool]\nenabled = true\nbuild_image = true\nregistry = "reg.io"\n').secchat_pool
    assert pool.enabled is True and pool.build_image is True and pool.image == ""


def test_secchat_pool_build_image_without_registry_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="registry is required"):
        _site(tmp_path, BARE + '\n[secchat.pool]\nenabled = true\nimage = "x"\nbuild_image = true\n')


def test_secchat_pool_unknown_key_is_rejected(tmp_path):
    with pytest.raises(ValueError, match=r"\[secchat.pool\]: unknown key"):
        _site(tmp_path, BARE + '\n[secchat.pool]\nimage = "x"\nbogus = 1\n')


def test_secchat_section_unknown_key_is_rejected(tmp_path):
    with pytest.raises(ValueError, match=r"\[secchat\]: unknown key"):
        _site(tmp_path, BARE + '\n[secchat]\nnope = 1\n')


def test_secchat_pool_round_trips_through_to_toml(tmp_path):
    site = _site(tmp_path, SITE_POOL)
    reloaded = _site(tmp_path, site.to_toml())
    assert reloaded.secchat_pool == site.secchat_pool


def test_bare_config_emits_no_pool_section(tmp_path):
    # A pool-less site never writes a [secchat.pool] block (keeps bare configs clean).
    assert "[secchat.pool]" not in _site(tmp_path, BARE).to_toml()


# ── [secchat.voice] — the 1:1 voice-call media relay (secchat-mediad). Mirrors the [secchat.pool]
#    coverage above: defaults, full-field parse, required-field/unknown-key rejection, round-trip,
#    bare-config cleanliness. See docs/voice.md / docs/plans/voice-calls-plan.md §2.5. ────────────
SITE_VOICE = BARE + """
[secchat.voice]
enabled = true
image = "registry.internal/secchat-mediad:1.0.0"
token = "shared-bearer"
stun = "stun.internal:3478"
advertise_addr = "192.168.5.1"
media_port = 48020
control_port = 48021
"""


def test_secchat_voice_defaults_off_when_absent(tmp_path):
    site = _site(tmp_path, BARE)
    assert site.secchat_voice.enabled is False
    assert site.secchat_voice.advertise_addr == ""
    assert site.secchat_voice.image == "secchat-mediad:local"  # the default
    assert site.secchat_voice.media_port == 47020
    assert site.secchat_voice.control_port == 47021


def test_secchat_voice_parses_all_fields(tmp_path):
    voice = _site(tmp_path, SITE_VOICE).secchat_voice
    assert voice.enabled is True
    assert voice.image == "registry.internal/secchat-mediad:1.0.0"
    assert voice.token == "shared-bearer"
    assert voice.stun == "stun.internal:3478"
    assert voice.advertise_addr == "192.168.5.1"
    assert voice.media_port == 48020
    assert voice.control_port == 48021


def test_secchat_voice_enabled_without_advertise_addr_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="advertise_addr is required"):
        _site(tmp_path, BARE + "\n[secchat.voice]\nenabled = true\n")


def test_secchat_voice_rejects_a_public_stun_default(tmp_path):
    # A public STUN server leaks call metadata + client IPs off-suite — the v3.1 REQUIRED default
    # (plan §2.5 point 4). Must be rejected, not silently accepted.
    with pytest.raises(ValueError, match="looks like a public STUN server"):
        _site(tmp_path, BARE + '\n[secchat.voice]\nenabled = true\nadvertise_addr = "1.2.3.4"\n'
                               'stun = "stun.l.google.com:19302"\n')


def test_secchat_voice_unknown_key_is_rejected(tmp_path):
    with pytest.raises(ValueError, match=r"\[secchat.voice\]: unknown key"):
        _site(tmp_path, BARE + '\n[secchat.voice]\nbogus = 1\n')


def test_secchat_voice_round_trips_through_to_toml(tmp_path):
    site = _site(tmp_path, SITE_VOICE)
    reloaded = _site(tmp_path, site.to_toml())
    assert reloaded.secchat_voice == site.secchat_voice


def test_bare_config_emits_no_voice_section(tmp_path):
    assert "[secchat.voice]" not in _site(tmp_path, BARE).to_toml()


def test_secchat_pool_and_voice_can_coexist(tmp_path):
    # [secchat] carries both sub-tables at once without either rejecting the other.
    site = _site(tmp_path, SITE_POOL + '\n[secchat.voice]\nenabled = true\nadvertise_addr = "1.2.3.4"\n')
    assert site.secchat_pool.enabled is True
    assert site.secchat_voice.enabled is True
