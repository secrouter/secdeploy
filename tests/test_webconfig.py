"""Tests for the graphical configurator (`secdeploy configure --web`) — the pure pieces: page
rendering, form → TOML shaping, and the SiteConfig round-trip validation. The HTTP handler is a
thin shell over these (loopback-only, stdlib http.server) and isn't exercised here."""

from __future__ import annotations

from pathlib import Path

from secdeploy import webconfig
from secdeploy.manifest import Manifest
from secdeploy.site import SiteConfig

ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> Manifest:
    return Manifest.load(ROOT / "suite.toml")


def _single_host_site() -> SiteConfig:
    return SiteConfig.single_host(_manifest(), "macos")


# A representative full submission (parse_qs shape: every value is a list).
def _form(**overrides) -> dict[str, list[str]]:
    base: dict[str, list[str]] = {
        "domain": ["sec.internal"],
        "upstream_dns": ["1.1.1.1, 8.8.8.8"],
        "without": ["secrecorder"],
        "res.0.name": ["mac"],
        "res.0.target": ["macos"],
        "res.0.address": ["127.0.0.1"],
        "res.0.capabilities": [""],
        "res.0.with_inference": ["on"],
        "res.0.inference_backend": ["metal"],
        "res.0.autostart_models": ["fast, balanced"],
        "res.0.with_agent": ["on"],
        "res.0.model_dir": [""],
        "group.identity": ["mac"],
        "group.inference": ["mac"],
        "group.gateway": ["mac"],
        "group.collab": ["mac"],
        "group.edge": ["mac"],
        "user.0.username": ["alice"],
        "user.0.email": ["alice@sec.internal"],
        "user.0.name": ["Alice Ng"],
        "user.0.groups": ["eng, secchat-admins"],
        "build.0.name": ["secchat-runnerd"],
        "build.0.component": ["secchat"],
        "build.0.dockerfile": ["Dockerfile.runnerd"],
        "build.0.tag": ["local"],
        "build.0.context": ["."],
    }
    base.update({k: (v if isinstance(v, list) else [v]) for k, v in overrides.items()})
    return base


def test_render_form_contains_every_section_and_help(tmp_path):
    html = webconfig.render_form(_single_host_site(), _manifest(), "secsite.toml")
    for section in ("Site", "Resources", "Tier placement", "Suite deploy options",
                    "Users", "Agent pool", "Container builds"):
        assert section in html
    # Explanations render (spot-check a few), and the optional components appear as checkboxes.
    assert "internal DNS domain" in html
    assert "vLLM-Metal" in html
    assert "secrecorder" in html
    # The SecRouter theme (palette variables) is inline — self-contained, no CDN.
    assert "--accent:#4f6a2e" in html and "<link" not in html


def test_render_form_matches_the_frozen_theme_contract():
    html = webconfig.render_form(_single_host_site(), _manifest(), "secsite.toml")
    # Canonical tokens (spec-a-design.md) — the corrected --bad plus the previously-missing
    # --ok/--warn and pill tokens, in both light (root) and dark (`[data-theme="dark"]`) form.
    assert "--bad:#8a2b1d;" in html and "--bad:#d4634c;" in html
    assert "--ok:#2f5a22;" in html and "--warn:#8a5a12;" in html
    assert "--pill-ok-bg:#e3ebd7;" in html and "--pill-bad-bg:#f0ddd7;" in html and "--pill-warn-bg:#efe6cf;" in html
    # Frozen theme mechanics: data-theme override, OS-media fallback guarded to not[data-theme=light],
    # the pre-paint localStorage read (no flash), and a visible toggle wired to the same key/attr
    # secrouter's admin-ui.ts / the landing page use.
    assert ':root[data-theme="dark"]' in html
    assert ':root:not([data-theme="light"])' in html
    assert "localStorage.getItem('secrouter-theme')" in html
    assert 'class="btn ghost theme-toggle"' in html
    assert "localStorage.setItem('secrouter-theme'" in html
    # Wordmark + inline hexagon logo (CSS theme-swap via currentColor/var(--accent), no asset files).
    assert '<span class="sec">SEC</span>DEPLOY' in html
    assert "polygon points=\"24,2 44,13 44,37 24,54 4,37 4,13\"" in html


def test_form_round_trips_to_a_valid_site(tmp_path):
    site, text, errors = webconfig.validate_form(_form(), _manifest(), tmp_path)
    assert errors == []
    assert site is not None
    assert site.topology.domain == "sec.internal"
    assert site.without == ["secrecorder"]
    opts = site.deploy_for("mac")
    assert opts.with_inference is True and opts.inference_backend == "metal"
    assert opts.autostart_models == ["fast", "balanced"]
    assert opts.tls is False  # unchecked checkbox stays off
    assert [u.username for u in site.users] == ["alice"]
    assert site.users[0].groups == ["eng", "secchat-admins"]
    assert [b.name for b in site.builds] == ["secchat-runnerd"]
    # The generated TOML itself reloads identically (webconfig writes exactly this text).
    p = tmp_path / "roundtrip.toml"
    p.write_text(text)
    assert SiteConfig.load(p, _manifest()).topology.domain == "sec.internal"


def test_form_pool_section_round_trips(tmp_path):
    form = _form(**{
        "pool.enabled": ["on"],
        "pool.image": ["secchat-runnerd:local"],
        "pool.namespace": ["secchat-pool"],
        "pool.service_account": ["secchat"],
        "pool.service_account_namespace": ["secchat-pool"],
        "pool.secchat_url": ["http://192.168.5.1:47010"],
        "pool.cpu": ["1"],
        "pool.memory": ["1Gi"],
        "pool.max_pods": ["5"],
        "pool.max_per_owner": ["2"],
        "pool.ttl_seconds": ["3600"],
        "pool.kube_context": ["colima"],
        "pool.apply": ["on"],
    })
    site, _text, errors = webconfig.validate_form(form, _manifest(), tmp_path)
    assert errors == []
    pool = site.secchat_pool
    assert pool.enabled is True and pool.image == "secchat-runnerd:local"
    assert pool.max_pods == 5 and pool.apply is True
    assert pool.build_image is False  # unchecked stays off


def test_invalid_form_surfaces_the_same_errors_as_the_cli(tmp_path):
    # An unplaced required tier → the exact fail-loud SiteConfig/topology error, on the page.
    form = _form()
    form.pop("group.gateway")
    site, _text, errors = webconfig.validate_form(form, _manifest(), tmp_path)
    assert site is None
    assert any("gateway" in e for e in errors)


def test_blank_rows_are_skipped(tmp_path):
    # An added-then-cleared row (all fields empty) must not produce a broken TOML block.
    form = _form(**{"user.1.username": [""], "user.1.email": [""], "user.1.name": [""], "user.1.groups": [""]})
    site, _text, errors = webconfig.validate_form(form, _manifest(), tmp_path)
    assert errors == []
    assert [u.username for u in site.users] == ["alice"]
