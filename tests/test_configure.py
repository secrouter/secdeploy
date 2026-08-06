"""Tests for the interactive `secdeploy configure` wizard (driven with scripted input)."""

from __future__ import annotations

import stat
from pathlib import Path

from secdeploy import configure
from secdeploy.manifest import Manifest
from secdeploy.site import SiteConfig

ROOT = Path(__file__).resolve().parents[1]


def _manifest() -> Manifest:
    return Manifest.load(ROOT / "suite.toml")


def _driver(answers: list[str]):
    it = iter(answers)
    return lambda _prompt="": next(it)


def _stage_env_examples(root: Path) -> None:
    """Copy the real repo's shipped ``*.env.example`` templates into an isolated tmp ``root``,
    so secret-seeding tests read/write real-shaped templates without ever touching the actual
    checkout's ``deploy/`` directory (which would leave stray test secrets on disk)."""
    for rel in (
        "deploy/fedora-fips/seccert.env.example",
        "deploy/fedora-fips/secagent.env.example",
        "deploy/fedora-fips/secrecorder.env.example",
        "deploy/fedora-fips/secrouter.env.example",
        "deploy/macos/secrets.env.example",
    ):
        src = ROOT / rel
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(src.read_text())


# ── layout presets: placement + suite-wide/per-resource deploy options ───────────────────────

def test_single_host_preset(tmp_path):
    dest = tmp_path / "secsite.toml"
    answers = [
        "sec.internal",  # domain
        "1.1.1.1",       # upstream
        "single-host",   # layout
        "local",         # resource name
        "macos",         # target
        "127.0.0.1",     # address
        "",              # ssh
        "",              # capabilities
        "",              # [deploy].without: drop none
        "",              # with_inference -> False (default)
        "",              # with_agent -> False (default)
        "",              # configure_resolver -> True (default; secdns is deployed here)
        "",              # tls -> False (default; macOS resource)
        "",              # configure_hosts -> False (default)
        "",              # trust_ca -> True (default)
        "",              # model_dir -> "" (blank)
        "N",             # set up operator secrets now? no
    ]
    result = configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert result == dest
    site = SiteConfig.load(dest, _manifest())
    topo = site.topology
    assert topo.domain == "sec.internal" and topo.upstream_dns == ["1.1.1.1"]
    assert list(topo.resources) == ["local"]
    assert topo.groups == {
        t: ["local"] for t in ("identity", "inference", "gateway", "collab", "edge")
    }
    assert site.without == []
    assert site.ssh is False
    opts = site.deploy_for("local")
    assert opts.with_inference is False
    assert opts.with_agent is False
    assert opts.configure_resolver is True
    assert opts.tls is False
    assert opts.configure_hosts is False
    assert opts.trust_ca is True
    assert opts.model_dir == ""


def test_gpu_split_preset_edge_placement_without_and_toggles(tmp_path):
    """gpu-split now also asks where to place the edge tier (closing its old gap — see
    _ask_edge_placement), the suite-wide [deploy].without, and each resource's own applicable
    deploy toggles. Drops secdns via `without` here specifically to prove configure_resolver is
    never even ASKED once secdns won't be deployed (see secdns_deployed gating)."""
    dest = tmp_path / "secsite.toml"
    answers = [
        "sec.internal", "",           # domain, (closed) upstream
        "gpu-split",
        "core", "fedora-fips", "10.0.0.5", "", "fips",       # core resource
        "gpu", "fedora-fips", "10.0.0.6", "", "fips,gpu",    # gpu resource
        "core",          # edge (secproxy) → core
        "secdns",        # [deploy].without: drop secdns
        "y",             # core: with_agent -> True (collab is on core)
        "y",             # gpu: with_inference -> True (inference is on gpu)
        "",              # gpu: autostart_models -> [] (none)
        "N",             # set up operator secrets now? no
    ]
    result = configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert result == dest
    site = SiteConfig.load(dest, _manifest())
    topo = site.topology
    assert set(topo.resources) == {"core", "gpu"}
    assert topo.upstream_dns == []  # closed network
    assert topo.groups["inference"] == ["gpu"]
    assert topo.groups["gateway"] == ["core"]
    assert topo.groups["edge"] == ["core"]  # the gpu-split edge gap is closed
    assert topo.resources["gpu"].capabilities == ["fips", "gpu"]
    assert site.without == ["secdns"]

    core_opts = site.deploy_for("core")
    assert core_opts.with_agent is True
    assert core_opts.configure_resolver is False  # secdns dropped -> never asked -> stays default

    gpu_opts = site.deploy_for("gpu")
    assert gpu_opts.with_inference is True
    assert gpu_opts.configure_resolver is False
    assert gpu_opts.autostart_models == []


def test_gpu_split_edge_none_omits_the_tier_entirely(tmp_path):
    """Choosing "none" for the edge question must skip secproxy placement entirely — not leave
    behind an empty [groups.edge] — same as never mentioning an all-optional tier at all."""
    dest = tmp_path / "secsite.toml"
    answers = [
        "sec.internal", "", "gpu-split",
        "core", "fedora-fips", "10.0.0.5", "", "fips",
        "gpu", "fedora-fips", "10.0.0.6", "", "fips,gpu",
        "none",   # edge (secproxy): skip
        "",       # without: drop none
        "", "",   # core: with_agent, configure_resolver
        "", "",   # gpu: with_inference, configure_resolver
        "N",      # secrets: no
    ]
    result = configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert result == dest
    site = SiteConfig.load(dest, _manifest())
    assert "edge" not in site.topology.groups
    assert "[groups.edge]" not in dest.read_text()


def test_custom_preset(tmp_path):
    dest = tmp_path / "secsite.toml"
    answers = [
        "sec.internal", "1.1.1.1",
        "custom", "2",
        "a", "fedora-fips", "10.0.0.1", "", "",       # resource a
        "b", "macos", "10.0.0.2", "", "gpu",          # resource b (has gpu)
        "a", "b", "a", "b", "a",  # identity→a inference→b gateway→a collab→b edge→a
        "",              # [deploy].without: drop none
        "n",             # a: configure_resolver -> False (only applicable toggle here)
        "y",             # b: with_inference -> True
        "fast,reasoning", # b: autostart_models
        "y",             # b: with_agent -> True
        "",              # b: configure_resolver -> True (default)
        "y",             # b: tls -> True
        "",              # b: configure_hosts -> False (default)
        "",              # b: trust_ca -> True (default)
        "/models",       # b: model_dir
        "N",             # secrets: no
    ]
    result = configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert result == dest
    site = SiteConfig.load(dest, _manifest())
    assert site.topology.groups == {
        "identity": ["a"], "inference": ["b"], "gateway": ["a"], "collab": ["b"], "edge": ["a"],
    }
    assert site.without == []

    a_opts = site.deploy_for("a")
    assert a_opts.configure_resolver is False
    assert a_opts.with_inference is False and a_opts.with_agent is False
    assert a_opts.tls is False and a_opts.trust_ca is False  # never asked (fedora-fips target)

    b_opts = site.deploy_for("b")
    assert b_opts.with_inference is True
    assert b_opts.autostart_models == ["fast", "reasoning"]
    assert b_opts.with_agent is True
    assert b_opts.configure_resolver is True
    assert b_opts.tls is True
    assert b_opts.configure_hosts is False
    assert b_opts.trust_ca is True
    assert b_opts.model_dir == "/models"


def test_aborts_without_overwrite(tmp_path):
    dest = tmp_path / "secsite.toml"
    dest.write_text("# existing\n")
    answers = [
        "sec.internal", "1.1.1.1", "single-host",
        "local", "macos", "127.0.0.1", "", "",
        "",                          # without
        "", "", "", "", "", "", "",  # the 7 macOS/full-tier per-resource questions
        "N",                         # do not overwrite
    ]
    result = configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert result is None
    assert dest.read_text() == "# existing\n"  # untouched — and secret-seeding never ran either
    # (declining consumed exactly the answers above — the driver would raise StopIteration if
    # _maybe_seed_secrets had been reached and asked anything further)


def test_output_via_verify_roundtrip(tmp_path):
    """The wizard's output must pass both `verify --topology` (the placement-only view a plain
    Topology.load takes) and `verify --site` (the full SiteConfig view) — see
    wiring.active_site's precedence. Also proves an explicit, non-default dest path (not
    literally named secsite.toml) still works."""
    from secdeploy.cli import main

    dest = tmp_path / "topology.toml"
    answers = [
        "sec.internal", "1.1.1.1", "gpu-split",
        "core", "fedora-fips", "10.0.0.5", "", "fips",
        "gpu", "fedora-fips", "10.0.0.6", "", "fips,gpu",
        "core",   # edge → core
        "",       # without: drop none
        "", "",   # core: with_agent, configure_resolver
        "", "",   # gpu: with_inference, configure_resolver
        "N",      # secrets: no
    ]
    configure.run(_manifest(), dest=dest, input_fn=_driver(answers), out=lambda *_: None)
    assert main(["--manifest", str(ROOT / "suite.toml"), "verify", "--topology", str(dest)]) == 0
    assert main(["--manifest", str(ROOT / "suite.toml"), "verify", "--site", str(dest)]) == 0


# ── secret-seeding: operator-typed secrets → gitignored *.env files, NEVER secsite.toml ──────

def test_secret_seeding_writes_fedora_env_files_never_in_secsite_toml(tmp_path):
    root = tmp_path / "checkout"
    _stage_env_examples(root)
    dest = tmp_path / "secsite.toml"
    answers = [
        "sec.internal", "1.1.1.1", "single-host",
        "local", "fedora-fips", "127.0.0.1", "", "",
        "",                    # [deploy].without: drop none
        "", "y", "",           # with_inference, with_agent (-> True), configure_resolver
        "y",                   # set up operator secrets now? yes
        "n",                   # auto-generate internal secrets? no — type them (below)
        "sup3r-ca-pass", "sup3r-admin-tok",    # SecCert
        "sso-secret-xyz", "mm-bot-tok-abc",    # SecAgent
        "hf_test_token",                        # SecRecorder
        "/etc/secsuite/secrouter.config.hardened.json",  # SecRouter FREEROUTER_CONFIG
    ]
    driver = _driver(answers)
    result = configure.run(
        _manifest(), dest=dest, root=root, input_fn=driver, out=lambda *_: None, getpass_fn=driver,
    )
    assert result == dest

    site_text = dest.read_text()
    for secret in (
        "sup3r-ca-pass", "sup3r-admin-tok", "sso-secret-xyz", "mm-bot-tok-abc", "hf_test_token",
    ):
        assert secret not in site_text  # NEVER in secsite.toml

    seccert_env = root / "deploy/fedora-fips/seccert.env"
    secagent_env = root / "deploy/fedora-fips/secagent.env"
    secrecorder_env = root / "deploy/fedora-fips/secrecorder.env"
    secrouter_env = root / "deploy/fedora-fips/secrouter.env"
    for p in (seccert_env, secagent_env, secrecorder_env, secrouter_env):
        assert p.exists()
        assert stat.S_IMODE(p.stat().st_mode) == 0o600

    assert "SECCERT_CA_PASSPHRASE=sup3r-ca-pass" in seccert_env.read_text()
    assert "SECCERT_ADMIN_TOKEN=sup3r-admin-tok" in seccert_env.read_text()
    assert "SECAGENT_CLIENT_SECRET=sso-secret-xyz" in secagent_env.read_text()
    assert "SECAGENT_MATTERMOST__BOT_TOKEN=mm-bot-tok-abc" in secagent_env.read_text()
    assert "HF_TOKEN=hf_test_token" in secrecorder_env.read_text()
    assert "FREEROUTER_CONFIG=/etc/secsuite/secrouter.config.hardened.json" in secrouter_env.read_text()
    # a fedora-fips-only site must never touch macOS's shared secrets.env
    assert not (root / "deploy/macos/secrets.env").exists()


def test_secret_seeding_macos_shares_one_secrets_env_file(tmp_path):
    root = tmp_path / "checkout"
    _stage_env_examples(root)
    dest = tmp_path / "secsite.toml"
    answers = [
        "sec.internal", "1.1.1.1", "single-host",
        "local", "macos", "127.0.0.1", "", "",
        "",                          # without
        "", "y", "",                 # with_inference, with_agent (-> True), configure_resolver
        "", "", "", "",              # tls, configure_hosts, trust_ca, model_dir
        "y",                         # set up operator secrets now? yes
        "n",                         # auto-generate internal secrets? no — type them (below)
        "ca-pass-mac", "admin-tok-mac",
        "sso-secret-mac", "bot-tok-mac",
        "hf-tok-mac",
        "",                          # FREEROUTER_CONFIG left blank -> skipped
    ]
    driver = _driver(answers)
    result = configure.run(
        _manifest(), dest=dest, root=root, input_fn=driver, out=lambda *_: None, getpass_fn=driver,
    )
    assert result == dest

    secrets_env = root / "deploy/macos/secrets.env"
    assert secrets_env.exists()
    assert stat.S_IMODE(secrets_env.stat().st_mode) == 0o600
    text = secrets_env.read_text()
    assert "SECCERT_CA_PASSPHRASE=ca-pass-mac" in text
    assert "SECCERT_ADMIN_TOKEN=admin-tok-mac" in text
    assert "SECAGENT_CLIENT_SECRET=sso-secret-mac" in text
    assert "SECAGENT_MATTERMOST__BOT_TOKEN=bot-tok-mac" in text
    assert "HF_TOKEN=hf-tok-mac" in text
    assert "FREEROUTER_CONFIG" not in text  # left blank -> never written at all
    assert "ca-pass-mac" not in dest.read_text()  # never in secsite.toml either
    # no per-component fedora-fips-style file for a macOS-only site
    assert not any((root / "deploy/fedora-fips").glob("*.env"))


def _env_val(text: str, key: str) -> str:
    line = next(ln for ln in text.splitlines() if ln.startswith(f"{key}="))
    return line.split("=", 1)[1]


def test_secret_seeding_autogenerates_internal_seccert_secrets(tmp_path):
    """Auto-generation (the default) mints strong SecCert secrets without asking — the operator
    never invents a CA passphrase — while external tokens (Hugging Face, Mattermost bot) and the
    shared SecAgent client secret are still asked. See _maybe_seed_secrets."""
    root = tmp_path / "checkout"
    _stage_env_examples(root)
    dest = tmp_path / "secsite.toml"
    answers = [
        "sec.internal", "1.1.1.1", "single-host",
        "local", "fedora-fips", "127.0.0.1", "", "",
        "",                    # without
        "", "y", "",           # with_inference, with_agent (-> True), configure_resolver
        "y",                   # set up operator secrets now? yes
        "y",                   # auto-generate internal secrets? yes (SecCert NOT asked below)
        "sso-secret-auto", "mm-bot-auto",   # SecAgent — still asked (shared/external)
        "hf-auto",                           # SecRecorder HF_TOKEN — still asked (external)
        "",                                  # SecRouter FREEROUTER_CONFIG — blank
    ]
    driver = _driver(answers)
    result = configure.run(
        _manifest(), dest=dest, root=root, input_fn=driver, out=lambda *_: None, getpass_fn=driver,
    )
    assert result == dest

    seccert_env = (root / "deploy/fedora-fips/seccert.env").read_text()
    passphrase = _env_val(seccert_env, "SECCERT_CA_PASSPHRASE")
    admin = _env_val(seccert_env, "SECCERT_ADMIN_TOKEN")
    # auto-generated: present, strong, distinct, and NOT any operator-typed answer
    assert len(passphrase) >= 32 and len(admin) >= 32
    assert passphrase != admin
    for typed in ("sso-secret-auto", "mm-bot-auto", "hf-auto"):
        assert typed not in (passphrase, admin)
    # the still-asked external/shared answers landed where they belong
    assert "SECAGENT_CLIENT_SECRET=sso-secret-auto" in (
        root / "deploy/fedora-fips/secagent.env").read_text()
    assert "HF_TOKEN=hf-auto" in (root / "deploy/fedora-fips/secrecorder.env").read_text()
    # no secret — generated or typed — is ever in secsite.toml
    assert "sso-secret-auto" not in dest.read_text()
    assert passphrase not in dest.read_text()


def test_declining_secrets_writes_no_env_file(tmp_path):
    root = tmp_path / "checkout"
    _stage_env_examples(root)
    dest = tmp_path / "secsite.toml"
    answers = [
        "sec.internal", "1.1.1.1", "single-host",
        "local", "fedora-fips", "127.0.0.1", "", "",
        "",              # without
        "", "", "",      # with_inference, with_agent, configure_resolver
        "N",             # set up operator secrets now? no
    ]
    result = configure.run(
        _manifest(), dest=dest, root=root, input_fn=_driver(answers), out=lambda *_: None,
    )
    assert result == dest
    assert not any((root / "deploy/fedora-fips").glob("*.env"))
    assert not (root / "deploy/macos/secrets.env").exists()


def test_secret_seeding_blank_values_writes_nothing(tmp_path):
    """Saying yes to seeding but leaving every value blank must still write no *.env file —
    blank always means "skip this value", not "write an empty one"."""
    root = tmp_path / "checkout"
    _stage_env_examples(root)
    dest = tmp_path / "secsite.toml"
    answers = [
        "sec.internal", "1.1.1.1", "single-host",
        "local", "fedora-fips", "127.0.0.1", "", "",
        "",              # without
        "", "", "",      # with_inference, with_agent, configure_resolver
        "y",             # set up operator secrets now? yes
        "n",             # auto-generate internal secrets? no — leave blank (below)
        "", "",          # SecCert — both blank
        "",              # SecRecorder HF_TOKEN — blank
        "",              # SecRouter FREEROUTER_CONFIG — blank
    ]
    driver = _driver(answers)
    result = configure.run(
        _manifest(), dest=dest, root=root, input_fn=driver, out=lambda *_: None, getpass_fn=driver,
    )
    assert result == dest
    assert not any((root / "deploy/fedora-fips").glob("*.env"))
