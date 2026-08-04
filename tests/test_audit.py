"""Tests for deploy audit artifacts (CMMC audit evidence) — secdeploy.audit."""

from __future__ import annotations

import json
import os as os_module
from datetime import datetime, timezone
from pathlib import Path

from secdeploy import audit, wiring
from secdeploy.manifest import Manifest
from secdeploy.topology import Topology

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "suite.toml"

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

# inference spread across TWO fedora-fips resources — the 2-instance SecLLM pool case.
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

FIXED_NOW = datetime(2026, 8, 3, 12, 0, 0, tzinfo=timezone.utc)


def _manifest() -> Manifest:
    return Manifest.load(MANIFEST)


def _topo(tmp_path, text: str) -> Topology:
    p = tmp_path / "topology.toml"
    p.write_text(text)
    return Topology.load(p, _manifest())


# ── write_deploy_audit: single (1-instance) inference topology ─────────────────────────
def test_write_deploy_audit_single_instance_has_expected_keys(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    shas = {"secrouter": "a" * 40, "seccert": "b" * 40}

    json_path = audit.write_deploy_audit(
        m, topo, "core", out,
        target="fedora-fips",
        services=["seccert", "secrouter", "secrecorder"],
        shas=shas,
        stacks=["secsso", "secchat"],
        flags={"with_inference": False, "tls": False, "trust_ca": False,
               "configure_resolver": False, "without": []},
        addressing={"zone": out / "addressing" / "secdns.zone", "env": {}},
        trust_anchor_added=True,
        resolver_configured=False,
        now=FIXED_NOW,
    )

    assert json_path == out / "audit" / "deploy-fedora-fips-core.json"
    assert json_path.exists()
    txt_path = json_path.with_suffix(".txt")
    assert txt_path.exists()

    record = json.loads(json_path.read_text())
    assert record["schema_version"] == 1
    assert record["generated_at"] == FIXED_NOW.isoformat()
    assert record["suite"] == {"version": m.suite, "released": m.released}
    assert record["target"] == "fedora-fips"
    assert record["resource"] == {"name": "core", "address": "10.0.0.5"}

    names = {c["name"] for c in record["components"]}
    assert names == {"seccert", "secrouter", "secrecorder", "secsso", "secchat"}
    secrouter = next(c for c in record["components"] if c["name"] == "secrouter")
    assert secrouter["ref"] == m.components["secrouter"].ref
    assert secrouter["sha"] == shas["secrouter"]
    assert secrouter["kind"] == "service"
    secsso = next(c for c in record["components"] if c["name"] == "secsso")
    assert secsso["kind"] == "stack"
    assert secsso["sha"] is None  # not in `shas` — recorded as unresolved, not dropped

    # single-instance inference → secrouter's pool is the one plain secllm URL
    assert record["addressing"]["secrouter_secllm_backend_pool"] == [
        "https://secllm.sec.internal:11400/v1"
    ]
    assert record["addressing"]["secdns_zone"]["record_count"] == len(topo.zone())
    assert record["addressing"]["secdns_zone"]["path"] == str(out / "addressing" / "secdns.zone")

    auth = record["authorizations"]
    assert auth["seccert_trust_anchor_added"] is True
    assert auth["resolver_pointed_at_secdns"] is False
    assert auth["egress"]["secllm_backend_pool_hosts"] == ["secllm.sec.internal:11400"]
    assert "CUI" in auth["egress"]["note"]

    assert record["flags"]["with_inference"] is False
    assert record["flags"]["without"] == []


# ── write_deploy_audit: 2-instance inference topology → pool captured ──────────────────
def test_write_deploy_audit_multi_instance_pool_captured(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, MULTI_INFERENCE)
    out = tmp_path / "out"

    json_path = audit.write_deploy_audit(
        m, topo, "core", out,
        target="fedora-fips",
        services=["seccert", "secrouter", "secdns"],
        shas={"secllm": "c" * 40},
        stacks=[],
        flags={"with_inference": True, "tls": False, "trust_ca": False,
               "configure_resolver": True, "without": []},
        addressing={"zone": out / "addressing" / "secdns.zone", "env": {}},
        trust_anchor_added=True,
        resolver_configured=True,
        now=FIXED_NOW,
    )

    record = json.loads(json_path.read_text())
    pool = record["addressing"]["secrouter_secllm_backend_pool"]
    assert pool == wiring.secllm_endpoints(topo) == [
        "https://secllm-gpu1.sec.internal:11400/v1",
        "https://secllm-gpu2.sec.internal:11400/v1",
    ]
    hosts = record["authorizations"]["egress"]["secllm_backend_pool_hosts"]
    assert hosts == ["secllm-gpu1.sec.internal:11400", "secllm-gpu2.sec.internal:11400"]
    assert record["authorizations"]["resolver_pointed_at_secdns"] is True
    assert record["flags"]["configure_resolver"] is True


def test_write_deploy_audit_pool_omitted_when_secrouter_not_here(tmp_path):
    # gpu1 hosts only secllm — no secrouter here, so no pool/egress is recorded, even though
    # the pool exists elsewhere in the topology.
    m = _manifest()
    topo = _topo(tmp_path, MULTI_INFERENCE)
    out = tmp_path / "out"

    json_path = audit.write_deploy_audit(
        m, topo, "gpu1", out,
        target="fedora-fips",
        services=["secllm"],
        shas={},
        addressing=None,  # no addressing artifacts written on this call
        now=FIXED_NOW,
    )

    record = json.loads(json_path.read_text())
    assert record["addressing"]["secrouter_secllm_backend_pool"] == []
    assert record["authorizations"]["egress"]["secllm_backend_pool_hosts"] == []
    assert "no SecLLM backend pool" in record["authorizations"]["egress"]["note"]
    # addressing=None → path unknown, but the record count is still derivable from the topology
    assert record["addressing"]["secdns_zone"]["path"] is None
    assert record["addressing"]["secdns_zone"]["record_count"] == len(topo.zone())
    assert record["resource"] == {"name": "gpu1", "address": "10.0.0.6"}


# ── single-host mode (no topology.toml) ─────────────────────────────────────────────────
def test_write_deploy_audit_single_host_mode_no_topology(tmp_path):
    m = _manifest()
    out = tmp_path / "out"

    json_path = audit.write_deploy_audit(
        m, None, None, out,
        target="macos",
        services=["seccert", "secrouter", "secrecorder"],
        shas={},
        now=FIXED_NOW,
    )

    assert json_path == out / "audit" / "deploy-macos-local.json"
    record = json.loads(json_path.read_text())
    assert record["resource"] == {"name": "local", "address": "127.0.0.1"}
    assert record["addressing"]["secdns_zone"] == {"path": None, "record_count": 0}
    assert record["addressing"]["secrouter_secllm_backend_pool"] == []
    assert "single-host mode" in record["addressing"]["note"]
    assert record["authorizations"]["egress"]["secllm_backend_pool_hosts"] == []


# ── SecRouter egress artifact + shared SecLLM token: audit reflects, never leaks ────────
def test_write_deploy_audit_points_egress_section_at_generated_file(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    # Use the REAL wiring.write_addressing() output (not a fabricated dict), same as a target
    # would pass in — this is what actually produces the "egress" key being asserted on.
    addressing = wiring.write_addressing(topo, out / "addressing", "core")

    json_path = audit.write_deploy_audit(
        m, topo, "core", out, target="fedora-fips",
        services=["seccert", "secrouter"], shas={},
        addressing=addressing, secllm_auth_enabled=True, now=FIXED_NOW,
    )
    record = json.loads(json_path.read_text())
    egress = record["authorizations"]["egress"]
    assert egress["rules_file"] == str(addressing["egress"])
    assert Path(egress["rules_file"]).exists()
    assert egress["secllm_backend_pool_hosts"] == ["secllm.sec.internal:11400"]
    # single source of truth: the audit's host list matches the generated file's content exactly
    generated_rules = json.loads(Path(egress["rules_file"]).read_text())
    assert generated_rules[0]["allowedHost"] == egress["secllm_backend_pool_hosts"]


def test_write_deploy_audit_egress_rules_file_absent_without_addressing(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    json_path = audit.write_deploy_audit(
        m, topo, "core", out, target="fedora-fips",
        services=["secrouter"], shas={}, addressing=None, now=FIXED_NOW,
    )
    record = json.loads(json_path.read_text())
    assert record["authorizations"]["egress"]["rules_file"] is None


def test_write_deploy_audit_secllm_auth_enabled_true(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    json_path = audit.write_deploy_audit(
        m, topo, "core", out, target="fedora-fips",
        services=["secrouter"], shas={}, secllm_auth_enabled=True, now=FIXED_NOW,
    )
    record = json.loads(json_path.read_text())
    assert record["authorizations"]["secllm_inference_auth_enabled"] is True


def test_write_deploy_audit_secllm_auth_enabled_false_by_default(tmp_path):
    m = _manifest()
    out = tmp_path / "out"
    json_path = audit.write_deploy_audit(
        m, None, None, out, target="macos", services=[], shas={}, now=FIXED_NOW,
    )
    record = json.loads(json_path.read_text())
    assert record["authorizations"]["secllm_inference_auth_enabled"] is False


def test_write_deploy_audit_never_records_the_token_value(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    # Generate the actual shared token exactly as a target would, into the SAME addressing dir.
    addressing = wiring.write_addressing(topo, out / "addressing", "core")
    token = wiring.secllm_shared_token(out / "addressing")
    assert token  # sanity: a real secret value exists on disk for this deploy

    json_path = audit.write_deploy_audit(
        m, topo, "core", out, target="fedora-fips",
        services=["secrouter"], shas={},
        addressing=addressing, secllm_auth_enabled=True, now=FIXED_NOW,
    )
    raw = json_path.read_text()
    assert token not in raw
    txt_raw = json_path.with_suffix(".txt").read_text()
    assert token not in txt_raw
    # write_deploy_audit's own signature has no parameter that could even carry a raw token —
    # only the boolean secllm_auth_enabled — so this isn't just "happened not to leak this time"
    import inspect
    assert "token" not in inspect.signature(audit.write_deploy_audit).parameters


def test_write_deploy_audit_txt_shows_auth_enabled_not_secret(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    json_path = audit.write_deploy_audit(
        m, topo, "core", out, target="fedora-fips",
        services=["secrouter"], shas={}, secllm_auth_enabled=True, now=FIXED_NOW,
    )
    txt = json_path.with_suffix(".txt").read_text()
    assert "secllm inference auth enabled:    yes" in txt
    assert "value never recorded here" in txt


# ── SecAgent chat-ops (--with-agent): audit reflects, never leaks ───────────────────────
def test_write_deploy_audit_secagent_fields_true_when_enabled(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    json_path = audit.write_deploy_audit(
        m, topo, "core", out, target="fedora-fips",
        services=["secrouter", "secagent"], shas={}, secagent_enabled=True, now=FIXED_NOW,
    )
    record = json.loads(json_path.read_text())
    auth = record["authorizations"]
    assert auth["secagent_chat_enabled"] is True
    assert auth["secagent_llm_at_secrouter"] is True
    assert auth["oidc_service_subject"] == "svc-secagent"


def test_write_deploy_audit_secagent_fields_false_by_default(tmp_path):
    m = _manifest()
    out = tmp_path / "out"
    json_path = audit.write_deploy_audit(
        m, None, None, out, target="macos", services=[], shas={}, now=FIXED_NOW,
    )
    record = json.loads(json_path.read_text())
    auth = record["authorizations"]
    assert auth["secagent_chat_enabled"] is False
    assert auth["secagent_llm_at_secrouter"] is False
    assert auth["oidc_service_subject"] is None


def test_write_deploy_audit_never_records_secagent_secrets(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    # Generate the REAL secrets a deploy would produce alongside this audit call, exactly as
    # a target does, and confirm none of them land in the artifact.
    addressing = wiring.write_addressing(topo, out / "addressing", "core")
    webhook_secret = wiring.secagent_webhook_secret(out / "addressing")
    fake_client_secret = "sso-client-secret-should-never-appear"
    fake_bot_token = "mm-bot-token-should-never-appear"

    json_path = audit.write_deploy_audit(
        m, topo, "core", out, target="fedora-fips",
        services=["secrouter", "secagent"], shas={},
        addressing=addressing, secagent_enabled=True, now=FIXED_NOW,
    )
    raw = json_path.read_text()
    txt_raw = json_path.with_suffix(".txt").read_text()
    for secret in (webhook_secret, fake_client_secret, fake_bot_token):
        assert secret not in raw
        assert secret not in txt_raw
    # write_deploy_audit's signature structurally cannot carry any of these — only the
    # boolean secagent_enabled — so this isn't just "happened not to leak this time".
    import inspect
    params = inspect.signature(audit.write_deploy_audit).parameters
    assert "secret" not in " ".join(params).lower()
    assert "token" not in " ".join(params).lower()


def test_write_deploy_audit_txt_shows_secagent_fields(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    json_path = audit.write_deploy_audit(
        m, topo, "core", out, target="fedora-fips",
        services=["secrouter", "secagent"], shas={}, secagent_enabled=True, now=FIXED_NOW,
    )
    txt = json_path.with_suffix(".txt").read_text()
    assert "SecAgent chat-ops enabled:         yes" in txt
    assert "SecAgent LLM routed via SecRouter: yes" in txt
    assert "OIDC service subject declared:     svc-secagent" in txt


# ── timestamp injection determinism ─────────────────────────────────────────────────────
def test_write_deploy_audit_now_is_injectable(tmp_path):
    m = _manifest()
    out = tmp_path / "out"
    json_path = audit.write_deploy_audit(
        m, None, None, out, target="macos", services=[], shas={}, now=FIXED_NOW,
    )
    record = json.loads(json_path.read_text())
    assert record["generated_at"] == "2026-08-03T12:00:00+00:00"


def test_write_deploy_audit_default_now_is_recent_utc(tmp_path):
    m = _manifest()
    out = tmp_path / "out"
    before = datetime.now(timezone.utc)
    json_path = audit.write_deploy_audit(m, None, None, out, target="macos", services=[], shas={})
    after = datetime.now(timezone.utc)
    record = json.loads(json_path.read_text())
    ts = datetime.fromisoformat(record["generated_at"])
    assert before <= ts <= after


# ── human-readable .txt summary ─────────────────────────────────────────────────────────
def test_write_deploy_audit_txt_is_human_readable(tmp_path):
    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)
    out = tmp_path / "out"
    json_path = audit.write_deploy_audit(
        m, topo, "core", out, target="fedora-fips",
        services=["secrouter"], shas={"secrouter": "deadbeef" * 5},
        trust_anchor_added=True, now=FIXED_NOW,
    )
    txt = json_path.with_suffix(".txt").read_text()
    assert "SecDeploy" in txt and "audit" in txt
    assert "secrouter" in txt
    assert "deadbeef" in txt
    assert "SecCert trust anchor added:       yes" in txt


# ── path-naming helpers shared with the --dry-run preview ──────────────────────────────
def test_audit_paths_naming():
    json_path, txt_path = audit.audit_paths("out", "fedora-fips", "gpu1")
    assert json_path == Path("out/audit/deploy-fedora-fips-gpu1.json")
    assert txt_path == Path("out/audit/deploy-fedora-fips-gpu1.txt")


def test_audit_paths_single_host_label():
    json_path, _ = audit.audit_paths("out", "macos", None)
    assert json_path == Path("out/audit/deploy-macos-local.json")


def test_dry_run_note_mentions_json_path_and_flags():
    note = audit.dry_run_note(
        "out", "fedora-fips", "core",
        component_count=3, trust_anchor=True, resolver=False,
    )
    assert "out/audit/deploy-fedora-fips-core.json" in note
    assert "3 component" in note
    assert "trust_anchor=yes" in note
    assert "resolver=no" in note


# ── integration: a real (non-dry-run) target deploy() writes the artifact ──────────────
# Both targets need real infra (Docker/Colima, or root on a FIPS Linux host) to actually
# deploy; these stub out the one thing that would fail in CI (subprocess execution / the
# root+Linux guard) to prove the *wiring* — that deploy() reaches write_deploy_audit with the
# right inputs — without needing that infra.
def test_macos_deploy_real_run_writes_audit(tmp_path, monkeypatch):
    from secdeploy import process as P
    from secdeploy.targets import macos

    monkeypatch.setattr(P, "run", lambda *a, **k: None)
    monkeypatch.setattr(macos, "_compose_cmd", lambda: ["docker", "compose"])

    m = _manifest()
    work, root, out = tmp_path / "work", tmp_path / "root", tmp_path / "out"
    work.mkdir()
    root.mkdir()

    macos.deploy(m, work, root, dry_run=False, out=out)

    audit_json = out / "audit" / "deploy-macos-local.json"
    assert audit_json.exists()
    record = json.loads(audit_json.read_text())
    assert record["resource"] == {"name": "local", "address": "127.0.0.1"}
    assert {"seccert", "secrouter", "secrecorder"} <= {c["name"] for c in record["components"]}
    assert record["authorizations"]["seccert_trust_anchor_added"] is False  # --trust-ca not passed


def test_fedora_deploy_real_run_writes_audit(tmp_path, monkeypatch):
    from secdeploy import process as P
    from secdeploy.targets import fedora_fips

    monkeypatch.setattr(P, "run", lambda *a, **k: None)
    monkeypatch.setattr(fedora_fips.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_module, "geteuid", lambda: 0)

    m = _manifest()
    work, root, out = tmp_path / "work", tmp_path / "root", tmp_path / "out"
    for svc in ("seccert", "secrouter", "secrecorder"):
        (work / svc).mkdir(parents=True)
    root.mkdir()

    fedora_fips.deploy(m, work, root, dry_run=False, out=out)

    audit_json = out / "audit" / "deploy-fedora-fips-local.json"
    assert audit_json.exists()
    record = json.loads(audit_json.read_text())
    assert record["resource"] == {"name": "local", "address": "127.0.0.1"}
    assert {"seccert", "secrouter", "secrecorder"} == {c["name"] for c in record["components"]}
    # seccert is in services on this (single-host) run → trust-anchor step ran
    assert record["authorizations"]["seccert_trust_anchor_added"] is True


def test_fedora_deploy_real_run_2instance_writes_egress_and_shared_token(tmp_path, monkeypatch):
    """End-to-end: a real deploy() on SecRouter's resource, against a 2-instance inference
    topology, actually produces the egress artifact + shared-token wiring (not just the
    wiring.py unit tests in isolation), actually RUNS the install step that layers it onto the
    live secrouter.env, and the audit reflects it without leaking the token."""
    from secdeploy import process as P
    from secdeploy.targets import fedora_fips

    run_calls: list[list[str]] = []
    monkeypatch.setattr(P, "run", lambda cmd, *a, **k: run_calls.append(cmd))
    monkeypatch.setattr(fedora_fips.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_module, "geteuid", lambda: 0)

    m = _manifest()
    topo = _topo(tmp_path, MULTI_INFERENCE)
    work, root, out = tmp_path / "work", tmp_path / "root", tmp_path / "out"
    # 'core' hosts identity + gateway + collab: secdns, seccert, secrouter, secrecorder
    # (services) plus secsso, secchat (stacks) — require_checkouts needs a dir for each.
    for name in ("secdns", "seccert", "secrouter", "secrecorder", "secsso", "secchat"):
        (work / name).mkdir(parents=True)
    root.mkdir()

    fedora_fips.deploy(m, work, root, dry_run=False, out=out, topology=topo, resource="core")

    addr_dir = out / "addressing"
    egress_json = addr_dir / "secrouter-egress.json"
    assert egress_json.exists()
    rules = json.loads(egress_json.read_text())
    assert rules == [{
        "provider": "secllm",
        "allowedHost": ["secllm-gpu1.sec.internal:11400", "secllm-gpu2.sec.internal:11400"],
        "authorizedClassifications": ["CUI"],
        "authorization": rules[0]["authorization"],
    }]

    secrouter_env_path = addr_dir / "env" / "secrouter.env"
    secrouter_env = secrouter_env_path.read_text()
    # fedora_fips.deploy() overrides SECROUTER_EGRESS_FILE to the real INSTALLED path
    # (/etc/secsuite/...), not the local staging path — that's the value SecRouter itself
    # would actually read on the deployed host.
    assert "SECROUTER_EGRESS_FILE=/etc/secsuite/secrouter-egress.json" in secrouter_env
    assert (
        "SECROUTER_SECLLM_ENDPOINTS=https://secllm-gpu1.sec.internal:11400/v1,"
        "https://secllm-gpu2.sec.internal:11400/v1"
    ) in secrouter_env
    token_line = next(
        ln for ln in secrouter_env.splitlines() if ln.startswith("SECROUTER_SECLLM_TOKEN=")
    )
    shared_token = token_line.split("=", 1)[1]
    assert shared_token

    # the install step that layers this onto the live service actually ran (not just that the
    # staging content was generated) — the exact command `deploy/fedora-fips/systemd/
    # secrouter.service`'s second EnvironmentFile= expects to have been populated by.
    addressing_install = [
        c for c in run_calls
        if c[:1] == ["install"] and c[-1] == "/etc/secsuite/secrouter-addressing.env"
    ]
    assert len(addressing_install) == 1
    assert addressing_install[0] == [
        "install", "-m", "640", str(secrouter_env_path), "/etc/secsuite/secrouter-addressing.env",
    ]

    audit_json_path = out / "audit" / "deploy-fedora-fips-core.json"
    audit_record = json.loads(audit_json_path.read_text())
    assert audit_record["authorizations"]["secllm_inference_auth_enabled"] is True
    assert audit_record["authorizations"]["egress"]["rules_file"] == str(egress_json)
    assert audit_record["authorizations"]["egress"]["secllm_backend_pool_hosts"] == [
        "secllm-gpu1.sec.internal:11400", "secllm-gpu2.sec.internal:11400",
    ]
    # the secret itself never appears in either audit artifact
    assert shared_token not in audit_json_path.read_text()
    assert shared_token not in audit_json_path.with_suffix(".txt").read_text()


def test_fedora_deploy_real_run_single_host_no_addressing_env_install(tmp_path, monkeypatch):
    """Single-host mode (no topology) must NOT install secrouter-addressing.env — there's no
    generated addressing at all in this mode, so the (optional, '-'-prefixed) EnvironmentFile=
    in secrouter.service simply has nothing to load, unchanged from before this feature."""
    from secdeploy import process as P
    from secdeploy.targets import fedora_fips

    run_calls: list[list[str]] = []
    monkeypatch.setattr(P, "run", lambda cmd, *a, **k: run_calls.append(cmd))
    monkeypatch.setattr(fedora_fips.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_module, "geteuid", lambda: 0)

    m = _manifest()
    work, root, out = tmp_path / "work", tmp_path / "root", tmp_path / "out"
    for svc in ("seccert", "secrouter", "secrecorder"):
        (work / svc).mkdir(parents=True)
    root.mkdir()

    fedora_fips.deploy(m, work, root, dry_run=False, out=out)

    assert not (out / "addressing").exists()
    assert not any(
        c[-1:] == ["/etc/secsuite/secrouter-addressing.env"] for c in run_calls
    )


def test_fedora_deploy_real_run_with_agent_stands_up_secagent_turnkey(tmp_path, monkeypatch):
    """End-to-end: a real deploy() with --with-agent on the collab resource actually produces
    the full SecAgent + Mattermost turnkey — the generated env, pi's models.json (from
    secagent's OWN checked-out example), the install steps (pi, addressing env, models.json),
    the SecRouter OIDC fragment — and the audit reflects it all without leaking any secret."""
    from secdeploy import process as P
    from secdeploy.targets import fedora_fips

    run_calls: list[list[str]] = []
    monkeypatch.setattr(P, "run", lambda cmd, *a, **k: run_calls.append(cmd))
    monkeypatch.setattr(fedora_fips.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_module, "geteuid", lambda: 0)

    m = _manifest()
    topo = _topo(tmp_path, GPU_SPLIT)  # 'core': identity (secsso) + gateway (secrouter) + collab (secagent, secchat)
    work, root, out = tmp_path / "work", tmp_path / "root", tmp_path / "out"
    for name in ("secdns", "seccert", "secrouter", "secagent", "secrecorder", "secsso", "secchat"):
        (work / name).mkdir(parents=True)
    root.mkdir()
    # A minimal but realistic pi/models.secrouter.example.json in the checkout — this is what
    # secdeploy reads + transforms, never something it hardcodes itself.
    pi_dir = work / "secagent" / "pi"
    pi_dir.mkdir(parents=True)
    (pi_dir / "models.secrouter.example.json").write_text(json.dumps({
        "_comment": ["KIMI GUARD: registers ONLY the secrouter provider"],
        "providers": {
            "secrouter": {
                "baseUrl": "https://secrouter.<domain>:47002/v1",
                "models": [{"id": "gemma-3-12b-it", "name": "Gemma 3 12B (SecRouter)"}],
            }
        },
    }))

    fedora_fips.deploy(m, work, root, dry_run=False, out=out, topology=topo, resource="core",
                       with_agent=True)

    addr_dir = out / "addressing"

    # Generated addressing env: full LLM/SecSSO/Mattermost wiring + webhook secret.
    secagent_env_path = addr_dir / "env" / "secagent.env"
    secagent_env = secagent_env_path.read_text()
    assert "SECAGENT_LLM__BASE_URL=https://secrouter.sec.internal:47002/v1" in secagent_env
    assert "SECAGENT_LLM__API_KEY=!secagent token" in secagent_env
    assert "SECAGENT_SECSSO__TOKEN_URL=https://secsso.sec.internal:9000/application/o/token/" \
        in secagent_env
    assert "SECAGENT_MATTERMOST__URL=https://secchat.sec.internal:8065" in secagent_env
    webhook_line = next(
        ln for ln in secagent_env.splitlines()
        if ln.startswith("SECAGENT_MATTERMOST__WEBHOOK_SECRET=")
    )
    webhook_secret = webhook_line.split("=", 1)[1]
    assert webhook_secret == wiring.secagent_webhook_secret(addr_dir)

    # pi's models.json: adapted from the REAL checked-out example.
    pi_models_path = addr_dir / "secagent-pi-models.json"
    pi_models = json.loads(pi_models_path.read_text())
    assert pi_models["providers"]["secrouter"]["baseUrl"] == "https://secrouter.sec.internal:47002/v1"
    assert pi_models["providers"]["secrouter"]["apiKey"] == "!secagent token"
    assert pi_models["providers"]["secrouter"]["models"] == \
        [{"id": "gemma-3-12b-it", "name": "Gemma 3 12B (SecRouter)"}]  # catalog passed through

    # SecRouter's OIDC config fragment.
    oidc_path = addr_dir / "secrouter-oidc.json"
    oidc = json.loads(oidc_path.read_text())
    assert oidc["serviceSubjects"] == ["svc-secagent"]
    assert oidc["issuer"] == "https://secsso.sec.internal:9000/"

    # The install steps actually ran (not just staging content generated).
    def _ran(*, cmd0: str, last: str) -> bool:
        return any(c[:1] == [cmd0] and c[-1:] == [last] for c in run_calls)

    assert any(c == ["npm", "install", "-g", "@earendil-works/pi-coding-agent"] for c in run_calls)
    assert _ran(cmd0="install", last="/etc/secsuite/secagent-addressing.env")
    assert any(c == ["install", "-m", "640", str(secagent_env_path),
                     "/etc/secsuite/secagent-addressing.env"] for c in run_calls)

    # The audit: booleans + declared subject, never a secret.
    audit_json_path = out / "audit" / "deploy-fedora-fips-core.json"
    audit_record = json.loads(audit_json_path.read_text())
    auth = audit_record["authorizations"]
    assert auth["secagent_chat_enabled"] is True
    assert auth["secagent_llm_at_secrouter"] is True
    assert auth["oidc_service_subject"] == "svc-secagent"
    raw_audit = audit_json_path.read_text() + audit_json_path.with_suffix(".txt").read_text()
    assert webhook_secret not in raw_audit
