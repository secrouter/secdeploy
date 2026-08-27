"""Tests for `secdeploy evidence` — secdeploy.evidence. Faked HTTP: monkeypatch the one network
seam (`evidence._http_get`) rather than hitting a real socket, same "monkeypatch the small
wrapper function" style test_audit.py/test_cli.py use for subprocess calls (P.run)."""

from __future__ import annotations

import json
import urllib.error
from datetime import date, datetime, timezone
from pathlib import Path

from secdeploy import audit, evidence
from secdeploy.manifest import Manifest

ROOT = Path(__file__).resolve().parents[1]


# ── token resolution — --token / per-component env var, never in the output ────────────────
def test_resolve_token_prefers_component_env_var_over_cli_token(monkeypatch):
    monkeypatch.setenv("SECROUTER_ADMIN_TOKEN", "from-env")
    assert evidence.resolve_token("secrouter", "from-cli") == "from-env"


def test_resolve_token_falls_back_to_cli_token(monkeypatch):
    monkeypatch.delenv("SECCERT_ADMIN_TOKEN", raising=False)
    assert evidence.resolve_token("seccert", "from-cli") == "from-cli"


def test_resolve_token_none_when_neither_set(monkeypatch):
    monkeypatch.delenv("SECLLM_ADMIN_TOKEN", raising=False)
    assert evidence.resolve_token("secllm", None) is None


def test_token_env_var_naming():
    assert evidence.token_env_var("secrouter") == "SECROUTER_ADMIN_TOKEN"
    assert evidence.token_env_var("secchat") == "SECCHAT_ADMIN_TOKEN"


# ── fetch_one: never raises, tolerates absence, never leaks the token ──────────────────────
def test_fetch_one_ok(monkeypatch):
    body = json.dumps({"product": "SecRouter", "auditChain": {"ok": True}}).encode()
    monkeypatch.setattr(evidence, "_http_get", lambda url, token, timeout: (200, body))
    result = evidence.fetch_one("secrouter", "https://secrouter.sec.internal", token="secret-tok")
    assert result["status"] == "ok"
    assert result["evidence"]["product"] == "SecRouter"
    assert result["auth"] == "token"
    assert "secret-tok" not in json.dumps(result)


def test_fetch_one_no_token_sent(monkeypatch):
    monkeypatch.setattr(evidence, "_http_get", lambda url, token, timeout: (200, b"{}"))
    result = evidence.fetch_one("secrouter", "https://secrouter.sec.internal", token=None)
    assert result["auth"] == "none"


def test_fetch_one_404_is_skipped_not_fatal(monkeypatch):
    def raise_404(url, token, timeout):
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    monkeypatch.setattr(evidence, "_http_get", raise_404)
    result = evidence.fetch_one("seccert", "https://seccert.sec.internal", token=None)
    assert result["status"] == "skipped"
    assert "404" in result["note"]


def test_fetch_one_connection_refused_is_skipped(monkeypatch):
    def raise_refused(url, token, timeout):
        raise urllib.error.URLError("Connection refused")

    monkeypatch.setattr(evidence, "_http_get", raise_refused)
    result = evidence.fetch_one("secchat", "https://secchat.sec.internal", token=None)
    assert result["status"] == "skipped"
    assert "unreachable" in result["note"]


def test_fetch_one_auth_failure_is_error_not_skipped(monkeypatch):
    def raise_401(url, token, timeout):
        raise urllib.error.HTTPError(url, 401, "Unauthorized", None, None)

    monkeypatch.setattr(evidence, "_http_get", raise_401)
    result = evidence.fetch_one("secrouter", "https://secrouter.sec.internal", token="bad")
    assert result["status"] == "error"
    assert "401" in result["note"]
    assert "SECROUTER_ADMIN_TOKEN" in result["note"]
    assert "bad" not in json.dumps(result)


def test_fetch_one_non_json_body_is_error(monkeypatch):
    monkeypatch.setattr(evidence, "_http_get", lambda url, token, timeout: (200, b"not json"))
    result = evidence.fetch_one("secrecorder", "https://secrecorder.sec.internal", token=None)
    assert result["status"] == "error"
    assert "not valid JSON" in result["note"]


# ── collect: bundles per-component results + the local deploy-audit chain verify result ─────
def test_collect_writes_bundle_with_all_components_and_chain(tmp_path, monkeypatch):
    def fake_http_get(url, token, timeout):
        if "secrouter" in url:
            return 200, json.dumps({"ok": True}).encode()
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    monkeypatch.setattr(evidence, "_http_get", fake_http_get)
    urls = {"SECROUTER": "https://secrouter.sec.internal", "SECCERT": "https://seccert.sec.internal"}
    result = evidence.collect(urls, tmp_path, token="shared-tok", today=date(2026, 8, 27))

    assert result["path"] == tmp_path / "evidence" / "suite-evidence-2026-08-27.json"
    assert result["path"].exists()
    bundle = json.loads(result["path"].read_text())
    assert bundle["components"]["secrouter"]["status"] == "ok"
    assert bundle["components"]["seccert"]["status"] == "skipped"  # has a URL, 404s
    assert bundle["components"]["secllm"]["status"] == "not_in_topology"  # no URL at all
    assert bundle["deploy_audit_chain"] == {"ok": True, "checked": 0, "brokenAt": None, "targets": {}}
    assert "shared-tok" not in result["path"].read_text()


def test_collect_marks_components_not_in_topology(tmp_path):
    result = evidence.collect({}, tmp_path, today=date(2026, 8, 27))
    for name in evidence.COMPONENTS:
        assert result["components"][name]["status"] == "not_in_topology"


def test_collect_includes_real_audit_chain_verify_result(tmp_path):
    m = Manifest.load(ROOT / "suite.toml")
    audit.write_deploy_audit(
        m, None, None, tmp_path, target="macos", services=[], shas={},
        now=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    result = evidence.collect({}, tmp_path, today=date(2026, 8, 27))
    assert result["audit_chain"]["ok"] is True
    assert result["audit_chain"]["checked"] == 1
