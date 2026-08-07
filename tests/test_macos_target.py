"""Unit tests for macos.py's landing-page setup-checklist helper."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from secdeploy.targets import macos


def _actions(placed, home, **kwargs):
    defaults = {"trust_anchor_added": True, "resolver_configured": True}
    defaults.update(kwargs)
    return macos._secproxy_setup_actions(
        placed, Path("/nonexistent-root"), SimpleNamespace(domain="sec.internal"), **defaults,
    )


def test_pi_login_action_shown_when_secagent_placed_and_not_logged_in(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    actions = _actions({"secagent"}, tmp_path)
    assert any("secagent login" in a for a in actions)


def test_pi_login_action_absent_once_user_token_cached(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    token_file = tmp_path / ".secagent" / "auth" / "user-token.json"
    token_file.parent.mkdir(parents=True)
    token_file.write_text("{}")
    actions = _actions({"secagent"}, tmp_path)
    assert not any("secagent login" in a for a in actions)


def test_pi_login_action_absent_when_secagent_not_placed(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    actions = _actions(set(), tmp_path)
    assert not any("secagent login" in a for a in actions)
