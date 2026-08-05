"""launchd plist generation + install/teardown command builders (macOS native services).

Pure-function coverage — no launchctl/sudo needed. The generated plist is validated as
well-formed XML via the stdlib parser (macOS's own `plutil -lint` accepts it too, but that's
not portable to CI); install/teardown are asserted structurally.
"""

from __future__ import annotations

from pathlib import Path
from xml.dom.minidom import parseString

from secdeploy import launchd


def _svc(**kw) -> launchd.LaunchdService:
    base = dict(name="secdns", program_args=["/uv", "run", "serve"], log_dir=Path("/x/out/logs"))
    base.update(kw)
    return launchd.LaunchdService(**base)


# ── labels / paths ────────────────────────────────────────────────────────────────────────
def test_label_and_paths():
    svc = _svc(name="secproxy")
    assert svc.label == "internal.secsuite.secproxy"
    assert svc.plist_path == Path("/Library/LaunchDaemons/internal.secsuite.secproxy.plist")
    assert svc.stdout_path == Path("/x/out/logs/secproxy.out.log")
    assert svc.stderr_path == Path("/x/out/logs/secproxy.err.log")
    assert launchd.label_for("secdns") == "internal.secsuite.secdns"


# ── plist_text ────────────────────────────────────────────────────────────────────────────
def test_plist_is_well_formed_xml_with_core_keys():
    xml = launchd.plist_text(_svc(env={"B": "2", "A": "1"}, working_dir="/x", user=None))
    parseString(xml)  # raises if malformed
    assert "<key>Label</key>" in xml
    assert "<key>RunAtLoad</key>\n\t<true/>" in xml
    assert "<key>KeepAlive</key>\n\t<true/>" in xml
    assert "<string>/x/out/logs/secdns.out.log</string>" in xml
    assert "<key>WorkingDirectory</key>\n\t<string>/x</string>" in xml
    # EnvironmentVariables emitted in SORTED key order → deterministic output
    assert xml.index("<key>A</key>") < xml.index("<key>B</key>")


def test_root_service_omits_username_user_service_includes_it():
    assert "<key>UserName</key>" not in launchd.plist_text(_svc(user=None))
    user_xml = launchd.plist_text(_svc(user="probe"))
    assert "<key>UserName</key>\n\t<string>probe</string>" in user_xml


def test_program_arguments_preserve_order():
    args = ["/uv", "run", "--no-sync", "secdns", "serve"]
    xml = launchd.plist_text(_svc(program_args=args))
    positions = [xml.index(f"<string>{a}</string>") for a in args]
    assert positions == sorted(positions)


def test_plist_xml_escapes_special_chars():
    xml = launchd.plist_text(_svc(env={"Z": "a & b < c > d"}))
    assert "a &amp; b &lt; c &gt; d" in xml
    parseString(xml)  # still well-formed after escaping


def test_keepalive_false_emits_false():
    assert "<key>KeepAlive</key>\n\t<false/>" in launchd.plist_text(_svc(keepalive=False))


def test_plist_is_deterministic():
    svc = _svc(env={"A": "1", "B": "2"}, user="probe", working_dir="/x")
    assert launchd.plist_text(svc) == launchd.plist_text(svc)  # byte-identical


# ── install command ───────────────────────────────────────────────────────────────────────
def test_install_command_copies_fixes_ownership_and_bootstraps(tmp_path):
    svc = _svc(name="secdns")
    cmd, desc = launchd.install_command(svc, tmp_path)
    assert cmd[:3] == ["sudo", "bash", "-c"]
    script = cmd[3]
    assert str(launchd.staging_path(svc, tmp_path)) in script
    assert str(svc.plist_path) in script
    assert "chown root:wheel" in script
    assert "chmod 644" in script
    # bootout (best-effort) BEFORE bootstrap — reload-safe
    assert script.index("launchctl bootout system") < script.index("launchctl bootstrap system")
    assert "internal.secsuite.secdns" in desc


def test_staging_path_under_staging_dir(tmp_path):
    assert launchd.staging_path(_svc(name="secllm"), tmp_path) == \
        tmp_path / "internal.secsuite.secllm.plist"


# ── discovery / teardown ──────────────────────────────────────────────────────────────────
def test_discovered_plists_globs_only_suite_plists(tmp_path):
    for n in ("internal.secsuite.secdns.plist", "internal.secsuite.secproxy.plist",
              "com.apple.something.plist", "notaplist.txt"):
        (tmp_path / n).write_text("x")
    names = [p.name for p in launchd.discovered_plists(tmp_path)]
    assert names == ["internal.secsuite.secdns.plist", "internal.secsuite.secproxy.plist"]


def test_discovered_plists_missing_dir_is_empty(tmp_path):
    assert launchd.discovered_plists(tmp_path / "nope") == []


def test_teardown_commands_bootout_then_rm(tmp_path):
    plist = tmp_path / "internal.secsuite.secproxy.plist"
    (bootout_cmd, bootout_desc), (rm_cmd, _rm_desc) = launchd.teardown_commands(plist)
    assert bootout_cmd[:3] == ["sudo", "bash", "-c"] and "bootout system" in bootout_cmd[3]
    assert rm_cmd == ["sudo", "rm", "-f", str(plist)]
    assert "internal.secsuite.secproxy" in bootout_desc
