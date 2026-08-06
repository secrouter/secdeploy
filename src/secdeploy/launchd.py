"""launchd (macOS) service management — the native-service runtime for the macOS target.

The macOS target runs SecDNS/SecLLM/SecAgent/SecRecorder natively (SecRecorder's MLX/Metal
backend and SecLLM's GPU access can't cross into Colima; SecDNS needs :53) and secproxy's nginx
too. This module turns each into a launchd service so ``deploy`` actually STARTS and SUPERVISES
it (``RunAtLoad`` + ``KeepAlive``) instead of only printing a run command — the direct fix for
"I deployed on a Mac but nothing is running / DNS doesn't resolve".

One convention, mirroring targets/fedora_fips.py's systemd side:

* every service is a LaunchDaemon under :data:`LAUNCHD_DIR` (system domain), labelled
  ``internal.secsuite.<name>`` — so discovery/teardown finds exactly the suite's own units and
  nothing else, the same way fedora-fips keys off its ``secsuite-<svc>`` unit/user names;
* privileged services (SecDNS :53, secproxy :443/:80) run as **root** — macOS has no per-port
  capability like Linux's ``CAP_NET_BIND_SERVICE``, so a sub-1024 bind needs root;
* the rest run as the **invoking user** (``UserName``), so ``uv``/its project venv/``$HOME``
  resolve exactly as they did when ``build`` created them — no root-owned-venv surprises.

Installing a LaunchDaemon writes a root-owned dir, so it needs sudo (the macOS deploy already
escalates for the resolver/keychain). :func:`plist_text` is pure + unit-tested; install/teardown
are thin ``launchctl bootstrap``/``bootout`` command lists the target runs (or prints on
``--dry-run``).
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path
from xml.sax.saxutils import escape

# System-domain LaunchDaemons live here; only root may write it (hence sudo on install/teardown).
LAUNCHD_DIR = Path("/Library/LaunchDaemons")
# Reverse-DNS label namespace for the suite's units — the discovery/teardown anchor (a glob on
# this prefix finds exactly the suite's plists). Not a real domain; never resolved.
LABEL_PREFIX = "internal.secsuite"


def label_for(name: str) -> str:
    return f"{LABEL_PREFIX}.{name}"


def plist_path_for(name: str) -> Path:
    return LAUNCHD_DIR / f"{label_for(name)}.plist"


@dataclass
class LaunchdService:
    """One native macOS service to run under launchd.

    ``program_args`` is the absolute argv; ``env`` becomes ``EnvironmentVariables``; ``user`` is
    the ``UserName`` to run as (``None`` = root, for the privileged :53/:443 binds). stdout/stderr
    are captured under ``log_dir`` so a crash-looping service leaves evidence instead of vanishing.
    """

    name: str
    program_args: list[str]
    log_dir: Path
    env: dict[str, str] = field(default_factory=dict)
    working_dir: str | None = None
    user: str | None = None          # None → runs as root (privileged ports)
    keepalive: bool = True

    @property
    def label(self) -> str:
        return label_for(self.name)

    @property
    def plist_path(self) -> Path:
        return plist_path_for(self.name)

    @property
    def stdout_path(self) -> Path:
        return self.log_dir / f"{self.name}.out.log"

    @property
    def stderr_path(self) -> Path:
        return self.log_dir / f"{self.name}.err.log"


def plist_text(svc: LaunchdService) -> str:
    """Render ``svc`` as a launchd property list (XML).

    Deterministic — ``EnvironmentVariables`` keys are sorted — so a redeploy that changes nothing
    produces byte-identical output (a diff is a real change). Only ``UserName`` is emitted for a
    user service; a root service (``user is None``) omits it so launchd runs it as root.
    """
    def _str(v: str) -> str:
        return f"<string>{escape(v)}</string>"

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
        '<plist version="1.0">',
        "<dict>",
        "\t<key>Label</key>",
        f"\t{_str(svc.label)}",
        "\t<key>ProgramArguments</key>",
        "\t<array>",
    ]
    lines += [f"\t\t{_str(a)}" for a in svc.program_args]
    lines.append("\t</array>")
    if svc.env:
        lines.append("\t<key>EnvironmentVariables</key>")
        lines.append("\t<dict>")
        for k in sorted(svc.env):
            lines.append(f"\t\t<key>{escape(k)}</key>")
            lines.append(f"\t\t{_str(svc.env[k])}")
        lines.append("\t</dict>")
    if svc.working_dir:
        lines += ["\t<key>WorkingDirectory</key>", f"\t{_str(svc.working_dir)}"]
    if svc.user:
        lines += ["\t<key>UserName</key>", f"\t{_str(svc.user)}"]
    lines += [
        "\t<key>RunAtLoad</key>",
        "\t<true/>",
        "\t<key>KeepAlive</key>",
        "\t<true/>" if svc.keepalive else "\t<false/>",
        "\t<key>StandardOutPath</key>",
        f"\t{_str(str(svc.stdout_path))}",
        "\t<key>StandardErrorPath</key>",
        f"\t{_str(str(svc.stderr_path))}",
        "</dict>",
        "</plist>",
    ]
    return "\n".join(lines) + "\n"


def staging_path(svc: LaunchdService, staging_dir: Path) -> Path:
    """Where the target writes ``svc``'s plist before ``sudo cp``-ing it into place — under the
    deploy's own ``out/`` (no privilege needed to stage), distinct from the root-owned
    :attr:`LaunchdService.plist_path` install target."""
    return Path(staging_dir) / f"{svc.label}.plist"


def install_command(svc: LaunchdService, staging_dir: Path) -> tuple[list[str], str]:
    """The single ``sudo`` command that installs + (re)starts ``svc``: copy the staged plist into
    the root-owned :data:`LAUNCHD_DIR`, fix ownership/mode (launchd refuses a non-root-owned
    daemon plist), ``bootout`` any prior instance (best-effort — none on a first deploy), then
    ``bootstrap`` it into the system domain (which starts it, via ``RunAtLoad``). Bundled into one
    ``sudo bash -c`` so a whole deploy needs the operator's password at most once (macOS caches
    it), same as the resolver/keychain steps around it.
    """
    stage = shlex.quote(str(staging_path(svc, staging_dir)))
    dest = shlex.quote(str(svc.plist_path))
    out_log = shlex.quote(str(svc.stdout_path))
    err_log = shlex.quote(str(svc.stderr_path))
    owner = shlex.quote(svc.user or "root")
    script = (
        f"cp {stage} {dest} && chown root:wheel {dest} && chmod 644 {dest} && "
        # launchd opens StandardOut/ErrorPath AS THE JOB'S USER, so a log left owned by a prior
        # run as a DIFFERENT user (e.g. SecDNS moving from a root :53 daemon to a user high-port
        # one) makes the open fail and the whole spawn abort with EX_CONFIG (78) — before the
        # program runs a line. Make sure the logs exist and are owned by this service's user.
        f"touch {out_log} {err_log} && chown {owner} {out_log} {err_log} && "
        f"{{ launchctl bootout system {dest} 2>/dev/null || true; }} && "
        f"launchctl bootstrap system {dest}"
    )
    return (["sudo", "bash", "-c", script],
            f"install + start launchd service {svc.label} (runs as {svc.user or 'root'})")


def discovered_plists(launchd_dir: Path = LAUNCHD_DIR) -> list[Path]:
    """Every installed suite plist (``internal.secsuite.*.plist``) under ``launchd_dir`` — the
    teardown discovery anchor. Empty if the dir is absent. Probe-driven, exactly like the rest of
    macOS teardown: it lists what's actually installed, never what a topology says should be."""
    d = Path(launchd_dir)
    return sorted(d.glob(f"{LABEL_PREFIX}.*.plist")) if d.is_dir() else []


def teardown_commands(plist: Path) -> list[tuple[list[str], str]]:
    """Reverse :func:`install_command` for one installed ``plist``: ``bootout`` (stops + unloads;
    best-effort — it may already be stopped) then remove the plist. Both need sudo (system-domain
    daemon in the root-owned dir)."""
    label = plist.stem  # internal.secsuite.<name>
    return [
        (["sudo", "bash", "-c",
          f"launchctl bootout system {shlex.quote(str(plist))} 2>/dev/null || true"],
         f"stop + unload launchd service {label}"),
        (["sudo", "rm", "-f", str(plist)], f"remove launchd plist {plist}"),
    ]
