"""macOS (Apple Silicon) target.

SecCert + SecRouter run as containers via Docker Compose (Colima). The native services —
SecDNS, SecLLM, SecAgent, SecRecorder (MLX/Metal — can't run in Docker on macOS) and
secproxy's nginx (:443/:80) — run **natively**, installed and supervised as **launchd
daemons** (see :mod:`secdeploy.launchd`) so a deploy actually starts and keeps them running
rather than printing a run command for the operator to paste. SecCert comes up first as the
internal CA; its root is exported so hosts/clients can trust the suite. SecDNS is installed
before the resolver is pointed at it (``--configure-resolver``), so ``<domain>`` names resolve
immediately instead of hitting a not-yet-started server. ``--no-native-services`` falls back to
printing the run commands (foreground, DIY).
"""

from __future__ import annotations

import getpass
import html
import os
import pwd
import re
import shutil
import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import common
from .. import audit
from .. import launchd
from .. import process as P
from .. import wiring
from ..manifest import Manifest

NAME = "macos"
KIND = "compose"
PLAN = [
    "Ensure Docker/Colima is running",
    "Build SecCert + SecRouter images from the pinned checkouts (tagged with the suite version)",
    "Bring up SecCert (internal CA) via Compose and wait for /health",
    "Export the SecCert root to ./out (trust anchor for the enclave)",
    "Bring up SecRouter via Compose",
    "Ensure ffmpeg is installed (SecRecorder transcoding — installs via brew if missing)",
    "(--configure-hosts) Map host.docker.internal to 127.0.0.1 in /etc/hosts (sudo, asks first)",
    "(--trust-ca) Trust the SecCert root in the System keychain (sudo, asks first)",
    "Install SecDNS as a launchd daemon (high port SECDNS_MACOS_PORT, as the user — :53 is "
    "Colima's) — BEFORE the resolver step",
    "(--configure-resolver) Point /etc/resolver/<domain> at the now-running SecDNS (sudo)",
    "(--with-inference) Install SecLLM as a launchd daemon (SECLLM_BACKEND=mlx — Apple's "
    "mlx-lm, real local inference — falling back to mock if mlx-lm isn't installed)",
    "(--with-agent) Install SecAgent's chat bridge as a launchd daemon (env layered from the "
    "generated addressing env + deploy/macos/secrets.env), then run `secagent init` to wire "
    "up pi + the secagent CLI for the deploying user (OAuth, not a stored secret)",
    "(--with-agent) Install the pinned LeanCTX binary + pi extension and wire pi for context "
    "compression (air-gapped: no update phone-home; best-effort — see secagent docs/leanctx.md)",
    "Install SecRecorder as a launchd daemon (native MLX/Metal; --tls issues a SecCert cert via "
    "certbot; HF_TOKEN/--model-dir layered in)",
    "Install secproxy (nginx :443/:80, root) as a launchd daemon — macOS-local conf + a "
    "SecCert-issued or self-signed cert",
    "(--no-native-services) Print the run commands instead of installing the launchd daemons",
]

IMAGES = ("seccert", "secrouter")  # secrecorder is native on macOS

# SecRecorder TLS (--tls): certbot's standalone HTTP-01 responder runs on the Mac itself;
# SecCert (in its container) reaches it via host.docker.internal, which Colima resolves to
# the host — see compose.yaml's SECCERT_HTTP01_PORT for the matching validation port.
CERT_HOST = "host.docker.internal"
HTTP01_PORT = 47080
SECRECORDER_PORT = 47003

# SecDNS listens on this HIGH port on macOS instead of the privileged :53. Colima's own VM manager
# (`limactl`) binds host :53, so a :53 SecDNS collides with it and crash-loops; and a high port
# also lets SecDNS run as the invoking user (no root). macOS's /etc/resolver/<domain> supports a
# `port` directive (resolver(5)), so the resolver is pointed at 127.0.0.1:<this> — see
# _configure_resolver + the secdns launchd unit in deploy(). fedora-fips keeps the standard :53
# (systemd, root, no Lima).
SECDNS_MACOS_PORT = 15353

# Pinned LeanCTX version (matches secagent's config.LEANCTX_VERSION) — the context-compression
# binary + pi extension the secagent standup installs + wires into pi. Air-gapped (no update
# phone-home); secagent's own-call compression daemon is a separate, deferred piece.
LEANCTX_VERSION = "3.9.17"


def _image(manifest: Manifest, name: str) -> str:
    return f"secrouter/{name}:{manifest.suite}"


def _compose(root: Path) -> Path:
    return root / "deploy/macos/compose.yaml"


def _seccert_override_path(root: Path) -> Path:
    return root / "out" / "seccert-compose.override.yaml"


def _write_seccert_extra_hosts(root: Path, topology, without: list[str] | None) -> Path:
    """Docker Compose override adding `extra_hosts` to seccert: every fronted FQDN (+ the bare
    domain) resolves, INSIDE the seccert container, to this Mac via Docker's `host-gateway`
    special value (the same address `host.docker.internal` resolves to — confirmed reachable
    from inside the container). Without this, certbot's HTTP-01 challenges for secproxy's SAN
    cert fail with 'Name or service not known': macOS's `/etc/resolver` only affects HOST
    processes, and Colima's `limactl` already holds host port 53, so pointing the container's
    DNS at a resolver on the standard port isn't an option either (see docs/macos.md). Written
    fresh on every deploy — the fronted set can change with topology.toml."""
    path = _seccert_override_path(root)
    names = [topology.domain] + [
        fqdn for fqdn, _addr, _port in wiring.fronted_instances(topology, without)
    ]
    lines = ["# Generated by secdeploy — do not edit; regenerated on every deploy.",
             "services:", "  seccert:", "    extra_hosts:"]
    lines += [f'      - "{name}:host-gateway"' for name in names]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
    return path


def _compose_files(root: Path) -> list[str]:
    """The ``-f`` flags for every ``docker compose`` invocation in this target: the base
    compose.yaml, plus the seccert extra_hosts override (see
    :func:`_write_seccert_extra_hosts`) IF one is already on disk — never written here (read-only,
    safe for ``--dry-run``/``status``/``teardown``, none of which have a topology of their own
    to regenerate it from); ``deploy`` writes/refreshes the file itself before using this."""
    files = ["-f", str(_compose(root))]
    override = _seccert_override_path(root)
    if override.exists():
        files += ["-f", str(override)]
    return files


def _compose_cmd() -> list[str]:
    """Prefer the `docker compose` plugin; fall back to standalone `docker-compose`."""
    import subprocess

    try:
        subprocess.run(["docker", "compose", "version"], capture_output=True, check=True)
        return ["docker", "compose"]
    except Exception:  # noqa: BLE001
        return ["docker-compose"] if P.which("docker-compose") else ["docker", "compose"]


def _ensure_ffmpeg() -> None:
    """SecRecorder needs ffmpeg on PATH (audio transcode for the MLX backend + the
    diarizer's WAV normalization); it degrades gracefully without it, but silently —
    so make sure it's actually there instead of finding out via a failed transcription."""
    if P.which("ffmpeg"):
        return
    if P.which("brew"):
        P.warn("ffmpeg not found — installing via brew (required for SecRecorder transcoding)")
        P.run(["brew", "install", "ffmpeg"], check=False)
        if not P.which("ffmpeg"):
            P.warn("ffmpeg install did not complete — SecRecorder transcoding will be degraded")
    else:
        P.warn("ffmpeg not found and brew is unavailable — install ffmpeg manually, "
               "or SecRecorder transcoding will be degraded")


def _ensure_certbot() -> None:
    """certbot is the ACME client used to get SecRecorder a cert from SecCert for --tls."""
    if P.which("certbot"):
        return
    if P.which("brew"):
        P.warn("certbot not found — installing via brew (required for --tls)")
        P.run(["brew", "install", "certbot"], check=False)
        if not P.which("certbot"):
            P.warn("certbot install did not complete — cannot issue a cert for SecRecorder")
    else:
        P.warn("certbot not found and brew is unavailable — install certbot manually for --tls")


def _ensure_nginx() -> None:
    """secproxy runs natively on macOS (see module docstring) — it needs the `nginx` binary on
    PATH. Same idiom as _ensure_certbot() above, and likewise only invoked when secproxy is
    actually being stood up (never during --dry-run — see its native-run note in deploy()). nginx
    is the reverse-proxy runtime on both targets now — fedora-fips uses the system OpenSSL
    (FIPS-validated in FIPS mode); macOS is a non-FIPS eval, so `brew install nginx` (whatever
    homebrew-core currently resolves to) is fine here."""
    if P.which("nginx"):
        return
    if P.which("brew"):
        P.warn("nginx not found — installing via brew (required for secproxy)")
        P.run(["brew", "install", "nginx"], check=False)
        if not P.which("nginx"):
            P.warn("nginx install did not complete — cannot run secproxy natively")
    else:
        P.warn("nginx not found and brew is unavailable — install nginx manually for secproxy "
               "(https://nginx.org/en/docs/install.html)")


def _wire_leanctx_for_pi(dry_run: bool = False) -> None:
    """Install the pinned LeanCTX binary + pi extension and wire them into pi on this box —
    context compression for the developer's pi (secagent v0.3.0 ships LeanCTX on by default; see
    its docs/leanctx.md). Best-effort + air-gapped: ``LEAN_CTX_NO_UPDATE_CHECK=1`` so it never
    phones home, and a missing ``npm`` just skips it (secagent degrades gracefully — ``secagent
    doctor`` reports whether LeanCTX is actually present).

    Scope note: this wires the pi-side compression only. secagent's OWN-CALL compression needs
    LeanCTX's persistent daemon, which it self-manages (its own LaunchAgents, incl. an
    auto-updater) — a separate, deliberately-deferred piece to verify live before enabling."""
    install = f"npm install -g lean-ctx-bin@{LEANCTX_VERSION} pi-lean-ctx@{LEANCTX_VERSION}"
    if dry_run:
        print(f"  · (--with-agent) LeanCTX: {install}, then LEAN_CTX_NO_UPDATE_CHECK=1 "
              "lean-ctx harden && lean-ctx init --agent pi (air-gapped; best-effort)")
        return
    if not P.which("npm"):
        P.warn(f"npm not found — skipping LeanCTX (context compression). Install it, then: {install} "
               "(see secagent docs/leanctx.md)")
        return
    P.log(f"installing LeanCTX (binary + pi extension, pinned {LEANCTX_VERSION})")
    P.run(["npm", "install", "-g", f"lean-ctx-bin@{LEANCTX_VERSION}",
           f"pi-lean-ctx@{LEANCTX_VERSION}"], check=False)
    if not P.which("lean-ctx"):
        P.warn("LeanCTX binary not on PATH after install — pi-side compression won't run yet "
               "(re-run once `lean-ctx` is installed; see secagent docs/leanctx.md)")
        return
    # Air-gapped: never phone home for updates. harden tightens the MCP/shell surface; init --agent
    # pi writes pi's LeanCTX config. Both best-effort — a failure here never aborts the deploy.
    env = {**_os_environ(), "LEAN_CTX_NO_UPDATE_CHECK": "1"}
    P.run(["lean-ctx", "harden"], check=False, env=env)
    P.run(["lean-ctx", "init", "--agent", "pi"], check=False, env=env)
    P.log("LeanCTX wired into pi (hardened, update-check disabled)")


def _configure_hosts(assume_yes: bool = False) -> None:
    """Map host.docker.internal to loopback on the Mac itself, so host-side clients (curl,
    browsers) can reach SecRecorder using the same hostname its SecCert cert was issued for —
    Docker/Colima only define that name inside containers, not on the host."""
    hosts = Path("/etc/hosts")
    if CERT_HOST in hosts.read_text():
        P.log(f"/etc/hosts already maps {CERT_HOST}")
        return
    if not P.confirm(f"Add '127.0.0.1 {CERT_HOST}' to /etc/hosts?", assume_yes):
        P.warn("skipped /etc/hosts — host-side clients can't use the --tls cert's hostname")
        return
    P.run(["sudo", "sh", "-c", f"echo '127.0.0.1 {CERT_HOST}' >> /etc/hosts"])


def _configure_resolver(domain: str, dns_ip: str, port: int = 53, assume_yes: bool = False) -> bool:
    """Point macOS at secdns for ``domain`` via /etc/resolver/<domain> — the multi-host
    replacement for the /etc/hosts ``host.docker.internal`` trick. macOS routes queries for a
    domain to the nameserver named in that file. When secdns listens on a non-standard ``port``
    (it does on macOS — :53 is taken by Colima's ``limactl``, see :data:`SECDNS_MACOS_PORT`), a
    ``port`` line is added — macOS's resolver(5) honours it, so the stub resolver dials
    ``dns_ip:port``. Returns whether the resolver was actually pointed at secdns (``False`` if the
    operator declined) — the deploy audit artifact (audit.py) records this as a security-relevant
    authorization."""
    path = f"/etc/resolver/{domain}"
    where = f"{dns_ip}:{port}" if port != 53 else dns_ip
    if not P.confirm(f"Point {domain} at secdns ({where}) via {path}?", assume_yes):
        P.warn(f"skipped resolver config — {domain} names won't resolve via secdns on this host")
        return False
    body = f"nameserver {dns_ip}\\n" + (f"port {port}\\n" if port != 53 else "")
    P.run(["sudo", "mkdir", "-p", "/etc/resolver"])
    P.run(["sudo", "sh", "-c", f"printf '{body}' > {path}"])
    P.log(f"{domain} → secdns {where} ({path})")
    return True


def _extract_cn(root_pem: Path) -> str | None:
    """The CN of the cert at ``root_pem`` (openssl x509 -noout -subject). Shared by
    :func:`_ca_already_trusted` (forward direction, during ``deploy --trust-ca``) and
    teardown's own keychain-removal discovery (below), so the two can never disagree on
    which CN they mean."""
    import subprocess

    subj = subprocess.run(
        ["openssl", "x509", "-in", str(root_pem), "-noout", "-subject"],
        capture_output=True, text=True, check=False,
    ).stdout
    m = re.search(r"CN\s*=\s*([^,/\n]+)", subj)
    return m.group(1).strip() if m else None


def _cn_trusted(cn: str) -> bool:
    import subprocess

    return subprocess.run(
        ["security", "find-certificate", "-c", cn, "/Library/Keychains/System.keychain"],
        capture_output=True, check=False,
    ).returncode == 0


def _ca_already_trusted(root_pem: Path) -> bool:
    cn = _extract_cn(root_pem)
    return cn is not None and _cn_trusted(cn)


def _cert_is_self_signed(fullchain: Path) -> bool:
    """Whether the cert at `fullchain` is self-signed (subject == issuer) — true for
    _secproxy_cert_macos's local fallback (the macOS container/host DNS boundary usually blocks
    certbot's cross-boundary ACME issuance, see _issue_secproxy_cert), false for a real
    SecCert-issued cert. This is what decides which trust action actually helps: --trust-ca
    (SecCert's root) does nothing for a self-signed leaf — it isn't signed by SecCert at all —
    which needs trusting directly instead (see _trust_secproxy_cert)."""
    import subprocess

    try:
        out = subprocess.run(
            ["openssl", "x509", "-in", str(fullchain), "-noout", "-subject", "-issuer"],
            capture_output=True, text=True, check=True,
        ).stdout
    except Exception:  # noqa: BLE001
        return False
    subj = next((line for line in out.splitlines() if line.startswith("subject=")), "")
    iss = next((line for line in out.splitlines() if line.startswith("issuer=")), "")
    return bool(subj) and subj.removeprefix("subject=") == iss.removeprefix("issuer=")


def _trust_secproxy_cert(fullchain: Path, assume_yes: bool = False) -> bool:
    """Trust secproxy's SELF-SIGNED cert directly in the System keychain. --trust-ca's SecCert
    root trust doesn't cover this cert at all (see _cert_is_self_signed) — this is the separate
    action that actually stops the browser/curl warning when certbot's cross-boundary ACME
    issuance didn't complete. _ca_already_trusted's CN-based find-certificate check works
    unchanged here — it just looks up whatever CN the given cert carries."""
    if _ca_already_trusted(fullchain):
        P.log("secproxy's self-signed cert already trusted in the System keychain")
        return True
    if not P.confirm(f"Trust secproxy's self-signed cert ({fullchain}) in the System keychain?", assume_yes):
        P.warn("skipped — browsers/clients will keep flagging fronted services as untrusted")
        return False
    P.run([
        "sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
        "-k", "/Library/Keychains/System.keychain", str(fullchain),
    ], check=False)
    return _ca_already_trusted(fullchain)


def _trust_ca_root(root: Path, assume_yes: bool = False) -> bool:
    """Add the SecCert root to the macOS System keychain as a trusted root, so browsers/curl
    stop flagging SecRecorder's SecCert-issued cert as untrusted. Same command docs/macos.md
    already documents for manual use — this just runs it for you, with consent. Returns whether
    the root ended up trusted (already-trusted counts) — the deploy audit artifact (audit.py)
    records this as a security-relevant authorization."""
    root_pem = root / "out/seccert-root.pem"
    if not root_pem.exists():
        P.warn(f"{root_pem} not found — deploy SecCert first (root export happens during deploy)")
        return False
    if _ca_already_trusted(root_pem):
        P.log("SecCert root already trusted in the System keychain")
        return True
    if not P.confirm(f"Trust the SecCert root ({root_pem}) in the System keychain?", assume_yes):
        P.warn("skipped CA trust — browsers/clients will flag SecRecorder's cert as untrusted")
        return False
    P.run([
        "sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
        "-k", "/Library/Keychains/System.keychain", str(root_pem),
    ])
    return True


def _read_hf_token(root: Path) -> str | None:
    """HF_TOKEN for the gated diarizer model, from deploy/macos/secrets.env (gitignored —
    copy from secrets.env.example and fill in). A --hf-token flag overrides this."""
    secrets = root / "deploy/macos/secrets.env"
    if not secrets.exists():
        return None
    for line in secrets.read_text().splitlines():
        line = line.strip()
        if line.startswith("HF_TOKEN=") and line[len("HF_TOKEN="):]:
            return line.split("=", 1)[1].strip()
    return None


def _model_env(root: Path, hf_token: str | None, model_dir: str | None) -> dict[str, str]:
    """Extra env vars layered onto the SecRecorder run command: HF_TOKEN (diarizer gated-model
    auth) and, for air-gapped hosts, WHISPER_MODEL/WHISPER_DIARIZE_MODEL pointed at manually
    pre-downloaded local model directories instead of Hugging Face repo IDs — see --model-dir
    in docs/macos.md for the expected layout and how to populate one on a connected host."""
    env: dict[str, str] = {}
    token = hf_token or _read_hf_token(root)
    if token:
        env["HF_TOKEN"] = token
    if model_dir:
        md = Path(model_dir)
        whisper_dir, diarizer_dir = md / "whisper", md / "diarizer"
        if whisper_dir.is_dir():
            env["WHISPER_MODEL"] = str(whisper_dir)
        else:
            P.warn(f"--model-dir given but {whisper_dir} not found — Whisper will use its default (network) model ID")
        if diarizer_dir.is_dir():
            env["WHISPER_DIARIZE_MODEL"] = str(diarizer_dir)
        else:
            P.warn(f"--model-dir given but {diarizer_dir} not found — diarizer will use its default (network) model ID")
    return env


def _env_prefix(env: dict[str, str]) -> str:
    return "".join(f"{k}={v} " for k, v in env.items())


def _tls_run_cmd(certfile: Path, keyfile: Path, extra_env: dict[str, str] | None = None) -> str:
    """The command to start SecRecorder with TLS. Bypasses run.sh (no --ssl-* flags there),
    so its prewarm defaults (WHISPER_PREWARM/WHISPER_PREWARM_DIARIZER=1) are set explicitly
    here too — otherwise the model loads lazily on the first real request instead of at
    startup, which can stall a request behind a slow/cold model download (max_concurrency=1
    means everything queues behind it)."""
    return (
        f"cd work/secrecorder && HOST=0.0.0.0 PORT={SECRECORDER_PORT} "
        "WHISPER_PREWARM=1 WHISPER_PREWARM_DIARIZER=1 "
        f"{_env_prefix(extra_env or {})}"
        f"uv run uvicorn server:app --host 0.0.0.0 --port {SECRECORDER_PORT} "
        f"--ssl-certfile {certfile} --ssl-keyfile {keyfile}"
    )


def _issue_secrecorder_cert(root: Path) -> tuple[Path, Path] | None:
    """Get SecRecorder an ACME cert from SecCert via certbot standalone. HTTP-01 crosses the
    container/host boundary through host.docker.internal (see module docstring). Idempotent —
    certbot no-ops if the existing cert at out/certbot isn't near expiry."""
    _ensure_certbot()
    if not P.which("certbot"):
        return None
    cb_root = root / "out/certbot"
    for d in ("config", "work", "logs"):
        (cb_root / d).mkdir(parents=True, exist_ok=True)
    P.run([
        "certbot", "certonly", "--standalone",
        "--non-interactive", "--agree-tos", "--register-unsafely-without-email",
        "--config-dir", str(cb_root / "config"),
        "--work-dir", str(cb_root / "work"),
        "--logs-dir", str(cb_root / "logs"),
        "--server", "http://localhost:47001/acme/directory",
        "--http-01-port", str(HTTP01_PORT),
        "--cert-name", "secrecorder",
        "-d", CERT_HOST,
    ], check=False)
    live = cb_root / "config/live/secrecorder"
    cert, key = live / "fullchain.pem", live / "privkey.pem"
    if cert.exists() and key.exists():
        return cert, key
    P.warn(f"certbot did not produce a certificate — check {cb_root}/logs/letsencrypt.log")
    return None


def _issue_secproxy_cert(
    root: Path, topology, without: list[str] | None = None
) -> tuple[Path, Path] | None:
    """Get secproxy ONE SAN ACME cert from SecCert via certbot standalone — covering every
    fronted FQDN (:func:`wiring.fronted_instances`, the SAME set the generated nginx conf serves)
    under a single ``--cert-name secproxy``. Mirrors :func:`_issue_secrecorder_cert`'s invocation
    (HTTP-01 crosses the container/host boundary through ``host.docker.internal`` on
    ``HTTP01_PORT`` — see the module docstring and ``compose.yaml``'s ``SECCERT_HTTP01_PORT``),
    just with N ``-d`` flags instead of one. Idempotent — certbot no-ops if the cert at
    ``out/certbot`` isn't near expiry. Empty when nothing is fronted.

    CROSS-BOUNDARY ACME CAVEAT (macOS eval only): SecCert (in its container) validates HTTP-01 by
    connecting to ``http://<fronted-fqdn>:47080``, so each fronted name must resolve INSIDE the
    container to this host — i.e. the container's resolver pointed at secdns. On a plain local
    eval that isn't set up, so issuance may not complete; a self-signed cert (or nginx's own
    ``ssl``) is a fine local fallback — see docs/macos.md. fedora-fips has no such boundary
    (native certbot on the host — see ``targets/fedora_fips._issue_secproxy_cert``).
    """
    _ensure_certbot()
    if not P.which("certbot"):
        return None
    fqdns = [fqdn for fqdn, _addr, _port in wiring.fronted_instances(topology, without)]
    if not fqdns:
        return None
    # The bare domain too — it's what wiring.nginx_conf_text's landing-page server block serves.
    fqdns = [topology.domain] + fqdns
    cb_root = root / "out/certbot"
    for d in ("config", "work", "logs"):
        (cb_root / d).mkdir(parents=True, exist_ok=True)
    d_flags: list[str] = []
    for f in fqdns:
        d_flags += ["-d", f]
    P.run([
        "certbot", "certonly", "--standalone",
        "--non-interactive", "--agree-tos", "--register-unsafely-without-email",
        "--config-dir", str(cb_root / "config"),
        "--work-dir", str(cb_root / "work"),
        "--logs-dir", str(cb_root / "logs"),
        "--server", "http://localhost:47001/acme/directory",
        "--http-01-port", str(HTTP01_PORT),
        "--cert-name", "secproxy",
        *d_flags,
    ], check=False)
    live = cb_root / "config/live/secproxy"
    cert, key = live / "fullchain.pem", live / "privkey.pem"
    if cert.exists() and key.exists():
        return cert, key
    P.warn(f"certbot did not produce a secproxy certificate — check {cb_root}/logs/letsencrypt.log "
           "(macOS eval: the fronted names must resolve to this host inside the SecCert "
           "container — see docs/macos.md; a self-signed cert is a fine local fallback)")
    return None


def build(manifest: Manifest, work: Path, out: Path, root: Path,
          without: list[str] | None = None) -> None:
    from .common import require_checkouts

    images = [i for i in IMAGES if i not in (without or [])]
    require_checkouts(manifest, work)
    if not P.which("docker"):
        P.die("docker (Colima) is required for the macOS target")
    out.mkdir(parents=True, exist_ok=True)
    for name in images:
        P.run(["docker", "build", "-t", _image(manifest, name), str(work / name)])
    _ensure_ffmpeg()
    # Native-service venvs — everything that runs via `uv run` under launchd (see deploy()):
    # SecRecorder (MLX/Metal), SecLLM (opt-in inference), secdns, secagent. Pre-syncing here means
    # the first service start is instant AND the deploy's `uv run --no-sync` never tries to build a
    # venv at start time — critical for secdns, which launchd runs as ROOT and must never sync into
    # the user-owned checkout. Respects --without; a component with no checkout/pyproject is
    # skipped (secllm/secagent aren't in every build).
    without = without or []
    # secagent's `chat serve` (the Mattermost bridge deployed here) needs fastapi/uvicorn, which
    # live behind the `review` extra (named for the UC100 review-webhook server that shares the
    # same optional dependency — see secagent/chat/webhook.py's module docstring). Without it,
    # secagent starts, imports the chat module, and crash-loops on ModuleNotFoundError.
    # secllm's `mlx` extra is Apple Silicon's real inference engine (mlx-lm) — vllm never
    # installs here (GPU/Linux only), so without this it's stuck on SECLLM_BACKEND=mock.
    extra_args = {"secagent": ["--extra", "review"], "secllm": ["--extra", "mlx"]}
    for name in ("secrecorder", "secllm", "secdns", "secagent"):
        if name in without:
            continue
        proj = work / name
        if P.which("uv") and (proj / "pyproject.toml").exists():
            P.run(["uv", "sync", "--project", str(proj), *extra_args.get(name, [])], check=False)
        elif not P.which("uv"):
            P.warn(f"uv not found — build {name}'s venv on the Mac before deploy "
                   f"(uv sync --project work/{name})")
    # pi (the agent runtime secagent's tools/skills plug into — see work/secagent/docs/pi.md) is
    # a global npm tool, not part of secagent's own checkout/venv. Optional: secagent's own
    # install.sh treats a missing npm the same way (installs everything else, warns, continues)
    # since pi is only needed for interactive use, never for secagent's own chat/review services.
    if "secagent" not in without:
        if P.which("npm"):
            P.run(["npm", "install", "-g", "@earendil-works/pi-coding-agent"], check=False)
        else:
            P.warn("npm not found — pi (the agent runtime secagent's tools/skills plug into) "
                   "won't be installed; install Node.js, then `npm install -g "
                   "@earendil-works/pi-coding-agent` yourself, or ignore this if you don't plan "
                   "to use pi interactively on this Mac")
    P.log(f"built images: {', '.join(_image(manifest, n) for n in images)}")


# ── native-service (launchd) helpers ─────────────────────────────────────────────────────────
# The macOS runtime for the suite's native services: rather than PRINT a run command and leave the
# operator to start (and re-start) each one by hand — the gap that left SecDNS down and `.internal`
# unresolvable after a deploy — deploy() installs each as a launchd daemon via these helpers (see
# launchd.py). Only secproxy (binds :443/:80) runs as root; the rest — including SecDNS, which uses
# the high SECDNS_MACOS_PORT rather than the privileged :53 (Colima's limactl holds :53) — run as
# the invoking user.


def _native_user() -> tuple[str, str]:
    """The user (and home dir) the user-run launchd services run as — the real invoking user even
    if the deploy was started under sudo (``SUDO_USER``), so ``uv``/its project venv/``$HOME``
    resolve exactly as they did when ``build`` created them. Only secproxy (:443/:80) runs as root
    (``LaunchdService.user is None``); SecDNS is a user service too (high port, not :53)."""
    user = os.environ.get("SUDO_USER") or getpass.getuser()
    try:
        home = pwd.getpwnam(user).pw_dir
    except KeyError:
        home = os.path.expanduser("~")
    return user, home


def _nginx_conf_user(user: str) -> str:
    """nginx's `user` directive is `user USERNAME [GROUP];` — omit GROUP and nginx uses USERNAME
    as the group too (`getgrnam(username)`), which fails on macOS: unlike Linux, macOS doesn't
    give every user a same-named private group (this user's real group is usually `staff`)."""
    try:
        import grp
        group = grp.getgrgid(pwd.getpwnam(user).pw_gid).gr_name
        return f"{user} {group}"
    except (KeyError, ImportError):
        return user


def _base_env(user_home: str | None = None) -> dict[str, str]:
    """The env every launchd service needs: the invoking user's ``PATH`` (so ``uv``/homebrew are
    found — launchd's own default is a bare ``/usr/bin:/bin:/usr/sbin:/sbin``) plus, for a user
    service, ``HOME``. A launchd job otherwise starts with almost no environment."""
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")}
    if user_home:
        env["HOME"] = user_home
    return env


def _parse_env_file(path: Path) -> dict[str, str]:
    """Parse a generated/seeded ``KEY=VALUE`` env file into a dict (comments/blanks skipped) — the
    launchd equivalent of systemd's ``EnvironmentFile=`` layering on fedora-fips, so SecAgent gets
    its addressing wiring + operator secrets as real process env instead of the old 'source it
    yourself' note (closing that documented macOS gap)."""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip()
    return env


def _venv_bin(root: Path, project: str, script: str) -> Path:
    """Absolute path to a console script inside a native service's project venv (created by
    ``build`` / ``uv sync``). The launchd daemon runs straight from here rather than through
    ``uv run``: a root-run service (SecDNS) then never invokes ``uv`` against the user-owned
    checkout, and no service depends on ``uv`` being resolvable in launchd's minimal environment
    (`uv run` in that context was the reported not-starting failure)."""
    return root / "work" / project / ".venv" / "bin" / script


def _secllm_backend(root: Path) -> str:
    """"mlx" if secllm's venv actually has mlx-lm installed (the real inference engine on Apple
    Silicon — see build()'s "secllm": ["--extra", "mlx"]), else "mock" with a warning — e.g. an
    Intel Mac, or a deploy that ran before a `build macos` synced the mlx extra."""
    python = _venv_bin(root, "secllm", "python3")
    if python.exists():
        r = P.run([str(python), "-c", "import mlx_lm"], check=False)
        if r.returncode == 0:
            return "mlx"
    P.warn("secllm: mlx-lm not installed (run `secdeploy build macos` to install it) — "
           "falling back to SECLLM_BACKEND=mock")
    return "mock"


def _ensure_native_venv(root: Path, name: str) -> bool:
    """Make sure ``work/<name>/.venv`` exists before installing a daemon that runs from it.
    ``build`` pre-syncs it, but a deploy that skipped ``build`` (or an older ``build`` that didn't
    cover this service) would otherwise install a daemon whose command can't start — the reported
    "installed but nothing is listening". Synced as the invoking user; returns whether a usable
    venv is present afterward."""
    proj = root / "work" / name
    if (proj / ".venv" / "bin").is_dir():
        return True
    if P.which("uv") and (proj / "pyproject.toml").exists():
        P.warn(f"{name}: project venv missing — building it now (uv sync --project work/{name})")
        P.run(["uv", "sync", "--project", str(proj)], check=False)
    return (proj / ".venv" / "bin").is_dir()


def _install_or_note(
    svc: launchd.LaunchdService, staging_dir: Path, *,
    native_services: bool, dry_run: bool, fallback_note: str,
) -> None:
    """Install ``svc`` as a launchd daemon — stage its plist under ``out/launchd``, then the single
    ``sudo`` bootstrap (:func:`launchd.install_command`) — or, on ``--dry-run`` / with
    ``--no-native-services``, just print/annotate what it would run. ``fallback_note`` is the exact
    'start it yourself' command, shown on the opt-out path so the operator always has the manual
    invocation behind every managed service."""
    if dry_run:
        print(f"  · launchd {svc.label} (as {svc.user or 'root'}): {' '.join(svc.program_args)}")
        return
    if not native_services:
        P.warn(f"--no-native-services: not installing {svc.label} — start it yourself: {fallback_note}")
        return
    staging_dir.mkdir(parents=True, exist_ok=True)
    svc.log_dir.mkdir(parents=True, exist_ok=True)
    launchd.staging_path(svc, staging_dir).write_text(launchd.plist_text(svc))
    cmd, desc = launchd.install_command(svc, staging_dir)
    P.log(desc)
    P.run(cmd, check=False)
    P.log(f"{svc.label}: launchd-managed (restarts on crash/boot); logs → {svc.stdout_path}")


def _secproxy_cert_macos(root: Path, cert_dir: Path, topology, without: list[str] | None) -> bool:
    """Put a usable cert at ``cert_dir/{fullchain,privkey}.pem`` for macOS secproxy, returning
    whether one is in place. Tries the SecCert SAN cert first (certbot — best-effort; the macOS
    container/host DNS boundary usually blocks its HTTP-01, see :func:`_issue_secproxy_cert`), and
    otherwise generates a locally SELF-SIGNED cert covering the fronted FQDNs — the 'fine local
    fallback' docs/macos.md documents, enough for nginx to terminate TLS for a local eval so the
    edge actually comes up instead of failing closed on a missing cert."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    fullchain, privkey = cert_dir / "fullchain.pem", cert_dir / "privkey.pem"
    issued = _issue_secproxy_cert(root, topology, without)
    if issued:
        shutil.copy(issued[0], fullchain)
        shutil.copy(issued[1], privkey)
        privkey.chmod(0o600)
        P.log(f"secproxy: installed SecCert SAN cert → {fullchain}")
        return True
    fqdns = [fqdn for fqdn, _addr, _port in wiring.fronted_instances(topology, without)]
    if not fqdns:
        P.warn("secproxy: nothing fronted in this topology — no cert generated")
        return False
    # The bare domain too — it's what wiring.nginx_conf_text's landing-page server block serves.
    fqdns = [topology.domain] + fqdns
    san = ",".join(f"DNS:{f}" for f in fqdns)
    P.warn("secproxy: SecCert SAN cert unavailable (macOS container/host DNS boundary) — "
           "generating a self-signed cert for the local eval (browsers will warn; fine locally)")
    P.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
           "-keyout", str(privkey), "-out", str(fullchain), "-days", "365",
           "-subj", f"/CN={fqdns[0]}", "-addext", f"subjectAltName={san}"], check=False)
    if privkey.exists():
        privkey.chmod(0o600)
    return fullchain.exists() and privkey.exists()


def deploy(
    manifest: Manifest,
    work: Path,
    root: Path,
    dry_run: bool = False,
    tls: bool = False,
    configure_hosts: bool = False,
    trust_ca: bool = False,
    assume_yes: bool = False,
    hf_token: str | None = None,
    model_dir: str | None = None,
    without: list[str] | None = None,
    configure_resolver: bool = False,
    topology=None,
    resource: str | None = None,
    out: Path | None = None,
    with_inference: bool = False,
    with_agent: bool = False,
    native_services: bool = True,
    autostart_models: list[str] | None = None,
    users=None,
) -> None:
    without = without or []
    users = users or []
    # Topology placement: only bring up the components placed on `resource` (single-host
    # synthesis places everything here, so this is a no-op without a topology.toml).
    placed = set(topology.components_on(resource, without)) if topology is not None else None

    def _here(name: str) -> bool:
        return placed is None or name in placed

    # Components on THIS resource this run — same secdns/secllm/secagent gating as
    # fedora_fips._include (secdns needs a topology; secllm/secagent additionally need
    # --with-inference/--with-agent). secproxy follows secdns's simpler rule exactly —
    # topology-only, no --with-* flag. Used for the deploy audit artifact (audit.py) — recorded
    # from PLACEMENT (what's part of this deploy), independent of whether native_services actually
    # installed the launchd unit (--no-native-services prints run commands instead), the same way
    # fedora-fips records placement regardless of what systemctl did.
    services = [
        n for n in ("secdns", "seccert", "secllm", "secrouter", "secagent", "secrecorder", "secproxy")
        if n not in without
        and (n != "secdns" or topology is not None)
        and (n != "secllm" or (topology is not None and with_inference))
        and (n != "secagent" or (topology is not None and with_agent))
        and (n != "secproxy" or topology is not None)
        and _here(n)
    ]

    if topology is not None and not dry_run:
        # So certbot's HTTP-01 challenges for secproxy's SAN cert can actually reach this host
        # from inside the seccert container — see _write_seccert_extra_hosts. Written before any
        # compose `up`, so seccert picks it up on first create (a redeploy after topology.toml
        # changes recreates the container — compose detects the config diff).
        _write_seccert_extra_hosts(root, topology, without)
    dc = ["docker", "compose"] if dry_run else _compose_cmd()
    compose_files = _compose_files(root)
    env = {"SECSUITE_VERSION": manifest.suite}
    steps = []
    if "seccert" not in without and _here("seccert"):
        steps += [
            (dc + compose_files + ["up", "-d", "seccert"], "start SecCert (CA)"),
            (["bash", "-c",
              "for i in $(seq 1 30); do curl -fsS http://localhost:47001/health >/dev/null && break; sleep 1; done"],
             "wait for SecCert /health"),
            (["bash", "-c", "curl -fsS http://localhost:47001/ca.crt -o out/seccert-root.pem && echo saved out/seccert-root.pem"],
             "export SecCert root trust anchor"),
        ]
    if _here("secrouter"):
        steps.append((dc + compose_files + ["up", "-d", "secrouter"], "start SecRouter"))
    P.log(f"deploy {NAME} — suite {manifest.suite} (SECSUITE_VERSION passed to compose)")
    written: dict[str, object] | None = None
    if topology is not None and not dry_run and out is not None:
        written = wiring.write_addressing(topology, Path(out) / "addressing", resource, without)
        P.log(f"addressing artifacts written → {written['zone']} (+ env/)")
    if dry_run and topology is not None:
        here = ", ".join(services) or "(none)"
        print(f"# topology: resource {resource!r} @ {topology.resources[resource].address} — "
              f"components here: {here}")
    for cmd, desc in steps:
        if dry_run:
            print(f"  · {desc}: {' '.join(cmd)}")
            continue
        P.run(cmd, env={**_os_environ(), **env})

    # ABSOLUTE — launchd resolves a relative WorkingDirectory/StandardOutPath/zone path
    # unpredictably (its cwd is /), so every path baked into a plist must be absolute. `root` is
    # already absolute (cli._root); resolve `out` (defaults to the relative "out") to match.
    base_out = (Path(out) if out is not None else root / "out").resolve()
    staging_dir = base_out / "launchd"
    log_dir = base_out / "logs"
    user, home = _native_user()

    # CA / host-trust setup — independent of any one service, needs the SecCert root the compose
    # steps exported. Pulled ahead of the native services so the trust anchor is in place before
    # secproxy/SecRecorder present their SecCert-issued certs.
    if dry_run:
        _print_ca_dry_run(configure_hosts, trust_ca)
    trust_anchor_added = False
    if not dry_run:
        if configure_hosts:
            _configure_hosts(assume_yes)
        trust_anchor_added = trust_ca and _trust_ca_root(root, assume_yes)

    # ── native services (launchd) ─────────────────────────────────────────────────────────────
    # Each is installed as a launchd daemon (RunAtLoad + KeepAlive) so the deploy actually STARTS
    # and supervises it — the fix for "I deployed but nothing is running / .internal won't resolve"
    # (--no-native-services / --dry-run print the run command instead). SecDNS is installed FIRST,
    # so the resolver step below points at a RUNNING server rather than a not-yet-started one.
    # SecDNS runs on the HIGH port SECDNS_MACOS_PORT (not :53 — Colima's limactl holds host :53) and
    # therefore as the invoking user, not root; the resolver below carries a matching `port` line.
    if topology is not None and _here("secdns"):
        zone = base_out / "addressing" / "secdns.zone"
        fallback = (f"SECDNS_DOMAIN={topology.domain} SECDNS_ZONE={zone} "
                    f"SECDNS_UPSTREAM={','.join(topology.upstream_dns)} "
                    f"SECDNS_PORT={SECDNS_MACOS_PORT} SECDNS_BIND=127.0.0.1 "
                    f"uv run --project work/secdns secdns serve")
        if not dry_run and native_services and not _ensure_native_venv(root, "secdns"):
            P.warn(f"secdns: no project venv — run `secdeploy build macos`, then start it: {fallback}")
        else:
            secdns = launchd.LaunchdService(
                name="secdns",
                program_args=[str(_venv_bin(root, "secdns", "secdns")), "serve"],
                log_dir=log_dir,
                env={**_base_env(home), "SECDNS_DOMAIN": topology.domain, "SECDNS_ZONE": str(zone),
                     "SECDNS_UPSTREAM": ",".join(topology.upstream_dns),
                     "SECDNS_PORT": str(SECDNS_MACOS_PORT), "SECDNS_BIND": "127.0.0.1",
                     "SECDNS_ADMIN_BIND": "127.0.0.1", "SECDNS_ADMIN_PORT": "47053"},
                working_dir=str(root),
                user=user,  # high port → no root needed (and :53 is Colima's anyway)
            )
            _install_or_note(secdns, staging_dir, native_services=native_services,
                             dry_run=dry_run, fallback_note=fallback)

    # Point this host's resolver at secdns — AFTER secdns is up (see above). On macOS secdns is on
    # SECDNS_MACOS_PORT, so the resolver entry carries a matching `port` line (resolver(5)).
    resolver_configured = False
    if configure_resolver and topology is not None:
        dns_ip = wiring.secdns_address_for(topology, resource, without)
        if dns_ip is None:
            if not dry_run:
                P.warn("--configure-resolver: secdns isn't placed in this topology — nothing to point at")
        elif dry_run:
            print(f"  · (--configure-resolver) point {topology.domain} at secdns "
                  f"{dns_ip}:{SECDNS_MACOS_PORT} via /etc/resolver/{topology.domain} (sudo, asks first)")
        else:
            if not native_services:
                P.warn(f"--no-native-services: {topology.domain} won't resolve until you start "
                       "secdns yourself (note above) — pointing the resolver at it regardless")
            resolver_configured = _configure_resolver(
                topology.domain, dns_ip, SECDNS_MACOS_PORT, assume_yes)

    # secllm — opt-in inference; real local inference via SECLLM_BACKEND=mlx (Apple's mlx-lm —
    # vllm never installs here, GPU/Linux only), falling back to mock if mlx-lm isn't actually
    # installed (see _secllm_backend). Runs as the user (high port).
    if with_inference and topology is not None and _here("secllm"):
        port = manifest.components["secllm"].port
        backend = _secllm_backend(root)
        fallback = (f"SECLLM_HOST=0.0.0.0 SECLLM_PORT={port} SECLLM_BACKEND={backend} "
                    f"uv run --project work/secllm secllm serve")
        if not dry_run and native_services and not _ensure_native_venv(root, "secllm"):
            P.warn(f"secllm: no project venv — run `secdeploy build macos`, then start it: {fallback}")
        else:
            # Cached (see wiring.secllm_admin_token) rather than left to secllm's own fallback —
            # unset, it mints a fresh one every process start and only logs it (secllm/config.py),
            # useless the moment it restarts. Not generated/written on --dry-run.
            admin_token = wiring.secllm_admin_token(root / "out") if not dry_run else "***"
            secllm = launchd.LaunchdService(
                name="secllm",
                program_args=[str(_venv_bin(root, "secllm", "secllm")), "serve"],
                log_dir=log_dir,
                env={**_base_env(home), "SECLLM_HOST": "0.0.0.0", "SECLLM_PORT": str(port),
                     "SECLLM_BACKEND": backend, "SECLLM_ADMIN_TOKEN": admin_token,
                     "SECLLM_AUTOSTART": ",".join(autostart_models or [])},
                working_dir=str(root), user=user,
            )
            _install_or_note(secllm, staging_dir, native_services=native_services,
                             dry_run=dry_run, fallback_note=fallback)
            if not dry_run and native_services:
                P.log("secllm admin token cached → out/secllm-admin-token (stable across restarts)")
                if autostart_models:
                    P.log(f"secllm autostart: {', '.join(autostart_models)} — downloaded (if not "
                          "already cached) and loaded the moment the service starts")

    # SecSSO's SECAGENT_SERVICE_CLIENT_SECRET (secsso/blueprints/secagent-service.yaml's
    # client_credentials provider) must exist BEFORE secagent's own block below can mirror it
    # into SECAGENT_CLIENT_SECRET — seed it here rather than waiting for the stacks bring-up
    # later in this function (too late for THIS deploy's secagent env), using the same
    # generate-if-blank pass deploy_stacks itself uses (so a fresh deploy's first run already
    # has the matching secret, not just a redeploy's second pass).
    if not dry_run and with_agent and placed and "secsso" in placed and "secsso" not in without:
        common.ensure_stack_secrets(work, ["secsso"])
        secrets_path = root / "deploy" / "macos" / "secrets.env"
        synced = wiring.sync_secagent_service_secret(work / "secsso" / ".env", secrets_path)
        if synced:
            P.log(f"secagent: SECAGENT_CLIENT_SECRET synced from SecSSO's generated service "
                  f"client secret → {secrets_path}")
        elif secrets_path.exists():
            current = _parse_env_file(secrets_path).get("SECAGENT_CLIENT_SECRET", "")
            provisioned = _parse_env_file(work / "secsso" / ".env").get(
                "SECAGENT_SERVICE_CLIENT_SECRET", "")
            if current and provisioned and current != provisioned:
                P.warn(f"secagent: {secrets_path}'s SECAGENT_CLIENT_SECRET doesn't match "
                       "SecSSO's provisioned secagent client secret — `secagent token` will "
                       "fail with invalid_client. Blank the line to auto-sync on the next "
                       "deploy, or set it to match work/secsso/.env's "
                       "SECAGENT_SERVICE_CLIENT_SECRET yourself.")

    # SecAssist (LibreChat stack) turnkey env: mirror SecSSO's two generated OIDC secrets and
    # write the topology-derived OIDC/gateway env into work/secassist/.env BEFORE the stacks
    # bring-up seeds it (same early-seed trick as the secagent mirror above — secsso deploys
    # last in the sorted stack order, too late otherwise). Needs SecSSO in the topology (an
    # external IdP means the operator supplies these). Single-host mode configures manually.
    if not dry_run and topology is not None and placed and "secassist" in placed \
            and "secassist" not in (without or []) and "secsso" in placed \
            and "secsso" not in (without or []):
        common.ensure_stack_secrets(work, ["secsso", "secassist"])
        written = wiring.sync_secassist_env(
            work / "secsso" / ".env", work / "secassist" / ".env", topology, without)
        if written:
            P.log(f"secassist: synced OIDC secrets + topology env → work/secassist/.env "
                  f"({len(written)} keys)")

    # Declared end-user accounts → SecSSO. Render work/secsso/blueprints/users.generated.yaml
    # (random initial passwords, forced reset on first login) BEFORE the stacks bring-up so
    # Authentik applies it on secsso's first boot. Print new credentials once, for distribution.
    if not dry_run and users and placed and "secsso" in placed and "secsso" not in without:
        users_bp = work / "secsso" / "blueprints" / "users.generated.yaml"
        new_creds = wiring.generate_secsso_users_blueprint(users, users_bp)
        if new_creds:
            P.log(f"secsso: provisioned {len(new_creds)} user(s) → {users_bp} "
                  "(each must reset their password on first login)")
            P.log("  ── initial credentials — distribute securely, one-time ──")
            for _uname, _pw in new_creds.items():
                P.log(f"      {_uname}: {_pw}")
        else:
            P.log(f"secsso: {len(users)} declared user(s) already provisioned (passwords unchanged)")

    # secagent — opt-in chat bridge, now with REAL env layering: the generated addressing env
    # (LLM/SecSSO/Mattermost wiring + webhook secret) + the SECAGENT_* operator secrets are folded
    # into the launchd job's EnvironmentVariables — the macOS equivalent of fedora's two
    # EnvironmentFile= layers, closing the old "source it yourself" eval gap. Runs as the user.
    if with_agent and topology is not None and _here("secagent"):
        # LeanCTX (secagent v0.3.0 ships it on by default): install the pinned binary + pi
        # extension and wire pi for context compression on this box — air-gapped, best-effort.
        _wire_leanctx_for_pi(dry_run)
        # Listen on secagent's MANIFEST port (fronted by secproxy at that port) — not the CLI's
        # own 8070 default — so the secagent.<domain> reverse-proxy route actually reaches it
        # (secproxy dials the topology port). Mirrors secllm using its manifest port above.
        port = manifest.components["secagent"].port
        agent_env = _parse_env_file(base_out / "addressing" / "env" / "secagent.env")
        agent_secrets = {k: v for k, v in
                         _parse_env_file(root / "deploy" / "macos" / "secrets.env").items()
                         if k.startswith("SECAGENT_")}
        fallback = (f"uv run --project work/secagent secagent chat serve --port {port} "
                    "(source out/addressing/env/secagent.env first)")
        if not dry_run and native_services and not _ensure_native_venv(root, "secagent"):
            P.warn(f"secagent: no project venv — run `secdeploy build macos`, then start it: {fallback}")
        else:
            # secagent's SecSSO calls (secsso.py) go through httpx, which bundles its own CA
            # list (certifi) rather than using the macOS System keychain — so --trust-ca
            # trusting SecCert's root there does NOTHING for secagent/pi's own TLS validation
            # (confirmed live: CERTIFICATE_VERIFY_FAILED even with the root already trusted
            # system-wide). Point httpx at the same root directly instead.
            root_pem = root / "out" / "seccert-root.pem"
            tls_env = {"SSL_CERT_FILE": str(root_pem), "REQUESTS_CA_BUNDLE": str(root_pem)} \
                if root_pem.exists() else {}
            secagent = launchd.LaunchdService(
                name="secagent",
                program_args=[str(_venv_bin(root, "secagent", "secagent")), "chat", "serve",
                              "--port", str(port)],
                log_dir=log_dir,
                env={**_base_env(home), **agent_env, **agent_secrets, **tls_env},
                working_dir=str(root), user=user,
            )
            _install_or_note(secagent, staging_dir, native_services=native_services,
                             dry_run=dry_run, fallback_note=fallback)

        # `secagent` onto PATH globally via `uv tool install` — mirrors secagent's own
        # install.sh (docs/installation.md), just pointed at the ALREADY-fetched local
        # checkout instead of re-cloning from git. Without this, `secagent` only exists at
        # work/secagent/.venv/bin/secagent — invisible to anything that shells out to the
        # bare command name, which is exactly what pi's `!secagent token --user` apiKey does
        # (confirmed live: pi's "API key auth failed... Failed to resolve API key" turned out
        # to be a plain command-not-found, not an actual auth/TLS problem). --force so a
        # redeploy re-installs whatever's now pinned in work/secagent, matching install.sh.
        if dry_run:
            print("  · uv tool install --force work/secagent (put `secagent` on PATH globally)")
        elif P.which("uv"):
            P.run(["uv", "tool", "install", "--force", str(root / "work" / "secagent")],
                  check=False)
        else:
            P.warn("uv not found — secagent won't be on PATH; pi's \"!secagent token --user\" "
                   "apiKey will fail with a command-not-found-shaped auth error")

        # pi, wired for the DEPLOYING USER (not the chat service above — pi is never in that
        # service's own request path, see work/secagent/docs/pi.md): `secagent init` writes
        # ~/.pi/agent/models.json + ~/.secagent/config.yaml using `!secagent token --user` as
        # the credential (never a stored secret) — the same one-command onboarding secagent's
        # own install.sh documents for a standalone client (docs/installation.md), just
        # triggered here instead of typed by hand.
        #
        # `secagent init --domain` alone derives raw-port guesses (secrouter.<domain>:47002,
        # secsso.<domain>:9000) that only work on a topology where those services are reached
        # directly — WRONG here, where secproxy fronts everything on :443 with no port in the
        # FQDN (confirmed live: https://secrouter.sec.internal:47002/v1 doesn't even speak TLS,
        # only plain HTTP does). Pass the ALREADY-CORRECT fronted URLs explicitly instead of
        # letting it re-derive its own — the exact same SECAGENT_LLM__BASE_URL/SECSSO_URL the
        # chat bridge above just got wired with, so pi and the chat service agree on how this
        # topology is actually reachable. Non-fatal: a developer who doesn't want pi shouldn't
        # have their deploy fail over it.
        secagent_bin = _venv_bin(root, "secagent", "secagent")
        secrouter_url = agent_env.get("SECAGENT_LLM__BASE_URL", "")
        secsso_url = agent_env.get("SECSSO_URL", "")
        init_args = ["init", "--domain", topology.domain]
        if secrouter_url:
            init_args += ["--secrouter-url", secrouter_url]
        if secsso_url:
            init_args += ["--secsso-url", secsso_url]
        init_cmd = " ".join([str(secagent_bin), *init_args])
        if dry_run:
            print(f"  · secagent {' '.join(init_args)} (wire up pi + secagent CLI for you; "
                  "run `secagent login` afterwards)")
        elif not secagent_bin.exists():
            P.warn(f"secagent: no project venv — run `secdeploy build macos` first, then: {init_cmd}")
        else:
            r = P.run([str(secagent_bin), *init_args], check=False)
            if r.returncode == 0:
                P.log("pi wired for you (~/.pi/agent/models.json, ~/.secagent/config.yaml) — "
                      "run `secagent login` to authenticate, then `pi --extension "
                      "work/secagent/pi/extensions/secagent.ts`")
            else:
                P.warn(f"secagent init failed — wire up pi yourself: {init_cmd}")

    # SecRecorder — native MLX/Metal (never containerized on macOS). Runs as the user; TLS optional
    # (a SecCert cert via certbot, reachable across the container boundary through
    # host.docker.internal — the one fronted name that DOES resolve inside the SecCert container)
    # — but ONLY when accessed directly (no topology/secproxy fronting it). Once secproxy fronts
    # it (fronted=true in the manifest, secproxy placed), nginx reverse-proxies every fronted
    # service over PLAIN HTTP to its backend (secproxy is the suite's one edge TLS terminator) —
    # SecRecorder terminating its OWN TLS too on the same port then breaks that proxy_pass with a
    # 502 ("upstream prematurely closed connection", nginx's plain-HTTP client hitting a TLS
    # handshake). So --tls is a no-op (with a warning) whenever secproxy is already fronting it.
    if _here("secrecorder"):
        model_env = _model_env(root, hf_token, model_dir)
        fronted_by_proxy = topology is not None and topology.is_fronted("secrecorder")
        certfiles: tuple[Path, Path] | None = None
        if tls and fronted_by_proxy:
            P.warn("secrecorder: --tls ignored — secproxy already fronts it with the suite's one "
                   "edge TLS (its own TLS here would break nginx's plain-HTTP proxy_pass, 502)")
        elif tls and not dry_run:
            certfiles = _issue_secrecorder_cert(root)
            if certfiles is None:
                P.warn("cert issuance failed — falling back to plain HTTP for SecRecorder")
        rec_args = [str(_venv_bin(root, "secrecorder", "uvicorn")), "server:app",
                    "--host", "0.0.0.0", "--port", str(SECRECORDER_PORT)]
        if certfiles:
            rec_args += ["--ssl-certfile", str(certfiles[0]), "--ssl-keyfile", str(certfiles[1])]
            fallback = _tls_run_cmd(certfiles[0], certfiles[1], model_env)
        else:
            fallback = (f"{_env_prefix(model_env)}HOST=0.0.0.0 PORT={SECRECORDER_PORT} "
                        f"work/secrecorder/run.sh")
        if tls and dry_run:
            if fronted_by_proxy:
                print("  · (--tls) ignored — secproxy already fronts secrecorder with the "
                      "suite's one edge TLS; runs plain HTTP behind it")
            else:
                print(f"  · (--tls) issue a SecCert cert for {CERT_HOST} via certbot, then run "
                      "SecRecorder with --ssl-certfile/--ssl-keyfile")
        if not dry_run and native_services and not _ensure_native_venv(root, "secrecorder"):
            P.warn(f"secrecorder: no project venv — run `secdeploy build macos`, then start it: {fallback}")
        else:
            secrecorder = launchd.LaunchdService(
                name="secrecorder", program_args=rec_args, log_dir=log_dir,
                env={**_base_env(home), "WHISPER_PREWARM": "1", "WHISPER_PREWARM_DIARIZER": "1",
                     **model_env},
                working_dir=str(root / "work" / "secrecorder"), user=user,
            )
            _install_or_note(secrecorder, staging_dir, native_services=native_services,
                             dry_run=dry_run, fallback_note=fallback)
    elif not dry_run:
        P.log(f"SecRecorder not placed on resource {resource!r} — skipping on this host")

    # secproxy — nginx :443/:80 (root). Generate a macOS-LOCAL nginx conf: writable state + cert
    # dirs under out/ (not fedora's /var/lib//etc production paths), and the worker `user` set
    # since launchd starts nginx as root with no user drop of its own. The cert is SecCert-issued
    # if certbot can (usually not, across the container/host DNS boundary) else self-signed, so the
    # edge actually comes up instead of failing closed on a missing cert.
    if topology is not None and _here("secproxy"):
        sp_state = base_out / "secproxy" / "state"
        sp_cert = base_out / "secproxy" / "cert"
        sp_conf = base_out / "secproxy" / "nginx.conf"
        fallback = f"sudo nginx -c {sp_conf} -g 'daemon off;'"
        if dry_run:
            print(f"  · secproxy: write macOS nginx conf → {sp_conf} (state {sp_state}, cert "
                  f"{sp_cert}), issue/self-sign the fronted-FQDN cert"
                  + (" (--trust-ca also trusts it directly if it comes back self-signed)"
                     if trust_ca else "") + ", then:")
            print(f"  · launchd {launchd.label_for('secproxy')} (as root): nginx -c {sp_conf} "
                  "-g daemon off;")
        elif not native_services:
            P.warn(f"--no-native-services: secproxy not installed — start it yourself: {fallback}")
        else:
            _ensure_nginx()
            nginx = P.which("nginx")
            if nginx is None:
                P.warn(f"nginx not found — cannot install secproxy; once installed: {fallback}")
            else:
                for d in (sp_state, sp_state / "tmp", sp_state / "acme", sp_state / "www", sp_cert):
                    d.mkdir(parents=True, exist_ok=True)
                sp_conf.write_text(wiring.nginx_conf_text(
                    topology, str(sp_cert), without, state_dir=str(sp_state),
                    user=_nginx_conf_user(user)))
                # Cert BEFORE the checklist/landing page below, so they reflect what actually
                # landed: certbot's cross-boundary ACME issuance usually can't complete on macOS
                # (see _issue_secproxy_cert), leaving a self-signed fallback that --trust-ca's
                # SecCert-root trust doesn't cover at all — trust that leaf directly instead.
                _secproxy_cert_macos(root, sp_cert, topology, without)
                sp_fullchain = sp_cert / "fullchain.pem"
                cert_untrusted = False
                if sp_fullchain.exists() and _cert_is_self_signed(sp_fullchain):
                    if trust_ca:
                        _trust_secproxy_cert(sp_fullchain, assume_yes)
                    cert_untrusted = not _ca_already_trusted(sp_fullchain)
                setup_actions = _secproxy_setup_actions(
                    placed or set(), root, topology,
                    trust_anchor_added=trust_anchor_added, resolver_configured=resolver_configured,
                    secproxy_cert_untrusted=cert_untrusted,
                )
                (sp_state / "www" / "index.html").write_text(wiring.landing_page_html(
                    topology, without, setup_actions=setup_actions))
                secproxy = launchd.LaunchdService(
                    name="secproxy",
                    program_args=[nginx, "-c", str(sp_conf), "-g", "daemon off;"],
                    log_dir=log_dir, env=_base_env(), working_dir=str(root),
                    user=None,  # root — binds :443/:80
                )
                _install_or_note(secproxy, staging_dir, native_services=True,
                                 dry_run=False, fallback_note=fallback)

    # Stack components (SecSSO / SecChat) — brought up via their own bootstrap where placed; their
    # .env secrets are auto-generated by deploy_stacks (see targets/common).
    stacks = sorted(n for n in (placed or set())
                    if manifest.components[n].kind == "stack" and n not in without) \
        if topology is not None else []
    if stacks and not dry_run:
        # Both stacks run NATIVE arm64 on Apple Silicon now: SecChat builds a native Mattermost
        # image from the official release binary on first bring-up (Mattermost's published image is
        # amd64-only, but its release BINARY ships arm64 too — see secchat/Dockerfile), and SecSSO's
        # Authentik/Postgres/Redis are multi-arch. So no QEMU/Rosetta emulation. The only cost is
        # SecChat's first build (download + build, a few minutes, one-time + cached); the bring-up
        # is detached, so a slow first run isn't a dead end.
        P.warn("bringing up SecSSO/SecChat (native arm64 — no emulation): SecChat builds its "
               "Mattermost image from the official binary on first run (a few minutes, one-time). "
               "The bring-up is detached + safe to Ctrl-C; finish/redo bot+team setup any time "
               "with `bash work/secchat/bootstrap/secchat.sh bot`.")
    if stacks:
        common.deploy_stacks(work, stacks, dry_run=dry_run)

    # CMMC audit evidence — see audit.py. Dry-run prints the note and stops.
    if dry_run:
        if out is not None:
            note = audit.dry_run_note(
                out, NAME, resource, component_count=len(services) + len(stacks),
                trust_anchor=trust_ca, resolver=resolver_configured,
            )
            print(f"  · {note}")
        if topology is not None and _here("secproxy") and wiring.fronted_instances(topology, without):
            print(f"  · landing page → https://{topology.domain}/")
        return
    if out is not None:
        shas = common.resolved_shas(manifest, work)
        audit_path = audit.write_deploy_audit(
            manifest, topology, resource, out,
            target=NAME, services=services, shas=shas, stacks=stacks,
            flags={
                "with_inference": with_inference, "with_agent": with_agent, "tls": tls,
                "trust_ca": trust_ca, "configure_resolver": configure_resolver,
                "without": without, "native_services": native_services,
            },
            addressing=written,
            trust_anchor_added=trust_anchor_added,
            resolver_configured=resolver_configured,
            secllm_auth_enabled=(written is not None),
            secagent_enabled=("secagent" in services),
        )
        P.log(f"deploy audit artifact written → {audit_path}")
    if topology is not None and _here("secproxy") and wiring.fronted_instances(topology, without):
        P.log(f"landing page → https://{topology.domain}/")
    P.log("suite deployed — check `secdeploy status macos`")


def _secproxy_setup_actions(
    placed: set[str], root: Path, topology, *,
    trust_anchor_added: bool, resolver_configured: bool, secproxy_cert_untrusted: bool = False,
) -> list[str]:
    """The landing page's 'finish setup' checklist — only items still outstanding for THIS
    deploy: trust/resolver reflect what this run actually did, HF_TOKEN/secchat reflect what's
    on disk/in the topology, so a repeat deploy's page shrinks as things get done."""
    actions: list[str] = []
    if not trust_anchor_added:
        actions.append(
            "Trust the SecCert root so browsers/curl stop flagging fronted services as "
            "untrusted: <code>secdeploy deploy macos --trust-ca</code>."
        )
    if secproxy_cert_untrusted:
        actions.append(
            "secproxy's cert is self-signed — SecCert couldn't issue a real one (the macOS "
            "container/host DNS boundary, see docs/macos.md) — and isn't trusted yet: "
            "<code>secdeploy deploy macos --trust-ca</code> trusts it directly too "
            "(<code>--trust-ca</code>'s SecCert-root trust alone doesn't cover a self-signed cert)."
        )
    if not resolver_configured:
        actions.append(
            f"Point this Mac's resolver at SecDNS so <code>*.{html.escape(topology.domain)}</code> "
            "names resolve: <code>secdeploy deploy macos --configure-resolver</code>."
        )
    if "secrecorder" in placed and not _read_hf_token(root):
        actions.append(
            "SecRecorder's speaker diarization needs a Hugging Face token (transcription "
            'works fine without one): accept <a href="https://huggingface.co/pyannote/'
            "speaker-diarization-community-1\">the gated model's terms</a>, create a read "
            "token, then set <code>HF_TOKEN</code> in <code>deploy/macos/secrets.env</code>."
        )
    if "secchat" in placed:
        actions.append(
            "Finish SecChat's bot + team setup (safe to re-run): "
            "<code>bash work/secchat/bootstrap/secchat.sh bot</code>."
        )
    if "secagent" in placed and not (Path.home() / ".secagent" / "auth" / "user-token.json").exists():
        # `secagent init` (see the with_agent block above) already wrote ~/.pi/agent/models.json
        # + ~/.secagent/config.yaml for whoever ran this deploy — the one step that can't be
        # automated is the actual login (needs a human to approve in a browser). Disappears
        # once that per-user token is cached, same "shrinks as things get done" convention as
        # every other item here.
        actions.append(
            "Configure your pi instance: <code>secagent</code>/pi validate TLS via httpx's own "
            "bundled CA list, not the System keychain, so <code>--trust-ca</code> alone isn't "
            "enough for them — export <code>SSL_CERT_FILE=$PWD/out/seccert-root.pem "
            "REQUESTS_CA_BUNDLE=$PWD/out/seccert-root.pem</code> first. Then authenticate as "
            "yourself: <code>work/secagent/.venv/bin/secagent login</code> (prints a device-code "
            "URL to approve in a browser) — then <code>pi --provider secrouter --model "
            "balanced</code>, and to load secagent's own tools, <code>pi --extension "
            "work/secagent/pi/extensions/secagent.ts</code>."
        )
    return actions


def _print_ca_dry_run(configure_hosts: bool, trust_ca: bool) -> None:
    if configure_hosts:
        print(f"  · (--configure-hosts) map {CERT_HOST} to 127.0.0.1 in /etc/hosts (sudo, asks first)")
    if trust_ca:
        print("  · (--trust-ca) trust the SecCert root in the System keychain (sudo, asks first)")


def status(manifest: Manifest, root: Path) -> None:
    if not P.which("docker"):
        P.die("docker not found")
    P.run(_compose_cmd() + _compose_files(root) + ["ps"], check=False)
    P.run(["bash", "-c", "curl -fsS http://localhost:47001/health && echo || echo 'seccert: down'"], check=False)
    if P.which("ffmpeg"):
        P.log("ffmpeg: found (SecRecorder transcoding available)")
    else:
        P.warn("ffmpeg: not found — SecRecorder transcoding will be degraded (run `secdeploy build macos` to install)")


def _os_environ() -> dict[str, str]:
    import os

    return dict(os.environ)


# ─────────────────────────────────────────────────────────────────────────────────────────
# Teardown — the reverse of deploy(). See targets/fedora_fips.py's own teardown section for
# the full PROBE-not-topology rationale (deploy is purely additive, so the host may be a
# superset of any one topology.toml/flag combination) — the same principle applies here: this
# module discovers what's actually on THIS Mac and removes what it finds, never trusting
# topology.toml/deploy flags/out/audit/*.json to decide the plan (the audit JSON may only
# annotate — see the drift note in teardown() below).
#
# Same (discover, teardown_plan, teardown) split for testability as fedora-fips — see
# tests/test_teardown.py. Like fedora-fips, teardown brings down any SecSSO/SecChat stack it
# finds a checkout for (work/<name>/bootstrap/<name>.sh down [-v]).
# ─────────────────────────────────────────────────────────────────────────────────────────


def _topology_domain_hint(topology_path: str | None) -> str | None:
    """Best-effort ONLY: the bare ``domain`` key from ``--topology``, if it's given and
    parses — used SOLELY to disambiguate which ``/etc/resolver/<domain>`` entry teardown
    should remove when more than one exists (see :func:`teardown_plan` below). NEVER used to
    decide what's installed — a missing, stale, or invalid topology.toml just falls back to
    plain discovery (list ``/etc/resolver``, and if more than one entry remains ambiguous,
    print them and don't guess) instead of raising. Deliberately avoids
    :meth:`secdeploy.topology.Topology.load` here — that validates the WHOLE file against the
    current manifest, which is more than teardown needs (just one string) and would make a
    stale/unrelated topology.toml break teardown instead of just not helping it."""
    if not topology_path:
        return None
    try:
        data = tomllib.loads(Path(topology_path).read_text())
    except (OSError, ValueError):  # missing/unreadable file, or tomllib.TOMLDecodeError
        return None
    domain = data.get("domain")
    return domain if isinstance(domain, str) and domain else None


@dataclass
class MacosFound:
    """What a probe of THIS host actually turned up — see the teardown section docstring
    above. Every field is a discovered fact, never a topology/flag-derived assumption."""

    docker_present: bool
    compose_cmd: list[str]         # resolved `docker compose` vs `docker-compose` (_compose_cmd)
    compose_file: Path | None      # deploy/macos/compose.yaml, if this checkout has it
    compose_containers: bool       # any container (running or stopped) for the compose project
    compose_volumes: bool          # any docker volume labeled for the compose project
    images: list[str]              # locally present secrouter/{seccert,secrouter}:<tag> refs
    resolver_domains: list[str]    # names of files under /etc/resolver
    domain_hint: str | None        # best-effort, from --topology (see _topology_domain_hint)
    hosts_line_present: bool       # /etc/hosts mentions CERT_HOST (loose check — discovery
                                   # only; the removal COMMAND below still only ever matches
                                   # one exact whole line, never a substring)
    keychain_cn: str | None        # SecCert root's CN, IF it is currently trusted (else None)
    out_exists: bool               # <root>/out exists
    root: Path
    stacks: list[tuple[str, Path]]  # (name, bootstrap/<name>.sh) per stack checkout found
    launchd_plists: list[Path]      # installed internal.secsuite.*.plist launchd daemons


def _discover(root: Path, work: Path, topology_path: str | None = None) -> MacosFound:
    """Probe this host — never raises. Every docker call tolerates the daemon being down
    (Colima stopped) by treating a failed probe as "found nothing" plus a warning — the same
    tolerate-absence spirit as status() and fedora_fips._discover()."""
    docker_present = bool(P.which("docker"))
    compose_cmd = _compose_cmd() if docker_present else ["docker", "compose"]
    compose_path = _compose(root)
    compose_file = compose_path if compose_path.exists() else None
    compose_containers = compose_volumes = False
    images: list[str] = []
    if docker_present:
        if compose_file is not None:
            r = P.run(compose_cmd + ["-f", str(compose_file), "ps", "-a", "-q"],
                      check=False, capture=True)
            if r.returncode == 0:
                compose_containers = bool(r.stdout.strip())
            else:
                P.warn("docker compose ps failed — is Docker/Colima running? skipping "
                       "compose container discovery")
        rv = P.run(["docker", "volume", "ls", "-q",
                   "--filter", "label=com.docker.compose.project=secsuite"],
                  check=False, capture=True)
        if rv.returncode == 0:
            compose_volumes = bool(rv.stdout.strip())
        ri = P.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                  check=False, capture=True)
        if ri.returncode == 0:
            images = sorted(
                ln for ln in ri.stdout.splitlines()
                if ln.startswith("secrouter/seccert:") or ln.startswith("secrouter/secrouter:")
            )
    resolver_dir = Path("/etc/resolver")
    resolver_domains = sorted(p.name for p in resolver_dir.iterdir()) if resolver_dir.is_dir() else []
    hosts_path = Path("/etc/hosts")
    hosts_line_present = hosts_path.exists() and CERT_HOST in hosts_path.read_text()
    keychain_cn = None
    root_pem = root / "out" / "seccert-root.pem"
    if root_pem.exists():
        cn = _extract_cn(root_pem)
        if cn and _cn_trusted(cn):
            keychain_cn = cn
    from .fedora_fips import STACK_NAMES
    stacks: list[tuple[str, Path]] = []
    for name in STACK_NAMES:
        boot = work / name / "bootstrap" / f"{name}.sh"
        if boot.exists():
            stacks.append((name, boot))
    return MacosFound(
        docker_present=docker_present, compose_cmd=compose_cmd, compose_file=compose_file,
        compose_containers=compose_containers, compose_volumes=compose_volumes, images=images,
        resolver_domains=resolver_domains, domain_hint=_topology_domain_hint(topology_path),
        hosts_line_present=hosts_line_present, keychain_cn=keychain_cn,
        out_exists=(root / "out").is_dir(), root=root, stacks=stacks,
        launchd_plists=launchd.discovered_plists(),
    )


def teardown_plan(found: MacosFound, purge: bool) -> list[common.Step]:
    """Pure — see fedora_fips.teardown_plan's docstring for the same PROBE-not-topology
    contract. Order mirrors docs/macos.md#teardown: compose, native-services guidance,
    resolver, /etc/hosts, keychain, out/ artifacts (--purge only), then a fixed "not removed"
    packages note."""
    steps: list[common.Step] = []

    # 1. compose — `down` (config/volumes kept) whenever something's actually there for this
    #    project; `down -v` (wipes seccert-data, the CA) plus offering to remove built images
    #    (compose down never removes images), --purge only.
    if found.compose_file is not None and (found.compose_containers or found.compose_volumes):
        sub = ["down", "-v"] if purge else ["down"]
        note = " — also wipes seccert-data (the CA)" if purge else " (config/volumes kept)"
        steps.append(common.Step(
            f"bring down the macOS compose stack{note}",
            found.compose_cmd + ["-f", str(found.compose_file), *sub], "compose",
        ))
    if purge:
        for img in found.images:
            steps.append(common.Step(
                f"remove built image {img} (compose down doesn't remove images; rebuildable "
                "via `secdeploy build macos`)", ["docker", "rmi", img], "compose",
            ))

    # 2. native services (launchd) — bootout + remove each installed internal.secsuite.* daemon
    #    that deploy() installed (discovered by plist, probe-driven like everything else here).
    #    `bootout` stops + unloads; then the plist is removed so it doesn't reload at next boot.
    for plist in found.launchd_plists:
        for cmd, desc in launchd.teardown_commands(plist):
            steps.append(common.Step(desc, cmd, "native_services"))
    # A service the operator started in the FOREGROUND instead (--no-native-services, or a manual
    # run) has no launchd unit to target — note it, but never auto-pkill (a fuzzy match on a shared
    # port like :53/:443 could kill an unrelated host process).
    steps.append(common.Step(
        "any native service started in the FOREGROUND (--no-native-services, or a manual run) has "
        "no launchd unit to target — Ctrl-C its terminal; `pgrep -fl 'secdns serve|secllm serve|"
        "secagent chat|nginx'` to check before any pkill", None, "native_services",
    ))

    # 3. /etc/resolver/<domain> — only when unambiguous (an explicit --topology hint that
    #    matches an existing entry, or exactly one entry present); otherwise print the
    #    candidates and don't guess.
    target_domain: str | None = None
    if found.domain_hint and found.domain_hint in found.resolver_domains:
        target_domain = found.domain_hint
    elif len(found.resolver_domains) == 1:
        target_domain = found.resolver_domains[0]
    elif len(found.resolver_domains) > 1:
        steps.append(common.Step(
            f"/etc/resolver has {len(found.resolver_domains)} entries "
            f"({', '.join(found.resolver_domains)}) and no --topology hint matched one of "
            "them — not guessing which is this suite's; pass --topology, or remove the "
            "right one by hand: sudo rm -f /etc/resolver/<domain>", None, "resolver",
        ))
    if target_domain:
        steps.append(common.Step(
            f"remove resolver entry for {target_domain}",
            ["sudo", "rm", "-f", f"/etc/resolver/{target_domain}"], "resolver",
        ))

    # 4. /etc/hosts — ONLY the exact whole line, ONLY with its own explicit confirmation
    #    (execute_teardown_plan's `gated`, wired in teardown() below): Docker Desktop may
    #    write this SAME line itself, so a substring strip is never safe here.
    if found.hosts_line_present:
        pattern = f"/^127\\.0\\.0\\.1[[:space:]]+{re.escape(CERT_HOST)}[[:space:]]*$/d"
        steps.append(common.Step(
            f"remove the exact line '127.0.0.1 {CERT_HOST}' from /etc/hosts — needs its OWN "
            "confirmation (below): Docker Desktop may also own this exact line, so only a "
            "whole-line match is ever touched, never a substring strip",
            ["sudo", "sed", "-i", "", "-E", pattern, "/etc/hosts"], "hosts",
        ))

    # 5. keychain — reverse _trust_ca_root via the exact same CN _ca_already_trusted extracts.
    if found.keychain_cn:
        steps.append(common.Step(
            f"remove the SecCert root ({found.keychain_cn!r}) from the System keychain",
            ["sudo", "security", "delete-certificate", "-c", found.keychain_cn,
             "/Library/Keychains/System.keychain"], "keychain",
        ))

    # 6. out/ build artifacts — --purge only; never even mentioned otherwise. Nothing here is
    #    un-rebuildable, but it DOES cache the same kind of no-backup-elsewhere secrets as
    #    fedora's /etc/secsuite warning above.
    if purge and found.out_exists:
        steps.append(common.Step(
            f"IRREVERSIBLE — {found.root / 'out'} also caches seccert-root.pem and the "
            "secllm-shared-token/secagent-webhook-secret used by any OTHER live deploy that "
            "shares this --out — copy it aside first if one does",
            None, "artifacts",
        ))
        steps.append(common.Step(
            f"remove build artifacts {found.root / 'out'}",
            ["rm", "-rf", str(found.root / "out")], "artifacts",
        ))

    # stacks (SecSSO/SecChat) — same as fedora-fips; mirrors common.deploy_stacks' invocation.
    for name, boot in found.stacks:
        sub = ["down", "-v"] if purge else ["down"]
        steps.append(common.Step(
            f"stack {name}: bring down via bootstrap/{name}.sh {' '.join(sub)}"
            + (" (also wipes its data volume)" if purge else " (config + data volume kept)"),
            ["bash", str(boot), *sub], "stacks",
        ))

    # packages — never removed, regardless of --purge or what was found.
    steps.append(common.Step(
        "NOT removed (shared): brew packages this host may have installed for the suite "
        "(colima, docker, uv, ffmpeg, nginx, certbot) — remove manually if you're sure "
        "nothing else on this host depends on them", None, "packages",
    ))
    return steps


def teardown(
    manifest: Manifest,
    work: Path,
    root: Path,
    dry_run: bool = False,
    purge: bool = False,
    assume_yes: bool = False,
    topology: str | None = None,
    out: Path | None = None,
) -> None:
    """The reverse of deploy() — see the teardown section docstring above. ``topology`` is
    used ONLY as a best-effort hint for which ``/etc/resolver/<domain>`` entry to remove (see
    :func:`_topology_domain_hint`) — never to decide what's installed. ``work`` locates the
    SecSSO/SecChat stack checkouts (work/<name>/bootstrap/<name>.sh) to bring them down, same
    as fedora-fips."""
    found = _discover(root, work, topology)
    plan = teardown_plan(found, purge)
    print(f"# macos teardown plan — suite {manifest.suite} — probed from THIS host, not from "
          "topology.toml/deploy flags/out/audit (see docs/macos.md#teardown)")
    common.render_teardown_plan(plan)
    if out is not None:
        note = common.audit_drift_note(Path(out), NAME)
        if note:
            print(f"\n{note}")
    if dry_run:
        return
    if not any(s.command for s in plan):
        P.log("nothing found to tear down on this host")
        return
    print()
    n = sum(1 for s in plan if s.command)
    if not P.confirm(f"Proceed with macOS teardown ({n} command(s) above)?", assume_yes):
        P.warn("teardown aborted — nothing changed")
        return
    if purge and (found.compose_volumes or found.out_exists):
        if not P.confirm(
            "--purge: ALSO wipe the seccert-data volume (the CA) and out/'s cached secrets "
            "(seccert-root.pem, the SecLLM/SecAgent shared tokens). This cannot be undone. "
            "Proceed?", assume_yes,
        ):
            P.warn("--purge declined — seccert-data/out/ left in place; tearing down everything else")
            purge = False
            plan = teardown_plan(found, purge)
    common.execute_teardown_plan(
        plan, assume_yes,
        gated={"hosts": f"Remove the exact line '127.0.0.1 {CERT_HOST}' from /etc/hosts? "
                        "Docker Desktop may also own this line — only that one exact line is "
                        "touched, nothing else."},
    )
    P.log("macOS teardown complete")
