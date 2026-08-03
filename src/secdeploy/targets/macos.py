"""macOS (Apple Silicon) target.

SecCert + SecRouter run as containers via Docker Compose (Colima). SecRecorder runs
**natively** through ``uv`` — its MLX/Metal backend can't run in Docker on macOS. SecCert
comes up first as the internal CA; its root is exported so hosts/clients can trust the suite.
"""

from __future__ import annotations

import re
from pathlib import Path

from .. import process as P
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
    "(--tls) Issue SecRecorder a SecCert cert via certbot — HTTP-01 through host.docker.internal",
    "(--configure-hosts) Map host.docker.internal to 127.0.0.1 in /etc/hosts (sudo, asks first)",
    "(--trust-ca) Trust the SecCert root in the System keychain (sudo, asks first)",
    "Layer HF_TOKEN (deploy/macos/secrets.env or --hf-token) and --model-dir (air-gapped "
    "local models) onto SecRecorder's printed run command, if set",
    "Prepare SecRecorder to run natively via uv (MLX/Metal — not containerized on macOS)",
]

IMAGES = ("seccert", "secrouter")  # secrecorder is native on macOS

# SecRecorder TLS (--tls): certbot's standalone HTTP-01 responder runs on the Mac itself;
# SecCert (in its container) reaches it via host.docker.internal, which Colima resolves to
# the host — see compose.yaml's SECCERT_HTTP01_PORT for the matching validation port.
CERT_HOST = "host.docker.internal"
HTTP01_PORT = 47080
SECRECORDER_PORT = 47003


def _image(manifest: Manifest, name: str) -> str:
    return f"secrouter/{name}:{manifest.suite}"


def _compose(root: Path) -> Path:
    return root / "deploy/macos/compose.yaml"


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


def _ca_already_trusted(root_pem: Path) -> bool:
    import subprocess

    subj = subprocess.run(
        ["openssl", "x509", "-in", str(root_pem), "-noout", "-subject"],
        capture_output=True, text=True, check=False,
    ).stdout
    m = re.search(r"CN\s*=\s*([^,/\n]+)", subj)
    if not m:
        return False
    cn = m.group(1).strip()
    return subprocess.run(
        ["security", "find-certificate", "-c", cn, "/Library/Keychains/System.keychain"],
        capture_output=True, check=False,
    ).returncode == 0


def _trust_ca_root(root: Path, assume_yes: bool = False) -> None:
    """Add the SecCert root to the macOS System keychain as a trusted root, so browsers/curl
    stop flagging SecRecorder's SecCert-issued cert as untrusted. Same command docs/macos.md
    already documents for manual use — this just runs it for you, with consent."""
    root_pem = root / "out/seccert-root.pem"
    if not root_pem.exists():
        P.warn(f"{root_pem} not found — deploy SecCert first (root export happens during deploy)")
        return
    if _ca_already_trusted(root_pem):
        P.log("SecCert root already trusted in the System keychain")
        return
    if not P.confirm(f"Trust the SecCert root ({root_pem}) in the System keychain?", assume_yes):
        P.warn("skipped CA trust — browsers/clients will flag SecRecorder's cert as untrusted")
        return
    P.run([
        "sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
        "-k", "/Library/Keychains/System.keychain", str(root_pem),
    ])


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
    # SecRecorder: create its native venv so `uv run` is instant at deploy time.
    rec = work / "secrecorder"
    if P.which("uv") and (rec / "pyproject.toml").exists():
        P.run(["uv", "sync", "--project", str(rec)], check=False)
    else:
        P.warn("uv not found or secrecorder has no pyproject — skipping native SecRecorder prep")
    P.log(f"built images: {', '.join(_image(manifest, n) for n in images)}")


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
    topology=None,
    resource: str | None = None,
    out: Path | None = None,
) -> None:
    without = without or []
    # Topology placement: only bring up the components placed on `resource` (single-host
    # synthesis places everything here, so this is a no-op without a topology.toml).
    placed = set(topology.components_on(resource, without)) if topology is not None else None

    def _here(name: str) -> bool:
        return placed is None or name in placed

    compose = _compose(root)
    dc = ["docker", "compose"] if dry_run else _compose_cmd()
    env = {"SECSUITE_VERSION": manifest.suite}
    steps = []
    if "seccert" not in without and _here("seccert"):
        steps += [
            (dc + ["-f", str(compose), "up", "-d", "seccert"], "start SecCert (CA)"),
            (["bash", "-c",
              "for i in $(seq 1 30); do curl -fsS http://localhost:47001/health >/dev/null && break; sleep 1; done"],
             "wait for SecCert /health"),
            (["bash", "-c", "curl -fsS http://localhost:47001/ca.crt -o out/seccert-root.pem && echo saved out/seccert-root.pem"],
             "export SecCert root trust anchor"),
        ]
    if _here("secrouter"):
        steps.append((dc + ["-f", str(compose), "up", "-d", "secrouter"], "start SecRouter"))
    P.log(f"deploy {NAME} — suite {manifest.suite} (SECSUITE_VERSION passed to compose)")
    if topology is not None and not dry_run and out is not None:
        from .. import wiring

        written = wiring.write_addressing(topology, Path(out) / "addressing", resource, without)
        P.log(f"addressing artifacts written → {written['zone']} (+ env/)")
    if dry_run and topology is not None:
        here = ", ".join(sorted(s for s in ("seccert", "secrouter", "secrecorder") if _here(s))) or "(none)"
        print(f"# topology: resource {resource!r} @ {topology.resources[resource].address} — "
              f"components here: {here}")
    for cmd, desc in steps:
        if dry_run:
            print(f"  · {desc}: {' '.join(cmd)}")
            continue
        P.run(cmd, env={**_os_environ(), **env})

    # secdns runs natively on macOS (like SecRecorder), fed by the generated zone — only when
    # a topology places it here (single-host has no topology, so this is skipped).
    if topology is not None and _here("secdns"):
        zone = (Path(out) / "addressing/secdns.zone") if out else Path("out/addressing/secdns.zone")
        secdns_cmd = (f"sudo SECDNS_DOMAIN={topology.domain} SECDNS_ZONE={zone} "
                      f"SECDNS_UPSTREAM={','.join(topology.upstream_dns)} "
                      f"uv run --project work/secdns secdns serve")
        if dry_run:
            print(f"  · secdns: run natively on :53 → {secdns_cmd}")
        else:
            P.warn(f"secdns runs natively on macOS — start it (needs :53) with: {secdns_cmd}")

    # SecRecorder runs natively on macOS — only when it's placed on this resource.
    if not _here("secrecorder"):
        if dry_run:
            _print_ca_dry_run(configure_hosts, trust_ca)
            return
        if configure_hosts:
            _configure_hosts(assume_yes)
        if trust_ca:
            _trust_ca_root(root, assume_yes)
        P.log(f"SecRecorder not placed on resource {resource!r} — skipping on this host")
        return

    model_env = _model_env(root, hf_token, model_dir)
    run_cmd = f"{_env_prefix(model_env)}HOST=0.0.0.0 PORT={SECRECORDER_PORT} work/secrecorder/run.sh"
    if dry_run:
        _print_ca_dry_run(configure_hosts, trust_ca)
        if tls:
            live = root / "out/certbot/config/live/secrecorder"
            print(f"  · (--tls) issue a SecCert cert for {CERT_HOST} via certbot, then: "
                  f"{_tls_run_cmd(live / 'fullchain.pem', live / 'privkey.pem', model_env)}")
        else:
            print(f"  · SecRecorder: run natively → {run_cmd}")
        return

    if configure_hosts:
        _configure_hosts(assume_yes)
    if trust_ca:
        _trust_ca_root(root, assume_yes)

    if tls:
        cert = _issue_secrecorder_cert(root)
        if cert:
            certfile, keyfile = cert
            P.log(f"SecRecorder cert ready (SecCert-issued): {certfile}")
            P.warn(f"SecRecorder is native on macOS — start it with TLS: {_tls_run_cmd(certfile, keyfile, model_env)}")
            return
        P.warn("cert issuance failed — falling back to plain HTTP for SecRecorder")
    P.warn(f"SecRecorder is native on macOS — start it with: {run_cmd}")


def _print_ca_dry_run(configure_hosts: bool, trust_ca: bool) -> None:
    if configure_hosts:
        print(f"  · (--configure-hosts) map {CERT_HOST} to 127.0.0.1 in /etc/hosts (sudo, asks first)")
    if trust_ca:
        print("  · (--trust-ca) trust the SecCert root in the System keychain (sudo, asks first)")


def status(manifest: Manifest, root: Path) -> None:
    if not P.which("docker"):
        P.die("docker not found")
    P.run(_compose_cmd() + ["-f", str(_compose(root)), "ps"], check=False)
    P.run(["bash", "-c", "curl -fsS http://localhost:47001/health && echo || echo 'seccert: down'"], check=False)
    if P.which("ffmpeg"):
        P.log("ffmpeg: found (SecRecorder transcoding available)")
    else:
        P.warn("ffmpeg: not found — SecRecorder transcoding will be degraded (run `secdeploy build macos` to install)")


def _os_environ() -> dict[str, str]:
    import os

    return dict(os.environ)
