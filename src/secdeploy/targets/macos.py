"""macOS (Apple Silicon) target.

SecCert + SecRouter run as containers via Docker Compose (Colima). SecRecorder runs
**natively** through ``uv`` — its MLX/Metal backend can't run in Docker on macOS. SecCert
comes up first as the internal CA; its root is exported so hosts/clients can trust the suite.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import common
from .. import audit
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
    "(--tls) Issue SecRecorder a SecCert cert via certbot — HTTP-01 through host.docker.internal",
    "(--configure-hosts) Map host.docker.internal to 127.0.0.1 in /etc/hosts (sudo, asks first)",
    "(--trust-ca) Trust the SecCert root in the System keychain (sudo, asks first)",
    "Layer HF_TOKEN (deploy/macos/secrets.env or --hf-token) and --model-dir (air-gapped "
    "local models) onto SecRecorder's printed run command, if set",
    "Prepare SecRecorder to run natively via uv (MLX/Metal — not containerized on macOS)",
    "(--with-inference) Print a native SecLLM run command (no GPU passthrough into Colima — "
    "GPU-free eval via SECLLM_BACKEND=mock)",
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


def _configure_resolver(domain: str, dns_ip: str, assume_yes: bool = False) -> bool:
    """Point macOS at secdns for ``domain`` via /etc/resolver/<domain> — the multi-host
    replacement for the /etc/hosts ``host.docker.internal`` trick. macOS routes queries for a
    domain to the nameserver named in that file. Returns whether the resolver was actually
    pointed at secdns (``False`` if the operator declined the confirm prompt) — the deploy
    audit artifact (audit.py) records this as a security-relevant authorization."""
    path = f"/etc/resolver/{domain}"
    if not P.confirm(f"Point {domain} at secdns ({dns_ip}) via {path}?", assume_yes):
        P.warn(f"skipped resolver config — {domain} names won't resolve via secdns on this host")
        return False
    P.run(["sudo", "mkdir", "-p", "/etc/resolver"])
    P.run(["sudo", "sh", "-c", f"printf 'nameserver {dns_ip}\\n' > {path}"])
    P.log(f"{domain} → secdns {dns_ip} ({path})")
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
    # SecRecorder: create its native venv so `uv run` is instant at deploy time.
    rec = work / "secrecorder"
    if P.which("uv") and (rec / "pyproject.toml").exists():
        P.run(["uv", "sync", "--project", str(rec)], check=False)
    else:
        P.warn("uv not found or secrecorder has no pyproject — skipping native SecRecorder prep")
    # SecLLM (--with-inference, native — no GPU passthrough into Colima): same treatment, so
    # its printed run command is instant too. Silent skip if absent — it's opt-in, so not
    # every macOS build needs it.
    sllm = work / "secllm"
    if P.which("uv") and (sllm / "pyproject.toml").exists():
        P.run(["uv", "sync", "--project", str(sllm)], check=False)
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
    configure_resolver: bool = False,
    topology=None,
    resource: str | None = None,
    out: Path | None = None,
    with_inference: bool = False,
    with_agent: bool = False,
) -> None:
    without = without or []
    # Topology placement: only bring up the components placed on `resource` (single-host
    # synthesis places everything here, so this is a no-op without a topology.toml).
    placed = set(topology.components_on(resource, without)) if topology is not None else None

    def _here(name: str) -> bool:
        return placed is None or name in placed

    # Components on THIS resource this run — same secdns/secllm/secagent gating as
    # fedora_fips._include (secdns needs a topology; secllm/secagent additionally need
    # --with-inference/--with-agent). secproxy follows secdns's simpler rule exactly —
    # topology-only, no --with-* flag (see its native-run note in deploy() below). Used for
    # the deploy audit artifact (audit.py) — recorded regardless of whether secdeploy itself
    # starts the process (SecRecorder/secagent/secproxy are always just a printed run command
    # on macOS, never a managed service), since the audit's job is "what's part of this
    # deploy", not "what secdeploy ran".
    services = [
        n for n in ("secdns", "seccert", "secllm", "secrouter", "secagent", "secrecorder", "secproxy")
        if n not in without
        and (n != "secdns" or topology is not None)
        and (n != "secllm" or (topology is not None and with_inference))
        and (n != "secagent" or (topology is not None and with_agent))
        and (n != "secproxy" or topology is not None)
        and _here(n)
    ]

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
    written: dict[str, object] | None = None
    if topology is not None and not dry_run and out is not None:
        written = wiring.write_addressing(topology, Path(out) / "addressing", resource, without)
        P.log(f"addressing artifacts written → {written['zone']} (+ env/)")
    if dry_run and topology is not None:
        watched = ("seccert", "secrouter", "secrecorder") + (("secllm",) if with_inference else ())
        here = ", ".join(sorted(s for s in watched if _here(s))) or "(none)"
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

    # secllm runs natively on macOS too (no GPU passthrough into Colima) — only when a topology
    # places it here AND --with-inference is set (a heavyweight GPU service is opt-in, like
    # secdns/SecRecorder's native-run notes above). GPU-free eval uses SECLLM_BACKEND=mock
    # instead of vllm.
    if with_inference and topology is not None and _here("secllm"):
        port = manifest.components["secllm"].port
        secllm_cmd = (f"SECLLM_HOST=0.0.0.0 SECLLM_PORT={port} SECLLM_BACKEND=mock "
                      f"uv run --project work/secllm secllm serve")
        if dry_run:
            print(f"  · (--with-inference) secllm: run natively (GPU-free eval) → {secllm_cmd}")
        else:
            P.warn(f"secllm is native on macOS (no GPU passthrough into Colima) — start it "
                   f"(GPU-free eval via SECLLM_BACKEND=mock) with: {secllm_cmd}")

    # secagent's Mattermost chat-ops bridge — KNOWN EVAL LIMITATION, not fixed here: fedora-fips
    # gets a real systemd install (two layered EnvironmentFile=, see docs/fedora-fips.md); macOS
    # has no equivalent service-manager env-file layering (compose.yaml has none either — same
    # gap as SecRouter's own addressing env, see docs/macos.md), so this is a native-run note
    # only, mirroring secdns/secllm's own notes above. The generated addressing env
    # (write_addressing()'s secagent branch — LLM/SecSSO/Mattermost wiring + webhook secret)
    # still lands in out/addressing/env/secagent.env either way; an operator running this
    # manually can source it themselves.
    if with_agent and topology is not None and _here("secagent"):
        chat_cmd = "uv run --project work/secagent secagent chat serve --port 8070"
        if dry_run:
            print(f"  · (--with-agent) secagent: run natively (known eval limitation — no "
                  f"macOS service install, see docs/macos.md) → {chat_cmd}")
        else:
            P.warn("secagent chat-ops has no macOS service install (known eval limitation — "
                   f"see docs/macos.md) — start it manually, e.g. sourcing the generated "
                   f"addressing env: {chat_cmd}")

    # secproxy runs natively on macOS too — the key simplification for this target (see module
    # docstring): nginx binds directly to the host, so it reaches every OTHER backend the same
    # way any host process does — containers publish their ports to the host (compose.yaml's
    # `ports:`), and every native service here (secdns/secllm/secagent above) already listens on
    # the host. Topology-gated only, no --with-* flag, exactly like secdns above: secproxy is the
    # suite's default front door the moment a topology places the edge tier here. nginx is the
    # reverse-proxy runtime on both targets now — fedora-fips for FIPS (system OpenSSL), macOS as
    # a non-FIPS eval. The nginx conf it points at was already written earlier in this function by
    # write_addressing() (whenever a topology is active and this isn't a dry-run); the SAN cert is
    # issued from SecCert via certbot (best-effort — see _issue_secproxy_cert's eval caveat). nginx
    # binds :443/:80, so — like secdns's :53 — starting it needs sudo.
    if topology is not None and _here("secproxy"):
        nginx_conf = (Path(out) / "addressing/secproxy.nginx.conf") if out \
            else Path("out/addressing/secproxy.nginx.conf")
        secproxy_cmd = f"sudo nginx -c {nginx_conf} -g 'daemon off;'"
        if dry_run:
            print(f"  · secproxy: issue a SecCert SAN cert (certbot) for the fronted FQDNs, then "
                  f"run nginx natively on :443/:80 → {secproxy_cmd}")
        else:
            _ensure_nginx()
            cert = _issue_secproxy_cert(root, topology, without)
            if cert:
                P.log(f"secproxy SAN cert ready (SecCert-issued): {cert[0]}")
            P.warn(f"secproxy (nginx) runs natively on macOS — start it (needs :443/:80) with: "
                   f"{secproxy_cmd}. The generated conf uses production paths (cert dir "
                   f"/etc/secsuite/secproxy, state /var/lib/secsuite/secproxy) — see docs/macos.md "
                   f"for the local-eval setup (cert placement + self-signed fallback).")

    # Optional: point this host's resolver at secdns for the internal domain.
    resolver_configured = False
    if configure_resolver and topology is not None:
        dns_ip = wiring.secdns_address_for(topology, resource, without)
        if dns_ip and dry_run:
            print(f"  · (--configure-resolver) point {topology.domain} at secdns {dns_ip} "
                  f"via /etc/resolver/{topology.domain} (sudo, asks first)")
        elif dns_ip:
            resolver_configured = _configure_resolver(topology.domain, dns_ip, assume_yes)
        elif not dry_run:
            P.warn("--configure-resolver: secdns isn't placed in this topology — nothing to point at")

    # Stack components (SecSSO / SecChat) — brought up via their own bootstrap where placed.
    stacks = sorted(n for n in (placed or set())
                    if manifest.components[n].kind == "stack" and n not in without) \
        if topology is not None else []
    if stacks:
        common.deploy_stacks(work, stacks, dry_run=dry_run)

    def _write_audit(trust_anchor_added: bool) -> None:
        """CMMC audit evidence for this deploy — see audit.py. A no-op on dry-run/no --out."""
        if dry_run or out is None:
            return
        shas = common.resolved_shas(manifest, work)
        audit_path = audit.write_deploy_audit(
            manifest, topology, resource, out,
            target=NAME, services=services, shas=shas, stacks=stacks,
            flags={
                "with_inference": with_inference, "with_agent": with_agent, "tls": tls,
                "trust_ca": trust_ca, "configure_resolver": configure_resolver, "without": without,
            },
            addressing=written,
            trust_anchor_added=trust_anchor_added,
            resolver_configured=resolver_configured,
            secllm_auth_enabled=(written is not None),
            secagent_enabled=("secagent" in services),
        )
        P.log(f"deploy audit artifact written → {audit_path}")

    # SecRecorder runs natively on macOS — only when it's placed on this resource.
    if not _here("secrecorder"):
        if dry_run:
            _print_ca_dry_run(configure_hosts, trust_ca)
            if out is not None:
                note = audit.dry_run_note(
                    out, NAME, resource, component_count=len(services) + len(stacks),
                    trust_anchor=trust_ca, resolver=resolver_configured,
                )
                print(f"  · {note}")
            return
        if configure_hosts:
            _configure_hosts(assume_yes)
        trust_anchor_added = trust_ca and _trust_ca_root(root, assume_yes)
        _write_audit(trust_anchor_added)
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
        if out is not None:
            note = audit.dry_run_note(
                out, NAME, resource, component_count=len(services) + len(stacks),
                trust_anchor=trust_ca, resolver=resolver_configured,
            )
            print(f"  · {note}")
        return

    if configure_hosts:
        _configure_hosts(assume_yes)
    trust_anchor_added = trust_ca and _trust_ca_root(root, assume_yes)

    if tls:
        cert = _issue_secrecorder_cert(root)
        if cert:
            certfile, keyfile = cert
            P.log(f"SecRecorder cert ready (SecCert-issued): {certfile}")
            P.warn(f"SecRecorder is native on macOS — start it with TLS: {_tls_run_cmd(certfile, keyfile, model_env)}")
            _write_audit(trust_anchor_added)
            return
        P.warn("cert issuance failed — falling back to plain HTTP for SecRecorder")
    P.warn(f"SecRecorder is native on macOS — start it with: {run_cmd}")
    _write_audit(trust_anchor_added)


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

    # 2. native services — secdns/secllm/secagent/secproxy run natively here with no PID or
    #    launchd unit secdeploy tracks — DOCUMENT only, never auto-pkill (a fuzzy match risks
    #    killing an unrelated host process bound to the same shared port).
    steps.append(common.Step(
        "secdns/secllm/secagent/secproxy run natively on macOS with no PID/launchd unit "
        "secdeploy can target — Ctrl-C the foreground terminal each is running in, or use "
        "the patterns below AFTER confirming they actually name your process (`pgrep -fl "
        "<pattern>` first): nginx and secdns bind ports other host processes may also use, "
        "so a fuzzy pkill can kill something unrelated. NEVER auto-run these:",
        None, "native_services",
    ))
    for label, pattern, needs_sudo in (
        ("secdns", "secdns serve", False), ("secllm", "secllm serve", False),
        ("secagent", "secagent chat serve", False),
        # secproxy's own native run command is `sudo nginx -c ... -g 'daemon off;'` (docs/
        # macos.md) — nginx binds :443/:80 and runs as root here, so killing it needs sudo too.
        ("secproxy", "nginx -c .*secproxy", True),
    ):
        prefix = "sudo " if needs_sudo else ""
        steps.append(common.Step(f"{label}: {prefix}pkill -f '{pattern}'", None, "native_services"))

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
