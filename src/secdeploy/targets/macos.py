"""macOS (Apple Silicon) target.

SecCert + SecRouter run as containers via Docker Compose (Colima). SecRecorder runs
**natively** through ``uv`` — its MLX/Metal backend can't run in Docker on macOS. SecCert
comes up first as the internal CA; its root is exported so hosts/clients can trust the suite.
"""

from __future__ import annotations

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
    "Prepare SecRecorder to run natively via uv (MLX/Metal — not containerized on macOS)",
]

IMAGES = ("seccert", "secrouter")  # secrecorder is native on macOS


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


def build(manifest: Manifest, work: Path, out: Path, root: Path) -> None:
    from .common import require_checkouts

    require_checkouts(manifest, work)
    if not P.which("docker"):
        P.die("docker (Colima) is required for the macOS target")
    out.mkdir(parents=True, exist_ok=True)
    for name in IMAGES:
        P.run(["docker", "build", "-t", _image(manifest, name), str(work / name)])
    # SecRecorder: create its native venv so `uv run` is instant at deploy time.
    rec = work / "secrecorder"
    if P.which("uv") and (rec / "pyproject.toml").exists():
        P.run(["uv", "sync", "--project", str(rec)], check=False)
    else:
        P.warn("uv not found or secrecorder has no pyproject — skipping native SecRecorder prep")
    P.log(f"built images: {', '.join(_image(manifest, n) for n in IMAGES)}")


def deploy(manifest: Manifest, work: Path, root: Path, dry_run: bool = False) -> None:
    compose = _compose(root)
    dc = ["docker", "compose"] if dry_run else _compose_cmd()
    env = {"SECSUITE_VERSION": manifest.suite}
    steps = [
        (dc + ["-f", str(compose), "up", "-d", "seccert"], "start SecCert (CA)"),
        (["bash", "-c",
          "for i in $(seq 1 30); do curl -fsS http://localhost:14000/health >/dev/null && break; sleep 1; done"],
         "wait for SecCert /health"),
        (["bash", "-c", "curl -fsS http://localhost:14000/ca.crt -o out/seccert-root.pem && echo saved out/seccert-root.pem"],
         "export SecCert root trust anchor"),
        (dc + ["-f", str(compose), "up", "-d", "secrouter"], "start SecRouter"),
    ]
    P.log(f"deploy {NAME} — suite {manifest.suite} (SECSUITE_VERSION passed to compose)")
    for cmd, desc in steps:
        if dry_run:
            print(f"  · {desc}: {' '.join(cmd)}")
            continue
        P.run(cmd, env={**_os_environ(), **env})
    if dry_run:
        print("  · SecRecorder: run natively → uv run --project work/secrecorder secrecorder")
        return
    P.warn("SecRecorder is native on macOS — start it with: uv run --project work/secrecorder secrecorder")


def status(manifest: Manifest, root: Path) -> None:
    if not P.which("docker"):
        P.die("docker not found")
    P.run(_compose_cmd() + ["-f", str(_compose(root)), "ps"], check=False)
    P.run(["bash", "-c", "curl -fsS http://localhost:14000/health && echo || echo 'seccert: down'"], check=False)


def _os_environ() -> dict[str, str]:
    import os

    return dict(os.environ)
