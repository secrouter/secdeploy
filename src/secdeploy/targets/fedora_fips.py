"""FIPS-ready Fedora target — native, hardened systemd services.

No containers: each component runs as its own systemd unit under a dedicated system
user, on a host in FIPS mode so the services link the system OpenSSL FIPS provider
directly (the tightest crypto boundary). SecCert starts first and issues the suite's
certs; its root is added to the host trust store.

On-host layout::

    /opt/secsuite/{seccert,secrouter,secrecorder}   code + built venvs/dist
    /etc/secsuite/*.env                             per-service configuration
    /var/lib/secsuite/{...}                          per-service state
    /etc/systemd/system/{...}.service + secsuite.target

This module is written to also be callable by an image builder (Proxmox qcow2/LXC) —
``build`` and the ``deploy`` step list are pure functions of the checkouts + assets.
"""

from __future__ import annotations

import platform
from pathlib import Path

from .. import process as P
from .. import wiring
from ..manifest import Manifest

NAME = "fedora-fips"
KIND = "systemd-native"

OPT = Path("/opt/secsuite")
ETC = Path("/etc/secsuite")
VAR = Path("/var/lib/secsuite")
UNITS = Path("/etc/systemd/system")
ANCHORS = Path("/etc/pki/ca-trust/source/anchors")
# Native systemd services, in start order. secdns (internal DNS) comes up first when a
# topology places it here; it is only deployed with a topology (it needs a generated zone).
SERVICES = ("secdns", "seccert", "secrouter", "secrecorder")
SECDNS_ZONE = VAR / "secdns" / "secdns.zone"  # where the secdns service reads its zone

PLAN = [
    "Preflight: verify the host is in FIPS mode + the OpenSSL FIPS provider is active (fail closed)",
    "Create dedicated system users and /opt, /etc, /var state dirs (owner-only)",
    "Build natively from pinned checkouts (npm build SecRouter; uv sync SecCert/SecRecorder/secdns)",
    "Install code to /opt/secsuite + env files to /etc/secsuite (+ generated secdns zone/env when placed)",
    "Install hardened systemd units + secsuite.target; daemon-reload",
    "Enable + start secsuite.target (secdns + SecCert first, then SecRouter, then SecRecorder)",
    "Add the SecCert root to the host trust store (update-ca-trust)",
    "Verify service health",
]


def build(manifest: Manifest, work: Path, out: Path, root: Path,
          without: list[str] | None = None) -> None:
    from .common import require_checkouts

    without = without or []
    require_checkouts(manifest, work)
    # SecRouter — Node build → dist/
    if "secrouter" not in without:
        sr = work / "secrouter"
        if P.which("npm"):
            P.run(["npm", "ci", "--prefix", str(sr)], check=False) or P.run(
                ["npm", "install", "--prefix", str(sr)], check=False
            )
            P.run(["npm", "run", "build", "--prefix", str(sr)])
        else:
            P.warn("npm not found — SecRouter must be built on the Fedora host (node>=24)")
    # SecCert + SecRecorder + secdns — uv venvs
    for name in ("seccert", "secrecorder", "secdns"):
        if name in without:
            continue
        proj = work / name
        if P.which("uv") and (proj / "pyproject.toml").exists():
            P.run(["uv", "sync", "--project", str(proj)])
        else:
            P.warn(f"uv not found or {name} missing pyproject — build on the Fedora host")
    P.log("native build complete (SecRouter dist + SecCert/SecRecorder/secdns venvs)")


def _deploy_steps(manifest: Manifest, work: Path, root: Path,
                  services: list[str], addr_dir: Path | None = None) -> list[tuple[list[str], str]]:
    preflight = root / "deploy/fedora-fips/fips-preflight.sh"
    unit_dir = root / "deploy/fedora-fips/systemd"
    steps: list[tuple[list[str], str]] = [
        (["bash", str(preflight)], "FIPS preflight (fail-closed)"),
    ]
    # users + dirs
    for svc in services:
        user = f"secsuite-{svc}"
        steps.append((
            ["bash", "-c", f"getent passwd {user} >/dev/null || "
             f"useradd --system --no-create-home --shell /usr/sbin/nologin --home-dir {VAR}/{svc} {user}"],
            f"ensure user {user}",
        ))
        steps.append((["install", "-d", "-m", "750", "-o", user, "-g", user, str(VAR / svc)],
                      f"state dir {VAR/svc}"))
    steps.append((["install", "-d", "-m", "755", str(OPT)], f"code dir {OPT}"))
    steps.append((["install", "-d", "-m", "750", str(ETC)], f"config dir {ETC}"))
    # code
    for svc in services:
        steps.append((["bash", "-c", f"rm -rf {OPT}/{svc} && cp -a {work}/{svc} {OPT}/{svc}"],
                      f"install {svc} code → {OPT}/{svc}"))
    # env files from examples (don't clobber) — secdns instead gets a generated env below
    for svc in services:
        if svc == "secdns":
            continue
        ex = root / f"deploy/fedora-fips/{svc}.env.example"
        steps.append((["bash", "-c", f"test -f {ETC}/{svc}.env || install -m 640 {ex} {ETC}/{svc}.env"],
                      f"config {ETC}/{svc}.env (from example if absent)"))
    # secdns — install the topology-generated zone (readable by the service user) + env
    if "secdns" in services and addr_dir is not None:
        steps.append((["install", "-m", "644", "-o", "secsuite-secdns", "-g", "secsuite-secdns",
                       str(addr_dir / "secdns.zone"), str(SECDNS_ZONE)],
                      f"install generated secdns zone → {SECDNS_ZONE}"))
        steps.append((["install", "-m", "640", str(addr_dir / "secdns.env"), f"{ETC}/secdns.env"],
                      "install generated secdns env (domain/upstream/zone)"))
    # units — only the selected services, plus the suite target
    for svc in services:
        steps.append((["install", "-m", "644", str(unit_dir / f"{svc}.service"), f"{UNITS}/"],
                      f"install {svc}.service"))
    steps.append((["install", "-m", "644", str(unit_dir / "secsuite.target"), f"{UNITS}/"],
                  "install secsuite.target"))
    steps.append((["systemctl", "daemon-reload"], "systemd daemon-reload"))
    steps.append((["systemctl", "enable", "--now", "secsuite.target"], "enable + start the suite"))
    # trust anchor (only if SecCert is part of this deploy)
    if "seccert" in services:
        steps.append((
            ["bash", "-c",
             "for i in $(seq 1 30); do curl -fsS http://127.0.0.1:47001/ca.crt "
             f"-o {ANCHORS}/secsuite-seccert-root.pem && break; sleep 1; done && update-ca-trust"],
            "add SecCert root to the host trust store",
        ))
    return steps


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
) -> None:
    if hf_token or model_dir:
        P.warn("--hf-token/--model-dir are macOS-only — on fedora-fips, set HF_TOKEN/"
               "WHISPER_MODEL/WHISPER_DIARIZE_MODEL directly in /etc/secsuite/secrecorder.env")
    if tls or configure_hosts or trust_ca:
        P.warn("--tls/--configure-hosts/--trust-ca are macOS-only (fedora-fips gets TLS via "
               "secrouter.env's FREEROUTER_CONFIG + SecCert's native ACME integration) — ignoring")
    without = without or []
    # Placement: which native services run on THIS resource. secdns is only deployed with a
    # topology (it needs a generated zone); single-host (no topology) is byte-identical.
    placed = set(topology.components_on(resource, without)) if topology is not None else None

    def _include(svc: str) -> bool:
        if svc in without:
            return False
        if svc == "secdns" and topology is None:
            return False
        return placed is None or svc in placed

    services = [s for s in SERVICES if _include(s)]
    addr_dir = (Path(out) / "addressing") if (topology is not None and out is not None) else None
    steps = _deploy_steps(manifest, work, root, services, addr_dir=addr_dir)

    # Optional: point this host's resolver at secdns for the internal domain.
    if configure_resolver and topology is not None:
        dns_ip = wiring.secdns_address_for(topology, resource, without)
        if dns_ip:
            drop = "/etc/systemd/resolved.conf.d/secsuite.conf"
            steps.append((
                ["bash", "-c",
                 "mkdir -p /etc/systemd/resolved.conf.d && "
                 f"printf '[Resolve]\\nDNS={dns_ip}\\nDomains=~{topology.domain}\\n' > {drop} && "
                 "systemctl restart systemd-resolved"],
                f"point resolver: {topology.domain} → secdns {dns_ip} (systemd-resolved)"))
        else:
            P.warn("--configure-resolver: secdns isn't placed in this topology — nothing to point at")

    if dry_run:
        print(f"# fedora-fips deploy plan — suite {manifest.suite} (run as root on the Fedora host)")
        if topology is not None:
            print(f"# topology: resource {resource!r} @ {topology.resources[resource].address} — "
                  f"native services here: {', '.join(services) or '(none)'}")
            print("# addressing: writes secdns zone/env + peer env/ (also via "
                  f"`bundle fedora-fips --resource {resource}`)")
        for cmd, desc in steps:
            print(f"  · {desc}\n      {' '.join(cmd)}")
        return
    if platform.system() != "Linux":
        P.die(f"fedora-fips deploy must run on the Fedora host (this is {platform.system()}). "
              "Use --dry-run to preview, or `secdeploy bundle fedora-fips` to build a transfer bundle.")
    import os

    if os.geteuid() != 0:
        P.die("fedora-fips deploy must run as root (systemd unit + trust-store install)")
    from .common import require_checkouts

    require_checkouts(manifest, work, include=set(services))
    if addr_dir is not None:
        wiring.write_addressing(topology, addr_dir, resource, without)
        if "secdns" in services:
            (addr_dir / "secdns.env").write_text(wiring.secdns_env_text(topology, str(SECDNS_ZONE)))
        P.log(f"addressing artifacts written → {addr_dir}")
    for cmd, desc in steps:
        P.log(desc)
        P.run(cmd)
    P.log("suite deployed — check `secdeploy status fedora-fips`")


def status(manifest: Manifest, root: Path) -> None:
    if platform.system() != "Linux":
        P.warn("status is meaningful on the Fedora host; showing intended checks")
        for svc in SERVICES:
            print(f"  systemctl status secsuite-{svc} (unit: {svc}.service)")
        return
    P.run(["systemctl", "--no-pager", "status", "secsuite.target"], check=False)
    for svc in SERVICES:
        P.run(["systemctl", "--no-pager", "--lines=0", "status", f"{svc}.service"], check=False)
