"""FIPS-ready Fedora target — native, hardened systemd services.

No containers: each component runs as its own systemd unit under a dedicated system
user, on a host in FIPS mode so the services link the system OpenSSL FIPS provider
directly (the tightest crypto boundary). SecCert starts first and issues the suite's
certs; its root is added to the host trust store.

On-host layout::

    /opt/secsuite/{seccert,secllm,secrouter,secrecorder}   code + built venvs/dist
    /etc/secsuite/*.env                                    per-service configuration
    /var/lib/secsuite/{...}                                 per-service state
    /etc/systemd/system/{...}.service + secsuite.target

This module is written to also be callable by an image builder (Proxmox qcow2/LXC) —
``build`` and the ``deploy`` step list are pure functions of the checkouts + assets.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path

from . import common
from .. import audit
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
# secllm (local inference) likewise only stands up with a topology, and additionally needs
# --with-inference (it's a heavyweight GPU service, so standing it up is opt-in — see deploy()).
# secagent (chat-ops) follows the exact same split as secllm: standing up the SERVICE (this
# tuple, the pi/systemd install steps below) needs --with-agent, but the generated wiring
# itself (write_addressing's secagent branch, in wiring.py/topology.py) is placement-only,
# unconditional on the flag — a redeploy that later turns --with-agent on picks up an env
# that was already being generated (harmlessly unused) rather than appearing from nothing.
# secproxy (the edge reverse proxy) follows the same topology-only rule as secdns — no
# --with-* flag, since it's the suite's default front door once a topology exists (see
# _include below). It's last in this tuple: Caddy's own automatic HTTPS dials SecCert's ACME
# directory and its Host-routed site blocks depend on secdns for name resolution, so it makes
# sense for it to come up after its backends here — though the REAL start ordering is enforced
# by secproxy.service's own After=, not by this tuple (which only orders the install loops below).
SERVICES = ("secdns", "seccert", "secllm", "secrouter", "secagent", "secrecorder", "secproxy")
SECDNS_ZONE = VAR / "secdns" / "secdns.zone"  # where the secdns service reads its zone
SECROUTER_EGRESS_FILE = ETC / "secrouter-egress.json"  # SecRouter's SECROUTER_EGRESS_FILE target
# The generated peer-wiring env (pool/token/egress-file path) — layered onto the operator's own
# secrouter.env via a SECOND EnvironmentFile= in secrouter.service (see that unit + deploy()
# below), a DISTINCT path from ETC/secrouter.env so it never clobbers the operator's config.
SECROUTER_ADDRESSING_ENV = ETC / "secrouter-addressing.env"
# Same two-file layering for secagent (see secagent.service) — generated LLM/SecSSO/Mattermost
# wiring + webhook secret, distinct from the operator-filled ETC/secagent.env.
SECAGENT_ADDRESSING_ENV = ETC / "secagent-addressing.env"
# pi's system-wide models.json for the secsuite-secagent service user (HOME=VAR/secagent, per
# its useradd --home-dir below) — the SERVICE (api-key) auth mode; see wiring.secagent_pi_models_json.
SECAGENT_PI_MODELS = VAR / "secagent" / ".pi" / "agent" / "models.json"
# Where secproxy reads its Caddyfile — installed from the topology-generated addr_dir/Caddyfile
# (wiring.write_addressing's "caddyfile" output). No secret in it (unlike SecLLM's admin token),
# so — like the secdns zone — it's refreshed unconditionally on every deploy, never test -f guarded.
SECPROXY_CADDYFILE = ETC / "Caddyfile"

PLAN = [
    "Preflight: verify the host is in FIPS mode + the OpenSSL FIPS provider is active (fail closed)",
    "Create dedicated system users and /opt, /etc, /var state dirs (owner-only)",
    "Build natively from pinned checkouts (npm build SecRouter; uv sync SecCert/SecRecorder/secdns/SecLLM)",
    "Install code to /opt/secsuite + env files to /etc/secsuite (+ generated secdns zone/env when "
    "placed, + generated secllm.env with --with-inference, + generated secrouter addressing env/"
    "egress allow-list when a SecLLM pool exists — layered onto secrouter.env, see below)",
    "Install hardened systemd units + secsuite.target; daemon-reload",
    "Enable + start secsuite.target (secdns + SecCert + SecLLM first, then SecRouter, then SecRecorder)",
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
    # SecCert + SecRecorder + secdns + secllm + secagent — uv venvs
    for name in ("seccert", "secrecorder", "secdns", "secllm", "secagent"):
        if name in without:
            continue
        proj = work / name
        if P.which("uv") and (proj / "pyproject.toml").exists():
            P.run(["uv", "sync", "--project", str(proj)])
        else:
            P.warn(f"uv not found or {name} missing pyproject — build on the Fedora host")
    P.log("native build complete (SecRouter dist + SecCert/SecRecorder/secdns/secllm/secagent venvs)")


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
    # env files from examples (don't clobber) — secdns/secllm instead get a generated env below;
    # secproxy needs no env file at all — its only configuration is the generated Caddyfile
    # installed below (Caddy takes no other environment-driven config from secdeploy).
    for svc in services:
        if svc in ("secdns", "secllm", "secproxy"):
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
    # secllm (--with-inference) — install the generated env (don't clobber: it carries the
    # admin token, and redeploying shouldn't rotate it out from under a running instance)
    if "secllm" in services and addr_dir is not None:
        steps.append((
            ["bash", "-c", f"test -f {ETC}/secllm.env || "
             f"install -m 640 {addr_dir}/secllm.env {ETC}/secllm.env"],
            f"config {ETC}/secllm.env (generated; kept across redeploys — carries the admin token)",
        ))
    # secrouter — install the generated egress allow-list (secrouter-egress.json), CMMC
    # evidence for the SecLLM-pool egress authorization (see wiring.secrouter_egress_rules).
    # Not a secret (unlike secllm.env above) — always refreshed, so a redeploy after the pool
    # changes (e.g. a new SecLLM instance) updates it immediately, same as the secdns zone.
    # Guarded (rather than unconditional like the zone) because the file is only written when
    # this topology actually has a SecLLM pool to authorize — see write_addressing.
    if "secrouter" in services and addr_dir is not None:
        steps.append((
            ["bash", "-c", f"test -f {addr_dir}/secrouter-egress.json && "
             f"install -m 644 -o secsuite-secrouter -g secsuite-secrouter "
             f"{addr_dir}/secrouter-egress.json {SECROUTER_EGRESS_FILE} || true"],
            f"install SecRouter egress allow-list → {SECROUTER_EGRESS_FILE} (if a SecLLM pool exists)",
        ))
        # ...and the generated peer-wiring env itself (pool/token/egress-file path) — a
        # DISTINCT path from ETC/secrouter.env (never clobbers the operator's config), layered
        # on top of it via a second EnvironmentFile= in secrouter.service (systemd applies
        # multiple EnvironmentFile= lines in order, later wins) so the topology-derived wiring
        # actually reaches the running service instead of staying generated-but-unapplied in
        # out/. Always refreshed like the secdns zone (no test -f guard) — it's fully derived
        # from the topology + the cached shared token (secllm_shared_token), so a redeploy
        # reproduces the same content whenever nothing has actually changed; unlike secllm.env
        # above, there's no independently-minted-per-install secret to protect from rotation.
        # write_addressing() always writes env/secrouter.env whenever secrouter is placed here
        # (regardless of whether a pool exists), so the source is guaranteed to exist under this
        # same "secrouter in services and addr_dir is not None" condition.
        steps.append((
            ["install", "-m", "640", str(addr_dir / "env" / "secrouter.env"),
             str(SECROUTER_ADDRESSING_ENV)],
            f"install generated secrouter addressing env → {SECROUTER_ADDRESSING_ENV} "
            "(pool/token/egress-file — layered onto secrouter.env via systemd EnvironmentFile=)",
        ))
    # secagent (--with-agent) — pi (the agent runtime) is a global npm tool, not part of any
    # pinned checkout; install it alongside secagent's own code. Then the generated addressing
    # env (LLM/SecSSO/Mattermost wiring + webhook secret), layered onto secagent.env via a
    # second EnvironmentFile= exactly like secrouter's above — always refreshed, fully derived.
    # Finally pi's own models.json (service api-key auth — see wiring.secagent_pi_models_json),
    # installed under the service user's HOME (VAR/secagent/.pi/agent), also always refreshed.
    if "secagent" in services and addr_dir is not None:
        steps.append((
            ["npm", "install", "-g", "@earendil-works/pi-coding-agent"],
            "install pi (coding agent runtime) globally",
        ))
        steps.append((
            ["install", "-m", "640", str(addr_dir / "env" / "secagent.env"),
             str(SECAGENT_ADDRESSING_ENV)],
            f"install generated secagent addressing env → {SECAGENT_ADDRESSING_ENV} "
            "(LLM/SecSSO/Mattermost wiring + webhook secret — layered via systemd EnvironmentFile=)",
        ))
        steps.append((
            ["install", "-d", "-m", "750", "-o", "secsuite-secagent", "-g", "secsuite-secagent",
             str(SECAGENT_PI_MODELS.parent)],
            f"pi config dir {SECAGENT_PI_MODELS.parent}",
        ))
        steps.append((
            ["bash", "-c", f"test -f {addr_dir}/secagent-pi-models.json && "
             f"install -m 644 -o secsuite-secagent -g secsuite-secagent "
             f"{addr_dir}/secagent-pi-models.json {SECAGENT_PI_MODELS} || true"],
            f"install pi models.json (service api-key auth) → {SECAGENT_PI_MODELS}",
        ))
    # secproxy needs the Caddy RUNTIME itself. Unlike every other entry in SERVICES, there is
    # no secproxy source checkout to build here — Caddy is an upstream Go binary (see
    # secproxy's own README/Dockerfile) — so, mirroring the idempotent "ensure user"/"ensure
    # X" idiom used throughout this function, this step is a no-op if Caddy is already on
    # PATH (e.g. pre-mirrored into a closed-network host's local dnf repo) and otherwise
    # installs it from Caddy's OFFICIAL Fedora/RHEL package — the @caddy/caddy COPR
    # (https://copr.fedorainfracloud.org/coprs/@caddy/caddy/), Caddy's own documented install
    # path for Fedora/RHEL — pinned to the 2.8 line to match secproxy's Dockerfile (FROM
    # caddy:2.8-alpine). A native binary + dedicated systemd unit (not a podman container)
    # was chosen deliberately: secproxy's manifest `kind` is "service" (like secdns), not
    # "stack" (secsso/secchat's podman/compose path, a wholly separate deploy_stacks()
    # mechanism — see targets/common.py); podman would also make binding :443/:80 with
    # AmbientCapabilities=CAP_NET_BIND_SERVICE — the exact mechanism secdns uses for :53 —
    # far less direct across a container boundary. See
    # docs/fedora-fips.md#secproxy-edge-reverse-proxy for the full rationale.
    if "secproxy" in services:
        steps.append((
            ["bash", "-c", "command -v caddy >/dev/null || "
             "(dnf install -y 'dnf-command(copr)' && dnf copr enable -y @caddy/caddy && "
             "dnf install -y 'caddy-2.8*')"],
            "ensure Caddy runtime is installed (pinned to the 2.8 line, via the @caddy/caddy COPR)",
        ))
    # secproxy — install the topology-generated Caddyfile (the suite's edge reverse-proxy
    # config; see wiring.caddyfile_text/write_addressing). Unconditional refresh, exactly like
    # the secdns zone above — it carries no secret (Caddy's own ACME account/cert material
    # lives under its state dir, never in this file), so a redeploy after topology.toml changes
    # (a fronted service added/moved) takes effect immediately.
    if "secproxy" in services and addr_dir is not None:
        steps.append((
            ["install", "-m", "644", "-o", "secsuite-secproxy", "-g", "secsuite-secproxy",
             str(addr_dir / "Caddyfile"), str(SECPROXY_CADDYFILE)],
            f"install generated Caddyfile → {SECPROXY_CADDYFILE}",
        ))
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
    with_inference: bool = False,
    with_agent: bool = False,
) -> None:
    if hf_token or model_dir:
        P.warn("--hf-token/--model-dir are macOS-only — on fedora-fips, set HF_TOKEN/"
               "WHISPER_MODEL/WHISPER_DIARIZE_MODEL directly in /etc/secsuite/secrecorder.env")
    if tls or configure_hosts or trust_ca:
        P.warn("--tls/--configure-hosts/--trust-ca are macOS-only (fedora-fips gets TLS via "
               "secrouter.env's FREEROUTER_CONFIG + SecCert's native ACME integration) — ignoring")
    without = without or []
    # Placement: which native services run on THIS resource. secdns is only deployed with a
    # topology (it needs a generated zone); single-host (no topology) is byte-identical. secllm
    # additionally needs --with-inference: the DNS + peer-env wiring (steps 1-3) always reflects
    # the inference tier's placement, but standing up the (heavyweight, GPU) service itself is
    # opt-in. secagent additionally needs --with-agent — UNLIKE secllm, its generated wiring is
    # ALSO gated by the flag (see the SERVICES comment above), so this single check covers both.
    # secproxy follows secdns's simpler rule exactly — topology-only, no --with-* flag: it's the
    # suite's default front door the moment an edge tier exists, same as secdns is the default
    # resolver the moment an identity tier exists.
    placed = set(topology.components_on(resource, without)) if topology is not None else None

    def _include(svc: str) -> bool:
        if svc in without:
            return False
        if svc == "secdns" and topology is None:
            return False
        if svc == "secllm" and (topology is None or not with_inference):
            return False
        if svc == "secagent" and (topology is None or not with_agent):
            return False
        if svc == "secproxy" and topology is None:
            return False
        return placed is None or svc in placed

    services = [s for s in SERVICES if _include(s)]
    stacks = sorted(n for n in (placed or set())
                    if manifest.components[n].kind == "stack" and n not in without) \
        if topology is not None else []
    # Security-relevant authorizations this deploy makes, for the audit artifact (see audit.py).
    # Neither step here is confirm()-gated (unlike their macOS counterparts), so "the step is in
    # the plan" and "the step happened" coincide once a real run reaches the end without dying.
    trust_anchor_added = "seccert" in services
    secagent_enabled = "secagent" in services
    addr_dir = (Path(out) / "addressing") if (topology is not None and out is not None) else None
    steps = _deploy_steps(manifest, work, root, services, addr_dir=addr_dir)

    # SecAgent's Mattermost bot token is minted on the SecChat host, not this one, and
    # `mmctl token generate` produces a fresh, non-idempotent token with no machine-readable
    # output contract secdeploy could safely parse across hosts — so this stays a printed
    # operator step (mirrors targets/common.py's deploy_stacks .env-from-example pattern)
    # rather than an automated cross-host fetch. Same note whether dry-run or real.
    secagent_bot_note = (
        "mint the SecAgent Mattermost bot token: on the SecChat host, run "
        "`bash bootstrap/secchat.sh bot`, copy the printed token, and set it as "
        f"SECAGENT_MATTERMOST__BOT_TOKEN in {ETC}/secagent.env"
    )
    # SecRouter's OIDC config fragment (security.oidc.issuer/jwksUri/serviceSubjects) — not a
    # turnkey env var like SECROUTER_EGRESS_FILE (SecRouter's FREEROUTER_CONFIG is hand-authored
    # JSON), so write_addressing() writes it as a documented fragment for the operator to merge
    # rather than installing it anywhere. It's generated whenever SecRouter+SecSSO are co-placed
    # (--with-agent or not — same placement-only precedent as the rest of write_addressing), but
    # only SURFACED here (dry-run/log) when --with-agent is set, since it's specifically about
    # authorizing svc-secagent and would be noise otherwise.
    oidc_preview = wiring.secrouter_oidc_config(topology, without) if topology is not None else {}

    # Optional: point this host's resolver at secdns for the internal domain.
    resolver_configured = False
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
            resolver_configured = True
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
        if stacks:
            common.deploy_stacks(work, stacks, dry_run=True)
        if secagent_enabled and "secchat" in stacks:
            print(f"  · {secagent_bot_note}")
        if secagent_enabled and oidc_preview:
            oidc_path = (addr_dir / "secrouter-oidc.json") if addr_dir else None
            print(f"  · SecRouter OIDC config fragment (merge into security.oidc) would be "
                  f"written → {oidc_path}: issuer={oidc_preview['issuer']!r}, "
                  f"serviceSubjects={oidc_preview['serviceSubjects']!r}")
        if out is not None:
            note = audit.dry_run_note(
                out, NAME, resource, component_count=len(services) + len(stacks),
                trust_anchor=trust_anchor_added, resolver=resolver_configured,
            )
            print(f"  · {note}")
        return
    if platform.system() != "Linux":
        P.die(f"fedora-fips deploy must run on the Fedora host (this is {platform.system()}). "
              "Use --dry-run to preview, or `secdeploy bundle fedora-fips` to build a transfer bundle.")
    import os

    if os.geteuid() != 0:
        P.die("fedora-fips deploy must run as root (systemd unit + trust-store install)")

    common.require_checkouts(manifest, work, include=set(services) | set(stacks))
    written: dict[str, object] | None = None
    if addr_dir is not None:
        written = wiring.write_addressing(topology, addr_dir, resource, without,
                                          secrouter_egress_path=str(SECROUTER_EGRESS_FILE))
        if "secdns" in services:
            (addr_dir / "secdns.env").write_text(wiring.secdns_env_text(topology, str(SECDNS_ZONE)))
        if "secllm" in services:
            # SECLLM_API_TOKEN must be the SAME value SecRouter's env got above
            # (SECROUTER_SECLLM_TOKEN) — secllm_shared_token() is a cache keyed on addr_dir, so
            # this reads back exactly what write_addressing just generated/reused, not a fresh
            # independent token.
            api_token = wiring.secllm_shared_token(addr_dir)
            (addr_dir / "secllm.env").write_text(wiring.secllm_env_text(api_token=api_token))
        if secagent_enabled:
            # pi's models.json (service api-key auth) — generated from secagent's OWN checked-
            # out example (never hardcoded here, so secdeploy can't drift from secagent's
            # actual model catalog), with the real SecRouter URL substituted and apiKey added.
            models_example = work / "secagent" / "pi" / "models.secrouter.example.json"
            secrouter_url = topology.urls(without).get("SECROUTER")
            if models_example.exists() and secrouter_url:
                example = json.loads(models_example.read_text())
                models = wiring.secagent_pi_models_json(example, f"{secrouter_url}/v1")
                (addr_dir / "secagent-pi-models.json").write_text(json.dumps(models, indent=2) + "\n")
            elif not models_example.exists():
                P.warn(f"{models_example} not found — pi models.json will not be generated "
                       "(expected secagent's checkout to carry pi/models.secrouter.example.json)")
            else:
                P.warn("secagent: SecRouter has no addressable URL in this topology — "
                       "skipping pi models.json generation")
        if secagent_enabled and written.get("oidc"):
            P.log(f"SecRouter OIDC config fragment written → {written['oidc']} "
                  "(merge into security.oidc — see docs/fedora-fips.md)")
        P.log(f"addressing artifacts written → {addr_dir}")
    for cmd, desc in steps:
        P.log(desc)
        P.run(cmd)
    if stacks:
        common.deploy_stacks(work, stacks, dry_run=False)
    if secagent_enabled and "secchat" in stacks:
        P.warn(secagent_bot_note)
    if out is not None:
        # CMMC audit evidence: what landed on this resource + which security-relevant
        # authorizations (trust anchor / resolver / SecLLM inference auth) this run made —
        # see audit.py. secllm_auth_enabled mirrors exactly when the token/egress wiring above
        # ran (addr_dir is not None) — no topology, no shared-token wiring, nothing to report.
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
            secllm_auth_enabled=(addr_dir is not None),
            secagent_enabled=secagent_enabled,
        )
        P.log(f"deploy audit artifact written → {audit_path}")
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
