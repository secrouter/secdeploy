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
from dataclasses import dataclass
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
# _include below). It's last in this tuple: nginx's SecCert-issued cert is minted at deploy time
# and its Host-routed server blocks depend on secdns for name resolution, so it makes sense for
# it to come up after its backends here — though the REAL start ordering is enforced by
# secproxy.service's own After=, not by this tuple (which only orders the install loops below).
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
# Where secproxy reads its generated nginx config — installed from addr_dir/secproxy.nginx.conf
# (wiring.write_addressing's "nginx_conf" output). No secret in it (unlike SecLLM's admin token),
# so — like the secdns zone — it's refreshed unconditionally on every deploy, never test -f
# guarded. nginx links the system OpenSSL — FIPS-validated in FIPS mode — which is why the suite
# standardized on it for the edge TLS termination (macOS runs the same nginx for its eval).
SECPROXY_NGINX_CONF = ETC / "nginx-secproxy.conf"
# The SAN cert nginx serves — issued from SecCert by certbot at deploy time (see
# _issue_secproxy_cert), covering all fronted FQDNs; nginx_conf_text points every :443 server
# block's ssl_certificate/ssl_certificate_key here. Key lands 0600, owned by secsuite-secproxy.
SECPROXY_CERT_DIR = ETC / "secproxy"
# --configure-resolver's systemd-resolved drop-in (below, in deploy()) — also teardown's
# reverse-direction target (see the teardown section at the end of this module). A module
# constant (not inlined twice) so the two can never drift apart.
RESOLVER_DROPIN = Path("/etc/systemd/resolved.conf.d/secsuite.conf")

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


def _issue_secproxy_cert(topology, without: list[str] | None = None) -> list[tuple[list[str], str]]:
    """Deploy steps that get secproxy ONE SAN certificate from SecCert — covering every fronted,
    placed FQDN — via ``certbot --standalone``, then install it to the cert dir nginx reads
    (:data:`SECPROXY_CERT_DIR`). Mirrors ``targets/macos.py``'s ``_issue_secrecorder_cert``'s
    certbot invocation, but with one ``-d`` per fronted component and a single
    ``--cert-name secproxy`` (the same fronted set :func:`wiring.nginx_conf_text` emits server
    blocks for — secproxy/secllm/secdns excluded explicitly, seccert by not being ``fronted``).
    The fronted set comes from :func:`wiring.fronted_instances` — the SAME source
    :func:`wiring.nginx_conf_text` builds its :443 server blocks from — so the cert always covers
    exactly the names nginx serves. Empty when nothing is fronted or SecCert isn't in this
    topology (nothing to issue, or no CA to issue from).

    BOOTSTRAP ORDERING — flagged, not fully solved this wave (see
    docs/fedora-fips.md#secproxy-edge-reverse-proxy): certbot's HTTP-01 challenge is answered by
    this ``--standalone`` responder on **:80**, so it must run BEFORE nginx starts (port 80
    free — these steps are ordered ahead of ``systemctl enable --now secsuite.target``) and
    AFTER SecCert is reachable and the fronted FQDNs resolve (via secdns's fronted-axis zone) to
    this proxy host — i.e. secdns up + this host's resolver pointed at it (``--configure-resolver``
    or manual ``/etc/resolver``/``/etc/hosts``). On a from-scratch first deploy SecCert may not be
    configured/running yet, so the issuance is wrapped to be NON-FATAL: it prints guidance instead
    of aborting the deploy, nginx's own ``nginx -t`` (ExecStartPre) then fails closed until the
    cert lands, and a redeploy re-issues idempotently. Renewal reuses the running nginx's :80
    ``/.well-known/acme-challenge`` webroot: ``certbot renew`` (``--webroot`` that dir) +
    ``nginx -s reload`` — documented, not automated here.
    """
    seccert = topology.manifest.select(without).get("seccert")
    fqdns = [fqdn for fqdn, _addr, _port in wiring.fronted_instances(topology, without)]
    if not fqdns or seccert is None or not seccert.port:
        return []
    acme = f"http://{topology.fqdn('seccert')}:{seccert.port}/acme/directory"
    cb = VAR / "secproxy" / "certbot"
    live = cb / "config" / "live" / "secproxy"
    d_flags = " ".join(f"-d {f}" for f in fqdns)
    certbot = (
        f"certbot certonly --standalone --non-interactive --agree-tos "
        f"--register-unsafely-without-email "
        f"--config-dir {cb}/config --work-dir {cb}/work --logs-dir {cb}/logs "
        f"--server {acme} --http-01-port 80 --cert-name secproxy {d_flags}"
    )
    guidance = (
        f"secproxy: certbot SAN-cert issuance did not complete — see {cb}/logs/letsencrypt.log; "
        f"ensure SecCert is reachable and this host's resolver points at secdns, then redeploy "
        f"(nginx will not start until {SECPROXY_CERT_DIR}/fullchain.pem exists)"
    )
    return [
        (["bash", "-c", f"{certbot} || echo '{guidance}'"],
         f"issue secproxy SAN cert from SecCert via certbot --standalone "
         f"(--cert-name secproxy, {len(fqdns)} -d names: {', '.join(fqdns)})"),
        (["bash", "-c", f"test -f {live}/fullchain.pem && install -m 644 "
          f"-o secsuite-secproxy -g secsuite-secproxy "
          f"{live}/fullchain.pem {SECPROXY_CERT_DIR}/fullchain.pem || true"],
         f"install secproxy fullchain → {SECPROXY_CERT_DIR}/fullchain.pem"),
        (["bash", "-c", f"test -f {live}/privkey.pem && install -m 600 "
          f"-o secsuite-secproxy -g secsuite-secproxy "
          f"{live}/privkey.pem {SECPROXY_CERT_DIR}/privkey.pem || true"],
         f"install secproxy privkey (0600, owned by secsuite-secproxy) → "
         f"{SECPROXY_CERT_DIR}/privkey.pem"),
    ]


def _deploy_steps(manifest: Manifest, work: Path, root: Path,
                  services: list[str], addr_dir: Path | None = None,
                  topology=None, without: list[str] | None = None) -> list[tuple[list[str], str]]:
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
    # env files (don't clobber an already-installed one) — secdns/secllm instead get a
    # generated env below; secproxy needs no env file at all — its only configuration is the
    # generated nginx config installed below (nginx takes no other environment-driven config
    # from secdeploy). PREFER a filled deploy/fedora-fips/<svc>.env over the .example when one
    # exists — that's what `secdeploy configure`'s optional secret-seeding step writes (see
    # configure.py's _write_env_seeds); a checkout no one has seeded still falls back to the
    # shipped .example exactly as before.
    for svc in services:
        if svc in ("secdns", "secllm", "secproxy"):
            continue
        filled = root / f"deploy/fedora-fips/{svc}.env"
        example = root / f"deploy/fedora-fips/{svc}.env.example"
        src = filled if filled.exists() else example
        label = "seeded env" if src == filled else "example"
        steps.append((["bash", "-c", f"test -f {ETC}/{svc}.env || install -m 640 {src} {ETC}/{svc}.env"],
                      f"config {ETC}/{svc}.env (from {label} if absent)"))
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
    # secproxy needs the nginx RUNTIME + certbot. Unlike every other entry in SERVICES, there is
    # no secproxy source checkout to build here — nginx is an upstream package (see secproxy's
    # own README). nginx is the secproxy runtime specifically FOR FIPS: it links the system
    # OpenSSL, which is FIPS-validated in FIPS mode (the reason the suite standardized on it for
    # edge TLS termination; macOS runs the same nginx for a non-FIPS eval — see targets/macos.py).
    # certbot is the ACME client that mints secproxy's SAN cert from SecCert at deploy time (see
    # _issue_secproxy_cert below) — nginx runs no ACME client of its own. A native package under a
    # dedicated hardened systemd unit (not a podman container) was chosen deliberately, same
    # reasoning as before: secproxy's manifest `kind` is "service" (like secdns), not "stack"
    # (secsso/secchat's podman/compose path — a wholly separate deploy_stacks() mechanism, see
    # targets/common.py); podman would also make binding :443/:80 with
    # AmbientCapabilities=CAP_NET_BIND_SERVICE — the exact mechanism secdns uses for :53 — far
    # less direct across a container boundary. See docs/fedora-fips.md#secproxy-edge-reverse-proxy.
    if "secproxy" in services:
        steps.append((
            ["dnf", "install", "-y", "nginx", "certbot"],
            "install the secproxy runtime (nginx — system-OpenSSL TLS, FIPS-validated in FIPS "
            "mode) + certbot",
        ))
    # secproxy — the cert dir nginx reads, the ACME-challenge webroot the :80 server serves, and
    # nginx's writable runtime dir (pid/logs/temp under ProtectSystem=strict); then the generated
    # nginx config, and the SecCert-issued SAN cert (certbot --standalone, before nginx starts).
    # The nginx config carries no secret (the key lands under the cert dir, never in this file),
    # so — exactly like the secdns zone — it's refreshed unconditionally, so a redeploy after a
    # topology.toml change (a fronted service added/moved) takes effect immediately.
    if "secproxy" in services and addr_dir is not None:
        for sub, desc in ((SECPROXY_CERT_DIR, "cert dir"),
                          (VAR / "secproxy" / "acme", "ACME-challenge webroot"),
                          (VAR / "secproxy" / "tmp", "nginx temp/runtime dir")):
            steps.append((
                ["install", "-d", "-m", "750", "-o", "secsuite-secproxy", "-g", "secsuite-secproxy",
                 str(sub)],
                f"secproxy {desc} {sub}",
            ))
        steps.append((
            ["install", "-m", "644", "-o", "secsuite-secproxy", "-g", "secsuite-secproxy",
             str(addr_dir / "secproxy.nginx.conf"), str(SECPROXY_NGINX_CONF)],
            f"install generated nginx config → {SECPROXY_NGINX_CONF}",
        ))
        if topology is not None:
            steps += _issue_secproxy_cert(topology, without)
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
    native_services: bool = True,
) -> None:
    # native_services is a macOS-only knob (launchd install vs. print) — fedora-fips is always
    # systemd-native, so it's accepted for calling-convention parity with macos.deploy() and
    # otherwise ignored (same pattern as the macOS-only --tls/--configure-hosts flags above).
    del native_services
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
    steps = _deploy_steps(manifest, work, root, services, addr_dir=addr_dir,
                          topology=topology, without=without)
    # secproxy's SecCert-issued SAN cert is minted at deploy time by certbot --standalone (see
    # _issue_secproxy_cert) — a bootstrap-ordering assumption worth surfacing, not just burying in
    # a step. HTTP-01 needs :80 free (nginx not started yet — the cert step is ordered ahead of
    # `enable --now secsuite.target`) AND SecCert reachable + this host's resolver pointed at
    # secdns so the fronted FQDNs resolve here. On a fresh first deploy where SecCert isn't
    # configured yet, issuance is non-fatal and nginx fails closed until a redeploy re-issues.
    secproxy_cert_note = (
        "secproxy TLS: certbot mints one SAN cert from SecCert for the fronted FQDNs BEFORE nginx "
        "starts (needs :80 free + SecCert reachable + this host's resolver → secdns; use "
        "--configure-resolver). If SecCert isn't up yet the step is non-fatal — nginx stays down "
        "until you redeploy. Renew with `certbot renew` (--webroot the :80 acme dir) + "
        "`nginx -s reload` — see docs/fedora-fips.md#secproxy-edge-reverse-proxy."
    )

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
            drop = str(RESOLVER_DROPIN)
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
        if "secproxy" in services:
            print(f"  · {secproxy_cert_note}")
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
    if "secproxy" in services:
        P.warn(secproxy_cert_note)
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


# ─────────────────────────────────────────────────────────────────────────────────────────
# Teardown — the reverse of deploy(). deploy() is purely ADDITIVE: a narrower redeploy (a
# smaller topology, a dropped --with-inference/--with-agent, a new --without) never removes a
# component that fell out of it — see SERVICES' own comment above. So the LIVE HOST can be a
# superset of any single topology.toml/deploy-flags/out/audit combination. Teardown must
# therefore DISCOVER what THIS host actually has installed and remove exactly that — it must
# NEVER drive off topology.toml, the deploy flags, or out/audit/*.json (the audit JSON may
# only annotate, as an optional drift note printed alongside discovery — see teardown() below
# — never decide what's in the plan).
#
# Split for testability (see tests/test_teardown.py), the same shape targets/macos.py uses:
#   _discover()     — probes the host, returns a FedoraFound. Host-dependent (systemctl/
#                     getent/the filesystem), so it isn't unit-tested directly — every check
#                     tolerates absence instead of raising (a fresh host, a partially torn-
#                     down host, and a host missing systemctl/getent entirely, like this dev
#                     Mac, all just report less "found" — the exact "tolerate absence" spirit
#                     status() above already uses for a health check, applied here to
#                     discovery instead).
#   teardown_plan() — PURE: FedoraFound + purge -> an ordered list of common.Step. No I/O, so
#                     tests exercise it directly with synthetic FedoraFound values — the
#                     ordering/content/--purge-gating logic is fully covered without a real
#                     Fedora host.
#   teardown()      — wires the two together: print the plan (+ a best-effort audit drift
#                     note), stop on --dry-run, else confirm (the main gate, then a SEPARATE
#                     extra-loud one under --purge) and execute.
# ─────────────────────────────────────────────────────────────────────────────────────────

# The suite's only two `kind = "stack"` components today (see suite.toml) — hardcoded here,
# NOT read from a Manifest, because teardown must stay 100% probe-driven: it discovers these
# by checkout path, never by asking a Manifest/Topology what's "supposed to" be a stack here.
STACK_NAMES = ("secsso", "secchat")
ALL_UNIT_NAMES = (*SERVICES, "secsuite.target")


def _unit_file(name: str) -> Path:
    return UNITS / (name if name == "secsuite.target" else f"{name}.service")


@dataclass
class FedoraFound:
    """What a probe of THIS host actually turned up — see the teardown section docstring
    above. Every field is a discovered fact, never a topology/flag-derived assumption."""

    units: list[str]                # names (SERVICES + maybe "secsuite.target") with a unit file present
    users: list[str]                # SERVICES entries whose secsuite-{svc} user exists
    opt_dirs: list[str]             # SERVICES entries with a code dir under OPT
    opt_root_exists: bool           # OPT itself exists
    etc_exists: bool                # the whole ETC (/etc/secsuite) tree exists
    var_dirs: list[str]             # SERVICES entries with a state dir under VAR
    var_root_exists: bool           # VAR itself exists
    anchor_exists: bool             # ANCHORS/secsuite-seccert-root.pem exists
    resolver_dropin_exists: bool    # RESOLVER_DROPIN exists
    stacks: list[tuple[str, Path]]  # (name, bootstrap/<name>.sh path) for each stack checkout found


def _discover(work: Path) -> FedoraFound:
    """Probe this host — never raises. A tool/path that isn't there (getent/systemctl on a
    non-Linux dev box, e.g.) just means less is reported "found", same as status()'s own
    not-Linux branch above."""

    def _user_exists(user: str) -> bool:
        if not P.which("getent"):
            return False
        return P.run(["getent", "passwd", user], check=False, capture=True).returncode == 0

    stacks: list[tuple[str, Path]] = []
    for name in STACK_NAMES:
        boot = work / name / "bootstrap" / f"{name}.sh"
        if boot.exists():
            stacks.append((name, boot))

    return FedoraFound(
        units=[u for u in ALL_UNIT_NAMES if _unit_file(u).exists()],
        users=[svc for svc in SERVICES if _user_exists(f"secsuite-{svc}")],
        opt_dirs=[svc for svc in SERVICES if (OPT / svc).is_dir()],
        opt_root_exists=OPT.is_dir(),
        etc_exists=ETC.is_dir(),
        var_dirs=[svc for svc in SERVICES if (VAR / svc).is_dir()],
        var_root_exists=VAR.is_dir(),
        anchor_exists=(ANCHORS / "secsuite-seccert-root.pem").is_file(),
        resolver_dropin_exists=RESOLVER_DROPIN.is_file(),
        stacks=stacks,
    )


def teardown_plan(found: FedoraFound, purge: bool) -> list[common.Step]:
    """Pure: the ordered reverse-actions for exactly what ``found`` reports — never consults
    the topology, deploy flags, or the audit JSON (see the teardown section docstring above).
    Order matches docs/fedora-fips.md#teardown exactly: services, users, code, config, data
    (--purge only — nothing under VAR is ever even MENTIONED without --purge), trust anchor,
    resolver, stacks, then a fixed "not removed" packages note.
    """
    steps: list[common.Step] = []

    # 1. services — stop everything BEFORE anything is deleted (a running unit's User=
    #    mustn't be removed out from under it; rm-ing a unit file that's still
    #    enabled/running just invites a confusing half-state). rm the unit files before the
    #    daemon-reload that makes systemd forget them.
    if found.units:
        if "secsuite.target" in found.units:
            steps.append(common.Step(
                "disable + stop secsuite.target (PartOf= cascades the stop to every member unit)",
                ["systemctl", "disable", "--now", "secsuite.target"], "services",
            ))
        for u in found.units:
            steps.append(common.Step(f"stop {u}", ["systemctl", "stop", u], "services"))
            steps.append(common.Step(
                f"unmask {u} (an operator may have masked it — see secrecorder.env.example)",
                ["systemctl", "unmask", u], "services",
            ))
        for u in found.units:
            steps.append(common.Step(
                f"remove unit file {_unit_file(u)}", ["rm", "-f", str(_unit_file(u))], "services",
            ))
        steps.append(common.Step(
            "reload systemd unit definitions", ["systemctl", "daemon-reload"], "services",
        ))

    # 2. users — AFTER services are stopped. No -r: the state dir is handled separately,
    #    below, gated on --purge (decoupling user removal from data removal).
    for svc in found.users:
        user = f"secsuite-{svc}"
        steps.append(common.Step(
            f"remove user {user} (no -r — state dir is handled separately, under --purge)",
            ["userdel", user], "users",
        ))

    # 3. code — always (rebuildable from the pinned checkouts).
    for svc in found.opt_dirs:
        steps.append(common.Step(
            f"remove code dir {OPT / svc}", ["rm", "-rf", str(OPT / svc)], "code",
        ))
    if found.opt_root_exists:
        steps.append(common.Step(f"remove {OPT} if now empty", ["rmdir", str(OPT)], "code"))

    # 4. config — always, but every *.env here may hold operator-typed secrets with no
    #    backup anywhere else (unlike the SecLLM/SecAgent tokens wiring.py caches under
    #    out/addressing, these are hand-typed and never generated/cached).
    if found.etc_exists:
        steps.append(common.Step(
            f"WARNING: {ETC} holds operator-typed secrets with no backup elsewhere — "
            "SECCERT_CA_PASSPHRASE, SECCERT_ADMIN_TOKEN, SECAGENT_CLIENT_SECRET, "
            "SECAGENT_MATTERMOST__BOT_TOKEN in the *.env files — copy it aside first if "
            "you'll need any of them again", None, "config",
        ))
        steps.append(common.Step(f"remove config dir {ETC}", ["rm", "-rf", str(ETC)], "config"))

    # 5. data — --purge ONLY. Nothing under VAR is mentioned at all otherwise.
    if purge and found.var_dirs:
        callouts = []
        if "seccert" in found.var_dirs:
            callouts.append(
                "the SecCert CA private key + passphrase — invalidates every cert it has "
                "issued and the trust anchor already distributed to clients"
            )
        if "secagent" in found.var_dirs:
            callouts.append("the SecAgent CMMC audit log (audit.jsonl)")
        if callouts:
            steps.append(common.Step(
                "IRREVERSIBLE — this also destroys: " + "; and ".join(callouts), None, "data",
            ))
        if "secdns" in found.var_dirs:
            steps.append(common.Step(
                f"note: {VAR / 'secdns' / 'secdns.zone'} is regenerable from topology.toml "
                "(not itself a secret) — removed here for completeness, not because it's precious",
                None, "data",
            ))
        for svc in found.var_dirs:
            steps.append(common.Step(
                f"remove state dir {VAR / svc}", ["rm", "-rf", str(VAR / svc)], "data",
            ))
        if found.var_root_exists:
            steps.append(common.Step(f"remove {VAR} if now empty", ["rmdir", str(VAR)], "data"))

    # 6. trust anchor — rm before update-ca-trust (so the extract reflects its removal).
    if found.anchor_exists:
        anchor = ANCHORS / "secsuite-seccert-root.pem"
        steps.append(common.Step(
            f"remove the trust anchor {anchor}", ["rm", "-f", str(anchor)], "trust anchor",
        ))
        steps.append(common.Step(
            "refresh the system trust store", ["update-ca-trust", "extract"], "trust anchor",
        ))

    # 7. resolver — rm the drop-in before restarting the resolver.
    if found.resolver_dropin_exists:
        steps.append(common.Step(
            f"remove resolver drop-in {RESOLVER_DROPIN}",
            ["rm", "-f", str(RESOLVER_DROPIN)], "resolver",
        ))
        steps.append(common.Step(
            "restart systemd-resolved to apply", ["systemctl", "restart", "systemd-resolved"], "resolver",
        ))
        steps.append(common.Step(
            "this reverts DNS host-wide — if another host still points its resolver at this "
            "one for the suite's domain, reverting strands it (operator's call)", None, "resolver",
        ))

    # 8. stacks (SecSSO/SecChat) — mirrors common.deploy_stacks' own invocation shape.
    for name, boot in found.stacks:
        sub = ["down", "-v"] if purge else ["down"]
        steps.append(common.Step(
            f"stack {name}: bring down via bootstrap/{name}.sh {' '.join(sub)}"
            + (" (also wipes its data volume)" if purge else " (config + data volume kept)"),
            ["bash", str(boot), *sub], "stacks",
        ))

    # packages — never removed, regardless of --purge or what was found.
    steps.append(common.Step(
        "NOT removed (shared): distro packages this host may have installed for the suite "
        "(nodejs/npm, uv, nginx, certbot, podman) and the global npm package "
        "@earendil-works/pi-coding-agent — remove manually if you're sure nothing else on "
        "this host depends on them (an interactive `pi` session in particular needs the npm "
        "package)", None, "packages",
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
    accepted only for calling-convention symmetry with the CLI/macOS's own ``teardown()``
    (which uses it as a best-effort /etc/resolver/<domain> hint) — fedora-fips needs no hint
    from it; every fact this function acts on comes from :func:`_discover`, never from that
    file. ``root`` is likewise unused here (fedora-fips's reverse actions are all absolute
    host paths — no repo asset needs locating) — kept for the same calling-convention parity
    ``status()`` already established (it accepts ``root`` too, and doesn't use it either)."""
    del root, topology  # unused — see docstring
    found = _discover(work)
    plan = teardown_plan(found, purge)
    print(f"# fedora-fips teardown plan — suite {manifest.suite} — probed from THIS host, "
          "not from topology.toml/deploy flags/out/audit (deploy is purely additive, so the "
          "live host may be a superset of any one of those — see docs/fedora-fips.md#teardown)")
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
    if platform.system() != "Linux":
        P.die(f"fedora-fips teardown must run on the Fedora host (this is {platform.system()}). "
              "Use --dry-run to preview.")
    import os

    if os.geteuid() != 0:
        P.die("fedora-fips teardown must run as root (systemd units + /opt,/etc,/var removal)")

    print()
    n = sum(1 for s in plan if s.command)
    if not P.confirm(f"Proceed with fedora-fips teardown ({n} command(s) above)?", assume_yes):
        P.warn("teardown aborted — nothing changed")
        return
    if purge and found.var_dirs:
        if not P.confirm(
            f"--purge: ALSO remove {VAR} state data — including the SecCert CA key/"
            "passphrase and the SecAgent audit log, if present. This cannot be undone. "
            "Proceed?", assume_yes,
        ):
            P.warn(f"--purge declined — {VAR} state data left in place; tearing down everything else")
            purge = False
            plan = teardown_plan(found, purge)
    common.execute_teardown_plan(plan, assume_yes)
    P.log("fedora-fips teardown complete")
