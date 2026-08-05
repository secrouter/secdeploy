"""Topology-driven deploy wiring — the bridge from the site topology to the targets.

This module turns a :class:`~secdeploy.topology.Topology` into the concrete things a deploy
needs: *which resource am I*, *which components run here*, and the **addressing artifacts** —
the ``secdns`` zone file and the per-component peer-URL env files. It is deliberately free of
any target/OS specifics so it can be unit-tested and reused by every target.

Backward compatibility: when no ``topology.toml`` exists, :func:`active_topology` synthesizes
a single-host topology (everything on this box, addresses at loopback), so a plain
``secdeploy deploy macos`` behaves exactly as it did before topologies existed. :func:`active_site`
is the newer, ``secsite.toml``-aware sibling ``cmd_deploy`` (and verify/plan/bundle) actually
use — it falls all the way back through a bare ``topology.toml`` to this same single-host
synthesis, so everything documented above still holds.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from .manifest import Manifest
from .site import SiteConfig
from .topology import Topology

# This suite's internal-CUI classification level — the default `authorizedClassifications`
# for the SecRouter egress rule secrouter_egress_rules() builds (see there). Override per call
# for a different/broader classification ladder (checkEgress does an exact membership check,
# not a hierarchical one — see secrouter_egress_rules' docstring).
DEFAULT_EGRESS_CLASSIFICATIONS = ["CUI"]


def active_topology(
    manifest: Manifest,
    topology_path: str | Path,
    target: str,
    address: str = "127.0.0.1",
) -> tuple[Topology, bool]:
    """Return ``(topology, from_file)``.

    Loads ``topology_path`` if it exists; otherwise synthesizes a single-host topology on
    ``target`` (reproducing the pre-topology, everything-on-this-host behavior).
    """
    path = Path(topology_path)
    if path.exists():
        return Topology.load(path, manifest), True
    return Topology.single_host(manifest, target, address=address), False


def active_site(
    manifest: Manifest,
    site_path: str | Path | None,
    topology_path: str | Path,
    target: str,
    address: str = "127.0.0.1",
) -> tuple[SiteConfig, bool]:
    """Return ``(site, from_file)`` — the unified site config, resolved in precedence order:

    1. ``site_path`` (``--site``), if given — an EXPLICIT path must exist; a missing/invalid
       file raises rather than silently falling through to a name the operator didn't ask for
       (same fail-loud contract a bad ``--topology`` already has);
    2. ``secsite.toml`` in the current directory, if present;
    3. ``topology_path`` (``--topology``, default ``topology.toml``), if present — loaded as a
       plain :class:`~secdeploy.topology.Topology` and wrapped with all-default deploy options
       (:meth:`SiteConfig.from_topology`), so a bare topology.toml behaves EXACTLY as it did
       before ``secsite.toml`` existed — this is the back-compat guarantee;
    4. a synthesized single-host SiteConfig (mirrors :func:`active_topology`'s own fallback).

    ``from_file`` is ``False`` only for case 4 — mirrors :func:`active_topology` exactly, so
    every caller that already branches on it (resource selection, "single-host mode" messaging)
    keeps working unchanged whether it's handed a Topology or a SiteConfig.
    """
    if site_path is not None:
        return SiteConfig.load(site_path, manifest), True
    default_site = Path("secsite.toml")
    if default_site.exists():
        return SiteConfig.load(default_site, manifest), True
    topo_path = Path(topology_path)
    if topo_path.exists():
        return SiteConfig.from_topology(Topology.load(topo_path, manifest)), True
    return SiteConfig.single_host(manifest, target, address=address), False


def resource_for(topology: Topology, target: str, explicit: str | None = None) -> str:
    """Pick which resource this invocation acts on.

    ``--resource`` wins; else the unique resource whose ``target`` matches; else, if there is
    only one resource, that one; else an error listing the candidates.
    """
    if explicit:
        if explicit not in topology.resources:
            raise KeyError(
                f"unknown resource {explicit!r}; defined: {', '.join(topology.resources) or '(none)'}"
            )
        return explicit
    matches = [name for name, r in topology.resources.items() if r.target == target]
    if len(matches) == 1:
        return matches[0]
    if len(topology.resources) == 1:
        return next(iter(topology.resources))
    candidates = ", ".join(matches or topology.resources)
    raise ValueError(
        f"could not pick a resource for target {target!r} — candidates: {candidates}. "
        f"Pass --resource <name>."
    )


def _short(fqdn: str, domain: str) -> str:
    suffix = "." + domain
    return fqdn[: -len(suffix)] if fqdn.endswith(suffix) else fqdn


def host_port(url: str) -> str:
    """The ``host:port`` (bare host if the URL carries no explicit port) form of a URL.

    This is what SecRouter's egress choke point actually compares an outbound request's host
    against — ``checkEgress()`` (secrouter/src/security/egress/allowlist.ts) matches ``rule.
    allowedHost`` against JS's ``new URL(url).host``, which includes the port when one is
    present. Deriving an ``EgressRule.allowedHost`` entry with this helper (see
    :func:`secrouter_egress_rules`) guarantees it matches what SecRouter looks up at request
    time — the same reasoning secrouter's own SECROUTER_SECLLM_ENDPOINTS turnkey intake
    documents for its ``hostOf()`` (config.ts ``applySecllmEndpointsIntake``).
    """
    return urlsplit(url).netloc


def zone_text(topology: Topology, without: list[str] | None = None) -> str:
    """Render the whole-suite ``secdns`` zone file (one A record per placed component).

    The zone is suite-wide (not per-resource): a host must be able to resolve peers that live
    on *other* hosts, and secdns — wherever it runs — serves them all.
    """
    lines = [
        f"# secdns zone for {topology.domain}",
        "# generated by secdeploy from the site topology — edit topology.toml, not this file",
    ]
    for fqdn, rtype, addr in topology.zone(without):
        lines.append(f"{_short(fqdn, topology.domain):<28} {rtype:<5} {addr}")
    return "\n".join(lines) + "\n"


def fronted_instances(
    topology: Topology, without: list[str] | None = None
) -> list[tuple[str, str, int]]:
    """Every FRONTED, PLACED ``(fqdn, backend_addr, port)`` secproxy serves — the SINGLE source
    of truth for both :func:`nginx_conf_text` (its :443 ``server`` blocks) and each target's
    certbot SAN ``-d`` names (``targets/*._issue_secproxy_cert``), so the cert always covers
    exactly the names nginx serves. Read directly from :meth:`Topology.instances` + the
    manifest's ``port`` — the same direct-dial pattern :func:`secllm_endpoints`/:func:`host_port`
    use — so nginx's upstream dial bypasses DNS/itself rather than looping through the very front
    door it serves. SecLLM (inference must dial direct) and secdns (not HTTP) are never fronted,
    and secproxy never fronts itself; that's enforced explicitly here, not just via the manifest
    ``fronted`` flag. seccert is excluded by not being ``fronted`` (it's the CA secproxy
    bootstraps its own cert from). Deterministic manifest order, so output is stable/testable;
    empty when nothing in this topology is both fronted and placed.
    """
    selected = topology.manifest.select(without)
    result: list[tuple[str, str, int]] = []
    for name, c in selected.items():
        if name in ("secproxy", "secllm", "secdns"):
            continue
        if not c.port or not topology.is_fronted(name):
            continue
        for instance_name, _res, addr in topology.instances(name):
            result.append((topology.fqdn(instance_name), addr, c.port))
    return result


# nginx runs its writable state (pid, logs, temp dirs, the ACME webroot) out of this dir, which
# the fedora-fips secproxy.service grants via ReadWritePaths under ProtectSystem=strict — so no
# default nginx path (/var/log/nginx, /var/lib/nginx, /run) is ever touched. This is the
# fedora-fips VAR convention (see targets/fedora_fips.py's VAR / "secproxy"); the macOS eval runs
# nginx natively too (see targets/macos.py + docs/macos.md) — hardcoding it here is fine, only
# cert_dir varies.
_NGINX_STATE_DIR = "/var/lib/secsuite/secproxy"


def nginx_conf_text(topology: Topology, cert_dir: str, without: list[str] | None = None) -> str:
    """Render the nginx config secproxy serves — the suite's one HTTPS front door (:443) for its
    FRONTED HTTP services (the ``fronted`` manifest flag; see :meth:`Topology.is_fronted`). nginx
    is the reverse-proxy runtime on BOTH targets: on fedora-fips it links the **system OpenSSL**,
    which is FIPS-validated in FIPS mode (the reason the suite standardized on nginx over a Go-TLS
    proxy); macOS runs the same nginx natively for a non-FIPS eval (see ``targets/macos.py`` +
    docs/macos.md).

    nginx does NOT issue its own certs: SecDeploy issues one SAN cert covering all fronted FQDNs
    from SecCert via certbot and installs it at ``cert_dir`` (fedora passes
    ``/etc/secsuite/secproxy``) — every fronted server block below reads that same
    ``cert_dir/{fullchain,privkey}.pem`` (see each target's ``_issue_secproxy_cert``). The output
    is a COMPLETE nginx configuration (``events``/``http`` blocks, pid/logs/temp under the state
    dir), run as ``nginx -c <this file> -g 'daemon off;'``.

    Contents:

    * a ``map $http_upgrade $connection_upgrade`` block, for WebSocket upgrade support
      (SecChat/SecRecorder need it) — the ``proxy_set_header Upgrade/Connection`` pair in each
      site block references it;
    * a **port-80** server for the fronted FQDNs: an ``/.well-known/acme-challenge/`` webroot
      (certbot renewal writes challenges there) plus a blanket ``301`` redirect to HTTPS;
    * one **:443** ``server`` block per FRONTED, PLACED component instance (see
      :func:`fronted_instances`), proxying straight to its real ``host:port`` so nginx's upstream
      dial bypasses DNS/itself rather than looping back through the very front door it's serving.
      Each carries the standard ``X-Forwarded-*``/``X-Real-IP``/``Host`` reverse-proxy headers and
      the WebSocket ``Upgrade``/``Connection`` pair.

    Deterministic manifest order, so the output is stable/testable.
    """
    fronted = fronted_instances(topology, without)
    lines = [
        "# nginx config for secproxy — generated by secdeploy from the site topology",
        "# edit topology.toml, not this file",
        "#",
        "# A COMPLETE nginx configuration: nginx -c <this file> -g 'daemon off;' (fedora-fips",
        "# installs it to /etc/secsuite/nginx-secproxy.conf — see secproxy.service). nginx does",
        "# the suite's edge TLS termination via the system OpenSSL (FIPS-validated in FIPS mode);",
        "# the SAN cert covering every fronted name is issued from SecCert by SecDeploy (certbot).",
        "worker_processes auto;",
        f"pid {_NGINX_STATE_DIR}/nginx.pid;",
        f"error_log {_NGINX_STATE_DIR}/error.log;",
        "",
        "events {",
        "\tworker_connections 1024;",
        "}",
        "",
        "http {",
        "\t# ProtectSystem=strict makes nginx's default /var/log/nginx, /var/lib/nginx and /run",
        "\t# paths read-only — keep every writable path inside the service state dir (granted by",
        "\t# secproxy.service's ReadWritePaths), so no default nginx temp/log/pid path is touched.",
        f"\taccess_log {_NGINX_STATE_DIR}/access.log;",
        f"\tclient_body_temp_path {_NGINX_STATE_DIR}/tmp/client_body;",
        f"\tproxy_temp_path {_NGINX_STATE_DIR}/tmp/proxy;",
        f"\tfastcgi_temp_path {_NGINX_STATE_DIR}/tmp/fastcgi;",
        f"\tuwsgi_temp_path {_NGINX_STATE_DIR}/tmp/uwsgi;",
        f"\tscgi_temp_path {_NGINX_STATE_DIR}/tmp/scgi;",
        "",
        "\t# WebSocket upgrade support (SecChat/SecRecorder need it) — referenced by the",
        "\t# proxy_set_header Upgrade/Connection pair in every site block below.",
        "\tmap $http_upgrade $connection_upgrade {",
        "\t\tdefault upgrade;",
        "\t\t'' close;",
        "\t}",
        "",
    ]
    if fronted:
        server_names = " ".join(fqdn for fqdn, _addr, _port in fronted)
        lines += [
            "\t# Port 80: the ACME HTTP-01 webroot (certbot renewal writes challenges under this",
            "\t# root) plus a blanket redirect of everything else to HTTPS.",
            "\tserver {",
            "\t\tlisten 80;",
            "\t\tlisten [::]:80;",
            f"\t\tserver_name {server_names};",
            "",
            "\t\tlocation /.well-known/acme-challenge/ {",
            f"\t\t\troot {_NGINX_STATE_DIR}/acme;",
            "\t\t}",
            "",
            "\t\tlocation / {",
            "\t\t\treturn 301 https://$host$request_uri;",
            "\t\t}",
            "\t}",
            "",
        ]
    for fqdn, addr, port in fronted:
        lines += [
            "\tserver {",
            "\t\tlisten 443 ssl;",
            "\t\thttp2 on;",
            f"\t\tserver_name {fqdn};",
            "",
            f"\t\tssl_certificate {cert_dir}/fullchain.pem;",
            f"\t\tssl_certificate_key {cert_dir}/privkey.pem;",
            "",
            "\t\tlocation / {",
            f"\t\t\tproxy_pass http://{addr}:{port};",
            "\t\t\tproxy_http_version 1.1;",
            "\t\t\tproxy_set_header Host $host;",
            "\t\t\tproxy_set_header X-Real-IP $remote_addr;",
            "\t\t\tproxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
            "\t\t\tproxy_set_header X-Forwarded-Proto $scheme;",
            "\t\t\tproxy_set_header Upgrade $http_upgrade;",
            "\t\t\tproxy_set_header Connection $connection_upgrade;",
            "\t\t}",
            "\t}",
            "",
        ]
    lines.append("}")
    return "\n".join(lines).rstrip() + "\n"


def env_text(
    topology: Topology, component: str, without: list[str] | None = None, *,
    secllm_token: str | None = None, secrouter_egress_file: str | None = None,
    secagent_webhook_secret: str | None = None,
) -> str:
    """Render one component's peer-wiring env file (``SEC_DOMAIN``, ``SELF_*``, ``<PEER>_URL``).

    ``secllm_token``/``secrouter_egress_file`` (``component == "secrouter"``) and
    ``secagent_webhook_secret`` (``component == "secagent"``) are passed straight through to
    :meth:`Topology.env_for` — see there.
    """
    env = topology.env_for(
        component, without, secllm_token=secllm_token, secrouter_egress_file=secrouter_egress_file,
        secagent_webhook_secret=secagent_webhook_secret,
    )
    lines = [f"# {component} peer wiring — generated by secdeploy from the site topology"]
    lines += [f"{k}={v}" for k, v in env.items()]
    return "\n".join(lines) + "\n"


def secllm_endpoints(topology: Topology, without: list[str] | None = None) -> list[str]:
    """Every SecLLM instance's OpenAI-compatible base URL (``https://<fqdn>:<port>/v1``) — the
    backend pool SecRouter reads as ``SECROUTER_SECLLM_ENDPOINTS`` (also set automatically in
    ``env_for("secrouter")``/``env_text``). SecLLM is stateless, so N instances need no
    coordination — one URL per resource the inference tier is placed on."""
    return topology.instance_urls("secllm", without, path="/v1")


def secrouter_egress_rules(
    topology: Topology, without: list[str] | None = None, *,
    classifications: list[str] | None = None,
) -> list[dict[str, object]]:
    """SecRouter ``EgressRule`` object(s) authorizing this deployment's SecLLM backend pool.

    Matches ``secrouter/src/security/types.ts``'s ``EgressRule`` shape EXACTLY — ``provider``,
    ``allowedHost`` (``string | string[]``), ``authorizedClassifications`` (``string[]``,
    *not* a single "classification" — ``checkEgress`` does an exact membership check against
    it, not a hierarchical one, so every classification that may reach this rule needs to be
    listed), and the optional ``authorization`` audit-trail note. This is the JSON array
    :func:`write_addressing` writes to ``secrouter-egress.json`` for SecRouter's
    ``SECROUTER_EGRESS_FILE`` to load directly as (or into) ``security.egress.allowlist`` — an
    explicit, deploy-time-declared authorization, alongside (not a replacement for) SecRouter's
    own implicit ``SECROUTER_SECLLM_ENDPOINTS`` turnkey intake (config.ts
    ``applySecllmEndpointsIntake``), which authorizes the same hosts if this file isn't loaded.

    One rule, provider ``"secllm"``: ``allowedHost`` lists every pool instance's ``host:port``
    (see :func:`host_port` — the exact form ``checkEgress`` compares against, so this rule is
    guaranteed to match what SecRouter looks up at request time). ``authorizedClassifications``
    defaults to :data:`DEFAULT_EGRESS_CLASSIFICATIONS` (this suite's internal-CUI level);
    override for a different/broader ladder.

    Empty when there's no SecLLM instance in this topology (nothing to authorize) — e.g. a
    manifest/topology with no ``secllm`` component at all.
    """
    hosts = [host_port(u) for u in secllm_endpoints(topology, without)]
    if not hosts:
        return []
    return [{
        "provider": "secllm",
        "allowedHost": hosts,
        "authorizedClassifications": (
            list(classifications) if classifications else list(DEFAULT_EGRESS_CLASSIFICATIONS)
        ),
        "authorization": (
            "Self-hosted SecLLM inference pool inside the accreditation boundary — "
            "auto-authorized by secdeploy from the site topology (see out/audit/)."
        ),
    }]


def secrouter_oidc_config(
    topology: Topology, without: list[str] | None = None,
) -> dict[str, object]:
    """The ``security.oidc`` fragment SecRouter needs once SecSSO runs with
    ``issuer_mode: global`` — matches ``secrouter/src/security/types.ts``'s ``OidcConfig``
    shape exactly (``issuer``, ``audience``, ``jwksUri``, ``serviceSubjects``).

    NOT env-var-driven in SecRouter today (unlike ``SECROUTER_SECLLM_ENDPOINTS``'s turnkey
    intake) — SecRouter's ``FREEROUTER_CONFIG`` is a hand-authored JSON file, so this fragment
    is meant to be read and merged into ``security.oidc`` there by the operator (see
    :func:`write_addressing`, which writes it to ``secrouter-oidc.json`` for exactly that).

    Values mirror secsso's own ``bootstrap/secsso.sh oidc-config``/``secagent-config`` output
    exactly, so the two never disagree: ``issuer``/``jwksUri`` are derived from SecSSO's
    topology address (``https://secsso.<domain>:<port>/`` — same base :func:`secllm_endpoints`-
    style derivation every other cross-component URL in this module uses; if your SecSSO's own
    external URL differs from that convention, e.g. a reverse proxy on a different port, adjust
    accordingly). ``audience`` is the SecRouter client id (``"secrouter"``). ``serviceSubjects``
    always includes ``"svc-secagent"`` — SecAgent's non-interactive service account, which
    otherwise trips ``requireMfa`` (client_credentials tokens can't carry an MFA assertion).

    Empty when SecSSO isn't in this topology at all (nothing to configure).
    """
    secsso_url = topology.urls(without).get("SECSSO")
    if not secsso_url:
        return {}
    issuer = f"{secsso_url}/"
    return {
        "issuer": issuer,
        "audience": "secrouter",
        "jwksUri": f"{issuer}application/o/secrouter/jwks/",
        "serviceSubjects": ["svc-secagent"],
    }


def secagent_pi_models_json(
    example: dict[str, object], secrouter_base_url: str,
) -> dict[str, object]:
    """Adapt secagent's ``pi/models.secrouter.example.json`` for pi's SERVICE (api-key) auth
    mode — the one ``secagent chat serve``'s host uses system-wide, distinct from the
    example's own per-user OAuth device-code mode (``pi/extensions/secrouter-auth.ts``,
    ``/login secrouter``). Two changes only: every provider's ``baseUrl`` becomes
    ``secrouter_base_url`` (replacing the example's ``<domain>`` placeholder), and every
    provider gets ``apiKey: "!secagent token"`` — secagent's own SecSSO-backed service token,
    resolved fresh at each request (see ``secagent``'s ``secretval.py``/``secsso.py``); this is
    a command string, never a stored secret, safe to write into a generated file.

    Everything else — the model catalog, ``_comment`` — passes through UNCHANGED. In
    particular this only ever touches provider entries the example itself already defines, so
    it can never introduce a provider (e.g. pi's built-in Kimi) that wasn't already there.
    """
    result = json.loads(json.dumps(example))  # stdlib-only deep copy
    providers = result.get("providers")
    if isinstance(providers, dict):
        for provider in providers.values():
            if isinstance(provider, dict):
                if isinstance(provider.get("baseUrl"), str):
                    provider["baseUrl"] = secrouter_base_url
                provider["apiKey"] = "!secagent token"
    return result


def secagent_webhook_secret(out_dir: str | Path) -> str:
    """The Mattermost slash-command/outgoing-webhook shared secret ``secagent chat serve``
    checks inbound deliveries against (``SECAGENT_MATTERMOST__WEBHOOK_SECRET``).

    Generated once via :func:`secrets.token_urlsafe` and cached at
    ``<out_dir>/secagent-webhook-secret`` — reused on every later call/redeploy rather than
    minted fresh, so it never rotates out from under a value the operator has already
    registered as the token on Mattermost's slash-command/outgoing-webhook definition (a
    manual step — see docs/fedora-fips.md; secdeploy has no Mattermost API access to register
    it there itself). Unlike :func:`secllm_shared_token`, this needs no cross-*resource*
    coordination (SecAgent is a single instance), only cross-*redeploy* stability — same
    mechanism, smaller problem.
    """
    path = Path(out_dir) / "secagent-webhook-secret"
    if path.exists():
        existing = path.read_text().strip()
        if existing:
            return existing
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n")
    return token


def secllm_shared_token(out_dir: str | Path) -> str:
    """The ONE bearer token SecRouter and every SecLLM instance share to authenticate to each
    other (``SECLLM_API_TOKEN`` in :func:`secllm_env_text`, ``SECROUTER_SECLLM_TOKEN`` in
    SecRouter's env via :meth:`Topology.env_for`).

    Unlike ``SECLLM_ADMIN_TOKEN`` (independently random per instance — every SecLLM instance is
    stateless and needs no coordination with its peers, see :func:`secllm_env_text`), this ONE
    value must be IDENTICAL everywhere it appears — including across the separate
    ``secdeploy deploy`` invocations that stand up each SecLLM instance's own resource and
    SecRouter's, possibly at different times. secdeploy has no shared control-plane state across
    those independent processes, so the coordination point is a small cache file at
    ``<out_dir>/secllm-shared-token`` (``out_dir`` is normally the shared ``addressing``
    directory under one deploy's ``--out``): the first call — from whichever resource happens to
    deploy first — generates a fresh :func:`secrets.token_urlsafe` value and persists it there;
    every later call, same run or a later redeploy, reads it back instead of minting a new one,
    so a live pair's token is never rotated out from under it (the same non-clobber spirit as
    the admin token's install-time ``test -f ... || install ...`` guard — see
    ``targets/fedora_fips.py``).
    """
    path = Path(out_dir) / "secllm-shared-token"
    if path.exists():
        existing = path.read_text().strip()
        if existing:
            return existing
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n")
    return token


def secdns_address_for(topology: Topology, resource: str,
                       without: list[str] | None = None) -> str | None:
    """The address ``resource`` should point its resolver at to reach secdns.

    Loopback when secdns runs on this same resource, otherwise the secdns host's address;
    ``None`` when secdns isn't deployed in this topology at all.
    """
    dns_res = topology.placement(without).get("secdns")
    if dns_res is None:
        return None
    return "127.0.0.1" if dns_res == resource else topology.resources[dns_res].address


def secdns_env_text(topology: Topology, zone_path: str) -> str:
    """Render the ``secdns`` service env (domain / upstream / zone) from the topology."""
    return (
        "# secdns — generated by secdeploy from the site topology\n"
        f"SECDNS_DOMAIN={topology.domain}\n"
        f"SECDNS_ZONE={zone_path}\n"
        f"SECDNS_UPSTREAM={','.join(topology.upstream_dns)}\n"
        "SECDNS_PORT=53\n"
        "SECDNS_ADMIN_BIND=127.0.0.1\n"
        "SECDNS_ADMIN_PORT=47053\n"
    )


def secllm_env_text(admin_token: str | None = None, api_token: str | None = None) -> str:
    """Render one SecLLM instance's env (host/port/backend/tokens) for ``--with-inference``.

    Unlike ``secdns_env_text`` (safe to regenerate every deploy — it carries no secret), the
    fedora-fips install guards the copy of this file with a ``test -f`` so a redeploy doesn't
    rotate a live token out from under an already-running instance; ``admin_token``/
    ``api_token`` let a caller (or a test) pin the values instead of a fresh
    :func:`secrets.token_urlsafe` each call.

    Two distinct tokens, two distinct sharing rules:

    - ``admin_token`` (``SECLLM_ADMIN_TOKEN``) — this instance's own admin surface. Every
      SecLLM instance is independent and stateless, so distinct per-instance values are fine —
      they need no coordination with each other.
    - ``api_token`` (``SECLLM_API_TOKEN``) — the ONE bearer token SecRouter uses to
      authenticate to *every* instance in the pool (``SECROUTER_SECLLM_TOKEN`` in SecRouter's
      own generated env — see :meth:`Topology.env_for`). Unlike the admin token, this value
      must be IDENTICAL across every instance; callers should pass the same
      :func:`secllm_shared_token` result into each instance's ``secllm_env_text`` call rather
      than letting each mint its own (which would leave SecRouter unable to authenticate to
      more than one of them).
    """
    token = admin_token if admin_token is not None else secrets.token_urlsafe(32)
    api = api_token if api_token is not None else secrets.token_urlsafe(32)
    return (
        "# secllm — generated by secdeploy (--with-inference); kept across redeploys\n"
        "SECLLM_HOST=0.0.0.0\n"
        "SECLLM_PORT=11400\n"
        "SECLLM_BACKEND=vllm\n"
        f"SECLLM_ADMIN_TOKEN={token}\n"
        f"SECLLM_API_TOKEN={api}\n"
        "# Autostart the backend on boot instead of lazy first-request load; uncomment to enable.\n"
        "# SECLLM_AUTOSTART=1\n"
    )


def write_addressing(
    topology: Topology,
    out_dir: str | Path,
    resource: str,
    without: list[str] | None = None,
    *,
    secrouter_egress_path: str | None = None,
) -> dict[str, object]:
    """Write the addressing artifacts for ``resource`` into ``out_dir``.

    Produces ``<out_dir>/secdns.zone`` (the suite-wide zone) and ``<out_dir>/env/<c>.env`` for
    every component placed on ``resource``. When SecRouter is placed on ``resource`` and this
    topology has a non-empty SecLLM pool, additionally produces ``<out_dir>/secrouter-egress.
    json`` (see :func:`secrouter_egress_rules`) and folds two more values into SecRouter's own
    env: ``SECROUTER_EGRESS_FILE`` — ``secrouter_egress_path`` if given (a target's real
    installed path, e.g. ``/etc/secsuite/secrouter-egress.json`` on fedora-fips), else this
    staging path — and ``SECROUTER_SECLLM_TOKEN`` (the shared SecRouter<->SecLLM bearer token,
    see :func:`secllm_shared_token` — cached under ``out_dir`` so it agrees with every SecLLM
    instance's own ``secllm_env_text(api_token=...)`` call, wherever/whenever that runs, as
    long as they share the same ``--out``). When SecRouter is placed on ``resource`` and SecSSO
    is anywhere in the topology, also writes ``<out_dir>/secrouter-oidc.json`` (see
    :func:`secrouter_oidc_config`) — a documented fragment for the operator to merge, not an
    installed/consumed file (SecRouter has no env-var turnkey for OIDC). When SecAgent is
    placed on ``resource``, its own env additionally gets ``SECAGENT_MATTERMOST__WEBHOOK_
    SECRET`` (see :func:`secagent_webhook_secret`, cached the same way). When secproxy is
    placed on ``resource``, also writes ``<out_dir>/secproxy.nginx.conf`` (see
    :func:`nginx_conf_text`, cert dir ``/etc/secsuite/secproxy``) — secproxy's reverse-proxy
    config for the topology's fronted services (installed on fedora-fips, pointed at natively on
    macOS; both targets run nginx). It is resource-specific like the egress/OIDC files above
    (only the resource secproxy itself runs on needs it), unlike the suite-wide zone. Returns the
    written paths — note that these last are
    generated purely from topology PLACEMENT, the same as everything else here, independent of
    whether a target's ``--with-inference``/``--with-agent`` flag actually installs the
    corresponding service (see ``targets/fedora_fips.py``).
    """
    rdir = Path(out_dir)
    (rdir / "env").mkdir(parents=True, exist_ok=True)
    zone_path = rdir / "secdns.zone"
    zone_path.write_text(zone_text(topology, without))

    token = secllm_shared_token(rdir)
    placed = topology.components_on(resource, without)

    egress_path: Path | None = None
    oidc_path: Path | None = None
    if "secrouter" in placed:
        rules = secrouter_egress_rules(topology, without)
        if rules:
            egress_path = rdir / "secrouter-egress.json"
            egress_path.write_text(json.dumps(rules, indent=2) + "\n")
        oidc = secrouter_oidc_config(topology, without)
        if oidc:
            oidc_path = rdir / "secrouter-oidc.json"
            oidc_path.write_text(json.dumps(oidc, indent=2) + "\n")

    agent_secret = secagent_webhook_secret(rdir) if "secagent" in placed else None

    nginx_conf_path: Path | None = None
    if "secproxy" in placed:
        # secproxy's generated nginx config for the topology's fronted services — installed on
        # fedora-fips, and pointed at natively on macOS (both targets run nginx; see targets/).
        nginx_conf_path = rdir / "secproxy.nginx.conf"
        nginx_conf_path.write_text(nginx_conf_text(topology, "/etc/secsuite/secproxy", without))

    env_paths: dict[str, Path] = {}
    for name in placed:
        ep = rdir / "env" / f"{name}.env"
        if name == "secrouter":
            egress_file = secrouter_egress_path or (str(egress_path) if egress_path else None)
            ep.write_text(env_text(
                topology, name, without, secllm_token=token, secrouter_egress_file=egress_file
            ))
        elif name == "secagent":
            ep.write_text(env_text(topology, name, without, secagent_webhook_secret=agent_secret))
        else:
            ep.write_text(env_text(topology, name, without))
        env_paths[name] = ep

    result: dict[str, object] = {"zone": zone_path, "env": env_paths}
    if egress_path is not None:
        result["egress"] = egress_path
    if oidc_path is not None:
        result["oidc"] = oidc_path
    if nginx_conf_path is not None:
        result["nginx_conf"] = nginx_conf_path
    return result
