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

import html
import json
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from .manifest import Manifest
from .site import SiteConfig, UserSpec
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


def landing_page_html(
    topology: Topology, without: list[str] | None = None, *, setup_actions: list[str] | None = None,
) -> str:
    """A minimal static HTML landing page for secproxy's BARE domain (``topology.domain``) — the
    one URL an operator naturally tries first, with nothing else served there otherwise. Lists
    every fronted service (:func:`fronted_instances`'s same set, HTTPS via secproxy) plus SecLLM
    as a direct HTTP link on its own port (never fronted — inference dials direct, see
    :func:`fronted_instances`'s docstring) — each row shows the component's manifest ``role`` for
    a one-line description — and, if given, a "finish setup" checklist.

    ``setup_actions`` is HTML the CALLER supplies (each string becomes one ``<li>``) rather than
    hardcoded here: the specific follow-up commands (trusting the CA root, the DNS resolver,
    secrets, a chat bootstrap script...) are target/OS-specific, and this module stays free of
    that (see module docstring) — each target builds its own list and passes it in.

    Deterministic manifest order, so output is stable/testable. Only meaningful once secproxy is
    actually placed (nginx is what serves this); an empty topology still renders a valid page
    (no services listed) rather than erroring.
    """
    selected = topology.manifest.select(without)
    services: list[tuple[str, str, str]] = []   # (href, fqdn, role)
    for name, c in selected.items():
        # secagent has no browsable UI here at all (the pi agentic harness — MR review / code
        # analysis, driven by CLI/CI, 404 at "/") — see the GitHub footer below instead.
        if name in ("secproxy", "secdns", "secagent") or not c.port:
            continue
        for instance_name, _res, _addr in topology.instances(name):
            fqdn = topology.fqdn(instance_name)
            if name == "secllm":
                # Never fronted (inference dials direct, see fronted_instances) — plain HTTP,
                # its own port, no secproxy/edge TLS in front of it. /admin is its model console
                # (load/switch models) — nothing useful at "/" itself.
                services.append((f"http://{fqdn}:{c.port}/admin", fqdn, c.role))
            elif topology.is_fronted(name):
                # secrouter has no useful landing page of its own at "/" — its actual UI is
                # the admin console at /admin.
                path = "/admin" if name == "secrouter" else "/"
                services.append((f"https://{fqdn}{path}", fqdn, c.role))

    if services:
        rows = "\n".join(
            f'\t\t<tr><td><a href="{href}">{html.escape(fqdn)}</a></td><td>{html.escape(role)}</td></tr>'
            for href, fqdn, role in services
        )
    else:
        rows = '\t\t<tr><td colspan="2" class="muted">No fronted services in this topology.</td></tr>'

    actions_card = ""
    if setup_actions:
        items = "\n".join(f"\t\t\t<li>{a}</li>" for a in setup_actions)
        actions_card = f"""\t<div class="card">
\t\t<h3>Finish setup</h3>
\t\t<ol class="actions">
{items}
\t\t</ol>
\t</div>
"""

    secagent_footer = ""
    if "secagent" in selected:
        secagent_url = selected["secagent"].url.removesuffix(".git")
        secagent_footer = (
            f'\t<p class="muted footer-note">SecAgent (the pi agentic harness — MR review / '
            f'code analysis) has no browsable UI. Set up a local instance from '
            f'<a href="{html.escape(secagent_url)}">{html.escape(selected["secagent"].repo)}'
            f"</a> on GitHub.</p>\n"
        )

    domain = html.escape(topology.domain)
    # Same "field console" theme as SecRouter's admin UI (secrouter/src/... admin.html) — warm
    # manila/olive-drab light, charcoal/olive dark, following OS by default with a persisted
    # toggle — so this page reads as part of the same suite rather than a bolt-on. Kept as one
    # inline, dependency-free file (no shared asset path across nginx server blocks/targets).
    return f"""<!doctype html>
<html lang="en">
<head>
\t<meta charset="utf-8">
\t<meta name="viewport" content="width=device-width, initial-scale=1">
\t<title>{domain} — SecRouter Suite</title>
\t<style>
\t\t:root {{
\t\t\t--mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
\t\t\t--sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
\t\t\t--bg:#e7e3d8; --panel:#f3f0e8; --panel2:#fbfaf4; --fg:#211f18; --muted:#6c6552;
\t\t\t--accent:#4f6a2e; --accent-ink:#f6f3ea; --accent-soft:rgba(79,106,46,.18);
\t\t\t--border:#cdc6b2; --rule:#dad4c2; --shadow:2px 2px 0 rgba(33,31,24,.06);
\t\t\t--code-bg:#e2ddcd;
\t\t}}
\t\t:root[data-theme="dark"] {{
\t\t\t--bg:#171511; --panel:#201e17; --panel2:#29271e; --fg:#e8e3d3; --muted:#9a9077;
\t\t\t--accent:#94ad50; --accent-ink:#16140e; --accent-soft:rgba(148,173,80,.26);
\t\t\t--border:#3a3730; --rule:#272520; --shadow:2px 2px 0 rgba(0,0,0,.30);
\t\t\t--code-bg:#2b2920;
\t\t}}
\t\t@media (prefers-color-scheme: dark) {{
\t\t\t:root:not([data-theme="light"]) {{
\t\t\t\t--bg:#171511; --panel:#201e17; --panel2:#29271e; --fg:#e8e3d3; --muted:#9a9077;
\t\t\t\t--accent:#94ad50; --accent-ink:#16140e; --accent-soft:rgba(148,173,80,.26);
\t\t\t\t--border:#3a3730; --rule:#272520; --shadow:2px 2px 0 rgba(0,0,0,.30);
\t\t\t\t--code-bg:#2b2920;
\t\t\t}}
\t\t}}
\t\t* {{ box-sizing:border-box; }}
\t\tbody {{ margin:0; font:14px/1.55 var(--sans); background:var(--bg); color:var(--fg);
\t\t       background-image:linear-gradient(var(--rule) 1px, transparent 1px);
\t\t       background-size:100% 28px; background-attachment:fixed; }}
\t\theader {{ display:flex; align-items:center; gap:14px; padding:14px 22px; background:var(--panel);
\t\t         border-bottom:1px solid var(--border); border-top:3px solid var(--accent); }}
\t\theader h1 {{ font-size:15px; margin:0; font-weight:700; text-transform:uppercase; letter-spacing:.14em; }}
\t\theader .lock {{ color:var(--accent); }}
\t\theader .who {{ margin-left:auto; color:var(--muted); font:11px var(--mono);
\t\t              text-transform:uppercase; letter-spacing:.08em; }}
\t\tmain {{ padding:24px 22px; max-width:900px; margin:0 auto; }}
\t\t.card {{ background:var(--panel); border:1px solid var(--border); border-radius:2px;
\t\t         padding:18px; margin-bottom:16px; box-shadow:var(--shadow); }}
\t\t.card h3 {{ margin:0 0 12px; font:11px var(--mono); font-weight:700; text-transform:uppercase;
\t\t           letter-spacing:.12em; color:var(--muted); padding-bottom:8px; border-bottom:1px solid var(--rule); }}
\t\ttable {{ width:100%; border-collapse:collapse; font-size:13px; }}
\t\tth, td {{ text-align:left; padding:7px 10px; border-bottom:1px solid var(--rule); }}
\t\ttd {{ font:12.5px var(--mono); }}
\t\tth {{ color:var(--muted); font:10px var(--mono); font-weight:700; text-transform:uppercase;
\t\t     letter-spacing:.1em; border-bottom:1px solid var(--border); }}
\t\ttr:last-child td {{ border-bottom:none; }}
\t\ta {{ color:var(--accent); text-decoration:none; }}
\t\ta:hover {{ text-decoration:underline; }}
\t\t.muted {{ color:var(--muted); }}
\t\t.footer-note {{ font-size:12px; margin:20px 4px 0; }}
\t\tol.actions {{ margin:0; padding-left:1.3em; }}
\t\tol.actions li {{ margin:.6rem 0; }}
\t\tcode {{ background:var(--code-bg); padding:1px 5px; border-radius:2px; font:12px var(--mono); }}
\t\t.btn.ghost {{ background:var(--panel2); color:var(--fg); border:1px solid var(--border); border-radius:2px;
\t\t             padding:5px 11px; font:11px var(--mono); text-transform:uppercase; letter-spacing:.08em;
\t\t             cursor:pointer; }}
\t\t.btn.ghost:hover {{ filter:brightness(1.08); }}
\t</style>
\t<script>
\t\t/* Apply the saved theme before first paint (no flash). Default = follow OS. */
\t\t(function(){{ try {{ var t = localStorage.getItem('secrouter-theme');
\t\t\tif (t === 'dark' || t === 'light') document.documentElement.setAttribute('data-theme', t); }} catch (e) {{}} }})();
\t</script>
</head>
<body>
\t<header>
\t\t<span class="lock">🔒</span>
\t\t<h1>SecRouter Suite</h1>
\t\t<span class="who">{domain}</span>
\t\t<button class="btn ghost theme-toggle" title="Toggle light / dark" onclick="toggleTheme()">DARK</button>
\t</header>
\t<main>
\t\t<div class="card">
\t\t\t<h3>Services</h3>
\t\t\t<table>
\t\t\t\t<tr><th>Service</th><th>Role</th></tr>
{rows}
\t\t\t</table>
\t\t</div>
{actions_card}{secagent_footer}\t</main>
\t<script>
\t\tfunction effectiveTheme(){{ var a=document.documentElement.getAttribute("data-theme");
\t\t\tif(a==="dark"||a==="light") return a;
\t\t\treturn (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light"; }}
\t\tfunction setTheme(t){{ document.documentElement.setAttribute("data-theme", t);
\t\t\ttry {{ localStorage.setItem("secrouter-theme", t); }} catch(e){{}}
\t\t\tvar b=document.querySelector(".theme-toggle"); if(b) b.textContent = effectiveTheme()==="dark" ? "LIGHT" : "DARK"; }}
\t\tfunction toggleTheme(){{ setTheme(effectiveTheme()==="dark" ? "light" : "dark"); }}
\t\tsetTheme(effectiveTheme());
\t</script>
</body>
</html>
"""


# nginx runs its writable state (pid, logs, temp dirs, the ACME webroot) out of this dir, which
# the fedora-fips secproxy.service grants via ReadWritePaths under ProtectSystem=strict — so no
# default nginx path (/var/log/nginx, /var/lib/nginx, /run) is ever touched. This is the
# fedora-fips VAR convention (see targets/fedora_fips.py's VAR / "secproxy"); the macOS eval runs
# nginx natively too (see targets/macos.py + docs/macos.md) — hardcoding it here is fine, only
# cert_dir varies.
_NGINX_STATE_DIR = "/var/lib/secsuite/secproxy"


def nginx_conf_text(topology: Topology, cert_dir: str, without: list[str] | None = None,
                    *, state_dir: str = _NGINX_STATE_DIR, user: str | None = None) -> str:
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

    ``state_dir`` (nginx's writable pid/log/temp/acme root) and ``user`` (the worker ``user``
    directive) default to the fedora convention — ``/var/lib/secsuite/secproxy`` and no directive
    (systemd's ``User=`` sets it) — so fedora output is byte-identical. The macOS target overrides
    both: a writable dir under the deploy's ``out/`` and the invoking user, since launchd starts
    nginx as root with no user drop of its own (see ``targets/macos.py``).
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
        f"pid {state_dir}/nginx.pid;",
        f"error_log {state_dir}/error.log;",
        "",
        "events {",
        "\tworker_connections 1024;",
        "}",
        "",
        "http {",
        "\t# ProtectSystem=strict makes nginx's default /var/log/nginx, /var/lib/nginx and /run",
        "\t# paths read-only — keep every writable path inside the service state dir (granted by",
        "\t# secproxy.service's ReadWritePaths), so no default nginx temp/log/pid path is touched.",
        f"\taccess_log {state_dir}/access.log;",
        f"\tclient_body_temp_path {state_dir}/tmp/client_body;",
        f"\tproxy_temp_path {state_dir}/tmp/proxy;",
        f"\tfastcgi_temp_path {state_dir}/tmp/fastcgi;",
        f"\tuwsgi_temp_path {state_dir}/tmp/uwsgi;",
        f"\tscgi_temp_path {state_dir}/tmp/scgi;",
        "",
        "\t# WebSocket upgrade support (SecChat/SecRecorder need it) — referenced by the",
        "\t# proxy_set_header Upgrade/Connection pair in every site block below.",
        "\tmap $http_upgrade $connection_upgrade {",
        "\t\tdefault upgrade;",
        "\t\t'' close;",
        "\t}",
        "",
    ]
    # macOS runs nginx under launchd as root (needed for :443/:80), so — unlike fedora, where
    # systemd's User= sets it — the conf itself must name the worker user, or workers default to
    # `nobody` and can't write the state dir. `user` is None on fedora → no directive, output
    # unchanged.
    if user:
        lines.insert(lines.index("worker_processes auto;"), f"user {user};")
    if fronted:
        # The bare domain gets the redirect + landing page (below) alongside every fronted FQDN —
        # it's the one URL an operator naturally tries first, and secproxy's cert covers it too
        # (see each target's _issue_secproxy_cert).
        server_names = " ".join([topology.domain] + [fqdn for fqdn, _addr, _port in fronted])
        lines += [
            "\t# Port 80: the ACME HTTP-01 webroot (certbot renewal writes challenges under this",
            "\t# root) plus a blanket redirect of everything else to HTTPS.",
            "\tserver {",
            "\t\tlisten 80;",
            "\t\tlisten [::]:80;",
            f"\t\tserver_name {server_names};",
            "",
            "\t\tlocation /.well-known/acme-challenge/ {",
            f"\t\t\troot {state_dir}/acme;",
            "\t\t}",
            "",
            "\t\tlocation / {",
            "\t\t\treturn 301 https://$host$request_uri;",
            "\t\t}",
            "\t}",
            "",
            "\t# Landing page: browsing the bare domain directly lists every fronted service +",
            "\t# any finish-setup steps. index.html is written by the target (see deploy()), not",
            "\t# here — this just serves whatever's in <state_dir>/www.",
            "\tserver {",
            "\t\tlisten 443 ssl;",
            "\t\thttp2 on;",
            f"\t\tserver_name {topology.domain};",
            "",
            f"\t\tssl_certificate {cert_dir}/fullchain.pem;",
            f"\t\tssl_certificate_key {cert_dir}/privkey.pem;",
            "",
            f"\t\troot {state_dir}/www;",
            "\t\tindex index.html;",
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
) -> str:
    """Render one component's peer-wiring env file (``SEC_DOMAIN``, ``SELF_*``, ``<PEER>_URL``).

    ``secllm_token``/``secrouter_egress_file`` (``component == "secrouter"``) are passed straight
    through to :meth:`Topology.env_for` — see there.
    """
    env = topology.env_for(
        component, without, secllm_token=secllm_token, secrouter_egress_file=secrouter_egress_file,
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
    urls = topology.urls(without)
    secsso_url = urls.get("SECSSO")
    if not secsso_url:
        return {}
    issuer = f"{secsso_url}/"
    service_subjects = ["svc-secagent"]
    fragment: dict[str, object] = {
        "issuer": issuer,
        "audience": "secrouter",
        "jwksUri": f"{issuer}application/o/secrouter/jwks/",
        "serviceSubjects": service_subjects,
    }
    return fragment


def secagent_pi_models_json(
    example: dict[str, object], secrouter_base_url: str,
) -> dict[str, object]:
    """Adapt secagent's ``pi/models.secrouter.example.json`` for pi's SERVICE (api-key) auth
    mode — the one a non-interactive host (e.g. secagent in CI) uses system-wide, distinct from
    the example's own per-user OAuth device-code mode (``pi/extensions/secrouter-auth.ts``,
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


def sync_secagent_service_secret(
    secsso_env_path: str | Path, secrets_env_path: str | Path,
) -> str | None:
    """Mirror SecSSO's auto-generated ``SECAGENT_SERVICE_CLIENT_SECRET`` (in ``secsso/.env`` —
    seeded by ``targets/common.ensure_stack_secrets``, read by
    ``secsso/blueprints/secagent-service.yaml``'s ``!Env`` to provision the confidential
    ``secagent`` client_credentials provider) into SecAgent's own ``SECAGENT_CLIENT_SECRET``
    (``deploy/macos/secrets.env`` or the fedora-fips equivalent). The two must be the IDENTICAL
    value — ``secagent token``'s client_credentials grant authenticates by comparing its
    ``client_secret`` against exactly what SecSSO's provider was given.

    Only fills a BLANK ``SECAGENT_CLIENT_SECRET=`` line — the same "blank key = fill me"
    convention :func:`~secdeploy.targets.common._seed_env_secrets` uses for the stacks' own
    secrets — so a value an operator (or an earlier sync) already set is never silently
    overwritten. Returns the synced value, or ``None`` if nothing changed: either file is
    missing, SecSSO hasn't generated its secret yet (stack never deployed), or SecAgent's own
    value is already non-blank (including a stale/mismatched one — see the caller's warning).
    """
    secsso_env_path, secrets_env_path = Path(secsso_env_path), Path(secrets_env_path)
    if not secsso_env_path.exists() or not secrets_env_path.exists():
        return None
    secsso_secret = ""
    for line in secsso_env_path.read_text().splitlines():
        if line.strip().startswith("SECAGENT_SERVICE_CLIENT_SECRET="):
            secsso_secret = line.split("=", 1)[1].strip()
            break
    if not secsso_secret:
        return None
    lines = secrets_env_path.read_text().splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "SECAGENT_CLIENT_SECRET=":
            lines[i] = f"SECAGENT_CLIENT_SECRET={secsso_secret}"
            secrets_env_path.write_text("\n".join(lines) + "\n")
            secrets_env_path.chmod(0o600)
            return secsso_secret
    return None


def _read_env_values(env_path: Path) -> dict[str, str]:
    """Parse a ``.env`` into a dict (last wins; comments/blank lines skipped)."""
    values: dict[str, str] = {}
    for line in env_path.read_text().splitlines():
        s = line.lstrip()
        if "=" in s and not s.startswith("#"):
            k, v = s.split("=", 1)
            values[k.strip()] = v.strip()
    return values


def _set_env_keys(env_path: Path, values: dict[str, str]) -> None:
    """Set/overwrite each ``KEY=value`` in ``env_path`` (update the existing line or append),
    preserving every other line, then ``chmod 0600``."""
    lines = env_path.read_text().splitlines()
    remaining = dict(values)
    for i, line in enumerate(lines):
        s = line.lstrip()
        if "=" in s and not s.startswith("#"):
            key = s.split("=", 1)[0].strip()
            if key in remaining:
                lines[i] = f"{key}={remaining.pop(key)}"
    for key, val in remaining.items():
        lines.append(f"{key}={val}")
    env_path.write_text("\n".join(lines) + "\n")
    env_path.chmod(0o600)


# The MANAGED keys secdeploy owns in SecChat's stack .env — mirrored secret from SecSSO +
# topology-derived OIDC/gateway env. Everything else (SECCHAT_SESSION_SECRET, DATABASE_URL's
# own PG_PASSWORD, ...) stays blank/untouched for deploy_stacks' generic seed to fill — see
# secchat's own .env.example.
_SECCHAT_MANAGED_KEYS = frozenset({
    "SECCHAT_OIDC_CLIENT_SECRET", "SECCHAT_OIDC_ISSUER", "SECCHAT_OIDC_AUDIENCE",
    "SECCHAT_OIDC_CLIENT_ID", "SECCHAT_PUBLIC_URL", "SECROUTER_URL",
})


def sync_secchat_env(
    secsso_env_path: str | Path, secchat_env_path: str | Path,
    topology: Topology, without: list[str] | None = None, scheme: str = "https",
) -> list[str] | None:
    """Make the native SecChat's stack ``.env`` turnkey: mirror the OIDC login-client secret SecSSO
    generated and write the topology-derived OIDC/gateway env into ``work/secchat/.env``.

    Unlike :func:`sync_secagent_service_secret`'s blank-only fill, this **overwrites** a fixed set
    of MANAGED keys (:data:`_SECCHAT_MANAGED_KEYS`), because SecChat is a *stack*:
    ``common.deploy_stacks``'s generic ``_seed_env_secrets`` would otherwise fill the blank
    ``SECCHAT_OIDC_CLIENT_SECRET`` with a *random* token that doesn't match SecSSO's provisioned
    client secret. So after the early seed we overwrite: ``SECCHAT_OIDC_CLIENT_SECRET`` ← SecSSO's
    ``SECCHATNG_OIDC_CLIENT_SECRET`` (SecChat's confidential login client — its Authentik client id
    stays ``secchatng`` from the rebuild's transitional phase; the backend runs the Authorization
    Code + PKCE dance itself, server-side, so there's no second client_credentials service secret to
    mirror), plus the ``env_for("secchat")`` topology values (issuer, audience, client id, SecChat's
    own public URL, SecRouter's URL). ``SECCHAT_SESSION_SECRET`` (the session-cookie signing key) is
    deliberately NOT managed here — it stays blank for ``deploy_stacks``' generic seed to fill.

    Returns the sorted list of keys written, or ``None`` if either file is missing or SecSSO
    hasn't generated the secret yet (stack never seeded).
    """
    secsso_env_path, secchat_env_path = Path(secsso_env_path), Path(secchat_env_path)
    if not secsso_env_path.exists() or not secchat_env_path.exists():
        return None
    secsso = _read_env_values(secsso_env_path)
    client_secret = secsso.get("SECCHATNG_OIDC_CLIENT_SECRET", "")
    if not client_secret:
        return None
    managed = dict(topology.env_for("secchat", without, scheme))
    managed["SECCHAT_OIDC_CLIENT_SECRET"] = client_secret
    to_write = {k: v for k, v in managed.items() if k in _SECCHAT_MANAGED_KEYS}
    _set_env_keys(secchat_env_path, to_write)
    return sorted(to_write)


def sync_secsso_secchat_redirect(
    secsso_env_path: str | Path, topology: Topology,
    without: list[str] | None = None, scheme: str = "https",
) -> list[str] | None:
    """Point SecSSO's SecChat OIDC client (client id ``secchatng``) at wherever SecChat is actually
    fronted in THIS topology, by writing ``SECCHATNG_REDIRECT_URI`` + ``SECCHATNG_LAUNCH_URL`` into
    secsso's ``.env`` BEFORE Authentik boots (the counterpart to :func:`sync_secchat_env`, which
    wires the SecChat side). The ``secchatng.yaml`` blueprint reads both via ``!Env``; without this
    they fall back to the ``sec.internal`` default and login fails with ``redirect_uri`` mismatch on
    any topology whose SecChat URL differs (a different domain, or plain http in a proxy-less eval).

    Uses SecChat's own (fronted) URL from :meth:`Topology.urls` — the same value
    ``env_for("secchat")`` derives ``SECCHAT_PUBLIC_URL`` from — so the two sides agree by
    construction: SecChat advertises ``<url>`` as its public URL and builds its callback as
    ``<url>/auth/callback``, and SecSSO registers exactly that. Returns the keys written, or ``None``
    if secsso's ``.env`` is missing or SecChat isn't placed in this topology (nothing to point at).
    """
    secsso_env_path = Path(secsso_env_path)
    if not secsso_env_path.exists():
        return None
    base = topology.urls(without, scheme).get("SECCHAT")
    if not base:
        return None
    base = base.rstrip("/")
    to_write = {"SECCHATNG_REDIRECT_URI": f"{base}/auth/callback", "SECCHATNG_LAUNCH_URL": base}
    _set_env_keys(secsso_env_path, to_write)
    return sorted(to_write)


def _read_generated_user_passwords(path: Path) -> dict[str, str]:
    """Extract ``{username: password}`` from an existing generated users blueprint. Line-based on
    the file's own fixed shape (username in identifiers, password in attrs) — no YAML dep."""
    if not path.exists():
        return {}
    creds: dict[str, str] = {}
    current: str | None = None
    for line in path.read_text().splitlines():
        s = line.strip()
        if s.startswith("username:"):
            current = s.split(":", 1)[1].strip().strip('"')
        elif s.startswith("password:") and current:
            creds[current] = s.split(":", 1)[1].strip().strip('"')
            current = None
    return creds


def _yaml_q(v: str) -> str:
    """Double-quote a YAML scalar (escaping ``\\`` and ``"``)."""
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def generate_secsso_users_blueprint(users: list[UserSpec], dest: str | Path) -> dict[str, str]:
    """Render ``dest`` (``work/secsso/blueprints/users.generated.yaml``) from the declared users —
    an ``authentik_core.group`` (state: present) per referenced group and an ``authentik_core.user``
    (**state: created** — created once, never overwritten, so a later password change is not
    clobbered) per account, each with a RANDOM initial password and ``attributes.reset_password:
    true`` (which ``secsso/blueprints/force-password-reset.yaml`` turns into a forced reset on first
    login).

    Idempotent like the ``.env`` seed: a username already in an existing ``dest`` keeps its password
    (``state: created`` ignores a rotated one anyway; re-printing a stale value would mislead).
    Returns ``{username: initial_password}`` for accounts generated THIS run only — the operator's
    one-time credential handout. Writes ``0600``; ``dest`` is gitignored.
    """
    dest = Path(dest)
    existing = _read_generated_user_passwords(dest)
    new_creds: dict[str, str] = {}
    lines = [
        "# GENERATED by secdeploy from secsite.toml [[users]] — do NOT edit (regenerated each",
        "# deploy). Holds INITIAL passwords: keep secret (0600, gitignored). Requires",
        "# blueprints/force-password-reset.yaml. state: created = create-once, never overwrite.",
        "version: 1",
        "metadata:",
        '  name: "SecSSO — Users (generated)"',
        "entries:",
    ]
    for g in sorted({g for u in users for g in u.groups}):
        lines += [
            "  - model: authentik_core.group",
            "    state: present",
            "    identifiers:",
            f"      name: {_yaml_q(g)}",
            "    attrs:",
            f"      name: {_yaml_q(g)}",
        ]
    for u in users:
        pw = existing.get(u.username) or secrets.token_urlsafe(12)
        if u.username not in existing:
            new_creds[u.username] = pw
        lines += [
            "  - model: authentik_core.user",
            "    state: created",
            "    identifiers:",
            f"      username: {_yaml_q(u.username)}",
            "    attrs:",
            "      type: internal",
            f"      password: {_yaml_q(pw)}",
        ]
        if u.name:
            lines.append(f"      name: {_yaml_q(u.name)}")
        if u.email:
            lines.append(f"      email: {_yaml_q(u.email)}")
        if u.groups:
            lines.append("      groups:")
            for g in u.groups:
                lines.append(f"        - !Find [authentik_core.group, [name, {_yaml_q(g)}]]")
        lines += ["      attributes:", "        reset_password: true"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(lines) + "\n")
    dest.chmod(0o600)
    return new_creds


def secllm_admin_token(out_dir: str | Path) -> str:
    """This SecLLM instance's own admin-surface token (``SECLLM_ADMIN_TOKEN`` — model
    load/switch via ``/admin``; independently random per instance, no cross-instance
    coordination needed, unlike :func:`secllm_shared_token`).

    Cached at ``<out_dir>/secllm-admin-token`` — same generate-once-reuse-forever pattern as
    :func:`secllm_shared_token`, for the same reason: without it, a target that doesn't
    pass ``SECLLM_ADMIN_TOKEN`` explicitly (e.g. targets/macos.py's launchd env) leaves SecLLM
    to generate a fresh one at EVERY process start and only log it (see secllm/config.py) —
    fine for a single session, useless the moment it restarts.
    """
    path = Path(out_dir) / "secllm-admin-token"
    if path.exists():
        existing = path.read_text().strip()
        if existing:
            return existing
    token = secrets.token_urlsafe(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(token + "\n")
    path.chmod(0o600)
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
    path.chmod(0o600)
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


def secllm_env_text(
    admin_token: str | None = None, api_token: str | None = None,
    autostart: list[str] | None = None,
) -> str:
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

    ``autostart`` (``SECLLM_AUTOSTART``) is a list of CATALOG MODEL IDS (e.g. ``["fast",
    "gemma-31b"]``, not a boolean) to load — downloading the weights first, if not already
    cached — the moment the service starts, instead of waiting for the first request routed
    to that model. Empty/``None`` (the default) leaves the line commented out as
    documentation, matching this file's pre-``autostart_models`` behavior.
    """
    token = admin_token if admin_token is not None else secrets.token_urlsafe(32)
    api = api_token if api_token is not None else secrets.token_urlsafe(32)
    autostart_line = (
        f"SECLLM_AUTOSTART={','.join(autostart)}\n" if autostart
        else "# Autostart model(s) at boot instead of lazy first-request load — comma-separated "
             "catalog ids, e.g. fast,reasoning.\n# SECLLM_AUTOSTART=\n"
    )
    return (
        "# secllm — generated by secdeploy (--with-inference); kept across redeploys\n"
        "SECLLM_HOST=0.0.0.0\n"
        "SECLLM_PORT=11400\n"
        "SECLLM_BACKEND=vllm\n"
        f"SECLLM_ADMIN_TOKEN={token}\n"
        f"SECLLM_API_TOKEN={api}\n"
        f"{autostart_line}"
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
    installed/consumed file (SecRouter has no env-var turnkey for OIDC). When secproxy is
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
