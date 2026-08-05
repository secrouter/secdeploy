"""Interactive ``secdeploy configure`` — write a ``secsite.toml`` by answering a few questions.

Builds a validated :class:`~secdeploy.site.SiteConfig` — placement (compute resources + tier
placement, exactly like the ``topology.toml``-only wizard before it) PLUS the deploy options
that used to be CLI-flags-only (the suite-wide ``[deploy].without``, and each resource's own
``with_inference``/``with_agent``/``configure_resolver``/``tls``/``configure_hosts``/
``trust_ca``/``model_dir``) — and writes it via :meth:`SiteConfig.to_toml`. Presets cover the
common shapes (single host, GPU split); ``custom`` lets you define resources and place each
tier yourself. Every per-resource deploy question is asked ONLY when it actually applies to
that resource (what's placed there / its target) — see :func:`_ask_deploy_options`.

Optionally (asked once, after ``secsite.toml`` is written) also seeds operator-typed secrets —
SecCert's admin token/CA passphrase, SecAgent's SecSSO client secret/Mattermost bot token,
SecRecorder's Hugging Face token, SecRouter's ``FREEROUTER_CONFIG`` path — into the gitignored
``*.env`` files. Secrets NEVER go in ``secsite.toml``: see :func:`_maybe_seed_secrets`.

Pure standard library (``getpass`` for the secret prompts, so nothing echoes to the terminal);
every I/O seam (input/output/getpass) is injectable so the whole flow is unit-testable.
"""

from __future__ import annotations

import getpass
import re
from pathlib import Path
from typing import Callable

from .manifest import Manifest
from .site import DeployOptions, SiteConfig
from .topology import DEFAULT_DOMAIN, Resource, Topology

# Tiers, in the order we place them (and the order the suite naturally layers in).
TIER_ORDER = ["identity", "inference", "gateway", "collab", "edge"]
# Tiers that may spread across several resources (N-way placement) — currently just inference
# (N SecLLM instances); the rest are single-resource-only in the wizard.
MULTI_RESOURCE_TIERS = {"inference"}


def _ask(input_fn: Callable[[str], str], prompt: str, default: str = "") -> str:
    raw = input_fn(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return raw or default


def _ask_choice(input_fn, out, prompt: str, choices: list[str], default: str) -> str:
    while True:
        raw = _ask(input_fn, f"{prompt} ({'/'.join(choices)})", default)
        if raw in choices:
            return raw
        out(f"  please choose one of: {', '.join(choices)}")


def _ask_multi_choice(input_fn, out, prompt: str, choices: list[str], default: str) -> list[str]:
    """Like :func:`_ask_choice` but accepts a comma-separated list — for a tier spread across
    several resources (e.g. inference → gpu1, gpu2). A single choice yields a one-element list."""
    while True:
        raw = _ask(input_fn, f"{prompt} ({'/'.join(choices)}, comma-separated for multiple)", default)
        picked = [n.strip() for n in raw.split(",") if n.strip()]
        bad = [n for n in picked if n not in choices]
        if picked and not bad:
            return picked
        out(f"  please choose one or more of: {', '.join(choices)}"
            + (f" (unknown: {', '.join(bad)})" if bad else ""))


def _ask_yn(input_fn: Callable[[str], str], prompt: str, default: bool) -> bool:
    """A y/n question with a boolean default — the same ``(y/N)``/``(Y/n)`` convention the
    wizard's overwrite-confirm prompt already used before this module grew per-resource deploy
    toggles; any answer other than y/yes reads as "no", so a blank line accepts the default."""
    hint, d = ("Y/n", "Y") if default else ("y/N", "N")
    return _ask(input_fn, f"{prompt} ({hint})", d).lower() in ("y", "yes")


def _ask_resource_fields(input_fn, out, manifest: Manifest, name: str,
                         target_default: str, caps_default: str = "") -> Resource:
    """Ask everything but the name for a resource (name already decided by the caller)."""
    target = _ask_choice(input_fn, out, "  deploy target", list(manifest.targets), target_default)
    address = _ask(input_fn, "  address (IP/hostname peers use)", "127.0.0.1")
    ssh = _ask(input_fn, "  ssh endpoint for remote push (blank = none)", "")
    caps = _ask(input_fn, "  capabilities, comma-separated (e.g. gpu,fips)", caps_default)
    return Resource(
        name=name, target=target, address=address, ssh=ssh,
        capabilities=[c.strip() for c in caps.split(",") if c.strip()],
    )


def _ask_resource(input_fn, out, manifest: Manifest, name_default: str,
                  target_default: str, caps_default: str = "") -> Resource:
    name = _ask(input_fn, "  resource name", name_default)
    return _ask_resource_fields(input_fn, out, manifest, name, target_default, caps_default)


def _ask_edge_placement(input_fn, out, resource_names: list[str], default: str) -> list[str]:
    """Where (if anywhere) to place the ``edge`` tier (secproxy) — one of ``resource_names``,
    or ``"none"`` to skip it entirely (edge, like identity, is all-optional infra). Defaults to
    ``default`` — the common case is one HTTPS front door on the core/front host. Used to close
    the gpu-split preset's edge gap (single-host already places edge on its one resource;
    custom already asks placement for every tier including edge via the loop below)."""
    choices = list(resource_names) + ["none"]
    pick = _ask_choice(input_fn, out, "  edge (secproxy) →", choices, default)
    return [] if pick == "none" else [pick]


def _ask_without(input_fn, out, manifest: Manifest) -> list[str]:
    """Suite-wide optional components to DROP because the operator already runs that
    infrastructure elsewhere (own CA/IdP/DNS/reverse-proxy) — ``[deploy].without``. Default is
    to drop nothing; a blank answer is valid (unlike :func:`_ask_multi_choice`, which requires
    at least one pick)."""
    optionals = manifest.optionals()
    if not optionals:
        return []
    out("\nOptional infrastructure — drop anything you already run elsewhere (default: keep "
        "everything):")
    while True:
        raw = _ask(input_fn, f"  drop ({'/'.join(optionals)}, comma-separated, blank = none)", "")
        picked = [n.strip() for n in raw.split(",") if n.strip()]
        bad = [n for n in picked if n not in optionals]
        if not bad:
            return picked
        out(f"  please choose from: {', '.join(optionals)} (unknown: {', '.join(bad)})")


def _placed_tiers(groups: dict[str, list[str]], resource: str) -> set[str]:
    return {tier for tier, res_list in groups.items() if resource in res_list}


def _ask_deploy_options(
    input_fn: Callable[[str], str], r: Resource, groups: dict[str, list[str]],
    secdns_deployed: bool,
) -> DeployOptions:
    """Ask only the per-resource deploy toggles that actually apply to ``r`` — gated on what
    tier is placed here (``with_inference``/``with_agent``) and on ``r.target`` (the macOS-only
    toggles) — see the WAVE 2 task notes / :mod:`secdeploy.site`'s ``DeployOptions`` docstring
    for what each one does. A resource nothing applies to (e.g. secdns dropped, no macOS
    resource, no inference/collab here) is asked NOTHING and keeps every field at its default —
    exactly like a resource in a hand-authored secsite.toml that never mentions these keys."""
    tiers = _placed_tiers(groups, r.name)
    opts = DeployOptions()
    if "inference" in tiers:
        opts.with_inference = _ask_yn(
            input_fn, f"  [{r.name}] install + start SecLLM here now? (else secdeploy just "
            "generates the wiring for an externally-run instance)", False,
        )
    if "collab" in tiers:
        opts.with_agent = _ask_yn(
            input_fn, f"  [{r.name}] install + start SecAgent's Mattermost chat bridge here now?",
            False,
        )
    if secdns_deployed:
        opts.configure_resolver = _ask_yn(
            input_fn, f"  [{r.name}] point this host's resolver at SecDNS?", True,
        )
    if r.target == "macos":
        opts.tls = _ask_yn(
            input_fn, f"  [{r.name}] issue SecRecorder a SecCert cert via certbot (--tls)?", False,
        )
        opts.configure_hosts = _ask_yn(
            input_fn, f"  [{r.name}] map host.docker.internal to 127.0.0.1 in /etc/hosts?", False,
        )
        opts.trust_ca = _ask_yn(
            input_fn, f"  [{r.name}] trust the SecCert root in the System keychain?", True,
        )
        if "collab" in tiers:
            opts.model_dir = _ask(
                input_fn, f"  [{r.name}] local model dir for air-gapped SecRecorder (blank = "
                "fetch from Hugging Face)", "",
            )
    return opts


def run(
    manifest: Manifest,
    dest: str | Path = "secsite.toml",
    root: str | Path = ".",
    input_fn: Callable[[str], str] = input,
    out: Callable[[str], None] = print,
    getpass_fn: Callable[[str], str] = getpass.getpass,
) -> Path | None:
    """Drive the wizard; write ``dest`` (a ``secsite.toml``) and return it, or ``None`` if
    aborted/invalid. ``root`` locates the ``deploy/{fedora-fips,macos}/*.env.example`` templates
    for the optional secret-seeding step at the end (``cmd_configure`` passes the same root
    every other target action uses — see ``cli._root``)."""
    out("secdeploy configure — describe where the suite runs and how deploy should run it\n")
    domain = _ask(input_fn, "internal DNS domain", DEFAULT_DOMAIN)
    up = _ask(input_fn, "upstream DNS resolvers, comma-separated (blank = closed network)", "")
    upstream = [u.strip() for u in up.split(",") if u.strip()]
    preset = _ask_choice(input_fn, out, "layout", ["single-host", "gpu-split", "custom"], "single-host")

    resources: dict[str, Resource] = {}
    groups: dict[str, list[str]] = {}

    if preset == "single-host":
        out("\nOne host runs everything:")
        r = _ask_resource(input_fn, out, manifest, "local", next(iter(manifest.targets)))
        resources[r.name] = r
        groups = {t: [r.name] for t in TIER_ORDER}
    elif preset == "gpu-split":
        out("\nCore host — identity + gateway + collaboration:")
        core = _ask_resource(input_fn, out, manifest, "core", "fedora-fips", "fips")
        resources[core.name] = core
        out("\nGPU host(s) — inference (comma-separated names for several SecLLM instances, "
            "e.g. gpu1,gpu2):")
        gpu_raw = _ask(input_fn, "  resource name(s)", "gpu")
        gpu_names = [n.strip() for n in gpu_raw.split(",") if n.strip()] or ["gpu"]
        for gname in gpu_names:
            if len(gpu_names) > 1:
                out(f"\nGPU host {gname!r} — inference:")
            gpu = _ask_resource_fields(input_fn, out, manifest, gname, "fedora-fips", "fips,gpu")
            resources[gpu.name] = gpu
        groups = {"identity": [core.name], "gateway": [core.name],
                  "collab": [core.name], "inference": gpu_names}
        out("\nEdge — secproxy, the suite's one HTTPS front door:")
        edge_placement = _ask_edge_placement(input_fn, out, list(resources), core.name)
        if edge_placement:  # omit the tier entirely when skipped — never an empty [groups.edge]
            groups["edge"] = edge_placement
    else:  # custom
        try:
            count = max(1, int(_ask(input_fn, "how many compute resources", "2")))
        except ValueError:
            count = 1
        for i in range(count):
            out(f"\nResource {i + 1}:")
            r = _ask_resource(input_fn, out, manifest, f"host{i + 1}", next(iter(manifest.targets)))
            resources[r.name] = r
        names = list(resources)
        out("\nPlace each tier on a resource:")
        for tier in TIER_ORDER:
            if tier in MULTI_RESOURCE_TIERS:
                groups[tier] = _ask_multi_choice(input_fn, out, f"  {tier} →", names, names[0])
            else:
                groups[tier] = [_ask_choice(input_fn, out, f"  {tier} →", names, names[0])]

    topo = Topology(domain=domain, upstream_dns=upstream, resources=resources,
                    groups=groups, manifest=manifest)
    try:
        topo.validate()
    except ValueError as exc:
        out(f"\n✗ {exc}\n  nothing written — re-run and adjust placement.")
        return None

    without = _ask_without(input_fn, out, manifest)

    secdns_deployed = bool(groups.get("identity")) and "secdns" not in without
    out("\nPer-resource deploy options (only what applies to each resource is asked):")
    deploy_options: dict[str, DeployOptions] = {}
    for r in resources.values():
        out(f"\n{r.name} ({r.target}):")
        deploy_options[r.name] = _ask_deploy_options(input_fn, r, groups, secdns_deployed)

    site = SiteConfig(topology=topo, without=without, ssh=False, deploy_options=deploy_options)
    try:
        site.validate()
    except ValueError as exc:
        out(f"\n✗ {exc}\n  nothing written — re-run and adjust placement.")
        return None

    dest = Path(dest)
    if dest.exists():
        if not _ask_yn(input_fn, f"\n{dest} exists — overwrite?", False):
            out("  aborted — nothing written.")
            return None
    dest.write_text(site.to_toml())
    out(f"\n✓ wrote {dest}")
    for w in topo.warnings:
        out(f"  ! {w}")
    if dest.name == "secsite.toml":
        out("  next: secdeploy verify   (or secdeploy deploy <target> — secsite.toml in the "
            "current directory is picked up automatically)")
    else:
        out(f"  next: secdeploy verify --site {dest}   (or secdeploy deploy <target> --site {dest})")

    _maybe_seed_secrets(site, Path(root), input_fn, out, getpass_fn)
    return dest


# ── optional secret-seeding: operator-typed secrets → the gitignored *.env files ─────────────
# NEVER secsite.toml — see the module docstring. Every value here is asked with getpass (masked,
# nothing echoed) except FREEROUTER_CONFIG, which is a PATH, not a secret.

_ENV_KEY_RE = re.compile(r"^#?\s*([A-Za-z_][A-Za-z0-9_]*)=")


def _fill_env_template(template: str, values: dict[str, str]) -> str:
    """Fill an env-file template: for each key in ``values``, overwrite ITS line — commented or
    not, wherever the template already has one, default value or not — with ``KEY=value``. A
    key the template doesn't mention at all is appended as a new line. Every other line
    (comments, other keys) passes through UNCHANGED, so this only ever touches the keys a value
    was actually entered for."""
    remaining = dict(values)
    lines = template.splitlines() if template else []
    for i, line in enumerate(lines):
        m = _ENV_KEY_RE.match(line)
        if m and m.group(1) in remaining:
            lines[i] = f"{m.group(1)}={remaining.pop(m.group(1))}"
    for key, val in remaining.items():
        lines.append(f"{key}={val}")
    return "\n".join(lines) + "\n"


def _write_env_seeds(
    items: list[tuple[str, str, dict[str, str]]], resources: dict[str, Resource], root: Path,
) -> list[Path]:
    """Group ``(component, resource, values)`` into actual files and write them: one
    ``deploy/fedora-fips/<component>.env`` per fedora-fips component, but every macOS
    component's values share the ONE ``deploy/macos/secrets.env`` — macOS has no per-component
    env plumbing today (see docs/secsite.md). Starts from the DESTINATION file if it already
    exists (so a second `configure` run — or leaving a field blank to mean "keep as-is" — never
    resets an already-seeded value you didn't retype this time), else the shipped
    ``*.env.example``. Blank-answered keys are dropped before grouping, so a component every
    value was skipped for contributes nothing. Written at ``0600``. Returns the distinct paths
    actually written, sorted for stable/testable output."""
    grouped: dict[Path, dict[str, str]] = {}
    example_for: dict[Path, Path] = {}
    for component, resource_name, raw_values in items:
        values = {k: v for k, v in raw_values.items() if v}
        if not values:
            continue
        resource = resources[resource_name]
        if resource.target == "macos":
            dest = root / "deploy/macos/secrets.env"
            example = root / "deploy/macos/secrets.env.example"
        else:
            dest = root / f"deploy/fedora-fips/{component}.env"
            example = root / f"deploy/fedora-fips/{component}.env.example"
        grouped.setdefault(dest, {}).update(values)
        example_for[dest] = example

    written: list[Path] = []
    for dest, values in grouped.items():
        base = dest if dest.exists() else example_for[dest]
        template = base.read_text() if base.exists() else ""
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(_fill_env_template(template, values))
        dest.chmod(0o600)
        written.append(dest)
    return sorted(written)


def _maybe_seed_secrets(
    site: SiteConfig, root: Path,
    input_fn: Callable[[str], str], out: Callable[[str], None],
    getpass_fn: Callable[[str], str],
) -> None:
    """Optionally seed operator-typed secrets into the gitignored ``*.env`` files — NEVER into
    secsite.toml. Declining (the default) touches nothing; this only runs after ``secsite.toml``
    itself was written successfully (an aborted/invalid configure never reaches here)."""
    if not _ask_yn(
        input_fn, "\nSet up the operator secrets now? (else fill in the *.env files yourself "
        "later — see docs/secsite.md)", False,
    ):
        out("  skipped — no *.env file touched.")
        return

    groups = site.topology.groups
    without = site.without
    # (component, resource, {ENV_KEY: value}) — the resource decides which target's env file(s)
    # this lands in (see _write_env_seeds); components with every value left blank contribute
    # nothing once _write_env_seeds filters them out.
    items: list[tuple[str, str, dict[str, str]]] = []

    if groups.get("identity") and "seccert" not in without:
        out("\nSecCert (the internal CA):")
        items.append(("seccert", groups["identity"][0], {
            "SECCERT_CA_PASSPHRASE": getpass_fn(
                "  SECCERT_CA_PASSPHRASE — encrypts the CA key at rest (blank = skip): "),
            "SECCERT_ADMIN_TOKEN": getpass_fn("  SECCERT_ADMIN_TOKEN (blank = skip): "),
        }))

    if groups.get("collab"):
        collab_resource = groups["collab"][0]
        if site.deploy_for(collab_resource).with_agent:
            out("\nSecAgent (Mattermost chat-ops bridge):")
            items.append(("secagent", collab_resource, {
                "SECAGENT_CLIENT_SECRET": getpass_fn(
                    "  SECAGENT_CLIENT_SECRET — SecSSO service-account secret (blank = skip): "),
                "SECAGENT_MATTERMOST__BOT_TOKEN": getpass_fn(
                    "  SECAGENT_MATTERMOST__BOT_TOKEN (blank = skip): "),
            }))
        out("\nSecRecorder (transcription):")
        items.append(("secrecorder", collab_resource, {
            "HF_TOKEN": getpass_fn(
                "  HF_TOKEN — optional, for the gated diarizer model (blank = skip): "),
        }))

    if groups.get("gateway"):
        out("\nSecRouter (governed AI gateway):")
        items.append(("secrouter", groups["gateway"][0], {
            "FREEROUTER_CONFIG": _ask(
                input_fn, "  FREEROUTER_CONFIG — path to a hardened config (not a secret; "
                "blank = leave the example default)", "",
            ),
        }))

    written = _write_env_seeds(items, site.topology.resources, root)
    if not written:
        out("\n  no values entered — nothing written.")
        return
    out("\nwrote operator secrets to (gitignored — never committed, and never in secsite.toml):")
    for p in written:
        out(f"  {p}")
        if p.name == "secrets.env":
            out("    ! macOS reads HF_TOKEN from this file automatically (deploy macos --tls / "
                "--model-dir); any other value just seeded here is for safekeeping until the "
                "macOS target wires it in too (known eval limitation — use fedora-fips for the "
                "automated env layering — see docs/secsite.md).")
