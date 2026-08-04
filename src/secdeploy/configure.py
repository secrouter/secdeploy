"""Interactive ``secdeploy configure`` — write a ``topology.toml`` by answering a few questions.

Builds a validated site topology (compute resources + tier→resource placement) and writes it.
Presets cover the common shapes (single host, GPU split); ``custom`` lets you define resources
and place each tier yourself. Pure standard library; the prompt/print callables are injectable
so the whole flow is unit-testable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from .manifest import Manifest
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


def run(manifest: Manifest, dest: str | Path = "topology.toml",
        input_fn: Callable[[str], str] = input, out: Callable[[str], None] = print) -> Path | None:
    """Drive the wizard; write ``dest`` and return it, or ``None`` if aborted/invalid."""
    out("secdeploy configure — describe where the suite runs (writes topology.toml)\n")
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

    dest = Path(dest)
    if dest.exists():
        if _ask(input_fn, f"\n{dest} exists — overwrite? (y/N)", "N").lower() not in ("y", "yes"):
            out("  aborted — nothing written.")
            return None
    dest.write_text(topo.to_toml())
    out(f"\n✓ wrote {dest}")
    for w in topo.warnings:
        out(f"  ! {w}")
    out(f"  next: secdeploy verify --topology {dest}")
    return dest
