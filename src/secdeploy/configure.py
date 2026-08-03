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
TIER_ORDER = ["identity", "inference", "gateway", "collab"]


def _ask(input_fn: Callable[[str], str], prompt: str, default: str = "") -> str:
    raw = input_fn(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return raw or default


def _ask_choice(input_fn, out, prompt: str, choices: list[str], default: str) -> str:
    while True:
        raw = _ask(input_fn, f"{prompt} ({'/'.join(choices)})", default)
        if raw in choices:
            return raw
        out(f"  please choose one of: {', '.join(choices)}")


def _ask_resource(input_fn, out, manifest: Manifest, name_default: str,
                  target_default: str, caps_default: str = "") -> Resource:
    name = _ask(input_fn, "  resource name", name_default)
    target = _ask_choice(input_fn, out, "  deploy target", list(manifest.targets), target_default)
    address = _ask(input_fn, "  address (IP/hostname peers use)", "127.0.0.1")
    ssh = _ask(input_fn, "  ssh endpoint for remote push (blank = none)", "")
    caps = _ask(input_fn, "  capabilities, comma-separated (e.g. gpu,fips)", caps_default)
    return Resource(
        name=name, target=target, address=address, ssh=ssh,
        capabilities=[c.strip() for c in caps.split(",") if c.strip()],
    )


def run(manifest: Manifest, dest: str | Path = "topology.toml",
        input_fn: Callable[[str], str] = input, out: Callable[[str], None] = print) -> Path | None:
    """Drive the wizard; write ``dest`` and return it, or ``None`` if aborted/invalid."""
    out("secdeploy configure — describe where the suite runs (writes topology.toml)\n")
    domain = _ask(input_fn, "internal DNS domain", DEFAULT_DOMAIN)
    up = _ask(input_fn, "upstream DNS resolvers, comma-separated (blank = closed network)", "")
    upstream = [u.strip() for u in up.split(",") if u.strip()]
    preset = _ask_choice(input_fn, out, "layout", ["single-host", "gpu-split", "custom"], "single-host")

    resources: dict[str, Resource] = {}
    groups: dict[str, str] = {}

    if preset == "single-host":
        out("\nOne host runs everything:")
        r = _ask_resource(input_fn, out, manifest, "local", next(iter(manifest.targets)))
        resources[r.name] = r
        groups = {t: r.name for t in TIER_ORDER}
    elif preset == "gpu-split":
        out("\nCore host — identity + gateway + collaboration:")
        core = _ask_resource(input_fn, out, manifest, "core", "fedora-fips", "fips")
        resources[core.name] = core
        out("\nGPU host — inference:")
        gpu = _ask_resource(input_fn, out, manifest, "gpu", "fedora-fips", "fips,gpu")
        resources[gpu.name] = gpu
        groups = {"identity": core.name, "gateway": core.name,
                  "collab": core.name, "inference": gpu.name}
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
            groups[tier] = _ask_choice(input_fn, out, f"  {tier} →", names, names[0])

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
