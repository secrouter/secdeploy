"""``secdeploy`` — the suite release/deploy CLI.

Subcommands:
  verify    validate the manifest and that each target's assets are present
  plan      show what a target deploy would do (pinned versions + steps)
  fetch     git clone/checkout every component at its pinned ref into ./work
  build     fetch, then build the target's artifacts into ./out
  bundle    produce an air-gapped release bundle (+ SHA256SUMS)
  deploy    stand the suite up on this host for a target (use --dry-run to preview)
  status    report health of a deployed target
  teardown  remove what a deploy installed on THIS host (discovers what's actually here —
            never trusts topology.toml/deploy flags/the audit JSON; use --dry-run to preview,
            --purge to also remove persistent data)

Optional infra (SecCert, SecSSO) can be dropped with ``--without seccert,secsso`` when you
already run that infrastructure.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import process as P
from . import wiring
from .manifest import Manifest
from .targets import common, fedora_fips, macos

TARGETS = {macos.NAME: macos, fedora_fips.NAME: fedora_fips}
ROADMAP_TARGETS = {
    "fedora-fips-image": "Proxmox-compatible qcow2 / LXC image (see docs/roadmap.md)",
}


def _target_mod(name: str):
    if name in TARGETS:
        return TARGETS[name]
    if name in ROADMAP_TARGETS:
        P.die(f"target {name!r} is on the roadmap, not yet implemented: {ROADMAP_TARGETS[name]}")
    P.die(f"unknown target {name!r}; available: {', '.join(TARGETS)}")


def _root(args) -> Path:
    return Path(args.manifest).resolve().parent


def _without(args) -> list[str]:
    return [s.strip() for s in getattr(args, "without", "").split(",") if s.strip()]


def _expected_assets(root: Path, target: str) -> list[Path]:
    if target == macos.NAME:
        return [root / "deploy/macos/compose.yaml"]
    if target == fedora_fips.NAME:
        d = root / "deploy/fedora-fips"
        return [
            d / "fips-preflight.sh",
            d / "systemd/secsuite.target",
            d / "systemd/secdns.service",
            d / "systemd/seccert.service",
            d / "systemd/secllm.service",
            d / "systemd/secrouter.service",
            d / "systemd/secagent.service",
            d / "systemd/secrecorder.service",
            d / "systemd/secproxy.service",
        ]
    return []


def cmd_verify(args) -> int:
    m = Manifest.load(args.manifest)
    root = _root(args)
    print(f"✓ manifest valid — suite {m.suite} ({m.released}): {m.description}")
    for c in m.components.values():
        opt = "  (optional)" if c.optional else ""
        print(f"    {c.name:<12} {c.ref:<8} {c.kind:<8} {c.repo}{opt}")
    print(f"  optional: {', '.join(m.optionals()) or '(none)'}")
    print(f"  targets:  {', '.join(m.targets) or '(none)'}")
    missing = [
        str(f.relative_to(root))
        for t in m.targets
        for f in _expected_assets(root, t)
        if not f.exists()
    ]
    if missing:
        P.warn("missing target assets:\n    - " + "\n    - ".join(missing))
        return 2
    print("✓ target assets present")
    _verify_topology(args, m)
    return 0


def _verify_topology(args, m: Manifest) -> None:
    """Report the site topology when a topology.toml is present, else note single-host mode."""
    from .topology import Topology

    tpath = Path(args.topology)
    if not tpath.exists():
        print("  topology: none — single-host mode (deploy places every component on this host)")
        return
    topo = Topology.load(tpath, m)  # raises ValueError on an invalid topology → main() dies
    print(f"✓ topology valid — domain {topo.domain}, {len(topo.resources)} resource(s)")
    for rname, r in topo.resources.items():
        placed = ", ".join(topo.components_on(rname)) or "(none)"
        caps = ",".join(r.capabilities) or "-"
        print(f"    {rname:<10} {r.target:<13} {r.address:<15} [{caps}]  ← {placed}")
    for w in topo.warnings:
        P.warn(w)


def cmd_configure(args) -> int:
    from . import configure

    m = Manifest.load(args.manifest)
    return 0 if configure.run(m, dest=args.topology) else 1


def cmd_plan(args) -> int:
    m = Manifest.load(args.manifest)
    mod = _target_mod(args.target)
    t = m.target(args.target)
    without = _without(args)
    topo, from_file = wiring.active_topology(m, args.topology, args.target)
    print(f"suite {m.suite}  →  target {t.name} ({t.kind})")
    print(f"  {t.description}\n")

    if from_file:
        resource = wiring.resource_for(topo, args.target, args.resource)
        print(f"  topology {args.topology} — this deploy targets resource "
              f"{resource!r} ({topo.resources[resource].address})\n")
        print("  placement:")
        for rname, r in topo.resources.items():
            marker = "→" if rname == resource else " "
            comps = ", ".join(topo.components_on(rname, without)) or "(none)"
            print(f"   {marker} {rname:<10} {r.target:<12} {r.address:<15} {comps}")
        selected = topo.components_on(resource, without)
        print(f"\n  components on {resource!r} (pinned):")
    else:
        selected = m.select(without)
        print("  topology: none — single-host mode (every component on this host)\n")
        print("  components (pinned):")

    for c in selected.values():
        tags = [x for x in ("stack" if c.kind == "stack" else "", "optional" if c.optional else "") if x]
        suffix = f"  ({', '.join(tags)})" if tags else ""
        print(f"    - {c.name} @ {c.ref}   [{c.runtime or c.kind}]   {c.role}{suffix}")
    elsewhere = [n for n in m.components if n not in selected]
    if elsewhere:
        label = "not on this resource / dropped" if from_file else "dropped (--without)"
        print(f"  {label}: {', '.join(elsewhere)}")
    print("\n  steps:")
    for i, step in enumerate(mod.PLAN, 1):
        print(f"    {i}. {step}")
    return 0


def cmd_fetch(args) -> int:
    m = Manifest.load(args.manifest)
    selected = m.select(_without(args))
    common.fetch(m, Path(args.work), only=args.component, include=set(selected))
    return 0


def cmd_build(args) -> int:
    m = Manifest.load(args.manifest)
    mod = _target_mod(args.target)
    without = _without(args)
    common.fetch(m, Path(args.work), include=set(m.select(without)))
    mod.build(m, Path(args.work), Path(args.out), root=_root(args), without=without)
    return 0


def cmd_bundle(args) -> int:
    from . import bundle

    m = Manifest.load(args.manifest)
    bundle.build_bundle(m, args.target, Path(args.work), Path(args.out),
                        root=_root(args), without=_without(args),
                        topology_path=args.topology, resource=args.resource)
    return 0


def cmd_deploy(args) -> int:
    m = Manifest.load(args.manifest)
    mod = _target_mod(args.target)
    without = _without(args)
    topo, from_file = wiring.active_topology(m, args.topology, args.target)
    if getattr(args, "ssh", False):
        if not from_file:
            P.die("--ssh needs a topology.toml defining resources with ssh endpoints")
        from . import remote
        remote.ssh_deploy(m, args.target, args.topology, topo, Path(args.work), Path(args.out),
                          _root(args), without=without, dry_run=args.dry_run)
        return 0
    resource = wiring.resource_for(topo, args.target, args.resource) if from_file else None
    mod.deploy(
        m, Path(args.work), root=_root(args), dry_run=args.dry_run,
        tls=args.tls, configure_hosts=args.configure_hosts,
        trust_ca=args.trust_ca, assume_yes=args.yes,
        hf_token=args.hf_token, model_dir=args.model_dir,
        without=without, configure_resolver=args.configure_resolver,
        topology=topo if from_file else None, resource=resource, out=Path(args.out),
        with_inference=args.with_inference, with_agent=args.with_agent,
    )
    return 0


def cmd_status(args) -> int:
    m = Manifest.load(args.manifest)
    mod = _target_mod(args.target)
    mod.status(m, root=_root(args))
    return 0


def cmd_teardown(args) -> int:
    m = Manifest.load(args.manifest)
    mod = _target_mod(args.target)
    mod.teardown(
        m, work=Path(args.work), root=_root(args), dry_run=args.dry_run,
        purge=args.purge, assume_yes=args.yes, topology=args.topology, out=Path(args.out),
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secdeploy", description=__doc__.splitlines()[0])
    p.add_argument("--manifest", default="suite.toml", help="release manifest (default: suite.toml)")
    p.add_argument("--work", default="work", help="checkout/build work dir (default: ./work)")
    p.add_argument("--out", default="out", help="artifact/bundle output dir (default: ./out)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def _without_arg(sp):
        sp.add_argument("--without", default="",
                        help="comma-separated optional components to drop (e.g. seccert,secsso)")

    def _topology_arg(sp):
        sp.add_argument("--topology", default="topology.toml",
                        help="site placement file (optional; single-host mode if absent)")

    def _resource_arg(sp):
        sp.add_argument("--resource",
                        help="topology resource this action targets (default: auto-detect by target)")

    vp = sub.add_parser("verify", help="validate manifest + target assets")
    _topology_arg(vp)
    vp.set_defaults(fn=cmd_verify)

    cp = sub.add_parser("configure", help="interactively write a topology.toml (resources + placement)")
    _topology_arg(cp)  # doubles as the destination path
    cp.set_defaults(fn=cmd_configure)

    for name in ("plan", "build", "deploy", "status"):
        sp = sub.add_parser(name, help=f"{name} a target")
        sp.add_argument("target", help="deploy target (e.g. macos, fedora-fips)")
        sp.set_defaults(fn=globals()[f"cmd_{name}"])
        if name != "status":
            _without_arg(sp)
        if name in ("plan", "build", "deploy"):
            _topology_arg(sp)
            _resource_arg(sp)
    sub.choices["deploy"].add_argument(
        "--dry-run", action="store_true", help="print the steps without executing them"
    )
    sub.choices["deploy"].add_argument(
        "--tls", action="store_true",
        help="macOS only: issue SecRecorder a SecCert cert via certbot and print its TLS run command",
    )
    sub.choices["deploy"].add_argument(
        "--configure-hosts", action="store_true",
        help="macOS only: map host.docker.internal to 127.0.0.1 in /etc/hosts (sudo, asks "
             "first — see -y/--yes), so host-side clients can use the --tls cert's hostname",
    )
    sub.choices["deploy"].add_argument(
        "--trust-ca", action="store_true",
        help="macOS only: trust the SecCert root in the System keychain (sudo, asks first — "
             "see -y/--yes), so browsers/curl stop flagging SecRecorder's cert as untrusted",
    )
    sub.choices["deploy"].add_argument(
        "-y", "--yes", action="store_true",
        help="grant blanket consent up front for --configure-hosts/--trust-ca's confirmation "
             "prompts (still runs sudo, which prompts for your password separately)",
    )
    sub.choices["deploy"].add_argument(
        "--hf-token",
        help="macOS only: Hugging Face token for the gated diarizer model, for SecRecorder's "
             "printed run command. Overrides deploy/macos/secrets.env if both are set.",
    )
    sub.choices["deploy"].add_argument(
        "--model-dir",
        help="macOS only, for air-gapped hosts: a local directory with pre-downloaded model "
             "snapshots at <dir>/whisper and <dir>/diarizer, used in place of Hugging Face "
             "repo IDs in SecRecorder's printed run command — see docs/macos.md",
    )
    sub.choices["deploy"].add_argument(
        "--ssh", action="store_true",
        help="control-host mode: build each resource's bundle, rsync it to that resource's ssh "
             "endpoint, and deploy remotely (needs ssh endpoints in topology.toml)",
    )
    sub.choices["deploy"].add_argument(
        "--configure-resolver", action="store_true", dest="configure_resolver",
        help="point this host's resolver at secdns for the internal domain (macOS /etc/resolver, "
             "Fedora systemd-resolved) — asks first; the multi-host replacement for --configure-hosts",
    )
    sub.choices["deploy"].add_argument(
        "--with-inference", action="store_true", dest="with_inference",
        help="also stand up SecLLM on every resource where the inference tier is placed here "
             "(default: off — the DNS/env wiring for SecLLM's backend pool is always generated; "
             "this additionally installs + starts the secllm service). fedora-fips only; macOS "
             "prints a native run command instead (see docs/macos.md)",
    )
    sub.choices["deploy"].add_argument(
        "--with-agent", action="store_true", dest="with_agent",
        help="also stand up SecAgent's Mattermost chat-ops bridge (`secagent chat serve`) on "
             "the resource where the collab tier is placed here (default: off — the peer-wiring "
             "env pointing SecAgent's LLM traffic at SecRouter is always generated; this "
             "additionally installs pi + secagent and starts the secagent service). "
             "fedora-fips only; macOS prints a native note instead (see docs/fedora-fips.md)",
    )

    tp = sub.add_parser(
        "teardown",
        help="remove what a deploy installed on this host — discovers what's actually here, "
             "never trusts topology.toml/deploy flags/the audit JSON (see docs)",
    )
    tp.add_argument("target", help="deploy target (e.g. macos, fedora-fips)")
    tp.add_argument(
        "--dry-run", action="store_true",
        help="print the discovered plan and stop — touches nothing",
    )
    tp.add_argument(
        "--purge", action="store_true",
        help="also remove persistent DATA (/var/lib/secsuite, or the seccert-data compose "
             "volume) — IRREVERSIBLE: destroys the SecCert CA key + any audit log. Asks a "
             "SEPARATE, extra-loud confirmation naming exactly what's lost",
    )
    tp.add_argument(
        "-y", "--yes", action="store_true",
        help="skip confirmation prompts (for automation) — including the --purge one and, on "
             "macOS, the /etc/hosts line's own confirmation",
    )
    tp.add_argument(
        "--topology", default="topology.toml",
        help="site placement file (optional). NOT used to decide what's installed (teardown "
             "always discovers that) — used ONLY as a best-effort hint for which "
             "/etc/resolver/<domain> entry to remove on macOS, when more than one exists",
    )
    tp.set_defaults(fn=cmd_teardown)

    fp = sub.add_parser("fetch", help="checkout components at pinned refs")
    fp.add_argument("--component", help="only fetch this component")
    _without_arg(fp)
    fp.set_defaults(fn=cmd_fetch)

    bp = sub.add_parser("bundle", help="produce an air-gapped release bundle")
    bp.add_argument("target", help="deploy target")
    _without_arg(bp)
    _topology_arg(bp)
    _resource_arg(bp)
    bp.set_defaults(fn=cmd_bundle)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.fn(args) or 0)
    except (ValueError, KeyError, FileNotFoundError) as exc:
        P.die(str(exc))
    except KeyboardInterrupt:  # pragma: no cover
        P.die("interrupted", code=130)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
