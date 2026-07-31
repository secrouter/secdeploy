"""``secdeploy`` — the suite release/deploy CLI.

Subcommands:
  verify   validate the manifest and that each target's assets are present
  plan     show what a target deploy would do (pinned versions + steps)
  fetch    git clone/checkout every component at its pinned ref into ./work
  build    fetch, then build the target's artifacts into ./out
  bundle   produce an air-gapped release bundle (+ SHA256SUMS)
  deploy   stand the suite up on this host for a target (use --dry-run to preview)
  status   report health of a deployed target
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import process as P
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


def _expected_assets(root: Path, target: str) -> list[Path]:
    if target == macos.NAME:
        return [root / "deploy/macos/compose.yaml"]
    if target == fedora_fips.NAME:
        d = root / "deploy/fedora-fips"
        return [
            d / "fips-preflight.sh",
            d / "systemd/secsuite.target",
            d / "systemd/seccert.service",
            d / "systemd/secrouter.service",
            d / "systemd/secrecorder.service",
        ]
    return []


def cmd_verify(args) -> int:
    m = Manifest.load(args.manifest)
    root = _root(args)
    print(f"✓ manifest valid — suite {m.suite} ({m.released}): {m.description}")
    for c in m.components.values():
        print(f"    {c.name:<12} {c.ref:<10} {c.repo}")
    print(f"  targets: {', '.join(m.targets) or '(none)'}")
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
    return 0


def cmd_plan(args) -> int:
    m = Manifest.load(args.manifest)
    mod = _target_mod(args.target)
    t = m.target(args.target)
    print(f"suite {m.suite}  →  target {t.name} ({t.kind})")
    print(f"  {t.description}\n")
    print("  components (pinned):")
    for c in m.components.values():
        print(f"    - {c.name} @ {c.ref}   [{c.runtime}]   {c.role}")
    print("\n  steps:")
    for i, step in enumerate(mod.PLAN, 1):
        print(f"    {i}. {step}")
    return 0


def cmd_fetch(args) -> int:
    m = Manifest.load(args.manifest)
    common.fetch(m, Path(args.work), only=args.component)
    return 0


def cmd_build(args) -> int:
    m = Manifest.load(args.manifest)
    mod = _target_mod(args.target)
    common.fetch(m, Path(args.work))
    mod.build(m, Path(args.work), Path(args.out), root=_root(args))
    return 0


def cmd_bundle(args) -> int:
    from . import bundle

    m = Manifest.load(args.manifest)
    bundle.build_bundle(m, args.target, Path(args.work), Path(args.out), root=_root(args))
    return 0


def cmd_deploy(args) -> int:
    m = Manifest.load(args.manifest)
    mod = _target_mod(args.target)
    mod.deploy(
        m, Path(args.work), root=_root(args), dry_run=args.dry_run,
        tls=args.tls, configure_hosts=args.configure_hosts,
    )
    return 0


def cmd_status(args) -> int:
    m = Manifest.load(args.manifest)
    mod = _target_mod(args.target)
    mod.status(m, root=_root(args))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secdeploy", description=__doc__.splitlines()[0])
    p.add_argument("--manifest", default="suite.toml", help="release manifest (default: suite.toml)")
    p.add_argument("--work", default="work", help="checkout/build work dir (default: ./work)")
    p.add_argument("--out", default="out", help="artifact/bundle output dir (default: ./out)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("verify", help="validate manifest + target assets").set_defaults(fn=cmd_verify)

    for name in ("plan", "build", "deploy", "status"):
        sp = sub.add_parser(name, help=f"{name} a target")
        sp.add_argument("target", help="deploy target (e.g. macos, fedora-fips)")
        sp.set_defaults(fn=globals()[f"cmd_{name}"])
    sub.choices["deploy"].add_argument(
        "--dry-run", action="store_true", help="print the steps without executing them"
    )
    sub.choices["deploy"].add_argument(
        "--tls", action="store_true",
        help="macOS only: issue SecRecorder a SecCert cert via certbot and print its TLS run command",
    )
    sub.choices["deploy"].add_argument(
        "--configure-hosts", action="store_true",
        help="macOS only: map host.docker.internal to 127.0.0.1 in /etc/hosts (sudo), "
             "so host-side clients can use the --tls cert's hostname",
    )

    fp = sub.add_parser("fetch", help="checkout components at pinned refs")
    fp.add_argument("--component", help="only fetch this component")
    fp.set_defaults(fn=cmd_fetch)

    bp = sub.add_parser("bundle", help="produce an air-gapped release bundle")
    bp.add_argument("target", help="deploy target")
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
