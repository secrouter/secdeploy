"""``deploy --ssh`` — push per-resource bundles to remote hosts and deploy them there.

Opt-in remote orchestration for connected setups (the air-gap default is to carry bundles by
hand — see ``bundle --resource``). From a control host, for each topology resource that
declares an ``ssh`` endpoint *and* matches the target, this builds that resource's air-gap
bundle, ``rsync``s it over, and runs ``secdeploy deploy <target> --resource <name>`` on the far
side. ``--dry-run`` prints the exact runbook without touching anything.
"""

from __future__ import annotations

from pathlib import Path

from . import bundle, process as P
from .manifest import Manifest
from .topology import Topology


def _ssh_resources(topo: Topology, target: str) -> list[tuple[str, object]]:
    return [(name, r) for name, r in topo.resources.items() if r.ssh and r.target == target]


def ssh_deploy(manifest: Manifest, target: str, topology_path: str | Path, topo: Topology,
               work: Path, out: Path, root: Path, without: list[str] | None = None,
               dry_run: bool = False) -> None:
    resources = _ssh_resources(topo, target)
    if not resources:
        P.die(f"--ssh: no {target!r} resource in the topology declares an 'ssh' endpoint "
              f"(add ssh = \"user@host\" to the resource, or deploy locally with a bundle)")
    P.log(f"--ssh: {len(resources)} remote resource(s) for target {target!r}")
    for name, r in resources:
        stem = f"secsuite-{manifest.suite}-{target}-{name}"
        tar_name = f"{stem}.tar.gz"
        remote_cmd = (f"cd /tmp && tar xzf {tar_name} && cd {stem} && "
                      f"sudo uv run secdeploy deploy {target} --resource {name}")
        if dry_run:
            print(f"# resource {name!r} @ {r.address}  (ssh {r.ssh}):")
            print(f"  · build:  secdeploy bundle {target} --resource {name}")
            print(f"  · copy:   rsync -az out/{tar_name} {r.ssh}:/tmp/{tar_name}")
            print(f"  · deploy: ssh {r.ssh} '{remote_cmd}'")
            continue
        tar = bundle.build_bundle(manifest, target, work, out, root, without=without,
                                  topology_path=topology_path, resource=name)
        P.run(["rsync", "-az", str(tar), f"{r.ssh}:/tmp/{tar.name}"])
        P.run(["ssh", r.ssh, remote_cmd])
        P.log(f"deployed resource {name!r} on {r.ssh}")
