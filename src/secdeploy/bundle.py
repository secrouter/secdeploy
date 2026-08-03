"""Air-gapped release bundle — a portable, checksummed tarball.

Run ``fetch`` (and, for macOS, ``build`` to produce image tarballs) on a connected build
host, then ``bundle`` to package the pinned source, the target's deploy assets, and the
SecDeploy CLI itself into one ``.tar.gz`` you can carry into the enclave and ``deploy``.
"""

from __future__ import annotations

import hashlib
import shutil
import tarfile
from pathlib import Path

from . import process as P
from . import wiring
from .manifest import Manifest
from .targets import common
from .topology import Topology


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _bundle_info(manifest: Manifest, target: str, components, shas: dict[str, str],
                 resource: str | None = None) -> str:
    lines = [
        f"suite:    {manifest.suite}",
        f"released: {manifest.released}",
        f"target:   {target}",
    ]
    if resource:
        lines.append(f"resource: {resource}   (per-resource bundle — addressing/ carries the zone + peer env)")
    lines.append("components:")
    for name, c in components.items():
        sha = shas.get(name, "?")
        lines.append(f"  - {name} {c.ref} ({sha[:12]}) {c.repo}")
    deploy_cmd = f"uv run secdeploy deploy {target}" + (f" --resource {resource}" if resource else "")
    lines += [
        "",
        "install:",
        "  1. verify:  sha256sum -c *.sha256",
        "  2. extract: tar xzf secsuite-*.tar.gz && cd secsuite-*",
        f"  3. deploy:  {deploy_cmd}   # (root, on the target host)",
    ]
    return "\n".join(lines) + "\n"


def build_bundle(manifest: Manifest, target: str, work: Path, out: Path, root: Path,
                 without: list[str] | None = None, topology_path: str | Path | None = None,
                 resource: str | None = None) -> Path:
    manifest.target(target)  # validates target exists
    without = without or []
    selected = manifest.select(without)

    # Per-resource bundle: if a topology is present, restrict to the components placed on the
    # chosen resource and carry that resource's addressing artifacts (zone + peer env).
    topo: Topology | None = None
    res: str | None = None
    if topology_path and Path(topology_path).exists():
        topo = Topology.load(topology_path, manifest)
        res = wiring.resource_for(topo, target, resource)
        selected = topo.components_on(res, without)

    common.require_checkouts(manifest, work, include=set(selected))
    shas = common.resolved_shas(manifest, work)
    out.mkdir(parents=True, exist_ok=True)

    stem = f"secsuite-{manifest.suite}-{target}" + (f"-{res}" if res else "")
    tar_path = out / f"{stem}.tar.gz"
    arc = stem  # top-level dir inside the archive

    def _filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        # Slim the source: drop VCS, venvs, caches, node_modules from the checkouts.
        drop = ("/.git/", "/.venv/", "/node_modules/", "/__pycache__/", "/.pytest_cache/")
        p = "/" + info.name
        return None if any(d in p for d in drop) else info

    P.log(f"bundling {tar_path}")
    with tarfile.open(tar_path, "w:gz") as tar:
        # SecDeploy itself (so the bundle is self-contained and runnable)
        for item in ("suite.toml", "pyproject.toml", "README.md", "LICENSE", "NOTICE", "src", "deploy"):
            src = root / item
            if src.exists():
                tar.add(src, arcname=f"{arc}/{item}", filter=_filter)
        # Pinned component source (selected set)
        for name in selected:
            tar.add(work / name, arcname=f"{arc}/work/{name}", filter=_filter)
        # macOS: include any saved image tarballs from `build`
        for img in sorted(out.glob("*.tar")):
            tar.add(img, arcname=f"{arc}/images/{img.name}")
        # Addressing artifacts (topology-driven): the secdns zone + per-component peer env.
        if topo is not None:
            addr_dir = out / "_addr"
            wiring.write_addressing(topo, addr_dir, res, without)
            tar.add(addr_dir / "secdns.zone", arcname=f"{arc}/addressing/secdns.zone")
            tar.add(addr_dir / "env", arcname=f"{arc}/addressing/env")
        # Bundle info
        info = _bundle_info(manifest, target, selected, shas, res)
        info_path = out / "BUNDLE-INFO.txt"
        info_path.write_text(info)
        tar.add(info_path, arcname=f"{arc}/BUNDLE-INFO.txt")
        info_path.unlink()

    if topo is not None:
        shutil.rmtree(out / "_addr", ignore_errors=True)  # artifacts now live inside the tarball

    digest = _sha256(tar_path)
    sums = out / f"{stem}.tar.gz.sha256"
    sums.write_text(f"{digest}  {tar_path.name}\n")
    P.log(f"bundle ready: {tar_path} ({tar_path.stat().st_size // 1024} KiB)")
    P.log(f"checksum:     {sums}  ({digest[:16]}…)")
    return tar_path
