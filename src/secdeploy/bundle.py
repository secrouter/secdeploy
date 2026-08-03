"""Air-gapped release bundle — a portable, checksummed tarball.

Run ``fetch`` (and, for macOS, ``build`` to produce image tarballs) on a connected build
host, then ``bundle`` to package the pinned source, the target's deploy assets, and the
SecDeploy CLI itself into one ``.tar.gz`` you can carry into the enclave and ``deploy``.
"""

from __future__ import annotations

import hashlib
import tarfile
from pathlib import Path

from . import process as P
from .manifest import Manifest
from .targets import common


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _bundle_info(manifest: Manifest, target: str, components, shas: dict[str, str]) -> str:
    lines = [
        f"suite:    {manifest.suite}",
        f"released: {manifest.released}",
        f"target:   {target}",
        "components:",
    ]
    for name, c in components.items():
        sha = shas.get(name, "?")
        lines.append(f"  - {name} {c.ref} ({sha[:12]}) {c.repo}")
    lines += [
        "",
        "install:",
        "  1. verify:  sha256sum -c *.sha256",
        "  2. extract: tar xzf secsuite-*.tar.gz && cd secsuite-*",
        f"  3. deploy:  uv run secdeploy deploy {target}   # (root, on the target host)",
    ]
    return "\n".join(lines) + "\n"


def build_bundle(manifest: Manifest, target: str, work: Path, out: Path, root: Path,
                 without: list[str] | None = None) -> Path:
    manifest.target(target)  # validates target exists
    selected = manifest.select(without or [])
    common.require_checkouts(manifest, work, include=set(selected))
    shas = common.resolved_shas(manifest, work)
    out.mkdir(parents=True, exist_ok=True)

    stem = f"secsuite-{manifest.suite}-{target}"
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
        # Bundle info
        info = _bundle_info(manifest, target, selected, shas)
        info_path = out / "BUNDLE-INFO.txt"
        info_path.write_text(info)
        tar.add(info_path, arcname=f"{arc}/BUNDLE-INFO.txt")
        info_path.unlink()

    digest = _sha256(tar_path)
    sums = out / f"{stem}.tar.gz.sha256"
    sums.write_text(f"{digest}  {tar_path.name}\n")
    P.log(f"bundle ready: {tar_path} ({tar_path.stat().st_size // 1024} KiB)")
    P.log(f"checksum:     {sums}  ({digest[:16]}…)")
    return tar_path
