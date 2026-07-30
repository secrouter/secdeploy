"""Load, validate, and (re)write the SecDeploy release manifest (``suite.toml``).

The manifest is the suite "bill of materials": a suite version pinning one compatible
set of component tags plus the deploy-target definitions. Read with the stdlib
``tomllib`` (no third-party deps); written back via a deterministic template.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

TARGET_KINDS = {"compose", "systemd-native", "image"}


@dataclass
class Component:
    name: str
    repo: str  # "org/name" on GitHub
    ref: str  # git tag/branch/sha to pin
    runtime: str = ""
    role: str = ""

    @property
    def url(self) -> str:
        return f"https://github.com/{self.repo}.git"


@dataclass
class Target:
    name: str
    kind: str
    description: str = ""


@dataclass
class Manifest:
    suite: str
    released: str
    description: str
    components: dict[str, Component]
    targets: dict[str, Target]
    path: Path | None = None

    @staticmethod
    def load(path: str | Path) -> "Manifest":
        path = Path(path)
        data = tomllib.loads(path.read_text())
        components = {
            name: Component(
                name=name,
                repo=c["repo"],
                ref=c["ref"],
                runtime=c.get("runtime", ""),
                role=c.get("role", ""),
            )
            for name, c in (data.get("components") or {}).items()
        }
        targets = {
            name: Target(name=name, kind=t["kind"], description=t.get("description", ""))
            for name, t in (data.get("targets") or {}).items()
        }
        manifest = Manifest(
            suite=data["suite"],
            released=data.get("released", ""),
            description=data.get("description", ""),
            components=components,
            targets=targets,
            path=path,
        )
        manifest.validate()
        return manifest

    def validate(self) -> None:
        errors: list[str] = []
        if not self.suite:
            errors.append("missing 'suite' version")
        if not self.components:
            errors.append("no components defined")
        for c in self.components.values():
            if c.repo.count("/") != 1:
                errors.append(f"component {c.name!r}: repo must be 'org/name', got {c.repo!r}")
            if not c.ref:
                errors.append(f"component {c.name!r}: missing 'ref'")
        for t in self.targets.values():
            if t.kind not in TARGET_KINDS:
                errors.append(
                    f"target {t.name!r}: unknown kind {t.kind!r} (expected one of {sorted(TARGET_KINDS)})"
                )
        if errors:
            raise ValueError("invalid manifest:\n  - " + "\n  - ".join(errors))

    def target(self, name: str) -> Target:
        if name not in self.targets:
            raise KeyError(
                f"unknown target {name!r}; defined targets: {', '.join(self.targets) or '(none)'}"
            )
        return self.targets[name]

    def to_toml(self) -> str:
        """Serialize back to TOML deterministically (used when cutting a new suite version)."""
        out = [
            '# SecDeploy release manifest — the suite "bill of materials".',
            "# A suite version pins one compatible, tested set of component tags. Deploying a",
            "# suite version gives you exactly this combination on any target.",
            "",
            f'suite = "{self.suite}"',
            f'released = "{self.released}"',
            f'description = "{self.description}"',
            "",
        ]
        for c in self.components.values():
            out += [
                f"[components.{c.name}]",
                f'repo = "{c.repo}"',
                f'ref = "{c.ref}"',
                f'runtime = "{c.runtime}"',
                f'role = "{c.role}"',
                "",
            ]
        for t in self.targets.values():
            out += [
                f"[targets.{t.name}]",
                f'kind = "{t.kind}"',
                f'description = "{t.description}"',
                "",
            ]
        return "\n".join(out).rstrip() + "\n"
