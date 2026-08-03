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
COMPONENT_KINDS = {"service", "stack"}
# Placement tiers — a component belongs to exactly one; the site topology assigns each
# tier to a compute resource (see topology.py).
TIERS = {"identity", "inference", "gateway", "collab"}


@dataclass
class Component:
    name: str
    repo: str  # "org/name" on GitHub
    ref: str  # git tag/branch/sha to pin
    kind: str = "service"  # "service" (built from source) | "stack" (compose deploy of upstream)
    tier: str = ""  # placement tier: identity | inference | gateway | collab
    port: int = 0  # primary inbound port for peer addressing (0 = no inbound listener)
    optional: bool = False  # optional infra — droppable with `--without`
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
                kind=c.get("kind", "service"),
                tier=c.get("tier", ""),
                port=int(c.get("port", 0)),
                optional=bool(c.get("optional", False)),
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
            if c.kind not in COMPONENT_KINDS:
                errors.append(
                    f"component {c.name!r}: unknown kind {c.kind!r} (expected one of {sorted(COMPONENT_KINDS)})"
                )
            if c.tier not in TIERS:
                errors.append(
                    f"component {c.name!r}: tier must be one of {sorted(TIERS)}, got {c.tier!r}"
                )
            if c.port and not 0 < c.port < 65536:
                errors.append(f"component {c.name!r}: port {c.port} out of range (1–65535)")
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

    def optionals(self) -> list[str]:
        return [c.name for c in self.components.values() if c.optional]

    def select(self, without: list[str] | None = None) -> dict[str, Component]:
        """Components to act on after dropping the (optional) ones named in ``without``.

        Only optional components may be dropped — naming a required one is an error, so a
        deploy can't accidentally omit the gateway.
        """
        without = list(without or [])
        unknown = [n for n in without if n not in self.components]
        if unknown:
            raise KeyError(f"unknown component(s) in --without: {', '.join(unknown)}")
        required = [n for n in without if not self.components[n].optional]
        if required:
            raise ValueError(
                f"cannot drop required component(s): {', '.join(required)} "
                f"(droppable: {', '.join(self.optionals()) or 'none'})"
            )
        return {n: c for n, c in self.components.items() if n not in without}

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
            lines = [f"[components.{c.name}]", f'repo = "{c.repo}"', f'ref = "{c.ref}"',
                     f'kind = "{c.kind}"', f'tier = "{c.tier}"']
            if c.port:
                lines.append(f"port = {c.port}")
            if c.optional:
                lines.append("optional = true")
            if c.runtime:
                lines.append(f'runtime = "{c.runtime}"')
            lines.append(f'role = "{c.role}"')
            out += lines + [""]
        for t in self.targets.values():
            out += [
                f"[targets.{t.name}]",
                f'kind = "{t.kind}"',
                f'description = "{t.description}"',
                "",
            ]
        return "\n".join(out).rstrip() + "\n"
