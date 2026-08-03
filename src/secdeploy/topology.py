"""Load, validate, and derive the SecDeploy site topology (``topology.toml``).

``suite.toml`` is the immutable bill of materials — *what versions*. ``topology.toml`` is
the operator's *site placement*: the compute resources (hosts) and which predefined tier
(``identity`` / ``inference`` / ``gateway`` / ``collab``) lands on each. From a manifest +
topology we derive, deterministically:

* **placement** — which resource each component runs on (via its tier);
* **FQDNs** — a stable ``<component>.<domain>`` name per component;
* **zone** — the A records ``secdns`` serves so those names resolve to the hosting resource;
* **env** — each component's *peer URLs*, the service-to-service wiring that lets a
  multi-host suite address and talk to itself.

``topology.toml`` is site-specific (like ``*.env``) and gitignored. When it is absent the
deployer synthesizes a single-host topology (:meth:`Topology.single_host`) that reproduces
the pre-topology, everything-on-this-box behavior.

Read with the stdlib ``tomllib`` (no third-party deps); written back via a deterministic
template (used by the ``configure`` wizard).
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .manifest import TIERS, Component, Manifest

# Advisory capability tags a resource may declare. Unknown tags are allowed (warned).
KNOWN_CAPABILITIES = {"gpu", "fips", "arm64", "x86_64"}
DEFAULT_DOMAIN = "sec.internal"


@dataclass
class Resource:
    """A compute resource — one host the suite (or part of it) is deployed onto."""

    name: str
    target: str  # deploy mechanism — a manifest target name (e.g. macos | fedora-fips)
    address: str = "127.0.0.1"  # how peer hosts reach this one (IP or resolvable name)
    ssh: str = ""  # optional user@host — presence enables `deploy --ssh` to this resource
    capabilities: list[str] = field(default_factory=list)  # gpu | fips | arch tags

    def has(self, cap: str) -> bool:
        return cap in self.capabilities


@dataclass
class Topology:
    """Site placement: resources + tier→resource assignments, bound to a manifest."""

    domain: str
    upstream_dns: list[str]
    resources: dict[str, Resource]
    groups: dict[str, str]  # tier -> resource name
    manifest: Manifest
    path: Path | None = None
    warnings: list[str] = field(default_factory=list)

    # ── construction ───────────────────────────────────────────────────────────────
    @staticmethod
    def load(path: str | Path, manifest: Manifest) -> "Topology":
        path = Path(path)
        data = tomllib.loads(path.read_text())
        resources = {
            name: Resource(
                name=name,
                target=r["target"],
                address=r.get("address", "127.0.0.1"),
                ssh=r.get("ssh", ""),
                capabilities=list(r.get("capabilities", [])),
            )
            for name, r in (data.get("resources") or {}).items()
        }
        groups = {
            tier: g["resource"] for tier, g in (data.get("groups") or {}).items()
        }
        topo = Topology(
            domain=data.get("domain", DEFAULT_DOMAIN),
            upstream_dns=list(data.get("upstream_dns", [])),
            resources=resources,
            groups=groups,
            manifest=manifest,
            path=path,
        )
        topo.validate()
        return topo

    @staticmethod
    def single_host(
        manifest: Manifest,
        target: str,
        address: str = "127.0.0.1",
        domain: str = DEFAULT_DOMAIN,
        name: str = "local",
    ) -> "Topology":
        """Synthesize a one-resource topology (all tiers on ``name``) — the no-``topology.toml``
        default that reproduces the historical single-host deploy."""
        resource = Resource(name=name, target=target, address=address)
        topo = Topology(
            domain=domain,
            upstream_dns=[],
            resources={name: resource},
            groups={tier: name for tier in TIERS},
            manifest=manifest,
        )
        topo.validate()
        return topo

    # ── validation ─────────────────────────────────────────────────────────────────
    def validate(self) -> None:
        errors: list[str] = []
        warnings: list[str] = []
        if not self.domain:
            errors.append("missing 'domain' (internal DNS zone)")
        for tier in self.groups:
            if tier not in TIERS:
                errors.append(f"group {tier!r}: unknown tier (expected one of {sorted(TIERS)})")
        for r in self.resources.values():
            if r.target not in self.manifest.targets:
                errors.append(
                    f"resource {r.name!r}: unknown target {r.target!r} "
                    f"(defined: {', '.join(self.manifest.targets) or 'none'})"
                )
            for cap in r.capabilities:
                if cap not in KNOWN_CAPABILITIES:
                    warnings.append(f"resource {r.name!r}: unrecognized capability {cap!r}")
        # every group must point at a real resource
        for tier, res in self.groups.items():
            if res not in self.resources:
                errors.append(f"group {tier!r} → unknown resource {res!r}")
        # every REQUIRED component's tier must be placed; optional-but-unplaced is allowed
        # (it simply won't be deployed, like an implicit --without).
        for c in self.manifest.components.values():
            if c.tier not in self.groups:
                if not c.optional:
                    errors.append(
                        f"component {c.name!r} (tier {c.tier!r}) is not placed on any resource"
                    )
                continue
            res = self.groups[c.tier]
            if c.tier == "inference" and res in self.resources and not self.resources[res].has("gpu"):
                warnings.append(
                    f"inference tier is on resource {res!r} which declares no 'gpu' capability — "
                    f"{c.name} inference will be CPU-bound (slow/unsupported)"
                )
        # no two components sharing a resource may collide on a port
        by_resource: dict[str, dict[int, str]] = {}
        for name, res in self.placement().items():
            port = self.manifest.components[name].port
            if not port:
                continue
            seen = by_resource.setdefault(res, {})
            if port in seen:
                errors.append(
                    f"resource {res!r}: port {port} used by both {seen[port]!r} and {name!r}"
                )
            else:
                seen[port] = name
        self.warnings = warnings
        if errors:
            raise ValueError("invalid topology:\n  - " + "\n  - ".join(errors))

    # ── derivations ────────────────────────────────────────────────────────────────
    def placement(self, without: list[str] | None = None) -> dict[str, str]:
        """Map each enabled, placed component → the resource name it runs on."""
        return {
            name: self.groups[c.tier]
            for name, c in self.manifest.select(without).items()
            if c.tier in self.groups
        }

    def resource_for(self, component: str) -> Resource:
        tier = self.manifest.components[component].tier
        if tier not in self.groups:
            raise KeyError(f"component {component!r} (tier {tier!r}) is not placed")
        return self.resources[self.groups[tier]]

    def fqdn(self, component: str) -> str:
        return f"{component}.{self.domain}"

    def components_on(
        self, resource: str, without: list[str] | None = None
    ) -> dict[str, Component]:
        """The enabled components placed on ``resource`` (after optional ``--without`` drops)."""
        placement = self.placement(without)
        return {
            name: c
            for name, c in self.manifest.select(without).items()
            if placement.get(name) == resource
        }

    def zone(self, without: list[str] | None = None) -> list[tuple[str, str, str]]:
        """DNS records secdns serves: (fqdn, "A", resource address) for each placed component."""
        records: list[tuple[str, str, str]] = []
        for name, res in self.placement(without).items():
            records.append((self.fqdn(name), "A", self.resources[res].address))
        return records

    def urls(self, without: list[str] | None = None, scheme: str = "https") -> dict[str, str]:
        """Peer base URLs keyed by upper-cased component name, for addressable (port>0) peers."""
        placed = self.placement(without)
        return {
            name.upper(): f"{scheme}://{self.fqdn(name)}:{self.manifest.components[name].port}"
            for name in placed
            if self.manifest.components[name].port
        }

    def env_for(
        self, component: str, without: list[str] | None = None, scheme: str = "https"
    ) -> dict[str, str]:
        """Environment for ``component``: its own identity plus every *other* peer's URL.

        Keys: ``SEC_DOMAIN``, ``SELF_FQDN``, ``SELF_PORT`` (if it listens), and
        ``<PEER>_URL`` for each addressable peer (e.g. ``SECLLM_URL``). Phase 3 targets pick
        the subset each component actually consumes; this is the full, deterministic map.
        """
        c = self.manifest.components[component]
        env: dict[str, str] = {"SEC_DOMAIN": self.domain, "SELF_FQDN": self.fqdn(component)}
        if c.port:
            env["SELF_PORT"] = str(c.port)
        for key, url in self.urls(without, scheme).items():
            if key == component.upper():
                continue
            env[f"{key}_URL"] = url
        return env

    # ── serialization ──────────────────────────────────────────────────────────────
    def to_toml(self) -> str:
        """Serialize back to TOML deterministically (used by the ``configure`` wizard)."""
        def _arr(items: list[str]) -> str:
            return "[" + ", ".join(f'"{i}"' for i in items) + "]"

        out = [
            "# SecDeploy site topology — where each tier of the suite runs.",
            "# suite.toml pins WHAT versions; this file places them on compute resources.",
            "# Site-specific: keep it out of version control (like your *.env files).",
            "",
            f'domain = "{self.domain}"',
            f"upstream_dns = {_arr(self.upstream_dns)}",
            "",
        ]
        for r in self.resources.values():
            out.append(f"[resources.{r.name}]")
            out.append(f'target = "{r.target}"')
            out.append(f'address = "{r.address}"')
            if r.ssh:
                out.append(f'ssh = "{r.ssh}"')
            out.append(f"capabilities = {_arr(r.capabilities)}")
            out.append("")
        for tier, res in self.groups.items():
            out.append(f'[groups.{tier}]')
            out.append(f'resource = "{res}"')
            out.append("")
        return "\n".join(out).rstrip() + "\n"
