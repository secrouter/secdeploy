"""Load, validate, and derive the SecDeploy site topology (``topology.toml``).

``suite.toml`` is the immutable bill of materials — *what versions*. ``topology.toml`` is
the operator's *site placement*: the compute resources (hosts) and which predefined tier
(``identity`` / ``inference`` / ``gateway`` / ``collab`` / ``edge``) lands on each. From a
manifest + topology we derive, deterministically:

* **placement** — which resource each component runs on (via its tier);
* **FQDNs** — a stable ``<component>.<domain>`` name per component;
* **zone** — the A records ``secdns`` serves so those names resolve to the hosting resource
  (or, for a FRONTED component, to secproxy's — see :meth:`Topology.is_fronted`);
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
    groups: dict[str, list[str]]  # tier -> resource names (usually one; several for N-way tiers)
    manifest: Manifest
    path: Path | None = None
    warnings: list[str] = field(default_factory=list)

    # ── construction ───────────────────────────────────────────────────────────────
    @staticmethod
    def load(path: str | Path, manifest: Manifest) -> "Topology":
        path = Path(path)
        data = tomllib.loads(path.read_text())
        return Topology.from_data(data, manifest, path=path)

    @staticmethod
    def from_data(
        data: dict, manifest: Manifest, path: Path | None = None, validate: bool = True,
    ) -> "Topology":
        """Build a Topology from an already-parsed TOML mapping (``tomllib.loads`` output).

        Split out of :meth:`load` so a caller that has ALREADY parsed the file for its own
        purposes — namely :class:`secdeploy.site.SiteConfig`, which layers deploy options onto
        the same ``[resources.*]``/``[groups.*]`` shape — can build the placement half without
        re-reading/re-parsing the file. Only the placement keys are read here (``target``/
        ``address``/``ssh``/``capabilities`` per resource); any other keys in ``data`` (e.g.
        SiteConfig's per-resource deploy toggles, or a ``[deploy]`` table) are simply ignored —
        Topology stays focused on placement, never deploy options. Pass ``validate=False`` to
        defer validation to the caller (e.g. SiteConfig, which validates placement + its own
        deploy-only additions together)."""
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
            tier: list(g["resources"]) if "resources" in g else [g["resource"]]
            for tier, g in (data.get("groups") or {}).items()
        }
        topo = Topology(
            domain=data.get("domain", DEFAULT_DOMAIN),
            upstream_dns=list(data.get("upstream_dns", [])),
            resources=resources,
            groups=groups,
            manifest=manifest,
            path=path,
        )
        if validate:
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
            groups={tier: [name] for tier in TIERS},
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
        # every group must point at real resources (a tier may list several)
        for tier, res_list in self.groups.items():
            for res in res_list:
                if res not in self.resources:
                    errors.append(f"group {tier!r} → unknown resource {res!r}")
        # every REQUIRED component's tier must be placed; optional-but-unplaced is allowed
        # (it simply won't be deployed, like an implicit --without).
        for c in self.manifest.components.values():
            res_list = self.groups.get(c.tier) or []
            if not res_list:
                if not c.optional:
                    errors.append(
                        f"component {c.name!r} (tier {c.tier!r}) is not placed on any resource"
                    )
                continue
            if c.tier == "inference":
                for res in res_list:
                    if res in self.resources and not self.resources[res].has("gpu"):
                        warnings.append(
                            f"inference tier is on resource {res!r} which declares no 'gpu' "
                            f"capability — {c.name} inference will be CPU-bound (slow/unsupported)"
                        )
        # no two components sharing a resource may collide on a port (checked per resource, so
        # a tier spread across several resources is fine — each instance owns its own host)
        for rname in self.resources:
            seen: dict[int, str] = {}
            for name, c in self.components_on(rname).items():
                if not c.port:
                    continue
                if c.port in seen:
                    errors.append(
                        f"resource {rname!r}: port {c.port} used by both {seen[c.port]!r} and {name!r}"
                    )
                else:
                    seen[c.port] = name
        self.warnings = warnings
        if errors:
            raise ValueError("invalid topology:\n  - " + "\n  - ".join(errors))

    # ── derivations ────────────────────────────────────────────────────────────────
    def placement(self, without: list[str] | None = None) -> dict[str, str]:
        """Map each enabled, placed component → the (primary) resource name it runs on.

        For a tier spread across multiple resources this is the first one — enough for
        callers that just need a single representative resource (e.g. locating secdns).
        Multi-instance-aware code (peer URLs, the DNS zone) uses :meth:`instances` instead,
        which enumerates every resource a tier is placed on.
        """
        return {
            name: self.groups[c.tier][0]
            for name, c in self.manifest.select(without).items()
            if self.groups.get(c.tier)
        }

    def resource_for(self, component: str) -> Resource:
        tier = self.manifest.components[component].tier
        res_list = self.groups.get(tier) or []
        if not res_list:
            raise KeyError(f"component {component!r} (tier {tier!r}) is not placed")
        return self.resources[res_list[0]]

    def fqdn(self, name: str) -> str:
        """The stable FQDN for ``name`` — a bare component name, or an instance name from
        :meth:`instances` (e.g. ``secllm-gpu1``) for a tier spread across several resources."""
        return f"{name}.{self.domain}"

    def components_on(
        self, resource: str, without: list[str] | None = None
    ) -> dict[str, Component]:
        """The enabled components placed on ``resource`` (after optional ``--without`` drops).

        A component is "on" ``resource`` if ``resource`` is in its tier's resource list — a
        tier spread across several resources (e.g. inference → gpu1, gpu2) places its
        component on EACH of them, one instance per resource.
        """
        return {
            name: c
            for name, c in self.manifest.select(without).items()
            if resource in self.groups.get(c.tier, [])
        }

    def _proxy_address(self) -> str | None:
        """The address of the resource the ``edge`` tier (secproxy) is placed on, or ``None``
        if secproxy/edge isn't placed in this topology at all. Like :meth:`resource_for`, the
        first resource wins if the edge tier were ever spread across several (secproxy is a
        single front door in this design, so that shouldn't happen in practice)."""
        res_list = self.groups.get("edge")
        if not res_list:
            return None
        return self.resources[res_list[0]].address

    def is_fronted(self, component: str) -> bool:
        """Whether ``component``'s traffic is addressed via secproxy instead of its own
        resource — true only when the manifest marks it ``fronted`` AND secproxy is actually
        placed somewhere in this topology. A topology with no ``edge`` tier at all (every
        topology that predates secproxy, and any without one today) makes this ``False`` for
        every component, so :meth:`zone`/:meth:`urls`/:meth:`instance_urls` stay
        byte-identical to their pre-secproxy behavior — fronting only takes effect once
        secproxy is actually deployed."""
        return self.manifest.components[component].fronted and self._proxy_address() is not None

    def instances(self, component: str) -> list[tuple[str, str, str]]:
        """Every ``(instance_name, resource_name, address)`` for ``component`` — one per
        resource its tier is placed on.

        A tier on ONE resource yields a single instance named after the bare component
        (unchanged FQDN, e.g. ``secllm``); a tier spread across MANY resources yields one
        instance per resource, named ``<component>-<resource>`` (e.g. ``secllm-gpu1``,
        ``secllm-gpu2``) so each gets a distinct, stable FQDN. SecLLM is the motivating case —
        stateless, so N instances need no coordination — but this works for any tier.
        """
        tier = self.manifest.components[component].tier
        res_list = self.groups.get(tier, [])
        if len(res_list) <= 1:
            return [(component, res, self.resources[res].address) for res in res_list]
        return [(f"{component}-{res}", res, self.resources[res].address) for res in res_list]

    def zone(self, without: list[str] | None = None) -> list[tuple[str, str, str]]:
        """DNS records secdns serves: (fqdn, "A", resource address) — one per placed
        *instance*, so a multi-resource tier gets one A record per instance.

        A FRONTED component (see :meth:`is_fronted`) resolves to secproxy's address instead
        of its own backend resource — secproxy is the suite's one HTTPS front door, so peers
        (and secdns clients) reach the fronted FQDN straight at it, and it routes to the real
        backend by Host header (see ``wiring.nginx_conf_text``). Unaffected when secproxy isn't
        placed in this topology at all — every component keeps resolving to its own resource,
        exactly as before secproxy existed."""
        records: list[tuple[str, str, str]] = []
        edge_addr = self._proxy_address()
        any_fronted = False
        for name, c in self.manifest.select(without).items():
            if c.tier not in self.groups:
                continue
            fronted = self.is_fronted(name)
            any_fronted = any_fronted or fronted
            proxy_addr = edge_addr if fronted else None
            for instance_name, _res, addr in self.instances(name):
                records.append(
                    (self.fqdn(instance_name), "A", proxy_addr if proxy_addr is not None else addr)
                )
        # The bare domain too, when secproxy has a landing page to serve there (see
        # wiring.nginx_conf_text) — same gating (something actually fronted), so this record
        # only appears when nginx actually has a :443 server block listening for it.
        if edge_addr is not None and any_fronted:
            records.append((self.domain, "A", edge_addr))
        return records

    def urls(self, without: list[str] | None = None, scheme: str = "https") -> dict[str, str]:
        """Peer base URLs keyed by upper-cased component name, for single-instance addressable
        (port>0) peers. A component whose tier spans multiple resources has no single URL —
        use :meth:`instance_urls` (e.g. ``SECROUTER_SECLLM_ENDPOINTS``) for those instead.

        A FRONTED component (see :meth:`is_fronted`) gets a bare ``https://<fqdn>`` — secproxy
        always terminates :443, so the port is implied — instead of ``https://<fqdn>:<port>``.

        A NON-fronted component gets ``http://`` regardless of ``scheme`` — it dials the
        component's own listener directly, which never terminates TLS itself. EXCEPT
        secproxy: it's never "fronted" (nothing fronts the fronter), but unlike every other
        non-fronted component it genuinely IS the suite's TLS terminator, so it keeps
        ``scheme`` unchanged. Confirmed all three live: SecCert/SecLLM only ever answer plain
        HTTP directly (curl -k to either over https fails outright) while secproxy answers
        https directly and 301s plain http to it — the exact opposite of what a blanket
        "fronted → https" rule assumed. This is also what broke SecRouter's turnkey SecLLM
        routing (see :meth:`instance_urls`): a bare "fetch failed" dialing the https URL this
        used to generate for a plain-HTTP-only listener.
        """
        result: dict[str, str] = {}
        for name, c in self.manifest.select(without).items():
            if not c.port or len(self.groups.get(c.tier, [])) != 1:
                continue
            fronted = self.is_fronted(name)
            terminates_tls = fronted or name == "secproxy"
            suffix = "" if fronted else f":{c.port}"
            result[name.upper()] = f"{scheme if terminates_tls else 'http'}://{self.fqdn(name)}{suffix}"
        return result

    def instance_urls(
        self, component: str, without: list[str] | None = None,
        scheme: str = "https", path: str = "",
    ) -> list[str]:
        """Every instance's base URL for ``component`` (one per resource its tier is placed
        on) — e.g. the SecLLM backend pool SecRouter load-balances/fails over across. Empty
        if ``component`` isn't selected or has no inbound port.

        A FRONTED instance (see :meth:`is_fronted`) gets a bare ``https://<fqdn>`` (443
        implied); otherwise ``http://<fqdn>:<port>`` — NOT ``https``, regardless of ``scheme``
        — SecLLM is never fronted (inference must dial direct, never through the proxy) and
        never terminates TLS itself, so its pool stays direct+ported+PLAIN-HTTP regardless of
        what else is fronted in this topology or what scheme the caller asks for. Confirmed
        live: SecRouter's turnkey SecLLM routing FATALs with a bare "fetch failed" against the
        https URL this used to generate."""
        if component not in self.manifest.select(without):
            return []
        port = self.manifest.components[component].port
        if not port:
            return []
        fronted = self.is_fronted(component)
        suffix = "" if fronted else f":{port}"
        effective_scheme = scheme if fronted else "http"
        return [
            f"{effective_scheme}://{self.fqdn(name)}{suffix}{path}"
            for name, _res, _addr in self.instances(component)
        ]

    def env_for(
        self, component: str, without: list[str] | None = None, scheme: str = "https",
        *, secllm_token: str | None = None, secrouter_egress_file: str | None = None,
    ) -> dict[str, str]:
        """Environment for ``component``: its own identity plus every *other* peer's URL.

        Keys: ``SEC_DOMAIN``, ``SELF_FQDN``, ``SELF_PORT`` (if it listens), and
        ``<PEER>_URL`` for each single-instance addressable peer (e.g. ``SECLLM_URL``). A
        FRONTED peer (see :meth:`is_fronted` — seccert/secsso/secrouter/secagent/secchat/
        secrecorder, once secproxy is placed) gets a bare ``https://<fqdn>`` (443 implied) via
        :meth:`urls`; every other peer keeps ``https://<fqdn>:<port>``. Backward-compatible: a
        topology with no ``edge`` tier placed makes every peer URL identical to before secproxy
        existed. SecRouter additionally gets ``SECROUTER_SECLLM_ENDPOINTS`` — the comma-joined
        base URL of *every* SecLLM instance (one when inference is on a single resource,
        several when it's spread across many) — since a single ``SECLLM_URL`` can't represent
        a pool; SecLLM is never fronted (inference must dial direct, never through the proxy),
        so this stays direct+ported no matter what else is fronted.

        ``secllm_token``/``secrouter_egress_file`` fold ``SECROUTER_SECLLM_TOKEN`` (the shared
        SecRouter<->SecLLM bearer token) / ``SECROUTER_EGRESS_FILE`` (the installed egress
        allow-list path) into SecRouter's env when given — see ``wiring.secllm_shared_token`` /
        ``wiring.secrouter_egress_rules``. Both are secrets/paths a caller supplies rather than
        topology-derived data, unlike everything else this method computes, and (like
        ``SECROUTER_SECLLM_ENDPOINTS``) only apply to ``component == "secrouter"``.

        SecAgent gets its own dedicated block (``SECAGENT_LLM__*``/``SECAGENT_SECSSO__*`` —
        secagent's pydantic-settings nested-env convention, double-underscore-delimited, distinct
        from the generic ``<PEER>_URL`` keys above which secagent's own config loader simply
        ignores): the LLM endpoint always points at SecRouter (never directly at SecLLM, so
        agent-triggered inference stays governed/audited), the SecSSO token endpoint is derived
        the same way as any other peer URL, and a handful of suite-wide conventions are fixed
        (client_id ``"secagent"``, ``SECAGENT_LLM__API_KEY="!secagent token"`` — never a secret, a
        resolved-at-request-time command, ``SECAGENT_LLM__MODEL="auto"`` — SecRouter's own catalog,
        NOT one of SecLLM's model ids (a different namespace; confirmed live that SecRouter 502s a
        SecLLM-style id like "balanced" as an unrecognized/misrouted provider), audit enabled).
        """
        c = self.manifest.components[component]
        env: dict[str, str] = {"SEC_DOMAIN": self.domain, "SELF_FQDN": self.fqdn(component)}
        if c.port:
            env["SELF_PORT"] = str(c.port)
        peer_urls = self.urls(without, scheme)
        for key, url in peer_urls.items():
            if key == component.upper():
                continue
            env[f"{key}_URL"] = url
        if component == "secrouter":
            endpoints = self.instance_urls("secllm", without, scheme, path="/v1")
            if endpoints:
                env["SECROUTER_SECLLM_ENDPOINTS"] = ",".join(endpoints)
            if secllm_token:
                env["SECROUTER_SECLLM_TOKEN"] = secllm_token
            if secrouter_egress_file:
                env["SECROUTER_EGRESS_FILE"] = secrouter_egress_file
        if component == "secagent":
            secrouter_url = peer_urls.get("SECROUTER")
            if secrouter_url:
                env["SECAGENT_LLM__BASE_URL"] = f"{secrouter_url}/v1"
            secsso_url = peer_urls.get("SECSSO")
            if secsso_url:
                env["SECAGENT_SECSSO__TOKEN_URL"] = f"{secsso_url}/application/o/token/"
            env["SECAGENT_SECSSO__CLIENT_ID"] = "secagent"
            env["SECAGENT_LLM__API_KEY"] = "!secagent token"
            # "auto" (SecRouter's own routing policy picks the backend) — NOT "balanced", a
            # SecLLM catalog id from a different namespace that doesn't exist in SecRouter's
            # own model catalog. Confirmed live: SecRouter 502s "Unsupported provider:
            # anthropic" for "balanced" (it apparently treats any unrecognized, unprefixed
            # model id as an Anthropic model name and tries to route it there — a provider
            # this SecRouter has no credentials for, only Bedrock's "bedrock/..." ids show up
            # in its real /v1/models).
            env["SECAGENT_LLM__MODEL"] = "auto"
            env["SECAGENT_AUDIT__ENABLED"] = "true"
        if component == "secchat":
            # The native SecChat reads plain SECCHAT_* env. Its ONLY trust root for user tokens is
            # SecSSO's per-provider issuer (JWKS discovered from it); the audience AND client id are
            # both its OIDC client id, which stays `secchatng` — the retained Authentik client from
            # the rebuild's transitional phase (re-provisioning it would rotate the secret for no
            # user-visible gain; users only ever see "SecChat"). SecChat's backend runs the
            # Authorization Code + PKCE dance itself, server-side — a BFF, see
            # secsso/blueprints/secchatng.yaml. The assistant path routes model calls through
            # SecRouter (governed + audited), never straight at SecLLM. DATABASE_URL is derived in
            # compose from the auto-seeded PG_PASSWORD, so it isn't set here. SECCHAT_OIDC_CLIENT_
            # SECRET is NOT set here either — it's mirrored from SecSSO's generated .env by
            # wiring.sync_secchat_env (SecSSO's SECCHATNG_OIDC_CLIENT_SECRET), not topology-derived.
            secsso_url = peer_urls.get("SECSSO")
            if secsso_url:
                env["SECCHAT_OIDC_ISSUER"] = f"{secsso_url}/application/o/secchatng/"
                env["SECCHAT_OIDC_AUDIENCE"] = "secchatng"
                env["SECCHAT_OIDC_CLIENT_ID"] = "secchatng"
            secrouter_url = peer_urls.get("SECROUTER")
            if secrouter_url:
                env["SECROUTER_URL"] = secrouter_url
            # Own fronted external URL — the peer_urls-by-self-key source. Used to build the OIDC
            # redirect URI (<SECCHAT_PUBLIC_URL>/auth/callback) and to decide the session cookie's
            # Secure flag (see secchat's src/config.ts).
            self_url = peer_urls.get("SECCHAT")
            if self_url:
                env["SECCHAT_PUBLIC_URL"] = self_url
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
        for tier, res_list in self.groups.items():
            out.append(f'[groups.{tier}]')
            if len(res_list) == 1:
                out.append(f'resource = "{res_list[0]}"')
            else:
                out.append(f"resources = {_arr(res_list)}")
            out.append("")
        return "\n".join(out).rstrip() + "\n"
