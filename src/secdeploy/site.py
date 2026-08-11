"""Load, validate, and (re)write the unified site config (``secsite.toml``).

``secsite.toml`` is the single site-specific file an operator maintains: it carries
EVERYTHING ``topology.toml`` carries today (``domain``/``upstream_dns``/``[resources.*]``/
``[groups.*]`` — the site *placement*), plus the deploy options that used to be CLI-flags-only
(``--without``, ``--ssh``, ``--with-inference``, ``--with-agent``, ``--configure-resolver``,
``--tls``, ``--configure-hosts``, ``--trust-ca``, ``--model-dir``). The goal: a routine
``secdeploy deploy <target>`` needs no flags at all — everything it would have asked for on the
command line instead lives in this one file. CLI flags remain as ONE-OFF OVERRIDES (see
``cli.cmd_deploy``'s tri-state ``None``-sentinel resolution).

Two kinds of options, two scopes:

* a suite-wide ``[deploy]`` table — ``without`` (optional components to drop) and ``ssh``
  (control-host push mode instead of local deploy);
* per-resource deploy toggles, as extra keys on each ``[resources.<name>]`` block (alongside
  the placement fields ``target``/``address``/``ssh``/``capabilities``) — because whether to
  stand up SecLLM, or configure a Mac's TLS/hosts/keychain, is a property of THAT host, not the
  suite. See :class:`DeployOptions`.

NO SECRETS live here: ``hf_token``, the SecCert CA passphrase, SecAgent's client secret/bot
token stay in the ``*.env`` files (Wave 2's ``configure`` wizard seeds those; this module never
reads or writes one). ``secsite.toml`` is site-specific and gitignored, exactly like
``topology.toml`` before it (the ``.example`` is tracked) — see ``secsite.toml.example``.

Back-compat is the whole point: a bare ``topology.toml`` (or no file at all) must behave
EXACTLY as it did before this module existed. :func:`secdeploy.wiring.active_site` is the
loader that guarantees this — see its docstring for the precedence order. This module only
defines the shape; :meth:`SiteConfig.load` never changes behavior when handed a file with no
``[deploy]``/per-resource-deploy keys (every option simply reads back at its default).

Read with the stdlib ``tomllib`` (no third-party deps); written back via a deterministic
template (:meth:`SiteConfig.to_toml`), ready for Wave 2's ``configure`` wizard to call.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .manifest import Manifest
from .topology import DEFAULT_DOMAIN, Topology

# Placement keys a [resources.<name>] block already carries today (mirrors topology.Resource's
# own fields exactly) — anything else on that block is either a recognized deploy toggle
# (RESOURCE_DEPLOY_KEYS) or an unknown key that SiteConfig.load rejects.
RESOURCE_PLACEMENT_KEYS = {"target", "address", "ssh", "capabilities"}

# Per-resource deploy toggles — these differ per host (inference on the GPU box, TLS/hosts/
# keychain on the Mac), hence per-resource rather than suite-wide. Mirrors DeployOptions' own
# fields exactly.
RESOURCE_DEPLOY_KEYS = {
    "with_inference", "with_agent", "configure_resolver",
    "tls", "configure_hosts", "trust_ca", "model_dir", "autostart_models",
}

# The suite-wide [deploy] table's keys. Mirrors SiteConfig's own without/ssh fields exactly.
DEPLOY_TABLE_KEYS = {"without", "ssh"}

# The top-level [[users]] array-of-tables — declared accounts SecDeploy provisions in SecSSO.
USER_KEYS = {"username", "email", "name", "groups"}

# The [secchat.pool] sub-table — the optional Kubernetes agent pool. Mirrors PoolOptions' fields.
SECCHAT_POOL_KEYS = {
    "enabled", "image", "namespace", "service_account", "service_account_namespace",
    "git_host", "secchat_url", "cpu", "memory", "max_pods", "ttl_seconds",
}


@dataclass
class DeployOptions:
    """Per-resource deploy toggles — what CLI flags used to be the only way to set.

    ``with_inference``/``with_agent``/``configure_resolver`` apply on both targets;
    ``tls``/``configure_hosts``/``trust_ca`` are macOS-only (fedora-fips warns and ignores
    them, exactly as it does for the equivalent CLI flags today); ``model_dir`` is macOS-only
    too (air-gapped pre-downloaded model snapshots — see ``targets/macos.py``).
    ``autostart_models`` applies on both targets — SecLLM catalog ids to load (downloading
    the weights first, if not already cached) at boot instead of on first request via
    ``/admin`` — see ``SECLLM_AUTOSTART`` in ``secllm/config.py``. Every bool defaults
    ``False`` and every string/list field defaults empty — a resource that declares none of
    these keys behaves exactly as it does without a secsite.toml at all.
    """

    with_inference: bool = False
    with_agent: bool = False
    configure_resolver: bool = False
    tls: bool = False
    configure_hosts: bool = False
    trust_ca: bool = False
    model_dir: str = ""
    autostart_models: list[str] = field(default_factory=list)


@dataclass
class UserSpec:
    """A declared end-user account (secsite.toml's ``[[users]]``). SecDeploy renders these into
    ``secsso/blueprints/users.generated.yaml`` with a RANDOM initial password + a forced reset on
    first login (see ``wiring.generate_secsso_users_blueprint`` + secsso's
    ``force-password-reset.yaml``). ``groups`` are created if absent and should match SecRouter's
    ``security.policy.groups`` names so per-group tiers/budgets apply from the token."""

    username: str
    email: str = ""
    name: str = ""
    groups: list[str] = field(default_factory=list)


@dataclass
class PoolOptions:
    """The optional Kubernetes agent pool for SecChat coding agents (secsite.toml's
    ``[secchat.pool]``). When ``enabled``, SecDeploy writes the ``SECCHAT_POOL_*`` env into
    secchat's ``.env`` and emits Kubernetes manifests (namespace / ServiceAccount / Role +
    binding / NetworkPolicy / ResourceQuota) to ``<out>/addressing/secchat-pool.k8s.json`` for the
    operator to ``kubectl apply`` to their cluster. Off by default — a deployment with no cluster
    simply omits this section and the pool stays unavailable. ``image`` (the runnerd image) is
    required when enabled; ``git_host`` (the enclave git host the pods may reach) scopes the egress
    NetworkPolicy; ``secchat_url`` is the cluster-internal URL a pod dials back (defaults to
    SecChat's own address from the topology)."""

    enabled: bool = False
    image: str = ""
    namespace: str = "secchat-pool"
    service_account: str = "secchat"
    service_account_namespace: str = "secchat"
    git_host: str = ""
    secchat_url: str = ""
    cpu: str = "1"
    memory: str = "1Gi"
    max_pods: int = 20
    ttl_seconds: int = 3600


@dataclass
class SiteConfig:
    """The whole site: WHERE things run (a :class:`Topology`) + how ``deploy`` should run them.

    ``topology`` is parsed from the placement fields exactly as ``topology.toml`` always was —
    ``SiteConfig`` never teaches ``Topology`` anything about deploy options (see
    :meth:`Topology.from_data`, which this loads through). ``without``/``ssh`` are the
    suite-wide ``[deploy]`` table; ``deploy_options`` holds each resource's own toggles, keyed
    by resource name — use :meth:`deploy_for` rather than indexing it directly, since a
    resource that declares no deploy keys (every resource in a bare topology.toml, or the
    synthesized single-host resource) simply has no entry and should read back as all-default,
    not raise.
    """

    topology: Topology
    without: list[str] = field(default_factory=list)
    ssh: bool = False
    deploy_options: dict[str, DeployOptions] = field(default_factory=dict)
    users: list[UserSpec] = field(default_factory=list)
    secchat_pool: PoolOptions = field(default_factory=PoolOptions)
    path: Path | None = None

    # ── construction ───────────────────────────────────────────────────────────────
    @staticmethod
    def load(path: str | Path, manifest: Manifest) -> "SiteConfig":
        """Parse ``path`` (stdlib ``tomllib``) into a validated SiteConfig.

        Placement (``domain``/``upstream_dns``/``[resources.*]``/``[groups.*]``) is handed to
        :meth:`Topology.from_data` unchanged — a secsite.toml's placement fields are read
        IDENTICALLY to a topology.toml's. On top of that, this reads the suite-wide
        ``[deploy]`` table and each resource's own deploy keys, rejecting (fail-loud, before
        any topology/without validation) any key that is neither a known placement key nor a
        known deploy key — a caught typo beats a silently-ignored toggle.
        """
        path = Path(path)
        data = tomllib.loads(path.read_text())

        errors: list[str] = []
        deploy_table = data.get("deploy") or {}
        unknown_deploy = sorted(k for k in deploy_table if k not in DEPLOY_TABLE_KEYS)
        if unknown_deploy:
            errors.append(
                f"[deploy]: unknown key(s) {', '.join(unknown_deploy)} "
                f"(expected: {', '.join(sorted(DEPLOY_TABLE_KEYS))})"
            )
        without = [str(w) for w in deploy_table.get("without", [])]
        ssh = bool(deploy_table.get("ssh", False))

        deploy_options: dict[str, DeployOptions] = {}
        for rname, rdata in (data.get("resources") or {}).items():
            unknown_res = sorted(
                k for k in rdata
                if k not in RESOURCE_PLACEMENT_KEYS and k not in RESOURCE_DEPLOY_KEYS
            )
            if unknown_res:
                errors.append(
                    f"resource {rname!r}: unknown key(s) {', '.join(unknown_res)} (expected "
                    f"placement keys {', '.join(sorted(RESOURCE_PLACEMENT_KEYS))} and/or "
                    f"deploy keys {', '.join(sorted(RESOURCE_DEPLOY_KEYS))})"
                )
            deploy_options[rname] = DeployOptions(
                with_inference=bool(rdata.get("with_inference", False)),
                with_agent=bool(rdata.get("with_agent", False)),
                configure_resolver=bool(rdata.get("configure_resolver", False)),
                tls=bool(rdata.get("tls", False)),
                configure_hosts=bool(rdata.get("configure_hosts", False)),
                trust_ca=bool(rdata.get("trust_ca", False)),
                model_dir=str(rdata.get("model_dir", "")),
                autostart_models=[str(m) for m in rdata.get("autostart_models", [])],
            )

        # Declared end-user accounts — a top-level [[users]] array-of-tables. Fail-loud on
        # unknown keys / missing username / duplicates (a typo'd account beats a silent drop);
        # top-level tables are otherwise ignored, so this is additive and backward-compatible.
        users: list[UserSpec] = []
        seen_usernames: set[str] = set()
        for i, u in enumerate(data.get("users") or []):
            if not isinstance(u, dict):
                errors.append(f"[[users]][{i}] must be a table")
                continue
            unknown_u = sorted(k for k in u if k not in USER_KEYS)
            if unknown_u:
                errors.append(
                    f"[[users]][{i}]: unknown key(s) {', '.join(unknown_u)} "
                    f"(expected: {', '.join(sorted(USER_KEYS))})"
                )
            username = str(u.get("username", "")).strip()
            if not username:
                errors.append(f"[[users]][{i}]: username is required")
                continue
            if username in seen_usernames:
                errors.append(f"[[users]]: duplicate username {username!r}")
                continue
            seen_usernames.add(username)
            users.append(UserSpec(
                username=username,
                email=str(u.get("email", "")).strip(),
                name=str(u.get("name", "")).strip(),
                groups=[str(g).strip() for g in (u.get("groups") or []) if str(g).strip()],
            ))

        # Optional [secchat.pool] — the Kubernetes agent pool. Additive top-level table (silently
        # ignored before this parser existed), with the same fail-loud unknown-key rejection.
        secchat_table = data.get("secchat") or {}
        if not isinstance(secchat_table, dict):
            errors.append("[secchat] must be a table")
            secchat_table = {}
        unknown_secchat = sorted(k for k in secchat_table if k != "pool")
        if unknown_secchat:
            errors.append(f"[secchat]: unknown key(s) {', '.join(unknown_secchat)} (expected: pool)")
        pool_data = secchat_table.get("pool") or {}
        if not isinstance(pool_data, dict):
            errors.append("[secchat.pool] must be a table")
            pool_data = {}
        unknown_pool = sorted(k for k in pool_data if k not in SECCHAT_POOL_KEYS)
        if unknown_pool:
            errors.append(
                f"[secchat.pool]: unknown key(s) {', '.join(unknown_pool)} "
                f"(expected: {', '.join(sorted(SECCHAT_POOL_KEYS))})"
            )
        secchat_pool = PoolOptions(
            enabled=bool(pool_data.get("enabled", False)),
            image=str(pool_data.get("image", "")).strip(),
            namespace=str(pool_data.get("namespace", "secchat-pool")).strip() or "secchat-pool",
            service_account=str(pool_data.get("service_account", "secchat")).strip() or "secchat",
            service_account_namespace=str(pool_data.get("service_account_namespace", "secchat")).strip() or "secchat",
            git_host=str(pool_data.get("git_host", "")).strip(),
            secchat_url=str(pool_data.get("secchat_url", "")).strip(),
            cpu=str(pool_data.get("cpu", "1")).strip() or "1",
            memory=str(pool_data.get("memory", "1Gi")).strip() or "1Gi",
            max_pods=int(pool_data.get("max_pods", 20)),
            ttl_seconds=int(pool_data.get("ttl_seconds", 3600)),
        )
        if secchat_pool.enabled and not secchat_pool.image:
            errors.append("[secchat.pool]: image is required when enabled = true")

        # Placement half — same parser topology.toml has always used; deferred (validate=False)
        # so a placement error and a deploy-key error can each raise their own focused message
        # rather than one tangled into the other (see validate() below).
        topology = Topology.from_data(data, manifest, path=path, validate=False)
        site = SiteConfig(
            topology=topology, without=without, ssh=ssh,
            deploy_options=deploy_options, users=users, secchat_pool=secchat_pool, path=path,
        )
        site.validate()
        if errors:
            raise ValueError("invalid site config:\n  - " + "\n  - ".join(errors))
        return site

    @staticmethod
    def single_host(
        manifest: Manifest,
        target: str,
        address: str = "127.0.0.1",
        domain: str = DEFAULT_DOMAIN,
        name: str = "local",
    ) -> "SiteConfig":
        """Synthesize a one-resource site (mirrors :meth:`Topology.single_host`) with every
        deploy option at its default — the no-file fallback (see
        :func:`secdeploy.wiring.active_site`)."""
        topology = Topology.single_host(manifest, target, address=address, domain=domain, name=name)
        return SiteConfig(topology=topology)

    @staticmethod
    def from_topology(topology: Topology) -> "SiteConfig":
        """Wrap an already-loaded (and already-validated) :class:`Topology` with all-default
        deploy options.

        This is the back-compat branch of :func:`secdeploy.wiring.active_site`: a bare
        ``topology.toml`` (no ``[deploy]``/per-resource-deploy keys) must behave EXACTLY as it
        did before ``secsite.toml`` existed, and "every deploy option defaults off" is exactly
        that behavior.
        """
        return SiteConfig(topology=topology)

    # ── validation ─────────────────────────────────────────────────────────────────
    def validate(self) -> None:
        """Validate placement (delegates to :meth:`Topology.validate` — the identical errors/
        warnings a plain topology.toml would raise) plus the one deploy-only check that
        survives past parse time: ``without`` may only name optional components, exactly like
        :meth:`Manifest.select` (which this delegates to directly — the same method a deploy
        eventually calls, so a SiteConfig can never accept a ``without`` that ``select`` would
        later reject).

        Unknown-key rejection (per-resource deploy keys, ``[deploy]`` keys) happens at parse
        time in :meth:`load` instead, since it inspects raw TOML keys that are no longer
        available once a SiteConfig has been (re)constructed programmatically — e.g. Wave 2's
        ``configure`` wizard, which builds one from typed fields, not hand-edited TOML.
        """
        self.topology.validate()
        try:
            self.topology.manifest.select(self.without)
        except (KeyError, ValueError) as exc:
            raise ValueError(f"invalid site config:\n  - [deploy].without: {exc}") from exc

    # ── derivations ────────────────────────────────────────────────────────────────
    def deploy_for(self, resource_name: str) -> DeployOptions:
        """The per-resource deploy toggles for ``resource_name`` — defaults (everything off,
        empty ``model_dir``) if that resource declares none, which is every resource in a bare
        topology.toml, the synthesized single-host resource, or simply a resource whose author
        never set one of these keys."""
        return self.deploy_options.get(resource_name, DeployOptions())

    # ── serialization ──────────────────────────────────────────────────────────────
    def to_toml(self) -> str:
        """Serialize back to TOML deterministically — round-trips through :meth:`load`.

        Mirrors :meth:`Topology.to_toml`'s structure (header, domain/upstream_dns, one
        ``[resources.*]`` block per resource, one ``[groups.*]`` block per tier), with a
        ``[deploy]`` table added right after the suite-wide fields and each resource's own
        deploy toggles appended to its placement block. Every value is written explicitly
        (booleans as ``true``/``false``, ``model_dir`` even when empty) rather than omitted at
        default, so the file is self-documenting about what's off, not just what's on — meant
        for Wave 2's ``configure`` wizard to call.
        """
        def _arr(items: list[str]) -> str:
            return "[" + ", ".join(f'"{i}"' for i in items) + "]"

        def _bool(b: bool) -> str:
            return "true" if b else "false"

        topo = self.topology
        out = [
            "# SecDeploy site config — placement (where each tier runs) + deploy options (how",
            "# `deploy` should run them) in ONE file, so a routine deploy needs no flags.",
            "# suite.toml pins WHAT versions; this file places + configures them on your hosts.",
            "# Site-specific: keep it out of version control (like your *.env files). CLI flags",
            "# still override anything set here (see `secdeploy deploy --help`).",
            "",
            f'domain = "{topo.domain}"',
            f"upstream_dns = {_arr(topo.upstream_dns)}",
            "",
            "[deploy]",
            f"without = {_arr(self.without)}",
            f"ssh = {_bool(self.ssh)}",
            "",
        ]
        for r in topo.resources.values():
            opts = self.deploy_for(r.name)
            out.append(f"[resources.{r.name}]")
            out.append(f'target = "{r.target}"')
            out.append(f'address = "{r.address}"')
            if r.ssh:
                out.append(f'ssh = "{r.ssh}"')
            out.append(f"capabilities = {_arr(r.capabilities)}")
            out.append(f"with_inference = {_bool(opts.with_inference)}")
            out.append(f"with_agent = {_bool(opts.with_agent)}")
            out.append(f"configure_resolver = {_bool(opts.configure_resolver)}")
            out.append(f"tls = {_bool(opts.tls)}")
            out.append(f"configure_hosts = {_bool(opts.configure_hosts)}")
            out.append(f"trust_ca = {_bool(opts.trust_ca)}")
            out.append(f'model_dir = "{opts.model_dir}"')
            out.append(f"autostart_models = {_arr(opts.autostart_models)}")
            out.append("")
        for tier, res_list in topo.groups.items():
            out.append(f"[groups.{tier}]")
            if len(res_list) == 1:
                out.append(f'resource = "{res_list[0]}"')
            else:
                out.append(f"resources = {_arr(res_list)}")
            out.append("")
        if self.users:
            out.append("# Declared end-user accounts — SecDeploy provisions each in SecSSO with a")
            out.append("# random initial password (printed once at deploy) that must be reset on")
            out.append("# first login. `groups` should match SecRouter's security.policy.groups.")
            for u in self.users:
                out.append("[[users]]")
                out.append(f'username = "{u.username}"')
                out.append(f'email = "{u.email}"')
                out.append(f'name = "{u.name}"')
                out.append(f"groups = {_arr(u.groups)}")
                out.append("")
        pool = self.secchat_pool
        if pool.enabled:
            out.append("# Optional Kubernetes agent pool — coding agents run in server-launched pods.")
            out.append("# SecDeploy emits the K8s manifests to <out>/addressing/secchat-pool.k8s.json.")
            out.append("[secchat.pool]")
            out.append(f"enabled = {_bool(pool.enabled)}")
            out.append(f'image = "{pool.image}"')
            out.append(f'namespace = "{pool.namespace}"')
            out.append(f'service_account = "{pool.service_account}"')
            out.append(f'service_account_namespace = "{pool.service_account_namespace}"')
            out.append(f'git_host = "{pool.git_host}"')
            out.append(f'secchat_url = "{pool.secchat_url}"')
            out.append(f'cpu = "{pool.cpu}"')
            out.append(f'memory = "{pool.memory}"')
            out.append(f"max_pods = {pool.max_pods}")
            out.append(f"ttl_seconds = {pool.ttl_seconds}")
            out.append("")
        return "\n".join(out).rstrip() + "\n"
