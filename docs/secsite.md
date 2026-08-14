# Single-file site config (`secsite.toml`)

`secsite.toml` is the one site-specific file an operator maintains: it carries everything
`topology.toml` always carried (placement — the compute resources and which tier runs where),
PLUS the deploy options that used to be CLI-flags-only. With a `secsite.toml` in place, a
routine `secdeploy deploy <target>` needs **no flags at all** — everything a flag would
otherwise ask for lives in this one file instead.

| File | Answers | Scope |
|---|---|---|
| `suite.toml` | *what versions* — the pinned bill of materials | ships with the release |
| `secsite.toml` | *where* each tier runs **and** *how* `deploy` should run it | **site-specific** (gitignored, like `*.env`) |

See [topology.md](topology.md) for the placement model itself (tiers → resources, addressing,
multi-instance inference, the reverse proxy) — this page covers the parts `secsite.toml` adds
on top: the suite-wide `[deploy]` table, each resource's own deploy toggles, the `configure`
wizard that writes the whole thing, and its optional operator-secret seeding step.

**Back-compat is the whole point.** A bare `topology.toml` (or no file at all) still works
**exactly** as it did before `secsite.toml` existed — see [Precedence and back-compat](#precedence-and-back-compat)
below. You never have to migrate an existing `topology.toml`.

## What's new on top of placement

Two kinds of options, two scopes:

- a suite-wide **`[deploy]`** table — `without` (optional components to drop) and `ssh`
  (control-host push mode instead of a local deploy);
- **per-resource** deploy toggles, as extra keys on each `[resources.<name>]` block (alongside
  the placement fields `target`/`address`/`ssh`/`capabilities`) — because whether to stand up
  SecLLM, or configure a Mac's TLS/hosts/keychain, is a property of *that host*, not the suite.

```toml
domain = "sec.internal"
upstream_dns = ["1.1.1.1"]

[deploy]
without = []          # optional components to drop, e.g. ["seccert", "secsso"]
ssh = false           # control-host push mode (needs resources with an `ssh` endpoint below)

[resources.core]
target = "fedora-fips"
address = "10.0.0.5"
capabilities = ["fips"]
with_inference = false      # stand up SecLLM here (only meaningful where inference is placed)
with_agent = false          # install SecAgent here as an on-demand pi harness (collab tier)
configure_resolver = true   # point this host's resolver at SecDNS
tls = false                 # macOS only
configure_hosts = false     # macOS only
trust_ca = false            # macOS only
model_dir = ""              # macOS only — air-gapped SecRecorder model dir
autostart_models = []       # SecLLM catalog ids to download + load at boot (both targets)
```

Every per-resource toggle mirrors a `deploy` flag that used to be the only way to set it
(`--with-inference`, `--with-agent`, `--configure-resolver`, `--tls`, `--configure-hosts`,
`--trust-ca`, `--model-dir`, `--autostart-models`). **CLI flags still exist and override whatever `secsite.toml`
sets** — see `secdeploy deploy --help`; each one resolves to *the flag if you actually passed
it, else the file's value* (a one-off `--without ""` on the command line, for instance,
overrides the file's `without` entirely for that run).

A full, commented reference lives in [`secsite.toml.example`](../secsite.toml.example) — copy
it to `secsite.toml` and edit, or generate one interactively with the wizard below.

## The `configure` wizard

```bash
secdeploy configure                     # writes ./secsite.toml
secdeploy configure --site sites/prod.toml
```

`secdeploy configure` asks a few questions and writes a validated `secsite.toml`. It covers
**every** deploy option, not just placement:

1. **Domain + upstream DNS** — same as always.
2. **Layout preset** — `single-host`, `gpu-split`, or `custom` (see
   [topology.md](topology.md#authoring-topologytoml) for what each preset places). Every preset
   can now end up with **secproxy** (the `edge` tier): `single-host` always places it,
   `gpu-split` asks where to place it (default: the core host — the common case of one HTTPS
   front door; answer `none` to skip it), and `custom` already asks placement for every tier
   including `edge`.
3. **Optional infrastructure to drop** — `[deploy].without`: which of `seccert`/`secsso`/
   `secdns`/`secproxy` you already run elsewhere, so `deploy` skips standing them up here.
   Default: keep everything.
4. **Per-resource deploy options** — asked **only** when it actually applies to that resource:

   | Toggle | Asked when | Default |
   |---|---|---|
   | `with_inference` | the `inference` tier is placed on this resource | no (it's a heavyweight GPU service — installs the wiring either way, just not the running service) |
   | `with_agent` | the `collab` tier is placed on this resource | no |
   | `configure_resolver` | SecDNS will actually be deployed (`identity` tier placed, `secdns` not in `without`) | yes — names won't resolve otherwise |
   | `tls`, `configure_hosts` | the resource's `target` is `macos` | no |
   | `trust_ca` | the resource's `target` is `macos` | yes |
   | `model_dir` | the resource's `target` is `macos` **and** the `collab` tier (SecRecorder) is placed here | blank (fetch from Hugging Face) |
   | `autostart_models` | `with_inference` was answered yes | blank (no autostart — SecLLM loads a model lazily on its first routed request via `/admin`) |

   A resource nothing applies to (say, a bare fedora-fips box hosting only inference, with
   SecDNS dropped) is asked nothing here — every toggle simply stays at its default, exactly
   like a resource in a hand-authored `secsite.toml` that never mentions these keys.
5. The assembled site is validated (`SiteConfig.validate`) before anything is written; on error,
   nothing is written and you're told to re-run and adjust placement. Writing won't clobber an
   existing `secsite.toml` without confirmation.

Afterwards:

```bash
secdeploy verify                # secsite.toml in the current directory is picked up automatically
secdeploy deploy <target>       # no flags needed — secsite.toml supplies everything
```

## Seeding operator secrets (optional)

Right after `secsite.toml` is written, the wizard asks:

> Set up the operator secrets now? (else fill in the `*.env` files yourself later)

Default is **no** — decline and nothing is touched; fill in the `*.env` files by hand whenever
you're ready (see [fedora-fips.md §4 Configure](fedora-fips.md#4-configure) /
[macos.md's diarization section](macos.md#diarization-hugging-face-token)). Say yes and it asks
(via `getpass` — nothing echoes to the terminal) for each **placed** component's secrets, blank
to skip any single value:

| Component | Asked when | Values |
|---|---|---|
| SecCert | placed (identity tier) and not dropped via `without` | `SECCERT_CA_PASSPHRASE`, `SECCERT_ADMIN_TOKEN` |
| SecAgent | placed (collab tier) **and** `with_agent` is on for that resource | `SECAGENT_CLIENT_SECRET` (SecSSO service-account secret) |
| SecRecorder | placed (collab tier) | `HF_TOKEN` (optional — only needed for the gated diarizer model) |
| SecRouter | placed (gateway tier) | `SECROUTER_CONFIG` — a **path** to a hardened config, not a secret; asked as plain text, not masked |

**secrets never land in `secsite.toml`.** They're written into the same local, gitignored
`*.env` files `deploy` already reads (`*.env` / `!*.env.example` in `.gitignore`):

- **fedora-fips** resources get one file per component — `deploy/fedora-fips/<svc>.env` —
  filled in from `<svc>.env.example` as the template (or from the file itself, if one is
  already there, so a value you don't retype on a later run is never reset to blank).
- **macOS** resources share **one** file, `deploy/macos/secrets.env` (from
  `secrets.env.example`), for every component — macOS has no per-component env plumbing today
  (SecCert/SecRouter get their config from `compose.yaml`, not a `*.env` file per service).

  > **Known limitation.** `deploy macos --tls`/`--model-dir` read `HF_TOKEN` from
  > `secrets.env` automatically. Any *other* value the wizard seeds there today
  > (`SECCERT_ADMIN_TOKEN`, `SECAGENT_CLIENT_SECRET`, …) is written for safekeeping only —
  > `compose.yaml`'s own `SECCERT_ADMIN_TOKEN` substitution reads the **shell environment**, not
  > `secrets.env`, and macOS has no service-manager env-file layering (the same known eval
  > limitation documented for [SecRouter's addressing env on macOS](macos.md)). Use `fedora-fips` for
  > the automated `*.env` layering described in
  > [fedora-fips.md §4 Configure](fedora-fips.md#4-configure).

Every file is written at mode `0600`. The wizard prints only the **paths** it wrote, never the
values, and reminds you they're gitignored.

If you decline (or leave every value blank), no `*.env` file is touched at all.

### fedora-fips prefers a seeded `.env` over the `.env.example`

`deploy fedora-fips` seeds each component's config the first time it runs on a host
(`test -f /etc/secsuite/<svc>.env || install …`) — it never overwrites one already there. What
it installs *from* now prefers a wizard-seeded `deploy/fedora-fips/<svc>.env` over the shipped
`<svc>.env.example` when one exists, so answering the secret-seeding questions above actually
reaches the target host on first deploy instead of landing an empty template that still needs a
manual `sudoedit`. A checkout nobody has seeded falls back to the `.env.example` exactly as
before.

## Optional: the SecChat Kubernetes agent pool

A `[secchat.pool]` table turns on SecChat's **Kubernetes agent pool** — coding agents whose launch
environment is "pool" run in server-launched, ephemeral pods (the runnerd image) instead of the
user's desktop. It is off unless you add the section, and needs a Kubernetes cluster (the enclave's
own — SecDeploy generates the manifests; the operator applies them).

```toml
[secchat.pool]
enabled = true
image = "registry.internal/secchat-runnerd:1.0.0"  # the runnerd image (required when enabled)
namespace = "secchat-pool"
service_account = "secchat"                          # SecChat's ServiceAccount (create/delete pods)
service_account_namespace = "secchat"
git_host = "git.sec.internal"                        # the enclave git host pods may reach
secchat_url = ""                                     # cluster-internal URL a pod dials back (default: SecChat's own)
max_pods = 20
ttl_seconds = 3600
```

When enabled, `deploy` does two things at the SecChat wiring step:

1. writes `SECCHAT_POOL_*` into `work/secchat/.env` (image, namespace, callback URL, limits, TTL),
   so the SecChat backend offers the pool; and
2. emits the cluster manifests — namespace, a Role granting SecChat's ServiceAccount create/delete
   on pods + its binding, a ResourceQuota, and a default-deny-ingress NetworkPolicy — to
   `<out>/addressing/secchat-pool.k8s.json`, which the operator applies with
   `kubectl apply -f secchat-pool.k8s.json`. The NetworkPolicy's egress is port-scoped (DNS + git);
   tighten it with real `to:` ipBlocks for your cluster. See
   [secchat's docs/agent-pool.md](https://github.com/secrouter/secchat/blob/main/docs/agent-pool.md).

## Precedence and back-compat

`secdeploy verify` / `plan` / `deploy` / `bundle` all resolve the active site config the same
way (`wiring.active_site`):

1. `--site <file>` — an **explicit** path must exist (fails loud otherwise, never silently
   falls through);
2. `secsite.toml` in the current directory, if present;
3. `--topology <file>` (default `topology.toml`), if present — loaded as a **placement-only**
   `Topology` and wrapped with every deploy option at its default;
4. single-host mode — every component on the machine you run `deploy` on, every deploy option
   off (the original, no-file behavior).

A bare `topology.toml` — including one the `configure` wizard wrote before this wave, or one
you hand-author with just `domain`/`upstream_dns`/`[resources.*]`/`[groups.*]` — reads back
**byte-identical** to before: every deploy option simply defaults off, and CLI flags work
exactly as they always did. You never need to touch `secsite.toml` to keep using `topology.toml`.

## What consumes `secsite.toml`

Same as `topology.toml` (see [What consumes the topology](topology.md#what-consumes-the-topology))
plus: `verify`/`plan`/`deploy`/`bundle` also accept `--site` and resolve every deploy-option
toggle from it, not just placement — and every one of those toggles remains a one-off CLI flag
override away.
