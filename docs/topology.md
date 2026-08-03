# Site topology — placing the suite across compute resources

SecDeploy separates **what** from **where**:

| File | Answers | Scope |
|---|---|---|
| `suite.toml` | *what versions* — the pinned bill of materials | ships with the release |
| `topology.toml` | *where each part runs* — hosts + placement | **site-specific** (gitignored, like `*.env`) |

If `topology.toml` is **absent**, SecDeploy runs in **single-host mode**: every component is
placed on the machine you run `deploy` on — the historical behavior. You only need a
topology file to split the suite across more than one machine.

## The model: components → tiers → resources

Every component belongs to one fixed **tier** (declared in `suite.toml`). You assign each
tier to a **compute resource** (a host). Multiple tiers may share one resource.

| Tier | Components | Notes |
|---|---|---|
| `identity` | seccert, secsso, secdns | trust / auth / naming — all optional infra |
| `inference` | secllm | wants a resource with the `gpu` capability |
| `gateway` | secrouter | the governed AI gateway |
| `collab` | secagent, secchat, secrecorder | agents + human collaboration |

Because the tier→component mapping lives in the manifest, you never hand-list components in
`topology.toml` — you place *tiers*, which keeps placement stable across suite upgrades.

## Authoring `topology.toml`

Copy [`topology.toml.example`](../topology.toml.example) to `topology.toml` and edit, or run
`secdeploy configure` to generate one interactively.

```toml
domain = "sec.internal"        # internal DNS zone; component FQDNs are <name>.<domain>
upstream_dns = ["1.1.1.1"]     # secdns forwards non-internal queries here ([] = closed net)

[resources.core]               # a host
target = "fedora-fips"         # deploy mechanism: macos | fedora-fips
address = "10.0.0.5"           # how peer hosts reach it
# ssh = "root@10.0.0.5"        # optional — enables `deploy --ssh` push to this host
capabilities = ["fips"]        # gpu | fips | arch tags

[resources.gpu]
target = "fedora-fips"
address = "10.0.0.6"
capabilities = ["fips", "gpu"]

[groups.identity]  resource = "core"    # tier → resource
[groups.gateway]   resource = "core"
[groups.collab]    resource = "core"
[groups.inference] resource = "gpu"      # inference lands on the GPU box
```

### Fields

- **`domain`** — the internal DNS zone the suite resolves under. Each component gets a stable
  FQDN `<component>.<domain>` (e.g. `secrouter.sec.internal`).
- **`upstream_dns`** — where `secdns` forwards queries it isn't authoritative for. Empty for
  a fully closed network.
- **`[resources.<name>]`** — `target` (which deploy mechanism), `address` (reachable
  IP/name), optional `ssh` (`user@host`, enables remote push), and advisory `capabilities`.
- **`[groups.<tier>]`** — `resource`, the host that tier runs on.

### Generating it with the wizard

`secdeploy configure` asks a few questions and writes a validated `topology.toml`:

```bash
secdeploy configure                          # writes ./topology.toml
secdeploy configure --topology sites/prod.toml
```

Pick a layout preset:

- **single-host** — one resource, every tier on it (equivalent to having no topology file).
- **gpu-split** — a `core` host (identity + gateway + collaboration) plus a `gpu` host
  (inference).
- **custom** — define N resources, then place each tier yourself.

The wizard validates before writing and won't clobber an existing file without confirmation.
Run `secdeploy verify --topology <file>` afterwards to review the placement.

## Addressing — how components find each other

From the topology SecDeploy derives, for every component: its FQDN, the DNS **zone**
`secdns` serves (name → hosting-resource address), and each component's **peer URLs** (e.g.
SecRouter's environment gets `SECLLM_URL=https://secllm.sec.internal:47004`). That
service-to-service wiring is generated, so it is correct whether two components share a host
or sit on opposite ends of the enclave. The per-component inbound port comes from the
`port` field in `suite.toml`.

## Validation

`secdeploy verify [--topology <file>]` validates the topology against the manifest and prints
the placement. It **fails** (non-zero) when:

- a group points at an undefined resource, or a resource names an unknown `target`;
- a **required** component's tier is not placed (optional infra like `seccert`/`secsso` may
  be left unplaced — it simply won't deploy, the same as `--without`);
- two components on the same resource collide on a port.

It **warns** (but succeeds) when the `inference` tier lands on a resource with no `gpu`
capability — fine for a CPU eval, slow/unsupported for real inference.

```bash
secdeploy verify --topology topology.toml
```

## Examples

**Single host** — one resource, all tiers on it (or just delete `topology.toml`):

```toml
domain = "sec.internal"
[resources.local]
target = "macos"
address = "127.0.0.1"
capabilities = []
[groups.identity]  resource = "local"
[groups.inference] resource = "local"
[groups.gateway]   resource = "local"
[groups.collab]    resource = "local"
```

**GPU split** — inference on the NVIDIA box, everything else on a core host: the example
above.

## What consumes the topology

- **`secdeploy verify`** validates the topology and prints the placement map.
- **`secdeploy plan <target> [--resource R]`** shows per-resource placement plus the steps.
- **`secdeploy bundle <target> --resource R`** builds a per-resource air-gap bundle carrying
  only R's components plus its addressing (`addressing/secdns.zone` + `addressing/env/`).
- **`secdeploy deploy <target> [--resource R]`** brings up only the components placed on R and
  writes the addressing artifacts under `out/addressing/`. The resource is auto-detected from
  the target when unambiguous; pass `--resource` otherwise.

Still being wired on top of this model: standing up `secdns` itself as a service, pointing each
host's resolver at it, bringing up the stack components (SecSSO/SecChat) on their host, and
`deploy --ssh` remote push — see [roadmap.md](roadmap.md).
