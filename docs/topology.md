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
| `inference` | secllm | wants a resource with the `gpu` capability; may span **several** resources |
| `gateway` | secrouter | the governed AI gateway |
| `collab` | secagent, secchat, secrecorder | agents + human collaboration |

Because the tier→component mapping lives in the manifest, you never hand-list components in
`topology.toml` — you place *tiers*, which keeps placement stable across suite upgrades.

Every tier maps to **one** resource except `inference`, which may map to **several** — see
[Multi-instance inference](#multi-instance-inference-n-secllm-backends) below.

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

# N-way inference: several SecLLM instances, one per resource — see the section below.
# [groups.inference] resources = ["gpu1", "gpu2"]
```

### Fields

- **`domain`** — the internal DNS zone the suite resolves under. Each component gets a stable
  FQDN `<component>.<domain>` (e.g. `secrouter.sec.internal`).
- **`upstream_dns`** — where `secdns` forwards queries it isn't authoritative for. Empty for
  a fully closed network.
- **`[resources.<name>]`** — `target` (which deploy mechanism), `address` (reachable
  IP/name), optional `ssh` (`user@host`, enables remote push), and advisory `capabilities`.
- **`[groups.<tier>]`** — `resource`, the (single) host that tier runs on — **or**, for a tier
  that supports it (currently just `inference`), `resources`, a list of hosts, one instance per
  host.

### Generating it with the wizard

`secdeploy configure` asks a few questions and writes a validated `topology.toml`:

```bash
secdeploy configure                          # writes ./topology.toml
secdeploy configure --topology sites/prod.toml
```

Pick a layout preset:

- **single-host** — one resource, every tier on it (equivalent to having no topology file).
- **gpu-split** — a `core` host (identity + gateway + collaboration) plus one or more `gpu`
  hosts (inference) — answer with a comma-separated list of names (e.g. `gpu1,gpu2`) for
  several SecLLM instances.
- **custom** — define N resources, then place each tier yourself; `inference` accepts a
  comma-separated list of resources.

The wizard validates before writing and won't clobber an existing file without confirmation.
Run `secdeploy verify --topology <file>` afterwards to review the placement.

## Addressing — how components find each other

From the topology SecDeploy derives, for every component: its FQDN, the DNS **zone**
`secdns` serves (name → hosting-resource address), and each component's **peer URLs** (e.g.
SecRouter's environment gets `SECLLM_URL=https://secllm.sec.internal:11400` when inference is
on a single resource). That service-to-service wiring is generated, so it is correct whether
two components share a host or sit on opposite ends of the enclave. The per-component inbound
port comes from the `port` field in `suite.toml`.

### Multi-instance inference (N SecLLM backends)

SecLLM is stateless, so it's the one tier that may be placed on **several** resources at once —
each gets its own SecLLM instance, and SecRouter load-balances/fails over across all of them.
Use `resources` (plural) instead of `resource` in `[groups.inference]`:

```toml
[resources.gpu1]
target = "fedora-fips"
address = "10.0.0.6"
capabilities = ["fips", "gpu"]

[resources.gpu2]
target = "fedora-fips"
address = "10.0.0.7"
capabilities = ["fips", "gpu"]

[groups.inference]
resources = ["gpu1", "gpu2"]
```

With a single inference resource, SecLLM keeps its plain FQDN (`secllm.sec.internal`) —
unchanged from single-instance topologies. With several, each instance is named
`<component>-<resource>` so it gets its own stable FQDN and DNS **A** record:

```
secllm-gpu1.sec.internal   A   10.0.0.6
secllm-gpu2.sec.internal   A   10.0.0.7
```

SecRouter's generated env carries the whole pool as one comma-joined variable,
`SECROUTER_SECLLM_ENDPOINTS` (each entry is the OpenAI-compatible base URL,
`https://<instance-fqdn>:11400/v1`):

```
SECROUTER_SECLLM_ENDPOINTS=https://secllm-gpu1.sec.internal:11400/v1,https://secllm-gpu2.sec.internal:11400/v1
```

Standing up each instance's `secllm` service is opt-in — pass `--with-inference` to `deploy` on
each resource where inference is placed (default off, since it's a heavyweight GPU service);
without it, secdeploy still generates the DNS + env wiring above for an externally-run SecLLM.
On fedora-fips this installs a hardened `secllm.service` (see
`deploy/fedora-fips/systemd/secllm.service`) with a generated `/etc/secsuite/secllm.env`; on
macOS (no GPU passthrough into Colima) it instead prints a native run command using
`SECLLM_BACKEND=mock` for a GPU-free eval.

Two more pieces of this pool's security setup are generated alongside the wiring above — both
are CMMC audit evidence, recorded in the [deploy audit artifact](fedora-fips.md#deployment-audit-artifacts):
an explicit SecRouter **egress allow-list** (`out/addressing/secrouter-egress.json`,
`SECROUTER_EGRESS_FILE`) naming exactly these pool hosts, and a **shared bearer token**
(`SECLLM_API_TOKEN` / `SECROUTER_SECLLM_TOKEN`) so SecRouter can authenticate to them — see
[SecRouter egress allow-list](fedora-fips.md#secrouter-egress-allow-list) and
[Shared SecRouter and SecLLM inference token](fedora-fips.md#shared-secrouter-and-secllm-inference-token).

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

**N-way inference** — two SecLLM instances behind SecRouter's backend pool: the
[Multi-instance inference](#multi-instance-inference-n-secllm-backends) example above (swap
`[groups.inference] resource = "gpu"` for `resources = ["gpu1", "gpu2"]`).

## What consumes the topology

- **`secdeploy verify`** validates the topology and prints the placement map.
- **`secdeploy plan <target> [--resource R]`** shows per-resource placement plus the steps.
- **`secdeploy bundle <target> --resource R`** builds a per-resource air-gap bundle carrying
  only R's components plus its addressing (`addressing/secdns.zone` + `addressing/env/`).
- **`secdeploy deploy <target> [--resource R]`** brings up only the components placed on R and
  writes the addressing artifacts under `out/addressing/`. The resource is auto-detected from
  the target when unambiguous; pass `--resource` otherwise.
- **`secdeploy deploy <target> --ssh`** (control host) builds each resource's bundle, `rsync`s
  it to that resource's `ssh` endpoint, and deploys it remotely. `--dry-run` prints the runbook.
- **`secdns` is stood up** on the host where the `identity` tier lands (Fedora systemd unit /
  macOS native), fed by the generated zone + env — so the internal names actually resolve.
- **`deploy <target> --configure-resolver`** points this host's resolver at secdns for the
  internal domain (macOS `/etc/resolver/<domain>`, Fedora systemd-resolved) — the multi-host
  replacement for the `--configure-hosts` `/etc/hosts` trick. It asks before touching the host.
- **Stack components** (SecSSO/SecChat) are brought up on the host where they're placed via
  their own `bootstrap/<name>.sh up`. The first deploy writes their `.env` from `.env.example`
  for you to fill in secrets; once set, the bootstrap does the compose up + suite wiring.
- **`deploy <target> --with-inference`** additionally stands up SecLLM on each resource where
  `inference` is placed — off by default, since it's a heavyweight GPU service; without it,
  SecDeploy still generates the DNS + `SECROUTER_SECLLM_ENDPOINTS` wiring for an
  externally-run SecLLM (see [Multi-instance inference](#multi-instance-inference-n-secllm-backends)).
- Every real `deploy` (not `--dry-run`) also writes a per-resource **audit artifact** to
  `out/audit/` — CMMC evidence of what was placed here and, notably, the SecLLM backend-pool
  hosts SecRouter is auto-authorized to egress to. See
  [Deployment audit artifacts](fedora-fips.md#deployment-audit-artifacts).

> Note: `secdns`, the stack components, and SecLLM (`--with-inference`) only deploy when a
> topology is active. To stand up the *full* suite on a single machine, generate a single-host
> `topology.toml` (via `secdeploy configure`) rather than running a bare `deploy` (which brings
> up the built-from-source core only). Remaining polish is tracked in [roadmap.md](roadmap.md).
