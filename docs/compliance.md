# Compliance posture

SecDeploy's own contribution to the suite's CMMC/NIST SP 800-171 r2 evidence — as distinct from
each component's own (secrouter's is the reference implementation; see
`work/secrouter/docs/compliance/cmmc-control-matrix.md`). This doc covers three things SecDeploy
itself does: the deploy-audit hash chain, the `secdeploy evidence` collector, and the `[audit]`
syslog wiring into SecRouter's config.

## The deploy-audit chain

Every real (non-`--dry-run`) `secdeploy deploy` has always written a snapshot of what it did —
`out/audit/deploy-<target>-<resource>.json` (+ a human-readable `.txt`) — see `src/secdeploy/
audit.py`. That snapshot is overwritten by the next deploy to the same target+resource, which
made it a fine "what does this host look like right now" record but no evidence of HISTORY: an
operator (or an auditor) had no way to tell whether an earlier deploy's record had been altered,
because there was nothing durable to compare it against.

Every real deploy now ALSO appends an immutable, timestamped copy —
`deploy-<target>-<resource>-<UTC timestamp>.json` — carrying two extra fields:

- `prevHash` — the SHA-256 of the previous such file's canonical content for the SAME
  target+resource, or the literal string `"GENESIS"` if this is the first one;
- `hash` — the SHA-256 of this record's own canonical content, `prevHash` included, `hash`
  itself excluded (a record cannot hash itself).

Tampering with — or deleting — any entry breaks the chain from that point forward: a later
entry's `prevHash` no longer matches the (recomputed) `hash` of what came before it.

**Verify:**

```
secdeploy audit verify
```

Walks `out/audit/` chronologically, per target+resource, recomputing and cross-checking every
`hash`/`prevHash`, and reports `{ok, checked, brokenAt}` per chain plus an aggregate. Exits
non-zero if any chain is broken.

**Grandfathering:** files from before this feature existed (or the fixed-name
`deploy-<target>-<resource>.json` snapshot itself, still written every deploy for convenience)
carry no `prevHash`/`hash` and don't match the timestamped chain-entry filename pattern, so
`verify` simply never sees them — the chain starts fresh at `GENESIS` the first time a real
deploy runs under this feature, rather than erroring on history it has no way to validate.

When `secsite.toml`'s `[secllm].catalog` is set, the record's `addressing.secllm_catalog` field
rides along in the same audited artifact — the catalog's path and its model id **list only**
(already non-secret; see [secsite.md](secsite.md)'s `[secllm]` table).

## `secdeploy evidence`

```
secdeploy evidence [--site <file>] [--topology <file>] [--without <list>] \
                    [--token <bearer>] [--timeout <seconds>]
```

Fetches `/admin/api/evidence` from every suite component that exposes one — using the same
topology/site placement `deploy`/`plan` already resolve — and bundles the responses together
with this host's own deploy-audit chain verify result (above) into
`out/evidence/suite-evidence-<date>.json`.

**This needs a live, reachable deployment.** Unlike the rest of SecDeploy (which only generates
deploy-time configuration), `evidence` is a network client: it dials each component's real
running admin endpoint. There is no offline/dry-run mode — a component that can't be reached
over the network from wherever you run this command is recorded as unreachable, not fabricated.

**Per-component tolerance:** SecRouter exposes `/admin/api/evidence` today; SecCert/SecLLM/
SecChat/SecRecorder are gaining their own in parallel. A component without the endpoint yet
(404), or simply unreachable, is recorded `"skipped"` — never fatal to the run. A component not
present in this topology/site at all (or whose tier spans multiple resources, so there's no
single addressable URL) is recorded `"not_in_topology"`.

**Auth:** these are admin-gated endpoints. `--token <bearer>` is sent to every component;
`<COMPONENT>_ADMIN_TOKEN` environment variables (e.g. `SECROUTER_ADMIN_TOKEN`,
`SECCHAT_ADMIN_TOKEN`) override it per-component, for operators who don't share one token across
every console. **No token value is ever written to the output bundle** — only whether one was
sent (`"auth": "token"` / `"none"`).

## `[audit]` syslog wiring

A `secsite.toml` `[audit]` table (`syslog_host`/`syslog_port`/`syslog_proto`/`syslog_format`)
turns on forwarding SecRouter's audit log to a syslog/SIEM sink, in *addition* to its own
tamper-evident SQLite chain — see [secsite.md](secsite.md)'s `[audit]` table
for the full table reference. SecRouter's `SECROUTER_CONFIG` is hand-authored JSON with no
env-var turnkey for `security.audit` (unlike, say, `SECROUTER_SECLLM_ENDPOINTS`), so `deploy`
writes this as a documented fragment (`secrouter-audit.json`, alongside the other addressing
artifacts) for the operator to merge — the same treatment as SecRouter's OIDC fragment
(`secrouter-oidc.json`).

## Control mapping

| Family | ID    | Requirement                                    | Implementation (file:function)                                                                 | Evidence command                       |
|--------|-------|-------------------------------------------------|--------------------------------------------------------------------------------------------------|-----------------------------------------|
| AU     | 3.3.1 | Create audit records of deploy events           | `src/secdeploy/audit.py:write_deploy_audit` — every real deploy records what landed + what security-relevant authorizations were made | `out/audit/deploy-<target>-<resource>.txt` |
| AU     | 3.3.8 | Protect audit information (tamper-evidence)      | `src/secdeploy/audit.py:_verify_files`/`verify_chain`/`verify_all` — SHA-256 hash chain, `GENESIS`-rooted, per target+resource | `secdeploy audit verify`                |

## Shared responsibility

SecDeploy's audit posture covers *deploy-time* events on the host running `secdeploy` — it is
not a substitute for each component's own runtime audit log (SecRouter's request-level audit
chain, SecChat's admin actions, etc. — see their own compliance docs). Explicitly NOT covered
here, and owned by the operator/environment instead:

- **Log integrity/retention/forwarding for secproxy's nginx access/error logs.** SecDeploy emits
  a `log_format`/`access_log` (request id + timing fields) and a modest default logrotate policy
  (fedora-fips/ubuntu only; see [fedora-fips.md](fedora-fips.md)) — but shipping those logs somewhere
  durable, retaining them for a compliance-mandated period, and protecting them from tampering
  is the deploying organization's responsibility, not something this repo enforces.
- **The syslog/SIEM sink itself** (`[audit].syslog_host`) — SecDeploy only wires SecRouter to
  *send* to it; receiving, retaining, and protecting those events is the SIEM's job.
- **`secdeploy evidence`'s admin tokens** — SecDeploy never stores or generates them; the
  operator supplies (and rotates) them via `--token`/env vars.
- **Chain storage durability** — `out/audit/` lives on the deploying host's filesystem like any
  other SecDeploy output; backing it up (or shipping the chain entries somewhere append-only) is
  environment-owned, same as the rest of `out/`.
