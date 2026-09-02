# Changelog

## [Unreleased]

### Targets
- **New `ubuntu` target.** Ubuntu 22.04+ / Debian 12+, native hardened systemd services — the
  same design as `fedora-fips` (systemd units are reused directly, byte-identical), with the
  distro deltas confined to `targets/ubuntu.py`: apt instead of dnf for the one package-manager
  step secdeploy runs itself (nginx + certbot); CA trust via `.crt`-suffixed files under
  `/usr/local/share/ca-certificates` + `update-ca-certificates` (fedora's `update-ca-trust`
  equivalent); and an **advisory** (WARN, never fail-closed) FIPS check in place of fedora-fips's
  fail-closed preflight, since stock Ubuntu/Debian ship no in-tree FIPS-validated OpenSSL module
  (the accredited path is Ubuntu Pro's `fips-updates`). Teardown/backup/restore/status,
  `[secllm]` catalog provisioning, `[audit]` syslog, and the secproxy logrotate config all carry
  over unchanged. Dry-run/unit verified only — there is no live Ubuntu host in this environment
  to validate a real deploy against; treat it as pending first live validation. See
  [docs/ubuntu.md](docs/ubuntu.md).

### Compliance & audit
- **Deploy-audit hash chain (AU-3.3.8).** Every real (non-`--dry-run`) deploy now also appends an
  immutable, timestamped `deploy-<target>-<resource>-<UTC timestamp>.json` carrying `prevHash`/
  `hash` — tampering with, or deleting, an entry breaks the chain from that point forward.
  `secdeploy audit verify` walks `out/audit/` chronologically and reports `{ok, checked,
  brokenAt}` per chain plus an aggregate; files from before this feature (or the fixed-name
  convenience snapshot) are grandfathered rather than erroring. See [docs/compliance.md](docs/compliance.md).
- **`secdeploy evidence`.** Fetches `/admin/api/evidence` from every reachable suite component
  (tolerant of components that don't expose it yet) plus this host's own audit-chain verify
  result, bundled into `out/evidence/suite-evidence-<date>.json`. Needs a live, reachable
  deployment — there is no offline/dry-run mode.
- **`[audit]` syslog/SIEM forwarding.** A suite-wide `secsite.toml` `[audit]` table
  (`syslog_host`/`syslog_port`/`syslog_proto`/`syslog_format`) forwards SecRouter's audit log to a
  syslog/SIEM sink, in addition to (never instead of) its own tamper-evident SQLite chain —
  written as a documented `secrouter-audit.json` fragment for the operator to merge.
- **Deploy-audit carries the SecLLM catalog.** When `[secllm].catalog` is provisioned this run,
  the deploy-audit record's `addressing.secllm_catalog` field carries the installed path and the
  model id **list only** (ids are already non-secret).

### Inference
- **`[secllm]` — a suite-wide, operator-maintained model catalog.** `catalog` points at a
  `models.json` (SecLLM's own catalog schema) that replaces SecLLM's built-in catalog on every
  inference resource/replica. Validated fail-loud at config load (file exists, valid JSON, unique
  non-empty model ids — lenient on every other entry field); copied to each resource at deploy
  time and pointed at via `SECLLM_CATALOG`. Absent = unchanged, built-in-catalog behavior.
- **Cross-component "Gemma drift" check.** Once a catalog is known, `deploy`/`secdeploy verify`
  cross-check every SecLLM model id SecRouter's turnkey routing (and `autostart_models`) will
  actually need against the catalog's own ids, and WARN — naming the missing id(s) and the exact
  fix — instead of letting a renamed/dropped model silently 502 the first live request that hits
  it. Quietly skips with a one-line note when no catalog is configured. See
  [docs/secsite.md](docs/secsite.md).

### Edge
- **Branded error pages.** secproxy's fronted server blocks (the landing page and every fronted
  proxy) now serve SecRouter-styled 502/503/504/404 pages instead of nginx's bare white-on-grey
  default.

### Agent pool & sites
- **Kubernetes agent pool for SecChat.** Optional `[secchat.pool]` — coding agents run in
  server-launched, ephemeral pods (the runnerd image) instead of a user's desktop; SecDeploy
  writes the `SECCHAT_POOL_*` env and emits the cluster manifests. Turnkey knobs followed in
  waves: build+push+`kubectl apply`, out-of-cluster SecChat support (`api_server`/
  `create_service_account`) with an egress dial-back fix, an analysis-sidecar catalog
  (`[secchat.pool.analysis_images]`, internet access per-agent and default off), and
  `task_image` for the one-shot `/pool/tasks` batch API. See [docs/agent-pool.md](docs/agent-pool.md).
- **Optional `[[builds]]` container builds + named site profiles.** Declare images the deploy
  should build from a fetched component checkout (docker layer cache keeps re-runs cheap);
  `configure --name <profile>` saves a site config under `sites/<name>.toml`, selectable
  anywhere `--site` is accepted (`configure --list` to enumerate).
- Real SecLLM model-name examples brought current across docs (catalog tags retired in favor of
  real model ids).

### Voice
- **1:1 voice calls.** Optional `[secchat.voice]` stands up the `secchat-mediad` media relay
  alongside SecChat (a new `recordings` volume, `SECCHAT_TRANSCRIBE_URL`/`SECCHAT_MEDIAD_*`/
  `SECCHAT_CALL_STUN` env), re-enables SecRecorder for per-leg transcription, and caps
  participants per call via `max_legs_per_session` (`MEDIAD_MAX_LEGS_PER_SESSION`, must stay
  `>= 2`). `mediad` runs with SecChat's own gid so it can read the shared recordings. See
  [docs/voice.md](docs/voice.md).

### Security
- **Secure-mode SecRouter wiring** — egress classifications generated as part of the deploy-time
  addressing artifacts.
- **Config rename.** SecRouter's config file/env var renamed `freerouter.config.json`/
  `FREEROUTER_CONFIG` → `secrouter.config.json`/`SECROUTER_CONFIG` (legacy names still honored).

## [2.0.0] — 2026-08-10

- **Native SecChat cutover.** Promoted the purpose-built, auditable team + agentic chat rebuild
  (Node/TS + Postgres, tamper-evident hash chains, owner-gated agents) to the canonical `secchat`
  component, retiring the prior Mattermost + LibreChat + SecAgent-chat-bridge arrangement. SSO
  redirect auto-registration and OIDC env sync with SecSSO shipped alongside.
- **Encrypted on-demand backup/restore** for both targets — capture a host's suite state (DBs,
  the SecCert CA, secrets) into one FIPS-encrypted archive, public-key: encrypt to a recipient
  cert and keep the private key offline.
- **Turnkey SSO wiring** for SecRecorder (governed summarization) and SecLLM's admin console.

## [1.6.0]

- **secproxy → nginx** on both targets, retiring Caddy.

## [1.5.0]

- **secproxy (edge reverse proxy)** — one HTTPS front door for the suite's web/API services:
  addressing core (the `fronted` axis + config generation), fedora-fips and macOS standup.

## [1.4.1]

- Pin SecAgent v0.2.1 (`--range` scope flag).

## [1.4.0]

- **Turnkey SecAgent chat-ops** — `--with-agent` stands up the chat-ops bridge; pin SecAgent
  v0.2.0.

## [1.3.0]

- **Multiple SecLLM instances** — per-resource pool wiring, egress + token handling, deploy-audit
  artifacts.
- Bring up stack components (SecSSO/SecChat) via their own bootstrap.
- `deploy --configure-resolver` — point hosts at secdns.
- Stand up secdns as a service (Fedora systemd + macOS native).
- `deploy --ssh` — push per-resource bundles to remote hosts.
- `secdeploy configure` — interactive topology wizard.
- Topology-driven wiring: per-resource plan + bundle + addressing artifacts.
- Pin SecRouter v1.1.0 + SecLLM v1.1.0.

## [1.2.0]

- **Site topology model** — tiers, compute resources, placement validation (`topology.toml`).
- Add secdns to the suite — internal DNS, optional identity-tier infrastructure.
- SecRecorder pin bumps (v0.8.0 → v0.8.2) fixing live-transcription repetition/duplication.
- `--model-dir` for air-gapped manual model placement; `HF_TOKEN` wiring into `deploy macos`.
- `--trust-ca`, plus confirmation gating on `--configure-hosts`/`--trust-ca` with `-y`/`--yes`
  for blanket consent.
- Suite ports moved to a sequential, uncommon range.

## [1.0.0]

First release of **SecDeploy** — the release train and deployer for the SecRouter suite: pins a
compatible, tested set of component tags (the `suite.toml` bill of materials) and stands up
SecCert, SecRouter, and SecRecorder on a target from a single command.
