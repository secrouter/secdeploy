# SecDeploy docs

`suite.toml` pins **what** versions ship together; `secsite.toml` (or a bare `topology.toml`)
says **where** each tier runs and **how** `deploy` should run it. This page is the index over
everything else in `docs/` — organized by task, not by file name.

## Get started

- [../README.md](../README.md) — what SecDeploy is, the suite table, quickstart, air-gapped
  deploys, and the full CLI verb list.
- [releasing.md](releasing.md) — what a "suite release" is and how to cut one.
- [roadmap.md](roadmap.md) — what's planned but not yet shipped (the Proxmox image target, DNS-01
  for SecCert, `secdeploy release`).

## Configure a site

- [topology.md](topology.md) — the placement model: tiers, compute resources, addressing,
  multi-instance inference, the reverse-proxy fronting rule. Read this first if you're placing
  the suite across more than one host.
- [secsite.md](secsite.md) — `secsite.toml`, the single site-specific file that carries placement
  *and* every deploy option that used to be a CLI flag. Covers the `configure` wizard (including
  `--web`, the graphical configurator, and named profiles via `--name`/`--list`), operator-secret
  seeding, and precedence/back-compat with a bare `topology.toml`.
- [`secsite.toml.example`](../secsite.toml.example) — a full, commented reference to copy from.

## Deploy targets

- [macos.md](macos.md) — the MacBook Pro M-series eval target: Docker Compose (Colima) for
  SecCert/SecRouter, native MLX/Metal for SecRecorder and (optionally) SecLLM, `--with-agent`
  pi onboarding.
- [fedora-fips.md](fedora-fips.md) — the production target: native, hardened systemd services
  linking the host's FIPS OpenSSL provider directly, with a fail-closed FIPS preflight, the
  secproxy edge front door, and logrotate for its access/error logs.

## Features

- [voice.md](voice.md) — 1:1 voice calls: the `secchat-mediad` media relay, the new `recordings`
  volume, `[secchat.voice]` in `secsite.toml`, and why `stun` must stay suite-local.
- [agent-pool.md](agent-pool.md) — SecChat's Kubernetes agent pool for coding agents (ephemeral,
  server-launched pods instead of a user's desktop), turnkey build+push+apply, and out-of-cluster
  SecChat support.
  - [Analysis sidecars](agent-pool.md#analysis-sidecars--secchatpoolanalysis_images) — attachable
    per-agent tool containers sharing the pod's `/workspace`.
- [`secsite.toml.example`](../secsite.toml.example) — `[[builds]]`, `[[users]]`, and named site
  profiles are also documented inline there.

## Compliance

- [compliance.md](compliance.md) — SecDeploy's own contribution to the suite's CMMC/NIST SP
  800-171 r2 evidence: the deploy-audit hash chain (`secdeploy audit verify`), the
  `secdeploy evidence` collector, and the `[audit]` syslog/SIEM wiring into SecRouter's config.

Each component's own compliance/control-validation docs live in its repo:

| Component | Control docs |
|---|---|
| [SecCert](https://github.com/secrouter/seccert) | [docs/security.md](https://github.com/secrouter/seccert/blob/main/docs/security.md) |
| [SecSSO](https://github.com/secrouter/secsso) | [docs/control-validation.md](https://github.com/secrouter/secsso/blob/main/docs/control-validation.md) |
| [SecDns](https://github.com/secrouter/secdns) | [docs/control-validation.md](https://github.com/secrouter/secdns/blob/main/docs/control-validation.md) |
| [SecLLM](https://github.com/secrouter/secllm) | [docs/control-validation.md](https://github.com/secrouter/secllm/blob/main/docs/control-validation.md) |
| [SecRouter](https://github.com/secrouter/secrouter) | [docs/compliance/cmmc-control-matrix.md](https://github.com/secrouter/secrouter/blob/main/docs/compliance/cmmc-control-matrix.md) |
| [SecAgent](https://github.com/secrouter/secagent) | [docs/cmmc.md](https://github.com/secrouter/secagent/blob/main/docs/cmmc.md) |
| [SecChat](https://github.com/secrouter/secchat) | [docs/compliance/cmmc-control-matrix.md](https://github.com/secrouter/secchat/blob/main/docs/compliance/cmmc-control-matrix.md) |
| [SecRecorder](https://github.com/secrouter/secrecorder) | [docs/control-validation.md](https://github.com/secrouter/secrecorder/blob/main/docs/control-validation.md) |
| [SecProxy](https://github.com/secrouter/secproxy) | [README.md](https://github.com/secrouter/secproxy/blob/main/README.md) (no dedicated control doc yet) |
