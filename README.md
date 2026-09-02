# SecDeploy — release train & deployer for the SecRouter suite

**One versioned product out of the suite's independent components.** SecDeploy pins a
compatible, tested set of component tags (a suite "bill of materials") and stands the whole
stack up on each supported target — from a single command, air-gap friendly.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## The suite

| Component | Role | Kind | |
|---|---|---|---|
| [SecCert](https://github.com/secrouter/seccert) | Internal ACME CA (comes up first) | service | *optional* |
| [SecSSO](https://github.com/secrouter/secsso) | Single sign-on (Authentik) | stack | *optional* |
| [SecDns](https://github.com/secrouter/secdns) | Internal DNS (resolves `*.internal`) | service | *optional* |
| [SecLLM](https://github.com/secrouter/secllm) | Local inference (vLLM control plane) | service | GPU |
| [SecRouter](https://github.com/secrouter/secrouter) | Governed AI gateway | service | |
| [SecAgent](https://github.com/secrouter/secagent) | Agentic harness (pi) | service | |
| [SecChat](https://github.com/secrouter/secchat) | Native auditable team + agentic chat | stack | |
| [SecRecorder](https://github.com/secrouter/secrecorder) | Transcription | service | |
| [SecProxy](https://github.com/secrouter/secproxy) | Edge reverse proxy — one HTTPS front door (`:443`) | service | *optional* |

The compatible versions for a release live in [`suite.toml`](suite.toml) — the manifest.
Deploying a suite version gives you *exactly* that combination on any target. **`service`**
components build from pinned source; **`stack`** components are Compose deploys
([SecSSO](https://github.com/secrouter/secsso) wraps upstream Authentik; SecChat is a native
Node/TS + Postgres build).

### Optional infrastructure

[SecCert](https://github.com/secrouter/seccert), [SecSSO](https://github.com/secrouter/secsso),
and [SecDns](https://github.com/secrouter/secdns) are the "start-from-zero" identity & trust tier
(CA / IdP / DNS) — provide them, or **drop** any you already run:

```bash
secdeploy deploy fedora-fips --without seccert,secsso,secdns
```

`--without` works on `plan` / `fetch` / `build` / `bundle` / `deploy`; only optional components
may be dropped (naming a required one is an error).

## Targets

- **`macos`** — MacBook Pro M-series (eval): [SecCert](https://github.com/secrouter/seccert) +
  [SecRouter](https://github.com/secrouter/secrouter) via Docker Compose (Colima);
  [SecRecorder](https://github.com/secrouter/secrecorder) runs **natively** (its MLX/Metal
  backend can't run in Docker on macOS).
- **`fedora-fips`** — FIPS-mode Fedora host (production): **native, hardened systemd services**
  linking the system OpenSSL FIPS provider directly, with a fail-closed FIPS preflight.
- **`ubuntu`** — Ubuntu 22.04+ / Debian 12+ host: the same native, hardened systemd design as
  `fedora-fips` (apt instead of dnf, `.crt`-suffixed CA trust anchors); FIPS is **advisory**
  (warns, doesn't abort) rather than fail-closed — see [docs/ubuntu.md](docs/ubuntu.md).
  Dry-run/unit verified only; pending first live-host validation.

## Placing the suite across hosts

By default a deploy stands the whole suite up on one machine. To split it — say inference on a
GPU box and everything else on a core host — describe your hosts and which **tier**
(identity / inference / gateway / collab / edge) runs where in a `secsite.toml`:

```bash
secdeploy configure           # wizard → writes secsite.toml (presets: single-host / gpu-split / custom)
secdeploy configure --web     # same thing, graphically — a local page with every option + explanation
secdeploy configure --name colima-test  # save as a NAMED profile (sites/colima-test.toml)
secdeploy verify               # validate placement + print the host map (secsite.toml auto-detected)
secdeploy plan fedora-fips --resource core  # per-resource placement + steps
secdeploy deploy fedora-fips --resource core # no flags needed — secsite.toml supplies them
```

`secsite.toml` carries placement (what `topology.toml` always carried) plus the deploy options
that used to be CLI-flags-only (`--without`, `--with-inference`, `--with-agent`, macOS's
`--tls`/`--trust-ca`/…), so a routine deploy needs no flags at all; the `configure` wizard also
offers to seed operator secrets ([SecCert](https://github.com/secrouter/seccert)'s admin token,
[SecAgent](https://github.com/secrouter/secagent)'s SecSSO client secret, …) into the gitignored
`*.env` files. `configure --web` serves the same wizard as a local, loopback-only web page
(`--port` to change from the default `4477`); `configure --name <profile>` saves a named site
profile (`sites/<name>.toml`) instead of the default `secsite.toml`, selectable anywhere `--site`
is accepted (`configure --list` shows the saved ones). See [docs/secsite.md](docs/secsite.md) and
[secsite.toml.example](secsite.toml.example) for the full picture, or
[docs/topology.md](docs/topology.md) for the placement model alone (a bare `topology.toml` still
works unchanged). Omit both files for single-host mode.

## Quickstart

```bash
uv run secdeploy verify                 # validate the manifest + target assets
uv run secdeploy plan macos             # show pinned versions + steps for a target
uv run secdeploy fetch                  # checkout every component at its pinned ref → ./work
```

**macOS eval**

```bash
uv run secdeploy build macos            # build SecCert + SecRouter images from the checkouts
uv run secdeploy deploy macos           # SecCert first (CA) → export root → SecRouter
# SecRecorder is native:  HOST=0.0.0.0 PORT=47003 work/secrecorder/run.sh
```

**Fedora / FIPS (on the target host, as root)**

```bash
sudo uv run secdeploy deploy fedora-fips --dry-run   # print the exact runbook first
sudo uv run secdeploy deploy fedora-fips             # preflight → build → systemd → trust → start
uv run secdeploy status fedora-fips
```

## Air-gapped deploys

Build on a connected host, carry one tarball into the enclave, deploy offline:

```bash
# connected build host
uv run secdeploy fetch
uv run secdeploy build fedora-fips      # (macos: also produces image tarballs)
uv run secdeploy bundle fedora-fips     # → out/secsuite-1.0.0-fedora-fips.tar.gz (+ .sha256)

# air-gapped target host
sha256sum -c secsuite-1.0.0-fedora-fips.tar.gz.sha256
tar xzf secsuite-1.0.0-fedora-fips.tar.gz && cd secsuite-1.0.0-fedora-fips
sudo uv run secdeploy deploy fedora-fips
```

## CLI

| Command | Does |
|---|---|
| `configure` | Interactive wizard → write a `secsite.toml` (placement + deploy options; optionally seeds operator secrets into `*.env`) |
| `verify` | Validate the manifest (+ topology, if present) and that each target's assets exist |
| `plan <target>` | Show the pinned versions and the steps a deploy would run |
| `fetch` | `git clone`/checkout each component at its pinned ref into `./work` |
| `build <target>` | Build the target's artifacts (images on macOS; native builds on Fedora) |
| `bundle <target>` | Produce an air-gapped release tarball + `SHA256SUMS` |
| `deploy <target>` | Stand the suite up on this host (`--dry-run` prints the runbook) |
| `status <target>` | Report health of the deployed services |
| `teardown <target>` | Remove what a deploy installed on this host (discovers what's actually here; `--purge` also removes persistent data) |
| `backup <target>` | Capture this host's suite state into one FIPS-encrypted archive |
| `restore <target> <archive>` | Decrypt + verify a backup archive and overwrite this host's state with it |
| `audit verify` | Walk `out/audit/`'s deploy-audit hash chain and report `{ok, checked, brokenAt}` (AU-3.3.8) |
| `evidence` | Fetch each reachable component's `/admin/api/evidence` + this host's own audit-chain verify result into one bundle |

## Documentation

[docs/index.md](docs/index.md) is the hub — get-started, configure-a-site, per-target deploy
guides, feature docs (voice, agent pool, analysis sidecars), and the compliance mapping, all in
one place. See [CHANGELOG.md](CHANGELOG.md) for the release history.

## The SecCert tie-in

On every target [SecCert](https://github.com/secrouter/seccert) starts **first** as the internal
CA; its root is exported (macOS) or added to the host trust store (Fedora), so the suite gets its
own trust chain with no public-CA dependency — the natural fit for a closed network.

## Roadmap

- **Proxmox image (`fedora-fips-image`)** — build a bootable **qcow2** (and/or LXC template)
  from the same native FIPS install, importable straight into Proxmox VE. The Fedora-FIPS
  install is already factored to be image-builder callable; see [docs/roadmap.md](docs/roadmap.md).
- DNS-01 for [SecCert](https://github.com/secrouter/seccert); suite-wide `secdeploy release` to
  cut + pin component tags.

## License

[Apache 2.0](LICENSE) — Copyright 2026 Austin Probe.
