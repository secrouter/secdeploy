# SecDeploy — release train & deployer for the SecRouter suite

**One versioned product out of four independent components.** SecDeploy pins a compatible,
tested set of component tags (a suite "bill of materials") and stands the whole stack up on
each supported target — from a single command, air-gap friendly.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## The suite

| Component | Role | Runtime |
|---|---|---|
| [SecCert](https://github.com/secrouter/seccert) | Internal ACME CA (comes up first, issues the suite's certs) | Python ≥3.11 |
| [SecRouter](https://github.com/secrouter/secrouter) | Governed AI gateway | Node ≥24 |
| [SecRecorder](https://github.com/secrouter/secrecorder) | Transcription (optional) | Python ≥3.11 |

The compatible versions for a release live in [`suite.toml`](suite.toml) — the manifest.
Deploying a suite version gives you *exactly* that combination on any target.

## Targets

- **`macos`** — MacBook Pro M-series (eval): SecCert + SecRouter via Docker Compose (Colima);
  SecRecorder runs **natively** (its MLX/Metal backend can't run in Docker on macOS).
- **`fedora-fips`** — FIPS-mode Fedora host (production): **native, hardened systemd services**
  linking the system OpenSSL FIPS provider directly, with a fail-closed FIPS preflight.

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
# SecRecorder is native:  uv run --project work/secrecorder secrecorder
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
| `verify` | Validate the manifest and that each target's assets exist |
| `plan <target>` | Show the pinned versions and the steps a deploy would run |
| `fetch` | `git clone`/checkout each component at its pinned ref into `./work` |
| `build <target>` | Build the target's artifacts (images on macOS; native builds on Fedora) |
| `bundle <target>` | Produce an air-gapped release tarball + `SHA256SUMS` |
| `deploy <target>` | Stand the suite up on this host (`--dry-run` prints the runbook) |
| `status <target>` | Report health of the deployed services |

## The SecCert tie-in

On every target SecCert starts **first** as the internal CA; its root is exported (macOS) or
added to the host trust store (Fedora), so the suite gets its own trust chain with no
public-CA dependency — the natural fit for a closed network.

## Roadmap

- **Proxmox image (`fedora-fips-image`)** — build a bootable **qcow2** (and/or LXC template)
  from the same native FIPS install, importable straight into Proxmox VE. The Fedora-FIPS
  install is already factored to be image-builder callable; see [docs/roadmap.md](docs/roadmap.md).
- DNS-01 for SecCert; suite-wide `secdeploy release` to cut + pin component tags.

## License

[Apache 2.0](LICENSE) — Copyright 2026 Austin Probe.
