# Roadmap

## Proxmox-compatible image (`fedora-fips-image`)

Goal: build a **bootable Fedora appliance** for the suite that imports straight into
Proxmox VE — a `qcow2` VM disk and/or an LXC container template — so the closed-network
install is "import and power on" instead of hand-provisioning a host.

Why it's a small step from here: the `fedora-fips` target's install is already a pure
function of the pinned checkouts + the deploy assets (`fips-preflight.sh`, the systemd units,
the env templates). An image build just runs that same install inside an image pipeline.

Planned approach:

- **VM image (qcow2):** drive an [image-builder](https://osbuild.org/) /
  `virt-customize` / `mkosi` pipeline that installs Fedora, enables FIPS mode, runs the
  SecDeploy `fedora-fips` install against a bundled release, and seals the units enabled.
  Output: `secsuite-<suite>-fedora-fips.qcow2` (+ checksum) → `qm importdisk` on Proxmox.
- **LXC template:** the same install into a rootfs tarball for Proxmox's container templates
  (lighter; note FIPS in a container inherits the *host* kernel's FIPS state).
- Wire it as `secdeploy build fedora-fips-image` / `secdeploy bundle fedora-fips-image`, using
  the existing `_deploy_steps` so the runbook and the image stay in lockstep.

First-boot concerns to design for: regenerate the SecCert CA (or inject an operator-provided
root), set unique admin tokens/passphrases, and re-key TLS for the real hostname.

## Suite orchestration

The manifest lists all seven components with `kind` (service | stack), `optional`, and now a
`tier` + `port`; `--without` drops optional infra across `plan`/`fetch`/`build`/`bundle`/`deploy`.

**Landed — site topology model.** A `topology.toml` places the predefined tiers
(identity / inference / gateway / collab) onto compute resources; `secdeploy verify` validates
it and reports placement, and the model derives per-component FQDNs, the DNS zone, and peer
URLs (see [topology.md](topology.md)). Absent → single-host mode (unchanged behavior).

**Landed — per-resource placement + the configure wizard.** `plan` / `deploy` / `bundle` are
topology-aware: each target now brings up only the components *placed on the current resource*
(`deploy --resource`), `bundle --resource` emits a per-resource air-gap tarball, and both
generate the addressing artifacts (the `secdns` zone + per-component peer-env). `secdeploy
configure` writes a validated `topology.toml` interactively (presets: single-host, GPU-split,
custom), and `deploy --ssh` pushes each resource's bundle to its `ssh` endpoint and deploys it
remotely. When a topology places it, **`secdns` now stands up as a service** — a hardened
Fedora systemd unit (binding :53 via `CAP_NET_BIND_SERVICE`) or a native macOS run — fed by the
generated zone + env, and `deploy --configure-resolver` points a host's resolver at it (macOS
`/etc/resolver/<domain>`, Fedora systemd-resolved). **Stack components** (SecSSO/SecChat) are
brought up via their own `bootstrap` where placed — the first deploy writes their `.env` from
the example for you to fill in secrets, then the bootstrap does the compose up + wiring.
Single-host behavior is unchanged (secdns + stacks only deploy with a topology).

**Landed — single-file site config (`secsite.toml`) + secret-seeding.** `secsite.toml` carries
everything `topology.toml` did plus the deploy options that were CLI-flags-only (a suite-wide
`[deploy]` table — `without`/`ssh` — and per-resource `with_inference`/`with_agent`/
`configure_resolver`/`tls`/`configure_hosts`/`trust_ca`/`model_dir`), so a routine `deploy` needs
no flags; CLI flags still override it one-off. `secdeploy configure` now writes a validated
`secsite.toml` — every deploy option is asked, but only where it actually applies to a given
resource — and can optionally seed operator secrets (SecCert's admin token/CA passphrase,
SecAgent's SecSSO client secret, SecRecorder's Hugging Face token, SecRouter's
`SECROUTER_CONFIG` path) into the gitignored `*.env` files, never into `secsite.toml` itself.
See [secsite.md](secsite.md). A bare `topology.toml` still works byte-identically.

Still to do, building on that:

- **Dynamic plan steps** — the per-target `plan` step list is currently static; make it reflect
  the selected component set + placement (the *components* section already honors `--without`).

## Other

- **`secdns` internal DNS** — a small from-scratch authoritative server that serves the zone
  above and forwards non-internal queries upstream (its own repo; retires the `--configure-hosts`
  `/etc/hosts` hack).
- **DNS-01 for SecCert** — wildcard + unreachable-host issuance in closed networks (natural once
  `secdns` is in place — SecCert sets `_acme-challenge` TXT records).
- **`secdeploy release`** — one command to tag + pin components and cut a suite version.
- **Signed bundles** — detached signatures on release tarballs for transfer integrity.
- **Podman/Quadlet variant** — a containerized Fedora path for sites that prefer it over native.
