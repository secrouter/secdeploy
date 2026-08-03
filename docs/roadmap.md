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

The manifest now lists all seven components with `kind` (service | stack) + `optional`, and
`--without` drops optional infra across `plan`/`fetch`/`build`/`bundle`/`deploy`. Still to do:

- **Stack-component deploy execution** — `secsso`/`secchat` are `stack` components; wire the
  targets to run their own `compose` / `bootstrap` (they're fetched and bundled today, and
  droppable via `--without`, but a target's `deploy` still brings up the core services only).
- **Dynamic plan steps** — the per-target `plan` step list is currently static; make it reflect
  the selected component set (the *components* section already honors `--without`).
- **SecLLM on the GPU path** — a target/overlay that places SecLLM on the NVIDIA host.

## Other

- **DNS-01 for SecCert** — wildcard + unreachable-host issuance in closed networks.
- **`secdeploy release`** — one command to tag + pin components and cut a suite version.
- **Signed bundles** — detached signatures on release tarballs for transfer integrity.
- **Podman/Quadlet variant** — a containerized Fedora path for sites that prefer it over native.
