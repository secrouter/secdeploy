# Ubuntu/Debian runbook

**Compatibility:** Ubuntu 22.04 LTS+ or Debian 12 (bookworm)+.

Native, hardened **systemd** services — the same design as
[fedora-fips.md](fedora-fips.md), and this doc leans on that one heavily rather than repeating
it: the systemd units, `/opt`/`/etc`/`/var/lib` layout, addressing/wiring, SecAgent harness,
secproxy edge, teardown, and backup/restore are **byte-identical or behaviorally identical** to
fedora-fips. Only the handful of genuine distro deltas are covered here in full; everything else
just links to the fedora-fips section that already explains it.

> **HONESTY NOTE.** This target is **dry-run/unit verified only** — there is no live Ubuntu host
> in this environment to validate a real deploy against. Treat it as pending first live
> validation; nothing here has been run for real yet. If you deploy it for real, please report
> back what did/didn't work.

## What's different from fedora-fips

| | fedora-fips | ubuntu |
|---|---|---|
| FIPS check | **fail-closed** preflight (aborts) | **advisory** (warns, never aborts) — see [FIPS](#fips) |
| Package manager | `dnf` | `apt-get` |
| CA trust anchor | `/etc/pki/ca-trust/source/anchors/*.pem` + `update-ca-trust extract` | `/usr/local/share/ca-certificates/*.crt` + `update-ca-certificates` — **`.crt` extension is required** |
| SELinux/AppArmor | none (fedora-fips has no SELinux steps either) | none — see [Hardening applied](#hardening-applied) |
| systemd units | `deploy/fedora-fips/systemd/*.service` | **the same files** — reused, not duplicated (they carry no SELinux/dnf-specific directive) |
| Seeded `*.env` | `deploy/fedora-fips/<svc>.env` | `deploy/ubuntu/<svc>.env` — its own copy (adapted `.env.example` header text only; same keys) |

Everything else — `/opt/secsuite`, `/etc/secsuite`, `/var/lib/secsuite`, `useradd` flags
(shadow-utils, identical on both distros), the `systemd-resolved` drop-in, secproxy's logrotate
config — carries over unchanged. See `src/secdeploy/targets/ubuntu.py`'s module docstring for
the authoritative list.

## 1. FIPS {#fips}

Stock Ubuntu/Debian ship **no in-tree FIPS-140-validated OpenSSL module**. The only accredited
path is [Ubuntu Pro's `fips-updates`](https://ubuntu.com/security/certifications/docs/fips) — a
paid entitlement `secdeploy` cannot enable for you. Aborting every non-FIPS ubuntu deploy would
make the target unusable for the (common) non-regulated case, so `deploy ubuntu` runs
[`deploy/ubuntu/fips-check.sh`](../deploy/ubuntu/fips-check.sh) first, which **WARNS and
continues** rather than failing closed the way fedora-fips's
[`fips-preflight.sh`](../deploy/fedora-fips/fips-preflight.sh) does:

```bash
bash deploy/ubuntu/fips-check.sh   # standalone; `secdeploy deploy ubuntu` runs it automatically
```

If your accreditation boundary genuinely requires a fail-closed FIPS check today, use the
`fedora-fips` target instead — ubuntu has no `--require-fips`-style escalation flag (fedora-fips
has no such flag either; its preflight is unconditional, so there's nothing to mirror).

To actually get a FIPS-validated boundary on Ubuntu:

```bash
sudo pro attach <token>
sudo pro enable fips-updates
sudo reboot
# after reboot, confirm:
cat /proc/sys/crypto/fips_enabled        # → 1
openssl list -providers | grep -i fips   # → fips provider present
```

## 2. Runtimes

Identical to fedora-fips's own [Runtimes](fedora-fips.md#2-runtimes) step, `apt` instead of `dnf`:

```bash
sudo apt-get update
sudo apt-get install -y nodejs npm git     # Node >= 24 for SecRouter
# uv for the Python components (SecCert, SecRecorder, secdns, SecLLM, SecAgent):
curl -LsSf https://astral.sh/uv/install.sh | sh
# a container runtime for the stacks (SecSSO/SecChat) — either is fine:
sudo apt-get install -y docker.io
# — or —
sudo apt-get install -y podman podman-compose
```

`secdeploy` itself only runs one package-manager step automatically — installing the secproxy
runtime (`nginx` + `certbot`) when the edge tier is placed here (see
[SecProxy](fedora-fips.md#secproxy-edge-reverse-proxy)); everything above is a manual,
one-time host prerequisite on both targets.

## 3. Deploy

```bash
# Always preview the exact runbook first:
sudo uv run secdeploy deploy ubuntu --dry-run

# Then run it (as root — installs users, code, systemd units, trust anchor):
sudo uv run secdeploy deploy ubuntu
```

`deploy ubuntu` performs, in order:
1. **FIPS advisory check** ([`fips-check.sh`](../deploy/ubuntu/fips-check.sh)) — WARN, never abort.
2. Create system users `secsuite-{seccert,secrouter,secrecorder,...}` and owner-only state dirs.
3. Build natively from the pinned checkouts (SecRouter `npm run build`; SecCert/SecRecorder/
   secdns/SecLLM/SecAgent `uv sync`) — identical to fedora-fips.
4. Install code to `/opt/secsuite`, config to `/etc/secsuite/*.env` (seeded from
   `deploy/ubuntu/<svc>.env` if `secdeploy configure` seeded one, else the shipped
   `deploy/ubuntu/<svc>.env.example`).
5. Install the hardened systemd units (reused from `deploy/fedora-fips/systemd/`) +
   `secsuite.target`; `daemon-reload`.
6. `systemctl enable --now secsuite.target`.
7. Add the SecCert root to the host trust store — `.crt` extension +
   `update-ca-certificates` (see [CA trust](#ca-trust)).
8. Write a deploy audit artifact to `out/audit/` — identical mechanism to fedora-fips, see
   [Deployment audit artifacts](fedora-fips.md#deployment-audit-artifacts).

Everything from here on — the SecRouter egress allow-list, the shared SecRouter/SecLLM
inference token, SecAgent (the pi harness), OIDC/audit-syslog config fragments, native SecChat
turnkey env, SecRecorder turnkey SSO, onboarding `[[users]]`, SecProxy (the generated nginx
config, TLS via SecCert/certbot, the systemd unit), `secdeploy configure`, and
`secdeploy status ubuntu` — work exactly as documented in fedora-fips.md's own sections; nothing
about them differs on ubuntu. Follow those sections directly, substituting `ubuntu` for
`fedora-fips` in any command shown.

## CA trust {#ca-trust}

Debian-family `update-ca-certificates` only picks up files under
`/usr/local/share/ca-certificates/` that end in **`.crt`** — unlike fedora's
`/etc/pki/ca-trust/source/anchors/`, which has no extension requirement.  `deploy ubuntu`
installs the SecCert root to `/usr/local/share/ca-certificates/secsuite-seccert-root.crt` (note
the extension — a `.pem` there is silently ignored) and runs `update-ca-certificates` (fedora's
`update-ca-trust extract` equivalent). Teardown reverses this: remove the `.crt` file, then
re-run `update-ca-certificates` so the refresh reflects its removal.

## SELinux / AppArmor {#hardening-applied}

fedora-fips has **no SELinux steps** to translate (`semanage`/`chcon`/`restorecon` — there are
none in `targets/fedora_fips.py`), so there's nothing to skip here either. AppArmor needs **no
configuration** for these services: the hardening boundary is the systemd sandboxing directives
already on every unit (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`ProtectKernel*`, `RestrictAddressFamilies`, `RestrictNamespaces`, `LockPersonality`, per-service
`ReadWritePaths`) — identical on both distros, see fedora-fips's own
[Hardening applied](fedora-fips.md#hardening-applied). Review and tighten further (an AppArmor
profile per unit, say) for your accreditation boundary if you need one.

## Teardown, backup, and restore

Identical mechanism and safety gates to fedora-fips — see
[Teardown](fedora-fips.md#teardown) and [Backup and restore](fedora-fips.md#backup-and-restore).
The only textual differences are the trust-anchor path (`.crt` + `update-ca-certificates`, per
[CA trust](#ca-trust) above) and the command name (`secdeploy teardown ubuntu` /
`secdeploy backup ubuntu` / `secdeploy restore ubuntu`).

```bash
sudo uv run secdeploy teardown ubuntu --dry-run   # preview — touches nothing
sudo uv run secdeploy teardown ubuntu             # asks first; --purge also wipes /var/lib/secsuite
sudo uv run secdeploy backup ubuntu --recipient backup-cert.pem --dry-run
sudo uv run secdeploy restore ubuntu <archive>.tar.cms --key backup-key.pem --dry-run
```

## Verifying this target's assets

```bash
secdeploy verify   # confirms deploy/ubuntu/fips-check.sh + the (shared) systemd units are present
```
