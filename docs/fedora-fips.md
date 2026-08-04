# FIPS-ready Fedora runbook

The production target: native, hardened **systemd** services on a Fedora host running in FIPS
mode. No containers — each component links the host's OpenSSL FIPS provider directly, the
tightest crypto boundary. SecDeploy refuses to deploy (fail-closed) if the host isn't FIPS-ready.

## 1. Put the host in FIPS mode

```bash
sudo fips-mode-setup --enable
sudo reboot
# after reboot, confirm:
cat /proc/sys/crypto/fips_enabled        # → 1
fips-mode-setup --check                  # → "FIPS mode is enabled."
openssl list -providers | grep -i fips   # → fips provider present
```

## 2. Runtimes

```bash
sudo dnf install -y nodejs git           # Node >= 24 for SecRouter
# uv for the Python components (SecCert, SecRecorder):
curl -LsSf https://astral.sh/uv/install.sh | sh
```

## 3. Deploy

```bash
# Always preview the exact runbook first:
sudo uv run secdeploy deploy fedora-fips --dry-run

# Then run it (as root — installs users, code, systemd units, trust anchor):
sudo uv run secdeploy deploy fedora-fips
```

`deploy fedora-fips` performs, in order:
1. **FIPS preflight** (`deploy/fedora-fips/fips-preflight.sh`) — fail-closed.
2. Create system users `secsuite-{seccert,secrouter,secrecorder}` and owner-only state dirs.
3. Build natively from the pinned checkouts (SecRouter `npm run build`; SecCert/SecRecorder `uv sync`).
4. Install code to `/opt/secsuite`, config to `/etc/secsuite/*.env`.
5. Install hardened systemd units + `secsuite.target`; `daemon-reload`.
6. `systemctl enable --now secsuite.target` (SecCert → SecRouter → SecRecorder).
7. Add the SecCert root to the host trust store (`update-ca-trust`).
8. Write a deploy audit artifact to `out/audit/` — see below.

## Deployment audit artifacts

Every real `deploy` (i.e. not `--dry-run`) writes a dated, per-resource audit record to
`out/audit/`: `deploy-<target>-<resource>.json` (machine-readable) plus a `.txt` twin (human-
readable) — the same spirit as `bundle`'s `BUNDLE-INFO.txt`, but per-deploy and aimed at CMMC
audit evidence of exactly what this run stood up and authorized. It records:

- suite version + release date, the target, and the resource's name + address;
- every component placed on **this** resource — name, pinned ref, and the git SHA it resolved
  to (`secdeploy fetch`'s checkout);
- the generated addressing: the `secdns` zone (record count + path), and — when SecRouter is
  on this resource — its SecLLM backend pool (`SECROUTER_SECLLM_ENDPOINTS`, see
  [topology.md](topology.md#multi-instance-inference-n-secllm-backends));
- the security-relevant authorizations this run made: whether the SecCert trust anchor was
  added to the host trust store, whether the resolver was pointed at `secdns`, whether the
  SecRouter↔SecLLM inference auth token is wired up (boolean only — see below, the value
  itself is never recorded here), and an **egress** section naming the SecLLM backend-pool
  hosts SecRouter is authorized to reach plus the path to the generated allow-list file that
  declares it (see [SecRouter egress allow-list](#secrouter-egress-allow-list) below) —
  inference traffic that may carry CUI, so this is SecRouter's declared egress boundary; cite
  it directly in your SSP / network boundary diagram instead of reconstructing it by hand from
  `topology.toml`;
- the flags in effect (`--with-inference`, `--tls`, `--trust-ca`, `--configure-resolver`,
  `--without`).

`--dry-run` never writes the artifact — dry-run stays side-effect-free — it instead prints a
one-line preview of the path it would write plus the headline facts (component count, whether
a trust anchor/resolver change is planned). `deploy macos` writes the same artifacts under the
same `out/audit/` layout.

### SecRouter egress allow-list

When SecRouter (gateway tier) and a SecLLM inference pool are both part of the topology,
`deploy` also generates `out/addressing/secrouter-egress.json` — a JSON array of SecRouter
`EgressRule` objects (matching `secrouter/src/security/types.ts`'s `EgressRule` exactly:
`provider`, `allowedHost`, `authorizedClassifications`, `authorization`) that explicitly
authorizes egress from SecRouter to its SecLLM backend pool:

```json
[
  {
    "provider": "secllm",
    "allowedHost": ["secllm-gpu1.sec.internal:11400", "secllm-gpu2.sec.internal:11400"],
    "authorizedClassifications": ["CUI"],
    "authorization": "Self-hosted SecLLM inference pool inside the accreditation boundary — auto-authorized by secdeploy from the site topology (see out/audit/)."
  }
]
```

`allowedHost` lists each pool instance's `host:port` — the exact form SecRouter's `checkEgress`
compares against (not the full URL), so the rule matches what SecRouter actually looks up at
request time. `authorizedClassifications` defaults to this suite's internal-CUI level (`CUI`);
override it (`wiring.secrouter_egress_rules(topology, classifications=[...])`) for a different
or broader classification ladder — `checkEgress` does an exact membership check, not a
hierarchical one, so list every level that should be allowed through.

On fedora-fips this file is installed to `/etc/secsuite/secrouter-egress.json` (owned by
`secsuite-secrouter`, refreshed on every redeploy so a topology change — e.g. adding a third
SecLLM instance — takes effect immediately, same as the `secdns` zone), and SecRouter's
generated env gets `SECROUTER_EGRESS_FILE` pointing at that installed path for SecRouter to
load directly as (or into) `security.egress.allowlist` — an explicit, deploy-time-declared
authorization alongside SecRouter's own implicit `SECROUTER_SECLLM_ENDPOINTS` turnkey intake.

### Shared SecRouter and SecLLM inference token

Alongside the egress allow-list, secdeploy generates **one** shared bearer token
(`secrets.token_urlsafe`) for SecRouter to authenticate to the SecLLM pool: `SECLLM_API_TOKEN`
in **every** SecLLM instance's generated env, and the identical `SECROUTER_SECLLM_TOKEN` in
SecRouter's own generated env. The value is cached under `out/addressing/` so every resource's
independent `deploy` invocation (each SecLLM instance's own resource, and SecRouter's) agrees
on the same token instead of minting its own; like the SecLLM admin token, it is never rotated
out from under a live pair on redeploy. The audit artifact records only whether this auth is
**enabled** (boolean) — never the token value.

### Getting the generated wiring into the running service

`SECROUTER_SECLLM_ENDPOINTS`, `SECROUTER_SECLLM_TOKEN`, and `SECROUTER_EGRESS_FILE` above all
land in one generated file, `out/addressing/env/secrouter.env` — but that alone doesn't reach
the running `secrouter.service`, which only reads `/etc/secsuite/*.env` on the target host.
When SecRouter is placed on this resource *and* the topology has a SecLLM pool, `deploy` also
installs that generated file to `/etc/secsuite/secrouter-addressing.env` — a path **distinct**
from `/etc/secsuite/secrouter.env` (the operator-owned file seeded from `secrouter.env.example`)
so it never clobbers it — and refreshes it on every redeploy (it's fully derived, like the
`secdns` zone; no `test -f` guard). `secrouter.service` declares **two**
`EnvironmentFile=` lines:

```ini
EnvironmentFile=/etc/secsuite/secrouter.env
EnvironmentFile=-/etc/secsuite/secrouter-addressing.env
```

systemd applies multiple `EnvironmentFile=` directives in the order listed, with a later file's
values overriding a same-named key from an earlier one — so **the generated addressing env is
authoritative** for any key both files set. The leading `-` on the second line makes it
optional: single-host mode, no `topology.toml`, or a topology where SecRouter isn't placed on
this resource all produce no such file, and systemd silently skips it (existing deploys with no
topology are unaffected). Don't hand-edit `secrouter-addressing.env` — it's overwritten every
deploy; change `topology.toml` instead.

> macOS's SecRouter runs in a Docker container via Compose, which has no equivalent of
> `/etc/secsuite/*.env` — `compose.yaml` only sets a couple of hardcoded vars today, so the
> generated `out/addressing/env/secrouter.env` (and this whole pool/token/egress wiring) stays
> generated-but-unapplied there. This is a known limitation of the macOS eval target, not
> something this mechanism fixes — see [docs/macos.md](macos.md) and use `fedora-fips` for a
> real multi-host deployment.

## 4. Configure

Edit the env files the installer dropped (they don't overwrite existing ones):

```bash
sudoedit /etc/secsuite/seccert.env      # set SECCERT_ADMIN_TOKEN, SECCERT_CA_PASSPHRASE, external URL
sudoedit /etc/secsuite/secrouter.env    # point FREEROUTER_CONFIG at a hardened config
sudoedit /etc/secsuite/secrecorder.env  # or: sudo systemctl mask secrecorder.service to skip it
sudo systemctl restart secsuite.target
```

SecRouter's config must enable the security block and `tls.mode: frontend|native`; it fails
closed if FIPS is required but unavailable. Start from `freerouter.config.hardened.example.json`
in the SecRouter checkout.

## 5. Operate

```bash
uv run secdeploy status fedora-fips
systemctl status secsuite.target
journalctl -u secrouter.service -f
sudo systemctl restart seccert.service
```

## Hardening applied

The units set `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`ProtectKernel*`, `RestrictAddressFamilies`, `RestrictNamespaces`, `LockPersonality`, and
per-service `ReadWritePaths` scoped to `/var/lib/secsuite/<svc>`. Review and tighten further
for your accreditation boundary.
