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

## SecAgent and Mattermost

`deploy fedora-fips --with-agent` stands up **SecAgent's chat-ops bridge** — `secagent chat
serve`, receiving Mattermost slash-commands/outgoing-webhooks and replying in-thread — on the
resource where the `collab` tier is placed (default off, opt-in exactly like
`--with-inference`/SecLLM: the peer-wiring env below is always generated once SecAgent is in
the topology, but installing + starting the service is opt-in, since it needs two manually
provisioned secrets first — see below).

```bash
sudo uv run secdeploy deploy fedora-fips --with-agent --resource <collab-resource> --dry-run
sudo uv run secdeploy deploy fedora-fips --with-agent --resource <collab-resource>
```

What `--with-agent` adds, on top of the normal steps:

1. Installs **pi** (`@earendil-works/pi-coding-agent`) globally via npm — the agent runtime
   `secagent`'s Skill/extension integrate with (see `secagent`'s own `docs/pi.md`) — alongside
   SecAgent's own code.
2. Installs `secagent.service` (`ExecStart=... secagent chat serve --port 8070`) and the
   generated addressing env `/etc/secsuite/secagent-addressing.env`, layered onto the
   operator-filled `/etc/secsuite/secagent.env` via a second `EnvironmentFile=` — the exact
   same two-file pattern as [SecRouter's own addressing env](#getting-the-generated-wiring-into-the-running-service):
   later file wins, `-`-prefixed so it's optional wherever SecAgent isn't placed/enabled.
3. Installs pi's system-wide `models.json` (`/var/lib/secsuite/secagent/.pi/agent/models.json`)
   — adapted from `secagent`'s own checked-out `pi/models.secrouter.example.json`, substituting
   the real SecRouter URL and adding the SERVICE api-key auth mode (see below); never hardcodes
   or curates the model catalog itself.
4. Prints the SecSSO/Mattermost secret-provisioning steps and the SecRouter OIDC config
   fragment (see below) — as guidance, not automated cross-host actions.

### The generated addressing env

`out/addressing/env/secagent.env` (secagent's pydantic-settings nested-env convention,
`SECAGENT_<SECTION>__<FIELD>`, confirmed against `secagent`'s own `src/secagent/config.py`):

| Key | Value |
|---|---|
| `SECAGENT_LLM__BASE_URL` | `https://secrouter.<domain>:47002/v1` — **always SecRouter**, never SecLLM directly, so chat-triggered inference stays governed/audited |
| `SECAGENT_LLM__API_KEY` | `!secagent token` — not a secret; a command SecAgent re-runs at each request (see below) |
| `SECAGENT_LLM__MODEL` | `balanced` |
| `SECAGENT_SECSSO__TOKEN_URL` | `https://secsso.<domain>:9000/application/o/token/` |
| `SECAGENT_SECSSO__CLIENT_ID` | `secagent` |
| `SECAGENT_MATTERMOST__URL` / `__TEAM` | `https://secchat.<domain>:8065` / `secrouter` |
| `SECAGENT_MATTERMOST__WEBHOOK_SECRET` | generated once, cached, never rotated on redeploy (same spirit as the [shared SecLLM token](#shared-secrouter-and-secllm-inference-token)) |
| `SECAGENT_AUDIT__ENABLED` | `true` |

### Two auth modes

SecAgent's own service identity against SecSSO (`client_credentials`, headless — see
`secagent`'s `src/secagent/secsso.py`) backs **two** distinct things on this host, both fed by
the same `secagent token` command:

- **The service/bot** — `secagent chat serve`'s own LLM calls use
  `SECAGENT_LLM__API_KEY="!secagent token"` directly (no `models.json` involved for the bot
  itself). Run `secagent token` by hand to see the bearer token it fetches (cached at
  `~/.secagent/auth/secsso-token.json`, 0600, refreshed near expiry).
- **pi run standalone/unattended on this host** — the installed
  `/var/lib/secsuite/secagent/.pi/agent/models.json` (step 3 above) gives any `pi` invocation
  as the `secsuite-secagent` user the same service identity out of the box (`apiKey:
  "!secagent token"`), for automation that doesn't have an interactive human to log in.
- **A developer using pi interactively** (not this service — their own machine or an
  interactive session on this host) instead does a **per-user OAuth device-code login**,
  attributed to *them*, not the shared service identity: load
  `pi/extensions/secrouter-auth.ts` from the `secagent` checkout, then `/login secrouter`. See
  `secagent`'s `pi/models.secrouter.example.json` and `docs/pi.md` for the full walkthrough.

Both modes ultimately reach SecRouter as the same governed/audited gateway; they differ only in
whose identity a request is attributed to.

### Provisioning the two secrets (manual — see below for why)

`/etc/secsuite/secagent.env` (seeded once from `secagent.env.example`, never overwritten) needs
two values secdeploy cannot fetch automatically — both come from a **different** host than the
one running `deploy --with-agent`, and neither source exposes a machine-readable, safely
re-invocable way to hand the value across:

```bash
# On the SecSSO host — confirms the client secret SecSSO's own operator already set in ITS
# .env (SecSSO provisions this value; secdeploy doesn't mint it):
./bootstrap/secsso.sh secagent-config
# → paste the SAME value into SECAGENT_CLIENT_SECRET on the SecAgent host's secagent.env

# On the SecChat host — MINTS a fresh Mattermost bot token and prints it ONCE:
./bootstrap/secchat.sh bot
# → paste it into SECAGENT_MATTERMOST__BOT_TOKEN on the SecAgent host's secagent.env
```

`secchat.sh bot` has no "get or create" semantics — re-running it mints a brand-new token every
time — so `deploy --with-agent` only ever *prints* this step (dry-run and real alike); it never
invokes `secchat.sh bot` itself. `secdeploy status`/`deploy` don't verify these are filled in
either — `secagent chat serve` itself refuses to start without a `mattermost.webhook_secret`
(generated automatically, see above) and will fail its own SecSSO calls loudly if
`SECAGENT_CLIENT_SECRET`/`SECAGENT_MATTERMOST__BOT_TOKEN` are still blank; check
`journalctl -u secagent.service` after first start.

The generated `SECAGENT_MATTERMOST__WEBHOOK_SECRET` (see the table above) also needs a matching
half on the Mattermost side: create a slash-command or outgoing-webhook definition in
Mattermost's own admin console with **that same value** as its token — secdeploy has no
Mattermost API access to register it for you.

### SecRouter OIDC config fragment

SecSSO's `issuer_mode: global` means every client shares one issuer, so SecRouter needs
`jwksUri` set explicitly (auto-discovery from `issuer` alone won't resolve) and SecAgent's
non-interactive service account added to `serviceSubjects` (client_credentials tokens carry no
MFA assertion, so `svc-secagent` would otherwise trip `requireMfa`). Unlike
`SECROUTER_EGRESS_FILE`, this ISN'T env-var-driven — SecRouter's `FREEROUTER_CONFIG` is a
hand-authored JSON file — so `deploy --with-agent` writes a documented fragment,
`out/addressing/secrouter-oidc.json`, for you to merge into `security.oidc` by hand:

```json
{
  "issuer": "https://secsso.<domain>/",
  "audience": "secrouter",
  "jwksUri": "https://secsso.<domain>/application/o/secrouter/jwks/",
  "serviceSubjects": ["svc-secagent"]
}
```

These values match `secsso.sh`'s own `oidc-config`/`secagent-config` output exactly (both
derive from the same SecSSO external URL), so the two never disagree.

## 4. Configure

Edit the env files the installer dropped (they don't overwrite existing ones):

```bash
sudoedit /etc/secsuite/seccert.env      # set SECCERT_ADMIN_TOKEN, SECCERT_CA_PASSPHRASE, external URL
sudoedit /etc/secsuite/secrouter.env    # point FREEROUTER_CONFIG at a hardened config
sudoedit /etc/secsuite/secrecorder.env  # or: sudo systemctl mask secrecorder.service to skip it
sudoedit /etc/secsuite/secagent.env     # --with-agent only: SECAGENT_CLIENT_SECRET + SECAGENT_MATTERMOST__BOT_TOKEN
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
