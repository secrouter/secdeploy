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
  "serviceSubjects": ["svc-secagent", "svc-secassist"],
  "delegatingSubjects": ["svc-secassist"]
}
```

These values match `secsso.sh`'s own `oidc-config`/`secagent-config` output exactly (both
derive from the same SecSSO external URL), so the two never disagree.

When **SecAssist** (the LibreChat chat UI) is in the topology, `svc-secassist` is added to
`serviceSubjects` **and** to `delegatingSubjects`: its auth proxy calls SecRouter on each
signed-in user's behalf, forwarding `x-sec-acting-user`, so SecRouter governs and audits chat
per end-user rather than as one shared account (see SecRouter's
`security.oidc.delegatingSubjects` and secassist/docs/governance.md).

**Turnkey env.** When SecAssist and SecSSO are both in the topology, the deploy is fully
turnkey — no manual reconciliation: it mirrors SecSSO's two generated OIDC secrets into
`work/secassist/.env` and writes the topology-derived issuer / SecRouter URL / domain there
(see `wiring.sync_secassist_env`), leaving the per-instance secrets for the stack's own seed.
An external IdP (no SecSSO) means you supply those two secrets yourself, as before.

**Native SecChat (`secchatng`, experimental — opt in with `--with secchatng`).** Same turnkey
shape as SecAssist above, one client instead of two: when secchatng and SecSSO are both in the
topology, the deploy mirrors SecSSO's generated `SECCHATNG_OIDC_CLIENT_SECRET` into
`work/secchatng/.env`'s `SECCHAT_OIDC_CLIENT_SECRET` and writes the topology-derived
`SECCHAT_OIDC_ISSUER` / `_AUDIENCE` / `_CLIENT_ID` / `SECCHAT_PUBLIC_URL` / `SECROUTER_URL`
there too (see `wiring.sync_secchatng_env`). secchatng's backend runs the OIDC Authorization
Code + PKCE exchange itself (a BFF — the browser only ever gets an httpOnly session cookie), so
unlike SecAssist's auth proxy there's no second, client_credentials service secret to mirror,
and no `svc-secchatng` entry in the OIDC config fragment above. `SECCHAT_SESSION_SECRET` (the
session-cookie signing key) is untouched by this sync — it's seeded blank-to-random the same
way as every other stack's per-instance secrets.

## Onboarding users (`[[users]]`)

Declare accounts once in `secsite.toml` and the deploy creates them in SecSSO with a random
initial password that must be reset on first login:

```toml
[[users]]
username = "alice"
email = "alice@example.mil"
groups = ["analysts"]      # created if absent; match SecRouter's security.policy.groups
```

`secdeploy deploy` renders these into `work/secsso/blueprints/users.generated.yaml` (state:
`created` — never overwrites a password the user later changes) and **prints the initial
credentials once** for you to distribute. It relies on secsso's `force-password-reset.yaml`
(shipped) for the forced reset. Re-running never rotates an already-provisioned password.

## SecProxy (edge reverse proxy)

Placing the `edge` tier stands up **secproxy** — [nginx](https://nginx.org) — as the suite's
one HTTPS front door. Like `secdns`, it needs no `--with-*` flag: it deploys the moment a
topology places the `edge` tier here.

```bash
sudo uv run secdeploy deploy fedora-fips --resource <edge-resource> --dry-run
sudo uv run secdeploy deploy fedora-fips --resource <edge-resource>
```

**Why nginx (and why it's the FIPS choice).** In FIPS mode the crypto boundary is the host's
OpenSSL FIPS provider. nginx links that **system OpenSSL**, so all edge TLS termination runs
through the FIPS-validated module — the reason the suite standardized on nginx for its reverse
proxy. (The macOS eval target runs the same nginx; see [macos.md](macos.md).)

### What it fronts

secproxy terminates TLS on **:443** and reverse-proxies by Host header to the real
`host:port` for the components `suite.toml` marks `fronted`: **secsso, secrouter, secagent,
secchat, secrecorder**. Three components are deliberately **never** fronted, reached directly
at their own `host:port` instead: **seccert** (the CA secproxy bootstraps its own cert from —
it can't sit behind the front door it issues certs for), **secllm** (inference must dial
direct, never hop through the proxy), and **secdns** (not HTTP). secproxy never fronts
itself either. See [topology.md#reverse-proxy-secproxy](topology.md#reverse-proxy-secproxy)
for how placement drives which FQDNs actually resolve through it.

### The generated nginx config

SecDeploy generates secproxy's entire configuration from the site topology
(`wiring.nginx_conf_text()`) — a complete nginx config (`events`/`http` blocks), containing a
`map` for WebSocket upgrades, a **:80** server (the ACME HTTP-01 webroot for renewal plus a
blanket HTTP→HTTPS redirect), and one **:443** `server { … proxy_pass … }` block per fronted,
placed component, each pointing straight at the backend's real `host:port`. It is written to
`out/addressing/secproxy.nginx.conf` and installed — unconditionally refreshed on every
redeploy (it carries no secret, exactly like the `secdns` zone) — to:

```
/etc/secsuite/nginx-secproxy.conf
```

nginx runs it as a complete config: `nginx -c /etc/secsuite/nginx-secproxy.conf -g 'daemon
off;'`. Every writable path (pid, logs, temp dirs, the ACME webroot) lives under the service
state dir `/var/lib/secsuite/secproxy`, so nothing touches nginx's default (read-only under
`ProtectSystem=strict`) `/var/log/nginx`, `/var/lib/nginx`, or `/run` paths. Don't hand-edit
the installed file — a redeploy overwrites it. Change `topology.toml` and redeploy instead. See
[secproxy's own `nginx-secproxy.conf.example`](https://github.com/secrouter/secproxy) for the
exact shape the generator emits.

### TLS via SecCert (the deploy-time SAN cert)

Unlike a self-ACME proxy, nginx does **not** run an ACME client. SecDeploy issues **one SAN
certificate** covering every fronted FQDN from **SecCert**'s ACME directory
(`http://seccert.<domain>:47001/acme/directory`) using `certbot --standalone` at deploy time,
under a single `--cert-name secproxy` with one `-d <fqdn>` per fronted component, and installs
it to:

```
/etc/secsuite/secproxy/fullchain.pem
/etc/secsuite/secproxy/privkey.pem      # 0600, owned by secsuite-secproxy
```

Every `:443` `server` block reads that same pair (the whole point of one SAN cert). nginx trusts
SecCert's root the same way every other suite component on this host does: the system trust
store, populated by the `update-ca-trust` step in the normal deploy flow above — nothing extra
to configure for that.

### Bootstrap ordering (flagged) and renewal

certbot's HTTP-01 challenge is answered by the `--standalone` responder on **:80**, which
imposes an ordering assumption worth stating plainly:

- **Port 80 must be free** when certbot runs — so issuance is ordered **before** nginx starts
  (the cert steps come ahead of `systemctl enable --now secsuite.target`).
- **SecCert must be reachable** and the **fronted FQDNs must resolve to this proxy host** (via
  secdns's fronted-axis zone) so SecCert can reach the responder for each of the five names —
  i.e. secdns up + this host's resolver pointed at it (`--configure-resolver`, or a manual
  `/etc/resolver`/`/etc/hosts`). On a from-scratch first deploy SecCert may not be configured or
  running yet, so the issuance step is **non-fatal**: it prints guidance instead of aborting the
  deploy, and nginx's own `ExecStartPre=nginx -t` then fails closed (secproxy stays down, the
  rest of the suite is unaffected) until the cert lands. A **redeploy re-issues idempotently**
  once SecCert is up and names resolve.

**Renewal** reuses the running nginx's `:80` `/.well-known/acme-challenge/` webroot (served out
of `/var/lib/secsuite/secproxy/acme`), so it does **not** need to stop nginx:

```bash
certbot renew --webroot -w /var/lib/secsuite/secproxy/acme && nginx -s reload -c /etc/secsuite/nginx-secproxy.conf
```

Wire that into a `certbot renew` timer (add `--deploy-hook` to re-copy the renewed
`fullchain.pem`/`privkey.pem` into `/etc/secsuite/secproxy/` and run the `nginx -s reload`).
This wave issues at deploy time and documents renewal rather than fully automating the timer.

### The systemd unit

`secproxy.service` (`deploy/fedora-fips/systemd/secproxy.service`) runs nginx as a dedicated,
non-root `secsuite-secproxy` user, with the same hardening block as every other unit here
(`NoNewPrivileges`, `ProtectSystem=strict`, `RestrictAddressFamilies`, etc.) plus
`AmbientCapabilities=CAP_NET_BIND_SERVICE` to bind the privileged **:443**/**:80** ports
without root — exactly the mechanism `secdns.service` uses to bind **:53**. `ReadWritePaths`
grants `/var/lib/secsuite/secproxy` (where the generated config points nginx's pid, logs, temp
dirs, and the ACME webroot). It orders itself `After=` both `secdns.service` and
`seccert.service`: nginx serves backends by the names secdns resolves, and its cert is issued
from SecCert, so both need to be up first. `ExecStartPre=nginx -t` validates the config (and
fails closed if the SecCert-issued cert isn't in place yet); `ExecReload=nginx -s reload` wires
`systemctl reload secproxy` to nginx's own graceful, connection-preserving config reload.

### Installing the nginx runtime

Unlike every other unit on this page, secproxy has no pinned source checkout to build — nginx is
an upstream package (see secproxy's own README), not something `secdeploy build fedora-fips`
compiles. `deploy fedora-fips` therefore installs the runtime as a one-time prerequisite (the
same way node/npm and uv are provisioned for the other units — see the [Runtimes](#2-runtimes)
step), alongside the `certbot` ACME client that mints the SAN cert above:

```bash
dnf install -y nginx certbot
```

A native package under its own hardened systemd unit was chosen over a Podman container
deliberately: secproxy's `suite.toml` `kind` is `"service"` (like `secdns`, `secllm`,
`secrouter`, `secagent`, `secrecorder`), not `"stack"` — the kind reserved for the
Podman/Compose path (`secsso`/`secchat`, brought up via their own `bootstrap/<name>.sh`, a
wholly separate mechanism — see `targets/common.py`'s `deploy_stacks`). Running nginx natively
also keeps its privileged-port binding identical in spirit to every other native unit here:
`AmbientCapabilities=CAP_NET_BIND_SERVICE` grants the port bind directly to the nginx process,
the same way `secdns.service` binds `:53` — a guarantee that gets considerably murkier once a
container boundary (and, for rootless Podman, its own port-publishing path) sits in between.

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

> **Filling these in *before* the first deploy.** `secdeploy configure`'s optional secret-
> seeding step (asked right after it writes `secsite.toml`) can pre-fill these same values —
> `SECCERT_ADMIN_TOKEN`/`SECCERT_CA_PASSPHRASE`, `SECAGENT_CLIENT_SECRET`/
> `SECAGENT_MATTERMOST__BOT_TOKEN`, `HF_TOKEN`, `FREEROUTER_CONFIG` — into the checkout's own
> `deploy/fedora-fips/<svc>.env` (gitignored, `0600`), which `deploy` then installs to
> `/etc/secsuite/<svc>.env` on first run **in place of** the blank `.env.example` (the
> `test -f … || install …` non-clobber guard still applies — an already-seeded target host is
> never overwritten). See [secsite.md § Seeding operator secrets](secsite.md#seeding-operator-secrets-optional).

## 5. Operate

```bash
uv run secdeploy status fedora-fips
systemctl status secsuite.target
journalctl -u secrouter.service -f
sudo systemctl restart seccert.service
```

## Teardown

`secdeploy teardown fedora-fips` reverses a deploy — it removes the services, users, code,
config, trust anchor, resolver drop-in, and stack(s) a deploy stood up on **this host**.

```bash
# Always preview first — prints the exact plan, touches nothing:
sudo uv run secdeploy teardown fedora-fips --dry-run

# Then run it for real (as root — same requirement as deploy):
sudo uv run secdeploy teardown fedora-fips
```

**It discovers, it doesn't assume.** `deploy` is purely *additive* — a narrower redeploy (a
smaller topology, a dropped `--with-inference`/`--with-agent`, a new `--without`) never
removes a component that fell out of it, so the live host can be a **superset** of any one
`topology.toml`/deploy-flags/`out/audit/*.json` combination. `teardown` therefore **probes
this host directly** (which unit files exist under `/etc/systemd/system`, which
`secsuite-*` users `getent passwd` finds, which directories exist under `/opt/secsuite`,
`/etc/secsuite`, `/var/lib/secsuite`, whether the trust anchor and the resolver drop-in are
present, which stack checkouts have a `bootstrap/<name>.sh`) and removes exactly what it
finds — never what `topology.toml`, the deploy flags, or a prior audit artifact say *should*
be here. If a prior deploy's audit JSON exists under `--out`, teardown prints a one-line
**drift note** naming what it recorded, purely as a courtesy comparison — it never drives
what gets torn down.

**The plan, in order:** stop + disable `secsuite.target` (cascades via `PartOf=`), then per
discovered unit `systemctl stop` + `unmask` (an operator may have masked one — see
`secrecorder.env.example`) + remove the unit file, then `daemon-reload`; remove the
`secsuite-*` users (**after** services are stopped, `userdel` with **no** `-r` — state stays
until `--purge`); remove `/opt/secsuite/<svc>` code (always — it's rebuildable); remove
`/etc/secsuite` config (always, with a printed warning — see below); remove the SecCert trust
anchor and refresh the trust store; remove the `systemd-resolved` drop-in and restart it; and
bring down any SecSSO/SecChat stack via its own `bootstrap/<name>.sh down`.

**Safety gates:**

- `--dry-run` prints the full discovered plan and stops — nothing is touched.
- Without `--dry-run`, the full plan is still printed first, then you're asked to confirm
  before anything runs; `-y`/`--yes` skips the prompt (for automation).
- `/etc/secsuite` holds **operator-typed secrets with no backup anywhere else** —
  `SECCERT_CA_PASSPHRASE`, `SECCERT_ADMIN_TOKEN`, `SECAGENT_CLIENT_SECRET`,
  `SECAGENT_MATTERMOST__BOT_TOKEN` in the `*.env` files. Teardown prints this warning before
  removing the directory; copy it aside first if you'll need any of those values again.
- Distro packages (`nodejs`/`npm`, `uv`, `nginx`, `certbot`, `podman`) and the global npm
  package `@earendil-works/pi-coding-agent` are **never removed** — they're listed under "NOT
  removed" only, since an interactive `pi` session (or other tooling) on this host may still
  depend on them.

### `--purge`: also wiping persistent data

Without `--purge`, `/var/lib/secsuite` is **never even mentioned**. `--purge` adds
`rm -rf /var/lib/secsuite/<svc>` for every discovered service, and asks a **second, separate,
extra-loud confirmation** before doing it — because for two services this is irreversible in
a way the rest of teardown isn't:

- **SecCert** (`/var/lib/secsuite/seccert`) holds the **CA private key and its passphrase**.
  Deleting it invalidates every certificate SecCert has issued *and* the trust anchor already
  distributed to every client that trusts it — there is no undo.
- **SecAgent** (`/var/lib/secsuite/secagent`) holds the **CMMC audit log**
  (`audit/audit.jsonl`) — required evidence, not just working state.

Back up `/var/lib/secsuite/{seccert,secagent}` (and `out/audit/` from any host that ran a
deploy) *before* confirming `--purge` if you might need either again. Declining the
purge-specific confirmation does **not** abort the rest of the teardown — it just leaves
`/var/lib/secsuite` in place and continues with everything else. Note that
`/var/lib/secsuite/secdns/secdns.zone` is removed under `--purge` too, purely for
completeness — unlike the two above, it's fully regenerable from `topology.toml` and isn't
itself a secret.

### Stacks (SecSSO / SecChat)

If a stack's checkout (`work/secsso` or `work/secchat`, i.e. it has a
`bootstrap/<name>.sh`) is present, teardown brings it down via that same script:
`bootstrap/<name>.sh down` (config and its data volume kept) — or `down -v` under `--purge`,
which also wipes the stack's own data volume.

### Resolver: a host-wide, cross-host caveat

Removing `/etc/systemd/resolved.conf.d/secsuite.conf` reverts this host's DNS resolution
host-wide. If **another** host still points its resolver at this one for the suite's
domain, tearing this down strands it — that's an operator call teardown can't make for you.

### What teardown does *not* do

- It never runs `git`, and never touches `topology.toml`, `suite.toml`, or any deploy flag —
  see "it discovers, it doesn't assume" above.
- It never removes a distro package, or the global `pi` npm package — see "NOT removed"
  above.
- It doesn't attempt to detect a SecSSO/SecChat stack that's still *running* if its checkout
  under `work/` has been deleted since the deploy that brought it up — there's no
  `bootstrap/<name>.sh` left to invoke `down` with in that case, so it's left running. Bring
  it down by hand (`docker`/`podman compose down`) first if that's happened.

## Backup and restore

`secdeploy backup fedora-fips` captures **this host's entire suite state** — every native
service's `/var/lib/secsuite/<svc>` (the SecCert **CA private key**, SecRouter's hash-chained
audit/usage SQLite, SecAgent's `audit.jsonl`, the SecDNS zone), all of `/etc/secsuite/*.env`
(the secrets that decrypt/authorize the rest — `SECCERT_CA_PASSPHRASE`, tokens), and each
stack's database + uploads (Authentik, Mattermost, LibreChat) — into **one encrypted archive**.

**Why one encrypted archive, all or nothing.** The state and its secrets are cryptographically
coupled: LibreChat's `CREDS_KEY` (in its `.env`) decrypts secrets *inside* the Mongo dump,
`SECCERT_CA_PASSPHRASE` decrypts the CA keys, SecSSO's `users.generated.yaml` holds cleartext
initial passwords. A data-only backup is un-restorable, so it's data + secrets + certs together
— or nothing — and it is always encrypted.

### Encryption: public-key, to a recipient cert (private key offline)

The archive is encrypted with **OpenSSL CMS** (RFC 5652 EnvelopedData) and **AES‑256** — FIPS
approved, and on this host driven by OpenSSL's FIPS provider (unlike `age`/ChaCha20, which is
not FIPS-approved). Encryption is **public-key**: you encrypt *to* an X.509 **recipient cert**;
the matching **private key is held offline** and is only needed to *restore*. Nothing secret
sits on the backup host — which is what makes an unattended backup safe.

**SecCert can mint the recipient cert** — it's a normal leaf/server cert (RSA or EC). Or use
any X.509 keypair, e.g.:

```bash
openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
  -keyout backup-key.pem -out backup-cert.pem -subj "/CN=secsuite-backup"
# → keep backup-key.pem OFFLINE (an HSM, an air-gapped USB); distribute only backup-cert.pem
```

### Taking a backup

```bash
# Preview — prints exactly what it would capture, reads/writes nothing:
sudo uv run secdeploy backup fedora-fips --dry-run

# Real backup — encrypts to the recipient cert (stacks must be up so their DBs can be dumped):
sudo uv run secdeploy backup fedora-fips --recipient backup-cert.pem
```

This writes, under `out/backups/`:

- `secsuite-fedora-fips-<resource>-<UTC>.tar.cms` — the AES‑256/CMS **encrypted** archive.
- `…​.manifest.json` / `…​.manifest.txt` — a manifest recording **only** metadata: what was
  captured (filenames), sizes, the plaintext **SHA‑256** (restore verifies it), the cipher, and
  the recipient cert **fingerprint** (so you know which offline key opens it). **Never a secret
  value.**

Backup runs as root, is **read-only** (services are not stopped), and never leaves plaintext
outside a temp staging dir that is wiped as soon as the archive is encrypted. Store the
`.tar.cms` like a secret; keep the private key offline — it is the *only* thing that can
decrypt it (there is no recovery without it).

### Restoring

```bash
# Preview the fixed restore flow (contents are only visible after decrypt, so this shows the flow):
sudo uv run secdeploy restore fedora-fips out/backups/secsuite-fedora-fips-core-<UTC>.tar.cms --dry-run

# Real restore — needs the OFFLINE private key; OVERWRITES this host's state (asks first):
sudo uv run secdeploy restore fedora-fips \
  out/backups/secsuite-fedora-fips-core-<UTC>.tar.cms --key backup-key.pem
```

Restore decrypts, **verifies the plaintext SHA‑256** against the manifest (fail-closed if it
doesn't match — the out-of-band integrity check that stands in for AEAD), stops
`secsuite.target`, restores native state **SecCert-CA-first** then `/etc/secsuite` then the
rest, restores each stack via its own `bootstrap/<name>.sh restore` (which reinitializes that
stack's DB from a clean volume so the restored `.env` secret keys match the dump), and restarts.
It is **destructive** — it overwrites the databases, the CA, and the audit logs — so it asks a
confirmation first (`-y`/`--yes` for automation). Keep the `…​.manifest.json` next to the
archive to enable the integrity check.

**After a restore, verify the integrity chains** before trusting the host: SecRouter's audit
chain (`GET /audit/verify` on the gateway), SecAgent's (`secagent audit verify`), and SecCert's
issuing log — all should report an unbroken chain.

> Scope: this is **on-demand**. A scheduled systemd-timer backup is a later maintenance item.
> The stacks must be running to be dumped; a stopped stack fails the backup loudly rather than
> writing a silently-incomplete archive.

## Hardening applied

The units set `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`ProtectKernel*`, `RestrictAddressFamilies`, `RestrictNamespaces`, `LockPersonality`, and
per-service `ReadWritePaths` scoped to `/var/lib/secsuite/<svc>`. Review and tighten further
for your accreditation boundary.
