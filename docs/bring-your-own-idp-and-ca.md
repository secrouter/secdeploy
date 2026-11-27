# Bring your own IdP and CA (deploying without SecSSO / SecCert)

SecCert (CA), SecSSO (IdP), and SecDns (DNS) are the suite's "start-from-zero"
identity & trust tier. If you already run that infrastructure, drop the bundled
component and point the suite at yours:

```bash
secdeploy deploy fedora-fips --without seccert,secsso        # drop the CA and IdP
```

`--without` works on `plan` / `fetch` / `build` / `bundle` / `deploy`; only
`optional` components may be dropped (see [Optional infrastructure](../README.md)).
In a `secsite.toml` deploy the same list lives under `[deploy].without`.

Dropping a component removes only the *turnkey wiring* it provided — the suite
still needs the same values, you now supply them yourself. This page is the
runbook for the two most common cases:

- **[Part A — External IdP (Azure Entra ID)](#part-a--external-idp-azure-entra-id)**
  in place of SecSSO.
- **[Part B — Pre-generated TLS certificates](#part-b--pre-generated-tls-certificates)**
  in place of SecCert.

The two are independent — do either, both, or neither. They extend the turnkey
sections of the [Fedora/FIPS runbook](fedora-fips.md) and the
[macOS runbook](macos.md); this page is the "negative case" of each.

---

## Part A — External IdP (Azure Entra ID)

### What SecSSO did for you, and what you now own

With SecSSO in the topology, `deploy` auto-wires OIDC end to end: it registers
clients, mirrors client secrets into each consumer's `.env`, and writes the
topology-derived issuer/audience/client-id values (see the turnkey sections in
[fedora-fips.md](fedora-fips.md#native-secchat-turnkey-env)). Without SecSSO,
**none of that runs** — you register the apps in Entra and set the values by hand
in three places:

1. **SecRouter** — the enforcement point. It *verifies* every inbound bearer
   token against the IdP (issuer + JWKS). Configured in its hand-authored
   `SECROUTER_CONFIG` JSON, `security.oidc` block.
2. **SecAgent** — *obtains* tokens from the IdP (a service identity for headless
   calls, and a per-user device-code login). Configured under `secsso:` in
   `~/.secagent/config.yaml` (or `SECAGENT_SECSSO__*` env vars).
3. **SecChat / SecRecorder** — browser sign-in (Authorization Code + PKCE) and
   token validation. Configured via their `SEC*_OIDC_*` env vars.

> **Heads-up: `secagent init --domain` is Authentik-only.** Its URL templating
> appends Authentik's fixed OAuth2 paths (`/application/o/token/`,
> `/application/o/device/`) and it only writes the *device-code* fields. For
> Entra you set the SecAgent OIDC values by hand (below), and it never touches
> SecRouter's config at all.

### A.1 Register the apps in Entra

Entra maps to the suite's three grants as follows. Create these app
registrations in your tenant (`<tenant-id>` is the directory/tenant GUID):

| Suite need | Entra app registration | Grant |
|---|---|---|
| **SecRouter API** (the resource; defines the token audience) | An app exposing an API — set an **Application ID URI** (e.g. `api://secrouter`) and expose a delegated scope (e.g. `secrouter.access`) plus, optionally, **app roles** | — (resource server) |
| **SecAgent service identity** (`secagent token`, headless) | A **confidential** client with a **client secret**, granted the SecRouter API's **application permission** (app role) | client_credentials |
| **SecAgent per-user login** (`secagent login`) | A **public** client (`allowPublicClient: true`), granted the SecRouter API's **delegated** scope | device code |
| **SecChat / SecRecorder browser login** | A confidential (BFF) client with a **Web** redirect URI `…/auth/callback`, delegated SecRouter scope + `openid profile email` | auth code + PKCE |

Grant admin consent for the application permission (client_credentials cannot
prompt a user to consent), and — if you use app roles for authorization — assign
the roles to the service principal / users.

### A.2 Point SecRouter's verifier at Entra

SecRouter's `security.oidc` block is **config-file only** (no env overrides). Edit
the JSON that `SECROUTER_CONFIG` points at (`/etc/secsuite/secrouter.config.json`
on Fedora; `/addressing/secrouter.config.json` in the macOS compose) — start from
`freerouter.config.hardened.example.json` in the SecRouter repo, whose example
block is **Keycloak-shaped** and must be changed for Entra:

```json
{
  "security": {
    "enabled": true,
    "oidc": {
      "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
      "audience": "<secrouter-api-app-client-id>",
      "rolesClaim": "roles",
      "serviceSubjects": ["<secagent-service-principal-object-id>"]
    }
  }
}
```

What changes vs. the SecSSO/Keycloak default, and why:

- **`issuer`** → Entra v2 issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`
  (not a Keycloak `/realms/<realm>` URL). It must match the token's `iss` exactly.
- **`jwksUri`** → **omit it.** SecRouter discovers the keys from
  `<issuer>/.well-known/openid-configuration` automatically. (If you must pin it:
  `https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys`.) Delete the
  example's Keycloak `…/protocol/openid-connect/certs` value.
- **`audience`** → the SecRouter API app's **client ID (GUID)** or its Application
  ID URI (`api://secrouter`) — **whichever the token actually carries in `aud`**.
  The example's literal `"secrouter"` will not appear in an Entra token. Decode a
  real token at [jwt.ms](https://jwt.ms) and copy its `aud` verbatim.
- **`rolesClaim`** → set to **`"roles"`** (Entra's flat app-roles claim). The
  hardened example's `"realm_access.roles"` is Keycloak-specific and will not
  resolve.
- **`serviceSubjects`** → the SecAgent service principal's **object ID** (the
  `sub`/`oid` in an app-only token — confirm at jwt.ms). App-only
  (client_credentials) tokens carry no MFA assertion, so without this they would
  trip `requireMfa`. This exempts the service account from MFA/`acr` checks only —
  it does **not** grant it authorization.
- **`algorithms`** → leave at the default; Entra signs with **RS256**, which is
  allowed. (`none` and `HS*` are always rejected.)

Leave the rest of the security block as your posture requires. `requireMfa` /
`requiredAcr`: Entra's `amr`/`acr` values differ from the RFdS/Keycloak defaults
in the example — prefer enforcing MFA with an Entra **Conditional Access** policy
and leaving `requireMfa` off, or set `mfaAmrValues` to what your tenant actually
emits (verify at jwt.ms).

> **Groups caveat.** `groupsClaim` defaults to `"groups"` and works, but Entra
> emits group **object-ID GUIDs** (not names) and *omits* the claim entirely for
> users in more than ~200 groups (an "overage" pointer is sent instead). Prefer
> **app roles** (`rolesClaim: "roles"`) for authorization, and map SecRouter
> `security.policy.groups` / `security.policy.users` to the GUIDs/subs you see in
> a real token.

SecRouter **fails closed**: an invalid or missing `security.oidc` block prevents
startup. Restart SecRouter after editing.

### A.3 Point SecAgent at Entra

Set these under `secsso:` in `~/.secagent/config.yaml` (or as
`SECAGENT_SECSSO__*` env vars — the mapping is 1:1, uppercased). Because
`secagent init` can't template Entra endpoints, author them directly:

```yaml
secsso:
  # Service identity — `secagent token` (headless / non-interactive)
  token_url: "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token"
  client_id: "<secagent-service-client-id>"
  client_secret_env: "SECAGENT_CLIENT_SECRET"   # NAME of the env var, not the secret
  scope: "api://secrouter/.default"             # client_credentials requires <resource>/.default

  # Per-user identity — `secagent login` (device code)
  device_authorization_url: "https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/devicecode"
  device_client_id: "<secagent-public-client-id>"
  device_scope: "openid profile email api://secrouter/secrouter.access"
```

Notes:

- **`client_secret_env`** names the environment variable that holds the secret;
  export the actual Entra client secret there out of band
  (`export SECAGENT_CLIENT_SECRET=…`). The secret is read at request time and is
  never written to config.
- **`scope` (service)** must be `<resource>/.default` for client_credentials —
  Entra rejects dynamic scopes on that grant. This yields a token whose `aud` is
  the SecRouter API app; that `aud` must equal SecRouter's `audience` (A.2).
- **`device_scope` (per-user)** requests a *delegated* scope you exposed on the
  SecRouter API app (e.g. `secrouter.access`), plus `openid profile email`. The
  literal `secrouter` scope from the defaults does not exist in Entra — replace it.
- **`device_client_id`** is the **public** client's ID (device code uses no
  secret). **`client_id`** is the confidential service client's ID.
- `username` (default `svc-secagent`) is informational only and never sent.

Then `secagent login` runs the Entra device-code flow, and
`api_key: "!secagent token --user"` (per-user) or `"!secagent token"` (service)
resolves tokens for every LLM call. Confirm the wiring with `secagent doctor`.

### A.4 Point SecChat / SecRecorder at Entra

When SecSSO is co-placed, `deploy` derives these values from the topology and
mirrors SecSSO's generated client secret into each component's `.env`
(`wiring.sync_secchat_env` / `sync_secrecorder_env`). Without SecSSO **that sync
does not run** — set each variable yourself. Both components are BFFs: their
backend runs the OIDC Authorization Code + PKCE exchange server-side and the
browser only ever holds an httpOnly session cookie, so each needs a **confidential
(Web)** Entra app registration with a client secret and a redirect URI of
`<PUBLIC_URL>/auth/callback`.

**SecChat** — in `work/secchat/.env` (defaults shown are the SecSSO/Authentik
values these replace):

| Variable | SecSSO default | Set to (Entra) |
|---|---|---|
| `SECCHAT_OIDC_ISSUER` | `https://secsso.<domain>/application/o/secchatng/` | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `SECCHAT_OIDC_AUDIENCE` | `secchatng` | the SecChat app's client ID / app ID URI (must equal the token `aud`) |
| `SECCHAT_OIDC_CLIENT_ID` | `secchatng` | the SecChat app registration client ID |
| `SECCHAT_OIDC_CLIENT_SECRET` | mirrored from SecSSO | the SecChat app's client secret |
| `SECCHAT_PUBLIC_URL` | its fronted URL | SecChat's own external URL — register `<SECCHAT_PUBLIC_URL>/auth/callback` as a **Web** redirect URI in Entra |
| `SECROUTER_URL` | the SecRouter peer URL | unchanged — SecRouter's `/v1` base (the assistant path) |

`SECCHAT_SESSION_SECRET` (the session-cookie signing key) is **not** an IdP value —
it stays operator-set and **stable** across redeploys (`openssl rand -base64 36`).

**SecRecorder** — in `/etc/secsuite/secrecorder.env` (Fedora). SSO is off until
these are set (start from `deploy/fedora-fips/secrecorder.env.example`):

| Variable | SecSSO default | Set to (Entra) |
|---|---|---|
| `SECRECORDER_OIDC_ISSUER` | `https://secsso.<domain>/application/o/secrecorder/` | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `SECRECORDER_OIDC_AUDIENCE` | `secrecorder` | the SecRecorder app's client ID / app ID URI |
| `SECRECORDER_OIDC_CLIENT_ID` | `secrecorder` | the SecRecorder app registration client ID |
| `SECRECORDER_OIDC_CLIENT_SECRET` | mirrored from SecSSO | the SecRecorder app's client secret |
| `SECRECORDER_PUBLIC_URL` | its fronted URL | SecRecorder's external URL — builds the `…/auth/callback` redirect (register it in Entra) and the cookie `Secure` flag |

`SECRECORDER_SESSION_SECRET` stays operator-set and stable (as above). The
summarization knobs (`SECRECORDER_SUMMARIZE_ENABLED` / `_MODEL` / `_API_KEY` /
`_PROMPT`) are unrelated to the IdP; leave `SECRECORDER_SUMMARIZE_ENDPOINT` at
SecRouter's `/v1` so summary calls stay governed.

Use the **same Entra `issuer`** as SecRouter (A.2) for both components, and give
each its own app registration so `audience`/`client_id` are distinct. Each
component's token `aud` must be accepted by SecRouter — either register these as
separate SecRouter policy subjects, or expose the SecRouter API scope to each so
their tokens carry SecRouter's audience.

### A.5 Verify

```bash
# 1. Service token issues and is accepted by SecRouter
SECAGENT_CLIENT_SECRET=… secagent token            # prints an access token
#    decode it at https://jwt.ms — check iss / aud / (sub for serviceSubjects)

# 2. A governed call succeeds end to end
curl -H "Authorization: Bearer $(SECAGENT_CLIENT_SECRET=… secagent token)" \
     https://secrouter.<domain>/v1/models

# 3. Interactive login
secagent login && secagent doctor
```

If SecRouter rejects the token, the usual culprits are `aud` mismatch (A.2 vs the
token's real `aud`), a wrong `issuer` (must be the `/v2.0` form), or `requireMfa`
tripping a service token not listed in `serviceSubjects`.

---

## Part B — Pre-generated TLS certificates

### What SecCert did for you, and what you now own

SecCert is an internal **ACME CA** (RFC 8555, HTTP-01), not a file generator: it
stands up a Root+Intermediate on first boot, then *issues leaf certs on demand*
to ACME clients (the deploy drives `certbot` against it). Dropping it with
`--without seccert` means the deploy:

- issues **no** certificates (`certbot` is not run), and
- **skips** installing SecCert's root into the host trust store.

So you provide two things yourself: **(1) a trust anchor** (the CA that signed
your certs) and **(2) the leaf server certificate(s)** the front door presents.

### B.1 What your certs must satisfy

All files **PEM**. Keys **RSA (3072/4096)** or **ECDSA (P-256/P-384)** to stay in
the suite's FIPS cipher set. Leaf certificates:

- **SubjectAltName** must list every fronted FQDN **plus the bare domain**. The
  fronted set is `<component>.<domain>` for each fronted, placed component
  (e.g. `secsso.<domain>`, `secrouter.<domain>`, `secchat.<domain>`); secproxy,
  secllm, secdns, and seccert are not fronted. Run `secdeploy plan <target>` (or
  check `out/seccert-compose.override.yaml`'s `extra_hosts`) to see the exact list
  for your topology.
- **ExtendedKeyUsage** must include `serverAuth` (and `clientAuth` too if the same
  leaf is reused as an mTLS client cert — see B.6).
- One SAN cert covering all fronted names is the model secproxy expects (every
  `:443` server block reads the same pair).

### B.2 Install the trust anchor

Every consumer must trust whatever CA signed your leaf certs — otherwise
SecRouter/SecChat fail `UNABLE_TO_VERIFY_LEAF_SIGNATURE` on their first HTTPS
JWKS fetch to the IdP.

- **The `SUITE_CA_PATH` seam (both targets).** The compose files mount
  `${SUITE_CA_PATH:-../../out/seccert-root.pem}` into containers at
  `/etc/ssl/certs/suite-ca.pem` and set `NODE_EXTRA_CA_CERTS` to it. Point
  `SUITE_CA_PATH` at your own CA bundle instead of the SecCert root:

  ```bash
  export SUITE_CA_PATH=/path/to/your-ca-bundle.pem
  ```

- **Fedora host trust.** The `update-ca-trust` step is skipped when seccert isn't
  deployed, so add your CA to the host store yourself:

  ```bash
  sudo cp your-ca-bundle.pem /etc/pki/ca-trust/source/anchors/suite-ca.pem
  sudo update-ca-trust
  ```

- **Host-side clients** (curl/python against the suite): point them at your bundle,
  as the docs already show for the SecCert root —
  `export SSL_CERT_FILE=/path/to/your-ca-bundle.pem REQUESTS_CA_BUNDLE=/path/to/your-ca-bundle.pem`.

- **macOS keychain**: import your CA if you want system-wide trust (the equivalent
  of the deploy's `--trust-ca`, which normally adds the SecCert root).

### B.3 Install the secproxy leaf (the front-door cert)

secproxy (nginx) does not run ACME; it just reads a fixed pair. Drop your PEM
files there instead of letting the deploy issue them (this replaces the
[TLS via SecCert](fedora-fips.md#tls-via-seccert-the-deploy-time-san-cert) step):

- **Fedora:** `/etc/secsuite/secproxy/fullchain.pem` and
  `/etc/secsuite/secproxy/privkey.pem` (privkey `0600`, owned by
  `secsuite-secproxy`).
- **macOS:** `out/secproxy/cert/fullchain.pem` and `out/secproxy/cert/privkey.pem`.

`fullchain.pem` = leaf **first**, then intermediate(s). nginx's
`ExecStartPre=nginx -t` **fails closed** — secproxy stays down until a valid pair
is in place, and the rest of the suite is unaffected while you sort it out.
Renewal is yours to run; re-copy the renewed pair and `nginx -s reload`.

### B.4 SecRouter TLS

SecRouter has two modes in its `SECROUTER_CONFIG` JSON:

- **`security.tls.mode: "frontend"` (recommended)** — SecRouter serves plain HTTP
  and **secproxy terminates TLS** (B.3). This is the FIPS-preferred path (crypto
  boundary is the host OpenSSL under nginx) and needs no cert on SecRouter itself.
- **`security.tls.mode: "native"`** — SecRouter terminates TLS and **requires**
  `security.tls.certPath` and `security.tls.keyPath` (PEM). Optional `minVersion`
  (default TLSv1.2) and `ciphers` (default FIPS set). Only use this if you are not
  fronting SecRouter with secproxy.

### B.5 SecRecorder (macOS native)

If you enable SecRecorder TLS on macOS, its cert's SAN must be
`host.docker.internal` (the fixed host clients reach it by), and that name must
resolve to `127.0.0.1` in `/etc/hosts`. Drop your pair where the deploy expects
the certbot output, or run it behind secproxy.

### B.6 mTLS for the SecAgent MR-review webhook

The only mutual-TLS surface in the suite. SecCert/secdeploy never generate these —
supply operator paths directly:

```bash
secagent review serve \
  --tls-cert server.crt --tls-key server.key \  # HTTPS server cert (serverAuth)
  --tls-ca client-ca.crt                        # require + verify client certs (mTLS)
```

Adding `--tls-ca` sets `ssl_cert_reqs = CERT_REQUIRED`, so GitLab must present a
client cert signed by that CA. All PEM; pair with `gitlab.webhook_allowed_ips` /
`gitlab.verify_tls`. (SecAgent→SecRouter is **not** mTLS — it uses the OIDC bearer
token from Part A over server-authenticated TLS.)

### B.7 Verify

```bash
# Leaf SANs cover the fronted names + bare domain
openssl x509 -in /etc/secsuite/secproxy/fullchain.pem -noout -text | grep -A1 'Subject Alternative Name'

# The front door presents your chain and it validates against your CA
openssl s_client -connect secrouter.<domain>:443 -CAfile /path/to/your-ca-bundle.pem </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer

# No trust errors from a governed call (exercises NODE_EXTRA_CA_CERTS end to end)
curl --cacert /path/to/your-ca-bundle.pem https://secrouter.<domain>/v1/models
```

---

## See also

- [README — Optional infrastructure](../README.md) — the `--without` mechanism.
- [fedora-fips.md](fedora-fips.md) — the full FIPS runbook (turnkey OIDC + SecCert
  TLS sections that this page replaces).
- [macos.md](macos.md) — the macOS eval runbook.
- [secsite.md](secsite.md) / [topology.md](topology.md) — placement and
  `[deploy].without`.
