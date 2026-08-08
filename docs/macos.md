# macOS (Apple Silicon) runbook

The macOS target is for evaluation and local work on a MacBook Pro M-series. SecCert and
SecRouter run as containers via Colima; SecRecorder runs natively because its MLX/Metal
backend can't run inside Docker on macOS.

## Prerequisites

On a clean Mac, start from zero — Command Line Tools, then Homebrew, then the tools
secdeploy drives. You don't install Python separately: `uv` runs secdeploy and
provisions the right Python for it.

```bash
xcode-select --install                      # Command Line Tools (compiler, git)

# Homebrew, if you don't already have it (https://brew.sh):
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
eval "$(/opt/homebrew/bin/brew shellenv)"   # put brew on PATH (Apple Silicon)

brew install colima docker uv ffmpeg        # ffmpeg: SecRecorder transcoding (build macos self-installs it too)
colima start                                # Docker daemon on Apple Silicon
```

> **Deploying SecChat or SecSSO?** Both run **native arm64** on Apple Silicon — no
> Rosetta/emulation. Mattermost's *published* image is amd64-only, but its release *binary* ships
> arm64 too, so SecChat builds a native Mattermost image from the official binary (see
> `secchat/Dockerfile`); SecSSO's Authentik/Postgres/Redis are multi-arch. Two practical notes:
> give Colima headroom for the extra containers, and SecChat's **first** bring-up *builds*
> Mattermost (a download + build — a few minutes, one-time, then cached):
>
> ```bash
> colima start --cpu 4 --memory 8 --disk 60   # room for SecChat + SecSSO (Mattermost, Authentik, 2× Postgres, Redis)
> ```
>
> If you don't need chat/SSO for an eval, `deploy macos --without secsso,secchat` skips them.

Then get secdeploy — it runs from its checkout via `uv` (no separate Python install):

```bash
git clone https://github.com/secrouter/secdeploy
cd secdeploy
uv run secdeploy verify                     # sanity-check the manifest + toolchain
```

## Deploy

```bash
uv run secdeploy fetch            # checkout components at the pinned tags → ./work
uv run secdeploy build macos      # docker build SecCert + SecRouter (tagged secrouter/*:<suite>)
uv run secdeploy deploy macos     # SecCert (CA) up → export root → SecRouter up
```

What `deploy macos` does:
1. `docker compose up -d seccert` and wait for `http://localhost:47001/health`.
2. Save the CA trust anchor to `out/seccert-root.pem`.
3. `docker compose up -d secrouter`.
4. Install + start the native services (with a `topology.toml` placing them here) as **launchd
   daemons** — see [Native services (launchd)](#native-services-launchd) below.
5. Write a deploy audit artifact to `out/audit/` (CMMC audit evidence — see
   [Deployment audit artifacts](fedora-fips.md#deployment-audit-artifacts)).

### Native services (launchd)

SecCert and SecRouter are containers; everything else that runs on macOS — **SecDNS**, **SecLLM**,
**SecAgent**, **SecRecorder** (MLX/Metal, never containerized here) and **secproxy**'s nginx
(`:443`/`:80`) — runs natively and is installed as a **launchd daemon** so `deploy` actually starts
and *keeps* it running (`RunAtLoad` + `KeepAlive`) instead of printing a command for you to paste
and babysit. The units live at `/Library/LaunchDaemons/internal.secsuite.<name>.plist`:

- Only **secproxy** binds privileged ports (`:443`/`:80`), so it's the one service that runs as
  **root** (macOS has no per-port capability like Linux's `CAP_NET_BIND_SERVICE`). SecDNS, SecLLM,
  SecAgent and SecRecorder run as **you** (the invoking user), so `uv`/their project venvs/`$HOME`
  resolve exactly as they did at `build` time. SecDNS in particular listens on a **high port**
  (`15353`), not `:53` — Colima's own VM manager (`limactl`) holds host `:53`, so a `:53` SecDNS
  would collide with it; the resolver is pointed at that high port instead (below).
- Installing a LaunchDaemon writes a root-owned directory, so it uses `sudo` (the same escalation
  the resolver/keychain steps already ask for; macOS caches it, so you're prompted at most once).
- Logs are captured under `out/logs/<name>.{out,err}.log`. Check status with
  `sudo launchctl print system/internal.secsuite.<name>` (or `secdeploy status macos`).
- **`deploy macos --no-native-services`** skips the install and prints each run command instead —
  for when you'd rather run one in the foreground (e.g. to watch its output while debugging).

`build macos` pre-syncs each native service's `uv` venv, so the first start is instant and — for
root-run SecDNS — nothing tries to write a venv into your checkout at start time. Teardown removes
these units (`launchctl bootout` + remove the plist) — see [Teardown](#teardown).

> **Known eval limitation:** with a `topology.toml` in play, secdeploy still generates
> SecRouter's pool/token/egress wiring (`SECROUTER_SECLLM_ENDPOINTS`/`_TOKEN`/
> `SECROUTER_EGRESS_FILE`) into `out/addressing/env/secrouter.env` — but nothing installs it
> into the running container: `compose.yaml` only sets `SECROUTER_HOST`/`SECROUTER_PORT`
> today, with no bind-mount or env-file passthrough for the generated addressing. On
> fedora-fips this same wiring *is* applied (a second `EnvironmentFile=` in `secrouter.service`
> — see [Getting the generated wiring into the running service](fedora-fips.md#getting-the-generated-wiring-into-the-running-service));
> on macOS it stays generated-but-unapplied. Use `fedora-fips` (or hand-edit `compose.yaml` to
> mount the file yourself) for anything beyond a single-host eval.

`deploy macos --with-agent` (with a `topology.toml` placing SecAgent here) installs SecAgent's
`secagent chat serve` bridge as a launchd daemon **with its wiring layered in**: the generated
addressing env (`out/addressing/env/secagent.env` — LLM/SecSSO/Mattermost wiring + webhook secret)
and the `SECAGENT_*` operator secrets from `deploy/macos/secrets.env` are read and folded into the
launchd job's `EnvironmentVariables` — the macOS equivalent of fedora-fips's two `EnvironmentFile=`
layers, closing the old "source it yourself" gap. See
[SecAgent and Mattermost](fedora-fips.md#secagent-and-mattermost) for the full turnkey standup.

`--with-agent` also installs **LeanCTX** (context compression — SecAgent v0.3.0 ships it on by
default): the pinned `lean-ctx` binary + `pi-lean-ctx` extension are installed and wired into pi
(`lean-ctx harden` + `lean-ctx init --agent pi`), **air-gapped** (`LEAN_CTX_NO_UPDATE_CHECK=1`, no
update phone-home), best-effort (a missing `npm` just skips it — SecAgent degrades gracefully; run
`secagent doctor` to check). This wires the pi-side compression only; SecAgent's own-call
compression daemon is a deferred follow-on (LeanCTX self-manages that, incl. an auto-updater to
suppress). See SecAgent's `docs/leanctx.md` for the full security posture.

### SecAssist + declared users

**SecAssist** (the LibreChat chat UI) deploys with the suite as a stack — no flag — and its
env is fully turnkey: when SecSSO is also placed, the deploy mirrors SecSSO's two generated
OIDC secrets and writes the topology issuer/SecRouter/domain env into `work/secassist/.env`
(nothing to reconcile by hand). And a `[[users]]` list in your `secsite.toml` provisions those
accounts in SecSSO with random, must-reset-on-first-login passwords (printed once at deploy).
Both work identically on Fedora — see [fedora-fips.md](fedora-fips.md#onboarding-users-users)
for the `[[users]]` shape and the security notes.

### Internal DNS (`*.internal`) on macOS

A single-host eval has no topology and no `.internal` names — reach everything at
`localhost:<port>` (see [Verify](#verify)). With a `topology.toml`, though, the suite's
`<component>.<domain>` hostnames **do** work on macOS; it isn't a Linux-only feature:

- **SecDNS runs natively** on the high port `15353` (not `:53` — Colima's `limactl` holds host
  `:53`), installed as a launchd daemon (as your user) and **started by the deploy** — no
  `secdns serve` to run by hand.
- **`deploy macos --configure-resolver`** writes `/etc/resolver/<domain>` pointing that domain
  at SecDNS with a matching `port 15353` line (macOS's resolver(5) honours it) — so
  `secrouter.<domain>` and friends resolve on the host. The deploy installs **SecDNS first, then**
  points the resolver at it, so there's no window where `<domain>` names are routed to a
  not-yet-running server (an earlier version configured the resolver against a SecDNS you still
  had to start yourself — every `.internal`
  lookup failed until you did; that's fixed).

Verify resolution once the deploy finishes:

```bash
dig @127.0.0.1 -p 15353 secrouter.sec.internal +short   # ask SecDNS directly (its high port)
sudo killall -HUP mDNSResponder                          # flush the macOS resolver cache
dscacheutil -q host -a name secrouter.sec.internal
```

Still **eval-grade** in two ways unrelated to whether the services are managed: SecLLM runs
`SECLLM_BACKEND=mock` (no GPU passthrough into Colima, so no real inference), and `/etc/resolver`
is host-side, so the **containers** (SecCert/SecRouter) still resolve peers through the Colima VM /
`host.docker.internal`, not through SecDNS — which is why the secproxy ACME cert usually can't
issue on macOS (see [TLS on macOS](#tls-on-macos-the-same-eval-limitation-as-secrecorder)). For
real inference and a FIPS crypto boundary, use `fedora-fips`.

SecRecorder is installed and started as a launchd daemon too. For a one-off foreground run
instead (e.g. `--no-native-services`, or to watch its output):

```bash
HOST=0.0.0.0 PORT=47003 work/secrecorder/run.sh     # http://127.0.0.1:47003
```

### SecRecorder over TLS (SecCert-issued cert)

`deploy macos --tls` gets SecRecorder a real cert from SecCert via `certbot` (installed via
brew if missing) and starts its launchd daemon with TLS. HTTP-01 validation crosses the container/host
boundary through `host.docker.internal` — SecCert (in its container) reaches back to a
`certbot`-managed responder on the Mac itself via that name; `compose.yaml`'s
`SECCERT_HTTP01_PORT=47080` matches the unprivileged port `certbot --standalone` binds to.

```bash
uv run secdeploy deploy macos --tls --configure-hosts --trust-ca
# --configure-hosts maps host.docker.internal -> 127.0.0.1 in /etc/hosts (sudo)
# --trust-ca        trusts the SecCert root in the System keychain (sudo)
# Both are idempotent (skipped once already done) and ask for confirmation before running
# sudo — pass -y/--yes to grant blanket consent up front for unattended runs. sudo's own
# password prompt is separate and always happens (this asks whether to invoke sudo at all).
```

Cert + key land under `out/certbot/config/live/secrecorder/`; the launchd daemon starts
uvicorn directly with `--ssl-certfile`/`--ssl-keyfile` (bypassing `run.sh`, which has no TLS
flags) and also sets `WHISPER_PREWARM=1`/`WHISPER_PREWARM_DIARIZER=1` explicitly — those are
`run.sh`'s defaults too, but bypassing it means they're not applied for free. Without prewarm,
the model loads lazily on the first real request instead of at startup, which can look like a
hang if that first load hits a slow/stalled model download (SecRecorder only handles one job
at a time, so everything queues behind it). Verify with the exported root as the trust anchor:

```bash
curl --cacert out/seccert-root.pem https://host.docker.internal:47003/health
```

### Diarization (Hugging Face token)

Speaker diarization uses a gated model (`pyannote/speaker-diarization-community-1`) — without
a token, transcription still works but the UI shows a "diarization skipped" pill. Set it up
once:

```bash
cp deploy/macos/secrets.env.example deploy/macos/secrets.env
# accept https://huggingface.co/pyannote/speaker-diarization-community-1, create a read token
# at https://huggingface.co/settings/tokens, then fill in HF_TOKEN in secrets.env
```

`deploy macos --tls` (and the plain-HTTP path) read `deploy/macos/secrets.env` automatically
and fold `HF_TOKEN` into SecRecorder's launchd environment; `--hf-token TOKEN` overrides it for a
one-off run. `secrets.env` is gitignored (`*.env`) — never commit a real token.

> `secdeploy configure`'s optional secret-seeding step can write `HF_TOKEN` into
> `deploy/macos/secrets.env` for you (`0600`, masked input) instead of the manual `cp` + edit
> above — see [secsite.md § Seeding operator secrets](secsite.md#seeding-operator-secrets-optional).
> SecAgent's `SECAGENT_*` secrets seeded into this same file **are** now layered into its launchd
> job (see [`--with-agent`](#deploy) above). SecCert's CA passphrase/admin token still land here
> for safekeeping only — SecCert runs as a container on macOS and takes its env from
> `compose.yaml`, so use `fedora-fips` if you need those applied. (`configure` auto-generates the
> SecCert secrets by default, so you don't have to invent them either way.)

### Air-gapped: manually pre-placed models

For a host with no path to Hugging Face at all, pre-download both models on a connected
machine and copy the directory over, instead of relying on `secdeploy deploy macos` fetching
them at runtime:

```bash
# connected host
uv run --project work/secrecorder hf download \
  mlx-community/whisper-large-v3-turbo --local-dir /path/to/models/whisper
uv run --project work/secrecorder hf download \
  pyannote/speaker-diarization-community-1 --local-dir /path/to/models/diarizer --token hf_...

# copy /path/to/models to the air-gapped host, then:
uv run secdeploy deploy macos --tls --model-dir /path/to/models
```

`--model-dir <dir>` sets `WHISPER_MODEL=<dir>/whisper` and `WHISPER_DIARIZE_MODEL=<dir>/diarizer`
in the printed run command in place of the Hugging Face repo IDs — both libraries load
straight from a local directory with no network call, so no `HF_TOKEN` is needed once the
diarizer model is already in place. Either subdirectory can be present independently; a
missing one just falls back to that model's default (network) ID with a warning.

## SecProxy (edge reverse proxy)

Placing the `edge` tier on this Mac stands up **secproxy** — [nginx](https://nginx.org) — as the
suite's one HTTPS front door, run **natively** here, same as SecDNS/SecLLM/SecAgent above —
**not** as a container. That's the key simplification for this target: a native nginx binds
directly to the host, so it reaches every other backend the same way any other host process does
— `<topology-address>:<port>` — whether that backend is containerized (SecCert, SecRouter publish
their ports to the host via `compose.yaml`) or itself native (SecDNS/SecLLM/SecAgent). Like
SecDNS, it needs no `--with-*` flag — it deploys the moment a topology places the edge tier here:

```bash
uv run secdeploy deploy macos --dry-run --topology topology.toml --resource <edge-resource>
uv run secdeploy deploy macos --topology topology.toml --resource <edge-resource>
```

nginx is the reverse-proxy runtime on **both** targets — fedora-fips uses the system OpenSSL
(FIPS-validated in FIPS mode), and macOS runs the same nginx for a non-FIPS eval. On macOS,
`deploy` makes sure `nginx` is on `PATH` (installing via `brew install nginx` if missing), writes a
**macOS-local** nginx config to `out/secproxy/nginx.conf`, obtains a cert (see below), and installs
nginx as a **launchd daemon** on `:443`/`:80` (as root) — started for you, not printed:

```bash
# what the launchd daemon runs (check it with `secdeploy status macos`, logs in out/logs/secproxy.*.log):
nginx -c out/secproxy/nginx.conf -g 'daemon off;'
```

Unlike fedora-fips's *production* config (cert at `/etc/secsuite/secproxy`, state under
`/var/lib/secsuite/secproxy`, worker user set by systemd), the macOS config keeps everything under
the deploy's own `out/` — cert dir `out/secproxy/cert`, writable state (pid/logs/temp + the ACME
webroot) under `out/secproxy/state` — and names your user as nginx's `worker` user, since launchd
starts nginx as root with no user drop of its own. No production paths to create, and no manual
cert placement: both are handled for you.

### What it fronts

The same components as fedora-fips — **secsso, secrouter, secagent, secchat, secrecorder** —
reverse-proxied by Host header on `:443`. **seccert**, **secllm**, and **secdns** are never
fronted (reached directly at their own `host:port` instead), and secproxy never fronts itself.
See [fedora-fips.md#what-it-fronts](fedora-fips.md#what-it-fronts) for why.

### TLS on macOS: automatic self-signed fallback

nginx doesn't run its own ACME client — SecDeploy issues it one **SAN certificate** covering every
fronted FQDN from SecCert via `certbot`, exactly like fedora-fips (see
[fedora-fips.md#tls-via-seccert-the-deploy-time-san-cert](fedora-fips.md#tls-via-seccert-the-deploy-time-san-cert)).
That validation needs SecCert to resolve each fronted FQDN **to this host, from inside its
container** — i.e. SecDNS serving the fronted FQDNs and the SecCert container's resolver pointed at
SecDNS. On a plain macOS eval that isn't set up (the containers resolve through the Colima VM, not
your host `/etc/resolver`), so HTTP-01 usually can't complete.

So on macOS the deploy **falls back automatically**: when the SecCert SAN cert can't be issued, it
generates a **self-signed** cert covering the fronted FQDNs into `out/secproxy/cert/` and nginx
serves that — enough to terminate TLS for a local eval (browsers warn on an untrusted issuer;
that's expected locally). You place nothing by hand. For a trusted cert, run where SecCert can
validate the fronted names from inside its container — that's what `fedora-fips` provides.

### SecAgent's port

`suite.toml` gives secagent port `47007` — the port the generated nginx config's
`secagent.<domain>` server block reverse-proxies to. The macOS launchd daemon starts
`secagent chat serve` on **that manifest port** (not the CLI's own `8070` default), so the
`secagent.<domain>` reverse-proxy route reaches it end-to-end — no manual `--port` override
needed. (fedora-fips's systemd unit likewise runs it on the manifest port.)

## Verify

```bash
uv run secdeploy status macos
open http://localhost:47001/admin        # SecCert console
curl -s http://localhost:47002/health    # SecRouter (dev mode by default)
```

## Teardown

`secdeploy teardown macos` reverses a deploy — bringing the compose stack and any SecSSO/SecChat
stack down, and reverting the resolver/`/etc/hosts`/keychain changes `--configure-resolver`/`--configure-hosts`/
`--trust-ca` made — for decommissioning or resetting between evals.

```bash
# Always preview first — prints the exact plan, touches nothing:
uv run secdeploy teardown macos --dry-run

# Then run it for real:
uv run secdeploy teardown macos
```

Equivalent to (but discovered, not hand-run):

```bash
docker compose -f deploy/macos/compose.yaml down            # keep the CA volume
docker compose -f deploy/macos/compose.yaml down -v         # also wipe SecCert state (--purge)
# each installed launchd daemon (SecDNS/SecLLM/SecAgent/SecRecorder/secproxy):
sudo launchctl bootout system /Library/LaunchDaemons/internal.secsuite.<name>.plist
sudo rm -f /Library/LaunchDaemons/internal.secsuite.<name>.plist
```

**It discovers, it doesn't assume.** Same principle as `fedora-fips` (see
[fedora-fips.md#teardown](fedora-fips.md#teardown)): `deploy` is purely additive, so this
Mac can be a superset of any one `topology.toml`/deploy-flags combination. Teardown probes
Docker directly (which containers/volumes exist for the `secsuite` compose project, which
`secrouter/{seccert,secrouter}` images are built), enumerates the installed
`/Library/LaunchDaemons/internal.secsuite.*.plist` units, lists `/etc/resolver` and checks
`/etc/hosts` and the System keychain itself, rather than trusting what was last deployed.
If a prior deploy's audit JSON exists under `--out`, it prints a one-line drift note (never
the driver of the plan — see fedora-fips.md's own note on this).

**Safety gates:** `--dry-run` prints the full plan and stops. A real run prints the plan,
then asks you to confirm before doing anything; `-y`/`--yes` skips it. Two steps below carry
their **own** extra confirmation on top of that, because they touch state another program
might also own.

### Native services (launchd): stopped + removed

The native services (`secdns`, `secllm`, `secagent`, `secrecorder`, `secproxy`) are launchd
daemons now, so teardown **stops and removes each one it finds** — `launchctl bootout system`
(stops + unloads) then removes the plist so it doesn't reload at next boot. It discovers them by
listing `/Library/LaunchDaemons/internal.secsuite.*.plist`, so it removes exactly the suite's own
units and nothing else.

The one thing it still won't touch is a service you ran in the **foreground** yourself
(`--no-native-services`, or a manual run) — that has no launchd unit to target. Teardown notes
this; stop it with Ctrl-C, and only after confirming the PID is yours (`pgrep -fl 'secdns
serve|secllm serve|secagent chat|nginx'`) should you `pkill`. Teardown never runs a fuzzy `pkill`
itself — `nginx`/`secdns` bind shared ports, so a loose match could kill something unrelated.

### `/etc/resolver/<domain>` and the cross-host resolver caveat

If `--configure-resolver` pointed this Mac's resolver at `secdns` for the suite's domain,
teardown removes `/etc/resolver/<domain>`. It gets `<domain>` from `--topology` if you pass
one (matched against what's actually present under `/etc/resolver`); otherwise it lists
`/etc/resolver` itself. If there's exactly one entry, that's unambiguous. If there's more
than one and no `--topology` hint matches, teardown **prints the candidates and does not
guess** — pass `--topology`, or remove the right one by hand.

Like fedora-fips's `systemd-resolved` drop-in, this is host-wide: if **another** host still
relies on this Mac's resolver config for the suite's domain, removing it strands that host —
an operator call teardown can't make for you.

### `/etc/hosts`: only the exact line, only with its own confirmation

If `--configure-hosts` added `127.0.0.1 host.docker.internal`, teardown can remove it — but
**only** that exact whole line, via an anchored match, and **only** after its own separate
confirmation (in addition to the main one above). Docker Desktop can write this identical
line itself, so a substring strip is never safe here; if the confirmation is declined, the
line is left in place and everything else in the plan still proceeds.

### Keychain: reverting `--trust-ca`

If the SecCert root is currently trusted in the System keychain, teardown extracts its CN
the same way `--trust-ca`'s own trust check does (`openssl x509 -noout -subject`) and runs
`security delete-certificate -c "<CN>" /Library/Keychains/System.keychain`. If the local
`out/seccert-root.pem` this reads the CN from isn't present (e.g. `out/` was already cleaned
on this checkout), teardown has no way to identify the CN and skips this step — remove it by
hand with the CN from wherever you still have the cert.

### `--purge`: also wiping the CA and cached secrets

Without `--purge`, `docker compose down` keeps the `seccert-data` volume and `out/` is left
alone entirely. `--purge` changes the compose step to `down -v` (which **wipes
`seccert-data` — the CA**), offers `docker rmi` for any built `secrouter/{seccert,secrouter}`
image (compose down never removes images; they're rebuildable via `secdeploy build macos`),
and offers to remove `out/` — which caches `out/seccert-root.pem` plus the SecLLM/SecAgent
shared tokens (`secllm-shared-token`, `secagent-webhook-secret`) another *live* deploy
sharing this same `--out` may still depend on.

`--purge` asks a **second, separate, extra-loud** confirmation before any of this, naming
exactly what's lost: wiping `seccert-data` destroys the CA private key the same way
fedora-fips's `/var/lib/secsuite/seccert` purge does (see
[fedora-fips.md#--purge-also-wiping-persistent-data](fedora-fips.md#--purge-also-wiping-persistent-data))
— every cert it issued, and the trust anchor already distributed to clients, become invalid.
Back up whatever you need from `seccert-data`/`out/` first. Declining this second
confirmation doesn't abort the rest of the teardown — it just leaves `seccert-data` and
`out/` in place and continues with everything else (compose `down` without `-v`, resolver,
`/etc/hosts`, keychain).

### brew packages: never removed

`colima`, `docker`, `uv`, `ffmpeg`, `nginx`, and `certbot` are never uninstalled — they're
listed under "NOT removed" only, since other tools on this Mac may depend on them.

### What teardown does *not* do

- It never runs `git`, and never touches `topology.toml`/deploy flags to decide what's
  installed — see "it discovers, it doesn't assume" above.
- It removes the **launchd** native services it finds (`bootout` + remove the plist), but a
  service you ran in the **foreground** yourself (`--no-native-services`) has no unit to target —
  Ctrl-C it, or `pkill` after confirming the PID with `pgrep -fl` (they bind shared ports). See
  [Native services (launchd): stopped + removed](#native-services-launchd-stopped--removed).

## Backup and restore

`secdeploy backup macos` captures this Mac's suite state into **one encrypted archive**:

- every `com.docker.compose.project=secsuite` **docker volume** — on macOS that's
  `seccert-data`, the **SecCert CA** (the suite's root of trust); SecRouter runs dev-mode with
  an ephemeral DB, so it has no durable volume here;
- the host-side cached secrets a deploy leaves under `out/` (`seccert-root.pem`, the
  SecLLM/SecAgent tokens), `deploy/macos/secrets.env` (your `HF_TOKEN`), and
  `~/.secagent` / `~/.config/secrouter`;
- each stack's database + uploads + `.env` (SecSSO/SecChat/SecAssist), via their own
  `bootstrap/<name>.sh backup`.

It's the same public-key flow as the [fedora-fips runbook](fedora-fips.md#backup-and-restore)
(read that for the full rationale) — **OpenSSL CMS + AES‑256**, encrypted to an X.509
**recipient cert** whose private key you keep **offline**. SecCert can mint the recipient cert,
or `openssl req -x509 -newkey rsa:4096 -nodes -keyout backup-key.pem -out backup-cert.pem
-subj /CN=secsuite-backup`.

```bash
# Preview (needs Colima/Docker up to see the volumes):
uv run secdeploy backup macos --dry-run

# Real backup — encrypts to the recipient cert (stacks must be up to dump their DBs):
uv run secdeploy backup macos --recipient backup-cert.pem
# → out/backups/secsuite-macos-<resource>-<UTC>.tar.cms  (+ .manifest.json/.txt)

# Restore — needs the OFFLINE private key; OVERWRITES state (asks first). Brings the root
# compose down (volumes kept), replaces volume contents + host secrets, restores the stacks,
# brings it back up:
uv run secdeploy restore macos out/backups/secsuite-macos-<resource>-<UTC>.tar.cms --key backup-key.pem
```

macOS notes specific to this target:

- Backup doesn't need `sudo` (it reads your own `out/`/`~` and drives Docker), but **Colima/
  Docker must be running** for the volume capture, and the staging dir lives under the project
  root so the util container can bind-mount it. The manifest records only metadata (filenames,
  sizes, the plaintext SHA‑256, the recipient fingerprint) — never a secret value — and the
  plaintext is wiped the moment the archive is encrypted.
- The volume tar uses a small utility image (`alpine:3` by default) — on an air-gapped Mac,
  pre-load it, or point `SECDEPLOY_VOLUME_UTIL_IMAGE` at an image you already have.
- After a restore, confirm the integrity chains as on fedora (SecRouter `GET /audit/verify`,
  `secagent audit verify`, SecCert's issuing log).

## Notes

- SecRouter runs in **dev mode** here (security disabled). For anything real, mount a hardened
  `freerouter.config.json` (see the SecRouter repo) — or use the `fedora-fips` target.
- The Mac path is not a FIPS environment; use it for evaluation, not accreditation.
