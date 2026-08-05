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
4. Write a deploy audit artifact to `out/audit/` (CMMC audit evidence — see
   [Deployment audit artifacts](fedora-fips.md#deployment-audit-artifacts)).

> **Known eval limitation:** with a `topology.toml` in play, secdeploy still generates
> SecRouter's pool/token/egress wiring (`SECROUTER_SECLLM_ENDPOINTS`/`_TOKEN`/
> `SECROUTER_EGRESS_FILE`) into `out/addressing/env/secrouter.env` — but nothing installs it
> into the running container: `compose.yaml` only sets `SECROUTER_HOST`/`SECROUTER_PORT`
> today, with no bind-mount or env-file passthrough for the generated addressing. On
> fedora-fips this same wiring *is* applied (a second `EnvironmentFile=` in `secrouter.service`
> — see [Getting the generated wiring into the running service](fedora-fips.md#getting-the-generated-wiring-into-the-running-service));
> on macOS it stays generated-but-unapplied. Use `fedora-fips` (or hand-edit `compose.yaml` to
> mount the file yourself) for anything beyond a single-host eval.

`deploy macos --with-agent` (with a `topology.toml` placing SecAgent here) is the same story:
it prints a native `secagent chat serve` run command (mirroring SecRecorder/secdns/SecLLM's own
native notes below) rather than installing anything — macOS has no systemd-style env-file
layering to install SecAgent's generated addressing env into. See
[SecAgent and Mattermost](fedora-fips.md#secagent-and-mattermost) for the real (fedora-fips)
turnkey standup; on macOS, source `out/addressing/env/secagent.env` yourself before running the
printed command if you want the generated wiring.

### Internal DNS (`*.internal`) on macOS

A single-host eval has no topology and no `.internal` names — reach everything at
`localhost:<port>` (see [Verify](#verify)). With a `topology.toml`, though, the suite's
`<component>.<domain>` hostnames **do** work on macOS; it isn't a Linux-only feature:

- **SecDNS runs natively** (a service on `:53`, like SecRecorder). `deploy macos` prints the
  `sudo … secdns serve` command for you to run — it isn't auto-started.
- **`deploy macos --configure-resolver`** writes `/etc/resolver/<domain>` pointing that domain
  at SecDNS — macOS's native per-domain resolver — so `secrouter.<domain>` and friends resolve
  on the host.

It is **eval-grade**, though: those native services (SecDNS, SecLLM, SecAgent) are run-commands
you start yourself rather than managed units; SecLLM runs `SECLLM_BACKEND=mock` (no GPU
passthrough into Colima, so no real inference); the generated wiring env isn't auto-applied to
the containers (see the limitation above); and `/etc/resolver` is host-side, so the containers
still resolve peers through the Colima VM / `host.docker.internal`. For managed, auto-started
services and real inference, use `fedora-fips`.

SecRecorder (optional, native):

```bash
HOST=0.0.0.0 PORT=47003 work/secrecorder/run.sh     # http://127.0.0.1:47003
```

### SecRecorder over TLS (SecCert-issued cert)

`deploy macos --tls` gets SecRecorder a real cert from SecCert via `certbot` (installed via
brew if missing) and prints the TLS run command. HTTP-01 validation crosses the container/host
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

Cert + key land under `out/certbot/config/live/secrecorder/`; the printed command starts
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
and fold `HF_TOKEN` into the printed run command; `--hf-token TOKEN` overrides it for a one-off
run. `secrets.env` is gitignored (`*.env`) — never commit a real token.

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
(FIPS-validated in FIPS mode), and macOS runs the same nginx for a non-FIPS eval. `deploy macos`
writes `out/addressing/secproxy.nginx.conf` whenever a topology is active (the same
`wiring.write_addressing()`/`wiring.nginx_conf_text()` generator fedora-fips installs — see
[fedora-fips.md#the-generated-nginx-config](fedora-fips.md#the-generated-nginx-config)), makes
sure `nginx` is on `PATH` first (installing via `brew install nginx` if missing — the same
`_ensure_certbot()`-style idiom `--tls` uses for `certbot`), issues the SAN cert (below), and —
like SecDNS/SecLLM/SecAgent's own native-run notes above — prints the command to run it rather
than starting it for you:

```bash
sudo nginx -c out/addressing/secproxy.nginx.conf -g 'daemon off;'
```

nginx binds `:443`/`:80`, so — like SecDNS's `:53` — starting it needs `sudo`.

> **Eval setup — production paths.** The generated config is the *production* shape: it reads its
> cert from `/etc/secsuite/secproxy/{fullchain,privkey}.pem` and points nginx's pid/logs/temp +
> the ACME webroot at the state dir `/var/lib/secsuite/secproxy`. For a local macOS eval, create
> those dirs and drop the cert in place (running as `sudo`), e.g.:
>
> ```bash
> sudo install -d /var/lib/secsuite/secproxy/tmp /var/lib/secsuite/secproxy/acme /etc/secsuite/secproxy
> sudo cp out/certbot/config/live/secproxy/{fullchain,privkey}.pem /etc/secsuite/secproxy/
> ```
>
> — or hand-edit the paths in your copy of the generated conf (a one-off local workaround; a
> redeploy overwrites it).

### What it fronts

The same components as fedora-fips — **secsso, secrouter, secagent, secchat, secrecorder** —
reverse-proxied by Host header on `:443`. **seccert**, **secllm**, and **secdns** are never
fronted (reached directly at their own `host:port` instead), and secproxy never fronts itself.
See [fedora-fips.md#what-it-fronts](fedora-fips.md#what-it-fronts) for why.

### TLS on macOS: the same eval limitation as SecRecorder

nginx doesn't run its own ACME client — SecDeploy issues it one **SAN certificate** covering
every fronted FQDN from SecCert via `certbot`, exactly like fedora-fips (see
[fedora-fips.md#tls-via-seccert-the-deploy-time-san-cert](fedora-fips.md#tls-via-seccert-the-deploy-time-san-cert)),
just adapted to macOS's container/host boundary the way SecRecorder's `--tls` flow is: the
HTTP-01 responder runs on the Mac and SecCert (in its container) reaches it on
`SECCERT_HTTP01_PORT` (see `compose.yaml`).

That validation needs the challenge to actually be reachable: SecCert must resolve each fronted
FQDN **to this host, from inside its container** — i.e. SecDNS serving the fronted FQDNs and the
SecCert container's resolver pointed at SecDNS. On a plain local eval that isn't set up, so
issuance may not complete (the deploy warns and continues).

For a pure local eval, skip ACME entirely instead of fighting it: drop a **self-signed**
certificate at `/etc/secsuite/secproxy/{fullchain,privkey}.pem` (e.g. `openssl req -x509 -newkey
rsa:2048 -nodes -keyout privkey.pem -out fullchain.pem -days 30 -subj /CN=secrouter.<domain>`),
which nginx serves the same way. Like every other generated file here, don't expect a hand-edited
conf to survive a redeploy — this is a one-off local workaround, not a supported flag.

### Known caveat: SecAgent's port

`suite.toml` gives secagent port `47007` — the port the generated nginx config's
`secagent.<domain>` server block reverse-proxies to. But SecAgent's own native run command (both
here and on fedora-fips — see
[fedora-fips.md#secagent-and-mattermost](fedora-fips.md#secagent-and-mattermost)) is `secagent
chat serve --port 8070`, a different port than the one nginx is told to dial. On a single-Mac
eval running secproxy and SecAgent together, that mismatch means `secagent.<domain>` won't
actually reach the running `chat serve` process unless you start it on `47007` instead of the
documented `8070` (`secagent chat serve --port 47007`) — or you accept that the fronted route
doesn't work end-to-end here and reach SecAgent directly at whatever port it's actually
listening on instead. This is a pre-existing gap in the port model, not something this native-
nginx integration introduces or fixes.

## Verify

```bash
uv run secdeploy status macos
open http://localhost:47001/admin        # SecCert console
curl -s http://localhost:47002/health    # SecRouter (dev mode by default)
```

## Teardown

```bash
docker compose -f deploy/macos/compose.yaml down            # keep the CA volume
docker compose -f deploy/macos/compose.yaml down -v         # also wipe SecCert state
```

## Notes

- SecRouter runs in **dev mode** here (security disabled). For anything real, mount a hardened
  `freerouter.config.json` (see the SecRouter repo) — or use the `fedora-fips` target.
- The Mac path is not a FIPS environment; use it for evaluation, not accreditation.
