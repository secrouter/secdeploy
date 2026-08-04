# macOS (Apple Silicon) runbook

The macOS target is for evaluation and local work on a MacBook Pro M-series. SecCert and
SecRouter run as containers via Colima; SecRecorder runs natively because its MLX/Metal
backend can't run inside Docker on macOS.

## Prerequisites

```bash
brew install colima docker uv ffmpeg   # ffmpeg: SecRecorder transcoding (build macos also self-installs it)
colima start                           # Docker daemon on Apple Silicon
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
