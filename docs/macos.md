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
uv run secdeploy deploy macos --tls --configure-hosts
# --configure-hosts maps host.docker.internal -> 127.0.0.1 in /etc/hosts (sudo, one-time)
# so host-side clients can use the same hostname the cert was issued for; safe to omit on repeat runs.
```

Cert + key land under `out/certbot/config/live/secrecorder/`; the printed command starts
uvicorn directly with `--ssl-certfile`/`--ssl-keyfile` (bypassing `run.sh`, which has no TLS
flags). Verify with the exported root as the trust anchor:

```bash
curl --cacert out/seccert-root.pem https://host.docker.internal:47003/health
```

## Verify

```bash
uv run secdeploy status macos
open http://localhost:47001/admin        # SecCert console
curl -s http://localhost:47002/health    # SecRouter (dev mode by default)
```

Trust the CA locally so SecCert-issued certs validate:

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain out/seccert-root.pem
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
