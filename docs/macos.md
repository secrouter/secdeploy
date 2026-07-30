# macOS (Apple Silicon) runbook

The macOS target is for evaluation and local work on a MacBook Pro M-series. SecCert and
SecRouter run as containers via Colima; SecRecorder runs natively because its MLX/Metal
backend can't run inside Docker on macOS.

## Prerequisites

```bash
brew install colima docker uv
colima start                      # Docker daemon on Apple Silicon
```

## Deploy

```bash
uv run secdeploy fetch            # checkout components at the pinned tags → ./work
uv run secdeploy build macos      # docker build SecCert + SecRouter (tagged secrouter/*:<suite>)
uv run secdeploy deploy macos     # SecCert (CA) up → export root → SecRouter up
```

What `deploy macos` does:
1. `docker compose up -d seccert` and wait for `http://localhost:14000/health`.
2. Save the CA trust anchor to `out/seccert-root.pem`.
3. `docker compose up -d secrouter`.

SecRecorder (optional, native):

```bash
uv run --project work/secrecorder secrecorder     # http://127.0.0.1:9000
```

## Verify

```bash
uv run secdeploy status macos
open http://localhost:14000/admin        # SecCert console
curl -s http://localhost:18800/health    # SecRouter (dev mode by default)
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
