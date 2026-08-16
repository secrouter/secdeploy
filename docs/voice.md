# Voice calls (secchat-mediad + SecRecorder)

SecChat's 1:1 voice calls (see `work/secchat/docs/plans/voice-calls-plan.md`, the authoritative
spec) need two things from the deploy that a plain SecChat stack doesn't have:

1. **`secrecorder` actually placed and reachable** — per-leg transcription posts a governed
   transcript into the DM after a recorded call.
2. **`secchat-mediad`** — a small Go/Pion daemon, ONE per suite, that relays and records
   *consented* calls server-side (unrecorded calls stay pure peer-to-peer; mediad never touches
   them). This is new custom infrastructure the secchat repo builds; SecDeploy's job is standing
   it up alongside SecChat and wiring the two together.

Both are **off by default** — omit `[secchat.voice]` (and keep `secrecorder` out of
`[deploy].without`, or leave it in `without` if you don't want it) and the stack is unchanged.

## Enabling it — `secsite.toml`

```toml
[deploy]
without = []   # secrecorder must NOT be listed here — voice transcription needs it

[secchat.voice]
enabled = true
advertise_addr = "192.168.5.1"   # REQUIRED — see "The advertised ICE address" below
# stun = ""                      # suite-local ONLY; leave empty unless you run one (see below)
# token = ""                     # blank = SecDeploy generates + persists one on first deploy
# image = "secchat-mediad:local"

[[builds]]
name = "secchat-mediad"
component = "secchat"
dockerfile = "mediad/Dockerfile"   # Go/Pion + ffmpeg image, built from the secchat checkout
context = "mediad"                # Dockerfile does `COPY go.mod go.sum ./`
```

`secrecorder` is `optional = true` in `suite.toml` (an eval instance can still drop it if voice
isn't in scope) but **must not** appear in `[deploy].without` for voice transcription to work —
`secdeploy` doesn't enforce this (it's a legitimate deploy shape without voice), but a
`[secchat.voice].enabled = true` site with `secrecorder` withheld will deploy mediad with no
`SECCHAT_TRANSCRIBE_URL` to call, and every recorded call ends in a stuck "transcription pending"
line.

## What a deploy does

With `[secchat.voice].enabled`, `secdeploy deploy <target>` (for the resource hosting SecChat):

1. **Builds the mediad image** (via a `[[builds]]` entry — see above; `secdeploy` doesn't build it
   automatically the way it can build the pool's runnerd image, since mediad isn't optional
   turnkey infra with a `build_image` knob — it's a normal site image build, same machinery as the
   secagent analyzer images).
2. **Writes the backend env** into `work/secchat/.env` (`sync_secchat_env`'s `voice=` argument —
   `src/secdeploy/wiring.py`'s `secchat_voice_env`):
   - `SECCHAT_TRANSCRIBE_URL` — SecRecorder's topology URL, straight from `Topology.urls()` (unset
     if SecRecorder isn't placed/is withheld — the backend's own "transcription unavailable"
     fallback decides what to do).
   - `SECCHAT_MEDIAD_URL` — always `http://mediad:<control_port>` (the compose service name IS
     the DNS name on the stack's own Docker network).
   - `SECCHAT_MEDIAD_TOKEN` — the shared control-API bearer. An operator-set `[secchat.voice].token`
     wins; otherwise SecDeploy generates a strong random one **once** and leaves it alone on every
     later deploy (same idempotent-once-set discipline the stack's other seeded secrets use) — a
     live mediad's bearer is never rotated out from under it by a redeploy.
   - `SECCHAT_CALL_STUN` — `[secchat.voice].stun` verbatim (see "STUN" below).
   - `SECCHAT_MEDIAD_ADVERTISE_ADDR` — `[secchat.voice].advertise_addr` verbatim.
3. **Writes `compose.override.yaml`** into `work/secchat/` (`mediad_compose_override` /
   `secchat_compose_override` — the latter also folds in the agent pool's ServiceAccount mount
   when `[secchat.pool].create_service_account` is *also* enabled, since Compose only auto-merges
   ONE override file): the `mediad` service, its media ports, and the new `recordings` volume
   mounted rw into both `mediad` and `secchat`.

Steps 2–3 run **before** the stacks bring-up, so `docker compose up` sees `mediad` from the first
`up` — same ordering as the agent pool's ServiceAccount-credential mount.

### The `recordings` volume

A **new** named Docker volume, distinct from SecChat's existing `uploads` volume (which mounts to
the `secchat` container only today):

```yaml
volumes:
  recordings: {}
services:
  mediad:
    volumes: ["recordings:/var/lib/mediad/recordings"]
  secchat:
    volumes: ["recordings:/var/lib/secchat/recordings"]
```

mediad writes per-leg OGG/Opus files + the mixed playback file + the finalize manifest here;
SecChat's backend reads/deletes them (ingest as an attachment, then transcribe) — both directions
constrained to `<volume-root>/<sessionId>/`, never a manifest-driven path outside it. See
`docs/plans/voice-contracts.md` §4 (secchat repo) for the on-disk layout.

## Media ports — `:47020` (published) and `:47021` (never published)

mediad uses **one well-known port for every session's media**: Pion's `ICEUDPMux` on UDP `:47020`,
with `SetICETCPMux` layering ICE-TCP on the **same port number** as a fallback for UDP-hostile
networks. Both are published:

```yaml
ports:
  - "47020:47020/udp"
  - "47020:47020/tcp"
```

This is **not** the same shape as SecChat's own `:47010` publish, which is TCP-only — media needs
both protocols on the identical port number.

The control API (`:47021` by default, `[secchat.voice].control_port`) is **never published** — it
stays on the compose-internal network, reachable only from the `secchat` container via
`SECCHAT_MEDIAD_URL`, bearer-authenticated with `SECCHAT_MEDIAD_TOKEN`. This is intentional
isolation, not an oversight: mediad has no per-session/per-leg credential of its own, so the
control-API bearer is the *only* auth surface, and it must never reach a client.

### The colima/Lima UDP caveat

**Colima's UDP port-forwarding is not at parity with its TCP publishes.** SecChat's own `:47010`
is TCP-only and forwards reliably; `:47020`'s UDP leg is historically less reliable through
colima/Lima. Don't assume "the container started, so the port works" — verify with an actual UDP
reachability test **from a second host** (this is exactly what the voice plan's P0 phase gates
on). If UDP doesn't forward cleanly, colima may need an explicit `proto: udp` entry in its
`portForwards` config; ICE-TCP on the same port number (above) is the documented fallback either
way, at some quality/latency cost.

### The advertised ICE address

`[secchat.voice].advertise_addr` → `SECCHAT_MEDIAD_ADVERTISE_ADDR` → mediad's `MEDIAD_ADVERTISE_ADDR`
env (via compose `.env` interpolation, not hardcoded into `compose.override.yaml`) → Pion's
`SetNAT1To1IPs`, applied to both the UDP and TCP candidates mediad advertises.

This is **required** when `[secchat.voice].enabled` — `SiteConfig.load` refuses to parse a site
config that enables voice without it. Get it wrong (or leave it unset and somehow bypass
validation by constructing a `VoiceOptions` programmatically) and relayed calls will *appear* to
work loopback-to-loopback on the same machine while silently never connecting from a second host —
the single most common containerized-Pion failure mode. Set it to the suite host's address as seen
from wherever your calling clients actually are (a colima VM's node IP for a single-Mac eval, a
LAN IP or public address for a real multi-host deployment).

## STUN — suite-local or empty, **never public**

`[secchat.voice].stun` → `SECCHAT_CALL_STUN`, read by SecChat's backend and handed to clients for
**unrecorded (p2p) calls only** — relayed calls never need STUN (mediad is a fixed host:port).

Leave it **empty** unless you run a suite-local STUN service. Do **not** point it at a public STUN
server (Google's default, or similar): a public STUN default leaks *every unrecorded call's
existence* plus each client's IP address to a third party outside the suite boundary, which
directly breaks the suite's CUI/air-gap posture — this was a REQUIRED finding in the plan's v3.1
architect review (§2.5 point 4), not a style preference. `SiteConfig.load` rejects an obviously
public value (`google.com`, `stunprotocol.org`, and similar markers in `stun`) as a guard against
the single most common accidental default — it is not an exhaustive allowlist, so don't treat
"validation passed" as "this STUN server is fine for a CUI enclave."

Empty usually just works: LAN/VPN peers typically connect via host or peer-reflexive candidates
without any STUN server at all. A future suite-local STUN component (coturn in STUN-only mode) is
spec'd as a P4 follow-up in the voice plan, alongside the TURN/SFU growth path.

## Fully manual path

Leave `[secchat.voice]` unset (or `enabled = false`) and `secdeploy` writes nothing voice-related —
stand up mediad yourself, point `SECCHAT_MEDIAD_URL`/`SECCHAT_MEDIAD_TOKEN`/`SECCHAT_TRANSCRIBE_URL`/
`SECCHAT_CALL_STUN` at it by hand in `work/secchat/.env`, and add its service to
`work/secchat/compose.override.yaml` yourself (`mediad_compose_override` in
`src/secdeploy/wiring.py` is a good starting template — call it from a Python one-liner, or copy
its shape).

## Re-enabling `secrecorder`

`secrecorder` is `optional = true` in `suite.toml` — some eval instances (chat + pi only, no
voice) legitimately drop it. To use voice calls, make sure it's **not** in `[deploy].without`:

```toml
[deploy]
without = []   # (or any list that doesn't include "secrecorder")
```

It's already `fronted = true`, so nothing else changes — the same SSO/summarization wiring every
other placed `secrecorder` instance gets (see [macos.md](macos.md#secrecorder-sso--summarization) /
[fedora-fips.md](fedora-fips.md#secrecorder-turnkey-sso--summarization)) applies unchanged; voice
calls are just one more caller of the same `/v1/audio/transcriptions` endpoint
(`docs/plans/voice-contracts.md` §5, secchat repo), now with `diarize=false` per-leg requests
instead of (or alongside) the summarizer's existing mixed-file use.
