# Handoff — SecRouter suite, native macOS (Apple Silicon) deploy debug

**Purpose:** continue debugging a from-scratch deploy of the full SecRouter suite on an Apple
Silicon Mac. Most of the suite is up; three native services are crash-looping with real
application errors and need their logs read. This doc is self-contained — you do **not** need the
prior chat.

Run everything from the repo root (`~/code/secdeploy`). The deploying user is a normal user (not
root); individual steps escalate with `sudo`.

---

## TL;DR — do this first

SecDNS was wedged by a stale **root-owned** log (it moved from a root `:53` daemon to a user
high-port one; launchd opens the log *as the job's user*, so the root-owned log → `EX_CONFIG`).
The installer now fixes this (commit `d101756`), but the already-installed unit needs a nudge:

```bash
cd ~/code/secdeploy && git pull            # ensure you're at d101756+
sudo rm -f out/logs/secdns.out.log out/logs/secdns.err.log
sudo launchctl kickstart -k system/internal.secsuite.secdns
sleep 1 && dig @127.0.0.1 -p 15353 secrouter.sec.internal +short   # expect: 127.0.0.1
sudo killall -HUP mDNSResponder
ping -c1 secrouter.sec.internal                                     # expect: resolves (via /etc/resolver)
```

If `ping` resolves, DNS is done. Then move to the three crash-loopers (below).

---

## What this deploys (service map)

Single-host topology, domain **`sec.internal`**, everything on this one Mac. `secsite.toml` in the
repo root holds the placement + deploy options. `out/` holds generated artifacts (zone, env,
launchd plists, logs, certs). `work/<component>/` holds the pinned checkouts.

| Component | Kind on macOS | Runs as | Port | Notes |
|---|---|---|---|---|
| **SecCert** | container (Colima) | — | 47001 | internal CA; root exported to `out/seccert-root.pem` |
| **SecRouter** | container (Colima) | — | 47002 | governed AI gateway (dev mode by default) |
| **SecDNS** | launchd | **user** | **15353** | internal DNS. NOT `:53` — Colima's `limactl` holds `:53` |
| **SecLLM** | launchd | user | 11400 | inference; `SECLLM_BACKEND=mock` on macОS (no GPU into Colima) |
| **SecAgent** | launchd | user | 47007 | Mattermost chat bridge (`secagent chat serve`) |
| **SecRecorder** | launchd | user | 47003 | transcription; native MLX/Metal |
| **secproxy** | launchd | **root** | 443/80 | nginx reverse proxy (only root service — privileged ports) |
| **SecSSO** | compose stack | — | 9000 | Authentik (native arm64 — multi-arch image) |
| **SecChat** | compose stack | — | 8065 | Mattermost (native arm64 — **built** from the official binary) |

Native launchd units live at `/Library/LaunchDaemons/internal.secsuite.<name>.plist`.
Logs at `out/logs/<name>.{out,err}.log`.

---

## Current status (from the last live diagnostic)

| Service | State | Next action |
|---|---|---|
| SecLLM | ✅ running (`never exited`) | — |
| SecDNS | ❌ `EX_CONFIG` (stale root log) | **the TL;DR fix above** |
| secproxy | ❌ crash-loop, `exit 1` (nginx) | read `out/logs/secproxy.err.log` |
| SecRecorder | ❌ crash-loop, `exit 3` | read `out/logs/secrecorder.err.log` |
| SecAgent | ❌ crash-loop, `exit 1` (big log) | read `out/logs/secagent.err.log` — may settle once DNS is up |
| SecCert / SecRouter | assumed up (containers) | `docker ps`; `curl -s localhost:47001/health`, `:47002/health` |
| SecSSO / SecChat | unknown | `docker ps`; SecChat's first run **builds** Mattermost (minutes) |

---

## Immediate debugging plan

### 1. SecDNS — the TL;DR fix. Verify `dig … -p 15353` and `ping secrouter.sec.internal`.

### 2. The three crash-loopers — read the logs, they run then exit with a real error

```bash
cd ~/code/secdeploy
echo '=== secproxy ==='; tail -30 out/logs/secproxy.err.log
echo '=== secrecorder ==='; tail -30 out/logs/secrecorder.err.log
echo '=== secagent ==='; tail -40 out/logs/secagent.err.log
```

Working hypotheses (unconfirmed — read the logs):
- **secproxy** — nginx rejecting the generated conf (`out/secproxy/nginx.conf`) or the cert path
  (`out/secproxy/cert/{fullchain,privkey}.pem`, self-signed on macOS). Test the conf directly:
  `sudo nginx -t -c "$PWD/out/secproxy/nginx.conf"`.
- **secrecorder** — missing/gated model or an MLX load error. Check `deploy/macos/secrets.env` for
  `HF_TOKEN`; it runs `uvicorn server:app` from `work/secrecorder`.
- **secagent** — likely can't reach SecRouter/SecDNS yet; **re-check after DNS is up** (kickstart it:
  `sudo launchctl kickstart -k system/internal.secsuite.secagent`). Its env is layered from
  `out/addressing/env/secagent.env` + `SECAGENT_*` in `deploy/macos/secrets.env`.

### 3. The stacks (SecSSO + SecChat)

```bash
docker ps                                   # authentik/server, secchat-mattermost-1, postgres, redis
tail -30 out/logs/../..  # (stacks log to docker) → docker logs secchat-mattermost-1 --tail 40
curl -sS http://localhost:8065/api/v4/system/ping; echo   # Mattermost ready?
```
SecChat now **builds** a native arm64 Mattermost image from the official binary on first `up`
(a few minutes, one-time). If the bootstrap's 3-min health-wait times out, finish provisioning
later: `bash work/secchat/bootstrap/secchat.sh bot`.

---

## Fixes already made this session (so you don't redo them)

All on `secdeploy` `main` unless noted. Pull to `d101756`+.

| Commit / tag | What |
|---|---|
| `34022dc` | Auto-generate stack `.env` secrets (Postgres/Authentik) before `compose up`; auto-gen SecCert secrets in the wizard |
| `e5ad525` | Native macOS services as **launchd daemons** (start them, not print) |
| `6acdae3` | Absolute plist paths + run daemons straight from `work/<svc>/.venv/bin/<script>` + ensure venv exists |
| `09c7804` + secchat **`v1.1.0`** | Native Mattermost image built from the official arm64 binary (no emulation); SecSSO already multi-arch |
| `de89292` | **SecDNS on high port 15353** as the user (Colima `limactl` holds `:53`); resolver gets a `port 15353` line |
| `d101756` | launchd install **touch+chowns the log files to the job's user** — fixes the `EX_CONFIG` above |
| secdns **`v1.0.1`** (tagged, **NOT pinned** — pin is `v0.1.0`) | `serve` keeps DNS up if the console port is taken (best-effort console) |

---

## Key gotchas discovered (the important knowledge)

- **Colima's `limactl` binds host TCP `:53`.** So SecDNS can't use `:53`; it uses **15353** and runs
  as the user. macOS `/etc/resolver/<domain>` gets `nameserver 127.0.0.1` + `port 15353`
  (resolver(5) honours the port). fedora-fips is unaffected (`:53`, systemd, no Lima).
- **launchd opens `StandardOut/ErrorPath` AS THE JOB'S USER.** A log file owned by a prior run as a
  *different* user → open fails → the whole spawn aborts with **`EX_CONFIG` (78)** before the program
  runs a line. Fixed in the installer (`d101756`); if you hit it manually, `sudo rm -f` the log +
  kickstart.
- **Mattermost Team Edition has no arm64 Docker image** (verified 10.5–11.10), but its official
  release **binary** is published for arm64 — so SecChat builds a native image from it
  (`secchat/Dockerfile`, arch via `dpkg --print-architecture`, no buildx needed). **Authentik** is
  multi-arch already. **No Rosetta needed.**
- Native services run **from the venv binary directly** (`.venv/bin/<script>`), not `uv run` — so a
  root service never syncs into the user checkout and there's no `uv`/PATH dependence under launchd.
  `build macos` (and deploy, as a fallback) pre-syncs the venvs.
- Only **secproxy** runs as **root** (needs `:443/:80`); every other native service runs as the user.
- Deploy is **additive**; **teardown is probe-driven** (`teardown macos --dry-run` shows the plan;
  it discovers installed plists / containers / resolver entries, doesn't trust topology).

---

## Command cheat-sheet

```bash
# --- status ---
for s in secdns secllm secagent secrecorder secproxy; do \
  printf '%-12s ' "$s"; sudo launchctl print system/internal.secsuite.$s 2>&1 \
  | grep -m1 -iE 'state =|last exit' | tr -d '\t'; done
docker ps

# --- logs ---
tail -f out/logs/<svc>.err.log
tail -f out/logs/<svc>.out.log

# --- restart / stop one service ---
sudo launchctl kickstart -k system/internal.secsuite.<svc>
sudo launchctl bootout   system/internal.secsuite.<svc>

# --- run a native service in the FOREGROUND to see errors live (example: secrecorder) ---
#   (each service's exact argv/env is in `sudo launchctl print system/internal.secsuite.<svc>`)

# --- redeploy (idempotent; reinstalls units, rewrites resolver) ---
git pull && uv run secdeploy build macos && uv run secdeploy deploy macos
#   lean eval (skip the heavy stacks): add  --without secsso,secchat
#   run services in the foreground instead of launchd:  add  --no-native-services

# --- teardown (always dry-run first) ---
uv run secdeploy teardown macos --dry-run
uv run secdeploy teardown macos            # add --purge to also wipe volumes/CA (extra confirm)

# --- DNS checks ---
dig @127.0.0.1 -p 15353 <name>.sec.internal +short    # SecDNS directly
sudo killall -HUP mDNSResponder                       # flush macOS resolver cache
ping -c1 <name>.sec.internal                          # via /etc/resolver (proves the port directive)
cat /etc/resolver/sec.internal                        # should say: nameserver 127.0.0.1 / port 15353

# --- Colima (resources; non-destructive resize) ---
colima status
colima stop && colima start --cpu 4 --memory 8
```

---

## Repos / versions to be on

- **secdeploy** — `main`, HEAD `d101756` (all the fixes above).
- **secchat** — pinned `v1.1.0` (native Mattermost build). `secdeploy fetch` pulls it into `work/`.
- **secdns** — pinned `v0.1.0` (works with the high-port fix). `v1.0.1` exists with the
  console-hardening but is intentionally **not** pinned yet (a separate, tested bump).
- Everything else at its `suite.toml` pin.

If the deployed `work/` checkouts are stale, `uv run secdeploy fetch` re-checks-out every component
at its pinned ref (gitignored `*.env` files are preserved).

---

## One open design question for later

SecDNS/SecLLM/SecAgent/SecRecorder currently run as **system LaunchDaemons** (in
`/Library/LaunchDaemons`) with `UserName` set to the deploying user. They work, but the
macOS-idiomatic home for user services is a **LaunchAgent** in `~/Library/LaunchAgents`
(`launchctl bootstrap gui/$UID`), which runs in the user's session and needs no sudo. The
`EX_CONFIG` log issue is fixed either way; a future refactor to LaunchAgents (keeping only secproxy
as a root LaunchDaemon) would drop the sudo requirement for the user services. Not urgent — noted so
it isn't rediscovered.
```
