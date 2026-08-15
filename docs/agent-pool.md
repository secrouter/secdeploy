# SecChat Kubernetes agent pool

The **agent pool** runs SecChat coding agents in **server-launched, per-session, ephemeral
Kubernetes pods** instead of in-process on the SecChat host or on a user's desktop daemon. Each
coding session gets its own hardened pod (`Dockerfile.runnerd`); SecChat owns the pod lifecycle —
it creates the pod when a pooled session starts and deletes it on stop/exit. The pod dials back to
SecChat over an owner-scoped runner token and relays events up, so **the execute-gate and all
authorization stay on the server** — the pod is just a sandboxed place to run `pi`.

SecChat itself stays where the target puts it (compose on macOS, systemd on Fedora); only the agent
pods live in the cluster. The pool is **off by default** — a deployment with no cluster simply omits
the section.

## Enabling it — `secsite.toml`

```toml
[secchat.pool]
enabled = true

# The runnerd image the pods run. Either point at a pre-built/pushed image…
image = "registry.internal/secchat-runnerd:1.4.0"
# …or have SecDeploy build + push it for you (then `image` is optional):
build_image = true
registry = "registry.internal"          # required when build_image = true

apply = true                            # kubectl apply the emitted manifests (else write-only)
kube_context = "enclave"                # optional --context for the apply

namespace = "secchat-pool"              # where the agent pods run
service_account = "secchat"             # SecChat's own SA (RoleBinding subject; referenced, not created)
service_account_namespace = "secchat"   # the namespace that SA lives in
secchat_url = "http://secchat.secchat.svc:47010"  # cluster-internal URL a pod dials back (see below)
git_host = "git.sec.internal"           # the enclave git host the pods reach (egress annotation)

cpu = "1"                               # per-pod CPU limit
memory = "1Gi"                          # per-pod memory limit
max_pods = 20                           # global cap (ResourceQuota + SecChat admission)
max_per_owner = 3                       # per-owner cap (SecChat admission only)
ttl_seconds = 3600                      # pod activeDeadlineSeconds (hard reap backstop)
```

`image` is required when `enabled` unless `build_image` produces it; `registry` is required when
`build_image`.

## What a deploy does

With `[secchat.pool].enabled`, `secdeploy deploy <target>` (for the resource hosting SecChat):

1. **Builds + pushes the runnerd image** (when `build_image`): `docker build -f Dockerfile.runnerd`
   from the fetched `work/secchat` checkout → pushes to `registry` as
   `<registry>/secchat-runnerd:<secchat-sha>` → pins `image` to the pushed **digest** when Docker
   reports one. Skipped (with a warning telling you what to run by hand) if `docker` is absent.
2. **Writes the backend env** into `work/secchat/.env` — the `SECCHAT_POOL_*` keys below — so
   SecChat enables the pool on its next bring-up.
3. **Emits the cluster manifests** to `<out>/addressing/secchat-pool.k8s.json`.
4. **Applies them** (when `apply`): `kubectl apply -f …` (with `--context kube_context` if set).
   Skipped (with the exact command to run yourself) if `kubectl` is absent or the cluster is
   unreachable — the deploy never fails over this.

Everything after step 2 is best-effort: SecChat on the host is already up, and the pool RBAC can be
applied out of band.

### The emitted manifests (a `v1/List`)

- **Namespace** `namespace`.
- **Role** `secchat-pool-manager` — `create/delete/get/list/watch` on `pods` in that namespace.
- **RoleBinding** — binds that Role to SecChat's `service_account` (in `service_account_namespace`).
  The SA is **referenced, not created** — it belongs to SecChat's own deployment.
- **ResourceQuota** `secchat-pool-quota` — `hard.pods = max_pods`.
- **NetworkPolicy** `secchat-pool-egress` — denies all ingress; allows egress to DNS and git
  ports (22/443/9418). See the egress note below.

The agent pods themselves are **not** in the manifest — SecChat creates them at runtime via the
RBAC granted here.

### The backend env (`work/secchat/.env`)

`SECCHAT_POOL_IMAGE`, `SECCHAT_POOL_NAMESPACE`, `SECCHAT_POOL_CPU`, `SECCHAT_POOL_MEMORY`,
`SECCHAT_POOL_TTL`, `SECCHAT_POOL_MAX_PODS`, `SECCHAT_POOL_MAX_PER_OWNER`, and
`SECCHAT_POOL_SECCHAT_URL` (from `secchat_url`, else SecChat's topology address). SecChat also needs
a runner-token secret to mint the per-pod credential — that's the stack's own session secret,
already seeded by the deploy.

## Using it

A user picks the launch environment when creating a coding agent (`POST /agents` with
`launchEnv:"pool"`, surfaced as "Online pool" in the picker). Every session for that agent then runs
in a fresh pod. Admission is capped: at `max_pods` (global) or `max_per_owner`, a new session is
rejected fast with a clear message rather than piling pods onto the cluster.

**Observability:** `GET /pool/status` (admin-gated) reports the limits and the live pool sessions
(session id, owner, pod name, attached?, age — metadata only, never content). SecChat also
reconciles every 60 s, reaping any `app=secchat-pool` pod with no live session (belt-and-suspenders
beyond per-session delete and the pods' `activeDeadlineSeconds`).

## Cross-boundary networking

SecChat runs on the host; the pods run in the cluster. `secchat_url` **must be reachable from inside
the cluster** — the pod dials back to `<secchat_url>/runner?pool=<sessionId>`. In a split topology
(host SecChat, remote cluster) this usually means exposing SecChat's `:47010` to the cluster (a
Service/Endpoints pointing at the host, an internal LB, or a tunnel). If SecChat is also in the
cluster, the in-cluster Service DNS name is the natural value.

## Egress / `git_host`

A vanilla Kubernetes `NetworkPolicy` **can't match hostnames**, so the emitted egress is port-only
(git ssh/https/git + DNS). `git_host` is surfaced as the `secchat.io/git-host` annotation on the
NetworkPolicy so an FQDN-aware layer (Cilium/Calico egress-by-FQDN) or you can scope egress to the
real host. Tighten this to your enclave's actual git/registry CIDRs before production.

## Fully manual path (no `build_image` / no `apply`)

Leave both off and SecDeploy just writes `work/secchat/.env` + `secchat-pool.k8s.json`. Then:

```bash
docker build -f work/secchat/Dockerfile.runnerd -t <registry>/secchat-runnerd:<tag> work/secchat
docker push <registry>/secchat-runnerd:<tag>
# set [secchat.pool].image to that ref, redeploy (writes the .env), then:
kubectl apply -f <out>/addressing/secchat-pool.k8s.json
```

## Out-of-cluster SecChat (compose on the host)

When SecChat runs outside the cluster — this suite's normal shape — set:

```toml
[secchat.pool]
api_server = "https://<node-ip>:<api-port>"   # reachable FROM the SecChat container, in the cert SANs
create_service_account = true                  # emit the SA + token Secret; deploy mounts the credential
```

The deploy then extracts the ServiceAccount token + cluster CA into `work/secchat/pool-sa/` and
writes a `compose.override.yaml` mounting them at the standard in-cluster paths, so the backend's
unmodified Kubernetes client works from compose.

### colima (macOS test instances)

`colima kubernetes start` adds k3s to the running VM. Notes from a live bring-up:

- k3s shares the **docker runtime**, so a locally-built image (`docker build -f Dockerfile.runnerd
  -t secchat-runnerd:local .`) is visible to the cluster with **no registry** — set
  `image = "secchat-runnerd:local"`.
- The API server does **not** listen on 6443: colima runs it on a nonstandard port bound on all VM
  interfaces (find it with `colima ssh -- sh -c "sudo ss -tlnp | grep k3s"` — the `*:<port>`
  listener, the same port as the macOS kubeconfig's `127.0.0.1:<port>`). Use
  `api_server = "https://192.168.5.1:<that-port>"` — `192.168.5.1` is the VM/node IP and is in the
  API cert's SANs. If a colima restart re-mints the port, update `api_server` and re-deploy.
- The pod dial-back URL is the VM IP too: `secchat_url = "http://192.168.5.1:47010"` (docker
  publishes SecChat's port on the VM's interfaces).

## Analysis sidecars — `[secchat.pool.analysis_images]`

Analysis tooling containers (the secagent analyzer family — IKOS, Roslyn, rust-analyzer — or any
site image) can be attached to an agent's pod **at agent creation**, chosen per agent from the
deployment's catalog:

```toml
[secchat.pool.analysis_images]
rust = "secagent-analyzer-rust:local"
ikos = "secagent-analysis:local"
```

The catalog reaches SecChat as `SECCHAT_POOL_ANALYSIS_IMAGES`; the New-Coding-Agent dialog offers
the names as checkboxes. Each chosen analyzer becomes a hardened sidecar in the agent's pod,
**sharing the pod's `/workspace` volume** (where pi's working tree is rooted) so its tooling
operates on the agent's actual code. Pair with `[[builds]]` entries so the images are built at
deploy. See secchat's own `docs/agent-pool.md` for the in-pod invocation protocol (the
file-based work queue on the shared volume).

## Internet access — per-agent, default OFF

The pool's base NetworkPolicy restricts pod egress to DNS + git ports + the SecChat dial-back.
A second, emitted-by-default policy (`secchat-pool-egress-open`) allows **all** egress — but only
for pods labeled `secchat.io/egress: open`, which SecChat sets solely when an agent was created
with **Internet access** enabled (a warn-tinted switch in the dialog, default off). Fail-closed:
no label → no match → restricted egress. Note the base policy is **port-scoped, not
destination-scoped** (a vanilla NetworkPolicy can't match hostnames): a restricted pod can still
reach any host on 443/22/9418 — tighten with real CIDRs (see `git_host`) for production.
