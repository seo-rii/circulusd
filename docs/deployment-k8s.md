# Kubernetes reference deployment — DEVELOPMENT/REFERENCE ONLY

> **Scope and honesty banner.** This document and the artifacts under
> `deploy/helm/circulusd` and `deploy/images` are a **development/reference**
> way to run the circulusd control-plane daemons on Kubernetes. They are **not**
> production-ready and this is **not** a Kubernetes scheduler.
>
> `SPEC.md` §4 (비목표 / non-goals) explicitly lists a **general-purpose
> Kubernetes scheduler** as out of scope, and circulusd is architected as a
> single-node, host-privileged daemon stack (§6). What follows *packages that
> stack to run on Kubernetes*; it does not make circulusd schedule Kubernetes
> workloads, and it does not wire any production capability. Every daemon serves
> only its diagnostic control socket, reports every capability as `NOT_WIRED`,
> and `AdmissionReady` stays **false**. No `docs/acceptance.md` §53 status
> changes because of this deployment.

## Verification status

- `helm lint` and `helm template` (both profiles, and with the privilege
  toggles on) pass; the rendered manifests parse as valid YAML.
- The container image has **not** been built and the chart has **not** been
  applied to a cluster in this workspace — no container runtime or cluster was
  available here. Treat both as unverified reference scaffolding and validate
  them in your own cluster before relying on them.

## What it deploys

One privilege-separated `DaemonSet` with a single pod per selected node. The
containers share an in-pod `emptyDir` mounted at `/run/pi-platform` so their
control sockets are mutually reachable:

| Container | Binary | Domain (SPEC §6.1) | Default privilege |
|---|---|---|---|
| `platformd` | `platformd-dev` (dev) or `platformd` (prod) | control plane / state authority | least privilege |
| `agentd` | `agentd` | workerd process + cgroup management | least privilege (diagnostic-only) |
| `executord` | `executord` | Docker socket, `/dev/kvm`, mount namespace | least privilege (diagnostic-only) |

The image also carries `platformctl`, which is used as the readiness/liveness
probe (`platformctl capabilities -socket <path>`); the probe exercises the real
credentialed control handshake, so a passing probe means the daemon completed
the v1α role/capability exchange over its socket.

### What it deliberately does NOT deploy

- **sandboxd** — it is launched *inside* a sandbox (NsJail/Docker/Firecracker)
  by `executord` with mandatory sealed launch inputs, not as a node daemon; its
  binaries are also an unresolved airgap artifact.
- **The workerd/celld/nsjail/Docker/Firecracker runtime** — those are separate
  digest-pinned airgap artifacts (`deploy/airgap/release-manifest.json`), and
  the current control shells do not construct any of them.
- **Any external network listener** — `platformd`'s production public API is not
  wired, and `platformd-dev` binds loopback only.

## Prerequisites

- Kubernetes ≥ 1.26.
- A built image (see below) reachable by the cluster (mirror it into your
  registry for air-gapped installs).
- A node you intend to run the single-node stack on. A `DaemonSet` targets every
  matching node, so set `nodeSelector`/`tolerations` to pin it to one node.

## Build the image

From the repository root (the Dockerfile expects the repo as its build context):

```sh
docker build -f deploy/images/Dockerfile -t circulusd:0.3.0-dev .
# air-gapped: repoint the runtime base at your mirror
docker build -f deploy/images/Dockerfile \
  --build-arg RUNTIME_BASE=registry.internal/distroless/static-debian12:nonroot \
  -t registry.internal/circulusd:0.3.0-dev .
```

The image builds only the pure-Go daemons (`CGO_ENABLED=0`, static) onto a
distroless nonroot base (uid/gid `65532`). It bundles no runtime backends.

## Install

```sh
# development-reference (default): platformd-dev comes up cleanly and serves
# a loopback /v1/status plus a diagnostic control socket.
helm install circ deploy/helm/circulusd \
  --set image.repository=registry.internal/circulusd \
  --set image.tag=0.3.0-dev \
  --set nodeSelector."kubernetes\.io/hostname"=my-node
```

Prefer raw manifests over Helm at apply time? Render and pipe:

```sh
helm template circ deploy/helm/circulusd --set image.tag=0.3.0-dev | kubectl apply -f -
```

### Profiles

- `profile=development-reference` (default) — runs `platformd-dev`. Clean
  bring-up, loopback `/v1/status`, diagnostic control socket.
- `profile=production-diagnostic` — runs `platformd`. Its production graph is
  intentionally incomplete, so it logs `production graph is unavailable` and
  degrades to serving only the diagnostic control socket. Provide operator files
  (`config.yaml`, `release-manifest.json`, `release-trust-roots.json`) through a
  pre-created Secret if you want it to *attempt* (and honestly fail) the
  production bootstrap:

  ```sh
  kubectl create secret generic pi-platform-files \
    --from-file=config.yaml --from-file=release-trust-roots.json \
    --from-file=release-manifest.json
  helm install circ deploy/helm/circulusd \
    --set profile=production-diagnostic \
    --set production.filesSecretName=pi-platform-files
  ```

## Reaching the diagnostics

```sh
POD=$(kubectl get pod -l app.kubernetes.io/instance=circ -o jsonpath='{.items[0].metadata.name}')

# Honest capability report over the control handshake (any daemon socket):
kubectl exec "$POD" -c platformd -- \
  platformctl capabilities -socket /run/pi-platform/platformd-dev.sock
kubectl exec "$POD" -c agentd -- \
  platformctl capabilities -socket /run/pi-platform/agentd.sock

# development-reference /v1/status. It binds 127.0.0.1 only, so it is NOT
# reachable via a Service or an httpGet kubelet probe. port-forward connects to
# the pod's loopback, so use it:
kubectl port-forward "$POD" 8081:8081
curl -s http://127.0.0.1:8081/v1/status
```

The status payload advertises `"productionEligible": false`,
`"admissionEnabled": false`, and `"mode": "diagnostic-only"` — by design.

## Privilege model (SPEC §6.1)

The architecture requires strict privilege separation: **only `executord`** may
hold the Docker socket, `/dev/kvm`, and host mount-namespace rights, and
`agentd` (not `platformd`) manages workerd cgroups. The chart honors this with
per-container security contexts, but because the current binaries are diagnostic
control shells that use **none** of those privileges, every elevation defaults
**off** (least privilege: `runAsNonRoot`, `readOnlyRootFilesystem`, all
capabilities dropped, `seccompProfile: RuntimeDefault`).

Enable an elevation only once the matching production provider is actually
wired. Each maps to the correct container alone:

```sh
# agentd: host cgroup2 for future workerd cgroup management
--set privilege.agentd.hostCgroup=true

# executord: privileged + Docker socket + /dev/kvm (executord only, per §6.1)
--set privilege.executord.privileged=true \
--set privilege.executord.dockerSocket=true \
--set privilege.executord.devKvm=true
```

Do not move any of these onto the `platformd` container — that would violate
§6.1.

## Air-gap notes

- Mirror both the runtime base image (`RUNTIME_BASE`) and the built circulusd
  image into your offline registry; set `image.repository`/`image.pullSecrets`
  accordingly.
- A production image would additionally layer the digest-pinned workerd, celld,
  and nsjail binaries from `deploy/airgap/release-manifest.json`. This reference
  image intentionally does not, because those capabilities are not wired.

## Boundaries this deployment does not cross

- `AdmissionReady` stays **false**; no production admission or readiness is
  enabled.
- Every capability reports `NOT_WIRED`; no model, MCP, execution, state, or
  isolation capability is promoted.
- No `docs/acceptance.md` §53 status is upgraded by running this chart.
- This is not, and does not become, a general-purpose Kubernetes scheduler
  (`SPEC.md` §4).
