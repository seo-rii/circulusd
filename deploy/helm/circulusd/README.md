# circulusd Helm chart (development/reference only)

This chart runs the circulusd control-plane daemons as one privilege-separated
`DaemonSet` (one pod per selected node):

- `platformd-dev` or `platformd`
- `agentd`
- `executord`

It is not production-ready, and it is not a Kubernetes scheduler (`SPEC.md` §4
lists that as a non-goal). The daemons serve only their diagnostic control
sockets, every capability reports `NOT_WIRED`, and `AdmissionReady` stays
false.

The full guide is [`docs/deployment-k8s.md`](../../../docs/deployment-k8s.md).
It covers the image build, installation, profiles, the privilege model and
air-gap notes.

## Chart contents

- **`Chart.yaml`.** Chart version `0.0.0-dev0`, `appVersion` `0.3.0`, Kubernetes
  1.26 or later.
- **`values.yaml`.** Each option is documented inline. Main settings:

  | Setting | Effect |
  |---|---|
  | `profile` | `development-reference` (the default) runs `platformd-dev`. Any other value runs `platformd`. The guide uses `production-diagnostic`. |
  | `image.*` | Image settings. The image is built from `deploy/images/Dockerfile`. |
  | `socketDir` | `/run/pi-platform` by default. |
  | `runAsUser` and `controlPeerUID` | `65532` by default. |
  | `production.*` | Secret name and paths for `platformd`'s config, release manifest and trust roots. |
  | `privilege.*` | Elevations, all off by default. |

- **`templates/daemonset.yaml`.** A root `socket-dir-init` init container
  prepares the shared socket directory. Each daemon runs under a shell that
  removes a stale socket before it `exec`s the daemon.

## Check

```sh
helm lint deploy/helm/circulusd
helm template circ deploy/helm/circulusd --set image.tag=0.3.0-dev
```
