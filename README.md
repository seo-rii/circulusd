# circulusd

`circulusd` is an offline, self-hosted, multi-tenant Pi agent platform. It keeps one disposable Pi Worker per session while placing the authoritative turn, effect, runtime, and workspace state in trusted durable objects.

The implementation follows [SPEC.md](SPEC.md), Draft v0.3. The non-negotiable boundaries are:

- one Session durable object is the only durable turn/effect program counter;
- an external call requires a state-issued dispatch permit after a durable commit;
- a Workspace durable object owns revisions, the single mutable lease, and its invocation ledger;
- Pi Workers, workerd shards, sandboxes, containers, and microVMs are disposable caches;
- NsJail, Docker, and Firecracker never silently fall back to another backend;
- mock components are development-only and never count as real conformance.

## Development

Prerequisites are pinned in `.tool-versions`. The root uses one Go module and a pnpm workspace.

```bash
pnpm install --frozen-lockfile
go test ./...
pnpm test
pnpm check
```

External runtime and isolation tests report one of `PASS`, `FAIL`, `UNAVAILABLE`, or `NOT_RUN`. Only `PASS` satisfies a required release profile. The current acceptance ledger is maintained in `docs/acceptance.md` as features land.

The phase roadmap is defined in `SPEC.md` §51. The current repository work-unit
cut, including the accepted Unit 10 Phase 0A resource-qualification plan, is in
[`docs/implementation-plan.md`](docs/implementation-plan.md). Planned work does
not change the evidence in [`docs/acceptance.md`](docs/acceptance.md).

The development daemon is a separate, non-production executable:

```bash
# terminal 1
CIRCULUSD_DEV_RUN_DIR="${XDG_RUNTIME_DIR:?set XDG_RUNTIME_DIR}/circulusd"
install -d -m 700 "$CIRCULUSD_DEV_RUN_DIR"
go run ./cmd/platformd-dev \
  --listen 127.0.0.1:8081 \
  --socket "$CIRCULUSD_DEV_RUN_DIR/platformd-dev.sock"
```

In another terminal:

```bash
CIRCULUSD_DEV_SOCKET="${XDG_RUNTIME_DIR:?set XDG_RUNTIME_DIR}/circulusd/platformd-dev.sock"
curl --fail http://127.0.0.1:8081/v1/status
go run ./cmd/platformctl capabilities --socket "$CIRCULUSD_DEV_SOCKET"
```

`platformd-dev` accepts only a canonical literal loopback address such as
`127.0.0.1:8081` or `[::1]:8081`; wildcard addresses, hostnames, production
configuration, and release inputs are rejected before any dependency or
listener is created. Its current `development-reference` profile is
diagnostic-only: it has no Session admission, state implementation, execution
provider, model gateway, or MCP gateway. A `200` response from `/v1/status`
means only that this local diagnostic shell is responding. It is not workload
readiness or production qualification. The control socket's parent directory
must be owned by the current user and must not be writable by group or others;
placing the socket directly under `/tmp` is rejected.

The current `agentd` and `executord` commands are also diagnostic-only control
shells. They start no workerd shard, sandbox, or execution provider and refuse
to bind until at least one `--allow-platformd-uid` or
`--allow-platformctl-uid` grants an explicit UID-to-protocol-role authority.
Giving one UID both roles is useful for local development, but is not service
isolation or a production deployment claim. Their canonical private UDS paths
are created with mode `0600`, and operational capabilities remain `NOT_WIRED`.

For example, after creating `CIRCULUSD_DEV_RUN_DIR` as above, the two shells can
be started in separate terminals for a local protocol exercise:

```bash
CIRCULUSD_LOCAL_UID="$(id -u)"
go run ./cmd/agentd \
  --socket "${XDG_RUNTIME_DIR:?set XDG_RUNTIME_DIR}/circulusd/agentd.sock" \
  --allow-platformd-uid "$CIRCULUSD_LOCAL_UID" \
  --allow-platformctl-uid "$CIRCULUSD_LOCAL_UID"

CIRCULUSD_LOCAL_UID="$(id -u)"
go run ./cmd/executord \
  --socket "${XDG_RUNTIME_DIR:?set XDG_RUNTIME_DIR}/circulusd/executord.sock" \
  --allow-platformd-uid "$CIRCULUSD_LOCAL_UID" \
  --allow-platformctl-uid "$CIRCULUSD_LOCAL_UID"
```

`sandboxd` is launcher-facing rather than a diagnostic shell. Its Linux CLI
requires the launch backend and execution-environment digest as well as the
sandbox identity, generation, protocol version, manifest owner, and at least
one executord UID. File descriptor 3 must be the read end of the launcher's
one-use 32-byte nonce pipe. A complete invocation has this shape:

```bash
./sandboxd \
  --control-socket "$CIRCULUSD_SANDBOX_CONTROL_SOCKET" \
  --command-manifest "$CIRCULUSD_COMMAND_MANIFEST" \
  --command-manifest-owner-uid "$CIRCULUSD_MANIFEST_OWNER_UID" \
  --sandbox-id "$CIRCULUSD_SANDBOX_ID" \
  --generation "$CIRCULUSD_SANDBOX_GENERATION" \
  --backend nsjail \
  --execution-environment-digest "$CIRCULUSD_EXECUTION_ENVIRONMENT_DIGEST" \
  --protocol-version 1 \
  --allow-client-uid "$CIRCULUSD_EXECUTORD_UID" \
  3<"$CIRCULUSD_LAUNCH_NONCE_PIPE"
```

The backend must be `nsjail`, `docker`, or `firecracker`, and the environment
digest must be `sha256:` followed by 64 lowercase hexadecimal digits. The
manifest owner must be a canonical non-root UID and the sandbox generation must
be positive. These values are fixed before the control socket opens; they are
not client-selected process options.

`platformctl doctor` includes one bounded `uds.protocol` probe over exactly
three distinct control sockets: platformd as `PLATFORMD`, agentd as `AGENTD`,
and executord as `EXECUTORD`. `--uds-timeout` is a shared total budget and may
not exceed 30 seconds. It is not a hard wall-clock bound: client construction
performs synchronous socket-path metadata checks without a context, so a custom
FUSE/NFS-backed path can block past the deadline. The default local `/run`
layout assumes responsive local metadata. The JSON report binds the run to the
profile, configuration and release digests, host, `platformctl` binary, boot
target, required-component set, and observation time, and its qualification
booleans are recomputed from the results. The retained report is unsigned and
production startup does not consume it. A successful role/descriptor probe
proves only live protocol compatibility at that socket; it is not daemon binary
attestation, process-instance identity, or startup authority. If caller
cancellation is observed before report completion, the partial report is
discarded instead of being emitted as a reusable snapshot.

The default `/run/pi-platform/{platformd,agentd,executord}.sock` locations are a
current local single-node runtime convention, not discovery or component
identity. Custom `platformctl doctor` socket flags retarget only that diagnostic
invocation; they do not reconfigure daemon startup, and the selected paths are
not included in retained component identity or startup authority. Artifact
references in a generated report are sorted by name. The JSON Schema validates
the serialized structure, while retained-report
acceptance additionally requires `internal/doctor.ValidateCurrent`: freshness
is measured from `startedAt`, future `finishedAt`/`observedAt` values and an
evidence window over 24 hours are rejected, and the identity and derived
qualification fields are recomputed.

Control and sandbox RPC metadata deadlines are capped at five minutes. Their
servers bound request reads to five seconds and keep a five-minute-five-second
write horizon so a response still has a short slow-reader margin after the
maximum RPC deadline; that transport margin does not extend request authority.

## Security status

This repository begins at version `0.3.0` in development status. A compiled unit-test build is not a production qualification. In particular, celld, workerd/Pi, NsJail, Docker, Firecracker, the object store, and the offline bundle each have separate fail-closed conformance gates.

The production `platformd` command therefore keeps only its credentialed
diagnostic control socket when the complete production graph is unavailable.
The currently composed state-only candidate graph is deliberately rejected as
incomplete, and no production public listener is opened.
