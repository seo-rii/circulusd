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

## Security status

This repository begins at version `0.3.0` in development status. A compiled unit-test build is not a production qualification. In particular, celld, workerd/Pi, NsJail, Docker, Firecracker, the object store, and the offline bundle each have separate fail-closed conformance gates.

The production `platformd` command therefore keeps only its credentialed
diagnostic control socket when the complete production graph is unavailable.
The currently composed state-only candidate graph is deliberately rejected as
incomplete, and no production public listener is opened.
