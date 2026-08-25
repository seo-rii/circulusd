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

## Security status

This repository begins at version `0.3.0` in development status. A compiled unit-test build is not a production qualification. In particular, celld, workerd/Pi, NsJail, Docker, Firecracker, the object store, and the offline bundle each have separate fail-closed conformance gates.
