# @circulusd/session-host

This is the session host that loads a verified runtime revision into a Pi
Worker and drives one turn at a time through an agent engine. The whole
implementation is `src/index.ts`.

## What it does

- **Construction.** `new SessionHost({ loader, verifier, bindings, limits?,
  checkpointBlobs? })` takes these inputs:
  - a `WorkerLoader`, the dynamic Worker loader;
  - a `RuntimeVerifier`;
  - exactly seven broker bindings: `STATE`, `WORKSPACE`, `MODEL`, `MCP`,
    `EXECUTOR`, `ARTIFACTS` and `EVENTS`.

  Optional `limits` bound module counts and sizes, authority, event and
  checkpoint payload sizes.
- **`load(runtime)`** validates a `RuntimeRevision` and has the verifier check
  it. The revision includes the session ID, the runtime revision digest, the
  Pi adapter ABI, the compatibility date and flags, the main module and
  modules, and the `cpuMs` and `subRequests` limits. `load` then obtains the
  Worker from the loader.
- **`startTurn` and `resumeTurn`** drive an `AgentEngine`. Durable events go to
  a `DurableEventCommitter`, and ephemeral events go to an
  `EphemeralEventSink`.

`workers/pi-runtime` provides the engine implementation,
`LowLevelPiSessionHostAdapter`. The package has no build step. `exports` points
at `src/index.ts`.

## Contract

Checkpoints and events use the types in `@circulusd/protocol-types`.
`test/session-host.test.ts` reads the shared runtime identity vector
`packages/protocol-types/fixtures/runtime-identity-v1.json`. Go's
`internal/agent` tests check the same vector.

## Test

```sh
pnpm --filter @circulusd/session-host test    # vitest, runs in Node
pnpm --filter @circulusd/session-host check   # tsc
```

The tests replace the `cloudflare:workers` module with
`workers/state-app/test/cloudflare-workers.ts` (see `vitest.config.ts`).
