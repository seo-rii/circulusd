# @circulusd/state-app

This is the trusted Durable Object application that holds the authoritative
Session, Workspace and control state. According to `SPEC.md` §37.4, it is
deployed to celld. The Worker entry is `src/host/worker.ts`, and
`wrangler.jsonc` declares its bindings.

## Contents

- **Durable Objects.** Six SQLite-backed classes, bound in `wrangler.jsonc`:
  - `SessionCell`, `WorkspaceCell`, `UserCell`
  - `ExtensionStateCell`, `CapabilityGenerationCell`, `AuditCell`
- **Aggregates.** `src/session/` and `src/workspace/` hold the Session and
  Workspace aggregates. `src/control/` holds the user, extension-state,
  capability-generation and audit aggregates.
- **`src/host/`** contains the Durable Object classes, the transactional
  aggregate kernel, history storage and the 20 host RPC operations
  (`src/host/rpc.ts`). It also contains the authenticated HTTP ingress
  (`src/host/ingress.ts`), which handles these paths:
  - `/circulusd/state/v1/session-events:read`
  - `/circulusd/state/v1/session-blob:read`
  - `/circulusd/state/v1/session-turn:admit`
  - `/circulusd/state/v1/session-turn:plan`
  - `/circulusd/state/v1/session-broker:execute`
  - `/circulusd/state/v1/session-dispatch-start:claim`
- **Ingress keys and policies.** Ingress requests are HMAC-authenticated
  (`src/host/ingress.ts`). The keys come from four groups of
  `CIRCULUSD_STATE_*` bindings:
  - `INGRESS`, for event and blob reads
  - `DISPATCH_START`
  - `ADMISSION`, for admit and plan
  - `BROKER`

  Each group has `_CURRENT_KEY_ID` and `_CURRENT_KEY`, plus an optional
  `_PREVIOUS_KEY_ID` and `_PREVIOUS_KEY` for rotation. Admission and broker
  host policies come from `CIRCULUSD_STATE_ADMISSION_POLICY` and
  `CIRCULUSD_STATE_BROKER_POLICY` (`src/host/cells.ts`).
- **`src/native-storage/`** contains the native storage Worker and Durable
  Object used by `scripts/prepare-native-storage.mjs` and
  `scripts/prepare-native-state-app.mjs`. These scripts prepare local
  deployment projects and deploy nothing. See
  [`docs/unit11-operator.md`](../../docs/unit11-operator.md).

## Contract

- **Go clients.** The Go clients of the ingress are in `internal/stateappclient`.
  `internal/stateappadapter`, `internal/stateappbroker` and
  `internal/stateappadmission` build on them. `internal/stateappcodec`
  translates the Session and Pi canonical values.
- **Fixtures.** Both sides read the shared fixtures in
  `packages/protocol-types/fixtures/state-app-*.json`.
- **Schema digests.** Each host RPC operation has a `schemaDigest`, derived by
  `scripts/generate-rpc-digests.mjs` from the files in its
  `SCHEMA_SOURCE_FILES` list. `test/host.rpc.test.ts` checks the digests
  against `src/host/rpc.ts`, and other tests, Go constants and fixtures also
  pin them. Editing any listed source changes every digest.

## Test

```sh
pnpm --filter @circulusd/state-app test                  # vitest, runs in Node
pnpm --filter @circulusd/state-app check                 # tsc
pnpm --filter @circulusd/state-app check:worker-types    # wrangler types --check
pnpm --filter @circulusd/state-app generate:rpc-digests  # print current host RPC digests
pnpm --filter @circulusd/state-app types:worker          # regenerate worker-configuration.d.ts
```

The tests replace `cloudflare:workers` with `test/cloudflare-workers.ts` (see
`vitest.config.ts`). `vitest.config.ts` includes only `test/session*`,
`test/workspace*`, `test/control*`, `test/host*` and `test/phase0b*` files.
