# @circulusd/pi-runtime

This is the Pi agent runtime that runs inside a disposable Pi Worker. It wraps
`@earendil-works/pi-agent-core` 0.84.3 in an engine that exchanges canonical
checkpoints and engine step results. Those formats are defined in
`@circulusd/protocol-types`.

## Contents

- **`LowLevelPiAgentEngine`** (`src/engine.ts`) drives one session's turns
  through the Pi Agent Core adapter in `src/pi-agent-core-adapter.ts` (adapter
  ABI 2, state version 2).
- **`LowLevelPiSessionHostAdapter`** (`src/session-host-adapter.ts`) implements
  the `AgentEngine` interface of `workers/session-host`.
- **Codecs:**
  - `$pi.number.v1` JSON numbers (`src/pi-json-codec.ts`)
  - `pi-cost-decimal-v1` costs (`src/pi-cost-codec.ts`)
  - `pi-tool-details-json-v1` tool details (`src/pi-tool-details-codec.ts`)
- **Genesis and execution entrypoints** (`src/genesis-entrypoint.ts`,
  `src/execution-entrypoint.ts`). These are factories for the WorkerEntrypoint
  classes, and `scripts/prepare-native-pi.mjs` bundles them.
- **Runtime mapping verification** (`src/genesis-runtime-mapping.ts`,
  `src/execution-runtime-mapping.ts`).
- **Status.** `getPiWorkerdConformanceStatus()` returns `UNAVAILABLE`. Pi Agent
  Core with stock workerd has not passed the dynamic-worker, outbound-denial
  and isolate-separation gate.

The package has no build step. `exports` points at `src/index.ts`. The harness
(`harness/backend`) and the workerd conformance fixture
(`internal/conformance/workerd/fixture/pi-worker.entry.ts`) import it.

## Contract

These Go packages implement the same wire formats, and they share fixtures in
`packages/protocol-types/fixtures/`:

| Go package | TypeScript source |
|---|---|
| `internal/enginegenesis` | genesis wire and genesis runtime mapping |
| `internal/engineexecution` | execution runtime mapping |
| `internal/modelgateway` | `$pi.number.v1` tool arguments and `pi-cost-decimal-v1` session results |
| `internal/stateappcodec` | state-app Pi codec (`stateapp-pi-codec-v1.json`) |

## Test

```sh
pnpm --filter @circulusd/pi-runtime test    # vitest, runs in Node
pnpm --filter @circulusd/pi-runtime check   # tsc
```
