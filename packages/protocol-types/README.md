# @circulusd/protocol-types

Shared TypeScript protocol types, validators and the canonical CBOR codec. The
workers and the other packages depend on this package.

## Contents

- **`src/cbor.ts`.** Canonical CBOR encoding and decoding, and value
  normalization. This is the TypeScript side of the cross-language canonical
  form; the Go side is `internal/canonical`.
- **`src/digest.ts`.** `digestStructuredValue` returns `sha256:` and the hex
  SHA-256 of the canonical CBOR encoding of
  `["circulusd.hash", 1, domain, schemaVersion, payload]`. Go's
  `canonical.StructuredDigest` computes the same digest.
- **`src/types.ts` and `src/validation.ts`.** These define and validate:
  - the RPC envelope (`circulus.v1alpha1`, version 1.0)
  - agent checkpoints and engine step results
  - effect claims and dispatch permit claims
  - conformance status values
- **`src/conversation.ts`.** The Pi conversation snapshot, head and activation
  records.
- **`src/execution-capacity.ts`.** `PI_EXECUTION_CAPACITY`, the shared size,
  item and depth budgets.
- **`src/errors.ts` and `src/text.ts`.** Validation errors and Unicode checks.

The package has no build step. `exports` points at `src/index.ts`, and
consumers import the TypeScript sources directly.

## Contract

- **Fixtures.** `fixtures/*.json` are cross-language golden fixtures, and Go
  and TypeScript tests both read them. For example,
  `fixtures/v1alpha-golden.json` holds the canonical CBOR and digest vectors
  that `internal/canonical` and `test/cbor.test.ts` check. Some fixtures are
  written by a test when an update variable is set. Grep for
  `CIRCULUSD_UPDATE_` and `UPDATE_ADMISSION_PLAN_FIXTURE`.
- **State-app digests.** Several files in `src/` are inputs to the state-app
  host RPC schema digests (`SCHEMA_SOURCE_FILES` in
  `workers/state-app/scripts/generate-rpc-digests.mjs`). Editing one of them,
  even a comment, changes every pinned host RPC digest.

## Test

```sh
pnpm --filter @circulusd/protocol-types test    # vitest
pnpm --filter @circulusd/protocol-types check   # tsc
```

`test/cbor.fuzz.test.ts` is a fast-check property test in the normal suite. It
reads `CIRCULUSD_FUZZ_SEED`, `CIRCULUSD_FUZZ_RUNS` and `CIRCULUSD_FUZZ_PATH`.
For longer fuzzing runs, see [`docs/fuzzing.md`](../../docs/fuzzing.md).
