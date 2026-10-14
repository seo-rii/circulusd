# Testing

This page lists the test suites in this repository and how to run each one. It
also explains how to regenerate checked-in fixtures, protobuf output and pinned
digests. Run commands from the repository root unless a section says otherwise.

No hosted CI configuration is checked in. The suites below are run locally, and
the results recorded in [`acceptance.md`](acceptance.md) come from local runs.

## Toolchain

`.tool-versions` pins Go 1.25.3, Node.js 24.1.0, pnpm 10.30.0 and protoc
3.21.12. The root `package.json` requires Node.js 24.1.0 or later. Python 3 runs
the API contract checker and some script tests. Use Python 3.11 or later,
because `scripts/tests/test_isolated_codex_test.py` imports `tomllib`.

Install the JavaScript dependencies once:

```sh
pnpm install --frozen-lockfile
```

## Summary

| Suite | Command | Notes |
|---|---|---|
| Go tests | `go test ./...` | One Go module (`go.work` uses only `.`). |
| Go race detector | `go test -race ./internal/controlrpc` | Needs cgo and a C compiler. |
| Fuzzing | `pnpm fuzz:list`, `pnpm fuzz` | See [`fuzzing.md`](fuzzing.md). |
| TypeScript and harness tests | `pnpm test` | Every workspace package's `test` script. |
| TypeScript type check | `pnpm check` | `tsc -p tsconfig.json` per package. |
| Lint | `pnpm lint` | `oxlint --deny-warnings` over `packages`, `workers` and `harness`. |
| API contract checker | `python3 api/proto/check_contract.py` | Needs `protoc` and the Python `protobuf` package. |
| Contract checker tests | `python3 -m unittest api.proto.check_contract_test` | Run from the repository root. |
| Script tests (Node) | `node --test scripts/tests/prepare-native-*.test.mjs` | Needs `pnpm install` (esbuild). |
| Script tests (Python) | `python3 scripts/tests/test_isolated_codex_test.py` | Tests `scripts/test-isolated-codex.py`. |
| Native celld fork | see [`deploy/native-celld/README.md`](../deploy/native-celld/README.md) | Python, Node and Rust checks. |
| Live gates | environment variables in [Opt-in live gates](#opt-in-live-gates) | Skipped unless selected. |

The Go gate recorded in [`acceptance.md`](acceptance.md) is:

```sh
go test -race -p=1 ./...
go vet -p=1 ./...
git diff --check
```

Those records run `pnpm check` and `pnpm lint` alongside it.

## Go

```sh
go test ./...                                  # every package
go test ./internal/canonical                   # one package
go test -count=1 ./internal/broker -run '^TestName$'   # one test, bypassing the cache
go test -race ./internal/controlrpc            # race detector
```

- Go skips directories named `testdata`. The differential CBOR probe in
  `testdata/cbor-differential` is therefore not part of `go test ./...`; the
  fuzz runner builds it.
- Files that end in `_linux.go` or `_linux_test.go` build only on Linux. Many
  daemon, sandbox and conformance packages have them, so run the full suite on
  Linux.
- A few tests skip themselves when the host cannot run them. Examples are an
  unavailable IPv6 loopback, and running as root where a test needs a non-root
  peer UID.
- Fuzz targets run their seed inputs and any saved inputs under
  `testdata/fuzz/` as ordinary tests. Mutation fuzzing needs `-fuzz`, which
  `pnpm fuzz` drives (see [`fuzzing.md`](fuzzing.md)).

### Opt-in live gates

These tests need provisioned external inputs. Without their variables they call
`t.Skip`, and a skip is never a `PASS`.

| Variable(s) | Test | Package |
|---|---|---|
| `CIRCULUSD_WORKERD_PATH`, `CIRCULUSD_WORKERD_SHA256`, `CIRCULUSD_WORKERD_VERSION` (all three) | `TestStockWorkerdFixture` | `internal/conformance/workerd` |
| `CIRCULUSD_WORKERD_QUALIFICATION_CONFIG` | `TestStockWorkerdResourceQualification` | `internal/conformance/workerd` |
| `CIRCULUSD_NSJAIL_QUALIFICATION_CONFIG` | `TestProvisionedNsJailQualification` | `internal/conformance/nsjail/qualification` |

[`unit10-operator.md`](unit10-operator.md) describes the workerd resource
qualification gate and its configuration.

## TypeScript

The pnpm workspace (`pnpm-workspace.yaml`) contains `packages/*`, `workers/*`,
`harness/backend` and `harness/frontend`.

| Package | Directory | `test` script | `check` script |
|---|---|---|---|
| `@circulusd/protocol-types` | `packages/protocol-types` | `vitest run` | `tsc -p tsconfig.json` |
| `@circulusd/extension-manifest` | `packages/extension-manifest` | `vitest run` | `tsc -p tsconfig.json` |
| `@circulusd/pi-runtime` | `workers/pi-runtime` | `vitest run` | `tsc -p tsconfig.json` |
| `@circulusd/session-host` | `workers/session-host` | `vitest run` | `tsc -p tsconfig.json` |
| `@circulusd/state-app` | `workers/state-app` | `vitest run` | `tsc -p tsconfig.json` |
| `@circulusd/harness-backend` | `harness/backend` | `node --test` (listed files) | `tsc -p tsconfig.json` |
| `@circulusd/harness-frontend` | `harness/frontend` | `node --test test/*.test.mjs` | none |

```sh
pnpm test                                        # all packages
pnpm test:unit                                   # only the five vitest packages
pnpm --filter @circulusd/state-app test          # one package
pnpm --filter @circulusd/state-app check:worker-types
```

- Each vitest package has a `vitest.config.ts`. `workers/state-app` includes
  only `test/session*`, `test/workspace*`, `test/control*`, `test/host*` and
  `test/phase0b*` test files, with a 20-second test timeout.
- `packages/protocol-types/test/cbor.fuzz.test.ts` runs in the normal suite. It
  reads `CIRCULUSD_FUZZ_SEED` (default 20260905), `CIRCULUSD_FUZZ_RUNS`
  (default 250) and `CIRCULUSD_FUZZ_PATH`.
- `check:worker-types` runs `wrangler types --check` against
  `workers/state-app/worker-configuration.d.ts`. `pnpm check` does not run it.
- The harness live sandbox test runs only when `CIRCULUSD_TEST_SANDBOX_LIVE=1`,
  `CIRCULUSD_TEST_SANDBOX_LAUNCHER` or `CIRCULUSD_TEST_SANDBOX_DISTRO` is set.
  See [`harness/README.md`](../harness/README.md).

## Python

```sh
python3 api/proto/check_contract.py
python3 -m unittest api.proto.check_contract_test
python3 scripts/tests/test_isolated_codex_test.py
python3 -m unittest discover -s deploy/native-celld -p test_build.py -v
```

`check_contract.py` compiles `api/proto/circulus/v1alpha/*.proto` with
`protoc` and validates the wire-contract rules and the JSON Schemas in
`api/json-schema/v1alpha`. It also checks that
`api/descriptors/circulus.v1alpha.pb` and its `.sha256` file match the
compiled protos. It needs the Python `protobuf` package. If the `jsonschema`
package is missing, the checker skips the steps that use it, and the two
schema test classes in `check_contract_test.py` are skipped.

## Script tests

```sh
node --test scripts/tests/prepare-native-pi.test.mjs \
  scripts/tests/prepare-native-state-app.test.mjs \
  scripts/tests/prepare-native-storage.test.mjs
```

These test the `scripts/prepare-native-*.mjs` preparation tools. They import
`esbuild` from the root dependencies.

`scripts/tests/native-rpc-output-gate.test.mjs` runs the celld JavaScript
harness from a patched native celld checkout. Set
`CIRCULUSD_NATIVE_CELLD_SOURCE` to that checkout. Its default,
`.codex/native-storage-qualification/source`, is ignored by git and is not in
the repository, and the test fails to load without it. List the three
preparation tests explicitly, as above. See
[`deploy/native-celld/README.md`](../deploy/native-celld/README.md).

## Fixture and golden update switches

Cross-language fixtures live in `packages/protocol-types/fixtures/`. One
language writes each fixture and the other language reads it. A switch writes
the file only when its value is exactly `1`. The same test then compares the
file with the output it just computed. After an update, run the reading side
too.

| Switch | Writing test | File | Read by |
|---|---|---|---|
| `CIRCULUSD_UPDATE_NATIVE_STORAGE_FIXTURE` | `TestNativeStorageGoldenWire` in `internal/celldbridge` | `native-storage-v1alpha1.json` | `workers/state-app/test/host.native-storage-worker.test.ts` |
| `CIRCULUSD_UPDATE_PI_EXECUTION_MAPPING_FIXTURE` | `TestRuntimeMappingGoldenFixture` in `internal/engineexecution` | `pi-execution-runtime-mapping-v1alpha1.json` | `workers/pi-runtime/test/execution-runtime-mapping.test.ts` |
| `CIRCULUSD_UPDATE_PI_GENESIS_MAPPING_FIXTURE` | `TestRuntimeMappingGoldenFixture` in `internal/enginegenesis` | `pi-genesis-runtime-mapping-v1alpha1.json` | `workers/pi-runtime/test/genesis-runtime-mapping.test.ts` |
| `CIRCULUSD_UPDATE_ENGINE_GENESIS_FIXTURE` | `TestEngineGenesisWireFixtureMatchesOperationalServer` in `internal/enginegenesis` | `engine-genesis-v1alpha1.json` | `workers/pi-runtime/test/genesis-wire.test.ts`, `genesis-worker.test.ts`, `celld-genesis-mapping.test.ts` |
| `UPDATE_ADMISSION_PLAN_FIXTURE` | `workers/state-app/test/host.admission-plan.test.ts` | `state-app-admission-plan-v1alpha1.json` | Go tests in `internal/stateappclient`, `internal/stateappadmission` and `internal/enginegenesis` |
| `CIRCULUSD_UPDATE_BROKER_GOLDEN` | `workers/state-app/test/session.broker-golden.test.ts` | `state-app-broker-lifecycle-v1.json` | Go tests in `internal/stateappbroker` |

Note that `UPDATE_ADMISSION_PLAN_FIXTURE` has no `CIRCULUSD_` prefix.

Examples:

```sh
CIRCULUSD_UPDATE_NATIVE_STORAGE_FIXTURE=1 \
  go test -count=1 ./internal/celldbridge -run '^TestNativeStorageGoldenWire$'
pnpm --filter @circulusd/state-app test

UPDATE_ADMISSION_PLAN_FIXTURE=1 pnpm --filter @circulusd/state-app test
go test -count=1 ./internal/stateappclient ./internal/stateappadmission ./internal/enginegenesis
```

The other fixtures in that directory have no update switch.

Two other generated files have their own commands:

- `pnpm generate:workerd-fixture` bundles
  `internal/conformance/workerd/fixture/pi-worker.entry.ts` into
  `pi-worker.mjs` in the same directory with esbuild. The workerd conformance
  harness embeds the bundle.
- `pnpm --filter @circulusd/state-app types:worker` regenerates
  `workers/state-app/worker-configuration.d.ts` from `wrangler.jsonc`.

## Protobuf regeneration

`api/proto/generate.sh` regenerates the Go protobuf and Connect code from
`api/proto/circulus/v1alpha/*.proto`. It pins:

| Tool | Version | Source |
|---|---|---|
| `protoc` | `libprotoc 3.21.12` | must be on `PATH` and also pinned in `.tool-versions`; the script exits if the version differs |
| `protoc-gen-go` | `v1.36.10` | installed by the script with `go install` into a temporary directory |
| `protoc-gen-connect-go` | `v1.19.1` | installed by the script with `go install` into a temporary directory |

These match `google.golang.org/protobuf v1.36.10` and
`connectrpc.com/connect v1.19.1` in `go.mod`. The `go install` steps need the
module cache or network access.

```sh
api/proto/generate.sh
```

The script does the following:

1. It keeps a copy of the current `api/descriptors/circulus.v1alpha.pb` as a
   baseline.
2. It runs `check_contract.py --against <baseline>`, which also checks backward
   compatibility. That run writes the new descriptor set and its `.sha256` file.
3. It regenerates `api/generated/circulus/v1alpha/*.pb.go` and
   `api/generated/circulus/v1alpha/circulusv1alphaconnect/*.connect.go`.
4. It runs `gofmt -w` on the generated tree.

The descriptor digest is also hard-coded in Go, and the script does not update
these copies:

- `internal/controlrpc/protocol.go`
- `internal/sandboxrpc/protocol.go`
- `internal/doctoruds/probe_linux.go`
- `cmd/platformctl/main_test.go`

The control and sandbox handshakes reject a peer whose descriptor digest
differs, so update all of these copies when the descriptor changes. To find
them, run `git grep` with the old digest.

## State-app host RPC schema digests

Each of the 20 state-app host RPC operations has a `schemaDigest` in
`HOST_RPC_SIZE_CONTRACTS` in `workers/state-app/src/host/rpc.ts`. The
operations are the `session.*`, `workspace.*`, `user.*`, `extension-state.*`,
`capability-generation.*` and `audit.*` operations. Each digest identifies the
source code that defines the operation's wire format. It is not a hash of a
schema document.

`computeHostRpcSchemaDigest(operation)` in
`workers/state-app/scripts/generate-rpc-digests.mjs` derives the digest. It
returns `sha256:` and the hex SHA-256 of this input:

1. the string `circulusd.state-host.rpc-source.v2` and a NUL byte;
2. the operation name and a NUL byte;
3. for each path in `SCHEMA_SOURCE_FILES`, in order:
   - the path as written, a NUL byte, the source length in bytes as a decimal
     string, and a NUL byte;
   - then the source text and a NUL byte.

Before the length and text are taken, CRLF line endings are converted to LF.
In `src/host/rpc.ts`, every `sha256:` followed by 64 hex digits is also
replaced with `sha256:<derived>`, so the pinned digests do not feed into their
own hash. `SCHEMA_SOURCE_FILES` lists sources from `packages/protocol-types/src`
and from the state-app `control`, `host`, `session` and `workspace`
directories. Its paths are relative to `workers/state-app/test/`. Any change
to a listed file changes every operation's digest, even a comment-only change.

To print the current digests (the script writes no files):

```sh
pnpm --filter @circulusd/state-app generate:rpc-digests
# or
node workers/state-app/scripts/generate-rpc-digests.mjs
```

`workers/state-app/test/host.rpc.test.ts` recomputes every digest and compares
it with `rpc.ts`. It also compares `rpc.ts` with its own
`GOLDEN_SCHEMA_DIGESTS` table. A changed digest is also pinned in these places:

- `workers/state-app/src/host/rpc.ts` and
  `workers/state-app/test/host.rpc.test.ts`, for all 20 operations;
- other state-app tests, such as `test/host.ingress.test.ts` and
  `test/host.dispatch-start-ingress.test.ts`;
- the Go client constants `hostSchemaDigest` and
  `dispatchStartHostSchemaDigest` in `internal/stateappclient/client.go` and
  `blobHostSchemaDigest` in `blob.go`, plus Go tests such as
  `internal/stateappclient/client_test.go` and
  `internal/modelgateway/native_session_quota_test.go`;
- the cross-language fixtures
  `packages/protocol-types/fixtures/state-app-*.json`.

To find every pin, run `git grep` with the old hex value. The fixtures
`state-app-admission`, `state-app-blob-ingress`, `state-app-broker-ingress`,
`state-app-ingress` and `state-app-admission-plan` embed the digest inside
their request and response CBOR and MACs. A text replacement therefore leaves
them inconsistent: their CBOR and MAC fields must be recomputed. Only the
admission-plan fixture has an update switch (`UPDATE_ADMISSION_PLAN_FIXTURE`).

The `ingressSchemaDigest`, `dispatchStartIngressSchemaDigest` and
`blobIngressSchemaDigest` constants in the same Go files are separate values.
The script does not produce them.
