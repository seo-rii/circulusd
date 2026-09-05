# Local fuzz testing

The local runner discovers native Go `func Fuzz…(*testing.F)` targets from test
sources and TypeScript `*.fuzz.test.ts` files from workspace packages. It also
runs two Go/TypeScript CBOR differential properties. No services or credentials
are required. Install the pinned workspace dependencies with `pnpm install
--frozen-lockfile`; use the Go and Node versions declared by `go.mod` and the root
`package.json`.

```sh
pnpm fuzz:list
pnpm fuzz --duration 30s --workers 2 --seed 20260905 --num-runs 1000
```

The second command starts a detached local process and immediately prints its
PID, artifact directory, and `status.json` path. Jobs run sequentially; the Go
fuzzer uses at most `--workers` fuzz workers. Each Go target gets its own
`--duration` budget plus bounded build/cleanup time. TypeScript and differential
jobs each have a `--job-timeout` budget (300 seconds by default). A failed or
timed-out job stops the run. The launch command returning zero means the process
started; **the final result is `status.json` with `state: "finished"` and
`exit_code: 0`**. A timeout has exit code 124, and interruption has code 130.

Artifacts are retained under a unique `~/logs/circulusd-fuzz-*` directory with
mode 0700; logs and JSON results use 0600. `run.json` records selected targets and
generator options. `status.json` records each command, child PID, log path, elapsed
time, and exit code. Monitor status without streaming logs, and inspect bounded
log excerpts after completion. Send SIGTERM to the printed supervisor PID to
stop its active process group while retaining the final status.

## Select a smaller run

`--target` is a regular expression against names printed by `fuzz:list`.

```sh
pnpm fuzz --suite go --target 'FuzzDecodeCanonical$' --duration 10s
pnpm fuzz --suite typescript --target 'cbor.fuzz.test.ts$' --num-runs 2000
pnpm fuzz --suite differential --num-runs 5000 --seed 42
```

Go fuzz names are qualified as `./internal/canonical#FuzzDecodeCanonical`.
TypeScript names are repository-relative file paths. The two differential names
are `differential:value` and `differential:bytes`. Discovery is a bounded source
scan, not a build: Go still checks build tags and native target registration when
each selected target runs. Source under `testdata`, generated output, and
dependency directories is excluded.

| Option | Default | Scope |
| --- | --- | --- |
| `--suite` | `all` | `go`, `typescript`, `differential`, or `all` |
| `--target` | all discovered targets | target-name regular expression |
| `--duration` | `30s` | mutation time per native Go target; at most `60m` |
| `--workers` | `2` | Go fuzz workers and Vitest worker limit; range 1–64 |
| `--seed` | `20260905` | signed 32-bit fast-check seed |
| `--num-runs` | `1000` | runs per fast-check property |
| `--path` | none | fast-check minimized counterexample path |
| `--test-name` | all matching-file tests | Vitest property name pattern |
| `--job-timeout` | `300` | seconds per TS/differential job; range 11–3600 |

## Preserve and replay a failure

Go writes minimized failures to the owning package's
`testdata/fuzz/FuzzName/<hash>` and prints a replay command. Keep that file as a
regression input after confirming the issue. The runner does not delete the
corpus or change `GOCACHE`; Go also retains useful non-failing coverage inputs in
its normal fuzz cache. Ordinary `go test` executes seed and saved regression
inputs without starting mutation fuzzing.

```sh
go test ./internal/canonical -run='FuzzDecodeCanonical/<hash>'
```

Go's native mutation engine does not expose a stable user seed. `--seed` controls
fast-check only; reproduce Go failures with the saved corpus, not an assumed
random seed.

TypeScript properties read `CIRCULUSD_FUZZ_SEED`, `CIRCULUSD_FUZZ_RUNS`, and
`CIRCULUSD_FUZZ_PATH`; the runner supplies them. Fast-check failures print the
seed, minimized path, and counterexample into the retained Vitest log. Select a
single property when replaying, using its exact logged test name:

```sh
pnpm fuzz --suite typescript --target 'cbor.fuzz.test.ts$' \
  --test-name '<exact failing test name>' --seed 42 --path '<logged path>'
pnpm fuzz --suite differential --target '^differential:bytes$' \
  --seed 42 --path '<logged path>'
```

Differential failures additionally retain `value.json` or `bytes.json` with the
counterexample (raw input is hexadecimal), explicit codec limits, seed, path,
and error. Keep the same generator revision and pinned fast-check version when
using a seed/path; turn a confirmed counterexample into a permanent regression
test before changing the generator.

## What the differential properties assert

`testdata/cbor-differential/main.go` is a JSONL test probe that calls the real Go
`internal/canonical` codec. `fuzz.mjs` imports the real TypeScript codec directly
under Node 24 and keeps one Go subprocess alive for bounded requests. It is test
data, so normal `go test ./...` and production builds do not include the probe.

The value property generates bounded nulls, booleans, safe integers, Unicode
text, byte strings, arrays, and maps. It includes normalization cases, BOM text,
special object keys, and integer width boundaries. Both implementations must
agree on acceptance and exact canonical bytes. Generous-limit generated values
must be accepted, preventing a pair of rejecting implementations from passing.

The byte property combines arbitrary bytes, malformed boundary seeds, and
mutations of valid encodings (flip, truncate, append, or retain). Both decoders
must agree on acceptance; accepted bytes must survive decode/encode unchanged.
Both properties pass identical explicit `maxBytes`, `maxDepth`, and `maxItems`
limits, including zero and restrictive limits, instead of comparing differing
language defaults. The runner retains any mismatch for reduction and replay.

The standalone harness can be invoked with `node
testdata/cbor-differential/fuzz.mjs --case value --num-runs 1000 --seed 42`; it
builds the probe into its private artifact directory when `--go-probe` is absent.
The `pnpm fuzz` wrapper is preferred because it also captures logs from the start,
runs in the background, and records process exit status.
