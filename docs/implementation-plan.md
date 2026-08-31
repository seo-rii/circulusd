# Implementation plan

Status: Unit 10 planned and accepted as the next implementation unit

Updated: 2026-08-31

This document turns the normative phase roadmap in `SPEC.md` §51 into small,
reviewable repository work units. `SPEC.md` remains the product contract;
`docs/acceptance.md` records evidence that has actually run. A completed work
unit is not a conformance `PASS` unless the acceptance ledger records the exact
required external evidence.

## Current sequence

| Unit | State | Scope |
|---|---|---|
| 7 | complete | Reference Session dispatch claims, subordinate effect ledgers, model/MCP consumers, and in-process recovery fault tests |
| 8 | complete | Fail-closed production bootstrap boundary and separate diagnostic-only development daemon |
| 9 | complete | Credentialed daemon UDS roles, complete sandbox launch binding, diagnostic shells, and identity-bound doctor evidence |
| 10 | planned | Phase 0A workerd resource enforcement, observation, recycle, and reconstruction qualification |

Unit 11 follows Unit 10 with the remaining Phase 0B real-process celld
durability and API/SSE recovery boundary. Phase 1A is then split into additional
units for the private workload composition and the NsJail single-node vertical
slice. Those later units are ordered but are not yet detailed here; their exact
cut lines must use the evidence produced by Units 10 and 11.

## Unit 10: Phase 0A workerd resource qualification

### Outcome

Complete the still-`NOT_RUN` Phase 0A resource checks against the release-pinned
stock workerd process:

- bounded CPU execution and worker-failure handling;
- cgroup-backed RSS observation and a cold-start benchmark;
- pressure/OOM-driven shard drain and recycle;
- Dynamic Worker eviction and reconstruction from the same committed
  checkpoint and content-addressed runtime identity;
- whole-shard kill/restart with stale placement activity rejected.

This is a Phase 0A Go/No-Go result, not production admission. The Phase 0A
model and tool services remain deterministic mocks as permitted by `SPEC.md`
§51.1, and their evidence remains `reference-only`/`mock`.

### Existing baseline

The implementation starts from these already-tested components:

- `internal/agent.Manager` serializes placement metadata, coalesces compatible
  cold starts, fences placement generations, drains pressure/expired shards,
  and coordinates concurrent shutdown;
- `internal/agent.WorkerdProcessLauncher` pins a verified executable snapshot,
  gates readiness, bounds output, and coordinates generation replacement and
  cleanup;
- the Linux cgroup controller creates one leaf per shard generation, writes and
  reads back CPU/memory/PID limits, attaches the child atomically, and performs
  generation-fenced `cgroup.kill` cleanup;
- `internal/conformance/workerd` runs the real Pi adapter and Dynamic Worker
  fixture but still reports `workerd.cpu-limit`, `workerd.rss-cold-start`, and
  `workerd.shard-recycle` as `NOT_RUN`;
- `cmd/agentd` is still a diagnostic-only control shell and does not compose
  any of the preceding operational components.

The manager and low-level process launcher are not yet one production
composition. Their distinct generation domains and readiness contracts must be
made explicit before they are joined.

### Cut line

Unit 10 may compose `internal/agent` components inside the external
qualification harness. It does not:

- add an agent workload RPC or a public listener;
- wire `platformd` Session admission to `agentd`;
- change `cmd/agentd` from its diagnostic-only capability claims;
- claim a real model, MCP broker, celld durability, or production state
  authority;
- add NsJail, Docker, Firecracker, native command execution, or outer workerd
  isolation;
- mark any production install profile qualified;
- choose permanent resident-session, RSS, or latency defaults from one host's
  measurements.

The current same-identity delegated cgroup mechanism proves mechanical limit
application, observation, and cleanup. It is not a security boundary against a
fully compromised same-UID workerd process. A production workload composition
must separately close cgroup-control authority isolation or place workerd in a
stronger outer boundary. Unit 10 must keep `AdmissionReady=false` while that
gap, the private workload authority, or any required production dependency is
open.

### Lifecycle and generation model

The manager's Session `placementGeneration` and the process launcher's shard
generation are different values and must never be substituted for one another:

- `placementGeneration` comes from the authoritative Session state and fences
  late Worker requests after placement changes;
- `shardGeneration` identifies one OS process/cgroup incarnation owned by the
  current agent runtime;
- an observation or exit callback carries the shard ID, shard generation, and
  pinned cgroup identity; it cannot drain or stop a replacement generation;
- a reconstructed Dynamic Worker keeps its content-addressed Worker ID but
  receives only the current placement authority.

The required process lifecycle is:

```text
allocated -> starting -> ready -> draining -> stopping -> stopped
                |          |          |
                +----------+----------+-> failed cleanup -> retry cleanup
```

`ready` is published only after the cgroup limits are read back, the process is
atomically attached, and the SessionHost readiness identity matches the
expected release/runtime inputs. Entering `draining` closes admission
immediately. Ownership is retained until the process is gone, the cgroup is
unpopulated and removed, and every borrowed descriptor is closed.

### Work packages and TDD order

Every behavioral slice follows strict RED → GREEN → race/shuffle verification.
Tests that need a real binary or cgroup are external conformance tests and must
not be replaced with a fake to obtain `PASS`.

#### U10.1 — Join manager and launcher contracts

1. Add failing contract tests for distinct placement/shard generations,
   immutable launch arguments, readiness identity mismatch, and cleanup of a
   process that becomes invalid before publication.
2. Add the narrow adapter that translates a manager-owned `ShardSpec` into one
   fixed launcher request. Callers cannot supply raw workerd arguments,
   environment, executable path, or cgroup controls.
3. Keep construction release-bound: the opened workerd binary, SessionHost
   artifact, compatibility inputs, limits, and explicit child environment are
   frozen before any shard starts.
4. Verify that a stale readiness, exit, or stop completion cannot publish or
   remove a newer shard generation.

#### U10.2 — Add generation-bound resource observation

1. Add failing parser and race tests for bounded reads of `memory.current`,
   `memory.events`, `cpu.stat`, `pids.current`, and the pinned cgroup identity.
2. Return immutable observations that distinguish ordinary RSS, CPU throttling,
   OOM/oom-kill counters, and unavailable/malformed kernel evidence.
3. Reject stale/replaced cgroup observations and never read an unbounded control
   file.
4. Feed observations into `Manager.Observe` without holding manager or cgroup
   locks across filesystem I/O or callbacks.

#### U10.3 — Make recycle and reconstruction deterministic

1. Add failing tests for concurrent pressure reports, natural process exit,
   explicit release, generation replacement, and daemon shutdown selecting one
   cleanup owner.
2. A pressure/OOM transition marks the shard draining once, excludes it from
   admission, and coalesces stop/cgroup cleanup. Independent shards continue to
   make progress.
3. Exercise Dynamic Worker eviction in the pinned Loader fixture and prove that
   initialization reconstructs from the committed checkpoint without shared
   global or lifecycle state.
4. Kill the complete workerd shard, rotate placement authority, reconstruct the
   same content-addressed Worker identity, and prove that late activity carrying
   the previous placement generation is rejected.

#### U10.4 — Replace the three resource `NOT_RUN` probes

1. Extend the explicit external workerd fixture with a provisioned, empty,
   delegated cgroup-v2 root. Absence of the pinned binary or usable delegation
   yields `UNAVAILABLE`/`NOT_RUN` with a stable reason, never a skip interpreted
   as success.
2. `workerd.cpu-limit` must observe both the configured shard quota and bounded
   handling of an infinite-JS/worker failure in stock workerd.
3. `workerd.rss-cold-start` must record repeated cold-start latency and cgroup
   memory observations in a versioned canonical artifact. `PASS` means the
   measurement completed with valid identity and bounds; it does not freeze a
   product performance threshold.
4. `workerd.shard-recycle` must cause real pressure or a real process kill,
   observe drain/cleanup, and reconstruct before it can pass.
5. Bind every result to the workerd binary/version, compatibility environment,
   host/kernel/architecture, probe inventory, and a digest reference to the
   resource-observation artifact. Synthetic model/tool evidence stays marked
   mock and cannot qualify a production profile.

#### U10.5 — Close the unit without widening readiness

1. Run focused race/shuffle tests for `internal/agent`, the workerd conformance
   harness, and `cmd/agentd`.
2. Run the complete Go race/vet and TypeScript check/lint/unit gates.
3. Run the real external fixture on a provisioned host and retain its report;
   if the host boundary is unavailable, Unit 10 remains incomplete.
4. Update `docs/acceptance.md` from the retained evidence. Do not infer an
   aggregate §53 `PASS` or change daemon capabilities from unit tests.

### Concurrency invariants

- One shard generation has at most one start operation and one cleanup owner.
- Same-generation waiters share a result; canceling one waiter does not cancel
  work still owned by other waiters.
- Independent shard starts, observations, and cleanup operations can progress
  concurrently.
- No manager mutex is held while launching, probing readiness, reading cgroup
  files, waiting for process exit, or draining a cgroup.
- Replacement waits for uncertain cleanup of the prior generation; timeout or
  cancellation cannot silently transfer ownership.
- Drain admission closes before the stop begins, and no observation from the
  drained generation can affect its replacement.
- Shutdown fences new admission first, joins every in-flight start/stop, and
  returns reproducible cleanup errors to concurrent/repeated callers.
- Test callbacks reached from product goroutines report through channels or
  returned errors; they never call `FailNow` methods.

### Required evidence and exit criteria

Unit 10 is complete only when all of the following are true:

- host-independent tests pass under `go test -race` with shuffled/repeated
  lifecycle cases;
- the pinned stock workerd external fixture reports non-mock `PASS` for
  `workerd.cpu-limit`, `workerd.rss-cold-start`, and
  `workerd.shard-recycle`;
- Dynamic Worker and whole-shard reconstruction both preserve durable identity
  and reject stale placement authority;
- no child process, process group, cgroup, goroutine, or file descriptor is
  left owned after success, failure, cancellation, or concurrent shutdown;
- the benchmark artifact and conformance report are canonical, bounded, and
  digest-linked;
- `cmd/agentd` still reports operational capabilities as `NOT_WIRED`, and
  production admission/readiness remains false;
- `docs/acceptance.md` records exactly what ran, including any environment
  limitation, without promoting mock/reference evidence.

## Commit boundaries

Implementation commits remain independently reviewable and revertible:

1. manager/launcher generation and readiness contract;
2. cgroup observation and accounting;
3. recycle/reconstruction lifecycle;
4. external conformance and canonical evidence artifact;
5. acceptance and operator documentation.

Each implementation commit includes its preceding failing tests and the green
result for that one work package. Cross-package changes are combined only when
splitting them would leave an invalid protocol or lifecycle contract.
