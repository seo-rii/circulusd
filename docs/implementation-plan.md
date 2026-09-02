# Implementation plan

Status: Unit 10 external resource gate executes green on a provisioned host. The
cpuMs/isolate-enforcement blocker is resolved by re-scope (2026-09-02): the
certified resource safety boundary is the kernel-enforced one (cgroup
`cpu.max`/`memory.max` + pidfd whole-shard kill). The live probe runner is built
and `TestStockWorkerdResourceQualification` reaches its achievable bar on a
provisioned WSL2 cgroup-v2 host against the pinned workerd — four required PASS
(cpu-limit kernel throttle, rss-cold-start, shard-pressure-recycle OOM,
shard-kill-reconstruction) plus a recorded honest FAIL
(dynamic-worker-reconstruction) from one bound envelope. `AdmissionReady` stays
false; the acceptance ledger and `docs/unit10-operator.md` record it without
promoting §53. Remaining: a production install-profile run (this is a
development host) and the final acceptance close.

Updated: 2026-09-02

This document turns the normative phase roadmap in `SPEC.md` §51 into small,
reviewable repository work units. `SPEC.md` remains the product contract;
`docs/acceptance.md` records evidence that has actually run. A completed work
unit is not a conformance `PASS` unless the acceptance ledger records the exact
required external evidence.

The machine-transfer resume checkpoint for the current unit is
[`docs/unit10-handoff.md`](unit10-handoff.md).

## Current sequence

| Unit | State | Scope |
|---|---|---|
| 7 | complete | Reference Session dispatch claims, subordinate effect ledgers, model/MCP consumers, and in-process recovery fault tests |
| 8 | complete | Fail-closed production bootstrap boundary and separate diagnostic-only development daemon |
| 9 | complete | Credentialed daemon UDS roles, complete sandbox launch binding, diagnostic shells, and identity-bound doctor evidence |
| 10 | in progress | Phase 0A workerd resource enforcement, observation, recycle, and reconstruction qualification |
| 11 | queued | Phase 0B real-process celld Session/effect/placement authority and kill/restart fault matrix |
| 12 | queued | Durable public idempotency and API/SSE disconnect/replay recovery |

After Unit 12, the private `platformd`-to-`agentd` workload composition and the
Phase 1A NsJail single-node vertical slice receive separate work-unit plans.
Their exact cut lines must use the evidence produced by Units 10–12; they are
not silently included in Unit 10.

## Unit 10: Phase 0A workerd resource qualification

### Implementation progress

- 2026-08-31: the finite cgroup-v2 CPU contract migrated from integer
  `CPUCores` multiplication to bounded `CPUMax{QuotaMicros, PeriodMicros}` with
  direct decimal serialization and exact readback rejection tests. Focused and
  full `internal/agent` race tests pass. This is a host-independent contract
  result only and does not promote an external qualification status.
- 2026-08-31: the versioned 64 KiB qualification-input parser now accepts only
  bounded operator paths, architecture, finite limits, timeouts, and sample
  count. Strict JSON tests reject duplicate/unknown members and any
  caller-controlled digest, version, argv, or child environment. Package race
  tests and vet pass; the external runner remains unimplemented.
- 2026-08-31: each workerd release artifact now pins its archive digest,
  `gzip-single-file-v1` extraction recipe, and extracted executable digest.
  Artifact and manifest signatures cover both new provenance fields, and the
  repository pins were checked against the official x86_64 and aarch64 assets.
  Release/package race tests, the API schema contract, and the complete Go test
  suite pass. Archive extraction remains owned by the separate release/install
  workflow, and runner composition remains; release-bound installed-executable
  verification is recorded below.
- 2026-08-31: the resource fixture now renders only the pinned
  `serve --experimental -I<fixture> <fixture>/phase0-resource.capnp` argument
  vector from a short canonical absolute directory. Golden tests reject unsafe
  paths and prove each call returns an unaliased fixed vector. Pinned-binary CLI
  preflight and persistent socket materialization remain to be implemented.
- 2026-09-01: Manager now creates one boot-scoped process identity and consumes
  a fresh typed shard generation for every OS start attempt. Manager-owned
  launch operations share one immutable result while caller cancellation only
  removes that caller; the last waiter requests cancellation without releasing
  cleanup ownership. Process `ID` and `Stop` callbacks run outside the Manager
  mutex, typed-nil processes fail closed, and generation-keyed stop epochs
  survive caller cancellation. Shutdown starts independent cleanup in parallel,
  joins results deterministically, retries uncertain cleanup, and fences
  replacement until the prior generation is quiescent. Repeated package
  race/shuffle tests pass. At this checkpoint, the low-level workerd launcher
  generation rename and fixed-configuration Manager adapter remained; both are
  recorded as complete below.
- 2026-09-01: the qualification release resolver now validates the manifest
  and configured trust policy for every release status, requires promotion
  verification for candidate/production releases, selects exactly one workerd
  artifact for the requested architecture, and derives all executable identity
  from its extraction provenance. It opens the installed executable through a
  no-symlink `openat2` walk, rejects unsafe type/mode/size or digest mismatch,
  and retains only a sealed memfd snapshot. Missing artifacts and unavailable
  host features remain distinct from malformed, permission, and identity
  failures. Focused race tests, the complete conformance package, and vet pass;
  runner launch composition and evidence serialization remain unimplemented.
- 2026-09-01: release-owned executable snapshots now reopen independent,
  read-only, close-on-exec descriptors while holding the owner lifetime lock.
  Only a genuinely closed owner reports `ReleaseClosed`; missing or unsupported
  proc descriptor access reports host unavailability, while permission and
  other syscall failures remain invalid qualification state. Concurrent clone,
  independent offset/lifetime, seal, and error-classification race tests pass.
- 2026-09-01: every low-level workerd launch, readiness identity, cgroup leaf,
  and returned handle now carries the named `ShardGeneration`; the launcher no
  longer exposes or accepts a placement generation. Each cgroup lease captures
  bounded canonical `memory.events` and `cpu.stat` baselines before process
  attachment, then returns immutable `memory.current`, cumulative/delta event
  and CPU counters, `pids.current`, and exact finite `cpu.max` samples from its
  pinned directory descriptor. Sampling verifies dev/inode before and after
  reads and poisons admission on replacement. A borrow/quiescence gate keeps
  mutexes out of cgroup I/O while preventing destruction or a queued integrity
  writer from racing an active descriptor borrower. Focused and complete
  repeated race tests pass. The fixed-configuration adapter and process-RSS
  primitive are recorded below; serialized observation sequence and Manager
  delivery remain.
- 2026-09-01: the Linux Manager adapter now binds every start to one
  construction-time snapshot of the release-derived workerd argument vector,
  validates the Manager-owned process/shard generation boundary, and gives
  each concurrent low-level `Ensure` call an unaliased copy. It forwards no
  placement generation or caller process arguments, rejects nil launchers and
  handles, and does not enter the low-level launcher for an already-canceled
  caller. Repeated adapter and complete agent race/shuffle tests pass. Full
  tuple validation is recorded by the later identity-boundary item; serialized
  observation and Manager delivery remain.
- 2026-09-01: Linux process observation now captures an immutable
  `(pid, startTicks)` token from bounded canonical `/proc/<pid>/stat` input and
  derives RSS bytes from bounded `statm` input with page-size and multiplication
  overflow checks. Each sample reads `stat`, `statm`, then `stat` again through
  one pinned proc directory descriptor and rejects PID reuse as a distinct stale
  identity outcome. Parser, injected-reader concurrency, and live current-process
  tests pass repeatedly under the race detector. pidfd ownership, launcher
  attachment, serialized observation sequencing, and Manager delivery remain.
- 2026-09-01: a successful Manager start now remains an immutable pending
  result until a still-valid waiter atomically adopts both the process and its
  first placement under the Manager lock. If the final claim is canceled, or
  shutdown wins first, ownership moves to one cached generation-keyed stop
  epoch; a late waiter joins that epoch instead of stopping the process twice.
  Failed and canceled starts reserve their logical `ShardID` for retry while
  consuming a fresh `ShardGeneration`; independent capacity slots still receive
  distinct shard IDs. Deterministic post-completion cancellation, late-claim,
  retry, shutdown, and repeated race/shuffle tests pass.
- 2026-09-01: the complete process identity tuple now survives the static
  `ShardProcess` boundary and is checked by the adapter and Manager before a
  placement can publish. Mismatched non-nil processes transfer to cleanup.
  Ensure, readiness, starter commands, handles, cgroup leases/leaves/samples,
  current/history keys, and stop ownership carry the same boot-scoped agent ID.
  A low-level launcher binds atomically to its first valid agent instance for
  its entire lifetime. It rechecks the cached cancellation signal inside the
  binding critical section, so a request canceled while waiting for that lock
  cannot reserve the lifetime or create pending work. Another boot fails before
  readiness, process, or cgroup callbacks, so history cannot accumulate across
  boots. Exact mismatch, cancellation-window, lock-free callback, first-bind
  race, and cgroup integration tests pass under full repository race and vet
  gates.
- 2026-09-01: the low-level cgroup error classifier now makes permission,
  privilege, read-only, and mixed provisioning failures contract failures
  distinct from the genuine-absence sentinel. This is reference-only
  classification: operation-scoped host absence versus post-provision path
  loss and U10.4 external status mapping remain. Constructor,
  direct-classifier, mixed-error, availability, agent, and conformance race
  tests pass.
- 2026-09-01: every cgroup syscall classification now names either delegated-
  root discovery or an operation on an already provisioned boundary. Only a
  discovery error tree made entirely of genuine absence/unsupported errno
  leaves is unavailable; mkdir, open, read, write, sample, destroy, and close
  failures after construction fail the contract. A missing required controller
  is distinct from an available controller the operator failed to enable, and
  provisioning or contradictory states dominate absence. Scoped classifier,
  controller matrix, real prepare-path, complete agent race, repository test,
  and vet gates pass. U10.4 external result mapping remains.
- 2026-09-01: Manager cleanup now distinguishes retryable ownership from a
  terminal released-or-quarantined result through
  `ErrTerminalShardCleanup`. It classifies returned errors outside the Manager
  mutex, gives the next explicit Release, Acquire, or Shutdown caller one fresh
  shared epoch after an unknown retryable error, and caches terminal results
  without another `Stop` call. Existing waiters retain their immutable epoch
  result and caller cancellation affects only the wait. Workerd marks destroyed
  cgroup cleanup failures and stale exact handles terminal, while process-group
  timeouts and pre-removal cgroup failures remain retryable. Retry sharing,
  cancellation, reentrant classification, mixed parallel shutdown, stale-
  handle, removal, poison, and terminal-close race tests pass.
- 2026-09-01: the Manager observation endpoint now validates the exact
  `(agentInstanceID, shardID, shardGeneration)` before a generation-local,
  strictly increasing `observationSequence`, and performs neither state
  mutation nor stop scheduling for invalid, missing, stale, duplicate, or
  decreasing input. Its stable classification order is malformed, closed
  Manager, wrong agent boot, missing shard, wrong shard generation, then stale
  sequence, so another boot cannot probe shard existence. A generation-scoped
  live-shard state starts with no accepted sequence; a tuple-consistent
  replacement-state test accepts its first nonzero value independently of the
  prior state. `ObservedAt` remains required diagnostic metadata but no longer
  drives lifetime or drain. The current lifetime path still trusts
  composition-supplied `PlacementRequest.Now`; composition-owned clock wiring
  remains open and is not claimed by this result. Simultaneous equal-sequence
  delivery linearizes to one winner without loser-payload mutation, draining
  is irreversible, observation-triggered Stop callbacks may reenter Manager
  without its mutex held, and sequence wrap is rejected. Focused 50-pass and
  complete agent 10-pass race/shuffle gates, repository tests, and vet pass.
  The serialized producer, process-token attachment, and lifecycle delivery
  remain.
- 2026-09-01: the Linux process-identity owner primitive now opens a pidfd
  before publishing an immutable `(pid,startTicks)` token and keeps the
  existing before/after `/proc` start-time checks around every RSS sample.
  Only an error tree made entirely of `ENOSYS` leaves is classified as pidfd
  unavailable; permission, policy, stale-process, invalid-operation, and mixed
  failures remain fail-closed. A borrow/quiescence gate rejects new samples
  after closing begins, waits for active samples without holding its mutex,
  closes the pidfd exactly once, and replays one cached terminal close error to
  concurrent callers without retrying a possibly reused descriptor. Focused
  100-pass race/shuffle and complete agent race gates pass. This is an
  unattached primitive: launcher capture/order, stop ownership, and observer
  lifecycle integration remain and no admission or external PASS is claimed.
- 2026-09-01: the low-level launcher now captures one pidfd-owning process
  identity for every successful OS start, after `starter.Start` returns and
  before the exit waiter, readiness probe, or handle publication can act on
  that process. The identity capturer is a required constructor input;
  production paths bind the real /proc-and-pidfd capture while tests inject a
  fake built on the existing proc-reader/pidfd fakes. Capture failure fails
  the launch closed through exactly one graceful process/cgroup cleanup owner,
  calls no readiness callback, publishes no handle, and preserves the
  pidfd-unsupported classification for later host-availability mapping. The
  exact owner is stored immutably on the instance; identity is never
  reconstructed from a later numeric PID lookup, and a capture-time token
  rejects PID reuse as stale. Natural exit, readiness failure, replacement,
  handle stop, and launcher close each close the owner exactly once, only
  after the process group is gone or the cgroup generation is destroyed and
  after sample-borrow quiescence; a retryable stop timeout or pre-removal
  cgroup failure retains the open owner for the next cleanup epoch. A pidfd
  close failure is terminal: it is cached on the stop epoch, replayed without
  another close syscall, and surfaces in the launcher close result. No
  launcher or instance mutex is held across capture, proc I/O, borrow
  quiescence, close, readiness callbacks, or cleanup waits, and an old
  generation's owner cannot sample, close, or otherwise act on its
  replacement. Verification on this Windows transfer host is limited to
  cross-compiled `GOOS=linux go vet ./internal/agent`, gofmt on CR-stripped
  copies, and `git diff --check`; the focused race/shuffle gates, the full
  repository test run, and repo-wide vet could not execute here (no Linux
  kernel boundary, and the host user disk quota blocked repo-wide module
  downloads) and remain required on a Linux host before any further status
  claim.
- 2026-09-01: the transfer host gained a WSL2 Ubuntu boundary, closing the
  previous entry's deferred-verification caveat. The launcher-attachment
  gates now pass on Linux: 50-repetition identity-focused and 10-repetition
  complete `internal/agent` race/shuffle runs, package vet, repo-wide
  cross-compiled vet, and the complete `go test ./...` suite from a native
  ext4 clone of the attachment commit. Runs launched from the drvfs-mounted
  CRLF working tree fail only on checkout/mount artifacts (CRLF fixture
  digests in the workerd conformance harness and drvfs parent owner/mode
  checks in dependency evidence tests), so native-clone runs are the
  canonical full-suite evidence on this machine.
- 2026-09-01: each published shard generation now owns exactly one serialized
  observer. Every round obtains a complete pinned-identity cgroup sample and
  an exact pidfd-verified process-RSS sample before allocating the next
  strictly increasing generation-local sequence, compares cumulative
  `memory.events` deltas against that exact generation's baseline for
  OOM/pressure classification, and delivers an immutable `ShardObservation`
  carrying the full boot/shard/generation tuple to a required
  `WorkerdObservationSink` with no launcher, instance, cgroup, or
  process-identity locks held; `Manager` satisfies the sink statically. The
  sequence allocator fails closed before `uint64` exhaustion, cancellation
  that wins after sample I/O but before delivery suppresses the sample, and
  sample, sink, or identity failures end only the producer, never the shard.
  Stop epochs cancel the observer without joining it, so a sink that
  synchronously stops its own shard completes without deadlock — a deliberate
  join-before-epoch mutation reproduces that deadlock and fails the self-stop
  test — while launcher close performs the final observer join before
  releasing the executable, and failed launches never start a producer.
  Focused observer race runs, 50-repetition focused and 10-repetition
  complete agent race/shuffle gates, and package vet pass on the WSL
  boundary. Composition of the sink into a live Manager and evidence-artifact
  status mapping remain with U10.4.
- 2026-09-01: the workerd probe inventory and every doctor install profile
  migrated from the ambiguous `workerd.shard-recycle` result to the three
  distinct reconstruction results. Each of
  `workerd.dynamic-worker-reconstruction`, `workerd.shard-kill-reconstruction`,
  and `workerd.shard-pressure-recycle` is a required non-mock external
  result with its own NOT_RUN reason and no runnable fixture substitute;
  contract tests reject a shared reason, a runnable entrypoint for any of the
  three, or the old name reappearing, and the runnable `workerd.dynamic-worker`
  probe cannot stand in for the reconstruction result. Conformance and doctor
  package tests pass; the external gate itself remains NOT_RUN until U10.4.
- 2026-09-01: the deterministic reconstruction checkpoint store now lives in
  the runner process, outside workerd. It records canonical checkpoint bytes
  and their `sha256:` digest per content-addressed Worker ID, returns an
  acknowledgement only for durably recorded state, replaces acknowledged
  state in commit order under one serialized sequence that fails closed
  before `uint64` exhaustion, reverifies the digest on every reload, returns
  only unaliased payload copies, and never serves unacknowledged, foreign-
  worker, or foreign-store state. `requireAcknowledged` gates destructive
  fault injection on the exact acknowledged digest, so a probe cannot inject
  a fault before its checkpoint commit is acknowledged. Focused 20-repetition
  race/shuffle tests pass on the WSL boundary. This store is reference test
  infrastructure for the three reconstruction probes, not durable production
  state.
- 2026-09-01: the Dynamic Worker fixture now boots through a handwritten
  `phase0-worker-entry.mjs` main module that keeps the pinned Pi worker
  bundle byte-identical and owns the initialization-instance identity in
  module-local state. The state transitions from null to one 128-bit
  identity at most once per module-graph initialization, so a changed value
  proves a demonstrably new initialization for the same content-addressed
  Worker ID; stock workerd forbids drawing entropy in module global scope,
  so the single `crypto.getRandomValues` draw executes on the first handler
  call into each instance. The session host cannot inject, rotate, or
  synthesize the identity, and the runnable `dynamicWorker` probe now proves
  pre-fault stability across two calls, the identity format, and
  distinctness across sibling isolates. The capnp template, embedded-fixture
  set, environment digest, and materialization all bind the new module.
  Contract tests and the complete conformance package pass, including the
  live `TestStockWorkerdFixture` gate against the release-pinned
  workerd 1.20260825.1 binary (archive and extracted digests verified
  against the manifest) on the WSL boundary. The post-fault
  initialization-instance change remains owned by the U10.4 external runner,
  which launches `workerd serve` without `--predictable`.

- 2026-09-01: the persistent private-socket qualification fixture exists:
  `phase0-resource.capnp.tmpl` serves the new `session-host-resource.mjs`
  over one directory-derived Unix socket, and `phase0-resource-entry.mjs`
  carries the qualification-only Dynamic Worker routes (module-local
  initialization instance, unbounded `/spin`, checkpointable retained state)
  while forwarding everything else to the byte-identical pinned Pi bundle.
  The materializer renders the fixed compiled compatibility inputs, binds
  the unrendered SessionHost artifact digest and rendered configuration
  digest into the readiness envelope, and rejects unrendered placeholders;
  the bounded `workerd test` fixture provably gains no spin or allocate
  route. Live probing against the pinned binary verified socket readiness,
  nonce rejection, worker state init/read/load, and produced a decisive
  finding: stock workerd 1.20260825.1 parses `limits.cpuMs` for dynamic
  Workers (the `ResourceLimits{cpuMs, subRequests}` wrapper exists) but
  never enforces it — synchronous, microtask-yielding, and timer-yielding
  infinite invocations all ran unbounded past twentyfold the limit and
  starved the shard's request handling. Per this plan's own predicates,
  `workerd.cpu-limit` (its Loader-failure half) and
  `workerd.dynamic-worker-reconstruction` (its destructive fault trigger)
  cannot reach `PASS` on this release pin; the runner must record that
  failure honestly and the probes must deterministically recycle the
  starved shard.
- 2026-09-01: the decision-independent U10.4 spine is implemented and
  host-independently tested. The launcher gained a pre-opened `Executable`
  handoff (sealing and digest-checking a supplied snapshot without path
  authority), `Handle.KillProcessInstance` (pidfd SIGKILL, borrow-gated), and
  `Handle.SampleResources` (exported pinned-cgroup + pidfd-RSS sample). The
  status layer encodes the fixed classification table (FAIL dominates a joined
  UNAVAILABLE) and the component PASS predicate (external, non-mock, run-bound
  binary/environment/observation digests), and the run-level evaluator
  requires all five distinct results from one shared envelope while still
  reporting an honest not-all-pass for a real component FAIL. The evidence
  layer validates and deterministically CBOR-encodes the versioned observation
  envelope through `internal/canonical` and retains it atomically with a
  same-directory 0600 temp file, fsync, no-clobber `renameat2`/`linkat`,
  directory fsync, and read-back digest revalidation into a caller-owned
  private directory. A follow-up experiment confirmed no stock-workerd
  in-isolate fault destroys a Worker Loader isolate, so
  `dynamic-worker-reconstruction` is blocked independently of `cpuMs`. Full
  repository tests, package race, and vet pass on the WSL boundary.
- 2026-09-01: `internal/agent` now exports `ProbeWorkerdCgroupProvisioning`,
  the qualification runner's cgroup preflight. It reuses the controller
  construction contract to validate an operator-provisioned delegated
  cgroup-v2 root without launching a process, captures the pinned root
  device/inode and enabled controllers for evidence, and separates a genuine
  host-unavailable boundary (UNAVAILABLE) from an ownership/mode/emptiness/
  controller contract violation (FAIL). Exercising it against a real
  provisioned cgroup surfaced and fixed a latent bug in the shared
  `inspectRoot` emptiness scan — `DirEntry.Info` lstat'd a working-directory-
  relative path built from the directory File's synthetic name, ENOENTing on
  every real cgroup entry and mislabeling a valid root as unavailable; the
  scan now resolves entry type via `fstatat` against the pinned directory FD.
  This is the first time the real (non-fake) cgroup discovery path ran on a
  live cgroup-v2 host. Verified `Satisfied` against a provisioned WSL2 root
  with real device/inode and cpu/memory/pids enabled; fake-backend
  classification cases and full agent race/shuffle and vet pass.
- 2026-09-02: the deferred cpuMs/isolate-enforcement decision is resolved by
  re-scope, not re-pin. The runner now splits the five results into four
  required PASS (`cpu-limit` re-scoped to the kernel cgroup `cpu.max` throttle +
  supervisor-observed starvation recycle, `rss-cold-start`,
  `shard-pressure-recycle`, `shard-kill-reconstruction`) and one recorded honest
  FAIL (`dynamic-worker-reconstruction`, per-isolate). `resource_status.go` now
  carries `requiredResourceQualificationComponents` and
  `recordedResourceQualificationComponents`; `evaluateResourceQualificationRun`
  qualifies only when the four required pass one shared envelope and every
  recorded component carries a FAIL, and it raises a framing error if a recorded
  component reports PASS (the pinned workerd cannot legitimately produce it) —
  proven by `TestEvaluateResourceQualificationRunRequiresFourPassPlusRecordedFail`.
  The `cpu-limit` and `dynamic-worker-reconstruction` probe NOT_RUN reasons were
  updated to the kernel boundary and the recorded-gap wording; the environment
  digest rebinds automatically. The certified safety boundary is the
  kernel-enforced one; `AdmissionReady` stays false while the residual
  per-isolate gap stands. Package vet, the resource-status/probe-inventory/
  environment-digest tests, and the full doctor package pass on the WSL
  boundary.

### Outcome

Complete the Phase 0A process, cgroup, and Worker Loader gates against the
release-pinned stock workerd process. Unit 10 produces five distinct external
results. Live qualification of the pinned `workerd 1.20260825.1` established
that its in-isolate limits are advisory only — `limits.cpuMs` is parsed but not
enforced, and no reachable in-isolate fault destroys a Worker Loader isolate
(see U10.4 and `docs/unit10-handoff.md`). The certified resource safety
boundary is therefore the kernel-enforced one — cgroup-v2 `cpu.max` throttling,
`memory.max` OOM, and pidfd whole-shard `SIGKILL` with reconstruction — which
holds against a fully uncooperative isolate that a cooperative in-isolate soft
limit cannot. Four results are required to PASS at that boundary:

- `workerd.cpu-limit`: exact cgroup `cpu.max` readback plus an observed
  `cpu.stat` throttling increase under a runaway Worker, escalated by
  supervisor-observed starvation to a deterministic whole-shard kill/recycle.
  The in-isolate `cpuMs` non-enforcement is recorded as an evidence-bound
  finding, not silently dropped;
- `workerd.rss-cold-start`: process RSS, cgroup memory attribution, and repeated
  cold-start measurements;
- `workerd.shard-pressure-recycle`: real cgroup pressure/OOM, drain, cleanup,
  and reconstruction;
- `workerd.shard-kill-reconstruction`: explicit whole-shard `SIGKILL`, cleanup,
  and reconstruction.

The fifth result, `workerd.dynamic-worker-reconstruction` (a destructive
per-isolate Dynamic Worker failure followed by a demonstrably new
initialization for the same content-addressed Worker ID), cannot PASS on this
pin: stock workerd never reconstructs a faulted isolate. It is demoted from the
required set to a **recorded honest FAIL** — a documented residual gap the
runner must always record and never report as PASS or skip. The safety-relevant
recovery of a wedged worker is delivered at the shard level by the
pressure-recycle and kill-reconstruction results, not per isolate. Unit 10
keeps `AdmissionReady=false` while that gap stands; closing it requires a
re-pinned or rebuilt workerd that enforces per-isolate limits in serve mode.

The old ambiguous `workerd.shard-recycle` result is replaced by the two
shard-level reconstruction results when the profile and probe inventory
migrate. Neither one may substitute for the other.

This is a Phase 0A Go/No-Go result, not production admission. The Phase 0A
model, tool, checkpoint store, and placement source remain deterministic test
infrastructure as permitted by `SPEC.md` §51.1. Their evidence remains
`reference-only`/`mock`. The five named results claim only the real
process/cgroup/Loader mechanics they directly observe; they do not turn those
fixture dependencies into durable or production evidence.

### Current implemented baseline

The implementation starts from these already-tested components:

- `internal/agent.Manager` serializes placement metadata, coalesces compatible
  cold starts, fences caller-supplied placement generations, drains
  pressure/expired shards, and coordinates concurrent shutdown;
- `internal/agent.WorkerdProcessLauncher` pins a verified executable snapshot,
  gates readiness, bounds output, and coordinates process replacement and
  cleanup;
- the Linux cgroup controller creates one leaf per current launcher generation,
  writes and reads back CPU/memory/PID limits, attaches the child atomically,
  and performs identity-fenced `cgroup.kill` cleanup;
- `internal/conformance/workerd` runs the real Pi adapter and Dynamic Worker
  fixture, but its resource checks are still `NOT_RUN`, its qualification path
  has no trusted Manager/cgroup composition, and its `workerd test` fixture has
  no persistent socket;
- the release manifest pins both compressed workerd archives and their
  deterministically extracted executable digests; the qualification resolver
  verifies promotion policy and retains a sealed executable snapshot;
- `cmd/agentd` is a diagnostic-only control shell and does not compose any of
  the preceding operational components.

The Manager and launcher now use a distinct typed `ShardGeneration`, and the
fixed-argument adapter joins their start boundaries. `AgentInstanceID` travels
through ensure, readiness, process, and cgroup values, and the Manager checks
the exact process tuple before publication. The Manager observation endpoint
also requires that tuple plus a generation-scoped increasing sequence and
rejects stale inputs before state changes. One launcher-owned serialized
observer per published generation produces those observations against a
required sink boundary that `Manager` satisfies; only the qualification
composition that connects a live Manager remains.

### Cut line

Unit 10 may compose `internal/agent` components inside the external
qualification harness. It does not:

- add an agent workload RPC or a public listener;
- wire `platformd` Session admission to `agentd`;
- change `cmd/agentd` from its diagnostic-only capability claims;
- claim a real model, MCP broker, celld durability, or production state
  authority;
- prove the downstream model/tool/workspace/turn/SSE stale-request rejection
  required by `SPEC.md` §34.3 and §53.4;
- add NsJail, Docker, Firecracker, native command execution, or outer workerd
  isolation;
- mark §53.1, §53.4, or any production install profile qualified;
- choose permanent resident-session, RSS, or latency defaults from one host's
  measurements.

The current same-identity delegated cgroup mechanism proves mechanical limit
application, observation, and cleanup. It is not a security boundary against a
fully compromised same-UID workerd process. A production workload composition
must separately close cgroup-control authority isolation or place workerd in a
stronger outer boundary. Unit 10 keeps `AdmissionReady=false` while that gap,
the private workload authority, or any required production dependency is open.

### Identity and generation model

Four identity domains remain distinct:

- Session `placementGeneration` is issued by authoritative Session state. It is
  used only by the reference fixture in Unit 10 and is never passed to the
  process launcher or used in a cgroup leaf name. Real rotation and downstream
  broker rejection belong to Unit 11 and later composition work.
- The qualification composition root MUST load the host boot identity before
  constructing Manager. Manager construction then creates `agentInstanceID`, a
  fresh, non-secret 128-bit identifier for that qualification-runtime boot.
  Restarting that runtime creates a new value.
- `shardID` names one manager-owned logical shard slot inside an agent instance.
- `shardGeneration` is allocated monotonically by `Manager`, scoped to
  `(agentInstanceID, shardID)`. Every OS start attempt consumes a new
  generation, including a retry after failed, canceled, timed-out, or uncertain
  cleanup. A generation is never reused for a second PID.

Unit 10 adds `AgentInstanceID` and `ShardGeneration` to `ShardSpec` and renames
the launcher's `PlacementGeneration` fields in ensure requests, process info,
launch keys, cgroup names, and handles. Contract tests prove that Session
placement values cannot flow into those fields. Neither `agentInstanceID` nor
`shardGeneration` is accepted in a placement request or qualification-input
document: `ShardSpec` is the outbound Manager-to-Launcher value, and Manager
fills both identities before calling `Launcher.Start`.

One `WorkerdProcessLauncher` lifetime belongs to exactly one
`agentInstanceID`, bound by its first valid non-canceled ensure request. A new
Manager boot must construct a new launcher/adapter lifetime and close the old
one; reusing the old launcher with another agent identity fails before
allocation or callbacks. Per-shard generation history therefore cannot grow
across boots.

Manager-facing `ShardObservation` values now carry
`(agentInstanceID, shardID, shardGeneration, observationSequence)`. Manager
checks the exact tuple and a generation-scoped increasing sequence before any
state mutation or stop scheduling. It requires a nonzero `ObservedAt` for the
diagnostic record shape, but does not use that wall clock for ordering,
freshness, lifetime, or drain decisions.

At U10.2 completion, every readiness response, exit callback, resource-sample
producer, and stop completion MUST carry the identity tuple plus a non-reusable
process-instance token and the pinned cgroup device/inode identity. On Linux,
the completed process token MUST use a pidfd when available and verify PID start
identity; a numeric PID alone is insufficient. A late callback from a prior
start must not publish, drain, account, or remove its replacement.

One observer loop will own each shard generation. It will serialize samples and
assign a monotonic `observationSequence` after a complete read before delivery
to the already-fenced Manager endpoint. It must never wrap a sequence inside
one generation; exhaustion must recycle that generation or fail closed before
another sample. Cumulative `memory.events` and `cpu.stat` values will be
compared with the baseline captured for that exact generation.

### Readiness boundary

Shard readiness and Dynamic Worker admission bind different identities.

Shard readiness proves only:

- agent instance, shard ID, and shard generation;
- workerd executable digest/version;
- static SessionHost artifact and configuration digest;
- Worker Loader ABI and release identity;
- the private readiness endpoint nonce and pinned cgroup identity.

It does not bind a per-session Runtime Revision. At Loader admission, the
trusted SessionHost separately verifies the session ID, Runtime Revision
digest, Pi adapter ABI, compatibility date/flags, module graph, stable binding
set, and content-addressed Worker ID. A shared/tenant shard can therefore host
Dynamic Workers with different Runtime Revisions without weakening either
identity check.

### External qualification contract

#### Release provenance

Unit 10 first extends the release artifact contract so a workerd entry records
the archive digest, compression/extraction recipe, and extracted executable
digest for each architecture. Those fields are covered by the release-manifest
signing digest. The resource runner loads and validates the manifest and trust
policy, selects the exact architecture entry, verifies deterministic
extraction provenance, and hashes the opened executable snapshot.

The runner does not accept an expected workerd digest, version, SessionHost
digest, or fixture digest from an environment variable or command-line flag.
Those values come only from the validated release and the compiled probe
inventory. A development-status manifest can support Phase 0A evidence, but it
cannot qualify a production profile and remains subject to the release-status
rules in `docs/acceptance.md`.

#### Input and invocation

The new external test consumes one canonical absolute path:

```text
CIRCULUSD_WORKERD_QUALIFICATION_CONFIG=/private/path/workerd-qualification-v1.json
```

The versioned, exact-field JSON document is bounded at 64 KiB and supplies only
operator/host inputs:

- release manifest and trust-root paths;
- installed workerd path and architecture;
- a pre-provisioned cgroup-v2 root and private evidence-output directory;
- exact CPU quota/period, memory/swap/PID limits, readiness/probe/drain/total
  timeouts, and cold-start sample count.

It supplies no raw workerd arguments, child environment, expected digest, or
capability claim. Reference qualification uses `cpu.max=50000 100000`,
`memory.max=1073741824`, `memory.swap.max=0`, `pids.max=128`, and at least five
cold starts. A different valid measurement profile changes the configuration
and environment digests and cannot be merged with the reference run.

The launcher and cgroup controller replace the integer `CPUCores` input with a
finite canonical `CPUMax{QuotaMicros, PeriodMicros}` value. Both members are
decimal `uint64` values; quota is in `[1_000, 1_000_000_000]` and period is in
`[1_000, 1_000_000]`. Zero, an unlimited `max` quota, out-of-range values,
extra tokens, and any value that cannot round-trip through the exact kernel
readback are rejected. The controller formats each member directly and does
not derive quota by multiplication, so no core-to-quota arithmetic can
overflow. Unit 10 qualification is finite-limit only.

The explicit gate command is:

```bash
env CIRCULUSD_WORKERD_QUALIFICATION_CONFIG=/private/path/workerd-qualification-v1.json \
  go test -race -count=1 \
  -run '^TestStockWorkerdResourceQualification$' \
  ./internal/conformance/workerd
```

The harness materializes a private fixture directory and a persistent workerd
configuration with a private Unix socket. The production launcher receives one
fixed, golden-tested argument vector rendered by the harness:

```text
serve --experimental
-I<fixture-directory> <fixture-directory>/phase0-resource.capnp
```

The golden-argv preflight executes this exact `serve` contract against the
pinned workerd binary. Flags accepted only by `workerd test` are not part of
the qualification launcher contract.

SessionHost readiness uses a bounded nonce challenge over that socket and
returns the shard-level identity defined above. The total run has a configured
deadline no greater than 15 minutes; every individual probe and cleanup round
has a smaller explicit bound.

The operator provisions the cgroup root before the test. Its ancestors are
root-owned and non-writable, the target is an empty cgroup-v2 domain owned by
the runner's effective UID/GID with mode `0700`, and `cpu`, `memory`, and `pids`
are available and enabled. The harness never creates or relaxes that root. It
creates only generation-derived child leaves and requires the root to be empty
again after the final cleanup join.

#### Status classification

The runner uses this fixed classification; callers cannot choose a weaker
status:

| Situation | Result |
|---|---|
| The resource runner is not implemented, the explicit gate was not selected, or the qualification config is absent | `NOT_RUN` |
| The validated release artifact, required kernel feature, cgroup-v2 mount, or controller delegation is genuinely absent on the target host | `UNAVAILABLE` |
| The supplied document is malformed, the release/binary identity mismatches, or a provisioned path/root is inaccessible, read-only, or violates its ownership, mode, emptiness, controller, or identity contract; any such failure dominates a joined unavailable error | `FAIL` |
| A probe assertion, readiness check, internal deadline, cleanup join, evidence write/read-back, or leak check fails | `FAIL` |
| The enclosing caller cancels before completion and cleanup succeeds without another observed failure | `NOT_RUN` |
| Cancellation also exposes cleanup, identity, assertion, or evidence failure | `FAIL` |
| Every predicate for one named component passes in the same fresh run | `PASS` |

An explicit gate invocation exits unsuccessfully unless the four required
Unit 10 resource results (`workerd.cpu-limit`, `workerd.rss-cold-start`,
`workerd.shard-pressure-recycle`, `workerd.shard-kill-reconstruction`) are
`PASS` **and** the recorded residual-gap result
(`workerd.dynamic-worker-reconstruction`) is a `FAIL`. A recorded residual-gap
result that reports `PASS` is a framing error, because the pinned workerd
cannot legitimately produce it; a run must be re-scoped or re-pinned before that
would be promoted. A test skip, timeout, whole-shard kill, or cgroup limit
readback alone can never be interpreted as a component `PASS`, and the recorded
`FAIL` may never be softened to a skip.

#### Evidence envelope and retention

Every run emits a versioned deterministic-CBOR qualification envelope before a
JSON view is produced. Its schema contains:

- run ID and start/finish timestamps;
- runner binary digest, embedded source/fixture digest, and probe-inventory
  digest;
- release manifest digest/status, architecture-specific archive digest,
  extraction recipe, executable digest/version, static SessionHost artifact
  digest, and compatibility inputs;
- configuration/environment digests and the exact limits/timeouts/sample
  bounds;
- host and boot identity, kernel, architecture, cgroup namespace/mount identity,
  root and leaf device/inode identities, and enabled controllers;
- per-probe start/finish times, raw bounded sample counts, result status, and
  final cleanup outcome;
- separately named process RSS, cgroup memory charge/event, CPU throttling, PID,
  readiness, initialization, checkpoint, and reconstruction observations.

Process RSS is read only for the pinned process instance and is not inferred
from `memory.current`; cgroup memory charge is recorded separately. Artifact
references and results are canonical-name sorted. All four required Unit 10
`PASS` results require `EvidenceClassExternal`, `Mock=false`, the same run ID
and identity envelope, and a digest reference to
`workerd-resource-observation-v1.cbor`. The recorded
`workerd.dynamic-worker-reconstruction` `FAIL` records the same external
non-enforcement finding and run identity but is not required to reference the
observation artifact.

The output directory must be canonical, private, owned by the caller, and not
group/other writable. Files are created through a same-directory exclusive
temporary file with mode `0600`, followed by file sync, a no-clobber atomic
rename (`renameat2(RENAME_NOREPLACE)` or an equivalent operation) relative to a
pinned output-directory FD, directory sync, read-back digest verification, and
semantic validation. A run never replaces, relabels, or appends to an existing
artifact. The runner performs no automatic deletion; release evidence is
retained for the support lifetime of the bound release and removed only by the
later release-retention policy.

This retained envelope is historical qualification evidence, not startup
authority. It is never reused to manufacture a fresh result. Any later doctor
or startup consumer must independently authenticate the current host, boot,
release, executable, config, and target and apply its own freshness policy.

### Lifecycle, ownership, and cancellation

The required process lifecycle is:

```text
allocated -> starting -> ready -> draining -> stopping -> quiescent
                |          |          |
                +----------+----------+-> cleanup pending -> cleanup retry
```

Every transition to a new `starting` process consumes a fresh shard generation.
`ready` is published only after limit readback, atomic cgroup attachment, and
the shard-level readiness challenge. Entering `draining` closes admission
immediately. Resource ownership remains with the shared lifecycle operation
until the process is gone, the cgroup is unpopulated and removed, and every
borrowed descriptor is closed.

Manager owns the launch context and a waiter/result record for each pending
start. Canceling the initiating caller after another waiter attaches does not
cancel the shared start. Canceling the last waiter requests cancellation, but
the detached cleanup owner remains responsible for reaching a quiescent state.
The immutable launch result/error is published to every remaining waiter.
Successful launch completion alone does not insert a zero-session process into
the live shard map. The first still-valid claim publishes the ready shard and
its initial placement atomically; if no valid claim remains, the pending owner
transfers that process to exactly one cleanup epoch.

Stop and shutdown use shared cleanup epochs:

- caller cancellation stops only that caller's wait and returns its local
  context error;
- all uncanceled waiters on one cleanup epoch observe its same terminal result;
- a retryable cleanup error retains resource ownership and an explicit retry
  starts a new shared epoch;
- a terminal integrity/identity error poisons the owner and is cached for every
  later caller;
- successful ownership release is terminal and idempotent;
- qualification report finalization joins every detached start/cleanup owner;
  no `PASS` is emitted while cleanup is pending or uncertain.

The quiescent-boundary leak assertion runs only after the enclosing
qualification run or shutdown has joined those owners. It does not incorrectly
require resources to disappear before an individually canceled caller returns.

### Concurrency invariants

- One `(agentInstanceID, shardID, shardGeneration)` has at most one OS start and
  one active cleanup epoch; a second OS start always has a new generation.
- Same-operation waiters share an immutable result. Initiator cancellation
  cannot cancel work still owned by another waiter.
- Independent shard starts, observation loops, and cleanup epochs progress
  concurrently.
- No manager mutex is held while calling any interface method, including
  `Launcher.Start`, `ShardProcess.ID`, readiness, observation sinks, or
  `ShardProcess.Stop`, or while doing process/cgroup I/O.
- Reentrant/blocking callbacks cannot deadlock `Acquire`, `Observe`, `Snapshot`,
  or `Shutdown`.
- Replacement waits for uncertain cleanup of the prior process instance;
  timeout or cancellation cannot silently transfer ownership.
- Drain admission closes before stop begins. Generation and observation
  sequence checks reject late, duplicate, and out-of-order samples before any
  state mutation or stop scheduling.
- Shutdown fences new admission first, joins every in-flight start/stop owner,
  and preserves caller-local cancellation separately from shared cleanup
  results.
- Test callbacks reached from product goroutines report through channels or
  returned errors; they never call `FailNow` methods.

### Work packages and strict TDD order

Every behavioral slice follows RED → GREEN → focused race/shuffle verification.
Fakes specify host-independent contracts only; they can never replace a real
binary/cgroup external `PASS`.

#### U10.1 — Release pin, generation, and composition contracts

Status: complete for the host-independent U10.1 contracts. Items 1–4, item 5's
adapter/fixed-snapshot contract, and the review-added cleanup item 6 are
implemented. Resolver-snapshot handoff into the live qualification composition
remains in U10.4.

1. Add failing release-manifest/schema tests for extraction provenance and the
   installed executable digest, plus failing qualification-input tests that
   reject caller-supplied expected identities or raw launch inputs.
2. Add failing launcher/controller API tests that replace `CPUCores` with the
   bounded finite `CPUMax` value; reject zero, `max`, range violations, extra
   tokens, and legacy multiplication/overflow behavior.
3. Add failing agent tests for the generation allocator/API rename, one fresh
   generation per OS attempt, placement-generation non-flow, and readiness
   identity separation.
4. Add cross-contract RED tests for “initiator cancels after a second waiter
   attaches → one OS start and remaining waiter succeeds”, cancellation between
   the final precheck and first launcher identity bind, and blocking or reentrant
   identity/readiness callbacks under Manager operations.
5. Implement the narrow manager/launcher adapter, canonical CPU-max migration,
   manager-owned launch context, immutable waiter result, and release-bound
   fixed launch configuration.
6. Add failing Manager and workerd tests that make retryable cleanup start one
   fresh shared epoch on the next explicit caller while terminal integrity or
   identity failures remain cached and side-effect free. Preserve parallel
   starts and deterministic joins during shutdown. Then define the minimal
   `ShardProcess.Stop` outcome contract for retryable ownership-retained versus
   terminal ownership-released or poisoned failures, and implement Manager
   epoch replacement or terminal caching from that contract without inferring
   disposition from an arbitrary non-nil error.

#### U10.2 — Generation-bound resource observation

Status: implemented except artifact mapping. Bounded cgroup parsing/readback,
pinned cgroup identity, generation baselines, pidfd-owning `(pid,startTicks)`
RSS primitives, permission/read-only dominance, operation-scoped host absence
versus post-provision path loss, controller availability versus enablement,
the Manager observation identity/sequence endpoint, launcher process-token
attachment, and the serialized per-generation observer producer are
implemented with their race/shuffle gates executed on a Linux boundary.
Wiring the sink to a live Manager inside the qualification composition and
evidence-artifact status mapping remain with U10.4.

1. Add failing bounded-parser tests for `memory.current`, `memory.events`,
   `cpu.stat`, exact two-token finite `cpu.max`, and `pids.current`; include
   controller write/readback tests for the canonical quota/period and
   process-RSS tests pinned to the process token/PID start identity. Add
   classification tests that distinguish genuine absence/unsupported errors
   from permission, read-only, and mixed provisioned-root failures. Include the
   operation phase: initial host/root absence may be unavailable, while loss,
   replacement, or unsupported operations on an already provisioned leaf fail
   the integrity contract. Distinguish an unavailable controller from one the
   operator failed to enable.
2. Add failing race tests for stale callback/cgroup identity,
   duplicate/decreasing observation sequence, delayed old low-memory samples,
   and cumulative-counter baseline replacement.
3. Implement one serialized observer loop per shard generation. Feed immutable
   observations into Manager without holding manager/cgroup locks across I/O or
   callbacks.
4. Keep cgroup memory charge, process RSS, CPU throttling, OOM/oom-kill counters,
   and unavailable/malformed evidence distinct in code and artifacts.

#### U10.3 — Distinct reconstruction and recycle contracts

Status: in progress. The probe inventory and doctor profile now carry the
three distinct reconstruction results with separate NOT_RUN reasons and no
runnable substitute, and the ambiguous `workerd.shard-recycle` name is gone
from both. The runner-side deterministic checkpoint store exists outside the
workerd process: it acknowledges canonical bytes/digest commits per
content-addressed Worker ID, reverifies digests on reload, never serves
unacknowledged or foreign state, fails closed before sequence exhaustion,
and gates fault injection on the exact acknowledged digest. The Dynamic
Worker fixture now carries the module-local initialization-instance identity
with its pre-fault stability proven under the pinned stock workerd binary.
The destructive fault paths, probe composition against the store, and the
mock placement rotation remain.

1. Add failing host-independent contract tests for all three new reconstruction
   result names, their non-substitutability, checkpoint commit/ack ordering,
   initialization-instance change, pressure drain, explicit `SIGKILL`, and
   quiescent cleanup.
2. Move the deterministic checkpoint store outside the workerd process. It
   records canonical checkpoint bytes/digest and acknowledges the commit before
   any destructive fault is injected.
3. For Dynamic Worker reconstruction, trigger a pinned Loader/CPU-limit fault
   that must destroy the isolate, then require a new initialization-instance ID
   for the same content-addressed Worker ID and reload the acknowledged
   checkpoint. If the pinned workerd behavior cannot prove a destroyed isolate,
   this result fails and the whole-shard probe cannot substitute for it.
   The ID is created inside the Dynamic Worker module during actual module
   initialization, retained in module-local state, and returned by the
   initialization hook. It must remain identical across two pre-fault calls and
   differ on the first successful post-fault initialization; the harness cannot
   inject, rotate, or synthesize it.
4. Separately induce real pressure/OOM for the pressure-recycle result and send
   `SIGKILL` to the pinned process instance for the shard-kill result. Each path
   must drain, clean the exact cgroup generation, start a new generation, and
   reload the acknowledged checkpoint.
5. A deterministic mock placement source rotates the fixture placement value
   and proves only Manager/fixture fencing shape. Label that evidence reference
   only; do not claim downstream broker rejection or §53.1/§53.4 `PASS`.

#### U10.4 — External runner, status, and evidence

Status: implemented and green on a provisioned host. The bounded input schema,
fixed argument renderer, release resolver, sealed executable snapshot,
private-socket serve fixture and materializer, status classification, component
PASS predicates, run-level evaluator, canonical-CBOR evidence envelope with
atomic retention, and `ProbeWorkerdCgroupProvisioning` preflight all exist and
are host-independently tested. The runner (`runResourceQualification`) composes
config → release → cgroup preflight → fixture → probes → evidence → evaluate
behind `TestStockWorkerdResourceQualification`, gated on
`CIRCULUSD_WORKERD_QUALIFICATION_CONFIG`. The live probe runner
(`liveResourceProbeRunner`) drives the launcher directly against the provisioned
cgroup with the digest-bound SessionHost readiness probe and implements all five
probes; the external RED negative control is retained
(`TestResourceGateIsNotSatisfiedByTheWorkerdTestPath`). Live-verified on a WSL2
cgroup-v2 host against the pinned workerd: the gate reaches its achievable bar
(four required PASS + one recorded FAIL). The runner consumes a preinstalled
executable; archive extraction remains owned by the separate release/install
workflow. Remaining before production promotion: a run on a production install
profile (the current evidence is a development host) and the final acceptance
close.

The maintainer decision on the verified external finding is resolved
(2026-09-02): re-scope to the kernel-enforced boundary rather than re-pin.
Stock `workerd 1.20260825.1` parses but does not enforce `limits.cpuMs` for
Worker Loader isolates in serve mode, and no in-isolate fault (uncaught error,
async rejection, oversized-array or stack `RangeError`, memory growth) destroys
the isolate — the initialization-instance ID is preserved across every one.
`workerd.cpu-limit` is therefore re-scoped to certify the kernel boundary
(cgroup `cpu.max` throttling plus supervisor-observed starvation → whole-shard
kill/recycle) and remains a required PASS; the in-isolate `cpuMs`
non-enforcement is recorded as an evidence-bound finding.
`workerd.dynamic-worker-reconstruction` (per-isolate) is demoted to a recorded
honest FAIL. The achievable bar is four required PASS plus that one recorded
FAIL, with `AdmissionReady=false` while the gap stands. See
`docs/unit10-handoff.md`.

1. Add failing host-independent tests for the exact input schema, fixed argv,
   provisioning preflight, status table, component PASS predicates, evidence
   class/identity agreement, canonical artifact validator, atomic retention,
   and cleanup-leak finalizer.
2. Add an external RED run showing that the existing `workerd test` fixture and
   three caller-supplied binary environment variables cannot satisfy the new
   resource gate; retain the command and result.
3. Implement the persistent private-socket fixture and run every real probe
   under the manager/launcher/cgroup composition.
4. `workerd.cpu-limit` passes only when exact `cpu.max` readback and an increase
   in `cpu.stat` throttling are observed under a runaway Worker invocation
   **and** supervisor-observed starvation drives a deterministic whole-shard
   kill/recycle within its own deadline. The run additionally records, as an
   evidence-bound finding, that the in-isolate `cpuMs` limit did not fire — a
   recorded negative observation, never a skip. The pinned Loader `cpuMs`
   failure is not part of the PASS predicate on this pin.
5. `workerd.rss-cold-start` passes only with at least five fresh-cgroup samples,
   separate process RSS/cgroup charge, bounded start/ready timestamps, exact
   identity, and a valid artifact; it records measurements rather than freezing
   a product performance threshold.
6. Run the two shard-level reconstruction probes (`shard-pressure-recycle`,
   `shard-kill-reconstruction`) independently and refuse aggregate PASS when
   either is missing, substituted, canceled, timed out, or not quiescent. Run
   the per-isolate `dynamic-worker-reconstruction` probe and record its honest
   FAIL (stock workerd does not reconstruct a faulted isolate); the evaluator
   treats a `PASS` there as a framing error and never lets its FAIL be softened
   to a skip.

#### U10.5 — Close the unit without widening readiness

Status: in progress. The explicit external gate ran on a provisioned WSL2 host
and reached its achievable bar (four required PASS + one recorded FAIL);
`docs/unit10-operator.md` and the acceptance ledger record it, and
`docs/acceptance.md` keeps §53.1/§53.3/§53.4 `NOT_RUN` with `AdmissionReady`
false. Remaining: the full race/vet + TypeScript gates and a production
install-profile run before the unit closes.

1. Run focused race/shuffle/repetition tests for `internal/agent`, the workerd
   conformance harness, and `cmd/agentd`.
2. Run the complete Go race/vet and TypeScript check/lint/unit gates.
3. Run the explicit external gate on a provisioned host and retain the fresh
   envelope and JSON view. If the boundary is unavailable, Unit 10 remains
   incomplete.
4. Update profiles, operator instructions, and `docs/acceptance.md` from that
   retained evidence. Record `workerd.dynamic-worker-reconstruction` as a
   documented residual gap (recorded FAIL: stock workerd does not reconstruct a
   faulted isolate on this pin) so the certified boundary is the kernel one, not
   an in-isolate limit. Do not infer aggregate §53 `PASS` or change daemon
   capabilities from unit/reference tests; `AdmissionReady` stays false while
   the residual gap or any production dependency is open.

### Required evidence and exit criteria

Unit 10 is complete only when all of the following are true:

- host-independent contract tests pass under `go test -race` with
  shuffled/repeated lifecycle cases;
- the four required Unit 10 results (`workerd.cpu-limit`,
  `workerd.rss-cold-start`, `workerd.shard-pressure-recycle`,
  `workerd.shard-kill-reconstruction`) are non-mock external `PASS` from the
  same release-, config-, host-, boot-, cgroup-, runner-, and run-bound
  envelope, and `workerd.dynamic-worker-reconstruction` is a recorded honest
  `FAIL` from that same run carrying the in-isolate non-reconstruction finding;
- pressure recycle and explicit whole-shard kill each reconstruct independently
  from an externally acknowledged checkpoint, and the per-isolate
  `dynamic-worker-reconstruction` FAIL is recorded rather than skipped;
- the reference placement-fencing shape is labeled mock/reference-only and
  §53.1/§53.4 remain unpromoted;
- after the enclosing final cleanup join, no child process, process group,
  cgroup child, goroutine, or file descriptor remains owned;
- the qualification envelope, resource artifact, and JSON view are canonical,
  bounded, atomically retained, digest-linked, and semantically revalidated;
- `cmd/agentd` still reports operational capabilities as `NOT_WIRED`, and
  production admission/readiness remains false;
- `docs/acceptance.md` records exactly what ran, including environment limits,
  without promoting mock/reference evidence.

## Commit boundaries

Implementation commits remain independently reviewable and revertible:

1. release extraction pin and qualification input/evidence schemas;
2. manager/launcher generation, waiter, and readiness contracts;
3. cgroup/process observation and accounting;
4. Dynamic Worker, pressure recycle, and shard-kill reconstruction contracts;
5. persistent external runner and retained evidence;
6. acceptance and operator documentation.

Each implementation commit includes its preceding failing tests and the green
result for that one work package. Cross-package changes are combined only when
splitting them would leave an invalid protocol, identity, or lifecycle
contract.
