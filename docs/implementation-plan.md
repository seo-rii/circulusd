# Implementation plan

Status: Unit 10 implementation in progress after independent architecture and
concurrency review

Updated: 2026-09-01

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
  decreasing input. A new generation resets sequence ownership. `ObservedAt`
  remains required diagnostic metadata but no longer drives lifetime or drain;
  admission-time lifetime enforcement remains separate. Simultaneous equal-
  sequence delivery linearizes to one winner without loser-payload mutation,
  draining is irreversible, and observation-triggered Stop callbacks may
  reenter Manager without its mutex held. Focused 50-pass and complete agent
  10-pass race/shuffle gates, repository tests, and vet pass. The serialized
  producer, process-token attachment, and lifecycle delivery remain.

### Outcome

Complete the Phase 0A process, cgroup, and Worker Loader gates against the
release-pinned stock workerd process. Unit 10 introduces five distinct required
external results:

- `workerd.cpu-limit`: both Loader `cpuMs` failure semantics and shard-level
  cgroup CPU throttling;
- `workerd.rss-cold-start`: process RSS, cgroup memory attribution, and repeated
  cold-start measurements;
- `workerd.dynamic-worker-reconstruction`: destructive Dynamic Worker failure
  followed by a demonstrably new initialization for the same content-addressed
  Worker ID;
- `workerd.shard-pressure-recycle`: real cgroup pressure/OOM, drain, cleanup,
  and reconstruction;
- `workerd.shard-kill-reconstruction`: explicit whole-shard `SIGKILL`, cleanup,
  and reconstruction.

The old ambiguous `workerd.shard-recycle` result is replaced by the last two
results when the profile and probe inventory migrate. Neither one may
substitute for the other.

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
rejects stale inputs before state changes. The remaining observation identity
work is the serialized producer and its lifecycle-owned delivery wiring.

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
to the already-fenced Manager endpoint. Cumulative `memory.events` and
`cpu.stat` values will be compared with the baseline captured for that exact
generation.

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

An explicit gate invocation exits unsuccessfully unless all five Unit 10
resource results are `PASS`. A test skip, timeout, whole-shard kill, or cgroup
limit readback alone can never be interpreted as a component `PASS`.

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
references and results are canonical-name sorted. All five Unit 10 `PASS`
results require `EvidenceClassExternal`, `Mock=false`, the same run ID and
identity envelope, and a digest reference to
`workerd-resource-observation-v1.cbor`.

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

Status: in progress. Bounded cgroup parsing/readback, pinned cgroup identity,
generation baselines, `(pid,startTicks)` RSS reads, permission/read-only
dominance, operation-scoped host absence versus post-provision path loss,
controller availability versus enablement, and the Manager observation
identity/sequence endpoint are implemented. pidfd ownership, launcher
attachment, serialized producer delivery, and evidence-artifact status mapping
remain.

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

Status: queued.

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

Status: partially implemented. The bounded input schema, fixed argument
renderer, release resolver, and sealed executable snapshot exist. The runner
consumes a preinstalled executable; archive extraction remains owned by the
separate release/install workflow. Pinned-binary CLI and provisioning
preflights, status/PASS predicates, sealed snapshot-to-launcher handoff,
persistent socket composition, real probes, canonical evidence retention, and
result promotion remain.

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
   in `cpu.stat` throttling are observed **and** an infinite Worker invocation
   reaches the pinned Loader `cpuMs` failure within its own deadline while the
   shard remains usable or is deterministically recycled.
5. `workerd.rss-cold-start` passes only with at least five fresh-cgroup samples,
   separate process RSS/cgroup charge, bounded start/ready timestamps, exact
   identity, and a valid artifact; it records measurements rather than freezing
   a product performance threshold.
6. Run the three reconstruction probes independently and refuse aggregate PASS
   when any one is missing, substituted, canceled, timed out, or not quiescent.

#### U10.5 — Close the unit without widening readiness

Status: queued.

1. Run focused race/shuffle/repetition tests for `internal/agent`, the workerd
   conformance harness, and `cmd/agentd`.
2. Run the complete Go race/vet and TypeScript check/lint/unit gates.
3. Run the explicit external gate on a provisioned host and retain the fresh
   envelope and JSON view. If the boundary is unavailable, Unit 10 remains
   incomplete.
4. Update profiles, operator instructions, and `docs/acceptance.md` from that
   retained evidence. Do not infer aggregate §53 `PASS` or change daemon
   capabilities from unit/reference tests.

### Required evidence and exit criteria

Unit 10 is complete only when all of the following are true:

- host-independent contract tests pass under `go test -race` with
  shuffled/repeated lifecycle cases;
- all five named Unit 10 results are non-mock external `PASS` from the same
  release-, config-, host-, boot-, cgroup-, runner-, and run-bound envelope;
- Dynamic Worker failure, pressure recycle, and explicit whole-shard kill each
  reconstruct independently from an externally acknowledged checkpoint;
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
