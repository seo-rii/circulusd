# Unit 10 continuation handoff

Updated: 2026-09-02

This is the restart point for continuing Unit 10 on another machine. Read
`SPEC.md`, then `docs/implementation-plan.md`, then this file. The normative
contract remains `SPEC.md`; this file records implementation state and the safe
next TDD boundary only.

## Resume checkpoint

- Git origin: `https://github.com/seo-rii/circulusd.git`
- Go module: `github.com/hancomac/circulusd`
- Branch: `main`
- Go version: `1.25.0`
- Last implementation commit: `2a53f22` (`docs(conformance): U10.5 acceptance
  ledger, operator guide, and RED negative control`), on 2026-09-02. The
  Unit 10 arc, in order: `45cb691` (launcher pidfd attachment), `de83aec`
  (serialized observation), `8d11098` (distinct reconstruction results),
  `c5eabaf` (external checkpoint store), `08eb353` (dynamic-worker
  initialization instances), `cb3f5f7` (launcher qualification surface),
  `96cbd69` (private-socket fixture), `d392cb8` (status + evidence spine),
  `e03543b` (cgroup provisioning preflight + inspectRoot fix), `c0a86eb`
  (resource gate re-scope: four required PASS + one recorded FAIL), `8824ed0`
  (external runner + gate orchestration), `294b10a` (SessionHost readiness
  probe), `c0aca58` (live probe composition + rss-cold-start),
  `6051819` (cpu-limit kernel-boundary probe), `e13ded2` (pressure-recycle +
  kill-reconstruction), `3cf30e8` (recorded dynamic-worker-reconstruction FAIL;
  gate qualifies), and `2a53f22` (U10.5 acceptance ledger + operator guide +
  RED control). The live gate reaches its achievable bar on a provisioned WSL2
  host. This handoff update is committed immediately after `2a53f22`.
- At original preparation time `origin/main` was `9ab2104`; all implementation
  and handoff documentation commits are local. No push was performed.
- The release-pinned stock workerd binary is installed inside WSL at
  `/home/seohyun/workerd-1.20260825.1` with both manifest digests verified
  (archive `45fb5f0e…`, extracted `b805ed48…`). Run the live fixture gate
  from the native clone with:
  `CIRCULUSD_WORKERD_PATH=/home/seohyun/workerd-1.20260825.1`,
  `CIRCULUSD_WORKERD_SHA256=sha256:b805ed481caa643953357d38146b82c118addcb525eb87e3d190b5617c82bc75`,
  `CIRCULUSD_WORKERD_VERSION='workerd 2026-08-25'`.
- The Windows transfer host now has a WSL2 Ubuntu 26.04 boundary with Go
  1.25.3 at `/home/seohyun/go/bin/go` and gcc for `-race`. Run linux-tagged
  package gates from `/mnt/c/Users/seohyun/Documents/dev/circulusd` with
  `TMPDIR`/`GOTMPDIR`/`GOCACHE` pointed at `/dev/shm` (recreate those
  directories after every WSL restart) and `CGO_ENABLED=1`. The `/mnt/c`
  working tree is CRLF (`core.autocrlf=true`) on a drvfs mount, which breaks
  only environment-sensitive tests elsewhere in the repository: workerd
  conformance fixture digests (CRLF content) and dependency evidence
  parent-mode checks (drvfs permissions). The canonical full-suite gate on
  this machine is therefore a native clone:
  `git clone /mnt/c/Users/seohyun/Documents/dev/circulusd ~/circulusd` (or
  `git -C ~/circulusd fetch origin && git -C ~/circulusd reset --hard
  origin/main` on later rounds), then `go test ./...` and `go vet ./...`
  there. A plain `gofmt -l` on the CRLF tree flags every file and is not
  evidence of a formatting change; check CR-stripped copies instead.
- `RISK_REGISTER.md` is intentionally local and untracked by repository policy.
  Its `ARCH-003` entry is summarized below so a fresh clone does not lose the
  risk.
- No infrastructure was created, changed, or deployed, and no external Unit 10
  result has been promoted to `PASS`.

The commits must be transferred before another PC can resume. Either obtain
approval and push the current `main`, or create and copy a Git bundle without
changing the remote:

```sh
git bundle create circulusd-unit10-handoff.bundle main
git clone circulusd-unit10-handoff.bundle circulusd
```

The bundle command is documentation only; this handoff did not create one.
After transfer, confirm that `git log -1 --format=%s` prints
`docs: record unit ten handoff` and its parent is `f6e9f80`. Repository
`git status --short` should then be empty on a fresh clone. In the originating
workspace it shows only the intentionally untracked `RISK_REGISTER.md`.
Root-workspace `MISTAKES.md`, `STAGING.md`, and `DONE.md` are bookkeeping files
and must not be staged.

## Completed implementation boundary

Units 7, 8, and 9 are complete. Unit 10 remains in progress.

U10.1 is complete for host-independent contracts:

- release manifests bind the compressed archive and extracted executable;
- finite canonical cgroup `cpu.max` replaces CPU multiplication;
- Manager owns boot and shard-generation identities;
- concurrent starts share immutable launch epochs and atomically adopt a ready
  process with the first valid placement;
- a canceled request cannot bind a low-level launcher lifetime;
- cleanup distinguishes retryable epochs from terminal released or quarantined
  outcomes.

The following U10.2 pieces are complete:

- bounded canonical cgroup parsing, limit write/readback, pinned directory
  identity, generation baselines, sampling, and cleanup classification;
- operation-scoped distinction between genuine delegated-root absence and any
  post-provision path, permission, read-only, or controller-enablement failure;
- bounded `(pid,startTicks)` capture and before/after `/proc` verification for
  process RSS;
- Manager-side observation fencing by
  `(agentInstanceID, shardID, shardGeneration, observationSequence)`;
- stable observation classification order: malformed input, closed Manager,
  wrong agent boot, missing shard, wrong shard generation, then stale sequence;
- diagnostic-only `ObservedAt`, irreversible drain, no sequence wrap, and
  lock-free Stop callback execution;
- an unattached `workerdProcessIdentity` primitive that owns one pidfd, lends
  sample borrows, closes only after borrow quiescence, and caches one terminal
  close result.

The pidfd primitive deliberately fails closed. Only an error tree containing
exclusively `ENOSYS` leaves is classified as unsupported. Permission, policy,
invalid-operation, stale-process, and mixed failures are not downgraded. There
is no numeric-PID-only fallback.

## Current verification evidence

For `45cb691` and `de83aec`, the WSL2 boundary on this machine executed and
passed: focused 50-repetition identity and observer race/shuffle runs, the
10-repetition complete `internal/agent` race/shuffle gate, package and
repo-wide vet, and the complete `go test ./...` suite from the native WSL
clone at each commit. The evidence below was produced on the original Linux
machine for `f6e9f80`; its final implementation checks before the machine
transfer passed:

- observation-focused race/shuffle: 50 repetitions;
- pidfd-owner-focused race/shuffle: 100 repetitions;
- complete `internal/agent` race/shuffle: 10 repetitions;
- `go test ./...`;
- `go vet ./...`;
- `gofmt -d` and `git diff --check` for the changed files.

Use task-owned shared-memory paths because repository tests exercise many
concurrent process fixtures. Recreate the volatile directories after a reboot
or resumed session before interpreting a Go command result:

```sh
mkdir -p /dev/shm/circulusd-go-tmp /dev/shm/circulusd-go-cache
TMPDIR=/dev/shm/circulusd-go-tmp GOTMPDIR=/dev/shm/circulusd-go-tmp GOCACHE=/dev/shm/circulusd-go-cache go test -race -shuffle=on -count=10 ./internal/agent
TMPDIR=/dev/shm/circulusd-go-tmp GOTMPDIR=/dev/shm/circulusd-go-tmp GOCACHE=/dev/shm/circulusd-go-cache go test ./...
TMPDIR=/dev/shm/circulusd-go-tmp GOTMPDIR=/dev/shm/circulusd-go-tmp GOCACHE=/dev/shm/circulusd-go-cache go vet ./...
git diff --check
```

Run these as independent commands. A yielded command must be joined by its
session identifier before treating it as evidence.

## Completed 2026-09-01: launcher process-token attachment

Commit `45cb691` implemented this unit as one coherent commit in
`internal/agent/workerd_launcher_linux.go`, its test file, and the cgroup
launcher test helpers (`workerd_process_linux.go` needed no change). All
eight planned boundaries are covered by focused tests:

1. capture of the exact pidfd/start-time owner after `starter.Start` and
   before `Wait`, readiness, observation, or handle publication;
2. capture failure producing exactly one process/cgroup cleanup owner with no
   readiness callback and no handle, preserving pidfd-unsupported
   classification;
3. the exact owner stored on `workerdInstance` with no numeric-PID
   reconstruction and stale rejection on PID reuse;
4. retryable process-group timeout retaining the open owner for the next
   cleanup epoch;
5. natural exit, readiness failure, replacement, `Handle.Stop`, and
   `Launcher.Close` each closing the owner exactly once after quiescence;
6. terminal pidfd close failure cached and replayed without another close
   syscall, surfacing in the launcher close result;
7. no launcher or instance mutex held across capture, proc I/O, borrow
   quiescence, close, readiness callbacks, or cleanup waits;
8. an old generation owner unable to sample, close, or otherwise act on its
   replacement.

The identity capturer is a required constructor input; production paths bind
the real `/proc`-and-pidfd capture, tests inject a fake built on the existing
proc-reader/pidfd fakes, and the real-child launcher integration test
exercises the production capture path end to end.

The deferred gates for this slice were executed on the WSL boundary on
2026-09-01 and passed: 50-repetition identity-focused race/shuffle,
10-repetition complete `internal/agent` race/shuffle, repo-wide
`GOOS=linux go vet ./...`, and `go test ./...` from the native WSL clone.

## Completed 2026-09-01: serialized observation lifecycle

Implemented in `internal/agent/workerd_observer_linux.go`, its test file, and
narrow launcher wiring. One launcher-owned observer per published shard
generation:

- obtains a complete pinned cgroup sample and exact pidfd-verified process-RSS
  sample before allocating the next strictly increasing generation-local
  sequence, and fails closed before `uint64` exhaustion;
- classifies OOM and heap pressure from `memory.events` deltas against that
  exact generation's baseline;
- delivers an immutable `ShardObservation` carrying the exact
  boot/shard/generation tuple to a required `WorkerdObservationSink`
  (`Manager` satisfies it statically) with no launcher, instance, cgroup, or
  process-identity locks held;
- suppresses a sample whose cancellation wins after I/O but before delivery;
- ends only the producer, never the shard, on sample or sink failure.

The self-stop cycle is resolved by ownership transfer, not a joining stop:
stop epochs cancel the observer and complete without joining it, so a sink
that synchronously stops its own shard returns first, and `Launcher.Close`
performs the final observer join before releasing the executable. A deliberate
join-before-epoch mutation reproduces the deadlock and fails
`TestWorkerdObserverSelfStopDrainDoesNotDeadlock`, which is the recorded RED
evidence for this boundary. Focused observer race runs, the 50-repetition
focused and 10-repetition complete agent race/shuffle gates, and package vet
passed on the WSL boundary.

## Completed 2026-09-01: U10.3 host-independent contracts

Three commits delivered the host-independent U10.3 scope:

- `8d11098`: the probe inventory and every doctor profile carry the three
  distinct reconstruction results with separate NOT_RUN reasons and no
  runnable substitute; `workerd.shard-recycle` is gone.
- `c5eabaf`: the deterministic checkpoint store lives in the runner process,
  acknowledges canonical bytes/digest commits per content-addressed Worker
  ID, and gates fault injection on the exact acknowledged digest.
- `08eb353`: every Dynamic Worker boots through `phase0-worker-entry.mjs`,
  whose module-local initialization-instance identity proves a new
  initialization when it changes; pre-fault stability, format, and sibling
  distinctness run live against the pinned workerd binary. workerd forbids
  entropy in module global scope, so the single draw happens on the first
  handler call while the null-to-value transition stays bound to module
  initialization.

The destructive Loader/CPU fault, real pressure/OOM, and pinned-process
`SIGKILL` paths deliberately stay out of the bounded embedded fixture (its
contract test forbids a spin route); they belong to the external runner.

## In progress 2026-09-01: U10.4 external runner composition

Two commits advanced U10.4:

- `cb3f5f7`: the launcher exposes the narrow qualification surface —
  `Executable` handoff of a pre-opened verified snapshot (so the release
  resolver's sealed snapshot needs no path authority),
  `Handle.KillProcessInstance` (SIGKILL through the owned pidfd, borrow-gated),
  and `Handle.SampleResources` (one immutable exported sample joining the
  pinned cgroup read and the exact pidfd-verified process RSS).
- `96cbd69`: the persistent private-socket serve fixture and its materializer
  (`phase0-resource.capnp.tmpl`, `session-host-resource.mjs`,
  `phase0-resource-entry.mjs`), digest-bound and placeholder-checked, with the
  bounded `workerd test` fixture provably free of the spin/allocate routes.

### RESOLVED (2026-09-02) — re-scope to the kernel boundary, not re-pin

The maintainer decision below is resolved: **re-scope** (option (a)), keeping a
real safety boundary. The certified resource safety boundary is the
kernel-enforced one — cgroup-v2 `cpu.max` throttling, `memory.max` OOM, and
pidfd whole-shard `SIGKILL` with reconstruction — which holds against a fully
uncooperative isolate (exactly the case here). `workerd.cpu-limit` is re-scoped
to certify that boundary (exact `cpu.max` readback + observed `cpu.stat`
throttling under a runaway Worker + supervisor-observed starvation →
deterministic whole-shard kill/recycle), and the in-isolate `cpuMs`
non-enforcement is recorded as an evidence-bound finding. The achievable Unit 10
bar is **four required external PASS** (`cpu-limit`, `rss-cold-start`,
`shard-pressure-recycle`, `shard-kill-reconstruction`) **plus one recorded
honest FAIL** (`dynamic-worker-reconstruction`, per-isolate: stock workerd never
reconstructs a faulted isolate). `AdmissionReady` stays false while that
per-isolate residual gap stands; a future re-pin/rebuild that enforces
per-isolate limits in serve mode can restore it to a required PASS and re-scope
this back. The runner encodes this split in
`internal/conformance/workerd/resource_status.go`
(`requiredResourceQualificationComponents` /
`recordedResourceQualificationComponents`, and
`evaluateResourceQualificationRun`); a recorded component that reports PASS is a
framing error, and its FAIL may never be softened to a skip. The original
finding and the rejected options are preserved below for the record.

### BLOCKER (historical) — stock workerd does not enforce `cpuMs`

Live probing of the pinned `workerd 1.20260825.1` binary in the exact
qualification shape (dynamic Worker via Worker Loader, invoked through the
serve SessionHost) established that `limits.cpuMs` is **parsed but not
enforced**: infinite invocations that yield on microtasks and on timers both
ran unbounded past 20x the 1000ms limit and starved the shard's request
handling. The binary contains only Python-Worker CPU-limit machinery and a
`ResourceLimits{cpuMs, subRequests}` wrapper; no generic per-isolate abort
fired. To reproduce: `workerd serve` the resource fixture against the pinned
binary, then `curl --max-time 20 --unix-socket <sock>
'http://q/worker/spin?worker=w/a'` — the request never returns and no isolate
fault is logged, for synchronous, microtask-yielding, and timer-yielding spin
loops alike.

Consequence for the plan's own PASS predicates:

- `workerd.cpu-limit` requires the Loader `cpuMs` failure half → cannot PASS
  on this pin.
- `workerd.dynamic-worker-reconstruction` triggers its destructive isolate
  fault via that same `cpuMs` limit → cannot PASS on this pin (and the plan
  forbids the whole-shard probe from substituting).

A follow-up experiment (2026-09-01, deferred-decision, at the maintainer's
request) tested every alternative per-isolate destructive fault reachable
from JS in the serve + Worker Loader shape. None destroys the isolate: an
uncaught `throw`, an async promise rejection, a `RangeError` from a
9e9-length `Array`, and a stack-overflow `RangeError` all leave the
module-local initialization-instance ID **identical** before and after, so
the isolate keeps its state; a 4 GB `Uint8Array` allocation even succeeded
(no per-isolate memory cap); and memory/CPU exhaustion loops starve the shard
exactly like `cpuMs`. The only observed way to force re-initialization is to
destroy the whole process, which the plan forbids as a substitute. So
`workerd.dynamic-worker-reconstruction` is blocked independently of `cpuMs`:
stock workerd on this pin never reconstructs a faulted isolate for a fixed
content-addressed Worker ID.

The other three results (`workerd.rss-cold-start`,
`workerd.shard-pressure-recycle`, `workerd.shard-kill-reconstruction`) depend
only on cgroup mechanics, real OOM, and pinned-process `SIGKILL`, all of which
the built primitives already cover, and remain achievable.

The exit criteria originally required all five results to be non-mock external
`PASS` from one envelope. The maintainer options were (a) accept a No-Go for
the CPU-limit results and re-scope Unit 10's exit to the achievable results
plus a recorded FAIL, (b) find an alternative pinned per-isolate destructive
fault that stock workerd actually enforces and re-tie
`dynamic-worker-reconstruction` to it, or (c) re-pin workerd to a release/build
that enforces `cpuMs` for Worker Loader isolates in serve mode. Option (b) is
empirically closed (the experiment above found no reachable enforced fault).
**Option (a) was chosen on 2026-09-02** with the safety-boundary guardrail
above: `cpu-limit` is re-scoped to a required kernel-boundary PASS and only the
per-isolate `dynamic-worker-reconstruction` becomes a recorded FAIL, so the exit
is four required PASS plus one recorded FAIL. The runner records the honest
FAIL, never a skip-as-PASS. Closing the residual gap (restoring the fifth to a
required PASS) still needs option (c) — a re-pin/rebuild — as separate,
authorized infrastructure work.

### U10.4 spine landed (decision-independent), commits cb3f5f7, 96cbd69, d392cb8

Already implemented and host-independently tested, usable on any decision path:

- launcher qualification surface (`cb3f5f7`): pre-opened `Executable` handoff,
  `Handle.KillProcessInstance`, `Handle.SampleResources`;
- persistent private-socket serve fixture + digest-binding materializer
  (`96cbd69`);
- status classification table, component PASS predicate, run-level all-five
  envelope evaluator, and the canonical CBOR observation envelope with atomic
  no-clobber `renameat2`/`linkat` retention and read-back revalidation
  (`d392cb8`).

### U10.4 complete — live gate qualifies (2026-09-02)

The external runner and all five probes are built and live-verified. Key
implementation facts learned on the live boundary:

- The runner composes the launcher DIRECTLY via `Ensure` (pull-based
  `Handle.SampleResources`), no `ObservationSink`, sidestepping the
  Manager↔launcher circular sink wiring. The agent instance identity is one
  fresh 128-bit value seeded into both `identity.New(Process)` and the evidence
  hex id.
- Stock workerd does NOT unlink its listening Unix socket on exit, so the
  harness removes the stale socket before each `Ensure` (the prior generation is
  stopped first, so no race).
- The `cpu-limit` probe fires the fixture `/spin` and keeps the request open;
  the kernel throttles it (cpu.stat), then supervisor SIGKILL + recycle. Live
  result: cpu.max 50000/100000 enforced, ~20 throttled periods over a 2 s
  window; in-isolate cpuMs confirmed not firing.
- WSL2 DOES enforce `memory.max` with OOM (verified: `memory.events.oom_kill`
  increments, `memory.peak` capped). The `pressure-recycle` probe allocates via
  `/allocate` in 16 MiB steps to OOM; with `swap.max=0` the terminal OOM is
  fast, so it is inferred from the failed request/sample corroborated by
  `memory.current` climbing to ≥ 3/4 of the cap. Use `memoryMaxBytes` ≈ 256 MiB.
- Reconstruction (kill and pressure) commits worker state to the acknowledged
  checkpoint store, faults, then requires a NEW initialization instance (a fresh
  isolate — only whole-shard destruction yields one on this pin) plus a replayed
  checkpoint value.
- `dynamic-worker-reconstruction` records FAIL: `/spin` is never aborted within
  its window (cpuMs unenforced), so no per-isolate reconstruction. It returns
  PASS only on a genuine reconstruction (impossible here), which trips the
  evaluator's framing error.

The external RED negative control is retained
(`TestResourceGateIsNotSatisfiedByTheWorkerdTestPath`). Remaining before
production promotion: a run on a production install profile (the current
evidence is a development WSL2 host) and the final acceptance close.

Live cgroup provisioning recipe (WSL2): manually-created cgroups do NOT
survive across separate `wsl.exe` invocations — provision and run in one
invocation. As root in one shell: enable controllers in the parent
(`echo '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control`), create
the domain (`mkdir /sys/fs/cgroup/<root>`), own it to the runner uid/gid at
mode 0700, enable controllers in ITS subtree_control
(`echo '+cpu +memory +pids' > /sys/fs/cgroup/<root>/cgroup.subtree_control`),
then run the probe with the runner's effective uid matching the owner (running
the whole invocation as root, root-owned root, works for a smoke). Passwordless
sudo is unavailable; use `wsl -u root`. Root-run Go tests leave root-owned
files in a shared GOCACHE — use a separate GOCACHE for root vs user runs.

### U10.5 and beyond

- U10.5: the provisioned-host external run is done (dev host); the acceptance
  ledger (`docs/acceptance.md`) and operator guide (`docs/unit10-operator.md`)
  record it without promoting §53 or `AdmissionReady`. Remaining: the full
  race/vet + TypeScript gates and a production install-profile run before the
  unit closes.
- Units 11 and 12 remain queued after Unit 10. Private
  `platformd`-to-`agentd` workload composition and Phase 1A NsJail work are
  later, separately planned cuts.

## Open constraints that must remain explicit

- `PlacementRequest.Now` is currently trusted because only the in-process
  composition constructs it. Manager does not own a clock or authenticate and
  monotonic-fence the value. Before any workload-facing admission surface, add
  a Manager-owned clock or a sealed trusted-time input with backward, future,
  and concurrent-expiry tests. This is local risk `ARCH-003`.
- The same-UID delegated cgroup controller is reference evidence, not a
  complete authority boundary against a compromised workerd process.
- `cmd/agentd` remains diagnostic-only and `AdmissionReady` remains false.
- Unit tests and fakes cannot promote external status. All five named Unit 10
  results must be fresh non-mock `PASS` values from one release-, host-, boot-,
  cgroup-, runner-, and run-bound envelope.
- The final external gate needs a provisioned Linux host with the pinned
  workerd executable, cgroup v2 delegation and controllers, permission to
  create/kill/remove leaves, and required private-socket support. If that host
  is unavailable, record `UNAVAILABLE` and leave Unit 10 incomplete.

## Commit and workspace discipline

- Preserve RED, then GREEN, then focused race/shuffle evidence for every
  behavioral slice.
- Keep launcher attachment, observer lifecycle, reconstruction contracts,
  external composition, and final acceptance as separate commits.
- Stay on the current branch unless explicitly instructed otherwise.
- Stage only files owned by the current slice.
- Never commit `RISK_REGISTER.md`, root `MISTAKES.md`, `STAGING.md`, or
  `DONE.md`.
- Do not infer permission to deploy or mutate infrastructure from this plan.
