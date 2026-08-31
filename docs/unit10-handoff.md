# Unit 10 continuation handoff

Updated: 2026-09-01

This is the restart point for continuing Unit 10 on another machine. Read
`SPEC.md`, then `docs/implementation-plan.md`, then this file. The normative
contract remains `SPEC.md`; this file records implementation state and the safe
next TDD boundary only.

## Resume checkpoint

- Git origin: `https://github.com/seo-rii/circulusd.git`
- Go module: `github.com/hancomac/circulusd`
- Branch: `main`
- Go version: `1.25.0`
- Last implementation commit: `f6e9f80` (`feat(agent): own pidfd process identities`)
- This handoff is committed immediately after that implementation commit with
  subject `docs: record unit ten handoff`.
- At preparation time `origin/main` is `9ab2104`; the three implementation
  commits `5aa7fa5`, `be0e0af`, and `f6e9f80` are local, and this documentation
  commit makes the local branch four commits ahead. No push was performed.
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

The final implementation checks before this handoff passed:

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

## Exact next TDD work unit: launcher process-token attachment

Do not begin with the serialized observer. First attach the completed pidfd
owner to `WorkerdProcessLauncher` and prove its lifecycle independently.

Expected implementation scope:

- `internal/agent/workerd_launcher_linux.go`
- `internal/agent/workerd_launcher_linux_test.go`
- `internal/agent/workerd_cgroup_launcher_linux_test.go` only where fake PIDs
  require an injected identity capturer
- `internal/agent/workerd_process_linux.go` and its tests only for a minimal
  attachment API correction discovered by a preceding RED
- `docs/implementation-plan.md`

Write focused failing tests first for all of these boundaries:

1. After `starter.Start` succeeds, capture the exact pidfd/start-time owner
   before starting `Wait`, readiness, observation, or handle publication.
2. Capture failure starts exactly one process/cgroup cleanup owner, calls no
   readiness callback, and publishes no handle.
3. Store the exact owner on `workerdInstance`; never reconstruct identity from
   a later numeric PID lookup.
4. A retryable process-group timeout or pre-removal cgroup failure retains the
   identity owner for the next cleanup epoch.
5. Natural exit, readiness failure, replacement, successful `Handle.Stop`, and
   `Launcher.Close` each close the owner exactly once only after process and
   observation borrows are quiescent.
6. pidfd close failure is terminal and replayed without another close syscall.
7. No launcher or instance mutex is held across pidfd capture, `/proc` I/O,
   borrow quiescence, close, readiness callbacks, or process cleanup waits.
8. An old generation owner cannot sample, close, or otherwise act on its
   replacement.

Keep process-token attachment as one coherent commit. Do not add the observer
loop in the same commit.

## Following TDD work unit: serialized observation lifecycle

Only after launcher attachment is green, add exactly one observer owner for
each adopted shard generation. The producer must:

- obtain a complete pinned cgroup sample and exact process-RSS sample before
  allocating the next sequence;
- compare cumulative `memory.events` and `cpu.stat` values with baselines from
  that exact generation;
- deliver an immutable `ShardObservation` with the exact boot/shard/generation
  tuple;
- serialize sequence assignment, allow gaps only after a fully formed sample,
  never wrap `uint64`, and recycle or fail closed before exhaustion;
- suppress a sample if cancellation wins after I/O but before sink delivery;
- call the Manager sink without launcher, instance, cgroup, process-owner, or
  Manager locks held;
- cancel and join before the generation's final cleanup closes its process and
  cgroup owners.

Beware the self-stop cycle: `Manager.Observe` can drain a zero-session shard.
If `ShardProcess.Stop` synchronously cancels and joins the observer that is
currently blocked inside the Manager sink, it deadlocks. A preceding RED must
prove that observation-triggered cleanup is transferred to a detached cleanup
owner so the sink returns before observer join. Caller cancellation may stop a
wait, but it must not abandon that cleanup owner.

## Work after observation delivery

Continue the numbered plan without widening the cut line:

1. U10.3: distinct Dynamic Worker reconstruction, cgroup pressure recycle, and
   explicit pinned-process `SIGKILL` reconstruction, all from an externally
   acknowledged checkpoint.
2. U10.4: release-snapshot-to-launcher composition, persistent private socket,
   real CPU/RSS/reconstruction probes, status mapping, canonical artifacts, and
   atomic evidence retention.
3. U10.5: complete race/vet/TypeScript gates, provisioned-host external run,
   leak finalization, acceptance ledger, and operator documentation.
4. Units 11 and 12 remain queued after Unit 10. Private
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
