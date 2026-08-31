# Architecture decisions

Status: accepted for the v0.3 implementation baseline

Date: 2026-08-26

These decisions close protocol gaps in `SPEC.md` without weakening its MUST/MUST NOT requirements. A later incompatible change requires a new decision record, a persisted-state migration, and a compatibility gate.

## ADR-001: Agent execution ends at every durable boundary

One engine invocation consumes one committed checkpoint and at most one unconsumed settlement. It may emit ephemeral deltas, then returns exactly one durable boundary and terminates.

```ts
interface AgentEngine {
  step(context: EngineStepContext): Promise<EngineStepResult>;
  abortTurn(turnId: string): Promise<void>;
}

type EngineStepResult =
  | { kind: "checkpoint"; checkpoint: AgentCheckpoint }
  | { kind: "effect_request"; checkpoint: AgentCheckpoint; request: EffectIntent }
  | { kind: "turn_complete"; checkpoint: AgentCheckpoint; result: TurnResult }
  | { kind: "turn_error"; checkpoint: AgentCheckpoint; error: AgentError };
```

The Pi adapter may use an upstream iterator internally, but no iterator remains suspended across external I/O. Pending tool calls and lifecycle position are checkpoint bytes. `abortTurn` is a best-effort execution interrupt; Session DO is the durable abort authority.

An accepted turn always receives a platform-owned genesis checkpoint. Engine checkpoints increment `checkpointSequence` by exactly one and bind their predecessor digest, session, turn, runtime revision, adapter ABI, and schema version.

## ADR-002: Session DO issues an opaque dispatch permit

`prepared` means no valid dispatch permit has ever existed. Before external I/O, Session DO validates the active turn, effect, request digest, service binding, and all generations; atomically records the next dispatch attempt; waits for the durable storage barrier; and returns an opaque permit.

The permit binds:

- tenant, user, session, turn, and effect identity;
- invocation ID and request digest;
- service and operation;
- dispatch attempt;
- turn-lease, placement, sandbox, and authorization generations;
- deadline for starting this admission.

Every broker rejects a request without a current matching permit. The durable `dispatched` state means external I/O may or may not have occurred. A crash after permit issuance is therefore classified by the effect replay policy and any external ledger; it is never inferred from process state.

The Session dispatch permit is not handed directly to a service adapter. The
broker first consumes an atomic, durable, single-start claim and then wraps the
exact receipt in a process-local sealed value whose zero value cannot authorize
I/O. Model, MCP, and reference-effect adapters may open that value only to
compare it with an immutable subordinate command. They cannot mint another
start authority. A subordinate ledger is selected by the Session-bound service
and every result, including `absent` and `unknown`, must repeat the complete
effect, invocation, request, attempt, platform request, and route identity.
Opaque Session bearers are stripped after verification and are neither stored
in the subordinate command nor forwarded to a provider; an adapter may pass
only its own package-sealed, non-secret exact binding for the active call.

A terminal reconciler never receives provider-start authority. It first asks
the Session coordinator for the current recovery decision and may issue a
settlement only for `settle_only` with the exact subordinate attempt, external
commit, result, and settlement digest. Once Session is already settled, that
same operation may only replay the original durable receipt; it cannot create
a second transition or consult the provider again.

## ADR-003: Turn status and effect state are separate

Turn status is one of `queued`, `active`, `needs_confirmation`, `completed`, `failed`, or `aborted`.

Effect state is one of:

```text
prepared
  → dispatched
  → externally_committed
  → settled

prepared → settled             validation/cancellation before dispatch
dispatched → blocked           uncertain confirm-policy effect
blocked → dispatched           explicit confirmed retry only
blocked → externally_committed external proof supplied
blocked → settled              explicit abandon/interrupted result
```

At most one effect occupies `activeEffectId`. A settled effect continues to occupy it until an engine checkpoint consumes the settlement.

In one Session DO transaction, the platform records settlement consumption, commits the next checkpoint, clears the prior active effect, and optionally prepares the next effect. A crash before that transaction reinjects the same settlement; a crash after it does not.

`safe` and `idempotency-key` retries keep the invocation ID and increment only the dispatch attempt. A `never` effect resolves to an interrupted-unknown result without automatic replay. A `confirm` effect enters `needs_confirmation` and blocks later turn admission.

## ADR-004: Composite operations flatten to sequential leaf effects

An external effect cannot recursively call another raw broker. A composite tool is checkpointed logical control flow that returns either one child effect request or a final result.

Child effects have a stable parent operation ID and ordinal but otherwise use the normal leaf effect protocol. Only one leaf is active at a time. If a native command can hide network or filesystem side effects internally, that whole command is one leaf and its manifest replay policy covers the complete risk.

## ADR-005: Workspace leases are invocation-bound and renewable

A mutable lease binds invocation ID, request digest, effect, session, sandbox and projection generations, base revision, lease generation, issue/expiry times, a maximum hold deadline, and a monotonic renewal sequence.

Acquisition is idempotent for the same invocation and digest. A queued retry retains its FIFO position. Renewal accepts only the next sequence for the same current generations; retrying the same sequence returns the same expiry. Renewal cannot exceed the maximum hold deadline.

After expiry, renewal and commit fail even if no replacement owner exists. Reacquisition uses a new generation and a newly materialized projection. An already dispatched effect still follows its replay policy; lease reacquisition alone never authorizes re-execution.

If renewal fails, executord stops further stdin/child admission, cancels the process group or cgroup, and quarantines the sandbox. Generation fencing protects durable state even if process cleanup is delayed.

Workspace revision, invocation ledger result, and lease consumption/release commit in one Workspace DO transaction. Session settlement does not extend the Workspace lease.

## ADR-006: Structured digests use deterministic CBOR

Raw file bytes use `sha256(rawBytes)`. Structured values use RFC 8949 Core Deterministic Encoding:

```text
sha256(
  deterministic-cbor([
    "circulusd.hash",
    1,
    domain,
    schemaVersion,
    normalizedPayload
  ])
)
```

External text is NFC UTF-8. Floating-point values, NaN, infinity, unknown fields, and duplicate normalized keys are rejected. Schema-defined sets are sorted by UTF-8 bytes; sequences preserve order. Digests use `sha256:` plus lowercase hexadecimal.

Workspace tree entries exclude inode, uid, gid, and timestamps. Modes normalize to `0644` or `0755` for files, `0755` for directories, and `0777` for symlinks. Flat and directory-object representations calculate the same logical root digest.

Go and TypeScript golden vectors are authoritative compatibility fixtures.

## ADR-007: GC uses protect-before-reference and two-epoch deletion

Creation-time grace alone cannot protect an old, currently unreferenced blob that a concurrent Workspace commit reuses. Every blob and tree object therefore has a tenant-scoped guard record with a generation and one of `live`, `candidate`, `deleting`, or `deleted`.

Before a new durable root references a digest, the writer obtains a protection permit by CAS. The Workspace transaction commits the reference and permit ID together; a reconciler finalizes any permit left pending after a crash. Pending permits are not removed solely by elapsed wall time.

The first unmarked epoch may move `live` to `candidate`. A later successful mark may resurrect a candidate. Physical deletion requires a later epoch, elapsed grace, a second complete root export, and an atomic candidate-generation transition to `deleting`.

If protection wins, the deletion CAS fails. If deletion wins, protection fails with `OBJECT_DELETING`; the caller restores/reuploads the immutable bytes, protects the new incarnation, and only then retries the root commit. A failed root export prevents sweep for that partition.

## ADR-008: Immutable policy and live emergency fencing are distinct

Runtime Revision contains immutable `policySnapshotDigest`. Session state contains monotonic `authorizationGeneration` and `emergencyOverlayDigest`.

Normal policy changes create a new Runtime Revision and activate only at a turn boundary. ACL revocation, credential incidents, and emergency tightening rotate `authorizationGeneration` immediately. Effective policy is the intersection of the immutable snapshot and emergency overlay.

An overlay may tighten an active turn but cannot widen it. Relaxation waits for the next turn boundary. A trusted reconciler may receive settlement-only authority for an already dispatched effect after generation rotation; it cannot admit a new dispatch.

Sandbox cache keys contain the canonical effective-policy digest, not merely a generation number.

## ADR-009: Authority-local queues are strict FIFO

Session DO assigns monotonic turn enqueue sequences. Workspace DO assigns monotonic lease enqueue sequences. Timestamps and caller priority do not determine order.

Idempotent retry does not allocate a new sequence. Cancelled or timed-out heads are skipped transactionally. `cancel-previous` records an abort request and adds the replacement at the FIFO tail; it does not create two active turns. A confirm-policy uncertain effect remains the sole active turn until resolved.

Read-only invocations do not join the writer queue. Lease maximum hold time prevents indefinite renewal starvation.

## ADR-010: Public idempotency is durable and scoped

The key scope is:

```text
tenantId
+ authenticated subjectId
+ HTTP method
+ canonical route template
+ target resource ID, when present
+ keyed digest of Idempotency-Key
```

The request digest covers the normalized effective body, mutation-relevant query/header values, and path parameters. The same key and digest returns the same operation/resource. The same key with a different digest returns `409 IDEMPOTENCY_KEY_REUSED` without disclosing another subject's result.

Target-local mutations store records in their authority DO. Workspace and Session creation use a tenant/user control-object saga that first reserves a stable resource ID, idempotently initializes the target DO, then finalizes the creation record.

Authentication and authorization happen before idempotency lookup. Public API idempotency and external invocation ledgers are separate concepts.

## ADR-011: Protocol and conformance classes fail closed

Host-daemon RPC uses generated Protobuf/Connect messages over UDS. The control
transport accepts only a canonical socket beneath a private, owner-controlled
directory, pins the socket identity across connection setup, checks kernel
`SO_PEERCRED`, and authorizes an explicit `(UID, claimed client role)` pair.
Independent UID and role allowlists may be used only when they cannot create an
ambiguous authority cross-product.

The pre-operation handshake fixes protocol version, feature bitmap, maximum
frame size, and the checked descriptor digest. Its response proof binds the
one-time nonce to that descriptor and the expected server-role label; the
sandbox handshake additionally binds sandbox identity and generation. This
prevents endpoint/role confusion inside the UDS authority boundary. It is not
component identity attestation: the handshake carries and proves no daemon
binary, build, or release digest, and a process already trusted under the same
socket-directory and UID boundary remains part of the trusted computing base.

Sandbox backend and execution-environment identity are a separate launch-time
binding. The trusted launcher must supply one real backend and one canonical
SHA-256 environment digest before `sandboxd` reads its one-use nonce or opens
the listener. The server retains immutable copies and rejects a `Spawn`
`SandboxHandle` that does not match them before invoking the runner. This keeps
one sandbox ID/generation from being replayed against another backend or image;
it does not turn the nonce proof into binary or image attestation.

Control and sandbox request metadata deadlines are bounded at five minutes;
clients without a deadline use 30 seconds. Servers allow five seconds for the
whole request read and a five-minute-five-second write horizon. The final five
seconds are transport headroom for delivering a deadline result to a slow
reader, not additional operation authority. The doctor daemon probe retains a
separate, shorter 30-second shared budget across all three control endpoints.

TypeScript Worker/state RPC uses one pinned runtime-validated schema package. Structured clone is transport only. Every envelope has protocol version, schema digest, request ID, size/depth limits, and explicit byte/integer rules. Persisted checkpoint payloads are opaque bytes with an encoding and digest, never arbitrary class instances.

Go import boundaries are directional: unprivileged commands may import protocol and narrow clients, but only `cmd/executord` reaches provider, mount, cgroup, Docker, or KVM implementation packages.

Conformance results are exactly `PASS`, `FAIL`, `UNAVAILABLE(reason)`, or `NOT_RUN`. Unit/domain, deterministic fault, and local mock tests never count as real celld, workerd/Pi, backend, or air-gap conformance. A required release profile treats every result other than `PASS` as failure. The `mock` backend is development-only and cannot satisfy a request for NsJail, Docker, or Firecracker.

`platformctl doctor` emits a versioned evidence snapshot bound to the selected
profile and required-component set, configuration and release digests, host,
runner binary, target boot instance, probe run, observation time, and explicit
evidence classes. Its UDS artifacts identify the checked protocol descriptor;
they deliberately omit a daemon `binaryDigest`. The top-level
`runnerBinaryDigest` identifies the reporting `platformctl` executable, not any
probed daemon. The report is unsigned diagnostic evidence, is not consumed by
daemon startup, and cannot itself authorize admission. Any future startup gate
must independently authenticate current component builds/releases and
revalidate the exact target rather than trusting report summary booleans.

Report generation sorts required components, results, and each result's
artifact references by their canonical keys. The JSON Schema checks bounded
wire structure, but it cannot establish current identity, ordering across
semantic keys, evidence freshness, or a valid qualification summary. Retained
reports therefore require `internal/doctor.ValidateCurrent`. Freshness begins
at `StartedAt`, covers the complete evidence window, rejects future
`FinishedAt`/`ObservedAt` values, and has an absolute 24-hour ceiling.

## ADR-012: Production and development daemon graphs are separate binaries

The production `platformd` and local `platformd-dev` commands use separate
composition roots. They may share generated protocol types, the credentialed
control server, and listener/runtime shutdown plumbing, but their flags,
constructed dependency graphs, and readiness claims remain separate.
Production does not accept a runtime-profile switch or import
reference-memory/fake providers. Development does not accept production
configuration, release roots, secret-bearing credential files, or privileged
execution providers.

Production opens no public/application listener until the complete production
graph has passed every required gate. A credentialed diagnostic UDS is the sole
exception: it may remain available after bootstrap failure, but it cannot
publish a partial graph and reports all uncomposed capabilities as `NOT_WIRED`.
A state-only graph is not the production graph and is closed immediately.

The initial `development-reference` graph is intentionally diagnostic-only. It
binds an exact canonical loopback address, rechecks the kernel-returned address,
and exposes immutable `/v1/status` metadata with
`productionEligible=false` and `admissionEnabled=false`. It does not construct
the legacy Go `MemoryStore`, a fake executor, Session routes, or readiness. Those
claims may change only when the corresponding dependency is actually composed
and its limitations are reported explicitly.

## ADR-013: Initial agentd and executord shells are control-only

The first `agentd` and `executord` commands bind only their private diagnostic
control UDS and require at least one explicit platformd or platformctl UID-role
authority. Their daemon-role and control-protocol capabilities are available;
workerd management, isolation, execution environments, and privileged backend
capabilities remain `NOT_WIRED`, with admission and production eligibility
fixed false. They have no application listener or workload provider dependency.
A successful handshake or `uds.protocol` probe therefore proves only the live
local control boundary, not daemon workload readiness or any §53 runtime gate.
The `/run/pi-platform/{platformd,agentd,executord}.sock` defaults are a local
single-node layout convention. A custom socket flag changes only the diagnostic
target for that invocation; the selected path is absent from retained component
identity, and neither it nor an available diagnostic shell is production
startup authority. The UDS probe's 30-second shared context is also not a hard
wall-clock guarantee: client construction performs synchronous,
context-free path metadata validation. The local `/run` convention assumes
responsive local metadata, while a custom FUSE/NFS-backed path may block beyond
the deadline and must not be treated as a bounded startup check.

The Unit 10 Phase 0A qualification harness may compose the existing internal
agent manager, workerd launcher, and cgroup controller to obtain real external
resource evidence. That harness is not an `agentd` workload graph and creates no
new application RPC or listener. Until a later unit binds an operational graph
to current release, state, placement, and private workload authority, the
`agentd` command keeps its operational capabilities `NOT_WIRED` and
`admissionEnabled=false` even when the targeted Phase 0A gate passes.

Phase 0A mechanical cgroup evidence also does not claim that a same-UID workerd
process cannot reopen delegated cgroup controls after a full process
compromise. Production composition must isolate that authority or place the
process inside a stronger outer boundary before it can become admission-ready.
