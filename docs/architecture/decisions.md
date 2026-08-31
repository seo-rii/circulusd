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

Host-daemon RPC uses generated Protobuf/Connect messages over UDS. A pre-mutation handshake binds protocol major/minor, feature bitmap, maximum frame size, build/release digest, and peer role. UDS filesystem permissions and peer credentials are method-level authorization inputs.

TypeScript Worker/state RPC uses one pinned runtime-validated schema package. Structured clone is transport only. Every envelope has protocol version, schema digest, request ID, size/depth limits, and explicit byte/integer rules. Persisted checkpoint payloads are opaque bytes with an encoding and digest, never arbitrary class instances.

Go import boundaries are directional: unprivileged commands may import protocol and narrow clients, but only `cmd/executord` reaches provider, mount, cgroup, Docker, or KVM implementation packages.

Conformance results are exactly `PASS`, `FAIL`, `UNAVAILABLE(reason)`, or `NOT_RUN`. Unit/domain, deterministic fault, and local mock tests never count as real celld, workerd/Pi, backend, or air-gap conformance. A required release profile treats every result other than `PASS` as failure. The `mock` backend is development-only and cannot satisfy a request for NsJail, Docker, or Firecracker.

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
