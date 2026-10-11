import { describe, expect, it } from "vitest";
import {
  decodeCanonicalCbor, digestBytes, digestStructuredValue, encodeCanonicalCbor,
  rehydrateAgentCheckpoint, type AgentCheckpoint, type Digest, type NormalizedValue,
} from "@circulusd/protocol-types";
import { LowLevelPiAgentEngine } from "../../pi-runtime/src/engine.ts";
import { createOpaqueTurnAuthority } from "../../pi-runtime/src/authority.ts";
import type { AgentCoreFactory } from "../../pi-runtime/src/types.ts";
import { SessionCell, WorkspaceCell, sessionCellName, workspaceCellName } from "../src/host/index.ts";
import { HOST_RPC_CONTRACTS, type HostRpcOperation, type HostRpcResponse } from "../src/host/rpc.ts";
import {
  turnInputDigest, type SessionAggregateState, type SessionCommand, type SessionEffect,
  type SessionFence, type SessionPayloadRef,
} from "../src/session/index.ts";
import type { WorkspaceAuthoritySnapshot, WorkspaceCommand, WorkspaceLeaseFence } from "../src/workspace/index.ts";
import { RestartableDurableStorage } from "./support/restartable-durable-storage.ts";

const NOW = 1_000;
const digest = (byte: string): Digest => `sha256:${byte.repeat(64)}`;
const IDENTITY = { sessionId: "reference-session", runtimeRevisionDigest: digest("1"), adapterAbiVersion: 1, checkpointSchemaVersion: 1 };
const INPUT = { messages: [{ role: "user", content: "Persist this workspace note exactly once." }] };
const EVIDENCE = { referenceOnly: true, productionEligible: false, conformanceClaimed: false, nativeSandboxExecuted: false } as const;
type Fault = "dispatch-start" | "workspace-commit" | "external-commit" | "settlement" | "terminal";
interface Observations { workspaceOperations: number; coreConstructions: number; freshClaims: number; reusedClaims: number; ledgerLookups: number }

async function rpc<Result>(operation: HostRpcOperation, payload: unknown, invoke: (request: unknown) => Promise<HostRpcResponse<Result>>): Promise<Result> {
  const response = await invoke({ protocol: "circulus.v1alpha1", major: 1, minor: 0,
    schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest, requestId: `reference-${operation}`, payload });
  if (!response.payload.ok) throw Object.assign(new Error(response.payload.error.message), { code: response.payload.error.code });
  return response.payload.result as Result;
}

/** Only Cells and engine checkpoints hold progress. Counters observe operations;
 * they are never consulted to decide whether a side effect may execute. */
class ReferenceComposition {
  readonly evidence = EVIDENCE;
  readonly session: SessionCell;
  readonly workspace: WorkspaceCell;
  readonly sessionStorage: RestartableDurableStorage;
  readonly workspaceStorage: RestartableDurableStorage;
  readonly observations: Observations;
  constructor(source?: ReferenceComposition) {
    this.sessionStorage = source?.sessionStorage.restart() ?? new RestartableDurableStorage();
    this.workspaceStorage = source?.workspaceStorage.restart() ?? new RestartableDurableStorage();
    this.observations = source?.observations ?? { workspaceOperations: 0, coreConstructions: 0, freshClaims: 0, reusedClaims: 0, ledgerLookups: 0 };
    const id = (name: string) => ({ toString: () => name, equals: (other: unknown) => String(other) === name });
    const env = { SESSION_CELL: { idFromName: id }, WORKSPACE_CELL: { idFromName: id } };
    this.session = new SessionCell({ storage: this.sessionStorage, id: id(sessionCellName("tenant", IDENTITY.sessionId)) } as never, env as never, () => NOW);
    this.workspace = new WorkspaceCell({ storage: this.workspaceStorage, id: id(workspaceCellName("tenant", "workspace")) } as never, env as never, () => NOW);
  }
  restart() { return new ReferenceComposition(this); }
  engine(): LowLevelPiAgentEngine {
    const factory: AgentCoreFactory = () => {
      this.observations.coreConstructions += 1;
      return { async advance(context) {
        if (context.input.kind === "turn_start") {
          expect(context.input.input).toEqual(INPUT);
          return { kind: "tool_requests", state: { input: context.input.input }, requests: [{
            service: "workspace", operation: "workspace.commit", replayPolicy: "idempotency-key",
            payload: { files: [{ path: "note.txt", content: "Reference operation committed once." }] },
          }] };
        }
        if (context.input.kind !== "tool_settlements" || context.input.results.length !== 1) throw new Error("expected one workspace settlement");
        const result = context.input.results[0]!;
        expect(result.request.service).toBe("workspace");
        expect(result.request.operation).toBe("workspace.commit");
        expect(context.state).toEqual({ input: INPUT });
        if (result.settlement.kind !== "success") throw new Error("expected committed workspace result");
        return { kind: "turn_complete", state: null, result: result.settlement.result };
      } };
    };
    return new LowLevelPiAgentEngine(IDENTITY, factory);
  }
  authority() {
    return { serviceBinding: "state", tenantId: "tenant", actorUserId: "user", subjectKind: "session", subjectId: IDENTITY.sessionId,
      roles: ["user"], permissions: ["session.read"], authorizationGeneration: 6, currentAuthorizationGeneration: 6, issuedAt: 1, expiresAt: 100_000 };
  }
  read() { return rpc("session.read", { authority: this.authority(), now: NOW }, (request) => this.session.readSession(request)); }
  execute(command: SessionCommand) { return rpc("session.execute", command, (request) => this.session.executeSessionCommand(request)); }
  workspaceExecute(command: WorkspaceCommand) { return rpc("workspace.execute", command, (request) => this.workspace.executeWorkspaceCommand(request)); }
  async readBytes(value: Digest): Promise<Uint8Array> {
    const blob = await rpc("session.read-blob", { authority: this.authority(), now: NOW, digest: value }, (request) => this.session.readSessionBlob(request));
    if (blob === null) throw new Error("durable blob is missing");
    expect(await digestBytes(blob.bytes)).toBe(value);
    expect(blob.encodedBytes).toBe(blob.bytes.byteLength);
    return blob.bytes;
  }
  async payload(inline: NormalizedValue | undefined, reference: SessionPayloadRef | undefined): Promise<NormalizedValue> {
    if (reference === undefined) return inline!;
    return decodeCanonicalCbor(await this.readBytes(reference.digest));
  }
  async checkpoint(state: SessionAggregateState): Promise<AgentCheckpoint> {
    const stored = state.activeTurn!.checkpoint;
    if ("payloadBytes" in stored) return stored;
    return rehydrateAgentCheckpoint(stored, await this.readBytes(stored.payloadDigest));
  }
  fence(state: SessionAggregateState): SessionFence {
    return { turnLeaseGeneration: state.activeTurn!.turnLeaseGeneration, placementGeneration: state.placementGeneration,
      sandboxGeneration: state.sandboxGeneration, authorizationGeneration: state.authorizationGeneration };
  }
  async initialize() {
    await rpc("session.initialize", { ...IDENTITY, tenantId: "tenant", userId: "user", workspaceId: "workspace",
      policySnapshotDigest: digest("2"), emergencyOverlayDigest: digest("3"), engineKind: "low-level",
      placementGeneration: 4, sandboxGeneration: 5, authorizationGeneration: 6 }, (request) => this.session.initializeSession(request));
    await rpc("workspace.initialize", { workspaceId: "workspace", tenantId: "tenant", initialRootDigest: digest("0") }, (request) => this.workspace.initializeWorkspace(request));
    const genesis = await this.engine().createGenesisCheckpoint({ turnId: "turn", input: INPUT, initialCoreState: null });
    await this.execute({ kind: "enqueue_turn", commandId: "admit", expectedEventSequence: 0, transactionTime: NOW,
      turnId: "turn", input: INPUT, inputDigest: await turnInputDigest(INPUT), genesisCheckpoint: genesis,
      turnLeaseGeneration: 10, leaseExpiresAt: 100_000,
      publicAdmission: { tenantId: "tenant", actorSubjectId: "user", authorizationGeneration: 6, idempotencyKeyDigest: digest("4"), requestDigest: digest("5") } });
  }
  claimCommand(state: SessionAggregateState, effect: SessionEffect): SessionCommand {
    const receipt = state.commandReceipts.find(({ outcome }) => outcome.kind === "effect_dispatched" && outcome.effectId === effect.effectId);
    if (receipt?.outcome.kind !== "effect_dispatched" || effect.lastDispatch === null) throw new Error("missing durable dispatch permit");
    return { kind: "claim_dispatch_start", commandId: "claim", expectedEventSequence: receipt.committedEventSequence,
      workspaceId: state.workspaceId, turnId: effect.turnId, effectId: effect.effectId, invocationId: effect.invocationId,
      requestDigest: effect.requestDigest, transactionTime: NOW, dispatchAttempt: effect.dispatchAttempt,
      fence: { turnLeaseGeneration: effect.lastDispatch.turnLeaseGeneration, placementGeneration: effect.lastDispatch.placementGeneration,
        sandboxGeneration: effect.lastDispatch.sandboxGeneration, authorizationGeneration: effect.lastDispatch.authorizationGeneration },
      providerRequestId: null, providerRouteDigest: digest("7"),
      dispatchPermitClaims: receipt.outcome.dispatchPermitClaims, commandDigest: digest("8") };
  }
  workspaceAuthority(state: SessionAggregateState, effect: SessionEffect, purpose: "admission" | "settlement"): WorkspaceAuthoritySnapshot {
    if (effect.service !== "workspace" || (effect.phase !== "dispatched" && effect.phase !== "externally_committed") || effect.lastDispatch === null) {
      throw new Error("only a dispatched workspace effect can mint reference workspace authority");
    }
    return { purpose, serviceBinding: "workspace", tenantId: state.tenantId, userId: state.userId, sessionId: state.sessionId,
      workspaceId: state.workspaceId, turnId: effect.turnId, runtimeRevision: state.runtimeRevisionDigest,
      policySnapshotDigest: state.policySnapshotDigest, emergencyOverlayDigest: state.emergencyOverlayDigest,
      effectivePermissions: ["workspace.read", "workspace.write"], sessionStatus: "active", turnStatus: "active",
      turnLeaseActive: true, turnLeaseExpiresAt: state.activeTurn!.leaseExpiresAt, effectStatus: effect.phase,
      effectService: effect.service, effectOperation: effect.operation, effectId: effect.effectId, invocationId: effect.invocationId,
      requestDigest: effect.requestDigest, replayPolicy: effect.replayPolicy, dispatchAttempt: effect.dispatchAttempt,
      // The schema requires a backend label. No process or sandbox is launched;
      // evidence explicitly forbids inferring native NsJail/cgroup qualification.
      sandboxId: "reference-sandbox", backend: "nsjail", ...this.fence(state), issuedAt: NOW, expiresAt: 10_000 };
  }
  async lookup(state: SessionAggregateState, effect: SessionEffect) {
    this.observations.ledgerLookups += 1;
    return rpc("workspace.lookup-invocation", { invocationId: effect.invocationId, requestDigest: effect.requestDigest,
      authority: this.workspaceAuthority(state, effect, "settlement"), now: NOW }, (request) => this.workspace.lookupWorkspaceInvocation(request));
  }
  async runWorkspace(state: SessionAggregateState, effect: SessionEffect, fault?: Fault) {
    const authority = this.workspaceAuthority(state, effect, "admission");
    const acquired = await this.workspaceExecute({ kind: "acquire_write_lease", expectedEventSequence: 0, now: NOW,
      authority, requestedLeaseId: "lease", sandboxId: "reference-sandbox", backend: "nsjail", projectionGeneration: 7,
      requestedLeaseTtlMs: 5_000, requestedMaximumHoldMs: 8_000, acquireDeadline: 9_000, waitPolicy: "fail" });
    if (acquired.outcome.kind !== "write_lease_acquired") throw new Error("expected workspace lease");
    const lease = acquired.outcome.lease;
    const leaseFence: WorkspaceLeaseFence = {
      leaseId: lease.leaseId, invocationId: lease.invocationId, requestDigest: lease.requestDigest, effectId: lease.effectId,
      sessionId: lease.sessionId, sandboxId: lease.sandboxId, leaseGeneration: lease.leaseGeneration,
      dispatchAttempt: lease.dispatchAttempt, turnLeaseGeneration: lease.turnLeaseGeneration, placementGeneration: lease.placementGeneration,
      sandboxGeneration: lease.sandboxGeneration, projectionGeneration: lease.projectionGeneration, authorizationGeneration: lease.authorizationGeneration,
    };
    await this.workspaceExecute({ kind: "prepare_materialization", expectedEventSequence: 1, now: NOW,
      ticketId: "ticket", accessMode: "read_write", requestedRevision: 0, authority, sandboxId: "reference-sandbox",
      backend: "nsjail", projectionGeneration: 7, leaseFence, ticketTtlMs: 4_000 });
    const input = await this.payload(effect.requestPayload, effect.requestPayloadRef);
    // This is the sole external-operation boundary. Recovery never calls it.
    this.observations.workspaceOperations += 1;
    const rootDigest = await digestBytes(encodeCanonicalCbor(input));
    if (fault === "workspace-commit") this.workspaceStorage.injectCrashOnce("after-commit-before-result");
    const committed = await this.workspaceExecute({ kind: "commit_workspace", expectedEventSequence: 2, now: NOW,
      materializationTicketId: "ticket", leaseFence, baseRevision: 0, workspaceCommitId: "workspace-commit",
      postExecutionRootDigest: rootDigest, referencedObjectDigests: [rootDigest],
      protectionProofs: [{ permitId: "reference-protection", tenantId: state.tenantId, objectDigest: rootDigest, guardGeneration: 1, status: "protected" }],
      authority: { ...authority, purpose: "settlement" } });
    if (committed.outcome.kind !== "workspace_committed") throw new Error("expected workspace commit");
    return committed.outcome.result;
  }
  async drive(fault?: Fault): Promise<NormalizedValue> {
    for (let transitions = 0; transitions < 12; transitions += 1) {
      const state = await this.read();
      if (state.activeTurn === null) {
        const terminal = state.terminalTurns[0];
        if (terminal?.status !== "completed") throw new Error("expected completed reference turn");
        return this.payload(terminal.result, terminal.resultPayloadRef);
      }
      const effect = state.effects.find((candidate) => candidate.turnId === state.activeTurn!.turnId);
      if (effect === undefined || effect.phase === "settled") {
        let settlement;
        if (effect !== undefined) {
          if (effect.settlement?.kind !== "success") throw new Error("expected durable success settlement");
          settlement = { requestDigest: effect.requestDigest, outcome: { kind: "success" as const,
            result: await this.payload(effect.settlement.result, effect.settlement.resultPayloadRef) } };
        }
        const step = await this.engine().step({ authority: createOpaqueTurnAuthority(new Uint8Array([1, 2, 3])), checkpoint: await this.checkpoint(state), ...(settlement === undefined ? {} : { settlement }) });
        if (effect !== undefined && step.kind !== "turn_complete") throw new Error("expected completed cold engine");
        if (fault === "terminal" && step.kind === "turn_complete") this.sessionStorage.injectCrashOnce("after-commit-before-result");
        await this.execute({ kind: "commit_engine_step", commandId: `engine-${step.checkpoint.checkpointSequence}`, expectedEventSequence: state.eventSequence,
          transactionTime: NOW, turnId: state.activeTurn.turnId, fence: this.fence(state), consumedSettlementEffectId: effect?.effectId ?? null,
          effectIdentity: step.kind === "effect_request" ? { effectId: "effect", invocationId: "invocation" } : null, step });
      } else if (effect.phase === "prepared") {
        await this.execute({ kind: "dispatch_effect", commandId: "dispatch", expectedEventSequence: state.eventSequence,
          turnId: effect.turnId, effectId: effect.effectId, invocationId: effect.invocationId, requestDigest: effect.requestDigest,
          fence: this.fence(state), transactionTime: NOW, deadline: 9_000, providerRouteDigest: digest("7") });
      } else if (effect.phase === "dispatched" || effect.phase === "externally_committed") {
        let result;
        if (effect.phase === "dispatched") {
          if (fault === "dispatch-start") this.sessionStorage.injectCrashOnce("after-commit-before-result");
          const claim = await this.execute(this.claimCommand(state, effect));
          if (claim.outcome.kind !== "dispatch_start_claimed") throw new Error("expected dispatch start claim");
          if (claim.outcome.fresh) {
            this.observations.freshClaims += 1;
            result = await this.runWorkspace(state, effect, fault);
          } else this.observations.reusedClaims += 1;
        }
        if (result === undefined) {
          const ledger = await this.lookup(state, effect);
          if (ledger === null) throw new Error("claimed operation requires recovery evidence; it cannot be rerun");
          result = ledger.result;
        }
        const latest = await this.read();
        if (effect.phase === "dispatched") {
          if (fault === "external-commit") this.sessionStorage.injectCrashOnce("after-commit-before-result");
          await this.execute({ kind: "record_external_commit", commandId: "external-commit", expectedEventSequence: latest.eventSequence,
            turnId: effect.turnId, effectId: effect.effectId, invocationId: effect.invocationId, requestDigest: effect.requestDigest,
            dispatchAttempt: effect.dispatchAttempt, fence: this.fence(latest), externalCommitId: result.workspaceCommitId,
            resultRef: await digestStructuredValue("reference.workspace.result", 1, result) });
        } else {
          if (fault === "settlement") this.sessionStorage.injectCrashOnce("after-commit-before-result");
          await this.execute({ kind: "settle_effect", commandId: "settlement", expectedEventSequence: latest.eventSequence,
            turnId: effect.turnId, effectId: effect.effectId, invocationId: effect.invocationId, requestDigest: effect.requestDigest,
            dispatchAttempt: effect.dispatchAttempt, fence: this.fence(latest), settlement: { kind: "success", result: { ...result } } });
        }
      } else throw new Error(`unexpected reference effect phase: ${effect.phase}`);
    }
    throw new Error("reference orchestration exceeded its bounded transition count");
  }
}

describe("U13.3 actual Cell reference orchestration", () => {
  it("does not execute after a lost start-claim response without a committed invocation", async () => {
    const initial = new ReferenceComposition();
    await initial.initialize();
    await expect(initial.drive("dispatch-start")).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
    const restored = initial.restart();
    const revision = restored.sessionStorage.durableRevision;
    await expect(restored.drive()).rejects.toThrow("claimed operation requires recovery evidence; it cannot be rerun");
    expect(restored.observations.workspaceOperations).toBe(0);
    expect(restored.observations.freshClaims).toBe(0);
    expect(restored.observations.reusedClaims).toBe(1);
    expect(restored.workspaceStorage.durableRevision).toBe(1);
    expect(restored.sessionStorage.durableRevision).toBe(revision);
    expect((await restored.read()).effects[0]).toMatchObject({ phase: "dispatched", invocationId: "invocation", dispatchAttempt: 1 });
  });

  for (const fault of [undefined, "workspace-commit", "external-commit", "settlement", "terminal"] as const) {
    it(`completes one engine workspace effect after ${fault ?? "no crash"}`, async () => {
      const initial = new ReferenceComposition();
      expect(initial.evidence).toEqual(EVIDENCE);
      await initial.initialize();
      let restored = initial;
      if (fault !== undefined) {
        await expect(initial.drive(fault)).rejects.toMatchObject({ code: "INTERNAL_ERROR" });
        expect(initial.observations.workspaceOperations).toBe(1);
        const afterFault = await initial.read();
        const faultState = {
          "workspace-commit": { sequence: 4, phase: "dispatched" },
          "external-commit": { sequence: 5, phase: "externally_committed" },
          settlement: { sequence: 6, phase: "settled" },
          terminal: { sequence: 7, phase: "settled" },
        }[fault];
        expect(afterFault.eventSequence).toBe(faultState.sequence);
        expect(afterFault.effects[0]?.phase).toBe(faultState.phase);
        expect(afterFault.activeTurn === null).toBe(fault === "terminal");
        expect(initial.workspaceStorage.durableRevision).toBe(4);
        if (fault === "workspace-commit" || fault === "external-commit") {
          const ledger = await initial.lookup(afterFault, afterFault.effects[0]!);
          expect(ledger).toMatchObject({ invocationId: "invocation", requestDigest: afterFault.effects[0]!.requestDigest,
            result: { workspaceCommitId: "workspace-commit", revision: 1 } });
        }
        restored = initial.restart();
        expect(restored.session).not.toBe(initial.session);
        expect(restored.workspace).not.toBe(initial.workspace);
      }
      const result = await restored.drive();
      expect(result).toMatchObject({ workspaceCommitId: "workspace-commit", revision: 1 });
      const state = await restored.read();
      expect(state.activeTurn).toBeNull();
      expect(state.eventSequence).toBe(7);
      expect(state.commandReceipts.map((receipt) => receipt.committedEventSequence)).toEqual([1, 2, 3, 4, 5, 6, 7]);
      expect(state.effects).toHaveLength(1);
      expect(state.effects[0]).toMatchObject({ service: "workspace", operation: "workspace.commit", phase: "settled",
        invocationId: "invocation", dispatchAttempt: 1, externalCommitId: "workspace-commit", consumedAtCheckpointSequence: 2 });
      const events = await rpc("session.read-events", { authority: restored.authority(), now: NOW, afterSequence: 0, limit: 20 }, (request) => restored.session.readSessionEvents(request));
      expect(events.events.map((event) => event.sequence)).toEqual([1, 2, 3, 4, 5]);
      expect(events.events.map((event) => event.type)).toEqual(["turn.accepted", "tool.effect.prepared", "tool.externally_committed", "tool.settled", "turn.completed"]);
      expect(restored.observations.workspaceOperations).toBe(1);
      expect(restored.observations.freshClaims).toBe(1);
      expect(restored.observations.coreConstructions).toBe(2);
      expect(restored.workspaceStorage.durableRevision).toBe(4);
      const revision = restored.sessionStorage.durableRevision;
      const replayedClaim = await restored.execute(restored.claimCommand(state, state.effects[0]!));
      expect(replayedClaim).toMatchObject({ replayed: true, outcome: { kind: "dispatch_start_claimed", fresh: false } });
      expect(await restored.restart().drive()).toEqual(result);
      expect(restored.sessionStorage.durableRevision).toBe(revision);
      expect(restored.workspaceStorage.durableRevision).toBe(4);
      expect(restored.observations.workspaceOperations).toBe(1);
      if (fault === "workspace-commit") expect(restored.observations.reusedClaims).toBe(1);
    });
  }
});
