import { describe, expect, it, vi } from "vitest";
import {
  PROTOCOL_MAJOR,
  PROTOCOL_MINOR,
  PROTOCOL_NAME,
  digestBytes,
  externalizeAgentCheckpoint,
  type AgentCheckpoint,
  type Digest,
  type EngineStepResult,
} from "@circulusd/protocol-types";

import {
  SessionHost,
  type AgentEngine,
  type BrokerBindings,
  type CheckpointBlobReader,
  type DriveTurnOptions,
} from "../src/index.ts";
import {
  LowLevelPiAgentEngine,
  LowLevelPiSessionHostAdapter,
  createOpaqueTurnAuthority,
  type AgentCoreFactory,
} from "../../pi-runtime/src/index.ts";
import {
  SessionCell,
  sessionCellName,
} from "../../state-app/src/host/index.ts";
import {
  HOST_RPC_CONTRACTS,
  type HostRpcOperation,
  type HostRpcResponse,
} from "../../state-app/src/host/rpc.ts";
import type { ControlAuthoritySnapshot } from "../../state-app/src/control/index.ts";
import { turnInputDigest } from "../../state-app/src/session/index.ts";
import { RestartableDurableStorage } from "../../state-app/test/support/restartable-durable-storage.ts";

const digest = (value: string): Digest => `sha256:${value.repeat(64)}`;
const authority = () => new Uint8Array([31, 41, 59]);
const engineIdentity = {
  sessionId: "session-1",
  runtimeRevisionDigest: digest("1"),
  adapterAbiVersion: 1,
  checkpointSchemaVersion: 1,
};
const core: AgentCoreFactory = () => ({
  async advance(context) {
    if (context.input.kind === "turn_start") {
      return {
        kind: "model_request",
        state: { programCounter: "waiting-model" },
        request: {
          service: "model",
          operation: "complete",
          replayPolicy: "idempotency-key",
          payload: { prompt: context.input.input },
        },
      };
    }
    expect(context.state).toEqual({ programCounter: "waiting-model" });
    expect(context.input.kind).toBe("effect_settlement");
    return { kind: "turn_complete", state: { programCounter: "done" }, result: "restored" };
  },
});

function makeHost(checkpointBlobs?: CheckpointBlobReader, maximumCheckpointPayloadBytes?: number): SessionHost {
  const bindings: BrokerBindings = {
    STATE: {}, WORKSPACE: {}, MODEL: {}, MCP: {}, EXECUTOR: {}, ARTIFACTS: {}, EVENTS: {},
  };
  return new SessionHost({
    bindings,
    loader: { get: async () => ({}) },
    verifier: {
      verify: async () => ({ revisionDigest: digest("1"), runtimeIdentityDigest: digest("2") }),
    },
    ...(checkpointBlobs === undefined ? {} : { checkpointBlobs }),
    ...(maximumCheckpointPayloadBytes === undefined ? {} : { limits: { maximumCheckpointPayloadBytes } }),
  });
}

function options(checkpoint: unknown): DriveTurnOptions {
  return {
    turnId: "turn-1",
    authority: authority(),
    checkpoint,
    committer: { commit: vi.fn(async () => undefined) },
    ephemeralSink: { emit: vi.fn(async () => undefined) },
    maximumEvents: 8,
  };
}

async function rpc<Result>(
  operation: HostRpcOperation,
  payload: unknown,
  invoke: (request: unknown) => Promise<HostRpcResponse<Result>>,
): Promise<Result> {
  const response = await invoke({
    protocol: PROTOCOL_NAME,
    major: PROTOCOL_MAJOR,
    minor: PROTOCOL_MINOR,
    schemaDigest: HOST_RPC_CONTRACTS[operation].schemaDigest,
    requestId: `request-${operation}`,
    payload,
  });
  if (!response.payload.ok) {
    throw Object.assign(new Error(response.payload.error.message), { code: response.payload.error.code });
  }
  return response.payload.result as Result;
}

async function storedTurn() {
  const storage = new RestartableDurableStorage();
  const logicalName = sessionCellName("tenant-1", "session-1");
  const physicalId = (name: string) => ({
    toString: () => `physical:${name}`,
    equals: (other: unknown) => String(other) === `physical:${name}`,
  });
  const cell = new SessionCell(
    { storage, id: physicalId(logicalName) } as never,
    { SESSION_CELL: { idFromName: physicalId } } as never,
    () => 200,
  );
  const readAuthority: ControlAuthoritySnapshot = {
    serviceBinding: "state",
    tenantId: "tenant-1",
    actorUserId: "user-1",
    subjectKind: "session",
    subjectId: "session-1",
    roles: ["user"],
    permissions: ["session.read"],
    authorizationGeneration: 6,
    currentAuthorizationGeneration: 6,
    issuedAt: 1,
    expiresAt: 10_000,
  };
  await rpc("session.initialize", {
    ...engineIdentity,
    tenantId: "tenant-1",
    userId: "user-1",
    workspaceId: "workspace-1",
    policySnapshotDigest: digest("2"),
    emergencyOverlayDigest: digest("3"),
    engineKind: "low-level",
    placementGeneration: 4,
    sandboxGeneration: 5,
    authorizationGeneration: 6,
  }, (request) => cell.initializeSession(request));
  const engine = new LowLevelPiAgentEngine(engineIdentity, core);
  const input = { prompt: "hello" };
  const genesis = await engine.createGenesisCheckpoint({
    turnId: "turn-1", input, initialCoreState: null,
  });
  await rpc("session.execute", {
    kind: "enqueue_turn",
    commandId: "enqueue-1",
    expectedEventSequence: 0,
    transactionTime: 100,
    turnId: "turn-1",
    input,
    inputDigest: await turnInputDigest(input),
    genesisCheckpoint: genesis,
    turnLeaseGeneration: 10,
    leaseExpiresAt: 1_000,
    publicAdmission: {
      authorizationGeneration: 6,
      idempotencyKeyDigest: digest("a"),
      requestDigest: digest("b"),
    },
  }, (request) => cell.executeSessionCommand(request));
  const snapshot = () => rpc("session.read", { authority: readAuthority, now: 200 },
    (request) => cell.readSession(request));
  const reader: CheckpointBlobReader = {
    readBlob: async ({ turnId, authority: opaqueAuthority, checkpoint }) => {
      expect(turnId).toBe("turn-1");
      expect(opaqueAuthority).toEqual(authority());
      return rpc("session.read-blob", {
        authority: readAuthority, now: 200, digest: checkpoint.payloadDigest,
      }, (request) => cell.readSessionBlob(request));
    },
  };
  const commit = async (step: EngineStepResult) => {
    const current = await snapshot();
    return rpc("session.execute", {
      kind: "commit_engine_step",
      commandId: `step-${step.checkpoint.checkpointSequence}`,
      expectedEventSequence: current.eventSequence,
      transactionTime: 200,
      turnId: "turn-1",
      fence: {
        turnLeaseGeneration: 10, placementGeneration: 4,
        sandboxGeneration: 5, authorizationGeneration: 6,
      },
      consumedSettlementEffectId: null,
      effectIdentity: step.kind === "effect_request"
        ? { effectId: "effect-1", invocationId: "invocation-1" } : null,
      step,
    }, (request) => cell.executeSessionCommand(request));
  };
  return { engine, genesis, reader, snapshot, commit, readAuthority, storage };
}

describe("SessionHost externalized checkpoint consumer", () => {
  it("reads SessionCell blobs and reconstructs a cold Pi engine for both start and resume", async () => {
    const stored = await storedTurn();
    const initial = (await stored.snapshot()).activeTurn!;
    expect(initial.checkpoint).not.toHaveProperty("payloadBytes");
    const cold = new LowLevelPiAgentEngine(engineIdentity, core);
    const adapter = new LowLevelPiSessionHostAdapter(cold);
    const start = options(initial.checkpoint);
    const result = await makeHost(stored.reader).startTurn(adapter, {
      ...start,
      checkpointChainDigest: initial.checkpointChainDigest,
      committer: {
        commit: async (event) => {
          if (event.type !== "model_request") throw new Error("expected model boundary");
          await stored.commit({
            kind: "effect_request", checkpoint: event.checkpoint, request: event.request,
          } as EngineStepResult);
        },
      },
    });
    expect(result.boundary.type).toBe("model_request");
    const persisted = (await stored.snapshot()).activeTurn!;
    expect(persisted.checkpoint.checkpointSequence).toBe(1);
    expect(persisted.checkpoint.payloadDigest).not.toBe(initial.checkpoint.payloadDigest);
    const request = (result.boundary as { request: { requestDigest: Digest } }).request;
    const reconstructed = new LowLevelPiSessionHostAdapter(new LowLevelPiAgentEngine(engineIdentity, core));
    const resumed = await makeHost(stored.reader).resumeTurn(reconstructed, {
      ...options(persisted.checkpoint),
      checkpointChainDigest: persisted.checkpointChainDigest,
      settlement: { requestDigest: request.requestDigest, outcome: { kind: "success", result: "answer" } },
    });
    expect(resumed.boundary).toMatchObject({ type: "turn_complete", result: "restored" });
    expect(stored.storage.evidence.productionEligible).toBe(false);
  });

  it.each(["missing", "superseded", "stale authority"] as const)(
    "refuses a %s SessionCell blob before touching the engine or sinks",
    async (failure) => {
      const stored = await storedTurn();
      const checkpoint = structuredClone((await stored.snapshot()).activeTurn!.checkpoint);
      if (failure === "missing") {
        Object.assign(checkpoint, { payloadDigest: await digestBytes(new Uint8Array([99])) });
      } else if (failure === "superseded") {
        const next = await stored.engine.step({
          authority: createOpaqueTurnAuthority(authority()), checkpoint: stored.genesis,
        });
        await stored.commit(next);
      } else {
        Object.assign(stored.readAuthority, { currentAuthorizationGeneration: 7 });
      }
      const engine: AgentEngine = {
        startTurn: vi.fn(), resumeTurn: vi.fn(), abortTurn: vi.fn(async () => undefined),
      };
      const turn = options(checkpoint);
      await expect(makeHost(stored.reader).startTurn(engine, turn))
        .rejects.toMatchObject({ code: "CHECKPOINT_UNAVAILABLE" });
      expect(engine.startTurn).not.toHaveBeenCalled();
      expect(engine.abortTurn).not.toHaveBeenCalled();
      expect(turn.committer.commit).not.toHaveBeenCalled();
      expect(turn.ephemeralSink.emit).not.toHaveBeenCalled();
    },
  );

  it.each(["digest", "encoded length", "payload length", "payload digest", "chain digest", "reader"] as const)(
    "rejects mismatched %s before starting the engine",
    async (failure) => {
      const stored = await storedTurn();
      const checkpoint = (await stored.snapshot()).activeTurn!.checkpoint;
      const blob = {
        digest: checkpoint.payloadDigest,
        encodedBytes: checkpoint.payloadSize,
        bytes: new Uint8Array(stored.genesis.payloadBytes),
      };
      if (failure === "digest") blob.digest = digest("f");
      if (failure === "encoded length") blob.encodedBytes += 1;
      if (failure === "payload length") blob.bytes = new Uint8Array([1]);
      if (failure === "payload digest") blob.bytes[0] = (blob.bytes[0] ?? 0) ^ 1;
      const host = makeHost(failure === "reader" ? undefined : { readBlob: async () => blob });
      const engine: AgentEngine = {
        startTurn: vi.fn(), resumeTurn: vi.fn(), abortTurn: vi.fn(async () => undefined),
      };
      await expect(host.startTurn(engine, {
        ...options(checkpoint),
        ...(failure === "chain digest" ? { checkpointChainDigest: digest("f") } : {}),
      })).rejects.toMatchObject({ code: "CHECKPOINT_UNAVAILABLE" });
      expect(engine.startTurn).not.toHaveBeenCalled();
      expect(engine.abortTurn).not.toHaveBeenCalled();
    },
  );

  it("snapshots caller inputs and excludes duplicate executions while the blob read is pending", async () => {
    const stored = await storedTurn();
    const checkpoint = structuredClone((await stored.snapshot()).activeTurn!.checkpoint);
    const turn = options(checkpoint);
    const gate = Promise.withResolvers<Awaited<ReturnType<CheckpointBlobReader["readBlob"]>>>();
    const readBlob = vi.fn(async (input) => {
      expect(input.checkpoint).toEqual(checkpoint);
      return gate.promise;
    });
    const host = makeHost({ readBlob });
    const adapter = new LowLevelPiSessionHostAdapter(new LowLevelPiAgentEngine(engineIdentity, core));
    const driving = host.startTurn(adapter, turn);
    expect(readBlob).toHaveBeenCalledTimes(1);
    Object.assign(checkpoint, { turnId: "changed", payloadDigest: digest("f") });
    turn.authority.fill(0);
    await expect(host.startTurn(adapter, options(externalizeAgentCheckpoint(stored.genesis).checkpoint)))
      .rejects.toMatchObject({ code: "INVALID_TURN" });
    expect(readBlob).toHaveBeenCalledTimes(1);
    gate.resolve({
      digest: stored.genesis.payloadDigest,
      encodedBytes: stored.genesis.payloadBytes.byteLength,
      bytes: stored.genesis.payloadBytes,
    });
    await expect(driving).resolves.toMatchObject({ boundary: { type: "model_request" } });
  });

  it("validates turn identity before reading a blob and releases ownership after rejected reads", async () => {
    const stored = await storedTurn();
    const checkpoint = (await stored.snapshot()).activeTurn!.checkpoint;
    const readBlob = vi.fn(stored.reader.readBlob);
    const host = makeHost({ readBlob });
    const adapter = new LowLevelPiSessionHostAdapter(new LowLevelPiAgentEngine(engineIdentity, core));
    await expect(host.startTurn(adapter, options({ ...checkpoint, turnId: "other-turn" })))
      .rejects.toMatchObject({ code: "CHECKPOINT_UNAVAILABLE" });
    expect(readBlob).not.toHaveBeenCalled();
    readBlob.mockRejectedValueOnce(new Error("stale authorization"));
    await expect(host.startTurn(adapter, options(checkpoint)))
      .rejects.toMatchObject({ code: "CHECKPOINT_UNAVAILABLE" });
    await expect(host.startTurn(adapter, options(checkpoint)))
      .resolves.toMatchObject({ boundary: { type: "model_request" } });
  });

  it("also binds inline checkpoints to a supplied durable chain digest", async () => {
    const stored = await storedTurn();
    const snapshot = (await stored.snapshot()).activeTurn!;
    const engine: AgentEngine = {
      startTurn: vi.fn(), resumeTurn: vi.fn(), abortTurn: vi.fn(async () => undefined),
    };
    await expect(makeHost().startTurn(engine, {
      ...options(stored.genesis), checkpointChainDigest: digest("f"),
    })).rejects.toMatchObject({ code: "CHECKPOINT_UNAVAILABLE" });
    expect(engine.startTurn).not.toHaveBeenCalled();
    expect(engine.abortTurn).not.toHaveBeenCalled();
    const adapter = new LowLevelPiSessionHostAdapter(new LowLevelPiAgentEngine(engineIdentity, core));
    await expect(makeHost().startTurn(adapter, {
      ...options(stored.genesis), checkpointChainDigest: snapshot.checkpointChainDigest,
    })).resolves.toMatchObject({ boundary: { type: "model_request" } });
  });

  it.each([(1 << 20) + 1, 4 << 20])("hydrates %i payload bytes without enlarging the event budget", async (size) => {
    const stored = await storedTurn();
    const bytes = new Uint8Array(size).fill(7);
    const checkpoint = {
      ...(await stored.snapshot()).activeTurn!.checkpoint,
      payloadSize: size,
      payloadDigest: await digestBytes(bytes),
    };
    let received: unknown;
    const engine: AgentEngine = {
      async *startTurn(context) {
        received = context.checkpoint;
        yield { type: "turn_complete", checkpoint: { sequence: 1 }, result: "done" };
      },
      resumeTurn: vi.fn(),
      abortTurn: vi.fn(async () => undefined),
    };
    const readBlob = vi.fn(async () => ({
      digest: checkpoint.payloadDigest, encodedBytes: bytes.byteLength, bytes,
    }));
    await expect(makeHost({ readBlob }).startTurn(engine, options(checkpoint)))
      .resolves.toMatchObject({ boundary: { type: "turn_complete" } });
    expect((received as AgentCheckpoint).payloadBytes.byteLength).toBe(size);
    expect(await digestBytes((received as AgentCheckpoint).payloadBytes)).toBe(checkpoint.payloadDigest);
    expect(received).not.toHaveProperty("payloadSize");
    readBlob.mockClear();
    await expect(makeHost({ readBlob }, size - 1).startTurn(engine, options(checkpoint)))
      .rejects.toMatchObject({ code: "CHECKPOINT_UNAVAILABLE" });
    expect(readBlob).not.toHaveBeenCalled();
  });
});
