import { decodeCanonicalCbor, digestBytes, encodeCanonicalCbor } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  PiGenesisGenerator, validatePiGenesisResult,
  type PiGenesisRequest,
} from "../src/genesis.ts";
import { createPiGenesisEntrypointClass } from "../src/genesis-entrypoint.ts";

import { SCOPE, environment, request, assertColdFirstBoundary } from "./genesis-fixtures.ts";

describe("actual scoped Pi genesis", () => {
  it("creates executable initial Pi state and preserves ordered public input through cold reconstruction", async () => {
    const input = await request();
    const generator = await PiGenesisGenerator.create(await environment());
    const result = await generator.createGenesis(input);
    expect(result.binding).toMatchObject({ ...SCOPE, turnId: input.turnId, inputDigest: input.inputDigest, runtime: input.runtime });
    expect(decodeCanonicalCbor(result.checkpoint.payloadBytes)).toMatchObject({
      version: 1, status: "ready", turnInput: input.input,
      coreState: { version: 2, phase: "ready", messages: [], pendingToolCalls: [] },
    });
    expect(await validatePiGenesisResult(result, input)).toEqual(result);
    await assertColdFirstBoundary(result.checkpoint);
    expect(await generator.createGenesis(input)).toEqual(result);
  });

  it("snapshots environment and public input before async hashing", async () => {
    const env = await environment();
    const building = PiGenesisGenerator.create(env);
    (env.scope as { sessionId: string }).sessionId = `sess_${"B".repeat(25)}A`;
    const generator = await building;
    const input = await request();
    const pending = generator.createGenesis(input);
    ((input.input as { messages: { content: string }[] }).messages[0]!).content = "caller mutation";
    expect(decodeCanonicalCbor((await pending).checkpoint.payloadBytes)).toMatchObject({
      turnInput: { messages: [{ role: "user", content: "첫 번째 메시지" }, { role: "user", content: "second message" }] },
    });
  });

  it("rejects malformed input, scoped mismatches and ABI/schema mismatches", async () => {
    const generator = await PiGenesisGenerator.create(await environment());
    const valid = await request();
    const bad = [
      { ...valid, tenantId: `tenant_${"B".repeat(25)}A` },
      { ...valid, workspaceId: `ws_${"B".repeat(25)}A` },
      { ...valid, actorSubjectId: `subject_${"B".repeat(25)}A` },
      { ...valid, sessionId: `sess_${"B".repeat(25)}A` },
      { ...valid, turnId: "tenant_wrong-kind" },
      { ...valid, runtime: { ...valid.runtime, runtimeRevisionDigest: `sha256:${"c".repeat(64)}` } },
      { ...valid, runtime: { ...valid.runtime, adapterAbiVersion: 1 } },
      { ...valid, runtime: { ...valid.runtime, checkpointSchemaVersion: 1 } },
      { ...valid, input: { messages: [{ role: "assistant", content: "invalid" }] } },
      { ...valid, input: { messages: [{ role: "user", content: "e\u0301" }] } },
      { ...valid, input: { messages: [{ role: "user", content: "\ud800" }] } },
      { ...valid, input: { messages: [{ role: "user", content: "x".repeat(1_048_577) }] } },
      { ...valid, input: { messages: [] } },
      { ...valid, inputDigest: `sha256:${"f".repeat(64)}` },
    ];
    for (const value of bad) await expect(generator.createGenesis(value as PiGenesisRequest)).rejects.toThrow();
    const env = await environment();
    await expect(PiGenesisGenerator.create({ ...env, configurationDigest: `sha256:${"0".repeat(64)}` })).rejects.toThrow();
  });

  it("rejects altered binding, input, core state, schema and oversized returned checkpoints", async () => {
    const input = await request();
    const result = await (await PiGenesisGenerator.create(await environment())).createGenesis(input);
    for (const mutation of [
      { ...result, binding: { ...result.binding, actorSubjectId: `subject_${"B".repeat(25)}A` } },
      { ...result, requestDigest: `sha256:${"0".repeat(64)}` },
      { ...result, checkpoint: { ...result.checkpoint, checkpointSchemaVersion: 1 } },
      { ...result, checkpoint: { ...result.checkpoint, payloadBytes: new Uint8Array(4 * 1_048_576 + 1) } },
    ]) await expect(validatePiGenesisResult(mutation, input)).rejects.toThrow();
    const state = decodeCanonicalCbor(result.checkpoint.payloadBytes) as Record<string, unknown>;
    for (const payload of [{ ...state, coreState: null }, { ...state, turnInput: { messages: [{ role: "user", content: "other" }] } }]) {
      const bytes = encodeCanonicalCbor(payload);
      await expect(validatePiGenesisResult({ ...result, checkpoint: { ...result.checkpoint,
        payloadBytes: bytes, payloadDigest: await digestBytes(bytes) } }, input)).rejects.toThrow();
    }
  });

  it("produces a real subclass of the supplied WorkerEntrypoint and exposes only genesis RPC", async () => {
    class NativeBase { constructor(readonly context: object, readonly env: unknown) {} }
    const Entry = createPiGenesisEntrypointClass(NativeBase);
    const entry = new Entry({}, await environment());
    expect(entry).toBeInstanceOf(NativeBase);
    expect(Object.getOwnPropertyNames(Entry.prototype)).toEqual(["constructor", "createGenesis"]);
    await assertColdFirstBoundary((await entry.createGenesis(await request())).checkpoint);
    expect(() => createPiGenesisEntrypointClass(null)).toThrow();
  });
});
