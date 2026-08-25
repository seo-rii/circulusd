import { describe, expect, it } from "vitest";

import type { Digest } from "@circulusd/protocol-types";

import {
  applyCapabilityGenerationCommand,
  applyExtensionStateCommand,
  assertCurrentCapabilityGeneration,
  createCapabilityGenerationState,
  createExtensionState,
  createMigratedExtensionState,
  extensionStateDigest,
  extensionStateKey,
  readExtensionState,
  type CapabilityGenerationAggregateState,
  type ControlAuthoritySnapshot,
  type ExtensionStateAggregateState,
} from "../src/control/index.ts";

const digest = (character: string): Digest =>
  `sha256:${character.repeat(64)}` as Digest;

function authority(
  subjectKind: ControlAuthoritySnapshot["subjectKind"],
  subjectId: string,
  permissions: ControlAuthoritySnapshot["permissions"],
  overrides: Partial<ControlAuthoritySnapshot> = {},
): ControlAuthoritySnapshot {
  return {
    serviceBinding: "state",
    tenantId: "tenant-1",
    actorUserId: "admin-1",
    subjectKind,
    subjectId,
    roles: ["tenant-admin"],
    permissions,
    authorizationGeneration: 4,
    currentAuthorizationGeneration: 4,
    issuedAt: 1,
    expiresAt: 10_000,
    ...overrides,
  };
}

function extensionState(): ExtensionStateAggregateState {
  return createExtensionState({
    tenantId: "tenant-1",
    scopeKind: "workspace",
    scopeId: "workspace-1",
    extensionId: "official/pdf",
    extensionSchemaVersion: 2,
    stateGeneration: 3,
    predecessor: {
      extensionSchemaVersion: 1,
      stateGeneration: 2,
      stateDigest: digest("a"),
    },
    value: { outputFormat: "pdf", counter: 1 },
  });
}

function generationState(): CapabilityGenerationAggregateState {
  return createCapabilityGenerationState({
    tenantId: "tenant-1",
    subjectKind: "workspace",
    subjectId: "workspace-1",
    generationKind: "workspace-security",
    initialGeneration: 7,
  });
}

describe("ExtensionState aggregate", () => {
  it("does not treat a namespace key as read authority", async () => {
    const initial = extensionState();
    const snapshot = await readExtensionState(
      initial,
      authority("workspace", "workspace-1", ["extension-state.read"]),
      10,
    );
    expect(snapshot).toEqual(initial);
    expect(snapshot).not.toBe(initial);
    await expect(
      readExtensionState(
        initial,
        authority("workspace", "workspace-2", ["extension-state.read"]),
        10,
      ),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("uses the complete namespaced key and copy-on-write predecessor proof", async () => {
    const initial = extensionState();
    expect(extensionStateKey(initial)).toBe(
      "tenant-1/workspace/workspace-1/official%2Fpdf/2/3",
    );
    expect(initial.predecessor).toEqual({
      extensionSchemaVersion: 1,
      stateGeneration: 2,
      stateDigest: digest("a"),
    });
    await expect(extensionStateDigest(initial)).resolves.toMatch(/^sha256:[0-9a-f]{64}$/);

    expect(() =>
      createExtensionState({
        tenantId: "tenant-1",
        scopeKind: "workspace",
        scopeId: "workspace-1",
        extensionId: "official/pdf",
        extensionSchemaVersion: 2,
        stateGeneration: 4,
        predecessor: {
          extensionSchemaVersion: 1,
          stateGeneration: 2,
          stateDigest: digest("a"),
        },
        value: {},
      }),
    ).toThrowError(expect.objectContaining({ code: "STALE_GENERATION" }));

    const migrated = await createMigratedExtensionState(initial, {
      extensionSchemaVersion: 3,
      value: { outputFormat: "svg" },
    });
    expect(migrated.stateGeneration).toBe(4);
    expect(migrated.predecessor).toEqual({
      extensionSchemaVersion: 2,
      stateGeneration: 3,
      stateDigest: await extensionStateDigest(initial),
    });
    expect(initial.value).toEqual({ outputFormat: "pdf", counter: 1 });
  });

  it("requires exactly the initial generation to omit a predecessor", () => {
    expect(() =>
      createExtensionState({
        tenantId: "tenant-1",
        scopeKind: "workspace",
        scopeId: "workspace-1",
        extensionId: "official/pdf",
        extensionSchemaVersion: 1,
        stateGeneration: 2,
        predecessor: null,
        value: {},
      }),
    ).toThrowError(expect.objectContaining({ code: "STALE_GENERATION" }));

    expect(() =>
      createExtensionState({
        tenantId: "tenant-1",
        scopeKind: "workspace",
        scopeId: "workspace-1",
        extensionId: "official/pdf",
        extensionSchemaVersion: 1,
        stateGeneration: 1,
        predecessor: {
          extensionSchemaVersion: 1,
          stateGeneration: 1,
          stateDigest: digest("a"),
        },
        value: {},
      }),
    ).toThrowError(expect.objectContaining({ code: "STALE_GENERATION" }));
  });

  it("snapshots migration source and input before asynchronous hashing", async () => {
    const source = extensionState();
    const sourceDigest = await extensionStateDigest(source);
    const value = { outputFormat: "svg", nested: ["original"] };
    const input = { extensionSchemaVersion: 3, value };

    const migration = createMigratedExtensionState(source, input);
    source.extensionSchemaVersion = 99;
    source.stateGeneration = 99;
    (source.value as { outputFormat: string }).outputFormat = "mutated";
    input.extensionSchemaVersion = 100;
    value.outputFormat = "png";
    value.nested[0] = "mutated";

    await expect(migration).resolves.toMatchObject({
      extensionSchemaVersion: 3,
      stateGeneration: 4,
      predecessor: {
        extensionSchemaVersion: 2,
        stateGeneration: 3,
        stateDigest: sourceDigest,
      },
      value: { outputFormat: "svg", nested: ["original"] },
    });
  });

  it("enforces subject ACL, CAS, exact idempotency, and immutable input copies", async () => {
    const initial = extensionState();
    const value = { counter: 2, nested: ["safe"] };
    const command = {
      kind: "replace_extension_state" as const,
      commandId: "extension-command-1",
      expectedRevision: 0,
      now: 10,
      authority: authority("workspace", "workspace-1", [
        "extension-state.read",
        "extension-state.write",
      ]),
      value,
    };
    const committed = await applyExtensionStateCommand(initial, command);
    value.nested[0] = "tampered";
    expect(committed.state.value).toEqual({ counter: 2, nested: ["safe"] });
    expect(committed.state.revision).toBe(1);

    const replay = await applyExtensionStateCommand(committed.state, {
      ...command,
      now: 20,
      value: { counter: 2, nested: ["safe"] },
      authority: authority(
        "workspace",
        "workspace-1",
        ["extension-state.read", "extension-state.write"],
        {
          authorizationGeneration: 5,
          currentAuthorizationGeneration: 5,
        },
      ),
    });
    expect(replay.replayed).toBe(true);
    expect(replay.state).toBe(committed.state);

    await expect(
      applyExtensionStateCommand(initial, {
        ...command,
        authority: authority("workspace", "workspace-2", ["extension-state.write"]),
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(
      applyExtensionStateCommand(initial, {
        ...command,
        authority: authority("workspace", "workspace-1", ["extension-state.read"]),
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("rejects unknown command fields and bounded-state overflow", async () => {
    const initial = extensionState();
    const base = {
      kind: "replace_extension_state" as const,
      commandId: "extension-command-2",
      expectedRevision: 0,
      now: 10,
      authority: authority("workspace", "workspace-1", ["extension-state.write"]),
      value: {},
    };
    await expect(
      applyExtensionStateCommand(initial, { ...base, extra: "forged" } as never),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    await expect(
      applyExtensionStateCommand(initial, {
        ...base,
        value: { huge: "x".repeat(600_000) },
      }),
    ).rejects.toMatchObject({ code: "RESOURCE_EXHAUSTED" });
  });
});

describe("CapabilityGeneration aggregate", () => {
  it("self-fences stale authorization authority before receipt replay", async () => {
    const initial = createCapabilityGenerationState({
      tenantId: "tenant-1",
      subjectKind: "tenant",
      subjectId: "tenant-1",
      generationKind: "authorization",
      initialGeneration: 4,
    });
    const command = {
      kind: "rotate_capability_generation" as const,
      commandId: "authorization-rotation-1",
      expectedRevision: 0,
      now: 100,
      authority: authority("tenant", "tenant-1", ["generation.rotate"], {
        authorizationGeneration: 4,
        currentAuthorizationGeneration: 4,
      }),
      nextGeneration: 5,
      reason: "credential incident",
    };
    const rotated = await applyCapabilityGenerationCommand(initial, command);

    await expect(
      applyCapabilityGenerationCommand(rotated.state, { ...command, now: 101 }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
    await expect(
      applyCapabilityGenerationCommand(rotated.state, {
        ...command,
        now: 101,
        authority: authority("tenant", "tenant-1", ["generation.rotate"], {
          authorizationGeneration: 5,
          currentAuthorizationGeneration: 5,
        }),
      }),
    ).resolves.toMatchObject({ replayed: true });
  });

  it("rotates by exactly one and immediately fences every prior generation", async () => {
    const initial = generationState();
    const command = {
      kind: "rotate_capability_generation" as const,
      commandId: "rotation-1",
      expectedRevision: 0,
      now: 100,
      authority: authority("workspace", "workspace-1", [
        "generation.read",
        "generation.rotate",
      ]),
      nextGeneration: 8,
      reason: "workspace ownership changed",
    };
    const rotated = await applyCapabilityGenerationCommand(initial, command);
    expect(rotated.state.currentGeneration).toBe(8);
    expect(rotated.state.revokedThroughGeneration).toBe(7);
    expect(rotated.state.history).toEqual([
      {
        generation: 8,
        revokedThroughGeneration: 7,
        reason: "workspace ownership changed",
        rotatedBy: "admin-1",
        rotatedAt: 100,
      },
    ]);

    expect(() =>
      assertCurrentCapabilityGeneration(
        rotated.state,
        7,
        authority("workspace", "workspace-1", ["generation.read"]),
        101,
      ),
    ).toThrowError(expect.objectContaining({ code: "STALE_GENERATION" }));
    expect(() =>
      assertCurrentCapabilityGeneration(
        rotated.state,
        8,
        authority("workspace", "workspace-1", ["generation.read"]),
        101,
      ),
    ).not.toThrow();

    await expect(
      applyCapabilityGenerationCommand(initial, { ...command, nextGeneration: 9 }),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("requires privileged rotation authority and serializes CAS winners", async () => {
    const initial = generationState();
    const base = {
      kind: "rotate_capability_generation" as const,
      commandId: "rotation-a",
      expectedRevision: 0,
      now: 100,
      authority: authority("workspace", "workspace-1", ["generation.rotate"]),
      nextGeneration: 8,
      reason: "security incident",
    };
    await expect(
      applyCapabilityGenerationCommand(initial, {
        ...base,
        authority: authority("workspace", "workspace-1", ["generation.rotate"], {
          roles: ["workspace-owner"],
        }),
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(
      applyCapabilityGenerationCommand(initial, {
        ...base,
        authority: authority("workspace", "workspace-1", ["generation.rotate"], {
          tenantId: "tenant-2",
        }),
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });

    const winner = await applyCapabilityGenerationCommand(initial, base);
    await expect(
      applyCapabilityGenerationCommand(winner.state, {
        ...base,
        commandId: "rotation-b",
      }),
    ).rejects.toMatchObject({ code: "CONFLICT" });

    const replay = await applyCapabilityGenerationCommand(winner.state, {
      ...base,
      now: 200,
      authority: authority("workspace", "workspace-1", ["generation.rotate"], {
        authorizationGeneration: 5,
        currentAuthorizationGeneration: 5,
        issuedAt: 150,
        expiresAt: 20_000,
      }),
    });
    expect(replay.replayed).toBe(true);
  });
});
