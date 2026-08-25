import { describe, expect, it } from "vitest";

import {
  applyUserCommand,
  createUserState,
  readUserState,
  validateUserState,
  type ControlAuthoritySnapshot,
  type UserAggregateState,
} from "../src/control/index.ts";

function authority(
  overrides: Partial<ControlAuthoritySnapshot> = {},
): ControlAuthoritySnapshot {
  return {
    serviceBinding: "state",
    tenantId: "tenant-1",
    actorUserId: "user-1",
    subjectKind: "user",
    subjectId: "user-1",
    roles: ["user"],
    permissions: ["user.preferences.write", "user.read"],
    authorizationGeneration: 1,
    currentAuthorizationGeneration: 1,
    issuedAt: 1,
    expiresAt: 10_000,
    ...overrides,
  };
}

function state(): UserAggregateState {
  return createUserState({
    userId: "user-1",
    tenantId: "tenant-1",
    defaultExtensions: [{ id: "official/pdf", version: "1.0.0" }],
    defaultExecutionBackend: "nsjail",
    preferredAgentIsolation: null,
    modelConfiguration: { provider: "lan-model", model: "small" },
    mcpConfiguration: [{ id: "docs", configuration: { enabled: true } }],
    quotaProfile: "standard",
  });
}

function preferencesCommand(
  current: UserAggregateState,
  overrides: Record<string, unknown> = {},
) {
  return {
    kind: "replace_preferences" as const,
    commandId: "command-preferences-1",
    expectedRevision: current.revision,
    now: 10,
    authority: authority(),
    defaultExtensions: [{ id: "official/code", version: "2.0.0" }],
    defaultExecutionBackend: "docker" as const,
    preferredAgentIsolation: {
      processScope: "tenant" as const,
      outerIsolation: "none" as const,
    },
    modelConfiguration: { provider: "lan-model", model: "large" },
    mcpConfiguration: [{ id: "search", configuration: { enabled: true } }],
    ...overrides,
  };
}

describe("User aggregate", () => {
  it("requires an exact tenant and user ACL even for reads", async () => {
    const initial = state();
    const snapshot = await readUserState(
      initial,
      authority({ permissions: ["user.read"] }),
      10,
    );
    expect(snapshot).toEqual(initial);
    expect(snapshot).not.toBe(initial);

    await expect(
      readUserState(
        initial,
        authority({ subjectId: "user-2", permissions: ["user.read"] }),
        10,
      ),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("commits a complete preference snapshot with revision CAS and defensive copies", async () => {
    const initial = state();
    const command = preferencesCommand(initial);
    const result = await applyUserCommand(initial, command);

    expect(result.replayed).toBe(false);
    expect(result.state).not.toBe(initial);
    expect(result.state.revision).toBe(1);
    expect(result.state.eventSequence).toBe(1);
    expect(result.state.defaultExecutionBackend).toBe("docker");
    expect(result.outcome).toEqual({ kind: "preferences_replaced", revision: 1 });
    expect(initial.revision).toBe(0);

    command.modelConfiguration.model = "tampered";
    expect(result.state.modelConfiguration).toEqual({
      provider: "lan-model",
      model: "large",
    });
    await expect(validateUserState(result.state)).resolves.toBeUndefined();
  });

  it("authenticates before replay with refreshed authority", async () => {
    const initial = state();
    const command = preferencesCommand(initial);
    const committed = await applyUserCommand(initial, command);

    const replay = await applyUserCommand(committed.state, {
      ...command,
      now: 20,
      authority: authority({
        authorizationGeneration: 2,
        currentAuthorizationGeneration: 2,
        issuedAt: 15,
        expiresAt: 20_000,
      }),
    });
    expect(replay.replayed).toBe(true);
    expect(replay.state).toBe(committed.state);

    await expect(
      applyUserCommand(committed.state, {
        ...command,
        now: 20,
        authority: authority({ permissions: ["user.read"] }),
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });

    await expect(
      applyUserCommand(committed.state, {
        ...command,
        now: 20,
        authority: authority({ tenantId: "tenant-2" }),
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });

    await expect(
      applyUserCommand(committed.state, {
        ...command,
        now: 20,
        authority: authority({ subjectId: "user-2" }),
      }),
    ).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("rejects stale CAS, command-id conflicts, and concurrent second writers", async () => {
    const initial = state();
    const winner = await applyUserCommand(initial, preferencesCommand(initial));

    await expect(
      applyUserCommand(winner.state, preferencesCommand(winner.state, {
        commandId: "command-stale",
        expectedRevision: 0,
      })),
    ).rejects.toMatchObject({ code: "CONFLICT" });

    await expect(
      applyUserCommand(winner.state, preferencesCommand(winner.state, {
        defaultExecutionBackend: "firecracker",
      })),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });

    const contenders = ["docker", "firecracker"] as const;
    let serialized = initial;
    const outcomes: string[] = [];
    for (const [index, backend] of contenders.entries()) {
      try {
        const result = await applyUserCommand(
          serialized,
          preferencesCommand(initial, {
            commandId: `concurrent-${index}`,
            defaultExecutionBackend: backend,
          }),
        );
        serialized = result.state;
        outcomes.push("committed");
      } catch (error) {
        outcomes.push((error as { code: string }).code);
      }
    }
    expect(outcomes).toEqual(["committed", "CONFLICT"]);
  });

  it("rejects unknown fields, non-canonical collections, and oversized values", async () => {
    const initial = state();
    await expect(
      applyUserCommand(initial, {
        ...preferencesCommand(initial),
        unexpected: true,
      } as never),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });

    await expect(
      applyUserCommand(initial, preferencesCommand(initial, {
        defaultExtensions: [
          { id: "z-last", version: "1" },
          { id: "a-first", version: "1" },
        ],
      })),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });

    await expect(
      applyUserCommand(initial, preferencesCommand(initial, {
        modelConfiguration: { huge: "x".repeat(300_000) },
      })),
    ).rejects.toMatchObject({ code: "RESOURCE_EXHAUSTED" });

    let getterCalls = 0;
    const accessorConfiguration = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(accessorConfiguration, "provider", {
      enumerable: true,
      get() {
        getterCalls += 1;
        return "forged";
      },
    });
    await expect(
      applyUserCommand(initial, preferencesCommand(initial, {
        modelConfiguration: accessorConfiguration,
      })),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(getterCalls).toBe(0);
  });

  it("rejects stale authorization generations for new mutations", async () => {
    const initial = state();
    await expect(
      applyUserCommand(initial, preferencesCommand(initial, {
        authority: authority({ currentAuthorizationGeneration: 2 }),
      })),
    ).rejects.toMatchObject({ code: "STALE_GENERATION" });
  });

  it("orders extension and MCP identifiers by canonical UTF-8 bytes", async () => {
    const initial = state();
    const canonical = await applyUserCommand(initial, preferencesCommand(initial, {
      defaultExtensions: [
        { id: "\uE000", version: "1" },
        { id: "\u{10000}", version: "1" },
      ],
      mcpConfiguration: [
        { id: "\uE000", configuration: {} },
        { id: "\u{10000}", configuration: {} },
      ],
    }));
    expect(canonical.state.defaultExtensions.map((extension) => extension.id)).toEqual([
      "\uE000",
      "\u{10000}",
    ]);

    await expect(
      applyUserCommand(initial, preferencesCommand(initial, {
        defaultExtensions: [
          { id: "\u{10000}", version: "1" },
          { id: "\uE000", version: "1" },
        ],
      })),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
  });

  it("rejects collection accessors without executing their getters", async () => {
    const initial = state();
    let getterCalls = 0;
    const extensions: unknown[] = [];
    Object.defineProperty(extensions, "0", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return { id: "hostile", version: "1" };
      },
    });

    await expect(
      applyUserCommand(initial, preferencesCommand(initial, {
        defaultExtensions: extensions,
      })),
    ).rejects.toMatchObject({ code: "INVALID_ARGUMENT" });
    expect(getterCalls).toBe(0);
  });

  it("rejects a command-kind accessor before aggregate dispatch", async () => {
    const initial = state();
    let getterCalls = 0;
    const hostile = preferencesCommand(initial);
    Object.defineProperty(hostile, "kind", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "replace_preferences";
      },
    });

    await expect(applyUserCommand(initial, hostile)).rejects.toMatchObject({
      code: "INVALID_ARGUMENT",
    });
    expect(getterCalls).toBe(0);
  });
});
