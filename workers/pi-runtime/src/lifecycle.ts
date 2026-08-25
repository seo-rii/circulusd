import type { EffectIntent, NormalizedValue } from "@circulusd/protocol-types";

import { BoundaryFault, PiRuntimeError } from "./errors.ts";
import {
  boundedIdentifier,
  boundedProtocolValue,
  exactRecord,
  frozenProtocolClone,
  frozenSignalContext,
} from "./validation.ts";
import type {
  EffectRequestDraft,
  EngineIdentity,
  ExtensionManifest,
  ExtensionRegistration,
  PatchableHook,
  PiPlatformExtension,
  RequestPatchField,
  ResultPatchField,
} from "./types.ts";

interface RegisteredExtension {
  readonly manifest: ExtensionManifest;
  readonly create: () => PiPlatformExtension;
  readonly registrationIndex: number;
}

interface ActiveExtension {
  readonly manifest: ExtensionManifest;
  readonly instance: PiPlatformExtension;
  readonly registrationIndex: number;
}

const PATCHABLE_HOOKS = [
  "beforeModelRequest",
  "afterModelResponse",
  "beforeToolCall",
  "afterToolCall",
] as const satisfies readonly PatchableHook[];
const REQUEST_PATCH_FIELDS = ["operation", "replayPolicy", "payload"] as const;
const RESULT_PATCH_FIELDS = ["result"] as const;

export class HookDispatcher {
  readonly #identity: EngineIdentity;
  readonly #maxOutputBytes: number;
  readonly #registrations: RegisteredExtension[] = [];
  #active: readonly ActiveExtension[] = [];
  #sealed = false;
  #initializing = false;
  #initialized = false;

  constructor(identity: EngineIdentity, maxOutputBytes: number) {
    this.#identity = identity;
    this.#maxOutputBytes = maxOutputBytes;
  }

  register(registration: ExtensionRegistration): void {
    if (this.#sealed || this.#initializing || this.#initialized) {
      throw new PiRuntimeError(
        "HOOK_REGISTRY_FROZEN",
        "extension hook registry is frozen once initialization starts",
      );
    }
    const registrationRecord = exactRecord(
      registration,
      ["manifest", "create"],
      [],
      "extensionRegistration",
      "INVALID_CONFIGURATION",
    );
    if (typeof registrationRecord.create !== "function") {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "extension create must be a factory");
    }
    const manifestRecord = exactRecord(
      registrationRecord.manifest,
      ["id", "priority", "tools", "patchableFields"],
      ["configuration"],
      "extensionManifest",
      "INVALID_CONFIGURATION",
    );
    boundedProtocolValue(
      registrationRecord.manifest,
      this.#maxOutputBytes,
      "extensionManifest",
      "INVALID_CONFIGURATION",
    );
    const id = boundedIdentifier(
      manifestRecord.id,
      "extensionManifest.id",
      "INVALID_CONFIGURATION",
    );
    if (!/^[a-z0-9][a-z0-9._/-]*$/.test(id)) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        "extensionManifest.id must use the canonical lowercase extension-id syntax",
      );
    }
    if (typeof manifestRecord.priority !== "number" || !Number.isSafeInteger(manifestRecord.priority)) {
      throw new PiRuntimeError(
        "INVALID_CONFIGURATION",
        "extensionManifest.priority must be a safe integer",
      );
    }
    if (!Array.isArray(manifestRecord.tools)) {
      throw new PiRuntimeError("INVALID_CONFIGURATION", "extensionManifest.tools must be an array");
    }
    const tools = manifestRecord.tools.map((tool, index) =>
      boundedIdentifier(tool, `extensionManifest.tools[${index}]`, "INVALID_CONFIGURATION"),
    );
    if (new Set(tools).size !== tools.length) {
      throw new PiRuntimeError(
        "TOOL_NAME_COLLISION",
        `extension ${id} declares the same tool more than once`,
      );
    }
    const patchableRecord = exactRecord(
      manifestRecord.patchableFields,
      [],
      PATCHABLE_HOOKS,
      "extensionManifest.patchableFields",
      "INVALID_CONFIGURATION",
    );
    const patchableFields: ExtensionManifest["patchableFields"] = {};
    for (const hook of PATCHABLE_HOOKS) {
      if (!Object.prototype.hasOwnProperty.call(patchableRecord, hook)) continue;
      const fields = patchableRecord[hook];
      if (!Array.isArray(fields)) {
        throw new PiRuntimeError(
          "INVALID_CONFIGURATION",
          `extensionManifest.patchableFields.${hook} must be an array`,
        );
      }
      const allowed: readonly string[] = hook === "beforeModelRequest" || hook === "beforeToolCall"
        ? REQUEST_PATCH_FIELDS
        : RESULT_PATCH_FIELDS;
      const validated = fields.map((field) => {
        if (typeof field !== "string" || !allowed.includes(field)) {
          throw new PiRuntimeError(
            "INVALID_CONFIGURATION",
            `${String(field)} is not patchable by ${hook}`,
          );
        }
        return field;
      });
      if (new Set(validated).size !== validated.length) {
        throw new PiRuntimeError(
          "INVALID_CONFIGURATION",
          `extensionManifest.patchableFields.${hook} contains duplicates`,
        );
      }
      Object.defineProperty(patchableFields, hook, {
        enumerable: true,
        value: Object.freeze([...validated]),
      });
    }
    const configuration = Object.prototype.hasOwnProperty.call(manifestRecord, "configuration")
      ? boundedProtocolValue(
          manifestRecord.configuration,
          this.#maxOutputBytes,
          "extensionManifest.configuration",
          "INVALID_CONFIGURATION",
        )
      : null;
    const manifest: ExtensionManifest = Object.freeze({
      id,
      priority: manifestRecord.priority,
      tools: Object.freeze(tools),
      configuration: frozenProtocolClone(configuration),
      patchableFields: Object.freeze(patchableFields),
    });
    this.#registrations.push({
      manifest,
      create: registrationRecord.create as () => PiPlatformExtension,
      registrationIndex: this.#registrations.length,
    });
  }

  seal(): void {
    this.#sealed = true;
  }

  async initialize(): Promise<void> {
    this.seal();
    if (this.#initialized) return;
    if (this.#initializing) {
      throw new PiRuntimeError(
        "INITIALIZATION_FAILED",
        "extension initialization was invoked concurrently",
      );
    }
    this.#initializing = true;
    try {
      const ordered = [...this.#registrations].sort((left, right) =>
        left.manifest.priority !== right.manifest.priority
          ? left.manifest.priority - right.manifest.priority
          : left.manifest.id !== right.manifest.id
            ? left.manifest.id < right.manifest.id
              ? -1
              : 1
            : left.registrationIndex - right.registrationIndex,
      );
      const toolOwners = new Map<string, string>();
      for (const registration of ordered) {
        for (const tool of registration.manifest.tools) {
          const existing = toolOwners.get(tool);
          if (existing !== undefined) {
            throw new PiRuntimeError(
              "TOOL_NAME_COLLISION",
              `tool ${tool} is declared by both ${existing} and ${registration.manifest.id}`,
            );
          }
          toolOwners.set(tool, registration.manifest.id);
        }
      }
      const active = ordered.map((registration) => ({
        manifest: registration.manifest,
        instance: registration.create(),
        registrationIndex: registration.registrationIndex,
      }));
      const controller = new AbortController();
      for (const extension of active) {
        const result = await extension.instance.initialize?.(
          frozenProtocolClone({
            sessionId: this.#identity.sessionId,
            runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
            extensionId: extension.manifest.id,
            configuration: extension.manifest.configuration ?? null,
          }),
        );
        if (result !== undefined) {
          throw new PiRuntimeError(
            "INITIALIZATION_FAILED",
            `extension ${extension.manifest.id} initialize returned data from a void hook`,
          );
        }
      }
      for (const extension of active) {
        const result = await extension.instance.beforeAgentStart?.(
          frozenSignalContext({
            sessionId: this.#identity.sessionId,
            runtimeRevisionDigest: this.#identity.runtimeRevisionDigest,
            signal: controller.signal,
          }),
        );
        if (result !== undefined) {
          throw new PiRuntimeError(
            "INITIALIZATION_FAILED",
            `extension ${extension.manifest.id} beforeAgentStart returned data from a void hook`,
          );
        }
      }
      this.#active = Object.freeze(active);
      this.#initialized = true;
    } catch (error) {
      if (error instanceof PiRuntimeError) throw error;
      throw new PiRuntimeError("INITIALIZATION_FAILED", "extension initialization failed", {
        cause: error,
      });
    } finally {
      this.#initializing = false;
    }
  }

  async beforeTurn(
    turnId: string,
    input: NormalizedValue,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#runVoidHook("beforeTurn", { sessionId: this.#identity.sessionId, turnId, input, signal });
  }

  async beforeModelRequest(
    turnId: string,
    request: EffectRequestDraft,
    signal: AbortSignal,
  ): Promise<EffectRequestDraft> {
    return this.#patchRequest("beforeModelRequest", turnId, request, signal);
  }

  async afterModelResponse(
    turnId: string,
    request: EffectIntent,
    result: NormalizedValue,
    signal: AbortSignal,
  ): Promise<NormalizedValue> {
    return this.#patchResult("afterModelResponse", turnId, request, result, signal);
  }

  async beforeToolCall(
    turnId: string,
    request: EffectRequestDraft,
    signal: AbortSignal,
  ): Promise<EffectRequestDraft> {
    return this.#patchRequest("beforeToolCall", turnId, request, signal);
  }

  async afterToolCall(
    turnId: string,
    request: EffectIntent,
    result: NormalizedValue,
    signal: AbortSignal,
  ): Promise<NormalizedValue> {
    return this.#patchResult("afterToolCall", turnId, request, result, signal);
  }

  async afterTurn(
    turnId: string,
    result: NormalizedValue,
    signal: AbortSignal,
  ): Promise<void> {
    await this.#runVoidHook("afterTurn", { sessionId: this.#identity.sessionId, turnId, result, signal });
  }

  async #runVoidHook(
    hook: "beforeTurn" | "afterTurn",
    event: Record<string, unknown>,
  ): Promise<void> {
    for (const extension of this.#active) {
      const callback = extension.instance[hook];
      if (callback === undefined) continue;
      try {
        const result = await callback.call(extension.instance, frozenSignalContext(event) as never);
        if (result !== undefined) {
          throw new BoundaryFault(
            "EXTENSION_OUTPUT_INVALID",
            `extension ${extension.manifest.id} returned data from void hook ${hook}`,
          );
        }
      } catch (error) {
        if (error instanceof BoundaryFault) throw error;
        throw new BoundaryFault(
          "EXTENSION_HOOK_FAILED",
          `extension ${extension.manifest.id} failed in ${hook}`,
          { cause: error },
        );
      }
    }
  }

  async #patchRequest(
    hook: "beforeModelRequest" | "beforeToolCall",
    turnId: string,
    initial: EffectRequestDraft,
    signal: AbortSignal,
  ): Promise<EffectRequestDraft> {
    let request = frozenProtocolClone(initial);
    for (const extension of this.#active) {
      const callback = extension.instance[hook];
      if (callback === undefined) continue;
      let output: unknown;
      try {
        output = await callback.call(
          extension.instance,
          frozenSignalContext({
            sessionId: this.#identity.sessionId,
            turnId,
            request,
            signal,
          }) as never,
        );
      } catch (error) {
        throw new BoundaryFault(
          "EXTENSION_HOOK_FAILED",
          `extension ${extension.manifest.id} failed in ${hook}`,
          { cause: error },
        );
      }
      if (output === undefined) continue;
      const patch = exactRecord(
        output,
        [],
        REQUEST_PATCH_FIELDS,
        `${extension.manifest.id}.${hook}.patch`,
        "EXTENSION_OUTPUT_INVALID",
      );
      boundedProtocolValue(
        patch,
        this.#maxOutputBytes,
        `${extension.manifest.id}.${hook}.patch`,
        "EXTENSION_OUTPUT_INVALID",
      );
      const allowed = new Set(extension.manifest.patchableFields[hook] ?? []);
      for (const field of Object.keys(patch)) {
        if (!allowed.has(field as RequestPatchField)) {
          throw new BoundaryFault(
            "EXTENSION_OUTPUT_INVALID",
            `extension ${extension.manifest.id} cannot patch ${field} in ${hook}`,
          );
        }
      }
      request = frozenProtocolClone({
        ...request,
        ...(Object.prototype.hasOwnProperty.call(patch, "operation")
          ? {
              operation: boundedIdentifier(
                patch.operation,
                `${extension.manifest.id}.${hook}.patch.operation`,
                "EXTENSION_OUTPUT_INVALID",
              ),
            }
          : {}),
        ...(Object.prototype.hasOwnProperty.call(patch, "replayPolicy")
          ? { replayPolicy: patch.replayPolicy }
          : {}),
        ...(Object.prototype.hasOwnProperty.call(patch, "payload")
          ? {
              payload: boundedProtocolValue(
                patch.payload,
                this.#maxOutputBytes,
                `${extension.manifest.id}.${hook}.patch.payload`,
                "EXTENSION_OUTPUT_INVALID",
              ),
            }
          : {}),
      } as EffectRequestDraft);
    }
    return request;
  }

  async #patchResult(
    hook: "afterModelResponse" | "afterToolCall",
    turnId: string,
    request: EffectIntent,
    initial: NormalizedValue,
    signal: AbortSignal,
  ): Promise<NormalizedValue> {
    let result = frozenProtocolClone(initial);
    for (const extension of this.#active) {
      const callback = extension.instance[hook];
      if (callback === undefined) continue;
      let output: unknown;
      try {
        output = await callback.call(
          extension.instance,
          frozenSignalContext({
            sessionId: this.#identity.sessionId,
            turnId,
            request,
            result,
            signal,
          }) as never,
        );
      } catch (error) {
        throw new BoundaryFault(
          "EXTENSION_HOOK_FAILED",
          `extension ${extension.manifest.id} failed in ${hook}`,
          { cause: error },
        );
      }
      if (output === undefined) continue;
      const patch = exactRecord(
        output,
        [],
        RESULT_PATCH_FIELDS,
        `${extension.manifest.id}.${hook}.patch`,
        "EXTENSION_OUTPUT_INVALID",
      );
      boundedProtocolValue(
        patch,
        this.#maxOutputBytes,
        `${extension.manifest.id}.${hook}.patch`,
        "EXTENSION_OUTPUT_INVALID",
      );
      const allowed = new Set(extension.manifest.patchableFields[hook] ?? []);
      for (const field of Object.keys(patch)) {
        if (!allowed.has(field as ResultPatchField)) {
          throw new BoundaryFault(
            "EXTENSION_OUTPUT_INVALID",
            `extension ${extension.manifest.id} cannot patch ${field} in ${hook}`,
          );
        }
      }
      if (Object.prototype.hasOwnProperty.call(patch, "result")) {
        result = boundedProtocolValue(
          patch.result,
          this.#maxOutputBytes,
          `${extension.manifest.id}.${hook}.patch.result`,
          "EXTENSION_OUTPUT_INVALID",
        );
      }
    }
    return result;
  }
}
