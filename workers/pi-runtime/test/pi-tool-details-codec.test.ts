import type { Context } from "@earendil-works/pi-ai";
import { decodeCanonicalCbor, encodeCanonicalCbor, type EffectIntent, type NormalizedValue } from "@circulusd/protocol-types";
import { describe, expect, it } from "vitest";

import {
  PI_AGENT_CORE_TOOL_DETAILS_ENCODING,
  decodePiAgentCoreModelContext,
  encodePiAgentCoreModelContext,
  encodePiAgentCoreToolResult,
  normalizePiAgentCoreSettlement,
  validatePiJson,
} from "../src/index.ts";

const requestDigest = `sha256:${"a".repeat(64)}` as const;
const request: EffectIntent = { service: "external-tool", operation: "call", replayPolicy: "safe", requestDigest,
  payload: { protocol: "pi-agent-core", version: 1, toolCall: { type: "toolCall", id: "details-call", name: "echo", arguments: {} } } };
const result = (details: unknown) => ({ version: 1, toolCallId: "details-call", toolName: "echo",
  content: [{ type: "text", text: "done" }], isError: false, timestamp: 3, details });
const settlement = (details: unknown) => ({ requestDigest, outcome: { kind: "success", result: result(details) } });
const message = (details: unknown, tagged = false) => ({ role: "toolResult", toolCallId: "details-call", toolName: "echo",
  content: [{ type: "text", text: "done" }], isError: false, timestamp: 3, details,
  ...(tagged ? { detailsEncoding: PI_AGENT_CORE_TOOL_DETAILS_ENCODING } : {}) });

describe("versioned finite Pi tool details", () => {
  it.each([0.5, Number.MIN_VALUE, Number.MAX_VALUE, 1e21, -0.25, null, "metadata", true,
    [0.5, { nested: [-1.25, null, "e\u0301"] }], { scale: 0.5, nested: [1, 0.125, { flag: false }] }])(
    "producer and context round trips preserve finite JSON %j", (details) => {
      const durable = decodeCanonicalCbor(encodeCanonicalCbor(encodePiAgentCoreToolResult(result(details)))) as Record<string, NormalizedValue>;
      expect(durable.detailsEncoding).toBe(PI_AGENT_CORE_TOOL_DETAILS_ENCODING);
      const stored = { messages: [message(durable.details, true)] };
      const decoded = decodePiAgentCoreModelContext(stored);
      expect(decoded.messages[0]).toMatchObject({ details: validatePiJson(details) });
      if (typeof details === "number") expect(Object.is((decoded.messages[0] as { details: number }).details, details)).toBe(true);
      // Pi captures are cloned at both loop boundaries. Keep the annotation
      // through that clone so repeated encode/decode cycles stay byte-identical.
      const reencoded = encodePiAgentCoreModelContext(structuredClone(decoded) as unknown as Context);
      expect(encodeCanonicalCbor(reencoded)).toEqual(encodeCanonicalCbor(stored));
      expect(encodePiAgentCoreModelContext(decodePiAgentCoreModelContext(reencoded) as unknown as Context)).toEqual(reencoded);
    },
  );

  it.each([{ value: 5 }, null, "opaque", [1, 2], new Uint8Array([1, 2]), { "$pi.number.v1": "0.5" }])(
    "preserves unmarked legacy metadata and receipt bytes %j", (details) => {
      const legacy = settlement(details);
      expect(normalizePiAgentCoreSettlement(legacy, request)).toBe(legacy);
      expect(encodeCanonicalCbor(normalizePiAgentCoreSettlement(legacy, request))).toEqual(encodeCanonicalCbor(legacy));
      const context = { messages: [message(details)] };
      expect(decodePiAgentCoreModelContext(context)).toEqual(context);
      expect(encodePiAgentCoreModelContext(decodePiAgentCoreModelContext(context) as unknown as Context)).toEqual(context);
    },
  );

  it("marks nested raw fractions only for the exact pending Pi tool result", () => {
    const raw = settlement({ scale: 0.5, nested: [Number.MIN_VALUE] });
    expect(normalizePiAgentCoreSettlement(raw, request)).toEqual({ requestDigest, outcome: { kind: "success", result: {
      ...result({ scale: { "$pi.number.v1": "0.5" }, nested: [{ "$pi.number.v1": Number.MIN_VALUE.toString() }] }),
      detailsEncoding: PI_AGENT_CORE_TOOL_DETAILS_ENCODING,
    } } });
    expect(() => encodeCanonicalCbor(raw)).toThrow(/safe integers/);
    for (const other of [null, { ...request, service: "model" as const }, { ...request, operation: "other" },
      { ...request, payload: { protocol: "other", version: 1, toolCall: { id: "details-call", name: "echo" } } },
      { ...request, payload: { protocol: "pi-agent-core", version: 2, toolCall: { id: "details-call", name: "echo" } } },
      { ...request, requestDigest: `sha256:${"b".repeat(64)}` as const },
      { ...request, payload: { protocol: "pi-agent-core", version: 1, toolCall: { id: "other", name: "echo" } } },
      { ...request, payload: { protocol: "pi-agent-core", version: 1, toolCall: { id: "details-call", name: "other" } } },
    ]) expect(normalizePiAgentCoreSettlement(raw, other)).toBe(raw);
    for (const changed of [
      { ...raw, outcome: { kind: "error", result: raw.outcome.result } },
      { ...raw, outcome: { ...raw.outcome, result: { ...raw.outcome.result, version: 2 } } },
      { ...raw, outcome: { ...raw.outcome, result: { ...raw.outcome.result, detailsEncoding: PI_AGENT_CORE_TOOL_DETAILS_ENCODING } } },
    ]) expect(normalizePiAgentCoreSettlement(changed, request)).toBe(changed);
  });

  it.each([NaN, Infinity, -Infinity, -0, new Uint8Array([1]), undefined,
    { "$pi.number.v1": "0.5" }, { nested: { "$pi.number.v1": "0.5" } }, { nested: [NaN] }])(
    "rejects invalid or reserved producer JSON %j", (details) => {
      expect(() => encodePiAgentCoreToolResult(result(details))).toThrow();
    },
  );

  it.each([
    { ...message(null, true), detailsEncoding: "unknown" },
    { role: "toolResult", toolCallId: "details-call", toolName: "echo", content: [], isError: false, timestamp: 3,
      detailsEncoding: PI_AGENT_CORE_TOOL_DETAILS_ENCODING },
    message({ "$pi.number.v1": "01" }, true), message({ "$pi.number.v1": "1" }, true),
    message({ "$pi.number.v1": "-0" }, true), message({ "$pi.number.v1": "Infinity" }, true),
    message({ "$pi.number.v1": "0.5", extra: true }, true),
    message(new Uint8Array([1]), true),
  ])("rejects malformed tagged transcript metadata %j", (entry) => {
    expect(() => decodePiAgentCoreModelContext({ messages: [entry] })).toThrow();
  });
});
