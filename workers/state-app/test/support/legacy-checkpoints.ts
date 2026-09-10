import type { Digest } from "@circulusd/protocol-types";

import type { SessionAggregateState } from "../../src/session/index.ts";

// Rebuild the pre-schema-v5 inline layout of a Session state for migration tests:
// every externalized checkpoint gets its payload bytes back (looked up in the blobs
// the producing command returned) and the v5-only checkpointChainDigest is dropped.
// The result is a legacy-shaped plain object; the caller sets its schemaVersion.
export function inlineLegacyCheckpoints(
  state: SessionAggregateState,
  blobs: ReadonlyMap<Digest, Uint8Array> | undefined,
): Record<string, unknown> {
  const inline = (checkpoint: Record<string, unknown>): Record<string, unknown> => {
    const digest = checkpoint.payloadDigest as Digest;
    const payloadBytes = blobs?.get(digest);
    if (payloadBytes === undefined) {
      throw new Error(`legacy fixture is missing payload bytes for ${digest}`);
    }
    const { payloadSize: _payloadSize, ...metadata } = checkpoint;
    return { ...metadata, payloadBytes: new Uint8Array(payloadBytes) };
  };
  const turn = (record: Record<string, unknown>): Record<string, unknown> => {
    const { checkpointChainDigest: _chain, ...rest } = record;
    return { ...rest, checkpoint: inline(rest.checkpoint as Record<string, unknown>) };
  };
  const legacy = structuredClone(state) as unknown as Record<string, unknown>;
  legacy.queuedTurns = (legacy.queuedTurns as Record<string, unknown>[]).map(turn);
  legacy.activeTurn =
    legacy.activeTurn === null ? null : turn(legacy.activeTurn as Record<string, unknown>);
  legacy.terminalTurns = (legacy.terminalTurns as Record<string, unknown>[]).map((record) => ({
    ...record,
    finalCheckpoint: inline(record.finalCheckpoint as Record<string, unknown>),
  }));
  return legacy;
}
