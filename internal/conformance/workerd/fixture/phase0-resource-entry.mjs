// phase0-resource-entry.mjs is the qualification Dynamic Worker main module.
// Like the workerd-test wrapper it owns a module-local initialization
// instance whose null-to-value transition happens at most once per module
// initialization, and it forwards unknown routes to the pinned Pi worker
// bundle unchanged. It additionally carries the qualification-only routes:
// an unbounded /spin the Worker Loader cpuMs limit must abort, and the
// module-local retained state the reconstruction probes checkpoint through
// the runner-side acknowledged store.
import worker from "./pi-worker.js";

let initializationInstance = null;
let retainedState = null;

function currentInitializationInstance() {
  if (initializationInstance === null) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    initializationInstance = Array.from(
      bytes,
      (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");
  }
  return initializationInstance;
}

function encodePayload(value) {
  const payloadBytes = new TextEncoder().encode(JSON.stringify(value));
  let binary = "";
  for (const byte of payloadBytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/initialization-instance") {
      return Response.json({
        initializationInstance: currentInitializationInstance(),
        marker: env.MARKER,
      });
    }
    if (path === "/spin") {
      const spinState = { value: 0 };
      for (;;) {
        spinState.value = (spinState.value + 1) % 1048576;
      }
    }
    if (path === "/state-init" && request.method === "POST") {
      const instance = currentInitializationInstance();
      retainedState = { marker: env.MARKER, value: `state-${instance}` };
      return Response.json({
        initializationInstance: instance,
        checkpointBase64: encodePayload(retainedState),
      });
    }
    if (path === "/state-read") {
      return Response.json({
        initializationInstance: currentInitializationInstance(),
        state: retainedState,
      });
    }
    if (path === "/state-load" && request.method === "POST") {
      const body = await request.json();
      const encoded = typeof body.checkpointBase64 === "string" ? body.checkpointBase64 : "";
      let parsed;
      try {
        const decoded = atob(encoded);
        const payloadBytes = Uint8Array.from(decoded, (character) => character.charCodeAt(0));
        parsed = JSON.parse(new TextDecoder().decode(payloadBytes));
      } catch {
        return Response.json({ code: "invalid_checkpoint" }, { status: 400 });
      }
      if (
        typeof parsed !== "object" || parsed === null ||
        typeof parsed.marker !== "string" || typeof parsed.value !== "string"
      ) {
        return Response.json({ code: "invalid_checkpoint" }, { status: 400 });
      }
      retainedState = { marker: parsed.marker, value: parsed.value };
      return Response.json({
        initializationInstance: currentInitializationInstance(),
        restoredValue: retainedState.value,
      });
    }
    return worker.fetch(request, env);
  },
};
