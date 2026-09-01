// phase0-worker-entry.mjs is the Dynamic Worker main module. Its
// initialization-instance identity lives in module-local state that can
// transition from null to a concrete value at most once per module-graph
// initialization, so a changed identity proves a demonstrably new
// initialization for the same content-addressed Worker ID. workerd forbids
// drawing entropy in global scope, so the single draw happens on the first
// handler call into this module instance; the harness and session host can
// observe the identity but can never inject, rotate, or synthesize it. Every
// other route forwards to the pinned Pi worker bundle unchanged.
import worker from "./pi-worker.js";

let initializationInstance = null;

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

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === "/initialization-instance") {
      return Response.json({
        initializationInstance: currentInitializationInstance(),
        marker: env.MARKER,
      });
    }
    return worker.fetch(request, env);
  },
};
