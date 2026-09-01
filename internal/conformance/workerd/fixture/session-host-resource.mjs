// session-host-resource.mjs is the qualification SessionHost served over the
// private Unix socket by `workerd serve`. It exposes only the bounded probe
// surface the external resource runner drives: a nonce readiness challenge
// bound to the static artifact and configuration digests, Dynamic Worker
// state and fault routes, and an explicit host-memory growth route for the
// cgroup pressure probe. It never accepts caller-supplied code, digests, or
// checkpoint authority: reconstruction state is only what the runner-side
// acknowledged checkpoint store replays through /worker/state-load.
import workerSource from "pi-worker-source";
import entrySource from "phase0-resource-entry-source";

const WORKER_PATTERN = /^[a-z0-9][a-z0-9/-]{0,127}$/;
const NONCE_PATTERN = /^[0-9a-f]{32}$/;

let hostInstance = null;

function currentHostInstance() {
  if (hostInstance === null) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    hostInstance = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  return hostInstance;
}

const retainedHostAllocations = [];

function definition(marker) {
  return {
    compatibilityDate: "@COMPATIBILITY_DATE@",
    compatibilityFlags: [@COMPATIBILITY_FLAGS@],
    limits: { cpuMs: 1000, subRequests: 0 },
    mainModule: "phase0-resource-entry.js",
    modules: {
      "phase0-resource-entry.js": { js: entrySource },
      "pi-worker.js": { js: workerSource },
    },
    env: { MARKER: marker },
    globalOutbound: null,
  };
}

function badRequest(code) {
  return Response.json({ code }, { status: 400 });
}

async function forwardWorker(stub, path, init) {
  const response = await stub.getEntrypoint().fetch(`https://phase0.invalid${path}`, init);
  const body = await response.text();
  return new Response(body, {
    status: response.status,
    headers: { "content-type": "application/json" },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/ready") {
      const nonce = url.searchParams.get("nonce") ?? "";
      if (!NONCE_PATTERN.test(nonce)) {
        return badRequest("invalid_nonce");
      }
      return Response.json({
        schemaVersion: 1,
        nonce,
        hostInstance: currentHostInstance(),
        artifactDigest: "@ARTIFACT_DIGEST@",
        configDigest: "@CONFIG_DIGEST@",
        workerdRelease: "@WORKERD_RELEASE@",
        loaderAbi: 1,
      });
    }
    if (path === "/allocate") {
      if (request.method !== "POST") {
        return badRequest("invalid_method");
      }
      const body = await request.json();
      const mebibytes = body.mebibytes;
      if (!Number.isInteger(mebibytes) || mebibytes < 1 || mebibytes > 256) {
        return badRequest("invalid_allocation");
      }
      const chunk = new Uint8Array(mebibytes * 1048576);
      for (let index = 0; index < chunk.length; index += 4096) {
        chunk[index] = 0xa5;
      }
      retainedHostAllocations.push(chunk);
      return Response.json({ retainedChunks: retainedHostAllocations.length });
    }
    const worker = url.searchParams.get("worker") ?? "";
    if (!WORKER_PATTERN.test(worker)) {
      return badRequest("invalid_worker");
    }
    const stub = env.LOADER.get(worker, () => definition("qualification"));
    if (path === "/worker/initialization-instance" && request.method === "GET") {
      return forwardWorker(stub, "/initialization-instance");
    }
    if (path === "/worker/state-init" && request.method === "POST") {
      return forwardWorker(stub, "/state-init", { method: "POST" });
    }
    if (path === "/worker/state-read" && request.method === "GET") {
      return forwardWorker(stub, "/state-read");
    }
    if (path === "/worker/state-load" && request.method === "POST") {
      return forwardWorker(stub, "/state-load", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: await request.text(),
      });
    }
    if (path === "/worker/spin" && request.method === "GET") {
      try {
        const response = await stub.getEntrypoint().fetch("https://phase0.invalid/spin");
        return Response.json({ faulted: false, status: response.status });
      } catch (error) {
        return Response.json({ faulted: true, message: String(error) });
      }
    }
    return new Response("not found", { status: 404 });
  },
};
