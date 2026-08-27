import workerSource from "pi-worker-source";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function definition(marker, limits = { cpuMs: 1000, subRequests: 0 }) {
  return {
    compatibilityDate: "@COMPATIBILITY_DATE@",
    compatibilityFlags: [@COMPATIBILITY_FLAGS@],
    limits,
    mainModule: "pi-worker.js",
    modules: { "pi-worker.js": { js: workerSource } },
    env: { MARKER: marker },
    globalOutbound: null,
  };
}

async function invoke(stub, path) {
  const response = await stub.getEntrypoint().fetch(`https://phase0.invalid${path}`);
  assert(response.ok, `dynamic Worker request ${path} failed with ${response.status}`);
  return response.json();
}

export const dynamicWorker = {
  async test(_controller, env) {
    const worker = env.LOADER.get("dynamic/sha256-a", () => definition("dynamic"));
    const result = await invoke(worker, "/identity");
    assert(result.marker === "dynamic", "dynamic Worker did not receive its scoped binding");
  },
};

export const contentAddressedReplacement = {
  async test(_controller, env) {
    const oldWorker = env.LOADER.get("replacement/sha256-a", () => definition("old"));
    const newWorker = env.LOADER.get("replacement/sha256-b", () => definition("new"));
    const staleFactory = env.LOADER.get("replacement/sha256-a", () => definition("forged"));
    const [oldResult, newResult, cachedResult] = await Promise.all([
      invoke(oldWorker, "/identity"),
      invoke(newWorker, "/identity"),
      invoke(staleFactory, "/identity"),
    ]);
    assert(oldResult.marker === "old", "old content address changed");
    assert(newResult.marker === "new", "new content address reused stale code");
    assert(cachedResult.marker === "old", "logical cache name did not preserve immutable identity");
  },
};

export const isolateSeparation = {
  async test(_controller, env) {
    const left = env.LOADER.get("isolation/left", () => definition("left"));
    const right = env.LOADER.get("isolation/right", () => definition("right"));
    const [leftFirst, rightFirst] = await Promise.all([
      invoke(left, "/counter"),
      invoke(right, "/counter"),
    ]);
    const leftSecond = await invoke(left, "/counter");
    assert(leftFirst.count === 1, "left Worker inherited global state");
    assert(rightFirst.count === 1, "right Worker inherited global state");
    assert(leftSecond.count === 2, "left Worker did not retain its own isolate state");
  },
};

export const agentEngine = {
  async test(_controller, env) {
    const worker = env.LOADER.get("agent-engine/sha256-a", () => definition("agent-engine"));
    const result = await invoke(worker, "/agent-turn");
    assert(result.completed === true, "low-level AgentEngine did not complete a model/tool turn");
    assert(result.modelRequests === 1, "model binding was not invoked exactly once");
    assert(result.toolRequests === 1, "tool binding was not invoked exactly once");
  },
};

export const extensionOrder = {
  async test(_controller, env) {
    const worker = env.LOADER.get("extension-order/sha256-a", () => definition("extensions"));
    const result = await invoke(worker, "/agent-turn");
    const expected = [
      "a:initialize", "b:initialize", "a:beforeAgentStart", "b:beforeAgentStart",
      "a:beforeTurn", "b:beforeTurn", "a:beforeModelRequest", "b:beforeModelRequest",
      "a:afterModelResponse", "b:afterModelResponse", "a:beforeToolCall", "b:beforeToolCall",
      "a:afterToolCall", "b:afterToolCall", "a:afterTurn", "b:afterTurn",
    ];
    assert(JSON.stringify(result.hooks) === JSON.stringify(expected), "extension hook order changed");
  },
};

export const outboundDenial = {
  async test(_controller, env) {
    const worker = env.LOADER.get("outbound/sha256-a", () => definition("outbound"));
    const result = await invoke(worker, "/outbound");
    assert(result.fetchDenied === true, "direct fetch escaped globalOutbound=null");
    assert(result.webSocketDenied === true, "WebSocket escaped globalOutbound=null");
    assert(result.rawSocketDenied === true, "raw socket escaped globalOutbound=null");
  },
};
