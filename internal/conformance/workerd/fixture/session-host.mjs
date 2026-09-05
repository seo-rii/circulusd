import workerSource from "pi-worker-source";
import entrySource from "phase0-entry-source";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function definition(marker, limits = { cpuMs: 1000, subRequests: 0 }, bindings = {}) {
  return {
    compatibilityDate: "@COMPATIBILITY_DATE@",
    compatibilityFlags: [@COMPATIBILITY_FLAGS@],
    limits,
    mainModule: "phase0-entry.js",
    modules: {
      "phase0-entry.js": { js: entrySource },
      "pi-worker.js": { js: workerSource },
    },
    env: { MARKER: marker, ...bindings },
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
    const first = await invoke(worker, "/initialization-instance");
    const second = await invoke(worker, "/initialization-instance");
    assert(/^[0-9a-f]{32}$/.test(first.initializationInstance), "initialization instance is not a module-local 128-bit identity");
    assert(first.marker === "dynamic" && second.marker === "dynamic", "initialization instance did not come from the scoped dynamic Worker");
    assert(first.initializationInstance === second.initializationInstance, "initialization instance changed between two pre-fault calls");
    const sibling = env.LOADER.get("dynamic/sha256-b", () => definition("dynamic-sibling"));
    const siblingResult = await invoke(sibling, "/initialization-instance");
    assert(siblingResult.initializationInstance !== first.initializationInstance, "distinct isolate initializations shared one initialization instance");
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
    const expectedTrace = ["model", "external-tool", "model", "turn_complete"];
    assert(result.completed === true, "low-level AgentEngine did not complete a model/tool turn");
    assert(result.modelBoundaries === 2, "pinned Pi adapter did not cross two model boundaries");
    assert(result.toolRequests === 1, "pinned Pi adapter did not cross one external-tool boundary");
    assert(JSON.stringify(result.trace) === JSON.stringify(expectedTrace), "pinned Pi adapter boundary trace changed");
  },
};

export const extensionOrder = {
  async test(_controller, env) {
    const worker = env.LOADER.get("extension-order/sha256-a", () => definition("extensions"));
    const result = await invoke(worker, "/agent-turn");
    const expected = [
      "a:initialize", "b:initialize", "a:beforeAgentStart", "b:beforeAgentStart",
      "a:beforeTurn", "b:beforeTurn", "a:beforeModelRequest", "b:beforeModelRequest",
      "a:initialize", "b:initialize", "a:beforeAgentStart", "b:beforeAgentStart",
      "a:afterModelResponse", "b:afterModelResponse", "a:beforeToolCall", "b:beforeToolCall",
      "a:initialize", "b:initialize", "a:beforeAgentStart", "b:beforeAgentStart",
      "a:afterToolCall", "b:afterToolCall", "a:beforeModelRequest", "b:beforeModelRequest",
      "a:initialize", "b:initialize", "a:beforeAgentStart", "b:beforeAgentStart",
      "a:afterModelResponse", "b:afterModelResponse", "a:afterTurn", "b:afterTurn",
    ];
    assert(JSON.stringify(result.hooks) === JSON.stringify(expected), "extension hook order changed");
  },
};

export const stableBrokerBinding = {
  async test(_controller, env) {
    const left = env.LOADER.get("stable-broker/sha256-52369d7290d083ce102306315793f416404d6fcd96abbca9d0007ae0cb790527/identity-a", () =>
      definition("identity-a", { cpuMs: 1000, subRequests: 12 }, { MODEL: env.MODEL, MCP: env.MCP })
    );
    const right = env.LOADER.get("stable-broker/sha256-52369d7290d083ce102306315793f416404d6fcd96abbca9d0007ae0cb790527/identity-b", () =>
      definition("identity-b", { cpuMs: 1000, subRequests: 12 }, { MODEL: env.MODEL, MCP: env.MCP })
    );
    const [leftResult, rightResult] = await Promise.all([
      invoke(left, "/stable-broker-turn"),
      invoke(right, "/stable-broker-turn"),
    ]);
    const expectedTrace = ["model", "external-tool", "model", "turn_complete"];
    const expectedBrokerTrace = ["model-tool", "mcp-echo", "model-complete"];
    assert(
      Math.max(leftResult.initialModelAttempts, rightResult.initialModelAttempts) >= 2,
      "stable broker rendezvous did not defer its first identity",
    );
    for (const [identity, result] of [
      ["identity-a", leftResult],
      ["identity-b", rightResult],
    ]) {
      assert(result.identity === identity, `stable broker crossed identity ${identity}`);
      assert(result.completed === true, `stable broker did not complete ${identity}`);
      assert(JSON.stringify(result.trace) === JSON.stringify(expectedTrace), `stable broker trace changed for ${identity}`);
      assert(JSON.stringify(result.brokerTrace) === JSON.stringify(expectedBrokerTrace), `stable broker settlement trace changed for ${identity}`);
    }

    const missingModel = env.LOADER.get("stable-broker/missing-model", () =>
      definition("identity-a", undefined, { MCP: env.MCP })
    );
    const missingMcp = env.LOADER.get("stable-broker/missing-mcp", () =>
      definition("identity-b", undefined, { MODEL: env.MODEL })
    );
    const [missingModelResponse, missingMcpResponse] = await Promise.all([
      missingModel.getEntrypoint().fetch("https://phase0.invalid/stable-broker-turn"),
      missingMcp.getEntrypoint().fetch("https://phase0.invalid/stable-broker-turn"),
    ]);
    assert(missingModelResponse.status === 503, "stable broker route accepted a missing MODEL binding");
    assert(missingMcpResponse.status === 503, "stable broker route accepted a missing MCP binding");
    const [missingModelBody, missingMcpBody] = await Promise.all([
      missingModelResponse.json(),
      missingMcpResponse.json(),
    ]);
    assert(missingModelBody.code === "missing_binding", "missing MODEL failure was not explicit");
    assert(missingMcpBody.code === "missing_binding", "missing MCP failure was not explicit");
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
