// circulusd-test frontend: a plain-JS chat client for the backend's
// SPEC §36-shaped API (POST /v1/sessions, POST .../turns, GET .../events SSE).

const $ = (id) => document.getElementById(id);
const ui = {
  connDot: $("conn-dot"),
  caps: $("caps"),
  sessionId: $("session-id"),
  revision: $("revision"),
  messages: $("messages"),
  composer: $("composer"),
  prompt: $("prompt"),
  send: $("send"),
  abort: $("abort"),
  newSession: $("new-session"),
  eventList: $("event-list"),
  eventCount: $("event-count"),
  lastId: $("last-id"),
  clearLog: $("clear-log"),
};

const EVENT_TYPES = [
  "stream.open",
  "turn.accepted",
  "checkpoint",
  "model.started",
  "model.thinking",
  "model.delta",
  "model.settled",
  "tool.started",
  "tool.stdout",
  "tool.completed",
  "effect.rejected",
  "turn.completed",
  "turn.failed",
  "turn.aborted",
];
const MAX_LOG_ROWS = 300;
const THINKING_PREVIEW_CHARS = 160;

const state = {
  sessionId: null,
  source: null,
  activeTurnId: null,
  bubbles: new Map(), // turnId -> assistant bubble record
  userBubbles: new Map(), // turnId -> user bubble element
  pendingUserBubble: null, // optimistic user bubble waiting for its turn.accepted
  finishedTurns: new Set(), // turns whose terminal event already arrived
  eventCount: 0,
  ephemeralCount: 0,
  lastEventId: 0,
};

async function api(path, init = {}) {
  const response = await fetch(path, {
    ...init,
    headers: { "content-type": "application/json", ...(init.headers ?? {}) },
  });
  // A proxy or a crashed backend may answer with HTML or nothing; report the
  // status rather than a JSON parse error.
  const text = response.status === 204 ? "" : await response.text();
  let body = null;
  if (text !== "") {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }
  if (!response.ok) {
    const message = body?.error?.message ?? `${response.status} ${response.statusText}`;
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return body;
}

function describePython(python) {
  if (!python || python.mode === "disabled") return "python: disabled";
  if (python.mode === "circulusd-sandbox") {
    return `python: circulusd sandboxd (${python.launcher}, ${python.distro}, no network)`;
  }
  return "python: HOST, no isolation";
}

function renderCapabilities(caps) {
  const model = caps.model;
  const badgeClass = model.kind === "mock" ? "badge warn" : "badge";
  const key =
    model.apiKeyEnv === null ? "" : ` · ${model.apiKeyEnv} ${model.apiKeyPresent ? "✓" : "unset"}`;
  ui.caps.innerHTML = "";
  const badge = document.createElement("span");
  badge.className = badgeClass;
  badge.textContent = `${model.kind}: ${model.modelId}`;
  badge.title = model.baseUrl ?? "";
  ui.caps.append(badge);
  const detail = document.createElement("span");
  detail.textContent =
    `${caps.engine.package} · pi-agent-core ${caps.engine.piAgentCore} · ABI ${caps.engine.adapterAbiVersion}` +
    ` · tools: ${caps.tools.map((tool) => tool.name).join(", ")}${model.supportsTools ? "" : " (model lacks tool support)"}` +
    ` · ctx ${model.contextWindow}${model.reasoning ? " · thinking" : ""} · ${describePython(caps.execution.python)}` +
    ` · history: ${caps.historyInjection ? "on" : "off"}${key}`;
  ui.caps.append(detail);
  ui.caps.title = caps.systemPrompt;
}

function setConnection(status) {
  ui.connDot.className = `dot ${status}`;
  ui.connDot.title = `SSE ${status}`;
}

// ---------------------------------------------------------------- rendering
//
// Streaming events (model.delta, model.thinking) can arrive dozens of times
// per second. Touching the DOM and forcing a layout for each one made the
// page stutter, so text is accumulated and painted once per animation frame.

const pendingPaint = new Map(); // bubble -> { delta: string, thinking: boolean }
let paintScheduled = false;
let scrollWanted = false;

function schedulePaint() {
  if (paintScheduled) return;
  paintScheduled = true;
  requestAnimationFrame(paint);
}

function paint() {
  paintScheduled = false;
  for (const [bubble, work] of pendingPaint) {
    if (work.delta !== "") bubble.body.append(document.createTextNode(work.delta));
    if (work.thinking) {
      bubble.thinking.hidden = false;
      bubble.thinkingLabel.textContent =
        `thinking (${bubble.thinkingText.length} chars): …${bubble.thinkingText.slice(-THINKING_PREVIEW_CHARS)}`;
    }
  }
  pendingPaint.clear();
  if (scrollWanted) {
    scrollWanted = false;
    ui.messages.scrollTop = ui.messages.scrollHeight;
  }
}

function queuePaint(bubble, patch) {
  const work = pendingPaint.get(bubble) ?? { delta: "", thinking: false };
  if (patch.delta) work.delta += patch.delta;
  if (patch.thinking) work.thinking = true;
  pendingPaint.set(bubble, work);
  scrollWanted = true;
  schedulePaint();
}

function scrollMessages() {
  scrollWanted = true;
  schedulePaint();
}

function addUserBubble(text) {
  const element = document.createElement("div");
  element.className = "bubble user";
  element.textContent = text;
  ui.messages.append(element);
  scrollMessages();
  return element;
}

function ensureAssistantBubble(turnId) {
  let bubble = state.bubbles.get(turnId);
  if (bubble) return bubble;
  const element = document.createElement("div");
  element.className = "bubble assistant";
  const thinking = document.createElement("details");
  thinking.className = "thinking";
  thinking.hidden = true;
  const thinkingLabel = document.createElement("summary");
  const thinkingBody = document.createElement("pre");
  thinking.append(thinkingLabel, thinkingBody);
  // The full thinking text is only materialised when the block is opened.
  thinking.addEventListener("toggle", () => {
    if (thinking.open) thinkingBody.textContent = bubble.thinkingText;
  });
  const body = document.createElement("span");
  body.className = "body cursor";
  const chips = document.createElement("div");
  chips.className = "chips";
  const runs = document.createElement("div");
  runs.className = "runs";
  const meta = document.createElement("span");
  meta.className = "meta";
  element.append(thinking, body, chips, runs, meta);
  ui.messages.append(element);
  bubble = {
    element, body, chips, runs, meta, thinking, thinkingLabel, thinkingBody,
    thinkingText: "", chipByCall: new Map(), argsByCall: new Map(),
    // Text of earlier model steps in this turn (kept when a tool call follows).
    priorText: "",
  };
  state.bubbles.set(turnId, bubble);
  scrollMessages();
  return bubble;
}

function setActiveTurn(turnId) {
  state.activeTurnId = turnId;
  ui.abort.disabled = turnId === null;
  ui.send.disabled = turnId !== null;
}

function logEvent(event, id) {
  if (id === null) {
    // Ephemeral events (deltas, thinking, tool stdout) are counted, not listed,
    // so the log stays readable and cheap.
    state.ephemeralCount += 1;
    ui.eventCount.textContent = `${state.eventCount} (+${state.ephemeralCount} ephemeral)`;
    if (event.type !== "stream.open") return;
  } else {
    state.eventCount += 1;
    state.lastEventId = Math.max(state.lastEventId, id);
    ui.eventCount.textContent = `${state.eventCount} (+${state.ephemeralCount} ephemeral)`;
    ui.lastId.textContent = String(state.lastEventId);
  }

  const row = document.createElement("li");
  const idCell = document.createElement("span");
  idCell.className = "id";
  idCell.textContent = id === null ? "·" : String(id);
  const typeCell = document.createElement("span");
  typeCell.className = `type${id === null ? " eph" : ""}${/failed|rejected|aborted/.test(event.type) ? " err" : ""}`;
  typeCell.textContent = event.type;
  const dataCell = document.createElement("span");
  dataCell.className = "data";
  dataCell.textContent = truncate(JSON.stringify(event.data), 400);
  // The pretty JSON is built on demand instead of for every row.
  dataCell.addEventListener("mouseenter", () => {
    if (dataCell.title === "") dataCell.title = JSON.stringify(event, null, 2);
  }, { once: true });
  row.append(idCell, typeCell, dataCell);
  ui.eventList.append(row);
  while (ui.eventList.children.length > MAX_LOG_ROWS) ui.eventList.firstChild.remove();
  ui.eventList.scrollTop = ui.eventList.scrollHeight;
}

function handleEvent(event, id) {
  logEvent(event, id);
  const data = event.data ?? {};
  const turnId = event.turnId;
  switch (event.type) {
    case "stream.open":
      setConnection("open");
      break;
    case "turn.accepted": {
      // The bubble drawn optimistically on submit is adopted here; otherwise
      // (replayed history after a reload) it is created from the event.
      if (!state.userBubbles.has(turnId)) {
        const pending = state.pendingUserBubble;
        if (pending !== null && pending.textContent === data.prompt) {
          state.pendingUserBubble = null;
          state.userBubbles.set(turnId, pending);
        } else {
          state.userBubbles.set(turnId, addUserBubble(data.prompt));
        }
      }
      ensureAssistantBubble(turnId);
      setActiveTurn(turnId);
      break;
    }
    case "model.started": {
      const bubble = ensureAssistantBubble(turnId);
      pendingPaint.delete(bubble);
      // Keep what earlier steps of this turn said; the new step streams after it.
      bubble.body.textContent = bubble.priorText === "" ? "" : `${bubble.priorText}\n\n`;
      bubble.thinkingText = "";
      bubble.thinking.hidden = true;
      bubble.thinking.open = false;
      bubble.thinkingBody.textContent = "";
      bubble.body.classList.add("cursor");
      bubble.meta.textContent = `model ${data.model} · request ${shortDigest(data.requestDigest)}` +
        (data.historyInjected ? ` · history ${data.historyInjected} msgs` : "");
      break;
    }
    case "model.thinking": {
      const bubble = ensureAssistantBubble(turnId);
      bubble.thinkingText += data.text;
      queuePaint(bubble, { thinking: true });
      break;
    }
    case "model.delta": {
      const bubble = ensureAssistantBubble(turnId);
      queuePaint(bubble, { delta: data.text });
      break;
    }
    case "model.settled": {
      const bubble = ensureAssistantBubble(turnId);
      pendingPaint.delete(bubble);
      if (bubble.thinkingText !== "") {
        bubble.thinking.hidden = false;
        bubble.thinkingLabel.textContent = `thinking · ${bubble.thinkingText.length} chars (click to expand)`;
      }
      if (data.outcome !== "success") {
        bubble.meta.textContent = `model error: ${data.error?.message ?? data.outcome}`;
        break;
      }
      const toolCalls = data.toolCalls ?? [];
      for (const call of toolCalls) {
        const chip = document.createElement("span");
        chip.className = "chip running";
        chip.textContent = `${call.name}(${truncate(JSON.stringify(call.arguments), 120)})`;
        bubble.chips.append(chip);
        bubble.chipByCall.set(call.id, chip);
        bubble.argsByCall.set(call.id, call.arguments ?? {});
      }
      const stepText = joinText(bubble.priorText, data.text ?? "");
      bubble.body.textContent = stepText;
      // A step that goes on to call tools is an intermediate step; its text stays.
      if (toolCalls.length > 0) bubble.priorText = stepText;
      bubble.meta.textContent = `stop: ${data.stopReason} · tokens in/out ${data.usage?.input ?? "?"}/${data.usage?.output ?? "?"}`;
      scrollMessages();
      break;
    }
    case "tool.started": {
      const bubble = ensureAssistantBubble(turnId);
      if (!bubble.argsByCall.has(data.toolCallId)) bubble.argsByCall.set(data.toolCallId, data.arguments ?? {});
      break;
    }
    case "tool.completed": {
      const bubble = ensureAssistantBubble(turnId);
      let chip = bubble.chipByCall.get(data.toolCallId);
      if (!chip) {
        chip = document.createElement("span");
        chip.textContent = data.name;
        bubble.chips.append(chip);
      }
      chip.className = `chip${data.isError ? " error" : ""}`;
      chip.textContent = `${data.name} → ${truncate(data.text, 80)}`;
      chip.title = truncate(data.text, 2000);
      const args = bubble.argsByCall.get(data.toolCallId);
      if (args && typeof args.code === "string") {
        // Script-style tools (python): show the code and its full output.
        const details = document.createElement("details");
        details.className = `tool-run${data.isError ? " error" : ""}`;
        const summary = document.createElement("summary");
        const lines = args.code.split("\n").length;
        summary.textContent = `${data.name} · ${data.isError ? "failed" : "ok"} · ${lines} line${lines === 1 ? "" : "s"}`;
        const code = document.createElement("pre");
        code.className = "code";
        code.textContent = args.code;
        const output = document.createElement("pre");
        output.className = "output";
        output.textContent = data.text || "(no output)";
        details.append(summary, code, output);
        bubble.runs.append(details);
      }
      scrollMessages();
      break;
    }
    case "turn.completed": {
      state.finishedTurns.add(turnId);
      const bubble = ensureAssistantBubble(turnId);
      pendingPaint.delete(bubble);
      bubble.body.classList.remove("cursor");
      bubble.body.textContent = typeof data.message?.text === "string"
        ? joinText(bubble.priorText, data.message.text)
        : bubble.body.textContent;
      bubble.meta.textContent = `completed · ${data.steps} engine steps · checkpoint #${data.checkpoint?.sequence} ${shortDigest(data.checkpoint?.payloadDigest)}`;
      setActiveTurn(null);
      scrollMessages();
      break;
    }
    case "turn.failed":
    case "turn.aborted": {
      state.finishedTurns.add(turnId);
      const bubble = ensureAssistantBubble(turnId);
      pendingPaint.delete(bubble);
      bubble.body.classList.remove("cursor");
      bubble.element.classList.add("error");
      bubble.body.textContent = `${event.type === "turn.aborted" ? "중단됨" : "실패"}: ${data.error?.code ?? ""} ${data.error?.message ?? ""}`.trim();
      bubble.meta.textContent = `${data.steps} engine steps`;
      setActiveTurn(null);
      scrollMessages();
      break;
    }
    default:
      break;
  }
}

function joinText(prior, text) {
  if (prior === "") return text;
  if (text === "") return prior;
  return `${prior}\n\n${text}`;
}

function shortDigest(digest) {
  if (typeof digest !== "string") return "";
  return digest.replace(/^sha256:/, "").slice(0, 12);
}

function truncate(text, max) {
  const value = String(text ?? "");
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function openEvents(sessionId) {
  if (state.source) state.source.close();
  setConnection("retry");
  const source = new EventSource(`/v1/sessions/${sessionId}/events`);
  for (const type of EVENT_TYPES) {
    source.addEventListener(type, (message) => {
      const id = message.lastEventId === "" ? null : Number(message.lastEventId);
      handleEvent(JSON.parse(message.data), id);
    });
  }
  let probing = false;
  source.onerror = () => {
    setConnection("retry");
    // EventSource retries forever, also when the session is gone (backend
    // restarted, session deleted). Check once per error and start over then.
    if (probing || state.source !== source) return;
    probing = true;
    fetch(`/v1/sessions/${sessionId}`)
      .then((response) => {
        if (response.status === 404 && state.source === source) {
          source.close();
          const element = document.createElement("div");
          element.className = "bubble assistant error";
          element.textContent = `세션 ${sessionId} 이(가) 더 이상 없습니다(백엔드 재시작 또는 삭제). 새 세션을 시작합니다.`;
          ui.messages.append(element);
          return newSession();
        }
        return undefined;
      })
      .catch(() => undefined)
      .finally(() => {
        probing = false;
      });
  };
  state.source = source;
}

function resetView() {
  state.bubbles.clear();
  state.userBubbles.clear();
  state.pendingUserBubble = null;
  state.finishedTurns.clear();
  pendingPaint.clear();
  ui.messages.innerHTML = "";
  ui.eventList.innerHTML = "";
  state.eventCount = 0;
  state.ephemeralCount = 0;
  state.lastEventId = 0;
  ui.eventCount.textContent = "0";
  ui.lastId.textContent = "0";
  setActiveTurn(null);
}

async function newSession() {
  if (state.source) state.source.close();
  state.sessionId = null;
  resetView();
  const session = await api("/v1/sessions", { method: "POST", body: "{}" });
  state.sessionId = session.sessionId;
  ui.sessionId.textContent = session.sessionId;
  ui.revision.textContent = session.runtimeRevisionDigest;
  ui.revision.title = session.runtimeRevisionDigest;
  history.replaceState(null, "", `#${session.sessionId}`);
  openEvents(session.sessionId);
}

async function submitPrompt() {
  const prompt = ui.prompt.value.trim();
  if (prompt === "" || state.sessionId === null || state.activeTurnId !== null) return;
  ui.prompt.value = "";
  ui.send.disabled = true;
  // Drawn once here; turn.accepted adopts this element instead of adding a second one.
  state.pendingUserBubble = addUserBubble(prompt);
  try {
    const accepted = await api(`/v1/sessions/${state.sessionId}/turns`, {
      method: "POST",
      headers: { "idempotency-key": crypto.randomUUID() },
      body: JSON.stringify({ messages: [{ role: "user", content: prompt }] }),
    });
    if (state.pendingUserBubble !== null) {
      state.userBubbles.set(accepted.turnId, state.pendingUserBubble);
      state.pendingUserBubble = null;
    }
    ensureAssistantBubble(accepted.turnId);
    // A very fast turn can finish over SSE before this response lands; do not
    // re-arm the composer lock for a turn that is already over.
    if (!state.finishedTurns.has(accepted.turnId)) setActiveTurn(accepted.turnId);
  } catch (error) {
    state.pendingUserBubble = null;
    const element = document.createElement("div");
    element.className = "bubble assistant error";
    element.textContent = `turn 제출 실패: ${error.message}`;
    ui.messages.append(element);
    setActiveTurn(null);
    if (error.status === 404) {
      // The session is gone (backend restarted, evicted, deleted elsewhere).
      element.textContent += " · 새 세션을 시작합니다.";
      await newSession();
    }
  }
}

async function abortTurn() {
  if (state.sessionId === null || state.activeTurnId === null) return;
  try {
    await api(`/v1/sessions/${state.sessionId}/turns/${state.activeTurnId}/abort`, { method: "POST", body: "{}" });
  } catch (error) {
    console.warn("abort failed", error);
  }
}

async function resumeOrCreate() {
  const wanted = location.hash.replace(/^#/, "");
  if (wanted !== "") {
    try {
      const snapshot = await api(`/v1/sessions/${wanted}`);
      if (state.source) state.source.close();
      resetView();
      state.sessionId = snapshot.sessionId;
      ui.sessionId.textContent = snapshot.sessionId;
      ui.revision.textContent = snapshot.runtimeRevisionDigest;
      openEvents(snapshot.sessionId); // replays the durable log from id 0
      return;
    } catch {
      // fall through: the backend restarted, or the session was deleted
    }
  }
  await newSession();
}

ui.composer.addEventListener("submit", (event) => {
  event.preventDefault();
  void submitPrompt();
});
ui.prompt.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
    event.preventDefault();
    void submitPrompt();
  }
});
ui.abort.addEventListener("click", () => void abortTurn());
// Browser back/forward (or a pasted #session) switches sessions.
window.addEventListener("hashchange", () => {
  const wanted = location.hash.replace(/^#/, "");
  if (wanted !== "" && wanted !== state.sessionId) void resumeOrCreate();
});
ui.newSession.addEventListener("click", () => void newSession());
ui.clearLog.addEventListener("click", () => {
  ui.eventList.innerHTML = "";
});

(async () => {
  try {
    renderCapabilities(await api("/v1/capabilities"));
    await resumeOrCreate();
  } catch (error) {
    ui.caps.textContent = `backend 연결 실패: ${error.message}`;
  }
})();
