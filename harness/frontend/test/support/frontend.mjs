import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import { runInNewContext } from "node:vm";

class Element {
  children = [];
  listeners = new Map();
  disabled = false;
  value = "";
  title = "";
  #text = "";
  classList = { add() {}, remove() {} };
  append(...children) { this.children.push(...children); }
  set textContent(value) { this.#text = String(value); this.children = []; }
  get textContent() { return this.#text + this.children.map((child) => child.textContent).join(""); }
  set innerHTML(value) { this.textContent = value; }
  addEventListener(type, listener) { this.listeners.set(type, listener); }
}

export function frontend() {
  const elements = new Map();
  const requests = [];
  const streams = [];
  const location = { hash: "" };
  class EventSource {
    listeners = new Map();
    closed = false;
    constructor(url) { this.url = url; streams.push(this); }
    addEventListener(type, listener) { this.listeners.set(type, listener); }
    close() { this.closed = true; }
    emit(event, lastEventId = "") {
      this.listeners.get(event.type)?.({ data: JSON.stringify(event), lastEventId });
    }
  }
  const context = {
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, new Element());
        return elements.get(id);
      },
      createElement: () => new Element(),
      createTextNode(text) { const element = new Element(); element.textContent = text; return element; },
    },
    window: { addEventListener() {} },
    history: { replaceState(_state, _title, hash) { location.hash = hash; } },
    location, EventSource, console,
    crypto: { randomUUID },
    requestAnimationFrame() {},
    fetch(url, init) {
      // Keep startup suspended so each test selects its own initial session.
      if (url === "/v1/capabilities") return new Promise(() => {});
      return new Promise((resolve, reject) => requests.push({ url, init, resolve, reject }));
    },
  };
  const source = readFileSync(new URL("../../app.js", import.meta.url), "utf8");
  runInNewContext(source + "\nwindow.testApp = { state, ui, newSession, submitPrompt, abortTurn, resumeOrCreate, openEvents, handleEvent };", context);
  const app = context.window.testApp;
  function respond(request, body, status = 200) {
    request.resolve(new Response(status === 204 ? null : JSON.stringify(body), { status }));
  }
  function select(sessionId) {
    app.state.sessionId = sessionId;
    app.openEvents(sessionId);
  }
  async function create(sessionId) {
    const promise = app.newSession();
    respond(requests.shift(), { sessionId, runtimeRevisionDigest: "sha256:revision" });
    await promise;
  }
  function submit(prompt = "hello") {
    app.ui.prompt.value = prompt;
    return app.submitPrompt();
  }
  return { ...app, requests, streams, location, respond, select, create, submit };
}
