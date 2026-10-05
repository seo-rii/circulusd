// Drive one session through the running backend and print the durable event
// stream compactly. Useful for checking a real model end to end.
//   node scripts/smoke-turn.mjs [base-url] [prompt...]
const base = process.argv[2] ?? "http://127.0.0.1:8090";
const prompts = process.argv.length > 3 ? process.argv.slice(3) : ["12*(3+4) 계산해줘"];
const timeoutMs = Number(process.env.SMOKE_TIMEOUT_MS ?? "180000");

const capabilities = await (await fetch(`${base}/v1/capabilities`)).json();
console.log(`model: ${capabilities.model.kind} ${capabilities.model.modelId} @ ${capabilities.model.baseUrl ?? "-"}`);
const session = await (await fetch(`${base}/v1/sessions`, { method: "POST", body: "{}" })).json();
console.log(`session: ${session.sessionId}`);

for (const prompt of prompts) {
  const accepted = await (
    await fetch(`${base}/v1/sessions/${session.sessionId}/turns`, {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": crypto.randomUUID() },
      body: JSON.stringify({ messages: [{ role: "user", content: prompt }] }),
    })
  ).json();
  if (accepted.turnId === undefined) {
    console.error("turn rejected:", JSON.stringify(accepted));
    process.exit(1);
  }
  console.log(`\n> ${prompt}   (${accepted.turnId})`);
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const response = await fetch(`${base}/v1/sessions/${session.sessionId}/events`, { signal: controller.signal });
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let thinking = 0;
  let deltas = 0;
  let done = false;
  while (!done) {
    const { value, done: closed } = await reader.read();
    if (closed) break;
    buffer += decoder.decode(value, { stream: true });
    let index = buffer.indexOf("\n\n");
    while (index !== -1) {
      const block = buffer.slice(0, index);
      buffer = buffer.slice(index + 2);
      index = buffer.indexOf("\n\n");
      const data = block.split("\n").find((line) => line.startsWith("data: "));
      if (!data) continue;
      const event = JSON.parse(data.slice(6));
      if (event.turnId !== accepted.turnId && event.type !== "stream.open") continue;
      const d = event.data ?? {};
      const elapsed = `${((Date.now() - started) / 1000).toFixed(1)}s`;
      switch (event.type) {
        case "model.thinking": thinking += d.text.length; break;
        case "model.delta": deltas += 1; break;
        case "model.started": console.log(`  [${elapsed}] model.started  history=${d.historyInjected} ctxMsgs=${d.contextMessages}`); break;
        case "model.settled":
          console.log(`  [${elapsed}] model.settled  stop=${d.stopReason ?? d.outcome} thinking=${thinking}ch deltas=${deltas}` +
            (d.toolCalls?.length ? ` tools=${d.toolCalls.map((c) => `${c.name}(${JSON.stringify(c.arguments)})`).join(",")}` : "") +
            (d.error ? ` error=${d.error.message}` : ""));
          thinking = 0; deltas = 0;
          break;
        case "tool.completed": console.log(`  [${elapsed}] tool.completed ${d.name} -> ${JSON.stringify(d.text)}${d.isError ? " (error)" : ""}`); break;
        case "turn.completed":
          console.log(`  [${elapsed}] turn.completed steps=${d.steps} checkpoint#${d.checkpoint?.sequence}`);
          console.log(`  answer: ${JSON.stringify(d.message?.text)}`);
          done = true;
          break;
        case "turn.failed":
        case "turn.aborted":
          console.log(`  [${elapsed}] ${event.type} ${JSON.stringify(d.error)}`);
          done = true;
          break;
        default: break;
      }
      if (done) break;
    }
  }
  clearTimeout(timer);
  controller.abort();
}
