import assert from "node:assert/strict";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

const base = process.argv[2] ?? "https://subfinder-index-stage.pundit.workers.dev";
const origin = new URL(base);
if (origin.protocol !== "https:" || origin.pathname !== "/") {
  throw new Error("Expected an HTTPS staging Worker origin");
}

const health = await fetch(new URL("/health", origin));
assert.equal(health.status, 200, "health must respond");
assert.equal(await health.text(), "ok");

for (const route of ["/ready", "/v1/stats", "/v1/search?apex=example.com"]) {
  const response = await fetch(new URL(route, origin));
  assert.equal(response.status, 503, `${route} must remain unready without an active root`);
}

for (const authorization of [undefined, "Bearer invalid-stage-token"]) {
  const response = await fetch(new URL("/internal/v1/record-batches", origin), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": "staging-auth-smoke",
      ...(authorization ? { authorization } : {}),
    },
    body: JSON.stringify({ apexes: ["example.com"] }),
  });
  assert.equal(response.status, 401, "internal batch must require a valid token");
}

if (process.env.SUBFINDER_STAGE_TOKEN) {
  const response = await fetch(new URL("/internal/v1/record-batches/nonexistent", origin), {
    headers: { authorization: `Bearer ${process.env.SUBFINDER_STAGE_TOKEN}` },
  });
  assert.equal(response.status, 404, "valid token must reach the private batch ledger");
}

const deniedOrigin = await fetch(new URL("/mcp", origin), {
  method: "POST",
  headers: { "content-type": "application/json", origin: "https://untrusted.example" },
  body: "{}",
});
assert.equal(deniedOrigin.status, 403, "MCP must reject untrusted browser origins");

const client = new Client({ name: "subfinder-stage-smoke", version: "1.0.0" });
try {
  await client.connect(new StreamableHTTPClientTransport(new URL("/mcp", origin)));
  const listed = await client.listTools();
  assert.deepEqual(listed.tools.map((tool) => tool.name), ["search"]);
} finally {
  await client.close();
}

console.log("Pre-seed staging Worker: health 200; reads 503; unauthorized batches 401; MCP host and origin checks passed.");
