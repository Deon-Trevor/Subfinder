#!/usr/bin/env node
// Use the protected publication route with remote staging storage, never production.
import { randomBytes } from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { resolve } from "node:path";

const workerRoot = resolve(import.meta.dirname, "../cloudflare/compaction-worker");
const wrangler = resolve(workerRoot, "node_modules/.bin/wrangler");
const [action, generation, flag] = process.argv.slice(2);
if (!(["activate", "rollback"].includes(action) && /^[a-f0-9]{64}$/.test(generation) &&
  (flag === undefined || flag === "--execute") && process.argv.length <= 5)) {
  throw new Error("usage: staging_generation_admin.mjs activate|rollback GENERATION_ID [--execute]");
}

function sql(query) {
  const raw = execFileSync(wrangler, [
    "d1", "execute", "subfinder-generation-stage-ledger", "--remote", "--json",
    "--config", "wrangler.staging.jsonc", "--command", query,
  ], { cwd: workerRoot, encoding: "utf8" });
  const result = JSON.parse(raw);
  if (result.length !== 1 || result[0].success !== true) throw new Error("staging D1 query failed");
  return result[0].results;
}

const rows = sql(`SELECT state, base_generation, candidate_root_key FROM catalog_generations ` +
  `WHERE generation_id = '${generation}'`);
const expectedState = action === "activate" ? "published" : "active";
if (rows.length !== 1 || rows[0].state !== expectedState) {
  throw new Error(`generation must be ${expectedState} before ${action}`);
}
const remaining = sql(`SELECT count(*) AS count FROM catalog_deltas ` +
  `WHERE generation_id = '${generation}' AND state != 'mapped'`)[0].count;
const partitions = sql(`SELECT state, count(*) AS count FROM generation_partitions ` +
  `WHERE generation_id = '${generation}' GROUP BY state`);
if (remaining !== 0 || partitions.length !== 1 || partitions[0].state !== "reduced") {
  throw new Error("generation has unfinished map or reduce work");
}
console.log(JSON.stringify({ action, generation, partitions: partitions[0].count,
  candidate: rows[0].candidate_root_key, execute: flag === "--execute" }));
if (flag !== "--execute") process.exit(0);

const token = randomBytes(32).toString("hex");
const port = 18792;
const child = spawn(wrangler, [
  "dev", "--config", "wrangler.staging-admin.jsonc", "--ip", "127.0.0.1",
  "--port", String(port), "--var", `PUBLISH_TOKEN:${token}`,
], { cwd: workerRoot, stdio: ["ignore", "pipe", "pipe"] });

let childExited = false;
child.stdout.resume();
child.stderr.resume();
child.on("exit", () => { childExited = true; });

async function waitForAdmin() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (childExited) throw new Error("local staging admin exited before it was ready");
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`, {
        signal: AbortSignal.timeout(1000),
      });
      if (response.ok && await response.text() === "ok") return;
    } catch {
      // Wrangler can take a few seconds to start its local listener.
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 1000));
  }
  throw new Error("local staging admin did not start");
}

try {
  await waitForAdmin();
  const response = await fetch(`http://127.0.0.1:${port}/admin/${action}`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: JSON.stringify({ generation_id: generation }),
    signal: AbortSignal.timeout(300000),
  });
  const document = await response.json();
  if (!response.ok) throw new Error(`staging ${action} failed: ${document.detail ?? response.status}`);
  console.log(JSON.stringify({ status: response.status, result: document }));
  const expected = action === "activate" ? generation : rows[0].base_generation;
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const live = await fetch("https://subfinder.pundit.workers.dev/ready", {
      signal: AbortSignal.timeout(10000),
    });
    if (live.ok && (await live.json()).generation === expected) {
      console.log(JSON.stringify({ live_generation: expected, verified: true }));
      process.exitCode = 0;
      break;
    }
    if (attempt === 11) throw new Error("active root changed, but live preview did not verify");
    await new Promise((resolveWait) => setTimeout(resolveWait, 5000));
  }
} finally {
  child.kill("SIGINT");
}
