import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { gunzipSync } from "node:zlib";


const TOTAL = 12000;
const HIT_COUNT = 1200;
const ALLOWED_ORIGINS = new Set([
  "https://subfinder-index-stage.pundit.workers.dev",
  "https://subfinder.pundit.workers.dev",
]);
const args = process.argv.slice(2);
const options = {};
for (let index = 0; index < args.length; index += 1) {
  if (args[index] === "--execute" && index === args.length - 1) {
    options.execute = true;
    continue;
  }
  if (!["--origin", "--export", "--key"].includes(args[index]) || !args[index + 1]) {
    throw new Error("usage: benchmark-live-batch.js --origin STAGING_URL --export R2_EXPORT --key RUN_ID [--execute]");
  }
  options[args[index].slice(2)] = args[++index];
}
if (!options.origin || !options.export || !options.key ||
    !/^[A-Za-z0-9_-]{1,128}$/.test(options.key)) {
  throw new Error("staging origin, export directory, and safe idempotency key are required");
}
const origin = new URL(options.origin);
if (!ALLOWED_ORIGINS.has(origin.origin) || origin.pathname !== "/" ||
    origin.search || origin.hash) {
  throw new Error("benchmark only accepts an exact staging Worker origin");
}

const directory = resolve(options.export);
const root = JSON.parse(readFileSync(resolve(directory, "catalog/root.json"), "utf8"));
const pool = [];
for (const metadata of Object.values(root.partitions)) {
  const index = JSON.parse(gunzipSync(readFileSync(resolve(directory, metadata.index))));
  for (const block of index.blocks) {
    if (!Object.hasOwn(index.overflow, block.first_apex)) pool.push(block.first_apex);
  }
}
assert.ok(pool.length >= HIT_COUNT, "export has too few known apexes");
const hits = Array.from({ length: HIT_COUNT }, (_, index) =>
  pool[Math.floor((index + 0.5) * pool.length / HIT_COUNT)]);
const apexes = Array.from({ length: TOTAL }, (_, index) => index % 10 === 0
  ? hits[index / 10]
  : `subfinder-perf-20260929-${String(index).padStart(5, "0")}.com`);
assert.equal(new Set(apexes).size, TOTAL, "benchmark apexes are not unique");
const digest = createHash("sha256").update(JSON.stringify(apexes)).digest("hex");
console.log(JSON.stringify({ phase: "prepared", origin: origin.origin,
  candidates: TOTAL, known_apexes: HIT_COUNT, synthetic_apexes: TOTAL - HIT_COUNT,
  input_sha256: digest, execute: options.execute === true }));
if (!options.execute) process.exit(0);

const token = process.env.SUBFINDER_BENCH_TOKEN || execFileSync("security", [
  "find-generic-password", "-s", "subfinder-stage-threat-hunter",
  "-a", "threat-hunter", "-w",
], { encoding: "utf8" }).trim();
assert.ok(token, "staging service token is missing");
const headers = { authorization: `Bearer ${token}` };
async function request(path, init = {}) {
  const response = await fetch(new URL(path, origin), {
    ...init,
    headers: { ...headers, ...init.headers },
    signal: AbortSignal.timeout(30000),
  });
  const document = await response.json();
  return { response, document };
}

const ready = await request("/ready");
assert.equal(ready.response.status, 200, "staging catalog is not ready");
const auth = await request("/internal/v1/record-batches/nonexistent");
assert.equal(auth.response.status, 404, "staging service token was rejected");
const started = performance.now();
const admitted = await request("/internal/v1/record-batches", {
  method: "POST",
  headers: { "content-type": "application/json", "idempotency-key": options.key },
  body: JSON.stringify({ apexes }),
});
assert.equal(admitted.response.status, 202,
  `batch admission failed: HTTP ${admitted.response.status} ${JSON.stringify(admitted.document)}`);
const jobId = admitted.document.job_id;
console.log(JSON.stringify({ phase: "admitted", job_id: jobId,
  replay: admitted.response.headers.get("x-idempotent-replay"),
  generation: ready.document.generation,
  remaining_allowance: admitted.response.headers.get("x-ratelimit-remaining") }));

let cursor = -1;
let received = 0;
let nonempty = 0;
let errors = 0;
let lastReport = performance.now();
let job;
while (performance.now() - started < 2 * 60 * 60 * 1000) {
  const page = await request(`/internal/v1/record-batches/${jobId}/chunks?after=${cursor}&limit=10&wait=20`);
  assert.equal(page.response.status, 200, `batch poll returned HTTP ${page.response.status}`);
  job = page.document.job;
  for (const chunk of page.document.chunks) {
    assert.equal(chunk.sequence, cursor + 1, "batch chunk sequence is not contiguous");
    for (const item of [...chunk.results, ...chunk.errors]) {
      assert.equal(item.apex, apexes[received], "batch reordered or duplicated an apex");
      if (item.records?.length) nonempty += 1;
      if (item.code) errors += 1;
      received += 1;
    }
    cursor = chunk.sequence;
  }
  assert.equal(cursor, page.document.next_cursor, "batch cursor disagrees with chunks");
  if (performance.now() - lastReport >= 60000 || ["done", "failed", "cancelled"].includes(job.state)) {
    const elapsed = (performance.now() - started) / 1000;
    console.log(JSON.stringify({ phase: "progress", state: job.state,
      received, completed: job.completed_apexes, failed: job.failed_apexes,
      chunks: cursor + 1, elapsed_s: Math.round(elapsed),
      apexes_per_s: Math.round(received / elapsed * 100) / 100 }));
    lastReport = performance.now();
  }
  if (["done", "failed", "cancelled"].includes(job.state)) break;
}
assert.equal(job?.state, "done", `batch did not complete: ${job?.state} ${job?.error}`);
assert.equal(received, TOTAL, "batch did not deliver all requested apexes");
assert.equal(job.completed_apexes, TOTAL);
assert.equal(job.failed_apexes, 0, "batch reported apex errors");
assert.equal(errors, 0, "batch chunks reported apex errors");
assert.equal(job.quota.committed, TOTAL);
assert.equal(job.quota.outstanding, 0);
const elapsed = (performance.now() - started) / 1000;
console.log(JSON.stringify({ phase: "verified", job_id: jobId,
  generation: ready.document.generation, candidates: TOTAL, nonempty,
  empty: TOTAL - nonempty, errors, chunks: cursor + 1,
  elapsed_s: Math.round(elapsed * 100) / 100,
  apexes_per_s: Math.round(TOTAL / elapsed * 100) / 100,
  server_elapsed_s: (Date.parse(job.updated_at) - Date.parse(job.created_at)) / 1000,
  quota: job.quota, input_sha256: digest }));
