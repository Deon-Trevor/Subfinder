#!/usr/bin/env node
// Requeue only unfinished work for one staging generation. Dry-run by default.
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const account = "13420e9593fa2a2b308bbdb9256daccf";
const queue = "877595bfda8042969d9abe95ae9d7f12";
const deadQueue = "3a5b3ca41870467283f328919b4c1041";
const workerRoot = resolve(import.meta.dirname, "../cloudflare/compaction-worker");
const wrangler = resolve(workerRoot, "node_modules/.bin/wrangler");
const [phase, generation, flag] = process.argv.slice(2);

if (!(["map", "reduce"].includes(phase) && /^[a-f0-9]{64}$/.test(generation) &&
  (flag === undefined || flag === "--execute") && process.argv.length <= 5)) {
  throw new Error("usage: dispatch_staging_compaction.mjs map|reduce GENERATION_ID [--execute]");
}

function sql(query) {
  const raw = execFileSync(wrangler, [
    "d1", "execute", "subfinder-generation-stage-ledger", "--remote", "--json",
    "--config", "wrangler.staging.jsonc", "--command", query,
  ], { cwd: workerRoot, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  const result = JSON.parse(raw);
  if (result.length !== 1 || result[0].success !== true) throw new Error("staging D1 query failed");
  return result[0].results;
}

const token = process.env.CLOUDFLARE_API_TOKEN || JSON.parse(execFileSync(wrangler, [
  "auth", "token", "--json",
], { cwd: workerRoot, encoding: "utf8" })).token;

async function api(queueId, path, body) {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${account}/queues/${queueId}/${path}`,
    {
      method: body === undefined ? "GET" : "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    },
  );
  const document = await response.json();
  if (!response.ok || document.success !== true || document.errors?.length) {
    throw new Error(`staging Queue ${path} failed: HTTP ${response.status}`);
  }
  return document.result;
}

const state = phase === "map" ? "mapping" : "reducing";
const generations = sql(
  `SELECT state FROM catalog_generations WHERE generation_id = '${generation}'`,
);
if (generations.length !== 1 || generations[0].state !== state) {
  throw new Error(`generation must be in ${state} state`);
}

const [mainMetrics, deadMetrics] = await Promise.all([
  api(queue, "metrics"), api(deadQueue, "metrics"),
]);
if (mainMetrics.backlog_count !== 0 || deadMetrics.backlog_count !== 0) {
  throw new Error("staging Queue or dead-letter Queue is not empty");
}

const rows = phase === "map"
  ? sql(`SELECT delta_id AS id FROM catalog_deltas WHERE generation_id = '${generation}' ` +
      "AND state = 'assigned' ORDER BY delta_id")
  : sql(`SELECT prefix AS id FROM generation_partitions WHERE generation_id = '${generation}' ` +
      `AND (state = 'mapped' OR (state = 'reducing' AND lease_until < '${new Date().toISOString()}')) ` +
      "ORDER BY prefix");
console.log(JSON.stringify({ phase, generation, pending: rows.length, execute: flag === "--execute" }));
if (flag !== "--execute") process.exit(0);

for (let offset = 0; offset < rows.length; offset += 100) {
  const messages = rows.slice(offset, offset + 100).map(({ id }) => ({
    content_type: "json",
    body: phase === "map"
      ? { schema_version: "subfinder.map-job.v1", generation_id: generation, delta_id: id }
      : { schema_version: "subfinder.reduce-partition.v1", generation_id: generation, prefix: id },
  }));
  await api(queue, "messages/batch", { messages });
  console.log(JSON.stringify({ published: offset + messages.length, total: rows.length }));
}
