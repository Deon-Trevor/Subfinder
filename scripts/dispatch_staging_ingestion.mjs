#!/usr/bin/env node
// Deliver one locally scheduled staging job to its deployed Queue consumer.
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

const account = "13420e9593fa2a2b308bbdb9256daccf";
const targets = {
  ct: {
    directory: "ingest-worker",
    database: "subfinder-ct-stage-control",
    table: "ingest_jobs",
    queue: "subfinder-direct-ct-stage",
    deadQueue: "subfinder-direct-ct-stage-dead",
    consumer: "subfinder-direct-ct-stage",
    schema: "subfinder.direct-ct-job.v1",
  },
  urlscan: {
    directory: "urlscan-worker",
    database: "subfinder-urlscan-stage-control",
    table: "urlscan_jobs",
    queue: "subfinder-urlscan-stage",
    deadQueue: "subfinder-urlscan-stage-dead",
    consumer: "subfinder-urlscan-stage",
    schema: "subfinder.urlscan-job.v1",
  },
};
const [kind, jobId, flag] = process.argv.slice(2);
if (!(Object.hasOwn(targets, kind) && /^[a-f0-9]{64}$/.test(jobId ?? "") &&
  (flag === undefined || flag === "--execute") && process.argv.length <= 5)) {
  throw new Error("usage: dispatch_staging_ingestion.mjs ct|urlscan JOB_ID [--execute]");
}

const target = targets[kind];
const workerRoot = resolve(import.meta.dirname, `../cloudflare/${target.directory}`);
const wrangler = resolve(workerRoot, "node_modules/.bin/wrangler");
const raw = execFileSync(wrangler, [
  "d1", "execute", target.database, "--remote", "--json",
  "--config", "wrangler.staging.jsonc",
  "--command", `SELECT state${kind === "urlscan" ? ", origin" : ""} FROM ${target.table} WHERE job_id = '${jobId}'`,
], { cwd: workerRoot, encoding: "utf8" });
const query = JSON.parse(raw);
if (query.length !== 1 || query[0].success !== true) throw new Error("staging D1 query failed");
const rows = query[0].results;
if (rows.length !== 1 || rows[0].state !== "queued" ||
  (kind === "urlscan" && rows[0].origin !== "scheduled")) {
  throw new Error("job must be a queued, scheduled staging job");
}

const token = process.env.CLOUDFLARE_API_TOKEN || JSON.parse(execFileSync(wrangler, [
  "auth", "token", "--json",
], { cwd: workerRoot, encoding: "utf8" })).token;

async function api(path, options = {}) {
  const response = await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/${path}`, {
    ...options,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    signal: AbortSignal.timeout(20000),
  });
  const document = await response.json();
  if (!response.ok || document.success !== true || document.errors?.length) {
    throw new Error(`Cloudflare API ${path} failed: HTTP ${response.status}`);
  }
  return document;
}

async function queueByName(name) {
  for (let page = 1; ; page += 1) {
    const listing = await api(`queues?per_page=100&page=${page}`);
    const found = listing.result.find((queue) => queue.queue_name === name);
    if (found) return found;
    if (page >= listing.result_info.total_pages) break;
  }
  throw new Error(`staging Queue ${name} was not found`);
}

const [queue, deadQueue] = await Promise.all([
  queueByName(target.queue), queueByName(target.deadQueue),
]);
if (queue.settings?.delivery_paused ||
  !queue.consumers?.some((consumer) => consumer.script === target.consumer &&
    consumer.dead_letter_queue === target.deadQueue)) {
  throw new Error("staging Queue is paused or the expected consumer is not attached");
}
const [mainMetrics, deadMetrics] = await Promise.all([
  api(`queues/${queue.queue_id}/metrics`),
  api(`queues/${deadQueue.queue_id}/metrics`),
]);
if (mainMetrics.result.backlog_count !== 0 || deadMetrics.result.backlog_count !== 0) {
  throw new Error("staging Queue or dead-letter Queue is not empty");
}

console.log(JSON.stringify({ kind, job_id: jobId, queue: target.queue,
  consumer: target.consumer, execute: flag === "--execute" }));
if (flag === "--execute") {
  await api(`queues/${queue.queue_id}/messages`, {
    method: "POST",
    body: JSON.stringify({ content_type: "json", body: {
      schema_version: target.schema,
      job_id: jobId,
    } }),
  });
  console.log(JSON.stringify({ job_id: jobId, submitted: true }));
}
