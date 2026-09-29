#!/usr/bin/env node
// Verify one staged CZDS Workflow without publishing its deltas.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { gunzipSync } from "node:zlib";

const jobId = process.argv[2];
if (!/^[a-f0-9]{64}$/.test(jobId ?? "") || process.argv.length !== 3) {
  throw new Error("usage: verify_staged_czds.mjs JOB_ID");
}

const root = resolve(import.meta.dirname, "../cloudflare/czds-worker");
const compactionRoot = resolve(import.meta.dirname, "../cloudflare/compaction-worker");
const wrangler = resolve(root, "node_modules/.bin/wrangler");
const config = "wrangler.staging.jsonc";

function command(args, cwd = root) {
  return execFileSync(wrangler, args, { cwd, maxBuffer: 64 * 1024 * 1024 });
}

function sql(database, query, cwd = root) {
  const result = JSON.parse(command([
    "d1", "execute", database, "--remote", "--json", "--config", config,
    "--command", query,
  ], cwd));
  if (result.length !== 1 || result[0].success !== true) {
    throw new Error(`staging D1 query failed for ${database}`);
  }
  return result[0].results;
}

const jobs = sql("subfinder-czds-stage-control",
  `SELECT zone,state,source_fingerprint,hostname_count,delta_count ` +
  `FROM czds_jobs WHERE job_id = '${jobId}'`);
if (jobs.length !== 1 || jobs[0].state !== "staged" ||
    !/^[a-z0-9-]+$/.test(jobs[0].zone) || !jobs[0].source_fingerprint ||
    !Number.isSafeInteger(jobs[0].hostname_count) || jobs[0].hostname_count < 1 ||
    !Number.isSafeInteger(jobs[0].delta_count) || jobs[0].delta_count < 1) {
  throw new Error("CZDS job is not a complete staged artifact");
}
const job = jobs[0];
const workflow = JSON.parse(command([
  "workflows", "instances", "describe", "subfinder-czds-ingestion-stage", jobId,
  "--json", "--config", config,
]));
const finish = workflow.steps?.find((step) => step.name?.startsWith("finish CZDS deltas"));
if (workflow.status !== "complete" || workflow.success !== true ||
    JSON.parse(finish?.output ?? "null")?.state !== "staged") {
  throw new Error("CZDS Workflow did not finish in stage-only mode");
}

const rows = sql("subfinder-czds-stage-control",
  `SELECT chunk_index,delta_id,object_key,record_count FROM czds_job_deltas ` +
  `WHERE job_id = '${jobId}' ORDER BY chunk_index`);
if (rows.length !== job.delta_count) throw new Error("CZDS chunk count differs from the job");
const manifest = createHash("sha256");
let records = 0;
let fetchedBytes = 0;
for (const [index, row] of rows.entries()) {
  const key = `ingest/czds/${job.zone}/${jobId}-${index}.json.gz`;
  const deltaId = createHash("sha256").update(`${jobId}:${index}`).digest("hex");
  if (row.chunk_index !== index || row.delta_id !== deltaId || row.object_key !== key ||
      !Number.isSafeInteger(row.record_count) || row.record_count < 1) {
    throw new Error(`CZDS chunk ${index} has an invalid D1 identity`);
  }
  const bytes = command([
    "r2", "object", "get", `subfinder-catalog-stage/${key}`, "--remote", "--pipe",
    "--config", config,
  ]);
  const payload = JSON.parse(bytes[0] === 0x1f && bytes[1] === 0x8b
    ? gunzipSync(bytes) : bytes);
  if (payload.schema_version !== "subfinder.ingest-delta.v1" ||
      payload.source !== `czds:${job.zone}` || payload.source_id !== job.zone ||
      payload.range?.chunk !== index || payload.entry_count !== row.record_count ||
      payload.hostname_count !== row.record_count ||
      !Array.isArray(payload.records) || payload.records.length !== row.record_count) {
    throw new Error(`CZDS chunk ${index} differs from its R2 object`);
  }
  records += row.record_count;
  fetchedBytes += bytes.byteLength;
  manifest.update(`${key}\t${bytes.byteLength}\t${createHash("sha256").update(bytes).digest("hex")}\n`);
}
if (records !== job.hostname_count) throw new Error("CZDS record total differs from the job");
const registered = sql("subfinder-generation-stage-ledger",
  `SELECT count(*) AS n FROM catalog_deltas WHERE object_key >= ` +
  `'ingest/czds/${job.zone}/${jobId}-' AND object_key < ` +
  `'ingest/czds/${job.zone}/${jobId}.'`, compactionRoot);
if (registered.length !== 1 || registered[0].n !== 0) {
  throw new Error("staged CZDS deltas entered the generation ledger");
}
console.log(JSON.stringify({ jobId, zone: job.zone, workflow: "complete", jobState: "staged",
  chunks: rows.length, records, fetchedBytes, r2ManifestSha256: manifest.digest("hex"),
  registeredDeltas: 0 }));
