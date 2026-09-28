import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { gzipSync } from "node:zlib";

import {
  apexForHostname,
  normalizeApex,
  normalizeHostname,
} from "../cloudflare/index-worker/src/domain-policy.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKER = resolve(ROOT, "cloudflare/czds-worker");
const WRANGLER = resolve(WORKER, "node_modules/.bin/wrangler");
const ACCOUNT = "13420e9593fa2a2b308bbdb9256daccf";
const QUEUE = "877595bfda8042969d9abe95ae9d7f12";
const DEAD_QUEUE = "3a5b3ca41870467283f328919b4c1041";
const BUCKET = "subfinder-catalog-stage";
const hex64 = /^[a-f0-9]{64}$/;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function repairDocument(document, expectedCount) {
  if (document?.schema_version !== "subfinder.ingest-delta.v1" ||
      document.source !== "czds:com" || !Array.isArray(document.records) ||
      document.records.length !== expectedCount ||
      document.entry_count !== expectedCount ||
      document.hostname_count !== expectedCount) {
    throw new Error("source document metadata does not match the immutable chunk");
  }
  const records = [];
  let excluded = 0;
  for (const record of document.records) {
    if (record?.first_seen !== null || typeof record.apex !== "string" ||
        typeof record.hostname !== "string") {
      throw new Error("source document contains an unrelated invalid record");
    }
    const hostname = normalizeHostname(record.hostname);
    if (hostname !== record.hostname || apexForHostname(hostname) !== record.apex) {
      throw new Error("source document contains an unrelated invalid record");
    }
    try {
      if (normalizeApex(record.apex) !== record.apex) {
        throw new Error("source document contains an unrelated invalid record");
      }
      records.push(record);
    } catch (error) {
      if (error.message !== "apex must be a valid eTLD+1" ||
          record.apex !== hostname) throw error;
      excluded += 1;
    }
  }
  if (!excluded || !records.length) {
    throw new Error("chunk is not a repairable public-suffix-owner case");
  }
  return {
    document: { ...document, entry_count: records.length,
      hostname_count: records.length, records },
    excluded,
  };
}

function wrangler(args, options = {}) {
  const readOnly = (args[0] === "r2" && args[2] === "get") ||
    (args[0] === "d1" && args.includes("--command") &&
      /^SELECT\b/i.test(args[args.indexOf("--command") + 1]));
  const command = args[0] === "auth" ? args : [...args, "--config", "wrangler.staging.jsonc"];
  for (let attempt = 0; ; attempt += 1) {
    try {
      return execFileSync(WRANGLER, command, {
        cwd: WORKER, encoding: options.encoding, input: options.input,
        maxBuffer: 32 * 1024 * 1024, timeout: 120000,
        stdio: ["pipe", "pipe", "pipe"],
      });
    } catch (error) {
      if (args[0] === "r2" &&
          /object.*not found|does not exist|404/i.test(String(error.stderr ?? error.message))) {
        throw error;
      }
      if (!readOnly || attempt === 2) throw error;
    }
  }
}

function sql(text, database = "subfinder-czds-stage-control") {
  const response = JSON.parse(wrangler([
    "d1", "execute", database, "--remote", "--json", "--command", text,
  ], { encoding: "utf8" }));
  if (response.length !== 1 || !response[0].success) throw new Error("D1 query failed");
  return response[0].results;
}

function readObject(key) {
  return wrangler(["r2", "object", "get", `${BUCKET}/${key}`, "--remote", "--pipe"]);
}

function getRow(jobId, chunkIndex) {
  const rows = sql(`SELECT d.delta_id, d.object_key, d.record_count, j.zone, j.state
    FROM czds_job_deltas d JOIN czds_jobs j USING(job_id)
    WHERE d.job_id = '${jobId}' AND d.chunk_index = ${chunkIndex}`);
  if (rows.length !== 1 || rows[0].zone !== "com" || rows[0].state !== "complete") {
    throw new Error("completed .com source chunk is unavailable");
  }
  if (rows[0].delta_id !== sha256(`${jobId}:${chunkIndex}`) ||
      rows[0].object_key !== `ingest/czds/com/${jobId}-${chunkIndex}.json.gz`) {
    throw new Error("source chunk identity is not the expected immutable identity");
  }
  return rows[0];
}

function ledgerHas(deltaId) {
  const rows = sql(`SELECT state FROM catalog_deltas WHERE delta_id = '${deltaId}'`,
    "subfinder-generation-stage-ledger");
  return rows.length ? rows[0].state : null;
}

function existingRepair(jobId, chunkIndex) {
  return sql(`SELECT * FROM czds_delta_repairs
    WHERE job_id = '${jobId}' AND chunk_index = ${chunkIndex}`)[0] ?? null;
}

async function pushReady(deltaId, objectKey) {
  await queueApi(QUEUE, "messages", { content_type: "json", body: {
    schema_version: "subfinder.delta-ready.v1", delta_id: deltaId,
    source_kind: "czds", object_key: objectKey,
  } });
}

let cachedToken;
function apiToken() {
  if (cachedToken === undefined) {
    cachedToken = process.env.CLOUDFLARE_API_TOKEN ||
      JSON.parse(wrangler(["auth", "token", "--json"], { encoding: "utf8" })).token;
  }
  return cachedToken;
}

async function queueApi(queue, method, body) {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}/queues/${queue}/${method}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiToken()}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  const result = await response.json();
  if (!response.ok || !result.success || result.result?.errors?.length ||
      Object.keys(result.result?.warnings ?? {}).length) {
    throw new Error(`Queue ${method} failed`);
  }
  return result.result;
}

async function repairChunk(jobId, chunkIndex, execute, assertedSource = null) {
  const source = getRow(jobId, chunkIndex);
  if (assertedSource && (assertedSource.delta_id !== source.delta_id ||
      assertedSource.object_key !== source.object_key)) {
    throw new Error("DLQ message does not match immutable source D1");
  }
  if (ledgerHas(source.delta_id)) throw new Error("original chunk is already registered");
  const original = readObject(source.object_key);
  const parsed = JSON.parse(original.toString("utf8"));
  if (parsed.range?.chunk !== chunkIndex || parsed.source_id !== "com") {
    throw new Error("source document range or zone does not match D1");
  }
  const { document, excluded } = repairDocument(parsed, source.record_count);
  const replacement = Buffer.from(JSON.stringify(document));
  const documentSha = sha256(replacement);
  const deltaId = sha256(`${source.delta_id}:${documentSha}`);
  const objectKey = `ingest/czds/com/${jobId}-${chunkIndex}-repair-${documentSha}.json.gz`;
  const expected = {
    original_delta_id: source.delta_id,
    original_object_key: source.object_key,
    original_record_count: source.record_count,
    original_document_sha256: sha256(original),
    replacement_delta_id: deltaId,
    replacement_object_key: objectKey,
    replacement_record_count: document.records.length,
    replacement_document_sha256: documentSha,
    excluded_record_count: excluded,
  };
  const prior = existingRepair(jobId, chunkIndex);
  if (prior && Object.entries(expected).some(([key, value]) => prior[key] !== value)) {
    throw new Error("existing repair audit conflicts with immutable source");
  }
  const summary = { chunk_index: chunkIndex, original_records: source.record_count,
    replacement_records: document.records.length, excluded_records: excluded,
    replacement_delta_id: deltaId, state: execute ? "processing" : "planned" };
  if (!execute) return summary;

  let present = false;
  try {
    present = sha256(Buffer.from(JSON.stringify(JSON.parse(readObject(objectKey).toString("utf8"))))) === documentSha;
    if (!present) throw new Error("existing replacement object conflicts with expected content");
  } catch (error) {
    if (error.message.includes("conflicts")) throw error;
    if (!/object.*not found|does not exist|404/i.test(String(error.stderr ?? error.message))) throw error;
  }
  if (!present) {
    wrangler(["r2", "object", "put", `${BUCKET}/${objectKey}`, "--remote", "--pipe",
      "--content-type", "application/json", "--content-encoding", "gzip"],
    { input: gzipSync(replacement, { mtime: 0 }) });
  }
  const received = JSON.parse(readObject(objectKey).toString("utf8"));
  if (sha256(Buffer.from(JSON.stringify(received))) !== documentSha) {
    throw new Error("replacement R2 readback differs from planned content");
  }
  if (!prior) {
    const now = new Date().toISOString();
    const values = [jobId, chunkIndex, ...Object.values(expected), now]
      .map((value) => typeof value === "number" ? value : `'${value}'`).join(", ");
    sql(`INSERT INTO czds_delta_repairs (
      job_id, chunk_index, original_delta_id, original_object_key,
      original_record_count, original_document_sha256, replacement_delta_id,
      replacement_object_key, replacement_record_count,
      replacement_document_sha256, excluded_record_count, created_at
    ) VALUES (${values})`);
  }
  if (!existingRepair(jobId, chunkIndex)) throw new Error("repair audit was not committed");
  if (ledgerHas(deltaId)) {
    summary.state = "registered";
    return summary;
  }
  await pushReady(deltaId, objectKey);
  summary.state = "queued";
  return summary;
}

async function waitForRegistration(deltaId) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (ledgerHas(deltaId) === "registered") return;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  throw new Error("replacement was queued but registration is not yet verified");
}

async function repairDeadLetters(jobId, limit, execute) {
  const generations = sql("SELECT COUNT(*) AS count FROM catalog_generations",
    "subfinder-generation-stage-ledger");
  if (generations[0]?.count !== 0) throw new Error("staging generation unexpectedly exists");
  let inspected = 0;
  let repaired = 0;
  let excluded = 0;
  while (inspected < limit) {
    const page = await queueApi(DEAD_QUEUE, "messages/peek", {
      batch_size: Math.min(100, limit - inspected),
    });
    const messages = page.messages ?? [];
    if (!messages.length) break;
    const selected = messages.slice(0, limit - inspected);
    const work = selected.map((message) => {
      const body = JSON.parse(message.body);
      const match = /^ingest\/czds\/com\/([a-f0-9]{64})-(\d+)\.json\.gz$/.exec(body.object_key);
      if (body.schema_version !== "subfinder.delta-ready.v1" ||
          body.source_kind !== "czds" || match?.[1] !== jobId ||
          !hex64.test(body.delta_id) || !message.ref) {
        throw new Error("DLQ contains a message outside the approved source job");
      }
      return { message, body, chunkIndex: Number(match[2]) };
    });
    for (let offset = 0; offset < selected.length; offset += 3) {
      const group = work.slice(offset, offset + 3);
      const settled = await Promise.allSettled(group.map(async ({ message, body, chunkIndex }) => {
        const result = await repairChunk(jobId, chunkIndex, execute, body);
        if (execute) {
          await waitForRegistration(result.replacement_delta_id);
          await queueApi(DEAD_QUEUE, "messages/purge", { refs: [{ ref: message.ref }] });
        }
        return result;
      }));
      for (const item of settled) {
        if (item.status === "fulfilled") {
          inspected += 1;
          excluded += item.value.excluded_records;
          if (execute) repaired += 1;
        }
      }
      if (inspected % 10 === 0) {
        console.log(JSON.stringify({ inspected, repaired, excluded }));
      }
      const failure = settled.find((item) => item.status === "rejected");
      if (failure) throw failure.reason;
    }
    if (!execute) break;
  }
  console.log(JSON.stringify({ inspected, repaired, excluded, state: execute ? "verified" : "planned" }));
}

async function main() {
  const args = process.argv.slice(2);
  const job = args[args.indexOf("--job-id") + 1];
  const execute = args.includes("--execute");
  if (!hex64.test(job ?? "")) throw new Error("--job-id must be SHA-256 hex");
  if (args.includes("--dlq")) {
    const limit = args.includes("--limit") ? Number(args[args.indexOf("--limit") + 1]) : 100;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) {
      throw new Error("--limit must be 1..1000");
    }
    await repairDeadLetters(job, limit, execute);
    return;
  }
  const chunk = Number(args[args.indexOf("--chunk") + 1]);
  if (!args.includes("--chunk") || !Number.isSafeInteger(chunk) || chunk < 0) {
    throw new Error("usage: node scripts/czds_delta_repair.mjs --job-id HEX64 --chunk N [--execute]; or --dlq [--limit N] [--execute]");
  }
  console.log(JSON.stringify(await repairChunk(job, chunk, execute)));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`repair stopped: ${error.message}`);
    process.exitCode = 1;
  });
}
