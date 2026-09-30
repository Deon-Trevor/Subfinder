#!/usr/bin/env node
// Read and hash every immutable object of one published staging generation.
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { resolve } from "node:path";
import { retryR2Read } from "./retry_r2_read.mjs";

const generation = process.argv[2];
const metadataOnly = process.argv[3] === "--metadata-only";
if (!/^[a-f0-9]{64}$/.test(generation ?? "") || process.argv.length > 4 ||
    (process.argv.length === 4 && !metadataOnly)) {
  throw new Error("usage: verify_staging_generation.mjs GENERATION_ID [--metadata-only]");
}

const worker = resolve(import.meta.dirname, "../cloudflare/compaction-worker");
const wrangler = resolve(worker, "node_modules/.bin/wrangler");
const bucket = "subfinder-catalog-stage";
const config = "wrangler.staging.jsonc";

function sql(query) {
  const raw = execFileSync(wrangler, ["d1", "execute",
    "subfinder-generation-stage-ledger", "--remote", "--json", "--config", config,
    "--command", query], { cwd: worker, encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  const result = JSON.parse(raw);
  if (result.length !== 1 || result[0].success !== true) {
    throw new Error("staging generation ledger query failed");
  }
  return result[0].results;
}

function object(key) {
  return execFileSync(wrangler, ["r2", "object", "get", `${bucket}/${key}`,
    "--remote", "--pipe", "--config", config],
  { cwd: worker, maxBuffer: 16 * 1024 * 1024 });
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function hashObject(key, expectedBytes, expectedHash) {
  if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 1 ||
      !/^[a-f0-9]{64}$/.test(expectedHash ?? "")) {
    throw new Error(`invalid object metadata for ${key}`);
  }
  return new Promise((resolveHash, reject) => {
    const child = spawn(wrangler, ["r2", "object", "get", `${bucket}/${key}`,
      "--remote", "--pipe", "--config", config], { cwd: worker, stdio: ["ignore", "pipe", "pipe"] });
    const digest = createHash("sha256");
    let size = 0;
    let errors = "";
    child.stdout.on("data", (chunk) => { size += chunk.length; digest.update(chunk); });
    child.stderr.on("data", (chunk) => { errors = (errors + chunk).slice(-2000); });
    child.on("error", (error) => reject(new Error(`R2 read failed for ${key}: ${error.message}`)));
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error(`R2 read failed for ${key}: ${errors.trim()}`));
      if (size !== expectedBytes || digest.digest("hex") !== expectedHash) {
        return reject(new Error(`R2 size or checksum mismatch for ${key}`));
      }
      resolveHash(size);
    });
  });
}

const rows = sql(`SELECT base_generation,state,delta_count,partition_count,` +
  `candidate_root_key,candidate_root_sha256,error FROM catalog_generations ` +
  `WHERE generation_id='${generation}'`);
if (rows.length !== 1 || rows[0].state !== "published" || rows[0].error !== null ||
    rows[0].candidate_root_key !== `catalog/candidates/${generation}.json` ||
    rows[0].partition_count !== 256 || rows[0].delta_count < 1) {
  throw new Error("generation is not a complete published staging candidate");
}
const ledger = rows[0];
const rawCandidate = object(ledger.candidate_root_key);
if (sha256(rawCandidate) !== ledger.candidate_root_sha256) {
  throw new Error("candidate root checksum differs from the ledger");
}
const candidate = JSON.parse(rawCandidate);
const rawRoot = object("catalog/root.json");
const root = JSON.parse(rawRoot);
if (candidate.format !== "subfinder.r2-index.v2" ||
    candidate.generation !== generation || root.generation !== ledger.base_generation ||
    candidate.domain_policy_version !== root.domain_policy_version ||
    candidate.psl_sha256 !== root.psl_sha256 ||
    candidate.partition_nibbles !== 2 ||
    Object.keys(candidate.partitions ?? {}).length !== ledger.partition_count) {
  throw new Error("candidate format, identity, partition count, or base root differs");
}

const parts = sql(`SELECT prefix,state,output_json FROM generation_partitions ` +
  `WHERE generation_id='${generation}' ORDER BY prefix`);
if (parts.length !== ledger.partition_count) throw new Error("ledger partition count differs");
const files = [];
const stats = { ...root.stats };
const statsKeys = ["apex_count", "hostname_count", "dated_hostname_count",
  "source_observation_count", "ct_hostname_count"];
for (const key of statsKeys) stats[key] ??= 0;
const sources = new Set(root.source_names ?? []);
const ctSources = new Set(root.ct_source_names ?? []);
for (const row of parts) {
  if (!/^[a-f0-9]{2}$/.test(row.prefix) || row.state !== "reduced") {
    throw new Error(`partition ${row.prefix} is not reduced`);
  }
  const output = JSON.parse(row.output_json);
  const metadata = output.metadata;
  if (!isDeepStrictEqual(candidate.partitions[row.prefix], metadata) ||
      metadata.index !== `catalog/generations/${generation}/partitions/${row.prefix}.index.json.gz` ||
      metadata.bundle !== `catalog/generations/${generation}/partitions/${row.prefix}.bundle`) {
    throw new Error(`candidate partition ${row.prefix} differs from the ledger`);
  }
  files.push([metadata.index, metadata.index_bytes, metadata.index_sha256]);
  files.push([metadata.bundle, metadata.bundle_bytes, metadata.bundle_sha256]);
  for (const key of statsKeys) stats[key] += output.stats_delta[key];
  for (const name of output.source_names) sources.add(name);
  for (const name of output.ct_source_names) ctSources.add(name);
  if (output.last_ingest_at &&
      (!stats.last_ingest_at || output.last_ingest_at > stats.last_ingest_at)) {
    stats.last_ingest_at = output.last_ingest_at;
  }
}
stats.source_count = sources.size;
stats.ct_log_count = ctSources.size;
stats.last_ingest_at ??= null;
if (!isDeepStrictEqual(candidate.stats, stats) ||
    !isDeepStrictEqual(candidate.source_names, [...sources].sort()) ||
    !isDeepStrictEqual(candidate.ct_source_names, [...ctSources].sort())) {
  throw new Error("candidate totals or source metadata differ from the reduced partitions");
}

let cursor = 0;
let verifiedBytes = 0;
async function workerLoop() {
  while (cursor < files.length) {
    const [key, bytes, hash] = files[cursor++];
    const size = await retryR2Read(() => hashObject(key, bytes, hash));
    verifiedBytes += size;
  }
}
if (!metadataOnly) await Promise.all(Array.from({ length: 4 }, workerLoop));
const expectedBytes = files.reduce((total, [, bytes]) => total + bytes, 0);
if (!metadataOnly && verifiedBytes !== expectedBytes) {
  throw new Error("verified object byte total differs from the candidate");
}
console.log(JSON.stringify({ generation, baseGeneration: root.generation,
  state: ledger.state, deltas: ledger.delta_count, partitions: parts.length,
  objects: metadataOnly ? 0 : files.length, verifiedBytes, expectedBytes,
  candidateSha256: sha256(rawCandidate),
  candidateStats: candidate.stats }));
