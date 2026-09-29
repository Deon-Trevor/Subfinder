#!/usr/bin/env node
// Rank historical CZDS artifacts for stage-only runs; live approval is checked by the scheduler.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const scripts = import.meta.dirname;
const worker = resolve(scripts, "../cloudflare/czds-worker");

export function selectSmallBatch(records, jobs, reserved, limit, maxBytes) {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new Error("CZDS batch limits are invalid");
  }
  const seen = new Set();
  const candidates = records.map((record) => {
    const match = /^([a-z0-9-]+)\.zone\.gz$/.exec(record.relative_filename);
    if (!match || !Number.isSafeInteger(record.bytes) || record.bytes < 1 ||
        !/^[a-f0-9]{64}$/.test(record.sha256) || seen.has(match[1])) {
      throw new Error("CZDS manifest contains an invalid or duplicate artifact");
    }
    seen.add(match[1]);
    return { zone: match[1], bytes: record.bytes };
  });
  const finished = new Set(jobs.filter((job) =>
    job.state === "staged" || job.state === "complete").map((job) => job.zone));
  const failed = jobs.filter((job) => job.state === "failed" &&
    !finished.has(job.zone) && !reserved.has(job.zone));
  if (failed.length) throw new Error(`review failed CZDS zones: ${failed.map((job) => job.zone).join(", ")}`);
  const occupied = new Set(jobs.map((job) => job.zone));
  return candidates.filter(({ zone, bytes }) =>
    bytes <= maxBytes && !reserved.has(zone) && !occupied.has(zone))
    .sort((left, right) => left.bytes - right.bytes || left.zone.localeCompare(right.zone))
    .slice(0, limit);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const args = process.argv.slice(2);
  if (args.length !== 1 && args.length !== 3 && args.length !== 5) {
    throw new Error("usage: select_czds_small_batch.mjs MANIFEST [--limit N] [--max-bytes N]");
  }
  const manifestPath = resolve(args[0]);
  let limit = 20;
  let maxBytes = 100000;
  for (let index = 1; index < args.length; index += 2) {
    if (args[index] === "--limit") limit = Number(args[index + 1]);
    else if (args[index] === "--max-bytes") maxBytes = Number(args[index + 1]);
    else throw new Error(`unknown CZDS batch option: ${args[index]}`);
  }
  const manifest = readFileSync(manifestPath);
  const records = manifest.toString("utf8").trim().split("\n").map((line) => JSON.parse(line));
  const reserved = new Set(JSON.parse(readFileSync(resolve(scripts, "czds_top15_batch.json"))).zones);
  const config = JSON.parse(readFileSync(resolve(worker, "wrangler.staging.jsonc")));
  for (const zone of (config.vars?.CZDS_CONTAINER_ZONES ?? "").split(",")) reserved.add(zone);
  const wrangler = resolve(worker, "node_modules/.bin/wrangler");
  const result = JSON.parse(execFileSync(wrangler, [
    "d1", "execute", "subfinder-czds-stage-control", "--remote", "--json",
    "--config", "wrangler.staging.jsonc", "--command",
    "SELECT zone,state FROM czds_jobs ORDER BY zone,created_at",
  ], { cwd: worker, maxBuffer: 16 * 1024 * 1024 }));
  if (result.length !== 1 || result[0].success !== true) {
    throw new Error("remote staging CZDS ledger query failed");
  }
  const selected = selectSmallBatch(records, result[0].results, reserved, limit, maxBytes);
  console.log(JSON.stringify({
    schema_version: 1,
    parser: "worker",
    ranking_basis: "Historical local gzip bytes; not a current CZDS size or approval claim",
    manifest_sha256: createHash("sha256").update(manifest).digest("hex"),
    max_historical_bytes: maxBytes,
    zones: selected.map((row) => row.zone),
    historical_bytes: Object.fromEntries(selected.map((row) => [row.zone, row.bytes])),
  }, null, 2));
}
