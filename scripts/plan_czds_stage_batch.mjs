#!/usr/bin/env node
// Read-only preflight for the next stage-only CZDS batch.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const repo = resolve(import.meta.dirname, "..");
const worker = resolve(repo, "cloudflare/czds-worker");
const batch = JSON.parse(readFileSync(resolve(import.meta.dirname,
  process.argv[2] ?? "czds_top15_batch.json")));
const config = JSON.parse(readFileSync(resolve(worker, "wrangler.staging.jsonc")));
const zones = batch.zones;

if (batch.schema_version !== 1 || !Array.isArray(zones) ||
    zones.length < 1 || zones.length > 100 || new Set(zones).size !== zones.length ||
    zones.some((zone) => typeof zone !== "string" || !/^[a-z0-9-]+$/.test(zone)) ||
    ![undefined, "container", "worker"].includes(batch.parser)) {
  throw new Error("CZDS batch must contain 1-100 distinct ASCII zones and a known parser");
}
if (config.vars?.CZDS_STAGE_ONLY !== "true" ||
    config.vars?.CZDS_MAX_ZONES !== "1" ||
    config.triggers?.crons?.length !== 0 ||
    config.workers_dev !== false || config.preview_urls !== false ||
    ![1, 2].includes(config.containers?.[0]?.max_instances)) {
  throw new Error("staging CZDS isolation settings are not intact");
}
const containerZones = new Set((config.vars.CZDS_CONTAINER_ZONES ?? "").split(","));
const wrongParser = zones.filter((zone) => containerZones.has(zone) !== (batch.parser !== "worker"));
if (wrongParser.length) throw new Error(`CZDS parser path differs from batch: ${wrongParser.join(", ")}`);

const wrangler = resolve(worker, "node_modules/.bin/wrangler");
const result = JSON.parse(execFileSync(wrangler, [
  "d1", "execute", "subfinder-czds-stage-control", "--remote", "--json",
  "--config", "wrangler.staging.jsonc", "--command",
  "SELECT zone,state,job_id FROM czds_jobs ORDER BY zone,created_at",
], { cwd: worker, maxBuffer: 16 * 1024 * 1024 }));
if (result.length !== 1 || result[0].success !== true) {
  throw new Error("remote staging CZDS ledger query failed");
}
const jobs = result[0].results;
const active = jobs.filter((job) => job.state === "queued" || job.state === "running");
if (active.length) throw new Error(`CZDS jobs are already active: ${active.map((job) => job.zone).join(", ")}`);
const failed = jobs.filter((job) => zones.includes(job.zone) && job.state === "failed");
if (failed.length) throw new Error(`review failed CZDS jobs first: ${failed.map((job) => job.zone).join(", ")}`);
const completed = new Set(jobs.filter((job) => job.state === "staged" || job.state === "complete")
  .map((job) => job.zone));
const pending = zones.filter((zone) => !completed.has(zone));
console.log(JSON.stringify({ batch: process.argv[2] ?? "czds_top15_batch.json",
  parser: batch.parser ?? "container", rankedAt: batch.ranked_at,
  completed: zones.filter((zone) => completed.has(zone)),
  pending, nextZone: pending[0] ?? null, configuredOnlyZone: config.vars.CZDS_ONLY_ZONE,
  stageOnly: true, cronCount: 0, maxInstances: config.containers[0].max_instances }, null, 2));
