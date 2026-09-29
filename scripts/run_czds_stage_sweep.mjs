#!/usr/bin/env node
// Stage one approved CZDS zone at a time. A remote Cron is armed only until one job exists.
import { execFileSync } from "node:child_process";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const repo = resolve(import.meta.dirname, "..");
const worker = resolve(repo, "cloudflare/czds-worker");
const wrangler = resolve(worker, "node_modules/.bin/wrangler");
const batchName = process.argv[2];
const flags = process.argv.slice(3);
const execute = flags.includes("--execute");
const limitIndex = flags.indexOf("--limit");
const limit = limitIndex < 0 ? 100 : Number(flags[limitIndex + 1]);
if (!/^[a-z0-9_-]+\.json$/.test(batchName ?? "") ||
    flags.some((flag, index) => flag !== "--execute" && flag !== "--limit" &&
      (limitIndex < 0 || index !== limitIndex + 1 || !/^\d+$/.test(flag))) ||
    flags.filter((flag) => flag === "--execute").length > 1 ||
    flags.filter((flag) => flag === "--limit").length > 1 ||
    !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
  throw new Error("usage: run_czds_stage_sweep.mjs BATCH.json [--limit 1..100] [--execute]");
}

let interrupted = false;
process.once("SIGINT", () => { interrupted = true; });
process.once("SIGTERM", () => { interrupted = true; });
function checkInterrupted() {
  if (interrupted) throw new Error("stage sweep interrupted");
}

function command(file, args, cwd = repo, allowInterrupted = false) {
  if (!allowInterrupted) checkInterrupted();
  return execFileSync(file, args, {
    cwd, encoding: "utf8", timeout: 120000, maxBuffer: 32 * 1024 * 1024,
  });
}

function sql(database, query, cwd = worker, config = "wrangler.staging.jsonc") {
  const output = JSON.parse(command(wrangler, [
    "d1", "execute", database, "--remote", "--json", "--config", config,
    "--command", query,
  ], cwd));
  if (output.length !== 1 || output[0].success !== true) {
    throw new Error(`staging D1 query failed for ${database}`);
  }
  return output[0].results;
}

function plan() {
  return JSON.parse(command(process.execPath, [
    resolve(repo, "scripts/plan_czds_stage_batch.mjs"), batchName,
  ]));
}

function comGate() {
  const jobId = "8b302c90798d27cf43c03d52c341787fd48c03c4b90ecb44acb0dbbc1a42e107";
  const rows = sql("subfinder-generation-stage-ledger",
    `SELECT count(*) AS total, sum(CASE WHEN g.state = 'active' THEN 1 ELSE 0 END) AS active ` +
    `FROM catalog_deltas d LEFT JOIN catalog_generations g ON g.generation_id = d.generation_id ` +
    `WHERE d.object_key >= 'ingest/czds/com/${jobId}-' ` +
    `AND d.object_key < 'ingest/czds/com/${jobId}.'`,
    resolve(repo, "cloudflare/compaction-worker"));
  const unfinished = sql("subfinder-generation-stage-ledger",
    "SELECT count(*) AS n FROM catalog_generations " +
    "WHERE state IN ('mapping','mapped','reducing','published')",
    resolve(repo, "cloudflare/compaction-worker"));
  return Number(rows[0]?.total) === 8760 && Number(rows[0]?.active) === 8760 &&
    Number(unfinished[0]?.n) === 0;
}

function zoneJobs(zone) {
  return sql("subfinder-czds-stage-control",
    `SELECT job_id,state FROM czds_jobs WHERE zone = '${zone}' ORDER BY created_at`);
}

async function schedules(token) {
  const response = await fetch(
    "https://api.cloudflare.com/client/v4/accounts/13420e9593fa2a2b308bbdb9256daccf/" +
    "workers/scripts/subfinder-czds-stage/schedules",
    { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(10000) },
  );
  const body = await response.json();
  if (!response.ok || body.success !== true || !Array.isArray(body.result?.schedules)) {
    throw new Error("cannot read deployed staging CZDS schedules");
  }
  return body.result.schedules;
}

const configPath = resolve(worker, "wrangler.staging.jsonc");
const base = JSON.parse(readFileSync(configPath, "utf8"));
const temporary = resolve(worker, `.wrangler-czds-sweep-${process.pid}.jsonc`);
const batch = JSON.parse(readFileSync(resolve(repo, "scripts", batchName), "utf8"));
if (batch.parser !== "worker" || base.vars?.CZDS_STAGE_ONLY !== "true" ||
    base.vars?.CZDS_MAX_ZONES !== "1" || base.triggers?.crons?.length !== 0 ||
    base.workers_dev !== false || base.preview_urls !== false) {
  throw new Error("staging-only Worker parser configuration is not intact");
}
const initial = plan();
if (!execute) {
  console.log(JSON.stringify({ execute: false, nextZone: initial.nextZone,
    pending: initial.pending.length, comGate: comGate() }));
  process.exit(0);
}
if (comGate()) {
  console.log(JSON.stringify({ stopped: "com-compaction-gate", staged: 0 }));
  process.exit(0);
}
const token = JSON.parse(command(wrangler, ["auth", "token", "--json"], worker)).token;
if ((await schedules(token)).length !== 0) throw new Error("staging CZDS Cron is already active");

let cronArmed = false;
let staged = 0;
let tempCreated = false;
try {
  writeFileSync(temporary, "", { flag: "wx", mode: 0o600 });
  tempCreated = true;
  for (; staged < limit; staged += 1) {
    checkInterrupted();
    if (comGate()) break;
    const next = plan();
    const zone = next.nextZone;
    if (zone === null) break;
    if (!batch.zones.includes(zone) || zoneJobs(zone).length !== 0) {
      throw new Error(`CZDS zone ${zone} is not a new pending job`);
    }
    const config = structuredClone(base);
    config.vars.CZDS_ONLY_ZONE = zone;
    config.triggers.crons = [];
    writeFileSync(temporary, JSON.stringify(config, null, 2));
    const deployed = command(wrangler, [
      "deploy", "--config", temporary, "--containers-rollout", "none",
    ], worker);
    if (!deployed.includes(`env.CZDS_ONLY_ZONE ("${zone}")`)) {
      throw new Error(`staging Worker deploy did not confirm ${zone}`);
    }
    try {
      config.triggers.crons = ["* * * * *"];
      writeFileSync(temporary, JSON.stringify(config, null, 2));
      cronArmed = true;
      const trigger = command(wrangler, ["triggers", "deploy", "--config", temporary], worker);
      if (!trigger.includes("schedule: * * * * *")) {
        throw new Error("staging Cron deployment was not confirmed");
      }
      let jobs = [];
      // A newly deployed Cloudflare Cron may take up to 15 minutes to propagate.
      for (let poll = 0; poll < 108; poll += 1) {
        checkInterrupted();
        jobs = zoneJobs(zone);
        if (jobs.length !== 0) break;
        await sleep(10000);
      }
      if (jobs.length !== 1 || !/^[a-f0-9]{64}$/.test(jobs[0].job_id)) {
        throw new Error(`exactly one ${zone} job did not appear within 18 minutes`);
      }
      config.triggers.crons = [];
      writeFileSync(temporary, JSON.stringify(config, null, 2));
      const removed = command(wrangler, ["triggers", "deploy", "--config", temporary], worker);
      if (removed.includes("schedule:")) throw new Error("staging Cron removal was not confirmed");
      if ((await schedules(token)).length !== 0) throw new Error("staging Cron remains active");
      cronArmed = false;
      for (let poll = 0; poll < 90; poll += 1) {
        checkInterrupted();
        const state = zoneJobs(zone);
        if (state.length !== 1 || state[0].job_id !== jobs[0].job_id ||
            state[0].state === "failed") {
          throw new Error(`CZDS ${zone} job failed or changed identity`);
        }
        if (state[0].state === "staged") break;
        if (poll === 89) throw new Error(`CZDS ${zone} job did not stage in 15 minutes`);
        await sleep(10000);
      }
      const verified = JSON.parse(command(process.execPath, [
        resolve(repo, "scripts/verify_staged_czds.mjs"), jobs[0].job_id,
      ]));
      if (verified.zone !== zone || verified.registeredDeltas !== 0) {
        throw new Error(`CZDS ${zone} verification differs from the requested zone`);
      }
      console.log(JSON.stringify({ staged: zone, ...verified }));
    } finally {
      if (cronArmed) {
        config.triggers.crons = [];
        writeFileSync(temporary, JSON.stringify(config, null, 2));
        const removed = command(wrangler, ["triggers", "deploy", "--config", temporary], worker, true);
        if (removed.includes("schedule:") || (await schedules(token)).length !== 0) {
          throw new Error("staging CZDS Cron cleanup failed; do not start another zone");
        }
        cronArmed = false;
      }
    }
  }
  console.log(JSON.stringify({ complete: true, staged,
    remaining: plan().pending.length, comGate: comGate() }));
} finally {
  if (tempCreated) unlinkSync(temporary);
}
