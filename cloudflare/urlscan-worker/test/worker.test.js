import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { gunzipSync } from "node:zlib";

import { buildSync } from "esbuild";
import { Miniflare } from "miniflare";

import {
  admitEnrichment,
  enrichmentOptions,
  enrichmentStatus,
  processUrlscanJob,
  recordsFromUrlscan,
  scheduleUrlscan,
} from "../src/index.js";
import urlscanWorker from "../src/index.js";


const workerRoot = resolve(import.meta.dirname, "..");
let miniflare;
let database;
let bucket;


before(async () => {
  const bundle = buildSync({
    bundle: true,
    entryPoints: [resolve(workerRoot, "src/index.js")],
    format: "esm",
    platform: "browser",
    write: false,
  }).outputFiles[0].text;
  miniflare = new Miniflare({
    workers: [{
      config: {
        name: "subfinder-urlscan",
        compatibilityDate: "2026-09-27",
        manifest: {
          mainModule: "index.js",
          modulesRoot: resolve(workerRoot, "src"),
          modules: { "index.js": { type: "esm", contents: bundle } },
        },
        env: {
          CONTROL: { type: "d1", name: "CONTROL" },
          CATALOG: { type: "r2", name: "CATALOG" },
        },
      },
    }],
  });
  database = await miniflare.getD1Database("CONTROL");
  bucket = await miniflare.getR2Bucket("CATALOG");
  for (const name of ["0001_urlscan_ingestion.sql", "0002_on_demand_enrichment.sql",
    "0003_priority_quota.sql", "0004_priority_quota_backfill.sql"]) {
    const migration = readFileSync(resolve(workerRoot, "migrations", name), "utf8");
    for (const statement of migration.split(";").map((value) => value.trim()).filter(Boolean)) {
      await database.prepare(statement).run();
    }
  }
});


beforeEach(async () => {
  await database.exec(
    "DELETE FROM urlscan_jobs; DELETE FROM urlscan_sources; DELETE FROM provider_quota;",
  );
  const objects = await bucket.list();
  if (objects.objects.length > 0) await bucket.delete(objects.objects.map((item) => item.key));
});


after(async () => {
  await miniflare?.dispose();
});


function responsePayload(size = 2) {
  const results = [
    {
      page: { domain: "WWW.EXAMPLE.COM" },
      task: { domain: "www.example.com", time: "2026-09-27T01:00:00Z" },
      sort: [100, "one"],
    },
    {
      page: { domain: "outside.example.net" },
      task: { domain: "api.example.com", time: "2026-09-27T02:00:00Z" },
      sort: [99, "two"],
    },
  ];
  return { results: results.slice(0, size) };
}


test("URLScan result parsing keeps only exact-apex observations and a full-page cursor", () => {
  const parsed = recordsFromUrlscan(responsePayload(), "example.com", 2);
  assert.equal(parsed.entryCount, 2);
  assert.equal(parsed.nextCursor, "99,two");
  assert.deepEqual(parsed.records, [
    {
      apex: "example.com",
      hostname: "api.example.com",
      first_seen: "2026-09-27T02:00:00.000Z",
    },
    {
      apex: "example.com",
      hostname: "www.example.com",
      first_seen: "2026-09-27T01:00:00.000Z",
    },
  ]);
});


test("scheduler and consumer persist a page, quota charge, cursor, and delta-ready event", async () => {
  const now = new Date("2026-09-27T03:00:00.000Z");
  await database.prepare(
    `INSERT INTO urlscan_sources(apex, cursor, next_run_at, updated_at)
     VALUES ('example.com', NULL, ?, ?)`,
  ).bind(now.toISOString(), now.toISOString()).run();
  const jobs = [];
  const deltas = [];
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    URLSCAN_API_KEY: "secret",
    URLSCAN_PAGE_SIZE: "2",
    URLSCAN_REFRESH_SECONDS: "86400",
    URLSCAN_QUEUE: { send: async (message) => jobs.push(message) },
    COMPACTION_QUEUE: { send: async (message) => deltas.push(message) },
    URLSCAN_FETCHER: {
      fetch: async (request) => {
        const url = new URL(request.url || request);
        assert.equal(url.hostname, "urlscan.io");
        assert.equal(url.searchParams.get("q"), "page.domain:example.com");
        return Response.json(responsePayload());
      },
    },
  };
  assert.equal(await scheduleUrlscan(env, now), 1);
  assert.equal(jobs.length, 1);
  const result = await processUrlscanJob(env, jobs[0]);
  assert.equal(result.state, "complete");
  assert.equal(result.duplicate, false);
  assert.equal(deltas.length, 1);
  assert.equal(deltas[0].source_kind, "urlscan");
  const stored = await bucket.get(result.objectKey);
  const document = JSON.parse(gunzipSync(Buffer.from(await stored.arrayBuffer())));
  assert.deepEqual(document.records.map((record) => record.hostname), [
    "api.example.com",
    "www.example.com",
  ]);
  assert.equal(
    (await database.prepare(
      "SELECT used FROM provider_quota WHERE provider = 'urlscan:breadth'",
    ).first()).used,
    1,
  );
  assert.equal(
    (await database.prepare(
      "SELECT cursor FROM urlscan_sources WHERE apex = 'example.com'",
    ).first()).cursor,
    "99,two",
  );

  assert.deepEqual(await processUrlscanJob(env, jobs[0]), {
    state: "complete",
    duplicate: true,
  });
  assert.equal(deltas.length, 2);
  assert.equal(
    (await database.prepare(
      "SELECT used FROM provider_quota WHERE provider = 'urlscan:breadth'",
    ).first()).used,
    1,
  );
});


test("production URLScan namespace cannot overwrite staging delta keys or IDs", async () => {
  const jobId = "a".repeat(64);
  await database.prepare(
    `INSERT INTO urlscan_sources(apex, cursor, enabled, next_run_at, updated_at)
     VALUES ('example.com', NULL, 0, '2026-09-27T03:00:00Z', '2026-09-27T03:00:00Z')`,
  ).run();
  await database.prepare(
    `INSERT INTO urlscan_jobs(job_id, apex, cursor, state, created_at, updated_at)
     VALUES (?, 'example.com', NULL, 'queued', '2026-09-27T03:00:00Z', '2026-09-27T03:00:00Z')`,
  ).bind(jobId).run();
  const deltas = [];
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    URLSCAN_API_KEY: "secret",
    URLSCAN_DELTA_NAMESPACE: "prod",
    COMPACTION_QUEUE: { send: async (message) => deltas.push(message) },
    URLSCAN_FETCHER: { fetch: async () => Response.json(responsePayload(1)) },
  };
  const result = await processUrlscanJob(env, { schema_version: "subfinder.urlscan-job.v1", job_id: jobId });
  assert.equal(result.objectKey, `ingest/urlscan/prod/example.com/${jobId}.json.gz`);
  assert.notEqual(deltas[0].delta_id, jobId);
  assert.equal(deltas[0].object_key, result.objectKey);
  await processUrlscanJob(env, { schema_version: "subfinder.urlscan-job.v1", job_id: jobId });
  assert.deepEqual(deltas[1], deltas[0]);
});


test("consumer fails closed without the URLSCAN_API_KEY Worker secret", async () => {
  const now = new Date("2026-09-27T03:00:00.000Z");
  await database.prepare(
    `INSERT INTO urlscan_sources(apex, cursor, next_run_at, updated_at)
     VALUES ('example.com', NULL, ?, ?)`,
  ).bind(now.toISOString(), now.toISOString()).run();
  const jobs = [];
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    URLSCAN_QUEUE: { send: async (message) => jobs.push(message) },
    COMPACTION_QUEUE: { send: async () => {} },
  };
  await scheduleUrlscan(env, now);
  await assert.rejects(processUrlscanJob(env, jobs[0]), /secret is not configured/);
});


test("quota stops provider calls after the configured UTC-day limit", async () => {
  const now = new Date("2026-09-27T03:00:00.000Z");
  for (const apex of ["example.com", "example.net"]) {
    await database.prepare(
      `INSERT INTO urlscan_sources(apex, cursor, next_run_at, updated_at)
       VALUES (?, NULL, ?, ?)`,
    ).bind(apex, now.toISOString(), now.toISOString()).run();
  }
  const jobs = [];
  let calls = 0;
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    URLSCAN_API_KEY: "secret",
    URLSCAN_BREADTH_DAILY_LIMIT: "1",
    URLSCAN_PAGE_SIZE: "2",
    URLSCAN_QUEUE: { send: async (message) => jobs.push(message) },
    COMPACTION_QUEUE: { send: async () => {} },
    URLSCAN_FETCHER: {
      fetch: async () => {
        calls += 1;
        return Response.json(responsePayload(1));
      },
    },
  };
  assert.equal(await scheduleUrlscan(env, now), 2);
  await processUrlscanJob(env, jobs[0]);
  await assert.rejects(processUrlscanJob(env, jobs[1]), /quota is exhausted/);
  assert.equal(calls, 1);
});


test("on-demand enrichment is private, idempotent, and leaves publication pending", async () => {
  const messages = [];
  const deltas = [];
  const env = {
    CONTROL: database, CATALOG: bucket,
    URLSCAN_API_KEY: "secret",
    URLSCAN_BREADTH_DAILY_LIMIT: "2",
    URLSCAN_PRIORITY_DAILY_LIMIT: "1",
    URLSCAN_QUEUE: { send: async (message) => messages.push(message) },
    COMPACTION_QUEUE: { send: async (message) => deltas.push(message) },
    URLSCAN_FETCHER: { fetch: async () => Response.json(responsePayload(1)) },
  };
  const options = await enrichmentOptions(env, "example.com");
  assert.equal(options.actions.local_zone.actionable, false);
  assert.equal(options.actions.urlscan.actionable, true);
  const input = { job_id: "a".repeat(64), subject: "ip:test", apex: "example.com" };
  const admitted = await admitEnrichment(env, input);
  assert.equal(admitted.status, 202);
  assert.equal(admitted.headers.get("X-Idempotent-Replay"), "0");
  assert.equal((await admitted.json()).lanes.urlscan.state, "queued");
  assert.equal((await database.prepare(
    "SELECT enabled FROM urlscan_sources WHERE apex = 'example.com'",
  ).first()).enabled, 0);
  assert.equal(await scheduleUrlscan(env), 0);
  assert.equal((await admitEnrichment(env, input)).headers.get("X-Idempotent-Replay"), "1");
  assert.equal(messages.length, 2);
  assert.equal((await admitEnrichment(env, { ...input, apex: "example.net" })).status, 409);
  assert.equal((await enrichmentStatus(env, input.job_id, "ip:someone-else")).status, 404);

  await processUrlscanJob(env, messages[0]);
  assert.equal(deltas.length, 1);
  const status = await enrichmentStatus(env, input.job_id, input.subject);
  assert.equal(status.status, 200);
  const document = await status.json();
  assert.equal(document.state, "done");
  assert.equal(document.lanes.urlscan.state, "pending_publication");
  assert.equal(document.lanes.urlscan.records_ingested, 1);
  assert.equal(document.lanes.urlscan.more_available, false);
  assert.equal(document.result_url, null);
  assert.equal((await enrichmentOptions(env, "example.net")).actions.urlscan.actionable, false);

  const scheduled = {
    CONTROL: database, CATALOG: bucket, URLSCAN_API_KEY: "secret",
    URLSCAN_BREADTH_DAILY_LIMIT: "2", URLSCAN_PRIORITY_DAILY_LIMIT: "1",
    URLSCAN_QUEUE: { send: async (message) => messages.push(message) },
    COMPACTION_QUEUE: { send: async () => {} },
    URLSCAN_FETCHER: { fetch: async () => Response.json(responsePayload(1)) },
  };
  await database.prepare(
    `INSERT INTO urlscan_sources(apex, cursor, next_run_at, updated_at)
     VALUES ('example.net', NULL, '2026-09-27T00:00:00Z', '2026-09-27T00:00:00Z')`,
  ).run();
  assert.equal(await scheduleUrlscan(scheduled), 1);
  await processUrlscanJob(scheduled, messages.at(-1));
  assert.equal((await database.prepare(
    "SELECT used FROM provider_quota WHERE provider = 'urlscan:breadth'",
  ).first()).used, 2);
  assert.equal((await database.prepare(
    "SELECT priority_used FROM provider_quota WHERE provider = 'urlscan:breadth'",
  ).first()).priority_used, 1);
});


test("options do not offer URLScan without its secret", async () => {
  const options = await enrichmentOptions({ CONTROL: database }, "example.com");
  assert.equal(options.actions.urlscan.actionable, false);
  assert.match(options.actions.urlscan.reason, /not configured/);
});


test("a transient on-demand failure stays queued until the final retry", async () => {
  const sent = [];
  const env = {
    CONTROL: database, CATALOG: bucket, URLSCAN_API_KEY: "secret",
    URLSCAN_QUEUE: { send: async (message) => sent.push(message) },
    COMPACTION_QUEUE: { send: async () => {} },
    URLSCAN_FETCHER: { fetch: async () => { throw new Error("temporary failure"); } },
  };
  const input = { job_id: "b".repeat(64), subject: "ip:test", apex: "example.com" };
  assert.equal((await admitEnrichment(env, input)).status, 202);
  let retried = false;
  await urlscanWorker.queue({ messages: [{ body: sent[0], attempts: 1,
    retry: () => { retried = true; }, ack: () => assert.fail("must retry") }] }, env);
  assert.equal(retried, true);
  assert.equal((await enrichmentStatus(env, input.job_id, input.subject)).status, 200);
  assert.equal((await database.prepare(
    "SELECT state FROM urlscan_jobs WHERE job_id = ?",
  ).bind(input.job_id).first()).state, "queued");
  await urlscanWorker.queue({ messages: [{ body: sent[0], attempts: 5,
    retry: () => {}, ack: () => assert.fail("must retry") }] }, env);
  assert.equal((await database.prepare(
    "SELECT state FROM urlscan_jobs WHERE job_id = ?",
  ).bind(input.job_id).first()).state, "failed");
});


test("a failed Queue publish retries the same admitted job", async () => {
  let attempts = 0;
  const env = {
    CONTROL: database, URLSCAN_API_KEY: "secret",
    URLSCAN_QUEUE: { send: async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("queue unavailable");
    } },
  };
  const input = { job_id: "c".repeat(64), subject: "ip:test", apex: "example.com" };
  assert.equal((await admitEnrichment(env, input)).status, 503);
  const retried = await admitEnrichment(env, input);
  assert.equal(retried.status, 202);
  assert.equal(retried.headers.get("X-Idempotent-Replay"), "1");
  assert.equal(attempts, 2);
  assert.equal((await database.prepare(
    "SELECT count(*) AS n FROM urlscan_jobs WHERE job_id = ?",
  ).bind(input.job_id).first()).n, 1);
});


test("a second on-demand pass resumes the stored URLScan cursor", async () => {
  const messages = [];
  const env = {
    CONTROL: database, CATALOG: bucket, URLSCAN_API_KEY: "secret",
    URLSCAN_PAGE_SIZE: "1", URLSCAN_BREADTH_DAILY_LIMIT: "3",
    URLSCAN_PRIORITY_DAILY_LIMIT: "2",
    URLSCAN_QUEUE: { send: async (message) => messages.push(message) },
    COMPACTION_QUEUE: { send: async () => {} },
    URLSCAN_FETCHER: { fetch: async () => Response.json(responsePayload(1)) },
  };
  const first = { job_id: "d".repeat(64), subject: "ip:test", apex: "example.com" };
  assert.equal((await admitEnrichment(env, first)).status, 202);
  await processUrlscanJob(env, messages[0]);
  const report = await (await enrichmentStatus(env, first.job_id, first.subject)).json();
  assert.equal(report.lanes.urlscan.more_available, true);
  const second = { ...first, job_id: "e".repeat(64) };
  assert.equal((await admitEnrichment(env, second)).status, 202);
  assert.equal((await database.prepare(
    "SELECT cursor FROM urlscan_jobs WHERE job_id = ?",
  ).bind(second.job_id).first()).cursor, "100,one");
});
