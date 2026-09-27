import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { gunzipSync } from "node:zlib";

import { buildSync } from "esbuild";
import { Miniflare } from "miniflare";

import {
  processUrlscanJob,
  recordsFromUrlscan,
  scheduleUrlscan,
} from "../src/index.js";


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
  const migration = readFileSync(
    resolve(workerRoot, "migrations/0001_urlscan_ingestion.sql"),
    "utf8",
  );
  for (const statement of migration.split(";").map((value) => value.trim()).filter(Boolean)) {
    await database.prepare(statement).run();
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
