import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { after, before, test } from "node:test";
import { gunzipSync } from "node:zlib";

import { buildSync } from "esbuild";
import { Miniflare } from "miniflare";

import {
  processDirectCtJob,
  scheduleDirectCt,
} from "../src/index.js";


const workerRoot = resolve(import.meta.dirname, "..");
const fixture = JSON.parse(execFileSync(
  resolve(workerRoot, "../../.venv/bin/python"),
  [resolve(import.meta.dirname, "build-ct-fixture.py")],
  { encoding: "utf8" },
));
let miniflare;
let database;
let bucket;


before(async () => {
  const bundle = buildSync({
    bundle: true,
    conditions: ["workerd", "worker", "browser"],
    entryPoints: [resolve(workerRoot, "src/index.js")],
    format: "esm",
    platform: "browser",
    write: false,
  }).outputFiles[0].text;
  miniflare = new Miniflare({
    workers: [{
      config: {
        name: "subfinder-ingest",
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
    resolve(workerRoot, "migrations/0001_ingestion.sql"),
    "utf8",
  );
  for (const statement of migration.split(";").map((value) => value.trim()).filter(Boolean)) {
    await database.prepare(statement).run();
  }
});


after(async () => {
  await miniflare?.dispose();
});


function ctFetcher(request) {
  const url = new URL(request.url || request);
  if (url.pathname.endsWith("/ct/v1/get-sth")) {
    return new Response(JSON.stringify({ tree_size: 3 }), {
      headers: { "content-type": "application/json" },
    });
  }
  if (url.pathname.endsWith("/ct/v1/get-entries")) {
    return new Response(JSON.stringify({ entries: [fixture.san, fixture.precert] }), {
      headers: { "content-type": "application/json" },
    });
  }
  return new Response("not found", { status: 404 });
}


async function resetSource() {
  await database.exec("DELETE FROM ingest_jobs; DELETE FROM ct_sources;");
  await database.prepare(
    `INSERT INTO ct_sources(source_id, log_url, next_index, enabled, updated_at)
     VALUES (?, ?, 0, 1, ?)`,
  ).bind("test-log", "https://ct.example/log", new Date(0).toISOString()).run();
}


test("scheduler queues one deterministic bounded range", async () => {
  await resetSource();
  const messages = [];
  const queued = await scheduleDirectCt({
    CONTROL: database,
    CT_ALLOWED_HOSTS: "ct.example",
    CT_FETCHER: { fetch: ctFetcher },
    CT_RANGE_SIZE: "2",
    CT_SOURCE_LIMIT: "5",
    INGEST_QUEUE: { send: async (message) => messages.push(message) },
  });
  assert.equal(queued, 1);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].schema_version, "subfinder.direct-ct-job.v1");
  const job = await database.prepare(
    "SELECT start_index, end_index, state FROM ingest_jobs",
  ).first();
  assert.deepEqual(job, { start_index: 0, end_index: 1, state: "queued" });

  assert.equal(await scheduleDirectCt({
    CONTROL: database,
    CT_ALLOWED_HOSTS: "ct.example",
    CT_FETCHER: { fetch: ctFetcher },
    CT_RANGE_SIZE: "2",
    CT_SOURCE_LIMIT: "5",
    INGEST_QUEUE: { send: async (message) => messages.push(message) },
  }), 0);
  assert.equal(messages.length, 1);
});


test("scheduler removes an undispatched job when Queue rejects it", async () => {
  await resetSource();
  await assert.rejects(
    scheduleDirectCt({
      CONTROL: database,
      CT_ALLOWED_HOSTS: "ct.example",
      CT_FETCHER: { fetch: ctFetcher },
      CT_RANGE_SIZE: "2",
      CT_SOURCE_LIMIT: "5",
      INGEST_QUEUE: { send: async () => { throw new Error("queue unavailable"); } },
    }),
    /queue unavailable/,
  );
  assert.equal(
    (await database.prepare("SELECT count(*) AS count FROM ingest_jobs").first()).count,
    0,
  );
});


test("queue job writes an immutable delta then atomically advances control state", async () => {
  await resetSource();
  await scheduleDirectCt({
    CONTROL: database,
    CT_ALLOWED_HOSTS: "ct.example",
    CT_FETCHER: { fetch: ctFetcher },
    CT_RANGE_SIZE: "2",
    CT_SOURCE_LIMIT: "5",
    INGEST_QUEUE: { send: async () => {} },
  });
  const queued = await database.prepare(
    "SELECT job_id FROM ingest_jobs WHERE state = 'queued'",
  ).first();
  const deltaMessages = [];
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    COMPACTION_QUEUE: { send: async (message) => deltaMessages.push(message) },
    CT_ALLOWED_HOSTS: "ct.example",
    CT_FETCHER: { fetch: ctFetcher },
  };
  const first = await processDirectCtJob(env, {
    schema_version: "subfinder.direct-ct-job.v1",
    job_id: queued.job_id,
  });
  assert.equal(first.state, "complete");
  assert.equal(first.duplicate, false);
  assert.deepEqual(deltaMessages, [{
    schema_version: "subfinder.delta-ready.v1",
    delta_id: queued.job_id,
    source_kind: "direct-ct",
    object_key: first.objectKey,
  }]);
  const stored = await bucket.get(first.objectKey);
  assert.ok(stored);
  const document = JSON.parse(gunzipSync(Buffer.from(await stored.arrayBuffer())));
  assert.equal(document.schema_version, "subfinder.ingest-delta.v1");
  assert.deepEqual(document.range, { start: 0, end: 1 });
  assert.equal(document.entry_count, 2);
  assert.equal(document.created_at, new Date(document.created_at).toISOString());
  assert.equal("started_at" in document, false);
  assert.equal("finished_at" in document, false);
  assert.deepEqual(
    document.records.map((record) => record.hostname),
    ["precert.example.com", "wild.example.com", "www.example.com"],
  );
  const job = await database.prepare(
    `SELECT state, entry_count, hostname_count, object_key
     FROM ingest_jobs WHERE job_id = ?`,
  ).bind(queued.job_id).first();
  assert.deepEqual(job, {
    state: "complete",
    entry_count: 2,
    hostname_count: 3,
    object_key: first.objectKey,
  });
  assert.equal(
    (await database.prepare(
      "SELECT next_index FROM ct_sources WHERE source_id = 'test-log'",
    ).first()).next_index,
    2,
  );

  const duplicate = await processDirectCtJob(env, {
    schema_version: "subfinder.direct-ct-job.v1",
    job_id: queued.job_id,
  });
  assert.deepEqual(duplicate, { state: "complete", duplicate: true });
  assert.equal(deltaMessages.length, 2);
  assert.deepEqual(deltaMessages[1], deltaMessages[0]);
});


test("a processing lease prevents concurrent delivery of the same range", async () => {
  await resetSource();
  await scheduleDirectCt({
    CONTROL: database,
    CT_ALLOWED_HOSTS: "ct.example",
    CT_FETCHER: { fetch: ctFetcher },
    CT_RANGE_SIZE: "2",
    CT_SOURCE_LIMIT: "5",
    INGEST_QUEUE: { send: async () => {} },
  });
  const queued = await database.prepare(
    "SELECT job_id FROM ingest_jobs WHERE state = 'queued'",
  ).first();
  let releaseEntries;
  let entriesRequested;
  const entriesGate = new Promise((resolveGate) => { releaseEntries = resolveGate; });
  const requestObserved = new Promise((resolveObserved) => { entriesRequested = resolveObserved; });
  const blockingFetcher = async (request) => {
    const url = new URL(request.url || request);
    if (url.pathname.endsWith("/ct/v1/get-entries")) {
      entriesRequested();
      await entriesGate;
    }
    return ctFetcher(request);
  };
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    COMPACTION_QUEUE: { send: async () => {} },
    CT_ALLOWED_HOSTS: "ct.example",
    CT_FETCHER: { fetch: blockingFetcher },
  };
  const message = {
    schema_version: "subfinder.direct-ct-job.v1",
    job_id: queued.job_id,
  };
  const first = processDirectCtJob(env, message);
  await requestObserved;
  await assert.rejects(processDirectCtJob(env, message), /active processing lease/);
  releaseEntries();
  assert.equal((await first).state, "complete");
});
