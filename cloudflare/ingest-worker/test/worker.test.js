import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { after, before, test } from "node:test";
import { gunzipSync } from "node:zlib";

import { buildSync } from "esbuild";
import { Miniflare } from "miniflare";

import ingestWorker, {
  processDirectCtJob,
  scheduleDirectCt,
} from "../src/index.js";
import { govRecords, refreshPublicSources, rootTlds } from "../src/public-sources.js";
import { discoverCtLogs, usableLogUrls } from "../src/log-discovery.js";
import { parseDataTile, staticRange, staticTreeSize } from "../src/static-ct.js";


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
  for (const file of [
    "0001_ingestion.sql", "0002_public_sources.sql", "0003_ct_log_discovery.sql",
    "0004_ct_log_memberships.sql", "0005_static_ct.sql",
  ]) {
    const migration = readFileSync(resolve(workerRoot, "migrations", file), "utf8");
    for (const statement of migration.split(";").map((value) => value.trim()).filter(Boolean)) {
      await database.prepare(statement).run();
    }
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


test("scheduled invocation reports an empty eligible CT source set", async () => {
  await resetSource();
  await database.prepare("UPDATE ct_sources SET enabled = 0").run();
  const output = [];
  const originalLog = console.log;
  console.log = (value) => output.push(JSON.parse(value));
  try {
    await ingestWorker.scheduled({}, {
      CONTROL: database,
      CT_ALLOWED_HOSTS: "ct.example",
      INGEST_QUEUE: { send: async () => { throw new Error("unexpected job"); } },
    });
  } finally {
    console.log = originalLog;
  }
  assert.deepEqual(output, [{
    event: "ingest-scheduled",
    ct_jobs: 0,
    discovered_logs: 0,
    public_sources: [],
    errors: [],
  }]);
});


function staticLeaf() {
  const leaf = Buffer.from(fixture.san.leaf_input, "base64");
  const certificate = leaf.subarray(15, leaf.length - 2);
  return Buffer.concat([
    leaf.subarray(2, 10), Buffer.from([0, 0]),
    leaf.subarray(12, 15), certificate, Buffer.alloc(2), Buffer.alloc(2),
  ]);
}


function staticFetcher(request) {
  const url = new URL(request);
  if (url.pathname.endsWith("/checkpoint")) {
    return new Response("test.example\n2\nroot-hash\n");
  }
  if (url.pathname.endsWith("/tile/data/000.p/2")) {
    return new Response(Buffer.concat([staticLeaf(), staticLeaf()]));
  }
  return new Response("not found", { status: 404 });
}


test("Static CT parses bounded tiles and schedules its own cursor", async () => {
  await resetSource();
  await database.prepare(
    `INSERT INTO ct_sources(source_id, log_url, next_index, enabled, updated_at,
     protocol, cursor_initialized)
     VALUES ('static-test', 'https://static.example/2026h2', 0, 1, ?, 'static', 0)`,
  ).bind(new Date(0).toISOString()).run();
  assert.equal(parseDataTile(staticLeaf()).length, 1);
  assert.throws(() => parseDataTile(staticLeaf().subarray(0, 20)), /truncated/);
  const messages = [];
  const env = {
    CONTROL: database, CATALOG: bucket,
    CT_ALLOWED_HOSTS: "ct.example",
    STATIC_CT_ALLOWED_HOSTS: "static.example",
    STATIC_CT_SOURCE_LIMIT: "1",
    CT_SOURCE_LIMIT: "1",
    CT_RANGE_SIZE: "2",
    CT_FETCHER: { fetch: (request) => (
      new URL(request).hostname === "static.example"
        ? staticFetcher(request) : new Response("not found", { status: 404 })
    ) },
    INGEST_QUEUE: { send: async (message) => messages.push(message) },
    COMPACTION_QUEUE: { send: async (message) => messages.push(message) },
  };
  assert.equal(await staticTreeSize(env, "https://static.example/2026h2", ["static.example"]), 2);
  const range = await staticRange(
    env, "https://static.example/2026h2", ["static.example"], 0, 1, 2,
  );
  assert.equal(range.entryCount, 2);
  assert.deepEqual(range.records.map((record) => record.hostname), [
    "wild.example.com", "www.example.com",
  ]);
  assert.equal(await scheduleDirectCt(env), 1);
  const job = await database.prepare(
    "SELECT job_id, start_index, end_index FROM ingest_jobs WHERE source_id = 'static-test'",
  ).first();
  assert.deepEqual([job.start_index, job.end_index], [0, 1]);
  const result = await processDirectCtJob(env, messages[0]);
  assert.match(result.objectKey, /^ingest\/static-ct\//);
  assert.equal(messages[1].source_kind, "static-ct");
  assert.equal(await scheduleDirectCt(env), 0);
  await assert.rejects(
    staticRange(env, "https://static.example.evil/2026h2", ["static.example"], 0, 1, 2),
    /not allowed/,
  );
});


function publicFixtures() {
  const root = Array.from({ length: 1001 }, (_, index) => (
    `t${index}. 86400 IN NS ns.example.\n`
  )).join("");
  const gov = "Domain name,Organization name\n" + Array.from(
    { length: 1001 }, (_, index) => `agency${index}.gov,Agency ${index}\n`,
  ).join("");
  return { root, gov };
}


async function resetPublicSources() {
  await database.prepare(
    `UPDATE public_source_state SET digest = NULL, etag = NULL, object_key = NULL,
       checked_at = NULL, next_run_at = '1970-01-01T00:00:00.000Z',
       lease_until = NULL, error = NULL`,
  ).run();
}


test("CT list discovery adds only active exact-host RFC logs", async () => {
  await database.exec("DELETE FROM ingest_jobs; DELETE FROM ct_sources;");
  await database.prepare("UPDATE ct_log_lists SET etag = NULL, checked_at = NULL").run();
  let payload = { operators: [{ logs: [
    { url: "https://ct.example/new/", state: { usable: {} } },
    { url: "https://ct.example/old/", state: { retired: {} } },
    { url: "https://ct.example.evil/new/", state: { usable: {} } },
  ] }] };
  assert.deepEqual(usableLogUrls(payload, ["ct.example"]), ["https://ct.example/new"]);
  const env = {
    CONTROL: database,
    CT_LOG_DISCOVERY_ENABLED: "1",
    CT_ALLOWED_HOSTS: "ct.example",
    CT_LIST_FETCHER: { fetch: async () => Response.json(payload) },
  };
  const now = new Date("2026-09-29T00:00:00.000Z");
  assert.equal(await discoverCtLogs(env, now), 1);
  assert.equal(await discoverCtLogs(env, now), 0);
  const source = await database.prepare(
    "SELECT log_url, discovered, cursor_initialized FROM ct_sources",
  ).first();
  assert.deepEqual(source, {
    log_url: "https://ct.example/new", discovered: 1, cursor_initialized: 0,
  });
  const messages = [];
  assert.equal(await scheduleDirectCt({
    CONTROL: database,
    CT_ALLOWED_HOSTS: "ct.example",
    CT_DISCOVERED_SOURCE_LIMIT: "1",
    CT_INITIAL_BACKFILL: "2",
    CT_RANGE_SIZE: "2",
    CT_FETCHER: { fetch: ctFetcher },
    INGEST_QUEUE: { send: async (message) => messages.push(message) },
  }), 1);
  assert.equal(messages.length, 1);
  const job = await database.prepare(
    "SELECT start_index, end_index FROM ingest_jobs",
  ).first();
  assert.deepEqual(job, { start_index: 1, end_index: 2 });
  await database.prepare(
    `INSERT INTO ct_sources(source_id, log_url, next_index, enabled, updated_at)
     VALUES ('reviewed-log', 'https://ct.example/reviewed', 0, 1, ?)`,
  ).bind(now.toISOString()).run();
  payload = { operators: [{ logs: [
    { url: "https://ct.example/other/", state: { usable: {} } },
    { url: "https://ct.example/new/", state: { retired: {} } },
  ] }] };
  assert.equal(await discoverCtLogs(env, new Date(now.valueOf() + 86400000)), 1);
  const statuses = await database.prepare(
    "SELECT log_url, enabled FROM ct_sources ORDER BY log_url",
  ).all();
  assert.deepEqual(statuses.results, [
    { log_url: "https://ct.example/new", enabled: 0 },
    { log_url: "https://ct.example/other", enabled: 1 },
    { log_url: "https://ct.example/reviewed", enabled: 1 },
  ]);
});


test("discovered CT work has its own cap and a failed log cannot block manual work", async () => {
  await resetSource();
  await database.prepare(
    `INSERT INTO ct_sources(source_id, log_url, next_index, enabled, updated_at,
     discovered, cursor_initialized)
     VALUES ('discovered-test', 'https://ct.example/new', 0, 1, ?, 1, 0)`,
  ).bind(new Date(0).toISOString()).run();
  const messages = [];
  const env = {
    CONTROL: database,
    CT_ALLOWED_HOSTS: "ct.example",
    CT_SOURCE_LIMIT: "1",
    CT_DISCOVERED_SOURCE_LIMIT: "1",
    CT_RANGE_SIZE: "2",
    CT_INITIAL_BACKFILL: "2",
    CT_FETCHER: { fetch: ctFetcher },
    INGEST_QUEUE: { send: async (message) => messages.push(message) },
  };
  assert.equal(await scheduleDirectCt(env), 2);
  assert.equal(messages.length, 2);
  const jobs = await database.prepare(
    "SELECT source_id, start_index FROM ingest_jobs ORDER BY source_id",
  ).all();
  assert.deepEqual(jobs.results, [
    { source_id: "discovered-test", start_index: 1 },
    { source_id: "test-log", start_index: 0 },
  ]);
  await database.exec("DELETE FROM ingest_jobs");
  await database.prepare(
    "UPDATE ct_sources SET log_url = 'https://ct.example/bad' WHERE source_id = 'discovered-test'",
  ).run();
  const failingFetcher = async (request) => (
    new URL(request).pathname.startsWith("/bad/")
      ? new Response("not found", { status: 404 })
      : ctFetcher(request)
  );
  assert.equal(await scheduleDirectCt({
    ...env, CT_FETCHER: { fetch: failingFetcher },
  }), 1);
  const failed = await database.prepare(
    "SELECT retry_at, last_error FROM ct_sources WHERE source_id = 'discovered-test'",
  ).first();
  assert.ok(failed.retry_at);
  assert.match(failed.last_error, /HTTP 404/);
});


test("public source parsers retain only TLDs and CISA domain names", () => {
  const { root, gov } = publicFixtures();
  assert.equal(rootTlds(root).length, 1001);
  assert.deepEqual(govRecords(gov)[0], {
    apex: "agency0.gov", hostname: "agency0.gov", first_seen: null,
  });
  assert.equal(govRecords(gov).length, 1001);
  assert.throws(() => govRecords("other,header\nexample.gov,x\n"), /header/);
  assert.throws(() => rootTlds("com. 86400 IN NS ns.example.\n"), /too few/);
});


test("public refresh writes immutable official snapshots and skips unchanged days", async () => {
  await resetPublicSources();
  const { root, gov } = publicFixtures();
  const messages = [];
  let calls = 0;
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    PUBLIC_SOURCES_ENABLED: "1",
    PUBLIC_FETCHER: { fetch: async (request) => {
      calls += 1;
      const url = new URL(request);
      return new Response(url.hostname === "www.internic.net" ? root : gov, {
        headers: { etag: '"fixture"' },
      });
    } },
    COMPACTION_QUEUE: { send: async (message) => messages.push(message) },
  };
  const now = new Date("2026-09-29T00:00:00.000Z");
  assert.deepEqual(await refreshPublicSources(env, now), ["updated", "updated"]);
  assert.equal(messages.length, 1);
  assert.equal(messages[0].source_kind, "public-bulk");
  const publicDelta = await bucket.get(messages[0].object_key);
  assert.ok(publicDelta);
  const document = JSON.parse(gunzipSync(Buffer.from(await publicDelta.arrayBuffer())));
  assert.equal(document.source, "gov:cisagov");
  assert.equal(document.records.length, 1001);
  const inventory = await database.prepare(
    "SELECT object_key FROM public_source_state WHERE source_id = 'iana-root'",
  ).first();
  assert.match(inventory.object_key, /^metadata\/iana-root\/[a-f0-9]{64}\.json\.gz$/);
  assert.deepEqual(await refreshPublicSources(env, now), ["not-due", "not-due"]);
  assert.equal(calls, 2);
  assert.deepEqual(await refreshPublicSources(env, new Date(now.valueOf() + 86400000)), [
    "unchanged", "unchanged",
  ]);
  assert.equal(messages.length, 2);
  assert.deepEqual(messages[1], messages[0]);
});


test("a Queue failure retries the same immutable CISA delta", async () => {
  await resetPublicSources();
  const { root, gov } = publicFixtures();
  let failQueue = true;
  const messages = [];
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    PUBLIC_SOURCES_ENABLED: "1",
    PUBLIC_FETCHER: { fetch: async (request) => new Response(
      new URL(request).hostname === "www.internic.net" ? root : gov,
    ) },
    COMPACTION_QUEUE: { send: async (message) => {
      if (failQueue) throw new Error("Queue unavailable");
      messages.push(message);
    } },
  };
  const now = new Date("2026-10-02T00:00:00.000Z");
  await assert.rejects(refreshPublicSources(env, now), /public source refresh failed/);
  const failed = await database.prepare(
    "SELECT digest, error FROM public_source_state WHERE source_id = 'cisa-gov'",
  ).first();
  assert.equal(failed.digest, null);
  assert.match(failed.error, /Queue unavailable/);
  failQueue = false;
  assert.deepEqual(await refreshPublicSources(env, new Date(now.valueOf() + 3600000)), [
    "not-due", "updated",
  ]);
  assert.equal(messages.length, 1);
  assert.ok(await bucket.head(messages[0].object_key));
});


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
