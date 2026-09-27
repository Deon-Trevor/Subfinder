import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { gunzipSync, gzipSync } from "node:zlib";

import { Miniflare } from "miniflare";

import {
  appendCzdsChunk,
  beginCzdsArtifact,
  claimCzdsJob,
  completeCzdsArtifact,
  publishCzdsJob,
  scheduleCzds,
  stageCzdsJob,
  validatedDownloadLink,
  zoneRecord,
} from "../src/core.js";


const workerRoot = resolve(import.meta.dirname, "..");
let miniflare;
let database;
let bucket;


before(async () => {
  miniflare = new Miniflare({
    workers: [{
      config: {
        name: "subfinder-czds-test",
        compatibilityDate: "2026-09-27",
        manifest: {
          mainModule: "index.js",
          modulesRoot: resolve(workerRoot, "src"),
          modules: {
            "index.js": {
              type: "esm",
              contents: "export default { fetch() { return new Response('ok'); } }",
            },
          },
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
    resolve(workerRoot, "migrations/0001_czds_ingestion.sql"),
    "utf8",
  );
  for (const statement of migration.split(";").map((value) => value.trim()).filter(Boolean)) {
    await database.prepare(statement).run();
  }
});


beforeEach(async () => {
  await database.exec("DELETE FROM czds_job_deltas; DELETE FROM czds_jobs; DELETE FROM czds_zones;");
  const objects = await bucket.list();
  if (objects.objects.length > 0) await bucket.delete(objects.objects.map((item) => item.key));
});


after(async () => {
  await miniflare?.dispose();
});


function fakeFetcher(zoneBytes) {
  return async (request) => {
    const url = new URL(request.url || request);
    if (url.hostname === "account-api.icann.org") {
      return Response.json({ accessToken: "access-token" });
    }
    if (url.hostname === "czds-api.icann.org" && url.pathname.endsWith("/links")) {
      return Response.json([
        "https://czds-download-api.icann.org/czds/downloads/com.zone",
      ]);
    }
    if (url.hostname === "czds-download-api.icann.org") {
      return new Response(zoneBytes, {
        headers: {
          "content-length": String(zoneBytes.length),
          "last-modified": "Sun, 27 Sep 2026 00:00:00 GMT",
        },
      });
    }
    return new Response("not found", { status: 404 });
  };
}


test("download link validation is exact-host and path scoped", () => {
  assert.deepEqual(
    validatedDownloadLink(
      "https://czds-download-api.icann.org/czds/downloads/example.zone",
    ),
    {
      url: "https://czds-download-api.icann.org/czds/downloads/example.zone",
      zone: "example",
    },
  );
  for (const link of [
    "http://czds-download-api.icann.org/czds/downloads/example.zone",
    "https://czds-download-api.icann.org.evil/czds/downloads/example.zone",
    "https://czds-download-api.icann.org/private/example.zone",
    "https://127.0.0.1/czds/downloads/example.zone",
  ]) {
    assert.throws(() => validatedDownloadLink(link), /not allowed|invalid zone path/);
  }
});


test("zone parser preserves owner continuation and ignores non-NS records", () => {
  const first = zoneRecord("example 3600 IN NS ns1.example.", "com", null);
  assert.deepEqual(first.record, {
    apex: "example.com",
    hostname: "example.com",
    first_seen: null,
  });
  const continued = zoneRecord("  3600 IN NS ns2.example.", "com", first.previousOwner);
  assert.equal(continued.record.hostname, "example.com");
  assert.equal(zoneRecord("www 3600 IN A 192.0.2.1", "com", null).record, null);
});


test("scheduled Workflow stages chunked deltas and publishes only after the full zone", async () => {
  const zone = [
    "$ORIGIN com.",
    "example 3600 IN NS ns1.example.",
    "example2 3600 IN NS ns1.example.",
    "example3 3600 IN NS ns1.example.",
    "www 3600 IN A 192.0.2.1",
    "",
  ].join("\n");
  const zoneBytes = gzipSync(zone);
  const workflows = [];
  const deltas = [];
  const now = new Date("2026-09-27T04:00:00.000Z");
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    CZDS_USERNAME: "user",
    CZDS_PASSWORD: "password",
    CZDS_DELTA_RECORDS: "2",
    CZDS_FETCHER: { fetch: fakeFetcher(zoneBytes) },
    CZDS_WORKFLOW: {
      create: async (input) => workflows.push(input),
    },
    COMPACTION_QUEUE: {
      sendBatch: async (batch) => deltas.push(...batch.map((item) => item.body)),
    },
  };
  assert.equal(await scheduleCzds(env, now), 1);
  assert.equal(workflows.length, 1);
  const jobId = workflows[0].params.job_id;
  assert.equal((await claimCzdsJob(env, jobId)).state, "running");
  const staged = await stageCzdsJob(env, jobId);
  assert.deepEqual(staged, { state: "staged", deltaCount: 2, hostnameCount: 3 });
  assert.equal(deltas.length, 0);

  const published = await publishCzdsJob(env, jobId);
  assert.deepEqual(published, { state: "complete", duplicate: false, deltas: 2 });
  assert.equal(deltas.length, 2);
  assert.ok(deltas.every((message) => message.source_kind === "czds"));
  const rows = await database.prepare(
    "SELECT object_key FROM czds_job_deltas ORDER BY chunk_index",
  ).all();
  const stored = await bucket.get(rows.results[0].object_key);
  const document = JSON.parse(gunzipSync(Buffer.from(await stored.arrayBuffer())));
  assert.equal(document.schema_version, "subfinder.ingest-delta.v1");
  assert.deepEqual(document.records.map((record) => record.hostname), [
    "example.com",
    "example2.com",
  ]);
  assert.deepEqual(await publishCzdsJob(env, jobId), {
    state: "complete",
    duplicate: true,
  });
  assert.equal(deltas.length, 2);
});


test("scheduling fails closed without both CZDS Worker secrets", async () => {
  await assert.rejects(scheduleCzds({ CONTROL: database }, new Date()), /secret is not configured/);
});


test("staging scheduler selects only the explicitly approved zone", async () => {
  const workflows = [];
  const env = {
    CONTROL: database,
    CZDS_USERNAME: "user",
    CZDS_PASSWORD: "password",
    CZDS_ONLY_ZONE: "com",
    CZDS_FETCHER: { fetch: fakeFetcher(gzipSync("example 3600 IN NS ns.example.\n")) },
    CZDS_WORKFLOW: { create: async (input) => workflows.push(input) },
  };
  assert.equal(await scheduleCzds(env, new Date("2026-09-27T05:00:00.000Z")), 1);
  assert.equal(workflows.length, 1);
  assert.equal((await database.prepare("SELECT zone FROM czds_jobs").first()).zone, "com");
  await assert.rejects(
    scheduleCzds({ ...env, CZDS_ONLY_ZONE: "net" }),
    /not approved/,
  );
});


test("completed zone publishes large delta sets in bounded queue batches", async () => {
  const workflows = [];
  const batchSizes = [];
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    CZDS_USERNAME: "user",
    CZDS_PASSWORD: "password",
    CZDS_FETCHER: { fetch: fakeFetcher(gzipSync("example 3600 IN NS ns.example.\n")) },
    CZDS_WORKFLOW: { create: async (input) => workflows.push(input) },
    COMPACTION_QUEUE: { sendBatch: async (batch) => batchSizes.push(batch.length) },
  };
  assert.equal(await scheduleCzds(env, new Date("2026-09-27T05:00:00.000Z")), 1);
  const jobId = workflows[0].params.job_id;
  await database.prepare("UPDATE czds_jobs SET state = 'staged' WHERE job_id = ?")
    .bind(jobId).run();
  await database.batch(Array.from({ length: 105 }, (_, index) => database.prepare(
    `INSERT INTO czds_job_deltas(job_id, chunk_index, delta_id, object_key,
     record_count, created_at) VALUES (?, ?, ?, ?, 1, ?)`,
  ).bind(
    jobId, index, index.toString(16).padStart(64, "0"),
    `ingest/czds/com/${jobId}-${index}.json.gz`, "2026-09-27T05:00:00.000Z",
  )));
  assert.deepEqual(await publishCzdsJob(env, jobId), {
    state: "complete", duplicate: false, deltas: 105,
  });
  assert.deepEqual(batchSizes, [100, 5]);
});


test("container callbacks refuse incomplete, reordered, or changed artifacts", async () => {
  const env = {
    CONTROL: database,
    CATALOG: bucket,
    CZDS_USERNAME: "user",
    CZDS_PASSWORD: "password",
    CZDS_DELTA_RECORDS: "2",
    CZDS_FETCHER: { fetch: fakeFetcher(gzipSync("example 3600 IN NS ns.example.\n")) },
    CZDS_WORKFLOW: { create: async () => {} },
  };
  await scheduleCzds(env, new Date("2026-09-27T05:00:00.000Z"));
  const jobId = (await database.prepare("SELECT job_id FROM czds_jobs").first()).job_id;
  await claimCzdsJob(env, jobId);
  await beginCzdsArtifact(env, jobId, '"artifact"||100');
  const first = [{ apex: "example.com", hostname: "example.com", first_seen: null }];
  await assert.rejects(appendCzdsChunk(env, jobId, 1, first), /in order/);
  await appendCzdsChunk(env, jobId, 0, first);
  await appendCzdsChunk(env, jobId, 0, first);
  assert.equal((await database.prepare(
    "SELECT COUNT(*) AS count FROM czds_job_deltas WHERE job_id = ?",
  ).bind(jobId).first()).count, 1);
  await assert.rejects(appendCzdsChunk(env, jobId, 0, [
    { apex: "other.com", hostname: "other.com", first_seen: null },
  ]), /does not match/);
  await assert.rejects(completeCzdsArtifact(env, jobId, 2, 1), /do not match/);
  await assert.rejects(beginCzdsArtifact(env, jobId, '"different"||100'), /changed/);
  assert.deepEqual(await completeCzdsArtifact(env, jobId, 1, 1), {
    state: "staged", deltaCount: 1, hostnameCount: 1,
  });
});
