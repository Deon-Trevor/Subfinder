import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { gunzipSync } from "node:zlib";

import { buildSync } from "esbuild";
import { Miniflare } from "miniflare";

import {
  mapDelta,
  registerDelta,
  runReduce,
  startGeneration,
  startReduce,
} from "../src/index.js";
import worker from "../src/index.js";
import { activateGeneration, registerSeed, rollbackGeneration } from "../src/publication.js";
import { copyOverflowChunks, storeBundle } from "../src/reducer.js";
import { DOMAIN_POLICY_VERSION, PSL_SHA256 } from "../../index-worker/src/domain-policy.js";


const workerRoot = resolve(import.meta.dirname, "..");
let miniflare;
let database;
let bucket;


if (typeof crypto.DigestStream !== "function") {
  crypto.DigestStream = class extends WritableStream {
    constructor() {
      const hash = createHash("sha256");
      let complete;
      const digest = new Promise((resolveDigest) => { complete = resolveDigest; });
      super({
        write(chunk) { hash.update(chunk); },
        close() { complete(hash.digest().buffer); },
      });
      this.digest = digest;
    }
  };
}


async function gzipJson(value) {
  const stream = new Blob([JSON.stringify(value)])
    .stream()
    .pipeThrough(new CompressionStream("gzip"));
  return await new Response(stream).arrayBuffer();
}


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
        name: "subfinder-compaction",
        compatibilityDate: "2026-09-27",
        manifest: {
          mainModule: "index.js",
          modulesRoot: resolve(workerRoot, "src"),
          modules: { "index.js": { type: "esm", contents: bundle } },
        },
        env: {
          LEDGER: { type: "d1", name: "LEDGER" },
          CATALOG: { type: "r2", name: "CATALOG" },
        },
      },
    }],
  });
  database = await miniflare.getD1Database("LEDGER");
  bucket = await miniflare.getR2Bucket("CATALOG");
  for (const name of ["0001_generation_ledger.sql", "0002_seed_publication.sql"]) {
    const migration = readFileSync(resolve(workerRoot, "migrations", name), "utf8");
    for (const statement of migration.split(";").map((value) => value.trim()).filter(Boolean)) {
      await database.prepare(statement).run();
    }
  }
});


beforeEach(async () => {
  await database.exec(
    "DELETE FROM generation_fragments; DELETE FROM generation_partitions; " +
    "DELETE FROM catalog_deltas; DELETE FROM catalog_generations; " +
    "DELETE FROM catalog_seeds;",
  );
  const objects = await bucket.list();
  if (objects.objects.length > 0) {
    await bucket.delete(objects.objects.map((object) => object.key));
  }
});


after(async () => {
  await miniflare?.dispose();
});


async function putDelta(deltaId, records) {
  const key = `ingest/urlscan/example/${deltaId}.json.gz`;
  await bucket.put(key, await gzipJson({
    schema_version: "subfinder.ingest-delta.v1",
    source: "urlscan",
    source_id: "example.com",
    created_at: "2026-09-27T00:00:00.000Z",
    entry_count: records.length,
    hostname_count: records.length,
    records,
  }));
  return key;
}


test("registers immutable deltas idempotently and rejects identity conflicts", async () => {
  const deltaId = "a".repeat(64);
  const key = await putDelta(deltaId, [{
    apex: "example.com",
    hostname: "www.example.com",
    first_seen: "2026-09-27T00:00:00.000Z",
  }]);
  const env = { LEDGER: database, CATALOG: bucket };
  const message = {
    schema_version: "subfinder.delta-ready.v1",
    delta_id: deltaId,
    source_kind: "urlscan",
    object_key: key,
  };
  assert.deepEqual(await registerDelta(env, message), {
    deltaId,
    state: "registered",
  });
  assert.deepEqual(await registerDelta(env, message), {
    deltaId,
    state: "registered",
  });

  const conflicting = await putDelta("b".repeat(64), [{
    apex: "example.com",
    hostname: "other.example.com",
    first_seen: null,
  }]);
  await assert.rejects(registerDelta(env, {
    ...message,
    object_key: conflicting,
  }), /identity conflicts/);
});


test("registration-only staging refuses generation messages and scheduled work", async () => {
  const delivery = { acked: false, retried: false };
  await worker.scheduled({}, { REGISTRATION_ONLY: "true" });
  await worker.queue({ messages: [{
    body: {
      schema_version: "subfinder.map-job.v1",
      generation_id: "a".repeat(64),
      delta_id: "b".repeat(64),
    },
    ack: () => { delivery.acked = true; },
    retry: () => { delivery.retried = true; },
  }] }, { REGISTRATION_ONLY: "true", LEDGER: database });
  assert.deepEqual(delivery, { acked: false, retried: true });
  const generation = await database.prepare("SELECT count(*) AS n FROM catalog_generations").first();
  assert.equal(generation.n, 0);
});


test("starts one generation and maps each delta into deterministic partition fragments", async () => {
  const deltaIds = ["1".repeat(64), "2".repeat(64)];
  const env = {
    LEDGER: database,
    CATALOG: bucket,
    PARTITION_NIBBLES: "2",
    COMPACTION_QUEUE: {
      send: async (message) => messages.push(message),
    },
  };
  const messages = [];
  for (const [index, deltaId] of deltaIds.entries()) {
    const key = await putDelta(deltaId, [{
      apex: "example.com",
      hostname: `${index}.example.com`,
      first_seen: null,
    }]);
    await registerDelta(env, {
      schema_version: "subfinder.delta-ready.v1",
      delta_id: deltaId,
      source_kind: "urlscan",
      object_key: key,
    });
  }

  const started = await startGeneration(env);
  assert.equal(started.resumed, false);
  assert.equal(started.waitingForReduce, false);
  assert.equal(started.queued, 2);
  assert.equal(messages.length, 2);
  assert.ok(messages.every((message) => message.schema_version === "subfinder.map-job.v1"));

  const resumed = await startGeneration(env);
  assert.equal(resumed.generationId, started.generationId);
  assert.equal(resumed.resumed, true);
  assert.equal(resumed.waitingForReduce, false);
  assert.equal(resumed.queued, 2);

  for (const message of messages.slice(0, 2)) {
    const result = await mapDelta(env, message);
    assert.equal(result.state, "mapped");
    assert.equal(result.duplicate, false);
  }
  const generation = await database.prepare(
    `SELECT state, delta_count, partition_count FROM catalog_generations
     WHERE generation_id = ?`,
  ).bind(started.generationId).first();
  assert.equal(generation.state, "mapped");
  assert.equal(generation.delta_count, 2);
  assert.equal(generation.partition_count, 1);
  const partition = await database.prepare(
    `SELECT fragment_count, record_count FROM generation_partitions
     WHERE generation_id = ?`,
  ).bind(started.generationId).first();
  assert.equal(partition.fragment_count, 2);
  assert.equal(partition.record_count, 2);

  const fragments = await database.prepare(
    "SELECT object_key, record_count FROM generation_fragments ORDER BY delta_id",
  ).all();
  assert.equal(fragments.results.length, 2);
  assert.deepEqual(fragments.results.map((row) => row.record_count), [1, 1]);
  const stored = await bucket.get(fragments.results[0].object_key);
  const document = JSON.parse(gunzipSync(Buffer.from(await stored.arrayBuffer())));
  assert.equal(document.schema_version, "subfinder.map-fragment.v1");
  assert.equal(document.generation_id, started.generationId);

  assert.deepEqual(await mapDelta(env, messages[0]), {
    state: "mapped",
    duplicate: true,
  });
  const waiting = await startGeneration(env);
  assert.deepEqual(waiting, {
    generationId: started.generationId,
    queued: 0,
    resumed: false,
    waitingForReduce: true,
  });
});


test("map refuses to overwrite an existing fragment with different bytes", async () => {
  const deltaId = "3".repeat(64);
  const key = await putDelta(deltaId, [{
    apex: "example.com",
    hostname: "www.example.com",
    first_seen: null,
  }]);
  const env = {
    LEDGER: database,
    CATALOG: bucket,
    COMPACTION_QUEUE: { send: async () => {} },
  };
  await registerDelta(env, {
    schema_version: "subfinder.delta-ready.v1",
    delta_id: deltaId,
    source_kind: "urlscan",
    object_key: key,
  });
  const { generationId } = await startGeneration(env);
  const prefix = createHash("sha256").update("example.com").digest("hex").slice(0, 2);
  const fragmentKey = `compact/staging/${generationId}/${prefix}/${deltaId}.json.gz`;
  await bucket.put(fragmentKey, "occupied", { customMetadata: { sha256: "wrong" } });

  await assert.rejects(mapDelta(env, {
    schema_version: "subfinder.map-job.v1",
    generation_id: generationId,
    delta_id: deltaId,
  }), /already contains different bytes/);
  assert.equal(await (await bucket.get(fragmentKey)).text(), "occupied");
  assert.equal((await database.prepare(
    "SELECT state FROM catalog_deltas WHERE delta_id = ?",
  ).bind(deltaId).first()).state, "assigned");
});


test("fails closed on malformed domain ownership", async () => {
  const deltaId = "c".repeat(64);
  const key = await putDelta(deltaId, [{
    apex: "example.net",
    hostname: "www.example.com",
    first_seen: null,
  }]);
  await assert.rejects(registerDelta(
    { LEDGER: database, CATALOG: bucket },
    {
      schema_version: "subfinder.delta-ready.v1",
      delta_id: deltaId,
      source_kind: "urlscan",
      object_key: key,
    },
  ), /apex does not match/);
});


test("generation activation routes reject callers without the Worker secret", async () => {
  for (const route of ["register-seed", "activate", "rollback"]) {
    const response = await miniflare.dispatchFetch(`http://worker.test/admin/${route}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ generation_id: "a".repeat(64) }),
    });
    assert.equal(response.status, 403);
  }
});


test("a verified seed candidate activates once and cannot roll back to absence", async () => {
  const id = "seed-20260927";
  const root = {
    format: "subfinder.r2-index.v2",
    generation: id,
    domain_policy_version: DOMAIN_POLICY_VERSION,
    psl_sha256: PSL_SHA256,
    partition_nibbles: 2,
    target_block_bytes: 262144,
    partitions: {},
    source_names: [],
    ct_source_names: [],
    stats: { apex_count: 0, hostname_count: 0 },
  };
  await bucket.put(`catalog/candidates/${id}.json`, JSON.stringify(root));
  const env = { LEDGER: database, CATALOG: bucket };
  assert.deepEqual(await registerSeed(env, id), { generationId: id, state: "published" });
  assert.deepEqual(await activateGeneration(env, id), { generationId: id, duplicate: false });
  assert.deepEqual(await activateGeneration(env, id), { generationId: id, duplicate: true });
  assert.equal((await (await bucket.get("catalog/root.json")).json()).generation, id);
  await assert.rejects(rollbackGeneration(env, id), /no prior root/);
});


test("bundle builder uses multipart storage above the bounded part size", async () => {
  const chunk = new Uint8Array(1024 * 1024).fill(0x5a);
  let sent = 0;
  const stream = new ReadableStream({
    pull(controller) {
      if (sent === 9) controller.close();
      else {
        controller.enqueue(chunk);
        sent += 1;
      }
    },
  });
  const stored = await storeBundle(bucket, "test/multipart.bundle", stream);
  assert.equal(stored.size, 9 * 1024 * 1024);
  const tail = await bucket.get("test/multipart.bundle", {
    range: { offset: 8 * 1024 * 1024, length: 16 },
  });
  assert.deepEqual(new Uint8Array(await tail.arrayBuffer()), new Uint8Array(16).fill(0x5a));
});


test("unchanged overflow members are copied in bounded ranges with per-member checksums", async () => {
  const members = Array.from({ length: 12 }, (_, index) =>
    Buffer.from(`compressed-member-${index}-`.repeat(100)));
  const chunks = [];
  let offset = 0;
  for (const member of members) {
    chunks.push({ offset, length: member.length,
      sha256: createHash("sha256").update(member).digest("hex") });
    offset += member.length;
  }
  const original = Buffer.concat(members);
  await bucket.put("test/base-overflow.bundle", original);
  let reads = 0;
  const source = { get: (...args) => {
    reads += 1;
    return bucket.get(...args);
  } };
  const copied = [];
  for await (const bytes of copyOverflowChunks(source, "test/base-overflow.bundle", chunks)) {
    copied.push(Buffer.from(bytes));
  }
  assert.deepEqual(Buffer.concat(copied), original);
  assert.equal(reads, 1);
  await assert.rejects(async () => {
    for await (const _ of copyOverflowChunks(source, "test/base-overflow.bundle", [
      ...chunks.slice(0, 5), { ...chunks[5], sha256: "0".repeat(64) }, ...chunks.slice(6),
    ])) { /* consume */ }
  }, /checksum mismatch/);
});


test("reduces immutable bundles, publishes a candidate, activates and rolls back", async () => {
  const messages = [];
  const env = {
    LEDGER: database,
    CATALOG: bucket,
    PARTITION_NIBBLES: "2",
    COMPACTION_QUEUE: { send: async (message) => messages.push(message) },
  };
  async function build(deltaId, apex, hostname, expectedCount) {
    const key = await putDelta(deltaId, [{
      apex, hostname, first_seen: "2026-09-27T00:00:00.000Z",
    }]);
    await registerDelta(env, {
      schema_version: "subfinder.delta-ready.v1",
      delta_id: deltaId,
      source_kind: "urlscan",
      object_key: key,
    });
    const started = await startGeneration(env);
    for (const message of messages.splice(0)) await mapDelta(env, message);
    const reducing = await startReduce(env);
    assert.equal(reducing.queued, 1);
    for (const message of messages.splice(0)) await runReduce(env, message);
    const row = await database.prepare(
      "SELECT state, candidate_root_key FROM catalog_generations WHERE generation_id = ?",
    ).bind(started.generationId).first();
    assert.equal(row.state, "published");
    const candidate = await (await bucket.get(row.candidate_root_key)).json();
    assert.equal(candidate.stats.hostname_count, expectedCount);
    await database.prepare(
      "UPDATE catalog_generations SET state = 'reducing' WHERE generation_id = ?",
    ).bind(started.generationId).run();
    assert.equal((await startReduce(env)).queued, 0);
    assert.equal((await database.prepare(
      "SELECT state FROM catalog_generations WHERE generation_id = ?",
    ).bind(started.generationId).first()).state, "published");
    return started.generationId;
  }
  const first = await build("1".repeat(64), "example.com", "one.example.com", 1);
  assert.deepEqual(await activateGeneration(env, first), { generationId: first, duplicate: false });
  assert.deepEqual(await activateGeneration(env, first), { generationId: first, duplicate: true });
  const second = await build("2".repeat(64), "example.com", "two.example.com", 2);
  assert.deepEqual(await activateGeneration(env, second), { generationId: second, duplicate: false });
  const active = await (await bucket.get("catalog/root.json")).json();
  assert.equal(active.generation, second);
  const partition = Object.values(active.partitions)[0];
  const index = JSON.parse(gunzipSync(Buffer.from(await (await bucket.get(partition.index)).arrayBuffer())));
  const block = index.blocks[0];
  const member = await bucket.get(partition.bundle, { range: {
    offset: block.offset, length: block.length,
  } });
  const document = JSON.parse(gunzipSync(Buffer.from(await member.arrayBuffer())).toString().trim());
  assert.deepEqual(document.r.map((record) => record.h), ["one.example.com", "two.example.com"]);
  const third = await build("3".repeat(64), "other.net", "three.other.net", 3);
  const candidateRow = await database.prepare(
    "SELECT candidate_root_key FROM catalog_generations WHERE generation_id = ?",
  ).bind(third).first();
  const thirdCandidate = await (await bucket.get(candidateRow.candidate_root_key)).json();
  const originalPrefix = createHash("sha256").update("example.com").digest("hex").slice(0, 2);
  assert.equal(thirdCandidate.partitions[originalPrefix].origin_generation, second);
  await activateGeneration(env, third);
  assert.deepEqual(await rollbackGeneration(env, third), {
    generationId: third, restoredGeneration: second,
  });
  assert.deepEqual(await rollbackGeneration(env, second), {
    generationId: second, restoredGeneration: first,
  });
  assert.equal((await (await bucket.get("catalog/root.json")).json()).generation, first);
  assert.equal((await database.prepare(
    "SELECT state FROM catalog_deltas WHERE delta_id = ?",
  ).bind("2".repeat(64)).first()).state, "registered");
  assert.notEqual((await startGeneration(env)).generationId, second);
});


test("production-sized CZDS delta maps across partitions and reducer fails closed", {
  skip: process.env.SUBFINDER_STRESS !== "1",
  timeout: 120000,
}, async () => {
  const recordCount = Number(process.env.SUBFINDER_STRESS_RECORDS || 20000);
  const deltaId = "f".repeat(64);
  const key = `ingest/czds/com/${deltaId}.json.gz`;
  const records = Array.from({ length: recordCount }, (_, index) => {
    const apex = `stress-${index.toString().padStart(6, "0")}.com`;
    return { apex, hostname: apex, first_seen: null };
  });
  await bucket.put(key, await gzipJson({
    schema_version: "subfinder.ingest-delta.v1",
    source: "czds:com",
    source_id: "com",
    created_at: "2026-09-27T00:00:00.000Z",
    entry_count: recordCount,
    hostname_count: recordCount,
    records,
  }));
  const messages = [];
  const env = {
    LEDGER: database,
    CATALOG: bucket,
    PARTITION_NIBBLES: "2",
    COMPACTION_QUEUE: { send: async (message) => messages.push(message) },
  };
  await registerDelta(env, {
    schema_version: "subfinder.delta-ready.v1",
    delta_id: deltaId,
    source_kind: "czds",
    object_key: key,
  });
  const started = await startGeneration(env);
  const mapStarted = performance.now();
  const mapped = await mapDelta(env, messages.shift());
  const mapMs = Math.round(performance.now() - mapStarted);
  assert.equal(mapped.state, "mapped");
  assert.equal(mapped.fragments, 256);
  const totals = await database.prepare(
    `SELECT COUNT(*) AS partitions, SUM(record_count) AS records
     FROM generation_partitions WHERE generation_id = ?`,
  ).bind(started.generationId).first();
  assert.equal(totals.partitions, 256);
  assert.equal(totals.records, recordCount);
  await startReduce(env);
  const reduceMessage = messages.shift();
  await assert.rejects(runReduce({ ...env, MAX_REDUCE_RECORDS: "1" }, reduceMessage),
    /memory bound/);
  const reduceStarted = performance.now();
  assert.equal((await runReduce(env, reduceMessage)).state, "reduced");
  const reduceMs = Math.round(performance.now() - reduceStarted);
  const partition = await database.prepare(
    `SELECT state, record_count FROM generation_partitions
     WHERE generation_id = ? AND prefix = ?`,
  ).bind(started.generationId, reduceMessage.prefix).first();
  assert.equal(partition.state, "reduced");
  console.log(JSON.stringify({ stress: "czds-delta", recordCount, mapMs, reduceMs,
    partitions: totals.partitions, reduced_partition_records: partition.record_count }));
});


test("one real CZDS partition merges with the exported seed and rolls back locally", {
  skip: !process.env.SUBFINDER_REAL_DELTA || !process.env.SUBFINDER_EXPORT,
  timeout: 120000,
}, async () => {
  const prefix = process.env.SUBFINDER_REAL_PREFIX || "b4";
  const exportDir = process.env.SUBFINDER_EXPORT;
  const root = JSON.parse(readFileSync(resolve(exportDir, "catalog/root.json")));
  const sourceBytes = readFileSync(process.env.SUBFINDER_REAL_DELTA);
  const delta = JSON.parse(
    sourceBytes[0] === 0x1f ? gunzipSync(sourceBytes) : sourceBytes,
  );
  const records = delta.records.filter((record) =>
    createHash("sha256").update(record.apex).digest("hex").startsWith(prefix));
  assert.ok(records.length > 0);
  assert.ok(root.partitions[prefix]);
  const metadata = root.partitions[prefix];
  await bucket.put("catalog/root.json", JSON.stringify({
    ...root, partitions: { [prefix]: metadata },
  }) + "\n");
  await bucket.put(metadata.index, readFileSync(resolve(exportDir, metadata.index)));
  await bucket.put(metadata.bundle, readFileSync(resolve(exportDir, metadata.bundle)));

  const reducedDelta = { ...delta, records,
    entry_count: records.length, hostname_count: records.length };
  const bytes = await gzipJson(reducedDelta);
  const deltaId = createHash("sha256").update(new Uint8Array(bytes)).digest("hex");
  const key = `ingest/czds/com/${deltaId}.json.gz`;
  await bucket.put(key, bytes);
  const messages = [];
  const env = {
    LEDGER: database, CATALOG: bucket, PARTITION_NIBBLES: "2",
    MAX_REDUCE_RECORDS: "200000",
    COMPACTION_QUEUE: { send: async (message) => messages.push(message) },
  };
  await registerDelta(env, {
    schema_version: "subfinder.delta-ready.v1", source_kind: "czds",
    delta_id: deltaId, object_key: key,
  });
  const started = await startGeneration(env);
  const mapped = await mapDelta(env, messages.shift());
  assert.equal(mapped.fragments, 1);
  assert.equal((await startReduce(env)).queued, 1);
  assert.equal((await runReduce(env, messages.shift())).state, "reduced");
  const candidate = await (await bucket.get(
    `catalog/candidates/${started.generationId}.json`,
  )).json();
  const output = candidate.partitions[prefix];
  const index = JSON.parse(gunzipSync(new Uint8Array(await (
    await bucket.get(output.index)
  ).arrayBuffer())));
  const sample = records[0];
  const block = index.blocks.find((item) =>
    item.first_apex <= sample.apex && sample.apex <= item.last_apex);
  assert.ok(block);
  const member = await bucket.get(output.bundle, {
    range: { offset: block.offset, length: block.length },
  });
  const documents = gunzipSync(new Uint8Array(await member.arrayBuffer()))
    .toString().trim().split("\n").map(JSON.parse);
  const found = documents.find((item) => item.a === sample.apex)?.r.find(
    (item) => item.h === sample.hostname,
  );
  assert.ok(found?.s.some((source) => source.n === "czds:com"));
  await activateGeneration(env, started.generationId);
  assert.equal((await (await bucket.get("catalog/root.json")).json()).generation,
    started.generationId);
  await rollbackGeneration(env, started.generationId);
  assert.equal((await (await bucket.get("catalog/root.json")).json()).generation,
    root.generation);
  console.log(JSON.stringify({ pilot: "real-com-local", prefix,
    original_records: delta.records.length, pilot_records: records.length,
    published: true, activated: true, rolled_back: true }));
});
