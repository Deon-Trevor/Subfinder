import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

import { validatedLogUrl } from "../src/direct-ct.js";


const config = JSON.parse(readFileSync(
  resolve(import.meta.dirname, "../wrangler.staging.jsonc"), "utf8",
));


test("CT staging is isolated and inert until a source is scheduled", () => {
  assert.equal(config.name, "subfinder-direct-ct-stage");
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.deepEqual(config.triggers.crons, []);
  assert.deepEqual(config.r2_buckets, [
    { binding: "CATALOG", bucket_name: "subfinder-catalog-stage" },
  ]);
  assert.equal(config.d1_databases[0].binding, "CONTROL");
  assert.equal(config.d1_databases[0].database_name, "subfinder-ct-stage-control");
  assert.match(config.d1_databases[0].database_id, /^[a-f0-9-]{36}$/);
  assert.deepEqual(config.queues.producers, [
    { binding: "INGEST_QUEUE", queue: "subfinder-direct-ct-stage" },
    { binding: "COMPACTION_QUEUE", queue: "subfinder-compaction-stage" },
  ]);
  assert.equal(config.queues.consumers[0].queue, "subfinder-direct-ct-stage");
  assert.equal(config.queues.consumers[0].dead_letter_queue, "subfinder-direct-ct-stage-dead");
  assert.equal(config.queues.consumers[0].max_concurrency, 1);
  assert.equal(config.vars.CT_RANGE_SIZE, "16");
  assert.equal(config.vars.CT_SOURCE_LIMIT, "1");
});


test("CT staging host policy admits configured logs and rejects other hosts", () => {
  const allowed = config.vars.CT_ALLOWED_HOSTS.split(",");
  assert.equal(
    validatedLogUrl("https://ct.googleapis.com/logs/test/", allowed).toString(),
    "https://ct.googleapis.com/logs/test",
  );
  assert.throws(
    () => validatedLogUrl("https://ct.googleapis.com.evil/logs/test", allowed),
    /not allowed/,
  );
});
