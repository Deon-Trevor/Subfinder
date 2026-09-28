import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";


const config = JSON.parse(readFileSync(
  resolve(import.meta.dirname, "../wrangler.staging.jsonc"), "utf8",
));


test("URLScan staging uses its own control and job queue without a schedule", () => {
  assert.equal(config.name, "subfinder-urlscan-stage");
  assert.equal(config.workers_dev, false);
  assert.equal(config.preview_urls, false);
  assert.deepEqual(config.triggers.crons, []);
  assert.deepEqual(config.r2_buckets, [
    { binding: "CATALOG", bucket_name: "subfinder-catalog-stage" },
  ]);
  assert.equal(config.d1_databases[0].binding, "CONTROL");
  assert.equal(config.d1_databases[0].database_name, "subfinder-urlscan-stage-control");
  assert.match(config.d1_databases[0].database_id, /^[a-f0-9-]{36}$/);
  assert.deepEqual(config.queues.producers, [
    { binding: "URLSCAN_QUEUE", queue: "subfinder-urlscan-stage" },
    { binding: "COMPACTION_QUEUE", queue: "subfinder-compaction-stage" },
  ]);
  assert.equal(config.queues.consumers[0].queue, "subfinder-urlscan-stage");
  assert.equal(config.queues.consumers[0].dead_letter_queue, "subfinder-urlscan-stage-dead");
  assert.equal(config.queues.consumers[0].max_concurrency, 1);
});


test("URLScan staging has a small quota and no committed provider credential", () => {
  assert.equal(config.vars.URLSCAN_BREADTH_DAILY_LIMIT, "25");
  assert.equal(config.vars.URLSCAN_PAGE_SIZE, "100");
  assert.equal(config.vars.URLSCAN_SOURCE_LIMIT, "1");
  assert.equal(Object.hasOwn(config.vars, "URLSCAN_API_KEY"), false);
});
