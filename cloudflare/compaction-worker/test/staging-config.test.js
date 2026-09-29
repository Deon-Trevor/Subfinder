import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

const workerRoot = resolve(import.meta.dirname, "..");
const staging = JSON.parse(readFileSync(resolve(workerRoot, "wrangler.staging.jsonc")));
const admin = JSON.parse(readFileSync(resolve(workerRoot, "wrangler.staging-admin.jsonc")));

test("staging consumer is bounded and has no automatic generation trigger", () => {
  assert.equal(staging.workers_dev, false);
  assert.deepEqual(staging.triggers.crons, []);
  assert.equal(staging.vars.REGISTRATION_ONLY, "false");
  assert.deepEqual(staging.queues.consumers, [{
    queue: "subfinder-compaction-stage",
    max_batch_size: 1,
    max_batch_timeout: 5,
    max_retries: 8,
    dead_letter_queue: "subfinder-compaction-stage-dead",
    max_concurrency: 8,
  }]);
  assert.equal(staging.r2_buckets[0].bucket_name, "subfinder-catalog-stage");
});

test("local admin uses remote staging storage and an isolated queue", () => {
  assert.equal(admin.workers_dev, false);
  assert.equal(admin.r2_buckets[0].bucket_name, "subfinder-catalog-stage");
  assert.equal(admin.r2_buckets[0].remote, true);
  assert.equal(admin.d1_databases[0].database_id, staging.d1_databases[0].database_id);
  assert.equal(admin.d1_databases[0].remote, true);
  assert.deepEqual(admin.queues.producers, [{
    binding: "COMPACTION_QUEUE",
    queue: "subfinder-compaction-stage",
    remote: false,
  }]);
  assert.deepEqual(admin.vars, staging.vars);
  assert.equal(admin.triggers, undefined);
});
