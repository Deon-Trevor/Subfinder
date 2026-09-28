import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

const workerRoot = resolve(import.meta.dirname, "..");
const staging = JSON.parse(readFileSync(resolve(workerRoot, "wrangler.staging.jsonc")));
const admin = JSON.parse(readFileSync(resolve(workerRoot, "wrangler.staging-admin.jsonc")));

test("staging deploy cannot consume the pending compaction queue", () => {
  assert.equal(staging.workers_dev, false);
  assert.deepEqual(staging.triggers.crons, []);
  assert.deepEqual(staging.queues.consumers, []);
  assert.equal(staging.r2_buckets[0].bucket_name, "subfinder-catalog-stage");
});

test("local admin uses only the remote staging catalog and ledger", () => {
  assert.equal(admin.workers_dev, false);
  assert.equal(admin.r2_buckets[0].bucket_name, "subfinder-catalog-stage");
  assert.equal(admin.r2_buckets[0].remote, true);
  assert.equal(admin.d1_databases[0].database_id, staging.d1_databases[0].database_id);
  assert.equal(admin.d1_databases[0].remote, true);
  assert.equal(admin.queues, undefined);
  assert.equal(admin.triggers, undefined);
});
