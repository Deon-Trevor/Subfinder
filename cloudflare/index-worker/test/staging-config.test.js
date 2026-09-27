import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const production = JSON.parse(readFileSync(new URL("../wrangler.jsonc", import.meta.url)));
const staging = JSON.parse(readFileSync(new URL("../wrangler.staging.jsonc", import.meta.url)));

test("staging read Worker cannot point at production or expose a candidate early", () => {
  assert.notEqual(staging.name, production.name);
  assert.equal(staging.workers_dev, true);
  assert.equal(staging.main, production.main);
  assert.equal(staging.r2_buckets[0].bucket_name, "subfinder-catalog-stage");
  assert.notEqual(staging.r2_buckets[0].bucket_name, production.r2_buckets[0].bucket_name);
  assert.equal(staging.vars.CATALOG_ROOT_KEY, "catalog/root.json");
  assert.equal(staging.vars.MCP_ALLOWED_HOSTS, "subfinder-index-stage.pundit.workers.dev");
  assert.equal(staging.assets, undefined);
  assert.equal(staging.routes, undefined);
  assert.equal(staging.CLIENT_TOKENS, undefined);
  for (const key of [
    "PUBLIC_REQUEST_LIMIT",
    "TOKEN_REQUEST_LIMIT",
    "QUEUED_BATCH_MAX_APEXES",
    "QUEUED_BATCH_MAX_PENDING",
    "QUEUED_BATCH_MAX_PENDING_PER_TOKEN",
  ]) {
    assert.equal(staging.vars[key], production.vars[key], `${key} must match production`);
  }
});
