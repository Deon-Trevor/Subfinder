#!/usr/bin/env node
// Check that a set of local Wrangler files points at one catalog pipeline.
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const roles = ["read", "compaction", "direct-ct", "urlscan", "czds"];
const examples = {
  read: "cloudflare/index-worker/wrangler.example.jsonc",
  compaction: "cloudflare/compaction-worker/wrangler.example.jsonc",
  "direct-ct": "cloudflare/ingest-worker/wrangler.example.jsonc",
  urlscan: "cloudflare/urlscan-worker/wrangler.example.jsonc",
  czds: "cloudflare/czds-worker/wrangler.example.jsonc",
};

function inputs(args) {
  const exampleMode = args[0] === "--examples";
  const selected = exampleMode ? { ...examples } : {};
  const seen = new Set();
  const options = exampleMode ? args.slice(1) : args;
  for (let i = 0; i < options.length; i += 2) {
    const flag = options[i];
    const path = options[i + 1];
    const role = flag?.startsWith("--") ? flag.slice(2) : "";
    if (!roles.includes(role) || !path || path.startsWith("--") || seen.has(role)) {
      throw new Error("usage: check_cloudflare_bindings.mjs [--examples] --read FILE --compaction FILE [--direct-ct FILE] [--urlscan FILE] [--czds FILE]");
    }
    seen.add(role);
    selected[role] = path;
  }
  assert.ok(selected.read && selected.compaction, "read and compaction configs are required");
  return selected;
}

function config(role, path, exampleMode) {
  const file = resolve(root, path);
  const value = JSON.parse(readFileSync(file, "utf8"));
  assert.ok(value.name && value.main === "src/index.js", `${role}: Worker name and main are required`);
  assert.ok(existsSync(resolve(dirname(file), value.main)), `${role}: main file is missing`);
  assert.deepEqual(value.triggers?.crons ?? [], [], `${role}: Crons must be disabled for initial deployment`);
  if (!exampleMode) {
    assert.ok(!value.name.startsWith("example-"), `${role}: replace the example Worker name`);
    for (const db of value.d1_databases ?? []) {
      assert.match(db.database_id ?? "", /^[a-f\d]{8}-[a-f\d-]{27,}$/i,
        `${role}: replace the example D1 database ID`);
    }
  }
  for (const secret of ["PUBLISH_TOKEN", "CLIENT_TOKENS", "URLSCAN_API_KEY", "CZDS_USERNAME", "CZDS_PASSWORD"]) {
    assert.ok(!Object.hasOwn(value.vars ?? {}, secret), `${role}: ${secret} must be a Worker secret`);
  }
  return value;
}

function binding(configValue, group, name) {
  return (configValue[group] ?? []).find((item) => item.binding === name);
}

const selected = inputs(process.argv.slice(2));
const exampleMode = process.argv[2] === "--examples";
const files = Object.fromEntries(Object.entries(selected).map(([role, path]) => [
  role, config(role, path, exampleMode),
]));
assert.equal(new Set(Object.values(files).map((item) => item.name)).size,
  Object.keys(files).length, "Worker names must be distinct");

const catalog = binding(files.read, "r2_buckets", "CATALOG")?.bucket_name;
assert.ok(catalog, "read: CATALOG bucket is required");
for (const [role, value] of Object.entries(files)) {
  assert.equal(binding(value, "r2_buckets", "CATALOG")?.bucket_name, catalog,
    `${role}: CATALOG bucket differs from read Worker`);
}
const compactionQueue = files.compaction.queues?.producers?.find(
  (item) => item.binding === "COMPACTION_QUEUE");
assert.ok(compactionQueue, "compaction: COMPACTION_QUEUE producer is required");
assert.ok(files.compaction.queues?.consumers?.some((item) => item.queue === compactionQueue.queue),
  "compaction: consumer must read its producer Queue");
for (const role of ["direct-ct", "urlscan", "czds"]) {
  if (!files[role]) continue;
  assert.equal(files[role].queues?.producers?.find((item) => item.binding === "COMPACTION_QUEUE")?.queue,
    compactionQueue.queue, `${role}: compaction Queue differs`);
}
for (const [role, producer] of [["direct-ct", "INGEST_QUEUE"], ["urlscan", "URLSCAN_QUEUE"]]) {
  if (!files[role]) continue;
  const name = files[role].queues?.producers?.find((item) => item.binding === producer)?.queue;
  assert.ok(name && files[role].queues?.consumers?.some((item) => item.queue === name),
    `${role}: job consumer must read its producer Queue`);
}
if (files.urlscan && files.read.services?.some((item) => item.binding === "URLSCAN_INGEST")) {
  assert.equal(files.read.services.find((item) => item.binding === "URLSCAN_INGEST").service,
    files.urlscan.name, "read: URLSCAN_INGEST points at a different Worker");
}
assert.equal(files.read.vars?.CATALOG_ROOT_KEY, "catalog/root.json",
  "read: catalog root key differs");
const docsOrigin = new URL(files.read.vars?.DOCS_ORIGIN);
assert.equal(docsOrigin.protocol, "https:", "read: docs origin must use HTTPS");
assert.equal(docsOrigin.pathname, "/", "read: docs origin must have no path");
assert.ok(files.read.assets?.run_worker_first?.includes("/docs/*"),
  "read: docs requests must reach the Worker");
if (files.read.routes?.length) {
  const hostname = files.read.routes[0].pattern;
  assert.equal(files.read.vars?.MCP_ALLOWED_HOSTS, hostname,
    "read: MCP host must match the public route");
  assert.equal(files.read.vars?.CLIENT_IP_HEADER_HOSTNAME, hostname,
    "read: client-IP rule host must match the public route");
}
console.log(`Checked ${Object.keys(files).length} Worker configs against one catalog pipeline.`);
