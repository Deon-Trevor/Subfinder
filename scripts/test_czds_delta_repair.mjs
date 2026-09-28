import assert from "node:assert/strict";
import { test } from "node:test";

import { repairDocument } from "./czds_delta_repair.mjs";

function source(records) {
  return {
    schema_version: "subfinder.ingest-delta.v1", source: "czds:com",
    source_id: "com", range: { chunk: 55 },
    created_at: "2026-09-27T00:00:00.000Z",
    entry_count: records.length, hostname_count: records.length, records,
  };
}

function record(hostname, apex = hostname) {
  return { apex, hostname, first_seen: null };
}

test("excludes only a bare public suffix and keeps its registrable child", () => {
  const original = source([
    record("blogspot.com"), record("tenant.blogspot.com"),
    record("www.example.com", "example.com"),
  ]);
  const { document, excluded } = repairDocument(original, 3);
  assert.equal(excluded, 1);
  assert.deepEqual(document.records, original.records.slice(1));
  assert.equal(document.entry_count, 2);
  assert.equal(document.hostname_count, 2);
  assert.equal(original.records.length, 3);
});

test("rejects unrelated corruption without silently dropping it", () => {
  assert.throws(() => repairDocument(source([
    record("blogspot.com"), record("www.example.com", "wrong.com"),
  ]), 2), /unrelated invalid record/);
});

test("rejects a count mismatch or a chunk that needs no repair", () => {
  assert.throws(() => repairDocument(source([record("blogspot.com")]), 2), /metadata/);
  assert.throws(() => repairDocument(source([record("tenant.blogspot.com")]), 1), /not a repairable/);
});
