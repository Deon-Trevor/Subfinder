import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

import { Miniflare } from "miniflare";


const root = resolve(import.meta.dirname, "..");


function statements(file) {
  return readFileSync(resolve(root, "migrations", file), "utf8")
    .split(";").map((value) => value.trim()).filter(Boolean);
}


test("fresh ledger accepts supported sources and generation references", async () => {
  const miniflare = new Miniflare({
    workers: [{ config: {
      name: "subfinder-migration-test",
      compatibilityDate: "2026-09-27",
      manifest: {
        mainModule: "index.js",
        modulesRoot: root,
        modules: { "index.js": { type: "esm", contents: "export default {};" } },
      },
      env: { LEDGER: { type: "d1", name: "LEDGER" } },
    } }],
  });
  try {
    const db = await miniflare.getD1Database("LEDGER");
    for (const file of ["0001_generation_ledger.sql", "0002_seed_publication.sql"]) {
      for (const statement of statements(file)) await db.prepare(statement).run();
    }
    const now = "2026-09-29T00:00:00.000Z";
    const generationId = "a".repeat(64);
    const deltaId = "b".repeat(64);
    await db.prepare(
      `INSERT INTO catalog_generations(generation_id, state, delta_count, created_at, updated_at)
       VALUES (?, 'mapped', 1, ?, ?)`,
    ).bind(generationId, now, now).run();
    await db.prepare(
      `INSERT INTO catalog_deltas(delta_id, source_kind, object_key, object_sha256,
       object_bytes, state, generation_id, record_count, created_at, updated_at)
       VALUES (?, 'czds', 'ingest/czds/existing.json.gz', ?, 1, 'mapped', ?, 1, ?, ?)`,
    ).bind(deltaId, "c".repeat(64), generationId, now, now).run();
    await db.prepare(
      `INSERT INTO generation_fragments(generation_id, delta_id, prefix, object_key,
       object_sha256, object_bytes, record_count, created_at)
       VALUES (?, ?, '0', 'fragments/existing.json.gz', ?, 1, 1, ?)`,
    ).bind(generationId, deltaId, "d".repeat(64), now).run();
    const existing = await db.prepare(
      "SELECT source_kind, generation_id FROM catalog_deltas WHERE delta_id = ?",
    ).bind(deltaId).first();
    assert.deepEqual(existing, { source_kind: "czds", generation_id: generationId });
    assert.equal((await db.prepare("PRAGMA foreign_key_check").all()).results.length, 0);
    await db.prepare(
      `INSERT INTO catalog_deltas(delta_id, source_kind, object_key, object_sha256,
       object_bytes, state, record_count, created_at, updated_at)
       VALUES (?, 'public-bulk', 'ingest/public-bulk/new.json.gz', ?, 1, 'registered', 1, ?, ?)`,
    ).bind("e".repeat(64), "f".repeat(64), now, now).run();
    await db.prepare(
      `INSERT INTO catalog_deltas(delta_id, source_kind, object_key, object_sha256,
       object_bytes, state, record_count, created_at, updated_at)
       VALUES (?, 'static-ct', 'ingest/static-ct/new.json.gz', ?, 1, 'registered', 1, ?, ?)`,
    ).bind("1".repeat(64), "2".repeat(64), now, now).run();
  } finally {
    await miniflare.dispose();
  }
});
