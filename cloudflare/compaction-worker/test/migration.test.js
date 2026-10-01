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

async function applyMigration(db, file) {
  for (const statement of statements(file)) await db.prepare(statement).run();
}

function createMiniflare() {
  return new Miniflare({
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
}


test("fresh ledger accepts supported sources and generation references", async () => {
  const miniflare = createMiniflare();
  try {
    const db = await miniflare.getD1Database("LEDGER");
    for (const file of ["0001_generation_ledger.sql", "0002_seed_publication.sql",
      "0004_expand_source_kinds.sql"]) {
      await applyMigration(db, file);
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

for (const [priorSchema, alreadyExpanded] of [
  ["original", false], ["previously expanded", true],
]) test(`${priorSchema} ledger upgrades without losing generation references`, async () => {
  const miniflare = createMiniflare();
  try {
    const db = await miniflare.getD1Database("LEDGER");
    const original = readFileSync(resolve(root, "migrations", "0001_generation_ledger.sql"), "utf8");
    const oldKinds = "'direct-ct', 'urlscan', 'czds'";
    const expanded = "'direct-ct', 'static-ct', 'urlscan', 'czds', 'public-bulk'";
    assert.ok(original.includes(oldKinds));
    const prior = alreadyExpanded ? original.replace(oldKinds, expanded) : original;
    for (const statement of prior.split(";").map((value) => value.trim()).filter(Boolean)) {
      await db.prepare(statement).run();
    }
    await applyMigration(db, "0002_seed_publication.sql");

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
    if (alreadyExpanded) {
      await db.prepare(
        `INSERT INTO catalog_deltas(delta_id, source_kind, object_key, object_sha256,
         object_bytes, state, record_count, created_at, updated_at)
         VALUES (?, 'public-bulk', 'ingest/public-bulk/before.json.gz', ?, 1, 'registered', 1, ?, ?)`,
      ).bind("0".repeat(64), "2".repeat(64), now, now).run();
    } else {
      await assert.rejects(db.prepare(
        `INSERT INTO catalog_deltas(delta_id, source_kind, object_key, object_sha256,
         object_bytes, state, record_count, created_at, updated_at)
         VALUES (?, 'static-ct', 'ingest/static-ct/before.json.gz', ?, 1, 'registered', 1, ?, ?)`,
      ).bind("1".repeat(64), "2".repeat(64), now, now).run());
    }

    await applyMigration(db, "0004_expand_source_kinds.sql");
    const retained = await db.prepare(
      `SELECT d.source_kind, d.generation_id, f.object_key
       FROM catalog_deltas d JOIN generation_fragments f ON f.delta_id = d.delta_id
       WHERE d.delta_id = ?`,
    ).bind(deltaId).first();
    assert.deepEqual(retained, {
      source_kind: "czds", generation_id: generationId,
      object_key: "fragments/existing.json.gz",
    });
    if (alreadyExpanded) {
      const retainedBulk = await db.prepare(
        "SELECT source_kind FROM catalog_deltas WHERE delta_id = ?",
      ).bind("0".repeat(64)).first();
      assert.deepEqual(retainedBulk, { source_kind: "public-bulk" });
    }
    assert.equal((await db.prepare("PRAGMA foreign_key_check").all()).results.length, 0);
    const indexes = (await db.prepare("PRAGMA index_list(catalog_deltas)").all()).results;
    assert.ok(indexes.some(({ name }) => name === "catalog_deltas_state_created"));
    assert.ok(indexes.some(({ name }) => name === "catalog_deltas_generation_state"));

    for (const [kind, id] of [["direct-ct", "1"], ["static-ct", "2"],
      ["urlscan", "3"], ["public-bulk", "4"]]) {
      await db.prepare(
        `INSERT INTO catalog_deltas(delta_id, source_kind, object_key, object_sha256,
         object_bytes, state, record_count, created_at, updated_at)
         VALUES (?, ?, ?, ?, 1, 'registered', 1, ?, ?)`,
      ).bind(id.repeat(64), kind, `ingest/${kind}/${id}.json.gz`, "e".repeat(64), now, now).run();
    }
    await assert.rejects(db.prepare(
      `INSERT INTO catalog_deltas(delta_id, source_kind, object_key, object_sha256,
       object_bytes, state, record_count, created_at, updated_at)
       VALUES (?, 'unknown', 'ingest/unknown/no.json.gz', ?, 1, 'registered', 1, ?, ?)`,
    ).bind("5".repeat(64), "e".repeat(64), now, now).run());
  } finally {
    await miniflare.dispose();
  }
});
