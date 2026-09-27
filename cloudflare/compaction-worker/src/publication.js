import { digest } from "./reducer.js";
import { DOMAIN_POLICY_VERSION, PSL_SHA256 } from "../../index-worker/src/domain-policy.js";


const ROOT_KEY = "catalog/root.json";


function generationId(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(value)) {
    throw new Error("generation ID is invalid");
  }
  return value;
}


export async function registerSeed(env, rawGenerationId) {
  const id = generationId(rawGenerationId);
  const key = `catalog/candidates/${id}.json`;
  const candidate = await env.CATALOG.get(key);
  if (candidate === null) throw new Error("seed candidate root is missing");
  const bytes = new Uint8Array(await candidate.arrayBuffer());
  const sha256 = await digest(bytes);
  const root = JSON.parse(new TextDecoder().decode(bytes));
  if (root.generation !== id || !Array.isArray(root.source_names)) {
    throw new Error("seed candidate identity or source metadata is invalid");
  }
  await verifyRootObjects(env.CATALOG, root);
  const active = await rootObject(env.CATALOG);
  if (active !== null && (
    active.document.generation !== id || await digest(active.bytes) !== sha256
  )) throw new Error("another catalog root is already active");
  const now = new Date().toISOString();
  await env.LEDGER.prepare(
    `INSERT OR IGNORE INTO catalog_seeds(
       seed_id, state, candidate_root_key, candidate_root_sha256,
       partition_count, created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    id, active === null ? "published" : "active", key, sha256,
    Object.keys(root.partitions).length, now, now,
  ).run();
  const stored = await env.LEDGER.prepare(
    "SELECT candidate_root_key, candidate_root_sha256, state FROM catalog_seeds WHERE seed_id = ?",
  ).bind(id).first();
  if (stored.candidate_root_key !== key || stored.candidate_root_sha256 !== sha256) {
    throw new Error("seed identity conflicts with the generation ledger");
  }
  return { generationId: id, state: stored.state };
}


async function rootObject(bucket) {
  const object = await bucket.get(ROOT_KEY);
  if (object === null) return null;
  const bytes = new Uint8Array(await object.arrayBuffer());
  return { bytes, etag: object.etag, document: JSON.parse(new TextDecoder().decode(bytes)) };
}


async function immutableRoot(bucket, key, bytes) {
  const expected = await digest(bytes);
  const current = await bucket.get(key);
  if (current !== null) {
    if (await digest(new Uint8Array(await current.arrayBuffer())) !== expected) {
      throw new Error("immutable root archive conflicts with current bytes");
    }
    return;
  }
  const stored = await bucket.put(key, bytes, {
    onlyIf: new Headers({ "If-None-Match": "*" }),
    httpMetadata: { contentType: "application/json" },
  });
  if (stored === null) {
    const raced = await bucket.get(key);
    if (raced === null || await digest(new Uint8Array(await raced.arrayBuffer())) !== expected) {
      throw new Error("immutable root archive changed concurrently");
    }
  }
}


function rootCondition(current) {
  return current === null
    ? new Headers({ "If-None-Match": "*" })
    : new Headers({ "If-Match": `"${current.etag}"` });
}


async function verifyRootObjects(bucket, root) {
  if (
    root?.format !== "subfinder.r2-index.v2" ||
    root.domain_policy_version !== DOMAIN_POLICY_VERSION ||
    root.psl_sha256 !== PSL_SHA256 ||
    !root.partitions || typeof root.partitions !== "object"
  ) throw new Error("root format or domain policy is unsupported");
  for (const [prefix, metadata] of Object.entries(root.partitions)) {
    if (!/^[a-f0-9]{1,3}$/.test(prefix) || prefix.length !== root.partition_nibbles) {
      throw new Error("root partition prefix is invalid");
    }
    const expectedGeneration = metadata.origin_generation ?? root.generation;
    const generationPrefix = `catalog/generations/${expectedGeneration}/partitions/${prefix}.`;
    if (
      metadata.index !== `${generationPrefix}index.json.gz` ||
      metadata.bundle !== `${generationPrefix}bundle`
    ) throw new Error("root partition object path is invalid");
    const index = await bucket.get(metadata.index);
    const bundle = await bucket.head(metadata.bundle);
    if (index === null || bundle === null || bundle.size !== metadata.bundle_bytes) {
      throw new Error("root partition object is missing or has changed size");
    }
    if (await digest(new Uint8Array(await index.arrayBuffer())) !== metadata.index_sha256) {
      throw new Error("root partition index checksum mismatch");
    }
  }
}


export async function activateGeneration(env, rawGenerationId) {
  const id = generationId(rawGenerationId);
  let row = await env.LEDGER.prepare(
    `SELECT base_generation, state, candidate_root_key, candidate_root_sha256
     FROM catalog_generations WHERE generation_id = ?`,
  ).bind(id).first();
  const seed = row === null;
  if (seed) {
    row = await env.LEDGER.prepare(
      `SELECT NULL AS base_generation, state, candidate_root_key,
              candidate_root_sha256 FROM catalog_seeds WHERE seed_id = ?`,
    ).bind(id).first();
  }
  if (row === null || !["published", "active"].includes(row.state)) {
    throw new Error("generation has no published candidate");
  }
  const candidate = await env.CATALOG.get(row.candidate_root_key);
  if (candidate === null) throw new Error("candidate root is missing");
  const bytes = new Uint8Array(await candidate.arrayBuffer());
  if (await digest(bytes) !== row.candidate_root_sha256) {
    throw new Error("candidate root checksum mismatch");
  }
  const document = JSON.parse(new TextDecoder().decode(bytes));
  if (document.generation !== id) throw new Error("candidate root identity mismatch");
  await verifyRootObjects(env.CATALOG, document);
  const current = await rootObject(env.CATALOG);
  if (current?.document.generation === id) {
    if (await digest(current.bytes) !== row.candidate_root_sha256) {
      throw new Error("active root bytes differ from the published candidate");
    }
    await env.LEDGER.prepare(seed
      ? `UPDATE catalog_seeds SET state = 'active', updated_at = ?
         WHERE seed_id = ? AND state = 'published'`
      : `UPDATE catalog_generations SET state = 'active', updated_at = ?
         WHERE generation_id = ? AND state = 'published'`
    ).bind(new Date().toISOString(), id).run();
    return { generationId: id, duplicate: true };
  }
  if ((current?.document.generation ?? null) !== row.base_generation) {
    throw new Error("active root no longer matches candidate base");
  }
  if (current !== null) {
    await immutableRoot(
      env.CATALOG,
      `catalog/roots/${current.document.generation}.json`,
      current.bytes,
    );
  }
  const stored = await env.CATALOG.put(ROOT_KEY, bytes, {
    onlyIf: rootCondition(current),
    httpMetadata: { contentType: "application/json", cacheControl: "no-cache" },
  });
  if (stored === null) throw new Error("active root compare-and-swap failed");
  const readback = await rootObject(env.CATALOG);
  if (readback === null || await digest(readback.bytes) !== row.candidate_root_sha256) {
    throw new Error("active root readback failed");
  }
  if (seed) {
    await env.LEDGER.prepare(
      `UPDATE catalog_seeds SET state = 'active', updated_at = ?
       WHERE seed_id = ? AND state = 'published'`,
    ).bind(new Date().toISOString(), id).run();
  } else {
    await env.LEDGER.prepare(
      `UPDATE catalog_generations SET state = 'active', previous_root_etag = ?,
       updated_at = ? WHERE generation_id = ? AND state = 'published'`,
    ).bind(current?.etag ?? null, new Date().toISOString(), id).run();
  }
  return { generationId: id, duplicate: false };
}


export async function rollbackGeneration(env, rawGenerationId) {
  const id = generationId(rawGenerationId);
  const row = await env.LEDGER.prepare(
    `SELECT base_generation, state FROM catalog_generations WHERE generation_id = ?`,
  ).bind(id).first();
  if (row === null && await env.LEDGER.prepare(
    "SELECT seed_id FROM catalog_seeds WHERE seed_id = ?",
  ).bind(id).first() !== null) {
    throw new Error("initial seed has no prior root to roll back to");
  }
  if (row === null || row.state !== "active") {
    throw new Error("generation is not active");
  }
  if (row.base_generation === null) {
    throw new Error("initial seed has no prior root to roll back to");
  }
  const archived = await env.CATALOG.get(`catalog/roots/${row.base_generation}.json`);
  if (archived === null) throw new Error("prior root archive is missing");
  const previousBytes = new Uint8Array(await archived.arrayBuffer());
  const previous = JSON.parse(new TextDecoder().decode(previousBytes));
  if (previous.generation !== row.base_generation) {
    throw new Error("prior root archive identity mismatch");
  }
  await verifyRootObjects(env.CATALOG, previous);
  const current = await rootObject(env.CATALOG);
  if (current?.document.generation === id) {
    await immutableRoot(env.CATALOG, `catalog/roots/${id}.json`, current.bytes);
    const restored = await env.CATALOG.put(ROOT_KEY, previousBytes, {
      onlyIf: rootCondition(current),
      httpMetadata: { contentType: "application/json", cacheControl: "no-cache" },
    });
    if (restored === null) throw new Error("rollback compare-and-swap failed");
  } else if (
    current?.document.generation !== row.base_generation ||
    await digest(current.bytes) !== await digest(previousBytes) ||
    await env.CATALOG.head(`catalog/roots/${id}.json`) === null
  ) {
    throw new Error("active root changed before rollback");
  }
  const readback = await rootObject(env.CATALOG);
  if (readback === null || await digest(readback.bytes) !== await digest(previousBytes)) {
    throw new Error("rollback root readback failed");
  }
  const now = new Date().toISOString();
  await env.LEDGER.batch([
    env.LEDGER.prepare(
      `UPDATE catalog_generations SET state = 'rolled_back', updated_at = ?
       WHERE generation_id = ? AND state = 'active'`,
    ).bind(now, id),
    env.LEDGER.prepare(
      `UPDATE catalog_deltas SET state = 'registered', generation_id = NULL,
       error = NULL, updated_at = ? WHERE generation_id = ? AND state = 'mapped'`,
    ).bind(now, id),
  ]);
  return { generationId: id, restoredGeneration: row.base_generation };
}
