import {
  apexForHostname,
  normalizeApex,
  normalizeHostname,
} from "../../index-worker/src/domain-policy.js";
import { reducePartition, stageCandidateRoot } from "./reducer.js";
import { activateGeneration, registerSeed, rollbackGeneration } from "./publication.js";


const DELTA_READY_SCHEMA_VERSION = "subfinder.delta-ready.v1";
const MAP_JOB_SCHEMA_VERSION = "subfinder.map-job.v1";
const REDUCE_JOB_SCHEMA_VERSION = "subfinder.reduce-partition.v1";
const DELTA_SCHEMA_VERSION = "subfinder.ingest-delta.v1";
const FRAGMENT_SCHEMA_VERSION = "subfinder.map-fragment.v1";
const encoder = new TextEncoder();


function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error("compaction limit configuration must be a positive integer");
  }
  return parsed;
}


function bytesToHex(value) {
  return [...new Uint8Array(value)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}


async function sha256Bytes(value) {
  return bytesToHex(await crypto.subtle.digest("SHA-256", value));
}


async function sha256Text(value) {
  return await sha256Bytes(encoder.encode(value));
}


async function gunzipJson(value) {
  const stream = new Blob([value]).stream().pipeThrough(new DecompressionStream("gzip"));
  return JSON.parse(await new Response(stream).text());
}


async function gzipJson(value) {
  const stream = new Blob([JSON.stringify(value)])
    .stream()
    .pipeThrough(new CompressionStream("gzip"));
  return await new Response(stream).arrayBuffer();
}


function validateFirstSeen(value) {
  if (value === null) return null;
  if (typeof value !== "string") throw new Error("delta first_seen is invalid");
  const date = new Date(value);
  if (Number.isNaN(date.valueOf()) || date.toISOString() !== value) {
    throw new Error("delta first_seen is invalid");
  }
  return value;
}


function validateDelta(document) {
  if (
    document?.schema_version !== DELTA_SCHEMA_VERSION ||
    typeof document.source !== "string" ||
    !document.source ||
    document.created_at == null ||
    !Array.isArray(document.records)
  ) {
    throw new Error("ingestion delta is invalid");
  }
  const records = [];
  const seen = new Set();
  for (const raw of document.records) {
    const hostname = normalizeHostname(raw?.hostname);
    const apex = normalizeApex(raw?.apex);
    if (apexForHostname(hostname) !== apex) {
      throw new Error("delta record apex does not match hostname");
    }
    const key = `${apex}\n${hostname}`;
    if (seen.has(key)) continue;
    seen.add(key);
    records.push({ apex, hostname, first_seen: validateFirstSeen(raw.first_seen) });
  }
  records.sort((left, right) => (
    left.apex.localeCompare(right.apex) || left.hostname.localeCompare(right.hostname)
  ));
  return {
    source: document.source,
    observedAt: validateFirstSeen(document.created_at),
    records,
  };
}


function validateDeltaReady(body) {
  if (
    body?.schema_version !== DELTA_READY_SCHEMA_VERSION ||
    !["direct-ct", "urlscan", "czds"].includes(body.source_kind) ||
    typeof body.delta_id !== "string" ||
    !/^[a-f0-9]{64}$/.test(body.delta_id) ||
    typeof body.object_key !== "string" ||
    !body.object_key.startsWith("ingest/") ||
    body.object_key.includes("..")
  ) {
    throw new Error("delta-ready queue message is invalid");
  }
  return body;
}


function validateMapJob(body) {
  if (
    body?.schema_version !== MAP_JOB_SCHEMA_VERSION ||
    typeof body.generation_id !== "string" ||
    !/^[a-f0-9]{64}$/.test(body.generation_id) ||
    typeof body.delta_id !== "string" ||
    !/^[a-f0-9]{64}$/.test(body.delta_id)
  ) {
    throw new Error("map queue message is invalid");
  }
  return body;
}


function validateReduceJob(body) {
  if (
    body?.schema_version !== REDUCE_JOB_SCHEMA_VERSION ||
    typeof body.generation_id !== "string" ||
    !/^[a-f0-9]{64}$/.test(body.generation_id) ||
    typeof body.prefix !== "string" ||
    !/^[a-f0-9]{1,3}$/.test(body.prefix)
  ) throw new Error("reduce queue message is invalid");
  return body;
}


async function readDeltaObject(env, objectKey) {
  const object = await env.CATALOG.get(objectKey);
  if (object === null) throw new Error("ingestion delta object does not exist");
  const bytes = await object.arrayBuffer();
  const maxBytes = positiveInteger(env.MAX_DELTA_BYTES, 32 * 1024 * 1024);
  if (bytes.byteLength === 0 || bytes.byteLength > maxBytes) {
    throw new Error("ingestion delta exceeds the configured map-stage bound");
  }
  const document = await gunzipJson(bytes);
  return {
    bytes,
    sha256: await sha256Bytes(bytes),
    ...validateDelta(document),
  };
}


export async function registerDelta(env, rawBody) {
  const body = validateDeltaReady(rawBody);
  const delta = await readDeltaObject(env, body.object_key);
  const now = new Date().toISOString();
  await env.LEDGER.prepare(
    `INSERT OR IGNORE INTO catalog_deltas(
       delta_id, source_kind, object_key, object_sha256, object_bytes,
       state, record_count, created_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, 'registered', ?, ?, ?)`,
  ).bind(
    body.delta_id,
    body.source_kind,
    body.object_key,
    delta.sha256,
    delta.bytes.byteLength,
    delta.records.length,
    now,
    now,
  ).run();
  const stored = await env.LEDGER.prepare(
    `SELECT source_kind, object_key, object_sha256, object_bytes, record_count, state
     FROM catalog_deltas WHERE delta_id = ?`,
  ).bind(body.delta_id).first();
  if (
    stored === null ||
    stored.source_kind !== body.source_kind ||
    stored.object_key !== body.object_key ||
    stored.object_sha256 !== delta.sha256 ||
    Number(stored.object_bytes) !== delta.bytes.byteLength ||
    Number(stored.record_count) !== delta.records.length
  ) {
    throw new Error("delta identity conflicts with the generation ledger");
  }
  return { deltaId: body.delta_id, state: stored.state };
}


async function activeRootGeneration(env) {
  const object = await env.CATALOG.get("catalog/root.json");
  if (object === null) return null;
  const root = await object.json();
  if (typeof root?.generation !== "string" || !root.generation) {
    throw new Error("active catalog root has no generation identity");
  }
  return root.generation;
}


async function sendMapJobs(env, generationId) {
  const rows = await env.LEDGER.prepare(
    `SELECT delta_id FROM catalog_deltas
     WHERE generation_id = ? AND state = 'assigned' ORDER BY delta_id`,
  ).bind(generationId).all();
  for (const row of rows.results) {
    await env.COMPACTION_QUEUE.send({
      schema_version: MAP_JOB_SCHEMA_VERSION,
      generation_id: generationId,
      delta_id: row.delta_id,
    });
  }
  return rows.results.length;
}


export async function startGeneration(env) {
  const existing = await env.LEDGER.prepare(
    `SELECT generation_id, state FROM catalog_generations
     WHERE state IN ('mapping', 'mapped', 'reducing', 'published')
     ORDER BY created_at LIMIT 1`,
  ).first();
  if (existing !== null) {
    if (existing.state !== "mapping") {
      return {
        generationId: existing.generation_id,
        queued: 0,
        resumed: false,
        waitingForReduce: true,
      };
    }
    return {
      generationId: existing.generation_id,
      queued: await sendMapJobs(env, existing.generation_id),
      resumed: true,
      waitingForReduce: false,
    };
  }
  const limit = positiveInteger(env.GENERATION_DELTA_LIMIT, 500);
  const pending = await env.LEDGER.prepare(
    `SELECT delta_id FROM catalog_deltas
     WHERE state = 'registered' ORDER BY created_at, delta_id LIMIT ?`,
  ).bind(limit).all();
  if (pending.results.length === 0) return null;
  const baseGeneration = await activeRootGeneration(env);
  const deltaIds = pending.results.map((row) => row.delta_id);
  const generationId = await sha256Text(JSON.stringify({
    baseGeneration, deltaIds, attempt: crypto.randomUUID(),
  }));
  const now = new Date().toISOString();
  const statements = [
    env.LEDGER.prepare(
      `INSERT INTO catalog_generations(
         generation_id, base_generation, state, delta_count, created_at, updated_at
       ) VALUES (?, ?, 'mapping', ?, ?, ?)`,
    ).bind(generationId, baseGeneration, deltaIds.length, now, now),
    ...deltaIds.map((deltaId) => env.LEDGER.prepare(
      `UPDATE catalog_deltas
       SET state = 'assigned', generation_id = ?, error = NULL, updated_at = ?
       WHERE delta_id = ? AND state = 'registered'`,
    ).bind(generationId, now, deltaId)),
  ];
  await env.LEDGER.batch(statements);
  return {
    generationId,
    queued: await sendMapJobs(env, generationId),
    resumed: false,
    waitingForReduce: false,
  };
}


async function partitionPrefix(apex, nibbles) {
  return (await sha256Text(apex)).slice(0, nibbles);
}


async function putFragment(env, key, document) {
  const bytes = await gzipJson(document);
  const digest = await sha256Bytes(bytes);
  const stored = await env.CATALOG.put(key, bytes, {
    onlyIf: new Headers({ "If-None-Match": "*" }),
    httpMetadata: { contentType: "application/json", contentEncoding: "gzip" },
    customMetadata: {
      schema_version: FRAGMENT_SCHEMA_VERSION,
      sha256: digest,
    },
  });
  if (stored === null) {
    const existing = await env.CATALOG.head(key);
    if (existing?.customMetadata?.sha256 !== digest || existing.size !== bytes.byteLength) {
      throw new Error("map fragment key already contains different bytes");
    }
  }
  return { bytes: bytes.byteLength, sha256: digest };
}


async function finishMappedGeneration(env, generationId, now) {
  const outstanding = await env.LEDGER.prepare(
    `SELECT count(*) AS count FROM catalog_deltas
     WHERE generation_id = ? AND state != 'mapped'`,
  ).bind(generationId).first();
  if (Number(outstanding.count) !== 0) return false;
  await env.LEDGER.prepare(
    `INSERT INTO generation_partitions(
       generation_id, prefix, state, fragment_count, record_count, updated_at
     )
     SELECT generation_id, prefix, 'mapped', count(*), sum(record_count), ?
     FROM generation_fragments WHERE generation_id = ? GROUP BY prefix
     ON CONFLICT(generation_id, prefix) DO UPDATE SET
       fragment_count = excluded.fragment_count,
       record_count = excluded.record_count,
       error = NULL,
       updated_at = excluded.updated_at
     WHERE generation_partitions.state = 'mapped'`,
  ).bind(now, generationId).run();
  const partitions = await env.LEDGER.prepare(
    "SELECT count(*) AS count FROM generation_partitions WHERE generation_id = ?",
  ).bind(generationId).first();
  await env.LEDGER.prepare(
    `UPDATE catalog_generations
     SET state = 'mapped', partition_count = ?, error = NULL, updated_at = ?
     WHERE generation_id = ? AND state = 'mapping'`,
  ).bind(Number(partitions.count), now, generationId).run();
  return true;
}


export async function mapDelta(env, rawBody) {
  const body = validateMapJob(rawBody);
  const row = await env.LEDGER.prepare(
    `SELECT delta_id, object_key, state, generation_id
     FROM catalog_deltas WHERE delta_id = ?`,
  ).bind(body.delta_id).first();
  if (row === null) throw new Error("map delta does not exist");
  if (row.generation_id !== body.generation_id) {
    throw new Error("map delta is assigned to a different generation");
  }
  if (row.state === "mapped") {
    await finishMappedGeneration(env, body.generation_id, new Date().toISOString());
    return { state: "mapped", duplicate: true };
  }
  if (row.state !== "assigned") throw new Error("map delta is not assigned");

  const delta = await readDeltaObject(env, row.object_key);
  const nibbles = Math.min(3, positiveInteger(env.PARTITION_NIBBLES, 2));
  const grouped = new Map();
  for (const record of delta.records) {
    const prefix = await partitionPrefix(record.apex, nibbles);
    const records = grouped.get(prefix) ?? [];
    records.push(record);
    grouped.set(prefix, records);
  }
  const now = new Date().toISOString();
  const fragmentRows = [];
  const prefixes = [...grouped.keys()].sort();
  // minimal: five concurrent R2 writes leave room under the six-connection Worker limit.
  for (let offset = 0; offset < prefixes.length; offset += 5) {
    fragmentRows.push(...await Promise.all(prefixes.slice(offset, offset + 5).map(async (prefix) => {
      const records = grouped.get(prefix);
      const objectKey = (
        `compact/staging/${body.generation_id}/${prefix}/${body.delta_id}.json.gz`
      );
      const metadata = await putFragment(env, objectKey, {
        schema_version: FRAGMENT_SCHEMA_VERSION,
        generation_id: body.generation_id,
        delta_id: body.delta_id,
        prefix,
        source: delta.source,
        observed_at: delta.observedAt,
        records,
      });
      return { prefix, objectKey, ...metadata, recordCount: records.length };
    })));
  }
  const statements = [];
  for (const fragment of fragmentRows) {
    statements.push(env.LEDGER.prepare(
      `INSERT OR REPLACE INTO generation_fragments(
         generation_id, delta_id, prefix, object_key, object_sha256,
         object_bytes, record_count, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      body.generation_id,
      body.delta_id,
      fragment.prefix,
      fragment.objectKey,
      fragment.sha256,
      fragment.bytes,
      fragment.recordCount,
      now,
    ));
  }
  statements.push(env.LEDGER.prepare(
    `UPDATE catalog_deltas
     SET state = 'mapped', error = NULL, updated_at = ?
     WHERE delta_id = ? AND state = 'assigned'`,
  ).bind(now, body.delta_id));
  await env.LEDGER.batch(statements);
  await finishMappedGeneration(env, body.generation_id, now);
  return { state: "mapped", duplicate: false, fragments: fragmentRows.length };
}


export async function startReduce(env) {
  const generation = await env.LEDGER.prepare(
    `SELECT generation_id, state FROM catalog_generations
     WHERE state IN ('mapped', 'reducing') ORDER BY created_at LIMIT 1`,
  ).first();
  if (generation === null) return null;
  if (generation.state === "mapped") {
    await env.LEDGER.prepare(
      `UPDATE catalog_generations SET state = 'reducing', updated_at = ?
       WHERE generation_id = ? AND state = 'mapped'`,
    ).bind(new Date().toISOString(), generation.generation_id).run();
  }
  const rows = await env.LEDGER.prepare(
    `SELECT prefix FROM generation_partitions WHERE generation_id = ?
     AND (state = 'mapped' OR (state = 'reducing' AND lease_until < ?))
     ORDER BY prefix`,
  ).bind(generation.generation_id, new Date().toISOString()).all();
  for (const row of rows.results) {
    await env.COMPACTION_QUEUE.send({
      schema_version: REDUCE_JOB_SCHEMA_VERSION,
      generation_id: generation.generation_id,
      prefix: row.prefix,
    });
  }
  if (rows.results.length === 0) await finishCandidate(env, generation.generation_id);
  return { generationId: generation.generation_id, queued: rows.results.length };
}


async function finishCandidate(env, generationId) {
  const outstanding = await env.LEDGER.prepare(
    `SELECT count(*) AS count FROM generation_partitions
     WHERE generation_id = ? AND state != 'reduced'`,
  ).bind(generationId).first();
  if (Number(outstanding.count) === 0) await stageCandidateRoot(env, generationId);
}


export async function runReduce(env, rawBody) {
  const body = validateReduceJob(rawBody);
  const token = crypto.randomUUID();
  const now = new Date();
  const claim = await env.LEDGER.prepare(
    `UPDATE generation_partitions
     SET state = 'reducing', lease_token = ?, lease_until = ?, updated_at = ?
     WHERE generation_id = ? AND prefix = ?
       AND (state = 'mapped' OR (state = 'reducing' AND lease_until < ?))`,
  ).bind(
    token,
    new Date(now.valueOf() + 20 * 60 * 1000).toISOString(),
    now.toISOString(),
    body.generation_id,
    body.prefix,
    now.toISOString(),
  ).run();
  if (Number(claim.meta?.changes ?? 0) !== 1) {
    const row = await env.LEDGER.prepare(
      "SELECT state FROM generation_partitions WHERE generation_id = ? AND prefix = ?",
    ).bind(body.generation_id, body.prefix).first();
    if (row?.state === "reduced") {
      await finishCandidate(env, body.generation_id);
      return { state: "reduced", prefix: body.prefix, duplicate: true };
    }
    throw new Error("partition reducer is already running or unavailable");
  }
  try {
    await reducePartition(env, body.generation_id, body.prefix);
  } catch (error) {
    await env.LEDGER.prepare(
      `UPDATE generation_partitions
       SET state = 'mapped', lease_token = NULL, lease_until = NULL,
           error = ?, updated_at = ?
       WHERE generation_id = ? AND prefix = ? AND lease_token = ?`,
    ).bind(
      String(error).slice(0, 1000), new Date().toISOString(),
      body.generation_id, body.prefix, token,
    ).run();
    throw error;
  }
  await finishCandidate(env, body.generation_id);
  return { state: "reduced", prefix: body.prefix };
}


async function recordMapError(env, body, error) {
  if (typeof body?.delta_id !== "string") return;
  await env.LEDGER.prepare(
    `UPDATE catalog_deltas SET error = ?, updated_at = ?
     WHERE delta_id = ? AND state = 'assigned'`,
  ).bind(String(error).slice(0, 1000), new Date().toISOString(), body.delta_id).run();
}


export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response("ok");
    }
    if (request.method === "POST" && [
      "/admin/register-seed", "/admin/activate", "/admin/rollback",
    ].includes(url.pathname)) {
      if (!env.PUBLISH_TOKEN || request.headers.get("authorization") !== `Bearer ${env.PUBLISH_TOKEN}`) {
        return new Response("forbidden", { status: 403 });
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return Response.json({ detail: "invalid JSON" }, { status: 400 });
      }
      try {
        const result = url.pathname === "/admin/register-seed"
          ? await registerSeed(env, body?.generation_id)
          : url.pathname === "/admin/activate"
            ? await activateGeneration(env, body?.generation_id)
            : await rollbackGeneration(env, body?.generation_id);
        return Response.json(result);
      } catch (error) {
        return Response.json({ detail: String(error.message) }, { status: 409 });
      }
    }
    return Response.json({ detail: "not found" }, { status: 404 });
  },

  async scheduled(_controller, env) {
    if (env.REGISTRATION_ONLY === "true") return;
    await startGeneration(env);
    await startReduce(env);
  },

  async queue(batch, env) {
    for (const message of batch.messages) {
      try {
        if (
          env.REGISTRATION_ONLY === "true" &&
          message.body?.schema_version !== DELTA_READY_SCHEMA_VERSION
        ) {
          throw new Error("registration-only consumer refuses generation work");
        }
        if (message.body?.schema_version === DELTA_READY_SCHEMA_VERSION) {
          await registerDelta(env, message.body);
        } else if (message.body?.schema_version === MAP_JOB_SCHEMA_VERSION) {
          await mapDelta(env, message.body);
        } else if (message.body?.schema_version === REDUCE_JOB_SCHEMA_VERSION) {
          await runReduce(env, message.body);
        } else {
          throw new Error("compaction queue message has an unknown schema");
        }
        message.ack();
      } catch (error) {
        console.error("compaction queue message failed", String(error).slice(0, 300));
        await recordMapError(env, message.body, error);
        message.retry({ delaySeconds: 60 });
      }
    }
  },
};
