import {
  apexForHostname,
  normalizeApex,
} from "../../index-worker/src/domain-policy.js";


const SOURCES = Object.freeze({
  "iana-root": "https://www.internic.net/domain/root.zone",
  "cisa-gov": "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv",
});
const MAX_SOURCE_BYTES = 8 * 1024 * 1024;
const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const encoder = new TextEncoder();


async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}


async function gzipJson(value) {
  const stream = new Blob([JSON.stringify(value)])
    .stream()
    .pipeThrough(new CompressionStream("gzip"));
  return await new Response(stream).arrayBuffer();
}


export async function boundedBody(response, maxBytes = MAX_SOURCE_BYTES) {
  const length = response.headers.get("content-length");
  if (length !== null && Number(length) > maxBytes) {
    throw new Error("public source exceeds the size limit");
  }
  if (response.body === null) throw new Error("public source has no body");
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      size += part.value.byteLength;
      if (size > maxBytes) throw new Error("public source exceeds the size limit");
      chunks.push(part.value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  }
  if (size === 0) throw new Error("public source is empty");
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}


export function rootTlds(text) {
  const tlds = new Set();
  for (const line of text.split(/\r?\n/)) {
    const match = /^([a-z0-9-]+)\.\s+\d+\s+IN\s+NS\s+/i.exec(line);
    if (match !== null) tlds.add(match[1].toLowerCase());
  }
  if (tlds.size < 1000) throw new Error("IANA root zone has too few TLDs");
  return [...tlds].sort();
}


export function govRecords(text) {
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/);
  if (!/^Domain name,/.test(lines.shift() ?? "")) {
    throw new Error("CISA domain CSV header is invalid");
  }
  const records = new Map();
  for (const line of lines) {
    const raw = line.split(",", 1)[0].trim().toLowerCase();
    if (!raw.endsWith(".gov")) continue;
    try {
      const apex = normalizeApex(raw);
      if (apexForHostname(apex) !== apex) continue;
      records.set(apex, { apex, hostname: apex, first_seen: null });
    } catch {
      // An invalid row does not invalidate the official CSV snapshot.
    }
  }
  if (records.size < 1000) throw new Error("CISA domain CSV has too few valid domains");
  return [...records.values()].sort((left, right) => left.apex.localeCompare(right.apex));
}


async function claim(env, sourceId, now) {
  const nowIso = now.toISOString();
  const leasedUntil = new Date(now.valueOf() + 15 * 60 * 1000).toISOString();
  const result = await env.CONTROL.prepare(
    `UPDATE public_source_state SET lease_until = ?, error = NULL
     WHERE source_id = ? AND next_run_at <= ?
       AND (lease_until IS NULL OR lease_until < ?)`,
  ).bind(leasedUntil, sourceId, nowIso, nowIso).run();
  if (Number(result.meta?.changes ?? 0) !== 1) return null;
  return await env.CONTROL.prepare(
    "SELECT digest, etag, object_key FROM public_source_state WHERE source_id = ?",
  ).bind(sourceId).first();
}


async function complete(env, sourceId, now, digest, etag, objectKey) {
  await env.CONTROL.prepare(
    `UPDATE public_source_state
     SET digest = ?, etag = ?, object_key = ?, checked_at = ?,
         next_run_at = ?, lease_until = NULL, error = NULL
     WHERE source_id = ?`,
  ).bind(
    digest, etag, objectKey, now.toISOString(),
    new Date(now.valueOf() + DAY_MS).toISOString(), sourceId,
  ).run();
}


async function fail(env, sourceId, now, error) {
  await env.CONTROL.prepare(
    `UPDATE public_source_state
     SET next_run_at = ?, lease_until = NULL, error = ? WHERE source_id = ?`,
  ).bind(
    new Date(now.valueOf() + HOUR_MS).toISOString(),
    String(error).slice(0, 500), sourceId,
  ).run();
}


async function confirmExisting(env, sourceId, objectKey) {
  if (typeof objectKey !== "string" || await env.CATALOG.head(objectKey) === null) {
    throw new Error(`${sourceId} snapshot is missing from R2`);
  }
  if (sourceId === "cisa-gov") {
    const match = /^ingest\/public-bulk\/cisa-gov\/([a-f0-9]{64})\.json\.gz$/.exec(objectKey);
    if (match === null) throw new Error("CISA delta key is invalid");
    await env.COMPACTION_QUEUE.send({
      schema_version: "subfinder.delta-ready.v1",
      delta_id: match[1],
      source_kind: "public-bulk",
      object_key: objectKey,
    });
  }
}


async function refreshOne(env, sourceId, now) {
  const state = await claim(env, sourceId, now);
  if (state === null) return "not-due";
  try {
    const headers = { "user-agent": "subfinder-public-sources/1.0" };
    if (state.etag) headers["if-none-match"] = state.etag;
    const fetchSource = env.PUBLIC_FETCHER?.fetch.bind(env.PUBLIC_FETCHER)
      ?? globalThis.fetch.bind(globalThis);
    const response = await fetchSource(SOURCES[sourceId], {
      headers,
      redirect: "manual",
    });
    if (response.status === 304 && state.digest) {
      await confirmExisting(env, sourceId, state.object_key);
      await complete(env, sourceId, now, state.digest, state.etag, state.object_key);
      return "unchanged";
    }
    if (!response.ok) throw new Error(`${sourceId} returned HTTP ${response.status}`);
    const bytes = await boundedBody(response);
    const digest = await sha256(bytes);
    const etag = response.headers.get("etag");
    if (digest === state.digest) {
      await confirmExisting(env, sourceId, state.object_key);
      await complete(env, sourceId, now, digest, etag, state.object_key);
      return "unchanged";
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (sourceId === "iana-root") {
      const tlds = rootTlds(text);
      const objectKey = `metadata/iana-root/${digest}.json.gz`;
      if (await env.CATALOG.head(objectKey) === null) {
        await env.CATALOG.put(objectKey, await gzipJson({
          schema_version: "subfinder.root-tlds.v1",
          source: SOURCES[sourceId],
          tlds,
        }));
      }
      await complete(env, sourceId, now, digest, etag, objectKey);
      return "updated";
    }
    const records = govRecords(text);
    const deltaId = await sha256(encoder.encode(`${sourceId}:${digest}`));
    const objectKey = `ingest/public-bulk/${sourceId}/${deltaId}.json.gz`;
    if (await env.CATALOG.head(objectKey) === null) {
      await env.CATALOG.put(objectKey, await gzipJson({
        schema_version: "subfinder.ingest-delta.v1",
        source: "gov:cisagov",
        source_id: sourceId,
        created_at: now.toISOString(),
        hostname_count: records.length,
        records,
      }));
    }
    await env.COMPACTION_QUEUE.send({
      schema_version: "subfinder.delta-ready.v1",
      delta_id: deltaId,
      source_kind: "public-bulk",
      object_key: objectKey,
    });
    await complete(env, sourceId, now, digest, etag, objectKey);
    return "updated";
  } catch (error) {
    await fail(env, sourceId, now, error);
    throw error;
  }
}


export async function refreshPublicSources(env, now = new Date()) {
  if (env.PUBLIC_SOURCES_ENABLED !== "1") return [];
  const results = await Promise.allSettled(
    Object.keys(SOURCES).map((sourceId) => refreshOne(env, sourceId, now)),
  );
  const errors = results.filter((result) => result.status === "rejected");
  if (errors.length > 0) throw new AggregateError(
    errors.map((result) => result.reason), "public source refresh failed",
  );
  return results.map((result) => result.value);
}
