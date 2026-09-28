import {
  DOMAIN_POLICY_VERSION,
  PSL_SHA256,
  normalizeApex,
} from "./domain-policy.js";
import {
  McpServer,
  createMcpHandler,
  hostHeaderValidationResponse,
  originValidationResponse,
} from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { clientIdentity, requireClient } from "./client-auth.js";
import { QuotaLedger as BaseQuotaLedger, admitQuota, quotaHeaders, subjectShard, utcWindow } from "./quota-ledger.js";


const FORMAT = "subfinder.r2-index.v2";
const RECORDS_SCHEMA_VERSION = "subfinder.index-records.v1";
const BATCH_RECORDS_SCHEMA_VERSION = "subfinder.internal-index-records-batch.v1";
const QUEUED_BATCH_SCHEMA_VERSION = "subfinder.internal-record-batch.v1";
const QUEUED_SLICE_SCHEMA_VERSION = "subfinder.internal-record-batch-slice.v1";
const INTERNAL_REQUEST_MAX_BYTES = 512 * 1024;
const QUEUED_REQUEST_MAX_BYTES = 8 * 1024 * 1024;
const QUEUED_APEXES_PER_ROW = 100;
const QUEUED_SLICE_APEXES = 25;
const QUEUED_SLICE_MAX_RECORDS = 5000;
const QUEUED_SLICE_MAX_BYTES = 2 * 1024 * 1024;
const QUEUED_DOCUMENT_PART_CHARS = 400000;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new Error("limit configuration must be a positive integer");
  }
  return parsed;
}

function csvValues(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function jsonResponse(value, status = 200, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

function errorResponse(status, detail, headers = {}) {
  return jsonResponse(
    { detail },
    status,
    { "cache-control": "no-store", ...headers },
  );
}

export async function docsPage(request, env, url, upstreamFetch = fetch) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return errorResponse(405, "method not allowed");
  }
  if (url.pathname === "/docs") {
    return Response.redirect(`${url.origin}/docs/${url.search}`, 308);
  }
  const upstream = new URL(env.DOCS_ORIGIN);
  upstream.pathname = url.pathname.slice("/docs".length);
  upstream.search = url.search;
  const headers = new Headers();
  for (const name of ["accept", "if-none-match", "if-modified-since", "range"]) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  const response = await upstreamFetch(upstream, { method: request.method, headers });
  const returnedHeaders = new Headers(response.headers);
  returnedHeaders.delete("set-cookie");
  returnedHeaders.delete("x-robots-tag");
  if (url.hostname === "subfinder.pundit.workers.dev") {
    returnedHeaders.set("x-robots-tag", "noindex");
  }
  const versionedAsset = /^\/docs\/assets\/.*\.[A-Za-z0-9_-]{8,}\.(?:lean\.)?(?:js|css|woff2?)$/;
  if (response.ok && versionedAsset.test(url.pathname)) {
    returnedHeaders.set("cache-control", "public, max-age=31536000, immutable");
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: returnedHeaders,
  });
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Hex(bytes) {
  return bytesToHex(await crypto.subtle.digest("SHA-256", bytes));
}

async function partitionPrefix(apex, nibbles) {
  return (await sha256Hex(encoder.encode(apex))).slice(0, nibbles);
}

async function gunzipText(bytes) {
  const stream = new Blob([bytes])
    .stream()
    .pipeThrough(new DecompressionStream("gzip"));
  return await new Response(stream).text();
}

async function objectBytes(bucket, key, range) {
  const object = await bucket.get(key, range ? { range } : undefined);
  if (object === null || !("body" in object)) {
    throw new Error(`catalog object is unavailable: ${key}`);
  }
  return await object.arrayBuffer();
}

async function checkedBytes(bucket, key, metadata) {
  const bytes = await objectBytes(bucket, key, {
    offset: Number(metadata.offset),
    length: Number(metadata.length),
  });
  if ((await sha256Hex(bytes)) !== metadata.sha256) {
    throw new Error("catalog block checksum mismatch");
  }
  return bytes;
}

async function loadRoot(env) {
  const key = env.CATALOG_ROOT_KEY || "catalog/root.json";
  const root = JSON.parse(decoder.decode(await objectBytes(env.CATALOG, key)));
  if (root.format !== FORMAT) {
    throw new Error("catalog root format is unsupported");
  }
  if (
    root.domain_policy_version !== DOMAIN_POLICY_VERSION ||
    root.psl_sha256 !== PSL_SHA256
  ) {
    throw new Error("catalog domain policy is unsupported");
  }
  return root;
}

async function loadPartition(env, root, prefix) {
  const metadata = root.partitions[prefix];
  if (metadata === undefined) return null;
  const bytes = await objectBytes(env.CATALOG, metadata.index);
  if ((await sha256Hex(bytes)) !== metadata.index_sha256) {
    throw new Error("partition index checksum mismatch");
  }
  const index = JSON.parse(await gunzipText(bytes));
  if (
    index.format !== FORMAT ||
    index.generation !== (metadata.origin_generation ?? root.generation) ||
    index.prefix !== prefix
  ) {
    throw new Error("partition index identity mismatch");
  }
  return { index, metadata };
}

function findRegularBlock(blocks, apex) {
  let low = 0;
  let high = blocks.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (blocks[middle].first_apex <= apex) low = middle + 1;
    else high = middle;
  }
  const position = low - 1;
  if (position < 0 || apex > blocks[position].last_apex) return null;
  return blocks[position];
}

async function readDocuments(bucket, bundle, metadata) {
  const bytes = await checkedBytes(bucket, bundle, metadata);
  const text = await gunzipText(bytes);
  return text
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

async function locateApex(env, apex, activeRoot = null) {
  const root = activeRoot ?? await loadRoot(env);
  const prefix = await partitionPrefix(apex, root.partition_nibbles);
  const partition = await loadPartition(env, root, prefix);
  if (partition === null) return { root, apex, total: 0, dated: 0, chunks: [] };
  const overflow = partition.index.overflow[apex];
  if (overflow !== undefined) {
    return {
      root,
      apex,
      total: Number(overflow.total),
      dated: Number(overflow.dated),
      bundle: partition.metadata.bundle,
      chunks: overflow.chunks,
    };
  }
  const block = findRegularBlock(partition.index.blocks, apex);
  if (block === null) return { root, apex, total: 0, dated: 0, chunks: [] };
  const documents = await readDocuments(
    env.CATALOG,
    partition.metadata.bundle,
    block,
  );
  const document = documents.find((value) => value.a === apex);
  if (document === undefined) {
    return { root, apex, total: 0, dated: 0, chunks: [] };
  }
  return {
    root,
    apex,
    total: Number(document.t),
    dated: Number(document.d),
    records: document.r,
    chunks: [],
  };
}

async function* apexRecords(env, located) {
  if (located.records !== undefined) {
    yield* located.records;
    return;
  }
  for (const chunk of located.chunks) {
    const documents = await readDocuments(env.CATALOG, located.bundle, chunk);
    for (const record of documents[0].r) yield record;
  }
}

function cursorKey(firstSeen, hostname) {
  return [firstSeen === null ? 1 : 0, firstSeen || "", hostname];
}

function compareKeys(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] < right[index]) return -1;
    if (left[index] > right[index]) return 1;
  }
  return 0;
}

function encodeBase64Url(value) {
  const bytes = encoder.encode(value);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function decodeBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return decoder.decode(Uint8Array.from(binary, (character) => character.charCodeAt(0)));
}

function encodeCursor(apex, record) {
  return encodeBase64Url(JSON.stringify([apex, record.f, record.h]));
}

function decodeCursor(apex, value) {
  if (value.length > 2048) throw new Error("cursor is invalid");
  let payload;
  try {
    payload = JSON.parse(decodeBase64Url(value));
  } catch {
    throw new Error("cursor is invalid");
  }
  if (
    !Array.isArray(payload) ||
    payload.length !== 3 ||
    payload[0] !== apex ||
    (payload[1] !== null && typeof payload[1] !== "string") ||
    typeof payload[2] !== "string"
  ) {
    throw new Error("cursor is invalid");
  }
  return cursorKey(payload[1], payload[2]);
}

async function pageRecords(env, located, after, limit) {
  const records = [];
  for await (const record of apexRecords(env, located)) {
    if (after !== null && compareKeys(cursorKey(record.f, record.h), after) <= 0) {
      continue;
    }
    records.push(record);
    if (records.length > limit) break;
  }
  return records;
}

function searchValue(record, dates) {
  return dates
    ? { first_seen: record.f, sub: record.h }
    : { sub: record.h };
}

function formatSearchPage(records, format, dates) {
  if (format === "json") {
    return JSON.stringify(records.map((record) => searchValue(record, dates)));
  }
  return records
    .map((record) => (dates ? `${record.h}\t${record.f || ""}\n` : `${record.h}\n`))
    .join("");
}

function searchStream(iterator, format, dates) {
  let first = true;
  let opened = false;
  return new ReadableStream({
    async pull(controller) {
      try {
        if (format === "json" && !opened) {
          opened = true;
          controller.enqueue(encoder.encode("["));
          return;
        }
        const item = await iterator.next();
        if (item.done) {
          if (format === "json") controller.enqueue(encoder.encode("]"));
          controller.close();
          return;
        }
        let value;
        if (format === "json") {
          value = `${first ? "" : ","}${JSON.stringify(searchValue(item.value, dates))}`;
        } else if (dates) {
          value = `${item.value.h}\t${item.value.f || ""}\n`;
        } else {
          value = `${item.value.h}\n`;
        }
        first = false;
        controller.enqueue(encoder.encode(value));
      } catch (error) {
        controller.error(error);
      }
    },
  });
}

function sourceRecord(source) {
  return { source: source.n, first_seen: source.f, last_seen: source.l };
}

function hostnameRecord(record) {
  return {
    hostname: record.h,
    first_seen: record.f,
    sources: record.s.map(sourceRecord),
  };
}

function recordsStream(apex, iterator) {
  let first = true;
  let opened = false;
  return new ReadableStream({
    async pull(controller) {
      try {
        if (!opened) {
          opened = true;
          controller.enqueue(
            encoder.encode(
              `{"schema_version":"${RECORDS_SCHEMA_VERSION}","apex":${JSON.stringify(apex)},"records":[`,
            ),
          );
          return;
        }
        const item = await iterator.next();
        if (item.done) {
          controller.enqueue(encoder.encode("]}"));
          controller.close();
          return;
        }
        controller.enqueue(
          encoder.encode(
            `${first ? "" : ","}${JSON.stringify(hostnameRecord(item.value))}`,
          ),
        );
        first = false;
      } catch (error) {
        controller.error(error);
      }
    },
  });
}

async function search(request, env, url) {
  const value = url.searchParams.get("apex");
  if (value === null) return errorResponse(422, "apex is required");
  let apex;
  try {
    apex = normalizeApex(value);
  } catch (error) {
    return errorResponse(400, error.message);
  }
  const identity = await clientIdentity(request, env);
  const quota = await admitQuota(env, identity);
  const format = url.searchParams.get("format") || "text";
  if (!new Set(["text", "json"]).has(format)) {
    return errorResponse(422, "format must be text or json");
  }
  const datesValue = url.searchParams.get("dates") || "0";
  if (!new Set(["0", "1"]).has(datesValue)) {
    return errorResponse(422, "dates must be 0 or 1");
  }
  const dates = datesValue === "1";
  const limitValue = url.searchParams.get("limit");
  const cursorValue = url.searchParams.get("cursor");
  if (cursorValue !== null && limitValue === null) {
    return errorResponse(400, "cursor requires limit");
  }
  let limit = null;
  if (limitValue !== null) {
    limit = Number(limitValue);
    if (!Number.isInteger(limit) || limit < 1 || limit > 5000) {
      return errorResponse(422, "limit must be between 1 and 5000");
    }
  }
  let after = null;
  if (cursorValue !== null) {
    try {
      after = decodeCursor(apex, cursorValue);
    } catch (error) {
      return errorResponse(400, error.message);
    }
  }
  const located = await locateApex(env, apex);
  const headers = new Headers({
    "cache-control": "no-store",
    "content-type": format === "json" ? "application/json" : "text/plain",
    "x-result-total": String(located.total),
    "x-result-dated-total": String(located.dated),
    "x-subfinder-data-spike": FORMAT,
    ...quotaHeaders(quota),
  });
  if (limit !== null) {
    const records = await pageRecords(env, located, after, limit);
    const truncated = records.length > limit;
    const page = records.slice(0, limit);
    headers.set("x-result-page-size", String(page.length));
    headers.set("x-result-truncated", String(truncated));
    if (truncated && page.length > 0) {
      const cursor = encodeCursor(apex, page.at(-1));
      headers.set("x-next-cursor", cursor);
      const next = new URL(request.url);
      next.searchParams.set("cursor", cursor);
      headers.set("link", `<${next.toString()}>; rel="next"`);
    }
    return new Response(formatSearchPage(page, format, dates), { headers });
  }
  headers.set("x-result-truncated", "false");
  return new Response(searchStream(apexRecords(env, located), format, dates), {
    headers,
  });
}

async function records(request, env, url) {
  const value = url.searchParams.get("apex");
  if (value === null) return errorResponse(422, "apex is required");
  let apex;
  try {
    apex = normalizeApex(value);
  } catch (error) {
    return errorResponse(400, error.message);
  }
  const identity = await clientIdentity(request, env);
  const quota = await admitQuota(env, identity);
  const located = await locateApex(env, apex);
  return new Response(recordsStream(apex, apexRecords(env, located)), {
    headers: {
      "cache-control": "no-cache",
      "content-type": "application/json",
      "x-subfinder-schema-version": RECORDS_SCHEMA_VERSION,
      "x-subfinder-data-spike": FORMAT,
      ...quotaHeaders(quota),
    },
  });
}

async function internalBatch(request, env) {
  const identity = await requireClient(request, env);
  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (declaredLength > INTERNAL_REQUEST_MAX_BYTES) {
    return errorResponse(413, "request body is too large");
  }
  const text = await request.text();
  if (encoder.encode(text).byteLength > INTERNAL_REQUEST_MAX_BYTES) {
    return errorResponse(413, "request body is too large");
  }
  let input;
  try {
    input = JSON.parse(text);
  } catch {
    return errorResponse(400, "request body must be valid JSON");
  }
  if (!Array.isArray(input?.apexes) || input.apexes.length === 0) {
    return errorResponse(400, "apexes must not be empty");
  }
  const maxApexes = positiveInteger(env.BATCH_MAX_APEXES, 100);
  if (input.apexes.length > maxApexes) {
    return errorResponse(
      413,
      `batch contains too many apexes; maximum is ${maxApexes}`,
    );
  }
  let apexes;
  try {
    apexes = input.apexes.map(normalizeApex);
  } catch (error) {
    return errorResponse(400, error.message);
  }
  if (new Set(apexes).size !== apexes.length) {
    return errorResponse(400, "apexes must be unique");
  }

  const maxRecords = positiveInteger(env.BATCH_MAX_RECORDS, 5000);
  let recordCount = 0;
  const results = [];
  for (const apex of apexes) {
    const located = await locateApex(env, apex);
    const records = [];
    for await (const record of apexRecords(env, located)) {
      recordCount += 1;
      if (recordCount > maxRecords) {
        return errorResponse(
          413,
          `batch contains ${recordCount} hostnames; maximum is ${maxRecords}; split the request`,
        );
      }
      records.push(hostnameRecord(record));
    }
    results.push({ schema_version: RECORDS_SCHEMA_VERSION, apex, records });
  }

  const quota = await admitQuota(env, identity, apexes.length);
  const requestId = [...crypto.getRandomValues(new Uint8Array(8))]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return jsonResponse(
    { schema_version: BATCH_RECORDS_SCHEMA_VERSION, results },
    200,
    {
      "cache-control": "no-store",
      "x-batch-apex-count": String(apexes.length),
      "x-request-id": requestId,
      "x-subfinder-schema-version": BATCH_RECORDS_SCHEMA_VERSION,
      ...quotaHeaders(quota),
    },
  );
}

function batchJobDocument(job) {
  const total = Number(job.total_apexes);
  const completed = Number(job.completed_apexes);
  const reserved = Number(job.reserved_units);
  const committed = Number(job.committed_units);
  const released = Number(job.released_units);
  const path = `/internal/v1/record-batches/${job.job_id}`;
  return {
    schema_version: QUEUED_BATCH_SCHEMA_VERSION,
    job_id: job.job_id,
    state: job.state,
    total_apexes: total,
    completed_apexes: completed,
    failed_apexes: Number(job.failed_apexes),
    queued_apexes: ["queued", "running"].includes(job.state)
      ? Math.max(0, total - completed) : 0,
    next_sequence: Number(job.next_sequence),
    cancel_requested: Boolean(job.cancel_requested),
    quota: {
      reserved, committed, released,
      outstanding: Math.max(0, reserved - committed - released),
    },
    created_at: job.created_at,
    updated_at: job.updated_at,
    error: job.error,
    links: { self: path, chunks: `${path}/chunks`, cancel: `${path}/cancel` },
  };
}

async function boundedJson(request, maxBytes) {
  const declared = Number(request.headers.get("content-length") || 0);
  if (declared > maxBytes) return { error: errorResponse(413, "request body is too large") };
  const reader = request.body?.getReader();
  if (reader === undefined) return { error: errorResponse(400, "request body must be valid JSON") };
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel();
      return { error: errorResponse(413, "request body is too large") };
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return { value: JSON.parse(decoder.decode(bytes)) };
  } catch {
    return { error: errorResponse(400, "request body must be valid JSON") };
  }
}

async function batchLedger(env, identity, path, body) {
  const id = env.QUOTA_LEDGER.idFromName(await subjectShard(identity.subject));
  return await env.QUOTA_LEDGER.get(id).fetch(`https://quota${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ subject: identity.subject, limit: identity.limit, ...body }),
  });
}

async function queuedBatch(request, env, url) {
  const identity = await requireClient(request, env);
  const base = "/internal/v1/record-batches";
  if (request.method === "POST" && url.pathname === base) {
    const parsed = await boundedJson(request, QUEUED_REQUEST_MAX_BYTES);
    if (parsed.error) return parsed.error;
    const input = parsed.value;
    if (!Array.isArray(input?.apexes) || input.apexes.length === 0) {
      return errorResponse(400, "apexes must not be empty");
    }
    const maxApexes = positiveInteger(env.QUEUED_BATCH_MAX_APEXES, 25000);
    if (input.apexes.length > maxApexes) {
      return errorResponse(413, `batch contains too many apexes; maximum is ${maxApexes}`);
    }
    let apexes;
    try {
      apexes = input.apexes.map(normalizeApex);
    } catch (error) {
      return errorResponse(400, error.message);
    }
    if (new Set(apexes).size !== apexes.length) {
      return errorResponse(400, "apexes must be unique");
    }
    const key = request.headers.get("idempotency-key")?.trim() ?? "";
    if (!key || key.length > 128) {
      return errorResponse(400, "Idempotency-Key is required and must be at most 128 characters");
    }
    const root = await loadRoot(env);
    return await batchLedger(env, identity, "/batch/submit", { apexes, key, root });
  }
  const match = url.pathname.match(/^\/internal\/v1\/record-batches\/([A-Za-z0-9_-]{1,128})(?:\/(chunks|cancel))?$/);
  if (!match) return errorResponse(404, "record batch not found");
  const [, jobId, action] = match;
  if (request.method === "GET" && action === "chunks") {
    const after = Number(url.searchParams.get("after") ?? -1);
    const limit = Number(url.searchParams.get("limit") ?? 10);
    const wait = Number(url.searchParams.get("wait") ?? 0);
    if (!Number.isSafeInteger(after) || after < -1 ||
        !Number.isSafeInteger(limit) || limit < 1 || limit > 50 ||
        !Number.isFinite(wait) || wait < 0 || wait > 20) {
      return errorResponse(422, "invalid batch cursor, limit, or wait");
    }
    const deadline = Date.now() + wait * 1000;
    for (;;) {
      const response = await batchLedger(env, identity, "/batch/chunks", {
        jobId, after, limit,
      });
      if (!response.ok || wait === 0) return response;
      const payload = await response.clone().json();
      if (payload.chunks.length || ["done", "failed", "cancelled"].includes(payload.job.state) ||
          Date.now() >= deadline) return response;
      await new Promise((resolve) => setTimeout(resolve, Math.min(200, deadline - Date.now())));
    }
  }
  if (request.method === "GET" && action === undefined) {
    return await batchLedger(env, identity, "/batch/status", { jobId });
  }
  if (request.method === "POST" && action === "cancel") {
    return await batchLedger(env, identity, "/batch/cancel", { jobId });
  }
  return errorResponse(405, "method not allowed");
}

async function mcpSearch(env, identity, value) {
  const apex = normalizeApex(value);
  await admitQuota(env, identity);
  const located = await locateApex(env, apex);
  const limit = positiveInteger(env.MCP_RESULT_LIMIT, 100000);
  const result = [];
  for await (const record of apexRecords(env, located)) {
    if (result.length >= limit) {
      throw new Error("result exceeds the MCP result limit; use the HTTP API");
    }
    result.push(record.h);
  }
  return result;
}

async function mcp(request, env) {
  const allowedHosts = csvValues(env.MCP_ALLOWED_HOSTS);
  if (allowedHosts.length === 0) {
    return errorResponse(503, "MCP_ALLOWED_HOSTS is not configured");
  }
  const rejected = hostHeaderValidationResponse(request, allowedHosts) ??
    originValidationResponse(request, csvValues(env.MCP_ALLOWED_ORIGINS));
  if (rejected !== undefined) return rejected;

  const identity = await clientIdentity(request, env);
  const handler = createMcpHandler(() => {
    const server = new McpServer(
      { name: "Subfinder", version: "1.0.0" },
      {
        instructions: (
          "Read the committed passive subdomain index by registrable apex."
        ),
      },
    );
    server.registerTool(
      "search",
      {
        description: "Return indexed hostnames for one registrable apex.",
        inputSchema: z.object({ apex: z.string() }),
      },
      async ({ apex }) => {
        const result = await mcpSearch(env, identity, apex);
        const structuredContent = { result };
        return {
          content: [{ type: "text", text: JSON.stringify(structuredContent) }],
          structuredContent,
        };
      },
    );
    return server;
  }, {
    maxRequestBodySize: 1024 * 1024,
  });
  return await handler.fetch(request);
}

async function stats(env) {
  const root = await loadRoot(env);
  return jsonResponse(
    { ...root.stats, ingest_jobs: {} },
    200,
    { "cache-control": "no-cache", "x-subfinder-data-spike": FORMAT },
  );
}

export class QuotaLedger extends BaseQuotaLedger {
  constructor(ctx, env) {
    super(ctx);
    this.env = env;
    ctx.blockConcurrencyWhile(() => {
      this.sql.exec(`
        CREATE TABLE IF NOT EXISTS record_batch_jobs (
          job_id TEXT PRIMARY KEY,
          subject TEXT NOT NULL,
          idempotency_key TEXT NOT NULL,
          request_sha256 TEXT NOT NULL,
          root_json TEXT NOT NULL,
          quota_day TEXT NOT NULL,
          state TEXT NOT NULL,
          total_apexes INTEGER NOT NULL,
          completed_apexes INTEGER NOT NULL DEFAULT 0,
          failed_apexes INTEGER NOT NULL DEFAULT 0,
          next_position INTEGER NOT NULL DEFAULT 0,
          next_sequence INTEGER NOT NULL DEFAULT 0,
          reserved_units INTEGER NOT NULL,
          committed_units INTEGER NOT NULL DEFAULT 0,
          released_units INTEGER NOT NULL DEFAULT 0,
          cancel_requested INTEGER NOT NULL DEFAULT 0,
          failures INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          error TEXT,
          UNIQUE(subject, idempotency_key)
        );
        CREATE TABLE IF NOT EXISTS record_batch_apexes (
          job_id TEXT NOT NULL,
          chunk_index INTEGER NOT NULL,
          apexes TEXT NOT NULL,
          PRIMARY KEY(job_id, chunk_index)
        );
        CREATE TABLE IF NOT EXISTS record_batch_chunks (
          job_id TEXT NOT NULL,
          sequence INTEGER NOT NULL,
          part INTEGER NOT NULL,
          document TEXT NOT NULL,
          PRIMARY KEY(job_id, sequence, part)
        );
      `);
    });
  }

  job(jobId, subject) {
    return this.sql.exec(
      "SELECT * FROM record_batch_jobs WHERE job_id = ? AND subject = ?",
      jobId, subject,
    ).toArray()[0] ?? null;
  }

  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (!path.startsWith("/batch/")) return await super.fetch(request);
    if (request.method !== "POST") return errorResponse(405, "method not allowed");
    let input;
    try {
      input = await request.json();
    } catch {
      return errorResponse(400, "invalid batch request");
    }
    const { subject } = input;
    if (typeof subject !== "string" || !subject.startsWith("token:") ||
        subject.length > 160) return errorResponse(400, "invalid batch subject");
    if (path === "/batch/submit") return await this.submit(input);
    const job = this.job(input.jobId, subject);
    if (job === null) return errorResponse(404, "record batch not found");
    if (path === "/batch/status") return jsonResponse(batchJobDocument(job), 200,
      { "cache-control": "no-store" });
    if (path === "/batch/chunks") {
      const sequences = this.sql.exec(
        `SELECT DISTINCT sequence FROM record_batch_chunks
         WHERE job_id = ? AND sequence > ? ORDER BY sequence LIMIT ?`,
        job.job_id, input.after, input.limit,
      ).toArray();
      const chunks = sequences.map((row) => {
        const parts = this.sql.exec(
          `SELECT document FROM record_batch_chunks WHERE job_id = ? AND sequence = ?
           ORDER BY part`, job.job_id, row.sequence,
        ).toArray();
        return { sequence: Number(row.sequence),
          ...JSON.parse(parts.map((part) => part.document).join("")) };
      });
      if (chunks.length === 0 && ["queued", "running"].includes(job.state) &&
          await this.ctx.storage.getAlarm() === null) {
        await this.ctx.storage.setAlarm(Date.now() + 100);
      }
      return jsonResponse({
        schema_version: QUEUED_SLICE_SCHEMA_VERSION,
        job: batchJobDocument(job),
        after: input.after,
        next_cursor: chunks.length ? chunks.at(-1).sequence : input.after,
        chunks,
      }, 200, { "cache-control": "no-store" });
    }
    if (path === "/batch/cancel") {
      const updated = this.ctx.storage.transactionSync(() => {
        const current = this.job(job.job_id, subject);
        if (!["queued", "running"].includes(current.state)) return current;
        const outstanding = Number(current.reserved_units) -
          Number(current.committed_units) - Number(current.released_units);
        this.sql.exec(
          "UPDATE request_counts SET used = max(0, used - ?) WHERE day = ? AND subject = ?",
          outstanding, current.quota_day, subject,
        );
        this.sql.exec(
          `UPDATE record_batch_jobs SET state = 'cancelled', cancel_requested = 1,
           released_units = released_units + ?, updated_at = ? WHERE job_id = ?`,
          outstanding, new Date().toISOString(), current.job_id,
        );
        return this.job(current.job_id, subject);
      });
      return jsonResponse(batchJobDocument(updated), 200, { "cache-control": "no-store" });
    }
    return errorResponse(404, "not found");
  }

  async submit(input) {
    const { subject, key, apexes, root } = input;
    const limit = Number(input.limit);
    if (!Array.isArray(apexes) || apexes.length < 1 ||
        apexes.length > positiveInteger(this.env.QUEUED_BATCH_MAX_APEXES, 25000) ||
        typeof key !== "string" || !key || key.length > 128 ||
        !Number.isSafeInteger(limit) || limit < 1 ||
        root?.format !== FORMAT || root.domain_policy_version !== DOMAIN_POLICY_VERSION ||
        root.psl_sha256 !== PSL_SHA256) {
      return errorResponse(400, "invalid batch admission");
    }
    const hash = await sha256Hex(encoder.encode(JSON.stringify(apexes)));
    const { day, resetAt } = utcWindow();
    const now = new Date().toISOString();
    const jobId = crypto.randomUUID().replaceAll("-", "");
    const outcome = this.ctx.storage.transactionSync(() => {
      const existing = this.sql.exec(
        "SELECT * FROM record_batch_jobs WHERE subject = ? AND idempotency_key = ?",
        subject, key,
      ).toArray()[0];
      if (existing) {
        if (existing.request_sha256 !== hash) return { status: 409 };
        return { job: existing, replay: true };
      }
      const pending = this.sql.exec(
        `SELECT COUNT(*) AS total,
         SUM(CASE WHEN subject = ? THEN 1 ELSE 0 END) AS subject_total
         FROM record_batch_jobs WHERE state IN ('queued', 'running')`, subject,
      ).toArray()[0];
      if (Number(pending.total) >= positiveInteger(this.env.QUEUED_BATCH_MAX_PENDING, 128) ||
          Number(pending.subject_total ?? 0) >= positiveInteger(
            this.env.QUEUED_BATCH_MAX_PENDING_PER_TOKEN, 16)) {
        return { status: 503 };
      }
      const used = Number(this.sql.exec(
        "SELECT used FROM request_counts WHERE day = ? AND subject = ?",
        day, subject,
      ).toArray()[0]?.used ?? 0);
      if (used + apexes.length > limit) return { status: 429, used };
      this.sql.exec(
        `INSERT INTO request_counts(day, subject, used) VALUES (?, ?, ?)
         ON CONFLICT(day, subject) DO UPDATE SET used = excluded.used`,
        day, subject, used + apexes.length,
      );
      this.sql.exec(
        `INSERT INTO record_batch_jobs
         (job_id, subject, idempotency_key, request_sha256, root_json, quota_day, state,
          total_apexes, reserved_units, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)`,
        jobId, subject, key, hash, JSON.stringify(root), day,
        apexes.length, apexes.length, now, now,
      );
      for (let index = 0; index < apexes.length; index += QUEUED_APEXES_PER_ROW) {
        this.sql.exec(
          "INSERT INTO record_batch_apexes VALUES (?, ?, ?)",
          jobId, index / QUEUED_APEXES_PER_ROW,
          JSON.stringify(apexes.slice(index, index + QUEUED_APEXES_PER_ROW)),
        );
      }
      return { job: this.job(jobId, subject), replay: false };
    });
    if (outcome.status === 409) {
      return errorResponse(409, "idempotency key was already used for another request");
    }
    if (outcome.status === 503) {
      return errorResponse(503, "record batch queue is full", {
        "Retry-After": "1", "X-Overload-Reason": "batch-queue",
      });
    }
    if (outcome.status === 429) {
      return errorResponse(429, "daily request limit exceeded", {
        ...quotaHeaders({ limit, remaining: Math.max(0, limit - outcome.used), reset_at: resetAt }),
        "Retry-After": String(Math.max(1, resetAt - Math.floor(Date.now() / 1000))),
      });
    }
    if (await this.ctx.storage.getAlarm() === null) {
      await this.ctx.storage.setAlarm(Date.now() + 100);
    }
    const used = Number(this.sql.exec(
      "SELECT used FROM request_counts WHERE day = ? AND subject = ?", day, subject,
    ).toArray()[0]?.used ?? 0);
    return jsonResponse(batchJobDocument(outcome.job), 202, {
      "cache-control": "no-store",
      "Location": `/internal/v1/record-batches/${outcome.job.job_id}`,
      "X-Idempotent-Replay": outcome.replay ? "1" : "0",
      ...quotaHeaders({ limit, remaining: Math.max(0, limit - used), reset_at: resetAt }),
    });
  }

  async alarm() {
    const job = this.sql.exec(
      `SELECT * FROM record_batch_jobs WHERE state IN ('queued', 'running')
       ORDER BY updated_at, job_id LIMIT 1`,
    ).toArray()[0];
    if (!job) return;
    let nextDelay = 1;
    try {
      const position = Number(job.next_position);
      const row = this.sql.exec(
        "SELECT apexes FROM record_batch_apexes WHERE job_id = ? AND chunk_index = ?",
        job.job_id, Math.floor(position / QUEUED_APEXES_PER_ROW),
      ).toArray()[0];
      const requested = JSON.parse(row.apexes).slice(
        position % QUEUED_APEXES_PER_ROW,
        position % QUEUED_APEXES_PER_ROW + QUEUED_SLICE_APEXES,
      );
      const results = [];
      const errors = [];
      const root = JSON.parse(job.root_json);
      let recordCount = 0;
      let sourceRows = 0;
      for (const apex of requested) {
        const located = await locateApex(this.env, apex, root);
        if (Number(located.total) > QUEUED_SLICE_MAX_RECORDS) {
          errors.push({ apex, code: "result_too_large", message: "apex snapshot exceeds the result record limit" });
          break;
        }
        const records = [];
        for await (const record of apexRecords(this.env, located)) {
          records.push(hostnameRecord(record));
        }
        const nextSourceRows = records.reduce(
          (count, record) => count + record.sources.length, 0,
        );
        if (results.length === 0 && sourceRows + nextSourceRows > 20000) {
          errors.push({ apex, code: "result_too_large",
            message: "apex snapshot exceeds the source row limit" });
          break;
        }
        const next = { schema_version: RECORDS_SCHEMA_VERSION, apex, records };
        const document = { schema_version: QUEUED_SLICE_SCHEMA_VERSION,
          results: [...results, next], errors };
        if (recordCount + records.length > QUEUED_SLICE_MAX_RECORDS ||
            sourceRows + nextSourceRows > 20000 ||
            encoder.encode(JSON.stringify(document)).byteLength > QUEUED_SLICE_MAX_BYTES) {
          if (results.length === 0) {
            errors.push({ apex, code: "serialized_result_too_large",
              message: "apex snapshot exceeds the result byte limit" });
          }
          break;
        }
        results.push(next);
        recordCount += records.length;
        sourceRows += nextSourceRows;
      }
      const processed = results.length + errors.length;
      if (processed < 1) throw new Error("record batch slice made no progress");
      const document = JSON.stringify({ schema_version: QUEUED_SLICE_SCHEMA_VERSION,
        results, errors });
      this.ctx.storage.transactionSync(() => {
        const current = this.job(job.job_id, job.subject);
        if (!current || !["queued", "running"].includes(current.state) ||
            Number(current.next_position) !== position) return;
        for (let start = 0, part = 0; start < document.length; part += 1) {
          let end = Math.min(start + QUEUED_DOCUMENT_PART_CHARS, document.length);
          if (end < document.length && /[\uD800-\uDBFF]/.test(document[end - 1])) end -= 1;
          this.sql.exec(
            "INSERT INTO record_batch_chunks VALUES (?, ?, ?, ?)",
            job.job_id, current.next_sequence, part, document.slice(start, end),
          );
          start = end;
        }
        const nextPosition = position + processed;
        this.sql.exec(
          `UPDATE record_batch_jobs SET state = ?, next_position = ?,
           next_sequence = next_sequence + 1, completed_apexes = completed_apexes + ?,
           failed_apexes = failed_apexes + ?, committed_units = committed_units + ?,
           failures = 0, error = NULL, updated_at = ? WHERE job_id = ?`,
          nextPosition === Number(current.total_apexes) ? "done" : "running",
          nextPosition, processed, errors.length, processed,
          new Date().toISOString(), job.job_id,
        );
      });
    } catch (error) {
      console.error("record batch slice failed", job.job_id, String(error));
      nextDelay = Math.min(60000, 1000 * 2 ** Math.min(Number(job.failures), 5));
      this.ctx.storage.transactionSync(() => {
        const current = this.job(job.job_id, job.subject);
        if (!current || !["queued", "running"].includes(current.state)) return;
        const failures = Number(current.failures) + 1;
        if (failures >= 5) {
          const outstanding = Number(current.reserved_units) -
            Number(current.committed_units) - Number(current.released_units);
          this.sql.exec(
            "UPDATE request_counts SET used = max(0, used - ?) WHERE day = ? AND subject = ?",
            outstanding, current.quota_day, job.subject,
          );
          this.sql.exec(
            `UPDATE record_batch_jobs SET state = 'failed', failures = ?,
             released_units = released_units + ?, error = ?, updated_at = ? WHERE job_id = ?`,
            failures, outstanding, String(error).slice(0, 300),
            new Date().toISOString(), job.job_id,
          );
        } else {
          this.sql.exec(
            "UPDATE record_batch_jobs SET failures = ?, updated_at = ? WHERE job_id = ?",
            failures, new Date().toISOString(), job.job_id,
          );
        }
      });
    }
    if (this.sql.exec(
      "SELECT 1 FROM record_batch_jobs WHERE state IN ('queued', 'running') LIMIT 1",
    ).toArray().length) {
      await this.ctx.storage.setAlarm(Date.now() + nextDelay);
    }
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/docs" || url.pathname.startsWith("/docs/")) {
        return await docsPage(request, env, url);
      }
      if (url.pathname === "/mcp") return await mcp(request, env);
      if (
        request.method === "POST" &&
        url.pathname === "/internal/v1/records/batch"
      ) {
        return await internalBatch(request, env);
      }
      if (url.pathname === "/internal/v1/record-batches" ||
          url.pathname.startsWith("/internal/v1/record-batches/")) {
        return await queuedBatch(request, env, url);
      }
      if (request.method === "GET") {
        if (url.pathname === "/v1/search") return await search(request, env, url);
        if (url.pathname === "/v1/records") return await records(request, env, url);
        if (url.pathname === "/v1/stats") return await stats(env);
        if (url.pathname === "/health") return new Response("ok");
        if (url.pathname === "/ready") {
          const root = await loadRoot(env);
          return jsonResponse(
            {
              status: "ready",
              generation: root.generation,
              hostname_count: root.stats.hostname_count,
              last_ingest_at: root.stats.last_ingest_at,
            },
            200,
            { "cache-control": "no-cache" },
          );
        }
      }
      if (
        (request.method === "GET" || request.method === "HEAD") &&
        env.ASSETS !== undefined
      ) {
        return env.ASSETS.fetch(request);
      }
      return errorResponse(405, "method not allowed");
    } catch (error) {
      const status = Number(error?.status ?? 503);
      const headers = {};
      if (status === 429 && error.quota) {
        Object.assign(headers, quotaHeaders(error.quota));
        headers["Retry-After"] = String(
          Math.max(1, error.quota.reset_at - Math.floor(Date.now() / 1000)),
        );
      }
      if (status === 401) headers["WWW-Authenticate"] = "Bearer";
      return errorResponse(
        status,
        error instanceof Error ? error.message : String(error),
        headers,
      );
    }
  },
};
