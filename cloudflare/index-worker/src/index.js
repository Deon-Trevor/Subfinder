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
import { QuotaLedger, admitQuota, quotaHeaders } from "./quota-ledger.js";


export { QuotaLedger };


const FORMAT = "subfinder.r2-index.v2";
const RECORDS_SCHEMA_VERSION = "subfinder.index-records.v1";
const BATCH_RECORDS_SCHEMA_VERSION = "subfinder.internal-index-records-batch.v1";
const INTERNAL_REQUEST_MAX_BYTES = 512 * 1024;
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

async function locateApex(env, apex) {
  const root = await loadRoot(env);
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

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/mcp") return await mcp(request, env);
      if (
        request.method === "POST" &&
        url.pathname === "/internal/v1/records/batch"
      ) {
        return await internalBatch(request, env);
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
