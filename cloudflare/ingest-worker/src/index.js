import {
  fetchEntries,
  recordsFromEntries,
  validatedLogUrl,
} from "./direct-ct.js";
import { refreshPublicSources } from "./public-sources.js";
import { discoverCtLogs } from "./log-discovery.js";
import { staticRange, staticTreeSize } from "./static-ct.js";


const JOB_SCHEMA_VERSION = "subfinder.direct-ct-job.v1";
const DELTA_SCHEMA_VERSION = "subfinder.ingest-delta.v1";
const DELTA_READY_SCHEMA_VERSION = "subfinder.delta-ready.v1";
const encoder = new TextEncoder();


function csvValues(value) {
  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}


function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error("ingestion limit configuration must be a positive integer");
  }
  return parsed;
}


function nonnegativeInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error("ingestion limit configuration must be a nonnegative integer");
  }
  return parsed;
}


function fetcher(env) {
  return env.CT_FETCHER === undefined
    ? globalThis.fetch.bind(globalThis)
    : env.CT_FETCHER.fetch.bind(env.CT_FETCHER);
}


async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}


async function getTreeSize(env, logUrl) {
  const url = new URL(logUrl);
  url.pathname = `${url.pathname}/ct/v1/get-sth`;
  const response = await fetcher(env)(url, {
    headers: { "user-agent": "subfinder-ingest/1.0" },
  });
  if (!response.ok) throw new Error(`CT log returned HTTP ${response.status}`);
  const payload = await response.json();
  const treeSize = Number(payload?.tree_size);
  if (!Number.isSafeInteger(treeSize) || treeSize < 0) {
    throw new Error("CT log tree size is invalid");
  }
  return treeSize;
}


export async function scheduleDirectCt(env) {
  const allowedHosts = csvValues(env.CT_ALLOWED_HOSTS);
  const staticAllowedHosts = csvValues(env.STATIC_CT_ALLOWED_HOSTS);
  const manualLimit = positiveInteger(env.CT_SOURCE_LIMIT, 20);
  const discoveredLimit = nonnegativeInteger(env.CT_DISCOVERED_SOURCE_LIMIT, 0);
  const staticLimit = nonnegativeInteger(env.STATIC_CT_SOURCE_LIMIT, 0);
  if (allowedHosts.length === 0 && (manualLimit > 0 || discoveredLimit > 0)) {
    throw new Error("CT_ALLOWED_HOSTS is not configured");
  }
  if (staticAllowedHosts.length === 0 && staticLimit > 0) {
    throw new Error("STATIC_CT_ALLOWED_HOSTS is not configured");
  }
  const rangeSize = Math.min(1000, positiveInteger(env.CT_RANGE_SIZE, 256));
  const now = new Date();
  const rows = [];
  for (const [protocol, discovered, limit] of [
    ["rfc6962", 0, manualLimit],
    ["rfc6962", 1, discoveredLimit],
    ["static", 0, staticLimit],
  ]) {
    if (limit === 0) continue;
    const sources = await env.CONTROL.prepare(
      `SELECT source_id, log_url, protocol, next_index, cursor_initialized
       FROM ct_sources WHERE enabled = 1 AND protocol = ? AND discovered = ?
         AND (retry_at IS NULL OR retry_at <= ?)
       ORDER BY updated_at, source_id LIMIT ?`,
    ).bind(protocol, discovered, now.toISOString(), limit).all();
    rows.push(...sources.results);
  }
  let queued = 0;
  for (const source of rows) {
    const isStatic = source.protocol === "static";
    const hosts = isStatic ? staticAllowedHosts : allowedHosts;
    const logUrl = validatedLogUrl(source.log_url, hosts);
    let treeSize;
    try {
      treeSize = isStatic
        ? await staticTreeSize(env, logUrl, hosts)
        : await getTreeSize(env, logUrl);
    } catch (error) {
      await env.CONTROL.prepare(
        `UPDATE ct_sources SET retry_at = ?, last_error = ?, updated_at = ?
         WHERE source_id = ?`,
      ).bind(
        new Date(now.valueOf() + 60 * 60 * 1000).toISOString(),
        String(error).slice(0, 500), now.toISOString(), source.source_id,
      ).run();
      continue;
    }
    let start = Number(source.next_index);
    if (Number(source.cursor_initialized) === 0) {
      const initialBackfill = positiveInteger(env.CT_INITIAL_BACKFILL, 1024);
      start = Math.max(0, treeSize - initialBackfill);
      await env.CONTROL.prepare(
        `UPDATE ct_sources SET next_index = ?, cursor_initialized = 1,
         retry_at = NULL, last_error = NULL WHERE source_id = ? AND cursor_initialized = 0`,
      ).bind(start, source.source_id).run();
    }
    if (start >= treeSize) continue;
    const end = Math.min(
      treeSize - 1,
      start + rangeSize - 1,
      isStatic ? (Math.floor(start / 256) + 1) * 256 - 1 : treeSize - 1,
    );
    const jobId = await sha256(`${source.source_id}:${start}:${end}`);
    const nowIso = now.toISOString();
    const inserted = await env.CONTROL.prepare(
      `INSERT OR IGNORE INTO ingest_jobs(
         job_id, source_id, start_index, end_index, state, created_at, updated_at
       ) VALUES (?, ?, ?, ?, 'queued', ?, ?)`,
    ).bind(jobId, source.source_id, start, end, nowIso, nowIso).run();
    if (Number(inserted.meta?.changes ?? 0) !== 1) continue;
    try {
      await env.INGEST_QUEUE.send({
        schema_version: JOB_SCHEMA_VERSION,
        job_id: jobId,
      });
    } catch (error) {
      await env.CONTROL.prepare(
        "DELETE FROM ingest_jobs WHERE job_id = ? AND state = 'queued'",
      ).bind(jobId).run();
      throw error;
    }
    queued += 1;
  }
  return queued;
}


async function loadJob(env, jobId) {
  return await env.CONTROL.prepare(
    `SELECT j.job_id, j.source_id, j.start_index, j.end_index, j.state,
            j.created_at, j.object_key, s.log_url, s.protocol
     FROM ingest_jobs AS j
     JOIN ct_sources AS s ON s.source_id = j.source_id
     WHERE j.job_id = ?`,
  ).bind(jobId).first();
}


async function notifyDelta(env, jobId, objectKey, protocol) {
  if (env.COMPACTION_QUEUE === undefined) {
    throw new Error("COMPACTION_QUEUE is not configured");
  }
  await env.COMPACTION_QUEUE.send({
    schema_version: DELTA_READY_SCHEMA_VERSION,
    delta_id: jobId,
    source_kind: protocol === "static" ? "static-ct" : "direct-ct",
    object_key: objectKey,
  });
}


function validateMessage(body) {
  if (
    body?.schema_version !== JOB_SCHEMA_VERSION ||
    typeof body.job_id !== "string" ||
    !/^[a-f0-9]{64}$/.test(body.job_id)
  ) {
    throw new Error("direct CT queue message is invalid");
  }
  return body.job_id;
}


async function gzipJson(value) {
  const stream = new Blob([JSON.stringify(value)])
    .stream()
    .pipeThrough(new CompressionStream("gzip"));
  return await new Response(stream).arrayBuffer();
}


export async function processDirectCtJob(env, body) {
  const jobId = validateMessage(body);
  const job = await loadJob(env, jobId);
  if (job === null) throw new Error("direct CT job does not exist");
  if (job.state === "complete") {
    if (typeof job.object_key !== "string" || !job.object_key) {
      throw new Error("completed direct CT job has no delta object");
    }
    await notifyDelta(env, jobId, job.object_key, job.protocol);
    return { state: "complete", duplicate: true };
  }

  const isStatic = job.protocol === "static";
  const allowedHosts = csvValues(isStatic ? env.STATIC_CT_ALLOWED_HOSTS : env.CT_ALLOWED_HOSTS);
  const logUrl = validatedLogUrl(job.log_url, allowedHosts);
  const startedAt = new Date();
  const startedAtIso = startedAt.toISOString();
  const leaseExpiresAt = new Date(startedAt.getTime() + 5 * 60 * 1000).toISOString();
  const claimed = await env.CONTROL.prepare(
    `UPDATE ingest_jobs
     SET state = 'running', attempt_count = attempt_count + 1,
         error = NULL, lease_expires_at = ?, updated_at = ?
     WHERE job_id = ? AND (
       state IN ('queued', 'failed') OR
       (state = 'running' AND lease_expires_at < ?)
     )`,
  ).bind(leaseExpiresAt, startedAtIso, jobId, startedAtIso).run();
  if (Number(claimed.meta?.changes ?? 0) !== 1) {
    const current = await loadJob(env, jobId);
    if (current?.state === "complete") {
      await notifyDelta(env, jobId, current.object_key, current.protocol);
      return { state: "complete", duplicate: true };
    }
    throw new Error("direct CT job has an active processing lease");
  }

  let entryCount;
  let records;
  if (isStatic) {
    const treeSize = await staticTreeSize(env, logUrl, allowedHosts);
    ({ entryCount, records } = await staticRange(
      env, logUrl, allowedHosts,
      Number(job.start_index), Number(job.end_index), treeSize,
    ));
  } else {
    const entries = await fetchEntries(
      fetcher(env), logUrl, Number(job.start_index), Number(job.end_index),
    );
    entryCount = entries.length;
    records = recordsFromEntries(entries);
  }
  if (entryCount === 0) throw new Error("CT log returned no entries");
  const requested = Number(job.end_index) - Number(job.start_index) + 1;
  if (entryCount > requested) throw new Error("CT log returned too many entries");
  const actualEnd = Number(job.start_index) + entryCount - 1;
  const finishedAt = new Date().toISOString();
  const objectKey = (
    `ingest/${isStatic ? "static-ct" : "direct-ct"}/${job.source_id}/${job.start_index}-${actualEnd}-${jobId}.json.gz`
  );
  const document = {
    schema_version: DELTA_SCHEMA_VERSION,
    source: `${isStatic ? "static_ct" : "direct_ct"}:${logUrl.toString()}`,
    source_id: job.source_id,
    range: { start: Number(job.start_index), end: actualEnd },
    created_at: job.created_at,
    entry_count: entryCount,
    hostname_count: records.length,
    records,
  };
  await env.CATALOG.put(objectKey, await gzipJson(document), {
    httpMetadata: { contentType: "application/json", contentEncoding: "gzip" },
    customMetadata: {
      job_id: jobId,
      schema_version: DELTA_SCHEMA_VERSION,
    },
  });
  await env.CONTROL.batch([
    env.CONTROL.prepare(
      `UPDATE ingest_jobs
       SET state = 'complete', end_index = ?, entry_count = ?, hostname_count = ?,
           object_key = ?, error = NULL, lease_expires_at = NULL, updated_at = ?
       WHERE job_id = ?`,
    ).bind(actualEnd, entryCount, records.length, objectKey, finishedAt, jobId),
    env.CONTROL.prepare(
      `UPDATE ct_sources
       SET next_index = MAX(next_index, ?), updated_at = ?
       WHERE source_id = ?`,
    ).bind(actualEnd + 1, finishedAt, job.source_id),
  ]);
  await notifyDelta(env, jobId, objectKey, job.protocol);
  return { state: "complete", duplicate: false, objectKey };
}


async function failJob(env, body, error) {
  if (typeof body?.job_id !== "string") return;
  await env.CONTROL.prepare(
    `UPDATE ingest_jobs
     SET state = 'failed', error = ?, lease_expires_at = NULL, updated_at = ?
     WHERE job_id = ? AND state != 'complete'`,
  ).bind(String(error).slice(0, 1000), new Date().toISOString(), body.job_id).run();
}


export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response("ok");
    }
    return new Response(JSON.stringify({ detail: "not found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  },

  async scheduled(_controller, env) {
    const results = await Promise.allSettled([
      scheduleDirectCt(env),
      discoverCtLogs(env),
      refreshPublicSources(env),
    ]);
    const errors = results.filter((result) => result.status === "rejected");
    if (errors.length > 0) {
      throw new AggregateError(errors.map((result) => result.reason), "ingestion schedule failed");
    }
  },

  async queue(batch, env) {
    await Promise.all(batch.messages.map(async (message) => {
      try {
        await processDirectCtJob(env, message.body);
        message.ack();
      } catch (error) {
        await failJob(env, message.body, error);
        message.retry({ delaySeconds: 60 });
      }
    }));
  },
};
