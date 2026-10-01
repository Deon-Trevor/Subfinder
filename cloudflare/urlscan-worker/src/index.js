import {
  apexForHostname,
  normalizeApex,
  normalizeHostname,
  zoneForApex,
} from "../../index-worker/src/domain-policy.js";


const JOB_SCHEMA_VERSION = "subfinder.urlscan-job.v1";
const DELTA_SCHEMA_VERSION = "subfinder.ingest-delta.v1";
const DELTA_READY_SCHEMA_VERSION = "subfinder.delta-ready.v1";
const ENRICHMENT_SCHEMA_VERSION = "subfinder.enrichment-job.v1";
const ENRICHMENT_OPTIONS_SCHEMA_VERSION = "subfinder.enrichment-options.v1";
const encoder = new TextEncoder();


function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error("URLScan limit configuration must be a positive integer");
  }
  return parsed;
}


function fetcher(env) {
  return env.URLSCAN_FETCHER === undefined
    ? globalThis.fetch.bind(globalThis)
    : env.URLSCAN_FETCHER.fetch.bind(env.URLSCAN_FETCHER);
}


async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
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


function normalizeObserved(value, apex) {
  try {
    const hostname = normalizeHostname(value);
    return apexForHostname(hostname) === apex ? hostname : null;
  } catch {
    return null;
  }
}


function firstSeen(value) {
  if (typeof value !== "string") return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? null : parsed.toISOString();
}


export function recordsFromUrlscan(payload, apex, pageSize) {
  if (!Array.isArray(payload?.results)) throw new Error("URLScan response is invalid");
  const records = new Map();
  for (const result of payload.results) {
    const observed = firstSeen(result?.task?.time);
    for (const value of [result?.page?.domain, result?.task?.domain]) {
      const hostname = normalizeObserved(value, apex);
      if (hostname === null) continue;
      const previous = records.get(hostname);
      if (
        previous === undefined ||
        (observed !== null && (previous.first_seen === null || observed < previous.first_seen))
      ) {
        records.set(hostname, { apex, hostname, first_seen: observed });
      }
    }
  }
  let nextCursor = null;
  if (payload.results.length === pageSize && payload.results.length > 0) {
    const sort = payload.results.at(-1)?.sort;
    if (!Array.isArray(sort) || sort.length === 0) {
      throw new Error("URLScan full page has no continuation cursor");
    }
    nextCursor = sort.map(String).join(",");
  }
  return {
    entryCount: payload.results.length,
    nextCursor,
    records: [...records.values()].sort((left, right) => (
      left.hostname.localeCompare(right.hostname)
    )),
  };
}


function validateMessage(body) {
  if (
    body?.schema_version !== JOB_SCHEMA_VERSION ||
    typeof body.job_id !== "string" ||
    !/^[a-f0-9]{64}$/.test(body.job_id)
  ) {
    throw new Error("URLScan queue message is invalid");
  }
  return body.job_id;
}


async function loadJob(env, jobId) {
  return await env.CONTROL.prepare(
    `SELECT job_id, apex, cursor, state, quota_charged, object_key, created_at,
            updated_at, hostname_count, next_cursor, error, subject, origin
     FROM urlscan_jobs WHERE job_id = ?`,
  ).bind(jobId).first();
}


function deltaNamespace(env) {
  const value = env.URLSCAN_DELTA_NAMESPACE;
  if (value === undefined) return null;
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{0,31}$/.test(value)) {
    throw new Error("URLScan delta namespace is invalid");
  }
  return value;
}


async function notifyDelta(env, jobId, objectKey) {
  if (env.COMPACTION_QUEUE === undefined) {
    throw new Error("COMPACTION_QUEUE is not configured");
  }
  const namespace = deltaNamespace(env);
  await env.COMPACTION_QUEUE.send({
    schema_version: DELTA_READY_SCHEMA_VERSION,
    delta_id: namespace === null ? jobId : await sha256(`${namespace}\n${jobId}`),
    source_kind: "urlscan",
    object_key: objectKey,
  });
}


async function chargeQuota(env, job) {
  if (Number(job.quota_charged) === 1) return;
  const day = new Date().toISOString().slice(0, 10);
  const limit = positiveInteger(env.URLSCAN_BREADTH_DAILY_LIMIT, 70000);
  await env.CONTROL.prepare(
    `INSERT OR IGNORE INTO provider_quota(provider, quota_day, used)
     VALUES ('urlscan:breadth', ?, 0)`,
  ).bind(day).run();
  const priority = job.origin === "enrichment";
  const claimed = priority
    ? await env.CONTROL.prepare(
      `UPDATE provider_quota SET used = used + 1, priority_used = priority_used + 1
       WHERE provider = 'urlscan:breadth' AND quota_day = ? AND used < ?
         AND priority_used < ?`,
    ).bind(day, limit, positiveInteger(env.URLSCAN_PRIORITY_DAILY_LIMIT, 20000)).run()
    : await env.CONTROL.prepare(
      `UPDATE provider_quota SET used = used + 1
       WHERE provider = 'urlscan:breadth' AND quota_day = ? AND used < ?`,
    ).bind(day, limit).run();
  if (Number(claimed.meta?.changes ?? 0) !== 1) {
    throw new Error("URLScan UTC-day quota is exhausted");
  }
  await env.CONTROL.prepare(
    `UPDATE urlscan_jobs SET quota_charged = 1, quota_day = ?, updated_at = ?
     WHERE job_id = ?`,
  ).bind(day, new Date().toISOString(), job.job_id).run();
}


export async function scheduleUrlscan(env, now = new Date()) {
  const sourceLimit = positiveInteger(env.URLSCAN_SOURCE_LIMIT, 50);
  const nowIso = now.toISOString();
  const sources = await env.CONTROL.prepare(
    `SELECT apex, cursor FROM urlscan_sources
     WHERE enabled = 1 AND next_run_at <= ?
       AND NOT EXISTS (
         SELECT 1 FROM urlscan_jobs AS jobs
         WHERE jobs.apex = urlscan_sources.apex
           AND jobs.state IN ('queued', 'running')
       )
     ORDER BY next_run_at, apex LIMIT ?`,
  ).bind(nowIso, sourceLimit).all();
  let queued = 0;
  const refreshSeconds = positiveInteger(env.URLSCAN_REFRESH_SECONDS, 86400);
  for (const source of sources.results) {
    const apex = normalizeApex(source.apex);
    const epoch = source.cursor === null
      ? Math.floor(now.valueOf() / (refreshSeconds * 1000))
      : source.cursor;
    const jobId = await sha256(`${apex}:${epoch}`);
    const inserted = await env.CONTROL.prepare(
      `INSERT OR IGNORE INTO urlscan_jobs(
         job_id, apex, cursor, state, created_at, updated_at
       ) VALUES (?, ?, ?, 'queued', ?, ?)`,
    ).bind(jobId, apex, source.cursor, nowIso, nowIso).run();
    if (Number(inserted.meta?.changes ?? 0) !== 1) continue;
    try {
      await env.URLSCAN_QUEUE.send({
        schema_version: JOB_SCHEMA_VERSION,
        job_id: jobId,
      });
    } catch (error) {
      await env.CONTROL.prepare(
        "DELETE FROM urlscan_jobs WHERE job_id = ? AND state = 'queued'",
      ).bind(jobId).run();
      throw error;
    }
    queued += 1;
  }
  return queued;
}


async function fetchPage(env, apex, cursor, pageSize) {
  if (typeof env.URLSCAN_API_KEY !== "string" || !env.URLSCAN_API_KEY) {
    throw new Error("URLSCAN_API_KEY secret is not configured");
  }
  const url = new URL("https://urlscan.io/api/v1/search/");
  url.searchParams.set("q", `page.domain:${apex}`);
  url.searchParams.set("size", String(pageSize));
  if (cursor !== null) url.searchParams.set("search_after", cursor);
  const response = await fetcher(env)(url, {
    headers: {
      "api-key": env.URLSCAN_API_KEY,
      "user-agent": "subfinder-urlscan/1.0",
    },
  });
  if (!response.ok) throw new Error(`URLScan returned HTTP ${response.status}`);
  return await response.json();
}


function enrichmentDocument(job) {
  const terminal = ["complete", "failed"].includes(job.state);
  return {
    schema_version: ENRICHMENT_SCHEMA_VERSION,
    job_id: job.job_id,
    state: job.state === "complete" ? "done" : job.state,
    apex: job.apex,
    zone: zoneForApex(job.apex),
    created_at: job.created_at,
    updated_at: job.updated_at,
    terminal,
    lanes: {
      local_zone: { state: "not_requested", records_ingested: 0, artifact: null },
      urlscan: {
        state: job.state === "complete" ? "pending_publication" : job.state,
        records_ingested: Number(job.hostname_count ?? 0),
        more_available: job.state === "complete" && job.next_cursor !== null,
      },
    },
    error: job.error || null,
    result_url: null,
  };
}


export async function enrichmentOptions(env, apex) {
  const canonical = normalizeApex(apex);
  const zone = zoneForApex(canonical);
  const available = typeof env.URLSCAN_API_KEY === "string" && env.URLSCAN_API_KEY.length > 0;
  const day = new Date().toISOString().slice(0, 10);
  const [active, quota] = await Promise.all([
    env.CONTROL.prepare(
      "SELECT 1 FROM urlscan_jobs WHERE apex = ? AND state IN ('queued', 'running') LIMIT 1",
    ).bind(canonical).first(),
    env.CONTROL.prepare(
      "SELECT used, priority_used FROM provider_quota WHERE provider = 'urlscan:breadth' AND quota_day = ?",
    ).bind(day).first(),
  ]);
  const capacity = Number(quota?.used ?? 0) < positiveInteger(env.URLSCAN_BREADTH_DAILY_LIMIT, 70000)
    && Number(quota?.priority_used ?? 0) < positiveInteger(env.URLSCAN_PRIORITY_DAILY_LIMIT, 20000);
  const actionable = available && capacity && active === null;
  return {
    schema_version: ENRICHMENT_OPTIONS_SCHEMA_VERSION,
    apex: canonical,
    zone,
    actions: {
      local_zone: {
        available: false, current: false, actionable: false,
        artifact: null, artifact_bytes: null,
        reason: "local zone import is not available on this Worker",
      },
      urlscan: {
        available, actionable,
        reason: !available ? "URLScan reading is not configured here"
          : active !== null ? "URLScan reading is already queued for this domain"
            : !capacity ? "URLScan's daily reading allowance is spent"
              : "passive URLScan history is ready",
      },
    },
  };
}


export async function admitEnrichment(env, input) {
  const apex = normalizeApex(input?.apex);
  const { job_id: jobId, subject } = input ?? {};
  if (!/^[a-f0-9]{64}$/.test(jobId) || typeof subject !== "string" ||
      subject.length < 1 || subject.length > 160) {
    return Response.json({ detail: "invalid enrichment request" }, { status: 400 });
  }
  let job = await loadJob(env, jobId);
  if (job && (job.subject !== subject || job.apex !== apex || job.origin !== "enrichment")) {
    return Response.json({ detail: "idempotency key was already used for another request" }, { status: 409 });
  }
  let created = false;
  if (!job) {
    if (!env.URLSCAN_API_KEY) {
      return Response.json({ detail: "passive URLScan enrichment is not configured" }, { status: 409 });
    }
    const options = await enrichmentOptions(env, apex);
    if (!options.actions.urlscan.actionable) {
      const current = await loadJob(env, jobId);
      if (current?.subject === subject && current.apex === apex &&
          current.origin === "enrichment") {
        job = current;
      } else {
        return Response.json({ detail: options.actions.urlscan.reason }, { status: 409 });
      }
    }
  }
  if (!job) {
    const now = new Date().toISOString();
    await env.CONTROL.prepare(
      `INSERT OR IGNORE INTO urlscan_sources(apex, cursor, enabled, next_run_at, updated_at)
       VALUES (?, NULL, 0, ?, ?)`,
    ).bind(apex, new Date(Date.now() + 86400000).toISOString(), now).run();
    const source = await env.CONTROL.prepare(
      "SELECT cursor FROM urlscan_sources WHERE apex = ?",
    ).bind(apex).first();
    try {
      await env.CONTROL.prepare(
        `INSERT INTO urlscan_jobs(job_id, apex, cursor, state, subject, origin, created_at, updated_at)
         VALUES (?, ?, ?, 'queued', ?, 'enrichment', ?, ?)`,
      ).bind(jobId, apex, source.cursor, subject, now, now).run();
    } catch (error) {
      if (String(error).includes("UNIQUE constraint")) {
        job = await loadJob(env, jobId);
        if (job === null || job.subject !== subject || job.apex !== apex) {
          return Response.json({ detail: "URLScan reading is already queued for this domain" }, { status: 409 });
        }
      } else {
        throw error;
      }
    }
    if (job === null) {
      job = await loadJob(env, jobId);
      created = true;
    }
  }
  if (job.state === "queued") {
    try {
      await env.URLSCAN_QUEUE.send({ schema_version: JOB_SCHEMA_VERSION, job_id: jobId });
    } catch {
      return Response.json({ detail: "URLScan queue is not taking work right now" },
        { status: 503, headers: { "Retry-After": "5" } });
    }
  }
  return Response.json(enrichmentDocument(job), {
    status: 202,
    headers: { "Location": `/v1/enrichment-jobs/${jobId}`,
      "X-Idempotent-Replay": created ? "0" : "1" },
  });
}


export async function enrichmentStatus(env, jobId, subject) {
  if (!/^[a-f0-9]{64}$/.test(jobId) || typeof subject !== "string") {
    return Response.json({ detail: "enrichment job not found" }, { status: 404 });
  }
  const job = await loadJob(env, jobId);
  if (job === null || job.subject !== subject || job.origin !== "enrichment") {
    return Response.json({ detail: "enrichment job not found" }, { status: 404 });
  }
  return Response.json(enrichmentDocument(job), {
    headers: { "Cache-Control": "no-store", "Retry-After": job.state === "running" ? "2" : "5" },
  });
}


export async function processUrlscanJob(env, body) {
  const jobId = validateMessage(body);
  const job = await loadJob(env, jobId);
  if (job === null) throw new Error("URLScan job does not exist");
  if (job.state === "complete") {
    if (typeof job.object_key !== "string" || !job.object_key) {
      throw new Error("completed URLScan job has no delta object");
    }
    await notifyDelta(env, jobId, job.object_key);
    return { state: "complete", duplicate: true };
  }
  const now = new Date();
  const nowIso = now.toISOString();
  const leaseExpiresAt = new Date(now.valueOf() + 5 * 60 * 1000).toISOString();
  const claimed = await env.CONTROL.prepare(
    `UPDATE urlscan_jobs
     SET state = 'running', attempt_count = attempt_count + 1,
         error = NULL, lease_expires_at = ?, updated_at = ?
     WHERE job_id = ? AND (
       state IN ('queued', 'failed') OR
       (state = 'running' AND lease_expires_at < ?)
     )`,
  ).bind(leaseExpiresAt, nowIso, jobId, nowIso).run();
  if (Number(claimed.meta?.changes ?? 0) !== 1) {
    const current = await loadJob(env, jobId);
    if (current?.state === "complete") {
      await notifyDelta(env, jobId, current.object_key);
      return { state: "complete", duplicate: true };
    }
    throw new Error("URLScan job has an active processing lease");
  }
  await chargeQuota(env, job);
  const pageSize = Math.min(1000, positiveInteger(env.URLSCAN_PAGE_SIZE, 1000));
  const payload = await fetchPage(env, job.apex, job.cursor, pageSize);
  const page = recordsFromUrlscan(payload, job.apex, pageSize);
  const namespace = deltaNamespace(env);
  const objectKey = `ingest/urlscan/${namespace === null ? "" : `${namespace}/`}${job.apex}/${jobId}.json.gz`;
  await env.CATALOG.put(objectKey, await gzipJson({
    schema_version: DELTA_SCHEMA_VERSION,
    source: "urlscan",
    source_id: job.apex,
    range: { cursor: job.cursor, next_cursor: page.nextCursor },
    created_at: job.created_at,
    entry_count: page.entryCount,
    hostname_count: page.records.length,
    records: page.records,
  }), {
    httpMetadata: { contentType: "application/json", contentEncoding: "gzip" },
    customMetadata: { job_id: jobId, schema_version: DELTA_SCHEMA_VERSION },
  });
  const finishedAt = new Date().toISOString();
  const refreshSeconds = positiveInteger(env.URLSCAN_REFRESH_SECONDS, 86400);
  const nextRunAt = page.nextCursor === null
    ? new Date(Date.now() + refreshSeconds * 1000).toISOString()
    : finishedAt;
  await env.CONTROL.batch([
    env.CONTROL.prepare(
      `UPDATE urlscan_jobs
       SET state = 'complete', entry_count = ?, hostname_count = ?,
           object_key = ?, next_cursor = ?, error = NULL,
           lease_expires_at = NULL, updated_at = ?
       WHERE job_id = ?`,
    ).bind(
      page.entryCount,
      page.records.length,
      objectKey,
      page.nextCursor,
      finishedAt,
      jobId,
    ),
    env.CONTROL.prepare(
      `UPDATE urlscan_sources
       SET cursor = ?, next_run_at = ?, updated_at = ? WHERE apex = ?`,
    ).bind(page.nextCursor, nextRunAt, finishedAt, job.apex),
  ]);
  await notifyDelta(env, jobId, objectKey);
  return { state: "complete", duplicate: false, objectKey };
}


async function failJob(env, body, error, terminal) {
  if (typeof body?.job_id !== "string") return;
  await env.CONTROL.prepare(
    `UPDATE urlscan_jobs
     SET state = ?, error = ?, lease_expires_at = NULL, updated_at = ?
     WHERE job_id = ? AND state != 'complete'`,
  ).bind(terminal ? "failed" : "queued", String(error).slice(0, 1000),
    new Date().toISOString(), body.job_id).run();
}


export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response("ok");
    }
    try {
      if (request.method === "GET" && url.pathname === "/internal/enrichment-options") {
        return Response.json(await enrichmentOptions(env, url.searchParams.get("apex")),
          { headers: { "Cache-Control": "no-store" } });
      }
      if (request.method === "POST" && url.pathname === "/internal/enrichment-jobs") {
        return await admitEnrichment(env, await request.json());
      }
      const match = url.pathname.match(/^\/internal\/enrichment-jobs\/([a-f0-9]{64})$/);
      if (request.method === "GET" && match) {
        return await enrichmentStatus(env, match[1], request.headers.get("X-Subfinder-Subject"));
      }
    } catch (error) {
      if (error instanceof TypeError || error instanceof SyntaxError) {
        return Response.json({ detail: "invalid enrichment request" }, { status: 400 });
      }
      throw error;
    }
    return Response.json({ detail: "not found" }, { status: 404 });
  },

  async scheduled(_controller, env) {
    await scheduleUrlscan(env);
  },

  async queue(batch, env) {
    for (const message of batch.messages) {
      try {
        await processUrlscanJob(env, message.body);
        message.ack();
      } catch (error) {
        await failJob(env, message.body, error, Number(message.attempts) >= 5);
        message.retry({ delaySeconds: 60 });
      }
    }
  },
};
