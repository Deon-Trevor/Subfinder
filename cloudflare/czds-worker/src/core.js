import {
  apexForHostname,
  normalizeApex,
  normalizeHostname,
} from "../../index-worker/src/domain-policy.js";


const AUTH_URL = "https://account-api.icann.org/api/authenticate";
const LINKS_URL = "https://czds-api.icann.org/czds/downloads/links";
const DELTA_SCHEMA_VERSION = "subfinder.ingest-delta.v1";
const DELTA_READY_SCHEMA_VERSION = "subfinder.delta-ready.v1";
const encoder = new TextEncoder();


function positiveInteger(value, fallback) {
  const parsed = Number(value ?? fallback);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error("CZDS limit configuration must be a positive integer");
  }
  return parsed;
}


function fetcher(env) {
  return env.CZDS_FETCHER === undefined
    ? globalThis.fetch.bind(globalThis)
    : env.CZDS_FETCHER.fetch.bind(env.CZDS_FETCHER);
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


function requireCredentials(env) {
  if (typeof env.CZDS_USERNAME !== "string" || !env.CZDS_USERNAME) {
    throw new Error("CZDS_USERNAME secret is not configured");
  }
  if (typeof env.CZDS_PASSWORD !== "string" || !env.CZDS_PASSWORD) {
    throw new Error("CZDS_PASSWORD secret is not configured");
  }
}


export async function authenticate(env) {
  requireCredentials(env);
  const response = await fetcher(env)(AUTH_URL, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "user-agent": "subfinder-czds/1.0",
    },
    body: JSON.stringify({
      username: env.CZDS_USERNAME,
      password: env.CZDS_PASSWORD,
    }),
  });
  if (!response.ok) throw new Error(`CZDS authentication returned HTTP ${response.status}`);
  const payload = await response.json();
  if (typeof payload?.accessToken !== "string" || !payload.accessToken) {
    throw new Error("CZDS authentication response has no accessToken");
  }
  return payload.accessToken;
}


export function validatedDownloadLink(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("CZDS download link is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !["czds-api.icann.org", "czds-download-api.icann.org"].includes(url.hostname)
  ) {
    throw new Error("CZDS download link is not allowed");
  }
  const match = /^\/czds\/downloads\/([a-z0-9-]+)\.zone$/.exec(url.pathname);
  if (match === null) throw new Error("CZDS download link has an invalid zone path");
  return { url: url.toString(), zone: match[1] };
}


export async function approvedLinks(env, token) {
  const response = await fetcher(env)(LINKS_URL, {
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
      "user-agent": "subfinder-czds/1.0",
    },
  });
  if (!response.ok) throw new Error(`CZDS links returned HTTP ${response.status}`);
  const payload = await response.json();
  if (!Array.isArray(payload)) throw new Error("CZDS links response is invalid");
  const links = payload.map(validatedDownloadLink);
  links.sort((left, right) => left.zone.localeCompare(right.zone));
  return links;
}


export async function scheduleCzds(env, now = new Date()) {
  const token = await authenticate(env);
  const approved = await approvedLinks(env, token);
  const onlyZone = env.CZDS_ONLY_ZONE;
  if (onlyZone !== undefined && !/^[a-z0-9-]+$/.test(onlyZone)) {
    throw new Error("CZDS_ONLY_ZONE is invalid");
  }
  const links = onlyZone === undefined
    ? approved
    : approved.filter((link) => link.zone === onlyZone);
  if (onlyZone !== undefined && links.length !== 1) {
    throw new Error("requested CZDS zone is not approved");
  }
  const nowIso = now.toISOString();
  for (const link of links) {
    await env.CONTROL.prepare(
      `INSERT INTO czds_zones(zone, updated_at) VALUES (?, ?)
       ON CONFLICT(zone) DO UPDATE SET updated_at = excluded.updated_at`,
    ).bind(link.zone, nowIso).run();
  }
  const maxZones = positiveInteger(env.CZDS_MAX_ZONES, 25);
  const intervalSeconds = positiveInteger(env.CZDS_REFRESH_SECONDS, 86400);
  const cutoff = new Date(now.valueOf() - intervalSeconds * 1000).toISOString();
  const due = await env.CONTROL.prepare(
    `SELECT zone, last_completed_at FROM czds_zones
     WHERE enabled = 1 AND (last_completed_at IS NULL OR last_completed_at <= ?)
       AND (last_attempt_at IS NULL OR last_attempt_at <= ?)
       AND (? IS NULL OR zone = ?)
       AND NOT EXISTS (
         SELECT 1 FROM czds_jobs AS jobs
         WHERE jobs.zone = czds_zones.zone
           AND jobs.state IN ('queued', 'running', 'staged')
       )
     ORDER BY last_completed_at IS NOT NULL,
              COALESCE(last_completed_at, last_attempt_at), zone LIMIT ?`,
  ).bind(cutoff, cutoff, onlyZone ?? null, onlyZone ?? null, maxZones).all();
  const byZone = new Map(links.map((link) => [link.zone, link.url]));
  let queued = 0;
  for (const source of due.results) {
    const downloadUrl = byZone.get(source.zone);
    if (downloadUrl === undefined) continue;
    const epoch = Math.floor(now.valueOf() / (intervalSeconds * 1000));
    const jobId = await sha256(`${source.zone}:${epoch}`);
    const inserted = await env.CONTROL.prepare(
      `INSERT OR IGNORE INTO czds_jobs(
         job_id, zone, download_url, state, created_at, updated_at
       ) VALUES (?, ?, ?, 'queued', ?, ?)`,
    ).bind(jobId, source.zone, downloadUrl, nowIso, nowIso).run();
    if (Number(inserted.meta?.changes ?? 0) !== 1) continue;
    try {
      await env.CZDS_WORKFLOW.create({
        id: jobId,
        params: { job_id: jobId },
      });
    } catch (error) {
      await env.CONTROL.prepare(
        "DELETE FROM czds_jobs WHERE job_id = ? AND state = 'queued'",
      ).bind(jobId).run();
      throw error;
    }
    await env.CONTROL.prepare(
      "UPDATE czds_zones SET last_attempt_at = ? WHERE zone = ?",
    ).bind(nowIso, source.zone).run();
    queued += 1;
  }
  return queued;
}


export async function claimCzdsJob(env, jobId) {
  if (typeof jobId !== "string" || !/^[a-f0-9]{64}$/.test(jobId)) {
    throw new Error("CZDS workflow job ID is invalid");
  }
  const now = new Date().toISOString();
  const claimed = await env.CONTROL.prepare(
    `UPDATE czds_jobs
     SET state = 'running', attempt_count = attempt_count + 1,
         error = NULL, updated_at = ?
     WHERE job_id = ? AND state IN ('queued', 'failed', 'running')`,
  ).bind(now, jobId).run();
  if (Number(claimed.meta?.changes ?? 0) !== 1) {
    const job = await env.CONTROL.prepare(
      "SELECT state FROM czds_jobs WHERE job_id = ?",
    ).bind(jobId).first();
    if (job?.state === "complete") return { state: "complete" };
    throw new Error("CZDS workflow job cannot be claimed");
  }
  return { state: "running" };
}


async function bodyWithDetectedCompression(body) {
  if (body === null) throw new Error("CZDS zone response has no body");
  const reader = body.getReader();
  const leading = [];
  let leadingBytes = 0;
  while (leadingBytes < 2) {
    const next = await reader.read();
    if (next.done) break;
    if (next.value.length === 0) continue;
    leading.push(next.value);
    leadingBytes += next.value.length;
  }
  if (leadingBytes === 0) throw new Error("CZDS zone response is empty");
  const magic = new Uint8Array(leadingBytes);
  let position = 0;
  for (const chunk of leading) {
    magic.set(chunk, position);
    position += chunk.length;
  }
  const stream = new ReadableStream({
    start(controller) {
      for (const chunk of leading) controller.enqueue(chunk);
    },
    async pull(controller) {
      const next = await reader.read();
      if (next.done) controller.close();
      else controller.enqueue(next.value);
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
  return magic[0] === 0x1f && magic[1] === 0x8b
    ? stream.pipeThrough(new DecompressionStream("gzip"))
    : stream;
}


async function* textLines(stream) {
  const reader = stream.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let buffer = "";
  while (true) {
    const result = await reader.read();
    if (result.done) break;
    buffer += decoder.decode(result.value, { stream: true });
    let newline;
    while ((newline = buffer.indexOf("\n")) !== -1) {
      yield buffer.slice(0, newline).replace(/\r$/, "");
      buffer = buffer.slice(newline + 1);
    }
  }
  buffer += decoder.decode();
  if (buffer) yield buffer.replace(/\r$/, "");
}


export function zoneRecord(rawLine, zone, previousOwner) {
  const leadingSpace = /^\s/.test(rawLine);
  const line = rawLine.split(";", 1)[0].trim();
  if (!line || line.startsWith("$")) return { record: null, previousOwner };
  const tokens = line.split(/\s+/);
  let ownerToken = previousOwner;
  if (!leadingSpace) ownerToken = tokens.shift()?.toLowerCase() ?? null;
  if (ownerToken === null || !tokens.some((token) => token.toUpperCase() === "NS")) {
    return { record: null, previousOwner: ownerToken };
  }
  let owner = ownerToken;
  if (owner === "@") owner = zone;
  else if (owner.endsWith(".")) owner = owner.slice(0, -1);
  else owner = `${owner}.${zone}`;
  try {
    const hostname = normalizeHostname(owner);
    if (hostname === zone || !hostname.endsWith(`.${zone}`)) {
      return { record: null, previousOwner: ownerToken };
    }
    return {
      record: { apex: normalizeApex(apexForHostname(hostname)), hostname, first_seen: null },
      previousOwner: ownerToken,
    };
  } catch {
    return { record: null, previousOwner: ownerToken };
  }
}


async function writeChunk(env, job, chunkIndex, records) {
  const deltaId = await sha256(`${job.job_id}:${chunkIndex}`);
  const objectKey = `ingest/czds/${job.zone}/${job.job_id}-${chunkIndex}.json.gz`;
  const recordsHash = await sha256(JSON.stringify(records));
  await env.CATALOG.put(objectKey, await gzipJson({
    schema_version: DELTA_SCHEMA_VERSION,
    source: `czds:${job.zone}`,
    source_id: job.zone,
    range: { chunk: chunkIndex },
    created_at: job.created_at,
    entry_count: records.length,
    hostname_count: records.length,
    records,
  }), {
    httpMetadata: { contentType: "application/json", contentEncoding: "gzip" },
    customMetadata: {
      delta_id: deltaId,
      schema_version: DELTA_SCHEMA_VERSION,
      records_sha256: recordsHash,
    },
  });
  await env.CONTROL.prepare(
    `INSERT OR REPLACE INTO czds_job_deltas(
       job_id, chunk_index, delta_id, object_key, record_count, created_at
     ) VALUES (?, ?, ?, ?, ?, ?)`,
  ).bind(
    job.job_id,
    chunkIndex,
    deltaId,
    objectKey,
    records.length,
    new Date().toISOString(),
  ).run();
}


export async function beginCzdsArtifact(env, jobId, fingerprint) {
  if (typeof fingerprint !== "string" || fingerprint === "||" || !fingerprint) {
    throw new Error("CZDS zone response has no stable artifact fingerprint");
  }
  const job = await env.CONTROL.prepare(
    "SELECT state, source_fingerprint FROM czds_jobs WHERE job_id = ?",
  ).bind(jobId).first();
  if (job?.state !== "running") throw new Error("CZDS job is not running");
  if (job.source_fingerprint !== null && job.source_fingerprint !== fingerprint) {
    throw new Error("CZDS zone artifact changed while its job was running");
  }
  await env.CONTROL.prepare(
    "UPDATE czds_jobs SET source_fingerprint = ?, updated_at = ? WHERE job_id = ?",
  ).bind(fingerprint, new Date().toISOString(), jobId).run();
}


export async function appendCzdsChunk(env, jobId, chunkIndex, records) {
  const limit = positiveInteger(env.CZDS_DELTA_RECORDS, 20000);
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 ||
      !Array.isArray(records) || records.length < 1 || records.length > limit) {
    throw new Error("CZDS chunk is invalid");
  }
  const job = await env.CONTROL.prepare(
    "SELECT job_id, zone, state, source_fingerprint, created_at FROM czds_jobs WHERE job_id = ?",
  ).bind(jobId).first();
  if (job?.state !== "running" || job.source_fingerprint === null) {
    throw new Error("CZDS artifact has not started");
  }
  for (const record of records) {
    if (typeof record?.hostname !== "string" ||
        normalizeHostname(record.hostname) !== record.hostname ||
        normalizeApex(record.apex) !== record.apex ||
        apexForHostname(record.hostname) !== record.apex ||
        !record.hostname.endsWith(`.${job.zone}`) ||
        record.first_seen !== null) {
      throw new Error("CZDS chunk has an invalid record");
    }
  }
  const last = await env.CONTROL.prepare(
    `SELECT chunk_index, object_key, record_count FROM czds_job_deltas
     WHERE job_id = ? ORDER BY chunk_index DESC LIMIT 1`,
  ).bind(jobId).first();
  const lastIndex = last === null ? -1 : Number(last.chunk_index);
  if (chunkIndex <= lastIndex) {
    const existing = await env.CONTROL.prepare(
      `SELECT object_key, record_count FROM czds_job_deltas
       WHERE job_id = ? AND chunk_index = ?`,
    ).bind(jobId, chunkIndex).first();
    if (Number(existing?.record_count) !== records.length) {
      throw new Error("CZDS repeated chunk does not match the staged object");
    }
    const object = await env.CATALOG.head(existing.object_key);
    const expectedHash = await sha256(JSON.stringify(records));
    if (object?.customMetadata?.records_sha256 === expectedHash) return;
    if (object?.customMetadata?.records_sha256 === undefined) {
      const legacyObject = await env.CATALOG.get(existing.object_key);
      if (legacyObject !== null) {
        const payload = await new Response(
          legacyObject.body.pipeThrough(new DecompressionStream("gzip")),
        ).json();
        if (JSON.stringify(payload.records) === JSON.stringify(records)) return;
      }
    }
    throw new Error("CZDS repeated chunk does not match the staged object");
  }
  if (chunkIndex !== lastIndex + 1) {
    throw new Error("CZDS chunks must be appended in order");
  }
  await writeChunk(env, job, chunkIndex, records);
}


export async function completeCzdsArtifact(env, jobId, chunkCount, hostnameCount) {
  if (!Number.isSafeInteger(chunkCount) || chunkCount < 1 ||
      !Number.isSafeInteger(hostnameCount) || hostnameCount < 1) {
    throw new Error("CZDS completion counts are invalid");
  }
  const counts = await env.CONTROL.prepare(
    `SELECT COUNT(*) AS chunks, COALESCE(SUM(record_count), 0) AS hostnames,
            MAX(chunk_index) AS last_index FROM czds_job_deltas WHERE job_id = ?`,
  ).bind(jobId).first();
  if (counts.chunks !== chunkCount || counts.hostnames !== hostnameCount ||
      counts.last_index !== chunkCount - 1) {
    throw new Error("CZDS staged delta counts do not match the completed artifact");
  }
  const updated = await env.CONTROL.prepare(
    `UPDATE czds_jobs SET state = 'staged', hostname_count = ?, delta_count = ?,
       error = NULL, updated_at = ? WHERE job_id = ? AND state = 'running'`,
  ).bind(hostnameCount, chunkCount, new Date().toISOString(), jobId).run();
  if (Number(updated.meta?.changes ?? 0) !== 1) {
    throw new Error("CZDS job is not running");
  }
  return { state: "staged", deltaCount: chunkCount, hostnameCount };
}


export async function stageCzdsJob(env, jobId) {
  requireCredentials(env);
  const job = await env.CONTROL.prepare(
    `SELECT job_id, zone, download_url, state, source_fingerprint, created_at
     FROM czds_jobs WHERE job_id = ?`,
  ).bind(jobId).first();
  if (job === null) throw new Error("CZDS job does not exist");
  if (job.state === "staged" || job.state === "complete") {
    return { state: job.state };
  }
  if (job.state !== "running") throw new Error("CZDS job is not running");
  const link = validatedDownloadLink(job.download_url);
  if (link.zone !== job.zone) throw new Error("CZDS job zone does not match its download link");
  const token = await authenticate(env);
  const response = await fetcher(env)(link.url, {
    headers: {
      accept: "application/x-gzip,application/octet-stream",
      authorization: `Bearer ${token}`,
      "user-agent": "subfinder-czds/1.0",
    },
  });
  if (!response.ok) throw new Error(`CZDS zone download returned HTTP ${response.status}`);
  const fingerprint = [
    response.headers.get("etag") ?? "",
    response.headers.get("last-modified") ?? "",
    response.headers.get("content-length") ?? "",
  ].join("|");
  await beginCzdsArtifact(env, jobId, fingerprint);

  const maxRecords = positiveInteger(env.CZDS_DELTA_RECORDS, 20000);
  const stream = await bodyWithDetectedCompression(response.body);
  let previousOwner = null;
  let chunkIndex = 0;
  let hostnameCount = 0;
  let records = new Map();
  for await (const line of textLines(stream)) {
    const parsed = zoneRecord(line, job.zone, previousOwner);
    previousOwner = parsed.previousOwner;
    if (parsed.record === null) continue;
    records.set(parsed.record.hostname, parsed.record);
    if (records.size < maxRecords) continue;
    const values = [...records.values()].sort((left, right) => (
      left.apex.localeCompare(right.apex) || left.hostname.localeCompare(right.hostname)
    ));
    await appendCzdsChunk(env, jobId, chunkIndex, values);
    hostnameCount += values.length;
    chunkIndex += 1;
    records = new Map();
  }
  if (records.size > 0) {
    const values = [...records.values()].sort((left, right) => (
      left.apex.localeCompare(right.apex) || left.hostname.localeCompare(right.hostname)
    ));
    await appendCzdsChunk(env, jobId, chunkIndex, values);
    hostnameCount += values.length;
    chunkIndex += 1;
  }
  if (chunkIndex === 0) throw new Error("CZDS zone produced no registrable NS owners");
  return await completeCzdsArtifact(env, jobId, chunkIndex, hostnameCount);
}


export async function startCzdsContainerJob(env, jobId) {
  requireCredentials(env);
  if (env.CZDS_PARSER === undefined) throw new Error("CZDS_PARSER is not configured");
  const job = await env.CONTROL.prepare(
    "SELECT zone, download_url, state FROM czds_jobs WHERE job_id = ?",
  ).bind(jobId).first();
  if (job?.state === "staged" || job?.state === "complete") return { state: job.state };
  if (job?.state !== "running") throw new Error("CZDS job is not running");
  const link = validatedDownloadLink(job.download_url);
  if (link.zone !== job.zone) throw new Error("CZDS job zone does not match its download link");
  const token = await authenticate(env);
  const response = await env.CZDS_PARSER.getByName(jobId).fetch(
    new Request("http://localhost/start", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        job_id: jobId,
        zone: job.zone,
        url: link.url,
        token,
        max_records: positiveInteger(env.CZDS_DELTA_RECORDS, 20000),
      }),
    }),
  );
  if (!response.ok) throw new Error(`CZDS parser start returned HTTP ${response.status}`);
  return await response.json();
}


export async function inspectCzdsContainerJob(env, jobId) {
  const response = await env.CZDS_PARSER.getByName(jobId).fetch(
    new Request("http://localhost/status"),
  );
  if (!response.ok) throw new Error(`CZDS parser status returned HTTP ${response.status}`);
  return await response.json();
}


export async function czdsJobUsesContainer(env, jobId) {
  const job = await env.CONTROL.prepare(
    "SELECT zone FROM czds_jobs WHERE job_id = ?",
  ).bind(jobId).first();
  if (job === null) throw new Error("CZDS job does not exist");
  return (env.CZDS_CONTAINER_ZONES ?? "").split(",").includes(job.zone);
}


export async function publishCzdsJob(env, jobId) {
  const job = await env.CONTROL.prepare(
    "SELECT zone, state FROM czds_jobs WHERE job_id = ?",
  ).bind(jobId).first();
  if (job === null) throw new Error("CZDS job does not exist");
  if (job.state === "complete") return { state: "complete", duplicate: true };
  if (job.state !== "staged") throw new Error("CZDS job is not staged");
  if (env.COMPACTION_QUEUE === undefined) {
    throw new Error("COMPACTION_QUEUE is not configured");
  }
  let lastChunk = -1;
  let published = 0;
  while (true) {
    const page = await env.CONTROL.prepare(
      `SELECT chunk_index, delta_id, object_key FROM czds_job_deltas
       WHERE job_id = ? AND chunk_index > ? ORDER BY chunk_index LIMIT 100`,
    ).bind(jobId, lastChunk).all();
    if (page.results.length === 0) break;
    await env.COMPACTION_QUEUE.sendBatch(page.results.map((delta) => ({
      body: {
        schema_version: DELTA_READY_SCHEMA_VERSION,
        delta_id: delta.delta_id,
        source_kind: "czds",
        object_key: delta.object_key,
      },
    })));
    published += page.results.length;
    lastChunk = page.results.at(-1).chunk_index;
  }
  if (published === 0) throw new Error("CZDS job has no staged deltas");
  const now = new Date().toISOString();
  await env.CONTROL.batch([
    env.CONTROL.prepare(
      `UPDATE czds_jobs SET state = 'complete', error = NULL, updated_at = ?
       WHERE job_id = ?`,
    ).bind(now, jobId),
    env.CONTROL.prepare(
      `UPDATE czds_zones
       SET last_completed_at = ?, last_modified = (
         SELECT source_fingerprint FROM czds_jobs WHERE job_id = ?
       ), updated_at = ? WHERE zone = ?`,
    ).bind(now, jobId, now, job.zone),
  ]);
  return { state: "complete", duplicate: false, deltas: published };
}


export async function finishCzdsWorkflow(env, jobId) {
  if (env.CZDS_STAGE_ONLY !== "true") return publishCzdsJob(env, jobId);
  const job = await env.CONTROL.prepare(
    "SELECT state, delta_count, hostname_count FROM czds_jobs WHERE job_id = ?",
  ).bind(jobId).first();
  if (job?.state !== "staged" || !Number.isSafeInteger(job.delta_count) ||
      job.delta_count < 1 || !Number.isSafeInteger(job.hostname_count) ||
      job.hostname_count < 1) {
    throw new Error("CZDS job is not fully staged");
  }
  return { state: "staged", deltaCount: job.delta_count, hostnameCount: job.hostname_count };
}


export async function failCzdsJob(env, jobId, error) {
  await env.CONTROL.prepare(
    `UPDATE czds_jobs SET state = 'failed', error = ?, updated_at = ?
     WHERE job_id = ? AND state != 'complete'`,
  ).bind(String(error).slice(0, 1000), new Date().toISOString(), jobId).run();
}
