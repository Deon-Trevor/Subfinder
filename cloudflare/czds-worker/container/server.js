import { createServer } from "node:http";
import { Readable } from "node:stream";
import { createGunzip } from "node:zlib";
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";

import { zoneRecord } from "../src/core.js";


const INTERNAL_URL = "http://czds.internal";


export async function postInternal(path, body, send = fetch) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    try {
      const response = await send(`${INTERNAL_URL}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (response.ok) return await response.json();
      const payload = await response.json().catch(() => ({}));
      const detail = typeof payload.detail === "string" ? payload.detail.slice(0, 500) : "";
      if (path !== "/chunk" ||
          (response.status !== 429 && response.status < 500) || attempt === 3) {
        throw new Error(`CZDS ${path} rejected with HTTP ${response.status}: ${detail}`);
      }
    } catch (error) {
      if (path !== "/chunk" || attempt === 3 ||
          (error instanceof Error && error.message.startsWith("CZDS "))) throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 250 * 2 ** attempt));
  }
}


async function* countedBytes(body, count) {
  for await (const chunk of Readable.fromWeb(body)) {
    count.value += chunk.length;
    yield chunk;
  }
}


async function decodedZone(body, count) {
  if (body === null) throw new Error("CZDS zone response has no body");
  const iterator = countedBytes(body, count)[Symbol.asyncIterator]();
  const header = [];
  let headerLength = 0;
  while (headerLength < 2) {
    const next = await iterator.next();
    if (next.done) break;
    header.push(next.value);
    headerLength += next.value.length;
  }
  if (headerLength === 0) throw new Error("CZDS zone response is empty");
  const magic = Buffer.concat(header);
  const input = Readable.from((async function* () {
    yield* header;
    for await (const chunk of { [Symbol.asyncIterator]: () => iterator }) yield chunk;
  })());
  return magic[0] === 0x1f && magic[1] === 0x8b
    ? input.pipe(createGunzip())
    : input;
}


export async function processZone(job, { download = fetch, post = postInternal } = {}) {
  const response = await download(job.url, {
    headers: {
      accept: "application/x-gzip,application/octet-stream",
      authorization: `Bearer ${job.token}`,
      "user-agent": "subfinder-czds/1.0",
    },
  });
  if (!response.ok) throw new Error(`CZDS zone download returned HTTP ${response.status}`);
  const fingerprint = [
    response.headers.get("etag") ?? "",
    response.headers.get("last-modified") ?? "",
    response.headers.get("content-length") ?? "",
  ].join("|");
  if (fingerprint === "||") {
    throw new Error("CZDS zone response has no stable artifact fingerprint");
  }
  await post("/begin", { job_id: job.job_id, fingerprint });

  const count = { value: 0 };
  const stream = await decodedZone(response.body, count);
  const lines = createInterface({ input: stream, crlfDelay: Infinity });
  let previousOwner = null;
  let chunkIndex = 0;
  let hostnameCount = 0;
  let records = new Map();
  const flush = async () => {
    const values = [...records.values()].sort((left, right) => (
      left.apex.localeCompare(right.apex) || left.hostname.localeCompare(right.hostname)
    ));
    await post("/chunk", {
      job_id: job.job_id,
      chunk_index: chunkIndex,
      records: values,
    });
    hostnameCount += values.length;
    chunkIndex += 1;
    records = new Map();
  };
  for await (const line of lines) {
    const parsed = zoneRecord(line, job.zone, previousOwner);
    previousOwner = parsed.previousOwner;
    if (parsed.record === null) continue;
    records.set(parsed.record.hostname, parsed.record);
    if (records.size >= job.max_records) await flush();
  }
  if (records.size > 0) await flush();
  if (chunkIndex === 0) throw new Error("CZDS zone produced no registrable NS owners");
  const expected = Number(response.headers.get("content-length"));
  if (response.headers.has("content-length") &&
      !response.headers.has("content-encoding") && count.value !== expected) {
    throw new Error("CZDS zone download length does not match the artifact");
  }
  return await post("/complete", {
    job_id: job.job_id,
    chunk_count: chunkIndex,
    hostname_count: hostnameCount,
  });
}


export function createParserServer({ process = processZone } = {}) {
  let current = { state: "idle" };
  return createServer(async (request, response) => {
    const send = (status, body) => {
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify(body));
    };
    if (request.method === "GET" && request.url === "/status") {
      return send(200, current);
    }
    if (request.method !== "POST" || request.url !== "/start") {
      return send(404, { detail: "not found" });
    }
    let body = "";
    for await (const part of request) {
      body += part;
      if (body.length > 16384) return send(413, { detail: "job request is too large" });
    }
    let job;
    try {
      job = JSON.parse(body);
      if (!/^[a-f0-9]{64}$/.test(job.job_id) ||
          !/^[a-z0-9-]+$/.test(job.zone) ||
          typeof job.url !== "string" || typeof job.token !== "string" ||
          !Number.isSafeInteger(job.max_records) || job.max_records < 1) {
        throw new Error("job request is invalid");
      }
    } catch {
      return send(400, { detail: "job request is invalid" });
    }
    if (current.state === "running") return send(202, { state: "running" });
    if (current.state === "staged") return send(200, current);
    current = { state: "running" };
    process(job).then(
      (result) => { current = result; },
      (error) => { current = { state: "failed", error: String(error) }; },
    );
    return send(202, { state: "running" });
  });
}


if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  createParserServer().listen(8080, "0.0.0.0");
}
