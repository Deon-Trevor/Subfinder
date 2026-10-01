import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import { after, before, test } from "node:test";

import {
  Client,
  StreamableHTTPClientTransport,
} from "@modelcontextprotocol/client";
import { createMiniflare } from "./miniflare.js";
import { docsPage, locateApex } from "../src/index.js";


const workerRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(workerRoot, "../..");
const fixtureRoot = mkdtempSync(join(tmpdir(), "subfinder-r2-worker-"));
let miniflare;


function* files(directory) {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) yield* files(path);
    else yield path;
  }
}


async function uploadFixture(worker) {
  const bucket = await worker.getR2Bucket("CATALOG");
  for (const path of files(fixtureRoot)) {
    const key = relative(fixtureRoot, path).split(sep).join("/");
    await bucket.put(key, readFileSync(path));
  }
}


before(async () => {
  execFileSync(
    resolve(repositoryRoot, ".venv/bin/python"),
    [resolve(workerRoot, "test/build_fixture.py"), fixtureRoot],
    { stdio: "inherit" },
  );
  miniflare = createMiniflare(workerRoot);
  await uploadFixture(miniflare);
});


after(async () => {
  await miniflare?.dispose();
  rmSync(fixtureRoot, { recursive: true, force: true });
});


test("search preserves pagination, counts, and cursor order", async () => {
  const first = await miniflare.dispatchFetch(
    "http://worker.test/v1/search?apex=example.com&format=json&dates=1&limit=2",
  );
  assert.equal(first.status, 200);
  assert.equal(first.headers.get("x-result-total"), "3");
  assert.equal(first.headers.get("x-result-dated-total"), "2");
  assert.equal(first.headers.get("x-result-truncated"), "true");
  assert.deepEqual(await first.json(), [
    { first_seen: "2020-01-01T00:00:00Z", sub: "old.example.com" },
    { first_seen: "2025-01-01T00:00:00Z", sub: "new.example.com" },
  ]);

  const cursor = first.headers.get("x-next-cursor");
  assert.ok(cursor);
  const second = await miniflare.dispatchFetch(
    `http://worker.test/v1/search?apex=example.com&format=json&dates=1&limit=2&cursor=${cursor}`,
  );
  assert.equal(second.headers.get("x-result-truncated"), "false");
  assert.deepEqual(await second.json(), [
    { first_seen: null, sub: "unknown.example.com" },
  ]);
});


test("overflow apex streams every ordered record", async () => {
  const response = await miniflare.dispatchFetch(
    "http://worker.test/v1/search?apex=large.dev&format=json&dates=1",
  );
  const records = await response.json();

  assert.equal(response.status, 200);
  assert.equal(response.headers.get("x-result-total"), "80");
  assert.equal(response.headers.get("x-result-truncated"), "false");
  assert.equal(records.length, 80);
  assert.deepEqual(records[0], {
    first_seen: "2026-01-01T00:00:00Z",
    sub: "node-000.large.dev",
  });
  assert.deepEqual(records.at(-1), {
    first_seen: "2026-01-28T00:00:00Z",
    sub: "node-055.large.dev",
  });
});


test("records preserves provenance and missing apexes stay empty", async () => {
  const response = await miniflare.dispatchFetch(
    "http://worker.test/v1/records?apex=example.com",
  );
  const document = await response.json();
  assert.equal(document.schema_version, "subfinder.index-records.v1");
  assert.equal(document.records.length, 3);
  assert.deepEqual(
    document.records[0].sources.map((source) => source.source),
    ["czds:com", "static_ct:test"],
  );

  const missing = await miniflare.dispatchFetch(
    "http://worker.test/v1/search?apex=missing.dev&format=json",
  );
  assert.deepEqual(await missing.json(), []);
  assert.equal(missing.headers.get("x-result-total"), "0");
});


test("stats comes from the exported generation", async () => {
  const response = await miniflare.dispatchFetch("http://worker.test/v1/stats");
  const stats = await response.json();
  assert.equal(stats.apex_count, 3);
  assert.equal(stats.hostname_count, 84);
  assert.equal(stats.dated_hostname_count, 82);
  assert.equal(stats.source_count, 2);
  assert.equal(stats.ct_hostname_count, 1);
  assert.equal(stats.ct_log_count, 1);
});


test("unchanged partitions remain readable through a later root generation", async () => {
  const worker = createMiniflare(workerRoot);
  try {
    await uploadFixture(worker);
    const bucket = await worker.getR2Bucket("CATALOG");
    const original = await (await bucket.get("catalog/root.json")).json();
    const inherited = {
      ...original,
      generation: "next-generation",
      partitions: Object.fromEntries(Object.entries(original.partitions).map(
        ([prefix, metadata]) => [prefix, {
          ...metadata,
          origin_generation: original.generation,
        }],
      )),
    };
    await bucket.put("catalog/root.json", JSON.stringify(inherited));
    const response = await worker.dispatchFetch(
      "http://worker.test/v1/search?apex=example.com&format=json",
    );
    assert.equal(response.status, 200);
    assert.equal((await response.json()).length, 3);
  } finally {
    await worker.dispose();
  }
});


test("batch partition cache reuses verified indexes without hiding a changed root", async () => {
  const root = JSON.parse(readFileSync(join(fixtureRoot, "catalog/root.json")));
  const overrides = new Map();
  let indexGets = 0;
  const env = { CATALOG: { get: async (key, options) => {
    if (!options?.range) indexGets += 1;
    const stored = overrides.get(key) ?? readFileSync(join(fixtureRoot, key));
    const { offset = 0, length = stored.length } = options?.range ?? {};
    return { body: true, arrayBuffer: async () => (
      Uint8Array.from(stored.subarray(offset, offset + length)).buffer
    ) };
  } } };
  const cache = new Map();
  const first = await locateApex(env, "example.com", root, cache);
  const repeated = await locateApex(env, "example.com", root, cache);
  assert.equal(first.total, 3);
  assert.deepEqual(repeated.records, first.records);
  assert.equal(indexGets, 1);

  const prefix = createHash("sha256").update("example.com").digest("hex")
    .slice(0, root.partition_nibbles);
  const metadata = root.partitions[prefix];
  const copiedKey = `catalog/test/${prefix}.index.json.gz`;
  overrides.set(copiedKey, readFileSync(join(fixtureRoot, metadata.index)));
  const changed = { ...root, partitions: { ...root.partitions,
    [prefix]: { ...metadata, index: copiedKey } } };
  assert.equal((await locateApex(env, "example.com", changed, cache)).total, 3);
  assert.equal(indexGets, 2);

  const wrongGeneration = { ...root, generation: "incorrect-generation" };
  await assert.rejects(locateApex(env, "example.com", wrongGeneration, cache),
    /partition index identity mismatch/);

  const badKey = `catalog/test/${prefix}.bad.index.json.gz`;
  overrides.set(badKey, Buffer.from("bad index"));
  const corrupt = { ...root, partitions: { ...root.partitions,
    [prefix]: { ...metadata, index: badKey } } };
  await assert.rejects(locateApex(env, "example.com", corrupt, cache),
    /partition index checksum mismatch/);
});


test("health is data-independent and readiness identifies the active generation", async () => {
  const health = await miniflare.dispatchFetch("http://worker.test/health");
  assert.equal(health.status, 200);
  assert.equal(await health.text(), "ok");

  const ready = await miniflare.dispatchFetch("http://worker.test/ready");
  assert.equal(ready.status, 200);
  assert.deepEqual(await ready.json(), {
    status: "ready",
    generation: "worker-fixture",
    hostname_count: 84,
    last_ingest_at: null,
  });
});


test("enrichment routes preserve quota, idempotency, and private status", async () => {
  let submissions = 0;
  const jobs = new Map();
  const worker = createMiniflare(workerRoot, {
    serviceHandler: async (request) => {
      const path = new URL(request.url).pathname;
      if (path === "/internal/enrichment-options") {
        return Response.json({ schema_version: "subfinder.enrichment-options.v1",
          actions: { local_zone: { actionable: false }, urlscan: { actionable: true } } });
      }
      if (path === "/internal/enrichment-jobs" && request.method === "POST") {
        submissions += 1;
        const body = await request.json();
        if (body.apex === "blocked.com") {
          return Response.json({ detail: "already queued" }, { status: 409 });
        }
        jobs.set(body.job_id, body.apex);
        return Response.json({ job_id: body.job_id, apex: body.apex, state: "queued" },
          { status: 202, headers: { Location: `/v1/enrichment-jobs/${body.job_id}` } });
      }
      if (path.startsWith("/internal/enrichment-jobs/")) {
        assert.equal(request.headers.get("X-Subfinder-Subject"), "ip:127.0.0.1");
        const jobId = path.split("/").at(-1);
        return jobs.has(jobId)
          ? Response.json({ job_id: jobId, apex: jobs.get(jobId), state: "running" })
          : Response.json({ detail: "not found" }, { status: 404 });
      }
      return Response.json({ detail: "not found" }, { status: 404 });
    },
  });
  try {
    const options = await worker.dispatchFetch(
      "http://worker.test/v1/enrichment-options?apex=example.com",
    );
    assert.equal(options.status, 200);
    assert.equal((await options.json()).actions.urlscan.actionable, true);

    const submit = (apex, actions = ["urlscan"], key = "same-key") => worker.dispatchFetch(
      "http://worker.test/v1/enrichment-jobs", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify({ apex, actions }),
      },
    );
    const first = await submit("example.com");
    assert.equal(first.status, 202);
    const firstRemaining = first.headers.get("X-RateLimit-Remaining");
    const job = await first.json();
    assert.match(job.job_id, /^[a-f0-9]{64}$/);
    const replay = await submit("example.com");
    assert.equal(replay.status, 202);
    assert.equal(replay.headers.get("X-Idempotent-Replay"), "1");
    assert.equal(submissions, 1);
    assert.equal((await submit("example.net")).status, 409);
    assert.equal(submissions, 1);
    assert.equal((await submit("example.com", ["local_zone"])).status, 409);
    const blocked = await submit("blocked.com", ["urlscan"], "blocked-key");
    assert.equal(blocked.status, 409);
    assert.equal(blocked.headers.get("X-RateLimit-Remaining"), firstRemaining);
    const next = await submit("example.net", ["urlscan"], "next-key");
    assert.equal(next.status, 202);
    assert.equal(Number(next.headers.get("X-RateLimit-Remaining")), Number(firstRemaining) - 1);

    const status = await worker.dispatchFetch(
      `http://worker.test/v1/enrichment-jobs/${job.job_id}`,
    );
    assert.equal(status.status, 200);
    assert.equal((await status.json()).state, "running");
  } finally {
    await worker.dispose();
  }
});


test("queued enrichment retries its private Queue publish without a second charge", async () => {
  let job;
  let publishes = 0;
  const worker = createMiniflare(workerRoot, {
    serviceHandler: async (request) => {
      const path = new URL(request.url).pathname;
      if (request.method === "GET") {
        return job ? Response.json({ ...job, state: "queued" })
          : Response.json({ detail: "not found" }, { status: 404 });
      }
      job = await request.json();
      publishes += 1;
      return publishes === 1
        ? Response.json({ detail: "queue unavailable" }, { status: 503 })
        : Response.json({ ...job, state: "queued" }, { status: 202 });
    },
  });
  try {
    const submit = () => worker.dispatchFetch("http://worker.test/v1/enrichment-jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Idempotency-Key": "retry-key" },
      body: JSON.stringify({ apex: "example.com", actions: ["urlscan"] }),
    });
    const first = await submit();
    assert.equal(first.status, 503);
    const remaining = first.headers.get("X-RateLimit-Remaining");
    const second = await submit();
    assert.equal(second.status, 202);
    assert.equal(second.headers.get("X-RateLimit-Remaining"), remaining);
    assert.equal(publishes, 2);
  } finally {
    await worker.dispose();
  }
});


test("non-API GET and HEAD requests fall through to the static asset binding", async () => {
  const page = await miniflare.dispatchFetch("http://worker.test/");
  assert.equal(page.status, 200);
  assert.equal(await page.text(), "asset:/");

  const css = await miniflare.dispatchFetch("http://worker.test/app.css", {
    method: "HEAD",
  });
  assert.equal(css.status, 200);
  assert.equal(await css.text(), "");

  const post = await miniflare.dispatchFetch("http://worker.test/anything", {
    method: "POST",
  });
  assert.equal(post.status, 405);
});


test("docs proxy keeps the worker path and does not send credentials upstream", async () => {
  const origin = "https://subfinder-docs.pages.dev";
  const request = new Request("https://subfinder.pundit.workers.dev/docs/reference/api?x=1", {
    headers: { authorization: "Bearer private", cookie: "session=private", accept: "text/html" },
  });
  let destination;
  const response = await docsPage(request, { DOCS_ORIGIN: origin }, new URL(request.url),
    async (url, options) => {
      destination = url.toString();
      assert.equal(options.headers.get("authorization"), null);
      assert.equal(options.headers.get("cookie"), null);
      assert.equal(options.headers.get("accept"), "text/html");
      return new Response("docs", { headers: { "set-cookie": "origin=private" } });
    });
  assert.equal(destination, `${origin}/reference/api?x=1`);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), "docs");
  assert.equal(response.headers.get("set-cookie"), null);
  assert.equal(response.headers.get("x-robots-tag"), "noindex");

  const assetRequest = new Request(
    "https://subfinder.pundit.workers.dev/docs/assets/style.ABC12345.css",
  );
  const asset = await docsPage(assetRequest, { DOCS_ORIGIN: origin },
    new URL(assetRequest.url), async () => new Response("css"));
  assert.equal(asset.headers.get("cache-control"),
    "public, max-age=31536000, immutable");
  assert.equal(asset.headers.get("x-robots-tag"), "noindex");
  const unversionedRequest = new Request(
    "https://subfinder.pundit.workers.dev/docs/assets/custom.css",
  );
  const unversioned = await docsPage(unversionedRequest, { DOCS_ORIGIN: origin },
    new URL(unversionedRequest.url), async () => new Response("css"));
  assert.equal(unversioned.headers.get("cache-control"), null);

  const productionRequest = new Request("https://subfinder.syncpundit.io/docs/");
  const production = await docsPage(productionRequest, { DOCS_ORIGIN: origin },
    new URL(productionRequest.url), async () => new Response("docs", {
      headers: { "x-robots-tag": "noindex" },
    }));
  assert.equal(production.headers.get("x-robots-tag"), null);

  const slash = await docsPage(new Request("https://subfinder.pundit.workers.dev/docs"),
    { DOCS_ORIGIN: origin }, new URL("https://subfinder.pundit.workers.dev/docs"));
  assert.equal(slash.status, 308);
  assert.equal(slash.headers.get("location"), "https://subfinder.pundit.workers.dev/docs/");

  for (const path of [
    "/docs/operations/cloudflare",
    "/docs/operations/cloudflare.html",
    "/docs/operations/compose",
    "/docs/operations/compose.html",
    "/docs/assets/operations_cloudflare.md.ABC12345.js",
    "/docs/assets/operations_compose.md.ABC12345.js",
  ]) {
    const request = new Request(`https://subfinder.syncpundit.io${path}`);
    const allowed = await docsPage(request, { DOCS_ORIGIN: origin },
      new URL(request.url), async () => new Response("public docs"));
    assert.equal(allowed.status, 200, path);
  }
  for (const operation of [
    "source-refresh",
    "staging-reconciliation",
    "staging-compaction",
    "staging-cost",
    "next-czds-batch",
    "czds-stage-sweep",
    "cutover-acceptance",
  ]) for (const path of [
    `/docs/operations/${operation}`,
    `/docs/operations/${operation}/`,
    `/docs/operations/${operation}.html`,
    `/docs/assets/operations_${operation}.md.ABC12345.lean.js`,
  ]) {
    const request = new Request(`https://subfinder.syncpundit.io${path}`);
    const blocked = await docsPage(request, { DOCS_ORIGIN: origin },
      new URL(request.url), async () => { throw new Error("blocked docs reached Pages"); });
    assert.equal(blocked.status, 404, path);
    assert.equal(blocked.headers.get("cache-control"), "no-store");
  }
});


test("HTTP search and records share one exact public allowance", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      LOCAL_CLIENT_IP: "quota-test",
      PUBLIC_REQUEST_LIMIT: "2",
    },
  });
  try {
    await uploadFixture(worker);
    const first = await worker.dispatchFetch(
      "http://worker.test/v1/search?apex=example.com",
    );
    const second = await worker.dispatchFetch(
      "http://worker.test/v1/records?apex=example.com",
    );
    const exhausted = await worker.dispatchFetch(
      "http://worker.test/v1/search?apex=example.com",
    );
    assert.equal(first.headers.get("x-ratelimit-remaining"), "1");
    assert.equal(second.headers.get("x-ratelimit-remaining"), "0");
    assert.equal(exhausted.status, 429);
    assert.equal(exhausted.headers.get("x-ratelimit-limit"), "2");
    assert.ok(Number(exhausted.headers.get("retry-after")) > 0);
  } finally {
    await worker.dispose();
  }
});


test("concurrent requests cannot overrun the exact daily allowance", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      LOCAL_CLIENT_IP: "quota-concurrency-test",
      PUBLIC_REQUEST_LIMIT: "2",
    },
  });
  try {
    await uploadFixture(worker);
    const responses = await Promise.all(
      Array.from({ length: 10 }, () => worker.dispatchFetch(
        "http://worker.test/v1/search?apex=example.com",
      )),
    );
    assert.equal(responses.filter((response) => response.status === 200).length, 2);
    assert.equal(responses.filter((response) => response.status === 429).length, 8);
  } finally {
    await worker.dispose();
  }
});


test("MCP exposes only search and shares the HTTP allowance", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      LOCAL_CLIENT_IP: "mcp-quota-test",
      PUBLIC_REQUEST_LIMIT: "2",
    },
  });
  const client = new Client(
    { name: "subfinder-worker-test", version: "1.0.0" },
  );
  try {
    await uploadFixture(worker);
    const first = await worker.dispatchFetch(
      "http://worker.test/v1/search?apex=example.com",
    );
    assert.equal(first.status, 200);

    const transport = new StreamableHTTPClientTransport(
      new URL("http://worker.test/mcp"),
      { fetch: (input, init) => worker.dispatchFetch(input, init) },
    );
    await client.connect(transport);
    const listed = await client.listTools();
    const result = await client.callTool({
      name: "search",
      arguments: { apex: "example.com" },
    });
    assert.deepEqual(listed.tools.map((tool) => tool.name), ["search"]);
    assert.deepEqual(result.structuredContent, {
      result: ["old.example.com", "new.example.com", "unknown.example.com"],
    });

    const exhausted = await worker.dispatchFetch(
      "http://worker.test/v1/search?apex=example.com",
    );
    assert.equal(exhausted.status, 429);
  } finally {
    await client.close();
    await worker.dispose();
  }
});


test("MCP accepts the preview and production hosts but rejects an unlisted host", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      MCP_ALLOWED_HOSTS: "127.0.0.1,subfinder.pundit.workers.dev,subfinder.syncpundit.io",
    },
  });
  try {
    for (const hostname of ["subfinder.pundit.workers.dev", "subfinder.syncpundit.io"]) {
      const client = new Client({ name: "host-allowlist-test", version: "1.0.0" });
      try {
        const transport = new StreamableHTTPClientTransport(
          new URL(`https://${hostname}/mcp`),
          { fetch: (input, init) => worker.dispatchFetch(input, init) },
        );
        await client.connect(transport);
        assert.deepEqual((await client.listTools()).tools.map((tool) => tool.name), ["search"]);
      } finally {
        await client.close();
      }
    }
    const unlisted = await worker.dispatchFetch("https://evil.test/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(unlisted.status, 400);
  } finally {
    await worker.dispose();
  }
});


test("MCP rejects untrusted hosts and origins before protocol handling", async () => {
  const worker = createMiniflare(workerRoot);
  try {
    const untrustedHost = await worker.dispatchFetch("http://evil.test/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const untrustedOrigin = await worker.dispatchFetch("http://worker.test/mcp", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "https://evil.test",
      },
      body: "{}",
    });
    assert.equal(untrustedHost.status, 400);
    assert.equal(untrustedOrigin.status, 403);
  } finally {
    await worker.dispose();
  }
});


test("MCP fails closed when its host allowlist is missing", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: { MCP_ALLOWED_HOSTS: "" },
  });
  try {
    const response = await worker.dispatchFetch("http://worker.test/mcp", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    assert.equal(response.status, 503);
  } finally {
    await worker.dispose();
  }
});


test("valid tokens have a separate allowance and invalid tokens stay public", async () => {
  const headers = { Authorization: "Bearer threat-hunter-test" };
  const authenticated = await miniflare.dispatchFetch(
    "http://worker.test/v1/search?apex=example.com",
    { headers },
  );
  const publicResponse = await miniflare.dispatchFetch(
    "http://worker.test/v1/search?apex=example.com",
    { headers: { Authorization: "Bearer invalid" } },
  );
  assert.equal(authenticated.status, 200);
  assert.equal(authenticated.headers.get("x-ratelimit-limit"), "3");
  assert.equal(authenticated.headers.get("x-ratelimit-remaining"), "2");
  assert.equal(publicResponse.status, 200);
  assert.equal(publicResponse.headers.get("x-ratelimit-limit"), "1000");
});


test("stats and readiness do not spend quota", async () => {
  const stats = await miniflare.dispatchFetch("http://worker.test/v1/stats");
  const ready = await miniflare.dispatchFetch("http://worker.test/ready");
  assert.equal(stats.headers.get("x-ratelimit-limit"), null);
  assert.equal(ready.headers.get("x-ratelimit-limit"), null);
});


test("private batches require a token, validate first, and charge each apex", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      BATCH_MAX_APEXES: "3",
      BATCH_MAX_RECORDS: "10",
      CLIENT_TOKENS: JSON.stringify([{
        id: "threat-hunter",
        sha256: "e200c300499b48616df8fbe5a089e1eebf525e826ed03163a4868985d9123ccb",
        limit: 4,
      }]),
      LOCAL_CLIENT_IP: "batch-test",
    },
  });
  const request = (apexes, token = "threat-hunter-test") => worker.dispatchFetch(
    "http://worker.test/internal/v1/records/batch",
    {
      method: "POST",
      headers: {
        "authorization": `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ apexes }),
    },
  );
  try {
    await uploadFixture(worker);
    const missing = await worker.dispatchFetch(
      "http://worker.test/internal/v1/records/batch",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ apexes: ["example.com"] }),
      },
    );
    const forged = await request(["example.com"], "wrong");
    const empty = await request([]);
    const duplicate = await request(["example.com", "EXAMPLE.COM."]);
    const oversized = await request([
      "example.com",
      "example.net",
      "example.org",
      "example.dev",
    ]);
    const first = await request(["example.net", "example.com"]);
    const second = await request(["example.com", "example.net"]);
    const exhausted = await request(["example.com"]);

    assert.equal(missing.status, 401);
    assert.equal(missing.headers.get("www-authenticate"), "Bearer");
    assert.equal(forged.status, 401);
    assert.equal(empty.status, 400);
    assert.equal(duplicate.status, 400);
    assert.equal(oversized.status, 413);
    assert.equal(first.status, 200);
    assert.equal(first.headers.get("cache-control"), "no-store");
    assert.equal(first.headers.get("x-ratelimit-remaining"), "2");
    assert.equal(first.headers.get("x-batch-apex-count"), "2");
    const document = await first.json();
    assert.equal(
      document.schema_version,
      "subfinder.internal-index-records-batch.v1",
    );
    assert.deepEqual(document.results[0].records, []);
    assert.equal(document.results[1].records[0].hostname, "old.example.com");
    assert.equal(second.status, 200);
    assert.equal(second.headers.get("x-ratelimit-remaining"), "0");
    assert.equal(exhausted.status, 429);
  } finally {
    await worker.dispose();
  }
});


test("batch result bounds reject before quota is consumed", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      BATCH_MAX_RECORDS: "1",
      LOCAL_CLIENT_IP: "batch-result-bound-test",
    },
  });
  const headers = {
    "authorization": "Bearer threat-hunter-test",
    "content-type": "application/json",
  };
  try {
    await uploadFixture(worker);
    const rejected = await worker.dispatchFetch(
      "http://worker.test/internal/v1/records/batch",
      { method: "POST", headers, body: JSON.stringify({ apexes: ["example.com"] }) },
    );
    const accepted = await worker.dispatchFetch(
      "http://worker.test/internal/v1/records/batch",
      { method: "POST", headers, body: JSON.stringify({ apexes: ["missing.dev"] }) },
    );
    assert.equal(rejected.status, 413);
    assert.match((await rejected.json()).detail, /maximum is 1/);
    assert.equal(accepted.status, 200);
    assert.equal(accepted.headers.get("x-ratelimit-remaining"), "2");
  } finally {
    await worker.dispose();
  }
});


test("durable batches replay admission and deliver cursor-stable chunks", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      CLIENT_TOKENS: JSON.stringify([{
        id: "threat-hunter",
        sha256: "e200c300499b48616df8fbe5a089e1eebf525e826ed03163a4868985d9123ccb",
        limit: 10,
      }, {
        id: "other-client",
        sha256: createHash("sha256").update("other-client-test").digest("hex"),
        limit: 10,
      }]),
    },
  });
  const headers = {
    authorization: "Bearer threat-hunter-test",
    "content-type": "application/json",
    "idempotency-key": "th-test-batch",
  };
  try {
    await uploadFixture(worker);
    const base = "http://worker.test/internal/v1/record-batches";
    const body = JSON.stringify({ apexes: ["example.com", "example.net", "large.dev"] });
    const unauthorized = await worker.dispatchFetch(base, {
      method: "POST", headers: { "content-type": "application/json" }, body,
    });
    assert.equal(unauthorized.status, 401);
    const admitted = await worker.dispatchFetch(base, { method: "POST", headers, body });
    assert.equal(admitted.status, 202);
    assert.equal(admitted.headers.get("x-ratelimit-remaining"), "7");
    const job = await admitted.json();
    assert.equal(job.total_apexes, 3);
    assert.equal(job.state, "queued");
    const ordinaryRead = await worker.dispatchFetch(
      "http://worker.test/v1/records?apex=example.com",
      { headers },
    );
    assert.equal(ordinaryRead.status, 200);
    assert.equal(ordinaryRead.headers.get("x-ratelimit-remaining"), "6");
    const replay = await worker.dispatchFetch(base, { method: "POST", headers, body });
    assert.equal(replay.status, 202);
    assert.equal(replay.headers.get("x-idempotent-replay"), "1");
    assert.equal(replay.headers.get("x-ratelimit-remaining"), "6");
    assert.equal((await replay.json()).job_id, job.job_id);
    const conflict = await worker.dispatchFetch(base, {
      method: "POST", headers, body: JSON.stringify({ apexes: ["example.net"] }),
    });
    assert.equal(conflict.status, 409);
    const chunksUrl = `${base}/${job.job_id}/chunks`;
    let delivered;
    for (let attempt = 0; attempt < 50; attempt += 1) {
      const response = await worker.dispatchFetch(`${chunksUrl}?after=-1&limit=10&wait=0`, {
        headers,
      });
      assert.equal(response.status, 200);
      const payload = await response.json();
      if (payload.job.state === "done") {
        delivered = payload;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.ok(delivered, "durable batch did not finish");
    assert.equal(delivered.job.completed_apexes, 3);
    assert.equal(delivered.job.quota.committed, 3);
    assert.equal(delivered.chunks.reduce((count, chunk) => count + chunk.results.length, 0), 3);
    assert.deepEqual(delivered.chunks.flatMap((chunk) => chunk.results.map((item) => item.apex)),
      ["example.com", "example.net", "large.dev"]);
    assert.equal(delivered.chunks[0].results[0].records.length, 3);
    const next = await worker.dispatchFetch(
      `${chunksUrl}?after=${delivered.next_cursor}&limit=10`, { headers },
    );
    assert.deepEqual((await next.json()).chunks, []);
    const otherToken = await worker.dispatchFetch(chunksUrl, {
      headers: { authorization: "Bearer wrong" },
    });
    assert.equal(otherToken.status, 401);
    const otherClient = await worker.dispatchFetch(chunksUrl, {
      headers: { authorization: "Bearer other-client-test" },
    });
    assert.equal(otherClient.status, 404);
  } finally {
    await worker.dispose();
  }
});


test("a 25K batch admits atomically and cancellation releases outstanding quota", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      CLIENT_TOKENS: JSON.stringify([{
        id: "threat-hunter",
        sha256: "e200c300499b48616df8fbe5a089e1eebf525e826ed03163a4868985d9123ccb",
        limit: 25000,
      }]),
    },
  });
  const base = "http://worker.test/internal/v1/record-batches";
  const apexes = Array.from({ length: 25000 }, (_, index) => `batch-${index}.com`);
  const headers = {
    authorization: "Bearer threat-hunter-test",
    "content-type": "application/json",
    "idempotency-key": "th-25k",
  };
  try {
    await uploadFixture(worker);
    const body = JSON.stringify({ apexes });
    const oversized = await worker.dispatchFetch(base, {
      method: "POST", headers,
      body: JSON.stringify({ apexes: [...apexes, "extra.com"] }),
    });
    assert.equal(oversized.status, 413);
    const admitted = await worker.dispatchFetch(base, { method: "POST", headers, body });
    assert.equal(admitted.status, 202, await admitted.clone().text());
    const job = await admitted.json();
    assert.equal(job.total_apexes, 25000);
    assert.equal(admitted.headers.get("x-ratelimit-remaining"), "0");
    const overLimit = await worker.dispatchFetch(base, {
      method: "POST", headers: { ...headers, "idempotency-key": "th-over" },
      body: JSON.stringify({ apexes: ["example.com"] }),
    });
    assert.equal(overLimit.status, 429);
    const cancelled = await worker.dispatchFetch(`${base}/${job.job_id}/cancel`, {
      method: "POST", headers,
    });
    assert.equal(cancelled.status, 200);
    const closed = await cancelled.json();
    assert.equal(closed.state, "cancelled");
    assert.equal(closed.quota.reserved, 25000);
    assert.equal(closed.quota.outstanding, 0);
    const next = await worker.dispatchFetch(base, {
      method: "POST", headers: { ...headers, "idempotency-key": "th-after-cancel" },
      body: JSON.stringify({ apexes: ["example.com"] }),
    });
    assert.equal(next.status, 202);
  } finally {
    await worker.dispose();
  }
});


test("durable batch retries a transient catalog read without losing its cursor", async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      CLIENT_TOKENS: JSON.stringify([{
        id: "threat-hunter",
        sha256: "e200c300499b48616df8fbe5a089e1eebf525e826ed03163a4868985d9123ccb",
        limit: 3,
      }]),
    },
  });
  const headers = {
    authorization: "Bearer threat-hunter-test",
    "content-type": "application/json",
    "idempotency-key": "th-retry-catalog",
  };
  try {
    await uploadFixture(worker);
    const bucket = await worker.getR2Bucket("CATALOG");
    const root = await (await bucket.get("catalog/root.json")).json();
    const prefix = createHash("sha256").update("example.com").digest("hex")
      .slice(0, root.partition_nibbles);
    const key = root.partitions[prefix].index;
    const contents = readFileSync(resolve(fixtureRoot, key));
    await bucket.delete(key);
    const base = "http://worker.test/internal/v1/record-batches";
    const admitted = await worker.dispatchFetch(base, {
      method: "POST", headers, body: JSON.stringify({ apexes: ["example.com"] }),
    });
    assert.equal(admitted.status, 202);
    const job = await admitted.json();
    await new Promise((resolve) => setTimeout(resolve, 250));
    const pending = await worker.dispatchFetch(`${base}/${job.job_id}/chunks?after=-1`, {
      headers,
    });
    assert.deepEqual((await pending.json()).chunks, []);
    await bucket.put(key, contents);
    let completed;
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const response = await worker.dispatchFetch(`${base}/${job.job_id}/chunks?after=-1`, {
        headers,
      });
      const payload = await response.json();
      if (payload.job.state === "done") {
        completed = payload;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(completed, "batch did not recover after the index returned");
    assert.equal(completed.chunks.length, 1);
    assert.equal(completed.chunks[0].results[0].records.length, 3);
    assert.equal(completed.next_cursor, 0);
    assert.equal(completed.job.quota.committed, 1);
  } finally {
    await worker.dispose();
  }
});


test("a full 25K batch delivers every apex once", {
  skip: process.env.SUBFINDER_STRESS !== "1",
  timeout: 180000,
}, async () => {
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      CLIENT_TOKENS: JSON.stringify([{
        id: "threat-hunter",
        sha256: "e200c300499b48616df8fbe5a089e1eebf525e826ed03163a4868985d9123ccb",
        limit: 25000,
      }]),
    },
  });
  const base = "http://worker.test/internal/v1/record-batches";
  const apexes = Array.from({ length: 25000 }, (_, index) => `batch-${index}.com`);
  const headers = {
    authorization: "Bearer threat-hunter-test",
    "content-type": "application/json",
    "idempotency-key": "th-25k-full",
  };
  try {
    await uploadFixture(worker);
    const admitted = await worker.dispatchFetch(base, {
      method: "POST", headers, body: JSON.stringify({ apexes }),
    });
    assert.equal(admitted.status, 202);
    const job = await admitted.json();
    const seen = new Set();
    let cursor = -1;
    let finalState = "queued";
    const started = performance.now();
    while (performance.now() - started < 170000) {
      const response = await worker.dispatchFetch(
        `${base}/${job.job_id}/chunks?after=${cursor}&limit=50`, { headers },
      );
      assert.equal(response.status, 200);
      const payload = await response.json();
      finalState = payload.job.state;
      for (const chunk of payload.chunks) {
        for (const item of chunk.results) {
          assert.equal(seen.has(item.apex), false);
          seen.add(item.apex);
        }
      }
      cursor = payload.next_cursor;
      if (finalState === "done") break;
      assert.notEqual(finalState, "failed", payload.job.error);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(finalState, "done");
    assert.equal(seen.size, 25000);
    assert.equal(cursor, 249);
    console.log(JSON.stringify({ stress: "25k-durable-batch", ms: Math.round(
      performance.now() - started), chunks: cursor + 1 }));
  } finally {
    await worker.dispose();
  }
});
