import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

const PRODUCTION_ORIGIN = "https://subfinder.syncpundit.io";
const APEXES = ["cloudflare.com", "example.com", "syncpundit.io"];
const MISSING_APEX = "subfinder-cutover-absent-20260929.com";

function options(argv) {
  const result = { base: PRODUCTION_ORIGIN };
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!value || !["--base", "--sqlite", "--expect-generation"].includes(key)) {
      throw new Error("Usage: verify-cutover.js --sqlite CATALOG [--base PRODUCTION_URL] [--expect-generation ID]");
    }
    result[key.slice(2).replaceAll("-", "_")] = value;
  }
  if (!result.sqlite) throw new Error("--sqlite is required for source parity");
  const origin = new URL(result.base);
  if (origin.origin !== PRODUCTION_ORIGIN ||
      origin.pathname !== "/" || origin.search || origin.hash) {
    throw new Error("This harness only accepts the production hostname");
  }
  return { ...result, origin };
}

function baseline(database, apex) {
  const escaped = apex.replaceAll("'", "''");
  const rows = JSON.parse(execFileSync("sqlite3", [
    "-readonly", "-json", database,
    `SELECT subdomain AS hostname FROM subdomains WHERE apex = '${escaped}' ORDER BY subdomain`,
  ], { encoding: "utf8" }) || "[]");
  return rows.map((row) => row.hostname);
}

async function get(origin, path, init = {}) {
  const started = performance.now();
  const response = await fetch(new URL(path, origin), {
    ...init,
    signal: AbortSignal.timeout(30000),
  });
  return { response, ms: Math.round(performance.now() - started) };
}

function requireQuota(response) {
  for (const name of ["x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"]) {
    assert.match(response.headers.get(name) ?? "", /^\d+$/, `${name} must be present`);
  }
}

async function searchAll(origin, apex) {
  const found = [];
  let cursor;
  let total;
  let pageCount = 0;
  let maxMs = 0;
  do {
    const url = new URL("/v1/search", origin);
    url.searchParams.set("apex", apex);
    url.searchParams.set("format", "json");
    url.searchParams.set("dates", "1");
    url.searchParams.set("limit", "250");
    if (cursor) url.searchParams.set("cursor", cursor);
    const { response, ms } = await get(origin, url.pathname + url.search);
    maxMs = Math.max(maxMs, ms);
    assert.equal(response.status, 200, `${apex} search HTTP ${response.status}`);
    requireQuota(response);
    const page = await response.json();
    assert.ok(Array.isArray(page));
    assert.ok(page.length <= 250);
    assert.equal(Number(response.headers.get("x-result-page-size")), page.length);
    const reported = Number(response.headers.get("x-result-total"));
    assert.ok(Number.isSafeInteger(reported) && reported >= 0);
    if (total === undefined) total = reported;
    else assert.equal(reported, total, `${apex} total changed during pagination`);
    for (const row of page) {
      assert.equal(typeof row.sub, "string");
      assert.ok(row.sub === apex || row.sub.endsWith(`.${apex}`), `${apex} leaked another apex`);
      found.push(row.sub);
    }
    const truncated = response.headers.get("x-result-truncated");
    assert.ok(["true", "false"].includes(truncated));
    cursor = response.headers.get("x-next-cursor") ?? undefined;
    assert.equal(Boolean(cursor), truncated === "true");
    pageCount += 1;
    assert.ok(pageCount <= 100, `${apex} exceeded bounded pagination`);
  } while (cursor);
  assert.equal(found.length, total);
  assert.equal(new Set(found).size, found.length, `${apex} duplicated a hostname`);
  return { hostnames: found, pages: pageCount, max_page_ms: maxMs };
}

async function main() {
  const { origin, sqlite, expect_generation: expected } = options(process.argv.slice(2));
  const checks = {};
  const health = await get(origin, "/health");
  assert.equal(health.response.status, 200);
  assert.equal(await health.response.text(), "ok");
  checks.health_ms = health.ms;

  const ready = await get(origin, "/ready");
  assert.equal(ready.response.status, 200);
  const readiness = await ready.response.json();
  assert.equal(readiness.status, "ready");
  assert.equal(typeof readiness.generation, "string");
  if (expected) assert.equal(readiness.generation, expected, "active generation differs from cutover target");
  const stats = await get(origin, "/v1/stats");
  assert.equal(stats.response.status, 200);
  const summary = await stats.response.json();
  assert.equal(summary.hostname_count, readiness.hostname_count);
  checks.generation = readiness.generation;
  checks.hostname_count = summary.hostname_count;

  const home = await get(origin, "/");
  assert.equal(home.response.status, 200);
  assert.match(await home.response.text(), /href=["']\/docs\/["']/);
  const docs = await get(origin, "/docs/");
  assert.equal(docs.response.status, 200);
  assert.match(docs.response.headers.get("content-type") ?? "", /text\/html/);
  checks.docs_ms = docs.ms;

  const apexChecks = {};
  for (const apex of APEXES) {
    const source = baseline(sqlite, apex);
    assert.ok(source.length > 0, `${apex} source baseline is empty`);
    const search = await searchAll(origin, apex);
    const response = await get(origin, `/v1/records?apex=${apex}`);
    assert.equal(response.response.status, 200);
    requireQuota(response.response);
    const document = await response.response.json();
    assert.equal(document.schema_version, "subfinder.index-records.v1");
    assert.equal(document.apex, apex);
    assert.ok(Array.isArray(document.records));
    const recordHosts = document.records.map((record) => {
      assert.ok(Array.isArray(record.sources));
      return record.hostname;
    });
    assert.deepEqual(new Set(recordHosts), new Set(search.hostnames), `${apex} records/search mismatch`);
    const live = new Set(recordHosts);
    for (const hostname of source) assert.ok(live.has(hostname), `${apex} lost a seed hostname`);
    if (readiness.generation === "seed-20260927") {
      assert.equal(live.size, source.length, `${apex} seed count changed`);
    }
    apexChecks[apex] = {
      source_count: source.length,
      served_count: live.size,
      pages: search.pages,
      max_page_ms: search.max_page_ms,
      records_ms: response.ms,
    };
  }
  checks.apexes = apexChecks;

  const missing = await searchAll(origin, MISSING_APEX);
  assert.equal(missing.hostnames.length, 0);
  const invalid = await get(origin, "/v1/search?apex=co.uk");
  assert.equal(invalid.response.status, 400, "public suffix must be rejected");
  const cursor = await get(origin, "/v1/search?apex=example.com&limit=2&cursor=invalid");
  assert.equal(cursor.response.status, 400, "invalid cursor must be rejected");
  const unauthorized = await get(origin, "/internal/v1/record-batches/nonexistent");
  assert.equal(unauthorized.response.status, 401);
  const wrongToken = await get(origin, "/internal/v1/record-batches/nonexistent", {
    headers: { authorization: "Bearer invalid-cutover-token" },
  });
  assert.equal(wrongToken.response.status, 401);
  checks.negative_cases = "passed";
  const token = process.env.SUBFINDER_CUTOVER_TOKEN;
  if (token) {
    const authorized = await get(origin, "/internal/v1/record-batches/nonexistent", {
      headers: { authorization: `Bearer ${token}` },
    });
    assert.equal(authorized.response.status, 404,
      "valid token must reach the private ledger without creating a job");
    checks.valid_token = "passed";
  } else {
    checks.valid_token = "not_evaluated";
  }

  const client = new Client({ name: "subfinder-cutover-check", version: "1.0.0" });
  try {
    await client.connect(new StreamableHTTPClientTransport(new URL("/mcp", origin)));
    const listed = await client.listTools();
    assert.deepEqual(listed.tools.map((tool) => tool.name), ["search"]);
    const result = await client.callTool({ name: "search", arguments: { apex: "example.com" } });
    const mcpHosts = new Set(result.structuredContent.result);
    assert.equal(mcpHosts.size, apexChecks["example.com"].served_count);
    for (const hostname of baseline(sqlite, "example.com")) {
      assert.ok(mcpHosts.has(hostname), "MCP lost a seed hostname");
    }
  } finally {
    await client.close();
  }
  checks.mcp = "passed";
  checks.expected_generation = expected ? "passed" : "not_evaluated";
  checks.live_25k_batch = "not_evaluated";
  console.log(JSON.stringify({ status: "passed", origin: origin.origin, checks }, null, 2));
}

main().catch((error) => {
  console.error(JSON.stringify({ status: "failed", reason: error.message }));
  process.exitCode = 1;
});
