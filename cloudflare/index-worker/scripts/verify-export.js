import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve, sep } from "node:path";

import { createMiniflare } from "../test/miniflare.js";

const MISSING_APEX = "not-present-subfinder-verifier.com";


function* files(directory) {
  for (const name of readdirSync(directory)) {
    const path = resolve(directory, name);
    if (statSync(path).isDirectory()) yield* files(path);
    else yield path;
  }
}


function parseExpectations(values) {
  return values.map((value) => {
    const split = value.lastIndexOf("=");
    if (split < 1) throw new Error(`expected apex=count, got ${value}`);
    const apex = value.slice(0, split);
    const count = Number(value.slice(split + 1));
    if (!Number.isInteger(count) || count < 0) {
      throw new Error(`expected a non-negative count, got ${value}`);
    }
    return { apex, count };
  });
}


function sqliteRecords(database, apex) {
  const quoted = `'${apex.replaceAll("'", "''")}'`;
  const query = `SELECT names.subdomain AS hostname, names.first_seen,
    evidence.source, evidence.first_seen AS source_first_seen, evidence.last_seen
    FROM subdomains AS names
    LEFT JOIN subdomain_sources AS evidence
      ON evidence.apex = names.apex AND evidence.subdomain = names.subdomain
    WHERE names.apex = ${quoted}
    ORDER BY names.subdomain, evidence.source`;
  const rows = JSON.parse(execFileSync("sqlite3", ["-readonly", "-json", database, query], {
    encoding: "utf8",
  }) || "[]");
  const byHostname = new Map();
  for (const row of rows) {
    if (!byHostname.has(row.hostname)) {
      byHostname.set(row.hostname, {
        hostname: row.hostname, first_seen: row.first_seen, sources: [],
      });
    }
    if (row.source !== null) {
      byHostname.get(row.hostname).sources.push({
        source: row.source,
        first_seen: row.source_first_seen,
        last_seen: row.last_seen,
      });
    }
  }
  return [...byHostname.values()];
}


function canonicalRecords(records) {
  return records.map((record) => ({
    ...record,
    sources: [...record.sources].sort((left, right) =>
      left.source.localeCompare(right.source)),
  })).sort((left, right) => left.hostname.localeCompare(right.hostname));
}


function selectedFiles(directory, apexes) {
  const root = JSON.parse(readFileSync(resolve(directory, "catalog/root.json"), "utf8"));
  const keys = new Set(["catalog/root.json"]);
  for (const apex of apexes) {
    const prefix = createHash("sha256").update(apex).digest("hex")
      .slice(0, root.partition_nibbles);
    const partition = root.partitions[prefix];
    if (partition !== undefined) {
      keys.add(partition.index);
      keys.add(partition.bundle);
    }
  }
  return [...keys].map((key) => {
    const path = resolve(directory, key);
    if (!path.startsWith(`${directory}${sep}`)) {
      throw new Error(`export object path escapes its directory: ${key}`);
    }
    return path;
  });
}


async function seed(bucket, directory, selected) {
  let objectCount = 0;
  let bytes = 0;
  for (const path of selected ?? files(directory)) {
    const key = relative(directory, path).split(sep).join("/");
    const contents = readFileSync(path);
    await bucket.put(key, contents);
    objectCount += 1;
    bytes += contents.length;
  }
  return { object_count: objectCount, bytes };
}


async function searchAll(miniflare, apex, limit = 5000) {
  const records = [];
  const pageTimesMs = [];
  let cursor = null;
  let reportedTotal = null;
  do {
    const url = new URL("http://worker.test/v1/search");
    url.searchParams.set("apex", apex);
    url.searchParams.set("format", "json");
    url.searchParams.set("dates", "1");
    url.searchParams.set("limit", String(limit));
    if (cursor !== null) url.searchParams.set("cursor", cursor);
    const started = performance.now();
    const response = await miniflare.dispatchFetch(url);
    const page = await response.json();
    pageTimesMs.push(performance.now() - started);
    assert.equal(response.status, 200, JSON.stringify(page));
    const total = Number(response.headers.get("x-result-total"));
    if (reportedTotal === null) reportedTotal = total;
    assert.equal(total, reportedTotal);
    records.push(...page);
    cursor = response.headers.get("x-next-cursor");
  } while (cursor !== null);
  return { records, reportedTotal, pageTimesMs };
}


async function main() {
  let args = process.argv.slice(2);
  const selective = args[0] === "--selective";
  if (selective) args = args.slice(1);
  if (args[0] === "--sqlite" && !args[1]) throw new Error("--sqlite requires a database path");
  const sqliteDatabase = args[0] === "--sqlite" ? resolve(args[1]) : null;
  if (sqliteDatabase !== null) args = args.slice(2);
  const [directoryValue, ...expectationValues] = args;
  if (directoryValue === undefined || expectationValues.length === 0) {
    throw new Error(
      "usage: node scripts/verify-export.js [--selective] [--sqlite DB] EXPORT_DIR apex=count [apex=count ...]",
    );
  }
  const directory = resolve(directoryValue);
  const expectations = parseExpectations(expectationValues);
  const workerRoot = resolve(import.meta.dirname, "..");
  const miniflare = createMiniflare(workerRoot);

  try {
    const bucket = await miniflare.getR2Bucket("CATALOG");
    const seeded = await seed(bucket, directory, selective
      ? selectedFiles(directory, [...expectations.map((item) => item.apex), MISSING_APEX])
      : null);
    seeded.selective = selective;
    const health = await miniflare.dispatchFetch("http://worker.test/health");
    assert.equal(health.status, 200);
    const statsResponse = await miniflare.dispatchFetch(
      "http://worker.test/v1/stats",
    );
    assert.equal(statsResponse.status, 200);
    const stats = await statsResponse.json();

    const verified = [];
    for (const expectation of expectations) {
      const result = await searchAll(miniflare, expectation.apex, 100);
      assert.equal(result.reportedTotal, expectation.count);
      assert.equal(result.records.length, expectation.count);
      const recordsResponse = await miniflare.dispatchFetch(
        `http://worker.test/v1/records?apex=${encodeURIComponent(expectation.apex)}`,
      );
      assert.equal(recordsResponse.status, 200);
      const recordsDocument = await recordsResponse.json();
      assert.equal(recordsDocument.records.length, expectation.count);
      if (sqliteDatabase !== null) {
        const expected = sqliteRecords(sqliteDatabase, expectation.apex);
        assert.deepEqual(canonicalRecords(recordsDocument.records), canonicalRecords(expected));
        assert.deepEqual(
          result.records.map((record) => [record.sub, record.first_seen])
            .sort((left, right) => left[0].localeCompare(right[0])),
          expected.map((record) => [record.hostname, record.first_seen]),
        );
      }
      verified.push({
        apex: expectation.apex,
        count: expectation.count,
        pages: result.pageTimesMs.length,
        sqlite_parity: sqliteDatabase !== null,
        page_ms: result.pageTimesMs.map((value) => Number(value.toFixed(3))),
      });
    }

    const missing = await searchAll(miniflare, MISSING_APEX);
    assert.equal(missing.reportedTotal, 0);
    assert.deepEqual(missing.records, []);
    process.stdout.write(`${JSON.stringify({ seeded, stats, verified }, null, 2)}\n`);
  } finally {
    await miniflare.dispose();
  }
}


await main();
