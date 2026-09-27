import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { relative, resolve, sep } from "node:path";

import { createMiniflare } from "../test/miniflare.js";


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


async function seed(bucket, directory) {
  let objectCount = 0;
  let bytes = 0;
  for (const path of files(directory)) {
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
  const [directoryValue, ...expectationValues] = process.argv.slice(2);
  if (directoryValue === undefined || expectationValues.length === 0) {
    throw new Error(
      "usage: node scripts/verify-export.js EXPORT_DIR apex=count [apex=count ...]",
    );
  }
  const directory = resolve(directoryValue);
  const expectations = parseExpectations(expectationValues);
  const workerRoot = resolve(import.meta.dirname, "..");
  const miniflare = createMiniflare(workerRoot);

  try {
    const bucket = await miniflare.getR2Bucket("CATALOG");
    const seeded = await seed(bucket, directory);
    const health = await miniflare.dispatchFetch("http://worker.test/health");
    assert.equal(health.status, 200);
    const statsResponse = await miniflare.dispatchFetch(
      "http://worker.test/v1/stats",
    );
    assert.equal(statsResponse.status, 200);
    const stats = await statsResponse.json();

    const verified = [];
    for (const expectation of expectations) {
      const result = await searchAll(miniflare, expectation.apex);
      assert.equal(result.reportedTotal, expectation.count);
      assert.equal(result.records.length, expectation.count);
      const recordsResponse = await miniflare.dispatchFetch(
        `http://worker.test/v1/records?apex=${encodeURIComponent(expectation.apex)}`,
      );
      assert.equal(recordsResponse.status, 200);
      const recordsDocument = await recordsResponse.json();
      assert.equal(recordsDocument.records.length, expectation.count);
      verified.push({
        apex: expectation.apex,
        count: expectation.count,
        pages: result.pageTimesMs.length,
        page_ms: result.pageTimesMs.map((value) => Number(value.toFixed(3))),
      });
    }

    const missing = await searchAll(miniflare, "not-present.invalid");
    assert.equal(missing.reportedTotal, 0);
    assert.deepEqual(missing.records, []);
    process.stdout.write(`${JSON.stringify({ seeded, stats, verified }, null, 2)}\n`);
  } finally {
    await miniflare.dispose();
  }
}


await main();
