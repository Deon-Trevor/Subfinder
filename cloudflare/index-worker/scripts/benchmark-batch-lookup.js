import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { open, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { gunzipSync } from "node:zlib";

import { locateApex } from "../src/index.js";


const directory = process.env.SUBFINDER_EXPORT_DIR;
if (!directory) throw new Error("SUBFINDER_EXPORT_DIR must name a local R2 export");
const base = resolve(directory);
const root = JSON.parse(await readFile(resolve(base, "catalog/root.json"), "utf8"));
const delayMs = Number(process.env.SUBFINDER_BENCH_DELAY_MS ?? 5);
if (!Number.isFinite(delayMs) || delayMs < 0 || delayMs > 100) {
  throw new Error("SUBFINDER_BENCH_DELAY_MS must be between 0 and 100");
}


function bucket() {
  const metrics = { gets: 0, index_gets: 0, range_gets: 0, bytes: 0 };
  return {
    metrics,
    async get(key, options) {
      if (key.includes("..") || key.startsWith("/")) throw new Error("invalid object key");
      if (delayMs) await new Promise((done) => setTimeout(done, delayMs));
      const path = resolve(base, key);
      let bytes;
      if (options?.range) {
        const { offset, length } = options.range;
        const file = await open(path, "r");
        try {
          const buffer = Buffer.alloc(length);
          const read = await file.read(buffer, 0, length, offset);
          bytes = buffer.subarray(0, read.bytesRead);
        } finally {
          await file.close();
        }
        metrics.range_gets += 1;
      } else {
        bytes = await readFile(path);
        metrics.index_gets += 1;
      }
      metrics.gets += 1;
      metrics.bytes += bytes.byteLength;
      return {
        body: true,
        arrayBuffer: async () => Uint8Array.from(bytes).buffer,
      };
    },
  };
}


async function candidates() {
  const hits = [];
  for (const [position, metadata] of Object.entries(root.partitions)) {
    if (Number.parseInt(position, 16) % 5 !== 0) continue;
    const index = JSON.parse(gunzipSync(await readFile(resolve(base, metadata.index))));
    hits.push(index.blocks[Math.floor(index.blocks.length / 2)].first_apex);
  }
  return Array.from({ length: 500 }, (_, position) => (
    position % 10 === 0
      ? hits[Math.floor(position / 10)]
      : `candidate-${String(position).padStart(5, "0")}.com`
  ));
}


async function orderedMap(values, concurrency, fn) {
  const results = new Array(values.length);
  let next = 0;
  await Promise.all(Array.from({ length: concurrency }, async () => {
    for (;;) {
      const index = next++;
      if (index >= values.length) return;
      results[index] = await fn(values[index]);
    }
  }));
  return results;
}


const apexes = await candidates();
let expected;
for (const [name, concurrency, cached] of [
  ["baseline", 1, false],
  ["parallel-4", 4, false],
  ["cache-64", 1, true],
  ["parallel-4-cache-64", 4, true],
]) {
  const catalog = bucket();
  const cache = cached ? new Map() : null;
  const started = performance.now();
  const results = await orderedMap(apexes, concurrency, async (apex) => {
    const found = await locateApex({ CATALOG: catalog }, apex, root, cache);
    return [apex, found.total, found.dated, found.records?.length ?? null,
      found.chunks.length];
  });
  const ms = Math.round(performance.now() - started);
  if (expected === undefined) expected = results;
  else assert.deepEqual(results, expected, `${name} changed lookup results`);
  if (cache !== null) assert.ok(cache.size <= 64, "partition cache exceeded its bound");
  const digest = createHash("sha256").update(JSON.stringify(results)).digest("hex");
  process.stdout.write(JSON.stringify({
    name, candidates: apexes.length, hits: results.filter((row) => row[1] > 0).length,
    ms, ...catalog.metrics, cache_entries: cache?.size ?? 0, digest,
  }) + "\n");
}
