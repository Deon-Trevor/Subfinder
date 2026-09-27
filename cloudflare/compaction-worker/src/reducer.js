import { DOMAIN_POLICY_VERSION, PSL_SHA256 } from "../../index-worker/src/domain-policy.js";


const FORMAT = "subfinder.r2-index.v2";
const FRAGMENT_FORMAT = "subfinder.map-fragment.v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder();


function hex(bytes) {
  return [...new Uint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0")).join("");
}


async function digest(bytes) {
  return hex(await crypto.subtle.digest("SHA-256", bytes));
}


async function gunzip(bytes) {
  return await new Response(
    new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip")),
  ).text();
}


async function gzip(bytes) {
  return new Uint8Array(await new Response(
    new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip")),
  ).arrayBuffer());
}


function cursor(record) {
  return [record.f, record.h];
}


function compareRecords(left, right) {
  if (left.f === null && right.f !== null) return 1;
  if (left.f !== null && right.f === null) return -1;
  return (left.f ?? "").localeCompare(right.f ?? "") || left.h.localeCompare(right.h);
}


function firstKnown(left, right) {
  if (left === null) return right;
  if (right === null) return left;
  return left < right ? left : right;
}


function stats(records) {
  return {
    hostname_count: records.length,
    dated_hostname_count: records.filter((record) => record.f !== null).length,
    source_observation_count: records.reduce((count, record) => count + record.s.length, 0),
    ct_hostname_count: records.filter((record) => record.s.some(
      (source) => source.n.startsWith("direct_ct:") || source.n.startsWith("static_ct:"),
    )).length,
  };
}


export function mergeApex(baseRecords, observations) {
  const byHostname = new Map();
  for (const record of baseRecords) {
    byHostname.set(record.h, {
      h: record.h,
      f: record.f,
      s: new Map(record.s.map((source) => [source.n, { ...source }])),
    });
  }
  const sourceNames = new Set();
  const ctSourceNames = new Set();
  for (const observation of observations) {
    const { hostname, first_seen: firstSeen, source, observed_at: observedAt } = observation;
    let record = byHostname.get(hostname);
    if (record === undefined) {
      record = { h: hostname, f: firstSeen, s: new Map() };
      byHostname.set(hostname, record);
    } else {
      record.f = firstKnown(record.f, firstSeen);
    }
    const current = record.s.get(source);
    if (current === undefined) {
      record.s.set(source, { n: source, f: firstSeen, l: observedAt });
    } else {
      current.f = firstKnown(current.f, firstSeen);
      if (observedAt > current.l) current.l = observedAt;
    }
    sourceNames.add(source);
    if (source.startsWith("direct_ct:") || source.startsWith("static_ct:")) {
      ctSourceNames.add(source);
    }
  }
  const records = [...byHostname.values()].map((record) => ({
    h: record.h,
    f: record.f,
    s: [...record.s.values()].sort((left, right) => left.n.localeCompare(right.n)),
  })).sort(compareRecords);
  return { records, sourceNames, ctSourceNames };
}


async function checkedObject(bucket, key, sha256, range) {
  const object = range ? await bucket.get(key, { range }) : await bucket.get(key);
  if (object === null || !("body" in object)) throw new Error(`catalog object missing: ${key}`);
  let bytes;
  try {
    bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
  } catch (error) {
    throw new Error(`catalog read failed for ${key} (bodyUsed=${object.bodyUsed}): ${error.message}`);
  }
  if (sha256 !== null && await digest(bytes) !== sha256) {
    throw new Error(`catalog checksum mismatch: ${key}`);
  }
  return bytes;
}


async function readMember(bucket, bundle, metadata) {
  const bytes = await checkedObject(bucket, bundle, metadata.sha256, {
    offset: metadata.offset,
    length: metadata.length,
  });
  return { bytes, documents: (await gunzip(bytes)).trimEnd().split("\n").map(JSON.parse) };
}


async function partitionIndex(bucket, root, prefix) {
  const metadata = root?.partitions?.[prefix];
  if (metadata === undefined) return null;
  const bytes = await checkedObject(bucket, metadata.index, metadata.index_sha256);
  const index = JSON.parse(await gunzip(bytes));
  if (
    index.format !== FORMAT || index.prefix !== prefix ||
    index.generation !== (metadata.origin_generation ?? root.generation) ||
    index.bundle !== metadata.bundle
  ) throw new Error("base partition identity mismatch");
  return { index, metadata };
}


async function* baseApexes(bucket, partition, overlay, maxRecords) {
  if (partition === null) return;
  const { index, metadata } = partition;
  const overflowKeys = Object.keys(index.overflow).sort();
  let overflowPosition = 0;
  async function* overflowBefore(apex) {
    while (overflowPosition < overflowKeys.length && overflowKeys[overflowPosition] < apex) {
      const key = overflowKeys[overflowPosition++];
      const details = index.overflow[key];
      if (!overlay.has(key)) {
        yield { apex: key, copy: details };
        continue;
      }
      const records = [];
      for (const chunk of details.chunks) {
        const member = await readMember(bucket, metadata.bundle, chunk);
        if (member.documents.length !== 1 || member.documents[0].a !== key) {
          throw new Error("base overflow chunk identity mismatch");
        }
        records.push(...member.documents[0].r);
        if (records.length > maxRecords) {
          throw new Error("modified overflow apex exceeds reducer memory bound");
        }
      }
      yield { apex: key, records };
    }
  }
  for (const block of index.blocks) {
    const member = await readMember(bucket, metadata.bundle, block);
    for (const document of member.documents) {
      yield* overflowBefore(document.a);
      yield { apex: document.a, records: document.r };
    }
  }
  yield* overflowBefore("\uffff");
}


async function readOverlay(env, generationId, prefix) {
  const rows = await env.LEDGER.prepare(
    `SELECT delta_id, object_key, object_sha256, object_bytes FROM generation_fragments
     WHERE generation_id = ? AND prefix = ? ORDER BY delta_id`,
  ).bind(generationId, prefix).all();
  const maxRecords = Number(env.MAX_REDUCE_RECORDS ?? 200000);
  if (!Number.isSafeInteger(maxRecords) || maxRecords < 1) throw new Error("invalid reducer bound");
  const overlay = new Map();
  let lastObservedAt = null;
  let count = 0;
  for (const row of rows.results) {
    if (Number(row.object_bytes) > 32 * 1024 * 1024) {
      throw new Error("map fragment exceeds reducer memory bound");
    }
    const bytes = await checkedObject(env.CATALOG, row.object_key, row.object_sha256);
    if (bytes.length !== Number(row.object_bytes)) throw new Error("map fragment size mismatch");
    const fragment = JSON.parse(await gunzip(bytes));
    if (
      fragment.schema_version !== FRAGMENT_FORMAT ||
      fragment.generation_id !== generationId || fragment.prefix !== prefix ||
      fragment.delta_id !== row.delta_id || !Array.isArray(fragment.records) ||
      typeof fragment.source !== "string" || !fragment.source ||
      typeof fragment.observed_at !== "string"
    ) throw new Error("map fragment identity mismatch");
    if (Number.isNaN(new Date(fragment.observed_at).valueOf())) {
      throw new Error("map fragment observation time is invalid");
    }
    if (lastObservedAt === null || fragment.observed_at > lastObservedAt) {
      lastObservedAt = fragment.observed_at;
    }
    for (const record of fragment.records) {
      const observations = overlay.get(record.apex) ?? [];
      observations.push({
        hostname: record.hostname,
        first_seen: record.first_seen,
        source: fragment.source,
        observed_at: fragment.observed_at,
      });
      overlay.set(record.apex, observations);
      count += 1;
      if (count > maxRecords) throw new Error("partition exceeds reducer memory bound");
    }
  }
  return { overlay, lastObservedAt };
}


function applyStats(delta, oldRecords, newRecords, newApex) {
  const before = stats(oldRecords);
  const after = stats(newRecords);
  if (newApex) delta.apex_count += 1;
  for (const key of Object.keys(before)) delta[key] += after[key] - before[key];
}


async function* mergedApexes(env, basePartition, overlay, maxRecords, delta, sourceNames, ctSourceNames) {
  const pending = [...overlay.keys()].sort();
  let position = 0;
  for await (const base of baseApexes(env.CATALOG, basePartition, overlay, maxRecords)) {
    while (position < pending.length && pending[position] < base.apex) {
      const apex = pending[position++];
      const merged = mergeApex([], overlay.get(apex));
      applyStats(delta, [], merged.records, true);
      for (const source of merged.sourceNames) sourceNames.add(source);
      for (const source of merged.ctSourceNames) ctSourceNames.add(source);
      yield { apex, records: merged.records };
    }
    if (pending[position] !== base.apex) {
      yield base;
      continue;
    }
    position += 1;
    const merged = mergeApex(base.records, overlay.get(base.apex));
    applyStats(delta, base.records, merged.records, false);
    for (const source of merged.sourceNames) sourceNames.add(source);
    for (const source of merged.ctSourceNames) ctSourceNames.add(source);
    yield { apex: base.apex, records: merged.records };
  }
  while (position < pending.length) {
    const apex = pending[position++];
    const merged = mergeApex([], overlay.get(apex));
    applyStats(delta, [], merged.records, true);
    for (const source of merged.sourceNames) sourceNames.add(source);
    for (const source of merged.ctSourceNames) ctSourceNames.add(source);
    yield { apex, records: merged.records };
  }
}


async function* bundleMembers(env, documents, basePartition, targetBytes, index) {
  let offset = 0;
  let regular = [];
  let regularBytes = 0;
  async function flush() {
    if (regular.length === 0) return null;
    const raw = encoder.encode(regular.map((item) => item.line).join(""));
    const compressed = await gzip(raw);
    index.blocks.push({
      offset, length: compressed.length, sha256: await digest(compressed),
      uncompressed_bytes: raw.length,
      first_apex: regular[0].apex, last_apex: regular.at(-1).apex,
      apex_count: regular.length,
    });
    offset += compressed.length;
    regular = [];
    regularBytes = 0;
    return compressed;
  }
  for await (const item of documents) {
    if (item.copy !== undefined) {
      const compressed = await flush();
      if (compressed) yield compressed;
      const chunks = [];
      for (const chunk of item.copy.chunks) {
        const bytes = await checkedObject(env.CATALOG, basePartition.metadata.bundle, chunk.sha256, {
          offset: chunk.offset, length: chunk.length,
        });
        chunks.push({ ...chunk, offset });
        offset += bytes.length;
        yield bytes;
      }
      index.overflow[item.apex] = { ...item.copy, chunks };
      continue;
    }
    const records = item.records;
    const dated = records.filter((record) => record.f !== null).length;
    const line = JSON.stringify({ a: item.apex, d: dated, r: records, t: records.length }) + "\n";
    const lineBytes = encoder.encode(line).length;
    if (lineBytes <= targetBytes) {
      if (regular.length && regularBytes + lineBytes > targetBytes) {
        yield await flush();
      }
      regular.push({ apex: item.apex, line });
      regularBytes += lineBytes;
      continue;
    }
    const compressed = await flush();
    if (compressed) yield compressed;
    const chunks = [];
    let group = [];
    let groupBytes = 0;
    async function writeChunk() {
      const raw = encoder.encode(JSON.stringify({
        a: item.apex, i: chunks.length, r: group, x: true,
      }) + "\n");
      const bytes = await gzip(raw);
      chunks.push({
        offset, length: bytes.length, sha256: await digest(bytes),
        uncompressed_bytes: raw.length, count: group.length,
        dated: group.filter((record) => record.f !== null).length,
        first_cursor: cursor(group[0]), last_cursor: cursor(group.at(-1)),
      });
      offset += bytes.length;
      group = [];
      groupBytes = 0;
      return bytes;
    }
    for (const record of records) {
      const recordBytes = encoder.encode(JSON.stringify(record)).length;
      if (group.length && groupBytes + recordBytes + 128 > targetBytes) {
        yield await writeChunk();
      }
      group.push(record);
      groupBytes += recordBytes;
    }
    if (group.length) yield await writeChunk();
    index.overflow[item.apex] = { total: records.length, dated, chunks };
  }
  const final = await flush();
  if (final) yield final;
}


function streamFromGenerator(generator) {
  return new ReadableStream({
    async pull(controller) {
      const result = await generator.next();
      if (result.done) controller.close();
      else controller.enqueue(result.value);
    },
    cancel(reason) { return generator.return?.(reason); },
  });
}


function takeBytes(chunks, byteCount) {
  const result = new Uint8Array(byteCount);
  let offset = 0;
  while (offset < byteCount) {
    const head = chunks[0];
    const length = Math.min(head.length, byteCount - offset);
    result.set(head.subarray(0, length), offset);
    offset += length;
    if (length === head.length) chunks.shift();
    else chunks[0] = head.subarray(length);
  }
  return result;
}


export async function storeBundle(bucket, key, stream) {
  const partBytes = 8 * 1024 * 1024;
  const reader = stream.getReader();
  const chunks = [];
  let available = 0;
  let upload = null;
  const parts = [];
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      chunks.push(next.value);
      available += next.value.length;
      while (available >= partBytes) {
        upload ??= await bucket.createMultipartUpload(key, {
          httpMetadata: { contentType: "application/octet-stream" },
        });
        parts.push(await upload.uploadPart(parts.length + 1, takeBytes(chunks, partBytes)));
        available -= partBytes;
      }
    }
    if (upload !== null) {
      if (available > 0) {
        parts.push(await upload.uploadPart(parts.length + 1, takeBytes(chunks, available)));
      }
      return await upload.complete(parts);
    }
    return await bucket.put(key, takeBytes(chunks, available), {
      httpMetadata: { contentType: "application/octet-stream" },
    });
  } catch (error) {
    if (upload !== null) await upload.abort();
    throw error;
  }
}


async function hashStream(stream) {
  const hash = new crypto.DigestStream("SHA-256");
  await stream.pipeTo(hash);
  return hex(await hash.digest);
}


export async function reducePartition(env, generationId, prefix) {
  if (!/^[a-f0-9]{64}$/.test(generationId) || !/^[a-f0-9]{1,3}$/.test(prefix)) {
    throw new Error("reduce partition identity is invalid");
  }
  const generation = await env.LEDGER.prepare(
    "SELECT base_generation, state FROM catalog_generations WHERE generation_id = ?",
  ).bind(generationId).first();
  if (generation === null || !["mapped", "reducing", "published"].includes(generation.state)) {
    throw new Error("generation is not ready for reduction");
  }
  const row = await env.LEDGER.prepare(
    "SELECT state, output_json FROM generation_partitions WHERE generation_id = ? AND prefix = ?",
  ).bind(generationId, prefix).first();
  if (row === null) throw new Error("mapped partition is absent");
  if (row.state === "reduced") return JSON.parse(row.output_json);
  const rootObject = await env.CATALOG.get("catalog/root.json");
  const baseRoot = rootObject === null ? null : await rootObject.json();
  if ((baseRoot?.generation ?? null) !== generation.base_generation) {
    throw new Error("active root changed during reduction");
  }
  if (baseRoot !== null && (baseRoot.format !== FORMAT || !Array.isArray(baseRoot.source_names))) {
    throw new Error("base root lacks reducer metadata");
  }
  const nibbles = baseRoot?.partition_nibbles ?? Number(env.PARTITION_NIBBLES ?? 2);
  if (prefix.length !== nibbles) throw new Error("partition width mismatch");
  const { overlay, lastObservedAt } = await readOverlay(env, generationId, prefix);
  if (overlay.size === 0) throw new Error("partition has no mapped records");
  const basePartition = await partitionIndex(env.CATALOG, baseRoot, prefix);
  const targetBytes = baseRoot?.target_block_bytes ?? 256 * 1024;
  const bundleKey = `catalog/generations/${generationId}/partitions/${prefix}.bundle`;
  const indexKey = `catalog/generations/${generationId}/partitions/${prefix}.index.json.gz`;
  const index = {
    format: FORMAT, generation: generationId, prefix, bundle: bundleKey,
    blocks: [], overflow: {},
  };
  const delta = {
    apex_count: 0, hostname_count: 0, dated_hostname_count: 0,
    source_observation_count: 0, ct_hostname_count: 0,
  };
  const sourceNames = new Set();
  const ctSourceNames = new Set();
  const maxRecords = Number(env.MAX_REDUCE_RECORDS ?? 200000);
  const documents = mergedApexes(
    env, basePartition, overlay, maxRecords, delta, sourceNames, ctSourceNames,
  );
  const source = streamFromGenerator(bundleMembers(env, documents, basePartition, targetBytes, index));
  const [forStorage, forHash] = source.tee();
  const hashPromise = hashStream(forHash);
  const existing = await env.CATALOG.head(bundleKey);
  if (existing === null) {
    const stored = await storeBundle(env.CATALOG, bundleKey, forStorage);
    if (stored === null) throw new Error("bundle write precondition failed");
  } else {
    await forStorage.pipeTo(new WritableStream({ write() {} }));
  }
  const bundleSha256 = await hashPromise;
  const bundleBytes = index.blocks.reduce((sum, block) => sum + block.length, 0) +
    Object.values(index.overflow).reduce((sum, item) => sum + item.chunks.reduce(
      (subtotal, chunk) => subtotal + chunk.length, 0,
    ), 0);
  const actual = await env.CATALOG.get(bundleKey);
  if (actual === null || actual.size !== bundleBytes ||
      await hashStream(actual.body) !== bundleSha256) {
    throw new Error("stored partition bundle failed readback verification");
  }
  const indexBytes = await gzip(encoder.encode(JSON.stringify(index) + "\n"));
  const indexSha256 = await digest(indexBytes);
  const previousIndex = await env.CATALOG.get(indexKey);
  if (previousIndex === null) {
    await env.CATALOG.put(indexKey, indexBytes, {
      httpMetadata: { contentType: "application/gzip" },
    });
  } else if (await digest(new Uint8Array(await previousIndex.arrayBuffer())) !== indexSha256) {
    throw new Error("immutable partition index conflicts with retry");
  }
  const output = {
    metadata: {
      index: indexKey, index_sha256: indexSha256, index_bytes: indexBytes.length,
      bundle: bundleKey, bundle_bytes: bundleBytes, bundle_sha256: bundleSha256,
      regular_blocks: index.blocks.length,
      overflow_apexes: Object.keys(index.overflow).length,
    },
    stats_delta: delta,
    source_names: [...sourceNames].sort(),
    ct_source_names: [...ctSourceNames].sort(),
    last_ingest_at: lastObservedAt,
  };
  await env.LEDGER.prepare(
    `UPDATE generation_partitions SET state = 'reduced', output_json = ?, error = NULL,
     lease_token = NULL, lease_until = NULL, updated_at = ?
     WHERE generation_id = ? AND prefix = ? AND state = 'reducing'`,
  ).bind(JSON.stringify(output), new Date().toISOString(), generationId, prefix).run();
  return output;
}


export async function stageCandidateRoot(env, generationId) {
  const generation = await env.LEDGER.prepare(
    "SELECT base_generation, state, partition_count FROM catalog_generations WHERE generation_id = ?",
  ).bind(generationId).first();
  if (generation === null || !["reducing", "published"].includes(generation.state)) {
    throw new Error("generation is not ready for publication");
  }
  const rows = await env.LEDGER.prepare(
    `SELECT prefix, state, output_json FROM generation_partitions
     WHERE generation_id = ? ORDER BY prefix`,
  ).bind(generationId).all();
  if (rows.results.length !== Number(generation.partition_count) ||
      rows.results.some((row) => row.state !== "reduced")) {
    throw new Error("not all partitions are reduced");
  }
  const current = await env.CATALOG.get("catalog/root.json");
  const base = current === null ? null : await current.json();
  if ((base?.generation ?? null) !== generation.base_generation) {
    throw new Error("active root changed before candidate publication");
  }
  if (base !== null && !Array.isArray(base.source_names)) {
    throw new Error("base root lacks source metadata");
  }
  const partitions = { ...(base?.partitions ?? {}) };
  for (const metadata of Object.values(partitions)) {
    metadata.origin_generation ??= base.generation;
  }
  const sourceNames = new Set(base?.source_names ?? []);
  const ctSourceNames = new Set(base?.ct_source_names ?? []);
  const stats = { ...base?.stats };
  for (const key of [
    "apex_count", "hostname_count", "dated_hostname_count",
    "source_observation_count", "ct_hostname_count",
  ]) stats[key] ??= 0;
  for (const row of rows.results) {
    const output = JSON.parse(row.output_json);
    const metadata = output.metadata;
    if (await env.CATALOG.head(metadata.index) === null ||
        await env.CATALOG.head(metadata.bundle) === null) {
      throw new Error("partition object is missing before publication");
    }
    partitions[row.prefix] = metadata;
    for (const [key, value] of Object.entries(output.stats_delta)) stats[key] += value;
    for (const name of output.source_names) sourceNames.add(name);
    for (const name of output.ct_source_names) ctSourceNames.add(name);
    if (output.last_ingest_at && (!stats.last_ingest_at || output.last_ingest_at > stats.last_ingest_at)) {
      stats.last_ingest_at = output.last_ingest_at;
    }
  }
  stats.source_count = sourceNames.size;
  stats.ct_log_count = ctSourceNames.size;
  stats.last_ingest_at ??= null;
  const root = {
    format: FORMAT, generation: generationId,
    domain_policy_version: base?.domain_policy_version ?? DOMAIN_POLICY_VERSION,
    psl_sha256: base?.psl_sha256 ?? PSL_SHA256,
    partition_nibbles: base?.partition_nibbles ?? Number(env.PARTITION_NIBBLES ?? 2),
    target_block_bytes: base?.target_block_bytes ?? 256 * 1024,
    ordering: ["first_seen_nulls_last", "first_seen", "hostname"],
    partitions, source_names: [...sourceNames].sort(),
    ct_source_names: [...ctSourceNames].sort(), stats,
  };
  if (!root.domain_policy_version || !root.psl_sha256) {
    throw new Error("candidate domain policy metadata is missing");
  }
  const bytes = encoder.encode(JSON.stringify(root) + "\n");
  const sha256 = await digest(bytes);
  const key = `catalog/candidates/${generationId}.json`;
  const existing = await env.CATALOG.get(key);
  if (existing === null) {
    await env.CATALOG.put(key, bytes, { httpMetadata: { contentType: "application/json" } });
  } else if (await digest(new Uint8Array(await existing.arrayBuffer())) !== sha256) {
    throw new Error("candidate root conflicts with retry");
  }
  await env.LEDGER.prepare(
    `UPDATE catalog_generations SET state = 'published', candidate_root_key = ?,
     candidate_root_sha256 = ?, updated_at = ?
     WHERE generation_id = ? AND state = 'reducing'`,
  ).bind(key, sha256, new Date().toISOString(), generationId).run();
  return { key, sha256, root };
}


export { digest, hex };
