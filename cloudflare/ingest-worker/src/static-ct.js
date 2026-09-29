import {
  apexForHostname,
  normalizeApex,
} from "../../index-worker/src/domain-policy.js";
import { certificateHostnames, validatedLogUrl } from "./direct-ct.js";
import { boundedBody } from "./public-sources.js";


const MAX_TILE_BYTES = 8 * 1024 * 1024;
const MAX_CERTIFICATE_BYTES = 1024 * 1024;


function take(bytes, offset, length) {
  if (length < 0 || offset + length > bytes.length) {
    throw new Error("Static CT data tile is truncated");
  }
  return [bytes.subarray(offset, offset + length), offset + length];
}


function vector(bytes, offset, lengthBytes) {
  const [lengthValue, next] = take(bytes, offset, lengthBytes);
  let length = 0;
  for (const byte of lengthValue) length = (length << 8) | byte;
  return take(bytes, next, length);
}


export function parseDataTile(bytes) {
  const leaves = [];
  let offset = 0;
  while (offset < bytes.length) {
    let field;
    [field, offset] = take(bytes, offset, 8);
    let milliseconds = 0n;
    for (const byte of field) milliseconds = (milliseconds << 8n) | BigInt(byte);
    if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new Error("Static CT timestamp is invalid");
    }
    const observed = new Date(Number(milliseconds));
    if (Number.isNaN(observed.valueOf())) throw new Error("Static CT timestamp is invalid");
    [field, offset] = take(bytes, offset, 2);
    const entryType = (field[0] << 8) | field[1];
    let certificate;
    if (entryType === 0) {
      [certificate, offset] = vector(bytes, offset, 3);
    } else if (entryType === 1) {
      [, offset] = take(bytes, offset, 32);
      [, offset] = vector(bytes, offset, 3);
    } else {
      throw new Error("Static CT entry type is unsupported");
    }
    [, offset] = vector(bytes, offset, 2);
    if (entryType === 1) [certificate, offset] = vector(bytes, offset, 3);
    if (certificate.length === 0 || certificate.length > MAX_CERTIFICATE_BYTES) {
      throw new Error("Static CT certificate is invalid");
    }
    [field, offset] = vector(bytes, offset, 2);
    if (field.length % 32 !== 0) {
      throw new Error("Static CT issuer fingerprints are invalid");
    }
    leaves.push({ certificate, first_seen: observed.toISOString() });
    if (leaves.length > 256) throw new Error("Static CT data tile has too many leaves");
  }
  return leaves;
}


function tilePath(number) {
  const groups = [];
  let value = String(number);
  while (value) {
    groups.unshift(value.slice(-3).padStart(3, "0"));
    value = value.slice(0, -3);
  }
  return groups.map((group, index) => (
    index === groups.length - 1 ? group : `x${group}`
  )).join("/");
}


function fetcher(env) {
  return env.CT_FETCHER?.fetch.bind(env.CT_FETCHER)
    ?? globalThis.fetch.bind(globalThis);
}


export async function staticTreeSize(env, value, allowedHosts) {
  const url = validatedLogUrl(value, allowedHosts);
  url.pathname += "/checkpoint";
  const response = await fetcher(env)(url, { redirect: "manual" });
  if (!response.ok) throw new Error(`Static CT checkpoint returned HTTP ${response.status}`);
  const text = new TextDecoder().decode(await boundedBody(response, 4096));
  const lines = text.split(/\r?\n/);
  const size = Number(lines[1]);
  if (lines.length < 2 || !Number.isSafeInteger(size) || size < 0) {
    throw new Error("Static CT checkpoint is invalid");
  }
  return size;
}


export async function staticRange(env, value, allowedHosts, start, end, treeSize) {
  if (
    !Number.isSafeInteger(start) || !Number.isSafeInteger(end) ||
    start < 0 || end < start || end >= treeSize ||
    Math.floor(start / 256) !== Math.floor(end / 256)
  ) throw new Error("Static CT entry range is invalid");
  const tileNumber = Math.floor(start / 256);
  const tileStart = tileNumber * 256;
  const width = Math.min(256, treeSize - tileStart);
  const url = validatedLogUrl(value, allowedHosts);
  url.pathname += `/tile/data/${tilePath(tileNumber)}`;
  if (width < 256) url.pathname += `.p/${width}`;
  const response = await fetcher(env)(url, {
    headers: { "accept-encoding": "gzip, identity" },
    redirect: "manual",
  });
  if (!response.ok) throw new Error(`Static CT tile returned HTTP ${response.status}`);
  let bytes = await boundedBody(response, MAX_TILE_BYTES);
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
    bytes = await boundedBody(new Response(stream), MAX_TILE_BYTES);
  }
  const leaves = parseDataTile(bytes);
  if (leaves.length !== width) throw new Error("Static CT tile width is invalid");
  const records = new Map();
  for (const leaf of leaves.slice(start - tileStart, end - tileStart + 1)) {
    for (const hostname of certificateHostnames(leaf.certificate)) {
      let apex;
      try {
        apex = normalizeApex(apexForHostname(hostname));
      } catch {
        continue;
      }
      const previous = records.get(hostname);
      if (previous === undefined || leaf.first_seen < previous.first_seen) {
        records.set(hostname, { apex, hostname, first_seen: leaf.first_seen });
      }
    }
  }
  return {
    entryCount: end - start + 1,
    records: [...records.values()].sort((left, right) => (
      left.apex.localeCompare(right.apex) || left.hostname.localeCompare(right.hostname)
    )),
  };
}
