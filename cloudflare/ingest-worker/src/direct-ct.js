import "reflect-metadata";
import {
  DNS,
  SubjectAlternativeNameExtension,
  X509Certificate,
} from "@peculiar/x509";

import {
  apexForHostname,
  normalizeApex,
  normalizeHostname,
} from "../../index-worker/src/domain-policy.js";


const MAX_CERTIFICATE_BYTES = 1024 * 1024;


function readU24(value, offset) {
  if (offset + 3 > value.length) return null;
  return (value[offset] << 16) | (value[offset + 1] << 8) | value[offset + 2];
}


function decodeBase64(value) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    return null;
  }
  try {
    return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  } catch {
    return null;
  }
}


function readCertificate(value, offset) {
  const length = readU24(value, offset);
  if (length === null || length < 1 || length > MAX_CERTIFICATE_BYTES) return null;
  const start = offset + 3;
  const end = start + length;
  if (end > value.length) return null;
  return value.slice(start, end);
}


function leafCertificate(entry) {
  const leaf = decodeBase64(entry?.leaf_input);
  if (leaf === null || leaf.length < 12 || leaf[0] !== 0 || leaf[1] !== 0) {
    return null;
  }
  const entryType = (leaf[10] << 8) | leaf[11];
  if (entryType === 0) return readCertificate(leaf, 12);
  if (entryType === 1) {
    const extra = decodeBase64(entry?.extra_data);
    return extra === null ? null : readCertificate(extra, 0);
  }
  return null;
}


export function entryFirstSeen(entry) {
  const leaf = decodeBase64(entry?.leaf_input);
  if (leaf === null || leaf.length < 12 || leaf[0] !== 0 || leaf[1] !== 0) {
    return null;
  }
  let milliseconds = 0n;
  for (const byte of leaf.slice(2, 10)) {
    milliseconds = (milliseconds << 8n) | BigInt(byte);
  }
  if (milliseconds > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  const date = new Date(Number(milliseconds));
  return Number.isNaN(date.valueOf()) ? null : date.toISOString();
}


function certificateNames(der) {
  const bytes = der.buffer.slice(der.byteOffset, der.byteOffset + der.byteLength);
  const certificate = new X509Certificate(bytes, {
    berOptions: {
      maxContentLength: MAX_CERTIFICATE_BYTES,
      maxDepth: 64,
      maxNodes: 20000,
    },
  });
  const alternativeNames = certificate.getExtension(SubjectAlternativeNameExtension);
  if (alternativeNames !== null) {
    return alternativeNames.names.items
      .filter((name) => name.type === DNS)
      .map((name) => name.value);
  }
  return certificate.subjectName.getField("CN");
}


export function certificateHostnames(der) {
  let values;
  try {
    values = certificateNames(der);
  } catch {
    return [];
  }
  const result = [];
  const seen = new Set();
  for (const value of values) {
    try {
      const hostname = normalizeHostname(value);
      if (!seen.has(hostname)) {
        seen.add(hostname);
        result.push(hostname);
      }
    } catch {
      // A certificate can contain non-DNS SAN values.
    }
  }
  return result;
}


export function entryHostnames(entry) {
  let values;
  if (Array.isArray(entry?.dns_names)) {
    values = entry.dns_names;
  } else {
    const der = leafCertificate(entry);
    if (der === null) return [];
    return certificateHostnames(der);
  }
  const result = [];
  const seen = new Set();
  for (const value of values) {
    try {
      const hostname = normalizeHostname(value);
      if (!seen.has(hostname)) {
        seen.add(hostname);
        result.push(hostname);
      }
    } catch {
      // A certificate may contain non-DNS SAN values or malformed names.
    }
  }
  return result;
}


export function recordsFromEntries(entries) {
  const records = new Map();
  for (const entry of entries) {
    const firstSeen = entryFirstSeen(entry);
    for (const hostname of entryHostnames(entry)) {
      let apex;
      try {
        apex = normalizeApex(apexForHostname(hostname));
      } catch {
        continue;
      }
      const previous = records.get(hostname);
      if (
        previous === undefined ||
        (firstSeen !== null && (previous.first_seen === null || firstSeen < previous.first_seen))
      ) {
        records.set(hostname, {
          apex,
          first_seen: firstSeen,
          hostname,
        });
      }
    }
  }
  return [...records.values()].sort((left, right) => (
    left.apex.localeCompare(right.apex) || left.hostname.localeCompare(right.hostname)
  ));
}


export function validatedLogUrl(value, allowedHosts) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error("CT log URL is invalid");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !allowedHosts.includes(url.hostname)
  ) {
    throw new Error("CT log URL is not allowed");
  }
  url.pathname = url.pathname.replace(/\/+$/, "");
  return url;
}


export async function fetchEntries(fetcher, logUrl, start, end) {
  const url = new URL(logUrl);
  url.pathname = `${url.pathname}/ct/v1/get-entries`;
  url.searchParams.set("start", String(start));
  url.searchParams.set("end", String(end));
  const response = await fetcher(url, {
    headers: { "user-agent": "subfinder-ingest/1.0" },
  });
  if (!response.ok) throw new Error(`CT log returned HTTP ${response.status}`);
  const payload = await response.json();
  if (!Array.isArray(payload?.entries)) throw new Error("CT log response is invalid");
  return payload.entries;
}
