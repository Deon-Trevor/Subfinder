import { validatedLogUrl } from "./direct-ct.js";
import { boundedBody } from "./public-sources.js";


const LISTS = Object.freeze({
  chrome: "https://www.gstatic.com/ct/log_list/v3/log_list.json",
  apple: "https://valid.apple.com/ct/log_list/current_log_list.json",
});
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_LIST_BYTES = 2 * 1024 * 1024;


function csvValues(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}


async function sha256Text(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}


export function usableLogUrls(payload, allowedHosts) {
  if (!Array.isArray(payload?.operators)) throw new Error("CT log list has no operators");
  const found = new Set();
  let active = 0;
  for (const operator of payload.operators) {
    if (!Array.isArray(operator?.logs)) continue;
    for (const log of operator.logs) {
      if (log?.state?.usable === undefined && log?.state?.qualified === undefined) continue;
      active += 1;
      try {
        found.add(validatedLogUrl(log.url, allowedHosts).toString());
      } catch {
        // The configured exact-host policy, not a remote list, owns egress.
      }
    }
  }
  if (active === 0) throw new Error("CT log list has no usable RFC 6962 logs");
  return [...found].sort();
}


async function fetchList(env, url, etag) {
  const fetchList = env.CT_LIST_FETCHER?.fetch.bind(env.CT_LIST_FETCHER)
    ?? globalThis.fetch.bind(globalThis);
  const headers = { "user-agent": "subfinder-ct-discovery/1.0" };
  if (etag) headers["if-none-match"] = etag;
  const response = await fetchList(url, { headers, redirect: "manual" });
  if (response.status === 304 && etag) return { unchanged: true, etag };
  if (!response.ok) throw new Error(`CT log list returned HTTP ${response.status}`);
  const bytes = await boundedBody(response, MAX_LIST_BYTES);
  return { payload: JSON.parse(new TextDecoder().decode(bytes)), etag: response.headers.get("etag") };
}


export async function discoverCtLogs(env, now = new Date()) {
  if (env.CT_LOG_DISCOVERY_ENABLED !== "1") return 0;
  const allowedHosts = csvValues(env.CT_ALLOWED_HOSTS);
  if (allowedHosts.length === 0) throw new Error("CT_ALLOWED_HOSTS is not configured");
  const dueBefore = new Date(now.valueOf() - DAY_MS).toISOString();
  const added = [];
  for (const [provider, url] of Object.entries(LISTS)) {
    const state = await env.CONTROL.prepare(
      "SELECT etag, checked_at FROM ct_log_lists WHERE provider = ?",
    ).bind(provider).first();
    if (state === null) throw new Error("CT log list migration is missing");
    if (state.checked_at !== null && state.checked_at > dueBefore) continue;
    const result = await fetchList(env, url, state.etag);
    if (!result.unchanged) {
      const urls = usableLogUrls(result.payload, allowedHosts);
      const statements = [env.CONTROL.prepare(
        "DELETE FROM ct_log_memberships WHERE provider = ?",
      ).bind(provider)];
      for (const logUrl of urls) {
        const sourceId = `discovered:${await sha256Text(logUrl)}`;
        statements.push(env.CONTROL.prepare(
          "INSERT INTO ct_log_memberships(provider, log_url) VALUES (?, ?)",
        ).bind(provider, logUrl));
        statements.push(env.CONTROL.prepare(
          `INSERT OR IGNORE INTO ct_sources(
             source_id, log_url, next_index, enabled, updated_at,
             discovered, cursor_initialized
           ) VALUES (?, ?, 0, 1, ?, 1, 0)`,
        ).bind(sourceId, logUrl, now.toISOString()));
      }
      const writes = await env.CONTROL.batch(statements);
      for (const [index, logUrl] of urls.entries()) {
        if (Number(writes[index * 2 + 2].meta?.changes ?? 0) === 1) {
          added.push(logUrl);
        }
      }
    }
    await env.CONTROL.prepare(
      "UPDATE ct_log_lists SET etag = ?, checked_at = ? WHERE provider = ?",
    ).bind(result.etag, now.toISOString(), provider).run();
  }
  await env.CONTROL.prepare(
    `UPDATE ct_sources SET enabled = 0
     WHERE discovered = 1 AND enabled = 1
       AND NOT EXISTS (
         SELECT 1 FROM ct_log_memberships
         WHERE ct_log_memberships.log_url = ct_sources.log_url
       )`,
  ).run();
  return new Set(added).size;
}
