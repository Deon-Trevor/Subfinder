import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const base = process.argv[2];
if (!base || !/^https?:\/\/[^/]+\/?$/.test(base)) {
  throw new Error("Usage: npm run verify -- https://<preview-host>/");
}
const origin = base.endsWith("/") ? base : `${base}/`;
const sourceDir = resolve(fileURLToPath(new URL("../../../web/", import.meta.url)));
const assets = [
  "index.html",
  "app.css",
  "app.js",
  "apple-touch-icon.png",
  "favicon.ico",
  "favicon.svg",
  "icon-192.png",
  "icon-512-maskable.png",
  "icon-512.png",
  "site.webmanifest",
  "robots.txt",
];
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

for (const asset of assets) {
  const response = await fetch(new URL(asset, origin));
  assert.equal(response.status, 200, `${asset} status`);
  const local = await readFile(resolve(sourceDir, asset));
  const remote = Buffer.from(await response.arrayBuffer());
  assert.equal(digest(remote), digest(local), `${asset} differs from web/`);
  assert.match(response.headers.get("x-robots-tag") ?? "", /noindex/, `${asset} must not be indexed`);
  console.log(`${asset}: 200, ${remote.length} bytes, SHA-256 match`);
}

for (const route of ["/v1/search?apex=example.com", "/v1/stats", "/mcp", "/internal/v1/records/batch"]) {
  const response = await fetch(new URL(route, origin));
  assert.equal(response.status, 404, `${route} must not reach an API`);
  console.log(`${route}: 404 (no API bound)`);
}
