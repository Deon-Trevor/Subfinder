import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { test } from "node:test";

const root = resolve(import.meta.dirname, "..");
const checker = resolve(root, "scripts/check_cloudflare_bindings.mjs");
const readExample = resolve(root, "cloudflare/index-worker/wrangler.example.jsonc");

function run(...args) {
  return spawnSync(process.execPath, [checker, ...args], {
    cwd: root,
    encoding: "utf8",
  });
}

test("the public Cloudflare examples form one pipeline", () => {
  const result = run("--examples");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Checked 5 Worker configs/);
});

test("a mismatched catalog bucket blocks deployment preflight", () => {
  const file = resolve(root, "cloudflare/index-worker", `wrangler.local.test-${randomUUID()}.jsonc`);
  const value = JSON.parse(readFileSync(readExample, "utf8"));
  value.r2_buckets[0].bucket_name = "wrong-catalog";
  try {
    writeFileSync(file, JSON.stringify(value));
    const result = run("--examples", "--read", file);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /CATALOG bucket differs/);
  } finally {
    try { unlinkSync(file); } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
});
