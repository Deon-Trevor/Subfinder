import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { test } from "node:test";

import {
  DOMAIN_POLICY_VERSION,
  PSL_SHA256,
  apexForHostname,
  normalizeApex,
  normalizeHostname,
  zoneForApex,
} from "../src/domain-policy.js";


const accepted = new Map([
  ["example.com", "example.com"],
  [" EXAMPLE.COM. ", "example.com"],
  ["faß.de", "fass.de"],
  ["customer.pages.dev", "customer.pages.dev"],
  ["www.ck", "www.ck"],
  ["city.kawasaki.jp", "city.kawasaki.jp"],
  ["x.foo.kawasaki.jp", "x.foo.kawasaki.jp"],
  ["食狮.com.cn", "xn--85x722f.com.cn"],
]);

const denied = [
  "",
  "com",
  "pages.dev",
  "www.example.com",
  "x.www.ck",
  "foo.kawasaki.jp",
  "https://example.com",
  "*.example.com",
  "example.invalidtld",
  "under_score.com",
  "-leading.com",
];


test("domain policy matches retained IDNA and private PSL behavior", () => {
  for (const [input, expected] of accepted) {
    assert.equal(normalizeApex(input), expected, input);
  }
  for (const input of denied) {
    assert.throws(() => normalizeApex(input), /eTLD\+1/, input);
  }
  assert.equal(zoneForApex("customer.pages.dev"), "pages.dev");
  assert.equal(
    PSL_SHA256,
    "b69315c085d53972724b8f2df111ffc329b0c84fe0a47d62c8c91655cc774a38",
  );
  assert.equal(DOMAIN_POLICY_VERSION, `python-idna2003+psl-${PSL_SHA256}`);
});


test("domain policy matches the retained Python implementation", () => {
  const values = [
    ...accepted.keys(),
    ...denied,
    "example.com\u3002",
    "مثال.إختبار",
    "مثال.com",
    "A\u00adB.com",
    "\u212a.com",
    "\ufb03.com",
  ];
  let state = 0x5eed1234;
  while (values.length < 600) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    const point = state % 0x110000;
    if (point >= 0xd800 && point <= 0xdfff) continue;
    values.push(`${String.fromCodePoint(point)}.com`);
  }

  const workerRoot = resolve(import.meta.dirname, "..");
  const python = resolve(workerRoot, "../../.venv/bin/python");
  const probe = spawnSync(
    python,
    [resolve(import.meta.dirname, "python-domain-policy.py")],
    { input: JSON.stringify(values), encoding: "utf8" },
  );
  assert.equal(probe.status, 0, probe.stderr);
  const expected = JSON.parse(probe.stdout);
  const actual = values.map((value) => {
    try {
      return { ok: true, value: normalizeApex(value) };
    } catch (error) {
      return { ok: false, error: error.message };
    }
  });
  assert.deepEqual(actual, expected);
});


test("hostname-to-apex mapping matches the retained ingestion implementation", () => {
  const values = [
    "www.example.com",
    "*.wild.example.com",
    "x.customer.pages.dev",
    "www.食狮.com.cn",
    "EXAMPLE.COM.",
    "unknown.invalidtld",
    "bad@name.com",
    "localhost",
  ];
  let state = 0x51f15e;
  const labels = ["www", "api", "deep", "faß", "食狮"];
  const suffixes = ["example.com", "customer.pages.dev", "example.co.uk"];
  while (values.length < 300) {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    values.push(`${labels[state % labels.length]}.${suffixes[(state >>> 8) % suffixes.length]}`);
  }
  const workerRoot = resolve(import.meta.dirname, "..");
  const probe = spawnSync(
    resolve(workerRoot, "../../.venv/bin/python"),
    [resolve(import.meta.dirname, "python-hostname-policy.py")],
    { input: JSON.stringify(values), encoding: "utf8" },
  );
  assert.equal(probe.status, 0, probe.stderr);
  const expected = JSON.parse(probe.stdout);
  const actual = values.map((value) => {
    try {
      return {
        ok: true,
        hostname: normalizeHostname(value),
        apex: apexForHostname(value),
      };
    } catch {
      return { ok: false };
    }
  });
  assert.deepEqual(actual, expected);
});
