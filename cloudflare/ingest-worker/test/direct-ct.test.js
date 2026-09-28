import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { test } from "node:test";

import {
  entryFirstSeen,
  entryHostnames,
  recordsFromEntries,
  validatedLogUrl,
} from "../src/direct-ct.js";


const workerRoot = resolve(import.meta.dirname, "..");
const fixtures = JSON.parse(execFileSync(
  resolve(workerRoot, "../../.venv/bin/python"),
  [resolve(import.meta.dirname, "build-ct-fixture.py")],
  { encoding: "utf8" },
));


test("direct CT extracts SAN, wildcard, precertificate, CN, and timestamp", () => {
  assert.deepEqual(entryHostnames(fixtures.san), [
    "www.example.com",
    "wild.example.com",
  ]);
  assert.deepEqual(entryHostnames(fixtures.precert), ["precert.example.com"]);
  assert.deepEqual(entryHostnames(fixtures.cn), ["cn-only.example.com"]);
  assert.equal(entryFirstSeen(fixtures.san), "2023-11-14T22:13:20.000Z");
});


test("direct CT ignores malformed entries and keeps deterministic apex records", () => {
  assert.deepEqual(entryHostnames({ leaf_input: "not-base64" }), []);
  const records = recordsFromEntries([
    fixtures.san,
    fixtures.precert,
    { dns_names: ["WWW.EXAMPLE.COM.", "bad@name.com"] },
  ]);
  assert.deepEqual(records, [
    {
      apex: "example.com",
      first_seen: "2023-11-14T22:13:20.000Z",
      hostname: "www.example.com",
    },
    {
      apex: "example.com",
      first_seen: "2023-11-14T22:13:20.000Z",
      hostname: "precert.example.com",
    },
    {
      apex: "example.com",
      first_seen: "2023-11-14T22:13:20.000Z",
      hostname: "wild.example.com",
    },
  ].sort((left, right) => left.hostname.localeCompare(right.hostname)));
});


test("direct CT excludes public suffix names but keeps registrable children", () => {
  assert.deepEqual(recordsFromEntries([{
    dns_names: ["blogspot.com", "tenant.blogspot.com"],
  }]), [{
    apex: "tenant.blogspot.com",
    first_seen: null,
    hostname: "tenant.blogspot.com",
  }]);
});


test("CT egress is HTTPS and exact-host allowlisted", () => {
  assert.equal(
    validatedLogUrl(
      "https://ct.example/log/",
      ["ct.example"],
    ).toString(),
    "https://ct.example/log",
  );
  for (const url of [
    "http://ct.example/log",
    "https://user@ct.example/log",
    "https://ct.example.evil/log",
    "https://127.0.0.1/log",
  ]) {
    assert.throws(() => validatedLogUrl(url, ["ct.example"]), /not allowed/);
  }
});
