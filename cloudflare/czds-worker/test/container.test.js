import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { test } from "node:test";
import { setTimeout } from "node:timers/promises";
import { gzipSync } from "node:zlib";

import { createParserServer, postInternal, processZone } from "../container/server.js";


const job = {
  job_id: "a".repeat(64),
  zone: "com",
  url: "https://czds-download-api.icann.org/czds/downloads/com.zone",
  token: "fixture-token",
  max_records: 2,
};


test("container streams a gzip zone into ordered chunks and completes only at EOF", async () => {
  const archive = gzipSync([
    "$ORIGIN com.",
    "example 3600 IN NS ns1.example.",
    "  3600 IN NS ns2.example.",
    "second 3600 IN NS ns.second.",
    "third 3600 IN NS ns.third.",
    "",
  ].join("\n"));
  const calls = [];
  const result = await processZone(job, {
    download: async (_url, options) => {
      assert.equal(options.headers.authorization, "Bearer fixture-token");
      return new Response(archive, {
        headers: { "content-length": String(archive.length), etag: '"fixture"' },
      });
    },
    post: async (path, body) => {
      calls.push({ path, body });
      return path === "/complete"
        ? { state: "staged", deltaCount: body.chunk_count, hostnameCount: body.hostname_count }
        : { ok: true };
    },
  });
  assert.deepEqual(calls.map((call) => call.path), [
    "/begin", "/chunk", "/chunk", "/complete",
  ]);
  assert.deepEqual(calls.filter((call) => call.path === "/chunk")
    .flatMap((call) => call.body.records.map((record) => record.hostname)), [
    "example.com", "second.com", "third.com",
  ]);
  assert.deepEqual(result, { state: "staged", deltaCount: 2, hostnameCount: 3 });
});


test("truncated compressed zone never sends completion", async () => {
  const archive = gzipSync("example 3600 IN NS ns.example.\n").subarray(0, -5);
  const calls = [];
  await assert.rejects(processZone(job, {
    download: async () => new Response(archive, {
      headers: { "content-length": String(archive.length), etag: '"fixture"' },
    }),
    post: async (path) => { calls.push(path); return { ok: true }; },
  }));
  assert.ok(calls.includes("/begin"));
  assert.ok(!calls.includes("/complete"));
});


test("parser server exposes running and terminal state without returning a token", async () => {
  let finish;
  const server = createParserServer({
    process: async () => await new Promise((resolve) => { finish = resolve; }),
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    const started = await fetch(`${url}/start`, {
      method: "POST",
      body: JSON.stringify(job),
    });
    assert.deepEqual(await started.json(), { state: "running" });
    assert.deepEqual(await (await fetch(`${url}/status`)).json(), { state: "running" });
    finish({ state: "staged", deltaCount: 1, hostnameCount: 1 });
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(await (await fetch(`${url}/status`)).json(), {
      state: "staged", deltaCount: 1, hostnameCount: 1,
    });
  } finally {
    server.close();
  }
});


test("chunk callbacks retry transient failures but report validation errors", async () => {
  let calls = 0;
  const result = await postInternal("/chunk", { chunk_index: 1 }, async () => {
    calls += 1;
    return calls === 1
      ? Response.json({ detail: "temporary D1 failure" }, { status: 503 })
      : Response.json({ ok: true });
  });
  assert.deepEqual(result, { ok: true });
  assert.equal(calls, 2);

  calls = 0;
  await assert.rejects(postInternal("/chunk", {}, async () => {
    calls += 1;
    return Response.json({ detail: "CZDS chunk has an invalid record" }, { status: 409 });
  }), /invalid record/);
  assert.equal(calls, 1);
});


test("parser server exits cleanly on SIGTERM", async () => {
  const child = spawn(process.execPath, [
    "--input-type=module", "-e",
    'import { runParserServer } from "./container/server.js"; ' +
      'const server = runParserServer(0); server.on("listening", () => console.log("ready"));',
  ], { cwd: new URL("..", import.meta.url), stdio: ["ignore", "pipe", "pipe"] });
  try {
    const ready = Promise.race([
      once(child.stdout, "data"),
      once(child, "exit").then(() => { throw new Error("parser exited before listening"); }),
    ]);
    await ready;
    const exited = once(child, "exit");
    child.kill("SIGTERM");
    const [code, signal] = await Promise.race([
      exited,
      setTimeout(2000).then(() => { throw new Error("parser ignored SIGTERM"); }),
    ]);
    assert.equal(code, 0);
    assert.equal(signal, null);
  } finally {
    if (child.exitCode === null) child.kill("SIGKILL");
  }
});
