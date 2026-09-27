import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";

import { createMiniflare } from "../test/miniflare.js";


const workerRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(workerRoot, "../..");
const threatHunterRoot = resolve(process.env.THREAT_HUNTER_ROOT ||
  resolve(repositoryRoot, "../threat-hunter"));
const fixtureRoot = mkdtempSync(join(tmpdir(), "subfinder-hunter-"));


function* files(directory) {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) yield* files(path);
    else yield path;
  }
}


const python = resolve(threatHunterRoot, ".venv/bin/python");
const probe = `
import asyncio
from hunter.intel.subfinder import read_indexes

async def main():
    pending = ("example.com", "large.dev") + tuple(
        f"batch-{index}.com" for index in range(24998)
    )
    seen = set()
    nonempty = {}
    job_id = ""
    cursor = -1
    while pending:
        result = await read_indexes(pending, resume_job_id=job_id, after_cursor=cursor)
        assert not result.failed(), result.error
        for item in result.evidence:
            assert item.apex not in seen
            seen.add(item.apex)
            if item.records:
                nonempty[item.apex] = len(item.records)
        pending = tuple(result.metadata["pending_apexes"])
        job_id = result.metadata["batch_job_id"]
        cursor = result.metadata["chunk_cursor"]
    assert len(seen) == 25000, len(seen)
    assert nonempty == {"example.com": 3, "large.dev": 80}, nonempty
    assert cursor == 999, cursor
    print(f"Threat Hunter delivered {len(seen)} apexes in job {job_id}, cursor {cursor}")

asyncio.run(main())
`;


async function main() {
  execFileSync(
    resolve(repositoryRoot, ".venv/bin/python"),
    [resolve(workerRoot, "test/build_fixture.py"), fixtureRoot],
    { stdio: "inherit" },
  );
  const worker = createMiniflare(workerRoot, {
    envOverrides: {
      CLIENT_TOKENS: JSON.stringify([{
        id: "threat-hunter",
        sha256: "e200c300499b48616df8fbe5a089e1eebf525e826ed03163a4868985d9123ccb",
        limit: 25000,
      }]),
    },
  });
  const server = createServer(async (request, response) => {
    try {
      const body = [];
      for await (const chunk of request) body.push(chunk);
      const upstream = await worker.dispatchFetch(`http://worker.test${request.url}`, {
        method: request.method,
        headers: request.headers,
        body: body.length ? Buffer.concat(body) : undefined,
      });
      response.writeHead(upstream.status, Object.fromEntries(upstream.headers));
      response.end(Buffer.from(await upstream.arrayBuffer()));
    } catch (error) {
      response.writeHead(500);
      response.end(String(error));
    }
  });
  try {
    const bucket = await worker.getR2Bucket("CATALOG");
    for (const path of files(fixtureRoot)) {
      await bucket.put(relative(fixtureRoot, path).split(sep).join("/"), readFileSync(path));
    }
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    const child = spawn(python, ["-c", probe], {
      cwd: threatHunterRoot,
      env: {
        ...process.env,
        SUBFINDER_BASE_URL: `http://127.0.0.1:${port}`,
        SUBFINDER_API_TOKEN: "threat-hunter-test",
        SUBFINDER_BATCH_WAIT_SECONDS: "60",
      },
      stdio: "inherit",
    });
    const code = await new Promise((resolve) => child.on("exit", resolve));
    assert.equal(code, 0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await worker.dispose();
    rmSync(fixtureRoot, { recursive: true, force: true });
  }
}


main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
