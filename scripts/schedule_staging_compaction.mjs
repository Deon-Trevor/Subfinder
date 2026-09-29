#!/usr/bin/env node
// Advance one staging generation through the local scheduled handler.
// Its Queue producer is local; dispatch remote jobs separately.
import { execFileSync, spawn } from "node:child_process";
import { resolve } from "node:path";

const account = "13420e9593fa2a2b308bbdb9256daccf";
const queues = ["877595bfda8042969d9abe95ae9d7f12", "3a5b3ca41870467283f328919b4c1041"];
const workerRoot = resolve(import.meta.dirname, "../cloudflare/compaction-worker");
const wrangler = resolve(workerRoot, "node_modules/.bin/wrangler");
const flag = process.argv[2];
if ((flag !== undefined && flag !== "--execute") || process.argv.length > 3) {
	throw new Error("usage: schedule_staging_compaction.mjs [--execute]");
}

function sql(query) {
	const raw = execFileSync(wrangler, [
		"d1", "execute", "subfinder-generation-stage-ledger", "--remote", "--json",
		"--config", "wrangler.staging.jsonc", "--command", query,
	], { cwd: workerRoot, encoding: "utf8" });
	const result = JSON.parse(raw);
	if (result.length !== 1 || result[0].success !== true) {
		throw new Error("staging D1 query failed");
	}
	return result[0].results;
}

function state() {
	const pending = sql("SELECT count(*) AS count FROM catalog_deltas WHERE state = 'registered'")[0];
	const generations = sql(
		"SELECT generation_id, state FROM catalog_generations " +
		"WHERE state IN ('mapping', 'mapped', 'reducing', 'published') ORDER BY created_at",
	);
	if (generations.length > 1) throw new Error("more than one unfinished generation exists");
	const current = generations[0] ?? null;
	return { current, registered: Number(pending.count) };
}

function nextAction() {
	const { current, registered } = state();
	return {
		action: current?.state === "mapped" ? "reduce" :
			current?.state === "mapping" || current?.state === "reducing" ? "wait" :
			current?.state === "published" ? "activate" : registered > 0 ? "map" : "none",
		generation: current?.generation_id ?? null,
		state: current?.state ?? null,
		registered,
	};
}

const before = nextAction();
console.log(JSON.stringify({ ...before, execute: flag === "--execute" }));
if (flag !== "--execute" || before.action === "none") process.exit(0);
if (!["map", "reduce"].includes(before.action)) {
	throw new Error(`cannot advance staging while action is ${before.action}`);
}

const token = process.env.CLOUDFLARE_API_TOKEN || JSON.parse(execFileSync(wrangler, [
	"auth", "token", "--json",
], { cwd: workerRoot, encoding: "utf8" })).token;
for (const queue of queues) {
	const response = await fetch(
		`https://api.cloudflare.com/client/v4/accounts/${account}/queues/${queue}/metrics`,
		{ headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(10000) },
	);
	const document = await response.json();
	if (!response.ok || document.success !== true || document.result.backlog_count !== 0) {
		throw new Error("staging Queue is unavailable or not empty");
	}
}

const port = 18793;
const child = spawn(wrangler, [
	"dev", "--config", "wrangler.staging-admin.jsonc", "--ip", "127.0.0.1",
	"--port", String(port), "--test-scheduled",
], { cwd: workerRoot, stdio: ["ignore", "pipe", "pipe"] });
let childExited = false;
child.stdout.resume();
child.stderr.resume();
child.on("exit", () => { childExited = true; });

async function waitForAdmin() {
	for (let attempt = 0; attempt < 60; attempt += 1) {
		if (childExited) throw new Error("local staging admin exited before it was ready");
		try {
			const response = await fetch(`http://127.0.0.1:${port}/health`, {
				signal: AbortSignal.timeout(1000),
			});
			if (response.ok && await response.text() === "ok") return;
		} catch {
			// Wrangler can take a few seconds to start its local listener.
		}
		await new Promise((resolveWait) => setTimeout(resolveWait, 1000));
	}
	throw new Error("local staging admin did not start");
}

try {
	await waitForAdmin();
	const response = await fetch(
		`http://127.0.0.1:${port}/cdn-cgi/local/scheduled?format=json`,
		{ signal: AbortSignal.timeout(300000) },
	);
	if (!response.ok) throw new Error(`scheduled handler failed: HTTP ${response.status}`);
	const after = state();
	if (before.action === "map" && after.current?.state !== "mapping") {
		throw new Error("scheduled handler did not start a mapping generation");
	}
	if (before.action === "reduce" &&
		(after.current?.generation_id !== before.generation || after.current?.state !== "reducing")) {
		throw new Error("scheduled handler did not start reduction for the same generation");
	}
	console.log(JSON.stringify({ before, after,
		next: `node scripts/dispatch_staging_compaction.mjs ${before.action} ${after.current.generation_id}` }));
} finally {
	child.kill("SIGINT");
}
