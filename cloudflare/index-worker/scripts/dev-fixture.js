import { readFileSync, readdirSync, statSync } from "node:fs";
import { resolve, sep } from "node:path";

import { createMiniflare } from "../test/miniflare.js";


const workerRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(workerRoot, "../..");
const exportRoot = resolve(process.argv[2] || "");
const webRoot = resolve(repositoryRoot, "web");
const contentTypes = new Map([
  [".css", "text/css; charset=utf-8"],
  [".html", "text/html; charset=utf-8"],
  [".ico", "image/x-icon"],
  [".js", "text/javascript; charset=utf-8"],
  [".json", "application/json; charset=utf-8"],
  [".png", "image/png"],
  [".svg", "image/svg+xml"],
  [".webmanifest", "application/manifest+json"],
]);


function* files(directory) {
  for (const name of readdirSync(directory)) {
    const path = resolve(directory, name);
    if (statSync(path).isDirectory()) yield* files(path);
    else yield path;
  }
}


function assetHandler(request) {
  const url = new URL(request.url);
  const relative = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
  const path = resolve(webRoot, relative);
  if (!path.startsWith(`${webRoot}${sep}`) || !statSafe(path)) {
    return new Response("not found", { status: 404 });
  }
  const suffix = path.slice(path.lastIndexOf("."));
  return new Response(request.method === "HEAD" ? null : readFileSync(path), {
    headers: {
      "content-type": contentTypes.get(suffix) || "application/octet-stream",
    },
  });
}


function statSafe(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}


if (!statSafe(resolve(exportRoot, "catalog/root.json"))) {
  throw new Error("pass an exported catalog directory as the first argument");
}

const miniflare = createMiniflare(workerRoot, { assetHandler });
const bucket = await miniflare.getR2Bucket("CATALOG");
for (const path of files(exportRoot)) {
  const key = path.slice(exportRoot.length + 1).split(sep).join("/");
  await bucket.put(key, readFileSync(path));
}

const url = await miniflare.ready;
process.stdout.write(`${url.toString()}\n`);

async function stop() {
  await miniflare.dispose();
  process.exit(0);
}

process.on("SIGINT", stop);
process.on("SIGTERM", stop);
