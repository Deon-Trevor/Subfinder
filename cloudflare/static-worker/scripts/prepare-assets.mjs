import { cp, mkdir, rm, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";

const workerDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const sourceDir = resolve(workerDir, "../../web");
const outputDir = join(workerDir, "dist");
const assets = [
  "app.css",
  "app.js",
  "apple-touch-icon.png",
  "favicon.ico",
  "favicon.svg",
  "icon-192.png",
  "icon-512-maskable.png",
  "icon-512.png",
  "index.html",
  "robots.txt",
  "site.webmanifest",
];

await rm(outputDir, { recursive: true, force: true });
await mkdir(outputDir, { recursive: true });
for (const asset of assets) {
  await cp(join(sourceDir, asset), join(outputDir, asset));
}
await writeFile(
  join(outputDir, "_headers"),
  "/*\n  X-Robots-Tag: noindex\n  X-Content-Type-Options: nosniff\n",
);
console.log(`Prepared ${assets.length} static assets for the isolated preview Worker.`);
