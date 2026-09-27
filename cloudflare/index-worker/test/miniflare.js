import { resolve } from "node:path";

import { buildSync } from "esbuild";
import { Miniflare } from "miniflare";


export function createMiniflare(workerRoot, { assetHandler, envOverrides = {} } = {}) {
  const moduleName = "index.js";
  const bundle = buildSync({
    bundle: true,
    conditions: ["workerd", "worker", "browser"],
    entryPoints: [resolve(workerRoot, "src/index.js")],
    format: "esm",
    platform: "browser",
    write: false,
  }).outputFiles[0].text;
  return new Miniflare({
    workers: [{
      config: {
        name: "subfinder-index",
        compatibilityDate: "2026-09-27",
        manifest: {
          mainModule: moduleName,
          modulesRoot: resolve(workerRoot, "src"),
          modules: { [moduleName]: { type: "esm", contents: bundle } },
        },
        env: {
          CATALOG: { type: "r2", name: "CATALOG" },
          QUOTA_LEDGER: {
            type: "durable-object",
            worker: "subfinder-index",
            exportName: "QuotaLedger",
          },
          CATALOG_ROOT_KEY: { type: "text", value: "catalog/root.json" },
          LOCAL_CLIENT_IP: { type: "text", value: "127.0.0.1" },
          PUBLIC_REQUEST_LIMIT: { type: "text", value: "1000" },
          TOKEN_REQUEST_LIMIT: { type: "text", value: "250000" },
          MCP_ALLOWED_HOSTS: { type: "text", value: "worker.test,127.0.0.1" },
          MCP_RESULT_LIMIT: { type: "text", value: "100000" },
          CLIENT_TOKENS: {
            type: "text",
            value: JSON.stringify([{
              id: "threat-hunter",
              sha256: "e200c300499b48616df8fbe5a089e1eebf525e826ed03163a4868985d9123ccb",
              limit: 3,
            }]),
          },
          ASSETS: {
            type: "fetcher",
            handler: assetHandler || ((request) => {
              const path = new URL(request.url).pathname;
              return new Response(`asset:${path}`, {
                headers: { "content-type": "text/plain" },
              });
            }),
          },
          ...Object.fromEntries(
            Object.entries(envOverrides).map(([name, value]) => [
              name,
              { type: "text", value: String(value) },
            ]),
          ),
        },
        exports: {
          QuotaLedger: { type: "durable-object", storage: "sqlite" },
        },
      },
    }],
  });
}
