# Run Subfinder on Cloudflare

This guide describes the Cloudflare deployment components. Choose your own
Worker, Queue, D1 database, R2 bucket, Pages project, and hostname names. The
names in this guide are examples, not resources you should connect to.

Cloudflare is optional. For a single-host installation, start with the
[Compose guide](/operations/compose).

## Deployment layout

| Component | Role | Example name |
| --- | --- | --- |
| Read Worker | Serves the UI, HTTP API, MCP, and `/docs/` | `example-read` |
| Catalog R2 bucket | Holds immutable partition objects and `catalog/root.json` | `example-catalog` |
| Compaction Worker | Maps deltas, reduces partitions, and publishes candidates | `example-compaction` |
| Generation D1 database | Tracks deltas, leases, and generations | `example-generation-ledger` |
| Compaction Queue and dead-letter Queue | Deliver and retain generation work | `example-compaction-jobs`, `example-compaction-dlq` |
| Pages project | Hosts the built documentation | `example-docs` |

Direct CT, URLScan, and CZDS ingestion are separate, optional Workers. Each
needs its own control D1 database and job Queue. Their completed deltas go to
the catalog bucket and notify the compaction Queue. Keep their schedules
disabled until their sources, limits, and recovery procedures are reviewed.

The read Worker serves only an **active** catalog root. A mapped or reduced
delta is not searchable until its candidate generation has been verified and
activated. The docs Pages project needs no R2, D1, Queue, or secret binding.

The repository does not ship the maintainer's zone files or index data. A new
operator starts with an empty database, collects only sources and zones they
are authorized to use, and builds their own first catalog. Until that first
generation is active, an empty or unready search service is expected.

## Configure your resources

1. Create an R2 catalog bucket, a generation-ledger D1 database, a compaction
   Queue, and its dead-letter Queue in your Cloudflare account.
2. Use the `wrangler.example.jsonc` files in the optional Worker directories
   as binding references. The read Worker has no generic checked-in template:
   create its configuration with your own hostname, catalog bucket, Pages
   origin, Durable Object, and optional service bindings. Never deploy a
   checked-in environment configuration unchanged.
3. Apply the migrations in the relevant Worker's `migrations/` directory to
   its own D1 database. Do this before sending jobs to a Queue.
4. Leave Cron lists empty for the initial deployment. Deploy the ingestion
   Workers and compaction Worker only after their bindings and Queue consumers
   point to the same catalog and generation ledger.
5. Set `PUBLISH_TOKEN` as a compaction Worker secret. Set `CLIENT_TOKENS` as a
   read Worker secret if clients need authenticated quotas or batch APIs.
   Never commit raw tokens or provider credentials.
6. Set `MCP_ALLOWED_HOSTS` to the exact hostnames that should serve `/mcp`.
   The read Worker refuses MCP traffic when this allowlist is absent.

If you enable the optional URLScan Worker, set `URLSCAN_API_KEY` as its Worker
secret. If you enable CZDS, set `CZDS_USERNAME` and `CZDS_PASSWORD` as Worker
secrets. Do not put these values in Wrangler configuration, D1 rows, Queue
messages, or documentation.

## Publish the first catalog

The catalog exporter and publication scripts live in `scripts/`. The exporter
writes partition objects and a candidate root. It does not overwrite
`catalog/root.json`. For the first seed, register the candidate through the
compaction Worker's protected `/admin/register-seed` route, verify the
candidate and its partition objects, then activate it through
`/admin/activate`. Set `PUBLISH_TOKEN` before calling either route.

For later generations, the compaction Worker consumes immutable deltas and
publishes a candidate. Verify its identity, source metadata, counts, and every
index and bundle hash before activation. Keep `catalog/root.json` as the
publication boundary. Never point the read Worker at a candidate prefix.

## Connect the read Worker and docs

Bind the read Worker to your catalog R2 bucket and any optional service
bindings. Configure your own custom hostname, for example
`search.example.net`. The hostname should resolve to the read Worker, which
serves the UI and APIs at `/` and proxies the Pages build at `/docs/`.

Build the docs from `docs/` with `npm run check`, then upload
`.vitepress/dist` to your Pages project. Configure the read Worker's docs
origin to match that project. The Pages project is a static asset origin; it
must not receive catalog bindings or secrets.

If your zone removes visitor IP headers, configure a request-header transform
for **only** the read Worker's hostname to overwrite a dedicated trusted
client-IP header with Cloudflare's `ip.src`. Do not trust a client-supplied
forwarded-IP header for per-client quotas. Test the rule and quota behavior on
the exact public hostname before relying on it.

## Check the deployment

Use your own hostname in these examples:

```sh
curl -fsS https://search.example.net/health
curl -fsS https://search.example.net/ready
curl -fsS https://search.example.net/v1/stats
curl -fsS 'https://search.example.net/v1/search?apex=example.com'
curl -fsS https://search.example.net/docs/
```

Confirm that `/ready` reports the expected active generation, that searches
return exact-apex results, and that both the main and dead-letter Queues have
the expected backlogs. Also test a known miss and an invalid token. Keep
source and compaction schedules disabled until you have a reviewed recovery
path for failed jobs and dead-letter messages.

See the [API reference](/reference/api) for HTTP, MCP, and durable batch
contracts. Search does not probe the requested domain or submit a URLScan
scan.
