# Cloudflare migration work

The read worker and direct CT ingestion worker are separate deployments. Search traffic does not load certificate parsing code, and queue work cannot consume a request's CPU budget.

## Read worker

`index-worker` serves the static UI, HTTP API, and the single MCP `search` tool. Public browser requests do not need a token. A valid bearer token gets its configured allowance and is required only for `/internal/v1/records/batch`.

Set `CLIENT_TOKENS` as a Worker secret. It is a JSON array of client IDs, SHA-256 token digests, and optional limits. Raw tokens do not belong in Wrangler configuration or source control.

```json
[{"id":"threat-hunter","sha256":"64 lowercase hex characters","limit":10000}]
```

Set `MCP_ALLOWED_HOSTS` to the exact production hostnames before enabling `/mcp`. `MCP_ALLOWED_ORIGINS` may remain empty for non-browser MCP clients. The Worker refuses MCP traffic when the host allowlist is absent.

The exact UTC-day allowance is stored by a sharded Durable Object and is shared by HTTP and MCP searches. Static assets, health, readiness, and stats do not consume it. Invalid bearer tokens on public routes remain public callers; they never receive the token allowance. The internal batch route rejects them.

Regenerate the checked-in Python IDNA 2003 and private-PSL policy after an intentional `tldextract` snapshot change:

```sh
cd cloudflare/index-worker
npm run generate:domain-policy
npm test
```

## Direct CT ingestion worker

`ingest-worker` polls only exact allowlisted HTTPS CT hosts. A scheduled invocation records a bounded job in D1 and sends its ID to a Queue. The consumer parses leaf or precertificate DNS names, writes one immutable gzip delta to R2, then advances the D1 cursor. Completed-job retries re-send the idempotent delta notification so an earlier Queue outage cannot orphan an R2 object.

Provisioning is deliberately not hidden in code. Create the D1 database, source Queue, dead-letter Queue, shared compaction Queue, and compaction dead-letter Queue. Copy `wrangler.example.jsonc` to `wrangler.jsonc`, replace the D1 ID, then apply `migrations/0001_ingestion.sql`. Add reviewed CT log URLs to `ct_sources`; the host must also appear in `CT_ALLOWED_HOSTS`.

## URLScan ingestion worker

`urlscan-worker` keeps per-apex pagination in D1, charges the breadth UTC-day provider ledger before each request, and writes bounded URLScan pages as immutable deltas. Its default 70,000-request ceiling preserves the existing 10,000 search and 20,000 priority reserves within the 100,000 daily account budget. Seed `urlscan_sources` with normalized eTLD+1 values. A completed history page runs again immediately; a completed newest page waits for `URLSCAN_REFRESH_SECONDS`.

The API key is a Worker secret. It is intentionally absent from Wrangler vars, D1, Queue messages, logs, and R2 metadata:

```sh
cd cloudflare/urlscan-worker
cp wrangler.example.jsonc wrangler.jsonc
npx wrangler secret put URLSCAN_API_KEY --config wrangler.jsonc
npx wrangler d1 migrations apply subfinder-urlscan-control --remote --config wrangler.jsonc
```

## CZDS ingestion worker

`czds-worker` uses a daily Cron to authenticate, validate the approved ICANN link feed, and start one durable Workflow per selected zone. The Workflow streams the gzip zone, extracts NS owners, and writes bounded immutable deltas. D1 exposes `queued`, `running`, `staged`, `complete`, and `failed` separately. Delta notifications are sent only after the entire zone reaches `staged`, so a partial zone cannot enter a catalog generation.

Both ICANN credentials are Worker secrets:

```sh
cd cloudflare/czds-worker
cp wrangler.example.jsonc wrangler.jsonc
npx wrangler secret put CZDS_USERNAME --config wrangler.jsonc
npx wrangler secret put CZDS_PASSWORD --config wrangler.jsonc
npx wrangler d1 migrations apply subfinder-czds-control --remote --config wrangler.jsonc
```

The Worker accepts download URLs only from the two documented ICANN CZDS hosts and requires an artifact fingerprint before parsing. `CZDS_MAX_ZONES` limits zones selected per scheduled pass; it does not truncate a selected zone. `CZDS_ONLY_ZONE` restricts a staging deployment to one approved zone. The download step currently has a 30-minute timeout.

The staging `.com` run on 2026-09-27 exposed the limit of the single-step parser. The compressed artifact was 4,961,932,317 bytes. Two attempts exceeded Worker CPU time; the third lost its network connection. The failed test left 140,000 records in seven partial staging deltas. The job is `failed`, its R2 objects remain in the staging bucket, and no delta was sent to compaction. The staging Cron is disabled. Do not enable `.com` in production until a chunked or Container parser completes a full artifact and publishes its deltas.

## Generation reduction and publication

`compaction-worker` consumes the shared compaction Queue. It validates and hashes each delta, creates one open D1 generation, and maps records by the same SHA-256 partition prefix that the read Worker uses. A leased reducer merges provenance and first-seen dates, writes range-readable partition bundles with R2 multipart uploads, and verifies each bundle after upload. Unchanged partitions remain in their original generation.

`MAX_REDUCE_RECORDS` bounds the observations loaded for one changed partition and the records loaded for one modified overflow apex. A partition that exceeds either bound fails closed. Test those limits with production-sized deltas before enabling the compaction Cron.

Apply both `compaction-worker` D1 migrations. When every changed partition is reduced, the Worker writes `catalog/candidates/<generation>.json`. That object does not change search results. The protected `/admin/activate` route checks the candidate and its partition objects, archives the prior root, and replaces `catalog/root.json` with an R2 compare-and-swap. `/admin/rollback` restores the archived root with the same guard and re-registers the rolled-back deltas. Set `PUBLISH_TOKEN` as a Worker secret before using these routes.

The full SQLite exporter writes its root last. `scripts/publish_r2_generation.py` validates the files and uploads immutable partition objects, then uploads a candidate root. It never uploads `catalog/root.json`. If an older export root lacks `source_names`, run `scripts/enrich_r2_export_root.py` after the export finishes and before staging it. For the first seed, call `/admin/register-seed` after staging, then call `/admin/activate`. The seed has no prior root, so `/admin/rollback` refuses to remove it. Later generations use the same activation route after the reducer publishes their candidates.
