# Cloudflare migration work

The read worker and direct CT ingestion worker are separate deployments. Search traffic does not load certificate parsing code, and queue work cannot consume a request's CPU budget.

The [documentation site](/) is a third, static deployment on Cloudflare
Pages. The read Worker serves it at `/docs/`. The Pages project has no R2, D1,
Queue, or secret binding. Building it does not publish a catalog generation.

`subfinder.pundit.workers.dev` now runs `index-worker` with the static UI,
HTTP API, MCP, the active staging R2 seed, and the Pages proxy. The earlier
`static-worker` configuration remains in the repository as an assets-only
fallback. Do not deploy it over the live read Worker.
The Workers preview and direct Pages site send `X-Robots-Tag: noindex`. The
Worker's static rule is scoped to `subfinder.pundit.workers.dev`, and its docs
proxy strips the Pages rule on other hosts. This keeps a future production
hostname indexable without changing the preview site.

## Read worker

`index-worker` serves the static UI, HTTP API, and the single MCP `search` tool. Public browser requests do not need a token. A valid bearer token gets its configured allowance and is required only for `/internal/v1/records/batch`.

`index-worker/wrangler.staging.jsonc` deploys the same API code at
`subfinder-index-stage.pundit.workers.dev` with the private
`subfinder-catalog-stage` R2 bucket. It has no static asset binding or custom
domain. Both Workers currently read the staging root `seed-20260927`; neither
changes `subfinder.syncpundit.io`. The pre-seed verification command applies
only before root activation.

The preview `CLIENT_TOKENS` secret uses a separate token from production.
On the Mac used for staging, its raw value is stored in the keychain item
`subfinder-stage-threat-hunter` for account `threat-hunter`; only its SHA-256
digest is stored in each preview Worker secret. Do not put the raw token in
Wrangler configuration.

Set `CLIENT_TOKENS` as a Worker secret. It is a JSON array of client IDs, SHA-256 token digests, and optional limits. Raw tokens do not belong in Wrangler configuration or source control.

```json
[{"id":"threat-hunter","sha256":"64 lowercase hex characters","limit":10000}]
```

Set `MCP_ALLOWED_HOSTS` to the exact production hostnames before enabling `/mcp`. `MCP_ALLOWED_ORIGINS` may remain empty for non-browser MCP clients. The Worker refuses MCP traffic when the host allowlist is absent.

The exact UTC-day allowance is stored by a sharded Durable Object and is shared by HTTP and MCP searches. Static assets, health, readiness, and stats do not consume it. Invalid bearer tokens on public routes remain public callers; they never receive the token allowance. The internal batch route rejects them.

### Durable Threat Hunter batches

The read Worker supports a queued batch for a normal hunt of up to 25,000
unique apexes. Send `POST /internal/v1/record-batches` with a valid bearer token,
an `Idempotency-Key` of at most 128 characters, and a JSON `apexes` array. A
successful submission returns `202`, a job document, and a `Location` header.
The same normalized request and key replay the existing job. Reusing the key
for a different request returns `409`.

Poll `GET /internal/v1/record-batches/{job_id}` for progress, or
`GET /internal/v1/record-batches/{job_id}/chunks?after=-1&limit=10&wait=20`
for immutable completed chunks. Advance `after` to each returned cursor.
`limit` may be 1 through 50 and `wait` may be 0 through 20 seconds. A replayed
cursor returns the same completed data. `POST .../{job_id}/cancel` releases
unstarted work. Only the token that submitted a job can read or cancel it.

The default token allowance is 250,000 apex units per UTC day and submission
reserves one unit per apex. The Durable Object processes up to 25 apexes per
alarm slice, with separate limits for record count, provenance rows, and
serialized bytes. A single oversized apex is reported as an error in its chunk
without losing unrelated apexes. The configured bounds live in
`index-worker/wrangler.jsonc` and `index-worker/src/index.js`.

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

The first staging `.com` run on 2026-09-27 exceeded Worker CPU time while parsing a 4,961,932,317-byte compressed artifact. The replacement parser runs in a Cloudflare Container for the zones listed in `CZDS_CONTAINER_ZONES`. The Workflow polls its state without holding a long CPU-bound step. The Container streams the zone, and its private outbound handler writes bounded deltas through the existing R2 and D1 bindings. Only a complete gzip stream with matching artifact length and contiguous delta counts can move the job to `staged`. The earlier seven partial staging deltas were not published. The staging Cron remains disabled.

The staging `.com` Workflow completed on 2026-09-28 with 8,760 contiguous
deltas and 175,195,918 records. The staging seed is active. The staging
compaction Queue consumer is connected with a batch size and concurrency of
one, eight retries, and a dead-letter Queue. `REGISTRATION_ONLY=true` makes
the staging Worker refuse map and reduce Queue messages and skip scheduled
generation work; refused messages retry and eventually reach the dead-letter
Queue. The staging Cron also remains disabled. Queue delivery can register
deltas but cannot start mapping, reduction, or root activation. A 98-message
remote sample registered 1,960,000 records in about
158 seconds, with no failed invocations observed in the sampled tail. The
remaining messages are being delivered under the same bound. A later
[full reconciliation](/operations/staging-reconciliation) found dead-lettered
CZDS chunks with invalid public-suffix apexes; the sampled invocation tail
was not proof of full coverage. Check both D1 databases, the live Queue and
dead-letter backlogs, and Worker errors before enabling generation work.
Registration throughput is not a measurement of reducer throughput or the
cost of a full generation.

A local pilot reduced one partition from a real `.com` delta against the seed,
then activated and rolled back the candidate in disposable storage. It did not
process the full delta or backlog. Reconcile registered deltas with the seed and
measure remote mapping and reduction before enabling the Cron. Do not switch
the production hostname until the operator approves the cutover.

## Generation reduction and publication

`compaction-worker` consumes the shared compaction Queue. It validates and hashes each delta, creates one open D1 generation, and maps records by the same SHA-256 partition prefix that the read Worker uses. A leased reducer merges provenance and first-seen dates, writes range-readable partition bundles with R2 multipart uploads, and verifies each bundle after upload. Unchanged partitions remain in their original generation.

`MAX_REDUCE_RECORDS` bounds the observations loaded for one changed partition and the records loaded for one modified overflow apex. A partition that exceeds either bound fails closed. Test those limits with production-sized deltas before enabling the compaction Cron.

Apply both `compaction-worker` D1 migrations. When every changed partition is reduced, the Worker writes `catalog/candidates/<generation>.json`. That object does not change search results. The protected `/admin/activate` route checks the candidate and its partition objects, archives the prior root, and replaces `catalog/root.json` with an R2 compare-and-swap. `/admin/rollback` restores the archived root with the same guard and re-registers the rolled-back deltas. Set `PUBLISH_TOKEN` as a Worker secret before using these routes.

The full SQLite exporter writes its root last. `scripts/publish_r2_generation.py` validates the files and uploads immutable partition objects, then uploads a candidate root. It never uploads `catalog/root.json`. If an older export root lacks `source_names`, run `scripts/enrich_r2_export_root.py` after the export finishes and before staging it. For the first seed, call `/admin/register-seed` after staging, then call `/admin/activate`. The seed has no prior root, so `/admin/rollback` refuses to remove it. Later generations use the same activation route after the reducer publishes their candidates.
