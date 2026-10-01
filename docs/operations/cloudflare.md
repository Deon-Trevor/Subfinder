# Cloudflare migration work

The read worker and direct CT ingestion worker are separate deployments. Search traffic does not load certificate parsing code, and queue work cannot consume a request's CPU budget.

The [documentation site](/) is a third, static deployment on Cloudflare
Pages. The read Worker serves it at `/docs/`. The Pages project has no R2, D1,
Queue, or secret binding. Building it does not publish a catalog generation.

`subfinder.syncpundit.io` runs `index-worker` with the static UI, HTTP API,
MCP, the active staging R2 catalog, and the Pages proxy. The earlier
`static-worker` configuration remains in the repository as an assets-only
fallback. Do not deploy it over the live read Worker.
The direct Pages site sends `X-Robots-Tag: noindex`; the read Worker's docs
proxy strips that header on the production hostname.

## Read worker

`index-worker` serves the static UI, HTTP API, and the single MCP `search` tool. Public browser requests do not need a token. A valid bearer token gets its configured allowance and is required for both internal batch APIs.

`cloudflare/index-worker/wrangler.staging.jsonc` deploys the same API code at
`subfinder-index-stage.pundit.workers.dev` with the private
`subfinder-catalog-stage` R2 bucket. It has no static asset binding or custom
domain. Production temporarily reads the same active R2 root, but staging
generation activation remains a separate operation. Check `/ready` and the
staging generation ledger before acting.

The preview `CLIENT_TOKENS` secret uses a separate token from production.
On the Mac used for staging, its raw value is stored in the keychain item
`subfinder-stage-threat-hunter` for account `threat-hunter`; only its SHA-256
digest is stored in each preview Worker secret. Do not put the raw token in
Wrangler configuration.

Use the [cutover acceptance checks](/operations/cutover-acceptance) to verify
the production read paths against the local catalog. They do not submit a
live batch.

### Interim production cutover

`cloudflare/index-worker/wrangler.jsonc` deploys the `subfinder` Worker at
`subfinder.syncpundit.io`. It reads the currently active
`subfinder-catalog-stage` root while staged `.com` compaction continues. This
is a partial catalog, not a copy to an isolated production bucket. The
Workers preview hostname is disabled for this deployment.

The `syncpundit.io` zone enables the Managed Transform "Remove visitor IP
headers". Public searches need a client IP for per-client quotas, so a
request-header transform scoped to `subfinder.syncpundit.io` overwrites
`X-Subfinder-Client-IP` with Cloudflare's `ip.src`. The Worker trusts this
custom header only on that exact hostname and fails closed if neither it nor
`CF-Connecting-IP` is present. Keep the zone-wide privacy transform enabled;
do not replace the scoped rule with an untrusted forwarded header.

The public read Worker binds to `subfinder-urlscan-prod`, while
`subfinder-index-stage` keeps `subfinder-urlscan-stage`. The production URLScan
Worker has its own D1 control database, job Queue, and dead-letter Queue. Its
Cron is disabled. On-demand jobs use a `prod` delta namespace so they cannot
overwrite staged URLScan objects or reuse staged ledger IDs. During this interim
cutover, completed deltas go into the shared staging R2 bucket and staging
compaction Queue because that is the catalog the public read Worker serves.
They are not immediately searchable: the generation must still be mapped,
reduced, verified, and activated. Do not promise immediate enrichment results.

The production URLScan API key belongs in the Worker secret
`URLSCAN_API_KEY`, not in Wrangler config. The initial on-demand bounds are
100 provider pages per UTC day, at most 20 priority pages, page size 100, and
one Queue consumer. No scheduled source is enabled. For each deployment,
verify both Queue backlogs and dead-letter Queues, the active root, the Pages
`/docs/` proxy, search and MCP on the exact hostname, and whether old preview
URLScan job IDs still need status access. The Pages project is
Direct Upload: building or merging `main` does not publish docs.

The URLScan service must be deployed before the public read Worker and have
its `URLSCAN_API_KEY` secret. Confirm the secret is listed without printing
its value. Apply D1 migrations if the production control database is new.
Do not enable a URLScan Cron or the compaction Cron as part of the hostname
cutover.

Set `CLIENT_TOKENS` as a Worker secret. It is a JSON array of client IDs, SHA-256 token digests, and optional limits. Raw tokens do not belong in Wrangler configuration or source control.

```json
[{"id":"threat-hunter","sha256":"64 lowercase hex characters","limit":250000}]
```

Set `MCP_ALLOWED_HOSTS` to the exact production hostnames before enabling `/mcp`. `MCP_ALLOWED_ORIGINS` may remain empty for non-browser MCP clients. The Worker refuses MCP traffic when the host allowlist is absent.

The exact UTC-day allowance is stored by a sharded Durable Object and is shared by HTTP and MCP searches. Static assets, health, readiness, and stats do not consume it. Invalid bearer tokens on public routes remain public callers; they never receive the token allowance. The internal batch route rejects them.

### Durable uMzingeli batches {#durable-threat-hunter-batches}

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
reserves one unit per apex. The Durable Object processes up to 100 apexes per
alarm slice, with separate limits for record count, provenance rows, and
serialized bytes. A single oversized apex is reported as an error in its chunk
without losing unrelated apexes. The configured bounds live in
`cloudflare/index-worker/wrangler.jsonc` and
`cloudflare/index-worker/src/index.js`.

Each slice looks up at most four apex locations concurrently and returns them
in request order. The Durable Object keeps up to 64 verified partition indexes
in memory, keyed by partition, expected generation, object key, and checksum.
A restart clears the cache without changing the job cursor or result. The cache
does not retain bundle blocks or bypass their checksum checks. To compare the
four read paths against a local catalog export, run this command from the
repository root:

```sh
SUBFINDER_EXPORT_DIR=/path/to/export node cloudflare/index-worker/scripts/benchmark-batch-lookup.js
```

The optional `SUBFINDER_BENCH_DELAY_MS` simulates object-read delay. It does
not measure live Cloudflare latency.

For a live authenticated check, run the staging-only harness once without
`--execute` to inspect the input digest, then repeat with `--execute`:

```sh
node cloudflare/index-worker/scripts/benchmark-live-batch.js \
  --origin https://subfinder-index-stage.pundit.workers.dev \
  --export /path/to/r2-export \
  --key your-stable-run-id --execute
```

The harness reads the staging token from the Mac keychain or
`SUBFINDER_BENCH_TOKEN`. It uses 1,200 indexed apexes and 10,800 synthetic
misses, verifies every returned position, and reports quota settlement. Reuse
the same key to inspect the same job without a second quota charge. On
2026-09-29, staging Worker version
`2f386018-5ab7-47d2-8b8c-849a34fa1e3a` delivered all 12,000 apexes in
120 chunks. Server processing took 544.8 seconds, or 22.0 apexes per second.
The run returned 1,200 nonempty results, zero apex errors, and zero outstanding
quota. This synthetic mix measures the Worker, not a real Threat Hunter cohort.

Regenerate the checked-in Python IDNA 2003 and private-PSL policy after an intentional `tldextract` snapshot change:

```sh
cd cloudflare/index-worker
npm run generate:domain-policy
npm test
```

## Direct CT ingestion worker

`ingest-worker` polls only exact allowlisted HTTPS CT hosts. A scheduled invocation records a bounded job in D1 and sends its ID to a Queue. The consumer parses leaf or precertificate DNS names, writes one immutable gzip delta to R2, then advances the D1 cursor. Completed-job retries re-send the idempotent delta notification so an earlier Queue outage cannot orphan an R2 object.

The Worker can also check Chrome and Apple log lists daily. It adds only active
RFC 6962 logs on exact allowlisted hosts. A separate
`CT_DISCOVERED_SOURCE_LIMIT` keeps discovered logs from using the reviewed
source budget. `PUBLIC_SOURCES_ENABLED` adds daily IANA root-zone and CISA
`.gov` checks. The IANA snapshot is private TLD metadata; a changed CISA CSV
creates a `public-bulk` catalog delta. See [Cloudflare source refresh](/operations/source-refresh)
for rollout gates and the sources that still run under Compose.

Provisioning is deliberately not hidden in code. Create the D1 database, source Queue, dead-letter Queue, shared compaction Queue, and compaction dead-letter Queue. Copy `wrangler.example.jsonc` to `wrangler.jsonc`, replace the D1 ID, then apply `migrations/0001_ingestion.sql`. Add reviewed CT log URLs to `ct_sources`; the host must also appear in `CT_ALLOWED_HOSTS`.

## URLScan ingestion worker

`urlscan-worker` keeps per-apex pagination in D1, charges a shared UTC-day
provider ledger before each request, and writes bounded URLScan pages as
immutable deltas. The default shared ceiling is 70,000 requests. On-demand
reads also have a separate priority ceiling of 20,000 per UTC day unless
`URLSCAN_PRIORITY_DAILY_LIMIT` is set. Seed `urlscan_sources` with normalized
eTLD+1 values for recurring reads. A completed history page runs again
immediately; a completed newest page waits for `URLSCAN_REFRESH_SECONDS`.

The API key is a Worker secret. It is intentionally absent from Wrangler vars, D1, Queue messages, logs, and R2 metadata:

```sh
cd cloudflare/urlscan-worker
cp wrangler.example.jsonc wrangler.jsonc
npx wrangler secret put URLSCAN_API_KEY --config wrangler.jsonc
npx wrangler d1 migrations apply subfinder-urlscan-control --remote --config wrangler.jsonc
```

### CT and URLScan staging

The staging configurations are
`cloudflare/ingest-worker/wrangler.staging.jsonc` and
`cloudflare/urlscan-worker/wrangler.staging.jsonc`. Each Worker has its own
control D1 database, job Queue, and dead-letter Queue. Both write deltas to
`subfinder-catalog-stage` and notify `subfinder-compaction-stage`. They do not
use the production hostname. Cloudflare selected the D1 placement; neither
configuration requests a region.

The staging CT and URLScan D1 migrations are applied. The separate compaction
ledger migration `0003_public_bulk_source.sql` is not yet applied. Both Workers were deployed on
2026-09-29 with empty Cron lists. The staging URLScan Worker received its
`URLSCAN_API_KEY` secret on 2026-09-29. Its CT and URLScan Queues each have
one producer and one consumer. Cron does not schedule provider work.
The staging CT settings allow one source and 16 entries per scheduled range.
URLScan allows one source, 100 results per page, and 25 provider requests per
UTC day. On-demand URLScan reads are capped at five requests within that
shared limit. These are staging test bounds, not product limits.

The live CT Cron test on 2026-09-29 completed job
`a1fd715c23a69774ebe97cffcb896fd32564818471a66810deb169b9130e686a`.
The scheduled invocation queued one 16-entry range. Its Queue consumer wrote
22 hostname records to an immutable R2 delta, and the generation ledger
registered that delta. The first trigger registration had no observed event
after 24 minutes. A trigger reapply at 17:40 UTC preceded the successful
17:47 UTC invocation; this sequence does not establish why the first
registration stayed silent. The reviewed test source is disabled again, and
the deployed CT Cron list is empty. The delta is registered, not yet active in
a catalog generation.

The read Worker uses a private service binding to submit on-demand URLScan
jobs. Its public API accepts only the `urlscan` action. The 2026-09-29 live
`example.com` test completed one provider page, stored a two-record immutable
delta, and registered it in the staging generation ledger. The delta awaits a
later catalog generation. The test created a disabled URLScan source so it
cannot start recurring reads when Cron is enabled.

Run the local tests and compile each staging configuration:

```sh
cd cloudflare/ingest-worker
npm test
npx wrangler deploy --dry-run --config wrangler.staging.jsonc

cd ../urlscan-worker
npm test
npx wrangler deploy --dry-run --config wrangler.staging.jsonc
```

Before another scheduled provider test, review the exact CT log URL and add
it to `ct_sources`, or add a normalized apex to `urlscan_sources`. Keep Cron
disabled for a manual test. The staging URLScan quota lives in its own D1
database; it does not reserve requests from a production deployment that uses
the same URLScan account. Check the account's remaining provider quota before
a live test.

`wrangler dev --test-scheduled` can create a job in remote D1, but its Queue
producer still sends to Miniflare's local broker even with `remote: true`.
Cloudflare tracks this in [workers-sdk issue #13727](https://github.com/cloudflare/workers-sdk/issues/13727).
The D1 row alone does not prove delivery. After local scheduling, copy the
exact queued job ID from staging D1. Check and submit that one job to the
deployed consumer:

```sh
node scripts/dispatch_staging_ingestion.mjs ct JOB_ID
node scripts/dispatch_staging_ingestion.mjs ct JOB_ID --execute
```

Use `urlscan` in place of `ct` for a URLScan job. The script accepts only a
queued scheduled job, checks the staging Queue and dead-letter Queue, and
requires `--execute` to send the message. Verify that the job becomes
`complete` and that its immutable delta appears in R2 and the staging
generation ledger. This tests the deployed consumer, not the deployed
scheduled producer. For a real Cron test, confirm that a reviewed `ct_sources`
row is enabled, its `retry_at` is null or past, and its `next_index` is behind
the log tree size. Deploy a temporary Cron on the staging Worker and confirm
it appears in the Worker's Cron Triggers settings. Cloudflare documents up to
15 minutes of propagation, but this test took longer. Watch past that period
and the next scheduled tick. If no invocation appears, confirm that the source
is still eligible and reapply the staging trigger with
`npx wrangler triggers deploy --config wrangler.staging.jsonc`. Each invocation
logs an `ingest-scheduled` summary, including
`ct_jobs: 0` when no source is eligible. Confirm the job, immutable R2 delta,
and generation-ledger registration before calling the scheduled path
end-to-end verified. Disable the test source before removing the temporary
Cron, then verify the deployed Cron list is empty. Do not infer that a trigger
ran from its configuration or from a short watch with no log event.

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
deltas and 175,195,918 records. The later
[full reconciliation](/operations/staging-reconciliation) found bare
public-suffix names in 219 chunks. Recovery retained 175,195,530 valid
records across all 8,760 effective chunks. Both staging Queues were empty
before compaction began on 2026-09-29. Verified 500-delta generations are
active in the shared staging root, which also serves the interim production
hostname. The remaining `.com` deltas are not yet all in the active catalog.
A mapped generation does not serve searches until it is
reduced, verified, and activated.

For the next staging batch, `CZDS_STAGE_ONLY=true` stops each successful
Workflow after the artifact reaches `staged`. It does not send delta-ready
messages or mark the zone complete. Verify each job with
`node scripts/verify_staged_czds.mjs JOB_ID` before changing zones. The
temporary trigger used to create a job must be removed and checked through
the deployed Worker schedules API. Keep this flag enabled until the `.com`
chain is clear and a separate publication gate is ready.

The staging compaction Worker now accepts map and reduce Queue messages. Its
Cron remains disabled, so it cannot start a generation on its own. The
[staging compaction procedure](/operations/staging-compaction) controls each
generation, checks the Queue and ledger, and activates a verified candidate.
Registration throughput is not a measurement of reducer throughput or the
cost of a full generation.

The [next staging CZDS batch](/operations/next-czds-batch) is prepared but
must wait until the `.com` backlog is in the active catalog and no generation
work is in flight.

### Staging invalid-record recovery

The CZDS parser and direct CT parser now skip bare public-suffix names while
keeping registrable children. The Container callback checks CZDS records again
before writing. The compaction Worker still rejects an invalid delta as a
whole; it must not silently omit records during registration.

Apply `czds-worker/migrations/0002_delta_repairs.sql` to the **staging** CZDS
D1 database before recovery. `scripts/czds_delta_repair.mjs` inspects a failed
original and only accepts the known bare-public-suffix-owner error. It copies
all other records into a new immutable R2 object, records the original and
replacement identities in `czds_delta_repairs`, and queues the replacement.
The completed CZDS job and its original R2 objects remain unchanged. A rerun
checks the audit row and object contents before doing anything else.

```sh
cd cloudflare/czds-worker
npx wrangler d1 migrations apply subfinder-czds-stage-control --remote --config wrangler.staging.jsonc
cd ../..
node scripts/czds_delta_repair.mjs --job-id JOB_SHA256 --dlq --limit 5
node scripts/czds_delta_repair.mjs --job-id JOB_SHA256 --dlq --limit 5 --execute
python3.11 scripts/staging_reconciliation.py --job-id JOB_SHA256 --require-complete
```

`--execute` purges only the precise dead-letter reference after the replacement
is registered in the generation ledger. If the source contains another kind of
invalid record, the tool stops and leaves that message untouched. Keep Cron
and generation work disabled until the source, repair audit, ledger, and both
Queue backlogs reconcile.

A local pilot reduced one partition from a real `.com` delta against the seed,
then activated and rolled back the candidate in disposable storage. It did not
process the full delta or backlog. The staging run processes 500 deltas per
generation and leaves Cron disabled. Do not change the production Worker route
as part of a staging compaction run.

## Generation reduction and publication

`compaction-worker` consumes the shared compaction Queue. It validates and hashes each delta, creates one open D1 generation, and maps records by the same SHA-256 partition prefix that the read Worker uses. A leased reducer merges provenance and first-seen dates, writes range-readable partition bundles with R2 multipart uploads, and verifies each bundle after upload. Unchanged partitions remain in their original generation.

`MAX_REDUCE_RECORDS` bounds the observations loaded for one changed partition. A partition that exceeds the bound fails closed. The reducer reads a modified overflow apex twice: it collects only the hostnames touched by the delta, then streams the sorted result into bounded bundle chunks. The real `3b` partition test covers an `amazonaws.com` apex with more than two million base records. Keep the compaction Cron disabled until the staging generation is verified.

Apply `compaction-worker` D1 migrations `0001_generation_ledger.sql` and
`0002_seed_publication.sql` for the CZDS path. Apply
`0003_public_bulk_source.sql` only at the separate
[source-refresh migration gate](/operations/source-refresh). When every changed
partition is reduced, the Worker writes `catalog/candidates/<generation>.json`.
That object does not change search results. The protected `/admin/activate`
route checks the candidate and its partition objects, archives the prior root,
and replaces `catalog/root.json` with an R2 compare-and-swap. `/admin/rollback`
restores the archived root with the same guard and re-registers the rolled-back
deltas. Set `PUBLISH_TOKEN` as a Worker secret before using these routes.

The full SQLite exporter writes its root last. `scripts/publish_r2_generation.py` validates the files and uploads immutable partition objects, then uploads a candidate root. It never uploads `catalog/root.json`. If an older export root lacks `source_names`, run `scripts/enrich_r2_export_root.py` after the export finishes and before staging it. For the first seed, call `/admin/register-seed` after staging, then call `/admin/activate`. The seed has no prior root, so `/admin/rollback` refuses to remove it. Later generations use the same activation route after the reducer publishes their candidates.
