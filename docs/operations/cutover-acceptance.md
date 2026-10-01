# Cutover acceptance checks

Run these checks against `subfinder.syncpundit.io` after attaching the custom
domain. The production Workers preview is disabled. The harness accepts only
the production hostname. It reads the local SQLite catalog but does not write
to SQLite, R2, D1, Queues, or a batch job.

From `cloudflare/index-worker`:

```sh
npm run verify:cutover -- \
  --sqlite /Users/pancake/Documents/subfinder-migration-backup/20260927T050403Z/catalog.sqlite3 \
  --expect-generation EXPECTED_GENERATION
```

If a valid production client token is available, pass it as
`SUBFINDER_CUTOVER_TOKEN`; do not use the staging token for this check.

Use the generation ID approved for cutover, not the seed ID by habit. If the
expected generation is omitted, the harness reports that gate as
`not_evaluated`. Without `SUBFINDER_CUTOVER_TOKEN`, the valid-token gate also
reports `not_evaluated`. The token value is never printed.

The harness checks health, readiness, root statistics, the home-page docs
link, the Pages proxy, exact-apex search pagination, records/search agreement,
MCP search, quota headers, public-suffix and cursor rejection, and private
batch authorization. It compares `cloudflare.com`, `example.com`, and
`syncpundit.io` with the local SQLite seed. A later generation may add
hostnames, but it must not lose any baseline hostname. The script makes only
bounded reads; it does not submit a live 25,000-apex job.

Run the full 25,000-apex path against the local Worker fixture separately:

```sh
SUBFINDER_STRESS=1 npm test
```

Also drive uMzingeli's installed Python client against that fixture, from the
Subfinder repository root:

```sh
UMZINGELI_ROOT=/absolute/path/to/umzingeli node cloudflare/index-worker/scripts/verify-threat-hunter.js
```

`THREAT_HUNTER_ROOT` remains accepted for existing automation. The default
sibling checkout is now `../umzingeli`. This verifies the client's 25,000-apex
admission default and replay path without submitting a live staging job.

That local result is not evidence of live Queue throughput or a completed
production-scale batch. Keep those gates separate in the cutover review.
For a full-catalog release, also require the
[staging compaction checks](/operations/staging-compaction),
[reconciliation](/operations/staging-reconciliation), and a reviewed
[cost scorecard](/operations/staging-cost). The temporary production cutover
uses the verified active staging root while later `.com` deltas continue.
These checks do not activate a generation or enable source schedules.
