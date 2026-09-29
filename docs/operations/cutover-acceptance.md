# Cutover acceptance checks

Run these checks against `subfinder.pundit.workers.dev` before proposing a
production hostname change. The harness refuses any other origin, including
`subfinder.syncpundit.io`. It reads the local SQLite catalog but does not write
to SQLite, R2, D1, Queues, or a batch job.

From `cloudflare/index-worker`:

```sh
SUBFINDER_STAGE_TOKEN="$(security find-generic-password \
  -s subfinder-stage-threat-hunter -a threat-hunter -w)" \
npm run verify:cutover -- \
  --sqlite /Users/pancake/Documents/subfinder-migration-backup/20260927T050403Z/catalog.sqlite3 \
  --expect-generation EXPECTED_GENERATION
```

Use the generation ID approved for cutover, not the seed ID by habit. If the
expected generation is omitted, the harness reports that gate as
`not_evaluated`. Omit `SUBFINDER_STAGE_TOKEN` when the staging token is not
available; the valid-token gate will then also report `not_evaluated`. The
token value is never printed.

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

That local result is not evidence of live Queue throughput or a completed
production-scale batch. Keep those gates separate in the cutover review.
Also require the [staging compaction checks](/operations/staging-compaction),
[reconciliation](/operations/staging-reconciliation), and a reviewed
[cost scorecard](/operations/staging-cost) before proposing activation or
production cutover. This page authorizes neither action.
