# Reconcile staging ingestion

Run this check before starting a staging generation, after installing the CZDS
and compaction Worker dependencies. It reads both remote D1 databases and the
Cloudflare Queue metrics API. It does not consume, acknowledge, or replay
messages; write to D1 or R2; start a generation; or change the active root.

```sh
uv run python scripts/staging_reconciliation.py \
  --job-id 8b302c90798d27cf43c03d52c341787fd48c03c4b90ecb44acb0dbbc1a42e107
```

The command uses `CLOUDFLARE_API_TOKEN` when set. Otherwise it uses the local
Wrangler login. It never prints the token. Use `--metrics-only` for a quick
point-in-time Queue and dead-letter backlog check. `--since` sets the UTC start
of the Queue operations window; the default is midnight UTC today.

The JSON report compares the completed CZDS job's declared chunk and record
totals with every source chunk, checks contiguous indexes, then matches each
source delta to the generation ledger by ID, object key, source kind, record
count, object byte length, and recorded SHA-256 format. It also checks that the
staging generation ledger is still empty. Once compaction starts, use this
command only with `--metrics-only`; a generation is no longer an unexpected
condition. `pending` means some
source chunks have not yet registered. `failed` means an invariant failed or
the dead-letter Queue is nonempty. Exit status is 0 for `pending` or `complete`,
1 for `failed` or a nonempty dead-letter Queue (including with
`--metrics-only`), and 2 when a remote read could not be completed. Use
`--require-complete` for a final gate: it turns missing ledger chunks into a
failure. Never infer complete coverage from the Queue backlog alone.

The report's Queue operation count is billable *usage*, not a dollar charge or
account invoice. See Cloudflare's [Queue metrics](https://developers.cloudflare.com/queues/observability/metrics/)
and [pricing](https://developers.cloudflare.com/queues/platform/pricing/) for
the operation definition and account-wide monthly allowance. The
oldest-message age is `null` when Cloudflare reports no
timestamp; that is unknown, not zero age. D1 registration checks the object
content at that time, but this command does not re-download and re-hash every
R2 object. A final publication gate needs a separate R2 integrity check.

The first staging `.com` drain found 219 chunks with bare public-suffix names.
The repair audit retained each original object and registered a corrected
immutable replacement. On 2026-09-28, the final pre-compaction report found
8,760 effective chunks, 175,195,530 valid records, no missing chunks, and
empty main and dead-letter Queues. The [staging compaction procedure](/operations/staging-compaction)
starts from that reconciled ledger.
