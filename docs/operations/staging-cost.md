# Measure staging throughput and cost

Use the read-only scorecard while the `.com` staging generation maps and
reduces. It reads the CZDS job, the generation ledger, Queue metrics, and
Cloudflare analytics. It does not list R2 objects or change the active root.

From the repository root, run:

```sh
python3.11 scripts/staging_cost_scorecard.py \
	--job-id 8b302c90798d27cf43c03d52c341787fd48c03c4b90ecb44acb0dbbc1a42e107 \
	--since-date 2026-09-27
```

The script needs the existing Wrangler login or `CLOUDFLARE_API_TOKEN`. It
prints JSON to standard output and never prints the token. `--since-date`
starts the analytics window at midnight UTC on that date. By default, the
window starts on the CZDS job's creation date.

Read `throughput.source_job` for the source parse rate. Read
`throughput.generations` for mapped records, map wall time, and reduced
partition counts. Wall rates include pauses and retries. A mapped chunk is
not a published or active partition.

Read `usage` for measured Cloudflare counters. Queue operations cover both
staging compaction Queues. R2 operations and storage cover the entire staging
bucket, including the seed and unrelated tests. D1 counters cover the staging
generation ledger and CZDS control database. Wrangler queries count toward D1
usage. Container counters cover the staging CZDS parser and its sandbox. Worker
CPU percentiles are not total billable CPU time. If an analytics dataset is
unavailable, the report marks it `unavailable` instead of zero.

`cost.usd_before_account_allowances` values the measured Queue operations,
D1 rows, classified successful R2 Standard operations, and CZDS Container
compute at published list rates. It is a partial estimate, not the amount
charged for `.com` or an account invoice. Monthly included usage is shared
across the account. The estimate excludes R2 and D1 storage, Workers CPU and
requests, Workflow duration, Container egress, and any R2 action the script
cannot classify. The R2 storage snapshot is not a GB-month charge.

Check the [Cloudflare billing page](https://dash.cloudflare.com/) for actual
charges. The list rates and analytics definitions come from the official
[R2 pricing](https://developers.cloudflare.com/r2/pricing/),
[D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/),
[Queues pricing](https://developers.cloudflare.com/queues/platform/pricing/),
[Containers pricing](https://developers.cloudflare.com/containers/platform/pricing/),
[Containers analytics](https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-container-metrics/),
[R2 analytics](https://developers.cloudflare.com/r2/platform/metrics-analytics/),
and [D1 analytics](https://developers.cloudflare.com/d1/observability/metrics-analytics/)
documentation.
