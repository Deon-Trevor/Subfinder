# Ingest source data

Run the commands on this page from the repository root. This guide describes
the Compose ingestion pipeline; see [Cloudflare operations](/operations/cloudflare)
for the separate Worker-based pipeline.

## Source families

Bulk adapters: `gov` (CISA), `ee`/`se`/`nu` (AXFR
`zonedata.iis.se` / `zone.internet.ee`), `ch`/`li` gated by
`CTLOGS_ENABLE_CH_LI=1` (TSIG `zonedata.switch.ch`), `root` (IANA), `chaos`
(public JSONL), `hagezi` (host lists), `commoncrawl` (CDX), and `czds`
(approved registry zones).

CT discovery: `chrome_ct` (`gstatic` log list), `apple_ct`
(`valid.apple.com`), `direct_ct` (`ct/v1/get-entries` / `get-sth`), and
`static_ct` (C2SP data tiles). urlscan is a separate account-backed enrichment
job.

Static CT monitoring prefixes use the C2SP data-tile reader. Configure them as
a comma-separated list in `CTLOGS_STATIC_CT_URLS`. Docker Compose includes the
current Let's Encrypt Willow 2026h2 shard. Static shards are time-bounded, so
deployment configuration must add new usable shards before the current shard
closes.

## Recurring schedule

The Compose `scheduler` owns recurring ingestion. It runs
live CT tails, bounded historical replay, IANA and CISA imports, configured
artifacts, optional CZDS, and optional URLScan breadth serially. Provider fetches
may be concurrent, but catalog commits share one process and the cross-process
writer lock. The dedicated enrichment worker owns all search-priority URLScan
and requested local-zone imports under that same lock and quota ledger. WAL
readers remain concurrent. SQLite stores each recurring job's next run time.

Set `CTLOGS_URLSCAN_APEXES` to a comma-separated allowlist, or set it to `*` to
walk every apex already in the local index. The all-index mode keeps both its
apex cursor and each apex's `search_after` cursor in SQLite. Each scheduled
visit fetches the next older page until that apex's history is complete. Later
visits refresh the newest page without discarding the completed history state.
Search-triggered refreshes do not change breadth pagination. They add the apex
to a persistent FIFO queue in the control database. The enrichment worker
processes up to 14 queued apexes every 60 seconds, one older 1,000-result page
per apex, and rotates incomplete apexes to the back of the queue. The global
breadth walk processes up to 69 apexes per run and starts its next pass 60
seconds after the previous run finishes.

The automated URLSCAN ceiling is 100,000 requests per UTC day. Provider calls
use independent quota identities: 20,000 priority-history requests and the
remaining breadth budget. Configure the total with
`CTLOGS_URLSCAN_DAILY_LIMIT`, the first share with
`CTLOGS_URLSCAN_PRIORITY_DAILY_LIMIT`; the legacy search reserve remains
accounted for by `CTLOGS_URLSCAN_SEARCH_DAILY_LIMIT`. Search admission itself
does not consume provider quota. Confirm
that this fits the account quota and urlscan's usage terms before enabling it.

The deployed cadence:

| Ingestion family | Cadence and bound |
| --- | --- |
| Newest Chrome/Apple RFC 6962 logs | About every 60 seconds; at most 8 batches of 1,024 entries per usable log per pass, with four log polls in flight. |
| Configured Static CT shards | The same live pass and bounds. The checked-in deployment pins the Let's Encrypt Willow `2026h2` shard; new shards must be added by hand. |
| Historical RFC 6962 replay | About every 60 seconds; one rotating log and at most 8,192 entries per pass. |
| Search-priority URLScan history | About every 60 seconds; up to 14 rotating apexes and one 1,000-result page per apex. |
| URLScan breadth walk | About every 60 seconds; up to 69 indexed apexes per pass. |
| ICANN CZDS | Daily; at most 25 approved zones. Never-ingested zones sort ahead of refreshes; unseen ties are alphabetical because the link feed has no approval timestamp. Older refreshes then rotate first. |
| IANA root, CISA `.gov`, configured artifacts | Daily, with conditional or digest-based no-op behavior where supported. |

The CZDS cap means the acquisition backlog advances by at most 25 zones per
daily pass. A newly granted link is not guaranteed to run next while other
never-ingested zones remain, because the upstream list does not say when access
was approved. The steady-state refresh interval for an unchanged approved
catalog is about `ceil(approved zones / 25)` days. On-demand enrichment does
not bypass that acquisition policy: it can only prioritize parsing an exact
artifact already on disk. A dedicated worker checks the enrichment queue every
two seconds and runs one composite job at a time. Catalog commits still use the
shared writer lock, while long CT polling can no longer delay admission or job
pickup.
`CTLOGS_CZDS_MAX_ZONES`, `CTLOGS_CZDS_INTERVAL`, and
`CTLOGS_CZDS_RETRY_INTERVAL` expose the acquisition cadence without coupling
it to the other daily artifacts; raising them changes upstream traffic and
download volume and should follow an observed catch-up budget.

All enabled sources consolidate into the same `subdomains` table. The database
keeps the earliest dated observation and records each source separately in
`subdomain_sources`. The API reads only this combined local index. It does not
query any upstream source during a request.

## Configure artifacts

HaGeZi, public Chaos data, Common Crawl, and registry exports are parsers for
artifacts whose locations or access details vary by deployment. Configure every
permitted artifact as a JSON list of `SOURCE=PATH_OR_URL` strings:

```bash
CTLOGS_URLSCAN_APEXES=*
CTLOGS_SCHEDULED_ARTIFACTS=["hagezi=https://data.example/hosts.txt"]
```

The scheduler accepts `root`, `gov`, `hagezi`, `chaos`, `commoncrawl`, `ee`,
`se`, and `nu` artifact sources. It applies the same 256 MiB per-artifact cap
as the manual importer. `.ch` and `.li` still require a purpose-approved TSIG
fetch outside this service. Geomys replay still requires a chosen archive.

Inspect the configured schedule without contacting upstream sources:

```bash
docker compose run --rm scheduler --list
```

## Benchmark ingestion and reads

Benchmark bulk fixtures:

```bash
python -m ctlogs.ingest.benchmark --fixtures data/fixtures --db data/ctlogs.sqlite3
```

Benchmark the HTTP path after a deployment. The command exits nonzero when a
response fails or either p95 threshold is exceeded.

```bash
python scripts/benchmark_search.py --url http://127.0.0.1:8200 \
  --apex zerofox.com --requests 100 --concurrency 8 \
  --max-ttfb-p95-ms 25 --max-total-p95-ms 30
```

Run the mixed public and Threat Hunter burst gate only against a loopback URL.
The script refuses any other target. The committed 70-domain cohort comes from
the final archived Alexa Top Sites data and pins the source commit in the
fixture header.

```bash
python scripts/benchmark_bursts.py \
  --url http://127.0.0.1:8200 \
  --domains tests/fixtures/alexa_top_70_2023-02-07.txt \
  --scenario distinct \
  --service-token "$CTLOGS_TEST_SERVICE_TOKEN" \
  --require-all-success \
  --max-public-p95-ms 250 \
  --max-service-p95-ms 250 \
  --max-health-p99-ms 50
```

Use `--scenario same-apex` for the repeated-apex case. Use `--scenario bursts`
for seven groups of ten public requests separated by 100 ms. By default, the
harness sends one benchmark-network client address per public request through
`X-Forwarded-For`. Add `--identity-mode shared` to model one client issuing the
entire public workload. Uvicorn accepts either form only when the loopback test
peer is trusted.

## Run imports manually

Import configured global artifacts immediately for an unscheduled run.
Repeating the same file or ETag is a no-op.

```bash
python -m ctlogs.ingest.backfill --db data/ctlogs.sqlite3 \
  --job hagezi=/data/hagezi.txt \
  --job chaos=https://example.invalid/chaos.jsonl
```

The maintained IANA root and CISA `.gov` artifacts can be run together:

```bash
python -m ctlogs.ingest.backfill --db data/ctlogs.sqlite3 --defaults
```

Historical RFC 6962 replay has a separate cursor and batch budget, so it does
not move the live tail cursor. Compose runs both jobs through the single
scheduler; the same history operation also runs manually:

```bash
python -m ctlogs.ingest.history --db data/ctlogs.sqlite3 \
  --log-url https://ct.example/log --max-batches-per-log 8
```

## Run account-backed enrichment

Account-backed sources are explicit per-apex jobs. Put their credentials in the
untracked `.env` file using `.env.example`. Each invocation has its own request
budget. The `jobs` and `scheduler` services load provider values from this file;
single-quoted credentials preserve dollar signs without exposing those
credentials to the public API container.

```bash
python -m ctlogs.ingest.enrich --db data/ctlogs.sqlite3 \
  --source urlscan --apex example.com --max-requests 10
```

With Docker Compose, run the same modules through the dormant `jobs` service.
Only ingestion services read credentials. The public API never
calls account-backed providers.

```bash
docker compose run --rm jobs -m ctlogs.ingest.enrich --db /data/ctlogs.sqlite3 \
  --source urlscan --apex example.com --max-requests 10
```

## Import approved CZDS zones

Approved ICANN CZDS zones can be downloaded and indexed without using the web
portal. The default cap is 25 zones per run. Use `--tld` to select a subset.
Later capped runs skip completed zones. Use `--refresh` to make
conditional requests for zones that already have download state.

```bash
python -m ctlogs.ingest.czds --db data/ctlogs.sqlite3 \
  --output data/czds --max-zones 25
```

## Remove development fixtures

Preview and remove only the known provenance-free development fixtures. The
modifying command requires an SQLite backup.

```bash
python -m ctlogs.maintenance --db data/ctlogs.sqlite3
python -m ctlogs.maintenance --db data/ctlogs.sqlite3 --apply \
  --backup data/backups/ctlogs-before-fixture-cleanup.sqlite3
```

See [source catalog](/reference/sources) for the full default no-credential catalog and optional account-backed sources.
