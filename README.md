# Subfinder

<img src="brand/lockup-on-dark.png#gh-dark-mode-only" alt="Subfinder" width="260">
<img src="brand/lockup-on-light.png#gh-light-mode-only" alt="Subfinder" width="260">

Subfinder is a passive subdomain enumeration service. Source adapters build a
local index from certificate transparency logs, registry zone data, public
crawls, and optional account-backed services. A lookup reads that index and
returns every hostname on file for one apex, oldest known first, with first-seen
dates where the source provides them. When urlscan is configured, each lookup
refreshes its newest indexed scans, stores matching hostnames locally, and
queues that apex for deeper historical pagination.

`GET /v1/search` and `POST /mcp` do not submit a urlscan scan and never probe the
requested apex or the hostnames they return.

## Run with Docker (recommended)

Build and run. The live CT worker fills an empty database from current log
entries. Docker Compose also starts the recurring non-CT scheduler. A standalone
`docker run` starts only the API and CT worker.

```bash
docker build -t ctlogs:latest .
docker run -d -p 8200:8200 --name ctlogs ctlogs:latest
# or
docker compose up -d --build
```

The image runs `uvicorn ctlogs.app:app --host 0.0.0.0 --port 8200` with `CTLOGS_DB_PATH=/data/ctlogs.sqlite3` persisted in the `ctlogs-data` volume. Production auto-seeding is disabled. Set `CTLOGS_AUTO_SEED=1` only for a local fixture database.

Healthcheck: `curl -fsS http://127.0.0.1:8200/health`

```bash
curl "http://127.0.0.1:8200/v1/search?apex=syncpundit.io"
curl "http://127.0.0.1:8200/v1/search?apex=syncpundit.io&format=json"
```

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/uvicorn ctlogs.app:app --reload
```

SQLite defaults to `data/ctlogs.sqlite3`. Set `CTLOGS_DB_PATH` elsewhere if needed. Set `CTLOGS_AUTO_SEED=1` when a local development database needs fixtures.

## Public interfaces

```text
GET /v1/search?apex=example.com
GET /v1/search?apex=example.com&format=json
GET /v1/search?apex=example.com&dates=1
GET /v1/search?apex=example.com&format=json&dates=1
GET /v1/stats
GET /ready
GET /health
POST /mcp

GET /                    the web interface, when web/ is shipped
GET /app.css
GET /app.js
GET /robots.txt
GET /site.webmanifest
GET /favicon.ico         and favicon.svg, apple-touch-icon.png,
                         icon-192.png, icon-512.png, icon-512-maskable.png
```

Plain text is one hostname per line unless `format=json` is requested. `dates=1` adds `first_seen`. Empty index returns `200` with empty body/array, not `404`.

`GET /v1/search` reports the refresh result in `X-URLScan-Status`: `ok`,
`disabled`, `quota-exhausted`, `timeout`, or `error`. Provider failure does not
hide cached results. The route falls back to SQLite after the configured
five-second wall-clock limit. On-demand refreshes read at most 100 indexed
scans per call. A background priority job advances older pages for searched
apexes without making the request wait for the full history.

MCP exposes one Streamable HTTP tool `search` (`{ "apex": "example.com" }` → `string[]`).

`GET /v1/search` and `POST /mcp` share one atomic allowance of 1,000 successful searches per client IP per UTC day (`request_counts`). Configure the reverse proxy to pass the real peer address to Uvicorn. Do not trust a client-supplied forwarding header.

Deployment operators can issue optional bearer tokens with a separate daily
allowance. Configure accepted tokens with `CTLOGS_API_TOKENS` and the limit for
each token with
`CTLOGS_TOKEN_REQUEST_LIMIT`. The database stores only a SHA-256 token digest
as the quota identity.

`GET /v1/stats` returns whole-index counts (`apex_count`, `hostname_count`,
`dated_hostname_count`, `source_count`), the certificate transparency subset
(`ct_hostname_count`, `ct_log_count`), and `last_ingest_at`. `GET /ready`
returns a status string with the hostname count and the same timestamp. Neither
route consumes the search allowance.

`Host`/`Origin` for MCP are validated via `TransportSecuritySettings`. Add deployment hostnames to `CTLOGS_ALLOWED_HOSTS` and browser origins to `CTLOGS_ALLOWED_ORIGINS` (comma-separated).

## Web interface

`web/` holds the frontend with no build step: `index.html`, `app.css`, `app.js`,
`robots.txt`, `site.webmanifest`, and the icon set.
`ctlogs.web.mount_frontend` registers each one as an explicit named route at
startup, so the page is served from the same origin as the API. Named routes
rather than a `StaticFiles` mount, because `create_app` mounts the MCP app at
`/` and a second directory mount on that prefix would swallow `/mcp`. Only
those names are servable, so a stray file dropped in `web/` is not reachable.

`ASSETS` are served with `Cache-Control: no-cache`, because the markup and the
assets it is versioned with ship together and a browser must not pair new
markup with a cached script. `MEDIA` - the icons - carry no such pairing and
are cached for a week instead. Brand sources live in [`brand/`](brand/), which
is not served.

`robots.txt` disallows `/v1/`, `/mcp`, and the `?apex=` form of the page. Those
routes spend the shared search allowance, and a crawler following every result
link would spend a visitor's day of reads on nobody's behalf. The page carries
`rel="canonical"` pointing at `/` for the same reason: `/?apex=example.com` is
the same document with a query on it, not a second page.

The page is optional. When `web/index.html` is missing, `mount_frontend` logs
and returns, and the API serves alone. Set `CTLOGS_WEB_DIR` to serve the
frontend from another directory. The Dockerfile copies `web/` after the
dependency install so static edits do not invalidate that layer.

Opening the page spends nothing from the search allowance. A visitor spends a
read only when they search, and a repeat lookup of an apex already read in that
browser session is answered from memory instead of the API. The counter in the
page header polls `/v1/stats` every 15 seconds and pauses while the tab is
hidden. That polling is only safe while `/v1/stats` stays outside the
allowance. At a 15 second interval a metered stats route would spend all 1,000
daily reads in about four hours for a visitor who never ran a search.
`test_opening_the_page_spends_no_search_allowance` and
`test_the_live_counter_endpoint_spends_no_search_allowance` in
`tests/test_web.py` pin both, so adding a `consume()` call to `/v1/stats` fails
the suite rather than quietly draining callers.

## Ingestion

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

The Compose `scheduler`, `urlscan-scheduler`, and `ct-history-scheduler`
services run recurring ingestion without web traffic. The first runs IANA root
and CISA `.gov` imports every 24 hours. When CZDS credentials are present, it
also checks up to 25 least-recently-checked zones per day. The second handles
urlscan breadth and searched-apex history. The third replays bounded prefixes
of usable RFC 6962 logs from their first entries. Separate volume locks prevent
duplicate processes, and SQLite stores each job's next run time.

Set `CTLOGS_URLSCAN_APEXES` to a comma-separated allowlist, or set it to `*` to
walk every apex already in the local index. The all-index mode keeps both its
apex cursor and each apex's `search_after` cursor in SQLite. Each scheduled
visit fetches the next older page until that apex's history is complete. Later
visits refresh the newest page without discarding the completed history state.
API-triggered refreshes do not change scheduler pagination. They add the apex
to a persistent FIFO queue. The priority job processes up to 14 queued apexes
per run, one older 1,000-result page per apex, and rotates incomplete apexes to
the back of the queue. The global walk processes up to 69 apexes per run. Both
jobs start their next run 60 seconds after the previous run finishes.

The automated URLSCAN ceiling is 100,000 requests per UTC day. Three
independent quota identities prevent one class from starving another: 10,000
live search refreshes, 20,000 priority-history requests, and the remaining
70,000 requests for the global breadth walk. Configure the total with
`CTLOGS_URLSCAN_DAILY_LIMIT`, the first share with
`CTLOGS_URLSCAN_SEARCH_DAILY_LIMIT`, and the second share with
`CTLOGS_URLSCAN_PRIORITY_DAILY_LIMIT`. The breadth share is always the
remainder, so the three maximums cannot exceed the configured total. Confirm
that this fits the account quota and urlscan's usage terms before enabling it.

All enabled sources consolidate into the same `subdomains` table. The database
keeps the earliest dated observation and records each source separately in
`subdomain_sources`. The API queries urlscan before reading this combined local
index. It does not query bulk sources during a request.

HaGeZi, public Chaos data, Common Crawl, and registry exports are parsers for
artifacts whose locations or access details vary by deployment. Configure every
permitted artifact as a JSON list of `SOURCE=PATH_OR_URL` strings:

```env
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
docker compose run --rm urlscan-scheduler --list
docker compose run --rm ct-history-scheduler --list
```

Benchmark bulk fixtures:

```bash
python -m ctlogs.ingest.benchmark --fixtures data/fixtures --db data/ctlogs.sqlite3
```

Import configured global artifacts immediately when an unscheduled run is
needed. Repeating the same file or ETag is a no-op.

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
not move or compete with the live tail cursor. Compose runs this continuously
through `ct-history-scheduler`; the same operation can be invoked manually:

```bash
python -m ctlogs.ingest.history --db data/ctlogs.sqlite3 \
  --log-url https://ct.example/log --max-batches-per-log 8
```

Account-backed sources are explicit per-apex jobs. Put their credentials in an
untracked `.env.providers` file using `.env.example`. Each invocation has its
own request budget. The different filename matters because Compose otherwise
interpolates dollar signs while automatically loading `.env`.

```bash
python -m ctlogs.ingest.enrich --db data/ctlogs.sqlite3 \
  --source urlscan --apex example.com --max-requests 10
```

With Docker Compose, run the same modules through the dormant `jobs` service.
The public API receives only the urlscan credential. CZDS credentials remain
limited to ingestion services.

```bash
docker compose run --rm jobs -m ctlogs.ingest.enrich --db /data/ctlogs.sqlite3 \
  --source urlscan --apex example.com --max-requests 10
```

Approved ICANN CZDS zones can be downloaded and indexed without using the web
portal. The default cap is 25 zones per run. Use `--tld` to select a subset.
Completed zones are skipped on later capped runs. Use `--refresh` to make
conditional requests for zones that already have download state.

```bash
python -m ctlogs.ingest.czds --db data/ctlogs.sqlite3 \
  --output data/czds --max-zones 25
```

Preview and remove only the known provenance-free development fixtures. An
SQLite backup is mandatory for the modifying command.

```bash
python -m ctlogs.maintenance --db data/ctlogs.sqlite3
python -m ctlogs.maintenance --db data/ctlogs.sqlite3 --apply \
  --backup data/backups/ctlogs-before-fixture-cleanup.sqlite3
```

See [SOURCES.md](SOURCES.md) for the full default no-credential catalog and optional account-backed sources.
