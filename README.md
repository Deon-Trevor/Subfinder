# Subfinder

Subfinder is a passive subdomain enumeration service. Source adapters build a
local index from certificate transparency logs, registry zone data, public
crawls, and optional account-backed services. A lookup reads that index and
returns every hostname on file for one apex, oldest known first, with first-seen
dates where the source provides them. Nothing is fetched from an upstream source
while the caller waits.

Queries are reads against a local SQLite index. `GET /v1/search` and `POST /mcp`
never probe the requested apex or the hostnames they return.

## Run with Docker (recommended)

Build and run. The live CT worker fills an empty database from current log entries.

```bash
docker build -t ctlogs:latest .
docker run -d -p 8000:8000 --name ctlogs ctlogs:latest
# or
docker compose up -d --build
```

The image runs `uvicorn ctlogs.app:app --host 0.0.0.0 --port 8000` with `CTLOGS_DB_PATH=/data/ctlogs.sqlite3` persisted in the `ctlogs-data` volume. Production auto-seeding is disabled. Set `CTLOGS_AUTO_SEED=1` only for a local fixture database.

Healthcheck: `curl -fsS http://127.0.0.1:8000/health`

```bash
curl "http://127.0.0.1:8000/v1/search?apex=syncpundit.io"
curl "http://127.0.0.1:8000/v1/search?apex=syncpundit.io&format=json"
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
```

Plain text is one hostname per line unless `format=json` is requested. `dates=1` adds `first_seen`. Empty index returns `200` with empty body/array, not `404`.

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

`web/` holds the frontend as three files with no build step: `index.html`,
`app.css`, `app.js`. `ctlogs.web.mount_frontend` registers each one as an
explicit named route at startup, so the page is served from the same origin as
the API. Named routes rather than a `StaticFiles` mount, because `create_app`
mounts the MCP app at `/` and a second directory mount on that prefix would
swallow `/mcp`. Only those three names are servable, so a stray file dropped in
`web/` is not reachable.

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
`static_ct` (C2SP data tiles). Censys, ProjectDiscovery Chaos, and urlscan are
separate account-backed enrichment jobs.

Static CT monitoring prefixes use the C2SP data-tile reader. Configure them as
a comma-separated list in `CTLOGS_STATIC_CT_URLS`. Docker Compose includes the
current Let's Encrypt Willow 2026h2 shard. Static shards are time-bounded, so
deployment configuration must add new usable shards before the current shard
closes.

Benchmark bulk fixtures:

```bash
python -m ctlogs.ingest.benchmark --fixtures data/fixtures --db data/ctlogs.sqlite3
```

Import configured global artifacts as a separate job. Repeating the same file
or ETag is a no-op.

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
not move or compete with the live tail cursor:

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
  --source censys --apex example.com --max-requests 10
python -m ctlogs.ingest.enrich --db data/ctlogs.sqlite3 \
  --source chaos-api --apex example.com --max-requests 10
python -m ctlogs.ingest.enrich --db data/ctlogs.sqlite3 \
  --source urlscan --apex example.com --max-requests 10
```

With Docker Compose, run the same modules through the dormant `jobs` service.
Provider secrets are available to that short-lived container, not to the
public API service.

```bash
docker compose run --rm jobs -m ctlogs.ingest.enrich --db /data/ctlogs.sqlite3 \
  --source censys --apex example.com --max-requests 10
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
