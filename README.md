# CT Logs backend

Passive indexed subdomain search. Queries are reads against a local SQLite index. `GET /v1/search` and `POST /mcp` never probe the requested apex or returned hostnames.

## Run with Docker (recommended)

Build and run — the database is seeded automatically on first startup so queries work immediately.

```bash
docker build -t ctlogs:latest .
docker run -d -p 8000:8000 --name ctlogs ctlogs:latest
# or
docker compose up -d --build
```

The image runs `uvicorn ctlogs.app:app --host 0.0.0.0 --port 8000` with `CTLOGS_DB_PATH=/data/ctlogs.sqlite3` persisted in the `ctlogs-data` volume. On startup `lifespan` calls `seed_if_empty` — if `subdomains` is empty it inserts deterministic fixtures for `syncpundit.io` and `example.com` (7 hostnames, earliest `first_seen` kept). Subsequent restarts are idempotent.

Healthcheck: `curl -fsS http://127.0.0.1:8000/v1/search?apex=example.com`

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

SQLite defaults to `data/ctlogs.sqlite3`. Set `CTLOGS_DB_PATH` elsewhere if needed. Local runs also auto-seed on first startup via the same `seed_if_empty` path.

## Public interfaces

```text
GET /v1/search?apex=example.com
GET /v1/search?apex=example.com&format=json
GET /v1/search?apex=example.com&dates=1
GET /v1/search?apex=example.com&format=json&dates=1
POST /mcp
```

Plain text is one hostname per line unless `format=json` is requested. `dates=1` adds `first_seen`. Empty index returns `200` with empty body/array, not `404`.

MCP exposes one Streamable HTTP tool `search` (`{ "apex": "example.com" }` → `string[]`).

`GET /v1/search` and `POST /mcp` share one atomic allowance of 1,000 successful searches per client IP per UTC day (`request_counts`). Configure the reverse proxy to pass the real peer address to Uvicorn. Do not trust a client-supplied forwarding header.

Cert Spotter and Shodan CT ingestion use isolated tables `certspotter_counts` and `shodanct_counts` so backfill never starves the query quota.

`Host`/`Origin` for MCP are validated via `TransportSecuritySettings`. Add deployment hostnames to `CTLOGS_ALLOWED_HOSTS` and browser origins to `CTLOGS_ALLOWED_ORIGINS` (comma-separated).

## Ingestion

Bulk adapters: `gov` (CISA), `ee`/`se`/`nu` (AXFR `zonedata.iis.se` / `zone.internet.ee`), `ch`/`li` gated by `CTLOGS_ENABLE_CH_LI=1` (TSIG `zonedata.switch.ch`), `root` (IANA), `chaos` (public JSONL), `hagezi` (host lists), `commoncrawl` (CDX).

CT discovery: `chrome_ct` (`gstatic` log_list), `apple_ct` (`valid.apple.com`), `direct_ct` (`ct/v1/get-entries` / `get-sth`), `geomys` (archive JSONL, `gzip` aware).

Per-apex keyless adapters: `certspotter`, `shodanct`, `crt.sh`, plus `subfaster` 7 — `thc`, `submd`, `rapiddns`, `hackertarget`, `sitedossier`, `crtname`.

Benchmark bulk fixtures:

```bash
python -m ctlogs.ingest.benchmark --fixtures data/fixtures --db data/ctlogs.sqlite3
```

See [SOURCES.md](SOURCES.md) for the full default no-credential catalog and optional account-backed sources.
