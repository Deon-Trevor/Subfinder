# Subfinder

<img src="brand/lockup-on-dark.png#gh-dark-mode-only" alt="Subfinder" width="260">
<img src="brand/lockup-on-light.png#gh-light-mode-only" alt="Subfinder" width="260">

Subfinder is a passive subdomain enumeration service. Source adapters build a
local index from certificate transparency logs, registry zone data, public
crawls, and optional account-backed services. A lookup reads that index and
returns every hostname on file for one apex, oldest known first, with first-seen
dates where the source provides them. When urlscan is configured, each lookup
returns local results immediately and queues that apex for passive enrichment.
The ingestion scheduler performs provider calls and catalog writes later.

`GET /v1/search` and `POST /mcp` do not submit a urlscan scan and never probe the
requested apex or the hostnames they return.

## Run with Docker (recommended)

Build and run with Compose. A one-shot migration prepares the catalog and small
control database before the read-only API and the single catalog-writer
scheduler start. The published loopback port belongs to a bounded NGINX edge;
the API itself is reachable only from Docker networks.

Copy `.env.example` to the single untracked `.env` deployment file and fill in
only the credentials and overrides this deployment uses. Compose passes
provider credentials from that file only to `jobs` and `scheduler`. Wrap values
containing `$` in single quotes so Compose preserves them literally and does not
interpret credential fragments as variable names. The API and workers receive
only the variables explicitly listed for them in `docker-compose.yml`; the file
is never injected wholesale into a container.

```bash
cp .env.example .env
docker network create syncpundit-data-plane
docker compose up -d --build
```

The API runs `uvicorn ctlogs.app:app --host 0.0.0.0 --port 8200`. The hostname
catalog is persisted in `ctlogs-data`; quotas and the deduplicated refresh queue
are persisted separately in `ctlogs-control`.
Compose publishes the edge on port 8200 only on host loopback for the host
NGINX and attaches only the API container to the external
`syncpundit-data-plane` network under the `subfinder-index` alias. Create that
network once before the first deployment.
The API opens the catalog read-only. The migration and scheduler services are
the only Compose services that can mutate it.
`CTLOGS_DATA_VOLUME`, `CTLOGS_CONTROL_VOLUME`, and `CTLOGS_DATA_NETWORK` in
`.env` make ownership of those shared deployment surfaces explicit.

The first deployment must stop every old API and scheduler container before
starting the new set. Old processes must not overlap the replacement. `docker
compose down` preserves named volumes unless `--volumes` is supplied. The
migration copies any legacy searched-apex queue entries out of the catalog and
into the control database before services start.

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

SQLite defaults to `data/ctlogs.sqlite3`. Set `CTLOGS_DB_PATH` and
`CTLOGS_CONTROL_DB_PATH` to use other local paths.

## Public interfaces

```text
GET /v1/search?apex=example.com
GET /v1/search?apex=example.com&format=json
GET /v1/search?apex=example.com&dates=1
GET /v1/search?apex=example.com&format=json&dates=1
GET /v1/records?apex=example.com
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

The unpaginated response remains backward compatible and streams valid text or
JSON without building the full result in memory. Large consumers can add
`limit=5000` and follow `X-Next-Cursor` or the `Link: rel="next"` header. A
cursor is valid only for the same apex and ordering contract used to obtain it.
Paginated responses also carry `X-Result-Total`, `X-Result-Dated-Total`, and
`X-Result-Page-Size`. The web interface requests 500 rows at a time and keeps
the shelf DOM bounded to the current page; moving forward is an explicit
search read, while moving back reuses pages already read in that tab.

`GET /v1/records` is the stable local-index interface for service consumers.
It never contacts an upstream provider. Its JSON response identifies
`schema_version` as `subfinder.index-records.v1` and returns each hostname's
earliest observation plus the source-specific `source`, `first_seen`, and
`last_seen` records. It consumes the same search allowance as `/v1/search` and
returns `X-Subfinder-Schema-Version` so consumers can reject an unsupported
contract before parsing the body.

Trusted services can read several complete index snapshots with
`POST /internal/v1/records/batch`:

```json
{"apexes":["example.com","example.net"]}
```

The route requires a bearer token configured in `CTLOGS_API_TOKENS`, is
available only by calling the API container on the private data plane, and is
explicitly hidden by the public NGINX edge. Its response schema is
`subfinder.internal-index-records-batch.v1`; `results` uses the existing
`subfinder.index-records.v1` object for each apex in request order. One batch
contains at most 100 unique apexes and 5,000 hostnames by default. Set
`CTLOGS_BATCH_MAX_APEXES` and `CTLOGS_BATCH_MAX_RECORDS` to lower deployment
limits. Oversized requests return `413` and must be split.

Threat Hunter should use the durable queue rather than hold a request open:

```http
POST /internal/v1/record-batches
Authorization: Bearer <service token>
Idempotency-Key: <stable request identity>
Content-Type: application/json

{"apexes":["example.com","example.net"]}
```

Submission returns `202` and a job identifier. Poll
`GET /internal/v1/record-batches/{job_id}/chunks?after=-1&limit=10&wait=20`
and advance `after` to the returned `next_cursor`. Chunks are immutable and
become visible only after their complete apex snapshots and quota settlement
commit together. Cursor replay is safe. `GET .../{job_id}` reports exact
queued, completed, failed, reserved, committed, released, and outstanding
counts; `POST .../{job_id}/cancel` releases unstarted work.

Two durable `batch-worker` replicas consume bounded slices by default. A large
apex is isolated and reported in the chunk's `errors` collection instead of
failing unrelated apexes. The catalog read uses one WAL snapshot and separate
hostname, provenance-row, and serialized-byte bounds. The queue is bounded
globally and per service token; an idempotent retry of the same normalized
request does not consume quota twice.

For another Compose project, attach only its API or worker that needs these
facts to `syncpundit-data-plane` and call
`http://subfinder-index:8200/v1/records?apex=example.com`. Do not mount the
Subfinder SQLite volume into another application. Subfinder owns neutral index
facts and provenance; classifications, scores, and application-specific
enrichments belong in the consuming application's state store.

`GET /v1/search` reports queue admission in `X-Refresh-Status` and the legacy
`X-URLScan-Status` header: `queued`, `already-pending`, `queue-full`, or
`disabled`. No provider request occurs in the API process. Control-state
contention fails quickly with `503`; catalog ingestion does not block `/health`
or a WAL-backed index read.

MCP exposes one Streamable HTTP tool `search` (`{ "apex": "example.com" }` → `string[]`).

`GET /v1/search`, `GET /v1/records`, and `POST /mcp` share one atomic
allowance of 1,000 successful searches per client IP per UTC day
(`request_counts`).

Deployment operators can issue optional bearer tokens with a separate daily
allowance. Configure accepted tokens with `CTLOGS_API_TOKENS` and the limit for
each token with
`CTLOGS_TOKEN_REQUEST_LIMIT`. The database stores only a SHA-256 token digest
as the quota identity.
The private batch route consumes one token allowance unit per apex, atomically;
an HTTP batch is not a quota discount and a rejected quota debit consumes no
units. It never schedules refresh or discovery work.

### Bound request load

The Compose edge admits an initial global burst of 80 public requests, then
limits sustained traffic to 10 requests per second. It also applies an
80-request per-client burst with a 10 request-per-second sustained rate and
bounds active proxied requests to 96 globally and 80 per client. Excess edge
traffic returns `503`, `Retry-After: 1`, and
`X-Overload-Reason: edge-capacity`. `/health` bypasses these public limits but
is available only to direct local probes; a request carrying the sanitized
client header from host NGINX receives `404`. The limits live in
`deploy/nginx.conf`; keep the host NGINX connection and request limits as an
additional outer boundary.

Behind that edge, the API accepts at most 80 public requests and 16 requests
with a valid service token at one time. These limits cover the complete
response, including a streamed response. A full class returns `503`,
`Retry-After: 1`, and
`X-Overload-Reason: public-capacity` or `service-capacity`. A request rejected
at this boundary does not consume quota. Quota exhaustion remains a distinct
`429` response with the exact limit, remaining count, reset time, and retry
time.

Set `CTLOGS_PUBLIC_INFLIGHT_LIMIT` and `CTLOGS_SERVICE_INFLIGHT_LIMIT` to
change the two limits. The default catalog concurrency is one. Local burst
tests show that 70 reads take about 55 ms sequentially and about 379 ms with
eight reader threads. Keep `CTLOGS_CATALOG_CONCURRENCY=1` unless a benchmark
on the deployment host proves that a different value is faster.

Concurrent quota checks wait 2 ms so the control database can commit them in
one ordered transaction. `CTLOGS_CONTROL_BATCH_WINDOW_SECONDS` changes that
window. The 80-public and 16-service request limits bound the batch queue.
Canceled requests leave the batch before transaction selection. After a
request enters a control transaction, its exact quota outcome is final even if
the client disconnects before it receives the response.

Run one Uvicorn worker. The in-process request limits apply per worker. Keep
`/health` outside public edge limits so an overloaded instance remains
observable. Threat Hunter should call `http://subfinder-index:8200` over the
private data network with its service token; it must not loop through the
public edge, where public DoS protection intentionally sheds excess traffic.

### Configure trusted client addresses

NGINX must replace client-supplied forwarding headers. Do not append an
untrusted chain.

```nginx
proxy_set_header Forwarded "";
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
```

The Compose API has no published host port, so its default
`CTLOGS_FORWARDED_ALLOW_IPS=*` trusts the edge and other private-network peers.
Only trusted services may join those networks. When the deployment assigns a
stable edge address or subnet, set `CTLOGS_FORWARDED_ALLOW_IPS` to that narrower
value. Do not use the wildcard if any untrusted container can reach port 8200;
it could forge a public client address and avoid its quota.

If a CDN connects to NGINX, configure the NGINX real-IP module with only the
CDN's published address ranges. NGINX must resolve the client address before
it sets `X-Forwarded-For` for Subfinder.

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

The Compose `scheduler` is the single recurring catalog-writer process. It runs
live CT tails, bounded historical replay, IANA and CISA imports, configured
artifacts, optional CZDS, and optional urlscan jobs serially. Provider fetches
may be concurrent, but catalog commits share one process and the cross-process
writer lock. WAL readers remain concurrent. SQLite stores each job's next run
time.

Set `CTLOGS_URLSCAN_APEXES` to a comma-separated allowlist, or set it to `*` to
walk every apex already in the local index. The all-index mode keeps both its
apex cursor and each apex's `search_after` cursor in SQLite. Each scheduled
visit fetches the next older page until that apex's history is complete. Later
visits refresh the newest page without discarding the completed history state.
Search-triggered refreshes do not change scheduler pagination. They add the
apex to a persistent FIFO queue in the control database. The priority job processes up to 14 queued apexes
per run, one older 1,000-result page per apex, and rotates incomplete apexes to
the back of the queue. The global walk processes up to 69 apexes per run. Both
jobs start their next run 60 seconds after the previous run finishes.

The automated URLSCAN ceiling is 100,000 requests per UTC day. Provider calls
use independent quota identities: 20,000 priority-history requests and the
remaining breadth budget. Configure the total with
`CTLOGS_URLSCAN_DAILY_LIMIT`, the first share with
`CTLOGS_URLSCAN_PRIORITY_DAILY_LIMIT`; the legacy search reserve remains
accounted for by `CTLOGS_URLSCAN_SEARCH_DAILY_LIMIT`. Search admission itself
does not consume provider quota. Confirm
that this fits the account quota and urlscan's usage terms before enabling it.

All enabled sources consolidate into the same `subdomains` table. The database
keeps the earliest dated observation and records each source separately in
`subdomain_sources`. The API reads only this combined local index. It does not
query any upstream source during a request.

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
```

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
not move the live tail cursor. Compose runs both jobs through the single
scheduler; the same history operation can be invoked manually:

```bash
python -m ctlogs.ingest.history --db data/ctlogs.sqlite3 \
  --log-url https://ct.example/log --max-batches-per-log 8
```

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
Credentials are consumed only by ingestion services. The public API never
calls account-backed providers.

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
