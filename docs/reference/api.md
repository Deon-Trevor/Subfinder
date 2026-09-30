# API reference

These are the Compose service's public and private HTTP interfaces. The
[Cloudflare migration guide](/operations/cloudflare) describes the separate
read Worker and its deployment controls.

## Routes

```text
GET /v1/search?apex=example.com
GET /v1/search?apex=example.com&format=json
GET /v1/search?apex=example.com&dates=1
GET /v1/search?apex=example.com&format=json&dates=1
GET /v1/records?apex=example.com
GET /v1/enrichment-options?apex=example.com
POST /v1/enrichment-jobs
GET /v1/enrichment-jobs/{job_id}
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

## Search results

Plain text is one hostname per line unless `format=json` is requested. `dates=1` adds `first_seen`. Empty index returns `200` with empty body/array, not `404`.

## Passive enrichment jobs

An empty local result can be enriched without turning the search request into
a long provider call. `GET /v1/enrichment-options?apex=nust.ac.zw` reports two
independent actions: import the exact public-suffix zone when its approved
artifact is already present under the managed CZDS directory, and query
existing URLScan history for the exact apex when the scheduler has published
that capability. Subfinder never downloads a missing zone for this route and
never accepts a caller-supplied path.

Submit one or both advertised actions with a stable idempotency key:

```http
POST /v1/enrichment-jobs
Idempotency-Key: nust-ac-zw-20260831
Content-Type: application/json

{"apex":"nust.ac.zw","actions":["local_zone","urlscan"]}
```

The response is `202` with a durable job and a `Location` header. Poll that
location until `terminal` is true, then request `result_url`. The local-zone
and URLScan lanes report their own state and ingested-record count. A bounded
URLScan page with older history remaining is `checkpointed`, not complete;
the ordinary priority queue continues from its existing cursor. "URLScan" here
means a passive search of scans already on file. It never submits a scan or
probes the apex. Jobs are bounded globally and per requester, consume one
normal search allowance unit only when first admitted, and hide their status
from other requester identities.

On `subfinder.pundit.workers.dev`, the Cloudflare Worker offers only the
`urlscan` action. It reports `local_zone` as unavailable because the Worker
has no local zone file. An admitted request uses one normal search allowance
unit and reads at most one URLScan page. The provider read writes an immutable
delta; it does not change the active index immediately. A completed job reports
`pending_publication` in its URLScan lane and has no `result_url`. Search again
after the next catalog generation is active. If the job reports
`more_available`, another request can read the next page. The on-demand source
does not join the recurring URLScan schedule.

## Pagination

The unpaginated response remains backward compatible and streams valid text or
JSON without building the full result in memory. Large consumers can add
`limit=5000` and follow `X-Next-Cursor` or the `Link: rel="next"` header. A
cursor is valid only for the same apex and ordering contract used to obtain it.
Paginated responses also carry `X-Result-Total`, `X-Result-Dated-Total`, and
`X-Result-Page-Size`. The web interface requests 500 rows at a time and keeps
the shelf DOM bounded to the current page; moving forward is an explicit
search read, while moving back reuses pages already read in that tab.

## Provenance records

`GET /v1/records` is the stable local-index interface for service consumers.
It never contacts an upstream provider. Its JSON response identifies
`schema_version` as `subfinder.index-records.v1` and returns each hostname's
earliest observation plus the source-specific `source`, `first_seen`, and
`last_seen` records. It consumes the same search allowance as `/v1/search` and
returns `X-Subfinder-Schema-Version` so consumers can reject an unsupported
contract before parsing the body.

## Private synchronous batches

Trusted services can read several complete index snapshots with
`POST /internal/v1/records/batch`:

```json
{"apexes":["example.com","example.net"]}
```

The route requires a bearer token configured in `CTLOGS_API_TOKENS` and
answers only on the private data plane. The public NGINX edge hides it. Its
response schema is
`subfinder.internal-index-records-batch.v1`; `results` uses the existing
`subfinder.index-records.v1` object for each apex in request order. One batch
contains at most 100 unique apexes and 5,000 hostnames by default. Set
`CTLOGS_BATCH_MAX_APEXES` and `CTLOGS_BATCH_MAX_RECORDS` to lower deployment
limits. Oversized requests return `413` and must be split.

## Durable uMzingeli batches {#durable-threat-hunter-batches}

uMzingeli uses the durable queue rather than hold a request open. The Python
service and Cloudflare read Worker implement the same admission and replay
contract:

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

One normal-hunt job accepts at most 25,000 unique apexes by default. The token
allowance defaults to 250,000 apex units per UTC day, enough for ten full-sized
normal hunts, while workers claim up to 100 apexes per slice.

These bounds are independent of uMzingeli's 1,000 completed-apex delivery bound
and 1,000-candidate source result budget. Its `SUBFINDER_BATCH_MAX_APEXES` must
not exceed the serving instance's admission bound. Stale local `.env` values
can lower admission or token quota despite newer Compose defaults.

Two durable `batch-worker` replicas consume bounded slices by default. A worker
isolates a large apex and reports it in the chunk's `errors` collection rather
than failing unrelated apexes. The catalog read uses one WAL snapshot and separate
hostname, provenance-row, and serialized-byte bounds. The queue is bounded
globally and per service token; an idempotent retry of the same normalized
request does not consume quota twice.

For another Compose project, attach only its API or worker that needs these
facts to `syncpundit-data-plane` and call
`http://subfinder-index:8200/v1/records?apex=example.com`. Do not mount the
Subfinder SQLite volume into another application. Subfinder owns neutral index
facts and provenance; classifications, scores, and application-specific
enrichments belong in the consuming application's state store.

## Refresh status and quotas

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

## Status and MCP security

`GET /v1/stats` returns whole-index counts (`apex_count`, `hostname_count`,
`dated_hostname_count`, `source_count`), the certificate transparency subset
(`ct_hostname_count`, `ct_log_count`), and `last_ingest_at`. `GET /ready`
returns a status string with the hostname count and the same timestamp. Neither
route consumes the search allowance.

`TransportSecuritySettings` validates `Host` and `Origin` for MCP. Add deployment hostnames to `CTLOGS_ALLOWED_HOSTS` and browser origins to `CTLOGS_ALLOWED_ORIGINS` (comma-separated).
