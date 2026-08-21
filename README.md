# CT Logs backend

This is the first backend slice for a public, indexed subdomain search service.
Searches are passive database reads. The public HTTP API and MCP tool never
probe the requested domain or returned hostnames.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/uvicorn ctlogs.app:app --reload
```

The SQLite database defaults to `data/ctlogs.sqlite3`. Set `CTLOGS_DB_PATH` to
put it elsewhere.

## Public interfaces

```text
GET /v1/search?apex=example.com
GET /v1/search?apex=example.com&format=json
GET /v1/search?apex=example.com&dates=1
POST /mcp
```

The HTTP response is one hostname per line unless `format=json` is requested.
`dates=1` adds the indexed first-seen timestamp. The MCP server exposes one
tool named `search`, which accepts an `apex` and returns all indexed hostnames.

Both interfaces share one atomic allowance of 1,000 successful searches per
client IP per UTC day. Configure the reverse proxy to pass the real peer address
to Uvicorn. Do not trust a client-supplied forwarding header directly.

The MCP transport validates `Host` and `Origin` headers. Add the deployment
hostname to `CTLOGS_ALLOWED_HOSTS` and browser origins to
`CTLOGS_ALLOWED_ORIGINS`, using comma-separated values.

See [SOURCES.md](SOURCES.md) for the no-credential default catalog and the
optional account-backed sources. Ingestion is the next backend slice and is not
implemented in this one.
