# Get started

Use the hosted passive index without installing anything:

```bash
curl "https://subfinder.syncpundit.io/v1/search?apex=example.com"
curl "https://subfinder.syncpundit.io/v1/search?apex=example.com&format=json"
```

The hosted catalog is being expanded. A missing hostname is not proof that it
does not exist. To run your own service, use the Compose path below from the
repository root. Compose and Cloudflare are separate deployments.

## Run with Docker (recommended)

Build and run with Compose. A one-shot migration prepares the catalog and small
control database before the read-only API, recurring scheduler, and dedicated
enrichment worker start. The two writers serialize every catalog mutation with
one cross-process lock. The published loopback port belongs to a bounded NGINX
edge; the API itself is reachable only from Docker networks.

Copy `.env.example` to the single untracked `.env` deployment file and fill in
only the credentials and overrides this deployment uses. Compose passes
provider credentials from that file only where needed: CZDS goes to the
scheduler, while URLScan goes to the scheduler and enrichment worker. Wrap
values containing `$` in single quotes so Compose preserves them literally and
does not interpret credential fragments as variable names. The API receives
only the variables listed for it in `docker-compose.yml`. Compose never
injects the whole file into a container.

```bash
cp .env.example .env
docker network create syncpundit-data-plane
docker compose up -d --build
```

The API runs `uvicorn ctlogs.app:app --host 0.0.0.0 --port 8200`. The hostname
catalog lives in `ctlogs-data`; quotas and the deduplicated refresh queue live
separately in `ctlogs-control`.
Compose publishes the edge on port 8200 on host loopback only, for the host
NGINX. It attaches the API container alone to the external
`syncpundit-data-plane` network, under the `subfinder-index` alias. Create that
network once before the first deployment.
The API opens the catalog read-only. Migration, the recurring scheduler, and
the single enrichment worker are the only Compose services that can mutate
it; every runtime write uses the same cross-process catalog lock.
`CTLOGS_DATA_VOLUME`, `CTLOGS_CONTROL_VOLUME`, and `CTLOGS_DATA_NETWORK` in
`.env` name the owner of each shared volume and network.

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
