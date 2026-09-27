# Subfinder

<img src="brand/lockup-on-dark.png#gh-dark-mode-only" alt="Subfinder" width="260">
<img src="brand/lockup-on-light.png#gh-light-mode-only" alt="Subfinder" width="260">

Subfinder is a passive subdomain enumeration service. It indexes certificate
transparency logs, registry zones, public datasets, and optional account-backed
sources. Searches read the local index. They do not probe a domain or submit a
urlscan scan.

## Quick start

```bash
cp .env.example .env
docker network create syncpundit-data-plane
docker compose up -d --build
curl "http://127.0.0.1:8200/v1/search?apex=example.com"
```

Add only the credentials and settings your deployment uses to `.env`.
Wrap values containing `$` in single quotes so Compose preserves them
literally. For local development, see the [getting-started guide](docs/getting-started.md).

## Documentation

- [Documentation home](docs/index.md)
- [API reference](docs/reference/api.md), including MCP and Threat Hunter batches
- [Compose operations](docs/operations/compose.md), including quotas and proxy trust
- [Ingestion guide](docs/how-to/ingestion.md) and [source catalog](docs/reference/sources.md)
- [Cloudflare migration](docs/operations/cloudflare.md)
- [Web interface design](docs/explanation/web-interface.md)

The documentation site has its own Cloudflare Pages build. See
[docs/README.md](docs/README.md) for local preview and Pages settings.

## Project layout

- `src/ctlogs/`: API, index, schedulers, and source adapters.
- `web/`: static search interface.
- `cloudflare/`: Workers and generation pipeline for the Cloudflare migration.
- `tests/`: service and deployment contract tests.
