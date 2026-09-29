# Cloudflare source refresh

The Compose scheduler remains the source of record for feeds that have not
moved to Cloudflare. The Cloudflare Workers use independent cursors and
limits. Do not turn off a Compose source until its Cloudflare replacement has
completed a staging refresh and its deltas have appeared in an active catalog
generation.

| Source | Cloudflare refresh path | Current staging gate |
| --- | --- | --- |
| Chrome and Apple RFC 6962 log lists | `ingest-worker` checks both official lists daily. It adds only usable or qualified RFC logs on exact `CT_ALLOWED_HOSTS` hosts and disables discovered logs absent from both active lists. Reviewed logs are never disabled by discovery. Discovered logs start near the current tree head and have a separate per-run cap. | Discovery and its cap are `0` in the staging config. Existing reviewed CT sources remain available. |
| Reviewed RFC 6962 logs | `ingest-worker` tails persisted D1 cursors on each Cron tick. A failed tree-head request waits one hour without blocking another log. | Staging Cron remains empty during `.com` compaction. |
| IANA root zone | `ingest-worker` checks the official root zone daily and stores a digest-addressed TLD inventory in private R2. TLDs are not registrant domains and never enter search results. | `PUBLIC_SOURCES_ENABLED=0`. |
| CISA `.gov` list | `ingest-worker` checks the official CSV daily. A changed digest creates one immutable, apex-only `public-bulk` delta. The same delta can be retried after a Queue failure. | `PUBLIC_SOURCES_ENABLED=0`; the compaction ledger migration must run before enabling it. |
| ICANN CZDS | `czds-worker` refreshes approved links, selects up to `CZDS_MAX_ZONES` due zones, and tracks the last attempt so a failed new zone does not take every daily slot. | Cron is empty and `CZDS_ONLY_ZONE=com` until the staged `.com` generation is verified. |
| URLScan | `urlscan-worker` refreshes enabled, explicitly seeded apexes from D1. Provider calls have a UTC-day cap; public searches never call URLScan. | Cron is empty. No searched apex is auto-enrolled into breadth refresh. |
| C2SP Static CT | `ingest-worker` has a separate allowlist, cursor, and per-run budget for C2SP data tiles. It seeds the configured Willow shard disabled and starts near the current checkpoint when enabled. This is indexing, not a CT consistency audit. | `STATIC_CT_SOURCE_LIMIT=0`, the seeded shard is disabled, and staging Cron is empty. Enable only after the ledger accepts `static-ct`. |
| Geomys archives | The Compose adapter remains active where configured. No approved Cloudflare archive location is provided. | No Cloudflare refresh is configured. |
| `.ee`, `.se`, `.nu`, Chaos, HaGeZi, and Common Crawl | The Compose artifact adapters remain active where a permitted location is configured. Their locations are not supplied by this repository. | No Cloudflare artifact location is configured. |
| `.ch` and `.li` | The Compose gated adapter requires purpose-approved registry TSIG access. | No Cloudflare access is configured. |

The public-feed Worker has an 8 MiB response cap. It rejects empty or
implausibly small official files and follows no redirects. The CISA parser
keeps only the domain column. The compaction Worker validates each domain
against the shared IDNA and public-suffix policy before registering the
delta. A full CSV refresh is append-only evidence; a removed CISA row does
not erase an older domain observation.

## Enable the direct feeds on staging

Wait until all `.com` deltas are in active staging generations, no generation
is mapping, mapped, reducing, or published, and both staging compaction Queues
are idle. The first active generation alone does not meet this gate. Keep the
production hostname unchanged.

1. Check the staging CT D1 migration list. Migrations
   `0002_public_sources.sql` through `0005_static_ct.sql` were already applied
   as of 2026-09-29. Apply any missing migration before enabling a feed.
2. Apply `cloudflare/compaction-worker/migrations/0003_public_bulk_source.sql`
   to the staging generation ledger while no map or reduce task is running.
   This migration copies the ledger and its fragment references in one D1
   transaction. Check `PRAGMA foreign_key_check` and the pre- and post-migration
   row counts before enabling CISA or Static CT.
3. Deploy the matching staging compaction and CT Worker revisions. Set
   `PUBLIC_SOURCES_ENABLED=1` only after the ledger accepts `public-bulk`.
   Enable the seeded Static CT shard and set `STATIC_CT_SOURCE_LIMIT=1`
   only after the ledger accepts `static-ct` and a controlled tile test passes.
   Set `CT_LOG_DISCOVERY_ENABLED=1` only after reviewing
   `CT_ALLOWED_HOSTS`; the remote lists cannot widen this allowlist.
4. Trigger one controlled staging refresh. Check the two
   `public_source_state` rows, the CT discovery rows, the immutable R2
   objects, the compaction ledger, and the dead-letter Queues. Enable Cron
   only after that check passes. Keep the discovered CT budget separate from
   `CT_SOURCE_LIMIT`, which reserves capacity for reviewed sources.

The artifact-fed sources need approved locations and a bounded Cloudflare
parser before their Compose jobs can retire. Do not point a Worker at an
arbitrary URL or treat an unconfigured source as an empty result.
