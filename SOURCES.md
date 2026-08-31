# Source catalog

This catalog separates the public query service from indexing jobs. A query
reads the local index and atomically queues optional passive enrichment. It does
not wait for urlscan, submit a live scan, or probe a hostname.

## Default sources without credentials

### Certificate Transparency

| Source | Use |
| --- | --- |
| [Chrome CT log list](https://googlechrome.github.io/CertificateTransparency/log_lists.html) | Discover usable logs in Chrome's program. |
| [Apple CT log list](https://support.apple.com/103214) | Add usable logs in Apple's program that are absent from Chrome's list. |
| RFC 6962 log APIs | Read new entries through `get-sth` and `get-entries`. |
| [C2SP Static CT](https://c2sp.org/static-ct-api) | Read new entries from configured data-tile monitoring prefixes. |
| [Geomys CT Archive](https://github.com/geomys/ct-archive) | Replay retired and historical logs, including archives hosted by the Internet Archive. |

### Zones and apex discovery

| Source | Use |
| --- | --- |
| [IANA root zone](https://www.internic.net/domain/root.zone) | TLD inventory and delegation metadata. It does not contain registrant domains. |
| [CISA .gov data](https://github.com/cisagov/dotgov-data) | Public `.gov` registered-domain and zone-derived data. |
| Registry data for `.ee`, `.se`, and `.nu` | Seed apexes from public zone transfers where the registry permits them. |
| Registry data for `.ch` and `.li` | Seed apexes through the gated TSIG adapter when `CTLOGS_ENABLE_CH_LI=1`. |

### Crawls and host lists

| Source | Use |
| --- | --- |
| [Common Crawl](https://commoncrawl.org/get-started) | Extract historical hostnames and apexes from the free crawl index and data files. |
| [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io/) public downloads | Import published public DNS datasets without an API key. |
| [HaGeZi DNS blocklists](https://github.com/hagezi/dns-blocklists) | Import hostname-only lists as discovery evidence, not as a maliciousness verdict. |

Every enabled adapter writes to one index. A hostname keeps its earliest dated
observation across sources, while `subdomain_sources` keeps each source's own
first and last observation. Public searches only read the consolidated index.
Bulk and CT sources run on the recurring writer scheduler. Search-priority
URLScan and user-requested local-zone imports run on one dedicated enrichment
worker. Both use the same cross-process catalog lock and URLScan quota ledger;
neither replaces another source's observations. `/v1/stats` reports the
current count of distinct provenance source IDs.

## Update cadence

One scheduler owns recurring catalog writes. It tails Chrome, Apple, RFC 6962,
and configured Static CT logs; rotates through historical RFC 6962 entries with
an independent cursor; runs IANA, CISA, configured artifacts, and CZDS; and
runs optional URLScan breadth jobs. Search requests only enqueue the searched
apex in the separate control database. The enrichment worker is the sole
consumer of that priority FIFO, so provider calls cannot race.

CZDS and URLScan have independent caps. CZDS first selects up to 25 zones that
have never been ingested, alphabetically because the approved-links feed has no
approval timestamp, then rotates through the least-recently checked zones. With
`CTLOGS_URLSCAN_APEXES=*`, URLScan walks
the full local apex index in batches of up to 69. Each apex keeps its own
`search_after` cursor. Search requests add their apex to a persistent FIFO queue
in the control database. Its job processes up to 14 apexes per run. Incomplete apexes rotate to the
back; completed apexes leave the queue. API refreshes do not overwrite those
cursors.

Automated URLSCAN calls use separate daily classes under one 100,000-request
ceiling: 20,000 queued-history requests, a retained 10,000-request reserve, and
70,000 breadth requests. Searches do not make provider calls. The class
maximums add up to the total, so breadth cannot silently consume the priority
share. Artifact imports each have their own
download and parser run, so adding one cannot consume another source's slot.

The `.ee`, `.se`, `.nu`, `.ch`, `.li`, Chaos, Common Crawl, HaGeZi, and Geomys
adapters do not discover their own upstream files. They run unattended only
after an operator configures a permitted artifact location. `.ch` and `.li`
also require the registry's purpose-approved TSIG access.

## Optional sources that require a free account or key

| Source | Requirement | Use |
| --- | --- | --- |
| [ICANN CZDS](https://github.com/icann/czds-api-client-python) | ICANN account with approved zones | Authenticated registry zone downloads and broad gTLD backfill. |
| [urlscan.io](https://urlscan.io/docs/api/) | API key for dependable automation | Per-apex hostname discovery from indexed scans. |

These are enrichment sources. The planned no-credential pipeline must remain
operable when all optional sources are disabled.

## Excluded from the free query path

- Active DNS or HTTP probing. Probing belongs in a separate, explicitly
  enabled indexing job and is never triggered by `/v1/search` or MCP.
- The old public CertStream aggregator. Its public stream has been stale, so it
  is not a live ingestion dependency.
- Paid-only APIs or sources whose terms do not allow storage and redistribution.

## Ingestion rules

- Normalize names to ASCII IDNA and group them by private-aware eTLD+1.
- Keep the earliest indexed `first_seen` value for each `(apex, subdomain)`.
- Record source provenance in the ingestion layer even though the public search
  response only exposes the hostname and first-seen date.
- Track unique contributions by source. A new adapter must not consume a shared
  cap in a way that silently removes coverage from an existing source.
- Cache bulk artifacts and log-list metadata. Respect published rate limits,
  access conditions, and redistribution terms.
