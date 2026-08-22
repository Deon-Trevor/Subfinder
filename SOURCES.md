# Source catalog

This catalog separates the public query service from the indexing jobs. A
query only reads the local index. It never fans out to these sources and never
probes a hostname.

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

These twelve adapters build one index. Public searches read that index rather
than contacting an adapter during the request.

## Optional sources that require a free account or key

| Source | Requirement | Use |
| --- | --- | --- |
| [ICANN CZDS](https://czds.icann.org/) | Login and approved zone requests | Broad gTLD zone backfill. |
| [urlscan.io](https://urlscan.io/docs/api/) | API key for dependable automation | Per-apex hostname discovery and comparison with Threat Hunter results. |
| [Censys](https://docs.censys.com/docs/platform-api) | Account and API credentials | Certificate and host backfill when quota permits. |
| [ProjectDiscovery Chaos API](https://docs.projectdiscovery.io/opensource/chaos/overview) | API key | Incremental access beyond public downloads. |

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
