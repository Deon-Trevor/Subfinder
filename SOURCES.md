# Source catalog

This catalog separates the public query service from the indexing jobs. A
query only reads the local index. It never fans out to these sources and never
probes a hostname.

## Default sources without credentials

### Certificate Transparency

| Source | Use |
| --- | --- |
| [Chrome CT log lists](https://googlechrome.github.io/CertificateTransparency/log_lists.html) | Discover active and retired RFC 6962 and Static CT logs. Cache the signed list and poll usable logs directly. |
| [Apple CT log list](https://support.apple.com/103214) | Add logs accepted by Apple's program that are not present in Chrome's usable set. |
| Direct CT log APIs | Read new entries from every usable log in the two program lists. Static CT and RFC 6962 need separate readers. |
| [Geomys CT Archive](https://github.com/geomys/ct-archive) | Replay retired and historical CT logs, including archives hosted by the Internet Archive. |
| [crt.sh](https://crt.sh/) | Best-effort historical backfill and comparison. It is not the live ingestion authority. |
| [Cert Spotter](https://sslmate.com/certspotter/api/) | Keyless per-apex backfill and independent coverage checks. |
| [Shodan CT](https://ctl.shodan.io/) | Keyless per-apex CT lookup. |

### Zones and apex discovery

| Source | Use |
| --- | --- |
| [IANA root zone](https://www.internic.net/domain/root.zone) | TLD inventory and delegation metadata. It does not contain registrant domains. |
| [CISA .gov data](https://github.com/cisagov/dotgov-data) | Public `.gov` registered-domain and zone-derived data. |
| Registry public data for `.ee`, `.se`, `.nu`, `.ch`, and `.li` | Seed apexes where the registry permits public zone transfer or publishes open zone data. Each adapter must record the registry's access and reuse terms. |
| [Common Crawl](https://commoncrawl.org/get-started) | Extract historical hostnames and apexes from the free crawl index and data files. |

### Passive enrichment

| Source | Use |
| --- | --- |
| [ProjectDiscovery Chaos](https://chaos.projectdiscovery.io/) public downloads | Import published public DNS datasets without an API key. |
| [HaGeZi DNS blocklists](https://github.com/hagezi/dns-blocklists) | Import hostname-only lists as discovery evidence, not as a maliciousness verdict. |
| [THC](https://ip.thc.org/) | Keyless per-apex passive enumeration. |
| [sub.md](https://sub.md/) | Keyless per-apex passive enumeration. An optional token may raise its service limits. |
| [crt.name](https://crt.name/) | Keyless per-apex backfill while it remains an external service. |
| [RapidDNS](https://rapiddns.io/) | Keyless per-apex passive lookup. |
| [HackerTarget](https://hackertarget.com/find-dns-host-records/) | Keyless, rate-limited per-apex lookup. |
| [SiteDossier](http://www.sitedossier.com/) | Keyless per-apex lookup with explicit handling for blocking and incomplete responses. |

The seven fast defaults in
[`subfaster`](https://github.com/melvinsh/subfaster) are `thc`, `submd`, `crt`,
`shodanct`, `rapiddns`, `hackertarget`, and `sitedossier`. We can reuse its
source behavior on the indexing side. If a deployment points `crt` back to its
own API, that source must be excluded to prevent a collection loop.

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
