---
layout: home

hero:
  name: Subfinder
  text: Passive subdomain intelligence
  tagline: Search a local index of observed hostnames without probing the domain you ask about.
  image:
    src: /mark.svg
    alt: Subfinder mark
  actions:
    - theme: brand
      text: Get started
      link: /getting-started
    - theme: alt
      text: API reference
      link: /reference/api

features:
  - title: Search an exact apex
    details: Plain text, JSON, provenance records, and bounded cursor pages read the same local index.
    link: /reference/api
    linkText: Explore the API
  - title: Understand the sources
    details: Certificate transparency, registry zones, public artifacts, and optional account-backed enrichment each have explicit ingestion paths.
    link: /reference/sources
    linkText: View sources
  - title: Run it your way
    details: Start a new Compose index or configure your own Cloudflare resources and publication controls.
    link: /operations/compose
    linkText: Read operations
---

## Choose a path

- **New operator:** [start the Compose service](/getting-started) and check the [operating limits](/operations/compose).
- **API consumer:** use the [search, records, batch, and MCP contracts](/reference/api).
- **Ingestion maintainer:** review the [source catalog](/reference/sources) and [ingestion commands](/how-to/ingestion).
- **Cloudflare operator:** follow the [Worker and catalog generation guide](/operations/cloudflare) to start with your own empty resources.
