# Web interface

The Compose service serves this frontend beside its API. The Cloudflare read
Worker serves its own static asset bundle.

`web/` holds the frontend with no build step: `index.html`, `app.css`, `app.js`,
`robots.txt`, `site.webmanifest`, and the icon set.
`ctlogs.web.mount_frontend` registers each one as an explicit named route at
startup, so the page and the API share an origin. They are named routes rather
than a `StaticFiles` mount because `create_app` mounts the MCP app at `/`, and a
second directory mount on that prefix would swallow `/mcp`. Only
those names are servable, so a stray file dropped in `web/` is not reachable.

Subfinder serves `ASSETS` with `Cache-Control: no-cache`, because the markup and
the assets ship together and a browser must not pair new markup with a cached
script. The icons in `MEDIA` carry no such pairing, so they are cached for a
week instead. Brand sources live in [`brand/`](https://github.com/Deon-Trevor/Subfinder/tree/main/brand), which
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
browser session comes from memory instead of the API. The counter in the
page header polls `/v1/stats` every 15 seconds and pauses while the tab is
hidden. That polling is only safe while `/v1/stats` stays outside the
allowance. At a 15 second interval a metered stats route would spend all 1,000
daily reads in about four hours for a visitor who never ran a search.
`test_opening_the_page_spends_no_search_allowance` and
`test_the_live_counter_endpoint_spends_no_search_allowance` in
`tests/test_web.py` pin both, so adding a `consume()` call to `/v1/stats` fails
the suite rather than quietly draining callers.
