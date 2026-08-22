from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Iterable

from ctlogs.database import Database, QuotaExceeded


CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
DEFAULT_LIMIT = 100  # documented free tier per hour guidance, caller controls


class CertSpotterClient:
    """Keyless per-apex Cert Spotter adapter with isolated quota.

    Separate table `certspotter_counts` ensures a burst of backfill never
    starves the shared `request_counts` used by GET /v1/search and POST /mcp.
    See database.Database.consume_certspotter vs consume_request.
    """

    def __init__(
        self,
        database: Database,
        *,
        client_ip: str = "ingest",
        daily_limit: int = DEFAULT_LIMIT,
        api_url: str = CERTSPOTTER_URL,
        timeout: int = 10,
    ) -> None:
        self.database = database
        self.client_ip = client_ip
        self.daily_limit = daily_limit
        self.api_url = api_url.rstrip("?")
        self.timeout = timeout

    def _consume(self) -> None:
        self.database.consume_certspotter(self.client_ip, self.daily_limit)

    def fetch(self, apex: str) -> list[str]:
        """Fetch dns_names for one apex. Raises QuotaExceeded or urllib.error."""
        self._consume()
        url = f"{self.api_url}?domain={apex}&include_subdomains=true&expand=dns_names"
        req = urllib.request.Request(url, headers={"User-Agent": "ctlogs/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read()
                payload = json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError:
            raise
        hostnames: list[str] = []
        if isinstance(payload, list):
            for entry in payload:
                names = entry.get("dns_names") if isinstance(entry, dict) else None
                if isinstance(names, list):
                    for n in names:
                        if isinstance(n, str):
                            h = n.strip().lower().rstrip(".")
                            if h:
                                hostnames.append(h)
        # Deduplicate preserve order
        seen: set[str] = set()
        uniq: list[str] = []
        for h in hostnames:
            if h not in seen:
                seen.add(h)
                uniq.append(h)
        return uniq

    def fetch_and_store(self, apex: str, first_seen: str | None = None) -> int:
        hostnames = self.fetch(apex)
        if not hostnames:
            return 0
        rows: Iterable[tuple[str, str | None]] = [(h, first_seen) for h in hostnames]
        self.database.upsert_subdomains(apex, rows)
        return len(hostnames)
