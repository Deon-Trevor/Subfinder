from __future__ import annotations

import json
import urllib.request

SHODANCT_URL = "https://ctl.shodan.io/api/search"
DEFAULT_LIMIT = 1000


class ShodanCTClient:
    """Keyless per-apex Shodan CT adapter.

    Isolated `shodanct_counts` table keeps Shodan consumption from starving
    `request_counts` (search/MCP) and `certspotter_counts`.
    """

    def __init__(
        self,
        database,
        *,
        client_ip: str = "ingest",
        daily_limit: int = DEFAULT_LIMIT,
        api_url: str = SHODANCT_URL,
        timeout: int = 10,
    ) -> None:
        self.database = database
        self.client_ip = client_ip
        self.daily_limit = daily_limit
        self.api_url = api_url.rstrip("?")
        self.timeout = timeout

    def fetch(self, apex: str) -> list[str]:
        self.database.consume_shodanct(self.client_ip, self.daily_limit)
        url = f"{self.api_url}?domain={apex}"
        req = urllib.request.Request(url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        hostnames: list[str] = []
        # Shodan CT returns {"subdomains": ["a.example.com", ...]} or list
        if isinstance(payload, dict):
            subs = payload.get("subdomains") or payload.get("data") or []
            if isinstance(subs, list):
                for item in subs:
                    if isinstance(item, str):
                        hostnames.append(item.strip().lower().rstrip("."))
                    elif isinstance(item, dict):
                        n = item.get("name") or item.get("subdomain") or item.get("value")
                        if isinstance(n, str):
                            hostnames.append(n.strip().lower().rstrip("."))
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, str):
                    hostnames.append(item.strip().lower().rstrip("."))
        # Dedup preserve order
        seen: set[str] = set()
        uniq: list[str] = []
        for h in hostnames:
            if h and h not in seen:
                seen.add(h)
                uniq.append(h)
        return uniq

    def fetch_and_store(self, apex: str, first_seen: str | None = None) -> int:
        hostnames = self.fetch(apex)
        if not hostnames:
            return 0
        self.database.upsert_subdomains(apex, [(h, first_seen) for h in hostnames])
        return len(hostnames)
