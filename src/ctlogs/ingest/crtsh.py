from __future__ import annotations

import json
import urllib.request
import urllib.parse


CRT_URL = "https://crt.sh/"


class CrtShClient:
    """Best-effort crt.sh backfill. No quota, tolerated 502/timeouts.

    Not the live ingestion authority. Use as fallback/comparison.
    """

    def __init__(self, database, *, api_url: str = CRT_URL, timeout: int = 15) -> None:
        self.database = database
        self.api_url = api_url.rstrip("/")
        self.timeout = timeout

    def fetch(self, apex: str) -> list[str]:
        q = urllib.parse.quote(apex, safe="")
        url = f"{self.api_url}/?q={q}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            if not body.strip():
                return []
            payload = json.loads(body)
        hostnames: list[str] = []
        if isinstance(payload, list):
            for entry in payload:
                if not isinstance(entry, dict):
                    continue
                nv = entry.get("name_value")
                if not isinstance(nv, str):
                    continue
                for raw in nv.splitlines():
                    h = raw.strip().lower().rstrip(".")
                    if h.startswith("*."):
                        h = h[2:]
                    if h:
                        hostnames.append(h)
        # Dedup preserve order
        seen: set[str] = set()
        uniq: list[str] = []
        for h in hostnames:
            if h not in seen:
                seen.add(h)
                uniq.append(h)
        return uniq

    def fetch_and_store(self, apex: str, first_seen: str | None = None) -> int:
        try:
            hostnames = self.fetch(apex)
        except Exception:
            return 0
        if not hostnames:
            return 0
        # Filter to names under apex (crt.sh can return unrelated)
        filtered = [h for h in hostnames if h == apex or h.endswith(f".{apex}")]
        if not filtered:
            return 0
        self.database.upsert_subdomains(apex, [(h, first_seen) for h in filtered])
        return len(filtered)
