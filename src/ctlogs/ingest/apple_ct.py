from __future__ import annotations

import json
import urllib.request


APPLE_LOG_LIST_URL = "https://valid.apple.com/ct/log_list/current_log_list.json"


class AppleCTLogList:
    name = "apple_ct_log_list"

    def __init__(self, api_url: str = APPLE_LOG_LIST_URL, timeout: int = 15) -> None:
        self.api_url = api_url
        self.timeout = timeout

    def fetch(self) -> list[dict]:
        req = urllib.request.Request(self.api_url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        logs: list[dict] = []
        if isinstance(payload, dict):
            # Apple format: {"version":..., "operators": [{"name":..., "logs": [...]}, ...]}
            ops = payload.get("operators")
            if isinstance(ops, list):
                for op in ops:
                    if isinstance(op, dict):
                        for log in op.get("logs", []):
                            if isinstance(log, dict) and "url" in log:
                                logs.append(log)
            # Fallback flat logs
            if not logs and isinstance(payload.get("logs"), list):
                logs = [x for x in payload["logs"] if isinstance(x, dict)]
        elif isinstance(payload, list):
            logs = [x for x in payload if isinstance(x, dict)]
        return logs

    def usable_urls(self) -> list[str]:
        logs = self.fetch()
        urls: list[str] = []
        for log in logs:
            url = log.get("url")
            if isinstance(url, str) and url.strip():
                urls.append(url.strip().rstrip("/"))
        seen: set[str] = set()
        uniq: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                uniq.append(u)
        return uniq
