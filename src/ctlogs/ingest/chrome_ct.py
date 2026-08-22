from __future__ import annotations

import json
import urllib.request


CHROME_LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"


class ChromeCTLogList:
    name = "chrome_ct_log_list"

    def __init__(self, api_url: str = CHROME_LOG_LIST_URL, timeout: int = 15) -> None:
        self.api_url = api_url
        self.timeout = timeout

    def fetch(self) -> list[dict]:
        req = urllib.request.Request(self.api_url, headers={"User-Agent": "ctlogs/1.0"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        logs = []
        if isinstance(payload, dict):
            for key in ("operators", "log_list", "logs"):
                val = payload.get(key)
                if isinstance(val, list):
                    # Chrome v3 format: {"operators": [{"logs": [...]}, ...]}
                    if key == "operators":
                        for op in val:
                            if isinstance(op, dict):
                                for log in op.get("logs", []):
                                    if isinstance(log, dict) and "url" in log:
                                        logs.append(log)
                    else:
                        logs.extend([x for x in val if isinstance(x, dict)])
                    break
            # Fallback: direct logs array at top level?
            if not logs and "logs" in payload and isinstance(payload["logs"], list):
                logs = [x for x in payload["logs"] if isinstance(x, dict)]
        return logs

    def usable_urls(self) -> list[str]:
        logs = self.fetch()
        urls: list[str] = []
        for log in logs:
            url = log.get("url")
            state = log.get("state") or {}
            # v3: state has exactly one key like "usable", "qualified", "pending", "retired", "rejected"
            # Retired, rejected, and pending RFC logs commonly return 404 here.
            if isinstance(state, dict):
                if not ("usable" in state or "qualified" in state):
                    continue
            if isinstance(url, str) and url.strip():
                urls.append(url.strip().rstrip("/"))
        # Dedup preserve order
        seen: set[str] = set()
        uniq: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                uniq.append(u)
        return uniq
