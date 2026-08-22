from __future__ import annotations

import json

from ctlogs.ingest import ZoneRecord


class ChaosAdapter:
    """Parses ProjectDiscovery Chaos public DNS datasets (JSONL).

    Input is bulk JSON lines from Chaos download, e.g.:
      {"domain": "example.com", "subdomain": "a.example.com"}
    or plain hostname list. No API key required.
    """

    name = "chaos"

    def parse(self, data: bytes | str) -> list[ZoneRecord]:
        text = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data
        records: list[ZoneRecord] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            # Try JSON first
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    # Chaos fields vary: subdomain, host, domain
                    for key in ("subdomain", "host", "hostname", "name"):
                        val = obj.get(key) if isinstance(obj, dict) else None
                        if isinstance(val, str) and val.strip():
                            h = val.strip().lower().rstrip(".")
                            records.append(ZoneRecord(apex=h, hostname=h, first_seen=None))
                            break
                    else:
                        # Fallback: try domain + subdomain combine?
                        if isinstance(obj, dict) and "domain" in obj:
                            d = obj.get("domain")
                            if isinstance(d, str):
                                h = d.strip().lower().rstrip(".")
                                records.append(ZoneRecord(apex=h, hostname=h, first_seen=None))
                    continue
                except json.JSONDecodeError:
                    pass
            # Plain hostname
            h = line.lower().rstrip(".")
            if h and "." in h:
                records.append(ZoneRecord(apex=h, hostname=h, first_seen=None))
        return records
