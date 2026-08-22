from __future__ import annotations

import json

import re

from ctlogs.ingest import ZoneRecord

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_hostname(value: str) -> bool:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or "." not in value:
        return False
    return all(_LABEL.fullmatch(l) for l in value.split("."))


class CommonCrawlAdapter:
    """Parses Common Crawl index lines for hostname discovery.

    Input is CDX index or columnar index lines containing URLs.
    Extracts hostnames without needing crawl WARC fetch.
    """

    name = "commoncrawl"

    def parse(self, data: bytes | str) -> list[ZoneRecord]:
        text = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data
        records: list[ZoneRecord] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Try JSON per line
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                    for key in ("url", "host", "hostname"):
                        val = obj.get(key) if isinstance(obj, dict) else None
                        if isinstance(val, str):
                            h = val.strip().lower()
                            if "://" in h:
                                h = h.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
                            h = h.rstrip(".")
                            if _is_hostname(h):
                                records.append(ZoneRecord(apex=h, hostname=h, first_seen=None))
                            break
                    continue
                except json.JSONDecodeError:
                    pass
            h = line.lower().split()[0]
            if "://" in h:
                h = h.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            h = h.rstrip(".")
            if _is_hostname(h):
                records.append(ZoneRecord(apex=h, hostname=h, first_seen=None))
        return records
