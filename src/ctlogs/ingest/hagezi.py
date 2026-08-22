from __future__ import annotations

from ctlogs.ingest import ZoneRecord


class HageziAdapter:
    """Parses HaGeZi DNS blocklists - hostname-only lists.

    Each line is a hostname or `0.0.0.0 host` format. Used as discovery
    evidence only, not maliciousness verdict.
    """

    name = "hagezi"

    def parse(self, data: bytes | str) -> list[ZoneRecord]:
        text = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data
        records: list[ZoneRecord] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            # Handle "0.0.0.0 host" or "127.0.0.1 host"
            parts = line.split()
            candidate = parts[-1] if parts else ""
            h = candidate.strip().lower().rstrip(".")
            if h and "." in h and not h[0].isdigit():
                records.append(ZoneRecord(apex=h, hostname=h, first_seen=None))
        return records
