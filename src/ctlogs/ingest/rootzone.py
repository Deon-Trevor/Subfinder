from __future__ import annotations

import re

from ctlogs.ingest import ZoneRecord

# Root zone line: "com. 86400 IN NS a.gtld-servers.net."
_TLD_LINE = re.compile(r"^([a-z0-9-]+\.?)\s+\d+\s+IN\s+NS\s+", re.IGNORECASE)


class RootZoneAdapter:
    name = "root"

    def parse(self, data: bytes | str) -> list[ZoneRecord]:
        text = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data
        records: list[ZoneRecord] = []
        seen: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("$"):
                continue
            m = _TLD_LINE.match(line)
            if not m:
                continue
            tld = m.group(1).lower().rstrip(".")
            if not tld or tld in seen:
                continue
            seen.add(tld)
            # Root zone does not provide apex hostnames, but we record TLD inventory
            # For benchmark, we store tld as hostname under synthetic apex
            records.append(ZoneRecord(apex=tld, hostname=tld, first_seen=None))
        return records
