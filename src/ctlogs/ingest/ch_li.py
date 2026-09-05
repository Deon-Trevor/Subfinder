from __future__ import annotations

import re

from ctlogs.ingest import ZoneRecord

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_hostname(value: str) -> bool:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or "." not in value:
        return False
    return all(_LABEL.fullmatch(l) for l in value.split("."))


class ChLiAdapter:
    """Parses AXFR dumps for .ch and .li from zonedata.switch.ch.

    Access needs a TSIG key and is restricted to cybercrime and research use.
    `CTLOGS_ENABLE_CH_LI=1` gates the adapter; without it the benchmark skips
    and ingest returns empty. See SOURCES.md.
    """

    def __init__(self, zone: str) -> None:
        self.name = zone.lower().strip(".")
        assert self.name in ("ch", "li")

    def parse(self, data: bytes | str) -> list[ZoneRecord]:
        text = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data
        records: list[ZoneRecord] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("$"):
                continue
            owner = line.split()[0].lower().rstrip(".")
            if not _is_hostname(owner):
                continue
            if owner != self.name and not owner.endswith(f".{self.name}"):
                continue
            records.append(ZoneRecord(apex=owner, hostname=owner, first_seen=None))
        return records
