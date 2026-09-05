from __future__ import annotations

import re

from ctlogs.ingest import ZoneRecord

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_hostname(value: str) -> bool:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or "." not in value:
        return False
    return all(_LABEL.fullmatch(l) for l in value.split("."))


class EeSeNuAdapter:
    """Parses AXFR dumps for .ee (zone.internet.ee), .se and .nu (zonedata.iis.se).

    Input is the raw AXFR text that `dig AXFR` returns. Each line starts with
    the owner name. The parser keeps delegated hostnames and ignores glue.
    """

    def __init__(self, zone: str) -> None:
        self.name = zone.lower().strip(".")
        assert self.name in ("ee", "se", "nu")

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
            # Only keep names under this zone
            if owner != self.name and not owner.endswith(f".{self.name}"):
                continue
            records.append(ZoneRecord(apex=owner, hostname=owner, first_seen=None))
        return records


# Convenience aliases for registry
EeAdapter = lambda: EeSeNuAdapter("ee")  # type: ignore
SeAdapter = lambda: EeSeNuAdapter("se")  # type: ignore
NuAdapter = lambda: EeSeNuAdapter("nu")  # type: ignore
