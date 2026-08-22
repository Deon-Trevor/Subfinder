from __future__ import annotations

import csv
import io
import re

from ctlogs.ingest import ZoneRecord

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_plausible_hostname(value: str) -> bool:
    value = value.strip().lower().rstrip(".")
    if not value or len(value) > 253 or "." not in value:
        return False
    labels = value.split(".")
    return all(_LABEL.fullmatch(l) for l in labels)


class GovAdapter:
    name = "gov"

    def parse(self, data: bytes | str) -> list[ZoneRecord]:
        text = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data
        records: list[ZoneRecord] = []
        # Try CSV detection: first non-empty line contains comma and header-like
        lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
        if not lines:
            return records
        # Heuristic: if first line looks like CSV header with comma
        head = lines[0]
        if "," in head and "domain" in head.lower():
            reader = csv.DictReader(io.StringIO(text))
            # Find domain column case-insensitive
            field = None
            for f in reader.fieldnames or []:
                if f.strip().lower() in ("domain", "domain_name", "domain name"):
                    field = f
                    break
            if field is None:
                field = (reader.fieldnames or [""])[0]
            for row in reader:
                raw = (row.get(field) or "").strip().lower().rstrip(".")
                if _is_plausible_hostname(raw):
                    # apex is the registrable domain itself for .gov
                    records.append(ZoneRecord(apex=raw, hostname=raw, first_seen=None))
            return records
        # Fallback: treat as zone-like or plain list, one hostname per line / first token
        for line in lines:
            # Handle zone format: "<name> <ttl> IN <type> <rdata>"
            token = line.split()[0].lower().rstrip(".") if line.split() else ""
            if _is_plausible_hostname(token):
                # For .gov zone, token is the full hostname
                apex = token  # will be re-derived by caller if needed; keep as token
                records.append(ZoneRecord(apex=apex, hostname=token, first_seen=None))
        return records
