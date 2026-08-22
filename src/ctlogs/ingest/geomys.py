from __future__ import annotations

import json
import gzip

from ctlogs.ingest import ZoneRecord
from ctlogs.database import Database


class GeomysArchive:
    """Replays Geomys CT Archive / Internet Archive historical CT logs.

    Input is bulk JSONL or gzipped JSONL where each line is a CT entry
    with hostnames. No token required. Used for historical backfill.
    """

    name = "geomys"

    def __init__(self, database: Database) -> None:
        self.database = database

    def parse_file(self, path: str) -> list[ZoneRecord]:
        records: list[ZoneRecord] = []
        open_fn = gzip.open if path.endswith(".gz") else open
        with open_fn(path, "rt", encoding="utf-8", errors="ignore") as f:  # type: ignore
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Geomys entries may have leaf DNS names under various keys
                hostnames: list[str] = []
                if isinstance(obj, dict):
                    for key in ("dns_names", "names", "hostnames", "subdomains"):
                        val = obj.get(key)
                        if isinstance(val, list):
                            for h in val:
                                if isinstance(h, str):
                                    hostnames.append(h.strip().lower().rstrip("."))
                            break
                    # Fallback single host
                    if not hostnames and isinstance(obj.get("hostname"), str):
                        hostnames.append(obj["hostname"].strip().lower().rstrip("."))
                for h in hostnames:
                    if h and "." in h:
                        records.append(ZoneRecord(apex=h, hostname=h, first_seen=None))
        return records

    def replay_and_store(self, path: str) -> int:
        from ctlogs.ingest.benchmark import _batch_upsert
        from datetime import UTC, datetime

        records = self.parse_file(path)
        if not records:
            return 0
        apex_c, host_c = _batch_upsert(self.database, records)
        self.database.record_ingest_run(
            f"geomys:{path}",
            datetime.now(UTC).isoformat(),
            datetime.now(UTC).isoformat(),
            apex_c,
            host_c,
            None,
            len(records),
        )
        return host_c
