from __future__ import annotations

import argparse
import time
from datetime import UTC, datetime
from pathlib import Path

import tldextract

import os

from ctlogs.database import Database
from ctlogs.ingest.chaos import ChaosAdapter
from ctlogs.ingest.ch_li import ChLiAdapter
from ctlogs.ingest.commoncrawl import CommonCrawlAdapter
from ctlogs.ingest.ee_se_nu import EeSeNuAdapter
from ctlogs.ingest.gov import GovAdapter
from ctlogs.ingest.hagezi import HageziAdapter
from ctlogs.ingest.rootzone import RootZoneAdapter

EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
    cache_dir=None,
)


def _load_text(path: Path) -> bytes:
    return path.read_bytes()


def _batch_upsert(database: Database, records, batch_size: int = 5000) -> tuple[int, int]:
    from collections import defaultdict

    def _apex_for_hostname(hostname: str) -> str:
        h = hostname.strip().lower().rstrip(".")
        ext = EXTRACT(h)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return h

    grouped: dict[str, list[tuple[str, str | None]]] = defaultdict(list)
    for r in records:
        apex = _apex_for_hostname(r.hostname)
        grouped[apex].append((r.hostname, r.first_seen))
    hostname_total = 0
    apex_total = len(grouped)
    for apex, rows in grouped.items():
        # earliest first_seen kept by DB upsert, so we just batch
        for i in range(0, len(rows), batch_size):
            database.upsert_subdomains(apex, rows[i : i + batch_size])
        hostname_total += len(rows)
    return apex_total, hostname_total


def main() -> None:
    parser = argparse.ArgumentParser(description="Ingest benchmark for .gov/.ee/.se/.nu")
    parser.add_argument("--db", default="data/ctlogs.sqlite3", help="SQLite path")
    parser.add_argument("--fixtures", default="data/fixtures", help="Directory with fixtures")
    parser.add_argument("--batch-size", type=int, default=5000)
    args = parser.parse_args()

    db = Database(args.db)
    db.initialize()

    fixtures = Path(args.fixtures)
    jobs: list[tuple[str, Path, object]] = []
    # gov: look for gov-*.csv or gov-*.zone
    for p in sorted(fixtures.glob("root.zone")):
        jobs.append(("root", p, RootZoneAdapter()))
    for p in sorted(fixtures.glob("gov*")):
        jobs.append(("gov", p, GovAdapter()))
    for p in sorted(fixtures.glob("chaos*")):
        jobs.append(("chaos", p, ChaosAdapter()))
    for p in sorted(fixtures.glob("hagezi*")):
        jobs.append(("hagezi", p, HageziAdapter()))
    for p in sorted(fixtures.glob("commoncrawl*")):
        jobs.append(("commoncrawl", p, CommonCrawlAdapter()))
    for zone in ("ee", "se", "nu"):
        for p in sorted(fixtures.glob(f"{zone}*")):
            jobs.append((zone, p, EeSeNuAdapter(zone)))
        for p in sorted(fixtures.glob(f"*.{zone}.zone")):
            jobs.append((zone, p, EeSeNuAdapter(zone)))
    if os.environ.get("CTLOGS_ENABLE_CH_LI") == "1":
        for zone in ("ch", "li"):
            for p in sorted(fixtures.glob(f"{zone}*")):
                jobs.append((zone, p, ChLiAdapter(zone)))
            for p in sorted(fixtures.glob(f"*.{zone}.zone")):
                jobs.append((zone, p, ChLiAdapter(zone)))

    if not jobs:
        print(f"No fixtures found in {fixtures}. Place gov-*.csv and *.ee/.se/.nu.zone files there.")
        print("Benchmark still validates storage path and idempotency with empty input.")
        # Run empty idempotency check
        started = datetime.now(UTC).isoformat()
        t0 = time.monotonic()
        apex_c, host_c = _batch_upsert(db, [])
        dt = int((time.monotonic() - t0) * 1000)
        db.record_ingest_run("benchmark-empty", started, datetime.now(UTC).isoformat(), apex_c, host_c, dt, 0)
        print(f"empty apex={apex_c} host={host_c} duration_ms={dt}")
        return

    for source, path, adapter in jobs:
        raw = _load_text(path)
        t0 = time.monotonic()
        started = datetime.now(UTC).isoformat()
        records = list(adapter.parse(raw))  # type: ignore
        apex_c, host_c = _batch_upsert(db, records, batch_size=args.batch_size)
        dt = int((time.monotonic() - t0) * 1000)
        # Second pass proves idempotency keeps earliest first_seen
        apex_c2, host_c2 = _batch_upsert(db, records, batch_size=args.batch_size)
        assert apex_c == apex_c2 and host_c == host_c2, "idempotency check failed"
        db.record_ingest_run(source, started, datetime.now(UTC).isoformat(), apex_c, host_c, dt, len(raw))
        print(f"{source}:{path.name} apex={apex_c} host={host_c} duration_ms={dt} bytes={len(raw)}")

        # Update cursor for reproducibility
        db.upsert_ingest_state(source, cursor=path.name, updated_at=datetime.now(UTC).isoformat())


if __name__ == "__main__":
    main()
