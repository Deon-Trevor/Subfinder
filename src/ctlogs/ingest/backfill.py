from __future__ import annotations

import argparse
import hashlib
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from ctlogs.database import Database
from ctlogs.ingest.benchmark import _batch_upsert
from ctlogs.ingest.chaos import ChaosAdapter
from ctlogs.ingest.commoncrawl import CommonCrawlAdapter
from ctlogs.ingest.gov import GovAdapter
from ctlogs.ingest.hagezi import HageziAdapter
from ctlogs.ingest.rootzone import RootZoneAdapter
from ctlogs.ingest.ee_se_nu import EeSeNuAdapter

DEFAULT_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_JOBS = (
    ("root", "https://www.internic.net/domain/root.zone"),
    (
        "gov",
        "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-full.csv",
    ),
)


def _adapter(source: str):
    if source == "root":
        return RootZoneAdapter()
    if source == "gov":
        return GovAdapter()
    if source == "chaos":
        return ChaosAdapter()
    if source == "hagezi":
        return HageziAdapter()
    if source == "commoncrawl":
        return CommonCrawlAdapter()
    if source in {"ee", "se", "nu"}:
        return EeSeNuAdapter(source)
    raise ValueError(f"unsupported global source: {source}")


def _read_bounded(response, max_bytes: int) -> bytes:
    length = response.headers.get("Content-Length")
    if length is not None and int(length) > max_bytes:
        raise ValueError(f"artifact exceeds {max_bytes} bytes")
    data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"artifact exceeds {max_bytes} bytes")
    return data


def _fetch(
    location: str,
    *,
    etag: str | None,
    timeout: int,
    max_bytes: int,
) -> tuple[bytes | None, str | None]:
    if location.startswith(("https://", "http://")):
        headers = {"User-Agent": "ctlogs/1.0"}
        if etag:
            headers["If-None-Match"] = etag
        request = urllib.request.Request(location, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return _read_bounded(response, max_bytes), response.headers.get("ETag")
        except urllib.error.HTTPError as error:
            if error.code == 304:
                return None, etag
            raise

    path = Path(location)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"artifact exceeds {max_bytes} bytes")
    return path.read_bytes(), None


def run_job(
    database: Database,
    source: str,
    location: str,
    *,
    timeout: int = 60,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> int:
    adapter = _adapter(source)
    state_key = f"bulk:{source}:{location}"
    state = database.get_ingest_state(state_key)
    data, response_etag = _fetch(
        location,
        etag=state.get("etag") if state else None,
        timeout=timeout,
        max_bytes=max_bytes,
    )
    if data is None:
        return 0

    digest = hashlib.sha256(data).hexdigest()
    if state and state.get("cursor") == digest:
        return 0

    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    records = adapter.parse(data)
    apex_count, hostname_count = _batch_upsert(
        database,
        records,
        source=source,
    )
    finished_at = datetime.now(UTC).isoformat()
    database.record_ingest_run(
        source,
        started_at,
        finished_at,
        apex_count,
        hostname_count,
        int((time.monotonic() - started) * 1000),
        len(data),
    )
    database.upsert_ingest_state(
        state_key,
        cursor=digest,
        etag=response_etag,
        updated_at=finished_at,
    )
    return hostname_count


def _parse_job(value: str) -> tuple[str, str]:
    source, separator, location = value.partition("=")
    if not separator or not source or not location:
        raise argparse.ArgumentTypeError("job must be SOURCE=PATH_OR_URL")
    return source, location


def main() -> None:
    parser = argparse.ArgumentParser(description="Import global hostname artifacts")
    parser.add_argument("--db", default="data/ctlogs.sqlite3")
    parser.add_argument(
        "--job",
        action="append",
        type=_parse_job,
        metavar="SOURCE=PATH_OR_URL",
    )
    parser.add_argument(
        "--defaults",
        action="store_true",
        help="import the maintained IANA root and CISA .gov artifacts",
    )
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    args = parser.parse_args()

    if args.timeout < 1 or args.max_bytes < 1:
        parser.error("timeout and max-bytes must be positive")
    jobs = [*(DEFAULT_JOBS if args.defaults else ()), *(args.job or ())]
    if not jobs:
        parser.error("at least one --job or --defaults is required")

    database = Database(args.db)
    database.initialize()
    for source, location in jobs:
        count = run_job(
            database,
            source,
            location,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
        )
        print(f"{source}: {count} hostnames")


if __name__ == "__main__":
    main()
