from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ctlogs.database import Database, QuotaExceeded


def test_upsert_keeps_the_earliest_first_seen(tmp_path: Path) -> None:
    database = Database(tmp_path / "data.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "example.com",
        [("www.example.com", "2025-03-01T00:00:00Z")],
    )
    database.upsert_subdomains(
        "example.com",
        [("www.example.com", "2024-03-01T00:00:00Z")],
    )

    assert database.search("example.com")[0].first_seen == "2024-03-01T00:00:00Z"


def test_quota_resets_on_the_next_utc_day(tmp_path: Path) -> None:
    database = Database(tmp_path / "quota.sqlite3")
    database.initialize()
    first_day = datetime(2026, 8, 21, 23, 59, tzinfo=UTC)
    next_day = datetime(2026, 8, 22, 0, 0, tzinfo=UTC)

    assert database.consume_request("192.0.2.1", 1, first_day).remaining == 0
    with pytest.raises(QuotaExceeded):
        database.consume_request("192.0.2.1", 1, first_day)
    assert database.consume_request("192.0.2.1", 1, next_day).remaining == 0


def test_concurrent_quota_consumers_cannot_exceed_the_limit(tmp_path: Path) -> None:
    database = Database(tmp_path / "concurrent.sqlite3")
    database.initialize()
    now = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

    def consume(_attempt: int) -> bool:
        try:
            database.consume_request("192.0.2.2", 5, now)
            return True
        except QuotaExceeded:
            return False

    with ThreadPoolExecutor(max_workers=10) as executor:
        outcomes = list(executor.map(consume, range(20)))

    assert outcomes.count(True) == 5
    assert outcomes.count(False) == 15
