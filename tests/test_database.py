from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
import sqlite3

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


def test_provenance_tracks_each_source_without_duplicating_search_rows(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "provenance.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "example.com",
        [("www.example.com", "2025-01-02T00:00:00Z")],
        source="source-a",
        observed_at="2026-08-21T00:00:00Z",
    )
    database.upsert_subdomains(
        "example.com",
        [("www.example.com", "2024-01-02T00:00:00Z")],
        source="source-b",
        observed_at="2026-08-22T00:00:00Z",
    )

    rows = database.search("example.com")
    assert len(rows) == 1
    assert rows[0].first_seen == "2024-01-02T00:00:00Z"
    with database.connect() as connection:
        sources = connection.execute(
            """
            SELECT source, first_seen, last_seen
            FROM subdomain_sources
            ORDER BY source
            """
        ).fetchall()
    assert [tuple(row) for row in sources] == [
        ("source-a", "2025-01-02T00:00:00Z", "2026-08-21T00:00:00Z"),
        ("source-b", "2024-01-02T00:00:00Z", "2026-08-22T00:00:00Z"),
    ]


def test_stats_report_index_and_provenance_counts(tmp_path: Path) -> None:
    database = Database(tmp_path / "stats.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "example.com",
        [("example.com", None), ("www.example.com", "2025-01-01T00:00:00Z")],
        source="fixture",
    )

    stats = database.stats()

    assert stats.apex_count == 1
    assert stats.hostname_count == 2
    assert stats.dated_hostname_count == 1
    assert stats.source_count == 1
    assert stats.ct_hostname_count == 0
    assert stats.ct_log_count == 0
    assert stats.last_ingest_at is None

    database.upsert_subdomains(
        "example.com",
        [("example.com", "2024-01-01T00:00:00Z")],
        source="fixture",
    )
    assert database.stats().dated_hostname_count == 2


def test_stats_materialize_unique_ct_names_and_logs(tmp_path: Path) -> None:
    database = Database(tmp_path / "ct-stats.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "example.com",
        [("one.example.com", None), ("two.example.com", None)],
        source="direct_ct:https://log-one.example",
    )
    database.upsert_subdomains(
        "example.com",
        [("one.example.com", None)],
        source="static_ct:https://log-two.example",
    )
    database.upsert_subdomains(
        "example.com",
        [("three.example.com", None)],
        source="commoncrawl",
    )

    stats = database.stats()
    assert stats.ct_hostname_count == 2
    assert stats.ct_log_count == 2

    with database.connect() as connection:
        connection.execute(
            "DELETE FROM subdomain_sources WHERE source = ?",
            ("direct_ct:https://log-one.example",),
        )

    stats = database.stats()
    assert stats.ct_hostname_count == 1
    assert stats.ct_log_count == 1


def test_initialize_builds_totals_for_an_existing_database(tmp_path: Path) -> None:
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TABLE subdomains (
                apex TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                first_seen TEXT,
                PRIMARY KEY (apex, subdomain)
            ) WITHOUT ROWID
            """
        )
        connection.executemany(
            "INSERT INTO subdomains VALUES (?, ?, ?)",
            [
                ("example.com", "example.com", None),
                ("example.com", "www.example.com", "2025-01-01T00:00:00Z"),
                ("example.net", "example.net", None),
            ],
        )

    database = Database(path)
    database.initialize()

    stats = database.stats()
    assert stats.apex_count == 2
    assert stats.hostname_count == 3
    assert stats.dated_hostname_count == 1
    assert stats.ct_hostname_count == 0
    assert stats.ct_log_count == 0
