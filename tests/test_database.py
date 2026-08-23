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


def test_apexes_after_pages_unique_apexes_in_index_order(tmp_path: Path) -> None:
    database = Database(tmp_path / "apexes.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "two.example",
        [("two.example", None), ("www.two.example", None)],
    )
    database.upsert_subdomains("one.example", [("one.example", None)])
    database.upsert_subdomains("three.example", [("three.example", None)])

    assert database.apexes_after("", 2) == ["one.example", "three.example"]
    assert database.apexes_after("three.example", 2) == ["two.example"]


def test_urlscan_history_queue_is_fifo_and_drops_completed_apexes(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "queue.sqlite3")
    database.initialize()
    database.enqueue_urlscan_history(
        "one.example",
        requested_at="2026-08-24T00:00:00Z",
    )
    database.enqueue_urlscan_history(
        "two.example",
        requested_at="2026-08-24T00:00:01Z",
    )
    database.enqueue_urlscan_history(
        "one.example",
        requested_at="2026-08-24T00:00:02Z",
    )

    assert database.queued_urlscan_history(2) == ["one.example", "two.example"]

    database.finish_urlscan_history_attempt(
        "one.example",
        attempted_at="2026-08-24T00:00:03Z",
    )
    assert database.queued_urlscan_history(2) == ["two.example", "one.example"]

    database.upsert_ingest_state(
        "enrich:urlscan:two.example",
        cursor="complete",
    )
    database.finish_urlscan_history_attempt("two.example")
    database.enqueue_urlscan_history("two.example")
    assert database.queued_urlscan_history(2) == ["one.example"]


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


def test_partitioned_quota_keeps_the_legacy_total_as_a_hard_ceiling(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "partitioned.sqlite3")
    database.initialize()
    now = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
    database.consume_request("provider:urlscan", 2, now)

    quota = database.consume_partitioned_request(
        "provider:urlscan",
        2,
        "provider:urlscan:priority",
        1,
        now,
    )
    assert quota.remaining == 0
    with pytest.raises(QuotaExceeded):
        database.consume_partitioned_request(
            "provider:urlscan",
            2,
            "provider:urlscan:search",
            1,
            now,
        )

    with database.connect() as connection:
        counts = connection.execute(
            """
            SELECT client_ip, used
            FROM request_counts
            WHERE day = ?
            ORDER BY client_ip
            """,
            (now.date().isoformat(),),
        ).fetchall()
    assert [tuple(row) for row in counts] == [
        ("provider:urlscan", 2),
        ("provider:urlscan:priority", 1),
    ]


def test_concurrent_partitioned_quotas_cannot_exceed_the_total(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "partitioned-concurrent.sqlite3")
    database.initialize()
    now = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)

    def consume(attempt: int) -> bool:
        try:
            database.consume_partitioned_request(
                "provider:urlscan",
                5,
                f"provider:urlscan:class-{attempt % 2}",
                5,
                now,
            )
            return True
        except QuotaExceeded:
            return False

    with ThreadPoolExecutor(max_workers=10) as executor:
        outcomes = list(executor.map(consume, range(20)))

    assert outcomes.count(True) == 5
    assert outcomes.count(False) == 15
    with database.connect() as connection:
        total = connection.execute(
            """
            SELECT used FROM request_counts
            WHERE day = ? AND client_ip = 'provider:urlscan'
            """,
            (now.date().isoformat(),),
        ).fetchone()
    assert total["used"] == 5


def test_sources_consolidate_without_duplicating_search_rows(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "provenance.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "example.com",
        [("www.example.com", "2025-01-02T00:00:00Z")],
        source="direct_ct:https://ct.example",
        observed_at="2026-08-21T00:00:00Z",
    )
    database.upsert_subdomains(
        "example.com",
        [("www.example.com", "2024-01-02T00:00:00Z")],
        source="urlscan",
        observed_at="2026-08-22T00:00:00Z",
    )
    database.upsert_subdomains(
        "example.com",
        [("www.example.com", None)],
        source="commoncrawl",
        observed_at="2026-08-23T00:00:00Z",
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
        ("commoncrawl", None, "2026-08-23T00:00:00Z"),
        (
            "direct_ct:https://ct.example",
            "2025-01-02T00:00:00Z",
            "2026-08-21T00:00:00Z",
        ),
        ("urlscan", "2024-01-02T00:00:00Z", "2026-08-22T00:00:00Z"),
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
