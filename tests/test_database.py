from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from multiprocessing import get_context
from pathlib import Path
from typing import Any

import pytest

from ctlogs.database import (
    BatchResultTooLarge,
    Database,
    IndexedRecord,
    QuotaExceeded,
    SearchCursor,
    SourceObservation,
)


def _hold_writer(path: str, entered: Any, release: Any) -> None:
    with Database(path).write_transaction():
        entered.set()
        if not release.wait(timeout=5):
            raise TimeoutError("writer release was not signalled")


def _enter_writer(path: str, entered: Any) -> None:
    with Database(path).write_transaction():
        entered.set()


def test_write_transactions_serialize_service_processes(tmp_path: Path) -> None:
    path = tmp_path / "serialized.sqlite3"
    Database(path).initialize()
    processes = get_context("spawn")
    first_entered = processes.Event()
    release_first = processes.Event()
    second_entered = processes.Event()
    first_process = processes.Process(
        target=_hold_writer,
        args=(str(path), first_entered, release_first),
    )
    second_process = processes.Process(
        target=_enter_writer,
        args=(str(path), second_entered),
    )
    first_process.start()
    assert first_entered.wait(timeout=2)
    second_process.start()

    assert not second_entered.wait(timeout=0.1)
    release_first.set()
    first_process.join(timeout=5)
    second_process.join(timeout=5)

    assert first_process.exitcode == 0
    assert second_process.exitcode == 0
    assert second_entered.is_set()


def test_write_transaction_releases_lock_after_failure(tmp_path: Path) -> None:
    path = tmp_path / "failed-write.sqlite3"
    first = Database(path)
    second = Database(path)
    first.initialize()

    with pytest.raises(RuntimeError, match="failed mutation"):
        with first.write_transaction():
            raise RuntimeError("failed mutation")

    with second.write_transaction() as connection:
        connection.execute(
            "INSERT INTO ingest_state (source, cursor) VALUES ('test', 'ok')"
        )

    assert second.get_ingest_state("test")["cursor"] == "ok"


def test_read_connections_reject_mutations(tmp_path: Path) -> None:
    database = Database(tmp_path / "read-only.sqlite3")
    database.initialize()

    with database.connect() as connection:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            connection.execute(
                "INSERT INTO ingest_state (source, cursor) VALUES ('test', 'bad')"
            )


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


def test_search_pages_preserve_order_without_duplicates(tmp_path: Path) -> None:
    database = Database(tmp_path / "page.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "example.com",
        [
            ("a.example.com", "2025-01-01T00:00:00Z"),
            ("b.example.com", "2025-01-01T00:00:00Z"),
            ("c.example.com", "2026-01-01T00:00:00Z"),
            ("z.example.com", None),
        ],
    )

    first, cursor = database.search_page("example.com", after=None, limit=2)
    assert [row.subdomain for row in first] == ["a.example.com", "b.example.com"]
    assert cursor == SearchCursor("b.example.com", "2025-01-01T00:00:00Z")

    second, cursor = database.search_page("example.com", after=cursor, limit=2)
    assert [row.subdomain for row in second] == ["c.example.com", "z.example.com"]
    assert cursor is None


def test_read_only_database_rejects_writes_and_verifies_schema(tmp_path: Path) -> None:
    path = tmp_path / "catalog.sqlite3"
    writable = Database(path)
    writable.initialize()
    writable.upsert_subdomains("example.com", [("example.com", None)])

    read_only = Database(path, read_only=True)
    read_only.verify_schema()
    assert [row.subdomain for row in read_only.search("example.com")] == [
        "example.com"
    ]
    with pytest.raises(RuntimeError, match="read-only"):
        read_only.upsert_subdomains("example.com", [("www.example.com", None)])


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


def test_search_counts_are_index_scoped(tmp_path: Path) -> None:
    database = Database(tmp_path / "counts.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "example.com",
        [("dated.example.com", "2026-01-01T00:00:00Z"), ("unknown.example.com", None)],
    )
    database.upsert_subdomains("example.net", [("example.net", None)])

    assert database.search_counts("example.com") == (2, 1)

    page, cursor, total, dated = database.search_page_with_counts(
        "example.com", after=None, limit=1
    )
    assert [row.subdomain for row in page] == ["dated.example.com"]
    assert cursor == SearchCursor("dated.example.com", "2026-01-01T00:00:00Z")
    assert (total, dated) == (2, 1)


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


def test_records_return_neutral_hostname_provenance(tmp_path: Path) -> None:
    database = Database(tmp_path / "records.sqlite3")
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

    assert database.records("example.com") == [
        IndexedRecord(
            hostname="www.example.com",
            first_seen="2024-01-02T00:00:00Z",
            sources=(
                SourceObservation(
                    source="direct_ct:https://ct.example",
                    first_seen="2025-01-02T00:00:00Z",
                    last_seen="2026-08-21T00:00:00Z",
                ),
                SourceObservation(
                    source="urlscan",
                    first_seen="2024-01-02T00:00:00Z",
                    last_seen="2026-08-22T00:00:00Z",
                ),
            ),
        )
    ]


def test_records_many_uses_one_bounded_snapshot_in_request_order(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "batch-records.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "example.com",
        [("www.example.com", "2025-02-03T04:05:06Z")],
        source="direct_ct:https://ct.example",
        observed_at="2026-08-21T00:00:00Z",
    )
    database.upsert_subdomains("example.net", [("example.net", None)])

    result = database.records_many(
        ["example.net", "missing.example", "example.com"],
        max_records=2,
    )

    assert list(result) == ["example.net", "missing.example", "example.com"]
    assert [record.hostname for record in result["example.net"]] == ["example.net"]
    assert result["missing.example"] == []
    assert result["example.com"] == [
        IndexedRecord(
            "www.example.com",
            "2025-02-03T04:05:06Z",
            (
                SourceObservation(
                    "direct_ct:https://ct.example",
                    "2025-02-03T04:05:06Z",
                    "2026-08-21T00:00:00Z",
                ),
            ),
        )
    ]

    with pytest.raises(BatchResultTooLarge) as failure:
        database.records_many(
            ["example.net", "example.com"],
            max_records=1,
        )
    assert failure.value.total == 2
    assert failure.value.limit == 1


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
    assert stats.source_count == 3

    with database.write_transaction() as connection:
        connection.execute(
            "DELETE FROM subdomain_sources WHERE source = ?",
            ("direct_ct:https://log-one.example",),
        )

    stats = database.stats()
    assert stats.ct_hostname_count == 1
    assert stats.ct_log_count == 1
    assert stats.source_count == 2


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
