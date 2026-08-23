from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ctlogs.database import Database
from ctlogs.scheduler import (
    ScheduledJob,
    _run_urlscan_batch,
    _run_urlscan_index_batch,
    _singleton_lock,
    build_jobs,
    run_due_jobs,
)


def test_due_jobs_persist_success_and_retry_times(tmp_path: Path) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    calls: list[str] = []

    def fail() -> None:
        calls.append("fail")
        raise RuntimeError("offline")

    jobs = [
        ScheduledJob("good", 3600, 60, lambda: calls.append("good")),
        ScheduledJob("bad", 3600, 60, fail),
    ]
    now = datetime(2026, 8, 23, tzinfo=UTC)

    assert run_due_jobs(database, jobs, now=now) == {
        "good": "ok",
        "bad": "error:RuntimeError",
    }
    assert calls == ["good", "fail"]
    assert run_due_jobs(database, jobs, now=now + timedelta(seconds=30)) == {}
    assert run_due_jobs(database, jobs, now=now + timedelta(seconds=61)) == {
        "bad": "error:RuntimeError"
    }


def test_urlscan_budget_rotates_without_starving_later_apexes(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    visited: list[str] = []

    def run_one(_database, _source, apexes, *, max_requests, refresh):
        assert max_requests == 1
        assert refresh is True
        visited.extend(apexes)
        return 1, 1

    monkeypatch.setattr("ctlogs.scheduler.run_source", run_one)
    source = object()
    apexes = ["one.example", "two.example", "three.example"]

    assert _run_urlscan_batch(  # type: ignore[arg-type]
        database, source, apexes, apexes_per_run=2
    ) == (2, 2)
    assert _run_urlscan_batch(  # type: ignore[arg-type]
        database, source, apexes, apexes_per_run=2
    ) == (2, 2)
    assert visited == [
        "one.example",
        "two.example",
        "three.example",
        "one.example",
    ]


def test_urlscan_all_apexes_uses_a_persistent_index_cursor(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    for apex in ("one.example", "three.example", "two.example"):
        database.upsert_subdomains(apex, [(apex, None)])
    visited: list[str] = []

    def run_one(_database, _source, apexes, *, max_requests, refresh):
        assert max_requests == 1
        assert refresh is True
        visited.extend(apexes)
        return 1, 1

    monkeypatch.setattr("ctlogs.scheduler.run_source", run_one)
    source = object()

    assert _run_urlscan_index_batch(  # type: ignore[arg-type]
        database, source, apexes_per_run=2
    ) == (2, 2)
    assert _run_urlscan_index_batch(  # type: ignore[arg-type]
        database, source, apexes_per_run=2
    ) == (1, 1)
    assert visited == ["one.example", "three.example", "two.example"]


def test_urlscan_all_apexes_does_not_advance_past_a_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    for apex in ("one.example", "two.example"):
        database.upsert_subdomains(apex, [(apex, None)])
    attempts: list[str] = []

    def run_one(_database, _source, apexes, *, max_requests, refresh):
        apex = apexes[0]
        attempts.append(apex)
        if apex == "two.example" and attempts.count(apex) == 1:
            raise RuntimeError("temporary failure")
        return 1, 1

    monkeypatch.setattr("ctlogs.scheduler.run_source", run_one)
    source = object()

    with pytest.raises(RuntimeError, match="temporary failure"):
        _run_urlscan_index_batch(  # type: ignore[arg-type]
            database, source, apexes_per_run=2
        )
    assert database.get_ingest_state("scheduler:urlscan:index-cursor")["cursor"] == (
        "one.example"
    )
    assert _run_urlscan_index_batch(  # type: ignore[arg-type]
        database, source, apexes_per_run=2
    ) == (1, 1)
    assert attempts == ["one.example", "two.example", "two.example"]


def test_build_jobs_keeps_each_capped_source_on_its_own_budget(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    for name in (
        "CZDS_USERNAME",
        "CZDS_PASSWORD",
        "URLSCAN_API_KEY",
        "CTLOGS_URLSCAN_APEXES",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(
        "CTLOGS_SCHEDULED_ARTIFACTS",
        '["hagezi=https://data.example/hosts.txt"]',
    )

    assert [job.name for job in build_jobs(database)] == [
        "root",
        "gov",
        "artifact:hagezi:bf2fe8a0d413",
    ]

    monkeypatch.setenv("CZDS_USERNAME", "user")
    monkeypatch.setenv("CZDS_PASSWORD", "password")
    monkeypatch.setenv("URLSCAN_API_KEY", "key")
    monkeypatch.setenv("CTLOGS_URLSCAN_APEXES", "one.example,two.example")

    assert [job.name for job in build_jobs(database)] == [
        "root",
        "gov",
        "artifact:hagezi:bf2fe8a0d413",
        "czds",
        "urlscan",
    ]

    monkeypatch.setenv("CTLOGS_URLSCAN_APEXES", "*")
    monkeypatch.setenv("CTLOGS_URLSCAN_INTERVAL", "60")
    monkeypatch.setenv("CTLOGS_URLSCAN_RETRY_INTERVAL", "120")
    urlscan_job = build_jobs(database)[-1]
    assert urlscan_job.name == "urlscan"
    assert urlscan_job.interval_seconds == 60
    assert urlscan_job.retry_seconds == 120


def test_singleton_lock_rejects_a_second_scheduler(tmp_path: Path) -> None:
    lock = tmp_path / "scheduler.lock"
    with _singleton_lock(lock):
        with pytest.raises(RuntimeError, match="already held"):
            with _singleton_lock(lock):
                pass
