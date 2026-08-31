from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ctlogs.control import ControlDatabase
from ctlogs.database import Database, QuotaExceeded
from ctlogs.enrichment_worker import (
    run_one as run_one_enrichment,
    run_priority_batch,
)
from ctlogs.ingest.enrich import (
    SourcePage,
    URLSCAN_BREADTH_QUOTA_SUBJECT,
    URLSCAN_PRIORITY_QUOTA_SUBJECT,
    URLSCAN_TOTAL_QUOTA_SUBJECT,
)
from ctlogs.scheduler import (
    ScheduledJob,
    _run_ct_history_batch,
    _run_urlscan_apex,
    _run_urlscan_batch,
    _run_urlscan_index_batch,
    _singleton_lock,
    build_jobs,
    run_due_jobs,
)


def _control(tmp_path: Path) -> ControlDatabase:
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()
    return control


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

    def run_one(
        _database,
        _source,
        apexes,
        *,
        max_requests,
        refresh,
        persist_state,
        request_guard,
    ):
        assert max_requests == 1
        assert refresh is False
        assert persist_state is True
        visited.extend(apexes)
        return 1, 1

    monkeypatch.setattr("ctlogs.scheduler.run_source", run_one)
    source = type("Source", (), {"name": "urlscan"})()
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


def test_composite_enrichment_imports_only_local_zone_and_passive_history(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    control = _control(tmp_path)
    zone_directory = tmp_path / "czds"
    zone_directory.mkdir()
    zone_path = zone_directory / "ac.zw.zone.gz"
    zone_path.write_bytes(b"nust 3600 IN NS ns1.example.\n")
    fingerprint = f"stat-v1:{zone_path.stat().st_size}:{zone_path.stat().st_mtime_ns}"
    admission = control.enqueue_enrichment(
        "test",
        10,
        "nust.ac.zw",
        "ac.zw",
        artifact_name="ac.zw.zone.gz",
        artifact_fingerprint=fingerprint,
        include_urlscan=True,
        idempotency_key="both",
        max_pending=4,
        max_pending_per_subject=2,
        now=datetime(2026, 8, 31, tzinfo=UTC),
    )
    calls: list[tuple[str, str | None]] = []

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            calls.append((apex, cursor))
            return SourcePage([("mail.nust.ac.zw", "2026-08-31T00:00:00Z")], None, 1)

    outcome = run_one_enrichment(
        database,
        control,
        zone_directory=zone_directory,
        max_zone_bytes=1024,
        urlscan_source=Source(),  # type: ignore[arg-type]
        worker_id="test-scheduler",
    )

    assert outcome["state"] == "done"
    job = control.enrichment_job(admission.job.job_id)
    assert job is not None
    assert job.zone_state == "complete"
    assert job.urlscan_state == "complete"
    assert calls == [("nust.ac.zw", None)]
    assert [row.subdomain for row in database.search("nust.ac.zw")] == [
        "mail.nust.ac.zw",
        "nust.ac.zw",
    ]
    assert control.queued_refreshes(1) == []


def test_incomplete_on_demand_urlscan_returns_to_the_normal_priority_queue(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    control = _control(tmp_path)
    admission = control.enqueue_enrichment(
        "test",
        10,
        "nust.ac.zw",
        "ac.zw",
        include_urlscan=True,
        idempotency_key="urlscan-only",
        max_pending=4,
        max_pending_per_subject=2,
        now=datetime(2026, 8, 31, tzinfo=UTC),
    )

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            assert apex == "nust.ac.zw"
            assert cursor is None
            return SourcePage([("mail.nust.ac.zw", None)], "older-page", 1)

    outcome = run_one_enrichment(
        database,
        control,
        zone_directory=tmp_path / "czds",
        max_zone_bytes=1024,
        urlscan_source=Source(),  # type: ignore[arg-type]
        worker_id="test-scheduler",
    )

    assert outcome["state"] == "partial"
    job = control.enrichment_job(admission.job.job_id)
    assert job is not None
    assert job.zone_state == "not_requested"
    assert job.urlscan_state == "checkpointed"
    assert control.queued_refreshes(1) == ["nust.ac.zw"]
    assert database.get_ingest_state("enrich:urlscan:nust.ac.zw")["cursor"] == (
        "older-page"
    )


def test_priority_batch_does_not_repeat_an_apex_just_advanced_on_demand(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    control = _control(tmp_path)
    for apex in ("one.example", "two.example", "three.example"):
        control.enqueue_refresh(apex)
    calls: list[str] = []

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            calls.append(apex)
            return SourcePage([], None, 1)

    assert run_priority_batch(  # type: ignore[arg-type]
        database,
        control,
        Source(),
        apexes_per_run=2,
        exclude_apexes={"one.example"},
    ) == (2, 0)
    assert calls == ["two.example", "three.example"]
    assert control.queued_refreshes(1) == ["one.example"]


def test_changed_zone_artifact_fails_closed_without_importing(tmp_path: Path) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    control = _control(tmp_path)
    zone_directory = tmp_path / "czds"
    zone_directory.mkdir()
    zone_path = zone_directory / "ac.zw.zone.gz"
    zone_path.write_bytes(b"nust 3600 IN NS ns1.example.\n")
    stale_fingerprint = (
        f"stat-v1:{zone_path.stat().st_size}:{zone_path.stat().st_mtime_ns}"
    )
    admission = control.enqueue_enrichment(
        "test",
        10,
        "nust.ac.zw",
        "ac.zw",
        artifact_name="ac.zw.zone.gz",
        artifact_fingerprint=stale_fingerprint,
        include_urlscan=False,
        idempotency_key="changed",
        max_pending=4,
        max_pending_per_subject=2,
        now=datetime(2026, 8, 31, tzinfo=UTC),
    )
    zone_path.write_bytes(b"changed content")

    outcome = run_one_enrichment(
        database,
        control,
        zone_directory=zone_directory,
        max_zone_bytes=1024,
        urlscan_source=None,
        worker_id="test-scheduler",
    )

    assert outcome["state"] == "failed"
    job = control.enrichment_job(admission.job.job_id)
    assert job is not None
    assert job.zone_state == "failed"
    assert database.search("nust.ac.zw") == []


def test_urlscan_all_apexes_uses_a_persistent_index_cursor(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    for apex in ("one.example", "three.example", "two.example"):
        database.upsert_subdomains(apex, [(apex, None)])
    visited: list[str] = []

    def run_one(
        _database,
        _source,
        apexes,
        *,
        max_requests,
        refresh,
        persist_state,
        request_guard,
    ):
        assert max_requests == 1
        assert refresh is False
        assert persist_state is True
        visited.extend(apexes)
        return 1, 1

    monkeypatch.setattr("ctlogs.scheduler.run_source", run_one)
    source = type("Source", (), {"name": "urlscan"})()

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

    def run_one(
        _database,
        _source,
        apexes,
        *,
        max_requests,
        refresh,
        persist_state,
        request_guard,
    ):
        apex = apexes[0]
        attempts.append(apex)
        if apex == "two.example" and attempts.count(apex) == 1:
            raise RuntimeError("temporary failure")
        return 1, 1

    monkeypatch.setattr("ctlogs.scheduler.run_source", run_one)
    source = type("Source", (), {"name": "urlscan"})()

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


def test_urlscan_apex_resumes_older_pages_then_refreshes_without_resetting(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    cursors: list[str | None] = []

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            cursors.append(cursor)
            if cursor == "older-page":
                return SourcePage(
                    [(f"old.{apex}", "2020-01-01T00:00:00Z")],
                    None,
                    1,
                )
            return SourcePage(
                [(f"new.{apex}", "2026-01-01T00:00:00Z")],
                "older-page",
                1,
            )

    source = Source()
    assert _run_urlscan_apex(  # type: ignore[arg-type]
        database, source, "example.com"
    ) == (1, 1)
    state = database.get_ingest_state("enrich:urlscan:example.com")
    assert state["cursor"] == "older-page"

    assert _run_urlscan_apex(  # type: ignore[arg-type]
        database, source, "example.com"
    ) == (1, 1)
    state = database.get_ingest_state("enrich:urlscan:example.com")
    assert state["cursor"] == "complete"

    assert _run_urlscan_apex(  # type: ignore[arg-type]
        database, source, "example.com"
    ) == (1, 1)
    state = database.get_ingest_state("enrich:urlscan:example.com")
    assert state["cursor"] == "complete"
    assert cursors == [None, "older-page", None]
    assert [row.subdomain for row in database.search("example.com")] == [
        "old.example.com",
        "new.example.com",
    ]


def test_priority_urlscan_queue_advances_history_until_complete(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    control = _control(tmp_path)
    control.admit("test", 10, "example.com")
    cursors: list[str | None] = []

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            cursors.append(cursor)
            if cursor == "older-page":
                return SourcePage(
                    [(f"old.{apex}", "2020-01-01T00:00:00Z")],
                    None,
                    1,
                )
            return SourcePage(
                [(f"new.{apex}", "2026-01-01T00:00:00Z")],
                "older-page",
                1,
            )

    source = Source()
    assert run_priority_batch(  # type: ignore[arg-type]
        database,
        control,
        source,
        apexes_per_run=1,
    ) == (1, 1)
    assert control.queued_refreshes(1) == ["example.com"]

    assert run_priority_batch(  # type: ignore[arg-type]
        database,
        control,
        source,
        apexes_per_run=1,
    ) == (1, 1)
    assert control.queued_refreshes(1) == []
    assert cursors == [None, "older-page"]
    assert [row.subdomain for row in database.search("example.com")] == [
        "old.example.com",
        "new.example.com",
    ]


def test_priority_quota_exhaustion_keeps_the_queue_position(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    control = _control(tmp_path)
    control.admit(
        "one",
        10,
        "one.example",
        now=datetime(2026, 8, 24, 0, 0, tzinfo=UTC),
    )
    control.admit(
        "two",
        10,
        "two.example",
        now=datetime(2026, 8, 24, 0, 0, 1, tzinfo=UTC),
    )

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            raise AssertionError("provider must not be called after quota denial")

    database.consume_request("exhausted", 1)
    with pytest.raises(QuotaExceeded):
        run_priority_batch(  # type: ignore[arg-type]
            database,
            control,
            Source(),
            apexes_per_run=1,
            request_guard=lambda: database.consume_request("exhausted", 1),
        )

    assert control.queued_refreshes(2) == ["one.example", "two.example"]


def test_ct_history_scheduler_rotates_across_logs_with_separate_cursors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    calls: list[str] = []

    def run_one(_database, log_url, *, batch_size, max_batches):
        assert batch_size == 1024
        assert max_batches == 8
        calls.append(log_url)
        return 2, 3

    monkeypatch.setattr("ctlogs.scheduler.run_history", run_one)
    urls = ["https://c.example", "https://a.example", "https://b.example"]

    assert _run_ct_history_batch(
        database,
        urls,
        logs_per_run=2,
        batch_size=1024,
        max_batches_per_log=8,
    ) == (4, 6)
    assert _run_ct_history_batch(
        database,
        urls,
        logs_per_run=2,
        batch_size=1024,
        max_batches_per_log=8,
    ) == (2, 3)
    assert _run_ct_history_batch(
        database,
        urls,
        logs_per_run=2,
        batch_size=1024,
        max_batches_per_log=8,
    ) == (0, 0)
    assert calls == ["https://a.example", "https://b.example", "https://c.example"]


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
    monkeypatch.setenv("CTLOGS_CZDS_INTERVAL", "21600")
    monkeypatch.setenv("CTLOGS_CZDS_RETRY_INTERVAL", "600")
    czds_job = next(job for job in build_jobs(database) if job.name == "czds")
    assert czds_job.interval_seconds == 21600
    assert czds_job.retry_seconds == 600

    monkeypatch.setenv("CTLOGS_URLSCAN_APEXES", "*")
    monkeypatch.setenv("CTLOGS_URLSCAN_INTERVAL", "60")
    monkeypatch.setenv("CTLOGS_URLSCAN_RETRY_INTERVAL", "120")
    urlscan_job = build_jobs(database)[-1]
    assert urlscan_job.name == "urlscan"
    assert urlscan_job.interval_seconds == 60
    assert urlscan_job.retry_seconds == 120


def test_disabled_urlscan_ignores_unrelated_provider_configuration(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    monkeypatch.setenv("CTLOGS_SCHEDULE_URLSCAN", "0")
    monkeypatch.setenv("URLSCAN_API_KEY", "key")
    monkeypatch.setenv("CTLOGS_URLSCAN_APEXES", "not an apex")
    monkeypatch.delenv("CZDS_USERNAME", raising=False)
    monkeypatch.delenv("CZDS_PASSWORD", raising=False)

    assert [job.name for job in build_jobs(database)] == [
        "root",
        "gov",
    ]


def test_urlscan_accepts_a_quoted_wildcard_from_a_raw_env_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    monkeypatch.setenv("CTLOGS_SCHEDULE_DEFAULTS", "0")
    monkeypatch.setenv("CTLOGS_SCHEDULE_CZDS", "0")
    monkeypatch.setenv("URLSCAN_API_KEY", "key")
    monkeypatch.setenv("CTLOGS_URLSCAN_APEXES", "'*'")

    assert [job.name for job in build_jobs(database)] == ["urlscan"]


def test_ct_history_job_is_explicit_and_independent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    monkeypatch.setenv("CTLOGS_SCHEDULE_DEFAULTS", "0")
    monkeypatch.setenv("CTLOGS_SCHEDULE_CZDS", "0")
    monkeypatch.setenv("CTLOGS_SCHEDULE_URLSCAN", "0")
    monkeypatch.setenv("CTLOGS_SCHEDULE_CT_HISTORY", "1")
    monkeypatch.delenv("CZDS_USERNAME", raising=False)
    monkeypatch.delenv("CZDS_PASSWORD", raising=False)

    assert [job.name for job in build_jobs(database)] == [
        "ct-history",
    ]


def test_live_ct_job_is_explicit_and_runs_inside_the_writer_scheduler(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    monkeypatch.setenv("CTLOGS_SCHEDULE_DEFAULTS", "0")
    monkeypatch.setenv("CTLOGS_SCHEDULE_CZDS", "0")
    monkeypatch.setenv("CTLOGS_SCHEDULE_URLSCAN", "0")
    monkeypatch.setenv("CTLOGS_SCHEDULE_LIVE_CT", "1")
    monkeypatch.delenv("CZDS_USERNAME", raising=False)
    monkeypatch.delenv("CZDS_PASSWORD", raising=False)
    calls: list[tuple[int, int, int]] = []

    async def poll(_database, *, batch, initial_backfill, max_batches):
        calls.append((batch, initial_backfill, max_batches))
        return 7

    monkeypatch.setattr("ctlogs.scheduler.poll_once", poll)
    jobs = build_jobs(database)

    assert [job.name for job in jobs] == ["live-ct"]
    assert jobs[0].action() == 7
    assert calls == [(1024, 1024, 8)]


def test_singleton_lock_rejects_a_second_scheduler(tmp_path: Path) -> None:
    lock = tmp_path / "scheduler.lock"
    with _singleton_lock(lock):
        with pytest.raises(RuntimeError, match="already held"):
            with _singleton_lock(lock):
                pass


def test_urlscan_breadth_cannot_spend_priority_or_search_reserves(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    database.upsert_subdomains("example.com", [("example.com", None)])
    monkeypatch.setenv("CTLOGS_SCHEDULE_DEFAULTS", "0")
    monkeypatch.setenv("CTLOGS_SCHEDULE_CZDS", "0")
    monkeypatch.setenv("URLSCAN_API_KEY", "key")
    monkeypatch.setenv("CTLOGS_URLSCAN_APEXES", "*")
    monkeypatch.setenv("CTLOGS_URLSCAN_APEXES_PER_RUN", "1")
    monkeypatch.setenv("CTLOGS_URLSCAN_DAILY_LIMIT", "3")
    monkeypatch.setenv("CTLOGS_URLSCAN_SEARCH_DAILY_LIMIT", "1")
    monkeypatch.setenv("CTLOGS_URLSCAN_PRIORITY_DAILY_LIMIT", "1")
    calls: list[str] = []

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            calls.append(apex)
            return SourcePage([], None, 1)

    monkeypatch.setattr(
        "ctlogs.scheduler.UrlscanSource",
        lambda *_args, **_kwargs: Source(),
    )
    database.consume_partitioned_request(
        URLSCAN_TOTAL_QUOTA_SUBJECT,
        3,
        URLSCAN_BREADTH_QUOTA_SUBJECT,
        1,
    )
    jobs = {job.name: job for job in build_jobs(database)}

    with pytest.raises(QuotaExceeded, match="daily request limit exceeded"):
        jobs["urlscan"].action()
    assert calls == []


def test_priority_history_still_runs_after_breadth_budget_is_exhausted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "scheduler.sqlite3")
    database.initialize()
    database.upsert_subdomains("breadth.example", [("breadth.example", None)])
    control = _control(tmp_path)
    control.admit("test", 10, "priority.example")
    monkeypatch.setenv("CTLOGS_SCHEDULE_DEFAULTS", "0")
    monkeypatch.setenv("CTLOGS_SCHEDULE_CZDS", "0")
    monkeypatch.setenv("URLSCAN_API_KEY", "key")
    monkeypatch.setenv("CTLOGS_URLSCAN_APEXES", "*")
    monkeypatch.setenv("CTLOGS_URLSCAN_APEXES_PER_RUN", "1")
    monkeypatch.setenv("CTLOGS_URLSCAN_PRIORITY_APEXES_PER_RUN", "1")
    monkeypatch.setenv("CTLOGS_URLSCAN_DAILY_LIMIT", "3")
    monkeypatch.setenv("CTLOGS_URLSCAN_SEARCH_DAILY_LIMIT", "1")
    monkeypatch.setenv("CTLOGS_URLSCAN_PRIORITY_DAILY_LIMIT", "1")
    calls: list[str] = []

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            calls.append(apex)
            return SourcePage([], None, 1)

    monkeypatch.setattr(
        "ctlogs.scheduler.UrlscanSource",
        lambda *_args, **_kwargs: Source(),
    )
    database.consume_partitioned_request(
        URLSCAN_TOTAL_QUOTA_SUBJECT,
        3,
        URLSCAN_BREADTH_QUOTA_SUBJECT,
        1,
    )
    jobs = {job.name: job for job in build_jobs(database)}

    assert run_priority_batch(  # type: ignore[arg-type]
        database,
        control,
        Source(),
        apexes_per_run=1,
        request_guard=lambda: database.consume_partitioned_request(
            URLSCAN_TOTAL_QUOTA_SUBJECT,
            3,
            URLSCAN_PRIORITY_QUOTA_SUBJECT,
            1,
        ),
    ) == (1, 0)
    with pytest.raises(QuotaExceeded):
        jobs["urlscan"].action()
    assert calls == ["priority.example"]
