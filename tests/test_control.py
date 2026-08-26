from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ctlogs.control import (
    Admission,
    AdmissionRequest,
    ControlDatabase,
    ControlUnavailable,
)
from ctlogs.database import QuotaExceeded


def test_admission_atomically_counts_and_coalesces_refreshes(tmp_path: Path) -> None:
    control = ControlDatabase(tmp_path / "control.sqlite3")
    control.initialize()
    now = datetime(2026, 8, 26, tzinfo=UTC)

    first = control.admit("198.51.100.1", 2, "example.com", now=now)
    second = control.admit("198.51.100.1", 2, "example.com", now=now)

    assert first.quota.remaining == 1
    assert first.refresh_status == "queued"
    assert second.quota.remaining == 0
    assert second.refresh_status == "already-pending"
    assert control.queued_refreshes(10) == ["example.com"]
    with pytest.raises(QuotaExceeded):
        control.admit("198.51.100.1", 2, "other.example", now=now)
    assert control.queued_refreshes(10) == ["example.com"]


def test_admission_is_atomic_across_threads(tmp_path: Path) -> None:
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()
    now = datetime(2026, 8, 26, tzinfo=UTC)

    def consume(index: int) -> bool:
        try:
            control.admit(
                "203.0.113.8",
                20,
                f"d{index}.example",
                enqueue_refresh=False,
                now=now,
            )
        except QuotaExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=10) as executor:
        accepted = list(executor.map(consume, range(50)))

    assert accepted.count(True) == 20
    assert accepted.count(False) == 30


def test_batched_admission_preserves_order_quota_and_refresh_deduplication(
    tmp_path: Path,
) -> None:
    control = ControlDatabase(tmp_path / "batch.sqlite3")
    control.initialize()
    now = datetime(2026, 8, 26, tzinfo=UTC)

    outcomes = control.admit_many(
        [
            AdmissionRequest("one", 2, "example.com"),
            AdmissionRequest("one", 2, "example.com"),
            AdmissionRequest("one", 2, "other.example"),
            AdmissionRequest("two", 1, "other.example", enqueue_refresh=False),
        ],
        now=now,
    )

    assert isinstance(outcomes[0], Admission)
    assert outcomes[0].quota.remaining == 1
    assert outcomes[0].refresh_status == "queued"
    assert isinstance(outcomes[1], Admission)
    assert outcomes[1].quota.remaining == 0
    assert outcomes[1].refresh_status == "already-pending"
    assert isinstance(outcomes[2], QuotaExceeded)
    assert isinstance(outcomes[3], Admission)
    assert outcomes[3].quota.remaining == 0
    assert outcomes[3].refresh_status == "disabled"
    assert control.queued_refreshes(10) == ["example.com"]


def test_refresh_queue_is_bounded_and_rotates_incomplete_work(tmp_path: Path) -> None:
    control = ControlDatabase(tmp_path / "control.sqlite3", max_refresh_queue=1)
    control.initialize()
    now = datetime(2026, 8, 26, tzinfo=UTC)

    assert control.admit("one", 10, "one.example", now=now).refresh_status == "queued"
    assert control.admit("two", 10, "two.example", now=now).refresh_status == "queue-full"

    control.finish_refresh_attempt(
        "one.example",
        complete=False,
        attempted_at="2026-08-26T00:01:00+00:00",
    )
    assert control.queued_refreshes(1) == ["one.example"]
    control.finish_refresh_attempt("one.example", complete=True)
    assert control.queued_refreshes(1) == []


def test_schema_verification_is_read_only_and_requires_migration(tmp_path: Path) -> None:
    missing = ControlDatabase(tmp_path / "missing.sqlite3")
    with pytest.raises(ControlUnavailable, match="migration required"):
        missing.verify_schema()

    migrated = ControlDatabase(tmp_path / "migrated.sqlite3")
    migrated.initialize()
    migrated.verify_schema()
