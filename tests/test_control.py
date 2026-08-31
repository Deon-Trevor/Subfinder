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
    EnrichmentQueueFull,
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


def test_multi_unit_consumption_is_exact_and_all_or_nothing(tmp_path: Path) -> None:
    control = ControlDatabase(tmp_path / "multi-unit.sqlite3")
    control.initialize()
    now = datetime(2026, 8, 26, tzinfo=UTC)

    accepted = control.consume("threat-hunter", 5, 3, now=now)
    assert accepted.remaining == 2

    with pytest.raises(QuotaExceeded) as rejected:
        control.consume("threat-hunter", 5, 3, now=now)
    assert rejected.value.quota.remaining == 2

    final = control.consume("threat-hunter", 5, 2, now=now)
    assert final.remaining == 0


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
    assert (
        control.admit("two", 10, "two.example", now=now).refresh_status == "queue-full"
    )

    control.finish_refresh_attempt(
        "one.example",
        complete=False,
        attempted_at="2026-08-26T00:01:00+00:00",
    )
    assert control.queued_refreshes(1) == ["one.example"]
    control.finish_refresh_attempt("one.example", complete=True)
    assert control.queued_refreshes(1) == []


def test_composite_enrichment_is_idempotent_owned_and_durable(tmp_path: Path) -> None:
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()
    now = datetime(2026, 8, 31, tzinfo=UTC)

    admitted = control.enqueue_enrichment(
        "198.51.100.8",
        10,
        "nust.ac.zw",
        "ac.zw",
        artifact_name="ac.zw.zone.gz",
        artifact_fingerprint="stat-v1:12:34",
        include_urlscan=True,
        idempotency_key="nust-both",
        max_pending=4,
        max_pending_per_subject=2,
        now=now,
    )
    replay = control.enqueue_enrichment(
        "198.51.100.8",
        10,
        "nust.ac.zw",
        "ac.zw",
        artifact_name="ac.zw.zone.gz",
        artifact_fingerprint="stat-v1:12:34",
        include_urlscan=True,
        idempotency_key="nust-both",
        max_pending=4,
        max_pending_per_subject=2,
        now=now,
    )

    assert admitted.created is True
    assert admitted.quota.remaining == 9
    assert replay.created is False
    assert replay.job.job_id == admitted.job.job_id
    assert replay.quota.remaining == 9
    assert control.queued_refreshes(1) == ["nust.ac.zw"]
    assert control.enrichment_job(admitted.job.job_id, subject="other") is None

    claimed = control.claim_enrichment("scheduler", lease_seconds=60, now=1)
    assert claimed is not None
    assert claimed.zone_state == "running"
    assert claimed.urlscan_state == "running"
    checkpointed = control.checkpoint_enrichment(
        claimed.job_id,
        "scheduler",
        zone_state="complete",
        zone_records=7,
        now=2,
    )
    assert checkpointed.zone_records == 7
    control.checkpoint_enrichment(
        claimed.job_id,
        "scheduler",
        urlscan_state="checkpointed",
        urlscan_records=3,
        now=3,
    )
    finished = control.finish_enrichment(claimed.job_id, "scheduler", now=4)
    assert finished.state == "partial"
    assert finished.zone_state == "complete"
    assert finished.urlscan_state == "checkpointed"


def test_enrichment_claim_recovers_only_unfinished_lanes(tmp_path: Path) -> None:
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()
    admitted = control.enqueue_enrichment(
        "test",
        10,
        "nust.ac.zw",
        "ac.zw",
        artifact_name="ac.zw.zone.gz",
        artifact_fingerprint="stat-v1:12:34",
        include_urlscan=True,
        idempotency_key="recover",
        max_pending=4,
        max_pending_per_subject=2,
        now=datetime(2026, 8, 31, tzinfo=UTC),
    )
    first = control.claim_enrichment("dead", lease_seconds=1, now=1)
    assert first is not None
    control.checkpoint_enrichment(
        admitted.job.job_id,
        "dead",
        zone_state="complete",
        zone_records=5,
        now=1.5,
    )

    recovered = control.claim_enrichment("replacement", lease_seconds=60, now=3)

    assert recovered is not None
    assert recovered.zone_state == "complete"
    assert recovered.urlscan_state == "running"


def test_enrichment_rejects_a_full_continuation_queue_atomically(
    tmp_path: Path,
) -> None:
    control = ControlDatabase(
        tmp_path / "control.sqlite3",
        busy_timeout_ms=1_000,
        max_refresh_queue=1,
    )
    control.initialize()
    now = datetime(2026, 8, 31, tzinfo=UTC)
    control.enqueue_refresh("already.example")

    with pytest.raises(EnrichmentQueueFull, match="refresh queue"):
        control.enqueue_enrichment(
            "test",
            10,
            "nust.ac.zw",
            "ac.zw",
            include_urlscan=True,
            idempotency_key="full",
            max_pending=4,
            max_pending_per_subject=2,
            now=now,
        )

    assert control.queued_refreshes(10) == ["already.example"]
    assert control.consume("test", 10, 10, now=now).remaining == 0


def test_schema_verification_is_read_only_and_requires_migration(
    tmp_path: Path,
) -> None:
    missing = ControlDatabase(tmp_path / "missing.sqlite3")
    with pytest.raises(ControlUnavailable, match="migration required"):
        missing.verify_schema()

    migrated = ControlDatabase(tmp_path / "migrated.sqlite3")
    migrated.initialize()
    migrated.verify_schema()
