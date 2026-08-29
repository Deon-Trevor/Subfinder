from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from ctlogs.app import create_app
from ctlogs.batch_worker import RecordBatchWorker
from ctlogs.control import ControlDatabase, IdempotencyConflict
from ctlogs.database import Database


def _stores(tmp_path: Path) -> tuple[Database, ControlDatabase]:
    database = Database(tmp_path / "catalog.sqlite3")
    control = ControlDatabase(tmp_path / "control.sqlite3")
    database.initialize()
    control.initialize()
    return database, control


def test_duplicate_admission_is_one_job_and_one_quota_reservation(
    tmp_path: Path,
) -> None:
    _database, control = _stores(tmp_path)
    now = datetime(2026, 8, 29, tzinfo=UTC)
    first = control.enqueue_record_batch(
        "token:one",
        10,
        ["example.com", "example.net"],
        idempotency_key="same",
        max_pending=10,
        max_pending_per_subject=5,
        now=now,
    )
    replay = control.enqueue_record_batch(
        "token:one",
        10,
        ["example.com", "example.net"],
        idempotency_key="same",
        max_pending=10,
        max_pending_per_subject=5,
        now=now,
    )

    assert first.created is True
    assert replay.created is False
    assert replay.job.job_id == first.job.job_id
    assert first.quota.remaining == replay.quota.remaining == 8
    with pytest.raises(IdempotencyConflict):
        control.enqueue_record_batch(
            "token:one",
            10,
            ["example.org"],
            idempotency_key="same",
            max_pending=10,
            max_pending_per_subject=5,
            now=now,
        )


def test_worker_commits_replayable_bounded_slices(tmp_path: Path) -> None:
    database, control = _stores(tmp_path)
    for apex in ("example.com", "example.net", "example.org"):
        database.upsert_subdomains(
            apex,
            [(f"www.{apex}", "2026-08-29T00:00:00Z")],
            source="fixture",
        )
    admission = control.enqueue_record_batch(
        "token:one",
        10,
        ["example.com", "example.net", "example.org"],
        idempotency_key="job",
        max_pending=10,
        max_pending_per_subject=5,
    )
    worker = RecordBatchWorker(
        database,
        control,
        worker_id="worker",
        slice_size=2,
        max_records=10,
    )

    assert worker.run_once() is True
    assert worker.run_once() is True
    assert worker.run_once() is False
    job = control.record_batch_job(admission.job.job_id, subject="token:one")
    assert job is not None
    assert job.state == "done"
    assert job.completed_apexes == 3
    assert job.committed_units == 3
    slices = control.record_batch_slices(
        job.job_id, subject="token:one", after=-1, limit=10
    )
    assert [row["sequence"] for row in slices] == [0, 1]
    assert [
        item["apex"]
        for row in slices
        for item in json.loads(str(row["document"]))["results"]
    ] == ["example.com", "example.net", "example.org"]
    assert control.record_batch_slices(
        job.job_id, subject="token:one", after=0, limit=10
    ) == [slices[1]]


def test_expired_lease_is_reclaimed_without_duplicate_visible_slice(
    tmp_path: Path,
) -> None:
    _database, control = _stores(tmp_path)
    admission = control.enqueue_record_batch(
        "token:one",
        10,
        ["example.com"],
        idempotency_key="crash",
        max_pending=10,
        max_pending_per_subject=5,
    )
    first = control.claim_record_batch("dead", lease_seconds=1, slice_size=1, now=10)
    assert first is not None
    reclaimed = control.claim_record_batch(
        "live", lease_seconds=10, slice_size=1, now=12
    )
    assert reclaimed is not None
    assert reclaimed[0].job_id == admission.job.job_id
    control.finish_record_batch_slice(
        admission.job.job_id,
        "live",
        apex_count=1,
        record_count=0,
        document_json='{"results":[],"errors":[]}',
        now=13,
    )
    assert (
        len(
            control.record_batch_slices(
                admission.job.job_id, subject="token:one", after=-1, limit=10
            )
        )
        == 1
    )


@pytest.mark.anyio
async def test_queued_api_submit_poll_replay_and_cancel(tmp_path: Path) -> None:
    app = create_app(
        tmp_path / "api.sqlite3",
        api_tokens=["service"],
        token_request_limit=10,
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    headers = {
        "Authorization": "Bearer service",
        "Idempotency-Key": "request-one",
    }
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver"
        ) as client,
    ):
        submitted = await client.post(
            "/internal/v1/record-batches",
            headers=headers,
            json={"apexes": ["example.com", "example.net"]},
        )
        replay = await client.post(
            "/internal/v1/record-batches",
            headers=headers,
            json={"apexes": ["example.com", "example.net"]},
        )
        job_id = submitted.json()["job_id"]
        worker = RecordBatchWorker(
            app.state.database,
            app.state.control_database,
            worker_id="api-test",
            slice_size=1,
        )
        await asyncio.to_thread(worker.run_once)
        chunks = await client.get(
            f"/internal/v1/record-batches/{job_id}/chunks",
            headers={"Authorization": "Bearer service"},
            params={"after": -1, "wait": 0},
        )
        cancelled = await client.post(
            f"/internal/v1/record-batches/{job_id}/cancel",
            headers={"Authorization": "Bearer service"},
        )

    assert submitted.status_code == 202
    assert submitted.headers["x-ratelimit-remaining"] == "8"
    assert replay.status_code == 202
    assert replay.headers["x-idempotent-replay"] == "1"
    assert chunks.status_code == 200
    assert chunks.json()["next_cursor"] == 0
    assert len(chunks.json()["chunks"]) == 1
    assert cancelled.json()["state"] == "cancelled"
    assert cancelled.json()["quota"] == {
        "reserved": 2,
        "committed": 1,
        "released": 1,
        "outstanding": 0,
    }
