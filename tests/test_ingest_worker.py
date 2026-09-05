from __future__ import annotations

import json
from pathlib import Path

import pytest

from ctlogs.control import ControlDatabase
from ctlogs.database import Database
from ctlogs.ingest_worker import run_czds_job, run_once


def test_czds_worker_claims_runs_and_finishes_job(tmp_path: Path, monkeypatch) -> None:
    database = Database(tmp_path / "ctlogs.sqlite3")
    database.initialize()
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()
    job, created = control.enqueue_ingest_job(
        "czds",
        idempotency_key="cycle",
        payload={
            "max_zones": 2,
            "max_bytes": 10,
            "output_directory": str(tmp_path / "czds"),
            "refresh": True,
        },
    )
    assert created is True
    seen = {}

    class Client:
        def __init__(self, username: str, password: str, *, timeout: int) -> None:
            seen["client"] = (username, password, timeout)

    def fake_run_czds(db, client, output, **kwargs):
        assert db is database
        assert isinstance(client, Client)
        seen["output"] = output
        seen["kwargs"] = kwargs
        return 2, 9

    monkeypatch.setenv("CZDS_USERNAME", "user")
    monkeypatch.setenv("CZDS_PASSWORD", "password")
    monkeypatch.setenv("CTLOGS_CZDS_OUTPUT", str(tmp_path / "czds"))
    monkeypatch.setattr("ctlogs.ingest_worker.CzdsClient", Client)
    monkeypatch.setattr("ctlogs.ingest_worker.run_czds", fake_run_czds)

    finished = run_once(
        database,
        control,
        kind="czds",
        owner="worker-1",
        lease_seconds=60,
        timeout=7,
    )

    assert finished is not None
    assert finished.job_id == job.job_id
    assert finished.state == "done"
    assert json.loads(finished.result_json) == {"hostnames": 9, "zones": 2}
    assert seen == {
        "client": ("user", "password", 7),
        "output": tmp_path / "czds",
        "kwargs": {
            "max_zones": 2,
            "max_bytes": 10,
            "refresh": True,
        },
    }


def test_czds_worker_failure_is_retried_then_failed(tmp_path: Path, monkeypatch) -> None:
    database = Database(tmp_path / "ctlogs.sqlite3")
    database.initialize()
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()
    job, _ = control.enqueue_ingest_job(
        "czds",
        idempotency_key="cycle",
        payload={"max_zones": 1},
        max_attempts=2,
    )
    monkeypatch.setenv("CZDS_USERNAME", "user")
    monkeypatch.setenv("CZDS_PASSWORD", "password")
    monkeypatch.setenv("CTLOGS_CZDS_OUTPUT", str(tmp_path / "czds"))
    monkeypatch.setattr(
        "ctlogs.ingest_worker.run_czds",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    first = run_once(
        database,
        control,
        kind="czds",
        owner="worker-1",
        lease_seconds=60,
        timeout=7,
    )
    second = run_once(
        database,
        control,
        kind="czds",
        owner="worker-1",
        lease_seconds=60,
        timeout=7,
    )

    assert first is not None and first.state == "queued"
    assert second is not None and second.state == "failed"
    stored = control.ingest_job(job.job_id)
    assert stored is not None
    assert stored.error == "boom"


def test_czds_job_rejects_missing_credentials(tmp_path: Path, monkeypatch) -> None:
    database = Database(tmp_path / "ctlogs.sqlite3")
    database.initialize()
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()
    job, _ = control.enqueue_ingest_job("czds", idempotency_key="cycle")
    monkeypatch.delenv("CZDS_USERNAME", raising=False)
    monkeypatch.delenv("CZDS_PASSWORD", raising=False)

    with pytest.raises(RuntimeError, match="CZDS_USERNAME and CZDS_PASSWORD"):
        run_czds_job(database, job, timeout=7)



def test_czds_worker_rejects_unconfigured_output_directory(tmp_path: Path, monkeypatch) -> None:
    database = Database(tmp_path / "ctlogs.sqlite3")
    database.initialize()
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()
    job, _ = control.enqueue_ingest_job(
        "czds",
        idempotency_key="cycle",
        payload={"output_directory": str(tmp_path / "elsewhere")},
    )
    monkeypatch.setenv("CZDS_USERNAME", "user")
    monkeypatch.setenv("CZDS_PASSWORD", "password")
    monkeypatch.setenv("CTLOGS_CZDS_OUTPUT", str(tmp_path / "czds"))

    with pytest.raises(ValueError, match="output_directory"):
        run_czds_job(database, job, timeout=7)


def test_czds_worker_clamps_payload_to_environment_bounds(tmp_path: Path, monkeypatch) -> None:
    database = Database(tmp_path / "ctlogs.sqlite3")
    database.initialize()
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()
    job, _ = control.enqueue_ingest_job(
        "czds",
        idempotency_key="cycle",
        payload={
            "max_zones": 999,
            "max_bytes": 999,
            "output_directory": str(tmp_path / "czds"),
        },
    )
    seen = {}

    class Client:
        def __init__(self, _username: str, _password: str, *, timeout: int) -> None:
            pass

    def fake_run_czds(_database, _client, _output, **kwargs):
        seen.update(kwargs)
        return 1, 1

    monkeypatch.setenv("CZDS_USERNAME", "user")
    monkeypatch.setenv("CZDS_PASSWORD", "password")
    monkeypatch.setenv("CTLOGS_CZDS_OUTPUT", str(tmp_path / "czds"))
    monkeypatch.setenv("CTLOGS_CZDS_MAX_ZONES", "3")
    monkeypatch.setenv("CTLOGS_CZDS_MAX_BYTES", "10")
    monkeypatch.setattr("ctlogs.ingest_worker.CzdsClient", Client)
    monkeypatch.setattr("ctlogs.ingest_worker.run_czds", fake_run_czds)

    assert run_czds_job(database, job, timeout=7) == {"zones": 1, "hostnames": 1}
    assert seen["max_zones"] == 3
    assert seen["max_bytes"] == 10

def test_worker_returns_none_when_no_job(tmp_path: Path) -> None:
    database = Database(tmp_path / "ctlogs.sqlite3")
    database.initialize()
    control = ControlDatabase(tmp_path / "control.sqlite3", busy_timeout_ms=1_000)
    control.initialize()

    assert (
        run_once(
            database,
            control,
            kind="czds",
            owner="worker-1",
            lease_seconds=60,
            timeout=7,
        )
        is None
    )
