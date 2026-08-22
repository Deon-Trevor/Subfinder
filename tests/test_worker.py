from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ctlogs.database import Database
from ctlogs import worker
from ctlogs.ingest.direct_ct import PollResult


@pytest.mark.anyio
async def test_poll_once_processes_every_log_within_the_parallel_cap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    urls = [f"https://log-{number}.example" for number in range(9)]
    static_urls = [f"https://static-{number}.example" for number in range(3)]
    active = 0
    peak = 0
    visited: list[str] = []

    monkeypatch.setattr(worker, "_usable_log_urls", lambda: urls)
    monkeypatch.setattr(worker, "_static_log_urls", lambda: static_urls)

    def poll_one(
        _database: Database,
        url: str,
        _batch: int,
        _initial_backfill: int,
        _max_batches: int,
    ) -> int:
        visited.append(url)
        return 1

    monkeypatch.setattr(worker, "_poll_one_log", poll_one)
    monkeypatch.setattr(worker, "_poll_one_static_log", poll_one)

    async def run_without_threads(function, *args):
        nonlocal active, peak
        if function in {worker._usable_log_urls, worker._static_log_urls}:
            return function(*args)
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0)
        try:
            return function(*args)
        finally:
            active -= 1

    monkeypatch.setattr(worker.asyncio, "to_thread", run_without_threads)

    total = await worker.poll_once(Database(tmp_path / "worker.sqlite3"))

    assert total == len(urls) + len(static_urls)
    assert sorted(visited) == sorted(urls + static_urls)
    assert peak == worker.MAX_PARALLEL_LOG_POLLS


@pytest.mark.anyio
async def test_poll_once_returns_zero_without_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(worker, "_usable_log_urls", lambda: [])
    monkeypatch.setattr(worker, "_static_log_urls", lambda: [])
    monkeypatch.setattr(
        worker.asyncio,
        "to_thread",
        lambda function, *args: asyncio.sleep(0, result=function(*args)),
    )

    assert await worker.poll_once(Database(tmp_path / "worker.sqlite3")) == 0


def test_new_log_starts_near_tail_and_checkpoints_actual_response_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "worker.sqlite3")
    database.initialize()
    ranges: list[tuple[int, int]] = []

    class Client:
        def __init__(self, _database: Database) -> None:
            pass

        def get_sth(self, _log_url: str) -> dict[str, int]:
            return {"tree_size": 10_000}

        def poll_and_store(
            self, _log_url: str, start: int, end: int
        ) -> PollResult:
            ranges.append((start, end))
            return PollResult(entry_count=2, hostname_count=3)

    monkeypatch.setattr(worker, "DirectCTClient", Client)

    count = worker._poll_one_log(
        database,
        "https://log.example",
        batch=100,
        initial_backfill=100,
        max_batches=1,
    )

    assert count == 3
    assert ranges == [(9_900, 9_999)]
    assert database.get_ingest_state("direct_ct:https://log.example")["cursor"] == "9902"


def test_existing_cursor_resumes_without_reapplying_tail_bootstrap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "worker.sqlite3")
    database.initialize()
    database.upsert_ingest_state("direct_ct:https://log.example", cursor="123")
    starts: list[int] = []

    class Client:
        def __init__(self, _database: Database) -> None:
            pass

        def get_sth(self, _log_url: str) -> dict[str, int]:
            return {"tree_size": 10_000}

        def poll_and_store(
            self, _log_url: str, start: int, _end: int
        ) -> PollResult:
            starts.append(start)
            return PollResult(entry_count=1, hostname_count=0)

    monkeypatch.setattr(worker, "DirectCTClient", Client)

    worker._poll_one_log(
        database,
        "https://log.example",
        batch=100,
        initial_backfill=100,
        max_batches=1,
    )

    assert starts == [123]
