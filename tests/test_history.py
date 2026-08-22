from __future__ import annotations

from pathlib import Path

from ctlogs.database import Database
from ctlogs.ingest.direct_ct import PollResult
from ctlogs.ingest.history import run_history


def test_history_has_its_own_bounded_resumable_cursor(tmp_path: Path) -> None:
    database = Database(tmp_path / "history.sqlite3")
    database.initialize()
    calls: list[tuple[int, int]] = []

    class Client:
        def get_sth(self, _url: str) -> dict:
            return {"tree_size": 10}

        def poll_and_store(self, _url: str, start: int, end: int) -> PollResult:
            calls.append((start, end))
            return PollResult(entry_count=end - start + 1, hostname_count=1)

    assert run_history(
        database,
        "https://log.example",
        batch_size=2,
        max_batches=2,
        client=Client(),  # type: ignore[arg-type]
    ) == (4, 2)
    assert run_history(
        database,
        "https://log.example",
        batch_size=2,
        max_batches=1,
        client=Client(),  # type: ignore[arg-type]
    ) == (2, 1)
    assert calls == [(0, 1), (2, 3), (4, 5)]
    assert database.get_ingest_state("history:https://log.example")["cursor"] == "6"
