from __future__ import annotations

import json
from pathlib import Path

from ctlogs.database import Database
from ctlogs.ingest.enrich import UrlscanSource, run_source


class Response:
    def __init__(self, payload: dict) -> None:
        self.payload = json.dumps(payload).encode()
        self.headers: dict[str, str] = {}

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, _size: int = -1) -> bytes:
        return self.payload


def test_urlscan_uses_api_key_and_search_after() -> None:
    requests = []

    def opener(request, *, timeout: int):
        requests.append(request)
        return Response(
            {
                "results": [
                    {
                        "page": {"domain": "www.example.com"},
                        "task": {
                            "domain": "example.com",
                            "time": "2026-08-21T10:00:00Z",
                        },
                        "sort": [123, "id"],
                    }
                ]
            }
        )

    page = UrlscanSource("key", page_size=1, opener=opener).fetch_page(
        "example.com", "100,old"
    )

    assert requests[0].get_header("Api-key") == "key"
    assert "search_after=100%2Cold" in requests[0].full_url
    assert page.rows == [
        ("www.example.com", "2026-08-21T10:00:00Z"),
        ("example.com", "2026-08-21T10:00:00Z"),
    ]
    assert page.next_cursor == "123,id"


def test_runner_stops_at_source_budget_and_resumes_cursor(tmp_path: Path) -> None:
    database = Database(tmp_path / "enrich.sqlite3")
    database.initialize()
    cursors: list[str | None] = []
    guarded_requests: list[None] = []

    class Source:
        name = "bounded"

        def fetch_page(self, apex: str, cursor: str | None):
            from ctlogs.ingest.enrich import SourcePage

            cursors.append(cursor)
            number = len(cursors)
            return SourcePage([(f"n{number}.{apex}", None)], f"cursor-{number}", 10)

    guard = lambda: guarded_requests.append(None)
    assert run_source(
        database,
        Source(),
        ["example.com"],
        max_requests=1,
        request_guard=guard,
    ) == (1, 1)
    assert run_source(
        database,
        Source(),
        ["example.com"],
        max_requests=1,
        request_guard=guard,
    ) == (1, 1)
    assert cursors == [None, "cursor-1"]
    assert guarded_requests == [None, None]
