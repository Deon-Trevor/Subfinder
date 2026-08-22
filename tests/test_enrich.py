from __future__ import annotations

import json
from pathlib import Path

from ctlogs.database import Database
from ctlogs.ingest.enrich import CensysSource, ChaosApiSource, UrlscanSource, run_source


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


def test_chaos_uses_authorization_key_and_expands_labels() -> None:
    requests = []

    def opener(request, *, timeout: int):
        requests.append((request, timeout))
        return Response({"domain": "example.com", "subdomains": ["api", "www.example.com"]})

    page = ChaosApiSource("secret", opener=opener).fetch_page("example.com", None)

    assert page.rows == [("api.example.com", None), ("www.example.com", None)]
    assert requests[0][0].get_header("Authorization") == "secret"
    assert requests[0][0].full_url.endswith("/dns/example.com/subdomains")


def test_censys_reads_certificate_names_and_page_token() -> None:
    requests = []

    def opener(request, *, timeout: int):
        requests.append(request)
        return Response(
            {
                "result": {
                    "hits": [
                        {
                            "certificate_v1": {
                                "resource": {
                                    "names": ["*.api.example.com", "other.test"],
                                    "added_at": "2026-08-20T00:00:00Z",
                                }
                            }
                        }
                    ],
                    "next_page_token": "next-token",
                }
            }
        )

    page = CensysSource("pat", organization_id="org", opener=opener).fetch_page(
        "example.com", "current-token"
    )

    body = json.loads(requests[0].data)
    assert body == {
        "query": 'cert.names: "example.com"',
        "fields": ["cert.names", "cert.added_at"],
        "page_size": 100,
        "page_token": "current-token",
    }
    assert requests[0].get_header("Authorization") == "Bearer pat"
    assert requests[0].full_url.endswith("?organization_id=org")
    assert page.rows == [("api.example.com", "2026-08-20T00:00:00Z")]
    assert page.next_cursor == "next-token"


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

    class Source:
        name = "bounded"

        def fetch_page(self, apex: str, cursor: str | None):
            from ctlogs.ingest.enrich import SourcePage

            cursors.append(cursor)
            number = len(cursors)
            return SourcePage([(f"n{number}.{apex}", None)], f"cursor-{number}", 10)

    assert run_source(database, Source(), ["example.com"], max_requests=1) == (1, 1)
    assert run_source(database, Source(), ["example.com"], max_requests=1) == (1, 1)
    assert cursors == [None, "cursor-1"]

