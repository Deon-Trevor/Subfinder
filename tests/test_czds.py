from __future__ import annotations

import gzip
import json
from pathlib import Path

from ctlogs.database import Database
from ctlogs.ingest.czds import AUTH_URL, LINKS_URL, CzdsClient, import_zone, run_czds


class Response:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None) -> None:
        self.body = body
        self.headers = headers or {}
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            size = len(self.body) - self.offset
        chunk = self.body[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk


def test_client_authenticates_and_lists_approved_links() -> None:
    requests = []

    def opener(request, *, timeout: int):
        requests.append(request)
        if request.full_url == AUTH_URL:
            return Response(json.dumps({"accessToken": "token"}).encode())
        assert request.full_url == LINKS_URL
        return Response(json.dumps(["https://czds-api.icann.org/czds/downloads/com.zone"]).encode())

    links = CzdsClient("user", "password", opener=opener).approved_links()

    assert links == ["https://czds-api.icann.org/czds/downloads/com.zone"]
    assert json.loads(requests[0].data) == {"username": "user", "password": "password"}
    assert requests[1].get_header("Authorization") == "Bearer token"


def test_import_zone_keeps_delegated_domains_only(tmp_path: Path) -> None:
    archive = tmp_path / "example.zone.gz"
    with gzip.open(archive, "wt") as output:
        output.write(
            "$ORIGIN example.\n"
            "example. 3600 IN SOA ns.example. hostmaster.example. 1 2 3 4 5\n"
            "example. 3600 IN NS ns.example.\n"
            "alpha 3600 IN NS ns1.provider.test.\n"
            "  3600 IN NS ns2.provider.test.\n"
            "ns.alpha 3600 IN A 192.0.2.1\n"
            "beta.example. 3600 IN NS ns1.provider.test.\n"
        )
    database = Database(tmp_path / "czds.sqlite3")
    database.initialize()

    assert import_zone(database, "example", archive, batch_size=1) == 3
    assert [row.subdomain for row in database.search("alpha.example")] == [
        "alpha.example"
    ]
    assert [row.subdomain for row in database.search("beta.example")] == [
        "beta.example"
    ]


def test_capped_runs_advance_past_completed_zones(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "czds.sqlite3")
    database.initialize()
    downloads: list[str] = []

    class Client:
        def approved_links(self) -> list[str]:
            return [
                "https://czds-api.icann.org/czds/downloads/beta.zone",
                "https://czds-api.icann.org/czds/downloads/alpha.zone",
            ]

        def download(self, url: str, destination: Path, **_kwargs):
            downloads.append(url)
            return 10, "Fri, 22 Aug 2026 00:00:00 GMT"

    monkeypatch.setattr("ctlogs.ingest.czds.import_zone", lambda *_args: 1)

    assert run_czds(database, Client(), tmp_path, max_zones=1) == (1, 1)  # type: ignore[arg-type]
    assert run_czds(database, Client(), tmp_path, max_zones=1) == (1, 1)  # type: ignore[arg-type]
    assert [url.rsplit("/", 1)[-1] for url in downloads] == [
        "alpha.zone",
        "beta.zone",
    ]


def test_completed_local_download_resumes_without_fetching(
    tmp_path: Path,
    monkeypatch,
) -> None:
    database = Database(tmp_path / "czds.sqlite3")
    database.initialize()
    (tmp_path / "alpha.zone.gz").write_bytes(b"complete archive")

    class Client:
        def approved_links(self) -> list[str]:
            return ["https://czds-api.icann.org/czds/downloads/alpha.zone"]

        def download(self, *_args, **_kwargs):
            raise AssertionError("completed local archive was downloaded again")

    monkeypatch.setattr("ctlogs.ingest.czds.import_zone", lambda *_args: 1)

    assert run_czds(database, Client(), tmp_path, max_zones=1) == (1, 1)  # type: ignore[arg-type]
