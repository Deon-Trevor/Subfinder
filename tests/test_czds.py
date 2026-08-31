from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ctlogs.database import Database
from ctlogs.ingest.czds import (
    AUTH_URL,
    LINKS_URL,
    CzdsClient,
    import_local_zone,
    import_zone,
    local_zone_artifact,
    run_czds,
)


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
        return Response(
            json.dumps(["https://czds-api.icann.org/czds/downloads/com.zone"]).encode()
        )

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


def test_refresh_cap_rotates_to_the_least_recently_checked_zone(
    tmp_path: Path,
) -> None:
    database = Database(tmp_path / "czds.sqlite3")
    database.initialize()
    now = datetime(2026, 8, 23, tzinfo=UTC)
    database.upsert_ingest_state(
        "czds-download:alpha",
        cursor="10",
        etag="alpha-tag",
        updated_at=(now - timedelta(days=2)).isoformat(),
    )
    database.upsert_ingest_state(
        "czds-download:beta",
        cursor="10",
        etag="beta-tag",
        updated_at=(now - timedelta(days=1)).isoformat(),
    )
    downloads: list[str] = []

    class Client:
        def approved_links(self) -> list[str]:
            return [
                "https://czds-api.icann.org/czds/downloads/beta.zone",
                "https://czds-api.icann.org/czds/downloads/alpha.zone",
            ]

        def download(self, url: str, *_args, **_kwargs):
            downloads.append(url)
            return None

    assert run_czds(  # type: ignore[arg-type]
        database,
        Client(),
        tmp_path,
        max_zones=1,
        refresh=True,
    ) == (0, 0)
    assert downloads[0].endswith("/alpha.zone")

    assert run_czds(  # type: ignore[arg-type]
        database,
        Client(),
        tmp_path,
        max_zones=1,
        refresh=True,
    ) == (0, 0)
    assert downloads[1].endswith("/beta.zone")


def test_local_zone_inventory_is_exact_bounded_and_does_not_follow_links(
    tmp_path: Path,
) -> None:
    artifact_path = tmp_path / "ac.zw.zone.gz"
    artifact_path.write_bytes(b"nust NS ns1.example.\n")

    artifact = local_zone_artifact(tmp_path, "ac.zw", max_bytes=1024)

    assert artifact is not None
    assert artifact.name == "ac.zw.zone.gz"
    assert artifact.size == artifact_path.stat().st_size
    assert local_zone_artifact(tmp_path, "zw", max_bytes=1024) is None
    assert local_zone_artifact(tmp_path, "ac.zw", max_bytes=1) is None
    linked = tmp_path / "org.zw.zone.gz"
    linked.symlink_to(artifact_path)
    assert local_zone_artifact(tmp_path, "org.zw", max_bytes=1024) is None


def test_local_zone_import_pins_the_exact_artifact_generation(tmp_path: Path) -> None:
    database = Database(tmp_path / "catalog.sqlite3")
    database.initialize()
    artifact_path = tmp_path / "ac.zw.zone.gz"
    artifact_path.write_bytes(
        b"$ORIGIN ac.zw.\nnust 3600 IN NS ns1.example.\nuz 3600 IN NS ns2.example.\n"
    )
    artifact = local_zone_artifact(tmp_path, "ac.zw")
    assert artifact is not None

    imported, digest = import_local_zone(database, artifact, batch_size=1)

    assert imported == 2
    assert len(digest) == 64
    assert [row.subdomain for row in database.search("nust.ac.zw")] == ["nust.ac.zw"]
    state = database.get_ingest_state("zone-import:ac.zw")
    assert state is not None
    assert state["cursor"] == artifact.fingerprint
    assert state["etag"] == digest
