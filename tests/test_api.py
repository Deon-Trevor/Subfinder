from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
import asyncio
import sqlite3
import threading
import time

import httpx
import pytest

from ctlogs.app import create_app, normalize_apex
from ctlogs.control import ControlDatabase
from ctlogs.database import Database


@pytest.fixture
async def client(tmp_path: Path) -> AsyncIterator[httpx.AsyncClient]:
    app = create_app(
        tmp_path / "test.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with app.router.lifespan_context(app):
        app.state.database.upsert_subdomains(
            "example.com",
            [
                ("www.example.com", "2025-02-03T04:05:06Z"),
                ("example.com", "2024-01-02T03:04:05Z"),
                ("unknown.example.com", None),
            ],
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client:
            yield test_client


@pytest.mark.anyio
async def test_plain_text_is_one_hostname_per_line(client: httpx.AsyncClient) -> None:
    response = await client.get("/v1/search", params={"apex": "EXAMPLE.COM."})

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.text == (
        "example.com\n"
        "www.example.com\n"
        "unknown.example.com\n"
    )
    assert response.headers["x-ratelimit-limit"] == "1000"
    assert response.headers["x-ratelimit-remaining"] == "999"


@pytest.mark.anyio
async def test_dates_and_json_match_the_public_contract(client: httpx.AsyncClient) -> None:
    dated_text = await client.get(
        "/v1/search",
        params={"apex": "example.com", "dates": 1},
    )
    json_response = await client.get(
        "/v1/search",
        params={"apex": "example.com", "format": "json", "dates": 1},
    )

    assert dated_text.text == (
        "example.com\t2024-01-02T03:04:05Z\n"
        "www.example.com\t2025-02-03T04:05:06Z\n"
        "unknown.example.com\t\n"
    )
    assert json_response.json() == [
        {"first_seen": "2024-01-02T03:04:05Z", "sub": "example.com"},
        {"first_seen": "2025-02-03T04:05:06Z", "sub": "www.example.com"},
        {"first_seen": None, "sub": "unknown.example.com"},
    ]


@pytest.mark.anyio
async def test_json_without_dates_only_returns_sub(client: httpx.AsyncClient) -> None:
    response = await client.get(
        "/v1/search",
        params={"apex": "example.com", "format": "json"},
    )

    assert response.json() == [
        {"sub": "example.com"},
        {"sub": "www.example.com"},
        {"sub": "unknown.example.com"},
    ]


@pytest.mark.anyio
async def test_records_api_returns_local_provenance_without_discovery(
    tmp_path: Path,
) -> None:
    app = create_app(
        tmp_path / "records.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client,
    ):
        app.state.database.upsert_subdomains(
            "example.com",
            [("www.example.com", "2025-02-03T04:05:06Z")],
            source="direct_ct:https://ct.example",
            observed_at="2026-08-21T00:00:00Z",
        )
        response = await test_client.get(
            "/v1/records",
            params={"apex": "example.com"},
        )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-cache"
    assert response.headers["x-subfinder-schema-version"] == (
        "subfinder.index-records.v1"
    )
    assert response.headers["x-ratelimit-remaining"] == "999"
    assert response.json() == {
        "schema_version": "subfinder.index-records.v1",
        "apex": "example.com",
        "records": [
            {
                "hostname": "www.example.com",
                "first_seen": "2025-02-03T04:05:06Z",
                "sources": [
                    {
                        "source": "direct_ct:https://ct.example",
                        "first_seen": "2025-02-03T04:05:06Z",
                        "last_seen": "2026-08-21T00:00:00Z",
                    }
                ],
            }
        ],
    }
    assert app.state.control_database.queued_refreshes(1) == []
    assert "x-urlscan-status" not in response.headers


@pytest.mark.anyio
async def test_search_returns_the_local_index_and_coalesces_refresh_work(
    tmp_path: Path,
) -> None:
    app = create_app(
        tmp_path / "urlscan.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with app.router.lifespan_context(app):
        app.state.database.upsert_subdomains(
            "example.com",
            [("cached.example.com", "2026-08-23T10:00:00Z")],
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client:
            first = await test_client.get(
                "/v1/search",
                params={"apex": "example.com", "format": "json"},
            )
            second = await test_client.get(
                "/v1/search",
                params={"apex": "example.com", "format": "json"},
            )

    assert first.status_code == 200
    assert first.headers["x-refresh-status"] == "queued"
    assert first.headers["x-urlscan-status"] == "queued"
    assert first.json() == [{"sub": "cached.example.com"}]
    assert second.headers["x-refresh-status"] == "already-pending"
    assert app.state.control_database.queued_refreshes(1) == ["example.com"]


@pytest.mark.anyio
async def test_optional_cursor_pages_preserve_the_legacy_body_shape(tmp_path: Path) -> None:
    app = create_app(tmp_path / "page.sqlite3", allowed_hosts=["testserver"], allowed_origins=[])
    async with app.router.lifespan_context(app):
        app.state.database.upsert_subdomains(
            "example.com",
            [
                ("a.example.com", "2024-01-01T00:00:00Z"),
                ("b.example.com", "2025-01-01T00:00:00Z"),
                ("z.example.com", None),
            ],
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client:
            first = await test_client.get(
                "/v1/search",
                params={"apex": "example.com", "format": "json", "dates": 1, "limit": 2},
            )
            second = await test_client.get(
                "/v1/search",
                params={
                    "apex": "example.com",
                    "format": "json",
                    "dates": 1,
                    "limit": 2,
                    "cursor": first.headers["x-next-cursor"],
                },
            )

    assert first.json() == [
        {"first_seen": "2024-01-01T00:00:00Z", "sub": "a.example.com"},
        {"first_seen": "2025-01-01T00:00:00Z", "sub": "b.example.com"},
    ]
    assert first.headers["x-result-truncated"] == "true"
    assert 'rel="next"' in first.headers["link"]
    assert second.json() == [{"first_seen": None, "sub": "z.example.com"}]
    assert second.headers["x-result-truncated"] == "false"


@pytest.mark.anyio
async def test_cursor_cannot_be_reused_for_another_apex(tmp_path: Path) -> None:
    app = create_app(
        tmp_path / "cursor.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with app.router.lifespan_context(app):
        app.state.database.upsert_subdomains(
            "example.com",
            [("a.example.com", None), ("b.example.com", None)],
        )
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            first = await client.get(
                "/v1/search",
                params={"apex": "example.com", "limit": 1},
            )
            response = await client.get(
                "/v1/search",
                params={
                    "apex": "example.org",
                    "limit": 1,
                    "cursor": first.headers["x-next-cursor"],
                },
            )

    assert response.status_code == 400
    assert response.json() == {"detail": "cursor is invalid"}


@pytest.mark.anyio
async def test_catalog_writer_does_not_stall_search_health_or_static_routes(
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.sqlite3"
    writer = Database(path)
    writer.initialize()
    writer.upsert_subdomains("example.com", [("cached.example.com", None)])
    ControlDatabase(tmp_path / "control.sqlite3").initialize()
    app = create_app(
        path,
        control_database_path=tmp_path / "control.sqlite3",
        read_only_index=True,
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    entered = threading.Event()
    release = threading.Event()

    def hold_writer() -> None:
        with writer.write_transaction() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO ingest_state(source, cursor) VALUES('held', '1')"
            )
            entered.set()
            release.wait(timeout=2)

    thread = threading.Thread(target=hold_writer)
    thread.start()
    assert entered.wait(timeout=1)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client:
            started = time.monotonic()
            search, health, homepage = await asyncio.gather(
                test_client.get("/v1/search", params={"apex": "example.com"}),
                test_client.get("/health"),
                test_client.get("/"),
            )
            elapsed = time.monotonic() - started
    release.set()
    thread.join(timeout=2)

    assert search.text == "cached.example.com\n"
    assert health.status_code == 200
    assert homepage.status_code == 200
    assert elapsed < 0.5


@pytest.mark.anyio
async def test_control_lock_fails_search_quickly_without_blocking_health(tmp_path: Path) -> None:
    app = create_app(
        tmp_path / "catalog.sqlite3",
        control_database_path=tmp_path / "control.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with app.router.lifespan_context(app):
        blocker = sqlite3.connect(tmp_path / "control.sqlite3")
        blocker.execute("BEGIN IMMEDIATE")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client:
            started = time.monotonic()
            search, health = await asyncio.gather(
                test_client.get("/v1/search", params={"apex": "example.net"}),
                test_client.get("/health"),
            )
            elapsed = time.monotonic() - started
        blocker.rollback()
        blocker.close()

    assert search.status_code == 503
    assert search.headers["retry-after"] == "1"
    assert health.status_code == 200
    assert elapsed < 0.5


@pytest.mark.parametrize(
    "apex",
    ["www.example.com", "com", "https://example.com", "*.example.com"],
)
@pytest.mark.anyio
async def test_apex_must_be_an_etld_plus_one(
    client: httpx.AsyncClient,
    apex: str,
) -> None:
    response = await client.get("/v1/search", params={"apex": apex})

    assert response.status_code == 400
    assert "eTLD+1" in response.json()["detail"]


def test_private_psl_boundaries_are_used() -> None:
    assert normalize_apex("customer.pages.dev") == "customer.pages.dev"
    with pytest.raises(ValueError):
        normalize_apex("pages.dev")


@pytest.mark.anyio
async def test_query_flags_are_strict(client: httpx.AsyncClient) -> None:
    bad_format = await client.get(
        "/v1/search",
        params={"apex": "example.com", "format": "xml"},
    )
    bad_dates = await client.get(
        "/v1/search",
        params={"apex": "example.com", "dates": 2},
    )

    assert bad_format.status_code == 422
    assert bad_dates.status_code == 422


@pytest.mark.anyio
async def test_rate_limit_is_atomic_and_stops_at_the_limit(tmp_path: Path) -> None:
    app = create_app(
        tmp_path / "limited.sqlite3",
        daily_request_limit=2,
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as limited_client,
    ):
        first = await limited_client.get(
            "/v1/search", params={"apex": "example.com"}
        )
        second = await limited_client.get(
            "/v1/search", params={"apex": "example.com"}
        )
        third = await limited_client.get(
            "/v1/search", params={"apex": "example.com"}
        )

    assert first.status_code == 200
    assert first.headers["x-ratelimit-remaining"] == "1"
    assert second.status_code == 200
    assert second.headers["x-ratelimit-remaining"] == "0"
    assert third.status_code == 429
    assert third.headers["x-ratelimit-remaining"] == "0"
    assert int(third.headers["retry-after"]) > 0


@pytest.mark.anyio
async def test_stats_and_readiness_do_not_spend_search_quota(
    client: httpx.AsyncClient,
) -> None:
    stats = await client.get("/v1/stats")
    ready = await client.get("/ready")
    search = await client.get("/v1/search", params={"apex": "example.com"})

    assert stats.status_code == 200
    assert stats.json() == {
        "apex_count": 1,
        "ct_hostname_count": 0,
        "ct_log_count": 0,
        "dated_hostname_count": 2,
        "hostname_count": 3,
        "last_ingest_at": None,
        "source_count": 0,
    }
    assert stats.headers["cache-control"] == "no-cache"
    assert ready.json() == {
        "status": "ready",
        "hostname_count": 3,
        "last_ingest_at": None,
    }
    assert search.headers["x-ratelimit-remaining"] == "999"


@pytest.mark.anyio
async def test_bearer_token_uses_a_separate_higher_allowance(tmp_path: Path) -> None:
    app = create_app(
        tmp_path / "token.sqlite3",
        daily_request_limit=1,
        api_tokens=["test-secret"],
        token_request_limit=3,
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as token_client,
    ):
        authenticated = await token_client.get(
            "/v1/search",
            params={"apex": "example.com"},
            headers={"Authorization": "Bearer test-secret"},
        )
        free = await token_client.get(
            "/v1/search",
            params={"apex": "example.com"},
        )
        free_exhausted = await token_client.get(
            "/v1/search",
            params={"apex": "example.com"},
        )

    assert authenticated.status_code == 200
    assert authenticated.headers["x-ratelimit-limit"] == "3"
    assert authenticated.headers["x-ratelimit-remaining"] == "2"
    assert free.status_code == 200
    assert free.headers["x-ratelimit-limit"] == "1"
    assert free_exhausted.status_code == 429
