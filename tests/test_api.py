from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
import asyncio
import time

import httpx
import pytest

from ctlogs.app import create_app, normalize_apex
from ctlogs.ingest.enrich import SourcePage, URLSCAN_QUOTA_SUBJECT


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
async def test_search_refreshes_urlscan_before_reading_the_local_index(
    tmp_path: Path,
) -> None:
    events: list[str] = []

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            events.append("urlscan")
            return SourcePage(
                [(f"fresh.{apex}", "2026-08-23T10:00:00Z")],
                None,
                10,
            )

    app = create_app(
        tmp_path / "urlscan.sqlite3",
        urlscan_source=Source(),
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with app.router.lifespan_context(app):
        original_search = app.state.database.search

        def tracked_search(apex: str):
            events.append("local")
            return original_search(apex)

        app.state.database.search = tracked_search
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client:
            response = await test_client.get(
                "/v1/search",
                params={"apex": "example.com", "format": "json"},
            )

    assert response.status_code == 200
    assert response.headers["x-urlscan-status"] == "ok"
    assert response.json() == [{"sub": "fresh.example.com"}]
    assert events == ["urlscan", "local"]


@pytest.mark.anyio
async def test_search_falls_back_to_local_when_urlscan_fails(tmp_path: Path) -> None:
    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            raise OSError("provider unavailable")

    app = create_app(
        tmp_path / "fallback.sqlite3",
        urlscan_source=Source(),
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with app.router.lifespan_context(app):
        app.state.database.upsert_subdomains(
            "example.com",
            [("cached.example.com", None)],
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client:
            response = await test_client.get(
                "/v1/search",
                params={"apex": "example.com"},
            )

    assert response.status_code == 200
    assert response.headers["x-urlscan-status"] == "error"
    assert response.text == "cached.example.com\n"


@pytest.mark.anyio
async def test_search_has_a_wall_clock_urlscan_limit(tmp_path: Path) -> None:
    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            time.sleep(0.2)
            return SourcePage([], None, 1)

    app = create_app(
        tmp_path / "timeout.sqlite3",
        urlscan_source=Source(),
        urlscan_wait_seconds=0.01,
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with app.router.lifespan_context(app):
        app.state.database.upsert_subdomains(
            "example.com",
            [("cached.example.com", None)],
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client:
            started = time.monotonic()
            response = await test_client.get(
                "/v1/search",
                params={"apex": "example.com"},
            )
            elapsed = time.monotonic() - started
            await asyncio.sleep(0.21)

    assert response.headers["x-urlscan-status"] == "timeout"
    assert response.text == "cached.example.com\n"
    assert elapsed < 0.15


@pytest.mark.anyio
async def test_api_honors_the_shared_urlscan_daily_ceiling(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class Source:
        name = "urlscan"

        def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
            calls.append(apex)
            return SourcePage([], None, 2)

    app = create_app(
        tmp_path / "provider-quota.sqlite3",
        urlscan_source=Source(),
        urlscan_daily_limit=1,
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
        app.state.database.consume_request(URLSCAN_QUOTA_SUBJECT, 1)
        response = await test_client.get(
            "/v1/search", params={"apex": "example.net"}
        )

    assert response.headers["x-urlscan-status"] == "quota-exhausted"
    assert calls == []


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
