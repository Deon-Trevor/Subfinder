from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

from ctlogs.app import create_app, normalize_apex


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
