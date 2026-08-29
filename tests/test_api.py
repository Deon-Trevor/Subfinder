from __future__ import annotations

import asyncio
import sqlite3
import threading
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

import ctlogs.app as app_module
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
    assert response.headers["server-timing"].startswith("admission;dur=")
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
async def test_private_batch_records_requires_token_and_charges_each_apex(
    tmp_path: Path,
) -> None:
    app = create_app(
        tmp_path / "batch-api.sqlite3",
        api_tokens=["threat-hunter-token"],
        token_request_limit=4,
        batch_max_apexes=3,
        batch_max_records=10,
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
        missing = await test_client.post(
            "/internal/v1/records/batch",
            json={"apexes": ["example.com"]},
        )
        forged = await test_client.post(
            "/internal/v1/records/batch",
            headers={"Authorization": "Bearer wrong"},
            json={"apexes": ["example.com"]},
        )
        first = await test_client.post(
            "/internal/v1/records/batch",
            headers={"Authorization": "Bearer threat-hunter-token"},
            json={"apexes": ["example.net", "example.com"]},
        )
        second = await test_client.post(
            "/internal/v1/records/batch",
            headers={"Authorization": "Bearer threat-hunter-token"},
            json={"apexes": ["example.com", "example.net"]},
        )
        exhausted = await test_client.post(
            "/internal/v1/records/batch",
            headers={"Authorization": "Bearer threat-hunter-token"},
            json={"apexes": ["example.com"]},
        )

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert forged.status_code == 401
    assert first.status_code == 200
    assert first.headers["cache-control"] == "no-store"
    assert first.headers["x-ratelimit-remaining"] == "2"
    assert first.headers["x-batch-apex-count"] == "2"
    assert first.json()["schema_version"] == (
        "subfinder.internal-index-records-batch.v1"
    )
    assert [item["apex"] for item in first.json()["results"]] == [
        "example.net",
        "example.com",
    ]
    assert first.json()["results"][0]["records"] == []
    assert first.json()["results"][1]["records"][0]["hostname"] == (
        "www.example.com"
    )
    assert second.status_code == 200
    assert second.headers["x-ratelimit-remaining"] == "0"
    assert exhausted.status_code == 429


@pytest.mark.anyio
async def test_private_batch_validates_bounds_before_consuming_quota(
    tmp_path: Path,
) -> None:
    app = create_app(
        tmp_path / "batch-bounds.sqlite3",
        api_tokens=["token"],
        token_request_limit=2,
        batch_max_apexes=2,
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    headers = {"Authorization": "Bearer token"}
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client,
    ):
        empty = await test_client.post(
            "/internal/v1/records/batch", headers=headers, json={"apexes": []}
        )
        duplicate = await test_client.post(
            "/internal/v1/records/batch",
            headers=headers,
            json={"apexes": ["example.com", "EXAMPLE.COM."]},
        )
        oversized = await test_client.post(
            "/internal/v1/records/batch",
            headers=headers,
            json={"apexes": ["example.com", "example.net", "example.org"]},
        )
        accepted = await test_client.post(
            "/internal/v1/records/batch",
            headers=headers,
            json={"apexes": ["example.com", "example.net"]},
        )

    assert empty.status_code == 400
    assert duplicate.status_code == 400
    assert oversized.status_code == 413
    assert accepted.status_code == 200
    assert accepted.headers["x-ratelimit-remaining"] == "0"


@pytest.mark.anyio
async def test_private_batch_refuses_an_unbounded_hostname_response(
    tmp_path: Path,
) -> None:
    app = create_app(
        tmp_path / "batch-result-bound.sqlite3",
        api_tokens=["token"],
        batch_max_records=1,
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
            [("one.example.com", None), ("two.example.com", None)],
        )
        response = await test_client.post(
            "/internal/v1/records/batch",
            headers={"Authorization": "Bearer token"},
            json={"apexes": ["example.com"]},
        )

    assert response.status_code == 413
    assert response.json() == {
        "detail": "batch contains 2 hostnames; maximum is 1; split the request"
    }


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
    assert first.headers["x-result-total"] == "3"
    assert first.headers["x-result-dated-total"] == "2"
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


@pytest.mark.anyio
async def test_overload_rejects_before_quota_and_reserves_service_capacity(
    tmp_path: Path,
) -> None:
    app = create_app(
        tmp_path / "capacity.sqlite3",
        api_tokens=["service-secret"],
        allowed_hosts=["testserver"],
        allowed_origins=[],
        public_inflight_limit=1,
        service_inflight_limit=1,
    )
    entered = threading.Event()
    release = threading.Event()
    original_admit_many = app.state.control_database.admit_many

    def blocking_admit_many(*args, **kwargs):
        entered.set()
        release.wait(timeout=2)
        return original_admit_many(*args, **kwargs)

    app.state.control_database.admit_many = blocking_admit_many
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client,
    ):
        first = asyncio.create_task(
            test_client.get("/v1/search", params={"apex": "example.com", "limit": 1})
        )
        assert await asyncio.to_thread(entered.wait, 1)

        overloaded, forged, health = await asyncio.gather(
            test_client.get("/v1/search", params={"apex": "example.net"}),
            test_client.get(
                "/v1/records",
                params={"apex": "example.org"},
                headers={"Authorization": "Bearer invalid"},
            ),
            test_client.get("/health"),
        )
        service = asyncio.create_task(
            test_client.get(
                "/v1/records",
                params={"apex": "example.org"},
                headers={"Authorization": "Bearer service-secret"},
            )
        )
        await asyncio.sleep(0.01)

        assert app.state.public_request_capacity.in_flight == 1
        assert app.state.service_request_capacity.in_flight == 1
        release.set()
        first_response, service_response = await asyncio.gather(first, service)

    assert first_response.status_code == 200
    assert service_response.status_code == 200
    assert overloaded.status_code == 503
    assert overloaded.headers["retry-after"] == "1"
    assert overloaded.headers["x-overload-reason"] == "public-capacity"
    assert forged.status_code == 503
    assert forged.headers["x-overload-reason"] == "public-capacity"
    assert health.status_code == 200

    with sqlite3.connect(tmp_path / "capacity-control.sqlite3") as connection:
        counts = connection.execute(
            "SELECT subject, used FROM request_counts ORDER BY subject"
        ).fetchall()
    assert sorted(used for _subject, used in counts) == [1, 1]


@pytest.mark.anyio
async def test_public_capacity_is_held_until_a_streamed_response_finishes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocking_stream(*_args, **_kwargs):
        entered.set()
        await release.wait()
        yield b"example.com\n"

    monkeypatch.setattr(app_module, "_cooperative_search_stream", blocking_stream)
    app = create_app(
        tmp_path / "stream-capacity.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
        public_inflight_limit=1,
    )
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client,
    ):
        first = asyncio.create_task(
            test_client.get("/v1/search", params={"apex": "example.com"})
        )
        await asyncio.wait_for(entered.wait(), timeout=1)

        overloaded = await test_client.get(
            "/v1/search", params={"apex": "example.net"}
        )
        assert app.state.public_request_capacity.in_flight == 1

        release.set()
        streamed = await first

    assert overloaded.status_code == 503
    assert streamed.status_code == 200
    assert streamed.text == "example.com\n"
    assert app.state.public_request_capacity.in_flight == 0


@pytest.mark.anyio
async def test_forwarded_client_identity_requires_a_trusted_socket_peer() -> None:
    observed: list[str] = []

    async def capture_client(scope, _receive, _send) -> None:
        observed.append(scope["client"][0])

    middleware = ProxyHeadersMiddleware(capture_client, trusted_hosts=["127.0.0.1"])

    async def receive() -> dict:
        return {"type": "http.disconnect"}

    async def send(_message: dict) -> None:
        return None

    base_scope = {
        "type": "http",
        "method": "GET",
        "path": "/v1/search",
        "headers": [(b"x-forwarded-for", b"198.18.0.1")],
        "scheme": "http",
        "server": ("testserver", 80),
    }
    await middleware(
        {**base_scope, "client": ("127.0.0.1", 40000)}, receive, send
    )
    await middleware(
        {**base_scope, "client": ("10.0.0.8", 40000)}, receive, send
    )

    assert observed == ["198.18.0.1", "10.0.0.8"]


@pytest.mark.parametrize(
    ("path", "protected"),
    [
        ("/v1/search", True),
        ("/v1/records", True),
        ("/internal/v1/records/batch", True),
        ("/mcp", True),
        ("/mcp/", True),
        ("/mcp/messages", True),
        ("/health", False),
        ("/ready", False),
        ("/v1/stats", False),
        ("/", False),
    ],
)
def test_capacity_boundary_covers_only_costly_request_paths(
    path: str,
    protected: bool,
) -> None:
    assert app_module._RequestCapacityMiddleware._protected_path(path) is protected


def test_public_edge_does_not_proxy_internal_data_plane_routes() -> None:
    config = (Path(__file__).resolve().parents[1] / "deploy/nginx.conf").read_text(
        encoding="utf-8"
    )
    internal = config.index("location ^~ /internal/")
    public = config.index("location / {", internal)

    assert "return 404;" in config[internal:public]


@pytest.mark.anyio
async def test_concurrent_admissions_share_control_transactions(tmp_path: Path) -> None:
    app = create_app(
        tmp_path / "batched-api.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    batch_sizes: list[int] = []
    original_admit_many = app.state.control_database.admit_many

    def record_batch(requests, **kwargs):
        batch_sizes.append(len(requests))
        return original_admit_many(requests, **kwargs)

    app.state.control_database.admit_many = record_batch
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client,
    ):
        responses = await asyncio.gather(
            *(
                test_client.get(
                    "/v1/search",
                    params={"apex": "example.com", "limit": 1},
                )
                for _index in range(20)
            )
        )

    assert {response.status_code for response in responses} == {200}
    assert sum(batch_sizes) == 20
    assert max(batch_sizes) > 1


@pytest.mark.anyio
async def test_cancellation_before_batch_selection_does_not_consume_quota(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CTLOGS_CONTROL_BATCH_WINDOW_SECONDS", "0.05")
    app = create_app(
        tmp_path / "cancel-before.sqlite3",
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
        request = asyncio.create_task(
            test_client.get("/v1/search", params={"apex": "example.com"})
        )
        await asyncio.sleep(0.005)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        await asyncio.sleep(0.06)

    with sqlite3.connect(tmp_path / "cancel-before-control.sqlite3") as connection:
        count = connection.execute("SELECT COUNT(*) FROM request_counts").fetchone()[0]
    assert count == 0


@pytest.mark.anyio
async def test_cancellation_after_batch_selection_keeps_committed_quota(
    tmp_path: Path,
) -> None:
    app = create_app(
        tmp_path / "cancel-after.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    selected = threading.Event()
    release = threading.Event()
    committed = threading.Event()
    original_admit_many = app.state.control_database.admit_many

    def blocking_admit_many(*args, **kwargs):
        selected.set()
        release.wait(timeout=2)
        outcomes = original_admit_many(*args, **kwargs)
        committed.set()
        return outcomes

    app.state.control_database.admit_many = blocking_admit_many
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client,
    ):
        request = asyncio.create_task(
            test_client.get("/v1/search", params={"apex": "example.com"})
        )
        assert await asyncio.to_thread(selected.wait, 1)
        request.cancel()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await request
        assert await asyncio.to_thread(committed.wait, 1)

    with sqlite3.connect(tmp_path / "cancel-after-control.sqlite3") as connection:
        used = connection.execute("SELECT SUM(used) FROM request_counts").fetchone()[0]
    assert used == 1


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
