from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
import re

import httpx
import pytest

from ctlogs.app import create_app
from ctlogs.web import ASSETS, INDEX, MEDIA, frontend_directory


PUBLIC_PRODUCT_FILES = (
    Path("README.md"),
    Path("SOURCES.md"),
    Path("web/index.html"),
    Path("web/app.js"),
    Path("web/app.css"),
)


def _write_frontend(root: Path) -> Path:
    directory = root / "web"
    directory.mkdir()
    (directory / INDEX).write_text("<!doctype html><title>First Seen</title>")
    for name in (*ASSETS, *MEDIA):
        (directory / name).write_text(f"/* {name} */")
    return directory


def test_public_copy_describes_a_standalone_product() -> None:
    forbidden = re.compile(r"\bsubfaster\b|\bcrt\b", re.IGNORECASE)
    for path in PUBLIC_PRODUCT_FILES:
        assert forbidden.search(path.read_text()) is None, path


def test_frontend_never_calls_itself_this_service() -> None:
    for path in PUBLIC_PRODUCT_FILES[2:]:
        assert "this service" not in path.read_text().lower(), path


@pytest.fixture
async def client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[httpx.AsyncClient]:
    monkeypatch.setenv("CTLOGS_WEB_DIR", str(_write_frontend(tmp_path)))
    app = create_app(
        tmp_path / "test.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as test_client:
            yield test_client


@pytest.mark.anyio
async def test_page_is_served_at_the_root(client: httpx.AsyncClient) -> None:
    response = await client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert "First Seen" in response.text


@pytest.mark.anyio
@pytest.mark.parametrize(("name", "media_type"), sorted(ASSETS.items()))
async def test_assets_carry_their_own_content_type(
    client: httpx.AsyncClient, name: str, media_type: str
) -> None:
    response = await client.get(f"/{name}")

    assert response.status_code == 200
    assert response.headers["content-type"] == media_type


@pytest.mark.anyio
@pytest.mark.parametrize(("name", "media_type"), sorted(MEDIA.items()))
async def test_icons_carry_their_own_content_type(
    client: httpx.AsyncClient, name: str, media_type: str
) -> None:
    response = await client.get(f"/{name}")

    assert response.status_code == 200
    assert response.headers["content-type"] == media_type


@pytest.mark.anyio
async def test_page_and_assets_revalidate(client: httpx.AsyncClient) -> None:
    # The markup and the assets it is versioned with ship together, so a
    # browser must not pair new markup with a cached script.
    for path in ("/", *(f"/{name}" for name in ASSETS)):
        response = await client.get(path)

        assert response.headers["cache-control"] == "no-cache"


@pytest.mark.anyio
async def test_icons_are_cached_rather_than_revalidated(
    client: httpx.AsyncClient,
) -> None:
    # Icons are the same bytes across deploys and nothing pairs them with the
    # markup, so paying a conditional request for each one on every load is
    # waste the page does not need to spend.
    for name in MEDIA:
        response = await client.get(f"/{name}")

        assert response.headers["cache-control"] == "public, max-age=604800"


@pytest.mark.anyio
async def test_robots_keeps_crawlers_off_the_metered_routes(
    client: httpx.AsyncClient, tmp_path: Path
) -> None:
    # A crawler walking every "?apex=" link it finds would spend a visitor's
    # whole day of reads, so the real file has to name each metered path. The
    # fixture frontend holds a placeholder, so this reads the shipped one.
    rules = Path("web/robots.txt").read_text()

    for path in ("/v1/", "/mcp", "/*?apex="):
        assert f"Disallow: {path}" in rules

    response = await client.get("/robots.txt")

    assert response.status_code == 200


@pytest.mark.anyio
async def test_opening_the_page_spends_no_search_allowance(
    client: httpx.AsyncClient,
) -> None:
    # GET /v1/search and POST /mcp share one allowance of 1000 reads per IP per
    # UTC day. The frontend is a third caller on those same routes, so loading
    # it must leave the allowance untouched: a visitor who never searches has
    # spent nothing, and the first search still sees a full counter.
    for path in ("/", *(f"/{name}" for name in ASSETS)):
        response = await client.get(path)

        assert "X-RateLimit-Remaining" not in response.headers

    first_search = await client.get("/v1/search", params={"apex": "example.com"})

    assert first_search.status_code == 200
    assert first_search.headers["X-RateLimit-Remaining"] == "999"


@pytest.mark.anyio
async def test_the_live_counter_endpoint_spends_no_search_allowance(
    client: httpx.AsyncClient,
) -> None:
    # web/app.js polls /v1/stats every 15 seconds to drive the index counter.
    # That is only safe while the route stays outside the shared allowance: at
    # that interval a quota'd stats route would burn all 1,000 daily reads in
    # about four hours for a visitor who never searched. Twenty polls here
    # stand in for a page left open, and the search that follows must still see
    # a full counter.
    for _ in range(20):
        response = await client.get("/v1/stats")

        assert response.status_code == 200
        assert "X-RateLimit-Remaining" not in response.headers

    first_search = await client.get("/v1/search", params={"apex": "example.com"})

    assert first_search.headers["X-RateLimit-Remaining"] == "999"


@pytest.mark.anyio
async def test_the_counter_reads_the_fields_the_page_renders(
    client: httpx.AsyncClient,
) -> None:
    # Renaming any of these silently blanks a cell in the wire strip rather
    # than failing anything, so the contract is pinned from the reader's side.
    response = await client.get("/v1/stats")
    body = response.json()

    for field in (
        "apex_count",
        "ct_hostname_count",
        "ct_log_count",
        "dated_hostname_count",
        "hostname_count",
        "source_count",
    ):
        assert field in body, f"web/app.js renders {field}"
        assert isinstance(body[field], int)

    assert "last_ingest_at" in body


@pytest.mark.anyio
async def test_a_stray_file_in_the_directory_is_not_servable(
    client: httpx.AsyncClient, tmp_path: Path
) -> None:
    (tmp_path / "web" / "notes.txt").write_text("private")

    response = await client.get("/notes.txt")

    assert response.status_code == 404


@pytest.mark.anyio
async def test_the_mcp_route_survives_the_frontend_routes(
    client: httpx.AsyncClient,
) -> None:
    # The frontend registers named paths so it cannot shadow the root mount that
    # carries /mcp. A missing session id proves the MCP app answered.
    response = await client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Accept": "application/json, text/event-stream"},
    )

    assert response.status_code != 404


def test_a_missing_directory_leaves_the_api_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CTLOGS_WEB_DIR", str(tmp_path / "absent"))

    assert frontend_directory() is None

    app = create_app(
        tmp_path / "test.sqlite3",
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    served = {route.path for route in app.routes}

    assert "/health" in served
    assert f"/{next(iter(ASSETS))}" not in served
