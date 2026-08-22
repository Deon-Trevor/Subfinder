from __future__ import annotations

from pathlib import Path

import httpx
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types.version import LATEST_MODERN_VERSION

from ctlogs.app import create_app


@pytest.mark.anyio
async def test_mcp_search_uses_the_same_ip_budget_as_http(tmp_path: Path) -> None:
    app = create_app(
        tmp_path / "mcp.sqlite3",
        daily_request_limit=2,
        allowed_hosts=["testserver"],
        allowed_origins=[],
    )
    app.state.database.initialize()
    app.state.database.upsert_subdomains(
        "example.com",
        [
            ("example.com", "2024-01-02T03:04:05Z"),
            ("www.example.com", "2025-02-03T04:05:06Z"),
        ],
    )

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as http_client,
        httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url="http://testserver",
        ) as mcp_http_client,
    ):
        first = await http_client.get(
            "/v1/search",
            params={"apex": "example.com"},
        )
        transport = streamable_http_client(
            "http://testserver/mcp",
            http_client=mcp_http_client,
        )
        async with Client(transport, mode=LATEST_MODERN_VERSION) as mcp_client:
            listed = await mcp_client.list_tools()
            result = await mcp_client.call_tool("search", {"apex": "example.com"})
        exhausted = await http_client.get(
            "/v1/search",
            params={"apex": "example.com"},
        )

    assert first.status_code == 200
    assert [tool.name for tool in listed.tools] == ["search"]
    assert result.structured_content == {
        "result": ["example.com", "www.example.com"]
    }
    assert exhausted.status_code == 429
