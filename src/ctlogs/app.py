from __future__ import annotations

import contextlib
import os
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Literal

import tldextract
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from ctlogs.database import Database, Quota, QuotaExceeded

DAILY_REQUEST_LIMIT = 1_000
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
    cache_dir=None,
)


def normalize_apex(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ValueError("apex must be a valid eTLD+1") from error

    labels = candidate.split(".")
    if len(candidate) > 253 or any(not LABEL.fullmatch(label) for label in labels):
        raise ValueError("apex must be a valid eTLD+1")

    extracted = EXTRACT(candidate)
    if not extracted.domain or not extracted.suffix:
        raise ValueError("apex must be a valid eTLD+1")
    if extracted.subdomain or extracted.top_domain_under_public_suffix != candidate:
        raise ValueError("apex must be an eTLD+1")
    return candidate


def _client_ip(request: Request) -> str:
    if request.client is None:
        raise HTTPException(status_code=500, detail="client IP is unavailable")
    return request.client.host


def _quota_headers(quota: Quota) -> dict[str, str]:
    return {
        "X-RateLimit-Limit": str(quota.limit),
        "X-RateLimit-Remaining": str(quota.remaining),
        "X-RateLimit-Reset": str(quota.reset_at),
    }


def _retry_headers(quota: Quota) -> dict[str, str]:
    from time import time as unix_time

    headers = _quota_headers(quota)
    headers["Retry-After"] = str(max(1, quota.reset_at - int(unix_time())))
    return headers


def _csv_environment(name: str, defaults: list[str]) -> list[str]:
    raw = os.environ.get(name)
    if raw is None:
        return defaults
    return [item.strip() for item in raw.split(",") if item.strip()]


def create_app(
    database_path: str | Path | None = None,
    *,
    daily_request_limit: int = DAILY_REQUEST_LIMIT,
    allowed_hosts: list[str] | None = None,
    allowed_origins: list[str] | None = None,
) -> FastAPI:
    if daily_request_limit < 1:
        raise ValueError("daily_request_limit must be positive")

    path = database_path or os.environ.get("CTLOGS_DB_PATH", "data/ctlogs.sqlite3")
    database = Database(path)
    mcp = MCPServer(
        "CT Logs",
        instructions="Search the indexed passive subdomain corpus by registrable apex.",
    )

    def consume(client_ip: str) -> Quota:
        return database.consume_request(client_ip, daily_request_limit)

    @mcp.tool()
    async def search(apex: str, ctx: Context) -> list[str]:
        """Return every indexed hostname for one registrable apex.

        This only reads the passive index. It does not probe the apex or any
        returned hostname.
        """
        canonical = normalize_apex(apex)
        request = ctx.request_context.request
        client = getattr(request, "client", None)
        if client is None:
            raise RuntimeError("client IP is unavailable")
        try:
            consume(client.host)
        except QuotaExceeded as error:
            raise ValueError("daily request limit exceeded") from error
        return [row.subdomain for row in database.search(canonical)]

    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=(
            allowed_hosts
            if allowed_hosts is not None
            else _csv_environment(
                "CTLOGS_ALLOWED_HOSTS",
                ["127.0.0.1:*", "localhost:*", "[::1]:*"],
            )
        ),
        allowed_origins=(
            allowed_origins
            if allowed_origins is not None
            else _csv_environment(
                "CTLOGS_ALLOWED_ORIGINS",
                ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"],
            )
        ),
    )
    mcp_app = mcp.streamable_http_app(
        json_response=True,
        stateless_http=True,
        transport_security=security,
    )

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        database.initialize()
        # Auto-seed so `docker run` is immediately queryable without manual ingest
        try:
            from ctlogs.seed import seed_if_empty

            seed_if_empty(database)
        except Exception:
            pass
        async with mcp.session_manager.run():
            yield

    app = FastAPI(title="CT Logs API", version="1.0.0", lifespan=lifespan)
    app.state.database = database
    app.state.mcp = mcp

    @app.get("/v1/search")
    async def search_api(
        request: Request,
        apex: str,
        output_format: Literal["text", "json"] = Query(default="text", alias="format"),
        dates: int = Query(default=0, ge=0, le=1),
    ) -> Response:
        try:
            canonical = normalize_apex(apex)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        try:
            quota = consume(_client_ip(request))
        except QuotaExceeded as error:
            raise HTTPException(
                status_code=429,
                detail="daily request limit exceeded",
                headers=_retry_headers(error.quota),
            ) from error

        rows = database.search(canonical)
        headers = _quota_headers(quota)
        if output_format == "json":
            if dates:
                body = [
                    {"first_seen": row.first_seen, "sub": row.subdomain}
                    for row in rows
                ]
            else:
                body = [{"sub": row.subdomain} for row in rows]
            return JSONResponse(body, headers=headers)

        if dates:
            body = "".join(
                f"{row.subdomain}\t{row.first_seen or ''}\n"
                for row in rows
            )
        else:
            body = "".join(f"{row.subdomain}\n" for row in rows)
        return PlainTextResponse(body, headers=headers)

    # The root mount preserves the MCP SDK's exact /mcp route. FastAPI routes
    # are registered first because a root mount catches every remaining path.
    app.mount("/", mcp_app)
    return app


app = create_app()
