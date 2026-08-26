from __future__ import annotations

import contextlib
import asyncio
import hashlib
import logging
import os
import re
import secrets
import time
from functools import lru_cache
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Literal

import tldextract
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel

from ctlogs.database import Database, Quota, QuotaExceeded
from ctlogs.ingest.enrich import (
    DEFAULT_URLSCAN_DAILY_LIMIT,
    DEFAULT_URLSCAN_PRIORITY_DAILY_LIMIT,
    DEFAULT_URLSCAN_SEARCH_DAILY_LIMIT,
    URLSCAN_SEARCH_QUOTA_SUBJECT,
    URLSCAN_TOTAL_QUOTA_SUBJECT,
    EnrichmentSource,
    UrlscanSource,
    run_source,
    split_urlscan_budget,
)
from ctlogs.web import mount_frontend

DAILY_REQUEST_LIMIT = 1_000
RECORDS_SCHEMA_VERSION = "subfinder.index-records.v1"
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
LOGGER = logging.getLogger("ctlogs.app")
EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    include_psl_private_domains=True,
    cache_dir=None,
)


class SourceRecord(BaseModel):
    source: str
    first_seen: str | None
    last_seen: str


class HostnameRecord(BaseModel):
    hostname: str
    first_seen: str | None
    sources: list[SourceRecord]


class IndexRecordsResponse(BaseModel):
    schema_version: Literal["subfinder.index-records.v1"] = RECORDS_SCHEMA_VERSION
    apex: str
    records: list[HostnameRecord]


def _get_env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if parsed < 1:
        raise ValueError(f"{name} must be a positive integer")
    return parsed


@lru_cache(maxsize=2048)
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
    headers = _quota_headers(quota)
    headers["Retry-After"] = str(max(1, quota.reset_at - int(time.time())))
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
    api_tokens: list[str] | None = None,
    token_request_limit: int | None = None,
    allowed_hosts: list[str] | None = None,
    allowed_origins: list[str] | None = None,
    urlscan_source: EnrichmentSource | None = None,
    urlscan_daily_limit: int | None = None,
    urlscan_wait_seconds: float | None = None,
) -> FastAPI:
    if daily_request_limit < 1:
        raise ValueError("daily_request_limit must be positive")

    configured_tokens = (
        api_tokens
        if api_tokens is not None
        else _csv_environment("CTLOGS_API_TOKENS", [])
    )
    configured_tokens = [token for token in configured_tokens if token]
    authenticated_limit = (
        token_request_limit
        if token_request_limit is not None
        else _get_env_int("CTLOGS_TOKEN_REQUEST_LIMIT", 10_000)
    )
    if authenticated_limit < 1:
        raise ValueError("token_request_limit must be positive")

    path = database_path or os.environ.get("CTLOGS_DB_PATH", "data/ctlogs.sqlite3")
    database = Database(path)
    configured_urlscan_wait = (
        urlscan_wait_seconds
        if urlscan_wait_seconds is not None
        else float(_get_env_int("CTLOGS_URLSCAN_SEARCH_TIMEOUT", 5))
    )
    if configured_urlscan_wait <= 0:
        raise ValueError("urlscan_wait_seconds must be positive")
    configured_urlscan = urlscan_source
    if configured_urlscan is None:
        urlscan_key = os.environ.get("URLSCAN_API_KEY")
        if urlscan_key:
            configured_urlscan = UrlscanSource(
                urlscan_key,
                page_size=_get_env_int("CTLOGS_URLSCAN_SEARCH_PAGE_SIZE", 100),
                timeout=max(1, int(configured_urlscan_wait)),
            )
    configured_urlscan_limit = (
        urlscan_daily_limit
        if urlscan_daily_limit is not None
        else _get_env_int(
            "CTLOGS_URLSCAN_DAILY_LIMIT",
            DEFAULT_URLSCAN_DAILY_LIMIT,
        )
    )
    if configured_urlscan_limit < 1:
        raise ValueError("urlscan_daily_limit must be positive")
    configured_urlscan_budgets = split_urlscan_budget(
        configured_urlscan_limit,
        _get_env_int(
            "CTLOGS_URLSCAN_SEARCH_DAILY_LIMIT",
            DEFAULT_URLSCAN_SEARCH_DAILY_LIMIT,
        ),
        _get_env_int(
            "CTLOGS_URLSCAN_PRIORITY_DAILY_LIMIT",
            DEFAULT_URLSCAN_PRIORITY_DAILY_LIMIT,
        ),
    )
    mcp = MCPServer(
        "Subfinder",
        instructions=(
            "Refresh urlscan's newest results, queue deeper history, then "
            "search the passive subdomain index by registrable apex."
        ),
    )

    def consume(client_ip: str, authorization: str | None = None) -> Quota:
        if authorization and authorization.startswith("Bearer "):
            candidate = authorization.removeprefix("Bearer ").strip()
            if any(
                secrets.compare_digest(candidate, token)
                for token in configured_tokens
            ):
                subject = "token:" + hashlib.sha256(candidate.encode()).hexdigest()
                return database.consume_request(subject, authenticated_limit)
        return database.consume_request(client_ip, daily_request_limit)

    def refresh_urlscan(apex: str) -> str:
        if configured_urlscan is None:
            return "disabled"
        database.enqueue_urlscan_history(apex)
        try:
            run_source(
                database,
                configured_urlscan,
                [apex],
                max_requests=1,
                refresh=True,
                persist_state=False,
                request_guard=lambda: database.consume_partitioned_request(
                    URLSCAN_TOTAL_QUOTA_SUBJECT,
                    configured_urlscan_limit,
                    URLSCAN_SEARCH_QUOTA_SUBJECT,
                    configured_urlscan_budgets.search,
                ),
            )
        except QuotaExceeded:
            return "quota-exhausted"
        except Exception:
            LOGGER.exception("urlscan search refresh failed for %s", apex)
            return "error"
        return "ok"

    async def refresh_urlscan_before_search(apex: str) -> str:
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(refresh_urlscan, apex),
                timeout=configured_urlscan_wait,
            )
        except TimeoutError:
            LOGGER.warning("urlscan search refresh timed out for %s", apex)
            return "timeout"

    def _run_seed_if_needed() -> None:
        if os.environ.get("CTLOGS_AUTO_SEED") != "1":
            return

        try:
            from ctlogs.seed import seed_if_empty
        except Exception as error:
            LOGGER.error("Unable to import seed module: %s", error)
            return

        try:
            inserted = seed_if_empty(database)
        except Exception as error:
            LOGGER.error("Automatic seed failed: %s", error)
            return

        if inserted:
            LOGGER.info("Seeded database with %s rows", inserted)
        else:
            LOGGER.debug("Seed skipped: database already has data")

    def _run_worker() -> asyncio.Task[None] | None:
        if os.environ.get("CTLOGS_ENABLE_LIVE_CT") != "1":
            return None

        try:
            from ctlogs.worker import worker_loop

            interval = _get_env_int("CTLOGS_WORKER_INTERVAL", 60)
            batch = _get_env_int("CTLOGS_WORKER_BATCH_SIZE", 1024)
            initial_backfill = _get_env_int("CTLOGS_INITIAL_BACKFILL", 1024)
            max_batches = _get_env_int("CTLOGS_MAX_BATCHES_PER_LOG", 8)
            return asyncio.create_task(
                worker_loop(
                    database,
                    interval=interval,
                    batch=batch,
                    initial_backfill=initial_backfill,
                    max_batches=max_batches,
                )
            )
        except Exception as error:
            LOGGER.error("Unable to start live CT worker: %s", error)
            return None

    @mcp.tool()
    async def search(apex: str, ctx: Context) -> list[str]:
        """Refresh from urlscan, queue history, then return indexed hostnames.

        This searches existing urlscan records. It does not submit a live scan
        or probe the apex or any returned hostname. Deeper history continues in
        the background.
        """
        canonical = normalize_apex(apex)
        request = ctx.request_context.request
        client = getattr(request, "client", None)
        if client is None:
            raise RuntimeError("client IP is unavailable")
        try:
            consume(client.host, request.headers.get("authorization"))
        except QuotaExceeded as error:
            raise ValueError("daily request limit exceeded") from error
        await refresh_urlscan_before_search(canonical)
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
        _run_seed_if_needed()
        # Background CT poller - polls all usable Chrome/Apple logs (enabled in Docker via ENV=1)
        worker_task = _run_worker()
        async with mcp.session_manager.run():
            try:
                yield
            finally:
                if worker_task is not None:
                    worker_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await worker_task

    app = FastAPI(title="Subfinder API", version="1.0.0", lifespan=lifespan)
    app.state.database = database
    app.state.mcp = mcp

    @app.get("/health")
    async def health() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.get("/ready")
    async def ready() -> JSONResponse:
        stats = database.stats()
        return JSONResponse(
            {
                "status": "ready",
                "hostname_count": stats.hostname_count,
                "last_ingest_at": stats.last_ingest_at,
            },
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/v1/stats")
    async def index_stats() -> JSONResponse:
        stats = database.stats()
        return JSONResponse(
            {
                "apex_count": stats.apex_count,
                "dated_hostname_count": stats.dated_hostname_count,
                "hostname_count": stats.hostname_count,
                "ct_hostname_count": stats.ct_hostname_count,
                "ct_log_count": stats.ct_log_count,
                "last_ingest_at": stats.last_ingest_at,
                "source_count": stats.source_count,
            },
            headers={"Cache-Control": "no-cache"},
        )

    @app.get("/v1/records", response_model=IndexRecordsResponse)
    async def index_records(
        request: Request,
        response: Response,
        apex: str,
    ) -> IndexRecordsResponse:
        """Read local index records and source provenance without discovery."""
        try:
            canonical = normalize_apex(apex)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        try:
            quota = consume(
                _client_ip(request),
                request.headers.get("authorization"),
            )
        except QuotaExceeded as error:
            raise HTTPException(
                status_code=429,
                detail="daily request limit exceeded",
                headers=_retry_headers(error.quota),
            ) from error

        response.headers.update(_quota_headers(quota))
        response.headers["Cache-Control"] = "no-cache"
        response.headers["X-Subfinder-Schema-Version"] = RECORDS_SCHEMA_VERSION
        return IndexRecordsResponse(
            apex=canonical,
            records=[
                HostnameRecord(
                    hostname=record.hostname,
                    first_seen=record.first_seen,
                    sources=[
                        SourceRecord(
                            source=source.source,
                            first_seen=source.first_seen,
                            last_seen=source.last_seen,
                        )
                        for source in record.sources
                    ],
                )
                for record in database.records(canonical)
            ],
        )

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
            quota = consume(
                _client_ip(request),
                request.headers.get("authorization"),
            )
        except QuotaExceeded as error:
            raise HTTPException(
                status_code=429,
                detail="daily request limit exceeded",
                headers=_retry_headers(error.quota),
            ) from error

        urlscan_status = await refresh_urlscan_before_search(canonical)
        rows = database.search(canonical)
        headers = _quota_headers(quota)
        headers["X-URLScan-Status"] = urlscan_status
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
    mount_frontend(app)
    app.mount("/", mcp_app)
    return app


app = create_app()
