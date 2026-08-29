from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from collections.abc import AsyncIterator, Iterable, Iterator
from dataclasses import dataclass
from functools import lru_cache, partial
from pathlib import Path
from threading import Lock
from typing import Literal

import tldextract
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import (
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import BaseModel

from ctlogs.control import (
    Admission,
    AdmissionRequest,
    ControlDatabase,
    ControlUnavailable,
)
from ctlogs.database import (
    BatchResultTooLarge,
    Database,
    Quota,
    QuotaExceeded,
    SearchCursor,
    SearchResult,
)
from ctlogs.web import mount_frontend

DAILY_REQUEST_LIMIT = 1_000
RECORDS_SCHEMA_VERSION = "subfinder.index-records.v1"
BATCH_RECORDS_SCHEMA_VERSION = "subfinder.internal-index-records-batch.v1"
STREAM_CHUNK_BYTES = 64 * 1024
INTERNAL_REQUEST_MAX_BYTES = 64 * 1024
LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
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


class BatchRecordsRequest(BaseModel):
    apexes: list[str]


class BatchRecordsResponse(BaseModel):
    schema_version: Literal["subfinder.internal-index-records-batch.v1"] = (
        BATCH_RECORDS_SCHEMA_VERSION
    )
    results: list[IndexRecordsResponse]


class _ImmediateCapacity:
    """Bound total in-flight requests without creating another wait queue."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._available = limit
        self._lock = Lock()

    def try_acquire(self) -> bool:
        with self._lock:
            if self._available == 0:
                return False
            self._available -= 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._available >= self.limit:
                raise RuntimeError("request capacity released without acquisition")
            self._available += 1

    @property
    def in_flight(self) -> int:
        with self._lock:
            return self.limit - self._available


class _RequestCapacityMiddleware:
    """Reserve independent public and authenticated-service request capacity."""

    def __init__(
        self,
        app,
        *,
        public_capacity: _ImmediateCapacity,
        service_capacity: _ImmediateCapacity,
        api_tokens: tuple[str, ...],
    ) -> None:
        self.app = app
        self.public_capacity = public_capacity
        self.service_capacity = service_capacity
        self.api_tokens = api_tokens

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or not self._protected_path(scope["path"]):
            await self.app(scope, receive, send)
            return

        authorization = next(
            (
                value.decode("latin-1")
                for name, value in scope.get("headers", ())
                if name.lower() == b"authorization"
            ),
            None,
        )
        service = _valid_bearer_token(authorization, self.api_tokens)
        if scope["path"].startswith("/internal/") and not service:
            response = JSONResponse(
                status_code=401,
                content={"detail": "a valid service token is required"},
                headers={
                    "Cache-Control": "no-store",
                    "WWW-Authenticate": "Bearer",
                },
            )
            await response(scope, receive, send)
            return
        if scope["path"].startswith("/internal/"):
            content_length = next(
                (
                    value.decode("latin-1")
                    for name, value in scope.get("headers", ())
                    if name.lower() == b"content-length"
                ),
                "0",
            )
            try:
                declared_bytes = int(content_length)
            except ValueError:
                declared_bytes = INTERNAL_REQUEST_MAX_BYTES + 1
            if declared_bytes > INTERNAL_REQUEST_MAX_BYTES:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "internal request body is too large"},
                    headers={"Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
                return
        capacity = self.service_capacity if service else self.public_capacity
        request_class = "service" if service else "public"
        if not capacity.try_acquire():
            response = JSONResponse(
                status_code=503,
                content={"detail": "request capacity is temporarily unavailable"},
                headers={
                    "Cache-Control": "no-store",
                    "Retry-After": "1",
                    "X-Overload-Reason": f"{request_class}-capacity",
                },
            )
            await response(scope, receive, send)
            return
        try:
            await self.app(scope, receive, send)
        finally:
            capacity.release()

    @staticmethod
    def _protected_path(path: str) -> bool:
        return (
            path in {
                "/v1/search",
                "/v1/records",
                "/internal/v1/records/batch",
                "/mcp",
            }
            or path.startswith("/mcp/")
        )


@dataclass(frozen=True)
class _PendingAdmission:
    request: AdmissionRequest
    future: asyncio.Future[Admission]


class _ControlBatcher:
    """Commit concurrent exact quota outcomes in one control transaction."""

    def __init__(self, control: ControlDatabase, window_seconds: float) -> None:
        self.control = control
        self.window_seconds = window_seconds
        self._pending: list[_PendingAdmission] = []
        self._drain_task: asyncio.Task[None] | None = None

    async def admit(self, request: AdmissionRequest) -> Admission:
        future = asyncio.get_running_loop().create_future()
        self._pending.append(_PendingAdmission(request, future))
        if self._drain_task is None:
            self._drain_task = asyncio.create_task(self._drain())
        return await future

    async def _drain(self) -> None:
        try:
            while self._pending:
                await asyncio.sleep(self.window_seconds)
                selected = [item for item in self._pending if not item.future.cancelled()]
                self._pending.clear()
                if not selected:
                    continue
                try:
                    outcomes = await asyncio.to_thread(
                        self.control.admit_many,
                        [item.request for item in selected],
                    )
                except Exception as error:
                    for item in selected:
                        if not item.future.cancelled():
                            item.future.set_exception(error)
                    continue
                for item, outcome in zip(selected, outcomes, strict=True):
                    if item.future.cancelled():
                        continue
                    if isinstance(outcome, Exception):
                        item.future.set_exception(outcome)
                    else:
                        item.future.set_result(outcome)
        finally:
            self._drain_task = None
            if self._pending:
                self._drain_task = asyncio.create_task(self._drain())


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


def _get_env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a number") from error
    if parsed <= 0:
        raise ValueError(f"{name} must be positive")
    return parsed


def _enabled(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    if value.lower() in {"1", "true", "yes"}:
        return True
    if value.lower() in {"0", "false", "no"}:
        return False
    raise ValueError(f"{name} must be 0 or 1")


def _encode_cursor(apex: str, cursor: SearchCursor) -> str:
    raw = json.dumps(
        [apex, cursor.first_seen, cursor.subdomain],
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(apex: str, value: str) -> SearchCursor:
    if len(value) > 2_048:
        raise ValueError("cursor is invalid")
    try:
        padded = value + "=" * (-len(value) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("cursor is invalid") from error
    if (
        not isinstance(payload, list)
        or len(payload) != 3
        or payload[0] != apex
        or (payload[1] is not None and not isinstance(payload[1], str))
        or not isinstance(payload[2], str)
    ):
        raise ValueError("cursor is invalid")
    return SearchCursor(subdomain=payload[2], first_seen=payload[1])


def _stream_search_rows(
    rows: Iterable[SearchResult],
    *,
    output_format: Literal["text", "json"],
    dates: bool,
) -> Iterator[bytes]:
    buffer = bytearray()
    first = True
    if output_format == "json":
        buffer.extend(b"[")
    for row in rows:
        if output_format == "json":
            if not first:
                buffer.extend(b",")
            value = (
                {"first_seen": row.first_seen, "sub": row.subdomain}
                if dates
                else {"sub": row.subdomain}
            )
            buffer.extend(json.dumps(value, separators=(",", ":")).encode())
        elif dates:
            buffer.extend(f"{row.subdomain}\t{row.first_seen or ''}\n".encode())
        else:
            buffer.extend(f"{row.subdomain}\n".encode())
        first = False
        if len(buffer) >= STREAM_CHUNK_BYTES:
            yield bytes(buffer)
            buffer.clear()
    if output_format == "json":
        buffer.extend(b"]")
    if buffer:
        yield bytes(buffer)


async def _cooperative_search_stream(
    rows: Iterable[SearchResult],
    *,
    output_format: Literal["text", "json"],
    dates: bool,
    slots: asyncio.Semaphore,
) -> AsyncIterator[bytes]:
    """Time-slice CPU-bound serialization instead of contending worker threads."""
    iterator = _stream_search_rows(
        rows,
        output_format=output_format,
        dates=dates,
    )
    exhausted = object()
    try:
        while True:
            async with slots:
                operation = asyncio.create_task(
                    asyncio.to_thread(next, iterator, exhausted)
                )
                try:
                    chunk = await asyncio.shield(operation)
                except asyncio.CancelledError:
                    await operation
                    raise
            if chunk is exhausted:
                return
            yield chunk
    finally:
        close = getattr(iterator, "close", None)
        if close is not None:
            await asyncio.to_thread(close)


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


def _valid_bearer_token(
    authorization: str | None,
    configured_tokens: Iterable[str],
) -> bool:
    if not authorization or not authorization.startswith("Bearer "):
        return False
    candidate = authorization.removeprefix("Bearer ").strip()
    return bool(candidate) and any(
        secrets.compare_digest(candidate, token) for token in configured_tokens
    )


def create_app(
    database_path: str | Path | None = None,
    *,
    control_database_path: str | Path | None = None,
    daily_request_limit: int = DAILY_REQUEST_LIMIT,
    api_tokens: list[str] | None = None,
    token_request_limit: int | None = None,
    allowed_hosts: list[str] | None = None,
    allowed_origins: list[str] | None = None,
    read_only_index: bool | None = None,
    enqueue_refresh: bool | None = None,
    public_inflight_limit: int | None = None,
    service_inflight_limit: int | None = None,
    batch_max_apexes: int | None = None,
    batch_max_records: int | None = None,
) -> FastAPI:
    if daily_request_limit < 1:
        raise ValueError("daily_request_limit must be positive")

    configured_tokens = (
        api_tokens
        if api_tokens is not None
        else _csv_environment("CTLOGS_API_TOKENS", [])
    )
    configured_tokens = [token for token in configured_tokens if token]
    public_capacity_limit = (
        public_inflight_limit
        if public_inflight_limit is not None
        else _get_env_int("CTLOGS_PUBLIC_INFLIGHT_LIMIT", 80)
    )
    service_capacity_limit = (
        service_inflight_limit
        if service_inflight_limit is not None
        else _get_env_int("CTLOGS_SERVICE_INFLIGHT_LIMIT", 16)
    )
    if public_capacity_limit < 1 or service_capacity_limit < 1:
        raise ValueError("request in-flight limits must be positive")
    authenticated_limit = (
        token_request_limit
        if token_request_limit is not None
        else _get_env_int("CTLOGS_TOKEN_REQUEST_LIMIT", 10_000)
    )
    if authenticated_limit < 1:
        raise ValueError("token_request_limit must be positive")
    configured_batch_max_apexes = (
        batch_max_apexes
        if batch_max_apexes is not None
        else _get_env_int("CTLOGS_BATCH_MAX_APEXES", 100)
    )
    configured_batch_max_records = (
        batch_max_records
        if batch_max_records is not None
        else _get_env_int("CTLOGS_BATCH_MAX_RECORDS", 5_000)
    )
    if configured_batch_max_apexes < 1 or configured_batch_max_records < 1:
        raise ValueError("batch limits must be positive")

    path = Path(
        database_path or os.environ.get("CTLOGS_DB_PATH", "data/ctlogs.sqlite3")
    )
    configured_read_only = (
        read_only_index
        if read_only_index is not None
        else _enabled("CTLOGS_INDEX_READ_ONLY", False)
    )
    database = Database(
        path,
        read_only=configured_read_only,
        busy_timeout_ms=_get_env_int("CTLOGS_INDEX_BUSY_TIMEOUT_MS", 500),
    )
    control_path = Path(
        control_database_path
        or os.environ.get(
            "CTLOGS_CONTROL_DB_PATH",
            str(path.with_name(f"{path.stem}-control.sqlite3")),
        )
    )
    control = ControlDatabase(
        control_path,
        busy_timeout_ms=_get_env_int("CTLOGS_CONTROL_BUSY_TIMEOUT_MS", 50),
        max_refresh_queue=_get_env_int("CTLOGS_MAX_REFRESH_QUEUE", 100_000),
    )
    configured_enqueue_refresh = (
        enqueue_refresh
        if enqueue_refresh is not None
        else _enabled("CTLOGS_ENQUEUE_SEARCH_REFRESH", True)
    )
    control_batch_window = _get_env_float(
        "CTLOGS_CONTROL_BATCH_WINDOW_SECONDS", 0.002
    )
    if control_batch_window < 0:
        raise ValueError("control batch window must not be negative")
    catalog_deadline = _get_env_float("CTLOGS_CATALOG_DEADLINE_SECONDS", 1.0)
    page_limit = _get_env_int("CTLOGS_MAX_PAGE_SIZE", 5_000)
    mcp_result_limit = _get_env_int("CTLOGS_MCP_RESULT_LIMIT", 100_000)
    control_batcher = _ControlBatcher(control, control_batch_window)
    # The read path is small and CPU-heavy enough that concurrent SQLite
    # readers lose badly to one serialized reader under a synchronized burst.
    catalog_slots = asyncio.Semaphore(_get_env_int("CTLOGS_CATALOG_CONCURRENCY", 1))
    stream_slots = asyncio.Semaphore(_get_env_int("CTLOGS_STREAM_CONCURRENCY", 1))
    mcp = MCPServer(
        "Subfinder",
        instructions=(
            "Read the committed passive subdomain index by registrable apex, "
            "then queue passive enrichment without making the caller wait."
        ),
    )

    def quota_subject(client_ip: str, authorization: str | None = None) -> tuple[str, int]:
        if _valid_bearer_token(authorization, configured_tokens):
            assert authorization is not None
            candidate = authorization.removeprefix("Bearer ").strip()
            subject = "token:" + hashlib.sha256(candidate.encode()).hexdigest()
            return subject, authenticated_limit
        return client_ip, daily_request_limit

    async def admit(
        client_ip: str,
        authorization: str | None,
        apex: str,
        *,
        refresh: bool,
    ) -> Admission:
        subject, limit = quota_subject(client_ip, authorization)
        return await control_batcher.admit(
            AdmissionRequest(
                subject,
                limit,
                apex,
                enqueue_refresh=refresh and configured_enqueue_refresh,
            )
        )

    def authenticated_subject(authorization: str | None) -> str:
        if not _valid_bearer_token(authorization, configured_tokens):
            raise HTTPException(
                status_code=401,
                detail="a valid service token is required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        assert authorization is not None
        candidate = authorization.removeprefix("Bearer ").strip()
        return "token:" + hashlib.sha256(candidate.encode()).hexdigest()

    async def catalog_call(function, *args, **kwargs):
        await asyncio.wait_for(catalog_slots.acquire(), timeout=catalog_deadline)
        try:
            return await asyncio.to_thread(partial(function, *args, **kwargs))
        finally:
            catalog_slots.release()

    @mcp.tool()
    async def search(apex: str, ctx: Context) -> list[str]:
        """Return indexed hostnames and queue passive enrichment."""
        canonical = normalize_apex(apex)
        request = ctx.request_context.request
        client = getattr(request, "client", None)
        if client is None:
            raise RuntimeError("client IP is unavailable")
        try:
            await admit(
                client.host,
                request.headers.get("authorization"),
                canonical,
                refresh=True,
            )
        except QuotaExceeded as error:
            raise ValueError("daily request limit exceeded") from error
        except (ControlUnavailable, TimeoutError) as error:
            raise RuntimeError("search admission is temporarily unavailable") from error
        rows, cursor = await catalog_call(
            database.search_page,
            canonical,
            after=None,
            limit=mcp_result_limit,
        )
        if cursor is not None:
            raise RuntimeError("result exceeds the MCP result limit; use the HTTP API")
        return [row.subdomain for row in rows]

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
        if database.read_only:
            database.verify_schema()
            control.verify_schema()
        else:
            database.initialize()
            control.initialize()
        async with mcp.session_manager.run():
            yield

    app = FastAPI(title="Subfinder API", version="1.0.0", lifespan=lifespan)
    public_capacity = _ImmediateCapacity(public_capacity_limit)
    service_capacity = _ImmediateCapacity(service_capacity_limit)
    app.add_middleware(
        _RequestCapacityMiddleware,
        public_capacity=public_capacity,
        service_capacity=service_capacity,
        api_tokens=tuple(configured_tokens),
    )
    app.state.database = database
    app.state.control_database = control
    app.state.mcp = mcp
    app.state.public_request_capacity = public_capacity
    app.state.service_request_capacity = service_capacity

    @app.get("/health")
    async def health() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.get("/ready")
    async def ready() -> JSONResponse:
        try:
            stats = await catalog_call(database.stats)
        except (sqlite3.Error, TimeoutError, RuntimeError) as error:
            raise HTTPException(
                status_code=503,
                detail="catalog is not ready",
                headers={"Retry-After": "1"},
            ) from error
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
        try:
            stats = await catalog_call(database.stats)
        except (sqlite3.Error, TimeoutError, RuntimeError) as error:
            raise HTTPException(
                status_code=503,
                detail="catalog statistics are temporarily unavailable",
                headers={"Retry-After": "1"},
            ) from error
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
        started = time.perf_counter()
        try:
            canonical = normalize_apex(apex)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        admission_started = time.perf_counter()
        try:
            admission = await admit(
                _client_ip(request),
                request.headers.get("authorization"),
                canonical,
                refresh=False,
            )
        except QuotaExceeded as error:
            raise HTTPException(
                status_code=429,
                detail="daily request limit exceeded",
                headers=_retry_headers(error.quota),
            ) from error
        except (ControlUnavailable, TimeoutError) as error:
            raise HTTPException(
                status_code=503,
                detail="search admission is temporarily unavailable",
                headers={"Retry-After": "1"},
            ) from error
        admission_ms = (time.perf_counter() - admission_started) * 1_000

        response.headers.update(_quota_headers(admission.quota))
        response.headers["Cache-Control"] = "no-cache"
        response.headers["X-Subfinder-Schema-Version"] = RECORDS_SCHEMA_VERSION

        def build_records() -> IndexRecordsResponse:
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

        catalog_started = time.perf_counter()
        try:
            records = await catalog_call(build_records)
        except (sqlite3.Error, TimeoutError, RuntimeError) as error:
            raise HTTPException(
                status_code=503,
                detail="catalog is temporarily unavailable",
                headers={"Retry-After": "1"},
            ) from error
        catalog_ms = (time.perf_counter() - catalog_started) * 1_000
        total_ms = (time.perf_counter() - started) * 1_000
        response.headers["Server-Timing"] = (
            f"admission;dur={admission_ms:.3f}, "
            f"catalog;dur={catalog_ms:.3f}, total;dur={total_ms:.3f}"
        )
        return records

    @app.post(
        "/internal/v1/records/batch",
        response_model=BatchRecordsResponse,
    )
    async def batch_index_records(
        request: Request,
        response: Response,
        body: BatchRecordsRequest,
    ) -> BatchRecordsResponse:
        """Read bounded index snapshots for trusted data-plane consumers."""
        started = time.perf_counter()
        authorization = request.headers.get("authorization")
        subject = authenticated_subject(authorization)
        if not body.apexes:
            raise HTTPException(status_code=400, detail="apexes must not be empty")
        if len(body.apexes) > configured_batch_max_apexes:
            raise HTTPException(
                status_code=413,
                detail=(
                    "batch contains too many apexes; maximum is "
                    f"{configured_batch_max_apexes}"
                ),
            )
        try:
            apexes = [normalize_apex(apex) for apex in body.apexes]
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        if len(set(apexes)) != len(apexes):
            raise HTTPException(status_code=400, detail="apexes must be unique")

        admission_started = time.perf_counter()
        try:
            quota = await asyncio.to_thread(
                control.consume,
                subject,
                authenticated_limit,
                len(apexes),
            )
        except QuotaExceeded as error:
            raise HTTPException(
                status_code=429,
                detail="daily request limit exceeded",
                headers=_retry_headers(error.quota),
            ) from error
        except (ControlUnavailable, TimeoutError) as error:
            raise HTTPException(
                status_code=503,
                detail="batch admission is temporarily unavailable",
                headers={"Retry-After": "1"},
            ) from error
        admission_ms = (time.perf_counter() - admission_started) * 1_000

        catalog_started = time.perf_counter()
        try:
            indexed = await catalog_call(
                database.records_many,
                apexes,
                max_records=configured_batch_max_records,
            )
        except BatchResultTooLarge as error:
            raise HTTPException(
                status_code=413,
                detail=(
                    f"batch contains {error.total} hostnames; maximum is "
                    f"{error.limit}; split the request"
                ),
            ) from error
        except (sqlite3.Error, TimeoutError, RuntimeError) as error:
            raise HTTPException(
                status_code=503,
                detail="catalog is temporarily unavailable",
                headers={"Retry-After": "1"},
            ) from error
        catalog_ms = (time.perf_counter() - catalog_started) * 1_000

        results = [
            IndexRecordsResponse(
                apex=apex,
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
                    for record in indexed[apex]
                ],
            )
            for apex in apexes
        ]
        total_ms = (time.perf_counter() - started) * 1_000
        response.headers.update(_quota_headers(quota))
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Subfinder-Schema-Version"] = (
            BATCH_RECORDS_SCHEMA_VERSION
        )
        response.headers["X-Request-ID"] = secrets.token_hex(8)
        response.headers["X-Batch-Apex-Count"] = str(len(apexes))
        response.headers["Server-Timing"] = (
            f"admission;dur={admission_ms:.3f}, "
            f"catalog;dur={catalog_ms:.3f}, total;dur={total_ms:.3f}"
        )
        return BatchRecordsResponse(results=results)

    @app.get("/v1/search")
    async def search_api(
        request: Request,
        apex: str,
        output_format: Literal["text", "json"] = Query(default="text", alias="format"),
        dates: int = Query(default=0, ge=0, le=1),
        limit: int | None = Query(default=None, ge=1, le=page_limit),
        cursor: str | None = Query(default=None),
    ) -> Response:
        started = time.perf_counter()
        try:
            canonical = normalize_apex(apex)
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        if cursor is not None and limit is None:
            raise HTTPException(status_code=400, detail="cursor requires limit")
        try:
            after = _decode_cursor(canonical, cursor) if cursor is not None else None
        except ValueError as error:
            raise HTTPException(status_code=400, detail=str(error)) from error

        admission_started = time.perf_counter()
        try:
            admission = await admit(
                _client_ip(request),
                request.headers.get("authorization"),
                canonical,
                refresh=True,
            )
        except QuotaExceeded as error:
            raise HTTPException(
                status_code=429,
                detail="daily request limit exceeded",
                headers=_retry_headers(error.quota),
            ) from error
        except (ControlUnavailable, TimeoutError) as error:
            raise HTTPException(
                status_code=503,
                detail="search admission is temporarily unavailable",
                headers={"Retry-After": "1"},
            ) from error
        admission_ms = (time.perf_counter() - admission_started) * 1_000

        try:
            watermark = await catalog_call(database.watermark)
        except (sqlite3.Error, TimeoutError, RuntimeError) as error:
            raise HTTPException(
                status_code=503,
                detail="catalog is temporarily unavailable",
                headers={"Retry-After": "1"},
            ) from error

        headers = _quota_headers(admission.quota)
        headers["Cache-Control"] = "no-store"
        headers["X-Refresh-Status"] = admission.refresh_status
        headers["X-URLScan-Status"] = admission.refresh_status
        headers["X-Request-ID"] = secrets.token_hex(8)
        if watermark is not None:
            headers["X-Index-As-Of"] = watermark

        if limit is not None:
            query_started = time.perf_counter()
            try:
                rows, next_cursor, total, dated_total = await catalog_call(
                    database.search_page_with_counts,
                    canonical,
                    after=after,
                    limit=limit,
                )
                body = await catalog_call(
                    lambda: b"".join(
                        _stream_search_rows(
                            rows,
                            output_format=output_format,
                            dates=bool(dates),
                        )
                    )
                )
            except (sqlite3.Error, TimeoutError, RuntimeError) as error:
                raise HTTPException(
                    status_code=503,
                    detail="catalog is temporarily unavailable",
                    headers={"Retry-After": "1"},
                ) from error
            query_ms = (time.perf_counter() - query_started) * 1_000
            headers["X-Result-Page-Size"] = str(len(rows))
            headers["X-Result-Total"] = str(total)
            headers["X-Result-Dated-Total"] = str(dated_total)
            headers["X-Result-Truncated"] = str(next_cursor is not None).lower()
            if next_cursor is not None:
                encoded = _encode_cursor(canonical, next_cursor)
                headers["X-Next-Cursor"] = encoded
                next_url = request.url.include_query_params(limit=limit, cursor=encoded)
                headers["Link"] = f'<{next_url}>; rel="next"'
            total_ms = (time.perf_counter() - started) * 1_000
            headers["Server-Timing"] = (
                f"admission;dur={admission_ms:.3f}, "
                f"catalog;dur={query_ms:.3f}, total;dur={total_ms:.3f}"
            )
            media_type = "application/json" if output_format == "json" else "text/plain"
            return Response(content=body, media_type=media_type, headers=headers)

        headers["X-Result-Truncated"] = "false"
        headers["Server-Timing"] = f"admission;dur={admission_ms:.3f}"
        rows = database.iter_search(canonical)
        media_type = "application/json" if output_format == "json" else "text/plain"
        return StreamingResponse(
            _cooperative_search_stream(
                rows,
                output_format=output_format,
                dates=bool(dates),
                slots=stream_slots,
            ),
            media_type=media_type,
            headers=headers,
        )

    # The root mount preserves the MCP SDK's exact /mcp route. FastAPI routes
    # are registered first because a root mount catches every remaining path.
    mount_frontend(app)
    app.mount("/", mcp_app)
    return app


app = create_app()
