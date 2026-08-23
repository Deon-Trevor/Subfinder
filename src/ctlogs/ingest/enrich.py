from __future__ import annotations

import argparse
import json
import os
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from ctlogs.database import Database

DEFAULT_URLSCAN_DAILY_LIMIT = 100_000
URLSCAN_QUOTA_SUBJECT = "provider:urlscan"


@dataclass(frozen=True)
class SourcePage:
    rows: list[tuple[str, str | None]]
    next_cursor: str | None
    bytes_read: int


class EnrichmentSource(Protocol):
    name: str

    def fetch_page(self, apex: str, cursor: str | None) -> SourcePage: ...


def _canonical_hostname(value: object, apex: str) -> str | None:
    if not isinstance(value, str):
        return None
    hostname = value.removeprefix("*.").strip().lower().rstrip(".")
    if hostname != apex and not hostname.endswith(f".{apex}"):
        return None
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def _json_request(
    url: str,
    *,
    headers: dict[str, str],
    body: dict[str, Any] | None = None,
    timeout: int = 30,
    opener=urllib.request.urlopen,
) -> tuple[dict[str, Any], int]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, headers=headers)
    with opener(request, timeout=timeout) as response:
        raw = response.read()
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("source returned a non-object JSON response")
    return parsed, len(raw)


class UrlscanSource:
    name = "urlscan"

    def __init__(
        self,
        api_key: str,
        *,
        page_size: int = 1000,
        timeout: int = 30,
        opener=urllib.request.urlopen,
    ) -> None:
        self.api_key = api_key
        self.page_size = page_size
        self.timeout = timeout
        self.opener = opener

    def fetch_page(self, apex: str, cursor: str | None) -> SourcePage:
        params = {"q": f"page.domain:{apex}", "size": str(self.page_size)}
        if cursor:
            params["search_after"] = cursor
        url = "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode(params)
        payload, size = _json_request(
            url,
            headers={"api-key": self.api_key, "User-Agent": "ctlogs/0.1"},
            timeout=self.timeout,
            opener=self.opener,
        )
        rows: list[tuple[str, str | None]] = []
        results = payload.get("results") or []
        for result in results:
            observed = (result.get("task") or {}).get("time")
            for value in (
                (result.get("page") or {}).get("domain"),
                (result.get("task") or {}).get("domain"),
            ):
                hostname = _canonical_hostname(value, apex)
                if hostname:
                    rows.append((hostname, observed if isinstance(observed, str) else None))
        next_cursor = None
        if len(results) == self.page_size and results:
            sort = results[-1].get("sort")
            if isinstance(sort, list) and sort:
                next_cursor = ",".join(str(value) for value in sort)
        return SourcePage(rows, next_cursor, size)


def run_source(
    database: Database,
    source: EnrichmentSource,
    apexes: list[str],
    *,
    max_requests: int,
    refresh: bool = False,
    request_guard: Callable[[], object] | None = None,
) -> tuple[int, int]:
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    request_count = 0
    hostname_count = 0
    bytes_read = 0
    apex_count = 0

    for apex in apexes:
        state_key = f"enrich:{source.name}:{apex}"
        state = database.get_ingest_state(state_key)
        if state and state.get("cursor") == "complete" and not refresh:
            continue
        cursor = None if refresh or not state else state.get("cursor")
        apex_count += 1
        while request_count < max_requests:
            if request_guard is not None:
                request_guard()
            page = source.fetch_page(apex, cursor)
            request_count += 1
            bytes_read += page.bytes_read
            if page.rows:
                database.upsert_subdomains(apex, page.rows, source=source.name)
                hostname_count += len(page.rows)
            cursor = page.next_cursor
            database.upsert_ingest_state(
                state_key,
                cursor=cursor or "complete",
                updated_at=datetime.now(UTC).isoformat(),
            )
            if cursor is None:
                break
        if request_count >= max_requests:
            break

    finished_at = datetime.now(UTC).isoformat()
    database.record_ingest_run(
        source.name,
        started_at,
        finished_at,
        apex_count,
        hostname_count,
        int((time.monotonic() - started) * 1000),
        bytes_read,
    )
    return request_count, hostname_count


def _source_from_environment(name: str, timeout: int) -> EnrichmentSource:
    if name == "urlscan":
        token = os.environ.get("URLSCAN_API_KEY")
        if not token:
            raise ValueError("URLSCAN_API_KEY is required")
        return UrlscanSource(token, timeout=timeout)
    raise ValueError(f"unsupported enrichment source: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded per-apex enrichment jobs")
    parser.add_argument("--db", default="data/ctlogs.sqlite3")
    parser.add_argument("--source", choices=("urlscan",), required=True)
    parser.add_argument("--apex", action="append", required=True)
    parser.add_argument("--max-requests", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()
    if args.max_requests < 1 or args.timeout < 1:
        parser.error("max-requests and timeout must be positive")

    database = Database(args.db)
    database.initialize()
    try:
        source = _source_from_environment(args.source, args.timeout)
    except ValueError as error:
        parser.error(str(error))
    requests, hostnames = run_source(
        database,
        source,
        [apex.lower().rstrip(".") for apex in args.apex],
        max_requests=args.max_requests,
        refresh=args.refresh,
    )
    print(f"{args.source}: requests={requests} hostnames={hostnames}")


if __name__ == "__main__":
    main()
