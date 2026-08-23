from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import logging
import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ctlogs.database import Database
from ctlogs.ingest.backfill import (
    DEFAULT_JOBS,
    DEFAULT_MAX_BYTES,
    _adapter,
    _parse_job,
    run_job,
)
from ctlogs.ingest.czds import CzdsClient, run_czds
from ctlogs.ingest.enrich import (
    DEFAULT_URLSCAN_DAILY_LIMIT,
    URLSCAN_QUOTA_SUBJECT,
    UrlscanSource,
    run_source,
)

LOGGER = logging.getLogger("ctlogs.scheduler")
DEFAULT_INTERVAL_SECONDS = 24 * 60 * 60
DEFAULT_RETRY_SECONDS = 60 * 60
ALL_INDEXED_APEXES = "*"


@dataclass(frozen=True)
class ScheduledJob:
    name: str
    interval_seconds: int
    retry_seconds: int
    action: Callable[[], object]


def _positive_environment_integer(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        result = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if result < 1:
        raise ValueError(f"{name} must be positive")
    return result


def _enabled(name: str, default: bool = True) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    if value in {"1", "true", "yes"}:
        return True
    if value in {"0", "false", "no"}:
        return False
    raise ValueError(f"{name} must be 0 or 1")


def _apexes_from_environment() -> list[str]:
    apexes: list[str] = []
    for raw in os.environ.get("CTLOGS_URLSCAN_APEXES", "").split(","):
        apex = raw.strip().lower().rstrip(".")
        if not apex:
            continue
        if apex == ALL_INDEXED_APEXES:
            apexes.append(apex)
            continue
        try:
            apex = apex.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError(f"invalid urlscan apex: {raw!r}") from error
        if "." not in apex:
            raise ValueError(f"invalid urlscan apex: {raw!r}")
        apexes.append(apex)
    result = list(dict.fromkeys(apexes))
    if ALL_INDEXED_APEXES in result and len(result) != 1:
        raise ValueError("'*' cannot be combined with explicit urlscan apexes")
    return result


def _scheduled_artifacts() -> list[tuple[str, str]]:
    raw = os.environ.get("CTLOGS_SCHEDULED_ARTIFACTS", "[]")
    try:
        values = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("CTLOGS_SCHEDULED_ARTIFACTS must be a JSON list") from error
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("CTLOGS_SCHEDULED_ARTIFACTS must be a JSON list of strings")
    jobs: list[tuple[str, str]] = []
    for value in values:
        source, location = _parse_job(value)
        _adapter(source)
        jobs.append((source, location))
    return jobs


def _run_urlscan_batch(
    database: Database,
    source: UrlscanSource,
    apexes: list[str],
    *,
    apexes_per_run: int,
    request_guard: Callable[[], object] | None = None,
) -> tuple[int, int]:
    state_key = "scheduler:urlscan:rotation"
    state = database.get_ingest_state(state_key)
    start = int(state["cursor"]) if state and str(state.get("cursor", "")).isdigit() else 0
    count = min(apexes_per_run, len(apexes))
    selected = [apexes[(start + offset) % len(apexes)] for offset in range(count)]
    requests = 0
    hostnames = 0
    failures = 0
    for apex in selected:
        try:
            source_requests, source_hostnames = run_source(
                database,
                source,
                [apex],
                max_requests=1,
                refresh=True,
                request_guard=request_guard,
            )
            requests += source_requests
            hostnames += source_hostnames
        except Exception:
            failures += 1
            LOGGER.exception("urlscan refresh failed for %s", apex)
    database.upsert_ingest_state(
        state_key,
        cursor=str((start + count) % len(apexes)),
        updated_at=datetime.now(UTC).isoformat(),
    )
    if failures:
        raise RuntimeError(f"urlscan failed for {failures} configured apexes")
    return requests, hostnames


def _run_urlscan_index_batch(
    database: Database,
    source: UrlscanSource,
    *,
    apexes_per_run: int,
    request_guard: Callable[[], object] | None = None,
) -> tuple[int, int]:
    state_key = "scheduler:urlscan:index-cursor"
    state = database.get_ingest_state(state_key)
    cursor = str(state.get("cursor") or "") if state else ""
    apexes = database.apexes_after(cursor, apexes_per_run)
    if not apexes:
        database.upsert_ingest_state(
            state_key,
            cursor="",
            updated_at=datetime.now(UTC).isoformat(),
        )
        return 0, 0

    requests = 0
    hostnames = 0
    for apex in apexes:
        source_requests, source_hostnames = run_source(
            database,
            source,
            [apex],
            max_requests=1,
            refresh=True,
            request_guard=request_guard,
        )
        requests += source_requests
        hostnames += source_hostnames
        database.upsert_ingest_state(
            state_key,
            cursor=apex,
            updated_at=datetime.now(UTC).isoformat(),
        )
    return requests, hostnames


def build_jobs(database: Database) -> list[ScheduledJob]:
    interval = _positive_environment_integer(
        "CTLOGS_SCHEDULER_INTERVAL",
        DEFAULT_INTERVAL_SECONDS,
    )
    retry = _positive_environment_integer(
        "CTLOGS_SCHEDULER_RETRY_INTERVAL",
        DEFAULT_RETRY_SECONDS,
    )
    timeout = _positive_environment_integer("CTLOGS_SCHEDULER_TIMEOUT", 60)
    max_bytes = _positive_environment_integer(
        "CTLOGS_SCHEDULER_MAX_BYTES",
        DEFAULT_MAX_BYTES,
    )
    jobs: list[ScheduledJob] = []

    if _enabled("CTLOGS_SCHEDULE_DEFAULTS"):
        for source, location in DEFAULT_JOBS:
            jobs.append(
                ScheduledJob(
                    source,
                    interval,
                    retry,
                    lambda source=source, location=location: run_job(
                        database,
                        source,
                        location,
                        timeout=timeout,
                        max_bytes=max_bytes,
                    ),
                )
            )

    for source, location in _scheduled_artifacts():
        digest = hashlib.sha256(location.encode()).hexdigest()[:12]
        jobs.append(
            ScheduledJob(
                f"artifact:{source}:{digest}",
                interval,
                retry,
                lambda source=source, location=location: run_job(
                    database,
                    source,
                    location,
                    timeout=timeout,
                    max_bytes=max_bytes,
                ),
            )
        )

    username = os.environ.get("CZDS_USERNAME")
    password = os.environ.get("CZDS_PASSWORD")
    if bool(username) != bool(password):
        raise ValueError("CZDS_USERNAME and CZDS_PASSWORD must be set together")
    if username and password and _enabled("CTLOGS_SCHEDULE_CZDS"):
        output = Path(os.environ.get("CTLOGS_CZDS_OUTPUT", "/data/czds"))
        max_zones = _positive_environment_integer("CTLOGS_CZDS_MAX_ZONES", 25)
        jobs.append(
            ScheduledJob(
                "czds",
                interval,
                retry,
                lambda: run_czds(
                    database,
                    CzdsClient(username, password, timeout=timeout),
                    output,
                    max_zones=max_zones,
                    refresh=True,
                ),
            )
        )

    urlscan_key = os.environ.get("URLSCAN_API_KEY")
    urlscan_apexes = _apexes_from_environment()
    if urlscan_apexes and not urlscan_key:
        raise ValueError("URLSCAN_API_KEY is required when CTLOGS_URLSCAN_APEXES is set")
    if urlscan_key and urlscan_apexes and _enabled("CTLOGS_SCHEDULE_URLSCAN"):
        apexes_per_run = _positive_environment_integer(
            "CTLOGS_URLSCAN_APEXES_PER_RUN",
            10,
        )
        urlscan_interval = _positive_environment_integer(
            "CTLOGS_URLSCAN_INTERVAL",
            interval,
        )
        urlscan_retry = _positive_environment_integer(
            "CTLOGS_URLSCAN_RETRY_INTERVAL",
            retry,
        )
        urlscan_daily_limit = _positive_environment_integer(
            "CTLOGS_URLSCAN_DAILY_LIMIT",
            DEFAULT_URLSCAN_DAILY_LIMIT,
        )
        request_guard = lambda: database.consume_request(
            URLSCAN_QUOTA_SUBJECT,
            urlscan_daily_limit,
        )
        if urlscan_apexes == [ALL_INDEXED_APEXES]:
            urlscan_action = lambda: _run_urlscan_index_batch(
                database,
                UrlscanSource(urlscan_key, timeout=timeout),
                apexes_per_run=apexes_per_run,
                request_guard=request_guard,
            )
        else:
            urlscan_action = lambda: _run_urlscan_batch(
                database,
                UrlscanSource(urlscan_key, timeout=timeout),
                urlscan_apexes,
                apexes_per_run=apexes_per_run,
                request_guard=request_guard,
            )
        jobs.append(
            ScheduledJob(
                "urlscan",
                urlscan_interval,
                urlscan_retry,
                urlscan_action,
            )
        )
    return jobs


def _next_due(database: Database, job: ScheduledJob) -> datetime | None:
    state = database.get_ingest_state(f"scheduler:{job.name}")
    if not state or not state.get("cursor"):
        return None
    try:
        result = datetime.fromisoformat(str(state["cursor"]))
    except ValueError:
        return None
    return result if result.tzinfo is not None else None


def run_due_jobs(
    database: Database,
    jobs: list[ScheduledJob],
    *,
    now: datetime | None = None,
) -> dict[str, str]:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise ValueError("now must include a timezone")
    outcomes: dict[str, str] = {}
    for job in jobs:
        due = _next_due(database, job)
        if due is not None and due > current:
            continue
        try:
            result = job.action()
        except Exception as error:
            LOGGER.exception("scheduled job %s failed", job.name)
            delay = job.retry_seconds
            status = f"error:{type(error).__name__}"
        else:
            LOGGER.info("scheduled job %s completed: %r", job.name, result)
            delay = job.interval_seconds
            status = "ok"
        finished = now or datetime.now(UTC)
        database.upsert_ingest_state(
            f"scheduler:{job.name}",
            cursor=(finished + timedelta(seconds=delay)).isoformat(),
            etag=status,
            updated_at=finished.isoformat(),
        )
        outcomes[job.name] = status
    return outcomes


@contextmanager
def _singleton_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError(f"scheduler lock is already held: {path}") from error
        yield


def run_forever(database: Database, jobs: list[ScheduledJob], tick_seconds: int) -> None:
    LOGGER.info("scheduler started with jobs: %s", ", ".join(job.name for job in jobs))
    while True:
        run_due_jobs(database, jobs)
        time.sleep(tick_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run recurring ingestion jobs")
    parser.add_argument("--db", default=os.environ.get("CTLOGS_DB_PATH", "data/ctlogs.sqlite3"))
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=os.environ.get("CTLOGS_LOG_LEVEL", "INFO"))

    database = Database(args.db)
    database.initialize()
    jobs = build_jobs(database)
    if os.environ.get("URLSCAN_API_KEY") and not os.environ.get("CTLOGS_URLSCAN_APEXES"):
        LOGGER.warning("urlscan is disabled because CTLOGS_URLSCAN_APEXES is empty")
    if args.list:
        for job in jobs:
            print(f"{job.name}: every {job.interval_seconds}s, retry {job.retry_seconds}s")
        return
    lock_path = Path(os.environ.get("CTLOGS_SCHEDULER_LOCK", "/data/scheduler.lock"))
    with _singleton_lock(lock_path):
        if args.once:
            outcomes = run_due_jobs(database, jobs)
            if any(status != "ok" for status in outcomes.values()):
                raise SystemExit(1)
            return
        tick = _positive_environment_integer("CTLOGS_SCHEDULER_TICK", 60)
        run_forever(database, jobs, tick)


if __name__ == "__main__":
    main()
