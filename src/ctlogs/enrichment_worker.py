from __future__ import annotations

import logging
import os
import time
import uuid
from collections.abc import Callable
from pathlib import Path

from ctlogs.control import ControlDatabase, ControlUnavailable
from ctlogs.database import Database, QuotaExceeded
from ctlogs.ingest.backfill import DEFAULT_MAX_BYTES
from ctlogs.ingest.czds import import_local_zone, local_zone_artifact
from ctlogs.ingest.enrich import (
    DEFAULT_URLSCAN_DAILY_LIMIT,
    DEFAULT_URLSCAN_PRIORITY_DAILY_LIMIT,
    DEFAULT_URLSCAN_SEARCH_DAILY_LIMIT,
    URLSCAN_PRIORITY_QUOTA_SUBJECT,
    URLSCAN_TOTAL_QUOTA_SUBJECT,
    UrlscanSource,
    run_source,
    split_urlscan_budget,
)

LOGGER = logging.getLogger("ctlogs.enrichment-worker")


def _positive_environment_integer(name: str, default: int) -> int:
    value = os.environ.get(name)
    try:
        result = default if value is None else int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if result < 1:
        raise ValueError(f"{name} must be positive")
    return result


def _run_urlscan_apex(
    database: Database,
    source: UrlscanSource,
    apex: str,
    *,
    request_guard: Callable[[], object] | None = None,
) -> tuple[int, int]:
    state = database.get_ingest_state(f"enrich:{source.name}:{apex}")
    history_complete = bool(state and state.get("cursor") == "complete")
    return run_source(
        database,
        source,
        [apex],
        max_requests=1,
        refresh=history_complete,
        persist_state=not history_complete,
        request_guard=request_guard,
    )


def run_priority_batch(
    database: Database,
    control_database: ControlDatabase,
    source: UrlscanSource,
    *,
    apexes_per_run: int,
    request_guard: Callable[[], object] | None = None,
    exclude_apexes: set[str] | None = None,
) -> tuple[int, int]:
    """Advance one bounded FIFO batch; this worker is its sole consumer."""
    excluded = exclude_apexes or set()
    apexes = [
        apex
        for apex in control_database.queued_refreshes(apexes_per_run + len(excluded))
        if apex not in excluded
    ][:apexes_per_run]
    requests = 0
    hostnames = 0
    failures = 0
    for apex in apexes:
        try:
            source_requests, source_hostnames = _run_urlscan_apex(
                database,
                source,
                apex,
                request_guard=request_guard,
            )
        except QuotaExceeded:
            raise
        except Exception:
            failures += 1
            LOGGER.exception("priority URLScan history failed for %s", apex)
        else:
            requests += source_requests
            hostnames += source_hostnames
        state = database.get_ingest_state(f"enrich:{source.name}:{apex}")
        control_database.finish_refresh_attempt(
            apex,
            complete=bool(state and state.get("cursor") == "complete"),
        )
    if apexes and failures == len(apexes):
        raise RuntimeError("URLScan priority history failed for every queued apex")
    return requests, hostnames


def run_one(
    database: Database,
    control_database: ControlDatabase,
    *,
    zone_directory: Path,
    max_zone_bytes: int,
    urlscan_source: UrlscanSource | None,
    request_guard: Callable[[], object] | None = None,
    worker_id: str,
    lease_seconds: float = 3600,
) -> dict[str, object]:
    """Run one user-requested local-zone and passive URLScan enrichment."""
    job = control_database.claim_enrichment(
        worker_id,
        lease_seconds=lease_seconds,
    )
    if job is None:
        return {"state": "idle"}

    errors: list[str] = []
    if job.zone_state == "running":
        try:
            artifact = local_zone_artifact(
                zone_directory,
                job.zone,
                max_bytes=max_zone_bytes,
            )
            if (
                artifact is None
                or artifact.name != job.artifact_name
                or artifact.fingerprint != job.artifact_fingerprint
            ):
                raise RuntimeError("local zone artifact is missing or changed")
            import_state = database.get_ingest_state(f"zone-import:{job.zone}")
            if import_state and import_state.get("cursor") == artifact.fingerprint:
                zone_state = "already_current"
                zone_records = 0
            else:
                zone_records, _digest = import_local_zone(database, artifact)
                zone_state = "complete"
            job = control_database.checkpoint_enrichment(
                job.job_id,
                worker_id,
                zone_state=zone_state,
                zone_records=zone_records,
            )
        except ControlUnavailable:
            raise
        except Exception as error:
            message = f"zone import: {type(error).__name__}: {error}"
            errors.append(message)
            job = control_database.checkpoint_enrichment(
                job.job_id,
                worker_id,
                zone_state="failed",
                error=message,
            )

    if job.urlscan_state == "running":
        if urlscan_source is None:
            message = "URLScan passive enrichment is not configured"
            errors.append(message)
            job = control_database.checkpoint_enrichment(
                job.job_id,
                worker_id,
                urlscan_state="unavailable",
                error="; ".join(errors),
            )
        else:
            try:
                _requests, urlscan_records = _run_urlscan_apex(
                    database,
                    urlscan_source,
                    job.apex,
                    request_guard=request_guard,
                )
                state = database.get_ingest_state(
                    f"enrich:{urlscan_source.name}:{job.apex}"
                )
                complete = bool(state and state.get("cursor") == "complete")
                control_database.finish_refresh_attempt(job.apex, complete=complete)
                job = control_database.checkpoint_enrichment(
                    job.job_id,
                    worker_id,
                    urlscan_state="complete" if complete else "checkpointed",
                    urlscan_records=urlscan_records,
                    error="; ".join(errors),
                )
            except ControlUnavailable:
                raise
            except QuotaExceeded as error:
                message = f"URLScan quota: {error}"
                errors.append(message)
                control_database.finish_refresh_attempt(job.apex, complete=False)
                job = control_database.checkpoint_enrichment(
                    job.job_id,
                    worker_id,
                    urlscan_state="checkpointed",
                    error="; ".join(errors),
                )
            except Exception as error:
                message = f"URLScan: {type(error).__name__}: {error}"
                errors.append(message)
                control_database.finish_refresh_attempt(job.apex, complete=False)
                job = control_database.checkpoint_enrichment(
                    job.job_id,
                    worker_id,
                    urlscan_state="failed",
                    error="; ".join(errors),
                )

    finished = control_database.finish_enrichment(job.job_id, worker_id)
    return {
        "state": finished.state,
        "job_id": finished.job_id,
        "apex": finished.apex,
        "urlscan_requested": finished.urlscan_state != "not_requested",
        "zone_records": finished.zone_records,
        "urlscan_records": finished.urlscan_records,
    }


def main() -> None:
    logging.basicConfig(level=os.environ.get("CTLOGS_LOG_LEVEL", "INFO"))
    database = Database(os.environ.get("CTLOGS_DB_PATH", "data/ctlogs.sqlite3"))
    database.verify_schema()
    control = ControlDatabase(
        os.environ.get("CTLOGS_CONTROL_DB_PATH", "data/control.sqlite3"),
        busy_timeout_ms=_positive_environment_integer(
            "CTLOGS_CONTROL_BUSY_TIMEOUT_MS",
            1000,
        ),
    )
    control.verify_schema()
    timeout = _positive_environment_integer("CTLOGS_SCHEDULER_TIMEOUT", 60)
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    source: UrlscanSource | None = None
    request_guard: Callable[[], object] | None = None
    if api_key:
        total = _positive_environment_integer(
            "CTLOGS_URLSCAN_DAILY_LIMIT",
            DEFAULT_URLSCAN_DAILY_LIMIT,
        )
        budgets = split_urlscan_budget(
            total,
            _positive_environment_integer(
                "CTLOGS_URLSCAN_SEARCH_DAILY_LIMIT",
                DEFAULT_URLSCAN_SEARCH_DAILY_LIMIT,
            ),
            _positive_environment_integer(
                "CTLOGS_URLSCAN_PRIORITY_DAILY_LIMIT",
                DEFAULT_URLSCAN_PRIORITY_DAILY_LIMIT,
            ),
        )
        if budgets.priority:
            source = UrlscanSource(api_key, timeout=timeout)

            def consume_priority_request() -> object:
                return database.consume_partitioned_request(
                    URLSCAN_TOTAL_QUOTA_SUBJECT,
                    total,
                    URLSCAN_PRIORITY_QUOTA_SUBJECT,
                    budgets.priority,
                )

            request_guard = consume_priority_request

    control.set_capability(
        "urlscan-passive",
        source is not None,
        detail=(
            "priority history is configured"
            if source is not None
            else "URLScan priority history is not configured"
        ),
    )
    poll_seconds = _positive_environment_integer(
        "CTLOGS_ENRICHMENT_POLL_SECONDS",
        2,
    )
    lease_seconds = _positive_environment_integer(
        "CTLOGS_ENRICHMENT_LEASE_SECONDS",
        3600,
    )
    max_zone_bytes = _positive_environment_integer(
        "CTLOGS_ON_DEMAND_ZONE_MAX_BYTES",
        DEFAULT_MAX_BYTES,
    )
    zone_directory = Path(os.environ.get("CTLOGS_CZDS_OUTPUT", "/data/czds"))
    priority_interval = _positive_environment_integer(
        "CTLOGS_URLSCAN_INTERVAL",
        60,
    )
    priority_apexes = _positive_environment_integer(
        "CTLOGS_URLSCAN_PRIORITY_APEXES_PER_RUN",
        14,
    )
    next_priority_at = 0.0
    worker_id = f"enrichment-{uuid.uuid4().hex[:12]}"
    LOGGER.info("enrichment worker started")
    while True:
        try:
            outcome = run_one(
                database,
                control,
                zone_directory=zone_directory,
                max_zone_bytes=max_zone_bytes,
                urlscan_source=source,
                request_guard=request_guard,
                worker_id=worker_id,
                lease_seconds=lease_seconds,
            )
        except Exception:
            LOGGER.exception("enrichment worker pass failed")
            time.sleep(poll_seconds)
            continue
        if outcome["state"] != "idle":
            LOGGER.info("enrichment completed: %r", outcome)
        exclude_apexes = (
            {str(outcome["apex"])}
            if outcome.get("urlscan_requested") and outcome.get("apex")
            else set()
        )
        now = time.monotonic()
        if source is not None and now >= next_priority_at:
            try:
                requests, hostnames = run_priority_batch(
                    database,
                    control,
                    source,
                    apexes_per_run=priority_apexes,
                    request_guard=request_guard,
                    exclude_apexes=exclude_apexes,
                )
            except Exception:
                LOGGER.exception("priority URLScan worker pass failed")
            else:
                if requests or hostnames:
                    LOGGER.info(
                        "priority URLScan completed: requests=%s hostnames=%s",
                        requests,
                        hostnames,
                    )
            next_priority_at = time.monotonic() + priority_interval
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
