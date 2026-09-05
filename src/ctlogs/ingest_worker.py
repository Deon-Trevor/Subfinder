"""Durable bounded workers for scheduled ingestion jobs."""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import time
from pathlib import Path
from typing import Any

from ctlogs.control import ControlDatabase, ControlUnavailable, IngestJob
from ctlogs.database import Database
from ctlogs.ingest.czds import CzdsClient, run_czds

LOGGER = logging.getLogger("ctlogs.ingest_worker")
DEFAULT_POLL_SECONDS = 5.0
DEFAULT_LEASE_SECONDS = 6 * 60 * 60
DEFAULT_CZDS_MAX_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_CZDS_RUN_TIMEOUT_SECONDS = 6 * 60 * 60


def _positive_environment_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value in (None, ""):
        return default
    try:
        parsed = float(value)
    except ValueError as error:
        raise ValueError(f"{name} must be a number") from error
    if parsed <= 0:
        raise ValueError(f"{name} must be positive")
    return parsed


def _positive_environment_integer(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value in (None, ""):
        return default
    try:
        parsed = int(value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if parsed < 1:
        raise ValueError(f"{name} must be positive")
    return parsed


def _run_with_deadline(callable_, *, seconds: int):
    def _timeout(_signum, _frame):
        raise TimeoutError(f"ingest job exceeded {seconds} seconds")

    previous_handler = signal.signal(signal.SIGALRM, _timeout)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        return callable_()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def worker_id(prefix: str) -> str:
    return f"{prefix}:{socket.gethostname()}:{os.getpid()}"


def _payload(job: IngestJob) -> dict[str, Any]:
    try:
        payload = json.loads(job.payload_json or "{}")
    except json.JSONDecodeError as error:
        raise ValueError("ingest job payload is not valid JSON") from error
    if not isinstance(payload, dict):
        raise ValueError("ingest job payload must be a JSON object")
    return payload


def _bounded_payload_integer(
    payload: dict[str, Any],
    key: str,
    *,
    default: int,
    upper_bound: int,
) -> int:
    try:
        value = int(payload.get(key, default))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{key} must be an integer") from error
    if value < 1:
        raise ValueError(f"{key} must be positive")
    return min(value, upper_bound)


def _configured_output_directory(payload: dict[str, Any]) -> Path:
    configured = Path(os.environ.get("CTLOGS_CZDS_OUTPUT", "/data/czds")).resolve()
    requested = Path(str(payload.get("output_directory", configured))).resolve()
    if requested != configured:
        raise ValueError("output_directory must match CTLOGS_CZDS_OUTPUT")
    return configured


def run_czds_job(database: Database, job: IngestJob, *, timeout: int) -> dict[str, object]:
    username = os.environ.get("CZDS_USERNAME")
    password = os.environ.get("CZDS_PASSWORD")
    if not username or not password:
        raise RuntimeError("CZDS_USERNAME and CZDS_PASSWORD are required")
    payload = _payload(job)
    zone_bound = _positive_environment_integer("CTLOGS_CZDS_MAX_ZONES", 25)
    byte_bound = _positive_environment_integer(
        "CTLOGS_CZDS_MAX_BYTES",
        DEFAULT_CZDS_MAX_BYTES,
    )
    max_zones = _bounded_payload_integer(
        payload,
        "max_zones",
        default=zone_bound,
        upper_bound=zone_bound,
    )
    max_bytes = _bounded_payload_integer(
        payload,
        "max_bytes",
        default=byte_bound,
        upper_bound=byte_bound,
    )
    output_directory = _configured_output_directory(payload)
    refresh = bool(payload.get("refresh", True))
    run_timeout = _positive_environment_integer(
        "CTLOGS_CZDS_RUN_TIMEOUT_SECONDS",
        DEFAULT_CZDS_RUN_TIMEOUT_SECONDS,
    )

    def _run() -> tuple[int, int]:
        return run_czds(
            database,
            CzdsClient(username, password, timeout=timeout),
            output_directory,
            max_zones=max_zones,
            max_bytes=max_bytes,
            refresh=refresh,
        )

    zones, hostnames = _run_with_deadline(_run, seconds=run_timeout)
    return {"zones": zones, "hostnames": hostnames}


def execute_ingest_job(
    database: Database,
    control: ControlDatabase,
    job: IngestJob,
    owner: str,
    *,
    timeout: int,
) -> IngestJob:
    try:
        if job.kind != "czds":
            raise RuntimeError(f"unsupported ingest job kind: {job.kind}")
        result = run_czds_job(database, job, timeout=timeout)
        return control.finish_ingest_job(job.job_id, owner, result=result)
    except Exception as error:
        LOGGER.exception("ingest job failed", extra={"job_id": job.job_id, "kind": job.kind})
        return control.fail_ingest_job(job.job_id, owner, str(error), retry=True)


def run_once(
    database: Database,
    control: ControlDatabase,
    *,
    kind: str,
    owner: str,
    lease_seconds: float,
    timeout: int,
) -> IngestJob | None:
    job = control.claim_ingest_job(kind, owner, lease_seconds=lease_seconds)
    if job is None:
        return None
    LOGGER.info("claimed ingest job", extra={"job_id": job.job_id, "kind": job.kind})
    return execute_ingest_job(database, control, job, owner, timeout=timeout)


def run_forever(
    database: Database,
    control: ControlDatabase,
    *,
    kind: str,
    owner: str,
    lease_seconds: float,
    poll_seconds: float,
    timeout: int,
) -> None:
    while True:
        try:
            job = run_once(
                database,
                control,
                kind=kind,
                owner=owner,
                lease_seconds=lease_seconds,
                timeout=timeout,
            )
            if job is None:
                time.sleep(poll_seconds)
        except ControlUnavailable:
            LOGGER.exception("control database unavailable")
            time.sleep(poll_seconds)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded scheduled ingestion jobs")
    parser.add_argument("--db", default=os.environ.get("CTLOGS_DB_PATH", "data/ctlogs.sqlite3"))
    parser.add_argument("--control-db", default=os.environ.get("CTLOGS_CONTROL_DB_PATH", "data/control.sqlite3"))
    parser.add_argument("--kind", default=os.environ.get("CTLOGS_INGEST_WORKER_KIND", "czds"))
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=os.environ.get("CTLOGS_LOG_LEVEL", "INFO"))
    database = Database(args.db)
    database.initialize()
    control = ControlDatabase(args.control_db)
    control.initialize()
    lease_seconds = _positive_environment_float("CTLOGS_INGEST_WORKER_LEASE_SECONDS", DEFAULT_LEASE_SECONDS)
    poll_seconds = _positive_environment_float("CTLOGS_INGEST_WORKER_POLL_SECONDS", DEFAULT_POLL_SECONDS)
    timeout = _positive_environment_integer("CTLOGS_SCHEDULER_TIMEOUT", 60)
    owner = worker_id(args.kind)
    if args.once:
        run_once(database, control, kind=args.kind, owner=owner, lease_seconds=lease_seconds, timeout=timeout)
    else:
        run_forever(
            database,
            control,
            kind=args.kind,
            owner=owner,
            lease_seconds=lease_seconds,
            poll_seconds=poll_seconds,
            timeout=timeout,
        )


if __name__ == "__main__":
    main()
