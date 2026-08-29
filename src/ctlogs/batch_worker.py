"""Durable workers for trusted local-index record batches."""

from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import time
import uuid
from pathlib import Path

from ctlogs.control import ControlDatabase, ControlUnavailable
from ctlogs.database import BatchResultTooLarge, Database, IndexedRecord

LOGGER = logging.getLogger("ctlogs.batch_worker")
SLICE_SCHEMA_VERSION = "subfinder.internal-record-batch-slice.v1"


def _positive_int(name: str, default: int) -> int:
    value = int(os.environ.get(name, default))
    if value < 1:
        raise ValueError(f"{name} must be positive")
    return value


def _record_document(record: IndexedRecord) -> dict[str, object]:
    return {
        "hostname": record.hostname,
        "first_seen": record.first_seen,
        "sources": [
            {
                "source": source.source,
                "first_seen": source.first_seen,
                "last_seen": source.last_seen,
            }
            for source in record.sources
        ],
    }


class RecordBatchWorker:
    """Claim small slices so memory, response size, and fairness stay bounded."""

    def __init__(
        self,
        database: Database,
        control: ControlDatabase,
        *,
        worker_id: str,
        slice_size: int = 25,
        max_records: int = 5_000,
        max_source_rows: int = 20_000,
        max_document_bytes: int = 2 * 1024 * 1024,
        lease_seconds: float = 60,
    ) -> None:
        if min(slice_size, max_records, max_source_rows, max_document_bytes) < 1:
            raise ValueError("batch worker bounds must be positive")
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self.database = database
        self.control = control
        self.worker_id = worker_id
        self.slice_size = slice_size
        self.max_records = max_records
        self.max_source_rows = max_source_rows
        self.max_document_bytes = max_document_bytes
        self.lease_seconds = lease_seconds

    def _build(self, apexes: list[str]) -> tuple[str, int, int]:
        """Build the largest bounded prefix; one pathological apex is isolated."""
        selected = list(apexes)
        while True:
            failures: list[dict[str, str]] = []
            try:
                indexed = self.database.records_many(
                    selected,
                    max_records=self.max_records,
                    max_source_rows=self.max_source_rows,
                )
            except BatchResultTooLarge as error:
                if len(selected) > 1:
                    selected = selected[: max(1, len(selected) // 2)]
                    continue
                indexed = {selected[0]: []}
                failures.append(
                    {
                        "apex": selected[0],
                        "code": "result_too_large",
                        "message": str(error),
                    }
                )
            document = {
                "schema_version": SLICE_SCHEMA_VERSION,
                "results": [
                    {
                        "schema_version": "subfinder.index-records.v1",
                        "apex": apex,
                        "records": [
                            _record_document(record) for record in indexed[apex]
                        ],
                    }
                    for apex in selected
                    if not failures
                ],
                "errors": failures,
            }
            encoded = json.dumps(document, separators=(",", ":"))
            if len(encoded.encode()) <= self.max_document_bytes:
                count = sum(len(records) for records in indexed.values())
                return encoded, count, len(failures)
            if len(selected) > 1:
                selected = selected[: max(1, len(selected) // 2)]
                continue
            error_document = {
                "schema_version": SLICE_SCHEMA_VERSION,
                "results": [],
                "errors": [
                    {
                        "apex": selected[0],
                        "code": "serialized_result_too_large",
                        "message": "apex snapshot exceeds the result byte limit",
                    }
                ],
            }
            return json.dumps(error_document, separators=(",", ":")), 0, 1

    def run_once(self) -> bool:
        claim = self.control.claim_record_batch(
            self.worker_id,
            lease_seconds=self.lease_seconds,
            slice_size=self.slice_size,
        )
        if claim is None:
            return False
        job, apexes = claim
        try:
            document, record_count, failed_apexes = self._build(apexes)
            decoded = json.loads(document)
            processed = len(decoded["results"]) + len(decoded["errors"])
            self.control.finish_record_batch_slice(
                job.job_id,
                self.worker_id,
                apex_count=processed,
                record_count=record_count,
                failed_apexes=failed_apexes,
                document_json=document,
            )
        except Exception as error:
            LOGGER.exception("record batch %s failed", job.job_id)
            try:
                self.control.fail_record_batch(
                    job.job_id, self.worker_id, type(error).__name__
                )
            except ControlUnavailable:
                LOGGER.exception("could not commit batch failure")
        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Run durable record-batch workers")
    parser.add_argument(
        "--db", default=os.environ.get("CTLOGS_DB_PATH", "/data/ctlogs.sqlite3")
    )
    parser.add_argument(
        "--control-db",
        default=os.environ.get("CTLOGS_CONTROL_DB_PATH", "/control/control.sqlite3"),
    )
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=os.environ.get("CTLOGS_LOG_LEVEL", "INFO"))
    database = Database(Path(args.db), read_only=True)
    control = ControlDatabase(Path(args.control_db), busy_timeout_ms=1_000)
    database.verify_schema()
    control.verify_schema()
    worker = RecordBatchWorker(
        database,
        control,
        worker_id=(
            os.environ.get("CTLOGS_BATCH_WORKER_ID")
            or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        ),
        slice_size=_positive_int("CTLOGS_BATCH_WORKER_SLICE_APEXES", 25),
        max_records=_positive_int("CTLOGS_BATCH_MAX_RECORDS", 5_000),
        max_source_rows=_positive_int("CTLOGS_BATCH_MAX_SOURCE_ROWS", 20_000),
        max_document_bytes=_positive_int(
            "CTLOGS_BATCH_MAX_DOCUMENT_BYTES", 2 * 1024 * 1024
        ),
        lease_seconds=float(os.environ.get("CTLOGS_BATCH_LEASE_SECONDS", "60")),
    )
    if args.once:
        worker.run_once()
        return
    poll = float(os.environ.get("CTLOGS_BATCH_POLL_SECONDS", "0.1"))
    while True:
        if not worker.run_once():
            time.sleep(poll)


if __name__ == "__main__":
    main()
