from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from time import time as epoch_seconds

from ctlogs.database import Quota, QuotaExceeded


class ControlUnavailable(RuntimeError):
    pass


class RecordBatchQueueFull(RuntimeError):
    pass


class IdempotencyConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class Admission:
    quota: Quota
    refresh_status: str


@dataclass(frozen=True)
class AdmissionRequest:
    subject: str
    limit: int
    apex: str
    enqueue_refresh: bool = True


@dataclass(frozen=True)
class RecordBatchJob:
    job_id: str
    subject: str
    state: str
    total_apexes: int
    completed_apexes: int
    next_position: int
    next_sequence: int
    created_at: float
    updated_at: float
    lease_owner: str = ""
    lease_expires: float = 0.0
    cancel_requested: bool = False
    error: str = ""
    failed_apexes: int = 0
    reserved_units: int = 0
    committed_units: int = 0
    released_units: int = 0


@dataclass(frozen=True)
class RecordBatchAdmission:
    job: RecordBatchJob
    quota: Quota
    created: bool


class ControlDatabase:
    """Small mutable state that must not share the catalog's writer lock."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 50,
        max_refresh_queue: int = 100_000,
    ) -> None:
        if busy_timeout_ms < 1:
            raise ValueError("busy_timeout_ms must be positive")
        if max_refresh_queue < 1:
            raise ValueError("max_refresh_queue must be positive")
        self.path = Path(path)
        self.busy_timeout_ms = busy_timeout_ms
        self.max_refresh_queue = max_refresh_queue
        self._last_prune_day: str | None = None

    def _connect(self, *, read_only: bool = False) -> sqlite3.Connection:
        target: str | Path = self.path
        uri = False
        if read_only:
            target = f"{self.path.resolve().as_uri()}?mode=ro"
            uri = True
        connection = sqlite3.connect(
            target,
            timeout=self.busy_timeout_ms / 1000,
            uri=uri,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = NORMAL")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS request_counts (
                        day TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        used INTEGER NOT NULL CHECK (used >= 0),
                        PRIMARY KEY (day, subject)
                    ) WITHOUT ROWID;

                    CREATE TABLE IF NOT EXISTS refresh_requests (
                        apex TEXT PRIMARY KEY,
                        requested_at TEXT NOT NULL,
                        attempted_at TEXT,
                        attempts INTEGER NOT NULL DEFAULT 0
                            CHECK (attempts >= 0)
                    ) WITHOUT ROWID;

                    CREATE INDEX IF NOT EXISTS idx_refresh_requests_fifo
                        ON refresh_requests(requested_at, apex);

                    CREATE TABLE IF NOT EXISTS record_batch_jobs (
                        job_id TEXT PRIMARY KEY,
                        subject TEXT NOT NULL,
                        idempotency_key TEXT NOT NULL,
                        request_sha256 TEXT NOT NULL,
                        quota_day TEXT NOT NULL,
                        state TEXT NOT NULL CHECK (
                            state IN ('queued','running','done','failed','cancelled')
                        ),
                        total_apexes INTEGER NOT NULL CHECK (total_apexes > 0),
                        completed_apexes INTEGER NOT NULL DEFAULT 0,
                        failed_apexes INTEGER NOT NULL DEFAULT 0,
                        reserved_units INTEGER NOT NULL,
                        committed_units INTEGER NOT NULL DEFAULT 0,
                        released_units INTEGER NOT NULL DEFAULT 0,
                        next_position INTEGER NOT NULL DEFAULT 0,
                        next_sequence INTEGER NOT NULL DEFAULT 0,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        lease_owner TEXT NOT NULL DEFAULT '',
                        lease_expires REAL NOT NULL DEFAULT 0,
                        cancel_requested INTEGER NOT NULL DEFAULT 0,
                        error TEXT NOT NULL DEFAULT '',
                        CHECK (committed_units + released_units <= reserved_units),
                        UNIQUE(subject, idempotency_key)
                    );
                    CREATE INDEX IF NOT EXISTS record_batch_jobs_claim
                        ON record_batch_jobs(state, updated_at, job_id);
                    CREATE INDEX IF NOT EXISTS record_batch_jobs_lease
                        ON record_batch_jobs(state, lease_expires);

                    CREATE TABLE IF NOT EXISTS record_batch_apexes (
                        job_id TEXT NOT NULL REFERENCES record_batch_jobs(job_id)
                            ON DELETE CASCADE,
                        position INTEGER NOT NULL,
                        apex TEXT NOT NULL,
                        PRIMARY KEY(job_id, position),
                        UNIQUE(job_id, apex)
                    );

                    CREATE TABLE IF NOT EXISTS record_batch_slices (
                        job_id TEXT NOT NULL REFERENCES record_batch_jobs(job_id)
                            ON DELETE CASCADE,
                        sequence INTEGER NOT NULL,
                        first_position INTEGER NOT NULL,
                        apex_count INTEGER NOT NULL,
                        record_count INTEGER NOT NULL,
                        created_at REAL NOT NULL,
                        document_json TEXT NOT NULL,
                        PRIMARY KEY(job_id, sequence)
                    );
                    """
                )
                connection.execute(
                    "DELETE FROM request_counts WHERE day < date('now', '-2 days')"
                )
                connection.execute(
                    "DELETE FROM refresh_requests "
                    "WHERE datetime(requested_at) < datetime('now', '-7 days')"
                )
                connection.execute(
                    "DELETE FROM record_batch_jobs "
                    "WHERE state IN ('done','failed','cancelled') "
                    "AND updated_at < strftime('%s','now') - 86400"
                )
        except sqlite3.Error as error:
            raise ControlUnavailable(
                "control database initialization failed"
            ) from error

    def verify_schema(self) -> None:
        """Check the migrated control schema without taking a writer lock."""
        try:
            with self._connect(read_only=True) as connection:
                present = {
                    str(row["name"])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
        except sqlite3.Error as error:
            raise ControlUnavailable(
                "control migration required; schema is unavailable"
            ) from error
        missing = {
            "request_counts",
            "refresh_requests",
            "record_batch_jobs",
            "record_batch_apexes",
            "record_batch_slices",
        } - present
        if missing:
            raise ControlUnavailable(
                "control migration required; missing tables: "
                + ", ".join(sorted(missing))
            )

    def _enqueue_refresh(
        self,
        connection: sqlite3.Connection,
        apex: str,
        requested_at: str,
    ) -> str:
        pending = connection.execute(
            "SELECT 1 FROM refresh_requests WHERE apex = ?",
            (apex,),
        ).fetchone()
        if pending:
            return "already-pending"
        size = int(
            connection.execute("SELECT COUNT(*) FROM refresh_requests").fetchone()[0]
        )
        if size >= self.max_refresh_queue:
            return "queue-full"
        connection.execute(
            "INSERT INTO refresh_requests (apex, requested_at) VALUES (?, ?)",
            (apex, requested_at),
        )
        return "queued"

    def enqueue_refresh(
        self,
        apex: str,
        *,
        requested_at: str | None = None,
    ) -> str:
        requested_at = requested_at or datetime.now(UTC).isoformat()
        try:
            with self._connect() as connection:
                return self._enqueue_refresh(connection, apex, requested_at)
        except sqlite3.Error as error:
            raise ControlUnavailable("control refresh enqueue failed") from error

    def admit(
        self,
        subject: str,
        limit: int,
        apex: str,
        *,
        enqueue_refresh: bool = True,
        now: datetime | None = None,
    ) -> Admission:
        outcome = self.admit_many(
            [AdmissionRequest(subject, limit, apex, enqueue_refresh)],
            now=now,
        )[0]
        if isinstance(outcome, QuotaExceeded):
            raise outcome
        return outcome

    def consume(
        self,
        subject: str,
        limit: int,
        units: int,
        *,
        now: datetime | None = None,
    ) -> Quota:
        """Atomically consume several quota units or consume none of them."""
        if limit < 1 or units < 1:
            raise ValueError("limit and units must be positive")
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("now must include a timezone")
        current = current.astimezone(UTC)
        day = current.date().isoformat()
        reset = datetime.combine(current.date() + timedelta(days=1), time.min, UTC)
        if units > limit:
            raise QuotaExceeded(Quota(limit, limit, int(reset.timestamp())))
        prune_before_day = (current.date() - timedelta(days=2)).isoformat()
        should_prune = self._last_prune_day != day
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if should_prune:
                    connection.execute(
                        "DELETE FROM request_counts WHERE day < ?",
                        (prune_before_day,),
                    )
                row = connection.execute(
                    """
                    INSERT INTO request_counts (day, subject, used)
                    VALUES (?, ?, ?)
                    ON CONFLICT (day, subject) DO UPDATE
                    SET used = used + excluded.used
                    WHERE used + excluded.used <= ?
                    RETURNING used
                    """,
                    (day, subject, units, limit),
                ).fetchone()
                if row is None:
                    existing = connection.execute(
                        "SELECT used FROM request_counts WHERE day = ? AND subject = ?",
                        (day, subject),
                    ).fetchone()
                    used = int(existing["used"]) if existing is not None else 0
                    raise QuotaExceeded(
                        Quota(
                            limit,
                            max(0, limit - used),
                            int(reset.timestamp()),
                        )
                    )
                used = int(row["used"])
        except QuotaExceeded:
            raise
        except sqlite3.Error as error:
            raise ControlUnavailable("control quota consumption failed") from error
        if should_prune:
            self._last_prune_day = day
        return Quota(limit, max(0, limit - used), int(reset.timestamp()))

    @staticmethod
    def _batch_job(row: sqlite3.Row) -> RecordBatchJob:
        return RecordBatchJob(
            job_id=str(row["job_id"]),
            subject=str(row["subject"]),
            state=str(row["state"]),
            total_apexes=int(row["total_apexes"]),
            completed_apexes=int(row["completed_apexes"]),
            next_position=int(row["next_position"]),
            next_sequence=int(row["next_sequence"]),
            created_at=float(row["created_at"]),
            updated_at=float(row["updated_at"]),
            lease_owner=str(row["lease_owner"]),
            lease_expires=float(row["lease_expires"]),
            cancel_requested=bool(row["cancel_requested"]),
            error=str(row["error"]),
            failed_apexes=int(row["failed_apexes"]),
            reserved_units=int(row["reserved_units"]),
            committed_units=int(row["committed_units"]),
            released_units=int(row["released_units"]),
        )

    def enqueue_record_batch(
        self,
        subject: str,
        limit: int,
        apexes: list[str],
        *,
        idempotency_key: str,
        max_pending: int,
        max_pending_per_subject: int,
        now: datetime | None = None,
    ) -> RecordBatchAdmission:
        """Atomically debit exact apex quota and enqueue idempotent work."""
        if not apexes or len(set(apexes)) != len(apexes):
            raise ValueError("apexes must be non-empty and unique")
        if not idempotency_key or len(idempotency_key) > 128:
            raise ValueError("idempotency_key must contain at most 128 characters")
        if min(limit, max_pending, max_pending_per_subject) < 1:
            raise ValueError("queue and quota limits must be positive")
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("now must include a timezone")
        current = current.astimezone(UTC)
        timestamp = current.timestamp()
        day = current.date().isoformat()
        reset = datetime.combine(current.date() + timedelta(days=1), time.min, UTC)
        reset_at = int(reset.timestamp())
        job_id = uuid.uuid4().hex
        request_sha256 = hashlib.sha256(
            json.dumps(apexes, separators=(",", ":")).encode()
        ).hexdigest()
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT * FROM record_batch_jobs "
                    "WHERE subject=? AND idempotency_key=?",
                    (subject, idempotency_key),
                ).fetchone()
                if existing is not None:
                    if str(existing["request_sha256"]) != request_sha256:
                        raise IdempotencyConflict(
                            "idempotency key was already used for another request"
                        )
                    used_row = connection.execute(
                        "SELECT used FROM request_counts WHERE day=? AND subject=?",
                        (day, subject),
                    ).fetchone()
                    used = int(used_row["used"]) if used_row is not None else 0
                    return RecordBatchAdmission(
                        self._batch_job(existing),
                        Quota(limit, max(0, limit - used), reset_at),
                        False,
                    )
                active = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM record_batch_jobs "
                        "WHERE state IN ('queued','running')"
                    ).fetchone()[0]
                )
                subject_active = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM record_batch_jobs WHERE subject=? "
                        "AND state IN ('queued','running')",
                        (subject,),
                    ).fetchone()[0]
                )
                if active >= max_pending or subject_active >= max_pending_per_subject:
                    raise RecordBatchQueueFull("record batch queue is full")
                units = len(apexes)
                if units > limit:
                    raise QuotaExceeded(Quota(limit, limit, reset_at))
                quota_row = connection.execute(
                    """
                    INSERT INTO request_counts(day,subject,used) VALUES(?,?,?)
                    ON CONFLICT(day,subject) DO UPDATE
                    SET used=used+excluded.used
                    WHERE used+excluded.used<=?
                    RETURNING used
                    """,
                    (day, subject, units, limit),
                ).fetchone()
                if quota_row is None:
                    used_row = connection.execute(
                        "SELECT used FROM request_counts WHERE day=? AND subject=?",
                        (day, subject),
                    ).fetchone()
                    used = int(used_row["used"]) if used_row is not None else 0
                    raise QuotaExceeded(Quota(limit, max(0, limit - used), reset_at))
                connection.execute(
                    "INSERT INTO record_batch_jobs "
                    "(job_id,subject,idempotency_key,request_sha256,quota_day,state,"
                    "total_apexes,completed_apexes,failed_apexes,reserved_units,"
                    "committed_units,released_units,next_position,next_sequence,"
                    "created_at,updated_at) "
                    "VALUES (?,?,?,?,?,'queued',?,0,0,?,0,0,0,0,?,?)",
                    (
                        job_id,
                        subject,
                        idempotency_key,
                        request_sha256,
                        day,
                        units,
                        units,
                        timestamp,
                        timestamp,
                    ),
                )
                connection.executemany(
                    "INSERT INTO record_batch_apexes VALUES (?,?,?)",
                    ((job_id, position, apex) for position, apex in enumerate(apexes)),
                )
                row = connection.execute(
                    "SELECT * FROM record_batch_jobs WHERE job_id=?", (job_id,)
                ).fetchone()
                assert row is not None
                return RecordBatchAdmission(
                    self._batch_job(row),
                    Quota(limit, max(0, limit - int(quota_row["used"])), reset_at),
                    True,
                )
        except (
            QuotaExceeded,
            ControlUnavailable,
            RecordBatchQueueFull,
            IdempotencyConflict,
        ):
            raise
        except sqlite3.Error as error:
            raise ControlUnavailable("record batch admission failed") from error

    def record_batch_job(
        self, job_id: str, *, subject: str | None = None
    ) -> RecordBatchJob | None:
        query = "SELECT * FROM record_batch_jobs WHERE job_id=?"
        parameters: tuple[object, ...] = (job_id,)
        if subject is not None:
            query += " AND subject=?"
            parameters = (job_id, subject)
        try:
            with self._connect(read_only=True) as connection:
                row = connection.execute(query, parameters).fetchone()
        except sqlite3.Error as error:
            raise ControlUnavailable("record batch status read failed") from error
        return self._batch_job(row) if row is not None else None

    def claim_record_batch(
        self,
        worker_id: str,
        *,
        lease_seconds: float,
        slice_size: int,
        max_active_per_subject: int = 1,
        now: float | None = None,
    ) -> tuple[RecordBatchJob, list[str]] | None:
        if not worker_id or lease_seconds <= 0 or slice_size < 1:
            raise ValueError("worker, lease, and slice size are required")
        if max_active_per_subject < 1:
            raise ValueError("max_active_per_subject must be positive")
        timestamp = epoch_seconds() if now is None else now
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("BEGIN IMMEDIATE")
                cancelled_rows = connection.execute(
                    "SELECT subject,quota_day,total_apexes-completed_apexes AS released "
                    "FROM record_batch_jobs WHERE state='running' "
                    "AND lease_expires<=? AND cancel_requested=1",
                    (timestamp,),
                ).fetchall()
                for cancelled in cancelled_rows:
                    released = int(cancelled["released"])
                    if released:
                        connection.execute(
                            "UPDATE request_counts SET used=max(0,used-?) "
                            "WHERE day=? AND subject=?",
                            (
                                released,
                                str(cancelled["quota_day"]),
                                str(cancelled["subject"]),
                            ),
                        )
                connection.execute(
                    "UPDATE record_batch_jobs SET state='cancelled',lease_owner='',"
                    "released_units=reserved_units-committed_units,lease_expires=0,"
                    "updated_at=? WHERE state='running' AND lease_expires<=? "
                    "AND cancel_requested=1",
                    (timestamp, timestamp),
                )
                connection.execute(
                    "UPDATE record_batch_jobs SET state='queued',lease_owner='',"
                    "lease_expires=0,updated_at=? WHERE state='running' "
                    "AND lease_expires<=? AND cancel_requested=0",
                    (timestamp, timestamp),
                )
                row = connection.execute(
                    "SELECT candidate.* FROM record_batch_jobs AS candidate "
                    "WHERE candidate.state='queued' AND candidate.cancel_requested=0 "
                    "AND (SELECT COUNT(*) FROM record_batch_jobs AS active "
                    "WHERE active.subject=candidate.subject AND active.state='running') "
                    "< ? ORDER BY candidate.updated_at,candidate.job_id LIMIT 1",
                    (max_active_per_subject,),
                ).fetchone()
                if row is None:
                    return None
                job = self._batch_job(row)
                changed = connection.execute(
                    "UPDATE record_batch_jobs SET state='running',lease_owner=?,"
                    "lease_expires=?,updated_at=? WHERE job_id=? AND state='queued'",
                    (worker_id, timestamp + lease_seconds, timestamp, job.job_id),
                )
                if not changed.rowcount:
                    return None
                apex_rows = connection.execute(
                    "SELECT apex FROM record_batch_apexes WHERE job_id=? "
                    "AND position>=? ORDER BY position LIMIT ?",
                    (job.job_id, job.next_position, slice_size),
                ).fetchall()
                claimed_row = connection.execute(
                    "SELECT * FROM record_batch_jobs WHERE job_id=?", (job.job_id,)
                ).fetchone()
                assert claimed_row is not None
                return self._batch_job(claimed_row), [
                    str(item["apex"]) for item in apex_rows
                ]
        except sqlite3.Error as error:
            raise ControlUnavailable("record batch claim failed") from error

    def finish_record_batch_slice(
        self,
        job_id: str,
        worker_id: str,
        *,
        apex_count: int,
        record_count: int,
        failed_apexes: int = 0,
        document_json: str,
        now: float | None = None,
    ) -> RecordBatchJob:
        if apex_count < 1 or record_count < 0 or not 0 <= failed_apexes <= apex_count:
            raise ValueError("slice counts are invalid")
        timestamp = epoch_seconds() if now is None else now
        try:
            with self._connect() as connection:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM record_batch_jobs WHERE job_id=? "
                    "AND state='running' AND lease_owner=?",
                    (job_id, worker_id),
                ).fetchone()
                if row is None:
                    raise ControlUnavailable("record batch lease was lost")
                job = self._batch_job(row)
                cancelled_remainder = 0
                if job.cancel_requested:
                    state = "cancelled"
                    cancelled_remainder = max(
                        0, job.total_apexes - job.completed_apexes - apex_count
                    )
                elif job.next_position + apex_count >= job.total_apexes:
                    state = "done"
                else:
                    state = "queued"
                connection.execute(
                    "INSERT INTO record_batch_slices VALUES (?,?,?,?,?,?,?)",
                    (
                        job_id,
                        job.next_sequence,
                        job.next_position,
                        apex_count,
                        record_count,
                        timestamp,
                        document_json,
                    ),
                )
                connection.execute(
                    "UPDATE record_batch_jobs SET state=?,completed_apexes="
                    "completed_apexes+?,failed_apexes=failed_apexes+?,"
                    "committed_units=committed_units+?,released_units=released_units+?,"
                    "next_position=next_position+?,next_sequence=next_sequence+1,"
                    "updated_at=?,lease_owner='',lease_expires=0 WHERE job_id=?",
                    (
                        state,
                        apex_count,
                        failed_apexes + cancelled_remainder,
                        apex_count - failed_apexes,
                        failed_apexes,
                        apex_count,
                        timestamp,
                        job_id,
                    ),
                )
                released_now = failed_apexes + cancelled_remainder
                if released_now:
                    connection.execute(
                        "UPDATE request_counts SET used=max(0,used-?) "
                        "WHERE day=? AND subject=?",
                        (released_now, str(row["quota_day"]), job.subject),
                    )
                updated = connection.execute(
                    "SELECT * FROM record_batch_jobs WHERE job_id=?", (job_id,)
                ).fetchone()
                assert updated is not None
                return self._batch_job(updated)
        except ControlUnavailable:
            raise
        except sqlite3.Error as error:
            raise ControlUnavailable("record batch slice commit failed") from error

    def fail_record_batch(
        self, job_id: str, worker_id: str, error: str, *, now: float | None = None
    ) -> None:
        timestamp = epoch_seconds() if now is None else now
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM record_batch_jobs WHERE job_id=? "
                    "AND state='running' AND lease_owner=?",
                    (job_id, worker_id),
                ).fetchone()
                if row is None:
                    raise ControlUnavailable("record batch lease was lost")
                job = self._batch_job(row)
                released = job.total_apexes - job.completed_apexes
                changed = connection.execute(
                    "UPDATE record_batch_jobs SET state='failed',error=?,updated_at=?,"
                    "released_units=released_units+?,"
                    "lease_owner='',lease_expires=0 WHERE job_id=? AND state='running' "
                    "AND lease_owner=?",
                    (error[:500], timestamp, released, job_id, worker_id),
                )
                if not changed.rowcount:
                    raise ControlUnavailable("record batch lease was lost")
                connection.execute(
                    "UPDATE request_counts SET used=max(0,used-?) "
                    "WHERE day=? AND subject=?",
                    (released, str(row["quota_day"]), job.subject),
                )
        except ControlUnavailable:
            raise
        except sqlite3.Error as sql_error:
            raise ControlUnavailable(
                "record batch failure commit failed"
            ) from sql_error

    def cancel_record_batch(
        self, job_id: str, *, subject: str
    ) -> RecordBatchJob | None:
        """Request cancellation, releasing quota for work that has not completed."""
        timestamp = epoch_seconds()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM record_batch_jobs WHERE job_id=? AND subject=?",
                    (job_id, subject),
                ).fetchone()
                if row is None:
                    return None
                job = self._batch_job(row)
                if job.state in {"done", "failed", "cancelled"}:
                    return job
                released = (
                    job.total_apexes - job.completed_apexes
                    if job.state == "queued"
                    else 0
                )
                state = "cancelled" if job.state == "queued" else "running"
                connection.execute(
                    "UPDATE record_batch_jobs SET state=?,cancel_requested=1,"
                    "released_units=released_units+?,updated_at=? WHERE job_id=?",
                    (state, released, timestamp, job_id),
                )
                connection.execute(
                    "UPDATE request_counts SET used=max(0,used-?) "
                    "WHERE day=? AND subject=?",
                    (released, str(row["quota_day"]), subject),
                )
                updated = connection.execute(
                    "SELECT * FROM record_batch_jobs WHERE job_id=?", (job_id,)
                ).fetchone()
                assert updated is not None
                return self._batch_job(updated)
        except sqlite3.Error as error:
            raise ControlUnavailable("record batch cancellation failed") from error

    def record_batch_slices(
        self,
        job_id: str,
        *,
        subject: str,
        after: int,
        limit: int,
    ) -> list[dict[str, object]]:
        if after < -1 or limit < 1:
            raise ValueError("result cursor and limit are invalid")
        try:
            with self._connect(read_only=True) as connection:
                rows = connection.execute(
                    "SELECT slices.sequence,slices.document_json "
                    "FROM record_batch_slices AS slices "
                    "JOIN record_batch_jobs AS jobs ON jobs.job_id=slices.job_id "
                    "WHERE slices.job_id=? AND jobs.subject=? AND slices.sequence>? "
                    "ORDER BY slices.sequence LIMIT ?",
                    (job_id, subject, after, limit),
                ).fetchall()
        except sqlite3.Error as error:
            raise ControlUnavailable("record batch result read failed") from error
        return [
            {"sequence": int(row["sequence"]), "document": str(row["document_json"])}
            for row in rows
        ]

    def admit_many(
        self,
        requests: list[AdmissionRequest],
        *,
        now: datetime | None = None,
    ) -> list[Admission | QuotaExceeded]:
        if not requests:
            return []
        if any(request.limit < 1 for request in requests):
            raise ValueError("limit must be positive")
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("now must include a timezone")
        current = current.astimezone(UTC)
        day = current.date().isoformat()
        reset = datetime.combine(current.date() + timedelta(days=1), time.min, UTC)
        requested_at = current.isoformat()
        prune_before_day = (current.date() - timedelta(days=2)).isoformat()
        prune_before_refresh = (current - timedelta(days=7)).isoformat()
        should_prune = self._last_prune_day != day
        outcomes: list[Admission | QuotaExceeded] = []

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if should_prune:
                    connection.execute(
                        "DELETE FROM request_counts WHERE day < ?",
                        (prune_before_day,),
                    )
                    connection.execute(
                        "DELETE FROM refresh_requests WHERE requested_at < ?",
                        (prune_before_refresh,),
                    )
                for request in requests:
                    row = connection.execute(
                        """
                        INSERT INTO request_counts (day, subject, used)
                        VALUES (?, ?, 1)
                        ON CONFLICT (day, subject) DO UPDATE SET used = used + 1
                        WHERE used < ?
                        RETURNING used
                        """,
                        (day, request.subject, request.limit),
                    ).fetchone()
                    if row is None:
                        outcomes.append(
                            QuotaExceeded(
                                Quota(
                                    limit=request.limit,
                                    remaining=0,
                                    reset_at=int(reset.timestamp()),
                                )
                            )
                        )
                        continue

                    refresh_status = "disabled"
                    if request.enqueue_refresh:
                        refresh_status = self._enqueue_refresh(
                            connection,
                            request.apex,
                            requested_at,
                        )
                    used = int(row["used"])
                    outcomes.append(
                        Admission(
                            quota=Quota(
                                limit=request.limit,
                                remaining=max(0, request.limit - used),
                                reset_at=int(reset.timestamp()),
                            ),
                            refresh_status=refresh_status,
                        )
                    )
        except sqlite3.Error as error:
            raise ControlUnavailable("control database admission failed") from error

        if should_prune:
            self._last_prune_day = day
        return outcomes

    def queued_refreshes(self, limit: int) -> list[str]:
        if limit < 1:
            raise ValueError("limit must be positive")
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT apex
                    FROM refresh_requests
                    ORDER BY requested_at, apex
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        except sqlite3.Error as error:
            raise ControlUnavailable("control refresh queue read failed") from error
        return [str(row["apex"]) for row in rows]

    def finish_refresh_attempt(
        self,
        apex: str,
        *,
        complete: bool,
        attempted_at: str | None = None,
    ) -> None:
        attempted_at = attempted_at or datetime.now(UTC).isoformat()
        try:
            with self._connect() as connection:
                if complete:
                    connection.execute(
                        "DELETE FROM refresh_requests WHERE apex = ?",
                        (apex,),
                    )
                else:
                    connection.execute(
                        """
                        UPDATE refresh_requests
                        SET requested_at = ?, attempted_at = ?, attempts = attempts + 1
                        WHERE apex = ?
                        """,
                        (attempted_at, attempted_at, apex),
                    )
        except sqlite3.Error as error:
            raise ControlUnavailable("control refresh queue update failed") from error
