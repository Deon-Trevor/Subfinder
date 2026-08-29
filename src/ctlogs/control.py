from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from pathlib import Path

from ctlogs.database import Quota, QuotaExceeded


class ControlUnavailable(RuntimeError):
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
                    """
                )
                connection.execute(
                    "DELETE FROM request_counts WHERE day < date('now', '-2 days')"
                )
                connection.execute(
                    "DELETE FROM refresh_requests "
                    "WHERE datetime(requested_at) < datetime('now', '-7 days')"
                )
        except sqlite3.Error as error:
            raise ControlUnavailable("control database initialization failed") from error

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
        missing = {"request_counts", "refresh_requests"} - present
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
