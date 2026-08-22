from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class SearchResult:
    subdomain: str
    first_seen: str | None


@dataclass(frozen=True)
class Quota:
    limit: int
    remaining: int
    reset_at: int


class QuotaExceeded(Exception):
    def __init__(self, quota: Quota) -> None:
        super().__init__("daily request limit exceeded")
        self.quota = quota


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS subdomains (
                    apex TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    first_seen TEXT,
                    PRIMARY KEY (apex, subdomain)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS request_counts (
                    day TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    used INTEGER NOT NULL CHECK (used >= 0),
                    PRIMARY KEY (day, client_ip)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS certspotter_counts (
                    day TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    used INTEGER NOT NULL CHECK (used >= 0),
                    PRIMARY KEY (day, client_ip)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS shodanct_counts (
                    day TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    used INTEGER NOT NULL CHECK (used >= 0),
                    PRIMARY KEY (day, client_ip)
                ) WITHOUT ROWID;

                CREATE TABLE IF NOT EXISTS ingest_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    apex_count INTEGER NOT NULL DEFAULT 0,
                    hostname_count INTEGER NOT NULL DEFAULT 0,
                    duration_ms INTEGER,
                    bytes_read INTEGER
                );

                CREATE TABLE IF NOT EXISTS ingest_state (
                    source TEXT PRIMARY KEY,
                    cursor TEXT,
                    etag TEXT,
                    updated_at TEXT
                ) WITHOUT ROWID;
                """
            )
            connection.execute(
                "DELETE FROM request_counts WHERE day < date('now', '-2 days')"
            )

    def search(self, apex: str) -> list[SearchResult]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT subdomain, first_seen
                FROM subdomains
                WHERE apex = ?
                ORDER BY first_seen IS NULL, first_seen, subdomain
                """,
                (apex,),
            ).fetchall()
        return [SearchResult(row["subdomain"], row["first_seen"]) for row in rows]

    def upsert_subdomains(
        self,
        apex: str,
        rows: Iterable[tuple[str, str | None]],
    ) -> None:
        values: list[tuple[str, str, str | None]] = []
        for subdomain, first_seen in rows:
            canonical = subdomain.lower().rstrip(".")
            if canonical != apex and not canonical.endswith(f".{apex}"):
                raise ValueError(f"{subdomain!r} is not under {apex!r}")
            values.append((apex, canonical, first_seen))

        with self.connect() as connection:
            connection.executemany(
                """
                INSERT INTO subdomains (apex, subdomain, first_seen)
                VALUES (?, ?, ?)
                ON CONFLICT (apex, subdomain) DO UPDATE SET
                    first_seen = CASE
                        WHEN subdomains.first_seen IS NULL THEN excluded.first_seen
                        WHEN excluded.first_seen IS NULL THEN subdomains.first_seen
                        WHEN excluded.first_seen < subdomains.first_seen THEN excluded.first_seen
                        ELSE subdomains.first_seen
                    END
                """,
                values,
            )

    def consume_request(
        self,
        client_ip: str,
        limit: int,
        now: datetime | None = None,
    ) -> Quota:
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("now must include a timezone")
        current = current.astimezone(UTC)
        day = current.date().isoformat()
        reset = datetime.combine(current.date() + timedelta(days=1), time.min, UTC)

        with self.connect() as connection:
            row = connection.execute(
                """
                INSERT INTO request_counts (day, client_ip, used)
                VALUES (?, ?, 1)
                ON CONFLICT (day, client_ip) DO UPDATE SET used = used + 1
                WHERE used < ?
                RETURNING used
                """,
                (day, client_ip, limit),
            ).fetchone()

        if row is None:
            raise QuotaExceeded(Quota(limit=limit, remaining=0, reset_at=int(reset.timestamp())))

        used = int(row["used"])
        return Quota(
            limit=limit,
            remaining=max(0, limit - used),
            reset_at=int(reset.timestamp()),
        )

    def consume_certspotter(
        self,
        client_ip: str,
        limit: int,
        now: datetime | None = None,
    ) -> Quota:
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("now must include a timezone")
        current = current.astimezone(UTC)
        day = current.date().isoformat()
        reset = datetime.combine(current.date() + timedelta(days=1), time.min, UTC)

        with self.connect() as connection:
            row = connection.execute(
                """
                INSERT INTO certspotter_counts (day, client_ip, used)
                VALUES (?, ?, 1)
                ON CONFLICT (day, client_ip) DO UPDATE SET used = used + 1
                WHERE used < ?
                RETURNING used
                """,
                (day, client_ip, limit),
            ).fetchone()

        if row is None:
            raise QuotaExceeded(Quota(limit=limit, remaining=0, reset_at=int(reset.timestamp())))

        used = int(row["used"])
        return Quota(
            limit=limit,
            remaining=max(0, limit - used),
            reset_at=int(reset.timestamp()),
        )

    def consume_shodanct(
        self,
        client_ip: str,
        limit: int,
        now: datetime | None = None,
    ) -> Quota:
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ValueError("now must include a timezone")
        current = current.astimezone(UTC)
        day = current.date().isoformat()
        reset = datetime.combine(current.date() + timedelta(days=1), time.min, UTC)

        with self.connect() as connection:
            row = connection.execute(
                """
                INSERT INTO shodanct_counts (day, client_ip, used)
                VALUES (?, ?, 1)
                ON CONFLICT (day, client_ip) DO UPDATE SET used = used + 1
                WHERE used < ?
                RETURNING used
                """,
                (day, client_ip, limit),
            ).fetchone()

        if row is None:
            raise QuotaExceeded(Quota(limit=limit, remaining=0, reset_at=int(reset.timestamp())))

        used = int(row["used"])
        return Quota(
            limit=limit,
            remaining=max(0, limit - used),
            reset_at=int(reset.timestamp()),
        )

    def record_ingest_run(
        self,
        source: str,
        started_at: str,
        finished_at: str | None = None,
        apex_count: int = 0,
        hostname_count: int = 0,
        duration_ms: int | None = None,
        bytes_read: int | None = None,
    ) -> int:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO ingest_runs (source, started_at, finished_at, apex_count, hostname_count, duration_ms, bytes_read)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (source, started_at, finished_at, apex_count, hostname_count, duration_ms, bytes_read),
            )
            return int(cursor.lastrowid)

    def get_ingest_state(self, source: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT source, cursor, etag, updated_at FROM ingest_state WHERE source = ?",
                (source,),
            ).fetchone()
            return dict(row) if row else None

    def upsert_ingest_state(
        self,
        source: str,
        cursor: str | None = None,
        etag: str | None = None,
        updated_at: str | None = None,
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO ingest_state (source, cursor, etag, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (source) DO UPDATE SET
                    cursor = excluded.cursor,
                    etag = excluded.etag,
                    updated_at = excluded.updated_at
                """,
                (source, cursor, etag, updated_at),
            )

