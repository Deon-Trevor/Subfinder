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


@dataclass(frozen=True)
class IndexStats:
    apex_count: int
    hostname_count: int
    dated_hostname_count: int
    source_count: int
    ct_hostname_count: int
    ct_log_count: int
    last_ingest_at: str | None


class QuotaExceeded(Exception):
    def __init__(self, quota: Quota) -> None:
        super().__init__("daily request limit exceeded")
        self.quota = quota


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=60)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 60000")
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
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

                CREATE TABLE IF NOT EXISTS subdomain_sources (
                    apex TEXT NOT NULL,
                    subdomain TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT,
                    last_seen TEXT NOT NULL,
                    PRIMARY KEY (apex, subdomain, source),
                    FOREIGN KEY (apex, subdomain)
                        REFERENCES subdomains(apex, subdomain)
                        ON DELETE CASCADE
                ) WITHOUT ROWID;

                CREATE INDEX IF NOT EXISTS idx_subdomains_search_order
                    ON subdomains(apex, (first_seen IS NULL), first_seen, subdomain);

                CREATE INDEX IF NOT EXISTS idx_subdomain_sources_source
                    ON subdomain_sources(source, apex, subdomain);

                CREATE TABLE IF NOT EXISTS index_totals (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    apex_count INTEGER NOT NULL,
                    hostname_count INTEGER NOT NULL,
                    dated_hostname_count INTEGER NOT NULL
                );

                INSERT OR IGNORE INTO index_totals (
                    singleton, apex_count, hostname_count, dated_hostname_count
                )
                SELECT
                    1,
                    COUNT(DISTINCT apex),
                    COUNT(*),
                    COUNT(first_seen)
                FROM subdomains;

                CREATE TRIGGER IF NOT EXISTS stats_subdomain_insert
                AFTER INSERT ON subdomains
                BEGIN
                    UPDATE index_totals SET
                        apex_count = apex_count + CASE
                            WHEN (
                                SELECT COUNT(*) FROM subdomains
                                WHERE apex = NEW.apex
                            ) = 1 THEN 1 ELSE 0 END,
                        hostname_count = hostname_count + 1,
                        dated_hostname_count = dated_hostname_count
                            + CASE WHEN NEW.first_seen IS NULL THEN 0 ELSE 1 END
                    WHERE singleton = 1;
                END;

                CREATE TRIGGER IF NOT EXISTS stats_subdomain_date_update
                AFTER UPDATE OF first_seen ON subdomains
                WHEN (OLD.first_seen IS NULL) != (NEW.first_seen IS NULL)
                BEGIN
                    UPDATE index_totals SET
                        dated_hostname_count = dated_hostname_count + CASE
                            WHEN NEW.first_seen IS NULL THEN -1 ELSE 1 END
                    WHERE singleton = 1;
                END;

                CREATE TRIGGER IF NOT EXISTS stats_subdomain_delete
                AFTER DELETE ON subdomains
                BEGIN
                    UPDATE index_totals SET
                        apex_count = apex_count - CASE
                            WHEN NOT EXISTS (
                                SELECT 1 FROM subdomains WHERE apex = OLD.apex
                            ) THEN 1 ELSE 0 END,
                        hostname_count = hostname_count - 1,
                        dated_hostname_count = dated_hostname_count
                            - CASE WHEN OLD.first_seen IS NULL THEN 0 ELSE 1 END
                    WHERE singleton = 1;
                END;
                """
            )

            total_columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(index_totals)")
            }
            if "ct_hostname_count" not in total_columns:
                connection.execute(
                    "ALTER TABLE index_totals "
                    "ADD COLUMN ct_hostname_count INTEGER NOT NULL DEFAULT 0"
                )
                connection.execute(
                    """
                    UPDATE index_totals SET ct_hostname_count = (
                        SELECT COUNT(*)
                        FROM subdomains AS names
                        WHERE EXISTS (
                            SELECT 1
                            FROM subdomain_sources AS evidence
                            WHERE evidence.apex = names.apex
                              AND evidence.subdomain = names.subdomain
                              AND (
                                  evidence.source LIKE 'direct_ct:%'
                                  OR evidence.source LIKE 'static_ct:%'
                              )
                        )
                    )
                    WHERE singleton = 1
                    """
                )
            if "ct_log_count" not in total_columns:
                connection.execute(
                    "ALTER TABLE index_totals "
                    "ADD COLUMN ct_log_count INTEGER NOT NULL DEFAULT 0"
                )
                connection.execute(
                    """
                    UPDATE index_totals SET ct_log_count = (
                        SELECT COUNT(DISTINCT source)
                        FROM subdomain_sources
                        WHERE source LIKE 'direct_ct:%'
                           OR source LIKE 'static_ct:%'
                    )
                    WHERE singleton = 1
                    """
                )

            connection.executescript(
                """
                CREATE TRIGGER IF NOT EXISTS stats_ct_source_insert
                AFTER INSERT ON subdomain_sources
                WHEN NEW.source LIKE 'direct_ct:%'
                  OR NEW.source LIKE 'static_ct:%'
                BEGIN
                    UPDATE index_totals SET
                        ct_hostname_count = ct_hostname_count + CASE
                            WHEN (
                                SELECT COUNT(*)
                                FROM subdomain_sources
                                WHERE apex = NEW.apex
                                  AND subdomain = NEW.subdomain
                                  AND (
                                      source LIKE 'direct_ct:%'
                                      OR source LIKE 'static_ct:%'
                                  )
                            ) = 1 THEN 1 ELSE 0 END,
                        ct_log_count = ct_log_count + CASE
                            WHEN (
                                SELECT COUNT(*)
                                FROM subdomain_sources
                                WHERE source = NEW.source
                            ) = 1 THEN 1 ELSE 0 END
                    WHERE singleton = 1;
                END;

                CREATE TRIGGER IF NOT EXISTS stats_ct_source_delete
                AFTER DELETE ON subdomain_sources
                WHEN OLD.source LIKE 'direct_ct:%'
                  OR OLD.source LIKE 'static_ct:%'
                BEGIN
                    UPDATE index_totals SET
                        ct_hostname_count = ct_hostname_count - CASE
                            WHEN NOT EXISTS (
                                SELECT 1
                                FROM subdomain_sources
                                WHERE apex = OLD.apex
                                  AND subdomain = OLD.subdomain
                                  AND (
                                      source LIKE 'direct_ct:%'
                                      OR source LIKE 'static_ct:%'
                                  )
                            ) THEN 1 ELSE 0 END,
                        ct_log_count = ct_log_count - CASE
                            WHEN NOT EXISTS (
                                SELECT 1
                                FROM subdomain_sources
                                WHERE source = OLD.source
                            ) THEN 1 ELSE 0 END
                    WHERE singleton = 1;
                END;
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
        *,
        source: str | None = None,
        observed_at: str | None = None,
    ) -> None:
        values: list[tuple[str, str, str | None]] = []
        for subdomain, first_seen in rows:
            canonical = subdomain.lower().rstrip(".")
            if canonical != apex and not canonical.endswith(f".{apex}"):
                raise ValueError(f"{subdomain!r} is not under {apex!r}")
            values.append((apex, canonical, first_seen))

        if source is not None:
            source = source.strip()
            if not source:
                raise ValueError("source must not be empty")
            observed_at = observed_at or datetime.now(UTC).isoformat()

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
            if source is not None and observed_at is not None:
                connection.executemany(
                    """
                    INSERT INTO subdomain_sources (
                        apex, subdomain, source, first_seen, last_seen
                    )
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (apex, subdomain, source) DO UPDATE SET
                        first_seen = CASE
                            WHEN subdomain_sources.first_seen IS NULL
                                THEN excluded.first_seen
                            WHEN excluded.first_seen IS NULL
                                THEN subdomain_sources.first_seen
                            WHEN excluded.first_seen < subdomain_sources.first_seen
                                THEN excluded.first_seen
                            ELSE subdomain_sources.first_seen
                        END,
                        last_seen = CASE
                            WHEN excluded.last_seen > subdomain_sources.last_seen
                                THEN excluded.last_seen
                            ELSE subdomain_sources.last_seen
                        END
                    """,
                    [
                        (row_apex, subdomain, source, first_seen, observed_at)
                        for row_apex, subdomain, first_seen in values
                    ],
                )

    def upsert_subdomains_batch_apex(
        self,
        rows: Iterable[tuple[str, str | None]],
        *,
        source: str,
        observed_at: str | None = None,
    ) -> None:
        """Insert apex-only rows whose apex is the hostname itself."""
        source = source.strip()
        if not source:
            raise ValueError("source must not be empty")
        observed_at = observed_at or datetime.now(UTC).isoformat()
        values = [(hostname, hostname, first_seen) for hostname, first_seen in rows]
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
            connection.executemany(
                """
                INSERT INTO subdomain_sources (
                    apex, subdomain, source, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT (apex, subdomain, source) DO UPDATE SET
                    last_seen = CASE
                        WHEN excluded.last_seen > subdomain_sources.last_seen
                            THEN excluded.last_seen
                        ELSE subdomain_sources.last_seen
                    END
                """,
                [
                    (apex, hostname, source, first_seen, observed_at)
                    for apex, hostname, first_seen in values
                ],
            )

    def stats(self) -> IndexStats:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    totals.apex_count,
                    totals.hostname_count,
                    totals.dated_hostname_count,
                    totals.ct_hostname_count,
                    totals.ct_log_count,
                    (SELECT COUNT(DISTINCT source) FROM subdomain_sources)
                        AS source_count,
                    (SELECT MAX(finished_at) FROM ingest_runs) AS last_ingest_at
                FROM index_totals AS totals
                WHERE totals.singleton = 1
                """
            ).fetchone()
        return IndexStats(
            apex_count=int(row["apex_count"]),
            hostname_count=int(row["hostname_count"]),
            dated_hostname_count=int(row["dated_hostname_count"]),
            source_count=int(row["source_count"]),
            ct_hostname_count=int(row["ct_hostname_count"]),
            ct_log_count=int(row["ct_log_count"]),
            last_ingest_at=row["last_ingest_at"],
        )

    def consume_request(
        self,
        client_ip: str,
        limit: int,
        now: datetime | None = None,
    ) -> Quota:
        if now is None:
            now = datetime.now(UTC)
        if now.tzinfo is None:
            raise ValueError("now must include a timezone")

        current = now.astimezone(UTC)
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
            raise QuotaExceeded(
                Quota(
                    limit=limit,
                    remaining=0,
                    reset_at=int(reset.timestamp()),
                )
            )

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
