from __future__ import annotations

from collections.abc import Iterable, Iterator
from contextlib import contextmanager
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
import fcntl
from pathlib import Path


@dataclass(frozen=True)
class SearchResult:
    subdomain: str
    first_seen: str | None


@dataclass(frozen=True)
class SearchCursor:
    subdomain: str
    first_seen: str | None


@dataclass(frozen=True)
class SourceObservation:
    source: str
    first_seen: str | None
    last_seen: str


@dataclass(frozen=True)
class IndexedRecord:
    hostname: str
    first_seen: str | None
    sources: tuple[SourceObservation, ...]


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
    def __init__(
        self,
        path: str | Path,
        *,
        read_only: bool = False,
        busy_timeout_ms: int = 1_000,
    ) -> None:
        if busy_timeout_ms < 1:
            raise ValueError("busy_timeout_ms must be positive")
        self.path = Path(path)
        self.read_only = read_only
        self.busy_timeout_ms = busy_timeout_ms

    def _open_connection(self) -> sqlite3.Connection:
        target: str | Path = self.path
        uri = False
        if self.read_only:
            target = f"{self.path.resolve().as_uri()}?mode=ro"
            uri = True
        connection = sqlite3.connect(
            target,
            timeout=self.busy_timeout_ms / 1000,
            uri=uri,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        return connection

    def connect(self) -> sqlite3.Connection:
        """Open a read-only application connection."""
        connection = self._open_connection()
        connection.execute("PRAGMA query_only = ON")
        return connection

    @contextmanager
    def write_transaction(self) -> Iterator[sqlite3.Connection]:
        """Run one mutation while excluding writers in every service process."""
        if self.read_only:
            raise RuntimeError("the catalog is read-only in this process")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(f"{self.path.name}.write.lock")
        with lock_path.open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            connection = self._open_connection()
            try:
                with connection:
                    yield connection
            finally:
                connection.close()
                fcntl.flock(lock, fcntl.LOCK_UN)

    def initialize(self) -> None:
        with self.write_transaction() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            needs_source_backfill = connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = 'index_sources'"
            ).fetchone() is None
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

                CREATE TABLE IF NOT EXISTS index_sources (
                    source TEXT PRIMARY KEY
                ) WITHOUT ROWID;

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

            if needs_source_backfill:
                connection.execute(
                    "INSERT INTO index_sources(source) "
                    "SELECT DISTINCT source FROM subdomain_sources"
                )

            if connection.execute(
                "SELECT 1 FROM index_totals WHERE singleton = 1"
            ).fetchone() is None:
                connection.execute(
                    """
                    INSERT INTO index_totals (
                        singleton, apex_count, hostname_count, dated_hostname_count
                    )
                    SELECT 1, COUNT(DISTINCT apex), COUNT(*), COUNT(first_seen)
                    FROM subdomains
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
                CREATE TRIGGER IF NOT EXISTS stats_source_insert
                AFTER INSERT ON subdomain_sources
                BEGIN
                    INSERT OR IGNORE INTO index_sources(source) VALUES(NEW.source);
                END;

                CREATE TRIGGER IF NOT EXISTS stats_source_delete
                AFTER DELETE ON subdomain_sources
                BEGIN
                    DELETE FROM index_sources
                    WHERE source = OLD.source
                      AND NOT EXISTS (
                          SELECT 1 FROM subdomain_sources
                          WHERE source = OLD.source
                      );
                END;

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

    def verify_schema(self) -> None:
        """Perform bounded startup checks without mutating or scanning the catalog."""
        required_tables = {
            "subdomains",
            "subdomain_sources",
            "index_totals",
            "index_sources",
            "ingest_runs",
        }
        with self.connect() as connection:
            present = {
                str(row["name"])
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            missing = required_tables - present
            if missing:
                raise RuntimeError(
                    "catalog migration required; missing tables: "
                    + ", ".join(sorted(missing))
                )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(index_totals)")
            }
            required_columns = {
                "apex_count",
                "hostname_count",
                "dated_hostname_count",
                "ct_hostname_count",
                "ct_log_count",
            }
            if required_columns - columns:
                raise RuntimeError("catalog migration required; index totals are stale")
            if connection.execute(
                "SELECT 1 FROM index_totals WHERE singleton = 1"
            ).fetchone() is None:
                raise RuntimeError("catalog migration required; index totals are missing")

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

    def iter_search(
        self,
        apex: str,
        *,
        after: SearchCursor | None = None,
        limit: int | None = None,
        fetch_size: int = 1_000,
    ) -> Iterator[SearchResult]:
        if limit is not None and limit < 1:
            raise ValueError("limit must be positive")
        if fetch_size < 1:
            raise ValueError("fetch_size must be positive")

        where = "WHERE apex = ?"
        parameters: list[object] = [apex]
        if after is not None:
            null_rank = 1 if after.first_seen is None else 0
            where += """
                AND (
                    (first_seen IS NULL) > ?
                    OR (
                        (first_seen IS NULL) = ?
                        AND (
                            (? = 0 AND (
                                first_seen > ?
                                OR (first_seen = ? AND subdomain > ?)
                            ))
                            OR (? = 1 AND subdomain > ?)
                        )
                    )
                )
            """
            parameters.extend(
                [
                    null_rank,
                    null_rank,
                    null_rank,
                    after.first_seen,
                    after.first_seen,
                    after.subdomain,
                    null_rank,
                    after.subdomain,
                ]
            )

        sql = f"""
            SELECT subdomain, first_seen
            FROM subdomains
            {where}
            ORDER BY first_seen IS NULL, first_seen, subdomain
        """
        if limit is not None:
            sql += " LIMIT ?"
            parameters.append(limit)

        with self.connect() as connection:
            cursor = connection.execute(sql, parameters)
            while rows := cursor.fetchmany(fetch_size):
                for row in rows:
                    yield SearchResult(str(row["subdomain"]), row["first_seen"])

    def search_page(
        self,
        apex: str,
        *,
        after: SearchCursor | None,
        limit: int,
    ) -> tuple[list[SearchResult], SearchCursor | None]:
        rows = list(self.iter_search(apex, after=after, limit=limit + 1))
        if len(rows) <= limit:
            return rows, None
        page = rows[:limit]
        tail = page[-1]
        return page, SearchCursor(tail.subdomain, tail.first_seen)

    def watermark(self) -> str | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT finished_at
                FROM ingest_runs
                WHERE finished_at IS NOT NULL
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
        return str(row["finished_at"]) if row else None

    def records(self, apex: str) -> list[IndexedRecord]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    names.subdomain,
                    names.first_seen AS hostname_first_seen,
                    evidence.source,
                    evidence.first_seen AS source_first_seen,
                    evidence.last_seen
                FROM subdomains AS names
                LEFT JOIN subdomain_sources AS evidence
                    ON evidence.apex = names.apex
                   AND evidence.subdomain = names.subdomain
                WHERE names.apex = ?
                ORDER BY
                    names.first_seen IS NULL,
                    names.first_seen,
                    names.subdomain,
                    evidence.source
                """,
                (apex,),
            ).fetchall()

        records: list[IndexedRecord] = []
        sources: list[SourceObservation] = []
        hostname: str | None = None
        first_seen: str | None = None
        for row in rows:
            row_hostname = str(row["subdomain"])
            if hostname is not None and row_hostname != hostname:
                records.append(IndexedRecord(hostname, first_seen, tuple(sources)))
                sources = []
            if row_hostname != hostname:
                hostname = row_hostname
                first_seen = row["hostname_first_seen"]
            if row["source"] is not None:
                sources.append(
                    SourceObservation(
                        source=str(row["source"]),
                        first_seen=row["source_first_seen"],
                        last_seen=str(row["last_seen"]),
                    )
                )
        if hostname is not None:
            records.append(IndexedRecord(hostname, first_seen, tuple(sources)))
        return records

    def apexes_after(self, cursor: str, limit: int) -> list[str]:
        if limit < 1:
            raise ValueError("limit must be positive")
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT apex
                FROM subdomains
                WHERE apex > ?
                ORDER BY apex
                LIMIT ?
                """,
                (cursor, limit),
            ).fetchall()
        return [str(row["apex"]) for row in rows]

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

        with self.write_transaction() as connection:
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
        with self.write_transaction() as connection:
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
                    (SELECT COUNT(*) FROM index_sources)
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

        with self.write_transaction() as connection:
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

    def consume_partitioned_request(
        self,
        total_subject: str,
        total_limit: int,
        class_subject: str,
        class_limit: int,
        now: datetime | None = None,
    ) -> Quota:
        if total_subject == class_subject:
            raise ValueError("quota subjects must be distinct")
        if total_limit < 1 or class_limit < 1:
            raise ValueError("quota limits must be positive")
        if now is None:
            now = datetime.now(UTC)
        if now.tzinfo is None:
            raise ValueError("now must include a timezone")

        current = now.astimezone(UTC)
        day = current.date().isoformat()
        reset = datetime.combine(current.date() + timedelta(days=1), time.min, UTC)
        reset_at = int(reset.timestamp())

        with self.write_transaction() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                """
                SELECT client_ip, used
                FROM request_counts
                WHERE day = ? AND client_ip IN (?, ?)
                """,
                (day, total_subject, class_subject),
            ).fetchall()
            used = {str(row["client_ip"]): int(row["used"]) for row in rows}
            total_used = used.get(total_subject, 0)
            class_used = used.get(class_subject, 0)
            if total_used >= total_limit:
                raise QuotaExceeded(Quota(total_limit, 0, reset_at))
            if class_used >= class_limit:
                raise QuotaExceeded(Quota(class_limit, 0, reset_at))
            connection.executemany(
                """
                INSERT INTO request_counts (day, client_ip, used)
                VALUES (?, ?, 1)
                ON CONFLICT (day, client_ip) DO UPDATE SET used = used + 1
                """,
                (
                    (day, total_subject),
                    (day, class_subject),
                ),
            )

        return Quota(
            limit=class_limit,
            remaining=class_limit - class_used - 1,
            reset_at=reset_at,
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
        with self.write_transaction() as connection:
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
        with self.write_transaction() as connection:
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
