from __future__ import annotations

import argparse
import os
from pathlib import Path

from ctlogs.control import ControlDatabase
from ctlogs.database import Database


def migrate(catalog_path: str | Path, control_path: str | Path) -> None:
    """Apply catalog and control schemas before read and writer services start."""
    catalog = Database(catalog_path)
    catalog.initialize()
    control = ControlDatabase(control_path, busy_timeout_ms=1_000)
    control.initialize()

    prefix = "queue:urlscan:"
    with catalog.connect() as connection:
        legacy = connection.execute(
            """
            SELECT substr(source, ?) AS apex, updated_at
            FROM ingest_state
            WHERE source >= 'queue:urlscan:' AND source < 'queue:urlscan;'
            ORDER BY updated_at, source
            """,
            (len(prefix) + 1,),
        ).fetchall()
    migrated_sources: list[tuple[str]] = []
    for row in legacy:
        status = control.enqueue_refresh(
            str(row["apex"]),
            requested_at=str(row["updated_at"]),
        )
        if status != "queue-full":
            migrated_sources.append((f"{prefix}{row['apex']}",))
    if migrated_sources:
        with catalog.write_transaction() as connection:
            connection.executemany(
                "DELETE FROM ingest_state WHERE source = ?",
                migrated_sources,
            )


def main() -> None:
    parser = argparse.ArgumentParser(description="Migrate Subfinder state stores")
    parser.add_argument(
        "--db",
        default=os.environ.get("CTLOGS_DB_PATH", "data/ctlogs.sqlite3"),
    )
    parser.add_argument(
        "--control-db",
        default=os.environ.get("CTLOGS_CONTROL_DB_PATH", "data/control.sqlite3"),
    )
    args = parser.parse_args()
    migrate(args.db, args.control_db)


if __name__ == "__main__":
    main()
