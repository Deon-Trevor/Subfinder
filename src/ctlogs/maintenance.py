from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

from ctlogs.database import Database

LEGACY_FIXTURE_ROWS = (
    ("syncpundit.io", "syncpundit.io", "2024-01-01T00:00:00Z"),
    ("syncpundit.io", "www.syncpundit.io", "2024-01-02T00:00:00Z"),
    ("syncpundit.io", "api.syncpundit.io", "2024-01-03T00:00:00Z"),
    ("syncpundit.io", "mcp.syncpundit.io", None),
    ("example.com", "example.com", "2024-01-01T00:00:00Z"),
    ("example.com", "www.example.com", "2024-01-02T00:00:00Z"),
    ("example.com", "api.example.com", None),
)


def find_legacy_fixture_rows(database: Database) -> list[tuple[str, str, str | None]]:
    matches: list[tuple[str, str, str | None]] = []
    with database.connect() as connection:
        for apex, hostname, first_seen in LEGACY_FIXTURE_ROWS:
            row = connection.execute(
                """
                SELECT apex, subdomain, first_seen
                FROM subdomains AS names
                WHERE apex = ? AND subdomain = ? AND first_seen IS ?
                  AND NOT EXISTS (
                      SELECT 1 FROM subdomain_sources AS evidence
                      WHERE evidence.apex = names.apex
                        AND evidence.subdomain = names.subdomain
                  )
                """,
                (apex, hostname, first_seen),
            ).fetchone()
            if row:
                matches.append((row["apex"], row["subdomain"], row["first_seen"]))
    return matches


def backup_database(database: Database, destination: Path) -> None:
    if destination.exists():
        raise FileExistsError(f"backup already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with database.connect() as source, sqlite3.connect(destination) as target:
        source.backup(target)


def remove_legacy_fixture_rows(database: Database) -> int:
    matches = find_legacy_fixture_rows(database)
    with database.write_transaction() as connection:
        cursor = connection.executemany(
            """
            DELETE FROM subdomains AS names
            WHERE apex = ? AND subdomain = ? AND first_seen IS ?
              AND NOT EXISTS (
                  SELECT 1 FROM subdomain_sources AS evidence
                  WHERE evidence.apex = names.apex
                    AND evidence.subdomain = names.subdomain
              )
            """,
            matches,
        )
    return cursor.rowcount


def main() -> None:
    parser = argparse.ArgumentParser(description="Safely remove known legacy fixture rows")
    parser.add_argument("--db", default="data/ctlogs.sqlite3")
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    database = Database(args.db)
    database.initialize()
    matches = find_legacy_fixture_rows(database)
    for apex, hostname, first_seen in matches:
        print(f"{apex}\t{hostname}\t{first_seen or ''}")
    if not args.apply:
        print(f"dry-run: {len(matches)} removable rows")
        return
    if args.backup is None:
        parser.error("--backup is required with --apply")
    backup_database(database, args.backup)
    removed = remove_legacy_fixture_rows(database)
    print(f"removed={removed} backup={args.backup}")


if __name__ == "__main__":
    main()
