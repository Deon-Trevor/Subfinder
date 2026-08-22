from __future__ import annotations

from pathlib import Path

from ctlogs.database import Database
from ctlogs.maintenance import (
    backup_database,
    find_legacy_fixture_rows,
    remove_legacy_fixture_rows,
)


def test_cleanup_removes_only_exact_provenance_free_fixture_rows(tmp_path: Path) -> None:
    database = Database(tmp_path / "live.sqlite3")
    database.initialize()
    database.upsert_subdomains(
        "syncpundit.io",
        [
            ("syncpundit.io", "2024-01-01T00:00:00Z"),
            ("www.syncpundit.io", "2024-01-02T00:00:00Z"),
            ("live.syncpundit.io", None),
        ],
    )
    database.upsert_subdomains(
        "syncpundit.io",
        [("api.syncpundit.io", "2024-01-03T00:00:00Z")],
        source="live-source",
    )
    backup = tmp_path / "backup.sqlite3"

    assert len(find_legacy_fixture_rows(database)) == 2
    backup_database(database, backup)
    assert remove_legacy_fixture_rows(database) == 2
    assert [row.subdomain for row in database.search("syncpundit.io")] == [
        "api.syncpundit.io",
        "live.syncpundit.io",
    ]
    assert len(Database(backup).search("syncpundit.io")) == 4

