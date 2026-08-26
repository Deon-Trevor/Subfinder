from pathlib import Path

from ctlogs.control import ControlDatabase
from ctlogs.database import Database
from ctlogs.migrate import migrate


def test_migrate_prepares_both_state_stores(tmp_path: Path) -> None:
    catalog_path = tmp_path / "catalog.sqlite3"
    control_path = tmp_path / "control.sqlite3"

    legacy = Database(catalog_path)
    legacy.initialize()
    legacy.upsert_ingest_state(
        "queue:urlscan:example.com",
        cursor="pending",
        updated_at="2026-08-24T00:00:00+00:00",
    )

    migrate(catalog_path, control_path)

    Database(catalog_path, read_only=True).verify_schema()
    assert ControlDatabase(control_path).queued_refreshes(1) == ["example.com"]
    assert legacy.get_ingest_state("queue:urlscan:example.com") is None
