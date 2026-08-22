from __future__ import annotations

from pathlib import Path

import pytest

from ctlogs.database import Database
from ctlogs.ingest.backfill import run_job


def test_local_backfill_records_provenance_and_skips_unchanged_artifact(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "hosts.txt"
    artifact.write_text("0.0.0.0 ads.example.com\n0.0.0.0 cdn.example.com\n")
    database = Database(tmp_path / "backfill.sqlite3")
    database.initialize()

    assert run_job(database, "hagezi", str(artifact)) == 2
    assert run_job(database, "hagezi", str(artifact)) == 0

    assert [row.subdomain for row in database.search("example.com")] == [
        "ads.example.com",
        "cdn.example.com",
    ]
    with database.connect() as connection:
        provenance = connection.execute(
            "SELECT DISTINCT source FROM subdomain_sources"
        ).fetchall()
        run_count = connection.execute(
            "SELECT COUNT(*) FROM ingest_runs WHERE source = 'hagezi'"
        ).fetchone()[0]
    assert [row["source"] for row in provenance] == ["hagezi"]
    assert run_count == 1


def test_backfill_rejects_unsupported_per_apex_source(tmp_path: Path) -> None:
    artifact = tmp_path / "hosts.txt"
    artifact.write_text("www.example.com\n")
    database = Database(tmp_path / "backfill.sqlite3")
    database.initialize()

    with pytest.raises(ValueError, match="unsupported global source"):
        run_job(database, "hackertarget", str(artifact))


def test_backfill_enforces_artifact_size_limit(tmp_path: Path) -> None:
    artifact = tmp_path / "hosts.txt"
    artifact.write_text("www.example.com\n")
    database = Database(tmp_path / "backfill.sqlite3")
    database.initialize()

    with pytest.raises(ValueError, match="artifact exceeds"):
        run_job(database, "hagezi", str(artifact), max_bytes=4)
