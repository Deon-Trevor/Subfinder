from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "export_r2_index.py"
SPEC = importlib.util.spec_from_file_location("export_r2_index", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def catalog() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE subdomains (
            apex TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            first_seen TEXT,
            PRIMARY KEY (apex, subdomain)
        ) WITHOUT ROWID;
        CREATE TABLE subdomain_sources (
            apex TEXT NOT NULL,
            subdomain TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (apex, subdomain, source)
        ) WITHOUT ROWID;
        """
    )
    connection.executemany(
        "INSERT INTO subdomains VALUES (?, ?, ?)",
        [
            ("example.com", "old.example.com", "2020-01-01T00:00:00Z"),
            ("example.com", "new.example.com", "2025-01-01T00:00:00Z"),
            ("example.com", "unknown.example.com", None),
            ("small.test", "small.test", None),
        ],
    )
    connection.executemany(
        "INSERT INTO subdomain_sources VALUES (?, ?, ?, ?, ?)",
        [
            (
                "example.com",
                "old.example.com",
                "czds:com",
                None,
                "2026-01-01T00:00:00Z",
            ),
            (
                "example.com",
                "old.example.com",
                "static_ct:test",
                "2020-01-01T00:00:00Z",
                "2026-01-02T00:00:00Z",
            ),
        ],
    )
    return connection


def test_export_preserves_records_and_search_order(tmp_path: Path) -> None:
    root = MODULE.export_catalog(
        catalog(),
        output=tmp_path,
        generation="fixture",
        apexes=None,
        partition_nibbles=2,
        target_block_bytes=4_096,
    )

    document = MODULE.read_export_apex(tmp_path, root, "example.com")

    assert document is not None
    assert document["total"] == 3
    assert document["dated"] == 2
    assert [record["h"] for record in document["records"]] == [
        "old.example.com",
        "new.example.com",
        "unknown.example.com",
    ]
    assert [source["n"] for source in document["records"][0]["s"]] == [
        "czds:com",
        "static_ct:test",
    ]
    assert MODULE.read_export_apex(tmp_path, root, "missing.test") is None


def test_exact_apex_counts_includes_missing_requested_names() -> None:
    assert MODULE.exact_apex_counts(
        catalog(),
        ["missing.test", "example.com", "example.com"],
    ) == {"example.com": 3, "missing.test": 0}


def test_catalog_watermark_uses_latest_finished_run() -> None:
    connection = catalog()
    connection.execute(
        "CREATE TABLE ingest_runs (id INTEGER PRIMARY KEY, finished_at TEXT)"
    )
    connection.executemany(
        "INSERT INTO ingest_runs VALUES (?, ?)",
        [(1, "2026-01-01T00:00:00Z"), (2, None), (3, "2026-02-01T00:00:00Z")],
    )
    assert MODULE.catalog_watermark(connection) == "2026-02-01T00:00:00Z"


def test_large_apex_uses_ordered_overflow_chunks(tmp_path: Path) -> None:
    connection = catalog()
    connection.executemany(
        "INSERT INTO subdomains VALUES (?, ?, ?)",
        [
            (
                "large.test",
                f"node-{index:03d}.large.test",
                f"2026-01-{1 + index % 28:02d}T00:00:00Z",
            )
            for index in range(80)
        ],
    )

    root = MODULE.export_catalog(
        connection,
        output=tmp_path,
        generation="overflow",
        apexes=None,
        partition_nibbles=1,
        target_block_bytes=512,
    )
    prefix = MODULE.partition_prefix("large.test", 1)
    index = MODULE.read_partition_index(tmp_path, root, prefix)
    overflow = index["overflow"]["large.test"]
    document = MODULE.read_export_apex(tmp_path, root, "large.test")

    assert len(overflow["chunks"]) > 1
    assert document is not None
    assert document["total"] == 80
    assert document["dated"] == 80
    assert len(document["records"]) == 80
    cursors = [MODULE.record_cursor(record) for record in document["records"]]
    assert cursors == sorted(cursors, key=MODULE.cursor_sort_key)


def test_export_is_reproducible_for_the_same_generation(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    root_a = MODULE.export_catalog(
        catalog(),
        output=first,
        generation="repeatable",
        apexes=None,
        partition_nibbles=2,
        target_block_bytes=1_024,
    )
    root_b = MODULE.export_catalog(
        catalog(),
        output=second,
        generation="repeatable",
        apexes=None,
        partition_nibbles=2,
        target_block_bytes=1_024,
    )

    assert root_a == root_b
    first_files = {
        path.relative_to(first): path.read_bytes()
        for path in first.rglob("*")
        if path.is_file()
    }
    second_files = {
        path.relative_to(second): path.read_bytes()
        for path in second.rglob("*")
        if path.is_file()
    }
    assert first_files == second_files
