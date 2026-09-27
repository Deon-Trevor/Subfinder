from __future__ import annotations

import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).parents[3]
sys.path.insert(0, str(ROOT / "scripts"))

from export_r2_index import export_catalog  # noqa: E402


def main() -> None:
    output = Path(sys.argv[1])
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
            ("small.dev", "small.dev", None),
            *[
                (
                    "large.dev",
                    f"node-{index:03d}.large.dev",
                    f"2026-01-{1 + index % 28:02d}T00:00:00Z",
                )
                for index in range(80)
            ],
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
    export_catalog(
        connection,
        output=output,
        generation="worker-fixture",
        apexes=None,
        partition_nibbles=1,
        target_block_bytes=512,
    )


if __name__ == "__main__":
    main()
