from __future__ import annotations

from datetime import UTC, datetime

from ctlogs.database import Database


# Deterministic fixtures for a usable DB immediately after `docker run`.
# These are plain hostnames that pass _is_hostname and PSL checks.
_SEED_ROWS: dict[str, list[tuple[str, str | None]]] = {
    "syncpundit.io": [
        ("syncpundit.io", "2024-01-01T00:00:00Z"),
        ("www.syncpundit.io", "2024-01-02T00:00:00Z"),
        ("api.syncpundit.io", "2024-01-03T00:00:00Z"),
        ("mcp.syncpundit.io", None),
    ],
    "example.com": [
        ("example.com", "2024-01-01T00:00:00Z"),
        ("www.example.com", "2024-01-02T00:00:00Z"),
        ("api.example.com", None),
    ],
}


def seed_if_empty(database: Database) -> int:
    """Populate DB if `subdomains` is empty. Returns number of hostnames inserted.

    Idempotent: if table already has rows, does nothing and returns 0.
    Keeps earliest first_seen via Database.upsert_subdomains.
    """
    with database.connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS c FROM subdomains").fetchone()
        if row and int(row["c"]) > 0:
            return 0

    total = 0
    for apex, rows in _SEED_ROWS.items():
        database.upsert_subdomains(apex, rows, source="seed")
        total += len(rows)

    # Record a synthetic ingest run for observability
    try:
        database.record_ingest_run(
            "seed",
            datetime.now(UTC).isoformat(),
            datetime.now(UTC).isoformat(),
            len(_SEED_ROWS),
            total,
            0,
            0,
        )
    except Exception:
        pass
    return total
