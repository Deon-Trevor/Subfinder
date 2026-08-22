from __future__ import annotations

import argparse
from datetime import UTC, datetime

from ctlogs.database import Database
from ctlogs.ingest.direct_ct import DirectCTClient


def run_history(
    database: Database,
    log_url: str,
    *,
    batch_size: int = 1024,
    max_batches: int = 8,
    client: DirectCTClient | None = None,
) -> tuple[int, int]:
    """Replay a bounded prefix of one RFC 6962 log and persist its cursor."""
    client = client or DirectCTClient(database)
    state_key = f"history:{log_url.rstrip('/')}"
    state = database.get_ingest_state(state_key)
    cursor = int(state["cursor"]) if state and state.get("cursor") else 0
    sth = client.get_sth(log_url)
    tree_size = int(sth.get("tree_size", 0))
    entry_count = 0
    hostname_count = 0
    for _batch in range(max_batches):
        if cursor >= tree_size:
            break
        end = min(cursor + batch_size - 1, tree_size - 1)
        result = client.poll_and_store(log_url, cursor, end)
        if result.entry_count < 1:
            break
        cursor += result.entry_count
        entry_count += result.entry_count
        hostname_count += result.hostname_count
        database.upsert_ingest_state(
            state_key,
            cursor=str(cursor),
            updated_at=datetime.now(UTC).isoformat(),
        )
    return entry_count, hostname_count


def main() -> None:
    parser = argparse.ArgumentParser(description="Run bounded historical RFC 6962 replay")
    parser.add_argument("--db", default="data/ctlogs.sqlite3")
    parser.add_argument("--log-url", action="append", required=True)
    parser.add_argument("--batch-size", type=int, default=1024)
    parser.add_argument("--max-batches-per-log", type=int, default=8)
    args = parser.parse_args()
    if args.batch_size < 1 or args.max_batches_per_log < 1:
        parser.error("batch-size and max-batches-per-log must be positive")
    database = Database(args.db)
    database.initialize()
    for log_url in args.log_url:
        entries, hostnames = run_history(
            database,
            log_url.rstrip("/"),
            batch_size=args.batch_size,
            max_batches=args.max_batches_per_log,
        )
        print(f"{log_url}: entries={entries} hostnames={hostnames}")


if __name__ == "__main__":
    main()
