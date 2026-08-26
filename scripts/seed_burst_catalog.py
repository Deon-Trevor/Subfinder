from __future__ import annotations

import argparse
from pathlib import Path

from ctlogs.database import Database


def read_domains(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a deterministic local catalog for burst testing"
    )
    parser.add_argument("--domains", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rows-per-apex", type=int, default=500)
    args = parser.parse_args()
    if args.rows_per_apex < 1:
        parser.error("rows-per-apex must be positive")
    if args.output.exists():
        parser.error(f"output already exists: {args.output}")

    domains = read_domains(args.domains)
    if not domains:
        parser.error("domain cohort is empty")

    database = Database(args.output)
    database.initialize()
    for rank, apex in enumerate(domains, start=1):
        rows = [(apex, "2023-02-01T00:00:00Z")]
        rows.extend(
            (
                f"node-{index:04d}.{apex}",
                f"2023-{1 + ((rank + index) % 12):02d}-01T00:00:00Z",
            )
            for index in range(1, args.rows_per_apex)
        )
        database.upsert_subdomains(
            apex,
            rows,
            source="static_ct:burst-fixture",
            observed_at="2026-08-26T00:00:00Z",
        )

    print(
        f"seeded {len(domains)} apexes and "
        f"{len(domains) * args.rows_per_apex} hostnames in {args.output}"
    )


if __name__ == "__main__":
    main()
