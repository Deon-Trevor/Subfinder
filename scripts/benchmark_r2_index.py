from __future__ import annotations

import argparse
import bisect
import gzip
import hashlib
import json
import sqlite3
import statistics
import time
from pathlib import Path
from typing import Any, Iterable


FORMAT = "subfinder.r2-index-spike.v1"
DEFAULT_ANCHORS = tuple("0123456789abcdefghijklmnopqrstuvwxyz")


def sampled_apexes(
    connection: sqlite3.Connection,
    *,
    anchors: Iterable[str],
    apexes_per_anchor: int,
    include_apexes: Iterable[str] = (),
) -> list[str]:
    if apexes_per_anchor < 1:
        raise ValueError("apexes_per_anchor must be positive")
    apexes: set[str] = set()
    for anchor in anchors:
        rows = connection.execute(
            "SELECT DISTINCT apex FROM subdomains "
            "WHERE apex >= ? ORDER BY apex LIMIT ?",
            (anchor, apexes_per_anchor),
        )
        apexes.update(str(row[0]) for row in rows)
    for apex in include_apexes:
        row = connection.execute(
            "SELECT apex FROM subdomains WHERE apex = ? LIMIT 1",
            (apex,),
        ).fetchone()
        if row is not None:
            apexes.add(str(row[0]))
    return sorted(apexes)


def read_records(
    connection: sqlite3.Connection,
    apexes: list[str],
    *,
    batch_size: int = 400,
) -> dict[str, list[dict[str, Any]]]:
    records: dict[str, list[dict[str, Any]]] = {apex: [] for apex in apexes}
    for start in range(0, len(apexes), batch_size):
        batch = apexes[start : start + batch_size]
        placeholders = ",".join("?" for _ in batch)
        rows = connection.execute(
            f"""
            SELECT
                names.apex,
                names.subdomain,
                names.first_seen AS hostname_first_seen,
                evidence.source,
                evidence.first_seen AS source_first_seen,
                evidence.last_seen
            FROM subdomains AS names
            LEFT JOIN subdomain_sources AS evidence
                ON evidence.apex = names.apex
               AND evidence.subdomain = names.subdomain
            WHERE names.apex IN ({placeholders})
            ORDER BY names.apex, names.subdomain, evidence.source
            """,
            batch,
        )
        current: tuple[str, str] | None = None
        current_record: dict[str, Any] | None = None
        for row in rows:
            key = (str(row[0]), str(row[1]))
            if key != current:
                current = key
                current_record = {
                    "h": key[1],
                    "f": row[2],
                    "s": [],
                }
                records[key[0]].append(current_record)
            if row[3] is not None and current_record is not None:
                current_record["s"].append(
                    {"n": str(row[3]), "f": row[4], "l": str(row[5])}
                )
    return records


def encode_line(apex: str, records: list[dict[str, Any]]) -> bytes:
    return (
        json.dumps(
            {"a": apex, "r": records},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def build_bundle(
    records_by_apex: dict[str, list[dict[str, Any]]],
    *,
    target_block_bytes: int,
    bundle_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    if target_block_bytes < 1:
        raise ValueError("target_block_bytes must be positive")
    encoded = [
        (apex, encode_line(apex, records_by_apex[apex]))
        for apex in sorted(records_by_apex)
    ]

    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    total_raw = 0
    total_compressed = 0

    def write_block(bundle: Any, members: list[tuple[str, bytes]]) -> None:
        nonlocal total_raw, total_compressed
        raw = b"".join(line for _apex, line in members)
        compressed = gzip.compress(raw, compresslevel=9, mtime=0)
        offset = bundle.tell()
        bundle.write(compressed)
        hostname_count = sum(
            len(records_by_apex[apex]) for apex, _line in members
        )
        source_count = sum(
            len(record["s"])
            for apex, _line in members
            for record in records_by_apex[apex]
        )
        entries.append(
            {
                "first_apex": members[0][0],
                "last_apex": members[-1][0],
                "offset": offset,
                "length": len(compressed),
                "sha256": hashlib.sha256(compressed).hexdigest(),
                "uncompressed_bytes": len(raw),
                "apex_count": len(members),
                "hostname_count": hostname_count,
                "source_count": source_count,
            }
        )
        total_raw += len(raw)
        total_compressed += len(compressed)

    with bundle_path.open("wb") as bundle:
        members: list[tuple[str, bytes]] = []
        raw_bytes = 0
        for item in encoded:
            if members and raw_bytes + len(item[1]) > target_block_bytes:
                write_block(bundle, members)
                members = []
                raw_bytes = 0
            members.append(item)
            raw_bytes += len(item[1])
        if members:
            write_block(bundle, members)

    manifest = {
        "format": FORMAT,
        "target_block_bytes": target_block_bytes,
        "bundle": bundle_path.name,
        "apex_count": len(records_by_apex),
        "hostname_count": sum(len(records) for records in records_by_apex.values()),
        "source_count": sum(
            len(record["s"])
            for records in records_by_apex.values()
            for record in records
        ),
        "uncompressed_bytes": total_raw,
        "compressed_bytes": total_compressed,
        "blocks": entries,
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def lookup(
    apex: str,
    *,
    bundle_path: Path,
    manifest: dict[str, Any],
) -> dict[str, Any] | None:
    blocks = manifest["blocks"]
    first_apexes = [entry["first_apex"] for entry in blocks]
    block_index = bisect.bisect_right(first_apexes, apex) - 1
    if block_index < 0:
        return None
    entry = blocks[block_index]
    if apex > entry["last_apex"]:
        return None
    with bundle_path.open("rb") as bundle:
        bundle.seek(int(entry["offset"]))
        compressed = bundle.read(int(entry["length"]))
    if hashlib.sha256(compressed).hexdigest() != entry["sha256"]:
        raise ValueError("shard checksum mismatch")
    lines = gzip.decompress(compressed).splitlines()
    apexes = [json.loads(line)["a"] for line in lines]
    position = bisect.bisect_left(apexes, apex)
    if position == len(apexes) or apexes[position] != apex:
        return None
    return json.loads(lines[position])


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * fraction))
    return ordered[index]


def benchmark_lookups(
    apexes: list[str],
    *,
    bundle_path: Path,
    manifest: dict[str, Any],
    sample_count: int,
) -> dict[str, float | int]:
    if sample_count < 1:
        raise ValueError("sample_count must be positive")
    stride = max(1, len(apexes) // sample_count)
    samples = apexes[::stride][:sample_count]
    timings: list[float] = []
    for apex in samples:
        started = time.perf_counter()
        if lookup(apex, bundle_path=bundle_path, manifest=manifest) is None:
            raise RuntimeError(f"sampled apex {apex!r} was not found in the bundle")
        timings.append((time.perf_counter() - started) * 1_000)
    return {
        "count": len(timings),
        "p50_ms": statistics.median(timings),
        "p95_ms": percentile(timings, 0.95),
        "p99_ms": percentile(timings, 0.99),
        "max_ms": max(timings),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure an immutable, range-readable R2 index against SQLite"
    )
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apexes-per-anchor", type=int, default=2_000)
    parser.add_argument("--anchors", default="".join(DEFAULT_ANCHORS))
    parser.add_argument(
        "--include-apex",
        action="append",
        default=[],
        help="include an existing apex in addition to the sampled cohort",
    )
    parser.add_argument("--target-block-bytes", type=int, default=256 * 1024)
    parser.add_argument("--lookup-samples", type=int, default=1_000)
    args = parser.parse_args()

    started = time.perf_counter()
    connection = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only = ON")
        apexes = sampled_apexes(
            connection,
            anchors=args.anchors,
            apexes_per_anchor=args.apexes_per_anchor,
            include_apexes=args.include_apex,
        )
        records = read_records(connection, apexes)
    finally:
        connection.close()

    bundle_path = args.output / "catalog.bundle"
    manifest_path = args.output / "manifest.json"
    manifest = build_bundle(
        records,
        target_block_bytes=args.target_block_bytes,
        bundle_path=bundle_path,
        manifest_path=manifest_path,
    )
    sample = apexes[len(apexes) // 2] if apexes else None
    if sample is not None and lookup(
        sample,
        bundle_path=bundle_path,
        manifest=manifest,
    ) != {"a": sample, "r": records[sample]}:
        raise RuntimeError("bundle lookup did not reproduce the SQLite record")

    lookup_timings = benchmark_lookups(
        apexes,
        bundle_path=bundle_path,
        manifest=manifest,
        sample_count=args.lookup_samples,
    )

    result = {
        **{key: value for key, value in manifest.items() if key != "blocks"},
        "block_count": len(manifest["blocks"]),
        "largest_compressed_block_bytes": max(
            (int(entry["length"]) for entry in manifest["blocks"]),
            default=0,
        ),
        "largest_uncompressed_block_bytes": max(
            (
                int(entry["uncompressed_bytes"])
                for entry in manifest["blocks"]
            ),
            default=0,
        ),
        "compression_ratio": (
            manifest["uncompressed_bytes"] / manifest["compressed_bytes"]
            if manifest["compressed_bytes"]
            else 0
        ),
        "sample_lookup": sample,
        "lookup_timings": lookup_timings,
        "elapsed_seconds": time.perf_counter() - started,
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
