from __future__ import annotations

import argparse
import bisect
import gzip
import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import tldextract


FORMAT = "subfinder.r2-index.v2"
ROOT_KEY = "catalog/root.json"
DEFAULT_ANCHORS = tuple("0123456789abcdefghijklmnopqrstuvwxyz")
GENERATION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def domain_policy_metadata() -> dict[str, str]:
    snapshot = Path(tldextract.__file__).resolve().parent / ".tld_set_snapshot"
    digest = file_sha256(snapshot)
    return {
        "domain_policy_version": f"python-idna2003+psl-{digest}",
        "psl_sha256": digest,
    }


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def deterministic_gzip(value: bytes) -> bytes:
    return gzip.compress(value, compresslevel=9, mtime=0)


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def partition_prefix(apex: str, nibbles: int) -> str:
    return hashlib.sha256(apex.encode("utf-8")).hexdigest()[:nibbles]


def record_cursor(record: dict[str, Any]) -> tuple[str | None, str]:
    return record["f"], str(record["h"])


def cursor_sort_key(cursor: tuple[str | None, str]) -> tuple[bool, str, str]:
    first_seen, hostname = cursor
    return first_seen is None, first_seen or "", hostname


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


def exact_apex_counts(
    connection: sqlite3.Connection,
    apexes: Iterable[str],
) -> dict[str, int]:
    requested = sorted(set(apexes))
    if not requested:
        return {}
    placeholders = ",".join("?" for _ in requested)
    counts = {
        str(apex): int(count)
        for apex, count in connection.execute(
            f"SELECT apex, count(*) FROM subdomains "
            f"WHERE apex IN ({placeholders}) GROUP BY apex ORDER BY apex",
            requested,
        )
    }
    return {apex: counts.get(apex, 0) for apex in requested}


def catalog_watermark(connection: sqlite3.Connection) -> str | None:
    try:
        row = connection.execute(
            "SELECT finished_at FROM ingest_runs "
            "WHERE finished_at IS NOT NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError:
        return None
    return str(row[0]) if row is not None else None


def _rows_for_apexes(
    connection: sqlite3.Connection,
    apexes: list[str] | None,
    *,
    batch_size: int = 400,
) -> Iterator[sqlite3.Row | tuple[Any, ...]]:
    select = """
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
    """
    order = """
        ORDER BY
            names.apex,
            names.subdomain
    """
    if apexes is None:
        yield from connection.execute(select + order)
        return
    for start in range(0, len(apexes), batch_size):
        batch = apexes[start : start + batch_size]
        placeholders = ",".join("?" for _ in batch)
        yield from connection.execute(
            select + f" WHERE names.apex IN ({placeholders}) " + order,
            batch,
        )


def iter_records(
    connection: sqlite3.Connection,
    apexes: list[str] | None,
) -> Iterator[tuple[str, dict[str, Any]]]:
    current_key: tuple[str, str] | None = None
    current_first_seen: str | None = None
    sources: list[dict[str, Any]] = []
    apex_records: list[dict[str, Any]] = []

    def finish_record() -> None:
        if current_key is None:
            return
        apex_records.append(
            {
                "h": current_key[1],
                "f": current_first_seen,
                "s": sorted(sources, key=lambda source: str(source["n"])),
            }
        )

    def finish_apex() -> Iterator[tuple[str, dict[str, Any]]]:
        if current_key is None:
            return
        apex_records.sort(key=lambda record: cursor_sort_key(record_cursor(record)))
        for record in apex_records:
            yield current_key[0], record

    for row in _rows_for_apexes(connection, apexes):
        key = (str(row[0]), str(row[1]))
        if current_key is not None and key != current_key:
            previous_apex = current_key[0]
            finish_record()
            sources = []
            if key[0] != previous_apex:
                yield from finish_apex()
                apex_records = []
        if key != current_key:
            current_key = key
            current_first_seen = row[2]
        if row[3] is not None:
            sources.append(
                {
                    "n": str(row[3]),
                    "f": row[4],
                    "l": str(row[5]),
                }
            )
    finish_record()
    yield from finish_apex()


class PartitionWriter:
    def __init__(
        self,
        *,
        output: Path,
        generation: str,
        prefix: str,
        target_block_bytes: int,
    ) -> None:
        base = Path("catalog") / "generations" / generation / "partitions"
        self.prefix = prefix
        self.bundle_key = str(base / f"{prefix}.bundle")
        self.index_key = str(base / f"{prefix}.index.json.gz")
        self.bundle_path = output / self.bundle_key
        self.index_path = output / self.index_key
        self.target_block_bytes = target_block_bytes
        self.lines: list[bytes] = []
        self.line_bytes = 0
        self.blocks: list[dict[str, Any]] = []
        self.overflow: dict[str, dict[str, Any]] = {}
        self.bundle_bytes = 0

    def _append_member(self, raw: bytes) -> dict[str, Any]:
        compressed = deterministic_gzip(raw)
        self.bundle_path.parent.mkdir(parents=True, exist_ok=True)
        with self.bundle_path.open("ab") as bundle:
            offset = bundle.tell()
            bundle.write(compressed)
        self.bundle_bytes += len(compressed)
        return {
            "offset": offset,
            "length": len(compressed),
            "sha256": sha256(compressed),
            "uncompressed_bytes": len(raw),
        }

    def flush_regular(self) -> None:
        if not self.lines:
            return
        documents = [json.loads(line) for line in self.lines]
        metadata = self._append_member(b"".join(self.lines))
        self.blocks.append(
            {
                **metadata,
                "first_apex": str(documents[0]["a"]),
                "last_apex": str(documents[-1]["a"]),
                "apex_count": len(documents),
            }
        )
        self.lines = []
        self.line_bytes = 0

    def add_regular(self, apex: str, document: bytes) -> None:
        if self.lines and self.line_bytes + len(document) > self.target_block_bytes:
            self.flush_regular()
        self.lines.append(document)
        self.line_bytes += len(document)

    def add_overflow_chunk(
        self,
        apex: str,
        records: list[dict[str, Any]],
        *,
        chunk_index: int,
    ) -> dict[str, Any]:
        self.flush_regular()
        raw = compact_json(
            {"a": apex, "i": chunk_index, "r": records, "x": True}
        ) + b"\n"
        metadata = self._append_member(raw)
        return {
            **metadata,
            "count": len(records),
            "dated": sum(record["f"] is not None for record in records),
            "first_cursor": list(record_cursor(records[0])),
            "last_cursor": list(record_cursor(records[-1])),
        }

    def finish_overflow(
        self,
        apex: str,
        *,
        total: int,
        dated: int,
        chunks: list[dict[str, Any]],
    ) -> None:
        self.overflow[apex] = {
            "total": total,
            "dated": dated,
            "chunks": chunks,
        }

    def finish(self, output: Path, generation: str) -> dict[str, Any]:
        self.flush_regular()
        index = {
            "format": FORMAT,
            "generation": generation,
            "prefix": self.prefix,
            "bundle": self.bundle_key,
            "blocks": self.blocks,
            "overflow": self.overflow,
        }
        compressed_index = deterministic_gzip(compact_json(index) + b"\n")
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        self.index_path.write_bytes(compressed_index)
        return {
            "index": self.index_key,
            "index_sha256": sha256(compressed_index),
            "index_bytes": len(compressed_index),
            "bundle": self.bundle_key,
            "bundle_bytes": self.bundle_bytes,
            "bundle_sha256": file_sha256(self.bundle_path),
            "regular_blocks": len(self.blocks),
            "overflow_apexes": len(self.overflow),
        }


def _regular_document(
    apex: str,
    records: list[dict[str, Any]],
    *,
    total: int,
    dated: int,
) -> bytes:
    return compact_json({"a": apex, "d": dated, "r": records, "t": total}) + b"\n"


def _estimated_document_bytes(
    apex: str,
    record_bytes: int,
    record_count: int,
) -> int:
    return len(apex.encode("utf-8")) + record_bytes + record_count + 96


def export_catalog(
    connection: sqlite3.Connection,
    *,
    output: Path,
    generation: str,
    apexes: list[str] | None,
    partition_nibbles: int = 2,
    target_block_bytes: int = 256 * 1024,
) -> dict[str, Any]:
    if not GENERATION.fullmatch(generation):
        raise ValueError("generation must be a safe path component")
    if partition_nibbles not in {1, 2, 3}:
        raise ValueError("partition_nibbles must be 1, 2, or 3")
    if target_block_bytes < 256:
        raise ValueError("target_block_bytes must be at least 256")
    root_path = output / ROOT_KEY
    if root_path.exists():
        raise FileExistsError(f"refusing to overwrite {root_path}")

    writers: dict[str, PartitionWriter] = {}
    current_apex: str | None = None
    current_records: list[dict[str, Any]] = []
    current_record_bytes = 0
    current_overflow = False
    current_chunks: list[dict[str, Any]] = []
    total = 0
    dated = 0
    apex_count = 0
    hostname_count = 0
    dated_hostname_count = 0
    source_observation_count = 0
    distinct_sources: set[str] = set()
    ct_hostname_count = 0
    ct_sources: set[str] = set()
    last_ingest_at = catalog_watermark(connection)

    def writer_for(apex: str) -> PartitionWriter:
        prefix = partition_prefix(apex, partition_nibbles)
        if prefix not in writers:
            writers[prefix] = PartitionWriter(
                output=output,
                generation=generation,
                prefix=prefix,
                target_block_bytes=target_block_bytes,
            )
        return writers[prefix]

    def flush_chunk() -> None:
        nonlocal current_records, current_record_bytes
        if current_apex is None or not current_records:
            return
        current_chunks.append(
            writer_for(current_apex).add_overflow_chunk(
                current_apex,
                current_records,
                chunk_index=len(current_chunks),
            )
        )
        current_records = []
        current_record_bytes = 0

    def finish_apex() -> None:
        nonlocal current_records, current_record_bytes, current_overflow
        nonlocal current_chunks, total, dated, apex_count
        if current_apex is None:
            return
        writer = writer_for(current_apex)
        if current_overflow:
            flush_chunk()
            writer.finish_overflow(
                current_apex,
                total=total,
                dated=dated,
                chunks=current_chunks,
            )
        else:
            document = _regular_document(
                current_apex,
                current_records,
                total=total,
                dated=dated,
            )
            if len(document) > target_block_bytes:
                current_overflow = True
                flush_chunk()
                writer.finish_overflow(
                    current_apex,
                    total=total,
                    dated=dated,
                    chunks=current_chunks,
                )
            else:
                writer.add_regular(current_apex, document)
        apex_count += 1
        current_records = []
        current_record_bytes = 0
        current_overflow = False
        current_chunks = []
        total = 0
        dated = 0

    for apex, record in iter_records(connection, apexes):
        if current_apex is not None and apex != current_apex:
            finish_apex()
        if apex != current_apex:
            current_apex = apex
        encoded_record = compact_json(record)
        projected = _estimated_document_bytes(
            apex,
            current_record_bytes + len(encoded_record),
            len(current_records) + 1,
        )
        if current_records and projected > target_block_bytes:
            current_overflow = True
            flush_chunk()
        current_records.append(record)
        current_record_bytes += len(encoded_record)
        total += 1
        dated += record["f"] is not None
        hostname_count += 1
        dated_hostname_count += record["f"] is not None
        source_observation_count += len(record["s"])
        record_sources = {str(source["n"]) for source in record["s"]}
        distinct_sources.update(record_sources)
        ct_record_sources = {
            source
            for source in record_sources
            if source.startswith("direct_ct:") or source.startswith("static_ct:")
        }
        if ct_record_sources:
            ct_hostname_count += 1
            ct_sources.update(ct_record_sources)
    finish_apex()

    partitions = {
        prefix: writers[prefix].finish(output, generation)
        for prefix in sorted(writers)
    }
    root = {
        "format": FORMAT,
        "generation": generation,
        **domain_policy_metadata(),
        "partition_nibbles": partition_nibbles,
        "target_block_bytes": target_block_bytes,
        "ordering": ["first_seen_nulls_last", "first_seen", "hostname"],
        "partitions": partitions,
        "source_names": sorted(distinct_sources),
        "ct_source_names": sorted(ct_sources),
        "stats": {
            "apex_count": apex_count,
            "hostname_count": hostname_count,
            "dated_hostname_count": dated_hostname_count,
            "source_count": len(distinct_sources),
            "source_observation_count": source_observation_count,
            "ct_hostname_count": ct_hostname_count,
            "ct_log_count": len(ct_sources),
            "last_ingest_at": last_ingest_at,
        },
    }
    root_path.parent.mkdir(parents=True, exist_ok=True)
    root_path.write_bytes(compact_json(root) + b"\n")
    return root


def read_partition_index(
    output: Path,
    root: dict[str, Any],
    prefix: str,
) -> dict[str, Any]:
    metadata = root["partitions"].get(prefix)
    if metadata is None:
        return {
            "format": FORMAT,
            "prefix": prefix,
            "blocks": [],
            "overflow": {},
        }
    compressed = (output / metadata["index"]).read_bytes()
    if sha256(compressed) != metadata["index_sha256"]:
        raise ValueError("partition index checksum mismatch")
    return json.loads(gzip.decompress(compressed))


def _read_member(
    output: Path,
    bundle_key: str,
    metadata: dict[str, Any],
) -> list[dict[str, Any]]:
    with (output / bundle_key).open("rb") as bundle:
        bundle.seek(int(metadata["offset"]))
        compressed = bundle.read(int(metadata["length"]))
    if sha256(compressed) != metadata["sha256"]:
        raise ValueError("catalog block checksum mismatch")
    return [json.loads(line) for line in gzip.decompress(compressed).splitlines()]


def read_export_apex(
    output: Path,
    root: dict[str, Any],
    apex: str,
) -> dict[str, Any] | None:
    prefix = partition_prefix(apex, int(root["partition_nibbles"]))
    partition = root["partitions"].get(prefix)
    if partition is None:
        return None
    index = read_partition_index(output, root, prefix)
    overflow = index["overflow"].get(apex)
    if overflow is not None:
        records: list[dict[str, Any]] = []
        for chunk in overflow["chunks"]:
            documents = _read_member(output, partition["bundle"], chunk)
            records.extend(documents[0]["r"])
        return {
            "apex": apex,
            "total": int(overflow["total"]),
            "dated": int(overflow["dated"]),
            "records": records,
        }

    blocks = index["blocks"]
    first_apexes = [block["first_apex"] for block in blocks]
    position = bisect.bisect_right(first_apexes, apex) - 1
    if position < 0 or apex > blocks[position]["last_apex"]:
        return None
    for document in _read_member(output, partition["bundle"], blocks[position]):
        if document["a"] == apex:
            return {
                "apex": apex,
                "total": int(document["t"]),
                "dated": int(document["d"]),
                "records": document["r"],
            }
    return None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Export a bounded, range-readable Subfinder R2 generation"
    )
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--generation", required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--all", action="store_true")
    mode.add_argument("--sample-per-anchor", type=int)
    parser.add_argument("--anchors", default="".join(DEFAULT_ANCHORS))
    parser.add_argument("--include-apex", action="append", default=[])
    parser.add_argument("--partition-nibbles", type=int, default=2)
    parser.add_argument("--target-block-bytes", type=int, default=256 * 1024)
    args = parser.parse_args()

    connection = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        apexes = None
        if not args.all:
            apexes = sampled_apexes(
                connection,
                anchors=args.anchors,
                apexes_per_anchor=args.sample_per_anchor,
                include_apexes=args.include_apex,
            )
        included_apex_counts = exact_apex_counts(
            connection,
            args.include_apex,
        )
        root = export_catalog(
            connection,
            output=args.output,
            generation=args.generation,
            apexes=apexes,
            partition_nibbles=args.partition_nibbles,
            target_block_bytes=args.target_block_bytes,
        )
    finally:
        connection.close()
    summary = {
        "format": root["format"],
        "generation": root["generation"],
        "partition_count": len(root["partitions"]),
        "stats": root["stats"],
        "index_bytes": sum(
            partition["index_bytes"] for partition in root["partitions"].values()
        ),
        "bundle_bytes": sum(
            partition["bundle_bytes"] for partition in root["partitions"].values()
        ),
        "regular_blocks": sum(
            partition["regular_blocks"]
            for partition in root["partitions"].values()
        ),
        "overflow_apexes": sum(
            partition["overflow_apexes"]
            for partition in root["partitions"].values()
        ),
        "included_apex_counts": included_apex_counts,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
