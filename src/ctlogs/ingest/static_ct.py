from __future__ import annotations

import gzip
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime

from ctlogs.database import Database
from ctlogs.ingest import ZoneRecord
from ctlogs.ingest.benchmark import _batch_upsert
from ctlogs.ingest.direct_ct import PollResult, extract_hostnames_from_der


@dataclass(frozen=True)
class StaticLeaf:
    certificate: bytes
    first_seen: str


def _take(data: bytes, cursor: int, length: int) -> tuple[bytes, int]:
    end = cursor + length
    if length < 0 or end > len(data):
        raise ValueError("truncated Static CT data tile")
    return data[cursor:end], end


def _take_vector(
    data: bytes,
    cursor: int,
    length_bytes: int,
) -> tuple[bytes, int]:
    encoded_length, cursor = _take(data, cursor, length_bytes)
    length = int.from_bytes(encoded_length, "big")
    return _take(data, cursor, length)


def parse_data_tile(data: bytes) -> list[StaticLeaf]:
    leaves: list[StaticLeaf] = []
    cursor = 0
    while cursor < len(data):
        timestamp_bytes, cursor = _take(data, cursor, 8)
        entry_type_bytes, cursor = _take(data, cursor, 2)
        entry_type = int.from_bytes(entry_type_bytes, "big")

        if entry_type == 0:
            certificate, cursor = _take_vector(data, cursor, 3)
        elif entry_type == 1:
            _issuer_hash, cursor = _take(data, cursor, 32)
            _tbs_certificate, cursor = _take_vector(data, cursor, 3)
            certificate = b""
        else:
            raise ValueError(f"unsupported Static CT entry type: {entry_type}")

        _extensions, cursor = _take_vector(data, cursor, 2)
        if entry_type == 1:
            certificate, cursor = _take_vector(data, cursor, 3)

        issuer_fingerprints, cursor = _take_vector(data, cursor, 2)
        if len(issuer_fingerprints) % 32:
            raise ValueError("invalid Static CT issuer fingerprint list")

        milliseconds = int.from_bytes(timestamp_bytes, "big")
        try:
            observed = datetime.fromtimestamp(milliseconds / 1000, UTC)
        except (OSError, OverflowError, ValueError) as error:
            raise ValueError("invalid Static CT timestamp") from error
        leaves.append(
            StaticLeaf(
                certificate=certificate,
                first_seen=observed.isoformat(timespec="milliseconds").replace(
                    "+00:00", "Z"
                ),
            )
        )
    return leaves


def _tile_path(tile_number: int) -> str:
    groups: list[str] = []
    remaining = str(tile_number)
    while remaining:
        groups.append(remaining[-3:].zfill(3))
        remaining = remaining[:-3]
    groups.reverse()
    return "/".join(
        group if index == len(groups) - 1 else f"x{group}"
        for index, group in enumerate(groups)
    )


class StaticCTClient:
    def __init__(self, database: Database, timeout: int = 15) -> None:
        self.database = database
        self.timeout = timeout

    def get_tree_size(self, monitoring_url: str) -> int:
        request = urllib.request.Request(
            f"{monitoring_url.rstrip('/')}/checkpoint",
            headers={"User-Agent": "ctlogs/1.0"},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            lines = response.read().decode("utf-8").splitlines()
        if len(lines) < 2:
            raise ValueError("invalid Static CT checkpoint")
        size = int(lines[1])
        if size < 0:
            raise ValueError("invalid Static CT tree size")
        # ponytail: This discovery index does not verify the checkpoint note or
        # Merkle consistency. Add C2SP verification before making audit claims.
        return size

    def get_tile(self, monitoring_url: str, tile_number: int, width: int) -> bytes:
        path = _tile_path(tile_number)
        suffix = "" if width == 256 else f".p/{width}"
        request = urllib.request.Request(
            f"{monitoring_url.rstrip('/')}/tile/data/{path}{suffix}",
            headers={
                "Accept-Encoding": "gzip, identity",
                "User-Agent": "ctlogs/1.0",
            },
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            data = response.read()
            if response.headers.get("Content-Encoding") == "gzip":
                data = gzip.decompress(data)
        return data

    def poll_and_store(
        self,
        monitoring_url: str,
        start: int,
        end: int,
        tree_size: int,
    ) -> PollResult:
        if start < 0 or end < start or end >= tree_size:
            raise ValueError("invalid Static CT entry range")

        source = f"static_ct:{monitoring_url.rstrip('/')}"
        records: list[ZoneRecord] = []
        entry_count = 0
        bytes_read = 0
        first_tile = start // 256
        last_tile = end // 256
        for tile_number in range(first_tile, last_tile + 1):
            tile_start = tile_number * 256
            width = min(256, tree_size - tile_start)
            tile = self.get_tile(monitoring_url, tile_number, width)
            bytes_read += len(tile)
            leaves = parse_data_tile(tile)
            if len(leaves) != width:
                raise ValueError(
                    f"Static CT tile {tile_number} has {len(leaves)} leaves, expected {width}"
                )
            lower = max(start, tile_start) - tile_start
            upper = min(end + 1, tile_start + width) - tile_start
            selected = leaves[lower:upper]
            entry_count += len(selected)
            for leaf in selected:
                for hostname in extract_hostnames_from_der(leaf.certificate):
                    records.append(
                        ZoneRecord(
                            apex=hostname,
                            hostname=hostname,
                            first_seen=leaf.first_seen,
                        )
                    )

        if records:
            apex_count, hostname_count = _batch_upsert(
                self.database,
                records,
                source=source,
            )
        else:
            apex_count, hostname_count = 0, 0
        now = datetime.now(UTC).isoformat()
        self.database.record_ingest_run(
            source,
            now,
            now,
            apex_count,
            hostname_count,
            bytes_read=bytes_read,
        )
        return PollResult(entry_count=entry_count, hostname_count=hostname_count)
