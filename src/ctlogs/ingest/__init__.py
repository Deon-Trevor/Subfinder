from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ZoneRecord:
    apex: str
    hostname: str
    first_seen: str | None = None


class ZoneAdapter:
    name: str

    def parse(self, data: bytes | str) -> Iterable[ZoneRecord]:
        raise NotImplementedError

    def source_bytes(self, data: bytes | str) -> int:
        if isinstance(data, bytes):
            return len(data)
        return len(data.encode("utf-8"))
