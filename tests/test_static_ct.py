from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ctlogs.database import Database
from ctlogs.ingest.direct_ct import PollResult
from ctlogs.ingest.static_ct import StaticCTClient, _tile_path, parse_data_tile


def _certificate(name: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name)]),
            critical=False,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return certificate.public_bytes(Encoding.DER)


def _vector(value: bytes, length_bytes: int) -> bytes:
    return len(value).to_bytes(length_bytes, "big") + value


def _x509_leaf(certificate: bytes, timestamp: int = 1_700_000_000_000) -> bytes:
    return (
        timestamp.to_bytes(8, "big")
        + b"\x00\x00"
        + _vector(certificate, 3)
        + _vector(b"", 2)
        + _vector(b"", 2)
    )


def _precert_leaf(certificate: bytes, timestamp: int = 1_700_000_000_000) -> bytes:
    return (
        timestamp.to_bytes(8, "big")
        + b"\x00\x01"
        + bytes(32)
        + _vector(b"tbs", 3)
        + _vector(b"", 2)
        + _vector(certificate, 3)
        + _vector(bytes(32), 2)
    )


def test_parse_data_tile_reads_x509_and_precertificate_entries() -> None:
    first = _certificate("first.example.com")
    second = _certificate("second.example.com")

    leaves = parse_data_tile(_x509_leaf(first) + _precert_leaf(second))

    assert [leaf.certificate for leaf in leaves] == [first, second]
    assert [leaf.first_seen for leaf in leaves] == [
        "2023-11-14T22:13:20.000Z",
        "2023-11-14T22:13:20.000Z",
    ]


def test_parse_data_tile_rejects_truncated_entry() -> None:
    with pytest.raises(ValueError, match="truncated"):
        parse_data_tile(b"short")


def test_tile_path_uses_c2sp_grouping() -> None:
    assert _tile_path(0) == "000"
    assert _tile_path(1_234_067) == "x001/x234/067"


def test_static_poll_stores_only_requested_leaf_range(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "static.sqlite3")
    database.initialize()
    client = StaticCTClient(database)
    tile = b"".join(
        _x509_leaf(_certificate(f"host-{index}.example.com"))
        for index in range(3)
    )

    monkeypatch.setattr(client, "get_tile", lambda *_args: tile)

    result = client.poll_and_store(
        "https://static.example/log",
        start=1,
        end=2,
        tree_size=3,
    )

    assert result == PollResult(entry_count=2, hostname_count=2)
    assert [row.subdomain for row in database.search("example.com")] == [
        "host-1.example.com",
        "host-2.example.com",
    ]
