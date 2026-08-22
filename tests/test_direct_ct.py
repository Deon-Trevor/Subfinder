from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from ctlogs.database import Database
from ctlogs.ingest.direct_ct import (
    DirectCTClient,
    PollResult,
    _extract_first_seen,
    _extract_hostnames_from_entry,
)


def _self_signed_der(dns_names: list[str] | None = None, common_name: str = "example.com") -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
    )

    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in dns_names],
            ),
            critical=False,
        )

    certificate = builder.sign(private_key=key, algorithm=hashes.SHA256())
    return certificate.public_bytes(Encoding.DER)


def _wrap_with_u24_entries(entries: list[bytes]) -> str:
    payload = bytearray()
    for cert in entries:
        payload.extend(len(cert).to_bytes(3, "big"))
        payload.extend(cert)
    return base64.b64encode(bytes(payload)).decode("utf-8")


def _x509_entry(leaf: bytes, chain: list[bytes] | None = None) -> dict[str, str]:
    chain_data = base64.b64decode(_wrap_with_u24_entries(chain or []))
    leaf_input = (
        b"\x00\x00"
        + (1_700_000_000_000).to_bytes(8, "big")
        + b"\x00\x00"
        + len(leaf).to_bytes(3, "big")
        + leaf
        + b"\x00\x00"
    )
    extra_data = len(chain_data).to_bytes(3, "big") + chain_data
    return {
        "leaf_input": base64.b64encode(leaf_input).decode("utf-8"),
        "extra_data": base64.b64encode(extra_data).decode("utf-8"),
    }


def _precert_entry(precertificate: bytes) -> dict[str, str]:
    leaf_input = (
        b"\x00\x00"
        + (1_700_000_000_000).to_bytes(8, "big")
        + b"\x00\x01"
        + bytes(32)
        + b"\x00\x00\x01\x00"
        + b"\x00\x00"
    )
    extra_data = (
        len(precertificate).to_bytes(3, "big")
        + precertificate
        + b"\x00\x00\x00"
    )
    return {
        "leaf_input": base64.b64encode(leaf_input).decode("utf-8"),
        "extra_data": base64.b64encode(extra_data).decode("utf-8"),
    }


def test_extract_hostnames_from_entry_reads_subject_alternative_names() -> None:
    cert = _self_signed_der(dns_names=["www.example.com", "*.wild.example.com"])
    entry = _x509_entry(cert)

    hostnames = _extract_hostnames_from_entry(entry)

    assert "www.example.com" in hostnames
    assert "wild.example.com" in hostnames
    assert "*.wild.example.com" not in hostnames


def test_extract_hostnames_from_entry_falls_back_to_common_name() -> None:
    cert = _self_signed_der(common_name="cn-only.example.com")
    entry = _x509_entry(cert)

    assert _extract_hostnames_from_entry(entry) == ["cn-only.example.com"]


def test_x509_entry_ignores_names_from_the_certificate_chain() -> None:
    leaf = _self_signed_der(dns_names=["leaf.example.com"])
    issuer = _self_signed_der(dns_names=["issuer.invalid.example"])

    assert _extract_hostnames_from_entry(_x509_entry(leaf, [issuer])) == [
        "leaf.example.com"
    ]


def test_precert_entry_reads_the_pre_certificate_from_extra_data() -> None:
    precertificate = _self_signed_der(dns_names=["precert.example.com"])

    assert _extract_hostnames_from_entry(_precert_entry(precertificate)) == [
        "precert.example.com"
    ]


def test_entry_timestamp_becomes_first_seen() -> None:
    entry = _x509_entry(_self_signed_der(dns_names=["dated.example.com"]))

    assert _extract_first_seen(entry) == "2023-11-14T22:13:20.000Z"


def test_malformed_rfc6962_entry_is_ignored() -> None:
    malformed = {
        "leaf_input": base64.b64encode(b"\x00\x00too-short").decode("utf-8"),
        "extra_data": "not base64",
    }

    assert _extract_hostnames_from_entry(malformed) == []


def test_poll_and_store_persists_leaf_names_and_timestamp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "ct.sqlite3")
    database.initialize()
    client = DirectCTClient(database)
    entry = _x509_entry(
        _self_signed_der(dns_names=["api.example.com", "www.example.com"])
    )

    def get_entries(_log_url: str, _start: int, _end: int) -> list[dict[str, Any]]:
        return [entry]

    monkeypatch.setattr(client, "get_entries", get_entries)

    assert client.poll_and_store("https://log.example", 10, 10) == PollResult(
        entry_count=1,
        hostname_count=2,
    )
    assert [
        (row.subdomain, row.first_seen) for row in database.search("example.com")
    ] == [
        ("api.example.com", "2023-11-14T22:13:20.000Z"),
        ("www.example.com", "2023-11-14T22:13:20.000Z"),
    ]


def test_poll_and_store_skips_one_unparseable_certificate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = Database(tmp_path / "ct.sqlite3")
    database.initialize()
    client = DirectCTClient(database)
    entries = [
        {"case": "malformed"},
        {"dns_names": ["kept.example.com"]},
    ]

    monkeypatch.setattr(
        client,
        "get_entries",
        lambda _log_url, _start, _end: entries,
    )
    original_extract = client._extract_hostnames

    def extract(entry: dict[str, Any]) -> list[str]:
        if entry.get("case") == "malformed":
            raise ValueError("invalid certificate ASN.1")
        return original_extract(entry)

    monkeypatch.setattr(client, "_extract_hostnames", extract)

    result = client.poll_and_store("https://log.example", 10, 11)

    assert result == PollResult(entry_count=2, hostname_count=1)
    assert [row.subdomain for row in database.search("example.com")] == [
        "kept.example.com"
    ]


def test_fixture_dns_names_path_lowercases_and_normalizes_wildcards(
    tmp_path: Path,
) -> None:
    client = DirectCTClient(Database(tmp_path / "ct.sqlite3"))

    hostnames = client._extract_hostnames(
        {
            "dns_names": [
                "Example.COM.",
                "*.wild.example.com",
                "bad@name.com",
            ]
        }
    )

    assert hostnames == ["example.com", "wild.example.com"]
