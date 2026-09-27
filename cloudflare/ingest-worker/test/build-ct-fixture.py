from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID


def certificate(*, dns_names: list[str] | None = None, common_name: str) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
    )
    if dns_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in dns_names]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256()).public_bytes(Encoding.DER)


def x509_entry(der: bytes) -> dict[str, str]:
    leaf = (
        b"\x00\x00"
        + (1_700_000_000_000).to_bytes(8, "big")
        + b"\x00\x00"
        + len(der).to_bytes(3, "big")
        + der
        + b"\x00\x00"
    )
    return {
        "leaf_input": base64.b64encode(leaf).decode(),
        "extra_data": base64.b64encode(b"\x00\x00\x00").decode(),
    }


def precert_entry(der: bytes) -> dict[str, str]:
    leaf = (
        b"\x00\x00"
        + (1_700_000_000_000).to_bytes(8, "big")
        + b"\x00\x01"
        + bytes(32)
        + b"\x00\x00\x01\x00"
        + b"\x00\x00"
    )
    extra = len(der).to_bytes(3, "big") + der + b"\x00\x00\x00"
    return {
        "leaf_input": base64.b64encode(leaf).decode(),
        "extra_data": base64.b64encode(extra).decode(),
    }


print(
    json.dumps(
        {
            "san": x509_entry(
                certificate(
                    dns_names=["www.example.com", "*.wild.example.com"],
                    common_name="ignored.example.net",
                )
            ),
            "cn": x509_entry(certificate(common_name="cn-only.example.com")),
            "precert": precert_entry(
                certificate(
                    dns_names=["precert.example.com"],
                    common_name="ignored.example.net",
                )
            ),
        }
    )
)
