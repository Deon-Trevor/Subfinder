from __future__ import annotations

import importlib.util
import sqlite3
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "benchmark_r2_index.py"
SPEC = importlib.util.spec_from_file_location("benchmark_r2_index", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_bundle_preserves_exact_apex_records(tmp_path: Path) -> None:
    records = {
        "example.com": [
            {
                "h": "www.example.com",
                "f": "2026-01-02T03:04:05Z",
                "s": [
                    {
                        "n": "czds:com",
                        "f": None,
                        "l": "2026-01-02T03:04:05Z",
                    }
                ],
            }
        ],
        "example.net": [{"h": "example.net", "f": None, "s": []}],
    }
    bundle = tmp_path / "catalog.bundle"
    manifest_path = tmp_path / "manifest.json"

    manifest = MODULE.build_bundle(
        records,
        target_block_bytes=128,
        bundle_path=bundle,
        manifest_path=manifest_path,
    )

    assert MODULE.lookup(
        "example.com", bundle_path=bundle, manifest=manifest
    ) == {"a": "example.com", "r": records["example.com"]}
    assert MODULE.lookup("example.edu", bundle_path=bundle, manifest=manifest) is None
    assert MODULE.lookup("missing.test", bundle_path=bundle, manifest=manifest) is None


def test_sampled_apexes_are_deduplicated_across_anchors() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE subdomains (apex TEXT, subdomain TEXT, first_seen TEXT)"
    )
    connection.executemany(
        "INSERT INTO subdomains VALUES (?, ?, NULL)",
        [
            ("alpha.example", "www.alpha.example"),
            ("alpha.example", "mail.alpha.example"),
            ("beta.example", "www.beta.example"),
        ],
    )

    assert MODULE.sampled_apexes(
        connection,
        anchors=("a", "alpha"),
        apexes_per_anchor=2,
    ) == ["alpha.example", "beta.example"]


def test_sampled_apexes_include_only_requested_apexes_that_exist() -> None:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE subdomains (apex TEXT, subdomain TEXT, first_seen TEXT)"
    )
    connection.executemany(
        "INSERT INTO subdomains VALUES (?, ?, NULL)",
        [
            ("alpha.example", "www.alpha.example"),
            ("large.example", "one.large.example"),
            ("large.example", "two.large.example"),
        ],
    )

    assert MODULE.sampled_apexes(
        connection,
        anchors=("a",),
        apexes_per_anchor=1,
        include_apexes=("large.example", "missing.example"),
    ) == ["alpha.example", "large.example"]


def test_target_block_size_must_be_positive(tmp_path: Path) -> None:
    try:
        MODULE.build_bundle(
            {},
            target_block_bytes=0,
            bundle_path=tmp_path / "catalog.bundle",
            manifest_path=tmp_path / "manifest.json",
        )
    except ValueError as error:
        assert str(error) == "target_block_bytes must be positive"
    else:
        raise AssertionError("expected invalid block size to fail")
