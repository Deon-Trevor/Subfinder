from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path

from test_r2_index_v2 import MODULE as EXPORT, catalog


SCRIPT = Path(__file__).parents[1] / "scripts/enrich_r2_export_root.py"
SPEC = importlib.util.spec_from_file_location("enrich_r2_export_root", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ENRICH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENRICH)


def test_enrich_adds_only_verified_source_names(tmp_path: Path) -> None:
    connection = catalog()
    connection.execute("CREATE TABLE index_sources(source TEXT PRIMARY KEY)")
    connection.executemany(
        "INSERT INTO index_sources(source) VALUES (?)",
        [("czds:com",), ("static_ct:test",)],
    )
    connection.commit()
    database = tmp_path / "catalog.sqlite3"
    destination = sqlite3.connect(database)
    connection.backup(destination)
    destination.close()
    output = tmp_path / "export"
    EXPORT.export_catalog(
        connection,
        output=output,
        generation="fixture",
        apexes=None,
        target_block_bytes=1024,
    )
    root_path = output / "catalog/root.json"
    original = json.loads(root_path.read_text())
    original.pop("source_names")
    original.pop("ct_source_names")
    root_path.write_text(json.dumps(original))

    result = ENRICH.enrich(database, output)
    root = json.loads(root_path.read_text())
    assert result == {"generation": "fixture", "source_count": 2, "ct_log_count": 1}
    assert root["source_names"] == ["czds:com", "static_ct:test"]
    assert root["ct_source_names"] == ["static_ct:test"]
