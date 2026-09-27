from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
from pathlib import Path


def enrich(db: Path, export: Path) -> dict[str, object]:
    path = export / "catalog/root.json"
    root = json.loads(path.read_text(encoding="utf-8"))
    if root.get("format") != "subfinder.r2-index.v2":
        raise ValueError("export root format is unsupported")
    connection = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        connection.execute("PRAGMA query_only = ON")
        names = [str(row[0]) for row in connection.execute(
            "SELECT source FROM index_sources ORDER BY source"
        )]
    finally:
        connection.close()
    ct_names = [name for name in names if name.startswith(("direct_ct:", "static_ct:"))]
    if len(names) != root["stats"]["source_count"]:
        raise ValueError("source ledger does not match exported source count")
    if len(ct_names) != root["stats"]["ct_log_count"]:
        raise ValueError("CT source ledger does not match exported CT log count")
    if "source_names" in root and root["source_names"] != names:
        raise ValueError("export source names conflict with source ledger")
    root["source_names"] = names
    root["ct_source_names"] = ct_names
    contents = (json.dumps(root, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()
    handle, temporary = tempfile.mkstemp(prefix=".root-enriched-", dir=path.parent)
    try:
        with os.fdopen(handle, "wb") as target:
            target.write(contents)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"generation": root["generation"], "source_count": len(names), "ct_log_count": len(ct_names)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Attach verified source names to a completed R2 export")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--export-root", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(enrich(args.db, args.export_root), sort_keys=True))


if __name__ == "__main__":
    main()
