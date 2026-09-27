from __future__ import annotations

import contextlib
import io
import json
import sys


with contextlib.redirect_stdout(io.StringIO()):
    from ctlogs.app import normalize_apex


def main() -> None:
    values = json.load(sys.stdin)
    results: list[dict[str, object]] = []
    for value in values:
        try:
            results.append({"ok": True, "value": normalize_apex(value)})
        except ValueError as error:
            results.append({"ok": False, "error": str(error)})
    json.dump(results, sys.stdout, ensure_ascii=False, separators=(",", ":"))


if __name__ == "__main__":
    main()
