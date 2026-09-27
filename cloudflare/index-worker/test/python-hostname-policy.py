from __future__ import annotations

import contextlib
import io
import json
import re
import sys

import tldextract


LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
with contextlib.redirect_stdout(io.StringIO()):
    EXTRACT = tldextract.TLDExtract(
        suffix_list_urls=(),
        include_psl_private_domains=True,
        cache_dir=None,
    )


def resolve(value: object) -> dict[str, object]:
    try:
        if not isinstance(value, str):
            raise ValueError("hostname is invalid")
        hostname = value.strip().lower().rstrip(".")
        if hostname.startswith("*."):
            hostname = hostname[2:]
        hostname = hostname.encode("idna").decode("ascii")
        labels = hostname.split(".")
        if (
            len(hostname) > 253
            or len(labels) < 2
            or any(not LABEL.fullmatch(label) for label in labels)
        ):
            raise ValueError("hostname is invalid")
        extracted = EXTRACT(hostname)
        apex = (
            extracted.top_domain_under_public_suffix
            if extracted.domain and extracted.suffix
            else hostname
        )
        return {"ok": True, "hostname": hostname, "apex": apex}
    except (UnicodeError, ValueError):
        return {"ok": False}


print(json.dumps([resolve(value) for value in json.load(sys.stdin)]))
