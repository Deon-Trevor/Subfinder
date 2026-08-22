from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from ctlogs.database import Database

AUTH_URL = "https://account-api.icann.org/api/authenticate"
LINKS_URL = "https://czds-api.icann.org/czds/downloads/links"


class CzdsClient:
    def __init__(
        self,
        username: str,
        password: str,
        *,
        timeout: int = 60,
        opener=urllib.request.urlopen,
    ) -> None:
        self.username = username
        self.password = password
        self.timeout = timeout
        self.opener = opener
        self._token: str | None = None

    def authenticate(self) -> str:
        request = urllib.request.Request(
            AUTH_URL,
            data=json.dumps(
                {"username": self.username, "password": self.password}
            ).encode(),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        with self.opener(request, timeout=self.timeout) as response:
            payload = json.loads(response.read())
        token = payload.get("accessToken") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise ValueError("CZDS authentication response did not contain accessToken")
        self._token = token
        return token

    def _authorized_request(self, url: str, headers: dict[str, str] | None = None):
        token = self._token or self.authenticate()
        request_headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "ctlogs/0.1",
        }
        request_headers.update(headers or {})
        return urllib.request.Request(url, headers=request_headers)

    def _open_authorized(self, url: str, headers: dict[str, str] | None = None):
        try:
            return self.opener(
                self._authorized_request(url, headers),
                timeout=self.timeout,
            )
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise
            self._token = None
            return self.opener(
                self._authorized_request(url, headers),
                timeout=self.timeout,
            )

    def approved_links(self) -> list[str]:
        with self._open_authorized(LINKS_URL) as response:
            payload = json.loads(response.read())
        if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
            raise ValueError("CZDS links response was not a list of URLs")
        return payload

    def download(
        self,
        url: str,
        destination: Path,
        *,
        if_modified_since: str | None = None,
        max_bytes: int = 4 * 1024 * 1024 * 1024,
    ) -> tuple[int, str | None] | None:
        headers = {"Accept": "application/octet-stream"}
        if if_modified_since:
            headers["If-Modified-Since"] = if_modified_since
        try:
            response = self._open_authorized(url, headers)
        except urllib.error.HTTPError as error:
            if error.code == 304:
                return None
            raise
        temporary = destination.with_suffix(destination.suffix + ".part")
        total = 0
        try:
            with response:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with temporary.open("wb") as output:
                    while chunk := response.read(1024 * 1024):
                        total += len(chunk)
                        if total > max_bytes:
                            raise ValueError(f"zone archive exceeds {max_bytes} bytes")
                        output.write(chunk)
                modified = response.headers.get("Last-Modified")
            temporary.replace(destination)
        finally:
            if temporary.exists():
                temporary.unlink()
        return total, modified


def _zone_from_link(link: str) -> str:
    filename = Path(urllib.parse.urlparse(link).path).name
    if not filename.endswith(".zone"):
        raise ValueError(f"unrecognized CZDS download link: {link}")
    return filename.removesuffix(".zone").lower()


def _zone_lines(path: Path):
    raw = path.open("rb")
    try:
        signature = raw.read(2)
        raw.seek(0)
        stream = gzip.GzipFile(fileobj=raw) if signature == b"\x1f\x8b" else raw
        with io.TextIOWrapper(stream, encoding="utf-8", errors="ignore") as text:
            yield from text
    finally:
        if not raw.closed:
            raw.close()


def import_zone(database: Database, zone: str, path: Path, *, batch_size: int = 5000) -> int:
    source = f"czds:{zone}"
    rows: list[tuple[str, str | None]] = []
    count = 0
    previous_owner: str | None = None
    for raw_line in _zone_lines(path):
        leading_space = raw_line[:1].isspace()
        line = raw_line.split(";", 1)[0].strip()
        if not line or line.startswith("$"):
            continue
        tokens = line.split()
        if leading_space:
            owner = previous_owner
        else:
            owner = tokens.pop(0).lower()
            previous_owner = owner
        if not owner or "NS" not in {token.upper() for token in tokens}:
            continue
        if owner == "@":
            owner = zone
        elif owner.endswith("."):
            owner = owner.rstrip(".")
        else:
            owner = f"{owner}.{zone}"
        if owner == zone or not owner.endswith(f".{zone}"):
            continue
        try:
            owner = owner.encode("idna").decode("ascii")
        except UnicodeError:
            continue
        rows.append((owner, None))
        if len(rows) >= batch_size:
            unique = list(dict.fromkeys(rows))
            database.upsert_subdomains_batch_apex(unique, source=source)
            count += len(unique)
            rows.clear()
    if rows:
        unique = list(dict.fromkeys(rows))
        database.upsert_subdomains_batch_apex(unique, source=source)
        count += len(unique)
    return count


def run_czds(
    database: Database,
    client: CzdsClient,
    output_directory: Path,
    *,
    tlds: set[str] | None = None,
    max_zones: int = 25,
) -> tuple[int, int]:
    links = [
        link
        for link in client.approved_links()
        if tlds is None or _zone_from_link(link) in tlds
    ]
    zone_count = 0
    hostname_count = 0
    for link in links[:max_zones]:
        zone = _zone_from_link(link)
        state_key = f"czds-download:{zone}"
        state = database.get_ingest_state(state_key)
        path = output_directory / f"{zone}.zone.gz"
        started_at = datetime.now(UTC).isoformat()
        started = time.monotonic()
        result = client.download(
            link,
            path,
            if_modified_since=state.get("etag") if state else None,
        )
        if result is None:
            continue
        bytes_read, modified = result
        inserted = import_zone(database, zone, path)
        finished_at = datetime.now(UTC).isoformat()
        database.record_ingest_run(
            f"czds:{zone}",
            started_at,
            finished_at,
            inserted,
            inserted,
            int((time.monotonic() - started) * 1000),
            bytes_read,
        )
        database.upsert_ingest_state(
            state_key,
            cursor=str(bytes_read),
            etag=modified,
            updated_at=finished_at,
        )
        zone_count += 1
        hostname_count += inserted
    return zone_count, hostname_count


def main() -> None:
    parser = argparse.ArgumentParser(description="Download and ingest approved ICANN CZDS zones")
    parser.add_argument("--db", default="data/ctlogs.sqlite3")
    parser.add_argument("--output", default="data/czds")
    parser.add_argument("--tld", action="append")
    parser.add_argument("--max-zones", type=int, default=25)
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()
    if args.max_zones < 1 or args.timeout < 1:
        parser.error("max-zones and timeout must be positive")
    username = os.environ.get("CZDS_USERNAME")
    password = os.environ.get("CZDS_PASSWORD")
    if not username or not password:
        parser.error("CZDS_USERNAME and CZDS_PASSWORD are required")
    database = Database(args.db)
    database.initialize()
    client = CzdsClient(username, password, timeout=args.timeout)
    zones, hostnames = run_czds(
        database,
        client,
        Path(args.output),
        tlds={item.lower().lstrip(".") for item in args.tld} if args.tld else None,
        max_zones=args.max_zones,
    )
    print(f"czds: zones={zones} hostnames={hostnames}")


if __name__ == "__main__":
    main()
