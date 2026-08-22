from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from ctlogs.database import Database
from ctlogs.ingest.apple_ct import AppleCTLogList
from ctlogs.ingest.chrome_ct import ChromeCTLogList
from ctlogs.ingest.direct_ct import DirectCTClient

log = logging.getLogger("ctlogs.worker")


def _usable_log_urls() -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for Cls in (ChromeCTLogList, AppleCTLogList):
        try:
            for u in Cls().usable_urls():
                if u not in seen:
                    seen.add(u)
                    urls.append(u)
        except Exception as e:
            log.warning("ct log list fetch failed %s: %s", Cls.__name__, e)
    return urls


def _poll_one_log(database: Database, log_url: str, batch: int = 64) -> int:
    client = DirectCTClient(database)
    try:
        sth = client.get_sth(log_url)
        tree_size = int(sth.get("tree_size", 0)) if isinstance(sth, dict) else 0
    except Exception as e:
        # 404 for retired logs and DNS for dead logs are expected once per cycle
        msg = str(e)
        if "404" in msg or "Name or service not known" in msg or "Temporary failure" in msg:
            log.debug("get-sth skipped %s: %s", log_url, e)
        else:
            log.warning("get-sth failed %s: %s", log_url, e)
        return 0
    state = database.get_ingest_state(f"direct_ct:{log_url}")
    try:
        cursor = int(state["cursor"]) if state and state.get("cursor") and str(state["cursor"]).isdigit() else 0
    except Exception:
        cursor = 0
    if cursor >= tree_size:
        return 0
    end = min(cursor + batch - 1, tree_size - 1)
    try:
        n = client.poll_and_store(log_url, cursor, end)
        # poll_and_store already recorded ingest_runs, we additionally checkpoint cursor
        database.upsert_ingest_state(
            f"direct_ct:{log_url}", cursor=str(end + 1), updated_at=datetime.now(UTC).isoformat()
        )
        return n
    except Exception as e:
        log.warning("poll_and_store failed %s %s-%s: %s", log_url, cursor, end, e)
        return 0


async def poll_once(database: Database, batch: int = 64) -> int:
    urls = await asyncio.to_thread(_usable_log_urls)
    total = 0
    for url in urls:
        n = await asyncio.to_thread(_poll_one_log, database, url, batch)
        total += n
        await asyncio.sleep(0)  # yield
    return total


async def worker_loop(database: Database, interval: int = 60, batch: int = 64) -> None:
    log.info("ct worker started: polling %s logs every %ss", "all usable", interval)
    while True:
        try:
            n = await poll_once(database, batch=batch)
            if n:
                log.info("ct worker inserted %s hostnames", n)
        except asyncio.CancelledError:
            log.info("ct worker cancelled")
            raise
        except Exception as e:
            log.warning("ct worker error: %s", e)
        await asyncio.sleep(interval)
