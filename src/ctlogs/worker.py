from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime

from ctlogs.database import Database
from ctlogs.ingest.apple_ct import AppleCTLogList
from ctlogs.ingest.chrome_ct import ChromeCTLogList
from ctlogs.ingest.direct_ct import DirectCTClient
from ctlogs.ingest.static_ct import StaticCTClient

log = logging.getLogger("ctlogs.worker")


MAX_PARALLEL_LOG_POLLS = 4
DEFAULT_BATCH_SIZE = 1024
DEFAULT_INITIAL_BACKFILL = 1024
DEFAULT_MAX_BATCHES_PER_LOG = 8


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


def _static_log_urls() -> list[str]:
    raw = os.environ.get("CTLOGS_STATIC_CT_URLS", "")
    return list(
        dict.fromkeys(
            item.strip().rstrip("/")
            for item in raw.split(",")
            if item.strip()
        )
    )


def _poll_one_log(
    database: Database,
    log_url: str,
    batch: int = DEFAULT_BATCH_SIZE,
    initial_backfill: int = DEFAULT_INITIAL_BACKFILL,
    max_batches: int = DEFAULT_MAX_BATCHES_PER_LOG,
) -> int:
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
    source = f"direct_ct:{log_url}"
    state = database.get_ingest_state(source)
    try:
        cursor = (
            int(state["cursor"])
            if state and state.get("cursor") and str(state["cursor"]).isdigit()
            else max(0, tree_size - initial_backfill)
        )
    except Exception:
        cursor = max(0, tree_size - initial_backfill)
    if cursor >= tree_size:
        return 0

    hostname_count = 0
    for _attempt in range(max_batches):
        if cursor >= tree_size:
            break
        end = min(cursor + batch - 1, tree_size - 1)
        try:
            result = client.poll_and_store(log_url, cursor, end)
        except Exception as e:
            log.warning("poll_and_store failed %s %s-%s: %s", log_url, cursor, end, e)
            break
        if result.entry_count < 1:
            log.warning("get-entries returned no entries for %s %s-%s", log_url, cursor, end)
            break

        cursor += result.entry_count
        hostname_count += result.hostname_count
        database.upsert_ingest_state(
            source,
            cursor=str(cursor),
            updated_at=datetime.now(UTC).isoformat(),
        )
    return hostname_count


def _poll_one_static_log(
    database: Database,
    monitoring_url: str,
    batch: int = DEFAULT_BATCH_SIZE,
    initial_backfill: int = DEFAULT_INITIAL_BACKFILL,
    max_batches: int = DEFAULT_MAX_BATCHES_PER_LOG,
) -> int:
    client = StaticCTClient(database)
    try:
        tree_size = client.get_tree_size(monitoring_url)
    except Exception as error:
        log.warning("Static CT checkpoint failed %s: %s", monitoring_url, error)
        return 0

    source = f"static_ct:{monitoring_url}"
    state = database.get_ingest_state(source)
    cursor = (
        int(state["cursor"])
        if state and state.get("cursor") and str(state["cursor"]).isdigit()
        else max(0, tree_size - initial_backfill)
    )
    if cursor >= tree_size:
        return 0

    hostname_count = 0
    for _attempt in range(max_batches):
        if cursor >= tree_size:
            break
        end = min(cursor + batch - 1, tree_size - 1)
        try:
            result = client.poll_and_store(
                monitoring_url,
                cursor,
                end,
                tree_size,
            )
        except Exception as error:
            log.warning(
                "Static CT poll failed %s %s-%s: %s",
                monitoring_url,
                cursor,
                end,
                error,
            )
            break
        if result.entry_count < 1:
            log.warning(
                "Static CT returned no entries for %s %s-%s",
                monitoring_url,
                cursor,
                end,
            )
            break
        cursor += result.entry_count
        hostname_count += result.hostname_count
        database.upsert_ingest_state(
            source,
            cursor=str(cursor),
            updated_at=datetime.now(UTC).isoformat(),
        )
    return hostname_count


async def poll_once(
    database: Database,
    batch: int = DEFAULT_BATCH_SIZE,
    initial_backfill: int = DEFAULT_INITIAL_BACKFILL,
    max_batches: int = DEFAULT_MAX_BATCHES_PER_LOG,
) -> int:
    urls = await asyncio.to_thread(_usable_log_urls)
    static_urls = await asyncio.to_thread(_static_log_urls)
    total = 0
    if not urls and not static_urls:
        return 0

    semaphore = asyncio.Semaphore(MAX_PARALLEL_LOG_POLLS)

    async def _run(kind: str, url: str) -> int:
        async with semaphore:
            poller = _poll_one_log if kind == "rfc6962" else _poll_one_static_log
            return await asyncio.to_thread(
                poller,
                database,
                url,
                batch,
                initial_backfill,
                max_batches,
            )

    jobs = [
        *(('rfc6962', url) for url in urls),
        *(('static', url) for url in static_urls),
    ]
    for n in await asyncio.gather(*(_run(kind, url) for kind, url in jobs)):
        total += n
    return total


async def worker_loop(
    database: Database,
    interval: int = 60,
    batch: int = DEFAULT_BATCH_SIZE,
    initial_backfill: int = DEFAULT_INITIAL_BACKFILL,
    max_batches: int = DEFAULT_MAX_BATCHES_PER_LOG,
) -> None:
    if interval < 1:
        raise ValueError("interval must be a positive integer")
    if batch < 1:
        raise ValueError("batch must be a positive integer")
    if initial_backfill < 1:
        raise ValueError("initial_backfill must be a positive integer")
    if max_batches < 1:
        raise ValueError("max_batches must be a positive integer")

    log.info("ct worker started: polling %s logs every %ss", "all usable", interval)
    while True:
        try:
            n = await poll_once(
                database,
                batch=batch,
                initial_backfill=initial_backfill,
                max_batches=max_batches,
            )
            if n:
                log.info("ct worker inserted %s hostnames", n)
        except asyncio.CancelledError:
            log.info("ct worker cancelled")
            raise
        except Exception as e:
            log.warning("ct worker error: %s", e)
        await asyncio.sleep(interval)
