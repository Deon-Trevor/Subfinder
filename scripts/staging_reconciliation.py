"""Read-only reconciliation of a staged CZDS job against its generation ledger."""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
ACCOUNT_ID = "13420e9593fa2a2b308bbdb9256daccf"
MAIN_QUEUE_ID = "877595bfda8042969d9abe95ae9d7f12"
DEAD_QUEUE_ID = "3a5b3ca41870467283f328919b4c1041"
JOB_ID_PATTERN = re.compile(r"[a-f0-9]{64}\Z")


def wrangler_query(worker, database, sql):
    executable = ROOT / "cloudflare" / worker / "node_modules/.bin/wrangler"
    if not executable.is_file():
        raise RuntimeError(f"Wrangler is not installed for {worker}")
    result = subprocess.run(
        [str(executable), "d1", "execute", database, "--remote", "--json",
         "--command", sql],
        cwd=ROOT / "cloudflare" / worker,
        check=True, capture_output=True, text=True,
    )
    response = json.loads(result.stdout)
    if len(response) != 1 or not response[0].get("success"):
        raise RuntimeError(f"D1 query failed for {database}")
    return response[0]["results"]


def paged_query(worker, database, sql_for_cursor, cursor_of, page_size):
    cursor = None
    while True:
        page = wrangler_query(worker, database, sql_for_cursor(cursor, page_size))
        if not page:
            return
        for row in page:
            yield row
        next_cursor = cursor_of(page[-1])
        if cursor is not None and next_cursor <= cursor:
            raise RuntimeError("D1 pagination cursor did not advance")
        cursor = next_cursor
        if len(page) < page_size:
            return


def read_job(job_id, page_size):
    rows = wrangler_query(
        "czds-worker", "subfinder-czds-stage-control",
        "SELECT zone, state, hostname_count, delta_count, error "
        f"FROM czds_jobs WHERE job_id = '{job_id}'",
    )
    if len(rows) != 1:
        raise RuntimeError("CZDS job is unavailable; coverage is unknown")
    source = list(paged_query(
        "czds-worker", "subfinder-czds-stage-control",
        lambda cursor, limit: (
            "SELECT chunk_index, delta_id, object_key, record_count "
            "FROM czds_job_deltas "
            f"WHERE job_id = '{job_id}' AND chunk_index > {cursor if cursor is not None else -1} "
            f"ORDER BY chunk_index LIMIT {limit}"
        ),
        lambda row: row["chunk_index"], page_size,
    ))
    return rows[0], source


def read_ledger(job_id, zone, page_size):
    if not re.fullmatch(r"[a-z0-9-]+", zone):
        raise RuntimeError("CZDS job has an invalid zone")
    prefix = f"ingest/czds/{zone}/{job_id}-"
    return list(paged_query(
        "compaction-worker", "subfinder-generation-stage-ledger",
        lambda cursor, limit: (
            "SELECT delta_id, source_kind, object_key, object_sha256, object_bytes, "
            "record_count, state, error FROM catalog_deltas "
            f"WHERE object_key >= '{prefix}' AND object_key < '{prefix}~' "
            + (f"AND object_key > '{cursor}' " if cursor is not None else "")
            + f"ORDER BY object_key LIMIT {limit}"
        ),
        lambda row: row["object_key"], page_size,
    ))


def read_generations():
    rows = wrangler_query(
        "compaction-worker", "subfinder-generation-stage-ledger",
        "SELECT state, COUNT(*) AS count FROM catalog_generations GROUP BY state",
    )
    return {row["state"]: row["count"] for row in rows}


def reconcile(job, source, ledger, require_complete=False):
    issues = []
    expected_count = job["delta_count"]
    expected_records = job["hostname_count"]
    if job["state"] != "complete":
        issues.append("source job is not complete")
    if expected_count != len(source):
        issues.append("source chunk count differs from job total")
    if expected_records != sum(row["record_count"] for row in source):
        issues.append("source record count differs from job total")
    if any(row["chunk_index"] != index for index, row in enumerate(source)):
        issues.append("source chunk indexes are not contiguous")
    by_id = {row["delta_id"]: row for row in ledger}
    if len(by_id) != len(ledger):
        issues.append("duplicate delta identities in ledger response")
    source_ids = {row["delta_id"] for row in source}
    if len(source_ids) != len(source):
        issues.append("duplicate delta identities in source")
    missing = []
    for row in source:
        registered = by_id.get(row["delta_id"])
        if registered is None:
            missing.append(row["chunk_index"])
            continue
        if (registered["source_kind"] != "czds" or
                registered["object_key"] != row["object_key"] or
                registered["record_count"] != row["record_count"] or
                not re.fullmatch(r"[a-f0-9]{64}", registered["object_sha256"]) or
                registered["object_bytes"] <= 0):
            issues.append(f"ledger identity or metadata mismatch at chunk {row['chunk_index']}")
    unexpected = sorted(set(by_id) - source_ids)
    if unexpected:
        issues.append(f"{len(unexpected)} ledger deltas are absent from the source job")
    failed = sum(row["state"] == "failed" or bool(row["error"]) for row in ledger)
    if failed:
        issues.append(f"{failed} ledger deltas have recorded errors")
    if require_complete and missing:
        issues.append(f"{len(missing)} source chunks are not registered")
    return {
        "status": "failed" if issues else "pending" if missing else "complete",
        "source_state": job["state"],
        "source_chunks": len(source),
        "source_records": sum(row["record_count"] for row in source),
        "ledger_chunks": len(ledger),
        "ledger_records": sum(row["record_count"] for row in ledger),
        "ledger_states": dict(Counter(row["state"] for row in ledger)),
        "missing_chunks": len(missing),
        "missing_chunk_sample": missing[:20],
        "issues": issues,
        "coverage_note": "Ledger metadata was verified on registration; this does not re-hash R2 objects.",
    }


def api_token():
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if token:
        return token
    path = Path.home() / "Library/Preferences/.wrangler/config/default.toml"
    if path.is_file():
        return tomllib.loads(path.read_text())["oauth_token"]
    raise RuntimeError("CLOUDFLARE_API_TOKEN or Wrangler login is required")


def queue_metric(queue_id, token):
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT_ID}/queues/{queue_id}/metrics"
    with urlopen(Request(url, headers={"Authorization": f"Bearer {token}"}), timeout=20) as response:
        payload = json.load(response)
    if not payload.get("success"):
        raise RuntimeError("Cloudflare Queue metrics are unavailable")
    result = payload["result"]
    timestamp = result.get("oldest_message_timestamp_ms")
    return {
        "backlog_count": result["backlog_count"],
        "backlog_bytes": result["backlog_bytes"],
        "oldest_message_age_seconds": (
            max(0, int(datetime.now(timezone.utc).timestamp() - timestamp / 1000))
            if timestamp else None
        ),
    }


def queue_operations(queue_id, token, since, until):
    query = """query QueueOperations($account: string!, $queue: string!,
      $start: Time!, $end: Time!) {
      viewer { accounts(filter: {accountTag: $account}) {
        queueMessageOperationsAdaptiveGroups(limit: 100,
          filter: {queueId: $queue, datetime_geq: $start, datetime_leq: $end}) {
          sum { billableOperations bytes }
          dimensions { actionType outcome }
        }
      } }
    }"""
    payload = json.dumps({"query": query, "variables": {
        "account": ACCOUNT_ID, "queue": queue_id,
        "start": since, "end": until,
    }}).encode()
    request = Request(
        "https://api.cloudflare.com/client/v4/graphql", data=payload,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=20) as response:
        document = json.load(response)
    if document.get("errors"):
        raise RuntimeError("Cloudflare Queue operation analytics are unavailable")
    accounts = document.get("data", {}).get("viewer", {}).get("accounts", [])
    if len(accounts) != 1:
        raise RuntimeError("Cloudflare account analytics are unavailable")
    rows = accounts[0]["queueMessageOperationsAdaptiveGroups"]
    return {
        "from": since, "to": until,
        "billable_operations": sum(row["sum"]["billableOperations"] for row in rows),
        "by_action_outcome": {
            f"{row['dimensions']['actionType']}:{row['dimensions']['outcome'] or 'none'}":
                row["sum"]["billableOperations"] for row in rows
        },
        "note": "Queue operations are usage, not an account invoice or dollar charge.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--page-size", type=int, default=500)
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--metrics-only", action="store_true")
    parser.add_argument("--since", help="UTC ISO timestamp for Queue operations; defaults to 00:00 UTC today")
    args = parser.parse_args()
    if not JOB_ID_PATTERN.fullmatch(args.job_id) or not 1 <= args.page_size <= 1000:
        parser.error("job ID must be SHA-256 hex and page size must be 1..1000")
    try:
        token = api_token()
        now = datetime.now(timezone.utc)
        since = args.since or now.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        since_time = datetime.fromisoformat(since.replace("Z", "+00:00"))
        if since_time.tzinfo is None or since_time.utcoffset().total_seconds() != 0 or since_time > now:
            parser.error("--since must be a past UTC ISO timestamp")
        result = {
            "observed_at": now.isoformat(),
            "job_id": args.job_id,
            "queues": {
                "main": queue_metric(MAIN_QUEUE_ID, token),
                "dead_letter": queue_metric(DEAD_QUEUE_ID, token),
                "operations": {
                    "main": queue_operations(MAIN_QUEUE_ID, token, since, now.isoformat()),
                    "dead_letter": queue_operations(DEAD_QUEUE_ID, token, since, now.isoformat()),
                },
            },
        }
        result["queues"]["status"] = (
            "dead-letter" if result["queues"]["dead_letter"]["backlog_count"]
            else "draining" if result["queues"]["main"]["backlog_count"]
            else "empty"
        )
        if not args.metrics_only:
            job, source = read_job(args.job_id, args.page_size)
            ledger = read_ledger(args.job_id, job["zone"], args.page_size)
            generations = read_generations()
            result["reconciliation"] = reconcile(job, source, ledger, args.require_complete)
            result["reconciliation"]["generation_states"] = generations
            if generations:
                result["reconciliation"]["issues"].append("staging generation started unexpectedly")
                result["reconciliation"]["status"] = "failed"
            if result["queues"]["dead_letter"]["backlog_count"]:
                result["reconciliation"]["issues"].append("dead-letter queue is not empty")
                result["reconciliation"]["status"] = "failed"
        print(json.dumps(result, indent=2, sort_keys=True))
        return 1 if (
            result["queues"]["status"] == "dead-letter" or
            result.get("reconciliation", {}).get("status") == "failed"
        ) else 0
    except (KeyError, ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"staging reconciliation unavailable: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
