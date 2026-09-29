"""Read-only throughput and usage scorecard for the staging .com ingestion."""

import argparse
from datetime import datetime, timezone
import json
import re
import subprocess
import sys
from urllib.request import Request, urlopen

from staging_reconciliation import (
    ACCOUNT_ID, DEAD_QUEUE_ID, JOB_ID_PATTERN, MAIN_QUEUE_ID, ROOT,
    api_token, queue_metric, queue_operations, wrangler_query,
)


BUCKET = "subfinder-catalog-stage"
LEDGER_ID = "f195a017-ef05-405b-9c9d-09919d5a3bc8"
CZDS_ID = "57aecc4f-970a-4327-a8e2-f525445becdc"
CLASS_A = {
    "ListBuckets", "PutBucket", "ListObjects", "PutObject", "CopyObject",
    "CompleteMultipartUpload", "CreateMultipartUpload", "LifecycleStorageTierTransition",
    "ListMultipartUploads", "UploadPart", "UploadPartCopy", "ListParts",
    "PutBucketEncryption", "PutBucketCors", "PutBucketLifecycleConfiguration",
}
CLASS_B = {
    "HeadBucket", "HeadObject", "GetObject", "UsageSummary", "GetBucketEncryption",
    "GetBucketLocation", "GetBucketCors", "GetBucketLifecycleConfiguration",
}


def graphql_rows(token, field, query, variables):
    body = json.dumps({"query": query, "variables": variables}).encode()
    request = Request(
        "https://api.cloudflare.com/client/v4/graphql", data=body,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urlopen(request, timeout=30) as response:
        document = json.load(response)
    if document.get("errors"):
        raise RuntimeError(f"{field} analytics query failed")
    accounts = document.get("data", {}).get("viewer", {}).get("accounts", [])
    if len(accounts) != 1 or field not in accounts[0]:
        raise RuntimeError(f"{field} analytics are unavailable")
    return accounts[0][field]


def r2_usage(token, since, until):
    variables = {"account": ACCOUNT_ID, "bucket": BUCKET, "since": since, "until": until}
    operations = graphql_rows(token, "r2OperationsAdaptiveGroups", """
      query($account: string!, $bucket: string!, $since: Time!, $until: Time!) {
        viewer { accounts(filter: {accountTag: $account}) {
          r2OperationsAdaptiveGroups(limit: 1000, filter: {
            bucketName: $bucket, datetime_geq: $since, datetime_leq: $until
          }) { sum { requests } dimensions { actionType actionStatus } }
        } }
      }
    """, variables)
    if len(operations) == 1000:
        raise RuntimeError("R2 operation groups reached the query limit")
    classified = {"class_a": 0, "class_b": 0, "free": 0}
    unknown = {}
    by_action = {}
    for row in operations:
        action = row["dimensions"]["actionType"]
        status = row["dimensions"]["actionStatus"]
        count = row["sum"]["requests"]
        by_action[f"{action}:{status}"] = count
        if status != "success":
            continue
        if action in CLASS_A:
            classified["class_a"] += count
        elif action in CLASS_B:
            classified["class_b"] += count
        elif action in {"DeleteObject", "DeleteBucket", "AbortMultipartUpload"}:
            classified["free"] += count
        else:
            unknown[action] = unknown.get(action, 0) + count
    storage = graphql_rows(token, "r2StorageAdaptiveGroups", """
      query($account: string!, $bucket: string!, $since: Time!, $until: Time!) {
        viewer { accounts(filter: {accountTag: $account}) {
          r2StorageAdaptiveGroups(limit: 1, orderBy: [datetime_DESC], filter: {
            bucketName: $bucket, datetime_geq: $since, datetime_leq: $until
          }) { max { objectCount payloadSize metadataSize uploadCount }
               dimensions { datetime } }
        } }
      }
    """, variables)
    return {
        "scope": "entire staging R2 bucket, not only .com",
        "operations_by_action_status": by_action,
        "successful_operations_by_price_class": classified,
        "successful_operations_unclassified": unknown,
        "latest_storage_snapshot": storage[0] if storage else None,
    }


def d1_usage(token, start_date, end_date):
    query = """
      query($account: string!, $database: string!, $start: Date!, $end: Date!) {
        viewer { accounts(filter: {accountTag: $account}) {
          d1AnalyticsAdaptiveGroups(limit: 40, filter: {
            databaseId: $database, date_geq: $start, date_leq: $end
          }) { sum { rowsRead rowsWritten readQueries writeQueries }
               dimensions { date } }
        } }
      }
    """
    result = {}
    for name, database in (("generation_ledger", LEDGER_ID), ("czds_control", CZDS_ID)):
        rows = graphql_rows(token, "d1AnalyticsAdaptiveGroups", query, {
            "account": ACCOUNT_ID, "database": database,
            "start": start_date, "end": end_date,
        })
        if len(rows) == 40:
            raise RuntimeError(f"{name} D1 daily groups reached the query limit")
        result[name] = {
            "rows_read": sum(row["sum"]["rowsRead"] for row in rows),
            "rows_written": sum(row["sum"]["rowsWritten"] for row in rows),
            "read_queries": sum(row["sum"]["readQueries"] for row in rows),
            "write_queries": sum(row["sum"]["writeQueries"] for row in rows),
        }
    return {"scope": "both staging D1 databases, including CLI queries", "databases": result}


def worker_usage(token, since, until):
    query = """
      query($account: string!, $script: string!, $since: Time!, $until: Time!) {
        viewer { accounts(filter: {accountTag: $account}) {
          workersInvocationsAdaptive(limit: 1, filter: {
            scriptName: $script, datetime_geq: $since, datetime_leq: $until
          }) { sum { requests errors } quantiles { cpuTimeP50 cpuTimeP99 } }
        } }
      }
    """
    result = {}
    for name in ("subfinder-compaction-stage", "subfinder-czds-stage"):
        rows = graphql_rows(token, "workersInvocationsAdaptive", query, {
            "account": ACCOUNT_ID, "script": name, "since": since, "until": until,
        })
        result[name] = rows[0] if rows else None
    return {"scope": "staging Worker invocations; CPU quantiles are not billable CPU totals",
            "workers": result}


def container_usage(token, start_date, end_date):
    executable = ROOT / "cloudflare/czds-worker/node_modules/.bin/wrangler"
    listed = subprocess.run([str(executable), "containers", "list", "--json"],
                            cwd=ROOT / "cloudflare/czds-worker", check=True,
                            capture_output=True, text=True)
    apps = [app for app in json.loads(listed.stdout)
            if app["name"] == "subfinder-czds-stage-czdsparser"]
    if len(apps) != 1:
        raise RuntimeError("staging CZDS Container application is unavailable")
    app = apps[0]
    rows = graphql_rows(token, "containersUsageAdaptiveGroups", """
      query($account: string!, $application: String!, $start: Time!, $end: Time!) {
        viewer { accounts(filter: {accountTag: $account}) {
          containersUsageAdaptiveGroups(limit: 40, filter: {
            applicationId: $application, date_geq: $start, date_leq: $end
          }) { sum { cpuTimeSec allocatedMemory allocatedDisk txBytes }
               dimensions { date applicationId } }
        } }
      }
    """, {"account": ACCOUNT_ID, "application": app["id"],
          "start": start_date, "end": end_date})
    if len(rows) == 40:
        raise RuntimeError("Container daily groups reached the query limit")
    return {
        "scope": "staging CZDS parser Container billing usage, including sandbox",
        "application_id": app["id"],
        "cpu_seconds": sum(row["sum"]["cpuTimeSec"] for row in rows),
        "memory_byte_seconds": sum(row["sum"]["allocatedMemory"] for row in rows),
        "disk_byte_seconds": sum(row["sum"]["allocatedDisk"] for row in rows),
        "transmitted_bytes": sum(row["sum"]["txBytes"] for row in rows),
    }


def seconds_between(start, end):
    if not start or not end:
        return None
    a = datetime.fromisoformat(start.replace("Z", "+00:00"))
    b = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return max(0, (b - a).total_seconds())


def throughput(job, generations, deltas, partitions):
    source_seconds = seconds_between(job["created_at"], job["updated_at"])
    by_generation = []
    for row in generations:
        states = {item["state"]: item for item in deltas if item["generation_id"] == row["generation_id"]}
        mapped = states.get("mapped", {})
        finished_at = mapped.get("last_updated_at")
        map_seconds = seconds_between(row["created_at"], finished_at)
        parts = {item["state"]: item["count"] for item in partitions
                 if item["generation_id"] == row["generation_id"]}
        by_generation.append({
            "generation_id": row["generation_id"], "state": row["state"],
            "base_generation": row["base_generation"],
            "delta_count": row["delta_count"], "partition_count": row["partition_count"],
            "mapped_chunks": mapped.get("count", 0),
            "mapped_records": mapped.get("records", 0),
            "mapping_wall_seconds": map_seconds,
            "mapped_records_per_wall_second":
                round(mapped["records"] / map_seconds, 1) if map_seconds else None,
            "partition_states": parts,
        })
    registered = next((item for item in deltas if item["generation_id"] is None), {})
    return {
        "source_job": {
            "zone": job["zone"], "state": job["state"],
            "chunks": job["delta_count"], "source_records": job["hostname_count"],
            "wall_seconds": source_seconds,
            "source_records_per_wall_second":
                round(job["hostname_count"] / source_seconds, 1)
                if source_seconds and job["hostname_count"] is not None else None,
        },
        "registered_not_assigned": {
            "chunks": registered.get("count", 0), "records": registered.get("records", 0),
        },
        "generations": by_generation,
        "note": "Wall rates include pauses and retries; source records are the pre-repair total.",
    }


def gross_list_rate(usage):
    components = {}
    queue = usage.get("queues")
    if queue and queue.get("status") == "measured":
        ops = sum(queue[name]["billable_operations"] for name in ("main", "dead_letter"))
        components["queue_operations_usd"] = round(ops * 0.40 / 1_000_000, 4)
    d1 = usage.get("d1")
    if d1 and d1.get("status") == "measured":
        reads = sum(db["rows_read"] for db in d1["databases"].values())
        writes = sum(db["rows_written"] for db in d1["databases"].values())
        components["d1_rows_usd"] = round(
            reads * 0.001 / 1_000_000 + writes * 1.00 / 1_000_000, 4)
    r2 = usage.get("r2")
    if r2 and r2.get("status") == "measured":
        classes = r2["successful_operations_by_price_class"]
        components["r2_classified_operations_usd"] = round(
            classes["class_a"] * 4.50 / 1_000_000 +
            classes["class_b"] * 0.36 / 1_000_000, 4)
    container = usage.get("container")
    if container and container.get("status") == "measured":
        components["czds_container_compute_usd"] = round(
            container["cpu_seconds"] * 0.000020 +
            container["memory_byte_seconds"] / (1024 ** 3) * 0.0000025 +
            container["disk_byte_seconds"] / 1_000_000_000 * 0.00000007, 4)
    return {
        "status": "partial_list_rate_estimate" if components else "unavailable",
        "usd_before_account_allowances": round(sum(components.values()), 4) if components else None,
        "components": components,
        "note": "Not an invoice or .com-only cost. Account allowances are shared. "
                "Excludes R2 storage, D1 storage, Workers CPU and requests, "
                "Workflow duration, Container egress, and unclassified R2 actions.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--since-date", help="UTC YYYY-MM-DD; defaults to the source job creation date")
    args = parser.parse_args()
    if not JOB_ID_PATTERN.fullmatch(args.job_id):
        parser.error("job ID must be SHA-256 hex")
    if args.since_date:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", args.since_date):
            parser.error("--since-date must be UTC YYYY-MM-DD")
        try:
            datetime.strptime(args.since_date, "%Y-%m-%d")
        except ValueError:
            parser.error("--since-date must be UTC YYYY-MM-DD")
    try:
        job_rows = wrangler_query(
            "czds-worker", "subfinder-czds-stage-control",
            "SELECT zone, state, delta_count, hostname_count, created_at, updated_at "
            f"FROM czds_jobs WHERE job_id = '{args.job_id}'",
        )
        if len(job_rows) != 1 or job_rows[0]["zone"] != "com":
            raise RuntimeError("staging .com job is unavailable")
        job = job_rows[0]
        now = datetime.now(timezone.utc)
        start_date = args.since_date or job["created_at"][:10]
        since = f"{start_date}T00:00:00Z"
        if datetime.fromisoformat(since.replace("Z", "+00:00")) > now:
            parser.error("--since-date must not be in the future")
        generations = wrangler_query(
            "compaction-worker", "subfinder-generation-stage-ledger",
            "SELECT generation_id, base_generation, state, delta_count, partition_count, "
            "created_at FROM catalog_generations ORDER BY created_at",
        )
        deltas = wrangler_query(
            "compaction-worker", "subfinder-generation-stage-ledger",
            "SELECT generation_id, state, count(*) AS count, sum(record_count) AS records, "
            "max(updated_at) AS last_updated_at FROM catalog_deltas "
            "GROUP BY generation_id, state",
        )
        partitions = wrangler_query(
            "compaction-worker", "subfinder-generation-stage-ledger",
            "SELECT generation_id, state, count(*) AS count FROM generation_partitions "
            "GROUP BY generation_id, state",
        )
        token = api_token()
        until = now.isoformat()
        usage = {}

        def capture(name, read):
            try:
                usage[name] = {"status": "measured", **read()}
            except (KeyError, ValueError, OSError, RuntimeError,
                    subprocess.CalledProcessError) as error:
                usage[name] = {"status": "unavailable", "reason": str(error)}

        capture("queues", lambda: {
            "scope": "both staging compaction Queues",
            "main": {**queue_metric(MAIN_QUEUE_ID, token),
                     **queue_operations(MAIN_QUEUE_ID, token, since, until)},
            "dead_letter": {**queue_metric(DEAD_QUEUE_ID, token),
                            **queue_operations(DEAD_QUEUE_ID, token, since, until)},
        })
        capture("r2", lambda: r2_usage(token, since, until))
        capture("d1", lambda: d1_usage(token, start_date, now.date().isoformat()))
        capture("workers", lambda: worker_usage(token, since, until))
        capture("container", lambda: container_usage(token, start_date, now.date().isoformat()))
        print(json.dumps({
            "observed_at": until, "job_id": args.job_id,
            "analytics_window": {"from": since, "to": until,
                                 "note": "D1 uses UTC calendar-day groups; other analytics use timestamps."},
            "throughput": throughput(job, generations, deltas, partitions),
            "usage": usage, "cost": gross_list_rate(usage),
        }, indent=2, sort_keys=True))
        return 0
    except (KeyError, ValueError, OSError, RuntimeError,
            subprocess.CalledProcessError) as error:
        print(f"staging cost scorecard unavailable: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
