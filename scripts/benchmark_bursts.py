from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import random
import statistics
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx


@dataclass(frozen=True)
class WorkItem:
    role: str
    apex: str
    path: str
    delay_seconds: float
    identity: str | None


@dataclass(frozen=True)
class Sample:
    role: str
    apex: str
    path: str
    identity: str | None
    status: int
    first_byte_ms: float
    total_ms: float
    bytes_read: int
    refresh_status: str | None
    server_timing: str | None
    error: str | None


def read_domains(path: Path) -> list[str]:
    domains = [
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not domains:
        raise ValueError("domain cohort is empty")
    return domains


def require_loopback_url(value: str) -> None:
    hostname = urlsplit(value).hostname
    if hostname == "localhost":
        return
    try:
        address = ipaddress.ip_address(hostname or "")
    except ValueError as error:
        raise ValueError("load tests require a loopback URL") from error
    if not address.is_loopback:
        raise ValueError("load tests require a loopback URL")


def load_test_identity(index: int, *, service: bool = False) -> str:
    offset = index + 1 + (65_536 if service else 0)
    return f"198.{18 + (offset // 65_536)}.{(offset // 256) % 256}.{offset % 256}"


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * fraction))
    return ordered[index]


def latency_summary(samples: list[Sample]) -> dict[str, float | None]:
    total = [sample.total_ms for sample in samples]
    first_byte = [sample.first_byte_ms for sample in samples]
    return {
        "ttfb_p50": statistics.median(first_byte) if first_byte else None,
        "ttfb_p95": percentile(first_byte, 0.95),
        "ttfb_p99": percentile(first_byte, 0.99),
        "total_p50": statistics.median(total) if total else None,
        "total_p95": percentile(total, 0.95),
        "total_p99": percentile(total, 0.99),
        "total_max": max(total) if total else None,
    }


def parse_server_timing(value: str | None) -> dict[str, float]:
    timings: dict[str, float] = {}
    for metric in (value or "").split(","):
        fields = [field.strip() for field in metric.split(";")]
        if not fields or not fields[0]:
            continue
        duration = next(
            (field[4:] for field in fields[1:] if field.startswith("dur=")),
            None,
        )
        if duration is None:
            continue
        try:
            timings[fields[0]] = float(duration)
        except ValueError:
            continue
    return timings


def server_timing_summary(samples: list[Sample]) -> dict[str, dict[str, float | None]]:
    parsed = [parse_server_timing(sample.server_timing) for sample in samples]
    metrics = sorted({metric for timing in parsed for metric in timing})
    return {
        metric: {
            "p50": statistics.median(values) if values else None,
            "p95": percentile(values, 0.95),
            "p99": percentile(values, 0.99),
            "max": max(values) if values else None,
        }
        for metric in metrics
        if (values := [timing[metric] for timing in parsed if metric in timing])
    }


def acceptance_failures(result: dict[str, Any], args: argparse.Namespace) -> list[str]:
    failures: list[str] = []
    status_counts = result["status_counts"]
    if args.require_all_success:
        expected = {
            "public": {"200": args.public_requests},
            "service": ({"200": args.service_requests} if args.service_requests else {}),
        }
        if status_counts != expected:
            failures.append(f"unexpected status counts: {status_counts}")
        if not result["health_status_counts"]:
            failures.append("health was not sampled")
        elif result["health_status_counts"] != {
            "200": sum(result["health_status_counts"].values())
        }:
            failures.append(
                f"unexpected health status counts: {result['health_status_counts']}"
            )
        if result["errors"]:
            failures.append("transport errors were recorded")
    if args.require_service_success and status_counts["service"] != {
        "200": args.service_requests
    }:
        failures.append(f"service requests did not all succeed: {status_counts['service']}")
    if args.require_public_overload:
        public_statuses = status_counts["public"]
        if int(public_statuses.get("503", 0)) == 0:
            failures.append("public overload did not shed any request with 503")
        if set(public_statuses) - {"200", "503"}:
            failures.append(f"public overload returned unexpected statuses: {public_statuses}")
    for argument, role, metric in (
        ("max_public_p95_ms", "public", "total_p95"),
        ("max_service_p95_ms", "service", "total_p95"),
        ("max_health_p99_ms", "health", "total_p99"),
    ):
        limit = getattr(args, argument)
        observed = result["latency_ms"][role][metric]
        if limit is not None and (observed is None or observed > limit):
            failures.append(f"{role} {metric} {observed} exceeded {limit} ms")
    health_samples = sum(result["health_status_counts"].values())
    minimum_health_samples = getattr(args, "min_health_samples", 20)
    if args.max_health_p99_ms is not None and health_samples < minimum_health_samples:
        failures.append(
            f"health sample count {health_samples} was below {minimum_health_samples}"
        )
    return failures


def build_public_work(
    scenario: str,
    domains: list[str],
    requests: int,
    *,
    seed: int,
    burst_size: int,
    burst_gap: float,
    identity_mode: str = "unique",
) -> tuple[list[WorkItem], dict[str, Any]]:
    rng = random.Random(seed)
    metadata: dict[str, Any] = {}
    if scenario == "same-apex":
        hot_count = rng.randint(max(1, requests // 3), max(1, requests * 2 // 3))
        apexes = [domains[0]] * hot_count
        apexes.extend(domains[1 + (index % (len(domains) - 1))] for index in range(requests - hot_count))
        rng.shuffle(apexes)
        delays = [0.0] * requests
        metadata = {"hot_apex": domains[0], "hot_request_count": hot_count}
    elif scenario == "distinct":
        apexes = [domains[index % len(domains)] for index in range(requests)]
        delays = [0.0] * requests
        metadata = {"unique_apexes": len(set(apexes))}
    elif scenario == "bursts":
        apexes = [domains[index % len(domains)] for index in range(requests)]
        rng.shuffle(apexes)
        delays = [(index // burst_size) * burst_gap for index in range(requests)]
        metadata = {
            "burst_size": burst_size,
            "burst_gap_seconds": burst_gap,
            "burst_count": (requests + burst_size - 1) // burst_size,
        }
    else:
        raise ValueError(f"unknown scenario: {scenario}")

    return [
        WorkItem(
            "public",
            apex,
            "/v1/search",
            delay,
            load_test_identity(0 if identity_mode == "shared" else index),
        )
        for index, (apex, delay) in enumerate(zip(apexes, delays, strict=True))
    ], metadata


def build_service_work(
    domains: list[str],
    requests: int,
    *,
    spread_seconds: float,
) -> list[WorkItem]:
    if requests == 0:
        return []
    step = spread_seconds / max(1, requests - 1)
    return [
        WorkItem(
            "service",
            domains[index % len(domains)],
            "/v1/records",
            index * step,
            load_test_identity(index, service=True),
        )
        for index in range(requests)
    ]


async def sample(
    client: httpx.AsyncClient,
    base_url: str,
    item: WorkItem,
    *,
    service_token: str | None,
    page_limit: int,
    start_gate: asyncio.Event,
) -> Sample:
    await start_gate.wait()
    if item.delay_seconds:
        await asyncio.sleep(item.delay_seconds)
    params: dict[str, str | int] = {}
    if item.apex:
        params["apex"] = item.apex
    if item.path == "/v1/search":
        params.update({"format": "json", "dates": 1, "limit": page_limit})
    headers = {"Accept": "application/json"}
    if item.identity:
        headers["X-Forwarded-For"] = item.identity
    if item.role == "service" and service_token:
        headers["Authorization"] = f"Bearer {service_token}"

    started = time.perf_counter()
    first_byte_at: float | None = None
    bytes_read = 0
    status = 0
    response_headers: httpx.Headers | None = None
    error: str | None = None
    try:
        async with client.stream(
            "GET",
            f"{base_url.rstrip('/')}{item.path}",
            params=params,
            headers=headers,
        ) as response:
            status = response.status_code
            response_headers = response.headers
            async for chunk in response.aiter_bytes():
                if first_byte_at is None:
                    first_byte_at = time.perf_counter()
                bytes_read += len(chunk)
    except Exception as caught:  # The harness records transport failures as data.
        error = f"{type(caught).__name__}: {caught}"
    finished = time.perf_counter()
    return Sample(
        role=item.role,
        apex=item.apex,
        path=item.path,
        identity=item.identity,
        status=status,
        first_byte_ms=((first_byte_at or finished) - started) * 1_000,
        total_ms=(finished - started) * 1_000,
        bytes_read=bytes_read,
        refresh_status=(
            response_headers.get("X-Refresh-Status") if response_headers else None
        ),
        server_timing=(
            response_headers.get("Server-Timing") if response_headers else None
        ),
        error=error,
    )


async def sample_health(
    client: httpx.AsyncClient,
    base_url: str,
    done: asyncio.Event,
    start_gate: asyncio.Event,
    interval: float,
) -> list[Sample]:
    samples: list[Sample] = []
    await start_gate.wait()
    while not done.is_set():
        item = WorkItem("health", "", "/health", 0, None)
        samples.append(
            await sample(
                client,
                base_url,
                item,
                service_token=None,
                page_limit=1,
                start_gate=start_gate,
            )
        )
        await asyncio.sleep(interval)
    return samples


async def run(args: argparse.Namespace) -> dict[str, Any]:
    domains = read_domains(args.domains)
    public, metadata = build_public_work(
        args.scenario,
        domains,
        args.public_requests,
        seed=args.seed,
        burst_size=args.burst_size,
        burst_gap=args.burst_gap,
        identity_mode=args.identity_mode,
    )
    spread = max((item.delay_seconds for item in public), default=0.0)
    service = build_service_work(
        domains,
        args.service_requests,
        spread_seconds=spread,
    )
    work = service + public
    concurrency = args.client_concurrency or len(work)
    public_concurrency = min(concurrency, max(1, len(public)))
    service_concurrency = min(concurrency, max(1, len(service)))
    timeout = httpx.Timeout(args.timeout)
    start_gate = asyncio.Event()
    done = asyncio.Event()
    started = time.perf_counter()
    async with (
        httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(
                max_connections=public_concurrency,
                max_keepalive_connections=public_concurrency,
            ),
        ) as public_client,
        httpx.AsyncClient(
            timeout=timeout,
            limits=httpx.Limits(
                max_connections=service_concurrency,
                max_keepalive_connections=service_concurrency,
            ),
        ) as service_client,
        httpx.AsyncClient(timeout=timeout, limits=httpx.Limits(max_connections=4)) as health_client,
    ):
        health_task = asyncio.create_task(
            sample_health(
                health_client,
                args.url,
                done,
                start_gate,
                args.health_interval,
            )
        )
        tasks = [
            asyncio.create_task(
                sample(
                    service_client if item.role == "service" else public_client,
                    args.url,
                    item,
                    service_token=args.service_token,
                    page_limit=args.page_limit,
                    start_gate=start_gate,
                )
            )
            for item in work
        ]
        start_gate.set()
        samples = await asyncio.gather(*tasks)
        done.set()
        health = await health_task
    duration_ms = (time.perf_counter() - started) * 1_000

    by_role = {
        role: [sample for sample in samples if sample.role == role]
        for role in ("public", "service")
    }
    return {
        "started_at": datetime.now(UTC).isoformat(),
        "request": {
            "url": args.url,
            "scenario": args.scenario,
            "public_requests": args.public_requests,
            "service_requests": args.service_requests,
            "client_concurrency": concurrency,
            "page_limit": args.page_limit,
            "seed": args.seed,
            "forwarded_identities": True,
            "identity_mode": args.identity_mode,
        },
        "workload": {**metadata, "service_spread_seconds": spread},
        "duration_ms": duration_ms,
        "status_counts": {
            role: dict(sorted(Counter(str(item.status) for item in role_samples).items()))
            for role, role_samples in by_role.items()
        },
        "refresh_status_counts": dict(
            sorted(
                Counter(
                    item.refresh_status or "absent"
                    for item in by_role["public"]
                ).items()
            )
        ),
        "latency_ms": {
            "all": latency_summary(samples),
            "public": latency_summary(by_role["public"]),
            "service": latency_summary(by_role["service"]),
            "health": latency_summary(health),
        },
        "server_timing_ms": {
            "public": server_timing_summary(by_role["public"]),
            "service": server_timing_summary(by_role["service"]),
        },
        "bytes": {
            "total": sum(item.bytes_read for item in samples),
            "max_response": max((item.bytes_read for item in samples), default=0),
        },
        "health_status_counts": dict(
            sorted(Counter(str(item.status) for item in health).items())
        ),
        "errors": [asdict(item) for item in samples if item.error][:20],
        "sample": [asdict(item) for item in samples[:5]],
        "slowest": [
            asdict(item)
            for item in sorted(samples, key=lambda item: item.total_ms, reverse=True)[:5]
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Exercise mixed public and service bursts against Subfinder"
    )
    parser.add_argument("--url", default="http://127.0.0.1:8200")
    parser.add_argument("--domains", type=Path, required=True)
    parser.add_argument(
        "--scenario", choices=("same-apex", "distinct", "bursts"), required=True
    )
    parser.add_argument("--public-requests", type=int, default=70)
    parser.add_argument("--service-requests", type=int, default=10)
    parser.add_argument("--service-token")
    parser.add_argument("--client-concurrency", type=int, default=0)
    parser.add_argument("--page-limit", type=int, default=500)
    parser.add_argument("--burst-size", type=int, default=10)
    parser.add_argument("--burst-gap", type=float, default=0.1)
    parser.add_argument("--health-interval", type=float, default=0.001)
    parser.add_argument("--min-health-samples", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--seed", type=int, default=20260826)
    parser.add_argument(
        "--identity-mode",
        choices=("unique", "shared"),
        default="unique",
        help="Use a distinct public client identity per request or one shared identity",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--require-all-success", action="store_true")
    parser.add_argument("--require-service-success", action="store_true")
    parser.add_argument("--require-public-overload", action="store_true")
    parser.add_argument("--max-public-p95-ms", type=float)
    parser.add_argument("--max-service-p95-ms", type=float)
    parser.add_argument("--max-health-p99-ms", type=float)
    args = parser.parse_args()
    try:
        require_loopback_url(args.url)
    except ValueError as error:
        parser.error(str(error))
    for name in (
        "public_requests",
        "page_limit",
        "burst_size",
    ):
        if getattr(args, name) < 1:
            parser.error(f"{name.replace('_', '-')} must be positive")
    if args.service_requests < 0 or args.client_concurrency < 0:
        parser.error("service-requests and client-concurrency cannot be negative")
    if args.min_health_samples < 1:
        parser.error("min-health-samples must be positive")
    if args.burst_gap < 0 or args.health_interval <= 0 or args.timeout <= 0:
        parser.error("timing values must be positive (burst-gap may be zero)")
    for name in ("max_public_p95_ms", "max_service_p95_ms", "max_health_p99_ms"):
        value = getattr(args, name)
        if value is not None and value <= 0:
            parser.error(f"{name.replace('_', '-')} must be positive")

    result = asyncio.run(run(args))
    failures = acceptance_failures(result, args)
    result["acceptance"] = {"passed": not failures, "failures": failures}
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    if not args.quiet:
        print(rendered, end="")
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
