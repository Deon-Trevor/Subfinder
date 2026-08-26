from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from dataclasses import asdict, dataclass

import httpx


@dataclass(frozen=True)
class Sample:
    status: int
    first_byte_ms: float
    total_ms: float
    bytes_read: int


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * fraction))
    return ordered[index]


async def sample(
    client: httpx.AsyncClient,
    url: str,
    apex: str,
    limit: int | None,
) -> Sample:
    started = time.perf_counter()
    first_byte_at: float | None = None
    bytes_read = 0
    params: dict[str, str | int] = {
        "apex": apex,
        "format": "json",
        "dates": 1,
    }
    if limit is not None:
        params["limit"] = limit
    async with client.stream(
        "GET",
        f"{url.rstrip('/')}/v1/search",
        params=params,
    ) as response:
        async for chunk in response.aiter_bytes():
            if first_byte_at is None:
                first_byte_at = time.perf_counter()
            bytes_read += len(chunk)
    finished = time.perf_counter()
    return Sample(
        status=response.status_code,
        first_byte_ms=((first_byte_at or finished) - started) * 1_000,
        total_ms=(finished - started) * 1_000,
        bytes_read=bytes_read,
    )


async def run(args: argparse.Namespace) -> list[Sample]:
    semaphore = asyncio.Semaphore(args.concurrency)
    limits = httpx.Limits(
        max_connections=args.concurrency,
        max_keepalive_connections=args.concurrency,
    )
    async with httpx.AsyncClient(timeout=args.timeout, limits=limits) as client:
        for _ in range(args.warmup):
            await sample(client, args.url, args.apex, args.limit)

        async def bounded_sample() -> Sample:
            async with semaphore:
                return await sample(client, args.url, args.apex, args.limit)

        return await asyncio.gather(
            *(bounded_sample() for _ in range(args.requests))
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark the Subfinder search API")
    parser.add_argument("--url", default="http://127.0.0.1:8200")
    parser.add_argument("--apex", required=True)
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-ttfb-p95-ms", type=float)
    parser.add_argument("--max-total-p95-ms", type=float)
    args = parser.parse_args()
    if args.requests < 1 or args.concurrency < 1 or args.warmup < 0:
        parser.error("requests and concurrency must be positive; warmup cannot be negative")
    if args.limit is not None and args.limit < 1:
        parser.error("limit must be positive")

    samples = asyncio.run(run(args))
    first_byte = [item.first_byte_ms for item in samples]
    total = [item.total_ms for item in samples]
    ttfb_p95 = percentile(first_byte, 0.95)
    total_p95 = percentile(total, 0.95)
    result = {
        "request": {
            "url": args.url,
            "apex": args.apex,
            "requests": args.requests,
            "concurrency": args.concurrency,
            "warmup": args.warmup,
            "limit": args.limit,
        },
        "status_counts": {
            str(status): sum(item.status == status for item in samples)
            for status in sorted({item.status for item in samples})
        },
        "response_bytes": sorted({item.bytes_read for item in samples}),
        "first_byte_ms": {
            "p50": statistics.median(first_byte),
            "p95": ttfb_p95,
            "p99": percentile(first_byte, 0.99),
        },
        "total_ms": {
            "p50": statistics.median(total),
            "p95": total_p95,
            "p99": percentile(total, 0.99),
        },
        "samples": [asdict(item) for item in samples[:3]],
    }
    print(json.dumps(result, indent=2))

    failed = any(item.status != 200 for item in samples)
    if args.max_ttfb_p95_ms is not None:
        failed = failed or ttfb_p95 > args.max_ttfb_p95_ms
    if args.max_total_p95_ms is not None:
        failed = failed or total_p95 > args.max_total_p95_ms
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
