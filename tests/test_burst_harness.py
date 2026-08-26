from pathlib import Path
from types import SimpleNamespace

import pytest

from ctlogs.app import normalize_apex
from scripts.benchmark_bursts import (
    acceptance_failures,
    build_public_work,
    load_test_identity,
    parse_server_timing,
    read_domains,
    require_loopback_url,
)


COHORT = Path("tests/fixtures/alexa_top_70_2023-02-07.txt")


def test_alexa_burst_cohort_has_70_unique_registrable_apexes() -> None:
    domains = read_domains(COHORT)

    assert len(domains) == 70
    assert len(set(domains)) == 70
    assert [normalize_apex(domain) for domain in domains] == domains


def test_burst_workloads_are_reproducible_and_cover_the_cohort() -> None:
    domains = read_domains(COHORT)

    same, same_metadata = build_public_work(
        "same-apex", domains, 70, seed=20260826, burst_size=10, burst_gap=0.1
    )
    distinct, distinct_metadata = build_public_work(
        "distinct", domains, 70, seed=20260826, burst_size=10, burst_gap=0.1
    )
    bursts, burst_metadata = build_public_work(
        "bursts", domains, 70, seed=20260826, burst_size=10, burst_gap=0.1
    )

    assert same_metadata == {"hot_apex": "google.com", "hot_request_count": 38}
    assert sum(item.apex == "google.com" for item in same) == 38
    assert len({item.identity for item in same}) == 70
    assert distinct_metadata == {"unique_apexes": 70}
    assert [item.apex for item in distinct] == domains
    assert {item.apex for item in bursts} == set(domains)
    assert burst_metadata == {
        "burst_size": 10,
        "burst_gap_seconds": 0.1,
        "burst_count": 7,
    }
    assert sorted({item.delay_seconds for item in bursts}) == pytest.approx([
        0.0,
        0.1,
        0.2,
        0.3,
        0.4,
        0.5,
        0.6,
    ])


def test_shared_identity_mode_models_one_client_burst() -> None:
    domains = read_domains(COHORT)

    work, _ = build_public_work(
        "distinct",
        domains,
        70,
        seed=20260826,
        burst_size=10,
        burst_gap=0.1,
        identity_mode="shared",
    )

    assert {item.identity for item in work} == {"198.18.0.1"}


def test_server_timing_parser_ignores_malformed_values() -> None:
    assert parse_server_timing(
        "admission;dur=6.136, cache;desc=hit, catalog;dur=3.006, bad;dur=nope"
    ) == {"admission": 6.136, "catalog": 3.006}


def test_burst_harness_refuses_non_loopback_targets() -> None:
    require_loopback_url("http://127.0.0.1:8200")
    require_loopback_url("http://[::1]:8200")
    require_loopback_url("http://localhost:8200")

    with pytest.raises(ValueError, match="loopback"):
        require_loopback_url("https://subfinder.syncpundit.io")


def test_private_service_lane_must_also_be_loopback_in_local_load_tests() -> None:
    require_loopback_url("http://127.0.0.1:18721")

    with pytest.raises(ValueError, match="loopback"):
        require_loopback_url("http://subfinder-index:8200")


def test_load_test_identities_are_stable_and_separate_by_class() -> None:
    assert load_test_identity(0) == "198.18.0.1"
    assert load_test_identity(499) == "198.18.1.244"
    assert load_test_identity(0, service=True) == "198.19.0.1"


def test_acceptance_gate_distinguishes_supported_load_from_overload() -> None:
    result = {
        "status_counts": {"public": {"200": 70}, "service": {"200": 10}},
        "health_status_counts": {"200": 20},
        "errors": [],
        "latency_ms": {
            "public": {"total_p95": 190.0},
            "service": {"total_p95": 90.0},
            "health": {"total_p99": 35.0},
        },
    }
    args = SimpleNamespace(
        public_requests=70,
        service_requests=10,
        require_all_success=True,
        require_service_success=False,
        require_public_overload=False,
        max_public_p95_ms=250.0,
        max_service_p95_ms=250.0,
        max_health_p99_ms=50.0,
    )

    assert acceptance_failures(result, args) == []

    args.require_all_success = False
    args.require_service_success = True
    args.require_public_overload = True
    result["status_counts"]["public"] = {"200": 80, "503": 420}
    result["overload_reason_counts"] = {"edge-capacity": 420}
    result["overload_retry_after_counts"] = {"1": 420}
    assert acceptance_failures(result, args) == []


def test_overload_gate_requires_machine_readable_retry_contract() -> None:
    result = {
        "status_counts": {"public": {"200": 80, "503": 20}, "service": {}},
        "health_status_counts": {"200": 20},
        "errors": [],
        "latency_ms": {
            "public": {"total_p95": 100.0},
            "service": {"total_p95": None},
            "health": {"total_p99": 1.0},
        },
        "overload_reason_counts": {"absent": 20},
        "overload_retry_after_counts": {"absent": 20},
    }
    args = SimpleNamespace(
        public_requests=100,
        service_requests=0,
        require_all_success=False,
        require_service_success=False,
        require_public_overload=True,
        max_public_p95_ms=None,
        max_service_p95_ms=None,
        max_health_p99_ms=None,
    )

    failures = acceptance_failures(result, args)

    assert "public overload returned invalid reasons: {'absent': 20}" in failures
    assert "public overload returned invalid retry headers: {'absent': 20}" in failures


def test_acceptance_gate_requires_enough_health_samples_for_a_tail_limit() -> None:
    result = {
        "status_counts": {"public": {"200": 70}, "service": {"200": 10}},
        "health_status_counts": {"200": 1},
        "errors": [],
        "latency_ms": {
            "public": {"total_p95": 100.0},
            "service": {"total_p95": 50.0},
            "health": {"total_p99": 1.0},
        },
    }
    args = SimpleNamespace(
        public_requests=70,
        service_requests=10,
        require_all_success=True,
        require_service_success=False,
        require_public_overload=False,
        max_public_p95_ms=250.0,
        max_service_p95_ms=250.0,
        max_health_p99_ms=50.0,
        min_health_samples=20,
    )

    assert acceptance_failures(result, args) == [
        "health sample count 1 was below 20"
    ]
