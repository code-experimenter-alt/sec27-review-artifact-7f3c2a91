from __future__ import annotations

import time

from dataplane.types import BackendResultKind, TypedBackendResult
from reference.filters import GlobalBloomFilter, TokenCodec
from service import (
    AuthenticationService,
    AuthRequest,
    KdfBackend,
    KdfProfile,
    OpenLoopLoadGenerator,
    ScheduledArrival,
    ServiceAccount,
    ServiceLimits,
    ServiceMethod,
    TrafficClass,
)


def _account() -> ServiceAccount:
    return ServiceAccount(
        account_index=0,
        username="alice",
        account_id="account-0",
        account_generation=1,
        credential_set_version=1,
        salt=b"0123456789abcdef",
    )


def _limits(**changes) -> ServiceLimits:
    values = {
        "frontend_workers": 1,
        "backend_workers": 1,
        "frontend_queue_capacity": 8,
        "backend_queue_capacity": 4,
        "max_connections": 32,
        "max_padding_timers": 32,
        "max_waiters_per_key": 16,
        "max_waiters_global": 16,
        "failure_padding_seconds": 0,
        "request_timeout_seconds": 1,
        "cache_capacity": 8,
        "cache_ttl_seconds": 10,
        "cache_max_entries_per_account": 8,
    }
    values.update(changes)
    return ServiceLimits(**values)


def _screen_and_codec():
    codec = TokenCodec(b"P" * 32)
    member = _account().screen_query(codec, b"correct")
    # One real Bloom bit is saturated by the member, so every query is an
    # observed positive without a mocked Boolean false-positive oracle.
    return GlobalBloomFilter.build([member], m_bits=1, k_hashes=1, seed=1), codec


def test_backend_confirmed_cache_suppresses_sequential_observed_false_positive() -> None:
    screen, codec = _screen_and_codec()
    profile = KdfProfile(
        "test", "pbkdf2_sha256", {"iterations": 100, "dklen": 16}
    )
    backend = KdfBackend(profile, b"dummy-salt-00000")
    backend.enroll(_account(), b"correct")
    service = AuthenticationService(
        [_account()],
        codec,
        screen,
        backend,
        ServiceMethod("rtraps", True, "lru", True),
        _limits(),
        b"N" * 32,
    )
    now = time.perf_counter_ns()
    first = AuthRequest(1, "alice", b"wrong", TrafficClass.INVALID, "alice:wrong")
    second = AuthRequest(2, "alice", b"wrong", TrafficClass.INVALID, "alice:wrong")
    assert service.submit(first, "measurement", now, now, now + 1_000_000_000)
    assert service.wait_phase("measurement", 2)
    later = time.perf_counter_ns()
    assert service.submit(second, "measurement", later, later, later + 1_000_000_000)
    assert service.wait_phase("measurement", 2)
    snapshot = service.phase_snapshot("measurement")
    assert snapshot["counters"]["backend_invalid_checks"] == 1
    assert snapshot["counters"]["cache_hits"] == 1
    assert snapshot["counters"]["route_negative_cache_reject"] == 1
    assert service.shutdown()


class _SlowMismatchBackend:
    def verify(self, account, username, password):
        time.sleep(0.04)
        assert account is not None
        return TypedBackendResult(
            kind=BackendResultKind.CREDENTIAL_MISMATCH,
            expected_version=account.credential_set_version,
            checked_version=account.credential_set_version,
            checked_account_id=account.account_id,
            checked_account_generation=account.account_generation,
            checked_authenticator_ids=frozenset({"password"}),
        )


def test_open_loop_generator_does_not_wait_for_slow_backend_and_queues_are_bounded() -> None:
    screen, codec = _screen_and_codec()
    service = AuthenticationService(
        [_account()],
        codec,
        screen,
        _SlowMismatchBackend(),
        ServiceMethod("static", True, None, False),
        _limits(
            frontend_queue_capacity=2,
            backend_queue_capacity=1,
            max_connections=6,
        ),
        b"N" * 32,
    )
    arrivals = [
        ScheduledArrival(
            index * 0.001,
            AuthRequest(
                index,
                "alice",
                f"wrong-{index}".encode(),
                TrafficClass.INVALID,
                f"alice:wrong-{index}",
            ),
        )
        for index in range(20)
    ]
    started = time.monotonic()
    report = OpenLoopLoadGenerator().run(
        service, arrivals, duration_seconds=0.03, phase="measurement"
    )
    generator_elapsed = time.monotonic() - started
    assert generator_elapsed < 0.12
    assert report.scheduled == 20
    assert service.wait_phase("measurement", 3)
    snapshot = service.phase_snapshot("measurement")
    drops = (
        snapshot["counters"].get("backend_queue_drops", 0)
        + snapshot["counters"].get("frontend_queue_drops", 0)
        + snapshot["counters"].get("connection_drops", 0)
    )
    assert drops > 0
    assert snapshot["counters"]["backend_checks"] < report.scheduled
    assert service.shutdown()


def test_async_singleflight_coalesces_concurrent_exact_tuple_without_frontend_waiting() -> None:
    screen, codec = _screen_and_codec()
    service = AuthenticationService(
        [_account()],
        codec,
        screen,
        _SlowMismatchBackend(),
        ServiceMethod("rtraps", True, "lru", True),
        _limits(frontend_workers=2, backend_queue_capacity=2),
        b"N" * 32,
    )
    now = time.perf_counter_ns()
    for index in range(8):
        request = AuthRequest(
            index,
            "alice",
            b"same-wrong-password",
            TrafficClass.INVALID,
            "alice:same-wrong-password",
        )
        assert service.submit(
            request,
            "measurement",
            now,
            now,
            now + 1_000_000_000,
        )
    assert service.wait_phase("measurement", 3)
    snapshot = service.phase_snapshot("measurement")
    assert snapshot["counters"]["backend_invalid_checks"] == 1
    assert snapshot["counters"]["singleflight_suppressed"] == 7
    assert snapshot["singleflight"]["peak_waiters"] == 7
    assert service.shutdown()


def test_offered_requests_have_exactly_one_terminal_route_and_drops_are_not_responses() -> None:
    screen, codec = _screen_and_codec()
    service = AuthenticationService(
        [_account()],
        codec,
        screen,
        _SlowMismatchBackend(),
        ServiceMethod("bounded", True, None, False),
        _limits(max_connections=1, frontend_queue_capacity=4, backend_queue_capacity=2),
        b"N" * 32,
    )
    now = time.perf_counter_ns()
    for index in range(4):
        service.submit(
            AuthRequest(
                index,
                "alice",
                f"wrong-{index}".encode(),
                TrafficClass.INVALID,
                f"alice:wrong-{index}",
            ),
            "measurement",
            now,
            now,
            now + 1_000_000_000,
        )
    assert service.wait_phase("measurement", 2)
    snapshot = service.phase_snapshot("measurement")
    counters = snapshot["counters"]
    assert counters["offered_requests"] == 4
    assert counters["terminal_outcomes"] == 4
    assert counters["route_connection_drop"] == 3
    assert counters["responses"] == 1
    assert counters.get("event_errors", 0) == 0
    assert snapshot["request_timeouts"] == 0
    assert snapshot["conservation"]["valid"]
    assert service.shutdown()


class _RaisingBackend:
    def verify(self, account, username, password):
        raise RuntimeError("injected verifier failure")


def test_backend_exception_is_an_event_error_not_a_timeout_and_worker_survives() -> None:
    screen, codec = _screen_and_codec()
    service = AuthenticationService(
        [_account()],
        codec,
        screen,
        _RaisingBackend(),
        ServiceMethod("failure", True, None, False),
        _limits(),
        b"N" * 32,
    )
    for index in range(2):
        now = time.perf_counter_ns()
        assert service.submit(
            AuthRequest(
                index,
                "alice",
                b"wrong",
                TrafficClass.INVALID,
                f"alice:wrong:{index}",
            ),
            "measurement",
            now,
            now,
            now + 1_000_000_000,
        )
        assert service.wait_phase("measurement", 1)
    snapshot = service.phase_snapshot("measurement")
    counters = snapshot["counters"]
    assert counters["event_errors"] == 2
    assert counters["backend_error_checks"] == 2
    assert counters["route_backend_failure"] == 2
    assert snapshot["request_timeouts"] == 0
    assert snapshot["conservation"]["valid"]
    assert service.shutdown()


def test_shutdown_timeout_is_bounded_and_terminalizes_pending_request() -> None:
    screen, codec = _screen_and_codec()
    service = AuthenticationService(
        [_account()],
        codec,
        screen,
        _SlowMismatchBackend(),
        ServiceMethod("shutdown", True, None, False),
        _limits(),
        b"N" * 32,
    )
    now = time.perf_counter_ns()
    assert service.submit(
        AuthRequest(1, "alice", b"wrong", TrafficClass.INVALID, "alice:wrong"),
        "measurement",
        now,
        now,
        now + 1_000_000_000,
    )
    started = time.monotonic()
    report = service.shutdown(timeout=0.01)
    elapsed = time.monotonic() - started
    snapshot = service.phase_snapshot("measurement")
    assert not report.clean
    assert not report.drained_before_deadline
    assert elapsed < 0.2
    assert snapshot["pending"] == 0
    assert snapshot["counters"]["route_shutdown_cancelled"] == 1
    assert snapshot["conservation"]["valid"]


def test_final_snapshot_after_clean_shutdown_includes_kdf_completed_during_drain() -> None:
    screen, codec = _screen_and_codec()
    service = AuthenticationService(
        [_account()],
        codec,
        screen,
        _SlowMismatchBackend(),
        ServiceMethod("drain", True, None, False),
        _limits(),
        b"N" * 32,
    )
    now = time.perf_counter_ns()
    assert service.submit(
        AuthRequest(1, "alice", b"wrong", TrafficClass.INVALID, "alice:wrong"),
        "measurement",
        now,
        now,
        now + 1_000_000_000,
    )
    assert not service.wait_phase("measurement", 0.001)
    report = service.shutdown(timeout=1.0)
    snapshot = service.phase_snapshot("measurement")
    assert report.clean
    assert snapshot["pending"] == 0
    assert snapshot["counters"]["backend_checks"] == 1
    assert snapshot["counters"]["backend_invalid_checks"] == 1
    assert snapshot["conservation"]["valid"]


def test_concurrent_cache_eviction_delta_matches_cache_owned_counter() -> None:
    screen, codec = _screen_and_codec()
    profile = KdfProfile(
        "test", "pbkdf2_sha256", {"iterations": 100, "dklen": 16}
    )
    backend = KdfBackend(profile, b"dummy-salt-00000")
    backend.enroll(_account(), b"correct")
    service = AuthenticationService(
        [_account()],
        codec,
        screen,
        backend,
        ServiceMethod("cache-accounting", True, "lru", False),
        _limits(
            frontend_workers=4,
            backend_workers=4,
            frontend_queue_capacity=64,
            backend_queue_capacity=64,
            cache_capacity=2,
            cache_max_entries_per_account=2,
        ),
        b"N" * 32,
    )
    now = time.perf_counter_ns()
    for index in range(20):
        assert service.submit(
            AuthRequest(
                index,
                "alice",
                f"wrong-{index}".encode(),
                TrafficClass.INVALID,
                f"alice:wrong-{index}",
            ),
            "measurement",
            now,
            now,
            now + 1_000_000_000,
        )
    assert service.wait_phase("measurement", 3)
    snapshot = service.phase_snapshot("measurement")
    assert service.negative_cache is not None
    cache_metrics = service.negative_cache.metrics_snapshot()
    assert snapshot["counters"]["cache_inserted"] == 20
    assert cache_metrics["evictions"] == 18
    assert snapshot["counters"]["cache_evictions"] == cache_metrics["evictions"]
    assert snapshot["conservation"]["valid"]
    assert service.shutdown()
