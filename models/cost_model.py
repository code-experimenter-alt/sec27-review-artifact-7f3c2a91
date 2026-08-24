"""Analytic resource-demand model for routed one-sided screening.

Every value returned by this module is a model prediction.  The functions do
not read a clock, execute a password verifier, or infer a service percentile.
In particular, the queue calculation is an M/M/c approximation and must not be
reported as an observed latency result.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any, Sequence


def _nonnegative(value: float, name: str) -> None:
    try:
        finite = math.isfinite(value) if type(value) in {int, float} else False
    except OverflowError:
        finite = False
    if not finite or value < 0:
        raise ValueError(f"{name} must be finite and nonnegative")


@dataclass(frozen=True)
class RegionTraffic:
    """Traffic observations and configured FFR for one stable routing region.

    ``cache_lookup_miss_episodes`` counts realized negative-cache misses that
    reached the positive screen. ``realized_positive_cache_misses`` is the
    subset accepted by the *same realized sticky screen predicate*.  The latter
    is already an observation and must never be multiplied by ``configured_ffr``
    a second time.
    """

    region_id: int
    represented_accounts: int
    distinct_invalid_tuples: int
    invalid_requests: int
    valid_requests: int
    cache_lookup_miss_episodes: int
    realized_positive_cache_misses: int
    configured_ffr: float

    def validate(self) -> None:
        for name in (
            "region_id",
            "represented_accounts",
            "distinct_invalid_tuples",
            "invalid_requests",
            "valid_requests",
            "cache_lookup_miss_episodes",
            "realized_positive_cache_misses",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"{name} must be a uint64 count")
        if self.distinct_invalid_tuples > self.invalid_requests:
            raise ValueError("distinct invalid tuples cannot exceed invalid requests")
        if self.cache_lookup_miss_episodes > self.invalid_requests:
            raise ValueError("cache lookup miss episodes cannot exceed invalid requests")
        if self.realized_positive_cache_misses > self.cache_lookup_miss_episodes:
            raise ValueError("realized positive cache misses cannot exceed cache lookup misses")
        if (
            type(self.configured_ffr) not in {int, float}
            or not math.isfinite(self.configured_ffr)
            or not 0 <= self.configured_ffr <= 1
        ):
            raise ValueError("configured_ffr must lie in [0, 1]")


@dataclass(frozen=True)
class MemoryLayout:
    """Complete incremental memory accounting inputs.

    ``cache_entry_payload_bytes`` includes the exact key and version metadata.
    ``cache_table_load_factor`` accounts for empty hash-table slots.  Fixed
    allocator metadata and a bounded admission sketch are separate terms.
    """

    filter_bytes: int
    model_bytes: int
    directory_extra_bytes: int
    cache_capacity_entries: int
    cache_entry_payload_bytes: int = 64
    cache_table_load_factor: float = 0.75
    cache_allocator_bytes_per_entry: int = 16
    cache_fixed_metadata_bytes: int = 0
    cache_admission_sketch_bytes: int = 0
    cache_reserved_slack_bytes: int = 0
    alignment_bytes: int = 8

    def validate(self) -> None:
        for name in (
            "filter_bytes",
            "model_bytes",
            "directory_extra_bytes",
            "cache_capacity_entries",
            "cache_entry_payload_bytes",
            "cache_allocator_bytes_per_entry",
            "cache_fixed_metadata_bytes",
            "cache_admission_sketch_bytes",
            "cache_reserved_slack_bytes",
            "alignment_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        if (
            type(self.cache_table_load_factor) not in {int, float}
            or not math.isfinite(self.cache_table_load_factor)
            or not (0 < self.cache_table_load_factor <= 1)
        ):
            raise ValueError("cache_table_load_factor must lie in (0, 1]")
        if self.alignment_bytes <= 0:
            raise ValueError("alignment_bytes must be positive")

    @property
    def cache_entry_bytes(self) -> int:
        self.validate()
        raw = self.cache_entry_payload_bytes + self.cache_allocator_bytes_per_entry
        table_adjusted = math.ceil(raw / self.cache_table_load_factor)
        return math.ceil(table_adjusted / self.alignment_bytes) * self.alignment_bytes

    @property
    def cache_bytes(self) -> int:
        return (
            self.cache_capacity_entries * self.cache_entry_bytes
            + self.cache_fixed_metadata_bytes
            + self.cache_admission_sketch_bytes
            + self.cache_reserved_slack_bytes
        )

    @property
    def total_bytes(self) -> int:
        self.validate()
        return self.filter_bytes + self.model_bytes + self.directory_extra_bytes + self.cache_bytes


@dataclass(frozen=True)
class CostModelAssumptions:
    """Declared inputs to the load and M/M/c latency approximation."""

    observation_seconds: float
    backend_workers: int
    backend_mean_service_ms: float
    directory_lookup_us: float
    negative_cache_lookup_us: float
    router_inference_us: float
    positive_screen_query_us: float

    def validate(self) -> None:
        for name in (
            "observation_seconds",
            "backend_mean_service_ms",
            "directory_lookup_us",
            "negative_cache_lookup_us",
            "router_inference_us",
            "positive_screen_query_us",
        ):
            _nonnegative(getattr(self, name), name)
        if self.observation_seconds <= 0:
            raise ValueError("observation_seconds must be positive")
        if (
            type(self.backend_workers) is not int
            or self.backend_workers <= 0
            or self.backend_workers > 65_536
        ):
            raise ValueError("backend_workers must be an integer in [1, 65536]")
        if self.backend_mean_service_ms <= 0:
            raise ValueError("backend_mean_service_ms must be positive")

    @property
    def frontend_service_us(self) -> float:
        return (
            self.directory_lookup_us
            + self.negative_cache_lookup_us
            + self.router_inference_us
            + self.positive_screen_query_us
        )


@dataclass(frozen=True)
class CostPrediction:
    evidence_kind: str
    analytic_expected_first_seen_invalid_backend_checks: float
    analytic_expected_static_invalid_backend_checks: float
    replay_observed_adaptive_invalid_backend_checks: int
    valid_backend_checks: int
    total_backend_checks: float
    backend_arrival_rps: float
    backend_worker_utilization: float
    queue_stable: bool
    predicted_mean_queue_ms: float | None
    predicted_mean_forwarded_response_ms: float | None
    predicted_mean_all_request_response_ms: float | None
    frontend_service_us: float
    frontend_full_miss_path_us: float
    frontend_screen_stage_requests: int
    memory_filter_bytes: int
    memory_model_bytes: int
    memory_cache_bytes: int
    memory_directory_extra_bytes: int
    memory_total_bytes: int
    assumptions: dict[str, Any]


def _erlang_c_mean_wait_seconds(
    arrival_rps: float, mean_service_ms: float, workers: int
) -> tuple[float, float | None]:
    """Return utilization and mean queue wait for an M/M/c queue."""

    service_rate = 1000.0 / mean_service_ms
    offered = arrival_rps / service_rate
    utilization = offered / workers
    if arrival_rps == 0:
        return 0.0, 0.0
    if utilization >= 1:
        return utilization, None

    # Erlang-B recursion followed by the B-to-C conversion avoids factorial
    # and power overflow for large worker pools.
    erlang_b = 1.0
    for worker_count in range(1, workers + 1):
        erlang_b = offered * erlang_b / (worker_count + offered * erlang_b)
    probability_wait = erlang_b / (1.0 - utilization + utilization * erlang_b)
    mean_wait = probability_wait / (workers * service_rate - arrival_rps)
    return utilization, mean_wait


def predict_cost(
    regions: Sequence[RegionTraffic],
    assumptions: CostModelAssumptions,
    memory: MemoryLayout,
) -> CostPrediction:
    """Predict queue demand while keeping observations and expectations separate.

    The static expectation weights each realized tuple's multiplicity by the
    region FFR.  This does *not* make repeated requests independent.  It is an
    expectation over filter construction (or over fresh deployments), while a
    realized static predicate remains sticky for every repeat of a tuple.

    Cache behavior and the sticky screen predicate are supplied by one realized
    replay.  ``realized_positive_cache_misses`` therefore enters backend demand
    directly.  Multiplying it by the configured FFR would apply construction
    randomness twice and undercount the realized demand.
    """

    if not regions:
        raise ValueError("at least one region is required")
    assumptions.validate()
    memory.validate()
    region_ids: set[int] = set()
    for region in regions:
        region.validate()
        if region.region_id in region_ids:
            raise ValueError("region_id values must be unique")
        region_ids.add(region.region_id)

    first_seen = math.fsum(
        region.distinct_invalid_tuples * region.configured_ffr for region in regions
    )
    static = math.fsum(region.invalid_requests * region.configured_ffr for region in regions)
    replay_observed_adaptive = sum(region.realized_positive_cache_misses for region in regions)
    for name, value in (
        ("first-seen expectation", first_seen),
        ("static expectation", static),
        ("realized adaptive checks", replay_observed_adaptive),
    ):
        _nonnegative(value, name)
    valid_checks = sum(region.valid_requests for region in regions)
    total_checks = valid_checks + replay_observed_adaptive
    arrival_rps = total_checks / assumptions.observation_seconds
    if not math.isfinite(arrival_rps):
        raise ValueError("backend arrival rate overflowed the finite prediction domain")
    utilization, wait_seconds = _erlang_c_mean_wait_seconds(
        arrival_rps,
        assumptions.backend_mean_service_ms,
        assumptions.backend_workers,
    )
    forwarded_response_ms = None
    all_response_ms = None
    total_requests = sum(region.invalid_requests + region.valid_requests for region in regions)
    screen_stage_requests = valid_checks + sum(
        region.cache_lookup_miss_episodes for region in regions
    )
    base_frontend_us = assumptions.directory_lookup_us + assumptions.negative_cache_lookup_us
    screen_stage_us = assumptions.router_inference_us + assumptions.positive_screen_query_us
    average_frontend_us = (
        base_frontend_us + (screen_stage_requests / total_requests) * screen_stage_us
        if total_requests
        else 0.0
    )
    if not math.isfinite(average_frontend_us):
        raise ValueError("frontend mean overflowed the finite prediction domain")
    if wait_seconds is not None:
        forwarded_response_ms = (
            assumptions.frontend_service_us / 1000.0
            + assumptions.backend_mean_service_ms
            + wait_seconds * 1000.0
        )
        forwarded_fraction = total_checks / total_requests if total_requests else 0.0
        all_response_ms = average_frontend_us / 1000.0 + forwarded_fraction * (
            assumptions.backend_mean_service_ms + wait_seconds * 1000.0
        )

    for name, value in (
        ("backend utilization", utilization),
        ("queue mean", None if wait_seconds is None else wait_seconds * 1000.0),
        ("forwarded response mean", forwarded_response_ms),
        ("all-request response mean", all_response_ms),
    ):
        if value is not None and not math.isfinite(value):
            raise ValueError(f"{name} overflowed the finite prediction domain")

    return CostPrediction(
        evidence_kind="MODEL_PREDICTION_MMC_CONDITIONED_ON_REALIZED_REPLAY",
        analytic_expected_first_seen_invalid_backend_checks=first_seen,
        analytic_expected_static_invalid_backend_checks=static,
        replay_observed_adaptive_invalid_backend_checks=replay_observed_adaptive,
        valid_backend_checks=valid_checks,
        total_backend_checks=total_checks,
        backend_arrival_rps=arrival_rps,
        backend_worker_utilization=utilization,
        queue_stable=wait_seconds is not None,
        predicted_mean_queue_ms=None if wait_seconds is None else wait_seconds * 1000.0,
        predicted_mean_forwarded_response_ms=forwarded_response_ms,
        predicted_mean_all_request_response_ms=all_response_ms,
        frontend_service_us=average_frontend_us,
        frontend_full_miss_path_us=assumptions.frontend_service_us,
        frontend_screen_stage_requests=screen_stage_requests,
        memory_filter_bytes=memory.filter_bytes,
        memory_model_bytes=memory.model_bytes,
        memory_cache_bytes=memory.cache_bytes,
        memory_directory_extra_bytes=memory.directory_extra_bytes,
        memory_total_bytes=memory.total_bytes,
        assumptions={
            **asdict(assumptions),
            "queue_model": "M/M/c Erlang-C mean only",
            "first_seen_static_semantics": ("analytic expectation over construction randomness"),
            "adaptive_semantics": (
                "observed cache miss under one realized sticky predicate; no second FFR factor"
            ),
            "request_scope": "represented valid and existing-account invalid; NO_ACCOUNT excluded",
            "frontend_stage_semantics": (
                "directory+negative lookup on every scoped request; router+positive screen "
                "only on valid requests and negative-cache misses"
            ),
            "tail_latency_modeled": False,
        },
    )
