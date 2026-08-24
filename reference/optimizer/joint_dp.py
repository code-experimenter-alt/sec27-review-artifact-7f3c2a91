from __future__ import annotations

import hashlib
import itertools
import math
import statistics
import sys
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, replace
from fractions import Fraction
from typing import Callable, Hashable, Iterable, Mapping, Sequence

from reference.optimizer.fixed_partition import (
    FixedPartitionProblem,
    FixedPartitionSolution,
    InfeasibleProblem,
    solve_fixed_partition,
)
from reference.optimizer.partition_baselines import normalize_partition

RELATIVE_GAP_DENOMINATOR = "candidate_upper_bound_v1"


def _relative_certificate_gap(
    absolute_gap: float | None, candidate_upper_bound: float | None
) -> float | None:
    """Normalize a certified gap by its positive primal upper bound."""

    if absolute_gap is None or candidate_upper_bound is None:
        return None
    if absolute_gap < 0.0 or candidate_upper_bound < 0.0:
        raise ValueError("certificate bounds must be nonnegative")
    if candidate_upper_bound > 0.0:
        return absolute_gap / candidate_upper_bound
    return 0.0 if absolute_gap == 0.0 else None


@dataclass(frozen=True)
class ReplayEvent:
    timestamp: float
    bin_index: int
    identity: Hashable
    race_extras: int = 0

    def __post_init__(self) -> None:
        if not math.isfinite(self.timestamp):
            raise ValueError("timestamp must be finite")
        if self.bin_index < 0:
            raise ValueError("bin_index must be nonnegative")
        if self.race_extras < 0:
            raise ValueError("race_extras must be nonnegative")


@dataclass(frozen=True)
class ReplayAccounting:
    backend_checks: int
    base_confirmations: int
    race_extras: int
    cache_hits: int
    evictions: int
    expirations: int
    admitted: int


@dataclass(frozen=True)
class OptionGridSpec:
    intervals: tuple[tuple[int, int], ...]
    positive_memory_choices: tuple[int, ...]
    cache_quota_choices: tuple[int, ...]
    cache_policies: tuple[str, ...]
    positive_quantum_bytes: int
    cache_entry_bytes: int
    resource_quantum_bytes: int
    compromise_quantum: float

    def __post_init__(self) -> None:
        if not self.intervals or len(set(self.intervals)) != len(self.intervals):
            raise ValueError("grid intervals must be nonempty and unique")
        if any(not 0 <= start < end for start, end in self.intervals):
            raise ValueError("grid intervals must satisfy 0 <= start < end")
        for name, choices in (
            ("positive-memory", self.positive_memory_choices),
            ("cache-quota", self.cache_quota_choices),
        ):
            if (
                not choices
                or tuple(sorted(set(choices))) != choices
                or any(type(choice) is not int or choice < 0 for choice in choices)
            ):
                raise ValueError(f"{name} choices must be sorted unique nonnegative integers")
        if (
            not self.cache_policies
            or len(set(self.cache_policies)) != len(self.cache_policies)
            or any(policy not in {"always", "second_hit", "none"} for policy in self.cache_policies)
        ):
            raise ValueError("cache policies must be unique supported values")
        if (
            min(
                self.positive_quantum_bytes,
                self.cache_entry_bytes,
                self.resource_quantum_bytes,
            )
            <= 0
        ):
            raise ValueError("grid memory byte sizes must be positive")
        if self.compromise_quantum <= 0 or not math.isfinite(self.compromise_quantum):
            raise ValueError("grid compromise quantum must be finite and positive")

    @property
    def expected_option_count(self) -> int:
        return (
            len(self.intervals)
            * len(self.positive_memory_choices)
            * len(self.cache_quota_choices)
            * len(self.cache_policies)
        )


@dataclass(frozen=True)
class PhysicalResolutionGrid:
    """Physical decision axes and quantizers for a resolution check.

    ``positive_cache_policies`` intentionally excludes ``none``.  A zero-slot
    point has only the ``none`` policy; every positive-slot point has exactly
    the declared positive policies.
    """

    intervals: tuple[tuple[int, int], ...]
    filter_memory_bytes_choices: tuple[int, ...]
    cache_capacity_choices: tuple[int, ...]
    positive_cache_policies: tuple[str, ...]
    resource_quantum_bytes: int
    compromise_quantum: float

    def __post_init__(self) -> None:
        if type(self.intervals) is not tuple or not self.intervals:
            raise ValueError("physical grid intervals must be a nonempty tuple")
        if any(
            type(interval) is not tuple
            or len(interval) != 2
            or type(interval[0]) is not int
            or type(interval[1]) is not int
            or not 0 <= interval[0] < interval[1]
            for interval in self.intervals
        ):
            raise ValueError("physical grid intervals must satisfy 0 <= start < end")
        if tuple(sorted(set(self.intervals))) != self.intervals:
            raise ValueError("physical grid intervals must be sorted and unique")
        for name, choices in (
            ("filter-memory-byte", self.filter_memory_bytes_choices),
            ("cache-slot", self.cache_capacity_choices),
        ):
            if (
                type(choices) is not tuple
                or not choices
                or any(type(choice) is not int or choice < 0 for choice in choices)
            ):
                raise ValueError(f"{name} choices must be sorted unique nonnegative integers")
            if tuple(sorted(set(choices))) != choices:
                raise ValueError(f"{name} choices must be sorted unique nonnegative integers")
        if type(self.positive_cache_policies) is not tuple:
            raise ValueError("positive cache policies must be an immutable tuple")
        if any(
            type(policy) is not str or policy not in {"always", "second_hit"}
            for policy in self.positive_cache_policies
        ):
            raise ValueError(
                "positive cache policies must be sorted unique values from {'always', 'second_hit'}"
            )
        if (
            len(set(self.positive_cache_policies)) != len(self.positive_cache_policies)
            or tuple(sorted(self.positive_cache_policies)) != self.positive_cache_policies
        ):
            raise ValueError(
                "positive cache policies must be sorted unique values from {'always', 'second_hit'}"
            )
        if any(self.cache_capacity_choices) and not self.positive_cache_policies:
            raise ValueError("a positive cache capacity requires positive cache policies")
        if type(self.resource_quantum_bytes) is not int or self.resource_quantum_bytes <= 0:
            raise ValueError("resource_quantum_bytes must be a positive integer")
        if (
            type(self.compromise_quantum) not in {int, float}
            or self.compromise_quantum <= 0
            or not math.isfinite(self.compromise_quantum)
        ):
            raise ValueError("compromise_quantum must be finite and positive")

    @property
    def expected_coordinates(self) -> tuple[tuple[int, int, int, int, str], ...]:
        coordinates: list[tuple[int, int, int, int, str]] = []
        for (start, end), filter_bytes, capacity in itertools.product(
            self.intervals,
            self.filter_memory_bytes_choices,
            self.cache_capacity_choices,
        ):
            policies = ("none",) if capacity == 0 else self.positive_cache_policies
            coordinates.extend((start, end, filter_bytes, capacity, policy) for policy in policies)
        return tuple(coordinates)


@dataclass(frozen=True)
class IntervalOption:
    start_bin: int
    end_bin: int
    positive_memory_quanta: int
    cache_quota: int
    cache_policy: str
    memory_quanta: int
    memory_bytes: int
    compromise_quanta: int
    compromise_mass: float
    worst_region_epsilon: float
    online_cost: float
    cost_standard_error: float = math.nan
    seeded_costs: tuple[float, ...] = ()

    def __post_init__(self) -> None:
        if not 0 <= self.start_bin < self.end_bin:
            raise ValueError("an interval must satisfy 0 <= start_bin < end_bin")
        if (
            min(
                self.positive_memory_quanta,
                self.cache_quota,
                self.memory_quanta,
                self.memory_bytes,
                self.compromise_quanta,
            )
            < 0
        ):
            raise ValueError("discrete resources must be nonnegative")
        if self.online_cost < 0 or not math.isfinite(self.online_cost):
            raise ValueError("online_cost must be finite and nonnegative")
        if not 0 <= self.worst_region_epsilon <= 1:
            raise ValueError("worst_region_epsilon must lie in [0, 1]")
        if any(cost < 0 or not math.isfinite(cost) for cost in self.seeded_costs):
            raise ValueError("seeded costs must be finite and nonnegative")
        if self.seeded_costs and not math.isclose(
            statistics.fmean(self.seeded_costs), self.online_cost, rel_tol=1e-12, abs_tol=1e-12
        ):
            raise ValueError("online_cost must equal the mean of seeded_costs")


@dataclass(frozen=True)
class PhysicalResolutionOption:
    """An interval option retaining its unquantized physical coordinates."""

    filter_memory_bytes: int
    cache_capacity: int
    cache_policy: str
    option: IntervalOption

    def __post_init__(self) -> None:
        if type(self.filter_memory_bytes) is not int or self.filter_memory_bytes < 0:
            raise ValueError("filter_memory_bytes must be a nonnegative integer")
        if type(self.cache_capacity) is not int or self.cache_capacity < 0:
            raise ValueError("cache_capacity must be a nonnegative integer")
        if type(self.cache_policy) is not str or self.cache_policy not in {
            "always",
            "second_hit",
            "none",
        }:
            raise ValueError("cache_policy is unsupported")
        if type(self.option) is not IntervalOption:
            raise TypeError("option must be an IntervalOption")
        if type(self.option.start_bin) is not int or type(self.option.end_bin) is not int:
            raise ValueError("IntervalOption bin coordinates must be integers")
        if type(self.option.cache_quota) is not int:
            raise ValueError("IntervalOption cache_quota must be an integer")
        if self.option.cache_quota != self.cache_capacity:
            raise ValueError("IntervalOption cache_quota differs from cache_capacity")
        if self.option.cache_policy != self.cache_policy:
            raise ValueError("IntervalOption cache_policy differs from the physical coordinate")
        if type(self.option.memory_bytes) is not int:
            raise ValueError("IntervalOption memory_bytes must be an integer")
        for name, value in (
            ("compromise_mass", self.option.compromise_mass),
            ("worst_region_epsilon", self.option.worst_region_epsilon),
            ("online_cost", self.option.online_cost),
        ):
            if type(value) not in {int, float} or not math.isfinite(value):
                raise ValueError(f"IntervalOption {name} must be a finite number")
        if type(self.option.cost_standard_error) not in {int, float}:
            raise ValueError("IntervalOption cost_standard_error must be numeric")
        if not (
            math.isnan(self.option.cost_standard_error)
            or (
                math.isfinite(self.option.cost_standard_error)
                and self.option.cost_standard_error >= 0
            )
        ):
            raise ValueError("IntervalOption cost_standard_error must be nonnegative or NaN")
        if any(type(cost) not in {int, float} for cost in self.option.seeded_costs):
            raise ValueError("IntervalOption seeded costs must be numeric")

    @property
    def coordinate(self) -> tuple[int, int, int, int, str]:
        return (
            self.option.start_bin,
            self.option.end_bin,
            self.filter_memory_bytes,
            self.cache_capacity,
            self.cache_policy,
        )

    @property
    def physical_coordinate(self) -> tuple[int, int, str]:
        return self.filter_memory_bytes, self.cache_capacity, self.cache_policy


@dataclass(frozen=True)
class DPStatistics:
    generated_labels: int
    pruned_labels: int
    maximum_frontier_size: int
    final_feasible_labels: int


@dataclass(frozen=True)
class JointDPSolution:
    options: tuple[IntervalOption, ...]
    online_cost: float
    cost_standard_error: float
    memory_quanta: int
    compromise_quanta: int
    regions_used: int
    statistics: DPStatistics

    @property
    def confidence_interval_95(self) -> tuple[float, float]:
        if not math.isfinite(self.cost_standard_error):
            return math.nan, math.nan
        radius = 1.96 * self.cost_standard_error
        return self.online_cost - radius, self.online_cost + radius


@dataclass(frozen=True)
class ResolutionDoublingResult:
    coarse_solution: JointDPSolution
    fine_solution: JointDPSolution
    relative_objective_change: float
    threshold: float
    resource_scale: int
    coarse_resource_quantum_bytes: int
    fine_resource_quantum_bytes: int
    coarse_compromise_quantum: float
    fine_compromise_quantum: float
    coarse_option_count: int
    fine_option_count: int
    coarse_options_nested_in_fine: bool

    @property
    def passed(self) -> bool:
        return (
            self.coarse_options_nested_in_fine and self.relative_objective_change < self.threshold
        )


@dataclass(frozen=True)
class PhysicalResolutionDoublingResult(ResolutionDoublingResult):
    """A physical resolution result that retains both selected designs."""

    coarse_selected_physical_coordinates: tuple[tuple[int, int, int, int, str], ...]
    fine_selected_physical_coordinates: tuple[tuple[int, int, int, int, str], ...]

    @property
    def coarse_selected_coordinates(self) -> tuple[tuple[int, int, int, int, str], ...]:
        return self.coarse_selected_physical_coordinates

    @property
    def fine_selected_coordinates(self) -> tuple[tuple[int, int, int, int, str], ...]:
        return self.fine_selected_physical_coordinates


@dataclass(frozen=True)
class TwoStageBaselineResult:
    solution: JointDPSolution
    stage_one_solution: JointDPSolution
    stage_one_memory_budget_quanta: int
    distinct_stage_one_designs_evaluated: int


@dataclass(frozen=True)
class StrongBaselineComparison:
    joint_solution: JointDPSolution
    dual_certificate: DualDPCertificate
    global_filter_solution: JointDPSolution | None
    two_stage: TwoStageBaselineResult | None
    joint_reduction_vs_global: float | None
    joint_reduction_vs_two_stage: float | None
    unavailable_baselines: tuple[str, ...]


@dataclass(frozen=True)
class DualDPCandidate:
    """A Lagrangian path in the declared finite ``IntervalOption`` table."""

    options: tuple[IntervalOption, ...]
    memory_multiplier: float
    compromise_multiplier: float
    raw_dual_value: float
    conservative_dual_lower_bound: float
    online_cost: float
    memory_quanta: int
    compromise_quanta: int
    primal_feasible: bool


@dataclass(frozen=True)
class DualDPCertificate:
    """Weak-duality certificate for the finite quantized option table only."""

    candidates: tuple[DualDPCandidate, ...]
    evaluated_multiplier_pairs: int
    dual_lower_bound: float
    best_memory_multiplier: float
    best_compromise_multiplier: float
    feasible_candidate: DualDPCandidate | None
    candidate_upper_bound: float | None
    certified_absolute_gap: float | None
    certified_relative_gap: float | None
    relative_gap_denominator: str


@dataclass(frozen=True)
class ContinuousPartitionCandidate:
    """One continuous-partition path emitted by a Lagrangian shortest-path DP."""

    partition: tuple[tuple[int, int], ...]
    memory_multiplier: float
    compromise_multiplier: float
    region_count_penalty: float
    lagrangian_epsilon: tuple[float, ...]
    raw_dual_value: float
    conservative_dual_lower_bound: float
    fixed_partition_solution: FixedPartitionSolution | None
    region_feasible: bool
    certified_absolute_gap_to_best_dual: float | None = None
    certified_relative_gap_to_best_dual: float | None = None
    relative_gap_denominator: str = RELATIVE_GAP_DENOMINATOR

    @property
    def primal_feasible(self) -> bool:
        return (
            self.region_feasible
            and self.fixed_partition_solution is not None
            and self.fixed_partition_solution.primal_feasible
        )

    @property
    def primal_objective(self) -> float | None:
        if not self.primal_feasible or self.fixed_partition_solution is None:
            return None
        return self.fixed_partition_solution.objective


@dataclass(frozen=True)
class ContinuousPartitionDualCertificate:
    """Weak-duality certificate for continuous T4a allocation over partitions."""

    candidates: tuple[ContinuousPartitionCandidate, ...]
    evaluated_multiplier_triples: int
    distinct_partitions_resolved: int
    dual_lower_bound: float
    best_memory_multiplier: float
    best_compromise_multiplier: float
    best_region_count_penalty: float
    feasible_candidate: ContinuousPartitionCandidate | None
    candidate_upper_bound: float | None
    certified_absolute_gap: float | None
    certified_relative_gap: float | None
    relative_gap_denominator: str


@dataclass(frozen=True)
class _Label:
    prefix_bin: int
    regions_used: int
    memory_quanta: int
    compromise_quanta: int
    online_cost: float
    seeded_costs: tuple[float, ...] | None
    options: tuple[IntervalOption, ...]


def _identity_bytes(identity: Hashable) -> bytes:
    if isinstance(identity, bytes):
        return b"bytes:" + identity
    return (type(identity).__qualname__ + ":" + repr(identity)).encode("utf-8")


def realized_screen_positive(
    identity: Hashable, *, seed: int, start_bin: int, end_bin: int, epsilon: float
) -> bool:
    """Sample a sticky predicate once through a stable threshold hash."""

    if not 0 <= epsilon <= 1:
        raise ValueError("epsilon must lie in [0, 1]")
    header = f"{seed}:{start_bin}:{end_bin}:".encode("ascii")
    digest = hashlib.blake2b(header + _identity_bytes(identity), digest_size=8).digest()
    value = int.from_bytes(digest, "big") / 2**64
    return value < epsilon


def replay_interval(
    events: Sequence[ReplayEvent],
    *,
    start_bin: int,
    end_bin: int,
    positive_identities: set[Hashable],
    cache_quota: int,
    cache_policy: str,
    ttl: float | None = None,
) -> ReplayAccounting:
    """Replay one region-sharded exact negative cache in trace order."""

    if not 0 <= start_bin < end_bin:
        raise ValueError("invalid interval")
    if cache_quota < 0:
        raise ValueError("cache_quota must be nonnegative")
    if cache_policy not in {"always", "second_hit", "none"}:
        raise ValueError("cache_policy must be always, second_hit, or none")
    if ttl is not None and (not math.isfinite(ttl) or ttl < 0):
        raise ValueError("ttl must be finite and nonnegative")

    cache: OrderedDict[Hashable, float] = OrderedDict()
    miss_count: dict[Hashable, int] = defaultdict(int)
    backend_checks = 0
    base_confirmations = 0
    race_extras = 0
    cache_hits = 0
    evictions = 0
    expirations = 0
    admitted = 0
    previous_timestamp = -math.inf

    for event in events:
        if event.timestamp < previous_timestamp:
            raise ValueError("events must be ordered by nondecreasing timestamp")
        previous_timestamp = event.timestamp
        if not start_bin <= event.bin_index < end_bin:
            continue
        if event.identity not in positive_identities:
            continue

        cached_at = cache.get(event.identity)
        if cached_at is not None and ttl is not None and event.timestamp - cached_at > ttl:
            del cache[event.identity]
            cached_at = None
            expirations += 1
        if cached_at is not None:
            cache.move_to_end(event.identity)
            cache_hits += 1
            continue

        base_confirmations += 1
        race_extras += event.race_extras
        backend_checks += 1 + event.race_extras
        miss_count[event.identity] += 1
        should_admit = (
            cache_quota > 0
            and cache_policy != "none"
            and (cache_policy == "always" or miss_count[event.identity] >= 2)
        )
        if should_admit:
            if len(cache) >= cache_quota:
                cache.popitem(last=False)
                evictions += 1
            cache[event.identity] = event.timestamp
            admitted += 1

    return ReplayAccounting(
        backend_checks=backend_checks,
        base_confirmations=base_confirmations,
        race_extras=race_extras,
        cache_hits=cache_hits,
        evictions=evictions,
        expirations=expirations,
        admitted=admitted,
    )


def build_replay_option_table(
    events: Sequence[ReplayEvent],
    *,
    intervals: Iterable[tuple[int, int]],
    occupancy_by_bin: Sequence[float],
    compromise_weight_by_bin: Sequence[float],
    interval_beta: Mapping[tuple[int, int], float],
    positive_memory_choices: Sequence[int],
    cache_quota_choices: Sequence[int],
    cache_policies: Sequence[str],
    seeds: Sequence[int],
    positive_quantum_bytes: int,
    cache_entry_bytes: int,
    resource_quantum_bytes: int,
    compromise_quantum: float,
    ttl: float | None = None,
) -> tuple[IntervalOption, ...]:
    """Construct the non-factorized seeded replay table consumed by the DP."""

    if not seeds:
        raise ValueError("at least one replay seed is required")
    if min(positive_quantum_bytes, cache_entry_bytes, resource_quantum_bytes) <= 0:
        raise ValueError("memory byte sizes must be positive")
    if compromise_quantum <= 0 or not math.isfinite(compromise_quantum):
        raise ValueError("compromise_quantum must be finite and positive")
    if len(occupancy_by_bin) != len(compromise_weight_by_bin):
        raise ValueError("bin arrays must have equal lengths")
    if any(value <= 0 for value in occupancy_by_bin):
        raise ValueError("occupancy must be positive")
    if any(value < 0 for value in compromise_weight_by_bin):
        raise ValueError("compromise weights must be nonnegative")
    if any(choice < 0 for choice in tuple(positive_memory_choices) + tuple(cache_quota_choices)):
        raise ValueError("memory and quota choices must be nonnegative")
    if any(event.bin_index >= len(occupancy_by_bin) for event in events):
        raise ValueError("an event bin falls outside the declared bin arrays")

    unique_by_interval: dict[tuple[int, int], set[Hashable]] = {}
    options: list[IntervalOption] = []
    for start_bin, end_bin in intervals:
        if not 0 <= start_bin < end_bin <= len(occupancy_by_bin):
            raise ValueError("interval falls outside the declared bins")
        beta = float(interval_beta[(start_bin, end_bin)])
        if beta <= 0 or not math.isfinite(beta):
            raise ValueError("interval beta must be finite and positive")
        occupancy = math.fsum(occupancy_by_bin[start_bin:end_bin])
        compromise_weight = math.fsum(compromise_weight_by_bin[start_bin:end_bin])
        identities = unique_by_interval.setdefault(
            (start_bin, end_bin),
            {event.identity for event in events if start_bin <= event.bin_index < end_bin},
        )

        for positive_quanta in positive_memory_choices:
            positive_bytes = positive_quanta * positive_quantum_bytes
            epsilon = math.exp(-beta * positive_bytes / occupancy)
            compromise_mass = compromise_weight * epsilon
            compromise_quanta = int(math.floor(compromise_mass / compromise_quantum + 1e-12))
            for cache_quota in cache_quota_choices:
                for policy in cache_policies:
                    costs: list[float] = []
                    for seed in seeds:
                        positives = {
                            identity
                            for identity in identities
                            if realized_screen_positive(
                                identity,
                                seed=seed,
                                start_bin=start_bin,
                                end_bin=end_bin,
                                epsilon=epsilon,
                            )
                        }
                        accounting = replay_interval(
                            events,
                            start_bin=start_bin,
                            end_bin=end_bin,
                            positive_identities=positives,
                            cache_quota=cache_quota,
                            cache_policy=policy,
                            ttl=ttl,
                        )
                        costs.append(float(accounting.backend_checks))
                    mean_cost = statistics.fmean(costs)
                    standard_error = (
                        statistics.stdev(costs) / math.sqrt(len(costs))
                        if len(costs) >= 2
                        else math.nan
                    )
                    memory_bytes = positive_bytes + cache_quota * cache_entry_bytes
                    memory_quanta = int(math.ceil(memory_bytes / resource_quantum_bytes))
                    options.append(
                        IntervalOption(
                            start_bin=start_bin,
                            end_bin=end_bin,
                            positive_memory_quanta=positive_quanta,
                            cache_quota=cache_quota,
                            cache_policy=policy,
                            memory_quanta=memory_quanta,
                            memory_bytes=memory_bytes,
                            compromise_quanta=compromise_quanta,
                            compromise_mass=compromise_mass,
                            worst_region_epsilon=epsilon,
                            online_cost=mean_cost,
                            cost_standard_error=standard_error,
                            seeded_costs=tuple(costs),
                        )
                    )
    return tuple(options)


def _dominates(left: _Label, right: _Label) -> bool:
    weak = (
        left.memory_quanta <= right.memory_quanta
        and left.compromise_quanta >= right.compromise_quanta
        and left.online_cost <= right.online_cost
    )
    strict = (
        left.memory_quanta < right.memory_quanta
        or left.compromise_quanta > right.compromise_quanta
        or left.online_cost < right.online_cost
    )
    return weak and strict


def _pareto_prune(labels: Sequence[_Label]) -> tuple[list[_Label], int]:
    ordered = sorted(
        labels,
        key=lambda label: (
            label.memory_quanta,
            -label.compromise_quanta,
            label.online_cost,
            tuple(
                (
                    option.start_bin,
                    option.end_bin,
                    option.positive_memory_quanta,
                    option.cache_quota,
                    option.cache_policy,
                )
                for option in label.options
            ),
        ),
    )
    kept: list[_Label] = []
    for candidate in ordered:
        if any(_dominates(existing, candidate) for existing in kept):
            continue
        kept = [existing for existing in kept if not _dominates(candidate, existing)]
        # Resource/objective-identical labels are interchangeable; retain one.
        if any(
            existing.memory_quanta == candidate.memory_quanta
            and existing.compromise_quanta == candidate.compromise_quanta
            and existing.online_cost == candidate.online_cost
            for existing in kept
        ):
            continue
        kept.append(candidate)
    return kept, len(labels) - len(kept)


def solve_exact_discretized_joint_dp(
    options: Iterable[IntervalOption],
    *,
    n_bins: int,
    memory_budget_quanta: int,
    minimum_compromise_quanta: int,
    maximum_regions: int,
    worst_region_epsilon_cap: float = 1.0,
) -> JointDPSolution:
    """Solve exactly over the supplied quantized interval-option table."""

    if n_bins <= 0 or memory_budget_quanta < 0 or minimum_compromise_quanta < 0:
        raise ValueError("invalid bin or resource limit")
    if maximum_regions <= 0:
        raise ValueError("maximum_regions must be positive")
    if not 0 <= worst_region_epsilon_cap <= 1:
        raise ValueError("worst_region_epsilon_cap must lie in [0, 1]")

    by_start: dict[int, list[IntervalOption]] = defaultdict(list)
    for option in options:
        if option.end_bin > n_bins:
            raise ValueError("an option extends beyond n_bins")
        if option.worst_region_epsilon <= worst_region_epsilon_cap:
            by_start[option.start_bin].append(option)
    for choices in by_start.values():
        choices.sort(
            key=lambda option: (
                option.end_bin,
                option.memory_quanta,
                -option.compromise_quanta,
                option.online_cost,
                option.cache_policy,
            )
        )

    frontiers: dict[tuple[int, int], list[_Label]] = defaultdict(list)
    frontiers[(0, 0)] = [_Label(0, 0, 0, 0, 0.0, (), ())]
    generated = 1
    pruned = 0
    maximum_frontier = 1

    for prefix in range(n_bins):
        for regions in range(maximum_regions):
            key = (prefix, regions)
            if not frontiers.get(key):
                continue
            frontier, removed = _pareto_prune(frontiers[key])
            frontiers[key] = frontier
            pruned += removed
            maximum_frontier = max(maximum_frontier, len(frontier))
            for label in frontier:
                for option in by_start.get(prefix, ()):
                    memory = label.memory_quanta + option.memory_quanta
                    if memory > memory_budget_quanta:
                        continue
                    compromise = min(
                        minimum_compromise_quanta,
                        label.compromise_quanta + option.compromise_quanta,
                    )
                    if label.seeded_costs == ():
                        seeded_costs = option.seeded_costs or None
                    elif (
                        label.seeded_costs is not None
                        and option.seeded_costs
                        and len(label.seeded_costs) == len(option.seeded_costs)
                    ):
                        seeded_costs = tuple(
                            left + right
                            for left, right in zip(
                                label.seeded_costs,
                                option.seeded_costs,
                                strict=True,
                            )
                        )
                    else:
                        seeded_costs = None
                    online_cost = label.online_cost + option.online_cost
                    if not math.isfinite(online_cost) or (
                        seeded_costs is not None
                        and any(not math.isfinite(value) for value in seeded_costs)
                    ):
                        raise ArithmeticError("discretized aggregate objective is not finite")
                    target = (option.end_bin, regions + 1)
                    frontiers[target].append(
                        _Label(
                            prefix_bin=option.end_bin,
                            regions_used=regions + 1,
                            memory_quanta=memory,
                            compromise_quanta=compromise,
                            online_cost=online_cost,
                            seeded_costs=seeded_costs,
                            options=label.options + (option,),
                        )
                    )
                    generated += 1

    final_labels: list[_Label] = []
    for regions in range(1, maximum_regions + 1):
        key = (n_bins, regions)
        frontier, removed = _pareto_prune(frontiers.get(key, ()))
        pruned += removed
        maximum_frontier = max(maximum_frontier, len(frontier))
        final_labels.extend(
            label for label in frontier if label.compromise_quanta >= minimum_compromise_quanta
        )
    if not final_labels:
        raise ValueError("the discretized option table has no feasible complete design")
    best = min(
        final_labels,
        key=lambda label: (
            label.online_cost,
            label.memory_quanta,
            label.regions_used,
            tuple((option.start_bin, option.end_bin) for option in label.options),
        ),
    )
    standard_error = (
        statistics.stdev(best.seeded_costs) / math.sqrt(len(best.seeded_costs))
        if best.seeded_costs is not None and len(best.seeded_costs) >= 2
        else math.nan
    )
    return JointDPSolution(
        options=best.options,
        online_cost=best.online_cost,
        cost_standard_error=standard_error,
        memory_quanta=best.memory_quanta,
        compromise_quanta=sum(option.compromise_quanta for option in best.options),
        regions_used=best.regions_used,
        statistics=DPStatistics(generated, pruned, maximum_frontier, len(final_labels)),
    )


def solve_fixed_partition_joint_dp(
    options: Iterable[IntervalOption],
    *,
    partition: Sequence[Sequence[int]],
    n_bins: int,
    memory_budget_quanta: int,
    minimum_compromise_quanta: int,
    maximum_regions: int,
    worst_region_epsilon_cap: float = 1.0,
) -> JointDPSolution:
    """Solve the exact option DP without allowing the frozen partition to move."""

    if type(n_bins) is not int or isinstance(n_bins, bool):
        raise TypeError("n_bins must be an exact integer")
    if type(memory_budget_quanta) is not int or isinstance(memory_budget_quanta, bool):
        raise TypeError("memory_budget_quanta must be an exact integer")
    if type(minimum_compromise_quanta) is not int or isinstance(minimum_compromise_quanta, bool):
        raise TypeError("minimum_compromise_quanta must be an exact integer")
    if type(maximum_regions) is not int or isinstance(maximum_regions, bool):
        raise TypeError("maximum_regions must be an exact integer")
    if type(worst_region_epsilon_cap) not in {int, float}:
        raise TypeError("worst_region_epsilon_cap must be a real number")
    if maximum_regions <= 0 or maximum_regions > n_bins:
        raise ValueError("maximum_regions must lie in [1, n_bins]")

    frozen = normalize_partition(partition, n_bins=n_bins)
    if maximum_regions < len(frozen):
        raise ValueError("frozen partition uses more than maximum_regions")
    allowed_intervals = set(frozen)
    restricted_options = tuple(options)
    if not restricted_options:
        raise ValueError("fixed-partition option table must be nonempty")
    for option in restricted_options:
        if type(option) is not IntervalOption:
            raise TypeError("fixed-partition option table must contain IntervalOption values")
        if type(option.start_bin) is not int or type(option.end_bin) is not int:
            raise TypeError("option interval coordinates must be exact integers")
        for field in (
            "positive_memory_quanta",
            "cache_quota",
            "memory_quanta",
            "memory_bytes",
            "compromise_quanta",
        ):
            if type(getattr(option, field)) is not int:
                raise TypeError(f"option {field} must be an exact integer")
        if (option.start_bin, option.end_bin) not in allowed_intervals:
            raise ValueError("option table contains an interval outside the frozen partition")
    represented = {(option.start_bin, option.end_bin) for option in restricted_options}
    missing = allowed_intervals - represented
    if missing:
        raise ValueError(f"fixed-partition option table is incomplete; missing={sorted(missing)}")

    solution = solve_exact_discretized_joint_dp(
        restricted_options,
        n_bins=n_bins,
        memory_budget_quanta=memory_budget_quanta,
        minimum_compromise_quanta=minimum_compromise_quanta,
        maximum_regions=maximum_regions,
        worst_region_epsilon_cap=worst_region_epsilon_cap,
    )
    selected_intervals = tuple((option.start_bin, option.end_bin) for option in solution.options)
    if selected_intervals != frozen:
        raise AssertionError("exact DP escaped the frozen partition")
    return solution


def exhaustive_joint_allocation(
    options: Iterable[IntervalOption],
    *,
    n_bins: int,
    memory_budget_quanta: int,
    minimum_compromise_quanta: int,
    maximum_regions: int,
    worst_region_epsilon_cap: float = 1.0,
) -> JointDPSolution:
    """Independent tiny-instance oracle without dynamic programming or pruning."""

    by_start: dict[int, list[IntervalOption]] = defaultdict(list)
    for option in options:
        if option.end_bin <= n_bins and option.worst_region_epsilon <= worst_region_epsilon_cap:
            by_start[option.start_bin].append(option)
    complete: list[tuple[IntervalOption, ...]] = []
    generated = 0

    def visit(prefix: int, selected: tuple[IntervalOption, ...], memory: int) -> None:
        nonlocal generated
        generated += 1
        if prefix == n_bins:
            complete.append(selected)
            return
        if len(selected) >= maximum_regions:
            return
        for option in by_start.get(prefix, ()):
            if memory + option.memory_quanta <= memory_budget_quanta:
                visit(option.end_bin, selected + (option,), memory + option.memory_quanta)

    visit(0, (), 0)
    feasible = [
        selected
        for selected in complete
        if sum(option.compromise_quanta for option in selected) >= minimum_compromise_quanta
    ]
    if not feasible:
        raise ValueError("the discretized option table has no feasible complete design")
    best = min(
        feasible,
        key=lambda selected: (
            sum(option.online_cost for option in selected),
            sum(option.memory_quanta for option in selected),
            len(selected),
            tuple((option.start_bin, option.end_bin) for option in selected),
        ),
    )
    seeded_costs: tuple[float, ...] | None = ()
    for option in best:
        if seeded_costs == ():
            seeded_costs = option.seeded_costs or None
        elif (
            seeded_costs is not None
            and option.seeded_costs
            and len(seeded_costs) == len(option.seeded_costs)
        ):
            seeded_costs = tuple(
                left + right
                for left, right in zip(
                    seeded_costs,
                    option.seeded_costs,
                    strict=True,
                )
            )
        else:
            seeded_costs = None
    standard_error = (
        statistics.stdev(seeded_costs) / math.sqrt(len(seeded_costs))
        if seeded_costs is not None and len(seeded_costs) >= 2
        else math.nan
    )
    return JointDPSolution(
        options=best,
        online_cost=sum(option.online_cost for option in best),
        cost_standard_error=standard_error,
        memory_quanta=sum(option.memory_quanta for option in best),
        compromise_quanta=sum(option.compromise_quanta for option in best),
        regions_used=len(best),
        statistics=DPStatistics(generated, 0, max(1, len(complete)), len(feasible)),
    )


def _dual_dp_candidate(
    options: Sequence[IntervalOption],
    *,
    n_bins: int,
    memory_budget_quanta: int,
    minimum_compromise_quanta: int,
    maximum_regions: int,
    worst_region_epsilon_cap: float,
    memory_multiplier: float,
    compromise_multiplier: float,
) -> DualDPCandidate:
    if (
        memory_multiplier < 0
        or compromise_multiplier < 0
        or not math.isfinite(memory_multiplier + compromise_multiplier)
    ):
        raise ValueError("dual multipliers must be finite and nonnegative")
    by_start: dict[int, list[IntervalOption]] = defaultdict(list)
    for option in options:
        if option.end_bin > n_bins:
            raise ValueError("an option extends beyond n_bins")
        if option.worst_region_epsilon <= worst_region_epsilon_cap:
            by_start[option.start_bin].append(option)
    for choices in by_start.values():
        choices.sort(key=_grid_key)

    states: dict[tuple[int, int], tuple[float, float, tuple[IntervalOption, ...]]] = {
        (0, 0): (0.0, 0.0, ())
    }
    for prefix in range(n_bins):
        for regions in range(maximum_regions):
            current = states.get((prefix, regions))
            if current is None:
                continue
            reduced_cost, absolute_sum, path = current
            for option in by_start.get(prefix, ()):
                contribution = (
                    option.online_cost
                    + memory_multiplier * option.memory_quanta
                    - compromise_multiplier * option.compromise_quanta
                )
                candidate = (
                    reduced_cost + contribution,
                    absolute_sum + abs(contribution),
                    path + (option,),
                )
                target = (option.end_bin, regions + 1)
                incumbent = states.get(target)
                if incumbent is None or (
                    candidate[0],
                    tuple(_grid_key(item) for item in candidate[2]),
                ) < (
                    incumbent[0],
                    tuple(_grid_key(item) for item in incumbent[2]),
                ):
                    states[target] = candidate
    finals = [
        value
        for (prefix, regions), value in states.items()
        if prefix == n_bins and 1 <= regions <= maximum_regions
    ]
    if not finals:
        raise ValueError("dual DP has no complete segmentation")
    reduced_cost, absolute_sum, path = min(
        finals,
        key=lambda value: (
            value[0],
            tuple(_grid_key(item) for item in value[2]),
        ),
    )
    memory_constant = memory_multiplier * memory_budget_quanta
    compromise_constant = compromise_multiplier * minimum_compromise_quanta
    raw_dual = reduced_cost - memory_constant + compromise_constant
    roundoff_allowance = (
        256
        * sys.float_info.epsilon
        * (len(path) + 2)
        * (absolute_sum + abs(memory_constant) + abs(compromise_constant) + abs(raw_dual) + 1.0)
    )
    memory = sum(option.memory_quanta for option in path)
    compromise = sum(option.compromise_quanta for option in path)
    return DualDPCandidate(
        options=path,
        memory_multiplier=memory_multiplier,
        compromise_multiplier=compromise_multiplier,
        raw_dual_value=raw_dual,
        conservative_dual_lower_bound=raw_dual - roundoff_allowance,
        online_cost=sum(option.online_cost for option in path),
        memory_quanta=memory,
        compromise_quanta=compromise,
        primal_feasible=(
            memory <= memory_budget_quanta and compromise >= minimum_compromise_quanta
        ),
    )


def generate_finite_option_dual_dp_candidates(
    options: Iterable[IntervalOption],
    *,
    n_bins: int,
    memory_budget_quanta: int,
    minimum_compromise_quanta: int,
    maximum_regions: int,
    worst_region_epsilon_cap: float = 1.0,
    memory_multipliers: Sequence[float] | None = None,
    compromise_multipliers: Sequence[float] | None = None,
) -> DualDPCertificate:
    """Certify the supplied finite ``IntervalOption`` design space.

    This is the Lagrangian relaxation of the quantized resource constraints in
    the exact finite-option DP.  It is deliberately distinct from
    :func:`generate_continuous_partition_dual_dp_candidates`, which minimizes
    the continuous T4a Lagrangian inside every candidate interval.
    """

    all_options = tuple(options)
    if n_bins <= 0 or memory_budget_quanta < 0 or minimum_compromise_quanta < 0:
        raise ValueError("invalid bin or resource limit")
    if maximum_regions <= 0:
        raise ValueError("maximum_regions must be positive")
    if not 0 <= worst_region_epsilon_cap <= 1:
        raise ValueError("worst_region_epsilon_cap must lie in [0, 1]")
    maximum_cost = max((option.online_cost for option in all_options), default=1.0)
    base_memory = max(1.0, maximum_cost / max(1, memory_budget_quanta))
    base_compromise = max(
        1.0,
        maximum_cost
        / max(
            1,
            minimum_compromise_quanta,
            max((option.compromise_quanta for option in all_options), default=1),
        ),
    )
    if memory_multipliers is None:
        memory_multipliers = (0.0,) + tuple(
            base_memory * 2.0**exponent for exponent in range(-4, 5)
        )
    if compromise_multipliers is None:
        compromise_multipliers = (0.0,) + tuple(
            base_compromise * 2.0**exponent for exponent in range(-4, 5)
        )
    memory_axis = tuple(float(value) for value in memory_multipliers)
    compromise_axis = tuple(float(value) for value in compromise_multipliers)
    if not memory_axis or not compromise_axis:
        raise ValueError("dual multiplier axes must be nonempty")
    if any(value < 0 or not math.isfinite(value) for value in memory_axis + compromise_axis):
        raise ValueError("dual multiplier axes must be finite and nonnegative")

    evaluated: list[DualDPCandidate] = []
    by_path: dict[tuple[tuple[int, int, int, int, str], ...], DualDPCandidate] = {}
    best_dual: DualDPCandidate | None = None
    for memory_multiplier, compromise_multiplier in itertools.product(memory_axis, compromise_axis):
        candidate = _dual_dp_candidate(
            all_options,
            n_bins=n_bins,
            memory_budget_quanta=memory_budget_quanta,
            minimum_compromise_quanta=minimum_compromise_quanta,
            maximum_regions=maximum_regions,
            worst_region_epsilon_cap=worst_region_epsilon_cap,
            memory_multiplier=memory_multiplier,
            compromise_multiplier=compromise_multiplier,
        )
        evaluated.append(candidate)
        if best_dual is None or candidate.conservative_dual_lower_bound > (
            best_dual.conservative_dual_lower_bound
        ):
            best_dual = candidate
        path_key = tuple(_grid_key(option) for option in candidate.options)
        incumbent = by_path.get(path_key)
        if incumbent is None or candidate.conservative_dual_lower_bound > (
            incumbent.conservative_dual_lower_bound
        ):
            by_path[path_key] = candidate
    assert best_dual is not None
    candidates = tuple(
        sorted(
            by_path.values(),
            key=lambda candidate: tuple(_grid_key(option) for option in candidate.options),
        )
    )
    feasible = [candidate for candidate in candidates if candidate.primal_feasible]
    feasible_candidate = min(
        feasible,
        key=lambda candidate: (
            candidate.online_cost,
            candidate.memory_quanta,
            tuple(_grid_key(option) for option in candidate.options),
        ),
        default=None,
    )
    upper_bound = feasible_candidate.online_cost if feasible_candidate else None
    absolute_gap = (
        max(0.0, upper_bound - best_dual.conservative_dual_lower_bound)
        if upper_bound is not None
        else None
    )
    relative_gap = _relative_certificate_gap(absolute_gap, upper_bound)
    return DualDPCertificate(
        candidates=candidates,
        evaluated_multiplier_pairs=len(evaluated),
        dual_lower_bound=best_dual.conservative_dual_lower_bound,
        best_memory_multiplier=best_dual.memory_multiplier,
        best_compromise_multiplier=best_dual.compromise_multiplier,
        feasible_candidate=feasible_candidate,
        candidate_upper_bound=upper_bound,
        certified_absolute_gap=absolute_gap,
        certified_relative_gap=relative_gap,
        relative_gap_denominator=RELATIVE_GAP_DENOMINATOR,
    )


# Backward-compatible name retained for existing artifact commands.  New code
# should use the explicit finite-option name to avoid confusing this certificate
# with continuous-partition T4a candidate generation.
generate_dual_dp_candidates = generate_finite_option_dual_dp_candidates


def _continuous_interval_value(
    *,
    member_occupancy: float,
    beta: float,
    online_weight: float,
    compromise_weight: float,
    epsilon_min: float,
    epsilon_cap: float,
    memory_multiplier: float,
    compromise_multiplier: float,
    region_count_penalty: float,
) -> tuple[float, float]:
    """Return the exact box minimum of one T4a Lagrangian coordinate."""

    a = member_occupancy / beta
    coefficient = online_weight - compromise_multiplier * compromise_weight
    if memory_multiplier == 0.0:
        epsilon = epsilon_min if coefficient > 0.0 else epsilon_cap
    elif coefficient <= 0.0:
        epsilon = epsilon_cap
    else:
        epsilon = min(
            epsilon_cap,
            max(epsilon_min, memory_multiplier * a / coefficient),
        )
    value = (
        coefficient * epsilon
        + memory_multiplier * a * math.log(1.0 / epsilon)
        + region_count_penalty
    )
    return value, epsilon


def _interval_scalar(
    value: float | Mapping[tuple[int, int], float],
    interval: tuple[int, int],
    *,
    name: str,
) -> float:
    selected = value[interval] if isinstance(value, Mapping) else value
    result = float(selected)
    if not math.isfinite(result):
        raise ValueError(f"{name} must contain only finite values")
    return result


def generate_continuous_partition_dual_dp_candidates(
    *,
    member_occupancy_by_bin: Sequence[float],
    online_weight_by_bin: Sequence[float],
    compromise_weight_by_bin: Sequence[float],
    interval_beta: Mapping[tuple[int, int], float],
    memory_budget: float,
    work_factor_floor: float,
    maximum_regions: int,
    epsilon_min: float | Mapping[tuple[int, int], float] = 1e-9,
    epsilon_cap: float | Mapping[tuple[int, int], float] = 1.0,
    memory_multipliers: Sequence[float] | None = None,
    compromise_multipliers: Sequence[float] | None = None,
    region_count_penalties: Sequence[float] | None = None,
) -> ContinuousPartitionDualCertificate:
    """Generate and certify contiguous continuous-partition candidates.

    For every nonnegative multiplier triple ``(lambda, nu, rho)``, each
    interval cost is the exact box minimum of the T4a Lagrangian.  A shortest
    path over all contiguous partitions then gives a valid lower bound after
    subtracting ``lambda * M`` and ``rho * K`` and adding ``nu * Gamma``.
    Every distinct emitted partition is re-solved with the continuous T4a
    solver.  Consequently the reported gap is a certified lower/upper gap for
    the candidate generator; it is not an assertion that multiplier search is
    exhaustive or that the unknown population objective is optimized.
    """

    occupancy = tuple(float(value) for value in member_occupancy_by_bin)
    online = tuple(float(value) for value in online_weight_by_bin)
    compromise = tuple(float(value) for value in compromise_weight_by_bin)
    n_bins = len(occupancy)
    if n_bins == 0 or len(online) != n_bins or len(compromise) != n_bins:
        raise ValueError("continuous partition bin arrays must have equal nonzero length")
    if any(not math.isfinite(value) or value <= 0.0 for value in occupancy):
        raise ValueError("member occupancy must be finite and positive")
    if any(not math.isfinite(value) or value < 0.0 for value in online + compromise):
        raise ValueError("online and compromise weights must be finite and nonnegative")
    if not math.isfinite(memory_budget) or memory_budget < 0.0:
        raise ValueError("memory_budget must be finite and nonnegative")
    if not math.isfinite(work_factor_floor) or work_factor_floor < 0.0:
        raise ValueError("work_factor_floor must be finite and nonnegative")
    if type(maximum_regions) is not int or not 1 <= maximum_regions <= n_bins:
        raise ValueError("maximum_regions must be an integer in [1, n_bins]")

    intervals = tuple(
        (start, end) for start in range(n_bins) for end in range(start + 1, n_bins + 1)
    )
    if set(interval_beta) != set(intervals):
        raise ValueError("interval_beta must cover every contiguous interval exactly")
    if isinstance(epsilon_min, Mapping) and set(epsilon_min) != set(intervals):
        raise ValueError("epsilon_min must cover every contiguous interval exactly")
    if isinstance(epsilon_cap, Mapping) and set(epsilon_cap) != set(intervals):
        raise ValueError("epsilon_cap must cover every contiguous interval exactly")

    occupancy_prefix = [0.0]
    online_prefix = [0.0]
    compromise_prefix = [0.0]
    for n_value, w_value, d_value in zip(occupancy, online, compromise, strict=True):
        occupancy_prefix.append(occupancy_prefix[-1] + n_value)
        online_prefix.append(online_prefix[-1] + w_value)
        compromise_prefix.append(compromise_prefix[-1] + d_value)

    parameters: dict[tuple[int, int], tuple[float, float, float, float, float, float]] = {}
    for interval in intervals:
        start, end = interval
        beta = float(interval_beta[interval])
        lower = _interval_scalar(epsilon_min, interval, name="epsilon_min")
        upper = _interval_scalar(epsilon_cap, interval, name="epsilon_cap")
        if not math.isfinite(beta) or beta <= 0.0:
            raise ValueError("interval_beta must contain finite positive values")
        if not 0.0 < lower <= upper <= 1.0:
            raise ValueError("epsilon bounds must satisfy 0 < min <= cap <= 1")
        parameters[interval] = (
            occupancy_prefix[end] - occupancy_prefix[start],
            beta,
            online_prefix[end] - online_prefix[start],
            compromise_prefix[end] - compromise_prefix[start],
            lower,
            upper,
        )

    maximum_cost = max(1.0, math.fsum(online))
    if memory_multipliers is None:
        scale = maximum_cost / max(1.0, memory_budget)
        memory_multipliers = (0.0,) + tuple(scale * 2.0**exponent for exponent in range(-4, 5))
    if compromise_multipliers is None:
        scale = maximum_cost / max(1.0, math.fsum(compromise), work_factor_floor)
        compromise_multipliers = (0.0,) + tuple(scale * 2.0**exponent for exponent in range(-4, 5))
    if region_count_penalties is None:
        scale = maximum_cost / max(1, maximum_regions)
        region_count_penalties = (0.0,) + tuple(scale * 2.0**exponent for exponent in range(-4, 5))
    axes = tuple(
        tuple(float(item) for item in axis)
        for axis in (
            memory_multipliers,
            compromise_multipliers,
            region_count_penalties,
        )
    )
    if any(not axis for axis in axes):
        raise ValueError("continuous dual multiplier axes must be nonempty")
    if any(value < 0.0 or not math.isfinite(value) for axis in axes for value in axis):
        raise ValueError("continuous dual multipliers must be finite and nonnegative")

    solved_partitions: dict[tuple[tuple[int, int], ...], FixedPartitionSolution | None] = {}
    candidate_by_partition: dict[tuple[tuple[int, int], ...], ContinuousPartitionCandidate] = {}
    best_dual: ContinuousPartitionCandidate | None = None
    evaluated = 0

    def solve_partition(
        partition: tuple[tuple[int, int], ...],
    ) -> FixedPartitionSolution | None:
        if partition in solved_partitions:
            return solved_partitions[partition]
        problem = FixedPartitionProblem(
            member_occupancy=[parameters[interval][0] for interval in partition],
            beta=[parameters[interval][1] for interval in partition],
            online_weights=[parameters[interval][2] for interval in partition],
            compromise_weights=[parameters[interval][3] for interval in partition],
            memory_budget=memory_budget,
            work_factor_floor=work_factor_floor,
            epsilon_min=[parameters[interval][4] for interval in partition],
            epsilon_cap=[parameters[interval][5] for interval in partition],
        )
        try:
            solution = solve_fixed_partition(problem)
        except InfeasibleProblem:
            solution = None
        solved_partitions[partition] = solution
        return solution

    for memory_multiplier, compromise_multiplier, region_penalty in itertools.product(*axes):
        evaluated += 1
        best_prefix: dict[
            int, tuple[float, float, tuple[tuple[int, int], ...], tuple[float, ...]]
        ] = {0: (0.0, 0.0, (), ())}
        for end in range(1, n_bins + 1):
            choices: list[tuple[float, float, tuple[tuple[int, int], ...], tuple[float, ...]]] = []
            for start in range(end):
                previous = best_prefix.get(start)
                if previous is None:
                    continue
                interval = (start, end)
                n_value, beta, w_value, d_value, lower, upper = parameters[interval]
                value, selected_epsilon = _continuous_interval_value(
                    member_occupancy=n_value,
                    beta=beta,
                    online_weight=w_value,
                    compromise_weight=d_value,
                    epsilon_min=lower,
                    epsilon_cap=upper,
                    memory_multiplier=memory_multiplier,
                    compromise_multiplier=compromise_multiplier,
                    region_count_penalty=region_penalty,
                )
                choices.append(
                    (
                        previous[0] + value,
                        previous[1] + abs(value),
                        previous[2] + (interval,),
                        previous[3] + (selected_epsilon,),
                    )
                )
            best_prefix[end] = min(choices, key=lambda item: (item[0], item[2]))

        reduced_cost, absolute_sum, partition, selected_epsilon = best_prefix[n_bins]
        memory_constant = memory_multiplier * memory_budget
        compromise_constant = compromise_multiplier * work_factor_floor
        region_constant = region_penalty * maximum_regions
        raw_dual = reduced_cost - memory_constant + compromise_constant - region_constant
        allowance = (
            256
            * sys.float_info.epsilon
            * (len(partition) + 3)
            * (
                absolute_sum
                + abs(memory_constant)
                + abs(compromise_constant)
                + abs(region_constant)
                + abs(raw_dual)
                + 1.0
            )
        )
        candidate = ContinuousPartitionCandidate(
            partition=partition,
            memory_multiplier=memory_multiplier,
            compromise_multiplier=compromise_multiplier,
            region_count_penalty=region_penalty,
            lagrangian_epsilon=selected_epsilon,
            raw_dual_value=raw_dual,
            conservative_dual_lower_bound=raw_dual - allowance,
            fixed_partition_solution=solve_partition(partition),
            region_feasible=len(partition) <= maximum_regions,
        )
        if best_dual is None or candidate.conservative_dual_lower_bound > (
            best_dual.conservative_dual_lower_bound
        ):
            best_dual = candidate
        incumbent = candidate_by_partition.get(partition)
        if incumbent is None or candidate.conservative_dual_lower_bound > (
            incumbent.conservative_dual_lower_bound
        ):
            candidate_by_partition[partition] = candidate

    assert best_dual is not None
    candidates = tuple(
        replace(
            candidate_by_partition[key],
            certified_absolute_gap_to_best_dual=(
                max(
                    0.0,
                    float(candidate_by_partition[key].primal_objective)
                    - best_dual.conservative_dual_lower_bound,
                )
                if candidate_by_partition[key].primal_objective is not None
                else None
            ),
            certified_relative_gap_to_best_dual=(
                _relative_certificate_gap(
                    max(
                        0.0,
                        float(candidate_by_partition[key].primal_objective)
                        - best_dual.conservative_dual_lower_bound,
                    ),
                    float(candidate_by_partition[key].primal_objective),
                )
                if candidate_by_partition[key].primal_objective is not None
                else None
            ),
        )
        for key in sorted(candidate_by_partition)
    )
    feasible = [candidate for candidate in candidates if candidate.primal_feasible]
    feasible_candidate = min(
        feasible,
        key=lambda candidate: (
            float(candidate.primal_objective),
            len(candidate.partition),
            candidate.partition,
        ),
        default=None,
    )
    upper_bound = feasible_candidate.primal_objective if feasible_candidate is not None else None
    absolute_gap = (
        max(0.0, upper_bound - best_dual.conservative_dual_lower_bound)
        if upper_bound is not None
        else None
    )
    relative_gap = _relative_certificate_gap(absolute_gap, upper_bound)
    return ContinuousPartitionDualCertificate(
        candidates=candidates,
        evaluated_multiplier_triples=evaluated,
        distinct_partitions_resolved=len(solved_partitions),
        dual_lower_bound=best_dual.conservative_dual_lower_bound,
        best_memory_multiplier=best_dual.memory_multiplier,
        best_compromise_multiplier=best_dual.compromise_multiplier,
        best_region_count_penalty=best_dual.region_count_penalty,
        feasible_candidate=feasible_candidate,
        candidate_upper_bound=upper_bound,
        certified_absolute_gap=absolute_gap,
        certified_relative_gap=relative_gap,
        relative_gap_denominator=RELATIVE_GAP_DENOMINATOR,
    )


def _same_physical_option(coarse: IntervalOption, fine: IntervalOption) -> bool:
    return (
        coarse.start_bin == fine.start_bin
        and coarse.end_bin == fine.end_bin
        and coarse.cache_quota == fine.cache_quota
        and coarse.cache_policy == fine.cache_policy
        and coarse.memory_bytes == fine.memory_bytes
        and math.isclose(coarse.compromise_mass, fine.compromise_mass, rel_tol=1e-12, abs_tol=1e-12)
        and math.isclose(
            coarse.worst_region_epsilon,
            fine.worst_region_epsilon,
            rel_tol=1e-12,
            abs_tol=1e-12,
        )
        and math.isclose(coarse.online_cost, fine.online_cost, rel_tol=1e-12, abs_tol=1e-12)
        and coarse.seeded_costs == fine.seeded_costs
    )


def _grid_key(option: IntervalOption) -> tuple[int, int, int, int, str]:
    return (
        option.start_bin,
        option.end_bin,
        option.positive_memory_quanta,
        option.cache_quota,
        option.cache_policy,
    )


def _validate_complete_grid(options: Sequence[IntervalOption], spec: OptionGridSpec) -> None:
    expected_keys = {
        (start, end, positive, cache, policy)
        for (start, end), positive, cache, policy in itertools.product(
            spec.intervals,
            spec.positive_memory_choices,
            spec.cache_quota_choices,
            spec.cache_policies,
        )
    }
    actual: dict[tuple[int, int, int, int, str], IntervalOption] = {}
    screening_values: dict[tuple[int, int, int], tuple[int, float, float]] = {}
    for option in options:
        key = _grid_key(option)
        if key in actual:
            raise ValueError("option table contains a duplicate Cartesian-grid point")
        actual[key] = option
        expected_bytes = (
            option.positive_memory_quanta * spec.positive_quantum_bytes
            + option.cache_quota * spec.cache_entry_bytes
        )
        expected_memory = int(math.ceil(expected_bytes / spec.resource_quantum_bytes))
        expected_compromise = int(
            math.floor(option.compromise_mass / spec.compromise_quantum + 1e-12)
        )
        if option.memory_bytes != expected_bytes or option.memory_quanta != expected_memory:
            raise ValueError("option memory does not match its declared Cartesian grid")
        if option.compromise_quanta != expected_compromise:
            raise ValueError("option compromise does not match its declared Cartesian grid")
        screen_key = (
            option.start_bin,
            option.end_bin,
            option.positive_memory_quanta,
        )
        screen_value = (
            option.compromise_quanta,
            option.compromise_mass,
            option.worst_region_epsilon,
        )
        previous = screening_values.setdefault(screen_key, screen_value)
        if previous != screen_value:
            raise ValueError("cache axes illegally change the positive-filter design")
    actual_keys = set(actual)
    if actual_keys != expected_keys:
        missing = len(expected_keys - actual_keys)
        extra = len(actual_keys - expected_keys)
        raise ValueError(
            f"option table is not the complete declared Cartesian grid "
            f"(missing={missing}, extra={extra})"
        )


def _validate_grid_refinement(
    coarse: OptionGridSpec, fine: OptionGridSpec, resource_scale: int
) -> None:
    def require_complete_subdivision(
        coarse_values: set[int], fine_values: set[int], *, name: str
    ) -> None:
        ordered = sorted(coarse_values)
        if len(ordered) == 1:
            if fine_values != coarse_values:
                raise ValueError(f"fine {name} axis changes a singleton coarse axis")
            return
        expected = set(ordered)
        for left, right in zip(ordered, ordered[1:], strict=False):
            for step in range(1, resource_scale):
                numerator = (resource_scale - step) * left + step * right
                if numerator % resource_scale:
                    raise ValueError(
                        f"coarse {name} axis cannot be subdivided into physical "
                        f"1/{resource_scale} steps"
                    )
                expected.add(numerator // resource_scale)
        if fine_values != expected:
            missing = sorted(expected - fine_values)
            extra = sorted(fine_values - expected)
            raise ValueError(
                f"fine {name} axis is not the complete physical "
                f"1/{resource_scale}-step refinement "
                f"(missing={missing}, extra={extra})"
            )

    if coarse.intervals != fine.intervals:
        raise ValueError("coarse and fine grids must declare identical intervals")
    if coarse.cache_policies != fine.cache_policies:
        raise ValueError("coarse and fine grids must declare identical cache policies")
    if coarse.cache_entry_bytes != fine.cache_entry_bytes:
        raise ValueError("cache entry bytes must remain physically fixed")
    if coarse.positive_quantum_bytes != resource_scale * fine.positive_quantum_bytes:
        raise ValueError("fine positive-memory quantum is not the scaled coarse quantum")
    if coarse.resource_quantum_bytes != resource_scale * fine.resource_quantum_bytes:
        raise ValueError("fine resource quantum is not the scaled coarse quantum")
    if not math.isclose(
        coarse.compromise_quantum,
        resource_scale * fine.compromise_quantum,
        rel_tol=1e-12,
        abs_tol=1e-12,
    ):
        raise ValueError("fine compromise quantum is not the scaled coarse quantum")
    coarse_positive_bytes = {
        choice * coarse.positive_quantum_bytes for choice in coarse.positive_memory_choices
    }
    fine_positive_bytes = {
        choice * fine.positive_quantum_bytes for choice in fine.positive_memory_choices
    }
    require_complete_subdivision(
        coarse_positive_bytes,
        fine_positive_bytes,
        name="positive-memory-byte",
    )
    require_complete_subdivision(
        {choice * coarse.cache_entry_bytes for choice in coarse.cache_quota_choices},
        {choice * fine.cache_entry_bytes for choice in fine.cache_quota_choices},
        name="negative-cache-byte",
    )


def _validate_physical_grid_refinement(
    coarse: PhysicalResolutionGrid,
    fine: PhysicalResolutionGrid,
) -> None:
    def require_midpoints(
        coarse_values: tuple[int, ...],
        fine_values: tuple[int, ...],
        *,
        axis_name: str,
    ) -> None:
        if len(coarse_values) == 1:
            if fine_values != coarse_values:
                raise ValueError(f"fine {axis_name} axis changes a singleton coarse axis")
            return
        expected = set(coarse_values)
        for left, right in zip(coarse_values, coarse_values[1:], strict=False):
            if (left + right) % 2:
                raise ValueError(
                    f"coarse {axis_name} axis has a non-integral doubling midpoint "
                    f"between {left} and {right}"
                )
            expected.add((left + right) // 2)
        actual = set(fine_values)
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise ValueError(
                f"fine {axis_name} axis is not the complete midpoint refinement "
                f"(missing={missing}, extra={extra})"
            )

    if coarse.intervals != fine.intervals:
        raise ValueError("coarse and fine physical grids must declare identical intervals")
    if coarse.positive_cache_policies != fine.positive_cache_policies:
        raise ValueError(
            "coarse and fine physical grids must declare identical positive cache policies"
        )
    if coarse.resource_quantum_bytes != 2 * fine.resource_quantum_bytes:
        raise ValueError("fine resource quantum is not half the coarse resource quantum")
    if coarse.compromise_quantum != 2 * fine.compromise_quantum:
        raise ValueError("fine compromise quantum is not half the coarse compromise quantum")
    require_midpoints(
        coarse.filter_memory_bytes_choices,
        fine.filter_memory_bytes_choices,
        axis_name="filter-byte",
    )
    require_midpoints(
        coarse.cache_capacity_choices,
        fine.cache_capacity_choices,
        axis_name="cache-slot",
    )


def _exact_float(left: float, right: float) -> bool:
    return left == right or (math.isnan(left) and math.isnan(right))


def _same_exact_physical_resolution_option(
    coarse: PhysicalResolutionOption,
    fine: PhysicalResolutionOption,
) -> bool:
    """Compare the physical point while excluding resolution-dependent quanta."""

    return (
        coarse.coordinate == fine.coordinate
        and coarse.option.memory_bytes == fine.option.memory_bytes
        and coarse.option.compromise_mass == fine.option.compromise_mass
        and coarse.option.worst_region_epsilon == fine.option.worst_region_epsilon
        and coarse.option.online_cost == fine.option.online_cost
        and _exact_float(
            coarse.option.cost_standard_error,
            fine.option.cost_standard_error,
        )
        and coarse.option.seeded_costs == fine.option.seeded_costs
    )


def _requantize_physical_option_table(
    options: Sequence[PhysicalResolutionOption],
    grid: PhysicalResolutionGrid,
    *,
    declared_memory_bytes: Callable[[int, int, str], int],
) -> tuple[
    tuple[IntervalOption, ...],
    dict[int, tuple[int, int, int, int, str]],
    dict[tuple[int, int, int, int, str], PhysicalResolutionOption],
]:
    expected = set(grid.expected_coordinates)
    actual: dict[tuple[int, int, int, int, str], PhysicalResolutionOption] = {}
    quantized: list[IntervalOption] = []
    coordinates_by_id: dict[int, tuple[int, int, int, int, str]] = {}
    screening_values: dict[tuple[int, int, int], tuple[float, float]] = {}

    if any(type(item) is not PhysicalResolutionOption for item in options):
        raise TypeError("physical option tables must contain PhysicalResolutionOption values")
    for physical_option in sorted(options, key=lambda item: item.coordinate):
        coordinate = physical_option.coordinate
        if coordinate in actual:
            raise ValueError("physical option table contains a duplicate coordinate")
        _, _, filter_bytes, capacity, policy = coordinate
        if capacity == 0 and policy != "none":
            raise ValueError("cache capacity 0 permits only the none policy")
        if capacity > 0 and policy == "none":
            raise ValueError("positive cache capacity cannot use the none policy")
        if capacity > 0 and policy not in grid.positive_cache_policies:
            raise ValueError("positive cache capacity uses an undeclared positive policy")

        accounted_bytes = declared_memory_bytes(filter_bytes, capacity, policy)
        if type(accounted_bytes) is not int or accounted_bytes < 0:
            raise ValueError(
                "physical memory accounting must return a nonnegative integer byte count"
            )
        option = physical_option.option
        if option.memory_bytes != accounted_bytes:
            raise ValueError(
                "option memory_bytes does not match caller-declared physical memory accounting"
            )
        if (
            type(option.compromise_mass) not in {int, float}
            or option.compromise_mass < 0
            or not math.isfinite(option.compromise_mass)
        ):
            raise ValueError("option compromise_mass must be finite and nonnegative")

        screen_key = (option.start_bin, option.end_bin, filter_bytes)
        screen_value = (option.compromise_mass, option.worst_region_epsilon)
        previous = screening_values.setdefault(screen_key, screen_value)
        if previous != screen_value:
            raise ValueError("cache decisions illegally change the physical filter design")

        requantized = replace(
            option,
            positive_memory_quanta=(filter_bytes + grid.resource_quantum_bytes - 1)
            // grid.resource_quantum_bytes,
            memory_quanta=(accounted_bytes + grid.resource_quantum_bytes - 1)
            // grid.resource_quantum_bytes,
            compromise_quanta=int(
                Fraction(option.compromise_mass) // Fraction(grid.compromise_quantum)
            ),
        )
        actual[coordinate] = physical_option
        quantized.append(requantized)
        coordinates_by_id[id(requantized)] = coordinate

    actual_coordinates = set(actual)
    if actual_coordinates != expected:
        missing = len(expected - actual_coordinates)
        extra = len(actual_coordinates - expected)
        raise ValueError(
            "physical option table is not the complete declared semantic grid "
            f"(missing={missing}, extra={extra})"
        )
    return tuple(quantized), coordinates_by_id, actual


def validate_physical_resolution_doubling(
    coarse_options: Iterable[PhysicalResolutionOption],
    fine_options: Iterable[PhysicalResolutionOption],
    *,
    n_bins: int,
    coarse_grid: PhysicalResolutionGrid,
    fine_grid: PhysicalResolutionGrid,
    physical_memory_bytes: Callable[[int, int, str], int],
    coarse_memory_budget_quanta: int,
    fine_memory_budget_quanta: int,
    coarse_minimum_compromise_quanta: int,
    fine_minimum_compromise_quanta: int,
    maximum_regions: int,
    resource_scale: int = 2,
    worst_region_epsilon_cap: float = 1.0,
    relative_threshold: float = 0.01,
) -> PhysicalResolutionDoublingResult:
    """Validate exact doubling over physical filter-byte and cache-slot axes.

    The caller supplies the real physical byte-accounting function.  Input
    resource fields are deliberately re-quantized for each grid before the two
    exact DP solves, so stale or shared coarse/fine quanta cannot affect the
    check.
    """

    if type(resource_scale) is not int or resource_scale != 2:
        raise ValueError("formal resolution doubling fixes resource_scale at 2")
    if type(relative_threshold) not in {int, float} or relative_threshold != 0.01:
        raise ValueError("formal resolution doubling fixes relative_threshold at 0.01")
    if not callable(physical_memory_bytes):
        raise TypeError("physical_memory_bytes must be callable")
    for name, value, minimum in (
        ("n_bins", n_bins, 1),
        ("coarse_memory_budget_quanta", coarse_memory_budget_quanta, 0),
        ("fine_memory_budget_quanta", fine_memory_budget_quanta, 0),
        (
            "coarse_minimum_compromise_quanta",
            coarse_minimum_compromise_quanta,
            0,
        ),
        ("fine_minimum_compromise_quanta", fine_minimum_compromise_quanta, 0),
        ("maximum_regions", maximum_regions, 1),
    ):
        if type(value) is not int or value < minimum:
            raise ValueError(f"{name} must be an integer greater than or equal to {minimum}")
    if (
        type(worst_region_epsilon_cap) not in {int, float}
        or not math.isfinite(worst_region_epsilon_cap)
        or not 0 <= worst_region_epsilon_cap <= 1
    ):
        raise ValueError("worst_region_epsilon_cap must lie in [0, 1]")
    _validate_physical_grid_refinement(coarse_grid, fine_grid)
    if fine_memory_budget_quanta != 2 * coarse_memory_budget_quanta:
        raise ValueError("fine memory budget is not twice the coarse quantum budget")
    if fine_minimum_compromise_quanta != 2 * coarse_minimum_compromise_quanta:
        raise ValueError("fine compromise floor is not twice the coarse quantum floor")

    accounting_cache: dict[tuple[int, int, str], int] = {}

    def declared_memory_bytes(filter_bytes: int, capacity: int, policy: str) -> int:
        coordinate = (filter_bytes, capacity, policy)
        if coordinate not in accounting_cache:
            accounting_cache[coordinate] = physical_memory_bytes(*coordinate)
        return accounting_cache[coordinate]

    coarse_input = tuple(coarse_options)
    fine_input = tuple(fine_options)
    coarse, coarse_coordinates_by_id, coarse_by_coordinate = _requantize_physical_option_table(
        coarse_input,
        coarse_grid,
        declared_memory_bytes=declared_memory_bytes,
    )
    fine, fine_coordinates_by_id, fine_by_coordinate = _requantize_physical_option_table(
        fine_input,
        fine_grid,
        declared_memory_bytes=declared_memory_bytes,
    )

    non_nested = [
        coordinate
        for coordinate, coarse_option in coarse_by_coordinate.items()
        if coordinate not in fine_by_coordinate
        or not _same_exact_physical_resolution_option(
            coarse_option,
            fine_by_coordinate[coordinate],
        )
    ]
    if non_nested:
        raise ValueError(
            f"coarse physical points are not exactly nested in the fine table: {sorted(non_nested)}"
        )

    coarse_solution = solve_exact_discretized_joint_dp(
        coarse,
        n_bins=n_bins,
        memory_budget_quanta=coarse_memory_budget_quanta,
        minimum_compromise_quanta=coarse_minimum_compromise_quanta,
        maximum_regions=maximum_regions,
        worst_region_epsilon_cap=worst_region_epsilon_cap,
    )
    fine_solution = solve_exact_discretized_joint_dp(
        fine,
        n_bins=n_bins,
        memory_budget_quanta=fine_memory_budget_quanta,
        minimum_compromise_quanta=fine_minimum_compromise_quanta,
        maximum_regions=maximum_regions,
        worst_region_epsilon_cap=worst_region_epsilon_cap,
    )
    if not math.isfinite(coarse_solution.online_cost) or not math.isfinite(
        fine_solution.online_cost
    ):
        raise ArithmeticError("physical resolution aggregate objective is not finite")
    monotonicity_allowance = (
        128
        * sys.float_info.epsilon
        * (len(coarse_solution.options) + len(fine_solution.options) + 1)
        * (abs(coarse_solution.online_cost) + abs(fine_solution.online_cost) + 1.0)
    )
    if fine_solution.online_cost > coarse_solution.online_cost + monotonicity_allowance:
        raise ArithmeticError(
            "fine physical grid objective exceeds its nested coarse-grid objective"
        )
    objective_improvement = max(
        0.0,
        coarse_solution.online_cost - fine_solution.online_cost,
    )
    if fine_solution.online_cost == 0:
        relative_change = 0.0 if objective_improvement == 0 else math.inf
    else:
        relative_change = objective_improvement / fine_solution.online_cost
    return PhysicalResolutionDoublingResult(
        coarse_solution=coarse_solution,
        fine_solution=fine_solution,
        relative_objective_change=relative_change,
        threshold=relative_threshold,
        resource_scale=resource_scale,
        coarse_resource_quantum_bytes=coarse_grid.resource_quantum_bytes,
        fine_resource_quantum_bytes=fine_grid.resource_quantum_bytes,
        coarse_compromise_quantum=coarse_grid.compromise_quantum,
        fine_compromise_quantum=fine_grid.compromise_quantum,
        coarse_option_count=len(coarse),
        fine_option_count=len(fine),
        coarse_options_nested_in_fine=True,
        coarse_selected_physical_coordinates=tuple(
            coarse_coordinates_by_id[id(option)] for option in coarse_solution.options
        ),
        fine_selected_physical_coordinates=tuple(
            fine_coordinates_by_id[id(option)] for option in fine_solution.options
        ),
    )


def validate_resolution_doubling(
    coarse_options: Iterable[IntervalOption],
    fine_options: Iterable[IntervalOption],
    *,
    n_bins: int,
    coarse_grid: OptionGridSpec,
    fine_grid: OptionGridSpec,
    coarse_memory_budget_quanta: int,
    fine_memory_budget_quanta: int,
    coarse_minimum_compromise_quanta: int,
    fine_minimum_compromise_quanta: int,
    maximum_regions: int,
    resource_scale: int = 2,
    worst_region_epsilon_cap: float = 1.0,
    relative_threshold: float = 0.01,
) -> ResolutionDoublingResult:
    """Apply the fixed formal twice-resolution, one-percent validation gate."""

    if type(resource_scale) is not int or resource_scale != 2:
        raise ValueError("formal resolution doubling fixes resource_scale at 2")
    if type(relative_threshold) not in {int, float} or relative_threshold != 0.01:
        raise ValueError("formal resolution doubling fixes relative_threshold at 0.01")
    _validate_grid_refinement(coarse_grid, fine_grid, resource_scale)
    if fine_memory_budget_quanta != resource_scale * coarse_memory_budget_quanta:
        raise ValueError("fine memory budget is not the scaled coarse budget")
    if fine_minimum_compromise_quanta != resource_scale * coarse_minimum_compromise_quanta:
        raise ValueError("fine compromise floor is not the scaled coarse floor")
    coarse = tuple(coarse_options)
    fine = tuple(fine_options)
    _validate_complete_grid(coarse, coarse_grid)
    _validate_complete_grid(fine, fine_grid)
    nested = all(
        any(_same_physical_option(coarse_option, fine_option) for fine_option in fine)
        for coarse_option in coarse
    )
    coarse_solution = solve_exact_discretized_joint_dp(
        coarse,
        n_bins=n_bins,
        memory_budget_quanta=coarse_memory_budget_quanta,
        minimum_compromise_quanta=coarse_minimum_compromise_quanta,
        maximum_regions=maximum_regions,
        worst_region_epsilon_cap=worst_region_epsilon_cap,
    )
    fine_solution = solve_exact_discretized_joint_dp(
        fine,
        n_bins=n_bins,
        memory_budget_quanta=fine_memory_budget_quanta,
        minimum_compromise_quanta=fine_minimum_compromise_quanta,
        maximum_regions=maximum_regions,
        worst_region_epsilon_cap=worst_region_epsilon_cap,
    )
    if fine_solution.online_cost == 0:
        relative_change = 0.0 if coarse_solution.online_cost == 0 else math.inf
    else:
        relative_change = abs(coarse_solution.online_cost - fine_solution.online_cost) / abs(
            fine_solution.online_cost
        )
    return ResolutionDoublingResult(
        coarse_solution=coarse_solution,
        fine_solution=fine_solution,
        relative_objective_change=relative_change,
        threshold=relative_threshold,
        resource_scale=resource_scale,
        coarse_resource_quantum_bytes=coarse_grid.resource_quantum_bytes,
        fine_resource_quantum_bytes=fine_grid.resource_quantum_bytes,
        coarse_compromise_quantum=coarse_grid.compromise_quantum,
        fine_compromise_quantum=fine_grid.compromise_quantum,
        coarse_option_count=len(coarse),
        fine_option_count=len(fine),
        coarse_options_nested_in_fine=nested,
    )


def _solution_from_fixed_design(
    selected_design: Sequence[IntervalOption],
    all_options: Sequence[IntervalOption],
    *,
    memory_budget_quanta: int,
    minimum_compromise_quanta: int,
    worst_region_epsilon_cap: float,
) -> JointDPSolution:
    labels: list[_Label] = [_Label(0, 0, 0, 0, 0.0, (), ())]
    generated = 1
    pruned = 0
    maximum_frontier = 1
    for position, design in enumerate(selected_design):
        candidates = [
            option
            for option in all_options
            if option.start_bin == design.start_bin
            and option.end_bin == design.end_bin
            and option.positive_memory_quanta == design.positive_memory_quanta
            and option.compromise_quanta == design.compromise_quanta
            and math.isclose(
                option.compromise_mass,
                design.compromise_mass,
                rel_tol=1e-12,
                abs_tol=1e-12,
            )
            and math.isclose(
                option.worst_region_epsilon,
                design.worst_region_epsilon,
                rel_tol=1e-12,
                abs_tol=1e-12,
            )
            and option.worst_region_epsilon <= worst_region_epsilon_cap
        ]
        if not candidates:
            raise ValueError("two-stage cache allocation has no matching interval option")
        expanded: list[_Label] = []
        for label in labels:
            for option in candidates:
                memory = label.memory_quanta + option.memory_quanta
                if memory > memory_budget_quanta:
                    continue
                compromise = min(
                    minimum_compromise_quanta,
                    label.compromise_quanta + option.compromise_quanta,
                )
                if label.seeded_costs == ():
                    seeded_costs = option.seeded_costs or None
                elif (
                    label.seeded_costs is not None
                    and option.seeded_costs
                    and len(label.seeded_costs) == len(option.seeded_costs)
                ):
                    seeded_costs = tuple(
                        left + right
                        for left, right in zip(label.seeded_costs, option.seeded_costs, strict=True)
                    )
                else:
                    seeded_costs = None
                online_cost = label.online_cost + option.online_cost
                if not math.isfinite(online_cost) or (
                    seeded_costs is not None
                    and any(not math.isfinite(value) for value in seeded_costs)
                ):
                    raise ArithmeticError("discretized aggregate objective is not finite")
                expanded.append(
                    _Label(
                        prefix_bin=option.end_bin,
                        regions_used=position + 1,
                        memory_quanta=memory,
                        compromise_quanta=compromise,
                        online_cost=online_cost,
                        seeded_costs=seeded_costs,
                        options=label.options + (option,),
                    )
                )
                generated += 1
        labels, removed = _pareto_prune(expanded)
        pruned += removed
        maximum_frontier = max(maximum_frontier, len(labels))
    feasible = [label for label in labels if label.compromise_quanta >= minimum_compromise_quanta]
    if not feasible:
        raise ValueError("two-stage cache allocation has no feasible completion")
    best = min(
        feasible,
        key=lambda label: (
            label.online_cost,
            label.memory_quanta,
            tuple(
                (
                    option.start_bin,
                    option.end_bin,
                    option.positive_memory_quanta,
                    option.cache_quota,
                    option.cache_policy,
                )
                for option in label.options
            ),
        ),
    )
    standard_error = (
        statistics.stdev(best.seeded_costs) / math.sqrt(len(best.seeded_costs))
        if best.seeded_costs is not None and len(best.seeded_costs) >= 2
        else math.nan
    )
    return JointDPSolution(
        options=best.options,
        online_cost=best.online_cost,
        cost_standard_error=standard_error,
        memory_quanta=best.memory_quanta,
        compromise_quanta=sum(option.compromise_quanta for option in best.options),
        regions_used=len(best.options),
        statistics=DPStatistics(generated, pruned, maximum_frontier, len(feasible)),
    )


def _screen_design_key(
    options: Sequence[IntervalOption],
) -> tuple[tuple[int, int, int, int, float, float], ...]:
    return tuple(
        (
            option.start_bin,
            option.end_bin,
            option.positive_memory_quanta,
            option.compromise_quanta,
            option.compromise_mass,
            option.worst_region_epsilon,
        )
        for option in options
    )


def _solution_for_selected_options(
    options: Sequence[IntervalOption], dp_statistics: DPStatistics
) -> JointDPSolution:
    seeded_costs: tuple[float, ...] | None = ()
    for option in options:
        if seeded_costs == ():
            seeded_costs = option.seeded_costs or None
        elif (
            seeded_costs is not None
            and option.seeded_costs
            and len(seeded_costs) == len(option.seeded_costs)
        ):
            seeded_costs = tuple(
                left + right for left, right in zip(seeded_costs, option.seeded_costs, strict=True)
            )
        else:
            seeded_costs = None
    standard_error = (
        statistics.stdev(seeded_costs) / math.sqrt(len(seeded_costs))
        if seeded_costs is not None and len(seeded_costs) >= 2
        else math.nan
    )
    return JointDPSolution(
        options=tuple(options),
        online_cost=sum(option.online_cost for option in options),
        cost_standard_error=standard_error,
        memory_quanta=sum(option.memory_quanta for option in options),
        compromise_quanta=sum(option.compromise_quanta for option in options),
        regions_used=len(options),
        statistics=dp_statistics,
    )


def _solve_tie_aware_two_stage(
    screen_options: Sequence[IntervalOption],
    all_options: Sequence[IntervalOption],
    *,
    n_bins: int,
    memory_budget_quanta: int,
    minimum_compromise_quanta: int,
    maximum_regions: int,
    worst_region_epsilon_cap: float,
) -> tuple[
    tuple[tuple[JointDPSolution, JointDPSolution, int], ...],
    DPStatistics,
]:
    """Enumerate every strictly stage-one-optimal screen design.

    Stage one minimizes the no-cache objective independently for each integer
    positive-memory budget.  A tie means exact equality of the stored binary64
    objective, not proximity under a tolerance.  Cache cost is never consulted
    to select a stage-one design.  All exactly tied paths are retained and then
    solved independently by the second-stage cache allocator.
    """

    by_start: dict[int, list[IntervalOption]] = defaultdict(list)
    for option in screen_options:
        if option.end_bin <= n_bins and option.worst_region_epsilon <= worst_region_epsilon_cap:
            by_start[option.start_bin].append(option)
    for choices in by_start.values():
        choices.sort(key=_grid_key)

    state_values: dict[
        tuple[int, int, int, int],
        tuple[
            float,
            dict[tuple[tuple[int, int, int, int, float, float], ...], tuple[IntervalOption, ...]],
        ],
    ] = {(0, 0, 0, 0): (0.0, {(): ()})}
    generated = 1
    pruned = 0
    maximum_frontier = 1
    for prefix in range(n_bins):
        for regions in range(maximum_regions):
            current = [
                (state, value)
                for state, value in state_values.items()
                if state[0] == prefix and state[1] == regions
            ]
            for (
                _,
                _,
                screen_memory_used,
                compromise_used,
            ), (screen_cost, screen_paths) in current:
                for screen in by_start.get(prefix, ()):
                    screen_memory = screen_memory_used + screen.memory_quanta
                    if screen_memory > memory_budget_quanta:
                        continue
                    compromise = min(
                        minimum_compromise_quanta,
                        compromise_used + screen.compromise_quanta,
                    )
                    target = (
                        screen.end_bin,
                        regions + 1,
                        screen_memory,
                        compromise,
                    )
                    candidate_cost = screen_cost + screen.online_cost
                    candidate_paths = {
                        _screen_design_key(path + (screen,)): path + (screen,)
                        for path in screen_paths.values()
                    }
                    generated += len(candidate_paths)
                    incumbent = state_values.get(target)
                    if incumbent is None or candidate_cost < incumbent[0]:
                        if incumbent is not None:
                            pruned += len(incumbent[1])
                        state_values[target] = (candidate_cost, candidate_paths)
                    elif candidate_cost == incumbent[0]:
                        merged = dict(incumbent[1])
                        before = len(merged)
                        merged.update(candidate_paths)
                        pruned += len(candidate_paths) - (len(merged) - before)
                        state_values[target] = (incumbent[0], merged)
                    else:
                        pruned += len(candidate_paths)
            maximum_frontier = max(maximum_frontier, len(state_values))

    finals = [
        (state, value)
        for state, value in state_values.items()
        if state[0] == n_bins and state[3] >= minimum_compromise_quanta
    ]
    selected: dict[
        tuple[tuple[int, int, int, int, float, float], ...],
        tuple[JointDPSolution, JointDPSolution, int],
    ] = {}
    statistics = DPStatistics(
        generated_labels=generated,
        pruned_labels=pruned,
        maximum_frontier_size=maximum_frontier,
        final_feasible_labels=sum(len(value[1]) for _, value in finals),
    )
    for budget in range(memory_budget_quanta + 1):
        eligible = [entry for entry in finals if entry[0][2] <= budget]
        if not eligible:
            continue
        best_stage_one_cost = min(entry[1][0] for entry in eligible)
        tied_paths = (
            path
            for _, (cost, paths) in eligible
            if cost == best_stage_one_cost
            for path in paths.values()
        )
        for screen_path in tied_paths:
            design_key = _screen_design_key(screen_path)
            if design_key in selected:
                continue
            final = _solution_from_fixed_design(
                screen_path,
                all_options,
                memory_budget_quanta=memory_budget_quanta,
                minimum_compromise_quanta=minimum_compromise_quanta,
                worst_region_epsilon_cap=worst_region_epsilon_cap,
            )
            selected[design_key] = (
                final,
                _solution_for_selected_options(screen_path, statistics),
                budget,
            )
    return tuple(selected.values()), statistics


def solve_strong_two_stage_baseline(
    options: Iterable[IntervalOption],
    *,
    n_bins: int,
    memory_budget_quanta: int,
    minimum_compromise_quanta: int,
    maximum_regions: int,
    worst_region_epsilon_cap: float = 1.0,
) -> TwoStageBaselineResult:
    """Optimize positive design first, then cache allocation for that fixed design."""

    all_options = tuple(options)
    no_cache_by_design: dict[tuple[int, int, int, int, float, float], IntervalOption] = {}
    for option in all_options:
        if option.cache_quota != 0:
            continue
        key = _screen_design_key((option,))[0]
        incumbent = no_cache_by_design.get(key)
        if incumbent is None or (option.online_cost, option.cache_policy) < (
            incumbent.online_cost,
            incumbent.cache_policy,
        ):
            no_cache_by_design[key] = option
    if not no_cache_by_design:
        raise ValueError("two-stage baseline requires cache_quota=0 options")

    evaluated: dict[
        tuple[tuple[int, int, int, int, float, float], ...],
        tuple[JointDPSolution, JointDPSolution, int],
    ] = {}
    stage_one_designs, _ = _solve_tie_aware_two_stage(
        tuple(no_cache_by_design.values()),
        all_options,
        n_bins=n_bins,
        memory_budget_quanta=memory_budget_quanta,
        minimum_compromise_quanta=minimum_compromise_quanta,
        maximum_regions=maximum_regions,
        worst_region_epsilon_cap=worst_region_epsilon_cap,
    )
    for final, stage_one, positive_budget in stage_one_designs:
        design_key = _screen_design_key(stage_one.options)
        evaluated[design_key] = (final, stage_one, positive_budget)
    if not evaluated:
        raise ValueError("two-stage baseline has no feasible positive/cache design")
    final, stage_one, positive_budget = min(
        evaluated.values(),
        key=lambda candidate: (
            candidate[0].online_cost,
            candidate[0].memory_quanta,
            candidate[2],
        ),
    )
    return TwoStageBaselineResult(
        solution=final,
        stage_one_solution=stage_one,
        stage_one_memory_budget_quanta=positive_budget,
        distinct_stage_one_designs_evaluated=len(evaluated),
    )


def _relative_reduction(candidate: float, baseline: float) -> float | None:
    if baseline == 0:
        return 0.0 if candidate == 0 else None
    return (baseline - candidate) / baseline


def compare_against_strong_baselines(
    options: Iterable[IntervalOption],
    *,
    n_bins: int,
    memory_budget_quanta: int,
    minimum_compromise_quanta: int,
    maximum_regions: int,
    worst_region_epsilon_cap: float = 1.0,
) -> StrongBaselineComparison:
    """Compare joint DP with exact global-filter and two-stage restrictions."""

    all_options = tuple(options)
    parameters = {
        "n_bins": n_bins,
        "memory_budget_quanta": memory_budget_quanta,
        "minimum_compromise_quanta": minimum_compromise_quanta,
        "maximum_regions": maximum_regions,
        "worst_region_epsilon_cap": worst_region_epsilon_cap,
    }
    joint = solve_exact_discretized_joint_dp(all_options, **parameters)
    dual_certificate = generate_finite_option_dual_dp_candidates(all_options, **parameters)
    unavailable = [
        "DP-KL requires per-bin distribution statistics absent from IntervalOption",
        "quantile/equal-occupancy cuts require score-mass and occupancy metadata",
        "held-out selection requires separate training and validation option tables",
    ]
    try:
        global_filter = solve_exact_discretized_joint_dp(
            [
                option
                for option in all_options
                if option.start_bin == 0 and option.end_bin == n_bins
            ],
            **{**parameters, "maximum_regions": 1},
        )
    except ValueError:
        global_filter = None
        unavailable.append("global-filter baseline is infeasible in the option table")
    try:
        two_stage = solve_strong_two_stage_baseline(all_options, **parameters)
    except ValueError:
        two_stage = None
        unavailable.append("strong two-stage baseline is infeasible in the option table")
    return StrongBaselineComparison(
        joint_solution=joint,
        dual_certificate=dual_certificate,
        global_filter_solution=global_filter,
        two_stage=two_stage,
        joint_reduction_vs_global=_relative_reduction(joint.online_cost, global_filter.online_cost)
        if global_filter is not None
        else None,
        joint_reduction_vs_two_stage=_relative_reduction(
            joint.online_cost, two_stage.solution.online_cost
        )
        if two_stage is not None
        else None,
        unavailable_baselines=tuple(unavailable),
    )
