"""Fail-closed held-out evidence envelopes for the T4b replay optimizer.

Formal loaders require a caller-supplied :class:`ExpectedT4bContract`.  That
object must come from a trusted, independently controlled configuration source;
loading it from the same producer or artifact only moves the trust boundary.
These contracts validate declarations and cross-field consistency.  They do not
independently reconstruct ``N_b``, ``W_b``, ``D_b``, traces, or filter builds
from raw data.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal
from fractions import Fraction
from typing import Any

from reference.optimizer.joint_dp import RELATIVE_GAP_DENOMINATOR
from reference.optimizer.partition_baselines import (
    DECIMAL_PRECISION,
    DP_KL_METHOD,
    EQUAL_OCCUPANCY_METHOD,
    FIXED_FINE_GRID_DOMAIN,
    QUANTILE_METHOD,
    FineGridPartitionCandidate,
    derive_partition_candidates,
    normalize_counts,
)

EXPECTED_T4B_CONTRACT_SCHEMA_VERSION = 3
FINE_BIN_EVIDENCE_SCHEMA_VERSION = 3
REPLAY_OPTION_TABLE_SCHEMA_VERSION = 5
FIXED_PARTITION_BASELINE_EVIDENCE_SCHEMA_VERSION = 1

DESIGN_ROLE = "validation"
BINNING_RULE = "left_closed_right_open_last_closed_v1"
ACTIVE_MEMBER_SNAPSHOT_POLICY = "validation_window_start_active_members_v1"
WORK_WEIGHT_DEFINITION = "sum_verifier_cost_over_invalid_validation_episodes_v1"
COMPROMISE_WEIGHT_DEFINITION = "preregistered_guess_corpus_unique_exposure_v1"
CERTIFICATE_GAP_DENOMINATOR = RELATIVE_GAP_DENOMINATOR
PHYSICAL_MEMORY_ACCOUNTING = "filter_plus_bounded_exact_negative_cache_v2"
PACKED_NEGATIVE_CACHE_LAYOUT = "bounded-exact-negative-cache-v2"
CI_METHOD = "paired_seed_student_t_two_sided_95_v1"
CI_CONFIDENCE_LEVEL = 0.95
EVIDENCE_STATUS = "EVIDENCE_CONTRACT_ONLY"
FIXED_PARTITION_BASELINE_EVIDENCE_ROLE = "train"
FIXED_PARTITION_BASELINE_POPULATION = "active_member_snapshot_vs_train_existing_invalid_episodes_v1"
FIXED_PARTITION_BASELINE_AGGREGATION = "exact_counts_per_frozen_score_bin_v1"
FIXED_PARTITION_BASELINE_CANDIDATE_ORDER = (
    DP_KL_METHOD,
    QUANTILE_METHOD,
    EQUAL_OCCUPANCY_METHOD,
)
NO_FILTER_BUILD_ID = hashlib.sha256(b"TRAPS/T4b/no-filter-build/v1").hexdigest()
M0_ALL_POSITIVE_REALIZATION_ID = hashlib.sha256(
    b"TRAPS/T4b/m0-all-positive-realization/v1"
).hexdigest()

_ROLES = ("train", "validation", "test")
_CACHE_POLICIES = frozenset({"always", "none", "second_hit"})
_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
_IDENTITY_PATTERN = re.compile(r"[0-9a-f]{64}")

_ENTRY_FIELDS_BYTES = {
    "negative_key_id_u64": 8,
    "negative_digest_256": 32,
    "stable_account_handle_128": 16,
    "account_generation_u64": 8,
    "credential_set_version_u64": 8,
    "region_u32": 4,
    "inserted_at_u64": 8,
    "expires_at_u64": 8,
}
_FIXED_FIELDS_BYTES = {
    "magic_and_schema": 16,
    "capacity_and_size": 16,
    "ttl_and_quota_metadata": 24,
    "allocator_header": 8,
}
_ENTRY_FIELDS_TOTAL_BYTES = 92
_ENTRY_ALIGNED_BYTES = 96
_HASH_TABLE_MAX_LOAD_NUMERATOR = 4
_HASH_TABLE_MAX_LOAD_DENOMINATOR = 5
_HASH_TABLE_SLACK_BYTES_PER_SLOT = 24
_ALLOCATOR_OVERHEAD_BYTES_PER_SLOT = 16
_ENTRY_BYTES_PER_SLOT = 136
_FIXED_METADATA_BYTES = 64
_LRU_POLICY_BYTES_PER_SLOT = 8


class _DuplicateJsonKeyError(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is forbidden")


def _dict(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise ValueError(f"{label} must be a JSON object")
    if any(type(key) is not str for key in value):
        raise ValueError(f"{label} keys must be strings")
    return value


def _list(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise ValueError(f"{label} must be a JSON array")
    return value


def _load_json_object(text: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (_DuplicateJsonKeyError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is malformed: {error}") from error
    return _dict(value, label)


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise ValueError(f"{label} missing fields {sorted(missing)}")
    if extra:
        raise ValueError(f"{label} has unbound fields {sorted(extra)}")


def _exact_value(actual: object, expected: object, label: str) -> None:
    """Require exact recursive JSON types and values, including bool-vs-int."""

    if type(actual) is not type(expected):
        raise ValueError(f"{label} has the wrong exact type")
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        _exact_keys(actual, set(expected), label)
        for key, expected_item in expected.items():
            _exact_value(actual[key], expected_item, f"{label}.{key}")
        return
    if isinstance(expected, list):
        assert isinstance(actual, list)
        if len(actual) != len(expected):
            raise ValueError(f"{label} has the wrong list length")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected, strict=True)):
            _exact_value(actual_item, expected_item, f"{label}[{index}]")
        return
    if isinstance(expected, float) and not math.isfinite(actual):
        raise ValueError(f"{label} must be finite")
    if actual != expected:
        raise ValueError(f"{label} does not match the trusted expected contract")


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value < minimum:
        raise ValueError(f"{label} must be at least {minimum}")
    return value


def _finite_number(
    value: object,
    label: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{label} must be finite")
    if minimum is not None and result < minimum:
        raise ValueError(f"{label} must be at least {minimum}")
    if maximum is not None and result > maximum:
        raise ValueError(f"{label} must be at most {maximum}")
    return 0.0 if result == 0.0 else result


def _optional_ttl(value: object) -> float | None:
    if value is None:
        return None
    return _finite_number(value, "ttl_seconds", minimum=0.0)


def _canonical_string(value: object, label: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{label} must be a nonempty canonical string")
    if any(ord(character) < 0x20 for character in value):
        raise ValueError(f"{label} must not contain control characters")
    return value


def _source_commit(value: object) -> str:
    result = _canonical_string(value, "source_commit")
    if _COMMIT_PATTERN.fullmatch(result) is None:
        raise ValueError("source_commit must be 40 lowercase hexadecimal characters")
    return result


def _semantic_identity(value: object, label: str) -> str:
    result = _canonical_string(value, label)
    if _IDENTITY_PATTERN.fullmatch(result) is None:
        raise ValueError(f"{label} must be 64 lowercase hexadecimal characters")
    return result


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChronologicalWindow:
    role: str
    start: float
    end: float

    def __post_init__(self) -> None:
        role = _canonical_string(self.role, "chronological window role")
        if role not in _ROLES:
            raise ValueError(f"chronological window role must be one of {_ROLES}")
        start = _finite_number(self.start, f"{role} window start", minimum=0.0, maximum=1.0)
        end = _finite_number(self.end, f"{role} window end", minimum=0.0, maximum=1.0)
        if start >= end:
            raise ValueError(f"{role} chronological window must be nonempty")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)

    def to_dict(self) -> dict[str, object]:
        return {"role": self.role, "start": self.start, "end": self.end}

    @classmethod
    def from_dict(cls, value: object) -> ChronologicalWindow:
        mapping = _dict(value, "chronological window")
        _exact_keys(mapping, {"role", "start", "end"}, "chronological window")
        return cls(role=mapping["role"], start=mapping["start"], end=mapping["end"])


def _formal_windows() -> tuple[ChronologicalWindow, ...]:
    return (
        ChronologicalWindow("train", 0.0, 0.5),
        ChronologicalWindow("validation", 0.5, 0.7),
        ChronologicalWindow("test", 0.7, 1.0),
    )


def _complete_contiguous_intervals(n_bins: int) -> tuple[tuple[int, int], ...]:
    return tuple((start, end) for start in range(n_bins) for end in range(start + 1, n_bins + 1))


@dataclass(frozen=True)
class ReplayGrid:
    intervals: tuple[tuple[int, int], ...]
    filter_memory_bytes_choices: tuple[int, ...]
    cache_capacity_choices: tuple[int, ...]
    cache_policies: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.intervals) is not tuple or not self.intervals:
            raise ValueError("replay grid intervals must be a nonempty tuple")
        intervals: list[tuple[int, int]] = []
        for index, interval in enumerate(self.intervals):
            if type(interval) is not tuple or len(interval) != 2:
                raise ValueError(f"grid interval {index} must be a two-integer tuple")
            start = _integer(interval[0], f"grid interval {index} start")
            end = _integer(interval[1], f"grid interval {index} end", minimum=1)
            if start >= end:
                raise ValueError("grid intervals must be nonempty")
            intervals.append((start, end))
        normalized_intervals = tuple(intervals)
        if normalized_intervals != tuple(sorted(set(normalized_intervals))):
            raise ValueError("grid intervals must be sorted and unique")
        memory_choices = self._integer_choices(
            self.filter_memory_bytes_choices, "filter_memory_bytes_choices"
        )
        capacity_choices = self._integer_choices(
            self.cache_capacity_choices, "cache_capacity_choices"
        )
        if type(self.cache_policies) is not tuple or not self.cache_policies:
            raise ValueError("cache_policies must be a nonempty tuple")
        policies = tuple(
            _canonical_string(policy, f"cache_policies[{index}]")
            for index, policy in enumerate(self.cache_policies)
        )
        if any(policy not in _CACHE_POLICIES for policy in policies):
            raise ValueError("cache_policies contains an unsupported replay policy")
        if policies != tuple(sorted(set(policies))):
            raise ValueError("cache_policies must be sorted and unique")
        object.__setattr__(self, "intervals", normalized_intervals)
        object.__setattr__(self, "filter_memory_bytes_choices", memory_choices)
        object.__setattr__(self, "cache_capacity_choices", capacity_choices)
        object.__setattr__(self, "cache_policies", policies)

    @staticmethod
    def _integer_choices(values: tuple[int, ...], label: str) -> tuple[int, ...]:
        if type(values) is not tuple or not values:
            raise ValueError(f"{label} must be a nonempty tuple")
        normalized = tuple(
            _integer(value, f"{label}[{index}]") for index, value in enumerate(values)
        )
        if normalized != tuple(sorted(set(normalized))):
            raise ValueError(f"{label} must be sorted and unique")
        return normalized

    @property
    def expected_coordinates(self) -> tuple[tuple[int, int, int, int, str], ...]:
        return tuple(
            (start, end, memory_bytes, cache_capacity, policy)
            for (start, end), memory_bytes, cache_capacity, policy in itertools.product(
                self.intervals,
                self.filter_memory_bytes_choices,
                self.cache_capacity_choices,
                self.cache_policies,
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "intervals": [list(interval) for interval in self.intervals],
            "filter_memory_bytes_choices": list(self.filter_memory_bytes_choices),
            "cache_capacity_choices": list(self.cache_capacity_choices),
            "cache_policies": list(self.cache_policies),
        }

    @classmethod
    def from_dict(cls, value: object) -> ReplayGrid:
        mapping = _dict(value, "replay grid")
        fields = {
            "intervals",
            "filter_memory_bytes_choices",
            "cache_capacity_choices",
            "cache_policies",
        }
        _exact_keys(mapping, fields, "replay grid")
        intervals: list[tuple[int, int]] = []
        for index, item in enumerate(_list(mapping["intervals"], "grid intervals")):
            pair = _list(item, f"grid interval {index}")
            if len(pair) != 2:
                raise ValueError(f"grid interval {index} must have length two")
            intervals.append((pair[0], pair[1]))
        return cls(
            intervals=tuple(intervals),
            filter_memory_bytes_choices=tuple(
                _list(
                    mapping["filter_memory_bytes_choices"],
                    "filter_memory_bytes_choices",
                )
            ),
            cache_capacity_choices=tuple(
                _list(mapping["cache_capacity_choices"], "cache_capacity_choices")
            ),
            cache_policies=tuple(_list(mapping["cache_policies"], "cache_policies")),
        )


@dataclass(frozen=True)
class PhysicalMemoryAccounting:
    """Exact compact bytes for bounded resident and probation stores."""

    method: str = PHYSICAL_MEMORY_ACCOUNTING
    layout_schema: str = PACKED_NEGATIVE_CACHE_LAYOUT

    def __post_init__(self) -> None:
        if self.method != PHYSICAL_MEMORY_ACCOUNTING:
            raise ValueError("memory accounting method is not the frozen physical formula")
        if self.layout_schema != PACKED_NEGATIVE_CACHE_LAYOUT:
            raise ValueError("memory layout is not bounded-exact-negative-cache-v2")

    @property
    def entry_bytes_per_slot(self) -> int:
        return _ENTRY_BYTES_PER_SLOT

    @property
    def fixed_metadata_bytes(self) -> int:
        return _FIXED_METADATA_BYTES

    @property
    def policy_bytes_per_slot(self) -> int:
        return _LRU_POLICY_BYTES_PER_SLOT

    def components(
        self, filter_memory_bytes: int, cache_capacity: int, cache_policy: str
    ) -> tuple[int, int, int, int, int, int]:
        """Return resident entries/LRU, probation entries/LRU, fixed, total."""

        filter_bytes = _integer(filter_memory_bytes, "filter_memory_bytes")
        capacity = _integer(cache_capacity, "cache_capacity")
        policy = _canonical_string(cache_policy, "cache_policy")
        if policy not in _CACHE_POLICIES:
            raise ValueError("cache_policy is unsupported")
        if capacity == 0 or policy == "none":
            return 0, 0, 0, 0, 0, filter_bytes
        resident_entry_bytes = capacity * self.entry_bytes_per_slot
        resident_lru_bytes = capacity * self.policy_bytes_per_slot
        probation_entry_bytes = 0
        probation_lru_bytes = 0
        fixed_bytes = self.fixed_metadata_bytes
        if policy == "second_hit":
            probation_entry_bytes = capacity * self.entry_bytes_per_slot
            probation_lru_bytes = capacity * self.policy_bytes_per_slot
            fixed_bytes += self.fixed_metadata_bytes
        return (
            resident_entry_bytes,
            resident_lru_bytes,
            probation_entry_bytes,
            probation_lru_bytes,
            fixed_bytes,
            filter_bytes
            + resident_entry_bytes
            + resident_lru_bytes
            + probation_entry_bytes
            + probation_lru_bytes
            + fixed_bytes,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "schema": self.layout_schema,
            "entry_fields_bytes": dict(_ENTRY_FIELDS_BYTES),
            "entry_fields_total_bytes": _ENTRY_FIELDS_TOTAL_BYTES,
            "entry_aligned_bytes": _ENTRY_ALIGNED_BYTES,
            "hash_table_max_load": 0.8,
            "hash_table_max_load_numerator": _HASH_TABLE_MAX_LOAD_NUMERATOR,
            "hash_table_max_load_denominator": _HASH_TABLE_MAX_LOAD_DENOMINATOR,
            "hash_table_slack_bytes_per_slot": _HASH_TABLE_SLACK_BYTES_PER_SLOT,
            "allocator_overhead_bytes_per_slot": _ALLOCATOR_OVERHEAD_BYTES_PER_SLOT,
            "entry_bytes_per_slot": _ENTRY_BYTES_PER_SLOT,
            "fixed_fields_bytes": dict(_FIXED_FIELDS_BYTES),
            "fixed_metadata_bytes_per_store": _FIXED_METADATA_BYTES,
            "resident_lru_bytes_per_slot": _LRU_POLICY_BYTES_PER_SLOT,
            "probation_lru_bytes_per_slot": _LRU_POLICY_BYTES_PER_SLOT,
            "resident_slot_capacity_rule": "cache_capacity",
            "probation_slot_capacity_rule": ("cache_capacity_for_second_hit_else_zero"),
            "probation_key_representation": "exact_full_cache_key",
            "resident_eviction_policy": "lru",
            "probation_eviction_policy": "lru",
            "scope": (
                "packed in-memory allocation for the resident exact-key table and "
                "the bounded second-hit exact-key probation table; Python "
                "runtime object-graph overhead is outside this compact layout"
            ),
        }

    @classmethod
    def from_dict(cls, value: object) -> PhysicalMemoryAccounting:
        mapping = _dict(value, "physical memory accounting")
        canonical = cls()
        _exact_value(mapping, canonical.to_dict(), "physical memory accounting")
        return canonical


@dataclass(frozen=True)
class CachePolicySemantics:
    cache_policy: str
    admission_policy_id: str
    eviction_policy_id: str
    expiration_policy_id: str

    def __post_init__(self) -> None:
        policy = _canonical_string(self.cache_policy, "cache_policy")
        if policy not in _CACHE_POLICIES:
            raise ValueError("cache policy semantics names an unsupported policy")
        for field_name in (
            "admission_policy_id",
            "eviction_policy_id",
            "expiration_policy_id",
        ):
            _semantic_identity(getattr(self, field_name), field_name)

    def to_dict(self) -> dict[str, object]:
        return {
            "cache_policy": self.cache_policy,
            "admission_policy_id": self.admission_policy_id,
            "eviction_policy_id": self.eviction_policy_id,
            "expiration_policy_id": self.expiration_policy_id,
        }

    @classmethod
    def from_dict(cls, value: object) -> CachePolicySemantics:
        mapping = _dict(value, "cache policy semantics")
        fields = {
            "cache_policy",
            "admission_policy_id",
            "eviction_policy_id",
            "expiration_policy_id",
        }
        _exact_keys(mapping, fields, "cache policy semantics")
        return cls(**{field: mapping[field] for field in fields})


@dataclass(frozen=True)
class VerifierCostModel:
    """Trusted rational weights for reconstructing replay work without floats."""

    model_id: str
    denominator: int
    base_confirmation_numerator: int
    race_extra_numerator: int

    def __post_init__(self) -> None:
        _semantic_identity(self.model_id, "verifier cost model_id")
        _integer(self.denominator, "verifier cost denominator", minimum=1)
        _integer(
            self.base_confirmation_numerator,
            "base confirmation cost numerator",
            minimum=1,
        )
        _integer(
            self.race_extra_numerator,
            "race extra cost numerator",
            minimum=1,
        )

    def work_numerator(self, base_confirmations: int, race_extras: int) -> int:
        base = _integer(base_confirmations, "base_confirmations")
        race = _integer(race_extras, "race_extras")
        return base * self.base_confirmation_numerator + race * self.race_extra_numerator

    def work(self, numerator: int) -> Fraction:
        return Fraction(_integer(numerator, "weighted_work_numerator"), self.denominator)

    def to_dict(self) -> dict[str, object]:
        return {
            "model_id": self.model_id,
            "denominator": self.denominator,
            "base_confirmation_numerator": self.base_confirmation_numerator,
            "race_extra_numerator": self.race_extra_numerator,
        }

    @classmethod
    def from_dict(cls, value: object) -> VerifierCostModel:
        mapping = _dict(value, "verifier cost model")
        fields = set(cls.__dataclass_fields__)
        _exact_keys(mapping, fields, "verifier cost model")
        return cls(**{field: mapping[field] for field in fields})


@dataclass(frozen=True)
class ExpectedT4bContract:
    """Trusted formal expectations, controlled independently from result producers."""

    schema_version: int
    dataset_id: str
    config_id: str
    source_commit: str
    chronology_key: str
    chronological_windows: tuple[ChronologicalWindow, ...]
    router_implementation_id: str
    bin_edges: tuple[float, ...]
    active_member_snapshot_id: str
    invalid_episode_corpus_id: str
    guess_corpus_id: str
    guess_corpus_preregistration_id: str
    exposure_profile_id: str
    validation_trace_id: str
    grid_implementation_id: str
    filter_implementation_id: str
    replay_implementation_id: str
    grid: ReplayGrid
    paired_seeds: tuple[int, ...]
    memory_accounting: PhysicalMemoryAccounting
    verifier_cost_model: VerifierCostModel
    ttl_seconds: float | None
    policy_semantics: tuple[CachePolicySemantics, ...]
    resource_quantum_bytes: int
    compromise_quantum: float
    worst_region_epsilon_cap: float
    ci_method: str
    ci_confidence_level: float

    def __post_init__(self) -> None:
        if _integer(self.schema_version, "expected schema_version", minimum=1) != (
            EXPECTED_T4B_CONTRACT_SCHEMA_VERSION
        ):
            raise ValueError(
                f"expected schema_version must be {EXPECTED_T4B_CONTRACT_SCHEMA_VERSION}"
            )
        for field_name in (
            "dataset_id",
            "config_id",
            "router_implementation_id",
            "active_member_snapshot_id",
            "invalid_episode_corpus_id",
            "guess_corpus_id",
            "guess_corpus_preregistration_id",
            "exposure_profile_id",
            "validation_trace_id",
            "grid_implementation_id",
            "filter_implementation_id",
            "replay_implementation_id",
        ):
            _semantic_identity(getattr(self, field_name), field_name)
        _source_commit(self.source_commit)
        _canonical_string(self.chronology_key, "chronology_key")
        if type(self.chronological_windows) is not tuple or any(
            type(window) is not ChronologicalWindow for window in self.chronological_windows
        ):
            raise ValueError("chronological_windows must be an immutable exact window tuple")
        if self.chronological_windows != _formal_windows():
            raise ValueError("formal windows must be train=[0,.5), validation=[.5,.7), test=[.7,1]")
        if type(self.bin_edges) is not tuple or len(self.bin_edges) < 2:
            raise ValueError("bin_edges must contain at least two frozen edges")
        edges = tuple(
            _finite_number(value, f"bin_edges[{index}]")
            for index, value in enumerate(self.bin_edges)
        )
        if any(left >= right for left, right in zip(edges, edges[1:], strict=False)):
            raise ValueError("bin_edges must be strictly increasing")
        object.__setattr__(self, "bin_edges", edges)
        if type(self.grid) is not ReplayGrid:
            raise ValueError("grid has the wrong exact type")
        if self.grid.intervals != _complete_contiguous_intervals(len(edges) - 1):
            raise ValueError("trusted grid must contain every contiguous interval")
        if 0 not in self.grid.filter_memory_bytes_choices:
            raise ValueError("trusted grid must include the zero-memory static option")
        if 0 not in self.grid.cache_capacity_choices or "none" not in self.grid.cache_policies:
            raise ValueError("trusted grid must include an explicit no-cache option")
        if type(self.paired_seeds) is not tuple or len(self.paired_seeds) < 10:
            raise ValueError("formal paired_seeds must contain at least 10 seeds")
        seeds = tuple(
            _integer(seed, f"paired_seeds[{index}]") for index, seed in enumerate(self.paired_seeds)
        )
        if seeds != tuple(sorted(set(seeds))):
            raise ValueError("paired_seeds must be sorted and unique")
        object.__setattr__(self, "paired_seeds", seeds)
        if type(self.memory_accounting) is not PhysicalMemoryAccounting:
            raise ValueError("memory_accounting has the wrong exact type")
        if type(self.verifier_cost_model) is not VerifierCostModel:
            raise ValueError("verifier_cost_model has the wrong exact type")
        ttl = _optional_ttl(self.ttl_seconds)
        object.__setattr__(self, "ttl_seconds", ttl)
        if type(self.policy_semantics) is not tuple or any(
            type(item) is not CachePolicySemantics for item in self.policy_semantics
        ):
            raise ValueError("policy_semantics must be an immutable exact tuple")
        policies = tuple(item.cache_policy for item in self.policy_semantics)
        if policies != self.grid.cache_policies:
            raise ValueError("policy_semantics must exactly cover the frozen cache policies")
        _integer(self.resource_quantum_bytes, "resource_quantum_bytes", minimum=1)
        compromise_quantum = _finite_number(
            self.compromise_quantum, "compromise_quantum", minimum=0.0
        )
        if compromise_quantum == 0.0:
            raise ValueError("compromise_quantum must be positive")
        epsilon_cap = _finite_number(
            self.worst_region_epsilon_cap,
            "worst_region_epsilon_cap",
            minimum=0.0,
            maximum=1.0,
        )
        if self.ci_method != CI_METHOD:
            raise ValueError(f"ci_method must be {CI_METHOD!r}")
        confidence = _finite_number(
            self.ci_confidence_level,
            "ci_confidence_level",
            minimum=0.0,
            maximum=1.0,
        )
        if confidence != CI_CONFIDENCE_LEVEL:
            raise ValueError(f"ci_confidence_level must be {CI_CONFIDENCE_LEVEL}")
        object.__setattr__(self, "compromise_quantum", compromise_quantum)
        object.__setattr__(self, "worst_region_epsilon_cap", epsilon_cap)
        object.__setattr__(self, "ci_confidence_level", confidence)

    @property
    def n_bins(self) -> int:
        return len(self.bin_edges) - 1

    @property
    def expected_contract_id(self) -> str:
        return _canonical_hash(self._identity_payload())

    def window(self, role: str) -> ChronologicalWindow:
        role = _canonical_string(role, "role")
        for window in self.chronological_windows:
            if window.role == role:
                return window
        raise ValueError(f"unknown chronological role {role!r}")

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "dataset_id": self.dataset_id,
            "config_id": self.config_id,
            "source_commit": self.source_commit,
            "chronology_key": self.chronology_key,
            "chronological_windows": [window.to_dict() for window in self.chronological_windows],
            "design_role": DESIGN_ROLE,
            "router_implementation_id": self.router_implementation_id,
            "binning_rule": BINNING_RULE,
            "bin_edges": list(self.bin_edges),
            "active_member_snapshot_id": self.active_member_snapshot_id,
            "active_member_snapshot_policy": ACTIVE_MEMBER_SNAPSHOT_POLICY,
            "invalid_episode_corpus_id": self.invalid_episode_corpus_id,
            "work_weight_definition": WORK_WEIGHT_DEFINITION,
            "guess_corpus_id": self.guess_corpus_id,
            "guess_corpus_preregistration_id": self.guess_corpus_preregistration_id,
            "exposure_profile_id": self.exposure_profile_id,
            "compromise_weight_definition": COMPROMISE_WEIGHT_DEFINITION,
            "certificate_gap_denominator": CERTIFICATE_GAP_DENOMINATOR,
            "validation_trace_id": self.validation_trace_id,
            "grid_implementation_id": self.grid_implementation_id,
            "filter_implementation_id": self.filter_implementation_id,
            "replay_implementation_id": self.replay_implementation_id,
            "grid": self.grid.to_dict(),
            "paired_seeds": list(self.paired_seeds),
            "memory_accounting": self.memory_accounting.to_dict(),
            "verifier_cost_model": self.verifier_cost_model.to_dict(),
            "ttl_seconds": self.ttl_seconds,
            "policy_semantics": [item.to_dict() for item in self.policy_semantics],
            "resource_quantum_bytes": self.resource_quantum_bytes,
            "compromise_quantum": self.compromise_quantum,
            "worst_region_epsilon_cap": self.worst_region_epsilon_cap,
            "ci_method": self.ci_method,
            "ci_confidence_level": self.ci_confidence_level,
            "evidence_status": EVIDENCE_STATUS,
        }

    def to_dict(self) -> dict[str, object]:
        result = self._identity_payload()
        result["expected_contract_id"] = self.expected_contract_id
        return result

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: object) -> ExpectedT4bContract:
        mapping = _dict(value, "expected T4b contract")
        canonical_fields = set(cls.__dataclass_fields__) | {
            "expected_contract_id",
            "design_role",
            "binning_rule",
            "active_member_snapshot_policy",
            "work_weight_definition",
            "compromise_weight_definition",
            "certificate_gap_denominator",
            "evidence_status",
        }
        _exact_keys(mapping, canonical_fields, "expected T4b contract")
        fixed = {
            "design_role": DESIGN_ROLE,
            "binning_rule": BINNING_RULE,
            "active_member_snapshot_policy": ACTIVE_MEMBER_SNAPSHOT_POLICY,
            "work_weight_definition": WORK_WEIGHT_DEFINITION,
            "compromise_weight_definition": COMPROMISE_WEIGHT_DEFINITION,
            "certificate_gap_denominator": CERTIFICATE_GAP_DENOMINATOR,
            "evidence_status": EVIDENCE_STATUS,
        }
        for field, expected_value in fixed.items():
            _exact_value(mapping[field], expected_value, f"expected T4b contract.{field}")
        result = cls(
            schema_version=mapping["schema_version"],
            dataset_id=mapping["dataset_id"],
            config_id=mapping["config_id"],
            source_commit=mapping["source_commit"],
            chronology_key=mapping["chronology_key"],
            chronological_windows=tuple(
                ChronologicalWindow.from_dict(item)
                for item in _list(mapping["chronological_windows"], "chronological_windows")
            ),
            router_implementation_id=mapping["router_implementation_id"],
            bin_edges=tuple(_list(mapping["bin_edges"], "bin_edges")),
            active_member_snapshot_id=mapping["active_member_snapshot_id"],
            invalid_episode_corpus_id=mapping["invalid_episode_corpus_id"],
            guess_corpus_id=mapping["guess_corpus_id"],
            guess_corpus_preregistration_id=mapping["guess_corpus_preregistration_id"],
            exposure_profile_id=mapping["exposure_profile_id"],
            validation_trace_id=mapping["validation_trace_id"],
            grid_implementation_id=mapping["grid_implementation_id"],
            filter_implementation_id=mapping["filter_implementation_id"],
            replay_implementation_id=mapping["replay_implementation_id"],
            grid=ReplayGrid.from_dict(mapping["grid"]),
            paired_seeds=tuple(_list(mapping["paired_seeds"], "paired_seeds")),
            memory_accounting=PhysicalMemoryAccounting.from_dict(mapping["memory_accounting"]),
            verifier_cost_model=VerifierCostModel.from_dict(mapping["verifier_cost_model"]),
            ttl_seconds=mapping["ttl_seconds"],
            policy_semantics=tuple(
                CachePolicySemantics.from_dict(item)
                for item in _list(mapping["policy_semantics"], "policy_semantics")
            ),
            resource_quantum_bytes=mapping["resource_quantum_bytes"],
            compromise_quantum=mapping["compromise_quantum"],
            worst_region_epsilon_cap=mapping["worst_region_epsilon_cap"],
            ci_method=mapping["ci_method"],
            ci_confidence_level=mapping["ci_confidence_level"],
        )
        supplied = _semantic_identity(mapping["expected_contract_id"], "expected_contract_id")
        if supplied != result.expected_contract_id:
            raise ValueError("expected T4b contract identity mismatch")
        return result

    @classmethod
    def from_json(cls, text: str) -> ExpectedT4bContract:
        return cls.from_dict(_load_json_object(text, "expected T4b contract JSON"))


def _fine_expected_metadata(expected: ExpectedT4bContract) -> dict[str, object]:
    return {
        "expected_contract_id": expected.expected_contract_id,
        "dataset_id": expected.dataset_id,
        "config_id": expected.config_id,
        "source_commit": expected.source_commit,
        "chronology_key": expected.chronology_key,
        "chronological_windows": [window.to_dict() for window in expected.chronological_windows],
        "design_role": DESIGN_ROLE,
        "router_implementation_id": expected.router_implementation_id,
        "binning_rule": BINNING_RULE,
        "bin_edges": list(expected.bin_edges),
        "active_member_snapshot_id": expected.active_member_snapshot_id,
        "active_member_snapshot_policy": ACTIVE_MEMBER_SNAPSHOT_POLICY,
        "invalid_episode_corpus_id": expected.invalid_episode_corpus_id,
        "work_weight_definition": WORK_WEIGHT_DEFINITION,
        "verifier_cost_model": expected.verifier_cost_model.to_dict(),
        "guess_corpus_id": expected.guess_corpus_id,
        "guess_corpus_preregistration_id": expected.guess_corpus_preregistration_id,
        "exposure_profile_id": expected.exposure_profile_id,
        "compromise_weight_definition": COMPROMISE_WEIGHT_DEFINITION,
        "certificate_gap_denominator": CERTIFICATE_GAP_DENOMINATOR,
        "evidence_status": EVIDENCE_STATUS,
    }


@dataclass(frozen=True)
class FineBinEvidence:
    """Validation evidence bound to an independently supplied expected contract."""

    schema_version: int
    expected: ExpectedT4bContract
    n_b: tuple[int, ...]
    invalid_episode_counts_b: tuple[int, ...]
    w_b: tuple[float, ...]
    d_b: tuple[float, ...]

    def __post_init__(self) -> None:
        if _integer(self.schema_version, "fine-bin schema_version", minimum=1) != (
            FINE_BIN_EVIDENCE_SCHEMA_VERSION
        ):
            raise ValueError(f"fine-bin schema_version must be {FINE_BIN_EVIDENCE_SCHEMA_VERSION}")
        if type(self.expected) is not ExpectedT4bContract:
            raise ValueError("FineBinEvidence requires the trusted expected contract")
        n_bins = self.expected.n_bins
        for field_name in ("n_b", "invalid_episode_counts_b", "w_b", "d_b"):
            if type(getattr(self, field_name)) is not tuple:
                raise ValueError(f"{field_name} must be an immutable tuple")
        if not (
            len(self.n_b)
            == len(self.invalid_episode_counts_b)
            == len(self.w_b)
            == len(self.d_b)
            == n_bins
        ):
            raise ValueError("fine-bin evidence vectors must match the frozen bin count")
        n_b = tuple(_integer(value, f"n_b[{index}]") for index, value in enumerate(self.n_b))
        invalid_counts = tuple(
            _integer(value, f"invalid_episode_counts_b[{index}]")
            for index, value in enumerate(self.invalid_episode_counts_b)
        )
        w_b = tuple(
            _finite_number(value, f"w_b[{index}]", minimum=0.0)
            for index, value in enumerate(self.w_b)
        )
        d_b = tuple(
            _finite_number(value, f"d_b[{index}]", minimum=0.0)
            for index, value in enumerate(self.d_b)
        )
        if sum(n_b) <= 0:
            raise ValueError("n_b must contain positive total validation occupancy")
        if not any(value > 0.0 for value in w_b):
            raise ValueError("w_b must contain positive held-out verifier work")
        if not any(value > 0.0 for value in d_b):
            raise ValueError("d_b must contain positive preregistered exposure mass")
        for index, (count, weight) in enumerate(zip(invalid_counts, w_b, strict=True)):
            if (count == 0) != (weight == 0.0):
                raise ValueError(
                    f"w_b[{index}] must be zero exactly for an empty invalid-episode bin"
                )
        object.__setattr__(self, "n_b", n_b)
        object.__setattr__(self, "invalid_episode_counts_b", invalid_counts)
        object.__setattr__(self, "w_b", w_b)
        object.__setattr__(self, "d_b", d_b)

    @property
    def n_bins(self) -> int:
        return self.expected.n_bins

    @property
    def expected_contract_id(self) -> str:
        return self.expected.expected_contract_id

    @property
    def evidence_status(self) -> str:
        return EVIDENCE_STATUS

    @property
    def evidence_id(self) -> str:
        return _canonical_hash(self._identity_payload())

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            **_fine_expected_metadata(self.expected),
            "n_b": list(self.n_b),
            "invalid_episode_counts_b": list(self.invalid_episode_counts_b),
            "w_b": list(self.w_b),
            "d_b": list(self.d_b),
        }

    def to_dict(self) -> dict[str, object]:
        result = self._identity_payload()
        result["evidence_id"] = self.evidence_id
        return result

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: object, *, expected: ExpectedT4bContract) -> FineBinEvidence:
        if type(expected) is not ExpectedT4bContract:
            raise ValueError("formal evidence loading requires a trusted expected contract")
        mapping = _dict(value, "fine-bin evidence")
        fields = {
            "schema_version",
            "evidence_id",
            "n_b",
            "invalid_episode_counts_b",
            "w_b",
            "d_b",
        } | set(_fine_expected_metadata(expected))
        _exact_keys(mapping, fields, "fine-bin evidence")
        _exact_value(
            mapping["schema_version"],
            FINE_BIN_EVIDENCE_SCHEMA_VERSION,
            "fine-bin evidence.schema_version",
        )
        for field, expected_value in _fine_expected_metadata(expected).items():
            _exact_value(
                mapping[field], expected_value, f"fine-bin evidence trusted metadata.{field}"
            )
        result = cls(
            schema_version=mapping["schema_version"],
            expected=expected,
            n_b=tuple(_list(mapping["n_b"], "n_b")),
            invalid_episode_counts_b=tuple(
                _list(mapping["invalid_episode_counts_b"], "invalid_episode_counts_b")
            ),
            w_b=tuple(_list(mapping["w_b"], "w_b")),
            d_b=tuple(_list(mapping["d_b"], "d_b")),
        )
        supplied = _semantic_identity(mapping["evidence_id"], "evidence_id")
        if supplied != result.evidence_id:
            raise ValueError("fine-bin evidence identity mismatch")
        return result

    @classmethod
    def from_json(cls, text: str, *, expected: ExpectedT4bContract) -> FineBinEvidence:
        return cls.from_dict(_load_json_object(text, "fine-bin evidence JSON"), expected=expected)


def _fixed_partition_algorithm_semantics() -> dict[str, object]:
    return {
        "candidate_order": {
            "primary": "regions_ascending",
            "secondary": list(FIXED_PARTITION_BASELINE_CANDIDATE_ORDER),
        },
        DP_KL_METHOD: {
            "mass_basis": "member_vs_existing_invalid",
            "atomic_bin_smoothing": "jeffreys_one_half_v1",
            "objective": "sum_region_p_ln_p_over_q_v1",
            "optimization": "maximize",
            "decimal_precision": DECIMAL_PRECISION,
            "tie_break": "lexicographically_smallest_cuts_v1",
        },
        QUANTILE_METHOD: {
            "mass_basis": "existing_invalid",
            "objective": None,
            "boundary_rule": "nearest_legal_cumulative_mass_boundary_v1",
            "tie_break": "smaller_grid_boundary_v1",
        },
        EQUAL_OCCUPANCY_METHOD: {
            "mass_basis": "member",
            "objective": None,
            "boundary_rule": "nearest_legal_cumulative_mass_boundary_v1",
            "tie_break": "smaller_grid_boundary_v1",
        },
    }


def _canonical_decimal_string(value: Decimal) -> str:
    if type(value) is not Decimal or not value.is_finite():
        raise ValueError("partition objective must be a finite Decimal")
    if value.is_zero():
        return "0"
    result = format(value, "f")
    if "." in result:
        result = result.rstrip("0").rstrip(".")
    if Decimal(result) != value:
        raise AssertionError("canonical Decimal rendering changed its exact value")
    return result


@dataclass(frozen=True)
class FixedPartitionBaselineEvidence:
    """Recomputable train-role fixed-grid partition baseline evidence.

    The constructor accepts only independently trusted base inputs.  Every cut,
    objective, alias class, ordering field, and semantic identity exposed by
    :meth:`to_dict` is recomputed from those inputs.
    """

    schema_version: int
    expected: ExpectedT4bContract
    train_existing_invalid_corpus_id: str
    member_counts: tuple[int, ...]
    existing_invalid_counts: tuple[int, ...]
    maximum_regions: int

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != (
            FIXED_PARTITION_BASELINE_EVIDENCE_SCHEMA_VERSION
        ):
            raise ValueError(
                "fixed-partition baseline schema_version must be "
                f"{FIXED_PARTITION_BASELINE_EVIDENCE_SCHEMA_VERSION}"
            )
        if type(self.expected) is not ExpectedT4bContract:
            raise ValueError(
                "FixedPartitionBaselineEvidence requires the trusted expected contract"
            )
        _semantic_identity(
            self.train_existing_invalid_corpus_id,
            "train_existing_invalid_corpus_id",
        )
        if type(self.member_counts) is not tuple:
            raise ValueError("member_counts must be an immutable exact count tuple")
        if type(self.existing_invalid_counts) is not tuple:
            raise ValueError("existing_invalid_counts must be an immutable exact count tuple")
        members = normalize_counts(self.member_counts, name="member_counts")
        invalid = normalize_counts(
            self.existing_invalid_counts,
            name="existing_invalid_counts",
        )
        if len(members) != self.expected.n_bins or len(invalid) != self.expected.n_bins:
            raise ValueError(
                "fixed-partition count tuples must match the trusted current bin count"
            )
        if type(self.maximum_regions) is not int:
            raise TypeError("maximum_regions must be an exact integer (bool is forbidden)")
        if not 1 <= self.maximum_regions <= self.expected.n_bins:
            raise ValueError("maximum_regions must lie in [1, current n_bins]")
        object.__setattr__(self, "member_counts", members)
        object.__setattr__(self, "existing_invalid_counts", invalid)

    @property
    def expected_contract_id(self) -> str:
        return self.expected.expected_contract_id

    @property
    def score_grid_id(self) -> str:
        return _canonical_hash(self._score_grid_identity_payload())

    @property
    def input_id(self) -> str:
        return _canonical_hash(self._input_identity_payload())

    @property
    def evidence_id(self) -> str:
        return _canonical_hash(self._identity_payload())

    def _score_grid_identity_payload(self) -> dict[str, object]:
        return {
            "semantic_domain": "TRAPS/T4b/fixed-partition-score-grid/v1",
            "router_implementation_id": self.expected.router_implementation_id,
            "binning_rule": BINNING_RULE,
            "bin_edges": list(self.expected.bin_edges),
            "n_bins": self.expected.n_bins,
            "grid_domain": FIXED_FINE_GRID_DOMAIN,
            "continuous_thresholds_certified": False,
        }

    def _input_identity_payload(self) -> dict[str, object]:
        return {
            "semantic_domain": "TRAPS/T4b/fixed-partition-input/v1",
            "expected_contract_id": self.expected_contract_id,
            "evidence_role": FIXED_PARTITION_BASELINE_EVIDENCE_ROLE,
            "population_definition": FIXED_PARTITION_BASELINE_POPULATION,
            "aggregation_rule": FIXED_PARTITION_BASELINE_AGGREGATION,
            "active_member_snapshot_id": self.expected.active_member_snapshot_id,
            "train_existing_invalid_corpus_id": (self.train_existing_invalid_corpus_id),
            "score_grid_id": self.score_grid_id,
            "member_counts": list(self.member_counts),
            "existing_invalid_counts": list(self.existing_invalid_counts),
            "maximum_regions": self.maximum_regions,
        }

    def _candidate_identity_payload(
        self,
        *,
        candidate_index: int,
        candidate: FineGridPartitionCandidate,
        kl_objective: str | None,
    ) -> dict[str, object]:
        return {
            "semantic_domain": "TRAPS/T4b/fixed-partition-candidate/v1",
            "score_grid_id": self.score_grid_id,
            "input_id": self.input_id,
            "candidate_index": candidate_index,
            "method": candidate.method,
            "mass_basis": candidate.mass_basis,
            "regions": candidate.regions,
            "cuts": list(candidate.cuts),
            "intervals": [list(interval) for interval in candidate.intervals],
            "kl_objective": kl_objective,
            "grid_domain": candidate.grid_domain,
            "continuous_thresholds_certified": False,
        }

    def _alias_identity_payload(
        self,
        candidate: FineGridPartitionCandidate,
    ) -> dict[str, object]:
        return {
            "semantic_domain": "TRAPS/T4b/fixed-partition-alias-class/v1",
            "score_grid_id": self.score_grid_id,
            "regions": candidate.regions,
            "cuts": list(candidate.cuts),
            "intervals": [list(interval) for interval in candidate.intervals],
        }

    def _derived_wire(
        self,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        derived = derive_partition_candidates(
            self.member_counts,
            self.existing_invalid_counts,
            maximum_regions=self.maximum_regions,
        )
        if tuple(candidate.method for candidate in derived) != tuple(
            method
            for _regions in range(1, self.maximum_regions + 1)
            for method in FIXED_PARTITION_BASELINE_CANDIDATE_ORDER
        ):
            raise AssertionError("partition candidate derivation order changed")

        candidate_records: list[dict[str, object]] = []
        alias_records: dict[str, dict[str, object]] = {}
        for candidate_index, candidate in enumerate(derived):
            objective = (
                _canonical_decimal_string(candidate.kl_objective)
                if candidate.method == DP_KL_METHOD
                else None
            )
            identity_payload = self._candidate_identity_payload(
                candidate_index=candidate_index,
                candidate=candidate,
                kl_objective=objective,
            )
            candidate_id = _canonical_hash(identity_payload)
            alias_identity = self._alias_identity_payload(candidate)
            alias_class_id = _canonical_hash(alias_identity)
            candidate_records.append(
                {
                    "candidate_index": candidate_index,
                    "candidate_id": candidate_id,
                    "alias_class_id": alias_class_id,
                    "method": candidate.method,
                    "mass_basis": candidate.mass_basis,
                    "regions": candidate.regions,
                    "cuts": list(candidate.cuts),
                    "intervals": [list(interval) for interval in candidate.intervals],
                    "kl_objective": objective,
                    "grid_domain": candidate.grid_domain,
                    "continuous_thresholds_certified": False,
                }
            )
            alias = alias_records.get(alias_class_id)
            if alias is None:
                alias = {
                    "alias_class_index": len(alias_records),
                    "alias_class_id": alias_class_id,
                    "regions": candidate.regions,
                    "cuts": list(candidate.cuts),
                    "intervals": [list(interval) for interval in candidate.intervals],
                    "candidate_ids": [],
                    "methods": [],
                }
                alias_records[alias_class_id] = alias
            candidate_ids = alias["candidate_ids"]
            methods = alias["methods"]
            assert isinstance(candidate_ids, list)
            assert isinstance(methods, list)
            candidate_ids.append(candidate_id)
            methods.append(candidate.method)
        return candidate_records, list(alias_records.values())

    @property
    def candidates(self) -> tuple[dict[str, object], ...]:
        candidates, _ = self._derived_wire()
        return tuple(candidates)

    @property
    def alias_classes(self) -> tuple[dict[str, object], ...]:
        _, aliases = self._derived_wire()
        return tuple(aliases)

    def _identity_payload(self) -> dict[str, object]:
        candidates, aliases = self._derived_wire()
        return {
            "schema_version": self.schema_version,
            "expected_contract_id": self.expected_contract_id,
            "evidence_role": FIXED_PARTITION_BASELINE_EVIDENCE_ROLE,
            "population_definition": FIXED_PARTITION_BASELINE_POPULATION,
            "aggregation_rule": FIXED_PARTITION_BASELINE_AGGREGATION,
            "active_member_snapshot_id": self.expected.active_member_snapshot_id,
            "train_existing_invalid_corpus_id": (self.train_existing_invalid_corpus_id),
            "router_implementation_id": self.expected.router_implementation_id,
            "binning_rule": BINNING_RULE,
            "bin_edges": list(self.expected.bin_edges),
            "n_bins": self.expected.n_bins,
            "grid_domain": FIXED_FINE_GRID_DOMAIN,
            "continuous_thresholds_certified": False,
            "algorithm_semantics": _fixed_partition_algorithm_semantics(),
            "score_grid_id": self.score_grid_id,
            "input_id": self.input_id,
            "member_counts": list(self.member_counts),
            "existing_invalid_counts": list(self.existing_invalid_counts),
            "maximum_regions": self.maximum_regions,
            "candidate_count": len(candidates),
            "alias_class_count": len(aliases),
            "candidates": candidates,
            "alias_classes": aliases,
        }

    def to_dict(self) -> dict[str, object]:
        result = self._identity_payload()
        result["evidence_id"] = self.evidence_id
        return result

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        expected: ExpectedT4bContract,
        train_existing_invalid_corpus_id: str,
        member_counts: tuple[int, ...],
        existing_invalid_counts: tuple[int, ...],
        maximum_regions: int,
    ) -> FixedPartitionBaselineEvidence:
        result = cls(
            schema_version=FIXED_PARTITION_BASELINE_EVIDENCE_SCHEMA_VERSION,
            expected=expected,
            train_existing_invalid_corpus_id=train_existing_invalid_corpus_id,
            member_counts=member_counts,
            existing_invalid_counts=existing_invalid_counts,
            maximum_regions=maximum_regions,
        )
        mapping = _dict(value, "fixed-partition baseline evidence")
        _exact_value(
            mapping,
            result.to_dict(),
            "fixed-partition baseline evidence",
        )
        return result

    @classmethod
    def from_json(
        cls,
        text: str,
        *,
        expected: ExpectedT4bContract,
        train_existing_invalid_corpus_id: str,
        member_counts: tuple[int, ...],
        existing_invalid_counts: tuple[int, ...],
        maximum_regions: int,
    ) -> FixedPartitionBaselineEvidence:
        return cls.from_dict(
            _load_json_object(text, "fixed-partition baseline evidence JSON"),
            expected=expected,
            train_existing_invalid_corpus_id=train_existing_invalid_corpus_id,
            member_counts=member_counts,
            existing_invalid_counts=existing_invalid_counts,
            maximum_regions=maximum_regions,
        )


@dataclass(frozen=True)
class ReplayFamilyResult:
    """Raw integer estimands for one workload family and paired seed."""

    family: str
    query_count: int
    positive_query_count: int
    base_confirmations: int
    race_extras: int
    weighted_base_work_numerator: int
    weighted_race_extra_work_numerator: int
    backend_checks: int
    cache_hits: int
    cache_misses: int
    admitted: int
    evictions: int
    expirations: int
    guess_count: int
    positive_guess_count: int
    guess_exposure_numerator: int
    positive_guess_exposure_numerator: int
    guess_exposure_denominator: int
    realized_epsilon: float
    realized_compromise_mass: float

    def __post_init__(self) -> None:
        _canonical_string(self.family, "replay family")
        query_count = _integer(self.query_count, "family query_count", minimum=1)
        positives = _integer(self.positive_query_count, "family positive_query_count")
        if positives > query_count:
            raise ValueError("family positive_query_count cannot exceed query_count")
        base = _integer(self.base_confirmations, "family base_confirmations")
        race = _integer(self.race_extras, "family race_extras")
        base_work = _integer(
            self.weighted_base_work_numerator,
            "family weighted_base_work_numerator",
        )
        race_work = _integer(
            self.weighted_race_extra_work_numerator,
            "family weighted_race_extra_work_numerator",
        )
        if (base == 0) != (base_work == 0):
            raise ValueError("family base work must preserve actual base confirmations")
        if (race == 0) != (race_work == 0):
            raise ValueError("family race work must preserve actual race extras")
        for field_name in (
            "backend_checks",
            "cache_hits",
            "cache_misses",
            "admitted",
            "evictions",
            "expirations",
        ):
            _integer(getattr(self, field_name), f"family {field_name}")
        if self.cache_hits + self.cache_misses != positives:
            raise ValueError("family cache accounting must cover every positive query")
        if self.cache_misses != base:
            raise ValueError("family cache misses must equal base confirmations")
        if self.backend_checks != base + race:
            raise ValueError("family backend checks must include base and race work")
        if self.admitted > base:
            raise ValueError("family admissions cannot exceed base confirmations")
        if self.evictions + self.expirations > self.admitted:
            raise ValueError("family cache removals cannot exceed admissions")
        guesses = _integer(self.guess_count, "family guess_count", minimum=1)
        positive_guesses = _integer(self.positive_guess_count, "family positive_guess_count")
        if positive_guesses > guesses:
            raise ValueError("family positive_guess_count cannot exceed guess_count")
        exposure = _integer(
            self.guess_exposure_numerator, "family guess_exposure_numerator", minimum=1
        )
        positive_exposure = _integer(
            self.positive_guess_exposure_numerator,
            "family positive_guess_exposure_numerator",
        )
        if positive_exposure > exposure:
            raise ValueError("family positive guess exposure cannot exceed preregistered exposure")
        denominator = _integer(
            self.guess_exposure_denominator,
            "family guess_exposure_denominator",
            minimum=1,
        )
        epsilon = _finite_number(
            self.realized_epsilon,
            "family realized_epsilon",
            minimum=0.0,
            maximum=1.0,
        )
        if epsilon != positives / query_count:
            raise ValueError("family epsilon must be reconstructed from raw query counts")
        compromise = _finite_number(
            self.realized_compromise_mass,
            "family realized_compromise_mass",
            minimum=0.0,
        )
        if compromise != positive_exposure / denominator:
            raise ValueError(
                "family compromise mass must use actual preregistered guess realization"
            )
        object.__setattr__(self, "realized_epsilon", epsilon)
        object.__setattr__(self, "realized_compromise_mass", compromise)

    def to_dict(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    def static_tuple(self) -> tuple[object, ...]:
        return (
            self.family,
            self.query_count,
            self.positive_query_count,
            self.guess_count,
            self.positive_guess_count,
            self.guess_exposure_numerator,
            self.positive_guess_exposure_numerator,
            self.guess_exposure_denominator,
            self.realized_epsilon,
            self.realized_compromise_mass,
        )

    @classmethod
    def from_dict(cls, value: object) -> ReplayFamilyResult:
        mapping = _dict(value, "replay family result")
        fields = set(cls.__dataclass_fields__)
        _exact_keys(mapping, fields, "replay family result")
        return cls(**{field: mapping[field] for field in fields})


@dataclass(frozen=True)
class ReplaySeedResult:
    trace_id: str
    query_corpus_id: str
    replay_transcript_id: str
    filter_build_id: str
    static_realization_id: str
    seed: int
    query_count: int
    positive_query_count: int
    backend_checks: int
    base_confirmations: int
    race_extras: int
    weighted_base_work_numerator: int
    weighted_race_extra_work_numerator: int
    weighted_work_numerator: int
    cache_hits: int
    cache_misses: int
    admitted: int
    evictions: int
    expirations: int
    guess_count: int
    positive_guess_count: int
    guess_exposure_numerator: int
    positive_guess_exposure_numerator: int
    guess_exposure_denominator: int
    realized_epsilon: float
    realized_compromise_mass: float
    worst_family_bin_epsilon: float
    family_results: tuple[ReplayFamilyResult, ...]

    def __post_init__(self) -> None:
        for field_name in (
            "trace_id",
            "query_corpus_id",
            "replay_transcript_id",
            "filter_build_id",
            "static_realization_id",
        ):
            _semantic_identity(getattr(self, field_name), field_name)
        _integer(self.seed, "replay seed")
        query_count = _integer(self.query_count, "query_count", minimum=1)
        positives = _integer(self.positive_query_count, "positive_query_count")
        if positives > query_count:
            raise ValueError("positive_query_count cannot exceed query_count")
        for field_name in (
            "backend_checks",
            "base_confirmations",
            "race_extras",
            "weighted_base_work_numerator",
            "weighted_race_extra_work_numerator",
            "weighted_work_numerator",
            "cache_hits",
            "cache_misses",
            "admitted",
            "evictions",
            "expirations",
            "guess_count",
            "positive_guess_count",
            "guess_exposure_numerator",
            "positive_guess_exposure_numerator",
            "guess_exposure_denominator",
        ):
            _integer(getattr(self, field_name), field_name)
        if self.cache_hits + self.cache_misses != positives:
            raise ValueError("cache_hits plus cache_misses must equal positive_query_count")
        if self.base_confirmations != self.cache_misses:
            raise ValueError("each cache miss must produce one base confirmation")
        if self.backend_checks != self.base_confirmations + self.race_extras:
            raise ValueError("backend_checks must equal base_confirmations plus race_extras")
        if self.base_confirmations == 0 and self.race_extras > 0:
            raise ValueError("race_extras require a source base confirmation")
        if positives > 0 and self.backend_checks == 0:
            raise ValueError("positive replay events must perform backend checks")
        if self.admitted > self.base_confirmations:
            raise ValueError("cache admissions cannot exceed base confirmations")
        if self.cache_hits > 0 and self.admitted == 0:
            raise ValueError("cache hits require at least one source admission")
        if self.evictions + self.expirations > self.admitted:
            raise ValueError("cache removals cannot exceed admissions")
        if (self.base_confirmations == 0) != (self.weighted_base_work_numerator == 0):
            raise ValueError("weighted base work must preserve actual confirmed event weights")
        if (self.race_extras == 0) != (self.weighted_race_extra_work_numerator == 0):
            raise ValueError("weighted race work must preserve actual race-event weights")
        if self.weighted_work_numerator != (
            self.weighted_base_work_numerator + self.weighted_race_extra_work_numerator
        ):
            raise ValueError("weighted work must equal its raw event-weighted components")
        if (self.backend_checks == 0) != (self.weighted_work_numerator == 0):
            raise ValueError(
                "weighted_work_numerator must be zero exactly when backend_checks is zero"
            )
        epsilon = _finite_number(
            self.realized_epsilon,
            "realized_epsilon",
            minimum=0.0,
            maximum=1.0,
        )
        expected_epsilon = positives / query_count
        if epsilon != expected_epsilon:
            raise ValueError("realized_epsilon must be recomputed from integer query counts")
        compromise = _finite_number(
            self.realized_compromise_mass,
            "realized_compromise_mass",
            minimum=0.0,
        )
        worst = _finite_number(
            self.worst_family_bin_epsilon,
            "worst_family_bin_epsilon",
            minimum=0.0,
            maximum=1.0,
        )
        if type(self.family_results) is not tuple or not self.family_results:
            raise ValueError("family_results must be a nonempty immutable tuple")
        if any(type(item) is not ReplayFamilyResult for item in self.family_results):
            raise ValueError("family_results contains the wrong exact type")
        families = tuple(item.family for item in self.family_results)
        if families != tuple(sorted(set(families))):
            raise ValueError("family_results must be sorted and unique")
        aggregate_fields = {
            "query_count": sum(item.query_count for item in self.family_results),
            "positive_query_count": sum(item.positive_query_count for item in self.family_results),
            "base_confirmations": sum(item.base_confirmations for item in self.family_results),
            "race_extras": sum(item.race_extras for item in self.family_results),
            "weighted_base_work_numerator": sum(
                item.weighted_base_work_numerator for item in self.family_results
            ),
            "weighted_race_extra_work_numerator": sum(
                item.weighted_race_extra_work_numerator for item in self.family_results
            ),
            "backend_checks": sum(item.backend_checks for item in self.family_results),
            "cache_hits": sum(item.cache_hits for item in self.family_results),
            "cache_misses": sum(item.cache_misses for item in self.family_results),
            "admitted": sum(item.admitted for item in self.family_results),
            "evictions": sum(item.evictions for item in self.family_results),
            "expirations": sum(item.expirations for item in self.family_results),
            "guess_count": sum(item.guess_count for item in self.family_results),
            "positive_guess_count": sum(item.positive_guess_count for item in self.family_results),
            "guess_exposure_numerator": sum(
                item.guess_exposure_numerator for item in self.family_results
            ),
            "positive_guess_exposure_numerator": sum(
                item.positive_guess_exposure_numerator for item in self.family_results
            ),
        }
        for field_name, expected_value in aggregate_fields.items():
            if getattr(self, field_name) != expected_value:
                raise ValueError(f"{field_name} differs from family_results reconstruction")
        denominators = {item.guess_exposure_denominator for item in self.family_results}
        if denominators != {self.guess_exposure_denominator}:
            raise ValueError("guess exposure denominator differs across workload families")
        if epsilon != self.positive_query_count / self.query_count:
            raise ValueError("realized_epsilon differs from family aggregate counts")
        if compromise != min(item.realized_compromise_mass for item in self.family_results):
            raise ValueError(
                "seed compromise mass must be the conservative actual family realization"
            )
        if worst < max(item.realized_epsilon for item in self.family_results):
            raise ValueError("worst family-bin epsilon is below a family aggregate epsilon")
        object.__setattr__(self, "realized_epsilon", epsilon)
        object.__setattr__(self, "realized_compromise_mass", compromise)
        object.__setattr__(self, "worst_family_bin_epsilon", worst)

    def static_tuple(self) -> tuple[object, ...]:
        return (
            self.trace_id,
            self.query_corpus_id,
            self.filter_build_id,
            self.static_realization_id,
            self.query_count,
            self.positive_query_count,
            self.realized_epsilon,
            self.realized_compromise_mass,
            self.worst_family_bin_epsilon,
            tuple(item.static_tuple() for item in self.family_results),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "trace_id": self.trace_id,
            "query_corpus_id": self.query_corpus_id,
            "replay_transcript_id": self.replay_transcript_id,
            "filter_build_id": self.filter_build_id,
            "static_realization_id": self.static_realization_id,
            "seed": self.seed,
            "query_count": self.query_count,
            "positive_query_count": self.positive_query_count,
            "backend_checks": self.backend_checks,
            "base_confirmations": self.base_confirmations,
            "race_extras": self.race_extras,
            "weighted_base_work_numerator": self.weighted_base_work_numerator,
            "weighted_race_extra_work_numerator": self.weighted_race_extra_work_numerator,
            "weighted_work_numerator": self.weighted_work_numerator,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "admitted": self.admitted,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "guess_count": self.guess_count,
            "positive_guess_count": self.positive_guess_count,
            "guess_exposure_numerator": self.guess_exposure_numerator,
            "positive_guess_exposure_numerator": self.positive_guess_exposure_numerator,
            "guess_exposure_denominator": self.guess_exposure_denominator,
            "realized_epsilon": self.realized_epsilon,
            "realized_compromise_mass": self.realized_compromise_mass,
            "worst_family_bin_epsilon": self.worst_family_bin_epsilon,
            "family_results": [item.to_dict() for item in self.family_results],
        }

    @classmethod
    def from_dict(cls, value: object) -> ReplaySeedResult:
        mapping = _dict(value, "replay seed result")
        fields = set(cls.__dataclass_fields__)
        _exact_keys(mapping, fields, "replay seed result")
        values = {field: mapping[field] for field in fields if field != "family_results"}
        return cls(
            **values,
            family_results=tuple(
                ReplayFamilyResult.from_dict(item)
                for item in _list(mapping["family_results"], "family_results")
            ),
        )


@dataclass(frozen=True)
class ReplayOption:
    start_bin: int
    end_bin: int
    filter_memory_bytes: int
    cache_capacity: int
    cache_policy: str
    cache_entry_compact_bytes: int
    cache_policy_compact_bytes: int
    cache_probation_entry_compact_bytes: int
    cache_probation_policy_compact_bytes: int
    cache_fixed_metadata_bytes: int
    physical_memory_bytes: int
    memory_quanta: int
    conservative_compromise_quanta: int
    worst_realized_epsilon: float
    seed_results: tuple[ReplaySeedResult, ...]

    def __post_init__(self) -> None:
        _integer(self.start_bin, "option start_bin")
        _integer(self.end_bin, "option end_bin", minimum=1)
        if self.start_bin >= self.end_bin:
            raise ValueError("replay option interval must be nonempty")
        for field_name in (
            "filter_memory_bytes",
            "cache_capacity",
            "cache_entry_compact_bytes",
            "cache_policy_compact_bytes",
            "cache_probation_entry_compact_bytes",
            "cache_probation_policy_compact_bytes",
            "cache_fixed_metadata_bytes",
            "physical_memory_bytes",
            "memory_quanta",
            "conservative_compromise_quanta",
        ):
            _integer(getattr(self, field_name), f"option {field_name}")
        policy = _canonical_string(self.cache_policy, "option cache_policy")
        if policy not in _CACHE_POLICIES:
            raise ValueError("option cache_policy is unsupported")
        worst = _finite_number(
            self.worst_realized_epsilon,
            "worst_realized_epsilon",
            minimum=0.0,
            maximum=1.0,
        )
        object.__setattr__(self, "worst_realized_epsilon", worst)
        if type(self.seed_results) is not tuple or not self.seed_results:
            raise ValueError("option seed_results must be a nonempty immutable tuple")
        if any(type(result) is not ReplaySeedResult for result in self.seed_results):
            raise ValueError("option seed_results contains the wrong exact type")

    @property
    def coordinate(self) -> tuple[int, int, int, int, str]:
        return (
            self.start_bin,
            self.end_bin,
            self.filter_memory_bytes,
            self.cache_capacity,
            self.cache_policy,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "start_bin": self.start_bin,
            "end_bin": self.end_bin,
            "filter_memory_bytes": self.filter_memory_bytes,
            "cache_capacity": self.cache_capacity,
            "cache_policy": self.cache_policy,
            "cache_entry_compact_bytes": self.cache_entry_compact_bytes,
            "cache_policy_compact_bytes": self.cache_policy_compact_bytes,
            "cache_probation_entry_compact_bytes": (self.cache_probation_entry_compact_bytes),
            "cache_probation_policy_compact_bytes": (self.cache_probation_policy_compact_bytes),
            "cache_fixed_metadata_bytes": self.cache_fixed_metadata_bytes,
            "physical_memory_bytes": self.physical_memory_bytes,
            "memory_quanta": self.memory_quanta,
            "conservative_compromise_quanta": self.conservative_compromise_quanta,
            "worst_realized_epsilon": self.worst_realized_epsilon,
            "seed_results": [result.to_dict() for result in self.seed_results],
        }

    @classmethod
    def from_dict(cls, value: object) -> ReplayOption:
        mapping = _dict(value, "replay option")
        fields = set(cls.__dataclass_fields__)
        _exact_keys(mapping, fields, "replay option")
        values = {field: mapping[field] for field in fields if field != "seed_results"}
        return cls(
            **values,
            seed_results=tuple(
                ReplaySeedResult.from_dict(item)
                for item in _list(mapping["seed_results"], "option seed_results")
            ),
        )


@dataclass(frozen=True)
class FormalConsumerInputs:
    """Exact inputs for a downstream consumer; this object carries no PASS claim."""

    evidence_status: str
    table_id: str
    evidence_id: str
    option_coordinate: tuple[int, int, int, int, str]
    paired_seeds: tuple[int, ...]
    trace_id: str
    filter_build_ids: tuple[str, ...]
    static_realization_ids: tuple[str, ...]
    weighted_work_samples: tuple[Fraction, ...]
    epsilon_samples: tuple[Fraction, ...]
    query_counts: tuple[int, ...]
    positive_query_counts: tuple[int, ...]
    backend_checks: tuple[int, ...]
    cache_hits: tuple[int, ...]
    cache_misses: tuple[int, ...]
    admissions: tuple[int, ...]
    evictions: tuple[int, ...]
    expirations: tuple[int, ...]
    weighted_base_work_numerators: tuple[int, ...]
    weighted_race_extra_work_numerators: tuple[int, ...]
    guess_counts: tuple[int, ...]
    positive_guess_counts: tuple[int, ...]
    guess_exposure_numerators: tuple[int, ...]
    positive_guess_exposure_numerators: tuple[int, ...]
    guess_exposure_denominators: tuple[int, ...]
    family_results: tuple[tuple[ReplayFamilyResult, ...], ...]
    query_corpus_ids: tuple[str, ...]
    replay_transcript_ids: tuple[str, ...]
    verifier_cost_model: VerifierCostModel
    physical_memory_bytes: int
    memory_quanta: int
    resource_quantum_bytes: int
    compromise_quantum: float
    realized_compromise_masses: tuple[float, ...]
    ttl_seconds: float | None
    policy_semantics: CachePolicySemantics
    worst_region_epsilon_cap: float
    ci_method: str
    ci_confidence_level: float
    required_external_actions: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.evidence_status != EVIDENCE_STATUS:
            raise ValueError("formal consumer inputs cannot upgrade evidence status")
        _semantic_identity(self.table_id, "consumer table_id")
        _semantic_identity(self.evidence_id, "consumer evidence_id")
        if self.required_external_actions != (
            "reconstruct_raw_query_corpus",
            "replay_ordered_transcript_for_ttl_admission_eviction",
            "compute_paired_seed_confidence_interval",
            "apply_worst_epsilon_selection_cap",
        ):
            raise ValueError("formal consumer actions must remain explicit and incomplete")


def _table_expected_metadata(expected: ExpectedT4bContract) -> dict[str, object]:
    return {
        "expected_contract_id": expected.expected_contract_id,
        "split": expected.window(DESIGN_ROLE).to_dict(),
        "validation_trace_id": expected.validation_trace_id,
        "grid_implementation_id": expected.grid_implementation_id,
        "filter_implementation_id": expected.filter_implementation_id,
        "replay_implementation_id": expected.replay_implementation_id,
        "grid": expected.grid.to_dict(),
        "paired_seeds": list(expected.paired_seeds),
        "memory_accounting": expected.memory_accounting.to_dict(),
        "verifier_cost_model": expected.verifier_cost_model.to_dict(),
        "ttl_seconds": expected.ttl_seconds,
        "policy_semantics": [item.to_dict() for item in expected.policy_semantics],
        "resource_quantum_bytes": expected.resource_quantum_bytes,
        "compromise_quantum": expected.compromise_quantum,
        "worst_region_epsilon_cap": expected.worst_region_epsilon_cap,
        "ci_method": expected.ci_method,
        "ci_confidence_level": expected.ci_confidence_level,
        "certificate_gap_denominator": CERTIFICATE_GAP_DENOMINATOR,
        "evidence_status": EVIDENCE_STATUS,
    }


@dataclass(frozen=True)
class ReplayOptionTable:
    """Complete formal validation table anchored to trusted expected metadata."""

    schema_version: int
    evidence: FineBinEvidence
    options: tuple[ReplayOption, ...]

    def __post_init__(self) -> None:
        if _integer(self.schema_version, "table schema_version", minimum=1) != (
            REPLAY_OPTION_TABLE_SCHEMA_VERSION
        ):
            raise ValueError(f"table schema_version must be {REPLAY_OPTION_TABLE_SCHEMA_VERSION}")
        if type(self.evidence) is not FineBinEvidence:
            raise ValueError("ReplayOptionTable requires trusted FineBinEvidence")
        expected = self.evidence.expected
        if type(self.options) is not tuple or any(
            type(option) is not ReplayOption for option in self.options
        ):
            raise ValueError("replay options must be an immutable exact tuple")
        coordinates = tuple(option.coordinate for option in self.options)
        if coordinates != expected.grid.expected_coordinates:
            raise ValueError("replay options do not form the trusted complete Cartesian grid")

        static_by_key: dict[tuple[int, int, int, int], tuple[object, ...]] = {}
        query_by_key: dict[tuple[int, int, int], tuple[object, ...]] = {}
        build_ids_by_design: dict[tuple[int, int, int], dict[int, str]] = {}
        realization_ids_by_design: dict[tuple[int, int, int], dict[int, str]] = {}
        for option in self.options:
            interval_occupancy = sum(self.evidence.n_b[option.start_bin : option.end_bin])
            if interval_occupancy == 0:
                raise ValueError("replay table contains an all-empty occupancy interval")
            (
                entry_bytes,
                policy_bytes,
                probation_entry_bytes,
                probation_policy_bytes,
                fixed_bytes,
                total_bytes,
            ) = expected.memory_accounting.components(
                option.filter_memory_bytes,
                option.cache_capacity,
                option.cache_policy,
            )
            components = (
                option.cache_entry_compact_bytes,
                option.cache_policy_compact_bytes,
                option.cache_probation_entry_compact_bytes,
                option.cache_probation_policy_compact_bytes,
                option.cache_fixed_metadata_bytes,
                option.physical_memory_bytes,
            )
            if components != (
                entry_bytes,
                policy_bytes,
                probation_entry_bytes,
                probation_policy_bytes,
                fixed_bytes,
                total_bytes,
            ):
                raise ValueError("option physical memory component manifest mismatch")
            expected_memory_quanta = math.ceil(total_bytes / expected.resource_quantum_bytes)
            if option.memory_quanta != expected_memory_quanta:
                raise ValueError("option memory_quanta does not match physical bytes")
            if tuple(result.seed for result in option.seed_results) != expected.paired_seeds:
                raise ValueError("every replay option must retain the trusted paired seeds")
            caching_disabled = option.cache_capacity == 0 or option.cache_policy == "none"
            realized_masses: list[float] = []
            realized_epsilons: list[float] = []
            for result in option.seed_results:
                if result.trace_id != expected.validation_trace_id:
                    raise ValueError("replay result trace_id differs from trusted validation trace")
                query_key = (option.start_bin, option.end_bin, result.seed)
                query_tuple = (
                    result.trace_id,
                    result.query_corpus_id,
                    result.query_count,
                )
                previous_query = query_by_key.setdefault(query_key, query_tuple)
                if previous_query != query_tuple:
                    raise ValueError(
                        "query corpus or denominator changed across filter/cache options"
                    )
                if expected.ttl_seconds is None and result.expirations != 0:
                    raise ValueError("expiration count must be zero when TTL is disabled")
                if caching_disabled and any(
                    (
                        result.cache_hits,
                        result.admitted,
                        result.evictions,
                        result.expirations,
                    )
                ):
                    raise ValueError("cache accounting must be zero when caching is disabled")
                if not caching_disabled:
                    for family_result in result.family_results:
                        resident_entries = (
                            family_result.admitted
                            - family_result.evictions
                            - family_result.expirations
                        )
                        if resident_entries > option.cache_capacity:
                            raise ValueError("family cache conservation exceeds ending capacity")
                        if option.cache_policy == "always" and (
                            family_result.admitted != family_result.cache_misses
                        ):
                            raise ValueError(
                                "always-admit policy must admit every family cache miss"
                            )
                if option.filter_memory_bytes == 0:
                    if result.filter_build_id != NO_FILTER_BUILD_ID:
                        raise ValueError("m=0 must use the no-filter build sentinel ID")
                    if result.static_realization_id != M0_ALL_POSITIVE_REALIZATION_ID:
                        raise ValueError("m=0 must use the all-positive realization sentinel ID")
                    if result.positive_query_count != result.query_count:
                        raise ValueError("m=0 must realize every query as screen-positive")
                    if result.realized_epsilon != 1.0:
                        raise ValueError("m=0 must realize epsilon=1")
                    if any(
                        item.positive_guess_exposure_numerator != item.guess_exposure_numerator
                        for item in result.family_results
                    ):
                        raise ValueError(
                            "m=0 must retain every actual preregistered guess exposure"
                        )
                    if result.backend_checks == 0:
                        raise ValueError("m=0 with replay events must perform backend checks")
                static_key = (
                    option.start_bin,
                    option.end_bin,
                    option.filter_memory_bytes,
                    result.seed,
                )
                previous = static_by_key.setdefault(static_key, result.static_tuple())
                if previous != result.static_tuple():
                    raise ValueError(
                        "static realization changed across cache quota/admission policy"
                    )
                design_key = (
                    option.start_bin,
                    option.end_bin,
                    option.filter_memory_bytes,
                )
                build_ids_by_design.setdefault(design_key, {})[result.seed] = result.filter_build_id
                realization_ids_by_design.setdefault(design_key, {})[result.seed] = (
                    result.static_realization_id
                )
                realized_masses.append(result.realized_compromise_mass)
                realized_epsilons.append(result.worst_family_bin_epsilon)
            if option.worst_realized_epsilon != max(realized_epsilons):
                raise ValueError("worst_realized_epsilon does not match per-seed results")
            conservative_mass = min(realized_masses)
            expected_compromise_quanta = math.floor(conservative_mass / expected.compromise_quantum)
            if option.conservative_compromise_quanta != expected_compromise_quanta:
                raise ValueError("conservative_compromise_quanta does not match per-seed mass")
        for design_key, build_ids in build_ids_by_design.items():
            memory_bytes = design_key[2]
            realization_ids = realization_ids_by_design[design_key]
            if set(build_ids) != set(expected.paired_seeds):
                raise ValueError("static build IDs do not cover every paired seed")
            if memory_bytes == 0:
                if set(build_ids.values()) != {NO_FILTER_BUILD_ID}:
                    raise ValueError("m=0 filter build IDs may only share the sentinel")
                if set(realization_ids.values()) != {M0_ALL_POSITIVE_REALIZATION_ID}:
                    raise ValueError("m=0 realization IDs may only share the sentinel")
                continue
            if NO_FILTER_BUILD_ID in build_ids.values():
                raise ValueError("positive-memory filters cannot use the no-filter sentinel")
            if M0_ALL_POSITIVE_REALIZATION_ID in realization_ids.values():
                raise ValueError("positive-memory filters cannot use the m=0 realization sentinel")
            if len(set(build_ids.values())) != len(expected.paired_seeds):
                raise ValueError("positive-memory filter_build_id must be independent across seeds")
            if len(set(realization_ids.values())) != len(expected.paired_seeds):
                raise ValueError(
                    "positive-memory static_realization_id must be independent across seeds"
                )

    @property
    def expected(self) -> ExpectedT4bContract:
        return self.evidence.expected

    @property
    def evidence_id(self) -> str:
        return self.evidence.evidence_id

    @property
    def table_id(self) -> str:
        return _canonical_hash(self._identity_payload())

    @property
    def evidence_status(self) -> str:
        return EVIDENCE_STATUS

    def formal_consumer_inputs(self, option: ReplayOption) -> FormalConsumerInputs:
        """Return exact samples and reconstruction IDs without executing a claim gate."""

        if type(option) is not ReplayOption:
            raise ValueError("formal consumer option has the wrong exact type")
        matching = [
            candidate for candidate in self.options if candidate.coordinate == option.coordinate
        ]
        if len(matching) != 1 or matching[0] != option:
            raise ValueError("formal consumer option is not the bound table option")
        semantics = next(
            item
            for item in self.expected.policy_semantics
            if item.cache_policy == option.cache_policy
        )
        cost_model = self.expected.verifier_cost_model
        return FormalConsumerInputs(
            evidence_status=EVIDENCE_STATUS,
            table_id=self.table_id,
            evidence_id=self.evidence_id,
            option_coordinate=option.coordinate,
            paired_seeds=self.expected.paired_seeds,
            trace_id=self.expected.validation_trace_id,
            filter_build_ids=tuple(result.filter_build_id for result in option.seed_results),
            static_realization_ids=tuple(
                result.static_realization_id for result in option.seed_results
            ),
            weighted_work_samples=tuple(
                cost_model.work(result.weighted_work_numerator) for result in option.seed_results
            ),
            epsilon_samples=tuple(
                Fraction(result.positive_query_count, result.query_count)
                for result in option.seed_results
            ),
            query_counts=tuple(result.query_count for result in option.seed_results),
            positive_query_counts=tuple(
                result.positive_query_count for result in option.seed_results
            ),
            backend_checks=tuple(result.backend_checks for result in option.seed_results),
            cache_hits=tuple(result.cache_hits for result in option.seed_results),
            cache_misses=tuple(result.cache_misses for result in option.seed_results),
            admissions=tuple(result.admitted for result in option.seed_results),
            evictions=tuple(result.evictions for result in option.seed_results),
            expirations=tuple(result.expirations for result in option.seed_results),
            weighted_base_work_numerators=tuple(
                result.weighted_base_work_numerator for result in option.seed_results
            ),
            weighted_race_extra_work_numerators=tuple(
                result.weighted_race_extra_work_numerator for result in option.seed_results
            ),
            guess_counts=tuple(result.guess_count for result in option.seed_results),
            positive_guess_counts=tuple(
                result.positive_guess_count for result in option.seed_results
            ),
            guess_exposure_numerators=tuple(
                result.guess_exposure_numerator for result in option.seed_results
            ),
            positive_guess_exposure_numerators=tuple(
                result.positive_guess_exposure_numerator for result in option.seed_results
            ),
            guess_exposure_denominators=tuple(
                result.guess_exposure_denominator for result in option.seed_results
            ),
            family_results=tuple(result.family_results for result in option.seed_results),
            query_corpus_ids=tuple(result.query_corpus_id for result in option.seed_results),
            replay_transcript_ids=tuple(
                result.replay_transcript_id for result in option.seed_results
            ),
            verifier_cost_model=cost_model,
            physical_memory_bytes=option.physical_memory_bytes,
            memory_quanta=option.memory_quanta,
            resource_quantum_bytes=self.expected.resource_quantum_bytes,
            compromise_quantum=self.expected.compromise_quantum,
            realized_compromise_masses=tuple(
                result.realized_compromise_mass for result in option.seed_results
            ),
            ttl_seconds=self.expected.ttl_seconds,
            policy_semantics=semantics,
            worst_region_epsilon_cap=self.expected.worst_region_epsilon_cap,
            ci_method=self.expected.ci_method,
            ci_confidence_level=self.expected.ci_confidence_level,
            required_external_actions=(
                "reconstruct_raw_query_corpus",
                "replay_ordered_transcript_for_ttl_admission_eviction",
                "compute_paired_seed_confidence_interval",
                "apply_worst_epsilon_selection_cap",
            ),
        )

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "evidence_id": self.evidence_id,
            **_table_expected_metadata(self.expected),
            "options": [option.to_dict() for option in self.options],
        }

    def to_dict(self) -> dict[str, object]:
        result = self._identity_payload()
        result["table_id"] = self.table_id
        return result

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(
        cls,
        value: object,
        *,
        evidence: FineBinEvidence,
        expected: ExpectedT4bContract,
    ) -> ReplayOptionTable:
        if type(expected) is not ExpectedT4bContract:
            raise ValueError("formal table loading requires a trusted expected contract")
        if type(evidence) is not FineBinEvidence:
            raise ValueError("formal table loading requires trusted fine-bin evidence")
        if evidence.expected_contract_id != expected.expected_contract_id:
            raise ValueError("evidence and trusted expected contract identities differ")
        mapping = _dict(value, "replay option table")
        fields = {"schema_version", "table_id", "evidence_id", "options"} | set(
            _table_expected_metadata(expected)
        )
        _exact_keys(mapping, fields, "replay option table")
        _exact_value(
            mapping["schema_version"],
            REPLAY_OPTION_TABLE_SCHEMA_VERSION,
            "replay option table.schema_version",
        )
        _exact_value(mapping["evidence_id"], evidence.evidence_id, "table.evidence_id")
        for field, expected_value in _table_expected_metadata(expected).items():
            _exact_value(mapping[field], expected_value, f"table trusted metadata.{field}")
        result = cls(
            schema_version=mapping["schema_version"],
            evidence=evidence,
            options=tuple(
                ReplayOption.from_dict(item) for item in _list(mapping["options"], "replay options")
            ),
        )
        supplied = _semantic_identity(mapping["table_id"], "table_id")
        if supplied != result.table_id:
            raise ValueError("replay option table identity mismatch")
        return result

    @classmethod
    def from_json(
        cls,
        text: str,
        *,
        evidence: FineBinEvidence,
        expected: ExpectedT4bContract,
    ) -> ReplayOptionTable:
        return cls.from_dict(
            _load_json_object(text, "replay option table JSON"),
            evidence=evidence,
            expected=expected,
        )
