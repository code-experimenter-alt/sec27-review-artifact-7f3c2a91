#!/usr/bin/env python3
"""Controlled E4 replay benchmark over observed filter false positives.

Rows are conditioned on nonmembers that actually produced a positive in the
fresh filter instance. The runner never substitutes an analytic false-positive
rate or a synthetic Boolean oracle for filter execution. It does not measure
service legitimate-request p99, so no row can adjudicate G2 by itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation, localcontext
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, MutableMapping, Sequence

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dataplane.negative_cache import (  # noqa: E402
    EvictionPolicy,
    LruPolicy,
    NegativeCache,
    NegativeKey,
    NegativeKeyDeriver,
    TinyLfuPolicy,
)
from dataplane.singleflight import Singleflight  # noqa: E402
from dataplane.types import (  # noqa: E402
    DirectoryStatus,
    DirectoryView,
)
from experiments.runners.filter_bench import (  # noqa: E402
    RESULT_SCHEMA,
    SyntheticCredentialSet,
)
from reference.adaptive import (  # noqa: E402
    AdaptiveCuckooFilter,
    ExactLfuPolicy,
    FutureReuseOraclePolicy,
)
from reference.filters import CuckooFilter, ScreenQuery, deep_sizeof  # noqa: E402

CONFIG_SCHEMA_VERSION = 4
ROW_SCHEMA = "traps-e4-controlled-replay-row-v3"
TRACE_SCHEMA = "traps-e4-generated-trace-summary-v2"
FORMAL_CONTRACT_ID = "traps-e4-formal-v4-10x93"
SMOKE_CONTRACT_ID = "traps-e4-smoke-v4"
SOURCE_ATTESTATION_SCHEMA = "traps-e4-source-attestation-v1"
NUMERIC_CONTRACT_ID = "traps-e4-field-decimal-v1"
NUMERIC_DECIMAL_PRECISION = 80
GIT_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
FORMAL_SEEDS = tuple(range(7100, 7110))
EXPECTED_FORMAL_POINTS_PER_SEED = 93
EXPECTED_FORMAL_ROWS = len(FORMAL_SEEDS) * EXPECTED_FORMAL_POINTS_PER_SEED
REQUIRED_MULTIPLICITIES = {2, 10, 100, 1_000, 10_000}
REQUIRED_METHODS = {
    "static_no_cache",
    "lru",
    "lfu",
    "tinylfu",
    "fixed_ttl",
    "future_oracle",
    "adaptive_cuckoo",
}

G2_CHECKS_PER_TUPLE_MAX = 1.1
G2_STATIC_WORK_IMPROVEMENT_MIN = 10.0
G2_LEGITIMATE_P99_REGRESSION_MAX_FRACTION = 0.05
ADAPTIVE_INVARIANT_PERIOD_EVENTS = 256
CACHE_MEMORY_LAYOUT_VERSION = "packed-negative-cache-v1"
CACHE_HASH_TABLE_MAX_LOAD = 0.80
CACHE_ENTRY_FIELDS_BYTES = {
    "negative_key_id_u64": 8,
    "negative_digest_256": 32,
    "stable_account_handle_128": 16,
    "account_generation_u64": 8,
    "credential_set_version_u64": 8,
    "region_u32": 4,
    "inserted_at_u64": 8,
    "expires_at_u64": 8,
}
CACHE_ALLOCATOR_OVERHEAD_BYTES_PER_SLOT = 16
CACHE_POLICY_BYTES_PER_SLOT = {"lru": 8, "fixed_ttl": 8, "lfu": 16}
CACHE_HASH_TABLE_MAX_LOAD_NUMERATOR = 4
CACHE_HASH_TABLE_MAX_LOAD_DENOMINATOR = 5
CACHE_FIXED_FIELDS_BYTES = {
    "magic_and_schema": 16,
    "capacity_and_size": 16,
    "ttl_and_quota_metadata": 24,
    "allocator_header": 8,
}

# Each JSON-number field is canonicalized independently. These are serialization
# quanta, not validator tolerances: v4 validation still requires exact type/value.
ROW_FLOAT_QUANTA = MappingProxyType(
    {
        "backend_checks_per_distinct_invalid": Decimal("1e-12"),
        "backend_work_amplification_per_tuple": Decimal("1e-12"),
        "backend_work_fraction_of_static": Decimal("1e-15"),
        "backend_work_reduction_factor_vs_static": Decimal("1e-12"),
        "false_positive_discovery_observed_fpr": Decimal("1e-15"),
        "filter_actual_load": Decimal("1e-15"),
        "filter_load_acceptance_max": Decimal("1e-15"),
        "filter_load_acceptance_min": Decimal("1e-15"),
        "filter_load_delta_from_target": Decimal("1e-15"),
        "filter_parameters.analytic_fpr_standard": Decimal("1e-15"),
        "filter_parameters.load_factor": Decimal("1e-15"),
        "filter_target_load": Decimal("1e-15"),
        "memory_cache_layout_manifest.hash_table_max_load": Decimal("1e-15"),
        "observed_first_seen_ffr": Decimal("1e-15"),
        "observed_request_weighted_ffr": Decimal("1e-15"),
        "replay_request_amplification": Decimal("1e-12"),
        "trace_summary.event_interval_seconds": Decimal("1e-15"),
        "trace_summary.generated_distinct_tuple_rate_per_second": Decimal("1e-9"),
        "trace_summary.generated_request_rate_per_second": Decimal("1e-9"),
        "trace_summary.logical_end_seconds": Decimal("1e-15"),
        "trace_summary.logical_start_seconds": Decimal("1e-15"),
        "trace_summary.logical_window_seconds": Decimal("1e-15"),
        "worst_region_ffr": Decimal("1e-15"),
    }
)
AGGREGATE_FLOAT_QUANTA = MappingProxyType(
    {
        "backend_checks_per_tuple": Decimal("1e-12"),
        "generated_request_rate_per_second_max": Decimal("1e-9"),
        "generated_request_rate_per_second_min": Decimal("1e-9"),
        "paired_backend_work_fraction_of_static": Decimal("1e-15"),
        "paired_backend_checks_saved_vs_static": Decimal("1e-6"),
        "paired_static_reduction_factor_finite": Decimal("1e-12"),
    }
)
DERIVED_ROW_FLOAT_PATHS = frozenset(
    {
        "backend_checks_per_distinct_invalid",
        "backend_work_amplification_per_tuple",
        "backend_work_fraction_of_static",
        "backend_work_reduction_factor_vs_static",
        "false_positive_discovery_observed_fpr",
        "filter_actual_load",
        "filter_load_delta_from_target",
        "filter_parameters.analytic_fpr_standard",
        "filter_parameters.load_factor",
        "observed_first_seen_ffr",
        "observed_request_weighted_ffr",
        "replay_request_amplification",
        "trace_summary.generated_distinct_tuple_rate_per_second",
        "trace_summary.generated_request_rate_per_second",
        "trace_summary.logical_end_seconds",
        "trace_summary.logical_window_seconds",
        "worst_region_ffr",
    }
)
FROZEN_NUMERIC_CONTRACT = {
    "schema": NUMERIC_CONTRACT_ID,
    "decimal_context_precision": NUMERIC_DECIMAL_PRECISION,
    "rounding": "ROUND_HALF_EVEN",
    "validation": "exact_json_type_and_canonical_value",
    "gate_comparison": "exact_unquantized_decimal_ratio",
    "row_field_quanta": {
        path: format(quantum, "E").lower()
        for path, quantum in ROW_FLOAT_QUANTA.items()
    },
    "aggregate_field_quanta": {
        path: format(quantum, "E").lower()
        for path, quantum in AGGREGATE_FLOAT_QUANTA.items()
    },
}


def _to_decimal(value: int | float | Decimal) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise TypeError("portable numeric input must be an integer, float, or Decimal")
    try:
        result = value if isinstance(value, Decimal) else Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError("portable numeric input is not a finite decimal") from error
    if not result.is_finite():
        raise ValueError("portable numeric input must be finite")
    return result


def _canonical_row_float(path: str, value: int | float | Decimal) -> float:
    try:
        quantum = ROW_FLOAT_QUANTA[path]
    except KeyError as error:
        raise KeyError(f"undeclared E4 row float path: {path}") from error
    with localcontext() as context:
        context.prec = NUMERIC_DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        canonical = _to_decimal(value).quantize(quantum)
    result = float(canonical)
    if not math.isfinite(result):
        raise ValueError(f"canonical E4 row float is not finite: {path}")
    return 0.0 if result == 0.0 else result


def _decimal_ratio(numerator: int | Decimal, denominator: int | Decimal) -> Decimal:
    with localcontext() as context:
        context.prec = NUMERIC_DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        denominator_decimal = _to_decimal(denominator)
        if denominator_decimal == 0:
            raise ZeroDivisionError("portable E4 ratio denominator is zero")
        return _to_decimal(numerator) / denominator_decimal


def _row_ratio(path: str, numerator: int | Decimal, denominator: int | Decimal) -> float:
    return _canonical_row_float(path, _decimal_ratio(numerator, denominator))


def _row_product(path: str, *values: int | float | Decimal) -> float:
    with localcontext() as context:
        context.prec = NUMERIC_DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        result = Decimal(1)
        for value in values:
            result *= _to_decimal(value)
    return _canonical_row_float(path, result)


def _row_difference(
    path: str, left: int | float | Decimal, right: int | float | Decimal
) -> float:
    with localcontext() as context:
        context.prec = NUMERIC_DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        result = _to_decimal(left) - _to_decimal(right)
    return _canonical_row_float(path, result)


def _ratio_at_most(
    numerator: int | Decimal, denominator: int | Decimal, threshold: int | float | Decimal
) -> bool:
    return _decimal_ratio(numerator, denominator) <= _to_decimal(threshold)


def _ratio_at_least(
    numerator: int | Decimal, denominator: int | Decimal, threshold: int | float | Decimal
) -> bool:
    return _decimal_ratio(numerator, denominator) >= _to_decimal(threshold)


def _canonical_cuckoo_analytic_fpr(
    *, n_items: int, slots: int, fingerprint_bits: int, bucket_size: int
) -> float:
    with localcontext() as context:
        context.prec = NUMERIC_DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        load = _decimal_ratio(n_items, slots)
        fingerprint_mask = Decimal((1 << fingerprint_bits) - 1)
        per_slot_match = load / fingerprint_mask
        exact_fpr = Decimal(1) - (Decimal(1) - per_slot_match) ** (2 * bucket_size)
    return _canonical_row_float("filter_parameters.analytic_fpr_standard", exact_fpr)


def _strict_typed_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, Mapping):
        if len(actual) != len(expected):
            return False
        unmatched_actual_keys = list(actual)
        for expected_key, expected_value in expected.items():
            matches = [
                key
                for key in unmatched_actual_keys
                if _strict_typed_equal(key, expected_key)
            ]
            if len(matches) != 1:
                return False
            actual_key = matches[0]
            unmatched_actual_keys.remove(actual_key)
            if not _strict_typed_equal(actual[actual_key], expected_value):
                return False
        return True
    if isinstance(expected, (list, tuple)):
        return len(actual) == len(expected) and all(
            _strict_typed_equal(left, right)
            for left, right in zip(actual, expected, strict=True)
        )
    if isinstance(expected, float) and expected == 0.0:
        return actual == expected and math.copysign(1.0, actual) == math.copysign(
            1.0, expected
        )
    return actual == expected


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate mapping key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _align_up(value: int, alignment: int = 8) -> int:
    return ((value + alignment - 1) // alignment) * alignment


_CACHE_ENTRY_FIELD_BYTES = sum(CACHE_ENTRY_FIELDS_BYTES.values())
_CACHE_ENTRY_ALIGNED_BYTES = _align_up(_CACHE_ENTRY_FIELD_BYTES)
_CACHE_HASH_SLACK_BYTES_PER_SLOT = (
    (
        _CACHE_ENTRY_ALIGNED_BYTES * CACHE_HASH_TABLE_MAX_LOAD_DENOMINATOR
        + CACHE_HASH_TABLE_MAX_LOAD_NUMERATOR
        - 1
    )
    // CACHE_HASH_TABLE_MAX_LOAD_NUMERATOR
    - _CACHE_ENTRY_ALIGNED_BYTES
)
CACHE_ENTRY_BYTES_PER_SLOT = (
    _CACHE_ENTRY_ALIGNED_BYTES
    + _CACHE_HASH_SLACK_BYTES_PER_SLOT
    + CACHE_ALLOCATOR_OVERHEAD_BYTES_PER_SLOT
)
CACHE_FIXED_METADATA_BYTES = _align_up(sum(CACHE_FIXED_FIELDS_BYTES.values()))
SOURCE_STATUS_SCOPE = "repository excluding generated experiments/outputs and tmp"
SOURCE_ATTESTATION_FIELDS = frozenset(
    {
        "schema",
        "config_contract_id",
        "config_hash",
        "row_schema",
        "trusted_expected_commit",
        "source_hostname",
        "source_checkout_absolute",
        "shard_index",
        "shard_count",
        "source_commit_before",
        "source_commit_after",
        "source_status_scope",
        "source_status_before",
        "source_status_after",
        "run_started_utc",
        "run_ended_utc",
        "verified_utc",
        "row_count",
        "first_row_timestamp_utc",
        "last_row_timestamp_utc",
    }
)
SOURCE_ATTESTATION_CONTRACT = {
    "schema": SOURCE_ATTESTATION_SCHEMA,
    "required_for_formal": True,
    "trust_model": "external_procedural_trusted_input_not_cryptographic_proof",
}
SMOKE_ATTESTATION_CONTRACT = {
    "schema": SOURCE_ATTESTATION_SCHEMA,
    "required_for_formal": False,
    "trust_model": "diagnostic_smoke_does_not_require_source_attestation",
}
FRONTEND_MEASUREMENT_SCOPE = (
    "not measured by E4; deterministic backend/cache semantics only; "
    "E7 owns all latency evidence"
)

FROZEN_GATE_POLICY = {
    "smoke_never_satisfies_g2": True,
    "g2_checks_per_tuple_max": G2_CHECKS_PER_TUPLE_MAX,
    "g2_static_work_improvement_min": G2_STATIC_WORK_IMPROVEMENT_MIN,
    "g2_legitimate_p99_regression_max_fraction": (
        G2_LEGITIMATE_P99_REGRESSION_MAX_FRACTION
    ),
    "phase1_static_baseline_source": "E1_E2_phase1_required",
    "service_p99_source": "E7_service_benchmark_required",
    "runner_does_not_adjudicate_gate": True,
}

FROZEN_FORMAL_CONTRACT = {
    "schema_version": CONFIG_SCHEMA_VERSION,
    "contract_id": FORMAL_CONTRACT_ID,
    "profile": "formal",
    "status": "RESEARCH_IN_PROGRESS",
    "evidence_tier": "formal_replay",
    "require_clean_git": True,
    "source_attestation": SOURCE_ATTESTATION_CONTRACT,
    "numeric_contract": FROZEN_NUMERIC_CONTRACT,
    "output": "experiments/outputs/raw/e4_replay.jsonl",
    "seeds": list(FORMAL_SEEDS),
    "methods": [
        "static_no_cache",
        "lru",
        "lfu",
        "tinylfu",
        "fixed_ttl",
        "future_oracle",
        "adaptive_cuckoo",
    ],
    "dataset": {
        "account_count": 3680,
        "seed": 20260805,
        "false_positive_search_limit": 2_000_000,
    },
    "filter": {
        "fingerprint_bits": 8,
        "bucket_size": 4,
        "target_load": 0.90,
        "actual_load_acceptance_min": 0.89,
        "actual_load_acceptance_max": 0.91,
        "max_kicks": 500,
        "max_seed_attempts": 30,
    },
    "cache": {
        "retention_ttl_seconds": 3600.0,
        "fixed_ttl_seconds": 0.01,
        "tinylfu_reset_after": 100_000,
    },
    "replay": {
        "multiplicities": [2, 10, 100, 1_000, 10_000],
        "modes": ["sequential", "concurrent"],
        "concurrency": 32,
        "event_interval_seconds": 0.000001,
        "concurrent_overlap_model": "frozen_batch_by_concurrency_width",
        "max_waiters_per_key": 64,
        "max_waiters_global": 4096,
        "waiter_timeout_seconds": 30.0,
    },
    "scenarios": [
        {
            "name": "resident_capacity",
            "key_count": 16,
            "order": "grouped",
            "cache_capacity": 32,
        },
        {
            "name": "over_capacity_churn_moderate",
            "key_count": 128,
            "order": "round_robin",
            "cache_capacity": 96,
            "multiplicities": [100],
            "modes": ["sequential"],
        },
        {
            "name": "over_capacity_churn_severe",
            "key_count": 128,
            "order": "round_robin",
            "cache_capacity": 32,
            "multiplicities": [1_000],
            "modes": ["sequential"],
        },
        {
            "name": "per_account_quota_tight",
            "key_count": 8,
            "order": "round_robin",
            "cache_capacity": 64,
            "max_entries_per_account": 1,
            "same_account": True,
            "multiplicities": [100],
            "modes": ["sequential"],
        },
        {
            "name": "per_account_quota_relaxed",
            "key_count": 8,
            "order": "round_robin",
            "cache_capacity": 64,
            "max_entries_per_account": 4,
            "same_account": True,
            "multiplicities": [1_000],
            "modes": ["sequential"],
        },
    ],
    "gate_policy": FROZEN_GATE_POLICY,
}

REPLAY_ROW_FIELDS = frozenset(RESULT_SCHEMA) | {
    "adaptive_feedback_attempts",
    "adaptive_invariant_check_period_events",
    "adaptive_invariant_checks",
    "adaptive_invariant_violations",
    "adaptive_updates",
    "backend_work_amplification_per_tuple",
    "backend_work_fraction_of_static",
    "backend_work_reduction_factor_vs_static",
    "cache_account_quota_pressure",
    "cache_admission_rejected",
    "cache_admissions",
    "cache_capacity_entries",
    "cache_expirations",
    "cache_global_quota_pressure",
    "cache_max_entries_per_account",
    "cache_memory_match_eligible",
    "cache_memory_match_exclusion_reason",
    "cache_policy",
    "cache_updates",
    "comparison_reference_method",
    "config_contract_id",
    "cpu_count",
    "evidence_tier",
    "experiment",
    "external_baseline_status",
    "external_baselines_included",
    "false_positive_discovery_count",
    "false_positive_discovery_observed_fpr",
    "false_positive_discovery_positive_set_id",
    "false_positive_discovery_queries",
    "false_positive_discovery_required_same_account",
    "false_positive_discovery_required_total",
    "false_positive_discovery_search_limit",
    "false_positive_discovery_stopping_rule",
    "filter_actual_load",
    "filter_load_acceptance_max",
    "filter_load_acceptance_min",
    "filter_load_acceptance_pass",
    "filter_load_delta_from_target",
    "filter_parameters",
    "filter_target_load",
    "first_seen_positive_forwards",
    "frontend_measurement_scope",
    "g2_capacity_condition_met",
    "g2_checks_per_tuple_le_1_1",
    "g2_gate_eligible_row",
    "g2_gate_status",
    "g2_legitimate_p99_regression_le_5pct",
    "g2_replay_component_criteria_pass",
    "g2_replay_component_eligible",
    "g2_row_criteria_pass",
    "g2_static_work_improvement_ge_10x",
    "git_dirty",
    "git_status_scope",
    "host_platform",
    "hostname",
    "legitimate_latency_method",
    "legitimate_p99_regression_fraction_vs_static",
    "legitimate_p99_required_source",
    "legitimate_static_p99_ms",
    "member_false_negatives",
    "member_validation_count",
    "memory_cache_entry_bytes_per_slot",
    "memory_cache_entry_compact_bytes",
    "memory_cache_fixed_metadata_bytes",
    "memory_cache_layout_manifest",
    "memory_cache_policy_bytes_per_slot",
    "memory_cache_policy_compact_bytes",
    "memory_cache_policy_python_bytes",
    "memory_cache_python_bytes",
    "memory_total_edge_bytes",
    "numeric_contract_id",
    "oracle_deployable",
    "oracle_future_input_count",
    "oracle_schedule_alignment_mismatches",
    "oracle_schedule_valid",
    "point_id",
    "python_version",
    "replay_mode",
    "replay_multiplicity",
    "replay_order",
    "replay_request_amplification",
    "research_status",
    "row_schema",
    "scenario_name",
    "screen_kind",
    "screen_positive_forwards",
    "screen_python_bytes",
    "seed_shard_ordinal",
    "selection_conditioned_on_observed_false_positive",
    "selected_query_set_id",
    "shard_count",
    "shard_index",
    "singleflight_enabled",
    "singleflight_idle_python_bytes",
    "singleflight_leaders",
    "singleflight_overlap_delay_seconds",
    "singleflight_overlap_model",
    "singleflight_peak_python_bytes",
    "singleflight_peak_waiters",
    "singleflight_per_waiter_state_bytes",
    "singleflight_waiter_memory_scope",
    "singleflight_waiter_queue_peak_bytes",
    "singleflight_waiter_timeouts",
    "source_metadata",
    "source_metadata_complete",
    "source_metadata_schema_version",
    "static_backend_checks_reference",
    "static_reference_role",
    "timestamp_utc",
    "trace_summary",
}


@dataclass(frozen=True)
class MethodSpec:
    config_name: str
    method: str
    screen_kind: str
    cache_policy: str | None
    singleflight: bool
    adaptive: bool = False


METHODS = {
    "static_no_cache": MethodSpec(
        "static_no_cache",
        "static_cuckoo_no_cache",
        "static_cuckoo",
        None,
        False,
    ),
    "lru": MethodSpec(
        "lru",
        "static_cuckoo_exact_lru",
        "static_cuckoo",
        "lru",
        True,
    ),
    "lfu": MethodSpec(
        "lfu",
        "static_cuckoo_exact_lfu",
        "static_cuckoo",
        "lfu",
        True,
    ),
    "tinylfu": MethodSpec(
        "tinylfu",
        "static_cuckoo_tinylfu_style_scan_resistant",
        "static_cuckoo",
        "tinylfu",
        True,
    ),
    "fixed_ttl": MethodSpec(
        "fixed_ttl",
        "static_cuckoo_fixed_ttl_exact_lru",
        "static_cuckoo",
        "fixed_ttl",
        True,
    ),
    "future_oracle": MethodSpec(
        "future_oracle",
        "static_cuckoo_offline_future_reuse_oracle",
        "static_cuckoo",
        "future_oracle",
        True,
    ),
    "adaptive_cuckoo": MethodSpec(
        "adaptive_cuckoo",
        "adaptive_cuckoo_d2_c4_no_negative_cache",
        "adaptive_cuckoo",
        None,
        True,
        adaptive=True,
    ),
}
METHODS_BY_RESULT_NAME = {spec.method: spec for spec in METHODS.values()}


@dataclass(frozen=True)
class Scenario:
    name: str
    key_count: int
    order: str
    cache_capacity: int
    max_entries_per_account: int | None
    same_account: bool
    multiplicities: tuple[int, ...]
    modes: tuple[str, ...]
    event_interval_seconds: float


@dataclass(frozen=True)
class ReplayEvent:
    query: ScreenQuery
    view: DirectoryView
    negative_key: NegativeKey
    occurrence: int
    logical_time: float


@dataclass(frozen=True)
class Discovery:
    queries: tuple[ScreenQuery, ...]
    scanned: int
    false_positives: int

    @property
    def observed_fpr(self) -> float:
        return _row_ratio(
            "false_positive_discovery_observed_fpr",
            self.false_positives,
            self.scanned,
        )


@dataclass(frozen=True)
class CacheMemoryAccounting:
    entry_compact_bytes: int
    policy_compact_bytes: int | None
    fixed_metadata_bytes: int
    total_compact_bytes: int | None
    entry_bytes_per_slot: int
    policy_bytes_per_slot: int | None
    memory_match_eligible: bool
    exclusion_reason: str | None


def _canonical_hash(value: Any) -> str:
    material = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(material).hexdigest()


def _query_set_id(queries: Sequence[ScreenQuery]) -> str:
    digest = hashlib.sha256(b"TRAPS/E4/query-set/v1\x00")
    digest.update(len(queries).to_bytes(8, "big"))
    for query in queries:
        digest.update(query.account_index.to_bytes(8, "big"))
        digest.update(query.token)
    return digest.hexdigest()


def _cache_layout_manifest() -> dict[str, Any]:
    return {
        "schema": CACHE_MEMORY_LAYOUT_VERSION,
        "entry_fields_bytes": dict(CACHE_ENTRY_FIELDS_BYTES),
        "entry_fields_total_bytes": _CACHE_ENTRY_FIELD_BYTES,
        "entry_aligned_bytes": _CACHE_ENTRY_ALIGNED_BYTES,
        "hash_table_max_load": _canonical_row_float(
            "memory_cache_layout_manifest.hash_table_max_load",
            CACHE_HASH_TABLE_MAX_LOAD,
        ),
        "hash_table_slack_bytes_per_slot": _CACHE_HASH_SLACK_BYTES_PER_SLOT,
        "allocator_overhead_bytes_per_slot": CACHE_ALLOCATOR_OVERHEAD_BYTES_PER_SLOT,
        "entry_bytes_per_slot": CACHE_ENTRY_BYTES_PER_SLOT,
        "fixed_fields_bytes": dict(CACHE_FIXED_FIELDS_BYTES),
        "fixed_metadata_bytes": CACHE_FIXED_METADATA_BYTES,
        "policy_bytes_per_slot": dict(CACHE_POLICY_BYTES_PER_SLOT),
        "scope": (
            "packed in-memory capacity allocation; Python object-graph measurements "
            "are reported separately"
        ),
    }


def _assert_adaptive_screen_invariants(screen: AdaptiveCuckooFilter) -> None:
    """Validate exact backing/fingerprint correspondence at a stable snapshot."""

    with screen._lock:
        if len(screen._keys) != screen._slot_count:
            raise RuntimeError("adaptive filter backing-table length changed")
        occupied = 0
        represented: set[bytes] = set()
        slots_per_table = screen.bucket_count * screen.bucket_size
        for slot, key in enumerate(screen._keys):
            if key is None:
                continue
            occupied += 1
            if key in represented:
                raise RuntimeError("adaptive filter contains a duplicate represented key")
            represented.add(key)
            table, table_slot = divmod(slot, slots_per_table)
            bucket, offset = divmod(table_slot, screen.bucket_size)
            if table not in (0, 1) or screen._bucket(key, table) != bucket:
                raise RuntimeError("adaptive filter backing key is in the wrong bucket")
            if screen._fingerprints.get(slot) != screen._fingerprint(key, offset):
                raise RuntimeError("adaptive filter fingerprint/backing key mismatch")
            if not screen.query(ScreenQuery(0, key)).positive:
                raise RuntimeError("adaptive filter lost a represented member")
        if occupied != screen.n_items:
            raise RuntimeError("adaptive filter occupancy does not match n_items")


def _git_metadata() -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
        status = subprocess.run(
            [
                "git",
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--",
                ".",
                ":(exclude)experiments/outputs/**",
                ":(exclude)tmp/**",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        return {
            "commit": None,
            "status": None,
            "git_dirty": None,
            "git_error": str(error),
            "git_status_scope": SOURCE_STATUS_SCOPE,
            "checkout_absolute": str(ROOT.resolve()),
        }
    return {
        "commit": commit or None,
        "status": status,
        "git_dirty": bool(status.strip()),
        "git_error": None,
        "git_status_scope": SOURCE_STATUS_SCOPE,
        "checkout_absolute": str(ROOT.resolve()),
    }


def _require_expected_commit(expected_commit: str | None) -> str:
    if not isinstance(expected_commit, str) or GIT_COMMIT_RE.fullmatch(expected_commit) is None:
        raise RuntimeError(
            "formal E4 replay requires an explicit trusted 40-character expected commit"
        )
    return expected_commit


def _enforce_git_policy(
    config: Mapping[str, Any],
    git: Mapping[str, Any],
    expected_commit: str | None = None,
) -> None:
    if not config["require_clean_git"]:
        return
    trusted_commit = _require_expected_commit(expected_commit)
    if git.get("git_error") is not None or git.get("commit") is None:
        raise RuntimeError("formal E4 replay requires readable Git provenance")
    if git.get("commit") != trusted_commit:
        raise RuntimeError("formal E4 replay checkout HEAD differs from trusted expected commit")
    if git.get("status") != "" or git.get("git_dirty") is not False:
        raise RuntimeError("formal E4 replay requires a clean Git worktree")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _build_source_attestation(
    *,
    config: Mapping[str, Any],
    config_hash: str,
    expected_commit: str,
    hostname: str,
    shard_index: int,
    shard_count: int,
    git_before: Mapping[str, Any],
    git_after: Mapping[str, Any],
    run_started_utc: str,
    run_ended_utc: str,
    verified_utc: str,
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    if not rows:
        raise RuntimeError("formal E4 source attestation cannot bind an empty shard")
    if git_before.get("checkout_absolute") != git_after.get("checkout_absolute"):
        raise RuntimeError("formal E4 checkout path changed during replay")
    attestation = {
        "schema": SOURCE_ATTESTATION_SCHEMA,
        "config_contract_id": config["contract_id"],
        "config_hash": config_hash,
        "row_schema": ROW_SCHEMA,
        "trusted_expected_commit": expected_commit,
        "source_hostname": hostname,
        "source_checkout_absolute": git_before["checkout_absolute"],
        "shard_index": shard_index,
        "shard_count": shard_count,
        "source_commit_before": git_before["commit"],
        "source_commit_after": git_after["commit"],
        "source_status_scope": SOURCE_STATUS_SCOPE,
        "source_status_before": git_before["status"],
        "source_status_after": git_after["status"],
        "run_started_utc": run_started_utc,
        "run_ended_utc": run_ended_utc,
        "verified_utc": verified_utc,
        "row_count": len(rows),
        "first_row_timestamp_utc": rows[0]["timestamp_utc"],
        "last_row_timestamp_utc": rows[-1]["timestamp_utc"],
    }
    if set(attestation) != SOURCE_ATTESTATION_FIELDS:
        raise AssertionError("source attestation schema construction differs")
    return attestation


def _view(account_index: int) -> DirectoryView:
    account_id = f"replay-account-{account_index}"
    return DirectoryView(
        username=account_id,
        canonical_username=account_id,
        status=DirectoryStatus.PRESENT,
        account_id=account_id,
        account_generation=1,
        credential_set_version=1,
        salt=b"controlled-replay",
        encoding_version=1,
        retry_class="controlled",
        active_authenticator_ids=frozenset({"password"}),
        directory_epoch=1,
        reason="controlled E4 replay view",
    )


def _filter_seed(seed: int, screen_kind: str) -> int:
    material = f"R-TRAPS/E4/{screen_kind}/{seed}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def _build_screen(
    members: list[ScreenQuery],
    seed: int,
    screen_kind: str,
    filter_config: dict[str, Any],
):
    parameters = {
        "fingerprint_bits": int(filter_config["fingerprint_bits"]),
        "bucket_size": int(filter_config.get("bucket_size", 4)),
        "target_load": float(filter_config.get("target_load", 0.90)),
        "seed": _filter_seed(seed, screen_kind),
        "max_kicks": int(filter_config.get("max_kicks", 500)),
        "max_seed_attempts": int(filter_config.get("max_seed_attempts", 20)),
    }
    if screen_kind == "static_cuckoo":
        return CuckooFilter.build(members, **parameters)
    if screen_kind == "adaptive_cuckoo":
        return AdaptiveCuckooFilter.build(members, **parameters)
    raise ValueError(f"unknown screen kind: {screen_kind}")


def _screen_load_counts(screen) -> tuple[int, int]:
    if isinstance(screen, CuckooFilter):
        return screen.n_items, screen.bucket_count * screen.bucket_size
    if isinstance(screen, AdaptiveCuckooFilter):
        return screen.n_items, 2 * screen.bucket_count * screen.bucket_size
    raise TypeError(f"unsupported E4 screen type: {type(screen).__name__}")


def _exact_filter_load_accepted(
    n_items: int, slots: int, filter_config: Mapping[str, Any]
) -> bool:
    exact_load = _decimal_ratio(n_items, slots)
    minimum = _to_decimal(filter_config["actual_load_acceptance_min"])
    maximum = _to_decimal(filter_config["actual_load_acceptance_max"])
    return minimum <= exact_load <= maximum


def _canonical_screen_parameters(screen) -> dict[str, Any]:
    parameters = dict(screen.parameters())
    n_items, slots = _screen_load_counts(screen)
    parameters["load_factor"] = _row_ratio(
        "filter_parameters.load_factor", n_items, slots
    )
    if isinstance(screen, CuckooFilter):
        parameters["analytic_fpr_standard"] = _canonical_cuckoo_analytic_fpr(
            n_items=n_items,
            slots=slots,
            fingerprint_bits=screen.fingerprint_bits,
            bucket_size=screen.bucket_size,
        )
    return parameters


def _validate_screen_load(screen, filter_config: dict[str, Any]) -> float:
    n_items, slots = _screen_load_counts(screen)
    exact_actual = _decimal_ratio(n_items, slots)
    exact_minimum = _to_decimal(filter_config["actual_load_acceptance_min"])
    exact_maximum = _to_decimal(filter_config["actual_load_acceptance_max"])
    if not _exact_filter_load_accepted(n_items, slots, filter_config):
        raise RuntimeError(
            f"actual filter load {exact_actual} is outside configured acceptance "
            f"[{exact_minimum}, {exact_maximum}]"
        )
    return _row_ratio("filter_parameters.load_factor", n_items, slots)


def _discover_false_positives(
    screen,
    dataset: SyntheticCredentialSet,
    search_limit: int,
    required_total: int,
    required_same_account: int,
) -> Discovery:
    found: list[ScreenQuery] = []
    per_account: dict[int, int] = {}
    false_positive_count = 0
    scanned = 0
    for invalid_index in range(search_limit):
        query = dataset.nonmember(invalid_index)
        scanned += 1
        if not screen.query(query).positive:
            continue
        false_positive_count += 1
        found.append(query)
        per_account[query.account_index] = per_account.get(query.account_index, 0) + 1
        enough_account = (
            required_same_account == 0
            or max(per_account.values(), default=0) >= required_same_account
        )
        if len(found) >= required_total and enough_account:
            break
    else:
        raise RuntimeError(
            "false-positive discovery exhausted its real query limit: "
            f"found={len(found)}, required_total={required_total}, "
            f"largest_account_group={max(per_account.values(), default=0)}, "
            f"required_same_account={required_same_account}, limit={search_limit}"
        )
    return Discovery(tuple(found), scanned, false_positive_count)


def _select_queries(discovery: Discovery, scenario: Scenario) -> list[ScreenQuery]:
    if not scenario.same_account:
        return list(discovery.queries[: scenario.key_count])
    grouped: dict[int, list[ScreenQuery]] = {}
    for query in discovery.queries:
        grouped.setdefault(query.account_index, []).append(query)
    eligible = [values for values in grouped.values() if len(values) >= scenario.key_count]
    if not eligible:
        raise RuntimeError(f"no account has {scenario.key_count} observed false positives")
    eligible.sort(key=lambda values: (values[0].account_index, values[0].token))
    return eligible[0][: scenario.key_count]


def _negative_key_deriver(seed: int) -> NegativeKeyDeriver:
    key = hashlib.sha256(f"R-TRAPS/E4/negative-key/{seed}".encode()).digest()
    return NegativeKeyDeriver(key)


def _build_trace(
    queries: Sequence[ScreenQuery],
    multiplicity: int,
    order: str,
    interval: float,
    deriver: NegativeKeyDeriver,
) -> list[ReplayEvent]:
    if order == "grouped":
        indexed = [(query, occurrence) for query in queries for occurrence in range(multiplicity)]
    elif order == "round_robin":
        indexed = [(query, occurrence) for occurrence in range(multiplicity) for query in queries]
    else:
        raise ValueError("scenario order must be grouped or round_robin")

    events: list[ReplayEvent] = []
    for index, (query, occurrence) in enumerate(indexed):
        view = _view(query.account_index)
        events.append(
            ReplayEvent(
                query=query,
                view=view,
                negative_key=deriver.derive(view, query.token),
                occurrence=occurrence,
                logical_time=index * interval,
            )
        )
    return events


def _make_policy(
    name: str,
    sequence: Sequence[NegativeKey],
    cache_config: dict[str, Any],
) -> EvictionPolicy:
    if name in {"lru", "fixed_ttl"}:
        return LruPolicy()
    if name == "lfu":
        return ExactLfuPolicy()
    if name == "tinylfu":
        return TinyLfuPolicy(reset_after=int(cache_config["tinylfu_reset_after"]))
    if name == "future_oracle":
        return FutureReuseOraclePolicy(sequence)
    raise ValueError(f"unknown cache policy: {name}")


def _make_cache(
    method: MethodSpec,
    scenario: Scenario,
    sequence: Sequence[NegativeKey],
    cache_config: dict[str, Any],
) -> tuple[NegativeCache | None, EvictionPolicy | None, float]:
    if method.cache_policy is None:
        return None, None, 0.0
    policy = _make_policy(method.cache_policy, sequence, cache_config)
    if method.cache_policy == "fixed_ttl":
        ttl = float(cache_config["fixed_ttl_seconds"])
    else:
        ttl = float(cache_config["retention_ttl_seconds"])
    cache = NegativeCache(
        capacity=scenario.cache_capacity,
        policy=policy,
        max_ttl_seconds=ttl,
        max_entries_per_account=scenario.max_entries_per_account,
    )
    return cache, policy, ttl


def _run_trace(
    screen,
    method: MethodSpec,
    scenario: Scenario,
    events: Sequence[ReplayEvent],
    mode: str,
    replay_config: dict[str, Any],
    cache_config: dict[str, Any],
) -> dict[str, Any]:
    if method.cache_policy == "future_oracle" and mode != "sequential":
        raise ValueError("the offline future-reuse oracle is sequential-only")
    sequence = [event.negative_key for event in events]
    cache, policy, ttl = _make_cache(method, scenario, sequence, cache_config)
    singleflight = Singleflight(
        max_waiters_per_key=int(replay_config["max_waiters_per_key"]),
        max_waiters_global=int(replay_config["max_waiters_global"]),
        waiter_timeout_seconds=float(replay_config["waiter_timeout_seconds"]),
    )
    idle_singleflight_bytes = deep_sizeof(singleflight)
    backend_calls = 0
    screen_forwards = 0
    first_seen_forwards = 0
    adaptation_attempts = 0
    adaptations = 0
    processed_events = 0
    adaptive_invariant_checks = 0
    singleflight_leaders = 0
    singleflight_suppressed = 0
    singleflight_peak_waiters = 0

    if method.adaptive:
        if not isinstance(screen, AdaptiveCuckooFilter):
            raise TypeError("adaptive method requires AdaptiveCuckooFilter")
        _assert_adaptive_screen_invariants(screen)
        adaptive_invariant_checks = 1

    def record_processed_event() -> None:
        nonlocal processed_events, adaptive_invariant_checks
        processed_events += 1
        should_check = bool(
            method.adaptive
            and processed_events % ADAPTIVE_INVARIANT_PERIOD_EVENTS == 0
        )
        if should_check:
            assert isinstance(screen, AdaptiveCuckooFilter)
            _assert_adaptive_screen_invariants(screen)
            adaptive_invariant_checks += 1

    def cache_hit(event: ReplayEvent, now: float) -> bool:
        if cache is None:
            return False
        return cache.lookup(
            event.negative_key,
            expected_view=event.view,
            now=now,
        ).hit

    def apply_feedback(event: ReplayEvent, now: float) -> None:
        nonlocal adaptation_attempts, adaptations
        if method.adaptive:
            adaptation_attempts += 1
            adaptations += int(screen.confirm_false_positive(event.query))
        if cache is not None:
            cache.insert(
                event.negative_key,
                event.view,
                region=0,
                ttl_seconds=ttl,
                now=now,
            )

    if mode == "sequential":
        for event in events:
            hit = cache_hit(event, event.logical_time)
            positive = False if hit else screen.query(event.query).positive
            if positive:
                screen_forwards += 1
                first_seen_forwards += int(event.occurrence == 0)
                backend_calls += 1
                singleflight_leaders += int(method.singleflight)
                apply_feedback(event, event.logical_time)
            record_processed_event()
    elif mode == "concurrent":
        width = int(replay_config["concurrency"])
        for start in range(0, len(events), width):
            batch = events[start : start + width]
            batch_time = batch[0].logical_time
            positive_events: list[ReplayEvent] = []
            for event in batch:
                hit = cache_hit(event, batch_time)
                positive = False if hit else screen.query(event.query).positive
                if positive:
                    positive_events.append(event)
                    screen_forwards += 1
                    first_seen_forwards += int(event.occurrence == 0)
            if method.singleflight:
                groups: dict[NegativeKey, int] = {}
                for event in positive_events:
                    groups[event.negative_key] = groups.get(event.negative_key, 0) + 1
                batch_suppressed = len(positive_events) - len(groups)
                if any(
                    count - 1 > int(replay_config["max_waiters_per_key"])
                    for count in groups.values()
                ) or batch_suppressed > int(replay_config["max_waiters_global"]):
                    raise RuntimeError("frozen concurrent batch exceeds singleflight waiter caps")
                backend_calls += len(groups)
                singleflight_leaders += len(groups)
                singleflight_suppressed += batch_suppressed
                singleflight_peak_waiters = max(
                    singleflight_peak_waiters, batch_suppressed
                )
            else:
                backend_calls += len(positive_events)
            for event in positive_events:
                apply_feedback(event, batch_time)
            for _ in batch:
                record_processed_event()
    else:
        raise ValueError("replay mode must be sequential or concurrent")

    if processed_events != len(events):
        raise RuntimeError("replay did not process every generated event")
    if method.adaptive:
        assert isinstance(screen, AdaptiveCuckooFilter)
        _assert_adaptive_screen_invariants(screen)
        adaptive_invariant_checks += 1

    cache_metrics = cache.metrics_snapshot() if cache is not None else {}
    singleflight_metrics = {
        "leaders": singleflight_leaders,
        "coalesced_waiters": singleflight_suppressed,
        "peak_waiters": singleflight_peak_waiters,
        "waiter_timeouts": 0,
    }
    oracle_mismatches = (
        policy.alignment_mismatches if isinstance(policy, FutureReuseOraclePolicy) else None
    )
    if oracle_mismatches not in {None, 0}:
        raise RuntimeError(
            "future-reuse oracle schedule did not match the realized logical sequence"
        )
    peak_singleflight_bytes = max(idle_singleflight_bytes, deep_sizeof(singleflight))
    return {
        "backend_calls": backend_calls,
        "screen_forwards": screen_forwards,
        "first_seen_forwards": first_seen_forwards,
        "cache_metrics": cache_metrics,
        "singleflight_metrics": singleflight_metrics,
        "adaptation_attempts": adaptation_attempts,
        "adaptations": adaptations,
        "processed_events": processed_events,
        "adaptive_invariant_checks": adaptive_invariant_checks,
        "adaptive_invariant_violations": 0,
        "oracle_alignment_mismatches": oracle_mismatches,
        "singleflight_idle_python_bytes": idle_singleflight_bytes,
        "singleflight_peak_python_bytes": peak_singleflight_bytes,
        "singleflight_waiter_queue_peak_bytes": 0,
        "cache_python_bytes": deep_sizeof(cache) if cache is not None else 0,
        "cache_policy_python_bytes": deep_sizeof(policy) if policy is not None else 0,
    }


def _cache_memory_accounting(
    method: MethodSpec,
    scenario: Scenario,
) -> CacheMemoryAccounting:
    if method.cache_policy is None:
        return CacheMemoryAccounting(0, 0, 0, 0, 0, 0, True, None)

    entry_bytes = scenario.cache_capacity * CACHE_ENTRY_BYTES_PER_SLOT
    if method.cache_policy in {"lru", "fixed_ttl"}:
        policy_per_slot = CACHE_POLICY_BYTES_PER_SLOT[method.cache_policy]
        policy_bytes = scenario.cache_capacity * policy_per_slot
        return CacheMemoryAccounting(
            entry_bytes,
            policy_bytes,
            CACHE_FIXED_METADATA_BYTES,
            entry_bytes + policy_bytes + CACHE_FIXED_METADATA_BYTES,
            CACHE_ENTRY_BYTES_PER_SLOT,
            policy_per_slot,
            True,
            None,
        )
    if method.cache_policy == "lfu":
        policy_per_slot = CACHE_POLICY_BYTES_PER_SLOT["lfu"]
        policy_bytes = scenario.cache_capacity * policy_per_slot
        return CacheMemoryAccounting(
            entry_bytes,
            policy_bytes,
            CACHE_FIXED_METADATA_BYTES,
            entry_bytes + policy_bytes + CACHE_FIXED_METADATA_BYTES,
            CACHE_ENTRY_BYTES_PER_SLOT,
            policy_per_slot,
            True,
            None,
        )
    if method.cache_policy == "tinylfu":
        return CacheMemoryAccounting(
            entry_bytes,
            None,
            CACHE_FIXED_METADATA_BYTES,
            None,
            CACHE_ENTRY_BYTES_PER_SLOT,
            None,
            False,
            "Python Counter baseline has no packed fixed-memory TinyLFU sketch layout",
        )
    if method.cache_policy == "future_oracle":
        return CacheMemoryAccounting(
            entry_bytes,
            None,
            CACHE_FIXED_METADATA_BYTES,
            None,
            CACHE_ENTRY_BYTES_PER_SLOT,
            None,
            False,
            "offline future sequence is non-deployable and excluded from edge memory",
        )
    raise ValueError(f"unknown cache policy: {method.cache_policy}")


def _source_metadata(method: MethodSpec) -> dict[str, str]:
    if method.screen_kind == "adaptive_cuckoo":
        screen_implementation = "reference.adaptive.cuckoo.AdaptiveCuckooFilter"
        screen_citation = "https://doi.org/10.1145/3339504"
    else:
        screen_implementation = "reference.filters.cuckoo.CuckooFilter"
        screen_citation = "https://doi.org/10.1145/2663716.2663754"

    policy = {
        None: (
            "not_applicable",
            "not_applicable",
            "no negative cache policy",
        ),
        "lru": (
            "dataplane.negative_cache.LruPolicy",
            "standard exact LRU",
            "deployable reference",
        ),
        "lfu": (
            "reference.adaptive.cache_policies.ExactLfuPolicy",
            "standard resident-bounded exact LFU",
            "deployable reference",
        ),
        "tinylfu": (
            "dataplane.negative_cache.TinyLfuPolicy",
            "https://doi.org/10.1145/3149371",
            "reference only; packed sketch layout unavailable",
        ),
        "fixed_ttl": (
            "dataplane.negative_cache.LruPolicy+NegativeCache TTL",
            "standard fixed TTL with exact LRU eviction",
            "deployable reference",
        ),
        "future_oracle": (
            "reference.adaptive.cache_policies.FutureReuseOraclePolicy",
            "https://doi.org/10.1145/321958.321973",
            "offline sequential upper bound; non-deployable",
        ),
    }[method.cache_policy]
    return {
        "screen_implementation": screen_implementation,
        "screen_citation": screen_citation,
        "cache_policy_implementation": policy[0],
        "cache_policy_citation": policy[1],
        "cache_policy_deployability": policy[2],
        "singleflight_implementation": (
            "deterministic E4 exact-key batch semantics matching Singleflight caps; "
            "runtime implementation is tested outside E4"
            if method.singleflight
            else "not_enabled"
        ),
    }


def _build_row(
    *,
    config: dict[str, Any],
    config_hash: str,
    commit: str | None,
    git_dirty: bool | None,
    hostname: str,
    dataset_hash: str,
    dataset: SyntheticCredentialSet,
    seed: int,
    method: MethodSpec,
    scenario: Scenario,
    multiplicity: int,
    mode: str,
    selected_queries: Sequence[ScreenQuery],
    discovery: Discovery,
    screen,
    trace_result: dict[str, Any],
) -> dict[str, Any]:
    event_count = len(selected_queries) * multiplicity
    distinct_count = len(selected_queries)
    if trace_result["processed_events"] != event_count:
        raise RuntimeError("trace result event count does not match the generated trace")
    backend_checks = int(trace_result["backend_calls"])
    cache_metrics = trace_result["cache_metrics"]
    singleflight_metrics = trace_result["singleflight_metrics"]
    memory = screen.memory_report()
    backing_bytes = (
        screen.backing_memory_report().total_bytes
        if isinstance(screen, AdaptiveCuckooFilter)
        else 0
    )
    cache_memory = _cache_memory_accounting(method, scenario)
    source_metadata = _source_metadata(method)
    source_metadata_complete = all(bool(value) for value in source_metadata.values())
    if not source_metadata_complete:
        raise AssertionError(f"incomplete method source metadata: {method.method}")
    checks_per_tuple = _row_ratio(
        "backend_checks_per_distinct_invalid", backend_checks, distinct_count
    )
    work_amplification = _row_ratio(
        "backend_work_amplification_per_tuple", backend_checks, distinct_count
    )
    work_fraction = _row_ratio(
        "backend_work_fraction_of_static", backend_checks, event_count
    )
    reduction_factor = (
        _row_ratio(
            "backend_work_reduction_factor_vs_static", event_count, backend_checks
        )
        if backend_checks
        else None
    )
    reuse_stride = 1 if scenario.order == "grouped" else distinct_count
    with localcontext() as decimal_context:
        decimal_context.prec = NUMERIC_DECIMAL_PRECISION
        maximum_reuse_horizon = (
            Decimal(multiplicity - 1)
            * Decimal(reuse_stride)
            * _to_decimal(scenario.event_interval_seconds)
        )
    ttl = _to_decimal(
        config["cache"]["fixed_ttl_seconds"]
        if method.cache_policy == "fixed_ttl"
        else config["cache"]["retention_ttl_seconds"]
    )
    capacity_condition = (
        method.cache_policy is not None
        and scenario.cache_capacity >= distinct_count
        and scenario.max_entries_per_account is None
        and ttl > maximum_reuse_horizon
    )
    g2_replay_component_eligible = bool(
        config["evidence_tier"] == "formal_replay"
        and multiplicity >= 100
        and method.singleflight
        and capacity_condition
        and cache_memory.memory_match_eligible
        and method.cache_policy != "future_oracle"
    )
    g2_checks_pass = _ratio_at_most(
        backend_checks, distinct_count, G2_CHECKS_PER_TUPLE_MAX
    )
    g2_improvement_pass = backend_checks == 0 or (
        reduction_factor is not None
        and _ratio_at_least(
            event_count, backend_checks, G2_STATIC_WORK_IMPROVEMENT_MIN
        )
    )
    g2_replay_component_pass = (
        g2_checks_pass and g2_improvement_pass if g2_replay_component_eligible else None
    )
    validation_count = dataset.account_count
    member_false_negatives = sum(
        not screen.query(dataset.member(index)).positive for index in range(validation_count)
    )
    configured_scenarios = _parse_scenarios(config)
    discovery_required_total = max(item.key_count for item in configured_scenarios)
    discovery_required_same = max(
        (item.key_count for item in configured_scenarios if item.same_account),
        default=0,
    )
    point_material = {
        "method": method.method,
        "scenario": scenario.name,
        "multiplicity": multiplicity,
        "mode": mode,
    }
    point_id = _canonical_hash(point_material)[:24]
    run_material = {
        "row_schema": ROW_SCHEMA,
        "commit": commit,
        "config_hash": config_hash,
        "dataset_hash": dataset_hash,
        "seed": seed,
        "point_id": point_id,
    }
    interval = _canonical_row_float(
        "trace_summary.event_interval_seconds", scenario.event_interval_seconds
    )
    logical_start = _canonical_row_float("trace_summary.logical_start_seconds", 0)
    logical_end = _row_product(
        "trace_summary.logical_end_seconds", event_count - 1, interval
    )
    logical_window = _row_product(
        "trace_summary.logical_window_seconds", event_count, interval
    )
    trace_summary = {
        "schema": TRACE_SCHEMA,
        "event_count": event_count,
        "distinct_tuple_count": distinct_count,
        "multiplicity": multiplicity,
        "order": scenario.order,
        "mode": mode,
        "event_interval_seconds": interval,
        "logical_start_seconds": logical_start,
        "logical_end_seconds": logical_end,
        "logical_window_seconds": logical_window,
        "generated_request_rate_per_second": _row_ratio(
            "trace_summary.generated_request_rate_per_second",
            event_count,
            _to_decimal(logical_window),
        ),
        "generated_distinct_tuple_rate_per_second": _row_ratio(
            "trace_summary.generated_distinct_tuple_rate_per_second",
            distinct_count,
            _to_decimal(logical_window),
        ),
        "concurrent_execution_width": (
            int(config["replay"]["concurrency"]) if mode == "concurrent" else 1
        ),
    }
    memory_total_edge_bytes = (
        memory.total_bytes
        + backing_bytes
        + cache_memory.total_compact_bytes
        if cache_memory.total_compact_bytes is not None
        else None
    )
    filter_parameters = _canonical_screen_parameters(screen)
    filter_actual_load = filter_parameters["load_factor"]
    filter_target_load = _canonical_row_float(
        "filter_target_load", config["filter"]["target_load"]
    )
    filter_load_minimum = _canonical_row_float(
        "filter_load_acceptance_min",
        config["filter"]["actual_load_acceptance_min"],
    )
    filter_load_maximum = _canonical_row_float(
        "filter_load_acceptance_max",
        config["filter"]["actual_load_acceptance_max"],
    )
    filter_n_items, filter_slots = _screen_load_counts(screen)
    filter_load_acceptance_pass = _exact_filter_load_accepted(
        filter_n_items, filter_slots, config["filter"]
    )
    if not filter_load_acceptance_pass:
        raise RuntimeError("exact filter load is outside configured acceptance")
    row: dict[str, Any] = {
        "row_schema": ROW_SCHEMA,
        "config_contract_id": config["contract_id"],
        "numeric_contract_id": NUMERIC_CONTRACT_ID,
        "run_id": _canonical_hash(run_material)[:24],
        "point_id": point_id,
        "commit": commit,
        "git_dirty": git_dirty,
        "git_status_scope": SOURCE_STATUS_SCOPE,
        "config_hash": config_hash,
        "dataset_hash": dataset_hash,
        "seed": seed,
        "method": method.method,
        "scenario_name": scenario.name,
        "scenario": f"e4_{scenario.name}_{mode}",
        "account_count": dataset.account_count,
        "event_count": event_count,
        "distinct_invalid_count": distinct_count,
        "memory_filter_bytes": memory.total_bytes,
        "memory_model_bytes": 0,
        "memory_cache_bytes": cache_memory.total_compact_bytes,
        "memory_cache_entry_compact_bytes": cache_memory.entry_compact_bytes,
        "memory_cache_policy_compact_bytes": cache_memory.policy_compact_bytes,
        "memory_cache_fixed_metadata_bytes": cache_memory.fixed_metadata_bytes,
        "memory_cache_entry_bytes_per_slot": cache_memory.entry_bytes_per_slot,
        "memory_cache_policy_bytes_per_slot": cache_memory.policy_bytes_per_slot,
        "memory_cache_layout_manifest": _cache_layout_manifest(),
        "memory_cache_python_bytes": trace_result["cache_python_bytes"],
        "memory_cache_policy_python_bytes": trace_result["cache_policy_python_bytes"],
        "cache_memory_match_eligible": cache_memory.memory_match_eligible,
        "cache_memory_match_exclusion_reason": cache_memory.exclusion_reason,
        "memory_directory_extra_bytes": backing_bytes,
        "memory_total_edge_bytes": memory_total_edge_bytes,
        "screen_python_bytes": deep_sizeof(screen),
        "frontend_p50_us": None,
        "frontend_p95_us": None,
        "frontend_p99_us": None,
        "frontend_measurement_scope": FRONTEND_MEASUREMENT_SCOPE,
        "observed_first_seen_ffr": _row_ratio(
            "observed_first_seen_ffr",
            int(trace_result["first_seen_forwards"]),
            distinct_count,
        ),
        "observed_request_weighted_ffr": _row_ratio(
            "observed_request_weighted_ffr",
            int(trace_result["screen_forwards"]),
            event_count,
        ),
        "worst_region_ffr": _row_ratio(
            "worst_region_ffr", int(trace_result["screen_forwards"]), event_count
        ),
        "backend_valid_checks": 0,
        "backend_invalid_checks": backend_checks,
        "screen_positive_forwards": int(trace_result["screen_forwards"]),
        "first_seen_positive_forwards": int(trace_result["first_seen_forwards"]),
        "backend_checks_per_distinct_invalid": checks_per_tuple,
        "cache_hits": int(cache_metrics.get("hits", 0)),
        "cache_misses": int(cache_metrics.get("misses", 0)),
        "cache_evictions": int(cache_metrics.get("evictions", 0)),
        "singleflight_suppressed": int(singleflight_metrics.get("coalesced_waiters", 0)),
        "legitimate_p99_ms": None,
        "legitimate_timeout_rate": None,
        "service_saturation_rps": None,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "hostname": hostname,
        "host_platform": platform.platform(),
        "python_version": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "experiment": "E4_controlled_false_positive_replay",
        "evidence_tier": config["evidence_tier"],
        "selection_conditioned_on_observed_false_positive": True,
        "false_positive_discovery_queries": discovery.scanned,
        "false_positive_discovery_count": discovery.false_positives,
        "false_positive_discovery_observed_fpr": discovery.observed_fpr,
        "false_positive_discovery_search_limit": int(
            config["dataset"]["false_positive_search_limit"]
        ),
        "false_positive_discovery_required_total": discovery_required_total,
        "false_positive_discovery_required_same_account": discovery_required_same,
        "false_positive_discovery_positive_set_id": _query_set_id(discovery.queries),
        "selected_query_set_id": _query_set_id(selected_queries),
        "false_positive_discovery_stopping_rule": (
            "stop after required total and same-account group; rate is descriptive "
            "and conditioned on this stopping rule"
        ),
        "screen_kind": method.screen_kind,
        "replay_mode": mode,
        "replay_order": scenario.order,
        "replay_multiplicity": multiplicity,
        "replay_request_amplification": _row_ratio(
            "replay_request_amplification", event_count, distinct_count
        ),
        "trace_summary": trace_summary,
        "backend_work_amplification_per_tuple": work_amplification,
        "backend_work_fraction_of_static": work_fraction,
        "static_backend_checks_reference": event_count,
        "backend_work_reduction_factor_vs_static": reduction_factor,
        "cache_policy": method.cache_policy,
        "cache_capacity_entries": scenario.cache_capacity if method.cache_policy else 0,
        "cache_max_entries_per_account": (
            scenario.max_entries_per_account if method.cache_policy else None
        ),
        "cache_admissions": int(cache_metrics.get("inserts", 0)),
        "cache_admission_rejected": int(cache_metrics.get("admission_rejected", 0)),
        "cache_updates": int(cache_metrics.get("updates", 0)),
        "cache_expirations": int(cache_metrics.get("expired", 0)),
        "cache_account_quota_pressure": int(cache_metrics.get("account_quota_pressure", 0)),
        "cache_global_quota_pressure": (
            int(cache_metrics.get("evictions", 0)) + int(cache_metrics.get("admission_rejected", 0))
            if scenario.max_entries_per_account is None
            else 0
        ),
        "singleflight_enabled": method.singleflight,
        "singleflight_overlap_delay_seconds": None,
        "singleflight_overlap_model": config["replay"]["concurrent_overlap_model"],
        "singleflight_leaders": int(singleflight_metrics.get("leaders", 0)),
        "singleflight_peak_waiters": int(singleflight_metrics.get("peak_waiters", 0)),
        "singleflight_waiter_timeouts": int(singleflight_metrics.get("waiter_timeouts", 0)),
        "singleflight_per_waiter_state_bytes": None,
        "singleflight_waiter_queue_peak_bytes": trace_result[
            "singleflight_waiter_queue_peak_bytes"
        ],
        "singleflight_waiter_memory_scope": (
            "not measured by deterministic E4 semantic replay; E7 owns runtime waiter memory"
        ),
        "singleflight_idle_python_bytes": trace_result["singleflight_idle_python_bytes"],
        "singleflight_peak_python_bytes": trace_result["singleflight_peak_python_bytes"],
        "adaptive_feedback_attempts": trace_result["adaptation_attempts"],
        "adaptive_updates": trace_result["adaptations"],
        "adaptive_invariant_check_period_events": (
            ADAPTIVE_INVARIANT_PERIOD_EVENTS if method.adaptive else None
        ),
        "adaptive_invariant_checks": trace_result["adaptive_invariant_checks"],
        "adaptive_invariant_violations": trace_result["adaptive_invariant_violations"],
        "oracle_future_input_count": event_count if method.cache_policy == "future_oracle" else 0,
        "oracle_schedule_alignment_mismatches": trace_result["oracle_alignment_mismatches"],
        "oracle_schedule_valid": (
            trace_result["oracle_alignment_mismatches"] == 0
            if method.cache_policy == "future_oracle"
            else None
        ),
        "oracle_deployable": False if method.cache_policy == "future_oracle" else None,
        "legitimate_static_p99_ms": None,
        "legitimate_p99_regression_fraction_vs_static": None,
        "legitimate_latency_method": "not measured by E4 replay runner",
        "legitimate_p99_required_source": "E7 service benchmark",
        "member_false_negatives": member_false_negatives,
        "member_validation_count": validation_count,
        "comparison_reference_method": "static_cuckoo_no_cache",
        "static_reference_role": (
            "controlled same-filter static reference; strongest Phase1 baseline "
            "selection remains external"
        ),
        "g2_capacity_condition_met": capacity_condition,
        "g2_replay_component_eligible": g2_replay_component_eligible,
        "g2_replay_component_criteria_pass": g2_replay_component_pass,
        "g2_gate_eligible_row": False,
        "g2_checks_per_tuple_le_1_1": g2_checks_pass,
        "g2_static_work_improvement_ge_10x": g2_improvement_pass,
        "g2_legitimate_p99_regression_le_5pct": None,
        "g2_row_criteria_pass": None,
        "g2_gate_status": "BLOCKED_PENDING_PHASE1_AND_E7",
        "source_metadata_schema_version": 1,
        "source_metadata": source_metadata,
        "source_metadata_complete": source_metadata_complete,
        "external_baselines_included": [],
        "external_baseline_status": "TAF_AND_AQF_REQUIRE_SEPARATE_HARNESS",
        "filter_target_load": filter_target_load,
        "filter_actual_load": filter_actual_load,
        "filter_load_delta_from_target": _row_difference(
            "filter_load_delta_from_target", filter_actual_load, filter_target_load
        ),
        "filter_load_acceptance_min": filter_load_minimum,
        "filter_load_acceptance_max": filter_load_maximum,
        "filter_load_acceptance_pass": filter_load_acceptance_pass,
        "research_status": "RESEARCH_IN_PROGRESS",
        "filter_parameters": filter_parameters,
    }
    missing = [field for field in RESULT_SCHEMA if field not in row]
    if missing:
        raise AssertionError(f"runner omitted required result fields: {missing}")
    return row


def _parse_scenarios(config: dict[str, Any]) -> list[Scenario]:
    default_multiplicities = tuple(int(value) for value in config["replay"]["multiplicities"])
    default_modes = tuple(str(value) for value in config["replay"]["modes"])
    scenarios: list[Scenario] = []
    for raw in config["scenarios"]:
        scenarios.append(
            Scenario(
                name=str(raw["name"]),
                key_count=int(raw["key_count"]),
                order=str(raw["order"]),
                cache_capacity=int(raw["cache_capacity"]),
                max_entries_per_account=(
                    int(raw["max_entries_per_account"])
                    if raw.get("max_entries_per_account") is not None
                    else None
                ),
                same_account=bool(raw.get("same_account", False)),
                multiplicities=tuple(
                    int(value) for value in raw.get("multiplicities", default_multiplicities)
                ),
                modes=tuple(str(value) for value in raw.get("modes", default_modes)),
                event_interval_seconds=float(
                    raw.get(
                        "event_interval_seconds",
                        config["replay"]["event_interval_seconds"],
                    )
                ),
            )
        )
    return scenarios


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{context} keys differ: missing={missing}, extra={extra}")


def _require_int(value: Any, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{context} must be an integer >= {minimum}")
    return value


def _require_finite(
    value: Any, context: str, *, minimum: float | None = None
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{context} must be numeric")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{context} must be finite")
    if minimum is not None and result < minimum:
        raise ValueError(f"{context} must be >= {minimum}")
    return result


def expected_points(config: Mapping[str, Any]) -> list[tuple[int, str, str, int, str]]:
    """Return the exact seed/method/scenario/multiplicity/mode evidence grid."""

    scenarios = _parse_scenarios(dict(config))
    points = [
        (int(seed), method.method, scenario.name, multiplicity, mode)
        for seed in config["seeds"]
        for method in (METHODS[str(name)] for name in config["methods"])
        for scenario in scenarios
        for multiplicity in scenario.multiplicities
        for mode in scenario.modes
        if not (method.cache_policy == "future_oracle" and mode == "concurrent")
    ]
    if len(points) != len(set(points)):
        raise ValueError("replay configuration produces duplicate evidence points")
    return points


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            config = yaml.load(handle, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as error:
        raise ValueError(f"invalid E4 YAML config {path}: {error}") from error
    if not isinstance(config, dict):
        raise ValueError("top-level YAML must be a mapping")
    _require_exact_keys(
        config,
        {
            "schema_version",
            "contract_id",
            "profile",
            "status",
            "evidence_tier",
            "require_clean_git",
            "source_attestation",
            "numeric_contract",
            "output",
            "seeds",
            "methods",
            "dataset",
            "filter",
            "cache",
            "replay",
            "scenarios",
            "gate_policy",
        },
        "top-level replay config",
    )
    if not _strict_typed_equal(config.get("schema_version"), CONFIG_SCHEMA_VERSION):
        raise ValueError(f"E4 config schema_version must be {CONFIG_SCHEMA_VERSION}")
    if config.get("status") != "RESEARCH_IN_PROGRESS":
        raise ValueError("E4 config status must remain RESEARCH_IN_PROGRESS")
    if config.get("profile") not in {"smoke", "formal"}:
        raise ValueError("profile must be smoke or formal")
    if config.get("evidence_tier") not in {"smoke_only", "formal_replay"}:
        raise ValueError("evidence_tier must be smoke_only or formal_replay")
    if type(config.get("require_clean_git")) is not bool:
        raise ValueError("require_clean_git must be boolean")
    source_attestation = config.get("source_attestation")
    if not isinstance(source_attestation, dict):
        raise ValueError("source_attestation must be a mapping")
    _require_exact_keys(
        source_attestation,
        {"schema", "required_for_formal", "trust_model"},
        "source_attestation",
    )
    if not _strict_typed_equal(
        source_attestation.get("schema"), SOURCE_ATTESTATION_SCHEMA
    ):
        raise ValueError("source_attestation schema differs from the frozen contract")
    if type(source_attestation.get("required_for_formal")) is not bool:
        raise ValueError("source_attestation.required_for_formal must be boolean")
    if not _strict_typed_equal(
        config.get("numeric_contract"), FROZEN_NUMERIC_CONTRACT
    ):
        raise ValueError("numeric_contract must equal the frozen field-level decimal contract")
    if not isinstance(config.get("output"), str) or not config["output"]:
        raise ValueError("output must be a non-empty path string")
    if not isinstance(config.get("seeds"), list):
        raise ValueError("seeds must be a list")
    seeds = [_require_int(seed, "seed", minimum=0) for seed in config["seeds"]]
    if not seeds or len(seeds) != len(set(seeds)):
        raise ValueError("seeds must be a non-empty unique list")
    if not isinstance(config.get("methods"), list) or not all(
        isinstance(method, str) for method in config["methods"]
    ):
        raise ValueError("methods must be a list of strings")
    methods = list(config["methods"])
    if not methods or len(methods) != len(set(methods)):
        raise ValueError("methods must be a non-empty unique list")
    unknown = set(methods) - set(METHODS)
    if unknown:
        raise ValueError(f"unknown replay methods: {sorted(unknown)}")
    if "static_no_cache" not in methods:
        raise ValueError("every replay config must include its paired static_no_cache reference")
    dataset = config["dataset"]
    if not isinstance(dataset, dict):
        raise ValueError("dataset must be a mapping")
    _require_exact_keys(
        dataset,
        {"account_count", "seed", "false_positive_search_limit"},
        "dataset",
    )
    _require_int(dataset["account_count"], "dataset.account_count", minimum=1)
    _require_int(dataset["seed"], "dataset.seed", minimum=0)
    _require_int(
        dataset["false_positive_search_limit"],
        "dataset.false_positive_search_limit",
        minimum=1,
    )
    filter_config = config["filter"]
    if not isinstance(filter_config, dict):
        raise ValueError("filter must be a mapping")
    _require_exact_keys(
        filter_config,
        {
            "fingerprint_bits",
            "bucket_size",
            "target_load",
            "actual_load_acceptance_min",
            "actual_load_acceptance_max",
            "max_kicks",
            "max_seed_attempts",
        },
        "filter",
    )
    _require_int(filter_config["fingerprint_bits"], "filter.fingerprint_bits", minimum=4)
    _require_int(filter_config["bucket_size"], "filter.bucket_size", minimum=2)
    _require_int(filter_config["max_kicks"], "filter.max_kicks", minimum=1)
    _require_int(
        filter_config["max_seed_attempts"], "filter.max_seed_attempts", minimum=1
    )
    target_load = _require_finite(filter_config["target_load"], "filter.target_load")
    load_minimum = _require_finite(
        filter_config["actual_load_acceptance_min"],
        "filter.actual_load_acceptance_min",
    )
    load_maximum = _require_finite(
        filter_config["actual_load_acceptance_max"],
        "filter.actual_load_acceptance_max",
    )
    if not 0.0 < load_minimum <= load_maximum < 1.0:
        raise ValueError("filter actual-load acceptance must lie inside (0, 1)")
    if not 0.1 <= target_load < 1.0:
        raise ValueError("filter.target_load must lie in [0.1, 1)")
    cache_config = config["cache"]
    if not isinstance(cache_config, dict):
        raise ValueError("cache must be a mapping")
    _require_exact_keys(
        cache_config,
        {"retention_ttl_seconds", "fixed_ttl_seconds", "tinylfu_reset_after"},
        "cache",
    )
    _require_finite(
        cache_config["retention_ttl_seconds"],
        "cache.retention_ttl_seconds",
        minimum=0.0,
    )
    _require_finite(
        cache_config["fixed_ttl_seconds"],
        "cache.fixed_ttl_seconds",
        minimum=0.0,
    )
    if float(cache_config["retention_ttl_seconds"]) <= 0.0 or float(
        cache_config["fixed_ttl_seconds"]
    ) <= 0.0:
        raise ValueError("cache TTLs must be strictly positive")
    _require_int(cache_config["tinylfu_reset_after"], "cache.tinylfu_reset_after", minimum=1)
    replay = config["replay"]
    if not isinstance(replay, dict):
        raise ValueError("replay must be a mapping")
    _require_exact_keys(
        replay,
        {
            "multiplicities",
            "modes",
            "concurrency",
            "event_interval_seconds",
            "concurrent_overlap_model",
            "max_waiters_per_key",
            "max_waiters_global",
            "waiter_timeout_seconds",
        },
        "replay",
    )
    if not isinstance(replay["multiplicities"], list):
        raise ValueError("replay.multiplicities must be a list")
    multiplicities = [
        _require_int(value, "replay multiplicity", minimum=1)
        for value in replay["multiplicities"]
    ]
    if not multiplicities or len(multiplicities) != len(set(multiplicities)):
        raise ValueError("replay.multiplicities must be non-empty and unique")
    if not isinstance(replay["modes"], list) or not replay["modes"]:
        raise ValueError("replay.modes must be a non-empty list")
    if len(replay["modes"]) != len(set(replay["modes"])) or set(
        replay["modes"]
    ) - {"sequential", "concurrent"}:
        raise ValueError("replay.modes must be unique sequential/concurrent values")
    for field in ("concurrency", "max_waiters_per_key", "max_waiters_global"):
        _require_int(replay[field], f"replay.{field}", minimum=1)
    for field in (
        "event_interval_seconds",
        "waiter_timeout_seconds",
    ):
        _require_finite(replay[field], f"replay.{field}", minimum=0.0)
    if float(replay["event_interval_seconds"]) <= 0.0:
        raise ValueError("replay.event_interval_seconds must be strictly positive")
    if float(replay["waiter_timeout_seconds"]) <= 0.0:
        raise ValueError("replay.waiter_timeout_seconds must be strictly positive")
    if replay["concurrent_overlap_model"] != "frozen_batch_by_concurrency_width":
        raise ValueError("replay.concurrent_overlap_model must equal the frozen batch model")
    if not isinstance(config["gate_policy"], dict) or not _strict_typed_equal(
        config["gate_policy"], FROZEN_GATE_POLICY
    ):
        raise ValueError("gate_policy must equal the frozen G2 dependency and threshold contract")
    if not isinstance(config["scenarios"], list):
        raise ValueError("scenarios must be a list")
    scenario_names: list[str] = []
    allowed_scenario_keys = {
        "name",
        "key_count",
        "order",
        "cache_capacity",
        "max_entries_per_account",
        "same_account",
        "multiplicities",
        "modes",
        "event_interval_seconds",
    }
    for index, raw in enumerate(config["scenarios"]):
        if not isinstance(raw, dict):
            raise ValueError(f"scenario {index} must be a mapping")
        if set(raw) - allowed_scenario_keys:
            unknown_keys = sorted(set(raw) - allowed_scenario_keys)
            raise ValueError(f"scenario {index} has unknown keys: {unknown_keys}")
        for required in ("name", "key_count", "order", "cache_capacity"):
            if required not in raw:
                raise ValueError(f"scenario {index} omits {required}")
        if not isinstance(raw["name"], str) or not raw["name"]:
            raise ValueError("scenario names must be non-empty strings")
        scenario_names.append(raw["name"])
        _require_int(raw["key_count"], "scenario.key_count", minimum=1)
        _require_int(raw["cache_capacity"], "scenario.cache_capacity", minimum=1)
        if raw["order"] not in {"grouped", "round_robin"}:
            raise ValueError("scenario order must be grouped or round_robin")
        if "same_account" in raw and type(raw["same_account"]) is not bool:
            raise ValueError("scenario.same_account must be boolean")
        if raw.get("max_entries_per_account") is not None:
            _require_int(
                raw["max_entries_per_account"],
                "scenario.max_entries_per_account",
                minimum=1,
            )
        for field, allowed in (
            ("multiplicities", None),
            ("modes", {"sequential", "concurrent"}),
        ):
            if field not in raw:
                continue
            if not isinstance(raw[field], list) or not raw[field]:
                raise ValueError(f"scenario.{field} must be a non-empty list")
            if len(raw[field]) != len(set(raw[field])):
                raise ValueError(f"scenario.{field} must be unique")
            if allowed is None:
                for value in raw[field]:
                    _require_int(value, "scenario multiplicity", minimum=1)
            elif set(raw[field]) - allowed:
                raise ValueError("scenario modes must be sequential/concurrent")
        if "event_interval_seconds" in raw:
            interval = _require_finite(
                raw["event_interval_seconds"],
                "scenario.event_interval_seconds",
                minimum=0.0,
            )
            if interval <= 0.0:
                raise ValueError("scenario.event_interval_seconds must be strictly positive")
    if len(scenario_names) != len(set(scenario_names)):
        raise ValueError("scenario names must be unique")
    scenarios = _parse_scenarios(config)
    if not scenarios:
        raise ValueError("at least one replay scenario is required")
    for scenario in scenarios:
        if scenario.key_count <= 0 or scenario.cache_capacity <= 0:
            raise ValueError("scenario key counts and cache capacities must be positive")
        if scenario.order not in {"grouped", "round_robin"}:
            raise ValueError("scenario order must be grouped or round_robin")
        if set(scenario.modes) - {"sequential", "concurrent"}:
            raise ValueError("scenario modes must be sequential/concurrent")
    if config["profile"] == "formal":
        if not _strict_typed_equal(config, FROZEN_FORMAL_CONTRACT):
            raise ValueError("formal E4 config must exactly equal the frozen 10x93 contract")
        points = expected_points(config)
        if len(points) != EXPECTED_FORMAL_ROWS:
            raise AssertionError("frozen formal E4 contract no longer produces 930 rows")
        per_seed = {seed: 0 for seed in FORMAL_SEEDS}
        for seed, *_ in points:
            per_seed[seed] += 1
        if set(per_seed.values()) != {EXPECTED_FORMAL_POINTS_PER_SEED}:
            raise AssertionError("frozen formal E4 contract no longer produces 93 points/seed")
    else:
        if config["contract_id"] != SMOKE_CONTRACT_ID:
            raise ValueError("smoke config must use the frozen smoke contract identifier")
        if config["evidence_tier"] != "smoke_only":
            raise ValueError("smoke profile must remain smoke_only")
        if config["require_clean_git"] is not False:
            raise ValueError("smoke profile must not masquerade as clean formal evidence")
        if not _strict_typed_equal(
            config["source_attestation"], SMOKE_ATTESTATION_CONTRACT
        ):
            raise ValueError("smoke source-attestation contract must remain diagnostic-only")
    expected_points(config)
    return config, _canonical_hash(config)


def run_config(
    config_path: Path,
    shard_index: int = 0,
    shard_count: int = 1,
    progress: bool = False,
    expected_commit: str | None = None,
    attestation_sink: MutableMapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if shard_count <= 0 or not 0 <= shard_index < shard_count:
        raise ValueError("invalid shard index/count")
    config, config_hash = load_config(config_path)
    is_formal = config["profile"] == "formal"
    trusted_commit = _require_expected_commit(expected_commit) if is_formal else None
    if is_formal and attestation_sink is None:
        raise RuntimeError("formal E4 replay requires a source-attestation output")
    run_started_utc = _utc_now()
    git = _git_metadata()
    _enforce_git_policy(config, git, trusted_commit)
    hostname = socket.gethostname()
    dataset_config = config["dataset"]
    dataset = SyntheticCredentialSet(
        int(dataset_config["account_count"]),
        int(dataset_config["seed"]),
    )
    members = [dataset.member(index) for index in range(dataset.account_count)]
    dataset_hash = dataset.manifest_hash(
        members,
        int(dataset_config["false_positive_search_limit"]),
    )
    scenarios = _parse_scenarios(config)
    scenario_by_name = {scenario.name: scenario for scenario in scenarios}
    seed_ordinals = {int(seed): ordinal for ordinal, seed in enumerate(config["seeds"])}
    selected_seeds = [
        int(seed)
        for ordinal, seed in enumerate(config["seeds"])
        if ordinal % shard_count == shard_index
    ]
    selected_seed_set = set(selected_seeds)
    points = [
        (
            seed,
            METHODS_BY_RESULT_NAME[method_name],
            scenario_by_name[scenario_name],
            multiplicity,
            mode,
        )
        for seed, method_name, scenario_name, multiplicity, mode in expected_points(config)
        if seed in selected_seed_set
    ]
    required_total = max(scenario.key_count for scenario in scenarios)
    required_same = max(
        (scenario.key_count for scenario in scenarios if scenario.same_account),
        default=0,
    )
    commit = git["commit"]
    rows: list[dict[str, Any]] = []
    for seed in selected_seeds:
        static_screen = _build_screen(members, seed, "static_cuckoo", config["filter"])
        adaptive_discovery_screen = _build_screen(
            members, seed, "adaptive_cuckoo", config["filter"]
        )
        _validate_screen_load(static_screen, config["filter"])
        _validate_screen_load(adaptive_discovery_screen, config["filter"])
        search_limit = int(dataset_config["false_positive_search_limit"])
        static_discovery = _discover_false_positives(
            static_screen,
            dataset,
            search_limit,
            required_total,
            required_same,
        )
        adaptive_discovery = _discover_false_positives(
            adaptive_discovery_screen,
            dataset,
            search_limit,
            required_total,
            required_same,
        )
        seed_points = [point for point in points if point[0] == seed]
        for ordinal, (_, method, scenario, multiplicity, mode) in enumerate(seed_points, start=1):
            if progress:
                print(
                    f"seed={seed} [{ordinal}/{len(seed_points)}] method={method.method} "
                    f"scenario={scenario.name} multiplicity={multiplicity} mode={mode}",
                    file=sys.stderr,
                    flush=True,
                )
            discovery = adaptive_discovery if method.adaptive else static_discovery
            selected_queries = _select_queries(discovery, scenario)
            deriver = _negative_key_deriver(seed)
            events = _build_trace(
                selected_queries,
                multiplicity,
                scenario.order,
                scenario.event_interval_seconds,
                deriver,
            )
            screen = (
                _build_screen(members, seed, "adaptive_cuckoo", config["filter"])
                if method.adaptive
                else static_screen
            )
            _validate_screen_load(screen, config["filter"])
            trace_result = _run_trace(
                screen,
                method,
                scenario,
                events,
                mode,
                config["replay"],
                config["cache"],
            )
            row = _build_row(
                config=config,
                config_hash=config_hash,
                commit=commit,
                git_dirty=git["git_dirty"],
                hostname=hostname,
                dataset_hash=dataset_hash,
                dataset=dataset,
                seed=seed,
                method=method,
                scenario=scenario,
                multiplicity=multiplicity,
                mode=mode,
                selected_queries=selected_queries,
                discovery=discovery,
                screen=screen,
                trace_result=trace_result,
            )
            row["shard_index"] = shard_index
            row["shard_count"] = shard_count
            row["seed_shard_ordinal"] = seed_ordinals[seed]
            if set(row) != REPLAY_ROW_FIELDS:
                missing = sorted(REPLAY_ROW_FIELDS - set(row))
                extra = sorted(set(row) - REPLAY_ROW_FIELDS)
                raise AssertionError(
                    f"E4 row schema differs: missing={missing}, extra={extra}"
                )
            rows.append(row)
    if is_formal:
        run_ended_utc = _utc_now()
        git_after = _git_metadata()
        _enforce_git_policy(config, git_after, trusted_commit)
        verified_utc = _utc_now()
        assert trusted_commit is not None
        assert attestation_sink is not None
        attestation_sink.clear()
        attestation_sink.update(
            _build_source_attestation(
                config=config,
                config_hash=config_hash,
                expected_commit=trusted_commit,
                hostname=hostname,
                shard_index=shard_index,
                shard_count=shard_count,
                git_before=git,
                git_after=git_after,
                run_started_utc=run_started_utc,
                run_ended_utc=run_ended_utc,
                verified_utc=verified_utc,
                rows=rows,
            )
        )
    return rows


def write_rows(path: Path, rows: Sequence[dict[str, Any]], overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w" if overwrite else "x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            if set(row) != REPLAY_ROW_FIELDS:
                raise ValueError("refusing to write a row outside the frozen E4 row schema")
            handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def write_source_attestation(
    path: Path, attestation: Mapping[str, Any], overwrite: bool
) -> None:
    if set(attestation) != SOURCE_ATTESTATION_FIELDS:
        raise ValueError("refusing to write an invalid E4 source attestation")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w" if overwrite else "x", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(attestation, sort_keys=True, indent=2, allow_nan=False) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--expected-commit")
    parser.add_argument("--attestation-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config, _ = load_config(args.config)
    if config["profile"] == "formal":
        _require_expected_commit(args.expected_commit)
        if args.attestation_output is None:
            raise RuntimeError("formal E4 CLI requires --attestation-output")
    output_value = args.output or config.get("output")
    if output_value is None:
        raise ValueError("provide --output or top-level output in the YAML config")
    output = Path(output_value)
    if args.output is None and not output.is_absolute():
        output = ROOT / output
    if args.output is None and args.shard_count > 1:
        output = output.with_name(
            f"{output.stem}.shard-{args.shard_index:04d}-of-{args.shard_count:04d}{output.suffix}"
        )
    attestation: dict[str, Any] = {}
    rows = run_config(
        args.config,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
        progress=True,
        expected_commit=args.expected_commit,
        attestation_sink=attestation if config["profile"] == "formal" else None,
    )
    write_rows(output, rows, overwrite=args.overwrite)
    if config["profile"] == "formal":
        assert args.attestation_output is not None
        write_source_attestation(
            args.attestation_output,
            attestation,
            overwrite=args.overwrite,
        )
    print(f"wrote {len(rows)} controlled replay rows to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
