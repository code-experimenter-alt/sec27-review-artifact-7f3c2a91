#!/usr/bin/env python3
"""Reproducible open-loop Phase 6 authentication service benchmark.

The runner emits observed JSONL rows from a real bounded threaded service. It
does not model queueing from request counts or substitute analytic Bloom false
positives for actual filter queries. The harness is in-process, so network/TLS
and isolated frontend-process memory remain explicitly unmeasured.
"""

from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import math
import os
import platform
import random
import ssl
import statistics
import struct
import subprocess
import sys
import sysconfig
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from importlib import metadata
from pathlib import Path
from typing import Any, Mapping, Sequence

from scipy.stats import t as student_t

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.analysis import register_phase1_v21_baseline as phase1_registration  # noqa: E402
from experiments.claims_manifest import (  # noqa: E402
    ClaimsManifestError,
    load_main_claims_manifest,
    load_unique_yaml,
)
from reference.filters import (  # noqa: E402
    SUPPORTED_TAG_BITS,
    BlockedBloomFilter,
    CuckooFilter,
    GlobalBloomFilter,
    MemoryReport,
    PerAccountTagFilter,
    QueryResult,
    ScreeningFilter,
    ScreenQuery,
    StaticXorFilter,
    TokenCodec,
    deep_sizeof,
)
from service import (  # noqa: E402
    AuthenticationService,
    AuthRequest,
    KdfBackend,
    KdfProfile,
    OpenLoopLoadGenerator,
    ResourceSampler,
    ScheduledArrival,
    ServiceAccount,
    ServiceLimits,
    ServiceMethod,
    ServiceRoute,
    TrafficClass,
)

RESULT_REQUIRED_FIELDS = (
    "run_id",
    "point_id",
    "curve_id",
    "curve",
    "commit",
    "config_hash",
    "main_claims_manifest_id",
    "dataset_hash",
    "seed",
    "method",
    "scenario",
    "account_count",
    "event_count",
    "distinct_invalid_count",
    "false_positive_source",
    "conditioned_tuple_set_id",
    "conditioned_tuple_count",
    "invalid_tuple_multiplicity_commitment_id",
    "minimum_invalid_tuple_multiplicity",
    "underlying_filter_query_executed",
    "conditional_intervention_does_not_estimate_ffr",
    "conditional_intervention_runtime",
    "memory_filter_bytes",
    "memory_model_bytes",
    "memory_cache_bytes",
    "memory_directory_extra_bytes",
    "frontend_p50_us",
    "frontend_p95_us",
    "frontend_p99_us",
    "observed_first_seen_ffr",
    "observed_request_weighted_ffr",
    "worst_region_ffr",
    "backend_valid_checks",
    "backend_invalid_checks",
    "backend_checks_per_distinct_invalid",
    "cache_hits",
    "cache_misses",
    "cache_evictions",
    "singleflight_suppressed",
    "legitimate_p99_ms",
    "legitimate_timeout_rate",
    "service_saturation_rps",
    "service_saturation_lower_bound_rps",
    "service_saturation_upper_bound_rps",
    "service_saturation_invalid_lower_bound_rps",
    "service_saturation_invalid_upper_bound_rps",
    "dataset_generator",
    "filter_family",
    "filter_configured_spec",
    "filter_realization",
    "method_implementation",
    "curve_environment_binding",
    "timestamp_utc",
    "host",
    "git",
    "result_schema_version",
    "result_status",
    "invalid_reasons",
    "provenance_class",
    "traffic_mode",
    "deployment_mode",
    "network_transport",
    "arrival_distribution",
    "offered_legitimate_rps",
    "offered_invalid_rps",
    "offered_total_rps",
    "nominal_scheduled_event_count",
    "event_count_semantics",
    "achieved_offered_rps",
    "achieved_legitimate_offered_rps",
    "achieved_invalid_offered_rps",
    "ingress_within_window",
    "ingress_outside_window",
    "arrival_lag_p99_us",
    "arrival_lag_max_us",
    "arrival_lag_gate",
    "successful_legitimate_throughput_rps",
    "legitimate_p50_ms",
    "legitimate_p95_ms",
    "legitimate_successes",
    "legitimate_successes_within_window",
    "queue_drop_count",
    "queue_drop_rate",
    "frontend_queue_drops",
    "backend_queue_drops",
    "connection_drops",
    "frontend_worker_utilization",
    "backend_worker_utilization",
    "frontend_thread_cpu_seconds",
    "backend_thread_cpu_seconds",
    "invalid_backend_checks_per_second",
    "backend_error_checks",
    "backend_policy_checks",
    "resource_samples",
    "queue_and_connection_state",
    "phase_metrics",
    "route_latencies_ms",
    "terminal_outcome_count",
    "response_count",
    "pending_request_count",
    "request_timeout_count",
    "event_error_count",
    "error_count",
    "error_counts",
    "exception_type_counts",
    "overload_outcome_counts",
    "warmup",
    "open_loop_report",
    "measurement_duration_seconds",
    "drained_before_request_timeout",
    "shutdown_clean",
    "shutdown_report",
    "method_config",
    "method_order_policy",
    "method_execution_order",
    "method_execution_position",
    "service_limits",
    "filter_parameters",
    "verifier_profile",
    "dataset_manifest",
    "memory_accounting",
    "measurement_integrity",
    "scope_blockers",
    "blockers",
)

# Backward-compatible name used by artifact tests; this is a required-field
# contract, not an exact whitelist because saturation annotations are added
# after a complete curve is assembled.
RESULT_SCHEMA = RESULT_REQUIRED_FIELDS
CONFIG_SCHEMA_VERSION = 2
RESULT_SCHEMA_VERSION = 8
CHECKPOINT_SCHEMA_VERSION = 7
SUMMARY_SCHEMA_VERSION = 7
NONFATAL_OPERATIONAL_OBSERVATION_REASONS = frozenset(
    {
        "MEASUREMENT_DRAIN_TIMEOUT",
        "INGRESS_OUTSIDE_MEASUREMENT_WINDOW",
        "ARRIVAL_LAG_P99_EXCEEDED",
        "ARRIVAL_LAG_MAX_EXCEEDED",
    }
)
ARRIVAL_LAG_P99_RECLASSIFICATION_MULTIPLIER = 2.0
ARRIVAL_LAG_MAX_RECLASSIFICATION_MULTIPLIER = 4.0
INGRESS_OUTSIDE_RECLASSIFICATION_FRACTION = 0.0002
CHECKPOINT_ENVELOPE_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "point_id",
        "config_hash",
        "main_claims_manifest_id",
        "point",
        "commit",
        "result_status",
        "row",
    }
)
DATASET_GENERATOR = "service-synthetic-exact-bytes-v1"
RUNNER_CAPABILITY = "GLOBAL_BLOOM_MECHANISM_ONLY"
GENERAL_SCREEN_FACTORY_CAPABILITY = "FROZEN_SCREEN_FACTORY_V1"
STRONG_BASELINE_READY = "FROZEN_PHASE1_STRONG_MATCHED_BASELINE"
PHASE1_BASELINE_REGISTRATION_SCHEMA = "traps-e7-phase1-v2-baseline-registration-v1"
PHASE1_BASELINE_PENDING = "PENDING_PHASE1_V2_1_POSTRUN_RECEIPT"
PHASE1_BASELINE_REGISTERED = "REGISTERED_PHASE1_V2_1_BASELINE"
PHASE1_BASELINE_RECOVERY_REGISTERED = "REGISTERED_PHASE1_V2_2_SERVICE_BASELINE"
PHASE1_BASELINE_REGISTERED_STATUSES = frozenset(
    {PHASE1_BASELINE_REGISTERED, PHASE1_BASELINE_RECOVERY_REGISTERED}
)
PHASE1_BASELINE_RECEIPT_SCHEMA = "traps-phase1-timing-frontier-v2-postrun-receipt-v2"
PHASE1_BASELINE_RECEIPT_BLOCKER = "PHASE1_V2_1_BASELINE_RECEIPT_NOT_REGISTERED"
PHASE1_BASELINE_RECOVERY_READY = "FROZEN_PHASE1_V2_2_SERVICE_BASELINE_RECOVERY"
MAIN_CLAIMS_ALIGNED = "ALIGNED"
MAIN_CLAIMS_NOT_FROZEN = "BLOCKED_MAIN_CLAIMS_MANIFEST_NOT_FROZEN"
MAIN_CLAIMS_ARTIFACT_BINDING_BLOCKER = "MAIN_CLAIMS_MANIFEST_ID_NOT_PROPAGATED_TO_ARTIFACTS"
MAIN_CLAIMS_ARTIFACT_BOUND = "BOUND"
MAIN_CLAIMS_PATH = ROOT / "experiments" / "configs" / "main_claims.yaml"
PAPER_CLAIMS_PATH = ROOT / "paper" / "claims.yaml"
SCREEN_SPEC_SCHEMA_VERSION = 1
SCREEN_REALIZATION_SCHEMA_VERSION = 1
G2_GATE_CONTRACT = {
    "schema": "traps-g2-e4-e7-gate-v1",
    "candidate_method": "frozen_screen_exact_cache_lru",
    "baseline_method": "static_frozen_screen_mechanism_baseline",
    "scenario": "repeat_heavy_false_positive",
    "offered_legitimate_rps": 16,
    "offered_invalid_rps": 32,
    "verifier_profiles": ["pbkdf2_reference_310k", "argon2id_reference_19mib"],
    "repeated_tuple_count": 16,
    "minimum_replay_multiplicity": 100,
    "paired_seed_count": 20,
    "latency_margin_ratio": 1.05,
    "familywise_alpha": 0.05,
    "multiplicity_adjustment": "bonferroni_one_sided_student_t_log_ratio_v1",
    "false_positive_source": "FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1",
    "underlying_filter_query_executed": True,
    "conditional_intervention_does_not_estimate_ffr": True,
}
G4_CAPACITY_CONTRACT = {
    "schema": "traps-g4-e7-backend-invalid-capacity-v1",
    "source_method": "static_frozen_screen_mechanism_baseline",
    "scenario": "repeat_heavy_false_positive",
    "offered_legitimate_rps": 16,
    "verifier_profiles": ["pbkdf2_reference_310k", "argon2id_reference_19mib"],
    "paired_seed_count": 20,
    "per_seed_safe_point_rule": ("HIGHEST_POSITIVE_INVALID_GRID_POINT_PASSING_SATURATION_CRITERIA"),
    "per_seed_estimand": "observed_invalid_backend_checks_per_second_at_safe_point",
    "familywise_alpha": 0.05,
    "multiplicity_adjustment": ("bonferroni_one_sided_student_t_log_capacity_over_2_profiles_v1"),
    "cross_profile_capacity_rule": "MINIMUM_SIMULTANEOUS_PROFILE_LOWER_BOUND",
    "offered_rate_planning_formula": "floor(min_capacity/(1.25*epsilon_cap))",
    "safety_factor": 1.25,
    "epsilon_authority": "PHASE1_REGISTERED_CONSERVATIVE_FFR_CI_UPPER",
}
G5_GATE_CONTRACT = {
    "schema": "traps-g5-e7-formal-gate-v2",
    "candidate_method": "frozen_screen_exact_cache_lru",
    "matched_baseline_method": "static_frozen_screen_mechanism_baseline",
    "scenario": "repeat_heavy_false_positive",
    "verifier_profiles": ["pbkdf2_reference_310k", "argon2id_reference_19mib"],
    "paired_seed_count": 20,
    "offered_legitimate_rps": 16,
    "offered_invalid_rps_grid": [0, 32, 64, 96, 128, 192, 256, 384, 512],
    "operational_safe_point_rule": ("VALID_TIMEOUT_QUEUE_DROP_AND_LEGITIMATE_THROUGHPUT_ONLY_V1"),
    "operational_safe_point_excludes": ["legitimate_p99_ms"],
    "saturation_ratio_threshold": 1.5,
    "saturation_per_seed_ratio_rule": (
        "CANDIDATE_OPERATIONAL_SAFE_INCLUSIVE_LOWER_OVER_BASELINE_"
        "OPERATIONAL_FAILURE_EXCLUSIVE_UPPER"
    ),
    "saturation_familywise_alpha": 0.05,
    "saturation_multiplicity_adjustment": (
        "bonferroni_one_sided_student_t_log_ratio_over_2_profiles_v1"
    ),
    "p99_safe_load_rule": (
        "HIGHEST_POSITIVE_COMMON_GRID_POINT_PASSING_OPERATIONAL_SAFE_CRITERIA_P99_EXCLUDED"
    ),
    "p99_margin_ratio": 1.05,
    "p99_familywise_alpha": 0.05,
    "p99_multiplicity_adjustment": ("bonferroni_one_sided_student_t_log_ratio_over_2_profiles_v1"),
    "resource_gate": "COMBINED_PROCESS_ENVELOPE_AND_CONFIGURED_HARD_BOUNDS_V2",
    "resource_bounds": {
        "process_scope": "COMBINED_BENCHMARK_PROCESS_ENVELOPES_FRONTEND",
        "maximum_process_rss_peak_bytes": 2_147_483_648,
        "rss_window_fraction_numerator": 1,
        "rss_window_fraction_denominator": 10,
        "minimum_resource_samples": 100,
        "maximum_late_minus_early_rss_mean_bytes": 268_435_456,
        "queue_connection_padding_limits_source": "SERVICE_CONFIG_HARD_CAPS",
        "waiter_limits_source": "SERVICE_CONFIG_HARD_CAPS",
        "cache_limits_source": "SERVICE_CONFIG_HARD_CAPS",
        "final_state_rule": "ALL_ZERO_AFTER_SHUTDOWN",
        "missing_data_policy": "INDETERMINATE_NO_PROMOTION",
        "threshold_exceedance_policy": "VALID_FAIL",
    },
    "unique_first_seen_role": "REPORT_ONLY_DOES_NOT_CONTROL_PASS",
    "missing_endpoint_policy": "INDETERMINATE_NO_POSTHOC_GRID_EXTENSION",
}

STRONG_ORACLE_SOURCE = "FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1"
FORMAL_CONDITIONED_UNIQUE_TUPLE_POOL_SIZE = 131_072

FILTER_PARAMETER_KEYS: dict[str, frozenset[str]] = {
    "tag": frozenset({"tag_bits"}),
    "global_bloom": frozenset({"bits_per_account", "k_hashes"}),
    "blocked_bloom": frozenset({"bits_per_account", "k_hashes"}),
    "xor_static": frozenset({"fingerprint_bits", "capacity_factor", "max_attempts"}),
    "cuckoo": frozenset(
        {
            "fingerprint_bits",
            "bucket_size",
            "target_load",
            "max_kicks",
            "max_seed_attempts",
        }
    ),
}
FILTER_IMPLEMENTATIONS = {
    "tag": "reference.filters.PerAccountTagFilter",
    "global_bloom": "reference.filters.GlobalBloomFilter",
    "blocked_bloom": "reference.filters.BlockedBloomFilter",
    "xor_static": "reference.filters.StaticXorFilter",
    "cuckoo": "reference.filters.CuckooFilter",
}

# These identifiers bind declarative method labels to the only implementations
# this runner actually instantiates.  In particular, none is a strong baseline.
METHOD_IMPLEMENTATIONS: dict[str, dict[str, Any]] = {
    "no_prescreen_v1": {
        "name": "no_prescreen",
        "use_positive_screen": False,
        "cache_policy": None,
        "use_singleflight": False,
        "claim_scope": "no_prescreen_control",
        "baseline_role": "control",
    },
    "static_global_bloom_v1": {
        "name": "static_global_bloom_mechanism_baseline",
        "use_positive_screen": True,
        "cache_policy": None,
        "use_singleflight": False,
        "claim_scope": "global_bloom_prescreen_mechanism",
        "baseline_role": "provisional_mechanism_baseline",
    },
    "global_bloom_exact_negative_cache_tinylfu_singleflight_v1": {
        "name": "mechanism_global_bloom_exact_cache_tinylfu",
        "use_positive_screen": True,
        "cache_policy": "tinylfu",
        "use_singleflight": True,
        "claim_scope": ("global_bloom_exact_negative_cache_tinylfu_singleflight_mechanism"),
        "baseline_role": "candidate_mechanism",
    },
    "static_frozen_screen_v1": {
        "name": "static_frozen_screen_mechanism_baseline",
        "use_positive_screen": True,
        "cache_policy": None,
        "use_singleflight": False,
        "claim_scope": "frozen_screen_prescreen_mechanism",
        "baseline_role": "provisional_mechanism_baseline",
    },
    "frozen_screen_exact_negative_cache_lru_singleflight_v1": {
        "name": "frozen_screen_exact_cache_lru",
        "use_positive_screen": True,
        "cache_policy": "lru",
        "use_singleflight": True,
        "claim_scope": "frozen_screen_exact_negative_cache_lru_singleflight_mechanism",
        "baseline_role": "candidate_mechanism",
    },
    "frozen_screen_exact_negative_cache_tinylfu_singleflight_v1": {
        "name": "frozen_screen_exact_cache_tinylfu",
        "use_positive_screen": True,
        "cache_policy": "tinylfu",
        "use_singleflight": True,
        "claim_scope": "frozen_screen_exact_negative_cache_tinylfu_singleflight_mechanism",
        "baseline_role": "candidate_mechanism",
    },
}

LEGACY_GLOBAL_SCREEN_IMPLEMENTATIONS = frozenset(
    {
        "static_global_bloom_v1",
        "global_bloom_exact_negative_cache_tinylfu_singleflight_v1",
    }
)
GENERIC_SCREEN_IMPLEMENTATIONS = frozenset(
    {
        "static_frozen_screen_v1",
        "frozen_screen_exact_negative_cache_lru_singleflight_v1",
        "frozen_screen_exact_negative_cache_tinylfu_singleflight_v1",
    }
)

SUPPORTED_SCENARIOS = {
    "uniform_unique_random",
    "password_spraying",
    "wrong_credential_stuffing",
    "old_password_replay",
    "no_account_flood",
    "repeat_heavy_false_positive",
    "unique_first_seen_false_positive",
    "cache_pollution_false_positive",
    "mixed_unique_repeat_false_positive",
    "correct_password_flood",
}
FALSE_POSITIVE_SCENARIOS = {
    "repeat_heavy_false_positive",
    "unique_first_seen_false_positive",
    "cache_pollution_false_positive",
    "mixed_unique_repeat_false_positive",
}


@dataclass(frozen=True)
class InvalidCredential:
    account: ServiceAccount
    password: bytes
    query: ScreenQuery
    tuple_id: str


@dataclass(frozen=True)
class WorkloadPlan:
    arrivals: tuple[ScheduledArrival, ...]
    dataset_hash: str
    distinct_invalid_count: int
    observed_first_seen_ffr: float | None
    observed_request_weighted_ffr: float | None
    false_positive_source: str | None
    conditioned_tuple_set_id: str | None
    conditioned_tuple_count: int
    conditioned_queries: frozenset[ScreenQuery]
    invalid_tuple_multiplicity_commitment_id: str
    minimum_invalid_tuple_multiplicity: int


@dataclass(frozen=True)
class CurveSpec:
    ordinal: int
    seed: int
    scenario: str
    profile_name: str
    legitimate_rps: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "ordinal": self.ordinal,
            "seed": self.seed,
            "scenario": self.scenario,
            "profile_name": self.profile_name,
            "legitimate_rps": self.legitimate_rps,
        }


@dataclass(frozen=True)
class PointSpec:
    curve: CurveSpec
    method_name: str
    invalid_rps: float

    def identity(self, config_hash: str) -> dict[str, Any]:
        return {
            "config_hash": config_hash,
            "curve": self.curve.as_dict(),
            "method": self.method_name,
            "invalid_rps": self.invalid_rps,
        }

    def point_id(self, config_hash: str) -> str:
        return _canonical_hash(self.identity(config_hash))[:32]


class ServiceDataset:
    generator_version = DATASET_GENERATOR

    def __init__(self, account_count: int, dataset_seed: int) -> None:
        if account_count < 1:
            raise ValueError("dataset.account_count must be positive")
        if not 0 <= dataset_seed <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("dataset.seed must fit uint64")
        self.account_count = account_count
        self.dataset_seed = dataset_seed
        key = hashlib.sha256(
            b"RTRAPS-service-token-key-v1\x00" + struct.pack(">Q", dataset_seed)
        ).digest()
        self.codec = TokenCodec(key)
        self.accounts = tuple(
            ServiceAccount(
                account_index=index,
                username=f"user-{index:08d}",
                account_id=f"account-{index:08d}",
                account_generation=1,
                credential_set_version=1,
                salt=struct.pack(">QQ", dataset_seed, index),
            )
            for index in range(account_count)
        )
        self._by_username = {account.username.casefold(): account for account in self.accounts}

    @staticmethod
    def correct_password(account_index: int) -> bytes:
        return b"valid-v1:" + struct.pack(">Q", account_index)

    @staticmethod
    def old_password(account_index: int) -> bytes:
        return b"retired-v0:" + struct.pack(">Q", account_index)

    def members(self) -> list[ScreenQuery]:
        return [
            account.screen_query(self.codec, self.correct_password(account.account_index))
            for account in self.accounts
        ]

    def invalid_credential(self, invalid_index: int) -> InvalidCredential:
        if invalid_index < 0:
            raise ValueError("invalid index must be non-negative")
        account_index = (
            invalid_index * 0x9E3779B97F4A7C15 + self.dataset_seed
        ) % self.account_count
        account = self.accounts[account_index]
        password = b"invalid-v1:" + struct.pack(">Q", invalid_index)
        query = account.screen_query(self.codec, password)
        return InvalidCredential(
            account=account,
            password=password,
            query=query,
            tuple_id=f"{account.account_id}:invalid:{invalid_index}",
        )

    def account(self, username: str) -> ServiceAccount | None:
        return self._by_username.get(username.casefold())

    def base_manifest(self) -> dict[str, Any]:
        return {
            "generator": self.generator_version,
            "dataset_seed": self.dataset_seed,
            "account_count": self.account_count,
            "account_generation": 1,
            "credential_set_version": 1,
            "password_bytes": "exact generated byte strings; no normalization",
        }


def _canonical_hash(value: Any) -> str:
    encoded = _canonical_json(value).encode()
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _derived_seed(seed: int, *labels: object) -> int:
    material = json.dumps([seed, *labels], separators=(",", ":")).encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def _strict_int(
    value: object,
    name: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise ValueError(f"{name} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        interval = f"[{minimum}, {maximum}]" if maximum is not None else f">= {minimum}"
        raise ValueError(f"{name} must be {interval}")
    return value


def _strict_finite_number(
    value: object,
    name: str,
    *,
    minimum: float,
    maximum_exclusive: float | None = None,
) -> int | float:
    if type(value) not in {int, float} or not math.isfinite(float(value)):
        raise ValueError(f"{name} must be a finite number")
    numeric = float(value)
    if numeric < minimum or (maximum_exclusive is not None and numeric >= maximum_exclusive):
        interval = (
            f"[{minimum}, {maximum_exclusive})"
            if maximum_exclusive is not None
            else f">= {minimum}"
        )
        raise ValueError(f"{name} must be {interval}")
    return value


@dataclass(frozen=True)
class FrozenScreenSpec:
    """Strict family-specific screen configuration shared by compared methods."""

    family: str
    parameter_items: tuple[tuple[str, int | float], ...]

    @classmethod
    def from_config(cls, value: Mapping[str, Any]) -> "FrozenScreenSpec":
        family = value.get("family")
        if not isinstance(family, str) or family not in FILTER_PARAMETER_KEYS:
            raise ValueError("filter.family must be one of " + repr(sorted(FILTER_PARAMETER_KEYS)))
        expected_fields = {"family", *FILTER_PARAMETER_KEYS[family]}
        observed_fields = set(value)
        if observed_fields != expected_fields:
            missing = sorted(expected_fields - observed_fields)
            unknown = sorted((repr(field) for field in observed_fields - expected_fields))
            raise ValueError(
                f"filter spec fields do not match family {family!r}; "
                f"missing={missing}, unknown={unknown}"
            )

        parameters: dict[str, int | float]
        if family == "tag":
            tag_bits = _strict_int(value["tag_bits"], "filter.tag_bits", minimum=1)
            if tag_bits not in SUPPORTED_TAG_BITS:
                raise ValueError(f"filter.tag_bits must be one of {SUPPORTED_TAG_BITS}")
            parameters = {"tag_bits": tag_bits}
        elif family in {"global_bloom", "blocked_bloom"}:
            parameters = {
                "bits_per_account": _strict_finite_number(
                    value["bits_per_account"],
                    "filter.bits_per_account",
                    minimum=sys.float_info.min,
                ),
                "k_hashes": _strict_int(
                    value["k_hashes"],
                    "filter.k_hashes",
                    minimum=1,
                    maximum=0xFFFF,
                ),
            }
        elif family == "xor_static":
            parameters = {
                "fingerprint_bits": _strict_int(
                    value["fingerprint_bits"],
                    "filter.fingerprint_bits",
                    minimum=4,
                    maximum=64,
                ),
                "capacity_factor": _strict_finite_number(
                    value["capacity_factor"],
                    "filter.capacity_factor",
                    minimum=1.05,
                ),
                "max_attempts": _strict_int(
                    value["max_attempts"],
                    "filter.max_attempts",
                    minimum=1,
                ),
            }
        else:
            parameters = {
                "fingerprint_bits": _strict_int(
                    value["fingerprint_bits"],
                    "filter.fingerprint_bits",
                    minimum=4,
                    maximum=64,
                ),
                "bucket_size": _strict_int(
                    value["bucket_size"],
                    "filter.bucket_size",
                    minimum=1,
                    maximum=16,
                ),
                "target_load": _strict_finite_number(
                    value["target_load"],
                    "filter.target_load",
                    minimum=0.1,
                    maximum_exclusive=1.0,
                ),
                "max_kicks": _strict_int(
                    value["max_kicks"],
                    "filter.max_kicks",
                    minimum=1,
                ),
                "max_seed_attempts": _strict_int(
                    value["max_seed_attempts"],
                    "filter.max_seed_attempts",
                    minimum=1,
                ),
            }
        return cls(family, tuple(sorted(parameters.items())))

    @property
    def parameters(self) -> dict[str, int | float]:
        return dict(self.parameter_items)

    def configured_binding(self) -> dict[str, Any]:
        return {
            "schema_version": SCREEN_SPEC_SCHEMA_VERSION,
            "family": self.family,
            "parameters": self.parameters,
        }

    @property
    def identity(self) -> str:
        return _canonical_hash(self.configured_binding())

    @property
    def phase1_identity(self) -> str:
        return _canonical_json({"family": self.family, "parameters": self.parameters})


@dataclass(frozen=True)
class ScreenRealization:
    """A built screen plus an immutable evidence snapshot of its exact state."""

    _filter: ScreeningFilter
    spec: FrozenScreenSpec
    experiment_seed: int
    requested_construction_seed: int | None
    realized_construction_seed: int | None
    method: str
    n_items: int
    ordered_member_snapshot_id: str
    realized_parameters_json: str
    memory_payload_bytes: int
    memory_metadata_bytes: int
    memory_alignment_bytes: int

    @property
    def seed(self) -> int | None:
        return self.realized_construction_seed

    def query(self, item: ScreenQuery) -> QueryResult:
        return self._filter.query(item)

    def parameters(self) -> dict[str, Any]:
        return json.loads(self.realized_parameters_json)

    def memory_report(self) -> MemoryReport:
        return MemoryReport(
            payload_bytes=self.memory_payload_bytes,
            metadata_bytes=self.memory_metadata_bytes,
            alignment_bytes=self.memory_alignment_bytes,
        )

    def _binding_material(self) -> dict[str, Any]:
        memory = self.memory_report()
        return {
            "schema_version": SCREEN_REALIZATION_SCHEMA_VERSION,
            "configured_spec_id": self.spec.identity,
            "family": self.spec.family,
            "implementation": FILTER_IMPLEMENTATIONS[self.spec.family],
            "method": self.method,
            "ordered_member_snapshot_id": self.ordered_member_snapshot_id,
            "experiment_seed": self.experiment_seed,
            "requested_construction_seed": self.requested_construction_seed,
            "realized_construction_seed": self.realized_construction_seed,
            "n_items": self.n_items,
            "realized_parameters": self.parameters(),
            "memory_report": {
                "payload_bytes": memory.payload_bytes,
                "metadata_bytes": memory.metadata_bytes,
                "alignment_bytes": memory.alignment_bytes,
                "total_bytes": memory.total_bytes,
            },
            "all_members_positive_at_build": True,
        }

    @property
    def identity(self) -> str:
        return _canonical_hash(self._binding_material())

    def binding(self) -> dict[str, Any]:
        return {**self._binding_material(), "realization_id": self.identity}


class StrongOracleConditionedScreen:
    """TM2 intervention that preserves every underlying filter query and its cost."""

    def __init__(
        self,
        underlying: ScreenRealization,
        conditioned_queries: frozenset[ScreenQuery],
    ) -> None:
        self._underlying = underlying
        self._conditioned_queries = conditioned_queries
        self._lock = threading.Lock()
        self._underlying_query_count = 0
        self._conditioned_query_count = 0
        self._natural_positive_conditioned_query_count = 0
        self._forced_positive_query_count = 0
        self.method = underlying.method
        self.n_items = underlying.n_items

    def query(self, item: ScreenQuery) -> QueryResult:
        result = self._underlying.query(item)
        conditioned = item in self._conditioned_queries
        with self._lock:
            self._underlying_query_count += 1
            if conditioned:
                self._conditioned_query_count += 1
                if result.positive:
                    self._natural_positive_conditioned_query_count += 1
                else:
                    self._forced_positive_query_count += 1
        if conditioned and not result.positive:
            return QueryResult(True, result.probes, result.comparisons)
        return result

    def memory_report(self) -> MemoryReport:
        # Oracle state is experimental harness state and is excluded symmetrically
        # from the compared deployed mechanisms' compact filter footprint.
        return self._underlying.memory_report()

    def runtime_evidence(self) -> dict[str, int]:
        with self._lock:
            return {
                "underlying_query_count": self._underlying_query_count,
                "conditioned_query_count": self._conditioned_query_count,
                "natural_positive_conditioned_query_count": (
                    self._natural_positive_conditioned_query_count
                ),
                "forced_positive_query_count": self._forced_positive_query_count,
            }

    def reset_runtime_evidence(self) -> None:
        with self._lock:
            self._underlying_query_count = 0
            self._conditioned_query_count = 0
            self._natural_positive_conditioned_query_count = 0
            self._forced_positive_query_count = 0


def _phase1_filter_seed(experiment_seed: int, spec: FrozenScreenSpec) -> int:
    digest = hashlib.sha256(f"{experiment_seed}:{spec.phase1_identity}".encode()).digest()
    return int.from_bytes(digest[:8], "big")


def _ordered_member_snapshot_id(members: Sequence[ScreenQuery]) -> str:
    digest = hashlib.sha256(b"TRAPS-service-screen-members-v1\x00")
    digest.update(struct.pack(">Q", len(members)))
    for member in members:
        if not isinstance(member, ScreenQuery):
            raise TypeError("screen members must be ScreenQuery values")
        if member.account_index > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("screen member account_index must fit uint64")
        digest.update(struct.pack(">Q", member.account_index))
        digest.update(member.token)
    return digest.hexdigest()


def build_screen(
    spec: FrozenScreenSpec,
    members: Sequence[ScreenQuery],
    experiment_seed: int,
) -> ScreenRealization:
    """Build one exact Phase-1-compatible filter realization, failing closed."""

    if not isinstance(spec, FrozenScreenSpec):
        raise TypeError("spec must be a FrozenScreenSpec")
    normalized_spec = FrozenScreenSpec.from_config({"family": spec.family, **spec.parameters})
    if spec != normalized_spec:
        raise ValueError("FrozenScreenSpec is not in canonical validated form")
    _strict_int(experiment_seed, "experiment seed", minimum=0, maximum=0xFFFFFFFFFFFFFFFF)
    member_list = list(members)
    if not member_list:
        raise ValueError("screen construction requires at least one member")
    member_snapshot_id = _ordered_member_snapshot_id(member_list)
    parameters = spec.parameters
    requested_seed = None if spec.family == "tag" else _phase1_filter_seed(experiment_seed, spec)
    if spec.family == "tag":
        built: ScreeningFilter = PerAccountTagFilter.build(
            member_list, tag_bits=int(parameters["tag_bits"])
        )
    elif spec.family in {"global_bloom", "blocked_bloom"}:
        filter_class = GlobalBloomFilter if spec.family == "global_bloom" else BlockedBloomFilter
        built = filter_class.build(
            member_list,
            m_bits=math.ceil(float(parameters["bits_per_account"]) * len(member_list)),
            k_hashes=int(parameters["k_hashes"]),
            seed=requested_seed,
        )
    elif spec.family == "xor_static":
        built = StaticXorFilter.build(
            member_list,
            fingerprint_bits=int(parameters["fingerprint_bits"]),
            seed=requested_seed,
            load_factor=float(parameters["capacity_factor"]),
            max_attempts=int(parameters["max_attempts"]),
        )
    elif spec.family == "cuckoo":
        built = CuckooFilter.build(
            member_list,
            fingerprint_bits=int(parameters["fingerprint_bits"]),
            bucket_size=int(parameters["bucket_size"]),
            target_load=float(parameters["target_load"]),
            seed=requested_seed,
            max_kicks=int(parameters["max_kicks"]),
            max_seed_attempts=int(parameters["max_seed_attempts"]),
        )
    else:  # pragma: no cover - FrozenScreenSpec rejects this before construction.
        raise AssertionError(f"unhandled filter family: {spec.family}")

    if not isinstance(built, ScreeningFilter):
        raise TypeError("constructed filter does not implement ScreeningFilter")
    if built.n_items != len(member_list):
        raise RuntimeError("constructed filter N does not match the member snapshot")
    if any(not built.query(member).positive for member in member_list):
        raise RuntimeError("constructed filter has a member false negative")
    parameter_method = getattr(built, "parameters", None)
    if not callable(parameter_method):
        raise TypeError("constructed filter does not expose realized parameters")
    realized_parameters = parameter_method()
    if not isinstance(realized_parameters, dict):
        raise TypeError("realized filter parameters must be a mapping")
    realized_parameters_json = _canonical_json(realized_parameters)
    memory = built.memory_report()
    realized_seed_value = getattr(built, "seed", None)
    realized_seed = (
        None
        if realized_seed_value is None
        else _strict_int(
            realized_seed_value,
            "realized construction seed",
            minimum=0,
            maximum=0xFFFFFFFFFFFFFFFF,
        )
    )
    if requested_seed is None and realized_seed is not None:
        raise RuntimeError("unseeded screen unexpectedly reported a construction seed")
    if requested_seed is not None and realized_seed is None:
        raise RuntimeError("seeded screen did not report its realized construction seed")
    return ScreenRealization(
        _filter=built,
        spec=spec,
        experiment_seed=experiment_seed,
        requested_construction_seed=requested_seed,
        realized_construction_seed=realized_seed,
        method=str(built.method),
        n_items=int(built.n_items),
        ordered_member_snapshot_id=member_snapshot_id,
        realized_parameters_json=realized_parameters_json,
        memory_payload_bytes=memory.payload_bytes,
        memory_metadata_bytes=memory.metadata_bytes,
        memory_alignment_bytes=memory.alignment_bytes,
    )


def enumerate_curves(config: Mapping[str, Any]) -> list[CurveSpec]:
    """Enumerate deterministic, curve-granular execution units."""

    profile_names = [str(item) for item in config["verifier"]["enabled_profiles"]]
    curves: list[CurveSpec] = []
    for seed_value in config["seeds"]:
        for scenario_value in config["scenarios"]:
            for profile_name in profile_names:
                for legitimate_value in config["loads"]["legitimate_rps"]:
                    curves.append(
                        CurveSpec(
                            ordinal=len(curves),
                            seed=int(seed_value),
                            scenario=str(scenario_value),
                            profile_name=profile_name,
                            legitimate_rps=float(legitimate_value),
                        )
                    )
    return curves


def select_curve_shard(
    curves: Sequence[CurveSpec], shard_index: int, shard_count: int
) -> list[CurveSpec]:
    """Assign complete seed blocks so every within-seed comparison stays on one host."""

    if shard_count < 1:
        raise ValueError("shard_count must be positive")
    if not 0 <= shard_index < shard_count:
        raise ValueError("shard_index must be in [0, shard_count)")
    seed_order = list(dict.fromkeys(curve.seed for curve in curves))
    seed_shards = {seed: rank % shard_count for rank, seed in enumerate(seed_order)}
    return [curve for curve in curves if seed_shards[curve.seed] == shard_index]


def enumerate_points(
    config: Mapping[str, Any], curves: Sequence[CurveSpec] | None = None
) -> list[PointSpec]:
    selected = enumerate_curves(config) if curves is None else list(curves)
    method_names = [str(item["name"]) for item in config["methods"]]
    return [
        PointSpec(curve, method_name, float(invalid_rps))
        for curve in selected
        for invalid_rps in config["loads"]["invalid_rps"]
        for method_name in method_names
    ]


def _git_metadata() -> dict[str, Any]:
    def run(*args: str) -> str | None:
        try:
            completed = subprocess.run(
                ["git", *args],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return completed.stdout.strip()

    commit = run("rev-parse", "HEAD")
    status = run("status", "--porcelain")
    return {
        "commit": commit or "UNCOMMITTED",
        "dirty": True if commit is None else bool(status),
        "status_available": status is not None,
    }


def enforce_git_policy(config: Mapping[str, Any], git: Mapping[str, Any]) -> None:
    execution = config["execution"]
    require_clean = bool(execution["require_clean_git"])
    provenance_class = str(execution["provenance_class"])
    if require_clean:
        failures: list[str] = []
        if not git.get("status_available"):
            failures.append("git status is unavailable")
        if git.get("commit") in {None, "", "UNCOMMITTED"}:
            failures.append("git commit is unavailable")
        if git.get("dirty") is not False:
            failures.append("working tree is dirty")
        if failures:
            raise RuntimeError(
                "formal service run requires a clean committed tree: " + "; ".join(failures)
            )
    elif not provenance_class.startswith("TEMPORARY_"):
        raise ValueError(
            "runs that do not require clean git must use a TEMPORARY_* provenance_class"
        )


def _numa_metadata() -> dict[str, Any]:
    if platform.system() == "Windows":
        try:
            highest = ctypes.c_ulong()
            function = ctypes.WinDLL("kernel32").GetNumaHighestNodeNumber
            if not function(ctypes.byref(highest)):
                raise ctypes.WinError()
            return {"status": "OBSERVED", "node_count": int(highest.value) + 1}
        except Exception as exc:  # pragma: no cover - depends on Windows API support.
            return {"status": "BLOCKED", "reason": f"{type(exc).__name__}: {exc}"}
    online = Path("/sys/devices/system/node/online")
    if online.exists():
        return {"status": "OBSERVED", "online": online.read_text().strip()}
    return {"status": "BLOCKED", "reason": "portable NUMA topology unavailable"}


def _host_metadata() -> dict[str, Any]:
    try:
        import psutil

        process = psutil.Process()
        affinity = process.cpu_affinity() if hasattr(process, "cpu_affinity") else None
        frequency = psutil.cpu_freq()
        temperatures = (
            psutil.sensors_temperatures() if hasattr(psutil, "sensors_temperatures") else {}
        )
        psutil_version = metadata.version("psutil")
    except Exception as exc:  # pragma: no cover - platform dependency failure.
        affinity = None
        frequency = None
        temperatures = {}
        psutil_version = None
        psutil_error = f"{type(exc).__name__}: {exc}"
    else:
        psutil_error = None
    packages: dict[str, str | None] = {}
    for package in ("argon2-cffi", "PyYAML", "psutil", "scipy"):
        try:
            packages[package] = metadata.version(package)
        except metadata.PackageNotFoundError:
            packages[package] = None
    return {
        "hostname": platform.node(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "process_affinity": affinity,
        "thread_affinity": "UNPINNED",
        "numa": _numa_metadata(),
        "cpu_frequency": {
            "observed_current_mhz": None if frequency is None else frequency.current,
            "observed_min_mhz": None if frequency is None else frequency.min,
            "observed_max_mhz": None if frequency is None else frequency.max,
            "policy": "BLOCKED: portable Python does not expose the OS governor/power plan",
        },
        "thermal_state": (
            {"status": "OBSERVED", "sensors": temperatures}
            if temperatures
            else {"status": "BLOCKED", "reason": "no sensor data exposed by psutil"}
        ),
        "python": sys.version,
        "python_compiler": platform.python_compiler(),
        "python_config_args": sysconfig.get_config_var("CONFIG_ARGS"),
        "openssl_version": ssl.OPENSSL_VERSION,
        "packages": packages,
        "psutil_probe_error": psutil_error,
        "psutil_version": psutil_version,
    }


def _curve_environment_binding(host: Mapping[str, Any], profile: KdfProfile) -> dict[str, Any]:
    """Stable fields that must not change within a partially resumed curve."""

    return _curve_environment_binding_values(
        host, {"name": profile.name, **profile.implementation_metadata()}
    )


def _curve_environment_binding_values(
    host: Mapping[str, Any], kdf: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "binding_schema_version": 1,
        "host": {
            key: host.get(key)
            for key in (
                "hostname",
                "platform",
                "machine",
                "processor",
                "logical_cpu_count",
                "process_affinity",
                "thread_affinity",
                "numa",
            )
        },
        "runtime": {
            "python": host.get("python"),
            "python_compiler": host.get("python_compiler"),
            "python_config_args": host.get("python_config_args"),
            "openssl_version": host.get("openssl_version"),
            "packages": host.get("packages"),
        },
        "kdf": dict(kdf),
    }


def _arrival_offsets(
    rate_rps: float,
    duration_seconds: float,
    distribution: str,
    rng: random.Random,
) -> list[float]:
    if rate_rps < 0:
        raise ValueError("offered rates must be non-negative")
    if rate_rps == 0:
        return []
    if distribution == "deterministic":
        count = int(math.floor(rate_rps * duration_seconds))
        return [(index + 0.5) / rate_rps for index in range(count)]
    if distribution != "poisson":
        raise ValueError("arrival_distribution must be deterministic or poisson")
    offsets: list[float] = []
    current = rng.expovariate(rate_rps)
    while current < duration_seconds:
        offsets.append(current)
        current += rng.expovariate(rate_rps)
    return offsets


def _required_conditioned_unique_tuple_pool_size(config: Mapping[str, Any]) -> int:
    """Return the largest conditioned tuple pool needed by the declared trace."""

    scenario_config = config.get("scenario_parameters", {})
    if (
        not isinstance(scenario_config, Mapping)
        or scenario_config.get("false_positive_source") != STRONG_ORACLE_SOURCE
    ):
        return 0
    measurement = config.get("measurement", {})
    if not isinstance(measurement, Mapping):
        return 0
    loads = config.get("loads", {})
    if not isinstance(loads, Mapping):
        return 0
    duration = float(measurement["duration_seconds"])
    distribution = str(measurement["arrival_distribution"])
    repeat_tuple_count = int(scenario_config.get("repeat_tuple_count", 4))
    required = 0
    for curve in enumerate_curves(config):
        if curve.scenario == "repeat_heavy_false_positive":
            required = max(required, repeat_tuple_count)
            continue
        if curve.scenario not in FALSE_POSITIVE_SCENARIOS:
            continue
        for invalid_value in loads["invalid_rps"]:
            invalid_rps = float(invalid_value)
            invalid_rng = random.Random(
                _derived_seed(curve.seed, curve.scenario, "invalid", duration)
            )
            invalid_count = len(
                _arrival_offsets(invalid_rps, duration, distribution, invalid_rng)
            )
            if curve.scenario == "mixed_unique_repeat_false_positive":
                invalid_count += repeat_tuple_count
            required = max(required, invalid_count)
    return required


def _discover_false_positives(
    dataset: ServiceDataset,
    screen: ScreenRealization,
    required: int,
    max_scan: int,
) -> tuple[InvalidCredential, ...]:
    found: list[InvalidCredential] = []
    for index in range(max_scan):
        credential = dataset.invalid_credential(index)
        if screen.query(credential.query).positive:
            found.append(credential)
            if len(found) >= required:
                return tuple(found)
    raise RuntimeError(
        "BLOCKED: actual screen queries found only "
        f"{len(found)} false positives after {max_scan} candidates; required {required}"
    )


def _uses_strong_oracle_conditioning(scenario: str, scenario_config: Mapping[str, Any]) -> bool:
    return (
        scenario in FALSE_POSITIVE_SCENARIOS
        and scenario_config.get("false_positive_source") == STRONG_ORACLE_SOURCE
    )


def _frozen_conditioned_credentials(
    dataset: ServiceDataset,
    scenario: str,
    scenario_config: Mapping[str, Any],
    pool_size: int,
) -> tuple[InvalidCredential, ...]:
    if not _uses_strong_oracle_conditioning(scenario, scenario_config):
        return ()
    required = (
        int(scenario_config["repeat_tuple_count"])
        if scenario == "repeat_heavy_false_positive"
        else pool_size
    )
    return tuple(dataset.invalid_credential(index) for index in range(required))


def _conditioned_tuple_set_id(
    credentials: Sequence[InvalidCredential],
) -> str | None:
    if not credentials:
        return None
    digest = hashlib.sha256(b"TRAPS-TM2-conditioned-tuples-v1\x00")
    digest.update(struct.pack(">Q", len(credentials)))
    for credential in credentials:
        tuple_bytes = credential.tuple_id.encode("utf-8")
        digest.update(struct.pack(">I", len(tuple_bytes)))
        digest.update(tuple_bytes)
        digest.update(struct.pack(">Q", credential.query.account_index))
        digest.update(credential.query.token)
    return digest.hexdigest()


def _invalid_request(
    scenario: str,
    index: int,
    request_id: int,
    dataset: ServiceDataset,
    false_positives: Sequence[InvalidCredential],
    scenario_config: Mapping[str, Any],
    rng: random.Random,
) -> AuthRequest:
    repeat_tuple_count = int(scenario_config.get("repeat_tuple_count", 4))
    if scenario == "repeat_heavy_false_positive":
        credential = false_positives[index % min(repeat_tuple_count, len(false_positives))]
    elif scenario in {
        "unique_first_seen_false_positive",
        "cache_pollution_false_positive",
    }:
        if index >= len(false_positives):
            raise RuntimeError(
                "BLOCKED: false-positive pool is smaller than the unique offered trace"
            )
        credential = false_positives[index]
    elif scenario == "mixed_unique_repeat_false_positive":
        repeat_fraction = float(scenario_config.get("repeat_fraction", 0.75))
        if rng.random() < repeat_fraction:
            credential = false_positives[index % min(repeat_tuple_count, len(false_positives))]
        else:
            unique_index = repeat_tuple_count + index
            if unique_index >= len(false_positives):
                raise RuntimeError(
                    "BLOCKED: false-positive pool is smaller than the mixed offered trace"
                )
            credential = false_positives[unique_index]
    elif scenario == "old_password_replay":
        account = dataset.accounts[index % dataset.account_count]
        password = dataset.old_password(account.account_index)
        credential = InvalidCredential(
            account,
            password,
            account.screen_query(dataset.codec, password),
            f"{account.account_id}:old-password",
        )
    elif scenario == "password_spraying":
        account = dataset.accounts[index % dataset.account_count]
        password = b"shared-spray-password"
        credential = InvalidCredential(
            account,
            password,
            account.screen_query(dataset.codec, password),
            f"{account.account_id}:spray",
        )
    elif scenario in {"uniform_unique_random", "wrong_credential_stuffing"}:
        credential = dataset.invalid_credential(index + 10_000_000)
    elif scenario == "no_account_flood":
        return AuthRequest(
            request_id=request_id,
            username=f"unknown-{index:012d}",
            password=b"unknown-invalid:" + struct.pack(">Q", index),
            traffic_class=TrafficClass.UNKNOWN,
            tuple_id=f"unknown-{index:012d}:invalid",
        )
    elif scenario == "correct_password_flood":
        account = dataset.accounts[index % dataset.account_count]
        return AuthRequest(
            request_id=request_id,
            username=account.username,
            password=dataset.correct_password(account.account_index),
            traffic_class=TrafficClass.CORRECT_PASSWORD_ATTACK,
            tuple_id=f"{account.account_id}:correct-attack",
        )
    else:
        raise ValueError(f"unsupported scenario: {scenario}")
    return AuthRequest(
        request_id=request_id,
        username=credential.account.username,
        password=credential.password,
        traffic_class=TrafficClass.INVALID,
        tuple_id=credential.tuple_id,
    )


def _build_plan(
    dataset: ServiceDataset,
    screen: ScreenRealization,
    false_positives: Sequence[InvalidCredential],
    seed: int,
    scenario: str,
    legitimate_rps: float,
    invalid_rps: float,
    duration_seconds: float,
    distribution: str,
    scenario_config: Mapping[str, Any],
    request_id_start: int = 0,
) -> WorkloadPlan:
    oracle_conditioned = _uses_strong_oracle_conditioning(scenario, scenario_config)
    legitimate_rng = random.Random(_derived_seed(seed, scenario, "legitimate", duration_seconds))
    invalid_rng = random.Random(_derived_seed(seed, scenario, "invalid", duration_seconds))
    legitimate_offsets = _arrival_offsets(
        legitimate_rps, duration_seconds, distribution, legitimate_rng
    )
    invalid_offsets = _arrival_offsets(invalid_rps, duration_seconds, distribution, invalid_rng)
    descriptors = [(offset, "legitimate", index) for index, offset in enumerate(legitimate_offsets)]
    descriptors.extend((offset, "invalid", index) for index, offset in enumerate(invalid_offsets))
    descriptors.sort(key=lambda item: (item[0], item[1], item[2]))
    arrivals: list[ScheduledArrival] = []
    for position, (offset, stream, index) in enumerate(descriptors):
        request_id = request_id_start + position
        if stream == "legitimate":
            account = dataset.accounts[legitimate_rng.randrange(dataset.account_count)]
            request = AuthRequest(
                request_id=request_id,
                username=account.username,
                password=dataset.correct_password(account.account_index),
                traffic_class=TrafficClass.LEGITIMATE,
                tuple_id=f"{account.account_id}:valid",
            )
        else:
            request = _invalid_request(
                scenario,
                index,
                request_id,
                dataset,
                false_positives,
                scenario_config,
                invalid_rng,
            )
        arrivals.append(ScheduledArrival(offset, request))

    invalid_requests = [
        item.request
        for item in arrivals
        if item.request.traffic_class in {TrafficClass.INVALID, TrafficClass.UNKNOWN}
    ]
    distinct_invalid = {request.tuple_id for request in invalid_requests}
    invalid_tuple_multiplicities: dict[str, int] = {}
    for request in invalid_requests:
        invalid_tuple_multiplicities[request.tuple_id] = (
            invalid_tuple_multiplicities.get(request.tuple_id, 0) + 1
        )
    multiplicity_commitment_id = _canonical_hash(
        {
            "schema": "traps-service-invalid-tuple-multiplicity-v1",
            "multiplicities": sorted(invalid_tuple_multiplicities.items()),
        }
    )
    minimum_invalid_tuple_multiplicity = (
        min(invalid_tuple_multiplicities.values()) if invalid_tuple_multiplicities else 0
    )
    known_invalid = [
        request for request in invalid_requests if dataset.account(request.username) is not None
    ]
    weighted_positives = 0
    first_results: dict[str, bool] = {}
    if not oracle_conditioned:
        for request in known_invalid:
            account = dataset.account(request.username)
            assert account is not None
            positive = screen.query(account.screen_query(dataset.codec, request.password)).positive
            weighted_positives += int(positive)
            first_results.setdefault(request.tuple_id, positive)

    conditioned_tuple_set_id = (
        _conditioned_tuple_set_id(false_positives) if oracle_conditioned else None
    )
    conditioning = {
        "false_positive_source": STRONG_ORACLE_SOURCE if oracle_conditioned else None,
        "conditioned_tuple_set_id": conditioned_tuple_set_id,
        "conditioned_tuple_count": len(false_positives) if oracle_conditioned else 0,
        "underlying_filter_query_executed": oracle_conditioned,
        "conditional_intervention_does_not_estimate_ffr": oracle_conditioned,
    }

    workload_manifest = {
        **dataset.base_manifest(),
        "filter_seed": screen.seed,
        "filter_spec_id": screen.spec.identity,
        "filter_realization_id": screen.identity,
        "scenario": scenario,
        "seed": seed,
        "legitimate_rps": legitimate_rps,
        "invalid_rps": invalid_rps,
        "duration_seconds": duration_seconds,
        "arrival_distribution": distribution,
        "false_positive_conditioning": conditioning,
        "invalid_tuple_multiplicity_commitment_id": multiplicity_commitment_id,
        "minimum_invalid_tuple_multiplicity": minimum_invalid_tuple_multiplicity,
        "events": [
            {
                "offset_ns": int(item.offset_seconds * 1_000_000_000),
                "traffic_class": item.request.traffic_class.value,
                "tuple_hash": hashlib.sha256(item.request.tuple_id.encode()).hexdigest(),
            }
            for item in arrivals
        ],
    }
    return WorkloadPlan(
        arrivals=tuple(arrivals),
        dataset_hash=_canonical_hash(workload_manifest),
        distinct_invalid_count=len(distinct_invalid),
        observed_first_seen_ffr=(
            None
            if oracle_conditioned
            else sum(first_results.values()) / len(first_results)
            if first_results
            else None
        ),
        observed_request_weighted_ffr=(
            None
            if oracle_conditioned
            else weighted_positives / len(known_invalid)
            if known_invalid
            else None
        ),
        false_positive_source=(STRONG_ORACLE_SOURCE if oracle_conditioned else None),
        conditioned_tuple_set_id=conditioned_tuple_set_id,
        conditioned_tuple_count=(len(false_positives) if oracle_conditioned else 0),
        conditioned_queries=(
            frozenset(credential.query for credential in false_positives)
            if oracle_conditioned
            else frozenset()
        ),
        invalid_tuple_multiplicity_commitment_id=multiplicity_commitment_id,
        minimum_invalid_tuple_multiplicity=minimum_invalid_tuple_multiplicity,
    )


def _parse_limits(config: Mapping[str, Any]) -> ServiceLimits:
    service = config["service"]
    return ServiceLimits(
        frontend_workers=int(service["frontend_workers"]),
        backend_workers=int(service["backend_workers"]),
        frontend_queue_capacity=int(service["frontend_queue_capacity"]),
        backend_queue_capacity=int(service["backend_queue_capacity"]),
        max_connections=int(service["max_connections"]),
        max_padding_timers=int(service["max_padding_timers"]),
        max_waiters_per_key=int(service["max_waiters_per_key"]),
        max_waiters_global=int(service["max_waiters_global"]),
        failure_padding_seconds=float(service["failure_padding_ms"]) / 1_000,
        request_timeout_seconds=float(service["request_timeout_ms"]) / 1_000,
        cache_capacity=int(service["cache_capacity"]),
        cache_ttl_seconds=float(service["cache_ttl_seconds"]),
        cache_max_entries_per_account=(
            None
            if service.get("cache_max_entries_per_account") is None
            else int(service["cache_max_entries_per_account"])
        ),
    )


def _parse_methods(config: Mapping[str, Any]) -> list[ServiceMethod]:
    methods = config.get("methods")
    if not isinstance(methods, list) or not methods:
        raise ValueError("methods must be a non-empty list")
    for item in methods:
        if not isinstance(item, Mapping):
            raise ValueError("each method declaration must be a mapping")
        implementation = str(item.get("implementation", ""))
        expected = METHOD_IMPLEMENTATIONS.get(implementation)
        if expected is None:
            raise ValueError(f"unsupported service method implementation: {implementation!r}")
        observed = {field: item.get(field) for field in expected}
        if observed != expected:
            raise ValueError(
                f"method {implementation!r} declaration does not match its runner implementation"
            )
        if "strong" in str(item.get("baseline_role", "")).casefold():
            raise ValueError(
                "the service runner cannot declare a strong baseline before the "
                "Phase 1 artifact is independently bound"
            )
    parsed = [
        ServiceMethod(
            name=str(item["name"]),
            use_positive_screen=bool(item["use_positive_screen"]),
            cache_policy=item.get("cache_policy"),
            use_singleflight=bool(item["use_singleflight"]),
            claim_scope=str(item.get("claim_scope", "mechanism_only")),
            baseline_role=str(item.get("baseline_role", "candidate")),
        )
        for item in methods
    ]
    if len({method.name for method in parsed}) != len(parsed):
        raise ValueError("method names must be unique")
    if len({str(item["implementation"]) for item in methods}) != len(methods):
        raise ValueError("method implementations must be unique")
    filter_family = FrozenScreenSpec.from_config(config["filter"]).family
    positive_implementations = {
        str(item["implementation"]) for item in methods if bool(item.get("use_positive_screen"))
    }
    if not positive_implementations:
        raise ValueError("at least one positive-screen method is required")
    if positive_implementations <= LEGACY_GLOBAL_SCREEN_IMPLEMENTATIONS:
        if filter_family != "global_bloom":
            raise ValueError("Global Bloom method labels cannot be used with another filter family")
    elif not positive_implementations <= GENERIC_SCREEN_IMPLEMENTATIONS:
        raise ValueError(
            "positive-screen methods cannot mix family-specific and generic implementations"
        )
    return parsed


def _configured_runner_capability(config: Mapping[str, Any]) -> str:
    positive_implementations = {
        str(item["implementation"])
        for item in config["methods"]
        if isinstance(item, Mapping) and bool(item.get("use_positive_screen"))
    }
    if not positive_implementations:
        raise ValueError("at least one positive-screen method is required")
    if positive_implementations <= LEGACY_GLOBAL_SCREEN_IMPLEMENTATIONS:
        return RUNNER_CAPABILITY
    if positive_implementations <= GENERIC_SCREEN_IMPLEMENTATIONS:
        return GENERAL_SCREEN_FACTORY_CAPABILITY
    raise ValueError("service method implementations do not define one screen capability")


def _method_declaration(config: Mapping[str, Any], method_name: str) -> Mapping[str, Any]:
    matches = [
        item
        for item in config["methods"]
        if isinstance(item, Mapping) and item.get("name") == method_name
    ]
    if len(matches) != 1:
        raise ValueError(f"method declaration is not unique: {method_name}")
    return matches[0]


def _main_claims_alignment(config: Mapping[str, Any]) -> dict[str, Any]:
    try:
        manifest, manifest_id = load_main_claims_manifest(
            MAIN_CLAIMS_PATH,
            paper_claims_path=PAPER_CLAIMS_PATH,
        )
    except OSError as exc:
        return {
            "status": "BLOCKED_MAIN_CLAIMS_MANIFEST_UNAVAILABLE",
            "reason": f"{type(exc).__name__}: {exc}",
        }
    except ClaimsManifestError as exc:
        return {
            "status": "BLOCKED_MAIN_CLAIMS_MANIFEST_INVALID",
            "reason": str(exc),
        }

    declared_manifest_id = config.get("main_claims_manifest_id")
    manifest_id_matches = type(declared_manifest_id) is str and declared_manifest_id == manifest_id
    if not manifest_id_matches:
        return {
            "status": "BLOCKED_MAIN_CLAIMS_MANIFEST_ID_MISMATCH",
            "reason": "service main_claims_manifest_id differs from strict manifest identity",
            "declared_manifest_id": declared_manifest_id,
            "main_claims_manifest_id": manifest_id,
            "manifest_id_matches": False,
        }
    if not bool(config.get("execution", {}).get("require_clean_git")):
        return {
            "status": MAIN_CLAIMS_NOT_FROZEN,
            "manifest_status": manifest["status"],
            "service_contract_freeze_status": manifest["service_e7_contract"]["freeze_status"],
            "main_claims_manifest_id": manifest_id,
            "declared_manifest_id": declared_manifest_id,
            "manifest_id_matches": True,
            "service_contract_aligned": False,
            "reason": "temporary smoke is outside the frozen formal E7 contract",
        }

    service_contract = manifest["service_e7_contract"]
    main_seeds = list(service_contract["seeds"])
    service_seeds = [int(item) for item in config.get("seeds", [])]
    main_profiles = list(service_contract["verifier_profiles"])
    service_profiles = [
        str(item) for item in config.get("verifier", {}).get("enabled_profiles", [])
    ]
    seeds_aligned = service_seeds == main_seeds
    profiles_aligned = service_profiles == main_profiles
    main_specs = service_contract["verifier_profiles"]
    service_specs = config.get("verifier", {}).get("profiles", {})
    specs_aligned = profiles_aligned and _canonical_json(service_specs) == _canonical_json(
        main_specs
    )
    workload = service_contract["workload"]
    measurement = service_contract["measurement"]
    execution_contract = service_contract["execution"]
    registration = config.get("phase1_baseline_registration", {})
    contract_aligned = all(
        (
            config.get("traffic_mode") == workload["traffic_mode"],
            list(config.get("scenarios", [])) == workload["scenarios"],
            list(config.get("loads", {}).get("legitimate_rps", [])) == workload["legitimate_rps"],
            list(config.get("loads", {}).get("invalid_rps", [])) == workload["invalid_rps"],
            [method.get("implementation") for method in config.get("methods", [])]
            == workload["methods"],
            config.get("measurement", {}).get("warmup_seconds") == measurement["warmup_seconds"],
            config.get("measurement", {}).get("duration_seconds")
            == measurement["duration_seconds"],
            config.get("measurement", {}).get("minimum_resource_samples")
            == measurement["minimum_resource_samples"],
            config.get("service", {}).get("backend_workers")
            == execution_contract["backend_workers_per_point"],
            registration.get("selection_contract_id")
            == service_contract["phase1_baseline_selection"]["contract_id"],
            registration.get("selected_profile")
            in {None, service_contract["phase1_baseline_selection"]["deployment_profile"]},
            config.get("g2_gate_contract") == service_contract["g2_gate_contract"],
            config.get("g4_capacity_contract") == service_contract["g4_capacity_contract"],
            config.get("g5_gate_contract") == service_contract["g5_gate_contract"],
        )
    )
    if service_contract["freeze_status"] != "PREREGISTERED_BEFORE_FORMAL_E7_COLLECTION":
        status = MAIN_CLAIMS_NOT_FROZEN
    elif seeds_aligned and profiles_aligned and specs_aligned and contract_aligned:
        status = MAIN_CLAIMS_ALIGNED
    else:
        status = "BLOCKED_MAIN_CLAIMS_SEED_OR_VERIFIER_PROFILE_MISMATCH"
    return {
        "status": status,
        "manifest_status": manifest["status"],
        "service_contract_freeze_status": service_contract["freeze_status"],
        "main_claims_manifest_id": manifest_id,
        "declared_manifest_id": declared_manifest_id,
        "manifest_id_matches": True,
        "seed_sequence_aligned": seeds_aligned,
        "verifier_profile_sequence_aligned": profiles_aligned,
        "verifier_profile_specs_aligned": specs_aligned,
        "service_contract_aligned": contract_aligned,
        "service_seed_count": len(service_seeds),
        "main_claim_seed_count": len(main_seeds),
        "service_verifier_profiles": service_profiles,
        "main_claim_verifier_profiles": main_profiles,
    }


def _require_current_main_claims_manifest_id(config: Mapping[str, Any], *, context: str) -> str:
    """Rebind an artifact consumer to the current strict claims manifest."""

    try:
        _, manifest_id = load_main_claims_manifest(
            MAIN_CLAIMS_PATH,
            paper_claims_path=PAPER_CLAIMS_PATH,
        )
    except (OSError, UnicodeError, ClaimsManifestError) as exc:
        raise ValueError(
            f"{context} cannot load the current strict main claims manifest: {exc}"
        ) from exc
    if config.get("main_claims_manifest_id") != manifest_id:
        raise ValueError(
            f"{context} main_claims_manifest_id differs from the current strict manifest"
        )
    evidence = config.get("evidence_scope")
    if (
        not isinstance(evidence, Mapping)
        or evidence.get("main_claims_artifact_binding") != MAIN_CLAIMS_ARTIFACT_BOUND
    ):
        raise ValueError(f"{context} main claims artifact binding is not BOUND")
    return manifest_id


def _validate_phase1_baseline_registration(
    config: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    """Validate either the prospective pending slot or a full v2.1 registration."""

    registration = config.get("phase1_baseline_registration")
    if registration is None:
        if bool(config["execution"]["require_clean_git"]):
            raise ValueError("formal service manifests require phase1_baseline_registration")
        return None
    expected_filter = (
        config.get("filter")
        if isinstance(registration, Mapping)
        and registration.get("status") in PHASE1_BASELINE_REGISTERED_STATUSES
        else None
    )
    try:
        return phase1_registration.validate_binding(
            registration,
            schema=PHASE1_BASELINE_REGISTRATION_SCHEMA,
            root=ROOT,
            expected_filter=expected_filter,
        )
    except phase1_registration.RegistrationError as error:
        raise ValueError(f"invalid phase1_baseline_registration: {error}") from error


def _phase1_baseline_ready_marker(status: object) -> str | None:
    if status == PHASE1_BASELINE_REGISTERED:
        return STRONG_BASELINE_READY
    if status == PHASE1_BASELINE_RECOVERY_REGISTERED:
        return PHASE1_BASELINE_RECOVERY_READY
    return None


def formal_execution_blockers(config: Mapping[str, Any]) -> list[str]:
    """Return semantic blockers that prevent promotion to formal evidence."""

    if not bool(config["execution"]["require_clean_git"]):
        return []
    _validate_phase1_baseline_registration(config)
    evidence = config.get("evidence_scope", {})
    blockers: list[str] = []
    registration = config.get("phase1_baseline_registration")
    if (
        not isinstance(registration, Mapping)
        or registration.get("status") not in PHASE1_BASELINE_REGISTERED_STATUSES
    ):
        blockers.append(PHASE1_BASELINE_RECEIPT_BLOCKER)
    alignment = _main_claims_alignment(config)
    if alignment["status"] != MAIN_CLAIMS_ALIGNED:
        blockers.append(str(alignment["status"]))
    if evidence.get("main_claims_artifact_binding") != MAIN_CLAIMS_ARTIFACT_BOUND:
        blockers.append(MAIN_CLAIMS_ARTIFACT_BINDING_BLOCKER)
    required_pool_size = _required_conditioned_unique_tuple_pool_size(config)
    configured_pool_size = int(config.get("dataset", {}).get("false_positive_pool_size", 0))
    if configured_pool_size < required_pool_size:
        blockers.append("CONDITIONED_UNIQUE_TUPLE_POOL_TOO_SMALL_FOR_FORMAL_TRACE")
    # Authorization and promotion flags are derivative gates.  Report them only
    # after the two authoritative inputs above have actually been registered.
    if not blockers:
        expected_baseline = _phase1_baseline_ready_marker(registration.get("status"))
        if config["execution"].get("run_authorization") != "AUTHORIZED":
            blockers.append("FORMAL_RUN_NOT_AUTHORIZED")
        if evidence.get("strong_matched_baseline") != expected_baseline:
            blockers.append("STRONG_MATCHED_BASELINE_NOT_FROZEN")
        if evidence.get("runner_capability") != GENERAL_SCREEN_FACTORY_CAPABILITY:
            blockers.append("PHASE1_SCREEN_ARTIFACT_NOT_BOUND")
        if evidence.get("gate_claims_permitted") is not True:
            blockers.append("GATE_CLAIMS_NOT_PERMITTED")
    return blockers


def enforce_execution_gate(config: Mapping[str, Any]) -> None:
    blockers = formal_execution_blockers(config)
    if blockers:
        raise RuntimeError(
            "BLOCKED: formal service execution is not authorized: " + "; ".join(blockers)
        )


def method_execution_order(
    config: Mapping[str, Any], curve: CurveSpec, invalid_load_index: int
) -> list[str]:
    """Deterministically rotate methods by seed rank and tested load rank."""

    names = [str(item["name"]) for item in config["methods"]]
    seed_values = [int(item) for item in config["seeds"]]
    try:
        seed_rank = seed_values.index(curve.seed)
    except ValueError as exc:
        raise ValueError(f"curve seed is not declared: {curve.seed}") from exc
    offset = (seed_rank + invalid_load_index) % len(names)
    return names[offset:] + names[:offset]


def _parse_profiles(config: Mapping[str, Any]) -> list[KdfProfile]:
    verifier = config.get("verifier")
    if not isinstance(verifier, Mapping):
        raise ValueError("verifier must be a mapping")
    enabled = verifier.get("enabled_profiles")
    profiles = verifier.get("profiles")
    if not isinstance(enabled, list) or not enabled or not isinstance(profiles, Mapping):
        raise ValueError("verifier enabled_profiles/profiles are required")
    return [KdfProfile.from_mapping(str(name), profiles[str(name)]) for name in enabled]


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    value = load_unique_yaml(path, label="service configuration")
    if not isinstance(value, dict):
        raise ValueError("configuration root must be a mapping")
    if value.get("schema_version") != CONFIG_SCHEMA_VERSION:
        raise ValueError(f"service configuration schema_version must be {CONFIG_SCHEMA_VERSION}")
    if value.get("traffic_mode") != "open_loop":
        raise ValueError("service overload runs require traffic_mode: open_loop")
    seeds = value.get("seeds")
    scenarios = value.get("scenarios")
    if not isinstance(seeds, list) or not seeds:
        raise ValueError("seeds must be a non-empty list")
    if any(isinstance(item, bool) or not isinstance(item, int) for item in seeds):
        raise ValueError("seeds must contain integers")
    if any(not 0 <= item <= 0xFFFFFFFFFFFFFFFF for item in seeds):
        raise ValueError("seeds must contain uint64 integers")
    if len(set(seeds)) != len(seeds):
        raise ValueError("seeds must be unique")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("scenarios must be a non-empty list")
    unknown = set(map(str, scenarios)) - SUPPORTED_SCENARIOS
    if unknown:
        raise ValueError(f"unsupported scenarios: {sorted(unknown)}")
    execution = value.get("execution")
    if not isinstance(execution, Mapping):
        raise ValueError("execution mapping is required")
    if not isinstance(execution.get("require_clean_git"), bool):
        raise ValueError("execution.require_clean_git must be Boolean")
    provenance_class = execution.get("provenance_class")
    if not isinstance(provenance_class, str) or not provenance_class:
        raise ValueError("execution.provenance_class must be non-empty")
    if not execution["require_clean_git"] and not provenance_class.startswith("TEMPORARY_"):
        raise ValueError("non-clean execution must use a TEMPORARY_* provenance_class")
    authorization = execution.get("run_authorization")
    if not isinstance(authorization, str) or not authorization:
        raise ValueError("execution.run_authorization must be non-empty")
    if execution["require_clean_git"] and provenance_class.startswith("TEMPORARY_"):
        raise ValueError("formal execution cannot use temporary provenance")
    _validate_phase1_baseline_registration(value)
    if execution["require_clean_git"]:
        if value.get("g2_gate_contract") != G2_GATE_CONTRACT:
            raise ValueError("formal g2_gate_contract differs from the prospective freeze")
        if value.get("g4_capacity_contract") != G4_CAPACITY_CONTRACT:
            raise ValueError("formal g4_capacity_contract differs from the prospective freeze")
        if value.get("g5_gate_contract") != G5_GATE_CONTRACT:
            raise ValueError("formal g5_gate_contract differs from the prospective freeze")
    dataset = value.get("dataset")
    if not isinstance(dataset, Mapping):
        raise ValueError("dataset mapping is required")
    if dataset.get("generator") != DATASET_GENERATOR:
        raise ValueError(f"dataset.generator must be the implemented {DATASET_GENERATOR!r}")
    for field in ("account_count", "false_positive_pool_size", "false_positive_max_scan"):
        if int(dataset.get(field, 0)) < 1:
            raise ValueError(f"dataset.{field} must be positive")
    scenario_parameters = value.get("scenario_parameters", {})
    if not isinstance(scenario_parameters, Mapping):
        raise ValueError("scenario_parameters must be a mapping")
    if execution["require_clean_git"]:
        expected_conditioning = {
            "false_positive_source": G2_GATE_CONTRACT["false_positive_source"],
            "underlying_filter_query_executed": True,
            "conditional_intervention_does_not_estimate_ffr": True,
            "conditioned_unique_tuple_pool_size": FORMAL_CONDITIONED_UNIQUE_TUPLE_POOL_SIZE,
        }
        for field, expected in expected_conditioning.items():
            if scenario_parameters.get(field) != expected:
                raise ValueError(f"formal scenario_parameters.{field} differs from the TM2 freeze")
        if int(dataset["false_positive_pool_size"]) != int(
            scenario_parameters["conditioned_unique_tuple_pool_size"]
        ):
            raise ValueError("conditioned unique tuple pool differs from dataset binding")
        if (
            scenario_parameters.get("repeat_tuple_count")
            != G2_GATE_CONTRACT["repeated_tuple_count"]
        ):
            raise ValueError("formal repeat tuple count differs from g2_gate_contract")
    dataset_seed = dataset.get("seed")
    if (
        isinstance(dataset_seed, bool)
        or not isinstance(dataset_seed, int)
        or not 0 <= dataset_seed <= 0xFFFFFFFFFFFFFFFF
    ):
        raise ValueError("dataset.seed must be a uint64 integer")
    filter_config = value.get("filter")
    if not isinstance(filter_config, Mapping):
        raise ValueError("filter mapping is required")
    FrozenScreenSpec.from_config(filter_config)
    measurement = value.get("measurement", {})
    for field in (
        "warmup_seconds",
        "duration_seconds",
        "resource_sample_interval_seconds",
        "shutdown_timeout_seconds",
    ):
        if float(measurement.get(field, 0)) <= 0:
            raise ValueError(f"measurement.{field} must be positive")
    for field in ("maximum_arrival_lag_p99_ms", "maximum_arrival_lag_max_ms"):
        if float(measurement.get(field, -1)) < 0:
            raise ValueError(f"measurement.{field} must be non-negative")
    if int(measurement.get("minimum_resource_samples", 0)) < 1:
        raise ValueError("measurement.minimum_resource_samples must be positive")
    if measurement.get("arrival_distribution") not in {"poisson", "deterministic"}:
        raise ValueError("measurement.arrival_distribution is invalid")
    loads = value.get("loads", {})
    for field in ("legitimate_rps", "invalid_rps"):
        if not isinstance(loads.get(field), list) or not loads[field]:
            raise ValueError(f"loads.{field} must be a non-empty list")
        if any(float(item) < 0 for item in loads[field]):
            raise ValueError(f"loads.{field} cannot contain negative rates")
        numeric = [float(item) for item in loads[field]]
        if numeric != sorted(set(numeric)):
            raise ValueError(f"loads.{field} must be unique and increasing")
    _parse_limits(value)
    methods = _parse_methods(value)
    _parse_profiles(value)
    criteria = value.get("saturation_criteria")
    if not isinstance(criteria, Mapping):
        raise ValueError("saturation_criteria mapping is required")
    inference_mode = criteria.get("inference_mode")
    if inference_mode not in {
        "interval_censored_curve",
        "diagnostic_points_only",
    }:
        raise ValueError("saturation_criteria.inference_mode is invalid")
    if execution["require_clean_git"] and inference_mode != "interval_censored_curve":
        raise ValueError("formal service manifests require interval-censored inference")
    baseline_method = str(criteria.get("baseline_method", ""))
    if baseline_method not in {method.name for method in methods}:
        raise ValueError("saturation_criteria.baseline_method must name a method")
    baseline_declaration = _method_declaration(value, baseline_method)
    if baseline_declaration.get("baseline_role") != "provisional_mechanism_baseline":
        raise ValueError(
            "the configured saturation baseline must be the provisional mechanism "
            "baseline; this runner has no strong matched baseline"
        )
    if float(criteria.get("maximum_legitimate_p99_regression_fraction", -1)) < 0:
        raise ValueError(
            "saturation_criteria.maximum_legitimate_p99_regression_fraction must be non-negative"
        )
    evidence = value.get("evidence_scope")
    if not isinstance(evidence, Mapping):
        raise ValueError("evidence_scope mapping is required")
    expected_capability = _configured_runner_capability(value)
    if evidence.get("runner_capability") != expected_capability:
        raise ValueError(f"evidence_scope.runner_capability must be {expected_capability!r}")
    if evidence.get("main_claims_artifact_binding") != MAIN_CLAIMS_ARTIFACT_BOUND:
        raise ValueError(
            f"evidence_scope.main_claims_artifact_binding must be {MAIN_CLAIMS_ARTIFACT_BOUND!r}"
        )
    registration_status = value.get("phase1_baseline_registration", {}).get("status")
    expected_baseline_marker = _phase1_baseline_ready_marker(registration_status)
    if (
        evidence.get("strong_matched_baseline")
        in {STRONG_BASELINE_READY, PHASE1_BASELINE_RECOVERY_READY}
        and registration_status not in PHASE1_BASELINE_REGISTERED_STATUSES
    ):
        raise ValueError(
            "this runner cannot declare a frozen strong matched baseline before "
            "the Phase 1 artifact identity and timing evidence are bound"
        )
    if (
        registration_status in PHASE1_BASELINE_REGISTERED_STATUSES
        and evidence.get("strong_matched_baseline") != expected_baseline_marker
    ):
        raise ValueError("a registered Phase 1 baseline must be the frozen strong baseline")
    alignment = _main_claims_alignment(value)
    if alignment["status"] in {
        "BLOCKED_MAIN_CLAIMS_MANIFEST_UNAVAILABLE",
        "BLOCKED_MAIN_CLAIMS_MANIFEST_INVALID",
        "BLOCKED_MAIN_CLAIMS_MANIFEST_ID_MISMATCH",
    }:
        raise ValueError(
            "service main_claims manifest binding is invalid: " + str(alignment["status"])
        )
    if evidence.get("main_claims_alignment") != alignment["status"]:
        raise ValueError(
            "evidence_scope.main_claims_alignment contradicts the authoritative "
            "main_claims seed/profile manifest"
        )
    if (
        alignment["status"] != MAIN_CLAIMS_ALIGNED
        and evidence.get("gate_claims_permitted") is not False
    ):
        raise ValueError("unaligned main-claim seeds/profiles require gate_claims_permitted: false")
    return value, _canonical_hash(value)


def _make_backends(
    dataset: ServiceDataset, profiles: Sequence[KdfProfile]
) -> dict[str, KdfBackend]:
    result: dict[str, KdfBackend] = {}
    dummy_salt = hashlib.sha256(
        b"RTRAPS-service-dummy-salt-v1\x00" + struct.pack(">Q", dataset.dataset_seed)
    ).digest()[:16]
    for profile in profiles:
        backend = KdfBackend(profile, dummy_salt=dummy_salt)
        for account in dataset.accounts:
            backend.enroll(account, dataset.correct_password(account.account_index))
        result[profile.name] = backend
    return result


def _warmup_integrity_reasons(
    report: Mapping[str, Any],
    phase: Mapping[str, Any],
    expected_scheduled: int,
    expected_duration_seconds: float,
) -> list[str]:
    counters = phase.get("counters")
    conservation = phase.get("conservation")
    if not isinstance(counters, Mapping) or not isinstance(conservation, Mapping):
        return ["WARMUP_SNAPSHOT_SCHEMA_INVALID"]
    reasons: list[str] = []
    if report.get("phase") != "warmup":
        reasons.append("WARMUP_REPORT_PHASE_MISMATCH")
    if float(report.get("duration_seconds", -1)) != expected_duration_seconds:
        reasons.append("WARMUP_REPORT_DURATION_MISMATCH")
    if int(report.get("scheduled", -1)) != expected_scheduled:
        reasons.append("WARMUP_REPORT_SCHEDULE_MISMATCH")
    if (
        int(report.get("accepted_for_queueing", -1)) + int(report.get("rejected_at_submission", -1))
        != expected_scheduled
    ):
        reasons.append("WARMUP_GENERATOR_CONSERVATION_FAILURE")
    if int(counters.get("offered_requests", -1)) != expected_scheduled:
        reasons.append("WARMUP_OFFERED_COUNT_MISMATCH")
    if int(phase.get("pending", -1)) != 0:
        reasons.append("WARMUP_PENDING_REQUESTS")
    if int(phase.get("overdue", -1)) != 0:
        reasons.append("WARMUP_OVERDUE_REQUESTS")
    if int(phase.get("request_timeouts", -1)) != 0:
        reasons.append("WARMUP_REQUEST_TIMEOUTS")
    if conservation.get("valid") is not True:
        reasons.append("WARMUP_REQUEST_ACCOUNTING_INVARIANT_FAILURE")
    if int(phase.get("event_errors", -1)) != 0:
        reasons.append("WARMUP_SERVICE_EVENT_ERRORS")
    if int(counters.get("ingress_outside_window", 0)) != 0:
        reasons.append("WARMUP_INGRESS_OUTSIDE_WINDOW")
    return list(dict.fromkeys(reasons))


def _run_point(
    config: Mapping[str, Any],
    config_hash: str,
    git: Mapping[str, Any],
    host: Mapping[str, Any],
    timestamp: str,
    dataset: ServiceDataset,
    screen: ScreenRealization,
    method: ServiceMethod,
    method_implementation: str,
    method_order: Sequence[str],
    method_execution_position: int,
    profile: KdfProfile,
    backend: KdfBackend,
    seed: int,
    scenario: str,
    legitimate_rps: float,
    invalid_rps: float,
    plan: WorkloadPlan,
) -> dict[str, Any]:
    measurement = config["measurement"]
    limits = _parse_limits(config)
    conditioned_screen = (
        StrongOracleConditionedScreen(screen, plan.conditioned_queries)
        if plan.false_positive_source == STRONG_ORACLE_SOURCE
        else None
    )
    service = AuthenticationService(
        accounts=list(dataset.accounts),
        codec=dataset.codec,
        positive_filter=conditioned_screen or screen,
        verifier=backend,
        method=method,
        limits=limits,
        negative_key=hashlib.sha256(
            b"RTRAPS-service-negative-key-v1\x00" + struct.pack(">Q", seed)
        ).digest(),
    )
    generator = OpenLoopLoadGenerator()
    warmup_seconds = float(measurement["warmup_seconds"])
    warmup_plan = _build_plan(
        dataset=dataset,
        screen=screen,
        false_positives=(),
        seed=_derived_seed(seed, scenario, "warmup"),
        scenario="uniform_unique_random",
        legitimate_rps=float(measurement["warmup_legitimate_rps"]),
        invalid_rps=0,
        duration_seconds=warmup_seconds,
        distribution=str(measurement["arrival_distribution"]),
        scenario_config={},
        request_id_start=1_000_000_000,
    )
    warmup_report = generator.run(service, warmup_plan.arrivals, warmup_seconds, phase="warmup")
    warmup_drained = service.wait_phase("warmup", limits.request_timeout_seconds + 5.0)
    if not warmup_drained:
        service.shutdown()
        raise RuntimeError("BLOCKED: warmup did not drain before the measurement phase")
    warmup_phase = service.phase_snapshot("warmup")
    warmup_invalid_reasons = _warmup_integrity_reasons(
        vars(warmup_report),
        warmup_phase,
        len(warmup_plan.arrivals),
        warmup_seconds,
    )
    if conditioned_screen is not None:
        conditioned_screen.reset_runtime_evidence()

    sampler = ResourceSampler(
        float(measurement["resource_sample_interval_seconds"]),
        service.queue_snapshot,
    )
    sampler.start()
    duration_seconds = float(measurement["duration_seconds"])
    load_report = generator.run(service, plan.arrivals, duration_seconds, phase="measurement")
    resources = sampler.stop()
    drained_before_timeout = service.wait_phase("measurement", limits.request_timeout_seconds)
    shutdown_report = service.shutdown(timeout=float(measurement["shutdown_timeout_seconds"]))
    # This final snapshot is intentionally after shutdown so that a valid row
    # includes every KDF completed during the drain interval.
    phase = service.phase_snapshot("measurement")
    cache_memory_bytes = (
        deep_sizeof(service.negative_cache) if service.negative_cache is not None else 0
    )
    conditional_runtime = (
        conditioned_screen.runtime_evidence()
        if conditioned_screen is not None
        else {
            "underlying_query_count": 0,
            "conditioned_query_count": 0,
            "natural_positive_conditioned_query_count": 0,
            "forced_positive_query_count": 0,
        }
    )
    conditional_runtime["intervention_applicable_to_method"] = bool(
        conditioned_screen is not None and method.use_positive_screen
    )
    conditional_runtime["oracle_harness_memory_excluded_from_method_footprint"] = bool(
        conditioned_screen is not None
    )

    resource_payload = resources.as_dict()
    derived = _derive_measurement_result(
        config,
        phase,
        {
            "event_count": len(plan.arrivals),
            "distinct_invalid_count": plan.distinct_invalid_count,
        },
        limits,
        vars(load_report),
        resource_payload,
        warmup_invalid_reasons,
        warmup_request_accounting_conserved=bool(warmup_phase["conservation"]["valid"]),
        drained_before_timeout=drained_before_timeout,
        shutdown_clean=shutdown_report.clean,
    )
    invalid_reasons = derived["invalid_reasons"]
    filter_memory = screen.memory_report().total_bytes if method.use_positive_screen else 0
    scope_blockers = [
        "NETWORK_BLOCKED: in-process harness does not measure sockets, TLS, or kernel networking",
        "FRONTEND_RSS_ISOLATION_BLOCKED: RSS/USS is sampled for the combined benchmark process",
    ]
    main_claims_manifest_id = _require_current_main_claims_manifest_id(
        config, context="result producer"
    )
    run_material = {
        "commit": git["commit"],
        "config_hash": config_hash,
        "main_claims_manifest_id": main_claims_manifest_id,
        "dataset_hash": plan.dataset_hash,
        "filter_realization_id": screen.identity,
        "seed": seed,
        "method": method.name,
        "scenario": scenario,
        "profile": profile.name,
        "legitimate_rps": legitimate_rps,
        "invalid_rps": invalid_rps,
        "timestamp": timestamp,
    }
    row: dict[str, Any] = {
        "run_id": _canonical_hash(run_material)[:24],
        "commit": git["commit"],
        "config_hash": config_hash,
        "main_claims_manifest_id": main_claims_manifest_id,
        "dataset_hash": plan.dataset_hash,
        "dataset_generator": DATASET_GENERATOR,
        "filter_family": screen.spec.family,
        "filter_configured_spec": {
            **screen.spec.configured_binding(),
            "configured_spec_id": screen.spec.identity,
        },
        "filter_realization": screen.binding(),
        "method_implementation": method_implementation,
        "curve_environment_binding": _curve_environment_binding(host, profile),
        "seed": seed,
        "method": method.name,
        "scenario": scenario,
        "account_count": dataset.account_count,
        "event_count": len(plan.arrivals),
        "distinct_invalid_count": plan.distinct_invalid_count,
        "false_positive_source": plan.false_positive_source,
        "conditioned_tuple_set_id": plan.conditioned_tuple_set_id,
        "conditioned_tuple_count": plan.conditioned_tuple_count,
        "invalid_tuple_multiplicity_commitment_id": (plan.invalid_tuple_multiplicity_commitment_id),
        "minimum_invalid_tuple_multiplicity": (plan.minimum_invalid_tuple_multiplicity),
        "underlying_filter_query_executed": (plan.false_positive_source == STRONG_ORACLE_SOURCE),
        "conditional_intervention_does_not_estimate_ffr": (
            plan.false_positive_source == STRONG_ORACLE_SOURCE
        ),
        "conditional_intervention_runtime": conditional_runtime,
        "memory_filter_bytes": filter_memory,
        "memory_model_bytes": 0,
        "memory_cache_bytes": cache_memory_bytes,
        "memory_directory_extra_bytes": 0,
        "observed_first_seen_ffr": (
            plan.observed_first_seen_ffr if method.use_positive_screen else None
        ),
        "observed_request_weighted_ffr": (
            plan.observed_request_weighted_ffr if method.use_positive_screen else None
        ),
        "worst_region_ffr": (plan.observed_first_seen_ffr if method.use_positive_screen else None),
        "service_saturation_rps": None,
        "service_saturation_lower_bound_rps": None,
        "service_saturation_upper_bound_rps": None,
        "service_saturation_invalid_lower_bound_rps": None,
        "service_saturation_invalid_upper_bound_rps": None,
        "timestamp_utc": timestamp,
        "host": dict(host),
        "git": dict(git),
        "result_schema_version": RESULT_SCHEMA_VERSION,
        "provenance_class": config["execution"]["provenance_class"],
        "traffic_mode": "open_loop",
        "deployment_mode": "in_process_bounded_threaded_service",
        "network_transport": "BLOCKED_NOT_MEASURED",
        "arrival_distribution": measurement["arrival_distribution"],
        "offered_legitimate_rps": legitimate_rps,
        "offered_invalid_rps": invalid_rps,
        "offered_total_rps": legitimate_rps + invalid_rps,
        "nominal_scheduled_event_count": len(plan.arrivals),
        "event_count_semantics": "nominal_scheduled_arrivals_not_achieved_ingress",
        "resource_samples": resource_payload,
        "queue_and_connection_state": service.queue_snapshot(),
        "phase_metrics": phase,
        "warmup": {
            **vars(warmup_report),
            "cache_persists_into_measurement": True,
            "invalid_rps": 0,
            "drained_before_measurement": warmup_drained,
            "phase_snapshot": warmup_phase,
            "integrity_valid": not warmup_invalid_reasons,
            "invalid_reasons": warmup_invalid_reasons,
        },
        "measurement_duration_seconds": duration_seconds,
        "drained_before_request_timeout": drained_before_timeout,
        "shutdown_clean": shutdown_report.clean,
        "shutdown_report": shutdown_report.as_dict(),
        "method_config": vars(method),
        "method_order_policy": "seed_rank_plus_invalid_load_rank_cyclic_v1",
        "method_execution_order": list(method_order),
        "method_execution_position": method_execution_position,
        "service_limits": vars(limits),
        "filter_parameters": screen.parameters() if method.use_positive_screen else None,
        "verifier_profile": {
            "name": profile.name,
            **profile.implementation_metadata(),
        },
        "dataset_manifest": dataset.base_manifest(),
        "memory_accounting": {
            "filter": "compact filter MemoryReport.total_bytes",
            "cache": "observed recursive CPython resident object graph at end of run",
            "model": "no model in this service profile",
            "directory_extra": "zero; common account directory excluded for every method",
        },
        "scope_blockers": scope_blockers,
        "blockers": [
            *scope_blockers,
            *(f"INVALID_MEASUREMENT: {reason}" for reason in invalid_reasons),
        ],
    }
    row.update(derived)
    return row


def _assign_saturation(config: Mapping[str, Any], rows: list[dict[str, Any]]) -> None:
    criteria = config["saturation_criteria"]
    inference_mode = str(criteria.get("inference_mode", "interval_censored_curve"))
    baseline_method = str(criteria["baseline_method"])
    p99_regression = float(criteria["maximum_legitimate_p99_regression_fraction"])
    point_rows = {
        (
            row["seed"],
            row["method"],
            row["scenario"],
            row["verifier_profile"]["name"],
            row["offered_legitimate_rps"],
            row["offered_invalid_rps"],
        ): row
        for row in rows
    }
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        key = (
            row["seed"],
            row["method"],
            row["scenario"],
            row["verifier_profile"]["name"],
            row["offered_legitimate_rps"],
        )
        groups.setdefault(key, []).append(row)
    for group in groups.values():
        ordered = sorted(group, key=lambda row: row["offered_invalid_rps"])
        passing: list[dict[str, Any]] = []
        for row in ordered:
            baseline = point_rows.get(
                (
                    row["seed"],
                    baseline_method,
                    row["scenario"],
                    row["verifier_profile"]["name"],
                    row["offered_legitimate_rps"],
                    row["offered_invalid_rps"],
                )
            )
            baseline_reference_valid = (
                baseline is not None and baseline.get("result_status") == "VALID"
            )
            baseline_p99 = None if baseline is None else baseline.get("legitimate_p99_ms")
            row_p99 = row.get("legitimate_p99_ms")
            p99_pass = (
                baseline_reference_valid
                and baseline_p99 is not None
                and row_p99 is not None
                and float(row_p99) <= float(baseline_p99) * (1.0 + p99_regression)
            )
            expected_legitimate = row["achieved_legitimate_offered_rps"] * float(
                criteria["minimum_legitimate_throughput_fraction"]
            )
            timeout_rate = row.get("legitimate_timeout_rate")
            queue_drop_rate = row.get("queue_drop_rate")
            measurement_valid = row.get("result_status") == "VALID"
            timeout_pass = timeout_rate is not None and float(timeout_rate) <= float(
                criteria["maximum_legitimate_timeout_rate"]
            )
            queue_drop_pass = queue_drop_rate is not None and float(queue_drop_rate) <= float(
                criteria["maximum_queue_drop_rate"]
            )
            throughput_pass = row["successful_legitimate_throughput_rps"] >= expected_legitimate
            operational_safe = (
                measurement_valid and timeout_pass and queue_drop_pass and throughput_pass
            )
            row["g5_operational_safe_point_pass"] = operational_safe
            row["g5_operational_safe_point_criteria"] = {
                "measurement_valid": measurement_valid,
                "legitimate_timeout_pass": timeout_pass,
                "queue_drop_pass": queue_drop_pass,
                "legitimate_throughput_pass": throughput_pass,
                "legitimate_p99_excluded": True,
                "rule": G5_GATE_CONTRACT["operational_safe_point_rule"],
            }
            passed = operational_safe and p99_pass
            row["saturation_point_pass"] = passed
            row["saturation_point_criteria"] = {
                "measurement_valid": measurement_valid,
                "legitimate_timeout_pass": timeout_pass,
                "queue_drop_pass": queue_drop_pass,
                "legitimate_throughput_pass": throughput_pass,
                "legitimate_p99_noninferiority_pass": p99_pass,
                "baseline_method": baseline_method,
                "baseline_reference_valid": baseline_reference_valid,
                "baseline_legitimate_p99_ms": baseline_p99,
                "maximum_p99_regression_fraction": p99_regression,
            }
            if passed:
                passing.append(row)
        has_invalid_measurement = any(row.get("result_status") != "VALID" for row in ordered)
        has_missing_baseline = any(
            not row["saturation_point_criteria"]["baseline_reference_valid"] for row in ordered
        )
        if inference_mode == "diagnostic_points_only":
            diagnostic_valid = not (has_invalid_measurement or has_missing_baseline)
            for row in ordered:
                row["service_saturation_rps"] = None
                row["service_saturation_invalid_rps"] = None
                row["service_saturation_lower_bound_rps"] = None
                row["service_saturation_upper_bound_rps"] = None
                row["service_saturation_invalid_lower_bound_rps"] = None
                row["service_saturation_invalid_upper_bound_rps"] = None
                row["service_saturation_interval_semantics"] = {
                    "lower_bound": None,
                    "upper_bound": None,
                    "exact_threshold_reported": False,
                }
                row["service_saturation_status"] = "DIAGNOSTIC_POINTS_ONLY"
                row["saturation_curve_valid"] = diagnostic_valid
                row["saturation_inference_mode"] = inference_mode
                row["saturation_baseline_scope"] = (
                    "PROVISIONAL_MECHANISM_BASELINE_PENDING_PHASE1_FRONTIER"
                )
            continue
        first_failure: dict[str, Any] | None = None
        safe_prefix: list[dict[str, Any]] = []
        for row in ordered:
            if not row["saturation_point_pass"]:
                if first_failure is None:
                    first_failure = row
            elif first_failure is None:
                safe_prefix.append(row)
        non_monotonic = bool(
            first_failure is not None
            and any(
                row["saturation_point_pass"]
                and row["offered_invalid_rps"] > first_failure["offered_invalid_rps"]
                for row in ordered
            )
        )
        curve_valid = not (has_invalid_measurement or has_missing_baseline)
        lower_total: float | None = None
        upper_total: float | None = None
        lower_invalid: float | None = None
        upper_invalid: float | None = None
        if has_invalid_measurement:
            status = "INVALID_MEASUREMENT_ROWS"
        elif has_missing_baseline:
            status = "BASELINE_REFERENCE_INVALID"
        elif first_failure is None:
            last = max(passing, key=lambda row: row["offered_invalid_rps"])
            lower_total = float(last["offered_total_rps"])
            lower_invalid = float(last["offered_invalid_rps"])
            status = "LOWER_BOUND_CENSORED"
        elif not safe_prefix:
            upper_total = float(first_failure["offered_total_rps"])
            upper_invalid = float(first_failure["offered_invalid_rps"])
            status = "BELOW_TESTED_GRID"
        else:
            last = max(safe_prefix, key=lambda row: row["offered_invalid_rps"])
            lower_total = float(last["offered_total_rps"])
            lower_invalid = float(last["offered_invalid_rps"])
            upper_total = float(first_failure["offered_total_rps"])
            upper_invalid = float(first_failure["offered_invalid_rps"])
            status = "BRACKETED"
        for row in ordered:
            # A finite grid never identifies an exact saturation threshold.
            row["service_saturation_rps"] = None
            row["service_saturation_invalid_rps"] = None
            row["service_saturation_lower_bound_rps"] = lower_total
            row["service_saturation_upper_bound_rps"] = upper_total
            row["service_saturation_invalid_lower_bound_rps"] = lower_invalid
            row["service_saturation_invalid_upper_bound_rps"] = upper_invalid
            row["service_saturation_interval_semantics"] = {
                "lower_bound": "inclusive_tested_safe_point",
                "upper_bound": "exclusive_first_tested_failure",
                "exact_threshold_reported": False,
            }
            row["service_saturation_status"] = status
            row["saturation_curve_valid"] = curve_valid
            row["saturation_inference_mode"] = inference_mode
            row["saturation_non_monotonic_point_pattern_observed"] = non_monotonic
            row["saturation_baseline_scope"] = (
                "PROVISIONAL_MECHANISM_BASELINE_PENDING_PHASE1_FRONTIER"
            )


def summarize_saturation(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[Mapping[str, Any]]] = {}
    seen_runs: set[tuple[Any, ...]] = set()
    for row in rows:
        identity = (
            row["seed"],
            row["method"],
            row["scenario"],
            row["verifier_profile"]["name"],
            row["offered_legitimate_rps"],
        )
        if identity in seen_runs:
            continue
        seen_runs.add(identity)
        key = identity[1:]
        groups.setdefault(key, []).append(row)
    summaries: list[dict[str, Any]] = []
    for key, group in sorted(groups.items(), key=lambda item: tuple(map(str, item[0]))):
        bracketed_intervals = [
            {
                "seed": row["seed"],
                "lower_bound_rps": row["service_saturation_lower_bound_rps"],
                "upper_bound_rps": row["service_saturation_upper_bound_rps"],
                "lower_inclusive": True,
                "upper_exclusive": True,
            }
            for row in group
            if row["service_saturation_status"] == "BRACKETED"
        ]
        censored_lower_bounds = [
            {
                "seed": row["seed"],
                "lower_bound_rps": row["service_saturation_lower_bound_rps"],
            }
            for row in group
            if row["service_saturation_status"] == "LOWER_BOUND_CENSORED"
        ]
        bracketed_lowers = [float(item["lower_bound_rps"]) for item in bracketed_intervals]
        bracketed_uppers = [float(item["upper_bound_rps"]) for item in bracketed_intervals]
        summary: dict[str, Any] = {
            "method": key[0],
            "scenario": key[1],
            "verifier_profile": key[2],
            "offered_legitimate_rps": key[3],
            "independent_seed_count": len(group),
            "bracketed_interval_count": len(bracketed_intervals),
            "bracketed_intervals": bracketed_intervals,
            "bracketed_mean_interval_lower_rps": (
                statistics.fmean(bracketed_lowers) if bracketed_lowers else None
            ),
            "bracketed_mean_interval_upper_rps": (
                statistics.fmean(bracketed_uppers) if bracketed_uppers else None
            ),
            "bracketed_mean_interval_upper_exclusive": True,
            "exact_saturation_mean_rps": None,
            "exact_threshold_inference_status": "NOT_IDENTIFIED_BY_FINITE_GRID",
            "censored_lower_bounds": censored_lower_bounds,
            "censored_lower_bound_count": len(censored_lower_bounds),
            "below_tested_grid_count": sum(
                row["service_saturation_status"] == "BELOW_TESTED_GRID" for row in group
            ),
            "diagnostic_curve_count": sum(
                row["service_saturation_status"] == "DIAGNOSTIC_POINTS_ONLY" for row in group
            ),
            "invalid_curve_count": sum(
                row["service_saturation_status"]
                in {
                    "INVALID_MEASUREMENT_ROWS",
                    "BASELINE_REFERENCE_INVALID",
                    "NON_MONOTONIC_INVALID",
                }
                for row in group
            ),
            "finite_grid_endpoints_are_not_exact_thresholds": True,
        }
        baseline_method = next(
            (
                row["saturation_point_criteria"]["baseline_method"]
                for row in group
                if "saturation_point_criteria" in row
            ),
            None,
        )
        representative = {
            (
                row["seed"],
                row["method"],
                row["scenario"],
                row["verifier_profile"]["name"],
                row["offered_legitimate_rps"],
            ): row
            for row in rows
        }
        paired_difference_intervals: list[dict[str, Any]] = []
        paired_ratio_intervals: list[dict[str, Any]] = []
        paired_non_bracketed: list[dict[str, Any]] = []
        for row in group:
            baseline = representative.get(
                (
                    row["seed"],
                    baseline_method,
                    row["scenario"],
                    row["verifier_profile"]["name"],
                    row["offered_legitimate_rps"],
                )
            )
            if (
                baseline is not None
                and row["service_saturation_status"] == "BRACKETED"
                and baseline["service_saturation_status"] == "BRACKETED"
                and row["service_saturation_lower_bound_rps"] is not None
                and row["service_saturation_upper_bound_rps"] is not None
                and baseline["service_saturation_lower_bound_rps"] not in {None, 0}
                and baseline["service_saturation_upper_bound_rps"] not in {None, 0}
            ):
                candidate_lower = float(row["service_saturation_lower_bound_rps"])
                candidate_upper = float(row["service_saturation_upper_bound_rps"])
                baseline_lower = float(baseline["service_saturation_lower_bound_rps"])
                baseline_upper = float(baseline["service_saturation_upper_bound_rps"])
                paired_difference_intervals.append(
                    {
                        "seed": row["seed"],
                        "lower_exclusive_rps": candidate_lower - baseline_upper,
                        "upper_exclusive_rps": candidate_upper - baseline_lower,
                    }
                )
                paired_ratio_intervals.append(
                    {
                        "seed": row["seed"],
                        "lower_exclusive": candidate_lower / baseline_upper,
                        "upper_exclusive": candidate_upper / baseline_lower,
                    }
                )
            else:
                paired_non_bracketed.append(
                    {
                        "seed": row["seed"],
                        "method_status": row["service_saturation_status"],
                        "baseline_status": None
                        if baseline is None
                        else baseline["service_saturation_status"],
                    }
                )
        difference_mean_lower = (
            statistics.fmean(item["lower_exclusive_rps"] for item in paired_difference_intervals)
            if paired_difference_intervals
            else None
        )
        difference_mean_upper = (
            statistics.fmean(item["upper_exclusive_rps"] for item in paired_difference_intervals)
            if paired_difference_intervals
            else None
        )
        ratio_mean_lower = (
            statistics.fmean(item["lower_exclusive"] for item in paired_ratio_intervals)
            if paired_ratio_intervals
            else None
        )
        ratio_mean_upper = (
            statistics.fmean(item["upper_exclusive"] for item in paired_ratio_intervals)
            if paired_ratio_intervals
            else None
        )
        summary.update(
            {
                "paired_baseline_method": baseline_method,
                "paired_bracketed_interval_seed_count": len(paired_difference_intervals),
                "paired_difference_intervals": paired_difference_intervals,
                "paired_difference_mean_interval_lower_exclusive_rps": (difference_mean_lower),
                "paired_difference_mean_interval_upper_exclusive_rps": (difference_mean_upper),
                "paired_ratio_intervals": paired_ratio_intervals,
                "paired_ratio_mean_interval_lower_exclusive": ratio_mean_lower,
                "paired_ratio_mean_interval_upper_exclusive": ratio_mean_upper,
                "paired_exact_point_estimate_status": ("NOT_IDENTIFIED_BY_INTERVAL_CENSORED_GRID"),
                "paired_non_bracketed": paired_non_bracketed,
            }
        )
        summaries.append(summary)
    return summaries


def summarize_backend_invalid_capacity(
    rows: Sequence[Mapping[str, Any]], contract: Mapping[str, Any]
) -> dict[str, Any]:
    """Emit G4's recomputable per-seed safe KDF-capacity lower bound."""

    profiles = list(contract["verifier_profiles"])
    expected_seed_count = int(contract["paired_seed_count"])
    alpha_per_profile = float(contract["familywise_alpha"]) / len(profiles)
    profile_summaries: list[dict[str, Any]] = []
    for profile in profiles:
        matching = [
            row
            for row in rows
            if row.get("method") == contract["source_method"]
            and row.get("scenario") == contract["scenario"]
            and row.get("verifier_profile", {}).get("name") == profile
            and float(row.get("offered_legitimate_rps", -1))
            == float(contract["offered_legitimate_rps"])
        ]
        by_seed: dict[int, list[Mapping[str, Any]]] = {}
        for row in matching:
            by_seed.setdefault(int(row["seed"]), []).append(row)
        per_seed: list[dict[str, Any]] = []
        invalid_seed_reasons: list[dict[str, Any]] = []
        for seed in sorted(by_seed):
            group = by_seed[seed]
            passing = [
                row
                for row in group
                if row.get("saturation_point_pass") is True
                and float(row.get("offered_invalid_rps", 0)) > 0
            ]
            if not passing:
                invalid_seed_reasons.append(
                    {"seed": seed, "reason": "NO_POSITIVE_SAFE_INVALID_GRID_POINT"}
                )
                continue
            selected = max(passing, key=lambda row: float(row["offered_invalid_rps"]))
            capacity = selected.get("invalid_backend_checks_per_second")
            if (
                type(capacity) not in (int, float)
                or not math.isfinite(float(capacity))
                or float(capacity) <= 0
                or selected.get("saturation_curve_valid") is not True
            ):
                invalid_seed_reasons.append(
                    {"seed": seed, "reason": "SAFE_POINT_CAPACITY_OR_CURVE_INVALID"}
                )
                continue
            per_seed.append(
                {
                    "seed": seed,
                    "point_id": selected["point_id"],
                    "offered_invalid_safe_lower_bound_rps": selected["offered_invalid_rps"],
                    "observed_invalid_backend_checks_per_second": float(capacity),
                    "saturation_status": selected["service_saturation_status"],
                }
            )
        logs = [math.log(item["observed_invalid_backend_checks_per_second"]) for item in per_seed]
        complete = len(per_seed) == expected_seed_count and not invalid_seed_reasons
        critical: float | None = None
        geometric_mean: float | None = None
        lower_bound: float | None = None
        if complete and len(logs) >= 2:
            critical = float(student_t.ppf(1.0 - alpha_per_profile, len(logs) - 1))
            mean_log = statistics.fmean(logs)
            standard_error = statistics.stdev(logs) / math.sqrt(len(logs))
            geometric_mean = math.exp(mean_log)
            lower_bound = math.exp(mean_log - critical * standard_error)
        profile_summaries.append(
            {
                "verifier_profile": profile,
                "status": "VALID_COMPLETE" if lower_bound is not None else "INDETERMINATE",
                "per_seed_safe_points": per_seed,
                "invalid_seed_reasons": invalid_seed_reasons,
                "independent_seed_count": len(per_seed),
                "log_scale_geometric_mean_checks_per_second": geometric_mean,
                "simultaneous_one_sided_lower_bound_checks_per_second": lower_bound,
                "student_t_degrees_of_freedom": len(logs) - 1 if logs else None,
                "student_t_critical": critical,
            }
        )
    lower_bounds = [
        item["simultaneous_one_sided_lower_bound_checks_per_second"] for item in profile_summaries
    ]
    complete = all(value is not None for value in lower_bounds)
    return {
        "schema": contract["schema"],
        "status": "VALID_COMPLETE" if complete else "INDETERMINATE",
        "contract": dict(contract),
        "familywise_alpha": contract["familywise_alpha"],
        "per_profile_one_sided_alpha": alpha_per_profile,
        "profiles": profile_summaries,
        "minimum_simultaneous_profile_lower_bound_checks_per_second": (
            min(float(value) for value in lower_bounds) if complete else None
        ),
        "offered_rate_planning_formula": contract["offered_rate_planning_formula"],
        "epsilon_value_not_selected_by_e7": True,
    }


def summarize_backend_invalid_capacity_for_config(
    rows: Sequence[Mapping[str, Any]], config: Mapping[str, Any]
) -> dict[str, Any]:
    contract = config.get("g4_capacity_contract")
    if contract is None:
        return {
            "schema": G4_CAPACITY_CONTRACT["schema"],
            "status": "NOT_APPLICABLE_NONFORMAL_PROFILE",
            "reason": "G4_CAPACITY_CONTRACT_NOT_CONFIGURED",
        }
    if not isinstance(contract, Mapping):
        raise ValueError("g4_capacity_contract must be a mapping")
    return summarize_backend_invalid_capacity(rows, contract)


def _checkpoint_path(checkpoint_dir: Path, point_id: str) -> Path:
    return checkpoint_dir / f"{point_id}.json"


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def _read_checkpoint(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid checkpoint {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("kind") != "service_bench_point":
        raise ValueError(f"invalid checkpoint envelope: {path}")
    if not isinstance(value.get("row"), dict):
        raise ValueError(f"checkpoint row is missing: {path}")
    return value


@lru_cache(maxsize=64)
def _expected_dataset_cached(account_count: int, dataset_seed: int) -> ServiceDataset:
    return ServiceDataset(account_count, dataset_seed)


@lru_cache(maxsize=256)
def _expected_screen_cached(
    account_count: int,
    dataset_seed: int,
    spec: FrozenScreenSpec,
    experiment_seed: int,
) -> ScreenRealization:
    dataset = _expected_dataset_cached(account_count, dataset_seed)
    return build_screen(spec, dataset.members(), experiment_seed)


@lru_cache(maxsize=256)
def _expected_false_positives_cached(
    account_count: int,
    dataset_seed: int,
    spec: FrozenScreenSpec,
    experiment_seed: int,
    required: int,
    max_scan: int,
) -> tuple[InvalidCredential, ...]:
    dataset = _expected_dataset_cached(account_count, dataset_seed)
    screen = _expected_screen_cached(
        account_count,
        dataset_seed,
        spec,
        experiment_seed,
    )
    return _discover_false_positives(dataset, screen, required, max_scan)


@lru_cache(maxsize=512)
def _expected_workload_contract_cached(
    account_count: int,
    dataset_seed: int,
    spec: FrozenScreenSpec,
    false_positive_pool_size: int,
    false_positive_max_scan: int,
    experiment_seed: int,
    scenario: str,
    legitimate_rps: float,
    invalid_rps: float,
    duration_seconds: float,
    distribution: str,
    scenario_parameters_json: str,
) -> dict[str, Any]:
    dataset = _expected_dataset_cached(account_count, dataset_seed)
    screen = _expected_screen_cached(
        account_count,
        dataset_seed,
        spec,
        experiment_seed,
    )
    scenario_config = json.loads(scenario_parameters_json)
    false_positives: tuple[InvalidCredential, ...] = ()
    if scenario in FALSE_POSITIVE_SCENARIOS:
        if _uses_strong_oracle_conditioning(scenario, scenario_config):
            false_positives = _frozen_conditioned_credentials(
                dataset,
                scenario,
                scenario_config,
                false_positive_pool_size,
            )
        else:
            false_positives = _expected_false_positives_cached(
                account_count,
                dataset_seed,
                spec,
                experiment_seed,
                false_positive_pool_size,
                false_positive_max_scan,
            )
    plan = _build_plan(
        dataset,
        screen,
        false_positives,
        experiment_seed,
        scenario,
        legitimate_rps,
        invalid_rps,
        duration_seconds,
        distribution,
        scenario_config,
    )
    return {
        "dataset_hash": plan.dataset_hash,
        "event_count": len(plan.arrivals),
        "distinct_invalid_count": plan.distinct_invalid_count,
        "observed_first_seen_ffr": plan.observed_first_seen_ffr,
        "observed_request_weighted_ffr": plan.observed_request_weighted_ffr,
        "false_positive_source": plan.false_positive_source,
        "conditioned_tuple_set_id": plan.conditioned_tuple_set_id,
        "conditioned_tuple_count": plan.conditioned_tuple_count,
        "invalid_tuple_multiplicity_commitment_id": (plan.invalid_tuple_multiplicity_commitment_id),
        "minimum_invalid_tuple_multiplicity": (plan.minimum_invalid_tuple_multiplicity),
    }


def _expected_workload_contract(config: Mapping[str, Any], point: PointSpec) -> dict[str, Any]:
    dataset = config["dataset"]
    spec = FrozenScreenSpec.from_config(config["filter"])
    return _expected_workload_contract_cached(
        int(dataset["account_count"]),
        int(dataset["seed"]),
        spec,
        int(dataset["false_positive_pool_size"]),
        int(dataset["false_positive_max_scan"]),
        point.curve.seed,
        point.curve.scenario,
        point.curve.legitimate_rps,
        point.invalid_rps,
        float(config["measurement"]["duration_seconds"]),
        str(config["measurement"]["arrival_distribution"]),
        json.dumps(
            config.get("scenario_parameters", {}),
            sort_keys=True,
            separators=(",", ":"),
        ),
    )


def _expected_filter_parameters(config: Mapping[str, Any], seed: int) -> dict[str, Any]:
    dataset = config["dataset"]
    return _expected_screen_cached(
        int(dataset["account_count"]),
        int(dataset["seed"]),
        FrozenScreenSpec.from_config(config["filter"]),
        seed,
    ).parameters()


def _expected_dataset_manifest(config: Mapping[str, Any]) -> dict[str, Any]:
    dataset = config["dataset"]
    return _expected_dataset_cached(
        int(dataset["account_count"]), int(dataset["seed"])
    ).base_manifest()


def _expected_warmup_scheduled(config: Mapping[str, Any], point: PointSpec) -> int:
    measurement = config["measurement"]
    duration = float(measurement["warmup_seconds"])
    warmup_seed = _derived_seed(point.curve.seed, point.curve.scenario, "warmup")
    rng = random.Random(_derived_seed(warmup_seed, "uniform_unique_random", "legitimate", duration))
    return len(
        _arrival_offsets(
            float(measurement["warmup_legitimate_rps"]),
            duration,
            str(measurement["arrival_distribution"]),
            rng,
        )
    )


def _recomputed_conservation(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    counters = snapshot.get("counters")
    if not isinstance(counters, Mapping):
        raise ValueError("phase counters must be a mapping")
    pending = int(snapshot.get("pending", -1))
    route_total = sum(int(counters.get(f"route_{route.value}", 0)) for route in ServiceRoute)
    offered_class_total = sum(
        int(counters.get(f"offered_{traffic.value}", 0)) for traffic in TrafficClass
    )
    terminal_class_total = sum(
        int(counters.get(f"terminal_{traffic.value}", 0)) for traffic in TrafficClass
    )
    backend_partition = sum(
        int(counters.get(f"backend_{category}_checks", 0))
        for category in ("valid", "invalid", "error", "policy")
    )
    checks = {
        "offered_equals_terminal_plus_pending": int(counters.get("offered_requests", 0))
        == int(counters.get("terminal_outcomes", 0)) + pending,
        "offered_equals_connections_plus_immediate_terminal": int(
            counters.get("offered_requests", 0)
        )
        == int(counters.get("connections_accepted", 0))
        + int(counters.get("immediate_terminal_outcomes", 0)),
        "connections_equal_accepted_terminal_plus_pending": int(
            counters.get("connections_accepted", 0)
        )
        == int(counters.get("accepted_terminal_outcomes", 0)) + pending,
        "terminal_partition": int(counters.get("terminal_outcomes", 0))
        == int(counters.get("accepted_terminal_outcomes", 0))
        + int(counters.get("immediate_terminal_outcomes", 0)),
        "response_partition": int(counters.get("accepted_terminal_outcomes", 0))
        == int(counters.get("responses", 0))
        + int(counters.get("admitted_no_response_terminal", 0)),
        "route_partition": route_total == int(counters.get("terminal_outcomes", 0)),
        "offered_class_partition": offered_class_total == int(counters.get("offered_requests", 0)),
        "terminal_class_partition": terminal_class_total
        == int(counters.get("terminal_outcomes", 0)),
        "ingress_window_partition": int(counters.get("ingress_within_window", 0))
        + int(counters.get("ingress_outside_window", 0))
        == int(counters.get("offered_requests", 0)),
        "backend_check_partition": backend_partition == int(counters.get("backend_checks", 0)),
    }
    return {
        "valid": all(checks.values()),
        "checks": checks,
        "route_total": route_total,
        "backend_partition_total": backend_partition,
    }


def _validate_phase_conservation(snapshot: Mapping[str, Any], label: str) -> None:
    reported = snapshot.get("conservation")
    if not isinstance(reported, Mapping):
        raise ValueError(f"{label} conservation must be a mapping")
    expected = _recomputed_conservation(snapshot)
    if dict(reported) != expected:
        raise ValueError(f"{label} conservation payload contradicts counters")
    counters = snapshot["counters"]
    assert isinstance(counters, Mapping)
    pending = int(snapshot.get("pending", -1))
    overdue = int(snapshot.get("overdue", -1))
    if pending < 0 or overdue < 0 or overdue > pending:
        raise ValueError(f"{label} pending/overdue counts are invalid")
    if int(snapshot.get("event_errors", -1)) != int(counters.get("event_errors", 0)):
        raise ValueError(f"{label} event-error count contradicts counters")
    expected_timeouts = int(counters.get("late_terminal_outcomes", 0)) + overdue
    if int(snapshot.get("request_timeouts", -1)) != expected_timeouts:
        raise ValueError(f"{label} timeout count contradicts counters")


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _finite_nonnegative(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError(f"{label} must be finite and non-negative")
    return result


def _histogram_summary(histograms: Mapping[str, Any], name: str) -> dict[str, float | int | None]:
    empty: dict[str, float | int | None] = {
        "p50": None,
        "p95": None,
        "p99": None,
        "max": None,
        "count": 0,
    }
    value = histograms.get(name)
    if value is None:
        return empty
    if not isinstance(value, Mapping) or set(value) != set(empty):
        raise ValueError(f"histogram {name} has an invalid schema")
    count = _nonnegative_int(value["count"], f"histogram {name}.count")
    result: dict[str, float | int | None] = {"count": count}
    for field in ("p50", "p95", "p99", "max"):
        observed = value[field]
        if count == 0:
            if observed is not None:
                raise ValueError(f"empty histogram {name}.{field} must be null")
            result[field] = None
        else:
            result[field] = _finite_nonnegative(observed, f"histogram {name}.{field}")
    if count and not (float(result["p50"]) <= float(result["p95"]) <= float(result["p99"])):
        raise ValueError(f"histogram {name} percentiles are not monotone")
    return result


def _validate_resource_payload(resources: Mapping[str, Any]) -> None:
    required = {
        "resource_payload_schema_version",
        "available",
        "metrics_complete",
        "sample_count",
        "queue_sample_count",
        "process_cpu_user_seconds",
        "process_cpu_system_seconds",
        "process_cpu_utilization_cores",
        "process_rss_min_bytes",
        "process_rss_peak_bytes",
        "process_vms_peak_bytes",
        "process_uss_peak_bytes",
        "queue_mean",
        "queue_peak",
        "expected_queue_metrics",
        "missing_queue_metrics",
        "rss_window_minimum_sample_count",
        "rss_window_fraction_numerator",
        "rss_window_fraction_denominator",
        "rss_window_k_samples",
        "rss_first_window_sum_bytes",
        "rss_first_window_sample_count",
        "rss_first_window_mean_bytes",
        "rss_last_window_sum_bytes",
        "rss_last_window_sample_count",
        "rss_last_window_mean_bytes",
        "error",
        "sampled_process_rss_min_bytes",
        "sampled_process_rss_max_bytes",
        "sampled_process_vms_max_bytes",
        "sampled_process_uss_max_bytes",
        "sampled_queue_mean",
        "sampled_queue_max",
        "extrema_semantics",
    }
    missing = sorted(required - set(resources))
    if missing:
        raise ValueError(f"resource payload is missing required fields: {missing}")
    if (
        resources["resource_payload_schema_version"]
        != ResourceSampler.RESOURCE_PAYLOAD_SCHEMA_VERSION
    ):
        raise ValueError("resource payload schema version mismatch")
    if not isinstance(resources["available"], bool) or not isinstance(
        resources["metrics_complete"], bool
    ):
        raise ValueError("resource availability/completeness must be Boolean")
    sample_count = _nonnegative_int(resources["sample_count"], "resource sample_count")
    queue_count = _nonnegative_int(resources["queue_sample_count"], "resource queue_sample_count")
    if queue_count > sample_count:
        raise ValueError("resource queue samples exceed process samples")
    expected_metrics = tuple(resources["expected_queue_metrics"])
    if expected_metrics != ResourceSampler.DEFAULT_QUEUE_METRICS:
        raise ValueError("resource expected queue metric contract mismatch")
    missing_metrics = tuple(resources["missing_queue_metrics"])
    if len(set(missing_metrics)) != len(missing_metrics) or not set(missing_metrics).issubset(
        expected_metrics
    ):
        raise ValueError("resource missing queue metrics are inconsistent")
    error = resources["error"]
    if error is not None and (not isinstance(error, str) or not error):
        raise ValueError("resource error must be null or a non-empty string")
    cpu_fields = (
        "process_cpu_user_seconds",
        "process_cpu_system_seconds",
        "process_cpu_utilization_cores",
    )
    for field in cpu_fields:
        if resources[field] is not None:
            _finite_nonnegative(resources[field], f"resource {field}")
    memory_fields = (
        "process_rss_min_bytes",
        "process_rss_peak_bytes",
        "process_vms_peak_bytes",
        "process_uss_peak_bytes",
    )
    for field in memory_fields:
        if resources[field] is not None:
            _nonnegative_int(resources[field], f"resource {field}")
    if (
        resources["process_rss_min_bytes"] is not None
        and resources["process_rss_peak_bytes"] is not None
        and resources["process_rss_min_bytes"] > resources["process_rss_peak_bytes"]
    ):
        raise ValueError("resource RSS minimum exceeds peak")
    aliases = {
        "sampled_process_rss_min_bytes": "process_rss_min_bytes",
        "sampled_process_rss_max_bytes": "process_rss_peak_bytes",
        "sampled_process_vms_max_bytes": "process_vms_peak_bytes",
        "sampled_process_uss_max_bytes": "process_uss_peak_bytes",
        "sampled_queue_mean": "queue_mean",
        "sampled_queue_max": "queue_peak",
    }
    if any(resources[alias] != resources[source] for alias, source in aliases.items()):
        raise ValueError("resource sampled aliases contradict source fields")
    for field in (
        "sampled_process_rss_min_bytes",
        "sampled_process_rss_max_bytes",
        "sampled_process_vms_max_bytes",
        "sampled_process_uss_max_bytes",
    ):
        if resources[field] is not None:
            _nonnegative_int(resources[field], f"resource {field}")
    for name, value in resources["sampled_queue_mean"].items():
        _finite_nonnegative(value, f"resource sampled queue mean {name}")
    for name, value in resources["sampled_queue_max"].items():
        _nonnegative_int(value, f"resource sampled queue max {name}")
    if resources["extrema_semantics"] != "sampled_not_continuous":
        raise ValueError("resource extrema semantics mismatch")
    queue_mean = resources["queue_mean"]
    queue_peak = resources["queue_peak"]
    if not isinstance(queue_mean, Mapping) or not isinstance(queue_peak, Mapping):
        raise ValueError("resource queue summaries must be mappings")
    if set(queue_mean) != set(queue_peak):
        raise ValueError("resource queue mean/peak keys differ")
    if queue_count:
        if set(queue_mean) != set(expected_metrics):
            raise ValueError("resource queue summaries are incomplete")
    elif queue_mean or queue_peak:
        raise ValueError("zero queue samples cannot have queue summaries")
    for name in queue_mean:
        mean = _finite_nonnegative(queue_mean[name], f"resource queue mean {name}")
        peak = _nonnegative_int(queue_peak[name], f"resource queue peak {name}")
        if mean > peak:
            raise ValueError(f"resource queue mean exceeds peak for {name}")
    complete = (
        bool(sample_count)
        and resources["available"]
        and error is None
        and not missing_metrics
        and queue_count == sample_count
        and resources["process_cpu_user_seconds"] is not None
        and resources["process_cpu_system_seconds"] is not None
        and resources["process_cpu_utilization_cores"] is not None
    )
    if resources["metrics_complete"] is not complete:
        raise ValueError("resource metrics_complete contradicts payload")
    if resources["available"] is not bool(sample_count):
        raise ValueError("resource available contradicts sample count")
    if resources["available"] and any(resources[field] is None for field in memory_fields):
        raise ValueError("available resource report is missing memory observations")
    if not resources["available"] and any(resources[field] is not None for field in memory_fields):
        raise ValueError("unavailable resource report cannot contain memory observations")
    expected_window_metadata = {
        "rss_window_minimum_sample_count": (ResourceSampler.RSS_WINDOW_MINIMUM_SAMPLE_COUNT),
        "rss_window_fraction_numerator": (ResourceSampler.RSS_WINDOW_FRACTION_NUMERATOR),
        "rss_window_fraction_denominator": (ResourceSampler.RSS_WINDOW_FRACTION_DENOMINATOR),
    }
    for field, expected in expected_window_metadata.items():
        if _nonnegative_int(resources[field], f"resource {field}") != expected:
            raise ValueError(f"resource {field} contract mismatch")
    k_samples = _nonnegative_int(resources["rss_window_k_samples"], "resource rss_window_k_samples")
    first_count = _nonnegative_int(
        resources["rss_first_window_sample_count"],
        "resource rss_first_window_sample_count",
    )
    last_count = _nonnegative_int(
        resources["rss_last_window_sample_count"],
        "resource rss_last_window_sample_count",
    )
    first_sum = _nonnegative_int(
        resources["rss_first_window_sum_bytes"],
        "resource rss_first_window_sum_bytes",
    )
    last_sum = _nonnegative_int(
        resources["rss_last_window_sum_bytes"],
        "resource rss_last_window_sum_bytes",
    )
    minimum_window_samples = ResourceSampler.RSS_WINDOW_MINIMUM_SAMPLE_COUNT
    expected_k = (
        0
        if sample_count < minimum_window_samples
        else max(
            1,
            sample_count
            * ResourceSampler.RSS_WINDOW_FRACTION_NUMERATOR
            // ResourceSampler.RSS_WINDOW_FRACTION_DENOMINATOR,
        )
    )
    if k_samples != expected_k or first_count != expected_k or last_count != expected_k:
        raise ValueError("resource RSS window counts do not recompute")
    first_mean = resources["rss_first_window_mean_bytes"]
    last_mean = resources["rss_last_window_mean_bytes"]
    if expected_k == 0:
        if first_sum or last_sum or first_mean is not None or last_mean is not None:
            raise ValueError("subminimum resource RSS windows must be empty")
    else:
        if _finite_nonnegative(first_mean, "resource RSS first-window mean") != (
            first_sum / first_count
        ):
            raise ValueError("resource RSS first-window mean does not recompute")
        if _finite_nonnegative(last_mean, "resource RSS last-window mean") != (
            last_sum / last_count
        ):
            raise ValueError("resource RSS last-window mean does not recompute")
        rss_min = resources["process_rss_min_bytes"]
        rss_peak = resources["process_rss_peak_bytes"]
        if rss_min is None or rss_peak is None:
            raise ValueError("non-empty resource RSS windows require RSS extrema")
        if not (
            rss_min * expected_k <= first_sum <= rss_peak * expected_k
            and rss_min * expected_k <= last_sum <= rss_peak * expected_k
        ):
            raise ValueError("resource RSS window sums contradict sampled extrema")


def _validate_phase_resource_bounds(
    snapshot: Mapping[str, Any],
    method: ServiceMethod,
    limits: ServiceLimits,
    *,
    label: str,
) -> None:
    cache_entries = _nonnegative_int(snapshot.get("cache_entries"), f"{label} cache entries")
    cache_capacity = _nonnegative_int(snapshot.get("cache_capacity"), f"{label} cache capacity")
    peak_per_account = _nonnegative_int(
        snapshot.get("cache_peak_entries_per_account"),
        f"{label} cache peak entries per account",
    )
    expected_capacity = limits.cache_capacity if method.cache_policy is not None else 0
    if cache_capacity != expected_capacity:
        raise ValueError(f"{label} cache capacity contradicts the method/config")
    if cache_entries > cache_capacity or peak_per_account > cache_capacity:
        raise ValueError(f"{label} cache observations exceed total capacity")
    singleflight = snapshot.get("singleflight")
    if not method.use_singleflight:
        if singleflight != {}:
            raise ValueError(f"{label} disabled singleflight snapshot must be empty")
        return
    if not isinstance(singleflight, Mapping):
        raise ValueError(f"{label} singleflight snapshot must be a mapping")
    values = {
        field: _nonnegative_int(singleflight.get(field), f"{label} singleflight {field}")
        for field in (
            "peak_waiters",
            "peak_waiters_per_key",
            "current_waiters",
            "inflight",
        )
    }
    if values["peak_waiters_per_key"] > values["peak_waiters"]:
        raise ValueError(f"{label} per-key waiter peak exceeds global waiter peak")
    if values["current_waiters"] > values["peak_waiters"]:
        raise ValueError(f"{label} current waiters exceed the recorded peak")


def _derive_measurement_result(
    config: Mapping[str, Any],
    phase: Mapping[str, Any],
    workload: Mapping[str, Any],
    limits: ServiceLimits,
    open_loop_report: Mapping[str, Any],
    resources: Mapping[str, Any],
    warmup_invalid_reasons: Sequence[str],
    *,
    warmup_request_accounting_conserved: bool,
    drained_before_timeout: bool,
    shutdown_clean: bool,
) -> dict[str, Any]:
    """Derive every phase-backed result field from one evidence contract."""

    _validate_phase_conservation(phase, "measurement")
    _validate_resource_payload(resources)
    counters = phase.get("counters")
    histograms = phase.get("histograms")
    if not isinstance(counters, Mapping) or not isinstance(histograms, Mapping):
        raise ValueError("measurement phase counters/histograms are required")
    for name, value in counters.items():
        if not isinstance(name, str) or not name:
            raise ValueError("measurement counter names must be non-empty strings")
        _nonnegative_int(value, f"counter {name}")
    for name in histograms:
        if not isinstance(name, str) or not name:
            raise ValueError("measurement histogram names must be non-empty strings")
        _histogram_summary(histograms, name)

    def counter(name: str) -> int:
        return _nonnegative_int(counters.get(name, 0), f"counter {name}")

    duration = float(config["measurement"]["duration_seconds"])
    event_count = _nonnegative_int(workload["event_count"], "workload event_count")
    distinct_invalid = _nonnegative_int(
        workload["distinct_invalid_count"], "workload distinct invalid count"
    )
    offered = counter("offered_requests")
    if offered != event_count:
        raise ValueError("measurement offered count contradicts deterministic workload")
    frontend_enqueued = counter("frontend_enqueued")
    if frontend_enqueued > offered:
        raise ValueError("frontend enqueued count exceeds offered requests")

    if not isinstance(open_loop_report, Mapping):
        raise ValueError("open-loop report must be a mapping")
    required_open_loop = {
        "phase",
        "duration_seconds",
        "scheduled",
        "accepted_for_queueing",
        "rejected_at_submission",
        "generator_elapsed_seconds",
        "arrival_lag_us",
    }
    if set(open_loop_report) != required_open_loop:
        raise ValueError("open-loop report schema mismatch")
    if open_loop_report.get("phase") != "measurement":
        raise ValueError("open-loop report phase mismatch")
    if (
        _finite_nonnegative(open_loop_report.get("duration_seconds"), "open-loop duration")
        != duration
    ):
        raise ValueError("open-loop report duration mismatch")
    scheduled = _nonnegative_int(open_loop_report.get("scheduled"), "open-loop scheduled")
    accepted = _nonnegative_int(
        open_loop_report.get("accepted_for_queueing"),
        "open-loop accepted_for_queueing",
    )
    rejected = _nonnegative_int(
        open_loop_report.get("rejected_at_submission"),
        "open-loop rejected_at_submission",
    )
    elapsed = _finite_nonnegative(
        open_loop_report.get("generator_elapsed_seconds"),
        "open-loop generator elapsed",
    )
    if elapsed + 1e-9 < duration:
        raise ValueError("open-loop generator elapsed time is shorter than duration")
    if (
        scheduled != event_count
        or accepted != frontend_enqueued
        or rejected != offered - frontend_enqueued
        or accepted + rejected != scheduled
    ):
        raise ValueError("open-loop report contradicts phase counters")
    generator_lag = _histogram_summary(
        {"arrival_lag_us": open_loop_report.get("arrival_lag_us")},
        "arrival_lag_us",
    )
    arrival_lag = _histogram_summary(histograms, "arrival_lag_ns")
    if generator_lag["count"] != scheduled or arrival_lag["count"] != offered:
        raise ValueError("open-loop/phase arrival-lag counts contradict offered load")
    if offered:
        for field in ("p50", "p95", "p99", "max"):
            if float(arrival_lag[field]) < float(generator_lag[field]):
                raise ValueError(f"phase arrival lag {field} precedes generator submission lag")

    frontend = _histogram_summary(histograms, "frontend_service_ns")
    backend = _histogram_summary(histograms, "backend_service_ns")
    residence = _histogram_summary(histograms, "residence_ns")
    legitimate_residence = _histogram_summary(histograms, "legitimate_residence_ns")
    legitimate = _histogram_summary(histograms, "legitimate_success_residence_ns")
    phase_event_errors = counter("event_errors")
    if drained_before_timeout and not phase_event_errors and frontend["count"] != frontend_enqueued:
        raise ValueError("frontend-service histogram count contradicts counters")
    if not phase_event_errors and backend["count"] != counter("backend_checks"):
        raise ValueError("backend-service histogram count contradicts counters")
    if residence["count"] != counter("terminal_outcomes"):
        raise ValueError("terminal-residence histogram count contradicts counters")
    if legitimate_residence["count"] != counter("terminal_legitimate"):
        raise ValueError("legitimate-residence histogram count contradicts counters")
    if legitimate["count"] != counter("legitimate_successes"):
        raise ValueError("legitimate-success histogram count contradicts counters")
    histogram_units = phase.get("histogram_units")
    if not isinstance(histogram_units, Mapping):
        raise ValueError("phase histogram units are required")
    expected_units = {
        name: ("milliseconds" if name.endswith("residence_ns") else "microseconds")
        for name in histograms
    }
    if dict(histogram_units) != expected_units:
        raise ValueError("phase histogram units contradict histogram names")
    known_route_histograms = {
        f"route_{route.value}_residence_ns": route.value for route in ServiceRoute
    }
    observed_route_histograms = {
        name for name in histograms if name.startswith("route_") and name.endswith("_residence_ns")
    }
    if not observed_route_histograms.issubset(known_route_histograms):
        raise ValueError("phase contains an unknown route-latency histogram")
    for histogram_name, route_name in known_route_histograms.items():
        summary = _histogram_summary(histograms, histogram_name)
        if summary["count"] != counter(f"route_{route_name}"):
            raise ValueError(f"route histogram count contradicts counter: {route_name}")
    expected_route_latencies = {
        name.removeprefix("route_").removesuffix("_residence_ns"): dict(
            _histogram_summary(histograms, name)
        )
        for name in observed_route_histograms
    }
    if phase.get("route_latencies_ms") != expected_route_latencies:
        raise ValueError("phase route latencies contradict histogram evidence")

    legitimate_offered = counter("offered_legitimate")
    legitimate_timeouts = counter("late_legitimate_terminal_outcomes") + _nonnegative_int(
        phase.get("overdue_legitimate", 0), "phase overdue legitimate"
    )
    legitimate_timeout_rate = (
        legitimate_timeouts / legitimate_offered if legitimate_offered else None
    )
    if phase.get("legitimate_timeout_rate") != legitimate_timeout_rate:
        raise ValueError("phase legitimate timeout rate contradicts counters")

    ingress_within = counter("ingress_within_window")
    ingress_outside = counter("ingress_outside_window")
    ingress_legitimate = counter("ingress_within_window_legitimate")
    ingress_invalid = sum(
        counter(name)
        for name in (
            "ingress_within_window_invalid",
            "ingress_within_window_unknown_username",
            "ingress_within_window_correct_password_attack",
        )
    )
    if ingress_legitimate + ingress_invalid != ingress_within:
        raise ValueError("within-window traffic-class counts do not conserve")
    queue_drop_count = sum(
        counter(name)
        for name in (
            "frontend_queue_drops",
            "backend_queue_drops",
            "connection_drops",
        )
    )
    backend_invalid_checks = counter("backend_invalid_checks")
    frontend_utilization = counter("frontend_busy_window_ns") / (
        limits.frontend_workers * duration * 1_000_000_000
    )
    backend_utilization = counter("backend_busy_window_ns") / (
        limits.backend_workers * duration * 1_000_000_000
    )
    if frontend_utilization > 1.0 + 1e-9 or backend_utilization > 1.0 + 1e-9:
        raise ValueError("worker utilization exceeds configured capacity")

    error_counts = {
        key: counter(key)
        for key in counters
        if key.startswith("event_error_") and not key.startswith("event_error_type_")
    }
    exception_types = {key: counter(key) for key in counters if key.startswith("event_error_type_")}
    overload_outcomes = {
        name: counter(name)
        for name in (
            "connection_drops",
            "frontend_queue_drops",
            "backend_queue_drops",
            "singleflight_overflow",
        )
    }
    maximum_p99_ms = float(config["measurement"]["maximum_arrival_lag_p99_ms"])
    maximum_max_ms = float(config["measurement"]["maximum_arrival_lag_max_ms"])
    arrival_p99 = arrival_lag["p99"]
    arrival_max = arrival_lag["max"]
    arrival_gate_passed = bool(
        (not offered or (arrival_p99 is not None and arrival_max is not None))
        and (arrival_p99 is None or float(arrival_p99) <= maximum_p99_ms * 1_000)
        and (arrival_max is None or float(arrival_max) <= maximum_max_ms * 1_000)
    )

    reasons = list(warmup_invalid_reasons)
    if not drained_before_timeout:
        reasons.append("MEASUREMENT_DRAIN_TIMEOUT")
    if _nonnegative_int(phase.get("pending", 0), "phase pending"):
        reasons.append("PENDING_REQUESTS_AFTER_SHUTDOWN")
    if _nonnegative_int(phase.get("overdue", 0), "phase overdue"):
        reasons.append("OVERDUE_REQUESTS_AFTER_SHUTDOWN")
    if not shutdown_clean:
        reasons.append("UNCLEAN_SHUTDOWN")
    if phase["conservation"]["valid"] is not True:
        reasons.append("REQUEST_ACCOUNTING_INVARIANT_FAILURE")
    if resources["metrics_complete"] is not True:
        reasons.append("RESOURCE_SAMPLING_INCOMPLETE")
    if resources["sample_count"] < int(config["measurement"]["minimum_resource_samples"]):
        reasons.append("INSUFFICIENT_RESOURCE_SAMPLES")
    if ingress_outside:
        reasons.append("INGRESS_OUTSIDE_MEASUREMENT_WINDOW")
    if offered and (arrival_p99 is None or arrival_max is None):
        reasons.append("ARRIVAL_LAG_METRICS_MISSING")
    if arrival_p99 is not None and float(arrival_p99) > maximum_p99_ms * 1_000:
        reasons.append("ARRIVAL_LAG_P99_EXCEEDED")
    if arrival_max is not None and float(arrival_max) > maximum_max_ms * 1_000:
        reasons.append("ARRIVAL_LAG_MAX_EXCEEDED")
    if _nonnegative_int(phase.get("event_errors", 0), "phase event errors"):
        reasons.append("SERVICE_EVENT_ERRORS")
    reasons = list(dict.fromkeys(reasons))

    derived: dict[str, Any] = {
        "frontend_p50_us": frontend["p50"],
        "frontend_p95_us": frontend["p95"],
        "frontend_p99_us": frontend["p99"],
        "backend_valid_checks": counter("backend_valid_checks"),
        "backend_invalid_checks": backend_invalid_checks,
        "backend_checks_per_distinct_invalid": (
            backend_invalid_checks / distinct_invalid if distinct_invalid else None
        ),
        "cache_hits": counter("cache_hits"),
        "cache_misses": counter("cache_misses"),
        "cache_evictions": counter("cache_evictions"),
        "singleflight_suppressed": counter("singleflight_suppressed"),
        "legitimate_p50_ms": legitimate["p50"],
        "legitimate_p95_ms": legitimate["p95"],
        "legitimate_p99_ms": legitimate["p99"],
        "legitimate_timeout_rate": legitimate_timeout_rate,
        "result_status": "VALID" if not reasons else "INVALID",
        "invalid_reasons": reasons,
        "achieved_offered_rps": ingress_within / duration,
        "achieved_legitimate_offered_rps": ingress_legitimate / duration,
        "achieved_invalid_offered_rps": ingress_invalid / duration,
        "ingress_within_window": ingress_within,
        "ingress_outside_window": ingress_outside,
        "arrival_lag_p99_us": arrival_p99,
        "arrival_lag_max_us": arrival_max,
        "arrival_lag_gate": {
            "maximum_p99_ms": maximum_p99_ms,
            "maximum_max_ms": maximum_max_ms,
            "passed": arrival_gate_passed,
        },
        "successful_legitimate_throughput_rps": counter("legitimate_successes_within_window")
        / duration,
        "legitimate_successes": counter("legitimate_successes"),
        "legitimate_successes_within_window": counter("legitimate_successes_within_window"),
        "queue_drop_count": queue_drop_count,
        "queue_drop_rate": queue_drop_count / offered if offered else None,
        "frontend_queue_drops": counter("frontend_queue_drops"),
        "backend_queue_drops": counter("backend_queue_drops"),
        "connection_drops": counter("connection_drops"),
        "frontend_worker_utilization": frontend_utilization,
        "backend_worker_utilization": backend_utilization,
        "frontend_thread_cpu_seconds": counter("frontend_cpu_ns") / 1_000_000_000,
        "backend_thread_cpu_seconds": counter("backend_cpu_ns") / 1_000_000_000,
        "invalid_backend_checks_per_second": counter("backend_invalid_checks_started_within_window")
        / duration,
        "backend_error_checks": counter("backend_error_checks"),
        "backend_policy_checks": counter("backend_policy_checks"),
        "route_latencies_ms": expected_route_latencies,
        "terminal_outcome_count": counter("terminal_outcomes"),
        "response_count": counter("responses"),
        "pending_request_count": _nonnegative_int(phase.get("pending", 0), "phase pending"),
        "request_timeout_count": _nonnegative_int(
            phase.get("request_timeouts", 0), "phase request timeouts"
        ),
        "event_error_count": _nonnegative_int(phase.get("event_errors", 0), "phase event errors"),
        "error_count": _nonnegative_int(phase.get("event_errors", 0), "phase event errors"),
        "error_counts": error_counts,
        "exception_type_counts": exception_types,
        "overload_outcome_counts": overload_outcomes,
        "open_loop_report": dict(open_loop_report),
        "measurement_integrity": {
            "valid": not reasons,
            "invalid_reasons": reasons,
            "resource_metrics_complete": resources["metrics_complete"],
            "request_accounting_conserved": phase["conservation"]["valid"],
            "warmup_valid": not warmup_invalid_reasons,
            "warmup_request_accounting_conserved": (warmup_request_accounting_conserved),
            "final_snapshot_after_shutdown": True,
        },
    }
    return derived


def _reclassifiable_operational_observation_reasons(
    row: Mapping[str, Any],
    derived: Mapping[str, Any],
    config: Mapping[str, Any],
) -> list[str]:
    reasons_value = derived.get("invalid_reasons")
    if not isinstance(reasons_value, list) or not reasons_value:
        return []
    if any(not isinstance(reason, str) or not reason for reason in reasons_value):
        return []
    reasons = list(reasons_value)
    reason_set = set(reasons)
    if not reason_set.issubset(NONFATAL_OPERATIONAL_OBSERVATION_REASONS):
        return []
    phase = row.get("phase_metrics")
    queue_state = row.get("queue_and_connection_state")
    integrity = row.get("measurement_integrity")
    if not isinstance(phase, Mapping) or not isinstance(queue_state, Mapping):
        return []
    if not isinstance(integrity, Mapping):
        return []
    if row.get("shutdown_clean") is not True:
        return []
    if _nonnegative_int(phase.get("pending", 0), "phase pending") != 0:
        return []
    if _nonnegative_int(phase.get("overdue", 0), "phase overdue") != 0:
        return []
    conservation = phase.get("conservation")
    if not isinstance(conservation, Mapping) or conservation.get("valid") is not True:
        return []
    if set(queue_state) != set(ResourceSampler.DEFAULT_QUEUE_METRICS):
        return []
    if any(
        _nonnegative_int(value, f"final queue state {name}") != 0
        for name, value in queue_state.items()
    ):
        return []
    if _nonnegative_int(row.get("event_error_count", 0), "event_error_count") != 0:
        return []
    if _nonnegative_int(row.get("error_count", 0), "error_count") != 0:
        return []
    if row.get("error_counts") != {} or row.get("exception_type_counts") != {}:
        return []
    required_integrity_flags = {
        "resource_metrics_complete": True,
        "request_accounting_conserved": True,
        "warmup_valid": True,
        "warmup_request_accounting_conserved": True,
        "final_snapshot_after_shutdown": True,
    }
    if any(
        integrity.get(key) is not expected
        for key, expected in required_integrity_flags.items()
    ):
        return []
    criteria = config.get("saturation_criteria", {})
    operational_failure_observed = False
    if isinstance(criteria, Mapping):
        timeout_rate = row.get("legitimate_timeout_rate")
        queue_drop_rate = row.get("queue_drop_rate")
        achieved = row.get("achieved_legitimate_offered_rps")
        successful = row.get("successful_legitimate_throughput_rps")
        if timeout_rate is not None and float(timeout_rate) > float(
            criteria.get("maximum_legitimate_timeout_rate", 0.0)
        ):
            operational_failure_observed = True
        if queue_drop_rate is not None and float(queue_drop_rate) > float(
            criteria.get("maximum_queue_drop_rate", 0.0)
        ):
            operational_failure_observed = True
        if achieved is not None and successful is not None:
            minimum_throughput = float(achieved) * float(
                criteria.get("minimum_legitimate_throughput_fraction", 1.0)
            )
            if float(successful) < minimum_throughput:
                operational_failure_observed = True
    if "INGRESS_OUTSIDE_MEASUREMENT_WINDOW" in reason_set:
        outside = _nonnegative_int(row.get("ingress_outside_window", 0), "ingress_outside_window")
        scheduled = _nonnegative_int(
            row.get("nominal_scheduled_event_count", 0),
            "nominal_scheduled_event_count",
        )
        allowed = max(1, math.ceil(scheduled * INGRESS_OUTSIDE_RECLASSIFICATION_FRACTION))
        if outside <= 0 or (outside > allowed and not operational_failure_observed):
            return []
    if "ARRIVAL_LAG_P99_EXCEEDED" in reason_set:
        p99_us = _finite_nonnegative(row.get("arrival_lag_p99_us"), "arrival_lag_p99_us")
        maximum_p99_us = float(config["measurement"]["maximum_arrival_lag_p99_ms"]) * 1_000
        if (
            p99_us > maximum_p99_us * ARRIVAL_LAG_P99_RECLASSIFICATION_MULTIPLIER
            and not operational_failure_observed
        ):
            return []
    if "ARRIVAL_LAG_MAX_EXCEEDED" in reason_set:
        max_us = _finite_nonnegative(row.get("arrival_lag_max_us"), "arrival_lag_max_us")
        maximum_max_us = float(config["measurement"]["maximum_arrival_lag_max_ms"]) * 1_000
        maximum_p99_us = float(config["measurement"]["maximum_arrival_lag_p99_ms"]) * 1_000
        p99_us = _finite_nonnegative(row.get("arrival_lag_p99_us"), "arrival_lag_p99_us")
        isolated_max_outlier = (
            reason_set == {"ARRIVAL_LAG_MAX_EXCEEDED"} and p99_us <= maximum_p99_us
        )
        if (
            max_us > maximum_max_us * ARRIVAL_LAG_MAX_RECLASSIFICATION_MULTIPLIER
            and not operational_failure_observed
            and not isolated_max_outlier
        ):
            return []
    return reasons


def _reclassified_operational_observation_fields(
    derived: Mapping[str, Any],
) -> dict[str, Any]:
    result = copy.deepcopy(dict(derived))
    integrity = dict(result["measurement_integrity"])
    integrity["valid"] = True
    integrity["invalid_reasons"] = []
    result["measurement_integrity"] = integrity
    result["result_status"] = "VALID"
    result["invalid_reasons"] = []
    return result


def _expected_measurement_fields_for_row(
    row: Mapping[str, Any],
    derived: Mapping[str, Any],
    config: Mapping[str, Any],
) -> dict[str, Any]:
    if row.get("result_status") == "VALID" and _reclassifiable_operational_observation_reasons(
        row, derived, config
    ):
        return _reclassified_operational_observation_fields(derived)
    return dict(derived)


def _reclassify_operational_observation_row(
    row: Mapping[str, Any],
    config: Mapping[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    reasons = _reclassifiable_operational_observation_reasons(row, row, config)
    if row.get("result_status") != "INVALID" or not reasons:
        return dict(row), []
    result = copy.deepcopy(dict(row))
    result["result_status"] = "VALID"
    result["invalid_reasons"] = []
    integrity = dict(result["measurement_integrity"])
    integrity["valid"] = True
    integrity["invalid_reasons"] = []
    result["measurement_integrity"] = integrity
    result["blockers"] = list(result["scope_blockers"])
    return result, reasons


def _validate_nonderived_measurements(
    row: Mapping[str, Any],
    method: ServiceMethod,
    expected_filter_memory: int,
) -> tuple[bool, bool]:
    for field in (
        "memory_filter_bytes",
        "memory_model_bytes",
        "memory_cache_bytes",
        "memory_directory_extra_bytes",
    ):
        _nonnegative_int(row.get(field), field)
    if row["memory_filter_bytes"] != expected_filter_memory:
        raise ValueError("filter memory does not match the implemented filter")
    if row["memory_model_bytes"] != 0 or row["memory_directory_extra_bytes"] != 0:
        raise ValueError("mechanism runner cannot report model or extra-directory memory")
    if method.cache_policy is None and row["memory_cache_bytes"] != 0:
        raise ValueError("method without a cache cannot report cache memory")
    if method.cache_policy is not None and row["memory_cache_bytes"] == 0:
        raise ValueError("cache-enabled method must report observed cache memory")
    expected_accounting = {
        "filter": "compact filter MemoryReport.total_bytes",
        "cache": "observed recursive CPython resident object graph at end of run",
        "model": "no model in this service profile",
        "directory_extra": "zero; common account directory excluded for every method",
    }
    if row.get("memory_accounting") != expected_accounting:
        raise ValueError("memory accounting declaration mismatch")

    resources = row.get("resource_samples")
    if not isinstance(resources, Mapping):
        raise ValueError("resource_samples mapping is required")
    _validate_resource_payload(resources)
    queue_state = row.get("queue_and_connection_state")
    if not isinstance(queue_state, Mapping) or set(queue_state) != set(
        ResourceSampler.DEFAULT_QUEUE_METRICS
    ):
        raise ValueError("final queue/connection state schema mismatch")
    for name, value in queue_state.items():
        _nonnegative_int(value, f"final queue state {name}")

    shutdown = row.get("shutdown_report")
    required_shutdown = {
        "clean",
        "drained_before_deadline",
        "frontend_workers_stopped",
        "backend_workers_stopped",
        "padding_stopped",
        "pending_after_shutdown",
        "elapsed_seconds",
    }
    if not isinstance(shutdown, Mapping) or set(shutdown) != required_shutdown:
        raise ValueError("shutdown report schema mismatch")
    for field in (
        "clean",
        "drained_before_deadline",
        "frontend_workers_stopped",
        "backend_workers_stopped",
        "padding_stopped",
    ):
        if not isinstance(shutdown[field], bool):
            raise ValueError(f"shutdown {field} must be Boolean")
    pending_after = _nonnegative_int(
        shutdown["pending_after_shutdown"], "shutdown pending_after_shutdown"
    )
    phase = row.get("phase_metrics")
    if not isinstance(phase, Mapping):
        raise ValueError("measurement phase payload is required")
    if pending_after != _nonnegative_int(phase.get("pending"), "phase pending"):
        raise ValueError("shutdown pending count contradicts final phase snapshot")
    _finite_nonnegative(shutdown["elapsed_seconds"], "shutdown elapsed_seconds")
    computed_clean = bool(
        shutdown["drained_before_deadline"]
        and shutdown["frontend_workers_stopped"]
        and shutdown["backend_workers_stopped"]
        and shutdown["padding_stopped"]
        and pending_after == 0
    )
    if shutdown["clean"] is not computed_clean:
        raise ValueError("shutdown clean flag contradicts shutdown evidence")
    if row.get("shutdown_clean") is not shutdown["clean"]:
        raise ValueError("top-level shutdown status contradicts shutdown report")
    drained = row.get("drained_before_request_timeout")
    if not isinstance(drained, bool):
        raise ValueError("measurement drain status must be Boolean")
    if shutdown["clean"] and any(queue_state.values()):
        raise ValueError("clean shutdown cannot retain queue/connection state")
    return bool(shutdown["clean"]), drained


def _validate_conditioning_result(
    row: Mapping[str, Any],
    workload: Mapping[str, Any],
    method: ServiceMethod,
) -> None:
    source = workload["false_positive_source"]
    conditioned = source == STRONG_ORACLE_SOURCE
    expected = {
        "false_positive_source": source,
        "conditioned_tuple_set_id": workload["conditioned_tuple_set_id"],
        "conditioned_tuple_count": workload["conditioned_tuple_count"],
        "invalid_tuple_multiplicity_commitment_id": workload[
            "invalid_tuple_multiplicity_commitment_id"
        ],
        "minimum_invalid_tuple_multiplicity": workload["minimum_invalid_tuple_multiplicity"],
        "underlying_filter_query_executed": conditioned,
        "conditional_intervention_does_not_estimate_ffr": conditioned,
    }
    if any(row.get(field) != value for field, value in expected.items()):
        raise ValueError("strong-oracle conditioning binding does not recompute")
    runtime = row.get("conditional_intervention_runtime")
    expected_runtime_fields = {
        "underlying_query_count",
        "conditioned_query_count",
        "natural_positive_conditioned_query_count",
        "forced_positive_query_count",
        "intervention_applicable_to_method",
        "oracle_harness_memory_excluded_from_method_footprint",
    }
    if not isinstance(runtime, Mapping) or set(runtime) != expected_runtime_fields:
        raise ValueError("conditional intervention runtime evidence schema changed")
    counts: dict[str, int] = {}
    for field in (
        "underlying_query_count",
        "conditioned_query_count",
        "natural_positive_conditioned_query_count",
        "forced_positive_query_count",
    ):
        counts[field] = _nonnegative_int(runtime.get(field), field)
    if (
        counts["natural_positive_conditioned_query_count"] + counts["forced_positive_query_count"]
        != counts["conditioned_query_count"]
        or counts["conditioned_query_count"] > counts["underlying_query_count"]
    ):
        raise ValueError("conditional intervention runtime counts do not conserve")
    applicable = conditioned and method.use_positive_screen
    if runtime.get("intervention_applicable_to_method") is not applicable:
        raise ValueError("conditional intervention method applicability changed")
    if runtime.get("oracle_harness_memory_excluded_from_method_footprint") is not conditioned:
        raise ValueError("conditional intervention memory scope changed")
    if not applicable and any(counts.values()):
        raise ValueError("non-applicable method reported conditional filter queries")
    minimum_multiplicity = _nonnegative_int(
        workload["minimum_invalid_tuple_multiplicity"],
        "minimum invalid tuple multiplicity",
    )
    conditioned_tuple_count = _nonnegative_int(
        workload["conditioned_tuple_count"], "conditioned tuple count"
    )
    distinct_invalid_count = _nonnegative_int(
        row.get("distinct_invalid_count"), "distinct invalid count"
    )
    expected_conditioned_queries = min(conditioned_tuple_count, distinct_invalid_count)
    if applicable and minimum_multiplicity > 0:
        if (
            conditioned_tuple_count <= 0
            or counts["conditioned_query_count"] < expected_conditioned_queries
            or counts["underlying_query_count"] < counts["conditioned_query_count"]
        ):
            raise ValueError(
                "conditional intervention lacks evidence that the frozen tuple set was queried"
            )
    if conditioned and any(
        row.get(field) is not None
        for field in (
            "observed_first_seen_ffr",
            "observed_request_weighted_ffr",
            "worst_region_ffr",
        )
    ):
        raise ValueError("conditioned workload cannot be reported as an FFR estimate")


def _validate_result_identity(
    row: Mapping[str, Any],
    point: PointSpec,
    config: Mapping[str, Any],
    config_hash: str,
) -> None:
    """Validate row coordinates and provenance without relying on its checkpoint envelope."""

    expected_curve = point.curve.as_dict()
    expected_curve_id = _canonical_hash({"config_hash": config_hash, "curve": expected_curve})[:32]
    verifier = row.get("verifier_profile")
    git = row.get("git")
    try:
        coordinates_match = (
            type(row.get("seed")) is int
            and row["seed"] == point.curve.seed
            and row.get("scenario") == point.curve.scenario
            and isinstance(verifier, Mapping)
            and verifier.get("name") == point.curve.profile_name
            and type(row.get("offered_legitimate_rps")) in {int, float}
            and not isinstance(row.get("offered_legitimate_rps"), bool)
            and float(row["offered_legitimate_rps"]) == point.curve.legitimate_rps
            and type(row.get("offered_invalid_rps")) in {int, float}
            and not isinstance(row.get("offered_invalid_rps"), bool)
            and float(row["offered_invalid_rps"]) == point.invalid_rps
        )
    except (KeyError, TypeError, ValueError):
        coordinates_match = False
    required_provenance = (
        "commit",
        "dataset_hash",
        "timestamp_utc",
        "host",
        "git",
        "provenance_class",
    )
    if (
        row.get("config_hash") != config_hash
        or row.get("point_id") != point.point_id(config_hash)
        or row.get("method") != point.method_name
        or row.get("curve") != expected_curve
        or row.get("curve_id") != expected_curve_id
        or not coordinates_match
        or any(not row.get(field) for field in required_provenance)
        or not isinstance(git, Mapping)
        or git.get("commit") != row.get("commit")
        or row.get("provenance_class") != config["execution"]["provenance_class"]
    ):
        raise ValueError("result row identity or provenance mismatch")
    try:
        timestamp = datetime.fromisoformat(str(row["timestamp_utc"]))
    except (TypeError, ValueError) as exc:
        raise ValueError("result timestamp is invalid") from exc
    if timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
        raise ValueError("result timestamp is not UTC")
    if not isinstance(git.get("dirty"), bool) or not isinstance(git.get("status_available"), bool):
        raise ValueError("result Git provenance types are invalid")
    if config["execution"]["require_clean_git"] and (
        row.get("commit") in {None, "", "UNCOMMITTED"}
        or git.get("dirty") is not False
        or git.get("status_available") is not True
        or str(row.get("provenance_class", "")).startswith("TEMPORARY_")
    ):
        raise ValueError("formal result provenance is invalid")


def _validate_result_contract(
    row: Mapping[str, Any],
    point: PointSpec,
    config: Mapping[str, Any],
    config_hash: str,
) -> None:
    missing = [field for field in RESULT_SCHEMA if field not in row]
    if missing:
        raise ValueError(f"result schema fields are missing: {missing}")
    _validate_result_identity(row, point, config, config_hash)
    main_claims_manifest_id = _require_current_main_claims_manifest_id(
        config, context="result consumer"
    )
    if row.get("main_claims_manifest_id") != main_claims_manifest_id:
        raise ValueError("result main_claims_manifest_id mismatch")
    if row.get("result_schema_version") != RESULT_SCHEMA_VERSION:
        raise ValueError("result schema version mismatch")
    if row.get("dataset_generator") != DATASET_GENERATOR:
        raise ValueError("dataset generator does not match implementation")
    expected_spec = FrozenScreenSpec.from_config(config["filter"])
    expected_screen = _expected_screen_cached(
        int(config["dataset"]["account_count"]),
        int(config["dataset"]["seed"]),
        expected_spec,
        point.curve.seed,
    )
    if row.get("filter_family") != expected_spec.family:
        raise ValueError("filter family does not match implementation")
    expected_configured_spec = {
        **expected_spec.configured_binding(),
        "configured_spec_id": expected_spec.identity,
    }
    if _canonical_json(row.get("filter_configured_spec")) != _canonical_json(
        expected_configured_spec
    ):
        raise ValueError("configured filter spec does not match configuration")
    if _canonical_json(row.get("filter_realization")) != _canonical_json(expected_screen.binding()):
        raise ValueError("filter realization does not match rebuilt implementation")
    if row.get("dataset_manifest") != _expected_dataset_manifest(config):
        raise ValueError("dataset manifest does not match configuration")
    if int(row.get("account_count", -1)) != int(config["dataset"]["account_count"]):
        raise ValueError("account count does not match configuration")
    dataset_hash = row.get("dataset_hash")
    if (
        not isinstance(dataset_hash, str)
        or len(dataset_hash) != 64
        or any(character not in "0123456789abcdef" for character in dataset_hash)
    ):
        raise ValueError("dataset semantic identifier is malformed")
    workload = _expected_workload_contract(config, point)
    if dataset_hash != workload["dataset_hash"]:
        raise ValueError("dataset semantic identifier does not match workload")
    if (
        int(row.get("event_count", -1)) != workload["event_count"]
        or int(row.get("distinct_invalid_count", -1)) != workload["distinct_invalid_count"]
    ):
        raise ValueError("workload event statistics do not match configuration")
    declaration = _method_declaration(config, point.method_name)
    if row.get("method_implementation") != declaration["implementation"]:
        raise ValueError("method implementation identifier mismatch")
    expected_method = next(
        method for method in _parse_methods(config) if method.name == point.method_name
    )
    _validate_conditioning_result(row, workload, expected_method)
    if row.get("method_config") != vars(expected_method):
        raise ValueError("method configuration does not match implementation")
    if row.get("service_limits") != vars(_parse_limits(config)):
        raise ValueError("service limits do not match configuration")
    expected_first_seen = (
        workload["observed_first_seen_ffr"] if expected_method.use_positive_screen else None
    )
    expected_weighted = (
        workload["observed_request_weighted_ffr"] if expected_method.use_positive_screen else None
    )
    if (
        row.get("observed_first_seen_ffr") != expected_first_seen
        or row.get("observed_request_weighted_ffr") != expected_weighted
        or row.get("worst_region_ffr") != expected_first_seen
    ):
        raise ValueError("observed filter outcomes do not match deterministic workload")
    expected_parameters = (
        _expected_filter_parameters(config, point.curve.seed)
        if expected_method.use_positive_screen
        else None
    )
    if _canonical_json(row.get("filter_parameters")) != _canonical_json(expected_parameters):
        raise ValueError("filter parameters do not match the implemented filter")
    expected_filter_memory = (
        expected_screen.memory_report().total_bytes if expected_method.use_positive_screen else 0
    )
    profile = next(
        (item for item in _parse_profiles(config) if item.name == point.curve.profile_name),
        None,
    )
    if profile is None:
        raise ValueError("verifier profile is not configured")
    verifier = row.get("verifier_profile")
    if not isinstance(verifier, Mapping):
        raise ValueError("verifier profile metadata is required")
    expected_profile_core = {
        "name": profile.name,
        "algorithm": profile.algorithm,
        "implementation": (
            "hashlib.pbkdf2_hmac"
            if profile.algorithm == "pbkdf2_sha256"
            else "argon2.low_level.hash_secret_raw(Type.ID)"
        ),
        "library": ("Python/OpenSSL" if profile.algorithm == "pbkdf2_sha256" else "argon2-cffi"),
        "parameters": dict(profile.parameters),
        "actual_kdf_execution": True,
    }
    if any(verifier.get(key) != value for key, value in expected_profile_core.items()):
        raise ValueError("verifier metadata contradicts the configured KDF")
    if profile.algorithm == "argon2id" and not isinstance(verifier.get("library_version"), str):
        raise ValueError("Argon2id result is missing its library version")
    host = row.get("host")
    binding = row.get("curve_environment_binding")
    if not isinstance(host, Mapping) or not isinstance(binding, Mapping):
        raise ValueError("host and curve environment binding are required")
    expected_binding = _curve_environment_binding_values(host, verifier)
    if dict(binding) != expected_binding:
        raise ValueError("curve environment binding contradicts host/runtime/KDF")
    warmup = row.get("warmup")
    phase = row.get("phase_metrics")
    resources = row.get("resource_samples")
    report = row.get("open_loop_report")
    if not all(isinstance(item, Mapping) for item in (warmup, phase, resources, report)):
        raise ValueError("warmup, phase, resource, and open-loop payloads are required")
    assert isinstance(warmup, Mapping)
    assert isinstance(phase, Mapping)
    assert isinstance(resources, Mapping)
    assert isinstance(report, Mapping)
    warmup_phase = warmup.get("phase_snapshot")
    if not isinstance(warmup_phase, Mapping):
        raise ValueError("warmup phase snapshot is required")
    _validate_phase_conservation(warmup_phase, "warmup")
    limits = _parse_limits(config)
    _validate_phase_resource_bounds(warmup_phase, expected_method, limits, label="warmup")
    _validate_phase_resource_bounds(phase, expected_method, limits, label="measurement")
    warmup_reasons = _warmup_integrity_reasons(
        warmup,
        warmup_phase,
        _expected_warmup_scheduled(config, point),
        float(config["measurement"]["warmup_seconds"]),
    )
    if (
        warmup.get("invalid_reasons") != warmup_reasons
        or warmup.get("integrity_valid") is not (not warmup_reasons)
        or warmup.get("drained_before_measurement") is not True
    ):
        raise ValueError("warmup integrity declaration is inconsistent")
    if (
        warmup.get("cache_persists_into_measurement") is not True
        or float(warmup.get("invalid_rps", -1)) != 0.0
    ):
        raise ValueError("warmup workload declaration is inconsistent")
    shutdown_clean, drained = _validate_nonderived_measurements(
        row, expected_method, expected_filter_memory
    )
    derived = _derive_measurement_result(
        config,
        phase,
        workload,
        limits,
        report,
        resources,
        warmup_reasons,
        warmup_request_accounting_conserved=bool(warmup_phase["conservation"]["valid"]),
        drained_before_timeout=drained,
        shutdown_clean=shutdown_clean,
    )
    expected_measurement_fields = _expected_measurement_fields_for_row(row, derived, config)
    for field, expected_value in expected_measurement_fields.items():
        if row.get(field) != expected_value:
            raise ValueError(f"derived result field contradicts evidence: {field}")
    scope_blockers = [
        "NETWORK_BLOCKED: in-process harness does not measure sockets, TLS, or kernel networking",
        "FRONTEND_RSS_ISOLATION_BLOCKED: RSS/USS is sampled for the combined benchmark process",
    ]
    if row.get("scope_blockers") != scope_blockers or row.get("blockers") != [
        *scope_blockers,
        *(
            f"INVALID_MEASUREMENT: {reason}"
            for reason in expected_measurement_fields["invalid_reasons"]
        ),
    ]:
        raise ValueError("result blockers contradict measurement evidence")
    invalid_values = [float(item) for item in config["loads"]["invalid_rps"]]
    load_index = invalid_values.index(point.invalid_rps)
    expected_order = method_execution_order(config, point.curve, load_index)
    if (
        row.get("method_order_policy") != "seed_rank_plus_invalid_load_rank_cyclic_v1"
        or row.get("method_execution_order") != expected_order
        or row.get("method_execution_position") != expected_order.index(point.method_name)
    ):
        raise ValueError("method execution order does not match seeded rotation")
    if row.get("traffic_mode") != "open_loop":
        raise ValueError("result traffic mode mismatch")
    if row.get("deployment_mode") != "in_process_bounded_threaded_service":
        raise ValueError("result deployment mode mismatch")
    if row.get("network_transport") != "BLOCKED_NOT_MEASURED":
        raise ValueError("result network scope mismatch")
    if row.get("arrival_distribution") != config["measurement"]["arrival_distribution"]:
        raise ValueError("arrival distribution mismatch")
    if float(row.get("offered_total_rps", -1)) != (point.curve.legitimate_rps + point.invalid_rps):
        raise ValueError("offered total rate contradicts point coordinates")
    if float(row.get("measurement_duration_seconds", -1)) != float(
        config["measurement"]["duration_seconds"]
    ):
        raise ValueError("measurement duration mismatch")
    if int(row.get("event_count", -1)) != int(row.get("nominal_scheduled_event_count", -2)):
        raise ValueError("event count semantics are inconsistent")
    if row.get("event_count_semantics") != "nominal_scheduled_arrivals_not_achieved_ingress":
        raise ValueError("event count semantics declaration mismatch")
    run_material = {
        "commit": row["commit"],
        "config_hash": config_hash,
        "main_claims_manifest_id": main_claims_manifest_id,
        "dataset_hash": row["dataset_hash"],
        "filter_realization_id": expected_screen.identity,
        "seed": point.curve.seed,
        "method": point.method_name,
        "scenario": point.curve.scenario,
        "profile": point.curve.profile_name,
        "legitimate_rps": point.curve.legitimate_rps,
        "invalid_rps": point.invalid_rps,
        "timestamp": row["timestamp_utc"],
    }
    if row.get("run_id") != _canonical_hash(run_material)[:24]:
        raise ValueError("run_id does not match result provenance")


def _validate_checkpoint(
    envelope: Mapping[str, Any],
    point: PointSpec,
    config_hash: str,
    path: Path,
    *,
    config: Mapping[str, Any],
    expected_environment: Mapping[str, Any] | None = None,
    expected_commit: str | None = None,
) -> dict[str, Any]:
    main_claims_manifest_id = _require_current_main_claims_manifest_id(
        config, context="checkpoint consumer"
    )
    if set(envelope) != CHECKPOINT_ENVELOPE_FIELDS:
        raise ValueError(f"checkpoint envelope schema mismatch: {path}")
    if envelope.get("schema_version") != CHECKPOINT_SCHEMA_VERSION:
        raise ValueError(f"checkpoint schema version mismatch: {path}")
    if envelope.get("kind") != "service_bench_point":
        raise ValueError(f"checkpoint kind mismatch: {path}")
    if envelope.get("main_claims_manifest_id") != main_claims_manifest_id:
        raise ValueError(f"checkpoint main_claims_manifest_id mismatch: {path}")
    point_id = point.point_id(config_hash)
    if envelope.get("point_id") != point_id:
        raise ValueError(f"checkpoint point_id mismatch: {path}")
    if envelope.get("config_hash") != config_hash:
        raise ValueError(f"checkpoint config_hash mismatch: {path}")
    if envelope.get("point") != point.identity(config_hash):
        raise ValueError(f"checkpoint point coordinates mismatch: {path}")
    row_payload = envelope.get("row")
    if not isinstance(row_payload, Mapping):
        raise ValueError(f"checkpoint row must be a mapping: {path}")
    row = dict(row_payload)
    expected_curve_id = _canonical_hash(
        {"config_hash": config_hash, "curve": point.curve.as_dict()}
    )[:32]
    try:
        coordinates_match = (
            int(row["seed"]) == point.curve.seed
            and row["scenario"] == point.curve.scenario
            and row["verifier_profile"]["name"] == point.curve.profile_name
            and float(row["offered_legitimate_rps"]) == point.curve.legitimate_rps
            and float(row["offered_invalid_rps"]) == point.invalid_rps
        )
    except (KeyError, TypeError, ValueError):
        coordinates_match = False
    required_provenance = (
        "commit",
        "dataset_hash",
        "timestamp_utc",
        "host",
        "git",
        "provenance_class",
    )
    row_git = row.get("git")
    if (
        row.get("config_hash") != config_hash
        or row.get("main_claims_manifest_id") != main_claims_manifest_id
        or row.get("main_claims_manifest_id") != envelope.get("main_claims_manifest_id")
        or row.get("point_id") != point_id
        or row.get("method") != point.method_name
        or row.get("curve") != point.curve.as_dict()
        or row.get("curve_id") != expected_curve_id
        or not coordinates_match
        or row.get("result_status") not in {"VALID", "INVALID"}
        or envelope.get("result_status") != row.get("result_status")
        or envelope.get("commit") != row.get("commit")
        or any(not row.get(field) for field in required_provenance)
        or not isinstance(row_git, Mapping)
        or row_git.get("commit") != row.get("commit")
        or row.get("provenance_class") != config["execution"]["provenance_class"]
    ):
        raise ValueError(f"checkpoint row identity mismatch: {path}")
    try:
        timestamp = datetime.fromisoformat(str(row["timestamp_utc"]))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"checkpoint timestamp is invalid: {path}") from exc
    if timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
        raise ValueError(f"checkpoint timestamp is not UTC: {path}")
    if not isinstance(row_git.get("dirty"), bool) or not isinstance(
        row_git.get("status_available"), bool
    ):
        raise ValueError(f"checkpoint git provenance types are invalid: {path}")
    if expected_commit is not None and row.get("commit") != expected_commit:
        raise ValueError(f"checkpoint commit differs from resumed run: {path}")
    if (
        expected_environment is not None
        and row.get("curve_environment_binding") != expected_environment
    ):
        raise ValueError(f"checkpoint curve environment differs from resumed run: {path}")
    if config["execution"]["require_clean_git"]:
        if (
            row.get("commit") in {None, "", "UNCOMMITTED"}
            or row_git.get("dirty") is not False
            or row_git.get("status_available") is not True
            or str(row.get("provenance_class", "")).startswith("TEMPORARY_")
        ):
            raise ValueError(f"formal checkpoint provenance is invalid: {path}")
    _validate_result_contract(row, point, config, config_hash)
    return row


def _write_checkpoint_atomic(
    checkpoint_dir: Path,
    point: PointSpec,
    config_hash: str,
    row: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
) -> Path:
    main_claims_manifest_id = _require_current_main_claims_manifest_id(
        config, context="checkpoint producer"
    )
    if row.get("main_claims_manifest_id") != main_claims_manifest_id:
        raise ValueError("checkpoint row main_claims_manifest_id mismatch")
    if row.get("result_schema_version") != RESULT_SCHEMA_VERSION:
        raise ValueError("checkpoint row result schema version mismatch")
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    point_id = point.point_id(config_hash)
    destination = _checkpoint_path(checkpoint_dir, point_id)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite point checkpoint {destination}; use --resume")
    envelope = {
        "schema_version": CHECKPOINT_SCHEMA_VERSION,
        "kind": "service_bench_point",
        "point_id": point_id,
        "config_hash": config_hash,
        "main_claims_manifest_id": main_claims_manifest_id,
        "point": point.identity(config_hash),
        "commit": row["commit"],
        "result_status": row["result_status"],
        "row": dict(row),
    }
    temporary = checkpoint_dir / (f".{point_id}.{os.getpid()}.{time_ns_for_checkpoint()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(envelope, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise FileExistsError(
                f"refusing to overwrite point checkpoint {destination}; use --resume"
            ) from exc
    finally:
        temporary.unlink(missing_ok=True)
    return destination


def time_ns_for_checkpoint() -> int:
    """Small indirection kept deterministic only for the published point ID."""

    import time

    return time.time_ns()


def aggregate_checkpoints(
    config: Mapping[str, Any],
    config_hash: str,
    checkpoint_dir: Path,
) -> dict[str, Any]:
    main_claims_manifest_id = _require_current_main_claims_manifest_id(
        config, context="checkpoint aggregate"
    )
    expected_points = enumerate_points(config)
    expected = {point.point_id(config_hash): point for point in expected_points}
    observed: dict[str, tuple[Path, dict[str, Any]]] = {}
    duplicates: dict[str, list[str]] = {}
    unexpected: list[str] = []
    malformed: list[str] = []
    malformed_errors: dict[str, str] = {}
    observed_main_claims_manifest_ids: set[str] = set()
    reclassified_operational_point_ids: list[str] = []
    reclassified_operational_reasons: dict[str, list[str]] = {}
    reclassified_operational_reason_counts: dict[str, int] = {}
    for path in sorted(checkpoint_dir.glob("*.json")):
        try:
            envelope = _read_checkpoint(path)
        except ValueError as exc:
            malformed.append(str(path))
            malformed_errors[str(path)] = str(exc)
            continue
        row_payload = envelope.get("row")
        for declared_id in (
            envelope.get("main_claims_manifest_id"),
            row_payload.get("main_claims_manifest_id")
            if isinstance(row_payload, Mapping)
            else None,
        ):
            if declared_id is not None:
                observed_main_claims_manifest_ids.add(str(declared_id))
        if (
            envelope.get("main_claims_manifest_id") != main_claims_manifest_id
            or not isinstance(row_payload, Mapping)
            or row_payload.get("main_claims_manifest_id") != main_claims_manifest_id
            or row_payload.get("main_claims_manifest_id") != envelope.get("main_claims_manifest_id")
        ):
            malformed.append(str(path))
            malformed_errors[str(path)] = (
                "checkpoint manifest identity differs from the current strict manifest"
            )
            continue
        point_id = str(envelope.get("point_id", ""))
        if point_id in observed:
            duplicates.setdefault(point_id, [str(observed[point_id][0])]).append(str(path))
            continue
        if point_id not in expected:
            unexpected.append(point_id or str(path))
            continue
        try:
            row = _validate_checkpoint(
                envelope,
                expected[point_id],
                config_hash,
                path,
                config=config,
            )
        except (KeyError, OverflowError, TypeError, ValueError) as exc:
            malformed.append(str(path))
            malformed_errors[str(path)] = str(exc)
            continue
        row, reclassified_reasons = _reclassify_operational_observation_row(row, config)
        if reclassified_reasons:
            reclassified_operational_point_ids.append(point_id)
            reclassified_operational_reasons[point_id] = reclassified_reasons
            for reason in reclassified_reasons:
                reclassified_operational_reason_counts[reason] = (
                    reclassified_operational_reason_counts.get(reason, 0) + 1
                )
        observed[point_id] = (path, row)
    missing = sorted(set(expected) - set(observed))
    rows = [
        observed[point.point_id(config_hash)][1]
        for point in expected_points
        if point.point_id(config_hash) in observed
    ]
    invalid_point_ids = sorted(
        row["point_id"] for row in rows if row.get("result_status") != "VALID"
    )
    commits = sorted({str(row.get("commit")) for row in rows})
    provenance_classes = sorted({str(row.get("provenance_class")) for row in rows})
    formal_provenance_invalid = bool(
        config["execution"]["require_clean_git"]
        and (
            len(commits) != 1
            or commits[0] in {"", "None", "UNCOMMITTED"}
            or any(
                row.get("git", {}).get("dirty") is not False
                or not row.get("git", {}).get("status_available")
                for row in rows
            )
        )
    )
    coverage_complete = not (missing or unexpected or duplicates or malformed)
    curve_environments: dict[str, set[str]] = {}
    workload_ids: dict[tuple[str, float], set[str]] = {}
    for row in rows:
        curve_id = str(row.get("curve_id"))
        curve_environments.setdefault(curve_id, set()).add(
            json.dumps(
                row.get("curve_environment_binding"),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        workload_ids.setdefault((curve_id, float(row["offered_invalid_rps"])), set()).add(
            str(row.get("dataset_hash"))
        )
    environment_conflict_curve_ids = sorted(
        curve_id for curve_id, bindings in curve_environments.items() if len(bindings) != 1
    )
    workload_identity_conflicts = sorted(
        f"{curve_id}:{invalid_rps:g}"
        for (curve_id, invalid_rps), identifiers in workload_ids.items()
        if len(identifiers) != 1
    )
    provenance_class_invalid = provenance_classes not in (
        [],
        [str(config["execution"]["provenance_class"])],
    )
    main_claims_manifest_id_conflict = bool(
        observed_main_claims_manifest_ids
        and observed_main_claims_manifest_ids != {main_claims_manifest_id}
    )
    formal_gate_blockers = formal_execution_blockers(config)
    if coverage_complete:
        _assign_saturation(config, rows)
    invalid_inference_curves = sorted(
        {
            str(row.get("curve_id"))
            for row in rows
            if row.get("service_saturation_status")
            in {
                "INVALID_MEASUREMENT_ROWS",
                "BASELINE_REFERENCE_INVALID",
                "NON_MONOTONIC_INVALID",
            }
        }
    )
    aggregation_valid = not (
        not coverage_complete
        or invalid_point_ids
        or formal_provenance_invalid
        or provenance_class_invalid
        or main_claims_manifest_id_conflict
        or environment_conflict_curve_ids
        or workload_identity_conflicts
        or formal_gate_blockers
        or invalid_inference_curves
    )
    coverage = {
        "main_claims_manifest_id": main_claims_manifest_id,
        "observed_main_claims_manifest_ids": sorted(observed_main_claims_manifest_ids),
        "main_claims_manifest_id_conflict": main_claims_manifest_id_conflict,
        "expected_point_count": len(expected),
        "observed_unique_point_count": len(observed),
        "coverage_complete": coverage_complete,
        "missing_point_ids": missing,
        "unexpected_point_ids": sorted(unexpected),
        "duplicate_point_ids": duplicates,
        "malformed_checkpoint_files": malformed,
        "malformed_checkpoint_errors": malformed_errors,
        "invalid_point_ids": invalid_point_ids,
        "reclassified_operational_observation_point_ids": sorted(
            reclassified_operational_point_ids
        ),
        "reclassified_operational_observation_reasons": dict(
            sorted(reclassified_operational_reasons.items())
        ),
        "reclassified_operational_observation_reason_counts": dict(
            sorted(reclassified_operational_reason_counts.items())
        ),
        "commit_values": commits,
        "formal_provenance_invalid": formal_provenance_invalid,
        "provenance_class_values": provenance_classes,
        "provenance_class_invalid": provenance_class_invalid,
        "environment_conflict_curve_ids": environment_conflict_curve_ids,
        "workload_identity_conflicts": workload_identity_conflicts,
        "formal_execution_blockers": formal_gate_blockers,
        "invalid_inference_curve_ids": invalid_inference_curves,
        "aggregation_status": "VALID" if aggregation_valid else "INVALID",
    }
    return {"rows": rows, "coverage": coverage}


def run_config(
    config: Mapping[str, Any],
    config_hash: str,
    *,
    curves: Sequence[CurveSpec] | None = None,
    checkpoint_dir: Path | None = None,
    resume: bool = False,
    git_metadata: Mapping[str, Any] | None = None,
    host_metadata: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    _require_current_main_claims_manifest_id(config, context="service runner")
    enforce_execution_gate(config)
    dataset_config = config["dataset"]
    dataset = ServiceDataset(
        account_count=int(dataset_config["account_count"]),
        dataset_seed=int(dataset_config["seed"]),
    )
    profiles = _parse_profiles(config)
    backends: dict[str, KdfBackend] = {}
    methods = _parse_methods(config)
    measurement = config["measurement"]
    duration = float(measurement["duration_seconds"])
    distribution = str(measurement["arrival_distribution"])
    scenario_config = config.get("scenario_parameters", {})
    git = dict(_git_metadata() if git_metadata is None else git_metadata)
    enforce_git_policy(config, git)
    host = dict(_host_metadata() if host_metadata is None else host_metadata)
    rows: list[dict[str, Any]] = []
    selected_curves = enumerate_curves(config) if curves is None else list(curves)
    known_curves = {curve.as_dict()["ordinal"]: curve for curve in enumerate_curves(config)}
    for curve in selected_curves:
        if known_curves.get(curve.ordinal) != curve:
            raise ValueError(f"curve is not part of this configuration: {curve}")
    selected_points = enumerate_points(config, selected_curves)
    if checkpoint_dir is not None and not resume:
        existing = [
            _checkpoint_path(checkpoint_dir, point.point_id(config_hash))
            for point in selected_points
            if _checkpoint_path(checkpoint_dir, point.point_id(config_hash)).exists()
        ]
        if existing:
            raise FileExistsError(
                f"refusing to overwrite {len(existing)} point checkpoint(s); use --resume"
            )
    profile_by_name = {profile.name: profile for profile in profiles}
    method_by_name = {method.name: method for method in methods}
    frozen_screen_spec = FrozenScreenSpec.from_config(config["filter"])
    screen_by_seed: dict[int, ScreenRealization] = {}
    false_positives_by_seed_scenario: dict[tuple[int, str], tuple[InvalidCredential, ...]] = {}
    for curve in selected_curves:
        seed = curve.seed
        screen = screen_by_seed.get(seed)
        if screen is None:
            screen = build_screen(frozen_screen_spec, dataset.members(), seed)
            screen_by_seed[seed] = screen
        false_positive_key = (seed, curve.scenario)
        false_positives = false_positives_by_seed_scenario.get(false_positive_key)
        if false_positives is None:
            false_positives = ()
            if curve.scenario in FALSE_POSITIVE_SCENARIOS:
                if _uses_strong_oracle_conditioning(curve.scenario, scenario_config):
                    false_positives = _frozen_conditioned_credentials(
                        dataset,
                        curve.scenario,
                        scenario_config,
                        int(dataset_config["false_positive_pool_size"]),
                    )
                else:
                    false_positives = _discover_false_positives(
                        dataset,
                        screen,
                        required=int(dataset_config["false_positive_pool_size"]),
                        max_scan=int(dataset_config["false_positive_max_scan"]),
                    )
            false_positives_by_seed_scenario[false_positive_key] = false_positives
        profile = profile_by_name[curve.profile_name]
        for invalid_load_index, invalid_value in enumerate(config["loads"]["invalid_rps"]):
            invalid_rps = float(invalid_value)
            plan = _build_plan(
                dataset,
                screen,
                false_positives,
                seed,
                curve.scenario,
                curve.legitimate_rps,
                invalid_rps,
                duration,
                distribution,
                scenario_config,
            )
            prescribed_order = method_execution_order(config, curve, invalid_load_index)
            for method_position, method_name in enumerate(prescribed_order):
                method_config = _method_declaration(config, method_name)
                method = method_by_name[method_name]
                point = PointSpec(curve, method.name, invalid_rps)
                point_id = point.point_id(config_hash)
                checkpoint_path = (
                    None if checkpoint_dir is None else _checkpoint_path(checkpoint_dir, point_id)
                )
                if checkpoint_path is not None and checkpoint_path.exists():
                    if not resume:
                        raise FileExistsError(
                            f"refusing to overwrite point checkpoint {checkpoint_path}"
                        )
                    row = _validate_checkpoint(
                        _read_checkpoint(checkpoint_path),
                        point,
                        config_hash,
                        checkpoint_path,
                        config=config,
                        expected_environment=_curve_environment_binding(host, profile),
                        expected_commit=str(git["commit"]),
                    )
                    rows.append(row)
                    continue
                timestamp = datetime.now(timezone.utc).isoformat()
                if profile.name not in backends:
                    backends.update(_make_backends(dataset, [profile]))
                row = _run_point(
                    config,
                    config_hash,
                    git,
                    host,
                    timestamp,
                    dataset,
                    screen,
                    method,
                    str(method_config["implementation"]),
                    prescribed_order,
                    method_position,
                    profile,
                    backends[profile.name],
                    seed,
                    curve.scenario,
                    curve.legitimate_rps,
                    invalid_rps,
                    plan,
                )
                row["curve"] = curve.as_dict()
                row["curve_id"] = _canonical_hash(
                    {"config_hash": config_hash, "curve": curve.as_dict()}
                )[:32]
                row["point_id"] = point_id
                missing = [field for field in RESULT_SCHEMA if field not in row]
                if missing:
                    raise AssertionError(f"result row is missing schema fields: {missing}")
                if checkpoint_dir is not None:
                    _write_checkpoint_atomic(
                        checkpoint_dir,
                        point,
                        config_hash,
                        row,
                        config=config,
                    )
                rows.append(row)
    _assign_saturation(config, rows)
    return rows


def write_results(
    output: Path,
    summary_output: Path,
    rows: Sequence[Mapping[str, Any]],
    overwrite: bool,
    coverage: Mapping[str, Any] | None = None,
    *,
    config: Mapping[str, Any],
) -> None:
    main_claims_manifest_id = _require_current_main_claims_manifest_id(
        config, context="result writer"
    )
    for row in rows:
        missing = [field for field in RESULT_SCHEMA if field not in row]
        if missing:
            raise ValueError(f"result rows are missing schema fields: {missing}")
        if row.get("result_schema_version") != RESULT_SCHEMA_VERSION:
            raise ValueError("result rows contain an old or unsupported schema version")
        if row.get("main_claims_manifest_id") != main_claims_manifest_id:
            raise ValueError("result rows contain a non-current main_claims_manifest_id")
    if coverage is not None:
        if coverage.get("main_claims_manifest_id") != main_claims_manifest_id:
            raise ValueError("coverage main_claims_manifest_id mismatch")
        observed_ids = coverage.get("observed_main_claims_manifest_ids")
        if observed_ids not in ([], [main_claims_manifest_id]):
            raise ValueError("coverage contains mixed main_claims_manifest_id values")
        if coverage.get("main_claims_manifest_id_conflict") is not False:
            raise ValueError("coverage reports a main_claims_manifest_id conflict")
    for path in (output, summary_output):
        if path.exists() and not overwrite:
            raise FileExistsError(f"refusing to overwrite {path}; pass --overwrite")
        path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
    temporary.replace(output)
    summary_temporary = summary_output.with_suffix(summary_output.suffix + ".tmp")
    with summary_temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(
            {
                "schema_version": SUMMARY_SCHEMA_VERSION,
                "main_claims_manifest_id": main_claims_manifest_id,
                "coverage": None if coverage is None else dict(coverage),
                "saturation": summarize_saturation(rows),
                "backend_invalid_capacity": summarize_backend_invalid_capacity_for_config(
                    rows, config
                ),
            },
            handle,
            sort_keys=True,
            separators=(",", ":"),
        )
        handle.write("\n")
    summary_temporary.replace(summary_output)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary-output", type=Path)
    parser.add_argument("--checkpoint-dir", type=Path)
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--aggregate-only", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config, config_hash = load_config(args.config)
    if args.validate_only:
        curves = enumerate_curves(config)
        blockers = formal_execution_blockers(config)
        status = "BLOCKED" if blockers else "PASS"
        print(
            json.dumps(
                {
                    "status": status,
                    "config_hash": config_hash,
                    "curve_count": len(curves),
                    "point_count": len(enumerate_points(config, curves)),
                    "formal_execution_blockers": blockers,
                },
                sort_keys=True,
            )
        )
        return 2 if blockers else 0
    blockers = formal_execution_blockers(config)
    if blockers and not args.aggregate_only:
        print(
            json.dumps(
                {
                    "status": "BLOCKED",
                    "config_hash": config_hash,
                    "formal_execution_blockers": blockers,
                    "message": "no service measurement was started",
                },
                sort_keys=True,
            )
        )
        return 2
    summary_output = args.summary_output or args.output.with_suffix(".summary.json")
    checkpoint_dir = args.checkpoint_dir or Path(f"{args.output}.checkpoints")
    if args.aggregate_only:
        aggregation = aggregate_checkpoints(config, config_hash, checkpoint_dir)
        coverage = aggregation["coverage"]
        if coverage["aggregation_status"] != "VALID":
            print(
                json.dumps(
                    {
                        "status": "INVALID",
                        "config_hash": config_hash,
                        "checkpoint_dir": str(checkpoint_dir.resolve()),
                        "coverage": coverage,
                    },
                    sort_keys=True,
                )
            )
            return 2
        write_results(
            args.output,
            summary_output,
            aggregation["rows"],
            overwrite=args.overwrite,
            coverage=coverage,
            config=config,
        )
        rows = aggregation["rows"]
        status = "VALID"
    else:
        all_curves = enumerate_curves(config)
        selected_curves = select_curve_shard(all_curves, args.shard_index, args.shard_count)
        rows = run_config(
            config,
            config_hash,
            curves=selected_curves,
            checkpoint_dir=checkpoint_dir,
            resume=args.resume,
        )
        aggregation = aggregate_checkpoints(config, config_hash, checkpoint_dir)
        coverage = aggregation["coverage"]
        complete_grid = args.shard_count == 1 and coverage["coverage_complete"]
        output_rows = aggregation["rows"] if complete_grid else rows
        if complete_grid:
            status = coverage["aggregation_status"]
        else:
            status = (
                "SHARD_COMPLETE"
                if all(row["result_status"] == "VALID" for row in rows)
                else "SHARD_INVALID"
            )
        write_results(
            args.output,
            summary_output,
            output_rows,
            overwrite=args.overwrite,
            coverage=coverage,
            config=config,
        )
        rows = output_rows
    print(
        json.dumps(
            {
                "status": status,
                "row_count": len(rows),
                "output": str(args.output.resolve()),
                "summary_output": str(summary_output.resolve()),
                "checkpoint_dir": str(checkpoint_dir.resolve()),
                "config_hash": config_hash,
                "coverage": coverage,
            },
            sort_keys=True,
        )
    )
    return 0 if status in {"VALID", "SHARD_COMPLETE"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
