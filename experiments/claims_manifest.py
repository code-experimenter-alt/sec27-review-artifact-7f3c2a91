"""Strict validation and canonical identity for the main claims manifest."""

from __future__ import annotations

import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Mapping

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MAIN_CLAIMS_PATH = ROOT / "experiments" / "configs" / "main_claims.yaml"
HISTORICAL_E9_MAIN_CLAIMS_PATH = ROOT / "experiments" / "configs" / "main_claims.e9_historical.yaml"
DEFAULT_PAPER_CLAIMS_PATH = ROOT / "paper" / "claims.yaml"

RESEARCH_IN_PROGRESS = "RESEARCH_IN_PROGRESS"
FROZEN = "FROZEN"
MANIFEST_ID_PREFIX = "sha256:"
HISTORICAL_E9_MANIFEST_ID = (
    "sha256:ce7c98b2c1c380dea096a88fbdc53b7bc315b42ada531feec7007b6e075cf179"
)

ROOT_KEYS = frozenset(
    {
        "schema_version",
        "status",
        "seeds",
        "datasets",
        "deployment_profiles",
        "state_exposure_profiles",
        "train_window",
        "validation_window",
        "test_window",
        "memory_budgets_bits_per_account",
        "frontend_latency_budgets_us",
        "region_counts",
        "epsilon_caps",
        "compromise_work_targets",
        "cache_sizes_bytes",
        "cache_policies",
        "recurrence_learning",
        "attack_scenarios",
        "verifier_profiles",
        "verifier_profile_specs",
        "hardware_profile",
        "measurement",
        "service_e7_contract",
        "evidence_scope",
        "e9_failure_classifier",
    }
)

ALLOWED_DATASETS = frozenset({"synthetic_zipf_v1", "synthetic_shift_v1"})
ALLOWED_DEPLOYMENT_PROFILES = frozenset({"U", "A"})
ALLOWED_STATE_EXPOSURE_PROFILES = frozenset({"TM0", "TM1", "TM2", "TM3", "TM4", "TM5"})
ALLOWED_WINDOWS = frozenset(
    {"synthetic_days_00_06", "synthetic_days_07_08", "synthetic_days_09_13"}
)
ALLOWED_CACHE_POLICIES = frozenset({"none", "lru", "tinylfu"})
ALLOWED_ATTACK_SCENARIOS = frozenset(
    {
        "benign_mixture",
        "repeated_false_positive",
        "unique_first_seen",
        "weakest_region_white_box",
        "false_positive_oracle",
        "cache_pollution",
        "occupancy_injection",
        "cross_generator_shift",
    }
)
VERIFIER_PROFILE_ALGORITHMS = {
    "argon2id_interactive": "argon2id",
    "argon2id_capacity_bound": "argon2id",
}
ALLOWED_VERIFIER_PROFILES = frozenset(VERIFIER_PROFILE_ALGORITHMS)
ALLOWED_HARDWARE_PROFILES = frozenset({"fu_i9_13900kf_rtx5090"})

E9_FAILURE_CLASSIFIER_FREEZE_STATUS = "PREREGISTERED_BEFORE_FORMAL_COLLECTION"
E9_FAILURE_CASES = [
    "unknown_username",
    "positive_screen_negative",
    "negative_cache_hit",
    "backend_mismatch",
    "transient_backend_failure",
]
E9_KDF_STRATA = {
    "pbkdf2_hmac_sha256_310000_dklen32": {
        "algorithm": "pbkdf2_hmac_sha256",
        "iterations": 310000,
        "dklen": 32,
    },
    "argon2id_m19456_t2_p1_h32": {
        "algorithm": "argon2id",
        "version": 19,
        "memory_kib": 19456,
        "time_cost": 2,
        "parallelism": 1,
        "hash_len": 32,
    },
}
E9_TRAINING_SEEDS_BY_KDF = {
    "pbkdf2_hmac_sha256_310000_dklen32": list(range(9400, 9410)),
    "argon2id_m19456_t2_p1_h32": list(range(9410, 9420)),
}
E9_EVALUATION_SEEDS_BY_KDF = {
    "pbkdf2_hmac_sha256_310000_dklen32": list(range(9420, 9450)),
    "argon2id_m19456_t2_p1_h32": list(range(9450, 9480)),
}
E9_SEED_UNIVERSE = list(range(9400, 9480))
E9_EXTERNAL_FEATURES = [
    "log1p_connect_ns",
    "log1p_request_to_first_byte_ns",
    "log1p_request_to_eof_ns",
    "log1p_connect_start_to_eof_ns",
    "receive_call_count",
    "receive_first_chunk_bytes",
    "receive_last_chunk_bytes",
    "receive_min_chunk_bytes",
    "receive_max_chunk_bytes",
    "receive_order_weighted_bytes",
    "local_port",
    "peer_port",
]
E9_CONSTANT_EQUIVALENCE_FIELDS = [
    "response.status",
    "response.bytes",
    "response.sha256",
    "response.frame_order",
    "response.frame_count",
    "response.client_observed_eof",
    "connection.transport",
    "connection.address_family",
    "connection.socket_type",
    "connection.protocol",
    "connection.local_is_loopback",
    "connection.peer_is_loopback",
    "connection.client_tcp_nodelay",
    "connection.client_half_closed_write",
    "connection.connection_reused",
    "server_resource.server_observed_client_eof",
    "server_resource.server_tcp_nodelay",
    "server_resource.server_shutdown_write",
]
E9_CLAIM_SCOPE = {
    "transport": "TCP_IPV4_LOOPBACK_EXACT_DECLARED_CONTRACT_ONLY",
    "kdf_role_by_stratum": {
        "pbkdf2_hmac_sha256_310000_dklen32": "LEGACY_COMPATIBILITY_KDF",
        "argon2id_m19456_t2_p1_h32": "ARGON2ID_INTERACTIVE_EXACT_PARAMETER_PROFILE",
    },
    "not_evaluated_verifier_profiles": ["argon2id_capacity_bound"],
    "generalization_policy": "NO_GENERALIZATION_BEYOND_DECLARED_TRANSPORT_AND_KDF_STRATA",
    "failed_gate_policy": "DOCUMENT_LEAKAGE_AND_NARROW_THE_CLAIM",
}
E9_PATH_CONTRACTS = {
    "unknown_username": {
        "precondition": "DIRECTORY_MISS_WITH_DUMMY_NO_ACCOUNT_VERIFIER_PATH",
        "route": "FAIL_OPEN_BACKEND",
        "accepted": False,
        "backend_kind": "NO_ACCOUNT",
        "backend_calls": 1,
        "kdf_calls": 1,
        "cache_hits": 0,
        "screen_negatives": 0,
        "response_status": 401,
        "response_body": "authentication failed",
    },
    "positive_screen_negative": {
        "precondition": "KNOWN_ACCOUNT_POSITIVE_SCREEN_NEGATIVE",
        "route": "POSITIVE_SCREEN_REJECT",
        "accepted": False,
        "backend_kind": None,
        "backend_calls": 0,
        "kdf_calls": 0,
        "cache_hits": 0,
        "screen_negatives": 1,
        "response_status": 401,
        "response_body": "authentication failed",
    },
    "negative_cache_hit": {
        "precondition": "KNOWN_ACCOUNT_PREWARMED_EXACT_NEGATIVE_CACHE_HIT",
        "route": "NEGATIVE_CACHE_REJECT",
        "accepted": False,
        "backend_kind": None,
        "backend_calls": 0,
        "kdf_calls": 0,
        "cache_hits": 1,
        "screen_negatives": 0,
        "response_status": 401,
        "response_body": "authentication failed",
    },
    "backend_mismatch": {
        "precondition": "KNOWN_ACCOUNT_POSITIVE_SCREEN_BACKEND_CREDENTIAL_MISMATCH",
        "route": "BACKEND_DENY",
        "accepted": False,
        "backend_kind": "CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS",
        "backend_calls": 1,
        "kdf_calls": 1,
        "cache_hits": 0,
        "screen_negatives": 1,
        "response_status": 401,
        "response_body": "authentication failed",
    },
    "transient_backend_failure": {
        "precondition": "KNOWN_ACCOUNT_PRE_VERIFIER_TYPED_TRANSIENT_BACKEND_RESULT",
        "route": "FAIL_OPEN_BACKEND",
        "accepted": False,
        "backend_kind": "TRANSIENT_FAILURE",
        "backend_calls": 1,
        "kdf_calls": 0,
        "cache_hits": 0,
        "screen_negatives": 1,
        "response_status": 401,
        "response_body": "authentication failed",
    },
    "valid_password": {
        "precondition": "KNOWN_ACCOUNT_CORRECT_PASSWORD",
        "route": "BACKEND_MATCH",
        "accepted": True,
        "backend_kind": "MATCH",
        "backend_calls": 1,
        "kdf_calls": 1,
        "cache_hits": 0,
        "screen_negatives": 0,
        "response_status": 200,
        "response_body": "authenticated",
    },
}
E9_FEATURE_FORMULAS = {
    "log1p_connect_ns": "log1p(timing.connect_ns)",
    "log1p_request_to_first_byte_ns": "log1p(timing.request_to_first_byte_ns)",
    "log1p_request_to_eof_ns": "log1p(timing.request_to_eof_ns)",
    "log1p_connect_start_to_eof_ns": "log1p(timing.connect_start_to_eof_ns)",
    "receive_call_count": "len(response.receive_call_sizes)",
    "receive_first_chunk_bytes": "response.receive_call_sizes[0]",
    "receive_last_chunk_bytes": "response.receive_call_sizes[-1]",
    "receive_min_chunk_bytes": "min(response.receive_call_sizes)",
    "receive_max_chunk_bytes": "max(response.receive_call_sizes)",
    "receive_order_weighted_bytes": "sum((index+1)*bytes for index,bytes in receive_call_sizes)",
    "local_port": "connection.local_port",
    "peer_port": "connection.peer_port",
}
E9_MEASUREMENT_CONTRACT = {
    "samples_per_case_per_seed": 200,
    "warmup_per_case_per_seed": 10,
    "measured_observations": 96_000,
    "failure_observations": 80_000,
    "functional_observations": 16_000,
    "failure_padding_ms": 10.0,
    "auth_workers": 4,
    "max_pending_padding": 256,
    "socket_timeout_seconds": 5.0,
    "seed_execution": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_RETRY",
    "schedule": {
        "unit": "WITHIN_SEED_COMPLETE_CASE_ORDINAL_GRID",
        "case_blocking": False,
        "shuffle": "PYTHON_RANDOM_FISHER_YATES",
        "seed_derivation": "SHA256_ASCII_E9_SCHEDULE_V1_SEED_FIRST_64_BITS_BIG_ENDIAN",
        "label_order": "ALL_CASES_DECLARED_ORDER_THEN_ORDINAL_BEFORE_SHUFFLE",
        "record_schedule_index": True,
    },
}
E9_DIAGNOSTICS_CONTRACT = {
    "timing_effects": [
        "seed_ks_request_to_eof",
        "seed_cliffs_delta_request_to_eof",
        "pooled_secondary_diagnostics",
    ],
    "resource_metrics": [
        "auth_worker_cpu_ns",
        "auth_worker_wall_ns",
        "backend_cpu_ns",
        "backend_wall_ns",
        "padding_actual_wait_ns",
    ],
    "padding_gates": [
        "auth_worker_overlap_failures_zero",
        "capacity_overflow_failures_zero",
        "early_release_count_zero",
        "pending_at_shutdown_zero",
    ],
    "role": "DESCRIPTIVE_AND_VALIDITY_DIAGNOSTICS_NOT_PRIMARY_AUC_GATE",
}

SERVICE_E7_FREEZE_STATUS = "PREREGISTERED_BEFORE_FORMAL_E7_COLLECTION"
SERVICE_E7_SEEDS = list(range(6100, 6120))
SERVICE_E7_VERIFIER_PROFILES = {
    "pbkdf2_reference_310k": {
        "algorithm": "pbkdf2_sha256",
        "iterations": 310000,
        "dklen": 32,
    },
    "argon2id_reference_19mib": {
        "algorithm": "argon2id",
        "time_cost": 2,
        "memory_cost_kib": 19456,
        "parallelism": 1,
        "hash_len": 32,
    },
}


class ClaimsManifestError(ValueError):
    """A claims or dependent paper manifest violates its frozen contract."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ClaimsManifestError("YAML mapping keys must be scalar and hashable") from exc
        if duplicate:
            raise ClaimsManifestError(f"duplicate YAML mapping key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_unique_yaml(path: Path, *, label: str = "YAML document") -> object:
    """Load YAML while rejecting duplicate keys at every mapping depth."""

    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise
    try:
        return yaml.load(text, Loader=_UniqueKeyLoader)
    except ClaimsManifestError:
        raise
    except yaml.YAMLError as exc:
        raise ClaimsManifestError(f"cannot parse {label}: {exc}") from exc


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ClaimsManifestError(f"{label} must be a string-keyed mapping")
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        raise ClaimsManifestError(f"{label} schema differs: missing={missing!r}, extra={extra!r}")


def _exact_literal(value: object, expected: object, label: str) -> None:
    """Require recursive exact type and value equality for a frozen literal."""

    if type(value) is not type(expected):
        raise ClaimsManifestError(
            f"{label} must have exact type {type(expected).__name__}, not {type(value).__name__}"
        )
    if type(expected) is dict:
        actual_mapping = _mapping(value, label)
        expected_mapping = expected
        _exact_keys(actual_mapping, frozenset(expected_mapping), label)
        for key, expected_item in expected_mapping.items():
            _exact_literal(actual_mapping[key], expected_item, f"{label}.{key}")
        return
    if type(expected) is list:
        actual_list = value
        expected_list = expected
        if len(actual_list) != len(expected_list):
            raise ClaimsManifestError(
                f"{label} must contain exactly {len(expected_list)} ordered items"
            )
        for index, (actual_item, expected_item) in enumerate(
            zip(actual_list, expected_list, strict=True)
        ):
            _exact_literal(actual_item, expected_item, f"{label}[{index}]")
        return
    if value != expected:
        raise ClaimsManifestError(f"{label} must equal the frozen value {expected!r}")


def _string(value: object, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ClaimsManifestError(f"{label} must be a non-empty string")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise ClaimsManifestError(f"{label} must be an exact integer, not Boolean or float")
    if minimum is not None and value < minimum:
        raise ClaimsManifestError(f"{label} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ClaimsManifestError(f"{label} must be at most {maximum}")
    return value


def _finite_float(
    value: object,
    label: str,
    *,
    minimum_exclusive: float | None = None,
    maximum: float | None = None,
) -> float:
    if type(value) is not float or not math.isfinite(value):
        raise ClaimsManifestError(f"{label} must be an exact finite float")
    if minimum_exclusive is not None and value <= minimum_exclusive:
        raise ClaimsManifestError(f"{label} must be greater than {minimum_exclusive}")
    if maximum is not None and value > maximum:
        raise ClaimsManifestError(f"{label} must be at most {maximum}")
    return value


def _string_list(
    value: object,
    label: str,
    *,
    allowed: frozenset[str],
) -> list[str]:
    if type(value) is not list or not value:
        raise ClaimsManifestError(f"{label} must be a non-empty list")
    if any(type(item) is not str or not item.strip() for item in value):
        raise ClaimsManifestError(f"{label} must contain non-empty strings")
    if len(set(value)) != len(value):
        raise ClaimsManifestError(f"{label} must contain unique values")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ClaimsManifestError(f"{label} contains unsupported values: {unknown!r}")
    return value


def _integer_grid(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> list[int]:
    if type(value) is not list or not value:
        raise ClaimsManifestError(f"{label} must be a non-empty list")
    parsed = [
        _integer(item, f"{label}[{index}]", minimum=minimum, maximum=maximum)
        for index, item in enumerate(value)
    ]
    if any(right <= left for left, right in zip(parsed, parsed[1:], strict=False)):
        raise ClaimsManifestError(f"{label} must be unique and strictly increasing")
    return parsed


def _uint64_list(value: object, label: str) -> list[int]:
    if type(value) is not list or not value:
        raise ClaimsManifestError(f"{label} must be a non-empty list")
    parsed = [
        _integer(item, f"{label}[{index}]", minimum=0, maximum=0xFFFFFFFFFFFFFFFF)
        for index, item in enumerate(value)
    ]
    if len(set(parsed)) != len(parsed):
        raise ClaimsManifestError(f"{label} must contain unique uint64 integers")
    return parsed


def _descending_float_grid(value: object, label: str) -> list[float]:
    if type(value) is not list or not value:
        raise ClaimsManifestError(f"{label} must be a non-empty list")
    parsed = [
        _finite_float(item, f"{label}[{index}]", minimum_exclusive=0.0, maximum=1.0)
        for index, item in enumerate(value)
    ]
    if any(right >= left for left, right in zip(parsed, parsed[1:], strict=False)):
        raise ClaimsManifestError(f"{label} must be unique and strictly decreasing")
    return parsed


def _validate_verifier_profile_specs(
    value: object, status: str, profile_names: list[str]
) -> dict[str, Any]:
    specs = _mapping(value, "main claims verifier_profile_specs")
    if status == RESEARCH_IN_PROGRESS:
        if specs:
            raise ClaimsManifestError(
                "RESEARCH_IN_PROGRESS manifests must not declare verifier algorithm parameters"
            )
        return specs
    if set(specs) != set(profile_names):
        raise ClaimsManifestError(
            "FROZEN verifier_profile_specs must exactly cover verifier_profiles"
        )
    for profile_name in profile_names:
        spec = _mapping(specs[profile_name], f"verifier_profile_specs.{profile_name}")
        algorithm = _string(spec.get("algorithm"), f"{profile_name}.algorithm")
        if algorithm != VERIFIER_PROFILE_ALGORITHMS[profile_name]:
            raise ClaimsManifestError(
                f"verifier_profile_specs.{profile_name}.algorithm contradicts its profile name"
            )
        if algorithm == "pbkdf2_sha256":
            expected = frozenset({"algorithm", "iterations", "dklen"})
        elif algorithm == "argon2id":
            expected = frozenset(
                {"algorithm", "memory_cost_kib", "time_cost", "parallelism", "hash_len"}
            )
        else:
            raise ClaimsManifestError(
                f"verifier_profile_specs.{profile_name}.algorithm is unsupported"
            )
        _exact_keys(spec, expected, f"verifier_profile_specs.{profile_name}")
        for field in expected - {"algorithm"}:
            minimum = 16 if field in {"dklen", "hash_len"} else 1
            _integer(
                spec[field],
                f"verifier_profile_specs.{profile_name}.{field}",
                minimum=minimum,
            )
    return specs


def _validate_e9_failure_classifier(value: object) -> dict[str, Any]:
    contract = _mapping(value, "e9_failure_classifier")
    _exact_keys(
        contract,
        frozenset(
            {
                "freeze_status",
                "analysis_script_path",
                "claim_scope",
                "failure_cases",
                "success_exclusion",
                "path_contracts",
                "kdf_strata",
                "seed_universe",
                "training_seeds_by_kdf",
                "evaluation_seeds_by_kdf",
                "feature_contract",
                "classifier",
                "inference",
                "data_integrity",
                "measurement_contract",
                "diagnostics_contract",
                "prospective_power_plan",
            }
        ),
        "e9_failure_classifier",
    )
    _exact_literal(
        contract["freeze_status"],
        E9_FAILURE_CLASSIFIER_FREEZE_STATUS,
        "e9_failure_classifier.freeze_status",
    )
    _exact_literal(
        contract["analysis_script_path"],
        "experiments/runners/failure_timing_bench.py",
        "e9_failure_classifier.analysis_script_path",
    )
    _exact_literal(
        contract["claim_scope"],
        E9_CLAIM_SCOPE,
        "e9_failure_classifier.claim_scope",
    )

    _string_list(
        contract["failure_cases"],
        "e9_failure_classifier.failure_cases",
        allowed=frozenset(E9_FAILURE_CASES),
    )
    _exact_literal(
        contract["failure_cases"],
        E9_FAILURE_CASES,
        "e9_failure_classifier.failure_cases",
    )
    _exact_literal(
        contract["success_exclusion"],
        {
            "excluded_case": "valid_password",
            "classifier_population": "FAILURE_CASES_ONLY",
            "role": "FUNCTIONAL_VALIDATION_ONLY",
        },
        "e9_failure_classifier.success_exclusion",
    )
    _exact_literal(
        contract["path_contracts"],
        E9_PATH_CONTRACTS,
        "e9_failure_classifier.path_contracts",
    )

    strata = _mapping(contract["kdf_strata"], "e9_failure_classifier.kdf_strata")
    _exact_keys(strata, frozenset(E9_KDF_STRATA), "e9_failure_classifier.kdf_strata")
    for stratum_id, expected_spec in E9_KDF_STRATA.items():
        _exact_literal(
            strata[stratum_id],
            expected_spec,
            f"e9_failure_classifier.kdf_strata.{stratum_id}",
        )

    seed_universe = _uint64_list(contract["seed_universe"], "e9_failure_classifier.seed_universe")
    if len(seed_universe) != 80:
        raise ClaimsManifestError("e9_failure_classifier.seed_universe must contain 80 seeds")
    partitions: dict[str, dict[str, list[int]]] = {}
    for split_name in ("training_seeds_by_kdf", "evaluation_seeds_by_kdf"):
        split = _mapping(contract[split_name], f"e9_failure_classifier.{split_name}")
        _exact_keys(
            split,
            frozenset(E9_KDF_STRATA),
            f"e9_failure_classifier.{split_name}",
        )
        partitions[split_name] = {}
        for stratum_id in E9_KDF_STRATA:
            seeds = _uint64_list(
                split[stratum_id],
                f"e9_failure_classifier.{split_name}.{stratum_id}",
            )
            expected_count = 10 if split_name == "training_seeds_by_kdf" else 30
            if len(seeds) != expected_count:
                raise ClaimsManifestError(
                    f"e9_failure_classifier.{split_name}.{stratum_id} "
                    f"must contain exactly {expected_count} seeds"
                )
            partitions[split_name][stratum_id] = seeds

    partitioned_seeds: list[int] = []
    for stratum_id in E9_KDF_STRATA:
        training = partitions["training_seeds_by_kdf"][stratum_id]
        evaluation = partitions["evaluation_seeds_by_kdf"][stratum_id]
        if set(training) & set(evaluation):
            raise ClaimsManifestError(
                f"e9_failure_classifier {stratum_id} training and evaluation seeds must be disjoint"
            )
        partitioned_seeds.extend(training)
        partitioned_seeds.extend(evaluation)
    if len(set(partitioned_seeds)) != len(partitioned_seeds):
        raise ClaimsManifestError("e9_failure_classifier seed partitions must be globally disjoint")
    if set(partitioned_seeds) != set(seed_universe):
        raise ClaimsManifestError(
            "e9_failure_classifier seed partitions must exactly cover seed_universe"
        )
    _exact_literal(
        seed_universe,
        E9_SEED_UNIVERSE,
        "e9_failure_classifier.seed_universe",
    )
    _exact_literal(
        contract["training_seeds_by_kdf"],
        E9_TRAINING_SEEDS_BY_KDF,
        "e9_failure_classifier.training_seeds_by_kdf",
    )
    _exact_literal(
        contract["evaluation_seeds_by_kdf"],
        E9_EVALUATION_SEEDS_BY_KDF,
        "e9_failure_classifier.evaluation_seeds_by_kdf",
    )

    feature_contract = _mapping(
        contract["feature_contract"], "e9_failure_classifier.feature_contract"
    )
    _exact_keys(
        feature_contract,
        frozenset(
            {
                "visibility",
                "features",
                "formulas",
                "input_policy",
                "constant_equivalence_fields",
            }
        ),
        "e9_failure_classifier.feature_contract",
    )
    _exact_literal(
        feature_contract["visibility"],
        "EXTERNAL_CLIENT_OBSERVATIONS_ONLY",
        "e9_failure_classifier.feature_contract.visibility",
    )
    _string_list(
        feature_contract["features"],
        "e9_failure_classifier.feature_contract.features",
        allowed=frozenset(E9_EXTERNAL_FEATURES),
    )
    _exact_literal(
        feature_contract["features"],
        E9_EXTERNAL_FEATURES,
        "e9_failure_classifier.feature_contract.features",
    )
    _exact_literal(
        feature_contract["formulas"],
        E9_FEATURE_FORMULAS,
        "e9_failure_classifier.feature_contract.formulas",
    )
    _exact_literal(
        feature_contract["input_policy"],
        "MISSING_EMPTY_NONPOSITIVE_TIMING_OR_NONFINITE_FEATURE_FAILS_CLOSED",
        "e9_failure_classifier.feature_contract.input_policy",
    )
    _string_list(
        feature_contract["constant_equivalence_fields"],
        "e9_failure_classifier.feature_contract.constant_equivalence_fields",
        allowed=frozenset(E9_CONSTANT_EQUIVALENCE_FIELDS),
    )
    _exact_literal(
        feature_contract["constant_equivalence_fields"],
        E9_CONSTANT_EQUIVALENCE_FIELDS,
        "e9_failure_classifier.feature_contract.constant_equivalence_fields",
    )

    _exact_literal(
        contract["classifier"],
        {
            "family": "RIDGE_LOGISTIC_REGRESSION",
            "fit_scope": "ONE_MODEL_PER_KDF_STRATUM_AND_FAILURE_CASE_PAIR",
            "training_rows": "ALL_TRAINING_SEED_SAMPLES_FOR_PAIR",
            "pair_label_assignment": "PAIR_ORDER_ONLY",
            "scaling": {
                "fit_on": "TRAINING_SEEDS_ONLY",
                "center": "MEDIAN",
                "scale": "IQR",
                "zero_iqr_scale": 1.0,
                "quantile_definition": "N_MINUS_ONE_TIMES_P_LINEAR_INTERPOLATION",
            },
            "numeric_semantics": {
                "dtype": "IEEE754_FLOAT64",
                "objective": (
                    "MEAN_BINARY_CROSS_ENTROPY_PLUS_HALF_LAMBDA_L2_COEFFICIENT_NORM_SQUARED"
                ),
                "row_weighting": "UNIFORM_NO_CLASS_WEIGHTS_BALANCED_BY_DESIGN",
                "initialization": "ALL_ZERO_INTERCEPT_AND_COEFFICIENTS",
                "stable_log_loss": "NUMPY_LOGADDEXP",
                "sigmoid_clip": [-709.0, 709.0],
            },
            "regularization": {
                "penalty": "L2_RIDGE",
                "lambda": 0.001,
                "penalize_intercept": False,
            },
            "optimizer": {
                "implementation": "scipy.optimize.minimize",
                "method": "L-BFGS-B",
                "options": {
                    "gtol": 1.0e-8,
                    "ftol": 1.0e-12,
                    "maxiter": 1000,
                    "maxls": 50,
                },
                "maximum_gradient_infinity_norm": 1.0e-6,
                "convergence_requirement": (
                    "SCIPY_SUCCESS_STATUS_ZERO_FINITE_AND_GRADIENT_INF_LE_1E_6"
                ),
                "failure_policy": "FAIL_CLOSED",
            },
        },
        "e9_failure_classifier.classifier",
    )
    _exact_literal(
        contract["inference"],
        {
            "evaluation_rows": "EVALUATION_SEEDS_ONLY",
            "evaluation_unit": "SEED",
            "evaluation_auc": "RAW_AUC_IN_FIXED_TRAINING_LABEL_DIRECTION_PER_SEED",
            "auc_tie_handling": "AVERAGE_RANK_MANN_WHITNEY",
            "point_estimate": "MAX_MEAN_RAW_AUC_ONE_MINUS_MEAN_RAW_AUC",
            "direction_invariant_ci_upper": "MAX_RAW_CI_UPPER_ONE_MINUS_RAW_CI_LOWER",
            "per_seed_oracle_orientation_sensitivity": (
                "MEAN_PER_SEED_MAX_RAW_AUC_ONE_MINUS_RAW_AUC_NOT_PRIMARY_ESTIMAND"
            ),
            "interval_sides": "TWO_SIDED",
            "bootstrap_method": "EVALUATION_SEED_PERCENTILE",
            "confidence_level": 0.95,
            "bootstrap_replicates": 2000,
            "bootstrap_resample_size": 30,
            "bootstrap_rng": {
                "namespace": "E9-FROZEN-CLASSIFIER-EVALUATION-SEED-BOOTSTRAP-v2",
                "seed_material": ("PROFILE_CONTRACT_ID_STRATUM_ID_LEFT_CASE_RIGHT_CASE"),
                "seed_derivation": "SHA256_ASCII_FIRST_64_BITS_BIG_ENDIAN",
                "pseudorandom_sequence": "PYTHON_RANDOM_MT19937_RANDRANGE",
            },
            "percentile_definition": "N_MINUS_ONE_TIMES_P_LINEAR_INTERPOLATION",
            "gate_scope": "EVERY_KDF_STRATUM_AND_FAILURE_CASE_PAIR",
            "gate_rule": "GLOBAL_AND_PER_SEED_ORACLE_CI_UPPERS_LE_THRESHOLD",
            "gate_comparison": "LESS_THAN_OR_EQUAL",
            "auc_ci_upper_threshold": 0.55,
        },
        "e9_failure_classifier.inference",
    )
    _exact_literal(
        contract["data_integrity"],
        {
            "require_complete_case_seed_grid": True,
            "allow_missing_samples": False,
            "allow_retries": False,
            "allow_sample_level_split": False,
            "split_unit": "SEED",
        },
        "e9_failure_classifier.data_integrity",
    )
    _exact_literal(
        contract["measurement_contract"],
        E9_MEASUREMENT_CONTRACT,
        "e9_failure_classifier.measurement_contract",
    )
    _exact_literal(
        contract["diagnostics_contract"],
        E9_DIAGNOSTICS_CONTRACT,
        "e9_failure_classifier.diagnostics_contract",
    )
    power = _mapping(
        contract["prospective_power_plan"],
        "e9_failure_classifier.prospective_power_plan",
    )
    _exact_keys(
        power,
        frozenset(
            {
                "status",
                "plan_path",
                "minimum_monte_carlo_replicates",
                "confidence_level",
                "planning_estimand",
                "planning_per_gate_one_sided_alpha",
                "planning_maximum_sum_failure_probability_upper_bounds",
                "minimum_planning_dependence_robust_joint_pass_probability_lower",
                "planning_joint_binomial_interval_role",
                "boundary_estimand",
                "boundary_operating_characteristic_scope",
                "maximum_boundary_dgp_gate_pass_upper_confidence_bound",
                "result_path",
                "result_id",
            }
        ),
        "e9_failure_classifier.prospective_power_plan",
    )
    expected_power_common = {
        "plan_path": "experiments/configs/failure_timing_power.e9.yaml",
        "minimum_monte_carlo_replicates": 2000,
        "confidence_level": 0.95,
        "planning_estimand": ("DEPENDENCE_ROBUST_LOWER_BOUND_ON_PROBABILITY_ALL_20_GATES_PASS"),
        "planning_per_gate_one_sided_alpha": 0.0025,
        "planning_maximum_sum_failure_probability_upper_bounds": 0.2,
        "minimum_planning_dependence_robust_joint_pass_probability_lower": 0.8,
        "planning_joint_binomial_interval_role": "DESCRIPTIVE_NOT_THE_POWER_GATE",
        "boundary_estimand": ("DGP_CONDITIONAL_PER_GATE_PASS_PROBABILITY_AT_MEAN_RAW_AUC_0_55"),
        "boundary_operating_characteristic_scope": (
            "FROZEN_BALANCED_BINORMAL_SCORE_DGP_ONLY_NOT_DISTRIBUTION_FREE_TYPE_I_CONTROL"
        ),
        "maximum_boundary_dgp_gate_pass_upper_confidence_bound": 0.05,
    }
    for key, expected in expected_power_common.items():
        _exact_literal(power[key], expected, f"e9_failure_classifier.prospective_power_plan.{key}")
    status = power["status"]
    if status == "PENDING":
        _exact_literal(
            power["result_path"],
            None,
            "e9_failure_classifier.prospective_power_plan.result_path",
        )
        _exact_literal(
            power["result_id"],
            None,
            "e9_failure_classifier.prospective_power_plan.result_id",
        )
    elif status == "PASSED":
        _exact_literal(
            power["result_path"],
            "experiments/configs/failure_timing_power.e9.result.json",
            "e9_failure_classifier.prospective_power_plan.result_path",
        )
        result_id = _string(
            power["result_id"],
            "e9_failure_classifier.prospective_power_plan.result_id",
        )
        if re.fullmatch(r"[0-9a-f]{64}", result_id) is None:
            raise ClaimsManifestError(
                "e9_failure_classifier prospective power result_id must be a semantic ID"
            )
    else:
        raise ClaimsManifestError(
            "e9_failure_classifier prospective power status must be PENDING or PASSED"
        )
    return contract


def _validate_paper_alignment(main: Mapping[str, Any], paper_object: object) -> None:
    paper = _mapping(paper_object, "paper claims ledger")
    if _integer(paper.get("schema_version"), "paper claims schema_version") != 1:
        raise ClaimsManifestError("paper claims schema_version is unsupported")
    paper_status = _string(paper.get("paper_status"), "paper claims paper_status")
    if paper_status not in {RESEARCH_IN_PROGRESS, FROZEN}:
        raise ClaimsManifestError("paper claims paper_status is unsupported")
    if paper_status != main["status"]:
        raise ClaimsManifestError("main and paper claims statuses have drifted")
    paper_decision = _mapping(
        paper.get("REMOVED_RECURRENCE_LEARNING"),
        "paper REMOVED_RECURRENCE_LEARNING",
    )
    _exact_keys(
        paper_decision,
        frozenset({"statement", "reason", "replacement", "gate", "status"}),
        "paper REMOVED_RECURRENCE_LEARNING",
    )
    if any(
        type(main["recurrence_learning"][field]) is not type(paper_decision[field])
        or main["recurrence_learning"][field] != paper_decision[field]
        for field in paper_decision
    ):
        raise ClaimsManifestError("recurrence-learning decision has drifted from paper ledger")
    retry_decision = _mapping(
        paper.get("REMOVED_REAL_RETRY_PREVALENCE"),
        "paper REMOVED_REAL_RETRY_PREVALENCE",
    )
    if retry_decision.get("status") != "REMOVED":
        raise ClaimsManifestError("paper real-retry claim must remain REMOVED")


def _expected_service_e7_contract() -> dict[str, Any]:
    return {
        "schema": "traps-service-e7-preregistered-contract-v2",
        "freeze_status": SERVICE_E7_FREEZE_STATUS,
        "phase1_baseline_selection": {
            "path": "experiments/configs/phase1_v21_downstream_selection.yaml",
            "contract_id": ("9721fc00a36dff19d3f56727c7c41fda41dc95a0e9ecac8d49e5f002adb536c2"),
            "deployment_profile": "A",
        },
        "seeds": SERVICE_E7_SEEDS,
        "tail_latency_seed_count": 20,
        "verifier_profiles": SERVICE_E7_VERIFIER_PROFILES,
        "workload": {
            "traffic_mode": "open_loop",
            "scenarios": [
                "repeat_heavy_false_positive",
                "unique_first_seen_false_positive",
            ],
            "legitimate_rps": [16],
            "invalid_rps": [0, 32, 64, 96, 128, 192, 256, 384, 512],
            "methods": [
                "no_prescreen_v1",
                "static_frozen_screen_v1",
                "frozen_screen_exact_negative_cache_lru_singleflight_v1",
                "frozen_screen_exact_negative_cache_tinylfu_singleflight_v1",
            ],
            "false_positive_conditioning": {
                "source": "FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1",
                "underlying_filter_query_executed": True,
                "conditional_intervention_does_not_estimate_ffr": True,
                "repeat_tuple_count": 16,
                "unique_tuple_pool_size": 20_000,
            },
        },
        "measurement": {
            "warmup_seconds": 30,
            "duration_seconds": 120,
            "minimum_resource_samples": 100,
        },
        "execution": {
            "backend_workers_per_point": 4,
            "shard_unit": "COMPLETE_SEED_BLOCK",
            "maximum_concurrent_points_per_host": 1,
            "immutable_no_overwrite_checkpoints": True,
        },
        "g2_gate_contract": {
            "schema": "traps-g2-e4-e7-gate-v1",
            "candidate_method": "frozen_screen_exact_cache_lru",
            "baseline_method": "static_frozen_screen_mechanism_baseline",
            "scenario": "repeat_heavy_false_positive",
            "offered_legitimate_rps": 16,
            "offered_invalid_rps": 32,
            "verifier_profiles": [
                "pbkdf2_reference_310k",
                "argon2id_reference_19mib",
            ],
            "repeated_tuple_count": 16,
            "minimum_replay_multiplicity": 100,
            "paired_seed_count": 20,
            "latency_margin_ratio": 1.05,
            "familywise_alpha": 0.05,
            "multiplicity_adjustment": ("bonferroni_one_sided_student_t_log_ratio_v1"),
            "false_positive_source": ("FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1"),
            "underlying_filter_query_executed": True,
            "conditional_intervention_does_not_estimate_ffr": True,
        },
        "g4_capacity_contract": {
            "schema": "traps-g4-e7-backend-invalid-capacity-v1",
            "source_method": "static_frozen_screen_mechanism_baseline",
            "scenario": "repeat_heavy_false_positive",
            "offered_legitimate_rps": 16,
            "verifier_profiles": [
                "pbkdf2_reference_310k",
                "argon2id_reference_19mib",
            ],
            "paired_seed_count": 20,
            "per_seed_safe_point_rule": (
                "HIGHEST_POSITIVE_INVALID_GRID_POINT_PASSING_SATURATION_CRITERIA"
            ),
            "per_seed_estimand": ("observed_invalid_backend_checks_per_second_at_safe_point"),
            "familywise_alpha": 0.05,
            "multiplicity_adjustment": (
                "bonferroni_one_sided_student_t_log_capacity_over_2_profiles_v1"
            ),
            "cross_profile_capacity_rule": ("MINIMUM_SIMULTANEOUS_PROFILE_LOWER_BOUND"),
            "offered_rate_planning_formula": ("floor(min_capacity/(1.25*epsilon_cap))"),
            "safety_factor": 1.25,
            "epsilon_authority": "PHASE1_REGISTERED_CONSERVATIVE_FFR_CI_UPPER",
        },
        "g5_gate_contract": {
            "schema": "traps-g5-e7-formal-gate-v2",
            "candidate_method": "frozen_screen_exact_cache_lru",
            "matched_baseline_method": "static_frozen_screen_mechanism_baseline",
            "scenario": "repeat_heavy_false_positive",
            "verifier_profiles": [
                "pbkdf2_reference_310k",
                "argon2id_reference_19mib",
            ],
            "paired_seed_count": 20,
            "offered_legitimate_rps": 16,
            "offered_invalid_rps_grid": [
                0,
                32,
                64,
                96,
                128,
                192,
                256,
                384,
                512,
            ],
            "operational_safe_point_rule": (
                "VALID_TIMEOUT_QUEUE_DROP_AND_LEGITIMATE_THROUGHPUT_ONLY_V1"
            ),
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
            "p99_multiplicity_adjustment": (
                "bonferroni_one_sided_student_t_log_ratio_over_2_profiles_v1"
            ),
            "resource_gate": ("COMBINED_PROCESS_ENVELOPE_AND_CONFIGURED_HARD_BOUNDS_V2"),
            "resource_bounds": {
                "process_scope": "COMBINED_BENCHMARK_PROCESS_ENVELOPES_FRONTEND",
                "maximum_process_rss_peak_bytes": 2_147_483_648,
                "rss_window_fraction_numerator": 1,
                "rss_window_fraction_denominator": 10,
                "minimum_resource_samples": 100,
                "maximum_late_minus_early_rss_mean_bytes": 268_435_456,
                "queue_connection_padding_limits_source": ("SERVICE_CONFIG_HARD_CAPS"),
                "waiter_limits_source": "SERVICE_CONFIG_HARD_CAPS",
                "cache_limits_source": "SERVICE_CONFIG_HARD_CAPS",
                "final_state_rule": "ALL_ZERO_AFTER_SHUTDOWN",
                "missing_data_policy": "INDETERMINATE_NO_PROMOTION",
                "threshold_exceedance_policy": "VALID_FAIL",
            },
            "unique_first_seen_role": "REPORT_ONLY_DOES_NOT_CONTROL_PASS",
            "missing_endpoint_policy": "INDETERMINATE_NO_POSTHOC_GRID_EXTENSION",
        },
    }


def _validate_service_e7_contract(value: object) -> dict[str, Any]:
    contract = _mapping(value, "service_e7_contract")
    expected = _expected_service_e7_contract()
    _exact_literal(contract, expected, "service_e7_contract")
    return contract


def validate_main_claims_manifest(
    manifest_object: object, paper_claims_object: object
) -> dict[str, Any]:
    """Validate the complete main manifest and its paper-ledger decisions."""

    manifest = _mapping(manifest_object, "main claims manifest")
    _exact_keys(manifest, ROOT_KEYS, "main claims manifest")
    if _integer(manifest["schema_version"], "main claims schema_version") != 1:
        raise ClaimsManifestError("main claims schema_version is unsupported")
    status = _string(manifest["status"], "main claims status")
    if status not in {RESEARCH_IN_PROGRESS, FROZEN}:
        raise ClaimsManifestError("main claims status is unsupported")

    seeds = _uint64_list(manifest["seeds"], "main claims seeds")
    _string_list(manifest["datasets"], "main claims datasets", allowed=ALLOWED_DATASETS)
    _string_list(
        manifest["deployment_profiles"],
        "main claims deployment_profiles",
        allowed=ALLOWED_DEPLOYMENT_PROFILES,
    )
    _string_list(
        manifest["state_exposure_profiles"],
        "main claims state_exposure_profiles",
        allowed=ALLOWED_STATE_EXPOSURE_PROFILES,
    )
    windows = [
        _string(manifest[field], f"main claims {field}")
        for field in ("train_window", "validation_window", "test_window")
    ]
    if any(window not in ALLOWED_WINDOWS for window in windows) or len(set(windows)) != 3:
        raise ClaimsManifestError("main claims train/validation/test windows are invalid")

    _integer_grid(
        manifest["memory_budgets_bits_per_account"],
        "main claims memory_budgets_bits_per_account",
        minimum=1,
    )
    _integer_grid(
        manifest["frontend_latency_budgets_us"],
        "main claims frontend_latency_budgets_us",
        minimum=1,
    )
    _integer_grid(manifest["region_counts"], "main claims region_counts", minimum=1)
    _descending_float_grid(manifest["epsilon_caps"], "main claims epsilon_caps")
    _integer_grid(
        manifest["compromise_work_targets"],
        "main claims compromise_work_targets",
        minimum=1,
    )
    _integer_grid(manifest["cache_sizes_bytes"], "main claims cache_sizes_bytes", minimum=0)
    cache_policies = _string_list(
        manifest["cache_policies"],
        "main claims cache_policies",
        allowed=ALLOWED_CACHE_POLICIES,
    )
    if "learned_recurrence" in cache_policies:
        raise ClaimsManifestError("learned_recurrence cannot be an active cache policy")

    recurrence = _mapping(manifest["recurrence_learning"], "recurrence_learning")
    _exact_keys(
        recurrence,
        frozenset({"statement", "reason", "replacement", "gate", "status"}),
        "recurrence_learning",
    )
    for field in ("statement", "reason", "replacement", "gate", "status"):
        _string(recurrence[field], f"recurrence_learning.{field}")
    if recurrence["gate"] != "G3" or recurrence["status"] != "REMOVED":
        raise ClaimsManifestError("recurrence learning must remain REMOVED at gate G3")

    _string_list(
        manifest["attack_scenarios"],
        "main claims attack_scenarios",
        allowed=ALLOWED_ATTACK_SCENARIOS,
    )
    verifier_profiles = _string_list(
        manifest["verifier_profiles"],
        "main claims verifier_profiles",
        allowed=ALLOWED_VERIFIER_PROFILES,
    )
    _validate_verifier_profile_specs(manifest["verifier_profile_specs"], status, verifier_profiles)
    hardware = _string(manifest["hardware_profile"], "main claims hardware_profile")
    if hardware not in ALLOWED_HARDWARE_PROFILES:
        raise ClaimsManifestError("main claims hardware_profile is unsupported")

    measurement = _mapping(manifest["measurement"], "main claims measurement")
    _exact_keys(
        measurement,
        frozenset(
            {
                "minimum_independent_seeds",
                "tail_latency_seeds",
                "confidence_level",
                "traffic_mode",
                "warmup_seconds",
                "measurement_seconds",
                "report_raw_rows",
            }
        ),
        "main claims measurement",
    )
    minimum_seeds = _integer(
        measurement["minimum_independent_seeds"],
        "measurement.minimum_independent_seeds",
        minimum=1,
    )
    tail_seeds = _integer(
        measurement["tail_latency_seeds"],
        "measurement.tail_latency_seeds",
        minimum=1,
    )
    if minimum_seeds > tail_seeds or tail_seeds > len(seeds):
        raise ClaimsManifestError("measurement seed requirements exceed the manifest seed grid")
    _finite_float(
        measurement["confidence_level"],
        "measurement.confidence_level",
        minimum_exclusive=0.0,
        maximum=1.0,
    )
    if measurement["confidence_level"] == 1.0:
        raise ClaimsManifestError("measurement.confidence_level must be less than 1")
    if measurement["traffic_mode"] != "open_loop":
        raise ClaimsManifestError("measurement.traffic_mode must be open_loop")
    _integer(measurement["warmup_seconds"], "measurement.warmup_seconds", minimum=1)
    _integer(measurement["measurement_seconds"], "measurement.measurement_seconds", minimum=1)
    if measurement["report_raw_rows"] is not True:
        raise ClaimsManifestError("measurement.report_raw_rows must be Boolean true")

    evidence = _mapping(manifest["evidence_scope"], "main claims evidence_scope")
    _exact_keys(
        evidence,
        frozenset(
            {
                "real_user_retry_prevalence",
                "synthetic_results_are_controlled_stress_tests",
            }
        ),
        "main claims evidence_scope",
    )
    if evidence["real_user_retry_prevalence"] != "REMOVED_PENDING_GOVERNED_TRACE":
        raise ClaimsManifestError("real-user retry prevalence must remain removed")
    if evidence["synthetic_results_are_controlled_stress_tests"] is not True:
        raise ClaimsManifestError("synthetic results must remain controlled stress tests")

    _validate_service_e7_contract(manifest["service_e7_contract"])
    _validate_e9_failure_classifier(manifest["e9_failure_classifier"])
    _validate_paper_alignment(manifest, paper_claims_object)
    return manifest


def canonical_manifest_id(manifest: Mapping[str, Any]) -> str:
    """Return the content ID of an already strictly validated manifest."""

    try:
        encoded = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise ClaimsManifestError("manifest is not canonical JSON data") from exc
    return MANIFEST_ID_PREFIX + hashlib.sha256(encoded).hexdigest()


def load_main_claims_manifest(
    path: Path = DEFAULT_MAIN_CLAIMS_PATH,
    *,
    paper_claims_path: Path = DEFAULT_PAPER_CLAIMS_PATH,
) -> tuple[dict[str, Any], str]:
    """Load, strictly validate, and identify the main claims manifest."""

    manifest = load_unique_yaml(path, label="main claims manifest")
    paper_claims = load_unique_yaml(paper_claims_path, label="paper claims ledger")
    validated = validate_main_claims_manifest(manifest, paper_claims)
    return validated, canonical_manifest_id(validated)


def load_main_claims_manifest_for_id(
    expected_manifest_id: str,
    *,
    current_path: Path = DEFAULT_MAIN_CLAIMS_PATH,
    historical_e9_path: Path = HISTORICAL_E9_MAIN_CLAIMS_PATH,
    paper_claims_path: Path = DEFAULT_PAPER_CLAIMS_PATH,
) -> tuple[dict[str, Any], str]:
    """Resolve the current manifest or the immutable historical E9 authority by ID."""

    current, current_id = load_main_claims_manifest(
        current_path,
        paper_claims_path=paper_claims_path,
    )
    if expected_manifest_id == current_id:
        return current, current_id
    if expected_manifest_id != HISTORICAL_E9_MANIFEST_ID:
        raise ClaimsManifestError("requested claims-manifest ID is not registered")

    historical_object = load_unique_yaml(
        historical_e9_path,
        label="historical E9 main claims manifest",
    )
    historical = _mapping(historical_object, "historical E9 main claims manifest")
    legacy_keys = ROOT_KEYS - {"service_e7_contract"}
    _exact_keys(historical, legacy_keys, "historical E9 main claims manifest")
    augmented = dict(historical)
    augmented["service_e7_contract"] = _expected_service_e7_contract()
    paper_claims = load_unique_yaml(paper_claims_path, label="paper claims ledger")
    historical_paper = json.loads(json.dumps(paper_claims))
    historical_paper["paper_status"] = historical["status"]
    validate_main_claims_manifest(augmented, historical_paper)
    historical_id = canonical_manifest_id(historical)
    if historical_id != HISTORICAL_E9_MANIFEST_ID:
        raise ClaimsManifestError("historical E9 main-claims identity changed")
    return historical, historical_id
