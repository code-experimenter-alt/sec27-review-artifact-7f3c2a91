#!/usr/bin/env python3
"""Collect and independently analyze E9 failure timing over loopback TCP.

The raw producer exercises the executable reference data plane behind a real
IPv4 loopback TCP server.  The consumer derives labels from a frozen schedule,
checks the byte-level protocol, and recomputes every statistic from raw samples.
Successful authentication is retained as a functional check but is never an
input to a failure-path classifier.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib
import importlib.metadata
import io
import json
import math
import os
import platform
import random
import re
import secrets
import socket
import ssl
import stat
import struct
import subprocess
import sys
import sysconfig
import threading
import time
import zipfile
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse
from urllib.request import url2pathname

_SEALED_CHILD_MODE = (
    os.environ.get("TRAPS_E9_SEALED_CHILD_MODE") == "SEALED_MEMFD_ZIPAPP_V1"
    and sys.argv[0].startswith("/proc/self/fd/")
)
if _SEALED_CHILD_MODE:
    sealed_source_root = os.environ.get("TRAPS_E9_SEALED_SOURCE_ROOT")
    if not sealed_source_root:
        raise RuntimeError("sealed E9 child lacks its source-root binding")
    ROOT = Path(sealed_source_root).resolve(strict=True)
else:
    ROOT = Path(__file__).resolve().parents[2]
if not _SEALED_CHILD_MODE and str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controlplane import ActivationStateMachine  # noqa: E402
from dataplane import (  # noqa: E402
    AuthDataPlane,
    AuthRoute,
    BackendResultKind,
    Directory,
    InMemoryBackend,
    NegativeCache,
    NegativeKeyDeriver,
    PositiveDecision,
    PositiveDisposition,
    PositiveScreen,
    Singleflight,
    TinyLfuPolicy,
)
from dataplane.crypto import exact_password_bytes  # noqa: E402

CONFIG_SCHEMA = "traps-e9-failure-timing-config-v4"
PREREGISTERED_CONFIG_SCHEMA = (
    "traps-e9-failure-timing-config-v5-preregistered-clean-run"
)
RAW_SCHEMA = "traps-e9-failure-timing-raw-v6"
SAMPLE_SCHEMA = "traps-e9-failure-timing-sample-v2"
ANALYSIS_SCHEMA = "traps-e9-failure-timing-analysis-v5"
REGISTRY_IDENTITY_SCHEMA = "traps-e9-replay-registry-identity-v1"
REGISTRY_IDENTITY_FILENAME = "registry.identity.json"
REGISTRY_STORAGE_CONTRACT = "AUDITOR_CONTROLLED_APPEND_ONLY_NONROLLBACK_V1"
HOST_CONTRACT_SCHEMA = "traps-e9-host-execution-contract-v4"
HOST_ATTESTATION_SCHEMA = "traps-e9-host-execution-attestation-v2"
EXCLUSIVE_LOCK_CONTRACT_SCHEMA = "traps-e9-exclusive-lock-contract-v2"
FORMAL_LOCK_SCHEMA = "traps-e9-exclusive-host-lock-v3"
FORMAL_EXECUTION_SCHEMA = "traps-e9-formal-execution-binding-v4"
PREREGISTERED_FORMAL_EXECUTION_SCHEMA = (
    "traps-e9-formal-execution-binding-v5-preregistered-clean-run"
)
PREREGISTERED_AUTHORIZATION_SCHEMA = (
    "traps-e9-preregistered-clean-run-authorization-v1"
)
FORMAL_CONTRACT_SCHEMA = "traps-e9-formal-contract-v4"
FRESHNESS_CHALLENGE_SCHEMA = "traps-e9-freshness-challenge-v2"
FORMAL_LOCK_RETENTION_SCOPE = (
    "SIGNED_RAW_CONSTRUCTION_VALIDATION_AND_EXCLUSIVE_PUBLICATION"
)
LOCK_FILESYSTEM_POLICY = "LOCAL_FILESYSTEM_ONLY_NETWORK_AND_CLOUD_SYNC_FORBIDDEN_V1"
POSIX_LOCK_API = "POSIX_FLOCK_LOCK_EX_LOCK_NB_WHOLE_FILE_V1"
WINDOWS_LOCK_API = "WINDOWS_LOCKFILEEX_EXCLUSIVE_FAIL_IMMEDIATELY_RANGE_V1"
LOCK_UNIQUENESS_PRIMITIVE = "SIGNED_PREPROVISIONED_ANCHOR_OS_ADVISORY_LOCK_V1"
LOCK_MARKER_ROLE = "DURABLE_AUDIT_AND_CRASH_REUSE_BLOCKER_NOT_UNIQUENESS_PRIMITIVE"
LOCK_ANCHOR_BYTE_COUNT = 32


class _WindowsOverlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", ctypes.c_uint32),
        ("OffsetHigh", ctypes.c_uint32),
        ("hEvent", ctypes.c_void_p),
    ]
PROCESS_ISOLATION_DECLARATION = {
    "mode": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_REUSE",
    "fresh_os_process_per_seed": True,
    "formal_status": "SMOKE_IMPLEMENTED_LINUX_FORMAL_SCALE_LONG_TEST_PENDING",
}
PROCESS_ISOLATION_BLOCKER = "FRESH_OS_PROCESS_PER_SEED_LINUX_FORMAL_SCALE_LONG_TEST_PENDING"
EXTERNAL_POWER_BLOCKER = "EXTERNAL_POWER_ATTESTATION_NOT_RUNTIME_VERIFIED"
ARTIFACT_PRIVACY_BLOCKER = (
    "HOST_EXECUTION_ARTIFACT_PUBLICATION_REQUIRES_AUDITOR_PRIVACY_APPROVAL"
)
FORMAL_BLOCKERS = (
    "AUDITOR_SIGNED_HOST_EXECUTION_CONTRACT_AND_FRESH_CHALLENGE_REQUIRED",
    PROCESS_ISOLATION_BLOCKER,
    ARTIFACT_PRIVACY_BLOCKER,
)
PREREGISTERED_FORMAL_CONTRACT = (
    "CLEAN_COMMIT_OPERATOR_ASSERTIONS_POST_RUN_INDEPENDENT_AUDIT_V1"
)
PREREGISTERED_FORMAL_BLOCKER = "INDEPENDENT_POST_RUN_AUDIT_REQUIRED"
PREREGISTERED_ASSERTION_CLASS = (
    "SELF_REPORTED_OPERATOR_ASSERTIONS_NOT_EXTERNAL_ATTESTATION"
)
PREREGISTERED_AUDIT_REQUIREMENT = "POST_RUN_INDEPENDENT_AUDIT_REQUIRED"
PREREGISTERED_PRODUCTION_ARCHITECTURE = "x86_64"
PREREGISTERED_ARGON2_ALGORITHM_VERSION = 19
PREREGISTERED_MEASUREMENT_ENVIRONMENT_SCHEMA = (
    "traps-e9-preregistered-measurement-environment-v1"
)
SEED_CHILD_MEASUREMENT_ENVIRONMENT_SCHEMA = (
    "traps-e9-seed-child-measurement-environment-v2"
)
SEED_CHILD_REQUEST_SCHEMA = "traps-e9-seed-child-request-v1"
SEED_CHILD_RESULT_SCHEMA = "traps-e9-seed-child-result-v2"
PROCESS_LONG_TEST_CONFIG_SCHEMA = "traps-e9-linux-process-long-test-config-v1"
PROCESS_LONG_TEST_RECEIPT_SCHEMA = "traps-e9-linux-process-long-test-receipt-v1"
PROCESS_LONG_TEST_SOURCE_SCHEMA = "traps-e9-tracked-source-snapshot-v1"
PROCESS_LONG_TEST_ARCHIVE_SCHEMA = "traps-e9-sealed-source-archive-v1"
PROCESS_LONG_TEST_PROFILE_NAME = "linux_process_long_test"
PROCESS_LONG_TEST_EVIDENCE_CLASS = "NON_EVIDENCE_PROCESS_ISOLATION_QUALIFICATION"
PROCESS_LONG_TEST_QUALIFICATION_ID = "e9-linux-process-isolation-formal-scale-v1"
PROCESS_LONG_TEST_AUTHENTICATION = "NONE"
PROCESS_LONG_TEST_BLOCKER_EFFECT = (
    "NO_BLOCKER_DISPOSITION_WITHOUT_EXTERNAL_TRUSTED_IMMUTABLE_EXECUTION_WITNESS_AND_REVIEW"
)
PROCESS_LONG_TEST_REVIEW_STATUS = (
    "EXTERNAL_TRUSTED_IMMUTABLE_EXECUTION_WITNESS_AND_REVIEW_REQUIRED"
)
PROCESS_LONG_TEST_ARCHIVE_MAX_BYTES = 64 * 1024 * 1024
PROCESS_LONG_TEST_ARCHIVE_SEAL_MASK = 0x0001 | 0x0002 | 0x0004 | 0x0008
PROCESS_LONG_TEST_ARCHIVE_EXECUTION = "LINUX_MEMFD_SEALED_ZIPAPP_V1"
PROCESS_LONG_TEST_ARCHIVE_MODULE = "_traps_e9_seed_child.py"
PROCESS_LONG_TEST_ARCHIVE_MAIN = (
    "from _traps_e9_seed_child import _seed_child_main\n"
    "raise SystemExit(_seed_child_main())\n"
).encode("ascii")
PROCESS_LONG_TEST_SEEDS = tuple(range(9300, 9320))
PROCESS_LONG_TEST_LIMITATIONS = (
    "CI_OR_MOCK_EXECUTION_MUST_NOT_REMOVE_THE_FORMAL_PROCESS_ISOLATION_BLOCKER",
    "ONLY_ONE_UNINTERRUPTED_FULL_LINUX_CLEAN_COMMIT_NO_RETRY_RUN_MAY_BE_SUBMITTED_FOR_"
    "INDEPENDENT_BLOCKER_REVIEW",
    "UNSIGNED_NON_EVIDENCE_RECEIPT_DOES_NOT_AUTHORIZE_OR_COLLECT_FORMAL_E9_EVIDENCE",
    "RECEIPT_ID_IS_AN_INTEGRITY_DIGEST_NOT_AUTHENTICATION_AND_VALIDATION_ALONE_MUST_NOT_"
    "CHANGE_ANY_FORMAL_BLOCKER_OR_CLAIM",
    "EXTERNAL_TRUSTED_WITNESS_MUST_ENFORCE_EXECUTED_TRACKED_BYTES_IMMUTABLE_ACROSS_"
    "CHILD_IMPORT_AND_WORKLOAD_AND_BIND_INVOCATION_COMMIT_AND_RECEIPT_DIGEST",
    "CHILD_CODE_EXECUTES_FROM_A_COMMIT_BOUND_WRITE_GROW_SHRINK_AND_SEAL_LOCKED_MEMFD_"
    "ZIPAPP_NOT_FROM_THE_MUTABLE_WORKTREE",
    "TRACKED_TREE_CHECKS_DETECT_ORDINARY_WORKTREE_MUTATION_WHILE_EXTERNAL_WITNESSING_"
    "REMAINS_REQUIRED_FOR_A_MALICIOUS_SAME_USER_REPOSITORY_RACE",
)
SEED_CHILD_REQUEST_MAX_BYTES = 64 * 1024
SEED_CHILD_RESULT_MAX_BYTES = 64 * 1024 * 1024
SEED_CHILD_STDERR_MAX_BYTES = 64 * 1024
SEED_CHILD_TERMINATE_GRACE_SECONDS = 2.0
SEED_CHILD_MAX_TIMEOUT_SECONDS = 6 * 60 * 60.0
FAILURE_CASES = (
    "unknown_username",
    "positive_screen_negative",
    "negative_cache_hit",
    "backend_mismatch",
    "transient_backend_failure",
)
FUNCTIONAL_CASES = ("valid_password",)
ALL_CASES = FAILURE_CASES + FUNCTIONAL_CASES
CASE_CODES = {case: index + 1 for index, case in enumerate(ALL_CASES)}
CODE_CASES = {value: key for key, value in CASE_CODES.items()}
FORMAL_SEEDS = tuple(range(9200, 9220))
PREREGISTERED_PBKDF2_STRATUM_ID = "pbkdf2_hmac_sha256_310000_dklen32"
PREREGISTERED_ARGON2_STRATUM_ID = "argon2id_m19456_t2_p1_h32"
PREREGISTERED_KDF_STRATUM_IDS = (
    PREREGISTERED_PBKDF2_STRATUM_ID,
    PREREGISTERED_ARGON2_STRATUM_ID,
)
PREREGISTERED_KDF_WORKLOADS = {
    PREREGISTERED_PBKDF2_STRATUM_ID: {
        "algorithm": "pbkdf2_hmac_sha256",
        "iterations": 310000,
        "dklen": 32,
    },
    PREREGISTERED_ARGON2_STRATUM_ID: {
        "algorithm": "argon2id",
        "version": PREREGISTERED_ARGON2_ALGORITHM_VERSION,
        "memory_kib": 19456,
        "time_cost": 2,
        "parallelism": 1,
        "hash_len": 32,
    },
}
PREREGISTERED_TRAINING_SEEDS_BY_KDF = {
    PREREGISTERED_PBKDF2_STRATUM_ID: tuple(range(9400, 9410)),
    PREREGISTERED_ARGON2_STRATUM_ID: tuple(range(9410, 9420)),
}
PREREGISTERED_EVALUATION_SEEDS_BY_KDF = {
    PREREGISTERED_PBKDF2_STRATUM_ID: tuple(range(9420, 9450)),
    PREREGISTERED_ARGON2_STRATUM_ID: tuple(range(9450, 9480)),
}
PREREGISTERED_FORMAL_SEEDS = tuple(
    seed
    for split in (
        PREREGISTERED_TRAINING_SEEDS_BY_KDF,
        PREREGISTERED_EVALUATION_SEEDS_BY_KDF,
    )
    for stratum_id in PREREGISTERED_KDF_STRATUM_IDS
    for seed in split[stratum_id]
)
PREREGISTERED_SEED_WORKLOAD_MAPPING = {
    str(seed): stratum_id
    for split in (
        PREREGISTERED_TRAINING_SEEDS_BY_KDF,
        PREREGISTERED_EVALUATION_SEEDS_BY_KDF,
    )
    for stratum_id in PREREGISTERED_KDF_STRATUM_IDS
    for seed in split[stratum_id]
}
SMOKE_SEEDS = (9900, 9901)
EDGE_ID = "edge-e9"
REQUEST_MAGIC = b"E9RQ"
REQUEST_VERSION = 1
REQUEST_STRUCT = struct.Struct("!4sBBQI32s60s")
FRAME_TYPES = {"status": 1, "body": 2, "end": 3}
FRAME_NAMES = {value: key for key, value in FRAME_TYPES.items()}
FAILURE_STATUS = 401
FAILURE_BODY = b"authentication failed"
VALID_STATUS = 200
VALID_BODY = b"authenticated"
END_BODY = b"close"
EXPECTED_ROUTES = {
    "unknown_username": (AuthRoute.FAIL_OPEN_BACKEND.value, BackendResultKind.NO_ACCOUNT.value, 1),
    "positive_screen_negative": (AuthRoute.POSITIVE_SCREEN_REJECT.value, None, 0),
    "negative_cache_hit": (AuthRoute.NEGATIVE_CACHE_REJECT.value, None, 0),
    "backend_mismatch": (
        AuthRoute.BACKEND_DENY.value,
        BackendResultKind.CREDENTIAL_MISMATCH.value,
        1,
    ),
    "transient_backend_failure": (
        AuthRoute.FAIL_OPEN_BACKEND.value,
        BackendResultKind.TRANSIENT_FAILURE.value,
        1,
    ),
    "valid_password": (AuthRoute.BACKEND_MATCH.value, BackendResultKind.MATCH.value, 1),
}
TRANSIENT_FAILURE_SCOPE = "PRE_VERIFIER_PRE_KDF_TYPED_TRANSIENT_BACKEND_RESULT"
PREREGISTERED_PATH_CONTRACTS = {
    "unknown_username": {
        "precondition": "DIRECTORY_MISS_WITH_DUMMY_NO_ACCOUNT_VERIFIER_PATH",
        "route": AuthRoute.FAIL_OPEN_BACKEND.value,
        "accepted": False,
        "backend_kind": BackendResultKind.NO_ACCOUNT.value,
        "backend_calls": 1,
        "kdf_calls": 1,
        "cache_hits": 0,
        "screen_negatives": 0,
        "response_status": FAILURE_STATUS,
        "response_body": FAILURE_BODY.decode("ascii"),
    },
    "positive_screen_negative": {
        "precondition": "KNOWN_ACCOUNT_POSITIVE_SCREEN_NEGATIVE",
        "route": AuthRoute.POSITIVE_SCREEN_REJECT.value,
        "accepted": False,
        "backend_kind": None,
        "backend_calls": 0,
        "kdf_calls": 0,
        "cache_hits": 0,
        "screen_negatives": 1,
        "response_status": FAILURE_STATUS,
        "response_body": FAILURE_BODY.decode("ascii"),
    },
    "negative_cache_hit": {
        "precondition": "KNOWN_ACCOUNT_PREWARMED_EXACT_NEGATIVE_CACHE_HIT",
        "route": AuthRoute.NEGATIVE_CACHE_REJECT.value,
        "accepted": False,
        "backend_kind": None,
        "backend_calls": 0,
        "kdf_calls": 0,
        "cache_hits": 1,
        "screen_negatives": 0,
        "response_status": FAILURE_STATUS,
        "response_body": FAILURE_BODY.decode("ascii"),
    },
    "backend_mismatch": {
        "precondition": "KNOWN_ACCOUNT_POSITIVE_SCREEN_BACKEND_CREDENTIAL_MISMATCH",
        "route": AuthRoute.BACKEND_DENY.value,
        "accepted": False,
        "backend_kind": BackendResultKind.CREDENTIAL_MISMATCH.value,
        "backend_calls": 1,
        "kdf_calls": 1,
        "cache_hits": 0,
        "screen_negatives": 1,
        "response_status": FAILURE_STATUS,
        "response_body": FAILURE_BODY.decode("ascii"),
    },
    "transient_backend_failure": {
        "precondition": "KNOWN_ACCOUNT_PRE_VERIFIER_TYPED_TRANSIENT_BACKEND_RESULT",
        "route": AuthRoute.FAIL_OPEN_BACKEND.value,
        "accepted": False,
        "backend_kind": BackendResultKind.TRANSIENT_FAILURE.value,
        "backend_calls": 1,
        "kdf_calls": 0,
        "cache_hits": 0,
        "screen_negatives": 1,
        "response_status": FAILURE_STATUS,
        "response_body": FAILURE_BODY.decode("ascii"),
    },
    "valid_password": {
        "precondition": "KNOWN_ACCOUNT_CORRECT_PASSWORD",
        "route": AuthRoute.BACKEND_MATCH.value,
        "accepted": True,
        "backend_kind": BackendResultKind.MATCH.value,
        "backend_calls": 1,
        "kdf_calls": 1,
        "cache_hits": 0,
        "screen_negatives": 0,
        "response_status": VALID_STATUS,
        "response_body": VALID_BODY.decode("ascii"),
    },
}
CLASSIFIER_FEATURE_NAMES = (
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
)
CLASSIFIER_FEATURE_FORMULAS = {
    "log1p_connect_ns": "log1p(timing.connect_ns)",
    "log1p_request_to_first_byte_ns": "log1p(timing.request_to_first_byte_ns)",
    "log1p_request_to_eof_ns": "log1p(timing.request_to_eof_ns)",
    "log1p_connect_start_to_eof_ns": "log1p(timing.connect_start_to_eof_ns)",
    "receive_call_count": "len(response.receive_call_sizes)",
    "receive_first_chunk_bytes": "response.receive_call_sizes[0]",
    "receive_last_chunk_bytes": "response.receive_call_sizes[-1]",
    "receive_min_chunk_bytes": "min(response.receive_call_sizes)",
    "receive_max_chunk_bytes": "max(response.receive_call_sizes)",
    "receive_order_weighted_bytes": (
        "sum((index+1)*bytes for index,bytes in receive_call_sizes)"
    ),
    "local_port": "connection.local_port",
    "peer_port": "connection.peer_port",
}
FROZEN_CLASSIFIER_CONTRACT = {
    "model": "RIDGE_LOGISTIC_REGRESSION",
    "feature_names": list(CLASSIFIER_FEATURE_NAMES),
    "feature_transform": "LOG1P_TIMINGS_IDENTITY_OTHER_FEATURES",
    "standardization": "TRAINING_MEDIAN_IQR_ZERO_IQR_UNIT",
    "quantile_definition": "N_MINUS_ONE_TIMES_P_LINEAR_INTERPOLATION",
    "numeric_dtype": "IEEE754_FLOAT64",
    "objective": "MEAN_BINARY_CROSS_ENTROPY_PLUS_HALF_LAMBDA_L2_COEFFICIENT_NORM_SQUARED",
    "row_weighting": "UNIFORM_NO_CLASS_WEIGHTS_BALANCED_BY_DESIGN",
    "initialization": "ALL_ZERO_INTERCEPT_AND_COEFFICIENTS",
    "stable_log_loss": "NUMPY_LOGADDEXP",
    "sigmoid_clip": [-709.0, 709.0],
    "l2_penalty": 0.001,
    "intercept_penalized": False,
    "solver": "SCIPY_L_BFGS_B",
    "gradient_tolerance": 1e-8,
    "function_tolerance": 1e-12,
    "convergence_gradient_inf_max": 1e-6,
    "max_iterations": 1000,
    "max_line_search_steps": 50,
    "convergence_gate": "SCIPY_SUCCESS_STATUS_ZERO_FINITE_AND_GRADIENT_INF_LE_1E_6",
    "training_scope": "PER_KDF_AND_FAILURE_PAIR_TRAINING_SEEDS_ONLY",
    "evaluation_scope": "FROZEN_MODEL_PER_EVALUATION_SEED",
    "decision_score": "STANDARDIZED_LINEAR_LOG_ODDS",
}
PREREGISTERED_SAMPLING_SCHEDULE_CONTRACT = {
    "unit": "WITHIN_SEED_COMPLETE_CASE_ORDINAL_GRID",
    "case_blocking": False,
    "shuffle": "PYTHON_RANDOM_FISHER_YATES",
    "seed_derivation": "SHA256_ASCII_E9_SCHEDULE_V1_SEED_FIRST_64_BITS_BIG_ENDIAN",
    "label_order": "ALL_CASES_DECLARED_ORDER_THEN_ORDINAL_BEFORE_SHUFFLE",
    "record_schedule_index": True,
}
PREREGISTERED_DIAGNOSTICS_CONTRACT = {
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


class EvidenceError(ValueError):
    """Raised when a configuration or artifact violates the frozen contract."""


def _load_unique_yaml(text: str) -> object:
    try:
        import yaml
    except ImportError as exc:
        raise EvidenceError("loading the E9 configuration requires PyYAML") from exc

    class UniqueKeyLoader(yaml.SafeLoader):
        pass

    def construct_unique_mapping(
        loader: UniqueKeyLoader,
        node: yaml.MappingNode,
        deep: bool = False,
    ) -> dict[object, object]:
        result: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            try:
                duplicate = key in result
            except TypeError as exc:
                raise EvidenceError("YAML mapping keys must be hashable") from exc
            if duplicate:
                raise EvidenceError(f"duplicate YAML mapping key {key!r}")
            result[key] = loader.construct_object(value_node, deep=deep)
        return result

    UniqueKeyLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_unique_mapping,
    )
    try:
        return yaml.load(text, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise EvidenceError(f"cannot parse strict E9 YAML: {exc}") from exc


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise EvidenceError(f"non-finite JSON constant {value!r}")


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot load strict JSON {path}: {exc}") from exc
    return _mapping(value, str(path))


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _decode_canonical_json(payload: bytes, label: str, maximum_bytes: int) -> dict[str, Any]:
    if not payload:
        raise EvidenceError(f"{label} is empty")
    if len(payload) > maximum_bytes:
        raise EvidenceError(f"{label} exceeds its byte limit")
    try:
        decoded = payload.decode("ascii")
        value = json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"{label} is not strict ASCII JSON: {exc}") from exc
    if payload != _canonical(value):
        raise EvidenceError(f"{label} is not one strict canonical JSON document")
    return _mapping(value, label)


def _identity(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise EvidenceError(f"{label} must be a string-keyed object")
    return value


def _exact_keys(value: Mapping[str, object], keys: set[str], label: str) -> None:
    actual = set(value)
    if actual != keys:
        raise EvidenceError(
            f"{label} keys differ: missing={sorted(keys - actual)}, "
            f"unexpected={sorted(actual - keys)}"
        )


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise EvidenceError(f"{label} must be an integer >= {minimum}")
    return value


def _number(value: object, label: str, minimum: float = 0.0) -> float:
    if type(value) not in {int, float}:
        raise EvidenceError(f"{label} must be numeric")
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < minimum:
        raise EvidenceError(f"{label} must be finite and >= {minimum}")
    return normalized


def _full_commit(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 40
        and all(character in "0123456789abcdef" for character in value)
    )


def _exact_value(actual: object, expected: object, label: str) -> None:
    if type(actual) is not type(expected):
        raise EvidenceError(f"{label} type differs")
    if isinstance(expected, dict):
        _exact_keys(actual, set(expected), label)  # type: ignore[arg-type]
        for key, expected_value in expected.items():
            _exact_value(actual[key], expected_value, f"{label}.{key}")  # type: ignore[index]
        return
    if isinstance(expected, list):
        if len(actual) != len(expected):  # type: ignore[arg-type]
            raise EvidenceError(f"{label} length differs")
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):  # type: ignore[arg-type]
            _exact_value(left, right, f"{label}[{index}]")
        return
    if isinstance(expected, float):
        if not math.isfinite(actual) or actual != expected:  # type: ignore[arg-type]
            raise EvidenceError(f"{label} differs")
        return
    if actual != expected:
        raise EvidenceError(f"{label} differs")


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise EvidenceError(f"cannot load E9 configuration {path}: {exc}") from exc
    config = validate_config(_load_unique_yaml(text))
    if _is_preregistered_clean_run(config):
        _current_e9_claims_binding(config, require_power=False)
    return config, _identity(config)


def validate_config(value: object) -> dict[str, Any]:
    """Strictly revalidate any in-memory configuration mapping."""

    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise EvidenceError("E9 configuration must be a string-keyed mapping")
    config = dict(value)
    preregistered = config.get("schema") == PREREGISTERED_CONFIG_SCHEMA
    top_level_keys = {
        "schema",
        "experiment_id",
        "default_profile",
        "failure_cases",
        "functional_cases",
        "wire_contract",
        "statistics",
        "profiles",
    }
    if preregistered:
        top_level_keys.update(
            {
                "main_claims_manifest_id",
                "failure_case_contracts",
                "sampling_schedule",
                "diagnostics_contract",
            }
        )
    _exact_keys(
        config,
        top_level_keys,
        "E9 configuration",
    )
    if config["schema"] not in {CONFIG_SCHEMA, PREREGISTERED_CONFIG_SCHEMA}:
        raise EvidenceError("E9 configuration schema mismatch")
    if type(config["experiment_id"]) is not str or not config["experiment_id"]:
        raise EvidenceError("experiment_id must be a nonempty string")
    if preregistered and (
        type(config["main_claims_manifest_id"]) is not str
        or re.fullmatch(r"sha256:[0-9a-f]{64}", config["main_claims_manifest_id"])
        is None
    ):
        raise EvidenceError("v5 main_claims_manifest_id must be a canonical semantic ID")
    if config["default_profile"] != "smoke":
        raise EvidenceError("default profile must remain the non-formal smoke profile")
    if tuple(config["failure_cases"]) != FAILURE_CASES:
        raise EvidenceError("failure cases differ from the frozen E9 set")
    if tuple(config["functional_cases"]) != FUNCTIONAL_CASES:
        raise EvidenceError("functional cases differ from the frozen E9 set")

    wire = _mapping(config["wire_contract"], "wire_contract")
    _exact_keys(
        wire,
        {
            "transport",
            "request_bytes",
            "failure_status",
            "failure_frames",
            "failure_body",
            "connection_behavior",
        },
        "wire_contract",
    )
    expected_wire = {
        "transport": "TCP_IPV4_LOOPBACK",
        "request_bytes": REQUEST_STRUCT.size,
        "failure_status": FAILURE_STATUS,
        "failure_frames": ["status", "body", "end"],
        "failure_body": FAILURE_BODY.decode("ascii"),
        "connection_behavior": "ONE_REQUEST_CLIENT_HALF_CLOSE_SERVER_EOF_NO_REUSE",
    }
    _exact_value(wire, expected_wire, "wire_contract")

    statistics = _mapping(config["statistics"], "statistics")
    expected_statistics = (
        {
            "primary_metric": "frozen_external_multivariate_classifier_auc",
            "secondary_metric": "request_to_eof_ns",
            "auc_orientation": (
                "FIXED_TRAINING_DIRECTION_RAW_CI_WITH_GLOBAL_DIRECTION_INVARIANT_BOUND"
            ),
            "confidence_level": 0.95,
            "failure_auc_ci_upper_threshold": 0.55,
            "cluster_unit": "evaluation_seed",
            "bootstrap_method": "evaluation_seed_cluster_percentile",
            "primary_stratification": "kdf_workload",
            "combined_role": "descriptive_secondary_only",
            "classifier": dict(FROZEN_CLASSIFIER_CONTRACT),
            "feature_formulas": dict(CLASSIFIER_FEATURE_FORMULAS),
            "feature_input_policy": (
                "MISSING_EMPTY_NONPOSITIVE_TIMING_OR_NONFINITE_FEATURE_FAILS_CLOSED"
            ),
            "auc_tie_handling": "AVERAGE_RANK_MANN_WHITNEY",
            "point_estimate": "MAX_MEAN_RAW_AUC_ONE_MINUS_MEAN_RAW_AUC",
            "direction_invariant_ci_upper": "MAX_RAW_CI_UPPER_ONE_MINUS_RAW_CI_LOWER",
            "per_seed_oracle_orientation_sensitivity": (
                "MEAN_PER_SEED_MAX_RAW_AUC_ONE_MINUS_RAW_AUC_NOT_PRIMARY_ESTIMAND"
            ),
            "gate_rule": "GLOBAL_AND_PER_SEED_ORACLE_CI_UPPERS_LE_THRESHOLD",
            "percentile_definition": "N_MINUS_ONE_TIMES_P_LINEAR_INTERPOLATION",
            "bootstrap": {
                "namespace": "E9-FROZEN-CLASSIFIER-EVALUATION-SEED-BOOTSTRAP-v2",
                "seed_material": (
                    "PROFILE_CONTRACT_ID_STRATUM_ID_LEFT_CASE_RIGHT_CASE"
                ),
                "seed_derivation": "SHA256_ASCII_FIRST_64_BITS_BIG_ENDIAN",
                "pseudorandom_sequence": "PYTHON_RANDOM_MT19937_RANDRANGE",
                "resample_size": 30,
            },
        }
        if preregistered
        else {
            "primary_metric": "request_to_eof_ns",
            "auc_orientation": "max_auc_one_minus_auc",
            "confidence_level": 0.95,
            "failure_auc_ci_upper_threshold": 0.55,
            "cluster_unit": "seed",
            "bootstrap_method": "paired_seed_percentile",
            "primary_stratification": "kdf_workload",
            "combined_role": "descriptive_secondary_only",
        }
    )
    _exact_value(statistics, expected_statistics, "statistics")

    if preregistered:
        _exact_value(
            config["failure_case_contracts"],
            PREREGISTERED_PATH_CONTRACTS,
            "failure_case_contracts",
        )
        _exact_value(
            config["sampling_schedule"],
            PREREGISTERED_SAMPLING_SCHEDULE_CONTRACT,
            "sampling_schedule",
        )
        _exact_value(
            config["diagnostics_contract"],
            PREREGISTERED_DIAGNOSTICS_CONTRACT,
            "diagnostics_contract",
        )

    profiles = _mapping(config["profiles"], "profiles")
    _exact_keys(profiles, {"smoke", "formal"}, "profiles")
    _validate_profile(
        "smoke",
        _mapping(profiles["smoke"], "profiles.smoke"),
        config_schema=str(config["schema"]),
    )
    _validate_profile(
        "formal",
        _mapping(profiles["formal"], "profiles.formal"),
        config_schema=str(config["schema"]),
    )
    return config


def _validate_profile(
    name: str,
    profile: Mapping[str, object],
    *,
    config_schema: str = CONFIG_SCHEMA,
) -> None:
    common = {
        "evidence_class",
        "enabled",
        "seeds",
        "samples_per_case_per_seed",
        "warmup_per_case_per_seed",
        "bootstrap_replicates",
        "pbkdf2_iterations",
        "pbkdf2_dklen",
        "kdf_workloads",
        "failure_padding_ms",
        "auth_workers",
        "max_pending_padding",
        "socket_timeout_seconds",
    }
    expected_keys = common | (
        {"freeze_status", "formal_contract", "formal_blockers"}
        if name == "formal"
        else {"expected_commit", "independent_audit_id", "producer_public_key_hex"}
    )
    if name == "formal" and config_schema == PREREGISTERED_CONFIG_SCHEMA:
        expected_keys |= {
            "seed_split",
            "seed_workload_mapping",
            "kdf_workload_contracts",
        }
    _exact_keys(profile, expected_keys, f"profiles.{name}")
    seeds_value = profile["seeds"]
    if type(seeds_value) is not list:
        raise EvidenceError(f"profiles.{name}.seeds must be an array")
    seeds = tuple(_integer(seed, f"profiles.{name}.seed", 1) for seed in seeds_value)
    expected_seeds = (
        SMOKE_SEEDS
        if name == "smoke"
        else (
            PREREGISTERED_FORMAL_SEEDS
            if config_schema == PREREGISTERED_CONFIG_SCHEMA
            else FORMAL_SEEDS
        )
    )
    if seeds != expected_seeds:
        raise EvidenceError(f"profiles.{name} uses the wrong frozen seed set")
    fixed = (
        {
            "samples_per_case_per_seed": 8,
            "warmup_per_case_per_seed": 1,
            "bootstrap_replicates": 200,
            "pbkdf2_iterations": 100,
            "pbkdf2_dklen": 16,
            "failure_padding_ms": 2.0,
            "auth_workers": 2,
            "max_pending_padding": 32,
            "socket_timeout_seconds": 2.0,
        }
        if name == "smoke"
        else {
            "samples_per_case_per_seed": 200,
            "warmup_per_case_per_seed": 10,
            "bootstrap_replicates": 2000,
            "pbkdf2_iterations": 310000,
            "pbkdf2_dklen": 32,
            "failure_padding_ms": 10.0,
            "auth_workers": 4,
            "max_pending_padding": 256,
            "socket_timeout_seconds": 5.0,
        }
    )
    for key, expected in fixed.items():
        _exact_value(profile[key], expected, f"profiles.{name}.{key}")
    argon2_workload = {
        "algorithm": "argon2id",
        **(
            {"version": PREREGISTERED_ARGON2_ALGORITHM_VERSION}
            if config_schema == PREREGISTERED_CONFIG_SCHEMA
            else {}
        ),
        "memory_kib": 19456,
        "time_cost": 2,
        "parallelism": 1,
        "hash_len": 32,
    }
    expected_workloads = (
        [{"algorithm": "pbkdf2_hmac_sha256", "iterations": 100, "dklen": 16}]
        if name == "smoke"
        else [
            {"algorithm": "pbkdf2_hmac_sha256", "iterations": 310000, "dklen": 32},
            argon2_workload,
        ]
    )
    _exact_value(profile["kdf_workloads"], expected_workloads, f"profiles.{name}.kdf_workloads")
    if type(profile["enabled"]) is not bool:
        raise EvidenceError(f"profiles.{name}.enabled must be Boolean")
    if name == "smoke":
        expected = {
            "evidence_class": "IMPLEMENTATION_SMOKE_ONLY",
            "enabled": True,
            "expected_commit": "UNPINNED_SMOKE",
            "independent_audit_id": "NOT_APPLICABLE_SMOKE",
            "producer_public_key_hex": None,
        }
        for key, value in expected.items():
            _exact_value(profile[key], value, f"profiles.smoke.{key}")
        return

    enabled = profile["enabled"]
    if config_schema == PREREGISTERED_CONFIG_SCHEMA:
        expected = {
            "evidence_class": "FORMAL_E9_EXTERNAL_TIMING",
            "enabled": True,
            "freeze_status": "PREREGISTERED_BEFORE_FORMAL_COLLECTION",
            "formal_contract": PREREGISTERED_FORMAL_CONTRACT,
            "formal_blockers": [PREREGISTERED_FORMAL_BLOCKER],
            "seed_split": {
                "training_seeds_by_kdf": {
                    key: list(PREREGISTERED_TRAINING_SEEDS_BY_KDF[key])
                    for key in PREREGISTERED_KDF_STRATUM_IDS
                },
                "evaluation_seeds_by_kdf": {
                    key: list(PREREGISTERED_EVALUATION_SEEDS_BY_KDF[key])
                    for key in PREREGISTERED_KDF_STRATUM_IDS
                },
            },
            "seed_workload_mapping": dict(PREREGISTERED_SEED_WORKLOAD_MAPPING),
            "kdf_workload_contracts": {
                key: dict(PREREGISTERED_KDF_WORKLOADS[key])
                for key in PREREGISTERED_KDF_STRATUM_IDS
            },
        }
        for key, value in expected.items():
            _exact_value(profile[key], value, f"profiles.formal.{key}")
        return
    if config_schema != CONFIG_SCHEMA:
        raise EvidenceError("E9 profile configuration schema mismatch")
    _exact_value(
        profile["formal_blockers"],
        list(FORMAL_BLOCKERS),
        "profiles.formal.formal_blockers",
    )
    if not enabled:
        expected = {
            "evidence_class": "FORMAL_E9_EXTERNAL_TIMING",
            "freeze_status": (
                "BLOCKED_PENDING_AUDITOR_CONTRACT_CHALLENGE_AND_LINUX_PROCESS_LONG_TEST"
            ),
            "formal_contract": "EXTERNAL_AUDITOR_SIGNED_MANIFEST_REQUIRED",
        }
        for key, value in expected.items():
            _exact_value(profile[key], value, f"profiles.formal.{key}")
        return
    if profile["evidence_class"] != "FORMAL_E9_EXTERNAL_TIMING":
        raise EvidenceError("formal evidence class mismatch")
    if profile["freeze_status"] != "FROZEN_BY_EXTERNAL_AUDITOR_MANIFEST":
        raise EvidenceError("formal E9 is not independently frozen")
    if profile["formal_contract"] != "EXTERNAL_AUDITOR_SIGNED_MANIFEST_REQUIRED":
        raise EvidenceError("formal E9 requires the external contract policy")


def profile_contract(config: Mapping[str, Any], name: str) -> tuple[dict[str, Any], str]:
    if name not in {"smoke", "formal"}:
        raise EvidenceError("profile must be smoke or formal")
    profile = _mapping(_mapping(config["profiles"], "profiles")[name], f"profiles.{name}")
    contract = {
        "experiment_id": config["experiment_id"],
        "profile_name": name,
        "failure_cases": list(config["failure_cases"]),
        "functional_cases": list(config["functional_cases"]),
        "wire_contract": config["wire_contract"],
        "statistics": config["statistics"],
        **(
            {
                "failure_case_contracts": config["failure_case_contracts"],
                "sampling_schedule": config["sampling_schedule"],
                "diagnostics_contract": config["diagnostics_contract"],
            }
            if _is_preregistered_clean_run(config)
            else {}
        ),
        "profile": profile,
    }
    return profile, _identity(contract)


def _is_preregistered_clean_run(config: Mapping[str, Any]) -> bool:
    return config.get("schema") == PREREGISTERED_CONFIG_SCHEMA


def _repository_contract_path(relative_path: object, label: str) -> Path:
    if type(relative_path) is not str or not relative_path or "\\" in relative_path:
        raise EvidenceError(f"{label} must be a nonempty repository-relative POSIX path")
    candidate = Path(relative_path)
    if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
        raise EvidenceError(f"{label} must stay within the repository")
    resolved = (ROOT / candidate).resolve(strict=False)
    if not _is_within(resolved, ROOT.resolve(strict=True)):
        raise EvidenceError(f"{label} escapes the repository")
    return resolved


def _current_e9_claims_binding(
    config: Mapping[str, Any], *, require_power: bool
) -> dict[str, object]:
    """Bind v5 to the current strict main-claims contract and prospective power state."""

    if not _is_preregistered_clean_run(config):
        raise EvidenceError("main-claims binding applies only to the v5 E9 contract")
    try:
        from experiments.claims_manifest import load_main_claims_manifest

        manifest, manifest_id = load_main_claims_manifest()
    except Exception as exc:
        raise EvidenceError(f"cannot load the strict current main-claims manifest: {exc}") from exc
    _exact_value(
        config["main_claims_manifest_id"],
        manifest_id,
        "v5 current main-claims manifest identity",
    )
    e9 = _mapping(manifest["e9_failure_classifier"], "main-claims E9 contract")
    formal = _mapping(config["profiles"]["formal"], "v5 formal profile")
    statistics = _mapping(config["statistics"], "v5 statistics")
    classifier = _mapping(statistics["classifier"], "v5 classifier")
    feature_contract = _mapping(e9["feature_contract"], "main-claims feature contract")
    inference = _mapping(e9["inference"], "main-claims inference")
    claims_classifier = _mapping(e9["classifier"], "main-claims classifier")
    claims_optimizer = _mapping(
        claims_classifier["optimizer"], "main-claims classifier optimizer"
    )
    _exact_value(e9["failure_cases"], list(config["failure_cases"]), "E9 failure cases")
    _exact_value(
        e9["success_exclusion"]["excluded_case"],
        config["functional_cases"][0],
        "E9 functional-success exclusion",
    )
    _exact_value(e9["path_contracts"], config["failure_case_contracts"], "E9 path contracts")
    _exact_value(e9["kdf_strata"], formal["kdf_workload_contracts"], "E9 KDF strata")
    _exact_value(e9["seed_universe"], formal["seeds"], "E9 seed universe")
    _exact_value(
        {
            "training_seeds_by_kdf": e9["training_seeds_by_kdf"],
            "evaluation_seeds_by_kdf": e9["evaluation_seeds_by_kdf"],
        },
        formal["seed_split"],
        "E9 train/evaluation seed split",
    )
    _exact_value(feature_contract["features"], classifier["feature_names"], "E9 features")
    _exact_value(
        feature_contract["formulas"], statistics["feature_formulas"], "E9 feature formulas"
    )
    _exact_value(
        feature_contract["input_policy"],
        statistics["feature_input_policy"],
        "E9 feature input policy",
    )
    _exact_value(claims_classifier["family"], classifier["model"], "E9 classifier family")
    _exact_value(
        claims_classifier["scaling"]["quantile_definition"],
        classifier["quantile_definition"],
        "E9 classifier quantile definition",
    )
    numeric = _mapping(claims_classifier["numeric_semantics"], "main-claims numeric semantics")
    numeric_pairs = {
        "dtype": "numeric_dtype",
        "objective": "objective",
        "row_weighting": "row_weighting",
        "initialization": "initialization",
        "stable_log_loss": "stable_log_loss",
        "sigmoid_clip": "sigmoid_clip",
    }
    for claims_key, config_key in numeric_pairs.items():
        _exact_value(numeric[claims_key], classifier[config_key], f"E9 numeric {claims_key}")
    regularization = _mapping(
        claims_classifier["regularization"], "main-claims regularization"
    )
    _exact_value(regularization["lambda"], classifier["l2_penalty"], "E9 L2 penalty")
    _exact_value(
        regularization["penalize_intercept"],
        classifier["intercept_penalized"],
        "E9 intercept penalty",
    )
    optimizer_options = _mapping(claims_optimizer["options"], "main-claims optimizer options")
    for claims_key, config_key in {
        "gtol": "gradient_tolerance",
        "ftol": "function_tolerance",
        "maxiter": "max_iterations",
        "maxls": "max_line_search_steps",
    }.items():
        _exact_value(
            optimizer_options[claims_key], classifier[config_key], f"E9 optimizer {claims_key}"
        )
    _exact_value(
        claims_optimizer["maximum_gradient_infinity_norm"],
        classifier["convergence_gradient_inf_max"],
        "E9 convergence gradient",
    )
    _exact_value(inference["auc_tie_handling"], statistics["auc_tie_handling"], "E9 AUC ties")
    _exact_value(inference["point_estimate"], statistics["point_estimate"], "E9 estimand")
    _exact_value(
        inference["direction_invariant_ci_upper"],
        statistics["direction_invariant_ci_upper"],
        "E9 direction-invariant confidence bound",
    )
    _exact_value(
        inference["per_seed_oracle_orientation_sensitivity"],
        statistics["per_seed_oracle_orientation_sensitivity"],
        "E9 per-seed oracle-orientation sensitivity",
    )
    _exact_value(inference["gate_rule"], statistics["gate_rule"], "E9 gate rule")
    _exact_value(
        inference["percentile_definition"],
        statistics["percentile_definition"],
        "E9 percentile definition",
    )
    _exact_value(
        {
            **dict(_mapping(inference["bootstrap_rng"], "main-claims bootstrap RNG")),
            "resample_size": inference["bootstrap_resample_size"],
        },
        statistics["bootstrap"],
        "E9 bootstrap RNG",
    )
    _exact_value(
        inference["auc_ci_upper_threshold"],
        statistics["failure_auc_ci_upper_threshold"],
        "E9 AUC threshold",
    )
    measurement = _mapping(e9["measurement_contract"], "main-claims E9 measurement")
    expected_measurement = {
        "samples_per_case_per_seed": formal["samples_per_case_per_seed"],
        "warmup_per_case_per_seed": formal["warmup_per_case_per_seed"],
        "measured_observations": len(formal["seeds"])
        * len(ALL_CASES)
        * int(formal["samples_per_case_per_seed"]),
        "failure_observations": len(formal["seeds"])
        * len(FAILURE_CASES)
        * int(formal["samples_per_case_per_seed"]),
        "functional_observations": len(formal["seeds"])
        * len(FUNCTIONAL_CASES)
        * int(formal["samples_per_case_per_seed"]),
        "failure_padding_ms": formal["failure_padding_ms"],
        "auth_workers": formal["auth_workers"],
        "max_pending_padding": formal["max_pending_padding"],
        "socket_timeout_seconds": formal["socket_timeout_seconds"],
        "seed_execution": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_RETRY",
        "schedule": config["sampling_schedule"],
    }
    _exact_value(measurement, expected_measurement, "E9 measurement contract")
    _exact_value(
        e9["diagnostics_contract"],
        config["diagnostics_contract"],
        "E9 diagnostics contract",
    )
    power = _mapping(e9["prospective_power_plan"], "main-claims E9 prospective power")
    plan_path = _repository_contract_path(power["plan_path"], "E9 power plan path")
    if not plan_path.is_file():
        raise EvidenceError("the frozen E9 prospective power plan is missing")
    binding: dict[str, object] = {
        "main_claims_manifest_id": manifest_id,
        "power_status": power["status"],
        "power_plan_path": power["plan_path"],
        "power_result_path": power["result_path"],
        "power_result_id": power["result_id"],
    }
    if not require_power:
        return binding
    if power["status"] != "PASSED":
        raise RuntimeError(
            "v5 formal collection is blocked until prospective statistical power passes"
        )
    result_path = _repository_contract_path(power["result_path"], "E9 power result path")
    try:
        from experiments.analysis.failure_timing_power import load_result

        _result, result_id = load_result(result_path, config_path=plan_path)
    except Exception as exc:
        raise EvidenceError(f"cannot validate the frozen E9 power result: {exc}") from exc
    _exact_value(result_id, power["result_id"], "E9 prospective power result identity")
    return binding


def _preregistered_authorization() -> dict[str, object]:
    return {
        "schema": PREREGISTERED_AUTHORIZATION_SCHEMA,
        "formal_contract": PREREGISTERED_FORMAL_CONTRACT,
        "authorization_basis": "PREREGISTERED_CLEAN_COMMIT_AND_OPERATOR_ASSERTIONS",
        "execution_evidence_class": PREREGISTERED_ASSERTION_CLASS,
        "external_runtime_attestation": False,
        "post_run_requirement": PREREGISTERED_AUDIT_REQUIREMENT,
    }


def _expected_process_long_test_config() -> dict[str, object]:
    return {
        "schema": PROCESS_LONG_TEST_CONFIG_SCHEMA,
        "experiment_id": "e9-loopback-failure-timing-v1",
        "qualification_id": PROCESS_LONG_TEST_QUALIFICATION_ID,
        "profile_name": PROCESS_LONG_TEST_PROFILE_NAME,
        "evidence_class": PROCESS_LONG_TEST_EVIDENCE_CLASS,
        "qualification_enabled": True,
        "formal_evidence_eligible": False,
        "formal_claim_eligible": False,
        "formal_blocker_effect": PROCESS_LONG_TEST_BLOCKER_EFFECT,
        "external_review_requirement": PROCESS_LONG_TEST_REVIEW_STATUS,
        "authentication": PROCESS_LONG_TEST_AUTHENTICATION,
        "failure_cases": list(FAILURE_CASES),
        "functional_cases": list(FUNCTIONAL_CASES),
        "wire_contract": {
            "transport": "TCP_IPV4_LOOPBACK",
            "request_bytes": REQUEST_STRUCT.size,
            "failure_status": FAILURE_STATUS,
            "failure_frames": ["status", "body", "end"],
            "failure_body": FAILURE_BODY.decode("ascii"),
            "connection_behavior": (
                "ONE_REQUEST_CLIENT_HALF_CLOSE_SERVER_EOF_NO_REUSE"
            ),
        },
        "profile": {
            "seeds": list(PROCESS_LONG_TEST_SEEDS),
            "samples_per_case_per_seed": 200,
            "warmup_per_case_per_seed": 10,
            "bootstrap_replicates": 2000,
            "pbkdf2_iterations": 310000,
            "pbkdf2_dklen": 32,
            "kdf_workloads": [
                {
                    "algorithm": "pbkdf2_hmac_sha256",
                    "iterations": 310000,
                    "dklen": 32,
                },
                {
                    "algorithm": "argon2id",
                    "memory_kib": 19456,
                    "time_cost": 2,
                    "parallelism": 1,
                    "hash_len": 32,
                },
            ],
            "failure_padding_ms": 10.0,
            "auth_workers": 4,
            "max_pending_padding": 256,
            "socket_timeout_seconds": 5.0,
        },
    }


def load_process_long_test_config(path: Path) -> tuple[dict[str, Any], str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise EvidenceError(
            f"cannot load E9 process long-test configuration {path}: {exc}"
        ) from exc
    value = _load_unique_yaml(text)
    config = _mapping(value, "E9 process long-test configuration")
    _exact_value(
        config,
        _expected_process_long_test_config(),
        "E9 process long-test configuration",
    )
    return config, _identity(config)


def process_long_test_profile_contract(
    config: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    _exact_value(
        config,
        _expected_process_long_test_config(),
        "E9 process long-test configuration",
    )
    configured_profile = _mapping(config["profile"], "process long-test profile")
    profile = {
        "evidence_class": config["evidence_class"],
        "enabled": config["qualification_enabled"],
        **dict(configured_profile),
        "qualification_id": config["qualification_id"],
        "formal_evidence_eligible": config["formal_evidence_eligible"],
        "formal_claim_eligible": config["formal_claim_eligible"],
        "formal_blocker_effect": config["formal_blocker_effect"],
        "external_review_requirement": config["external_review_requirement"],
        "authentication": config["authentication"],
    }
    contract = {
        "experiment_id": config["experiment_id"],
        "qualification_id": config["qualification_id"],
        "profile_name": config["profile_name"],
        "evidence_class": config["evidence_class"],
        "formal_evidence_eligible": config["formal_evidence_eligible"],
        "formal_claim_eligible": config["formal_claim_eligible"],
        "formal_blocker_effect": config["formal_blocker_effect"],
        "external_review_requirement": config["external_review_requirement"],
        "authentication": config["authentication"],
        "failure_cases": list(config["failure_cases"]),
        "functional_cases": list(config["functional_cases"]),
        "wire_contract": dict(config["wire_contract"]),
        "profile": dict(configured_profile),
    }
    return profile, _identity(contract)


@dataclass(frozen=True)
class Coordinate:
    seed: int
    case: str
    ordinal: int
    schedule_index: int


@dataclass(frozen=True)
class _SeedChildLaunch:
    process_id: int
    result: dict[str, Any]


def measurement_plan(profile: Mapping[str, Any]) -> list[Coordinate]:
    count = int(profile["samples_per_case_per_seed"])
    result: list[Coordinate] = []
    schedule_index = 0
    for seed in profile["seeds"]:
        points = [(case, ordinal) for case in ALL_CASES for ordinal in range(count)]
        derived = hashlib.sha256(f"E9-SCHEDULE-v1:{seed}".encode("ascii")).digest()
        random.Random(int.from_bytes(derived[:8], "big")).shuffle(points)
        for case, ordinal in points:
            result.append(Coordinate(int(seed), case, ordinal, schedule_index))
            schedule_index += 1
    return result


def _workload_for_seed(
    profile: Mapping[str, Any], seed: int, seed_index: int
) -> dict[str, Any]:
    if profile.get("formal_contract") == PREREGISTERED_FORMAL_CONTRACT:
        mapping = _mapping(profile["seed_workload_mapping"], "seed workload mapping")
        stratum_id = mapping.get(str(seed))
        contracts = _mapping(profile["kdf_workload_contracts"], "KDF workload contracts")
        if type(stratum_id) is not str or stratum_id not in contracts:
            raise EvidenceError("seed lacks its frozen v5 KDF workload mapping")
        return _mapping(contracts[stratum_id], f"KDF workload contract {stratum_id}")
    workloads = list(profile["kdf_workloads"])
    return _mapping(
        workloads[seed_index % len(workloads)], "seed-child selected KDF workload"
    )


def _seed_workload_schedule(profile: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(seed): dict(_workload_for_seed(profile, int(seed), index))
        for index, seed in enumerate(profile["seeds"])
    }


def _credential(case: str, seed: int, ordinal: int) -> tuple[str, bytes]:
    if case == "unknown_username":
        return f"unknown-{seed}-{ordinal}", f"unknown-pass-{seed}-{ordinal}".encode("ascii")
    if case == "positive_screen_negative":
        return "alice", f"screen-neg-{seed}-{ordinal}".encode("ascii")
    if case == "negative_cache_hit":
        return "alice", b"cached-wrong"
    if case == "backend_mismatch":
        return "alice", f"backend-wrong-{seed}-{ordinal}".encode("ascii")
    if case == "transient_backend_failure":
        return "alice", f"transient-wrong-{seed}-{ordinal}".encode("ascii")
    if case == "valid_password":
        return "alice", b"correct-password"
    raise EvidenceError(f"unknown case {case!r}")


def _fixed_bytes(value: bytes, size: int, label: str) -> bytes:
    if not value or len(value) > size or b"\0" in value:
        raise EvidenceError(f"{label} does not fit the fixed request field")
    return value + bytes(size - len(value))


def build_request(coordinate: Coordinate) -> bytes:
    username, password = _credential(coordinate.case, coordinate.seed, coordinate.ordinal)
    request = REQUEST_STRUCT.pack(
        REQUEST_MAGIC,
        REQUEST_VERSION,
        CASE_CODES[coordinate.case],
        coordinate.seed,
        coordinate.ordinal,
        _fixed_bytes(username.encode("ascii"), 32, "username"),
        _fixed_bytes(password, 60, "password"),
    )
    assert len(request) == REQUEST_STRUCT.size
    return request


def parse_request(value: bytes) -> Coordinate:
    if len(value) != REQUEST_STRUCT.size:
        raise EvidenceError("request has the wrong fixed byte length")
    magic, version, case_code, seed, ordinal, username_raw, password_raw = REQUEST_STRUCT.unpack(
        value
    )
    if magic != REQUEST_MAGIC or version != REQUEST_VERSION or case_code not in CODE_CASES:
        raise EvidenceError("request header is outside the E9 wire contract")
    case = CODE_CASES[case_code]
    username = username_raw.rstrip(b"\0").decode("ascii")
    password = password_raw.rstrip(b"\0")
    expected_username, expected_password = _credential(case, seed, ordinal)
    if username != expected_username or password != expected_password:
        raise EvidenceError("request credential does not match its derived coordinate")
    return Coordinate(seed, case, ordinal, -1)


def _encode_response(status: int, body: bytes) -> tuple[bytes, list[bytes]]:
    frames = []
    for name, payload in (
        ("status", str(status).encode("ascii")),
        ("body", body),
        ("end", END_BODY),
    ):
        frames.append(struct.pack("!BH", FRAME_TYPES[name], len(payload)) + payload)
    return b"".join(frames), frames


FAILURE_RESPONSE, FAILURE_RESPONSE_FRAMES = _encode_response(FAILURE_STATUS, FAILURE_BODY)
VALID_RESPONSE, VALID_RESPONSE_FRAMES = _encode_response(VALID_STATUS, VALID_BODY)


def _decode_response(value: bytes) -> tuple[int, bytes, list[str]]:
    offset = 0
    frames: list[tuple[str, bytes]] = []
    while offset < len(value):
        if len(value) - offset < 3:
            raise EvidenceError("truncated response frame header")
        type_code, length = struct.unpack("!BH", value[offset : offset + 3])
        offset += 3
        if type_code not in FRAME_NAMES or len(value) - offset < length:
            raise EvidenceError("malformed response frame")
        frames.append((FRAME_NAMES[type_code], value[offset : offset + length]))
        offset += length
    if [name for name, _ in frames] != ["status", "body", "end"]:
        raise EvidenceError("response frame order differs from the wire contract")
    try:
        status = int(frames[0][1].decode("ascii"))
    except (UnicodeError, ValueError) as exc:
        raise EvidenceError("response status frame is invalid") from exc
    if frames[2][1] != END_BODY:
        raise EvidenceError("response end frame differs from the wire contract")
    return status, frames[1][1], [name for name, _ in frames]


class _ScenarioScreen(PositiveScreen):
    def query(self, view, password, edge_id, token=None):  # type: ignore[override]
        decision = super().query(view, password, edge_id, token)
        password_bytes = exact_password_bytes(password)
        forced = password_bytes == b"cached-wrong" or password_bytes.startswith(
            (b"backend-wrong-", b"transient-wrong-")
        )
        if decision.disposition is PositiveDisposition.NEGATIVE and forced:
            return PositiveDecision(
                PositiveDisposition.POSITIVE,
                "controlled E9 false-positive path",
                credential_token=decision.credential_token,
                region=decision.region,
                certificate=decision.certificate,
            )
        return decision


class _MeasuredKdfBackend(InMemoryBackend):
    def __init__(self, workload: Mapping[str, Any]) -> None:
        super().__init__()
        self.workload = dict(workload)
        self._measurement_lock = threading.Lock()
        self._kdf_calls = 0
        self._kdf_cpu_ns = 0
        self._kdf_wall_ns = 0

    def verify(self, username, password, expected_version):  # type: ignore[override]
        username_key = self._key(username)
        with self._lock:
            injected = self._inject_once.get(username_key)
            if injected is BackendResultKind.TRANSIENT_FAILURE:
                self._inject_once.pop(username_key)
                self.verify_calls += 1
                return self._result(
                    injected,
                    expected_version,
                    None,
                    detail="injected pre-verifier pre-KDF transient failure",
                )
        cpu_started = time.thread_time_ns()
        wall_started = time.perf_counter_ns()
        password_bytes = exact_password_bytes(password)
        salt = hashlib.sha256(username.casefold().encode("utf-8")).digest()[:16]
        if self.workload["algorithm"] == "pbkdf2_hmac_sha256":
            hashlib.pbkdf2_hmac(
                "sha256",
                password_bytes,
                salt,
                int(self.workload["iterations"]),
                int(self.workload["dklen"]),
            )
        elif self.workload["algorithm"] == "argon2id":
            try:
                from argon2.low_level import Type, hash_secret_raw
            except ImportError as exc:
                raise RuntimeError("formal Argon2id timing requires argon2-cffi") from exc
            hash_secret_raw(
                password_bytes,
                salt,
                time_cost=int(self.workload["time_cost"]),
                memory_cost=int(self.workload["memory_kib"]),
                parallelism=int(self.workload["parallelism"]),
                hash_len=int(self.workload["hash_len"]),
                type=Type.ID,
                version=int(
                    self.workload.get(
                        "version", PREREGISTERED_ARGON2_ALGORITHM_VERSION
                    )
                ),
            )
        else:  # configuration validation makes this unreachable
            raise RuntimeError("unsupported E9 KDF workload")
        cpu_elapsed = time.thread_time_ns() - cpu_started
        wall_elapsed = time.perf_counter_ns() - wall_started
        with self._measurement_lock:
            self._kdf_calls += 1
            self._kdf_cpu_ns += cpu_elapsed
            self._kdf_wall_ns += wall_elapsed
        return super().verify(username, password, expected_version)

    def measurement_snapshot(self) -> tuple[int, int, int, int]:
        with self._measurement_lock:
            return self.verify_calls, self._kdf_calls, self._kdf_cpu_ns, self._kdf_wall_ns


class _SystemUnderTest:
    def __init__(self, profile: Mapping[str, Any], workload: Mapping[str, Any]) -> None:
        self.instance_id = secrets.token_hex(16)
        self.directory = Directory()
        self.screen = _ScenarioScreen(b"P" * 32, b"C" * 32, region_count=4)
        self.backend = _MeasuredKdfBackend(workload)
        self._stress_lock = threading.Lock()
        self._stress_release = threading.Event()
        self._stress_enabled = False
        self._stress_expected = 0
        self._stress_active = 0
        self._stress_peak = 0
        self.cache = NegativeCache(
            capacity=128,
            policy=TinyLfuPolicy(reset_after=1024),
            max_ttl_seconds=3600.0,
            max_entries_per_account=128,
            max_entries_per_region=128,
        )
        self.control = ActivationStateMachine(self.directory, self.screen, self.backend)
        key = self.control.prepare(
            username="alice",
            account_id="e9-account-1",
            account_generation=1,
            credential_set_version=1,
            salt=b"e9-fixed-account-salt",
            authenticators={"password": b"correct-password"},
            required_edges=(EDGE_ID,),
        )
        self.control.publish_delta(key)
        self.control.acknowledge_delta(key, EDGE_ID)
        self.control.activate(key)
        self.engine = AuthDataPlane(
            self.directory,
            self.screen,
            NegativeKeyDeriver(b"N" * 32),
            self.cache,
            Singleflight(max_waiters_per_key=16, max_waiters_global=64),
            self.backend,
            negative_ttl_seconds=3600.0,
        )
        prewarm = self.engine.authenticate(EDGE_ID, "alice", b"cached-wrong")
        if prewarm.route is not AuthRoute.BACKEND_DENY:
            raise RuntimeError("negative-cache timing path could not be prewarmed")
        self._auth_worker_ids_lock = threading.Lock()
        self._auth_worker_native_ids: set[int] = set()

    def begin_concurrency_stress(self, expected_workers: int) -> None:
        with self._stress_lock:
            self._stress_enabled = True
            self._stress_expected = expected_workers
            self._stress_active = 0
            self._stress_peak = 0
            self._stress_release.clear()

    def end_concurrency_stress(self) -> int:
        with self._stress_lock:
            self._stress_enabled = False
            return self._stress_peak

    def auth_worker_native_ids(self) -> list[int]:
        with self._auth_worker_ids_lock:
            return sorted(self._auth_worker_native_ids)

    def process(self, coordinate: Coordinate) -> dict[str, object]:
        with self._stress_lock:
            stress_enabled = self._stress_enabled
            if stress_enabled:
                self._stress_active += 1
                self._stress_peak = max(self._stress_peak, self._stress_active)
                if self._stress_active == self._stress_expected:
                    self._stress_release.set()
        if stress_enabled:
            if not self._stress_release.wait(2.0):
                raise RuntimeError("real SUT concurrency stress could not saturate workers")
            with self._stress_lock:
                self._stress_active -= 1
        username, password = _credential(coordinate.case, coordinate.seed, coordinate.ordinal)
        if coordinate.case == "transient_backend_failure":
            self.backend.inject_once("alice", BackendResultKind.TRANSIENT_FAILURE)
        backend_before = self.backend.measurement_snapshot()
        cache_before = self.cache.metrics_snapshot()
        screen_before = self.screen.metrics_snapshot()
        wall_started = time.perf_counter_ns()
        cpu_started = time.thread_time_ns()
        auth_thread_id = threading.get_ident()
        auth_worker_native_id = threading.get_native_id()
        with self._auth_worker_ids_lock:
            self._auth_worker_native_ids.add(auth_worker_native_id)
        decision = self.engine.authenticate(EDGE_ID, username, password)
        auth_cpu_ns = time.thread_time_ns() - cpu_started
        wall_finished = time.perf_counter_ns()
        backend_after = self.backend.measurement_snapshot()
        cache_after = self.cache.metrics_snapshot()
        screen_after = self.screen.metrics_snapshot()
        backend_kind = (
            None if decision.backend_result is None else decision.backend_result.kind.value
        )
        return {
            "route": decision.route.value,
            "accepted": decision.accepted,
            "backend_kind": backend_kind,
            "backend_calls": backend_after[0] - backend_before[0],
            "kdf_calls": backend_after[1] - backend_before[1],
            "backend_cpu_ns": backend_after[2] - backend_before[2],
            "backend_wall_ns": backend_after[3] - backend_before[3],
            "auth_worker_cpu_ns": auth_cpu_ns,
            "auth_worker_wall_ns": wall_finished - wall_started,
            "auth_worker_thread_id": auth_thread_id,
            "auth_worker_native_id": auth_worker_native_id,
            "auth_finished_monotonic_ns": wall_finished,
            "cache_hits": cache_after.get("hits", 0) - cache_before.get("hits", 0),
            "screen_negatives": screen_after.get("negative", 0) - screen_before.get("negative", 0),
        }


class _StrictAsyncPadder:
    """Timer-only padding; capacity exhaustion fails instead of blocking auth workers."""

    def __init__(self, minimum_seconds: float, max_pending: int) -> None:
        self.minimum_ns = int(minimum_seconds * 1_000_000_000)
        self.max_pending = max_pending
        self._lock = threading.Lock()
        self._pending = 0
        self._scheduled = 0
        self._immediate = 0
        self._peak = 0
        self._overflow = 0

    def defer(
        self, value: object, request_received_ns: int
    ) -> Future[tuple[object, dict[str, object]]]:
        scheduled_ns = time.perf_counter_ns()
        delay_ns = max(0, request_received_ns + self.minimum_ns - scheduled_ns)
        future: Future[tuple[object, dict[str, object]]] = Future()
        if delay_ns == 0:
            with self._lock:
                self._immediate += 1
            future.set_result(
                (
                    value,
                    {
                        "scheduled": False,
                        "requested_delay_ns": 0,
                        "actual_wait_ns": 0,
                        "padding_thread_id": None,
                        "padding_scheduled_monotonic_ns": scheduled_ns,
                        "response_release_monotonic_ns": scheduled_ns,
                    },
                )
            )
            return future
        with self._lock:
            if self._pending >= self.max_pending:
                self._overflow += 1
                raise RuntimeError("asynchronous padding capacity exhausted")
            self._pending += 1
            self._scheduled += 1
            self._peak = max(self._peak, self._pending)

        def complete() -> None:
            completed_ns = time.perf_counter_ns()
            try:
                future.set_result(
                    (
                        value,
                        {
                            "scheduled": True,
                            "requested_delay_ns": delay_ns,
                            "actual_wait_ns": completed_ns - scheduled_ns,
                            "padding_thread_id": threading.get_ident(),
                            "padding_scheduled_monotonic_ns": scheduled_ns,
                            "response_release_monotonic_ns": completed_ns,
                        },
                    )
                )
            finally:
                with self._lock:
                    self._pending -= 1

        timer = threading.Timer(delay_ns / 1_000_000_000, complete)
        timer.daemon = True
        timer.start()
        return future

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return {
                "scheduled_async": self._scheduled,
                "immediate_after_slow_auth": self._immediate,
                "peak_pending": self._peak,
                "pending": self._pending,
                "overflow_failures": self._overflow,
                "max_pending": self.max_pending,
            }


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise EvidenceError("peer closed before the fixed request was complete")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class _LoopbackServer:
    def __init__(
        self, profile: Mapping[str, Any], workload: Mapping[str, Any], construction_ordinal: int
    ) -> None:
        self.profile = profile
        self.workload = dict(workload)
        self.system = _SystemUnderTest(profile, workload)
        self.instance_id = self.system.instance_id
        self.construction_ordinal = construction_ordinal
        self.padder = _StrictAsyncPadder(
            float(profile["failure_padding_ms"]) / 1000.0,
            int(profile["max_pending_padding"]),
        )
        self.executor = ThreadPoolExecutor(
            max_workers=int(profile["auth_workers"]), thread_name_prefix="e9-auth"
        )
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.listener.settimeout(0.2)
        self.host, self.port = self.listener.getsockname()
        self._stop = threading.Event()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="e9-accept", daemon=True
        )
        self._handlers: list[threading.Thread] = []
        self._handlers_lock = threading.Lock()
        self._results: dict[tuple[int, str, int], dict[str, object]] = {}
        self._result_events: dict[tuple[int, str, int], threading.Event] = {}
        self._results_lock = threading.Lock()
        self._seen: set[tuple[int, str, int]] = set()
        self._errors: list[str] = []

    def start(self) -> None:
        self._accept_thread.start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._handle,
                args=(connection,),
                name="e9-connection",
                daemon=True,
            )
            with self._handlers_lock:
                self._handlers.append(thread)
            thread.start()

    def _handle(self, connection: socket.socket) -> None:
        coordinate_key: tuple[int, str, int] | None = None
        try:
            connection.settimeout(float(self.profile["socket_timeout_seconds"]))
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            request = _recv_exact(connection, REQUEST_STRUCT.size)
            trailing = connection.recv(1)
            client_eof = trailing == b""
            if not client_eof:
                raise EvidenceError("client sent bytes after the fixed request")
            received_ns = time.perf_counter_ns()
            coordinate = parse_request(request)
            coordinate_key = (coordinate.seed, coordinate.case, coordinate.ordinal)
            with self._results_lock:
                if coordinate_key in self._seen:
                    raise EvidenceError("duplicate request coordinate reached the server")
                self._seen.add(coordinate_key)
                event = self._result_events.setdefault(coordinate_key, threading.Event())
            resource = self.executor.submit(self.system.process, coordinate).result(
                timeout=float(self.profile["socket_timeout_seconds"])
            )
            padded_resource, padding = self.padder.defer(resource, received_ns).result(
                timeout=float(self.profile["socket_timeout_seconds"])
            )
            resource = dict(padded_resource)  # type: ignore[arg-type]
            padding = dict(padding)
            auth_thread_id = int(resource["auth_worker_thread_id"])
            padding_thread_id = padding["padding_thread_id"]
            resource.update(
                {
                    "sut_instance_id": self.instance_id,
                    "sut_construction_ordinal": self.construction_ordinal,
                    "sut_process_id": os.getpid(),
                    "kdf_workload": self.workload,
                    "padding_scheduled_async": padding["scheduled"],
                    "padding_requested_delay_ns": padding["requested_delay_ns"],
                    "padding_actual_wait_ns": padding["actual_wait_ns"],
                    "padding_thread_id": padding_thread_id,
                    "padding_execution_class": "threading.Timer",
                    "request_received_monotonic_ns": received_ns,
                    "padding_deadline_monotonic_ns": received_ns
                    + self.padder.minimum_ns,
                    "response_release_monotonic_ns": padding[
                        "response_release_monotonic_ns"
                    ],
                    "auth_worker_released_before_padding": int(
                        resource["auth_finished_monotonic_ns"]
                    )
                    <= int(padding["padding_scheduled_monotonic_ns"]),
                    "padding_used_auth_worker": (
                        padding_thread_id is not None and padding_thread_id == auth_thread_id
                    ),
                    "server_observed_client_eof": client_eof,
                    "server_tcp_nodelay": connection.getsockopt(
                        socket.IPPROTO_TCP, socket.TCP_NODELAY
                    )
                    == 1,
                }
            )
            del resource["auth_finished_monotonic_ns"]
            accepted = bool(resource["accepted"])
            response_frames = VALID_RESPONSE_FRAMES if accepted else FAILURE_RESPONSE_FRAMES
            send_started_ns = time.perf_counter_ns()
            resource["response_send_started_monotonic_ns"] = send_started_ns
            if send_started_ns < int(resource["padding_deadline_monotonic_ns"]):
                raise EvidenceError("response send began before the minimum padding deadline")
            for frame in response_frames:
                connection.sendall(frame)
            connection.shutdown(socket.SHUT_WR)
            resource["server_shutdown_write"] = True
            with self._results_lock:
                self._results[coordinate_key] = resource
                event.set()
        except Exception as exc:
            with self._results_lock:
                self._errors.append(f"{type(exc).__name__}: {exc}")
                if coordinate_key is not None:
                    self._result_events.setdefault(coordinate_key, threading.Event()).set()
        finally:
            connection.close()

    def take_result(self, coordinate: Coordinate) -> dict[str, object]:
        key = (coordinate.seed, coordinate.case, coordinate.ordinal)
        with self._results_lock:
            event = self._result_events.setdefault(key, threading.Event())
        if not event.wait(float(self.profile["socket_timeout_seconds"])):
            raise RuntimeError(f"server resource record timed out for {key}")
        with self._results_lock:
            if key not in self._results:
                raise RuntimeError(f"server failed for {key}: {self._errors[-1:]}")
            return self._results.pop(key)

    def run_concurrency_stress(self, seed: int) -> dict[str, object]:
        workers = int(self.profile["auth_workers"])
        count = workers + 1
        base = (
            int(self.profile["samples_per_case_per_seed"])
            + int(self.profile["warmup_per_case_per_seed"])
            + 10_000
        )
        coordinates = [
            Coordinate(seed, "backend_mismatch", base + index, -1) for index in range(count)
        ]
        self.system.begin_concurrency_stress(workers)

        def request(coordinate: Coordinate) -> None:
            _collect_external(
                self.host,
                self.port,
                coordinate,
                float(self.profile["socket_timeout_seconds"]),
            )
            self.take_result(coordinate)

        with ThreadPoolExecutor(
            max_workers=count, thread_name_prefix="e9-stress-client"
        ) as clients:
            futures = [clients.submit(request, coordinate) for coordinate in coordinates]
            for future in futures:
                future.result(timeout=float(self.profile["socket_timeout_seconds"]) * 2.0)
        peak = self.system.end_concurrency_stress()
        if peak != workers:
            raise RuntimeError("real loopback requests did not saturate every auth worker")
        return {
            "configured_workers": workers,
            "simultaneously_active_sut_workers": peak,
            "concurrent_loopback_requests": count,
            "one_additional_request_queued": count > peak,
        }

    def close(self) -> dict[str, object]:
        self._stop.set()
        self.listener.close()
        self._accept_thread.join(timeout=2.0)
        with self._handlers_lock:
            handlers = list(self._handlers)
        for handler in handlers:
            handler.join(timeout=float(self.profile["socket_timeout_seconds"]))
        alive = sum(handler.is_alive() for handler in handlers)
        self.executor.shutdown(wait=True, cancel_futures=False)
        padding = self.padder.snapshot()
        if alive or padding["pending"] or self._errors:
            raise RuntimeError(
                "unclean E9 server shutdown: "
                f"alive={alive}, padding={padding}, errors={self._errors}"
            )
        return {
            "handler_threads_created": len(handlers),
            "handler_threads_alive_after_shutdown": alive,
            "padding": padding,
            "server_errors": list(self._errors),
        }


def _collect_external(
    host: str,
    port: int,
    coordinate: Coordinate,
    timeout_seconds: float,
) -> dict[str, object]:
    request = build_request(coordinate)
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    connection.settimeout(timeout_seconds)
    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    total_started = time.perf_counter_ns()
    connection.connect((host, port))
    connected_ns = time.perf_counter_ns()
    local_host, local_port = connection.getsockname()
    peer_host, peer_port = connection.getpeername()
    request_started = time.perf_counter_ns()
    connection.sendall(request)
    connection.shutdown(socket.SHUT_WR)
    chunks: list[bytes] = []
    recv_sizes: list[int] = []
    first_byte_ns: int | None = None
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            eof_ns = time.perf_counter_ns()
            break
        if first_byte_ns is None:
            first_byte_ns = time.perf_counter_ns()
        chunks.append(chunk)
        recv_sizes.append(len(chunk))
    connection.close()
    if first_byte_ns is None:
        raise RuntimeError("loopback server closed without a response")
    response = b"".join(chunks)
    status, body, order = _decode_response(response)
    return {
        "request": {
            "bytes": len(request),
            "sha256": hashlib.sha256(request).hexdigest(),
        },
        "response": {
            "status": status,
            "bytes": len(response),
            "sha256": hashlib.sha256(response).hexdigest(),
            "frame_order": order,
            "frame_count": len(order),
            "receive_call_sizes": recv_sizes,
            "client_observed_eof": True,
        },
        "connection": {
            "transport": "TCP_IPV4_LOOPBACK",
            "address_family": "AF_INET",
            "socket_type": "SOCK_STREAM",
            "protocol": "IPPROTO_TCP",
            "local_host": local_host,
            "local_port": local_port,
            "peer_host": peer_host,
            "peer_port": peer_port,
            "local_is_loopback": local_host == "127.0.0.1",
            "peer_is_loopback": peer_host == "127.0.0.1",
            "client_tcp_nodelay": True,
            "client_half_closed_write": True,
            "connection_reused": False,
        },
        "timing": {
            "clock": "time.perf_counter_ns",
            "connect_ns": connected_ns - total_started,
            "request_to_first_byte_ns": first_byte_ns - request_started,
            "request_to_eof_ns": eof_ns - request_started,
            "connect_start_to_eof_ns": eof_ns - total_started,
        },
        "decoded_body": body.decode("ascii"),
    }


def _git_state(root: Path = ROOT) -> dict[str, object]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {"commit": commit, "clean": status == "", "status": status.splitlines()}


def _tracked_source_snapshot(root: Path = ROOT) -> dict[str, object]:
    git_state = _validate_git_state(_git_state(root), "tracked source Git state")
    if git_state["clean"] is not True or git_state["status"] != []:
        raise EvidenceError("tracked source snapshot requires a clean Git worktree")
    commit = str(git_state["commit"])
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    index = subprocess.run(
        ["git", "ls-files", "--stage", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    manifest = hashlib.sha256()
    file_count = 0
    for entry in index.split(b"\0"):
        if not entry:
            continue
        header, separator, path_bytes = entry.partition(b"\t")
        if not separator:
            raise EvidenceError("tracked source index entry lacks a path separator")
        header_fields = header.split(b" ")
        if len(header_fields) != 3:
            raise EvidenceError("tracked source index entry has invalid metadata")
        mode, object_id, stage = header_fields
        if stage != b"0":
            raise EvidenceError("tracked source index contains an unresolved merge stage")
        path_parts = path_bytes.split(b"/")
        if (
            path_bytes.startswith(b"/")
            or not path_parts
            or any(part in {b"", b".", b".."} for part in path_parts)
        ):
            raise EvidenceError("tracked source index path is unsafe")
        path = root.joinpath(*(os.fsdecode(part) for part in path_parts))
        try:
            before = path.lstat()
            if mode == b"120000":
                if not stat.S_ISLNK(before.st_mode):
                    raise EvidenceError("tracked source symlink mode differs from the worktree")
                content = os.fsencode(os.readlink(path))
            elif mode in {b"100644", b"100755"}:
                if not stat.S_ISREG(before.st_mode):
                    raise EvidenceError("tracked source file mode differs from the worktree")
                content = path.read_bytes()
            else:
                raise EvidenceError("tracked source contains an unsupported index mode")
            after = path.lstat()
        except OSError as exc:
            raise EvidenceError("tracked source file could not be hashed") from exc
        if (
            not _same_identity(after, before.st_dev, before.st_ino)
            or after.st_mode != before.st_mode
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
        ):
            raise EvidenceError("tracked source file changed while its manifest was hashed")
        content_digest = hashlib.sha256(content).digest()
        for field in (path_bytes, mode, object_id, content_digest):
            manifest.update(struct.pack("!Q", len(field)))
            manifest.update(field)
        file_count += 1
    snapshot = {
        "schema": PROCESS_LONG_TEST_SOURCE_SCHEMA,
        "commit": commit,
        "git_tree": tree,
        "manifest_sha256": manifest.hexdigest(),
        "tracked_file_count": file_count,
        "git_state": git_state,
    }
    return _validate_tracked_source_snapshot(snapshot, "tracked source snapshot")


def _validate_tracked_source_snapshot(value: object, label: str) -> dict[str, Any]:
    snapshot = _mapping(value, label)
    _exact_keys(
        snapshot,
        {
            "schema",
            "commit",
            "git_tree",
            "manifest_sha256",
            "tracked_file_count",
            "git_state",
        },
        label,
    )
    _exact_value(snapshot["schema"], PROCESS_LONG_TEST_SOURCE_SCHEMA, f"{label} schema")
    if not _full_commit(snapshot["commit"]):
        raise EvidenceError(f"{label} commit must be a full lowercase commit")
    tree = snapshot["git_tree"]
    if (
        type(tree) is not str
        or len(tree) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in tree)
    ):
        raise EvidenceError(f"{label} Git tree ID is invalid")
    manifest = snapshot["manifest_sha256"]
    if (
        type(manifest) is not str
        or len(manifest) != 64
        or any(character not in "0123456789abcdef" for character in manifest)
    ):
        raise EvidenceError(f"{label} manifest digest is invalid")
    _integer(snapshot["tracked_file_count"], f"{label} tracked file count", 1)
    git_state = _validate_git_state(snapshot["git_state"], f"{label} Git state")
    if git_state["clean"] is not True or git_state["status"] != []:
        raise EvidenceError(f"{label} Git state must be clean")
    _exact_value(snapshot["commit"], git_state["commit"], f"{label} Git commit binding")
    return snapshot


def _validate_sealed_archive_identity(value: object, label: str) -> dict[str, Any]:
    identity = _mapping(value, label)
    _exact_keys(
        identity,
        {
            "schema",
            "commit",
            "git_tree",
            "sha256",
            "byte_count",
            "execution",
            "seal_mask",
        },
        label,
    )
    _exact_value(identity["schema"], PROCESS_LONG_TEST_ARCHIVE_SCHEMA, f"{label} schema")
    if not _full_commit(identity["commit"]):
        raise EvidenceError(f"{label} commit must be a full lowercase commit")
    tree = identity["git_tree"]
    if (
        type(tree) is not str
        or len(tree) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in tree)
    ):
        raise EvidenceError(f"{label} Git tree ID is invalid")
    digest = identity["sha256"]
    if (
        type(digest) is not str
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise EvidenceError(f"{label} digest is invalid")
    byte_count = _integer(identity["byte_count"], f"{label} byte count", 1)
    if byte_count > PROCESS_LONG_TEST_ARCHIVE_MAX_BYTES:
        raise EvidenceError(f"{label} exceeds its byte limit")
    _exact_value(
        identity["execution"], PROCESS_LONG_TEST_ARCHIVE_EXECUTION, f"{label} execution"
    )
    _exact_value(
        identity["seal_mask"], PROCESS_LONG_TEST_ARCHIVE_SEAL_MASK, f"{label} seal mask"
    )
    return identity


def _build_sealed_child_archive(
    source_snapshot_value: object,
) -> tuple[bytes, dict[str, Any]]:
    source_snapshot = _validate_tracked_source_snapshot(
        source_snapshot_value, "sealed archive source snapshot"
    )
    archived_tree = subprocess.run(
        ["git", "rev-parse", f"{source_snapshot['commit']}^{{tree}}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    _exact_value(
        archived_tree,
        source_snapshot["git_tree"],
        "sealed child archive Git tree binding",
    )
    completed = subprocess.run(
        ["git", "archive", "--format=zip", str(source_snapshot["commit"])],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    if not completed.stdout or len(completed.stdout) > PROCESS_LONG_TEST_ARCHIVE_MAX_BYTES:
        raise EvidenceError("sealed child Git archive is empty or exceeds its byte limit")
    buffer = io.BytesIO(completed.stdout)
    runner_name = "experiments/runners/failure_timing_bench.py"
    with zipfile.ZipFile(buffer, mode="a", compression=zipfile.ZIP_DEFLATED) as archive:
        names = set(archive.namelist())
        if runner_name not in names:
            raise EvidenceError("sealed child Git archive lacks the E9 runner")
        if "__main__.py" in names or PROCESS_LONG_TEST_ARCHIVE_MODULE in names:
            raise EvidenceError("sealed child Git archive collides with its fixed entrypoint")
        runner_source = archive.read(runner_name)
        for name, payload in (
            (PROCESS_LONG_TEST_ARCHIVE_MODULE, runner_source),
            ("__main__.py", PROCESS_LONG_TEST_ARCHIVE_MAIN),
        ):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = (stat.S_IFREG | 0o444) << 16
            archive.writestr(entry, payload)
    archive_bytes = buffer.getvalue()
    if len(archive_bytes) > PROCESS_LONG_TEST_ARCHIVE_MAX_BYTES:
        raise EvidenceError("sealed child zipapp exceeds its byte limit")
    identity = {
        "schema": PROCESS_LONG_TEST_ARCHIVE_SCHEMA,
        "commit": source_snapshot["commit"],
        "git_tree": source_snapshot["git_tree"],
        "sha256": hashlib.sha256(archive_bytes).hexdigest(),
        "byte_count": len(archive_bytes),
        "execution": PROCESS_LONG_TEST_ARCHIVE_EXECUTION,
        "seal_mask": PROCESS_LONG_TEST_ARCHIVE_SEAL_MASK,
    }
    return archive_bytes, _validate_sealed_archive_identity(
        identity, "sealed child archive identity"
    )


def _create_sealed_archive_memfd(
    archive_bytes: bytes,
    expected_identity_value: object,
) -> int:
    if platform.system() != "Linux" or os.name != "posix":
        raise EvidenceError("sealed child archive requires Linux memfd")
    creator = getattr(os, "memfd_create", None)
    if creator is None:
        raise EvidenceError("Linux memfd_create is unavailable")
    expected_identity = _validate_sealed_archive_identity(
        expected_identity_value, "expected sealed child archive"
    )
    _exact_value(
        hashlib.sha256(archive_bytes).hexdigest(),
        expected_identity["sha256"],
        "sealed child archive byte digest",
    )
    _exact_value(
        len(archive_bytes), expected_identity["byte_count"], "sealed child archive byte count"
    )
    descriptor = creator(
        "traps-e9-sealed-source",
        flags=getattr(os, "MFD_CLOEXEC", 0x0001)
        | getattr(os, "MFD_ALLOW_SEALING", 0x0002),
    )
    try:
        offset = 0
        while offset < len(archive_bytes):
            written = os.write(descriptor, archive_bytes[offset:])
            if written <= 0:
                raise OSError("sealed child archive write made no progress")
            offset += written
        import fcntl

        add_seals = getattr(fcntl, "F_ADD_SEALS", 1033)
        get_seals = getattr(fcntl, "F_GET_SEALS", 1034)
        fcntl.fcntl(descriptor, add_seals, PROCESS_LONG_TEST_ARCHIVE_SEAL_MASK)
        actual_seals = fcntl.fcntl(descriptor, get_seals)
        _exact_value(
            actual_seals,
            PROCESS_LONG_TEST_ARCHIVE_SEAL_MASK,
            "sealed child archive active seal mask",
        )
        _exact_value(
            os.fstat(descriptor).st_size,
            len(archive_bytes),
            "sealed child archive memfd size",
        )
        os.lseek(descriptor, 0, os.SEEK_SET)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _probe_sealed_child_archive(expected_identity_value: object) -> dict[str, Any]:
    expected_identity = _validate_sealed_archive_identity(
        expected_identity_value, "seed-child expected sealed archive"
    )
    descriptor_text = os.environ.get("TRAPS_E9_SEALED_ARCHIVE_FD")
    if (
        type(descriptor_text) is not str
        or not descriptor_text.isascii()
        or not descriptor_text.isdigit()
    ):
        raise EvidenceError("seed child lacks its sealed archive descriptor")
    descriptor = int(descriptor_text)
    _exact_value(
        sys.argv[0],
        f"/proc/self/fd/{descriptor}",
        "seed child executed sealed archive descriptor",
    )
    try:
        identity = os.fstat(descriptor)
        link_target = os.readlink(f"/proc/self/fd/{descriptor}")
    except OSError as exc:
        raise EvidenceError("seed child cannot inspect its sealed archive descriptor") from exc
    if not stat.S_ISREG(identity.st_mode) or identity.st_size != expected_identity["byte_count"]:
        raise EvidenceError("seed child sealed archive descriptor identity differs")
    if not link_target.startswith("/memfd:traps-e9-sealed-source"):
        raise EvidenceError("seed child did not execute from the expected memfd")
    import fcntl

    actual_seals = fcntl.fcntl(descriptor, getattr(fcntl, "F_GET_SEALS", 1034))
    _exact_value(
        actual_seals,
        expected_identity["seal_mask"],
        "seed child sealed archive seal mask",
    )
    digest = hashlib.sha256()
    offset = 0
    while offset < identity.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, identity.st_size - offset), offset)
        if not chunk:
            raise EvidenceError("seed child sealed archive ended before its declared size")
        digest.update(chunk)
        offset += len(chunk)
    _exact_value(digest.hexdigest(), expected_identity["sha256"], "sealed archive digest")
    return expected_identity


def _clock_metadata(name: str) -> dict[str, object]:
    info = time.get_clock_info(name)
    return {
        "implementation": info.implementation,
        "monotonic": info.monotonic,
        "adjustable": info.adjustable,
        "resolution_seconds": info.resolution,
    }


def _verify_root_signed_document(
    document: Mapping[str, Any], root_public_key_hex: str, label: str
) -> dict[str, Any]:
    if len(root_public_key_hex) != 64:
        raise EvidenceError(f"{label} requires an explicit 32-byte auditor root public key")
    signature = document.get("signature_hex")
    if type(signature) is not str or len(signature) != 128:
        raise EvidenceError(f"{label} has an invalid signature encoding")
    body = {key: value for key, value in document.items() if key != "signature_hex"}
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(bytes.fromhex(root_public_key_hex)).verify(
            bytes.fromhex(signature), _canonical(body)
        )
    except ImportError as exc:
        raise EvidenceError("formal E9 verification requires cryptography") from exc
    except (ValueError, InvalidSignature) as exc:
        raise EvidenceError(f"{label} is not signed by the supplied auditor trust root") from exc
    return dict(document)


def _registry_id(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EvidenceError(f"{label} must be 32-byte lowercase hex")
    return value


def _require_registry_identity(
    registry: Path,
    *,
    namespace: str,
    expected_registry_id: object,
    expected_uri: object,
) -> None:
    if registry.is_symlink() or not registry.is_dir():
        raise EvidenceError("replay registry must be a pre-existing non-symlink directory")
    _exact_value(
        expected_uri,
        registry.resolve().as_uri(),
        f"auditor-bound {namespace} registry URI",
    )
    identity_path = registry / REGISTRY_IDENTITY_FILENAME
    if identity_path.is_symlink() or not identity_path.is_file():
        raise EvidenceError("replay registry lacks its pre-provisioned identity document")
    identity = load_json(identity_path)
    _exact_keys(
        identity,
        {"schema", "registry_id", "namespace", "storage_contract"},
        "replay registry identity",
    )
    _exact_value(identity["schema"], REGISTRY_IDENTITY_SCHEMA, "registry identity schema")
    _exact_value(
        identity["registry_id"],
        _registry_id(expected_registry_id, f"{namespace} registry ID"),
        "auditor-bound registry ID",
    )
    _exact_value(identity["namespace"], namespace, "registry identity namespace")
    _exact_value(
        identity["storage_contract"],
        REGISTRY_STORAGE_CONTRACT,
        "registry identity storage contract",
    )


def _opaque_id(value: object, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise EvidenceError(f"{label} must be an opaque 32-byte lowercase-hex identifier")
    return value


def _nonempty_ascii(value: object, label: str, maximum: int = 128) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or not value.isascii()
        or any(not 32 <= ord(character) <= 126 for character in value)
    ):
        raise EvidenceError(f"{label} must be a nonempty printable ASCII string")
    return value


def _file_uri_path(value: object, label: str) -> Path:
    uri = _nonempty_ascii(value, label, 2048)
    parsed = urlparse(uri)
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
    ):
        raise EvidenceError(f"{label} must be a local file URI without query or fragment")
    path = Path(url2pathname(parsed.path))
    if not path.is_absolute():
        raise EvidenceError(f"{label} must identify an absolute path")
    return path


def _external_document_uri(value: object, label: str) -> str:
    uri = _nonempty_ascii(value, label, 2048)
    parsed = urlparse(uri)
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise EvidenceError(f"{label} cannot contain credentials, query, or fragment")
    if parsed.scheme == "file":
        _file_uri_path(uri, label)
    elif parsed.scheme != "https" or not parsed.netloc:
        raise EvidenceError(f"{label} must be an absolute file or HTTPS URI")
    return uri


_WINDOWS_LOCAL_FILESYSTEMS = {"NTFS", "ReFS"}
_LINUX_LOCAL_FILESYSTEMS = {
    "btrfs",
    "ext2",
    "ext3",
    "ext4",
    "f2fs",
    "overlay",
    "tmpfs",
    "xfs",
    "zfs",
}


def _expected_lock_api(system: object) -> str:
    if system == "Windows":
        return WINDOWS_LOCK_API
    if system == "Linux":
        return POSIX_LOCK_API
    raise EvidenceError("exclusive anchor locking is unsupported on this host system")


def _validate_lock_filesystem(value: object, system: object) -> dict[str, Any]:
    filesystem = _mapping(value, "exclusive lock filesystem evidence")
    _exact_keys(
        filesystem,
        {
            "policy",
            "platform",
            "probe_api",
            "filesystem_type",
            "locality",
            "network_filesystem_forbidden",
        },
        "exclusive lock filesystem evidence",
    )
    _exact_value(filesystem["policy"], LOCK_FILESYSTEM_POLICY, "lock filesystem policy")
    _exact_value(filesystem["platform"], system, "lock filesystem platform")
    _exact_value(
        filesystem["network_filesystem_forbidden"],
        True,
        "network-filesystem exclusion",
    )
    filesystem_type = _nonempty_ascii(
        filesystem["filesystem_type"], "lock filesystem type", 64
    )
    if system == "Windows":
        _exact_value(
            filesystem["probe_api"],
            "WIN32_GETVOLUMEPATHNAMEW_GETDRIVETYPEW_GETVOLUMEINFORMATIONW_V1",
            "Windows lock filesystem probe API",
        )
        _exact_value(
            filesystem["locality"],
            "LOCAL_FIXED_VOLUME",
            "Windows lock filesystem locality",
        )
        if filesystem_type not in _WINDOWS_LOCAL_FILESYSTEMS:
            raise EvidenceError("Windows lock anchor requires local NTFS or ReFS")
    elif system == "Linux":
        _exact_value(
            filesystem["probe_api"],
            "LINUX_PROC_SELF_MOUNTINFO_LONGEST_MOUNT_V1",
            "Linux lock filesystem probe API",
        )
        _exact_value(
            filesystem["locality"],
            "LOCAL_KERNEL_FILESYSTEM",
            "Linux lock filesystem locality",
        )
        if filesystem_type not in _LINUX_LOCAL_FILESYSTEMS:
            raise EvidenceError("Linux lock anchor filesystem is remote or unsupported")
    else:
        raise EvidenceError("exclusive anchor filesystem probing is unsupported")
    return filesystem


def _validate_exclusive_lock_contract(
    value: object, system: object
) -> dict[str, Any]:
    lock = _mapping(value, "exclusive lock contract")
    _exact_keys(
        lock,
        {
            "schema",
            "lock_id",
            "marker_uri",
            "anchor_uri",
            "anchor_bytes_hex",
            "anchor_sha256",
            "anchor_device",
            "anchor_inode",
            "lock_byte_offset",
            "lock_byte_length",
            "expected_lock_api",
            "filesystem",
        },
        "exclusive lock contract",
    )
    _exact_value(
        lock["schema"], EXCLUSIVE_LOCK_CONTRACT_SCHEMA, "exclusive lock contract schema"
    )
    _opaque_id(lock["lock_id"], "exclusive lock ID")
    marker_path = _file_uri_path(lock["marker_uri"], "exclusive lock marker URI")
    anchor_path = _file_uri_path(lock["anchor_uri"], "exclusive lock anchor URI")
    if marker_path.absolute().as_uri() != lock["marker_uri"]:
        raise EvidenceError("exclusive lock marker URI must be canonical")
    if anchor_path.absolute().as_uri() != lock["anchor_uri"]:
        raise EvidenceError("exclusive lock anchor URI must be canonical")
    if marker_path == anchor_path:
        raise EvidenceError("exclusive lock marker cannot alias its anchor")
    anchor_hex = lock["anchor_bytes_hex"]
    if (
        type(anchor_hex) is not str
        or len(anchor_hex) != LOCK_ANCHOR_BYTE_COUNT * 2
        or any(character not in "0123456789abcdef" for character in anchor_hex)
    ):
        raise EvidenceError("exclusive lock anchor must bind 32 lowercase-hex bytes")
    anchor_bytes = bytes.fromhex(anchor_hex)
    _exact_value(
        lock["anchor_sha256"],
        hashlib.sha256(anchor_bytes).hexdigest(),
        "exclusive lock anchor content digest",
    )
    _integer(lock["anchor_device"], "exclusive lock anchor device", 0)
    _integer(lock["anchor_inode"], "exclusive lock anchor inode", 1)
    _exact_value(lock["lock_byte_offset"], 0, "exclusive anchor lock byte offset")
    _exact_value(
        lock["lock_byte_length"],
        len(anchor_bytes),
        "exclusive anchor lock byte length",
    )
    _exact_value(
        lock["expected_lock_api"],
        _expected_lock_api(system),
        "exclusive anchor lock API",
    )
    _validate_lock_filesystem(lock["filesystem"], system)
    return lock


def _validate_service_assertions(value: object, label: str) -> list[dict[str, Any]]:
    if type(value) is not list or not value:
        raise EvidenceError(f"{label} must be a nonempty array")
    result: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        assertion = _mapping(item, f"{label}[{index}]")
        _exact_keys(
            assertion,
            {"service_id", "load_state", "active_state", "sub_state"},
            f"{label}[{index}]",
        )
        service_id = _nonempty_ascii(assertion["service_id"], "service ID", 128)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*\.service", service_id) is None:
            raise EvidenceError("service ID contains unsupported characters")
        for key in ("load_state", "active_state", "sub_state"):
            _nonempty_ascii(assertion[key], f"service assertion {key}", 64)
        result.append(dict(assertion))
    service_ids = [str(item["service_id"]) for item in result]
    if service_ids != sorted(service_ids) or len(service_ids) != len(set(service_ids)):
        raise EvidenceError(f"{label} must be uniquely sorted by service_id")
    return result


def _validate_python_runtime_identity(value: object, label: str) -> dict[str, Any]:
    runtime = _mapping(value, label)
    _exact_keys(
        runtime,
        {
            "implementation",
            "version",
            "cache_tag",
            "executable_sha256",
            "launcher_sha256",
            "environment",
        },
        label,
    )
    for key in ("implementation", "version", "cache_tag"):
        _nonempty_ascii(runtime[key], f"{label} {key}")
    _opaque_id(runtime["executable_sha256"], f"{label} executable digest")
    _opaque_id(runtime["launcher_sha256"], f"{label} launcher digest")
    environment = _mapping(runtime["environment"], f"{label} environment")
    _exact_keys(
        environment,
        {"prefix_id", "pyvenv_config_sha256", "dependency_versions"},
        f"{label} environment",
    )
    _opaque_id(environment["prefix_id"], f"{label} environment prefix ID")
    pyvenv_digest = environment["pyvenv_config_sha256"]
    if pyvenv_digest is not None:
        _opaque_id(pyvenv_digest, f"{label} pyvenv configuration digest")
    dependencies = _mapping(
        environment["dependency_versions"], f"{label} dependency versions"
    )
    _exact_keys(
        dependencies,
        {"argon2-cffi", "argon2-cffi-bindings", "cryptography", "PyYAML"},
        f"{label} dependency versions",
    )
    for distribution, version in dependencies.items():
        _nonempty_ascii(version, f"{label} {distribution} version")
    return runtime


def _validate_host_execution_contract(value: object) -> dict[str, Any]:
    contract = _mapping(value, "host execution contract")
    _exact_keys(
        contract,
        {
            "schema",
            "host_id",
            "system",
            "architecture",
            "logical_cpu_count",
            "allowed_cpu_affinity",
            "python_runtime",
            "power_governor_assertion",
            "max_load_average_1m",
            "required_service_states",
            "seed_process_isolation",
            "exclusive_lock",
        },
        "host execution contract",
    )
    _exact_value(contract["schema"], HOST_CONTRACT_SCHEMA, "host contract schema")
    _opaque_id(contract["host_id"], "host ID")
    _nonempty_ascii(contract["system"], "host system")
    _nonempty_ascii(contract["architecture"], "host architecture")
    cpu_count = _integer(contract["logical_cpu_count"], "logical CPU count", 1)
    affinity = contract["allowed_cpu_affinity"]
    if type(affinity) is not list or not affinity:
        raise EvidenceError("allowed CPU affinity must be a nonempty array")
    cpus = [_integer(cpu, "allowed CPU", 0) for cpu in affinity]
    if cpus != sorted(set(cpus)) or cpus[-1] >= cpu_count:
        raise EvidenceError("allowed CPU affinity must be sorted, unique, and in range")

    _validate_python_runtime_identity(contract["python_runtime"], "Python runtime contract")

    power = _mapping(contract["power_governor_assertion"], "power/governor assertion")
    mode = power.get("mode")
    if mode == "RUNTIME_VERIFIED":
        _exact_keys(
            power,
            {"mode", "probe", "expected_value"},
            "runtime power/governor assertion",
        )
        _exact_value(
            power["probe"],
            "LINUX_SCALING_GOVERNOR",
            "runtime power/governor probe",
        )
        _nonempty_ascii(power["expected_value"], "expected power/governor value", 64)
    elif mode == "EXTERNAL_ATTESTATION":
        _exact_keys(
            power,
            {
                "mode",
                "attestation_id",
                "expected_value",
                "document_uri",
                "document_sha256",
            },
            "external power/governor assertion",
        )
        _opaque_id(power["attestation_id"], "external power attestation ID")
        _nonempty_ascii(
            power["expected_value"],
            "auditor-signed external asserted governor value",
            64,
        )
        _external_document_uri(power["document_uri"], "external power document URI")
        _opaque_id(power["document_sha256"], "external power document digest")
    else:
        raise EvidenceError("power/governor assertion mode is unsupported")

    _number(contract["max_load_average_1m"], "maximum one-minute load average")
    _validate_service_assertions(
        contract["required_service_states"], "required service-state assertions"
    )
    _exact_value(
        contract["seed_process_isolation"],
        PROCESS_ISOLATION_DECLARATION,
        "seed process-isolation declaration",
    )
    _validate_exclusive_lock_contract(contract["exclusive_lock"], contract["system"])
    return contract


def _probe_host_baseline() -> dict[str, object]:
    logical_cpu_count = os.cpu_count()
    if logical_cpu_count is None:
        raise EvidenceError("logical CPU count is unavailable")
    return {
        "system": platform.system(),
        "architecture": platform.machine(),
        "logical_cpu_count": logical_cpu_count,
    }


def _require_windows_affinity_capacity(logical_cpu_count: object) -> None:
    count = _integer(logical_cpu_count, "Windows logical CPU count", 1)
    capacity = ctypes.sizeof(ctypes.c_size_t) * 8
    if count > capacity:
        raise EvidenceError(
            "Windows processor-group affinity exceeds the supported single-mask capacity"
        )


def _probe_cpu_affinity() -> list[int]:
    getter = getattr(os, "sched_getaffinity", None)
    if getter is not None:
        return sorted(int(cpu) for cpu in getter(0))
    if os.name == "nt":
        import ctypes

        _require_windows_affinity_capacity(os.cpu_count())
        process_mask = ctypes.c_size_t()
        system_mask = ctypes.c_size_t()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.GetProcessAffinityMask.argtypes = (
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_size_t),
            ctypes.POINTER(ctypes.c_size_t),
        )
        kernel32.GetProcessAffinityMask.restype = ctypes.c_int
        if not kernel32.GetProcessAffinityMask(
            kernel32.GetCurrentProcess(),
            ctypes.byref(process_mask),
            ctypes.byref(system_mask),
        ):
            raise EvidenceError("cannot read the process CPU affinity")
        return [
            index
            for index in range(process_mask.value.bit_length())
            if process_mask.value & (1 << index)
        ]
    raise EvidenceError("this runtime cannot verify process CPU affinity")


def _read_linux_value(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8", errors="strict").strip()
    except (OSError, UnicodeError):
        return "UNAVAILABLE"
    return value or "UNAVAILABLE"


def _probe_cpu_frequency_policy(frequency_root: Path) -> dict[str, str]:
    fields = {
        "scaling_driver": _read_linux_value(frequency_root / "scaling_driver"),
        "scaling_governor": _read_linux_value(frequency_root / "scaling_governor"),
        "scaling_min_freq_khz": _read_linux_value(
            frequency_root / "scaling_min_freq"
        ),
        "scaling_max_freq_khz": _read_linux_value(
            frequency_root / "scaling_max_freq"
        ),
        "scaling_current_freq_khz": _read_linux_value(
            frequency_root / "scaling_cur_freq"
        ),
    }
    available_count = sum(value != "UNAVAILABLE" for value in fields.values())
    status = (
        "AVAILABLE"
        if available_count == len(fields)
        else "PARTIAL"
        if available_count
        else "UNAVAILABLE"
    )
    return {"status": status, **fields}


def _probe_linux_numa_maps() -> dict[str, object]:
    try:
        numa_payload = Path("/proc/self/numa_maps").read_bytes()
        numa_text = numa_payload.decode("utf-8")
    except (OSError, UnicodeError):
        return {
            "status": "UNAVAILABLE",
            "reason": "PROC_SELF_NUMA_MAPS_UNAVAILABLE",
            "line_count": 0,
            "mapped_pages": 0,
            "node_pages": {},
            "policy_counts": {},
        }

    node_pages: dict[str, int] = {}
    policy_counts: dict[str, int] = {}
    lines = [line for line in numa_text.splitlines() if line]
    for line in lines:
        fields = line.split()
        policy = fields[1].split("=", 1)[0] if len(fields) > 1 else "UNKNOWN"
        policy_counts[policy] = policy_counts.get(policy, 0) + 1
        for node, pages in re.findall(r"\bN(\d+)=(\d+)\b", line):
            node_pages[node] = node_pages.get(node, 0) + int(pages)
    return {
        "status": "AVAILABLE",
        "reason": None,
        "line_count": len(lines),
        "mapped_pages": sum(node_pages.values()),
        "node_pages": dict(sorted(node_pages.items(), key=lambda item: int(item[0]))),
        "policy_counts": dict(sorted(policy_counts.items())),
    }


def _parse_linux_id_list(value: str, label: str) -> list[int]:
    result: list[int] = []
    for part in value.split(","):
        token = part.strip()
        if not token:
            raise EvidenceError(f"{label} contains an empty range")
        if "-" in token:
            bounds = token.split("-", 1)
            if len(bounds) != 2 or not all(bound.isdigit() for bound in bounds):
                raise EvidenceError(f"{label} contains an invalid range")
            start, end = (int(bound) for bound in bounds)
            if end < start:
                raise EvidenceError(f"{label} contains a descending range")
            result.extend(range(start, end + 1))
        elif token.isdigit():
            result.append(int(token))
        else:
            raise EvidenceError(f"{label} contains an invalid identifier")
    if not result or result != sorted(set(result)):
        raise EvidenceError(f"{label} must describe sorted unique identifiers")
    return result


def _probe_linux_auth_worker_placement(native_id: int) -> dict[str, object]:
    task_root = Path(f"/proc/self/task/{native_id}")
    try:
        status_text = (task_root / "status").read_text(encoding="utf-8", errors="strict")
        stat_text = (task_root / "stat").read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        raise EvidenceError("cannot read auth-worker Linux task placement") from exc
    status_fields: dict[str, str] = {}
    for line in status_text.splitlines():
        key, separator, raw_value = line.partition(":")
        if separator:
            status_fields[key] = raw_value.strip()
    cpus_allowed_list = status_fields.get("Cpus_allowed_list", "")
    mems_allowed_list = status_fields.get("Mems_allowed_list", "")
    _parse_linux_id_list(cpus_allowed_list, "auth-worker Cpus_allowed_list")
    _parse_linux_id_list(mems_allowed_list, "auth-worker Mems_allowed_list")

    closing_parenthesis = stat_text.rfind(")")
    if closing_parenthesis < 0:
        raise EvidenceError("auth-worker Linux task stat is malformed")
    remaining_fields = stat_text[closing_parenthesis + 1 :].split()
    processor_index = 39 - 3
    if len(remaining_fields) <= processor_index:
        raise EvidenceError("auth-worker Linux task stat lacks its processor field")
    try:
        last_cpu = int(remaining_fields[processor_index])
    except ValueError as exc:
        raise EvidenceError("auth-worker last CPU is malformed") from exc
    cpu_nodes = sorted(Path(f"/sys/devices/system/cpu/cpu{last_cpu}").glob("node[0-9]*"))
    last_cpu_numa_node: int | str = (
        int(cpu_nodes[0].name.removeprefix("node")) if cpu_nodes else "UNAVAILABLE"
    )
    return {
        "cpus_allowed_list": cpus_allowed_list,
        "mems_allowed_list": mems_allowed_list,
        "last_cpu": last_cpu,
        "last_cpu_numa_node": last_cpu_numa_node,
    }


def _probe_loaded_shared_libraries(name_patterns: Sequence[str]) -> dict[str, object]:
    try:
        maps_text = Path("/proc/self/maps").read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return {
            "status": "UNAVAILABLE",
            "reason": "PROC_SELF_MAPS_UNAVAILABLE",
            "basenames": [],
        }
    basenames = sorted(
        {
            Path(fields[-1]).name
            for line in maps_text.splitlines()
            if (fields := line.split())
            and len(fields) >= 6
            and fields[-1].startswith("/")
            and any(pattern in Path(fields[-1]).name.lower() for pattern in name_patterns)
        }
    )
    return {
        "status": "AVAILABLE" if basenames else "UNAVAILABLE",
        "reason": None if basenames else "NO_SEPARATE_MATCHING_SHARED_LIBRARY_MAPPING",
        "basenames": basenames,
    }


def _probe_preregistered_measurement_environment(phase: str) -> dict[str, object]:
    if phase not in {"PRE_MEASUREMENT", "POST_MEASUREMENT"}:
        raise EvidenceError("v5 measurement environment phase is invalid")
    if platform.system() != "Linux" or os.name != "posix":
        raise EvidenceError("v5 measurement environment probing requires a real Linux runtime")

    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise EvidenceError("cannot read Linux CPU identity for v5 measurement") from exc
    cpu_models = sorted(
        {
            match.group(1).strip()
            for match in re.finditer(
                r"^(?:model name|Hardware|Processor)\s*:\s*(.+)$",
                cpuinfo,
                flags=re.MULTILINE,
            )
            if match.group(1).strip()
        }
    ) or ["UNAVAILABLE"]
    microcodes = sorted(
        {
            match.group(1).strip()
            for match in re.finditer(
                r"^microcode\s*:\s*(.+)$", cpuinfo, flags=re.MULTILINE
            )
            if match.group(1).strip()
        }
    ) or ["UNAVAILABLE"]

    process_affinity = _probe_cpu_affinity()
    affinity_getter = getattr(os, "sched_getaffinity", None)
    if affinity_getter is None:
        raise EvidenceError("Linux v5 measurement cannot inspect thread CPU affinity")
    threads: list[dict[str, object]] = []
    for task_path in sorted(
        Path("/proc/self/task").iterdir(), key=lambda path: int(path.name)
    ):
        try:
            tid = int(task_path.name)
            allowed = sorted(int(cpu) for cpu in affinity_getter(tid))
        except (OSError, ValueError, ProcessLookupError):
            continue
        threads.append({"tid": tid, "allowed_cpus": allowed})
    if not threads:
        raise EvidenceError("Linux v5 measurement found no inspectable process threads")

    cpu_policies: list[dict[str, object]] = []
    for cpu in process_affinity:
        cpu_root = Path(f"/sys/devices/system/cpu/cpu{cpu}")
        nodes = sorted(cpu_root.glob("node[0-9]*"))
        numa_node: int | str = (
            int(nodes[0].name.removeprefix("node")) if nodes else "UNAVAILABLE"
        )
        frequency_root = cpu_root / "cpufreq"
        cpu_policies.append(
            {
                "cpu": cpu,
                "numa_node": numa_node,
                "cpufreq": _probe_cpu_frequency_policy(frequency_root),
            }
        )

    numa_maps = _probe_linux_numa_maps()

    sensors: list[dict[str, object]] = []
    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        temperature = _read_linux_value(zone / "temp")
        if temperature == "UNAVAILABLE" or not temperature.lstrip("-").isdigit():
            continue
        sensor_type = _read_linux_value(zone / "type")
        sensors.append(
            {
                "sensor": f"thermal:{zone.name}:{sensor_type}",
                "temperature_millicelsius": int(temperature),
            }
        )
    for hwmon in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        device_name = _read_linux_value(hwmon / "name")
        for input_path in sorted(hwmon.glob("temp*_input")):
            temperature = _read_linux_value(input_path)
            if temperature == "UNAVAILABLE" or not temperature.lstrip("-").isdigit():
                continue
            stem = input_path.name.removesuffix("_input")
            label = _read_linux_value(hwmon / f"{stem}_label")
            sensors.append(
                {
                    "sensor": f"hwmon:{device_name}:{label}:{stem}",
                    "temperature_millicelsius": int(temperature),
                }
            )
    thermal = {
        "status": "AVAILABLE" if sensors else "UNAVAILABLE",
        "reason": None if sensors else "NO_READABLE_THERMAL_SENSOR",
        "sensors": sensors,
    }

    dependency_versions: dict[str, str] = {}
    for key, distribution in {
        "argon2_cffi": "argon2-cffi",
        "pyyaml": "PyYAML",
        "numpy": "numpy",
        "scipy": "scipy",
    }.items():
        try:
            dependency_versions[key] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise EvidenceError(
                f"v5 formal measurement dependency {distribution} is unavailable"
            ) from exc

    clock_root = Path("/sys/devices/system/clocksource/clocksource0")
    return {
        "schema": PREREGISTERED_MEASUREMENT_ENVIRONMENT_SCHEMA,
        "phase": phase,
        "captured_unix_ns": time.time_ns(),
        "cpu_identity": {
            "model_names": cpu_models,
            "microcodes": microcodes,
        },
        "affinity": {
            "process_id": os.getpid(),
            "process_allowed_cpus": process_affinity,
            "thread_affinity_policy": (
                "RUNNER_DOES_NOT_REPIN_THREADS_OBSERVED_ALLOWED_CPU_SETS_RECORDED"
            ),
            "threads": threads,
        },
        "cpu_policies": cpu_policies,
        "numa_maps": numa_maps,
        "thermal": thermal,
        "kernel_clock": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "current_clocksource": _read_linux_value(
                clock_root / "current_clocksource"
            ),
            "available_clocksources": _read_linux_value(
                clock_root / "available_clocksource"
            ),
        },
        "python_build": {
            key: sysconfig.get_config_var(key)
            for key in (
                "CC",
                "CFLAGS",
                "CONFIG_ARGS",
                "PY_CFLAGS",
                "LDFLAGS",
                "MULTIARCH",
                "SOABI",
            )
        },
        "crypto_runtime": {
            "openssl_version": ssl.OPENSSL_VERSION,
            "hashlib_algorithms_guaranteed": sorted(hashlib.algorithms_guaranteed),
            "hashlib_algorithms_available": sorted(hashlib.algorithms_available),
        },
        "dependency_versions": dependency_versions,
    }


def _validate_preregistered_measurement_environment(
    value: object, expected_phase: str
) -> dict[str, Any]:
    environment = _mapping(value, f"v5 {expected_phase} measurement environment")
    _exact_keys(
        environment,
        {
            "schema",
            "phase",
            "captured_unix_ns",
            "cpu_identity",
            "affinity",
            "cpu_policies",
            "numa_maps",
            "thermal",
            "kernel_clock",
            "python_build",
            "crypto_runtime",
            "dependency_versions",
        },
        f"v5 {expected_phase} measurement environment",
    )
    _exact_value(
        environment["schema"],
        PREREGISTERED_MEASUREMENT_ENVIRONMENT_SCHEMA,
        "v5 measurement environment schema",
    )
    _exact_value(environment["phase"], expected_phase, "v5 measurement phase")
    _integer(environment["captured_unix_ns"], "v5 environment timestamp", 1)

    identity = _mapping(environment["cpu_identity"], "v5 CPU identity")
    _exact_keys(identity, {"model_names", "microcodes"}, "v5 CPU identity")
    for key in ("model_names", "microcodes"):
        values = identity[key]
        if (
            type(values) is not list
            or not values
            or values != sorted(set(values))
            or any(type(item) is not str or not item for item in values)
        ):
            raise EvidenceError(f"v5 CPU identity {key} must be sorted nonempty strings")

    affinity = _mapping(environment["affinity"], "v5 affinity evidence")
    _exact_keys(
        affinity,
        {"process_id", "process_allowed_cpus", "thread_affinity_policy", "threads"},
        "v5 affinity evidence",
    )
    _integer(affinity["process_id"], "v5 affinity process ID", 1)
    cpus = affinity["process_allowed_cpus"]
    if type(cpus) is not list or not cpus:
        raise EvidenceError("v5 process CPU affinity must be a nonempty array")
    normalized_cpus = [_integer(cpu, "v5 process affinity CPU") for cpu in cpus]
    if normalized_cpus != sorted(set(normalized_cpus)):
        raise EvidenceError("v5 process CPU affinity must be sorted and unique")
    _exact_value(
        affinity["thread_affinity_policy"],
        "RUNNER_DOES_NOT_REPIN_THREADS_OBSERVED_ALLOWED_CPU_SETS_RECORDED",
        "v5 thread affinity policy",
    )
    threads = affinity["threads"]
    if type(threads) is not list or not threads:
        raise EvidenceError("v5 thread affinity evidence must be nonempty")
    prior_tid = 0
    for thread_value in threads:
        thread = _mapping(thread_value, "v5 thread affinity record")
        _exact_keys(thread, {"tid", "allowed_cpus"}, "v5 thread affinity record")
        tid = _integer(thread["tid"], "v5 thread ID", 1)
        if tid <= prior_tid:
            raise EvidenceError("v5 thread affinity records must be strictly sorted")
        prior_tid = tid
        allowed = thread["allowed_cpus"]
        if type(allowed) is not list or not allowed:
            raise EvidenceError("v5 thread allowed CPU set must be nonempty")
        normalized = [_integer(cpu, "v5 thread affinity CPU") for cpu in allowed]
        if normalized != sorted(set(normalized)) or not set(normalized) <= set(normalized_cpus):
            raise EvidenceError("v5 thread CPU affinity exceeds the process affinity")

    policies = environment["cpu_policies"]
    if type(policies) is not list or len(policies) != len(normalized_cpus):
        raise EvidenceError("v5 CPU policies must cover the process affinity exactly")
    for expected_cpu, policy_value in zip(normalized_cpus, policies, strict=True):
        policy = _mapping(policy_value, "v5 CPU policy")
        _exact_keys(policy, {"cpu", "numa_node", "cpufreq"}, "v5 CPU policy")
        _exact_value(policy["cpu"], expected_cpu, "v5 CPU policy ordering")
        if policy["numa_node"] != "UNAVAILABLE":
            _integer(policy["numa_node"], "v5 CPU NUMA node")
        frequency = _mapping(policy["cpufreq"], "v5 CPU frequency policy")
        frequency_keys = {
            "status",
            "scaling_driver",
            "scaling_governor",
            "scaling_min_freq_khz",
            "scaling_max_freq_khz",
            "scaling_current_freq_khz",
        }
        _exact_keys(frequency, frequency_keys, "v5 CPU frequency policy")
        data_keys = frequency_keys - {"status"}
        available_keys = {
            key for key in data_keys if frequency[key] != "UNAVAILABLE"
        }
        expected_status = (
            "AVAILABLE"
            if len(available_keys) == len(data_keys)
            else "PARTIAL"
            if available_keys
            else "UNAVAILABLE"
        )
        _exact_value(
            frequency["status"], expected_status, "v5 CPU frequency availability status"
        )
        for key in ("scaling_driver", "scaling_governor"):
            if key in available_keys and (
                type(frequency[key]) is not str or not frequency[key]
            ):
                raise EvidenceError("readable CPU policy identity must be nonempty")
        for key in (
            "scaling_min_freq_khz",
            "scaling_max_freq_khz",
            "scaling_current_freq_khz",
        ):
            if key in available_keys and (
                type(frequency[key]) is not str or not str(frequency[key]).isdigit()
            ):
                raise EvidenceError("readable CPU frequency must be an integer string")

    numa = _mapping(environment["numa_maps"], "v5 NUMA maps summary")
    _exact_keys(
        numa,
        {
            "status",
            "reason",
            "line_count",
            "mapped_pages",
            "node_pages",
            "policy_counts",
        },
        "v5 NUMA maps summary",
    )
    if numa["status"] == "UNAVAILABLE":
        _exact_value(numa["reason"], "PROC_SELF_NUMA_MAPS_UNAVAILABLE", "NUMA reason")
        _exact_value(numa["line_count"], 0, "NUMA unavailable line count")
        _exact_value(numa["mapped_pages"], 0, "NUMA unavailable page count")
        _exact_value(numa["node_pages"], {}, "NUMA unavailable node pages")
        _exact_value(numa["policy_counts"], {}, "NUMA unavailable policies")
    elif numa["status"] == "AVAILABLE":
        _exact_value(numa["reason"], None, "NUMA available reason")
        line_count = _integer(numa["line_count"], "NUMA maps line count", 1)
        mapped_pages = _integer(numa["mapped_pages"], "NUMA mapped pages")
        node_pages = _mapping(numa["node_pages"], "NUMA node pages")
        for key, count in node_pages.items():
            if not key.isdigit():
                raise EvidenceError("NUMA node page key must be numeric")
            _integer(count, "NUMA node page count")
        policy_counts = _mapping(numa["policy_counts"], "NUMA policies")
        for key, count in policy_counts.items():
            if not key:
                raise EvidenceError("NUMA policy name must be nonempty")
            _integer(count, "NUMA policy count", 1)
        _exact_value(
            mapped_pages,
            sum(int(count) for count in node_pages.values()),
            "NUMA mapped page summary",
        )
        _exact_value(
            line_count,
            sum(int(count) for count in policy_counts.values()),
            "NUMA policy line summary",
        )
    else:
        raise EvidenceError("v5 NUMA maps status is invalid")

    thermal = _mapping(environment["thermal"], "v5 thermal evidence")
    _exact_keys(thermal, {"status", "reason", "sensors"}, "v5 thermal evidence")
    sensors = thermal["sensors"]
    if type(sensors) is not list:
        raise EvidenceError("v5 thermal sensors must be an array")
    if thermal["status"] == "UNAVAILABLE":
        _exact_value(thermal["reason"], "NO_READABLE_THERMAL_SENSOR", "thermal reason")
        _exact_value(sensors, [], "unavailable thermal sensors")
    elif thermal["status"] == "AVAILABLE":
        _exact_value(thermal["reason"], None, "available thermal reason")
        if not sensors:
            raise EvidenceError("available v5 thermal evidence must name a sensor")
        for sensor_value in sensors:
            sensor = _mapping(sensor_value, "v5 thermal sensor")
            _exact_keys(
                sensor,
                {"sensor", "temperature_millicelsius"},
                "v5 thermal sensor",
            )
            if type(sensor["sensor"]) is not str or not sensor["sensor"]:
                raise EvidenceError("v5 thermal sensor name must be nonempty")
            if type(sensor["temperature_millicelsius"]) is not int:
                raise EvidenceError("v5 thermal temperature must be an integer")
    else:
        raise EvidenceError("v5 thermal status is invalid")

    kernel = _mapping(environment["kernel_clock"], "v5 kernel/clocksource evidence")
    _exact_keys(
        kernel,
        {
            "system",
            "release",
            "version",
            "current_clocksource",
            "available_clocksources",
        },
        "v5 kernel/clocksource evidence",
    )
    for key, item in kernel.items():
        if type(item) is not str or not item:
            raise EvidenceError(f"v5 kernel/clocksource {key} must be nonempty")
    _exact_value(kernel["system"], "Linux", "v5 measurement kernel system")

    python_build = _mapping(environment["python_build"], "v5 Python build flags")
    build_keys = {"CC", "CFLAGS", "CONFIG_ARGS", "PY_CFLAGS", "LDFLAGS", "MULTIARCH", "SOABI"}
    _exact_keys(python_build, build_keys, "v5 Python build flags")
    if any(value is not None and type(value) is not str for value in python_build.values()):
        raise EvidenceError("v5 Python build flags must be strings or null")

    crypto = _mapping(environment["crypto_runtime"], "v5 crypto runtime")
    _exact_keys(
        crypto,
        {
            "openssl_version",
            "hashlib_algorithms_guaranteed",
            "hashlib_algorithms_available",
        },
        "v5 crypto runtime",
    )
    if type(crypto["openssl_version"]) is not str or not crypto["openssl_version"]:
        raise EvidenceError("v5 OpenSSL version must be nonempty")
    for key in ("hashlib_algorithms_guaranteed", "hashlib_algorithms_available"):
        algorithms = crypto[key]
        if (
            type(algorithms) is not list
            or not algorithms
            or algorithms != sorted(set(algorithms))
            or any(type(item) is not str or not item for item in algorithms)
        ):
            raise EvidenceError(f"v5 {key} must be sorted unique algorithm names")

    dependencies = _mapping(
        environment["dependency_versions"], "v5 measurement dependency versions"
    )
    _exact_keys(
        dependencies,
        {"argon2_cffi", "pyyaml", "numpy", "scipy"},
        "v5 measurement dependency versions",
    )
    if any(type(version) is not str or not version for version in dependencies.values()):
        raise EvidenceError("v5 measurement dependency versions must be nonempty")
    return environment


def _stable_measurement_environment(value: Mapping[str, Any]) -> dict[str, object]:
    policies = []
    for policy_value in value["cpu_policies"]:
        policy = _mapping(policy_value, "v5 stable CPU policy")
        frequency = _mapping(policy["cpufreq"], "v5 stable CPU frequency policy")
        stable_frequency_keys = (
            "scaling_driver",
            "scaling_governor",
            "scaling_min_freq_khz",
            "scaling_max_freq_khz",
        )
        stable_available_count = sum(
            frequency[key] != "UNAVAILABLE" for key in stable_frequency_keys
        )
        stable_status = (
            "AVAILABLE"
            if stable_available_count == len(stable_frequency_keys)
            else "PARTIAL"
            if stable_available_count
            else "UNAVAILABLE"
        )
        policies.append(
            {
                "cpu": policy["cpu"],
                "numa_node": policy["numa_node"],
                "cpufreq": {
                    "status": stable_status,
                    **{key: frequency[key] for key in stable_frequency_keys},
                },
            }
        )
    affinity = _mapping(value["affinity"], "v5 stable affinity")
    return {
        "cpu_identity": value["cpu_identity"],
        "process_allowed_cpus": affinity["process_allowed_cpus"],
        "thread_affinity_policy": affinity["thread_affinity_policy"],
        "cpu_policies": policies,
        "kernel_clock": value["kernel_clock"],
        "python_build": value["python_build"],
        "crypto_runtime": value["crypto_runtime"],
        "dependency_versions": value["dependency_versions"],
    }


def _active_kdf_runtime_evidence(workload: Mapping[str, Any]) -> dict[str, object]:
    algorithm = workload.get("algorithm")
    python_build = {
        "python_compiler": platform.python_compiler() or "UNAVAILABLE",
        "sysconfig": {
            key: sysconfig.get_config_var(key)
            for key in ("CC", "CFLAGS", "LDFLAGS", "EXT_SUFFIX", "SOABI")
        },
    }
    build_flags = {
        "status": "UNAVAILABLE",
        "reason": "NATIVE_EXTENSION_BUILD_FLAGS_NOT_EXPOSED_AT_RUNTIME",
    }
    if algorithm == "pbkdf2_hmac_sha256":
        native_module = importlib.import_module("_hashlib")
        module_file = getattr(native_module, "__file__", None)
        if type(module_file) is not str or not module_file:
            raise EvidenceError("PBKDF2 native provider module filename is unavailable")
        return {
            "algorithm": algorithm,
            "provider": f"{hashlib.pbkdf2_hmac.__module__}.pbkdf2_hmac",
            "native_module_filename": Path(module_file).name,
            "algorithm_specification_version": (
                "PBKDF2_HMAC_SHA256_NO_SEPARATE_VERSION_IDENTIFIER"
            ),
            "runtime_library_version": ssl.OPENSSL_VERSION,
            "runtime_library_version_reason": None,
            "package_versions": {},
            "loaded_shared_libraries": _probe_loaded_shared_libraries(
                ("libcrypto", "libssl")
            ),
            "native_build_flags": build_flags,
            "python_runtime_build": python_build,
        }
    if algorithm == "argon2id":
        binding_module = importlib.import_module("_argon2_cffi_bindings._ffi")
        module_file = getattr(binding_module, "__file__", None)
        if type(module_file) is not str or not module_file:
            raise EvidenceError("Argon2 native provider module filename is unavailable")
        versions: dict[str, str] = {}
        for key, distribution in {
            "argon2_cffi": "argon2-cffi",
            "argon2_cffi_bindings": "argon2-cffi-bindings",
            "cffi": "cffi",
        }.items():
            try:
                versions[key] = importlib.metadata.version(distribution)
            except importlib.metadata.PackageNotFoundError as exc:
                raise EvidenceError(
                    f"Argon2 native provider dependency {distribution} is unavailable"
                ) from exc
        return {
            "algorithm": algorithm,
            "provider": "argon2.low_level.hash_secret_raw",
            "native_module_filename": Path(module_file).name,
            "algorithm_specification_version": (
                f"ARGON2_VERSION_{int(workload['version'])}"
            ),
            "runtime_library_version": "UNAVAILABLE",
            "runtime_library_version_reason": (
                "ARGON2_IMPLEMENTATION_VERSION_NOT_EXPOSED_BY_RUNTIME_BINDING"
            ),
            "package_versions": versions,
            "loaded_shared_libraries": _probe_loaded_shared_libraries(("argon",)),
            "native_build_flags": build_flags,
            "python_runtime_build": python_build,
        }
    raise EvidenceError("seed-child active KDF workload is unsupported")


def _probe_seed_child_measurement_environment(
    phase: str,
    auth_worker_native_ids: Sequence[int],
    workload: Mapping[str, Any],
) -> dict[str, object]:
    if phase not in {"PRE_SEED_MEASUREMENT", "POST_SEED_MEASUREMENT"}:
        raise EvidenceError("seed-child measurement environment phase is invalid")
    if platform.system() != "Linux" or os.name != "posix":
        raise EvidenceError("seed-child measurement environment requires Linux")
    if platform.machine() != PREREGISTERED_PRODUCTION_ARCHITECTURE:
        raise EvidenceError("seed-child measurement environment requires x86_64")
    worker_ids = sorted(int(tid) for tid in auth_worker_native_ids)
    if not worker_ids or worker_ids != sorted(set(worker_ids)):
        raise EvidenceError("seed-child auth worker native IDs must be unique")
    affinity_getter = getattr(os, "sched_getaffinity", None)
    if affinity_getter is None:
        raise EvidenceError("seed-child cannot inspect native-thread CPU affinity")
    worker_affinity: list[dict[str, object]] = []
    for native_id in worker_ids:
        try:
            allowed_cpus = sorted(int(cpu) for cpu in affinity_getter(native_id))
        except (OSError, ProcessLookupError) as exc:
            raise EvidenceError(
                "seed-child auth worker vanished before affinity capture"
            ) from exc
        placement = _probe_linux_auth_worker_placement(native_id)
        if _parse_linux_id_list(
            str(placement["cpus_allowed_list"]),
            "auth-worker Cpus_allowed_list",
        ) != allowed_cpus:
            raise EvidenceError(
                "auth-worker sched_getaffinity and /proc CPU lists disagree"
            )
        worker_affinity.append(
            {"native_id": native_id, "allowed_cpus": allowed_cpus, **placement}
        )
    return {
        "schema": SEED_CHILD_MEASUREMENT_ENVIRONMENT_SCHEMA,
        "phase": phase,
        "captured_unix_ns": time.time_ns(),
        "process_id": os.getpid(),
        "host_architecture": platform.machine(),
        "seed_main_thread_native_id": threading.get_native_id(),
        "seed_main_thread_allowed_cpus": _probe_cpu_affinity(),
        "auth_worker_scope": "NATIVE_TIDS_CAPTURED_INSIDE_AUTH_EXECUTOR_TASK",
        "auth_worker_native_ids": worker_ids,
        "auth_worker_affinity": worker_affinity,
        "numa_maps": _probe_linux_numa_maps(),
        "active_kdf_runtime": _active_kdf_runtime_evidence(workload),
    }


def _validate_seed_child_measurement_environment(
    value: object,
    expected_phase: str,
    expected_process_id: int,
    expected_process_affinity: Sequence[int],
    expected_auth_workers: int,
    expected_workload: Mapping[str, Any],
) -> dict[str, Any]:
    label = f"seed-child {expected_phase} measurement environment"
    environment = _mapping(value, label)
    _exact_keys(
        environment,
        {
            "schema",
            "phase",
            "captured_unix_ns",
            "process_id",
            "host_architecture",
            "seed_main_thread_native_id",
            "seed_main_thread_allowed_cpus",
            "auth_worker_scope",
            "auth_worker_native_ids",
            "auth_worker_affinity",
            "numa_maps",
            "active_kdf_runtime",
        },
        label,
    )
    _exact_value(
        environment["schema"],
        SEED_CHILD_MEASUREMENT_ENVIRONMENT_SCHEMA,
        f"{label} schema",
    )
    _exact_value(environment["phase"], expected_phase, f"{label} phase")
    _integer(environment["captured_unix_ns"], f"{label} timestamp", 1)
    _exact_value(environment["process_id"], expected_process_id, f"{label} process")
    _exact_value(
        environment["host_architecture"],
        PREREGISTERED_PRODUCTION_ARCHITECTURE,
        f"{label} host architecture",
    )
    expected_affinity = list(expected_process_affinity)
    seed_main_thread_native_id = _integer(
        environment["seed_main_thread_native_id"],
        f"{label} seed main native thread ID",
        1,
    )
    _exact_value(
        seed_main_thread_native_id,
        expected_process_id,
        f"{label} seed main thread/process binding",
    )
    _exact_value(
        environment["seed_main_thread_allowed_cpus"],
        expected_affinity,
        f"{label} seed main thread affinity",
    )
    _exact_value(
        environment["auth_worker_scope"],
        "NATIVE_TIDS_CAPTURED_INSIDE_AUTH_EXECUTOR_TASK",
        f"{label} worker scope",
    )
    native_ids = environment["auth_worker_native_ids"]
    if type(native_ids) is not list or len(native_ids) != expected_auth_workers:
        raise EvidenceError(f"{label} does not cover every configured auth worker")
    normalized_ids = [_integer(tid, f"{label} native thread ID", 1) for tid in native_ids]
    if normalized_ids != sorted(set(normalized_ids)):
        raise EvidenceError(f"{label} native thread IDs must be sorted and unique")
    worker_affinity = environment["auth_worker_affinity"]
    if type(worker_affinity) is not list or len(worker_affinity) != expected_auth_workers:
        raise EvidenceError(f"{label} auth worker affinity coverage is incomplete")
    for expected_tid, record_value in zip(
        normalized_ids, worker_affinity, strict=True
    ):
        if expected_tid == expected_process_id:
            raise EvidenceError(f"{label} auth worker cannot be the seed main thread")
        record = _mapping(record_value, f"{label} auth worker affinity")
        _exact_keys(
            record,
            {
                "native_id",
                "allowed_cpus",
                "cpus_allowed_list",
                "mems_allowed_list",
                "last_cpu",
                "last_cpu_numa_node",
            },
            f"{label} worker affinity",
        )
        _exact_value(record["native_id"], expected_tid, f"{label} worker ordering")
        allowed = record["allowed_cpus"]
        if type(allowed) is not list or not allowed:
            raise EvidenceError(f"{label} worker affinity must be nonempty")
        normalized_allowed = [
            _integer(cpu, f"{label} worker affinity CPU", 0) for cpu in allowed
        ]
        if (
            normalized_allowed != sorted(set(normalized_allowed))
            or not set(normalized_allowed) <= set(expected_affinity)
        ):
            raise EvidenceError(f"{label} worker affinity exceeds process affinity")
        if _parse_linux_id_list(
            record["cpus_allowed_list"], f"{label} Cpus_allowed_list"
        ) != normalized_allowed:
            raise EvidenceError(f"{label} Linux/scheduler worker affinity disagrees")
        mems_allowed = _parse_linux_id_list(
            record["mems_allowed_list"], f"{label} Mems_allowed_list"
        )
        last_cpu = _integer(record["last_cpu"], f"{label} last CPU", 0)
        if last_cpu not in normalized_allowed:
            raise EvidenceError(f"{label} last CPU is outside worker affinity")
        last_node = record["last_cpu_numa_node"]
        if last_node != "UNAVAILABLE":
            normalized_node = _integer(last_node, f"{label} last CPU NUMA node", 0)
            if normalized_node not in mems_allowed:
                raise EvidenceError(f"{label} last CPU NUMA node is disallowed")

    numa = _mapping(environment["numa_maps"], f"{label} NUMA maps")
    _exact_keys(
        numa,
        {"status", "reason", "line_count", "mapped_pages", "node_pages", "policy_counts"},
        f"{label} NUMA maps",
    )
    if numa["status"] == "UNAVAILABLE":
        _exact_value(numa["reason"], "PROC_SELF_NUMA_MAPS_UNAVAILABLE", f"{label} NUMA reason")
        for key in ("line_count", "mapped_pages"):
            _exact_value(numa[key], 0, f"{label} unavailable NUMA {key}")
        _exact_value(numa["node_pages"], {}, f"{label} unavailable NUMA nodes")
        _exact_value(numa["policy_counts"], {}, f"{label} unavailable NUMA policies")
    elif numa["status"] == "AVAILABLE":
        _exact_value(numa["reason"], None, f"{label} NUMA reason")
        line_count = _integer(numa["line_count"], f"{label} NUMA line count", 1)
        mapped_pages = _integer(numa["mapped_pages"], f"{label} NUMA page count")
        node_pages = _mapping(numa["node_pages"], f"{label} NUMA nodes")
        for key, count in node_pages.items():
            if not key.isdigit():
                raise EvidenceError(f"{label} NUMA node key must be numeric")
            _integer(count, f"{label} NUMA node page count")
        policy_counts = _mapping(numa["policy_counts"], f"{label} NUMA policies")
        for key, count in policy_counts.items():
            if not key:
                raise EvidenceError(f"{label} NUMA policy name must be nonempty")
            _integer(count, f"{label} NUMA policy count", 1)
        _exact_value(
            mapped_pages,
            sum(int(count) for count in node_pages.values()),
            f"{label} NUMA mapped page summary",
        )
        _exact_value(
            line_count,
            sum(int(count) for count in policy_counts.values()),
            f"{label} NUMA policy line summary",
        )
    else:
        raise EvidenceError(f"{label} NUMA status is invalid")

    runtime = _mapping(environment["active_kdf_runtime"], f"{label} KDF runtime")
    _exact_keys(
        runtime,
        {
            "algorithm",
            "provider",
            "native_module_filename",
            "algorithm_specification_version",
            "runtime_library_version",
            "runtime_library_version_reason",
            "package_versions",
            "loaded_shared_libraries",
            "native_build_flags",
            "python_runtime_build",
        },
        f"{label} KDF runtime",
    )
    _exact_value(runtime["algorithm"], expected_workload["algorithm"], f"{label} KDF")
    for key in (
        "provider",
        "native_module_filename",
        "algorithm_specification_version",
        "runtime_library_version",
    ):
        if type(runtime[key]) is not str or not runtime[key]:
            raise EvidenceError(f"{label} {key} must be nonempty")
    if expected_workload["algorithm"] == "pbkdf2_hmac_sha256":
        _exact_value(runtime["provider"], "_hashlib.pbkdf2_hmac", f"{label} provider")
        _exact_value(
            runtime["algorithm_specification_version"],
            "PBKDF2_HMAC_SHA256_NO_SEPARATE_VERSION_IDENTIFIER",
            f"{label} PBKDF2 algorithm specification version",
        )
        if not str(runtime["runtime_library_version"]).startswith("OpenSSL "):
            raise EvidenceError(f"{label} PBKDF2 runtime library version is invalid")
        _exact_value(
            runtime["runtime_library_version_reason"],
            None,
            f"{label} PBKDF2 runtime library version reason",
        )
    else:
        _exact_value(
            runtime["provider"],
            "argon2.low_level.hash_secret_raw",
            f"{label} provider",
        )
        _exact_value(
            runtime["algorithm_specification_version"],
            f"ARGON2_VERSION_{int(expected_workload['version'])}",
            f"{label} Argon2 algorithm version",
        )
        _exact_value(
            runtime["runtime_library_version"],
            "UNAVAILABLE",
            f"{label} Argon2 runtime library version",
        )
        _exact_value(
            runtime["runtime_library_version_reason"],
            "ARGON2_IMPLEMENTATION_VERSION_NOT_EXPOSED_BY_RUNTIME_BINDING",
            f"{label} Argon2 runtime library version reason",
        )
    versions = _mapping(runtime["package_versions"], f"{label} KDF package versions")
    expected_version_keys = (
        set()
        if expected_workload["algorithm"] == "pbkdf2_hmac_sha256"
        else {"argon2_cffi", "argon2_cffi_bindings", "cffi"}
    )
    _exact_keys(versions, expected_version_keys, f"{label} KDF package versions")
    if any(type(version) is not str or not version for version in versions.values()):
        raise EvidenceError(f"{label} KDF package versions must be nonempty")
    loaded_libraries = _mapping(
        runtime["loaded_shared_libraries"], f"{label} loaded shared libraries"
    )
    _exact_keys(
        loaded_libraries,
        {"status", "reason", "basenames"},
        f"{label} loaded shared libraries",
    )
    basenames = loaded_libraries["basenames"]
    if (
        type(basenames) is not list
        or basenames != sorted(set(basenames))
        or any(type(name) is not str or not name for name in basenames)
    ):
        raise EvidenceError(f"{label} loaded library basenames are invalid")
    if loaded_libraries["status"] == "AVAILABLE":
        _exact_value(loaded_libraries["reason"], None, f"{label} library reason")
        if not basenames:
            raise EvidenceError(f"{label} available library mapping is empty")
    elif loaded_libraries["status"] == "UNAVAILABLE":
        if loaded_libraries["reason"] not in {
            "PROC_SELF_MAPS_UNAVAILABLE",
            "NO_SEPARATE_MATCHING_SHARED_LIBRARY_MAPPING",
        }:
            raise EvidenceError(f"{label} unavailable library reason is invalid")
        if basenames:
            raise EvidenceError(f"{label} unavailable library mapping is nonempty")
    else:
        raise EvidenceError(f"{label} loaded library status is invalid")
    flags = _mapping(runtime["native_build_flags"], f"{label} native build flags")
    _exact_value(
        flags,
        {
            "status": "UNAVAILABLE",
            "reason": "NATIVE_EXTENSION_BUILD_FLAGS_NOT_EXPOSED_AT_RUNTIME",
        },
        f"{label} native build flags",
    )
    python_build = _mapping(runtime["python_runtime_build"], f"{label} Python build")
    _exact_keys(python_build, {"python_compiler", "sysconfig"}, f"{label} Python build")
    if type(python_build["python_compiler"]) is not str or not python_build["python_compiler"]:
        raise EvidenceError(f"{label} Python compiler must be nonempty")
    build_vars = _mapping(python_build["sysconfig"], f"{label} Python sysconfig")
    _exact_keys(
        build_vars,
        {"CC", "CFLAGS", "LDFLAGS", "EXT_SUFFIX", "SOABI"},
        f"{label} Python sysconfig",
    )
    if any(item is not None and type(item) is not str for item in build_vars.values()):
        raise EvidenceError(f"{label} Python build variables must be strings or null")
    return environment


def _stable_seed_child_measurement_environment(
    value: Mapping[str, Any],
) -> dict[str, object]:
    stable_worker_affinity = []
    for record_value in value["auth_worker_affinity"]:
        record = _mapping(record_value, "stable seed-child worker affinity")
        stable_worker_affinity.append(
            {
                key: record[key]
                for key in (
                    "native_id",
                    "allowed_cpus",
                    "cpus_allowed_list",
                    "mems_allowed_list",
                )
            }
        )
    return {
        "seed_main_thread_native_id": value["seed_main_thread_native_id"],
        "seed_main_thread_allowed_cpus": value["seed_main_thread_allowed_cpus"],
        "auth_worker_scope": value["auth_worker_scope"],
        "auth_worker_native_ids": value["auth_worker_native_ids"],
        "auth_worker_affinity": stable_worker_affinity,
        "active_kdf_runtime": value["active_kdf_runtime"],
    }


def _actual_python_runtime_executable() -> Path:
    if os.name == "nt":
        base_executable = getattr(sys, "_base_executable", None)
        if type(base_executable) is str and base_executable:
            return Path(base_executable)
    return Path(sys.executable)


def _probe_isolated_dependency_versions() -> dict[str, str]:
    script = (
        "import importlib.metadata as metadata, json, sys\n"
        "result = {}\n"
        "for distribution in ("
        "'argon2-cffi', 'argon2-cffi-bindings', 'cryptography', 'PyYAML'"
        "):\n"
        "    try:\n"
        "        result[distribution] = metadata.version(distribution)\n"
        "    except metadata.PackageNotFoundError:\n"
        "        result[distribution] = 'NOT_INSTALLED'\n"
        "sys.stdout.write(json.dumps(result, sort_keys=True, separators=(',', ':')))\n"
    )
    try:
        completed = subprocess.run(
            [str(_actual_python_runtime_executable()), "-I", "-c", script],
            check=True,
            capture_output=True,
            text=False,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise EvidenceError("cannot probe isolated seed-child dependency versions") from exc
    if completed.stderr:
        raise EvidenceError("isolated dependency probe wrote unexpected stderr bytes")
    versions = _decode_canonical_json(
        completed.stdout,
        "isolated dependency probe stdout",
        4096,
    )
    _exact_keys(
        versions,
        {"argon2-cffi", "argon2-cffi-bindings", "cryptography", "PyYAML"},
        "isolated dependency versions",
    )
    for distribution, version in versions.items():
        _nonempty_ascii(version, f"isolated dependency {distribution} version")
    return {str(distribution): str(version) for distribution, version in versions.items()}


def _probe_python_environment_identity() -> dict[str, object]:
    prefix = Path(sys.prefix).resolve()
    prefix_id = hashlib.sha256(os.path.normcase(str(prefix)).encode("utf-8")).hexdigest()
    pyvenv_config = prefix / "pyvenv.cfg"
    try:
        pyvenv_config_sha256: str | None = (
            hashlib.sha256(pyvenv_config.read_bytes()).hexdigest()
            if pyvenv_config.is_file()
            else None
        )
    except OSError as exc:
        raise EvidenceError("cannot hash the active Python environment configuration") from exc

    return {
        "prefix_id": prefix_id,
        "pyvenv_config_sha256": pyvenv_config_sha256,
        "dependency_versions": _probe_isolated_dependency_versions(),
    }


def _probe_python_runtime_identity() -> dict[str, object]:
    launcher = Path(sys.executable)
    executable = _actual_python_runtime_executable()
    try:
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        launcher_digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
    except OSError as exc:
        raise EvidenceError("cannot hash the active Python runtime executable") from exc
    cache_tag = getattr(sys.implementation, "cache_tag", None)
    if type(cache_tag) is not str or not cache_tag:
        raise EvidenceError("Python runtime cache tag is unavailable")
    return {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "cache_tag": cache_tag,
        "executable_sha256": digest,
        "launcher_sha256": launcher_digest,
        "environment": _probe_python_environment_identity(),
    }


def _probe_power_governor(
    assertion: Mapping[str, Any], allowed_cpu_affinity: Sequence[int]
) -> dict[str, object]:
    if assertion["mode"] == "EXTERNAL_ATTESTATION":
        return {
            "mode": "EXTERNAL_ATTESTATION",
            "attestation_id": assertion["attestation_id"],
            "expected_value": assertion["expected_value"],
            "document_uri": assertion["document_uri"],
            "document_sha256": assertion["document_sha256"],
            "runtime_probe": "NOT_PERFORMED_BY_SIGNED_CONTRACT",
        }
    governors: set[str] = set()
    for cpu in allowed_cpu_affinity:
        path = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")
        try:
            value = path.read_text(encoding="ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise EvidenceError("cannot read the signed Linux CPU governor assertion") from exc
        if not value:
            raise EvidenceError("Linux CPU governor probe returned an empty value")
        governors.add(value)
    if len(governors) != 1:
        raise EvidenceError("allowed CPUs do not share one scaling governor")
    return {
        "mode": "RUNTIME_VERIFIED",
        "probe": "LINUX_SCALING_GOVERNOR",
        "value": next(iter(governors)),
    }


def _probe_load_average_1m() -> float:
    try:
        value = float(os.getloadavg()[0])
    except (AttributeError, OSError) as exc:
        raise EvidenceError("one-minute load average is unavailable") from exc
    if not math.isfinite(value) or value < 0.0:
        raise EvidenceError("one-minute load average is invalid")
    return value


def _probe_service_states(
    assertions: Sequence[Mapping[str, Any]],
) -> list[dict[str, object]]:
    states: list[dict[str, object]] = []
    for assertion in assertions:
        service_id = str(assertion["service_id"])
        completed = subprocess.run(
            [
                "systemctl",
                "show",
                "--no-pager",
                "--property=LoadState",
                "--property=ActiveState",
                "--property=SubState",
                "--",
                service_id,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise EvidenceError(f"read-only service-state probe failed for {service_id}")
        parsed: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            key, separator, item = line.partition("=")
            if separator:
                parsed[key] = item
        if set(parsed) != {"LoadState", "ActiveState", "SubState"}:
            raise EvidenceError(f"service-state probe was incomplete for {service_id}")
        states.append(
            {
                "service_id": service_id,
                "load_state": parsed["LoadState"],
                "active_state": parsed["ActiveState"],
                "sub_state": parsed["SubState"],
            }
        )
    return states


def _validate_host_attestation(
    value: object,
    contract: Mapping[str, Any],
    phase: str,
) -> dict[str, Any]:
    attestation = _mapping(value, f"{phase} host attestation")
    _exact_keys(
        attestation,
        {
            "schema",
            "phase",
            "captured_unix_ns",
            "host_id",
            "system",
            "architecture",
            "logical_cpu_count",
            "allowed_cpu_affinity",
            "python_runtime",
            "power_governor_assertion",
            "load_average_1m",
            "service_states",
        },
        f"{phase} host attestation",
    )
    _exact_value(attestation["schema"], HOST_ATTESTATION_SCHEMA, "host attestation schema")
    _exact_value(attestation["phase"], phase, "host attestation phase")
    _integer(attestation["captured_unix_ns"], "host attestation timestamp", 1)
    for key in (
        "host_id",
        "system",
        "architecture",
        "logical_cpu_count",
        "allowed_cpu_affinity",
        "python_runtime",
    ):
        _exact_value(attestation[key], contract[key], f"host attestation {key}")

    power_contract = _mapping(
        contract["power_governor_assertion"], "power/governor assertion"
    )
    if power_contract["mode"] == "RUNTIME_VERIFIED":
        expected_power = {
            "mode": "RUNTIME_VERIFIED",
            "probe": power_contract["probe"],
            "value": power_contract["expected_value"],
        }
    else:
        expected_power = {
            "mode": "EXTERNAL_ATTESTATION",
            "attestation_id": power_contract["attestation_id"],
            "expected_value": power_contract["expected_value"],
            "document_uri": power_contract["document_uri"],
            "document_sha256": power_contract["document_sha256"],
            "runtime_probe": "NOT_PERFORMED_BY_SIGNED_CONTRACT",
        }
    _exact_value(
        attestation["power_governor_assertion"],
        expected_power,
        "host attestation power/governor assertion",
    )
    load_average = _number(attestation["load_average_1m"], "one-minute load average")
    if load_average > float(contract["max_load_average_1m"]):
        raise EvidenceError("one-minute background load exceeds the signed maximum")
    expected_services = _validate_service_assertions(
        contract["required_service_states"], "required service-state assertions"
    )
    _exact_value(attestation["service_states"], expected_services, "service-state attestation")
    return attestation


def _capture_host_attestation(
    contract: Mapping[str, Any], phase: str
) -> dict[str, object]:
    baseline = _probe_host_baseline()
    affinity = _probe_cpu_affinity()
    attestation = {
        "schema": HOST_ATTESTATION_SCHEMA,
        "phase": phase,
        "captured_unix_ns": time.time_ns(),
        "host_id": contract["host_id"],
        "system": baseline["system"],
        "architecture": baseline["architecture"],
        "logical_cpu_count": baseline["logical_cpu_count"],
        "allowed_cpu_affinity": affinity,
        "python_runtime": _probe_python_runtime_identity(),
        "power_governor_assertion": _probe_power_governor(
            _mapping(contract["power_governor_assertion"], "power/governor assertion"),
            affinity,
        ),
        "load_average_1m": _probe_load_average_1m(),
        "service_states": _probe_service_states(contract["required_service_states"]),
    }
    return _validate_host_attestation(attestation, contract, phase)


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def _is_within(path: Path, root: Path) -> bool:
    normalized_path = os.path.normcase(str(path.resolve(strict=False)))
    normalized_root = os.path.normcase(str(root.resolve(strict=False)))
    try:
        return os.path.commonpath((normalized_path, normalized_root)) == normalized_root
    except ValueError:
        return False


def _is_within_absolute_lexical(path: Path, root: Path) -> bool:
    normalized_path = os.path.normcase(os.path.abspath(os.fspath(path)))
    normalized_root = os.path.normcase(os.path.abspath(os.fspath(root)))
    try:
        return os.path.commonpath((normalized_path, normalized_root)) == normalized_root
    except ValueError:
        return False


def _reject_cloud_sync_path(path: Path) -> None:
    for environment_name in (
        "OneDrive",
        "OneDriveConsumer",
        "OneDriveCommercial",
        "Dropbox",
        "GoogleDrive",
        "Box",
        "iCloudDrive",
    ):
        configured = os.environ.get(environment_name)
        if configured and _is_within(path, Path(configured)):
            raise EvidenceError("exclusive lock paths cannot use cloud-synchronized storage")
    cloud_components = {
        "box",
        "dropbox",
        "google drive",
        "icloud drive",
        "onedrive",
    }
    for component in path.resolve(strict=True).parts:
        normalized = component.casefold()
        if normalized in cloud_components or normalized.startswith("onedrive - "):
            raise EvidenceError("exclusive lock paths cannot use cloud-synchronized storage")


def _decode_mountinfo_path(value: str) -> str:
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    return re.sub(r"\\([0-7]{3})", lambda match: escapes.get(match.group(1), match.group(0)), value)


def _probe_linux_lock_filesystem(path: Path) -> dict[str, object]:
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise EvidenceError("Linux lock filesystem semantics cannot be established") from exc
    resolved = path.resolve(strict=True)
    matches: list[tuple[int, str]] = []
    for line in lines:
        before, separator, after = line.partition(" - ")
        before_fields = before.split()
        after_fields = after.split()
        if not separator or len(before_fields) < 5 or not after_fields:
            raise EvidenceError("Linux mountinfo contains an unsupported record")
        mount_path = Path(_decode_mountinfo_path(before_fields[4]))
        if not mount_path.is_absolute():
            raise EvidenceError("Linux mountinfo contains a relative mount path")
        if _is_within_absolute_lexical(resolved, mount_path):
            matches.append((len(str(mount_path)), after_fields[0]))
    if not matches:
        raise EvidenceError("Linux lock filesystem mount cannot be identified")
    filesystem_type = max(matches)[1]
    if filesystem_type not in _LINUX_LOCAL_FILESYSTEMS:
        raise EvidenceError(
            f"Linux lock filesystem {filesystem_type!r} is remote or unsupported"
        )
    return {
        "policy": LOCK_FILESYSTEM_POLICY,
        "platform": "Linux",
        "probe_api": "LINUX_PROC_SELF_MOUNTINFO_LONGEST_MOUNT_V1",
        "filesystem_type": filesystem_type,
        "locality": "LOCAL_KERNEL_FILESYSTEM",
        "network_filesystem_forbidden": True,
    }


def _probe_windows_lock_filesystem(path: Path) -> dict[str, object]:
    import ctypes
    from ctypes import wintypes

    resolved = path.resolve(strict=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_volume_path = kernel32.GetVolumePathNameW
    get_volume_path.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get_volume_path.restype = wintypes.BOOL
    get_drive_type = kernel32.GetDriveTypeW
    get_drive_type.argtypes = [wintypes.LPCWSTR]
    get_drive_type.restype = wintypes.UINT
    get_volume_information = kernel32.GetVolumeInformationW
    get_volume_information.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    get_volume_information.restype = wintypes.BOOL

    volume_path = ctypes.create_unicode_buffer(32768)
    if not get_volume_path(str(resolved), volume_path, len(volume_path)):
        raise EvidenceError("Windows lock volume path cannot be identified")
    if get_drive_type(volume_path.value) != 3:
        raise EvidenceError("Windows lock anchor requires a local fixed drive")
    volume_name = ctypes.create_unicode_buffer(261)
    filesystem_name = ctypes.create_unicode_buffer(261)
    serial_number = wintypes.DWORD()
    maximum_component_length = wintypes.DWORD()
    filesystem_flags = wintypes.DWORD()
    if not get_volume_information(
        volume_path.value,
        volume_name,
        len(volume_name),
        ctypes.byref(serial_number),
        ctypes.byref(maximum_component_length),
        ctypes.byref(filesystem_flags),
        filesystem_name,
        len(filesystem_name),
    ):
        raise EvidenceError("Windows lock filesystem type cannot be identified")
    if filesystem_name.value not in _WINDOWS_LOCAL_FILESYSTEMS:
        raise EvidenceError("Windows lock anchor requires local NTFS or ReFS")
    return {
        "policy": LOCK_FILESYSTEM_POLICY,
        "platform": "Windows",
        "probe_api": "WIN32_GETVOLUMEPATHNAMEW_GETDRIVETYPEW_GETVOLUMEINFORMATIONW_V1",
        "filesystem_type": filesystem_name.value,
        "locality": "LOCAL_FIXED_VOLUME",
        "network_filesystem_forbidden": True,
    }


def _probe_lock_filesystem(path: Path) -> dict[str, object]:
    _reject_cloud_sync_path(path)
    system = platform.system()
    if system == "Windows" and os.name == "nt":
        evidence = _probe_windows_lock_filesystem(path)
    elif system == "Linux" and os.name == "posix":
        evidence = _probe_linux_lock_filesystem(path)
    else:
        raise EvidenceError("exclusive lock filesystem semantics are unsupported")
    _validate_lock_filesystem(evidence, system)
    return evidence


def _same_identity(value: os.stat_result, device: int, inode: int) -> bool:
    return value.st_dev == device and value.st_ino == inode


def _require_unlinked_ancestors(path: Path, label: str) -> None:
    cursor = path.absolute()
    while True:
        if _is_link_or_junction(cursor):
            raise EvidenceError(f"{label} traverses a link or junction")
        parent = cursor.parent
        if parent == cursor:
            return
        cursor = parent


@dataclass
class _PinnedDirectory:
    lexical_path: Path
    resolved_path: Path
    device: int
    inode: int
    descriptor: int | None

    def verify(self, label: str) -> None:
        _require_unlinked_ancestors(self.lexical_path, label)
        try:
            lexical_identity = self.lexical_path.lstat()
            resolved = self.lexical_path.resolve(strict=True)
            resolved_identity = self.resolved_path.lstat()
        except OSError as exc:
            raise EvidenceError(f"{label} identity is unavailable") from exc
        if (
            os.path.normcase(str(resolved))
            != os.path.normcase(str(self.resolved_path))
            or not _same_identity(lexical_identity, self.device, self.inode)
            or not _same_identity(resolved_identity, self.device, self.inode)
        ):
            raise EvidenceError(f"{label} identity changed after preflight")
        if self.descriptor is not None and not _same_identity(
            os.fstat(self.descriptor), self.device, self.inode
        ):
            raise EvidenceError(f"{label} descriptor identity changed after preflight")

    def close(self) -> None:
        if self.descriptor is not None:
            os.close(self.descriptor)
            self.descriptor = None


def _pin_directory(path: Path, label: str) -> _PinnedDirectory:
    lexical_path = path.absolute()
    if not lexical_path.is_dir():
        raise EvidenceError(f"{label} must be a pre-existing directory")
    _require_unlinked_ancestors(lexical_path, label)
    resolved_path = lexical_path.resolve(strict=True)
    identity = lexical_path.lstat()
    descriptor: int | None = None
    if os.name != "nt" and os.open in os.supports_dir_fd:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(resolved_path, flags)
    pinned = _PinnedDirectory(
        lexical_path,
        resolved_path,
        identity.st_dev,
        identity.st_ino,
        descriptor,
    )
    try:
        pinned.verify(label)
    except BaseException:
        pinned.close()
        raise
    return pinned


def _verify_open_child(
    parent: _PinnedDirectory,
    name: str,
    descriptor: int,
    device: int,
    inode: int,
    label: str,
) -> None:
    parent.verify(f"{label} parent")
    descriptor_identity = os.fstat(descriptor)
    try:
        path_identity = (parent.resolved_path / name).lstat()
        resolved_child = (parent.lexical_path / name).resolve(strict=True)
    except OSError as exc:
        raise EvidenceError(f"{label} path identity is unavailable") from exc
    if (
        os.path.normcase(str(resolved_child))
        != os.path.normcase(str(parent.resolved_path / name))
        or not _same_identity(descriptor_identity, device, inode)
        or not _same_identity(path_identity, device, inode)
    ):
        raise EvidenceError(f"{label} path or descriptor identity changed")
    if parent.descriptor is not None and os.stat in os.supports_dir_fd:
        anchored_identity = os.stat(
            name,
            dir_fd=parent.descriptor,
            follow_symlinks=False,
        )
        if not _same_identity(anchored_identity, device, inode):
            raise EvidenceError(f"{label} openat identity differs from its descriptor")


def _open_exclusive_child(
    parent: _PinnedDirectory, name: str, label: str
) -> tuple[int, os.stat_result]:
    parent.verify(f"{label} parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    if parent.descriptor is not None and os.open in os.supports_dir_fd:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent.descriptor)
    else:
        descriptor = os.open(parent.resolved_path / name, flags, 0o600)
    identity = os.fstat(descriptor)
    try:
        _verify_open_child(
            parent,
            name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            label,
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, identity


def _open_existing_child(
    parent: _PinnedDirectory, name: str, label: str
) -> tuple[int, os.stat_result]:
    parent.verify(f"{label} parent")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    if parent.descriptor is not None and os.open in os.supports_dir_fd:
        descriptor = os.open(name, flags, dir_fd=parent.descriptor)
    else:
        descriptor = os.open(parent.resolved_path / name, flags)
    identity = os.fstat(descriptor)
    try:
        if not stat.S_ISREG(identity.st_mode):
            raise EvidenceError(f"{label} must be a regular file")
        _verify_open_child(
            parent,
            name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            label,
        )
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, identity


def _read_anchor_descriptor(descriptor: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = LOCK_ANCHOR_BYTE_COUNT + 1
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return b"".join(chunks)


def _windows_lock_function(name: str):
    from ctypes import wintypes

    function = getattr(ctypes.WinDLL("kernel32", use_last_error=True), name)
    function.argtypes = (
        [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_WindowsOverlapped),
        ]
        if name == "LockFileEx"
        else [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_WindowsOverlapped),
        ]
    )
    function.restype = wintypes.BOOL
    return function


def _windows_file_handle(descriptor: int):
    import msvcrt
    from ctypes import wintypes

    handle = msvcrt.get_osfhandle(descriptor)
    if handle == -1:
        raise EvidenceError("Windows anchor descriptor has no OS file handle")
    return wintypes.HANDLE(handle)


def _windows_overlapped(offset: int) -> _WindowsOverlapped:
    overlapped = _WindowsOverlapped()
    overlapped.Offset = offset & 0xFFFFFFFF
    overlapped.OffsetHigh = (offset >> 32) & 0xFFFFFFFF
    overlapped.hEvent = None
    return overlapped


def _acquire_anchor_advisory_lock(
    descriptor: int, lock_api: str, offset: int, length: int
) -> None:
    _exact_value(
        lock_api,
        _expected_lock_api(platform.system()),
        "runtime exclusive anchor lock API",
    )
    if lock_api == POSIX_LOCK_API and os.name == "posix":
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN}:
                raise EvidenceError("exclusive advisory anchor lock is busy") from exc
            raise EvidenceError("POSIX advisory anchor lock failed closed") from exc
        return
    if lock_api == WINDOWS_LOCK_API and os.name == "nt":
        lock_file = _windows_lock_function("LockFileEx")
        overlapped = _windows_overlapped(offset)
        ctypes.set_last_error(0)
        acquired = lock_file(
            _windows_file_handle(descriptor),
            0x00000001 | 0x00000002,
            0,
            length & 0xFFFFFFFF,
            (length >> 32) & 0xFFFFFFFF,
            ctypes.byref(overlapped),
        )
        if not acquired:
            error = ctypes.get_last_error()
            if error in {33, 997}:
                raise EvidenceError("exclusive advisory anchor lock is busy")
            raise EvidenceError(
                f"Windows advisory anchor lock failed closed with error {error}"
            )
        return
    raise EvidenceError("exclusive advisory anchor locking is unsupported")


def _release_anchor_advisory_lock(
    descriptor: int, lock_api: str, offset: int, length: int
) -> None:
    if lock_api == POSIX_LOCK_API and os.name == "posix":
        try:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except OSError as exc:
            raise EvidenceError("POSIX advisory anchor unlock failed") from exc
        return
    if lock_api == WINDOWS_LOCK_API and os.name == "nt":
        unlock_file = _windows_lock_function("UnlockFileEx")
        overlapped = _windows_overlapped(offset)
        ctypes.set_last_error(0)
        released = unlock_file(
            _windows_file_handle(descriptor),
            0,
            length & 0xFFFFFFFF,
            (length >> 32) & 0xFFFFFFFF,
            ctypes.byref(overlapped),
        )
        if not released:
            raise EvidenceError(
                "Windows advisory anchor unlock failed with error "
                f"{ctypes.get_last_error()}"
            )
        return
    raise EvidenceError("exclusive advisory anchor unlocking is unsupported")


@dataclass
class _AdvisoryAnchorLock:
    path: Path
    parent: _PinnedDirectory
    name: str
    descriptor: int
    device: int
    inode: int
    expected_bytes: bytes
    content_sha256: str
    byte_offset: int
    byte_length: int
    lock_api: str
    filesystem: dict[str, Any]
    acquired_unix_ns: int
    locked: bool = True

    def verify(self) -> None:
        _verify_open_child(
            self.parent,
            self.name,
            self.descriptor,
            self.device,
            self.inode,
            "exclusive advisory anchor",
        )
        identity = os.fstat(self.descriptor)
        if not stat.S_ISREG(identity.st_mode) or identity.st_size != len(
            self.expected_bytes
        ):
            raise EvidenceError("exclusive advisory anchor size or type changed")
        observed_bytes = _read_anchor_descriptor(self.descriptor)
        if (
            observed_bytes != self.expected_bytes
            or hashlib.sha256(observed_bytes).hexdigest() != self.content_sha256
        ):
            raise EvidenceError("exclusive advisory anchor content changed")
        _exact_value(
            _probe_lock_filesystem(self.path),
            self.filesystem,
            "exclusive advisory anchor filesystem",
        )

    def release(self) -> None:
        failure: BaseException | None = None
        try:
            if self.locked:
                _release_anchor_advisory_lock(
                    self.descriptor,
                    self.lock_api,
                    self.byte_offset,
                    self.byte_length,
                )
        except BaseException as exc:
            failure = exc
        finally:
            self.locked = False
            try:
                os.close(self.descriptor)
            except BaseException as exc:
                if failure is None:
                    failure = exc
            try:
                self.parent.close()
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure


def _acquire_advisory_anchor(
    lock_contract: Mapping[str, Any], system: object
) -> _AdvisoryAnchorLock:
    anchor_path = _file_uri_path(lock_contract["anchor_uri"], "exclusive lock anchor URI")
    parent = _pin_directory(anchor_path.parent, "exclusive advisory anchor parent")
    resolved_path = parent.resolved_path / anchor_path.name
    descriptor: int | None = None
    locked = False
    try:
        if resolved_path.as_uri() != lock_contract["anchor_uri"]:
            raise EvidenceError(
                "exclusive advisory anchor URI is not canonical or traverses a link"
            )
        filesystem = _probe_lock_filesystem(resolved_path)
        _exact_value(
            filesystem,
            _validate_lock_filesystem(lock_contract["filesystem"], system),
            "auditor-signed anchor filesystem",
        )
        descriptor, identity = _open_existing_child(
            parent, anchor_path.name, "exclusive advisory anchor"
        )
        if (
            identity.st_dev != lock_contract["anchor_device"]
            or identity.st_ino != lock_contract["anchor_inode"]
        ):
            raise EvidenceError("exclusive advisory anchor signed identity differs")
        expected_bytes = bytes.fromhex(str(lock_contract["anchor_bytes_hex"]))
        if identity.st_size != len(expected_bytes):
            raise EvidenceError("exclusive advisory anchor signed size differs")
        lock_api = str(lock_contract["expected_lock_api"])
        byte_offset = int(lock_contract["lock_byte_offset"])
        byte_length = int(lock_contract["lock_byte_length"])
        _acquire_anchor_advisory_lock(
            descriptor, lock_api, byte_offset, byte_length
        )
        locked = True
        anchor = _AdvisoryAnchorLock(
            resolved_path,
            parent,
            anchor_path.name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            expected_bytes,
            str(lock_contract["anchor_sha256"]),
            byte_offset,
            byte_length,
            lock_api,
            dict(filesystem),
            time.time_ns(),
        )
        anchor.verify()
        return anchor
    except BaseException:
        if descriptor is not None:
            if locked:
                try:
                    _release_anchor_advisory_lock(
                        descriptor,
                        str(lock_contract["expected_lock_api"]),
                        int(lock_contract["lock_byte_offset"]),
                        int(lock_contract["lock_byte_length"]),
                    )
                except BaseException:
                    pass
            os.close(descriptor)
        parent.close()
        raise


@dataclass
class _ExclusiveHostLock:
    path: Path
    parent: _PinnedDirectory
    name: str
    descriptor: int | None
    device: int
    inode: int
    anchor: _AdvisoryAnchorLock
    evidence: dict[str, object]

    def release(self) -> None:
        failure: BaseException | None = None
        try:
            self.anchor.verify()
            if self.descriptor is None:
                raise EvidenceError("exclusive host lock marker descriptor is closed")
            _verify_open_child(
                self.parent,
                self.name,
                self.descriptor,
                self.device,
                self.inode,
                "exclusive host lock",
            )
            self.anchor.verify()
            if self.parent.descriptor is not None and os.unlink in os.supports_dir_fd:
                os.unlink(self.name, dir_fd=self.parent.descriptor)
                os.fsync(self.parent.descriptor)
            else:
                os.close(self.descriptor)
                self.descriptor = None
                self.parent.verify("exclusive host lock parent")
                current = self.path.lstat()
                if not _same_identity(current, self.device, self.inode):
                    raise EvidenceError(
                        "exclusive host lock identity changed before cleanup"
                    )
                self.anchor.verify()
                self.path.unlink()
        except BaseException as exc:
            failure = exc
        finally:
            if self.descriptor is not None:
                try:
                    os.close(self.descriptor)
                except BaseException as exc:
                    if failure is None:
                        failure = exc
                self.descriptor = None
            try:
                self.parent.close()
            except BaseException as exc:
                if failure is None:
                    failure = exc
            try:
                self.anchor.release()
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure


def _acquire_exclusive_host_lock(
    contract: Mapping[str, Any],
    manifest: Mapping[str, Any],
    *,
    raw_output_path: Path | None,
    collection_replay_registry: Path,
    retention_scope: str,
) -> _ExclusiveHostLock:
    _exact_value(
        retention_scope,
        FORMAL_LOCK_RETENTION_SCOPE,
        "exclusive lock retention scope",
    )
    lock_contract = _validate_exclusive_lock_contract(
        contract["exclusive_lock"], contract["system"]
    )
    path = _file_uri_path(lock_contract["marker_uri"], "exclusive lock marker URI")
    anchor_path = _file_uri_path(lock_contract["anchor_uri"], "exclusive lock anchor URI")
    prohibited_roots = [ROOT.resolve(), collection_replay_registry.resolve(strict=True)]
    verification_registry = _file_uri_path(
        manifest["verification_registry_uri"], "verification registry URI"
    )
    prohibited_roots.append(verification_registry.resolve(strict=False))
    if raw_output_path is not None:
        output = raw_output_path.resolve(strict=False)
        prohibited_roots.append(output.parent)
        if path.resolve(strict=False) == output or anchor_path.resolve(strict=False) == output:
            raise EvidenceError("exclusive lock paths cannot alias the raw output")
    if any(
        _is_within(candidate.resolve(strict=False), root)
        for candidate in (path, anchor_path)
        for root in prohibited_roots
    ):
        raise EvidenceError(
            "exclusive lock paths must be outside the repository, outputs, and registries"
        )
    anchor = _acquire_advisory_anchor(lock_contract, contract["system"])
    pinned_parent: _PinnedDirectory | None = None
    descriptor: int | None = None
    try:
        pinned_parent = _pin_directory(path.parent, "exclusive lock marker parent")
        resolved_path = pinned_parent.resolved_path / path.name
        if resolved_path.as_uri() != lock_contract["marker_uri"]:
            raise EvidenceError(
                "exclusive lock marker URI is not canonical or traverses a link"
            )
        marker_filesystem = _probe_lock_filesystem(pinned_parent.resolved_path)
        _exact_value(
            marker_filesystem,
            anchor.filesystem,
            "exclusive lock marker and anchor filesystem semantics",
        )
        if pinned_parent.device != anchor.device:
            raise EvidenceError("exclusive lock marker and anchor must share one local volume")
        if path.exists() or _is_link_or_junction(path):
            raise EvidenceError("exclusive host lock marker already exists or is a link")
        try:
            descriptor, identity = _open_exclusive_child(
                pinned_parent, path.name, "exclusive host lock marker"
            )
        except FileExistsError as exc:
            raise EvidenceError("exclusive host lock marker already exists") from exc
        marker = {
            "schema": FORMAL_LOCK_SCHEMA,
            "lock_id": lock_contract["lock_id"],
            "audit_id": manifest["audit_id"],
            "anchor_uri": lock_contract["anchor_uri"],
            "anchor_device": lock_contract["anchor_device"],
            "anchor_inode": lock_contract["anchor_inode"],
            "anchor_sha256": lock_contract["anchor_sha256"],
            "lock_api": lock_contract["expected_lock_api"],
            "acquired_unix_ns": anchor.acquired_unix_ns,
        }
        marker_payload = _canonical(marker) + b"\n"
        offset = 0
        while offset < len(marker_payload):
            written = os.write(descriptor, marker_payload[offset:])
            if written <= 0:
                raise OSError("exclusive host lock marker made no write progress")
            offset += written
        os.fsync(descriptor)
        if pinned_parent.descriptor is not None:
            os.fsync(pinned_parent.descriptor)
        _verify_open_child(
            pinned_parent,
            path.name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            "exclusive host lock marker",
        )
        anchor.verify()
        evidence = {
            "schema": FORMAL_LOCK_SCHEMA,
            "lock_id": lock_contract["lock_id"],
            "audit_id": manifest["audit_id"],
            "marker_uri": lock_contract["marker_uri"],
            "acquired_unix_ns": anchor.acquired_unix_ns,
            "retention_scope": retention_scope,
            "uniqueness_primitive": LOCK_UNIQUENESS_PRIMITIVE,
            "marker_role": LOCK_MARKER_ROLE,
            "anchor": {
                "uri": lock_contract["anchor_uri"],
                "device": lock_contract["anchor_device"],
                "inode": lock_contract["anchor_inode"],
                "content_sha256": lock_contract["anchor_sha256"],
                "lock_byte_offset": lock_contract["lock_byte_offset"],
                "lock_byte_length": lock_contract["lock_byte_length"],
                "lock_api": lock_contract["expected_lock_api"],
                "filesystem": dict(anchor.filesystem),
            },
        }
        return _ExclusiveHostLock(
            resolved_path,
            pinned_parent,
            path.name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            anchor,
            evidence,
        )
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if pinned_parent is not None:
            try:
                pinned_parent.close()
            except OSError:
                pass
        try:
            anchor.release()
        except BaseException:
            pass
        raise


def _load_formal_authorization(
    manifest_path: Path,
    challenge_path: Path,
    auditor_root_public_key_hex: str,
    config: Mapping[str, Any],
    config_id: str,
    profile_id: str,
    collection_replay_registry: Path,
) -> dict[str, Any]:
    manifest = load_json(manifest_path)
    _exact_keys(
        manifest,
        {
            "schema",
            "experiment_id",
            "config_id",
            "profile_id",
            "source_commit",
            "audit_id",
            "producer_public_key_hex",
            "not_before_unix",
            "not_after_unix",
            "collection_registry_uri",
            "collection_registry_id",
            "verification_registry_uri",
            "verification_registry_id",
            "registry_storage_contract",
            "host_execution_contract",
            "signature_hex",
        },
        "formal contract manifest",
    )
    _verify_root_signed_document(manifest, auditor_root_public_key_hex, "formal contract manifest")
    _validate_host_execution_contract(manifest["host_execution_contract"])
    now = int(time.time())
    expected = {
        "schema": FORMAL_CONTRACT_SCHEMA,
        "experiment_id": config["experiment_id"],
        "config_id": config_id,
        "profile_id": profile_id,
    }
    for key, value in expected.items():
        _exact_value(manifest[key], value, f"formal contract manifest.{key}")
    if not _full_commit(manifest["source_commit"]):
        raise EvidenceError("formal contract manifest requires an exact source commit")
    audit_id = _nonempty_ascii(manifest["audit_id"], "formal contract manifest audit ID")
    if len(audit_id) < 16:
        raise EvidenceError("formal contract manifest audit ID is invalid")
    _opaque_id(
        manifest["producer_public_key_hex"],
        "formal contract manifest producer key",
    )
    if not (
        _integer(manifest["not_before_unix"], "manifest not_before", 1)
        <= now
        <= _integer(manifest["not_after_unix"], "manifest not_after", 1)
    ):
        raise EvidenceError("formal contract manifest is not currently valid")
    _exact_value(
        manifest["registry_storage_contract"],
        REGISTRY_STORAGE_CONTRACT,
        "formal contract manifest.registry_storage_contract",
    )
    _registry_id(manifest["collection_registry_id"], "collection registry ID")
    _registry_id(manifest["verification_registry_id"], "verification registry ID")
    _require_registry_identity(
        collection_replay_registry,
        namespace="collection",
        expected_registry_id=manifest["collection_registry_id"],
        expected_uri=manifest["collection_registry_uri"],
    )
    if type(manifest["verification_registry_uri"]) is not str or not str(
        manifest["verification_registry_uri"]
    ).startswith("file:"):
        raise EvidenceError("formal contract verification registry URI is invalid")

    challenge = load_json(challenge_path)
    _exact_keys(
        challenge,
        {
            "schema",
            "experiment_id",
            "config_id",
            "profile_id",
            "audit_id",
            "formal_manifest_sha256",
            "nonce_hex",
            "issued_unix",
            "expires_unix",
            "signature_hex",
        },
        "freshness challenge",
    )
    _verify_root_signed_document(challenge, auditor_root_public_key_hex, "freshness challenge")
    manifest_sha256 = _identity(manifest)
    challenge_expected = {
        "schema": FRESHNESS_CHALLENGE_SCHEMA,
        "experiment_id": config["experiment_id"],
        "config_id": config_id,
        "profile_id": profile_id,
        "audit_id": manifest["audit_id"],
        "formal_manifest_sha256": manifest_sha256,
    }
    for key, value in challenge_expected.items():
        _exact_value(challenge[key], value, f"freshness challenge.{key}")
    nonce = challenge["nonce_hex"]
    if (
        type(nonce) is not str
        or len(nonce) != 64
        or any(c not in "0123456789abcdef" for c in nonce)
    ):
        raise EvidenceError("freshness challenge nonce is invalid")
    _opaque_id(challenge["formal_manifest_sha256"], "freshness manifest digest")
    issued = _integer(challenge["issued_unix"], "challenge issued", 1)
    expires = _integer(challenge["expires_unix"], "challenge expires", 1)
    if expires - issued > 3600 or not issued <= now <= expires:
        raise EvidenceError("freshness challenge is expired, premature, or valid for over one hour")
    return {
        "manifest": manifest,
        "challenge": challenge,
        "auditor_root_sha256": hashlib.sha256(
            bytes.fromhex(auditor_root_public_key_hex)
        ).hexdigest(),
    }


def _signed_window_bounds_ns(
    manifest: Mapping[str, Any], challenge: Mapping[str, Any]
) -> tuple[int, int]:
    start = max(
        _integer(manifest["not_before_unix"], "manifest start", 1),
        _integer(challenge["issued_unix"], "challenge issued", 1),
    ) * 1_000_000_000
    end = (
        min(
            _integer(manifest["not_after_unix"], "manifest end", 1),
            _integer(challenge["expires_unix"], "challenge expires", 1),
        )
        + 1
    ) * 1_000_000_000 - 1
    return start, end


def _require_formal_authorization(
    profile: Mapping[str, Any],
    *,
    config: Mapping[str, Any] | None = None,
    config_id: str | None = None,
    profile_id: str | None = None,
    manifest_path: Path | None = None,
    challenge_path: Path | None = None,
    auditor_root_public_key_hex: str | None = None,
    collection_replay_registry: Path | None = None,
    signing_key_path: Path | None = None,
) -> dict[str, object]:
    if profile["enabled"] is not True:
        raise RuntimeError(
            "formal E9 collection is disabled pending an auditor-signed contract and challenge"
        )
    if (
        None
        in {
            config_id,
            profile_id,
            manifest_path,
            challenge_path,
            auditor_root_public_key_hex,
            collection_replay_registry,
        }
        or config is None
    ):
        raise RuntimeError(
            "formal E9 requires manifest, fresh challenge, and explicit auditor root"
        )
    authorization = _load_formal_authorization(
        manifest_path,
        challenge_path,
        auditor_root_public_key_hex,
        config,
        config_id,
        profile_id,
        collection_replay_registry,
    )  # type: ignore[arg-type]
    _preflight_formal_signing_key(
        signing_key_path,
        authorization["manifest"]["producer_public_key_hex"],
    )
    state = _git_state()
    if state["commit"] != authorization["manifest"]["source_commit"] or state["clean"] is not True:
        raise RuntimeError("formal E9 collection requires its exact clean frozen source commit")
    host_contract = _validate_host_execution_contract(
        authorization["manifest"]["host_execution_contract"]
    )
    collection_started_unix_ns = time.time_ns()
    pre_attestation = _capture_host_attestation(host_contract, "PRE_COLLECTION")
    window_start, window_end = _signed_window_bounds_ns(
        authorization["manifest"], authorization["challenge"]
    )
    if not (
        window_start
        <= collection_started_unix_ns
        <= int(pre_attestation["captured_unix_ns"])
        <= window_end
    ):
        raise EvidenceError("formal pre-attestation is outside its signed nanosecond window")
    return {
        "source_state": state,
        "authorization": authorization,
        "host_contract": host_contract,
        "collection_started_unix_ns": collection_started_unix_ns,
        "pre_attestation": pre_attestation,
    }


def _sample_body(
    profile_name: str,
    profile_id: str,
    coordinate: Coordinate,
    external: Mapping[str, object],
    resource: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": SAMPLE_SCHEMA,
        "profile": profile_name,
        "profile_id": profile_id,
        "seed": coordinate.seed,
        "case": coordinate.case,
        "case_kind": "FAILURE" if coordinate.case in FAILURE_CASES else "FUNCTIONAL_SUCCESS",
        "case_code": CASE_CODES[coordinate.case],
        "case_ordinal": coordinate.ordinal,
        "schedule_index": coordinate.schedule_index,
        "request": external["request"],
        "response": external["response"],
        "connection": external["connection"],
        "timing": external["timing"],
        "decoded_body": external["decoded_body"],
        "server_resource": dict(resource),
    }


def _chain(samples: Sequence[Mapping[str, object]]) -> str:
    state = bytes(32)
    for sample in samples:
        state = hashlib.sha256(state + _canonical(sample)).digest()
    return state.hex()


def _load_private_key(path: Path):
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise RuntimeError("formal E9 signing requires the cryptography package") from exc
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise RuntimeError("cannot read formal E9 signing key") from exc
    if data.startswith(b"-----BEGIN"):
        try:
            key = serialization.load_pem_private_key(data, password=None)
        except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
            raise RuntimeError(
                "formal E9 signing key must be an unencrypted Ed25519 private key"
            ) from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError("formal E9 signing key is not Ed25519")
        return key
    try:
        encoded = data.decode("ascii")
    except UnicodeError as exc:
        raise RuntimeError("Ed25519 private key must be PEM or 32-byte lowercase hex") from exc
    if len(encoded) != 64:
        raise RuntimeError("raw Ed25519 private key must contain 32 bytes")
    if any(character not in "0123456789abcdef" for character in encoded):
        raise RuntimeError("Ed25519 private key must be PEM or 32-byte lowercase hex")
    raw = bytes.fromhex(encoded)
    return Ed25519PrivateKey.from_private_bytes(raw)


def _preflight_formal_signing_key(
    signing_key_path: Path | None,
    expected_public_key_hex: object,
) -> None:
    expected = _opaque_id(expected_public_key_hex, "formal contract manifest producer key")
    if signing_key_path is None:
        raise RuntimeError("formal E9 collection requires --signing-key")
    key = _load_private_key(signing_key_path)
    from cryptography.hazmat.primitives import serialization

    actual = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )
    if not secrets.compare_digest(actual, expected):
        raise RuntimeError("formal signing key does not match the auditor-frozen producer key")


def _write_registry_marker_exclusive(
    registry: Path,
    name: str,
    payload: bytes,
    label: str,
) -> None:
    parent = _pin_directory(registry, f"{label} parent")
    descriptor: int | None = None
    try:
        descriptor, identity = _open_exclusive_child(parent, name, label)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError(f"{label} made no write progress")
            offset += written
        os.fsync(descriptor)
        if parent.descriptor is not None:
            os.fsync(parent.descriptor)
        _verify_open_child(
            parent,
            name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            label,
        )
    finally:
        if descriptor is not None:
            os.close(descriptor)
        parent.close()


def _read_registry_marker(registry: Path, name: str, maximum: int, label: str) -> bytes:
    parent = _pin_directory(registry, f"{label} parent")
    descriptor: int | None = None
    try:
        descriptor, identity = _open_existing_child(parent, name, label)
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(4096, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum:
            raise EvidenceError(f"{label} exceeds its byte limit")
        _verify_open_child(
            parent,
            name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            label,
        )
        return payload
    finally:
        if descriptor is not None:
            os.close(descriptor)
        parent.close()


def _consume_nonce(registry: Path, namespace: str, nonce_hex: str, marker: str) -> None:
    if registry.is_symlink() or not registry.is_dir():
        raise EvidenceError("replay registry must be pre-provisioned before nonce use")
    name = f"{namespace}-{nonce_hex}.used"
    try:
        _write_registry_marker_exclusive(
            registry,
            name,
            (marker + "\n").encode("ascii"),
            "collection replay registry marker",
        )
    except FileExistsError as exc:
        raise EvidenceError(
            f"freshness challenge nonce was already consumed for {namespace}"
        ) from exc


def _register_verification_nonce(registry: Path, nonce_hex: str, raw_id: str) -> None:
    if registry.is_symlink() or not registry.is_dir():
        raise EvidenceError("replay registry must be pre-provisioned before nonce use")
    name = f"verification-{nonce_hex}.used"
    payload = (raw_id + "\n").encode("ascii")
    try:
        _write_registry_marker_exclusive(
            registry,
            name,
            payload,
            "verification replay registry marker",
        )
    except FileExistsError:
        try:
            existing = _read_registry_marker(
                registry,
                name,
                len(payload),
                "verification replay registry marker",
            )
            registered_raw_id = existing.decode("ascii").strip()
        except (OSError, UnicodeError) as exc:
            raise EvidenceError("verification replay registry entry is unreadable") from exc
        if registered_raw_id != raw_id:
            raise EvidenceError(
                "freshness nonce is already bound to a different raw artifact"
            ) from None
        return


def _run_stress_audit(
    profile: Mapping[str, Any], real_sut_results: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    capacity = int(profile["max_pending_padding"])
    padder = _StrictAsyncPadder(1.0, capacity)
    pending = [padder.defer(index, time.perf_counter_ns()) for index in range(capacity)]
    overflow_failed_closed = False
    try:
        padder.defer("overflow", time.perf_counter_ns())
    except RuntimeError:
        overflow_failed_closed = True
    for future in pending:
        future.result(timeout=2.0)
    padding = padder.snapshot()
    if (
        not all(result["one_additional_request_queued"] is True for result in real_sut_results)
        or not overflow_failed_closed
        or padding["overflow_failures"] != 1
    ):
        raise RuntimeError("E9 concurrency/overflow stress audit did not fail closed")
    return {
        "worker_saturation": {
            "probe": "CONCURRENT_REAL_LOOPBACK_AUTH_REQUESTS_PER_SEED",
            "per_seed": list(real_sut_results),
        },
        "padding_capacity_probe": {
            "probe": "CONFIGURED_PADDER_MECHANISM_CAPACITY_NO_TCP_OVERFLOW_CLAIM",
            "capacity": capacity,
            "peak_pending": padding["peak_pending"],
            "overflow_attempts": padding["overflow_failures"],
            "overflow_failed_closed": overflow_failed_closed,
            "pending_after_probe": padding["pending"],
        },
    }


def _seed_child_timeout_seconds(profile: Mapping[str, Any]) -> float:
    per_seed_requests = (
        int(profile["auth_workers"])
        + 1
        + len(ALL_CASES) * int(profile["warmup_per_case_per_seed"])
        + len(ALL_CASES) * int(profile["samples_per_case_per_seed"])
    )
    timeout = 10.0 + 2.0 * float(profile["socket_timeout_seconds"]) * per_seed_requests
    return min(SEED_CHILD_MAX_TIMEOUT_SECONDS, max(30.0, timeout))


def _build_seed_child_request(
    profile_name: str,
    profile_id: str,
    profile: Mapping[str, Any],
    seed: int,
    seed_index: int,
    expected_python_runtime: Mapping[str, object],
    expected_cpu_affinity: Sequence[int],
    expected_source_snapshot: Mapping[str, object] | None = None,
    expected_sealed_archive: Mapping[str, object] | None = None,
) -> dict[str, object]:
    request: dict[str, object] = {
        "schema": SEED_CHILD_REQUEST_SCHEMA,
        "profile_name": profile_name,
        "profile_id": profile_id,
        "profile": dict(profile),
        "seed": seed,
        "seed_index": seed_index,
        "parent_process_id": os.getpid(),
        "expected_python_runtime": dict(expected_python_runtime),
        "expected_cpu_affinity": list(expected_cpu_affinity),
    }
    if profile_name == PROCESS_LONG_TEST_PROFILE_NAME:
        if expected_source_snapshot is None or expected_sealed_archive is None:
            raise EvidenceError(
                "process long-test seed child requires tracked and sealed source bindings"
            )
        request["expected_source_snapshot"] = dict(expected_source_snapshot)
        request["expected_sealed_archive"] = dict(expected_sealed_archive)
    elif expected_source_snapshot is not None or expected_sealed_archive is not None:
        raise EvidenceError("only the process long-test seed child accepts source bindings")
    return _validate_seed_child_request(request)


def _validate_seed_child_request(value: object) -> dict[str, Any]:
    request = _mapping(value, "seed-child request")
    profile_name = request.get("profile_name")
    if type(profile_name) is not str or profile_name not in {
        "smoke",
        "formal",
        PROCESS_LONG_TEST_PROFILE_NAME,
    }:
        raise EvidenceError(
            "seed-child profile must be smoke, formal, or the Linux process long test"
        )
    request_keys = {
        "schema",
        "profile_name",
        "profile_id",
        "profile",
        "seed",
        "seed_index",
        "parent_process_id",
        "expected_python_runtime",
        "expected_cpu_affinity",
    }
    if profile_name == PROCESS_LONG_TEST_PROFILE_NAME:
        request_keys.update({"expected_source_snapshot", "expected_sealed_archive"})
    _exact_keys(
        request,
        request_keys,
        "seed-child request",
    )
    _exact_value(request["schema"], SEED_CHILD_REQUEST_SCHEMA, "seed-child request schema")
    profile_id = request["profile_id"]
    if (
        type(profile_id) is not str
        or len(profile_id) != 64
        or any(character not in "0123456789abcdef" for character in profile_id)
    ):
        raise EvidenceError("seed-child profile ID must be a lowercase SHA-256 digest")
    profile = _mapping(request["profile"], "seed-child profile")
    profile_common_keys = {
        "evidence_class",
        "enabled",
        "seeds",
        "samples_per_case_per_seed",
        "warmup_per_case_per_seed",
        "bootstrap_replicates",
        "pbkdf2_iterations",
        "pbkdf2_dklen",
        "kdf_workloads",
        "failure_padding_ms",
        "auth_workers",
        "max_pending_padding",
        "socket_timeout_seconds",
    }
    if profile_name == "formal":
        profile_specific_keys = {"freeze_status", "formal_contract", "formal_blockers"}
        if profile.get("formal_contract") == PREREGISTERED_FORMAL_CONTRACT:
            profile_specific_keys.update(
                {"seed_split", "seed_workload_mapping", "kdf_workload_contracts"}
            )
    elif profile_name == PROCESS_LONG_TEST_PROFILE_NAME:
        profile_specific_keys = {
            "qualification_id",
            "formal_evidence_eligible",
            "formal_claim_eligible",
            "formal_blocker_effect",
            "external_review_requirement",
            "authentication",
        }
    else:
        profile_specific_keys = {
            "expected_commit",
            "independent_audit_id",
            "producer_public_key_hex",
        }
    _exact_keys(profile, profile_common_keys | profile_specific_keys, "seed-child profile")
    if (
        profile_name == "formal"
        and profile.get("formal_contract") == PREREGISTERED_FORMAL_CONTRACT
    ):
        _exact_value(
            profile["seed_split"],
            {
                "training_seeds_by_kdf": {
                    key: list(PREREGISTERED_TRAINING_SEEDS_BY_KDF[key])
                    for key in PREREGISTERED_KDF_STRATUM_IDS
                },
                "evaluation_seeds_by_kdf": {
                    key: list(PREREGISTERED_EVALUATION_SEEDS_BY_KDF[key])
                    for key in PREREGISTERED_KDF_STRATUM_IDS
                },
            },
            "seed-child v5 seed split",
        )
        _exact_value(
            profile["seed_workload_mapping"],
            PREREGISTERED_SEED_WORKLOAD_MAPPING,
            "seed-child v5 workload mapping",
        )
        _exact_value(
            profile["kdf_workload_contracts"],
            PREREGISTERED_KDF_WORKLOADS,
            "seed-child v5 KDF workload contracts",
        )
    if profile_name == PROCESS_LONG_TEST_PROFILE_NAME:
        expected_profile, expected_profile_id = process_long_test_profile_contract(
            _expected_process_long_test_config()
        )
        _exact_value(profile, expected_profile, "seed-child process long-test profile")
        _exact_value(
            profile_id,
            expected_profile_id,
            "seed-child process long-test profile ID",
        )
        source_snapshot = _validate_tracked_source_snapshot(
            request["expected_source_snapshot"], "seed-child expected source snapshot"
        )
        sealed_archive = _validate_sealed_archive_identity(
            request["expected_sealed_archive"], "seed-child expected sealed archive"
        )
        _exact_value(
            sealed_archive["commit"],
            source_snapshot["commit"],
            "seed-child sealed archive commit binding",
        )
        _exact_value(
            sealed_archive["git_tree"],
            source_snapshot["git_tree"],
            "seed-child sealed archive Git tree binding",
        )
    seeds = profile.get("seeds")
    if type(seeds) is not list or not seeds:
        raise EvidenceError("seed-child profile seeds must be a nonempty array")
    seed_index = _integer(request["seed_index"], "seed-child seed index")
    if seed_index >= len(seeds):
        raise EvidenceError("seed-child seed index is outside the frozen seed set")
    seed = _integer(request["seed"], "seed-child seed", 1)
    _exact_value(seed, seeds[seed_index], "seed-child frozen seed order")
    _integer(request["parent_process_id"], "seed-child parent process ID", 1)

    _validate_python_runtime_identity(
        request["expected_python_runtime"], "seed-child Python runtime"
    )
    affinity = request["expected_cpu_affinity"]
    if type(affinity) is not list or not affinity:
        raise EvidenceError("seed-child expected CPU affinity must be a nonempty array")
    cpus = [_integer(cpu, "seed-child expected CPU", 0) for cpu in affinity]
    if cpus != sorted(set(cpus)):
        raise EvidenceError("seed-child expected CPU affinity must be sorted and unique")

    _integer(profile["samples_per_case_per_seed"], "seed-child measured sample count", 1)
    _integer(profile["warmup_per_case_per_seed"], "seed-child warmup count")
    _number(profile["failure_padding_ms"], "seed-child failure padding")
    _integer(profile["auth_workers"], "seed-child auth worker count", 1)
    _integer(profile["max_pending_padding"], "seed-child padding capacity", 1)
    _number(profile["socket_timeout_seconds"], "seed-child socket timeout", 0.001)
    workloads = profile["kdf_workloads"]
    if type(workloads) is not list or not workloads:
        raise EvidenceError("seed-child KDF workloads must be a nonempty array")
    for index, workload_value in enumerate(workloads):
        workload = _mapping(workload_value, f"seed-child KDF workload {index}")
        algorithm = workload.get("algorithm")
        if algorithm == "pbkdf2_hmac_sha256":
            _exact_keys(
                workload,
                {"algorithm", "iterations", "dklen"},
                f"seed-child KDF workload {index}",
            )
            _integer(workload["iterations"], "seed-child PBKDF2 iterations", 1)
            _integer(workload["dklen"], "seed-child PBKDF2 output length", 1)
        elif algorithm == "argon2id":
            argon2_keys = {
                "algorithm",
                "memory_kib",
                "time_cost",
                "parallelism",
                "hash_len",
            }
            if profile.get("formal_contract") == PREREGISTERED_FORMAL_CONTRACT:
                argon2_keys.add("version")
            _exact_keys(
                workload,
                argon2_keys,
                f"seed-child KDF workload {index}",
            )
            for key in ("memory_kib", "time_cost", "parallelism", "hash_len"):
                _integer(workload[key], f"seed-child Argon2 {key}", 1)
            if "version" in argon2_keys:
                _exact_value(
                    workload["version"],
                    PREREGISTERED_ARGON2_ALGORITHM_VERSION,
                    "seed-child Argon2 algorithm version",
                )
        else:
            raise EvidenceError("seed-child KDF workload algorithm is unsupported")
    return request


def _run_seed_child_request(value: object) -> dict[str, object]:
    request = _validate_seed_child_request(value)
    expected_runtime = _mapping(
        request["expected_python_runtime"], "seed-child expected Python runtime"
    )
    runtime = _probe_python_runtime_identity()
    _exact_value(runtime, expected_runtime, "seed-child active Python runtime")
    affinity = _probe_cpu_affinity()
    _exact_value(
        affinity,
        request["expected_cpu_affinity"],
        "seed-child active CPU affinity",
    )
    parent_process_id = int(request["parent_process_id"])
    process_id = os.getpid()
    if process_id == parent_process_id:
        raise EvidenceError("seed-child did not cross an operating-system process boundary")

    profile_name = str(request["profile_name"])
    if profile_name == PROCESS_LONG_TEST_PROFILE_NAME and platform.system() != "Linux":
        raise EvidenceError("the E9 process long-test seed child is Linux-only")
    source_before: dict[str, Any] | None = None
    actual_parent_process_id: int | None = None
    sealed_archive_identity: dict[str, Any] | None = None
    if profile_name == PROCESS_LONG_TEST_PROFILE_NAME:
        if not _SEALED_CHILD_MODE:
            raise EvidenceError("process long-test seed child must execute from a sealed zipapp")
        sealed_archive_identity = _probe_sealed_child_archive(
            request["expected_sealed_archive"]
        )
        expected_source_snapshot = _validate_tracked_source_snapshot(
            request["expected_source_snapshot"], "seed-child expected source snapshot"
        )
        source_before = _tracked_source_snapshot()
        _exact_value(
            source_before,
            expected_source_snapshot,
            "seed-child source snapshot before workload",
        )
        actual_parent_process_id = os.getppid()
        _exact_value(
            actual_parent_process_id,
            parent_process_id,
            "seed-child actual parent process ID",
        )
    profile_id = str(request["profile_id"])
    profile = _mapping(request["profile"], "seed-child profile")
    seed = int(request["seed"])
    seed_index = int(request["seed_index"])
    workload = _workload_for_seed(profile, seed, seed_index)
    seed_plan = [coordinate for coordinate in measurement_plan(profile) if coordinate.seed == seed]
    server = _LoopbackServer(profile, workload, seed_index)
    server.start()
    samples: list[dict[str, object]] = []
    stress_result: dict[str, object]
    runtime_result: dict[str, object]
    measurement_environment: dict[str, object] | None = None
    capture_measurement_environment = (
        profile_name == "formal"
        and profile.get("formal_contract") == PREREGISTERED_FORMAL_CONTRACT
    )
    try:
        stress_result = server.run_concurrency_stress(seed)
        auth_worker_native_ids = server.system.auth_worker_native_ids()
        if len(auth_worker_native_ids) != int(profile["auth_workers"]):
            raise EvidenceError(
                "seed-child stress did not identify every configured auth worker"
            )
        if capture_measurement_environment:
            measurement_environment = {
                "pre": _probe_seed_child_measurement_environment(
                    "PRE_SEED_MEASUREMENT", auth_worker_native_ids, workload
                )
            }
        warmup_count = int(profile["warmup_per_case_per_seed"])
        measured_count = int(profile["samples_per_case_per_seed"])
        for case in ALL_CASES:
            for offset in range(warmup_count):
                coordinate = Coordinate(seed, case, measured_count + offset, -1)
                _collect_external(
                    server.host,
                    server.port,
                    coordinate,
                    float(profile["socket_timeout_seconds"]),
                )
                server.take_result(coordinate)
        for coordinate in seed_plan:
            external = _collect_external(
                server.host,
                server.port,
                coordinate,
                float(profile["socket_timeout_seconds"]),
            )
            resource = server.take_result(coordinate)
            body = _sample_body(profile_name, profile_id, coordinate, external, resource)
            samples.append({**body, "sample_id": _identity(body)})
        if capture_measurement_environment:
            if measurement_environment is None:
                raise RuntimeError("seed-child pre-measurement environment is missing")
            post_auth_worker_native_ids = server.system.auth_worker_native_ids()
            _exact_value(
                post_auth_worker_native_ids,
                auth_worker_native_ids,
                "seed-child auth worker native IDs across measurement",
            )
            post_environment = _probe_seed_child_measurement_environment(
                "POST_SEED_MEASUREMENT", post_auth_worker_native_ids, workload
            )
            measurement_environment["post"] = post_environment
    finally:
        runtime_result = server.close()
    result: dict[str, object] = {
        "schema": SEED_CHILD_RESULT_SCHEMA,
        "status": "ok",
        "seed": seed,
        "seed_index": seed_index,
        "process_id": process_id,
        "python_runtime": runtime,
        "cpu_affinity": affinity,
        "listen_host": server.host,
        "listen_port": server.port,
        "sut_instance_id": server.instance_id,
        "stress_result": stress_result,
        "samples": samples,
        "runtime": runtime_result,
    }
    if capture_measurement_environment:
        if measurement_environment is None or set(measurement_environment) != {"pre", "post"}:
            raise RuntimeError("seed-child measurement environment is incomplete")
        result["measurement_environment"] = measurement_environment
    if profile_name == PROCESS_LONG_TEST_PROFILE_NAME:
        if (
            source_before is None
            or actual_parent_process_id is None
            or sealed_archive_identity is None
        ):
            raise RuntimeError("process long-test sealed source/parent binding was not captured")
        source_after = _tracked_source_snapshot()
        _exact_value(
            source_after,
            source_before,
            "seed-child source snapshot after workload",
        )
        result.update(
            {
                "actual_parent_process_id": actual_parent_process_id,
                "source_before": source_before,
                "source_after": source_after,
                "sealed_archive": sealed_archive_identity,
            }
        )
    return result


def _validate_seed_child_result(
    value: object,
    request_value: object,
    launched_process_id: int,
) -> dict[str, Any]:
    request = _validate_seed_child_request(request_value)
    result = _mapping(value, "seed-child result")
    result_keys = {
        "schema",
        "status",
        "seed",
        "seed_index",
        "process_id",
        "python_runtime",
        "cpu_affinity",
        "listen_host",
        "listen_port",
        "sut_instance_id",
        "stress_result",
        "samples",
        "runtime",
    }
    if request["profile_name"] == PROCESS_LONG_TEST_PROFILE_NAME:
        result_keys.update(
            {"actual_parent_process_id", "source_before", "source_after", "sealed_archive"}
        )
    preregistered_formal = (
        request["profile_name"] == "formal"
        and _mapping(request["profile"], "seed-child profile").get("formal_contract")
        == PREREGISTERED_FORMAL_CONTRACT
    )
    if preregistered_formal:
        result_keys.add("measurement_environment")
    _exact_keys(
        result,
        result_keys,
        "seed-child result",
    )
    _exact_value(result["schema"], SEED_CHILD_RESULT_SCHEMA, "seed-child result schema")
    _exact_value(result["status"], "ok", "seed-child result status")
    _exact_value(result["seed"], request["seed"], "seed-child result seed")
    _exact_value(result["seed_index"], request["seed_index"], "seed-child result seed index")
    process_id = _integer(result["process_id"], "seed-child reported process ID", 1)
    _exact_value(process_id, launched_process_id, "Popen/seed-child process ID binding")
    if process_id == int(request["parent_process_id"]):
        raise EvidenceError("seed-child process ID equals its parent process ID")
    if request["profile_name"] == PROCESS_LONG_TEST_PROFILE_NAME:
        _exact_value(
            result["actual_parent_process_id"],
            request["parent_process_id"],
            "seed-child actual/requested parent process ID binding",
        )
        expected_source = _validate_tracked_source_snapshot(
            request["expected_source_snapshot"], "seed-child expected source snapshot"
        )
        _exact_value(
            result["source_before"],
            expected_source,
            "seed-child source snapshot before workload",
        )
        _exact_value(
            result["source_after"],
            expected_source,
            "seed-child source snapshot after workload",
        )
        _exact_value(
            result["sealed_archive"],
            request["expected_sealed_archive"],
            "seed-child sealed archive identity",
        )
    _exact_value(
        result["python_runtime"],
        request["expected_python_runtime"],
        "seed-child reported Python runtime",
    )
    _exact_value(
        result["cpu_affinity"],
        request["expected_cpu_affinity"],
        "seed-child reported CPU affinity",
    )
    _exact_value(result["listen_host"], "127.0.0.1", "seed-child listen host")
    listen_port = _integer(result["listen_port"], "seed-child listen port", 1)
    instance_id = result["sut_instance_id"]
    if (
        type(instance_id) is not str
        or len(instance_id) != 32
        or any(character not in "0123456789abcdef" for character in instance_id)
    ):
        raise EvidenceError("seed-child SUT instance ID is invalid")

    profile = _mapping(request["profile"], "seed-child profile")
    seed = int(request["seed"])
    seed_index = int(request["seed_index"])
    expected_workload = _workload_for_seed(profile, seed, seed_index)
    if preregistered_formal:
        measurement_environment = _mapping(
            result["measurement_environment"], "seed-child measurement environment"
        )
        _exact_keys(
            measurement_environment,
            {"pre", "post"},
            "seed-child measurement environment",
        )
        pre_environment = _validate_seed_child_measurement_environment(
            measurement_environment["pre"],
            "PRE_SEED_MEASUREMENT",
            process_id,
            request["expected_cpu_affinity"],
            int(profile["auth_workers"]),
            expected_workload,
        )
        post_environment = _validate_seed_child_measurement_environment(
            measurement_environment["post"],
            "POST_SEED_MEASUREMENT",
            process_id,
            request["expected_cpu_affinity"],
            int(profile["auth_workers"]),
            expected_workload,
        )
        if int(post_environment["captured_unix_ns"]) <= int(
            pre_environment["captured_unix_ns"]
        ):
            raise EvidenceError("seed-child environment postflight does not follow preflight")
        _exact_value(
            _stable_seed_child_measurement_environment(post_environment),
            _stable_seed_child_measurement_environment(pre_environment),
            "seed-child stable measurement environment",
        )
    expected_stress = {
        "configured_workers": profile["auth_workers"],
        "simultaneously_active_sut_workers": profile["auth_workers"],
        "concurrent_loopback_requests": int(profile["auth_workers"]) + 1,
        "one_additional_request_queued": True,
    }
    _exact_value(result["stress_result"], expected_stress, "seed-child stress result")
    expected_plan = [
        coordinate for coordinate in measurement_plan(profile) if coordinate.seed == seed
    ]
    samples = result["samples"]
    if type(samples) is not list or len(samples) != len(expected_plan):
        raise EvidenceError("seed-child samples do not cover its frozen seed denominator")
    validated_samples = [
        _validate_sample(
            sample,
            str(request["profile_name"]),
            str(request["profile_id"]),
            profile,
            coordinate,
        )
        for sample, coordinate in zip(samples, expected_plan, strict=True)
    ]
    if preregistered_formal:
        expected_worker_native_ids = set(pre_environment["auth_worker_native_ids"])
        if any(
            int(sample["server_resource"]["auth_worker_native_id"])
            not in expected_worker_native_ids
            for sample in validated_samples
        ):
            raise EvidenceError(
                "seed-child sample auth worker is absent from native-thread evidence"
            )
    if any(
        sample["server_resource"]["sut_process_id"] != process_id
        for sample in validated_samples
    ):
        raise EvidenceError("seed-child sample process ID differs from its child process")
    if any(
        sample["server_resource"]["sut_instance_id"] != instance_id
        for sample in validated_samples
    ):
        raise EvidenceError("seed-child sample instance differs from its child SUT instance")
    if any(sample["connection"]["peer_port"] != listen_port for sample in validated_samples):
        raise EvidenceError("seed-child sample peer port differs from its listener")

    runtime_result = _mapping(result["runtime"], "seed-child runtime")
    _exact_keys(
        runtime_result,
        {
            "handler_threads_created",
            "handler_threads_alive_after_shutdown",
            "padding",
            "server_errors",
        },
        "seed-child runtime",
    )
    expected_requests = (
        len(expected_plan)
        + len(ALL_CASES) * int(profile["warmup_per_case_per_seed"])
        + int(profile["auth_workers"])
        + 1
    )
    _exact_value(
        runtime_result["handler_threads_created"],
        expected_requests,
        "seed-child handler count",
    )
    _exact_value(
        runtime_result["handler_threads_alive_after_shutdown"],
        0,
        "seed-child alive handler count",
    )
    _exact_value(runtime_result["server_errors"], [], "seed-child server errors")
    padding = _mapping(runtime_result["padding"], "seed-child padding")
    _exact_keys(
        padding,
        {
            "scheduled_async",
            "immediate_after_slow_auth",
            "peak_pending",
            "pending",
            "overflow_failures",
            "max_pending",
        },
        "seed-child padding",
    )
    for key in padding:
        _integer(padding[key], f"seed-child padding {key}")
    _exact_value(padding["pending"], 0, "seed-child pending padding")
    _exact_value(padding["overflow_failures"], 0, "seed-child padding overflow")
    _exact_value(padding["max_pending"], profile["max_pending_padding"], "seed-child padding cap")
    if int(padding["peak_pending"]) > int(padding["max_pending"]):
        raise EvidenceError("seed-child padding peak exceeds its configured capacity")
    if (
        int(padding["scheduled_async"]) + int(padding["immediate_after_slow_auth"])
        != expected_requests
    ):
        raise EvidenceError("seed-child padding accounting does not conserve requests")
    return result


def _terminate_seed_child(process: subprocess.Popen[bytes]) -> None:
    cleanup_errors: list[BaseException] = []
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        except BaseException as exc:
            cleanup_errors.append(exc)
    try:
        process.wait(timeout=SEED_CHILD_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    except BaseException as exc:
        cleanup_errors.append(exc)
    if process.poll() is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        except BaseException as exc:
            cleanup_errors.append(exc)
        try:
            process.wait(timeout=SEED_CHILD_TERMINATE_GRACE_SECONDS)
        except BaseException as exc:
            cleanup_errors.append(exc)
    if process.poll() is None:
        cause = cleanup_errors[0] if cleanup_errors else None
        raise RuntimeError("seed-child process could not be killed and reaped") from cause


def _communicate_seed_child_bounded(
    process: subprocess.Popen[bytes],
    payload: bytes,
    timeout_seconds: float,
) -> tuple[bytes, bytes]:
    if process.stdin is None or process.stdout is None or process.stderr is None:
        _terminate_seed_child(process)
        raise RuntimeError("seed-child pipes were not created")
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    stdout_overflow = threading.Event()
    stderr_overflow = threading.Event()
    pipe_error_event = threading.Event()
    pipe_errors: list[tuple[str, BaseException]] = []
    pipe_error_lock = threading.Lock()

    def record_pipe_error(pipe_name: str, exc: BaseException) -> None:
        with pipe_error_lock:
            pipe_errors.append((pipe_name, exc))
            pipe_error_event.set()

    def read_bounded(stream, buffer: bytearray, maximum: int, overflow: threading.Event) -> None:
        try:
            while True:
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                remaining = maximum - len(buffer)
                if remaining > 0:
                    buffer.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    overflow.set()
        except BaseException as exc:
            record_pipe_error("output reader", exc)

    def write_payload() -> None:
        try:
            written = process.stdin.write(payload)
            if written != len(payload):
                raise RuntimeError("seed-child stdin accepted a partial payload")
            process.stdin.flush()
        except BrokenPipeError:
            pass
        except BaseException as exc:
            record_pipe_error("stdin writer", exc)
        finally:
            try:
                process.stdin.close()
            except BrokenPipeError:
                pass
            except BaseException as exc:
                record_pipe_error("stdin closer", exc)

    readers = [
        threading.Thread(
            target=read_bounded,
            args=(process.stdout, stdout_buffer, SEED_CHILD_RESULT_MAX_BYTES, stdout_overflow),
            name="e9-seed-child-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=read_bounded,
            args=(process.stderr, stderr_buffer, SEED_CHILD_STDERR_MAX_BYTES, stderr_overflow),
            name="e9-seed-child-stderr",
            daemon=True,
        ),
    ]
    writer = threading.Thread(
        target=write_payload,
        name="e9-seed-child-stdin",
        daemon=True,
    )
    deadline = time.monotonic() + timeout_seconds
    pipe_threads = [*readers, writer]
    started_threads: list[threading.Thread] = []
    timeout_expired = False
    child_reaped = False
    try:
        for pipe_thread in pipe_threads:
            pipe_thread.start()
            started_threads.append(pipe_thread)
        while process.poll() is None:
            if (
                stdout_overflow.is_set()
                or stderr_overflow.is_set()
                or pipe_error_event.is_set()
            ):
                _terminate_seed_child(process)
                child_reaped = True
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                _terminate_seed_child(process)
                child_reaped = True
                timeout_expired = True
                break
            time.sleep(min(0.01, remaining))
        if not child_reaped:
            process.wait()
    except BaseException:
        if process.poll() is None:
            _terminate_seed_child(process)
        raise
    finally:
        for pipe_thread in reversed(started_threads):
            pipe_thread.join(timeout=SEED_CHILD_TERMINATE_GRACE_SECONDS)
    alive_threads = [
        pipe_thread.name for pipe_thread in started_threads if pipe_thread.is_alive()
    ]
    if alive_threads:
        raise RuntimeError(
            "seed-child pipe thread did not terminate after process reap: "
            + ", ".join(alive_threads)
        )
    if timeout_expired:
        raise subprocess.TimeoutExpired("seed-child", timeout_seconds)
    if pipe_errors:
        pipe_name, pipe_error = pipe_errors[0]
        raise RuntimeError(f"seed-child {pipe_name} failed") from pipe_error
    if stdout_overflow.is_set():
        raise EvidenceError("seed-child stdout exceeds its byte limit")
    if stderr_overflow.is_set():
        raise EvidenceError("seed-child stderr exceeds its byte limit")
    return bytes(stdout_buffer), bytes(stderr_buffer)


def _launch_seed_child(
    request_value: object,
    *,
    timeout_seconds: float | None = None,
    sealed_archive: bytes | None = None,
) -> _SeedChildLaunch:
    request = _validate_seed_child_request(request_value)
    payload = _canonical(request)
    if len(payload) > SEED_CHILD_REQUEST_MAX_BYTES:
        raise EvidenceError("seed-child request exceeds its byte limit")
    child_executable = _actual_python_runtime_executable()
    sealed_descriptor: int | None = None
    process_long_test = request["profile_name"] == PROCESS_LONG_TEST_PROFILE_NAME
    if process_long_test:
        if type(sealed_archive) is not bytes:
            raise EvidenceError("process long-test launch requires sealed archive bytes")
        sealed_descriptor = _create_sealed_archive_memfd(
            sealed_archive, request["expected_sealed_archive"]
        )
        command = [
            str(child_executable),
            "-I",
            "-u",
            f"/proc/self/fd/{sealed_descriptor}",
        ]
    else:
        if sealed_archive is not None:
            raise EvidenceError("only the process long test accepts sealed archive bytes")
        command = [
            str(child_executable),
            "-I",
            "-u",
            str(Path(__file__).resolve()),
            "_seed-child",
        ]
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    popen_options: dict[str, object] = {
        "stdin": subprocess.PIPE,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
        "close_fds": True,
        "creationflags": creationflags,
    }
    if os.name == "nt" and child_executable != Path(sys.executable):
        child_environment = os.environ.copy()
        child_environment["__PYVENV_LAUNCHER__"] = sys.executable
        popen_options["env"] = child_environment
    if process_long_test:
        if sealed_descriptor is None:
            raise RuntimeError("process long-test sealed descriptor was not created")
        child_environment = os.environ.copy()
        child_environment["TRAPS_E9_SEALED_CHILD_MODE"] = "SEALED_MEMFD_ZIPAPP_V1"
        child_environment["TRAPS_E9_SEALED_SOURCE_ROOT"] = str(ROOT.resolve(strict=True))
        child_environment["TRAPS_E9_SEALED_ARCHIVE_FD"] = str(sealed_descriptor)
        popen_options["env"] = child_environment
        popen_options["pass_fds"] = (sealed_descriptor,)
    try:
        process = subprocess.Popen(command, **popen_options)  # type: ignore[arg-type]
    finally:
        if sealed_descriptor is not None:
            os.close(sealed_descriptor)
    timeout = (
        _seed_child_timeout_seconds(_mapping(request["profile"], "seed-child profile"))
        if timeout_seconds is None
        else float(timeout_seconds)
    )
    if not math.isfinite(timeout) or timeout <= 0.0:
        _terminate_seed_child(process)
        raise EvidenceError("seed-child timeout must be finite and positive")
    try:
        stdout, stderr = _communicate_seed_child_bounded(process, payload, timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"seed child {request['seed']} timed out without retry") from exc
    result = _decode_canonical_json(
        stdout,
        "seed-child stdout",
        SEED_CHILD_RESULT_MAX_BYTES,
    )
    if process.returncode != 0:
        _exact_keys(
            result,
            {"schema", "status", "process_id", "error_type", "message"},
            "seed-child error result",
        )
        _exact_value(result["schema"], SEED_CHILD_RESULT_SCHEMA, "seed-child error schema")
        _exact_value(result["status"], "error", "seed-child error status")
        _exact_value(result["process_id"], process.pid, "failed seed-child process ID")
        raise RuntimeError(
            f"seed child {request['seed']} failed without retry: "
            f"{result['error_type']}: {result['message']}"
        )
    if stderr:
        raise EvidenceError("successful seed child wrote unexpected stderr bytes")
    validated = _validate_seed_child_result(result, request, process.pid)
    return _SeedChildLaunch(process.pid, validated)


def _seed_child_main() -> int:
    try:
        payload = sys.stdin.buffer.read(SEED_CHILD_REQUEST_MAX_BYTES + 1)
        request = _decode_canonical_json(
            payload,
            "seed-child stdin",
            SEED_CHILD_REQUEST_MAX_BYTES,
        )
        result = _run_seed_child_request(request)
        encoded = _canonical(result)
        if len(encoded) > SEED_CHILD_RESULT_MAX_BYTES:
            raise EvidenceError("seed-child result exceeds its byte limit")
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()
        return 0
    except Exception as exc:
        message = str(exc)
        if len(message) > 1024:
            message = message[:1024]
        error = {
            "schema": SEED_CHILD_RESULT_SCHEMA,
            "status": "error",
            "process_id": os.getpid(),
            "error_type": type(exc).__name__,
            "message": message,
        }
        sys.stdout.buffer.write(_canonical(error))
        sys.stdout.buffer.flush()
        return 1


def _sign_attestation(
    raw_without_attestation: Mapping[str, object],
    profile_name: str,
    profile: Mapping[str, Any],
    signing_key_path: Path | None,
    producer_public_key_hex: str | None = None,
) -> dict[str, object]:
    signed_bytes = _canonical(raw_without_attestation)
    preregistered = profile.get("formal_contract") == PREREGISTERED_FORMAL_CONTRACT
    if profile_name == "smoke" or preregistered:
        if signing_key_path is not None:
            kind = "preregistered clean-run" if preregistered else "smoke"
            raise RuntimeError(f"{kind} evidence must not use a producer signing key")
        return {"algorithm": "NONE", "public_key_hex": None, "signature_hex": None}
    if signing_key_path is None:
        raise RuntimeError("formal E9 collection requires --signing-key")
    key = _load_private_key(signing_key_path)
    from cryptography.hazmat.primitives import serialization

    public = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )
    if public != producer_public_key_hex:
        raise RuntimeError("formal signing key does not match the auditor-frozen producer key")
    return {
        "algorithm": "Ed25519",
        "public_key_hex": public,
        "signature_hex": key.sign(signed_bytes).hex(),
    }


def _raw_limitations(
    profile_name: str,
    power_mode: object | None = None,
    *,
    formal_contract: object | None = None,
) -> list[str]:
    preregistered = formal_contract == PREREGISTERED_FORMAL_CONTRACT
    limitations = [
        "loopback TCP without TLS, proxy, or wide-area network variance",
        "controlled deterministic false-positive paths in the Python reference screen",
        (
            "each frozen seed runs serially in one fresh isolated Python operating-system "
            "process; authorization, signing, publication, registry, lock, and output objects "
            "are excluded from seed IPC and inherited handles, but the same-UID child is not "
            "an operating-system capability boundary"
        ),
        "padding overflow is a configured-capacity mechanism probe, not a TCP overflow claim",
        (
            "smoke uses a deliberately reduced PBKDF2 cost and is not E9 evidence"
            if profile_name == "smoke"
            else "preregistered formal seeds use frozen KDF-specific training and evaluation blocks"
            if preregistered
            else "formal seeds alternate PBKDF2-310k and Argon2id-19MiB verifier workloads"
        ),
        (
            "unsigned preregistered raw records self-reported operator assertions and requires "
            "independent post-run audit before formal eligibility"
            if preregistered
            else "producer signature authenticates bytes but does not prove independent execution"
            if profile_name == "formal"
            else "smoke evidence is unsigned and cannot support a gate claim"
        ),
    ]
    if profile_name == "smoke":
        if power_mode is not None:
            raise EvidenceError("smoke limitations cannot claim a formal power assertion")
        return limitations
    if preregistered:
        if power_mode is not None:
            raise EvidenceError("preregistered clean-run limitations do not accept power probes")
        limitations.extend(
            [
                "exclusive-host and quiesced-service conditions are operator assertions, not "
                "runtime service queries or external attestations",
                "the formal run records eighty distinct serial seed-child processes with frozen "
                "KDF-specific training/evaluation splits and does not depend on the non-evidence "
                "process qualification receipt",
                "CPU-frequency and thermal snapshots are parent host-level evidence; each "
                "preregistered formal seed child separately records actual authentication-worker "
                "native-thread affinity, allowed NUMA nodes, process NUMA maps, and active KDF "
                "runtime evidence",
                "native-extension compiler flags not exposed by the installed runtime or wheel "
                "are recorded as unavailable rather than inferred",
                "formal eligibility remains blocked until an independent post-run audit validates "
                "the raw evidence and numerical criterion",
            ]
        )
        return limitations
    if power_mode == "EXTERNAL_ATTESTATION":
        privacy_uri_scope = "registry, lock-marker, lock-anchor, and external-document"
        limitations.append(
            "power/governor state relies on an auditor-signed external assertion of the "
            "expected governor value, document URI, and digest; no runtime governor "
            "measurement was performed"
        )
    elif power_mode == "RUNTIME_VERIFIED":
        privacy_uri_scope = "registry, lock-marker, and lock-anchor"
        limitations.append(
            "power/governor state was checked only by signed pre- and post-collection "
            "runtime governor probes"
        )
    else:
        raise EvidenceError("formal limitations require a recognized power assertion mode")
    limitations.append(
        "the signed preprovisioned anchor OS advisory lock is the sole concurrency "
        "uniqueness primitive; the O_EXCL marker is only a durable audit and crash-reuse "
        "blocker, and no independently witnessed completion receipt is claimed"
    )
    limitations.append(
        "formal raw publication uses direct O_EXCL creation and fsync; a crash may leave "
        "a partial blocking artifact requiring auditor-supervised disposition"
    )
    limitations.append(
        f"formal raw embeds absolute {privacy_uri_scope} URIs plus service, CPU-affinity, "
        "and Python-runtime fingerprints; publication requires "
        "auditor-approved privacy handling"
    )
    return limitations


def _process_isolation_verified(
    parent_process_id: int,
    process_ids: Sequence[int],
    expected_seed_count: int,
) -> bool:
    return (
        len(process_ids) == expected_seed_count
        and len(set(process_ids)) == expected_seed_count
        and all(process_id != parent_process_id for process_id in process_ids)
    )


def _formal_execution_blockers(
    power_mode: object,
    *,
    process_isolation_verified: bool,
) -> list[str]:
    blockers: list[str] = [PROCESS_ISOLATION_BLOCKER]
    if not process_isolation_verified:
        raise EvidenceError("formal execution lacks per-seed process isolation evidence")
    if power_mode == "EXTERNAL_ATTESTATION":
        blockers.append(EXTERNAL_POWER_BLOCKER)
    elif power_mode != "RUNTIME_VERIFIED":
        raise EvidenceError("formal blockers require a recognized power assertion mode")
    blockers.append(ARTIFACT_PRIVACY_BLOCKER)
    return blockers


def collect_raw(
    config: Mapping[str, Any],
    config_id: str,
    profile_name: str,
    *,
    signing_key_path: Path | None = None,
    manifest_path: Path | None = None,
    challenge_path: Path | None = None,
    auditor_root_public_key_hex: str | None = None,
    collection_replay_registry: Path | None = None,
    raw_output_path: Path | None = None,
    overwrite: bool = False,
    exclusive_host_asserted: bool = False,
    services_quiesced_asserted: bool = False,
) -> dict[str, object]:
    config = validate_config(config)
    _exact_value(config_id, _identity(config), "E9 configuration ID")
    profile, profile_id = profile_contract(config, profile_name)
    preregistered = _is_preregistered_clean_run(config)
    if preregistered:
        _current_e9_claims_binding(config, require_power=False)
    if profile_name == "smoke":
        if exclusive_host_asserted or services_quiesced_asserted:
            raise RuntimeError("operator assertion flags are valid only for v5 formal collection")
        artifact = _collect_raw_impl(
            config,
            config_id,
            profile_name,
            profile,
            profile_id,
            _git_state(),
            None,
            None,
            None,
            None,
            None,
            signing_key_path,
            auditor_root_public_key_hex,
        )
        if raw_output_path is not None:
            _write_json(raw_output_path, artifact, overwrite)
        return artifact

    if profile["enabled"] is not True:
        raise RuntimeError(
            "formal E9 collection is disabled pending an auditor-signed contract and challenge"
        )
    if overwrite:
        raise RuntimeError("formal raw publication forbids --overwrite")
    if raw_output_path is None:
        raise RuntimeError("formal raw collection requires an exclusive raw output path")
    if preregistered:
        legacy_arguments = {
            "signing_key_path": signing_key_path,
            "manifest_path": manifest_path,
            "challenge_path": challenge_path,
            "auditor_root_public_key_hex": auditor_root_public_key_hex,
            "collection_replay_registry": collection_replay_registry,
        }
        mixed = [name for name, value in legacy_arguments.items() if value is not None]
        if mixed:
            raise RuntimeError(
                "v5 preregistered collection forbids v4 authorization arguments: "
                + ", ".join(mixed)
            )
        if type(exclusive_host_asserted) is not bool or exclusive_host_asserted is not True:
            raise RuntimeError("v5 formal collection requires --assert-exclusive-host")
        if (
            type(services_quiesced_asserted) is not bool
            or services_quiesced_asserted is not True
        ):
            raise RuntimeError("v5 formal collection requires --assert-services-quiesced")
        if platform.system() != "Linux":
            raise RuntimeError("v5 formal collection is Linux-only")
        if platform.machine() != PREREGISTERED_PRODUCTION_ARCHITECTURE:
            raise RuntimeError("v5 formal collection requires Linux x86_64")
        source_state = _validate_git_state(_git_state(), "v5 formal source state")
        if source_state["clean"] is not True or source_state["status"] != []:
            raise RuntimeError("v5 formal collection requires a clean Git HEAD")
        publication = _preflight_formal_raw_output(raw_output_path)
        try:
            if _is_within(publication.path, ROOT.resolve(strict=True)):
                raise RuntimeError("v5 formal raw output must be outside the Git worktree")
            governance_binding = _current_e9_claims_binding(
                config, require_power=True
            )
            operator_assertions = {
                "evidence_class": PREREGISTERED_ASSERTION_CLASS,
                "exclusive_host_asserted": True,
                "services_quiesced_asserted": True,
                "runner_service_state_query_performed": False,
            }
            artifact = _collect_raw_impl(
                config,
                config_id,
                profile_name,
                profile,
                profile_id,
                source_state,
                _preregistered_authorization(),
                None,
                time.time_ns(),
                None,
                None,
                None,
                None,
                preregistered_operator_assertions=operator_assertions,
                preregistered_governance_binding=governance_binding,
            )
            _write_json_exclusive(publication, artifact)
            return artifact
        finally:
            publication.close()
    if exclusive_host_asserted or services_quiesced_asserted:
        raise RuntimeError("operator assertion flags are valid only for v5 formal collection")
    publication = _preflight_formal_raw_output(raw_output_path)
    try:
        result = _require_formal_authorization(
            profile,
            config=config,
            config_id=config_id,
            profile_id=profile_id,
            manifest_path=manifest_path,
            challenge_path=challenge_path,
            auditor_root_public_key_hex=auditor_root_public_key_hex,
            collection_replay_registry=collection_replay_registry,
            signing_key_path=signing_key_path,
        )
        if collection_replay_registry is None:
            raise RuntimeError("formal E9 collection requires a collection replay registry")
        authorization = _mapping(result["authorization"], "formal authorization")
        host_contract = _mapping(result["host_contract"], "host execution contract")
        pre_attestation = _mapping(
            result["pre_attestation"], "pre-collection host attestation"
        )
        lock = _acquire_exclusive_host_lock(
            host_contract,
            _mapping(authorization["manifest"], "formal contract manifest"),
            raw_output_path=publication.path,
            collection_replay_registry=collection_replay_registry,
            retention_scope=FORMAL_LOCK_RETENTION_SCOPE,
        )
        try:
            _, signed_window_end = _signed_window_bounds_ns(
                _mapping(authorization["manifest"], "formal contract manifest"),
                _mapping(authorization["challenge"], "freshness challenge"),
            )
            pre_captured = _integer(
                pre_attestation["captured_unix_ns"],
                "pre-collection host attestation timestamp",
                1,
            )
            lock_acquired = _integer(
                lock.evidence["acquired_unix_ns"],
                "exclusive lock acquisition timestamp",
                1,
            )
            if not pre_captured <= lock_acquired <= signed_window_end:
                raise EvidenceError(
                    "formal exclusive-lock acquisition is outside its signed "
                    "nanosecond timeline"
                )
            _consume_nonce(
                collection_replay_registry,
                "collection",
                str(authorization["challenge"]["nonce_hex"]),
                str(authorization["manifest"]["audit_id"]),
            )
            artifact = _collect_raw_impl(
                config,
                config_id,
                profile_name,
                profile,
                profile_id,
                result["source_state"],
                authorization,
                host_contract,
                result["collection_started_unix_ns"],
                pre_attestation,
                lock.evidence,
                signing_key_path,
                auditor_root_public_key_hex,
            )
            _write_json_exclusive(publication, artifact)
            return artifact
        finally:
            lock.release()
    finally:
        publication.close()


def _collect_raw_impl(
    config: Mapping[str, Any],
    config_id: str,
    profile_name: str,
    profile: Mapping[str, Any],
    profile_id: str,
    before: object,
    formal_authorization: Mapping[str, Any] | None,
    host_contract: Mapping[str, Any] | None,
    collection_started_unix_ns: object | None,
    pre_attestation: Mapping[str, Any] | None,
    lock_evidence: Mapping[str, Any] | None,
    signing_key_path: Path | None,
    auditor_root_public_key_hex: str | None,
    preregistered_operator_assertions: Mapping[str, Any] | None = None,
    preregistered_governance_binding: Mapping[str, Any] | None = None,
) -> dict[str, object]:
    preregistered_formal = (
        _is_preregistered_clean_run(config) and profile_name == "formal"
    )
    samples: list[dict[str, object]] = []
    runtimes: list[dict[str, object]] = []
    ports_by_seed: dict[str, int] = {}
    instances_by_seed: dict[str, str] = {}
    process_ids_by_seed: dict[str, int] = {}
    child_processes_by_seed: dict[str, dict[str, object]] = {}
    real_stress_results: list[dict[str, object]] = []
    parent_process_id = os.getpid()
    if pre_attestation is None:
        expected_python_runtime = _probe_python_runtime_identity()
        expected_cpu_affinity = _probe_cpu_affinity()
    else:
        expected_python_runtime = dict(
            _mapping(pre_attestation["python_runtime"], "pre-collection Python runtime")
        )
        expected_cpu_affinity = list(pre_attestation["allowed_cpu_affinity"])
    pre_measurement_environment = (
        _probe_preregistered_measurement_environment("PRE_MEASUREMENT")
        if preregistered_formal
        else None
    )
    for seed_index, seed_value in enumerate(profile["seeds"]):
        seed = int(seed_value)
        request = _build_seed_child_request(
            profile_name,
            profile_id,
            profile,
            seed,
            seed_index,
            expected_python_runtime,
            expected_cpu_affinity,
        )
        launch = _launch_seed_child(request)
        result = _validate_seed_child_result(launch.result, request, launch.process_id)
        process_id = int(result["process_id"])
        if process_id in process_ids_by_seed.values():
            raise EvidenceError("operating system reused a seed-child PID; run fails without retry")
        seed_key = str(seed)
        process_ids_by_seed[seed_key] = process_id
        child_processes_by_seed[seed_key] = {
            "popen_pid": launch.process_id,
            "reported_pid": process_id,
            "python_runtime": result["python_runtime"],
            "cpu_affinity": result["cpu_affinity"],
            **(
                {"measurement_environment": result["measurement_environment"]}
                if preregistered_formal
                else {}
            ),
        }
        ports_by_seed[seed_key] = int(result["listen_port"])
        instance_id = str(result["sut_instance_id"])
        if instance_id in instances_by_seed.values():
            raise EvidenceError("seed child reused a SUT instance ID; run fails without retry")
        instances_by_seed[seed_key] = instance_id
        real_stress_results.append({"seed": seed, **dict(result["stress_result"])})
        samples.extend(result["samples"])
        runtimes.append(dict(result["runtime"]))
    post_measurement_environment = (
        _probe_preregistered_measurement_environment("POST_MEASUREMENT")
        if preregistered_formal
        else None
    )
    isolation_verified = _process_isolation_verified(
        parent_process_id,
        list(process_ids_by_seed.values()),
        len(profile["seeds"]),
    )
    if not isolation_verified:
        raise EvidenceError("fresh operating-system process isolation per seed was not verified")
    runtime = {
        "handler_threads_created": sum(int(item["handler_threads_created"]) for item in runtimes),
        "handler_threads_alive_after_shutdown": sum(
            int(item["handler_threads_alive_after_shutdown"]) for item in runtimes
        ),
        "padding": {
            key: (
                max(int(item["padding"][key]) for item in runtimes)
                if key in {"peak_pending", "max_pending"}
                else sum(int(item["padding"][key]) for item in runtimes)
            )
            for key in (
                "scheduled_async",
                "immediate_after_slow_auth",
                "peak_pending",
                "pending",
                "overflow_failures",
                "max_pending",
            )
        },
        "server_errors": [error for item in runtimes for error in item["server_errors"]],
        "parent_process_id": parent_process_id,
        "parent_python_runtime": expected_python_runtime,
        "parent_cpu_affinity": expected_cpu_affinity,
        "sut_instances_by_seed": instances_by_seed,
        "sut_process_ids_by_seed": process_ids_by_seed,
        "seed_child_processes_by_seed": child_processes_by_seed,
        "stress_audit": _run_stress_audit(profile, real_stress_results),
    }
    after = _git_state()
    formal_execution: dict[str, object] | None = None
    collection_completed_unix_ns: int | None = None
    if preregistered_formal:
        before_state = _validate_git_state(before, "v5 formal source_before")
        after_state = _validate_git_state(after, "v5 formal source_after")
        if before_state["clean"] is not True or before_state["status"] != []:
            raise EvidenceError("v5 formal collection did not start from a clean Git HEAD")
        _exact_value(after_state, before_state, "v5 formal source stability")
        collection_completed_unix_ns = time.time_ns()
    if host_contract is not None:
        if (
            collection_started_unix_ns is None
            or pre_attestation is None
            or lock_evidence is None
        ):
            raise RuntimeError("formal collection lacks its preflight execution evidence")
        post_attestation = _capture_host_attestation(host_contract, "POST_COLLECTION")
        collection_completed_unix_ns = time.time_ns()
        power_mode = _mapping(
            host_contract["power_governor_assertion"], "power/governor assertion"
        )["mode"]
        formal_execution = {
            "schema": FORMAL_EXECUTION_SCHEMA,
            "host_contract_id": _identity(host_contract),
            "collection_started_unix_ns": collection_started_unix_ns,
            "pre_attestation": dict(pre_attestation),
            "post_attestation": post_attestation,
            "collection_completed_unix_ns": collection_completed_unix_ns,
            "exclusive_lock": dict(lock_evidence),
            "seed_process_isolation": dict(PROCESS_ISOLATION_DECLARATION),
            "formal_readiness_blockers": _formal_execution_blockers(
                power_mode,
                process_isolation_verified=isolation_verified,
            ),
            "formal_readiness": "BLOCKED_BY_UNRESOLVED_EXECUTION_OR_PUBLICATION_GATES",
        }
        runtime_identity = _mapping(
            pre_attestation["python_runtime"], "pre-collection Python runtime"
        )
        host = {
            "node": pre_attestation["host_id"],
            "machine": pre_attestation["architecture"],
            "platform": pre_attestation["system"],
            "python": (
                f"{runtime_identity['implementation']} {runtime_identity['version']}"
            ),
            "logical_cpu_count": pre_attestation["logical_cpu_count"],
        }
    else:
        host = {
            "node": platform.node(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "logical_cpu_count": os.cpu_count(),
        }
    if preregistered_formal:
        if collection_started_unix_ns is None or collection_completed_unix_ns is None:
            raise RuntimeError("v5 formal collection lacks its start/end timestamps")
        assertions = _mapping(
            preregistered_operator_assertions,
            "v5 formal operator assertions",
        )
        expected_assertions = {
            "evidence_class": PREREGISTERED_ASSERTION_CLASS,
            "exclusive_host_asserted": True,
            "services_quiesced_asserted": True,
            "runner_service_state_query_performed": False,
        }
        _exact_value(assertions, expected_assertions, "v5 formal operator assertions")
        governance = _mapping(
            preregistered_governance_binding,
            "v5 formal governance binding",
        )
        _exact_value(
            governance,
            _current_e9_claims_binding(config, require_power=True),
            "v5 formal current governance binding",
        )
        formal_execution = {
            "schema": PREREGISTERED_FORMAL_EXECUTION_SCHEMA,
            "formal_contract": PREREGISTERED_FORMAL_CONTRACT,
            "collection_started_unix_ns": collection_started_unix_ns,
            "collection_completed_unix_ns": collection_completed_unix_ns,
            "source_commit": before_state["commit"],
            "python_runtime": expected_python_runtime,
            "cpu_affinity": expected_cpu_affinity,
            "host_system": platform.system(),
            "host": dict(host),
            "pre_measurement_environment": pre_measurement_environment,
            "post_measurement_environment": post_measurement_environment,
            "operator_assertions": dict(assertions),
            "governance_binding": dict(governance),
            "seed_process_isolation": {
                "mode": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_REUSE",
                "fresh_os_process_per_seed": True,
                "serial_execution": True,
                "retry_count": 0,
                "seed_count": len(profile["seeds"]),
                "unique_child_process_ids": len(set(process_ids_by_seed.values())),
                "unique_sut_instance_ids": len(set(instances_by_seed.values())),
                "evidence_role": (
                    "FORMAL_RUN_INTERNAL_EXECUTION_EVIDENCE_REPLACES_QUALIFICATION_RECEIPT"
                ),
            },
            "formal_readiness_blockers": [PREREGISTERED_FORMAL_BLOCKER],
            "formal_readiness": "BLOCKED_PENDING_INDEPENDENT_POST_RUN_AUDIT",
        }
    body: dict[str, object] = {
        "schema": RAW_SCHEMA,
        "experiment_id": config["experiment_id"],
        "config_id": config_id,
        "profile": profile_name,
        "profile_id": profile_id,
        "evidence_class": profile["evidence_class"],
        "source_before": before,
        "source_after": after,
        "host": host,
        "resource_clocks": {
            "external_wall": _clock_metadata("perf_counter"),
            "worker_cpu": _clock_metadata("thread_time"),
        },
        "service_parameters": {
            "screen": "Python exact positive representation with controlled false-positive paths",
            "backend_kdf": "REAL_CONFIGURED_VERIFIER_PATH",
            "pbkdf2_iterations": profile["pbkdf2_iterations"],
            "pbkdf2_dklen": profile["pbkdf2_dklen"],
            "kdf_workloads": profile["kdf_workloads"],
            "seed_workload_schedule": _seed_workload_schedule(profile),
            "auth_workers": profile["auth_workers"],
            "failure_padding_ms": profile["failure_padding_ms"],
            "max_pending_padding": profile["max_pending_padding"],
            "negative_cache_prewarm": "one typed backend mismatch before network warmup",
            "backend_cpu_field_scope": "configured real KDF call only",
            "auth_worker_cpu_field_scope": "complete AuthDataPlane.authenticate task",
            **(
                {
                    "path_contracts": config["failure_case_contracts"]
                }
                if _is_preregistered_clean_run(config)
                else {}
            ),
        },
        "transport": {
            "listen_host": "127.0.0.1",
            "listen_ports_by_seed": ports_by_seed,
            "family": "AF_INET",
            "type": "SOCK_STREAM",
            "protocol": "IPPROTO_TCP",
            "tls": False,
            "scope": "SINGLE_HOST_LOOPBACK_EXTERNAL_SOCKET_BOUNDARY",
        },
        "producer_contract": {
            "label_source": "FROZEN_SEED_CASE_ORDINAL_SCHEDULE",
            "request_shape": "FIXED_110_BYTE_BINARY_REQUEST",
            "failure_response": "IDENTICAL_THREE_FRAME_401_THEN_EOF",
            "padding": "BOUNDED_THREADING_TIMER_AFTER_AUTH_WORKER_RELEASE",
            "classifier_population": "FAILURE_CASES_ONLY",
            "functional_success_excluded_from_auc": True,
            "seed_isolation": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_REUSE",
            **(
                {
                    "classifier": "FROZEN_EXTERNAL_MULTIVARIATE_RIDGE_LOGISTIC",
                    "classifier_fit_scope": "TRAINING_SEEDS_ONLY_PER_KDF_AND_FAILURE_PAIR",
                    "classifier_evaluation_scope": "THIRTY_DISJOINT_EVALUATION_SEEDS_PER_KDF",
                    "sampling_schedule": config["sampling_schedule"],
                    "path_contracts": config["failure_case_contracts"],
                    "diagnostics_contract": config["diagnostics_contract"],
                }
                if preregistered_formal
                else {}
            ),
        },
        "warmup_requests": len(profile["seeds"])
        * len(ALL_CASES)
        * int(profile["warmup_per_case_per_seed"]),
        "stress_requests": len(profile["seeds"]) * (int(profile["auth_workers"]) + 1),
        "samples": samples,
        "sample_chain_sha256": _chain(samples),
        "runtime": runtime,
        "formal_authorization": formal_authorization,
        "collected_unix": (
            int(time.time())
            if collection_completed_unix_ns is None
            else collection_completed_unix_ns // 1_000_000_000
        ),
        "limitations": _raw_limitations(
            profile_name,
            None
            if host_contract is None
            else _mapping(
                host_contract["power_governor_assertion"], "power/governor assertion"
            )["mode"],
            formal_contract=profile.get("formal_contract"),
        ),
        "status": "FORMAL_RAW_CAPTURE_COMPLETE_WITH_UNRESOLVED_BLOCKERS"
        if profile_name == "formal"
        else "SMOKE_NON_EVIDENCE_COMPLETE",
        "g7_status": "NOT_CLAIMED_E9_RAW_ONLY",
    }
    if formal_execution is not None:
        body["formal_execution"] = formal_execution
    raw_id = _identity(body)
    unsigned = {**body, "raw_id": raw_id}
    producer_key = None
    if formal_authorization is not None and not preregistered_formal:
        producer_key = str(formal_authorization["manifest"]["producer_public_key_hex"])
    attestation = _sign_attestation(unsigned, profile_name, profile, signing_key_path, producer_key)
    artifact = {**unsigned, "attestation": attestation}
    validate_raw(
        artifact,
        config,
        config_id,
        profile_name,
        auditor_root_public_key_hex=auditor_root_public_key_hex,
        register_replay=False,
    )
    return artifact


def _validate_git_state(value: object, label: str) -> dict[str, Any]:
    state = _mapping(value, label)
    _exact_keys(state, {"commit", "clean", "status"}, label)
    if not _full_commit(state["commit"]):
        raise EvidenceError(f"{label}.commit must be a full lowercase commit")
    if type(state["clean"]) is not bool or type(state["status"]) is not list:
        raise EvidenceError(f"{label} clean/status types are invalid")
    if any(type(line) is not str for line in state["status"]):
        raise EvidenceError(f"{label}.status entries must be strings")
    return state


def _positive_int(value: object, label: str, allow_zero: bool = False) -> int:
    return _integer(value, label, 0 if allow_zero else 1)


def _process_long_test_counts(profile: Mapping[str, Any]) -> dict[str, int]:
    seed_count = len(profile["seeds"])
    case_count = len(ALL_CASES)
    measured_per_seed = case_count * int(profile["samples_per_case_per_seed"])
    warmup_per_seed = case_count * int(profile["warmup_per_case_per_seed"])
    stress_per_seed = int(profile["auth_workers"]) + 1
    loopback_per_seed = measured_per_seed + warmup_per_seed + stress_per_seed
    return {
        "seed_count": seed_count,
        "case_count": case_count,
        "measured_requests_per_seed": measured_per_seed,
        "warmup_requests_per_seed": warmup_per_seed,
        "stress_requests_per_seed": stress_per_seed,
        "loopback_requests_per_seed": loopback_per_seed,
        "measured_requests": seed_count * measured_per_seed,
        "warmup_requests": seed_count * warmup_per_seed,
        "stress_requests": seed_count * stress_per_seed,
        "loopback_requests": seed_count * loopback_per_seed,
    }


def _reject_process_long_test_evidence_fields(value: object) -> None:
    forbidden = {
        "samples",
        "timing",
        "analysis",
        "formal_authorization",
        "signature",
        "signature_hex",
        "attestation",
        "raw",
        "raw_id",
        "sample_chain_sha256",
    }
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise EvidenceError("process long-test receipt has a non-string key")
            if key in forbidden:
                raise EvidenceError(
                    f"process long-test receipt contains prohibited evidence field {key!r}"
                )
            _reject_process_long_test_evidence_fields(item)
    elif type(value) is list:
        for item in value:
            _reject_process_long_test_evidence_fields(item)


def _process_long_test_workload_counts(profile: Mapping[str, Any]) -> list[dict[str, object]]:
    workloads = list(profile["kdf_workloads"])
    counts = [0 for _ in workloads]
    for index, _seed in enumerate(profile["seeds"]):
        counts[index % len(workloads)] += 1
    return [
        {"workload": dict(_mapping(workload, "process long-test workload")), "seed_count": count}
        for workload, count in zip(workloads, counts, strict=True)
    ]


def validate_process_long_test_receipt(
    receipt_value: object,
    config: Mapping[str, Any],
    config_id: str,
) -> dict[str, Any]:
    _exact_value(
        config,
        _expected_process_long_test_config(),
        "E9 process long-test configuration",
    )
    _exact_value(config_id, _identity(config), "process long-test configuration ID")
    profile, profile_id = process_long_test_profile_contract(config)
    receipt = _mapping(receipt_value, "E9 process long-test receipt")
    _reject_process_long_test_evidence_fields(receipt)
    body_keys = {
        "schema",
        "status",
        "experiment_id",
        "qualification_id",
        "profile_name",
        "evidence_class",
        "formal_evidence_eligible",
        "formal_claim_eligible",
        "formal_blocker_effect",
        "review_status",
        "authentication",
        "config_id",
        "profile_id",
        "source_before",
        "source_after",
        "source_snapshot",
        "sealed_source_archive",
        "host",
        "parent_process_id",
        "profile_parameters",
        "counts",
        "process_isolation",
        "workload_seed_counts",
        "children",
        "limitations",
    }
    _exact_keys(receipt, body_keys | {"receipt_id"}, "E9 process long-test receipt")
    expected_header = {
        "schema": PROCESS_LONG_TEST_RECEIPT_SCHEMA,
        "status": "NON_EVIDENCE_PROCESS_ISOLATION_QUALIFICATION_COMPLETE",
        "experiment_id": config["experiment_id"],
        "qualification_id": PROCESS_LONG_TEST_QUALIFICATION_ID,
        "profile_name": PROCESS_LONG_TEST_PROFILE_NAME,
        "evidence_class": PROCESS_LONG_TEST_EVIDENCE_CLASS,
        "formal_evidence_eligible": False,
        "formal_claim_eligible": False,
        "formal_blocker_effect": PROCESS_LONG_TEST_BLOCKER_EFFECT,
        "review_status": PROCESS_LONG_TEST_REVIEW_STATUS,
        "authentication": PROCESS_LONG_TEST_AUTHENTICATION,
        "config_id": config_id,
        "profile_id": profile_id,
    }
    for key, expected in expected_header.items():
        _exact_value(receipt[key], expected, f"process long-test receipt {key}")
    before = _validate_git_state(receipt["source_before"], "process long-test source_before")
    after = _validate_git_state(receipt["source_after"], "process long-test source_after")
    if before["clean"] is not True or before["status"] != []:
        raise EvidenceError("process long test requires a clean source tree before launch")
    _exact_value(after, before, "process long-test source stability")
    source_snapshot = _validate_tracked_source_snapshot(
        receipt["source_snapshot"], "process long-test tracked source snapshot"
    )
    _exact_value(
        source_snapshot["commit"], before["commit"], "process long-test source commit binding"
    )
    sealed_archive = _validate_sealed_archive_identity(
        receipt["sealed_source_archive"], "process long-test sealed source archive"
    )
    _exact_value(
        sealed_archive["commit"],
        source_snapshot["commit"],
        "process long-test sealed source commit binding",
    )
    _exact_value(
        sealed_archive["git_tree"],
        source_snapshot["git_tree"],
        "process long-test sealed source Git tree binding",
    )

    host = _mapping(receipt["host"], "process long-test host")
    _exact_keys(host, {"system", "architecture", "python_runtime", "cpu_affinity"}, "host")
    _exact_value(host["system"], "Linux", "process long-test host system")
    if type(host["architecture"]) is not str or not host["architecture"]:
        raise EvidenceError("process long-test host architecture must be nonempty")
    python_runtime = _validate_python_runtime_identity(
        host["python_runtime"], "process long-test Python runtime"
    )
    affinity_value = host["cpu_affinity"]
    if type(affinity_value) is not list or not affinity_value:
        raise EvidenceError("process long-test CPU affinity must be a nonempty array")
    affinity = [_integer(cpu, "process long-test CPU", 0) for cpu in affinity_value]
    if affinity != sorted(set(affinity)):
        raise EvidenceError("process long-test CPU affinity must be sorted and unique")
    parent_process_id = _integer(
        receipt["parent_process_id"], "process long-test parent process ID", 1
    )
    _exact_value(
        receipt["profile_parameters"],
        config["profile"],
        "process long-test profile parameters",
    )
    expected_counts = _process_long_test_counts(profile)
    _exact_value(receipt["counts"], expected_counts, "process long-test counts")
    _exact_value(
        receipt["workload_seed_counts"],
        _process_long_test_workload_counts(profile),
        "process long-test workload seed counts",
    )

    children = receipt["children"]
    if type(children) is not list or len(children) != len(PROCESS_LONG_TEST_SEEDS):
        raise EvidenceError("process long-test receipt must contain exactly twenty children")
    child_keys = {
        "seed",
        "seed_index",
        "workload",
        "parent_process_id",
        "popen_pid",
        "reported_pid",
        "sample_sut_process_id",
        "python_runtime_id",
        "source_snapshot_id",
        "sealed_archive_sha256",
        "cpu_affinity",
        "listen_host",
        "listen_port",
        "sut_instance_id",
        "measured_requests",
        "warmup_requests",
        "stress_requests",
        "loopback_requests",
        "handler_threads_created",
        "handler_threads_alive_after_shutdown",
        "padding",
        "server_errors_count",
        "retry_count",
        "timeout_count",
    }
    process_ids: list[int] = []
    instance_ids: list[str] = []
    measured_total = 0
    warmup_total = 0
    stress_total = 0
    loopback_total = 0
    for seed_index, (seed, child_value) in enumerate(
        zip(PROCESS_LONG_TEST_SEEDS, children, strict=True)
    ):
        child = _mapping(child_value, f"process long-test child {seed}")
        _exact_keys(child, child_keys, f"process long-test child {seed}")
        _exact_value(child["seed"], seed, f"process long-test child {seed} seed")
        _exact_value(
            child["seed_index"], seed_index, f"process long-test child {seed} index"
        )
        expected_workload = profile["kdf_workloads"][
            seed_index % len(profile["kdf_workloads"])
        ]
        _exact_value(
            child["workload"],
            expected_workload,
            f"process long-test child {seed} workload",
        )
        _exact_value(
            child["parent_process_id"],
            parent_process_id,
            f"process long-test child {seed} parent process ID",
        )
        popen_pid = _integer(child["popen_pid"], f"child {seed} Popen PID", 1)
        reported_pid = _integer(child["reported_pid"], f"child {seed} reported PID", 1)
        sample_pid = _integer(
            child["sample_sut_process_id"], f"child {seed} sample SUT PID", 1
        )
        if popen_pid != reported_pid or reported_pid != sample_pid:
            raise EvidenceError(f"process long-test child {seed} PID binding differs")
        if reported_pid == parent_process_id:
            raise EvidenceError(f"process long-test child {seed} reused its parent PID")
        process_ids.append(reported_pid)
        _exact_value(
            child["python_runtime_id"],
            _identity(python_runtime),
            f"process long-test child {seed} Python runtime ID",
        )
        _exact_value(
            child["source_snapshot_id"],
            _identity(source_snapshot),
            f"process long-test child {seed} source snapshot ID",
        )
        _exact_value(
            child["sealed_archive_sha256"],
            sealed_archive["sha256"],
            f"process long-test child {seed} sealed archive digest",
        )
        _exact_value(
            child["cpu_affinity"], affinity, f"process long-test child {seed} affinity"
        )
        _exact_value(child["listen_host"], "127.0.0.1", f"child {seed} listen host")
        listen_port = _integer(child["listen_port"], f"child {seed} listen port", 1)
        if listen_port > 65535:
            raise EvidenceError(f"process long-test child {seed} listen port is invalid")
        instance_id = child["sut_instance_id"]
        if (
            type(instance_id) is not str
            or len(instance_id) != 32
            or any(character not in "0123456789abcdef" for character in instance_id)
        ):
            raise EvidenceError(f"process long-test child {seed} instance ID is invalid")
        instance_ids.append(instance_id)

        per_seed_counts = {
            "measured_requests": expected_counts["measured_requests_per_seed"],
            "warmup_requests": expected_counts["warmup_requests_per_seed"],
            "stress_requests": expected_counts["stress_requests_per_seed"],
            "loopback_requests": expected_counts["loopback_requests_per_seed"],
        }
        for key, expected in per_seed_counts.items():
            _exact_value(child[key], expected, f"process long-test child {seed} {key}")
        measured_total += int(child["measured_requests"])
        warmup_total += int(child["warmup_requests"])
        stress_total += int(child["stress_requests"])
        loopback_total += int(child["loopback_requests"])
        _exact_value(
            child["handler_threads_created"],
            expected_counts["loopback_requests_per_seed"],
            f"process long-test child {seed} handler count",
        )
        _exact_value(
            child["handler_threads_alive_after_shutdown"],
            0,
            f"process long-test child {seed} live handlers",
        )
        padding = _mapping(child["padding"], f"process long-test child {seed} padding")
        _exact_keys(
            padding,
            {
                "scheduled_async",
                "immediate_after_slow_auth",
                "peak_pending",
                "pending",
                "overflow_failures",
                "max_pending",
            },
            f"process long-test child {seed} padding",
        )
        for key in padding:
            _integer(padding[key], f"process long-test child {seed} padding {key}")
        _exact_value(padding["pending"], 0, f"process long-test child {seed} pending")
        _exact_value(
            padding["overflow_failures"], 0, f"process long-test child {seed} overflow"
        )
        _exact_value(
            padding["max_pending"], profile["max_pending_padding"], f"child {seed} padding cap"
        )
        if int(padding["peak_pending"]) > int(padding["max_pending"]):
            raise EvidenceError(f"process long-test child {seed} exceeded its padding cap")
        if (
            int(padding["scheduled_async"])
            + int(padding["immediate_after_slow_auth"])
            != expected_counts["loopback_requests_per_seed"]
        ):
            raise EvidenceError(f"process long-test child {seed} padding count differs")
        for key in ("server_errors_count", "retry_count", "timeout_count"):
            _exact_value(child[key], 0, f"process long-test child {seed} {key}")
    if not _process_isolation_verified(
        parent_process_id, process_ids, len(PROCESS_LONG_TEST_SEEDS)
    ):
        raise EvidenceError("process long-test child process IDs are not globally unique")
    if len(set(instance_ids)) != len(PROCESS_LONG_TEST_SEEDS):
        raise EvidenceError("process long-test SUT instance IDs are not globally unique")
    aggregate = {
        "measured_requests": measured_total,
        "warmup_requests": warmup_total,
        "stress_requests": stress_total,
        "loopback_requests": loopback_total,
    }
    for key, actual in aggregate.items():
        _exact_value(actual, expected_counts[key], f"process long-test aggregate {key}")

    expected_isolation = {
        "mode": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_REUSE",
        "serial_execution": True,
        "launch_attempts": len(PROCESS_LONG_TEST_SEEDS),
        "successful_children": len(PROCESS_LONG_TEST_SEEDS),
        "unique_child_process_ids": len(PROCESS_LONG_TEST_SEEDS),
        "unique_sut_instance_ids": len(PROCESS_LONG_TEST_SEEDS),
        "retry_count": 0,
        "timeout_count": 0,
    }
    _exact_value(
        receipt["process_isolation"], expected_isolation, "process long-test isolation"
    )
    _exact_value(
        receipt["limitations"], list(PROCESS_LONG_TEST_LIMITATIONS), "long-test limitations"
    )
    body = {key: receipt[key] for key in body_keys}
    _exact_value(receipt["receipt_id"], _identity(body), "process long-test receipt ID")
    return receipt


def run_linux_process_long_test(
    config: Mapping[str, Any],
    config_id: str,
) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise RuntimeError("the E9 process long test is Linux-only")
    _exact_value(config_id, _identity(config), "process long-test configuration ID")
    profile, profile_id = process_long_test_profile_contract(config)
    source_before = _validate_git_state(_git_state(), "process long-test source_before")
    if source_before["clean"] is not True or source_before["status"] != []:
        raise RuntimeError("the E9 process long test requires an exact clean source commit")
    source_snapshot = _tracked_source_snapshot()
    _exact_value(
        source_snapshot["commit"],
        source_before["commit"],
        "process long-test source snapshot commit",
    )
    _exact_value(
        _validate_git_state(_git_state(), "process long-test source freeze state"),
        source_before,
        "process long-test source freeze stability",
    )
    sealed_archive, sealed_archive_identity = _build_sealed_child_archive(source_snapshot)
    _exact_value(
        _tracked_source_snapshot(),
        source_snapshot,
        "process long-test source after sealed archive construction",
    )
    python_runtime = _probe_python_runtime_identity()
    cpu_affinity = _probe_cpu_affinity()
    if not cpu_affinity:
        raise EvidenceError("process long-test CPU affinity is empty")
    architecture = platform.machine()
    if not architecture:
        raise EvidenceError("process long-test architecture is unavailable")
    parent_process_id = os.getpid()
    children: list[dict[str, object]] = []
    process_ids: set[int] = set()
    instance_ids: set[str] = set()
    counts = _process_long_test_counts(profile)
    workloads = list(profile["kdf_workloads"])
    for seed_index, seed_value in enumerate(profile["seeds"]):
        seed = int(seed_value)
        _exact_value(
            _tracked_source_snapshot(),
            source_snapshot,
            f"process long-test parent source before seed {seed}",
        )
        request = _build_seed_child_request(
            PROCESS_LONG_TEST_PROFILE_NAME,
            profile_id,
            profile,
            seed,
            seed_index,
            python_runtime,
            cpu_affinity,
            source_snapshot,
            sealed_archive_identity,
        )
        launch = _launch_seed_child(request, sealed_archive=sealed_archive)
        result = _validate_seed_child_result(launch.result, request, launch.process_id)
        _exact_value(
            _tracked_source_snapshot(),
            source_snapshot,
            f"process long-test parent source after seed {seed}",
        )
        process_id = int(result["process_id"])
        if process_id in process_ids:
            raise EvidenceError("operating system reused a long-test child PID; no retry allowed")
        process_ids.add(process_id)
        instance_id = str(result["sut_instance_id"])
        if instance_id in instance_ids:
            raise EvidenceError("long-test child reused a SUT instance ID; no retry allowed")
        instance_ids.add(instance_id)
        samples = result["samples"]
        if type(samples) is not list:
            raise EvidenceError("long-test child samples are unavailable for structural reduction")
        sample_process_ids = {
            int(_mapping(sample, "long-test child sample")["server_resource"]["sut_process_id"])
            for sample in samples
        }
        sample_instance_ids = {
            str(_mapping(sample, "long-test child sample")["server_resource"]["sut_instance_id"])
            for sample in samples
        }
        if sample_process_ids != {process_id} or sample_instance_ids != {instance_id}:
            raise EvidenceError("long-test child sample ownership binding differs")
        runtime = _mapping(result["runtime"], "long-test child runtime")
        padding = _mapping(runtime["padding"], "long-test child padding")
        children.append(
            {
                "seed": seed,
                "seed_index": seed_index,
                "workload": dict(
                    _mapping(
                        workloads[seed_index % len(workloads)],
                        "long-test selected workload",
                    )
                ),
                "parent_process_id": result["actual_parent_process_id"],
                "popen_pid": launch.process_id,
                "reported_pid": process_id,
                "sample_sut_process_id": next(iter(sample_process_ids)),
                "python_runtime_id": _identity(result["python_runtime"]),
                "source_snapshot_id": _identity(result["source_after"]),
                "sealed_archive_sha256": result["sealed_archive"]["sha256"],
                "cpu_affinity": list(result["cpu_affinity"]),
                "listen_host": result["listen_host"],
                "listen_port": result["listen_port"],
                "sut_instance_id": instance_id,
                "measured_requests": len(samples),
                "warmup_requests": counts["warmup_requests_per_seed"],
                "stress_requests": counts["stress_requests_per_seed"],
                "loopback_requests": runtime["handler_threads_created"],
                "handler_threads_created": runtime["handler_threads_created"],
                "handler_threads_alive_after_shutdown": runtime[
                    "handler_threads_alive_after_shutdown"
                ],
                "padding": dict(padding),
                "server_errors_count": len(runtime["server_errors"]),
                "retry_count": 0,
                "timeout_count": 0,
            }
        )
    if not _process_isolation_verified(
        parent_process_id, sorted(process_ids), len(PROCESS_LONG_TEST_SEEDS)
    ):
        raise EvidenceError("fresh operating-system process isolation was not verified")
    source_after = _validate_git_state(_git_state(), "process long-test source_after")
    _exact_value(source_after, source_before, "process long-test source stability")
    _exact_value(
        _tracked_source_snapshot(),
        source_snapshot,
        "process long-test final tracked source snapshot",
    )
    body: dict[str, object] = {
        "schema": PROCESS_LONG_TEST_RECEIPT_SCHEMA,
        "status": "NON_EVIDENCE_PROCESS_ISOLATION_QUALIFICATION_COMPLETE",
        "experiment_id": config["experiment_id"],
        "qualification_id": PROCESS_LONG_TEST_QUALIFICATION_ID,
        "profile_name": PROCESS_LONG_TEST_PROFILE_NAME,
        "evidence_class": PROCESS_LONG_TEST_EVIDENCE_CLASS,
        "formal_evidence_eligible": False,
        "formal_claim_eligible": False,
        "formal_blocker_effect": PROCESS_LONG_TEST_BLOCKER_EFFECT,
        "review_status": PROCESS_LONG_TEST_REVIEW_STATUS,
        "authentication": PROCESS_LONG_TEST_AUTHENTICATION,
        "config_id": config_id,
        "profile_id": profile_id,
        "source_before": source_before,
        "source_after": source_after,
        "source_snapshot": source_snapshot,
        "sealed_source_archive": sealed_archive_identity,
        "host": {
            "system": "Linux",
            "architecture": architecture,
            "python_runtime": python_runtime,
            "cpu_affinity": cpu_affinity,
        },
        "parent_process_id": parent_process_id,
        "profile_parameters": dict(config["profile"]),
        "counts": counts,
        "process_isolation": {
            "mode": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_REUSE",
            "serial_execution": True,
            "launch_attempts": len(children),
            "successful_children": len(children),
            "unique_child_process_ids": len(process_ids),
            "unique_sut_instance_ids": len(instance_ids),
            "retry_count": 0,
            "timeout_count": 0,
        },
        "workload_seed_counts": _process_long_test_workload_counts(profile),
        "children": children,
        "limitations": list(PROCESS_LONG_TEST_LIMITATIONS),
    }
    receipt = {**body, "receipt_id": _identity(body)}
    return validate_process_long_test_receipt(receipt, config, config_id)


def _validate_sample(
    sample: object,
    profile_name: str,
    profile_id: str,
    profile: Mapping[str, Any],
    expected: Coordinate,
) -> dict[str, Any]:
    value = _mapping(sample, "E9 sample")
    body_keys = {
        "schema",
        "profile",
        "profile_id",
        "seed",
        "case",
        "case_kind",
        "case_code",
        "case_ordinal",
        "schedule_index",
        "request",
        "response",
        "connection",
        "timing",
        "decoded_body",
        "server_resource",
    }
    _exact_keys(value, body_keys | {"sample_id"}, "E9 sample")
    expected_coordinate = {
        "schema": SAMPLE_SCHEMA,
        "profile": profile_name,
        "profile_id": profile_id,
        "seed": expected.seed,
        "case": expected.case,
        "case_kind": "FAILURE" if expected.case in FAILURE_CASES else "FUNCTIONAL_SUCCESS",
        "case_code": CASE_CODES[expected.case],
        "case_ordinal": expected.ordinal,
        "schedule_index": expected.schedule_index,
    }
    for key, item in expected_coordinate.items():
        _exact_value(value[key], item, f"E9 sample.{key}")
    body = {key: value[key] for key in body_keys}
    if value["sample_id"] != _identity(body):
        raise EvidenceError("E9 sample identity mismatch")

    expected_request = build_request(expected)
    request = _mapping(value["request"], "sample.request")
    _exact_keys(request, {"bytes", "sha256"}, "sample.request")
    _exact_value(request["bytes"], len(expected_request), "sample.request.bytes")
    _exact_value(
        request["sha256"], hashlib.sha256(expected_request).hexdigest(), "sample.request.sha256"
    )

    failure = expected.case in FAILURE_CASES
    expected_response = FAILURE_RESPONSE if failure else VALID_RESPONSE
    expected_status = FAILURE_STATUS if failure else VALID_STATUS
    expected_body = FAILURE_BODY if failure else VALID_BODY
    response = _mapping(value["response"], "sample.response")
    _exact_keys(
        response,
        {
            "status",
            "bytes",
            "sha256",
            "frame_order",
            "frame_count",
            "receive_call_sizes",
            "client_observed_eof",
        },
        "sample.response",
    )
    expected_response_fields = {
        "status": expected_status,
        "bytes": len(expected_response),
        "sha256": hashlib.sha256(expected_response).hexdigest(),
        "frame_order": ["status", "body", "end"],
        "frame_count": 3,
        "client_observed_eof": True,
    }
    for key, item in expected_response_fields.items():
        _exact_value(response[key], item, f"sample.response.{key}")
    recv_sizes = response["receive_call_sizes"]
    if type(recv_sizes) is not list or not recv_sizes:
        raise EvidenceError("response receive call sizes must be a nonempty array")
    if sum(_positive_int(item, "receive call size") for item in recv_sizes) != len(
        expected_response
    ):
        raise EvidenceError("response receive calls do not conserve response bytes")
    _exact_value(value["decoded_body"], expected_body.decode("ascii"), "decoded_body")

    connection = _mapping(value["connection"], "sample.connection")
    _exact_keys(
        connection,
        {
            "transport",
            "address_family",
            "socket_type",
            "protocol",
            "local_host",
            "local_port",
            "peer_host",
            "peer_port",
            "local_is_loopback",
            "peer_is_loopback",
            "client_tcp_nodelay",
            "client_half_closed_write",
            "connection_reused",
        },
        "sample.connection",
    )
    fixed_connection = {
        "transport": "TCP_IPV4_LOOPBACK",
        "address_family": "AF_INET",
        "socket_type": "SOCK_STREAM",
        "protocol": "IPPROTO_TCP",
        "local_host": "127.0.0.1",
        "peer_host": "127.0.0.1",
        "local_is_loopback": True,
        "peer_is_loopback": True,
        "client_tcp_nodelay": True,
        "client_half_closed_write": True,
        "connection_reused": False,
    }
    for key, item in fixed_connection.items():
        _exact_value(connection[key], item, f"sample.connection.{key}")
    _positive_int(connection["local_port"], "sample.connection.local_port")
    _positive_int(connection["peer_port"], "sample.connection.peer_port")

    timing = _mapping(value["timing"], "sample.timing")
    _exact_keys(
        timing,
        {
            "clock",
            "connect_ns",
            "request_to_first_byte_ns",
            "request_to_eof_ns",
            "connect_start_to_eof_ns",
        },
        "sample.timing",
    )
    _exact_value(timing["clock"], "time.perf_counter_ns", "sample.timing.clock")
    connect_ns = _positive_int(timing["connect_ns"], "connect_ns")
    first_ns = _positive_int(timing["request_to_first_byte_ns"], "first_byte_ns")
    eof_ns = _positive_int(timing["request_to_eof_ns"], "request_to_eof_ns")
    total_ns = _positive_int(timing["connect_start_to_eof_ns"], "total_external_ns")
    if (
        first_ns > eof_ns
        or connect_ns > total_ns
        or eof_ns > total_ns
        or connect_ns + eof_ns > total_ns
    ):
        raise EvidenceError("external timing fields violate monotone clock order")

    resource = _mapping(value["server_resource"], "sample.server_resource")
    _exact_keys(
        resource,
        {
            "route",
            "accepted",
            "backend_kind",
            "backend_calls",
            "kdf_calls",
            "backend_cpu_ns",
            "backend_wall_ns",
            "auth_worker_cpu_ns",
            "auth_worker_wall_ns",
            "auth_worker_thread_id",
            "auth_worker_native_id",
            "cache_hits",
            "screen_negatives",
            "padding_scheduled_async",
            "padding_requested_delay_ns",
            "padding_actual_wait_ns",
            "padding_thread_id",
            "padding_execution_class",
            "request_received_monotonic_ns",
            "padding_deadline_monotonic_ns",
            "response_release_monotonic_ns",
            "response_send_started_monotonic_ns",
            "auth_worker_released_before_padding",
            "padding_used_auth_worker",
            "server_observed_client_eof",
            "server_tcp_nodelay",
            "server_shutdown_write",
            "sut_instance_id",
            "sut_construction_ordinal",
            "sut_process_id",
            "kdf_workload",
        },
        "sample.server_resource",
    )
    route, backend_kind, backend_calls = EXPECTED_ROUTES[expected.case]
    expected_resource = {
        "route": route,
        "accepted": expected.case == "valid_password",
        "backend_kind": backend_kind,
        "backend_calls": backend_calls,
        "kdf_calls": 0 if expected.case == "transient_backend_failure" else backend_calls,
        "cache_hits": 1 if expected.case == "negative_cache_hit" else 0,
        # The controlled false-positive wrapper first evaluates the real
        # one-sided screen, so its underlying negative counter also advances
        # for the two forced backend paths.
        "screen_negatives": (
            1
            if expected.case
            in {
                "positive_screen_negative",
                "backend_mismatch",
                "transient_backend_failure",
            }
            else 0
        ),
        "padding_execution_class": "threading.Timer",
        "auth_worker_released_before_padding": True,
        "padding_used_auth_worker": False,
        "server_observed_client_eof": True,
        "server_tcp_nodelay": True,
        "server_shutdown_write": True,
    }
    for key, item in expected_resource.items():
        _exact_value(resource[key], item, f"sample.server_resource.{key}")
    if type(resource["sut_instance_id"]) is not str or len(resource["sut_instance_id"]) != 32:
        raise EvidenceError("sample SUT instance ID is invalid")
    seed_index = list(profile["seeds"]).index(expected.seed)
    _exact_value(
        resource["sut_construction_ordinal"], seed_index, "sample SUT construction ordinal"
    )
    _positive_int(resource["sut_process_id"], "sample SUT process ID")
    expected_workload = _workload_for_seed(profile, expected.seed, seed_index)
    _exact_value(resource["kdf_workload"], expected_workload, "sample.server_resource.kdf_workload")
    for key in (
        "backend_cpu_ns",
        "backend_wall_ns",
        "auth_worker_cpu_ns",
        "auth_worker_wall_ns",
        "padding_requested_delay_ns",
        "padding_actual_wait_ns",
    ):
        _positive_int(resource[key], f"sample.server_resource.{key}", allow_zero=True)
    if resource["kdf_calls"] == 0 and (
        resource["backend_cpu_ns"] != 0 or resource["backend_wall_ns"] != 0
    ):
        raise EvidenceError("KDF resource use must be zero when no KDF call occurred")
    if resource["kdf_calls"] == 1 and int(resource["backend_wall_ns"]) <= 0:
        raise EvidenceError("a KDF call must report positive measured backend wall time")
    if int(resource["auth_worker_wall_ns"]) <= 0:
        raise EvidenceError("authentication worker wall time must be positive")
    _positive_int(resource["auth_worker_thread_id"], "auth_worker_thread_id")
    _positive_int(resource["auth_worker_native_id"], "auth_worker_native_id")
    if type(resource["padding_scheduled_async"]) is not bool:
        raise EvidenceError("padding_scheduled_async must be Boolean")
    if resource["padding_scheduled_async"]:
        _positive_int(resource["padding_thread_id"], "padding_thread_id")
        if int(resource["padding_requested_delay_ns"]) <= 0:
            raise EvidenceError("scheduled padding requires a positive requested delay")
        if int(resource["padding_actual_wait_ns"]) <= 0:
            raise EvidenceError("scheduled padding requires a positive observed wait")
        if resource["padding_thread_id"] == resource["auth_worker_thread_id"]:
            raise EvidenceError("padding ran on the authentication worker")
    elif resource["padding_thread_id"] is not None:
        raise EvidenceError("immediate response cannot report a padding thread")
    elif resource["padding_requested_delay_ns"] != 0 or resource["padding_actual_wait_ns"] != 0:
        raise EvidenceError("immediate response cannot report a padding delay")
    received_ns = _positive_int(
        resource["request_received_monotonic_ns"], "request_received_monotonic_ns"
    )
    deadline_ns = _positive_int(
        resource["padding_deadline_monotonic_ns"], "padding_deadline_monotonic_ns"
    )
    release_ns = _positive_int(
        resource["response_release_monotonic_ns"], "response_release_monotonic_ns"
    )
    send_started_ns = _positive_int(
        resource["response_send_started_monotonic_ns"],
        "response_send_started_monotonic_ns",
    )
    minimum_padding_ns = int(float(profile["failure_padding_ms"]) * 1_000_000)
    _exact_value(
        deadline_ns,
        received_ns + minimum_padding_ns,
        "minimum padding deadline",
    )
    if release_ns < deadline_ns or send_started_ns < release_ns:
        raise EvidenceError("response release/send order violates the minimum padding deadline")
    if send_started_ns < received_ns + minimum_padding_ns:
        raise EvidenceError("response send began before request receipt plus minimum padding")
    return value


def _verify_attestation(
    value: Mapping[str, object],
    profile_name: str,
    profile: Mapping[str, Any],
    producer_public_key_hex: str | None = None,
) -> None:
    attestation = _mapping(value["attestation"], "raw.attestation")
    _exact_keys(attestation, {"algorithm", "public_key_hex", "signature_hex"}, "raw.attestation")
    unsigned = {key: item for key, item in value.items() if key != "attestation"}
    if (
        profile_name == "smoke"
        or profile.get("formal_contract") == PREREGISTERED_FORMAL_CONTRACT
    ):
        expected = {"algorithm": "NONE", "public_key_hex": None, "signature_hex": None}
        _exact_value(attestation, expected, "raw.attestation")
        return
    if attestation["algorithm"] != "Ed25519":
        raise EvidenceError("formal raw evidence must use Ed25519 attestation")
    if attestation["public_key_hex"] != producer_public_key_hex:
        raise EvidenceError("formal raw evidence public key differs from auditor manifest")
    if type(attestation["signature_hex"]) is not str or len(attestation["signature_hex"]) != 128:
        raise EvidenceError("formal raw evidence has an invalid Ed25519 signature encoding")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(str(attestation["public_key_hex"]))
        )
        public.verify(bytes.fromhex(str(attestation["signature_hex"])), _canonical(unsigned))
    except ImportError as exc:
        raise EvidenceError("formal E9 verification requires the cryptography package") from exc
    except (ValueError, InvalidSignature) as exc:
        raise EvidenceError("formal E9 producer attestation is invalid") from exc


def _validate_formal_execution_binding(
    value: object,
    contract: Mapping[str, Any],
    manifest: Mapping[str, Any],
    challenge: Mapping[str, Any],
    host: Mapping[str, Any],
    collected_unix: int,
    *,
    process_isolation_verified: bool,
) -> dict[str, Any]:
    execution = _mapping(value, "raw.formal_execution")
    _exact_keys(
        execution,
        {
            "schema",
            "host_contract_id",
            "collection_started_unix_ns",
            "pre_attestation",
            "post_attestation",
            "collection_completed_unix_ns",
            "exclusive_lock",
            "seed_process_isolation",
            "formal_readiness_blockers",
            "formal_readiness",
        },
        "raw.formal_execution",
    )
    _exact_value(execution["schema"], FORMAL_EXECUTION_SCHEMA, "formal execution schema")
    _exact_value(
        execution["host_contract_id"],
        _identity(contract),
        "auditor-signed host contract binding",
    )
    started = _integer(
        execution["collection_started_unix_ns"], "formal collection start timestamp", 1
    )
    pre = _validate_host_attestation(execution["pre_attestation"], contract, "PRE_COLLECTION")
    post = _validate_host_attestation(
        execution["post_attestation"], contract, "POST_COLLECTION"
    )
    completed = _integer(
        execution["collection_completed_unix_ns"],
        "formal collection completion timestamp",
        1,
    )

    lock = _mapping(execution["exclusive_lock"], "formal exclusive-lock evidence")
    _exact_keys(
        lock,
        {
            "schema",
            "lock_id",
            "audit_id",
            "marker_uri",
            "acquired_unix_ns",
            "retention_scope",
            "uniqueness_primitive",
            "marker_role",
            "anchor",
        },
        "formal exclusive-lock evidence",
    )
    _exact_value(lock["schema"], FORMAL_LOCK_SCHEMA, "formal exclusive-lock schema")
    lock_contract = _validate_exclusive_lock_contract(
        contract["exclusive_lock"], contract["system"]
    )
    _exact_value(lock["lock_id"], lock_contract["lock_id"], "exclusive lock ID binding")
    _exact_value(
        lock["marker_uri"],
        lock_contract["marker_uri"],
        "exclusive lock marker URI binding",
    )
    _exact_value(lock["audit_id"], manifest["audit_id"], "exclusive lock audit binding")
    acquired = _integer(lock["acquired_unix_ns"], "exclusive lock acquisition timestamp", 1)
    _exact_value(
        lock["retention_scope"],
        FORMAL_LOCK_RETENTION_SCOPE,
        "exclusive lock retention scope",
    )
    _exact_value(
        lock["uniqueness_primitive"],
        LOCK_UNIQUENESS_PRIMITIVE,
        "formal uniqueness primitive",
    )
    _exact_value(lock["marker_role"], LOCK_MARKER_ROLE, "formal marker role")
    _exact_value(
        lock["anchor"],
        {
            "uri": lock_contract["anchor_uri"],
            "device": lock_contract["anchor_device"],
            "inode": lock_contract["anchor_inode"],
            "content_sha256": lock_contract["anchor_sha256"],
            "lock_byte_offset": lock_contract["lock_byte_offset"],
            "lock_byte_length": lock_contract["lock_byte_length"],
            "lock_api": lock_contract["expected_lock_api"],
            "filesystem": lock_contract["filesystem"],
        },
        "auditor-signed advisory anchor execution evidence",
    )
    signed_window_start, signed_window_end = _signed_window_bounds_ns(manifest, challenge)
    timeline = (
        signed_window_start,
        started,
        int(pre["captured_unix_ns"]),
        acquired,
        int(post["captured_unix_ns"]),
        completed,
        signed_window_end,
    )
    if any(left > right for left, right in zip(timeline, timeline[1:], strict=False)):
        raise EvidenceError("formal collection nanosecond timeline violates its signed window")
    _exact_value(
        collected_unix,
        completed // 1_000_000_000,
        "formal collection second/nanosecond binding",
    )
    _exact_value(
        execution["seed_process_isolation"],
        PROCESS_ISOLATION_DECLARATION,
        "formal seed process-isolation evidence",
    )
    _exact_value(
        execution["formal_readiness_blockers"],
        _formal_execution_blockers(
            _mapping(contract["power_governor_assertion"], "power/governor assertion")[
                "mode"
            ],
            process_isolation_verified=process_isolation_verified,
        ),
        "formal readiness blockers",
    )
    _exact_value(
        execution["formal_readiness"],
        "BLOCKED_BY_UNRESOLVED_EXECUTION_OR_PUBLICATION_GATES",
        "formal readiness status",
    )
    runtime = _mapping(pre["python_runtime"], "pre-collection Python runtime")
    expected_host = {
        "node": pre["host_id"],
        "machine": pre["architecture"],
        "platform": pre["system"],
        "python": f"{runtime['implementation']} {runtime['version']}",
        "logical_cpu_count": pre["logical_cpu_count"],
    }
    _exact_value(host, expected_host, "formal raw host projection")
    return execution


def _validate_preregistered_authorization(value: object) -> dict[str, Any]:
    authorization = _mapping(value, "raw.formal_authorization")
    _exact_value(
        authorization,
        _preregistered_authorization(),
        "v5 preregistered formal authorization",
    )
    return authorization


def _validate_preregistered_execution_binding(
    value: object,
    config: Mapping[str, Any],
    profile: Mapping[str, Any],
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    host: Mapping[str, Any],
    parent_process_id: int,
    parent_runtime: Mapping[str, Any],
    parent_affinity: Sequence[int],
    collected_unix: int,
) -> dict[str, Any]:
    execution = _mapping(value, "raw.formal_execution")
    _exact_keys(
        execution,
        {
            "schema",
            "formal_contract",
            "collection_started_unix_ns",
            "collection_completed_unix_ns",
            "source_commit",
            "python_runtime",
            "cpu_affinity",
            "host_system",
            "host",
            "pre_measurement_environment",
            "post_measurement_environment",
            "operator_assertions",
            "governance_binding",
            "seed_process_isolation",
            "formal_readiness_blockers",
            "formal_readiness",
        },
        "raw.formal_execution",
    )
    _exact_value(
        execution["schema"],
        PREREGISTERED_FORMAL_EXECUTION_SCHEMA,
        "v5 formal execution schema",
    )
    _exact_value(
        execution["formal_contract"],
        PREREGISTERED_FORMAL_CONTRACT,
        "v5 formal execution contract",
    )
    started = _integer(
        execution["collection_started_unix_ns"],
        "v5 formal collection start timestamp",
        1,
    )
    completed = _integer(
        execution["collection_completed_unix_ns"],
        "v5 formal collection completion timestamp",
        1,
    )
    if completed < started:
        raise EvidenceError("v5 formal collection completion precedes its start")
    _exact_value(
        collected_unix,
        completed // 1_000_000_000,
        "v5 formal collection second/nanosecond binding",
    )
    _exact_value(after, before, "v5 formal unchanged clean source")
    if before["clean"] is not True or before["status"] != []:
        raise EvidenceError("v5 formal source_before must be clean with empty status")
    if after["clean"] is not True or after["status"] != []:
        raise EvidenceError("v5 formal source_after must be clean with empty status")
    _exact_value(execution["source_commit"], before["commit"], "v5 source commit binding")
    _exact_value(execution["python_runtime"], parent_runtime, "v5 Python runtime binding")
    _exact_value(execution["cpu_affinity"], list(parent_affinity), "v5 CPU affinity binding")
    _exact_value(execution["host_system"], "Linux", "v5 host system")
    _exact_value(execution["host"], host, "v5 host/platform binding")
    pre_environment = _validate_preregistered_measurement_environment(
        execution["pre_measurement_environment"], "PRE_MEASUREMENT"
    )
    post_environment = _validate_preregistered_measurement_environment(
        execution["post_measurement_environment"], "POST_MEASUREMENT"
    )
    pre_captured = int(pre_environment["captured_unix_ns"])
    post_captured = int(post_environment["captured_unix_ns"])
    if not started <= pre_captured <= post_captured <= completed:
        raise EvidenceError("v5 pre/post measurement environment timeline is invalid")
    _exact_value(
        _stable_measurement_environment(post_environment),
        _stable_measurement_environment(pre_environment),
        "v5 stable pre/post measurement environment",
    )
    _exact_value(
        pre_environment["affinity"]["process_allowed_cpus"],
        list(parent_affinity),
        "v5 pre-measurement parent affinity binding",
    )
    _exact_value(
        post_environment["affinity"]["process_allowed_cpus"],
        list(parent_affinity),
        "v5 post-measurement parent affinity binding",
    )
    _exact_value(
        pre_environment["affinity"]["process_id"],
        parent_process_id,
        "v5 pre-measurement parent process binding",
    )
    _exact_value(
        post_environment["affinity"]["process_id"],
        parent_process_id,
        "v5 post-measurement parent process binding",
    )
    expected_assertions = {
        "evidence_class": PREREGISTERED_ASSERTION_CLASS,
        "exclusive_host_asserted": True,
        "services_quiesced_asserted": True,
        "runner_service_state_query_performed": False,
    }
    _exact_value(
        execution["operator_assertions"],
        expected_assertions,
        "v5 self-reported operator assertions",
    )
    _exact_value(
        execution["governance_binding"],
        _current_e9_claims_binding(config, require_power=True),
        "v5 formal current governance binding",
    )
    seed_count = len(profile["seeds"])
    expected_isolation = {
        "mode": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_REUSE",
        "fresh_os_process_per_seed": True,
        "serial_execution": True,
        "retry_count": 0,
        "seed_count": seed_count,
        "unique_child_process_ids": seed_count,
        "unique_sut_instance_ids": seed_count,
        "evidence_role": "FORMAL_RUN_INTERNAL_EXECUTION_EVIDENCE_REPLACES_QUALIFICATION_RECEIPT",
    }
    _exact_value(
        execution["seed_process_isolation"],
        expected_isolation,
        "v5 formal seed process-isolation evidence",
    )
    _exact_value(
        execution["formal_readiness_blockers"],
        [PREREGISTERED_FORMAL_BLOCKER],
        "v5 formal readiness blockers",
    )
    _exact_value(
        execution["formal_readiness"],
        "BLOCKED_PENDING_INDEPENDENT_POST_RUN_AUDIT",
        "v5 formal readiness status",
    )
    return execution


def validate_raw(
    artifact: object,
    config: Mapping[str, Any],
    config_id: str,
    profile_name: str,
    *,
    auditor_root_public_key_hex: str | None = None,
    verification_replay_registry: Path | None = None,
    register_replay: bool = True,
) -> dict[str, Any]:
    config = validate_config(config)
    _exact_value(config_id, _identity(config), "E9 configuration ID")
    profile, profile_id = profile_contract(config, profile_name)
    preregistered = _is_preregistered_clean_run(config)
    if preregistered:
        _current_e9_claims_binding(
            config, require_power=profile_name == "formal"
        )
    if preregistered and profile_name == "formal" and (
        auditor_root_public_key_hex is not None
        or verification_replay_registry is not None
    ):
        raise EvidenceError(
            "v5 preregistered validation forbids v4 auditor-root and replay-registry arguments"
        )
    value = _mapping(artifact, "E9 raw artifact")
    body_keys = {
        "schema",
        "experiment_id",
        "config_id",
        "profile",
        "profile_id",
        "evidence_class",
        "source_before",
        "source_after",
        "host",
        "resource_clocks",
        "service_parameters",
        "transport",
        "producer_contract",
        "warmup_requests",
        "stress_requests",
        "samples",
        "sample_chain_sha256",
        "runtime",
        "formal_authorization",
        "collected_unix",
        "limitations",
        "status",
        "g7_status",
    }
    if profile_name == "formal":
        body_keys.add("formal_execution")
    _exact_keys(value, body_keys | {"raw_id", "attestation"}, "E9 raw artifact")
    expected_header = {
        "schema": RAW_SCHEMA,
        "experiment_id": config["experiment_id"],
        "config_id": config_id,
        "profile": profile_name,
        "profile_id": profile_id,
        "evidence_class": profile["evidence_class"],
        "warmup_requests": len(profile["seeds"])
        * len(ALL_CASES)
        * int(profile["warmup_per_case_per_seed"]),
        "status": "FORMAL_RAW_CAPTURE_COMPLETE_WITH_UNRESOLVED_BLOCKERS"
        if profile_name == "formal"
        else "SMOKE_NON_EVIDENCE_COMPLETE",
        "g7_status": "NOT_CLAIMED_E9_RAW_ONLY",
        "stress_requests": len(profile["seeds"]) * (int(profile["auth_workers"]) + 1),
    }
    for key, item in expected_header.items():
        _exact_value(value[key], item, f"raw.{key}")
    collected_unix = _positive_int(value["collected_unix"], "raw.collected_unix")
    before = _validate_git_state(value["source_before"], "source_before")
    after = _validate_git_state(value["source_after"], "source_after")
    if profile_name == "formal" and (before != after or before["clean"] is not True):
        raise EvidenceError("formal raw artifact requires unchanged exact clean source")
    host = _mapping(value["host"], "raw.host")
    _exact_keys(
        host,
        {"node", "machine", "platform", "python", "logical_cpu_count"},
        "raw.host",
    )
    if any(
        type(host[key]) is not str or not host[key]
        for key in ("node", "machine", "platform", "python")
    ):
        raise EvidenceError("raw host fields must be nonempty strings")
    if preregistered and profile_name == "formal":
        _exact_value(
            host["machine"],
            PREREGISTERED_PRODUCTION_ARCHITECTURE,
            "v5 formal host architecture",
        )
    _positive_int(host["logical_cpu_count"], "raw.host.logical_cpu_count")
    clocks = _mapping(value["resource_clocks"], "raw.resource_clocks")
    _exact_keys(clocks, {"external_wall", "worker_cpu"}, "raw.resource_clocks")
    for clock_name, clock_value in clocks.items():
        clock = _mapping(clock_value, f"raw.resource_clocks.{clock_name}")
        _exact_keys(
            clock,
            {"implementation", "monotonic", "adjustable", "resolution_seconds"},
            f"raw.resource_clocks.{clock_name}",
        )
        if type(clock["implementation"]) is not str or not clock["implementation"]:
            raise EvidenceError("resource clock implementation must be a nonempty string")
        if type(clock["monotonic"]) is not bool or type(clock["adjustable"]) is not bool:
            raise EvidenceError("resource clock flags must be Boolean")
        _number(
            clock["resolution_seconds"],
            f"raw.resource_clocks.{clock_name}.resolution_seconds",
            0.0,
        )
    service_parameters = _mapping(value["service_parameters"], "raw.service_parameters")
    expected_service_parameters = {
        "screen": "Python exact positive representation with controlled false-positive paths",
        "backend_kdf": "REAL_CONFIGURED_VERIFIER_PATH",
        "pbkdf2_iterations": profile["pbkdf2_iterations"],
        "pbkdf2_dklen": profile["pbkdf2_dklen"],
        "kdf_workloads": profile["kdf_workloads"],
        "seed_workload_schedule": _seed_workload_schedule(profile),
        "auth_workers": profile["auth_workers"],
        "failure_padding_ms": profile["failure_padding_ms"],
        "max_pending_padding": profile["max_pending_padding"],
        "negative_cache_prewarm": "one typed backend mismatch before network warmup",
        "backend_cpu_field_scope": "configured real KDF call only",
        "auth_worker_cpu_field_scope": "complete AuthDataPlane.authenticate task",
        **(
            {
                "path_contracts": config["failure_case_contracts"]
            }
            if preregistered
            else {}
        ),
    }
    _exact_value(
        service_parameters,
        expected_service_parameters,
        "raw.service_parameters",
    )
    transport = _mapping(value["transport"], "raw.transport")
    _exact_keys(
        transport,
        {"listen_host", "listen_ports_by_seed", "family", "type", "protocol", "tls", "scope"},
        "raw.transport",
    )
    expected_transport = {
        "listen_host": "127.0.0.1",
        "family": "AF_INET",
        "type": "SOCK_STREAM",
        "protocol": "IPPROTO_TCP",
        "tls": False,
        "scope": "SINGLE_HOST_LOOPBACK_EXTERNAL_SOCKET_BOUNDARY",
    }
    for key, item in expected_transport.items():
        _exact_value(transport[key], item, f"raw.transport.{key}")
    ports = _mapping(transport["listen_ports_by_seed"], "raw.transport.listen_ports_by_seed")
    if set(ports) != {str(seed) for seed in profile["seeds"]}:
        raise EvidenceError("listener ports do not cover the frozen seed set")
    for port in ports.values():
        _positive_int(port, "seed listener port")
    expected_contract = {
        "label_source": "FROZEN_SEED_CASE_ORDINAL_SCHEDULE",
        "request_shape": "FIXED_110_BYTE_BINARY_REQUEST",
        "failure_response": "IDENTICAL_THREE_FRAME_401_THEN_EOF",
        "padding": "BOUNDED_THREADING_TIMER_AFTER_AUTH_WORKER_RELEASE",
        "classifier_population": "FAILURE_CASES_ONLY",
        "functional_success_excluded_from_auc": True,
        "seed_isolation": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_REUSE",
        **(
            {
                "classifier": "FROZEN_EXTERNAL_MULTIVARIATE_RIDGE_LOGISTIC",
                "classifier_fit_scope": "TRAINING_SEEDS_ONLY_PER_KDF_AND_FAILURE_PAIR",
                    "classifier_evaluation_scope": "THIRTY_DISJOINT_EVALUATION_SEEDS_PER_KDF",
                "sampling_schedule": config["sampling_schedule"],
                "path_contracts": config["failure_case_contracts"],
                "diagnostics_contract": config["diagnostics_contract"],
            }
            if preregistered and profile_name == "formal"
            else {}
        ),
    }
    _exact_value(value["producer_contract"], expected_contract, "raw.producer_contract")

    plan = measurement_plan(profile)
    samples = value["samples"]
    if type(samples) is not list or len(samples) != len(plan):
        raise EvidenceError("raw samples do not cover the fixed denominator")
    validated = [
        _validate_sample(sample, profile_name, profile_id, profile, coordinate)
        for sample, coordinate in zip(samples, plan, strict=True)
    ]
    if any(sample["connection"]["peer_port"] != ports[str(sample["seed"])] for sample in validated):
        raise EvidenceError("sample peer port differs from its seed-isolated listener")
    _exact_value(value["sample_chain_sha256"], _chain(validated), "sample chain")
    runtime = _mapping(value["runtime"], "raw.runtime")
    _exact_keys(
        runtime,
        {
            "handler_threads_created",
            "handler_threads_alive_after_shutdown",
            "padding",
            "server_errors",
            "parent_process_id",
            "parent_python_runtime",
            "parent_cpu_affinity",
            "sut_instances_by_seed",
            "sut_process_ids_by_seed",
            "seed_child_processes_by_seed",
            "stress_audit",
        },
        "raw.runtime",
    )
    expected_requests = len(plan) + int(value["warmup_requests"]) + int(value["stress_requests"])
    _exact_value(runtime["handler_threads_created"], expected_requests, "handler count")
    _exact_value(runtime["handler_threads_alive_after_shutdown"], 0, "alive handler count")
    _exact_value(runtime["server_errors"], [], "server errors")
    instances = _mapping(runtime["sut_instances_by_seed"], "raw.runtime.sut_instances_by_seed")
    if set(instances) != {str(seed) for seed in profile["seeds"]}:
        raise EvidenceError("SUT instances do not cover every seed")
    if len(set(instances.values())) != len(profile["seeds"]):
        raise EvidenceError("each seed must use a distinct SUT instance")
    if any(
        sample["server_resource"]["sut_instance_id"] != instances[str(sample["seed"])]
        for sample in validated
    ):
        raise EvidenceError("sample does not belong to its seed-isolated SUT instance")
    process_ids = _mapping(
        runtime["sut_process_ids_by_seed"], "raw.runtime.sut_process_ids_by_seed"
    )
    if set(process_ids) != {str(seed) for seed in profile["seeds"]}:
        raise EvidenceError("SUT process IDs do not cover every seed")
    normalized_process_ids = [
        _positive_int(process_ids[str(seed)], "seed SUT process ID")
        for seed in profile["seeds"]
    ]
    parent_process_id = _positive_int(runtime["parent_process_id"], "raw parent process ID")
    isolation_verified = _process_isolation_verified(
        parent_process_id,
        normalized_process_ids,
        len(profile["seeds"]),
    )
    if not isolation_verified:
        raise EvidenceError(
            "each seed must use a distinct child process ID different from the parent"
        )
    if any(
        sample["server_resource"]["sut_process_id"] != process_ids[str(sample["seed"])]
        for sample in validated
    ):
        raise EvidenceError("sample SUT process ID differs from its seed record")
    parent_runtime = _validate_python_runtime_identity(
        runtime["parent_python_runtime"], "raw parent Python runtime"
    )
    parent_affinity = runtime["parent_cpu_affinity"]
    if type(parent_affinity) is not list or not parent_affinity:
        raise EvidenceError("raw parent CPU affinity must be a nonempty array")
    normalized_affinity = [_integer(cpu, "raw parent affinity CPU") for cpu in parent_affinity]
    if normalized_affinity != sorted(set(normalized_affinity)):
        raise EvidenceError("raw parent CPU affinity must be sorted and unique")
    child_processes = _mapping(
        runtime["seed_child_processes_by_seed"],
        "raw.runtime.seed_child_processes_by_seed",
    )
    if set(child_processes) != {str(seed) for seed in profile["seeds"]}:
        raise EvidenceError("seed-child launch evidence does not cover every seed")
    child_environment_window: tuple[int, int] | None = None
    previous_child_post_ns: int | None = None
    if preregistered and profile_name == "formal":
        preregistered_execution = _mapping(
            value["formal_execution"], "raw.formal_execution"
        )
        parent_pre_environment = _mapping(
            preregistered_execution.get("pre_measurement_environment"),
            "v5 parent pre-measurement environment",
        )
        parent_post_environment = _mapping(
            preregistered_execution.get("post_measurement_environment"),
            "v5 parent post-measurement environment",
        )
        child_environment_window = (
            _integer(
                parent_pre_environment.get("captured_unix_ns"),
                "v5 parent pre-measurement timestamp",
                1,
            ),
            _integer(
                parent_post_environment.get("captured_unix_ns"),
                "v5 parent post-measurement timestamp",
                1,
            ),
        )
    for seed in profile["seeds"]:
        seed_key = str(seed)
        child = _mapping(child_processes[seed_key], f"seed-child launch evidence {seed}")
        expected_child_keys = {
            "popen_pid",
            "reported_pid",
            "python_runtime",
            "cpu_affinity",
        }
        if preregistered and profile_name == "formal":
            expected_child_keys.add("measurement_environment")
        _exact_keys(
            child,
            expected_child_keys,
            f"seed-child launch evidence {seed}",
        )
        _exact_value(child["popen_pid"], process_ids[seed_key], "Popen PID evidence")
        _exact_value(child["reported_pid"], process_ids[seed_key], "reported child PID evidence")
        _exact_value(child["python_runtime"], parent_runtime, "seed-child Python identity")
        _exact_value(child["cpu_affinity"], parent_affinity, "seed-child CPU affinity")
        if preregistered and profile_name == "formal":
            seed_index = list(profile["seeds"]).index(seed)
            workload = _workload_for_seed(profile, seed, seed_index)
            child_environment = _mapping(
                child["measurement_environment"],
                f"seed-child measurement environment {seed}",
            )
            _exact_keys(
                child_environment,
                {"pre", "post"},
                f"seed-child measurement environment {seed}",
            )
            pre_child_environment = _validate_seed_child_measurement_environment(
                child_environment["pre"],
                "PRE_SEED_MEASUREMENT",
                int(process_ids[seed_key]),
                parent_affinity,
                int(profile["auth_workers"]),
                workload,
            )
            post_child_environment = _validate_seed_child_measurement_environment(
                child_environment["post"],
                "POST_SEED_MEASUREMENT",
                int(process_ids[seed_key]),
                parent_affinity,
                int(profile["auth_workers"]),
                workload,
            )
            pre_child_ns = int(pre_child_environment["captured_unix_ns"])
            post_child_ns = int(post_child_environment["captured_unix_ns"])
            if post_child_ns <= pre_child_ns:
                raise EvidenceError(
                    f"seed-child environment {seed} postflight does not follow preflight"
                )
            _exact_value(
                _stable_seed_child_measurement_environment(post_child_environment),
                _stable_seed_child_measurement_environment(pre_child_environment),
                f"seed-child stable environment {seed}",
            )
            if child_environment_window is None:
                raise RuntimeError("v5 child environment window is missing")
            started_ns, completed_ns = child_environment_window
            if not started_ns < pre_child_ns < post_child_ns < completed_ns:
                raise EvidenceError(
                    f"seed-child environment {seed} falls outside collection time"
                )
            if previous_child_post_ns is not None and pre_child_ns <= previous_child_post_ns:
                raise EvidenceError(
                    f"seed-child environment {seed} overlaps a prior serial seed"
                )
            previous_child_post_ns = post_child_ns
            expected_worker_native_ids = set(
                pre_child_environment["auth_worker_native_ids"]
            )
            if any(
                int(sample["server_resource"]["auth_worker_native_id"])
                not in expected_worker_native_ids
                for sample in validated
                if int(sample["seed"]) == int(seed)
            ):
                raise EvidenceError(
                    f"seed-child sample {seed} lacks native auth-worker binding"
                )
    stress = _mapping(runtime["stress_audit"], "raw.runtime.stress_audit")
    _exact_keys(stress, {"worker_saturation", "padding_capacity_probe"}, "raw.runtime.stress_audit")
    worker_stress = _mapping(stress.get("worker_saturation"), "worker saturation audit")
    overflow_stress = _mapping(stress.get("padding_capacity_probe"), "padding capacity audit")
    _exact_keys(worker_stress, {"probe", "per_seed"}, "worker saturation audit")
    _exact_value(
        worker_stress["probe"],
        "CONCURRENT_REAL_LOOPBACK_AUTH_REQUESTS_PER_SEED",
        "worker stress probe",
    )
    expected_per_seed = [
        {
            "seed": seed,
            "configured_workers": profile["auth_workers"],
            "simultaneously_active_sut_workers": profile["auth_workers"],
            "concurrent_loopback_requests": int(profile["auth_workers"]) + 1,
            "one_additional_request_queued": True,
        }
        for seed in profile["seeds"]
    ]
    _exact_value(worker_stress["per_seed"], expected_per_seed, "per-seed worker stress")
    _exact_keys(
        overflow_stress,
        {
            "capacity",
            "probe",
            "peak_pending",
            "overflow_attempts",
            "overflow_failed_closed",
            "pending_after_probe",
        },
        "padding capacity audit",
    )
    _exact_value(
        overflow_stress["probe"],
        "CONFIGURED_PADDER_MECHANISM_CAPACITY_NO_TCP_OVERFLOW_CLAIM",
        "padding capacity probe scope",
    )
    _exact_value(
        overflow_stress["capacity"], profile["max_pending_padding"], "stress padding capacity"
    )
    _exact_value(
        overflow_stress["peak_pending"],
        profile["max_pending_padding"],
        "stress peak pending",
    )
    _exact_value(overflow_stress["overflow_attempts"], 1, "stress overflow attempts")
    _exact_value(overflow_stress["overflow_failed_closed"], True, "stress overflow behavior")
    _exact_value(overflow_stress["pending_after_probe"], 0, "stress pending cleanup")
    padding = _mapping(runtime["padding"], "raw.runtime.padding")
    _exact_keys(
        padding,
        {
            "scheduled_async",
            "immediate_after_slow_auth",
            "peak_pending",
            "pending",
            "overflow_failures",
            "max_pending",
        },
        "raw.runtime.padding",
    )
    for key in padding:
        _positive_int(padding[key], f"raw.runtime.padding.{key}", allow_zero=True)
    _exact_value(padding["pending"], 0, "raw.runtime.padding.pending")
    _exact_value(padding["overflow_failures"], 0, "raw.runtime.padding.overflow_failures")
    _exact_value(padding["max_pending"], profile["max_pending_padding"], "max pending")
    if int(padding["peak_pending"]) > int(padding["max_pending"]):
        raise EvidenceError("padding peak exceeds its configured capacity")
    if (
        int(padding["scheduled_async"]) + int(padding["immediate_after_slow_auth"])
        != expected_requests
    ):
        raise EvidenceError("padding accounting does not conserve requests")
    limitations = value["limitations"]
    if profile_name == "smoke":
        _exact_value(limitations, _raw_limitations("smoke"), "raw.limitations")
    elif preregistered:
        _exact_value(
            limitations,
            _raw_limitations(
                "formal",
                formal_contract=PREREGISTERED_FORMAL_CONTRACT,
            ),
            "raw.limitations",
        )
    body = {key: value[key] for key in body_keys}
    _exact_value(value["raw_id"], _identity(body), "raw.raw_id")
    producer_public_key_hex = None
    replay_nonce: str | None = None
    authorization = value["formal_authorization"]
    if profile_name == "smoke":
        _exact_value(authorization, None, "raw.formal_authorization")
    elif preregistered:
        _validate_preregistered_authorization(authorization)
        _validate_preregistered_execution_binding(
            value["formal_execution"],
            config,
            profile,
            before,
            after,
            host,
            parent_process_id,
            parent_runtime,
            normalized_affinity,
            collected_unix,
        )
    else:
        if auditor_root_public_key_hex is None:
            raise EvidenceError("formal verification requires an explicit auditor trust root")
        auth = _mapping(authorization, "raw.formal_authorization")
        _exact_keys(
            auth, {"manifest", "challenge", "auditor_root_sha256"}, "raw.formal_authorization"
        )
        manifest = _mapping(auth["manifest"], "embedded formal manifest")
        challenge = _mapping(auth["challenge"], "embedded freshness challenge")
        _exact_keys(
            manifest,
            {
                "schema",
                "experiment_id",
                "config_id",
                "profile_id",
                "source_commit",
                "audit_id",
                "producer_public_key_hex",
                "not_before_unix",
                "not_after_unix",
                "collection_registry_uri",
                "collection_registry_id",
                "verification_registry_uri",
                "verification_registry_id",
                "registry_storage_contract",
                "host_execution_contract",
                "signature_hex",
            },
            "embedded formal manifest",
        )
        _exact_keys(
            challenge,
            {
                "schema",
                "experiment_id",
                "config_id",
                "profile_id",
                "audit_id",
                "formal_manifest_sha256",
                "nonce_hex",
                "issued_unix",
                "expires_unix",
                "signature_hex",
            },
            "embedded freshness challenge",
        )
        _verify_root_signed_document(
            manifest, auditor_root_public_key_hex, "embedded formal manifest"
        )
        host_contract = _validate_host_execution_contract(manifest["host_execution_contract"])
        _exact_value(
            parent_runtime,
            host_contract["python_runtime"],
            "raw parent/contract Python runtime binding",
        )
        _exact_value(
            parent_affinity,
            host_contract["allowed_cpu_affinity"],
            "raw parent/contract CPU affinity binding",
        )
        power_contract = _mapping(
            host_contract["power_governor_assertion"], "power/governor assertion"
        )
        _exact_value(
            limitations,
            _raw_limitations("formal", power_contract["mode"]),
            "raw.limitations",
        )
        _verify_root_signed_document(
            challenge, auditor_root_public_key_hex, "embedded freshness challenge"
        )
        _exact_value(
            auth["auditor_root_sha256"],
            hashlib.sha256(bytes.fromhex(auditor_root_public_key_hex)).hexdigest(),
            "auditor root fingerprint",
        )
        for key, expected in {
            "schema": FORMAL_CONTRACT_SCHEMA,
            "experiment_id": config["experiment_id"],
            "config_id": config_id,
            "profile_id": profile_id,
        }.items():
            _exact_value(manifest[key], expected, f"embedded manifest.{key}")
            if key != "schema":
                _exact_value(challenge[key], expected, f"embedded challenge.{key}")
        _exact_value(
            challenge["schema"],
            FRESHNESS_CHALLENGE_SCHEMA,
            "embedded challenge.schema",
        )
        _exact_value(challenge["audit_id"], manifest["audit_id"], "challenge audit ID")
        _opaque_id(challenge["formal_manifest_sha256"], "embedded manifest digest")
        _exact_value(
            challenge["formal_manifest_sha256"],
            _identity(manifest),
            "freshness challenge formal manifest binding",
        )
        _exact_value(before["commit"], manifest["source_commit"], "auditor-frozen source commit")
        if not _full_commit(manifest["source_commit"]):
            raise EvidenceError("embedded manifest source commit is invalid")
        manifest_start = _positive_int(manifest["not_before_unix"], "manifest start")
        manifest_end = _positive_int(manifest["not_after_unix"], "manifest end")
        if not manifest_start <= collected_unix <= manifest_end:
            raise EvidenceError("formal collection is outside its signed contract window")
        audit_id = _nonempty_ascii(manifest["audit_id"], "embedded manifest audit ID")
        if len(audit_id) < 16:
            raise EvidenceError("embedded manifest audit ID is invalid")
        _exact_value(
            manifest["registry_storage_contract"],
            REGISTRY_STORAGE_CONTRACT,
            "embedded registry storage contract",
        )
        _registry_id(manifest["collection_registry_id"], "collection registry ID")
        _registry_id(manifest["verification_registry_id"], "verification registry ID")
        producer_public_key_hex = str(manifest["producer_public_key_hex"])
        if len(producer_public_key_hex) != 64 or any(
            c not in "0123456789abcdef" for c in producer_public_key_hex
        ):
            raise EvidenceError("embedded manifest producer key is invalid")
        nonce = str(challenge["nonce_hex"])
        if len(nonce) != 64 or any(c not in "0123456789abcdef" for c in nonce):
            raise EvidenceError("embedded freshness nonce is invalid")
        issued = _positive_int(challenge["issued_unix"], "embedded challenge issued")
        expires = _positive_int(challenge["expires_unix"], "embedded challenge expires")
        if expires - issued > 3600 or not issued <= collected_unix <= expires:
            raise EvidenceError("formal collection is outside its signed freshness window")
        _validate_formal_execution_binding(
            value["formal_execution"],
            host_contract,
            manifest,
            challenge,
            host,
            collected_unix,
            process_isolation_verified=isolation_verified,
        )
        if register_replay:
            if verification_replay_registry is None:
                raise EvidenceError("formal verification requires a replay registry")
            _require_registry_identity(
                verification_replay_registry,
                namespace="verification",
                expected_registry_id=manifest["verification_registry_id"],
                expected_uri=manifest["verification_registry_uri"],
            )
            replay_nonce = nonce
    _verify_attestation(value, profile_name, profile, producer_public_key_hex)
    if replay_nonce is not None:
        assert verification_replay_registry is not None
        _register_verification_nonce(
            verification_replay_registry, replay_nonce, str(value["raw_id"])
        )
    return value


def _percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise EvidenceError("cannot compute a percentile of an empty sample")
    ordered = sorted(float(value) for value in values)
    if any(not math.isfinite(value) for value in ordered):
        raise EvidenceError("statistics received a non-finite observation")
    position = (len(ordered) - 1) * probability
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + fraction * (ordered[upper] - ordered[lower])


def fit_frozen_ridge_logistic(
    feature_rows: Sequence[Sequence[float]], labels: Sequence[int]
) -> dict[str, object]:
    """Fit the frozen numeric classifier without depending on raw E9 samples."""

    try:
        import numpy as np
        from scipy.optimize import minimize
    except ImportError as exc:
        raise EvidenceError("the frozen E9 classifier requires NumPy and SciPy") from exc

    matrix = np.asarray(feature_rows, dtype=np.float64)
    target = np.asarray(labels, dtype=np.float64)
    if (
        matrix.ndim != 2
        or matrix.shape[0] < 2
        or matrix.shape[1] != len(CLASSIFIER_FEATURE_NAMES)
    ):
        raise EvidenceError(
            "ridge logistic features must use the frozen numeric feature width"
        )
    if target.ndim != 1 or target.shape[0] != matrix.shape[0]:
        raise EvidenceError("ridge logistic labels must align one-for-one with feature rows")
    if not np.isfinite(matrix).all() or not np.isfinite(target).all():
        raise EvidenceError("ridge logistic inputs must be finite")
    if set(float(value) for value in target.tolist()) != {0.0, 1.0}:
        raise EvidenceError("ridge logistic training requires both frozen binary classes")

    medians = np.asarray(
        [_percentile(matrix[:, index].tolist(), 0.5) for index in range(matrix.shape[1])],
        dtype=np.float64,
    )
    iqrs = np.asarray(
        [
            _percentile(matrix[:, index].tolist(), 0.75)
            - _percentile(matrix[:, index].tolist(), 0.25)
            for index in range(matrix.shape[1])
        ],
        dtype=np.float64,
    )
    scales = np.where(iqrs > 0.0, iqrs, 1.0)
    standardized = (matrix - medians) / scales
    l2_penalty = float(FROZEN_CLASSIFIER_CONTRACT["l2_penalty"])

    def objective(parameters):
        intercept = parameters[0]
        coefficients = parameters[1:]
        logits = intercept + standardized @ coefficients
        loss = np.mean(np.logaddexp(0.0, logits) - target * logits)
        loss += 0.5 * l2_penalty * np.dot(coefficients, coefficients)
        residual = 1.0 / (1.0 + np.exp(-np.clip(logits, -709.0, 709.0))) - target
        gradient = np.empty_like(parameters)
        gradient[0] = np.mean(residual)
        gradient[1:] = standardized.T @ residual / matrix.shape[0]
        gradient[1:] += l2_penalty * coefficients
        return float(loss), gradient

    result = minimize(
        objective,
        np.zeros(matrix.shape[1] + 1, dtype=np.float64),
        method="L-BFGS-B",
        jac=True,
        options={
            "gtol": float(FROZEN_CLASSIFIER_CONTRACT["gradient_tolerance"]),
            "ftol": float(FROZEN_CLASSIFIER_CONTRACT["function_tolerance"]),
            "maxiter": int(FROZEN_CLASSIFIER_CONTRACT["max_iterations"]),
            "maxls": int(FROZEN_CLASSIFIER_CONTRACT["max_line_search_steps"]),
        },
    )
    parameters = np.asarray(result.x, dtype=np.float64)
    gradient = np.asarray(result.jac, dtype=np.float64)
    finite = (
        np.isfinite(parameters).all()
        and np.isfinite(gradient).all()
        and math.isfinite(float(result.fun))
    )
    gradient_inf = float(np.max(np.abs(gradient)))
    converged = (
        result.success is True
        and int(result.status) == 0
        and finite
        and gradient_inf
        <= float(FROZEN_CLASSIFIER_CONTRACT["convergence_gradient_inf_max"])
    )
    if not converged:
        raise EvidenceError(
            "frozen ridge logistic failed its fail-closed convergence contract: "
            f"success={result.success}, status={result.status}, finite={finite}, "
            f"gradient_inf={gradient_inf}"
        )
    return {
        "schema": "traps-e9-frozen-ridge-logistic-model-v1",
        "classifier_contract": dict(FROZEN_CLASSIFIER_CONTRACT),
        "feature_count": int(matrix.shape[1]),
        "training_row_count": int(matrix.shape[0]),
        "training_positive_count": int(target.sum()),
        "training_negative_count": int(matrix.shape[0] - target.sum()),
        "training_medians": [float(value) for value in medians],
        "training_iqrs": [float(value) for value in iqrs],
        "training_scales": [float(value) for value in scales],
        "intercept": float(parameters[0]),
        "coefficients": [float(value) for value in parameters[1:]],
        "optimizer_iterations": int(result.nit),
        "optimizer_function_evaluations": int(result.nfev),
        "optimizer_objective": float(result.fun),
        "optimizer_gradient_inf": gradient_inf,
        "optimizer_success": True,
        "optimizer_status": 0,
    }


def score_frozen_ridge_logistic(
    model_value: Mapping[str, object], feature_rows: Sequence[Sequence[float]]
) -> list[float]:
    """Return deterministic linear decision scores for a frozen numeric model."""

    try:
        import numpy as np
    except ImportError as exc:
        raise EvidenceError("scoring the frozen E9 classifier requires NumPy") from exc

    model = _mapping(model_value, "frozen ridge logistic model")
    _exact_keys(
        model,
        {
            "schema",
            "classifier_contract",
            "feature_count",
            "training_row_count",
            "training_positive_count",
            "training_negative_count",
            "training_medians",
            "training_iqrs",
            "training_scales",
            "intercept",
            "coefficients",
            "optimizer_iterations",
            "optimizer_function_evaluations",
            "optimizer_objective",
            "optimizer_gradient_inf",
            "optimizer_success",
            "optimizer_status",
        },
        "frozen ridge logistic model",
    )
    _exact_value(
        model["schema"],
        "traps-e9-frozen-ridge-logistic-model-v1",
        "frozen ridge logistic model schema",
    )
    _exact_value(
        model["classifier_contract"],
        FROZEN_CLASSIFIER_CONTRACT,
        "frozen ridge logistic classifier contract",
    )
    feature_count = _integer(model["feature_count"], "classifier feature count", 1)
    _exact_value(
        feature_count,
        len(CLASSIFIER_FEATURE_NAMES),
        "classifier frozen feature count",
    )
    training_count = _integer(
        model["training_row_count"], "classifier training row count", 2
    )
    training_positive = _integer(
        model["training_positive_count"], "classifier positive training count", 1
    )
    training_negative = _integer(
        model["training_negative_count"], "classifier negative training count", 1
    )
    if training_positive + training_negative != training_count:
        raise EvidenceError("classifier training class counts do not conserve rows")
    _integer(model["optimizer_iterations"], "classifier optimizer iterations")
    _integer(
        model["optimizer_function_evaluations"],
        "classifier optimizer function evaluations",
        1,
    )
    _number(model["optimizer_objective"], "classifier optimizer objective")
    gradient_inf = _number(
        model["optimizer_gradient_inf"], "classifier optimizer gradient infinity norm"
    )
    if gradient_inf > float(
        FROZEN_CLASSIFIER_CONTRACT["convergence_gradient_inf_max"]
    ):
        raise EvidenceError("classifier model exceeds its fail-closed gradient gate")
    _exact_value(model["optimizer_success"], True, "classifier optimizer success")
    _exact_value(model["optimizer_status"], 0, "classifier optimizer status")
    matrix = np.asarray(feature_rows, dtype=np.float64)
    if matrix.ndim != 2 or matrix.shape[1] != feature_count:
        raise EvidenceError("classifier scoring rows differ from the frozen feature width")
    if not np.isfinite(matrix).all():
        raise EvidenceError("classifier scoring features must be finite")
    medians = np.asarray(model["training_medians"], dtype=np.float64)
    iqrs = np.asarray(model["training_iqrs"], dtype=np.float64)
    scales = np.asarray(model["training_scales"], dtype=np.float64)
    coefficients = np.asarray(model["coefficients"], dtype=np.float64)
    if any(
        array.shape != (feature_count,)
        for array in (medians, iqrs, scales, coefficients)
    ):
        raise EvidenceError("frozen classifier parameter vectors have the wrong width")
    if (
        not np.isfinite(medians).all()
        or not np.isfinite(iqrs).all()
        or not np.isfinite(scales).all()
        or not np.isfinite(coefficients).all()
        or np.any(iqrs < 0.0)
        or np.any(scales <= 0.0)
    ):
        raise EvidenceError("frozen classifier parameters must be finite with positive scales")
    intercept = _number(model["intercept"], "classifier intercept", -math.inf)
    scores = intercept + ((matrix - medians) / scales) @ coefficients
    if not np.isfinite(scores).all():
        raise EvidenceError("frozen classifier produced non-finite decision scores")
    return [float(value) for value in scores]


def evaluation_seed_cluster_percentile_ci(
    seed_raw_auc: Sequence[float],
    bootstrap_replicates: int,
    *,
    bootstrap_namespace: str,
) -> dict[str, object]:
    """Compute fixed-direction and seed-calibrated evaluation-seed bounds."""

    values = [float(value) for value in seed_raw_auc]
    if len(values) < 2 or any(
        not math.isfinite(value) or value < 0.0 or value > 1.0 for value in values
    ):
        raise EvidenceError(
            "evaluation-seed classifier CI requires at least two finite raw AUCs in [0, 1]"
        )
    replicates = _integer(
        bootstrap_replicates, "evaluation-seed bootstrap replicates", 1
    )
    namespace = _nonempty_ascii(
        bootstrap_namespace, "evaluation-seed bootstrap namespace", 512
    )
    bootstrap_seed = int.from_bytes(
        hashlib.sha256(
            (
                "E9-FROZEN-CLASSIFIER-EVALUATION-SEED-BOOTSTRAP-v2:"
                + namespace
            ).encode("ascii")
        ).digest()[:8],
        "big",
    )
    rng = random.Random(bootstrap_seed)
    bootstrap_indices = [
        [rng.randrange(len(values)) for _ in values] for _ in range(replicates)
    ]
    raw_bootstraps = [
        sum(values[index] for index in indices) / len(values)
        for indices in bootstrap_indices
    ]
    oracle_values = [max(value, 1.0 - value) for value in values]
    oracle_bootstraps = [
        sum(oracle_values[index] for index in indices) / len(values)
        for indices in bootstrap_indices
    ]
    raw_lower = _percentile(raw_bootstraps, 0.025)
    raw_upper = _percentile(raw_bootstraps, 0.975)
    global_lower = (
        0.5
        if raw_lower <= 0.5 <= raw_upper
        else min(max(raw_lower, 1.0 - raw_lower), max(raw_upper, 1.0 - raw_upper))
    )
    global_upper = max(raw_upper, 1.0 - raw_lower)
    raw_mean = sum(values) / len(values)
    return {
        "bootstrap_seed": bootstrap_seed,
        "bootstrap_replicates": replicates,
        "raw_auc_ci_lower": raw_lower,
        "raw_auc_ci_upper": raw_upper,
        "fixed_classifier_direction_invariant_auc": max(raw_mean, 1.0 - raw_mean),
        "fixed_classifier_direction_invariant_ci_lower": global_lower,
        "fixed_classifier_direction_invariant_ci_upper": global_upper,
        "per_seed_oracle_direction_invariant_auc": sum(oracle_values) / len(oracle_values),
        "per_seed_oracle_ci_lower": _percentile(oracle_bootstraps, 0.025),
        "per_seed_oracle_ci_upper": _percentile(oracle_bootstraps, 0.975),
    }


def _auc(left: Sequence[int], right: Sequence[int]) -> float:
    if not left or not right:
        raise EvidenceError("AUC requires two nonempty classes")
    combined = sorted([(value, 1) for value in left] + [(value, 0) for value in right])
    rank_sum = 0.0
    index = 0
    while index < len(combined):
        end = index + 1
        while end < len(combined) and combined[end][0] == combined[index][0]:
            end += 1
        average_rank = (index + 1 + end) / 2.0
        rank_sum += average_rank * sum(label for _, label in combined[index:end])
        index = end
    return (rank_sum - len(left) * (len(left) + 1) / 2.0) / (len(left) * len(right))


def _ks(left: Sequence[int], right: Sequence[int]) -> float:
    left_ordered = sorted(left)
    right_ordered = sorted(right)
    points = sorted(set(left_ordered) | set(right_ordered))
    left_index = 0
    right_index = 0
    maximum = 0.0
    for point in points:
        while left_index < len(left_ordered) and left_ordered[left_index] <= point:
            left_index += 1
        while right_index < len(right_ordered) and right_ordered[right_index] <= point:
            right_index += 1
        maximum = max(
            maximum,
            abs(left_index / len(left_ordered) - right_index / len(right_ordered)),
        )
    return maximum


def _distribution(values: Sequence[int]) -> dict[str, object]:
    return {
        "count": len(values),
        "minimum": min(values),
        "p50": _percentile(values, 0.50),
        "p95": _percentile(values, 0.95),
        "p99": _percentile(values, 0.99),
        "maximum": max(values),
        "mean": sum(values) / len(values),
    }


def _external_classifier_features(sample: Mapping[str, Any]) -> list[float]:
    """Extract only the preregistered externally observable numeric features."""

    timing = _mapping(sample["timing"], "classifier sample timing")
    response = _mapping(sample["response"], "classifier sample response")
    connection = _mapping(sample["connection"], "classifier sample connection")
    receive_sizes_value = response["receive_call_sizes"]
    if type(receive_sizes_value) is not list or not receive_sizes_value:
        raise EvidenceError("classifier receive-call shape must be a nonempty array")
    receive_sizes = [
        _positive_int(value, "classifier receive-call size")
        for value in receive_sizes_value
    ]
    timing_names = (
        "connect_ns",
        "request_to_first_byte_ns",
        "request_to_eof_ns",
        "connect_start_to_eof_ns",
    )
    row = [
        math.log1p(_positive_int(timing[name], f"classifier {name}"))
        for name in timing_names
    ]
    row.extend(
        [
            float(len(receive_sizes)),
            float(receive_sizes[0]),
            float(receive_sizes[-1]),
            float(min(receive_sizes)),
            float(max(receive_sizes)),
            float(
                sum(
                    (index + 1) * size
                    for index, size in enumerate(receive_sizes)
                )
            ),
            float(_positive_int(connection["local_port"], "classifier local port")),
            float(_positive_int(connection["peer_port"], "classifier peer port")),
        ]
    )
    if len(row) != len(CLASSIFIER_FEATURE_NAMES) or any(
        not math.isfinite(value) for value in row
    ):
        raise EvidenceError("classifier feature extraction violated its frozen schema")
    return row


def _preregistered_pairwise_classifier(
    samples: Sequence[Mapping[str, Any]],
    profile: Mapping[str, Any],
    profile_id: str,
    threshold: float,
    stratum_id: str,
    training_seeds: Sequence[int],
    evaluation_seeds: Sequence[int],
) -> list[dict[str, object]]:
    training = [int(seed) for seed in training_seeds]
    evaluation = [int(seed) for seed in evaluation_seeds]
    if len(training) != 10 or len(evaluation) != 30 or set(training) & set(evaluation):
        raise EvidenceError(
            "v5 classifier requires ten training and thirty disjoint evaluation seeds per KDF"
        )
    rows: list[dict[str, object]] = []
    for left_case, right_case in combinations(FAILURE_CASES, 2):
        training_left = [
            sample
            for sample in samples
            if int(sample["seed"]) in set(training) and sample["case"] == left_case
        ]
        training_right = [
            sample
            for sample in samples
            if int(sample["seed"]) in set(training) and sample["case"] == right_case
        ]
        if not training_left or len(training_left) != len(training_right):
            raise EvidenceError("v5 classifier training classes are empty or unbalanced")
        training_features = [
            _external_classifier_features(sample)
            for sample in (*training_left, *training_right)
        ]
        labels = [1] * len(training_left) + [0] * len(training_right)
        model = fit_frozen_ridge_logistic(training_features, labels)

        seed_raw_auc: list[float] = []
        evaluation_sample_count_per_case: list[int] = []
        for seed in evaluation:
            left_rows = [
                sample
                for sample in samples
                if int(sample["seed"]) == seed and sample["case"] == left_case
            ]
            right_rows = [
                sample
                for sample in samples
                if int(sample["seed"]) == seed and sample["case"] == right_case
            ]
            if not left_rows or len(left_rows) != len(right_rows):
                raise EvidenceError("v5 classifier evaluation classes are empty or unbalanced")
            left_scores = score_frozen_ridge_logistic(
                model, [_external_classifier_features(sample) for sample in left_rows]
            )
            right_scores = score_frozen_ridge_logistic(
                model, [_external_classifier_features(sample) for sample in right_rows]
            )
            raw_auc = _auc(left_scores, right_scores)
            seed_raw_auc.append(raw_auc)
            evaluation_sample_count_per_case.append(len(left_rows))

        interval = evaluation_seed_cluster_percentile_ci(
            seed_raw_auc,
            int(profile["bootstrap_replicates"]),
            bootstrap_namespace=(
                f"{profile_id}:{stratum_id}:{left_case}:{right_case}"
            ),
        )
        fixed_lower = float(interval["fixed_classifier_direction_invariant_ci_lower"])
        fixed_upper = float(interval["fixed_classifier_direction_invariant_ci_upper"])
        oracle_lower = float(interval["per_seed_oracle_ci_lower"])
        oracle_upper = float(interval["per_seed_oracle_ci_upper"])
        ci_lower = min(fixed_lower, oracle_lower)
        ci_upper = max(fixed_upper, oracle_upper)
        rows.append(
            {
                "left_case": left_case,
                "right_case": right_case,
                "training_seeds": training,
                "evaluation_seeds": evaluation,
                "training_sample_count_per_case": len(training_left),
                "evaluation_sample_count_per_case_by_seed": (
                    evaluation_sample_count_per_case
                ),
                "model": model,
                "seed_raw_auc": seed_raw_auc,
                "seed_direction_invariant_auc": [
                    max(value, 1.0 - value) for value in seed_raw_auc
                ],
                "direction_invariant_auc": interval[
                    "fixed_classifier_direction_invariant_auc"
                ],
                "fixed_classifier_direction_invariant_auc": interval[
                    "fixed_classifier_direction_invariant_auc"
                ],
                "raw_auc_ci_lower": interval["raw_auc_ci_lower"],
                "raw_auc_ci_upper": interval["raw_auc_ci_upper"],
                "fixed_classifier_direction_invariant_ci_lower": fixed_lower,
                "fixed_classifier_direction_invariant_ci_upper": fixed_upper,
                "per_seed_oracle_direction_invariant_auc": interval[
                    "per_seed_oracle_direction_invariant_auc"
                ],
                "per_seed_oracle_ci_lower": oracle_lower,
                "per_seed_oracle_ci_upper": oracle_upper,
                "ci_confidence_level": 0.95,
                "ci_method": "evaluation-seed-cluster-percentile-bootstrap",
                "bootstrap_seed": interval["bootstrap_seed"],
                "bootstrap_replicates": interval["bootstrap_replicates"],
                "ci_lower": ci_lower,
                "ci_upper": ci_upper,
                "ci_upper_within_threshold": (
                    fixed_upper <= threshold and oracle_upper <= threshold
                ),
            }
        )
    return rows


def _pairwise_timing(
    samples: Sequence[Mapping[str, Any]],
    profile: Mapping[str, Any],
    profile_id: str,
    threshold: float,
    *,
    seeds: Sequence[int] | None = None,
    bootstrap_namespace: str = "combined",
) -> list[dict[str, object]]:
    selected_seeds = [int(seed) for seed in (profile["seeds"] if seeds is None else seeds)]
    selected_set = set(selected_seeds)
    by_seed_case: dict[tuple[int, str], list[int]] = {}
    pooled: dict[str, list[int]] = {case: [] for case in FAILURE_CASES}
    for sample in samples:
        case = str(sample["case"])
        if case not in FAILURE_CASES or int(sample["seed"]) not in selected_set:
            continue
        value = int(sample["timing"]["request_to_eof_ns"])
        pooled[case].append(value)
        by_seed_case.setdefault((int(sample["seed"]), case), []).append(value)
    rows = []
    for left_case, right_case in combinations(FAILURE_CASES, 2):
        seed_aucs = [
            _auc(by_seed_case[(seed, left_case)], by_seed_case[(seed, right_case)])
            for seed in selected_seeds
        ]
        seed_ks = [
            _ks(by_seed_case[(seed, left_case)], by_seed_case[(seed, right_case)])
            for seed in selected_seeds
        ]
        seed_cliffs = [2.0 * value - 1.0 for value in seed_aucs]
        seed_oriented_aucs = [max(value, 1.0 - value) for value in seed_aucs]
        seed_absolute_cliffs = [abs(value) for value in seed_cliffs]
        raw_auc = sum(seed_aucs) / len(seed_aucs)
        oriented_auc = sum(seed_oriented_aucs) / len(seed_oriented_aucs)
        bootstrap_seed = int.from_bytes(
            hashlib.sha256(
                f"E9-BOOTSTRAP-v1:{profile_id}:{bootstrap_namespace}:{left_case}:{right_case}".encode(
                    "ascii"
                )
            ).digest()[:8],
            "big",
        )
        rng = random.Random(bootstrap_seed)
        bootstraps: list[float] = []
        for _ in range(int(profile["bootstrap_replicates"])):
            resampled = [
                seed_oriented_aucs[rng.randrange(len(seed_oriented_aucs))]
                for _ in seed_oriented_aucs
            ]
            bootstraps.append(sum(resampled) / len(resampled))
        pooled_raw = _auc(pooled[left_case], pooled[right_case])
        ci_lower = _percentile(bootstraps, 0.025)
        ci_upper = _percentile(bootstraps, 0.975)
        rows.append(
            {
                "left_case": left_case,
                "right_case": right_case,
                "samples_per_case": len(pooled[left_case]),
                "seed_count": len(selected_seeds),
                "seed_raw_auc": seed_aucs,
                "macro_raw_auc_directional_diagnostic": raw_auc,
                "seed_direction_invariant_auc": seed_oriented_aucs,
                "direction_invariant_auc": oriented_auc,
                "pooled_raw_auc_diagnostic": pooled_raw,
                "ci_confidence_level": 0.95,
                "ci_method": "paired-seed-percentile-bootstrap",
                "bootstrap_replicates": int(profile["bootstrap_replicates"]),
                "ci_lower": ci_lower,
                "ci_upper": ci_upper,
                "ci_upper_within_threshold": ci_upper <= threshold,
                "seed_ks_statistic": seed_ks,
                "macro_ks_statistic": sum(seed_ks) / len(seed_ks),
                "seed_cliffs_delta": seed_cliffs,
                "macro_cliffs_delta_directional_diagnostic": sum(seed_cliffs) / len(seed_cliffs),
                "seed_absolute_cliffs_delta": seed_absolute_cliffs,
                "mean_seed_absolute_cliffs_delta": sum(seed_absolute_cliffs)
                / len(seed_absolute_cliffs),
                "pooled_diagnostics": {
                    "estimand": "POOLED_SAMPLE_DIAGNOSTIC_NOT_PRIMARY_SEED_CLUSTER_ESTIMAND",
                    "raw_auc": pooled_raw,
                    "ks_statistic": _ks(pooled[left_case], pooled[right_case]),
                    "cliffs_delta": 2.0 * pooled_raw - 1.0,
                    "absolute_cliffs_delta": abs(2.0 * pooled_raw - 1.0),
                },
            }
        )
    return rows


def _resource_analysis_group(samples: Sequence[Mapping[str, Any]]) -> dict[str, object]:
    by_case: dict[str, list[Mapping[str, Any]]] = {case: [] for case in ALL_CASES}
    for sample in samples:
        by_case[str(sample["case"])].append(sample)
    metrics = (
        "auth_worker_cpu_ns",
        "auth_worker_wall_ns",
        "backend_cpu_ns",
        "backend_wall_ns",
        "padding_actual_wait_ns",
    )
    summaries: dict[str, object] = {}
    for case in ALL_CASES:
        rows = by_case[case]
        summaries[case] = {
            "backend_calls": sum(int(row["server_resource"]["backend_calls"]) for row in rows),
            "kdf_calls": sum(int(row["server_resource"]["kdf_calls"]) for row in rows),
            "cache_hits": sum(int(row["server_resource"]["cache_hits"]) for row in rows),
            "padding_scheduled_async": sum(
                bool(row["server_resource"]["padding_scheduled_async"]) for row in rows
            ),
            "distributions": {
                metric: _distribution([int(row["server_resource"][metric]) for row in rows])
                for metric in metrics
            },
        }
    pairwise = []
    for metric in (
        "auth_worker_cpu_ns",
        "auth_worker_wall_ns",
        "backend_cpu_ns",
        "backend_wall_ns",
    ):
        for left_case, right_case in combinations(FAILURE_CASES, 2):
            left = [int(row["server_resource"][metric]) for row in by_case[left_case]]
            right = [int(row["server_resource"][metric]) for row in by_case[right_case]]
            raw_auc = _auc(left, right)
            pairwise.append(
                {
                    "metric": metric,
                    "left_case": left_case,
                    "right_case": right_case,
                    "raw_auc": raw_auc,
                    "direction_invariant_auc": max(raw_auc, 1.0 - raw_auc),
                    "ks_statistic": _ks(left, right),
                    "cliffs_delta": 2.0 * raw_auc - 1.0,
                    "absolute_cliffs_delta": abs(2.0 * raw_auc - 1.0),
                }
            )
    return {"by_case": summaries, "pairwise_effects": pairwise}


def _resource_analysis(
    samples: Sequence[Mapping[str, Any]], profile: Mapping[str, Any]
) -> dict[str, object]:
    by_workload: list[dict[str, object]] = []
    for workload_value in profile["kdf_workloads"]:
        workload = _mapping(workload_value, "KDF workload")
        selected = [
            sample
            for sample in samples
            if sample["server_resource"]["kdf_workload"] == workload
        ]
        if not selected:
            raise EvidenceError("resource analysis KDF stratum is empty")
        by_workload.append(
            {
                "workload": dict(workload),
                "workload_id": _identity(workload),
                "seed_count": len({int(sample["seed"]) for sample in selected}),
                "sample_count": len(selected),
                "analysis": _resource_analysis_group(selected),
            }
        )
    return {
        "primary_by_kdf_workload": by_workload,
        "pooled_diagnostic": _resource_analysis_group(samples),
        "pooled_role": "DESCRIPTIVE_ONLY_MIXED_KDF_RESOURCE_DIAGNOSTIC",
    }


def _delivery_metadata(samples: Sequence[Mapping[str, Any]]) -> dict[str, object]:
    by_case: dict[str, object] = {}
    for case in ALL_CASES:
        rows = [sample for sample in samples if sample["case"] == case]
        call_counts = [len(sample["response"]["receive_call_sizes"]) for sample in rows]
        shapes = {
            tuple(int(size) for size in sample["response"]["receive_call_sizes"]) for sample in rows
        }
        by_case[case] = {
            "receive_call_count": _distribution(call_counts),
            "unique_receive_chunk_shapes": len(shapes),
            "receive_chunk_shapes": [list(shape) for shape in sorted(shapes)],
            "unique_local_ports": len({int(sample["connection"]["local_port"]) for sample in rows}),
            "peer_port_count": len({int(sample["connection"]["peer_port"]) for sample in rows}),
        }
    return {
        "note": (
            "TCP receive-call chunking is recorded as delivery metadata; "
            "application frame order is independently fixed and validated"
        ),
        "by_case": by_case,
    }


def _formal_criterion_is_eligible(
    profile_name: str,
    profile_enabled: object,
    criterion_met: bool,
    formal_readiness_blockers: Sequence[object],
) -> bool:
    return (
        profile_name == "formal"
        and profile_enabled is True
        and criterion_met
        and not formal_readiness_blockers
    )


def build_analysis(
    raw_artifact: Mapping[str, Any],
    config: Mapping[str, Any],
    config_id: str,
    profile_name: str,
    *,
    auditor_root_public_key_hex: str | None = None,
    verification_replay_registry: Path | None = None,
    register_replay: bool = True,
) -> dict[str, object]:
    raw = validate_raw(
        raw_artifact,
        config,
        config_id,
        profile_name,
        auditor_root_public_key_hex=auditor_root_public_key_hex,
        verification_replay_registry=verification_replay_registry,
        register_replay=register_replay,
    )
    profile, profile_id = profile_contract(config, profile_name)
    samples = raw["samples"]
    failure_samples = [sample for sample in samples if sample["case"] in FAILURE_CASES]
    functional_samples = [sample for sample in samples if sample["case"] in FUNCTIONAL_CASES]
    timing_by_case = {
        case: {
            metric: _distribution(
                [int(sample["timing"][metric]) for sample in samples if sample["case"] == case]
            )
            for metric in (
                "connect_ns",
                "request_to_first_byte_ns",
                "request_to_eof_ns",
                "connect_start_to_eof_ns",
            )
        }
        for case in ALL_CASES
    }
    threshold = float(config["statistics"]["failure_auc_ci_upper_threshold"])
    preregistered_classifier = (
        _is_preregistered_clean_run(config) and profile_name == "formal"
    )
    combined_pairwise = _pairwise_timing(samples, profile, profile_id, threshold)
    failure_signatures = {
        _identity(
            {
                "status": sample["response"]["status"],
                "bytes": sample["response"]["bytes"],
                "sha256": sample["response"]["sha256"],
                "frame_order": sample["response"]["frame_order"],
                "frame_count": sample["response"]["frame_count"],
                "client_observed_eof": sample["response"]["client_observed_eof"],
                "transport": sample["connection"]["transport"],
                "address_family": sample["connection"]["address_family"],
                "socket_type": sample["connection"]["socket_type"],
                "protocol": sample["connection"]["protocol"],
                "local_is_loopback": sample["connection"]["local_is_loopback"],
                "peer_is_loopback": sample["connection"]["peer_is_loopback"],
                "client_tcp_nodelay": sample["connection"]["client_tcp_nodelay"],
                "client_half_closed_write": sample["connection"][
                    "client_half_closed_write"
                ],
                "connection_reused": sample["connection"]["connection_reused"],
                "server_observed_client_eof": sample["server_resource"][
                    "server_observed_client_eof"
                ],
                "server_tcp_nodelay": sample["server_resource"]["server_tcp_nodelay"],
                "server_shutdown_write": sample["server_resource"]["server_shutdown_write"],
            }
        )
        for sample in failure_samples
    }
    if preregistered_classifier and len(failure_signatures) != 1:
        raise EvidenceError(
            "v5 classifier exact outward-response/TCP equivalence gate failed closed"
        )
    primary_strata: list[dict[str, object]] = []
    secondary_strata: list[dict[str, object]] = []
    if preregistered_classifier:
        split = _mapping(profile["seed_split"], "v5 frozen seed split")
        training_by_kdf = _mapping(
            split["training_seeds_by_kdf"], "v5 training seeds by KDF"
        )
        evaluation_by_kdf = _mapping(
            split["evaluation_seeds_by_kdf"], "v5 evaluation seeds by KDF"
        )
        workload_contracts = _mapping(
            profile["kdf_workload_contracts"], "v5 KDF workload contracts"
        )
        for stratum_id in PREREGISTERED_KDF_STRATUM_IDS:
            training_seeds = list(training_by_kdf[stratum_id])
            evaluation_seeds = list(evaluation_by_kdf[stratum_id])
            workload = workload_contracts[stratum_id]
            rows = _preregistered_pairwise_classifier(
                samples,
                profile,
                profile_id,
                threshold,
                stratum_id,
                training_seeds,
                evaluation_seeds,
            )
            secondary_rows = _pairwise_timing(
                samples,
                profile,
                profile_id,
                threshold,
                seeds=evaluation_seeds,
                bootstrap_namespace=f"secondary:{stratum_id}",
            )
            primary_strata.append(
                {
                    "stratum_id": stratum_id,
                    "kdf_workload": workload,
                    "training_seeds": training_seeds,
                    "training_seed_count": len(training_seeds),
                    "evaluation_seeds": evaluation_seeds,
                    "evaluation_seed_count": len(evaluation_seeds),
                    "failure_pairwise_classifier": rows,
                    "maximum_failure_auc_ci_upper": max(
                        float(row["ci_upper"]) for row in rows
                    ),
                    "all_pairs_within_threshold": all(
                        row["ci_upper_within_threshold"] is True for row in rows
                    ),
                }
            )
            secondary_strata.append(
                {
                    "stratum_id": stratum_id,
                    "kdf_workload": workload,
                    "evaluation_seeds": evaluation_seeds,
                    "failure_pairwise_request_to_eof": secondary_rows,
                    "role": "SECONDARY_DIAGNOSTIC_NOT_USED_FOR_FORMAL_CRITERION",
                }
            )
    else:
        workloads = list(profile["kdf_workloads"])
        for workload_index, workload in enumerate(workloads):
            stratum_seeds = [
                int(seed)
                for index, seed in enumerate(profile["seeds"])
                if index % len(workloads) == workload_index
            ]
            if profile_name == "formal" and len(stratum_seeds) < 10:
                raise EvidenceError(
                    "each formal verifier-profile stratum requires at least ten seeds"
                )
            stratum_id = f"{workload['algorithm']}:{_identity(workload)[:16]}"
            rows = _pairwise_timing(
                samples,
                profile,
                profile_id,
                threshold,
                seeds=stratum_seeds,
                bootstrap_namespace=stratum_id,
            )
            primary_strata.append(
                {
                    "stratum_id": stratum_id,
                    "kdf_workload": workload,
                    "seeds": stratum_seeds,
                    "seed_count": len(stratum_seeds),
                    "failure_pairwise_timing": rows,
                    "maximum_failure_auc_ci_upper": max(
                        float(row["ci_upper"]) for row in rows
                    ),
                    "all_pairs_within_threshold": all(
                        row["ci_upper_within_threshold"] is True for row in rows
                    ),
                }
            )
    maximum_upper = max(
        float(stratum["maximum_failure_auc_ci_upper"]) for stratum in primary_strata
    )
    functional_successes = sum(
        sample["response"]["status"] == VALID_STATUS
        and sample["server_resource"]["accepted"] is True
        and sample["server_resource"]["route"] == AuthRoute.BACKEND_MATCH.value
        for sample in functional_samples
    )
    padding_isolation_failures = sum(
        sample["server_resource"]["padding_used_auth_worker"] is not False
        or sample["server_resource"]["auth_worker_released_before_padding"] is not True
        for sample in samples
    )
    early_release_count = sum(
        int(sample["server_resource"]["response_send_started_monotonic_ns"])
        < int(sample["server_resource"]["padding_deadline_monotonic_ns"])
        for sample in samples
    )
    criterion_met = (
        all(stratum["all_pairs_within_threshold"] is True for stratum in primary_strata)
        and len(failure_signatures) == 1
        and early_release_count == 0
    )
    failed_kdf_pairs: list[dict[str, object]] = []
    pair_key = (
        "failure_pairwise_classifier"
        if preregistered_classifier
        else "failure_pairwise_timing"
    )
    for stratum in primary_strata:
        for row in stratum[pair_key]:  # type: ignore[index]
            if row["ci_upper_within_threshold"] is not True:
                failed_kdf_pairs.append(
                    {
                        "stratum_id": stratum["stratum_id"],
                        "left_case": row["left_case"],
                        "right_case": row["right_case"],
                        "ci_lower": row["ci_lower"],
                        "ci_upper": row["ci_upper"],
                        "threshold": threshold,
                    }
                )
    formal_readiness_blockers = (
        []
        if profile_name == "smoke"
        else list(
            _mapping(raw["formal_execution"], "formal execution")[
                "formal_readiness_blockers"
            ]
        )
    )
    body: dict[str, object] = {
        "schema": ANALYSIS_SCHEMA,
        "experiment_id": config["experiment_id"],
        "config_id": config_id,
        "profile": profile_name,
        "profile_id": profile_id,
        "raw_id": raw["raw_id"],
        "classifier_contract": (
            {
                "positive_or_negative_class_assignment": "PAIR_ORDER_ONLY",
                "population": list(FAILURE_CASES),
                "excluded": list(FUNCTIONAL_CASES),
                "numeric_classifier": dict(FROZEN_CLASSIFIER_CONTRACT),
                "feature_source": (
                    "EXTERNAL_TIMING_CLIENT_RECV_CHUNK_SUMMARY_AND_SOCKET_PORTS_ONLY"
                ),
                "prohibited_features": [
                    "case",
                    "seed",
                    "schedule_index",
                    "case_ordinal",
                    "request_content_or_hash",
                    "server_resource",
                ],
                "primary_estimand": "MAX_MEAN_RAW_AUC_ONE_MINUS_MEAN_RAW_AUC",
                "direction_invariant_ci_upper": (
                    "MAX_RAW_CI_UPPER_ONE_MINUS_RAW_CI_LOWER"
                ),
                "per_seed_oracle_orientation_sensitivity": (
                    "FAIL_CLOSED_ADDITIONAL_GATE_NOT_PRIMARY_ESTIMAND"
                ),
                "gate_rule": "GLOBAL_AND_PER_SEED_ORACLE_CI_UPPERS_LE_THRESHOLD",
                "cluster_unit": "evaluation seed fresh OS process",
                "process_isolation": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_REUSE",
                "primary_stratification": "KDF_WORKLOAD_VERIFIER_PROFILE",
                "seed_split": profile["seed_split"],
                "fit_order": "ALL_TRAINING_SEEDS_BEFORE_ANY_EVALUATION_SEED",
                "exact_equivalence_gate": (
                    "RESPONSE_SIZE_HASH_FRAME_ORDER_EOF_AND_TCP_BEHAVIOR"
                ),
            }
            if preregistered_classifier
            else {
                "positive_or_negative_class_assignment": "PAIR_ORDER_ONLY",
                "population": list(FAILURE_CASES),
                "excluded": list(FUNCTIONAL_CASES),
                "primary_metric": "request_to_eof_ns",
                "orientation": "max(AUC,1-AUC)",
                "cluster_unit": "fresh-OS-process-per-seed temporal cluster",
                "process_isolation": "FRESH_OS_PROCESS_PER_SEED_SERIAL_NO_REUSE",
                "primary_stratification": "KDF_WORKLOAD_VERIFIER_PROFILE",
            }
        ),
        "denominators": {
            "total_samples": len(samples),
            "failure_samples": len(failure_samples),
            "functional_samples": len(functional_samples),
            "samples_per_case": int(profile["samples_per_case_per_seed"]) * len(profile["seeds"]),
            "failure_pair_count_per_stratum": len(combined_pairwise),
            "primary_stratum_count": len(primary_strata),
        },
        "outward_equivalence": {
            "failure_signature_count": len(failure_signatures),
            "identical_status_size_order_connection_behavior": len(failure_signatures) == 1,
            "failure_status": FAILURE_STATUS,
            "failure_response_bytes": len(FAILURE_RESPONSE),
            "failure_response_sha256": hashlib.sha256(FAILURE_RESPONSE).hexdigest(),
            "failure_frame_order": ["status", "body", "end"],
            "connection_behavior": "ONE_REQUEST_CLIENT_HALF_CLOSE_SERVER_EOF_NO_REUSE",
        },
        "external_delivery_metadata": _delivery_metadata(samples),
        "timing_distributions": timing_by_case,
        "secondary_combined_failure_pairwise_timing": combined_pairwise,
        "secondary_combined_role": "DESCRIPTIVE_ONLY_NOT_USED_FOR_FORMAL_CRITERION",
        "maximum_failure_auc_ci_upper": maximum_upper,
        "failure_auc_ci_upper_threshold": threshold,
        "formal_criterion_rule": (
            "FROZEN_CLASSIFIER_ALL_KDF_STRATA_AND_ALL_FAILURE_PAIRS_MUST_PASS"
            if preregistered_classifier
            else "ALL_KDF_STRATA_AND_ALL_FAILURE_PAIRS_MUST_PASS"
        ),
        "timing_conclusion": (
            "SMOKE_DIAGNOSTIC_ONLY_NO_E9_CONCLUSION"
            if profile_name == "smoke"
            else (
                (
                    "FROZEN_CLASSIFIER_BOUND_MET_PENDING_INDEPENDENT_AUDIT"
                    if criterion_met
                    else "FROZEN_CLASSIFIER_LEAKAGE_DETECTED_OR_NOT_RULED_OUT"
                )
                if preregistered_classifier
                else (
                (
                    "E9_FAILURE_TIMING_DIAGNOSTIC_WITHIN_0_55_WITH_UNRESOLVED_GATES"
                    if formal_readiness_blockers
                    else "E9_FAILURE_TIMING_WITHIN_0_55_FORMAL_CRITERION_ELIGIBLE"
                )
                if criterion_met
                else "LEAKAGE_DETECTED_OR_NOT_RULED_OUT"
                )
            )
        ),
        "claim_disposition": (
            "SMOKE_ONLY_NO_SECURITY_OR_GATE_CLAIM"
            if profile_name == "smoke"
            else (
                (
                    "BOUND_MET_PENDING_AUDIT"
                    if criterion_met
                    else "LEAKAGE_DOCUMENTATION_AND_CLAIM_NARROWING_REQUIRED"
                )
                if preregistered_classifier
                else (
                (
                    "E9_TIMING_DIAGNOSTIC_BLOCKED_BY_REMAINING_GATES_G7_NOT_CLAIMED"
                    if formal_readiness_blockers
                    else "E9_TIMING_CRITERION_ELIGIBLE_G7_NOT_CLAIMED"
                )
                if criterion_met
                else "TIMING_LEAKAGE_MUST_BE_DOCUMENTED_AND_CLAIM_NARROWED"
                )
            )
        ),
        "disposition": {
            "status": (
                "NOT_APPLICABLE_SMOKE"
                if profile_name == "smoke"
                else (
                    "BOUND_MET_PENDING_AUDIT"
                    if criterion_met
                    else "LEAKAGE_DOCUMENTATION_AND_CLAIM_NARROWING_REQUIRED"
                )
            ),
            "failed_kdf_pairs": failed_kdf_pairs,
            "independent_post_audit_required": profile_name == "formal",
            "g7_pass_claimed": False,
        },
        "resource_side": _resource_analysis(samples, profile),
        "padding_audit": {
            "mechanism": "threading.Timer",
            "auth_worker_overlap_failures": padding_isolation_failures,
            "capacity_overflow_failures": raw["runtime"]["padding"]["overflow_failures"],
            "scheduled_async": raw["runtime"]["padding"]["scheduled_async"],
            "immediate_after_slow_auth": raw["runtime"]["padding"]["immediate_after_slow_auth"],
            "worker_isolation_verified": padding_isolation_failures == 0,
            "early_release_count": early_release_count,
            "minimum_padding_deadline_verified": early_release_count == 0,
            "stress_audit": raw["runtime"]["stress_audit"],
        },
        "functional_check": {
            "sample_count": len(functional_samples),
            "accepted_count": functional_successes,
            "all_valid_credentials_accepted": functional_successes == len(functional_samples),
            "included_in_failure_auc": False,
        },
        "formal_criterion_eligible": _formal_criterion_is_eligible(
            profile_name,
            profile["enabled"],
            criterion_met,
            formal_readiness_blockers,
        ),
        "analysis_status": "ANALYSIS_COMPLETE",
        "g7_status": "NOT_CLAIMED_E9_ONLY_REQUIRES_ALL_G7_EVIDENCE",
    }
    if preregistered_classifier:
        body["primary_stratified_failure_classifier"] = primary_strata
        body["secondary_stratified_request_to_eof"] = secondary_strata
    else:
        body["primary_stratified_failure_timing"] = primary_strata
    if profile_name == "formal":
        body["formal_readiness_blockers"] = formal_readiness_blockers
    return {**body, "analysis_id": _identity(body)}


def validate_analysis(
    analysis: object,
    raw_artifact: Mapping[str, Any],
    config: Mapping[str, Any],
    config_id: str,
    profile_name: str,
    *,
    auditor_root_public_key_hex: str | None = None,
    verification_replay_registry: Path | None = None,
    register_replay: bool = True,
) -> dict[str, Any]:
    value = _mapping(analysis, "E9 analysis artifact")
    expected = build_analysis(
        raw_artifact,
        config,
        config_id,
        profile_name,
        auditor_root_public_key_hex=auditor_root_public_key_hex,
        verification_replay_registry=verification_replay_registry,
        register_replay=register_replay,
    )
    _exact_value(value, expected, "E9 analysis artifact")
    return value


@dataclass
class _ProcessLongTestPublicationTarget:
    path: Path
    parent: _PinnedDirectory
    name: str

    def close(self) -> None:
        self.parent.close()


def _process_long_test_temporary_prefix(name: str) -> str:
    name_id = hashlib.sha256(os.fsencode(name)).hexdigest()[:16]
    return f".e9-process-long-test-{name_id}-"


def _preflight_process_long_test_output(path: Path) -> _ProcessLongTestPublicationTarget:
    if not path.name:
        raise EvidenceError("process long-test receipt output must name a file")
    parent = _pin_directory(path.parent, "process long-test receipt output parent")
    resolved_path = parent.resolved_path / path.name
    if resolved_path.exists() or _is_link_or_junction(resolved_path):
        parent.close()
        raise FileExistsError(
            f"process long-test receipt output already exists: {resolved_path}"
        )
    temporary_prefix = _process_long_test_temporary_prefix(path.name)
    try:
        blocking_temporaries = [
            child.name
            for child in parent.resolved_path.iterdir()
            if child.name.startswith(temporary_prefix) and child.name.endswith(".tmp")
        ]
    except OSError:
        parent.close()
        raise
    if blocking_temporaries:
        parent.close()
        raise EvidenceError(
            "process long-test receipt has a retained failed-publication temporary; "
            "independent disposition is required before rerun"
        )
    return _ProcessLongTestPublicationTarget(resolved_path, parent, path.name)


def _rename_process_long_test_output_no_replace(
    target: _ProcessLongTestPublicationTarget,
    temporary_name: str,
) -> None:
    if platform.system() != "Linux" or os.name != "posix":
        raise EvidenceError("process long-test atomic publication requires Linux")
    target.parent.verify("process long-test receipt output parent")
    if target.parent.descriptor is None:
        raise EvidenceError("process long-test atomic publication requires an anchored directory")
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise EvidenceError("Linux renameat2 is unavailable for no-replace publication")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        target.parent.descriptor,
        os.fsencode(temporary_name),
        target.parent.descriptor,
        os.fsencode(target.name),
        1,  # RENAME_NOREPLACE
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number == errno.EEXIST:
        raise FileExistsError(error_number, os.strerror(error_number), target.path)
    raise OSError(error_number, os.strerror(error_number), target.path)


def _write_process_long_test_receipt_exclusive(
    target: _ProcessLongTestPublicationTarget,
    receipt: Mapping[str, Any],
) -> None:
    payload = _canonical(receipt) + b"\n"
    temporary_name = (
        f"{_process_long_test_temporary_prefix(target.name)}{secrets.token_hex(16)}.tmp"
    )
    descriptor: int | None = None
    identity: os.stat_result | None = None
    try:
        target.parent.verify("process long-test receipt output parent")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        if target.parent.descriptor is not None and os.open in os.supports_dir_fd:
            descriptor = os.open(
                temporary_name,
                flags,
                0o600,
                dir_fd=target.parent.descriptor,
            )
        else:
            descriptor = os.open(
                target.parent.resolved_path / temporary_name,
                flags,
                0o600,
            )
        identity = os.fstat(descriptor)
        _verify_open_child(
            target.parent,
            temporary_name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            "process long-test temporary receipt output",
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("process long-test receipt publication made no write progress")
            offset += written
        os.fsync(descriptor)
        if target.parent.descriptor is not None:
            os.fsync(target.parent.descriptor)
        _rename_process_long_test_output_no_replace(target, temporary_name)
        _verify_open_child(
            target.parent,
            target.name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            "process long-test receipt output",
        )
        if target.parent.descriptor is not None:
            os.fsync(target.parent.descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def publish_linux_process_long_test(
    config: Mapping[str, Any],
    config_id: str,
    output_path: Path,
) -> dict[str, Any]:
    if platform.system() != "Linux":
        raise RuntimeError("the E9 process long test is Linux-only")
    target = _preflight_process_long_test_output(output_path)
    try:
        receipt = run_linux_process_long_test(config, config_id)
        validate_process_long_test_receipt(receipt, config, config_id)
        _write_process_long_test_receipt_exclusive(target, receipt)
        return receipt
    finally:
        target.close()


@dataclass
class _FormalPublicationTarget:
    path: Path
    parent: _PinnedDirectory
    name: str

    def close(self) -> None:
        self.parent.close()


def _preflight_formal_raw_output(path: Path) -> _FormalPublicationTarget:
    if not path.name:
        raise EvidenceError("formal raw output must name a file")
    parent = _pin_directory(path.parent, "formal raw output parent")
    resolved_path = parent.resolved_path / path.name
    if resolved_path.exists() or _is_link_or_junction(resolved_path):
        parent.close()
        raise FileExistsError(f"formal raw output already exists: {resolved_path}")
    return _FormalPublicationTarget(resolved_path, parent, path.name)


def _write_json_exclusive(target: _FormalPublicationTarget, value: object) -> None:
    """Publish formal raw bytes once; a partial crash artifact intentionally blocks reuse."""
    payload = (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    try:
        descriptor, identity = _open_exclusive_child(
            target.parent, target.name, "formal raw output"
        )
    except FileExistsError as exc:
        raise FileExistsError(
            f"formal raw output appeared during publication: {target.path}"
        ) from exc
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("formal raw publication made no write progress")
            offset += written
        os.fsync(descriptor)
        if target.parent.descriptor is not None:
            os.fsync(target.parent.descriptor)
        _verify_open_child(
            target.parent,
            target.name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            "formal raw output",
        )
    finally:
        os.close(descriptor)


def _write_json(path: Path, value: object, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    collect = subparsers.add_parser("collect")
    collect.add_argument("--config", type=Path, required=True)
    collect.add_argument("--profile", choices=("smoke", "formal"), default="smoke")
    collect.add_argument("--raw-output", type=Path, required=True)
    collect.add_argument("--signing-key", type=Path)
    collect.add_argument("--formal-manifest", type=Path)
    collect.add_argument("--freshness-challenge", type=Path)
    collect.add_argument("--auditor-root-public-key-hex")
    collect.add_argument("--collection-replay-registry", type=Path)
    collect.add_argument(
        "--assert-exclusive-host",
        action="store_true",
        help="self-report exclusive use of the host for a v5 preregistered formal run",
    )
    collect.add_argument(
        "--assert-services-quiesced",
        action="store_true",
        help="self-report that unrelated services were quiesced before a v5 formal run",
    )
    collect.add_argument("--overwrite", action="store_true")
    analyze = subparsers.add_parser("analyze")
    analyze.add_argument("--config", type=Path, required=True)
    analyze.add_argument("--profile", choices=("smoke", "formal"), default="smoke")
    analyze.add_argument("--raw-input", type=Path, required=True)
    analyze.add_argument("--output", type=Path, required=True)
    analyze.add_argument("--overwrite", action="store_true")
    analyze.add_argument("--auditor-root-public-key-hex")
    analyze.add_argument("--verification-replay-registry", type=Path)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--config", type=Path, required=True)
    validate.add_argument("--profile", choices=("smoke", "formal"), default="smoke")
    validate.add_argument("--raw-input", type=Path, required=True)
    validate.add_argument("--analysis-input", type=Path, required=True)
    validate.add_argument("--auditor-root-public-key-hex")
    validate.add_argument("--verification-replay-registry", type=Path)
    process_long_test = subparsers.add_parser("linux-process-long-test")
    process_long_test.add_argument("--config", type=Path, required=True)
    process_long_test.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    if sys.argv[1:] == ["_seed-child"]:
        return _seed_child_main()
    args = _parse_args()
    if args.command == "linux-process-long-test":
        config, config_id = load_process_long_test_config(args.config)
        receipt = publish_linux_process_long_test(config, config_id, args.output)
        print(
            json.dumps(
                {
                    "status": receipt["status"],
                    "evidence_class": receipt["evidence_class"],
                    "formal_claim_eligible": receipt["formal_claim_eligible"],
                    "review_status": receipt["review_status"],
                    "children": receipt["counts"]["seed_count"],
                    "measured_requests": receipt["counts"]["measured_requests"],
                    "receipt_id": receipt["receipt_id"],
                },
                sort_keys=True,
            )
        )
        return 0
    config, config_id = load_config(args.config)
    if args.command == "collect":
        raw = collect_raw(
            config,
            config_id,
            args.profile,
            signing_key_path=args.signing_key,
            manifest_path=args.formal_manifest,
            challenge_path=args.freshness_challenge,
            auditor_root_public_key_hex=args.auditor_root_public_key_hex,
            collection_replay_registry=args.collection_replay_registry,
            raw_output_path=args.raw_output,
            overwrite=args.overwrite,
            exclusive_host_asserted=args.assert_exclusive_host,
            services_quiesced_asserted=args.assert_services_quiesced,
        )
        print(
            json.dumps(
                {
                    "status": raw["status"],
                    "profile": args.profile,
                    "samples": len(raw["samples"]),
                    "raw_id": raw["raw_id"],
                },
                sort_keys=True,
            )
        )
        return 0
    raw = load_json(args.raw_input)
    if args.command == "analyze":
        analysis = build_analysis(
            raw,
            config,
            config_id,
            args.profile,
            auditor_root_public_key_hex=args.auditor_root_public_key_hex,
            verification_replay_registry=args.verification_replay_registry,
        )
        _write_json(args.output, analysis, args.overwrite)
        print(
            json.dumps(
                {
                    "status": analysis["analysis_status"],
                    "timing_conclusion": analysis["timing_conclusion"],
                    "maximum_ci_upper": analysis["maximum_failure_auc_ci_upper"],
                    "g7_status": analysis["g7_status"],
                },
                sort_keys=True,
            )
        )
        return 0
    analysis = load_json(args.analysis_input)
    validate_analysis(
        analysis,
        raw,
        config,
        config_id,
        args.profile,
        auditor_root_public_key_hex=args.auditor_root_public_key_hex,
        verification_replay_registry=args.verification_replay_registry,
    )
    print(
        json.dumps(
            {
                "status": "VALID",
                "analysis_id": analysis["analysis_id"],
                "g7_status": analysis["g7_status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
