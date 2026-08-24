#!/usr/bin/env python3
"""Fail-closed Phase 1 aggregation and deployment-profile frontiers."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import yaml
from scipy.stats import beta as beta_distribution
from scipy.stats import t as student_t

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.runners.filter_analytic_diagnostic import (  # noqa: E402
    AMBIGUOUS_NUMERIC,
    ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED,
    ANALYTIC_MODEL_VALIDATION_STATUS,
    BLOOM_FAMILY_SIZE,
    DIAGNOSTIC_CONFIG_ID,
    DIAGNOSTIC_PROTOCOL,
    EVIDENCE_SCOPE,
    INTERVAL_RELATIONS,
    NUMERIC_CONTRACT,
    ROBUST_OVERLAP,
    ROBUST_SEPARATION,
    SCIENTIFIC_BLOCKED_STATUS,
    SCIENTIFIC_PASS_RULE,
    SCIENTIFIC_PASS_STATUS,
    SIMULTANEOUS_RULE,
    TAXONOMY_VERSION,
    _UniqueKeySafeLoader,
    load_aggregate_artifact,
)
from experiments.runners.filter_bench import (  # noqa: E402
    FilterSpec,
    SyntheticCredentialSet,
    _filter_seed,
    _wilson_interval,
    expand_specs,
    load_config,
)
from reference.filters.bloom import blocked_bloom_fpr_finite  # noqa: E402
from reference.filters.common import (  # noqa: E402
    ceil_power_of_two,
    finite_bloom_fpr,
    standard_bloom_fpr,
)

SHARD_PATTERN = re.compile(r"\.shard-(\d+)-of-(\d+)\.jsonl$")
REQUIRED_METADATA = {
    "run_id",
    "commit",
    "config_hash",
    "dataset_hash",
    "seed",
    "method",
    "timestamp_utc",
    "host_platform",
    "shard_index",
    "shard_count",
}

# These identify semantic manifests, not file contents.  Changing any formal
# dataset or grid input requires a deliberate new experiment contract.
PHASE1_CONFIG_ID = "38c20f538643106159a799deb90c78e6c909934e3858b163ae2c56ea3438bade"
PHASE1_DATASET_ID = "0e0299a7367c6a115e077440e7a04936712b654a1e0a836785d3e6862ac34a4a"
PHASE1_ACCOUNT_COUNT = 100_000
PHASE1_NONMEMBER_COUNT = 10_000_000
PHASE1_SPEC_COUNT = 794
PHASE1_STATIC_SPEC_COUNT = 8
PHASE1_RANDOMIZED_SPEC_COUNT = 786
PHASE1_SEED_COUNT = 10
PHASE1_ROW_COUNT = 7_868
PHASE1_SHARD_COUNT = 36
SOURCE_STATUS_SCOPE = "repository excluding experiments/outputs/**"
LEGACY_ATTESTATION_SCHEMA_VERSION = 2
CLEAN_SOURCE_ATTESTATION_ID_SCHEMA = "phase1-clean-source-attestation-v1"
# Frozen after independently checking the three legacy source checkouts.  The
# value is replaced only by a deliberate new Phase 1 evidence contract.
PHASE1_LEGACY_ATTESTATION_ID = (
    "ff2d7c3d8d4b6356f26d4cf7aeee051257f6b81712a3d89695205204bd521dfa"
)
ANALYTIC_TAXONOMY_VERSION = TAXONOMY_VERSION
ANALYTIC_CODE_GLOBAL_REALIZED_DENSITY = "GLOBAL_REALIZED_DENSITY_CORRECTION_V1"
ANALYTIC_CODE_EXACT_QUERY_SIMULATION = (
    "INDEPENDENT_QUERY_PATH_REPRODUCTION_V1"
)
ANALYTIC_DIAGNOSTIC_PROTOCOL = DIAGNOSTIC_PROTOCOL
PHASE1_ANALYTIC_DIAGNOSTIC_CONFIG_ID = DIAGNOSTIC_CONFIG_ID
PHASE1_QUALIFIED_ANALYTIC_DIAGNOSTIC_CONFIG_ID = (
    "dd0193c424468553b21101122e2b513dabae5800e5d3f6c46d024afd1294294e"
)
PHASE1_QUALIFIED_ANALYTIC_DIAGNOSTIC_NUMERIC_CONTRACT = {
    **NUMERIC_CONTRACT,
    "numpy_version": "2.2.6",
    "scipy_version": "1.15.3",
}
PHASE1_AGGREGATE_IDENTITY_SCHEMA = "phase1-selection-aggregate-v2"
PHASE1_FRONTIER_RULE = (
    "nondominated pooled first-seen FFR and compact total edge bytes; "
    "eligibility must hold for every seed"
)
_ROW_SOURCE_ROOT = "_source_root_label"
_ROW_SOURCE_PARENT = "_source_parent_label"
_ROW_SOURCE_FILE = "_source_filename"
_ROW_SOURCE_LINE = "_source_line_number"

PROFILE_DEFINITIONS = {
    "U": "user-indexed state allowed; all measured positive screens are eligible",
    "A": (
        "aggregate password-derived edge state only; per-account tags are excluded "
        "and shown only as cross-profile references"
    ),
}


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class _DuplicateJsonKeyError(ValueError):
    pass


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    mapping: dict[str, object] = {}
    for key, value in pairs:
        if key in mapping:
            raise _DuplicateJsonKeyError(f"duplicate JSON object key {key!r}")
        mapping[key] = value
    return mapping


def _summary_bool(value: object, label: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value in {"True", "False"}:
        return value == "True"
    raise ValueError(f"Phase 1 aggregate {label} must be Boolean")


def _summary_integer(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"Phase 1 aggregate {label} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.isdigit():
        result = int(value)
    else:
        raise ValueError(f"Phase 1 aggregate {label} must be an integer")
    if result < 0:
        raise ValueError(f"Phase 1 aggregate {label} must be nonnegative")
    return result


def _summary_number(value: object, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"Phase 1 aggregate {label} must be numeric")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Phase 1 aggregate {label} must be numeric") from error
    if not math.isfinite(result) or result < 0.0:
        raise ValueError(
            f"Phase 1 aggregate {label} must be finite and nonnegative"
        )
    return result


def normalize_phase1_selection_summary(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize the typed, selection-relevant portion of one summary row."""

    required = {
        "method",
        "configured_spec",
        "independent_constructions",
        "eligible_profile_U_all_seeds",
        "eligible_profile_A_all_seeds",
        "memory_total_edge_bytes_mean",
        "first_seen_false_positives_pooled",
        "first_seen_trials_pooled",
        "first_seen_ffr_mean",
        "first_seen_ffr_ci_method",
        "first_seen_ffr_ci_low",
        "first_seen_ffr_ci_high",
        "pareto_U_memory_ffr",
        "pareto_A_memory_ffr",
        "analytic_model_validation_status",
        "analytic_model_agreement_claim_permitted",
    }
    missing = required - row.keys()
    if missing:
        raise ValueError(f"Phase 1 aggregate row missing {sorted(missing)}")
    analytic_status = str(row["analytic_model_validation_status"])
    if analytic_status != ANALYTIC_MODEL_VALIDATION_STATUS:
        raise ValueError(
            "Phase 1 aggregate analytic_model_validation_status must remain "
            f"{ANALYTIC_MODEL_VALIDATION_STATUS}"
        )
    analytic_claim = _summary_bool(
        row["analytic_model_agreement_claim_permitted"],
        "analytic_model_agreement_claim_permitted",
    )
    if analytic_claim is not ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED:
        raise ValueError(
            "Phase 1 aggregate analytic_model_agreement_claim_permitted must be false"
        )
    configured = row["configured_spec"]
    if isinstance(configured, str):
        try:
            configured = json.loads(
                configured, object_pairs_hook=_reject_duplicate_json_keys
            )
        except _DuplicateJsonKeyError as error:
            raise ValueError(
                "Phase 1 aggregate configured_spec contains duplicate keys"
            ) from error
        except json.JSONDecodeError as error:
            raise ValueError("Phase 1 aggregate configured_spec is malformed") from error
    if not isinstance(configured, dict) or not configured:
        raise ValueError("Phase 1 aggregate configured_spec must be a nonempty mapping")
    method = str(row["method"])
    if not method:
        raise ValueError("Phase 1 aggregate method must be nonempty")
    constructions = _summary_integer(
        row["independent_constructions"], "independent_constructions"
    )
    successes = _summary_integer(
        row["first_seen_false_positives_pooled"],
        "first_seen_false_positives_pooled",
    )
    trials = _summary_integer(row["first_seen_trials_pooled"], "first_seen_trials_pooled")
    if constructions == 0 or trials == 0 or successes > trials:
        raise ValueError("Phase 1 aggregate construction/query counts are invalid")
    mean = _summary_number(row["first_seen_ffr_mean"], "first_seen_ffr_mean")
    low = _summary_number(row["first_seen_ffr_ci_low"], "first_seen_ffr_ci_low")
    high = _summary_number(row["first_seen_ffr_ci_high"], "first_seen_ffr_ci_high")
    if not math.isclose(mean, successes / trials, rel_tol=2e-12, abs_tol=2e-15):
        raise ValueError("Phase 1 aggregate FFR mean/count identity failed")
    if not 0.0 <= low <= mean <= high <= 1.0:
        raise ValueError("Phase 1 aggregate primary FFR interval is invalid")
    eligible_u = _summary_bool(
        row["eligible_profile_U_all_seeds"], "eligible_profile_U_all_seeds"
    )
    eligible_a = _summary_bool(
        row["eligible_profile_A_all_seeds"], "eligible_profile_A_all_seeds"
    )
    pareto_u = _summary_bool(row["pareto_U_memory_ffr"], "pareto_U_memory_ffr")
    pareto_a = _summary_bool(row["pareto_A_memory_ffr"], "pareto_A_memory_ffr")
    if (pareto_u and not eligible_u) or (pareto_a and not eligible_a):
        raise ValueError("Phase 1 aggregate marks an ineligible point as Pareto")
    interval_method = str(row["first_seen_ffr_ci_method"])
    if not interval_method:
        raise ValueError("Phase 1 aggregate primary FFR interval method is empty")
    memory = _summary_number(
        row["memory_total_edge_bytes_mean"], "memory_total_edge_bytes_mean"
    )
    if memory <= 0.0:
        raise ValueError("Phase 1 aggregate memory must be positive")
    return {
        "method": method,
        "configured_spec": configured,
        "independent_constructions": constructions,
        "eligible_profile_U_all_seeds": eligible_u,
        "eligible_profile_A_all_seeds": eligible_a,
        "memory_total_edge_bytes_mean": memory,
        "first_seen_false_positives_pooled": successes,
        "first_seen_trials_pooled": trials,
        "first_seen_ffr_mean": mean,
        "first_seen_ffr_ci_method": interval_method,
        "first_seen_ffr_ci_low": low,
        "first_seen_ffr_ci_high": high,
        "pareto_U_memory_ffr": pareto_u,
        "pareto_A_memory_ffr": pareto_a,
        "analytic_model_validation_status": analytic_status,
        "analytic_model_agreement_claim_permitted": analytic_claim,
    }


def compute_phase1_aggregate_identity(
    summaries: Iterable[dict[str, Any]], audit: dict[str, Any]
) -> str:
    """Return the semantic identity used to preregister timing selection."""

    required_audit = {
        "commit",
        "status",
        "semantic_config_id",
        "semantic_dataset_id",
        "row_count",
        "shard_count",
        "summary_point_count",
        "phase1_cartesian_grid_status",
        "phase1_evidence_status",
        "e1_bloom_query_path_reproduction_gate",
        "e1_bloom_analytic_model_validation_status",
        "e1_bloom_analytic_unresolved_rows",
        "analytic_model_validation_status",
        "analytic_model_agreement_claim_permitted",
        "analytic_discrepancy_taxonomy_version",
        "machine_verified_discrepancies_by_code",
        "analytic_diagnostic_overlay_status",
        "analytic_diagnostic_integrity_status",
        "query_path_reproduction_status",
        "query_path_reproduction_evidence_scope",
        "query_path_reproduction_scientific_pass_rule",
        "analytic_diagnostic_source_commit",
        "analytic_diagnostic_config_id",
        "analytic_diagnostic_family_size",
        "analytic_diagnostic_fwer_consistent_rows",
        "analytic_diagnostic_fwer_inconsistent_rows",
        "analytic_diagnostic_robust_overlap_rows",
        "analytic_diagnostic_robust_separation_rows",
        "analytic_diagnostic_ambiguous_numeric_rows",
        "analytic_diagnostic_numeric_contract",
        "analytic_diagnostic_bias_direction_counts",
        "analytic_diagnostic_consistency_rule",
        "legacy_ideal_model_uncovered_rows",
        "phase1_p0b_qualification_status",
        "analytic_interval_coverage_by_method",
        "clean_source_attestation_id",
        "frontier_rule",
        "source_clean_provenance",
    }
    missing = required_audit - audit.keys()
    if missing:
        raise ValueError(f"Phase 1 aggregate audit missing {sorted(missing)}")
    _require_exact_semantic_value(
        audit["analytic_model_validation_status"],
        ANALYTIC_MODEL_VALIDATION_STATUS,
        "Phase 1 aggregate analytic_model_validation_status",
    )
    _require_exact_semantic_value(
        audit["analytic_model_agreement_claim_permitted"],
        ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED,
        "Phase 1 aggregate analytic_model_agreement_claim_permitted",
    )
    _require_exact_semantic_value(
        audit["e1_bloom_analytic_model_validation_status"],
        ANALYTIC_MODEL_VALIDATION_STATUS,
        "Phase 1 aggregate e1_bloom_analytic_model_validation_status",
    )
    if audit["e1_bloom_query_path_reproduction_gate"] not in {"PASS", "BLOCKED"}:
        raise ValueError("Phase 1 query-path reproduction gate must be PASS or BLOCKED")
    if audit["phase1_p0b_qualification_status"] not in {
        "PASS_EMPIRICAL_QUERY_PATH_REPRODUCIBILITY",
        "BLOCKED",
    }:
        raise ValueError("Phase 1 P0-B qualification status is invalid")
    diagnostic_family_size = audit["analytic_diagnostic_family_size"]
    if type(diagnostic_family_size) is not int or diagnostic_family_size not in {
        0,
        BLOOM_FAMILY_SIZE,
    }:
        raise ValueError("Phase 1 analytic diagnostic family size is invalid")
    count_fields = (
        "analytic_diagnostic_fwer_consistent_rows",
        "analytic_diagnostic_fwer_inconsistent_rows",
        "analytic_diagnostic_robust_overlap_rows",
        "analytic_diagnostic_robust_separation_rows",
        "analytic_diagnostic_ambiguous_numeric_rows",
    )
    if diagnostic_family_size == 0:
        if any(audit[field] is not None for field in count_fields) or audit[
            "analytic_diagnostic_numeric_contract"
        ] is not None:
            raise ValueError("absent Phase 1 diagnostic has bound evidence fields")
    else:
        for field in count_fields:
            value = audit[field]
            if type(value) is not int or not 0 <= value <= BLOOM_FAMILY_SIZE:
                raise ValueError(f"Phase 1 aggregate {field} is invalid")
        robust_overlap = audit["analytic_diagnostic_robust_overlap_rows"]
        robust_separation = audit["analytic_diagnostic_robust_separation_rows"]
        ambiguous = audit["analytic_diagnostic_ambiguous_numeric_rows"]
        if (
            robust_overlap + robust_separation + ambiguous != BLOOM_FAMILY_SIZE
            or audit["analytic_diagnostic_fwer_consistent_rows"] != robust_overlap
            or audit["analytic_diagnostic_fwer_inconsistent_rows"]
            != robust_separation + ambiguous
        ):
            raise ValueError("Phase 1 diagnostic relation counts are inconsistent")
        diagnostic_config_id = audit["analytic_diagnostic_config_id"]
        if diagnostic_config_id == PHASE1_ANALYTIC_DIAGNOSTIC_CONFIG_ID:
            diagnostic_numeric_contract = NUMERIC_CONTRACT
        elif diagnostic_config_id == PHASE1_QUALIFIED_ANALYTIC_DIAGNOSTIC_CONFIG_ID:
            diagnostic_numeric_contract = (
                PHASE1_QUALIFIED_ANALYTIC_DIAGNOSTIC_NUMERIC_CONTRACT
            )
        else:
            raise ValueError("Phase 1 aggregate analytic diagnostic config ID is invalid")
        _require_exact_semantic_value(
            audit["analytic_diagnostic_numeric_contract"],
            diagnostic_numeric_contract,
            "Phase 1 aggregate analytic diagnostic numeric contract",
        )
        if audit["e1_bloom_query_path_reproduction_gate"] == "PASS" and (
            robust_overlap != BLOOM_FAMILY_SIZE
            or robust_separation != 0
            or ambiguous != 0
        ):
            raise ValueError("Phase 1 PASS gate has non-robust diagnostic rows")
    analytic_reports = audit["analytic_interval_coverage_by_method"]
    if not isinstance(analytic_reports, dict) or not analytic_reports:
        raise ValueError("Phase 1 analytic interval report must be a nonempty mapping")
    for method, report in analytic_reports.items():
        if not isinstance(report, dict):
            raise ValueError(f"Phase 1 analytic interval report {method} must be a mapping")
        _require_exact_semantic_value(
            report.get("analytic_model_validation_status"),
            ANALYTIC_MODEL_VALIDATION_STATUS,
            f"Phase 1 analytic interval report {method} validation status",
        )
        _require_exact_semantic_value(
            report.get("analytic_model_agreement_claim_permitted"),
            ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED,
            f"Phase 1 analytic interval report {method} claim permission",
        )
    normalized = sorted(
        (normalize_phase1_selection_summary(row) for row in summaries),
        key=lambda row: (row["method"], _canonical(row["configured_spec"])),
    )
    identities = [
        (row["method"], _canonical(row["configured_spec"])) for row in normalized
    ]
    if len(identities) != len(set(identities)):
        raise ValueError("Phase 1 aggregate contains duplicate method/spec points")
    if len(normalized) != int(audit["summary_point_count"]):
        raise ValueError("Phase 1 aggregate summary count disagrees with its audit")
    material = {
        "schema": PHASE1_AGGREGATE_IDENTITY_SCHEMA,
        "source_commit": str(audit["commit"]),
        "qualification_status": audit["status"],
        "source_clean_provenance": audit["source_clean_provenance"],
        "clean_source_attestation_id": audit["clean_source_attestation_id"],
        "semantic_config_id": str(audit["semantic_config_id"]),
        "semantic_dataset_id": str(audit["semantic_dataset_id"]),
        "raw_row_count": int(audit["row_count"]),
        "shard_count": int(audit["shard_count"]),
        "summary_point_count": int(audit["summary_point_count"]),
        "phase1_cartesian_grid_status": audit["phase1_cartesian_grid_status"],
        "phase1_evidence_status": audit["phase1_evidence_status"],
        "e1_bloom_query_path_reproduction_gate": audit[
            "e1_bloom_query_path_reproduction_gate"
        ],
        "e1_bloom_analytic_model_validation_status": audit[
            "e1_bloom_analytic_model_validation_status"
        ],
        "e1_bloom_analytic_unresolved_rows": int(
            audit["e1_bloom_analytic_unresolved_rows"]
        ),
        "analytic_discrepancy_taxonomy_version": audit[
            "analytic_discrepancy_taxonomy_version"
        ],
        "machine_verified_discrepancies_by_code": audit[
            "machine_verified_discrepancies_by_code"
        ],
        "analytic_diagnostic_overlay_status": audit[
            "analytic_diagnostic_overlay_status"
        ],
        "analytic_diagnostic_integrity_status": audit[
            "analytic_diagnostic_integrity_status"
        ],
        "query_path_reproduction_status": audit["query_path_reproduction_status"],
        "query_path_reproduction_evidence_scope": audit[
            "query_path_reproduction_evidence_scope"
        ],
        "query_path_reproduction_scientific_pass_rule": audit[
            "query_path_reproduction_scientific_pass_rule"
        ],
        "analytic_diagnostic_source_commit": audit[
            "analytic_diagnostic_source_commit"
        ],
        "analytic_diagnostic_config_id": audit["analytic_diagnostic_config_id"],
        "analytic_diagnostic_family_size": diagnostic_family_size,
        "analytic_diagnostic_fwer_consistent_rows": audit[
            "analytic_diagnostic_fwer_consistent_rows"
        ],
        "analytic_diagnostic_fwer_inconsistent_rows": audit[
            "analytic_diagnostic_fwer_inconsistent_rows"
        ],
        "analytic_diagnostic_robust_overlap_rows": audit[
            "analytic_diagnostic_robust_overlap_rows"
        ],
        "analytic_diagnostic_robust_separation_rows": audit[
            "analytic_diagnostic_robust_separation_rows"
        ],
        "analytic_diagnostic_ambiguous_numeric_rows": audit[
            "analytic_diagnostic_ambiguous_numeric_rows"
        ],
        "analytic_diagnostic_numeric_contract": audit[
            "analytic_diagnostic_numeric_contract"
        ],
        "analytic_diagnostic_bias_direction_counts": audit[
            "analytic_diagnostic_bias_direction_counts"
        ],
        "analytic_diagnostic_consistency_rule": audit[
            "analytic_diagnostic_consistency_rule"
        ],
        "legacy_ideal_model_uncovered_rows": int(
            audit["legacy_ideal_model_uncovered_rows"]
        ),
        "analytic_model_validation_status": audit[
            "analytic_model_validation_status"
        ],
        "analytic_model_agreement_claim_permitted": audit[
            "analytic_model_agreement_claim_permitted"
        ],
        "phase1_p0b_qualification_status": audit[
            "phase1_p0b_qualification_status"
        ],
        "analytic_interval_coverage_by_method": analytic_reports,
        "frontier_rule": audit["frontier_rule"],
        "selection_records": normalized,
    }
    return hashlib.sha256(_canonical(material).encode()).hexdigest()


def _mean_ci(
    values: Iterable[float], confidence: float = 0.95
) -> tuple[float, float, float]:
    samples = list(values)
    if not samples:
        raise ValueError("cannot summarize an empty sample")
    center = statistics.mean(samples)
    if len(samples) == 1:
        return center, center, center
    standard_error = statistics.stdev(samples) / math.sqrt(len(samples))
    critical = float(student_t.ppf((1.0 + confidence) / 2.0, len(samples) - 1))
    return center, center - critical * standard_error, center + critical * standard_error


def _clopper_pearson_interval(
    successes: int, trials: int, confidence: float = 0.95
) -> tuple[float, float]:
    """Conservative exact binomial interval, including a nonzero zero-event bound."""

    if trials <= 0 or not 0 <= successes <= trials:
        raise ValueError("invalid binomial counts")
    alpha = 1.0 - confidence
    lower = (
        0.0
        if successes == 0
        else float(beta_distribution.ppf(alpha / 2.0, successes, trials - successes + 1))
    )
    upper = (
        1.0
        if successes == trials
        else float(
            beta_distribution.ppf(
                1.0 - alpha / 2.0, successes + 1, trials - successes
            )
        )
    )
    return lower, upper


def _parse_utc(value: object, label: str) -> datetime:
    try:
        timestamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label}: invalid UTC timestamp") from error
    if timestamp.utcoffset() is None or timestamp.utcoffset().total_seconds() != 0:
        raise ValueError(f"{label}: timestamp is not UTC")
    return timestamp


def _require_exact_keys(
    value: dict[str, Any],
    required: set[str],
    label: str,
    optional: set[str] | None = None,
) -> None:
    optional = set() if optional is None else optional
    missing = required - value.keys()
    unexpected = value.keys() - required - optional
    if missing:
        raise ValueError(f"{label} missing {sorted(missing)}")
    if unexpected:
        raise ValueError(f"{label} has unbound fields {sorted(unexpected)}")


def _require_exact_semantic_value(
    actual: object, expected: object, label: str
) -> None:
    """Reject bool/int substitution and nested coordinated mutations."""

    if type(actual) is not type(expected):
        raise ValueError(f"{label} has the wrong exact type")
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        _require_exact_keys(actual, set(expected), label)
        for key, expected_item in expected.items():
            _require_exact_semantic_value(
                actual[key], expected_item, f"{label}.{key}"
            )
        return
    if isinstance(expected, list):
        assert isinstance(actual, list)
        if len(actual) != len(expected):
            raise ValueError(f"{label} has the wrong list length")
        for index, (actual_item, expected_item) in enumerate(
            zip(actual, expected, strict=True)
        ):
            _require_exact_semantic_value(
                actual_item, expected_item, f"{label}[{index}]"
            )
        return
    if isinstance(expected, float) and not math.isfinite(actual):
        raise ValueError(f"{label} must be finite")
    if actual != expected:
        raise ValueError(f"{label} does not match the expected value")


def _attestation_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must be a nonempty canonical string")
    return value


def _attestation_integer(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value < (1 if positive else 0):
        qualifier = "positive" if positive else "nonnegative"
        raise ValueError(f"{label} must be {qualifier}")
    return value


def _canonical_utc(value: object, label: str) -> tuple[str, datetime]:
    timestamp = _parse_utc(value, label)
    canonical = timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return canonical, timestamp


def _normalized_clean_attestation_payload(value: object) -> dict[str, Any]:
    """Return the complete, order-stable semantic attestation payload."""

    if not isinstance(value, dict):
        raise ValueError("clean-source attestation must be a JSON object")
    required = {
        "schema_version",
        "semantic_config_id",
        "semantic_dataset_id",
        "source_commit",
        "shard_count",
        "status_scope",
        "result_root_label",
        "source_checks",
    }
    _require_exact_keys(
        value,
        required,
        "clean-source attestation",
        {"semantic_attestation_id"},
    )
    schema_version = _attestation_integer(
        value["schema_version"], "clean-source attestation schema_version"
    )
    if schema_version != LEGACY_ATTESTATION_SCHEMA_VERSION:
        raise ValueError(
            "clean-source attestation schema_version must be "
            f"{LEGACY_ATTESTATION_SCHEMA_VERSION}"
        )
    config_id = _attestation_string(
        value["semantic_config_id"], "clean-source attestation semantic_config_id"
    )
    dataset_id = _attestation_string(
        value["semantic_dataset_id"], "clean-source attestation semantic_dataset_id"
    )
    source_commit = _attestation_string(
        value["source_commit"], "clean-source attestation source_commit"
    )
    if re.fullmatch(r"[0-9a-f]{64}", config_id) is None:
        raise ValueError("clean-source attestation config ID must be 64 lowercase hex")
    if re.fullmatch(r"[0-9a-f]{64}", dataset_id) is None:
        raise ValueError("clean-source attestation dataset ID must be 64 lowercase hex")
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("clean-source attestation commit must be 40 lowercase hex")
    shard_count = _attestation_integer(
        value["shard_count"], "clean-source attestation shard_count", positive=True
    )
    if value["status_scope"] != SOURCE_STATUS_SCOPE:
        raise ValueError("clean-source attestation has the wrong status scope")
    root_label = _attestation_string(
        value["result_root_label"], "clean-source attestation result_root_label"
    )
    if root_label in {".", ".."} or "/" in root_label or "\\" in root_label:
        raise ValueError("clean-source attestation has an invalid result_root_label")
    checks = value["source_checks"]
    if not isinstance(checks, list) or not checks:
        raise ValueError("clean-source attestation source_checks must be nonempty")

    check_required = {
        "parent_directory_label",
        "hostname",
        "checkout_path",
        "row_host_platform",
        "source_commit",
        "source_commit_before",
        "source_commit_after",
        "source_clean",
        "source_status_scope",
        "source_status_porcelain",
        "checked_at_utc",
        "verified_at_utc",
        "shard_files",
    }
    file_required = {
        "filename",
        "shard_index",
        "shard_count",
        "row_count",
        "row_timestamp_min_utc",
        "row_timestamp_max_utc",
    }
    all_indices: list[int] = []
    parent_labels: set[str] = set()
    shard_bindings: set[tuple[str, str]] = set()
    normalized_checks: list[dict[str, Any]] = []
    for ordinal, check in enumerate(checks):
        label = f"clean-source attestation source_checks[{ordinal}]"
        if not isinstance(check, dict):
            raise ValueError(f"{label} must be a mapping")
        _require_exact_keys(check, check_required, label)
        parent_label = _attestation_string(
            check["parent_directory_label"], f"{label}.parent_directory_label"
        )
        if parent_label in {".", ".."} or "/" in parent_label or "\\" in parent_label:
            raise ValueError(f"{label} has an invalid parent_directory_label")
        if parent_label in parent_labels:
            raise ValueError(f"{label} duplicates parent_directory_label {parent_label}")
        parent_labels.add(parent_label)
        hostname = _attestation_string(check["hostname"], f"{label}.hostname")
        checkout_path = _attestation_string(
            check["checkout_path"], f"{label}.checkout_path"
        )
        posix_checkout = PurePosixPath(checkout_path)
        if (
            not posix_checkout.is_absolute()
            or str(posix_checkout) != checkout_path
            or ".." in posix_checkout.parts
        ):
            raise ValueError(f"{label} checkout_path must be a canonical absolute POSIX path")
        row_platform = _attestation_string(
            check["row_host_platform"], f"{label}.row_host_platform"
        )
        commits = [
            _attestation_string(check[field], f"{label}.{field}")
            for field in ("source_commit", "source_commit_before", "source_commit_after")
        ]
        if any(re.fullmatch(r"[0-9a-f]{40}", item) is None for item in commits):
            raise ValueError(f"{label} commits must be 40 lowercase hex")
        if set(commits) != {source_commit}:
            raise ValueError(f"{label} before/after/source commits do not match")
        if check["source_clean"] is not True:
            raise ValueError(f"{label} does not attest a clean source")
        if check["source_status_scope"] != SOURCE_STATUS_SCOPE:
            raise ValueError(f"{label} has the wrong source_status_scope")
        if check["source_status_porcelain"] != []:
            raise ValueError(f"{label} does not record an empty scoped status")
        checked_text, checked_at = _canonical_utc(
            check["checked_at_utc"], f"{label}.checked_at_utc"
        )
        verified_text, verified_at = _canonical_utc(
            check["verified_at_utc"], f"{label}.verified_at_utc"
        )
        if checked_at >= verified_at:
            raise ValueError(f"{label} checked_at_utc must precede verified_at_utc")
        shard_files = check["shard_files"]
        if not isinstance(shard_files, list) or not shard_files:
            raise ValueError(f"{label} shard_files must be nonempty")
        normalized_files: list[dict[str, Any]] = []
        for file_ordinal, file_entry in enumerate(shard_files):
            file_label = f"{label}.shard_files[{file_ordinal}]"
            if not isinstance(file_entry, dict):
                raise ValueError(f"{file_label} must be a mapping")
            _require_exact_keys(file_entry, file_required, file_label)
            filename = _attestation_string(
                file_entry["filename"], f"{file_label}.filename"
            )
            if PurePosixPath(filename).name != filename or "\\" in filename:
                raise ValueError(f"{file_label} filename must not contain a path")
            match = SHARD_PATTERN.search(filename)
            if match is None or match.end() != len(filename):
                raise ValueError(f"{file_label} has a malformed shard filename")
            filename_index, filename_count = (int(item) for item in match.groups())
            index = _attestation_integer(
                file_entry["shard_index"], f"{file_label}.shard_index"
            )
            count = _attestation_integer(
                file_entry["shard_count"], f"{file_label}.shard_count", positive=True
            )
            row_count = _attestation_integer(
                file_entry["row_count"], f"{file_label}.row_count", positive=True
            )
            if index != filename_index or count != filename_count:
                raise ValueError(f"{file_label} filename/metadata shard mismatch")
            if count != shard_count or index >= shard_count:
                raise ValueError(f"{file_label} disagrees with top-level shard_count")
            binding = (parent_label, filename)
            if binding in shard_bindings:
                raise ValueError(f"duplicate attested shard binding {binding}")
            shard_bindings.add(binding)
            all_indices.append(index)
            timestamp_min_text, timestamp_min = _canonical_utc(
                file_entry["row_timestamp_min_utc"],
                f"{file_label}.row_timestamp_min_utc",
            )
            timestamp_max_text, timestamp_max = _canonical_utc(
                file_entry["row_timestamp_max_utc"],
                f"{file_label}.row_timestamp_max_utc",
            )
            if timestamp_min > timestamp_max:
                raise ValueError(f"{file_label} timestamp minimum exceeds maximum")
            if checked_at <= timestamp_max or verified_at <= timestamp_max:
                raise ValueError(f"{file_label} is not covered by post-run source checks")
            normalized_files.append(
                {
                    "filename": filename,
                    "shard_index": index,
                    "shard_count": count,
                    "row_count": row_count,
                    "row_timestamp_min_utc": timestamp_min_text,
                    "row_timestamp_max_utc": timestamp_max_text,
                }
            )
        normalized_checks.append(
            {
                "parent_directory_label": parent_label,
                "hostname": hostname,
                "checkout_path": checkout_path,
                "row_host_platform": row_platform,
                "source_commit": commits[0],
                "source_commit_before": commits[1],
                "source_commit_after": commits[2],
                "source_clean": True,
                "source_status_scope": SOURCE_STATUS_SCOPE,
                "source_status_porcelain": [],
                "checked_at_utc": checked_text,
                "verified_at_utc": verified_text,
                "shard_files": sorted(
                    normalized_files,
                    key=lambda item: (item["shard_index"], item["filename"]),
                ),
            }
        )
    if len(all_indices) != shard_count or set(all_indices) != set(range(shard_count)):
        raise ValueError("clean-source attestation must bind every shard exactly once")
    return {
        "schema_version": schema_version,
        "semantic_config_id": config_id,
        "semantic_dataset_id": dataset_id,
        "source_commit": source_commit,
        "shard_count": shard_count,
        "status_scope": SOURCE_STATUS_SCOPE,
        "result_root_label": root_label,
        "source_checks": sorted(
            normalized_checks, key=lambda item: item["parent_directory_label"]
        ),
    }


def compute_clean_source_attestation_id(value: object) -> str:
    """Hash the normalized semantic payload, never the attestation file bytes."""

    material = {
        "schema": CLEAN_SOURCE_ATTESTATION_ID_SCHEMA,
        "attestation": _normalized_clean_attestation_payload(value),
    }
    return hashlib.sha256(_canonical(material).encode()).hexdigest()


def _validated_clean_attestation(value: object) -> tuple[dict[str, Any], str]:
    normalized = _normalized_clean_attestation_payload(value)
    if not isinstance(value, dict) or "semantic_attestation_id" not in value:
        raise ValueError("clean-source attestation missing semantic_attestation_id")
    reported_id = value["semantic_attestation_id"]
    if not isinstance(reported_id, str) or re.fullmatch(r"[0-9a-f]{64}", reported_id) is None:
        raise ValueError("clean-source attestation semantic ID must be 64 lowercase hex")
    computed_id = compute_clean_source_attestation_id(normalized)
    if reported_id != computed_id:
        raise ValueError("clean-source attestation semantic ID mismatch")
    return {**normalized, "semantic_attestation_id": computed_id}, computed_id


def load_clean_attestation(path: Path) -> dict[str, Any]:
    """Load and self-verify a post-run clean-source semantic attestation."""

    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=_reject_duplicate_json_keys)
    except _DuplicateJsonKeyError as error:
        raise ValueError(f"{path.name} contains {error}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"{path.name} is malformed JSON") from error
    normalized, _ = _validated_clean_attestation(value)
    return normalized


def _validate_clean_provenance(
    rows: list[dict[str, Any]],
    expected_commit: str,
    expected_shards: int,
    attestation: dict[str, Any] | None,
) -> str:
    explicit_dirty = [
        row for row in rows if "git_dirty" in row and row["git_dirty"] is not False
    ]
    if explicit_dirty:
        raise ValueError("formal rows contain dirty or unreadable Git provenance")

    missing = [row for row in rows if "git_dirty" not in row]
    if not missing:
        return "row-recorded-clean"
    if len(missing) != len(rows):
        raise ValueError("formal rows mix legacy and row-recorded Git provenance")
    if attestation is None:
        raise ValueError("formal legacy rows require a clean-source attestation")
    attestation, attestation_id = _validated_clean_attestation(attestation)
    if attestation_id != PHASE1_LEGACY_ATTESTATION_ID:
        raise ValueError("clean-source attestation ID is not the frozen Phase 1 ID")
    if str(attestation["semantic_config_id"]) != PHASE1_CONFIG_ID:
        raise ValueError("clean-source attestation config ID mismatch")
    if str(attestation["semantic_dataset_id"]) != PHASE1_DATASET_ID:
        raise ValueError("clean-source attestation dataset ID mismatch")
    if str(attestation["source_commit"]) != expected_commit:
        raise ValueError("clean-source attestation commit mismatch")
    if int(attestation["shard_count"]) != expected_shards:
        raise ValueError("clean-source attestation shard count mismatch")
    root_labels = {str(row.get(_ROW_SOURCE_ROOT, "")) for row in rows}
    if root_labels != {str(attestation["result_root_label"])}:
        raise ValueError("clean-source attestation result-root label mismatch")
    checks = attestation["source_checks"]

    actual_by_file: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        parent_label = str(row.get(_ROW_SOURCE_PARENT, ""))
        filename = str(row.get(_ROW_SOURCE_FILE, ""))
        if not parent_label or not filename:
            raise ValueError("legacy row lacks source-file binding metadata")
        actual_by_file[(parent_label, filename)].append(row)

    covered: set[int] = set()
    attested_bindings: set[tuple[str, str]] = set()
    for check_ordinal, check in enumerate(checks):
        parent_label = str(check["parent_directory_label"])
        if (
            check.get("source_clean") is not True
            or check.get("source_status_scope") != SOURCE_STATUS_SCOPE
        ):
            raise ValueError(f"source check {parent_label} is not clean in the frozen scope")
        if not str(check.get("hostname", "")).strip() or not str(
            check.get("checkout_path", "")
        ).startswith("/"):
            raise ValueError(f"source check {parent_label} lacks host/checkout binding")
        checked_at = _parse_utc(
            check["checked_at_utc"], f"source_checks[{check_ordinal}]"
        )
        verified_at = _parse_utc(
            check["verified_at_utc"], f"source_checks[{check_ordinal}]"
        )
        for file_entry in check["shard_files"]:
            filename = str(file_entry["filename"])
            binding = (parent_label, filename)
            attested_bindings.add(binding)
            file_rows = actual_by_file.get(binding)
            if file_rows is None:
                raise ValueError(f"attestation names absent shard file {binding}")
            index = int(file_entry["shard_index"])
            count = int(file_entry["shard_count"])
            if len(file_rows) != int(file_entry["row_count"]):
                raise ValueError(f"attested row count mismatch for shard {index}")
            timestamps = [
                _parse_utc(row["timestamp_utc"], f"attested shard {index}")
                for row in file_rows
            ]
            declared_min = _parse_utc(
                file_entry["row_timestamp_min_utc"], f"attested shard {index}"
            )
            declared_max = _parse_utc(
                file_entry["row_timestamp_max_utc"], f"attested shard {index}"
            )
            if min(timestamps) != declared_min or max(timestamps) != declared_max:
                raise ValueError(f"attested timestamp endpoints mismatch for shard {index}")
            if checked_at <= max(timestamps) or verified_at <= max(timestamps):
                raise ValueError(f"attestation for shard {index} is not post-run")
            for row in file_rows:
                if int(row["shard_index"]) != index or int(row["shard_count"]) != count:
                    raise ValueError(f"attested shard metadata mismatch for shard {index}")
                if str(row["host_platform"]) != str(check["row_host_platform"]):
                    raise ValueError(f"attested row platform mismatch for shard {index}")
                if str(row["commit"]) != str(check["source_commit"]):
                    raise ValueError(f"attested row commit mismatch for shard {index}")
                if row["config_hash"] != attestation["semantic_config_id"]:
                    raise ValueError(f"attested row config mismatch for shard {index}")
                if row["dataset_hash"] != attestation["semantic_dataset_id"]:
                    raise ValueError(f"attested row dataset mismatch for shard {index}")
            covered.add(index)
    if attested_bindings != set(actual_by_file):
        raise ValueError("clean-source attestation does not bind every discovered file")
    if covered != set(range(expected_shards)):
        raise ValueError("clean-source attestation does not cover every shard")
    return "legacy-external-clean-attestation"


def load_shards(
    input_dir: Path,
    expected_shards: int,
    expected_rows: int | None = None,
    expected_commit: str | None = None,
    expected_config_id: str | None = None,
    expected_dataset_id: str | None = None,
    require_clean_provenance: bool = False,
    clean_attestation: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    paths = sorted(input_dir.rglob("filter_bench_E1_E2*.jsonl"))
    if len(paths) != expected_shards:
        raise ValueError(f"expected {expected_shards} shard files, found {len(paths)}")

    rows: list[dict[str, Any]] = []
    observed_indices: set[int] = set()
    for path in paths:
        match = SHARD_PATTERN.search(path.name)
        if match is None:
            raise ValueError(f"malformed shard filename: {path.name}")
        file_index, file_count = (int(value) for value in match.groups())
        if file_count != expected_shards:
            raise ValueError(f"{path.name} declares shard count {file_count}")
        if file_index in observed_indices:
            raise ValueError(f"duplicate shard index {file_index}")
        observed_indices.add(file_index)
        file_rows = 0
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                label = f"{path.name}:{line_number}"
                try:
                    row = json.loads(
                        line, object_pairs_hook=_reject_duplicate_json_keys
                    )
                except _DuplicateJsonKeyError as error:
                    raise ValueError(f"{label}: contains {error}") from error
                except json.JSONDecodeError as error:
                    raise ValueError(f"{label}: malformed JSON") from error
                if not isinstance(row, dict):
                    raise ValueError(f"{label}: row must be a JSON object")
                missing = REQUIRED_METADATA - row.keys()
                if missing:
                    raise ValueError(f"{label}: missing {sorted(missing)}")
                if row["shard_index"] != file_index or row["shard_count"] != file_count:
                    raise ValueError(f"{label}: shard metadata mismatch")
                _parse_utc(row["timestamp_utc"], label)
                row[_ROW_SOURCE_ROOT] = input_dir.name
                row[_ROW_SOURCE_PARENT] = path.parent.name
                row[_ROW_SOURCE_FILE] = path.name
                row[_ROW_SOURCE_LINE] = line_number
                rows.append(row)
                file_rows += 1
        if file_rows == 0:
            raise ValueError(f"empty shard: {path.name}")

    expected_indices = set(range(expected_shards))
    if observed_indices != expected_indices:
        missing = sorted(expected_indices - observed_indices)
        raise ValueError(f"missing shard indices: {missing}")
    if expected_rows is not None and len(rows) != expected_rows:
        raise ValueError(f"expected {expected_rows} rows, found {len(rows)}")

    run_ids = [str(row["run_id"]) for row in rows]
    if len(run_ids) != len(set(run_ids)):
        raise ValueError("duplicate run_id values")
    commits = {row["commit"] for row in rows}
    configs = {row["config_hash"] for row in rows}
    datasets = {row["dataset_hash"] for row in rows}
    if len(commits) != 1 or None in commits or "UNCOMMITTED" in commits:
        raise ValueError(f"results do not have one committed revision: {commits}")
    commit = str(next(iter(commits)))
    if expected_commit is not None and commit != expected_commit:
        raise ValueError(f"expected commit {expected_commit}, found {commit}")
    if len(configs) != 1 or len(datasets) != 1:
        raise ValueError("results mix config or dataset manifests")
    config_id = str(next(iter(configs)))
    dataset_id = str(next(iter(datasets)))
    if expected_config_id is not None and config_id != expected_config_id:
        raise ValueError(f"expected config ID {expected_config_id}, found {config_id}")
    if expected_dataset_id is not None and dataset_id != expected_dataset_id:
        raise ValueError(f"expected dataset ID {expected_dataset_id}, found {dataset_id}")
    if any(int(row.get("member_false_negatives", -1)) != 0 for row in rows):
        raise ValueError("at least one filter row has a member false negative")
    if any(not bool(row.get("e1_distinct_nonmember_target_met")) for row in rows):
        raise ValueError("at least one row did not run the E1 distinct-query target")

    provenance_mode = "not-required"
    attestation_id: str | None = None
    if require_clean_provenance:
        if expected_commit is None:
            raise ValueError("clean provenance validation requires expected_commit")
        provenance_mode = _validate_clean_provenance(
            rows, expected_commit, expected_shards, clean_attestation
        )
        if provenance_mode == "legacy-external-clean-attestation":
            assert clean_attestation is not None
            _, attestation_id = _validated_clean_attestation(clean_attestation)

    audit = {
        "status": "PASS",
        "row_count": len(rows),
        "shard_count": expected_shards,
        "commit": commit,
        "semantic_config_id": config_id,
        "semantic_dataset_id": dataset_id,
        "source_clean_provenance": provenance_mode,
        "clean_source_attestation_id": attestation_id,
        "member_false_negatives": 0,
        "analytic_discrepancy_rows": sum(
            row.get("analytic_discrepancy") is not None for row in rows
        ),
        "legacy_memory_name_rows": sum(
            "memory_object_graph_estimate_bytes" not in row
            and "memory_python_resident_bytes" in row
            for row in rows
        ),
        "cuckoo_load_model_recomputed_rows": sum(
            row.get("method") == "cuckoo_filter" for row in rows
        ),
        "hosts": sorted({str(row["host_platform"]) for row in rows}),
    }
    return rows, audit


def _cuckoo_load_corrected_fpr(row: dict[str, Any]) -> float | None:
    if row.get("method") != "cuckoo_filter":
        value = row.get("analytic_fpr_standard")
        return None if value is None else float(value)
    parameters = row.get("filter_parameters")
    if not isinstance(parameters, dict):
        raise ValueError("Cuckoo row lacks filter_parameters")
    try:
        load = float(parameters["load_factor"])
        width = int(parameters["fingerprint_bits"])
        bucket_size = int(parameters["bucket_size"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("Cuckoo row lacks load-model parameters") from error
    if not 0.0 <= load <= 1.0 or width < 1 or bucket_size < 1:
        raise ValueError("Cuckoo row has invalid load-model parameters")
    per_slot_match = load / ((1 << width) - 1)
    return -math.expm1((2 * bucket_size) * math.log1p(-per_slot_match))


def _row_interval_contains(row: dict[str, Any], value: float | None) -> bool:
    if value is None:
        return False
    return float(row["observed_fpr_ci_lower"]) <= value <= float(
        row["observed_fpr_ci_upper"]
    )


def _profile_eligible(row: dict[str, Any], profile: str) -> bool:
    labels = row.get("eligible_profiles", [])
    if not isinstance(labels, list):
        return False
    exposure = str(row.get("exposed_state_model", ""))
    if profile == "U":
        return "U" in labels
    if profile == "A":
        return "A" in labels and exposure == "aggregate_edge_state"
    raise ValueError(f"unknown deployment profile: {profile}")


def _object_graph_estimate(row: dict[str, Any]) -> float | None:
    current = row.get("memory_object_graph_estimate_bytes")
    legacy = row.get("memory_python_resident_bytes")
    if current is not None and legacy is not None and current != legacy:
        raise ValueError("object-graph memory aliases disagree")
    value = current if current is not None else legacy
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("object-graph memory estimate must be numeric")
    return float(value)


def _finite_number(
    row: dict[str, Any], field: str, *, allow_none: bool = False
) -> float | None:
    value = row.get(field)
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a numeric value")
    result = float(value)
    if not math.isfinite(result) or result < 0.0:
        raise ValueError(f"{field} must be finite and nonnegative")
    return result


def _integer(row: dict[str, Any], field: str) -> int:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if value < 0:
        raise ValueError(f"{field} must be nonnegative")
    return value


def _close(actual: object, expected: float, label: str) -> None:
    if isinstance(actual, bool) or not isinstance(actual, (int, float)):
        raise ValueError(f"{label} must be numeric")
    value = float(actual)
    if not math.isfinite(value) or not math.isclose(
        value, expected, rel_tol=2e-12, abs_tol=2e-15
    ):
        raise ValueError(f"{label} does not match the recomputed value")


@lru_cache(maxsize=None)
def _blocked_finite_model(
    block_count: int, n_items: int, k_hashes: int
) -> float:
    return blocked_bloom_fpr_finite(block_count, 512, n_items, k_hashes)


def load_analytic_diagnostics(
    path: Path, expected_diagnostic_commit: str
) -> dict[str, Any]:
    """Load the complete strict overlay from a trusted diagnostic revision."""

    return load_aggregate_artifact(path, expected_diagnostic_commit)


def _validated_diagnostic_rows(
    artifact: dict[str, Any] | None,
    expected_commit: str,
) -> tuple[str | None, dict[str, dict[str, Any]]]:
    if artifact is None:
        return None, {}
    if artifact.get("semantic_config_id") != PHASE1_CONFIG_ID:
        raise ValueError("analytic diagnostic config ID mismatch")
    if artifact.get("semantic_dataset_id") != PHASE1_DATASET_ID:
        raise ValueError("analytic diagnostic dataset ID mismatch")
    if artifact.get("target_source_commit") != expected_commit:
        raise ValueError("analytic diagnostic target commit mismatch")
    if artifact.get("diagnostic_config_id") != PHASE1_ANALYTIC_DIAGNOSTIC_CONFIG_ID:
        raise ValueError("analytic diagnostic protocol config ID mismatch")
    if artifact.get("diagnostic_protocol") != ANALYTIC_DIAGNOSTIC_PROTOCOL:
        raise ValueError("analytic diagnostic protocol mismatch")
    _require_exact_semantic_value(
        artifact.get("analytic_model_validation_status"),
        ANALYTIC_MODEL_VALIDATION_STATUS,
        "analytic diagnostic model validation status",
    )
    _require_exact_semantic_value(
        artifact.get("analytic_model_agreement_claim_permitted"),
        ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED,
        "analytic diagnostic model agreement claim permission",
    )
    familywise_rule = artifact.get("familywise_rule")
    if not isinstance(familywise_rule, dict):
        raise ValueError("analytic diagnostic familywise rule must be a mapping")
    _require_exact_semantic_value(
        familywise_rule.get("numeric_contract"),
        NUMERIC_CONTRACT,
        "analytic diagnostic numeric contract",
    )
    result: dict[str, dict[str, Any]] = {}
    direction_counts = {"exact_higher": 0, "exact_lower": 0, "equal": 0}
    relation_counts = {relation: 0 for relation in INTERVAL_RELATIONS}
    for ordinal, diagnostic in enumerate(artifact["diagnostic_rows"]):
        label = f"analytic diagnostic row {ordinal}"
        if not isinstance(diagnostic, dict):
            raise ValueError(f"{label} must be a mapping")
        run_id = str(diagnostic["target_run_id"])
        if not run_id or run_id in result:
            raise ValueError("analytic diagnostic target_run_id is empty or duplicate")
        if not isinstance(diagnostic.get("fwer_consistent"), bool):
            raise ValueError(f"{label}.fwer_consistent must be Boolean")
        relation = diagnostic.get("fwer_interval_relation")
        if relation not in relation_counts:
            raise ValueError(f"{label} has an invalid interval relation")
        if diagnostic["fwer_consistent"] is not (relation == ROBUST_OVERLAP):
            raise ValueError(f"{label}.fwer_consistent contradicts interval relation")
        _require_exact_semantic_value(
            diagnostic.get("analytic_model_validation_status"),
            ANALYTIC_MODEL_VALIDATION_STATUS,
            f"{label}.analytic_model_validation_status",
        )
        _require_exact_semantic_value(
            diagnostic.get("analytic_model_agreement_claim_permitted"),
            ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED,
            f"{label}.analytic_model_agreement_claim_permitted",
        )
        direction = diagnostic.get("systematic_bias_direction")
        if direction not in direction_counts:
            raise ValueError(f"{label} has an invalid bias direction")
        relation_counts[str(relation)] += 1
        direction_counts[str(direction)] += 1
        result[run_id] = diagnostic
    if len(result) != BLOOM_FAMILY_SIZE:
        raise ValueError("analytic diagnostic overlay must contain all 7680 Bloom rows")
    consistent_rows = relation_counts[ROBUST_OVERLAP]
    separation_rows = relation_counts[ROBUST_SEPARATION]
    ambiguous_rows = relation_counts[AMBIGUOUS_NUMERIC]
    inconsistent_rows = separation_rows + ambiguous_rows
    evidence_passes = (
        consistent_rows == BLOOM_FAMILY_SIZE
        and separation_rows == 0
        and ambiguous_rows == 0
    )
    expected_audit = {
        "status": "PASS" if evidence_passes else "BLOCKED",
        "integrity_status": "PASS",
        "scientific_status": (
            SCIENTIFIC_PASS_STATUS
            if evidence_passes
            else SCIENTIFIC_BLOCKED_STATUS
        ),
        "evidence_scope": EVIDENCE_SCOPE,
        "analytic_model_validation_status": ANALYTIC_MODEL_VALIDATION_STATUS,
        "analytic_model_agreement_claim_permitted": (
            ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED
        ),
        "scientific_pass_rule": SCIENTIFIC_PASS_RULE,
        "expected_shards": 36,
        "observed_shards": 36,
        "expected_rows": BLOOM_FAMILY_SIZE,
        "observed_rows": BLOOM_FAMILY_SIZE,
        "fwer_consistent_rows": consistent_rows,
        "fwer_inconsistent_rows": inconsistent_rows,
        "robust_overlap_rows": consistent_rows,
        "robust_separation_rows": separation_rows,
        "ambiguous_numeric_rows": ambiguous_rows,
        "bias_direction_counts": direction_counts,
        "formal_run_completed": True,
    }
    _require_exact_semantic_value(
        artifact.get("audit"), expected_audit, "analytic diagnostic overlay audit"
    )
    return str(artifact["diagnostic_source_commit"]), result


def _bind_diagnostic_to_target(
    row: dict[str, Any], diagnostic: dict[str, Any]
) -> None:
    """Bind an already structurally validated overlay row to one raw row."""

    required_equal = {
        "target_run_id": row["run_id"],
        "method": row["method"],
        "configured_spec": row["configured_spec"],
        "seed": row["seed"],
        "filter_hash_seed": row["filter_parameters"]["hash_seed"],
        "filter_parameters": row["filter_parameters"],
        "target_raw_shard_index": row["shard_index"],
        "target_raw_shard_count": row["shard_count"],
        "observed_false_positive_count": row["backend_invalid_checks"],
        "observed_trial_count": row["distinct_invalid_count"],
    }
    for field, expected in required_equal.items():
        _require_exact_semantic_value(
            diagnostic[field],
            expected,
            f"analytic diagnostic {field} for target {row['run_id']}",
        )


def _machine_verified_discrepancy(
    row: dict[str, Any],
    diagnostics_by_run: dict[str, dict[str, Any]],
) -> str | None:
    """Return the frozen evidence code only when its numeric contract passes."""

    code = row.get("analytic_discrepancy_code")
    if code == ANALYTIC_CODE_GLOBAL_REALIZED_DENSITY:
        if row.get("method") != "global_bloom":
            return None
        parameters = row.get("filter_parameters")
        if not isinstance(parameters, dict):
            return None
        density = float(parameters["bit_density"])
        k_hashes = int(parameters["k_hashes"])
        realized = density**k_hashes
        _close(
            parameters["analytic_fpr_realized_density"],
            realized,
            "global realized-density discrepancy model",
        )
        return code if _row_interval_contains(row, realized) else None
    diagnostic = diagnostics_by_run.get(str(row.get("run_id")))
    if (
        diagnostic is not None
        and diagnostic["fwer_consistent"] is True
        and diagnostic.get("fwer_interval_relation") == ROBUST_OVERLAP
    ):
        if diagnostic["fwer_consistency_rule"] != SIMULTANEOUS_RULE:
            raise ValueError("analytic diagnostic simultaneous rule mismatch")
        return ANALYTIC_CODE_EXACT_QUERY_SIMULATION
    return None


def _family_for_method(method: str) -> str:
    if method == "exact_tag_128" or method.startswith("truncated_tag_"):
        return "tag"
    return {
        "global_bloom": "global_bloom",
        "blocked_bloom_64b": "blocked_bloom",
        "xor_static_3way": "xor_static",
        "cuckoo_filter": "cuckoo",
    }[method]


def _recomputed_run_id(row: dict[str, Any]) -> str:
    method = str(row["method"])
    family = _family_for_method(method)
    configured_spec = row["configured_spec"]
    spec = FilterSpec(family, configured_spec)
    seed = row["seed"]
    run_material = (
        f"{row['commit']}:{row['config_hash']}:{row['dataset_hash']}:"
        f"{seed if seed is not None else 'STATIC'}:{spec.identity}"
    )
    return hashlib.sha256(run_material.encode()).hexdigest()[:24]


def _validate_memory(
    row: dict[str, Any], expected_payload: int, metadata: int, alignment: int
) -> None:
    payload = _integer(row, "memory_payload_bytes")
    metadata_observed = _integer(row, "memory_metadata_bytes")
    alignment_observed = _integer(row, "memory_alignment_bytes")
    compact = _integer(row, "memory_compact_total_bytes")
    filter_bytes = _integer(row, "memory_filter_bytes")
    model_bytes = _integer(row, "memory_model_bytes")
    cache_bytes = _integer(row, "memory_cache_bytes")
    directory_bytes = _integer(row, "memory_directory_extra_bytes")
    common_key = _integer(row, "memory_common_prf_key_bytes")
    total = _integer(row, "memory_total_edge_bytes")
    if (payload, metadata_observed, alignment_observed) != (
        expected_payload,
        metadata,
        alignment,
    ):
        raise ValueError("compact memory components do not match the filter layout")
    if compact != payload + metadata_observed + alignment_observed:
        raise ValueError("memory_compact_total_bytes identity failed")
    is_tag = _family_for_method(str(row["method"])) == "tag"
    expected_filter = 0 if is_tag else compact
    expected_directory = compact if is_tag else 0
    if filter_bytes != expected_filter or directory_bytes != expected_directory:
        raise ValueError("filter/directory memory attribution is inconsistent")
    if model_bytes != 0 or cache_bytes != 0 or common_key != 32:
        raise ValueError("Phase 1 baseline auxiliary memory is inconsistent")
    if total != filter_bytes + model_bytes + cache_bytes + directory_bytes + common_key:
        raise ValueError("memory_total_edge_bytes identity failed")
    object_estimate = _object_graph_estimate(row)
    if object_estimate is not None and (
        not math.isfinite(object_estimate) or object_estimate < compact
    ):
        raise ValueError("object-graph estimate must be finite and at least compact state")


def _validate_filter_parameters(row: dict[str, Any]) -> dict[str, float | None]:
    """Validate the exact frozen implementation contract and return analytic models."""

    method = str(row["method"])
    configured = row.get("configured_spec")
    parameters = row.get("filter_parameters")
    if not isinstance(configured, dict) or not isinstance(parameters, dict):
        raise ValueError("configured_spec and filter_parameters must be mappings")
    seed = row.get("seed")
    n_items = PHASE1_ACCOUNT_COUNT
    if parameters.get("n_items") != n_items:
        raise ValueError("filter_parameters.n_items mismatch")

    if method == "exact_tag_128" or method.startswith("truncated_tag_"):
        expected_keys = {"m_bits", "n_items", "k_hashes", "tag_bits", "hash_scheme"}
        if set(parameters) != expected_keys:
            raise ValueError("tag filter_parameters schema mismatch")
        width = int(configured.get("tag_bits", -1))
        expected_method = "exact_tag_128" if width == 128 else f"truncated_tag_{width}"
        if method != expected_method or width not in (8, 12, 16, 20, 24, 32, 64, 128):
            raise ValueError("tag configured_spec/method mismatch")
        if parameters["tag_bits"] != width or parameters["k_hashes"] is not None:
            raise ValueError("tag filter_parameters mismatch")
        if parameters["m_bits"] != n_items * width:
            raise ValueError("tag m_bits mismatch")
        if parameters["hash_scheme"] != (
            "HMAC-SHA256/128 common token; network-order prefix"
        ):
            raise ValueError("tag hash scheme mismatch")
        payload = math.ceil(n_items * width / 8)
        _validate_memory(row, payload, 32, (-payload) % 8)
        analytic = 2.0**-width
        _close(row.get("analytic_fpr_finite"), analytic, "analytic_fpr_finite")
        _close(row.get("analytic_fpr_standard"), analytic, "analytic_fpr_standard")
        return {"finite": analytic, "standard": analytic, "primary": analytic}

    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("randomized filter seed must be an integer")

    if method in ("global_bloom", "blocked_bloom_64b"):
        blocked = method == "blocked_bloom_64b"
        expected_keys = (
            {
                "requested_m_bits",
                "m_bits",
                "n_items",
                "k_hashes",
                "hash_seed",
                "block_bytes",
                "block_count",
                "hash_scheme",
                "analytic_fpr_finite",
                "analytic_fpr_standard",
                "analytic_fpr_realized_density",
                "bit_density",
            }
            if blocked
            else {
                "m_bits",
                "n_items",
                "k_hashes",
                "hash_seed",
                "hash_scheme",
                "analytic_fpr_finite",
                "analytic_fpr_standard",
                "analytic_fpr_realized_density",
                "bit_density",
            }
        )
        if set(parameters) != expected_keys:
            raise ValueError("Bloom filter_parameters schema mismatch")
        bits_per_account = int(configured.get("bits_per_account", -1))
        k_hashes = int(configured.get("k_hashes", -1))
        requested_m_bits = n_items * bits_per_account
        if bits_per_account not in (4, 8, 12, 16, 24, 32, 48, 64):
            raise ValueError("Bloom bits_per_account is outside the frozen grid")
        if not 1 <= k_hashes <= 48:
            raise ValueError("Bloom k_hashes is outside the frozen grid")
        family = "blocked_bloom" if blocked else "global_bloom"
        expected_hash_seed = _filter_seed(seed, FilterSpec(family, configured))
        if parameters["hash_seed"] != expected_hash_seed:
            raise ValueError("Bloom hash_seed mismatch")
        if parameters["k_hashes"] != k_hashes:
            raise ValueError("Bloom k_hashes parameter mismatch")
        if blocked:
            block_count = max(1, math.ceil(requested_m_bits / 512))
            m_bits = block_count * 512
            if (
                parameters["requested_m_bits"] != requested_m_bits
                or parameters["block_bytes"] != 64
                or parameters["block_count"] != block_count
                or parameters["m_bits"] != m_bits
            ):
                raise ValueError("blocked Bloom capacity parameters mismatch")
            if parameters["hash_scheme"] != (
                "BLAKE2b-128: one block plus odd local double hash"
            ):
                raise ValueError("blocked Bloom hash scheme mismatch")
            finite = _blocked_finite_model(block_count, n_items, k_hashes)
            alignment = (-70) % 64
            metadata = 70
        else:
            m_bits = requested_m_bits
            if parameters["m_bits"] != m_bits:
                raise ValueError("global Bloom m_bits mismatch")
            if parameters["hash_scheme"] != "BLAKE2b-128 keyed double hashing":
                raise ValueError("global Bloom hash scheme mismatch")
            finite = finite_bloom_fpr(m_bits, n_items, k_hashes)
            metadata = 52
            alignment = (-metadata) % 8 + (-math.ceil(m_bits / 8)) % 8
        standard = standard_bloom_fpr(m_bits, n_items, k_hashes)
        density = _finite_number(parameters, "bit_density")
        realized = _finite_number(parameters, "analytic_fpr_realized_density")
        assert density is not None and realized is not None
        if density > 1.0 or realized > 1.0:
            raise ValueError("Bloom density/model probability exceeds one")
        if not blocked:
            _close(realized, density**k_hashes, "global Bloom realized-density FPR")
        _close(parameters["analytic_fpr_finite"], finite, "filter finite FPR")
        _close(parameters["analytic_fpr_standard"], standard, "filter standard FPR")
        _close(row.get("analytic_fpr_finite"), finite, "analytic_fpr_finite")
        _close(row.get("analytic_fpr_standard"), standard, "analytic_fpr_standard")
        _validate_memory(row, math.ceil(m_bits / 8), metadata, alignment)
        return {"finite": finite, "standard": standard, "primary": finite}

    retry_step = 0x9E3779B97F4A7C15
    if method == "xor_static_3way":
        expected_keys = {
            "m_bits",
            "n_items",
            "k_hashes",
            "fingerprint_bits",
            "capacity",
            "capacity_factor",
            "hash_seed",
            "build_attempts",
            "hash_scheme",
        }
        if set(parameters) != expected_keys:
            raise ValueError("Xor filter_parameters schema mismatch")
        width = int(configured.get("fingerprint_bits", -1))
        capacity_factor = float(configured.get("capacity_factor", math.nan))
        max_attempts = int(configured.get("max_attempts", -1))
        capacity = 3 * max(1, math.ceil(capacity_factor * n_items / 3))
        attempt = int(parameters.get("build_attempts", 0))
        base = _filter_seed(seed, FilterSpec("xor_static", configured))
        expected_hash_seed = (base + (attempt - 1) * retry_step) & 0xFFFFFFFFFFFFFFFF
        if (
            width not in (4, 8, 12, 16, 20, 24, 32, 48, 64)
            or capacity_factor != 1.23
            or max_attempts != 100
            or not 1 <= attempt <= max_attempts
            or parameters["fingerprint_bits"] != width
            or parameters["capacity"] != capacity
            or parameters["m_bits"] != capacity * width
            or parameters["k_hashes"] != 3
            or parameters["hash_seed"] != expected_hash_seed
        ):
            raise ValueError("Xor configured/realized parameters mismatch")
        _close(parameters["capacity_factor"], capacity / n_items, "Xor capacity_factor")
        if parameters["hash_scheme"] != "BLAKE2b-64, three disjoint segments":
            raise ValueError("Xor hash scheme mismatch")
        m_bits = capacity * width
        payload = math.ceil(m_bits / 8)
        _validate_memory(row, payload, 66, (-66) % 8 + (-payload) % 8)
        analytic = 2.0**-width
        _close(row.get("analytic_fpr_finite"), analytic, "analytic_fpr_finite")
        _close(row.get("analytic_fpr_standard"), analytic, "analytic_fpr_standard")
        return {"finite": analytic, "standard": analytic, "primary": analytic}

    if method == "cuckoo_filter":
        expected_keys = {
            "m_bits",
            "n_items",
            "k_hashes",
            "fingerprint_bits",
            "bucket_count",
            "bucket_size",
            "load_factor",
            "hash_seed",
            "max_kicks",
            "build_attempts",
            "analytic_fpr_standard",
            "hash_scheme",
        }
        allowed_keys = expected_keys | {"analytic_fpr_standard_model"}
        if not expected_keys <= set(parameters) or not set(parameters) <= allowed_keys:
            raise ValueError("Cuckoo filter_parameters schema mismatch")
        width = int(configured.get("fingerprint_bits", -1))
        bucket_size = int(configured.get("bucket_size", -1))
        target_load = float(configured.get("target_load", math.nan))
        max_kicks = int(configured.get("max_kicks", -1))
        max_attempts = int(configured.get("max_seed_attempts", -1))
        desired_slots = math.ceil(n_items / target_load)
        bucket_count = ceil_power_of_two(max(2, math.ceil(desired_slots / bucket_size)))
        slots = bucket_count * bucket_size
        load = n_items / slots
        m_bits = slots * width
        attempt = int(parameters.get("build_attempts", 0))
        base = _filter_seed(seed, FilterSpec("cuckoo", configured))
        expected_hash_seed = (base + (attempt - 1) * retry_step) & 0xFFFFFFFFFFFFFFFF
        if (
            width not in (4, 8, 12, 16, 20, 24, 32, 48, 64)
            or bucket_size != 4
            or target_load != 0.90
            or max_kicks != 500
            or max_attempts != 20
            or not 1 <= attempt <= max_attempts
            or parameters["fingerprint_bits"] != width
            or parameters["bucket_size"] != bucket_size
            or parameters["bucket_count"] != bucket_count
            or parameters["m_bits"] != m_bits
            or parameters["k_hashes"] != 2
            or parameters["max_kicks"] != max_kicks
            or parameters["hash_seed"] != expected_hash_seed
        ):
            raise ValueError("Cuckoo configured/capacity parameters mismatch")
        _close(parameters["load_factor"], load, "Cuckoo load_factor")
        corrected = -math.expm1(
            (2 * bucket_size) * math.log1p(-load / ((1 << width) - 1))
        )
        model_label = parameters.get("analytic_fpr_standard_model")
        if model_label is None:
            # Frozen legacy rows recorded a full-occupancy model.  Preserve and
            # validate that raw value, but return the realized-load correction
            # as the only aggregate standard model.
            recorded_model = -math.expm1(
                (2 * bucket_size) * math.log1p(-1.0 / ((1 << width) - 1))
            )
        else:
            if model_label != (
                "1-(1-load_factor/(2^fingerprint_bits-1))^(2*bucket_size)"
            ):
                raise ValueError("Cuckoo analytic model label mismatch")
            recorded_model = corrected
        _close(
            parameters["analytic_fpr_standard"],
            recorded_model,
            "Cuckoo recorded analytic FPR",
        )
        if parameters["hash_scheme"] != (
            "BLAKE2b-64 with fingerprint-derived alternate bucket"
        ):
            raise ValueError("Cuckoo hash scheme mismatch")
        if row.get("analytic_fpr_finite") is not None:
            raise ValueError("Cuckoo finite FPR must be null")
        _close(row.get("analytic_fpr_standard"), recorded_model, "analytic_fpr_standard")
        payload = math.ceil(m_bits / 8)
        _validate_memory(row, payload, 62, (-62) % 8 + (-payload) % 8)
        return {"finite": None, "standard": corrected, "primary": corrected}

    raise ValueError(f"unknown filter method {method}")


def summarize(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        key = (str(row["method"]), _canonical(row["configured_spec"]))
        grouped[key].append(row)

    summaries: list[dict[str, Any]] = []
    for (method, configured_spec), group in sorted(grouped.items()):
        successes = sum(int(row["backend_invalid_checks"]) for row in group)
        trials = sum(int(row["distinct_invalid_count"]) for row in group)
        ffr = successes / trials
        query_low, query_high = _clopper_pearson_interval(successes, trials)
        construction_rates = [
            int(row["backend_invalid_checks"]) / int(row["distinct_invalid_count"])
            for row in group
        ]
        cluster_low: float | None
        cluster_high: float | None
        if len(construction_rates) >= 2:
            _, raw_cluster_low, raw_cluster_high = _mean_ci(construction_rates)
            cluster_low = max(0.0, raw_cluster_low)
            cluster_high = min(1.0, raw_cluster_high)
        else:
            cluster_low = cluster_high = None
        ffr_low = (
            min(query_low, cluster_low) if cluster_low is not None else query_low
        )
        ffr_high = (
            max(query_high, cluster_high) if cluster_high is not None else query_high
        )
        latency, latency_low, latency_high = _mean_ci(
            float(row["frontend_p99_us"]) for row in group
        )
        memory, _, _ = _mean_ci(float(row["memory_total_edge_bytes"]) for row in group)
        object_estimates = [
            value for row in group if (value := _object_graph_estimate(row)) is not None
        ]
        formal_timing = all(
            row.get("timing_protocol_valid") is True for row in group
        )
        eligible_u = all(_profile_eligible(row, "U") for row in group)
        eligible_a = all(_profile_eligible(row, "A") for row in group)
        cross_profile_reference_a = all(
            "A-reference-only" in row.get("eligible_profiles", []) for row in group
        )
        analytic_either_coverage: list[bool] = []
        analytic_finite_coverage: list[bool] = []
        analytic_standard_coverage: list[bool] = []
        analytic_standard_values: list[float] = []
        analytic_finite_values: list[float] = []
        for row in group:
            finite = row.get("analytic_fpr_finite")
            finite_value = None if finite is None else float(finite)
            standard_value = _cuckoo_load_corrected_fpr(row)
            if finite_value is not None:
                analytic_finite_values.append(finite_value)
                analytic_finite_coverage.append(
                    _row_interval_contains(row, finite_value)
                )
            if standard_value is not None:
                analytic_standard_values.append(standard_value)
                analytic_standard_coverage.append(
                    _row_interval_contains(row, standard_value)
                )
            analytic_either_coverage.append(
                _row_interval_contains(row, finite_value)
                or _row_interval_contains(row, standard_value)
            )
        summary = {
            "method": method,
            "configured_spec": configured_spec,
            "independent_constructions": len(group),
            "eligible_profiles": ",".join(
                profile
                for profile, eligible in (("U", eligible_u), ("A", eligible_a))
                if eligible
            ),
            "eligible_profile_U_all_seeds": eligible_u,
            "eligible_profile_A_all_seeds": eligible_a,
            "cross_profile_reference_A": cross_profile_reference_a,
            "memory_total_edge_bytes_mean": memory,
            "memory_object_graph_estimate_bytes_mean": (
                statistics.mean(object_estimates) if object_estimates else None
            ),
            "first_seen_false_positives_pooled": successes,
            "first_seen_trials_pooled": trials,
            "first_seen_ffr_mean": ffr,
            "first_seen_ffr_ci_method": (
                "outer envelope of query-level pooled Clopper-Pearson exact 95% "
                "and construction-seed t 95%"
                if cluster_low is not None
                else "query-level pooled Clopper-Pearson exact 95% (single static construction)"
            ),
            "first_seen_ffr_ci_low": ffr_low,
            "first_seen_ffr_ci_high": ffr_high,
            "query_level_pooled_fpr_ci_method": "Clopper-Pearson exact 95%",
            "query_level_pooled_fpr_ci_low": query_low,
            "query_level_pooled_fpr_ci_high": query_high,
            "construction_seed_fpr_ci_method": (
                "Student-t 95% over independent construction rates"
                if cluster_low is not None
                else "not estimable from one static construction"
            ),
            "construction_seed_fpr_ci_low": cluster_low,
            "construction_seed_fpr_ci_high": cluster_high,
            "per_seed_fpr_ci_method": "Wilson score (retained in raw rows)",
            "formal_timing_eligible": formal_timing,
            "frontend_p99_us_mean": latency if formal_timing else None,
            "frontend_p99_us_ci_low": max(0.0, latency_low) if formal_timing else None,
            "frontend_p99_us_ci_high": latency_high if formal_timing else None,
            "diagnostic_frontend_p99_us_mean": latency,
            "diagnostic_frontend_p99_us_ci_low": max(0.0, latency_low),
            "diagnostic_frontend_p99_us_ci_high": latency_high,
            "member_false_negatives": sum(
                int(row["member_false_negatives"]) for row in group
            ),
            "analytic_fpr_finite_mean": (
                statistics.mean(analytic_finite_values)
                if analytic_finite_values
                else None
            ),
            "analytic_fpr_standard_mean": (
                statistics.mean(analytic_standard_values)
                if analytic_standard_values
                else None
            ),
            "analytic_fpr_standard_source": (
                "recomputed realized-load Cuckoo ideal-placement model"
                if method == "cuckoo_filter"
                else "raw recorded model"
            ),
            "analytic_model_validation_status": ANALYTIC_MODEL_VALIDATION_STATUS,
            "analytic_model_agreement_claim_permitted": (
                ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED
            ),
            "analytic_interval_coverage_scope": (
                "diagnostic ideal-model containment; not analytic-model validation"
            ),
            "analytic_finite_interval_coverage_fraction": (
                statistics.mean(analytic_finite_coverage)
                if analytic_finite_coverage
                else None
            ),
            "analytic_standard_interval_coverage_fraction": (
                statistics.mean(analytic_standard_coverage)
                if analytic_standard_coverage
                else None
            ),
            "analytic_either_interval_coverage_fraction": statistics.mean(
                analytic_either_coverage
            ),
            "minimum_event_count": min(int(row["event_count"]) for row in group),
            "pareto_rule": (
                "nondominated pooled first-seen FFR and compact total edge bytes; "
                "profile eligibility must hold for every construction seed"
            ),
        }
        summaries.append(summary)

    for profile in ("U", "A"):
        eligibility_field = f"eligible_profile_{profile}_all_seeds"
        eligible_rows = [row for row in summaries if row[eligibility_field]]
        for row in summaries:
            row[f"pareto_{profile}_memory_ffr"] = False
        for candidate in eligible_rows:
            dominated = any(
                other is not candidate
                and other["memory_total_edge_bytes_mean"]
                <= candidate["memory_total_edge_bytes_mean"]
                and other["first_seen_ffr_mean"] <= candidate["first_seen_ffr_mean"]
                and (
                    other["memory_total_edge_bytes_mean"]
                    < candidate["memory_total_edge_bytes_mean"]
                    or other["first_seen_ffr_mean"] < candidate["first_seen_ffr_mean"]
                )
                for other in eligible_rows
            )
            candidate[f"pareto_{profile}_memory_ffr"] = not dominated
    return summaries


def _method_for_spec(family: str, parameters: dict[str, Any]) -> str:
    if family == "tag":
        width = int(parameters["tag_bits"])
        return "exact_tag_128" if width == 128 else f"truncated_tag_{width}"
    return {
        "global_bloom": "global_bloom",
        "blocked_bloom": "blocked_bloom_64b",
        "xor_static": "xor_static_3way",
        "cuckoo": "cuckoo_filter",
    }[family]


def _load_phase1_contract(config_path: Path) -> tuple[dict[str, Any], str, str]:
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            strict_config = yaml.load(handle, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as error:
        raise ValueError(
            "frozen Phase 1 config is malformed or contains duplicate mapping keys"
        ) from error
    if not isinstance(strict_config, dict):
        raise ValueError("frozen Phase 1 config must be a mapping")
    config, config_id = load_config(config_path)
    _require_exact_semantic_value(
        config, strict_config, "frozen Phase 1 config strict-loader agreement"
    )
    if config_id != PHASE1_CONFIG_ID:
        raise ValueError(
            f"frozen Phase 1 config ID mismatch: expected {PHASE1_CONFIG_ID}, found {config_id}"
        )
    dataset_config = config["dataset"]
    dataset = SyntheticCredentialSet(
        int(dataset_config["account_count"]), int(dataset_config["seed"])
    )
    members = [dataset.member(index) for index in range(dataset.account_count)]
    dataset_id = dataset.manifest_hash(members, int(dataset_config["nonmember_count"]))
    if dataset_id != PHASE1_DATASET_ID:
        raise ValueError(
            f"frozen Phase 1 dataset ID mismatch: expected {PHASE1_DATASET_ID}, found {dataset_id}"
        )
    return config, config_id, dataset_id


def _expected_phase1_rows(config: dict[str, Any]) -> Counter[tuple[str, str, int | None]]:
    seeds = [int(seed) for seed in config["seeds"]]
    expected: Counter[tuple[str, str, int | None]] = Counter()
    for spec in expand_specs(config):
        method = _method_for_spec(spec.family, spec.parameters)
        row_seeds: list[int | None] = [None] if spec.family == "tag" else seeds
        for seed in row_seeds:
            expected[(method, _canonical(spec.parameters), seed)] += 1
    return expected


def _expected_phase1_rows_by_shard(
    config: dict[str, Any], shard_count: int
) -> dict[int, Counter[tuple[str, str, int | None]]]:
    if shard_count <= 0:
        raise ValueError("shard_count must be positive")
    specs = expand_specs(config)
    points = [
        (int(seed), spec)
        for seed_ordinal, seed in enumerate(config["seeds"])
        for spec in specs
        if spec.family != "tag" or seed_ordinal == 0
    ]
    expected = {index: Counter() for index in range(shard_count)}
    for ordinal, (seed, spec) in enumerate(points):
        method = _method_for_spec(spec.family, spec.parameters)
        row_seed = None if spec.family == "tag" else seed
        expected[ordinal % shard_count][
            (method, _canonical(spec.parameters), row_seed)
        ] += 1
    return expected


def _actual_row_identity(row: dict[str, Any]) -> tuple[str, str, int | None]:
    configured_spec = row.get("configured_spec")
    if not isinstance(configured_spec, dict):
        raise ValueError("configured_spec must be a mapping")
    seed = row.get("seed")
    if seed is not None:
        if isinstance(seed, bool) or not isinstance(seed, int):
            raise ValueError("filter seed must be an integer or null")
        seed = int(seed)
    return str(row.get("method")), _canonical(configured_spec), seed


def _counter_example(counter: Counter[tuple[str, str, int | None]]) -> str:
    if not counter:
        return "none"
    identity, count = next(iter(counter.items()))
    return f"{identity} x{count}"


def validate_phase1_grid(
    rows: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    config_path: Path,
    expected_commit: str,
    expected_shards: int,
    clean_attestation: dict[str, Any] | None = None,
    analytic_diagnostics: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config, config_id, dataset_id = _load_phase1_contract(config_path)
    confidence_z = float(config["measurement"]["confidence_z"])
    expected = _expected_phase1_rows(config)
    expected_by_shard = _expected_phase1_rows_by_shard(config, expected_shards)
    diagnostic_source_commit, diagnostics_by_run = _validated_diagnostic_rows(
        analytic_diagnostics, expected_commit
    )
    bloom_target_run_ids: set[str] = set()
    discrepancy_taxonomy_counts: Counter[str] = Counter()
    if len(expected) != PHASE1_ROW_COUNT:
        raise ValueError("frozen Phase 1 contract does not expand to 7868 row identities")
    spec_identities = {(method, spec) for method, spec, _ in expected}
    if len(spec_identities) != PHASE1_SPEC_COUNT:
        raise ValueError("frozen Phase 1 contract does not expand to 794 specs")
    if len(rows) != PHASE1_ROW_COUNT:
        raise ValueError(f"Phase 1 grid requires 7868 rows, found {len(rows)}")

    actual: Counter[tuple[str, str, int | None]] = Counter()
    actual_by_shard = {index: Counter() for index in range(expected_shards)}
    analytic_by_method: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "modeled_rows": 0,
            "finite_available": 0,
            "finite_covered": 0,
            "standard_available": 0,
            "standard_covered": 0,
            "either_covered": 0,
            "uncovered_explained": 0,
            "uncovered_unresolved": 0,
        }
    )
    for ordinal, row in enumerate(rows):
        identity = _actual_row_identity(row)
        actual[identity] += 1
        shard_index = _integer(row, "shard_index")
        if shard_index not in actual_by_shard:
            raise ValueError(f"row {ordinal}: invalid shard index")
        if _integer(row, "shard_count") != expected_shards:
            raise ValueError(f"row {ordinal}: invalid shard count")
        actual_by_shard[shard_index][identity] += 1
        method, _, seed = identity
        is_tag = method == "exact_tag_128" or method.startswith("truncated_tag_")
        if bool(row.get("randomized_construction")) == is_tag:
            raise ValueError(f"row {ordinal}: static/randomized construction mismatch")
        if (seed is None) != is_tag:
            raise ValueError(f"row {ordinal}: static/randomized seed mismatch")
        expected_profiles = ["U", "A-reference-only"] if is_tag else ["U", "A"]
        if row.get("eligible_profiles") != expected_profiles:
            raise ValueError(f"row {ordinal}: deployment-profile eligibility mismatch")
        expected_exposure = (
            "protected_per_account_prf_records" if is_tag else "aggregate_edge_state"
        )
        if row.get("exposed_state_model") != expected_exposure:
            raise ValueError(f"row {ordinal}: exposed-state model mismatch")
        expected_deployment = "U" if is_tag else "A"
        if row.get("deployment_profile") != expected_deployment:
            raise ValueError(f"row {ordinal}: deployment-profile label mismatch")
        if _integer(row, "account_count") != PHASE1_ACCOUNT_COUNT:
            raise ValueError(f"row {ordinal}: wrong account_count")
        if _integer(row, "member_validation_count") != PHASE1_ACCOUNT_COUNT:
            raise ValueError(f"row {ordinal}: wrong member_validation_count")
        if _integer(row, "distinct_invalid_count") != PHASE1_NONMEMBER_COUNT:
            raise ValueError(f"row {ordinal}: wrong distinct_invalid_count")
        if _integer(row, "event_count") != PHASE1_NONMEMBER_COUNT:
            raise ValueError(f"row {ordinal}: wrong event_count")
        if row.get("config_hash") != config_id:
            raise ValueError(f"row {ordinal}: wrong semantic config ID")
        if row.get("dataset_hash") != dataset_id:
            raise ValueError(f"row {ordinal}: wrong semantic dataset ID")
        if row.get("commit") != expected_commit:
            raise ValueError(f"row {ordinal}: wrong source commit")
        if row.get("scenario") != config["scenario"]:
            raise ValueError(f"row {ordinal}: wrong scenario")
        if "git_dirty" in row and row.get("source_status_scope") != SOURCE_STATUS_SCOPE:
            raise ValueError(f"row {ordinal}: wrong source status scope")
        if row.get("run_id") != _recomputed_run_id(row):
            raise ValueError(f"row {ordinal}: run_id does not match frozen identity")
        if _integer(row, "member_false_negatives") != 0:
            raise ValueError(f"row {ordinal}: member false negatives")
        if row.get("e1_distinct_nonmember_target_met") is not True:
            raise ValueError(f"row {ordinal}: distinct-query target not met")
        if row.get("observed_fpr_ci_method") != "Wilson score":
            raise ValueError(f"row {ordinal}: per-seed Wilson interval missing")
        successes = _integer(row, "backend_invalid_checks")
        if not 0 <= successes <= PHASE1_NONMEMBER_COUNT:
            raise ValueError(f"row {ordinal}: invalid false-positive count")
        if _integer(row, "backend_valid_checks") != 0:
            raise ValueError(f"row {ordinal}: unexpected valid backend checks")
        observed = float(row.get("observed_first_seen_ffr", math.nan))
        if not math.isclose(
            observed,
            successes / PHASE1_NONMEMBER_COUNT,
            rel_tol=0.0,
            abs_tol=1e-15,
        ):
            raise ValueError(f"row {ordinal}: FFR does not match integer counts")
        lower = float(row.get("observed_fpr_ci_lower", math.nan))
        upper = float(row.get("observed_fpr_ci_upper", math.nan))
        if not 0.0 <= lower <= observed <= upper <= 1.0:
            raise ValueError(f"row {ordinal}: malformed per-seed Wilson interval")
        _close(
            row.get("observed_fpr_confidence_z"),
            confidence_z,
            f"row {ordinal} Wilson z",
        )
        expected_lower, expected_upper = _wilson_interval(
            successes, PHASE1_NONMEMBER_COUNT, confidence_z
        )
        _close(lower, expected_lower, f"row {ordinal} Wilson lower")
        _close(upper, expected_upper, f"row {ordinal} Wilson upper")
        _close(
            row.get("backend_checks_per_distinct_invalid"),
            observed,
            f"row {ordinal} backend checks per distinct invalid",
        )
        _close(
            row.get("observed_request_weighted_ffr"),
            observed,
            f"row {ordinal} request-weighted diagnostic FFR",
        )
        _close(
            row.get("worst_region_ffr"),
            observed,
            f"row {ordinal} worst-region diagnostic FFR",
        )

        required_nonnegative_metrics = (
            "build_time_s",
            "warm_scan_time_s",
            "warm_query_throughput_qps",
            "frontend_p50_us",
            "frontend_p95_us",
            "frontend_p99_us",
            "member_probe_mean",
            "member_comparison_mean",
            "probe_mean",
            "probe_p50",
            "probe_p95",
            "probe_p99",
            "comparison_mean",
            "comparison_p99",
        )
        optional_nonnegative_metrics = (
            "frontend_cold_p50_us",
            "frontend_cold_p95_us",
            "frontend_cold_p99_us",
            "repeated_fp_p50_us",
            "repeated_fp_p95_us",
            "repeated_fp_p99_us",
        )
        for field in required_nonnegative_metrics:
            _finite_number(row, field)
        for field in optional_nonnegative_metrics:
            _finite_number(row, field, allow_none=True)
        for field in (
            "repeated_false_positive_keys",
            "repeated_false_positive_queries",
            "repeated_fp_positive_queries",
        ):
            _integer(row, field)

        models = _validate_filter_parameters(row)
        if method in {"global_bloom", "blocked_bloom_64b"}:
            run_id = str(row["run_id"])
            bloom_target_run_ids.add(run_id)
            if diagnostics_by_run:
                diagnostic = diagnostics_by_run.get(run_id)
                if diagnostic is None:
                    raise ValueError(
                        f"analytic diagnostic overlay is missing target {run_id}"
                    )
                _bind_diagnostic_to_target(row, diagnostic)
        coverage = analytic_by_method[method]
        coverage["modeled_rows"] += 1
        finite_model = models["finite"]
        standard_model = models["standard"]
        finite_covered = finite_model is not None and _row_interval_contains(
            row, finite_model
        )
        standard_covered = standard_model is not None and _row_interval_contains(
            row, standard_model
        )
        if finite_model is not None:
            coverage["finite_available"] += 1
            coverage["finite_covered"] += int(finite_covered)
        if standard_model is not None:
            coverage["standard_available"] += 1
            coverage["standard_covered"] += int(standard_covered)
        either_covered = finite_covered or standard_covered
        coverage["either_covered"] += int(either_covered)
        if not either_covered:
            verified_code = _machine_verified_discrepancy(
                row, diagnostics_by_run
            )
            explained = verified_code is not None
            if verified_code is not None:
                discrepancy_taxonomy_counts[verified_code] += 1
            coverage[
                "uncovered_explained" if explained else "uncovered_unresolved"
            ] += 1

    missing = expected - actual
    unexpected = actual - expected
    if missing or unexpected:
        raise ValueError(
            "Phase 1 Cartesian grid mismatch; "
            f"missing example: {_counter_example(missing)}; "
            f"unexpected example: {_counter_example(unexpected)}"
        )
    if diagnostics_by_run and set(diagnostics_by_run) != bloom_target_run_ids:
        raise ValueError(
            "analytic diagnostic overlay does not exactly cover every Bloom target"
        )
    for shard_index in range(expected_shards):
        if actual_by_shard[shard_index] != expected_by_shard[shard_index]:
            raise ValueError(
                f"Phase 1 shard {shard_index} does not match the frozen modulo assignment"
            )
    if len(summaries) != PHASE1_SPEC_COUNT:
        raise ValueError(
            f"Phase 1 grid requires 794 parameter summaries, found {len(summaries)}"
        )
    for summary in summaries:
        is_tag = summary["method"] == "exact_tag_128" or str(
            summary["method"]
        ).startswith("truncated_tag_")
        expected_constructions = 1 if is_tag else PHASE1_SEED_COUNT
        if int(summary["independent_constructions"]) != expected_constructions:
            raise ValueError(
                f"{summary['method']} {summary['configured_spec']} has "
                f"{summary['independent_constructions']} constructions; "
                f"expected {expected_constructions}"
            )
    provenance_mode = _validate_clean_provenance(
        rows, expected_commit, expected_shards, clean_attestation
    )
    attestation_id: str | None = None
    if provenance_mode == "legacy-external-clean-attestation":
        assert clean_attestation is not None
        _, attestation_id = _validated_clean_attestation(clean_attestation)
    analytic_report: dict[str, dict[str, int | float | None]] = {}
    for method, counts in sorted(analytic_by_method.items()):
        finite_available = counts["finite_available"]
        standard_available = counts["standard_available"]
        modeled_rows = counts["modeled_rows"]
        analytic_report[method] = {
            **counts,
            "analytic_model_validation_status": ANALYTIC_MODEL_VALIDATION_STATUS,
            "analytic_model_agreement_claim_permitted": (
                ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED
            ),
            "coverage_scope": (
                "diagnostic ideal-model containment only; not model validation"
            ),
            "finite_coverage_fraction": (
                counts["finite_covered"] / finite_available
                if finite_available
                else None
            ),
            "standard_coverage_fraction": (
                counts["standard_covered"] / standard_available
                if standard_available
                else None
            ),
            "either_coverage_fraction": counts["either_covered"] / modeled_rows,
        }
    bloom_unresolved = sum(
        analytic_by_method[method]["uncovered_unresolved"]
        for method in ("global_bloom", "blocked_bloom_64b")
    )
    bloom_ideal_model_uncovered = sum(
        analytic_by_method[method]["modeled_rows"]
        - analytic_by_method[method]["either_covered"]
        for method in ("global_bloom", "blocked_bloom_64b")
    )
    overlay_audit = (
        None if analytic_diagnostics is None else analytic_diagnostics["audit"]
    )
    overlay_family_pass = (
        overlay_audit is not None
        and overlay_audit["scientific_status"] == SCIENTIFIC_PASS_STATUS
        and overlay_audit["robust_overlap_rows"] == BLOOM_FAMILY_SIZE
        and overlay_audit["robust_separation_rows"] == 0
        and overlay_audit["ambiguous_numeric_rows"] == 0
    )
    qualification_pass = bloom_unresolved == 0 and overlay_family_pass
    overlay_status = "ABSENT"
    if overlay_audit is not None:
        if overlay_family_pass:
            overlay_status = "PASS_COMPLETE_7680"
        elif overlay_audit["ambiguous_numeric_rows"] > 0:
            overlay_status = "BLOCKED_COMPLETE_7680_NUMERIC_AMBIGUITY"
        else:
            overlay_status = "BLOCKED_COMPLETE_7680_ROBUST_SEPARATION"
    return {
        "expected_parameter_points": PHASE1_SPEC_COUNT,
        "expected_static_parameter_points": PHASE1_STATIC_SPEC_COUNT,
        "expected_randomized_parameter_points": PHASE1_RANDOMIZED_SPEC_COUNT,
        "expected_result_rows": PHASE1_ROW_COUNT,
        "independent_randomized_seeds": PHASE1_SEED_COUNT,
        "semantic_config_id": config_id,
        "semantic_dataset_id": dataset_id,
        "source_clean_provenance": provenance_mode,
        "clean_source_attestation_id": attestation_id,
        "phase1_cartesian_grid_status": "PASS",
        "analytic_interval_coverage_by_method": analytic_report,
        "analytic_discrepancy_taxonomy_version": ANALYTIC_TAXONOMY_VERSION,
        "machine_verified_discrepancies_by_code": dict(
            sorted(discrepancy_taxonomy_counts.items())
        ),
        "analytic_diagnostic_overlay_status": overlay_status,
        "analytic_diagnostic_integrity_status": (
            None if overlay_audit is None else overlay_audit["integrity_status"]
        ),
        "query_path_reproduction_status": (
            "NOT_RUN" if overlay_audit is None else overlay_audit["scientific_status"]
        ),
        "query_path_reproduction_evidence_scope": EVIDENCE_SCOPE,
        "query_path_reproduction_scientific_pass_rule": SCIENTIFIC_PASS_RULE,
        "analytic_diagnostic_source_commit": diagnostic_source_commit,
        "analytic_diagnostic_config_id": (
            None
            if analytic_diagnostics is None
            else PHASE1_ANALYTIC_DIAGNOSTIC_CONFIG_ID
        ),
        "analytic_diagnostic_family_size": (
            0 if analytic_diagnostics is None else BLOOM_FAMILY_SIZE
        ),
        "analytic_diagnostic_fwer_consistent_rows": (
            None if overlay_audit is None else overlay_audit["fwer_consistent_rows"]
        ),
        "analytic_diagnostic_fwer_inconsistent_rows": (
            None if overlay_audit is None else overlay_audit["fwer_inconsistent_rows"]
        ),
        "analytic_diagnostic_robust_overlap_rows": (
            None if overlay_audit is None else overlay_audit["robust_overlap_rows"]
        ),
        "analytic_diagnostic_robust_separation_rows": (
            None if overlay_audit is None else overlay_audit["robust_separation_rows"]
        ),
        "analytic_diagnostic_ambiguous_numeric_rows": (
            None if overlay_audit is None else overlay_audit["ambiguous_numeric_rows"]
        ),
        "analytic_diagnostic_numeric_contract": (
            None
            if analytic_diagnostics is None
            else analytic_diagnostics["familywise_rule"]["numeric_contract"]
        ),
        "analytic_diagnostic_bias_direction_counts": (
            None if overlay_audit is None else overlay_audit["bias_direction_counts"]
        ),
        "analytic_diagnostic_consistency_rule": (
            None if analytic_diagnostics is None else SIMULTANEOUS_RULE
        ),
        "legacy_ideal_model_uncovered_rows": bloom_ideal_model_uncovered,
        "analytic_model_validation_status": ANALYTIC_MODEL_VALIDATION_STATUS,
        "analytic_model_agreement_claim_permitted": (
            ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED
        ),
        "e1_bloom_analytic_unresolved_rows": bloom_unresolved,
        "e1_bloom_query_path_reproduction_gate": (
            "PASS" if overlay_family_pass else "BLOCKED"
        ),
        "e1_bloom_analytic_model_validation_status": (
            ANALYTIC_MODEL_VALIDATION_STATUS
        ),
        "phase1_evidence_status": "PASS" if qualification_pass else "BLOCKED",
        "phase1_p0b_qualification_status": (
            "PASS_EMPIRICAL_QUERY_PATH_REPRODUCIBILITY"
            if qualification_pass
            else "BLOCKED"
        ),
        "e1_bloom_query_path_reproduction_gate_interpretation": (
            "PASS establishes only complete empirical query-path reproduction; "
            "it does not establish finite/standard analytic-model agreement"
        ),
        "e1_bloom_query_path_reproduction_gate_rule": (
            "all 7680 overlay rows must be ROBUST_OVERLAP, with zero robust "
            "separations and zero numeric ambiguities; this is not analytic-model "
            "validation"
        ),
        "phase1_p0b_qualification_rule": (
            "the query-path reproduction gate must pass and every ideal-model "
            "exclusion must be explicitly explained by a frozen machine-verifiable "
            "anomaly contract"
        ),
        "profile_definitions": PROFILE_DEFINITIONS,
        "frontier_rule": PHASE1_FRONTIER_RULE,
        "formal_timing_status": "BLOCKED_PENDING_ISOLATED_TIMING_RUN",
    }


def write_csv(path: Path, rows: list[dict[str, Any]], overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(path)
    if not rows:
        raise ValueError("cannot write an empty summary")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, value: object, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def plot_frontier(prefix: Path, summaries: list[dict[str, Any]], overwrite: bool) -> None:
    import matplotlib.pyplot as plt

    outputs = [prefix.with_suffix(".pdf"), prefix.with_suffix(".png")]
    for output in outputs:
        if output.exists() and not overwrite:
            raise FileExistsError(output)
    prefix.parent.mkdir(parents=True, exist_ok=True)

    families = {
        "tag": ("#0072B2", "o"),
        "global_bloom": ("#D55E00", "s"),
        "blocked_bloom": ("#009E73", "^"),
        "xor": ("#CC79A7", "D"),
        "cuckoo": ("#E69F00", "v"),
    }

    def family(method: str) -> str:
        if "tag" in method:
            return "tag"
        if "blocked_bloom" in method:
            return "blocked_bloom"
        if "global_bloom" in method:
            return "global_bloom"
        if "xor" in method:
            return "xor"
        return "cuckoo"

    def y_value(row: dict[str, Any]) -> float:
        return max(
            0.5 / int(row["first_seen_trials_pooled"]),
            float(row["first_seen_ffr_mean"]),
        )

    figure, axes = plt.subplots(1, 2, figsize=(7.0, 2.8), constrained_layout=True)
    for axis, profile in zip(axes, ("U", "A"), strict=True):
        eligibility_field = f"eligible_profile_{profile}_all_seeds"
        for family_name, (color, marker) in families.items():
            eligible = [
                row
                for row in summaries
                if family(row["method"]) == family_name and row[eligibility_field]
            ]
            if eligible:
                axis.scatter(
                    [row["memory_total_edge_bytes_mean"] for row in eligible],
                    [y_value(row) for row in eligible],
                    s=13,
                    alpha=0.42,
                    color=color,
                    marker=marker,
                    linewidths=0,
                    label=family_name.replace("_", " "),
                )
            if profile == "A" and family_name == "tag":
                references = [
                    row for row in summaries if row["cross_profile_reference_A"]
                ]
                axis.scatter(
                    [row["memory_total_edge_bytes_mean"] for row in references],
                    [y_value(row) for row in references],
                    s=18,
                    facecolors="none",
                    edgecolors=color,
                    marker=marker,
                    linewidths=0.8,
                    label="tag (cross-profile reference)",
                )
        frontier = sorted(
            (row for row in summaries if row[f"pareto_{profile}_memory_ffr"]),
            key=lambda row: row["memory_total_edge_bytes_mean"],
        )
        axis.plot(
            [row["memory_total_edge_bytes_mean"] for row in frontier],
            [y_value(row) for row in frontier],
            color="#222222",
            linewidth=1.0,
            label="eligible Pareto frontier",
        )
        axis.set_xscale("log", base=2)
        axis.set_yscale("log")
        axis.set_title(f"Profile {profile}")
        axis.set_xlabel("Total edge state (bytes)")
        axis.grid(True, which="both", linewidth=0.35, alpha=0.35)
    axes[0].set_ylabel("First-seen false-forward rate")
    handles, labels = axes[0].get_legend_handles_labels()
    by_label = dict(zip(labels, handles, strict=True))
    figure.legend(
        by_label.values(),
        by_label.keys(),
        loc="outside lower center",
        ncol=3,
        frameon=False,
        fontsize=7,
    )
    figure.savefig(outputs[0])
    figure.savefig(outputs[1], dpi=240)
    plt.close(figure)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--expected-shards", type=int, required=True)
    parser.add_argument("--expected-rows", type=int)
    parser.add_argument("--expected-commit")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--clean-source-attestation", type=Path)
    parser.add_argument("--analytic-diagnostic-artifact", type=Path)
    parser.add_argument("--expected-diagnostic-commit")
    parser.add_argument("--summary-csv", type=Path, required=True)
    parser.add_argument("--audit-json", type=Path, required=True)
    parser.add_argument("--figure-prefix", type=Path, required=True)
    parser.add_argument("--require-phase1-grid", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if (args.analytic_diagnostic_artifact is None) != (
        args.expected_diagnostic_commit is None
    ):
        raise ValueError(
            "--analytic-diagnostic-artifact and --expected-diagnostic-commit "
            "must be supplied together"
        )
    attestation = (
        load_clean_attestation(args.clean_source_attestation)
        if args.clean_source_attestation is not None
        else None
    )
    analytic_diagnostics = (
        load_analytic_diagnostics(
            args.analytic_diagnostic_artifact,
            args.expected_diagnostic_commit,
        )
        if args.analytic_diagnostic_artifact is not None
        else None
    )
    if args.require_phase1_grid and (args.config is None or args.expected_commit is None):
        raise ValueError(
            "--require-phase1-grid also requires --config and --expected-commit"
        )
    rows, audit = load_shards(
        args.input_dir,
        args.expected_shards,
        args.expected_rows,
        args.expected_commit,
        PHASE1_CONFIG_ID if args.require_phase1_grid else None,
        PHASE1_DATASET_ID if args.require_phase1_grid else None,
        require_clean_provenance=args.require_phase1_grid,
        clean_attestation=attestation,
    )
    summaries = summarize(rows)
    if args.require_phase1_grid:
        assert args.config is not None and args.expected_commit is not None
        audit.update(
            validate_phase1_grid(
                rows,
                summaries,
                args.config,
                args.expected_commit,
                args.expected_shards,
                attestation,
                analytic_diagnostics,
            )
        )
        audit["status"] = audit["phase1_evidence_status"]
    audit["summary_point_count"] = len(summaries)
    audit["profile_u_pareto_points"] = sum(
        bool(row["pareto_U_memory_ffr"]) for row in summaries
    )
    audit["profile_a_pareto_points"] = sum(
        bool(row["pareto_A_memory_ffr"]) for row in summaries
    )
    if args.require_phase1_grid:
        audit["phase1_aggregate_identity_schema"] = (
            PHASE1_AGGREGATE_IDENTITY_SCHEMA
        )
        audit["phase1_aggregate_identity"] = compute_phase1_aggregate_identity(
            summaries, audit
        )
    write_csv(args.summary_csv, summaries, args.overwrite)
    write_json(args.audit_json, audit, args.overwrite)
    plot_frontier(args.figure_prefix, summaries, args.overwrite)
    print(json.dumps(audit, sort_keys=True))
    return 0 if audit["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
