#!/usr/bin/env python3
"""Strict raw aggregation for the Phase 1 timing-frontier v2 protocol."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import statistics
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from scipy.stats import beta as beta_distribution
from scipy.stats import t as student_t

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.analysis import filter_frontier as source_frontier  # noqa: E402
from experiments.analysis import filter_timing_aggregate as v1_aggregate  # noqa: E402
from experiments.runners import filter_analytic_diagnostic as diagnostic_runner  # noqa: E402
from experiments.runners import filter_timing as v1_timing  # noqa: E402
from experiments.runners import filter_timing_frontier_v2 as runner  # noqa: E402
from experiments.runners.filter_bench import SyntheticCredentialSet  # noqa: E402

AGGREGATE_SCHEMA = "traps-phase1-timing-frontier-v2-aggregate-v2"
LOOK1_DECISION_SCHEMA = "traps-phase1-v2-look1-extension-decision-v2"
SOURCE_BINDING_SCHEMA = "traps-phase1-v2-source-evidence-binding-v1"
SUPPORT_BINDING_SCHEMA = "traps-phase1-v2-support-receipts-binding-v1"
POINT_SCHEMA = "traps-phase1-timing-frontier-v2-point-v1"
VALID_COMPLETE = "VALID_COMPLETE"
VALID_BUT_NONPROMOTABLE = "VALID_BUT_NONPROMOTABLE"
INVALID_EVIDENCE = "INVALID_EVIDENCE"
PASS_STOP_N20 = "PASS_STOP_N20"
REQUIRE_FULL_LOOK2 = "REQUIRE_FULL_LOOK2"
STOP_NONPROMOTABLE_TIMER_RESOLUTION = "STOP_NONPROMOTABLE_TIMER_RESOLUTION"
STOP_NONPROMOTABLE_HARDWARE_STRATUM = "STOP_NONPROMOTABLE_HARDWARE_STRATUM"
LOOK1_DECISION_RULE = "hardware_stratum_then_timer_resolution_then_precision_v2"
PRIMARY_METRIC = "indexed_directory_to_screen_decision_warm_p99_us"
QUERY_ONLY_METRIC = "filter_query_only_warm_p99_us"
TIMER_MINIMUM_RATIO = 10.0
PRECISION_LIMIT = 0.05
SOURCE_SHARDS = 36
SOURCE_ROWS = 7_868
SOURCE_POINTS = 794
SOURCE_RANDOMIZED_CONSTRUCTIONS = 10
SOURCE_STATIC_CONSTRUCTIONS = 1
SOURCE_AGGREGATE_SCHEMA = "phase1-selection-aggregate-v2"
V1_RELATION_COUNT = 28
V1_PAIRED_SEED_COUNT = 20
V1_MARGIN = 1.05
V1_FAMILYWISE_ALPHA = 0.05
HEX64 = frozenset("0123456789abcdef")

CLOCK_KEYS = frozenset(
    {
        "api",
        "implementation",
        "monotonic",
        "adjustable",
        "resolution_seconds",
        "resolution_ns",
        "call_pattern",
        "overhead_measurement",
        "overhead_sample_count",
        "overhead_histogram_ns",
        "overhead_p50_ns",
        "overhead_p95_ns",
        "overhead_p99_ns",
    }
)
HOST_ENVIRONMENT_KEYS = frozenset(
    {
        "host_platform",
        "hostname",
        "python_version",
        "cpu_model",
        "cpu_model_source",
        "logical_cpu_count",
        "affinity_cpus",
        "affinity_cpu_count",
        "affinity_cpu_records",
        "scaling_governor_by_affinity_cpu",
        "declared_benchmark_process_concurrency",
        "exclusive_host_human_declared",
        "exclusive_host_automatically_verified",
        "load_average_1m_5m_15m",
        "host_lock_path",
        "host_lock_required_for_formal",
        "host_lock_scope",
        "same_runner_host_lock_acquired",
        "source_evidence_binding_id",
        "corpus_equivalence_receipt_id",
        "corpus_equivalence_dataset_id",
        "construction_feasibility_receipt_id",
        "construction_feasibility_status",
        "construction_feasibility_build_count",
        "look1_extension_decision_receipt_id",
        "expected_look1_extension_decision_id",
        "timing_clock",
    }
)
COMMON_ROW_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "timestamp_utc",
        "protocol",
        "formal_timing",
        "result_status",
        "source_commit",
        "expected_source_commit",
        "git_dirty",
        "source_status_scope",
        "semantic_config_id",
        "semantic_dataset_id",
        "source_evidence_mode",
        "source_filter_grid_commit",
        "source_filter_grid_semantic_config_id",
        "source_filter_grid_semantic_dataset_id",
        "source_filter_grid_aggregate_identity",
        "source_filter_grid_attestation_id",
        "source_ffr_randomized_construction_count",
        "source_ffr_static_tag_construction_count",
        "source_ffr_randomized_interval",
        "source_ffr_static_tag_interval",
        "source_evidence_binding_id",
        "corpus_equivalence_receipt_id",
        "construction_feasibility_receipt_id",
        "construction_feasibility_status",
        "construction_feasibility_build_count",
        "look1_extension_decision_receipt_id",
        "expected_look1_extension_decision_id",
        "corpus_public_api_equivalence",
        "stage",
        "measurement_trial_seed",
        "construction_seed",
        "global_seed_ordinal",
        "measurement_order",
        "shard_index",
        "shard_count",
        "method",
        "family",
        "spec_identity",
        "spec_id",
        "spec_universe_count",
        "configured_spec",
        "filter_parameters",
        "randomized_construction",
        "account_count",
        "build_time_s",
        "memory_payload_bytes",
        "memory_metadata_bytes",
        "memory_alignment_bytes",
        "memory_compact_total_bytes",
        "memory_filter_bytes",
        "memory_directory_extra_bytes",
        "memory_common_prf_key_bytes",
        "memory_total_edge_bytes",
        "analytic_fpr_finite",
        "analytic_fpr_standard",
        "timing_clock",
        "host_environment",
        "observation_sha256",
    }
)
WARM_ONLY_ROW_KEYS = frozenset(
    {
        "primary_timing_metric",
        "actual_front_timing_interval",
        "actual_front_timing_excludes",
        "query_only_timing_interval",
        "path_measurement_order",
        "query_window_assignment",
        "query_window_start",
        "query_window_end_exclusive",
        "query_pool_count",
        "warmup_query_count",
        "preflight_query_count",
        "member_validation_count",
        "member_false_negatives",
        "preflight_query_only_positive_count",
        "preflight_path_decision_mismatch_count",
        "actual_front_throughput_query_count_per_trial",
        "actual_front_throughput_repetition_count",
        "actual_front_throughput_qps_trials",
        "actual_front_throughput_qps_mean",
        "actual_front_latency_sample_count",
        "actual_front_warm_latency_histogram_ns",
        "indexed_directory_to_screen_decision_warm_p50_us",
        "indexed_directory_to_screen_decision_warm_p95_us",
        "indexed_directory_to_screen_decision_warm_p99_us",
        "primary_p99_to_clock_call_p99_ratio",
        "primary_p99_to_clock_call_p99_minimum",
        "primary_p99_to_clock_call_p99_gate_pass",
        "query_only_latency_sample_count",
        "query_only_warm_latency_histogram_ns",
        "filter_query_only_warm_p50_us",
        "filter_query_only_warm_p95_us",
        "filter_query_only_warm_p99_us",
        "precision_rule",
    }
)
COLD_ONLY_ROW_KEYS = frozenset(
    {
        "primary_timing_metric",
        "diagnostic_timing_metric",
        "query_only_timing_interval",
        "cold_claim_scope",
        "member_validation_count",
        "member_false_negatives",
        "cold_latency_sample_count",
        "query_only_cold_latency_histogram_ns",
        "filter_query_only_cold_p50_us",
        "filter_query_only_cold_p95_us",
        "filter_query_only_cold_p99_us",
        "cold_query_window_start",
        "cold_query_window_end_exclusive",
        "cold_eviction_bytes_per_query",
        "cold_eviction_method",
        "cold_eviction_per_query",
        "cold_eviction_time_excluded",
        "cold_eviction_last_level_cache_bytes",
        "cold_eviction_buffer_to_llc_ratio",
        "cold_eviction_minimum_llc_multiple",
        "cold_eviction_terminal_token",
    }
)


class AggregateValidationError(ValueError):
    """Raised when raw evidence violates the frozen v2 contract."""


@dataclass(frozen=True)
class SourceEvidence:
    binding: dict[str, Any]
    records: dict[tuple[str, str], dict[str, Any]]


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _is_hex64(value: object) -> bool:
    return (
        type(value) is str and len(value) == 64 and all(character in HEX64 for character in value)
    )


def _reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AggregateValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise AggregateValidationError(f"non-finite JSON number: {value}")


def _reject_nonfinite(value: Any, path: str = "$") -> None:
    if type(value) is float and not math.isfinite(value):
        raise AggregateValidationError(f"{path} contains a non-finite number")
    if type(value) is dict:
        for key, nested in value.items():
            _reject_nonfinite(nested, f"{path}.{key}")
    elif type(value) is list:
        for index, nested in enumerate(value):
            _reject_nonfinite(nested, f"{path}[{index}]")


def load_strict_json(path: Path, expected_type: type[Any]) -> Any:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_pairs,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AggregateValidationError(f"cannot load strict JSON from {path}") from error
    if type(value) is not expected_type:
        raise AggregateValidationError(f"{path} must contain a JSON {expected_type.__name__}")
    _reject_nonfinite(value)
    return value


def _same_exact(expected: Any, actual: Any, path: str = "$") -> None:
    if type(expected) is not type(actual):
        raise AggregateValidationError(
            f"{path} type mismatch: {type(expected).__name__} != {type(actual).__name__}"
        )
    if type(expected) is dict:
        if set(expected) != set(actual):
            raise AggregateValidationError(f"{path} mapping keys differ")
        for key in expected:
            _same_exact(expected[key], actual[key], f"{path}.{key}")
        return
    if type(expected) is list:
        if len(expected) != len(actual):
            raise AggregateValidationError(f"{path} list length differs")
        for index, (left, right) in enumerate(zip(expected, actual, strict=True)):
            _same_exact(left, right, f"{path}[{index}]")
        return
    if expected != actual:
        raise AggregateValidationError(f"{path} value differs")


def _analysis_checkout_binding(expected_source_commit: str) -> dict[str, Any]:
    """Bind aggregation to the exact clean checkout used for formal timing."""

    try:
        commit = runner._verify_source_pin(expected_source_commit)
    except (ValueError, RuntimeError) as error:
        raise AggregateValidationError(
            "analysis checkout is not the exact clean frozen source"
        ) from error
    return {
        "analysis_source_commit": commit,
        "analysis_source_clean": True,
        "analysis_source_status_scope": source_frontier.SOURCE_STATUS_SCOPE,
    }


def _require_exact(actual: Any, expected: Any, path: str) -> None:
    try:
        _same_exact(expected, actual, path)
    except AggregateValidationError:
        raise


def _integer(value: Any, path: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < 0 or (positive and value == 0):
        qualifier = "positive" if positive else "nonnegative"
        raise AggregateValidationError(f"{path} must be an exact {qualifier} integer")
    return value


def _number(value: Any, path: str, *, positive: bool = False) -> float:
    if type(value) not in {int, float}:
        raise AggregateValidationError(f"{path} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0.0 or (positive and result == 0.0):
        qualifier = "positive" if positive else "nonnegative"
        raise AggregateValidationError(f"{path} must be finite and {qualifier}")
    return result


def _parse_utc(value: Any, path: str) -> datetime:
    if type(value) is not str:
        raise AggregateValidationError(f"{path} must be a UTC string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AggregateValidationError(f"{path} is not an ISO timestamp") from error
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise AggregateValidationError(f"{path} is not UTC")
    return parsed


def _source_pin(source: Mapping[str, Any], key: str, expected_type: type[Any]) -> Any:
    if key not in source or type(source[key]) is not expected_type:
        raise AggregateValidationError(f"source_evidence.{key} is missing or mistyped")
    return source[key]


def _reaggregate_diagnostic_raw(
    *,
    input_dir: Path,
    supplied: Mapping[str, Any],
    expected_diagnostic_commit: str,
) -> None:
    """Rebuild the diagnostic row/manifest closure without trusting its aggregate."""

    try:
        contract = diagnostic_runner.load_contract()
        targets = diagnostic_runner.load_bloom_targets(contract)
        expected_order = [target.run_id for target in targets]
        order_by_id = {run_id: index for index, run_id in enumerate(expected_order)}
        discovered = diagnostic_runner._discover_shards(input_dir, SOURCE_SHARDS)
        normalized_rows: list[dict[str, Any]] = []
        normalized_manifests: list[dict[str, Any]] = []
        seen: set[str] = set()
        for shard_index, result_path, manifest_path in discovered:
            raw_rows = diagnostic_runner._load_jsonl(result_path)
            start, stop = diagnostic_runner.shard_bounds(len(targets), shard_index, SOURCE_SHARDS)
            expected_targets = targets[start:stop]
            if [str(row.get("target_run_id")) for row in raw_rows] != [
                target.run_id for target in expected_targets
            ]:
                raise ValueError("diagnostic raw shard violates frozen target order")
            shard_rows: list[dict[str, Any]] = []
            for raw_row, target in zip(raw_rows, expected_targets, strict=True):
                if target.run_id in seen:
                    raise ValueError("diagnostic raw duplicates a target")
                seen.add(target.run_id)
                shard_rows.append(
                    diagnostic_runner._validate_result_row(
                        raw_row,
                        target,
                        contract,
                        expected_diagnostic_commit,
                        shard_index,
                    )
                )
            manifest = diagnostic_runner._load_manifest(manifest_path)
            normalized_manifest = diagnostic_runner._validate_manifest(
                manifest,
                shard_rows,
                result_path.name,
                contract,
                expected_diagnostic_commit,
                shard_index,
            )
            normalized_rows.extend(shard_rows)
            normalized_manifests.append(normalized_manifest)
        if (
            seen != set(expected_order)
            or len(normalized_rows) != diagnostic_runner.BLOOM_FAMILY_SIZE
        ):
            raise ValueError("diagnostic raw target universe is incomplete")
        normalized_rows.sort(key=lambda row: order_by_id[str(row["target_run_id"])])
        normalized_manifests.sort(key=lambda row: int(row["shard_index"]))
        direction_counts = {
            direction: sum(row["systematic_bias_direction"] == direction for row in normalized_rows)
            for direction in ("exact_higher", "exact_lower", "equal")
        }
        relation_counts = {
            relation: sum(row["fwer_interval_relation"] == relation for row in normalized_rows)
            for relation in diagnostic_runner.INTERVAL_RELATIONS
        }
        rebuilt_audit = diagnostic_runner._expected_aggregate_audit(
            relation_counts, direction_counts
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise AggregateValidationError(
            "analytic diagnostic raw shard reaggregation failed"
        ) from error
    _same_exact(
        normalized_rows,
        supplied.get("diagnostic_rows"),
        "analytic_diagnostic.diagnostic_rows",
    )
    _same_exact(
        normalized_manifests,
        supplied.get("execution_manifests"),
        "analytic_diagnostic.execution_manifests",
    )
    _same_exact(rebuilt_audit, supplied.get("audit"), "analytic_diagnostic.audit")


def _load_source_frontier_summary(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise AggregateValidationError(
                    "source frontier summary has missing or duplicate headers"
                )
            rows = [
                source_frontier.normalize_phase1_selection_summary(row)
                for row in reader
            ]
    except AggregateValidationError:
        raise
    except (OSError, UnicodeError, csv.Error, ValueError) as error:
        raise AggregateValidationError("cannot load source frontier summary") from error
    if len(rows) != SOURCE_POINTS:
        raise AggregateValidationError("source frontier summary does not contain 794 points")
    return rows


def _configured_mapping(value: Any, path: str) -> dict[str, Any]:
    if type(value) is dict:
        result = value
    elif type(value) is str:
        try:
            result = json.loads(value, object_pairs_hook=_reject_pairs)
        except json.JSONDecodeError as error:
            raise AggregateValidationError(f"{path} is not canonical JSON") from error
        if type(result) is not dict or _canonical(result) != value:
            raise AggregateValidationError(f"{path} is not a canonical mapping")
    else:
        raise AggregateValidationError(f"{path} must be a configured-spec mapping")
    _reject_nonfinite(result, path)
    return result


def _identity(method: object, configured: object) -> tuple[str, str]:
    return str(method), _canonical(_configured_mapping(configured, "configured_spec"))


def _family_for_method(method: str) -> str:
    if method == "exact_tag_128" or method.startswith("truncated_tag_"):
        return "tag"
    return {
        "global_bloom": "global_bloom",
        "blocked_bloom_64b": "blocked_bloom",
        "xor_static_3way": "xor_static",
        "cuckoo_filter": "cuckoo",
    }[method]


def _spec_identity(identity: tuple[str, str]) -> str:
    return _canonical(
        {
            "family": _family_for_method(identity[0]),
            "parameters": json.loads(identity[1]),
        }
    )


def _point_id(identity: tuple[str, str]) -> str:
    return hashlib.sha256(_spec_identity(identity).encode()).hexdigest()


def _source_binding_id(binding: Mapping[str, Any]) -> str:
    material = dict(binding)
    material.pop("source_evidence_binding_id", None)
    return _sha256(material)


def _simultaneous_ffr_interval(
    group: Sequence[dict[str, Any]], coordinate_alpha: float
) -> tuple[int, int, float, float, float, str]:
    successes = sum(
        _integer(row.get("backend_invalid_checks"), "source.successes") for row in group
    )
    trials = sum(
        _integer(row.get("distinct_invalid_count"), "source.trials", positive=True) for row in group
    )
    if not 0 < coordinate_alpha < 1.0:
        raise AggregateValidationError("coordinate alpha is outside (0,1)")
    lower = (
        0.0
        if successes == 0
        else float(beta_distribution.ppf(coordinate_alpha / 2.0, successes, trials - successes + 1))
    )
    upper = (
        1.0
        if successes == trials
        else float(
            beta_distribution.ppf(
                1.0 - coordinate_alpha / 2.0,
                successes + 1,
                trials - successes,
            )
        )
    )
    rates = [
        _integer(row.get("backend_invalid_checks"), "source.successes")
        / _integer(row.get("distinct_invalid_count"), "source.trials", positive=True)
        for row in group
    ]
    if len(rates) >= 2:
        center = statistics.fmean(rates)
        standard_error = statistics.stdev(rates) / math.sqrt(len(rates))
        critical = float(student_t.ppf(1.0 - coordinate_alpha / 2.0, len(rates) - 1))
        lower = min(lower, max(0.0, center - critical * standard_error))
        upper = max(upper, min(1.0, center + critical * standard_error))
        method = (
            "outer_envelope_of_pooled_clopper_pearson_and_construction_t_"
            "at_simultaneous_coordinate_alpha"
        )
    else:
        method = "pooled_clopper_pearson_at_simultaneous_coordinate_alpha"
    return successes, trials, successes / trials, lower, upper, method


def _validate_v2_environment(row: Mapping[str, Any]) -> str:
    environment = row.get("host_environment")
    if type(environment) is not dict:
        raise ValueError("formal timing environment is missing")
    required = {
        "host_platform",
        "hostname",
        "python_version",
        "cpu_model",
        "cpu_model_source",
        "logical_cpu_count",
        "affinity_cpus",
        "affinity_cpu_count",
        "affinity_cpu_records",
        "scaling_governor_by_affinity_cpu",
        "declared_benchmark_process_concurrency",
        "exclusive_host_human_declared",
        "exclusive_host_automatically_verified",
        "host_lock_required_for_formal",
        "host_lock_scope",
        "same_runner_host_lock_acquired",
    }
    missing = required - environment.keys()
    if missing:
        raise ValueError(f"timing environment missing {sorted(missing)}")
    affinity = environment["affinity_cpus"]
    records = environment["affinity_cpu_records"]
    if (
        not isinstance(affinity, list)
        or len(affinity) != 1
        or isinstance(affinity[0], bool)
        or not isinstance(affinity[0], int)
        or type(environment["affinity_cpu_count"]) is not int
        or environment["affinity_cpu_count"] != 1
        or type(environment["logical_cpu_count"]) is not int
        or environment["logical_cpu_count"] <= 0
    ):
        raise ValueError("formal timing requires one recorded affinity CPU")
    if (
        not isinstance(records, list)
        or len(records) != 1
        or not isinstance(records[0], dict)
        or type(records[0].get("logical_cpu")) is not int
        or records[0].get("logical_cpu") != affinity[0]
        or not str(records[0].get("model_name", "")).strip()
        or records[0].get("model_name") == "unknown"
        or not str(records[0].get("model_name_source", "")).strip()
        or records[0].get("model_name_source") == "unavailable"
        or not str(records[0].get("scaling_governor", "")).strip()
    ):
        raise ValueError("formal timing affinity CPU description is incomplete")
    record = records[0]
    v1_aggregate._validated_last_level_cache(record)
    if environment["cpu_model_source"] != "unique affinity_cpu_records[0].model_name":
        raise ValueError("formal timing CPU model source is not affinity-specific")
    if environment["cpu_model"] != record["model_name"]:
        raise ValueError("formal timing CPU model disagrees with affinity CPU record")
    governors = environment["scaling_governor_by_affinity_cpu"]
    expected_governors = {str(affinity[0]): record.get("scaling_governor")}
    if governors != expected_governors:
        raise ValueError("formal timing governor mapping disagrees with affinity CPU record")
    if (
        type(environment["declared_benchmark_process_concurrency"]) is not int
        or environment["declared_benchmark_process_concurrency"] != 1
    ):
        raise ValueError("formal timing declared concurrency is not one")
    if environment["exclusive_host_human_declared"] is not True:
        raise ValueError("formal timing lacks the human exclusive-host declaration")
    if environment["exclusive_host_automatically_verified"] is not False:
        raise ValueError("exclusive-host status must not be presented as auto-verified")
    if environment["host_lock_required_for_formal"] is not True:
        raise ValueError("formal timing host-lock contract is missing")
    if environment["same_runner_host_lock_acquired"] is not True:
        raise ValueError("formal timing did not record its cooperating-runner lock")
    if environment["host_lock_scope"] != "cooperating TRAPS v2 timing processes only":
        raise ValueError("formal timing v2 host-lock scope mismatch")
    return v1_aggregate._hardware_stratum(environment)


def validate_source_evidence(
    *,
    config: Mapping[str, Any],
    frontier_audit_path: Path,
    frontier_summary_path: Path,
    grid_dir: Path,
    grid_config_path: Path,
    clean_attestation_path: Path,
    diagnostic_raw_dir: Path,
    diagnostic_artifact_path: Path,
) -> SourceEvidence:
    """Recompute and validate the frozen 794-point functional evidence."""

    source = config.get("source_evidence")
    if type(source) is not dict:
        raise AggregateValidationError("source_evidence must be a mapping")
    base_commit = _source_pin(source, "filter_grid_commit", str)
    base_config_id = _source_pin(source, "filter_grid_semantic_config_id", str)
    base_dataset_id = _source_pin(source, "filter_grid_semantic_dataset_id", str)
    base_attestation_id = _source_pin(source, "filter_grid_attestation_id", str)
    base_shards = _source_pin(source, "filter_grid_shard_count", int)
    base_rows = _source_pin(source, "filter_grid_raw_row_count", int)
    base_points = _source_pin(source, "filter_grid_spec_count", int)
    base_aggregate_schema = _source_pin(source, "filter_grid_aggregate_identity_schema", str)
    base_aggregate_id = _source_pin(source, "filter_grid_aggregate_identity", str)
    diagnostic_schema = _source_pin(source, "diagnostic_schema_version", int)
    diagnostic_protocol = _source_pin(source, "diagnostic_protocol", str)
    diagnostic_commit = _source_pin(source, "diagnostic_source_commit", str)
    diagnostic_config_id = _source_pin(source, "diagnostic_config_id", str)
    diagnostic_family_size = _source_pin(source, "diagnostic_family_size", int)
    expected_overlap = _source_pin(source, "diagnostic_robust_overlap_count", int)
    expected_separation = _source_pin(source, "diagnostic_robust_separation_count", int)
    expected_ambiguous = _source_pin(source, "diagnostic_ambiguous_count", int)
    if (
        base_shards != SOURCE_SHARDS
        or base_rows != SOURCE_ROWS
        or base_points != SOURCE_POINTS
        or base_aggregate_schema != SOURCE_AGGREGATE_SCHEMA
    ):
        raise AggregateValidationError("source Phase 1 grid pins differ from the freeze")
    if not _is_hex64(base_aggregate_id):
        raise AggregateValidationError("source aggregate identity is malformed")

    try:
        if not grid_dir.exists():
            raise ValueError("source grid directory is missing")
        if not grid_config_path.exists():
            raise ValueError("source grid config is missing")
        attestation = source_frontier.load_clean_attestation(clean_attestation_path)
        diagnostic = source_frontier.load_analytic_diagnostics(
            diagnostic_artifact_path, diagnostic_commit
        )
        _reaggregate_diagnostic_raw(
            input_dir=diagnostic_raw_dir,
            supplied=diagnostic,
            expected_diagnostic_commit=diagnostic_commit,
        )
        audit = load_strict_json(frontier_audit_path, dict)
        summaries = _load_source_frontier_summary(frontier_summary_path)
    except (OSError, UnicodeError, ValueError) as error:
        raise AggregateValidationError("Phase 1 source evidence revalidation failed") from error
    if attestation.get("semantic_attestation_id") != base_attestation_id:
        raise AggregateValidationError("clean-source attestation ID mismatch")
    expected_audit_fields = {
        "commit": base_commit,
        "semantic_config_id": base_config_id,
        "semantic_dataset_id": base_dataset_id,
        "clean_source_attestation_id": base_attestation_id,
        "row_count": base_rows,
        "shard_count": base_shards,
        "summary_point_count": base_points,
        "phase1_aggregate_identity_schema": base_aggregate_schema,
        "phase1_aggregate_identity": base_aggregate_id,
        "status": "PASS",
        "phase1_cartesian_grid_status": "PASS",
        "phase1_evidence_status": "PASS",
        "member_false_negatives": 0,
    }
    for key, expected in expected_audit_fields.items():
        _require_exact(audit.get(key), expected, f"source_frontier_audit.{key}")
    aggregate_id = source_frontier.compute_phase1_aggregate_identity(summaries, audit)
    if aggregate_id != base_aggregate_id:
        raise AggregateValidationError("recomputed Phase 1 aggregate identity mismatch")
    diagnostic_audit = diagnostic.get("audit")
    if type(diagnostic_audit) is not dict:
        raise AggregateValidationError("analytic diagnostic audit is missing")
    expected_diagnostic = {
        "schema_version": diagnostic_schema,
        "diagnostic_protocol": diagnostic_protocol,
        "diagnostic_source_commit": diagnostic_commit,
        "diagnostic_config_id": diagnostic_config_id,
        "family_size": diagnostic_family_size,
        "robust_overlap_rows": expected_overlap,
        "robust_separation_rows": expected_separation,
        "ambiguous_numeric_rows": expected_ambiguous,
    }
    actual_diagnostic = {
        "schema_version": diagnostic.get("schema_version"),
        "diagnostic_protocol": diagnostic.get("diagnostic_protocol"),
        "diagnostic_source_commit": diagnostic.get("diagnostic_source_commit"),
        "diagnostic_config_id": diagnostic.get("diagnostic_config_id"),
        "family_size": diagnostic_audit.get("expected_rows"),
        "robust_overlap_rows": diagnostic_audit.get("robust_overlap_rows"),
        "robust_separation_rows": diagnostic_audit.get("robust_separation_rows"),
        "ambiguous_numeric_rows": diagnostic_audit.get("ambiguous_numeric_rows"),
    }
    _same_exact(expected_diagnostic, actual_diagnostic, "analytic_diagnostic")
    if (
        audit.get("phase1_cartesian_grid_status") != "PASS"
        or audit.get("phase1_evidence_status") != "PASS"
        or audit.get("query_path_reproduction_status") != "PASS_ALL_7680_QUERY_PATHS_REPRODUCED"
        or audit.get("analytic_diagnostic_robust_overlap_rows") != expected_overlap
        or audit.get("analytic_diagnostic_robust_separation_rows") != expected_separation
        or audit.get("analytic_diagnostic_ambiguous_numeric_rows") != expected_ambiguous
    ):
        raise AggregateValidationError("Phase 1 source evidence does not pass its frozen gates")

    summary_by_identity: dict[tuple[str, str], dict[str, Any]] = {
        _identity(row.get("method"), row.get("configured_spec")): row for row in summaries
    }
    expected_identities = {
        (runner._method_for_spec(spec), _canonical(spec.parameters))
        for spec in runner.expand_specs(dict(config))
    }
    if len(summary_by_identity) != SOURCE_POINTS or set(summary_by_identity) != expected_identities:
        raise AggregateValidationError("source evidence does not contain exactly 794 identities")
    records: dict[tuple[str, str], dict[str, Any]] = {}
    for identity, summary in sorted(summary_by_identity.items()):
        summary = summary_by_identity[identity]
        is_tag = identity[0] == "exact_tag_128" or identity[0].startswith("truncated_tag_")
        expected_constructions = (
            SOURCE_STATIC_CONSTRUCTIONS if is_tag else SOURCE_RANDOMIZED_CONSTRUCTIONS
        )
        constructions = _integer(
            summary.get("independent_constructions"),
            "source.independent_constructions",
            positive=True,
        )
        if constructions != expected_constructions:
            raise AggregateValidationError("source construction count mismatch")
        memory = _number(
            summary.get("memory_total_edge_bytes_mean"),
            "source.memory_total_edge_bytes_mean",
            positive=True,
        )
        if not memory.is_integer():
            raise AggregateValidationError("source memory summary must be an exact integer")
        successes = _integer(
            summary.get("first_seen_false_positives_pooled"),
            "source.first_seen_false_positives_pooled",
        )
        trials = _integer(
            summary.get("first_seen_trials_pooled"),
            "source.first_seen_trials_pooled",
            positive=True,
        )
        expected_trials = 10_000_000 if is_tag else 100_000_000
        if trials != expected_trials or successes > trials:
            raise AggregateValidationError("source FFR counts mismatch")
        ffr = _number(summary.get("first_seen_ffr_mean"), "source.first_seen_ffr_mean")
        if not math.isclose(ffr, successes / trials, rel_tol=2e-12, abs_tol=2e-15):
            raise AggregateValidationError("source FFR mean/count identity mismatch")
        ffr_low = _number(
            summary.get("first_seen_ffr_ci_low"),
            "source.first_seen_ffr_ci_low",
        )
        ffr_high = _number(
            summary.get("first_seen_ffr_ci_high"),
            "source.first_seen_ffr_ci_high",
        )
        if not 0.0 <= ffr_low <= ffr <= ffr_high <= 1.0:
            raise AggregateValidationError("source FFR interval is invalid")
        interval_method = str(summary.get("first_seen_ffr_ci_method"))
        if not interval_method:
            raise AggregateValidationError("source FFR interval method is empty")
        configured = json.loads(identity[1])
        records[identity] = {
            "point_id": _point_id(identity),
            "spec_identity": _spec_identity(identity),
            "method": identity[0],
            "configured_spec": configured,
            "eligible_profile_U": bool(summary["eligible_profile_U_all_seeds"]),
            "eligible_profile_A": bool(summary["eligible_profile_A_all_seeds"]),
            "memory_total_edge_bytes": int(memory),
            "first_seen_false_positives": successes,
            "first_seen_trials": trials,
            "first_seen_ffr": ffr,
            "first_seen_ffr_simultaneous_ci_low": ffr_low,
            "first_seen_ffr_simultaneous_ci_high": ffr_high,
            "first_seen_ffr_simultaneous_ci_method": interval_method,
            "first_seen_ffr_construction_count": constructions,
            "first_seen_ffr_construction_semantics": (
                "static_10m_query_trials"
                if is_tag
                else "10_independent_constructions_each_10m_query_trials"
            ),
        }

    binding = {
        "schema": SOURCE_BINDING_SCHEMA,
        "filter_grid_source_commit": base_commit,
        "filter_grid_semantic_config_id": base_config_id,
        "filter_grid_semantic_dataset_id": base_dataset_id,
        "filter_grid_clean_source_attestation_id": base_attestation_id,
        "filter_grid_shard_count": base_shards,
        "filter_grid_raw_row_count": base_rows,
        "filter_grid_spec_count": base_points,
        "filter_grid_aggregate_schema": base_aggregate_schema,
        "filter_grid_aggregate_id": aggregate_id,
        "analytic_diagnostic_schema_version": diagnostic_schema,
        "analytic_diagnostic_protocol": diagnostic_protocol,
        "analytic_diagnostic_source_commit": diagnostic_commit,
        "analytic_diagnostic_config_id": diagnostic_config_id,
        "analytic_diagnostic_family_size": diagnostic_family_size,
        "analytic_diagnostic_robust_overlap_rows": expected_overlap,
        "analytic_diagnostic_robust_separation_rows": expected_separation,
        "analytic_diagnostic_ambiguous_numeric_rows": expected_ambiguous,
        "functional_ffr_trials_are_not_timing_trials": True,
    }
    binding["source_evidence_binding_id"] = _sha256(
        {"schema": "phase1-v2-source-evidence-binding-v1", "pins": source}
    )
    return SourceEvidence(binding=binding, records=records)


def _support_receipt_id(value: Mapping[str, Any], path: str) -> str:
    receipt_id = value.get("receipt_id")
    if not _is_hex64(receipt_id):
        raise AggregateValidationError(f"{path}.receipt_id is malformed")
    material = dict(value)
    material.pop("receipt_id", None)
    material.pop("created_at_utc", None)
    if _sha256(material) != receipt_id:
        raise AggregateValidationError(f"{path}.receipt_id does not match its payload")
    return str(receipt_id)


def validate_support_receipts(
    config: Mapping[str, Any],
    config_id: str,
    source_commit: str,
    source_evidence_binding_id: str,
    corpus_receipt_path: Path,
    construction_receipt_path: Path,
) -> dict[str, Any]:
    """Strictly load the independently generated corpus and feasibility receipts."""

    untrusted_corpus = load_strict_json(corpus_receipt_path, dict)
    untrusted_construction = load_strict_json(construction_receipt_path, dict)
    corpus_id = untrusted_corpus.get("receipt_id")
    construction_id = untrusted_construction.get("receipt_id")
    if not _is_hex64(corpus_id) or not _is_hex64(construction_id):
        raise AggregateValidationError("support receipt identity is malformed")
    try:
        corpus = runner.validate_corpus_equivalence_receipt(
            dict(config),
            config_id,
            source_commit,
            source_evidence_binding_id,
            corpus_receipt_path,
            corpus_id,
        )
        construction = runner.validate_construction_feasibility_receipt(
            dict(config),
            config_id,
            source_commit,
            source_evidence_binding_id,
            corpus_id,
            corpus["semantic_dataset_id"],
            construction_receipt_path,
            construction_id,
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise AggregateValidationError("support receipt validation failed") from error
    if construction["semantic_dataset_id"] != corpus["semantic_dataset_id"]:
        raise AggregateValidationError("support receipts bind different datasets")
    _parse_utc(corpus.get("created_at_utc"), "corpus_receipt.created_at_utc")
    _parse_utc(
        construction.get("created_at_utc"),
        "construction_receipt.created_at_utc",
    )
    binding = {
        "schema": SUPPORT_BINDING_SCHEMA,
        "semantic_dataset_id": corpus["semantic_dataset_id"],
        "corpus_equivalence_receipt_id": corpus_id,
        "construction_feasibility_receipt_id": construction_id,
        "construction_feasibility_status": construction["status"],
        "construction_feasibility_build_count": construction["build_count"],
    }
    binding["support_receipts_binding_id"] = _sha256(binding)
    return binding


@lru_cache(maxsize=4)
def _dataset_id(account_count: int, dataset_seed: int, nonmember_count: int) -> str:
    dataset = SyntheticCredentialSet(account_count, dataset_seed)
    members = [dataset.member(index) for index in range(dataset.account_count)]
    return dataset.manifest_hash(members, nonmember_count)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    raise AggregateValidationError(
                        f"{path.name}:{line_number} contains a blank raw row"
                    )
                try:
                    row = json.loads(
                        line,
                        object_pairs_hook=_reject_pairs,
                        parse_constant=_reject_constant,
                    )
                except json.JSONDecodeError as error:
                    raise AggregateValidationError(
                        f"{path.name}:{line_number} is malformed JSON"
                    ) from error
                if type(row) is not dict:
                    raise AggregateValidationError(
                        f"{path.name}:{line_number} must be a JSON object"
                    )
                _reject_nonfinite(row, f"{path.name}:{line_number}")
                rows.append(row)
    except (OSError, UnicodeError) as error:
        raise AggregateValidationError(f"cannot read raw shard {path}") from error
    if not rows:
        raise AggregateValidationError(f"raw shard {path} is empty")
    return rows


def _histogram(value: Any, expected_count: int, path: str) -> list[tuple[int, int]]:
    if type(value) is not list or not value:
        raise AggregateValidationError(f"{path} must be a nonempty histogram")
    result: list[tuple[int, int]] = []
    previous = -1
    total = 0
    for index, entry in enumerate(value):
        if type(entry) is not dict or set(entry) != {"latency_ns", "count"}:
            raise AggregateValidationError(f"{path}[{index}] has the wrong schema")
        latency = _integer(entry["latency_ns"], f"{path}[{index}].latency_ns")
        count = _integer(entry["count"], f"{path}[{index}].count", positive=True)
        if latency <= previous:
            raise AggregateValidationError(f"{path} is not strictly sorted")
        previous = latency
        total += count
        result.append((latency, count))
    if total != expected_count:
        raise AggregateValidationError(f"{path} sample count mismatch")
    return result


def _histogram_value_at(histogram: Sequence[tuple[int, int]], index: int) -> int:
    cursor = 0
    for latency, count in histogram:
        cursor += count
        if index < cursor:
            return latency
    raise AssertionError("validated histogram index is outside its sample")


def _histogram_percentile_us(
    histogram: Sequence[tuple[int, int]], count: int, quantile: float
) -> float:
    position = quantile * (count - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    low_value = _histogram_value_at(histogram, lower)
    high_value = _histogram_value_at(histogram, upper)
    low_us = low_value / 1000.0
    if lower == upper:
        return low_us
    high_us = high_value / 1000.0
    fraction = position - lower
    return low_us * (1.0 - fraction) + high_us * fraction


def _clock_p99_ns(clock: Mapping[str, Any], path: str, expected_sample_count: int) -> float:
    if set(clock) != CLOCK_KEYS:
        raise AggregateValidationError(f"{path} has unexpected or missing keys")
    sample_count = _integer(
        clock.get("overhead_sample_count"),
        f"{path}.overhead_sample_count",
        positive=True,
    )
    _require_exact(sample_count, expected_sample_count, f"{path}.overhead_sample_count")
    histogram = _histogram(
        clock.get("overhead_histogram_ns"),
        sample_count,
        f"{path}.overhead_histogram_ns",
    )
    p50 = _histogram_percentile_us(histogram, sample_count, 0.50) * 1000.0
    p95 = _histogram_percentile_us(histogram, sample_count, 0.95) * 1000.0
    p99 = _histogram_percentile_us(histogram, sample_count, 0.99) * 1000.0
    _require_exact(clock.get("overhead_p50_ns"), p50, f"{path}.overhead_p50_ns")
    _require_exact(clock.get("overhead_p95_ns"), p95, f"{path}.overhead_p95_ns")
    _require_exact(clock.get("overhead_p99_ns"), p99, f"{path}.overhead_p99_ns")
    if type(clock.get("implementation")) is not str or not clock["implementation"]:
        raise AggregateValidationError(f"{path}.implementation is invalid")
    if type(clock.get("adjustable")) is not bool:
        raise AggregateValidationError(f"{path}.adjustable must be Boolean")
    for field in (
        "resolution_seconds",
        "resolution_ns",
        "overhead_p50_ns",
        "overhead_p95_ns",
        "overhead_p99_ns",
    ):
        if type(clock.get(field)) is not float:
            raise AggregateValidationError(f"{path}.{field} must be an exact float")
    resolution = _number(clock.get("resolution_ns"), f"{path}.resolution_ns", positive=True)
    resolution_seconds = _number(
        clock.get("resolution_seconds"), f"{path}.resolution_seconds", positive=True
    )
    _require_exact(
        resolution,
        resolution_seconds * 1_000_000_000.0,
        f"{path}.resolution_ns",
    )
    _require_exact(clock.get("api"), "time.perf_counter_ns", f"{path}.api")
    _require_exact(clock.get("monotonic"), True, f"{path}.monotonic")
    _require_exact(
        clock.get("call_pattern"),
        "one_call_immediately_before_and_after_each_timed_query",
        f"{path}.call_pattern",
    )
    _require_exact(
        clock.get("overhead_measurement"),
        "back_to_back_perf_counter_ns_delta",
        f"{path}.overhead_measurement",
    )
    return p99


def _adapt_filter_validation_row(row: Mapping[str, Any]) -> dict[str, Any]:
    adapted = dict(row)
    adapted["seed"] = row.get("construction_seed")
    adapted["memory_model_bytes"] = 0
    adapted["memory_cache_bytes"] = 0
    return adapted


def _validate_common_row(
    row: dict[str, Any],
    *,
    config: Mapping[str, Any],
    config_id: str,
    dataset_id: str,
    expected_source_commit: str,
    source_binding: Mapping[str, Any],
    support_binding: Mapping[str, Any],
    plan: runner.StagePlan,
    spec: Any,
    order: int,
    label: str,
) -> str:
    expected_row_keys = COMMON_ROW_KEYS | (
        WARM_ONLY_ROW_KEYS if plan.stage.startswith("warm-") else COLD_ONLY_ROW_KEYS
    )
    if set(row) != expected_row_keys:
        missing = sorted(expected_row_keys - row.keys())
        extra = sorted(row.keys() - expected_row_keys)
        raise AggregateValidationError(
            f"{label} raw row schema mismatch: missing={missing}, extra={extra}"
        )
    expected_method = runner._method_for_spec(spec)
    required_equal = {
        "schema": runner.ROW_SCHEMA,
        "protocol": runner.PROTOCOL,
        "formal_timing": True,
        "result_status": "FORMAL_RAW_OBSERVATION",
        "source_commit": expected_source_commit,
        "expected_source_commit": expected_source_commit,
        "git_dirty": False,
        "source_status_scope": source_frontier.SOURCE_STATUS_SCOPE,
        "semantic_config_id": config_id,
        "semantic_dataset_id": dataset_id,
        "source_evidence_mode": config["source_evidence"]["mode"],
        "source_filter_grid_commit": config["source_evidence"]["filter_grid_commit"],
        "source_filter_grid_semantic_config_id": config["source_evidence"][
            "filter_grid_semantic_config_id"
        ],
        "source_filter_grid_semantic_dataset_id": config["source_evidence"][
            "filter_grid_semantic_dataset_id"
        ],
        "source_filter_grid_aggregate_identity": config["source_evidence"][
            "filter_grid_aggregate_identity"
        ],
        "source_filter_grid_attestation_id": config["source_evidence"][
            "filter_grid_attestation_id"
        ],
        "source_ffr_randomized_construction_count": SOURCE_RANDOMIZED_CONSTRUCTIONS,
        "source_ffr_static_tag_construction_count": SOURCE_STATIC_CONSTRUCTIONS,
        "source_ffr_randomized_interval": config["source_evidence"][
            "randomized_first_seen_interval"
        ],
        "source_ffr_static_tag_interval": config["source_evidence"][
            "static_tag_first_seen_interval"
        ],
        "stage": plan.stage,
        "measurement_trial_seed": plan.trial_seed,
        "global_seed_ordinal": plan.global_seed_ordinal,
        "measurement_order": order,
        "shard_index": plan.shard_index,
        "shard_count": plan.shard_count,
        "method": expected_method,
        "family": spec.family,
        "spec_identity": spec.identity,
        "spec_id": hashlib.sha256(spec.identity.encode()).hexdigest(),
        "spec_universe_count": runner.PHASE1_SPEC_COUNT,
        "configured_spec": spec.parameters,
        "randomized_construction": spec.family != "tag",
        "account_count": runner.ACCOUNT_COUNT,
        "corpus_public_api_equivalence": "PASS_BIT_IDENTICAL_FULL_CORPUS",
        "construction_feasibility_status": support_binding["construction_feasibility_status"],
        "construction_feasibility_build_count": support_binding[
            "construction_feasibility_build_count"
        ],
    }
    for field, expected in required_equal.items():
        if field not in row:
            raise AggregateValidationError(f"{label}.{field} is missing")
        _require_exact(row[field], expected, f"{label}.{field}")
    expected_construction_seed = None if spec.family == "tag" else plan.trial_seed
    _require_exact(
        row.get("construction_seed"),
        expected_construction_seed,
        f"{label}.construction_seed",
    )
    if row.get("source_evidence_binding_id") != source_binding.get("source_evidence_binding_id"):
        raise AggregateValidationError(f"{label} source evidence binding mismatch")
    if row.get("corpus_equivalence_receipt_id") != support_binding.get(
        "corpus_equivalence_receipt_id"
    ):
        raise AggregateValidationError(f"{label} corpus receipt binding mismatch")
    if row.get("construction_feasibility_receipt_id") != support_binding.get(
        "construction_feasibility_receipt_id"
    ):
        raise AggregateValidationError(f"{label} construction receipt binding mismatch")
    if row.get("look1_extension_decision_receipt_id") != support_binding.get(
        "look1_extension_decision_receipt_id"
    ):
        raise AggregateValidationError(f"{label} look1 decision binding mismatch")
    if row.get("expected_look1_extension_decision_id") != support_binding.get(
        "expected_look1_extension_decision_id"
    ):
        raise AggregateValidationError(f"{label} expected look1 decision binding mismatch")
    expected_run_material = (
        f"{expected_source_commit}:{config_id}:{dataset_id}:{plan.stage}:"
        f"{plan.trial_seed}:{spec.identity}:{order}:{plan.shard_index}:"
        f"{plan.shard_count}"
    )
    expected_run_id = hashlib.sha256(expected_run_material.encode()).hexdigest()[:24]
    _require_exact(row.get("run_id"), expected_run_id, f"{label}.run_id")
    _parse_utc(row.get("timestamp_utc"), f"{label}.timestamp_utc")
    if row.get("observation_sha256") != v1_timing.observation_sha256(row):
        raise AggregateValidationError(f"{label}.observation_sha256 mismatch")
    _number(row.get("build_time_s"), f"{label}.build_time_s")
    _require_exact(
        row.get("member_validation_count"),
        runner.ACCOUNT_COUNT,
        f"{label}.member_validation_count",
    )
    _require_exact(row.get("member_false_negatives"), 0, f"{label}.member_false_negatives")
    for field in (
        "memory_payload_bytes",
        "memory_metadata_bytes",
        "memory_alignment_bytes",
        "memory_compact_total_bytes",
        "memory_filter_bytes",
        "memory_directory_extra_bytes",
        "memory_common_prf_key_bytes",
        "memory_total_edge_bytes",
    ):
        _integer(row.get(field), f"{label}.{field}")
    try:
        source_frontier._validate_filter_parameters(_adapt_filter_validation_row(row))
        stratum = _validate_v2_environment(row)
    except ValueError as error:
        raise AggregateValidationError(f"{label} filter/environment contract failed") from error
    timing_clock = row.get("timing_clock")
    if type(timing_clock) is not dict:
        raise AggregateValidationError(f"{label}.timing_clock must be a mapping")
    environment = row.get("host_environment")
    if type(environment) is not dict or set(environment) != HOST_ENVIRONMENT_KEYS:
        raise AggregateValidationError(f"{label}.host_environment has unexpected or missing keys")
    _same_exact(
        timing_clock,
        environment.get("timing_clock"),
        f"{label}.host_environment.timing_clock",
    )
    expected_environment_bindings = {
        "source_evidence_binding_id": source_binding["source_evidence_binding_id"],
        "corpus_equivalence_receipt_id": support_binding["corpus_equivalence_receipt_id"],
        "corpus_equivalence_dataset_id": dataset_id,
        "construction_feasibility_receipt_id": support_binding[
            "construction_feasibility_receipt_id"
        ],
        "construction_feasibility_status": support_binding["construction_feasibility_status"],
        "construction_feasibility_build_count": support_binding[
            "construction_feasibility_build_count"
        ],
        "look1_extension_decision_receipt_id": support_binding.get(
            "look1_extension_decision_receipt_id"
        ),
        "expected_look1_extension_decision_id": support_binding.get(
            "expected_look1_extension_decision_id"
        ),
        "same_runner_host_lock_acquired": True,
    }
    for field, expected in expected_environment_bindings.items():
        _require_exact(environment.get(field), expected, f"{label}.host_environment.{field}")
    _clock_p99_ns(
        timing_clock,
        f"{label}.timing_clock",
        int(config["timing"]["clock_call_overhead_sample_count"]),
    )
    return stratum


def _validate_warm_row(
    row: dict[str, Any], config: Mapping[str, Any], plan: runner.StagePlan, label: str
) -> None:
    warm = config["warm"]
    global_ordinal = _integer(row.get("global_seed_ordinal"), f"{label}.global_seed_ordinal")
    start = global_ordinal * int(warm["query_window_stride"])
    expected_order = list(runner.path_measurement_order(global_ordinal))
    expected_equal = {
        "primary_timing_metric": PRIMARY_METRIC,
        "path_measurement_order": expected_order,
        "query_window_assignment": "disjoint_global_seed_windows_v2",
        "query_window_start": start,
        "query_window_end_exclusive": start
        + int(warm["query_pool_count"])
        + int(warm["actual_front_latency_query_count"])
        + int(warm["query_only_latency_query_count"]),
        "query_pool_count": int(warm["query_pool_count"]),
        "warmup_query_count": int(warm["warmup_query_count"]),
        "preflight_query_count": int(warm["preflight_query_count"]),
        "preflight_path_decision_mismatch_count": 0,
        "actual_front_throughput_query_count_per_trial": int(
            warm["actual_front_throughput_query_count"]
        ),
        "actual_front_throughput_repetition_count": int(
            warm["actual_front_throughput_repetitions"]
        ),
        "actual_front_latency_sample_count": int(warm["actual_front_latency_query_count"]),
        "query_only_latency_sample_count": int(warm["query_only_latency_query_count"]),
    }
    for field, expected in expected_equal.items():
        _require_exact(row.get(field), expected, f"{label}.{field}")
    preflight_positive = _integer(
        row.get("preflight_query_only_positive_count"),
        f"{label}.preflight_query_only_positive_count",
    )
    if preflight_positive > int(warm["preflight_query_count"]):
        raise AggregateValidationError(f"{label} preflight positive count is impossible")
    throughput = row.get("actual_front_throughput_qps_trials")
    if type(throughput) is not list or len(throughput) != int(
        warm["actual_front_throughput_repetitions"]
    ):
        raise AggregateValidationError(f"{label} throughput trial count mismatch")
    throughput_values = [
        _number(value, f"{label}.throughput[{index}]", positive=True)
        for index, value in enumerate(throughput)
    ]
    _require_exact(
        row.get("actual_front_throughput_qps_mean"),
        statistics.mean(throughput_values),
        f"{label}.actual_front_throughput_qps_mean",
    )
    actual_count = int(warm["actual_front_latency_query_count"])
    actual_histogram = _histogram(
        row.get("actual_front_warm_latency_histogram_ns"),
        actual_count,
        f"{label}.actual_front_warm_latency_histogram_ns",
    )
    query_count = int(warm["query_only_latency_query_count"])
    query_histogram = _histogram(
        row.get("query_only_warm_latency_histogram_ns"),
        query_count,
        f"{label}.query_only_warm_latency_histogram_ns",
    )
    for quantile, suffix in ((0.50, "p50"), (0.95, "p95"), (0.99, "p99")):
        _require_exact(
            row.get(f"indexed_directory_to_screen_decision_warm_{suffix}_us"),
            _histogram_percentile_us(actual_histogram, actual_count, quantile),
            f"{label}.actual_front_{suffix}",
        )
        _require_exact(
            row.get(f"filter_query_only_warm_{suffix}_us"),
            _histogram_percentile_us(query_histogram, query_count, quantile),
            f"{label}.query_only_{suffix}",
        )
    precision_rule = row.get("precision_rule")
    expected_precision_rule = {
        "scale": warm["precision_scale"],
        "relative_half_width_max": warm["precision_relative_half_width_max"],
        "look_alpha": warm["precision_look_alpha"],
        "coordinate_alpha": warm["simultaneous_coordinate_alpha"],
        "maximum_trial_count": warm["maximum_trial_count"],
    }
    _same_exact(expected_precision_rule, precision_rule, f"{label}.precision_rule")
    clock = row["timing_clock"]
    clock_p99 = _number(
        clock.get("overhead_p99_ns"),
        f"{label}.timing_clock.overhead_p99_ns",
        positive=True,
    )
    primary_p99_us = _number(row.get(PRIMARY_METRIC), f"{label}.{PRIMARY_METRIC}", positive=True)
    ratio, ratio_gate = _timer_ratio_and_gate(primary_p99_us, clock_p99)
    _require_exact(
        row.get("primary_p99_to_clock_call_p99_ratio"),
        ratio,
        f"{label}.primary_p99_to_clock_call_p99_ratio",
    )
    _require_exact(
        row.get("primary_p99_to_clock_call_p99_minimum"),
        TIMER_MINIMUM_RATIO,
        f"{label}.primary_p99_to_clock_call_p99_minimum",
    )
    _require_exact(
        row.get("primary_p99_to_clock_call_p99_gate_pass"),
        ratio_gate,
        f"{label}.primary_p99_to_clock_call_p99_gate_pass",
    )


def _timer_ratio_and_gate(primary_p99_us: float, clock_call_p99_ns: float) -> tuple[float, bool]:
    if (
        type(primary_p99_us) is not float
        or type(clock_call_p99_ns) is not float
        or not math.isfinite(primary_p99_us)
        or not math.isfinite(clock_call_p99_ns)
        or primary_p99_us <= 0.0
        or clock_call_p99_ns <= 0.0
    ):
        raise AggregateValidationError("timer gate requires positive finite floats")
    ratio = primary_p99_us * 1000.0 / clock_call_p99_ns
    return ratio, ratio >= TIMER_MINIMUM_RATIO


def _validate_cold_row(row: dict[str, Any], config: Mapping[str, Any], label: str) -> None:
    cold = config["cold"]
    count = int(cold["query_only_latency_query_count"])
    start = int(cold["query_window_start"])
    expected_equal = {
        "primary_timing_metric": None,
        "diagnostic_timing_metric": "filter_query_only_cold_p99_us",
        "cold_claim_scope": cold["claim_scope"],
        "cold_latency_sample_count": count,
        "cold_query_window_start": start,
        "cold_query_window_end_exclusive": start + count,
        "cold_eviction_bytes_per_query": int(cold["eviction_bytes"]),
        "cold_eviction_method": cold["eviction_method"],
        "cold_eviction_per_query": True,
        "cold_eviction_time_excluded": True,
        "cold_eviction_minimum_llc_multiple": int(cold["eviction_minimum_llc_multiple"]),
    }
    for field, expected in expected_equal.items():
        _require_exact(row.get(field), expected, f"{label}.{field}")
    histogram = _histogram(
        row.get("query_only_cold_latency_histogram_ns"),
        count,
        f"{label}.query_only_cold_latency_histogram_ns",
    )
    for quantile, suffix in ((0.50, "p50"), (0.95, "p95"), (0.99, "p99")):
        _require_exact(
            row.get(f"filter_query_only_cold_{suffix}_us"),
            _histogram_percentile_us(histogram, count, quantile),
            f"{label}.cold_{suffix}",
        )
    llc = _integer(
        row.get("cold_eviction_last_level_cache_bytes"),
        f"{label}.cold_eviction_last_level_cache_bytes",
        positive=True,
    )
    ratio = int(cold["eviction_bytes"]) / llc
    _require_exact(
        row.get("cold_eviction_buffer_to_llc_ratio"),
        ratio,
        f"{label}.cold_eviction_buffer_to_llc_ratio",
    )
    if ratio < int(cold["eviction_minimum_llc_multiple"]):
        raise AggregateValidationError(f"{label} cold eviction capacity is insufficient")
    _integer(row.get("cold_eviction_terminal_token"), f"{label}.terminal_token")


def _compact_stage_row(row: Mapping[str, Any], stage: str) -> dict[str, Any]:
    compact = {
        "observation_sha256": row["observation_sha256"],
        "method": row["method"],
        "configured_spec": row["configured_spec"],
        "measurement_trial_seed": row["measurement_trial_seed"],
        "memory_total_edge_bytes": row["memory_total_edge_bytes"],
        "host_environment": row["host_environment"],
    }
    if stage.startswith("warm-"):
        compact.update(
            {
                PRIMARY_METRIC: row[PRIMARY_METRIC],
                QUERY_ONLY_METRIC: row[QUERY_ONLY_METRIC],
                "actual_front_throughput_qps_mean": row["actual_front_throughput_qps_mean"],
                "primary_p99_to_clock_call_p99_ratio": row[
                    "primary_p99_to_clock_call_p99_ratio"
                ],
            }
        )
    else:
        compact["filter_query_only_cold_p99_us"] = row["filter_query_only_cold_p99_us"]
    return compact


def _stage_paths(
    raw_root: Path,
    config: Mapping[str, Any],
    stage: str,
) -> list[Path]:
    output_key = {
        "warm-look1": "warm_look1_pattern",
        "warm-look2": "warm_look2_pattern",
        "cold": "cold_pattern",
    }[stage]
    count = runner.COLD_SHARD_COUNT if stage == "cold" else runner.WARM_SHARD_COUNT
    pattern = str(config["outputs"][output_key])
    return [raw_root / pattern.format(index=index) for index in range(count)]


def _validate_stage(
    *,
    raw_root: Path,
    config: Mapping[str, Any],
    config_id: str,
    dataset_id: str,
    expected_source_commit: str,
    source_binding: Mapping[str, Any],
    support_binding: Mapping[str, Any],
    stage: str,
    required: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    paths = _stage_paths(raw_root, config, stage)
    present = [path.exists() for path in paths]
    if not any(present) and not required:
        return [], []
    if not all(present):
        raise AggregateValidationError(f"{stage} is missing one or more frozen shards")
    rows: list[dict[str, Any]] = []
    strata: list[str] = []
    run_ids: set[str] = set()
    for shard_index, path in enumerate(paths):
        plan = runner.plan_stage(dict(config), config_id, stage, shard_index, len(paths))
        file_rows = _load_jsonl(path)
        if len(file_rows) != len(plan.specs):
            raise AggregateValidationError(
                f"{stage} shard {shard_index} row count differs from its plan"
            )
        timestamps: list[datetime] = []
        for order, (row, spec) in enumerate(zip(file_rows, plan.specs, strict=True)):
            label = f"{stage}[{shard_index}][{order}]"
            stratum = _validate_common_row(
                row,
                config=config,
                config_id=config_id,
                dataset_id=dataset_id,
                expected_source_commit=expected_source_commit,
                source_binding=source_binding,
                support_binding=support_binding,
                plan=plan,
                spec=spec,
                order=order,
                label=label,
            )
            if row["run_id"] in run_ids:
                raise AggregateValidationError("raw timing evidence has duplicate run_id")
            run_ids.add(row["run_id"])
            timestamps.append(_parse_utc(row["timestamp_utc"], f"{label}.timestamp_utc"))
            if stage.startswith("warm-"):
                _validate_warm_row(row, config, plan, label)
            else:
                _validate_cold_row(row, config, label)
            rows.append(_compact_stage_row(row, stage))
            strata.append(stratum)
        if any(left >= right for left, right in zip(timestamps, timestamps[1:], strict=False)):
            raise AggregateValidationError(f"{stage} shard timestamps are not sequential")
    return rows, strata


def _observation_set_id(rows: Iterable[dict[str, Any]], label: str) -> str:
    return _sha256(
        {
            "schema": "traps-phase1-timing-frontier-v2-observation-set-v1",
            "scope": label,
            "observations": [row["observation_sha256"] for row in rows],
        }
    )


def _reject_extra_raw_shards(
    raw_root: Path, config: Mapping[str, Any], include_look2: bool, *, include_cold: bool
) -> None:
    stages = ["warm-look1"]
    if include_look2:
        stages.append("warm-look2")
    if include_cold:
        stages.append("cold")
    expected = {
        path.resolve() for stage in stages for path in _stage_paths(raw_root, config, stage)
    }
    if include_cold:
        actual = {path.resolve() for path in raw_root.rglob("*.jsonl")}
    else:
        cold_directories = {
            path.parent.resolve() for path in _stage_paths(raw_root, config, "cold")
        }
        actual = {
            path.resolve()
            for path in raw_root.rglob("*.jsonl")
            if path.parent.resolve() not in cold_directories
        }
    if actual != expected:
        missing = len(expected - actual)
        extra = len(actual - expected)
        raise AggregateValidationError(
            f"raw shard namespace mismatch: {missing} missing, {extra} extra"
        )


def _precision_gate(log_half_width: float) -> bool:
    if type(log_half_width) is not float or not math.isfinite(log_half_width):
        raise AggregateValidationError("log half-width must be a finite float")
    if log_half_width < 0.0:
        raise AggregateValidationError("log half-width must be nonnegative")
    return log_half_width <= math.log1p(PRECISION_LIMIT)


def _log_t_summary(values: Sequence[float], coordinate_alpha: float) -> dict[str, Any]:
    if len(values) < 2 or any(not math.isfinite(value) or value <= 0.0 for value in values):
        raise AggregateValidationError("log-t summary requires at least two positive values")
    logs = [math.log(value) for value in values]
    mean_log = statistics.fmean(logs)
    standard_error = statistics.stdev(logs) / math.sqrt(len(logs))
    critical = float(student_t.ppf(1.0 - coordinate_alpha / 2.0, len(logs) - 1))
    half_width = critical * standard_error
    geometric_mean = math.exp(mean_log)
    lower = math.exp(mean_log - half_width)
    upper = math.exp(mean_log + half_width)
    relative_half_width = math.expm1(half_width)
    return {
        "sample_count": len(values),
        "mean_log": mean_log,
        "log_standard_error": standard_error,
        "student_t_critical": critical,
        "log_half_width": half_width,
        "geometric_mean": geometric_mean,
        "simultaneous_ci_low": lower,
        "simultaneous_ci_high": upper,
        "relative_half_width": relative_half_width,
        "relative_half_width_definition": (
            "max(upper/geometric_mean-1,1-lower/geometric_mean)=exp(log_half_width)-1"
        ),
        "precision_limit": PRECISION_LIMIT,
        "precision_gate_comparison": "log_half_width <= log1p(0.05)",
        "precision_gate_pass": _precision_gate(half_width),
    }


def _mean_t_summary(values: Sequence[float]) -> dict[str, Any]:
    if not values or any(not math.isfinite(value) or value <= 0.0 for value in values):
        raise AggregateValidationError("descriptive t summary requires positive values")
    mean = statistics.fmean(values)
    if len(values) == 1:
        return {
            "sample_count": 1,
            "mean": mean,
            "ci_low": None,
            "ci_high": None,
            "interval_method": "not_estimable_from_one_block",
        }
    standard_error = statistics.stdev(values) / math.sqrt(len(values))
    critical = float(student_t.ppf(0.975, len(values) - 1))
    return {
        "sample_count": len(values),
        "mean": mean,
        "ci_low": max(0.0, mean - critical * standard_error),
        "ci_high": mean + critical * standard_error,
        "interval_method": "two_sided_student_t_95_across_blocks_descriptive",
    }


def _warm_groups(rows: Sequence[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[_identity(row["method"], row["configured_spec"])].append(row)
    return grouped


def _look1_gate_summary(
    rows: Sequence[dict[str, Any]], config: Mapping[str, Any]
) -> dict[str, Any]:
    grouped = _warm_groups(rows)
    if len(grouped) != runner.PHASE1_SPEC_COUNT:
        raise AggregateValidationError("look1 does not cover exactly 794 specifications")
    coordinate_alpha = _number(
        config["warm"]["simultaneous_coordinate_alpha"],
        "warm.simultaneous_coordinate_alpha",
        positive=True,
    )
    precision: dict[str, dict[str, Any]] = {}
    timer_pass = True
    strata: set[str] = set()
    for identity, group in sorted(grouped.items()):
        if len(group) != len(runner.LOOK1_SEEDS):
            raise AggregateValidationError("look1 point lacks its complete 20-seed block")
        seed_set = {int(row["measurement_trial_seed"]) for row in group}
        if seed_set != set(runner.LOOK1_SEEDS):
            raise AggregateValidationError("look1 point has the wrong timing seeds")
        point_summary = _log_t_summary(
            [_number(row[PRIMARY_METRIC], PRIMARY_METRIC, positive=True) for row in group],
            coordinate_alpha,
        )
        precision[_point_id(identity)] = point_summary
        timer_pass = timer_pass and all(
            _number(
                row["primary_p99_to_clock_call_p99_ratio"],
                "primary_p99_to_clock_call_p99_ratio",
                positive=True,
            )
            >= TIMER_MINIMUM_RATIO
            for row in group
        )
        for row in group:
            try:
                strata.add(v1_aggregate._hardware_stratum(row["host_environment"]))
            except (KeyError, TypeError, ValueError) as error:
                raise AggregateValidationError("look1 hardware stratum is malformed") from error
    maximum_log = max(summary["log_half_width"] for summary in precision.values())
    maximum = math.expm1(maximum_log)
    precision_pass = _precision_gate(maximum_log)
    return {
        "coordinate_alpha": coordinate_alpha,
        "precision_by_point": precision,
        "max_primary_log_half_width": maximum_log,
        "max_primary_relative_half_width": maximum,
        "precision_gate_pass": precision_pass,
        "timer_resolution_gate_pass": timer_pass,
        "single_hardware_stratum_gate_pass": len(strata) == 1,
        "hardware_strata": sorted(strata),
    }


def _decision_material(value: Mapping[str, Any]) -> dict[str, Any]:
    material = dict(value)
    material.pop("receipt_id", None)
    material.pop("created_at_utc", None)
    return material


def _classify_look1_gate(gate: Mapping[str, Any]) -> tuple[str, str]:
    if gate.get("single_hardware_stratum_gate_pass") is not True:
        return VALID_BUT_NONPROMOTABLE, STOP_NONPROMOTABLE_HARDWARE_STRATUM
    if gate.get("timer_resolution_gate_pass") is not True:
        return VALID_BUT_NONPROMOTABLE, STOP_NONPROMOTABLE_TIMER_RESOLUTION
    if gate.get("precision_gate_pass") is True:
        return "VALID", PASS_STOP_N20
    return "VALID", REQUIRE_FULL_LOOK2


def _validate_decision_receipt_id(value: Mapping[str, Any]) -> None:
    if not _is_hex64(value.get("receipt_id")):
        raise AggregateValidationError("look1 decision receipt_id is malformed")
    _parse_utc(value.get("created_at_utc"), "look1_decision.created_at_utc")
    if _sha256(_decision_material(value)) != value["receipt_id"]:
        raise AggregateValidationError("look1 decision receipt_id mismatch")


def _same_look1_decision_material(
    expected: Mapping[str, Any], actual: Mapping[str, Any]
) -> None:
    tolerant_fields = {
        "max_primary_log_half_width",
        "max_primary_relative_half_width",
    }
    if set(expected) != set(actual):
        raise AggregateValidationError("look1_decision mapping keys differ")
    for key in expected:
        if key in tolerant_fields:
            left = _number(expected[key], f"look1_decision.{key}")
            right = _number(actual[key], f"look1_decision.{key}")
            if not math.isclose(left, right, rel_tol=1e-12, abs_tol=1e-12):
                raise AggregateValidationError(f"look1_decision.{key} value differs")
            continue
        _same_exact(expected[key], actual[key], f"look1_decision.{key}")


def _finalize_look1_receipt(
    receipt: dict[str, Any],
    *,
    analysis_binding: Mapping[str, Any],
    expected_source_commit: str,
) -> dict[str, Any]:
    receipt["receipt_id"] = _sha256(_decision_material(receipt))
    _same_exact(
        analysis_binding,
        _analysis_checkout_binding(expected_source_commit),
        "analysis_checkout_completion",
    )
    return receipt


def build_look1_extension_decision(
    *,
    raw_root: Path,
    config_path: Path,
    expected_source_commit: str,
    frontier_audit_path: Path,
    frontier_summary_path: Path,
    grid_dir: Path,
    grid_config_path: Path,
    clean_attestation_path: Path,
    diagnostic_raw_dir: Path,
    diagnostic_artifact_path: Path,
    corpus_receipt_path: Path,
    construction_receipt_path: Path,
    created_at_utc: str | None = None,
    allow_existing_look2: bool = False,
) -> dict[str, Any]:
    analysis_binding = _analysis_checkout_binding(expected_source_commit)
    config, config_id = runner.load_config(config_path)
    source = validate_source_evidence(
        config=config,
        frontier_audit_path=frontier_audit_path,
        frontier_summary_path=frontier_summary_path,
        grid_dir=grid_dir,
        grid_config_path=grid_config_path,
        clean_attestation_path=clean_attestation_path,
        diagnostic_raw_dir=diagnostic_raw_dir,
        diagnostic_artifact_path=diagnostic_artifact_path,
    )
    support = validate_support_receipts(
        config,
        config_id,
        expected_source_commit,
        source.binding["source_evidence_binding_id"],
        corpus_receipt_path,
        construction_receipt_path,
    )
    dataset_config = config["dataset"]
    dataset_id = _dataset_id(
        int(dataset_config["account_count"]),
        int(dataset_config["seed"]),
        int(dataset_config["nonmember_count"]),
    )
    if support["semantic_dataset_id"] != dataset_id:
        raise AggregateValidationError("support receipt dataset differs from recomputation")
    look1, _ = _validate_stage(
        raw_root=raw_root,
        config=config,
        config_id=config_id,
        dataset_id=dataset_id,
        expected_source_commit=expected_source_commit,
        source_binding=source.binding,
        support_binding=support,
        stage="warm-look1",
        required=True,
    )
    look2_presence = [path.exists() for path in _stage_paths(raw_root, config, "warm-look2")]
    if not allow_existing_look2 and any(look2_presence):
        raise AggregateValidationError("look1 decision refuses already-present look2 shards")
    if allow_existing_look2 and any(look2_presence) and not all(look2_presence):
        raise AggregateValidationError("existing look2 evidence is only partially present")
    _reject_extra_raw_shards(
        raw_root,
        config,
        include_look2=allow_existing_look2 and all(look2_presence),
        include_cold=False,
    )
    gate = _look1_gate_summary(look1, config)
    validation_status, decision = _classify_look1_gate(gate)
    receipt = {
        "schema": LOOK1_DECISION_SCHEMA,
        "receipt_id_schema": config["warm"]["look1_extension_decision_id_schema"],
        "validation_status": validation_status,
        "protocol": runner.PROTOCOL,
        "semantic_config_id": config_id,
        "source_commit": expected_source_commit,
        **analysis_binding,
        "source_evidence_binding_id": source.binding["source_evidence_binding_id"],
        "corpus_equivalence_receipt_id": support["corpus_equivalence_receipt_id"],
        "construction_feasibility_receipt_id": support["construction_feasibility_receipt_id"],
        "look1_shard_count": runner.WARM_SHARD_COUNT,
        "look1_row_count": len(look1),
        "look1_spec_count": runner.PHASE1_SPEC_COUNT,
        "look1_seed_count": len(runner.LOOK1_SEEDS),
        "precision_gate_pass": gate["precision_gate_pass"],
        "timer_resolution_gate_pass": gate["timer_resolution_gate_pass"],
        "single_hardware_stratum_gate_pass": gate["single_hardware_stratum_gate_pass"],
        "max_primary_log_half_width": gate["max_primary_log_half_width"],
        "max_primary_relative_half_width": gate["max_primary_relative_half_width"],
        "look1_observation_set_id": _observation_set_id(look1, "warm-look1"),
        "decision": decision,
        "decision_rule": LOOK1_DECISION_RULE,
        "created_at_utc": created_at_utc or datetime.now(timezone.utc).isoformat(),
    }
    return _finalize_look1_receipt(
        receipt,
        analysis_binding=analysis_binding,
        expected_source_commit=expected_source_commit,
    )


def _recomputed_decision_without_timestamp(
    *, allow_existing_look2: bool = False, **kwargs: Any
) -> dict[str, Any]:
    value = build_look1_extension_decision(
        **kwargs,
        created_at_utc="1970-01-01T00:00:00+00:00",
        allow_existing_look2=allow_existing_look2,
    )
    return _decision_material(value)


def validate_look1_decision(
    supplied_path: Path,
    *,
    recomputed_material: Mapping[str, Any],
    config: Mapping[str, Any],
    config_id: str,
    source_commit: str,
    source_evidence_binding_id: str,
    corpus_equivalence_receipt_id: str,
    construction_feasibility_receipt_id: str,
) -> dict[str, Any]:
    supplied = load_strict_json(supplied_path, dict)
    _validate_decision_receipt_id(supplied)
    _same_look1_decision_material(dict(recomputed_material), _decision_material(supplied))
    try:
        runner.validate_look1_extension_decision(
            dict(config),
            config_id,
            source_commit,
            source_evidence_binding_id,
            corpus_equivalence_receipt_id,
            construction_feasibility_receipt_id,
            supplied_path,
            supplied["receipt_id"],
            require_look2=False,
        )
    except (OSError, UnicodeError, ValueError) as error:
        raise AggregateValidationError("runner rejected the look1 decision receipt") from error
    return supplied


def _v1_relation_material(
    config: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], set[tuple[str, str]]]:
    selection = config.get("confirmation_selection")
    if type(selection) is not dict:
        raise AggregateValidationError("v1 config lacks confirmation_selection")
    ledger = selection.get("candidate_and_matched_neighbors")
    if type(ledger) is not list or len(ledger) != 46:
        raise AggregateValidationError("v1 ledger must contain exactly 46 entries")
    candidates: dict[str, dict[str, Any]] = {}
    neighbors: list[dict[str, Any]] = []
    universe: set[tuple[str, str]] = set()
    for index, entry in enumerate(ledger):
        if type(entry) is not dict:
            raise AggregateValidationError(f"v1 ledger[{index}] is not a mapping")
        method = entry.get("method")
        parameters = entry.get("parameters")
        identity = _identity(method, parameters)
        universe.add(identity)
        expected_spec_id = v1_aggregate._timing_spec_id(method, parameters)
        if entry.get("spec_id") != expected_spec_id:
            raise AggregateValidationError("v1 ledger spec identity does not recompute")
        role = entry.get("role")
        selection_key = entry.get("selection_key")
        if type(selection_key) is not str or not selection_key:
            raise AggregateValidationError("v1 ledger selection_key is invalid")
        if role == "budget_candidate":
            if selection_key in candidates:
                raise AggregateValidationError("v1 ledger duplicates a candidate")
            candidates[selection_key] = entry
        elif role == "matched_neighbor":
            neighbors.append(entry)
        else:
            raise AggregateValidationError("v1 ledger has an unknown role")
    if len(candidates) != 18 or len(neighbors) != V1_RELATION_COUNT:
        raise AggregateValidationError("v1 candidate/relation count differs from freeze")
    relations: list[dict[str, Any]] = []
    relation_ids: set[str] = set()
    for neighbor in neighbors:
        selection_key = str(neighbor["selection_key"])
        candidate = candidates.get(selection_key)
        if candidate is None:
            raise AggregateValidationError("v1 neighbor lacks its candidate")
        if neighbor.get("anchor_candidate_spec_id") != candidate.get("spec_id"):
            raise AggregateValidationError("v1 neighbor anchor differs from candidate")
        if neighbor.get("neighbor_direction") not in {"lower", "upper"}:
            raise AggregateValidationError("v1 neighbor direction is invalid")
        for field in (
            "profile",
            "memory_budget_bits_per_account",
            "memory_budget_total_edge_bytes",
        ):
            if neighbor.get(field) != candidate.get(field):
                raise AggregateValidationError(
                    "v1 relation context differs between candidate and neighbor"
                )
        material = {
            "selection_key": selection_key,
            "profile": neighbor.get("profile"),
            "memory_budget_bits_per_account": neighbor.get("memory_budget_bits_per_account"),
            "neighbor_direction": neighbor.get("neighbor_direction"),
            "candidate_spec_id": candidate.get("spec_id"),
            "neighbor_spec_id": neighbor.get("spec_id"),
            "candidate_method": candidate.get("method"),
            "candidate_parameters": candidate.get("parameters"),
            "neighbor_method": neighbor.get("method"),
            "neighbor_parameters": neighbor.get("parameters"),
        }
        relation_identity = {
            key: material[key]
            for key in (
                "selection_key",
                "profile",
                "memory_budget_bits_per_account",
                "neighbor_direction",
                "candidate_spec_id",
                "neighbor_spec_id",
            )
        }
        relation_id = _sha256(relation_identity)
        if relation_id in relation_ids:
            raise AggregateValidationError("v1 relation identity is duplicated")
        relation_ids.add(relation_id)
        relations.append({**material, "relation_id": relation_id})
    if len(universe) != 24:
        raise AggregateValidationError("v1 ledger must contain exactly 24 unique specs")
    return sorted(relations, key=lambda row: row["relation_id"]), universe


def _v1_relation_decision(mean_log: float, upper_log: float) -> str:
    return v1_aggregate._latency_relation_decision(
        mean_log_ratio=mean_log,
        upper_log_ratio=upper_log,
        margin=V1_MARGIN,
    )


def validate_v1_replication(
    *,
    v1_config_path: Path,
    v1_audit_path: Path,
    config: Mapping[str, Any],
    look1_rows: Sequence[dict[str, Any]],
    v2_universe: set[tuple[str, str]],
) -> dict[str, Any]:
    try:
        v1_config, v1_config_id = v1_timing.load_config(v1_config_path)
    except (OSError, UnicodeError, ValueError) as error:
        raise AggregateValidationError("cannot validate frozen v1 timing config") from error
    v1_audit = load_strict_json(v1_audit_path, dict)
    source = config["source_evidence"]
    frozen = {
        "semantic_config_id": _source_pin(source, "immutable_v1_timing_semantic_config_id", str),
        "candidate_set_id": _source_pin(source, "immutable_v1_candidate_set_id", str),
        "source_commit": _source_pin(source, "immutable_v1_timing_commit", str),
        "raw_observation_set_sha256": _source_pin(
            source, "immutable_v1_raw_observation_set_sha256", str
        ),
        "timing_claim_gate": _source_pin(source, "immutable_v1_timing_claim_gate", str),
        "relation_count": _source_pin(source, "immutable_v1_relation_count", int),
        "pass_count": _source_pin(source, "immutable_v1_pass_count", int),
        "fail_count": _source_pin(source, "immutable_v1_fail_count", int),
        "indeterminate_count": _source_pin(source, "immutable_v1_indeterminate_count", int),
    }
    if v1_config_id != frozen["semantic_config_id"]:
        raise AggregateValidationError("v1 config ID differs from the frozen pin")
    if v1_config.get("candidate_set_id") != frozen["candidate_set_id"]:
        raise AggregateValidationError("v1 candidate-set ID differs from the frozen pin")
    for field, expected in {
        key: frozen[key]
        for key in (
            "semantic_config_id",
            "candidate_set_id",
            "source_commit",
            "raw_observation_set_sha256",
        )
    }.items():
        if v1_audit.get(field) != expected:
            raise AggregateValidationError(f"v1 audit {field} differs from the pin")
    family = v1_audit.get("latency_match_family")
    if type(family) is not dict:
        raise AggregateValidationError("v1 audit lacks its relation family")
    if (
        v1_audit.get("timing_claim_gate") != frozen["timing_claim_gate"]
        or family.get("gate") != frozen["timing_claim_gate"]
        or family.get("relation_count") != frozen["relation_count"]
        or family.get("relation_count") != V1_RELATION_COUNT
        or family.get("noninferiority_ratio_margin") != V1_MARGIN
        or family.get("familywise_alpha") != V1_FAMILYWISE_ALPHA
        or family.get("paired_unit") != "measurement_trial_seed"
        or family.get("multiplicity_adjustment") != "bonferroni_one_sided_student_t_log_ratio_v1"
    ):
        raise AggregateValidationError("v1 relation family differs from the freeze")
    expected_decision_counts = {
        "PASS_NONINFERIOR": frozen["pass_count"],
        "FAIL_POINT_ESTIMATE_EXCEEDS_MARGIN": frozen["fail_count"],
        "INDETERMINATE_NONINFERIORITY_NOT_ESTABLISHED": frozen["indeterminate_count"],
    }
    if family.get("decision_counts") != expected_decision_counts:
        raise AggregateValidationError("v1 decision counts differ from the frozen pins")
    relations, v1_universe = _v1_relation_material(v1_config)
    if not v1_universe <= v2_universe:
        raise AggregateValidationError("v2 794-point universe omits a v1 relation spec")
    audit_relation_ids = {
        row.get("relation_id") for row in family.get("relations", []) if type(row) is dict
    }
    if audit_relation_ids != {row["relation_id"] for row in relations}:
        raise AggregateValidationError("v1 audit relation IDs differ from its ledger")
    by_point: dict[tuple[str, str], dict[int, float]] = defaultdict(dict)
    for row in look1_rows:
        identity = _identity(row["method"], row["configured_spec"])
        seed = int(row["measurement_trial_seed"])
        if seed in by_point[identity]:
            raise AggregateValidationError("v1 replication point has duplicate seed")
        by_point[identity][seed] = _number(row[QUERY_ONLY_METRIC], QUERY_ONLY_METRIC, positive=True)
    expected_seeds = set(runner.LOOK1_SEEDS)
    alpha_per_relation = V1_FAMILYWISE_ALPHA / V1_RELATION_COUNT
    critical = float(student_t.ppf(1.0 - alpha_per_relation, V1_PAIRED_SEED_COUNT - 1))
    reports: list[dict[str, Any]] = []
    for relation in relations:
        candidate_identity = _identity(
            relation["candidate_method"], relation["candidate_parameters"]
        )
        neighbor_identity = _identity(relation["neighbor_method"], relation["neighbor_parameters"])
        if (
            set(by_point[candidate_identity]) != expected_seeds
            or set(by_point[neighbor_identity]) != expected_seeds
        ):
            raise AggregateValidationError("v1 replication lacks a paired look1 seed")
        ratios: dict[str, float] = {}
        logs: list[float] = []
        for seed in runner.LOOK1_SEEDS:
            ratio = by_point[candidate_identity][seed] / by_point[neighbor_identity][seed]
            ratios[str(seed)] = ratio
            logs.append(math.log(ratio))
        mean_log = statistics.fmean(logs)
        standard_error = statistics.stdev(logs) / math.sqrt(len(logs))
        upper_log = mean_log + critical * standard_error
        reports.append(
            {
                **{
                    key: relation[key]
                    for key in (
                        "relation_id",
                        "selection_key",
                        "profile",
                        "memory_budget_bits_per_account",
                        "neighbor_direction",
                        "candidate_spec_id",
                        "neighbor_spec_id",
                    )
                },
                "paired_seed_count": len(logs),
                "paired_seed_source": "v2_warm_look1_only",
                "primary_metric": QUERY_ONLY_METRIC,
                "paired_seed_ratios": ratios,
                "mean_log_ratio": mean_log,
                "log_ratio_standard_error": standard_error,
                "simultaneous_upper_log_ratio": upper_log,
                "simultaneous_upper_ratio_bound": math.exp(upper_log),
                "noninferiority_ratio_margin": V1_MARGIN,
                "decision": _v1_relation_decision(mean_log, upper_log),
            }
        )
    decisions = Counter(report["decision"] for report in reports)
    relation_family_id = _sha256(
        {
            "schema": "traps-phase1-v1-secondary-replication-family-v1",
            "v1_semantic_config_id": v1_config_id,
            "candidate_set_id": frozen["candidate_set_id"],
            "relation_ids": sorted(row["relation_id"] for row in reports),
        }
    )
    expected_family_id = source.get("immutable_v1_relation_family_id")
    if expected_family_id is not None and relation_family_id != expected_family_id:
        raise AggregateValidationError("v1 relation-family identity differs from config")
    return {
        "status": "SECONDARY_REPLICATION_ONLY_DOES_NOT_CONTROL_V2_GATE",
        "v1_semantic_config_id": v1_config_id,
        "v1_candidate_set_id": frozen["candidate_set_id"],
        "v1_reference_source_commit": frozen["source_commit"],
        "v1_reference_raw_observation_set_sha256": frozen["raw_observation_set_sha256"],
        "relation_family_id": relation_family_id,
        "relation_count": len(reports),
        "paired_seed_count": V1_PAIRED_SEED_COUNT,
        "paired_seed_source": "v2_warm_look1_only_even_when_final_uses_n40",
        "comparison_domain": "paired_log_ratio",
        "one_sided_familywise_alpha": V1_FAMILYWISE_ALPHA,
        "bonferroni_alpha_per_relation": alpha_per_relation,
        "simultaneous_one_sided_critical": critical,
        "margin": V1_MARGIN,
        "decision_counts": dict(sorted(decisions.items())),
        "relations": reports,
        "controls_v2_p0_eligibility": False,
    }


def _descriptive_and_conservative_frontiers(
    points: list[dict[str, Any]], profile: str
) -> tuple[list[str], list[str]]:
    eligible = [point for point in points if point[f"eligible_profile_{profile}"]]

    def point_dominates(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        coordinates = (
            (left["memory_total_edge_bytes"], right["memory_total_edge_bytes"]),
            (left["first_seen_ffr"], right["first_seen_ffr"]),
            (
                left["actual_front_warm_p99"]["geometric_mean"],
                right["actual_front_warm_p99"]["geometric_mean"],
            ),
        )
        return all(left_value <= right_value for left_value, right_value in coordinates) and any(
            left_value < right_value for left_value, right_value in coordinates
        )

    def certified_dominates(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
        coordinates = (
            (left["memory_total_edge_bytes"], right["memory_total_edge_bytes"]),
            (
                left["first_seen_ffr_simultaneous_ci_high"],
                right["first_seen_ffr_simultaneous_ci_low"],
            ),
            (
                left["actual_front_warm_p99"]["simultaneous_ci_high"],
                right["actual_front_warm_p99"]["simultaneous_ci_low"],
            ),
        )
        return all(left_value <= right_value for left_value, right_value in coordinates) and any(
            left_value < right_value for left_value, right_value in coordinates
        )

    descriptive = [
        point["point_id"]
        for point in eligible
        if not any(other is not point and point_dominates(other, point) for other in eligible)
    ]
    conservative = [
        point["point_id"]
        for point in eligible
        if not any(other is not point and certified_dominates(other, point) for other in eligible)
    ]
    return sorted(descriptive), sorted(conservative)


def _summarize_points(
    *,
    warm_rows: Sequence[dict[str, Any]],
    cold_rows: Sequence[dict[str, Any]],
    source: SourceEvidence,
    config: Mapping[str, Any],
) -> list[dict[str, Any]]:
    warm = _warm_groups(warm_rows)
    cold = _warm_groups(cold_rows)
    if set(warm) != set(source.records) or set(cold) != set(source.records):
        raise AggregateValidationError("timing/source identity universes differ")
    coordinate_alpha = float(config["warm"]["simultaneous_coordinate_alpha"])
    expected_timing_count = len(warm_rows) // runner.PHASE1_SPEC_COUNT
    points: list[dict[str, Any]] = []
    for identity in sorted(source.records):
        source_record = source.records[identity]
        group = warm[identity]
        cold_group = cold[identity]
        if len(group) != expected_timing_count or len(cold_group) != 1:
            raise AggregateValidationError("timing point block count mismatch")
        memories = {
            _integer(row["memory_total_edge_bytes"], "timing.memory", positive=True)
            for row in (*group, *cold_group)
        }
        if memories != {source_record["memory_total_edge_bytes"]}:
            raise AggregateValidationError("timing exact memory differs from Phase 1 source")
        actual = _log_t_summary([float(row[PRIMARY_METRIC]) for row in group], coordinate_alpha)
        point = {
            "schema": POINT_SCHEMA,
            **source_record,
            "timing_seed_count": len(group),
            "timing_seeds": sorted(int(row["measurement_trial_seed"]) for row in group),
            "timing_seeds_are_not_ffr_construction_trials": True,
            "actual_front_warm_p99": actual,
            "filter_query_only_warm_p99_descriptive": _mean_t_summary(
                [float(row[QUERY_ONLY_METRIC]) for row in group]
            ),
            "actual_front_throughput_qps_descriptive": _mean_t_summary(
                [float(row["actual_front_throughput_qps_mean"]) for row in group]
            ),
            "filter_query_only_cold_p99_us_descriptive": float(
                cold_group[0]["filter_query_only_cold_p99_us"]
            ),
            "cold_claim_scope": config["cold"]["claim_scope"],
        }
        points.append(point)
    for profile in ("U", "A"):
        descriptive, conservative = _descriptive_and_conservative_frontiers(points, profile)
        descriptive_set = set(descriptive)
        conservative_set = set(conservative)
        for point in points:
            point[f"point_estimate_frontier_{profile}"] = point["point_id"] in descriptive_set
            point[f"conservative_frontier_{profile}"] = point["point_id"] in conservative_set
    return points


def _aggregate_id(value: Mapping[str, Any]) -> str:
    material = dict(value)
    material.pop("aggregate_id", None)
    return _sha256(material)


def _finalize_aggregate(
    value: dict[str, Any],
    *,
    analysis_binding: Mapping[str, Any],
    expected_source_commit: str,
) -> dict[str, Any]:
    value["aggregate_id"] = _aggregate_id(value)
    _same_exact(
        analysis_binding,
        _analysis_checkout_binding(expected_source_commit),
        "analysis_checkout_completion",
    )
    return value


def validate_and_aggregate(
    *,
    raw_root: Path,
    config_path: Path,
    expected_source_commit: str,
    frontier_audit_path: Path,
    frontier_summary_path: Path,
    grid_dir: Path,
    grid_config_path: Path,
    clean_attestation_path: Path,
    diagnostic_raw_dir: Path,
    diagnostic_artifact_path: Path,
    corpus_receipt_path: Path,
    construction_receipt_path: Path,
    look1_decision_path: Path,
    v1_config_path: Path,
    v1_audit_path: Path,
) -> dict[str, Any]:
    analysis_binding = _analysis_checkout_binding(expected_source_commit)
    config, config_id = runner.load_config(config_path)
    source = validate_source_evidence(
        config=config,
        frontier_audit_path=frontier_audit_path,
        frontier_summary_path=frontier_summary_path,
        grid_dir=grid_dir,
        grid_config_path=grid_config_path,
        clean_attestation_path=clean_attestation_path,
        diagnostic_raw_dir=diagnostic_raw_dir,
        diagnostic_artifact_path=diagnostic_artifact_path,
    )
    support = validate_support_receipts(
        config,
        config_id,
        expected_source_commit,
        source.binding["source_evidence_binding_id"],
        corpus_receipt_path,
        construction_receipt_path,
    )
    dataset_config = config["dataset"]
    dataset_id = _dataset_id(
        int(dataset_config["account_count"]),
        int(dataset_config["seed"]),
        int(dataset_config["nonmember_count"]),
    )
    if support["semantic_dataset_id"] != dataset_id:
        raise AggregateValidationError("support receipt dataset differs from recomputation")
    look1, look1_strata = _validate_stage(
        raw_root=raw_root,
        config=config,
        config_id=config_id,
        dataset_id=dataset_id,
        expected_source_commit=expected_source_commit,
        source_binding=source.binding,
        support_binding=support,
        stage="warm-look1",
        required=True,
    )
    recomputed_decision_material = _recomputed_decision_without_timestamp(
        allow_existing_look2=True,
        raw_root=raw_root,
        config_path=config_path,
        expected_source_commit=expected_source_commit,
        frontier_audit_path=frontier_audit_path,
        frontier_summary_path=frontier_summary_path,
        grid_dir=grid_dir,
        grid_config_path=grid_config_path,
        clean_attestation_path=clean_attestation_path,
        diagnostic_raw_dir=diagnostic_raw_dir,
        diagnostic_artifact_path=diagnostic_artifact_path,
        corpus_receipt_path=corpus_receipt_path,
        construction_receipt_path=construction_receipt_path,
    )
    decision = validate_look1_decision(
        look1_decision_path,
        recomputed_material=recomputed_decision_material,
        config=config,
        config_id=config_id,
        source_commit=expected_source_commit,
        source_evidence_binding_id=source.binding["source_evidence_binding_id"],
        corpus_equivalence_receipt_id=support["corpus_equivalence_receipt_id"],
        construction_feasibility_receipt_id=support["construction_feasibility_receipt_id"],
    )
    look2_present = any(path.exists() for path in _stage_paths(raw_root, config, "warm-look2"))
    if decision["decision"] != REQUIRE_FULL_LOOK2 and look2_present:
        raise AggregateValidationError("look2 is forbidden after a non-extension decision")
    if decision["decision"] == REQUIRE_FULL_LOOK2 and not look2_present:
        raise AggregateValidationError("full look2 is required by the interim decision")
    look2_support = {
        **support,
        "look1_extension_decision_receipt_id": decision["receipt_id"],
        "expected_look1_extension_decision_id": decision["receipt_id"],
    }
    look2, look2_strata = _validate_stage(
        raw_root=raw_root,
        config=config,
        config_id=config_id,
        dataset_id=dataset_id,
        expected_source_commit=expected_source_commit,
        source_binding=source.binding,
        support_binding=look2_support,
        stage="warm-look2",
        required=decision["decision"] == REQUIRE_FULL_LOOK2,
    )
    cold, cold_strata = _validate_stage(
        raw_root=raw_root,
        config=config,
        config_id=config_id,
        dataset_id=dataset_id,
        expected_source_commit=expected_source_commit,
        source_binding=source.binding,
        support_binding=support,
        stage="cold",
        required=True,
    )
    _reject_extra_raw_shards(raw_root, config, include_look2=bool(look2), include_cold=True)
    warm_rows = [*look1, *look2]
    points = _summarize_points(warm_rows=warm_rows, cold_rows=cold, source=source, config=config)
    hardware_strata = sorted(set((*look1_strata, *look2_strata, *cold_strata)))
    precision_pass = all(point["actual_front_warm_p99"]["precision_gate_pass"] for point in points)
    timer_pass = all(
        float(row["primary_p99_to_clock_call_p99_ratio"]) >= TIMER_MINIMUM_RATIO
        for row in warm_rows
    )
    stratum_pass = len(hardware_strata) == 1
    p0_eligible = precision_pass and timer_pass and stratum_pass
    reasons: list[str] = []
    if not precision_pass:
        reasons.append(
            "PRIMARY_PRECISION_RELATIVE_HALF_WIDTH_EXCEEDS_0_05_"
            f"AT_N{len(warm_rows) // len(points)}"
        )
    if not timer_pass:
        reasons.append("PRIMARY_P99_BELOW_10X_CLOCK_CALL_P99")
    if not stratum_pass:
        reasons.append("MIXED_HARDWARE_STRATA")
    frontiers: dict[str, Any] = {}
    for profile in ("U", "A"):
        descriptive = sorted(
            point["point_id"] for point in points if point[f"point_estimate_frontier_{profile}"]
        )
        conservative = sorted(
            point["point_id"] for point in points if point[f"conservative_frontier_{profile}"]
        )
        if not descriptive or not conservative:
            raise AggregateValidationError(f"profile {profile} has an empty frontier")
        frontiers[profile] = {
            "eligible_point_count": sum(point[f"eligible_profile_{profile}"] for point in points),
            "point_estimate_frontier_point_ids": descriptive,
            "conservative_frontier_point_ids": conservative,
        }
    v1 = validate_v1_replication(
        v1_config_path=v1_config_path,
        v1_audit_path=v1_audit_path,
        config=config,
        look1_rows=look1,
        v2_universe=set(source.records),
    )
    aggregate = {
        "schema": AGGREGATE_SCHEMA,
        "validation_status": VALID_COMPLETE if p0_eligible else VALID_BUT_NONPROMOTABLE,
        "p0_eligible": p0_eligible,
        "reason_codes": reasons,
        "protocol": runner.PROTOCOL,
        "semantic_config_id": config_id,
        "semantic_dataset_id": dataset_id,
        "source_commit": expected_source_commit,
        **analysis_binding,
        "source_evidence": source.binding,
        "support_receipts": support,
        "look1_extension_decision": decision,
        "observation_sets": {
            "look1": _observation_set_id(look1, "warm-look1"),
            "look2": _observation_set_id(look2, "warm-look2") if look2 else None,
            "cold": _observation_set_id(cold, "cold"),
            "all": _observation_set_id([*warm_rows, *cold], "all"),
        },
        "counts": {
            "specifications": len(points),
            "warm_timing_seeds_per_spec": len(warm_rows) // len(points),
            "warm_rows": len(warm_rows),
            "cold_rows": len(cold),
            "cold_seeds_per_spec": 1,
            "hardware_strata": len(hardware_strata),
        },
        "gates": {
            "complete_794_point_coverage": True,
            "single_hardware_stratum": stratum_pass,
            "all_primary_precision_relative_half_width_lte_0_05": precision_pass,
            "all_primary_p99_at_least_10x_clock_call_p99": timer_pass,
            "p0_eligible": p0_eligible,
        },
        "precision_contract": {
            "familywise_alpha": 0.05,
            "look_alpha": 0.025,
            "uncertain_coordinate_count_per_point": 2,
            "point_count": runner.PHASE1_SPEC_COUNT,
            "coordinate_alpha": config["warm"]["simultaneous_coordinate_alpha"],
            "scale": "log",
            "relative_half_width_definition": (
                "max_upper_over_gm_minus_one_and_one_minus_lower_over_gm"
            ),
            "unrounded_gate": "log_half_width <= log1p(0.05)",
        },
        "hardware_strata": hardware_strata,
        "points": points,
        "frontiers": frontiers,
        "v1_secondary_replication": v1,
        "scientific_boundary": {
            "primary_axes": [
                "memory_total_edge_bytes",
                "first_seen_ffr",
                PRIMARY_METRIC,
            ],
            "query_only_throughput_and_cold_are_descriptive": True,
            "point_estimate_frontier_is_descriptive": True,
            "conservative_frontier_uses_certified_dominance": True,
            "candidate_winner_does_not_control_p0_eligibility": True,
            "v1_replication_does_not_control_p0_eligibility": True,
            "frontier_composition_does_not_control_p0_eligibility": True,
        },
    }
    return _finalize_aggregate(
        aggregate,
        analysis_binding=analysis_binding,
        expected_source_commit=expected_source_commit,
    )


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    except OSError:
        if os.name != "nt":
            raise
    finally:
        os.close(descriptor)


def atomic_write_json_no_replace(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise AggregateValidationError(f"refusing to overwrite {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            json.dump(value, handle, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        linked = False
        try:
            os.link(temporary, path)
            linked = True
            _fsync_directory(path.parent)
        except FileExistsError as error:
            raise AggregateValidationError(f"refusing to overwrite {path}") from error
        except Exception:
            if linked:
                path.unlink(missing_ok=True)
            raise
    finally:
        temporary.unlink(missing_ok=True)


def _common_parser(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--source-frontier-audit", type=Path, required=True)
    parser.add_argument("--source-frontier-summary", type=Path, required=True)
    parser.add_argument("--source-grid-dir", type=Path, required=True)
    parser.add_argument("--source-grid-config", type=Path, required=True)
    parser.add_argument("--source-clean-attestation", type=Path, required=True)
    parser.add_argument("--source-analytic-diagnostic-dir", type=Path, required=True)
    parser.add_argument("--source-analytic-diagnostic", type=Path, required=True)
    parser.add_argument("--corpus-equivalence-receipt", type=Path, required=True)
    parser.add_argument("--construction-feasibility-receipt", type=Path, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    look1 = subparsers.add_parser("look1-decision")
    _common_parser(look1)
    look1.add_argument("--output", type=Path, required=True)
    final = subparsers.add_parser("final")
    _common_parser(final)
    final.add_argument("--look1-decision", type=Path, required=True)
    final.add_argument("--v1-config", type=Path, required=True)
    final.add_argument("--v1-audit", type=Path, required=True)
    final.add_argument("--output", type=Path, required=True)
    return parser


def _common_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "raw_root": args.raw_root,
        "config_path": args.config,
        "expected_source_commit": args.expected_source_commit,
        "frontier_audit_path": args.source_frontier_audit,
        "frontier_summary_path": args.source_frontier_summary,
        "grid_dir": args.source_grid_dir,
        "grid_config_path": args.source_grid_config,
        "clean_attestation_path": args.source_clean_attestation,
        "diagnostic_raw_dir": args.source_analytic_diagnostic_dir,
        "diagnostic_artifact_path": args.source_analytic_diagnostic,
        "corpus_receipt_path": args.corpus_equivalence_receipt,
        "construction_receipt_path": args.construction_feasibility_receipt,
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if args.mode == "look1-decision":
            result = build_look1_extension_decision(**_common_kwargs(args))
            atomic_write_json_no_replace(args.output, result)
            print(_canonical(result))
            return 0 if result["validation_status"] == "VALID" else 2
        result = validate_and_aggregate(
            **_common_kwargs(args),
            look1_decision_path=args.look1_decision,
            v1_config_path=args.v1_config,
            v1_audit_path=args.v1_audit,
        )
        atomic_write_json_no_replace(args.output, result)
    except SystemExit as error:
        return 0 if error.code == 0 else 3
    except Exception as error:
        print(
            f"v2 aggregate refused: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 3
    print(_canonical(result))
    return 0 if result["p0_eligible"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
