#!/usr/bin/env python3
"""Strict aggregation for the staged Phase 1 isolated-timing protocol."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import statistics
import sys
from collections import Counter, defaultdict
from functools import lru_cache
from itertools import combinations
from pathlib import Path
from typing import Any

from scipy.stats import t as student_t

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.analysis.filter_frontier import (  # noqa: E402
    SOURCE_STATUS_SCOPE,
    _canonical,
    _mean_ci,
    _method_for_spec,
    _parse_utc,
    _reject_duplicate_json_keys,
    _validate_filter_parameters,
)
from experiments.runners.filter_bench import (  # noqa: E402
    SyntheticCredentialSet,
    load_config,
)
from experiments.runners.filter_timing import (  # noqa: E402
    CONFIRMATION_CANDIDATE_SET_ID,
    CONFIRMATION_SEEDS,
    FORMAL_QUERY_WINDOW_ASSIGNMENT,
    FORMAL_SAMPLE_CONTRACT,
    LATENCY_MATCH_ADJUSTMENT,
    LATENCY_MATCH_DECISION_RULE,
    LATENCY_MATCH_FAMILY,
    LATENCY_MATCH_SCOPE,
    PHASE1_DATASET_ID,
    PHASE1_SPEC_COUNT,
    TIMING_PROTOCOL,
    _confirmation_selection,
    expand_timing_specs,
    load_phase1_selection_aggregate,
    observation_sha256,
    ordered_timing_points,
    query_window_assignment,
    recompute_candidate_set_id,
    validate_frozen_config_id,
    validate_timing_config,
)

SHARD_PATTERN = re.compile(
    r"^filter_timing_E1\.(pilot|screening|confirmation)\."
    r"shard-(\d+)-of-(\d+)\.jsonl$"
)
INTERNAL_SOURCE_FILE = "_timing_source_filename"


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant {value}")


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError(f"non-finite JSON number {value}")
    return parsed


def _stage_filename_label(stage: str) -> str:
    return {
        "pilot": "pilot",
        "all_spec_screening": "screening",
        "candidate_confirmation": "confirmation",
    }[stage]


def load_timing_shards(
    input_dir: Path, expected_shards: int, expected_stage: str
) -> list[dict[str, Any]]:
    paths = sorted(input_dir.rglob("filter_timing_E1.*.jsonl"))
    if len(paths) != expected_shards:
        raise ValueError(
            f"expected {expected_shards} timing shard files, found {len(paths)}"
        )
    expected_label = _stage_filename_label(expected_stage)
    observed_indices: set[int] = set()
    rows: list[dict[str, Any]] = []
    for path in paths:
        match = SHARD_PATTERN.fullmatch(path.name)
        if match is None:
            raise ValueError(f"malformed timing shard filename: {path.name}")
        stage_label, index_text, count_text = match.groups()
        index, count = int(index_text), int(count_text)
        if stage_label != expected_label:
            raise ValueError(f"timing shard {path.name} has the wrong stage label")
        if count != expected_shards:
            raise ValueError(f"timing shard {path.name} has the wrong shard count")
        if index in observed_indices:
            raise ValueError(f"duplicate timing shard index {index}")
        observed_indices.add(index)
        file_rows = 0
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                label = f"{path.name}:{line_number}"
                try:
                    row = json.loads(
                        line,
                        object_pairs_hook=_reject_duplicate_json_keys,
                        parse_constant=_reject_json_constant,
                        parse_float=_parse_finite_json_float,
                    )
                except ValueError as error:
                    raise ValueError(f"{label}: malformed JSON") from error
                if not isinstance(row, dict):
                    raise ValueError(f"{label}: row must be a mapping")
                if (
                    type(row.get("shard_index")) is not int
                    or row["shard_index"] != index
                    or type(row.get("shard_count")) is not int
                    or row["shard_count"] != count
                ):
                    raise ValueError(f"{label}: shard metadata mismatch")
                row[INTERNAL_SOURCE_FILE] = path.name
                rows.append(row)
                file_rows += 1
        if file_rows == 0:
            raise ValueError(f"empty timing shard {path.name}")
    if observed_indices != set(range(expected_shards)):
        raise ValueError("timing shard indices are incomplete")
    return rows


def _expected_points(
    config: dict[str, Any], shard_count: int
) -> tuple[
    Counter[tuple[str, str, int]],
    dict[int, Counter[tuple[str, str, int]]],
    dict[tuple[str, str, int], int],
]:
    points = ordered_timing_points(config)
    expected: Counter[tuple[str, str, int]] = Counter()
    by_shard = {index: Counter() for index in range(shard_count)}
    order_by_identity: dict[tuple[str, str, int], int] = {}
    for ordinal, (seed, spec) in enumerate(points):
        identity = (
            _method_for_spec(spec.family, spec.parameters),
            _canonical(spec.parameters),
            seed,
        )
        expected[identity] += 1
        by_shard[ordinal % shard_count][identity] += 1
        order_by_identity[identity] = ordinal
    return expected, by_shard, order_by_identity


@lru_cache(maxsize=None)
def _dataset_id(account_count: int, dataset_seed: int, nonmember_count: int) -> str:
    dataset = SyntheticCredentialSet(account_count, dataset_seed)
    members = [dataset.member(index) for index in range(dataset.account_count)]
    return dataset.manifest_hash(members, nonmember_count)


def _row_identity(row: dict[str, Any]) -> tuple[str, str, int]:
    configured = row.get("configured_spec")
    seed = row.get("measurement_trial_seed")
    if not isinstance(configured, dict):
        raise ValueError("timing configured_spec must be a mapping")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("timing measurement_trial_seed must be an integer")
    return str(row.get("method")), _canonical(configured), seed


def _recomputed_run_id(
    row: dict[str, Any], config_id: str, dataset_id: str
) -> str:
    configured = row["configured_spec"]
    method = str(row["method"])
    family = (
        "tag"
        if method == "exact_tag_128" or method.startswith("truncated_tag_")
        else {
            "global_bloom": "global_bloom",
            "blocked_bloom_64b": "blocked_bloom",
            "xor_static_3way": "xor_static",
            "cuckoo_filter": "cuckoo",
        }[method]
    )
    identity = json.dumps(configured, sort_keys=True, separators=(",", ":"))
    material = (
        f"{row['commit']}:{config_id}:{dataset_id}:"
        f"{row['measurement_trial_seed']}:{family}:{identity}:"
        f"{row.get('measurement_order')}:{row.get('shard_index')}:"
        f"{row.get('shard_count')}"
    )
    return hashlib.sha256(material.encode()).hexdigest()[:24]


def _number(row: dict[str, Any], field: str, *, positive: bool = False) -> float:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"timing {field} must be numeric")
    result = float(value)
    if not math.isfinite(result) or result < 0.0 or (positive and result == 0.0):
        raise ValueError(f"timing {field} must be finite and nonnegative")
    return result


def _integer(row: dict[str, Any], field: str) -> int:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"timing {field} must be a nonnegative integer")
    return value


def _latency_histogram(
    row: dict[str, Any], field: str, expected_count: int
) -> list[tuple[int, int]]:
    value = row.get(field)
    if not isinstance(value, list) or not value:
        raise ValueError(f"timing {field} must be a nonempty array")
    result: list[tuple[int, int]] = []
    total = 0
    previous = -1
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"latency_ns", "count"}:
            raise ValueError(f"timing {field} entry has the wrong schema")
        latency_ns = entry["latency_ns"]
        count = entry["count"]
        if (
            type(latency_ns) is not int
            or latency_ns <= 0
            or latency_ns <= previous
            or type(count) is not int
            or count <= 0
        ):
            raise ValueError(f"timing {field} entry is invalid or unsorted")
        result.append((latency_ns, count))
        total += count
        previous = latency_ns
    if total != expected_count:
        raise ValueError(f"timing {field} count differs from the sample contract")
    return result


def _histogram_value_at(histogram: list[tuple[int, int]], index: int) -> int:
    cursor = 0
    for latency_ns, count in histogram:
        cursor += count
        if index < cursor:
            return latency_ns
    raise AssertionError("validated histogram index is out of range")


def _histogram_percentile_us(
    histogram: list[tuple[int, int]], sample_count: int, quantile: float
) -> float:
    position = quantile * (sample_count - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    lower_value = _histogram_value_at(histogram, lower)
    upper_value = _histogram_value_at(histogram, upper)
    if lower == upper:
        return lower_value / 1000.0
    fraction = position - lower
    return (lower_value * (1.0 - fraction) + upper_value * fraction) / 1000.0


def _close(actual: object, expected: float, label: str) -> None:
    if isinstance(actual, bool) or not isinstance(actual, (int, float)):
        raise ValueError(f"{label} must be numeric")
    if not math.isfinite(float(actual)) or not math.isclose(
        float(actual), expected, rel_tol=2e-12, abs_tol=2e-15
    ):
        raise ValueError(f"{label} mismatch")


def _hardware_stratum(environment: dict[str, Any]) -> str:
    fields = {
        "hostname": environment["hostname"],
        "host_platform": environment["host_platform"],
        "python_version": environment["python_version"],
        "cpu_model": environment["cpu_model"],
        "cpu_model_source": environment["cpu_model_source"],
        "affinity_cpus": environment["affinity_cpus"],
        "affinity_cpu_records": environment["affinity_cpu_records"],
        "scaling_governor_by_affinity_cpu": environment[
            "scaling_governor_by_affinity_cpu"
        ],
    }
    return _canonical(fields)


def _validated_last_level_cache(record: dict[str, Any]) -> int:
    if record.get("cache_enumeration_status") != "COMPLETE":
        raise ValueError("formal timing cache enumeration is not complete")
    cache_records = record.get("cache_records")
    if not isinstance(cache_records, list) or not cache_records:
        raise ValueError("formal timing cache hierarchy is missing")
    candidates: list[tuple[int, int]] = []
    for cache in cache_records:
        if not isinstance(cache, dict):
            raise ValueError("formal timing cache record must be a mapping")
        if (
            not isinstance(cache.get("index"), str)
            or not cache["index"].strip()
            or isinstance(cache.get("level"), bool)
            or not isinstance(cache.get("level"), int)
            or int(cache["level"]) <= 0
            or cache.get("type") not in {"Data", "Instruction", "Unified"}
            or isinstance(cache.get("size_bytes"), bool)
            or not isinstance(cache.get("size_bytes"), int)
            or int(cache["size_bytes"]) <= 0
            or not isinstance(cache.get("shared_cpu_list"), str)
            or not cache["shared_cpu_list"].strip()
        ):
            raise ValueError("formal timing cache record is malformed")
        if cache["type"] in {"Data", "Unified"}:
            candidates.append((int(cache["level"]), int(cache["size_bytes"])))
    if not candidates:
        raise ValueError("formal timing data/unified cache hierarchy is missing")
    level = max(candidate[0] for candidate in candidates)
    size = max(candidate[1] for candidate in candidates if candidate[0] == level)
    if (
        type(record.get("last_level_cache_level")) is not int
        or record["last_level_cache_level"] != level
        or type(record.get("last_level_cache_bytes")) is not int
        or record["last_level_cache_bytes"] != size
    ):
        raise ValueError("formal timing last-level cache summary disagrees with hierarchy")
    return size


def _validate_environment(row: dict[str, Any]) -> str:
    environment = row.get("host_environment")
    if not isinstance(environment, dict):
        raise ValueError("timing host_environment must be a mapping")
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
    _validated_last_level_cache(record)
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
    if environment["host_lock_scope"] != "cooperating TRAPS timing processes only":
        raise ValueError("formal timing overstates its host-lock scope")
    return _hardware_stratum(environment)


def _validate_filter_parameter_integer_types(row: dict[str, Any]) -> None:
    method = str(row.get("method", ""))
    parameters = row.get("filter_parameters")
    if not isinstance(parameters, dict):
        raise ValueError("timing filter_parameters must be a mapping")
    if method == "exact_tag_128" or method.startswith("truncated_tag_"):
        fields = {"m_bits", "n_items", "tag_bits"}
    elif method == "global_bloom":
        fields = {"m_bits", "n_items", "k_hashes", "hash_seed"}
    elif method == "blocked_bloom_64b":
        fields = {
            "requested_m_bits",
            "m_bits",
            "n_items",
            "k_hashes",
            "hash_seed",
            "block_bytes",
            "block_count",
        }
    elif method == "xor_static_3way":
        fields = {
            "m_bits",
            "n_items",
            "k_hashes",
            "fingerprint_bits",
            "capacity",
            "hash_seed",
            "build_attempts",
        }
    elif method == "cuckoo_filter":
        fields = {
            "m_bits",
            "n_items",
            "k_hashes",
            "fingerprint_bits",
            "bucket_count",
            "bucket_size",
            "hash_seed",
            "max_kicks",
            "build_attempts",
        }
    else:
        raise ValueError("timing row has an unknown filter method")
    for field in fields:
        if type(parameters.get(field)) is not int:
            raise ValueError(f"timing filter_parameters.{field} must be an exact integer")


def _validate_row_contract(
    row: dict[str, Any], config: dict[str, Any], config_id: str, dataset_id: str
) -> str:
    stage = str(config["timing_stage"])
    if row.get("commit") is None or row.get("git_dirty") is not False:
        raise ValueError("formal timing lacks clean readable Git provenance")
    if row.get("source_status_scope") != SOURCE_STATUS_SCOPE:
        raise ValueError("formal timing source status scope mismatch")
    if row.get("semantic_config_id") != config_id:
        raise ValueError("formal timing semantic config ID mismatch")
    if row.get("semantic_dataset_id") != dataset_id:
        raise ValueError("formal timing semantic dataset ID mismatch")
    if row.get("formal_timing") is not True or row.get("timing_stage") != stage:
        raise ValueError("formal timing stage/formality mismatch")
    if row.get("result_status") != "OBSERVED":
        raise ValueError("formal timing row is not OBSERVED")
    if row.get("timing_protocol") != TIMING_PROTOCOL:
        raise ValueError("formal timing protocol version mismatch")
    if row.get("timing_protocol_valid") is not True:
        raise ValueError("formal timing protocol is marked invalid")
    if row.get("timing_interval") != "filter.query only":
        raise ValueError("formal timing interval mismatch")
    _parse_utc(row.get("timestamp_utc"), "timing row")
    observation_id = row.get("observation_sha256")
    if (
        not isinstance(observation_id, str)
        or not re.fullmatch(r"[0-9a-f]{64}", observation_id)
        or observation_id != observation_sha256(row)
    ):
        raise ValueError("formal timing observation hash mismatch")
    if row.get("run_id") != _recomputed_run_id(row, config_id, dataset_id):
        raise ValueError("formal timing run_id mismatch")

    method, _, trial_seed = _row_identity(row)
    is_tag = method == "exact_tag_128" or method.startswith("truncated_tag_")
    randomized = row.get("randomized_construction")
    if type(randomized) is not bool or randomized is not (not is_tag):
        raise ValueError("formal timing randomized-construction label mismatch")
    construction_seed = row.get("construction_seed")
    if (construction_seed is None) != is_tag:
        raise ValueError("formal timing construction seed mismatch")
    if not is_tag and construction_seed != trial_seed:
        raise ValueError("formal timing construction/measurement seed mismatch")
    measurement_order = _integer(row, "measurement_order")
    shard_index = _integer(row, "shard_index")
    shard_count = _integer(row, "shard_count")
    timing = config["timing"]
    if measurement_order != shard_index or shard_count != int(
        timing["formal_shard_count"]
    ):
        raise ValueError("formal timing measurement order/shard contract mismatch")
    window_ordinal, window_start = query_window_assignment(config, trial_seed)
    if (
        row.get("query_window_assignment") != FORMAL_QUERY_WINDOW_ASSIGNMENT
        or _integer(row, "query_window_ordinal") != window_ordinal
        or _integer(row, "query_window_start") != window_start
        or _integer(row, "query_window_end_exclusive")
        != window_start
        + int(timing["query_pool_count"])
        + int(timing["warm_latency_query_count"])
        + int(timing["cold_latency_query_count"])
    ):
        raise ValueError("formal timing disjoint query-window binding mismatch")
    hardware_stratum = _validate_environment(row)

    exact_integer_fields = {
        "preflight_query_count": min(1024, int(timing["query_pool_count"])),
        "query_pool_count": int(timing["query_pool_count"]),
        "warmup_query_count": int(timing["warmup_query_count"]),
        "warm_throughput_query_count_per_trial": int(
            timing["warm_throughput_query_count"]
        ),
        "warm_throughput_repetition_count": int(
            timing["warm_throughput_repetitions"]
        ),
        "warm_latency_sample_count": int(timing["warm_latency_query_count"]),
        "cold_latency_sample_count": int(timing["cold_latency_query_count"]),
        "cold_eviction_bytes_per_query": int(timing["cold_eviction_bytes"]),
        "cold_eviction_minimum_llc_multiple": int(
            timing["cold_eviction_minimum_llc_multiple"]
        ),
    }
    for field, expected in exact_integer_fields.items():
        if _integer(row, field) != expected:
            raise ValueError(f"formal timing {field} sample contract mismatch")
    trials = row.get("warm_query_throughput_qps_trials")
    if not isinstance(trials, list) or len(trials) != int(
        timing["warm_throughput_repetitions"]
    ):
        raise ValueError("formal timing throughput trial count mismatch")
    throughput = []
    for value in trials:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("formal timing throughput trial must be numeric")
        if not math.isfinite(float(value)) or float(value) <= 0.0:
            raise ValueError("formal timing throughput trial must be finite and positive")
        throughput.append(float(value))
    _close(
        row.get("warm_query_throughput_qps_mean"),
        statistics.mean(throughput),
        "formal timing throughput mean",
    )
    for prefix, histogram_field, count in (
        (
            "frontend_warm",
            "warm_latency_histogram_ns",
            int(timing["warm_latency_query_count"]),
        ),
        (
            "frontend_cold",
            "cold_latency_histogram_ns",
            int(timing["cold_latency_query_count"]),
        ),
    ):
        histogram = _latency_histogram(row, histogram_field, count)
        for label, quantile in (("p50", 0.50), ("p95", 0.95), ("p99", 0.99)):
            _close(
                row.get(f"{prefix}_{label}_us"),
                _histogram_percentile_us(histogram, count, quantile),
                f"formal timing {prefix} {label} histogram reconstruction",
            )
    _number(row, "build_time_s")
    _integer(row, "preflight_positive_count")
    _integer(row, "cold_eviction_terminal_token")
    environment = row["host_environment"]
    llc_bytes = _validated_last_level_cache(environment["affinity_cpu_records"][0])
    if _integer(row, "cold_eviction_last_level_cache_bytes") != llc_bytes:
        raise ValueError("formal timing cold-eviction LLC binding mismatch")
    eviction_bytes = int(timing["cold_eviction_bytes"])
    minimum_multiple = int(timing["cold_eviction_minimum_llc_multiple"])
    if eviction_bytes < minimum_multiple * llc_bytes:
        raise ValueError("formal timing cold-eviction buffer is too small for the LLC")
    _close(
        row.get("cold_eviction_buffer_to_llc_ratio"),
        eviction_bytes / llc_bytes,
        "formal timing cold-eviction buffer/LLC ratio",
    )
    if (
        row.get("cold_eviction_per_query") is not True
        or row.get("cold_eviction_time_excluded") is not True
        or row.get("cold_eviction_method")
        != "zlib.crc32 native full-buffer read before every query"
        or row.get("cold_eviction_claim_scope")
        != "software cache displacement; not a hardware flush guarantee"
    ):
        raise ValueError("formal timing cold-eviction contract mismatch")
    excluded = row.get("timed_interval_excludes")
    required_exclusions = {
        "query generation",
        "warmup",
        "positive counting",
        "histogram and percentile construction",
        "throughput bookkeeping",
        "cold-cache eviction",
    }
    if not isinstance(excluded, list) or set(excluded) != required_exclusions:
        raise ValueError("formal timing exclusion list mismatch")

    proxy = dict(row)
    proxy["seed"] = construction_seed
    _validate_filter_parameter_integer_types(proxy)
    _validate_filter_parameters(proxy)
    return hardware_stratum


def _summary_interval(
    values: list[float],
) -> tuple[float, float | None, float | None]:
    if len(values) == 1:
        return values[0], None, None
    center, lower, upper = _mean_ci(values)
    return center, max(0.0, lower), upper


def _timing_spec_id(method: object, configured_spec: object) -> str:
    material = {"method": method, "configured_spec": configured_spec}
    return hashlib.sha256(_canonical(material).encode()).hexdigest()


def _latency_relation_decision(
    *, mean_log_ratio: float, upper_log_ratio: float, margin: float
) -> str:
    threshold = math.log(margin)
    if upper_log_ratio <= threshold:
        return "PASS_NONINFERIOR"
    if mean_log_ratio > threshold:
        return "FAIL_POINT_ESTIMATE_EXCEEDS_MARGIN"
    return "INDETERMINATE_NONINFERIORITY_NOT_ESTABLISHED"


def _latency_match_family(
    config: dict[str, Any],
    by_spec: dict[tuple[str, str], dict[int, dict[str, Any]]],
    expected_seeds: set[int],
) -> dict[str, Any]:
    selection = _confirmation_selection(config)
    contract = selection["latency_match_contract"]
    if (
        config.get("candidate_set_id") != CONFIRMATION_CANDIDATE_SET_ID
        or recompute_candidate_set_id(config) != CONFIRMATION_CANDIDATE_SET_ID
    ):
        raise ValueError("latency match family differs from the frozen candidate set")
    if (
        tuple(config.get("seeds", ())) != CONFIRMATION_SEEDS
        or expected_seeds != set(CONFIRMATION_SEEDS)
        or len(expected_seeds) != contract["required_seed_count"]
    ):
        raise ValueError("latency match family lacks the exact frozen paired seeds")
    ledger = selection["candidate_and_matched_neighbors"]
    candidates: dict[str, dict[str, Any]] = {}
    neighbors: list[dict[str, Any]] = []
    for raw_entry in ledger:
        if not isinstance(raw_entry, dict):
            raise ValueError("latency match ledger entry must be a mapping")
        role = raw_entry.get("role")
        selection_key = raw_entry.get("selection_key")
        if type(selection_key) is not str or not selection_key:
            raise ValueError("latency match ledger entry lacks a selection key")
        expected_spec_id = _timing_spec_id(
            raw_entry.get("method"), raw_entry.get("parameters")
        )
        if raw_entry.get("spec_id") != expected_spec_id:
            raise ValueError("latency match ledger spec identity mismatch")
        if role == contract["candidate_role"]:
            if selection_key in candidates:
                raise ValueError("latency match ledger has duplicate budget candidates")
            candidates[selection_key] = raw_entry
        elif role == contract["reference_role"]:
            neighbors.append(raw_entry)
        else:
            raise ValueError("latency match ledger has an unknown role")
    if not candidates or not neighbors:
        raise ValueError("latency match family requires candidates and matched neighbors")
    relation_candidate_keys = {
        str(entry["selection_key"]) for entry in neighbors
    }
    if not relation_candidate_keys.issubset(candidates):
        raise ValueError("latency match ledger candidate/relation coverage mismatch")
    candidates_without_neighbors = sorted(set(candidates) - relation_candidate_keys)

    relation_count = len(neighbors)
    alpha = float(contract["familywise_alpha"])
    alpha_per_relation = alpha / relation_count
    critical = float(
        student_t.ppf(
            1.0 - alpha_per_relation,
            int(contract["required_seed_count"]) - 1,
        )
    )
    if not math.isfinite(critical) or critical <= 0.0:
        raise ValueError("latency match simultaneous critical value is invalid")
    margin = float(contract["noninferiority_ratio_margin"])
    relation_reports: list[dict[str, Any]] = []
    relation_ids: set[str] = set()
    for neighbor in neighbors:
        selection_key = str(neighbor["selection_key"])
        candidate = candidates[selection_key]
        if neighbor.get("anchor_candidate_spec_id") != candidate["spec_id"]:
            raise ValueError("latency match neighbor anchor differs from its candidate")
        if neighbor.get("neighbor_direction") not in {"lower", "upper"}:
            raise ValueError("latency match neighbor direction is invalid")
        for field in (
            "profile",
            "memory_budget_bits_per_account",
            "memory_budget_total_edge_bytes",
        ):
            if neighbor.get(field) != candidate.get(field):
                raise ValueError("latency match relation context differs from its candidate")
        candidate_identity = (
            str(candidate["method"]),
            _canonical(candidate["parameters"]),
        )
        neighbor_identity = (
            str(neighbor["method"]),
            _canonical(neighbor["parameters"]),
        )
        if candidate_identity == neighbor_identity:
            raise ValueError("latency match relation compares a spec with itself")
        if candidate_identity not in by_spec or neighbor_identity not in by_spec:
            raise ValueError("latency match relation lacks a measured frozen spec")
        candidate_rows = by_spec[candidate_identity]
        neighbor_rows = by_spec[neighbor_identity]
        if set(candidate_rows) != expected_seeds or set(neighbor_rows) != expected_seeds:
            raise ValueError("latency match relation lacks a frozen paired seed")
        log_ratios: list[float] = []
        ratios: list[float] = []
        for seed in sorted(expected_seeds):
            candidate_raw = candidate_rows[seed][contract["primary_metric"]]
            neighbor_raw = neighbor_rows[seed][contract["primary_metric"]]
            if type(candidate_raw) not in {int, float} or type(neighbor_raw) not in {
                int,
                float,
            }:
                raise ValueError("latency match p99 values must be exact numeric values")
            candidate_value = float(candidate_raw)
            neighbor_value = float(neighbor_raw)
            if (
                not math.isfinite(candidate_value)
                or not math.isfinite(neighbor_value)
                or candidate_value <= 0.0
                or neighbor_value <= 0.0
            ):
                raise ValueError("latency match requires positive finite paired p99 values")
            ratio = candidate_value / neighbor_value
            ratios.append(ratio)
            log_ratios.append(math.log(ratio))
        mean_log_ratio = statistics.fmean(log_ratios)
        standard_error = statistics.stdev(log_ratios) / math.sqrt(len(log_ratios))
        upper_log_ratio = mean_log_ratio + critical * standard_error
        geometric_ratio = math.exp(mean_log_ratio)
        upper_ratio = math.exp(upper_log_ratio)
        decision = _latency_relation_decision(
            mean_log_ratio=mean_log_ratio,
            upper_log_ratio=upper_log_ratio,
            margin=margin,
        )
        relation_material = {
            "selection_key": selection_key,
            "profile": neighbor["profile"],
            "memory_budget_bits_per_account": neighbor[
                "memory_budget_bits_per_account"
            ],
            "neighbor_direction": neighbor["neighbor_direction"],
            "candidate_spec_id": candidate["spec_id"],
            "neighbor_spec_id": neighbor["spec_id"],
        }
        relation_id = hashlib.sha256(_canonical(relation_material).encode()).hexdigest()
        if relation_id in relation_ids:
            raise ValueError("latency match relation ledger is duplicated")
        relation_ids.add(relation_id)
        relation_reports.append(
            {
                **relation_material,
                "relation_id": relation_id,
                "paired_seed_count": len(log_ratios),
                "paired_seed_ratios": {
                    str(seed): ratio
                    for seed, ratio in zip(sorted(expected_seeds), ratios, strict=True)
                },
                "geometric_mean_candidate_over_neighbor_ratio": geometric_ratio,
                "mean_log_ratio": mean_log_ratio,
                "log_ratio_standard_error": standard_error,
                "simultaneous_upper_log_ratio": upper_log_ratio,
                "simultaneous_upper_ratio_bound": upper_ratio,
                "noninferiority_ratio_margin": margin,
                "decision": decision,
            }
        )
    decisions = Counter(report["decision"] for report in relation_reports)
    if decisions["FAIL_POINT_ESTIMATE_EXCEEDS_MARGIN"]:
        gate = "FAIL_PHASE1_SCREENING_LATENCY_ELIGIBILITY"
    elif decisions["INDETERMINATE_NONINFERIORITY_NOT_ESTABLISHED"]:
        gate = "INDETERMINATE_PHASE1_SCREENING_LATENCY_ELIGIBILITY"
    else:
        gate = "PASS_PHASE1_SCREENING_LATENCY_ELIGIBILITY_ONLY"
    return {
        "schema_version": contract["schema_version"],
        "primary_metric": contract["primary_metric"],
        "paired_unit": contract["paired_unit"],
        "estimand": contract["estimand"],
        "noninferiority_ratio_margin": margin,
        "familywise_alpha": alpha,
        "multiplicity_adjustment": LATENCY_MATCH_ADJUSTMENT,
        "multiplicity_family": LATENCY_MATCH_FAMILY,
        "relation_count": relation_count,
        "candidate_count": len(candidates),
        "candidate_with_relation_count": len(relation_candidate_keys),
        "candidates_without_matched_neighbor": candidates_without_neighbors,
        "candidate_without_neighbor_role": (
            "NOT_IN_MULTIPLICITY_FAMILY_NO_FROZEN_ELIGIBLE_ADJACENT_SPEC"
        ),
        "alpha_per_relation": alpha_per_relation,
        "student_t_degrees_of_freedom": int(contract["required_seed_count"]) - 1,
        "simultaneous_one_sided_critical": critical,
        "decision_rule": LATENCY_MATCH_DECISION_RULE,
        "decision_counts": dict(sorted(decisions.items())),
        "relations": relation_reports,
        "gate": gate,
        "scope": LATENCY_MATCH_SCOPE,
        "scientific_boundary": (
            "Filter-query warm p99 eligibility only; not service p99, an SLA, or "
            "evidence that closes G1, G2, or E7. Cold p99 and throughput remain "
            "descriptive diagnostics."
        ),
    }


def validate_and_summarize(
    rows: list[dict[str, Any]],
    config_path: Path,
    expected_commit: str,
    expected_shards: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    config, config_id = load_config(config_path)
    phase1_aggregate = (
        load_phase1_selection_aggregate(config, config_path)
        if config.get("timing_stage") == "candidate_confirmation"
        and config.get("execution_enabled") is True
        else None
    )
    validate_timing_config(config, phase1_aggregate)
    validate_frozen_config_id(config, config_id)
    if config["formal_timing"] is not True or config["execution_enabled"] is not True:
        raise ValueError("strict aggregation requires an enabled formal timing config")
    frozen_shards = config["timing"].get("formal_shard_count")
    if type(expected_shards) is not int or expected_shards != frozen_shards:
        raise ValueError("strict aggregation shard count differs from the frozen config")

    dataset_config = config["dataset"]
    dataset_id = _dataset_id(
        int(dataset_config["account_count"]),
        int(dataset_config["seed"]),
        int(dataset_config["nonmember_count"]),
    )
    if dataset_id != PHASE1_DATASET_ID:
        raise ValueError("strict timing aggregation dataset ID mismatch")

    expected, expected_by_shard, expected_order = _expected_points(
        config, expected_shards
    )
    if len(rows) != sum(expected.values()):
        raise ValueError(
            f"formal timing expected {sum(expected.values())} rows, found {len(rows)}"
        )
    actual: Counter[tuple[str, str, int]] = Counter()
    actual_by_shard = {index: Counter() for index in range(expected_shards)}
    run_ids: set[str] = set()
    strata_by_row: list[str] = []
    for ordinal, row in enumerate(rows):
        if row.get("commit") != expected_commit:
            raise ValueError(f"timing row {ordinal} source commit mismatch")
        run_id = str(row.get("run_id", ""))
        if not run_id or run_id in run_ids:
            raise ValueError("formal timing has an empty or duplicate run_id")
        run_ids.add(run_id)
        identity = _row_identity(row)
        if _integer(row, "measurement_order") != expected_order.get(identity):
            raise ValueError("formal timing row violates the frozen point order")
        actual[identity] += 1
        shard = row.get("shard_index")
        if isinstance(shard, bool) or not isinstance(shard, int) or shard not in actual_by_shard:
            raise ValueError(f"timing row {ordinal} has an invalid shard index")
        actual_by_shard[shard][identity] += 1
        strata_by_row.append(_validate_row_contract(row, config, config_id, dataset_id))
    if actual != expected:
        raise ValueError("formal timing spec/trial Cartesian product mismatch")
    for shard in range(expected_shards):
        if actual_by_shard[shard] != expected_by_shard[shard]:
            raise ValueError(
                f"formal timing shard {shard} violates the frozen modulo assignment"
            )
    ordered_rows = sorted(rows, key=lambda row: _integer(row, "measurement_order"))
    timestamps = [_parse_utc(row["timestamp_utc"], "timing row") for row in ordered_rows]
    if any(left >= right for left, right in zip(timestamps, timestamps[1:], strict=False)):
        raise ValueError("formal timing timestamps violate the frozen sequential order")
    raw_observation_set_sha256 = hashlib.sha256(
        json.dumps(
            [
                {
                    key: value
                    for key, value in row.items()
                    if not key.startswith("_")
                }
                for row in ordered_rows
            ],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()

    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row, stratum in zip(rows, strata_by_row, strict=True):
        grouped[(stratum, str(row["method"]), _canonical(row["configured_spec"]))].append(
            row
        )
    summaries: list[dict[str, Any]] = []
    for (stratum, method, configured), group in sorted(grouped.items()):
        warm = [float(row["frontend_warm_p99_us"]) for row in group]
        cold = [float(row["frontend_cold_p99_us"]) for row in group]
        throughput = [float(row["warm_query_throughput_qps_mean"]) for row in group]
        warm_mean, warm_low, warm_high = _summary_interval(warm)
        cold_mean, cold_low, cold_high = _summary_interval(cold)
        throughput_mean, throughput_low, throughput_high = _summary_interval(throughput)
        summaries.append(
            {
                "hardware_stratum": stratum,
                "method": method,
                "configured_spec": configured,
                "independent_trials": len(group),
                "frontend_warm_p99_us_mean": warm_mean,
                "frontend_warm_p99_us_ci_low": warm_low,
                "frontend_warm_p99_us_ci_high": warm_high,
                "frontend_cold_p99_us_mean": cold_mean,
                "frontend_cold_p99_us_ci_low": cold_low,
                "frontend_cold_p99_us_ci_high": cold_high,
                "warm_query_throughput_qps_mean": throughput_mean,
                "warm_query_throughput_qps_ci_low": throughput_low,
                "warm_query_throughput_qps_ci_high": throughput_high,
                "interval_method": (
                    "Student-t 95% across independent trials"
                    if len(group) > 1
                    else "not estimable from one screening trial"
                ),
            }
        )

    distinct_strata = sorted(set(strata_by_row))
    status = "PASS" if len(distinct_strata) == 1 else "BLOCKED_HETEROGENEOUS_AFFINITY"
    stage = str(config["timing_stage"])
    paired_comparisons: list[dict[str, Any]] = []
    latency_match_family: dict[str, Any] | None = None
    if stage == "candidate_confirmation" and status == "PASS":
        by_spec: dict[tuple[str, str], dict[int, dict[str, Any]]] = defaultdict(dict)
        for row in rows:
            identity = (str(row["method"]), _canonical(row["configured_spec"]))
            by_spec[identity][int(row["measurement_trial_seed"])] = row
        expected_seeds = set(int(seed) for seed in config["seeds"])
        for left_identity, right_identity in combinations(sorted(by_spec), 2):
            left = by_spec[left_identity]
            right = by_spec[right_identity]
            if set(left) != expected_seeds or set(right) != expected_seeds:
                raise ValueError("paired timing comparison lacks a frozen seed")
            metrics: dict[str, dict[str, float]] = {}
            for label, field in (
                ("warm_p99_us", "frontend_warm_p99_us"),
                ("cold_p99_us", "frontend_cold_p99_us"),
                ("warm_throughput_qps", "warm_query_throughput_qps_mean"),
            ):
                left_values = [float(left[seed][field]) for seed in sorted(expected_seeds)]
                right_values = [float(right[seed][field]) for seed in sorted(expected_seeds)]
                differences = [
                    right_value - left_value
                    for left_value, right_value in zip(
                        left_values, right_values, strict=True
                    )
                ]
                ratios = [
                    right_value / left_value
                    for left_value, right_value in zip(
                        left_values, right_values, strict=True
                    )
                ]
                difference_mean, difference_low, difference_high = _mean_ci(differences)
                ratio_mean, ratio_low, ratio_high = _mean_ci(ratios)
                metrics[label] = {
                    "right_minus_left_mean": difference_mean,
                    "right_minus_left_ci_low": difference_low,
                    "right_minus_left_ci_high": difference_high,
                    "right_over_left_mean": ratio_mean,
                    "right_over_left_ci_low": ratio_low,
                    "right_over_left_ci_high": ratio_high,
                }
            paired_comparisons.append(
                {
                    "left_method": left_identity[0],
                    "left_configured_spec": left_identity[1],
                    "right_method": right_identity[0],
                    "right_configured_spec": right_identity[1],
                    "paired_seed_count": len(expected_seeds),
                    "interval_method": "paired Student-t 95% across frozen seeds",
                    "metrics": metrics,
                }
            )
        latency_match_family = _latency_match_family(
            config, by_spec, expected_seeds
        )
    audit = {
        "status": status,
        "timing_stage": stage,
        "semantic_config_id": config_id,
        "semantic_dataset_id": dataset_id,
        "source_commit": expected_commit,
        "raw_observation_set_sha256": raw_observation_set_sha256,
        "row_count": len(rows),
        "spec_count": len(expand_timing_specs(config)),
        "trial_seed_count": len(config["seeds"]),
        "candidate_set_id": config.get("candidate_set_id"),
        "phase1_aggregate_identity": (
            phase1_aggregate["identity"] if phase1_aggregate is not None else None
        ),
        "phase1_aggregate_source_commit": (
            phase1_aggregate["source_commit"]
            if phase1_aggregate is not None
            else None
        ),
        "candidate_selection_algorithm": config.get("candidate_selection_rule"),
        "candidate_and_matched_neighbor_ledger_entry_count": len(
            config.get("confirmation_selection", {}).get(
                "candidate_and_matched_neighbors", []
            )
        ),
        "frozen_latency_relation_count": sum(
            entry.get("role") == "matched_neighbor"
            for entry in config.get("confirmation_selection", {}).get(
                "candidate_and_matched_neighbors", []
            )
            if isinstance(entry, dict)
        ),
        "expected_shards": expected_shards,
        "point_ordering": config["timing"]["point_ordering"],
        "query_window_assignment": config["timing"]["query_window_assignment"],
        "hardware_strata_count": len(distinct_strata),
        "hardware_strata": [json.loads(value) for value in distinct_strata],
        "heterogeneous_hardware_pooling": False,
        "exclusive_host_evidence": (
            "human declaration plus cooperating-runner lock; unrelated host activity "
            "is not automatically verified"
        ),
        "sample_contract": FORMAL_SAMPLE_CONTRACT,
        "paired_all_spec_comparisons": paired_comparisons,
        "latency_match_family": latency_match_family,
        "paired_comparison_multiplicity": (
            "all-spec pairwise intervals remain descriptive and unadjusted; the "
            "preregistered frozen candidate-to-neighbor family uses a one-sided "
            "Bonferroni simultaneous noninferiority bound"
        ),
        "interval_scope": (
            "Student-t intervals over seed-level empirical p99 or paired seed-level "
            "differences/ratios on one fixed hardware stratum. Only the frozen "
            "candidate-to-neighbor warm-p99 family is simultaneous; all-spec pairs, "
            "cold p99, and throughput are descriptive. This is not an SLA, service "
            "p99, or population-tail guarantee"
        ),
        "timing_evidence_status": (
            "PASS_STRICT_DESCRIPTIVE_MEASUREMENT"
            if status == "PASS"
            else "BLOCKED_HETEROGENEOUS_AFFINITY"
        ),
        "timing_claim_gate": (
            "SCREENING_ONLY_NO_CLAIM"
            if stage == "all_spec_screening"
            else (
                latency_match_family["gate"]
                if status == "PASS" and latency_match_family is not None
                else "BLOCKED_HETEROGENEOUS_AFFINITY"
            )
        ),
    }
    if stage == "all_spec_screening" and (
        audit["spec_count"] != PHASE1_SPEC_COUNT or audit["row_count"] != PHASE1_SPEC_COUNT
    ):
        raise ValueError("formal screening does not contain exactly 794 rows/specs")
    return summaries, audit


def _write_json(path: Path, value: object, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-shards", type=int, required=True)
    parser.add_argument("--summary-json", type=Path, required=True)
    parser.add_argument("--audit-json", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config, _ = load_config(args.config)
    phase1_aggregate = (
        load_phase1_selection_aggregate(config, args.config)
        if config.get("timing_stage") == "candidate_confirmation"
        and config.get("execution_enabled") is True
        else None
    )
    validate_timing_config(config, phase1_aggregate)
    rows = load_timing_shards(
        args.input_dir, args.expected_shards, str(config["timing_stage"])
    )
    summaries, audit = validate_and_summarize(
        rows, args.config, args.expected_commit, args.expected_shards
    )
    _write_json(args.summary_json, summaries, args.overwrite)
    _write_json(args.audit_json, audit, args.overwrite)
    print(json.dumps(audit, sort_keys=True))
    return 0 if audit["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
