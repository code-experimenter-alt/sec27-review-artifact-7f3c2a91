#!/usr/bin/env python3
"""Isolated warm-throughput and per-query-eviction timing for Phase 1 filters."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import statistics
import subprocess
import sys
import time
import zlib
from collections import Counter
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.analysis.filter_frontier import (  # noqa: E402
    ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED,
    ANALYTIC_MODEL_VALIDATION_STATUS,
    ANALYTIC_TAXONOMY_VERSION,
    BLOOM_FAMILY_SIZE,
    EVIDENCE_SCOPE,
    PHASE1_AGGREGATE_IDENTITY_SCHEMA,
    PHASE1_CONFIG_ID,
    PHASE1_FRONTIER_RULE,
    PHASE1_LEGACY_ATTESTATION_ID,
    PHASE1_QUALIFIED_ANALYTIC_DIAGNOSTIC_CONFIG_ID,
    PHASE1_QUALIFIED_ANALYTIC_DIAGNOSTIC_NUMERIC_CONTRACT,
    PHASE1_ROW_COUNT,
    PHASE1_SHARD_COUNT,
    SCIENTIFIC_PASS_RULE,
    SCIENTIFIC_PASS_STATUS,
    SIMULTANEOUS_RULE,
    _canonical,
    _DuplicateJsonKeyError,
    _reject_duplicate_json_keys,
    _require_exact_semantic_value,
    _UniqueKeySafeLoader,
    compute_phase1_aggregate_identity,
    normalize_phase1_selection_summary,
)
from experiments.runners.filter_bench import (  # noqa: E402
    FilterSpec,
    SyntheticCredentialSet,
    _analytic_fprs,
    _git_provenance,
    _percentile,
    build_filter,
    expand_specs,
)
from experiments.runners.filter_bench import (  # noqa: E402
    load_config as _load_filter_config,
)

TIMING_PROTOCOL = "isolated_filter_timing_v3"
TIMING_STAGES = {"pilot", "all_spec_screening", "candidate_confirmation"}
QUALIFIED_PHASE1_ANALYTIC_DIAGNOSTIC_CONFIG_ID = (
    PHASE1_QUALIFIED_ANALYTIC_DIAGNOSTIC_CONFIG_ID
)
QUALIFIED_PHASE1_ANALYTIC_DIAGNOSTIC_NUMERIC_CONTRACT = (
    PHASE1_QUALIFIED_ANALYTIC_DIAGNOSTIC_NUMERIC_CONTRACT
)
FORMAL_QUERY_WINDOW_ASSIGNMENT = "disjoint_stage_seed_windows_v1"
FORMAL_POINT_ORDERING = "sha256_base_permutation_coprime_rotation_v1"
PHASE1_ACCOUNT_COUNT = 100_000
PHASE1_NONMEMBER_COUNT = 10_000_000
PHASE1_DATASET_SEED = 20260805
PHASE1_DATASET_ID = "0e0299a7367c6a115e077440e7a04936712b654a1e0a836785d3e6862ac34a4a"
PHASE1_SPEC_COUNT = 794
SCREENING_SEED = 641051
CONFIRMATION_SEEDS = (
    104729,
    130363,
    155921,
    181081,
    205759,
    230411,
    255053,
    279709,
    304349,
    329041,
    353869,
    378599,
    403339,
    428083,
    452827,
    477571,
    502321,
    527053,
    551797,
    576533,
)
FORMAL_SAMPLE_CONTRACT = {
    "query_pool_count": 100_000,
    "warmup_query_count": 100_000,
    "warm_throughput_query_count": 1_000_000,
    "warm_throughput_repetitions": 5,
    "warm_latency_query_count": 100_000,
    "cold_latency_query_count": 2_000,
    "cold_eviction_bytes": 150_994_944,
    "cold_eviction_minimum_llc_multiple": 4,
}
FORMAL_QUERY_WINDOW_STRIDE = (
    FORMAL_SAMPLE_CONTRACT["query_pool_count"]
    + FORMAL_SAMPLE_CONTRACT["warm_latency_query_count"]
    + FORMAL_SAMPLE_CONTRACT["cold_latency_query_count"]
)
SCREENING_SHARD_COUNT = PHASE1_SPEC_COUNT
CONFIRMATION_SHARD_COUNT = 24 * len(CONFIRMATION_SEEDS)
PILOT_CONFIG_ID = "43fc8d04f2712ac217b6422df851be005ea9568ac96480b110835fcdfd8f4e43"
SCREENING_CONFIG_ID = "7051c21eaff6936efb6060a9f3c15405b1ea34dc46398ad8a4b88389dcbacc44"
CONFIRMATION_CONFIG_ID = "cdddd91c24b008b37d5c833b127f08d94c8d20546b5f1673a38617a18b4037f9"
CONFIRMATION_CANDIDATE_SET_ID = (
    "e23c6e8625cf41e19eee9abff349ac3b62af28a30208631b095c1f30115eae43"
)
CONFIRMATION_TEMPLATE_CONFIG_ID = (
    "4b630aea16734eaf96a9442cf57c1be32645f89ca7851af8947b85ec4a9a3dd8"
)
CANDIDATE_SELECTION_RULE = "phase1_profile_memory_budget_ci_high_v1"
CONFIRMATION_SELECTION_SCHEMA_VERSION = 2
LATENCY_MATCH_SCHEMA_VERSION = 1
LATENCY_MATCH_PRIMARY_METRIC = "frontend_warm_p99_us"
LATENCY_MATCH_PAIRED_UNIT = "measurement_trial_seed"
LATENCY_MATCH_ESTIMAND = (
    "geometric_mean_paired_seed_candidate_over_neighbor_warm_p99_ratio"
)
LATENCY_MATCH_MARGIN = 1.05
LATENCY_MATCH_FAMILYWISE_ALPHA = 0.05
LATENCY_MATCH_ADJUSTMENT = (
    "bonferroni_one_sided_student_t_log_ratio_v1"
)
LATENCY_MATCH_FAMILY = "all_frozen_candidate_matched_neighbor_relations"
LATENCY_MATCH_DECISION_RULE = (
    "all_adjusted_upper_ratio_bounds_lte_margin"
)
LATENCY_MATCH_SCOPE = "PHASE1_FILTER_QUERY_ONLY_NOT_SERVICE_P99_OR_SLA"
SELECTION_PROFILES = ("U", "A")
SELECTION_MEMORY_BUDGET_BITS_PER_ACCOUNT = (4, 8, 12, 16, 24, 32, 48, 64, 128)
SELECTION_FIXED_MEMORY_OVERHEAD_BYTES = 256
SELECTION_OBJECTIVE = (
    "minimize primary first-seen FFR 95% CI high, then total edge bytes, "
    "then method/spec identity"
)
SELECTION_NEIGHBOR_RULE = (
    "same profile and memory budget; adjacent tag_bits for tags, k_hashes at fixed "
    "Bloom method/bits_per_account, or fingerprint_bits at fixed Xor/Cuckoo method"
)


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    """Load timing YAML without allowing duplicate keys or numeric aliases."""

    try:
        with path.open("r", encoding="utf-8") as handle:
            strict_config = yaml.load(handle, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as error:
        raise ValueError(
            "timing config is malformed or contains duplicate mapping keys"
        ) from error
    if not isinstance(strict_config, dict):
        raise ValueError("top-level YAML value must be a mapping")
    schema_version = strict_config.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise ValueError("timing config schema_version must be integer 1")
    selection = strict_config.get("confirmation_selection")
    if selection is not None:
        if not isinstance(selection, dict):
            raise ValueError("confirmation_selection must be a mapping")
        selection_schema = selection.get("schema_version")
        if (
            type(selection_schema) is not int
            or selection_schema != CONFIRMATION_SELECTION_SCHEMA_VERSION
        ):
            raise ValueError("confirmation selection schema version must be integer 2")
        _latency_match_contract(selection)

    config, config_id = _load_filter_config(path)
    try:
        _require_exact_semantic_value(
            config, strict_config, "timing config strict-loader agreement"
        )
    except ValueError as error:
        raise ValueError("timing config strict-loader agreement failed") from error
    return strict_config, config_id


class HostTimingLock(AbstractContextManager["HostTimingLock"]):
    """Fail closed if another formal timing process is active on this host."""

    def __init__(self, required: bool) -> None:
        self.required = required
        self._handle = None

    def __enter__(self) -> "HostTimingLock":
        if not self.required:
            return self
        try:
            import fcntl
        except ImportError as error:
            raise RuntimeError("formal timing requires POSIX fcntl host locking") from error
        path = Path(os.environ.get("TRAPS_TIMING_LOCK", "/tmp/traps-filter-timing.lock"))
        self._handle = path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self._handle.close()
            self._handle = None
            raise RuntimeError("another filter timing process is active on this host") from error
        return self

    def __exit__(self, *args: object) -> None:
        if self._handle is not None:
            import fcntl

            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
            self._handle = None


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _cpuinfo_by_processor() -> dict[int, dict[str, str]]:
    cpuinfo = _read_text(Path("/proc/cpuinfo"))
    if not cpuinfo:
        return {}
    records: dict[int, dict[str, str]] = {}
    for block in cpuinfo.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip().lower()] = value.strip()
        processor = fields.get("processor")
        if processor is not None and processor.isdigit():
            records[int(processor)] = fields
    return records


def _parse_lscpu_model_names(payload: str) -> dict[int, str]:
    parsed = json.loads(payload, object_pairs_hook=_reject_duplicate_json_keys)
    if not isinstance(parsed, dict) or set(parsed) != {"cpus"}:
        raise ValueError("lscpu JSON must contain only the cpus array")
    rows = parsed["cpus"]
    if not isinstance(rows, list):
        raise ValueError("lscpu cpus must be an array")
    models: dict[int, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"cpu", "modelname"}:
            raise ValueError("lscpu CPU row has the wrong schema")
        cpu = row["cpu"]
        model = row["modelname"]
        if (
            isinstance(cpu, bool)
            or not isinstance(cpu, int)
            or cpu < 0
            or not isinstance(model, str)
            or not model.strip()
            or cpu in models
        ):
            raise ValueError("lscpu CPU row is invalid or duplicated")
        models[cpu] = model.strip()
    return models


def _lscpu_model_names() -> dict[int, str]:
    environment = dict(os.environ)
    environment.update({"LANG": "C", "LC_ALL": "C"})
    try:
        completed = subprocess.run(
            ["lscpu", "--json", "--extended=CPU,MODELNAME"],
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="strict",
            env=environment,
            timeout=5,
        )
        if completed.returncode != 0:
            return {}
        return _parse_lscpu_model_names(completed.stdout)
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return {}


_CACHE_SIZE_PATTERN = re.compile(r"^(\d+)([KMG])?$")


def _parse_cache_size_bytes(value: str) -> int:
    match = _CACHE_SIZE_PATTERN.fullmatch(value.strip().upper())
    if match is None:
        raise ValueError(f"invalid sysfs cache size {value!r}")
    amount = int(match.group(1))
    multiplier = {None: 1, "K": 1024, "M": 1024**2, "G": 1024**3}[
        match.group(2)
    ]
    return amount * multiplier


def _read_cache_index(index: Path) -> dict[str, Any]:
    level = _read_text(index / "level")
    cache_type = _read_text(index / "type")
    size = _read_text(index / "size")
    shared = _read_text(index / "shared_cpu_list")
    if (
        level is None
        or not level.isdigit()
        or cache_type not in {"Data", "Instruction", "Unified"}
        or size is None
        or shared is None
    ):
        raise RuntimeError(f"sysfs cache index {index} is incomplete or invalid")
    try:
        size_bytes = _parse_cache_size_bytes(size)
    except ValueError as error:
        raise RuntimeError(f"sysfs cache index {index} has an invalid size") from error
    return {
        "index": index.name,
        "level": int(level),
        "type": cache_type,
        "size_bytes": size_bytes,
        "shared_cpu_list": shared,
    }


def _cpu_cache_records(cpu: int) -> list[dict[str, Any]]:
    root = Path(f"/sys/devices/system/cpu/cpu{cpu}/cache")
    indexes = sorted(root.glob("index*"), key=lambda path: path.name)
    return [_read_cache_index(index) for index in indexes]


def _last_level_data_cache(cache_records: list[dict[str, Any]]) -> tuple[int | None, int | None]:
    candidates = [
        record
        for record in cache_records
        if record.get("type") in {"Data", "Unified"}
        and type(record.get("level")) is int
        and type(record.get("size_bytes")) is int
        and int(record["size_bytes"]) > 0
    ]
    if not candidates:
        return None, None
    level = max(int(record["level"]) for record in candidates)
    size = max(
        int(record["size_bytes"])
        for record in candidates
        if int(record["level"]) == level
    )
    return level, size


def _affinity() -> list[int]:
    getter = getattr(os, "sched_getaffinity", None)
    if getter is None:
        return []
    return sorted(int(cpu) for cpu in getter(0))


def _affinity_cpu_records(cpus: list[int]) -> list[dict[str, Any]]:
    cpuinfo = _cpuinfo_by_processor()
    lscpu_models = _lscpu_model_names()
    records: list[dict[str, Any]] = []
    for cpu in cpus:
        fields = cpuinfo.get(cpu, {})
        cpuinfo_model = fields.get("model name") or fields.get("model")
        model_name = cpuinfo_model or lscpu_models.get(cpu) or "unknown"
        model_source = (
            "/proc/cpuinfo"
            if cpuinfo_model
            else (
                "LC_ALL=C lscpu --json --extended=CPU,MODELNAME"
                if cpu in lscpu_models
                else "unavailable"
            )
        )
        frequency_root = Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq")
        cache_records = _cpu_cache_records(cpu)
        llc_level, llc_bytes = _last_level_data_cache(cache_records)
        records.append(
            {
                "logical_cpu": cpu,
                "model_name": model_name,
                "model_name_source": model_source,
                "vendor_id": fields.get("vendor_id") or fields.get("cpu implementer"),
                "physical_id": fields.get("physical id"),
                "core_id": fields.get("core id"),
                "cpu_part": fields.get("cpu part"),
                "scaling_driver": _read_text(frequency_root / "scaling_driver"),
                "scaling_governor": _read_text(frequency_root / "scaling_governor"),
                "scaling_min_freq_khz": _read_text(frequency_root / "scaling_min_freq"),
                "scaling_max_freq_khz": _read_text(frequency_root / "scaling_max_freq"),
                "cache_enumeration_status": (
                    "COMPLETE" if cache_records else "UNAVAILABLE"
                ),
                "cache_records": cache_records,
                "last_level_cache_level": llc_level,
                "last_level_cache_bytes": llc_bytes,
            }
        )
    return records


def host_environment(declared_concurrency: int) -> dict[str, Any]:
    affinity = _affinity()
    affinity_records = _affinity_cpu_records(affinity)
    unique_affinity = len(affinity_records) == 1
    try:
        load_average = list(os.getloadavg())
    except (AttributeError, OSError):
        load_average = None
    return {
        "host_platform": platform.platform(),
        "hostname": platform.node(),
        "python_version": platform.python_version(),
        "cpu_model": (
            affinity_records[0]["model_name"]
            if unique_affinity
            else "not uniquely determined from affinity"
        ),
        "cpu_model_source": (
            "unique affinity_cpu_records[0].model_name"
            if unique_affinity
            else "not uniquely determined: affinity_cpu_count != 1"
        ),
        "logical_cpu_count": os.cpu_count(),
        "affinity_cpus": affinity,
        "affinity_cpu_count": len(affinity),
        "affinity_cpu_records": affinity_records,
        "scaling_governor_by_affinity_cpu": {
            str(record["logical_cpu"]): record["scaling_governor"]
            for record in affinity_records
        },
        "declared_benchmark_process_concurrency": declared_concurrency,
        "exclusive_host_human_declared": os.environ.get("TRAPS_EXCLUSIVE_HOST") == "1",
        "exclusive_host_automatically_verified": False,
        "load_average_1m_5m_15m": load_average,
        "host_lock_path": os.environ.get(
            "TRAPS_TIMING_LOCK", "/tmp/traps-filter-timing.lock"
        ),
        "host_lock_required_for_formal": True,
        "host_lock_scope": "cooperating TRAPS timing processes only",
        "same_runner_host_lock_acquired": False,
    }


def _require_formal_host_environment(environment: dict[str, Any]) -> None:
    affinity = environment["affinity_cpus"]
    records = environment["affinity_cpu_records"]
    if len(affinity) != 1 or len(records) != 1:
        raise RuntimeError("formal timing requires exactly one affinity CPU")
    record = records[0]
    if (
        environment["cpu_model_source"]
        != "unique affinity_cpu_records[0].model_name"
        or environment["cpu_model"] != record["model_name"]
        or record["model_name"] == "unknown"
        or record.get("model_name_source") == "unavailable"
    ):
        raise RuntimeError("formal timing requires an affinity-specific CPU model")
    cache_records = record.get("cache_records")
    derived_llc_level, derived_llc_bytes = _last_level_data_cache(
        cache_records if isinstance(cache_records, list) else []
    )
    if (
        type(record.get("last_level_cache_level")) is not int
        or type(record.get("last_level_cache_bytes")) is not int
        or int(record["last_level_cache_bytes"]) <= 0
        or not isinstance(cache_records, list)
        or record.get("cache_enumeration_status") != "COMPLETE"
        or record["last_level_cache_level"] != derived_llc_level
        or record["last_level_cache_bytes"] != derived_llc_bytes
    ):
        raise RuntimeError("formal timing requires an affinity-specific cache hierarchy")
    if (
        not str(record.get("scaling_governor", "")).strip()
        or environment["scaling_governor_by_affinity_cpu"]
        != {str(affinity[0]): record["scaling_governor"]}
    ):
        raise RuntimeError("formal timing requires an affinity-specific CPU governor")
    if environment["exclusive_host_human_declared"] is not True:
        raise RuntimeError("formal timing requires TRAPS_EXCLUSIVE_HOST=1")


def _require_cold_eviction_capacity(
    config: dict[str, Any], environment: dict[str, Any]
) -> None:
    record = environment["affinity_cpu_records"][0]
    llc_bytes = int(record["last_level_cache_bytes"])
    timing = config["timing"]
    eviction_bytes = int(timing["cold_eviction_bytes"])
    minimum_multiple = int(timing["cold_eviction_minimum_llc_multiple"])
    if eviction_bytes < minimum_multiple * llc_bytes:
        raise RuntimeError(
            "formal cold-cache displacement buffer is smaller than the frozen "
            "multiple of the affinity CPU last-level cache"
        )


def expand_timing_specs(config: dict[str, Any]) -> list[FilterSpec]:
    selected = config.get("selected_specs")
    if selected is None:
        return expand_specs(config)
    if not isinstance(selected, list):
        raise ValueError("selected_specs must be a list")
    specs: list[FilterSpec] = []
    for ordinal, value in enumerate(selected):
        if not isinstance(value, dict) or set(value) != {"family", "parameters"}:
            raise ValueError(f"selected_specs[{ordinal}] has the wrong schema")
        family = str(value["family"])
        parameters = value["parameters"]
        if not isinstance(parameters, dict):
            raise ValueError(f"selected_specs[{ordinal}].parameters must be a mapping")
        specs.append(FilterSpec(family, parameters))
    identities = [spec.identity for spec in specs]
    if len(identities) != len(set(identities)):
        raise ValueError("selected_specs contains duplicates")
    universe = {spec.identity for spec in expand_specs(config)}
    unexpected = sorted(set(identities) - universe)
    if unexpected:
        raise ValueError("selected_specs contains a point outside the frozen universe")
    return specs


def ordered_timing_points(config: dict[str, Any]) -> list[tuple[int, FilterSpec]]:
    specs = expand_timing_specs(config)
    seeds = [int(seed) for seed in config["seeds"]]
    if not bool(config.get("formal_timing", False)):
        return [(seed, spec) for seed in seeds for spec in specs]
    anchor = str(config.get("candidate_set_id") or config["scenario"])
    base = sorted(
        specs,
        key=lambda spec: hashlib.sha256(
            f"{FORMAL_POINT_ORDERING}:{anchor}:{spec.identity}".encode()
        ).digest(),
    )
    if config["timing_stage"] == "all_spec_screening":
        return [(seeds[0], spec) for spec in base]
    if (
        config["timing_stage"] != "candidate_confirmation"
        or len(base) < 2
        or math.gcd(5, len(base)) != 1
    ):
        raise ValueError(
            "formal confirmation point ordering requires at least two specs and "
            "a spec count coprime with the frozen rotation"
        )
    points: list[tuple[int, FilterSpec]] = []
    for seed_ordinal, seed in enumerate(seeds):
        shift = (seed_ordinal * 5) % len(base)
        rotated = base[shift:] + base[:shift]
        points.extend((seed, spec) for spec in rotated)
    return points


def query_window_assignment(
    config: dict[str, Any], trial_seed: int
) -> tuple[int, int]:
    if not bool(config.get("formal_timing", False)):
        needed = (
            int(config["timing"]["query_pool_count"])
            + int(config["timing"]["warm_latency_query_count"])
            + int(config["timing"]["cold_latency_query_count"])
        )
        max_start = int(config["dataset"]["nonmember_count"]) - needed
        return -1, (trial_seed * 0x9E3779B1) % (max_start + 1)
    if config["timing_stage"] == "all_spec_screening":
        if trial_seed != SCREENING_SEED:
            raise ValueError("screening query-window seed mismatch")
        ordinal = 0
    elif config["timing_stage"] == "candidate_confirmation":
        try:
            ordinal = 1 + CONFIRMATION_SEEDS.index(trial_seed)
        except ValueError as error:
            raise ValueError("confirmation query-window seed mismatch") from error
    else:
        raise ValueError("formal query-window assignment requires a staged design")
    start = ordinal * FORMAL_QUERY_WINDOW_STRIDE
    end = start + FORMAL_QUERY_WINDOW_STRIDE
    if end > int(config["dataset"]["nonmember_count"]):
        raise ValueError("formal disjoint query windows exceed the dataset")
    return ordinal, start


def _confirmation_selection(config: dict[str, Any]) -> dict[str, Any]:
    selection = config.get("confirmation_selection")
    if not isinstance(selection, dict):
        raise ValueError("confirmation_selection must be a mapping")
    required = {
        "schema_version",
        "algorithm",
        "aggregate_summary_path",
        "aggregate_audit_path",
        "expected_phase1_aggregate_identity",
        "expected_phase1_source_commit",
        "profiles",
        "memory_budget_bits_per_account",
        "fixed_memory_overhead_bytes",
        "objective",
        "neighbor_rule",
        "latency_match_contract",
        "candidate_and_matched_neighbors",
    }
    if set(selection) != required:
        raise ValueError(
            "confirmation_selection schema mismatch: "
            f"expected {sorted(required)}, found {sorted(selection)}"
        )
    schema_version = selection["schema_version"]
    if (
        type(schema_version) is not int
        or schema_version != CONFIRMATION_SELECTION_SCHEMA_VERSION
    ):
        raise ValueError("confirmation selection schema version mismatch")
    algorithm = selection["algorithm"]
    if type(algorithm) is not str or algorithm != CANDIDATE_SELECTION_RULE:
        raise ValueError("confirmation candidate-selection algorithm mismatch")
    profiles = selection["profiles"]
    if (
        type(profiles) is not list
        or any(type(profile) is not str for profile in profiles)
        or tuple(profiles) != SELECTION_PROFILES
    ):
        raise ValueError("confirmation selection profiles mismatch")
    budgets = selection["memory_budget_bits_per_account"]
    if (
        type(budgets) is not list
        or any(type(value) is not int for value in budgets)
        or tuple(budgets) != SELECTION_MEMORY_BUDGET_BITS_PER_ACCOUNT
    ):
        raise ValueError("confirmation memory budgets mismatch")
    fixed_overhead = selection["fixed_memory_overhead_bytes"]
    if (
        type(fixed_overhead) is not int
        or fixed_overhead != SELECTION_FIXED_MEMORY_OVERHEAD_BYTES
    ):
        raise ValueError("confirmation fixed memory overhead mismatch")
    objective = selection["objective"]
    if type(objective) is not str or objective != SELECTION_OBJECTIVE:
        raise ValueError("confirmation selection objective mismatch")
    neighbor_rule = selection["neighbor_rule"]
    if type(neighbor_rule) is not str or neighbor_rule != SELECTION_NEIGHBOR_RULE:
        raise ValueError("confirmation matched-neighbor rule mismatch")
    _latency_match_contract(selection)
    entries = selection["candidate_and_matched_neighbors"]
    if not isinstance(entries, list):
        raise ValueError("candidate_and_matched_neighbors must be a list")
    for path_field in ("aggregate_summary_path", "aggregate_audit_path"):
        if type(selection[path_field]) is not str or not selection[path_field]:
            raise ValueError(f"confirmation_selection.{path_field} must be a path")
    return selection


def _latency_match_contract(selection: dict[str, Any]) -> dict[str, Any]:
    contract = selection.get("latency_match_contract")
    if not isinstance(contract, dict):
        raise ValueError("latency_match_contract must be a mapping")
    required = {
        "schema_version",
        "primary_metric",
        "paired_unit",
        "estimand",
        "candidate_role",
        "reference_role",
        "noninferiority_ratio_margin",
        "familywise_alpha",
        "multiplicity_adjustment",
        "multiplicity_family",
        "required_seed_count",
        "decision_rule",
        "cold_p99_role",
        "throughput_role",
        "scope",
    }
    if set(contract) != required:
        raise ValueError(
            "latency_match_contract schema mismatch: "
            f"expected {sorted(required)}, found {sorted(contract)}"
        )
    exact_values = {
        "schema_version": LATENCY_MATCH_SCHEMA_VERSION,
        "primary_metric": LATENCY_MATCH_PRIMARY_METRIC,
        "paired_unit": LATENCY_MATCH_PAIRED_UNIT,
        "estimand": LATENCY_MATCH_ESTIMAND,
        "candidate_role": "budget_candidate",
        "reference_role": "matched_neighbor",
        "multiplicity_adjustment": LATENCY_MATCH_ADJUSTMENT,
        "multiplicity_family": LATENCY_MATCH_FAMILY,
        "required_seed_count": len(CONFIRMATION_SEEDS),
        "decision_rule": LATENCY_MATCH_DECISION_RULE,
        "cold_p99_role": "DESCRIPTIVE_ONLY",
        "throughput_role": "DESCRIPTIVE_ONLY",
        "scope": LATENCY_MATCH_SCOPE,
    }
    for field, expected in exact_values.items():
        value = contract[field]
        if type(value) is not type(expected) or value != expected:
            raise ValueError(f"latency match {field} mismatch")
    numeric_values = {
        "noninferiority_ratio_margin": LATENCY_MATCH_MARGIN,
        "familywise_alpha": LATENCY_MATCH_FAMILYWISE_ALPHA,
    }
    for field, expected in numeric_values.items():
        value = contract[field]
        if type(value) is not float or value != expected:
            raise ValueError(f"latency match {field} mismatch")
    return contract


def _resolve_evidence_path(value: str, config_path: Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    repository_path = ROOT / path
    if repository_path.exists():
        return repository_path
    return config_path.resolve().parent / path


class _NonFiniteJsonNumberError(ValueError):
    pass


def _parse_finite_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise _NonFiniteJsonNumberError(f"non-finite JSON number {value}")
    return parsed


def _require_phase1_audit_value(
    audit: dict[str, Any], field: str, expected: object
) -> None:
    try:
        _require_exact_semantic_value(
            audit.get(field), expected, f"qualified Phase 1 aggregate audit {field}"
        )
    except ValueError as error:
        raise ValueError(
            f"qualified Phase 1 aggregate audit has invalid {field}"
        ) from error


def load_phase1_selection_aggregate(
    config: dict[str, Any], config_path: Path
) -> dict[str, Any]:
    """Load and independently qualify the exact aggregate used for selection."""

    selection = _confirmation_selection(config)
    expected_identity = selection["expected_phase1_aggregate_identity"]
    expected_commit = selection["expected_phase1_source_commit"]
    if not isinstance(expected_identity, str) or not re.fullmatch(
        r"[0-9a-f]{64}", expected_identity
    ):
        raise ValueError("enabled confirmation requires a frozen aggregate identity")
    if not isinstance(expected_commit, str) or not re.fullmatch(
        r"[0-9a-f]{40}", expected_commit
    ):
        raise ValueError("enabled confirmation requires a Phase 1 source commit")
    summary_path = _resolve_evidence_path(
        selection["aggregate_summary_path"], config_path
    )
    audit_path = _resolve_evidence_path(selection["aggregate_audit_path"], config_path)
    try:
        with audit_path.open("r", encoding="utf-8") as handle:
            audit = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_float=_parse_finite_json_float,
                parse_constant=_parse_finite_json_float,
            )
    except _DuplicateJsonKeyError as error:
        raise ValueError(
            "qualified Phase 1 aggregate audit contains duplicate JSON keys"
        ) from error
    except _NonFiniteJsonNumberError as error:
        raise ValueError(
            "qualified Phase 1 aggregate audit contains a non-finite JSON number"
        ) from error
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("qualified Phase 1 aggregate audit is unavailable") from error
    if not isinstance(audit, dict):
        raise ValueError("Phase 1 aggregate audit must be a mapping")
    if "e1_bloom_analytic_gate" in audit:
        raise ValueError(
            "qualified Phase 1 aggregate audit contains removed "
            "e1_bloom_analytic_gate"
        )
    required_qualification = {
        "status": "PASS",
        "phase1_cartesian_grid_status": "PASS",
        "phase1_evidence_status": "PASS",
        "phase1_p0b_qualification_status": (
            "PASS_EMPIRICAL_QUERY_PATH_REPRODUCIBILITY"
        ),
        "e1_bloom_query_path_reproduction_gate": "PASS",
        "e1_bloom_analytic_model_validation_status": (
            ANALYTIC_MODEL_VALIDATION_STATUS
        ),
        "analytic_model_validation_status": ANALYTIC_MODEL_VALIDATION_STATUS,
        "analytic_model_agreement_claim_permitted": (
            ANALYTIC_MODEL_AGREEMENT_CLAIM_PERMITTED
        ),
        "analytic_diagnostic_overlay_status": "PASS_COMPLETE_7680",
        "analytic_diagnostic_integrity_status": "PASS",
        "query_path_reproduction_status": SCIENTIFIC_PASS_STATUS,
        "query_path_reproduction_evidence_scope": EVIDENCE_SCOPE,
        "query_path_reproduction_scientific_pass_rule": SCIENTIFIC_PASS_RULE,
        "analytic_diagnostic_config_id": QUALIFIED_PHASE1_ANALYTIC_DIAGNOSTIC_CONFIG_ID,
        "analytic_diagnostic_family_size": BLOOM_FAMILY_SIZE,
        "analytic_diagnostic_fwer_consistent_rows": BLOOM_FAMILY_SIZE,
        "analytic_diagnostic_fwer_inconsistent_rows": 0,
        "analytic_diagnostic_robust_overlap_rows": BLOOM_FAMILY_SIZE,
        "analytic_diagnostic_robust_separation_rows": 0,
        "analytic_diagnostic_ambiguous_numeric_rows": 0,
        "analytic_diagnostic_numeric_contract": (
            QUALIFIED_PHASE1_ANALYTIC_DIAGNOSTIC_NUMERIC_CONTRACT
        ),
        "analytic_diagnostic_consistency_rule": SIMULTANEOUS_RULE,
        "e1_bloom_analytic_unresolved_rows": 0,
        "semantic_config_id": PHASE1_CONFIG_ID,
        "semantic_dataset_id": PHASE1_DATASET_ID,
        "phase1_aggregate_identity_schema": PHASE1_AGGREGATE_IDENTITY_SCHEMA,
        "analytic_discrepancy_taxonomy_version": ANALYTIC_TAXONOMY_VERSION,
        "frontier_rule": PHASE1_FRONTIER_RULE,
    }
    for field, expected in required_qualification.items():
        _require_phase1_audit_value(audit, field, expected)
    if (
        audit.get("commit") != expected_commit
        or audit.get("source_clean_provenance")
        not in {"row-recorded-clean", "legacy-external-clean-attestation"}
        or not isinstance(audit.get("machine_verified_discrepancies_by_code"), dict)
    ):
        raise ValueError("qualified Phase 1 aggregate audit contract mismatch")
    for field, expected in {
        "row_count": PHASE1_ROW_COUNT,
        "shard_count": PHASE1_SHARD_COUNT,
        "summary_point_count": PHASE1_SPEC_COUNT,
    }.items():
        _require_phase1_audit_value(audit, field, expected)
    diagnostic_commit = audit.get("analytic_diagnostic_source_commit")
    if not isinstance(diagnostic_commit, str) or not re.fullmatch(
        r"[0-9a-f]{40}", diagnostic_commit
    ):
        raise ValueError(
            "qualified Phase 1 aggregate audit has invalid "
            "analytic_diagnostic_source_commit"
        )
    provenance = audit["source_clean_provenance"]
    attestation_id = audit.get("clean_source_attestation_id")
    if (provenance == "row-recorded-clean" and attestation_id is not None) or (
        provenance == "legacy-external-clean-attestation"
        and attestation_id != PHASE1_LEGACY_ATTESTATION_ID
    ):
        raise ValueError("qualified Phase 1 aggregate clean provenance mismatch")
    bias_counts = audit.get("analytic_diagnostic_bias_direction_counts")
    if not isinstance(bias_counts, dict) or set(bias_counts) != {
        "exact_higher",
        "exact_lower",
        "equal",
    }:
        raise ValueError(
            "qualified Phase 1 aggregate diagnostic bias counts are invalid"
        )
    if any(
        isinstance(count, bool) or not isinstance(count, int) or count < 0
        for count in bias_counts.values()
    ) or sum(bias_counts.values()) != BLOOM_FAMILY_SIZE:
        raise ValueError(
            "qualified Phase 1 aggregate diagnostic bias counts are invalid"
        )
    discrepancy_counts = audit["machine_verified_discrepancies_by_code"]
    if any(
        not isinstance(code, str)
        or not code
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        for code, count in discrepancy_counts.items()
    ):
        raise ValueError(
            "qualified Phase 1 aggregate discrepancy counts are invalid"
        )
    legacy_uncovered = audit.get("legacy_ideal_model_uncovered_rows")
    if (
        isinstance(legacy_uncovered, bool)
        or not isinstance(legacy_uncovered, int)
        or legacy_uncovered < 0
    ):
        raise ValueError(
            "qualified Phase 1 aggregate legacy ideal-model count is invalid"
        )
    try:
        with summary_path.open("r", encoding="utf-8", newline="") as handle:
            summary_rows = list(csv.DictReader(handle))
    except (OSError, csv.Error) as error:
        raise ValueError("qualified Phase 1 aggregate summary is unavailable") from error
    normalized = [normalize_phase1_selection_summary(row) for row in summary_rows]
    expected_points = {
        (_method_for_spec(spec.family, spec.parameters), _canonical(spec.parameters))
        for spec in expand_specs(config)
    }
    actual_points = {
        (row["method"], _canonical(row["configured_spec"])) for row in normalized
    }
    if (
        len(normalized) != PHASE1_SPEC_COUNT
        or len(actual_points) != PHASE1_SPEC_COUNT
        or actual_points != expected_points
    ):
        raise ValueError("qualified Phase 1 aggregate does not contain the exact grid")
    for row in normalized:
        is_tag = row["method"] == "exact_tag_128" or row["method"].startswith(
            "truncated_tag_"
        )
        expected_constructions = 1 if is_tag else 10
        if row["independent_constructions"] != expected_constructions:
            raise ValueError("qualified Phase 1 aggregate construction count mismatch")
        if row["eligible_profile_U_all_seeds"] is not True:
            raise ValueError("qualified Phase 1 aggregate profile U eligibility mismatch")
        if row["eligible_profile_A_all_seeds"] != (not is_tag):
            raise ValueError("qualified Phase 1 aggregate profile A eligibility mismatch")
    for profile in SELECTION_PROFILES:
        pareto_field = f"pareto_{profile}_memory_ffr"
        recomputed = _recomputed_pareto_identities(normalized, profile)
        for row in normalized:
            identity = (row["method"], _canonical(row["configured_spec"]))
            if row[pareto_field] != (identity in recomputed):
                raise ValueError(
                    f"qualified Phase 1 aggregate profile {profile} Pareto mismatch"
                )
    if not any(row["pareto_U_memory_ffr"] for row in normalized) or not any(
        row["pareto_A_memory_ffr"] for row in normalized
    ):
        raise ValueError("qualified Phase 1 aggregate has an empty profile frontier")
    recomputed_identity = compute_phase1_aggregate_identity(normalized, audit)
    if (
        audit.get("phase1_aggregate_identity") != recomputed_identity
        or expected_identity != recomputed_identity
    ):
        raise ValueError("qualified Phase 1 aggregate semantic identity mismatch")
    return {
        "audit": audit,
        "summaries": normalized,
        "identity": recomputed_identity,
        "source_commit": expected_commit,
    }


def _family_from_method(method: str) -> str:
    if method == "exact_tag_128" or method.startswith("truncated_tag_"):
        return "tag"
    return {
        "global_bloom": "global_bloom",
        "blocked_bloom_64b": "blocked_bloom",
        "xor_static_3way": "xor_static",
        "cuckoo_filter": "cuckoo",
    }[method]


def _neighbor_axis(row: dict[str, Any]) -> tuple[tuple[object, ...], int]:
    method = row["method"]
    configured = row["configured_spec"]
    if method == "exact_tag_128" or method.startswith("truncated_tag_"):
        return ("tag",), int(configured["tag_bits"])
    if method in {"global_bloom", "blocked_bloom_64b"}:
        return (method, int(configured["bits_per_account"])), int(
            configured["k_hashes"]
        )
    return (method,), int(configured["fingerprint_bits"])


def _recomputed_pareto_identities(
    summaries: list[dict[str, Any]], profile: str
) -> set[tuple[str, str]]:
    eligible_field = f"eligible_profile_{profile}_all_seeds"
    eligible = [row for row in summaries if row[eligible_field]]
    result: set[tuple[str, str]] = set()
    for candidate in eligible:
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
            for other in eligible
        )
        if not dominated:
            result.add((candidate["method"], _canonical(candidate["configured_spec"])))
    return result


def _selection_entry(
    row: dict[str, Any],
    *,
    role: str,
    profile: str,
    budget_bits: int,
    budget_bytes: int,
    selection_key: str,
    direction: str | None = None,
    anchor_spec_id: str | None = None,
) -> dict[str, Any]:
    spec_material = {
        "method": row["method"],
        "configured_spec": row["configured_spec"],
    }
    spec_id = hashlib.sha256(_canonical(spec_material).encode()).hexdigest()
    entry = {
        "selection_key": selection_key,
        "role": role,
        "profile": profile,
        "memory_budget_bits_per_account": budget_bits,
        "memory_budget_total_edge_bytes": budget_bytes,
        "method": row["method"],
        "family": _family_from_method(row["method"]),
        "parameters": row["configured_spec"],
        "spec_id": spec_id,
        "phase1_first_seen_ffr_ci_high": row["first_seen_ffr_ci_high"],
        "phase1_memory_total_edge_bytes_mean": row[
            "memory_total_edge_bytes_mean"
        ],
    }
    if direction is not None:
        entry["neighbor_direction"] = direction
        entry["anchor_candidate_spec_id"] = anchor_spec_id
    return entry


def derive_confirmation_selection(
    summaries: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Derive the complete candidate/neighbor ledger and unique timed specs."""

    normalized = [normalize_phase1_selection_summary(row) for row in summaries]
    entries: list[dict[str, Any]] = []
    for profile in SELECTION_PROFILES:
        eligible_field = f"eligible_profile_{profile}_all_seeds"
        pareto_identities = _recomputed_pareto_identities(normalized, profile)
        for budget_bits in SELECTION_MEMORY_BUDGET_BITS_PER_ACCOUNT:
            budget_bytes = (
                math.ceil(PHASE1_ACCOUNT_COUNT * budget_bits / 8)
                + SELECTION_FIXED_MEMORY_OVERHEAD_BYTES
            )
            candidates = [
                row
                for row in normalized
                if row[eligible_field]
                and (row["method"], _canonical(row["configured_spec"]))
                in pareto_identities
                and row["memory_total_edge_bytes_mean"] <= budget_bytes
            ]
            if not candidates:
                raise ValueError(
                    f"qualified Phase 1 aggregate has no {profile} candidate "
                    f"within {budget_bits} bits/account"
                )
            candidate = min(
                candidates,
                key=lambda row: (
                    row["first_seen_ffr_ci_high"],
                    row["memory_total_edge_bytes_mean"],
                    row["method"],
                    _canonical(row["configured_spec"]),
                ),
            )
            selection_key = f"profile-{profile}-memory-{budget_bits}-bpa"
            candidate_entry = _selection_entry(
                candidate,
                role="budget_candidate",
                profile=profile,
                budget_bits=budget_bits,
                budget_bytes=budget_bytes,
                selection_key=selection_key,
            )
            entries.append(candidate_entry)
            group, axis_value = _neighbor_axis(candidate)
            peers = [
                row
                for row in normalized
                if row[eligible_field]
                and row["memory_total_edge_bytes_mean"] <= budget_bytes
                and _neighbor_axis(row)[0] == group
            ]
            ordered = sorted(
                peers,
                key=lambda row: (
                    _neighbor_axis(row)[1],
                    row["method"],
                    _canonical(row["configured_spec"]),
                ),
            )
            candidate_index = next(
                index
                for index, row in enumerate(ordered)
                if row["method"] == candidate["method"]
                and _canonical(row["configured_spec"])
                == _canonical(candidate["configured_spec"])
                and _neighbor_axis(row)[1] == axis_value
            )
            neighbors: list[tuple[str, dict[str, Any]]] = []
            if candidate_index > 0:
                neighbors.append(("lower", ordered[candidate_index - 1]))
            if candidate_index + 1 < len(ordered):
                neighbors.append(("upper", ordered[candidate_index + 1]))
            for direction, neighbor in neighbors:
                entries.append(
                    _selection_entry(
                        neighbor,
                        role="matched_neighbor",
                        profile=profile,
                        budget_bits=budget_bits,
                        budget_bytes=budget_bytes,
                        selection_key=selection_key,
                        direction=direction,
                        anchor_spec_id=candidate_entry["spec_id"],
                    )
                )
    selected_specs: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        identity = (entry["family"], _canonical(entry["parameters"]))
        if identity not in seen:
            seen.add(identity)
            selected_specs.append(
                {"family": entry["family"], "parameters": entry["parameters"]}
            )
    return entries, selected_specs


def recompute_candidate_set_id(config: dict[str, Any]) -> str:
    selected = config.get("selected_specs")
    if not isinstance(selected, list) or not selected:
        raise ValueError("candidate set ID requires nonempty selected_specs")
    selection = _confirmation_selection(config)
    entries = selection["candidate_and_matched_neighbors"]
    if not entries:
        raise ValueError("candidate set ID requires the full candidate/neighbor ledger")
    material = {
        "schema": "phase1-timing-candidate-set-v3",
        "phase1_aggregate_identity": selection[
            "expected_phase1_aggregate_identity"
        ],
        "phase1_source_commit": selection["expected_phase1_source_commit"],
        "selection_schema_version": selection["schema_version"],
        "selection_algorithm": selection["algorithm"],
        "profiles": selection["profiles"],
        "memory_budget_bits_per_account": selection[
            "memory_budget_bits_per_account"
        ],
        "fixed_memory_overhead_bytes": selection[
            "fixed_memory_overhead_bytes"
        ],
        "objective": selection["objective"],
        "neighbor_rule": selection["neighbor_rule"],
        "latency_match_contract": selection["latency_match_contract"],
        "candidate_and_matched_neighbors": entries,
        "screening_measurements_used_for_favorable_selection": config.get(
            "screening_measurements_used_for_favorable_selection"
        ),
        "selected_specs": selected,
        "screening_seed": SCREENING_SEED,
        "confirmation_seeds": list(CONFIRMATION_SEEDS),
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_timing_config(
    config: dict[str, Any], phase1_aggregate: dict[str, Any] | None = None
) -> None:
    stage = str(config.get("timing_stage", ""))
    if stage not in TIMING_STAGES:
        raise ValueError(f"timing_stage must be one of {sorted(TIMING_STAGES)}")
    if not isinstance(config.get("execution_enabled"), bool):
        raise ValueError("execution_enabled must be Boolean")
    timing = config.get("timing")
    if not isinstance(timing, dict):
        raise ValueError("timing must be a mapping")
    required_positive = (
        "query_pool_count",
        "warmup_query_count",
        "warm_throughput_query_count",
        "warm_throughput_repetitions",
        "warm_latency_query_count",
        "cold_latency_query_count",
        "cold_eviction_bytes",
    )
    for field in required_positive:
        value = timing.get(field)
        if type(value) is not int or value <= 0:
            raise ValueError(f"timing.{field} must be positive")
    pool = int(timing["query_pool_count"])
    if int(timing["warm_throughput_query_count"]) % pool:
        raise ValueError("warm_throughput_query_count must be divisible by query_pool_count")
    needed = pool + int(timing["warm_latency_query_count"]) + int(
        timing["cold_latency_query_count"]
    )
    if needed > int(config["dataset"]["nonmember_count"]):
        raise ValueError("timing query ranges exceed dataset.nonmember_count")
    concurrency = timing.get("declared_benchmark_process_concurrency")
    if type(concurrency) is not int or concurrency != 1:
        raise ValueError("the isolated timing protocol requires concurrency=1")
    formal_value = config.get("formal_timing")
    if type(formal_value) is not bool:
        raise ValueError("formal_timing must be Boolean")
    formal = formal_value
    if (stage == "pilot") != (not formal):
        raise ValueError("only pilot timing may be nonformal")
    if formal:
        if config.get("require_clean_git") is not True:
            raise ValueError("formal timing must require clean Git provenance")
        if timing.get("require_single_cpu_affinity") is not True:
            raise ValueError("formal timing must require single-CPU affinity")
        if timing.get("require_exclusive_host") is not True:
            raise ValueError("formal timing must require an exclusive host")
        dataset = config["dataset"]
        if (
            type(dataset.get("account_count")) is not int
            or dataset["account_count"] != PHASE1_ACCOUNT_COUNT
            or type(dataset.get("nonmember_count")) is not int
            or dataset["nonmember_count"] != PHASE1_NONMEMBER_COUNT
            or type(dataset.get("seed")) is not int
            or dataset["seed"] != PHASE1_DATASET_SEED
        ):
            raise ValueError("formal timing requires the frozen Phase 1 dataset")
        for field, expected in FORMAL_SAMPLE_CONTRACT.items():
            if type(timing.get(field)) is not int or timing[field] != expected:
                raise ValueError(f"formal timing has the wrong timing.{field}")
        if timing.get("query_window_assignment") != FORMAL_QUERY_WINDOW_ASSIGNMENT:
            raise ValueError("formal timing query-window assignment mismatch")
        if timing.get("point_ordering") != FORMAL_POINT_ORDERING:
            raise ValueError("formal timing point-ordering contract mismatch")

    specs = expand_timing_specs(config)
    seed_values = config.get("seeds")
    if (
        not isinstance(seed_values, list)
        or not seed_values
        or any(type(seed) is not int or seed < 0 for seed in seed_values)
    ):
        raise ValueError("seeds must be a nonempty list of nonnegative integers")
    seeds = tuple(seed_values)
    if formal and len(specs) == PHASE1_SPEC_COUNT and len(seeds) >= 20:
        raise ValueError(
            "the 794-spec by 20-trial formal contract is prohibited; "
            "use staged screening and confirmation"
        )
    if stage == "all_spec_screening":
        if len(specs) != PHASE1_SPEC_COUNT or seeds != (SCREENING_SEED,):
            raise ValueError("screening requires all 794 specs and its one frozen seed")
        if config.get("selected_specs") is not None:
            raise ValueError("screening must cover the full configured spec universe")
        if (
            type(timing.get("formal_shard_count")) is not int
            or timing["formal_shard_count"] != SCREENING_SHARD_COUNT
        ):
            raise ValueError("screening formal shard count mismatch")
    elif stage == "candidate_confirmation":
        if seeds != CONFIRMATION_SEEDS:
            raise ValueError("confirmation requires the 20 frozen independent seeds")
        if SCREENING_SEED in seeds:
            raise ValueError("confirmation seeds must be independent of screening")
        if config.get("candidate_selection_rule") != CANDIDATE_SELECTION_RULE:
            raise ValueError("confirmation candidate-selection rule mismatch")
        if config.get("screening_measurements_used_for_favorable_selection") is not False:
            raise ValueError("confirmation forbids favorable screening-based selection")
        selection = _confirmation_selection(config)
        enabled = config["execution_enabled"]
        expected_shard_count = (
            len(specs) * len(seeds) if enabled else CONFIRMATION_SHARD_COUNT
        )
        if (
            type(timing.get("formal_shard_count")) is not int
            or timing["formal_shard_count"] != expected_shard_count
        ):
            raise ValueError("confirmation formal shard count mismatch")
        if enabled:
            if not specs:
                raise ValueError("enabled confirmation requires frozen selected_specs")
            if config.get("candidate_set_status") != "FROZEN":
                raise ValueError("enabled confirmation requires candidate_set_status=FROZEN")
            if phase1_aggregate is None:
                raise ValueError(
                    "enabled confirmation requires a qualified Phase 1 aggregate"
                )
            summaries = phase1_aggregate.get("summaries")
            audit = phase1_aggregate.get("audit")
            if not isinstance(summaries, list) or not isinstance(audit, dict):
                raise ValueError("qualified Phase 1 aggregate object is malformed")
            recomputed_identity = compute_phase1_aggregate_identity(summaries, audit)
            if (
                phase1_aggregate.get("identity") != recomputed_identity
                or selection["expected_phase1_aggregate_identity"]
                != recomputed_identity
                or phase1_aggregate.get("source_commit")
                != selection["expected_phase1_source_commit"]
            ):
                raise ValueError("enabled confirmation aggregate binding mismatch")
            expected_entries, expected_specs = derive_confirmation_selection(summaries)
            if selection["candidate_and_matched_neighbors"] != expected_entries:
                raise ValueError(
                    "enabled confirmation candidate/matched-neighbor ledger mismatch"
                )
            if config["selected_specs"] != expected_specs:
                raise ValueError("enabled confirmation selected_specs union mismatch")
            if config.get("candidate_set_id") != recompute_candidate_set_id(config):
                raise ValueError("enabled confirmation candidate_set_id mismatch")
        else:
            if specs:
                raise ValueError("disabled confirmation template must not name candidates")
            if config.get("candidate_set_status") != (
                "BLOCKED_PENDING_QUALIFIED_PHASE1_AGGREGATE"
            ):
                raise ValueError("disabled confirmation status is not fail-closed")
            if config.get("candidate_set_id") is not None:
                raise ValueError("disabled confirmation template has a candidate set ID")
            if (
                selection["expected_phase1_aggregate_identity"] is not None
                or selection["expected_phase1_source_commit"] is not None
                or selection["candidate_and_matched_neighbors"]
            ):
                raise ValueError(
                    "disabled confirmation template must not bind aggregate candidates"
                )


def validate_frozen_config_id(config: dict[str, Any], config_id: str) -> None:
    stage = str(config["timing_stage"])
    expected: str | None = None
    if stage == "pilot" and config.get("scenario") == "E1_isolated_filter_timing_pilot":
        expected = PILOT_CONFIG_ID
    elif stage == "all_spec_screening":
        expected = SCREENING_CONFIG_ID
    elif stage == "candidate_confirmation":
        if config["execution_enabled"] is False:
            expected = CONFIRMATION_TEMPLATE_CONFIG_ID
        elif config.get("candidate_set_id") == CONFIRMATION_CANDIDATE_SET_ID:
            expected = CONFIRMATION_CONFIG_ID
        else:
            raise ValueError("enabled confirmation has an unknown frozen candidate set ID")
    if expected is not None and config_id != expected:
        raise ValueError(
            f"{stage} semantic config ID mismatch: expected {expected}, found {config_id}"
        )


def _summary_us(latencies_ns: list[int]) -> dict[str, float]:
    if not latencies_ns:
        raise ValueError("latency sample is empty")
    values = [value / 1000.0 for value in latencies_ns]
    return {
        "p50": float(_percentile(values, 0.50)),
        "p95": float(_percentile(values, 0.95)),
        "p99": float(_percentile(values, 0.99)),
    }


def _latency_histogram(latencies_ns: list[int]) -> list[dict[str, int]]:
    counts = Counter(latencies_ns)
    return [
        {"latency_ns": latency_ns, "count": counts[latency_ns]}
        for latency_ns in sorted(counts)
    ]


def observation_sha256(row: dict[str, Any]) -> str:
    material = {
        key: value
        for key, value in row.items()
        if key != "observation_sha256" and not key.startswith("_")
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _query_window(
    dataset: SyntheticCredentialSet, start: int, count: int
) -> list[Any]:
    return [dataset.nonmember(start + ordinal) for ordinal in range(count)]


def _warm_throughput_trials(
    filter_object: Any,
    query_pool: list[Any],
    query_count: int,
    repetitions: int,
) -> list[float]:
    rounds = query_count // len(query_pool)
    trials: list[float] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        for _ in range(rounds):
            for query in query_pool:
                filter_object.query(query)
        elapsed_ns = time.perf_counter_ns() - started
        trials.append(query_count / (elapsed_ns / 1_000_000_000.0))
    return trials


def _warm_latencies(filter_object: Any, queries: list[Any]) -> list[int]:
    latencies: list[int] = []
    for query in queries:
        started = time.perf_counter_ns()
        filter_object.query(query)
        finished = time.perf_counter_ns()
        latencies.append(finished - started)
    return latencies


def _cold_latencies(
    filter_object: Any, queries: list[Any], eviction_bytes: int
) -> tuple[list[int], int]:
    eviction = bytearray(eviction_bytes)
    token = 0
    latencies: list[int] = []
    for query in queries:
        # crc32 is a native full-buffer read.  It is outside the timed interval
        # and its evolving return value prevents the read from being discarded.
        token = zlib.crc32(eviction, token)
        started = time.perf_counter_ns()
        filter_object.query(query)
        finished = time.perf_counter_ns()
        latencies.append(finished - started)
    return latencies, token


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


def _benchmark_point(
    config: dict[str, Any],
    config_id: str,
    dataset_id: str,
    commit: str,
    git_dirty: bool,
    environment: dict[str, Any],
    dataset: SyntheticCredentialSet,
    members: list[Any],
    spec: Any,
    trial_seed: int,
    measurement_order: int,
    shard_index: int,
    shard_count: int,
) -> dict[str, Any]:
    timing = config["timing"]
    build_started = time.perf_counter_ns()
    filter_object = build_filter(spec, members, trial_seed)
    build_ns = time.perf_counter_ns() - build_started

    # Deterministic disjoint windows keep token generation outside all timed
    # intervals and vary the measurement stream across independent trials.
    query_window_ordinal, start = query_window_assignment(config, trial_seed)
    cursor = start
    query_pool = _query_window(dataset, cursor, int(timing["query_pool_count"]))
    cursor += len(query_pool)
    warm_queries = _query_window(
        dataset, cursor, int(timing["warm_latency_query_count"])
    )
    cursor += len(warm_queries)
    cold_queries = _query_window(
        dataset, cursor, int(timing["cold_latency_query_count"])
    )

    preflight = query_pool[: min(1024, len(query_pool))]
    preflight_positives = sum(filter_object.query(query).positive for query in preflight)
    for ordinal in range(int(timing["warmup_query_count"])):
        filter_object.query(query_pool[ordinal % len(query_pool)])

    throughput_trials = _warm_throughput_trials(
        filter_object,
        query_pool,
        int(timing["warm_throughput_query_count"]),
        int(timing["warm_throughput_repetitions"]),
    )
    warm_values = _warm_latencies(filter_object, warm_queries)
    warm = _summary_us(warm_values)
    cold_values, eviction_token = _cold_latencies(
        filter_object, cold_queries, int(timing["cold_eviction_bytes"])
    )
    cold = _summary_us(cold_values)
    memory = filter_object.memory_report()
    filter_parameters = filter_object.parameters()
    finite_fpr, standard_fpr = _analytic_fprs(filter_object)
    is_tag = spec.family == "tag"
    method = _method_for_spec(spec.family, spec.parameters)
    identity = json.dumps(spec.parameters, sort_keys=True, separators=(",", ":"))
    run_material = (
        f"{commit}:{config_id}:{dataset_id}:{trial_seed}:{spec.family}:{identity}:"
        f"{measurement_order}:{shard_index}:{shard_count}"
    )
    run_id = hashlib.sha256(run_material.encode()).hexdigest()[:24]
    single_affinity = (
        type(environment["affinity_cpu_count"]) is int
        and environment["affinity_cpu_count"] == 1
    )
    formal = bool(config.get("formal_timing", False))
    if formal and shard_count != int(config["timing"]["formal_shard_count"]):
        raise ValueError("formal timing shard count differs from the frozen config")
    affinity_record = environment["affinity_cpu_records"][0] if single_affinity else {}
    llc_bytes = affinity_record.get("last_level_cache_bytes")
    eviction_bytes = int(timing["cold_eviction_bytes"])
    eviction_ratio = (
        eviction_bytes / int(llc_bytes)
        if type(llc_bytes) is int and int(llc_bytes) > 0
        else None
    )
    protocol_valid = (
        not git_dirty
        and type(environment["declared_benchmark_process_concurrency"]) is int
        and environment["declared_benchmark_process_concurrency"] == 1
        and single_affinity
        and environment["exclusive_host_human_declared"] is True
        and environment["same_runner_host_lock_acquired"] is True
    )
    row = {
        "run_id": run_id,
        "commit": commit,
        "git_dirty": git_dirty,
        "source_status_scope": "repository excluding experiments/outputs/**",
        "semantic_config_id": config_id,
        "semantic_dataset_id": dataset_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "formal_timing": formal,
        "timing_stage": str(config["timing_stage"]),
        "result_status": "OBSERVED" if formal and protocol_valid else "TEMP_SMOKE",
        "timing_protocol": TIMING_PROTOCOL,
        "timing_protocol_valid": protocol_valid,
        "timing_interval": "filter.query only",
        "timed_interval_excludes": [
            "query generation",
            "warmup",
            "positive counting",
            "histogram and percentile construction",
            "throughput bookkeeping",
            "cold-cache eviction",
        ],
        "method": method,
        "configured_spec": spec.parameters,
        "filter_parameters": filter_parameters,
        "construction_seed": None if is_tag else trial_seed,
        "measurement_trial_seed": trial_seed,
        "measurement_order": measurement_order,
        "shard_index": shard_index,
        "shard_count": shard_count,
        "query_window_assignment": timing.get("query_window_assignment", "pilot_hash_v1"),
        "query_window_ordinal": query_window_ordinal,
        "query_window_start": start,
        "query_window_end_exclusive": start
        + int(timing["query_pool_count"])
        + int(timing["warm_latency_query_count"])
        + int(timing["cold_latency_query_count"]),
        "randomized_construction": not is_tag,
        "host_environment": environment,
        "build_time_s": build_ns / 1_000_000_000.0,
        "memory_payload_bytes": memory.payload_bytes,
        "memory_metadata_bytes": memory.metadata_bytes,
        "memory_alignment_bytes": memory.alignment_bytes,
        "memory_compact_total_bytes": memory.total_bytes,
        "memory_filter_bytes": 0 if is_tag else memory.total_bytes,
        "memory_model_bytes": 0,
        "memory_cache_bytes": 0,
        "memory_directory_extra_bytes": memory.total_bytes if is_tag else 0,
        "memory_common_prf_key_bytes": 32,
        "memory_total_edge_bytes": memory.total_bytes + 32,
        "analytic_fpr_finite": finite_fpr,
        "analytic_fpr_standard": standard_fpr,
        "preflight_query_count": len(preflight),
        "preflight_positive_count": preflight_positives,
        "warm_query_throughput_qps_trials": throughput_trials,
        "warm_query_throughput_qps_mean": statistics.mean(throughput_trials),
        "warm_throughput_query_count_per_trial": int(
            timing["warm_throughput_query_count"]
        ),
        "warm_throughput_repetition_count": int(
            timing["warm_throughput_repetitions"]
        ),
        "warmup_query_count": int(timing["warmup_query_count"]),
        "query_pool_count": int(timing["query_pool_count"]),
        "warm_latency_sample_count": len(warm_queries),
        "warm_latency_histogram_ns": _latency_histogram(warm_values),
        "frontend_warm_p50_us": warm["p50"],
        "frontend_warm_p95_us": warm["p95"],
        "frontend_warm_p99_us": warm["p99"],
        "cold_latency_sample_count": len(cold_values),
        "cold_latency_histogram_ns": _latency_histogram(cold_values),
        "cold_eviction_bytes_per_query": eviction_bytes,
        "cold_eviction_method": "zlib.crc32 native full-buffer read before every query",
        "cold_eviction_per_query": True,
        "cold_eviction_time_excluded": True,
        "cold_eviction_last_level_cache_bytes": llc_bytes,
        "cold_eviction_buffer_to_llc_ratio": eviction_ratio,
        "cold_eviction_minimum_llc_multiple": int(
            timing.get("cold_eviction_minimum_llc_multiple", 4)
        ),
        "cold_eviction_claim_scope": (
            "software cache displacement; not a hardware flush guarantee"
        ),
        "cold_eviction_terminal_token": eviction_token,
        "frontend_cold_p50_us": cold["p50"],
        "frontend_cold_p95_us": cold["p95"],
        "frontend_cold_p99_us": cold["p99"],
    }
    row["observation_sha256"] = observation_sha256(row)
    return row


def run_config(
    config_path: Path,
    shard_index: int = 0,
    shard_count: int = 1,
    progress: bool = False,
) -> list[dict[str, Any]]:
    if shard_count <= 0 or not 0 <= shard_index < shard_count:
        raise ValueError("invalid shard index/count")
    config, config_id = load_config(config_path)
    phase1_aggregate = (
        load_phase1_selection_aggregate(config, config_path)
        if config.get("timing_stage") == "candidate_confirmation"
        and config.get("execution_enabled") is True
        else None
    )
    validate_timing_config(config, phase1_aggregate)
    validate_frozen_config_id(config, config_id)
    if config["execution_enabled"] is not True:
        raise RuntimeError("timing config is a disabled protocol template")
    formal = bool(config.get("formal_timing", False))
    if formal and shard_count != int(config["timing"]["formal_shard_count"]):
        raise ValueError("formal timing shard count differs from the frozen config")
    commit, git_dirty = _git_provenance()
    if commit is None or git_dirty is None:
        raise RuntimeError("timing requires readable Git provenance")
    if formal and git_dirty:
        raise RuntimeError("formal timing requires a clean source tree")
    environment = host_environment(
        int(config["timing"]["declared_benchmark_process_concurrency"])
    )
    if formal:
        _require_formal_host_environment(environment)
        _require_cold_eviction_capacity(config, environment)

    dataset_config = config["dataset"]
    dataset = SyntheticCredentialSet(
        int(dataset_config["account_count"]), int(dataset_config["seed"])
    )
    members = [dataset.member(index) for index in range(dataset.account_count)]
    dataset_id = dataset.manifest_hash(
        members, int(dataset_config["nonmember_count"])
    )
    if formal and dataset_id != PHASE1_DATASET_ID:
        raise RuntimeError("formal timing dataset semantic ID mismatch")
    points = ordered_timing_points(config)
    selected = [
        (ordinal, point)
        for ordinal, point in enumerate(points)
        if ordinal % shard_count == shard_index
    ]
    rows: list[dict[str, Any]] = []
    with HostTimingLock(required=formal):
        environment["same_runner_host_lock_acquired"] = formal
        for local_ordinal, (measurement_order, (seed, spec)) in enumerate(
            selected, start=1
        ):
            if progress:
                print(
                    f"[{local_ordinal}/{len(selected)}] order={measurement_order} "
                    f"seed={seed} spec={spec.identity}",
                    file=sys.stderr,
                    flush=True,
                )
            row = _benchmark_point(
                config,
                config_id,
                dataset_id,
                commit,
                git_dirty,
                environment,
                dataset,
                members,
                spec,
                seed,
                measurement_order,
                shard_index,
                shard_count,
            )
            rows.append(row)
    return rows


def write_rows(path: Path, rows: list[dict[str, Any]], overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w" if overwrite else "x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--shard-index", type=int, default=0)
    parser.add_argument("--shard-count", type=int, default=1)
    parser.add_argument("--check-environment-only", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config, config_id = load_config(args.config)
    phase1_aggregate = (
        load_phase1_selection_aggregate(config, args.config)
        if config.get("timing_stage") == "candidate_confirmation"
        and config.get("execution_enabled") is True
        else None
    )
    validate_timing_config(config, phase1_aggregate)
    validate_frozen_config_id(config, config_id)
    if args.check_environment_only:
        if config["execution_enabled"] is not True:
            raise RuntimeError("timing config is a disabled protocol template")
        commit, git_dirty = _git_provenance()
        environment = host_environment(
            int(config["timing"]["declared_benchmark_process_concurrency"])
        )
        formal = bool(config.get("formal_timing", False))
        if commit is None or git_dirty is None:
            raise RuntimeError("timing requires readable Git provenance")
        if formal and git_dirty:
            raise RuntimeError("formal timing requires a clean source tree")
        if formal:
            _require_formal_host_environment(environment)
            _require_cold_eviction_capacity(config, environment)
        print(
            json.dumps(
                {"commit": commit, "git_dirty": git_dirty, **environment},
                sort_keys=True,
            )
        )
        return 0
    output_value = args.output or config.get("output")
    if output_value is None:
        raise ValueError("provide --output or top-level output in the YAML config")
    output_path = Path(output_value)
    if args.output is None and not output_path.is_absolute():
        output_path = ROOT / output_path
    if args.output is None and args.shard_count > 1:
        output_path = output_path.with_name(
            f"{output_path.stem}.shard-{args.shard_index:04d}"
            f"-of-{args.shard_count:04d}{output_path.suffix}"
        )
    rows = run_config(
        args.config,
        shard_index=args.shard_index,
        shard_count=args.shard_count,
        progress=True,
    )
    write_rows(output_path, rows, args.overwrite)
    print(f"wrote {len(rows)} timing rows to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
