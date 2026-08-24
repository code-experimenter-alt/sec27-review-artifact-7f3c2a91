#!/usr/bin/env python3
"""Formal full-grid timing runner for the Phase 1 v2 Pareto frontier."""

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
import tempfile
import time
import zlib
from collections import Counter
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.runners.filter_bench import (  # noqa: E402
    FilterSpec,
    SyntheticCredentialSet,
    _analytic_fprs,
    _git_provenance,
    _percentile,
    build_filter,
    expand_specs,
)
from reference.filters import CredentialInput, ScreenQuery  # noqa: E402
from reference.filters.prescreen import (  # noqa: E402
    CanonicalPrescreenPath,
    DirectoryRecord,
    LoginAttempt,
)

PROTOCOL = "phase1_timing_frontier_v2_1"
ROW_SCHEMA = "traps-phase1-timing-frontier-v2-raw-row-v2"
STAGES = ("warm-look1", "warm-look2", "cold")
PHASE1_SPEC_COUNT = 794
ACCOUNT_COUNT = 100_000
NONMEMBER_COUNT = 13_000_000
DATASET_SEED = 20_260_813
TIMING_DATASET_ID = "94fac88de13e9808962f6970c4a7865aa56c805b09003d90eb5de262043d4551"
WARM_SHARD_COUNT = 20
COLD_SHARD_COUNT = 8
ROTATION_STRIDE = 251
SOURCE_COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
SEMANTIC_ID_PATTERN = re.compile(r"[0-9a-f]{64}")


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader, node: MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)

LOOK1_SEEDS = (
    2700004,
    2725012,
    2750022,
    2775010,
    2800014,
    2825004,
    2850012,
    2875014,
    2900004,
    2925022,
    2950012,
    2975014,
    3000006,
    3025012,
    3050014,
    3075010,
    3100012,
    3125004,
    3150030,
    3175006,
)
LOOK2_SEEDS = (
    3225012,
    3250006,
    3275014,
    3300024,
    3325014,
    3350004,
    3375010,
    3400020,
    3425010,
    3450022,
    3475006,
    3500010,
    3525024,
    3550030,
    3575014,
    3600036,
    3625020,
    3650004,
    3675004,
    3700024,
)
COLD_SEED = 3_200_010

EXPECTED_TOP_LEVEL_KEYS = {
    "schema_version",
    "scenario",
    "protocol",
    "execution_enabled",
    "formal_timing",
    "require_clean_git",
    "source_commit_binding",
    "source_evidence",
    "corpus_equivalence",
    "construction_feasibility",
    "dataset",
    "warm",
    "cold",
    "timing",
    "frontier",
    "methods",
    "outputs",
}
EXPECTED_SOURCE_EVIDENCE = {
    "mode": "REUSE_FROZEN_794_UNCHANGED_FILTER_SEMANTICS",
    "filter_grid_commit": "782cbcf17db7959a1521764e26d2b4fa859142fc",
    "filter_grid_semantic_config_id": (
        "38c20f538643106159a799deb90c78e6c909934e3858b163ae2c56ea3438bade"
    ),
    "filter_grid_semantic_dataset_id": (
        "0e0299a7367c6a115e077440e7a04936712b654a1e0a836785d3e6862ac34a4a"
    ),
    "filter_grid_attestation_id": (
        "ff2d7c3d8d4b6356f26d4cf7aeee051257f6b81712a3d89695205204bd521dfa"
    ),
    "filter_grid_raw_row_count": 7_868,
    "filter_grid_shard_count": 36,
    "filter_grid_spec_count": 794,
    "filter_grid_aggregate_identity_schema": "phase1-selection-aggregate-v2",
    "filter_grid_aggregate_identity": (
        "1449c451bc2f6862881ce5b8fb52d584b6329ce088d3ca36a4981bc96c055da1"
    ),
    "randomized_constructions_per_spec": 10,
    "randomized_first_seen_interval": ("outer_envelope_cluster_t95_and_pooled_clopper_pearson95"),
    "static_tag_constructions_per_spec": 1,
    "static_tag_first_seen_interval": "pooled_clopper_pearson_exact95",
    "per_construction_interval": "wilson_score95",
    "diagnostic_schema_version": 3,
    "diagnostic_protocol": "phase1-independent-bloom-query-path-reproduction-v4",
    "diagnostic_source_commit": "6dcbaaa9748f4e5f8b1e9fbaf9bd7d31ccc9678e",
    "diagnostic_config_id": ("dd0193c424468553b21101122e2b513dabae5800e5d3f6c46d024afd1294294e"),
    "diagnostic_family_size": 7_680,
    "diagnostic_robust_overlap_count": 7_680,
    "diagnostic_robust_separation_count": 0,
    "diagnostic_ambiguous_count": 0,
    "diagnostic_target_attestation_id": (
        "ff2d7c3d8d4b6356f26d4cf7aeee051257f6b81712a3d89695205204bd521dfa"
    ),
    "immutable_v1_timing_commit": "4097f2b8555238b79253b506f61d3fb473b51d74",
    "immutable_v1_timing_semantic_config_id": (
        "cdddd91c24b008b37d5c833b127f08d94c8d20546b5f1673a38617a18b4037f9"
    ),
    "immutable_v1_candidate_set_id": (
        "e23c6e8625cf41e19eee9abff349ac3b62af28a30208631b095c1f30115eae43"
    ),
    "immutable_v1_raw_observation_set_sha256": (
        "77e081baf406dd130daa3cd4775ce08ee317580363d61d234afb7c4f32ce8b2b"
    ),
    "immutable_v1_timing_claim_gate": "FAIL_PHASE1_SCREENING_LATENCY_ELIGIBILITY",
    "immutable_v1_relation_count": 28,
    "immutable_v1_pass_count": 24,
    "immutable_v1_fail_count": 3,
    "immutable_v1_indeterminate_count": 1,
    "semantic_change_action": "RERUN_FULL_7868_ROW_FUNCTIONAL_FFR_GRID",
}
EXPECTED_METHODS = {
    "exact_tag": True,
    "truncated_tags": {"bits": [8, 12, 16, 20, 24, 32, 64]},
    "global_bloom": {
        "bits_per_account": [4, 8, 12, 16, 24, 32, 48, 64],
        "k_min": 1,
        "k_max": 48,
    },
    "blocked_bloom": {
        "bits_per_account": [4, 8, 12, 16, 24, 32, 48, 64],
        "k_min": 1,
        "k_max": 48,
    },
    "xor_static": {
        "fingerprint_bits": [4, 8, 12, 16, 20, 24, 32, 48, 64],
        "capacity_factor": 1.23,
        "max_attempts": 100,
    },
    "cuckoo": {
        "fingerprint_bits": [4, 8, 12, 16, 20, 24, 32, 48, 64],
        "bucket_size": 4,
        "target_load": 0.90,
        "max_kicks": 500,
        "max_seed_attempts": 20,
    },
}


@dataclass(frozen=True)
class StagePlan:
    stage: str
    trial_seed: int
    global_seed_ordinal: int | None
    specs: tuple[FilterSpec, ...]
    shard_index: int
    shard_count: int


@dataclass(frozen=True)
class WarmInputs:
    query_window_start: int
    query_window_end_exclusive: int
    pool_attempts: tuple[LoginAttempt, ...]
    pool_queries: tuple[ScreenQuery, ...]
    actual_latency_attempts: tuple[LoginAttempt, ...]
    query_only_latency_queries: tuple[ScreenQuery, ...]


class HostTimingLock(AbstractContextManager["HostTimingLock"]):
    """Fail closed if another cooperating formal timing process is active."""

    def __init__(self, required: bool) -> None:
        self.required = required
        self._handle: Any = None

    def __enter__(self) -> HostTimingLock:
        if not self.required:
            return self
        try:
            import fcntl
        except ImportError as error:
            raise RuntimeError("formal timing requires POSIX fcntl host locking") from error
        path = Path(os.environ.get("TRAPS_TIMING_LOCK", "/tmp/traps-filter-timing-v2.lock"))
        self._handle = path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self._handle.close()
            self._handle = None
            raise RuntimeError("another v2 timing process is active on this host") from error
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
    parsed = json.loads(
        payload,
        object_pairs_hook=_reject_duplicate_json_pairs,
        parse_constant=_reject_nonfinite_json_constant,
    )
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
            type(cpu) is not int
            or cpu < 0
            or not isinstance(model, str)
            or not model.strip()
            or cpu in models
        ):
            raise ValueError("lscpu CPU row is invalid or duplicated")
        models[cpu] = model.strip()
    return models


def _lscpu_model_names() -> dict[int, str]:
    process_environment = dict(os.environ)
    process_environment.update({"LANG": "C", "LC_ALL": "C"})
    try:
        completed = subprocess.run(
            ["lscpu", "--json", "--extended=CPU,MODELNAME"],
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="strict",
            env=process_environment,
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
    multiplier = {None: 1, "K": 1024, "M": 1024**2, "G": 1024**3}[match.group(2)]
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


def _last_level_data_cache(
    cache_records: list[dict[str, Any]],
) -> tuple[int | None, int | None]:
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
    size = max(int(record["size_bytes"]) for record in candidates if int(record["level"]) == level)
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
                "cache_enumeration_status": ("COMPLETE" if cache_records else "UNAVAILABLE"),
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
            str(record["logical_cpu"]): record["scaling_governor"] for record in affinity_records
        },
        "declared_benchmark_process_concurrency": declared_concurrency,
        "exclusive_host_human_declared": os.environ.get("TRAPS_EXCLUSIVE_HOST") == "1",
        "exclusive_host_automatically_verified": False,
        "load_average_1m_5m_15m": load_average,
        "host_lock_path": os.environ.get("TRAPS_TIMING_LOCK", "/tmp/traps-filter-timing-v2.lock"),
        "host_lock_required_for_formal": True,
        "host_lock_scope": "cooperating TRAPS v2 timing processes only",
        "same_runner_host_lock_acquired": False,
    }


def _require_formal_host_environment(environment: dict[str, Any]) -> None:
    affinity = environment["affinity_cpus"]
    records = environment["affinity_cpu_records"]
    if len(affinity) != 1 or len(records) != 1:
        raise RuntimeError("formal timing requires exactly one affinity CPU")
    record = records[0]
    if (
        environment["cpu_model_source"] != "unique affinity_cpu_records[0].model_name"
        or environment["cpu_model"] != record["model_name"]
        or record["model_name"] == "unknown"
        or record.get("model_name_source") == "unavailable"
    ):
        raise RuntimeError("formal timing requires an affinity-specific CPU model")
    cache_records = record.get("cache_records")
    derived_level, derived_bytes = _last_level_data_cache(
        cache_records if isinstance(cache_records, list) else []
    )
    if (
        type(record.get("last_level_cache_level")) is not int
        or type(record.get("last_level_cache_bytes")) is not int
        or int(record["last_level_cache_bytes"]) <= 0
        or not isinstance(cache_records, list)
        or record.get("cache_enumeration_status") != "COMPLETE"
        or record["last_level_cache_level"] != derived_level
        or record["last_level_cache_bytes"] != derived_bytes
    ):
        raise RuntimeError("formal timing requires an affinity-specific cache hierarchy")
    if not str(record.get("scaling_governor", "")).strip() or environment[
        "scaling_governor_by_affinity_cpu"
    ] != {str(affinity[0]): record["scaling_governor"]}:
        raise RuntimeError("formal timing requires an affinity-specific CPU governor")
    if environment["exclusive_host_human_declared"] is not True:
        raise RuntimeError("formal timing requires TRAPS_EXCLUSIVE_HOST=1")


def _require_cold_eviction_capacity(config: dict[str, Any], environment: dict[str, Any]) -> None:
    record = environment["affinity_cpu_records"][0]
    llc_bytes = int(record["last_level_cache_bytes"])
    eviction_bytes = int(config["timing"]["cold_eviction_bytes"])
    minimum_multiple = int(config["timing"]["cold_eviction_minimum_llc_multiple"])
    if eviction_bytes < minimum_multiple * llc_bytes:
        raise RuntimeError(
            "formal cold displacement buffer is smaller than the frozen LLC multiple"
        )


def observation_sha256(row: dict[str, Any]) -> str:
    material = {
        key: value
        for key, value in row.items()
        if key != "observation_sha256" and not key.startswith("_")
    }
    return _canonical_hash(material)


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _require_exact(actual: Any, expected: Any, path: str) -> None:
    """Compare frozen YAML values without Python's bool/int aliasing."""

    if type(actual) is not type(expected):
        raise ValueError(f"{path} has the wrong type")
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            raise ValueError(f"{path} has the wrong keys")
        for key, value in expected.items():
            _require_exact(actual[key], value, f"{path}.{key}")
        return
    if isinstance(expected, list):
        if len(actual) != len(expected):
            raise ValueError(f"{path} has the wrong length")
        for ordinal, (item, value) in enumerate(zip(actual, expected, strict=True)):
            _require_exact(item, value, f"{path}[{ordinal}]")
        return
    if actual != expected:
        raise ValueError(f"{path} does not match the frozen v2 contract")


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            config = yaml.load(handle, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as error:
        raise ValueError("v2 config is malformed or has duplicate keys") from error
    if not isinstance(config, dict):
        raise ValueError("v2 config must be a mapping")
    validate_config(config)
    return config, _canonical_hash(config)


def validate_config(config: dict[str, Any]) -> None:
    if set(config) != EXPECTED_TOP_LEVEL_KEYS:
        raise ValueError("v2 config has unexpected or missing top-level keys")
    for key, expected in {
        "schema_version": 3,
        "scenario": "E1_E2_complete_timing_aware_frontier_v2_1",
        "protocol": PROTOCOL,
        "execution_enabled": True,
        "formal_timing": True,
        "require_clean_git": True,
        "source_commit_binding": "CLI_EXPECTED_SOURCE_COMMIT_REQUIRED",
    }.items():
        _require_exact(config[key], expected, key)
    _require_exact(config["source_evidence"], EXPECTED_SOURCE_EVIDENCE, "source_evidence")
    _require_exact(
        config["corpus_equivalence"],
        {
            "receipt_schema": "traps-phase1-v2-corpus-equivalence-receipt-v1",
            "receipt_id_schema": "phase1-v2-corpus-equivalence-id-v1",
            "member_count": ACCOUNT_COUNT,
            "nonmember_count": NONMEMBER_COUNT,
            "verification": ("every_member_and_every_nonmember_public_api_vs_frozen_formula"),
            "required_for_every_timing_shard": True,
        },
        "corpus_equivalence",
    )
    _require_exact(
        config["construction_feasibility"],
        {
            "receipt_schema": "traps-phase1-v2-construction-feasibility-receipt-v1",
            "receipt_id_schema": "phase1-v2-construction-feasibility-id-v1",
            "families": ["xor_static", "cuckoo"],
            "spec_count": 18,
            "seed_count": 41,
            "build_count": 738,
            "member_validation_count_per_build": ACCOUNT_COUNT,
            "maximum_member_false_negatives": 0,
            "action_on_any_failure": ("VERSION_NEW_PROTOCOL_BEFORE_ANY_FORMAL_TIMING_ROW"),
            "required_for_every_timing_shard": True,
        },
        "construction_feasibility",
    )
    _require_exact(
        config["dataset"],
        {
            "generator": "phase1-exact-bytes-v1",
            "seed": DATASET_SEED,
            "account_count": ACCOUNT_COUNT,
            "nonmember_count": NONMEMBER_COUNT,
            "semantic_dataset_id": TIMING_DATASET_ID,
        },
        "dataset",
    )
    warm = config["warm"]
    expected_warm = {
        "look1_seeds": list(LOOK1_SEEDS),
        "look2_seeds": list(LOOK2_SEEDS),
        "shard_count_per_look": WARM_SHARD_COUNT,
        "specs_per_seed_shard": PHASE1_SPEC_COUNT,
        "query_window_stride": 300_000,
        "query_pool_count": 100_000,
        "warmup_query_count": 100_000,
        "actual_front_throughput_query_count": 100_000,
        "actual_front_throughput_repetitions": 5,
        "actual_front_latency_query_count": 100_000,
        "query_only_latency_query_count": 100_000,
        "preflight_query_count": 1_024,
        "point_ordering": "sha256_base_permutation_coprime_rotation_251_v2",
        "path_counterbalance": ("even_global_seed_ordinal_actual_first_odd_query_only_first"),
        "precision_metric": "indexed_directory_to_screen_decision_warm_p99_us",
        "precision_scale": "log",
        "precision_relative_half_width_max": 0.05,
        "precision_interval": "two_sided_student_t_log_p99",
        "precision_relative_half_width": (
            "max_upper_over_gm_minus_one_and_one_minus_lower_over_gm"
        ),
        "precision_familywise_alpha": 0.05,
        "precision_look_alpha": 0.025,
        "uncertain_coordinate_families_per_look": 2,
        "simultaneous_coordinate_alpha": 0.025 / (2 * PHASE1_SPEC_COUNT),
        "look2_trigger": "ANY_OF_794_LOOK1_POINTS_EXCEEDS_PRECISION_TARGET",
        "look1_decision_rule": ("hardware_stratum_then_timer_resolution_then_precision_v2"),
        "look1_extension_decision_receipt_schema": ("traps-phase1-v2-look1-extension-decision-v2"),
        "look1_extension_decision_id_schema": ("phase1-v2-look1-extension-decision-id-v2"),
        "look1_extension_decision_binding": "CLI_PATH_AND_EXPECTED_ID_REQUIRED",
        "maximum_trial_count": 40,
        "extension_rule": "FULL_794_POINT_SECOND_20_SEED_BLOCK_ONLY",
    }
    _require_exact(warm, expected_warm, "warm")
    _require_exact(
        config["cold"],
        {
            "seeds": [COLD_SEED],
            "shard_count": COLD_SHARD_COUNT,
            "spec_partition": "contiguous_floor_boundaries_over_frozen_base_order",
            "query_window_start": 12_000_000,
            "query_only_latency_query_count": 2_000,
            "eviction_bytes": 150_994_944,
            "eviction_minimum_llc_multiple": 4,
            "eviction_method": "zlib_crc32_native_full_buffer_read_before_each_query",
            "claim_scope": "QUERY_ONLY_SOFTWARE_CACHE_DISPLACEMENT_DIAGNOSTIC",
        },
        "cold",
    )
    _require_exact(
        config["timing"],
        {
            "declared_benchmark_process_concurrency": 1,
            "require_single_cpu_affinity": True,
            "require_exclusive_host": True,
            "clock": "time.perf_counter_ns",
            "clock_call_pattern": ("one_call_immediately_before_and_after_each_timed_query"),
            "clock_call_overhead_measurement": "back_to_back_perf_counter_ns_delta",
            "clock_call_overhead_sample_count": 100_000,
            "require_monotonic_clock": True,
            "minimum_primary_p99_to_clock_call_p99_ratio": 10.0,
            "cold_eviction_bytes": 150_994_944,
            "cold_eviction_minimum_llc_multiple": 4,
        },
        "timing",
    )
    _require_exact(
        config["frontier"],
        {
            "profiles": ["U", "A"],
            "profile_u_eligibility": "ALL_794_STATIC_FILTER_SPECS",
            "profile_a_eligibility": "AGGREGATE_FILTERS_ONLY_EXCLUDES_PER_ACCOUNT_TAGS",
            "objectives": [
                "memory_total_edge_bytes",
                "first_seen_ffr",
                "actual_front_warm_p99",
            ],
            "dominance": "all_objectives_lte_and_at_least_one_strict_lt_within_profile",
            "primary_membership": ("simultaneous_confidence_conservative_nondominated_set"),
            "secondary_membership": "descriptive_complete_grid_point_estimate_pareto",
            "ffr_interval_randomized": (
                "adjusted_raw_scale_construction_t_and_pooled_cp_outer_envelope"
            ),
            "ffr_interval_static_tag": "adjusted_pooled_clopper_pearson",
            "timing_interval": "adjusted_log_scale_student_t_over_seed_p99",
            "conservative_dominance": (
                "memory_lte_and_ffr_upper_lte_lower_and_timing_upper_lte_lower_one_strict"
            ),
            "gate": "complete_valid_reconstructable_actual_front_grid_and_precision_target",
            "multiplicity": "two_looks_by_two_uncertain_coordinates_by_794_bonferroni",
        },
        "frontier",
    )
    _require_exact(config["methods"], EXPECTED_METHODS, "methods")
    _require_exact(
        config["outputs"],
        {
            "root": "experiments/outputs/raw/filter_timing_frontier_v2_1",
            "warm_look1_pattern": (
                "warm-look1/filter_timing_frontier_v2_1.warm-look1.shard-{index:04d}-of-0020.jsonl"
            ),
            "warm_look2_pattern": (
                "warm-look2/filter_timing_frontier_v2_1.warm-look2.shard-{index:04d}-of-0020.jsonl"
            ),
            "cold_pattern": (
                "cold/filter_timing_frontier_v2_1.cold.shard-{index:04d}-of-0008.jsonl"
            ),
        },
        "outputs",
    )
    specs = expand_specs(config)
    identities = [spec.identity for spec in specs]
    if len(specs) != PHASE1_SPEC_COUNT or len(set(identities)) != PHASE1_SPEC_COUNT:
        raise ValueError("v2 methods do not expand to exactly 794 unique specs")
    warm_needed = len(LOOK1_SEEDS + LOOK2_SEEDS) * int(warm["query_window_stride"])
    cold_end = int(config["cold"]["query_window_start"]) + int(
        config["cold"]["query_only_latency_query_count"]
    )
    if max(warm_needed, cold_end) > NONMEMBER_COUNT:
        raise ValueError("frozen timing query windows exceed the corpus")


def _reject_duplicate_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _load_strict_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_nonfinite_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load strict JSON evidence: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"JSON evidence must be one object: {path}")
    return value


def _require_fields(value: dict[str, Any], expected: dict[str, Any], label: str) -> None:
    for key, wanted in expected.items():
        if key not in value:
            raise ValueError(f"{label} is missing {key}")
        _require_exact(value[key], wanted, f"{label}.{key}")


def _source_summary_bool(value: object, label: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value in {"True", "False"}:
        return value == "True"
    raise ValueError(f"source frontier {label} must be Boolean")


def _source_summary_integer(value: object, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"source frontier {label} must be an integer")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.isdigit():
        result = int(value)
    else:
        raise ValueError(f"source frontier {label} must be an integer")
    if result < 0:
        raise ValueError(f"source frontier {label} must be nonnegative")
    return result


def _source_summary_number(value: object, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"source frontier {label} must be numeric")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"source frontier {label} must be numeric") from error
    if not math.isfinite(result) or result < 0.0:
        raise ValueError(f"source frontier {label} must be finite and nonnegative")
    return result


def _normalize_source_selection_summary(row: dict[str, Any]) -> dict[str, Any]:
    configured = row["configured_spec"]
    if isinstance(configured, str):
        configured = json.loads(
            configured,
            object_pairs_hook=_reject_duplicate_json_pairs,
            parse_constant=_reject_nonfinite_json_constant,
        )
    if not isinstance(configured, dict) or not configured:
        raise ValueError("source frontier configured_spec must be a nonempty object")
    constructions = _source_summary_integer(
        row["independent_constructions"], "independent_constructions"
    )
    successes = _source_summary_integer(
        row["first_seen_false_positives_pooled"],
        "first_seen_false_positives_pooled",
    )
    trials = _source_summary_integer(row["first_seen_trials_pooled"], "first_seen_trials_pooled")
    mean = _source_summary_number(row["first_seen_ffr_mean"], "first_seen_ffr_mean")
    low = _source_summary_number(row["first_seen_ffr_ci_low"], "first_seen_ffr_ci_low")
    high = _source_summary_number(row["first_seen_ffr_ci_high"], "first_seen_ffr_ci_high")
    memory = _source_summary_number(
        row["memory_total_edge_bytes_mean"], "memory_total_edge_bytes_mean"
    )
    return {
        "method": str(row["method"]),
        "configured_spec": configured,
        "independent_constructions": constructions,
        "eligible_profile_U_all_seeds": _source_summary_bool(
            row["eligible_profile_U_all_seeds"], "eligible_profile_U_all_seeds"
        ),
        "eligible_profile_A_all_seeds": _source_summary_bool(
            row["eligible_profile_A_all_seeds"], "eligible_profile_A_all_seeds"
        ),
        "memory_total_edge_bytes_mean": memory,
        "first_seen_false_positives_pooled": successes,
        "first_seen_trials_pooled": trials,
        "first_seen_ffr_mean": mean,
        "first_seen_ffr_ci_method": str(row["first_seen_ffr_ci_method"]),
        "first_seen_ffr_ci_low": low,
        "first_seen_ffr_ci_high": high,
        "pareto_U_memory_ffr": _source_summary_bool(
            row["pareto_U_memory_ffr"], "pareto_U_memory_ffr"
        ),
        "pareto_A_memory_ffr": _source_summary_bool(
            row["pareto_A_memory_ffr"], "pareto_A_memory_ffr"
        ),
        "analytic_model_validation_status": str(row["analytic_model_validation_status"]),
        "analytic_model_agreement_claim_permitted": _source_summary_bool(
            row["analytic_model_agreement_claim_permitted"],
            "analytic_model_agreement_claim_permitted",
        ),
    }


def _recompute_source_aggregate_identity(
    summaries: Sequence[dict[str, Any]], audit: dict[str, Any]
) -> str:
    """Recompute the frozen semantic identity without importing SciPy analysis code."""

    normalized = sorted(
        (_normalize_source_selection_summary(row) for row in summaries),
        key=lambda row: (
            row["method"],
            json.dumps(row["configured_spec"], sort_keys=True, separators=(",", ":")),
        ),
    )
    material = {
        "schema": audit["phase1_aggregate_identity_schema"],
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
        "e1_bloom_query_path_reproduction_gate": audit["e1_bloom_query_path_reproduction_gate"],
        "e1_bloom_analytic_model_validation_status": audit[
            "e1_bloom_analytic_model_validation_status"
        ],
        "e1_bloom_analytic_unresolved_rows": int(audit["e1_bloom_analytic_unresolved_rows"]),
        "analytic_discrepancy_taxonomy_version": audit["analytic_discrepancy_taxonomy_version"],
        "machine_verified_discrepancies_by_code": audit["machine_verified_discrepancies_by_code"],
        "analytic_diagnostic_overlay_status": audit["analytic_diagnostic_overlay_status"],
        "analytic_diagnostic_integrity_status": audit["analytic_diagnostic_integrity_status"],
        "query_path_reproduction_status": audit["query_path_reproduction_status"],
        "query_path_reproduction_evidence_scope": audit["query_path_reproduction_evidence_scope"],
        "query_path_reproduction_scientific_pass_rule": audit[
            "query_path_reproduction_scientific_pass_rule"
        ],
        "analytic_diagnostic_source_commit": audit["analytic_diagnostic_source_commit"],
        "analytic_diagnostic_config_id": audit["analytic_diagnostic_config_id"],
        "analytic_diagnostic_family_size": audit["analytic_diagnostic_family_size"],
        "analytic_diagnostic_fwer_consistent_rows": audit[
            "analytic_diagnostic_fwer_consistent_rows"
        ],
        "analytic_diagnostic_fwer_inconsistent_rows": audit[
            "analytic_diagnostic_fwer_inconsistent_rows"
        ],
        "analytic_diagnostic_robust_overlap_rows": audit["analytic_diagnostic_robust_overlap_rows"],
        "analytic_diagnostic_robust_separation_rows": audit[
            "analytic_diagnostic_robust_separation_rows"
        ],
        "analytic_diagnostic_ambiguous_numeric_rows": audit[
            "analytic_diagnostic_ambiguous_numeric_rows"
        ],
        "analytic_diagnostic_numeric_contract": audit["analytic_diagnostic_numeric_contract"],
        "analytic_diagnostic_bias_direction_counts": audit[
            "analytic_diagnostic_bias_direction_counts"
        ],
        "analytic_diagnostic_consistency_rule": audit["analytic_diagnostic_consistency_rule"],
        "legacy_ideal_model_uncovered_rows": int(audit["legacy_ideal_model_uncovered_rows"]),
        "analytic_model_validation_status": audit["analytic_model_validation_status"],
        "analytic_model_agreement_claim_permitted": audit[
            "analytic_model_agreement_claim_permitted"
        ],
        "phase1_p0b_qualification_status": audit["phase1_p0b_qualification_status"],
        "analytic_interval_coverage_by_method": audit["analytic_interval_coverage_by_method"],
        "frontier_rule": audit["frontier_rule"],
        "selection_records": normalized,
    }
    return _canonical_hash(material)


def validate_source_evidence(
    config: dict[str, Any],
    frontier_audit_path: Path,
    frontier_summary_path: Path,
    diagnostic_aggregate_path: Path,
    v1_postrun_receipt_path: Path,
) -> str:
    """Validate semantic source pins without introducing ordinary file hashes."""

    source = config["source_evidence"]
    audit = _load_strict_json(frontier_audit_path)
    _require_fields(
        audit,
        {
            "status": "PASS",
            "phase1_evidence_status": "PASS",
            "phase1_cartesian_grid_status": "PASS",
            "commit": source["filter_grid_commit"],
            "semantic_config_id": source["filter_grid_semantic_config_id"],
            "semantic_dataset_id": source["filter_grid_semantic_dataset_id"],
            "clean_source_attestation_id": source["filter_grid_attestation_id"],
            "phase1_aggregate_identity_schema": source["filter_grid_aggregate_identity_schema"],
            "phase1_aggregate_identity": source["filter_grid_aggregate_identity"],
            "row_count": source["filter_grid_raw_row_count"],
            "shard_count": source["filter_grid_shard_count"],
            "summary_point_count": source["filter_grid_spec_count"],
            "member_false_negatives": 0,
        },
        "frontier audit",
    )
    expected_specs = {(_method_for_spec(spec), spec.identity) for spec in expand_specs(config)}
    observed_specs: set[tuple[str, str]] = set()
    source_summary_rows: list[dict[str, Any]] = []
    try:
        with frontier_summary_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)):
                raise ValueError("frontier summary has missing or duplicate headers")
            required = {
                "method",
                "configured_spec",
                "independent_constructions",
                "member_false_negatives",
                "first_seen_false_positives_pooled",
                "first_seen_trials_pooled",
                "memory_total_edge_bytes_mean",
            }
            if not required.issubset(reader.fieldnames):
                raise ValueError("frontier summary is missing v2 source fields")
            for row in reader:
                source_summary_rows.append(row)
                parameters = json.loads(
                    row["configured_spec"],
                    object_pairs_hook=_reject_duplicate_json_pairs,
                    parse_constant=_reject_nonfinite_json_constant,
                )
                if not isinstance(parameters, dict):
                    raise ValueError("frontier configured_spec must be an object")
                method = row["method"]
                family = (
                    "tag"
                    if method == "exact_tag_128" or method.startswith("truncated_tag_")
                    else {
                        "global_bloom": "global_bloom",
                        "blocked_bloom_64b": "blocked_bloom",
                        "xor_static_3way": "xor_static",
                        "cuckoo_filter": "cuckoo",
                    }.get(method)
                )
                if family is None:
                    raise ValueError(f"unknown source frontier method: {method}")
                spec = FilterSpec(family, parameters)
                identity = (method, spec.identity)
                if identity in observed_specs:
                    raise ValueError("frontier summary has a duplicate spec")
                observed_specs.add(identity)
                constructions = int(row["independent_constructions"])
                expected_constructions = 1 if family == "tag" else 10
                if constructions != expected_constructions:
                    raise ValueError("frontier summary construction count mismatch")
                if int(row["member_false_negatives"]) != 0:
                    raise ValueError("frontier summary contains a member false negative")
                trials = int(row["first_seen_trials_pooled"])
                expected_trials = 10_000_000 if family == "tag" else 100_000_000
                successes = int(row["first_seen_false_positives_pooled"])
                if trials != expected_trials or not 0 <= successes <= trials:
                    raise ValueError("frontier summary FFR integer counts are invalid")
                memory = float(row["memory_total_edge_bytes_mean"])
                if not math.isfinite(memory) or memory <= 0.0 or not memory.is_integer():
                    raise ValueError("frontier summary memory must be a finite integer")
    except (OSError, UnicodeError, csv.Error, json.JSONDecodeError) as error:
        raise ValueError("cannot load the source frontier summary") from error
    if observed_specs != expected_specs:
        raise ValueError("frontier summary does not contain the exact 794-spec universe")
    recomputed_source_identity = _recompute_source_aggregate_identity(source_summary_rows, audit)
    if recomputed_source_identity != source["filter_grid_aggregate_identity"]:
        raise ValueError("source frontier aggregate identity does not recompute")

    diagnostic = _load_strict_json(diagnostic_aggregate_path)
    _require_fields(
        diagnostic,
        {
            "schema_version": source["diagnostic_schema_version"],
            "diagnostic_protocol": source["diagnostic_protocol"],
            "diagnostic_source_commit": source["diagnostic_source_commit"],
            "diagnostic_config_id": source["diagnostic_config_id"],
            "semantic_config_id": source["filter_grid_semantic_config_id"],
            "semantic_dataset_id": source["filter_grid_semantic_dataset_id"],
            "target_clean_source_attestation_id": source["diagnostic_target_attestation_id"],
            "target_source_commit": source["filter_grid_commit"],
        },
        "diagnostic aggregate",
    )
    diagnostic_rows = diagnostic.get("diagnostic_rows")
    if (
        not isinstance(diagnostic_rows, list)
        or len(diagnostic_rows) != source["diagnostic_family_size"]
    ):
        raise ValueError("diagnostic aggregate row count mismatch")
    diagnostic_audit = diagnostic.get("audit")
    if not isinstance(diagnostic_audit, dict):
        raise ValueError("diagnostic aggregate audit is missing")
    _require_fields(
        diagnostic_audit,
        {
            "status": "PASS",
            "integrity_status": "PASS",
            "observed_rows": source["diagnostic_family_size"],
            "robust_overlap_rows": source["diagnostic_robust_overlap_count"],
            "robust_separation_rows": source["diagnostic_robust_separation_count"],
            "ambiguous_numeric_rows": source["diagnostic_ambiguous_count"],
        },
        "diagnostic aggregate audit",
    )

    v1_receipt = _load_strict_json(v1_postrun_receipt_path)
    _require_fields(
        v1_receipt,
        {
            "schema": "traps-phase1-filter-timing-postrun-gate-v1",
            "validation_status": "VALID",
            "timing_claim_gate": source["immutable_v1_timing_claim_gate"],
            "scientific_gate_passed": False,
            "promotion_eligible": False,
        },
        "v1 postrun receipt",
    )
    bindings = v1_receipt.get("bindings")
    counts = v1_receipt.get("counts")
    relation_gate = v1_receipt.get("relation_gate")
    if not all(isinstance(value, dict) for value in (bindings, counts, relation_gate)):
        raise ValueError("v1 postrun receipt ledgers are missing")
    _require_fields(
        bindings,
        {
            "candidate_set_id": source["immutable_v1_candidate_set_id"],
            "phase1_aggregate_identity": source["filter_grid_aggregate_identity"],
            "phase1_aggregate_source_commit": source["filter_grid_commit"],
            "raw_observation_set_sha256": source["immutable_v1_raw_observation_set_sha256"],
            "semantic_config_id": source["immutable_v1_timing_semantic_config_id"],
            "semantic_dataset_id": source["filter_grid_semantic_dataset_id"],
            "timing_source_commit": source["immutable_v1_timing_commit"],
        },
        "v1 postrun bindings",
    )
    _require_fields(counts, {"relations": 28, "rows": 480, "trial_seeds": 20}, "v1 counts")
    _require_fields(
        relation_gate,
        {
            "relation_count": source["immutable_v1_relation_count"],
            "paired_seed_count": 20,
            "noninferiority_ratio_margin": 1.05,
            "decision_counts": {
                "PASS_NONINFERIOR": source["immutable_v1_pass_count"],
                "FAIL_POINT_ESTIMATE_EXCEEDS_MARGIN": source["immutable_v1_fail_count"],
                "INDETERMINATE_NONINFERIORITY_NOT_ESTABLISHED": source[
                    "immutable_v1_indeterminate_count"
                ],
            },
        },
        "v1 relation gate",
    )
    return _canonical_hash({"schema": "phase1-v2-source-evidence-binding-v1", "pins": source})


def _base_order(specs: Sequence[FilterSpec], config_id: str) -> tuple[FilterSpec, ...]:
    def ordering_key(spec: FilterSpec) -> tuple[bytes, str]:
        material = f"{PROTOCOL}:{config_id}:{spec.identity}".encode()
        return hashlib.sha256(material).digest(), spec.identity

    return tuple(sorted(specs, key=ordering_key))


def plan_stage(
    config: dict[str, Any],
    config_id: str,
    stage: str,
    shard_index: int,
    shard_count: int,
) -> StagePlan:
    if stage not in STAGES:
        raise ValueError(f"stage must be one of {STAGES}")
    expected_count = COLD_SHARD_COUNT if stage == "cold" else WARM_SHARD_COUNT
    if shard_count != expected_count or not 0 <= shard_index < shard_count:
        raise ValueError(
            f"{stage} requires shard_index in [0,{expected_count}) and shard_count={expected_count}"
        )
    base = _base_order(expand_specs(config), config_id)
    if stage == "cold":
        start = len(base) * shard_index // shard_count
        end = len(base) * (shard_index + 1) // shard_count
        return StagePlan(stage, COLD_SEED, None, base[start:end], shard_index, shard_count)
    seeds = LOOK1_SEEDS if stage == "warm-look1" else LOOK2_SEEDS
    global_ordinal = shard_index if stage == "warm-look1" else len(LOOK1_SEEDS) + shard_index
    shift = global_ordinal * ROTATION_STRIDE % len(base)
    ordered = base[shift:] + base[:shift]
    return StagePlan(
        stage,
        seeds[shard_index],
        global_ordinal,
        ordered,
        shard_index,
        shard_count,
    )


def path_measurement_order(global_seed_ordinal: int) -> tuple[str, str]:
    if global_seed_ordinal % 2 == 0:
        return "actual_front", "query_only"
    return "query_only", "actual_front"


def _summary_us(latencies_ns: Sequence[int]) -> dict[str, float]:
    if not latencies_ns:
        raise ValueError("latency sample is empty")
    values = [value / 1000.0 for value in latencies_ns]
    return {
        "p50": float(_percentile(values, 0.50)),
        "p95": float(_percentile(values, 0.95)),
        "p99": float(_percentile(values, 0.99)),
    }


def timing_clock_record(sample_count: int) -> dict[str, Any]:
    """Measure the clock metadata and frozen back-to-back call overhead sample."""

    if sample_count <= 0:
        raise ValueError("clock-call sample count must be positive")
    info = time.get_clock_info("perf_counter")
    if not info.monotonic:
        raise RuntimeError("formal timing requires a monotonic perf_counter clock")
    latencies: list[int] = []
    for _ in range(sample_count):
        started = time.perf_counter_ns()
        finished = time.perf_counter_ns()
        latencies.append(finished - started)
    summary = _summary_us(latencies)
    overhead_p99_ns = summary["p99"] * 1000.0
    if overhead_p99_ns <= 0.0:
        raise RuntimeError("clock-call p99 must be positive")
    return {
        "api": "time.perf_counter_ns",
        "implementation": info.implementation,
        "monotonic": info.monotonic,
        "adjustable": info.adjustable,
        "resolution_seconds": info.resolution,
        "resolution_ns": info.resolution * 1_000_000_000.0,
        "call_pattern": "one_call_immediately_before_and_after_each_timed_query",
        "overhead_measurement": "back_to_back_perf_counter_ns_delta",
        "overhead_sample_count": sample_count,
        "overhead_histogram_ns": _latency_histogram(latencies),
        "overhead_p50_ns": summary["p50"] * 1000.0,
        "overhead_p95_ns": summary["p95"] * 1000.0,
        "overhead_p99_ns": overhead_p99_ns,
    }


def _latency_histogram(latencies_ns: Sequence[int]) -> list[dict[str, int]]:
    counts = Counter(latencies_ns)
    return [{"latency_ns": latency, "count": counts[latency]} for latency in sorted(counts)]


def _query_only_latencies(filter_object: Any, queries: Sequence[ScreenQuery]) -> list[int]:
    latencies: list[int] = []
    for query in queries:
        started = time.perf_counter_ns()
        filter_object.query(query)
        latencies.append(time.perf_counter_ns() - started)
    return latencies


def _actual_front_latencies(
    path: CanonicalPrescreenPath, attempts: Sequence[LoginAttempt]
) -> list[int]:
    latencies: list[int] = []
    for attempt in attempts:
        started = time.perf_counter_ns()
        path.query(attempt)
        latencies.append(time.perf_counter_ns() - started)
    return latencies


def _actual_front_throughput_trials(
    path: CanonicalPrescreenPath,
    attempts: Sequence[LoginAttempt],
    repetitions: int,
) -> list[float]:
    trials: list[float] = []
    for _ in range(repetitions):
        started = time.perf_counter_ns()
        for attempt in attempts:
            path.query(attempt)
        elapsed_ns = time.perf_counter_ns() - started
        trials.append(len(attempts) / (elapsed_ns / 1_000_000_000.0))
    return trials


def _require_zero_member_false_negatives(
    filter_object: Any, members: Sequence[ScreenQuery]
) -> None:
    for ordinal, member in enumerate(members):
        if not filter_object.query(member).positive:
            raise RuntimeError(f"member false negative at member ordinal {ordinal}")


def _cold_query_only_latencies(
    filter_object: Any,
    queries: Sequence[ScreenQuery],
    eviction: bytearray,
) -> tuple[list[int], int]:
    token = 0
    latencies: list[int] = []
    for query in queries:
        token = zlib.crc32(eviction, token)
        started = time.perf_counter_ns()
        filter_object.query(query)
        latencies.append(time.perf_counter_ns() - started)
    return latencies, token


def _method_for_spec(spec: FilterSpec) -> str:
    if spec.family == "tag":
        width = int(spec.parameters["tag_bits"])
        return "exact_tag_128" if width == 128 else f"truncated_tag_{width}"
    return {
        "global_bloom": "global_bloom",
        "blocked_bloom": "blocked_bloom_64b",
        "xor_static": "xor_static_3way",
        "cuckoo": "cuckoo_filter",
    }[spec.family]


def _credential_from_legacy_formula(
    dataset: SyntheticCredentialSet, invalid_index: int
) -> CredentialInput:
    account_index = (
        invalid_index * 0x9E3779B97F4A7C15 + dataset.dataset_seed
    ) % dataset.account_count
    return CredentialInput(
        account_index=account_index,
        account_id=b"acct-v1:" + account_index.to_bytes(8, "big"),
        account_generation=1,
        credential_set_version=1,
        password=b"invalid-v1:" + invalid_index.to_bytes(8, "big"),
        salt=dataset.dataset_seed.to_bytes(8, "big") + account_index.to_bytes(8, "big"),
    )


def _member_credential_from_legacy_formula(
    dataset: SyntheticCredentialSet, account_index: int
) -> CredentialInput:
    """Reconstruct one member without calling any newly added corpus helper."""

    return CredentialInput(
        account_index=account_index,
        account_id=b"acct-v1:" + account_index.to_bytes(8, "big"),
        account_generation=1,
        credential_set_version=1,
        password=b"valid-v1:" + account_index.to_bytes(8, "big"),
        salt=dataset.dataset_seed.to_bytes(8, "big") + account_index.to_bytes(8, "big"),
    )


def verify_bit_identical_corpus_api(
    dataset: SyntheticCredentialSet,
    member_count: int,
    nonmember_count: int,
    progress: bool = False,
) -> list[ScreenQuery]:
    """Exhaustively compare every public corpus item with the frozen formula."""

    members: list[ScreenQuery] = []
    for account_index in range(member_count):
        attempt = dataset.member_attempt(account_index)
        public_credential = dataset.credential_for_attempt(
            attempt, dataset.directory_record(account_index)
        )
        legacy_credential = _member_credential_from_legacy_formula(dataset, account_index)
        if public_credential != legacy_credential:
            raise RuntimeError(f"public member credential differs at account {account_index}")
        public_query = dataset.codec.token(public_credential)
        legacy_query = dataset.codec.token(legacy_credential)
        if public_query != legacy_query:
            raise RuntimeError(f"public member token differs at account {account_index}")
        members.append(legacy_query)
    for invalid_index in range(nonmember_count):
        attempt = dataset.nonmember_attempt(invalid_index)
        public_credential = dataset.credential_for_attempt(
            attempt, dataset.directory_record(attempt.account_index)
        )
        legacy_credential = _credential_from_legacy_formula(dataset, invalid_index)
        if public_credential != legacy_credential:
            raise RuntimeError(
                f"public nonmember credential differs at invalid index {invalid_index}"
            )
        if dataset.codec.token(public_credential) != dataset.codec.token(legacy_credential):
            raise RuntimeError(f"public nonmember token differs at invalid index {invalid_index}")
        if progress and (invalid_index + 1) % 1_000_000 == 0:
            print(
                f"corpus equivalence: checked {invalid_index + 1}/{nonmember_count} nonmembers",
                file=sys.stderr,
                flush=True,
            )
    return members


def _corpus_receipt_material(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in receipt.items() if key not in {"created_at_utc", "receipt_id"}
    }


def create_corpus_equivalence_receipt(
    config: dict[str, Any],
    config_id: str,
    source_commit: str,
    source_evidence_binding_id: str,
    output: Path,
    progress: bool = False,
) -> dict[str, Any]:
    dataset = SyntheticCredentialSet(ACCOUNT_COUNT, DATASET_SEED)
    members = verify_bit_identical_corpus_api(
        dataset,
        ACCOUNT_COUNT,
        NONMEMBER_COUNT,
        progress=progress,
    )
    dataset_id = dataset.manifest_hash(members, NONMEMBER_COUNT)
    if dataset_id != TIMING_DATASET_ID:
        raise RuntimeError("exhaustive corpus preflight dataset ID changed")
    receipt: dict[str, Any] = {
        "schema": config["corpus_equivalence"]["receipt_schema"],
        "receipt_id_schema": config["corpus_equivalence"]["receipt_id_schema"],
        "status": "PASS_BIT_IDENTICAL_FULL_CORPUS",
        "protocol": PROTOCOL,
        "source_commit": source_commit,
        "semantic_config_id": config_id,
        "semantic_dataset_id": dataset_id,
        "source_evidence_binding_id": source_evidence_binding_id,
        "generator": config["dataset"]["generator"],
        "dataset_seed": DATASET_SEED,
        "member_count_checked": ACCOUNT_COUNT,
        "nonmember_count_checked": NONMEMBER_COUNT,
        "member_mismatch_count": 0,
        "nonmember_mismatch_count": 0,
        "verification": config["corpus_equivalence"]["verification"],
    }
    receipt["receipt_id"] = _canonical_hash(_corpus_receipt_material(receipt))
    receipt["created_at_utc"] = datetime.now(timezone.utc).isoformat()
    atomic_write_jsonl_no_overwrite(
        output,
        [receipt],
        before_publish=lambda: _verify_source_pin(source_commit),
        expected_count=1,
    )
    return receipt


def validate_corpus_equivalence_receipt(
    config: dict[str, Any],
    config_id: str,
    source_commit: str,
    source_evidence_binding_id: str,
    path: Path,
    expected_receipt_id: str,
) -> dict[str, Any]:
    if SEMANTIC_ID_PATTERN.fullmatch(expected_receipt_id) is None:
        raise ValueError("expected corpus equivalence ID must be 64 lowercase hex digits")
    receipt = _load_strict_json(path)
    expected_keys = {
        "schema",
        "receipt_id_schema",
        "status",
        "protocol",
        "source_commit",
        "semantic_config_id",
        "semantic_dataset_id",
        "source_evidence_binding_id",
        "generator",
        "dataset_seed",
        "member_count_checked",
        "nonmember_count_checked",
        "member_mismatch_count",
        "nonmember_mismatch_count",
        "verification",
        "receipt_id",
        "created_at_utc",
    }
    if set(receipt) != expected_keys:
        raise ValueError("corpus equivalence receipt has unexpected or missing keys")
    _require_fields(
        receipt,
        {
            "schema": config["corpus_equivalence"]["receipt_schema"],
            "receipt_id_schema": config["corpus_equivalence"]["receipt_id_schema"],
            "status": "PASS_BIT_IDENTICAL_FULL_CORPUS",
            "protocol": PROTOCOL,
            "source_commit": source_commit,
            "semantic_config_id": config_id,
            "semantic_dataset_id": TIMING_DATASET_ID,
            "source_evidence_binding_id": source_evidence_binding_id,
            "generator": config["dataset"]["generator"],
            "dataset_seed": DATASET_SEED,
            "member_count_checked": ACCOUNT_COUNT,
            "nonmember_count_checked": NONMEMBER_COUNT,
            "member_mismatch_count": 0,
            "nonmember_mismatch_count": 0,
            "verification": config["corpus_equivalence"]["verification"],
            "receipt_id": expected_receipt_id,
        },
        "corpus equivalence receipt",
    )
    if not isinstance(receipt.get("created_at_utc"), str):
        raise ValueError("corpus equivalence receipt timestamp is invalid")
    recomputed = _canonical_hash(_corpus_receipt_material(receipt))
    if recomputed != expected_receipt_id:
        raise ValueError("corpus equivalence receipt ID does not recompute")
    return receipt


def _construction_receipt_material(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in receipt.items() if key not in {"created_at_utc", "receipt_id"}
    }


def create_construction_feasibility_receipt(
    config: dict[str, Any],
    config_id: str,
    source_commit: str,
    source_evidence_binding_id: str,
    corpus_receipt: dict[str, Any],
    output: Path,
    progress: bool = False,
) -> dict[str, Any]:
    dataset = SyntheticCredentialSet(ACCOUNT_COUNT, DATASET_SEED)
    members = [dataset.member(index) for index in range(ACCOUNT_COUNT)]
    dataset_id = dataset.manifest_hash(members, NONMEMBER_COUNT)
    if dataset_id != TIMING_DATASET_ID or dataset_id != corpus_receipt["semantic_dataset_id"]:
        raise RuntimeError("construction preflight dataset differs from corpus receipt")
    specs = tuple(spec for spec in expand_specs(config) if spec.family in {"xor_static", "cuckoo"})
    seeds = LOOK1_SEEDS + LOOK2_SEEDS + (COLD_SEED,)
    if len(specs) != 18 or len(seeds) != 41:
        raise AssertionError("frozen construction preflight cardinality changed")
    builds: list[dict[str, Any]] = []
    for seed_ordinal, seed in enumerate(seeds):
        for spec_ordinal, spec in enumerate(specs):
            filter_object = build_filter(spec, members, seed)
            _require_zero_member_false_negatives(filter_object, members)
            memory = filter_object.memory_report()
            builds.append(
                {
                    "seed_ordinal": seed_ordinal,
                    "seed": seed,
                    "spec_ordinal": spec_ordinal,
                    "family": spec.family,
                    "configured_spec": spec.parameters,
                    "spec_identity": spec.identity,
                    "spec_id": hashlib.sha256(spec.identity.encode()).hexdigest(),
                    "filter_parameters": filter_object.parameters(),
                    "member_validation_count": ACCOUNT_COUNT,
                    "member_false_negatives": 0,
                    "memory_payload_bytes": memory.payload_bytes,
                    "memory_metadata_bytes": memory.metadata_bytes,
                    "memory_alignment_bytes": memory.alignment_bytes,
                    "memory_compact_total_bytes": memory.total_bytes,
                }
            )
        if progress:
            print(
                f"construction feasibility: checked {seed_ordinal + 1}/{len(seeds)} seeds",
                file=sys.stderr,
                flush=True,
            )
    receipt: dict[str, Any] = {
        "schema": config["construction_feasibility"]["receipt_schema"],
        "receipt_id_schema": config["construction_feasibility"]["receipt_id_schema"],
        "status": "PASS_ALL_FROZEN_CONSTRUCTIONS_BUILD",
        "protocol": PROTOCOL,
        "source_commit": source_commit,
        "semantic_config_id": config_id,
        "semantic_dataset_id": dataset_id,
        "source_evidence_binding_id": source_evidence_binding_id,
        "corpus_equivalence_receipt_id": corpus_receipt["receipt_id"],
        "families": config["construction_feasibility"]["families"],
        "spec_count": len(specs),
        "seed_count": len(seeds),
        "build_count": len(builds),
        "failure_count": 0,
        "builds": builds,
    }
    receipt["receipt_id"] = _canonical_hash(_construction_receipt_material(receipt))
    receipt["created_at_utc"] = datetime.now(timezone.utc).isoformat()
    atomic_write_jsonl_no_overwrite(
        output,
        [receipt],
        before_publish=lambda: _verify_source_pin(source_commit),
        expected_count=1,
    )
    return receipt


def validate_construction_feasibility_receipt(
    config: dict[str, Any],
    config_id: str,
    source_commit: str,
    source_evidence_binding_id: str,
    corpus_receipt_id: str,
    corpus_semantic_dataset_id: str,
    path: Path,
    expected_receipt_id: str,
) -> dict[str, Any]:
    if SEMANTIC_ID_PATTERN.fullmatch(expected_receipt_id) is None:
        raise ValueError("expected construction feasibility ID must be 64 lowercase hex digits")
    receipt = _load_strict_json(path)
    expected_keys = {
        "schema",
        "receipt_id_schema",
        "status",
        "protocol",
        "source_commit",
        "semantic_config_id",
        "semantic_dataset_id",
        "source_evidence_binding_id",
        "corpus_equivalence_receipt_id",
        "families",
        "spec_count",
        "seed_count",
        "build_count",
        "failure_count",
        "builds",
        "receipt_id",
        "created_at_utc",
    }
    if set(receipt) != expected_keys:
        raise ValueError("construction feasibility receipt has unexpected or missing keys")
    _require_fields(
        receipt,
        {
            "schema": config["construction_feasibility"]["receipt_schema"],
            "receipt_id_schema": config["construction_feasibility"]["receipt_id_schema"],
            "status": "PASS_ALL_FROZEN_CONSTRUCTIONS_BUILD",
            "protocol": PROTOCOL,
            "source_commit": source_commit,
            "semantic_config_id": config_id,
            "source_evidence_binding_id": source_evidence_binding_id,
            "corpus_equivalence_receipt_id": corpus_receipt_id,
            "semantic_dataset_id": corpus_semantic_dataset_id,
            "families": config["construction_feasibility"]["families"],
            "spec_count": 18,
            "seed_count": 41,
            "build_count": 738,
            "failure_count": 0,
            "receipt_id": expected_receipt_id,
        },
        "construction feasibility receipt",
    )
    if not isinstance(receipt.get("created_at_utc"), str):
        raise ValueError("construction feasibility receipt timestamp is invalid")
    builds = receipt.get("builds")
    if not isinstance(builds, list) or len(builds) != 738:
        raise ValueError("construction feasibility build ledger is incomplete")
    expected_build_keys = {
        "seed_ordinal",
        "seed",
        "spec_ordinal",
        "family",
        "configured_spec",
        "spec_identity",
        "spec_id",
        "filter_parameters",
        "member_validation_count",
        "member_false_negatives",
        "memory_payload_bytes",
        "memory_metadata_bytes",
        "memory_alignment_bytes",
        "memory_compact_total_bytes",
    }
    ordered_specs = tuple(
        spec for spec in expand_specs(config) if spec.family in {"xor_static", "cuckoo"}
    )
    spec_by_identity = {
        spec.identity: (ordinal, spec) for ordinal, spec in enumerate(ordered_specs)
    }
    seeds = LOOK1_SEEDS + LOOK2_SEEDS + (COLD_SEED,)
    combinations: set[tuple[int, str]] = set()
    for row in builds:
        if not isinstance(row, dict) or set(row) != expected_build_keys:
            raise ValueError("construction feasibility build row schema changed")
        identity = row["spec_identity"]
        if not isinstance(identity, str) or identity not in spec_by_identity:
            raise ValueError("construction feasibility build spec is invalid")
        spec_ordinal, spec = spec_by_identity[identity]
        seed = row["seed"]
        if type(seed) is not int or seed not in seeds:
            raise ValueError("construction feasibility seed is invalid")
        if (
            row["seed_ordinal"] != seeds.index(seed)
            or row["spec_ordinal"] != spec_ordinal
            or row["family"] != spec.family
            or row["configured_spec"] != spec.parameters
            or row["spec_id"] != hashlib.sha256(identity.encode()).hexdigest()
            or not isinstance(row["filter_parameters"], dict)
            or row["member_validation_count"] != ACCOUNT_COUNT
            or row["member_false_negatives"] != 0
        ):
            raise ValueError("construction feasibility build binding changed")
        memory_fields = (
            "memory_payload_bytes",
            "memory_metadata_bytes",
            "memory_alignment_bytes",
            "memory_compact_total_bytes",
        )
        if any(type(row[field]) is not int or row[field] < 0 for field in memory_fields):
            raise ValueError("construction feasibility memory fields are invalid")
        if row["memory_compact_total_bytes"] != sum(row[field] for field in memory_fields[:3]):
            raise ValueError("construction feasibility memory total does not recompute")
        combinations.add((seed, identity))
    expected_combinations = {(seed, identity) for seed in seeds for identity in spec_by_identity}
    if combinations != expected_combinations:
        raise ValueError("construction feasibility build ledger changed")
    recomputed = _canonical_hash(_construction_receipt_material(receipt))
    if recomputed != expected_receipt_id:
        raise ValueError("construction feasibility receipt ID does not recompute")
    return receipt


def _look1_decision_material(receipt: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value for key, value in receipt.items() if key not in {"created_at_utc", "receipt_id"}
    }


def validate_look1_extension_decision(
    config: dict[str, Any],
    config_id: str,
    source_commit: str,
    source_evidence_binding_id: str,
    corpus_equivalence_receipt_id: str,
    construction_feasibility_receipt_id: str,
    path: Path,
    expected_receipt_id: str,
    require_look2: bool = False,
) -> dict[str, Any]:
    if SEMANTIC_ID_PATTERN.fullmatch(expected_receipt_id) is None:
        raise ValueError("expected look1 decision ID must be 64 lowercase hex digits")
    receipt = _load_strict_json(path)
    if receipt.get("receipt_id") != expected_receipt_id:
        raise ValueError("look1 decision receipt does not match expected look1 decision ID")
    expected_keys = {
        "schema",
        "receipt_id_schema",
        "validation_status",
        "protocol",
        "semantic_config_id",
        "source_commit",
        "analysis_source_commit",
        "analysis_source_clean",
        "analysis_source_status_scope",
        "source_evidence_binding_id",
        "corpus_equivalence_receipt_id",
        "construction_feasibility_receipt_id",
        "look1_shard_count",
        "look1_row_count",
        "look1_spec_count",
        "look1_seed_count",
        "precision_gate_pass",
        "timer_resolution_gate_pass",
        "single_hardware_stratum_gate_pass",
        "max_primary_log_half_width",
        "max_primary_relative_half_width",
        "decision",
        "decision_rule",
        "look1_observation_set_id",
        "receipt_id",
        "created_at_utc",
    }
    if set(receipt) != expected_keys:
        raise ValueError("look1 extension decision has unexpected or missing keys")
    _require_fields(
        receipt,
        {
            "schema": config["warm"]["look1_extension_decision_receipt_schema"],
            "receipt_id_schema": config["warm"]["look1_extension_decision_id_schema"],
            "protocol": PROTOCOL,
            "semantic_config_id": config_id,
            "source_commit": source_commit,
            "analysis_source_commit": source_commit,
            "analysis_source_clean": True,
            "analysis_source_status_scope": ("repository excluding experiments/outputs/**"),
            "source_evidence_binding_id": source_evidence_binding_id,
            "corpus_equivalence_receipt_id": corpus_equivalence_receipt_id,
            "construction_feasibility_receipt_id": (construction_feasibility_receipt_id),
            "receipt_id": expected_receipt_id,
            "look1_shard_count": 20,
            "look1_row_count": 20 * PHASE1_SPEC_COUNT,
            "look1_spec_count": PHASE1_SPEC_COUNT,
            "look1_seed_count": 20,
            "decision_rule": config["warm"]["look1_decision_rule"],
        },
        "look1 extension decision",
    )
    for key in ("look1_observation_set_id", "receipt_id"):
        value = receipt[key]
        if not isinstance(value, str) or SEMANTIC_ID_PATTERN.fullmatch(value) is None:
            raise ValueError(f"look1 extension decision {key} is invalid")
    if not isinstance(receipt["created_at_utc"], str):
        raise ValueError("look1 extension decision timestamp is invalid")
    for key in (
        "precision_gate_pass",
        "timer_resolution_gate_pass",
        "single_hardware_stratum_gate_pass",
    ):
        if type(receipt[key]) is not bool:
            raise ValueError(f"look1 extension decision {key} must be Boolean")
    maximum_log_half_width = receipt["max_primary_log_half_width"]
    maximum_half_width = receipt["max_primary_relative_half_width"]
    if (
        type(maximum_log_half_width) is not float
        or not math.isfinite(maximum_log_half_width)
        or maximum_log_half_width < 0.0
    ):
        raise ValueError("look1 extension decision log half-width is invalid")
    if (
        type(maximum_half_width) is not float
        or not math.isfinite(maximum_half_width)
        or maximum_half_width < 0.0
    ):
        raise ValueError("look1 extension decision precision width is invalid")
    _require_exact(
        maximum_half_width,
        math.expm1(maximum_log_half_width),
        "look1 extension decision relative half-width",
    )
    precision_pass = maximum_log_half_width <= math.log1p(
        float(config["warm"]["precision_relative_half_width_max"])
    )
    if receipt["precision_gate_pass"] is not precision_pass:
        raise ValueError("look1 precision gate disagrees with its maximum half-width")
    timer_pass = receipt["timer_resolution_gate_pass"]
    stratum_pass = receipt["single_hardware_stratum_gate_pass"]
    if not stratum_pass:
        expected_decision = "STOP_NONPROMOTABLE_HARDWARE_STRATUM"
        expected_validation = "VALID_BUT_NONPROMOTABLE"
    elif not timer_pass:
        expected_decision = "STOP_NONPROMOTABLE_TIMER_RESOLUTION"
        expected_validation = "VALID_BUT_NONPROMOTABLE"
    elif precision_pass:
        expected_decision = "PASS_STOP_N20"
        expected_validation = "VALID"
    else:
        expected_decision = "REQUIRE_FULL_LOOK2"
        expected_validation = "VALID"
    if (
        receipt["decision"] != expected_decision
        or receipt["validation_status"] != expected_validation
    ):
        raise ValueError("look1 decision state disagrees with its frozen gates")
    if require_look2 and expected_decision != "REQUIRE_FULL_LOOK2":
        raise ValueError("look1 decision does not authorize warm-look2")
    if _canonical_hash(_look1_decision_material(receipt)) != receipt["receipt_id"]:
        raise ValueError("look1 extension decision receipt ID does not recompute")
    return receipt


def _warm_inputs(
    dataset: SyntheticCredentialSet, global_seed_ordinal: int, warm: dict[str, Any]
) -> WarmInputs:
    start = global_seed_ordinal * int(warm["query_window_stride"])
    pool_count = int(warm["query_pool_count"])
    actual_count = int(warm["actual_front_latency_query_count"])
    query_only_count = int(warm["query_only_latency_query_count"])
    pool_attempts = tuple(
        dataset.nonmember_attempt(start + ordinal) for ordinal in range(pool_count)
    )
    pool_queries = tuple(
        dataset.codec.token(dataset.credential_for_attempt(attempt)) for attempt in pool_attempts
    )
    cursor = start + pool_count
    actual_attempts = tuple(
        dataset.nonmember_attempt(cursor + ordinal) for ordinal in range(actual_count)
    )
    cursor += actual_count
    query_only_queries = tuple(
        dataset.nonmember(cursor + ordinal) for ordinal in range(query_only_count)
    )
    cursor += query_only_count
    return WarmInputs(
        start,
        cursor,
        pool_attempts,
        pool_queries,
        actual_attempts,
        query_only_queries,
    )


def _common_row(
    config: dict[str, Any],
    config_id: str,
    dataset_id: str,
    source_commit: str,
    environment: dict[str, Any],
    plan: StagePlan,
    spec: FilterSpec,
    measurement_order: int,
    filter_object: Any,
    build_ns: int,
) -> dict[str, Any]:
    memory = filter_object.memory_report()
    finite_fpr, standard_fpr = _analytic_fprs(filter_object)
    is_tag = spec.family == "tag"
    run_material = (
        f"{source_commit}:{config_id}:{dataset_id}:{plan.stage}:{plan.trial_seed}:"
        f"{spec.identity}:{measurement_order}:{plan.shard_index}:{plan.shard_count}"
    )
    return {
        "schema": ROW_SCHEMA,
        "run_id": hashlib.sha256(run_material.encode()).hexdigest()[:24],
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "protocol": PROTOCOL,
        "formal_timing": True,
        "result_status": "FORMAL_RAW_OBSERVATION",
        "source_commit": source_commit,
        "expected_source_commit": source_commit,
        "git_dirty": False,
        "source_status_scope": "repository excluding experiments/outputs/**",
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
        "source_ffr_randomized_construction_count": 10,
        "source_ffr_static_tag_construction_count": 1,
        "source_ffr_randomized_interval": config["source_evidence"][
            "randomized_first_seen_interval"
        ],
        "source_ffr_static_tag_interval": config["source_evidence"][
            "static_tag_first_seen_interval"
        ],
        "source_evidence_binding_id": environment["source_evidence_binding_id"],
        "corpus_equivalence_receipt_id": environment["corpus_equivalence_receipt_id"],
        "construction_feasibility_receipt_id": environment["construction_feasibility_receipt_id"],
        "construction_feasibility_status": environment["construction_feasibility_status"],
        "construction_feasibility_build_count": environment["construction_feasibility_build_count"],
        "look1_extension_decision_receipt_id": environment["look1_extension_decision_receipt_id"],
        "expected_look1_extension_decision_id": environment["expected_look1_extension_decision_id"],
        "corpus_public_api_equivalence": "PASS_BIT_IDENTICAL_FULL_CORPUS",
        "stage": plan.stage,
        "measurement_trial_seed": plan.trial_seed,
        "construction_seed": None if is_tag else plan.trial_seed,
        "global_seed_ordinal": plan.global_seed_ordinal,
        "measurement_order": measurement_order,
        "shard_index": plan.shard_index,
        "shard_count": plan.shard_count,
        "method": _method_for_spec(spec),
        "family": spec.family,
        "spec_identity": spec.identity,
        "spec_id": hashlib.sha256(spec.identity.encode()).hexdigest(),
        "spec_universe_count": PHASE1_SPEC_COUNT,
        "configured_spec": spec.parameters,
        "filter_parameters": filter_object.parameters(),
        "randomized_construction": not is_tag,
        "account_count": ACCOUNT_COUNT,
        "build_time_s": build_ns / 1_000_000_000.0,
        "memory_payload_bytes": memory.payload_bytes,
        "memory_metadata_bytes": memory.metadata_bytes,
        "memory_alignment_bytes": memory.alignment_bytes,
        "memory_compact_total_bytes": memory.total_bytes,
        "memory_filter_bytes": 0 if is_tag else memory.total_bytes,
        "memory_directory_extra_bytes": memory.total_bytes if is_tag else 0,
        "memory_common_prf_key_bytes": 32,
        "memory_total_edge_bytes": memory.total_bytes + 32,
        "analytic_fpr_finite": finite_fpr,
        "analytic_fpr_standard": standard_fpr,
        "timing_clock": environment["timing_clock"],
        "host_environment": environment,
    }


def _warm_row(
    config: dict[str, Any],
    config_id: str,
    dataset_id: str,
    source_commit: str,
    environment: dict[str, Any],
    dataset: SyntheticCredentialSet,
    directory: Sequence[DirectoryRecord],
    members: list[ScreenQuery],
    inputs: WarmInputs,
    plan: StagePlan,
    spec: FilterSpec,
    measurement_order: int,
) -> dict[str, Any]:
    warm = config["warm"]
    build_started = time.perf_counter_ns()
    filter_object = build_filter(spec, members, plan.trial_seed)
    build_ns = time.perf_counter_ns() - build_started
    _require_zero_member_false_negatives(filter_object, members)
    path = CanonicalPrescreenPath(directory, dataset.codec, filter_object)
    preflight_count = int(warm["preflight_query_count"])
    mismatch_count = 0
    positive_count = 0
    for attempt, query in zip(
        inputs.pool_attempts[:preflight_count],
        inputs.pool_queries[:preflight_count],
        strict=True,
    ):
        query_only = filter_object.query(query)
        actual_front = path.query(attempt)
        positive_count += int(query_only.positive)
        mismatch_count += int(query_only != actual_front)
    if mismatch_count:
        raise RuntimeError("actual-front and query-only preflight decisions differ")
    for ordinal in range(int(warm["warmup_query_count"])):
        filter_object.query(inputs.pool_queries[ordinal % len(inputs.pool_queries)])
    throughput = _actual_front_throughput_trials(
        path,
        inputs.pool_attempts,
        int(warm["actual_front_throughput_repetitions"]),
    )
    order = path_measurement_order(int(plan.global_seed_ordinal))
    measured: dict[str, list[int]] = {}
    for timing_path in order:
        if timing_path == "actual_front":
            measured[timing_path] = _actual_front_latencies(path, inputs.actual_latency_attempts)
        else:
            measured[timing_path] = _query_only_latencies(
                filter_object, inputs.query_only_latency_queries
            )
    actual = _summary_us(measured["actual_front"])
    query_only = _summary_us(measured["query_only"])
    clock_p99_ns = float(environment["timing_clock"]["overhead_p99_ns"])
    clock_ratio = actual["p99"] * 1000.0 / clock_p99_ns
    row = _common_row(
        config,
        config_id,
        dataset_id,
        source_commit,
        environment,
        plan,
        spec,
        measurement_order,
        filter_object,
        build_ns,
    )
    row.update(
        {
            "primary_timing_metric": ("indexed_directory_to_screen_decision_warm_p99_us"),
            "actual_front_timing_interval": (
                "directory[attempt.account_index] + CredentialInput allocation + "
                "SHA256 prehash + HMAC token + filter.query"
            ),
            "actual_front_timing_excludes": [
                "username-to-account-index resolution",
                "network and request parsing",
                "queueing",
                "backend verification",
                "input generation",
                "histogram and percentile construction",
            ],
            "query_only_timing_interval": "filter.query only",
            "path_measurement_order": list(order),
            "query_window_assignment": "disjoint_global_seed_windows_v2",
            "query_window_start": inputs.query_window_start,
            "query_window_end_exclusive": inputs.query_window_end_exclusive,
            "query_pool_count": len(inputs.pool_queries),
            "warmup_query_count": int(warm["warmup_query_count"]),
            "preflight_query_count": preflight_count,
            "member_validation_count": len(members),
            "member_false_negatives": 0,
            "preflight_query_only_positive_count": positive_count,
            "preflight_path_decision_mismatch_count": mismatch_count,
            "actual_front_throughput_query_count_per_trial": len(inputs.pool_attempts),
            "actual_front_throughput_repetition_count": len(throughput),
            "actual_front_throughput_qps_trials": throughput,
            "actual_front_throughput_qps_mean": statistics.mean(throughput),
            "actual_front_latency_sample_count": len(measured["actual_front"]),
            "actual_front_warm_latency_histogram_ns": _latency_histogram(measured["actual_front"]),
            "indexed_directory_to_screen_decision_warm_p50_us": actual["p50"],
            "indexed_directory_to_screen_decision_warm_p95_us": actual["p95"],
            "indexed_directory_to_screen_decision_warm_p99_us": actual["p99"],
            "primary_p99_to_clock_call_p99_ratio": clock_ratio,
            "primary_p99_to_clock_call_p99_minimum": config["timing"][
                "minimum_primary_p99_to_clock_call_p99_ratio"
            ],
            "primary_p99_to_clock_call_p99_gate_pass": clock_ratio
            >= float(config["timing"]["minimum_primary_p99_to_clock_call_p99_ratio"]),
            "query_only_latency_sample_count": len(measured["query_only"]),
            "query_only_warm_latency_histogram_ns": _latency_histogram(measured["query_only"]),
            "filter_query_only_warm_p50_us": query_only["p50"],
            "filter_query_only_warm_p95_us": query_only["p95"],
            "filter_query_only_warm_p99_us": query_only["p99"],
            "precision_rule": {
                "scale": warm["precision_scale"],
                "relative_half_width_max": warm["precision_relative_half_width_max"],
                "look_alpha": warm["precision_look_alpha"],
                "coordinate_alpha": warm["simultaneous_coordinate_alpha"],
                "maximum_trial_count": warm["maximum_trial_count"],
            },
        }
    )
    row["observation_sha256"] = observation_sha256(row)
    return row


def _cold_row(
    config: dict[str, Any],
    config_id: str,
    dataset_id: str,
    source_commit: str,
    environment: dict[str, Any],
    members: list[ScreenQuery],
    queries: Sequence[ScreenQuery],
    eviction: bytearray,
    plan: StagePlan,
    spec: FilterSpec,
    measurement_order: int,
) -> dict[str, Any]:
    build_started = time.perf_counter_ns()
    filter_object = build_filter(spec, members, plan.trial_seed)
    build_ns = time.perf_counter_ns() - build_started
    _require_zero_member_false_negatives(filter_object, members)
    values, terminal_token = _cold_query_only_latencies(filter_object, queries, eviction)
    summary = _summary_us(values)
    record = environment["affinity_cpu_records"][0]
    llc_bytes = int(record["last_level_cache_bytes"])
    eviction_bytes = len(eviction)
    row = _common_row(
        config,
        config_id,
        dataset_id,
        source_commit,
        environment,
        plan,
        spec,
        measurement_order,
        filter_object,
        build_ns,
    )
    row.update(
        {
            "primary_timing_metric": None,
            "diagnostic_timing_metric": "filter_query_only_cold_p99_us",
            "query_only_timing_interval": "filter.query only",
            "cold_claim_scope": config["cold"]["claim_scope"],
            "member_validation_count": len(members),
            "member_false_negatives": 0,
            "cold_latency_sample_count": len(values),
            "query_only_cold_latency_histogram_ns": _latency_histogram(values),
            "filter_query_only_cold_p50_us": summary["p50"],
            "filter_query_only_cold_p95_us": summary["p95"],
            "filter_query_only_cold_p99_us": summary["p99"],
            "cold_query_window_start": config["cold"]["query_window_start"],
            "cold_query_window_end_exclusive": int(config["cold"]["query_window_start"])
            + len(queries),
            "cold_eviction_bytes_per_query": eviction_bytes,
            "cold_eviction_method": config["cold"]["eviction_method"],
            "cold_eviction_per_query": True,
            "cold_eviction_time_excluded": True,
            "cold_eviction_last_level_cache_bytes": llc_bytes,
            "cold_eviction_buffer_to_llc_ratio": eviction_bytes / llc_bytes,
            "cold_eviction_minimum_llc_multiple": config["cold"]["eviction_minimum_llc_multiple"],
            "cold_eviction_terminal_token": terminal_token,
        }
    )
    row["observation_sha256"] = observation_sha256(row)
    return row


def _verify_source_pin(expected_source_commit: str) -> str:
    if SOURCE_COMMIT_PATTERN.fullmatch(expected_source_commit) is None:
        raise ValueError("expected source commit must be exactly 40 lowercase hex digits")
    commit, dirty = _git_provenance()
    if commit != expected_source_commit:
        raise RuntimeError(
            f"source commit mismatch: expected {expected_source_commit}, found {commit}"
        )
    if dirty is not False:
        raise RuntimeError("formal v2 timing requires a clean source checkout")
    return commit


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


def atomic_write_jsonl_no_overwrite(
    output: Path,
    rows: Iterable[dict[str, Any]],
    before_publish: Callable[[], None] | None = None,
    expected_count: int | None = None,
) -> int:
    """Stream a shard to a sibling temp and atomically publish without overwrite."""

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite existing shard: {output}")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent,
        prefix=f".{output.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    count = 0
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
                handle.write("\n")
                count += 1
            if count == 0:
                raise RuntimeError("refusing to publish an empty timing shard")
            if expected_count is not None and count != expected_count:
                raise RuntimeError(
                    f"refusing row-count mismatch: expected {expected_count}, found {count}"
                )
            handle.flush()
            os.fsync(handle.fileno())
        if before_publish is not None:
            before_publish()
        linked = False
        try:
            os.link(temporary, output)
            linked = True
            _fsync_directory(output.parent)
        except FileExistsError as error:
            raise FileExistsError(f"refusing to overwrite existing shard: {output}") from error
        except Exception:
            if linked:
                output.unlink(missing_ok=True)
            raise
        temporary.unlink()
        return count
    finally:
        if temporary.exists():
            temporary.unlink()


def _iter_rows(
    config: dict[str, Any],
    config_id: str,
    source_commit: str,
    environment: dict[str, Any],
    plan: StagePlan,
) -> Iterator[dict[str, Any]]:
    dataset = SyntheticCredentialSet(ACCOUNT_COUNT, DATASET_SEED)
    members = [dataset.member(index) for index in range(ACCOUNT_COUNT)]
    dataset_id = dataset.manifest_hash(members, NONMEMBER_COUNT)
    if (
        dataset_id != TIMING_DATASET_ID
        or dataset_id != environment["corpus_equivalence_dataset_id"]
    ):
        raise RuntimeError("timing shard dataset differs from corpus equivalence receipt")
    if plan.stage.startswith("warm-"):
        if plan.global_seed_ordinal is None:
            raise AssertionError("warm plan lacks a global seed ordinal")
        directory = dataset.directory()
        inputs = _warm_inputs(dataset, plan.global_seed_ordinal, config["warm"])
        for measurement_order, spec in enumerate(plan.specs):
            yield _warm_row(
                config,
                config_id,
                dataset_id,
                source_commit,
                environment,
                dataset,
                directory,
                members,
                inputs,
                plan,
                spec,
                measurement_order,
            )
        return
    start = int(config["cold"]["query_window_start"])
    count = int(config["cold"]["query_only_latency_query_count"])
    queries = tuple(dataset.nonmember(start + ordinal) for ordinal in range(count))
    eviction = bytearray(int(config["cold"]["eviction_bytes"]))
    for measurement_order, spec in enumerate(plan.specs):
        yield _cold_row(
            config,
            config_id,
            dataset_id,
            source_commit,
            environment,
            members,
            queries,
            eviction,
            plan,
            spec,
            measurement_order,
        )


def run_shard(
    config_path: Path,
    stage: str,
    shard_index: int,
    shard_count: int,
    expected_source_commit: str,
    frontier_audit_path: Path,
    frontier_summary_path: Path,
    diagnostic_aggregate_path: Path,
    v1_postrun_receipt_path: Path,
    corpus_equivalence_receipt_path: Path,
    expected_corpus_equivalence_id: str,
    construction_feasibility_receipt_path: Path,
    expected_construction_feasibility_id: str,
    look1_extension_decision_path: Path | None,
    expected_look1_extension_decision_id: str | None,
    output: Path | None,
    check_environment_only: bool = False,
) -> dict[str, Any]:
    config, config_id = load_config(config_path)
    plan = plan_stage(config, config_id, stage, shard_index, shard_count)
    commit = _verify_source_pin(expected_source_commit)
    source_evidence_binding_id = validate_source_evidence(
        config,
        frontier_audit_path,
        frontier_summary_path,
        diagnostic_aggregate_path,
        v1_postrun_receipt_path,
    )
    corpus_receipt = validate_corpus_equivalence_receipt(
        config,
        config_id,
        commit,
        source_evidence_binding_id,
        corpus_equivalence_receipt_path,
        expected_corpus_equivalence_id,
    )
    construction_receipt = validate_construction_feasibility_receipt(
        config,
        config_id,
        commit,
        source_evidence_binding_id,
        expected_corpus_equivalence_id,
        corpus_receipt["semantic_dataset_id"],
        construction_feasibility_receipt_path,
        expected_construction_feasibility_id,
    )
    if construction_receipt["semantic_dataset_id"] != corpus_receipt["semantic_dataset_id"]:
        raise RuntimeError("preflight receipts bind different timing datasets")
    if stage == "warm-look2":
        if look1_extension_decision_path is None or expected_look1_extension_decision_id is None:
            raise ValueError("warm-look2 requires a look1 decision receipt and expected ID")
        look1_decision = validate_look1_extension_decision(
            config,
            config_id,
            commit,
            source_evidence_binding_id,
            expected_corpus_equivalence_id,
            expected_construction_feasibility_id,
            look1_extension_decision_path,
            expected_look1_extension_decision_id,
            require_look2=True,
        )
        look1_extension_decision_id: str | None = look1_decision["receipt_id"]
    else:
        if (
            look1_extension_decision_path is not None
            or expected_look1_extension_decision_id is not None
        ):
            raise ValueError("look1 decision receipt and expected ID are valid only for warm-look2")
        look1_extension_decision_id = None
    environment = host_environment(int(config["timing"]["declared_benchmark_process_concurrency"]))
    environment["source_evidence_binding_id"] = source_evidence_binding_id
    environment["corpus_equivalence_receipt_id"] = expected_corpus_equivalence_id
    environment["corpus_equivalence_dataset_id"] = corpus_receipt["semantic_dataset_id"]
    environment["construction_feasibility_receipt_id"] = expected_construction_feasibility_id
    environment["construction_feasibility_status"] = construction_receipt["status"]
    environment["construction_feasibility_build_count"] = construction_receipt["build_count"]
    environment["look1_extension_decision_receipt_id"] = look1_extension_decision_id
    environment["expected_look1_extension_decision_id"] = expected_look1_extension_decision_id
    with HostTimingLock(required=True):
        environment["same_runner_host_lock_acquired"] = True
        _require_formal_host_environment(environment)
        environment["timing_clock"] = timing_clock_record(
            int(config["timing"]["clock_call_overhead_sample_count"])
        )
        if stage == "cold":
            _require_cold_eviction_capacity(config, environment)
        if check_environment_only:
            _verify_source_pin(expected_source_commit)
            return {
                "status": "ENVIRONMENT_OK",
                "stage": stage,
                "semantic_config_id": config_id,
                "source_commit": commit,
                "source_evidence_binding_id": source_evidence_binding_id,
                "corpus_equivalence_receipt_id": expected_corpus_equivalence_id,
                "construction_feasibility_receipt_id": (expected_construction_feasibility_id),
                "look1_extension_decision_receipt_id": (look1_extension_decision_id),
                "expected_look1_extension_decision_id": (expected_look1_extension_decision_id),
                "timing_clock": environment["timing_clock"],
                "shard_index": shard_index,
                "shard_count": shard_count,
            }
        if output is None:
            raise ValueError("--output is required unless --check-environment-only is used")

        def verify_before_publish() -> None:
            _verify_source_pin(expected_source_commit)

        expected_rows = PHASE1_SPEC_COUNT if stage != "cold" else len(plan.specs)
        row_count = atomic_write_jsonl_no_overwrite(
            output,
            _iter_rows(config, config_id, commit, environment, plan),
            before_publish=verify_before_publish,
            expected_count=expected_rows,
        )
    return {
        "status": "SHARD_COMPLETE",
        "stage": stage,
        "semantic_config_id": config_id,
        "source_commit": commit,
        "shard_index": shard_index,
        "shard_count": shard_count,
        "row_count": row_count,
        "output": str(output),
    }


def run_corpus_equivalence_preflight(
    config_path: Path,
    expected_source_commit: str,
    frontier_audit_path: Path,
    frontier_summary_path: Path,
    diagnostic_aggregate_path: Path,
    v1_postrun_receipt_path: Path,
    output: Path,
    progress: bool = False,
) -> dict[str, Any]:
    config, config_id = load_config(config_path)
    commit = _verify_source_pin(expected_source_commit)
    source_evidence_binding_id = validate_source_evidence(
        config,
        frontier_audit_path,
        frontier_summary_path,
        diagnostic_aggregate_path,
        v1_postrun_receipt_path,
    )
    receipt = create_corpus_equivalence_receipt(
        config,
        config_id,
        commit,
        source_evidence_binding_id,
        output,
        progress=progress,
    )
    return {
        "status": receipt["status"],
        "semantic_config_id": config_id,
        "semantic_dataset_id": receipt["semantic_dataset_id"],
        "source_commit": commit,
        "source_evidence_binding_id": source_evidence_binding_id,
        "corpus_equivalence_receipt_id": receipt["receipt_id"],
        "output": str(output),
    }


def run_construction_feasibility_preflight(
    config_path: Path,
    expected_source_commit: str,
    frontier_audit_path: Path,
    frontier_summary_path: Path,
    diagnostic_aggregate_path: Path,
    v1_postrun_receipt_path: Path,
    corpus_equivalence_receipt_path: Path,
    expected_corpus_equivalence_id: str,
    output: Path,
    progress: bool = False,
) -> dict[str, Any]:
    config, config_id = load_config(config_path)
    commit = _verify_source_pin(expected_source_commit)
    source_evidence_binding_id = validate_source_evidence(
        config,
        frontier_audit_path,
        frontier_summary_path,
        diagnostic_aggregate_path,
        v1_postrun_receipt_path,
    )
    corpus_receipt = validate_corpus_equivalence_receipt(
        config,
        config_id,
        commit,
        source_evidence_binding_id,
        corpus_equivalence_receipt_path,
        expected_corpus_equivalence_id,
    )
    receipt = create_construction_feasibility_receipt(
        config,
        config_id,
        commit,
        source_evidence_binding_id,
        corpus_receipt,
        output,
        progress=progress,
    )
    return {
        "status": receipt["status"],
        "semantic_config_id": config_id,
        "semantic_dataset_id": receipt["semantic_dataset_id"],
        "source_commit": commit,
        "source_evidence_binding_id": source_evidence_binding_id,
        "corpus_equivalence_receipt_id": expected_corpus_equivalence_id,
        "construction_feasibility_receipt_id": receipt["receipt_id"],
        "output": str(output),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--stage", choices=STAGES)
    parser.add_argument("--shard-index", type=int)
    parser.add_argument("--shard-count", type=int)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--source-frontier-audit", required=True, type=Path)
    parser.add_argument("--source-frontier-summary", required=True, type=Path)
    parser.add_argument("--source-diagnostic-aggregate", required=True, type=Path)
    parser.add_argument("--v1-postrun-receipt", required=True, type=Path)
    parser.add_argument("--corpus-equivalence-receipt", type=Path)
    parser.add_argument("--expected-corpus-equivalence-id")
    parser.add_argument("--construction-feasibility-receipt", type=Path)
    parser.add_argument("--expected-construction-feasibility-id")
    parser.add_argument("--look1-extension-decision", type=Path)
    parser.add_argument("--expected-look1-extension-decision-id")
    parser.add_argument("--output", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-environment-only", action="store_true")
    modes.add_argument("--check-corpus-equivalence", action="store_true")
    modes.add_argument("--check-construction-feasibility", action="store_true")
    parser.add_argument("--progress", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        source_arguments = (
            args.source_frontier_audit,
            args.source_frontier_summary,
            args.source_diagnostic_aggregate,
            args.v1_postrun_receipt,
        )
        if args.check_corpus_equivalence:
            if args.corpus_equivalence_receipt is None:
                raise ValueError("--check-corpus-equivalence requires --corpus-equivalence-receipt")
            result = run_corpus_equivalence_preflight(
                args.config,
                args.expected_source_commit,
                *source_arguments,
                args.corpus_equivalence_receipt,
                progress=args.progress,
            )
        elif args.check_construction_feasibility:
            if (
                args.corpus_equivalence_receipt is None
                or args.expected_corpus_equivalence_id is None
                or args.construction_feasibility_receipt is None
            ):
                raise ValueError(
                    "construction preflight requires corpus receipt/ID and output receipt"
                )
            result = run_construction_feasibility_preflight(
                args.config,
                args.expected_source_commit,
                *source_arguments,
                args.corpus_equivalence_receipt,
                args.expected_corpus_equivalence_id,
                args.construction_feasibility_receipt,
                progress=args.progress,
            )
        else:
            if (
                args.stage is None
                or args.shard_index is None
                or args.shard_count is None
                or args.corpus_equivalence_receipt is None
                or args.expected_corpus_equivalence_id is None
                or args.construction_feasibility_receipt is None
                or args.expected_construction_feasibility_id is None
            ):
                raise ValueError(
                    "timing mode requires stage/shard and both preflight receipt bindings"
                )
            result = run_shard(
                args.config,
                args.stage,
                args.shard_index,
                args.shard_count,
                args.expected_source_commit,
                *source_arguments,
                args.corpus_equivalence_receipt,
                args.expected_corpus_equivalence_id,
                args.construction_feasibility_receipt,
                args.expected_construction_feasibility_id,
                args.look1_extension_decision,
                args.expected_look1_extension_decision_id,
                args.output,
                args.check_environment_only,
            )
    except SystemExit:
        raise
    except Exception as error:
        print(f"v2 timing refused: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
