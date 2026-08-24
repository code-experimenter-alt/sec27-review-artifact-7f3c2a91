#!/usr/bin/env python3
"""Adjudicate G2 from frozen E4 replay and registered E7 service evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import statistics
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from scipy.stats import t as student_t

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.analysis import register_phase1_v21_baseline as registration  # noqa: E402
from experiments.runners import replay_bench, service_bench  # noqa: E402
from experiments.runners import replay_e4_aggregate as e4_aggregate  # noqa: E402

RECEIPT_SCHEMA = "traps-e4-e7-g2-adjudication-receipt-v2"
G2_CONTRACT_SCHEMA = "traps-g2-e4-e7-gate-v1"
PASS = "PASS_G2_REPEATED_FALSE_POSITIVE_SUPPRESSION"
FAIL = "FAIL_G2_REPEATED_FALSE_POSITIVE_SUPPRESSION"
INDETERMINATE = "INDETERMINATE_G2_REPEATED_FALSE_POSITIVE_SUPPRESSION"
VALID = "VALID"
EXIT_PASS = 0
EXIT_NONPROMOTABLE = 2
EXIT_INVALID = 3
ANALYSIS_SOURCE_SCOPE = "REPOSITORY_EXCLUDING_EXPERIMENT_OUTPUTS"
SERVICE_RECOVERY_SCOPE = registration.RECOVERY_SCOPE

E4_METHOD = "static_cuckoo_exact_lru"
E4_ELIGIBLE_METHODS = (
    "static_cuckoo_exact_lfu",
    "static_cuckoo_exact_lru",
    "static_cuckoo_fixed_ttl_exact_lru",
)
E4_SCENARIO = "resident_capacity"
E4_MULTIPLICITIES = (100, 1000, 10000)
E4_MODES = ("concurrent", "sequential")
E7_CANDIDATE = "frozen_screen_exact_cache_lru"
E7_BASELINE = "static_frozen_screen_mechanism_baseline"
ADJUSTMENT = "bonferroni_one_sided_student_t_log_ratio_v1"
HEX = frozenset("0123456789abcdef")
E4_AGGREGATE_ID = "556cc9c506d5b1603ff81fc866e49cb177968e5cf5315ef82be9ff9b4512ae66"
E4_CONFIG_ID = "e2e7551836574687f0481363d919f0aff19475e9303947587e6c0055facd0ae8"
E4_DATASET_ID = "3fa274b9c341b6151dd82b0ded86bfd28b54d438c1dfcf9c81aac10d957ff5d3"
E4_SOURCE_COMMIT = "6dcbaaa9748f4e5f8b1e9fbaf9bd7d31ccc9678e"
E4_CONFIG_PATH = ROOT / "experiments" / "configs" / "replay_e4.yaml"
E4_AGGREGATE_PATH = ROOT / "experiments" / "evidence" / "e4-v4-6dcbaaa" / "e4-v4-aggregate.json"


class G2AdjudicationError(ValueError):
    """Raised when the G2 evidence package is invalid or incomplete."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise G2AdjudicationError(f"invalid CLI: {message}")


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise G2AdjudicationError(f"{label} must be a string-keyed object")
    return value


def _finite(value: object, label: str, *, positive: bool = False) -> float:
    if type(value) is not float or not math.isfinite(value):
        raise G2AdjudicationError(f"{label} must be a finite JSON float")
    if positive and value <= 0.0:
        raise G2AdjudicationError(f"{label} must be positive")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise G2AdjudicationError(f"{label} must be an integer >= {minimum}")
    return value


def _hex64(value: object, label: str) -> str:
    if type(value) is not str or len(value) != 64 or set(value) - HEX:
        raise G2AdjudicationError(f"{label} must be 64 lowercase hexadecimal characters")
    return value


def canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise G2AdjudicationError("value is not canonical JSON data") from error


def semantic_id(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def _require_analysis_checkout(expected_commit: str, *, root: Path = ROOT) -> dict[str, Any]:
    if (
        type(expected_commit) is not str
        or len(expected_commit) != 40
        or any(character not in HEX for character in expected_commit)
    ):
        raise G2AdjudicationError("expected analysis commit is not a lowercase 40-hex ID")
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--",
                ".",
                ":(exclude)experiments/outputs/**",
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise G2AdjudicationError("analysis Git provenance is unavailable") from error
    if commit != expected_commit:
        raise G2AdjudicationError("analysis checkout commit differs from the frozen commit")
    if status.strip():
        raise G2AdjudicationError("analysis checkout is dirty in the frozen source scope")
    return {
        "commit": commit,
        "clean": True,
        "scope": ANALYSIS_SOURCE_SCOPE,
    }


def _unique_pairs(pairs: list[tuple[str, Any]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise G2AdjudicationError(f"duplicate JSON key in {label}: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise G2AdjudicationError(f"non-finite JSON constant: {value}")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=lambda pairs: _unique_pairs(pairs, label),
            parse_constant=_reject_constant,
        )
    except G2AdjudicationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise G2AdjudicationError(f"cannot load {label}: {error}") from error
    return _mapping(value, label)


def load_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    raise G2AdjudicationError(f"blank line in {label} at {line_number}")
                try:
                    value = json.loads(
                        line,
                        object_pairs_hook=lambda pairs, n=line_number: _unique_pairs(
                            pairs, f"{label}:{n}"
                        ),
                        parse_constant=_reject_constant,
                    )
                except json.JSONDecodeError as error:
                    raise G2AdjudicationError(
                        f"invalid JSON in {label} at {line_number}: {error}"
                    ) from error
                rows.append(_mapping(value, f"{label}:{line_number}"))
    except G2AdjudicationError:
        raise
    except (OSError, UnicodeError) as error:
        raise G2AdjudicationError(f"cannot load {label}: {error}") from error
    if not rows:
        raise G2AdjudicationError(f"{label} is empty")
    return rows


def _same(expected: object, observed: object, label: str) -> None:
    if type(expected) is not type(observed) or canonical(expected) != canonical(observed):
        raise G2AdjudicationError(f"{label} differs from strict recomputation")


def validate_e4_aggregate(value: Mapping[str, Any]) -> dict[str, Any]:
    aggregate = _mapping(dict(value), "E4 aggregate")
    try:
        frozen_config, frozen_config_id = replay_bench.load_config(E4_CONFIG_PATH)
    except (OSError, TypeError, ValueError) as error:
        raise G2AdjudicationError(f"cannot reload the frozen E4 config: {error}") from error
    if frozen_config_id != E4_CONFIG_ID:
        raise G2AdjudicationError("frozen E4 config identity differs from the retained evidence")
    required = {
        "schema": e4_aggregate.AGGREGATE_SCHEMA,
        "integrity_status": "PASS",
        "evidence_status": "FORMAL_REPLAY_VALID",
        "config_contract_id": replay_bench.FORMAL_CONTRACT_ID,
        "row_count": replay_bench.EXPECTED_FORMAL_ROWS,
        "expected_row_count": replay_bench.EXPECTED_FORMAL_ROWS,
        "seed_count": 10,
        "points_per_seed": 93,
        "source_attestation_status": "TRUSTED_MANIFESTS_BOUND",
        "timing_evidence_status": "NOT_MEASURED_E7_REQUIRED",
        "g2_gate_status": e4_aggregate.G2_BLOCKED_STATUS,
    }
    for field, expected in required.items():
        if aggregate.get(field) != expected or type(aggregate.get(field)) is not type(expected):
            raise G2AdjudicationError(f"E4 aggregate {field} differs from formal evidence")
    _hex64(aggregate.get("config_hash"), "E4 config_hash")
    _hex64(aggregate.get("dataset_hash"), "E4 dataset_hash")
    commit = aggregate.get("commit")
    if type(commit) is not str or len(commit) != 40 or set(commit) - HEX:
        raise G2AdjudicationError("E4 commit must be 40 lowercase hexadecimal characters")
    summaries = aggregate.get("paired_seed_summaries")
    if type(summaries) is not list or len(summaries) != 93:
        raise G2AdjudicationError("E4 aggregate must contain all 93 paired summaries")
    coordinates: set[tuple[object, ...]] = set()
    selected: dict[tuple[str, int, str], dict[str, Any]] = {}
    for index, raw in enumerate(summaries):
        summary = _mapping(raw, f"E4 paired summary {index}")
        coordinate = (
            summary.get("method"),
            summary.get("scenario"),
            summary.get("multiplicity"),
            summary.get("mode"),
        )
        if coordinate in coordinates:
            raise G2AdjudicationError(f"duplicate E4 paired summary {coordinate!r}")
        coordinates.add(coordinate)
        if (
            summary.get("method") in E4_ELIGIBLE_METHODS
            and summary.get("scenario") == E4_SCENARIO
            and summary.get("multiplicity") in E4_MULTIPLICITIES
            and summary.get("mode") in E4_MODES
        ):
            key = (summary["method"], summary["multiplicity"], summary["mode"])
            if key in selected:
                raise G2AdjudicationError(f"duplicate E4 G2 summary {key!r}")
            selected[key] = summary
        elif (
            summary.get("g2_replay_component_eligible_seed_count") != 0
            or summary.get("g2_replay_component_all_eligible_rows_pass") is not None
        ):
            raise G2AdjudicationError(
                f"undeclared E4 coordinate {coordinate!r} is marked G2 eligible"
            )
    expected_coordinates = {point[1:] for point in replay_bench.expected_points(frozen_config)}
    if coordinates != expected_coordinates:
        raise G2AdjudicationError("E4 paired summaries differ from the frozen 93 coordinates")
    expected_keys = {
        (method, multiplicity, mode)
        for method in E4_ELIGIBLE_METHODS
        for multiplicity in E4_MULTIPLICITIES
        for mode in E4_MODES
    }
    if set(selected) != expected_keys:
        raise G2AdjudicationError("E4 exact-LRU G2 summary family is incomplete")
    relations: list[dict[str, Any]] = []
    for key in sorted(selected):
        summary = selected[key]
        if summary.get("seed_count") != 10 or summary.get("paired_seed_count", 10) != 10:
            raise G2AdjudicationError(f"E4 G2 summary {key!r} must use 10 paired seeds")
        if summary.get("seed_set") != list(range(7100, 7110)):
            raise G2AdjudicationError(f"E4 G2 summary {key!r} uses the wrong seed set")
        if summary.get("g2_replay_component_eligible_seed_count") != 10:
            raise G2AdjudicationError(f"E4 G2 summary {key!r} is not fully eligible")
        if summary.get("g2_replay_component_all_eligible_rows_pass") is not True:
            raise G2AdjudicationError(f"E4 G2 summary {key!r} does not pass replay criteria")
        checks = _mapping(summary.get("backend_checks_per_tuple"), "E4 checks interval")
        reduction = _mapping(
            summary.get("paired_static_reduction_factor_finite"), "E4 reduction interval"
        )
        checks_high = _finite(checks.get("ci95_high"), "E4 checks CI high")
        reduction_low = _finite(reduction.get("ci95_low"), "E4 reduction CI low")
        if checks_high > replay_bench.G2_CHECKS_PER_TUPLE_MAX:
            raise G2AdjudicationError(f"E4 G2 summary {key!r} exceeds 1.1 checks per tuple")
        if reduction_low < replay_bench.G2_STATIC_WORK_IMPROVEMENT_MIN:
            raise G2AdjudicationError(f"E4 G2 summary {key!r} is below 10x reduction")
        relations.append(
            {
                "method": key[0],
                "multiplicity": key[1],
                "mode": key[2],
                "paired_seed_count": 10,
                "checks_per_tuple_ci95_high": checks_high,
                "static_reduction_factor_ci95_low": reduction_low,
                "decision": "PASS_E4_REPLAY_COMPONENT",
            }
        )
    aggregate_id = semantic_id(aggregate)
    pins = {
        "aggregate_id": (aggregate_id, E4_AGGREGATE_ID),
        "config_hash": (aggregate["config_hash"], E4_CONFIG_ID),
        "dataset_hash": (aggregate["dataset_hash"], E4_DATASET_ID),
        "source_commit": (aggregate["commit"], E4_SOURCE_COMMIT),
    }
    for label, (observed, expected) in pins.items():
        if observed != expected:
            raise G2AdjudicationError(f"E4 retained {label} differs from its frozen pin")
    return {
        "aggregate_id": aggregate_id,
        "config_hash": aggregate["config_hash"],
        "dataset_hash": aggregate["dataset_hash"],
        "source_commit": aggregate["commit"],
        "eligible_methods": list(E4_ELIGIBLE_METHODS),
        "deployed_e7_policy_match": E4_METHOD,
        "conditional_estimand": "KNOWN_FALSE_POSITIVE_TUPLE_REPLAY",
        "filter_transfer_scope": (
            "Conditional repeated work after a tuple is known to be a false positive; "
            "the E4 Cuckoo discovery FFR is not transferred to the Phase 1 selected filter"
        ),
        "relation_count": len(relations),
        "relations": relations,
        "decision": "PASS_E4_REPLAY_COMPONENT",
    }


def _expected_g2_contract(config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema": G2_CONTRACT_SCHEMA,
        "candidate_method": E7_CANDIDATE,
        "baseline_method": E7_BASELINE,
        "scenario": "repeat_heavy_false_positive",
        "offered_legitimate_rps": 16,
        "offered_invalid_rps": 32,
        "verifier_profiles": list(config["verifier"]["enabled_profiles"]),
        "repeated_tuple_count": 16,
        "minimum_replay_multiplicity": 100,
        "paired_seed_count": 20,
        "latency_margin_ratio": 1.05,
        "familywise_alpha": 0.05,
        "multiplicity_adjustment": ADJUSTMENT,
        "false_positive_source": "FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1",
        "underlying_filter_query_executed": True,
        "conditional_intervention_does_not_estimate_ffr": True,
    }


def validate_g2_contract(config: Mapping[str, Any]) -> dict[str, Any]:
    observed = _mapping(config.get("g2_gate_contract"), "g2_gate_contract")
    expected = _expected_g2_contract(config)
    _same(expected, observed, "g2_gate_contract")
    if config.get("seeds") != list(range(6100, 6120)):
        raise G2AdjudicationError("E7 G2 contract must use all 20 frozen service seeds")
    if config.get("scenario_parameters", {}).get("repeat_tuple_count") != 16:
        raise G2AdjudicationError("E7 repeat tuple count differs from the G2 contract")
    service = _mapping(config.get("service"), "E7 service config")
    if _integer(service.get("cache_capacity"), "E7 cache capacity", minimum=1) < 16:
        raise G2AdjudicationError("E7 cache cannot retain all frozen repeated tuples")
    ttl = service.get("cache_ttl_seconds")
    if type(ttl) not in {int, float} or isinstance(ttl, bool) or not math.isfinite(float(ttl)):
        raise G2AdjudicationError("E7 cache TTL must be finite")
    if float(ttl) <= float(config["measurement"]["duration_seconds"]):
        raise G2AdjudicationError("E7 cache TTL does not cover the measurement window")
    quota = service.get("cache_max_entries_per_account")
    if quota is not None and _integer(quota, "E7 per-account cache quota", minimum=1) < 16:
        raise G2AdjudicationError("E7 per-account cache quota is below the repeated-tuple set")
    candidate = next((item for item in config["methods"] if item.get("name") == E7_CANDIDATE), None)
    if candidate is None or {
        "cache_policy": candidate.get("cache_policy"),
        "use_singleflight": candidate.get("use_singleflight"),
    } != {"cache_policy": "lru", "use_singleflight": True}:
        raise G2AdjudicationError("E7 G2 candidate is not exact LRU plus singleflight")
    return dict(observed)


def validate_registration_artifact(
    artifact_path: Path, *, root: Path = ROOT
) -> tuple[dict[str, Any], dict[str, Any]]:
    artifact = registration.load_strict_json(artifact_path, "Phase 1 registration artifact")
    try:
        relative = artifact_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise G2AdjudicationError("registration artifact must be inside the repository") from error
    try:
        phase1_boundary = _phase1_registration_boundary(artifact)
        if phase1_boundary["status"] == registration.REGISTERED:
            binding = registration.registered_binding(
                registration.SERVICE_BINDING_SCHEMA, artifact, relative
            )
        else:
            binding = registration.registered_recovery_binding(
                registration.SERVICE_BINDING_SCHEMA, artifact, relative
            )
        registration.validate_binding(
            binding,
            schema=registration.SERVICE_BINDING_SCHEMA,
            root=root,
            expected_filter=artifact["selection"]["selected_filter"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise G2AdjudicationError(f"invalid Phase 1 registration: {error}") from error
    return artifact, binding


def _phase1_registration_boundary(artifact: Mapping[str, Any]) -> dict[str, Any]:
    status = artifact.get("status")
    evidence = _mapping(artifact.get("phase1_evidence"), "Phase 1 evidence binding")
    selection = _mapping(artifact.get("selection"), "Phase 1 selection")
    if status == registration.REGISTERED:
        if artifact.get("schema") != registration.REGISTRATION_SCHEMA:
            raise G2AdjudicationError("Phase 1 registration schema differs")
        if evidence.get("p0_eligible") is not True:
            raise G2AdjudicationError("Phase 1 registration is not P0 eligible")
        if evidence.get("recovery_scope") is not None:
            raise G2AdjudicationError("P0 registration unexpectedly declares recovery scope")
        if selection.get("policy") != registration.SELECTION_POLICY:
            raise G2AdjudicationError("P0 registration selection policy differs")
        return {"status": status, "recovery_scope": None}
    if status == registration.RECOVERY_REGISTERED:
        if artifact.get("schema") != registration.RECOVERY_REGISTRATION_SCHEMA:
            raise G2AdjudicationError("Phase 1 recovery registration schema differs")
        if evidence.get("p0_eligible") is not False:
            raise G2AdjudicationError("Phase 1 recovery registration must remain non-P0")
        if evidence.get("validation_status") != "VALID_BUT_NONPROMOTABLE":
            raise G2AdjudicationError("Phase 1 recovery must bind the nonpromotable receipt")
        if evidence.get("recovery_scope") != SERVICE_RECOVERY_SCOPE:
            raise G2AdjudicationError("Phase 1 recovery scope is not service-only")
        if selection.get("policy") != registration.RECOVERY_SELECTION_POLICY:
            raise G2AdjudicationError("Phase 1 recovery selection policy differs")
        return {"status": status, "recovery_scope": SERVICE_RECOVERY_SCOPE}
    raise G2AdjudicationError("Phase 1 baseline is not registered")


def _validate_service_summary(
    summary: Mapping[str, Any],
    config: Mapping[str, Any],
    rows: list[dict[str, Any]],
) -> None:
    if set(summary) != {
        "schema_version",
        "main_claims_manifest_id",
        "coverage",
        "saturation",
        "backend_invalid_capacity",
    }:
        raise G2AdjudicationError("E7 summary has the wrong fields")
    if summary["schema_version"] != service_bench.SUMMARY_SCHEMA_VERSION:
        raise G2AdjudicationError("E7 summary schema version differs")
    if summary["main_claims_manifest_id"] != config["main_claims_manifest_id"]:
        raise G2AdjudicationError("E7 summary main-claims binding differs")
    coverage = _mapping(summary["coverage"], "E7 coverage")
    required = {
        "aggregation_status": "VALID",
        "coverage_complete": True,
        "formal_execution_blockers": [],
        "invalid_point_ids": [],
        "missing_point_ids": [],
        "unexpected_point_ids": [],
        "duplicate_point_ids": {},
        "malformed_checkpoint_files": [],
        "formal_provenance_invalid": False,
        "provenance_class_invalid": False,
        "main_claims_manifest_id_conflict": False,
        "environment_conflict_curve_ids": [],
        "workload_identity_conflicts": [],
        "invalid_inference_curve_ids": [],
    }
    for field, expected in required.items():
        if coverage.get(field) != expected or type(coverage.get(field)) is not type(expected):
            raise G2AdjudicationError(f"E7 coverage {field} is not valid and complete")
    if coverage.get("expected_point_count") != len(rows):
        raise G2AdjudicationError("E7 expected point count differs from results")
    if coverage.get("observed_unique_point_count") != len(rows):
        raise G2AdjudicationError("E7 observed point count differs from results")
    expected_saturation = service_bench.summarize_saturation(rows)
    _same(expected_saturation, summary["saturation"], "E7 saturation summary")
    expected_capacity = service_bench.summarize_backend_invalid_capacity(
        rows, config["g4_capacity_contract"]
    )
    _same(
        expected_capacity,
        summary["backend_invalid_capacity"],
        "E7 backend-invalid capacity summary",
    )


def validate_service_evidence(
    *,
    config_path: Path,
    results_path: Path,
    summary_path: Path,
    registration_artifact: Mapping[str, Any],
    registration_binding: Mapping[str, Any],
) -> tuple[dict[str, Any], str, list[dict[str, Any]], dict[str, Any]]:
    try:
        config, config_hash = service_bench.load_config(config_path)
    except (KeyError, TypeError, ValueError) as error:
        raise G2AdjudicationError(f"invalid E7 config: {error}") from error
    blockers = service_bench.formal_execution_blockers(config)
    if blockers:
        raise G2AdjudicationError(f"E7 formal execution remains blocked: {blockers}")
    _same(
        registration_binding,
        config.get("phase1_baseline_registration"),
        "E7 Phase 1 registration binding",
    )
    _same(
        registration_artifact["selection"]["selected_filter"],
        config.get("filter"),
        "E7 selected filter",
    )
    contract = validate_g2_contract(config)
    rows = load_jsonl(results_path, "E7 results")
    expected_points = service_bench.enumerate_points(config)
    expected = {point.point_id(config_hash): point for point in expected_points}
    observed: dict[str, dict[str, Any]] = {}
    for row in rows:
        point_id = row.get("point_id")
        if type(point_id) is not str or point_id not in expected:
            raise G2AdjudicationError("E7 results contain an unexpected point")
        if point_id in observed:
            raise G2AdjudicationError(f"E7 results duplicate point {point_id}")
        try:
            service_bench._validate_result_contract(row, expected[point_id], config, config_hash)
        except (KeyError, OverflowError, TypeError, ValueError) as error:
            raise G2AdjudicationError(f"invalid E7 result {point_id}: {error}") from error
        if row.get("result_status") != "VALID":
            raise G2AdjudicationError(f"E7 result {point_id} is not a valid measurement")
        git = _mapping(row.get("git"), f"E7 result {point_id} git provenance")
        if git.get("dirty") is not False or git.get("status_available") is not True:
            raise G2AdjudicationError(f"E7 result {point_id} lacks clean Git provenance")
        observed[point_id] = row
    if set(observed) != set(expected):
        raise G2AdjudicationError("E7 results do not cover the full frozen grid")
    ordered = [observed[point.point_id(config_hash)] for point in expected_points]
    recomputed = copy.deepcopy(ordered)
    service_bench._assign_saturation(config, recomputed)
    _same(recomputed, ordered, "E7 result saturation annotations")
    summary = load_json(summary_path, "E7 summary")
    _validate_service_summary(summary, config, ordered)
    return config, config_hash, ordered, {"summary": summary, "contract": contract}


def _conditioned_pair_multiplicity(
    candidate: Mapping[str, Any],
    baseline: Mapping[str, Any],
    contract: Mapping[str, Any],
    context: str,
) -> int:
    paired_fields = (
        "false_positive_source",
        "conditioned_tuple_set_id",
        "conditioned_tuple_count",
        "invalid_tuple_multiplicity_commitment_id",
        "minimum_invalid_tuple_multiplicity",
        "underlying_filter_query_executed",
        "conditional_intervention_does_not_estimate_ffr",
    )
    for field in paired_fields:
        if canonical(candidate.get(field)) != canonical(baseline.get(field)):
            raise G2AdjudicationError(f"{context} differs on {field}")
    if candidate.get("false_positive_source") != contract["false_positive_source"]:
        raise G2AdjudicationError(f"{context} does not use the frozen conditioned tuples")
    if candidate.get("underlying_filter_query_executed") is not True:
        raise G2AdjudicationError(f"{context} did not execute the registered filter query")
    if candidate.get("conditional_intervention_does_not_estimate_ffr") is not True:
        raise G2AdjudicationError(f"{context} misstates the conditioned workload scope")
    conditioned_tuple_count = _integer(
        candidate.get("conditioned_tuple_count"),
        f"{context} conditioned tuple count",
        minimum=1,
    )
    if conditioned_tuple_count != contract["repeated_tuple_count"]:
        raise G2AdjudicationError(f"{context} has the wrong conditioned tuple count")
    distinct_invalid_count = _integer(
        candidate.get("distinct_invalid_count"),
        f"{context} distinct invalid count",
        minimum=1,
    )
    expected_conditioned_queries = min(conditioned_tuple_count, distinct_invalid_count)
    for field in ("conditioned_tuple_set_id", "invalid_tuple_multiplicity_commitment_id"):
        value = candidate.get(field)
        if (
            type(value) is not str
            or len(value) != 64
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise G2AdjudicationError(f"{context} has an invalid {field}")
    multiplicity = _integer(
        candidate.get("minimum_invalid_tuple_multiplicity"),
        f"{context} minimum invalid tuple multiplicity",
        minimum=0,
    )
    if multiplicity < contract["minimum_replay_multiplicity"]:
        raise G2AdjudicationError(f"{context} is below multiplicity 100")
    runtime = _mapping(
        candidate.get("conditional_intervention_runtime"),
        f"{context} conditional intervention runtime",
    )
    runtime_fields = {
        "underlying_query_count",
        "conditioned_query_count",
        "natural_positive_conditioned_query_count",
        "forced_positive_query_count",
        "intervention_applicable_to_method",
        "oracle_harness_memory_excluded_from_method_footprint",
    }
    if set(runtime) != runtime_fields:
        raise G2AdjudicationError(f"{context} conditional runtime schema differs")
    counts = {
        field: _integer(runtime.get(field), f"{context} {field}")
        for field in (
            "underlying_query_count",
            "conditioned_query_count",
            "natural_positive_conditioned_query_count",
            "forced_positive_query_count",
        )
    }
    if (
        runtime.get("intervention_applicable_to_method") is not True
        or runtime.get("oracle_harness_memory_excluded_from_method_footprint") is not True
        or counts["underlying_query_count"] < counts["conditioned_query_count"]
        or counts["conditioned_query_count"] != expected_conditioned_queries
        or counts["natural_positive_conditioned_query_count"]
        + counts["forced_positive_query_count"]
        != counts["conditioned_query_count"]
    ):
        raise G2AdjudicationError(f"{context} lacks complete underlying-query evidence")
    return multiplicity


def _p99_relation(
    *,
    profile: str,
    candidate_rows: list[Mapping[str, Any]],
    baseline_rows: list[Mapping[str, Any]],
    contract: Mapping[str, Any],
    relation_count: int,
) -> dict[str, Any]:
    candidates = {row["seed"]: row for row in candidate_rows}
    baselines = {row["seed"]: row for row in baseline_rows}
    expected_seeds = list(range(6100, 6120))
    if sorted(candidates) != expected_seeds or sorted(baselines) != expected_seeds:
        raise G2AdjudicationError(f"E7 p99 relation {profile} lacks all 20 paired seeds")
    logs: list[float] = []
    multiplicities: list[int] = []
    paired_observations: list[dict[str, Any]] = []
    for seed in expected_seeds:
        candidate = candidates[seed]
        baseline = baselines[seed]
        if candidate["dataset_hash"] != baseline["dataset_hash"]:
            raise G2AdjudicationError(f"E7 p99 relation {profile} workload IDs differ")
        if candidate.get("curve_environment_binding") != baseline.get("curve_environment_binding"):
            raise G2AdjudicationError(f"E7 p99 relation {profile} hardware/runtime bindings differ")
        if canonical(candidate.get("filter_realization")) != canonical(
            baseline.get("filter_realization")
        ):
            raise G2AdjudicationError(f"E7 p99 relation {profile} filter realizations differ")
        candidate_p99 = _finite(
            candidate.get("legitimate_p99_ms"), "candidate legitimate p99", positive=True
        )
        baseline_p99 = _finite(
            baseline.get("legitimate_p99_ms"), "baseline legitimate p99", positive=True
        )
        logs.append(math.log(candidate_p99 / baseline_p99))
        candidate_counters = _mapping(
            _mapping(candidate.get("phase_metrics"), "candidate phase_metrics").get("counters"),
            "candidate counters",
        )
        baseline_counters = _mapping(
            _mapping(baseline.get("phase_metrics"), "baseline phase_metrics").get("counters"),
            "baseline counters",
        )
        offered_candidate = _integer(
            candidate_counters.get("offered_invalid"), "candidate offered_invalid"
        )
        offered_baseline = _integer(
            baseline_counters.get("offered_invalid"), "baseline offered_invalid"
        )
        if offered_candidate != offered_baseline:
            raise G2AdjudicationError(f"E7 p99 relation {profile} offered loads differ")
        multiplicity = _conditioned_pair_multiplicity(
            candidate,
            baseline,
            contract,
            f"E7 p99 relation {profile}/{seed}",
        )
        multiplicities.append(multiplicity)
        paired_observations.append(
            {
                "seed": seed,
                "candidate_legitimate_p99_ms": candidate_p99,
                "baseline_legitimate_p99_ms": baseline_p99,
                "log_ratio": logs[-1],
                "observed_replay_multiplicity": multiplicity,
            }
        )
    mean_log = statistics.fmean(logs)
    standard_error = statistics.stdev(logs) / math.sqrt(len(logs))
    alpha_per_relation = contract["familywise_alpha"] / relation_count
    critical = float(student_t.ppf(1.0 - alpha_per_relation, len(logs) - 1))
    upper_log = mean_log + critical * standard_error
    threshold_log = math.log(contract["latency_margin_ratio"])
    if upper_log <= threshold_log:
        decision = "PASS_P99_NONINFERIOR"
    elif mean_log > threshold_log:
        decision = "FAIL_P99_NONINFERIOR"
    else:
        decision = "INDETERMINATE_P99_NONINFERIOR"
    return {
        "profile": profile,
        "paired_seed_count": len(logs),
        "paired_observations": paired_observations,
        "minimum_observed_replay_multiplicity": min(multiplicities),
        "mean_log_ratio": mean_log,
        "standard_error_log_ratio": standard_error,
        "student_t_critical": critical,
        "simultaneous_upper_log_ratio": upper_log,
        "geometric_mean_ratio": math.exp(mean_log),
        "simultaneous_upper_ratio_bound": math.exp(upper_log),
        "margin_ratio": contract["latency_margin_ratio"],
        "alpha_per_relation": alpha_per_relation,
        "decision": decision,
    }


def adjudicate_p99(
    rows: Sequence[Mapping[str, Any]], contract: Mapping[str, Any]
) -> dict[str, Any]:
    relations: list[dict[str, Any]] = []
    profiles = list(contract["verifier_profiles"])
    for profile in profiles:
        common = {
            "scenario": contract["scenario"],
            "profile": profile,
            "legitimate": contract["offered_legitimate_rps"],
            "invalid": contract["offered_invalid_rps"],
        }
        candidate = [
            row
            for row in rows
            if row["method"] == contract["candidate_method"]
            and row["scenario"] == common["scenario"]
            and row["verifier_profile"]["name"] == common["profile"]
            and row["offered_legitimate_rps"] == common["legitimate"]
            and row["offered_invalid_rps"] == common["invalid"]
        ]
        baseline = [
            row
            for row in rows
            if row["method"] == contract["baseline_method"]
            and row["scenario"] == common["scenario"]
            and row["verifier_profile"]["name"] == common["profile"]
            and row["offered_legitimate_rps"] == common["legitimate"]
            and row["offered_invalid_rps"] == common["invalid"]
        ]
        relations.append(
            _p99_relation(
                profile=profile,
                candidate_rows=candidate,
                baseline_rows=baseline,
                contract=contract,
                relation_count=len(profiles),
            )
        )
    counts = {
        "PASS_P99_NONINFERIOR": sum(
            relation["decision"] == "PASS_P99_NONINFERIOR" for relation in relations
        ),
        "FAIL_P99_NONINFERIOR": sum(
            relation["decision"] == "FAIL_P99_NONINFERIOR" for relation in relations
        ),
        "INDETERMINATE_P99_NONINFERIOR": sum(
            relation["decision"] == "INDETERMINATE_P99_NONINFERIOR" for relation in relations
        ),
    }
    if counts["FAIL_P99_NONINFERIOR"]:
        decision = "FAIL_E7_LEGITIMATE_P99"
    elif counts["INDETERMINATE_P99_NONINFERIOR"]:
        decision = "INDETERMINATE_E7_LEGITIMATE_P99"
    else:
        decision = "PASS_E7_LEGITIMATE_P99"
    return {
        "candidate_method": contract["candidate_method"],
        "baseline_method": contract["baseline_method"],
        "scenario": contract["scenario"],
        "offered_legitimate_rps": contract["offered_legitimate_rps"],
        "offered_invalid_rps": contract["offered_invalid_rps"],
        "familywise_alpha": contract["familywise_alpha"],
        "multiplicity_adjustment": contract["multiplicity_adjustment"],
        "relation_count": len(relations),
        "decision_counts": counts,
        "relations": relations,
        "decision": decision,
    }


def adjudicate_backend_work(
    rows: Sequence[Mapping[str, Any]], contract: Mapping[str, Any]
) -> dict[str, Any]:
    relations: list[dict[str, Any]] = []
    for profile in contract["verifier_profiles"]:
        candidate_rows = {
            row["seed"]: row
            for row in rows
            if row["method"] == contract["candidate_method"]
            and row["scenario"] == contract["scenario"]
            and row["verifier_profile"]["name"] == profile
            and row["offered_legitimate_rps"] == contract["offered_legitimate_rps"]
            and row["offered_invalid_rps"] == contract["offered_invalid_rps"]
        }
        baseline_rows = {
            row["seed"]: row
            for row in rows
            if row["method"] == contract["baseline_method"]
            and row["scenario"] == contract["scenario"]
            and row["verifier_profile"]["name"] == profile
            and row["offered_legitimate_rps"] == contract["offered_legitimate_rps"]
            and row["offered_invalid_rps"] == contract["offered_invalid_rps"]
        }
        expected_seeds = list(range(6100, 6120))
        if sorted(candidate_rows) != expected_seeds or sorted(baseline_rows) != expected_seeds:
            raise G2AdjudicationError(
                f"E7 backend-work relation {profile} lacks all 20 paired seeds"
            )
        for seed in expected_seeds:
            candidate = candidate_rows[seed]
            baseline = baseline_rows[seed]
            for field in ("dataset_hash", "curve_environment_binding", "filter_realization"):
                if canonical(candidate.get(field)) != canonical(baseline.get(field)):
                    raise G2AdjudicationError(
                        f"E7 backend-work relation {profile}/{seed} differs on {field}"
                    )
            candidate_checks = _integer(
                candidate.get("backend_invalid_checks"), "candidate backend invalid checks"
            )
            baseline_checks = _integer(
                baseline.get("backend_invalid_checks"), "baseline backend invalid checks"
            )
            candidate_distinct = _integer(
                candidate.get("distinct_invalid_count"),
                "candidate distinct invalid count",
                minimum=1,
            )
            baseline_distinct = _integer(
                baseline.get("distinct_invalid_count"),
                "baseline distinct invalid count",
                minimum=1,
            )
            if (
                candidate_distinct != baseline_distinct
                or candidate_distinct != contract["repeated_tuple_count"]
            ):
                raise G2AdjudicationError(
                    f"E7 backend-work relation {profile}/{seed} has the wrong tuple set"
                )
            candidate_counters = _mapping(
                _mapping(candidate.get("phase_metrics"), "candidate phase_metrics").get("counters"),
                "candidate counters",
            )
            baseline_counters = _mapping(
                _mapping(baseline.get("phase_metrics"), "baseline phase_metrics").get("counters"),
                "baseline counters",
            )
            offered_candidate = _integer(
                candidate_counters.get("offered_invalid"), "candidate offered invalid"
            )
            offered_baseline = _integer(
                baseline_counters.get("offered_invalid"), "baseline offered invalid"
            )
            if offered_candidate != offered_baseline:
                raise G2AdjudicationError(
                    f"E7 backend-work relation {profile}/{seed} offered loads differ"
                )
            minimum_multiplicity = _conditioned_pair_multiplicity(
                candidate,
                baseline,
                contract,
                f"E7 backend-work relation {profile}/{seed}",
            )
            if baseline_checks != offered_baseline:
                raise G2AdjudicationError(
                    f"E7 static relation {profile}/{seed} did not verify every known false positive"
                )
            checks_pass = 10 * candidate_checks <= 11 * candidate_distinct
            reduction_pass = candidate_checks == 0 or baseline_checks >= 10 * candidate_checks
            relations.append(
                {
                    "profile": profile,
                    "seed": seed,
                    "minimum_tuple_multiplicity": minimum_multiplicity,
                    "distinct_invalid_tuple_count": candidate_distinct,
                    "candidate_backend_invalid_checks": candidate_checks,
                    "baseline_backend_invalid_checks": baseline_checks,
                    "candidate_checks_per_tuple": candidate_checks / candidate_distinct,
                    "static_reduction_factor": (
                        None if candidate_checks == 0 else baseline_checks / candidate_checks
                    ),
                    "static_reduction_is_infinite": candidate_checks == 0,
                    "checks_per_tuple_le_1_1": checks_pass,
                    "static_reduction_ge_10x": reduction_pass,
                    "decision": (
                        "PASS_E7_SELECTED_FILTER_BACKEND_WORK"
                        if checks_pass and reduction_pass
                        else "FAIL_E7_SELECTED_FILTER_BACKEND_WORK"
                    ),
                }
            )
    failures = sum(
        relation["decision"] != "PASS_E7_SELECTED_FILTER_BACKEND_WORK" for relation in relations
    )
    return {
        "candidate_method": contract["candidate_method"],
        "baseline_method": contract["baseline_method"],
        "selected_filter_recomputed_in_e7": True,
        "relation_count": len(relations),
        "pass_count": len(relations) - failures,
        "fail_count": failures,
        "relations": relations,
        "decision": (
            "PASS_E7_SELECTED_FILTER_BACKEND_WORK"
            if not failures
            else "FAIL_E7_SELECTED_FILTER_BACKEND_WORK"
        ),
    }


def _gate_from_components(backend_decision: object, p99_decision: object) -> tuple[str, list[str]]:
    reasons: list[str] = []
    if backend_decision == "FAIL_E7_SELECTED_FILTER_BACKEND_WORK":
        reasons.append("E7_SELECTED_FILTER_BACKEND_WORK_CRITERIA_FAILED")
        has_failure = True
    elif backend_decision == "PASS_E7_SELECTED_FILTER_BACKEND_WORK":
        has_failure = False
    else:
        raise G2AdjudicationError("G2 receipt has an unsupported backend-work decision")
    has_indeterminate = False
    if p99_decision == "FAIL_E7_LEGITIMATE_P99":
        reasons.append("E7_LEGITIMATE_P99_REGRESSION_EXCEEDS_5_PERCENT")
        has_failure = True
    elif p99_decision == "INDETERMINATE_E7_LEGITIMATE_P99":
        reasons.append("E7_LEGITIMATE_P99_NONINFERIORITY_INDETERMINATE")
        has_indeterminate = True
    elif p99_decision != "PASS_E7_LEGITIMATE_P99":
        raise G2AdjudicationError("G2 receipt has an unsupported p99 decision")
    if has_failure:
        return FAIL, reasons
    if has_indeterminate:
        return INDETERMINATE, reasons
    return PASS, reasons


def _validate_decision_contract_value(value: object) -> dict[str, Any]:
    contract = _mapping(value, "G2 decision contract")
    expected = {
        "schema": G2_CONTRACT_SCHEMA,
        "candidate_method": E7_CANDIDATE,
        "baseline_method": E7_BASELINE,
        "scenario": "repeat_heavy_false_positive",
        "offered_legitimate_rps": 16,
        "offered_invalid_rps": 32,
        "verifier_profiles": ["pbkdf2_reference_310k", "argon2id_reference_19mib"],
        "repeated_tuple_count": 16,
        "minimum_replay_multiplicity": 100,
        "paired_seed_count": 20,
        "latency_margin_ratio": 1.05,
        "familywise_alpha": 0.05,
        "multiplicity_adjustment": ADJUSTMENT,
        "false_positive_source": "FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1",
        "underlying_filter_query_executed": True,
        "conditional_intervention_does_not_estimate_ffr": True,
    }
    _same(expected, contract, "G2 decision contract")
    return dict(contract)


def _validate_backend_component(value: object, contract: Mapping[str, Any]) -> dict[str, Any]:
    component = _mapping(value, "G2 backend-work component")
    fields = {
        "candidate_method",
        "baseline_method",
        "selected_filter_recomputed_in_e7",
        "relation_count",
        "pass_count",
        "fail_count",
        "relations",
        "decision",
    }
    if set(component) != fields:
        raise G2AdjudicationError("G2 backend-work component has the wrong fields")
    if (
        component["candidate_method"] != contract["candidate_method"]
        or component["baseline_method"] != contract["baseline_method"]
        or component["selected_filter_recomputed_in_e7"] is not True
    ):
        raise G2AdjudicationError("G2 backend-work component method binding differs")
    relations = component.get("relations")
    if type(relations) is not list:
        raise G2AdjudicationError("G2 backend-work relations must be a list")
    expected_coordinates = {
        (profile, seed) for profile in contract["verifier_profiles"] for seed in range(6100, 6120)
    }
    observed: set[tuple[str, int]] = set()
    relation_fields = {
        "profile",
        "seed",
        "minimum_tuple_multiplicity",
        "distinct_invalid_tuple_count",
        "candidate_backend_invalid_checks",
        "baseline_backend_invalid_checks",
        "candidate_checks_per_tuple",
        "static_reduction_factor",
        "static_reduction_is_infinite",
        "checks_per_tuple_le_1_1",
        "static_reduction_ge_10x",
        "decision",
    }
    failures = 0
    for relation in relations:
        item = _mapping(relation, "G2 backend-work relation")
        if set(item) != relation_fields:
            raise G2AdjudicationError("G2 backend-work relation has the wrong fields")
        coordinate = (
            item.get("profile"),
            _integer(item.get("seed"), "G2 backend-work seed"),
        )
        if coordinate in observed:
            raise G2AdjudicationError("G2 backend-work relation is duplicated")
        observed.add(coordinate)
        multiplicity = _integer(
            item.get("minimum_tuple_multiplicity"),
            "G2 backend-work multiplicity",
            minimum=contract["minimum_replay_multiplicity"],
        )
        distinct = _integer(
            item.get("distinct_invalid_tuple_count"),
            "G2 backend-work distinct tuples",
            minimum=1,
        )
        if distinct != contract["repeated_tuple_count"] or multiplicity < 100:
            raise G2AdjudicationError("G2 backend-work tuple contract differs")
        candidate = _integer(
            item.get("candidate_backend_invalid_checks"), "G2 candidate backend checks"
        )
        baseline = _integer(
            item.get("baseline_backend_invalid_checks"), "G2 baseline backend checks"
        )
        checks_pass = 10 * candidate <= 11 * distinct
        reduction_pass = candidate == 0 or baseline >= 10 * candidate
        expected_values = {
            "candidate_checks_per_tuple": candidate / distinct,
            "static_reduction_factor": None if candidate == 0 else baseline / candidate,
            "static_reduction_is_infinite": candidate == 0,
            "checks_per_tuple_le_1_1": checks_pass,
            "static_reduction_ge_10x": reduction_pass,
            "decision": (
                "PASS_E7_SELECTED_FILTER_BACKEND_WORK"
                if checks_pass and reduction_pass
                else "FAIL_E7_SELECTED_FILTER_BACKEND_WORK"
            ),
        }
        for field, expected in expected_values.items():
            if item.get(field) != expected or type(item.get(field)) is not type(expected):
                raise G2AdjudicationError(
                    f"G2 backend-work relation derived field differs: {field}"
                )
        failures += expected_values["decision"] != "PASS_E7_SELECTED_FILTER_BACKEND_WORK"
    if observed != expected_coordinates:
        raise G2AdjudicationError("G2 backend-work relation family is incomplete")
    expected_decision = (
        "PASS_E7_SELECTED_FILTER_BACKEND_WORK"
        if failures == 0
        else "FAIL_E7_SELECTED_FILTER_BACKEND_WORK"
    )
    if (
        component.get("relation_count") != len(relations)
        or component.get("pass_count") != len(relations) - failures
        or component.get("fail_count") != failures
        or component.get("decision") != expected_decision
    ):
        raise G2AdjudicationError("G2 backend-work component counts or decision differ")
    return dict(component)


def _validate_p99_component(value: object, contract: Mapping[str, Any]) -> dict[str, Any]:
    component = _mapping(value, "G2 p99 component")
    fields = {
        "candidate_method",
        "baseline_method",
        "scenario",
        "offered_legitimate_rps",
        "offered_invalid_rps",
        "familywise_alpha",
        "multiplicity_adjustment",
        "relation_count",
        "decision_counts",
        "relations",
        "decision",
    }
    if set(component) != fields:
        raise G2AdjudicationError("G2 p99 component has the wrong fields")
    for field in (
        "candidate_method",
        "baseline_method",
        "scenario",
        "offered_legitimate_rps",
        "offered_invalid_rps",
        "familywise_alpha",
        "multiplicity_adjustment",
    ):
        if component.get(field) != contract[field] or type(component.get(field)) is not type(
            contract[field]
        ):
            raise G2AdjudicationError(f"G2 p99 component binding differs: {field}")
    relations = component.get("relations")
    if type(relations) is not list:
        raise G2AdjudicationError("G2 p99 relations must be a list")
    relation_fields = {
        "profile",
        "paired_seed_count",
        "paired_observations",
        "minimum_observed_replay_multiplicity",
        "mean_log_ratio",
        "standard_error_log_ratio",
        "student_t_critical",
        "simultaneous_upper_log_ratio",
        "geometric_mean_ratio",
        "simultaneous_upper_ratio_bound",
        "margin_ratio",
        "alpha_per_relation",
        "decision",
    }
    observed_profiles: set[str] = set()
    counts = {
        "PASS_P99_NONINFERIOR": 0,
        "FAIL_P99_NONINFERIOR": 0,
        "INDETERMINATE_P99_NONINFERIOR": 0,
    }
    relation_count = len(contract["verifier_profiles"])
    alpha = contract["familywise_alpha"] / relation_count
    critical = float(student_t.ppf(1.0 - alpha, contract["paired_seed_count"] - 1))
    threshold = math.log(contract["latency_margin_ratio"])
    for relation in relations:
        item = _mapping(relation, "G2 p99 relation")
        if set(item) != relation_fields:
            raise G2AdjudicationError("G2 p99 relation has the wrong fields")
        profile = item.get("profile")
        if type(profile) is not str or profile in observed_profiles:
            raise G2AdjudicationError("G2 p99 relation profile is invalid or duplicated")
        observed_profiles.add(profile)
        observations = item.get("paired_observations")
        if type(observations) is not list:
            raise G2AdjudicationError("G2 p99 paired observations must be a list")
        observation_fields = {
            "seed",
            "candidate_legitimate_p99_ms",
            "baseline_legitimate_p99_ms",
            "log_ratio",
            "observed_replay_multiplicity",
        }
        logs: list[float] = []
        multiplicities: list[int] = []
        observed_seeds: set[int] = set()
        for observation in observations:
            pair = _mapping(observation, "G2 p99 paired observation")
            if set(pair) != observation_fields:
                raise G2AdjudicationError("G2 p99 paired observation has the wrong fields")
            seed = _integer(pair.get("seed"), "G2 p99 paired seed")
            if seed in observed_seeds:
                raise G2AdjudicationError("G2 p99 paired seed is duplicated")
            observed_seeds.add(seed)
            candidate_p99 = _finite(
                pair.get("candidate_legitimate_p99_ms"),
                "G2 paired candidate p99",
                positive=True,
            )
            baseline_p99 = _finite(
                pair.get("baseline_legitimate_p99_ms"),
                "G2 paired baseline p99",
                positive=True,
            )
            log_ratio = math.log(candidate_p99 / baseline_p99)
            if pair.get("log_ratio") != log_ratio or type(pair.get("log_ratio")) is not float:
                raise G2AdjudicationError("G2 p99 paired log ratio differs")
            logs.append(log_ratio)
            multiplicities.append(
                _integer(
                    pair.get("observed_replay_multiplicity"),
                    "G2 paired replay multiplicity",
                    minimum=contract["minimum_replay_multiplicity"],
                )
            )
        expected_seeds = set(range(6100, 6120))
        if observed_seeds != expected_seeds:
            raise G2AdjudicationError("G2 p99 paired seed family is incomplete")
        if (
            item.get("paired_seed_count") != len(observations)
            or len(observations) != contract["paired_seed_count"]
            or item.get("minimum_observed_replay_multiplicity") != min(multiplicities)
        ):
            raise G2AdjudicationError("G2 p99 paired count or multiplicity differs")
        mean = statistics.fmean(logs)
        standard_error = statistics.stdev(logs) / math.sqrt(len(logs))
        upper = mean + critical * standard_error
        if upper <= threshold:
            decision = "PASS_P99_NONINFERIOR"
        elif mean > threshold:
            decision = "FAIL_P99_NONINFERIOR"
        else:
            decision = "INDETERMINATE_P99_NONINFERIOR"
        expected_values = {
            "mean_log_ratio": mean,
            "standard_error_log_ratio": standard_error,
            "student_t_critical": critical,
            "simultaneous_upper_log_ratio": upper,
            "geometric_mean_ratio": math.exp(mean),
            "simultaneous_upper_ratio_bound": math.exp(upper),
            "margin_ratio": contract["latency_margin_ratio"],
            "alpha_per_relation": alpha,
            "decision": decision,
        }
        for field, expected in expected_values.items():
            if item.get(field) != expected or type(item.get(field)) is not type(expected):
                raise G2AdjudicationError(f"G2 p99 relation derived field differs: {field}")
        counts[decision] += 1
    if observed_profiles != set(contract["verifier_profiles"]):
        raise G2AdjudicationError("G2 p99 relation family is incomplete")
    if counts["FAIL_P99_NONINFERIOR"]:
        decision = "FAIL_E7_LEGITIMATE_P99"
    elif counts["INDETERMINATE_P99_NONINFERIOR"]:
        decision = "INDETERMINATE_E7_LEGITIMATE_P99"
    else:
        decision = "PASS_E7_LEGITIMATE_P99"
    if (
        component.get("relation_count") != len(relations)
        or component.get("decision_counts") != counts
        or component.get("decision") != decision
    ):
        raise G2AdjudicationError("G2 p99 component counts or decision differ")
    return dict(component)


def build_receipt(
    *,
    e4: Mapping[str, Any],
    registration_artifact: Mapping[str, Any],
    service_config: Mapping[str, Any],
    service_config_id: str,
    service_rows: Sequence[Mapping[str, Any]],
    service_summary: Mapping[str, Any],
    g2_contract: Mapping[str, Any],
    analysis_source_state: Mapping[str, Any],
) -> dict[str, Any]:
    e4_result = validate_e4_aggregate(e4)
    backend_work = adjudicate_backend_work(service_rows, g2_contract)
    p99 = adjudicate_p99(service_rows, g2_contract)
    gate, reasons = _gate_from_components(backend_work["decision"], p99["decision"])
    phase1_boundary = _phase1_registration_boundary(registration_artifact)
    phase1 = registration_artifact["phase1_evidence"]
    selection = registration_artifact["selection"]
    commits = sorted({row["commit"] for row in service_rows})
    if len(commits) != 1:
        raise G2AdjudicationError("E7 results must bind one source commit")
    body: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "validation_status": VALID,
        "analysis_source_state": dict(analysis_source_state),
        "g2_gate_status": gate,
        "promotion_eligible": gate == PASS,
        "reason_codes": reasons,
        "bindings": {
            "phase1_registration_id": registration_artifact["registration_id"],
            "phase1_registration_status": phase1_boundary["status"],
            "phase1_recovery_scope": phase1_boundary["recovery_scope"],
            "phase1_receipt_id": phase1["receipt_id"],
            "phase1_aggregate_id": phase1["aggregate_id"],
            "phase1_selected_spec_id": selection["selected_spec_id"],
            "phase1_selected_spec_identity": selection["selected_spec_identity"],
            "phase1_selected_filter": selection["selected_filter"],
            "e4_aggregate_id": e4_result["aggregate_id"],
            "e4_source_commit": e4_result["source_commit"],
            "e7_config_id": service_config_id,
            "e7_main_claims_manifest_id": service_config["main_claims_manifest_id"],
            "e7_results_id": semantic_id(list(service_rows)),
            "e7_summary_id": semantic_id(service_summary),
            "e7_source_commit": commits[0],
        },
        "decision_contract": dict(g2_contract),
        "e4_replay_component": e4_result,
        "e7_selected_filter_backend_work_component": backend_work,
        "e7_legitimate_p99_component": p99,
        "scientific_scope": (
            "Repeated known false-positive tuples with multiplicity >=100 under the frozen "
            "synthetic E4/E7 deployment profile; no user-prevalence or unique-first-seen claim"
        ),
        "claim_disposition": {
            "c2_status": "PASS" if gate == PASS else "BLOCKED",
            "g2_status": "PASS" if gate == PASS else gate,
            "phase1_service_baseline_recovery": (
                phase1_boundary["recovery_scope"] == SERVICE_RECOVERY_SCOPE
            ),
            "g1_g4_g5_g8_affected": False,
        },
    }
    return {**body, "receipt_id": semantic_id(body)}


def _validate_receipt_bindings(value: object, e4_component: Mapping[str, Any]) -> dict[str, Any]:
    bindings = _mapping(value, "G2 receipt bindings")
    fields = {
        "phase1_registration_id",
        "phase1_registration_status",
        "phase1_recovery_scope",
        "phase1_receipt_id",
        "phase1_aggregate_id",
        "phase1_selected_spec_id",
        "phase1_selected_spec_identity",
        "phase1_selected_filter",
        "e4_aggregate_id",
        "e4_source_commit",
        "e7_config_id",
        "e7_main_claims_manifest_id",
        "e7_results_id",
        "e7_summary_id",
        "e7_source_commit",
    }
    if set(bindings) != fields:
        raise G2AdjudicationError("G2 receipt bindings have the wrong fields")
    for field in (
        "phase1_registration_id",
        "phase1_receipt_id",
        "phase1_aggregate_id",
        "phase1_selected_spec_id",
        "e4_aggregate_id",
        "e7_config_id",
        "e7_results_id",
        "e7_summary_id",
    ):
        _hex64(bindings.get(field), f"G2 binding {field}")
    for field in ("e4_source_commit", "e7_source_commit"):
        commit = bindings.get(field)
        if type(commit) is not str or len(commit) != 40 or set(commit) - HEX:
            raise G2AdjudicationError(f"G2 binding {field} is not a lowercase commit")
    status = bindings.get("phase1_registration_status")
    if status == registration.REGISTERED:
        if bindings.get("phase1_recovery_scope") is not None:
            raise G2AdjudicationError("G2 P0 binding unexpectedly declares recovery scope")
    elif status == registration.RECOVERY_REGISTERED:
        if bindings.get("phase1_recovery_scope") != SERVICE_RECOVERY_SCOPE:
            raise G2AdjudicationError("G2 recovery binding lacks the service-only scope")
    else:
        raise G2AdjudicationError("G2 Phase 1 registration status is unsupported")
    manifest_id = bindings.get("e7_main_claims_manifest_id")
    if type(manifest_id) is not str or not manifest_id.startswith("sha256:"):
        raise G2AdjudicationError("G2 binding main-claims ID is malformed")
    _hex64(manifest_id.removeprefix("sha256:"), "G2 binding main-claims digest")
    if (
        bindings["e4_aggregate_id"] != e4_component["aggregate_id"]
        or bindings["e4_source_commit"] != e4_component["source_commit"]
    ):
        raise G2AdjudicationError("G2 E4 binding contradicts the replay component")
    identity_text = bindings.get("phase1_selected_spec_identity")
    if type(identity_text) is not str:
        raise G2AdjudicationError("G2 selected spec identity must be canonical JSON text")
    try:
        identity = json.loads(
            identity_text,
            object_pairs_hook=lambda pairs: _unique_pairs(pairs, "selected spec identity"),
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeError) as error:
        raise G2AdjudicationError("G2 selected spec identity is invalid JSON") from error
    identity = _mapping(identity, "G2 selected spec identity")
    if set(identity) != {"family", "parameters"}:
        raise G2AdjudicationError("G2 selected spec identity has the wrong fields")
    parameters = _mapping(identity["parameters"], "G2 selected spec parameters")
    selected_filter = {"family": identity["family"], **parameters}
    _same(selected_filter, bindings["phase1_selected_filter"], "G2 selected filter binding")
    try:
        service_bench.FrozenScreenSpec.from_config(selected_filter)
    except (KeyError, TypeError, ValueError) as error:
        raise G2AdjudicationError("G2 selected filter is unsupported") from error
    return dict(bindings)


def validate_receipt(
    receipt: Mapping[str, Any],
    *,
    e4: Mapping[str, Any],
    registration_artifact: Mapping[str, Any],
    service_config: Mapping[str, Any],
    service_config_id: str,
    service_rows: Sequence[Mapping[str, Any]],
    service_summary: Mapping[str, Any],
    g2_contract: Mapping[str, Any],
    analysis_source_state: Mapping[str, Any],
) -> dict[str, Any]:
    value = _mapping(dict(receipt), "G2 receipt")
    fields = {
        "schema",
        "validation_status",
        "analysis_source_state",
        "g2_gate_status",
        "promotion_eligible",
        "reason_codes",
        "bindings",
        "decision_contract",
        "e4_replay_component",
        "e7_selected_filter_backend_work_component",
        "e7_legitimate_p99_component",
        "scientific_scope",
        "claim_disposition",
        "receipt_id",
    }
    if set(value) != fields:
        raise G2AdjudicationError("G2 receipt has the wrong fields")
    if value["schema"] != RECEIPT_SCHEMA or value["validation_status"] != VALID:
        raise G2AdjudicationError("G2 receipt schema or validation status differs")
    source_state = _mapping(value["analysis_source_state"], "G2 analysis source state")
    if set(source_state) != {"commit", "clean", "scope"}:
        raise G2AdjudicationError("G2 analysis source state has the wrong fields")
    if (
        type(source_state["commit"]) is not str
        or len(source_state["commit"]) != 40
        or any(character not in HEX for character in source_state["commit"])
        or source_state["clean"] is not True
        or source_state["scope"] != ANALYSIS_SOURCE_SCOPE
    ):
        raise G2AdjudicationError("G2 analysis source state is not a clean frozen commit")
    body = {key: item for key, item in value.items() if key != "receipt_id"}
    if value["receipt_id"] != semantic_id(body):
        raise G2AdjudicationError("G2 receipt ID does not recompute")
    contract = _validate_decision_contract_value(value["decision_contract"])
    expected_e4 = validate_e4_aggregate(load_json(E4_AGGREGATE_PATH, "retained E4 aggregate"))
    e4_component = _mapping(value["e4_replay_component"], "G2 E4 component")
    _same(expected_e4, e4_component, "G2 retained E4 component")
    backend_component = _validate_backend_component(
        value["e7_selected_filter_backend_work_component"], contract
    )
    p99_component = _validate_p99_component(value["e7_legitimate_p99_component"], contract)
    _validate_receipt_bindings(value["bindings"], e4_component)
    gate, reasons = _gate_from_components(backend_component["decision"], p99_component["decision"])
    if value["g2_gate_status"] != gate:
        raise G2AdjudicationError("G2 receipt gate contradicts component decisions")
    if value["promotion_eligible"] is not (gate == PASS):
        raise G2AdjudicationError("G2 receipt promotion flag contradicts the gate")
    if value["reason_codes"] != reasons:
        raise G2AdjudicationError("G2 receipt reason codes contradict the gate")
    disposition = _mapping(value["claim_disposition"], "G2 claim disposition")
    expected_disposition = {
        "c2_status": "PASS" if gate == PASS else "BLOCKED",
        "g2_status": "PASS" if gate == PASS else gate,
        "phase1_service_baseline_recovery": (
            value["bindings"]["phase1_recovery_scope"] == SERVICE_RECOVERY_SCOPE
        ),
        "g1_g4_g5_g8_affected": False,
    }
    _same(expected_disposition, disposition, "G2 claim disposition")
    expected_scope = (
        "Repeated known false-positive tuples with multiplicity >=100 under the frozen "
        "synthetic E4/E7 deployment profile; no user-prevalence or unique-first-seen claim"
    )
    if value["scientific_scope"] != expected_scope:
        raise G2AdjudicationError("G2 receipt scientific scope differs")
    expected = build_receipt(
        e4=e4,
        registration_artifact=registration_artifact,
        service_config=service_config,
        service_config_id=service_config_id,
        service_rows=service_rows,
        service_summary=service_summary,
        g2_contract=g2_contract,
        analysis_source_state=analysis_source_state,
    )
    _same(expected, value, "G2 receipt and bound evidence")
    return value


def _write_exclusive(
    path: Path,
    value: Mapping[str, Any],
    *,
    before_publish: Callable[[], None] | None = None,
) -> None:
    if path.exists() or path.is_symlink():
        raise G2AdjudicationError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="ascii", newline="\n") as handle:
            json.dump(value, handle, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if before_publish is not None:
            before_publish()
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise G2AdjudicationError(f"refusing to overwrite {path}") from error
    finally:
        temporary.unlink(missing_ok=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = _StrictArgumentParser(description=__doc__)
    parser.add_argument("--e4-aggregate", type=Path, required=True)
    parser.add_argument("--phase1-registration", type=Path, required=True)
    parser.add_argument("--service-config", type=Path, required=True)
    parser.add_argument("--service-results", type=Path, required=True)
    parser.add_argument("--service-summary", type=Path, required=True)
    parser.add_argument("--expected-analysis-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        analysis_source_state = _require_analysis_checkout(args.expected_analysis_commit)
        e4 = load_json(args.e4_aggregate, "E4 aggregate")
        artifact, binding = validate_registration_artifact(args.phase1_registration)
        config, config_id, rows, service = validate_service_evidence(
            config_path=args.service_config,
            results_path=args.service_results,
            summary_path=args.service_summary,
            registration_artifact=artifact,
            registration_binding=binding,
        )
        receipt = build_receipt(
            e4=e4,
            registration_artifact=artifact,
            service_config=config,
            service_config_id=config_id,
            service_rows=rows,
            service_summary=service["summary"],
            g2_contract=service["contract"],
            analysis_source_state=analysis_source_state,
        )
        validate_receipt(
            receipt,
            e4=e4,
            registration_artifact=artifact,
            service_config=config,
            service_config_id=config_id,
            service_rows=rows,
            service_summary=service["summary"],
            g2_contract=service["contract"],
            analysis_source_state=analysis_source_state,
        )

        def require_completion_state() -> None:
            _same(
                analysis_source_state,
                _require_analysis_checkout(args.expected_analysis_commit),
                "G2 analysis source completion state",
            )

        _write_exclusive(args.output, receipt, before_publish=require_completion_state)
    except (G2AdjudicationError, KeyError, OSError, TypeError, ValueError) as error:
        print(
            canonical(
                {
                    "schema": RECEIPT_SCHEMA,
                    "status": "INVALID",
                    "error": str(error),
                }
            ),
            file=sys.stderr,
        )
        return EXIT_INVALID
    print(
        canonical(
            {
                "status": receipt["validation_status"],
                "g2_gate_status": receipt["g2_gate_status"],
                "receipt_id": receipt["receipt_id"],
                "output": str(args.output.resolve()),
            }
        )
    )
    return EXIT_PASS if receipt["promotion_eligible"] else EXIT_NONPROMOTABLE


if __name__ == "__main__":
    raise SystemExit(main())
