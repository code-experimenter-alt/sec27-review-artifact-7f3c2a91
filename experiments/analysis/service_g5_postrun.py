"""Independently adjudicate G5 from the frozen formal E7 service grid."""

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
from experiments.runners import service_bench  # noqa: E402

RECEIPT_SCHEMA = "traps-e7-g5-adjudication-receipt-v2"
CONTRACT_SCHEMA = "traps-g5-e7-formal-gate-v2"
VALID = "VALID"
PASS = "PASS_G5_SERVICE_LEVEL"
FAIL = "FAIL_G5_SERVICE_LEVEL"
INDETERMINATE = "INDETERMINATE_G5_SERVICE_LEVEL"
EXIT_PASS = 0
EXIT_NONPROMOTABLE = 2
EXIT_INVALID = 3
ANALYSIS_SOURCE_SCOPE = "REPOSITORY_EXCLUDING_EXPERIMENT_OUTPUTS"

SATURATION_PASS = "PASS_G5_SATURATION_SUPERIORITY"
SATURATION_FAIL = "FAIL_G5_SATURATION_SUPERIORITY"
SATURATION_INDETERMINATE = "INDETERMINATE_G5_SATURATION_SUPERIORITY"
P99_PASS = "PASS_G5_P99_NONINFERIORITY"
P99_FAIL = "FAIL_G5_P99_NONINFERIORITY"
P99_INDETERMINATE = "INDETERMINATE_G5_P99_NONINFERIORITY"
RESOURCE_PASS = "PASS_G5_BOUNDED_RESOURCES"
RESOURCE_FAIL = "FAIL_G5_BOUNDED_RESOURCES"
RESOURCE_INDETERMINATE = "INDETERMINATE_G5_BOUNDED_RESOURCES"
SERVICE_RECOVERY_SCOPE = registration.RECOVERY_SCOPE

CANDIDATE = "frozen_screen_exact_cache_lru"
BASELINE = "static_frozen_screen_mechanism_baseline"
REPEAT_SCENARIO = "repeat_heavy_false_positive"
UNIQUE_SCENARIO = "unique_first_seen_false_positive"
PROFILES = ("pbkdf2_reference_310k", "argon2id_reference_19mib")
SEEDS = tuple(range(6100, 6120))
INVALID_GRID = (0, 32, 64, 96, 128, 192, 256, 384, 512)
HEX = frozenset("0123456789abcdef")
RESOURCE_ONLY_INVALID_REASONS = frozenset(
    {"RESOURCE_SAMPLING_INCOMPLETE", "INSUFFICIENT_RESOURCE_SAMPLES"}
)
RESOURCE_FINAL_STATE_INVALID_REASONS = frozenset(
    {
        "MEASUREMENT_DRAIN_TIMEOUT",
        "PENDING_REQUESTS_AFTER_SHUTDOWN",
        "OVERDUE_REQUESTS_AFTER_SHUTDOWN",
        "UNCLEAN_SHUTDOWN",
    }
)
ANALYZABLE_G5_INVALID_REASONS = RESOURCE_ONLY_INVALID_REASONS | RESOURCE_FINAL_STATE_INVALID_REASONS

EXPECTED_CONTRACT: dict[str, Any] = {
    "schema": CONTRACT_SCHEMA,
    "candidate_method": CANDIDATE,
    "matched_baseline_method": BASELINE,
    "scenario": REPEAT_SCENARIO,
    "verifier_profiles": list(PROFILES),
    "paired_seed_count": 20,
    "offered_legitimate_rps": 16,
    "offered_invalid_rps_grid": list(INVALID_GRID),
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


class G5AdjudicationError(ValueError):
    """Raised when an E7/G5 evidence package is malformed or incomplete."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise G5AdjudicationError(f"invalid CLI: {message}")


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise G5AdjudicationError(f"{label} must be a string-keyed object")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise G5AdjudicationError(f"{label} must be an integer >= {minimum}")
    return value


def _number(value: object, label: str, *, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise G5AdjudicationError(f"{label} must be numeric")
    result = float(value)
    if not math.isfinite(result) or (positive and result <= 0.0):
        qualifier = "positive and finite" if positive else "finite"
        raise G5AdjudicationError(f"{label} must be {qualifier}")
    return result


def _hex(value: object, label: str, length: int) -> str:
    if type(value) is not str or len(value) != length or set(value) - HEX:
        raise G5AdjudicationError(f"{label} must be {length} lowercase hexadecimal characters")
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
        raise G5AdjudicationError("value is not canonical JSON data") from error


def semantic_id(value: object) -> str:
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def _is_resource_only_invalid(row: Mapping[str, Any]) -> bool:
    reasons = row.get("invalid_reasons")
    return (
        row.get("result_status") == "INVALID"
        and type(reasons) is list
        and bool(reasons)
        and all(type(reason) is str for reason in reasons)
        and set(reasons).issubset(RESOURCE_ONLY_INVALID_REASONS)
    )


def _has_resource_observation_gap(row: Mapping[str, Any]) -> bool:
    reasons = row.get("invalid_reasons")
    return (
        row.get("result_status") == "INVALID"
        and type(reasons) is list
        and any(reason in RESOURCE_ONLY_INVALID_REASONS for reason in reasons)
    )


def _is_analyzable_g5_invalid(row: Mapping[str, Any]) -> bool:
    reasons = row.get("invalid_reasons")
    return (
        row.get("result_status") == "INVALID"
        and type(reasons) is list
        and bool(reasons)
        and all(type(reason) is str for reason in reasons)
        and set(reasons).issubset(ANALYZABLE_G5_INVALID_REASONS)
    )


def _same(expected: object, observed: object, label: str) -> None:
    if type(expected) is not type(observed) or canonical(expected) != canonical(observed):
        raise G5AdjudicationError(f"{label} differs from strict recomputation")


def _unique_pairs(pairs: list[tuple[str, Any]], label: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise G5AdjudicationError(f"duplicate JSON key in {label}: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise G5AdjudicationError(f"non-finite JSON constant: {value}")


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=lambda pairs: _unique_pairs(pairs, label),
            parse_constant=_reject_constant,
        )
    except G5AdjudicationError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise G5AdjudicationError(f"cannot load {label}: {error}") from error
    return _mapping(value, label)


def load_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    raise G5AdjudicationError(f"blank line in {label} at {line_number}")
                try:
                    value = json.loads(
                        line,
                        object_pairs_hook=lambda pairs, n=line_number: _unique_pairs(
                            pairs, f"{label}:{n}"
                        ),
                        parse_constant=_reject_constant,
                    )
                except json.JSONDecodeError as error:
                    raise G5AdjudicationError(
                        f"invalid JSON in {label} at {line_number}: {error}"
                    ) from error
                rows.append(_mapping(value, f"{label}:{line_number}"))
    except G5AdjudicationError:
        raise
    except (OSError, UnicodeError) as error:
        raise G5AdjudicationError(f"cannot load {label}: {error}") from error
    if not rows:
        raise G5AdjudicationError(f"{label} is empty")
    return rows


def _require_analysis_checkout(expected_commit: str, *, root: Path = ROOT) -> dict[str, Any]:
    _hex(expected_commit, "expected analysis commit", 40)
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
        raise G5AdjudicationError("analysis Git provenance is unavailable") from error
    if commit != expected_commit:
        raise G5AdjudicationError("analysis checkout commit differs from the frozen commit")
    if status.strip():
        raise G5AdjudicationError("analysis checkout is dirty in the frozen source scope")
    return {"commit": commit, "clean": True, "scope": ANALYSIS_SOURCE_SCOPE}


def validate_registration_artifact(
    artifact_path: Path, *, root: Path = ROOT
) -> tuple[dict[str, Any], dict[str, Any]]:
    artifact = registration.load_strict_json(artifact_path, "Phase 1 registration artifact")
    try:
        relative = artifact_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise G5AdjudicationError("registration artifact must be inside the repository") from error
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
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise G5AdjudicationError(f"invalid Phase 1 registration: {error}") from error
    return artifact, binding


def _phase1_registration_boundary(artifact: Mapping[str, Any]) -> dict[str, Any]:
    status = artifact.get("status")
    evidence = _mapping(artifact.get("phase1_evidence"), "Phase 1 evidence binding")
    selection = _mapping(artifact.get("selection"), "Phase 1 selection")
    if status == registration.REGISTERED:
        if artifact.get("schema") != registration.REGISTRATION_SCHEMA:
            raise G5AdjudicationError("Phase 1 registration schema differs")
        if evidence.get("p0_eligible") is not True:
            raise G5AdjudicationError("Phase 1 registration is not P0 eligible")
        if evidence.get("recovery_scope") is not None:
            raise G5AdjudicationError("P0 registration unexpectedly declares recovery scope")
        if selection.get("policy") != registration.SELECTION_POLICY:
            raise G5AdjudicationError("P0 registration selection policy differs")
        return {"status": status, "recovery_scope": None}
    if status == registration.RECOVERY_REGISTERED:
        if artifact.get("schema") != registration.RECOVERY_REGISTRATION_SCHEMA:
            raise G5AdjudicationError("Phase 1 recovery registration schema differs")
        if evidence.get("p0_eligible") is not False:
            raise G5AdjudicationError("Phase 1 recovery registration must remain non-P0")
        if evidence.get("validation_status") != "VALID_BUT_NONPROMOTABLE":
            raise G5AdjudicationError("Phase 1 recovery must bind the nonpromotable receipt")
        if evidence.get("recovery_scope") != SERVICE_RECOVERY_SCOPE:
            raise G5AdjudicationError("Phase 1 recovery scope is not service-only")
        if selection.get("policy") != registration.RECOVERY_SELECTION_POLICY:
            raise G5AdjudicationError("Phase 1 recovery selection policy differs")
        return {"status": status, "recovery_scope": SERVICE_RECOVERY_SCOPE}
    raise G5AdjudicationError("Phase 1 baseline is not registered")


def validate_g5_contract(config: Mapping[str, Any]) -> dict[str, Any]:
    observed = _mapping(config.get("g5_gate_contract"), "g5_gate_contract")
    _same(EXPECTED_CONTRACT, observed, "g5_gate_contract")
    if observed != service_bench.G5_GATE_CONTRACT:
        raise G5AdjudicationError("runner and adjudicator G5 contracts differ")
    if config.get("seeds") != list(SEEDS):
        raise G5AdjudicationError("G5 requires the frozen 20-seed service family")
    if config.get("verifier", {}).get("enabled_profiles") != list(PROFILES):
        raise G5AdjudicationError("G5 requires both frozen KDF profiles")
    if config.get("loads", {}).get("legitimate_rps") != [16]:
        raise G5AdjudicationError("G5 requires offered legitimate load 16")
    if config.get("loads", {}).get("invalid_rps") != list(INVALID_GRID):
        raise G5AdjudicationError("G5 invalid-load grid differs from the freeze")
    if config.get("scenarios") != [REPEAT_SCENARIO, UNIQUE_SCENARIO]:
        raise G5AdjudicationError("G5 requires repeat-heavy and unique-first-seen families")
    declarations = {
        str(item.get("name")): item
        for item in config.get("methods", [])
        if isinstance(item, Mapping)
    }
    candidate = declarations.get(CANDIDATE)
    baseline = declarations.get(BASELINE)
    if candidate is None or {
        "implementation": candidate.get("implementation"),
        "cache_policy": candidate.get("cache_policy"),
        "use_singleflight": candidate.get("use_singleflight"),
    } != {
        "implementation": "frozen_screen_exact_negative_cache_lru_singleflight_v1",
        "cache_policy": "lru",
        "use_singleflight": True,
    }:
        raise G5AdjudicationError("G5 candidate is not frozen exact LRU plus singleflight")
    if baseline is None or {
        "implementation": baseline.get("implementation"),
        "cache_policy": baseline.get("cache_policy"),
        "use_singleflight": baseline.get("use_singleflight"),
    } != {
        "implementation": "static_frozen_screen_v1",
        "cache_policy": None,
        "use_singleflight": False,
    }:
        raise G5AdjudicationError("G5 baseline is not the frozen matched static screen")
    try:
        manifest, manifest_id = service_bench.load_main_claims_manifest(
            service_bench.MAIN_CLAIMS_PATH,
            paper_claims_path=service_bench.PAPER_CLAIMS_PATH,
        )
    except (OSError, TypeError, ValueError) as error:
        raise G5AdjudicationError(f"cannot load frozen main claims: {error}") from error
    service_contract = _mapping(manifest.get("service_e7_contract"), "service_e7_contract")
    if service_contract.get("freeze_status") != "PREREGISTERED_BEFORE_FORMAL_E7_COLLECTION":
        raise G5AdjudicationError("main-claims E7 contract is not prospectively frozen")
    _same(EXPECTED_CONTRACT, service_contract.get("g5_gate_contract"), "main-claims G5 contract")
    if config.get("main_claims_manifest_id") != manifest_id:
        raise G5AdjudicationError("service config does not bind the current main-claims manifest")
    return dict(observed)


def _coverage_is_complete(
    summary: Mapping[str, Any], config: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]
) -> None:
    expected_fields = {
        "schema_version",
        "main_claims_manifest_id",
        "coverage",
        "saturation",
        "backend_invalid_capacity",
    }
    if set(summary) != expected_fields:
        raise G5AdjudicationError("E7 summary has the wrong fields")
    if summary.get("schema_version") != service_bench.SUMMARY_SCHEMA_VERSION:
        raise G5AdjudicationError("E7 summary schema version differs")
    if summary.get("main_claims_manifest_id") != config["main_claims_manifest_id"]:
        raise G5AdjudicationError("E7 summary main-claims binding differs")
    coverage = _mapping(summary.get("coverage"), "E7 summary coverage")
    analyzable_invalid_ids = sorted(
        str(row["point_id"]) for row in rows if _is_analyzable_g5_invalid(row)
    )
    invalid_curve_statuses = {
        "INVALID_MEASUREMENT_ROWS",
        "BASELINE_REFERENCE_INVALID",
        "NON_MONOTONIC_INVALID",
    }
    invalid_curve_ids = sorted(
        {
            str(row.get("curve_id"))
            for row in rows
            if row.get("service_saturation_status") in invalid_curve_statuses
        }
    )
    required = {
        "aggregation_status": (
            "INVALID" if analyzable_invalid_ids or invalid_curve_ids else "VALID"
        ),
        "coverage_complete": True,
        "formal_execution_blockers": [],
        "invalid_point_ids": analyzable_invalid_ids,
        "missing_point_ids": [],
        "unexpected_point_ids": [],
        "duplicate_point_ids": {},
        "malformed_checkpoint_files": [],
        "formal_provenance_invalid": False,
        "provenance_class_invalid": False,
        "main_claims_manifest_id_conflict": False,
        "environment_conflict_curve_ids": [],
        "workload_identity_conflicts": [],
        "invalid_inference_curve_ids": invalid_curve_ids,
    }
    for field, expected in required.items():
        if type(coverage.get(field)) is not type(expected) or coverage.get(field) != expected:
            raise G5AdjudicationError(f"E7 coverage {field} is not valid and complete")
    if coverage.get("expected_point_count") != len(rows):
        raise G5AdjudicationError("E7 expected point count differs from results")
    if coverage.get("observed_unique_point_count") != len(rows):
        raise G5AdjudicationError("E7 observed point count differs from results")
    if coverage.get("main_claims_manifest_id") != config["main_claims_manifest_id"]:
        raise G5AdjudicationError("E7 coverage main-claims binding differs")
    if coverage.get("observed_main_claims_manifest_ids") != [config["main_claims_manifest_id"]]:
        raise G5AdjudicationError("E7 coverage contains a different main-claims identity")
    expected_saturation = service_bench.summarize_saturation(rows)
    expected_capacity = service_bench.summarize_backend_invalid_capacity(
        rows, config["g4_capacity_contract"]
    )
    _same(expected_saturation, summary["saturation"], "E7 saturation summary")
    _same(expected_capacity, summary["backend_invalid_capacity"], "E7 capacity summary")


def validate_service_evidence(
    *,
    config_path: Path,
    results_path: Path,
    summary_path: Path,
    registration_artifact: Mapping[str, Any],
    registration_binding: Mapping[str, Any],
) -> tuple[dict[str, Any], str, list[dict[str, Any]], dict[str, Any]]:
    try:
        config, config_id = service_bench.load_config(config_path)
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise G5AdjudicationError(f"invalid E7 config: {error}") from error
    blockers = service_bench.formal_execution_blockers(config)
    if blockers:
        raise G5AdjudicationError(f"E7 formal execution remains blocked: {blockers}")
    _same(registration_binding, config.get("phase1_baseline_registration"), "E7 registration")
    _same(
        registration_artifact["selection"]["selected_filter"],
        config.get("filter"),
        "E7 registered filter",
    )
    contract = validate_g5_contract(config)
    rows = load_jsonl(results_path, "E7 results")
    expected_points = service_bench.enumerate_points(config)
    expected = {point.point_id(config_id): point for point in expected_points}
    observed: dict[str, dict[str, Any]] = {}
    commits: set[str] = set()
    for row in rows:
        point_id = row.get("point_id")
        if type(point_id) is not str or point_id not in expected:
            raise G5AdjudicationError("E7 results contain an unexpected point")
        if point_id in observed:
            raise G5AdjudicationError(f"E7 results duplicate point {point_id}")
        try:
            service_bench._validate_result_contract(row, expected[point_id], config, config_id)
        except (KeyError, OverflowError, TypeError, ValueError) as error:
            raise G5AdjudicationError(f"invalid E7 result {point_id}: {error}") from error
        if row.get("result_status") != "VALID" and not _is_analyzable_g5_invalid(row):
            raise G5AdjudicationError(
                f"E7 result {point_id} has a non-resource measurement failure"
            )
        git = _mapping(row.get("git"), f"E7 result {point_id} git provenance")
        if git.get("dirty") is not False or git.get("status_available") is not True:
            raise G5AdjudicationError(f"E7 result {point_id} lacks clean Git provenance")
        commit = _hex(row.get("commit"), f"E7 result {point_id} commit", 40)
        if git.get("commit") != commit:
            raise G5AdjudicationError(f"E7 result {point_id} Git commit binding differs")
        commits.add(commit)
        observed[point_id] = row
    if set(observed) != set(expected):
        raise G5AdjudicationError("E7 results do not cover the full frozen grid")
    if len(commits) != 1:
        raise G5AdjudicationError("E7 results do not share one frozen source commit")
    ordered = [observed[point.point_id(config_id)] for point in expected_points]
    recomputed = copy.deepcopy(ordered)
    service_bench._assign_saturation(config, recomputed)
    _same(recomputed, ordered, "E7 saturation annotations")
    summary = load_json(summary_path, "E7 summary")
    _coverage_is_complete(summary, config, ordered)
    return (
        config,
        config_id,
        ordered,
        {
            "contract": contract,
            "summary": summary,
            "source_commit": next(iter(commits)),
        },
    )


def _rows_for_curve(
    rows: Sequence[Mapping[str, Any]],
    *,
    method: str,
    scenario: str,
    profile: str,
    seed: int,
    legitimate_rps: float,
) -> list[Mapping[str, Any]]:
    selected = [
        row
        for row in rows
        if row.get("method") == method
        and row.get("scenario") == scenario
        and row.get("verifier_profile", {}).get("name") == profile
        and row.get("seed") == seed
        and float(row.get("offered_legitimate_rps", -1)) == legitimate_rps
    ]
    by_load: dict[float, Mapping[str, Any]] = {}
    for row in selected:
        load = _number(row.get("offered_invalid_rps"), "offered invalid load")
        if load in by_load:
            raise G5AdjudicationError(
                f"duplicate curve coordinate for {method}/{profile}/{seed}/{load:g}"
            )
        by_load[load] = row
    expected = [float(item) for item in INVALID_GRID]
    if sorted(by_load) != expected:
        raise G5AdjudicationError(f"incomplete curve for {method}/{profile}/{seed}")
    ordered = [by_load[item] for item in expected]
    passes = [row.get("g5_operational_safe_point_pass") for row in ordered]
    if any(type(value) is not bool for value in passes):
        raise G5AdjudicationError(
            f"missing G5 operational-safe decisions in {method}/{profile}/{seed}"
        )
    return ordered


def _operational_curve_is_nonmonotone(rows: Sequence[Mapping[str, Any]]) -> bool:
    seen_failure = False
    for row in rows:
        if row["g5_operational_safe_point_pass"] is False:
            seen_failure = True
        elif seen_failure:
            return True
    return False


def _paired_identity(candidate: Mapping[str, Any], baseline: Mapping[str, Any], label: str) -> None:
    for field in (
        "dataset_hash",
        "filter_realization",
        "curve_environment_binding",
        "offered_legitimate_rps",
        "offered_invalid_rps",
    ):
        if canonical(candidate.get(field)) != canonical(baseline.get(field)):
            raise G5AdjudicationError(f"{label} differs on paired field {field}")


def one_sided_log_relation(
    ratios: Sequence[float],
    *,
    familywise_alpha: float,
    relation_count: int,
    threshold: float,
    direction: str,
) -> dict[str, Any]:
    if len(ratios) != len(SEEDS):
        raise G5AdjudicationError("log-t relation requires all 20 paired seeds")
    values = [_number(value, "paired ratio", positive=True) for value in ratios]
    if relation_count < 1:
        raise G5AdjudicationError("relation count must be positive")
    alpha = _number(familywise_alpha, "familywise alpha", positive=True) / relation_count
    if not 0.0 < alpha < 1.0:
        raise G5AdjudicationError("per-relation alpha must be in (0,1)")
    threshold_value = _number(threshold, "ratio threshold", positive=True)
    logs = [math.log(value) for value in values]
    mean_log = statistics.fmean(logs)
    standard_error = statistics.stdev(logs) / math.sqrt(len(logs))
    critical = float(student_t.ppf(1.0 - alpha, len(logs) - 1))
    lower_log = mean_log - critical * standard_error
    upper_log = mean_log + critical * standard_error
    threshold_log = math.log(threshold_value)
    if direction == "lower":
        if lower_log >= threshold_log:
            decision = "PASS"
        elif mean_log < threshold_log:
            decision = "FAIL"
        else:
            decision = "INDETERMINATE"
    elif direction == "upper":
        if upper_log <= threshold_log:
            decision = "PASS"
        elif mean_log > threshold_log:
            decision = "FAIL"
        else:
            decision = "INDETERMINATE"
    else:
        raise G5AdjudicationError("log-t direction must be lower or upper")
    return {
        "paired_seed_count": len(values),
        "familywise_alpha": float(familywise_alpha),
        "per_relation_alpha": alpha,
        "relation_count": relation_count,
        "student_t_degrees_of_freedom": len(values) - 1,
        "student_t_critical": critical,
        "mean_log_ratio": mean_log,
        "standard_error_log_ratio": standard_error,
        "simultaneous_lower_log_ratio": lower_log,
        "simultaneous_upper_log_ratio": upper_log,
        "geometric_mean_ratio": math.exp(mean_log),
        "simultaneous_lower_ratio_bound": math.exp(lower_log),
        "simultaneous_upper_ratio_bound": math.exp(upper_log),
        "threshold_ratio": threshold_value,
        "direction": direction,
        "decision": decision,
    }


def _component_decision(decisions: Sequence[str], *, kind: str) -> str:
    if kind == "saturation":
        if "FAIL" in decisions:
            return SATURATION_FAIL
        if "INDETERMINATE" in decisions:
            return SATURATION_INDETERMINATE
        return SATURATION_PASS
    if "FAIL" in decisions:
        return P99_FAIL
    if "INDETERMINATE" in decisions:
        return P99_INDETERMINATE
    return P99_PASS


def adjudicate_saturation(
    rows: Sequence[Mapping[str, Any]], contract: Mapping[str, Any]
) -> dict[str, Any]:
    relations: list[dict[str, Any]] = []
    for profile in contract["verifier_profiles"]:
        per_seed: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []
        ratios: list[float] = []
        for seed in SEEDS:
            candidate = _rows_for_curve(
                rows,
                method=contract["candidate_method"],
                scenario=contract["scenario"],
                profile=profile,
                seed=seed,
                legitimate_rps=float(contract["offered_legitimate_rps"]),
            )
            baseline = _rows_for_curve(
                rows,
                method=contract["matched_baseline_method"],
                scenario=contract["scenario"],
                profile=profile,
                seed=seed,
                legitimate_rps=float(contract["offered_legitimate_rps"]),
            )
            for candidate_row, baseline_row in zip(candidate, baseline, strict=True):
                _paired_identity(candidate_row, baseline_row, f"saturation pair {profile}/{seed}")
            resource_gaps = []
            if any(_has_resource_observation_gap(row) for row in candidate):
                resource_gaps.append("CANDIDATE_RESOURCE_OBSERVATION_MISSING")
            if any(_has_resource_observation_gap(row) for row in baseline):
                resource_gaps.append("BASELINE_RESOURCE_OBSERVATION_MISSING")
            if resource_gaps:
                missing.append({"seed": seed, "reasons": resource_gaps})
                continue
            nonmonotone = []
            if _operational_curve_is_nonmonotone(candidate):
                nonmonotone.append("CANDIDATE_OPERATIONAL_CURVE_NON_MONOTONIC")
            if _operational_curve_is_nonmonotone(baseline):
                nonmonotone.append("BASELINE_OPERATIONAL_CURVE_NON_MONOTONIC")
            if nonmonotone:
                missing.append({"seed": seed, "reasons": nonmonotone})
                continue
            safe = [row for row in candidate if row["g5_operational_safe_point_pass"] is True]
            failures = [row for row in baseline if row["g5_operational_safe_point_pass"] is False]
            if not safe or not failures:
                reasons = []
                if not safe:
                    reasons.append("CANDIDATE_INCLUSIVE_SAFE_LOWER_MISSING")
                if not failures:
                    reasons.append("BASELINE_EXCLUSIVE_FAILURE_UPPER_MISSING")
                missing.append({"seed": seed, "reasons": reasons})
                continue
            candidate_lower = max(safe, key=lambda row: float(row["offered_invalid_rps"]))
            baseline_upper = min(failures, key=lambda row: float(row["offered_invalid_rps"]))
            lower_total = _number(
                candidate_lower.get("offered_total_rps"),
                "candidate inclusive safe lower",
                positive=True,
            )
            upper_total = _number(
                baseline_upper.get("offered_total_rps"),
                "baseline exclusive failure upper",
                positive=True,
            )
            ratio = lower_total / upper_total
            ratios.append(ratio)
            per_seed.append(
                {
                    "seed": seed,
                    "candidate_passing_invalid_rps": [
                        float(row["offered_invalid_rps"]) for row in safe
                    ],
                    "baseline_failing_invalid_rps": [
                        float(row["offered_invalid_rps"]) for row in failures
                    ],
                    "candidate_safe_point_id": candidate_lower.get("point_id"),
                    "candidate_inclusive_safe_lower_total_rps": lower_total,
                    "candidate_inclusive_safe_lower_invalid_rps": float(
                        candidate_lower["offered_invalid_rps"]
                    ),
                    "baseline_failure_point_id": baseline_upper.get("point_id"),
                    "baseline_exclusive_failure_upper_total_rps": upper_total,
                    "baseline_exclusive_failure_upper_invalid_rps": float(
                        baseline_upper["offered_invalid_rps"]
                    ),
                    "conservative_ratio": ratio,
                }
            )
        if missing:
            statistics_payload = None
            decision = "INDETERMINATE"
        else:
            statistics_payload = one_sided_log_relation(
                ratios,
                familywise_alpha=float(contract["saturation_familywise_alpha"]),
                relation_count=len(contract["verifier_profiles"]),
                threshold=float(contract["saturation_ratio_threshold"]),
                direction="lower",
            )
            decision = statistics_payload["decision"]
        relations.append(
            {
                "verifier_profile": profile,
                "per_seed": per_seed,
                "missing_endpoints": missing,
                "statistics": statistics_payload,
                "decision": decision,
            }
        )
    decision = _component_decision([item["decision"] for item in relations], kind="saturation")
    return {
        "estimand": contract["saturation_per_seed_ratio_rule"],
        "missing_endpoint_policy": contract["missing_endpoint_policy"],
        "multiplicity_adjustment": contract["saturation_multiplicity_adjustment"],
        "relations": relations,
        "decision": decision,
    }


def adjudicate_p99(
    rows: Sequence[Mapping[str, Any]], contract: Mapping[str, Any]
) -> dict[str, Any]:
    relations: list[dict[str, Any]] = []
    for profile in contract["verifier_profiles"]:
        per_seed: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []
        ratios: list[float] = []
        for seed in SEEDS:
            candidate = _rows_for_curve(
                rows,
                method=contract["candidate_method"],
                scenario=contract["scenario"],
                profile=profile,
                seed=seed,
                legitimate_rps=float(contract["offered_legitimate_rps"]),
            )
            baseline = _rows_for_curve(
                rows,
                method=contract["matched_baseline_method"],
                scenario=contract["scenario"],
                profile=profile,
                seed=seed,
                legitimate_rps=float(contract["offered_legitimate_rps"]),
            )
            pairs: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
            for candidate_row, baseline_row in zip(candidate, baseline, strict=True):
                _paired_identity(candidate_row, baseline_row, f"p99 pair {profile}/{seed}")
                if (
                    float(candidate_row["offered_invalid_rps"]) > 0.0
                    and candidate_row["g5_operational_safe_point_pass"] is True
                    and baseline_row["g5_operational_safe_point_pass"] is True
                ):
                    pairs.append((candidate_row, baseline_row))
            resource_gap_methods = []
            if any(_has_resource_observation_gap(row) for row in candidate):
                resource_gap_methods.append("candidate")
            if any(_has_resource_observation_gap(row) for row in baseline):
                resource_gap_methods.append("baseline")
            if resource_gap_methods:
                missing.append(
                    {
                        "seed": seed,
                        "reason": "RESOURCE_OBSERVATION_MISSING_ON_COMPARATIVE_CURVE",
                        "methods": resource_gap_methods,
                    }
                )
                continue
            if _operational_curve_is_nonmonotone(candidate) or _operational_curve_is_nonmonotone(
                baseline
            ):
                missing.append(
                    {
                        "seed": seed,
                        "reason": "NON_MONOTONIC_OPERATIONAL_SAFE_CURVE",
                    }
                )
                continue
            if not pairs:
                missing.append({"seed": seed, "reason": "NO_POSITIVE_COMMON_SAFE_GRID_POINT"})
                continue
            candidate_row, baseline_row = max(
                pairs, key=lambda pair: float(pair[0]["offered_invalid_rps"])
            )
            candidate_p99 = _number(
                candidate_row.get("legitimate_p99_ms"), "candidate legitimate p99", positive=True
            )
            baseline_p99 = _number(
                baseline_row.get("legitimate_p99_ms"), "baseline legitimate p99", positive=True
            )
            ratio = candidate_p99 / baseline_p99
            ratios.append(ratio)
            per_seed.append(
                {
                    "seed": seed,
                    "common_passing_positive_invalid_rps": [
                        float(pair[0]["offered_invalid_rps"]) for pair in pairs
                    ],
                    "selected_invalid_rps": float(candidate_row["offered_invalid_rps"]),
                    "candidate_point_id": candidate_row.get("point_id"),
                    "baseline_point_id": baseline_row.get("point_id"),
                    "candidate_legitimate_p99_ms": candidate_p99,
                    "baseline_legitimate_p99_ms": baseline_p99,
                    "p99_ratio": ratio,
                }
            )
        if missing:
            statistics_payload = None
            decision = "INDETERMINATE"
        else:
            statistics_payload = one_sided_log_relation(
                ratios,
                familywise_alpha=float(contract["p99_familywise_alpha"]),
                relation_count=len(contract["verifier_profiles"]),
                threshold=float(contract["p99_margin_ratio"]),
                direction="upper",
            )
            decision = statistics_payload["decision"]
        relations.append(
            {
                "verifier_profile": profile,
                "per_seed": per_seed,
                "missing_safe_coordinates": missing,
                "statistics": statistics_payload,
                "decision": decision,
            }
        )
    decision = _component_decision([item["decision"] for item in relations], kind="p99")
    return {
        "safe_load_rule": contract["p99_safe_load_rule"],
        "multiplicity_adjustment": contract["p99_multiplicity_adjustment"],
        "relations": relations,
        "decision": decision,
    }


QUEUE_LIMIT_FIELDS = {
    "frontend_queue_length": "frontend_queue_capacity",
    "backend_queue_length": "backend_queue_capacity",
    "active_connections": "max_connections",
    "active_frontend_workers": "frontend_workers",
    "active_backend_workers": "backend_workers",
    "pending_padding_timers": "max_padding_timers",
}
LIMIT_FIELDS = tuple(
    dict.fromkeys(
        [
            *QUEUE_LIMIT_FIELDS.values(),
            "max_waiters_per_key",
            "max_waiters_global",
            "cache_capacity",
            "cache_max_entries_per_account",
        ]
    )
)


def adjudicate_resources(
    rows: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    bounds = _mapping(contract.get("resource_bounds"), "G5 resource bounds")
    service = _mapping(config.get("service"), "service resource limits")
    configured: dict[str, int | None] = {}
    for field in LIMIT_FIELDS:
        value = service.get(field)
        if value is None and field == "cache_max_entries_per_account":
            configured[field] = None
        else:
            configured[field] = _integer(value, f"service.{field}", minimum=0)
    if configured["max_waiters_per_key"] > configured["max_waiters_global"]:
        raise G5AdjudicationError("per-key waiter cap exceeds global waiter cap")
    quota = configured["cache_max_entries_per_account"]
    if quota is not None and quota > configured["cache_capacity"]:
        raise G5AdjudicationError("per-account cache cap exceeds total cache cap")
    measurement = _mapping(config.get("measurement"), "service measurement contract")
    required_samples = _integer(
        measurement.get("minimum_resource_samples"),
        "measurement.minimum_resource_samples",
        minimum=1,
    )
    contract_minimum_samples = _integer(
        bounds.get("minimum_resource_samples"),
        "resource_bounds.minimum_resource_samples",
        minimum=1,
    )
    if required_samples != contract_minimum_samples:
        raise G5AdjudicationError(
            "measurement minimum resource samples differs from the frozen G5 bound"
        )
    maximum_rss_peak = _integer(
        bounds.get("maximum_process_rss_peak_bytes"),
        "resource_bounds.maximum_process_rss_peak_bytes",
        minimum=1,
    )
    maximum_rss_growth = _integer(
        bounds.get("maximum_late_minus_early_rss_mean_bytes"),
        "resource_bounds.maximum_late_minus_early_rss_mean_bytes",
        minimum=0,
    )
    window_numerator = _integer(
        bounds.get("rss_window_fraction_numerator"),
        "resource_bounds.rss_window_fraction_numerator",
        minimum=1,
    )
    window_denominator = _integer(
        bounds.get("rss_window_fraction_denominator"),
        "resource_bounds.rss_window_fraction_denominator",
        minimum=1,
    )
    if window_numerator >= window_denominator:
        raise G5AdjudicationError("RSS window fraction must be less than one")
    selected = [
        row
        for row in rows
        if row.get("method") == contract["candidate_method"]
        and row.get("scenario") == contract["scenario"]
        and row.get("verifier_profile", {}).get("name") in contract["verifier_profiles"]
        and row.get("seed") in SEEDS
        and float(row.get("offered_legitimate_rps", -1))
        == float(contract["offered_legitimate_rps"])
        and float(row.get("offered_invalid_rps", -1)) in INVALID_GRID
    ]
    expected_count = len(SEEDS) * len(PROFILES) * len(INVALID_GRID)
    if len(selected) != expected_count:
        raise G5AdjudicationError("resource gate lacks the complete repeat-heavy candidate grid")
    maxima = {name: 0 for name in QUEUE_LIMIT_FIELDS}
    maxima.update(
        {
            "rss_peak_bytes": 0,
            "late_minus_early_rss_mean_bytes": None,
            "declared_component_bytes": 0,
            "cache_entries": 0,
            "peak_entries_per_account": 0,
            "global_peak_waiters": 0,
            "peak_waiters_per_key": 0,
            "current_waiters": 0,
            "inflight": 0,
        }
    )
    minimum_samples: int | None = None
    violations: list[dict[str, Any]] = []
    missing_data: list[dict[str, str]] = []
    maximum_growth_support: dict[str, Any] | None = None

    def missing(point_id: str, field: str) -> None:
        missing_data.append({"point_id": point_id, "field": field})

    for row in selected:
        point_id = str(row.get("point_id"))
        raw_resources = row.get("resource_samples")
        if type(raw_resources) is not dict:
            missing(point_id, "resource_samples")
            continue
        resources = _mapping(raw_resources, f"resource samples {point_id}")
        if resources.get("metrics_complete") is not True:
            missing(point_id, "resource_samples.metrics_complete")
        if resources.get("resource_payload_schema_version") != 2:
            missing(point_id, "resource_samples.resource_payload_schema_version")
        sample_count_raw = resources.get("sample_count")
        sample_count = (
            None
            if sample_count_raw is None
            else _integer(sample_count_raw, f"sample count {point_id}")
        )
        if sample_count is None:
            missing(point_id, "resource_samples.sample_count")
        else:
            minimum_samples = (
                sample_count if minimum_samples is None else min(minimum_samples, sample_count)
            )
            if sample_count < required_samples:
                missing(point_id, "resource_samples.minimum_resource_samples")
        rss_peak_raw = resources.get("process_rss_peak_bytes")
        rss_peak = None if rss_peak_raw is None else _integer(rss_peak_raw, f"RSS peak {point_id}")
        if rss_peak is None:
            missing(point_id, "resource_samples.process_rss_peak_bytes")
        else:
            maxima["rss_peak_bytes"] = max(maxima["rss_peak_bytes"], rss_peak)
            if rss_peak > maximum_rss_peak:
                violations.append(
                    {
                        "point_id": point_id,
                        "resource": "process_rss_peak_bytes",
                        "observed": rss_peak,
                        "limit": maximum_rss_peak,
                    }
                )

        expected_window_metadata = {
            "rss_window_minimum_sample_count": contract_minimum_samples,
            "rss_window_fraction_numerator": window_numerator,
            "rss_window_fraction_denominator": window_denominator,
        }
        window_metadata_complete = True
        for field, expected_value in expected_window_metadata.items():
            if field not in resources:
                missing(point_id, f"resource_samples.{field}")
                window_metadata_complete = False
            elif _integer(resources[field], f"{field} {point_id}") != expected_value:
                raise G5AdjudicationError(
                    f"resource samples {field} differs from the frozen contract at {point_id}"
                )
        window_fields = (
            "rss_window_k_samples",
            "rss_first_window_sum_bytes",
            "rss_first_window_sample_count",
            "rss_first_window_mean_bytes",
            "rss_last_window_sum_bytes",
            "rss_last_window_sample_count",
            "rss_last_window_mean_bytes",
        )
        if any(field not in resources for field in window_fields):
            for field in window_fields:
                if field not in resources:
                    missing(point_id, f"resource_samples.{field}")
            window_metadata_complete = False
        if window_metadata_complete and sample_count is not None:
            k_samples = _integer(resources["rss_window_k_samples"], f"RSS window size {point_id}")
            expected_k = sample_count * window_numerator // window_denominator
            first_count = _integer(
                resources["rss_first_window_sample_count"],
                f"RSS first-window sample count {point_id}",
            )
            last_count = _integer(
                resources["rss_last_window_sample_count"],
                f"RSS last-window sample count {point_id}",
            )
            first_sum = _integer(
                resources["rss_first_window_sum_bytes"],
                f"RSS first-window sum {point_id}",
            )
            last_sum = _integer(
                resources["rss_last_window_sum_bytes"],
                f"RSS last-window sum {point_id}",
            )
            first_mean = resources["rss_first_window_mean_bytes"]
            last_mean = resources["rss_last_window_mean_bytes"]
            if sample_count < contract_minimum_samples:
                if (
                    k_samples != 0
                    or first_count != 0
                    or last_count != 0
                    or first_sum != 0
                    or last_sum != 0
                    or first_mean is not None
                    or last_mean is not None
                ):
                    raise G5AdjudicationError(
                        f"subminimum RSS window payload is not empty at {point_id}"
                    )
            else:
                if expected_k < 1 or k_samples != expected_k:
                    raise G5AdjudicationError(f"RSS window size differs at {point_id}")
                if first_count != k_samples or last_count != k_samples:
                    raise G5AdjudicationError(f"RSS window counts differ at {point_id}")
                observed_first_mean = _number(first_mean, f"RSS first-window mean {point_id}")
                observed_last_mean = _number(last_mean, f"RSS last-window mean {point_id}")
                if observed_first_mean != first_sum / first_count:
                    raise G5AdjudicationError(
                        f"RSS first-window mean does not recompute at {point_id}"
                    )
                if observed_last_mean != last_sum / last_count:
                    raise G5AdjudicationError(
                        f"RSS last-window mean does not recompute at {point_id}"
                    )
                growth_numerator = last_sum * first_count - first_sum * last_count
                growth_denominator = last_count * first_count
                growth_value = growth_numerator / growth_denominator
                if (
                    maximum_growth_support is None
                    or growth_numerator * maximum_growth_support["denominator"]
                    > maximum_growth_support["numerator"] * growth_denominator
                ):
                    maximum_growth_support = {
                        "point_id": point_id,
                        "numerator": growth_numerator,
                        "denominator": growth_denominator,
                        "value_bytes": growth_value,
                    }
                    maxima["late_minus_early_rss_mean_bytes"] = growth_value
                if growth_numerator > maximum_rss_growth * growth_denominator:
                    violations.append(
                        {
                            "point_id": point_id,
                            "resource": "late_minus_early_rss_mean_bytes",
                            "observed": growth_value,
                            "limit": maximum_rss_growth,
                        }
                    )
        declared_bytes = sum(
            _integer(row.get(field), f"{field} {point_id}")
            for field in (
                "memory_filter_bytes",
                "memory_model_bytes",
                "memory_cache_bytes",
                "memory_directory_extra_bytes",
            )
        )
        maxima["declared_component_bytes"] = max(maxima["declared_component_bytes"], declared_bytes)
        if rss_peak is not None and declared_bytes > rss_peak:
            violations.append(
                {
                    "point_id": point_id,
                    "resource": "declared_component_bytes",
                    "observed": declared_bytes,
                    "limit": rss_peak,
                }
            )
        raw_queue_peak = resources.get("queue_peak")
        if type(raw_queue_peak) is not dict:
            missing(point_id, "resource_samples.queue_peak")
            queue_peak: dict[str, Any] = {}
        else:
            queue_peak = _mapping(raw_queue_peak, f"queue peaks {point_id}")
        final_state = _mapping(
            row.get("queue_and_connection_state"), f"final queue state {point_id}"
        )
        unexpected_queue_metrics = set(queue_peak) - set(QUEUE_LIMIT_FIELDS)
        if unexpected_queue_metrics:
            raise G5AdjudicationError(f"queue resource schema has unexpected metrics at {point_id}")
        for metric in set(QUEUE_LIMIT_FIELDS) - set(queue_peak):
            missing(point_id, f"resource_samples.queue_peak.{metric}")
        if set(final_state) != set(QUEUE_LIMIT_FIELDS):
            raise G5AdjudicationError(f"final queue state schema differs at {point_id}")
        if any(_integer(value, f"final state {name}") != 0 for name, value in final_state.items()):
            violations.append(
                {
                    "point_id": point_id,
                    "resource": "final_queue_connection_state",
                    "observed": 1,
                    "limit": 0,
                }
            )
        shutdown_clean = row.get("shutdown_clean")
        if type(shutdown_clean) is not bool:
            missing(point_id, "shutdown_clean")
        elif not shutdown_clean:
            violations.append(
                {
                    "point_id": point_id,
                    "resource": "unclean_shutdown",
                    "observed": 1,
                    "limit": 0,
                }
            )
        for metric, limit_field in QUEUE_LIMIT_FIELDS.items():
            if metric not in queue_peak:
                continue
            observed = _integer(queue_peak.get(metric), f"queue peak {metric} {point_id}")
            maxima[metric] = max(maxima[metric], observed)
            limit = configured[limit_field]
            assert limit is not None
            if observed > limit:
                violations.append(
                    {"point_id": point_id, "resource": metric, "observed": observed, "limit": limit}
                )
        phase = _mapping(row.get("phase_metrics"), f"phase metrics {point_id}")
        cache_entries = _integer(phase.get("cache_entries"), f"cache entries {point_id}")
        cache_capacity = _integer(phase.get("cache_capacity"), f"cache capacity {point_id}")
        if cache_capacity != configured["cache_capacity"]:
            raise G5AdjudicationError(f"phase cache capacity differs from config at {point_id}")
        maxima["cache_entries"] = max(maxima["cache_entries"], cache_entries)
        if cache_entries > cache_capacity:
            violations.append(
                {
                    "point_id": point_id,
                    "resource": "cache_entries",
                    "observed": cache_entries,
                    "limit": cache_capacity,
                }
            )
        account_peak_raw = phase.get("cache_peak_entries_per_account")
        if account_peak_raw is None:
            missing(point_id, "phase_metrics.cache_peak_entries_per_account")
        else:
            account_peak = _integer(account_peak_raw, f"cache peak entries per account {point_id}")
            maxima["peak_entries_per_account"] = max(
                maxima["peak_entries_per_account"], account_peak
            )
            if quota is None:
                missing(point_id, "service.cache_max_entries_per_account")
            elif account_peak > quota:
                violations.append(
                    {
                        "point_id": point_id,
                        "resource": "peak_entries_per_account",
                        "observed": account_peak,
                        "limit": quota,
                    }
                )
        singleflight = _mapping(phase.get("singleflight"), f"singleflight {point_id}")
        for field in ("peak_waiters", "current_waiters", "inflight"):
            observed = _integer(singleflight.get(field, 0), f"singleflight {field} {point_id}")
            target = "global_peak_waiters" if field == "peak_waiters" else field
            maxima[target] = max(maxima[target], observed)
        point_peak_waiters = _integer(
            singleflight.get("peak_waiters", 0), f"singleflight peak waiters {point_id}"
        )
        if point_peak_waiters > configured["max_waiters_global"]:
            violations.append(
                {
                    "point_id": point_id,
                    "resource": "global_peak_waiters",
                    "observed": point_peak_waiters,
                    "limit": configured["max_waiters_global"],
                }
            )
        per_key_peak_raw = singleflight.get("peak_waiters_per_key")
        if per_key_peak_raw is None:
            missing(point_id, "phase_metrics.singleflight.peak_waiters_per_key")
        else:
            per_key_peak = _integer(
                per_key_peak_raw, f"singleflight peak waiters per key {point_id}"
            )
            maxima["peak_waiters_per_key"] = max(maxima["peak_waiters_per_key"], per_key_peak)
            if per_key_peak > configured["max_waiters_per_key"]:
                violations.append(
                    {
                        "point_id": point_id,
                        "resource": "peak_waiters_per_key",
                        "observed": per_key_peak,
                        "limit": configured["max_waiters_per_key"],
                    }
                )
        if _integer(singleflight.get("current_waiters", 0), "current waiters") != 0:
            violations.append(
                {
                    "point_id": point_id,
                    "resource": "current_waiters",
                    "observed": singleflight["current_waiters"],
                    "limit": 0,
                }
            )
        if _integer(singleflight.get("inflight", 0), "inflight") != 0:
            violations.append(
                {
                    "point_id": point_id,
                    "resource": "inflight",
                    "observed": singleflight["inflight"],
                    "limit": 0,
                }
            )
    unique_violations = sorted(
        {canonical(item): item for item in violations}.values(),
        key=lambda item: (item["point_id"], item["resource"]),
    )
    unique_missing_data = sorted(
        {canonical(item): item for item in missing_data}.values(),
        key=lambda item: (item["point_id"], item["field"]),
    )
    if unique_violations:
        decision = RESOURCE_FAIL
    elif unique_missing_data:
        decision = RESOURCE_INDETERMINATE
    else:
        decision = RESOURCE_PASS
    return {
        "gate_contract": contract["resource_gate"],
        "frozen_bounds": bounds,
        "scope": "REPEAT_HEAVY_CANDIDATE_FULL_GRID",
        "evaluated_row_count": len(selected),
        "configured_limits": configured,
        "configured_minimum_resource_samples": required_samples,
        "minimum_resource_sample_count": minimum_samples,
        "observed_maxima": maxima,
        "maximum_rss_growth_support": maximum_growth_support,
        "rss_bound_semantics": (
            "COMBINED_BENCHMARK_PROCESS_RSS_ENVELOPES_FRONTEND;_"
            "PEAK_AND_EXACT_FIRST_LAST_TEN_PERCENT_MEAN_DIFFERENCE_ARE_BOUNDED;_"
            "QUEUE_CONNECTION_WAITER_AND_CACHE_LIMITS_ARE_CONFIGURED_HARD_CAPS"
        ),
        "violations": unique_violations,
        "missing_data": unique_missing_data,
        "decision": decision,
    }


def adjudicate_unique_first_seen(
    rows: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    method_names = [str(item["name"]) for item in config["methods"]]
    expected = {
        (seed, method, profile, float(load))
        for seed in SEEDS
        for method in method_names
        for profile in PROFILES
        for load in INVALID_GRID
    }
    observed: dict[tuple[int, str, str, float], Mapping[str, Any]] = {}
    for row in rows:
        if row.get("scenario") != UNIQUE_SCENARIO:
            continue
        if float(row.get("offered_legitimate_rps", -1)) != float(
            contract["offered_legitimate_rps"]
        ):
            raise G5AdjudicationError("unique-first-seen row uses an undeclared legitimate load")
        key = (
            _integer(row.get("seed"), "unique-first-seen seed"),
            str(row.get("method")),
            str(row.get("verifier_profile", {}).get("name")),
            _number(row.get("offered_invalid_rps"), "unique-first-seen invalid load"),
        )
        if key in observed:
            raise G5AdjudicationError(f"duplicate unique-first-seen coordinate {key!r}")
        if row.get("result_status") != "VALID" and not _is_analyzable_g5_invalid(row):
            raise G5AdjudicationError(f"invalid unique-first-seen measurement {key!r}")
        observed[key] = row
    if set(observed) != expected:
        missing = len(expected - set(observed))
        unexpected = len(set(observed) - expected)
        raise G5AdjudicationError(
            f"unique-first-seen family is incomplete ({missing} missing, {unexpected} unexpected)"
        )
    reports: list[dict[str, Any]] = []
    maximum_load = float(max(INVALID_GRID))
    for profile in PROFILES:
        for method in method_names:
            high = [observed[(seed, method, profile, maximum_load)] for seed in SEEDS]
            p99 = [
                _number(row.get("legitimate_p99_ms"), "unique-first-seen p99", positive=True)
                for row in high
            ]
            backend = [
                _integer(row.get("backend_invalid_checks"), "unique-first-seen backend checks")
                for row in high
            ]
            reports.append(
                {
                    "verifier_profile": profile,
                    "method": method,
                    "reported_invalid_rps": maximum_load,
                    "seed_count": len(high),
                    "mean_legitimate_p99_ms": statistics.fmean(p99),
                    "mean_backend_invalid_checks": statistics.fmean(backend),
                }
            )
    has_resource_gaps = any(_is_resource_only_invalid(row) for row in observed.values())
    has_operational_invalid = any(row.get("result_status") != "VALID" for row in observed.values())
    return {
        "scenario": UNIQUE_SCENARIO,
        "role": contract["unique_first_seen_role"],
        "status": (
            "COMPLETE_RESOURCE_OBSERVATION_INDETERMINATE_REPORT_ONLY"
            if has_resource_gaps
            else (
                "COMPLETE_OPERATIONAL_INVALID_MEASUREMENTS_REPORT_ONLY"
                if has_operational_invalid
                else "VALID_COMPLETE_REPORT_ONLY"
            )
        ),
        "expected_point_count": len(expected),
        "observed_point_count": len(observed),
        "reports_at_maximum_load": reports,
        "controls_g5_directional_decision": False,
    }


def _gate_from_components(saturation: str, p99: str, resource: str) -> tuple[str, list[str]]:
    reasons: list[str] = []
    failures = {
        SATURATION_FAIL: "SATURATION_SUPERIORITY_FAILED",
        P99_FAIL: "P99_NONINFERIORITY_FAILED",
        RESOURCE_FAIL: "RESOURCE_BOUND_FAILED",
    }
    indeterminate = {
        SATURATION_INDETERMINATE: "SATURATION_SUPERIORITY_INDETERMINATE",
        P99_INDETERMINATE: "P99_NONINFERIORITY_INDETERMINATE",
        RESOURCE_INDETERMINATE: "RESOURCE_BOUND_INDETERMINATE",
    }
    for decision in (saturation, p99, resource):
        if decision in failures:
            reasons.append(failures[decision])
        elif decision in indeterminate:
            reasons.append(indeterminate[decision])
    if any(decision in failures for decision in (saturation, p99, resource)):
        return FAIL, reasons
    if any(decision in indeterminate for decision in (saturation, p99, resource)):
        return INDETERMINATE, reasons
    return PASS, reasons


def build_receipt(
    *,
    registration_artifact: Mapping[str, Any],
    service_config: Mapping[str, Any],
    service_config_id: str,
    service_rows: Sequence[Mapping[str, Any]],
    service_summary: Mapping[str, Any],
    service_source_commit: str,
    contract: Mapping[str, Any],
    analysis_source_state: Mapping[str, Any],
) -> dict[str, Any]:
    saturation = adjudicate_saturation(service_rows, contract)
    p99 = adjudicate_p99(service_rows, contract)
    resources = adjudicate_resources(service_rows, service_config, contract)
    unique = adjudicate_unique_first_seen(service_rows, service_config, contract)
    gate, reasons = _gate_from_components(
        saturation["decision"], p99["decision"], resources["decision"]
    )
    phase1_boundary = _phase1_registration_boundary(registration_artifact)
    evidence = registration_artifact["phase1_evidence"]
    body: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "validation_status": VALID,
        "analysis_source_state": dict(analysis_source_state),
        "g5_gate_status": gate,
        "promotion_eligible": gate == PASS,
        "reason_codes": reasons,
        "bindings": {
            "main_claims_manifest_id": service_config["main_claims_manifest_id"],
            "phase1_registration_id": registration_artifact["registration_id"],
            "phase1_registration_status": phase1_boundary["status"],
            "phase1_recovery_scope": phase1_boundary["recovery_scope"],
            "phase1_receipt_id": evidence["receipt_id"],
            "phase1_aggregate_id": evidence["aggregate_id"],
            "service_config_id": service_config_id,
            "service_results_id": semantic_id(list(service_rows)),
            "service_summary_id": semantic_id(service_summary),
            "service_source_commit": service_source_commit,
            "analysis_commit": analysis_source_state["commit"],
        },
        "decision_contract": dict(contract),
        "saturation_component": saturation,
        "legitimate_p99_component": p99,
        "bounded_resource_component": resources,
        "unique_first_seen_report_only_component": unique,
        "scientific_scope": (
            "Frozen synthetic in-process E7 deployment profile; unique-first-seen is reported "
            "but does not control the directional G5 decision; network/TLS is not measured"
        ),
        "claim_disposition": {
            "c5_status": "PASS" if gate == PASS else "BLOCKED",
            "g5_status": "PASS" if gate == PASS else gate,
            "phase1_service_baseline_recovery": (
                phase1_boundary["recovery_scope"] == SERVICE_RECOVERY_SCOPE
            ),
            "unique_first_seen_directional_claim": False,
        },
    }
    receipt = {**body, "receipt_id": semantic_id(body)}
    return receipt


def _validate_relation_statistics(
    relation: Mapping[str, Any],
    *,
    ratio_field: str,
    missing_field: str,
    alpha: float,
    threshold: float,
    direction: str,
) -> str:
    per_seed = relation.get("per_seed")
    missing = relation.get(missing_field)
    if type(per_seed) is not list or type(missing) is not list:
        raise G5AdjudicationError("G5 relation seed evidence has the wrong type")
    seeds = [item.get("seed") for item in per_seed]
    missing_seeds = [item.get("seed") for item in missing]
    if len(set(seeds + missing_seeds)) != len(seeds) + len(missing_seeds):
        raise G5AdjudicationError("G5 relation duplicates a seed")
    if sorted(seeds + missing_seeds) != list(SEEDS):
        raise G5AdjudicationError("G5 relation does not bind all 20 seeds")
    if missing:
        if relation.get("statistics") is not None or relation.get("decision") != "INDETERMINATE":
            raise G5AdjudicationError("missing endpoint must make the relation indeterminate")
        return "INDETERMINATE"
    ratios = [_number(item.get(ratio_field), ratio_field, positive=True) for item in per_seed]
    expected = one_sided_log_relation(
        ratios,
        familywise_alpha=alpha,
        relation_count=len(PROFILES),
        threshold=threshold,
        direction=direction,
    )
    _same(expected, relation.get("statistics"), "G5 relation statistics")
    if relation.get("decision") != expected["decision"]:
        raise G5AdjudicationError("G5 relation decision contradicts its statistics")
    return expected["decision"]


def _validate_saturation_component(
    component: Mapping[str, Any], contract: Mapping[str, Any]
) -> str:
    value = _mapping(component, "G5 saturation component")
    relations = value.get("relations")
    if type(relations) is not list or [item.get("verifier_profile") for item in relations] != list(
        PROFILES
    ):
        raise G5AdjudicationError("G5 saturation relations differ from the frozen profiles")
    decisions: list[str] = []
    for relation in relations:
        for item in relation.get("per_seed", []):
            passing = item.get("candidate_passing_invalid_rps")
            failing = item.get("baseline_failing_invalid_rps")
            if type(passing) is not list or not passing or type(failing) is not list or not failing:
                raise G5AdjudicationError("saturation endpoint support sets are incomplete")
            passing_values = [_number(value, "candidate passing load") for value in passing]
            failing_values = [_number(value, "baseline failing load") for value in failing]
            if any(value not in INVALID_GRID for value in passing_values + failing_values):
                raise G5AdjudicationError("saturation endpoint support is outside the frozen grid")
            lower = _number(
                item.get("candidate_inclusive_safe_lower_total_rps"),
                "candidate safe lower",
                positive=True,
            )
            upper = _number(
                item.get("baseline_exclusive_failure_upper_total_rps"),
                "baseline failure upper",
                positive=True,
            )
            lower_invalid = _number(
                item.get("candidate_inclusive_safe_lower_invalid_rps"),
                "candidate safe invalid lower",
            )
            upper_invalid = _number(
                item.get("baseline_exclusive_failure_upper_invalid_rps"),
                "baseline failure invalid upper",
            )
            if lower_invalid != max(passing_values) or upper_invalid != min(failing_values):
                raise G5AdjudicationError("saturation endpoints are not the conservative extrema")
            legitimate = float(contract["offered_legitimate_rps"])
            if lower != legitimate + lower_invalid or upper != legitimate + upper_invalid:
                raise G5AdjudicationError("saturation total-rate endpoints do not recompute")
            if item.get("conservative_ratio") != lower / upper:
                raise G5AdjudicationError("saturation per-seed ratio does not recompute")
        decisions.append(
            _validate_relation_statistics(
                relation,
                ratio_field="conservative_ratio",
                missing_field="missing_endpoints",
                alpha=float(contract["saturation_familywise_alpha"]),
                threshold=float(contract["saturation_ratio_threshold"]),
                direction="lower",
            )
        )
    expected = _component_decision(decisions, kind="saturation")
    if value.get("decision") != expected:
        raise G5AdjudicationError("saturation component decision does not recompute")
    return expected


def _validate_p99_component(component: Mapping[str, Any], contract: Mapping[str, Any]) -> str:
    value = _mapping(component, "G5 p99 component")
    relations = value.get("relations")
    if type(relations) is not list or [item.get("verifier_profile") for item in relations] != list(
        PROFILES
    ):
        raise G5AdjudicationError("G5 p99 relations differ from the frozen profiles")
    decisions: list[str] = []
    for relation in relations:
        for item in relation.get("per_seed", []):
            common = item.get("common_passing_positive_invalid_rps")
            if type(common) is not list or not common:
                raise G5AdjudicationError("p99 common-safe support set is incomplete")
            common_values = [
                _number(value, "common-safe p99 load", positive=True) for value in common
            ]
            if any(value not in INVALID_GRID for value in common_values):
                raise G5AdjudicationError("p99 common-safe support is outside the frozen grid")
            candidate = _number(
                item.get("candidate_legitimate_p99_ms"), "candidate p99", positive=True
            )
            baseline = _number(
                item.get("baseline_legitimate_p99_ms"), "baseline p99", positive=True
            )
            if item.get("p99_ratio") != candidate / baseline:
                raise G5AdjudicationError("p99 per-seed ratio does not recompute")
            selected = _number(item.get("selected_invalid_rps"), "selected p99 load", positive=True)
            if selected != max(common_values):
                raise G5AdjudicationError("p99 coordinate is not the highest common safe load")
        decisions.append(
            _validate_relation_statistics(
                relation,
                ratio_field="p99_ratio",
                missing_field="missing_safe_coordinates",
                alpha=float(contract["p99_familywise_alpha"]),
                threshold=float(contract["p99_margin_ratio"]),
                direction="upper",
            )
        )
    expected = _component_decision(decisions, kind="p99")
    if value.get("decision") != expected:
        raise G5AdjudicationError("p99 component decision does not recompute")
    return expected


def _validate_resource_component(component: Mapping[str, Any], contract: Mapping[str, Any]) -> str:
    value = _mapping(component, "G5 resource component")
    configured = _mapping(value.get("configured_limits"), "G5 configured limits")
    maxima = _mapping(value.get("observed_maxima"), "G5 observed maxima")
    violations = value.get("violations")
    missing_data = value.get("missing_data")
    if type(violations) is not list or type(missing_data) is not list:
        raise G5AdjudicationError("G5 resource violations/missing data must be lists")
    _same(contract["resource_bounds"], value.get("frozen_bounds"), "G5 resource bounds")
    if value.get("evaluated_row_count") != len(SEEDS) * len(PROFILES) * len(INVALID_GRID):
        raise G5AdjudicationError("G5 resource component does not cover the full candidate grid")
    required_samples = _integer(
        value.get("configured_minimum_resource_samples"),
        "configured minimum resource samples",
        minimum=1,
    )
    observed_minimum = value.get("minimum_resource_sample_count")
    if observed_minimum is not None:
        _integer(observed_minimum, "observed minimum resource samples")
    if not missing_data and (observed_minimum is None or observed_minimum < required_samples):
        raise G5AdjudicationError("G5 resource sampling is below the configured minimum")
    rss_peak = _integer(maxima.get("rss_peak_bytes"), "maximum RSS peak")
    rss_growth = maxima.get("late_minus_early_rss_mean_bytes")
    if rss_growth is not None:
        _number(rss_growth, "maximum late-minus-early RSS mean")
    declared = _integer(maxima.get("declared_component_bytes"), "declared component bytes")
    if declared > rss_peak and not violations:
        raise G5AdjudicationError("declared component bytes exceed RSS without a violation")
    for metric, limit_field in QUEUE_LIMIT_FIELDS.items():
        if (
            _integer(maxima.get(metric), f"maximum {metric}")
            > _integer(configured.get(limit_field), f"configured {limit_field}")
            and not violations
        ):
            raise G5AdjudicationError(f"{metric} exceeds its bound without a violation")
    if (
        _integer(maxima.get("cache_entries"), "maximum cache entries")
        > _integer(configured.get("cache_capacity"), "configured cache capacity")
        and not violations
    ):
        raise G5AdjudicationError("cache entries exceed capacity without a violation")
    quota = configured.get("cache_max_entries_per_account")
    if (
        quota is not None
        and _integer(maxima.get("peak_entries_per_account"), "maximum per-account cache entries")
        > _integer(quota, "configured per-account cache entries")
        and not violations
    ):
        raise G5AdjudicationError("per-account cache peak exceeds its bound without a violation")
    if (
        _integer(maxima.get("global_peak_waiters"), "maximum global waiters")
        > _integer(configured.get("max_waiters_global"), "configured global waiters")
        and not violations
    ):
        raise G5AdjudicationError("global waiter peak exceeds its bound without a violation")
    if (
        _integer(maxima.get("peak_waiters_per_key"), "maximum per-key waiters")
        > _integer(configured.get("max_waiters_per_key"), "configured per-key waiters")
        and not violations
    ):
        raise G5AdjudicationError("per-key waiter peak exceeds its bound without a violation")
    if violations:
        expected = RESOURCE_FAIL
    elif missing_data:
        expected = RESOURCE_INDETERMINATE
    else:
        expected = RESOURCE_PASS
    if value.get("decision") != expected:
        raise G5AdjudicationError("resource component decision does not recompute")
    return expected


def _validate_receipt_internal(receipt: Mapping[str, Any]) -> dict[str, Any]:
    value = _mapping(dict(receipt), "G5 receipt")
    fields = {
        "schema",
        "validation_status",
        "analysis_source_state",
        "g5_gate_status",
        "promotion_eligible",
        "reason_codes",
        "bindings",
        "decision_contract",
        "saturation_component",
        "legitimate_p99_component",
        "bounded_resource_component",
        "unique_first_seen_report_only_component",
        "scientific_scope",
        "claim_disposition",
        "receipt_id",
    }
    if set(value) != fields:
        raise G5AdjudicationError("G5 receipt has the wrong fields")
    if value["schema"] != RECEIPT_SCHEMA or value["validation_status"] != VALID:
        raise G5AdjudicationError("G5 receipt schema or validation status differs")
    contract = _mapping(value["decision_contract"], "G5 receipt contract")
    _same(EXPECTED_CONTRACT, contract, "G5 receipt contract")
    source = _mapping(value["analysis_source_state"], "G5 analysis source state")
    if set(source) != {"commit", "clean", "scope"}:
        raise G5AdjudicationError("G5 analysis source state has the wrong fields")
    _hex(source.get("commit"), "G5 analysis commit", 40)
    if source.get("clean") is not True or source.get("scope") != ANALYSIS_SOURCE_SCOPE:
        raise G5AdjudicationError("G5 analysis source state is not a clean frozen commit")
    bindings = _mapping(value["bindings"], "G5 bindings")
    if set(bindings) != {
        "main_claims_manifest_id",
        "phase1_registration_id",
        "phase1_registration_status",
        "phase1_recovery_scope",
        "phase1_receipt_id",
        "phase1_aggregate_id",
        "service_config_id",
        "service_results_id",
        "service_summary_id",
        "service_source_commit",
        "analysis_commit",
    }:
        raise G5AdjudicationError("G5 bindings have the wrong fields")
    for field in (
        "phase1_registration_id",
        "phase1_receipt_id",
        "phase1_aggregate_id",
        "service_config_id",
        "service_results_id",
        "service_summary_id",
    ):
        _hex(bindings.get(field), f"G5 binding {field}", 64)
    _hex(bindings.get("service_source_commit"), "G5 service source commit", 40)
    if bindings.get("analysis_commit") != source["commit"]:
        raise G5AdjudicationError("G5 analysis binding contradicts source state")
    status = bindings.get("phase1_registration_status")
    if status == registration.REGISTERED:
        if bindings.get("phase1_recovery_scope") is not None:
            raise G5AdjudicationError("G5 P0 binding unexpectedly declares recovery scope")
    elif status == registration.RECOVERY_REGISTERED:
        if bindings.get("phase1_recovery_scope") != SERVICE_RECOVERY_SCOPE:
            raise G5AdjudicationError("G5 recovery binding lacks the service-only scope")
    else:
        raise G5AdjudicationError("G5 Phase 1 registration status is unsupported")
    saturation = _validate_saturation_component(value["saturation_component"], contract)
    p99 = _validate_p99_component(value["legitimate_p99_component"], contract)
    resources = _validate_resource_component(value["bounded_resource_component"], contract)
    unique = _mapping(
        value["unique_first_seen_report_only_component"], "unique-first-seen component"
    )
    if (
        unique.get("status")
        not in {
            "VALID_COMPLETE_REPORT_ONLY",
            "COMPLETE_RESOURCE_OBSERVATION_INDETERMINATE_REPORT_ONLY",
            "COMPLETE_OPERATIONAL_INVALID_MEASUREMENTS_REPORT_ONLY",
        }
        or unique.get("role") != contract["unique_first_seen_role"]
        or unique.get("controls_g5_directional_decision") is not False
        or unique.get("expected_point_count") != unique.get("observed_point_count")
    ):
        raise G5AdjudicationError("unique-first-seen report-only component is inconsistent")
    gate, reasons = _gate_from_components(saturation, p99, resources)
    if value["g5_gate_status"] != gate:
        raise G5AdjudicationError("G5 receipt gate contradicts component decisions")
    if value["promotion_eligible"] is not (gate == PASS):
        raise G5AdjudicationError("G5 receipt promotion flag contradicts the gate")
    if value["reason_codes"] != reasons:
        raise G5AdjudicationError("G5 receipt reason codes contradict the gate")
    disposition = {
        "c5_status": "PASS" if gate == PASS else "BLOCKED",
        "g5_status": "PASS" if gate == PASS else gate,
        "phase1_service_baseline_recovery": (
            bindings["phase1_recovery_scope"] == SERVICE_RECOVERY_SCOPE
        ),
        "unique_first_seen_directional_claim": False,
    }
    _same(disposition, value["claim_disposition"], "G5 claim disposition")
    body = {key: item for key, item in value.items() if key != "receipt_id"}
    if value["receipt_id"] != semantic_id(body):
        raise G5AdjudicationError("G5 receipt ID does not recompute")
    return value


def _validate_raw_registration(
    artifact: Mapping[str, Any], service_config: Mapping[str, Any]
) -> None:
    value = _mapping(dict(artifact), "raw Phase 1 registration")
    phase1_boundary = _phase1_registration_boundary(value)
    material = dict(value)
    observed_id = material.pop("registration_id", None)
    if observed_id != registration.semantic_id(material):
        raise G5AdjudicationError("raw Phase 1 registration ID does not recompute")
    selection = _mapping(value.get("selection"), "raw Phase 1 selection")
    _same(selection.get("selected_filter"), service_config.get("filter"), "registered filter")
    binding = _mapping(
        service_config.get("phase1_baseline_registration"),
        "service Phase 1 registration binding",
    )
    artifact_path = binding.get("registration_artifact_path")
    if type(artifact_path) is not str or not artifact_path:
        raise G5AdjudicationError("service registration binding lacks an artifact path")
    if phase1_boundary["status"] == registration.REGISTERED:
        expected_binding = registration.registered_binding(
            registration.SERVICE_BINDING_SCHEMA, value, artifact_path
        )
    else:
        expected_binding = registration.registered_recovery_binding(
            registration.SERVICE_BINDING_SCHEMA, value, artifact_path
        )
    _same(expected_binding, binding, "service Phase 1 registration binding")


def _validate_raw_service_inputs(
    *,
    service_config: Mapping[str, Any],
    service_config_id: str,
    service_rows: Sequence[Mapping[str, Any]],
    service_summary: Mapping[str, Any],
    service_source_commit: str,
    contract: Mapping[str, Any],
) -> list[Mapping[str, Any]]:
    config = _mapping(dict(service_config), "raw E7 config")
    if service_bench._canonical_hash(config) != service_config_id:
        raise G5AdjudicationError("raw E7 config ID does not recompute")
    _same(validate_g5_contract(config), contract, "raw E7 G5 contract")
    blockers = service_bench.formal_execution_blockers(config)
    if blockers:
        raise G5AdjudicationError(f"raw E7 config remains blocked: {blockers}")
    expected_points = service_bench.enumerate_points(config)
    expected = {point.point_id(service_config_id): point for point in expected_points}
    observed: dict[str, Mapping[str, Any]] = {}
    commits: set[str] = set()
    for row in service_rows:
        point_id = row.get("point_id")
        if type(point_id) is not str or point_id not in expected or point_id in observed:
            raise G5AdjudicationError("raw E7 rows contain an unexpected or duplicate point")
        try:
            service_bench._validate_result_contract(
                row, expected[point_id], config, service_config_id
            )
        except (KeyError, OverflowError, TypeError, ValueError) as error:
            raise G5AdjudicationError(f"invalid raw E7 result {point_id}: {error}") from error
        if row.get("result_status") != "VALID" and not _is_analyzable_g5_invalid(row):
            raise G5AdjudicationError(
                f"raw E7 result {point_id} has a non-resource measurement failure"
            )
        commit = _hex(row.get("commit"), f"raw E7 result {point_id} commit", 40)
        git = _mapping(row.get("git"), f"raw E7 result {point_id} Git provenance")
        if (
            git.get("commit") != commit
            or git.get("dirty") is not False
            or git.get("status_available") is not True
        ):
            raise G5AdjudicationError(f"raw E7 result {point_id} lacks clean provenance")
        commits.add(commit)
        observed[point_id] = row
    if set(observed) != set(expected) or len(commits) != 1:
        raise G5AdjudicationError("raw E7 rows do not form one complete frozen grid")
    ordered = [observed[point.point_id(service_config_id)] for point in expected_points]
    _same(ordered, list(service_rows), "raw E7 row order")
    recomputed = copy.deepcopy(ordered)
    service_bench._assign_saturation(config, recomputed)
    _same(recomputed, ordered, "raw E7 saturation annotations")
    if next(iter(commits)) != service_source_commit:
        raise G5AdjudicationError("raw E7 source commit binding differs")
    summary = _mapping(dict(service_summary), "raw E7 summary")
    _coverage_is_complete(summary, config, ordered)
    return ordered


def validate_receipt(
    receipt: Mapping[str, Any],
    *,
    registration_artifact: Mapping[str, Any],
    service_config: Mapping[str, Any],
    service_config_id: str,
    service_rows: Sequence[Mapping[str, Any]],
    service_summary: Mapping[str, Any],
    service_source_commit: str,
    contract: Mapping[str, Any],
    analysis_source_state: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate a public receipt by rebuilding it from the complete raw evidence."""

    value = _validate_receipt_internal(receipt)
    _validate_raw_registration(registration_artifact, service_config)
    ordered = _validate_raw_service_inputs(
        service_config=service_config,
        service_config_id=service_config_id,
        service_rows=service_rows,
        service_summary=service_summary,
        service_source_commit=service_source_commit,
        contract=contract,
    )
    expected = build_receipt(
        registration_artifact=registration_artifact,
        service_config=service_config,
        service_config_id=service_config_id,
        service_rows=ordered,
        service_summary=service_summary,
        service_source_commit=service_source_commit,
        contract=contract,
        analysis_source_state=analysis_source_state,
    )
    _same(expected, value, "raw-evidence-bound G5 receipt")
    return value


def _write_exclusive(
    path: Path,
    value: Mapping[str, Any],
    *,
    before_publish: Callable[[], None] | None = None,
) -> None:
    if path.exists() or path.is_symlink():
        raise G5AdjudicationError(f"refusing to overwrite {path}")
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
            raise G5AdjudicationError(f"refusing to overwrite {path}") from error
    finally:
        temporary.unlink(missing_ok=True)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = _StrictArgumentParser(description=__doc__)
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
        analysis_state = _require_analysis_checkout(args.expected_analysis_commit)
        artifact, binding = validate_registration_artifact(args.phase1_registration)
        config, config_id, rows, service = validate_service_evidence(
            config_path=args.service_config,
            results_path=args.service_results,
            summary_path=args.service_summary,
            registration_artifact=artifact,
            registration_binding=binding,
        )
        receipt = build_receipt(
            registration_artifact=artifact,
            service_config=config,
            service_config_id=config_id,
            service_rows=rows,
            service_summary=service["summary"],
            service_source_commit=service["source_commit"],
            contract=service["contract"],
            analysis_source_state=analysis_state,
        )
        validate_receipt(
            receipt,
            registration_artifact=artifact,
            service_config=config,
            service_config_id=config_id,
            service_rows=rows,
            service_summary=service["summary"],
            service_source_commit=service["source_commit"],
            contract=service["contract"],
            analysis_source_state=analysis_state,
        )
        _write_exclusive(
            args.output,
            receipt,
            before_publish=lambda: _same(
                analysis_state,
                _require_analysis_checkout(args.expected_analysis_commit),
                "G5 analysis source prepublication state",
            ),
        )
    except (G5AdjudicationError, KeyError, OSError, OverflowError, TypeError, ValueError) as error:
        print(
            canonical({"schema": RECEIPT_SCHEMA, "status": "INVALID", "error": str(error)}),
            file=sys.stderr,
        )
        return EXIT_INVALID
    print(
        canonical(
            {
                "status": receipt["validation_status"],
                "g5_gate_status": receipt["g5_gate_status"],
                "receipt_id": receipt["receipt_id"],
                "output": str(args.output.resolve()),
            }
        )
    )
    return EXIT_PASS if receipt["promotion_eligible"] else EXIT_NONPROMOTABLE


if __name__ == "__main__":
    raise SystemExit(main())
