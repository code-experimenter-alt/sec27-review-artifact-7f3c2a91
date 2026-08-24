#!/usr/bin/env python3
"""Prospective Monte Carlo power plan for the frozen E9 failure classifier."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import multiprocessing
import os
import platform
import random
import re
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from itertools import combinations
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import scipy
import yaml
from scipy.optimize import brentq
from scipy.stats import beta as beta_distribution
from scipy.stats import norm
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.runners.failure_timing_bench import (  # noqa: E402
    CLASSIFIER_FEATURE_NAMES,
    FAILURE_CASES,
    FROZEN_CLASSIFIER_CONTRACT,
    PREREGISTERED_ARGON2_STRATUM_ID,
    PREREGISTERED_PBKDF2_STRATUM_ID,
    evaluation_seed_cluster_percentile_ci,
    profile_contract,
)
from experiments.runners.failure_timing_bench import (  # noqa: E402
    load_config as load_failure_timing_config,
)

CONFIG_PATH = ROOT / "experiments/configs/failure_timing_power.e9.yaml"
CONFIG_SCHEMA = "traps-e9-failure-timing-prospective-power-plan-v2"
CONFIG_STATUS = "FROZEN_PROSPECTIVE_BEFORE_FORMAL_E9_COLLECTION"
PROTOCOL = "e9-external-failure-classifier-power-v2"
SHARD_SCHEMA = "traps-e9-failure-timing-power-shard-v2"
RESULT_SCHEMA = "traps-e9-failure-timing-power-result-v2"
PASS_STATUS = "PASS_PROSPECTIVE_POWER_AND_DGP_BOUNDARY_OPERATING_CHARACTERISTIC"
BLOCKED_STATUS = "BLOCKED_PROSPECTIVE_POWER_OR_DGP_BOUNDARY_OPERATING_CHARACTERISTIC"
EXPECTED_NUMPY_VERSION = "2.4.6"
EXPECTED_SCIPY_VERSION = "1.17.1"
EXPECTED_STRATA = (
    PREREGISTERED_PBKDF2_STRATUM_ID,
    PREREGISTERED_ARGON2_STRATUM_ID,
)
EXPECTED_TRAINING_SEEDS = {
    PREREGISTERED_PBKDF2_STRATUM_ID: list(range(9400, 9410)),
    PREREGISTERED_ARGON2_STRATUM_ID: list(range(9410, 9420)),
}
EXPECTED_EVALUATION_SEEDS = {
    PREREGISTERED_PBKDF2_STRATUM_ID: list(range(9420, 9450)),
    PREREGISTERED_ARGON2_STRATUM_ID: list(range(9450, 9480)),
}
FULL_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SEMANTIC_ID_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_POWER_RESULT_DESCENDANT_CHANGES = {
    "audit/e9_evidence_protocol.md": frozenset({"M"}),
    "audit/phase6_service.md": frozenset({"M"}),
    "experiments/configs/failure_timing_power.e9.result.json": frozenset({"A"}),
    "experiments/configs/failure_timing_preregistered.e9.yaml": frozenset({"M"}),
    "experiments/configs/main_claims.yaml": frozenset({"M"}),
    "experiments/configs/service_bench.phase6.yaml": frozenset({"M"}),
    "experiments/configs/service_bench.smoke.yaml": frozenset({"M"}),
    "supplement/sections/failure_timing.tex": frozenset({"M"}),
    "tests/unit/test_claims_manifest.py": frozenset({"M"}),
}


class PowerPlanError(ValueError):
    """Raised when the frozen power contract or a result fails validation."""


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader, node: MappingNode, deep: bool = False
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _canonical(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise PowerPlanError("semantic material must be finite canonical JSON") from exc


def _semantic_id(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise PowerPlanError(f"{label} must be a string-keyed mapping")
    return dict(value)


def _array(value: object, label: str) -> list[Any]:
    if type(value) is not list:
        raise PowerPlanError(f"{label} must be an array")
    return list(value)


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    unexpected = value.keys() - expected
    if missing:
        raise PowerPlanError(f"{label} is missing {sorted(missing)}")
    if unexpected:
        raise PowerPlanError(f"{label} has unbound fields {sorted(unexpected)}")


def _exact_value(actual: object, expected: object, label: str) -> None:
    if type(actual) is not type(expected):
        raise PowerPlanError(f"{label} has the wrong exact type")
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        _exact_keys(actual, set(expected), label)
        for key, item in expected.items():
            _exact_value(actual[key], item, f"{label}.{key}")
        return
    if isinstance(expected, list):
        assert isinstance(actual, list)
        if len(actual) != len(expected):
            raise PowerPlanError(f"{label} has the wrong length")
        for index, (left, right) in enumerate(zip(actual, expected, strict=True)):
            _exact_value(left, right, f"{label}[{index}]")
        return
    if isinstance(expected, float) and not math.isfinite(actual):
        raise PowerPlanError(f"{label} must be finite")
    if actual != expected:
        raise PowerPlanError(f"{label} differs from the frozen contract")


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PowerPlanError(f"{label} must be an integer >= {minimum}")
    return value


def _calibrated_base(target_auc: float, heterogeneity: float) -> float:
    def objective(base: float) -> float:
        return (
            float(norm.cdf(abs(base - heterogeneity)))
            + float(norm.cdf(abs(base + heterogeneity)))
        ) / 2.0 - target_auc

    return float(brentq(objective, 0.0, 2.0, xtol=5e-15, rtol=1e-14))


def _classifier_contract_id() -> str:
    return _semantic_id(
        {
            "feature_names": list(CLASSIFIER_FEATURE_NAMES),
            "frozen_contract": dict(FROZEN_CLASSIFIER_CONTRACT),
        }
    )


def _validate_seed_mapping(
    value: object,
    strata: Sequence[str],
    expected_count: int,
    label: str,
) -> dict[str, list[int]]:
    mapping = _mapping(value, label)
    _exact_keys(mapping, set(strata), label)
    result: dict[str, list[int]] = {}
    for stratum in strata:
        seeds = _array(mapping[stratum], f"{label}.{stratum}")
        normalized = [_integer(seed, f"{label}.{stratum} seed", 1) for seed in seeds]
        if len(normalized) != expected_count or len(set(normalized)) != len(normalized):
            raise PowerPlanError(f"{label}.{stratum} has the wrong unique seed count")
        result[stratum] = normalized
    return result


def _validate_config(value: object, *, production: bool) -> dict[str, Any]:
    config = _mapping(value, "E9 power configuration")
    _exact_keys(
        config,
        {
            "schema",
            "status",
            "protocol",
            "classifier",
            "design",
            "generator",
            "simulation",
            "decision",
            "numeric_runtime",
            "provenance",
        },
        "E9 power configuration",
    )
    _exact_value(config["schema"], CONFIG_SCHEMA, "configuration schema")
    _exact_value(config["status"], CONFIG_STATUS, "configuration status")
    _exact_value(config["protocol"], PROTOCOL, "configuration protocol")

    classifier = _mapping(config["classifier"], "classifier")
    _exact_keys(
        classifier,
        {
            "identity_algorithm",
            "feature_count",
            "feature_names",
            "frozen_contract",
        },
        "classifier",
    )
    _exact_value(
        classifier["identity_algorithm"],
        "SHA256_CANONICAL_JSON_V1",
        "classifier.identity_algorithm",
    )
    _exact_value(classifier["feature_count"], len(CLASSIFIER_FEATURE_NAMES), "feature count")
    _exact_value(
        classifier["feature_names"], list(CLASSIFIER_FEATURE_NAMES), "classifier feature names"
    )
    _exact_value(
        classifier["frozen_contract"],
        dict(FROZEN_CLASSIFIER_CONTRACT),
        "classifier frozen contract",
    )

    design = _mapping(config["design"], "design")
    _exact_keys(
        design,
        {
            "kdf_strata",
            "failure_cases",
            "pair_order",
            "training_seeds_per_stratum",
            "evaluation_seeds_per_stratum",
            "samples_per_case_per_seed",
            "gate_count",
            "training_seeds_by_stratum",
            "evaluation_seeds_by_stratum",
        },
        "design",
    )
    _exact_value(design["kdf_strata"], list(EXPECTED_STRATA), "design.kdf_strata")
    _exact_value(design["failure_cases"], list(FAILURE_CASES), "design.failure_cases")
    _exact_value(
        design["pair_order"],
        "ALL_UNORDERED_COMBINATIONS_IN_DECLARED_CASE_ORDER",
        "design.pair_order",
    )
    training_count = _integer(
        design["training_seeds_per_stratum"], "training seeds per stratum", 2
    )
    evaluation_count = _integer(
        design["evaluation_seeds_per_stratum"], "evaluation seeds per stratum", 10
    )
    samples = _integer(design["samples_per_case_per_seed"], "samples per case/seed", 4)
    gate_count = len(EXPECTED_STRATA) * math.comb(len(FAILURE_CASES), 2)
    _exact_value(design["gate_count"], gate_count, "design.gate_count")
    training = _validate_seed_mapping(
        design["training_seeds_by_stratum"], EXPECTED_STRATA, training_count, "training seeds"
    )
    evaluation = _validate_seed_mapping(
        design["evaluation_seeds_by_stratum"],
        EXPECTED_STRATA,
        evaluation_count,
        "evaluation seeds",
    )
    all_training = {seed for seeds in training.values() for seed in seeds}
    all_evaluation = {seed for seeds in evaluation.values() for seed in seeds}
    if all_training & all_evaluation:
        raise PowerPlanError("training and evaluation seed sets must be disjoint")

    generator = _mapping(config["generator"], "generator")
    _validate_generator(generator)
    simulation = _mapping(config["simulation"], "simulation")
    _validate_simulation(simulation, evaluation_count, production=production)
    _validate_decision(_mapping(config["decision"], "decision"))
    _validate_runtime_contract(_mapping(config["numeric_runtime"], "numeric_runtime"))
    _validate_provenance_contract(_mapping(config["provenance"], "provenance"))

    if production:
        _exact_value(training_count, 10, "production training seed count")
        _exact_value(evaluation_count, 30, "production evaluation seed count")
        _exact_value(samples, 200, "production samples per case/seed")
        _exact_value(training, EXPECTED_TRAINING_SEEDS, "production training seeds")
        _exact_value(evaluation, EXPECTED_EVALUATION_SEEDS, "production evaluation seeds")
    return copy.deepcopy(config)


def _validate_generator(generator: dict[str, Any]) -> None:
    _exact_keys(
        generator,
        {
            "model",
            "power_scope",
            "training_randomness",
            "raw_feature_geometry",
            "score_distribution",
            "gate_dependence",
            "auc_model",
        },
        "generator",
    )
    _exact_value(
        generator["model"],
        "FIXED_CLASSIFIER_SCORE_SPACE_EQUAL_VARIANCE_BINORMAL_V1",
        "generator.model",
    )
    _exact_value(
        generator["power_scope"],
        "CONDITIONAL_ON_THE_FROZEN_TRAINED_PAIRWISE_CLASSIFIER",
        "generator.power_scope",
    )
    _exact_value(
        generator["training_randomness"],
        "EXCLUDED_FROM_THE_EVALUATION_SEED_CONFIDENCE_INTERVAL",
        "generator.training_randomness",
    )
    _exact_value(
        generator["raw_feature_geometry"],
        "NOT_MODELED_AND_NOT_CLAIMED_AS_WIRE_OR_FEATURE_DGP",
        "generator.raw_feature_geometry",
    )
    _exact_value(
        generator["score_distribution"],
        {
            "left": "NORMAL_POSITIVE_HALF_MEAN_UNIT_VARIANCE",
            "right": "NORMAL_NEGATIVE_HALF_MEAN_UNIT_VARIANCE",
            "population_auc_formula": "PHI_MEAN_DIFFERENCE_OVER_SQRT_2",
            "finite_sample_auc": "EXACT_AVERAGE_RANK_MANN_WHITNEY_ON_200_BY_200_SCORES",
            "ties": "PROBABILITY_ZERO_UNDER_THE_CONTINUOUS_MODEL",
        },
        "generator.score_distribution",
    )
    _exact_value(
        generator["gate_dependence"],
        {
            "random_streams": "INDEPENDENT_PER_REPLICATE_SCENARIO_STRATUM_AND_PAIR",
            "planning_decision": (
                "BONFERRONI_ONE_SIDED_CP_UNION_BOUND_INDEPENDENT_OF_GATE_DEPENDENCE"
            ),
        },
        "generator.gate_dependence",
    )
    auc = _mapping(generator["auc_model"], "generator.auc_model")
    expected_auc = {
        "primary_estimand": "MAX_MEAN_RAW_AUC_ONE_MINUS_MEAN_RAW_AUC",
        "oracle_sensitivity": (
            "MEAN_PER_SEED_MAX_RAW_AUC_ONE_MINUS_RAW_AUC_NOT_PRIMARY_ESTIMAND"
        ),
        "planning_population_mean_raw_auc": 0.52,
        "boundary_population_mean_raw_auc": 0.55,
        "seed_heterogeneity_distribution": (
            "EXACTLY_BALANCED_RADEMACHER_PROBIT_DISCRIMINABILITY"
        ),
        "seed_heterogeneity_probit_half_width": 0.02,
        "seed_heterogeneity_scope": (
            "FIFTEEN_LOW_AND_FIFTEEN_HIGH_AUC_SEEDS_PER_GATE_SHUFFLED_DETERMINISTICALLY"
        ),
        "calibration_equation": (
            "MEAN_PHI_ABS_BASE_PLUS_MINUS_PROBIT_HALF_WIDTH_EQUALS_TARGET_AUC"
        ),
        "calibration_absolute_tolerance": 1e-14,
        "planning_calibrated_base_probit": 0.05016361518288215,
        "boundary_calibrated_base_probit": 0.12568648161137017,
    }
    _exact_value(auc, expected_auc, "generator.auc_model")
    tolerance = float(auc["calibration_absolute_tolerance"])
    heterogeneity = float(auc["seed_heterogeneity_probit_half_width"])
    for scenario in ("planning", "boundary"):
        target = float(auc[f"{scenario}_population_mean_raw_auc"])
        frozen = float(auc[f"{scenario}_calibrated_base_probit"])
        if abs(_calibrated_base(target, heterogeneity) - frozen) > tolerance:
            raise PowerPlanError(f"{scenario} probit calibration differs from its equation")


def _validate_simulation(
    simulation: dict[str, Any], evaluation_count: int, *, production: bool
) -> None:
    _exact_keys(
        simulation,
        {
            "monte_carlo_design_replicates",
            "evaluation_seed_bootstrap_replicates",
            "confidence_level",
            "rng",
            "frozen_runner_bootstrap",
        },
        "simulation",
    )
    replicates = _integer(
        simulation["monte_carlo_design_replicates"], "Monte Carlo replicates", 1
    )
    bootstraps = _integer(
        simulation["evaluation_seed_bootstrap_replicates"], "bootstrap replicates", 1
    )
    _exact_value(simulation["confidence_level"], 0.95, "simulation confidence level")
    rng = _mapping(simulation["rng"], "simulation.rng")
    _exact_value(
        rng,
        {
            "seed_sequence": "NUMPY_SEEDSEQUENCE_V1",
            "bit_generator": "NUMPY_PCG64DXSM",
            "root_entropy": 20260810,
            "spawn_key_fields": [
                "replicate_index",
                "scenario_code",
                "stratum_index",
                "gate_index",
                "seed_position",
                "class_code",
                "stream_code",
            ],
            "scenario_codes": {"planning": 1, "boundary": 2},
            "class_codes": {"left": 1, "right": 2},
            "stream_codes": {
                "seed_heterogeneity_shuffle": 1,
                "finite_sample_scores": 2,
            },
            "shard_assignment": "REPLICATE_INDEX_MODULO_SHARD_COUNT",
        },
        "simulation.rng",
    )
    bootstrap = _mapping(simulation["frozen_runner_bootstrap"], "runner bootstrap")
    _exact_keys(
        bootstrap,
        {
            "method",
            "execution_optimization",
            "parity_oracle",
            "source_config_path",
            "scientific_config_contract_id",
            "profile_name",
            "profile_id_source",
            "formal_profile_contract_id",
            "namespace",
            "seed_derivation",
            "pseudorandom_sequence",
            "resample_size",
            "resample_sequence_scope",
            "prospective_power_conditioning",
        },
        "runner bootstrap",
    )
    _exact_value(
        bootstrap,
        {
            "method": "EXACT_MIRROR_OF_FAILURE_TIMING_BENCH_V5",
            "execution_optimization": (
                "CACHED_ORDERED_INDEX_MATRIX_LEFT_TO_RIGHT_FLOAT64_REDUCTION"
            ),
            "parity_oracle": (
                "experiments.runners.failure_timing_bench."
                "evaluation_seed_cluster_percentile_ci"
            ),
            "source_config_path": (
                "experiments/configs/failure_timing_preregistered.e9.yaml"
            ),
            "scientific_config_contract_id": (
                "7b9b180e23f97073bf7723affaca366d3c2b5fe2c2e81ae46473f4b0d607aefd"
            ),
            "profile_name": "formal",
            "profile_id_source": "CANONICAL_PROFILE_CONTRACT_ID_FROM_V5_CONFIG",
            "formal_profile_contract_id": (
                "8b34ed3b0cfd8434297fbf4e4f546a45c8a1f0961f500e1bf364d139e987c2ca"
            ),
            "namespace": "E9-FROZEN-CLASSIFIER-EVALUATION-SEED-BOOTSTRAP-v2",
            "seed_derivation": "SHA256_ASCII_NAMESPACE_FIRST_64_BITS_BIG_ENDIAN",
            "pseudorandom_sequence": "PYTHON_RANDOM_MT19937_RANDRANGE",
            "resample_size": 30,
            "resample_sequence_scope": (
                "FIXED_PER_STRATUM_PAIR_ACROSS_DESIGN_REPLICATES_AND_SCENARIOS"
            ),
            "prospective_power_conditioning": (
                "CONDITIONAL_ON_FROZEN_FORMAL_RESAMPLE_INDEX_SEQUENCE"
            ),
        },
        "runner bootstrap",
    )
    _exact_value(bootstrap["resample_size"], evaluation_count, "bootstrap resample size")
    if production:
        if replicates < 2000:
            raise PowerPlanError("production power plan requires at least 2000 design replicates")
        _exact_value(replicates, 2000, "production design replicate count")
        _exact_value(bootstraps, 2000, "production bootstrap replicate count")


def _validate_decision(decision: dict[str, Any]) -> None:
    _exact_value(
        decision,
        {
            "training_seed_power_scope": (
                "NOT_ESTIMATED_POWER_IS_CONDITIONAL_ON_THE_FROZEN_TRAINED_CLASSIFIER"
            ),
            "primary_seed_auc": "RAW_AUC_IN_FIXED_TRAINING_LABEL_DIRECTION",
            "primary_point_estimate": "MAX_MEAN_RAW_AUC_ONE_MINUS_MEAN_RAW_AUC",
            "primary_ci_upper": "MAX_RAW_CI_UPPER_ONE_MINUS_RAW_CI_LOWER",
            "per_seed_oracle_orientation_sensitivity": (
                "FAIL_CLOSED_ADDITIONAL_GATE_NOT_PRIMARY_ESTIMAND"
            ),
            "auc_tie_handling": "AVERAGE_RANK_MANN_WHITNEY",
            "interval": "EVALUATION_SEED_CLUSTER_PERCENTILE_BOOTSTRAP_TWO_SIDED_95",
            "percentile_definition": "N_MINUS_ONE_TIMES_P_LINEAR_INTERPOLATION",
            "auc_ci_upper_threshold": 0.55,
            "gate_rule": "GLOBAL_AND_PER_SEED_ORACLE_CI_UPPERS_LE_THRESHOLD",
            "planning_power_estimand": (
                "DEPENDENCE_ROBUST_LOWER_BOUND_ON_PROBABILITY_ALL_20_GATES_PASS"
            ),
            "planning_simultaneous_confidence_level": 0.95,
            "planning_per_gate_one_sided_alpha": 0.0025,
            "planning_maximum_sum_failure_probability_upper_bounds": 0.20,
            "boundary_estimand": (
                "DGP_CONDITIONAL_PER_GATE_PASS_PROBABILITY_AT_MEAN_RAW_AUC_0_55"
            ),
            "boundary_operating_characteristic_scope": (
                "FROZEN_BALANCED_BINORMAL_SCORE_DGP_ONLY_NOT_DISTRIBUTION_FREE_"
                "TYPE_I_CONTROL"
            ),
            "boundary_intersection_is_not_type_i_control": True,
            "boundary_maximum_each_gate_dgp_pass_binomial_ci95_upper": 0.05,
            "monte_carlo_interval": "CLOPPER_PEARSON_EXACT_TWO_SIDED_95",
        },
        "decision",
    )


def _validate_runtime_contract(runtime: dict[str, Any]) -> None:
    _exact_value(
        runtime,
        {
            "numpy_version": EXPECTED_NUMPY_VERSION,
            "scipy_version": EXPECTED_SCIPY_VERSION,
            "floating_dtype": "float64",
            "require_exact_versions": True,
            "production_platform": "Linux",
            "production_architecture": "x86_64",
        },
        "numeric_runtime",
    )


def _validate_provenance_contract(provenance: dict[str, Any]) -> None:
    _exact_value(
        provenance,
        {
            "require_full_source_commit": True,
            "require_clean_source": True,
            "source_status_scope": "ENTIRE_REPOSITORY_BEFORE_OUTPUT_WRITE",
            "require_identical_pre_and_postflight_source": True,
            "parallel_worker_start_method": "FORK_INHERITS_PREFLIGHT_LOADED_CODE",
        },
        "provenance",
    )


def load_config(path: Path = CONFIG_PATH) -> tuple[dict[str, Any], str]:
    try:
        source = path.read_text(encoding="utf-8")
        value = yaml.load(source, Loader=_UniqueKeySafeLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise PowerPlanError(f"cannot load E9 power configuration {path}: {exc}") from exc
    config = _validate_config(value, production=True)
    binding = _runner_binding(config)
    _verify_bootstrap_execution_parity(config, binding["formal_profile_contract_id"])
    return config, _semantic_id(config)


def _runner_binding(config: Mapping[str, Any]) -> dict[str, str]:
    bootstrap = _mapping(config["simulation"], "simulation")["frozen_runner_bootstrap"]
    contract = _mapping(bootstrap, "simulation.frozen_runner_bootstrap")
    relative = str(contract["source_config_path"])
    source_path = (ROOT / relative).resolve()
    try:
        source_path.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise PowerPlanError("runner bootstrap source config escapes the repository") from exc
    try:
        runner_config, _runner_config_id = load_failure_timing_config(source_path)
        _, formal_profile_id = profile_contract(runner_config, str(contract["profile_name"]))
    except (OSError, ValueError) as exc:
        raise PowerPlanError(f"cannot bind the frozen v5 formal profile: {exc}") from exc
    scientific_config = dict(runner_config)
    scientific_config.pop("main_claims_manifest_id", None)
    scientific_config_id = _semantic_id(scientific_config)
    _exact_value(
        scientific_config_id,
        contract["scientific_config_contract_id"],
        "frozen v5 scientific configuration contract ID",
    )
    _exact_value(
        formal_profile_id,
        contract["formal_profile_contract_id"],
        "frozen v5 formal profile contract ID",
    )
    return {
        "source_config_path": relative,
        "scientific_config_contract_id": scientific_config_id,
        "formal_profile_contract_id": formal_profile_id,
        "bootstrap_contract_authority": (
            "experiments.runners.failure_timing_bench."
            "evaluation_seed_cluster_percentile_ci"
        ),
    }


def _runtime_metadata(config: Mapping[str, Any]) -> dict[str, str]:
    expected = _mapping(config["numeric_runtime"], "numeric_runtime")
    libc_name, libc_version = platform.libc_ver()
    actual = {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "python_compiler": platform.python_compiler() or "UNAVAILABLE",
        "numpy_version": np.__version__,
        "scipy_version": scipy.__version__,
        "platform_system": platform.system(),
        "platform_architecture": platform.machine() or "UNAVAILABLE",
        "libc_runtime": " ".join(part for part in (libc_name, libc_version) if part)
        or "UNAVAILABLE",
    }
    if actual["numpy_version"] != expected["numpy_version"]:
        raise PowerPlanError("runtime NumPy version differs from the frozen power plan")
    if actual["scipy_version"] != expected["scipy_version"]:
        raise PowerPlanError("runtime SciPy version differs from the frozen power plan")
    return actual


def _source_metadata() -> dict[str, object]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise PowerPlanError(f"cannot establish power-plan source provenance: {exc}") from exc
    if FULL_COMMIT_RE.fullmatch(commit) is None:
        raise PowerPlanError("power-plan source commit is not full lowercase hexadecimal")
    return {
        "commit": commit,
        "clean": not bool(status.strip()),
        "status_scope": "ENTIRE_REPOSITORY_BEFORE_OUTPUT_WRITE",
    }


def _commit_is_ancestor(ancestor: str, descendant: str) -> bool:
    try:
        completed = subprocess.run(
            ["git", "merge-base", "--is-ancestor", ancestor, descendant],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PowerPlanError(f"cannot verify power-result source ancestry: {exc}") from exc
    if completed.returncode == 0:
        return True
    if completed.returncode == 1:
        return False
    raise PowerPlanError(
        "git merge-base could not verify power-result source ancestry: "
        f"{completed.stderr.strip()}"
    )


def _changed_paths_between_commits(
    ancestor: str, descendant: str
) -> list[tuple[str, str]]:
    try:
        completed = subprocess.run(
            [
                "git",
                "-c",
                "core.quotepath=false",
                "diff",
                "--name-status",
                "--no-renames",
                ancestor,
                descendant,
                "--",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PowerPlanError(
            f"cannot verify power-result descendant changes: {exc}"
        ) from exc
    changes: list[tuple[str, str]] = []
    for line in completed.stdout.splitlines():
        fields = line.split("\t", 1)
        if len(fields) != 2 or len(fields[0]) != 1 or not fields[1]:
            raise PowerPlanError("git returned an invalid descendant change record")
        changes.append((fields[0], fields[1].replace("\\", "/")))
    return changes


def _validate_consumer_source_lineage(
    recorded: Mapping[str, object], current: Mapping[str, object]
) -> None:
    _validate_source(recorded, expected=None)
    _validate_source(current, expected=None)
    ancestor = str(recorded["commit"])
    descendant = str(current["commit"])
    if not _commit_is_ancestor(ancestor, descendant):
        raise PowerPlanError(
            "power-result source commit is not an ancestor of the current clean checkout"
        )
    rejected = [
        f"{status}:{path}"
        for status, path in _changed_paths_between_commits(ancestor, descendant)
        if status not in ALLOWED_POWER_RESULT_DESCENDANT_CHANGES.get(path, frozenset())
    ]
    if rejected:
        raise PowerPlanError(
            "power-result descendant changed a frozen implementation, plan, or "
            f"unapproved path: {', '.join(rejected)}"
        )


def _preflight_bindings(
    config: Mapping[str, Any],
    *,
    source: Mapping[str, object] | None = None,
) -> tuple[dict[str, str], dict[str, object], dict[str, str]]:
    runtime = _runtime_metadata(config)
    required_platform = str(config["numeric_runtime"]["production_platform"])
    if runtime["platform_system"] != required_platform:
        raise PowerPlanError(
            f"production power simulation requires {required_platform}, not "
            f"{runtime['platform_system']}"
        )
    required_architecture = str(config["numeric_runtime"]["production_architecture"])
    if runtime["platform_architecture"] != required_architecture:
        raise PowerPlanError(
            "production power simulation architecture differs from the frozen plan"
        )
    source_value = dict(_source_metadata() if source is None else source)
    _validate_source(source_value, expected=None)
    if source_value["clean"] is not True:
        raise PowerPlanError("production power simulation requires a clean source checkout")
    binding = _runner_binding(config)
    _verify_bootstrap_execution_parity(config, binding["formal_profile_contract_id"])
    return runtime, source_value, binding


def _postflight_source(expected: Mapping[str, object]) -> None:
    observed = _source_metadata()
    _exact_value(observed, dict(expected), "identical pre/postflight source provenance")


def _validate_source(
    value: object, expected: Mapping[str, object] | None
) -> dict[str, object]:
    source = _mapping(value, "source provenance")
    _exact_keys(source, {"commit", "clean", "status_scope"}, "source provenance")
    if type(source["commit"]) is not str or FULL_COMMIT_RE.fullmatch(source["commit"]) is None:
        raise PowerPlanError("source commit must be 40 lowercase hexadecimal characters")
    _exact_value(source["clean"], True, "source clean state")
    _exact_value(
        source["status_scope"],
        "ENTIRE_REPOSITORY_BEFORE_OUTPUT_WRITE",
        "source status scope",
    )
    if expected is not None:
        _exact_value(source, dict(expected), "source provenance binding")
    return source


def _gate_specs(config: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    design = _mapping(config["design"], "design")
    return [
        (stratum, left, right)
        for stratum in design["kdf_strata"]
        for left, right in combinations(design["failure_cases"], 2)
    ]


def gate_ids(config: Mapping[str, Any]) -> list[str]:
    return [f"{stratum}:{left}__vs__{right}" for stratum, left, right in _gate_specs(config)]


def _rng(
    config: Mapping[str, Any],
    replicate_index: int,
    scenario_code: int,
    stratum_index: int,
    gate_index: int,
    seed_position: int,
    class_code: int,
    stream_code: int,
) -> np.random.Generator:
    root_entropy = int(_mapping(config["simulation"], "simulation")["rng"]["root_entropy"])
    spawn_key = (
        replicate_index,
        scenario_code,
        stratum_index,
        gate_index,
        seed_position,
        class_code,
        stream_code,
    )
    if any(type(value) is not int or value < 0 for value in spawn_key):
        raise PowerPlanError("SeedSequence spawn keys must be nonnegative integers")
    sequence = np.random.SeedSequence(entropy=root_entropy, spawn_key=spawn_key)
    return np.random.Generator(np.random.PCG64DXSM(sequence))


def _population_auc_by_seed(
    config: Mapping[str, Any],
    replicate_index: int,
    scenario: str,
    stratum_index: int,
    gate_index: int,
) -> list[float]:
    generator = _mapping(config["generator"], "generator")
    simulation = _mapping(config["simulation"], "simulation")
    rng_contract = _mapping(simulation["rng"], "simulation.rng")
    auc = _mapping(generator["auc_model"], "generator.auc_model")
    scenario_code = int(_mapping(rng_contract["scenario_codes"], "scenario codes")[scenario])
    stream_codes = _mapping(rng_contract["stream_codes"], "stream codes")
    evaluation_count = int(config["design"]["evaluation_seeds_per_stratum"])
    if evaluation_count % 2 != 0:
        raise PowerPlanError("balanced seed heterogeneity requires an even evaluation count")
    heterogeneity = float(auc["seed_heterogeneity_probit_half_width"])
    base = float(auc[f"{scenario}_calibrated_base_probit"])
    signs = np.asarray(
        [-1.0] * (evaluation_count // 2) + [1.0] * (evaluation_count // 2),
        dtype=np.float64,
    )
    shuffle_rng = _rng(
        config,
        replicate_index,
        scenario_code,
        stratum_index,
        gate_index,
        0,
        0,
        int(stream_codes["seed_heterogeneity_shuffle"]),
    )
    shuffle_rng.shuffle(signs)
    values = [float(norm.cdf(abs(base + sign * heterogeneity))) for sign in signs]
    target = float(auc[f"{scenario}_population_mean_raw_auc"])
    if abs(sum(values) / len(values) - target) > float(
        auc["calibration_absolute_tolerance"]
    ):
        raise PowerPlanError("balanced population AUCs differ from the frozen target")
    return values


def _score_seed_raw_aucs(
    config: Mapping[str, Any],
    replicate_index: int,
    scenario: str,
    stratum_index: int,
    gate_index: int,
) -> list[float]:
    simulation = _mapping(config["simulation"], "simulation")
    rng_contract = _mapping(simulation["rng"], "simulation.rng")
    scenario_code = int(_mapping(rng_contract["scenario_codes"], "scenario codes")[scenario])
    class_codes = _mapping(rng_contract["class_codes"], "class codes")
    stream_code = int(
        _mapping(rng_contract["stream_codes"], "stream codes")["finite_sample_scores"]
    )
    sample_count = int(config["design"]["samples_per_case_per_seed"])
    raw_aucs: list[float] = []
    for seed_position, population_auc in enumerate(
        _population_auc_by_seed(
            config, replicate_index, scenario, stratum_index, gate_index
        )
    ):
        mean_difference = math.sqrt(2.0) * float(norm.ppf(population_auc))
        left_rng = _rng(
            config,
            replicate_index,
            scenario_code,
            stratum_index,
            gate_index,
            seed_position,
            int(class_codes["left"]),
            stream_code,
        )
        right_rng = _rng(
            config,
            replicate_index,
            scenario_code,
            stratum_index,
            gate_index,
            seed_position,
            int(class_codes["right"]),
            stream_code,
        )
        left = left_rng.normal(0.5 * mean_difference, 1.0, sample_count).tolist()
        right = right_rng.normal(-0.5 * mean_difference, 1.0, sample_count).tolist()
        raw_aucs.append(_auc(left, right))
    return raw_aucs


def _auc(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or not right:
        raise PowerPlanError("AUC requires two nonempty classes")
    if any(not math.isfinite(float(value)) for value in (*left, *right)):
        raise PowerPlanError("AUC inputs must be finite")
    combined = sorted(
        [(float(value), 1) for value in left]
        + [(float(value), 0) for value in right]
    )
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


def _bootstrap_namespace(
    formal_profile_id: str, stratum: str, left: str, right: str
) -> str:
    return f"{formal_profile_id}:{stratum}:{left}:{right}"


_BOOTSTRAP_INDEX_CACHE: dict[tuple[str, int, int], tuple[int, np.ndarray]] = {}


def _ordered_bootstrap_indices(
    bootstrap_namespace: str, bootstrap_replicates: int, resample_size: int
) -> tuple[int, np.ndarray]:
    key = (bootstrap_namespace, bootstrap_replicates, resample_size)
    cached = _BOOTSTRAP_INDEX_CACHE.get(key)
    if cached is not None:
        return cached
    seed = int.from_bytes(
        hashlib.sha256(
            (
                "E9-FROZEN-CLASSIFIER-EVALUATION-SEED-BOOTSTRAP-v2:"
                + bootstrap_namespace
            ).encode("ascii")
        ).digest()[:8],
        "big",
    )
    rng = random.Random(seed)
    indices = np.fromiter(
        (
            rng.randrange(resample_size)
            for _ in range(bootstrap_replicates * resample_size)
        ),
        dtype=np.intp,
        count=bootstrap_replicates * resample_size,
    ).reshape(bootstrap_replicates, resample_size)
    indices.setflags(write=False)
    result = (seed, indices)
    _BOOTSTRAP_INDEX_CACHE[key] = result
    return result


def _linear_percentile(values: Sequence[float], probability: float) -> float:
    if not values:
        raise PowerPlanError("cannot compute a percentile of an empty sample")
    ordered = sorted(float(value) for value in values)
    if any(not math.isfinite(value) for value in ordered):
        raise PowerPlanError("percentile input must be finite")
    position = (len(ordered) - 1) * probability
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + fraction * (ordered[upper] - ordered[lower])


def _evaluation_seed_cluster_ci(
    seed_raw_auc: Sequence[float],
    bootstrap_replicates: int,
    *,
    bootstrap_namespace: str,
) -> dict[str, object]:
    """Bit-exact cached execution of the runner's frozen bootstrap helper."""

    values = [float(value) for value in seed_raw_auc]
    if len(values) < 2 or any(
        not math.isfinite(value) or value < 0.0 or value > 1.0 for value in values
    ):
        raise PowerPlanError("evaluation-seed CI requires finite raw AUCs in [0, 1]")
    replicates = _integer(bootstrap_replicates, "evaluation-seed bootstrap replicates", 1)
    if type(bootstrap_namespace) is not str or not bootstrap_namespace.isascii():
        raise PowerPlanError("evaluation-seed bootstrap namespace must be ASCII")
    seed, indices = _ordered_bootstrap_indices(
        bootstrap_namespace, replicates, len(values)
    )
    index_rows = indices.tolist()
    oracle_values = [max(value, 1.0 - value) for value in values]
    raw_bootstraps = [
        sum(values[index] for index in row) / len(values) for row in index_rows
    ]
    oracle_bootstraps = [
        sum(oracle_values[index] for index in row) / len(values) for row in index_rows
    ]
    raw_lower = _linear_percentile(raw_bootstraps, 0.025)
    raw_upper = _linear_percentile(raw_bootstraps, 0.975)
    fixed_lower = (
        0.5
        if raw_lower <= 0.5 <= raw_upper
        else min(max(raw_lower, 1.0 - raw_lower), max(raw_upper, 1.0 - raw_upper))
    )
    raw_mean = sum(values) / len(values)
    return {
        "bootstrap_seed": seed,
        "bootstrap_replicates": replicates,
        "raw_auc_ci_lower": raw_lower,
        "raw_auc_ci_upper": raw_upper,
        "fixed_classifier_direction_invariant_auc": max(raw_mean, 1.0 - raw_mean),
        "fixed_classifier_direction_invariant_ci_lower": fixed_lower,
        "fixed_classifier_direction_invariant_ci_upper": max(raw_upper, 1.0 - raw_lower),
        "per_seed_oracle_direction_invariant_auc": (
            sum(float(value) for value in oracle_values) / len(oracle_values)
        ),
        "per_seed_oracle_ci_lower": _linear_percentile(oracle_bootstraps, 0.025),
        "per_seed_oracle_ci_upper": _linear_percentile(oracle_bootstraps, 0.975),
    }


def _verify_bootstrap_execution_parity(
    config: Mapping[str, Any], formal_profile_id: str
) -> None:
    bootstrap_replicates = int(config["simulation"]["evaluation_seed_bootstrap_replicates"])
    evaluation_count = int(config["design"]["evaluation_seeds_per_stratum"])
    sentinel = [0.35 + 0.3 * index / (evaluation_count - 1) for index in range(evaluation_count)]
    for stratum, left, right in _gate_specs(config):
        namespace = _bootstrap_namespace(formal_profile_id, stratum, left, right)
        optimized = _evaluation_seed_cluster_ci(
            sentinel, bootstrap_replicates, bootstrap_namespace=namespace
        )
        authority = evaluation_seed_cluster_percentile_ci(
            sentinel, bootstrap_replicates, bootstrap_namespace=namespace
        )
        if optimized != authority:
            raise PowerPlanError(
                "cached bootstrap execution differs from the frozen runner helper"
            )


def _evaluate_scenario(
    config: Mapping[str, Any],
    replicate_index: int,
    scenario: str,
    formal_profile_id: str,
) -> dict[str, object]:
    simulation = _mapping(config["simulation"], "simulation")
    bootstrap_replicates = int(simulation["evaluation_seed_bootstrap_replicates"])
    threshold = float(_mapping(config["decision"], "decision")["auc_ci_upper_threshold"])
    raw_by_gate: list[list[float]] = []
    raw_ci_lower: list[float] = []
    raw_ci_upper: list[float] = []
    fixed_point: list[float] = []
    fixed_ci_lower: list[float] = []
    fixed_ci_upper: list[float] = []
    oracle_point: list[float] = []
    oracle_ci_lower: list[float] = []
    oracle_ci_upper: list[float] = []
    ci_lower: list[float] = []
    ci_upper: list[float] = []
    bootstrap_seeds: list[int] = []
    gate_pass: list[bool] = []
    for gate_index, (stratum, left, right) in enumerate(_gate_specs(config)):
        stratum_index = EXPECTED_STRATA.index(stratum)
        seed_raw = _score_seed_raw_aucs(
            config, replicate_index, scenario, stratum_index, gate_index
        )
        interval = _evaluation_seed_cluster_ci(
            seed_raw,
            bootstrap_replicates,
            bootstrap_namespace=_bootstrap_namespace(
                formal_profile_id, stratum, left, right
            ),
        )
        fixed_lower = float(interval["fixed_classifier_direction_invariant_ci_lower"])
        fixed_upper = float(interval["fixed_classifier_direction_invariant_ci_upper"])
        oracle_lower = float(interval["per_seed_oracle_ci_lower"])
        oracle_upper = float(interval["per_seed_oracle_ci_upper"])
        lower = min(fixed_lower, oracle_lower)
        upper = max(fixed_upper, oracle_upper)
        raw_by_gate.append(seed_raw)
        raw_ci_lower.append(float(interval["raw_auc_ci_lower"]))
        raw_ci_upper.append(float(interval["raw_auc_ci_upper"]))
        fixed_point.append(float(interval["fixed_classifier_direction_invariant_auc"]))
        fixed_ci_lower.append(fixed_lower)
        fixed_ci_upper.append(fixed_upper)
        oracle_point.append(float(interval["per_seed_oracle_direction_invariant_auc"]))
        oracle_ci_lower.append(oracle_lower)
        oracle_ci_upper.append(oracle_upper)
        ci_lower.append(lower)
        ci_upper.append(upper)
        bootstrap_seeds.append(int(interval["bootstrap_seed"]))
        gate_pass.append(fixed_upper <= threshold and oracle_upper <= threshold)
    return {
        "seed_raw_auc": raw_by_gate,
        "raw_auc_ci_lower": raw_ci_lower,
        "raw_auc_ci_upper": raw_ci_upper,
        "fixed_classifier_direction_invariant_auc": fixed_point,
        "fixed_classifier_direction_invariant_ci_lower": fixed_ci_lower,
        "fixed_classifier_direction_invariant_ci_upper": fixed_ci_upper,
        "per_seed_oracle_direction_invariant_auc": oracle_point,
        "per_seed_oracle_ci_lower": oracle_ci_lower,
        "per_seed_oracle_ci_upper": oracle_ci_upper,
        "bootstrap_seed": bootstrap_seeds,
        "ci_lower": ci_lower,
        "ci_upper": ci_upper,
        "gate_pass": gate_pass,
    }


def _simulate_replicate(
    config: Mapping[str, Any], replicate_index: int, formal_profile_id: str
) -> dict[str, object]:
    _integer(replicate_index, "replicate index")
    planning = _evaluate_scenario(config, replicate_index, "planning", formal_profile_id)
    boundary = _evaluate_scenario(config, replicate_index, "boundary", formal_profile_id)
    return {
        "replicate_index": replicate_index,
        "planning": planning,
        "planning_joint_all_pass": all(planning["gate_pass"]),
        "boundary_marginal": boundary,
    }


_WORKER_CONFIG: dict[str, Any] | None = None
_WORKER_PROFILE_ID: str | None = None


def _initialize_worker(config: dict[str, Any], formal_profile_id: str) -> None:
    global _WORKER_CONFIG, _WORKER_PROFILE_ID
    _WORKER_CONFIG = config
    _WORKER_PROFILE_ID = formal_profile_id
    bootstrap_replicates = int(config["simulation"]["evaluation_seed_bootstrap_replicates"])
    resample_size = int(config["design"]["evaluation_seeds_per_stratum"])
    for stratum, left, right in _gate_specs(config):
        _ordered_bootstrap_indices(
            _bootstrap_namespace(formal_profile_id, stratum, left, right),
            bootstrap_replicates,
            resample_size,
        )


def _worker_simulate(replicate_index: int) -> dict[str, object]:
    if _WORKER_CONFIG is None or _WORKER_PROFILE_ID is None:
        raise RuntimeError("power worker was not initialized")
    return _simulate_replicate(_WORKER_CONFIG, replicate_index, _WORKER_PROFILE_ID)


def _simulate_indices(
    config: dict[str, Any],
    indices: Sequence[int],
    formal_profile_id: str,
    *,
    workers: int,
) -> list[dict[str, object]]:
    worker_count = _integer(workers, "worker count", 1)
    normalized = [_integer(index, "replicate index") for index in indices]
    if len(normalized) != len(set(normalized)):
        raise PowerPlanError("replicate indices must be unique")
    if worker_count == 1:
        return [
            _simulate_replicate(config, replicate_index, formal_profile_id)
            for replicate_index in normalized
        ]
    context = (
        multiprocessing.get_context("fork")
        if platform.system() == "Linux"
        else multiprocessing.get_context()
    )
    with ProcessPoolExecutor(
        max_workers=worker_count,
        mp_context=context,
        initializer=_initialize_worker,
        initargs=(config, formal_profile_id),
    ) as executor:
        records = list(executor.map(_worker_simulate, normalized, chunksize=1))
    return records


def _clopper_pearson(successes: int, trials: int, confidence: float) -> tuple[float, float]:
    successes = _integer(successes, "binomial successes")
    trials = _integer(trials, "binomial trials", 1)
    if successes > trials:
        raise PowerPlanError("binomial successes cannot exceed trials")
    if not 0.0 < confidence < 1.0:
        raise PowerPlanError("binomial confidence must lie strictly between zero and one")
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
    if not (math.isfinite(lower) and math.isfinite(upper) and 0.0 <= lower <= upper <= 1.0):
        raise PowerPlanError("Clopper-Pearson computation failed closed")
    return lower, upper


def _one_sided_clopper_pearson_upper(
    successes: int, trials: int, alpha: float
) -> float:
    successes = _integer(successes, "one-sided binomial successes")
    trials = _integer(trials, "one-sided binomial trials", 1)
    if successes > trials or not 0.0 < alpha < 1.0:
        raise PowerPlanError("one-sided binomial inputs are invalid")
    upper = (
        1.0
        if successes == trials
        else float(beta_distribution.ppf(1.0 - alpha, successes + 1, trials - successes))
    )
    if not math.isfinite(upper) or not 0.0 <= upper <= 1.0:
        raise PowerPlanError("one-sided Clopper-Pearson computation failed closed")
    return upper


def _planning_summary(
    config: Mapping[str, Any], records: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    decision = _mapping(config["decision"], "decision")
    successes = sum(record["planning_joint_all_pass"] is True for record in records)
    trials = len(records)
    lower, upper = _clopper_pearson(
        successes, trials, float(config["simulation"]["confidence_level"])
    )
    alpha = float(decision["planning_per_gate_one_sided_alpha"])
    failure_gates: list[dict[str, object]] = []
    for gate_index, identifier in enumerate(gate_ids(config)):
        failures = sum(
            record["planning"]["gate_pass"][gate_index] is False for record in records
        )
        upper_failure = _one_sided_clopper_pearson_upper(failures, trials, alpha)
        failure_gates.append(
            {
                "gate_id": identifier,
                "failure_count": failures,
                "design_replicate_count": trials,
                "observed_failure_probability": failures / trials,
                "one_sided_alpha": alpha,
                "failure_probability_upper": upper_failure,
            }
        )
    sum_upper = sum(float(gate["failure_probability_upper"]) for gate in failure_gates)
    maximum_sum = float(
        decision["planning_maximum_sum_failure_probability_upper_bounds"]
    )
    return {
        "estimand": (
            "DEPENDENCE_ROBUST_LOWER_BOUND_ON_PROBABILITY_ALL_20_GATES_PASS"
        ),
        "all_pass_count": successes,
        "design_replicate_count": trials,
        "joint_all_pass_probability": successes / trials,
        "binomial_ci95_lower": lower,
        "binomial_ci95_upper": upper,
        "joint_binomial_interval_role": "DESCRIPTIVE_NOT_THE_POWER_GATE",
        "simultaneous_confidence_level": float(
            decision["planning_simultaneous_confidence_level"]
        ),
        "bonferroni_per_gate_one_sided_alpha": alpha,
        "marginal_failure_gates": failure_gates,
        "sum_failure_probability_upper_bounds": sum_upper,
        "dependence_robust_joint_pass_probability_lower": max(0.0, 1.0 - sum_upper),
        "maximum_sum_failure_probability_upper_bounds": maximum_sum,
        "passes": sum_upper <= maximum_sum,
    }


def _boundary_summary(
    config: Mapping[str, Any], records: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    decision = _mapping(config["decision"], "decision")
    identifiers = gate_ids(config)
    trials = len(records)
    confidence = float(config["simulation"]["confidence_level"])
    threshold = float(
        decision["boundary_maximum_each_gate_dgp_pass_binomial_ci95_upper"]
    )
    gates: list[dict[str, object]] = []
    for gate_index, identifier in enumerate(identifiers):
        successes = sum(
            record["boundary_marginal"]["gate_pass"][gate_index] is True
            for record in records
        )
        lower, upper = _clopper_pearson(successes, trials, confidence)
        gates.append(
            {
                "gate_id": identifier,
                "dgp_conditional_gate_pass_count": successes,
                "design_replicate_count": trials,
                "dgp_conditional_gate_pass_probability": successes / trials,
                "binomial_ci95_lower": lower,
                "binomial_ci95_upper": upper,
                "maximum_ci95_upper": threshold,
                "passes": upper <= threshold,
            }
        )
    maximum_probability = max(
        float(gate["dgp_conditional_gate_pass_probability"]) for gate in gates
    )
    maximum_upper = max(float(gate["binomial_ci95_upper"]) for gate in gates)
    return {
        "estimand": (
            "DGP_CONDITIONAL_PER_GATE_PASS_PROBABILITY_AT_MEAN_RAW_AUC_0_55"
        ),
        "scope": (
            "FROZEN_BALANCED_BINORMAL_SCORE_DGP_ONLY_NOT_DISTRIBUTION_FREE_"
            "TYPE_I_CONTROL"
        ),
        "calibration_unit": "EACH_OF_20_STRATUM_PAIR_GATES_SEPARATELY",
        "intersection_is_not_reported_as_type_i_control": True,
        "marginal_gates": gates,
        "maximum_observed_dgp_conditional_gate_pass_probability": maximum_probability,
        "maximum_per_pair_binomial_ci95_upper": maximum_upper,
        "required_maximum_each_gate_dgp_pass_binomial_ci95_upper": threshold,
        "all_20_dgp_operating_characteristics_pass": all(
            gate["passes"] is True for gate in gates
        ),
    }


def workload_counts(config: Mapping[str, Any]) -> dict[str, int]:
    """Return exact operation counts implied by a validated plan."""

    design = _mapping(config["design"], "design")
    simulation = _mapping(config["simulation"], "simulation")
    replicates = int(simulation["monte_carlo_design_replicates"])
    bootstraps = int(simulation["evaluation_seed_bootstrap_replicates"])
    strata = len(design["kdf_strata"])
    cases = len(design["failure_cases"])
    gates = strata * math.comb(cases, 2)
    scenarios = 2
    evaluation_seeds = int(design["evaluation_seeds_per_stratum"])
    samples = int(design["samples_per_case_per_seed"])
    gate_evaluations = replicates * scenarios * gates
    scores_per_gate = 2 * evaluation_seeds * samples
    cluster_resamples = gate_evaluations * bootstraps
    return {
        "scenario_count": scenarios,
        "classifier_fit_count": 0,
        "conditional_fixed_classifier_gate_evaluation_count": gate_evaluations,
        "generated_score_count": gate_evaluations * scores_per_gate,
        "finite_sample_auc_count": gate_evaluations * evaluation_seeds,
        "bootstrap_cluster_resample_count": cluster_resamples,
        "bootstrap_metric_reduction_count": 2 * cluster_resamples,
        "bootstrap_seed_value_selection_count": (
            2 * cluster_resamples * evaluation_seeds
        ),
    }


def _result_material(
    config: Mapping[str, Any],
    config_id: str,
    records: Sequence[dict[str, object]],
    runtime: Mapping[str, str],
    source: Mapping[str, object],
    runner_binding: Mapping[str, str],
) -> dict[str, object]:
    planning = _planning_summary(config, records)
    boundary = _boundary_summary(config, records)
    status = (
        PASS_STATUS
        if planning["passes"] is True
        and boundary["all_20_dgp_operating_characteristics_pass"] is True
        else BLOCKED_STATUS
    )
    return {
        "schema": RESULT_SCHEMA,
        "protocol": PROTOCOL,
        "status": status,
        "config_id": config_id,
        "classifier_contract_id": _classifier_contract_id(),
        "runtime": dict(runtime),
        "source": dict(source),
        "runner_binding": dict(runner_binding),
        "gate_ids": gate_ids(config),
        "design_replicate_count": len(records),
        "workload": workload_counts(config),
        "records": list(records),
        "planning": planning,
        "boundary": boundary,
    }


def _build_result(
    config: Mapping[str, Any],
    config_id: str,
    records: Sequence[dict[str, object]],
    runtime: Mapping[str, str],
    source: Mapping[str, object],
    runner_binding: Mapping[str, str],
) -> dict[str, object]:
    material = _result_material(config, config_id, records, runtime, source, runner_binding)
    return {**material, "result_id": _semantic_id(material)}


def _validate_runtime_metadata(
    value: object,
    config: Mapping[str, Any],
    expected: Mapping[str, str] | None,
    *,
    production: bool,
) -> dict[str, str]:
    runtime = _mapping(value, "result runtime")
    _exact_keys(
        runtime,
        {
            "python_implementation",
            "python_version",
            "python_compiler",
            "numpy_version",
            "scipy_version",
            "platform_system",
            "platform_architecture",
            "libc_runtime",
        },
        "result runtime",
    )
    for field in (
        "python_implementation",
        "python_version",
        "python_compiler",
        "platform_system",
        "platform_architecture",
        "libc_runtime",
    ):
        if type(runtime[field]) is not str or not runtime[field]:
            raise PowerPlanError(f"result runtime {field} must be a nonempty string")
    contract = _mapping(config["numeric_runtime"], "numeric_runtime")
    _exact_value(runtime["numpy_version"], contract["numpy_version"], "result NumPy version")
    _exact_value(runtime["scipy_version"], contract["scipy_version"], "result SciPy version")
    if production:
        _exact_value(
            runtime["platform_system"],
            contract["production_platform"],
            "result production platform",
        )
        _exact_value(
            runtime["platform_architecture"],
            contract["production_architecture"],
            "result production architecture",
        )
    if expected is not None:
        _exact_value(runtime, dict(expected), "result runtime environment binding")
    return {key: str(item) for key, item in runtime.items()}


def _validate_runner_binding(
    value: object, expected: Mapping[str, str]
) -> dict[str, str]:
    binding = _mapping(value, "runner binding")
    _exact_value(binding, dict(expected), "runner binding")
    return {key: str(item) for key, item in binding.items()}


def _validate_records(
    value: object,
    config: Mapping[str, Any],
    formal_profile_id: str,
    expected_indices: Sequence[int],
) -> list[dict[str, object]]:
    records = _array(value, "replicate records")
    indices = [
        _integer(
            _mapping(record, "replicate record").get("replicate_index"),
            "replicate index",
        )
        for record in records
    ]
    if indices != list(expected_indices):
        raise PowerPlanError("replicate records are missing, duplicated, or out of order")
    replay_workers = (
        min(8, os.cpu_count() or 1)
        if platform.system() == "Linux" and len(indices) >= 8
        else 1
    )
    replayed = _simulate_indices(
        dict(config), indices, formal_profile_id, workers=replay_workers
    )
    _exact_value(records, replayed, "deterministic full power-simulation replay")
    return replayed


def _require_config_id(config: Mapping[str, Any], config_id: str) -> None:
    if SEMANTIC_ID_RE.fullmatch(config_id) is None:
        raise PowerPlanError("power configuration ID must be 64 lowercase hexadecimal characters")
    _exact_value(config_id, _semantic_id(config), "power configuration ID")


def _build_shard(
    config: Mapping[str, Any],
    config_id: str,
    records: Sequence[dict[str, object]],
    runtime: Mapping[str, str],
    source: Mapping[str, object],
    runner_binding: Mapping[str, str],
    shard_index: int,
    shard_count: int,
) -> dict[str, object]:
    return {
        "schema": SHARD_SCHEMA,
        "protocol": PROTOCOL,
        "config_id": config_id,
        "classifier_contract_id": _classifier_contract_id(),
        "runtime": dict(runtime),
        "source": dict(source),
        "runner_binding": dict(runner_binding),
        "shard_index": shard_index,
        "shard_count": shard_count,
        "replicate_indices": [int(record["replicate_index"]) for record in records],
        "records": list(records),
    }


def _environment_expectations(
    config: Mapping[str, Any],
    verify_environment: bool,
    expected_source: Mapping[str, object] | None,
) -> tuple[dict[str, str] | None, dict[str, object] | None, dict[str, str]]:
    binding = _runner_binding(config)
    if verify_environment:
        runtime, source, actual_binding = _preflight_bindings(config)
        _exact_value(actual_binding, binding, "current runner binding")
        return runtime, source, binding
    if expected_source is not None:
        source = _validate_source(expected_source, expected=None)
    else:
        source = None
    return None, source, binding


def _validate_shard(
    value: object,
    config: Mapping[str, Any],
    config_id: str,
    *,
    production: bool,
    verify_environment: bool = True,
    expected_source: Mapping[str, object] | None = None,
) -> dict[str, object]:
    config = _validate_config(config, production=production)
    _require_config_id(config, config_id)
    expected_runtime, source_expectation, binding = _environment_expectations(
        config, verify_environment, expected_source
    )
    shard = _mapping(value, "power shard")
    _exact_keys(
        shard,
        {
            "schema",
            "protocol",
            "config_id",
            "classifier_contract_id",
            "runtime",
            "source",
            "runner_binding",
            "shard_index",
            "shard_count",
            "replicate_indices",
            "records",
        },
        "power shard",
    )
    _exact_value(shard["schema"], SHARD_SCHEMA, "power shard schema")
    _exact_value(shard["protocol"], PROTOCOL, "power shard protocol")
    _exact_value(shard["config_id"], config_id, "power shard config ID")
    _exact_value(
        shard["classifier_contract_id"],
        _classifier_contract_id(),
        "power shard classifier contract ID",
    )
    runtime = _validate_runtime_metadata(
        shard["runtime"], config, expected_runtime, production=production
    )
    source = _validate_source(shard["source"], source_expectation)
    validated_binding = _validate_runner_binding(shard["runner_binding"], binding)
    shard_count = _integer(shard["shard_count"], "shard count", 1)
    shard_index = _integer(shard["shard_index"], "shard index")
    if shard_index >= shard_count:
        raise PowerPlanError("shard index must be less than shard count")
    total = int(config["simulation"]["monte_carlo_design_replicates"])
    expected_indices = list(range(shard_index, total, shard_count))
    if not expected_indices:
        raise PowerPlanError("power shard has no assigned design replicates")
    _exact_value(shard["replicate_indices"], expected_indices, "shard replicate assignment")
    records = _validate_records(
        shard["records"],
        config,
        validated_binding["formal_profile_contract_id"],
        expected_indices,
    )
    if verify_environment and source_expectation is not None:
        _postflight_source(source_expectation)
    return {
        "schema": SHARD_SCHEMA,
        "protocol": PROTOCOL,
        "config_id": config_id,
        "classifier_contract_id": _classifier_contract_id(),
        "runtime": runtime,
        "source": source,
        "runner_binding": validated_binding,
        "shard_index": shard_index,
        "shard_count": shard_count,
        "replicate_indices": expected_indices,
        "records": records,
    }


def validate_shard(
    value: object,
    config: Mapping[str, Any],
    config_id: str,
    *,
    verify_environment: bool = True,
    expected_source: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return _validate_shard(
        value,
        config,
        config_id,
        production=True,
        verify_environment=verify_environment,
        expected_source=expected_source,
    )


def _validate_result(
    value: object,
    config: Mapping[str, Any],
    config_id: str,
    *,
    production: bool,
    verify_environment: bool = True,
    expected_source: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Recompute every bootstrap CI, gate decision, and Monte Carlo summary."""

    config = _validate_config(config, production=production)
    _require_config_id(config, config_id)
    binding = _runner_binding(config)
    current_source: dict[str, object] | None = None
    if verify_environment:
        expected_runtime = _runtime_metadata(config)
        current_source = _validate_source(_source_metadata(), expected=None)
        source_expectation = dict(expected_source) if expected_source is not None else None
    else:
        expected_runtime = None
        source_expectation = (
            _validate_source(expected_source, expected=None)
            if expected_source is not None
            else None
        )
    result = _mapping(value, "power result")
    material_keys = {
        "schema",
        "protocol",
        "status",
        "config_id",
        "classifier_contract_id",
        "runtime",
        "source",
        "runner_binding",
        "gate_ids",
        "design_replicate_count",
        "workload",
        "records",
        "planning",
        "boundary",
    }
    _exact_keys(result, material_keys | {"result_id"}, "power result")
    _exact_value(result["schema"], RESULT_SCHEMA, "power result schema")
    _exact_value(result["protocol"], PROTOCOL, "power result protocol")
    _exact_value(result["config_id"], config_id, "power result config ID")
    _exact_value(
        result["classifier_contract_id"],
        _classifier_contract_id(),
        "power result classifier contract ID",
    )
    runtime = _validate_runtime_metadata(
        result["runtime"], config, expected_runtime, production=production
    )
    source = _validate_source(result["source"], source_expectation)
    if current_source is not None:
        _validate_consumer_source_lineage(source, current_source)
    validated_binding = _validate_runner_binding(result["runner_binding"], binding)
    identifiers = gate_ids(config)
    _exact_value(result["gate_ids"], identifiers, "power result gate IDs")
    total = int(config["simulation"]["monte_carlo_design_replicates"])
    _exact_value(result["design_replicate_count"], total, "design replicate count")
    records = _validate_records(
        result["records"],
        config,
        validated_binding["formal_profile_contract_id"],
        list(range(total)),
    )
    expected_material = _result_material(
        config, config_id, records, runtime, source, validated_binding
    )
    for field in ("status", "workload", "planning", "boundary"):
        _exact_value(result[field], expected_material[field], f"power result {field}")
    result_id = result["result_id"]
    if type(result_id) is not str or SEMANTIC_ID_RE.fullmatch(result_id) is None:
        raise PowerPlanError("result ID must be 64 lowercase hexadecimal characters")
    supplied_material = {key: result[key] for key in material_keys}
    _exact_value(result_id, _semantic_id(supplied_material), "power result ID")
    if current_source is not None:
        _postflight_source(current_source)
    return {**expected_material, "result_id": str(result_id)}


def validate_result(
    value: object,
    config: Mapping[str, Any],
    config_id: str,
    *,
    verify_environment: bool = True,
    expected_source: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return _validate_result(
        value,
        config,
        config_id,
        production=True,
        verify_environment=verify_environment,
        expected_source=expected_source,
    )


def _require_tracked_result_path(path: Path) -> Path:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise PowerPlanError("formal power result must be tracked inside the repository") from exc
    try:
        completed = subprocess.run(
            ["git", "ls-files", "--error-unmatch", "--", relative.as_posix()],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PowerPlanError(f"cannot verify tracked power result path: {exc}") from exc
    if completed.returncode != 0:
        raise PowerPlanError("formal power result is not tracked by Git")
    return resolved


def load_result(
    path: Path, config_path: Path = CONFIG_PATH
) -> tuple[dict[str, object], str]:
    """Load a tracked PASS artifact and strictly revalidate every bound criterion."""

    config, config_id = load_config(config_path)
    result = validate_result(read_json(_require_tracked_result_path(path)), config, config_id)
    if result["status"] != PASS_STATUS:
        raise PowerPlanError("E9 formal preflight requires a validated PASS power result")
    return result, str(result["result_id"])


def run_shard(
    config: Mapping[str, Any],
    config_id: str,
    *,
    shard_index: int,
    shard_count: int,
    workers: int = 1,
) -> dict[str, object]:
    """Run one deterministic modulo-assigned production shard."""

    validated = _validate_config(config, production=True)
    _require_config_id(validated, config_id)
    count = _integer(shard_count, "shard count", 1)
    index = _integer(shard_index, "shard index")
    if index >= count:
        raise PowerPlanError("shard index must be less than shard count")
    runtime, source, binding = _preflight_bindings(validated)
    total = int(validated["simulation"]["monte_carlo_design_replicates"])
    indices = list(range(index, total, count))
    if not indices:
        raise PowerPlanError("power shard has no assigned design replicates")
    records = _simulate_indices(
        validated,
        indices,
        binding["formal_profile_contract_id"],
        workers=workers,
    )
    shard = _build_shard(
        validated, config_id, records, runtime, source, binding, index, count
    )
    _postflight_source(source)
    return shard


def simulate(
    config: Mapping[str, Any], config_id: str, *, workers: int = 1
) -> dict[str, object]:
    """Run the complete production plan, returning PASS or fail-closed BLOCKED JSON."""

    validated = _validate_config(config, production=True)
    _require_config_id(validated, config_id)
    runtime, source, binding = _preflight_bindings(validated)
    total = int(validated["simulation"]["monte_carlo_design_replicates"])
    records = _simulate_indices(
        validated,
        list(range(total)),
        binding["formal_profile_contract_id"],
        workers=workers,
    )
    result = _build_result(validated, config_id, records, runtime, source, binding)
    validated_result = validate_result(
        result,
        validated,
        config_id,
        verify_environment=False,
        expected_source=source,
    )
    _postflight_source(source)
    return validated_result


def _aggregate_shards(
    config: Mapping[str, Any],
    config_id: str,
    shards: Sequence[object],
    *,
    production: bool,
    verify_environment: bool = True,
    expected_source: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Validate and aggregate an exact complete shard set in shard-index order."""

    validated = _validate_config(config, production=production)
    _require_config_id(validated, config_id)
    if not shards:
        raise PowerPlanError("aggregation requires at least one shard")
    normalized = [
        _validate_shard(
            shard,
            validated,
            config_id,
            production=production,
            verify_environment=False,
            expected_source=expected_source,
        )
        for shard in shards
    ]
    shard_counts = {int(shard["shard_count"]) for shard in normalized}
    if len(shard_counts) != 1:
        raise PowerPlanError("shards disagree on the frozen shard count")
    shard_count = shard_counts.pop()
    by_index = {int(shard["shard_index"]): shard for shard in normalized}
    if len(by_index) != len(normalized) or set(by_index) != set(range(shard_count)):
        raise PowerPlanError("aggregation requires exactly one shard for every shard index")
    first = by_index[0]
    for shard in by_index.values():
        for field in ("runtime", "source", "runner_binding"):
            _exact_value(shard[field], first[field], f"cross-shard {field}")
    if verify_environment:
        runtime, source, binding = _preflight_bindings(validated)
        _exact_value(first["runtime"], runtime, "aggregate current runtime")
        _exact_value(first["source"], source, "aggregate current source")
        _exact_value(first["runner_binding"], binding, "aggregate current runner binding")
    else:
        runtime = dict(first["runtime"])
        source = dict(first["source"])
        binding = dict(first["runner_binding"])
        if expected_source is not None:
            _exact_value(source, dict(expected_source), "aggregate expected source")
    records = sorted(
        [record for shard in by_index.values() for record in shard["records"]],
        key=lambda record: int(record["replicate_index"]),
    )
    total = int(validated["simulation"]["monte_carlo_design_replicates"])
    if [int(record["replicate_index"]) for record in records] != list(range(total)):
        raise PowerPlanError("aggregated shards do not cover every replicate exactly once")
    result = _build_result(validated, config_id, records, runtime, source, binding)
    validated_result = _validate_result(
        result,
        validated,
        config_id,
        production=production,
        verify_environment=False,
        expected_source=source,
    )
    if verify_environment:
        _postflight_source(source)
    return validated_result


def aggregate_shards(
    config: Mapping[str, Any],
    config_id: str,
    shards: Sequence[object],
    *,
    verify_environment: bool = True,
    expected_source: Mapping[str, object] | None = None,
) -> dict[str, object]:
    return _aggregate_shards(
        config,
        config_id,
        shards,
        production=True,
        verify_environment=verify_environment,
        expected_source=expected_source,
    )


class _DuplicateJsonKeyError(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def read_json(path: Path) -> object:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_json_keys
        )
    except (OSError, UnicodeError, json.JSONDecodeError, _DuplicateJsonKeyError) as exc:
        raise PowerPlanError(f"cannot load JSON artifact {path}: {exc}") from exc


def write_json(path: Path, value: object, *, overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise PowerPlanError(f"refusing to overwrite existing output {path}")
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=True,
            allow_nan=False,
        ) + "\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(payload, encoding="utf-8", newline="\n")
        if path.exists() and not overwrite:
            temporary.unlink(missing_ok=True)
            raise PowerPlanError(f"refusing to overwrite existing output {path}")
        os.replace(temporary, path)
    except (OSError, TypeError, ValueError) as exc:
        raise PowerPlanError(f"cannot write JSON artifact {path}: {exc}") from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="run the complete production power plan")
    run.add_argument("--config", type=Path, default=CONFIG_PATH)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--workers", type=int, default=max(1, os.cpu_count() or 1))
    run.add_argument("--overwrite", action="store_true")

    shard = subparsers.add_parser("shard", help="run one modulo-assigned shard")
    shard.add_argument("--config", type=Path, default=CONFIG_PATH)
    shard.add_argument("--output", type=Path, required=True)
    shard.add_argument("--shard-index", type=int, required=True)
    shard.add_argument("--shard-count", type=int, required=True)
    shard.add_argument("--workers", type=int, default=1)
    shard.add_argument("--overwrite", action="store_true")

    aggregate = subparsers.add_parser("aggregate", help="aggregate a complete shard set")
    aggregate.add_argument("--config", type=Path, default=CONFIG_PATH)
    aggregate.add_argument("--output", type=Path, required=True)
    aggregate.add_argument("--shards", type=Path, nargs="+", required=True)
    aggregate.add_argument("--overwrite", action="store_true")

    validate = subparsers.add_parser("validate", help="strictly validate one result")
    validate.add_argument("--config", type=Path, default=CONFIG_PATH)
    validate.add_argument("--result", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config, config_id = load_config(args.config)
        if args.command == "run":
            result = simulate(config, config_id, workers=args.workers)
            _postflight_source(_mapping(result["source"], "power result source"))
            write_json(args.output, result, overwrite=args.overwrite)
            print(
                json.dumps(
                    {
                        "status": result["status"],
                        "result_id": result["result_id"],
                        "output": str(args.output),
                    },
                    sort_keys=True,
                )
            )
            return 0 if result["status"] == PASS_STATUS else 3
        if args.command == "shard":
            shard = run_shard(
                config,
                config_id,
                shard_index=args.shard_index,
                shard_count=args.shard_count,
                workers=args.workers,
            )
            _postflight_source(_mapping(shard["source"], "power shard source"))
            write_json(args.output, shard, overwrite=args.overwrite)
            print(
                json.dumps(
                    {
                        "schema": shard["schema"],
                        "shard_index": shard["shard_index"],
                        "replicate_count": len(shard["records"]),
                        "output": str(args.output),
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "aggregate":
            result = aggregate_shards(
                config, config_id, [read_json(path) for path in args.shards]
            )
            _postflight_source(_mapping(result["source"], "power result source"))
            write_json(args.output, result, overwrite=args.overwrite)
            print(
                json.dumps(
                    {
                        "status": result["status"],
                        "result_id": result["result_id"],
                        "output": str(args.output),
                    },
                    sort_keys=True,
                )
            )
            return 0 if result["status"] == PASS_STATUS else 3
        result = validate_result(read_json(args.result), config, config_id)
        print(json.dumps({"status": result["status"], "result_id": result["result_id"]}))
        return 0 if result["status"] == PASS_STATUS else 3
    except (PowerPlanError, ValueError) as exc:
        print(f"failure_timing_power: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
