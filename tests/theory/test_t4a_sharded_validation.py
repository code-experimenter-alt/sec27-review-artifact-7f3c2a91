from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

import pytest

from theory.optimizer_provenance import (
    FORMAL_PROFILE_SPEC,
    FROZEN_GENERATOR_SPEC,
    build_provenance,
    canonical_hash,
    dataset_spec,
    load_validation_config,
    validate_validation_config,
)
from theory.t4a_aggregate_validation import aggregate_shards
from theory.t4a_evidence import generate_instance, serialize_problem
from theory.t4a_sharded_validation import DEFAULT_CONFIG, run_shard


def _config(
    *, seed: int, expected: int, cvxpy: bool, brute_force: bool, points: int = 31
) -> dict[str, Any]:
    return {
        "schema": "traps-t4a-validation-config-v3",
        "experiment": "t4a_fixed_partition_validation",
        "profile": "smoke",
        "expected_instances": expected,
        "seed": seed,
        "generator": {
            "name": "random_feasible_problem",
            "version": 3,
            "dimensions": [1, 2],
            "index_seed_derivation": "splitmix64-v1",
            "numeric_canonicalization": "decimal-13-significant-v1",
        },
        "references": {
            "cvxpy": cvxpy,
            "brute_force": brute_force,
            "brute_force_points": points,
        },
        "thresholds": {
            "maximum_relative_gap": 1e-8,
            "maximum_primal_violation": 1e-8,
            "maximum_cvxpy_difference": 1e-7,
            "maximum_cvxpy_primal_violation": 1e-7,
            "maximum_dual_above_primal": 1e-8,
            "brute_force_tolerance": 1e-8,
        },
        "require_clean_git": False,
    }


def _provenance(config: dict[str, Any], *, dirty: bool = False) -> dict[str, Any]:
    return build_provenance(
        config,
        git={"commit": "a" * 40, "git_dirty": dirty},
        host="test-host",
        timestamp="2026-08-06T00:00:00Z",
    )


def _read(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_committed_optimizer_config_declares_formal_10k_design() -> None:
    config, config_hash = load_validation_config(DEFAULT_CONFIG)
    assert config["profile"] == "formal"
    assert config["expected_instances"] == 10_000
    assert config["seed"] == 20260805
    assert config["require_clean_git"] is True
    assert config["references"] == {
        "cvxpy": True,
        "brute_force": True,
        "brute_force_points": 101,
    }
    assert config["thresholds"] == FORMAL_PROFILE_SPEC["thresholds"]
    assert len(config_hash) == 64
    assert len(canonical_hash(dataset_spec(config))) == 64


def test_shards_are_deterministic_by_global_index_with_fixed_provenance(
    tmp_path: Path,
) -> None:
    whole = tmp_path / "whole.jsonl"
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    config = _config(seed=123, expected=16, cvxpy=False, brute_force=False)
    provenance = _provenance(config)
    common = dict(
        validation_config=config,
        provenance=provenance,
    )
    run_shard(start=10, count=6, output=whole, **common)
    run_shard(start=10, count=2, output=left, **common)
    run_shard(start=12, count=4, output=right, **common)
    assert _read(whole) == _read(left) + _read(right)
    required = {
        "commit",
        "git_dirty",
        "config_hash",
        "dataset_hash",
        "seed",
        "profile",
        "host",
        "timestamp_utc",
        "primal_objective",
        "dual_lower_bound",
        "relative_gap",
        "primal_violation",
    }
    assert all(required <= set(row) for row in _read(whole))


def test_formal_runner_rejects_dirty_provenance_before_writing(tmp_path: Path) -> None:
    output = tmp_path / "dirty.jsonl"
    config, _ = load_validation_config(DEFAULT_CONFIG)
    with pytest.raises(RuntimeError, match="clean Git worktree"):
        run_shard(
            start=0,
            count=1,
            output=output,
            validation_config=config,
            provenance=_provenance(config, dirty=True),
        )
    assert not output.exists()


def test_aggregator_fails_closed_on_inexact_index_coverage(tmp_path: Path) -> None:
    shard = tmp_path / "small.jsonl"
    config = _config(seed=5, expected=4, cvxpy=False, brute_force=False)
    run_shard(
        start=0,
        count=4,
        output=shard,
        validation_config=config,
        provenance=_provenance(config),
    )
    aggregate_config = _config(seed=5, expected=5, cvxpy=False, brute_force=False)
    summary = aggregate_shards([shard], validation_config=aggregate_config)
    assert summary["gate_status"] == "FAIL"
    assert summary["missing_index_count"] == 1
    assert summary["coverage_failures"]


@pytest.mark.integration
def test_small_complete_smoke_is_explicitly_diagnostic(tmp_path: Path) -> None:
    pytest.importorskip(
        "cvxpy",
        reason="the complete T4a cross-check requires the optional CVXPY reference solver",
    )
    shard = tmp_path / "complete.jsonl"
    config = _config(seed=77, expected=3, cvxpy=True, brute_force=True)
    provenance = _provenance(config)
    run_shard(
        start=0,
        count=3,
        output=shard,
        validation_config=config,
        provenance=provenance,
    )
    summary = aggregate_shards(
        [shard],
        validation_config=config,
    )
    assert summary["gate_status"] == "PASS"
    assert summary["profile"] == "smoke"
    assert summary["evidence_class"] == "diagnostic_only"
    assert summary["formal_gate_status"] == "NOT_APPLICABLE"
    assert summary["complete_numerical_rows"] == 3
    assert summary["provenance"]["commit"] == "a" * 40
    rendered = json.dumps(summary, sort_keys=True)
    anonymous_user_path = re.compile(r"(?i)[a-z]:[\\/]users[\\/][^\\/]+")
    assert anonymous_user_path.search(rendered) is None
    assert str(tmp_path) not in rendered


def test_aggregator_expands_directory_without_exposing_absolute_path(
    tmp_path: Path,
) -> None:
    shard_directory = tmp_path / "shards"
    shard_directory.mkdir()
    config = _config(seed=101, expected=2, cvxpy=False, brute_force=False)
    run_shard(
        start=0,
        count=2,
        output=shard_directory / "part-000.jsonl",
        validation_config=config,
        provenance=_provenance(config),
    )
    summary = aggregate_shards([shard_directory], validation_config=config)
    assert summary["input_files"] == ["external/part-000.jsonl"]
    assert all("cannot read" not in failure for failure in summary["row_failure_counts"])


@pytest.mark.parametrize("schema", ["traps-t4a-validation-v1", "traps-t4a-validation-v2"])
def test_legacy_schema_is_not_accepted_as_formal_evidence(
    tmp_path: Path, schema: str
) -> None:
    legacy = tmp_path / "legacy.jsonl"
    legacy.write_text(json.dumps({"schema": schema, "index": 0}) + "\n", encoding="utf-8")
    config = _config(seed=0, expected=1, cvxpy=False, brute_force=False)
    summary = aggregate_shards([legacy], validation_config=config)
    assert summary["gate_status"] == "FAIL"
    assert summary["unique_instances"] == 0
    assert summary["row_failure_counts"] == {"external/legacy.jsonl: schema mismatch": 1}


def test_aggregator_fails_closed_on_unhashable_provenance(tmp_path: Path) -> None:
    shard = tmp_path / "malformed.jsonl"
    config = _config(seed=41, expected=1, cvxpy=False, brute_force=False)
    run_shard(
        start=0,
        count=1,
        output=shard,
        validation_config=config,
        provenance=_provenance(config),
    )
    rows = _read(shard)
    rows[0]["commit"] = ["not", "hashable"]
    shard.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")
    summary = aggregate_shards([shard], validation_config=config)
    assert summary["gate_status"] == "FAIL"
    assert summary["row_failure_counts"]["invalid full commit"] == 1
    assert summary["row_failure_counts"]["unhashable commit"] == 1


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("name", "another_generator"),
        ("version", 999),
        ("dimensions", [1, 3]),
        ("index_seed_derivation", "linear"),
    ],
)
def test_frozen_generator_rejects_forged_config(tmp_path: Path, field: str, forged: object) -> None:
    config = _config(seed=13, expected=1, cvxpy=False, brute_force=False)
    config["generator"][field] = forged
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError, match="frozen random_feasible_problem"):
        load_validation_config(path)
    output = tmp_path / "must-not-exist.jsonl"
    with pytest.raises(ValueError, match="frozen random_feasible_problem"):
        run_shard(
            start=0,
            count=1,
            output=output,
            validation_config=config,
        )
    assert not output.exists()


@pytest.mark.integration
@pytest.mark.parametrize(
    "mutation",
    ["instance_seed", "dimensions", "problem", "missing_problem_field", "numeric_domain"],
)
def test_aggregator_rejects_forged_replay_rows(tmp_path: Path, mutation: str) -> None:
    pytest.importorskip("cvxpy")
    config = _config(seed=211, expected=1, cvxpy=True, brute_force=True)
    source = tmp_path / "source.jsonl"
    run_shard(
        start=0,
        count=1,
        output=source,
        validation_config=config,
        provenance=_provenance(config),
    )
    row = copy.deepcopy(_read(source)[0])
    if mutation == "instance_seed":
        row["instance_seed"] = int(row["instance_seed"]) + 1
    elif mutation == "dimensions":
        row["dimensions"] = 3
    elif mutation == "problem":
        row["problem"]["member_occupancy"][0] *= 2
    elif mutation == "missing_problem_field":
        del row["problem"]["beta"]
    else:
        row["primal_objective"] = -1.0
    forged = tmp_path / f"{mutation}.jsonl"
    forged.write_text(json.dumps(row, allow_nan=False) + "\n", encoding="utf-8")
    summary = aggregate_shards([forged], validation_config=config)
    assert summary["gate_status"] == "FAIL"
    assert summary["row_failure_counts"]


def test_test_sources_do_not_hardcode_a_windows_user_profile() -> None:
    anonymous_user_path = re.compile(r"(?i)[a-z]:[\\/]users[\\/][^\\/]+")
    theory_tests = Path(__file__).resolve().parent
    for path in theory_tests.glob("*.py"):
        assert anonymous_user_path.search(path.read_text(encoding="utf-8")) is None, path


def test_frozen_generator_constant_matches_committed_contract() -> None:
    assert FROZEN_GENERATOR_SPEC == {
        "name": "random_feasible_problem",
        "version": 3,
        "dimensions": [1, 2],
        "index_seed_derivation": "splitmix64-v1",
        "numeric_canonicalization": "decimal-13-significant-v1",
    }


def test_canonical_generator_matches_cross_platform_regression_records() -> None:
    config, _ = load_validation_config(DEFAULT_CONFIG)
    expected = {
        592: "b7a3be8de6d09c5072e1f67f84a5fb5afe09edf66ad19b81bbdf738e9b106674",
        837: "69373d17bb8a10368d2de847d1ee46afd40ecfd6460e19b7d7f5534fc76d2991",
        867: "42f1c6c185fb52215ae6d8083676bde8db56b9666be3823afee67d86fc73780a",
        934: "261a645ca9db8ec40242c1bcf634b8def3cc42d24b6b9e1eb86340a8eb48b131",
        1056: "6abd1f75d4e54593c90cdfae3c1a5f82c4213feb0f13c00802c024e57e3dcef9",
        1697: "9e95b0928dda700bdd92fa8feb732acb9b32d39607b177ed572e4d5ea6d7b11b",
        1791: "a8fd5ca2d81d9071b9eb6bfe24c4a19ac6618743318eb14b5e9ea843f84d216d",
        2124: "3f4e18c8257b7d698a9c170acc94eec848a5ddb03c44e63cf423e19c50700868",
    }
    for index, expected_hash in expected.items():
        _, dimensions, problem, record, problem_hash = generate_instance(config, index)
        assert serialize_problem(problem) == record
        assert len(record["member_occupancy"]) == dimensions
        assert problem_hash == expected_hash


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("expected_instances", 9_999),
        ("seed", 7),
        (
            "references",
            {"cvxpy": False, "brute_force": True, "brute_force_points": 101},
        ),
        (
            "thresholds",
            {
                **FORMAL_PROFILE_SPEC["thresholds"],
                "maximum_relative_gap": 2e-8,
            },
        ),
        ("require_clean_git", False),
    ],
)
def test_formal_profile_cannot_be_silently_downgraded(field: str, replacement: object) -> None:
    config, _ = load_validation_config(DEFAULT_CONFIG)
    config[field] = replacement
    with pytest.raises(ValueError, match="formal optimizer profile"):
        validate_validation_config(config)


def test_smoke_profile_cannot_claim_formal_scale_or_cleanliness() -> None:
    config = _config(seed=3, expected=2, cvxpy=False, brute_force=False)
    config["require_clean_git"] = True
    with pytest.raises(ValueError, match="smoke optimizer profile"):
        validate_validation_config(config)
    config["require_clean_git"] = False
    config["expected_instances"] = 10_000
    with pytest.raises(ValueError, match="smoke optimizer profile"):
        validate_validation_config(config)
