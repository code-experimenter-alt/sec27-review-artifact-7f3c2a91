from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Mapping

from reference.optimizer.fixed_partition import (
    brute_force_grid,
    solve_fixed_partition,
    solve_with_cvxpy,
)
from theory.optimizer_provenance import (
    FROZEN_GENERATOR_SPEC,
    ROOT,
    build_provenance,
    canonical_hash,
    dataset_spec,
    display_path,
    load_validation_config,
    redact_user_paths,
    require_formal_provenance,
    validate_validation_config,
)
from theory.t4a_evidence import generate_instance

SCHEMA = "traps-t4a-validation-v3"
DEFAULT_CONFIG = ROOT / "experiments" / "configs" / "optimizer_t4a_validation.json"


def validate_one(
    *,
    index: int,
    config: Mapping[str, Any],
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    seed = int(config["seed"])
    references = config["references"]
    include_cvxpy = bool(references["cvxpy"])
    include_brute_force = bool(references["brute_force"])
    brute_force_points = int(references["brute_force_points"])
    derived_seed, dimensions, problem, problem_record, problem_hash = generate_instance(
        config, index
    )
    row: dict[str, Any] = {
        "schema": SCHEMA,
        "index": index,
        "base_seed": seed,
        "seed": seed,
        "profile": config["profile"],
        "instance_seed": derived_seed,
        "dimensions": dimensions,
        "generator": dict(FROZEN_GENERATOR_SPEC),
        "problem": problem_record,
        "problem_hash": problem_hash,
        "status": "pass",
        "error": None,
        "cvxpy_status": "not_requested",
        "brute_force_status": "not_requested",
        "commit": provenance.get("commit"),
        "git_dirty": provenance.get("git_dirty"),
        "config_hash": provenance.get("config_hash"),
        "dataset_hash": provenance.get("dataset_hash"),
        "host": provenance.get("host"),
        "timestamp_utc": provenance.get("timestamp_utc"),
    }
    try:
        solution = solve_fixed_partition(problem)
        row.update(
            primal_objective=solution.objective,
            primal_epsilon=list(solution.epsilon),
            memory_used=solution.memory_used,
            memory_budget=problem.memory_budget,
            compromise_mass=solution.compromise_mass,
            work_factor_floor=problem.work_factor_floor,
            primal_violation=solution.primal_violation,
            dual_lambda=solution.dual_lambda,
            dual_nu=solution.dual_nu,
            dual_lower_bound=solution.dual_lower_bound,
            conservative_dual_lower_bound=solution.conservative_dual_lower_bound,
            raw_primal_minus_dual=solution.raw_primal_minus_dual,
            dual_above_primal_residual=solution.dual_above_primal_residual,
            primal_dual_gap=solution.primal_dual_gap,
            relative_gap=solution.relative_gap,
            conservative_primal_dual_gap=solution.conservative_primal_dual_gap,
            conservative_relative_gap=solution.conservative_relative_gap,
            stationarity_residual=solution.stationarity_residual,
            complementarity_residual=solution.complementarity_residual,
            primal_solver_success=solution.solver_success,
            primal_solver_message=solution.solver_message,
        )

        if include_cvxpy:
            try:
                reference = solve_with_cvxpy(problem)
            except Exception as error:  # The row must survive for fail-closed aggregation.
                row["cvxpy_status"] = "error"
                row["cvxpy_error"] = redact_user_paths(f"{type(error).__name__}: {error}")
                row["status"] = "fail"
            else:
                difference = abs(solution.objective - reference.objective) / max(
                    1.0, abs(solution.objective)
                )
                cvxpy_epsilon = reference.epsilon
                _, _, _, lower, upper = problem.arrays()
                cvxpy_violation = max(
                    0.0,
                    (problem.memory(cvxpy_epsilon) - problem.memory_budget)
                    / max(1.0, problem.memory_budget),
                    (problem.work_factor_floor - problem.compromise_mass(cvxpy_epsilon))
                    / max(1.0, problem.work_factor_floor),
                    max(lo - value for lo, value in zip(lower, cvxpy_epsilon, strict=True)),
                    max(value - cap for value, cap in zip(cvxpy_epsilon, upper, strict=True)),
                )
                row.update(
                    cvxpy_status=reference.status,
                    cvxpy_solver=reference.solver,
                    cvxpy_epsilon=list(reference.epsilon),
                    cvxpy_objective=reference.objective,
                    cvxpy_relative_objective_difference=difference,
                    cvxpy_primal_violation=cvxpy_violation,
                )

        if include_brute_force:
            try:
                grid = brute_force_grid(problem, points_per_dimension=brute_force_points)
            except Exception as error:
                row["brute_force_status"] = "error"
                row["brute_force_error"] = redact_user_paths(f"{type(error).__name__}: {error}")
                row["status"] = "fail"
            else:
                row.update(
                    brute_force_status="completed",
                    brute_force_epsilon=list(grid.epsilon),
                    brute_force_objective=grid.objective,
                    brute_force_feasible_points=grid.feasible_points,
                    brute_force_total_points=grid.total_points,
                    solver_minus_brute_force_objective=solution.objective - grid.objective,
                )
    except Exception as error:
        row["status"] = "fail"
        row["error"] = redact_user_paths(f"{type(error).__name__}: {error}")
    return row


def run_shard(
    *,
    start: int,
    count: int,
    output: Path,
    validation_config: Mapping[str, Any],
    provenance: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if start < 0 or count <= 0:
        raise ValueError("start must be nonnegative and count must be positive")
    config, config_hash = validate_validation_config(validation_config)
    seed = int(config["seed"])
    references = config["references"]
    expected_instances = int(config["expected_instances"])
    if start + count > expected_instances:
        raise ValueError("shard range exceeds config expected_instances")
    run_provenance = dict(
        provenance if provenance is not None else build_provenance(config, config_hash=config_hash)
    )
    if run_provenance.get("config_hash") != config_hash:
        raise ValueError("provenance config_hash does not match validation config")
    if run_provenance.get("dataset_hash") != canonical_hash(dataset_spec(config)):
        raise ValueError("provenance dataset_hash does not match validation config")
    if int(run_provenance.get("seed", -1)) != seed:
        raise ValueError("provenance seed does not match runner seed")
    if run_provenance.get("profile") != config["profile"]:
        raise ValueError("provenance profile does not match validation config")
    host = run_provenance.get("host")
    if not isinstance(host, str) or not host.strip() or redact_user_paths(host) != host:
        raise ValueError("provenance host is missing or contains a user path")
    if bool(config["require_clean_git"]):
        require_formal_provenance(run_provenance)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    failures = 0
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for index in range(start, start + count):
            row = validate_one(
                index=index,
                config=config,
                provenance=run_provenance,
            )
            failures += int(row["status"] != "pass")
            handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, output)
    return {
        "schema": SCHEMA,
        "start": start,
        "count": count,
        "seed": seed,
        "profile": config["profile"],
        "output": display_path(output),
        "failures": failures,
        "cvxpy_requested": bool(references["cvxpy"]),
        "brute_force_requested": bool(references["brute_force"]),
        "brute_force_points": int(references["brute_force_points"]),
        "commit": run_provenance.get("commit"),
        "git_dirty": run_provenance.get("git_dirty"),
        "config_hash": run_provenance.get("config_hash"),
        "dataset_hash": run_provenance.get("dataset_hash"),
        "host": run_provenance.get("host"),
        "timestamp_utc": run_provenance.get("timestamp_utc"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    config, _ = load_validation_config(args.config)
    summary = run_shard(
        start=args.start,
        count=args.count,
        output=args.output,
        validation_config=config,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    if summary["failures"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
