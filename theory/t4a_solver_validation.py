from __future__ import annotations

import argparse
import json
import random

import numpy as np

from reference.optimizer.fixed_partition import (
    FixedPartitionProblem,
    brute_force_grid,
    solve_fixed_partition,
    solve_with_cvxpy,
)


def random_feasible_problem(rng: random.Random, dimensions: int) -> FixedPartitionProblem:
    occupancy = np.asarray([10 ** rng.uniform(0.0, 3.0) for _ in range(dimensions)])
    beta = np.asarray([rng.uniform(0.25, 1.5) for _ in range(dimensions)])
    online = np.asarray([10 ** rng.uniform(-1.0, 2.0) for _ in range(dimensions)])
    compromise = np.asarray([10 ** rng.uniform(-1.0, 2.0) for _ in range(dimensions)])
    lower = np.asarray([rng.uniform(0.002, 0.12) for _ in range(dimensions)])
    upper = np.asarray([rng.uniform(max(0.2, lo + 0.05), 0.98) for lo in lower])
    a = occupancy / beta
    min_memory = float(np.dot(a, -np.log(upper)))
    max_memory = float(np.dot(a, -np.log(lower)))
    memory_budget = rng.uniform(min_memory, max_memory)
    min_work = float(np.dot(compromise, lower))
    max_work = float(np.dot(compromise, upper))
    work_floor = rng.uniform(min_work, max_work)
    return FixedPartitionProblem(
        member_occupancy=occupancy,
        beta=beta,
        online_weights=online,
        compromise_weights=compromise,
        memory_budget=memory_budget,
        work_factor_floor=work_floor,
        epsilon_min=lower,
        epsilon_cap=upper,
    )


def run_validation(
    instances: int,
    *,
    seed: int = 0,
    cvxpy_instances: int = 0,
    brute_force_instances: int = 20,
    brute_force_points: int = 151,
) -> dict[str, float | int | str]:
    if instances <= 0:
        raise ValueError("instances must be positive")
    rng = random.Random(seed)
    max_gap = 0.0
    max_violation = 0.0
    max_cvxpy_relative_difference = 0.0
    max_grid_advantage = 0.0
    cvxpy_completed = 0
    grid_completed = 0
    cvxpy_status = "not requested"

    for instance in range(instances):
        dimensions = rng.randint(1, 5)
        if instance < brute_force_instances:
            dimensions = rng.randint(1, 2)
        problem = random_feasible_problem(rng, dimensions)
        solution = solve_fixed_partition(problem)
        max_gap = max(max_gap, solution.relative_gap)
        max_violation = max(max_violation, solution.primal_violation)
        if not solution.primal_feasible:
            raise AssertionError({"instance": instance, "solution": solution})
        if solution.relative_gap >= 1e-8:
            raise AssertionError({"instance": instance, "solution": solution})

        if instance < brute_force_instances:
            grid = brute_force_grid(problem, points_per_dimension=brute_force_points)
            # A grid point is a feasible continuous point, so it cannot improve the
            # certified continuous optimum beyond numerical tolerance.
            advantage = solution.objective - grid.objective
            max_grid_advantage = max(max_grid_advantage, advantage)
            if advantage > 1e-8 * max(1.0, abs(solution.objective)):
                raise AssertionError(
                    {"instance": instance, "continuous": solution, "grid": grid}
                )
            grid_completed += 1

        if instance < cvxpy_instances:
            try:
                reference = solve_with_cvxpy(problem)
            except RuntimeError as error:
                cvxpy_status = str(error)
            else:
                difference = abs(solution.objective - reference.objective) / max(
                    abs(solution.objective), 1e-15
                )
                max_cvxpy_relative_difference = max(max_cvxpy_relative_difference, difference)
                if difference >= 1e-7:
                    raise AssertionError(
                        {"instance": instance, "continuous": solution, "cvxpy": reference}
                    )
                cvxpy_completed += 1
                cvxpy_status = "completed"

    return {
        "instances": instances,
        "maximum_relative_primal_dual_gap": max_gap,
        "maximum_scaled_primal_violation": max_violation,
        "brute_force_instances_completed": grid_completed,
        "maximum_grid_advantage_over_solver": max_grid_advantage,
        "cvxpy_instances_completed": cvxpy_completed,
        "cvxpy_status": cvxpy_status,
        "maximum_cvxpy_relative_objective_difference": max_cvxpy_relative_difference,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instances", type=int, default=100)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--cvxpy-instances", type=int, default=0)
    parser.add_argument("--brute-force-instances", type=int, default=20)
    parser.add_argument("--brute-force-points", type=int, default=151)
    args = parser.parse_args()
    print(
        json.dumps(
            run_validation(
                args.instances,
                seed=args.seed,
                cvxpy_instances=args.cvxpy_instances,
                brute_force_instances=args.brute_force_instances,
                brute_force_points=args.brute_force_points,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
