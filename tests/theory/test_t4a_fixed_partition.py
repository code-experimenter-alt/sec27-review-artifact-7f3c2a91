from __future__ import annotations

import math
import random
from types import SimpleNamespace

import numpy as np
import pytest

from reference.optimizer import fixed_partition
from reference.optimizer.fixed_partition import (
    FixedPartitionProblem,
    InfeasibleProblem,
    brute_force_grid,
    lagrangian_dual_value,
    solve_fixed_partition,
)
from theory.t4a_solver_validation import random_feasible_problem


def test_one_region_closed_form_with_active_work_floor() -> None:
    problem = FixedPartitionProblem(
        member_occupancy=[10.0],
        beta=[1.0],
        online_weights=[3.0],
        compromise_weights=[2.0],
        memory_budget=10.0 * math.log(5.0),
        work_factor_floor=0.6,
        epsilon_min=0.01,
        epsilon_cap=0.9,
    )
    solution = solve_fixed_partition(problem)
    assert solution.primal_feasible
    assert math.isclose(solution.epsilon[0], 0.3, rel_tol=1e-10, abs_tol=1e-10)
    assert math.isclose(solution.objective, 0.9, rel_tol=1e-10, abs_tol=1e-10)
    assert solution.relative_gap < 1e-9


def test_memory_constraint_and_box_constraint_are_audited() -> None:
    problem = FixedPartitionProblem(
        member_occupancy=[4.0, 2.0],
        beta=[1.0, 0.5],
        online_weights=[2.0, 5.0],
        compromise_weights=[1.0, 1.0],
        memory_budget=9.0,
        work_factor_floor=0.0,
        epsilon_min=[0.01, 0.02],
        epsilon_cap=[0.7, 0.8],
    )
    solution = solve_fixed_partition(problem)
    assert solution.primal_feasible
    assert solution.memory_used <= problem.memory_budget + 1e-9
    assert solution.stationarity_residual < 1e-6
    lower_bound, _ = lagrangian_dual_value(
        problem, solution.dual_lambda, solution.dual_nu
    )
    assert lower_bound <= solution.objective + 1e-8


def test_infeasible_caps_are_detected_before_numerical_optimization() -> None:
    memory_infeasible = FixedPartitionProblem(
        [1.0], [1.0], [1.0], [1.0], 0.1, epsilon_min=0.1, epsilon_cap=0.5
    )
    with pytest.raises(InfeasibleProblem, match="memory"):
        solve_fixed_partition(memory_infeasible)

    work_infeasible = FixedPartitionProblem(
        [1.0],
        [1.0],
        [1.0],
        [1.0],
        10.0,
        work_factor_floor=0.8,
        epsilon_min=0.1,
        epsilon_cap=0.5,
    )
    with pytest.raises(InfeasibleProblem, match="work-factor"):
        solve_fixed_partition(work_infeasible)

    one_ulp_memory_infeasible = FixedPartitionProblem(
        [1.0],
        [1.0],
        [1.0],
        [1.0],
        math.log(2.0) - 1e-16,
        epsilon_min=0.1,
        epsilon_cap=0.5,
    )
    with pytest.raises(InfeasibleProblem, match="memory"):
        solve_fixed_partition(one_ulp_memory_infeasible)

    one_ulp_work_infeasible = FixedPartitionProblem(
        [1.0],
        [1.0],
        [1.0],
        [1.0],
        10.0,
        work_factor_floor=0.5 + 1e-16,
        epsilon_min=0.1,
        epsilon_cap=0.5,
    )
    with pytest.raises(InfeasibleProblem, match="work-factor"):
        solve_fixed_partition(one_ulp_work_infeasible)


def test_random_certificates_and_brute_force_upper_reference() -> None:
    rng = random.Random(22)
    for _ in range(25):
        problem = random_feasible_problem(rng, rng.randint(1, 2))
        solution = solve_fixed_partition(problem)
        grid = brute_force_grid(problem, points_per_dimension=61)
        assert solution.primal_feasible
        assert solution.relative_gap < 1e-8
        assert solution.objective <= grid.objective + 1e-8 * max(1.0, solution.objective)


def test_failed_slsqp_status_is_accepted_only_with_independent_certificate(
    monkeypatch,
) -> None:
    problem = FixedPartitionProblem(
        member_occupancy=[1.0],
        beta=[1.0],
        online_weights=[1.0],
        compromise_weights=[1.0],
        memory_budget=100.0,
        work_factor_floor=0.2,
        epsilon_min=0.1,
        epsilon_cap=0.9,
    )

    def failed_minimize(**_kwargs):
        return SimpleNamespace(
            x=np.asarray([0.2]),
            success=False,
            message="reported numerical failure",
        )

    monkeypatch.setattr(fixed_partition, "minimize", failed_minimize)
    solution = solve_fixed_partition(problem)

    assert solution.solver_success is True
    assert "independently certified candidate" in solution.solver_message
    assert "reported numerical failure" in solution.solver_message
    assert solution.epsilon == pytest.approx([0.2])
    assert solution.primal_violation == 0.0
    assert solution.conservative_relative_gap < 1e-8


def test_failed_slsqp_status_remains_failed_without_tight_certificate(monkeypatch) -> None:
    problem = FixedPartitionProblem(
        member_occupancy=[1.0],
        beta=[1.0],
        online_weights=[1.0],
        compromise_weights=[1.0],
        memory_budget=100.0,
        work_factor_floor=0.2,
        epsilon_min=0.1,
        epsilon_cap=0.9,
    )

    monkeypatch.setattr(
        fixed_partition,
        "_dual_search",
        lambda *_args: (0.0, 0.0, 0.1, np.asarray([0.9])),
    )

    def failed_minimize(**_kwargs):
        return SimpleNamespace(
            x=np.asarray([0.3]),
            success=False,
            message="reported numerical failure",
        )

    monkeypatch.setattr(fixed_partition, "minimize", failed_minimize)
    solution = solve_fixed_partition(problem)

    assert solution.solver_success is False
    assert solution.solver_message == "reported numerical failure"
    assert solution.primal_violation == 0.0
    assert solution.conservative_relative_gap > 0.1


def test_optional_cvxpy_dependency_is_declared() -> None:
    from pathlib import Path

    requirements = Path(__file__).parents[2] / "reference" / "optimizer" / "requirements.txt"
    assert "cvxpy" in requirements.read_text(encoding="ascii").lower()
