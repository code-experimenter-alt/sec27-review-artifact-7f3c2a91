from __future__ import annotations

import itertools
import math
import warnings
from dataclasses import dataclass
from typing import Sequence

import numpy as np
from scipy.optimize import minimize, minimize_scalar


class InfeasibleProblem(ValueError):
    pass


def _array(value: float | Sequence[float], size: int, name: str) -> np.ndarray:
    result = np.asarray(value, dtype=float)
    if result.ndim == 0:
        result = np.full(size, float(result))
    if result.shape != (size,):
        raise ValueError(f"{name} must be scalar or have shape ({size},)")
    return result


@dataclass(frozen=True)
class FixedPartitionProblem:
    member_occupancy: Sequence[float]
    beta: Sequence[float]
    online_weights: Sequence[float]
    compromise_weights: Sequence[float]
    memory_budget: float
    work_factor_floor: float = 0.0
    epsilon_min: float | Sequence[float] = 1e-9
    epsilon_cap: float | Sequence[float] = 1.0

    def arrays(self) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        n = np.asarray(self.member_occupancy, dtype=float)
        beta = np.asarray(self.beta, dtype=float)
        weights = np.asarray(self.online_weights, dtype=float)
        compromise = np.asarray(self.compromise_weights, dtype=float)
        if not (n.ndim == beta.ndim == weights.ndim == compromise.ndim == 1):
            raise ValueError("all region parameters must be one-dimensional")
        if not (len(n) and len(n) == len(beta) == len(weights) == len(compromise)):
            raise ValueError("all region parameter arrays must have the same nonzero length")
        lower = _array(self.epsilon_min, len(n), "epsilon_min")
        upper = _array(self.epsilon_cap, len(n), "epsilon_cap")
        values = np.concatenate((n, beta, weights, compromise, lower, upper))
        if not np.all(np.isfinite(values)):
            raise ValueError("all problem data must be finite")
        if np.any(n <= 0) or np.any(beta <= 0):
            raise ValueError("member occupancy and beta must be positive")
        if np.any(weights < 0) or np.any(compromise < 0):
            raise ValueError("weights must be nonnegative")
        if np.any(lower <= 0) or np.any(upper > 1) or np.any(lower > upper):
            raise ValueError("epsilon bounds must satisfy 0 < min <= cap <= 1")
        if not math.isfinite(self.memory_budget) or self.memory_budget < 0:
            raise ValueError("memory_budget must be finite and nonnegative")
        if not math.isfinite(self.work_factor_floor) or self.work_factor_floor < 0:
            raise ValueError("work_factor_floor must be finite and nonnegative")
        return n / beta, weights, compromise, lower, upper

    def memory(self, epsilon: Sequence[float]) -> float:
        a, _, _, lower, _ = self.arrays()
        values = np.asarray(epsilon, dtype=float)
        if values.shape != lower.shape or np.any(values <= 0):
            return math.inf
        return float(np.dot(a, -np.log(values)))

    def objective(self, epsilon: Sequence[float]) -> float:
        _, weights, _, _, _ = self.arrays()
        return float(np.dot(weights, np.asarray(epsilon, dtype=float)))

    def compromise_mass(self, epsilon: Sequence[float]) -> float:
        _, _, compromise, _, _ = self.arrays()
        return float(np.dot(compromise, np.asarray(epsilon, dtype=float)))


@dataclass(frozen=True)
class FixedPartitionSolution:
    epsilon: tuple[float, ...]
    objective: float
    memory_used: float
    compromise_mass: float
    primal_violation: float
    dual_lambda: float
    dual_nu: float
    dual_lower_bound: float
    conservative_dual_lower_bound: float
    raw_primal_minus_dual: float
    dual_above_primal_residual: float
    primal_dual_gap: float
    relative_gap: float
    conservative_primal_dual_gap: float
    conservative_relative_gap: float
    stationarity_residual: float
    complementarity_residual: float
    solver_success: bool
    solver_message: str

    @property
    def primal_feasible(self) -> bool:
        return self.primal_violation <= 1e-8


@dataclass(frozen=True)
class GridReference:
    epsilon: tuple[float, ...]
    objective: float
    feasible_points: int
    total_points: int


@dataclass(frozen=True)
class CvxpyReference:
    epsilon: tuple[float, ...]
    objective: float
    status: str
    solver: str


def _memory(a: np.ndarray, epsilon: np.ndarray) -> float:
    return float(np.dot(a, -np.log(epsilon)))


def _lagrangian_minimizer(
    a: np.ndarray,
    weights: np.ndarray,
    compromise: np.ndarray,
    lower: np.ndarray,
    upper: np.ndarray,
    dual_lambda: float,
    dual_nu: float,
) -> np.ndarray:
    q = weights - dual_nu * compromise
    if dual_lambda == 0.0:
        # At a zero coefficient either endpoint minimizes the Lagrangian. The upper
        # endpoint is the useful representative because it consumes less memory.
        return np.where(q > 0.0, lower, upper)
    unconstrained = np.full_like(q, np.inf)
    positive = q > 0.0
    unconstrained[positive] = dual_lambda * a[positive] / q[positive]
    return np.clip(unconstrained, lower, upper)


def lagrangian_dual_value(
    problem: FixedPartitionProblem, dual_lambda: float, dual_nu: float
) -> tuple[float, tuple[float, ...]]:
    """Evaluate a weak-duality lower bound and its box minimizer."""

    if dual_lambda < 0 or dual_nu < 0 or not math.isfinite(dual_lambda + dual_nu):
        raise ValueError("dual variables must be finite and nonnegative")
    a, weights, compromise, lower, upper = problem.arrays()
    epsilon = _lagrangian_minimizer(
        a, weights, compromise, lower, upper, dual_lambda, dual_nu
    )
    # This algebraically equivalent form avoids cancellation between two terms of
    # order nu when the affine work-factor constraint is active.
    value = (
        float(np.dot(weights, epsilon))
        + dual_lambda * (_memory(a, epsilon) - problem.memory_budget)
        + dual_nu
        * (problem.work_factor_floor - float(np.dot(compromise, epsilon)))
    )
    return value, tuple(float(item) for item in epsilon)


def _best_lambda(
    problem: FixedPartitionProblem,
    dual_nu: float,
    *,
    iterations: int = 100,
) -> tuple[float, np.ndarray, float]:
    a, weights, compromise, lower, upper = problem.arrays()
    epsilon_zero = _lagrangian_minimizer(a, weights, compromise, lower, upper, 0.0, dual_nu)
    if _memory(a, epsilon_zero) <= problem.memory_budget:
        value, _ = lagrangian_dual_value(problem, 0.0, dual_nu)
        return 0.0, epsilon_zero, value

    lo = 0.0
    hi = 1.0
    while _memory(
        a,
        _lagrangian_minimizer(a, weights, compromise, lower, upper, hi, dual_nu),
    ) > problem.memory_budget:
        hi *= 2.0
        if not math.isfinite(hi):
            raise ArithmeticError("failed to bracket the memory multiplier")
    for _ in range(iterations):
        midpoint = 0.5 * (lo + hi)
        epsilon = _lagrangian_minimizer(
            a, weights, compromise, lower, upper, midpoint, dual_nu
        )
        if _memory(a, epsilon) > problem.memory_budget:
            lo = midpoint
        else:
            hi = midpoint
    dual_lambda = 0.5 * (lo + hi)
    epsilon = _lagrangian_minimizer(
        a, weights, compromise, lower, upper, dual_lambda, dual_nu
    )
    value, _ = lagrangian_dual_value(problem, dual_lambda, dual_nu)
    return dual_lambda, epsilon, value


def _dual_search(
    problem: FixedPartitionProblem, tolerance: float
) -> tuple[float, float, float, np.ndarray]:
    _, _, compromise, _, _ = problem.arrays()
    lambda_zero, epsilon_zero, value_zero = _best_lambda(problem, 0.0)
    if float(np.dot(compromise, epsilon_zero)) >= problem.work_factor_floor - tolerance:
        return lambda_zero, 0.0, value_zero, epsilon_zero

    lo = 0.0
    hi = 1.0
    _, high_epsilon, _ = _best_lambda(problem, hi)
    while float(np.dot(compromise, high_epsilon)) < problem.work_factor_floor:
        hi *= 2.0
        if hi > 1e300:
            raise ArithmeticError("failed to bracket the work-factor multiplier")
        _, high_epsilon, _ = _best_lambda(problem, hi)

    # Subgradient bisection localizes a maximizer even at a nondifferentiable kink.
    candidates = {0.0, hi}
    for _ in range(180):
        midpoint = 0.5 * (lo + hi)
        _, epsilon, _ = _best_lambda(problem, midpoint)
        candidates.add(midpoint)
        if float(np.dot(compromise, epsilon)) < problem.work_factor_floor:
            lo = midpoint
        else:
            hi = midpoint
        if hi - lo <= max(2 * np.spacing(max(1.0, hi)), tolerance * 1e-4 * max(1.0, hi)):
            break
    candidates.update((lo, hi, 0.5 * (lo + hi)))

    # A bounded scalar maximization provides an independent candidate and improves
    # accuracy when the work residual is very flat.
    scalar = minimize_scalar(
        lambda nu: -_best_lambda(problem, float(nu))[2],
        bounds=(0.0, hi),
        method="bounded",
        options={"xatol": max(1e-14, tolerance * max(1.0, hi)), "maxiter": 500},
    )
    if scalar.success:
        candidates.add(float(scalar.x))

    best: tuple[float, float, float, np.ndarray] | None = None
    for dual_nu in candidates:
        dual_lambda, epsilon, value = _best_lambda(problem, dual_nu)
        if best is None or value > best[2]:
            best = (dual_lambda, dual_nu, value, epsilon)
    assert best is not None
    return best


def _primal_violation(
    problem: FixedPartitionProblem, epsilon: np.ndarray
) -> float:
    _, _, _, lower, upper = problem.arrays()
    scale_memory = max(1.0, problem.memory_budget)
    scale_work = max(1.0, problem.work_factor_floor)
    return max(
        0.0,
        (problem.memory(epsilon) - problem.memory_budget) / scale_memory,
        (problem.work_factor_floor - problem.compromise_mass(epsilon)) / scale_work,
        float(np.max(lower - epsilon)),
        float(np.max(epsilon - upper)),
    )


def _make_feasible(problem: FixedPartitionProblem, epsilon: np.ndarray) -> np.ndarray:
    """Move a near-optimal point monotonically toward the feasible upper box."""

    a, weights, compromise, lower, upper = problem.arrays()
    result = np.clip(np.asarray(epsilon, dtype=float), lower, upper)
    if _memory(a, result) > problem.memory_budget:
        lo = 0.0
        hi = 1.0
        base = result.copy()
        for _ in range(100):
            midpoint = 0.5 * (lo + hi)
            candidate = base + midpoint * (upper - base)
            if _memory(a, candidate) > problem.memory_budget:
                lo = midpoint
            else:
                hi = midpoint
        result = base + hi * (upper - base)

    deficit = problem.work_factor_floor - float(np.dot(compromise, result))
    if deficit > 0:
        order = sorted(
            (index for index, weight in enumerate(compromise) if weight > 0),
            key=lambda index: (weights[index] / compromise[index], index),
        )
        for index in order:
            increment = min(upper[index] - result[index], deficit / compromise[index])
            result[index] += increment
            deficit -= compromise[index] * increment
            if deficit <= 8 * np.finfo(float).eps * max(1.0, problem.work_factor_floor):
                break
        # One-ulp nudges address downward rounding at an active affine constraint.
        if float(np.dot(compromise, result)) < problem.work_factor_floor:
            for index in order:
                if result[index] < upper[index]:
                    result[index] = np.nextafter(result[index], upper[index])
                    if float(np.dot(compromise, result)) >= problem.work_factor_floor:
                        break
    return result


def _solve_primal(
    problem: FixedPartitionProblem,
    dual_epsilon: np.ndarray,
    tolerance: float,
):
    a, weights, compromise, lower, upper = problem.arrays()
    memory_scale = max(1.0, problem.memory_budget)
    work_scale = max(1.0, problem.work_factor_floor)

    constraints = [
        {
            "type": "ineq",
            "fun": lambda epsilon: (problem.memory_budget - _memory(a, epsilon)) / memory_scale,
            "jac": lambda epsilon: (a / epsilon) / memory_scale,
        },
        {
            "type": "ineq",
            "fun": lambda epsilon: (float(np.dot(compromise, epsilon)) - problem.work_factor_floor)
            / work_scale,
            "jac": lambda epsilon: compromise / work_scale,
        },
    ]
    starts = [_make_feasible(problem, dual_epsilon), np.array(upper, copy=True)]
    candidates: list[tuple[np.ndarray, bool, str]] = []
    for start in starts:
        candidates.append((start, True, "feasible dual recovery"))
        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=(
                    "Values in x were outside bounds during a minimize step, "
                    "clipping to bounds"
                ),
                category=RuntimeWarning,
            )
            result = minimize(
                fun=lambda epsilon: float(np.dot(weights, epsilon)),
                x0=np.clip(start, lower, upper),
                jac=lambda epsilon: weights,
                bounds=list(zip(lower, upper, strict=True)),
                constraints=constraints,
                method="SLSQP",
                options={
                    "ftol": min(1e-12, tolerance),
                    "maxiter": 2000,
                    "disp": False,
                },
            )
        repaired = _make_feasible(problem, result.x)
        candidates.append((repaired, bool(result.success), str(result.message)))

    feasible_candidates = [
        candidate for candidate in candidates if _primal_violation(problem, candidate[0]) <= 1e-12
    ]
    if feasible_candidates:
        return min(feasible_candidates, key=lambda candidate: problem.objective(candidate[0]))
    return min(
        candidates,
        key=lambda candidate: (
            _primal_violation(problem, candidate[0]),
            problem.objective(candidate[0]),
        ),
    )


def solve_fixed_partition(
    problem: FixedPartitionProblem, *, tolerance: float = 1e-11
) -> FixedPartitionSolution:
    if not 0 < tolerance < 1:
        raise ValueError("tolerance must lie in (0, 1)")
    a, weights, compromise, lower, upper = problem.arrays()
    minimum_memory = _memory(a, upper)
    maximum_work = float(np.dot(compromise, upper))
    if minimum_memory > problem.memory_budget:
        raise InfeasibleProblem("epsilon caps require more memory than the budget")
    if maximum_work < problem.work_factor_floor:
        raise InfeasibleProblem("epsilon caps cannot meet the work-factor floor")

    dual_lambda, dual_nu, dual_value, dual_epsilon = _dual_search(problem, tolerance)
    epsilon, primal_success, primal_message = _solve_primal(problem, dual_epsilon, tolerance)
    epsilon = np.clip(np.asarray(epsilon, dtype=float), lower, upper)
    objective = float(np.dot(weights, epsilon))
    memory_used = _memory(a, epsilon)
    compromise_mass = float(np.dot(compromise, epsilon))
    violation = _primal_violation(problem, epsilon)

    # Re-evaluate the lower bound from the returned multipliers and subtract a
    # conservative floating-point evaluation allowance. Weak duality itself does
    # not depend on the primal solver's status.
    dual_value, lagrangian_epsilon_tuple = lagrangian_dual_value(
        problem, dual_lambda, dual_nu
    )
    lagrangian_epsilon = np.asarray(lagrangian_epsilon_tuple)
    magnitude = (
        abs(dual_value)
        + abs(dual_lambda * problem.memory_budget)
        + abs(dual_nu * problem.work_factor_floor)
        + float(np.dot(np.abs(weights - dual_nu * compromise), lagrangian_epsilon))
        + abs(dual_lambda * _memory(a, lagrangian_epsilon))
        + 1.0
    )
    roundoff_allowance = 128 * np.finfo(float).eps * magnitude
    conservative_lower = dual_value - roundoff_allowance
    raw_primal_minus_dual = objective - dual_value
    dual_above_primal = max(0.0, -raw_primal_minus_dual)
    gap = max(0.0, raw_primal_minus_dual)
    relative_gap = gap / max(1.0, abs(objective))
    conservative_gap = max(0.0, objective - conservative_lower)
    conservative_relative_gap = conservative_gap / max(1.0, abs(objective))
    certificate_tolerance = max(32.0 * tolerance, 4096.0 * np.finfo(float).eps)
    certificate_success = (
        violation <= certificate_tolerance
        and conservative_relative_gap <= certificate_tolerance
        and dual_above_primal <= certificate_tolerance
    )
    if not primal_success and certificate_success:
        primal_success = True
        primal_message = (
            "independently certified candidate after local optimizer status: "
            f"{primal_message}"
        )

    q = weights - dual_nu * compromise
    gradient = q - dual_lambda * a / epsilon
    stationarity_components = np.zeros_like(gradient)
    bound_tolerance = 1e-8
    for index, value in enumerate(epsilon):
        if value <= lower[index] + bound_tolerance:
            stationarity_components[index] = max(0.0, -gradient[index])
        elif value >= upper[index] - bound_tolerance:
            stationarity_components[index] = max(0.0, gradient[index])
        else:
            stationarity_components[index] = abs(gradient[index])
    stationarity = float(np.max(stationarity_components))
    complementarity = max(
        abs(dual_lambda * (memory_used - problem.memory_budget)),
        abs(dual_nu * (problem.work_factor_floor - compromise_mass)),
    )

    return FixedPartitionSolution(
        epsilon=tuple(float(item) for item in epsilon),
        objective=objective,
        memory_used=memory_used,
        compromise_mass=compromise_mass,
        primal_violation=violation,
        dual_lambda=dual_lambda,
        dual_nu=dual_nu,
        dual_lower_bound=dual_value,
        conservative_dual_lower_bound=conservative_lower,
        raw_primal_minus_dual=raw_primal_minus_dual,
        dual_above_primal_residual=dual_above_primal,
        primal_dual_gap=gap,
        relative_gap=relative_gap,
        conservative_primal_dual_gap=conservative_gap,
        conservative_relative_gap=conservative_relative_gap,
        stationarity_residual=stationarity,
        complementarity_residual=complementarity,
        solver_success=primal_success,
        solver_message=primal_message,
    )


def brute_force_grid(
    problem: FixedPartitionProblem, *, points_per_dimension: int = 101
) -> GridReference:
    if points_per_dimension < 2:
        raise ValueError("points_per_dimension must be at least two")
    _, _, _, lower, upper = problem.arrays()
    total_points = points_per_dimension ** len(lower)
    if total_points > 5_000_000:
        raise ValueError("requested brute-force grid exceeds 5,000,000 points")
    axes = [
        np.linspace(lo, hi, points_per_dimension)
        for lo, hi in zip(lower, upper, strict=True)
    ]
    best_epsilon: tuple[float, ...] | None = None
    best_objective = math.inf
    feasible = 0
    for point in itertools.product(*axes):
        epsilon = np.asarray(point)
        if (
            problem.memory(epsilon) <= problem.memory_budget + 1e-12
            and problem.compromise_mass(epsilon) + 1e-12 >= problem.work_factor_floor
        ):
            feasible += 1
            objective = problem.objective(epsilon)
            if objective < best_objective:
                best_objective = objective
                best_epsilon = tuple(float(item) for item in epsilon)
    if best_epsilon is None:
        raise InfeasibleProblem("the finite grid contains no feasible point")
    return GridReference(best_epsilon, best_objective, feasible, total_points)


def solve_with_cvxpy(
    problem: FixedPartitionProblem, *, solver: str | None = None
) -> CvxpyReference:
    try:
        import cvxpy as cp
    except ImportError as error:
        raise RuntimeError(
            "CVXPY is optional; install reference/optimizer/requirements.txt in the project venv"
        ) from error

    a, weights, compromise, lower, upper = problem.arrays()
    epsilon = cp.Variable(len(a))
    constraints = [
        cp.sum(cp.multiply(a, -cp.log(epsilon))) <= problem.memory_budget,
        compromise @ epsilon >= problem.work_factor_floor,
        epsilon >= lower,
        epsilon <= upper,
    ]
    cvx_problem = cp.Problem(cp.Minimize(weights @ epsilon), constraints)
    if solver is None:
        installed = set(cp.installed_solvers())
        solver = next(
            (candidate for candidate in ("CLARABEL", "ECOS", "SCS") if candidate in installed),
            None,
        )
    solve_kwargs = {"solver": solver} if solver else {}
    if solver == "CLARABEL":
        solve_kwargs.update(
            tol_gap_abs=1e-10,
            tol_gap_rel=1e-10,
            tol_feas=1e-10,
            max_iter=1_000,
        )
    cvx_problem.solve(**solve_kwargs)
    if epsilon.value is None or cvx_problem.status not in (cp.OPTIMAL, cp.OPTIMAL_INACCURATE):
        raise RuntimeError(f"CVXPY failed with status {cvx_problem.status}")
    values = np.asarray(epsilon.value, dtype=float)
    return CvxpyReference(
        epsilon=tuple(float(item) for item in values),
        objective=float(cvx_problem.value),
        status=str(cvx_problem.status),
        solver=str(solver or cvx_problem.solver_stats.solver_name),
    )
