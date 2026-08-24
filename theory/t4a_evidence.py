from __future__ import annotations

import random
from typing import Any, Mapping

import numpy as np

from reference.optimizer.fixed_partition import FixedPartitionProblem
from theory.optimizer_provenance import FROZEN_GENERATOR_SPEC, canonical_hash
from theory.t4a_solver_validation import random_feasible_problem

PROBLEM_FIELDS = {
    "member_occupancy",
    "beta",
    "online_weights",
    "compromise_weights",
    "memory_budget",
    "work_factor_floor",
    "epsilon_min",
    "epsilon_cap",
}
PROBLEM_VECTOR_FIELDS = (
    "member_occupancy",
    "beta",
    "online_weights",
    "compromise_weights",
    "epsilon_min",
    "epsilon_cap",
)
CANONICAL_SIGNIFICANT_DIGITS = 13


def _canonical_float(value: float) -> float:
    result = float(format(float(value), f".{CANONICAL_SIGNIFICANT_DIGITS}g"))
    if not np.isfinite(result):
        raise ValueError("optimizer problem values must be finite")
    return result


def _splitmix64(value: int) -> int:
    value = (value + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
    return value ^ (value >> 31)


def instance_seed(base_seed: int, index: int) -> int:
    if index < 0:
        raise ValueError("index must be nonnegative")
    return _splitmix64((base_seed & 0xFFFFFFFFFFFFFFFF) ^ _splitmix64(index))


def serialize_problem(problem: FixedPartitionProblem) -> dict[str, Any]:
    _, _, _, lower, upper = problem.arrays()
    return {
        "member_occupancy": [
            _canonical_float(item)
            for item in np.asarray(problem.member_occupancy, dtype=float)
        ],
        "beta": [_canonical_float(item) for item in np.asarray(problem.beta, dtype=float)],
        "online_weights": [
            _canonical_float(item)
            for item in np.asarray(problem.online_weights, dtype=float)
        ],
        "compromise_weights": [
            _canonical_float(item)
            for item in np.asarray(problem.compromise_weights, dtype=float)
        ],
        "memory_budget": _canonical_float(problem.memory_budget),
        "work_factor_floor": _canonical_float(problem.work_factor_floor),
        "epsilon_min": [_canonical_float(item) for item in lower],
        "epsilon_cap": [_canonical_float(item) for item in upper],
    }


def deserialize_problem(value: Any, *, dimensions: int) -> FixedPartitionProblem:
    if not isinstance(value, dict) or set(value) != PROBLEM_FIELDS:
        raise ValueError("problem record does not contain exactly the frozen fields")
    for field in PROBLEM_VECTOR_FIELDS:
        vector = value[field]
        if not isinstance(vector, list) or len(vector) != dimensions:
            raise ValueError(f"problem {field} must have length {dimensions}")
        if any(type(item) not in {int, float} for item in vector):
            raise ValueError(f"problem {field} must contain only numbers")
    for field in ("memory_budget", "work_factor_floor"):
        if type(value[field]) not in {int, float}:
            raise ValueError(f"problem {field} must be numeric")
    problem = FixedPartitionProblem(
        member_occupancy=value["member_occupancy"],
        beta=value["beta"],
        online_weights=value["online_weights"],
        compromise_weights=value["compromise_weights"],
        memory_budget=float(value["memory_budget"]),
        work_factor_floor=float(value["work_factor_floor"]),
        epsilon_min=value["epsilon_min"],
        epsilon_cap=value["epsilon_cap"],
    )
    problem.arrays()
    return problem


def generate_instance(
    config: Mapping[str, Any], index: int
) -> tuple[int, int, FixedPartitionProblem, dict[str, Any], str]:
    if config.get("generator") != FROZEN_GENERATOR_SPEC:
        raise ValueError("cannot replay an unfrozen optimizer generator")
    derived_seed = instance_seed(int(config["seed"]), index)
    rng = random.Random(derived_seed)
    dimensions = rng.randint(1, 2)
    generated = random_feasible_problem(rng, dimensions)
    record = serialize_problem(generated)
    problem = deserialize_problem(record, dimensions=dimensions)
    return derived_seed, dimensions, problem, record, canonical_hash(record)
