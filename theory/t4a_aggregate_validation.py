from __future__ import annotations

import argparse
import glob
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from reference.optimizer.fixed_partition import lagrangian_dual_value
from theory.optimizer_provenance import (
    FULL_COMMIT_RE,
    SHA256_RE,
    canonical_hash,
    dataset_spec,
    display_path,
    load_validation_config,
    redact_user_paths,
    utc_timestamp,
    validate_validation_config,
)
from theory.t4a_evidence import deserialize_problem, generate_instance
from theory.t4a_sharded_validation import DEFAULT_CONFIG, SCHEMA

REQUIRED_PROVENANCE = {
    "commit",
    "git_dirty",
    "config_hash",
    "dataset_hash",
    "seed",
    "profile",
    "host",
    "timestamp_utc",
}
REQUIRED_CORE = {
    "base_seed",
    "instance_seed",
    "dimensions",
    "generator",
    "problem",
    "problem_hash",
    "primal_epsilon",
    "primal_solver_success",
    "primal_solver_message",
}
CORE_NUMERIC = {
    "primal_objective",
    "memory_used",
    "memory_budget",
    "compromise_mass",
    "work_factor_floor",
    "primal_violation",
    "dual_lambda",
    "dual_nu",
    "dual_lower_bound",
    "conservative_dual_lower_bound",
    "raw_primal_minus_dual",
    "dual_above_primal_residual",
    "primal_dual_gap",
    "relative_gap",
    "conservative_primal_dual_gap",
    "conservative_relative_gap",
    "stationarity_residual",
    "complementarity_residual",
}
CVXPY_REQUIRED = {"cvxpy_status", "cvxpy_solver", "cvxpy_epsilon"}
CVXPY_NUMERIC = {
    "cvxpy_objective",
    "cvxpy_relative_objective_difference",
    "cvxpy_primal_violation",
}
BRUTE_REQUIRED = {
    "brute_force_status",
    "brute_force_epsilon",
    "brute_force_feasible_points",
    "brute_force_total_points",
}
BRUTE_NUMERIC = {
    "brute_force_objective",
    "solver_minus_brute_force_objective",
}


def _expand_inputs(inputs: Iterable[str | Path]) -> list[Path]:
    expanded: list[Path] = []
    for item in inputs:
        value = str(item)
        path = Path(value)
        if path.is_dir():
            expanded.extend(sorted(path.glob("*.jsonl")))
        else:
            matches = [Path(match) for match in glob.glob(value)]
            expanded.extend(matches or [path])
    return sorted({path.resolve() for path in expanded})


def _utc_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed.astimezone(timezone.utc)


def _finite_number(value: Any) -> bool:
    return type(value) in {int, float} and math.isfinite(float(value))


def _close(left: float, right: float, *, tolerance: float = 1e-9) -> bool:
    return math.isclose(float(left), float(right), rel_tol=tolerance, abs_tol=tolerance)


def _numeric_vector(value: Any, dimensions: int) -> tuple[float, ...] | None:
    if not isinstance(value, list) or len(value) != dimensions:
        return None
    if any(not _finite_number(item) for item in value):
        return None
    return tuple(float(item) for item in value)


def _scaled_violation(problem: Any, epsilon: Sequence[float]) -> float:
    _, _, _, lower, upper = problem.arrays()
    return max(
        0.0,
        (problem.memory(epsilon) - problem.memory_budget) / max(1.0, problem.memory_budget),
        (problem.work_factor_floor - problem.compromise_mass(epsilon))
        / max(1.0, problem.work_factor_floor),
        max(lo - value for lo, value in zip(lower, epsilon, strict=True)),
        max(value - cap for value, cap in zip(epsilon, upper, strict=True)),
    )


def _row_evidence_failures(
    row: Mapping[str, Any], config: Mapping[str, Any], index: int
) -> list[str]:
    failures: list[str] = []
    expected_seed, expected_dimensions, expected_problem, expected_record, expected_hash = (
        generate_instance(config, index)
    )
    if row.get("instance_seed") != expected_seed:
        failures.append("instance_seed does not match index derivation")
    if row.get("dimensions") != expected_dimensions:
        failures.append("dimensions do not match generator replay")
    if row.get("generator") != config["generator"]:
        failures.append("row generator does not match frozen config")
    if row.get("problem_hash") != expected_hash:
        failures.append("problem_hash does not match generator replay")
    record = row.get("problem")
    try:
        recorded_problem = deserialize_problem(record, dimensions=expected_dimensions)
    except (TypeError, ValueError) as error:
        failures.append(f"invalid complete problem record ({type(error).__name__})")
        return failures
    if canonical_hash(record) != expected_hash or record != expected_record:
        failures.append("problem parameters do not match generator replay")

    problem = recorded_problem
    if not _close(float(row["memory_budget"]), problem.memory_budget):
        failures.append("memory_budget does not match problem record")
    if not _close(float(row["work_factor_floor"]), problem.work_factor_floor):
        failures.append("work_factor_floor does not match problem record")
    primal = _numeric_vector(row.get("primal_epsilon"), expected_dimensions)
    if primal is None:
        failures.append("primal_epsilon is not a finite dimension-matched vector")
    else:
        objective = problem.objective(primal)
        memory = problem.memory(primal)
        compromise = problem.compromise_mass(primal)
        violation = _scaled_violation(problem, primal)
        for label, observed, expected in (
            ("primal objective", row["primal_objective"], objective),
            ("primal memory", row["memory_used"], memory),
            ("primal compromise", row["compromise_mass"], compromise),
            ("primal violation", row["primal_violation"], violation),
        ):
            if not _close(float(observed), expected):
                failures.append(f"{label} is internally inconsistent")

    dual_lambda = float(row["dual_lambda"])
    dual_nu = float(row["dual_nu"])
    if dual_lambda < 0 or dual_nu < 0:
        failures.append("dual multipliers must be nonnegative")
    else:
        recomputed_dual, _ = lagrangian_dual_value(problem, dual_lambda, dual_nu)
        if not _close(float(row["dual_lower_bound"]), recomputed_dual):
            failures.append("dual lower bound does not match its multipliers")
    primal_objective = float(row["primal_objective"])
    dual_lower = float(row["dual_lower_bound"])
    conservative_lower = float(row["conservative_dual_lower_bound"])
    raw_gap = primal_objective - dual_lower
    expected_formulas = (
        ("raw primal-dual gap", row["raw_primal_minus_dual"], raw_gap),
        ("dual-above-primal residual", row["dual_above_primal_residual"], max(0.0, -raw_gap)),
        ("primal-dual gap", row["primal_dual_gap"], max(0.0, raw_gap)),
        (
            "relative primal-dual gap",
            row["relative_gap"],
            max(0.0, raw_gap) / max(1.0, abs(primal_objective)),
        ),
        (
            "conservative primal-dual gap",
            row["conservative_primal_dual_gap"],
            max(0.0, primal_objective - conservative_lower),
        ),
        (
            "conservative relative gap",
            row["conservative_relative_gap"],
            max(0.0, primal_objective - conservative_lower) / max(1.0, abs(primal_objective)),
        ),
    )
    for label, observed, expected in expected_formulas:
        if not _close(float(observed), expected):
            failures.append(f"{label} is internally inconsistent")
    if conservative_lower > dual_lower + 1e-12 * max(1.0, abs(dual_lower)):
        failures.append("conservative dual lower bound exceeds raw dual value")

    references = config["references"]
    if references["cvxpy"]:
        cvxpy = _numeric_vector(row.get("cvxpy_epsilon"), expected_dimensions)
        if cvxpy is None:
            failures.append("cvxpy_epsilon is not a finite dimension-matched vector")
        else:
            cvxpy_objective = problem.objective(cvxpy)
            cvxpy_violation = _scaled_violation(problem, cvxpy)
            cvxpy_difference = abs(primal_objective - cvxpy_objective) / max(
                1.0, abs(primal_objective)
            )
            for label, observed, expected in (
                ("CVXPY objective", row["cvxpy_objective"], cvxpy_objective),
                ("CVXPY violation", row["cvxpy_primal_violation"], cvxpy_violation),
                (
                    "CVXPY relative difference",
                    row["cvxpy_relative_objective_difference"],
                    cvxpy_difference,
                ),
            ):
                if not _close(float(observed), expected):
                    failures.append(f"{label} is internally inconsistent")

    if references["brute_force"]:
        brute = _numeric_vector(row.get("brute_force_epsilon"), expected_dimensions)
        if brute is None:
            failures.append("brute_force_epsilon is not a finite dimension-matched vector")
        else:
            brute_objective = problem.objective(brute)
            if not _close(float(row["brute_force_objective"]), brute_objective):
                failures.append("brute-force objective is internally inconsistent")
            if _scaled_violation(problem, brute) > 1e-10:
                failures.append("reported brute-force point is infeasible")
            _, _, _, lower, upper = problem.arrays()
            points = int(references["brute_force_points"])
            for value, lo, hi in zip(brute, lower, upper, strict=True):
                grid_coordinate = (value - lo) * (points - 1) / (hi - lo)
                if not _close(grid_coordinate, round(grid_coordinate), tolerance=1e-7):
                    failures.append("reported brute-force point is not on the declared grid")
                    break
            expected_difference = primal_objective - brute_objective
            if not _close(float(row["solver_minus_brute_force_objective"]), expected_difference):
                failures.append("solver-minus-brute objective is internally inconsistent")
        total_points = row.get("brute_force_total_points")
        feasible_points = row.get("brute_force_feasible_points")
        expected_total = int(references["brute_force_points"]) ** expected_dimensions
        if type(total_points) is not int or total_points != expected_total:
            failures.append("brute-force total point count is inconsistent")
        if (
            type(feasible_points) is not int
            or feasible_points <= 0
            or type(total_points) is not int
            or feasible_points > total_points
        ):
            failures.append("brute-force feasible point count is invalid")

    nonnegative_fields = {
        "primal_objective",
        "memory_used",
        "memory_budget",
        "compromise_mass",
        "work_factor_floor",
        "primal_violation",
        "dual_lambda",
        "dual_nu",
        "dual_above_primal_residual",
        "primal_dual_gap",
        "relative_gap",
        "conservative_primal_dual_gap",
        "conservative_relative_gap",
        "stationarity_residual",
        "complementarity_residual",
    }
    if any(float(row[field]) < 0 for field in nonnegative_fields):
        failures.append("a nonnegative numerical field is negative")
    return failures


def aggregate_shards(
    inputs: Iterable[str | Path],
    *,
    validation_config: Mapping[str, Any],
) -> dict[str, Any]:
    config, expected_config_hash = validate_validation_config(validation_config)
    expected_instances = int(config["expected_instances"])
    expected_dataset_hash = canonical_hash(dataset_spec(config))
    expected_seed = int(config["seed"])
    expected_profile = str(config["profile"])
    thresholds: Mapping[str, Any] = config["thresholds"]
    require_clean_commit = bool(config["require_clean_git"])
    references = config["references"]
    required_numeric = set(CORE_NUMERIC)
    required_fields = REQUIRED_PROVENANCE | REQUIRED_CORE | required_numeric
    if references["cvxpy"]:
        required_numeric |= CVXPY_NUMERIC
        required_fields |= CVXPY_REQUIRED | CVXPY_NUMERIC
    if references["brute_force"]:
        required_numeric |= BRUTE_NUMERIC
        required_fields |= BRUTE_REQUIRED | BRUTE_NUMERIC

    paths = _expand_inputs(inputs)
    rows: dict[int, dict[str, Any]] = {}
    duplicate_indices: list[int] = []
    failure_counts: Counter[str] = Counter()
    total_rows = 0
    timestamps: list[datetime] = []

    for path in paths:
        location = display_path(path)
        try:
            handle = path.open("r", encoding="utf-8")
        except OSError as error:
            failure_counts[f"cannot read {location}: {type(error).__name__}"] += 1
            continue
        with handle:
            for line_number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                total_rows += 1
                row_location = f"{display_path(path)}:{line_number}"
                try:
                    row = json.loads(line)
                except Exception as error:
                    failure_counts[f"{row_location}: invalid JSON ({type(error).__name__})"] += 1
                    continue
                if not isinstance(row, dict):
                    failure_counts[f"{row_location}: row is not an object"] += 1
                    continue
                if row.get("schema") != SCHEMA:
                    failure_counts[f"{location}: schema mismatch"] += 1
                    continue
                index = row.get("index")
                if type(index) is not int:
                    failure_counts[f"{row_location}: index is not an integer"] += 1
                    continue
                if index in rows:
                    duplicate_indices.append(index)
                    continue
                rows[index] = row

                missing = sorted(required_fields - set(row))
                if missing:
                    failure_counts[f"missing fields {missing}"] += 1
                    continue
                if row.get("status") != "pass" or row.get("error") is not None:
                    failure_counts["runner status is not pass"] += 1
                if row.get("primal_solver_success") is not True:
                    failure_counts["primal solver did not report success"] += 1
                if not isinstance(row.get("primal_solver_message"), str):
                    failure_counts["primal solver message is missing"] += 1
                if references["cvxpy"]:
                    if row.get("cvxpy_status") not in {"optimal", "optimal_inaccurate"}:
                        failure_counts["CVXPY reference did not complete"] += 1
                    if not isinstance(row.get("cvxpy_solver"), str):
                        failure_counts["CVXPY solver identity is missing"] += 1
                if references["brute_force"] and row.get("brute_force_status") != "completed":
                    failure_counts["brute-force reference did not complete"] += 1
                if any(not _finite_number(row[field]) for field in required_numeric):
                    failure_counts["non-finite numerical evidence"] += 1
                    continue

                commit = row.get("commit")
                if not isinstance(commit, str) or FULL_COMMIT_RE.fullmatch(commit) is None:
                    failure_counts["invalid full commit"] += 1
                if require_clean_commit and row.get("git_dirty") is not False:
                    failure_counts["formal evidence is not clean"] += 1
                elif type(row.get("git_dirty")) is not bool:
                    failure_counts["git_dirty is not Boolean"] += 1
                for field in ("config_hash", "dataset_hash", "problem_hash"):
                    value = row.get(field)
                    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
                        failure_counts[f"invalid {field}"] += 1
                if type(row.get("seed")) is not int or row.get("seed") != row.get("base_seed"):
                    failure_counts["inconsistent seed fields"] += 1
                if row.get("profile") != expected_profile:
                    failure_counts["row profile does not match the declared config"] += 1
                host = row.get("host")
                if not isinstance(host, str) or not host.strip():
                    failure_counts["missing host"] += 1
                elif redact_user_paths(host) != host:
                    failure_counts["host contains a user path"] += 1
                timestamp = _utc_datetime(row.get("timestamp_utc"))
                if timestamp is None:
                    failure_counts["invalid UTC timestamp"] += 1
                else:
                    timestamps.append(timestamp)
                for failure in _row_evidence_failures(row, config, index):
                    failure_counts[failure] += 1

    expected_indices = set(range(expected_instances))
    observed_indices = set(rows)
    missing_indices = sorted(expected_indices - observed_indices)
    unexpected_indices = sorted(observed_indices - expected_indices)
    coverage_failures: list[str] = []
    if total_rows != expected_instances:
        coverage_failures.append(f"total rows {total_rows} != expected {expected_instances}")
    if len(rows) != expected_instances:
        coverage_failures.append(f"unique rows {len(rows)} != expected {expected_instances}")
    if missing_indices:
        coverage_failures.append(f"missing {len(missing_indices)} expected indices")
    if unexpected_indices:
        coverage_failures.append(f"found {len(unexpected_indices)} unexpected indices")
    if duplicate_indices:
        coverage_failures.append(f"found {len(duplicate_indices)} duplicate rows")

    def values(field: str) -> set[Any]:
        found: set[Any] = set()
        for row in rows.values():
            if field not in row:
                continue
            try:
                found.add(row[field])
            except TypeError:
                failure_counts[f"unhashable {field}"] += 1
        return found

    commits = values("commit")
    config_hashes = values("config_hash")
    dataset_hashes = values("dataset_hash")
    seeds = values("seed")
    profiles = values("profile")
    git_dirty_values = values("git_dirty")
    hosts = sorted(redact_user_paths(value) for value in values("host"))
    provenance_failures: list[str] = []
    for field, found in (
        ("commit", commits),
        ("config_hash", config_hashes),
        ("dataset_hash", dataset_hashes),
        ("seed", seeds),
        ("profile", profiles),
    ):
        if len(found) != 1:
            provenance_failures.append(f"rows do not share exactly one {field}")
    if config_hashes != {expected_config_hash}:
        provenance_failures.append("config_hash does not match the declared config")
    if dataset_hashes != {expected_dataset_hash}:
        provenance_failures.append("dataset_hash does not match the generator corpus")
    if seeds != {expected_seed}:
        provenance_failures.append("seed does not match the declared config")
    if profiles != {expected_profile}:
        provenance_failures.append("profile does not match the declared config")

    complete_rows = [
        row
        for row in rows.values()
        if required_fields <= set(row)
        and all(_finite_number(row[field]) for field in required_numeric)
    ]

    def maximum(field: str) -> float | None:
        selected = [float(row[field]) for row in complete_rows]
        return max(selected) if selected else None

    max_relative_gap = maximum("relative_gap")
    max_primal_violation = maximum("primal_violation")
    max_cvxpy = maximum("cvxpy_relative_objective_difference") if references["cvxpy"] else None
    max_cvxpy_violation = maximum("cvxpy_primal_violation") if references["cvxpy"] else None
    max_dual_above = maximum("dual_above_primal_residual")
    max_solver_minus_brute = (
        maximum("solver_minus_brute_force_objective") if references["brute_force"] else None
    )
    numerical_failures: list[str] = []
    comparisons = [
        ("relative gap", max_relative_gap, float(thresholds["maximum_relative_gap"]), False),
        (
            "primal violation",
            max_primal_violation,
            float(thresholds["maximum_primal_violation"]),
            True,
        ),
        (
            "dual above primal",
            max_dual_above,
            float(thresholds["maximum_dual_above_primal"]),
            True,
        ),
    ]
    if references["cvxpy"]:
        comparisons.extend(
            [
                (
                    "CVXPY difference",
                    max_cvxpy,
                    float(thresholds["maximum_cvxpy_difference"]),
                    False,
                ),
                (
                    "CVXPY primal violation",
                    max_cvxpy_violation,
                    float(thresholds["maximum_cvxpy_primal_violation"]),
                    True,
                ),
            ]
        )
    if references["brute_force"]:
        comparisons.append(
            (
                "solver minus brute force",
                max_solver_minus_brute,
                float(thresholds["brute_force_tolerance"]),
                True,
            )
        )
    for label, observed, threshold, strict in comparisons:
        if observed is None or (observed > threshold if strict else observed >= threshold):
            numerical_failures.append(f"{label} {observed!r} violates threshold {threshold}")

    hard_failures = bool(
        failure_counts or coverage_failures or provenance_failures or numerical_failures
    )

    def common(found: set[Any]) -> Any | None:
        return next(iter(found)) if len(found) == 1 else None

    return {
        "schema": SCHEMA,
        "gate_status": "FAIL" if hard_failures else "PASS",
        "profile": expected_profile,
        "evidence_class": ("formal" if expected_profile == "formal" else "diagnostic_only"),
        "formal_gate_status": (
            "FAIL"
            if expected_profile == "formal" and hard_failures
            else "PASS"
            if expected_profile == "formal"
            else "NOT_APPLICABLE"
        ),
        "aggregation_timestamp_utc": utc_timestamp(),
        "input_files": [display_path(path) for path in paths],
        "total_rows": total_rows,
        "unique_instances": len(rows),
        "expected_instances": expected_instances,
        "complete_numerical_rows": len(complete_rows),
        "cvxpy_instances": sum(
            row.get("cvxpy_status") in {"optimal", "optimal_inaccurate"} for row in rows.values()
        ),
        "brute_force_instances": sum(
            row.get("brute_force_status") == "completed" for row in rows.values()
        ),
        "duplicate_indices": sorted(set(duplicate_indices)),
        "missing_index_count": len(missing_indices),
        "unexpected_indices": unexpected_indices,
        "row_failure_counts": dict(sorted(failure_counts.items())),
        "coverage_failures": coverage_failures,
        "provenance_failures": provenance_failures,
        "numerical_failures": numerical_failures,
        "provenance": {
            "commit": common(commits),
            "git_dirty": common(git_dirty_values),
            "config_hash": common(config_hashes),
            "dataset_hash": common(dataset_hashes),
            "seed": common(seeds),
            "profile": common(profiles),
            "hosts": hosts,
            "first_timestamp_utc": min(timestamps).isoformat().replace("+00:00", "Z")
            if timestamps
            else None,
            "last_timestamp_utc": max(timestamps).isoformat().replace("+00:00", "Z")
            if timestamps
            else None,
        },
        "maximum_relative_gap": max_relative_gap,
        "maximum_primal_violation": max_primal_violation,
        "maximum_cvxpy_relative_objective_difference": max_cvxpy,
        "maximum_cvxpy_primal_violation": max_cvxpy_violation,
        "maximum_dual_above_primal_residual": max_dual_above,
        "maximum_solver_minus_brute_force_objective": max_solver_minus_brute,
        "thresholds": {**thresholds, "require_clean_commit": require_clean_commit},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    config, _ = load_validation_config(args.config)
    summary = aggregate_shards(args.inputs, validation_config=config)
    summary["config_path"] = display_path(args.config)
    rendered = json.dumps(summary, indent=2, sort_keys=True, allow_nan=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    if summary["gate_status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
