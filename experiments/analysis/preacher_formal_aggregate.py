#!/usr/bin/env python3
"""Validate and aggregate E11 formal PreAcher point outputs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from statistics import fmean
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.runners import preacher_formal_bench as formal  # noqa: E402
from experiments.runners.preacher_matched_adapters import (  # noqa: E402
    REPOSITORY_METHOD,
    UPSTREAM_METHOD,
    validate_adapter_result,
)

AGGREGATE_SCHEMA = "traps-e11-preacher-formal-aggregate-v1"


class AggregateError(ValueError):
    """Raised when E11 formal point outputs cannot be aggregated."""


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise AggregateError(f"cannot read {label}: {error}") from error


def _write_json_new(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="ascii", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def _point_id(point: Mapping[str, Any]) -> str:
    material = dict(point)
    material.pop("point_id", None)
    return formal._identity(material)


def _result_mismatches(result: Mapping[str, Any]) -> int:
    events = result.get("events")
    if not isinstance(events, list):
        raise AggregateError("adapter result events are missing")
    return sum(event.get("expected_outcome_observed") is False for event in events)


def _mean(values: Sequence[float]) -> float | None:
    return None if not values else fmean(values)


def _validate_point(
    *,
    config: Mapping[str, Any],
    manifest_id: str,
    point_dir: Path,
    workload_name: str,
    seed: int,
    expected_commit: str | None,
) -> dict[str, Any]:
    expected_trace, runtime_manifest = formal.build_trace(config, manifest_id, workload_name, seed)
    trace = _load_json(point_dir / "trace.json", f"{workload_name}/{seed} trace")
    point = _load_json(point_dir / "point.json", f"{workload_name}/{seed} point")
    upstream = _load_json(
        point_dir / f"{UPSTREAM_METHOD}.json",
        f"{workload_name}/{seed} upstream result",
    )
    repository = _load_json(
        point_dir / f"{REPOSITORY_METHOD}.json",
        f"{workload_name}/{seed} repository result",
    )
    if trace != expected_trace:
        raise AggregateError(f"{workload_name}/{seed} trace does not rebuild")
    if point.get("schema") != formal.POINT_SCHEMA:
        raise AggregateError(f"{workload_name}/{seed} point schema changed")
    if point.get("status") != "PASS_RAW_FORMAL_POINT_NOT_AGGREGATED":
        raise AggregateError(f"{workload_name}/{seed} point is not a raw formal pass")
    if point.get("point_id") != _point_id(point):
        raise AggregateError(f"{workload_name}/{seed} point ID does not recompute")
    if point.get("manifest_id") != manifest_id:
        raise AggregateError(f"{workload_name}/{seed} manifest binding changed")
    if point.get("registration_id") != config["derived_baseline_binding"]["registration_id"]:
        raise AggregateError(f"{workload_name}/{seed} registration binding changed")
    if point.get("workload_name") != workload_name or point.get("seed") != seed:
        raise AggregateError(f"{workload_name}/{seed} point coordinate changed")
    if point.get("trace_id") != trace["trace_id"]:
        raise AggregateError(f"{workload_name}/{seed} trace binding changed")
    if point.get("upstream_result_id") != upstream.get("result_id"):
        raise AggregateError(f"{workload_name}/{seed} upstream result binding changed")
    if point.get("repository_result_id") != repository.get("result_id"):
        raise AggregateError(f"{workload_name}/{seed} repository result binding changed")
    source_state = point.get("analysis_source_state")
    if not isinstance(source_state, Mapping) or source_state.get("clean") is not True:
        raise AggregateError(f"{workload_name}/{seed} source state is not clean")
    if expected_commit is not None and source_state.get("commit") != expected_commit:
        raise AggregateError(f"{workload_name}/{seed} source commit changed")
    contract_id = formal._identity(runtime_manifest["matched_contract"])
    validate_adapter_result(
        upstream,
        expected_method=UPSTREAM_METHOD,
        manifest_id=manifest_id,
        contract_id=contract_id,
        trace=trace,
        expected_baseline_binding=config["derived_baseline_binding"],
        expected_execution_status=formal.FORMAL_EXECUTION_STATUS,
    )
    validate_adapter_result(
        repository,
        expected_method=REPOSITORY_METHOD,
        manifest_id=manifest_id,
        contract_id=contract_id,
        trace=trace,
        expected_baseline_binding=config["derived_baseline_binding"],
        expected_execution_status=formal.FORMAL_EXECUTION_STATUS,
    )
    return {
        "workload_name": workload_name,
        "seed": seed,
        "point_id": point["point_id"],
        "trace_id": trace["trace_id"],
        "commit": source_state["commit"],
        "upstream_result_id": upstream["result_id"],
        "repository_result_id": repository["result_id"],
        "upstream_mismatches": _result_mismatches(upstream),
        "repository_mismatches": _result_mismatches(repository),
        "upstream_backend_valid_checks": upstream["summary"]["backend_valid_checks"],
        "repository_backend_valid_checks": repository["summary"]["backend_valid_checks"],
        "upstream_backend_invalid_checks": upstream["summary"]["backend_invalid_checks"],
        "repository_backend_invalid_checks": repository["summary"]["backend_invalid_checks"],
        "upstream_legitimate_p99_ms": upstream["summary"]["legitimate_p99_ms"],
        "repository_legitimate_p99_ms": repository["summary"]["legitimate_p99_ms"],
        "minimum_invalid_tuple_multiplicity": trace["minimum_invalid_tuple_multiplicity"],
        "conditioned_tuple_count": trace["conditioned_tuple_count"],
    }


def rebuild_aggregate(
    *,
    config_path: Path,
    points_dir: Path,
    expected_commit: str | None = None,
    allow_incomplete: bool = False,
) -> dict[str, Any]:
    config, manifest_id = formal.load_config(config_path)
    if config["status"] != formal.REGISTERED_STATUS:
        raise AggregateError("E11 aggregate requires a registered formal config")
    workloads = [workload["name"] for workload in config["workloads"]]
    seeds = list(config["seeds"])
    points: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for workload_name in workloads:
        for seed in seeds:
            point_dir = points_dir / f"{workload_name}-{seed}"
            if not (point_dir / "point.json").exists():
                missing.append({"workload_name": workload_name, "seed": seed})
                continue
            points.append(
                _validate_point(
                    config=config,
                    manifest_id=manifest_id,
                    point_dir=point_dir,
                    workload_name=workload_name,
                    seed=int(seed),
                    expected_commit=expected_commit,
                )
            )
    if missing and not allow_incomplete:
        raise AggregateError(f"E11 aggregate is missing {len(missing)} formal points")
    expected_point_count = len(workloads) * len(seeds)
    commits = sorted({point["commit"] for point in points})
    body: dict[str, Any] = {
        "schema": AGGREGATE_SCHEMA,
        "status": "INCOMPLETE_FORMAL_POINTS" if missing else "PASS_FORMAL_AGGREGATE",
        "manifest_id": manifest_id,
        "registration_id": config["derived_baseline_binding"]["registration_id"],
        "points_dir": str(points_dir),
        "expected_point_count": expected_point_count,
        "observed_point_count": len(points),
        "missing_point_count": len(missing),
        "missing_points": missing,
        "workloads": workloads,
        "seeds": seeds,
        "commits": commits,
        "total_upstream_mismatches": sum(point["upstream_mismatches"] for point in points),
        "total_repository_mismatches": sum(point["repository_mismatches"] for point in points),
        "total_upstream_backend_valid_checks": sum(
            point["upstream_backend_valid_checks"] for point in points
        ),
        "total_repository_backend_valid_checks": sum(
            point["repository_backend_valid_checks"] for point in points
        ),
        "total_upstream_backend_invalid_checks": sum(
            point["upstream_backend_invalid_checks"] for point in points
        ),
        "total_repository_backend_invalid_checks": sum(
            point["repository_backend_invalid_checks"] for point in points
        ),
        "mean_upstream_legitimate_p99_ms": _mean(
            [
                float(point["upstream_legitimate_p99_ms"])
                for point in points
                if point["upstream_legitimate_p99_ms"] is not None
            ]
        ),
        "mean_repository_legitimate_p99_ms": _mean(
            [
                float(point["repository_legitimate_p99_ms"])
                for point in points
                if point["repository_legitimate_p99_ms"] is not None
            ]
        ),
        "points": points,
    }
    return {**body, "aggregate_id": formal._identity(body)}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--points-dir", type=Path, required=True)
    parser.add_argument("--expected-commit")
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        aggregate = rebuild_aggregate(
            config_path=args.config,
            points_dir=args.points_dir,
            expected_commit=args.expected_commit,
            allow_incomplete=args.allow_incomplete,
        )
        if args.output is not None:
            _write_json_new(args.output, aggregate)
    except Exception as error:
        print(json.dumps({"status": "INVALID", "error": str(error)}, sort_keys=True))
        return 3
    print(json.dumps(aggregate, sort_keys=True))
    return 0 if aggregate["status"] == "PASS_FORMAL_AGGREGATE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
