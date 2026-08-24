#!/usr/bin/env python3
"""Strict post-run validation and publication for Phase 1 timing frontier v2."""

from __future__ import annotations

import argparse
import ctypes
import errno
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.analysis import (  # noqa: E402
    filter_timing_frontier_v2_aggregate as aggregate,
)

RECEIPT_SCHEMA = "traps-phase1-timing-frontier-v2-postrun-receipt-v2"
RECEIPT_ID_SCHEMA = "phase1-timing-frontier-v2-postrun-receipt-id-v2"
PASS_DECISION = "PASS_P0_B_COMPLETE_TIMING_FRONTIER_V2"
NONPROMOTABLE_DECISION = "VALID_EVIDENCE_DO_NOT_PROMOTE_P0_B"
AGGREGATE_FILENAME = "filter_timing_frontier_v2_1.aggregate.json"
RECEIPT_FILENAME = "gate-receipt.json"
AT_FDCWD = -100
RENAME_NOREPLACE = 1


class PostrunValidationError(ValueError):
    """Raised when v2 evidence is invalid or cannot be atomically published."""


def _same_exact(expected: Any, actual: Any, path: str = "$") -> None:
    try:
        aggregate._same_exact(expected, actual, path)
    except aggregate.AggregateValidationError as error:
        raise PostrunValidationError(str(error)) from error


def _receipt_material(receipt: Mapping[str, Any]) -> dict[str, Any]:
    material = dict(receipt)
    material.pop("receipt_id", None)
    return material


def _validate_aggregate_state(value: Mapping[str, Any]) -> None:
    if type(value) is not dict:
        raise PostrunValidationError("aggregate must be a JSON object")
    if value.get("schema") != aggregate.AGGREGATE_SCHEMA:
        raise PostrunValidationError("aggregate schema is not the frozen v2 schema")
    if value.get("analysis_source_commit") != value.get("source_commit"):
        raise PostrunValidationError(
            "aggregate analysis source commit differs from its timing source commit"
        )
    if value.get("analysis_source_clean") is not True:
        raise PostrunValidationError("aggregate analysis source is not clean")
    if value.get("analysis_source_status_scope") != aggregate.source_frontier.SOURCE_STATUS_SCOPE:
        raise PostrunValidationError("aggregate analysis source status scope changed")
    aggregate_id = value.get("aggregate_id")
    if not aggregate._is_hex64(aggregate_id):
        raise PostrunValidationError("aggregate_id is malformed")
    if aggregate._aggregate_id(value) != aggregate_id:
        raise PostrunValidationError("aggregate_id does not recompute exactly")
    gates = value.get("gates")
    counts = value.get("counts")
    points = value.get("points")
    frontiers = value.get("frontiers")
    if not all(type(item) is dict for item in (gates, counts, frontiers)):
        raise PostrunValidationError("aggregate gate/count/frontier ledgers are missing")
    if type(points) is not list or len(points) != aggregate.runner.PHASE1_SPEC_COUNT:
        raise PostrunValidationError("aggregate does not contain exactly 794 points")
    expected_gate_keys = {
        "complete_794_point_coverage",
        "single_hardware_stratum",
        "all_primary_precision_relative_half_width_lte_0_05",
        "all_primary_p99_at_least_10x_clock_call_p99",
        "p0_eligible",
    }
    if set(gates) != expected_gate_keys or any(
        type(gates[key]) is not bool for key in expected_gate_keys
    ):
        raise PostrunValidationError("aggregate gates have the wrong schema")
    if gates["complete_794_point_coverage"] is not True:
        raise PostrunValidationError("a valid aggregate must have complete 794-point coverage")
    p0_eligible = all(
        gates[key]
        for key in (
            "complete_794_point_coverage",
            "single_hardware_stratum",
            "all_primary_precision_relative_half_width_lte_0_05",
            "all_primary_p99_at_least_10x_clock_call_p99",
        )
    )
    if type(value.get("p0_eligible")) is not bool or value["p0_eligible"] is not p0_eligible:
        raise PostrunValidationError("aggregate P0 eligibility contradicts its gates")
    if gates["p0_eligible"] is not p0_eligible:
        raise PostrunValidationError("aggregate gate ledger contradicts P0 eligibility")
    expected_status = aggregate.VALID_COMPLETE if p0_eligible else aggregate.VALID_BUT_NONPROMOTABLE
    if value.get("validation_status") != expected_status:
        raise PostrunValidationError("aggregate validation status contradicts its gates")
    warm_seed_count = counts.get("warm_timing_seeds_per_spec")
    if type(warm_seed_count) is not int or warm_seed_count not in {20, 40}:
        raise PostrunValidationError("aggregate warm seed count must be exactly 20 or 40")
    expected_counts = {
        "specifications": aggregate.runner.PHASE1_SPEC_COUNT,
        "warm_timing_seeds_per_spec": warm_seed_count,
        "warm_rows": aggregate.runner.PHASE1_SPEC_COUNT * warm_seed_count,
        "cold_rows": aggregate.runner.PHASE1_SPEC_COUNT,
        "cold_seeds_per_spec": 1,
        "hardware_strata": len(value.get("hardware_strata", [])),
    }
    _same_exact(expected_counts, counts, "aggregate.counts")
    expected_reasons: list[str] = []
    if not gates["all_primary_precision_relative_half_width_lte_0_05"]:
        expected_reasons.append(
            f"PRIMARY_PRECISION_RELATIVE_HALF_WIDTH_EXCEEDS_0_05_AT_N{warm_seed_count}"
        )
    if not gates["all_primary_p99_at_least_10x_clock_call_p99"]:
        expected_reasons.append("PRIMARY_P99_BELOW_10X_CLOCK_CALL_P99")
    if not gates["single_hardware_stratum"]:
        expected_reasons.append("MIXED_HARDWARE_STRATA")
    _same_exact(expected_reasons, value.get("reason_codes"), "aggregate.reason_codes")
    decision = value.get("look1_extension_decision")
    if type(decision) is not dict:
        raise PostrunValidationError("aggregate look1 decision is missing")
    if warm_seed_count == 40:
        if decision.get("decision") != aggregate.REQUIRE_FULL_LOOK2:
            raise PostrunValidationError("N40 aggregate lacks a full-look2 authorization")
    elif decision.get("decision") == aggregate.REQUIRE_FULL_LOOK2:
        raise PostrunValidationError("N20 aggregate contradicts its look2 authorization")
    point_ids = [point.get("point_id") for point in points if type(point) is dict]
    if len(point_ids) != len(points) or len(set(point_ids)) != len(points):
        raise PostrunValidationError("aggregate points are malformed or duplicated")
    for profile in ("U", "A"):
        report = frontiers.get(profile)
        if type(report) is not dict:
            raise PostrunValidationError(f"aggregate frontier {profile} is missing")
        descriptive = sorted(
            point["point_id"] for point in points if point[f"point_estimate_frontier_{profile}"]
        )
        conservative = sorted(
            point["point_id"] for point in points if point[f"conservative_frontier_{profile}"]
        )
        expected_report = {
            "eligible_point_count": sum(point[f"eligible_profile_{profile}"] for point in points),
            "point_estimate_frontier_point_ids": descriptive,
            "conservative_frontier_point_ids": conservative,
        }
        _same_exact(expected_report, report, f"aggregate.frontiers.{profile}")
        if not descriptive or not conservative:
            raise PostrunValidationError(f"aggregate frontier {profile} is empty")


def build_receipt(value: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic receipt after validating aggregate self-consistency."""

    _validate_aggregate_state(value)
    p0_eligible = value["p0_eligible"]
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "receipt_id_schema": RECEIPT_ID_SCHEMA,
        "validation_status": value["validation_status"],
        "p0_eligible": p0_eligible,
        "promotion_decision": (PASS_DECISION if p0_eligible else NONPROMOTABLE_DECISION),
        "reason_codes": list(value["reason_codes"]),
        "protocol": value["protocol"],
        "bindings": {
            "aggregate_id": value["aggregate_id"],
            "semantic_config_id": value["semantic_config_id"],
            "semantic_dataset_id": value["semantic_dataset_id"],
            "source_commit": value["source_commit"],
            "analysis_source_commit": value["analysis_source_commit"],
            "analysis_source_clean": value["analysis_source_clean"],
            "analysis_source_status_scope": value["analysis_source_status_scope"],
            "source_evidence_binding_id": value["source_evidence"]["source_evidence_binding_id"],
            "support_receipts_binding_id": value["support_receipts"]["support_receipts_binding_id"],
            "look1_extension_decision_receipt_id": value["look1_extension_decision"]["receipt_id"],
            "all_observation_set_id": value["observation_sets"]["all"],
        },
        "counts": dict(value["counts"]),
        "gates": dict(value["gates"]),
        "validation_contract": {
            "raw_and_source_reaggregated": True,
            "provided_aggregate_type_sensitive_exact_match": True,
            "publication_revalidates_raw_and_source_before_rename": True,
            "frontier_composition_does_not_control_exit_code": True,
            "v1_secondary_replication_does_not_control_exit_code": True,
            "candidate_winner_does_not_control_exit_code": True,
        },
    }
    receipt["receipt_id"] = aggregate._sha256(_receipt_material(receipt))
    return receipt


def validate_result(result: Mapping[str, Any]) -> None:
    if type(result) is not dict or set(result) != {"aggregate", "receipt"}:
        raise PostrunValidationError("postrun result has the wrong schema")
    value = result["aggregate"]
    receipt = result["receipt"]
    if type(value) is not dict or type(receipt) is not dict:
        raise PostrunValidationError("postrun result members must be objects")
    expected_receipt = build_receipt(value)
    _same_exact(expected_receipt, receipt, "postrun.receipt")
    if not aggregate._is_hex64(receipt.get("receipt_id")):
        raise PostrunValidationError("postrun receipt ID is malformed")
    if aggregate._sha256(_receipt_material(receipt)) != receipt["receipt_id"]:
        raise PostrunValidationError("postrun receipt ID does not recompute")


def _verify_bound_analysis_checkout(value: Mapping[str, Any]) -> None:
    expected = {
        "analysis_source_commit": value.get("analysis_source_commit"),
        "analysis_source_clean": value.get("analysis_source_clean"),
        "analysis_source_status_scope": value.get("analysis_source_status_scope"),
    }
    try:
        current = aggregate._analysis_checkout_binding(value.get("source_commit"))
    except (aggregate.AggregateValidationError, TypeError) as error:
        raise PostrunValidationError(
            "postrun analysis checkout no longer matches the frozen source"
        ) from error
    _same_exact(expected, current, "analysis_checkout")


def recompute_and_validate(
    *, supplied_aggregate_path: Path, aggregate_kwargs: Mapping[str, Any]
) -> dict[str, Any]:
    """Reaggregate raw authorities and compare the supplied aggregate exactly."""

    try:
        recomputed = aggregate.validate_and_aggregate(**dict(aggregate_kwargs))
        _verify_bound_analysis_checkout(recomputed)
        supplied = aggregate.load_strict_json(supplied_aggregate_path, dict)
        _same_exact(recomputed, supplied, "provided_aggregate")
        result = {"aggregate": recomputed, "receipt": build_receipt(recomputed)}
        validate_result(result)
        _verify_bound_analysis_checkout(recomputed)
        return result
    except PostrunValidationError:
        raise
    except Exception as error:
        raise PostrunValidationError("raw/source postrun recomputation failed") from error


def _write_json_fsync(path: Path, value: Mapping[str, Any]) -> None:
    with path.open("x", encoding="ascii", newline="\n") as handle:
        json.dump(
            value,
            handle,
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        if os.name == "nt":
            return
        raise
    try:
        os.fsync(descriptor)
    except OSError:
        if os.name != "nt":
            raise
    finally:
        os.close(descriptor)


def _rename_directory_no_replace(source: Path, destination: Path) -> None:
    """Atomically rename a directory while refusing an existing destination."""

    if os.name == "nt":
        try:
            os.rename(source, destination)
        except FileExistsError as error:
            raise PostrunValidationError(
                f"refusing to overwrite publication directory {destination}"
            ) from error
        return
    if sys.platform.startswith("linux"):
        library = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(library, "renameat2", None)
        if renameat2 is None:
            raise PostrunValidationError("renameat2 no-replace is unavailable")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            AT_FDCWD,
            os.fsencode(source),
            AT_FDCWD,
            os.fsencode(destination),
            RENAME_NOREPLACE,
        )
        if result == 0:
            return
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise PostrunValidationError(
                f"refusing to overwrite publication directory {destination}"
            )
        raise PostrunValidationError(
            f"atomic no-replace publication failed: {os.strerror(error_number)}"
        )
    raise PostrunValidationError(
        "atomic directory no-replace publication is unsupported on this platform"
    )


def publish_outputs(
    output_dir: Path,
    result: Mapping[str, Any],
    *,
    recompute: Callable[[], Mapping[str, Any]],
    writer: Callable[[Path, Mapping[str, Any]], None] = _write_json_fsync,
) -> None:
    """Revalidate, stage, and atomically publish a complete result directory."""

    validate_result(result)
    _verify_bound_analysis_checkout(result["aggregate"])
    if output_dir.exists():
        raise PostrunValidationError(f"refusing to overwrite publication directory {output_dir}")
    fresh = recompute()
    if type(fresh) is not dict:
        raise PostrunValidationError("publication recomputation did not return an aggregate")
    _same_exact(result["aggregate"], fresh, "publication_recomputation")
    fresh_result = {"aggregate": fresh, "receipt": build_receipt(fresh)}
    _same_exact(result, fresh_result, "publication_result")
    validate_result(fresh_result)
    _verify_bound_analysis_checkout(fresh_result["aggregate"])
    immutable_snapshot = aggregate._canonical(fresh_result)

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    published = False
    try:
        aggregate_path = temporary / AGGREGATE_FILENAME
        receipt_path = temporary / RECEIPT_FILENAME
        publication_payload = json.loads(immutable_snapshot)
        writer(aggregate_path, publication_payload["aggregate"])
        writer(receipt_path, publication_payload["receipt"])
        staged_result = {
            "aggregate": aggregate.load_strict_json(aggregate_path, dict),
            "receipt": aggregate.load_strict_json(receipt_path, dict),
        }
        if aggregate._canonical(staged_result) != immutable_snapshot:
            raise PostrunValidationError(
                "staged result differs from immutable publication snapshot"
            )
        validate_result(staged_result)
        _fsync_directory(temporary)
        _verify_bound_analysis_checkout(staged_result["aggregate"])
        _rename_directory_no_replace(temporary, output_dir)
        try:
            _fsync_directory(output_dir.parent)
        except OSError as durability_error:
            try:
                os.rename(output_dir, temporary)
                _fsync_directory(output_dir.parent)
            except OSError as rollback_error:
                raise PostrunValidationError(
                    "publication parent-directory fsync failed and atomic rollback "
                    "could not be made durable; publication state is indeterminate"
                ) from rollback_error
            raise PostrunValidationError(
                "publication parent-directory fsync failed; publication was rolled back"
            ) from durability_error
        published = True
    except PostrunValidationError:
        raise
    except Exception as error:
        raise PostrunValidationError("publication staging failed") from error
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)


def exit_code_for_result(result: Mapping[str, Any]) -> int:
    validate_result(result)
    return 0 if result["receipt"]["p0_eligible"] else 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    aggregate._common_parser(parser)
    parser.add_argument("--look1-decision", type=Path, required=True)
    parser.add_argument("--v1-config", type=Path, required=True)
    parser.add_argument("--v1-audit", type=Path, required=True)
    parser.add_argument("--aggregate", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def _aggregate_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    return {
        **aggregate._common_kwargs(args),
        "look1_decision_path": args.look1_decision,
        "v1_config_path": args.v1_config,
        "v1_audit_path": args.v1_audit,
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        kwargs = _aggregate_kwargs(args)
        result = recompute_and_validate(
            supplied_aggregate_path=args.aggregate,
            aggregate_kwargs=kwargs,
        )
        publish_outputs(
            args.output_dir,
            result,
            recompute=lambda: aggregate.validate_and_aggregate(**kwargs),
        )
    except SystemExit as error:
        return 0 if error.code == 0 else 3
    except Exception as error:
        print(
            f"v2 postrun refused: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 3
    print(aggregate._canonical(result["receipt"]))
    return exit_code_for_result(result)


if __name__ == "__main__":
    raise SystemExit(main())
