#!/usr/bin/env python3
"""Validate and execute preregistered E11 formal matched-system points."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.analysis import register_phase1_v21_baseline as registration  # noqa: E402
from experiments.runners import preacher_matched_bench as smoke  # noqa: E402
from experiments.runners.preacher_matched_adapters import (  # noqa: E402
    ADAPTER_RESULT_SCHEMA,
    REPOSITORY_METHOD,
    UPSTREAM_METHOD,
    AdapterExecutionError,
    run_repository_adapter,
    run_upstream_adapter,
    validate_adapter_result,
)

MANIFEST_SCHEMA = "traps-e11-preacher-formal-workload-manifest-v1"
TRACE_SCHEMA = "traps-e11-preacher-formal-trace-v1"
POINT_SCHEMA = "traps-e11-preacher-formal-point-v1"
PENDING_STATUS = "PREREGISTERED_PENDING_PHASE1_V2_1_BASELINE"
REGISTERED_STATUS = "REGISTERED_READY_FOR_FORMAL_POINTS"
FORMAL_EXECUTION_STATUS = "PASS_FORMAL_POINT"
STRONG_ORACLE_SOURCE = "FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1"
HEX40 = re.compile(r"[0-9a-f]{40}")


class FormalBenchError(ValueError):
    """Raised when an E11 formal point is not exactly preregistered."""


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _identity(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FormalBenchError(f"{label} must be a mapping")
    return value


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise FormalBenchError(f"{label} fields changed")


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 1:
        raise FormalBenchError(f"{label} must be a positive integer")
    return value


def _positive_screen_label(binding_status: object) -> str:
    if binding_status == registration.RECOVERY_REGISTERED:
        return "REGISTERED_PHASE1_V2_2_SERVICE_BASELINE_RECOVERY"
    return "REGISTERED_PHASE1_V2_1_STRONG_BASELINE"


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    root = registration.load_strict_yaml(path, "formal E11 config")
    _exact_keys(
        root,
        {
            "schema",
            "status",
            "source",
            "preacher_profiles",
            "active_preacher_profile",
            "derived_baseline_binding",
            "seeds",
            "matched_system_contract",
            "workloads",
            "output_contract",
            "execution",
        },
        "formal E11 config",
    )
    if root.get("schema") != MANIFEST_SCHEMA:
        raise FormalBenchError("formal E11 schema changed")
    status = root.get("status")
    if status not in {PENDING_STATUS, REGISTERED_STATUS}:
        raise FormalBenchError("formal E11 status changed")
    source = _mapping(root["source"], "source")
    if dict(source) != {
        "repository": "https://github.com/SHiftLin/NSDI2025-PreAcher.git",
        "revision": smoke.UPSTREAM_REVISION,
        "redistribution": "RETRIEVE_ONLY_NO_BUNDLING",
    }:
        raise FormalBenchError("formal E11 upstream source binding changed")
    profiles = _mapping(root["preacher_profiles"], "preacher_profiles")
    if set(profiles) != {"upstream_as_released", "paper_intended_derived"}:
        raise FormalBenchError("formal E11 profile set changed")
    if root["active_preacher_profile"] != "upstream_as_released":
        raise FormalBenchError("derived PreAcher profile cannot be activated")
    upstream_profile = _mapping(profiles["upstream_as_released"], "upstream profile")
    if dict(upstream_profile) != {
        "source_class": "UPSTREAM_AS_RELEASED",
        "implementation_status": "RELEASED_PROTOCOL_ADAPTER_IMPLEMENTED",
        "kmer_k": 5,
        "weighted_minhash": True,
        "minhash_key_mode": "CONSTANT_LITERAL",
        "minhash_key_literal": 42,
        "failure_cutoff_q": None,
    }:
        raise FormalBenchError("upstream-as-released profile changed")
    derived_profile = _mapping(profiles["paper_intended_derived"], "derived profile")
    if dict(derived_profile) != {
        "source_class": "DERIVED_NOT_UPSTREAM",
        "implementation_status": "NOT_IMPLEMENTED_EXCLUDED_FROM_FORMAL_RESULTS",
        "kmer_k": 4,
        "weighted_minhash": True,
        "minhash_key_mode": "USER_BOUND_HMAC",
        "minhash_key_literal": None,
        "failure_cutoff_q": 20,
    }:
        raise FormalBenchError("paper-intended derived profile changed")

    binding = registration.validate_binding(
        root["derived_baseline_binding"],
        schema=registration.E11_BINDING_SCHEMA,
    )
    if status == PENDING_STATUS and binding["status"] != registration.PENDING:
        raise FormalBenchError("pending formal config has a registered binding")
    if status == REGISTERED_STATUS and not registration.is_registered_status(binding["status"]):
        raise FormalBenchError("registered formal config lacks its Phase 1 binding")

    seeds = root["seeds"]
    if seeds != list(range(7100, 7120)):
        raise FormalBenchError("formal E11 seeds changed")
    contract = _mapping(root["matched_system_contract"], "matched_system_contract")
    _exact_keys(
        contract,
        {
            "arrival_unit",
            "arrival_mode",
            "schedule",
            "account_count",
            "kdf",
            "workers",
            "methods",
            "repository_mechanism",
        },
        "matched_system_contract",
    )
    if {
        "arrival_unit": contract["arrival_unit"],
        "arrival_mode": contract["arrival_mode"],
        "schedule": contract["schedule"],
        "account_count": contract["account_count"],
        "methods": contract["methods"],
        "repository_mechanism": contract["repository_mechanism"],
    } != {
        "arrival_unit": "authentication_attempt",
        "arrival_mode": "open_loop",
        "schedule": "deterministic_interleaved",
        "account_count": 128,
        "methods": [UPSTREAM_METHOD, REPOSITORY_METHOD],
        "repository_mechanism": {
            "positive_screen": _positive_screen_label(binding["status"]),
            "exact_negative_cache": "lru",
            "singleflight": True,
        },
    }:
        raise FormalBenchError("formal E11 matched-system contract changed")
    if dict(_mapping(contract["kdf"], "kdf")) != {
        "algorithm": "pbkdf2_hmac_sha256",
        "iterations": 10000,
        "salt_bytes": 32,
        "output_bytes": 256,
    }:
        raise FormalBenchError("formal E11 released KDF contract changed")
    if dict(_mapping(contract["workers"], "workers")) != {
        "load_generator": 1,
        "frontend_handler": 20,
        "origin_kdf_handler": 20,
    }:
        raise FormalBenchError("formal E11 worker contract changed")

    workloads = root["workloads"]
    if not isinstance(workloads, list) or len(workloads) != 2:
        raise FormalBenchError("formal E11 workload set changed")
    by_name: dict[str, Mapping[str, Any]] = {}
    expected_workload_keys = {
        "name",
        "role",
        "duration_seconds",
        "legitimate_attempts_per_second",
        "invalid_attempts_per_second",
        "invalid_tuple_mode",
        "false_positive_source",
        "repeated_tuple_count",
        "minimum_replay_multiplicity",
        "direct_latency_comparison_permitted",
    }
    for index, raw in enumerate(workloads):
        workload = _mapping(raw, f"workloads[{index}]")
        _exact_keys(workload, expected_workload_keys, f"workloads[{index}]")
        name = workload.get("name")
        if not isinstance(name, str) or name in by_name:
            raise FormalBenchError("formal E11 workload names are invalid")
        by_name[name] = workload
    expected_workloads = {
        "matched_ados_open_loop": {
            "role": "SAME_BACKEND_AND_OFFERED_LOAD_END_TO_END_ADOS",
            "invalid_tuple_mode": "DETERMINISTIC_UNIQUE_FIRST_SEEN",
            "false_positive_source": None,
            "repeated_tuple_count": None,
            "minimum_replay_multiplicity": None,
        },
        "repeat_heavy_static_survivor": {
            "role": "STATIC_SURVIVOR_REPLAY_AMPLIFICATION",
            "invalid_tuple_mode": "FROZEN_STRONG_ORACLE_CONDITIONED_REPEAT",
            "false_positive_source": STRONG_ORACLE_SOURCE,
            "repeated_tuple_count": 16,
            "minimum_replay_multiplicity": 100,
        },
    }
    if set(by_name) != set(expected_workloads):
        raise FormalBenchError("formal E11 workload names changed")
    for name, literals in expected_workloads.items():
        workload = by_name[name]
        if any(workload.get(key) != value for key, value in literals.items()):
            raise FormalBenchError(f"formal E11 {name} contract changed")
        if (
            workload.get("duration_seconds") != 120
            or workload.get("legitimate_attempts_per_second") != 16
            or workload.get("invalid_attempts_per_second") != 32
            or workload.get("direct_latency_comparison_permitted") is not True
        ):
            raise FormalBenchError(f"formal E11 {name} offered-load contract changed")

    output = _mapping(root["output_contract"], "output_contract")
    if dict(output) != {
        "point_schema": POINT_SCHEMA,
        "trace_schema": TRACE_SCHEMA,
        "adapter_result_schema": ADAPTER_RESULT_SCHEMA,
        "immutable_directory_no_overwrite": True,
        "required_bindings": [
            "manifest_id",
            "registration_id",
            "workload_name",
            "seed",
            "trace_id",
            "invalid_tuple_multiplicity_commitment_id",
            "minimum_invalid_tuple_multiplicity",
            "upstream_result_id",
            "repository_result_id",
        ],
    }:
        raise FormalBenchError("formal E11 output contract changed")
    execution = _mapping(root["execution"], "execution")
    expected_result_status = "NOT_RUN" if status == PENDING_STATUS else "READY_FOR_FORMAL_POINTS"
    if dict(execution) != {
        "result_status": expected_result_status,
        "require_clean_git": True,
        "provenance_class": "CANDIDATE_FORMAL_E11",
        "maximum_concurrent_points_per_host": 1,
        "paper_intended_derived_profile_executed": False,
        "engineering_smoke_is_formal_result": False,
    }:
        raise FormalBenchError("formal E11 execution contract changed")
    return dict(root), _identity(root)


def _runtime_manifest(
    config: Mapping[str, Any], workload: Mapping[str, Any], seed: int
) -> dict[str, Any]:
    matched = config["matched_system_contract"]
    return {
        "matched_contract": {
            "arrival_unit": matched["arrival_unit"],
            "arrival_mode": matched["arrival_mode"],
            "schedule": matched["schedule"],
            "seed": seed,
            "duration_seconds": workload["duration_seconds"],
            "legitimate_attempts_per_second": workload["legitimate_attempts_per_second"],
            "invalid_attempts_per_second": workload["invalid_attempts_per_second"],
            "account_count": matched["account_count"],
            "kdf": dict(matched["kdf"]),
            "workers": dict(matched["workers"]),
        },
        "repository_mechanism": dict(matched["repository_mechanism"]),
        "derived_baseline_binding": dict(config["derived_baseline_binding"]),
    }


def build_trace(
    config: Mapping[str, Any], manifest_id: str, workload_name: str, seed: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    if seed not in config["seeds"]:
        raise FormalBenchError("seed is outside the frozen formal E11 set")
    workloads = {item["name"]: item for item in config["workloads"]}
    if workload_name not in workloads:
        raise FormalBenchError("workload is outside the frozen formal E11 set")
    workload = workloads[workload_name]
    runtime_manifest = _runtime_manifest(config, workload, seed)
    contract = runtime_manifest["matched_contract"]
    account_count = int(contract["account_count"])
    enrollments = [
        {
            "account_id": f"e11-formal-account-{index:03d}",
            "enrollment_password": f"E11-formal-valid:{seed}:{index:03d}",
        }
        for index in range(account_count)
    ]
    duration_ns = int(contract["duration_seconds"]) * 1_000_000_000
    scheduled: list[tuple[int, str, int]] = []
    for credential_class, rate in (
        ("legitimate", int(contract["legitimate_attempts_per_second"])),
        ("invalid", int(contract["invalid_attempts_per_second"])),
    ):
        count = int(contract["duration_seconds"]) * rate
        scheduled.extend(
            ((index + 1) * duration_ns // (count + 1), credential_class, index)
            for index in range(count)
        )
    scheduled.sort(key=lambda item: (item[0], item[1], item[2]))
    events: list[dict[str, Any]] = []
    invalid_ordinal = 0
    legitimate_ordinal = 0
    repeat_count = workload["repeated_tuple_count"]
    for ordinal, (offset_ns, credential_class, _class_index) in enumerate(scheduled):
        if credential_class == "legitimate":
            account_index = (legitimate_ordinal * 17 + seed) % account_count
            credential_id = f"valid-{account_index:03d}"
            attempt_password = enrollments[account_index]["enrollment_password"]
            legitimate_ordinal += 1
        else:
            tuple_index = (
                invalid_ordinal if repeat_count is None else invalid_ordinal % repeat_count
            )
            account_index = (tuple_index * 29 + seed) % account_count
            credential_id = f"invalid-{workload_name}-{seed}-{tuple_index:06d}"
            attempt_password = f"E11-formal-invalid:{seed}:{tuple_index:06d}"
            invalid_ordinal += 1
        enrollment = enrollments[account_index]
        event = {
            "ordinal": ordinal,
            "scheduled_offset_ns": offset_ns,
            "credential_class": credential_class,
            "account_id": enrollment["account_id"],
            "credential_id": credential_id,
            "enrollment_password": enrollment["enrollment_password"],
            "attempt_password": attempt_password,
        }
        event["attempt_id"] = _identity(
            {"manifest_id": manifest_id, "workload": workload_name, "seed": seed, **event}
        )
        events.append(event)
    invalid_events = [event for event in events if event["credential_class"] == "invalid"]
    multiplicities = Counter(str(event["credential_id"]) for event in invalid_events)
    commitment_material = [
        {"credential_id": credential_id, "multiplicity": multiplicities[credential_id]}
        for credential_id in sorted(multiplicities)
    ]
    conditioned_material = [
        {
            "account_id": event["account_id"],
            "credential_id": event["credential_id"],
            "attempt_password": event["attempt_password"],
        }
        for event in invalid_events
        if multiplicities[event["credential_id"]] > 1
    ]
    conditioned_by_id = {item["credential_id"]: item for item in conditioned_material}
    trace: dict[str, Any] = {
        "schema": TRACE_SCHEMA,
        "manifest_id": manifest_id,
        "workload_name": workload_name,
        "seed": seed,
        "arrival_unit": contract["arrival_unit"],
        "arrival_mode": contract["arrival_mode"],
        "schedule": contract["schedule"],
        "duration_seconds": contract["duration_seconds"],
        "event_count": len(events),
        "enrollment_account_count": len(enrollments),
        "enrollment_accounts": enrollments,
        "false_positive_source": workload["false_positive_source"],
        "conditioned_tuple_set_id": (
            _identity([conditioned_by_id[key] for key in sorted(conditioned_by_id)])
            if conditioned_by_id
            else None
        ),
        "conditioned_tuple_count": len(conditioned_by_id),
        "invalid_tuple_multiplicity_commitment_id": _identity(commitment_material),
        "minimum_invalid_tuple_multiplicity": min(multiplicities.values()),
        "events": events,
    }
    if repeat_count is not None:
        if len(multiplicities) != repeat_count:
            raise FormalBenchError("repeat-heavy trace tuple count changed")
        if trace["minimum_invalid_tuple_multiplicity"] < int(
            workload["minimum_replay_multiplicity"]
        ):
            raise FormalBenchError("repeat-heavy trace misses its multiplicity floor")
    trace["trace_id"] = _identity(trace)
    return trace, runtime_manifest


def _require_clean_commit(expected_commit: str) -> dict[str, Any]:
    if HEX40.fullmatch(expected_commit) is None:
        raise FormalBenchError("expected commit must be lowercase 40-hex")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()
    if commit != expected_commit or dirty:
        raise FormalBenchError("formal E11 requires the expected clean committed checkout")
    return {"commit": commit, "clean": True, "scope": "FULL_REPOSITORY"}


def _publish_point(output_dir: Path, files: Mapping[str, Mapping[str, Any]]) -> None:
    if output_dir.exists() or output_dir.is_symlink():
        raise FormalBenchError("refusing to overwrite an E11 formal point directory")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    published = False
    try:
        for name, value in files.items():
            with (temporary / name).open("x", encoding="ascii", newline="\n") as handle:
                handle.write(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        os.replace(temporary, output_dir)
        published = True
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)


def run_point(
    *,
    config: Mapping[str, Any],
    manifest_id: str,
    workload_name: str,
    seed: int,
    upstream_root: Path,
    node_adapter: Path,
    expected_commit: str,
    output_dir: Path,
) -> dict[str, Any]:
    if config["status"] != REGISTERED_STATUS:
        raise FormalBenchError("formal E11 point cannot run before Phase 1 registration")
    source_state = _require_clean_commit(expected_commit)
    trace, runtime_manifest = build_trace(config, manifest_id, workload_name, seed)
    preflight = smoke.inspect_upstream(upstream_root, smoke.UPSTREAM_REVISION)
    if preflight["status"] != "PASS":
        raise FormalBenchError("formal E11 upstream preflight failed")
    upstream = run_upstream_adapter(
        runtime_manifest,
        manifest_id,
        trace,
        upstream_root=upstream_root,
        node_adapter=node_adapter,
        upstream_preflight=preflight,
        execution_status=FORMAL_EXECUTION_STATUS,
    )
    repository = run_repository_adapter(
        runtime_manifest,
        manifest_id,
        trace,
        execution_status=FORMAL_EXECUTION_STATUS,
        phase_name=f"e11_formal_{workload_name}_{seed}",
    )
    contract_id = _identity(runtime_manifest["matched_contract"])
    for method, result in ((UPSTREAM_METHOD, upstream), (REPOSITORY_METHOD, repository)):
        validate_adapter_result(
            result,
            expected_method=method,
            manifest_id=manifest_id,
            contract_id=contract_id,
            trace=trace,
            expected_baseline_binding=config["derived_baseline_binding"],
            expected_execution_status=FORMAL_EXECUTION_STATUS,
        )
    if trace["false_positive_source"] == STRONG_ORACLE_SOURCE:
        binding = repository["source_binding"]
        if (
            binding.get("false_positive_source") != STRONG_ORACLE_SOURCE
            or binding.get("conditioned_tuple_set_id") != trace["conditioned_tuple_set_id"]
            or binding.get("conditioned_tuple_count") != trace["conditioned_tuple_count"]
            or binding.get("underlying_filter_query_executed") is not True
            or binding.get("conditional_intervention_does_not_estimate_ffr") is not True
        ):
            raise FormalBenchError("repository strong-oracle binding changed")
        runtime = _mapping(
            binding.get("conditional_intervention_runtime"),
            "conditional intervention runtime",
        )
        if (
            runtime.get("underlying_query_count", 0) < trace["conditioned_tuple_count"]
            or runtime.get("conditioned_query_count", 0) < trace["conditioned_tuple_count"]
        ):
            raise FormalBenchError("repository did not query every conditioned tuple")
    body: dict[str, Any] = {
        "schema": POINT_SCHEMA,
        "status": "PASS_RAW_FORMAL_POINT_NOT_AGGREGATED",
        "provenance_class": "CANDIDATE_FORMAL_E11",
        "manifest_id": manifest_id,
        "registration_id": config["derived_baseline_binding"]["registration_id"],
        "workload_name": workload_name,
        "seed": seed,
        "trace_id": trace["trace_id"],
        "invalid_tuple_multiplicity_commitment_id": trace[
            "invalid_tuple_multiplicity_commitment_id"
        ],
        "minimum_invalid_tuple_multiplicity": trace["minimum_invalid_tuple_multiplicity"],
        "upstream_result_id": upstream["result_id"],
        "repository_result_id": repository["result_id"],
        "analysis_source_state": source_state,
        "active_preacher_profile": "upstream_as_released",
        "paper_intended_derived_profile_executed": False,
        "engineering_smoke_is_formal_result": False,
        "formal_aggregate_status": "NOT_RUN",
    }
    point = {**body, "point_id": _identity(body)}
    _publish_point(
        output_dir,
        {
            "trace.json": trace,
            f"{UPSTREAM_METHOD}.json": upstream,
            f"{REPOSITORY_METHOD}.json": repository,
            "point.json": point,
        },
    )
    return point


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--validate-only", action="store_true")
    mode.add_argument("--run-point", action="store_true")
    parser.add_argument("--workload")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--upstream-root", type=Path)
    parser.add_argument(
        "--node-adapter",
        type=Path,
        default=Path(__file__).with_name("preacher_upstream_adapter.mjs"),
    )
    parser.add_argument("--expected-commit")
    parser.add_argument("--output-dir", type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        config, manifest_id = load_config(args.config)
        if args.validate_only:
            payload = {
                "schema": MANIFEST_SCHEMA,
                "status": config["status"],
                "manifest_id": manifest_id,
                "formal_execution_started": False,
            }
            print(_canonical(payload))
            return 0 if config["status"] == REGISTERED_STATUS else 2
        required = {
            "--workload": args.workload,
            "--seed": args.seed,
            "--upstream-root": args.upstream_root,
            "--expected-commit": args.expected_commit,
            "--output-dir": args.output_dir,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            raise FormalBenchError("run-point requires " + ", ".join(missing))
        point = run_point(
            config=config,
            manifest_id=manifest_id,
            workload_name=args.workload,
            seed=args.seed,
            upstream_root=args.upstream_root,
            node_adapter=args.node_adapter,
            expected_commit=args.expected_commit,
            output_dir=args.output_dir,
        )
    except (
        AdapterExecutionError,
        FormalBenchError,
        OSError,
        registration.RegistrationError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(_canonical({"status": "INVALID", "error": str(error)}), file=sys.stderr)
        return 3
    print(_canonical(point))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
