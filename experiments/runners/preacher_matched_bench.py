#!/usr/bin/env python3
"""Attempt-matched PreAcher engineering runner with fail-closed receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.analysis import register_phase1_v21_baseline as phase1_registration  # noqa: E402
from experiments.runners.preacher_matched_adapters import (  # noqa: E402
    REPOSITORY_METHOD,
    UPSTREAM_METHOD,
    AdapterExecutionError,
    run_repository_adapter,
    run_upstream_adapter,
    validate_adapter_result,
)

MANIFEST_SCHEMA = "traps-e11-preacher-matched-load-manifest-v2"
TRACE_SCHEMA = "traps-e11-preacher-attempt-trace-v2"
RECEIPT_SCHEMA = "traps-e11-preacher-engineering-receipt-v2"
ERROR_SCHEMA = "traps-e11-preacher-runner-error-v1"
UPSTREAM_REVISION = "5a083ceea001b002187d9d4b5a26371be061f1cc"
UPSTREAM_PROFILE = "upstream_as_released"
DERIVED_PROFILE = "paper_intended_derived"
SHARED_TRACE_BINDING = "HARNESS_GENERATED_SINGLE_ATTEMPT_TRACE"
MANIFEST_STATUS = "ENGINEERING_SMOKE_IMPLEMENTED_NOT_ADJUDICABLE"
NOT_ADJUDICABLE = "NOT_ADJUDICABLE"
DERIVED_BASELINE_BINDING_SCHEMA = "traps-e11-phase1-v2-derived-baseline-binding-v1"
DERIVED_BASELINE_PENDING = "PENDING_PHASE1_V2_1_POSTRUN_RECEIPT"
DERIVED_BASELINE_REGISTERED = "REGISTERED_PHASE1_V2_1_BASELINE"
DERIVED_BASELINE_RECOVERY_REGISTERED = "REGISTERED_PHASE1_V2_2_SERVICE_BASELINE"
DERIVED_BASELINE_REGISTERED_STATUSES = frozenset(
    {DERIVED_BASELINE_REGISTERED, DERIVED_BASELINE_RECOVERY_REGISTERED}
)
PHASE1_RECEIPT_SCHEMA = "traps-phase1-timing-frontier-v2-postrun-receipt-v2"
PHASE1_RECEIPT_BLOCKER = "PHASE1_V2_1_BASELINE_RECEIPT_NOT_REGISTERED"
EXIT_ADJUDICATED = 0
EXIT_NOT_ADJUDICABLE = 2
EXIT_INVALID = 3


class ManifestError(ValueError):
    """Raised when an E11 manifest contradicts the engineering contract."""


class _StrictArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ManifestError(f"invalid CLI: {message}")


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ManifestError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping,
)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _exact_keys(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise ManifestError(f"{label} fields differ: missing={missing}, extra={extra}")


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestError(f"{label} must be a mapping")
    return value


def _validate_kdf(value: Any, label: str) -> dict[str, Any]:
    kdf = dict(_require_mapping(value, label))
    expected = {
        "algorithm": "pbkdf2_hmac_sha256",
        "iterations": 10000,
        "salt_bytes": 32,
        "output_bytes": 256,
    }
    if kdf != expected:
        raise ManifestError(f"{label} must match the upstream released PBKDF2 profile")
    return kdf


def _validate_workers(value: Any, label: str) -> dict[str, int]:
    workers = dict(_require_mapping(value, label))
    _exact_keys(
        workers,
        {"load_generator", "frontend_handler", "origin_kdf_handler"},
        label,
    )
    if any(type(item) is not int or item < 1 for item in workers.values()):
        raise ManifestError(f"{label} counts must be positive integers")
    if workers != {
        "load_generator": 1,
        "frontend_handler": 20,
        "origin_kdf_handler": 20,
    }:
        raise ManifestError(f"{label} must match the released Workflow worker contract")
    return workers


def _validate_derived_baseline_binding(value: Any) -> dict[str, Any]:
    try:
        return phase1_registration.validate_binding(
            value,
            schema=DERIVED_BASELINE_BINDING_SCHEMA,
            root=ROOT,
        )
    except phase1_registration.RegistrationError as error:
        raise ManifestError(f"invalid derived_baseline_binding: {error}") from error


def _validate_profiles(value: Any) -> dict[str, dict[str, Any]]:
    profiles = _require_mapping(value, "preacher_profiles")
    if set(profiles) != {UPSTREAM_PROFILE, DERIVED_PROFILE}:
        raise ManifestError("preacher_profiles must keep released and derived profiles separate")
    upstream = dict(_require_mapping(profiles[UPSTREAM_PROFILE], UPSTREAM_PROFILE))
    derived = dict(_require_mapping(profiles[DERIVED_PROFILE], DERIVED_PROFILE))
    _exact_keys(
        upstream,
        {
            "source_class",
            "implementation_status",
            "kmer_k",
            "weighted_minhash",
            "minhash_key_mode",
            "minhash_key_literal",
            "failure_cutoff_q",
        },
        UPSTREAM_PROFILE,
    )
    if upstream != {
        "source_class": "UPSTREAM_AS_RELEASED",
        "implementation_status": "BUILT_AND_PROTOCOL_SMOKED_ONLY",
        "kmer_k": 5,
        "weighted_minhash": True,
        "minhash_key_mode": "CONSTANT_LITERAL",
        "minhash_key_literal": 42,
        "failure_cutoff_q": None,
    }:
        raise ManifestError("upstream_as_released parameters contradict the pinned source")
    _exact_keys(
        derived,
        {
            "source_class",
            "implementation_status",
            "kmer_k",
            "weighted_minhash",
            "minhash_key_mode",
            "minhash_key_literal",
            "failure_cutoff_q",
        },
        DERIVED_PROFILE,
    )
    if derived != {
        "source_class": "DERIVED_NOT_UPSTREAM",
        "implementation_status": "NOT_IMPLEMENTED",
        "kmer_k": 4,
        "weighted_minhash": True,
        "minhash_key_mode": "USER_BOUND_HMAC",
        "minhash_key_literal": None,
        "failure_cutoff_q": 20,
    }:
        raise ManifestError("paper_intended_derived must remain an unimplemented derived profile")
    return {UPSTREAM_PROFILE: upstream, DERIVED_PROFILE: derived}


def load_manifest(path: Path) -> tuple[dict[str, Any], str]:
    try:
        value = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ManifestError(f"cannot load E11 manifest: {exc}") from exc
    root = _require_mapping(value, "manifest")
    _exact_keys(
        root,
        {
            "schema",
            "status",
            "source",
            "preacher_profiles",
            "active_preacher_profile",
            "derived_baseline_binding",
            "matched_contract",
            "methods",
            "report_contract",
            "execution",
        },
        "manifest",
    )
    if root.get("schema") != MANIFEST_SCHEMA:
        raise ManifestError("unsupported E11 manifest schema")
    if root.get("status") != MANIFEST_STATUS:
        raise ManifestError(
            "E11 manifest cannot claim adjudication without a frozen derived baseline"
        )

    source = _require_mapping(root["source"], "source")
    _exact_keys(source, {"repository", "revision", "redistribution"}, "source")
    if source.get("repository") != "https://github.com/SHiftLin/NSDI2025-PreAcher.git":
        raise ManifestError("unexpected PreAcher repository")
    revision = source.get("revision")
    if revision != UPSTREAM_REVISION:
        raise ManifestError("PreAcher revision must remain pinned to the audited source")
    if source.get("redistribution") != "RETRIEVE_ONLY_NO_BUNDLING":
        raise ManifestError("PreAcher redistribution boundary changed")

    profiles = _validate_profiles(root["preacher_profiles"])
    if root.get("active_preacher_profile") != UPSTREAM_PROFILE:
        raise ManifestError(
            "the derived PreAcher profile cannot be activated before implementation"
        )
    baseline_binding = _validate_derived_baseline_binding(root["derived_baseline_binding"])

    contract = _require_mapping(root["matched_contract"], "matched_contract")
    _exact_keys(
        contract,
        {
            "arrival_unit",
            "arrival_mode",
            "schedule",
            "seed",
            "duration_seconds",
            "legitimate_attempts_per_second",
            "invalid_attempts_per_second",
            "account_count",
            "account_concurrency_policy",
            "credential_sequence",
            "kdf",
            "workers",
        },
        "matched_contract",
    )
    expected_literals = {
        "arrival_unit": "authentication_attempt",
        "arrival_mode": "open_loop",
        "schedule": "deterministic_interleaved",
        "account_concurrency_policy": "UNIQUE_ACCOUNT_PER_ATTEMPT",
        "credential_sequence": "DETERMINISTIC_SHARED_VALID_AND_DISTINCT_INVALID",
    }
    for field, expected in expected_literals.items():
        if contract.get(field) != expected:
            raise ManifestError(f"matched_contract.{field} must be {expected}")
    for field in (
        "seed",
        "duration_seconds",
        "legitimate_attempts_per_second",
        "invalid_attempts_per_second",
        "account_count",
    ):
        if type(contract.get(field)) is not int or int(contract[field]) < 1:
            raise ManifestError(f"matched_contract.{field} must be a positive integer")
    kdf = _validate_kdf(contract["kdf"], "matched_contract.kdf")
    workers = _validate_workers(contract["workers"], "matched_contract.workers")
    total_attempts = int(contract["duration_seconds"]) * (
        int(contract["legitimate_attempts_per_second"])
        + int(contract["invalid_attempts_per_second"])
    )
    if int(contract["account_count"]) < total_attempts:
        raise ManifestError(
            "matched_contract.account_count must permit a unique account for every attempt"
        )

    methods = root["methods"]
    if not isinstance(methods, list) or len(methods) != 2:
        raise ManifestError("methods must contain exactly the PreAcher and R-TRAPS adapters")
    expected_names = {"preacher_upstream_as_released", "r_traps_released_kdf_profile"}
    observed_names: set[str] = set()
    for index, item in enumerate(methods):
        method = _require_mapping(item, f"methods[{index}]")
        _exact_keys(
            method,
            {
                "name",
                "system_profile",
                "adapter_status",
                "arrival_trace_binding",
                "kdf",
                "workers",
            },
            f"methods[{index}]",
        )
        name = str(method.get("name"))
        observed_names.add(name)
        expected_adapter_status = "IMPLEMENTED_RELEASED_PROTOCOL_ADAPTER"
        if name == REPOSITORY_METHOD:
            expected_adapter_status = (
                "IMPLEMENTED_REPOSITORY_ADAPTER_REGISTERED_PHASE1_BASELINE"
                if baseline_binding["status"] in DERIVED_BASELINE_REGISTERED_STATUSES
                else "IMPLEMENTED_REPOSITORY_ADAPTER_PENDING_PHASE1_BASELINE"
            )
        if method.get("adapter_status") != expected_adapter_status:
            raise ManifestError(f"{name} adapter status contradicts the implementation")
        if method.get("arrival_trace_binding") != SHARED_TRACE_BINDING:
            raise ManifestError("both methods must consume the one harness-generated trace")
        if _validate_kdf(method["kdf"], f"methods[{index}].kdf") != kdf:
            raise ManifestError("method KDF contracts differ")
        if _validate_workers(method["workers"], f"methods[{index}].workers") != workers:
            raise ManifestError("method worker pools differ")
        expected_profile = (
            UPSTREAM_PROFILE if name == UPSTREAM_METHOD else "r_traps_matched_released_kdf"
        )
        if method.get("system_profile") != expected_profile:
            raise ManifestError(f"{name} has the wrong system profile")
    if observed_names != expected_names:
        raise ManifestError("method names do not identify both matched systems")

    report = _require_mapping(root["report_contract"], "report_contract")
    _exact_keys(report, {"required_metrics"}, "report_contract")
    required_metrics = report["required_metrics"]
    expected_metrics = [
        "backend_invalid_checks",
        "checks_per_distinct_invalid_tuple",
        "legitimate_throughput_rps",
        "legitimate_p99_ms",
        "legitimate_timeout_rate",
        "saturation_interval",
        "frontend_cpu_seconds",
        "frontend_peak_rss_bytes",
        "origin_cpu_seconds",
        "origin_peak_rss_bytes",
        "protocol_http_requests",
        "rsa_operations",
        "two_round_attempts",
    ]
    if required_metrics != expected_metrics:
        raise ManifestError("report_contract.required_metrics changed")

    execution = _require_mapping(root["execution"], "execution")
    _exact_keys(
        execution,
        {"phase", "result_status", "adapters", "matched_load"},
        "execution",
    )
    if dict(execution) != {
        "phase": "ENGINEERING_SMOKE",
        "result_status": NOT_ADJUDICABLE,
        "adapters": "IMPLEMENTED",
        "matched_load": "IMPLEMENTED_ENGINEERING_SMOKE",
    }:
        raise ManifestError("execution must bind implemented engineering adapters")

    # Break YAML alias object identity so later mutation cannot update multiple
    # method declarations through one shared Python object.
    normalized = json.loads(json.dumps(root))
    normalized["preacher_profiles"] = profiles
    normalized["derived_baseline_binding"] = baseline_binding
    normalized["matched_contract"] = dict(contract)
    return normalized, _sha256(normalized)


def build_attempt_trace(manifest: Mapping[str, Any], manifest_id: str) -> dict[str, Any]:
    contract = manifest["matched_contract"]
    duration_ns = int(contract["duration_seconds"]) * 1_000_000_000
    scheduled: list[tuple[int, str]] = []
    for credential_class, rate in (
        ("legitimate", int(contract["legitimate_attempts_per_second"])),
        ("invalid", int(contract["invalid_attempts_per_second"])),
    ):
        count = int(contract["duration_seconds"]) * rate
        scheduled.extend(
            ((index + 1) * duration_ns // (count + 1), credential_class) for index in range(count)
        )
    scheduled.sort(key=lambda item: (item[0], item[1]))
    events: list[dict[str, Any]] = []
    for ordinal, (offset_ns, credential_class) in enumerate(scheduled):
        account_id = f"e11-account-{ordinal:06d}"
        credential_id = (
            f"valid-for-{account_id}"
            if credential_class == "legitimate"
            else f"distinct-invalid-{ordinal:06d}"
        )
        enrollment_password = f"E11-valid-password:{account_id}"
        attempt_password = (
            enrollment_password
            if credential_class == "legitimate"
            else f"E11-invalid-password:{credential_id}"
        )
        event = {
            "ordinal": ordinal,
            "scheduled_offset_ns": offset_ns,
            "credential_class": credential_class,
            "account_id": account_id,
            "credential_id": credential_id,
            "enrollment_password": enrollment_password,
            "attempt_password": attempt_password,
        }
        event["attempt_id"] = _sha256(
            {
                "manifest_id": manifest_id,
                "seed": contract["seed"],
                **event,
            }
        )
        events.append(event)
    trace: dict[str, Any] = {
        "schema": TRACE_SCHEMA,
        "manifest_id": manifest_id,
        "binding": SHARED_TRACE_BINDING,
        "arrival_unit": contract["arrival_unit"],
        "arrival_mode": contract["arrival_mode"],
        "schedule": contract["schedule"],
        "seed": contract["seed"],
        "duration_seconds": contract["duration_seconds"],
        "event_count": len(events),
        "events": events,
    }
    trace["trace_id"] = _sha256(trace)
    return trace


def _run_git(root: Path, *args: str) -> tuple[int, str, str]:
    try:
        process = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True,
            check=False,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", f"{type(exc).__name__}: {exc}"
    return process.returncode, process.stdout.strip(), process.stderr.strip()


def inspect_upstream(root: Path, expected_revision: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "FAIL",
        "root": str(root.resolve()),
        "expected_revision": expected_revision,
        "observed_revision": None,
        "revision_matches": False,
        "git_status_available": False,
        "git_clean": False,
        "required_sources_present": False,
        "required_binaries_present": False,
        "required_binary_hashes_recorded": False,
        "binary_sha256": {},
        "released_parameter_probe_passed": False,
        "workflow_header_path": None,
        "workflow_header_sha256": None,
        "workflow_handler_threads": None,
        "workflow_worker_contract_passed": False,
    }
    if not root.is_dir():
        return result
    code, stdout, _ = _run_git(root, "rev-parse", "HEAD")
    if code == 0:
        result["observed_revision"] = stdout
        result["revision_matches"] = stdout == expected_revision
    code, stdout, _ = _run_git(root, "status", "--porcelain", "--untracked-files=all")
    if code == 0:
        result["git_status_available"] = True
        result["git_clean"] = stdout == ""

    source_paths = [
        root / "src" / "PreAcher_crypto.cpp",
        root / "src" / "PreAcher.cpp",
        root / "test" / "share" / "static" / "js" / "single_client.js",
        root / "test" / "cdn.cpp",
        root / "test" / "server.cpp",
    ]
    binary_paths = [root / "build" / "test" / "cdn", root / "build" / "test" / "server"]
    result["required_sources_present"] = all(path.is_file() for path in source_paths)
    result["required_binaries_present"] = all(
        path.is_file() and os.access(path, os.X_OK) for path in binary_paths
    )
    if result["required_binaries_present"]:
        try:
            result["binary_sha256"] = {
                str(path.relative_to(root)).replace("\\", "/"): _file_sha256(path)
                for path in binary_paths
            }
        except OSError:
            pass
        else:
            result["required_binary_hashes_recorded"] = True
    if result["required_sources_present"]:
        try:
            crypto = source_paths[0].read_text(encoding="utf-8")
            protocol = source_paths[1].read_text(encoding="utf-8")
            client = source_paths[2].read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            pass
        else:
            probes = (
                re.search(r"hash_len\s*=\s*256\s*;", crypto),
                re.search(r"iterations\s*=\s*10000\s*;", crypto),
                re.search(r"generate_salt\(32\)", protocol),
                re.search(r"KmerMinHash\(5\s*,\s*true\s*,\s*42\)", client),
            )
            result["released_parameter_probe_passed"] = all(probes)

    workflow_candidates = [root / "build" / "runtime" / "WFGlobal.h"]
    if binary_paths[1].is_file():
        try:
            linked = subprocess.run(
                ["ldd", str(binary_paths[1])],
                capture_output=True,
                check=False,
                text=True,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            linked = None
        if linked is not None and linked.returncode == 0:
            match = re.search(r"libworkflow[^ ]*\s+=>\s+(\S+)", linked.stdout)
            if match is not None:
                library_path = Path(match.group(1)).resolve()
                workflow_candidates.append(
                    library_path.parent.parent / "include" / "workflow" / "WFGlobal.h"
                )
    workflow_header = next(
        (candidate for candidate in workflow_candidates if candidate.is_file()),
        None,
    )
    if workflow_header is not None:
        try:
            workflow_source = workflow_header.read_text(encoding="utf-8")
            application_sources = "\n".join(
                path.read_text(encoding="utf-8") for path in source_paths[3:]
            )
        except (OSError, UnicodeError):
            pass
        else:
            handler_match = re.search(r"handler_threads\s*=\s*(\d+)\s*[,;]", workflow_source)
            if handler_match is not None:
                result["workflow_header_path"] = str(workflow_header.resolve())
                result["workflow_header_sha256"] = _file_sha256(workflow_header)
                result["workflow_handler_threads"] = int(handler_match.group(1))
                no_application_override = not re.search(
                    r"WFGlobalSettings|WORKFLOW_library_init", application_sources
                )
                result["workflow_worker_contract_passed"] = (
                    int(handler_match.group(1)) == 20 and no_application_override
                )
    result["status"] = (
        "PASS"
        if all(
            result[field]
            for field in (
                "revision_matches",
                "git_status_available",
                "git_clean",
                "required_sources_present",
                "required_binaries_present",
                "required_binary_hashes_recorded",
                "released_parameter_probe_passed",
                "workflow_worker_contract_passed",
            )
        )
        else "FAIL"
    )
    return result


def build_receipt(
    manifest: Mapping[str, Any],
    manifest_id: str,
    trace: Mapping[str, Any],
    upstream: Mapping[str, Any] | None,
    adapter_results: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    contract = manifest["matched_contract"]
    methods = manifest["methods"]
    upstream_pass = upstream is not None and upstream.get("status") == "PASS"
    matched_load_completed = adapter_results is not None
    adapter_result_bindings: dict[str, dict[str, str]] = {}
    if adapter_results is not None:
        if set(adapter_results) != {UPSTREAM_METHOD, REPOSITORY_METHOD}:
            raise ManifestError("adapter results must contain exactly both E11 methods")
        for method_name, result in adapter_results.items():
            result_id = result.get("result_id")
            if not isinstance(result_id, str) or len(result_id) != 64:
                raise ManifestError(f"{method_name} adapter result has no result ID")
            adapter_result_bindings[method_name] = {
                "result_id": result_id,
                "execution_status": str(result.get("execution_status")),
            }
    harness_files = [
        Path(__file__).resolve(),
        Path(__file__).with_name("preacher_matched_adapters.py").resolve(),
        Path(__file__).with_name("preacher_upstream_adapter.mjs").resolve(),
    ]
    harness_ledger = {
        str(path.relative_to(ROOT)).replace("\\", "/"): _file_sha256(path) for path in harness_files
    }
    baseline_registered = (
        manifest["derived_baseline_binding"]["status"] in DERIVED_BASELINE_REGISTERED_STATUSES
    )
    gates = {
        "released_and_derived_profiles_separate": True,
        "released_profile_is_only_active_profile": True,
        "same_kdf_contract": all(method["kdf"] == contract["kdf"] for method in methods),
        "same_worker_pool": all(method["workers"] == contract["workers"] for method in methods),
        "same_attempt_arrivals": all(
            method["arrival_trace_binding"] == trace["binding"] for method in methods
        ),
        "unique_account_per_attempt": len({event["account_id"] for event in trace["events"]})
        == trace["event_count"],
        "upstream_preflight_passed": upstream_pass,
        "real_system_adapters_implemented": True,
        "matched_load_completed": matched_load_completed,
        "derived_baseline_receipt_registered": baseline_registered,
        "paper_intended_preacher_profile_implemented": False,
    }
    reasons = [] if baseline_registered else [PHASE1_RECEIPT_BLOCKER]
    if baseline_registered:
        reasons.append("FORMAL_E11_WORKLOAD_NOT_RUN_ENGINEERING_SMOKE_ONLY")
    if not matched_load_completed:
        reasons.append("MATCHED_LOAD_NOT_RUN")
    if upstream is None:
        reasons.append("UPSTREAM_PREFLIGHT_NOT_RUN")
    elif not upstream_pass:
        reasons.append("UPSTREAM_PREFLIGHT_FAILED")
    receipt: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "manifest_id": manifest_id,
        "status": NOT_ADJUDICABLE,
        "exit_code": EXIT_NOT_ADJUDICABLE,
        "exit_semantics": {
            "0": "ADJUDICATED_MATCHED_RESULT",
            "2": "VALID_NOT_ADJUDICABLE",
            "3": "INVALID_OR_OPERATIONAL_ERROR",
        },
        "reason_codes": sorted(reasons),
        "active_preacher_profile": manifest["active_preacher_profile"],
        "profile_classes": {
            name: profile["source_class"] for name, profile in manifest["preacher_profiles"].items()
        },
        "matched_contract": {
            "contract_id": _sha256(contract),
            "kdf": dict(contract["kdf"]),
            "workers": dict(contract["workers"]),
            "attempt_trace_id": trace["trace_id"],
            "attempt_count": trace["event_count"],
        },
        "derived_baseline_binding": dict(manifest["derived_baseline_binding"]),
        "adapter_results": adapter_result_bindings,
        "harness_implementation": {
            "files": harness_ledger,
            "ledger_id": _sha256(harness_ledger),
        },
        "gates": gates,
        "upstream_preflight": dict(upstream) if upstream is not None else {"status": "NOT_RUN"},
        "evidence_scope": {
            "engineering_smoke_completed": matched_load_completed,
            "synthetic_credentials_only": True,
            "scientific_claim": False,
            "matched_performance_result": False,
            "e11_adjudicated": False,
        },
        "publication": {
            "receipt_is_commit_marker": True,
            "artifacts_published_before_receipt": True,
            "no_replace": True,
        },
    }
    receipt["receipt_id"] = _sha256(receipt)
    return receipt


def _write_new_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary_path, path)
        if os.name != "nt":
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
    finally:
        temporary_path.unlink(missing_ok=True)


def _ensure_new_targets(paths: list[Path]) -> None:
    resolved = [path.resolve() for path in paths]
    if len(set(resolved)) != len(resolved):
        raise ManifestError("E11 output paths must be distinct")
    existing = [str(path) for path in resolved if path.exists()]
    if existing:
        raise FileExistsError(f"E11 output target already exists: {existing}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = _StrictArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--receipt-output", type=Path)
    parser.add_argument("--trace-output", type=Path)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--run-engineering-smoke", action="store_true")
    parser.add_argument("--upstream-root", type=Path)
    parser.add_argument("--adapter-output-dir", type=Path)
    parser.add_argument(
        "--node-adapter",
        type=Path,
        default=Path(__file__).with_name("preacher_upstream_adapter.mjs"),
    )
    args = parser.parse_args(argv)
    action_count = sum(
        bool(action) for action in (args.validate_only, args.preflight, args.run_engineering_smoke)
    )
    if action_count != 1:
        parser.error(
            "choose exactly one of --validate-only, --preflight, or --run-engineering-smoke"
        )
    if (args.preflight or args.run_engineering_smoke) and args.upstream_root is None:
        parser.error("--preflight and --run-engineering-smoke require --upstream-root")
    if args.validate_only and args.upstream_root is not None:
        parser.error("--upstream-root requires --preflight or --run-engineering-smoke")
    if args.run_engineering_smoke:
        for field in ("receipt_output", "trace_output", "adapter_output_dir"):
            if getattr(args, field) is None:
                parser.error(f"--run-engineering-smoke requires --{field.replace('_', '-')}")
    elif args.adapter_output_dir is not None:
        parser.error("--adapter-output-dir requires --run-engineering-smoke")
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        manifest, manifest_id = load_manifest(args.config)
        trace = build_attempt_trace(manifest, manifest_id)
        upstream = (
            inspect_upstream(args.upstream_root, manifest["source"]["revision"])
            if args.preflight or args.run_engineering_smoke
            else None
        )
        adapter_results = None
        output_bindings: list[tuple[Path, Mapping[str, Any]]] = []
        if args.run_engineering_smoke:
            assert upstream is not None
            if upstream.get("status") != "PASS":
                raise AdapterExecutionError("upstream preflight failed")
            if not args.node_adapter.is_file():
                raise AdapterExecutionError("official-client Node adapter is missing")
            upstream_output = args.adapter_output_dir / f"{UPSTREAM_METHOD}.json"
            repository_output = args.adapter_output_dir / f"{REPOSITORY_METHOD}.json"
            _ensure_new_targets(
                [args.trace_output, upstream_output, repository_output, args.receipt_output]
            )
            upstream_result = run_upstream_adapter(
                manifest,
                manifest_id,
                trace,
                upstream_root=args.upstream_root,
                node_adapter=args.node_adapter,
                upstream_preflight=upstream,
            )
            repository_result = run_repository_adapter(manifest, manifest_id, trace)
            contract_id = _sha256(manifest["matched_contract"])
            adapter_results = {
                UPSTREAM_METHOD: upstream_result,
                REPOSITORY_METHOD: repository_result,
            }
            for method_name, result in adapter_results.items():
                validate_adapter_result(
                    result,
                    expected_method=method_name,
                    manifest_id=manifest_id,
                    contract_id=contract_id,
                    trace=trace,
                    expected_baseline_binding=manifest["derived_baseline_binding"],
                )
            output_bindings = [
                (args.trace_output, trace),
                (upstream_output, upstream_result),
                (repository_output, repository_result),
            ]
        receipt = build_receipt(
            manifest,
            manifest_id,
            trace,
            upstream,
            adapter_results,
        )
        if not args.run_engineering_smoke:
            paths = [path for path in (args.trace_output, args.receipt_output) if path is not None]
            _ensure_new_targets(paths)
            if args.trace_output is not None:
                output_bindings.append((args.trace_output, trace))
        for path, value in output_bindings:
            _write_new_json(path, value)
        if args.receipt_output is not None:
            _write_new_json(args.receipt_output, receipt)
        print(json.dumps(receipt, sort_keys=True, allow_nan=False))
        return EXIT_NOT_ADJUDICABLE
    except (
        AdapterExecutionError,
        KeyError,
        ManifestError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema": ERROR_SCHEMA,
                    "status": "INVALID",
                    "exit_code": EXIT_INVALID,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return EXIT_INVALID


if __name__ == "__main__":
    raise SystemExit(main())
