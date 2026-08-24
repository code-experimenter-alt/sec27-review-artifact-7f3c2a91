#!/usr/bin/env python3
"""Fail-closed G7 loopback TCP, process, and backend-fault evidence harness.

The public ``run`` and ``validate`` commands require an exact clean Git
checkout.  Private child-process commands host a real edge data plane and a
real verifier backend on ephemeral IPv4 loopback TCP sockets.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dataplane import (  # noqa: E402
    AuthDataPlane,
    BackendResultKind,
    Directory,
    DirectoryStatus,
    DirectoryView,
    InMemoryBackend,
    LruPolicy,
    NegativeCache,
    NegativeKeyDeriver,
    PositiveScreen,
    RepresentationSource,
    Singleflight,
    TypedBackendResult,
)

CONFIG_SCHEMA = "traps-g7-service-fault-config-v1"
ARTIFACT_SCHEMA = "traps-g7-service-fault-artifact-v1"
ROW_SCHEMA = "traps-g7-service-fault-row-v1"
EDGE_STATE_SCHEMA = "traps-g7-service-fault-edge-state-v1"
BACKEND_STATE_SCHEMA = "traps-g7-service-fault-backend-state-v1"
EXPERIMENT_ID = "g7-network-process-backend-formal-v1"
EXECUTION_CLASSIFICATION = "FORMAL_SERVICE_FAULT_MATRIX"
EVIDENCE_SCOPE = "LOOPBACK_USERSPACE_PROXY_PROCESS_BACKEND_FAULT_COMPONENT"
G7_STATUS = "BLOCKED_PENDING_E9_AND_INDEPENDENT_FREEZE_AUDIT"
STATUS = "COMPONENT_CHECK_PASS_G7_BLOCKED"
VALIDATION_MODE = "EXACT_CLEAN_SOURCE_AND_FRESH_LOOPBACK_PROCESS_REEXECUTION"
GIT_STATUS_FORMAT = "GIT_STATUS_PORCELAIN_V1_Z_HEX"
HOST = "127.0.0.1"
EDGES = ("edge-a",)
COORDINATES = (
    "core_path_probe",
    "transport_delay",
    "transport_loss",
    "transport_duplicate",
    "transport_reorder",
    "edge_kill_restart_persistence",
    "edge_corrupt_state_fail_open",
    "backend_timeout",
    "backend_drop",
    "backend_malformed",
    "backend_typed_transient_failure",
    "backend_typed_partial_failure",
    "backend_crash_restart",
)
BLOCKERS = (
    "E9_EXTERNAL_FAILURE_ONLY_TIMING_ARTIFACT_NOT_COMPLETE",
    "CONTENT_ADDRESSED_SERVICE_FAULT_ARTIFACT_FREEZE_NOT_COMPLETE",
    "INDEPENDENT_SERVICE_FAULT_ARTIFACT_AUDIT_NOT_COMPLETE",
)
BACKEND_FAULTS = frozenset(
    {
        "normal",
        "timeout",
        "drop",
        "malformed",
        "typed_transient_failure",
        "typed_partial_failure",
        "crash",
    }
)
BACKEND_CRASH_TRANSPORT_TERMINATIONS = frozenset(
    {
        ("EOF", "EOF"),
        ("ConnectionAbortedError", "ERROR"),
        ("ConnectionResetError", "ERROR"),
    }
)
NORMALIZED_BACKEND_CRASH_TERMINATION = "BACKEND_APPLICATION_CRASH_NO_RESPONSE"
UNCERTAIN_BACKEND_KINDS = frozenset(
    {
        BackendResultKind.TRANSIENT_FAILURE.value,
        BackendResultKind.VERSION_MISMATCH.value,
        BackendResultKind.PARTIAL_AUTHENTICATOR_FAILURE.value,
    }
)

FORMAL_CONFIG: dict[str, object] = {
    "schema": CONFIG_SCHEMA,
    "experiment_id": EXPERIMENT_ID,
    "formal": True,
    "execution_enabled": True,
    "execution_classification": EXECUTION_CLASSIFICATION,
    "evidence_scope": EVIDENCE_SCOPE,
    "g7_status": G7_STATUS,
    "blockers": list(BLOCKERS),
    "fault_layer": {
        "transport_proxy_process": "REQUIRED_INDEPENDENT_OS_PROCESS",
        "producer_to_proxy_transport": "IPV4_LOOPBACK_TCP",
        "proxy_to_edge_transport": "IPV4_LOOPBACK_TCP_ONE_CONNECTION_PER_DELIVERY",
        "edge_fault_injection_rpc": "FORBIDDEN",
        "loopback_only": True,
        "kernel_netem": False,
        "production_network_claim": False,
        "claim": "USERSPACE_LOGICAL_DELIVERY_FAULTS_ACROSS_REAL_LOOPBACK_TCP_BOUNDARIES",
    },
    "rpc_accounting": {
        "classification": "RECORDED_CLAIM_BEARING_RPCS_ONLY",
        "included": [
            "coordinator_to_edge_login",
            "coordinator_to_edge_lease_expire",
            "coordinator_to_proxy_produce",
            "coordinator_to_proxy_delay_barrier_wait",
            "coordinator_to_proxy_delay_release",
            "proxy_to_edge_deliver",
            "edge_to_backend_verify_finalize",
        ],
        "excluded_orchestration": [
            "startup_ping",
            "status_poll",
            "set_backend_endpoint",
            "set_edge_endpoint",
        ],
    },
    "random_observations": {
        "classification": ("SESSION_LOCAL_RELATIONAL_EVIDENCE_NOT_CROSS_RUN_SCALAR_EQUALITY"),
        "excluded_from_cross_run_scalar_equality": [
            "pid",
            "ephemeral_port",
            "session_nonce",
            "connection_nonce",
            "exact_elapsed_ns",
            "platform_specific_nonzero_edge_kill_exit_code",
            "platform_specific_backend_crash_failure_category",
            "platform_specific_backend_crash_transport_outcome",
            "derived_session_id",
            "derived_connection_id",
            "exact_request_bytes",
            "exact_response_bytes",
        ],
        "claim_bearing_normalization": [
            "role_ordered_process_alias",
            "session_and_endpoint_relationship_graph",
            "caller_callee_rpc_relationship",
            "connection_outcome_and_payload_presence",
            "elapsed_threshold_class",
            "exit_class",
            "backend_application_crash_exit_code_73",
            "backend_application_crash_no_response_transport_class",
            "delay_barrier_causal_order",
            "complete_component_metrics_and_cache_delta",
        ],
    },
    "edges": list(EDGES),
    "coordinates": list(COORDINATES),
    "credential": {
        "username": "alice",
        "account_id": "account-alice",
        "account_generation": 1,
        "credential_set_version": 1,
        "directory_epoch": 1,
        "salt_hex": "30313233343536373839616263646566",
        "valid_password_hex": "636f72726563742d70617373776f7264",
        "invalid_probe_password_hex": "696e76616c69642d70726f6265",
    },
    "transport": {
        "host": HOST,
        "rpc_timeout_ms": 1000,
        "backend_client_timeout_ms": 80,
        "backend_timeout_server_ms": 240,
        "logical_delay_ms": 120,
        "process_start_timeout_ms": 5000,
        "process_exit_timeout_ms": 5000,
    },
    "negative_cache": {
        "capacity": 16,
        "max_ttl_seconds": 60.0,
        "max_entries_per_account": 8,
        "max_entries_per_region": 16,
    },
    "singleflight": {
        "max_waiters_per_key": 8,
        "max_waiters_global": 32,
        "waiter_timeout_seconds": 1.0,
    },
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _identity(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _session_id(role: str, pid: int, nonce_hex: str) -> str:
    return _identity(
        {
            "domain": "TRAPS/G7/SERVICE-FAULT/PROCESS-SESSION/v1",
            "role": role,
            "pid": pid,
            "nonce_hex": nonce_hex,
        }
    )


def _connection_id(transport: Mapping[str, object]) -> str:
    return _identity(
        {
            "domain": "TRAPS/G7/SERVICE-FAULT/TCP-CONNECTION/v1",
            "connection_nonce_hex": transport["connection_nonce_hex"],
            "protocol": transport["protocol"],
            "family": transport["family"],
            "server_host": transport["server_host"],
            "server_port": transport["server_port"],
            "client_host": transport["client_host"],
            "client_port": transport["client_port"],
        }
    )


def _delay_barrier_id(proxy_session_id: str, message_id: str, sequence: int) -> str:
    return _identity(
        {
            "domain": "TRAPS/G7/SERVICE-FAULT/DELAY-BARRIER/v1",
            "proxy_session_id": proxy_session_id,
            "message_id": message_id,
            "sequence": sequence,
        }
    )


def _login_completion_id(login: Mapping[str, object]) -> str:
    return _identity(
        {
            "domain": "TRAPS/G7/SERVICE-FAULT/LOGIN-COMPLETION/v1",
            "login": login,
        }
    )


def _seal_transport(
    transport: dict[str, object], started_ns: int, *, elapsed_class: str | None = None
) -> None:
    transport["elapsed_ns"] = max(1, time.monotonic_ns() - started_ns)
    if elapsed_class is not None:
        transport["elapsed_class"] = elapsed_class
    transport["connection_id"] = _connection_id(transport)


def _bind_transport(
    transport: Mapping[str, object],
    *,
    caller_role: str,
    caller_pid: int,
    caller_session_id: str,
    callee_role: str,
    callee_pid: int,
    callee_session_id: str,
) -> dict[str, object]:
    value = dict(transport)
    value.update(
        {
            "caller_role": caller_role,
            "caller_pid": caller_pid,
            "caller_session_id": caller_session_id,
            "caller_endpoint": f"{value['client_host']}:{value['client_port']}",
            "callee_role": callee_role,
            "callee_pid": callee_pid,
            "callee_session_id": callee_session_id,
            "callee_endpoint": f"{value['server_host']}:{value['server_port']}",
        }
    )
    return value


def _frozen_factory(value: Mapping[str, object]):
    canonical = _canonical_json(value)

    def fresh() -> dict[str, object]:
        loaded = json.loads(canonical)
        assert isinstance(loaded, dict)
        return loaded

    return fresh


_formal_config_spec = _frozen_factory(FORMAL_CONFIG)
_artifact_policy_spec = _frozen_factory(
    {
        "artifact_schema": ARTIFACT_SCHEMA,
        "row_schema": ROW_SCHEMA,
        "experiment_id": EXPERIMENT_ID,
        "execution_classification": EXECUTION_CLASSIFICATION,
        "evidence_scope": EVIDENCE_SCOPE,
        "g7_claim_eligible": False,
        "g7_status": G7_STATUS,
        "blockers": list(BLOCKERS),
        "validation_mode": VALIDATION_MODE,
        "fault_layer": FORMAL_CONFIG["fault_layer"],
        "rpc_accounting": FORMAL_CONFIG["rpc_accounting"],
        "random_observations": FORMAL_CONFIG["random_observations"],
        "unfrozen_artifact_integrity_boundary": (
            "RAW_VALUES_NOT_TAMPER_EVIDENT_UNTIL_CONTENT_ADDRESSED_FREEZE_AND_INDEPENDENT_AUDIT"
        ),
        "status": STATUS,
    }
)


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML mapping key {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class _DuplicateJsonKeyError(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is forbidden")


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError(f"{label} must be a string-keyed object")
    return value


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing or extra:
        raise ValueError(
            f"{label} fields mismatch: missing={sorted(missing)}, extra={sorted(extra)}"
        )


def _exact_value(actual: object, expected: object, label: str) -> None:
    if type(actual) is not type(expected):
        raise ValueError(f"{label} has the wrong exact type")
    if isinstance(expected, dict):
        assert isinstance(actual, dict)
        _exact_keys(actual, set(expected), label)
        for key, expected_item in expected.items():
            _exact_value(actual[key], expected_item, f"{label}.{key}")
    elif isinstance(expected, list):
        assert isinstance(actual, list)
        if len(actual) != len(expected):
            raise ValueError(f"{label} has the wrong list length")
        for index, (actual_item, expected_item) in enumerate(zip(actual, expected, strict=True)):
            _exact_value(actual_item, expected_item, f"{label}[{index}]")
    elif actual != expected:
        raise ValueError(f"{label} does not match the frozen value")


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _strict_hex(value: object, label: str, length: int | None = None) -> str:
    if type(value) is not str or (length is not None and len(value) != length):
        raise ValueError(f"{label} must be canonical lowercase hexadecimal")
    if any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be canonical lowercase hexadecimal")
    return value


def _load_json_text(payload: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, _DuplicateJsonKeyError) as error:
        raise ValueError(f"{label} JSON is malformed: {error}") from error
    return _mapping(value, label)


def load_json_object(path: Path) -> dict[str, Any]:
    return _load_json_text(path.read_text(encoding="utf-8"), "service-fault artifact")


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    try:
        loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise ValueError(f"service-fault config YAML is malformed: {error}") from error
    config = _mapping(loaded, "service-fault config")
    expected = _formal_config_spec()
    _exact_value(config, expected, "service-fault config")
    if config["execution_enabled"] is not True:
        raise RuntimeError("formal service-fault execution is disabled")
    return config, _identity(expected)


def _validate_porcelain_v1_z(payload: bytes, label: str) -> None:
    if not payload:
        return
    if not payload.endswith(b"\0"):
        raise ValueError(f"{label} must be NUL terminated")
    records = payload[:-1].split(b"\0")
    index = 0
    valid_status = b" MTADRCU?!"
    while index < len(records):
        record = records[index]
        if len(record) < 4 or record[2:3] != b" ":
            raise ValueError(f"{label} has invalid canonical shape")
        first, second = record[0], record[1]
        if first not in valid_status or second not in valid_status:
            raise ValueError(f"{label} has invalid status code")
        if first == ord(" ") and second == ord(" "):
            raise ValueError(f"{label} contains an empty status code")
        if not record[3:]:
            raise ValueError(f"{label} has an empty path")
        if first in b"RC" or second in b"RC":
            index += 1
            if index >= len(records) or not records[index]:
                raise ValueError(f"{label} rename/copy record lacks its second path")
        index += 1


def _validate_git_state(state: object, label: str) -> dict[str, Any]:
    value = _mapping(state, label)
    _exact_keys(value, {"commit", "clean", "status"}, label)
    _strict_hex(value["commit"], f"{label}.commit", 40)
    if type(value["clean"]) is not bool:
        raise ValueError(f"{label}.clean must be Boolean")
    status = _mapping(value["status"], f"{label}.status")
    _exact_keys(status, {"format", "payload_hex"}, f"{label}.status")
    if status["format"] != GIT_STATUS_FORMAT:
        raise ValueError(f"{label}.status format mismatch")
    payload_hex = status["payload_hex"]
    if type(payload_hex) is not str or len(payload_hex) % 2:
        raise ValueError(f"{label}.status payload must be even-length lowercase hex")
    _strict_hex(payload_hex, f"{label}.status.payload_hex")
    payload = bytes.fromhex(payload_hex)
    _validate_porcelain_v1_z(payload, f"{label}.status")
    if value["clean"] is not (payload == b""):
        raise ValueError(f"{label}.clean must be true iff status is empty")
    return value


def _git_state() -> dict[str, object]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=normal"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    return {
        "commit": commit,
        "clean": status == b"",
        "status": {"format": GIT_STATUS_FORMAT, "payload_hex": status.hex()},
    }


def _require_clean_source(expected_commit: str) -> dict[str, Any]:
    _strict_hex(expected_commit, "expected commit", 40)
    state = _validate_git_state(_git_state(), "current Git state")
    if state["commit"] != expected_commit or state["clean"] is not True:
        raise RuntimeError("service-fault evidence requires the exact clean expected commit")
    return state


def _write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = _canonical_json(value) + "\n"
    with temporary.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _write_json_exclusive(path: Path, value: object) -> None:
    resolved = path.resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise ValueError("service-fault output must be outside the source checkout")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (_canonical_json(value) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _credential(config: Mapping[str, object]) -> dict[str, Any]:
    return _mapping(config["credential"], "credential config")


def _transport(config: Mapping[str, object]) -> dict[str, Any]:
    return _mapping(config["transport"], "transport config")


_POSITIVE_KEY = hashlib.sha256(b"g7-service-fault-positive-key").digest()
_CERTIFICATE_KEY = hashlib.sha256(b"g7-service-fault-certificate-key").digest()


def _view_from_config(config: Mapping[str, object]) -> DirectoryView:
    credential = _credential(config)
    username = str(credential["username"])
    return DirectoryView(
        username=username,
        status=DirectoryStatus.PRESENT,
        canonical_username=username,
        account_id=str(credential["account_id"]),
        account_generation=int(credential["account_generation"]),
        credential_set_version=int(credential["credential_set_version"]),
        salt=bytes.fromhex(str(credential["salt_hex"])),
        encoding_version=1,
        retry_class="default",
        active_authenticator_ids=frozenset({"password"}),
        directory_epoch=int(credential["directory_epoch"]),
    )


def _represented_token_digest(config: Mapping[str, object]) -> str:
    credential = _credential(config)
    view = _view_from_config(config)
    screen = PositiveScreen(_POSITIVE_KEY, _CERTIFICATE_KEY, region_count=4)
    tokens = sorted(
        screen.credential_token(view, bytes.fromhex(str(credential[field]))).hex()
        for field in ("valid_password_hex", "invalid_probe_password_hex")
    )
    return _identity(tokens)


def _state_body(
    config: Mapping[str, object], *, ready: bool, last_sequence: int
) -> dict[str, object]:
    credential = _credential(config)
    return {
        "schema": EDGE_STATE_SCHEMA,
        "edge_id": EDGES[0],
        "username": credential["username"],
        "account_id": credential["account_id"],
        "account_generation": credential["account_generation"],
        "credential_set_version": credential["credential_set_version"],
        "directory_epoch": credential["directory_epoch"],
        "represented_token_digest": _represented_token_digest(config),
        "negative_cache_recovery_policy": "CLEAR_UNTRUSTED_VOLATILE_CACHE_ON_START",
        "ready": ready,
        "last_sequence": last_sequence,
    }


def _edge_state(
    config: Mapping[str, object], *, ready: bool, last_sequence: int
) -> dict[str, object]:
    body = _state_body(config, ready=ready, last_sequence=last_sequence)
    return {**body, "state_id": _identity(body)}


def _backend_state(config: Mapping[str, object]) -> dict[str, object]:
    credential = _credential(config)
    body = {
        "schema": BACKEND_STATE_SCHEMA,
        "username": credential["username"],
        "account_id": credential["account_id"],
        "account_generation": credential["account_generation"],
        "credential_set_version": credential["credential_set_version"],
        "salt_hex": credential["salt_hex"],
        "valid_password_hex": credential["valid_password_hex"],
    }
    return {**body, "state_id": _identity(body)}


def _load_edge_state(path: Path, config: Mapping[str, object]) -> tuple[dict[str, Any], bool, str]:
    fallback = _edge_state(config, ready=False, last_sequence=0)
    try:
        loaded = _load_json_text(path.read_text(encoding="utf-8"), "edge state")
        _exact_keys(loaded, set(fallback), "edge state")
        state_id = loaded.pop("state_id")
        expected_body = _state_body(
            config,
            ready=loaded.get("ready") if type(loaded.get("ready")) is bool else False,
            last_sequence=(
                loaded.get("last_sequence")
                if isinstance(loaded.get("last_sequence"), int)
                and not isinstance(loaded.get("last_sequence"), bool)
                else -1
            ),
        )
        _exact_value(loaded, expected_body, "edge state body")
        if state_id != _identity(expected_body):
            raise ValueError("edge state identity mismatch")
        return {**loaded, "state_id": state_id}, True, "trusted_persistent_state"
    except (OSError, UnicodeError, ValueError, TypeError):
        return fallback, False, "corrupt_or_missing_state_fail_open"


def _load_backend_state(path: Path, config: Mapping[str, object]) -> dict[str, Any]:
    loaded = _load_json_text(path.read_text(encoding="utf-8"), "backend state")
    expected = _backend_state(config)
    _exact_value(loaded, expected, "backend state")
    return loaded


def _typed_result_to_json(result: TypedBackendResult) -> dict[str, object]:
    return {
        "kind": result.kind.value,
        "expected_version": result.expected_version,
        "checked_version": result.checked_version,
        "checked_account_id": result.checked_account_id,
        "checked_account_generation": result.checked_account_generation,
        "checked_authenticator_ids": sorted(result.checked_authenticator_ids),
        "matched_authenticator_id": result.matched_authenticator_id,
        "authenticated_internal_result": result.authenticated_internal_result,
        "detail": result.detail,
    }


def _typed_result_from_json(value: object) -> TypedBackendResult:
    item = _mapping(value, "typed backend result")
    _exact_keys(
        item,
        {
            "kind",
            "expected_version",
            "checked_version",
            "checked_account_id",
            "checked_account_generation",
            "checked_authenticator_ids",
            "matched_authenticator_id",
            "authenticated_internal_result",
            "detail",
        },
        "typed backend result",
    )
    try:
        kind = BackendResultKind(item["kind"])
    except (TypeError, ValueError) as error:
        raise ValueError("typed backend result kind is invalid") from error
    optional_integers = (
        item["expected_version"],
        item["checked_version"],
        item["checked_account_generation"],
    )
    if any(
        value is not None and (isinstance(value, bool) or not isinstance(value, int))
        for value in optional_integers
    ):
        raise ValueError("typed backend result version fields are invalid")
    if item["checked_account_id"] is not None and type(item["checked_account_id"]) is not str:
        raise ValueError("typed backend account ID is invalid")
    checked_ids = item["checked_authenticator_ids"]
    if type(checked_ids) is not list or any(type(value) is not str for value in checked_ids):
        raise ValueError("typed backend checked authenticator IDs are invalid")
    if checked_ids != sorted(set(checked_ids)):
        raise ValueError("typed backend checked authenticator IDs are not canonical")
    if (
        item["matched_authenticator_id"] is not None
        and type(item["matched_authenticator_id"]) is not str
    ):
        raise ValueError("typed backend matched authenticator ID is invalid")
    if type(item["authenticated_internal_result"]) is not bool or type(item["detail"]) is not str:
        raise ValueError("typed backend result metadata is invalid")
    return TypedBackendResult(
        kind=kind,
        expected_version=item["expected_version"],
        checked_version=item["checked_version"],
        checked_account_id=item["checked_account_id"],
        checked_account_generation=item["checked_account_generation"],
        checked_authenticator_ids=frozenset(checked_ids),
        matched_authenticator_id=item["matched_authenticator_id"],
        authenticated_internal_result=item["authenticated_internal_result"],
        detail=item["detail"],
    )


class _LoopbackServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _JsonLineHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        payload = self.rfile.readline(1_048_577)
        if not payload or len(payload) > 1_048_576 or not payload.endswith(b"\n"):
            return
        try:
            request = _load_json_text(payload.decode("utf-8"), "RPC request")
            response = self.server.dispatch(request)  # type: ignore[attr-defined]
            if response is None:
                return
            if isinstance(response, bytes):
                wire = response
            else:
                wire = (_canonical_json(response) + "\n").encode("utf-8")
            self.wfile.write(wire)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, UnicodeError, ValueError):
            return


class _BackendApplication:
    def __init__(self, config: Mapping[str, object], state_path: Path) -> None:
        self.session_nonce_hex = ""
        self.session_id = ""
        self.endpoint = (HOST, 0)
        state = _load_backend_state(state_path, config)
        self.config = config
        self.backend = InMemoryBackend()
        username = str(state["username"])
        account_id = str(state["account_id"])
        generation = int(state["account_generation"])
        version = int(state["credential_set_version"])
        salt = bytes.fromhex(str(state["salt_hex"]))
        password = bytes.fromhex(str(state["valid_password_hex"]))
        self.backend.prepare_version(
            username,
            account_id,
            generation,
            version,
            salt,
            1,
            {"password": password},
        )
        self.backend.activate_version(username, account_id, generation, version)
        self.backend.commit_directory_version(username, account_id, generation, version)

    def bind_process(
        self,
        session_nonce_hex: str,
        session_id: str,
        endpoint: tuple[str, int],
    ) -> None:
        self.session_nonce_hex = session_nonce_hex
        self.session_id = session_id
        self.endpoint = endpoint

    def _process_identity(self) -> dict[str, object]:
        return {
            "pid": os.getpid(),
            "session_id": self.session_id,
            "endpoint": f"{self.endpoint[0]}:{self.endpoint[1]}",
        }

    def dispatch(self, request: dict[str, Any]) -> object:
        op = request.get("op")
        if op == "ping":
            _exact_keys(request, {"op"}, "backend ping request")
            return {"ok": True, "role": "backend", **self._process_identity()}
        if op == "verify":
            _exact_keys(
                request,
                {"op", "username", "password_hex", "expected_version", "fault"},
                "backend verify request",
            )
            fault = request["fault"]
            if fault not in BACKEND_FAULTS:
                raise ValueError("unknown backend fault")
            expected = request["expected_version"]
            if expected is not None:
                _integer(expected, "expected version", 1)
            username = request["username"]
            if type(username) is not str or not username:
                raise ValueError("backend username is invalid")
            password = bytes.fromhex(_strict_hex(request["password_hex"], "password"))
            if fault == "crash":
                os._exit(73)
            if fault == "drop":
                return None
            if fault == "malformed":
                return b'{"malformed":\n'
            if fault == "timeout":
                delay = _integer(
                    _transport(self.config)["backend_timeout_server_ms"],
                    "backend timeout server milliseconds",
                    1,
                )
                time.sleep(delay / 1000.0)
            if fault == "typed_transient_failure":
                self.backend.inject_once(username, BackendResultKind.TRANSIENT_FAILURE)
            elif fault == "typed_partial_failure":
                self.backend.inject_once(username, BackendResultKind.PARTIAL_AUTHENTICATOR_FAILURE)
            result = self.backend.verify(username, password, expected_version=expected)
            return {
                "ok": True,
                **self._process_identity(),
                "result": _typed_result_to_json(result),
            }
        if op == "finalize":
            _exact_keys(request, {"op", "username", "comparison"}, "backend finalize request")
            username = request["username"]
            if type(username) is not str or not username:
                raise ValueError("backend finalize username is invalid")
            comparison = _typed_result_from_json(request["comparison"])
            result = self.backend.finalize_match(username, comparison)
            return {
                "ok": True,
                **self._process_identity(),
                "result": _typed_result_to_json(result),
            }
        raise ValueError("unknown backend RPC operation")


class _RpcFailure(RuntimeError):
    def __init__(self, category: str, transport: Mapping[str, object]) -> None:
        super().__init__(f"loopback RPC failed: {category}")
        self.category = category
        self.transport = dict(transport)


def _rpc(
    endpoint: tuple[str, int], request: Mapping[str, object], timeout_seconds: float
) -> tuple[dict[str, Any], dict[str, object]]:
    wire = (_canonical_json(request) + "\n").encode("utf-8")
    started = time.monotonic_ns()
    connection_nonce_hex = secrets.token_hex(32)
    transport: dict[str, object] = {
        "protocol": "TCP",
        "family": "AF_INET",
        "server_host": endpoint[0],
        "server_port": endpoint[1],
        "client_host": HOST,
        "client_port": 0,
        "request_bytes": len(wire),
        "response_bytes": 0,
        "request_present": True,
        "response_present": False,
        "elapsed_ns": 0,
        "elapsed_class": "NONZERO_NOT_LATENCY_CLAIM",
        "outcome": "PENDING",
        "connection_nonce_hex": connection_nonce_hex,
        "connection_id": "0" * 64,
        "ephemeral_observation_classification": ("RAW_SESSION_LOCAL_NOT_CROSS_RUN_SCALAR_EQUALITY"),
    }
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout_seconds)
    try:
        sock.connect(endpoint)
        local = sock.getsockname()
        peer = sock.getpeername()
        if local[0] != HOST or peer != endpoint:
            raise RuntimeError("RPC escaped the frozen IPv4 loopback endpoint")
        transport["client_host"] = local[0]
        transport["client_port"] = local[1]
        sock.sendall(wire)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > 1_048_576:
                raise ValueError("RPC response exceeds one MiB")
            if b"\n" in chunk:
                break
        response_wire = b"".join(chunks)
        transport["response_bytes"] = len(response_wire)
        transport["response_present"] = bool(response_wire)
        if not response_wire:
            raise EOFError("RPC peer closed without a response")
        if not response_wire.endswith(b"\n") or response_wire.count(b"\n") != 1:
            raise ValueError("RPC response is not one canonical JSON line")
        response = _load_json_text(response_wire.decode("utf-8"), "RPC response")
        transport["outcome"] = "RESPONSE"
        _seal_transport(transport, started)
        return response, transport
    except socket.timeout as error:
        transport["outcome"] = "TIMEOUT"
        _seal_transport(transport, started)
        raise _RpcFailure("TIMEOUT", transport) from error
    except EOFError as error:
        transport["outcome"] = "EOF"
        _seal_transport(transport, started)
        raise _RpcFailure("EOF", transport) from error
    except (OSError, UnicodeError, ValueError, _DuplicateJsonKeyError) as error:
        transport["outcome"] = "ERROR"
        _seal_transport(transport, started)
        raise _RpcFailure(type(error).__name__, transport) from error
    finally:
        sock.close()


class _RemoteBackend:
    def __init__(
        self,
        endpoint: tuple[str, int],
        backend_pid: int,
        backend_session_id: str,
        timeout_seconds: float,
    ) -> None:
        self.endpoint = endpoint
        self.backend_pid = backend_pid
        self.backend_session_id = backend_session_id
        self.timeout_seconds = timeout_seconds
        self.caller_pid = os.getpid()
        self.caller_session_id = ""
        self.next_fault = "normal"
        self._interactions: list[dict[str, object]] = []
        self._lock = threading.RLock()

    def bind_caller(self, caller_session_id: str) -> None:
        _strict_hex(caller_session_id, "edge caller session", 64)
        with self._lock:
            self.caller_session_id = caller_session_id

    def set_endpoint(
        self,
        endpoint: tuple[str, int],
        backend_pid: int,
        backend_session_id: str,
    ) -> None:
        _integer(backend_pid, "backend PID", 1)
        _strict_hex(backend_session_id, "backend session", 64)
        with self._lock:
            self.endpoint = endpoint
            self.backend_pid = backend_pid
            self.backend_session_id = backend_session_id

    def begin_observation(self, fault: str) -> None:
        if fault not in BACKEND_FAULTS:
            raise ValueError("unknown backend fault")
        with self._lock:
            self.next_fault = fault
            self._interactions = []

    def interactions(self) -> list[dict[str, object]]:
        with self._lock:
            return [dict(item) for item in self._interactions]

    def _identity_snapshot(
        self,
    ) -> tuple[tuple[str, int], int, str, int, str]:
        with self._lock:
            if not self.caller_session_id:
                raise RuntimeError("edge process session is not bound")
            return (
                self.endpoint,
                self.backend_pid,
                self.backend_session_id,
                self.caller_pid,
                self.caller_session_id,
            )

    def _bound_transport(
        self,
        transport: Mapping[str, object],
        snapshot: tuple[tuple[str, int], int, str, int, str],
    ) -> dict[str, object]:
        _, backend_pid, backend_session_id, caller_pid, caller_session_id = snapshot
        return _bind_transport(
            transport,
            caller_role="edge",
            caller_pid=caller_pid,
            caller_session_id=caller_session_id,
            callee_role="backend",
            callee_pid=backend_pid,
            callee_session_id=backend_session_id,
        )

    @staticmethod
    def _validate_response_identity(
        response: Mapping[str, object],
        snapshot: tuple[tuple[str, int], int, str, int, str],
        label: str,
    ) -> None:
        endpoint, backend_pid, backend_session_id, _, _ = snapshot
        if (
            response["pid"] != backend_pid
            or response["session_id"] != backend_session_id
            or response["endpoint"] != f"{endpoint[0]}:{endpoint[1]}"
        ):
            raise ValueError(f"{label} process identity mismatch")

    def _record(
        self,
        *,
        operation: str,
        fault: str,
        completed_response: bool,
        failure_category: str | None,
        result_kind: str,
        identity_source: str,
        snapshot: tuple[tuple[str, int], int, str, int, str],
        transport: Mapping[str, object],
    ) -> None:
        endpoint, backend_pid, backend_session_id, _, _ = snapshot
        with self._lock:
            self._interactions.append(
                {
                    "operation": operation,
                    "fault": fault,
                    "completed_response": completed_response,
                    "failure_category": failure_category,
                    "result_kind": result_kind,
                    "backend_pid": backend_pid,
                    "backend_session_id": backend_session_id,
                    "backend_endpoint": f"{endpoint[0]}:{endpoint[1]}",
                    "backend_identity_source": identity_source,
                    "transport": dict(transport),
                }
            )

    def verify(
        self,
        username: str,
        password: bytes,
        expected_version: int | None,
    ) -> TypedBackendResult:
        with self._lock:
            fault = self.next_fault
            self.next_fault = "normal"
        snapshot = self._identity_snapshot()
        endpoint = snapshot[0]
        request = {
            "op": "verify",
            "username": username,
            "password_hex": bytes(password).hex(),
            "expected_version": expected_version,
            "fault": fault,
        }
        bound_transport: dict[str, object] | None = None
        try:
            response, raw_transport = _rpc(endpoint, request, self.timeout_seconds)
            bound_transport = self._bound_transport(raw_transport, snapshot)
            _exact_keys(
                response,
                {"ok", "pid", "session_id", "endpoint", "result"},
                "backend verify response",
            )
            if response["ok"] is not True:
                raise ValueError("backend verify response is not successful")
            self._validate_response_identity(response, snapshot, "backend verify response")
            result = _typed_result_from_json(response["result"])
            self._record(
                operation="verify",
                fault=fault,
                completed_response=True,
                failure_category=None,
                result_kind=result.kind.value,
                identity_source="RESPONSE_CROSS_CHECKED",
                snapshot=snapshot,
                transport=bound_transport,
            )
            return result
        except (_RpcFailure, ValueError, TypeError) as error:
            if isinstance(error, _RpcFailure):
                raw_transport = error.transport
                if fault == "timeout":
                    raw_transport["elapsed_class"] = "CONFIGURED_BACKEND_TIMEOUT_WINDOW"
                bound_transport = self._bound_transport(raw_transport, snapshot)
                category = error.category
            else:
                if bound_transport is None:
                    raise RuntimeError("backend response validation lacked TCP evidence") from error
                category = type(error).__name__
            result = TypedBackendResult.transient_failure(
                expected_version,
                f"external backend RPC {category}",
            )
            self._record(
                operation="verify",
                fault=fault,
                completed_response=False,
                failure_category=category,
                result_kind=result.kind.value,
                identity_source="READY_REGISTRY_EXPECTED_NO_VALID_RESPONSE",
                snapshot=snapshot,
                transport=bound_transport,
            )
            return result

    def finalize_match(
        self,
        username: str,
        comparison_result: TypedBackendResult,
    ) -> TypedBackendResult:
        if comparison_result.kind is not BackendResultKind.MATCH:
            return comparison_result
        snapshot = self._identity_snapshot()
        endpoint = snapshot[0]
        request = {
            "op": "finalize",
            "username": username,
            "comparison": _typed_result_to_json(comparison_result),
        }
        bound_transport: dict[str, object] | None = None
        try:
            response, raw_transport = _rpc(endpoint, request, self.timeout_seconds)
            bound_transport = self._bound_transport(raw_transport, snapshot)
            _exact_keys(
                response,
                {"ok", "pid", "session_id", "endpoint", "result"},
                "backend finalize response",
            )
            if response["ok"] is not True:
                raise ValueError("backend finalize response is not successful")
            self._validate_response_identity(response, snapshot, "backend finalize response")
            result = _typed_result_from_json(response["result"])
            self._record(
                operation="finalize",
                fault="normal",
                completed_response=True,
                failure_category=None,
                result_kind=result.kind.value,
                identity_source="RESPONSE_CROSS_CHECKED",
                snapshot=snapshot,
                transport=bound_transport,
            )
            return result
        except (_RpcFailure, ValueError, TypeError) as error:
            if isinstance(error, _RpcFailure):
                bound_transport = self._bound_transport(error.transport, snapshot)
                category = error.category
            else:
                if bound_transport is None:
                    raise RuntimeError("backend finalize validation lacked TCP evidence") from error
                category = type(error).__name__
            result = TypedBackendResult.transient_failure(
                comparison_result.expected_version,
                f"external backend finalize RPC {category}",
            )
            self._record(
                operation="finalize",
                fault="normal",
                completed_response=False,
                failure_category=category,
                result_kind=result.kind.value,
                identity_source="READY_REGISTRY_EXPECTED_NO_VALID_RESPONSE",
                snapshot=snapshot,
                transport=bound_transport,
            )
            return result


class _EdgeApplication:
    def __init__(
        self,
        config: Mapping[str, object],
        state_path: Path,
        backend_endpoint: tuple[str, int],
        backend_pid: int,
        backend_session_id: str,
    ) -> None:
        self.session_nonce_hex = ""
        self.session_id = ""
        self.endpoint = (HOST, 0)
        self.config = config
        self.state_path = state_path
        self.state, self.state_trusted, self.recovery_mode = _load_edge_state(state_path, config)
        self._lock = threading.RLock()
        credential = _credential(config)
        username = str(credential["username"])
        view = _view_from_config(config)
        self.view = view
        self.directory = Directory()
        self.directory.publish_active(view)
        self.positive_screen = PositiveScreen(_POSITIVE_KEY, _CERTIFICATE_KEY, region_count=4)
        authenticators = {
            "password": bytes.fromhex(str(credential["valid_password_hex"])),
            "invalid-probe": bytes.fromhex(str(credential["invalid_probe_password_hex"])),
        }
        tokens = [
            self.positive_screen.credential_token(view, password)
            for password in authenticators.values()
        ]
        self.positive_screen.publish_delta(view, tokens)
        self.positive_screen.compact(view)
        self.positive_screen.retire_delta(view)
        self.positive_screen.issue_certificate(EDGES[0], view, RepresentationSource.COMPACTED_BASE)
        if self.state_trusted and self.state["ready"] is True:
            self.directory.replicate_to_edge(EDGES[0], username)
            self.directory.recover_edge(EDGES[0])
        else:
            self.directory.mark_edge_uncertain(EDGES[0])
        cache_config = _mapping(config["negative_cache"], "negative cache config")
        self.negative_cache = NegativeCache(
            capacity=int(cache_config["capacity"]),
            policy=LruPolicy(),
            max_ttl_seconds=float(cache_config["max_ttl_seconds"]),
            max_entries_per_account=int(cache_config["max_entries_per_account"]),
            max_entries_per_region=int(cache_config["max_entries_per_region"]),
        )
        flight_config = _mapping(config["singleflight"], "singleflight config")
        self.singleflight = Singleflight(
            max_waiters_per_key=int(flight_config["max_waiters_per_key"]),
            max_waiters_global=int(flight_config["max_waiters_global"]),
            waiter_timeout_seconds=float(flight_config["waiter_timeout_seconds"]),
        )
        timeout = int(_transport(config)["backend_client_timeout_ms"]) / 1000.0
        self.remote_backend = _RemoteBackend(
            backend_endpoint,
            backend_pid,
            backend_session_id,
            timeout,
        )
        self.data_plane = AuthDataPlane(
            self.directory,
            self.positive_screen,
            NegativeKeyDeriver(hashlib.sha256(b"g7-service-fault-negative-key").digest()),
            self.negative_cache,
            self.singleflight,
            self.remote_backend,  # type: ignore[arg-type]
            negative_ttl_seconds=float(cache_config["max_ttl_seconds"]),
        )

    def bind_process(
        self,
        session_nonce_hex: str,
        session_id: str,
        endpoint: tuple[str, int],
    ) -> None:
        self.session_nonce_hex = session_nonce_hex
        self.session_id = session_id
        self.endpoint = endpoint
        self.remote_backend.bind_caller(session_id)

    def _process_identity(self) -> dict[str, object]:
        return {
            "pid": os.getpid(),
            "session_id": self.session_id,
            "endpoint": f"{self.endpoint[0]}:{self.endpoint[1]}",
        }

    def _persist(self) -> None:
        ready = self.state["ready"]
        last_sequence = self.state["last_sequence"]
        assert type(ready) is bool and isinstance(last_sequence, int)
        self.state = _edge_state(
            self.config,
            ready=ready,
            last_sequence=last_sequence,
        )
        _write_json_atomic(self.state_path, self.state)
        self.state_trusted = True

    def _mark_uncertain(self) -> None:
        with self._lock:
            self.directory.mark_edge_uncertain(EDGES[0])
            self.state["ready"] = False
            self._persist()

    def _apply_message(self, message: Mapping[str, object]) -> str:
        _exact_keys(message, {"message_id", "sequence", "kind"}, "transport message")
        message_id = message["message_id"]
        if type(message_id) is not str or not message_id:
            raise ValueError("transport message ID is invalid")
        sequence = _integer(message["sequence"], "transport sequence", 1)
        if message["kind"] != "RECOVER_READY":
            raise ValueError("transport message kind is invalid")
        with self._lock:
            last_sequence = int(self.state["last_sequence"])
            if sequence == last_sequence:
                return "DUPLICATE"
            if sequence < last_sequence:
                return "STALE"
            self.state["last_sequence"] = sequence
            self.state["ready"] = True
            self.directory.replicate_to_edge(EDGES[0], str(_credential(self.config)["username"]))
            self.directory.recover_edge(EDGES[0])
            self._persist()
            self.recovery_mode = "transport_recovered"
            return "APPLIED"

    def _status(self) -> dict[str, object]:
        with self._lock:
            return {
                "ok": True,
                **self._process_identity(),
                "role": "edge",
                "edge_id": EDGES[0],
                "state_trusted": self.state_trusted,
                "state_id": self.state["state_id"],
                "ready": self.state["ready"],
                "last_sequence": self.state["last_sequence"],
                "recovery_mode": self.recovery_mode,
                "components": [
                    "AuthDataPlane",
                    "Directory",
                    "PositiveScreen",
                    "NegativeCache",
                    "Singleflight",
                ],
                "metrics": {
                    "data_plane": self.data_plane.metrics_snapshot(),
                    "positive_screen": self.positive_screen.metrics_snapshot(),
                    "negative_cache": self.negative_cache.metrics_snapshot(),
                    "singleflight": self.singleflight.metrics_snapshot(),
                },
            }

    def dispatch(self, request: dict[str, Any]) -> object:
        op = request.get("op")
        if op in {"ping", "status"}:
            _exact_keys(request, {"op"}, "edge status request")
            return self._status()
        if op == "set_backend":
            _exact_keys(
                request,
                {"op", "host", "port", "pid", "session_id"},
                "edge backend update",
            )
            if request["host"] != HOST:
                raise ValueError("backend update must remain on IPv4 loopback")
            port = _integer(request["port"], "backend port", 1)
            if port > 65535:
                raise ValueError("backend port is invalid")
            backend_pid = _integer(request["pid"], "backend PID", 1)
            backend_session_id = _strict_hex(request["session_id"], "backend session", 64)
            self.remote_backend.set_endpoint((HOST, port), backend_pid, backend_session_id)
            return {
                "ok": True,
                **self._process_identity(),
                "backend_endpoint": f"{HOST}:{port}",
                "backend_pid": backend_pid,
                "backend_session_id": backend_session_id,
            }
        if op == "lease_expire":
            _exact_keys(request, {"op", "lease_id"}, "edge lease-expire request")
            if type(request["lease_id"]) is not str or not request["lease_id"]:
                raise ValueError("lease ID is invalid")
            self._mark_uncertain()
            return {
                "ok": True,
                **self._process_identity(),
                "lease_id": request["lease_id"],
                "state": self._status(),
            }
        if op == "deliver":
            _exact_keys(request, {"op", "message"}, "edge delivery request")
            message = _mapping(request["message"], "edge delivered message")
            outcome = self._apply_message(message)
            return {
                "ok": True,
                **self._process_identity(),
                "message_id": message["message_id"],
                "sequence": message["sequence"],
                "outcome": outcome,
                "state": self._status(),
            }
        if op == "login":
            _exact_keys(
                request,
                {"op", "username", "password_hex", "credential_class", "backend_fault"},
                "edge login request",
            )
            if request["credential_class"] not in {"VALID", "INVALID"}:
                raise ValueError("credential class is invalid")
            fault = request["backend_fault"]
            if fault not in BACKEND_FAULTS:
                raise ValueError("backend fault is invalid")
            username = request["username"]
            if type(username) is not str or not username:
                raise ValueError("login username is invalid")
            password = bytes.fromhex(_strict_hex(request["password_hex"], "login password"))
            self.remote_backend.begin_observation(str(fault))
            cache_before = self.negative_cache.metrics_snapshot()
            decision = self.data_plane.authenticate(EDGES[0], username, password)
            cache_after = self.negative_cache.metrics_snapshot()
            cache_delta = {
                key: cache_after.get(key, 0) - cache_before.get(key, 0)
                for key in sorted(set(cache_before) | set(cache_after))
            }
            interactions = self.remote_backend.interactions()
            return {
                "ok": True,
                **self._process_identity(),
                "edge_id": EDGES[0],
                "credential_class": request["credential_class"],
                "accepted": decision.accepted,
                "pre_screen_rejected": decision.pre_screen_rejected,
                "route": decision.route.value,
                "directory_status": decision.directory_view.status.value,
                "positive_disposition": (
                    None
                    if decision.positive_decision is None
                    else decision.positive_decision.disposition.value
                ),
                "backend_kind": (
                    None if decision.backend_result is None else decision.backend_result.kind.value
                ),
                "backend_interactions": interactions,
                "state_trusted": self.state_trusted,
                "state_id": self.state["state_id"],
                "ready": self.state["ready"],
                "metrics": self._status()["metrics"],
                "negative_cache_before": cache_before,
                "negative_cache_after": cache_after,
                "negative_cache_delta": cache_delta,
            }
        raise ValueError("unknown edge RPC operation")


class _TransportProxyApplication:
    def __init__(
        self,
        config: Mapping[str, object],
        edge_endpoint: tuple[str, int],
        edge_pid: int,
        edge_session_id: str,
    ) -> None:
        self.config = config
        self.session_nonce_hex = ""
        self.session_id = ""
        self.endpoint = (HOST, 0)
        self.edge_endpoint = edge_endpoint
        self.edge_pid = edge_pid
        self.edge_session_id = edge_session_id
        self._lock = threading.RLock()
        self._delay_condition = threading.Condition(self._lock)
        self._delay_barriers: dict[str, dict[str, object]] = {}

    def bind_process(
        self,
        session_nonce_hex: str,
        session_id: str,
        endpoint: tuple[str, int],
    ) -> None:
        self.session_nonce_hex = session_nonce_hex
        self.session_id = session_id
        self.endpoint = endpoint

    def _process_identity(self) -> dict[str, object]:
        return {
            "pid": os.getpid(),
            "session_id": self.session_id,
            "endpoint": f"{self.endpoint[0]}:{self.endpoint[1]}",
        }

    def _edge_snapshot(self) -> tuple[tuple[str, int], int, str]:
        with self._lock:
            return self.edge_endpoint, self.edge_pid, self.edge_session_id

    def _deliver(
        self,
        message: Mapping[str, object],
        delivery_index: int,
    ) -> dict[str, object]:
        edge_endpoint, edge_pid, edge_session_id = self._edge_snapshot()
        timeout = int(_transport(self.config)["rpc_timeout_ms"]) / 1000.0
        response, raw_transport = _rpc(
            edge_endpoint,
            {"op": "deliver", "message": dict(message)},
            timeout,
        )
        transport = _bind_transport(
            raw_transport,
            caller_role="transport-proxy",
            caller_pid=os.getpid(),
            caller_session_id=self.session_id,
            callee_role="edge",
            callee_pid=edge_pid,
            callee_session_id=edge_session_id,
        )
        _exact_keys(
            response,
            {
                "ok",
                "pid",
                "session_id",
                "endpoint",
                "message_id",
                "sequence",
                "outcome",
                "state",
            },
            "proxy edge-delivery response",
        )
        if (
            response["ok"] is not True
            or response["pid"] != edge_pid
            or response["session_id"] != edge_session_id
            or response["endpoint"] != f"{edge_endpoint[0]}:{edge_endpoint[1]}"
            or response["message_id"] != message["message_id"]
            or response["sequence"] != message["sequence"]
            or response["outcome"] not in {"APPLIED", "DUPLICATE", "STALE"}
        ):
            raise ValueError("proxy delivery response identity or message mismatch")
        return {
            "delivery_index": delivery_index,
            "message_id": response["message_id"],
            "sequence": response["sequence"],
            "edge_outcome": response["outcome"],
            "edge_pid": edge_pid,
            "edge_session_id": edge_session_id,
            "edge_endpoint": f"{edge_endpoint[0]}:{edge_endpoint[1]}",
            "response_present": True,
            "rpc": transport,
        }

    def dispatch(self, request: dict[str, Any]) -> object:
        op = request.get("op")
        if op == "ping":
            _exact_keys(request, {"op"}, "transport-proxy ping request")
            return {
                "ok": True,
                "role": "transport-proxy",
                **self._process_identity(),
            }
        if op == "set_edge":
            _exact_keys(
                request,
                {"op", "host", "port", "pid", "session_id"},
                "transport-proxy edge update",
            )
            if request["host"] != HOST:
                raise ValueError("proxy edge endpoint must remain on IPv4 loopback")
            port = _integer(request["port"], "edge port", 1)
            if port > 65535:
                raise ValueError("edge port is invalid")
            pid = _integer(request["pid"], "edge PID", 1)
            session_id = _strict_hex(request["session_id"], "edge session", 64)
            with self._lock:
                self.edge_endpoint = (HOST, port)
                self.edge_pid = pid
                self.edge_session_id = session_id
            return {
                "ok": True,
                **self._process_identity(),
                "edge_pid": pid,
                "edge_session_id": session_id,
                "edge_endpoint": f"{HOST}:{port}",
            }
        if op == "delay_barrier_wait":
            _exact_keys(
                request,
                {"op", "barrier_id", "message_id", "sequence"},
                "transport-proxy delay barrier wait request",
            )
            message_id = request["message_id"]
            if type(message_id) is not str or not message_id:
                raise ValueError("proxy delay barrier message ID is invalid")
            sequence = _integer(request["sequence"], "proxy delay barrier sequence", 1)
            barrier_id = _strict_hex(request["barrier_id"], "proxy delay barrier ID", 64)
            if barrier_id != _delay_barrier_id(self.session_id, message_id, sequence):
                raise ValueError("proxy delay barrier ID is not session/message derived")
            deadline = time.monotonic() + int(_transport(self.config)["rpc_timeout_ms"]) / 1000.0
            with self._delay_condition:
                while barrier_id not in self._delay_barriers:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("proxy delay barrier was not entered before timeout")
                    self._delay_condition.wait(timeout=remaining)
                barrier = self._delay_barriers[barrier_id]
                if (
                    barrier["message_id"] != message_id
                    or barrier["sequence"] != sequence
                    or barrier["release_received"] is not False
                    or barrier["delivery_started"] is not False
                ):
                    raise ValueError("proxy delay barrier entered state is contradictory")
                return {
                    "ok": True,
                    **self._process_identity(),
                    "status": "DELAY_ENTERED",
                    "barrier_id": barrier_id,
                    "message_id": message_id,
                    "sequence": sequence,
                    "release_received": False,
                    "delivery_started": False,
                }
        if op == "delay_release":
            _exact_keys(
                request,
                {"op", "barrier_id", "message_id", "sequence", "login_completion_id"},
                "transport-proxy delay release request",
            )
            message_id = request["message_id"]
            if type(message_id) is not str or not message_id:
                raise ValueError("proxy delay release message ID is invalid")
            sequence = _integer(request["sequence"], "proxy delay release sequence", 1)
            barrier_id = _strict_hex(request["barrier_id"], "proxy delay release barrier ID", 64)
            login_completion_id = _strict_hex(
                request["login_completion_id"],
                "proxy delay release login completion ID",
                64,
            )
            if barrier_id != _delay_barrier_id(self.session_id, message_id, sequence):
                raise ValueError("proxy delay release barrier ID is not session/message derived")
            with self._delay_condition:
                barrier = self._delay_barriers.get(barrier_id)
                if (
                    barrier is None
                    or barrier["message_id"] != message_id
                    or barrier["sequence"] != sequence
                    or barrier["release_received"] is not False
                    or barrier["delivery_started"] is not False
                ):
                    raise ValueError("proxy delay release does not match an entered barrier")
                barrier["release_received"] = True
                barrier["login_completion_id"] = login_completion_id
                self._delay_condition.notify_all()
                return {
                    "ok": True,
                    **self._process_identity(),
                    "status": "DELAY_RELEASED",
                    "barrier_id": barrier_id,
                    "message_id": message_id,
                    "sequence": sequence,
                    "login_completion_id": login_completion_id,
                    "release_received": True,
                    "delivery_started": False,
                }
        if op == "produce":
            _exact_keys(
                request,
                {"op", "action", "messages", "delay_ms", "barrier_id"},
                "transport-proxy producer request",
            )
            action = request["action"]
            if action not in {"delay", "loss", "duplicate", "reorder", "recover"}:
                raise ValueError("proxy delivery action is invalid")
            messages_value = request["messages"]
            if type(messages_value) is not list or not messages_value:
                raise ValueError("proxy producer request requires messages")
            messages = [
                _mapping(message, f"proxy producer message[{index}]")
                for index, message in enumerate(messages_value)
            ]
            for message in messages:
                _exact_keys(message, {"message_id", "sequence", "kind"}, "proxy message")
                if type(message["message_id"]) is not str or not message["message_id"]:
                    raise ValueError("proxy message ID is invalid")
                _integer(message["sequence"], "proxy message sequence", 1)
                if message["kind"] != "RECOVER_READY":
                    raise ValueError("proxy message kind is invalid")
            delay_ms = _integer(request["delay_ms"], "proxy logical delay milliseconds")
            barrier_id: str | None = None
            delay_gate: dict[str, object] | None = None
            if action == "delay":
                if delay_ms != int(_transport(self.config)["logical_delay_ms"]):
                    raise ValueError("proxy delay does not match the frozen config")
                if len(messages) != 1:
                    raise ValueError("proxy delay requires one producer message")
                message_id = str(messages[0]["message_id"])
                sequence = int(messages[0]["sequence"])
                barrier_id = _strict_hex(request["barrier_id"], "proxy delay barrier ID", 64)
                if barrier_id != _delay_barrier_id(self.session_id, message_id, sequence):
                    raise ValueError("proxy delay barrier ID is not session/message derived")
                entered_ns = time.monotonic_ns()
                not_before_ns = entered_ns + delay_ms * 1_000_000
                hard_deadline_ns = (
                    not_before_ns + int(_transport(self.config)["rpc_timeout_ms"]) * 1_000_000
                )
                with self._delay_condition:
                    if barrier_id in self._delay_barriers:
                        raise ValueError("proxy delay barrier ID was reused")
                    barrier: dict[str, object] = {
                        "message_id": message_id,
                        "sequence": sequence,
                        "entered_ns": entered_ns,
                        "not_before_ns": not_before_ns,
                        "release_received": False,
                        "login_completion_id": None,
                        "delivery_started": False,
                    }
                    self._delay_barriers[barrier_id] = barrier
                    self._delay_condition.notify_all()
                    while True:
                        now_ns = time.monotonic_ns()
                        minimum_delay_satisfied = now_ns >= not_before_ns
                        if minimum_delay_satisfied and barrier["release_received"] is True:
                            barrier["delivery_started"] = True
                            break
                        if now_ns >= hard_deadline_ns:
                            raise ValueError("proxy delay barrier was not released before timeout")
                        next_wake_ns = (
                            hard_deadline_ns
                            if minimum_delay_satisfied
                            else min(not_before_ns, hard_deadline_ns)
                        )
                        self._delay_condition.wait(
                            timeout=max(0.001, (next_wake_ns - now_ns) / 1_000_000_000.0)
                        )
                    login_completion_id = str(barrier["login_completion_id"])
                    delay_gate = {
                        "status": "DELIVERY_PERMITTED",
                        "barrier_id": barrier_id,
                        "message_id": message_id,
                        "sequence": sequence,
                        "login_completion_id": login_completion_id,
                        "minimum_delay_satisfied": True,
                        "release_received": True,
                        "delivery_started_after_release": True,
                    }
            else:
                if delay_ms != 0 or request["barrier_id"] is not None:
                    raise ValueError("non-delay proxy actions require zero delay and no barrier")

            if action == "loss":
                delivery_order: list[dict[str, Any]] = []
            elif action == "duplicate":
                if len(messages) != 1:
                    raise ValueError("proxy duplicate requires one producer message")
                delivery_order = [messages[0], messages[0]]
            elif action == "reorder":
                if len(messages) != 2:
                    raise ValueError("proxy reorder requires two producer messages")
                delivery_order = list(reversed(messages))
            else:
                delivery_order = messages
            deliveries = [
                self._deliver(message, index) for index, message in enumerate(delivery_order)
            ]
            return {
                "ok": True,
                **self._process_identity(),
                "action": action,
                "producer_message_ids": [str(item["message_id"]) for item in messages],
                "producer_sequences": [int(item["sequence"]) for item in messages],
                "delivery_message_ids": [str(item["message_id"]) for item in delivery_order],
                "delivery_sequences": [int(item["sequence"]) for item in delivery_order],
                "deliveries": deliveries,
                "delay_ms": delay_ms,
                "dropped_count": len(messages) if action == "loss" else 0,
                "delay_barrier": delay_gate,
            }
        raise ValueError("unknown transport-proxy RPC operation")


def _serve_application(application: object, ready_path: Path, role: str) -> int:
    with _LoopbackServer((HOST, 0), _JsonLineHandler) as server:
        host, port = server.server_address
        session_nonce_hex = secrets.token_hex(32)
        session_id = _session_id(role, os.getpid(), session_nonce_hex)
        application.bind_process(  # type: ignore[attr-defined]
            session_nonce_hex,
            session_id,
            (host, port),
        )
        server.dispatch = application.dispatch  # type: ignore[attr-defined]
        ready = {
            "schema": "traps-g7-service-fault-ready-v1",
            "role": role,
            "pid": os.getpid(),
            "session_nonce_hex": session_nonce_hex,
            "session_id": session_id,
            "host": host,
            "port": port,
            "protocol": "TCP",
            "family": "AF_INET",
        }
        _write_json_exclusive(ready_path, ready)
        server.serve_forever(poll_interval=0.02)
    return 0


def _backend_child(config_path: Path, state_path: Path, ready_path: Path) -> int:
    config, _ = load_config(config_path)
    return _serve_application(_BackendApplication(config, state_path), ready_path, "backend")


def _edge_child(
    config_path: Path,
    state_path: Path,
    ready_path: Path,
    backend_host: str,
    backend_port: int,
    backend_pid: int,
    backend_session_id: str,
) -> int:
    if backend_host != HOST or not 1 <= backend_port <= 65535:
        raise ValueError("edge child backend endpoint must be IPv4 loopback")
    config, _ = load_config(config_path)
    application = _EdgeApplication(
        config,
        state_path,
        (backend_host, backend_port),
        backend_pid,
        backend_session_id,
    )
    return _serve_application(application, ready_path, "edge")


def _transport_proxy_child(
    config_path: Path,
    ready_path: Path,
    edge_host: str,
    edge_port: int,
    edge_pid: int,
    edge_session_id: str,
) -> int:
    if edge_host != HOST or not 1 <= edge_port <= 65535:
        raise ValueError("proxy child edge endpoint must be IPv4 loopback")
    config, _ = load_config(config_path)
    application = _TransportProxyApplication(
        config,
        (edge_host, edge_port),
        edge_pid,
        edge_session_id,
    )
    return _serve_application(application, ready_path, "transport-proxy")


@dataclass
class _ManagedProcess:
    role: str
    process: subprocess.Popen[bytes]
    ready: dict[str, Any]

    @property
    def endpoint(self) -> tuple[str, int]:
        return (str(self.ready["host"]), int(self.ready["port"]))

    @property
    def session_id(self) -> str:
        return str(self.ready["session_id"])

    @property
    def session_nonce_hex(self) -> str:
        return str(self.ready["session_nonce_hex"])


@dataclass(frozen=True)
class _CoordinatorIdentity:
    pid: int
    session_nonce_hex: str
    session_id: str


def _validate_ready(value: object, role: str, process: subprocess.Popen[bytes]) -> dict[str, Any]:
    ready = _mapping(value, f"{role} ready record")
    _exact_keys(
        ready,
        {
            "schema",
            "role",
            "pid",
            "session_nonce_hex",
            "session_id",
            "host",
            "port",
            "protocol",
            "family",
        },
        f"{role} ready record",
    )
    if (
        ready["schema"] != "traps-g7-service-fault-ready-v1"
        or ready["role"] != role
        or ready["pid"] != process.pid
        or ready["host"] != HOST
        or ready["protocol"] != "TCP"
        or ready["family"] != "AF_INET"
    ):
        raise ValueError(f"{role} ready record does not identify the child process")
    port = _integer(ready["port"], f"{role} ready port", 1)
    if port > 65535:
        raise ValueError(f"{role} ready port is invalid")
    nonce_hex = _strict_hex(ready["session_nonce_hex"], f"{role} session nonce", 64)
    session_id = _strict_hex(ready["session_id"], f"{role} session ID", 64)
    if session_id != _session_id(role, process.pid, nonce_hex):
        raise ValueError(f"{role} session identity mismatch")
    return ready


def _python_child_launch() -> tuple[Path, dict[str, str] | None]:
    executable = Path(sys.executable)
    environment: dict[str, str] | None = None
    if os.name == "nt":
        base_executable = getattr(sys, "_base_executable", None)
        if type(base_executable) is str and base_executable:
            executable = Path(base_executable)
            if executable != Path(sys.executable):
                environment = os.environ.copy()
                environment["__PYVENV_LAUNCHER__"] = sys.executable
    return executable, environment


def _start_process(
    role: str,
    config_path: Path,
    state_path: Path | None,
    ready_path: Path,
    start_timeout_seconds: float,
    backend: _ManagedProcess | None = None,
    edge: _ManagedProcess | None = None,
) -> _ManagedProcess:
    try:
        ready_path.unlink()
    except FileNotFoundError:
        pass
    child_executable, child_environment = _python_child_launch()
    command = [
        str(child_executable),
        str(Path(__file__).resolve()),
        "_transport_proxy" if role == "transport-proxy" else f"_{role}",
        "--config",
        str(config_path),
        "--ready",
        str(ready_path),
    ]
    if state_path is not None:
        command.extend(["--state", str(state_path)])
    if role == "edge":
        if backend is None:
            raise ValueError("edge process requires a backend process identity")
        command.extend(
            [
                "--backend-host",
                backend.endpoint[0],
                "--backend-port",
                str(backend.endpoint[1]),
                "--backend-pid",
                str(backend.process.pid),
                "--backend-session-id",
                backend.session_id,
            ]
        )
    elif role == "transport-proxy":
        if edge is None:
            raise ValueError("transport proxy requires an edge process identity")
        command.extend(
            [
                "--edge-host",
                edge.endpoint[0],
                "--edge-port",
                str(edge.endpoint[1]),
                "--edge-pid",
                str(edge.process.pid),
                "--edge-session-id",
                edge.session_id,
            ]
        )
    creationflags = 0
    if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
        creationflags = subprocess.CREATE_NO_WINDOW
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=creationflags,
        env=child_environment,
    )
    deadline = time.monotonic() + start_timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{role} child exited during startup with {process.returncode}")
        if ready_path.is_file():
            try:
                ready = _load_json_text(ready_path.read_text(encoding="utf-8"), "ready record")
                validated = _validate_ready(ready, role, process)
                response, _ = _rpc(
                    (str(validated["host"]), int(validated["port"])),
                    {"op": "ping"},
                    min(1.0, start_timeout_seconds),
                )
                if (
                    response.get("pid") != process.pid
                    or response.get("session_id") != validated["session_id"]
                    or response.get("endpoint") != f"{validated['host']}:{validated['port']}"
                ):
                    raise RuntimeError(f"{role} ping process identity mismatch")
                return _ManagedProcess(role, process, validated)
            except (OSError, UnicodeError, ValueError, _RpcFailure):
                pass
        time.sleep(0.01)
    process.kill()
    process.wait(timeout=max(1.0, start_timeout_seconds))
    raise TimeoutError(f"{role} child did not become ready")


def _kill_process(managed: _ManagedProcess, timeout_seconds: float) -> int:
    if managed.process.poll() is None:
        managed.process.kill()
    return managed.process.wait(timeout=timeout_seconds)


def _cleanup_process(managed: _ManagedProcess | None, timeout_seconds: float) -> None:
    if managed is None or managed.process.poll() is not None:
        return
    managed.process.terminate()
    try:
        managed.process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        managed.process.kill()
        managed.process.wait(timeout=timeout_seconds)


def _parent_rpc(
    managed: _ManagedProcess,
    request: Mapping[str, object],
    timeout_seconds: float,
    coordinator: _CoordinatorIdentity,
) -> tuple[dict[str, Any], dict[str, object]]:
    if managed.process.poll() is not None:
        raise RuntimeError(f"{managed.role} process is not running")
    response, raw_transport = _rpc(managed.endpoint, request, timeout_seconds)
    if (
        response.get("pid") != managed.process.pid
        or response.get("session_id") != managed.session_id
        or response.get("endpoint") != f"{managed.endpoint[0]}:{managed.endpoint[1]}"
    ):
        raise RuntimeError(f"{managed.role} response process identity mismatch")
    return response, _bind_transport(
        raw_transport,
        caller_role="coordinator",
        caller_pid=coordinator.pid,
        caller_session_id=coordinator.session_id,
        callee_role=managed.role,
        callee_pid=managed.process.pid,
        callee_session_id=managed.session_id,
    )


def _process_event(
    role: str,
    action: str,
    *,
    pid: int | None,
    session_nonce_hex: str | None,
    session_id: str | None,
    endpoint: tuple[str, int] | None,
    exit_code: int | None,
    state_id: str | None,
    state_trusted: bool | None,
) -> dict[str, object]:
    if exit_code is None:
        exit_class = None
    elif role == "backend" and exit_code == 73:
        exit_class = "APPLICATION_CRASH_73"
    elif exit_code != 0:
        exit_class = "FORCED_TERMINATION_NONZERO"
    else:
        exit_class = "CLEAN_EXIT"
    return {
        "role": role,
        "action": action,
        "pid": pid,
        "session_nonce_hex": session_nonce_hex,
        "session_id": session_id,
        "endpoint": None if endpoint is None else f"{endpoint[0]}:{endpoint[1]}",
        "exit_code": exit_code,
        "exit_class": exit_class,
        "state_id": state_id,
        "state_trusted": state_trusted,
        "random_observation_classification": (
            "SESSION_LOCAL_RELATIONAL_NOT_CROSS_RUN_SCALAR_EQUALITY"
        ),
    }


def _edge_status(
    edge: _ManagedProcess,
    timeout_seconds: float,
    coordinator: _CoordinatorIdentity,
) -> tuple[dict[str, Any], dict[str, object]]:
    response, rpc = _parent_rpc(edge, {"op": "status"}, timeout_seconds, coordinator)
    if response.get("ok") is not True:
        raise RuntimeError("edge status response is not bound to the live child")
    return response, rpc


def _update_proxy_edge(
    proxy: _ManagedProcess,
    edge: _ManagedProcess,
    timeout_seconds: float,
    coordinator: _CoordinatorIdentity,
) -> None:
    response, _ = _parent_rpc(
        proxy,
        {
            "op": "set_edge",
            "host": HOST,
            "port": edge.endpoint[1],
            "pid": edge.process.pid,
            "session_id": edge.session_id,
        },
        timeout_seconds,
        coordinator,
    )
    if (
        response.get("edge_pid") != edge.process.pid
        or response.get("edge_session_id") != edge.session_id
        or response.get("edge_endpoint") != f"{HOST}:{edge.endpoint[1]}"
    ):
        raise RuntimeError("transport proxy did not bind the restarted edge identity")


def _login(
    edge: _ManagedProcess,
    config: Mapping[str, object],
    coordinator: _CoordinatorIdentity,
    *,
    label: str,
    credential_class: str,
    backend_fault: str = "normal",
    uncertainty_reason: str | None = None,
) -> dict[str, object]:
    credential = _credential(config)
    password_field = (
        "valid_password_hex" if credential_class == "VALID" else "invalid_probe_password_hex"
    )
    request = {
        "op": "login",
        "username": credential["username"],
        "password_hex": credential[password_field],
        "credential_class": credential_class,
        "backend_fault": backend_fault,
    }
    timeout = int(_transport(config)["rpc_timeout_ms"]) / 1000.0
    response, rpc = _parent_rpc(edge, request, timeout, coordinator)
    if response.get("ok") is not True:
        raise RuntimeError("edge login response is not bound to the live child")
    interactions = response.get("backend_interactions")
    if type(interactions) is not list:
        raise ValueError("edge login response lacks backend interactions")
    backend_forwarded = any(
        type(item) is dict and item.get("operation") == "verify" for item in interactions
    )
    expected_valid = credential_class == "VALID"
    backend_kind = response.get("backend_kind")
    unavailable = bool(
        expected_valid
        and response.get("accepted") is False
        and backend_forwarded
        and backend_kind in UNCERTAIN_BACKEND_KINDS
    )
    return {
        "label": label,
        "credential_class": credential_class,
        "expected_valid": expected_valid,
        "accepted": response["accepted"],
        "pre_screen_rejected": response["pre_screen_rejected"],
        "route": response["route"],
        "directory_status": response["directory_status"],
        "positive_disposition": response["positive_disposition"],
        "backend_kind": backend_kind,
        "backend_forwarded": backend_forwarded,
        "uncertainty_reason": uncertainty_reason,
        "unavailable_authentication": unavailable,
        "edge_pid": response["pid"],
        "edge_session_id": response["session_id"],
        "edge_endpoint": f"{edge.endpoint[0]}:{edge.endpoint[1]}",
        "state_trusted": response["state_trusted"],
        "state_id": response["state_id"],
        "rpc": rpc,
        "backend_interactions": interactions,
        "component_metrics": response["metrics"],
        "negative_cache_before": response["negative_cache_before"],
        "negative_cache_after": response["negative_cache_after"],
        "negative_cache_delta": response["negative_cache_delta"],
    }


def _expire_lease_event(
    edge: _ManagedProcess,
    config: Mapping[str, object],
    coordinator: _CoordinatorIdentity,
    *,
    lease_id: str,
) -> dict[str, object]:
    timeout = int(_transport(config)["rpc_timeout_ms"]) / 1000.0
    response, rpc = _parent_rpc(
        edge,
        {"op": "lease_expire", "lease_id": lease_id},
        timeout,
        coordinator,
    )
    if response.get("ok") is not True or response.get("lease_id") != lease_id:
        raise RuntimeError("edge lease expiration was not acknowledged")
    state = _mapping(response["state"], "edge lease-expire state")
    return {
        "lease_id": lease_id,
        "edge_pid": edge.process.pid,
        "edge_session_id": edge.session_id,
        "edge_endpoint": f"{edge.endpoint[0]}:{edge.endpoint[1]}",
        "state_id": state["state_id"],
        "ready": state["ready"],
        "rpc": rpc,
    }


def _observe_delay_entered(
    proxy: _ManagedProcess,
    config: Mapping[str, object],
    coordinator: _CoordinatorIdentity,
    *,
    barrier_id: str,
    message_id: str,
    sequence: int,
) -> dict[str, object]:
    timeout = int(_transport(config)["rpc_timeout_ms"]) * 2 / 1000.0
    response, rpc = _parent_rpc(
        proxy,
        {
            "op": "delay_barrier_wait",
            "barrier_id": barrier_id,
            "message_id": message_id,
            "sequence": sequence,
        },
        timeout,
        coordinator,
    )
    _exact_keys(
        response,
        {
            "ok",
            "pid",
            "session_id",
            "endpoint",
            "status",
            "barrier_id",
            "message_id",
            "sequence",
            "release_received",
            "delivery_started",
        },
        "proxy delay-entered response",
    )
    if (
        response["ok"] is not True
        or response["status"] != "DELAY_ENTERED"
        or response["barrier_id"] != barrier_id
        or response["message_id"] != message_id
        or response["sequence"] != sequence
        or response["release_received"] is not False
        or response["delivery_started"] is not False
    ):
        raise RuntimeError("proxy did not expose the entered delay barrier")
    return {
        "event_ordinal": 0,
        "status": response["status"],
        "barrier_id": barrier_id,
        "message_id": message_id,
        "sequence": sequence,
        "proxy_pid": proxy.process.pid,
        "proxy_session_id": proxy.session_id,
        "proxy_endpoint": f"{proxy.endpoint[0]}:{proxy.endpoint[1]}",
        "release_received": False,
        "delivery_started": False,
        "rpc": rpc,
    }


def _release_delay_barrier(
    proxy: _ManagedProcess,
    config: Mapping[str, object],
    coordinator: _CoordinatorIdentity,
    *,
    barrier_id: str,
    message_id: str,
    sequence: int,
    login_completion_id: str,
) -> dict[str, object]:
    timeout = int(_transport(config)["rpc_timeout_ms"]) / 1000.0
    response, rpc = _parent_rpc(
        proxy,
        {
            "op": "delay_release",
            "barrier_id": barrier_id,
            "message_id": message_id,
            "sequence": sequence,
            "login_completion_id": login_completion_id,
        },
        timeout,
        coordinator,
    )
    _exact_keys(
        response,
        {
            "ok",
            "pid",
            "session_id",
            "endpoint",
            "status",
            "barrier_id",
            "message_id",
            "sequence",
            "login_completion_id",
            "release_received",
            "delivery_started",
        },
        "proxy delay-release response",
    )
    if (
        response["ok"] is not True
        or response["status"] != "DELAY_RELEASED"
        or response["barrier_id"] != barrier_id
        or response["message_id"] != message_id
        or response["sequence"] != sequence
        or response["login_completion_id"] != login_completion_id
        or response["release_received"] is not True
        or response["delivery_started"] is not False
    ):
        raise RuntimeError("proxy did not acknowledge the login-bound delay release")
    return {
        "event_ordinal": 2,
        "status": response["status"],
        "barrier_id": barrier_id,
        "message_id": message_id,
        "sequence": sequence,
        "login_completion_id": login_completion_id,
        "proxy_pid": proxy.process.pid,
        "proxy_session_id": proxy.session_id,
        "proxy_endpoint": f"{proxy.endpoint[0]}:{proxy.endpoint[1]}",
        "release_received": True,
        "delivery_started": False,
        "rpc": rpc,
    }


def _transport_event(
    proxy: _ManagedProcess,
    config: Mapping[str, object],
    coordinator: _CoordinatorIdentity,
    *,
    label: str,
    action: str,
    messages: Sequence[Mapping[str, object]],
    delay_ms: int = 0,
    lease_expiry: Mapping[str, object] | None = None,
    barrier_id: str | None = None,
) -> dict[str, object]:
    timeout = (
        int(_transport(config)["rpc_timeout_ms"]) + (delay_ms if action == "delay" else 0)
    ) / 1000.0
    response, rpc = _parent_rpc(
        proxy,
        {
            "op": "produce",
            "action": action,
            "messages": list(messages),
            "delay_ms": delay_ms,
            "barrier_id": barrier_id,
        },
        timeout,
        coordinator,
    )
    if response.get("ok") is not True:
        raise RuntimeError("producer response is not bound to the live transport proxy")
    if action == "delay":
        rpc["elapsed_class"] = "CONFIGURED_PROXY_DELAY_WINDOW"
    deliveries = response["deliveries"]
    if type(deliveries) is not list:
        raise ValueError("proxy delivery records are invalid")
    outcomes = [
        _mapping(delivery, "proxy delivery record")["edge_outcome"] for delivery in deliveries
    ]
    return {
        "label": label,
        "action": action,
        "producer_message_ids": response["producer_message_ids"],
        "producer_sequences": response["producer_sequences"],
        "delivery_message_ids": response["delivery_message_ids"],
        "delivery_sequences": response["delivery_sequences"],
        "edge_outcomes": outcomes,
        "deliveries": deliveries,
        "applied_count": outcomes.count("APPLIED"),
        "proxy_drop_count": response["dropped_count"],
        "duplicate_count": outcomes.count("DUPLICATE"),
        "stale_count": outcomes.count("STALE"),
        "delay_ms": response["delay_ms"],
        "proxy_pid": proxy.process.pid,
        "proxy_session_id": proxy.session_id,
        "proxy_endpoint": f"{proxy.endpoint[0]}:{proxy.endpoint[1]}",
        "producer_rpc": rpc,
        "lease_expiry": None if lease_expiry is None else dict(lease_expiry),
        "delay_barrier": response["delay_barrier"],
    }


def _message(message_id: str, sequence: int) -> dict[str, object]:
    return {"message_id": message_id, "sequence": sequence, "kind": "RECOVER_READY"}


def _checks(*items: tuple[str, bool]) -> list[dict[str, object]]:
    return [{"name": name, "passed": bool(passed)} for name, passed in items]


def _derive_row_summary(
    logins: Sequence[Mapping[str, object]],
    transport_events: Sequence[Mapping[str, object]],
    process_events: Sequence[Mapping[str, object]],
    checks: Sequence[Mapping[str, object]],
) -> dict[str, int]:
    valid = [item for item in logins if item["expected_valid"] is True]
    uncertainty = [item for item in logins if item["uncertainty_reason"] is not None]
    backend_rpc_count = sum(len(item["backend_interactions"]) for item in logins)
    lease_expiry_count = sum(item["lease_expiry"] is not None for item in transport_events)
    proxy_delivery_count = sum(len(item["deliveries"]) for item in transport_events)
    delay_barrier_count = sum(item["delay_barrier"] is not None for item in transport_events)
    return {
        "login_count": len(logins),
        "valid_attempts": len(valid),
        "structural_false_rejects": sum(item["pre_screen_rejected"] is True for item in valid),
        "unavailable_authentications": sum(
            item["unavailable_authentication"] is True for item in valid
        ),
        "uncertainty_attempts": len(uncertainty),
        "uncertainty_backend_forwarded": sum(
            item["backend_forwarded"] is True for item in uncertainty
        ),
        "recorded_coordinator_edge_login_rpc_count": len(logins),
        "recorded_coordinator_edge_lease_expire_rpc_count": lease_expiry_count,
        "recorded_coordinator_proxy_produce_rpc_count": len(transport_events),
        "recorded_coordinator_proxy_delay_barrier_wait_rpc_count": delay_barrier_count,
        "recorded_coordinator_proxy_delay_release_rpc_count": delay_barrier_count,
        "recorded_proxy_edge_delivery_rpc_count": proxy_delivery_count,
        "recorded_edge_backend_rpc_count": backend_rpc_count,
        "recorded_producer_message_count": sum(
            len(item["producer_message_ids"]) for item in transport_events
        ),
        "process_exit_events": sum(item["action"] == "EXIT" for item in process_events),
        "process_restart_events": sum(item["action"] == "RESTART" for item in process_events),
        "passed_checks": sum(item["passed"] is True for item in checks),
        "check_count": len(checks),
    }


def _make_row(
    coordinate: str,
    *,
    logins: Sequence[Mapping[str, object]],
    transport_events: Sequence[Mapping[str, object]] = (),
    process_events: Sequence[Mapping[str, object]] = (),
    checks: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    summary = _derive_row_summary(logins, transport_events, process_events, checks)
    passed = (
        summary["structural_false_rejects"] == 0
        and summary["uncertainty_attempts"] == summary["uncertainty_backend_forwarded"]
        and summary["passed_checks"] == summary["check_count"]
    )
    body: dict[str, object] = {
        "schema": ROW_SCHEMA,
        "coordinate": coordinate,
        "fault_class": coordinate.split("_", 1)[0].upper(),
        "logins": [dict(item) for item in logins],
        "transport_events": [dict(item) for item in transport_events],
        "process_events": [dict(item) for item in process_events],
        "checks": [dict(item) for item in checks],
        "summary": summary,
        "status": "PASS" if passed else "FAIL",
    }
    return {**body, "row_id": _identity(body)}


def _execute_matrix(config: Mapping[str, object], workdir: Path) -> list[dict[str, object]]:
    expected = _formal_config_spec()
    _exact_value(dict(config), expected, "matrix execution config")
    resolved_workdir = workdir.resolve()
    if resolved_workdir == ROOT or ROOT in resolved_workdir.parents:
        raise ValueError("service-fault matrix work directory must be outside checkout")
    resolved_workdir.mkdir(parents=True, exist_ok=False)
    config_path = resolved_workdir / "service_fault.g7.yaml"
    config_path.write_text(yaml.safe_dump(expected, sort_keys=False), encoding="utf-8")
    edge_state_path = resolved_workdir / "edge-state.json"
    backend_state_path = resolved_workdir / "backend-state.json"
    _write_json_atomic(edge_state_path, _edge_state(config, ready=True, last_sequence=0))
    _write_json_atomic(backend_state_path, _backend_state(config))
    transport = _transport(config)
    start_timeout = int(transport["process_start_timeout_ms"]) / 1000.0
    exit_timeout = int(transport["process_exit_timeout_ms"]) / 1000.0
    rpc_timeout = int(transport["rpc_timeout_ms"]) / 1000.0
    backend_ready = resolved_workdir / "backend-ready.json"
    edge_ready = resolved_workdir / "edge-ready.json"
    proxy_ready = resolved_workdir / "transport-proxy-ready.json"
    coordinator_nonce_hex = secrets.token_hex(32)
    coordinator = _CoordinatorIdentity(
        pid=os.getpid(),
        session_nonce_hex=coordinator_nonce_hex,
        session_id=_session_id("coordinator", os.getpid(), coordinator_nonce_hex),
    )
    backend: _ManagedProcess | None = None
    edge: _ManagedProcess | None = None
    proxy: _ManagedProcess | None = None
    rows: list[dict[str, object]] = []
    try:
        backend = _start_process(
            "backend",
            config_path,
            backend_state_path,
            backend_ready,
            start_timeout,
        )
        edge = _start_process(
            "edge",
            config_path,
            edge_state_path,
            edge_ready,
            start_timeout,
            backend=backend,
        )
        proxy = _start_process(
            "transport-proxy",
            config_path,
            None,
            proxy_ready,
            start_timeout,
            edge=edge,
        )
        initial_status, _ = _edge_status(edge, rpc_timeout, coordinator)
        initial_process = [
            _process_event(
                "coordinator",
                "START",
                pid=coordinator.pid,
                session_nonce_hex=coordinator.session_nonce_hex,
                session_id=coordinator.session_id,
                endpoint=None,
                exit_code=None,
                state_id=None,
                state_trusted=None,
            ),
            _process_event(
                "backend",
                "START",
                pid=backend.process.pid,
                session_nonce_hex=backend.session_nonce_hex,
                session_id=backend.session_id,
                endpoint=backend.endpoint,
                exit_code=None,
                state_id=str(_backend_state(config)["state_id"]),
                state_trusted=True,
            ),
            _process_event(
                "edge",
                "START",
                pid=edge.process.pid,
                session_nonce_hex=edge.session_nonce_hex,
                session_id=edge.session_id,
                endpoint=edge.endpoint,
                exit_code=None,
                state_id=str(initial_status["state_id"]),
                state_trusted=bool(initial_status["state_trusted"]),
            ),
            _process_event(
                "transport-proxy",
                "START",
                pid=proxy.process.pid,
                session_nonce_hex=proxy.session_nonce_hex,
                session_id=proxy.session_id,
                endpoint=proxy.endpoint,
                exit_code=None,
                state_id=None,
                state_trusted=None,
            ),
        ]

        invalid_first = _login(
            edge,
            config,
            coordinator,
            label="invalid-first-backend-mismatch",
            credential_class="INVALID",
        )
        invalid_cached = _login(
            edge,
            config,
            coordinator,
            label="invalid-second-exact-cache-hit",
            credential_class="INVALID",
        )
        valid_core = _login(
            edge,
            config,
            coordinator,
            label="valid-after-core-path-probe",
            credential_class="VALID",
        )
        core_metrics = _mapping(valid_core["component_metrics"], "core metrics")
        cache_metrics = _mapping(core_metrics["negative_cache"], "negative cache metrics")
        flight_metrics = _mapping(core_metrics["singleflight"], "singleflight metrics")
        rows.append(
            _make_row(
                "core_path_probe",
                logins=[invalid_first, invalid_cached, valid_core],
                process_events=initial_process,
                checks=_checks(
                    (
                        "first-invalid-reached-typed-backend-and-was-denied",
                        invalid_first["backend_forwarded"] is True
                        and invalid_first["backend_kind"]
                        == BackendResultKind.CREDENTIAL_MISMATCH.value
                        and invalid_first["accepted"] is False,
                    ),
                    (
                        "second-invalid-hit-exact-negative-cache",
                        invalid_cached["route"] == "NEGATIVE_CACHE_REJECT"
                        and invalid_cached["backend_forwarded"] is False,
                    ),
                    (
                        "valid-credential-was-not-prescreen-rejected",
                        valid_core["accepted"] is True
                        and valid_core["pre_screen_rejected"] is False,
                    ),
                    (
                        "negative-cache-insert-and-hit-executed",
                        cache_metrics.get("inserts", 0) >= 1 and cache_metrics.get("hits", 0) >= 1,
                    ),
                    ("singleflight-leader-executed", flight_metrics.get("leaders", 0) >= 2),
                ),
            )
        )

        delay_lease = _expire_lease_event(
            edge,
            config,
            coordinator,
            lease_id="lease-expire-delay-1",
        )
        delay_holder: dict[str, object] = {}
        delay_message = _message("message-delay-1", 1)
        delay_barrier_id = _delay_barrier_id(
            proxy.session_id,
            str(delay_message["message_id"]),
            int(delay_message["sequence"]),
        )

        def run_delayed_transport() -> None:
            try:
                delay_holder["event"] = _transport_event(
                    proxy,  # type: ignore[arg-type]
                    config,
                    coordinator,
                    label="delayed-recovery-message",
                    action="delay",
                    messages=[delay_message],
                    delay_ms=int(transport["logical_delay_ms"]),
                    lease_expiry=delay_lease,
                    barrier_id=delay_barrier_id,
                )
            except BaseException as error:
                delay_holder["error"] = error

        delay_thread = threading.Thread(target=run_delayed_transport, daemon=True)
        delay_thread.start()
        delay_entered = _observe_delay_entered(
            proxy,
            config,
            coordinator,
            barrier_id=delay_barrier_id,
            message_id=str(delay_message["message_id"]),
            sequence=int(delay_message["sequence"]),
        )
        valid_during_delay = _login(
            edge,
            config,
            coordinator,
            label="valid-during-logical-delay",
            credential_class="VALID",
            uncertainty_reason="DIRECTORY_UNCERTAIN_DURING_DELAY",
        )
        delay_login_completion_id = _login_completion_id(valid_during_delay)
        delay_release = _release_delay_barrier(
            proxy,
            config,
            coordinator,
            barrier_id=delay_barrier_id,
            message_id=str(delay_message["message_id"]),
            sequence=int(delay_message["sequence"]),
            login_completion_id=delay_login_completion_id,
        )
        delay_thread.join(timeout=rpc_timeout + int(transport["logical_delay_ms"]) / 1000.0)
        if delay_thread.is_alive():
            raise TimeoutError("delayed transport RPC did not complete")
        if "error" in delay_holder:
            raise RuntimeError("delayed transport RPC failed") from delay_holder["error"]  # type: ignore[arg-type]
        delayed_event = _mapping(delay_holder["event"], "delayed transport event")
        delivery_gate = _mapping(
            delayed_event["delay_barrier"],
            "delayed transport delivery gate",
        )
        delayed_event["delay_barrier"] = {
            "barrier_id": delay_barrier_id,
            "message_id": delay_message["message_id"],
            "sequence": delay_message["sequence"],
            "proxy_pid": proxy.process.pid,
            "proxy_session_id": proxy.session_id,
            "proxy_endpoint": f"{proxy.endpoint[0]}:{proxy.endpoint[1]}",
            "entered_observation": delay_entered,
            "login_completion": {
                "event_ordinal": 1,
                "login_label": valid_during_delay["label"],
                "login_completion_id": delay_login_completion_id,
                "edge_session_id": valid_during_delay["edge_session_id"],
                "login_rpc_connection_id": valid_during_delay["rpc"]["connection_id"],
            },
            "release": delay_release,
            "delivery_gate": {"event_ordinal": 3, **delivery_gate},
            "causal_order": [
                "DELAY_ENTERED",
                "LOGIN_COMPLETED",
                "DELAY_RELEASED",
                "EDGE_DELIVERY",
            ],
        }
        valid_after_delay = _login(
            edge,
            config,
            coordinator,
            label="valid-after-logical-delay",
            credential_class="VALID",
        )
        rows.append(
            _make_row(
                "transport_delay",
                logins=[valid_during_delay, valid_after_delay],
                transport_events=[delayed_event],
                checks=_checks(
                    (
                        "delay-window-observed-before-apply",
                        delay_entered["status"] == "DELAY_ENTERED"
                        and delay_entered["delivery_started"] is False,
                    ),
                    (
                        "delay-barrier-entered-login-release-delivery-order",
                        delayed_event["delay_barrier"]["causal_order"]
                        == [
                            "DELAY_ENTERED",
                            "LOGIN_COMPLETED",
                            "DELAY_RELEASED",
                            "EDGE_DELIVERY",
                        ],
                    ),
                    (
                        "valid-during-delay-failed-open-to-backend",
                        valid_during_delay["route"] == "FAIL_OPEN_BACKEND"
                        and valid_during_delay["backend_forwarded"] is True
                        and valid_during_delay["pre_screen_rejected"] is False,
                    ),
                    (
                        "delayed-message-eventually-applied",
                        delayed_event["applied_count"] == 1
                        and delayed_event["delay_ms"] == transport["logical_delay_ms"],
                    ),
                    (
                        "delay-proxy-used-one-edge-delivery-connection",
                        len(delayed_event["deliveries"]) == 1,
                    ),
                    ("post-delay-valid-login-recovered", valid_after_delay["accepted"] is True),
                ),
            )
        )

        loss_lease = _expire_lease_event(
            edge,
            config,
            coordinator,
            lease_id="lease-expire-loss-2",
        )
        lost_event = _transport_event(
            proxy,
            config,
            coordinator,
            label="lost-recovery-message",
            action="loss",
            messages=[_message("message-loss-2", 2)],
            lease_expiry=loss_lease,
        )
        valid_during_loss = _login(
            edge,
            config,
            coordinator,
            label="valid-after-logical-message-loss",
            credential_class="VALID",
            uncertainty_reason="DIRECTORY_UNCERTAIN_AFTER_LOSS",
        )
        loss_recovery = _transport_event(
            proxy,
            config,
            coordinator,
            label="loss-recovery-redelivery",
            action="recover",
            messages=[_message("message-loss-recovery-2", 2)],
        )
        valid_after_loss = _login(
            edge,
            config,
            coordinator,
            label="valid-after-loss-recovery",
            credential_class="VALID",
        )
        rows.append(
            _make_row(
                "transport_loss",
                logins=[valid_during_loss, valid_after_loss],
                transport_events=[lost_event, loss_recovery],
                checks=_checks(
                    (
                        "logical-message-was-dropped",
                        lost_event["proxy_drop_count"] == 1,
                    ),
                    (
                        "loss-proxy-made-zero-edge-deliveries",
                        len(lost_event["deliveries"]) == 0,
                    ),
                    (
                        "valid-after-loss-failed-open-to-backend",
                        valid_during_loss["route"] == "FAIL_OPEN_BACKEND"
                        and valid_during_loss["backend_forwarded"] is True
                        and valid_during_loss["pre_screen_rejected"] is False,
                    ),
                    ("loss-recovery-message-applied", loss_recovery["applied_count"] == 1),
                    ("post-loss-valid-login-recovered", valid_after_loss["accepted"] is True),
                ),
            )
        )

        duplicate_lease = _expire_lease_event(
            edge,
            config,
            coordinator,
            lease_id="lease-expire-duplicate-3",
        )
        duplicate_event = _transport_event(
            proxy,
            config,
            coordinator,
            label="duplicate-recovery-message",
            action="duplicate",
            messages=[_message("message-duplicate-3", 3)],
            lease_expiry=duplicate_lease,
        )
        valid_after_duplicate = _login(
            edge,
            config,
            coordinator,
            label="valid-after-duplicate-message",
            credential_class="VALID",
        )
        rows.append(
            _make_row(
                "transport_duplicate",
                logins=[valid_after_duplicate],
                transport_events=[duplicate_event],
                checks=_checks(
                    (
                        "duplicate-message-was-idempotent",
                        duplicate_event["applied_count"] == 1
                        and duplicate_event["duplicate_count"] == 1,
                    ),
                    (
                        "duplicate-proxy-made-two-independent-edge-connections",
                        len(duplicate_event["deliveries"]) == 2
                        and duplicate_event["deliveries"][0]["rpc"]["connection_id"]
                        != duplicate_event["deliveries"][1]["rpc"]["connection_id"],
                    ),
                    (
                        "valid-after-duplicate-was-not-prescreen-rejected",
                        valid_after_duplicate["accepted"] is True
                        and valid_after_duplicate["pre_screen_rejected"] is False,
                    ),
                ),
            )
        )

        reorder_lease = _expire_lease_event(
            edge,
            config,
            coordinator,
            lease_id="lease-expire-reorder-5",
        )
        reorder_event = _transport_event(
            proxy,
            config,
            coordinator,
            label="reordered-recovery-messages",
            action="reorder",
            messages=[
                _message("message-reorder-old-4", 4),
                _message("message-reorder-new-5", 5),
            ],
            lease_expiry=reorder_lease,
        )
        valid_after_reorder = _login(
            edge,
            config,
            coordinator,
            label="valid-after-reordered-messages",
            credential_class="VALID",
        )
        rows.append(
            _make_row(
                "transport_reorder",
                logins=[valid_after_reorder],
                transport_events=[reorder_event],
                checks=_checks(
                    (
                        "newer-message-applied-and-stale-message-rejected",
                        reorder_event["applied_count"] == 1 and reorder_event["stale_count"] == 1,
                    ),
                    (
                        "reorder-proxy-delivered-reversed-over-two-connections",
                        reorder_event["producer_sequences"] == [4, 5]
                        and reorder_event["delivery_sequences"] == [5, 4]
                        and len(reorder_event["deliveries"]) == 2
                        and reorder_event["deliveries"][0]["rpc"]["connection_id"]
                        != reorder_event["deliveries"][1]["rpc"]["connection_id"],
                    ),
                    (
                        "valid-after-reorder-was-not-prescreen-rejected",
                        valid_after_reorder["accepted"] is True
                        and valid_after_reorder["pre_screen_rejected"] is False,
                    ),
                ),
            )
        )

        before_restart_status, _ = _edge_status(edge, rpc_timeout, coordinator)
        old_edge_pid = edge.process.pid
        old_edge_session_id = edge.session_id
        old_edge_session_nonce = edge.session_nonce_hex
        old_edge_endpoint = edge.endpoint
        edge_exit = _kill_process(edge, exit_timeout)
        restarted_edge = _start_process(
            "edge",
            config_path,
            edge_state_path,
            edge_ready,
            start_timeout,
            backend=backend,
        )
        edge = restarted_edge
        _update_proxy_edge(proxy, edge, rpc_timeout, coordinator)
        after_restart_status, _ = _edge_status(edge, rpc_timeout, coordinator)
        valid_after_restart = _login(
            edge,
            config,
            coordinator,
            label="valid-after-edge-process-restart",
            credential_class="VALID",
        )
        restart_metrics = _mapping(
            valid_after_restart["component_metrics"], "edge restart component metrics"
        )
        restart_cache = _mapping(
            restart_metrics["negative_cache"], "edge restart negative cache metrics"
        )
        restart_events = [
            _process_event(
                "edge",
                "EXIT",
                pid=old_edge_pid,
                session_nonce_hex=old_edge_session_nonce,
                session_id=old_edge_session_id,
                endpoint=old_edge_endpoint,
                exit_code=edge_exit,
                state_id=str(before_restart_status["state_id"]),
                state_trusted=bool(before_restart_status["state_trusted"]),
            ),
            _process_event(
                "edge",
                "RESTART",
                pid=edge.process.pid,
                session_nonce_hex=edge.session_nonce_hex,
                session_id=edge.session_id,
                endpoint=edge.endpoint,
                exit_code=None,
                state_id=str(after_restart_status["state_id"]),
                state_trusted=bool(after_restart_status["state_trusted"]),
            ),
        ]
        rows.append(
            _make_row(
                "edge_kill_restart_persistence",
                logins=[valid_after_restart],
                process_events=restart_events,
                checks=_checks(
                    ("edge-process-exited-after-kill", edge_exit is not None),
                    ("edge-restart-has-new-pid", edge.process.pid != old_edge_pid),
                    (
                        "persistent-state-identity-restored",
                        before_restart_status["state_id"] == after_restart_status["state_id"]
                        and after_restart_status["state_trusted"] is True,
                    ),
                    (
                        "valid-after-restart-was-not-prescreen-rejected",
                        valid_after_restart["accepted"] is True
                        and valid_after_restart["pre_screen_rejected"] is False,
                    ),
                    (
                        "volatile-negative-cache-cleared-on-restart",
                        restart_cache.get("entries") == 0 and restart_cache.get("inserts", 0) == 0,
                    ),
                ),
            )
        )

        trusted_status, _ = _edge_status(edge, rpc_timeout, coordinator)
        corrupt_old_pid = edge.process.pid
        corrupt_old_session_id = edge.session_id
        corrupt_old_session_nonce = edge.session_nonce_hex
        corrupt_old_endpoint = edge.endpoint
        corrupt_exit = _kill_process(edge, exit_timeout)
        corrupt_payload = b'{"schema":"corrupt","state_id":"forged"'
        edge_state_path.write_bytes(corrupt_payload)
        corrupt_digest = hashlib.sha256(corrupt_payload).hexdigest()
        edge = _start_process(
            "edge",
            config_path,
            edge_state_path,
            edge_ready,
            start_timeout,
            backend=backend,
        )
        _update_proxy_edge(proxy, edge, rpc_timeout, coordinator)
        corrupt_status, _ = _edge_status(edge, rpc_timeout, coordinator)
        corrupt_edge_session_id = edge.session_id
        corrupt_edge_session_nonce = edge.session_nonce_hex
        valid_with_corrupt_state = _login(
            edge,
            config,
            coordinator,
            label="valid-with-corrupt-persistent-state",
            credential_class="VALID",
            uncertainty_reason="CORRUPT_PERSISTENT_STATE",
        )
        corrupt_recovery = _transport_event(
            proxy,
            config,
            coordinator,
            label="corrupt-state-authoritative-recovery",
            action="recover",
            messages=[_message("message-corrupt-recovery-6", 6)],
        )
        recovered_before_restart, _ = _edge_status(edge, rpc_timeout, coordinator)
        corrupt_edge_pid = edge.process.pid
        corrupt_edge_endpoint = edge.endpoint
        corrupt_recovery_exit = _kill_process(edge, exit_timeout)
        edge = _start_process(
            "edge",
            config_path,
            edge_state_path,
            edge_ready,
            start_timeout,
            backend=backend,
        )
        _update_proxy_edge(proxy, edge, rpc_timeout, coordinator)
        recovered_status, _ = _edge_status(edge, rpc_timeout, coordinator)
        valid_after_corrupt_recovery = _login(
            edge,
            config,
            coordinator,
            label="valid-after-corrupt-state-recovery-restart",
            credential_class="VALID",
        )
        corrupt_events = [
            _process_event(
                "edge",
                "EXIT",
                pid=corrupt_old_pid,
                session_nonce_hex=corrupt_old_session_nonce,
                session_id=corrupt_old_session_id,
                endpoint=corrupt_old_endpoint,
                exit_code=corrupt_exit,
                state_id=str(trusted_status["state_id"]),
                state_trusted=True,
            ),
            _process_event(
                "edge-state-file",
                "CORRUPT_STATE",
                pid=None,
                session_nonce_hex=None,
                session_id=None,
                endpoint=None,
                exit_code=None,
                state_id=corrupt_digest,
                state_trusted=False,
            ),
            _process_event(
                "edge",
                "RESTART",
                pid=corrupt_edge_pid,
                session_nonce_hex=corrupt_edge_session_nonce,
                session_id=corrupt_edge_session_id,
                endpoint=corrupt_edge_endpoint,
                exit_code=None,
                state_id=str(corrupt_status["state_id"]),
                state_trusted=False,
            ),
            _process_event(
                "edge",
                "EXIT",
                pid=corrupt_edge_pid,
                session_nonce_hex=corrupt_edge_session_nonce,
                session_id=corrupt_edge_session_id,
                endpoint=corrupt_edge_endpoint,
                exit_code=corrupt_recovery_exit,
                state_id=str(recovered_before_restart["state_id"]),
                state_trusted=True,
            ),
            _process_event(
                "edge",
                "RESTART",
                pid=edge.process.pid,
                session_nonce_hex=edge.session_nonce_hex,
                session_id=edge.session_id,
                endpoint=edge.endpoint,
                exit_code=None,
                state_id=str(recovered_status["state_id"]),
                state_trusted=True,
            ),
        ]
        rows.append(
            _make_row(
                "edge_corrupt_state_fail_open",
                logins=[valid_with_corrupt_state, valid_after_corrupt_recovery],
                transport_events=[corrupt_recovery],
                process_events=corrupt_events,
                checks=_checks(
                    ("corrupt-state-was-not-trusted", corrupt_status["state_trusted"] is False),
                    (
                        "corrupt-state-valid-login-failed-open-to-backend",
                        valid_with_corrupt_state["route"] == "FAIL_OPEN_BACKEND"
                        and valid_with_corrupt_state["accepted"] is True
                        and valid_with_corrupt_state["pre_screen_rejected"] is False
                        and valid_with_corrupt_state["backend_forwarded"] is True,
                    ),
                    (
                        "authoritative-recovery-message-applied",
                        corrupt_recovery["applied_count"] == 1,
                    ),
                    (
                        "recovered-state-survived-process-restart",
                        recovered_before_restart["state_id"] == recovered_status["state_id"]
                        and recovered_status["state_trusted"] is True,
                    ),
                    (
                        "valid-after-corrupt-recovery-authenticated",
                        valid_after_corrupt_recovery["accepted"] is True
                        and valid_after_corrupt_recovery["pre_screen_rejected"] is False,
                    ),
                ),
            )
        )

        fault_coordinates = (
            ("backend_timeout", "timeout", BackendResultKind.TRANSIENT_FAILURE.value),
            ("backend_drop", "drop", BackendResultKind.TRANSIENT_FAILURE.value),
            ("backend_malformed", "malformed", BackendResultKind.TRANSIENT_FAILURE.value),
            (
                "backend_typed_transient_failure",
                "typed_transient_failure",
                BackendResultKind.TRANSIENT_FAILURE.value,
            ),
            (
                "backend_typed_partial_failure",
                "typed_partial_failure",
                BackendResultKind.PARTIAL_AUTHENTICATOR_FAILURE.value,
            ),
        )
        for coordinate, fault, expected_kind in fault_coordinates:
            faulted = _login(
                edge,
                config,
                coordinator,
                label=f"valid-during-{fault}",
                credential_class="VALID",
                backend_fault=fault,
                uncertainty_reason=f"BACKEND_{fault.upper()}",
            )
            recovered = _login(
                edge,
                config,
                coordinator,
                label=f"valid-after-{fault}-recovery",
                credential_class="VALID",
            )
            first_interaction = _mapping(
                faulted["backend_interactions"][0],  # type: ignore[index]
                "faulted backend interaction",
            )
            faulted_metrics = _mapping(faulted["component_metrics"], "faulted component metrics")
            faulted_cache = _mapping(
                faulted_metrics["negative_cache"], "faulted negative cache metrics"
            )
            rows.append(
                _make_row(
                    coordinate,
                    logins=[faulted, recovered],
                    checks=_checks(
                        (
                            "faulted-valid-login-reached-external-backend",
                            faulted["backend_forwarded"] is True
                            and first_interaction["fault"] == fault,
                        ),
                        (
                            "backend-uncertainty-was-not-a-prescreen-reject",
                            faulted["route"] == "FAIL_OPEN_BACKEND"
                            and faulted["pre_screen_rejected"] is False
                            and faulted["backend_kind"] == expected_kind
                            and faulted["unavailable_authentication"] is True,
                        ),
                        (
                            "backend-recovery-valid-login-authenticated",
                            recovered["accepted"] is True
                            and recovered["pre_screen_rejected"] is False,
                        ),
                        (
                            "backend-uncertainty-did-not-write-negative-cache",
                            faulted_cache.get("entries") == 0
                            and faulted_cache.get("inserts", 0) == 0,
                        ),
                    ),
                )
            )

        old_backend_pid = backend.process.pid
        old_backend_session_id = backend.session_id
        old_backend_session_nonce = backend.session_nonce_hex
        old_backend_endpoint = backend.endpoint
        crash_login = _login(
            edge,
            config,
            coordinator,
            label="valid-during-backend-process-crash",
            credential_class="VALID",
            backend_fault="crash",
            uncertainty_reason="BACKEND_PROCESS_CRASH",
        )
        backend_exit = backend.process.wait(timeout=exit_timeout)
        backend = _start_process(
            "backend",
            config_path,
            backend_state_path,
            backend_ready,
            start_timeout,
        )
        update_response, _ = _parent_rpc(
            edge,
            {
                "op": "set_backend",
                "host": HOST,
                "port": backend.endpoint[1],
                "pid": backend.process.pid,
                "session_id": backend.session_id,
            },
            rpc_timeout,
            coordinator,
        )
        if (
            update_response.get("backend_endpoint") != f"{HOST}:{backend.endpoint[1]}"
            or update_response.get("backend_pid") != backend.process.pid
            or update_response.get("backend_session_id") != backend.session_id
        ):
            raise RuntimeError("edge did not bind the restarted backend endpoint")
        backend_recovered = _login(
            edge,
            config,
            coordinator,
            label="valid-after-backend-process-restart",
            credential_class="VALID",
        )
        crash_metrics = _mapping(
            crash_login["component_metrics"], "backend crash component metrics"
        )
        crash_cache = _mapping(
            crash_metrics["negative_cache"], "backend crash negative cache metrics"
        )
        backend_events = [
            _process_event(
                "backend",
                "EXIT",
                pid=old_backend_pid,
                session_nonce_hex=old_backend_session_nonce,
                session_id=old_backend_session_id,
                endpoint=old_backend_endpoint,
                exit_code=backend_exit,
                state_id=str(_backend_state(config)["state_id"]),
                state_trusted=True,
            ),
            _process_event(
                "backend",
                "RESTART",
                pid=backend.process.pid,
                session_nonce_hex=backend.session_nonce_hex,
                session_id=backend.session_id,
                endpoint=backend.endpoint,
                exit_code=None,
                state_id=str(_backend_state(config)["state_id"]),
                state_trusted=True,
            ),
        ]
        rows.append(
            _make_row(
                "backend_crash_restart",
                logins=[crash_login, backend_recovered],
                process_events=backend_events,
                checks=_checks(
                    (
                        "backend-crash-valid-login-was-forwarded-not-prescreen-rejected",
                        crash_login["backend_forwarded"] is True
                        and crash_login["pre_screen_rejected"] is False
                        and crash_login["route"] == "FAIL_OPEN_BACKEND"
                        and crash_login["unavailable_authentication"] is True,
                    ),
                    ("backend-process-exited-with-crash-code", backend_exit == 73),
                    ("backend-restart-has-new-pid", backend.process.pid != old_backend_pid),
                    (
                        "backend-restart-valid-login-authenticated",
                        backend_recovered["accepted"] is True
                        and backend_recovered["pre_screen_rejected"] is False,
                    ),
                    (
                        "backend-crash-did-not-write-negative-cache",
                        crash_cache.get("entries") == 0 and crash_cache.get("inserts", 0) == 0,
                    ),
                ),
            )
        )

        if tuple(row["coordinate"] for row in rows) != COORDINATES:
            raise RuntimeError(
                "service-fault execution did not produce the frozen coordinate order"
            )
        return rows
    finally:
        _cleanup_process(proxy, exit_timeout)
        _cleanup_process(edge, exit_timeout)
        _cleanup_process(backend, exit_timeout)


def _private_child_main(argv: Sequence[str]) -> int | None:
    if not argv or argv[0] not in {"_backend", "_edge", "_transport_proxy"}:
        return None
    role = argv[0]
    parser = argparse.ArgumentParser(prog=f"service_fault_evidence.py {role}")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    if role in {"_backend", "_edge"}:
        parser.add_argument("--state", type=Path, required=True)
    if role == "_edge":
        parser.add_argument("--backend-host", required=True)
        parser.add_argument("--backend-port", type=int, required=True)
        parser.add_argument("--backend-pid", type=int, required=True)
        parser.add_argument("--backend-session-id", required=True)
    elif role == "_transport_proxy":
        parser.add_argument("--edge-host", required=True)
        parser.add_argument("--edge-port", type=int, required=True)
        parser.add_argument("--edge-pid", type=int, required=True)
        parser.add_argument("--edge-session-id", required=True)
    args = parser.parse_args(list(argv[1:]))
    if role == "_backend":
        return _backend_child(args.config, args.state, args.ready)
    if role == "_edge":
        return _edge_child(
            args.config,
            args.state,
            args.ready,
            args.backend_host,
            args.backend_port,
            args.backend_pid,
            args.backend_session_id,
        )
    return _transport_proxy_child(
        args.config,
        args.ready,
        args.edge_host,
        args.edge_port,
        args.edge_pid,
        args.edge_session_id,
    )


def _validate_rpc_transport(value: object, label: str) -> dict[str, Any]:
    transport = _mapping(value, label)
    _exact_keys(
        transport,
        {
            "protocol",
            "family",
            "server_host",
            "server_port",
            "client_host",
            "client_port",
            "request_bytes",
            "response_bytes",
            "request_present",
            "response_present",
            "elapsed_ns",
            "elapsed_class",
            "outcome",
            "connection_nonce_hex",
            "connection_id",
            "ephemeral_observation_classification",
            "caller_role",
            "caller_pid",
            "caller_session_id",
            "caller_endpoint",
            "callee_role",
            "callee_pid",
            "callee_session_id",
            "callee_endpoint",
        },
        label,
    )
    if (
        transport["protocol"] != "TCP"
        or transport["family"] != "AF_INET"
        or transport["server_host"] != HOST
        or transport["client_host"] != HOST
    ):
        raise ValueError(f"{label} is not real IPv4 loopback TCP")
    for field in ("server_port", "client_port"):
        port = _integer(transport[field], f"{label}.{field}", 1)
        if port > 65535:
            raise ValueError(f"{label}.{field} is invalid")
    request_bytes = _integer(transport["request_bytes"], f"{label}.request_bytes", 2)
    response_bytes = _integer(transport["response_bytes"], f"{label}.response_bytes")
    for field in ("request_present", "response_present"):
        if type(transport[field]) is not bool:
            raise ValueError(f"{label}.{field} must be Boolean")
    if transport["request_present"] is not (request_bytes > 0):
        raise ValueError(f"{label}.request_present is not derived from request_bytes")
    if transport["response_present"] is not (response_bytes > 0):
        raise ValueError(f"{label}.response_present is not derived from response_bytes")
    elapsed_ns = _integer(transport["elapsed_ns"], f"{label}.elapsed_ns", 1)
    if transport["outcome"] not in {"RESPONSE", "TIMEOUT", "EOF", "ERROR"}:
        raise ValueError(f"{label}.outcome is invalid")
    if transport["outcome"] == "RESPONSE" and response_bytes < 2:
        raise ValueError(f"{label} successful response is empty")
    if transport["outcome"] == "RESPONSE" and transport["response_present"] is not True:
        raise ValueError(f"{label} successful response lacks response presence")
    if transport["outcome"] in {"TIMEOUT", "EOF"} and response_bytes != 0:
        raise ValueError(f"{label} terminal outcome has contradictory response bytes")
    if transport["elapsed_class"] not in {
        "NONZERO_NOT_LATENCY_CLAIM",
        "CONFIGURED_BACKEND_TIMEOUT_WINDOW",
        "CONFIGURED_PROXY_DELAY_WINDOW",
    }:
        raise ValueError(f"{label}.elapsed_class is invalid")
    transport_config = _mapping(_formal_config_spec()["transport"], "frozen transport")
    if transport["elapsed_class"] == "CONFIGURED_BACKEND_TIMEOUT_WINDOW":
        lower = int(transport_config["backend_client_timeout_ms"]) * 750_000
        upper = (
            int(transport_config["rpc_timeout_ms"])
            + int(transport_config["backend_timeout_server_ms"])
        ) * 4_000_000
        if transport["outcome"] != "TIMEOUT" or not lower <= elapsed_ns <= upper:
            raise ValueError(f"{label} violates the configured backend timeout window")
    elif transport["elapsed_class"] == "CONFIGURED_PROXY_DELAY_WINDOW":
        lower = int(transport_config["logical_delay_ms"]) * 750_000
        upper = (
            int(transport_config["rpc_timeout_ms"]) + int(transport_config["logical_delay_ms"])
        ) * 4_000_000
        if transport["outcome"] != "RESPONSE" or not lower <= elapsed_ns <= upper:
            raise ValueError(f"{label} violates the configured proxy delay window")
    elif transport["outcome"] == "TIMEOUT":
        raise ValueError(f"{label} timeout lacks the configured threshold class")
    if (
        transport["ephemeral_observation_classification"]
        != "RAW_SESSION_LOCAL_NOT_CROSS_RUN_SCALAR_EQUALITY"
    ):
        raise ValueError(f"{label} raw observation classification is invalid")
    _strict_hex(transport["connection_nonce_hex"], f"{label}.connection_nonce_hex", 64)
    connection_id = _strict_hex(transport["connection_id"], f"{label}.connection_id", 64)
    if connection_id != _connection_id(transport):
        raise ValueError(f"{label}.connection_id is not derived from the TCP observation")
    roles = {"coordinator", "edge", "backend", "transport-proxy"}
    if transport["caller_role"] not in roles or transport["callee_role"] not in roles:
        raise ValueError(f"{label} caller/callee role is invalid")
    _integer(transport["caller_pid"], f"{label}.caller_pid", 1)
    _integer(transport["callee_pid"], f"{label}.callee_pid", 1)
    _strict_hex(transport["caller_session_id"], f"{label}.caller_session_id", 64)
    _strict_hex(transport["callee_session_id"], f"{label}.callee_session_id", 64)
    expected_caller = f"{transport['client_host']}:{transport['client_port']}"
    expected_callee = f"{transport['server_host']}:{transport['server_port']}"
    if transport["caller_endpoint"] != expected_caller:
        raise ValueError(f"{label}.caller_endpoint does not match the observed TCP client")
    if transport["callee_endpoint"] != expected_callee:
        raise ValueError(f"{label}.callee_endpoint does not match the observed TCP server")
    return transport


def _validate_metrics(value: object, label: str) -> dict[str, Any]:
    metrics = _mapping(value, label)
    _exact_keys(
        metrics,
        {"data_plane", "positive_screen", "negative_cache", "singleflight"},
        label,
    )
    for component, counters_value in metrics.items():
        counters = _mapping(counters_value, f"{label}.{component}")
        for name, count in counters.items():
            if not name:
                raise ValueError(f"{label}.{component} has an empty counter name")
            _integer(count, f"{label}.{component}.{name}")
    return metrics


def _validate_backend_interaction(value: object, label: str) -> dict[str, Any]:
    interaction = _mapping(value, label)
    _exact_keys(
        interaction,
        {
            "operation",
            "fault",
            "completed_response",
            "failure_category",
            "result_kind",
            "backend_pid",
            "backend_session_id",
            "backend_endpoint",
            "backend_identity_source",
            "transport",
        },
        label,
    )
    if interaction["operation"] not in {"verify", "finalize"}:
        raise ValueError(f"{label}.operation is invalid")
    if interaction["fault"] not in BACKEND_FAULTS:
        raise ValueError(f"{label}.fault is invalid")
    if type(interaction["completed_response"]) is not bool:
        raise ValueError(f"{label}.completed_response must be Boolean")
    if (
        interaction["failure_category"] is not None
        and type(interaction["failure_category"]) is not str
    ):
        raise ValueError(f"{label}.failure_category is invalid")
    try:
        BackendResultKind(interaction["result_kind"])
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label}.result_kind is invalid") from error
    _integer(interaction["backend_pid"], f"{label}.backend_pid", 1)
    _strict_hex(interaction["backend_session_id"], f"{label}.backend_session_id", 64)
    if type(interaction["backend_endpoint"]) is not str or not interaction[
        "backend_endpoint"
    ].startswith(f"{HOST}:"):
        raise ValueError(f"{label}.backend_endpoint is invalid")
    if interaction["backend_identity_source"] not in {
        "RESPONSE_CROSS_CHECKED",
        "READY_REGISTRY_EXPECTED_NO_VALID_RESPONSE",
    }:
        raise ValueError(f"{label}.backend_identity_source is invalid")
    transport = _validate_rpc_transport(interaction["transport"], f"{label}.transport")
    if transport["caller_role"] != "edge" or transport["callee_role"] != "backend":
        raise ValueError(f"{label} is not an edge-to-backend RPC")
    if (
        transport["callee_pid"] != interaction["backend_pid"]
        or transport["callee_session_id"] != interaction["backend_session_id"]
        or transport["callee_endpoint"] != interaction["backend_endpoint"]
    ):
        raise ValueError(f"{label} backend identity is not cross-bound to its TCP RPC")
    if interaction["completed_response"] is True:
        if (
            interaction["failure_category"] is not None
            or transport["outcome"] != "RESPONSE"
            or interaction["backend_identity_source"] != "RESPONSE_CROSS_CHECKED"
        ):
            raise ValueError(f"{label} completed response metadata is contradictory")
    else:
        if (
            interaction["failure_category"] is None
            or interaction["backend_identity_source"] != "READY_REGISTRY_EXPECTED_NO_VALID_RESPONSE"
        ):
            raise ValueError(f"{label} failed response metadata is contradictory")
        if interaction["result_kind"] != BackendResultKind.TRANSIENT_FAILURE.value:
            raise ValueError(f"{label} RPC failure must become a typed transient failure")
    return interaction


def _validate_login(value: object, label: str) -> dict[str, Any]:
    login = _mapping(value, label)
    _exact_keys(
        login,
        {
            "label",
            "credential_class",
            "expected_valid",
            "accepted",
            "pre_screen_rejected",
            "route",
            "directory_status",
            "positive_disposition",
            "backend_kind",
            "backend_forwarded",
            "uncertainty_reason",
            "unavailable_authentication",
            "edge_pid",
            "edge_session_id",
            "edge_endpoint",
            "state_trusted",
            "state_id",
            "rpc",
            "backend_interactions",
            "component_metrics",
            "negative_cache_before",
            "negative_cache_after",
            "negative_cache_delta",
        },
        label,
    )
    if type(login["label"]) is not str or not login["label"]:
        raise ValueError(f"{label}.label is invalid")
    if login["credential_class"] not in {"VALID", "INVALID"}:
        raise ValueError(f"{label}.credential_class is invalid")
    for field in (
        "expected_valid",
        "accepted",
        "pre_screen_rejected",
        "backend_forwarded",
        "unavailable_authentication",
        "state_trusted",
    ):
        if type(login[field]) is not bool:
            raise ValueError(f"{label}.{field} must be Boolean")
    if login["expected_valid"] is not (login["credential_class"] == "VALID"):
        raise ValueError(f"{label}.expected_valid contradicts credential_class")
    if login["route"] not in {
        "BACKEND_MATCH",
        "BACKEND_DENY",
        "POSITIVE_SCREEN_REJECT",
        "NEGATIVE_CACHE_REJECT",
        "FAIL_OPEN_BACKEND",
    }:
        raise ValueError(f"{label}.route is invalid")
    if login["directory_status"] not in {item.value for item in DirectoryStatus}:
        raise ValueError(f"{label}.directory_status is invalid")
    if login["positive_disposition"] not in {None, "POSITIVE", "NEGATIVE", "FAIL_OPEN"}:
        raise ValueError(f"{label}.positive_disposition is invalid")
    if login["backend_kind"] is not None:
        try:
            BackendResultKind(login["backend_kind"])
        except (TypeError, ValueError) as error:
            raise ValueError(f"{label}.backend_kind is invalid") from error
    if login["uncertainty_reason"] is not None and (
        type(login["uncertainty_reason"]) is not str or not login["uncertainty_reason"]
    ):
        raise ValueError(f"{label}.uncertainty_reason is invalid")
    _integer(login["edge_pid"], f"{label}.edge_pid", 1)
    _strict_hex(login["edge_session_id"], f"{label}.edge_session_id", 64)
    endpoint = login["edge_endpoint"]
    if type(endpoint) is not str or not endpoint.startswith(f"{HOST}:"):
        raise ValueError(f"{label}.edge_endpoint is not loopback")
    state_id = _strict_hex(login["state_id"], f"{label}.state_id", 64)
    if not state_id:
        raise ValueError(f"{label}.state_id is empty")
    rpc = _validate_rpc_transport(login["rpc"], f"{label}.rpc")
    if rpc["caller_role"] != "coordinator" or rpc["callee_role"] != "edge":
        raise ValueError(f"{label}.rpc is not a coordinator-to-edge login RPC")
    if (
        endpoint != rpc["callee_endpoint"]
        or login["edge_pid"] != rpc["callee_pid"]
        or login["edge_session_id"] != rpc["callee_session_id"]
    ):
        raise ValueError(f"{label}.edge identity does not match its TCP RPC")
    interactions = login["backend_interactions"]
    if type(interactions) is not list:
        raise ValueError(f"{label}.backend_interactions must be an array")
    validated_interactions = [
        _validate_backend_interaction(item, f"{label}.backend_interactions[{index}]")
        for index, item in enumerate(interactions)
    ]
    verify_count = sum(item["operation"] == "verify" for item in validated_interactions)
    if verify_count not in {0, 1}:
        raise ValueError(f"{label} must have at most one external verify RPC")
    if login["backend_forwarded"] is not (verify_count == 1):
        raise ValueError(f"{label}.backend_forwarded is not derived from the RPC trace")
    for index, interaction in enumerate(validated_interactions):
        transport = interaction["transport"]
        if (
            transport["caller_pid"] != login["edge_pid"]
            or transport["caller_session_id"] != login["edge_session_id"]
        ):
            raise ValueError(
                f"{label}.backend_interactions[{index}] is not bound to the login edge"
            )
    if login["pre_screen_rejected"] is not (
        login["route"] in {"POSITIVE_SCREEN_REJECT", "NEGATIVE_CACHE_REJECT"}
    ):
        raise ValueError(f"{label}.pre_screen_rejected contradicts route")
    if login["uncertainty_reason"] is not None and login["backend_forwarded"] is not True:
        raise ValueError(f"{label} uncertainty did not reach the external backend")
    derived_unavailable = bool(
        login["expected_valid"] is True
        and login["accepted"] is False
        and login["backend_forwarded"] is True
        and login["backend_kind"] in UNCERTAIN_BACKEND_KINDS
    )
    if login["unavailable_authentication"] is not derived_unavailable:
        raise ValueError(f"{label}.unavailable_authentication is not derived")
    metrics = _validate_metrics(login["component_metrics"], f"{label}.component_metrics")
    cache_snapshots: dict[str, dict[str, Any]] = {}
    for field in ("negative_cache_before", "negative_cache_after"):
        counters = _mapping(login[field], f"{label}.{field}")
        if not counters:
            raise ValueError(f"{label}.{field} is empty")
        for name, count in counters.items():
            if not name:
                raise ValueError(f"{label}.{field} has an empty counter name")
            _integer(count, f"{label}.{field}.{name}")
        cache_snapshots[field] = counters
    delta = _mapping(login["negative_cache_delta"], f"{label}.negative_cache_delta")
    expected_delta = {
        name: int(cache_snapshots["negative_cache_after"].get(name, 0))
        - int(cache_snapshots["negative_cache_before"].get(name, 0))
        for name in sorted(
            cache_snapshots["negative_cache_before"].keys()
            | cache_snapshots["negative_cache_after"].keys()
        )
    }
    for name, count in delta.items():
        if not name or isinstance(count, bool) or not isinstance(count, int):
            raise ValueError(f"{label}.negative_cache_delta.{name} is invalid")
    _exact_value(delta, expected_delta, f"{label}.negative_cache_delta")
    _exact_value(
        metrics["negative_cache"],
        cache_snapshots["negative_cache_after"],
        f"{label} negative cache metric snapshot",
    )
    return login


def _validate_delay_barrier(
    value: object,
    label: str,
    *,
    proxy_pid: int,
    proxy_session_id: str,
    proxy_endpoint: str,
    message_id: str,
    sequence: int,
    producer_connection_id: str,
    delivery_connection_id: str,
) -> dict[str, Any]:
    barrier = _mapping(value, label)
    _exact_keys(
        barrier,
        {
            "barrier_id",
            "message_id",
            "sequence",
            "proxy_pid",
            "proxy_session_id",
            "proxy_endpoint",
            "entered_observation",
            "login_completion",
            "release",
            "delivery_gate",
            "causal_order",
        },
        label,
    )
    barrier_id = _strict_hex(barrier["barrier_id"], f"{label}.barrier_id", 64)
    if barrier_id != _delay_barrier_id(proxy_session_id, message_id, sequence):
        raise ValueError(f"{label}.barrier_id is not bound to proxy session/message")
    if (
        barrier["message_id"] != message_id
        or barrier["sequence"] != sequence
        or barrier["proxy_pid"] != proxy_pid
        or barrier["proxy_session_id"] != proxy_session_id
        or barrier["proxy_endpoint"] != proxy_endpoint
    ):
        raise ValueError(f"{label} top-level binding differs")
    if barrier["causal_order"] != [
        "DELAY_ENTERED",
        "LOGIN_COMPLETED",
        "DELAY_RELEASED",
        "EDGE_DELIVERY",
    ]:
        raise ValueError(f"{label}.causal_order differs")

    entered = _mapping(barrier["entered_observation"], f"{label}.entered_observation")
    _exact_keys(
        entered,
        {
            "event_ordinal",
            "status",
            "barrier_id",
            "message_id",
            "sequence",
            "proxy_pid",
            "proxy_session_id",
            "proxy_endpoint",
            "release_received",
            "delivery_started",
            "rpc",
        },
        f"{label}.entered_observation",
    )
    if (
        entered["event_ordinal"] != 0
        or entered["status"] != "DELAY_ENTERED"
        or entered["barrier_id"] != barrier_id
        or entered["message_id"] != message_id
        or entered["sequence"] != sequence
        or entered["proxy_pid"] != proxy_pid
        or entered["proxy_session_id"] != proxy_session_id
        or entered["proxy_endpoint"] != proxy_endpoint
        or entered["release_received"] is not False
        or entered["delivery_started"] is not False
    ):
        raise ValueError(f"{label}.entered_observation is contradictory")

    login_completion = _mapping(barrier["login_completion"], f"{label}.login_completion")
    _exact_keys(
        login_completion,
        {
            "event_ordinal",
            "login_label",
            "login_completion_id",
            "edge_session_id",
            "login_rpc_connection_id",
        },
        f"{label}.login_completion",
    )
    if login_completion["event_ordinal"] != 1 or type(login_completion["login_label"]) is not str:
        raise ValueError(f"{label}.login_completion identity is invalid")
    login_completion_id = _strict_hex(
        login_completion["login_completion_id"],
        f"{label}.login_completion.login_completion_id",
        64,
    )
    _strict_hex(
        login_completion["edge_session_id"],
        f"{label}.login_completion.edge_session_id",
        64,
    )
    login_connection_id = _strict_hex(
        login_completion["login_rpc_connection_id"],
        f"{label}.login_completion.login_rpc_connection_id",
        64,
    )

    release = _mapping(barrier["release"], f"{label}.release")
    _exact_keys(
        release,
        {
            "event_ordinal",
            "status",
            "barrier_id",
            "message_id",
            "sequence",
            "login_completion_id",
            "proxy_pid",
            "proxy_session_id",
            "proxy_endpoint",
            "release_received",
            "delivery_started",
            "rpc",
        },
        f"{label}.release",
    )
    if (
        release["event_ordinal"] != 2
        or release["status"] != "DELAY_RELEASED"
        or release["barrier_id"] != barrier_id
        or release["message_id"] != message_id
        or release["sequence"] != sequence
        or release["login_completion_id"] != login_completion_id
        or release["proxy_pid"] != proxy_pid
        or release["proxy_session_id"] != proxy_session_id
        or release["proxy_endpoint"] != proxy_endpoint
        or release["release_received"] is not True
        or release["delivery_started"] is not False
    ):
        raise ValueError(f"{label}.release is contradictory")

    gate = _mapping(barrier["delivery_gate"], f"{label}.delivery_gate")
    _exact_keys(
        gate,
        {
            "event_ordinal",
            "status",
            "barrier_id",
            "message_id",
            "sequence",
            "login_completion_id",
            "minimum_delay_satisfied",
            "release_received",
            "delivery_started_after_release",
        },
        f"{label}.delivery_gate",
    )
    if (
        gate["event_ordinal"] != 3
        or gate["status"] != "DELIVERY_PERMITTED"
        or gate["barrier_id"] != barrier_id
        or gate["message_id"] != message_id
        or gate["sequence"] != sequence
        or gate["login_completion_id"] != login_completion_id
        or gate["minimum_delay_satisfied"] is not True
        or gate["release_received"] is not True
        or gate["delivery_started_after_release"] is not True
    ):
        raise ValueError(f"{label}.delivery_gate lacks both release conditions")

    control_connection_ids = []
    for phase, phase_value in (("entered_observation", entered), ("release", release)):
        rpc = _validate_rpc_transport(phase_value["rpc"], f"{label}.{phase}.rpc")
        if (
            rpc["caller_role"] != "coordinator"
            or rpc["callee_role"] != "transport-proxy"
            or rpc["callee_pid"] != proxy_pid
            or rpc["callee_session_id"] != proxy_session_id
            or rpc["callee_endpoint"] != proxy_endpoint
            or rpc["outcome"] != "RESPONSE"
        ):
            raise ValueError(f"{label}.{phase}.rpc is not bound to the proxy session")
        control_connection_ids.append(rpc["connection_id"])
    all_connection_ids = [
        producer_connection_id,
        login_connection_id,
        delivery_connection_id,
        *control_connection_ids,
    ]
    if len(all_connection_ids) != len(set(all_connection_ids)):
        raise ValueError(f"{label} did not use independent causal RPC connections")
    return barrier


def _validate_transport_event(value: object, label: str) -> dict[str, Any]:
    event = _mapping(value, label)
    _exact_keys(
        event,
        {
            "label",
            "action",
            "producer_message_ids",
            "producer_sequences",
            "delivery_message_ids",
            "delivery_sequences",
            "edge_outcomes",
            "deliveries",
            "applied_count",
            "proxy_drop_count",
            "duplicate_count",
            "stale_count",
            "delay_ms",
            "proxy_pid",
            "proxy_session_id",
            "proxy_endpoint",
            "producer_rpc",
            "lease_expiry",
            "delay_barrier",
        },
        label,
    )
    if type(event["label"]) is not str or not event["label"]:
        raise ValueError(f"{label}.label is invalid")
    if event["action"] not in {"delay", "loss", "duplicate", "reorder", "recover"}:
        raise ValueError(f"{label}.action is invalid")
    producer_message_ids = event["producer_message_ids"]
    producer_sequences = event["producer_sequences"]
    delivery_message_ids = event["delivery_message_ids"]
    delivery_sequences = event["delivery_sequences"]
    outcomes = event["edge_outcomes"]
    deliveries = event["deliveries"]
    if (
        type(producer_message_ids) is not list
        or type(producer_sequences) is not list
        or type(delivery_message_ids) is not list
        or type(delivery_sequences) is not list
        or type(outcomes) is not list
        or type(deliveries) is not list
        or not producer_message_ids
        or len(producer_message_ids) != len(producer_sequences)
        or len(delivery_message_ids) != len(delivery_sequences)
        or len(delivery_message_ids) != len(outcomes)
        or len(delivery_message_ids) != len(deliveries)
    ):
        raise ValueError(f"{label} message arrays are misaligned")
    if any(
        type(item) is not str or not item for item in producer_message_ids + delivery_message_ids
    ):
        raise ValueError(f"{label} message IDs are invalid")
    for sequence in producer_sequences + delivery_sequences:
        _integer(sequence, f"{label}.sequence", 1)
    if any(item not in {"APPLIED", "DROPPED", "DUPLICATE", "STALE"} for item in outcomes):
        raise ValueError(f"{label}.outcomes are invalid")
    validated_deliveries: list[dict[str, Any]] = []
    for index, delivery_value in enumerate(deliveries):
        delivery = _mapping(delivery_value, f"{label}.deliveries[{index}]")
        _exact_keys(
            delivery,
            {
                "delivery_index",
                "message_id",
                "sequence",
                "edge_outcome",
                "response_present",
                "edge_pid",
                "edge_session_id",
                "edge_endpoint",
                "rpc",
            },
            f"{label}.deliveries[{index}]",
        )
        if delivery["delivery_index"] != index or isinstance(delivery["delivery_index"], bool):
            raise ValueError(f"{label}.deliveries[{index}] has the wrong delivery index")
        if (
            delivery["message_id"] != delivery_message_ids[index]
            or delivery["sequence"] != delivery_sequences[index]
            or delivery["edge_outcome"] != outcomes[index]
        ):
            raise ValueError(f"{label}.deliveries[{index}] is not aligned with its arrays")
        if delivery["response_present"] is not True:
            raise ValueError(f"{label}.deliveries[{index}] lacks an edge response")
        _integer(delivery["edge_pid"], f"{label}.deliveries[{index}].edge_pid", 1)
        _strict_hex(
            delivery["edge_session_id"],
            f"{label}.deliveries[{index}].edge_session_id",
            64,
        )
        if type(delivery["edge_endpoint"]) is not str or not delivery["edge_endpoint"].startswith(
            f"{HOST}:"
        ):
            raise ValueError(f"{label}.deliveries[{index}].edge_endpoint is invalid")
        rpc = _validate_rpc_transport(delivery["rpc"], f"{label}.deliveries[{index}].rpc")
        if rpc["caller_role"] != "transport-proxy" or rpc["callee_role"] != "edge":
            raise ValueError(f"{label}.deliveries[{index}] is not proxy-to-edge")
        if (
            rpc["callee_pid"] != delivery["edge_pid"]
            or rpc["callee_session_id"] != delivery["edge_session_id"]
            or rpc["callee_endpoint"] != delivery["edge_endpoint"]
            or rpc["response_present"] is not delivery["response_present"]
        ):
            raise ValueError(f"{label}.deliveries[{index}] edge identity is not cross-bound")
        validated_deliveries.append(delivery)
    derived = {
        "applied_count": outcomes.count("APPLIED"),
        "duplicate_count": outcomes.count("DUPLICATE"),
        "stale_count": outcomes.count("STALE"),
    }
    for field, expected in derived.items():
        if event[field] != expected or isinstance(event[field], bool):
            raise ValueError(f"{label}.{field} is not derived")
    delay_ms = _integer(event["delay_ms"], f"{label}.delay_ms")
    frozen_transport = _mapping(_formal_config_spec()["transport"], "frozen transport config")
    expected_delay = int(frozen_transport["logical_delay_ms"]) if event["action"] == "delay" else 0
    if delay_ms != expected_delay:
        raise ValueError(f"{label}.delay_ms violates the frozen action contract")
    _integer(event["proxy_pid"], f"{label}.proxy_pid", 1)
    _strict_hex(event["proxy_session_id"], f"{label}.proxy_session_id", 64)
    if type(event["proxy_endpoint"]) is not str or not event["proxy_endpoint"].startswith(
        f"{HOST}:"
    ):
        raise ValueError(f"{label}.proxy_endpoint is invalid")
    producer_rpc = _validate_rpc_transport(event["producer_rpc"], f"{label}.producer_rpc")
    if (
        producer_rpc["caller_role"] != "coordinator"
        or producer_rpc["callee_role"] != "transport-proxy"
        or producer_rpc["callee_pid"] != event["proxy_pid"]
        or producer_rpc["callee_session_id"] != event["proxy_session_id"]
        or producer_rpc["callee_endpoint"] != event["proxy_endpoint"]
        or producer_rpc["outcome"] != "RESPONSE"
    ):
        raise ValueError(f"{label}.producer_rpc is not bound to the transport proxy")
    expected_elapsed_class = (
        "CONFIGURED_PROXY_DELAY_WINDOW"
        if event["action"] == "delay"
        else "NONZERO_NOT_LATENCY_CLAIM"
    )
    if producer_rpc["elapsed_class"] != expected_elapsed_class:
        raise ValueError(f"{label}.producer_rpc has the wrong elapsed class")
    for index, delivery in enumerate(validated_deliveries):
        rpc = delivery["rpc"]
        if (
            rpc["caller_pid"] != event["proxy_pid"]
            or rpc["caller_session_id"] != event["proxy_session_id"]
        ):
            raise ValueError(f"{label}.deliveries[{index}] is not bound to this proxy")
    connection_ids = [delivery["rpc"]["connection_id"] for delivery in validated_deliveries]
    if len(connection_ids) != len(set(connection_ids)):
        raise ValueError(f"{label} reused a proxy-to-edge TCP connection identity")
    if event["action"] == "delay":
        if len(producer_message_ids) != 1 or len(connection_ids) != 1:
            raise ValueError(f"{label} delay requires one message and one delivery")
        _validate_delay_barrier(
            event["delay_barrier"],
            f"{label}.delay_barrier",
            proxy_pid=event["proxy_pid"],
            proxy_session_id=event["proxy_session_id"],
            proxy_endpoint=event["proxy_endpoint"],
            message_id=producer_message_ids[0],
            sequence=producer_sequences[0],
            producer_connection_id=producer_rpc["connection_id"],
            delivery_connection_id=connection_ids[0],
        )
    elif event["delay_barrier"] is not None:
        raise ValueError(f"{label} non-delay action carries a delay barrier")
    drop_count = _integer(event["proxy_drop_count"], f"{label}.proxy_drop_count")
    if event["action"] == "loss":
        if (
            drop_count != len(producer_message_ids)
            or deliveries
            or delivery_message_ids
            or outcomes
        ):
            raise ValueError(f"{label} loss did not stop at the independent proxy")
    elif drop_count != 0:
        raise ValueError(f"{label} non-loss action reported a proxy drop")
    if event["action"] in {"delay", "recover"} and (
        producer_message_ids != delivery_message_ids
        or producer_sequences != delivery_sequences
        or outcomes != ["APPLIED"]
    ):
        raise ValueError(f"{label} single delivery action is contradictory")
    if event["action"] == "duplicate" and (
        len(producer_message_ids) != 1
        or delivery_message_ids != producer_message_ids * 2
        or delivery_sequences != producer_sequences * 2
        or outcomes != ["APPLIED", "DUPLICATE"]
        or len(connection_ids) != 2
    ):
        raise ValueError(f"{label} duplicate was not two independent edge deliveries")
    if event["action"] == "reorder" and (
        len(producer_message_ids) != 2
        or delivery_message_ids != list(reversed(producer_message_ids))
        or delivery_sequences != list(reversed(producer_sequences))
        or outcomes != ["APPLIED", "STALE"]
        or len(connection_ids) != 2
    ):
        raise ValueError(f"{label} reorder was not reverse delivery over two connections")
    lease_value = event["lease_expiry"]
    if event["action"] in {"delay", "loss", "duplicate", "reorder"}:
        lease = _mapping(lease_value, f"{label}.lease_expiry")
        _exact_keys(
            lease,
            {
                "lease_id",
                "edge_pid",
                "edge_session_id",
                "edge_endpoint",
                "state_id",
                "ready",
                "rpc",
            },
            f"{label}.lease_expiry",
        )
        if type(lease["lease_id"]) is not str or not lease["lease_id"]:
            raise ValueError(f"{label}.lease_expiry.lease_id is invalid")
        _integer(lease["edge_pid"], f"{label}.lease_expiry.edge_pid", 1)
        _strict_hex(lease["edge_session_id"], f"{label}.lease_expiry.edge_session_id", 64)
        _strict_hex(lease["state_id"], f"{label}.lease_expiry.state_id", 64)
        if lease["ready"] is not False:
            raise ValueError(f"{label}.lease_expiry did not make the directory uncertain")
        lease_rpc = _validate_rpc_transport(lease["rpc"], f"{label}.lease_expiry.rpc")
        if (
            lease_rpc["caller_role"] != "coordinator"
            or lease_rpc["callee_role"] != "edge"
            or lease_rpc["callee_pid"] != lease["edge_pid"]
            or lease_rpc["callee_session_id"] != lease["edge_session_id"]
            or lease_rpc["callee_endpoint"] != lease["edge_endpoint"]
            or lease_rpc["outcome"] != "RESPONSE"
        ):
            raise ValueError(f"{label}.lease_expiry is not bound to its edge RPC")
        if any(
            delivery["edge_pid"] != lease["edge_pid"]
            or delivery["edge_session_id"] != lease["edge_session_id"]
            or delivery["edge_endpoint"] != lease["edge_endpoint"]
            for delivery in validated_deliveries
        ):
            raise ValueError(f"{label} delivered to an edge other than the lease-expired edge")
    elif lease_value is not None:
        raise ValueError(f"{label} recovery action unexpectedly carries a lease expiry")
    return event


def _validate_process_event(value: object, label: str) -> dict[str, Any]:
    event = _mapping(value, label)
    _exact_keys(
        event,
        {
            "role",
            "action",
            "pid",
            "session_nonce_hex",
            "session_id",
            "endpoint",
            "exit_code",
            "exit_class",
            "state_id",
            "state_trusted",
            "random_observation_classification",
        },
        label,
    )
    process_roles = {"coordinator", "edge", "backend", "transport-proxy"}
    if event["role"] not in process_roles | {"edge-state-file"}:
        raise ValueError(f"{label}.role is invalid")
    if event["action"] not in {"START", "EXIT", "RESTART", "CORRUPT_STATE"}:
        raise ValueError(f"{label}.action is invalid")
    if (
        event["random_observation_classification"]
        != "SESSION_LOCAL_RELATIONAL_NOT_CROSS_RUN_SCALAR_EQUALITY"
    ):
        raise ValueError(f"{label}.random_observation_classification is invalid")
    if event["role"] in process_roles:
        pid = _integer(event["pid"], f"{label}.pid", 1)
        nonce = _strict_hex(event["session_nonce_hex"], f"{label}.session_nonce_hex", 64)
        session_id = _strict_hex(event["session_id"], f"{label}.session_id", 64)
        if session_id != _session_id(event["role"], pid, nonce):
            raise ValueError(f"{label}.session_id is not derived from role, PID, and nonce")
    elif (
        event["pid"] is not None
        or event["session_nonce_hex"] is not None
        or event["session_id"] is not None
    ):
        raise ValueError(f"{label} state-file event carries a process identity")
    if event["endpoint"] is not None and (
        type(event["endpoint"]) is not str or not event["endpoint"].startswith(f"{HOST}:")
    ):
        raise ValueError(f"{label}.endpoint is invalid")
    if event["exit_code"] is not None and (
        isinstance(event["exit_code"], bool) or not isinstance(event["exit_code"], int)
    ):
        raise ValueError(f"{label}.exit_code is invalid")
    if event["state_id"] is not None:
        _strict_hex(event["state_id"], f"{label}.state_id", 64)
    if event["state_trusted"] is not None and type(event["state_trusted"]) is not bool:
        raise ValueError(f"{label}.state_trusted is invalid")
    if event["role"] == "coordinator" and event["endpoint"] is not None:
        raise ValueError(f"{label} coordinator must not claim a listening endpoint")
    if event["role"] in {"edge", "backend", "transport-proxy"} and event["endpoint"] is None:
        raise ValueError(f"{label} child process lacks a listening endpoint")
    if event["role"] in {"coordinator", "transport-proxy"} and (
        event["state_id"] is not None or event["state_trusted"] is not None
    ):
        raise ValueError(f"{label} stateless process carries edge/backend state")
    if event["action"] == "EXIT" and (
        event["pid"] is None or event["endpoint"] is None or event["exit_code"] is None
    ):
        raise ValueError(f"{label} exit evidence is incomplete")
    if event["action"] == "EXIT":
        expected_exit_class = (
            "APPLICATION_CRASH_73"
            if event["role"] == "backend" and event["exit_code"] == 73
            else "FORCED_TERMINATION_NONZERO"
            if event["exit_code"] != 0
            else "CLEAN_EXIT"
        )
        if event["exit_class"] != expected_exit_class:
            raise ValueError(f"{label}.exit_class is not derived")
        if expected_exit_class == "CLEAN_EXIT":
            raise ValueError(f"{label} claim-bearing exit must be nonzero")
    if event["action"] in {"START", "RESTART"} and (
        event["pid"] is None
        or (event["role"] != "coordinator" and event["endpoint"] is None)
        or event["exit_code"] is not None
        or event["exit_class"] is not None
    ):
        raise ValueError(f"{label} start evidence is incomplete")
    if event["role"] == "coordinator" and event["action"] != "START":
        raise ValueError(f"{label} coordinator lifecycle action is invalid")
    if event["role"] == "transport-proxy" and event["action"] != "START":
        raise ValueError(f"{label} transport proxy lifecycle action is invalid")
    if event["action"] == "CORRUPT_STATE" and (
        event["role"] != "edge-state-file"
        or event["pid"] is not None
        or event["endpoint"] is not None
        or event["exit_code"] is not None
        or event["exit_class"] is not None
        or event["state_trusted"] is not False
    ):
        raise ValueError(f"{label} corruption evidence is incomplete")
    return event


def _validate_check(value: object, label: str) -> dict[str, Any]:
    check = _mapping(value, label)
    _exact_keys(check, {"name", "passed"}, label)
    if type(check["name"]) is not str or not check["name"] or type(check["passed"]) is not bool:
        raise ValueError(f"{label} is invalid")
    return check


def _login_contract(
    label: str,
    credential_class: str,
    accepted: bool,
    route: str,
    directory_status: str,
    positive_disposition: str | None,
    backend_kind: str | None,
    backend_forwarded: bool,
    uncertainty_reason: str | None,
    unavailable_authentication: bool,
    state_trusted: bool,
    backend_trace: Sequence[tuple[str, str, bool, str]],
) -> dict[str, object]:
    return {
        "label": label,
        "credential_class": credential_class,
        "expected_valid": credential_class == "VALID",
        "accepted": accepted,
        "pre_screen_rejected": route in {"POSITIVE_SCREEN_REJECT", "NEGATIVE_CACHE_REJECT"},
        "route": route,
        "directory_status": directory_status,
        "positive_disposition": positive_disposition,
        "backend_kind": backend_kind,
        "backend_forwarded": backend_forwarded,
        "uncertainty_reason": uncertainty_reason,
        "unavailable_authentication": unavailable_authentication,
        "state_trusted": state_trusted,
        "backend_trace": [list(item) for item in backend_trace],
    }


_MATCH_TRACE = (
    ("verify", "normal", True, BackendResultKind.MATCH.value),
    ("finalize", "normal", True, BackendResultKind.MATCH.value),
)
_LOGIN_CONTRACT_TEMPLATE: dict[str, object] = {
    "core_path_probe": [
        _login_contract(
            "invalid-first-backend-mismatch",
            "INVALID",
            False,
            "BACKEND_DENY",
            "PRESENT",
            "POSITIVE",
            BackendResultKind.CREDENTIAL_MISMATCH.value,
            True,
            None,
            False,
            True,
            (
                (
                    "verify",
                    "normal",
                    True,
                    BackendResultKind.CREDENTIAL_MISMATCH.value,
                ),
            ),
        ),
        _login_contract(
            "invalid-second-exact-cache-hit",
            "INVALID",
            False,
            "NEGATIVE_CACHE_REJECT",
            "PRESENT",
            None,
            None,
            False,
            None,
            False,
            True,
            (),
        ),
        _login_contract(
            "valid-after-core-path-probe",
            "VALID",
            True,
            "BACKEND_MATCH",
            "PRESENT",
            "POSITIVE",
            BackendResultKind.MATCH.value,
            True,
            None,
            False,
            True,
            _MATCH_TRACE,
        ),
    ],
    "transport_delay": [
        _login_contract(
            "valid-during-logical-delay",
            "VALID",
            True,
            "FAIL_OPEN_BACKEND",
            "UNCERTAIN",
            None,
            BackendResultKind.MATCH.value,
            True,
            "DIRECTORY_UNCERTAIN_DURING_DELAY",
            False,
            True,
            _MATCH_TRACE,
        ),
        _login_contract(
            "valid-after-logical-delay",
            "VALID",
            True,
            "BACKEND_MATCH",
            "PRESENT",
            "POSITIVE",
            BackendResultKind.MATCH.value,
            True,
            None,
            False,
            True,
            _MATCH_TRACE,
        ),
    ],
    "transport_loss": [
        _login_contract(
            "valid-after-logical-message-loss",
            "VALID",
            True,
            "FAIL_OPEN_BACKEND",
            "UNCERTAIN",
            None,
            BackendResultKind.MATCH.value,
            True,
            "DIRECTORY_UNCERTAIN_AFTER_LOSS",
            False,
            True,
            _MATCH_TRACE,
        ),
        _login_contract(
            "valid-after-loss-recovery",
            "VALID",
            True,
            "BACKEND_MATCH",
            "PRESENT",
            "POSITIVE",
            BackendResultKind.MATCH.value,
            True,
            None,
            False,
            True,
            _MATCH_TRACE,
        ),
    ],
    "transport_duplicate": [
        _login_contract(
            "valid-after-duplicate-message",
            "VALID",
            True,
            "BACKEND_MATCH",
            "PRESENT",
            "POSITIVE",
            BackendResultKind.MATCH.value,
            True,
            None,
            False,
            True,
            _MATCH_TRACE,
        )
    ],
    "transport_reorder": [
        _login_contract(
            "valid-after-reordered-messages",
            "VALID",
            True,
            "BACKEND_MATCH",
            "PRESENT",
            "POSITIVE",
            BackendResultKind.MATCH.value,
            True,
            None,
            False,
            True,
            _MATCH_TRACE,
        )
    ],
    "edge_kill_restart_persistence": [
        _login_contract(
            "valid-after-edge-process-restart",
            "VALID",
            True,
            "BACKEND_MATCH",
            "PRESENT",
            "POSITIVE",
            BackendResultKind.MATCH.value,
            True,
            None,
            False,
            True,
            _MATCH_TRACE,
        )
    ],
    "edge_corrupt_state_fail_open": [
        _login_contract(
            "valid-with-corrupt-persistent-state",
            "VALID",
            True,
            "FAIL_OPEN_BACKEND",
            "UNCERTAIN",
            None,
            BackendResultKind.MATCH.value,
            True,
            "CORRUPT_PERSISTENT_STATE",
            False,
            False,
            _MATCH_TRACE,
        ),
        _login_contract(
            "valid-after-corrupt-state-recovery-restart",
            "VALID",
            True,
            "BACKEND_MATCH",
            "PRESENT",
            "POSITIVE",
            BackendResultKind.MATCH.value,
            True,
            None,
            False,
            True,
            _MATCH_TRACE,
        ),
    ],
}

for _coordinate, _fault, _kind, _completed in (
    ("backend_timeout", "timeout", BackendResultKind.TRANSIENT_FAILURE.value, False),
    ("backend_drop", "drop", BackendResultKind.TRANSIENT_FAILURE.value, False),
    ("backend_malformed", "malformed", BackendResultKind.TRANSIENT_FAILURE.value, False),
    (
        "backend_typed_transient_failure",
        "typed_transient_failure",
        BackendResultKind.TRANSIENT_FAILURE.value,
        True,
    ),
    (
        "backend_typed_partial_failure",
        "typed_partial_failure",
        BackendResultKind.PARTIAL_AUTHENTICATOR_FAILURE.value,
        True,
    ),
):
    _LOGIN_CONTRACT_TEMPLATE[_coordinate] = [
        _login_contract(
            f"valid-during-{_fault}",
            "VALID",
            False,
            "FAIL_OPEN_BACKEND",
            "PRESENT",
            "POSITIVE",
            _kind,
            True,
            f"BACKEND_{_fault.upper()}",
            True,
            True,
            (("verify", _fault, _completed, _kind),),
        ),
        _login_contract(
            f"valid-after-{_fault}-recovery",
            "VALID",
            True,
            "BACKEND_MATCH",
            "PRESENT",
            "POSITIVE",
            BackendResultKind.MATCH.value,
            True,
            None,
            False,
            True,
            _MATCH_TRACE,
        ),
    ]

_LOGIN_CONTRACT_TEMPLATE["backend_crash_restart"] = [
    _login_contract(
        "valid-during-backend-process-crash",
        "VALID",
        False,
        "FAIL_OPEN_BACKEND",
        "PRESENT",
        "POSITIVE",
        BackendResultKind.TRANSIENT_FAILURE.value,
        True,
        "BACKEND_PROCESS_CRASH",
        True,
        True,
        (("verify", "crash", False, BackendResultKind.TRANSIENT_FAILURE.value),),
    ),
    _login_contract(
        "valid-after-backend-process-restart",
        "VALID",
        True,
        "BACKEND_MATCH",
        "PRESENT",
        "POSITIVE",
        BackendResultKind.MATCH.value,
        True,
        None,
        False,
        True,
        _MATCH_TRACE,
    ),
]
_login_contract_spec = _frozen_factory(_LOGIN_CONTRACT_TEMPLATE)

_CHECK_NAMES_TEMPLATE: dict[str, object] = {
    "core_path_probe": [
        "first-invalid-reached-typed-backend-and-was-denied",
        "second-invalid-hit-exact-negative-cache",
        "valid-credential-was-not-prescreen-rejected",
        "negative-cache-insert-and-hit-executed",
        "singleflight-leader-executed",
    ],
    "transport_delay": [
        "delay-window-observed-before-apply",
        "delay-barrier-entered-login-release-delivery-order",
        "valid-during-delay-failed-open-to-backend",
        "delayed-message-eventually-applied",
        "delay-proxy-used-one-edge-delivery-connection",
        "post-delay-valid-login-recovered",
    ],
    "transport_loss": [
        "logical-message-was-dropped",
        "loss-proxy-made-zero-edge-deliveries",
        "valid-after-loss-failed-open-to-backend",
        "loss-recovery-message-applied",
        "post-loss-valid-login-recovered",
    ],
    "transport_duplicate": [
        "duplicate-message-was-idempotent",
        "duplicate-proxy-made-two-independent-edge-connections",
        "valid-after-duplicate-was-not-prescreen-rejected",
    ],
    "transport_reorder": [
        "newer-message-applied-and-stale-message-rejected",
        "reorder-proxy-delivered-reversed-over-two-connections",
        "valid-after-reorder-was-not-prescreen-rejected",
    ],
    "edge_kill_restart_persistence": [
        "edge-process-exited-after-kill",
        "edge-restart-has-new-pid",
        "persistent-state-identity-restored",
        "valid-after-restart-was-not-prescreen-rejected",
        "volatile-negative-cache-cleared-on-restart",
    ],
    "edge_corrupt_state_fail_open": [
        "corrupt-state-was-not-trusted",
        "corrupt-state-valid-login-failed-open-to-backend",
        "authoritative-recovery-message-applied",
        "recovered-state-survived-process-restart",
        "valid-after-corrupt-recovery-authenticated",
    ],
    "backend_timeout": [
        "faulted-valid-login-reached-external-backend",
        "backend-uncertainty-was-not-a-prescreen-reject",
        "backend-recovery-valid-login-authenticated",
        "backend-uncertainty-did-not-write-negative-cache",
    ],
    "backend_drop": [
        "faulted-valid-login-reached-external-backend",
        "backend-uncertainty-was-not-a-prescreen-reject",
        "backend-recovery-valid-login-authenticated",
        "backend-uncertainty-did-not-write-negative-cache",
    ],
    "backend_malformed": [
        "faulted-valid-login-reached-external-backend",
        "backend-uncertainty-was-not-a-prescreen-reject",
        "backend-recovery-valid-login-authenticated",
        "backend-uncertainty-did-not-write-negative-cache",
    ],
    "backend_typed_transient_failure": [
        "faulted-valid-login-reached-external-backend",
        "backend-uncertainty-was-not-a-prescreen-reject",
        "backend-recovery-valid-login-authenticated",
        "backend-uncertainty-did-not-write-negative-cache",
    ],
    "backend_typed_partial_failure": [
        "faulted-valid-login-reached-external-backend",
        "backend-uncertainty-was-not-a-prescreen-reject",
        "backend-recovery-valid-login-authenticated",
        "backend-uncertainty-did-not-write-negative-cache",
    ],
    "backend_crash_restart": [
        "backend-crash-valid-login-was-forwarded-not-prescreen-rejected",
        "backend-process-exited-with-crash-code",
        "backend-restart-has-new-pid",
        "backend-restart-valid-login-authenticated",
        "backend-crash-did-not-write-negative-cache",
    ],
}
_check_names_spec = _frozen_factory(_CHECK_NAMES_TEMPLATE)

_TRANSPORT_CONTRACT_TEMPLATE: dict[str, object] = {
    "core_path_probe": [],
    "transport_delay": [
        {
            "label": "delayed-recovery-message",
            "action": "delay",
            "producer_message_ids": ["message-delay-1"],
            "producer_sequences": [1],
            "delivery_message_ids": ["message-delay-1"],
            "delivery_sequences": [1],
            "edge_outcomes": ["APPLIED"],
            "proxy_drop_count": 0,
            "delay_ms": 120,
        }
    ],
    "transport_loss": [
        {
            "label": "lost-recovery-message",
            "action": "loss",
            "producer_message_ids": ["message-loss-2"],
            "producer_sequences": [2],
            "delivery_message_ids": [],
            "delivery_sequences": [],
            "edge_outcomes": [],
            "proxy_drop_count": 1,
            "delay_ms": 0,
        },
        {
            "label": "loss-recovery-redelivery",
            "action": "recover",
            "producer_message_ids": ["message-loss-recovery-2"],
            "producer_sequences": [2],
            "delivery_message_ids": ["message-loss-recovery-2"],
            "delivery_sequences": [2],
            "edge_outcomes": ["APPLIED"],
            "proxy_drop_count": 0,
            "delay_ms": 0,
        },
    ],
    "transport_duplicate": [
        {
            "label": "duplicate-recovery-message",
            "action": "duplicate",
            "producer_message_ids": ["message-duplicate-3"],
            "producer_sequences": [3],
            "delivery_message_ids": ["message-duplicate-3", "message-duplicate-3"],
            "delivery_sequences": [3, 3],
            "edge_outcomes": ["APPLIED", "DUPLICATE"],
            "proxy_drop_count": 0,
            "delay_ms": 0,
        }
    ],
    "transport_reorder": [
        {
            "label": "reordered-recovery-messages",
            "action": "reorder",
            "producer_message_ids": ["message-reorder-old-4", "message-reorder-new-5"],
            "producer_sequences": [4, 5],
            "delivery_message_ids": ["message-reorder-new-5", "message-reorder-old-4"],
            "delivery_sequences": [5, 4],
            "edge_outcomes": ["APPLIED", "STALE"],
            "proxy_drop_count": 0,
            "delay_ms": 0,
        }
    ],
    "edge_kill_restart_persistence": [],
    "edge_corrupt_state_fail_open": [
        {
            "label": "corrupt-state-authoritative-recovery",
            "action": "recover",
            "producer_message_ids": ["message-corrupt-recovery-6"],
            "producer_sequences": [6],
            "delivery_message_ids": ["message-corrupt-recovery-6"],
            "delivery_sequences": [6],
            "edge_outcomes": ["APPLIED"],
            "proxy_drop_count": 0,
            "delay_ms": 0,
        }
    ],
    "backend_timeout": [],
    "backend_drop": [],
    "backend_malformed": [],
    "backend_typed_transient_failure": [],
    "backend_typed_partial_failure": [],
    "backend_crash_restart": [],
}
_transport_contract_spec = _frozen_factory(_TRANSPORT_CONTRACT_TEMPLATE)

_PROCESS_CONTRACT_TEMPLATE: dict[str, object] = {coordinate: [] for coordinate in COORDINATES}
_PROCESS_CONTRACT_TEMPLATE["core_path_probe"] = [
    ["coordinator", "START", None],
    ["backend", "START", True],
    ["edge", "START", True],
    ["transport-proxy", "START", None],
]
_PROCESS_CONTRACT_TEMPLATE["edge_kill_restart_persistence"] = [
    ["edge", "EXIT", True],
    ["edge", "RESTART", True],
]
_PROCESS_CONTRACT_TEMPLATE["edge_corrupt_state_fail_open"] = [
    ["edge", "EXIT", True],
    ["edge-state-file", "CORRUPT_STATE", False],
    ["edge", "RESTART", False],
    ["edge", "EXIT", True],
    ["edge", "RESTART", True],
]
_PROCESS_CONTRACT_TEMPLATE["backend_crash_restart"] = [
    ["backend", "EXIT", True],
    ["backend", "RESTART", True],
]
_process_contract_spec = _frozen_factory(_PROCESS_CONTRACT_TEMPLATE)


def validate_row(value: object, coordinate: str) -> dict[str, Any]:
    policy = _artifact_policy_spec()
    row = _mapping(value, f"row {coordinate}")
    _exact_keys(
        row,
        {
            "schema",
            "coordinate",
            "fault_class",
            "logins",
            "transport_events",
            "process_events",
            "checks",
            "summary",
            "status",
            "row_id",
        },
        f"row {coordinate}",
    )
    if row["schema"] != policy["row_schema"] or row["coordinate"] != coordinate:
        raise ValueError(f"row {coordinate} identity mismatch")
    if row["fault_class"] != coordinate.split("_", 1)[0].upper():
        raise ValueError(f"row {coordinate} fault class mismatch")
    for field in ("logins", "transport_events", "process_events", "checks"):
        if type(row[field]) is not list:
            raise ValueError(f"row {coordinate}.{field} must be an array")
    logins = [
        _validate_login(item, f"row {coordinate}.logins[{index}]")
        for index, item in enumerate(row["logins"])
    ]
    transport_events = [
        _validate_transport_event(item, f"row {coordinate}.transport_events[{index}]")
        for index, item in enumerate(row["transport_events"])
    ]
    process_events = [
        _validate_process_event(item, f"row {coordinate}.process_events[{index}]")
        for index, item in enumerate(row["process_events"])
    ]
    checks = [
        _validate_check(item, f"row {coordinate}.checks[{index}]")
        for index, item in enumerate(row["checks"])
    ]
    login_projection = []
    for login in logins:
        login_projection.append(
            {
                field: login[field]
                for field in (
                    "label",
                    "credential_class",
                    "expected_valid",
                    "accepted",
                    "pre_screen_rejected",
                    "route",
                    "directory_status",
                    "positive_disposition",
                    "backend_kind",
                    "backend_forwarded",
                    "uncertainty_reason",
                    "unavailable_authentication",
                    "state_trusted",
                )
            }
        )
        login_projection[-1]["backend_trace"] = [
            [
                interaction["operation"],
                interaction["fault"],
                interaction["completed_response"],
                interaction["result_kind"],
            ]
            for interaction in login["backend_interactions"]
        ]
    expected_logins = _mapping(_login_contract_spec(), "login contracts")[coordinate]
    _exact_value(login_projection, expected_logins, f"row {coordinate} login contract")
    if any(item["expected_valid"] and item["pre_screen_rejected"] for item in logins):
        raise ValueError(f"row {coordinate} contains a structural false reject")
    if any(not item["passed"] for item in checks):
        raise ValueError(f"row {coordinate} contains a failed evidence check")
    expected_check_names = _mapping(_check_names_spec(), "check contracts")[coordinate]
    _exact_value(
        [item["name"] for item in checks],
        expected_check_names,
        f"row {coordinate} check names",
    )
    transport_projection = [
        {
            field: event[field]
            for field in (
                "label",
                "action",
                "producer_message_ids",
                "producer_sequences",
                "delivery_message_ids",
                "delivery_sequences",
                "edge_outcomes",
                "proxy_drop_count",
                "delay_ms",
            )
        }
        for event in transport_events
    ]
    expected_transport = _mapping(_transport_contract_spec(), "transport contracts")[coordinate]
    _exact_value(
        transport_projection,
        expected_transport,
        f"row {coordinate} transport contract",
    )
    process_projection = [
        [event["role"], event["action"], event["state_trusted"]] for event in process_events
    ]
    expected_process = _mapping(_process_contract_spec(), "process contracts")[coordinate]
    _exact_value(
        process_projection,
        expected_process,
        f"row {coordinate} process contract",
    )
    if coordinate == "transport_delay" and tuple(item["action"] for item in transport_events) != (
        "delay",
    ):
        raise ValueError("transport delay row lacks its delay event")
    if coordinate == "transport_delay":
        barrier = _mapping(transport_events[0]["delay_barrier"], "transport delay barrier")
        completion = _mapping(
            barrier["login_completion"],
            "transport delay login completion",
        )
        during_delay = logins[0]
        if (
            completion["login_label"] != during_delay["label"]
            or completion["login_completion_id"] != _login_completion_id(during_delay)
            or completion["edge_session_id"] != during_delay["edge_session_id"]
            or completion["login_rpc_connection_id"] != during_delay["rpc"]["connection_id"]
        ):
            raise ValueError("transport delay release is not bound to the completed login")
    if coordinate == "transport_loss" and tuple(item["action"] for item in transport_events) != (
        "loss",
        "recover",
    ):
        raise ValueError("transport loss row lacks loss and recovery events")
    if coordinate == "transport_duplicate" and tuple(
        item["action"] for item in transport_events
    ) != ("duplicate",):
        raise ValueError("transport duplicate row lacks its duplicate event")
    if coordinate == "transport_reorder" and tuple(item["action"] for item in transport_events) != (
        "reorder",
    ):
        raise ValueError("transport reorder row lacks its reorder event")
    if coordinate == "edge_kill_restart_persistence":
        if tuple(item["action"] for item in process_events) != ("EXIT", "RESTART"):
            raise ValueError("edge persistence row lacks exact exit/restart evidence")
        if process_events[0]["pid"] == process_events[1]["pid"]:
            raise ValueError("edge restart reused the exited PID")
        if process_events[0]["state_id"] != process_events[1]["state_id"]:
            raise ValueError("edge restart did not restore the same persistent state")
        metrics = _mapping(logins[0]["component_metrics"], "edge restart component metrics")
        cache = _mapping(metrics["negative_cache"], "edge restart negative cache metrics")
        if cache.get("entries") != 0 or cache.get("inserts", 0) != 0:
            raise ValueError("edge restart retained an untrusted volatile negative cache")
    if coordinate == "edge_corrupt_state_fail_open":
        if tuple(item["action"] for item in process_events) != (
            "EXIT",
            "CORRUPT_STATE",
            "RESTART",
            "EXIT",
            "RESTART",
        ):
            raise ValueError("corrupt-state row lacks exact process evidence")
        if logins[0]["directory_status"] != DirectoryStatus.UNCERTAIN.value:
            raise ValueError("corrupt state did not force an uncertain directory view")
    if coordinate.startswith("backend_") and coordinate != "backend_crash_restart":
        expected_fault = coordinate.removeprefix("backend_")
        first = logins[0]["backend_interactions"]
        if not first or first[0]["operation"] != "verify" or first[0]["fault"] != expected_fault:
            raise ValueError(f"row {coordinate} lacks its external backend fault RPC")
        if logins[0]["unavailable_authentication"] is not True:
            raise ValueError(f"row {coordinate} did not classify backend unavailability")
    if coordinate == "backend_crash_restart":
        if tuple(item["action"] for item in process_events) != ("EXIT", "RESTART"):
            raise ValueError("backend crash row lacks exact exit/restart evidence")
        if process_events[0]["exit_code"] != 73:
            raise ValueError("backend crash process did not exit with the frozen code")
        first = logins[0]["backend_interactions"]
        if not first or first[0]["fault"] != "crash":
            raise ValueError("backend crash row lacks the crash RPC")
    if coordinate.startswith("backend_"):
        metrics = _mapping(logins[0]["component_metrics"], f"row {coordinate} fault metrics")
        cache = _mapping(metrics["negative_cache"], f"row {coordinate} negative cache metrics")
        if cache.get("entries") != 0 or cache.get("inserts", 0) != 0:
            raise ValueError(f"row {coordinate} wrote a negative entry from uncertainty")
    if coordinate == "core_path_probe":
        metrics = _mapping(logins[-1]["component_metrics"], "core path metrics")
        cache = _mapping(metrics["negative_cache"], "core path negative cache metrics")
        flight = _mapping(metrics["singleflight"], "core path singleflight metrics")
        if cache.get("inserts", 0) < 1 or cache.get("hits", 0) < 1:
            raise ValueError("core path did not execute a negative-cache insert and hit")
        if flight.get("leaders", 0) < 2:
            raise ValueError("core path did not execute Singleflight leaders")
    derived_summary = _derive_row_summary(logins, transport_events, process_events, checks)
    _exact_value(row["summary"], derived_summary, f"row {coordinate}.summary")
    if row["status"] != "PASS":
        raise ValueError(f"row {coordinate} did not pass")
    body = {key: item for key, item in row.items() if key != "row_id"}
    if row["row_id"] != _identity(body):
        raise ValueError(f"row {coordinate} identity mismatch")
    return row


def _process_registry(
    rows: Sequence[Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    registry: dict[str, dict[str, object]] = {}
    role_counts = {role: 0 for role in ("coordinator", "backend", "edge", "transport-proxy")}
    for row in rows:
        for event_value in row["process_events"]:  # type: ignore[union-attr]
            event = _mapping(event_value, "process registry event")
            if event["action"] not in {"START", "RESTART"}:
                continue
            role = str(event["role"])
            session_id = str(event["session_id"])
            if session_id in registry:
                raise ValueError("process lifecycle reused a session identity")
            alias = f"{role}#{role_counts[role]}"
            role_counts[role] += 1
            registry[session_id] = {
                "alias": alias,
                "role": role,
                "pid": event["pid"],
                "session_nonce_hex": event["session_nonce_hex"],
                "endpoint": event["endpoint"],
            }
    _exact_value(
        role_counts,
        {"coordinator": 1, "backend": 2, "edge": 4, "transport-proxy": 1},
        "process lifecycle start counts",
    )
    return registry


def _validate_lifecycle_graph(rows: Sequence[Mapping[str, object]]) -> None:
    registry = _process_registry(rows)
    exited: set[str] = set()
    connection_ids: set[str] = set()

    def require_process(
        *,
        role: object,
        pid: object,
        session_id: object,
        endpoint: object | None,
        label: str,
    ) -> dict[str, object]:
        if type(session_id) is not str or session_id not in registry:
            raise ValueError(f"{label} references an unregistered process session")
        process = registry[session_id]
        if process["role"] != role or process["pid"] != pid:
            raise ValueError(f"{label} process role/PID does not match its session registry")
        if endpoint is not None and process["endpoint"] != endpoint:
            raise ValueError(f"{label} listening endpoint does not match its session registry")
        return process

    def require_rpc(rpc_value: object, label: str) -> None:
        rpc = _mapping(rpc_value, label)
        require_process(
            role=rpc["caller_role"],
            pid=rpc["caller_pid"],
            session_id=rpc["caller_session_id"],
            endpoint=None,
            label=f"{label}.caller",
        )
        require_process(
            role=rpc["callee_role"],
            pid=rpc["callee_pid"],
            session_id=rpc["callee_session_id"],
            endpoint=rpc["callee_endpoint"],
            label=f"{label}.callee",
        )
        connection_id = str(rpc["connection_id"])
        if connection_id in connection_ids:
            raise ValueError(f"{label} reuses a recorded TCP connection identity")
        connection_ids.add(connection_id)

    for row in rows:
        coordinate = str(row["coordinate"])
        for index, event_value in enumerate(row["process_events"]):  # type: ignore[union-attr]
            event = _mapping(event_value, f"row {coordinate}.process_events[{index}]")
            if event["action"] != "EXIT":
                continue
            session_id = str(event["session_id"])
            process = require_process(
                role=event["role"],
                pid=event["pid"],
                session_id=session_id,
                endpoint=event["endpoint"],
                label=f"row {coordinate}.process_events[{index}]",
            )
            if process["session_nonce_hex"] != event["session_nonce_hex"]:
                raise ValueError("process exit nonce does not match its registered start")
            if session_id in exited:
                raise ValueError("process lifecycle contains a duplicate exit")
            exited.add(session_id)
        for index, login_value in enumerate(row["logins"]):  # type: ignore[union-attr]
            login = _mapping(login_value, f"row {coordinate}.logins[{index}]")
            require_process(
                role="edge",
                pid=login["edge_pid"],
                session_id=login["edge_session_id"],
                endpoint=login["edge_endpoint"],
                label=f"row {coordinate}.logins[{index}].edge",
            )
            require_rpc(login["rpc"], f"row {coordinate}.logins[{index}].rpc")
            for interaction_index, interaction_value in enumerate(login["backend_interactions"]):
                interaction = _mapping(
                    interaction_value,
                    f"row {coordinate}.logins[{index}].backend_interactions[{interaction_index}]",
                )
                require_process(
                    role="backend",
                    pid=interaction["backend_pid"],
                    session_id=interaction["backend_session_id"],
                    endpoint=interaction["backend_endpoint"],
                    label=(
                        f"row {coordinate}.logins[{index}]."
                        f"backend_interactions[{interaction_index}].backend"
                    ),
                )
                require_rpc(
                    interaction["transport"],
                    (
                        f"row {coordinate}.logins[{index}]."
                        f"backend_interactions[{interaction_index}].transport"
                    ),
                )
        for index, event_value in enumerate(row["transport_events"]):  # type: ignore[union-attr]
            event = _mapping(event_value, f"row {coordinate}.transport_events[{index}]")
            require_process(
                role="transport-proxy",
                pid=event["proxy_pid"],
                session_id=event["proxy_session_id"],
                endpoint=event["proxy_endpoint"],
                label=f"row {coordinate}.transport_events[{index}].proxy",
            )
            require_rpc(
                event["producer_rpc"],
                f"row {coordinate}.transport_events[{index}].producer_rpc",
            )
            barrier = event["delay_barrier"]
            if barrier is not None:
                barrier_value = _mapping(
                    barrier,
                    f"row {coordinate}.transport_events[{index}].delay_barrier",
                )
                for phase in ("entered_observation", "release"):
                    phase_value = _mapping(
                        barrier_value[phase],
                        f"row {coordinate}.transport_events[{index}].delay_barrier.{phase}",
                    )
                    require_rpc(
                        phase_value["rpc"],
                        (f"row {coordinate}.transport_events[{index}].delay_barrier.{phase}.rpc"),
                    )
            lease = event["lease_expiry"]
            if lease is not None:
                lease_value = _mapping(
                    lease, f"row {coordinate}.transport_events[{index}].lease_expiry"
                )
                require_process(
                    role="edge",
                    pid=lease_value["edge_pid"],
                    session_id=lease_value["edge_session_id"],
                    endpoint=lease_value["edge_endpoint"],
                    label=f"row {coordinate}.transport_events[{index}].lease_expiry.edge",
                )
                require_rpc(
                    lease_value["rpc"],
                    f"row {coordinate}.transport_events[{index}].lease_expiry.rpc",
                )
            for delivery_index, delivery_value in enumerate(event["deliveries"]):
                delivery = _mapping(
                    delivery_value,
                    f"row {coordinate}.transport_events[{index}].deliveries[{delivery_index}]",
                )
                require_process(
                    role="edge",
                    pid=delivery["edge_pid"],
                    session_id=delivery["edge_session_id"],
                    endpoint=delivery["edge_endpoint"],
                    label=(
                        f"row {coordinate}.transport_events[{index}]."
                        f"deliveries[{delivery_index}].edge"
                    ),
                )
                require_rpc(
                    delivery["rpc"],
                    (
                        f"row {coordinate}.transport_events[{index}]."
                        f"deliveries[{delivery_index}].rpc"
                    ),
                )

    exited_aliases = {str(registry[session_id]["alias"]) for session_id in exited}
    _exact_value(
        sorted(exited_aliases),
        sorted({"backend#0", "edge#0", "edge#1", "edge#2"}),
        "process lifecycle exited sessions",
    )
    indexed = {str(row["coordinate"]): row for row in rows}
    persistence = indexed["edge_kill_restart_persistence"]
    persistence_restart = persistence["process_events"][1]  # type: ignore[index]
    persistence_login = persistence["logins"][0]  # type: ignore[index]
    if persistence_login["edge_session_id"] != persistence_restart["session_id"]:
        raise ValueError("edge persistence login is not bound to the restarted edge")
    corruption = indexed["edge_corrupt_state_fail_open"]
    corrupt_restart = corruption["process_events"][2]  # type: ignore[index]
    trusted_restart = corruption["process_events"][4]  # type: ignore[index]
    corrupt_login = corruption["logins"][0]  # type: ignore[index]
    trusted_login = corruption["logins"][1]  # type: ignore[index]
    recovery_event = corruption["transport_events"][0]  # type: ignore[index]
    if (
        corrupt_login["edge_session_id"] != corrupt_restart["session_id"]
        or recovery_event["deliveries"][0]["edge_session_id"] != corrupt_restart["session_id"]
        or trusted_login["edge_session_id"] != trusted_restart["session_id"]
    ):
        raise ValueError("corrupt-state recovery is not bound to the correct edge sessions")
    crash = indexed["backend_crash_restart"]
    crashed_backend = crash["process_events"][0]  # type: ignore[index]
    restarted_backend = crash["process_events"][1]  # type: ignore[index]
    crash_interaction = crash["logins"][0]["backend_interactions"][0]  # type: ignore[index]
    recovered_interactions = crash["logins"][1]["backend_interactions"]  # type: ignore[index]
    if (
        crash_interaction["backend_session_id"] != crashed_backend["session_id"]
        or not recovered_interactions
        or any(
            item["backend_session_id"] != restarted_backend["session_id"]
            for item in recovered_interactions
        )
    ):
        raise ValueError("backend crash/restart interactions are not lifecycle-bound")

    def alias_for(session_id: object, label: str) -> str:
        if type(session_id) is not str or session_id not in registry:
            raise ValueError(f"{label} references an unknown lifecycle session")
        return str(registry[session_id]["alias"])

    expected_login_edges = {
        "core_path_probe": ["edge#0", "edge#0", "edge#0"],
        "transport_delay": ["edge#0", "edge#0"],
        "transport_loss": ["edge#0", "edge#0"],
        "transport_duplicate": ["edge#0"],
        "transport_reorder": ["edge#0"],
        "edge_kill_restart_persistence": ["edge#1"],
        "edge_corrupt_state_fail_open": ["edge#2", "edge#3"],
        "backend_timeout": ["edge#3", "edge#3"],
        "backend_drop": ["edge#3", "edge#3"],
        "backend_malformed": ["edge#3", "edge#3"],
        "backend_typed_transient_failure": ["edge#3", "edge#3"],
        "backend_typed_partial_failure": ["edge#3", "edge#3"],
        "backend_crash_restart": ["edge#3", "edge#3"],
    }
    for coordinate, row in indexed.items():
        login_aliases = [
            alias_for(login["edge_session_id"], f"row {coordinate} login edge")
            for login in row["logins"]  # type: ignore[union-attr]
        ]
        _exact_value(
            login_aliases,
            expected_login_edges[coordinate],
            f"row {coordinate} login lifecycle aliases",
        )
        for login_index, login in enumerate(row["logins"]):  # type: ignore[union-attr]
            expected_backend = (
                "backend#1"
                if coordinate == "backend_crash_restart" and login_index == 1
                else "backend#0"
            )
            for interaction in login["backend_interactions"]:
                if (
                    alias_for(
                        interaction["backend_session_id"],
                        f"row {coordinate} backend interaction",
                    )
                    != expected_backend
                ):
                    raise ValueError(
                        f"row {coordinate} backend interaction violates lifecycle order"
                    )
        for event in row["transport_events"]:  # type: ignore[union-attr]
            if alias_for(event["proxy_session_id"], f"row {coordinate} proxy") != (
                "transport-proxy#0"
            ):
                raise ValueError(f"row {coordinate} used an unexpected transport proxy")
            expected_edge = "edge#2" if coordinate == "edge_corrupt_state_fail_open" else "edge#0"
            if event["lease_expiry"] is not None and (
                alias_for(
                    event["lease_expiry"]["edge_session_id"],
                    f"row {coordinate} lease edge",
                )
                != expected_edge
            ):
                raise ValueError(f"row {coordinate} lease violates edge lifecycle order")
            for delivery in event["deliveries"]:
                if (
                    alias_for(delivery["edge_session_id"], f"row {coordinate} delivery edge")
                    != expected_edge
                ):
                    raise ValueError(f"row {coordinate} delivery violates edge lifecycle order")


def _semantic_projection(rows: Sequence[Mapping[str, object]]) -> list[dict[str, object]]:
    registry = _process_registry(rows)
    connection_counter = 0

    def process_alias(session_id: object, label: str) -> str:
        if type(session_id) is not str or session_id not in registry:
            raise ValueError(f"{label} does not resolve to a normalized process alias")
        return str(registry[session_id]["alias"])

    def normalized_rpc(
        value: object,
        label: str,
        *,
        outcome_override: str | None = None,
    ) -> dict[str, object]:
        nonlocal connection_counter
        rpc = _mapping(value, label)
        alias = f"tcp-connection#{connection_counter}"
        connection_counter += 1
        return {
            "connection": alias,
            "protocol": rpc["protocol"],
            "family": rpc["family"],
            "caller": process_alias(rpc["caller_session_id"], f"{label}.caller"),
            "callee": process_alias(rpc["callee_session_id"], f"{label}.callee"),
            "caller_endpoint_class": "IPV4_LOOPBACK_EPHEMERAL_TCP",
            "callee_endpoint_class": "IPV4_LOOPBACK_LISTENER_TCP",
            "request_present": rpc["request_present"],
            "response_present": rpc["response_present"],
            "outcome": rpc["outcome"] if outcome_override is None else outcome_override,
            "elapsed_class": rpc["elapsed_class"],
        }

    projection: list[dict[str, object]] = []
    for row in rows:
        coordinate = str(row["coordinate"])
        process_events = [
            _mapping(event, f"normalized {coordinate} process event")
            for event in row["process_events"]  # type: ignore[union-attr]
        ]
        crashed_backend_sessions = {
            event["session_id"]
            for event in process_events
            if event["role"] == "backend"
            and event["action"] == "EXIT"
            and event["exit_code"] == 73
            and event["exit_class"] == "APPLICATION_CRASH_73"
        }
        normalized_logins: list[dict[str, object]] = []
        for login_index, login_value in enumerate(row["logins"]):  # type: ignore[union-attr]
            login = _mapping(login_value, f"normalized {coordinate} login {login_index}")
            normalized_interactions: list[dict[str, object]] = []
            for interaction_index, interaction_value in enumerate(login["backend_interactions"]):
                interaction = _mapping(
                    interaction_value,
                    f"normalized {coordinate} backend interaction {interaction_index}",
                )
                interaction_transport = _mapping(
                    interaction["transport"],
                    f"normalized {coordinate} backend interaction {interaction_index} transport",
                )
                failure_category = interaction["failure_category"]
                outcome_override = None
                if interaction["fault"] == "crash":
                    termination = (failure_category, interaction_transport["outcome"])
                    if (
                        interaction["operation"] != "verify"
                        or interaction["completed_response"] is not False
                        or interaction["result_kind"] != BackendResultKind.TRANSIENT_FAILURE.value
                        or interaction["backend_session_id"] not in crashed_backend_sessions
                        or interaction_transport["request_present"] is not True
                        or interaction_transport["response_present"] is not False
                        or interaction_transport["response_bytes"] != 0
                        or termination not in BACKEND_CRASH_TRANSPORT_TERMINATIONS
                    ):
                        raise ValueError(
                            "backend crash transport termination is not bound to the "
                            "observed application crash"
                        )
                    failure_category = NORMALIZED_BACKEND_CRASH_TERMINATION
                    outcome_override = NORMALIZED_BACKEND_CRASH_TERMINATION
                normalized_interactions.append(
                    {
                        "operation": interaction["operation"],
                        "fault": interaction["fault"],
                        "completed_response": interaction["completed_response"],
                        "failure_category": failure_category,
                        "result_kind": interaction["result_kind"],
                        "backend": process_alias(
                            interaction["backend_session_id"], "normalized backend"
                        ),
                        "backend_identity_source": interaction["backend_identity_source"],
                        "rpc": normalized_rpc(
                            interaction_transport,
                            "normalized backend RPC",
                            outcome_override=outcome_override,
                        ),
                    }
                )
            normalized_logins.append(
                {
                    **{
                        field: login[field]
                        for field in (
                            "label",
                            "credential_class",
                            "expected_valid",
                            "accepted",
                            "pre_screen_rejected",
                            "route",
                            "directory_status",
                            "positive_disposition",
                            "backend_kind",
                            "backend_forwarded",
                            "uncertainty_reason",
                            "unavailable_authentication",
                            "state_trusted",
                            "state_id",
                        )
                    },
                    "edge": process_alias(login["edge_session_id"], "normalized login edge"),
                    "edge_endpoint_class": "IPV4_LOOPBACK_LISTENER_TCP",
                    "rpc": normalized_rpc(login["rpc"], "normalized login RPC"),
                    "backend_interactions": normalized_interactions,
                    "component_metrics": login["component_metrics"],
                    "negative_cache_before": login["negative_cache_before"],
                    "negative_cache_after": login["negative_cache_after"],
                    "negative_cache_delta": login["negative_cache_delta"],
                }
            )
        normalized_transport: list[dict[str, object]] = []
        for event_index, event_value in enumerate(row["transport_events"]):  # type: ignore[union-attr]
            event = _mapping(event_value, f"normalized {coordinate} transport {event_index}")
            lease_value = event["lease_expiry"]
            normalized_lease: dict[str, object] | None = None
            if lease_value is not None:
                lease = _mapping(lease_value, "normalized lease expiry")
                normalized_lease = {
                    "lease_id": lease["lease_id"],
                    "edge": process_alias(lease["edge_session_id"], "normalized lease edge"),
                    "state_id": lease["state_id"],
                    "ready": lease["ready"],
                    "rpc": normalized_rpc(lease["rpc"], "normalized lease RPC"),
                }
            normalized_deliveries: list[dict[str, object]] = []
            for delivery_index, delivery_value in enumerate(event["deliveries"]):
                delivery = _mapping(delivery_value, "normalized proxy delivery")
                normalized_deliveries.append(
                    {
                        "delivery_index": delivery_index,
                        "message_id": delivery["message_id"],
                        "sequence": delivery["sequence"],
                        "edge_outcome": delivery["edge_outcome"],
                        "response_present": delivery["response_present"],
                        "edge": process_alias(
                            delivery["edge_session_id"], "normalized delivery edge"
                        ),
                        "rpc": normalized_rpc(delivery["rpc"], "normalized delivery RPC"),
                    }
                )
            normalized_barrier: dict[str, object] | None = None
            if event["delay_barrier"] is not None:
                barrier = _mapping(event["delay_barrier"], "normalized delay barrier")
                entered = _mapping(
                    barrier["entered_observation"],
                    "normalized delay entered observation",
                )
                completion = _mapping(
                    barrier["login_completion"],
                    "normalized delay login completion",
                )
                release = _mapping(barrier["release"], "normalized delay release")
                gate = _mapping(barrier["delivery_gate"], "normalized delay delivery gate")
                normalized_barrier = {
                    "barrier": f"delay-barrier#{event_index}",
                    "message_id": barrier["message_id"],
                    "sequence": barrier["sequence"],
                    "proxy": process_alias(
                        barrier["proxy_session_id"],
                        "normalized delay barrier proxy",
                    ),
                    "entered": {
                        "event_ordinal": entered["event_ordinal"],
                        "status": entered["status"],
                        "release_received": entered["release_received"],
                        "delivery_started": entered["delivery_started"],
                        "rpc": normalized_rpc(
                            entered["rpc"],
                            "normalized delay entered RPC",
                        ),
                    },
                    "login_completion": {
                        "event_ordinal": completion["event_ordinal"],
                        "login": "login#0",
                        "login_label": completion["login_label"],
                        "edge": process_alias(
                            completion["edge_session_id"],
                            "normalized delay login edge",
                        ),
                    },
                    "release": {
                        "event_ordinal": release["event_ordinal"],
                        "status": release["status"],
                        "release_received": release["release_received"],
                        "delivery_started": release["delivery_started"],
                        "rpc": normalized_rpc(
                            release["rpc"],
                            "normalized delay release RPC",
                        ),
                    },
                    "delivery_gate": {
                        "event_ordinal": gate["event_ordinal"],
                        "status": gate["status"],
                        "minimum_delay_satisfied": gate["minimum_delay_satisfied"],
                        "release_received": gate["release_received"],
                        "delivery_started_after_release": gate["delivery_started_after_release"],
                    },
                    "causal_order": barrier["causal_order"],
                    "independent_rpc_connections": True,
                }
            normalized_transport.append(
                {
                    **{
                        field: event[field]
                        for field in (
                            "label",
                            "action",
                            "producer_message_ids",
                            "producer_sequences",
                            "delivery_message_ids",
                            "delivery_sequences",
                            "edge_outcomes",
                            "applied_count",
                            "proxy_drop_count",
                            "duplicate_count",
                            "stale_count",
                            "delay_ms",
                        )
                    },
                    "proxy": process_alias(event["proxy_session_id"], "normalized transport proxy"),
                    "proxy_endpoint_class": "IPV4_LOOPBACK_LISTENER_TCP",
                    "producer_rpc": normalized_rpc(
                        event["producer_rpc"], "normalized producer RPC"
                    ),
                    "lease_expiry": normalized_lease,
                    "delay_barrier": normalized_barrier,
                    "deliveries": normalized_deliveries,
                }
            )
        normalized_process: list[dict[str, object]] = []
        state_file_count = 0
        for event in process_events:
            if event["session_id"] is None:
                alias = f"edge-state-file#{state_file_count}"
                state_file_count += 1
            else:
                alias = process_alias(event["session_id"], "normalized process event")
            normalized_process.append(
                {
                    "process": alias,
                    "role": event["role"],
                    "action": event["action"],
                    "endpoint_class": (
                        "NONE" if event["endpoint"] is None else "IPV4_LOOPBACK_LISTENER_TCP"
                    ),
                    "exit_class": event["exit_class"],
                    "state_id": event["state_id"],
                    "state_trusted": event["state_trusted"],
                }
            )
        projection.append(
            {
                "coordinate": coordinate,
                "status": row["status"],
                "logins": normalized_logins,
                "transport": normalized_transport,
                "process": normalized_process,
                "checks": row["checks"],
                "summary": row["summary"],
            }
        )
    return projection


def _derive_artifact_summary(rows: Sequence[Mapping[str, object]]) -> dict[str, object]:
    summaries = [_mapping(row["summary"], "row summary") for row in rows]
    return {
        "coordinate_count": len(rows),
        "passing_rows": sum(row["status"] == "PASS" for row in rows),
        "login_count": sum(int(item["login_count"]) for item in summaries),
        "valid_attempts": sum(int(item["valid_attempts"]) for item in summaries),
        "structural_false_rejects": sum(
            int(item["structural_false_rejects"]) for item in summaries
        ),
        "unavailable_authentications": sum(
            int(item["unavailable_authentications"]) for item in summaries
        ),
        "uncertainty_attempts": sum(int(item["uncertainty_attempts"]) for item in summaries),
        "uncertainty_backend_forwarded": sum(
            int(item["uncertainty_backend_forwarded"]) for item in summaries
        ),
        "recorded_coordinator_edge_login_rpc_count": sum(
            int(item["recorded_coordinator_edge_login_rpc_count"]) for item in summaries
        ),
        "recorded_coordinator_edge_lease_expire_rpc_count": sum(
            int(item["recorded_coordinator_edge_lease_expire_rpc_count"]) for item in summaries
        ),
        "recorded_coordinator_proxy_produce_rpc_count": sum(
            int(item["recorded_coordinator_proxy_produce_rpc_count"]) for item in summaries
        ),
        "recorded_coordinator_proxy_delay_barrier_wait_rpc_count": sum(
            int(item["recorded_coordinator_proxy_delay_barrier_wait_rpc_count"])
            for item in summaries
        ),
        "recorded_coordinator_proxy_delay_release_rpc_count": sum(
            int(item["recorded_coordinator_proxy_delay_release_rpc_count"]) for item in summaries
        ),
        "recorded_proxy_edge_delivery_rpc_count": sum(
            int(item["recorded_proxy_edge_delivery_rpc_count"]) for item in summaries
        ),
        "recorded_edge_backend_rpc_count": sum(
            int(item["recorded_edge_backend_rpc_count"]) for item in summaries
        ),
        "recorded_producer_message_count": sum(
            int(item["recorded_producer_message_count"]) for item in summaries
        ),
        "process_exit_events": sum(int(item["process_exit_events"]) for item in summaries),
        "process_restart_events": sum(int(item["process_restart_events"]) for item in summaries),
        "coordinate_digest": _identity(list(COORDINATES)),
        "semantic_replay_digest": _identity(_semantic_projection(rows)),
    }


def build_artifact(
    config: Mapping[str, object],
    config_id: str,
    expected_commit: str,
    git_before: Mapping[str, object],
    git_after: Mapping[str, object],
    rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    expected = _formal_config_spec()
    policy = _artifact_policy_spec()
    _exact_value(dict(config), expected, "artifact construction config")
    if config_id != _identity(expected):
        raise ValueError("artifact construction config identity mismatch")
    validated_rows = [
        validate_row(row, coordinate) for row, coordinate in zip(rows, COORDINATES, strict=True)
    ]
    if len(validated_rows) != len(COORDINATES):
        raise ValueError("artifact construction coordinate count mismatch")
    _validate_lifecycle_graph(validated_rows)
    body: dict[str, object] = {
        "schema": policy["artifact_schema"],
        "experiment_id": policy["experiment_id"],
        "execution_classification": policy["execution_classification"],
        "evidence_scope": policy["evidence_scope"],
        "g7_claim_eligible": policy["g7_claim_eligible"],
        "g7_status": policy["g7_status"],
        "blockers": policy["blockers"],
        "source_commit": expected_commit,
        "config_id": config_id,
        "git_before": dict(git_before),
        "git_after": dict(git_after),
        "validation_mode": policy["validation_mode"],
        "fault_layer": policy["fault_layer"],
        "rpc_accounting": policy["rpc_accounting"],
        "random_observations": policy["random_observations"],
        "unfrozen_artifact_integrity_boundary": policy["unfrozen_artifact_integrity_boundary"],
        "coordinates": list(COORDINATES),
        "rows": [dict(row) for row in validated_rows],
        "summary": _derive_artifact_summary(validated_rows),
        "status": policy["status"],
    }
    return {**body, "artifact_id": _identity(body)}


def validate_artifact(
    artifact: object,
    config: Mapping[str, object],
    config_id: str,
    expected_commit: str,
) -> dict[str, Any]:
    expected = _formal_config_spec()
    policy = _artifact_policy_spec()
    _exact_value(dict(config), expected, "artifact validation config")
    if config_id != _identity(expected):
        raise ValueError("artifact validation config identity mismatch")
    _strict_hex(expected_commit, "expected commit", 40)
    value = _mapping(artifact, "service-fault artifact")
    _exact_keys(
        value,
        {
            "schema",
            "experiment_id",
            "execution_classification",
            "evidence_scope",
            "g7_claim_eligible",
            "g7_status",
            "blockers",
            "source_commit",
            "config_id",
            "git_before",
            "git_after",
            "validation_mode",
            "fault_layer",
            "rpc_accounting",
            "random_observations",
            "unfrozen_artifact_integrity_boundary",
            "coordinates",
            "rows",
            "summary",
            "status",
            "artifact_id",
        },
        "service-fault artifact",
    )
    frozen_fields = {
        "schema": policy["artifact_schema"],
        "experiment_id": policy["experiment_id"],
        "execution_classification": policy["execution_classification"],
        "evidence_scope": policy["evidence_scope"],
        "g7_claim_eligible": policy["g7_claim_eligible"],
        "g7_status": policy["g7_status"],
        "blockers": policy["blockers"],
        "source_commit": expected_commit,
        "config_id": config_id,
        "validation_mode": policy["validation_mode"],
        "fault_layer": policy["fault_layer"],
        "rpc_accounting": policy["rpc_accounting"],
        "random_observations": policy["random_observations"],
        "unfrozen_artifact_integrity_boundary": policy["unfrozen_artifact_integrity_boundary"],
        "coordinates": list(COORDINATES),
        "status": policy["status"],
    }
    for field, frozen in frozen_fields.items():
        _exact_value(value[field], frozen, f"artifact.{field}")
    for field in ("git_before", "git_after"):
        state = _validate_git_state(value[field], f"artifact.{field}")
        if state["commit"] != expected_commit or state["clean"] is not True:
            raise ValueError(f"artifact.{field} is not the exact clean source")
    rows_value = value["rows"]
    if type(rows_value) is not list or len(rows_value) != len(COORDINATES):
        raise ValueError("artifact rows do not cover the frozen coordinate count")
    rows = [
        validate_row(row, coordinate)
        for row, coordinate in zip(rows_value, COORDINATES, strict=True)
    ]
    _validate_lifecycle_graph(rows)
    _semantic_projection(rows)
    summary = _derive_artifact_summary(rows)
    _exact_value(value["summary"], summary, "artifact.summary")
    if (
        summary["passing_rows"] != len(COORDINATES)
        or summary["structural_false_rejects"] != 0
        or summary["uncertainty_attempts"] != summary["uncertainty_backend_forwarded"]
        or summary["process_exit_events"] < 4
        or summary["process_restart_events"] < 4
    ):
        raise ValueError("service-fault artifact did not satisfy its evidence gates")
    body = {key: item for key, item in value.items() if key != "artifact_id"}
    if value["artifact_id"] != _identity(body):
        raise ValueError("service-fault artifact identity mismatch")
    return value


def _fresh_matrix(config: Mapping[str, object]) -> list[dict[str, object]]:
    with tempfile.TemporaryDirectory(prefix="traps-g7-service-fault-") as directory:
        return _execute_matrix(config, Path(directory) / "matrix")


def collect_to_path(
    config: Mapping[str, object],
    config_id: str,
    expected_commit: str,
    output: Path,
) -> dict[str, object]:
    before = _require_clean_source(expected_commit)
    rows = _fresh_matrix(config)
    after = _require_clean_source(expected_commit)
    artifact = build_artifact(config, config_id, expected_commit, before, after, rows)
    validate_artifact(artifact, config, config_id, expected_commit)
    final_state = _require_clean_source(expected_commit)
    if final_state != after:
        raise RuntimeError("source changed after service-fault artifact construction")
    _write_json_exclusive(output, artifact)
    return artifact


def validate_with_reexecution(
    artifact: object,
    config: Mapping[str, object],
    config_id: str,
    expected_commit: str,
) -> dict[str, Any]:
    before = _require_clean_source(expected_commit)
    value = validate_artifact(artifact, config, config_id, expected_commit)
    replay_rows = _fresh_matrix(config)
    replay_rows = [
        validate_row(row, coordinate)
        for row, coordinate in zip(replay_rows, COORDINATES, strict=True)
    ]
    _validate_lifecycle_graph(replay_rows)
    _exact_value(
        _semantic_projection(replay_rows),
        _semantic_projection(value["rows"]),
        "fresh service-fault semantic replay",
    )
    after = _require_clean_source(expected_commit)
    if before != after:
        raise RuntimeError("source changed during service-fault artifact validation")
    return value


def _public_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--expected-commit", required=True)
    run.add_argument("--output", type=Path, required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--config", type=Path, required=True)
    validate.add_argument("--expected-commit", required=True)
    validate.add_argument("--input", type=Path, required=True)
    return parser


def main() -> int:
    child_result = _private_child_main(sys.argv[1:])
    if child_result is not None:
        return child_result
    args = _public_parser().parse_args()
    config, config_id = load_config(args.config)
    if args.command == "run":
        artifact = collect_to_path(
            config,
            config_id,
            args.expected_commit,
            args.output,
        )
        print(
            _canonical_json(
                {
                    "status": artifact["status"],
                    "artifact_id": artifact["artifact_id"],
                }
            )
        )
        return 0
    artifact = load_json_object(args.input)
    validate_with_reexecution(artifact, config, config_id, args.expected_commit)
    print(_canonical_json({"status": "COMPONENT_CHECK_PASS"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
