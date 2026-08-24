"""Real-system adapters for the E11 PreAcher engineering smoke."""

from __future__ import annotations

import hashlib
import json
import math
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from dataplane.types import BackendResultKind
from experiments.runners.service_bench import (
    FrozenScreenSpec,
    StrongOracleConditionedScreen,
    build_screen,
)
from reference.filters import TokenCodec
from service import (
    AuthenticationService,
    AuthRequest,
    KdfBackend,
    KdfProfile,
    OpenLoopLoadGenerator,
    ScheduledArrival,
    ServiceAccount,
    ServiceLimits,
    ServiceMethod,
    ServiceRoute,
    TrafficClass,
)

REGISTERED_PHASE1_BASELINE_STATUSES = frozenset(
    {"REGISTERED_PHASE1_V2_1_BASELINE", "REGISTERED_PHASE1_V2_2_SERVICE_BASELINE"}
)

ADAPTER_RESULT_SCHEMA = "traps-e11-matched-adapter-result-v1"
NODE_OBSERVATION_SCHEMA = "traps-e11-preacher-node-observations-v1"
UPSTREAM_METHOD = "preacher_upstream_as_released"
REPOSITORY_METHOD = "r_traps_released_kdf_profile"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SUMMARY_FIELDS = {
    "offered_attempts",
    "completed_attempts",
    "backend_valid_checks",
    "backend_invalid_checks",
    "distinct_invalid_tuples",
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
    "adapter_process_cpu_seconds",
}


class AdapterExecutionError(RuntimeError):
    """Raised when a real adapter cannot complete a valid smoke run."""


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


def _repository_implementation_ledger() -> dict[str, Any]:
    paths = [Path(__file__).resolve(), Path(__file__).with_name("service_bench.py").resolve()]
    for relative_root in ("service", "dataplane", "reference/filters"):
        paths.extend(sorted((REPOSITORY_ROOT / relative_root).glob("*.py")))
    files = {
        str(path.relative_to(REPOSITORY_ROOT)).replace("\\", "/"): _file_sha256(path)
        for path in paths
    }
    return {"files": files, "ledger_id": _sha256(files)}


def _strict_json(path: Path) -> Any:
    def reject_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AdapterExecutionError(f"duplicate JSON key: {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AdapterExecutionError(f"cannot load adapter JSON: {exc}") from exc


def _p99(values: Sequence[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(0.99 * len(ordered)) - 1)]


def _finalize_result(value: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["result_id"] = _sha256(result)
    return result


class _RecordingVerifier:
    def __init__(self, backend: KdfBackend) -> None:
        self.backend = backend
        self.records: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def verify(self, account, username: str, password: bytes):
        started_ns = time.perf_counter_ns()
        result = self.backend.verify(account, username, password)
        completed_ns = time.perf_counter_ns()
        with self._lock:
            self.records.setdefault(username, []).append(
                {
                    "backend_started_ns": started_ns,
                    "backend_completed_ns": completed_ns,
                    "backend_result_kind": result.kind.value,
                }
            )
        return result


class _PendingBaselineScreen:
    method = "PENDING_PHASE1_V2_1_BASELINE_FAIL_IF_QUERIED"
    n_items = 0

    def query(self, _item):
        raise AdapterExecutionError("pending E11 baseline screen was queried")

    def memory_report(self):
        raise AdapterExecutionError("pending E11 baseline has no memory report")


@dataclass(frozen=True)
class _Completion:
    completed_ns: int
    route: str
    accepted: bool


class _RecordingAuthenticationService(AuthenticationService):
    """Expose per-attempt terminal routes without changing the service runtime."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.completions: dict[int, _Completion] = {}
        self._completion_lock = threading.Lock()

    def _record_completion(
        self,
        context: Any,
        route: ServiceRoute,
        accepted: bool,
        *,
        response_emitted: bool = True,
    ) -> None:
        super()._record_completion(
            context,
            route,
            accepted,
            response_emitted=response_emitted,
        )
        completion = _Completion(time.perf_counter_ns(), route.value, accepted)
        with self._completion_lock:
            if context.request.request_id in self.completions:
                raise AdapterExecutionError("repository adapter completed one request twice")
            self.completions[context.request.request_id] = completion


@dataclass
class _Submission:
    scheduled_ns: int
    submitted_ns: int
    accepted: bool


class _RecordingService:
    def __init__(self, service: AuthenticationService) -> None:
        self.service = service
        self.submissions: dict[int, _Submission] = {}

    def submit(
        self,
        request: AuthRequest,
        phase: str,
        scheduled_ns: int,
        window_start_ns: int,
        window_end_ns: int,
    ) -> bool:
        submitted_ns = time.perf_counter_ns()
        accepted = self.service.submit(
            request,
            phase,
            scheduled_ns,
            window_start_ns,
            window_end_ns,
        )
        self.submissions[request.request_id] = _Submission(
            scheduled_ns=scheduled_ns,
            submitted_ns=submitted_ns,
            accepted=accepted,
        )
        return accepted


def _enrollment_records(trace: Mapping[str, Any]) -> list[dict[str, str]]:
    records = trace.get("enrollment_accounts")
    if records is None:
        first_by_account: dict[str, dict[str, str]] = {}
        for event in trace["events"]:
            account_id = str(event["account_id"])
            password = str(event["enrollment_password"])
            existing = first_by_account.get(account_id)
            if existing is not None and existing["enrollment_password"] != password:
                raise AdapterExecutionError("one account has conflicting enrollment passwords")
            first_by_account.setdefault(
                account_id,
                {"account_id": account_id, "enrollment_password": password},
            )
        records = list(first_by_account.values())
    if not isinstance(records, list) or not records:
        raise AdapterExecutionError("trace enrollment account set is missing")
    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise AdapterExecutionError("trace enrollment account is not an object")
        account_id = record.get("account_id")
        password = record.get("enrollment_password")
        if not isinstance(account_id, str) or not account_id:
            raise AdapterExecutionError("trace enrollment account ID is invalid")
        if not isinstance(password, str) or not password:
            raise AdapterExecutionError("trace enrollment password is invalid")
        if account_id in seen:
            raise AdapterExecutionError("trace enrollment account IDs are not unique")
        seen.add(account_id)
        normalized.append({"account_id": account_id, "enrollment_password": password})
    event_accounts = {str(event["account_id"]) for event in trace["events"]}
    if event_accounts != seen:
        raise AdapterExecutionError("trace events and enrollment account set differ")
    return normalized


def run_repository_adapter(
    manifest: Mapping[str, Any],
    manifest_id: str,
    trace: Mapping[str, Any],
    *,
    execution_status: str = "PASS_ENGINEERING_SMOKE",
    phase_name: str = "e11_engineering_smoke",
) -> dict[str, Any]:
    """Drive the repository AuthenticationService with the shared trace."""

    contract = manifest["matched_contract"]
    workers = contract["workers"]
    events = trace["events"]
    enrollment_records = _enrollment_records(trace)
    token_key = hashlib.sha256(
        b"TRAPS-E11-engineering-token-key-v1\x00" + trace["trace_id"].encode()
    ).digest()
    codec = TokenCodec(token_key)
    accounts: list[ServiceAccount] = []
    for ordinal, enrollment in enumerate(enrollment_records):
        account_id = enrollment["account_id"]
        accounts.append(
            ServiceAccount(
                account_index=ordinal,
                username=account_id,
                account_id=account_id,
                account_generation=1,
                credential_set_version=1,
                salt=hashlib.sha256(
                    b"TRAPS-E11-engineering-salt-v1\x00" + account_id.encode()
                ).digest(),
            )
        )
    account_by_name = {account.username: account for account in accounts}
    profile = KdfProfile(
        name="preacher_released_pbkdf2_matched",
        algorithm="pbkdf2_sha256",
        parameters={
            "iterations": int(contract["kdf"]["iterations"]),
            "dklen": int(contract["kdf"]["output_bytes"]),
        },
    )
    backend = KdfBackend(
        profile,
        dummy_salt=hashlib.sha256(b"TRAPS-E11-engineering-dummy-salt-v1").digest(),
    )
    for enrollment in enrollment_records:
        backend.enroll(
            account_by_name[enrollment["account_id"]],
            enrollment["enrollment_password"].encode("utf-8"),
        )
    recorder = _RecordingVerifier(backend)
    baseline = manifest["derived_baseline_binding"]
    baseline_registered = baseline["status"] in REGISTERED_PHASE1_BASELINE_STATUSES
    if baseline_registered:
        spec = FrozenScreenSpec.from_config(baseline["selected_filter"])
        members = [
            account_by_name[enrollment["account_id"]].screen_query(
                codec,
                enrollment["enrollment_password"].encode("utf-8"),
            )
            for enrollment in enrollment_records
        ]
        raw_positive_screen = build_screen(spec, members, int(contract["seed"]))
        conditioned_queries = frozenset(
            account_by_name[str(event["account_id"])].screen_query(
                codec, str(event["attempt_password"]).encode("utf-8")
            )
            for event in events
            if event["credential_class"] == "invalid"
        )
        positive_screen = (
            StrongOracleConditionedScreen(raw_positive_screen, conditioned_queries)
            if trace.get("false_positive_source") == "FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1"
            else raw_positive_screen
        )
    else:
        raw_positive_screen = None
        positive_screen = _PendingBaselineScreen()
    mechanism = manifest.get("repository_mechanism", {})
    if not isinstance(mechanism, Mapping):
        raise AdapterExecutionError("repository mechanism contract is invalid")
    cache_policy = mechanism.get("exact_negative_cache")
    use_singleflight = mechanism.get("singleflight", False)
    if cache_policy not in {None, "lru"} or type(use_singleflight) is not bool:
        raise AdapterExecutionError("unsupported repository mechanism contract")
    if (cache_policy is not None or use_singleflight) and not baseline_registered:
        raise AdapterExecutionError("formal repository mechanism requires registration")
    method = ServiceMethod(
        name=(
            "e11_repository_registered_phase1_baseline"
            if baseline_registered
            else "e11_repository_pending_phase1_baseline"
        ),
        use_positive_screen=baseline_registered,
        cache_policy=cache_policy,
        use_singleflight=use_singleflight,
        claim_scope=(
            "engineering_registered_phase1_screen"
            if baseline_registered
            else "engineering_kdf_path_only_pending_phase1_screen"
        ),
        baseline_role=(
            "registered_phase1_baseline"
            if baseline_registered
            else "pending_phase1_v2_1_baseline"
        ),
    )
    limits = ServiceLimits(
        frontend_workers=int(workers["frontend_handler"]),
        backend_workers=int(workers["origin_kdf_handler"]),
        frontend_queue_capacity=64,
        backend_queue_capacity=64,
        max_connections=64,
        max_padding_timers=64,
        max_waiters_per_key=64 if use_singleflight else 0,
        max_waiters_global=2048 if use_singleflight else 0,
        failure_padding_seconds=0.0,
        request_timeout_seconds=10.0,
        cache_capacity=16,
        cache_ttl_seconds=30.0,
        cache_max_entries_per_account=1,
    )
    service = _RecordingAuthenticationService(
        accounts=accounts,
        codec=codec,
        positive_filter=positive_screen,
        verifier=recorder,
        method=method,
        limits=limits,
        negative_key=hashlib.sha256(b"TRAPS-E11-engineering-negative-key-v1").digest(),
    )
    proxy = _RecordingService(service)
    arrivals: list[ScheduledArrival] = []
    for event in events:
        legitimate = event["credential_class"] == "legitimate"
        arrivals.append(
            ScheduledArrival(
                offset_seconds=int(event["scheduled_offset_ns"]) / 1_000_000_000,
                request=AuthRequest(
                    request_id=int(event["ordinal"]),
                    username=str(event["account_id"]),
                    password=str(event["attempt_password"]).encode("utf-8"),
                    traffic_class=(TrafficClass.LEGITIMATE if legitimate else TrafficClass.INVALID),
                    tuple_id=str(event["credential_id"]),
                ),
            )
        )

    cpu_started = time.process_time()
    try:
        load_report = OpenLoopLoadGenerator().run(
            proxy,
            arrivals,
            float(contract["duration_seconds"]),
            phase=phase_name,
        )
        drain_timeout = max(20.0, float(contract["duration_seconds"]) + 120.0)
        if not service.wait_phase(phase_name, timeout=drain_timeout):
            raise AdapterExecutionError("repository adapter did not drain")
        snapshot = service.phase_snapshot(phase_name)
    finally:
        shutdown = service.shutdown(timeout=20.0)
    cpu_seconds = time.process_time() - cpu_started
    if not shutdown.clean:
        raise AdapterExecutionError("repository adapter shutdown was not clean")
    if load_report.accepted_for_queueing != len(events):
        raise AdapterExecutionError("repository adapter rejected an offered attempt")
    if len(service.completions) != len(events):
        raise AdapterExecutionError("repository adapter did not complete every attempt")
    recorded_kdfs = sum(len(records) for records in recorder.records.values())
    if not baseline_registered and recorded_kdfs != len(events):
        raise AdapterExecutionError("pending repository adapter did not execute every KDF")
    if snapshot["pending"] != 0 or not snapshot["conservation"]["valid"]:
        raise AdapterExecutionError("repository adapter conservation checks failed")

    observed: list[dict[str, Any]] = []
    backend_records = {
        account_id: list(records) for account_id, records in recorder.records.items()
    }
    for event in events:
        ordinal = int(event["ordinal"])
        account_id = str(event["account_id"])
        submission = proxy.submissions[ordinal]
        account_records = backend_records.get(account_id, [])
        backend_record = account_records.pop(0) if account_records else None
        completion = service.completions[ordinal]
        legitimate = event["credential_class"] == "legitimate"
        valid_route = (
            completion.route == ServiceRoute.BACKEND_MATCH.value
            if legitimate
            else completion.route
            in {
                ServiceRoute.POSITIVE_SCREEN_REJECT.value,
                ServiceRoute.BACKEND_MISMATCH.value,
                ServiceRoute.NEGATIVE_CACHE_REJECT.value,
            }
        )
        expected_kind = BackendResultKind.MATCH.value if legitimate else "AUTHENTICATION_REJECT"
        observed_kind = completion.route
        observed.append(
            {
                "attempt_id": event["attempt_id"],
                "ordinal": ordinal,
                "credential_class": event["credential_class"],
                "scheduled_offset_ns": event["scheduled_offset_ns"],
                "arrival_lag_ns": max(0, submission.submitted_ns - submission.scheduled_ns),
                "completion_latency_ms": (completion.completed_ns - submission.submitted_ns)
                / 1_000_000,
                "backend_kdf_ms": (
                    None
                    if backend_record is None
                    else (
                        backend_record["backend_completed_ns"]
                        - backend_record["backend_started_ns"]
                    )
                    / 1_000_000
                ),
                "expected_outcome": expected_kind,
                "observed_outcome": observed_kind,
                "expected_outcome_observed": valid_route,
                "protocol_http_requests": 0,
                "error_name": None,
            }
        )
    if not all(event["expected_outcome_observed"] for event in observed):
        raise AdapterExecutionError("repository adapter observed a wrong authentication outcome")

    legitimate_latencies = [
        float(event["completion_latency_ms"])
        for event in observed
        if event["credential_class"] == "legitimate"
    ]
    invalid_count = sum(event["credential_class"] == "invalid" for event in observed)
    counters = snapshot["counters"]
    backend_valid_checks = int(counters.get("backend_valid_checks", 0))
    backend_invalid_checks = int(counters.get("backend_invalid_checks", 0))
    distinct_invalid_tuples = len(
        {
            event["credential_id"]
            for event in events
            if event["credential_class"] == "invalid"
        }
    )
    return _finalize_result(
        {
            "schema": ADAPTER_RESULT_SCHEMA,
            "method": REPOSITORY_METHOD,
            "manifest_id": manifest_id,
            "matched_contract_id": _sha256(contract),
            "attempt_trace_id": trace["trace_id"],
            "execution_status": execution_status,
            "adapter_implementation": "repository.service.AuthenticationService",
            "source_binding": {
                "screen_active": baseline_registered,
                "screen_binding": (
                    baseline["registration_id"]
                    if baseline_registered
                    else "PENDING_PHASE1_V2_1_BASELINE"
                ),
                "screen_object": (
                    raw_positive_screen.binding()
                    if baseline_registered
                    else "FAIL_IF_QUERIED_PENDING_BASELINE_SENTINEL"
                ),
                "false_positive_source": trace.get("false_positive_source"),
                "conditioned_tuple_set_id": trace.get("conditioned_tuple_set_id"),
                "conditioned_tuple_count": trace.get("conditioned_tuple_count", 0),
                "underlying_filter_query_executed": (
                    trace.get("false_positive_source")
                    == "FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1"
                ),
                "conditional_intervention_does_not_estimate_ffr": (
                    trace.get("false_positive_source")
                    == "FROZEN_STRONG_ORACLE_CONDITIONED_TUPLES_V1"
                ),
                "conditional_intervention_runtime": (
                    positive_screen.runtime_evidence()
                    if isinstance(positive_screen, StrongOracleConditionedScreen)
                    else None
                ),
                "phase1_selected_spec_id": (
                    baseline["selected_spec_id"] if baseline_registered else None
                ),
                "phase1_selected_spec_identity": (
                    baseline["selected_spec_identity"] if baseline_registered else None
                ),
                "actual_kdf_execution": True,
                "kdf_implementation": profile.implementation_metadata(),
                "worker_contract": dict(workers),
                "implementation_ledger": _repository_implementation_ledger(),
            },
            "events": observed,
            "summary": {
                "offered_attempts": len(events),
                "completed_attempts": len(observed),
                "backend_valid_checks": backend_valid_checks,
                "backend_invalid_checks": backend_invalid_checks,
                "distinct_invalid_tuples": distinct_invalid_tuples,
                "checks_per_distinct_invalid_tuple": (
                    backend_invalid_checks / distinct_invalid_tuples
                    if invalid_count
                    else None
                ),
                "legitimate_throughput_rps": (
                    len(legitimate_latencies) / float(contract["duration_seconds"])
                ),
                "legitimate_p99_ms": _p99(legitimate_latencies),
                "legitimate_timeout_rate": 0.0,
                "saturation_interval": None,
                "frontend_cpu_seconds": None,
                "frontend_peak_rss_bytes": None,
                "origin_cpu_seconds": None,
                "origin_peak_rss_bytes": None,
                "protocol_http_requests": 0,
                "rsa_operations": 0,
                "two_round_attempts": 0,
                "adapter_process_cpu_seconds": cpu_seconds,
            },
        }
    )


def _port_is_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _wait_port(port: int, process: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AdapterExecutionError(f"upstream process exited before port {port} opened")
        if _port_is_open(port):
            return
        time.sleep(0.05)
    raise AdapterExecutionError(f"upstream port {port} did not open")


def _stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait(timeout=10)


def run_upstream_adapter(
    manifest: Mapping[str, Any],
    manifest_id: str,
    trace: Mapping[str, Any],
    *,
    upstream_root: Path,
    node_adapter: Path,
    upstream_preflight: Mapping[str, Any],
    execution_status: str = "PASS_ENGINEERING_SMOKE",
) -> dict[str, Any]:
    """Start released binaries and drive their official JS client with Node."""

    if upstream_preflight.get("status") != "PASS":
        raise AdapterExecutionError("upstream preflight must pass before execution")
    if any(_port_is_open(port) for port in (8000, 8080)):
        raise AdapterExecutionError("upstream fixed ports 8000/8080 are already in use")
    build_dir = upstream_root / "build" / "test"
    js_root = upstream_root / "test" / "share" / "static" / "js"
    env = os.environ.copy()
    env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"
    server: subprocess.Popen[str] | None = None
    cdn: subprocess.Popen[str] | None = None
    with tempfile.TemporaryDirectory(prefix="traps-e11-upstream-") as temporary_name:
        temporary = Path(temporary_name)
        trace_path = temporary / "trace.json"
        node_output = temporary / "node-observations.json"
        trace_path.write_text(json.dumps(trace, sort_keys=True, allow_nan=False), encoding="utf-8")
        server_log = (temporary / "server.log").open("w", encoding="utf-8")
        cdn_log = (temporary / "cdn.log").open("w", encoding="utf-8")
        try:
            server = subprocess.Popen(
                [str(build_dir / "server")],
                cwd=build_dir,
                env=env,
                stdout=server_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            _wait_port(8080, server, 15.0)
            cdn = subprocess.Popen(
                [str(build_dir / "cdn")],
                cwd=build_dir,
                env=env,
                stdout=cdn_log,
                stderr=subprocess.STDOUT,
                text=True,
            )
            _wait_port(8000, cdn, 15.0)
            command = [
                "node",
                str(node_adapter),
                "--trace",
                str(trace_path),
                "--output",
                str(node_output),
                "--official-js-root",
                str(js_root),
                "--base-url",
                "https://localhost:8000",
            ]
            completed = subprocess.run(
                command,
                env=env,
                capture_output=True,
                check=False,
                text=True,
                timeout=max(180, int(trace["duration_seconds"]) + 600),
            )
            if completed.returncode != 0:
                raise AdapterExecutionError(
                    "official-client adapter failed: "
                    + (completed.stderr.strip() or completed.stdout.strip())[-2000:]
                )
            observations = _strict_json(node_output)
        finally:
            if cdn is not None:
                _stop_process(cdn)
            if server is not None:
                _stop_process(server)
            server_log.close()
            cdn_log.close()

    if not isinstance(observations, Mapping):
        raise AdapterExecutionError("Node observations must be an object")
    if observations.get("schema") != NODE_OBSERVATION_SCHEMA:
        raise AdapterExecutionError("Node observation schema changed")
    if observations.get("attempt_trace_id") != trace["trace_id"]:
        raise AdapterExecutionError("Node observations bind another trace")
    events = observations.get("events")
    if not isinstance(events, list) or len(events) != trace["event_count"]:
        raise AdapterExecutionError("Node observations are incomplete")
    if [event.get("attempt_id") for event in events] != [
        event["attempt_id"] for event in trace["events"]
    ]:
        raise AdapterExecutionError("Node attempt order or identities changed")

    summary = observations.get("summary")
    if not isinstance(summary, Mapping):
        raise AdapterExecutionError("Node observation summary is missing")
    return _finalize_result(
        {
            "schema": ADAPTER_RESULT_SCHEMA,
            "method": UPSTREAM_METHOD,
            "manifest_id": manifest_id,
            "matched_contract_id": _sha256(manifest["matched_contract"]),
            "attempt_trace_id": trace["trace_id"],
            "execution_status": execution_status,
            "adapter_implementation": "upstream.single_client.js.via_node_webcrypto",
            "source_binding": {
                "upstream_revision": upstream_preflight["observed_revision"],
                "upstream_clean": upstream_preflight["git_clean"],
                "released_parameter_probe_passed": upstream_preflight[
                    "released_parameter_probe_passed"
                ],
                "workflow_worker_contract_passed": upstream_preflight[
                    "workflow_worker_contract_passed"
                ],
                "worker_contract": dict(manifest["matched_contract"]["workers"]),
                "official_client_module": "test/share/static/js/single_client.js",
                "node_adapter_sha256": _file_sha256(node_adapter),
                "upstream_binary_sha256": dict(upstream_preflight["binary_sha256"]),
                "workflow_header_sha256": upstream_preflight["workflow_header_sha256"],
                "actual_protocol_execution": True,
            },
            "events": events,
            "summary": dict(summary),
        }
    )


def validate_adapter_result(
    result: Mapping[str, Any],
    *,
    expected_method: str,
    manifest_id: str,
    contract_id: str,
    trace: Mapping[str, Any],
    expected_baseline_binding: Mapping[str, Any] | None = None,
    expected_execution_status: str = "PASS_ENGINEERING_SMOKE",
) -> None:
    expected_top_level = {
        "schema",
        "method",
        "manifest_id",
        "matched_contract_id",
        "attempt_trace_id",
        "execution_status",
        "adapter_implementation",
        "source_binding",
        "events",
        "summary",
        "result_id",
    }
    if set(result) != expected_top_level:
        raise AdapterExecutionError("adapter result fields changed")
    if result.get("schema") != ADAPTER_RESULT_SCHEMA:
        raise AdapterExecutionError("adapter result schema changed")
    if result.get("method") != expected_method:
        raise AdapterExecutionError("adapter result method changed")
    if result.get("manifest_id") != manifest_id:
        raise AdapterExecutionError("adapter result manifest binding changed")
    if result.get("matched_contract_id") != contract_id:
        raise AdapterExecutionError("adapter result contract binding changed")
    if result.get("attempt_trace_id") != trace["trace_id"]:
        raise AdapterExecutionError("adapter result trace binding changed")
    if result.get("execution_status") != expected_execution_status:
        raise AdapterExecutionError("adapter result execution status changed")
    result_id = result.get("result_id")
    material = dict(result)
    material.pop("result_id", None)
    if not isinstance(result_id, str) or _sha256(material) != result_id:
        raise AdapterExecutionError("adapter result ID does not recompute")
    events = result.get("events")
    if not isinstance(events, list) or len(events) != trace["event_count"]:
        raise AdapterExecutionError("adapter result event coverage is incomplete")
    if [event.get("attempt_id") for event in events] != [
        event["attempt_id"] for event in trace["events"]
    ]:
        raise AdapterExecutionError("adapter result attempt identities changed")
    expected_event_contract = [
        (
            event["ordinal"],
            event["credential_class"],
            event["scheduled_offset_ns"],
        )
        for event in trace["events"]
    ]
    observed_event_contract = [
        (
            event.get("ordinal"),
            event.get("credential_class"),
            event.get("scheduled_offset_ns"),
        )
        for event in events
    ]
    if observed_event_contract != expected_event_contract:
        raise AdapterExecutionError("adapter result event contract changed")
    for event in events:
        latency = event.get("completion_latency_ms")
        lag = event.get("arrival_lag_ns")
        if (
            type(latency) not in (int, float)
            or not math.isfinite(float(latency))
            or float(latency) < 0
        ):
            raise AdapterExecutionError("adapter result contains an invalid latency")
        if type(lag) is not int or lag < 0:
            raise AdapterExecutionError("adapter result contains an invalid arrival lag")
    source_binding = result.get("source_binding")
    summary = result.get("summary")
    if not isinstance(source_binding, Mapping) or not isinstance(summary, Mapping):
        raise AdapterExecutionError("adapter result binding or summary is missing")
    if set(summary) != SUMMARY_FIELDS:
        raise AdapterExecutionError("adapter result summary fields changed")
    if summary.get("offered_attempts") != trace["event_count"]:
        raise AdapterExecutionError("adapter result offered-attempt count changed")
    if summary.get("completed_attempts") != trace["event_count"]:
        raise AdapterExecutionError("adapter result completed-attempt count changed")
    if expected_method == REPOSITORY_METHOD:
        registered = (
            expected_baseline_binding is not None
            and expected_baseline_binding.get("status") in REGISTERED_PHASE1_BASELINE_STATUSES
        )
        if registered:
            if source_binding.get("screen_active") is not True:
                raise AdapterExecutionError("registered repository baseline did not activate")
            if source_binding.get("screen_binding") != expected_baseline_binding.get(
                "registration_id"
            ):
                raise AdapterExecutionError("repository screen registration binding changed")
            if source_binding.get("phase1_selected_spec_id") != expected_baseline_binding.get(
                "selected_spec_id"
            ):
                raise AdapterExecutionError("repository selected Phase 1 spec changed")
            if source_binding.get("phase1_selected_spec_identity") != expected_baseline_binding.get(
                "selected_spec_identity"
            ):
                raise AdapterExecutionError("repository Phase 1 spec identity changed")
            realization = source_binding.get("screen_object")
            if not isinstance(realization, Mapping):
                raise AdapterExecutionError("registered repository screen binding is missing")
            spec = FrozenScreenSpec.from_config(expected_baseline_binding["selected_filter"])
            if realization.get("configured_spec_id") != spec.identity:
                raise AdapterExecutionError("repository screen realization uses another spec")
            if realization.get("all_members_positive_at_build") is not True:
                raise AdapterExecutionError("repository screen lacks its one-sided build check")
            if realization.get("n_items") != len(_enrollment_records(trace)):
                raise AdapterExecutionError("repository screen member count changed")
        else:
            if source_binding.get("screen_active") is not False:
                raise AdapterExecutionError("pending repository baseline activated a screen")
            if source_binding.get("screen_binding") != "PENDING_PHASE1_V2_1_BASELINE":
                raise AdapterExecutionError("repository adapter lost its pending baseline binding")
            if source_binding.get("screen_object") != "FAIL_IF_QUERIED_PENDING_BASELINE_SENTINEL":
                raise AdapterExecutionError("repository adapter installed a baseline placeholder")
            if (
                source_binding.get("phase1_selected_spec_id") is not None
                or source_binding.get("phase1_selected_spec_identity") is not None
            ):
                raise AdapterExecutionError("pending repository adapter selected a Phase 1 spec")
        implementation_ledger = source_binding.get("implementation_ledger")
        if not isinstance(implementation_ledger, Mapping):
            raise AdapterExecutionError("repository implementation ledger is missing")
        implementation_files = implementation_ledger.get("files")
        if (
            not isinstance(implementation_files, Mapping)
            or not implementation_files
            or implementation_ledger.get("ledger_id") != _sha256(implementation_files)
        ):
            raise AdapterExecutionError("repository implementation ledger is invalid")
        if summary.get("backend_valid_checks") != sum(
            event["credential_class"] == "legitimate" for event in trace["events"]
        ):
            raise AdapterExecutionError("repository valid KDF count changed")
        expected_invalid_checks = sum(
            event.get("credential_class") == "invalid"
            and event.get("observed_outcome") == ServiceRoute.BACKEND_MISMATCH.value
            for event in events
        )
        if summary.get("backend_invalid_checks") != expected_invalid_checks:
            raise AdapterExecutionError("repository invalid KDF count changed")
    elif expected_method == UPSTREAM_METHOD:
        if source_binding.get("actual_protocol_execution") is not True:
            raise AdapterExecutionError("upstream adapter did not bind protocol execution")
        if source_binding.get("workflow_worker_contract_passed") is not True:
            raise AdapterExecutionError("upstream adapter lost the Workflow worker binding")
        binary_hashes = source_binding.get("upstream_binary_sha256")
        if (
            not isinstance(binary_hashes, Mapping)
            or set(binary_hashes) != {"build/test/cdn", "build/test/server"}
            or not all(
                isinstance(value, str) and len(value) == 64 for value in binary_hashes.values()
            )
        ):
            raise AdapterExecutionError("upstream binary provenance is invalid")
        for field in ("node_adapter_sha256", "workflow_header_sha256"):
            value = source_binding.get(field)
            if not isinstance(value, str) or len(value) != 64:
                raise AdapterExecutionError(f"upstream {field} provenance is invalid")
        legitimate_count = sum(
            event["credential_class"] == "legitimate" for event in trace["events"]
        )
        backend_invalid_count = 0
        for event in events:
            statuses = event.get("http_statuses")
            if (
                event.get("credential_class") == "invalid"
                and event.get("protocol_http_requests") == 2
                and isinstance(statuses, list)
                and statuses
                and statuses[-1] == 403
                and event.get("error_name") is None
            ):
                backend_invalid_count += 1
        two_round_count = sum(event.get("protocol_http_requests") == 2 for event in events)
        if summary.get("backend_valid_checks") != legitimate_count:
            raise AdapterExecutionError("upstream valid KDF count changed")
        if summary.get("backend_invalid_checks") != backend_invalid_count:
            raise AdapterExecutionError("upstream invalid KDF count changed")
        if summary.get("protocol_http_requests") != sum(
            int(event.get("protocol_http_requests", -1)) for event in events
        ):
            raise AdapterExecutionError("upstream HTTP request count changed")
        if summary.get("two_round_attempts") != two_round_count:
            raise AdapterExecutionError("upstream two-round count changed")
        if summary.get("rsa_operations") != 2 * two_round_count:
            raise AdapterExecutionError("upstream RSA-operation count changed")
