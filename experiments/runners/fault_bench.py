#!/usr/bin/env python3
"""Fail-closed E8 version/fault matrix for the executable reference data plane.

This runner tests structural one-sided safety and fail-open routing.  It does
not measure external timing, network behavior, or service saturation, and its
artifact cannot by itself upgrade G7.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from controlplane import ActivationKey, ActivationStateMachine  # noqa: E402
from dataplane import (  # noqa: E402
    AuthDataPlane,
    AuthDecision,
    AuthRoute,
    BackendResultKind,
    Directory,
    DirectoryStatus,
    DirectoryView,
    InMemoryBackend,
    NegativeCache,
    NegativeKeyDeriver,
    PositiveDecision,
    PositiveDisposition,
    PositiveScreen,
    Singleflight,
    TinyLfuPolicy,
)
from dataplane.crypto import exact_password_bytes  # noqa: E402
from dataplane.negative_cache import NegativeKey  # noqa: E402

CONFIG_SCHEMA = "traps-e8-fault-config-v1"
ARTIFACT_SCHEMA = "traps-e8-fault-artifact-v1"
ROW_SCHEMA = "traps-e8-fault-row-v1"
EVIDENCE_SCOPE = "REFERENCE_PROTOCOL_FAULT_MATRIX_ONLY"
EDGES = ("edge-a", "edge-b")
FAULT_SEEDS = tuple(range(8200, 8220))
SCENARIOS = (
    "delayed_directory_replication",
    "delayed_positive_delta",
    "activation_message_loss_duplication_reordering",
    "frontend_restart_stale_epoch",
    "backend_verifier_write_before_filter_state",
    "filter_state_before_directory_activation",
    "concurrent_password_change_and_login",
    "account_deletion_and_username_reuse",
    "cache_insert_racing_password_rotation",
    "dual_active_authenticators",
)

# These are coverage floors, not empirical success thresholds.  They keep a
# coordinated edit from silently deleting the fault-bearing observations.
SCENARIO_CONTRACT = {
    "delayed_directory_replication": (4, 2, 2, 0),
    "delayed_positive_delta": (4, 0, 1, 2),
    "activation_message_loss_duplication_reordering": (2, 0, 1, 3),
    "frontend_restart_stale_epoch": (2, 1, 1, 0),
    "backend_verifier_write_before_filter_state": (3, 0, 1, 1),
    "filter_state_before_directory_activation": (3, 0, 1, 1),
    "concurrent_password_change_and_login": (201, 1, 1, 1),
    "account_deletion_and_username_reuse": (2, 2, 1, 0),
    "cache_insert_racing_password_rotation": (2, 0, 1, 1),
    "dual_active_authenticators": (2, 0, 1, 1),
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _identity(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


class _DuplicateJsonKeyError(ValueError):
    pass


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_unique_yaml_mapping(loader, node, deep=False):
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
    _construct_unique_yaml_mapping,
)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value!r} is forbidden")


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, _DuplicateJsonKeyError) as error:
        raise ValueError(f"fault artifact JSON is malformed: {error}") from error
    return _mapping(value, "fault artifact")


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
        raise ValueError(f"{label} does not match its derived value")


def _integer(value: object, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _number(value: object, label: str, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be numeric")
    result = float(value)
    if not result >= minimum or result == float("inf"):
        raise ValueError(f"{label} must be finite and >= {minimum}")
    return result


def _mapping(value: object, label: str) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError(f"{label} must be a string-keyed object")
    return value


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    value = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    config = _mapping(value, "fault config")
    _exact_keys(
        config,
        {
            "schema",
            "experiment_id",
            "formal",
            "required_edges",
            "seeds",
            "scenarios",
            "concurrent_login_attempts",
            "negative_cache",
            "singleflight",
        },
        "fault config",
    )
    if config["schema"] != CONFIG_SCHEMA:
        raise ValueError("fault config schema mismatch")
    if type(config["experiment_id"]) is not str or not config["experiment_id"]:
        raise ValueError("experiment_id must be a nonempty string")
    if config["formal"] is not True:
        raise ValueError("the E8 evidence config must be formal")
    if tuple(config["required_edges"]) != EDGES:
        raise ValueError("required_edges must be the frozen two-edge order")
    seeds = config["seeds"]
    if type(seeds) is not list:
        raise ValueError("formal E8 seeds must be an array")
    normalized_seeds = tuple(_integer(seed, "seed", 1) for seed in seeds)
    if normalized_seeds != FAULT_SEEDS:
        raise ValueError("formal E8 requires the frozen ordered 20-seed set")
    if tuple(config["scenarios"]) != SCENARIOS:
        raise ValueError("fault config must contain the complete ordered scenario matrix")
    attempts = _integer(config["concurrent_login_attempts"], "concurrent attempts", 1)
    if attempts != 200:
        raise ValueError("formal E8 requires exactly 200 concurrent login attempts")

    cache = _mapping(config["negative_cache"], "negative_cache")
    _exact_keys(
        cache,
        {
            "capacity",
            "max_ttl_seconds",
            "max_entries_per_account",
            "max_entries_per_region",
        },
        "negative_cache",
    )
    _integer(cache["capacity"], "negative_cache.capacity", 1)
    _number(cache["max_ttl_seconds"], "negative_cache.max_ttl_seconds", 0.001)
    _integer(cache["max_entries_per_account"], "max_entries_per_account", 1)
    _integer(cache["max_entries_per_region"], "max_entries_per_region", 1)

    singleflight = _mapping(config["singleflight"], "singleflight")
    _exact_keys(
        singleflight,
        {"max_waiters_per_key", "max_waiters_global"},
        "singleflight",
    )
    _integer(singleflight["max_waiters_per_key"], "max_waiters_per_key", 1)
    _integer(singleflight["max_waiters_global"], "max_waiters_global", 1)
    return config, _identity(config)


class _FalsePositiveScreen(PositiveScreen):
    """Inject selected false positives without changing represented positives."""

    def __init__(self, seed: int, false_positive_passwords: Iterable[bytes]) -> None:
        positive_key = hashlib.sha256(f"positive:{seed}".encode()).digest()
        certificate_key = hashlib.sha256(f"certificate:{seed}".encode()).digest()
        super().__init__(positive_key, certificate_key, region_count=4)
        self._false_positive_passwords = frozenset(false_positive_passwords)

    def query(self, view, password, edge_id, token=None):  # type: ignore[override]
        decision = super().query(view, password, edge_id, token)
        if (
            decision.disposition is PositiveDisposition.NEGATIVE
            and exact_password_bytes(password) in self._false_positive_passwords
        ):
            return PositiveDecision(
                PositiveDisposition.POSITIVE,
                "deterministic injected false positive",
                credential_token=decision.credential_token,
                region=decision.region,
                certificate=decision.certificate,
            )
        return decision


class _PausingBackend(InMemoryBackend):
    """Pause one version-specific verification at a controlled race point."""

    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()
        self._armed_version: int | None = None
        self._pause_lock = threading.Lock()

    def arm(self, expected_version: int) -> None:
        with self._pause_lock:
            self.entered.clear()
            self.release.clear()
            self._armed_version = expected_version

    def verify(self, username, password, expected_version):  # type: ignore[override]
        pause = False
        with self._pause_lock:
            if expected_version == self._armed_version:
                self._armed_version = None
                pause = True
        if pause:
            self.entered.set()
            if not self.release.wait(5):
                raise RuntimeError("timed out waiting for forced version-race release")
        return super().verify(username, password, expected_version)


class _PausingNegativeCache(NegativeCache):
    """Pause one old-scope insertion after its typed backend mismatch."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.entered = threading.Event()
        self.release = threading.Event()
        self._armed_version: int | None = None
        self._pause_lock = threading.Lock()

    def arm(self, credential_set_version: int) -> None:
        with self._pause_lock:
            self.entered.clear()
            self.release.clear()
            self._armed_version = credential_set_version

    def insert(
        self,
        key: NegativeKey,
        view: DirectoryView,
        region: int,
        ttl_seconds: float,
        now: float | None = None,
    ) -> bool:
        pause = False
        with self._pause_lock:
            if view.credential_set_version == self._armed_version:
                self._armed_version = None
                pause = True
        if pause:
            self.entered.set()
            if not self.release.wait(5):
                raise RuntimeError("timed out waiting for forced cache-race release")
        return super().insert(key, view, region, ttl_seconds, now)


class _System:
    def __init__(
        self,
        config: Mapping[str, Any],
        seed: int,
        *,
        backend: InMemoryBackend | None = None,
        cache: NegativeCache | None = None,
    ) -> None:
        cache_config = config["negative_cache"]
        singleflight_config = config["singleflight"]
        self.directory = Directory()
        self.positive = _FalsePositiveScreen(
            seed,
            {b"future-password", b"known-false-positive"},
        )
        self.backend = InMemoryBackend() if backend is None else backend
        negative_key = hashlib.sha256(f"negative:{seed}".encode()).digest()
        self.cache = (
            NegativeCache(
                capacity=int(cache_config["capacity"]),
                policy=TinyLfuPolicy(reset_after=128),
                max_ttl_seconds=float(cache_config["max_ttl_seconds"]),
                max_entries_per_account=int(cache_config["max_entries_per_account"]),
                max_entries_per_region=int(cache_config["max_entries_per_region"]),
            )
            if cache is None
            else cache
        )
        self.control = ActivationStateMachine(
            self.directory,
            self.positive,
            self.backend,
        )
        self.engine = AuthDataPlane(
            self.directory,
            self.positive,
            NegativeKeyDeriver(negative_key),
            self.cache,
            Singleflight(
                max_waiters_per_key=int(singleflight_config["max_waiters_per_key"]),
                max_waiters_global=int(singleflight_config["max_waiters_global"]),
            ),
            self.backend,
        )

    def prepare(
        self,
        generation: int,
        version: int,
        authenticators: Mapping[str, bytes],
        *,
        account_id: str = "account-1",
    ) -> ActivationKey:
        return self.control.prepare(
            username="alice",
            account_id=account_id,
            account_generation=generation,
            credential_set_version=version,
            salt=f"salt-{generation}-{version}".encode(),
            authenticators=authenticators,
            required_edges=EDGES,
        )

    def finish_activation(
        self,
        key: ActivationKey,
        *,
        replicate_directory: bool = True,
    ) -> None:
        self.control.publish_delta(key)
        for edge in EDGES:
            self.control.acknowledge_delta(key, edge)
        self.control.activate(key, replicate_directory=replicate_directory)

    def activate(
        self,
        generation: int,
        version: int,
        authenticators: Mapping[str, bytes],
        *,
        account_id: str = "account-1",
        replicate_directory: bool = True,
    ) -> ActivationKey:
        key = self.prepare(
            generation,
            version,
            authenticators,
            account_id=account_id,
        )
        self.finish_activation(key, replicate_directory=replicate_directory)
        return key


class _Recorder:
    def __init__(self, scenario: str, seed: int) -> None:
        self.scenario = scenario
        self.seed = seed
        self.events: list[dict[str, object]] = []
        self.guards: list[dict[str, object]] = []
        self._lock = threading.Lock()

    def authenticate(
        self,
        system: _System,
        label: str,
        edge: str,
        password: bytes,
        *,
        expected_valid: bool,
        require_fail_open: bool = False,
        require_backend: bool = False,
        recovery_check: bool = False,
    ) -> AuthDecision:
        before = system.backend.verify_calls
        decision = system.engine.authenticate(edge, "alice", password)
        after = system.backend.verify_calls
        event = {
            "label": label,
            "edge": edge,
            "expected_valid": expected_valid,
            "require_fail_open": require_fail_open,
            "require_backend": require_backend,
            "recovery_check": recovery_check,
            "accepted": decision.accepted,
            "pre_screen_rejected": decision.pre_screen_rejected,
            "route": decision.route.value,
            "directory_status": decision.directory_view.status.value,
            "directory_account_id": decision.directory_view.account_id,
            "directory_account_generation": decision.directory_view.account_generation,
            "directory_credential_set_version": (decision.directory_view.credential_set_version),
            "directory_epoch": decision.directory_view.directory_epoch,
            "positive_disposition": (
                None
                if decision.positive_decision is None
                else decision.positive_decision.disposition.value
            ),
            "backend_kind": (
                None if decision.backend_result is None else decision.backend_result.kind.value
            ),
            "backend_expected_version": (
                None
                if decision.backend_result is None
                else decision.backend_result.expected_version
            ),
            "backend_checked_version": (
                None if decision.backend_result is None else decision.backend_result.checked_version
            ),
            "backend_checked_account_id": (
                None
                if decision.backend_result is None
                else decision.backend_result.checked_account_id
            ),
            "backend_checked_account_generation": (
                None
                if decision.backend_result is None
                else decision.backend_result.checked_account_generation
            ),
            "backend_checked_authenticator_ids": (
                []
                if decision.backend_result is None
                else sorted(decision.backend_result.checked_authenticator_ids)
            ),
            "backend_calls_delta": after - before if require_backend else None,
        }
        with self._lock:
            self.events.append(event)
        return decision

    def guard(self, label: str, passed: bool, detail: str) -> None:
        with self._lock:
            self.guards.append({"label": label, "passed": passed, "detail": detail})

    def expect_value_error(self, label: str, action: Callable[[], object]) -> None:
        try:
            action()
        except ValueError as error:
            self.guard(label, True, str(error))
        else:
            self.guard(label, False, "operation unexpectedly succeeded")

    def finish(self, concurrent_attempts: int) -> dict[str, object]:
        events = sorted(self.events, key=lambda item: str(item["label"]))
        guards = sorted(self.guards, key=lambda item: str(item["label"]))
        summary = _summarize_observations(events, guards)
        valid_floor, fail_open_floor, recovery_floor, guard_floor = SCENARIO_CONTRACT[self.scenario]
        if self.scenario == "concurrent_password_change_and_login":
            valid_floor = concurrent_attempts + 1
        coverage = {
            "valid_attempts_floor": valid_floor,
            "fail_open_expectations_floor": fail_open_floor,
            "recovery_checks_floor": recovery_floor,
            "guard_expectations_floor": guard_floor,
            "complete": (
                summary["valid_attempts"] >= valid_floor
                and summary["fail_open_expectations"] >= fail_open_floor
                and summary["recovery_checks"] >= recovery_floor
                and summary["guard_expectations"] >= guard_floor
            ),
        }
        failures = (
            summary["structural_false_rejects"]
            + summary["valid_acceptance_failures"]
            + summary["invalid_acceptance_failures"]
            + summary["fail_open_violations"]
            + summary["backend_forward_violations"]
            + summary["recovery_failures"]
            + summary["guard_failures"]
        )
        body: dict[str, object] = {
            "schema": ROW_SCHEMA,
            "scenario": self.scenario,
            "seed": self.seed,
            "evidence_scope": EVIDENCE_SCOPE,
            "events": events,
            "guards": guards,
            "summary": summary,
            "coverage": coverage,
            "status": "PASS" if coverage["complete"] and failures == 0 else "FAIL",
        }
        return {**body, "row_id": _identity(body)}


def _summarize_observations(
    events: Sequence[Mapping[str, object]], guards: Sequence[Mapping[str, object]]
) -> dict[str, int]:
    valid = [event for event in events if event["expected_valid"] is True]
    invalid = [event for event in events if event["expected_valid"] is False]
    fail_open = [event for event in events if event["require_fail_open"] is True]
    backend = [event for event in events if event["require_backend"] is True]
    recovery = [event for event in events if event["recovery_check"] is True]
    return {
        "event_count": len(events),
        "valid_attempts": len(valid),
        "structural_false_rejects": sum(event["pre_screen_rejected"] is True for event in valid),
        "valid_acceptance_failures": sum(event["accepted"] is not True for event in valid),
        "invalid_acceptance_failures": sum(event["accepted"] is not False for event in invalid),
        "fail_open_expectations": len(fail_open),
        "fail_open_violations": sum(
            event["route"] != AuthRoute.FAIL_OPEN_BACKEND.value for event in fail_open
        ),
        "backend_forward_violations": sum(
            event["backend_kind"] is None or int(event["backend_calls_delta"]) < 1
            for event in backend
        ),
        "recovery_checks": len(recovery),
        "recovery_failures": sum(
            event["accepted"] is not True
            or event["pre_screen_rejected"] is True
            or event["directory_status"] != DirectoryStatus.PRESENT.value
            or event["route"] != AuthRoute.BACKEND_MATCH.value
            for event in recovery
        ),
        "guard_expectations": len(guards),
        "guard_failures": sum(guard["passed"] is not True for guard in guards),
    }


def _event_contract(
    edge: str,
    *,
    expected_valid: bool = True,
    require_fail_open: bool = False,
    require_backend: bool = False,
    recovery_check: bool = False,
) -> dict[str, object]:
    return {
        "edge": edge,
        "expected_valid": expected_valid,
        "require_fail_open": require_fail_open,
        "require_backend": require_backend,
        "recovery_check": recovery_check,
    }


def _worker_counts(total: int, workers: int = 4) -> tuple[int, ...]:
    counts = [total // workers] * workers
    for index in range(total % workers):
        counts[index] += 1
    return tuple(counts)


def expected_event_contracts(
    scenario: str, seed: int, concurrent_attempts: int
) -> dict[str, dict[str, object]]:
    if scenario == SCENARIOS[0]:
        result = {}
        for edge in EDGES:
            result[f"stale-{edge}"] = _event_contract(
                edge,
                require_fail_open=True,
                require_backend=True,
            )
            result[f"recovered-{edge}"] = _event_contract(edge, recovery_check=True)
        return result
    if scenario == SCENARIOS[1]:
        return {
            "old-before-delta": _event_contract("edge-a"),
            "old-before-acks": _event_contract("edge-b"),
            "new-after-delta-edge-a": _event_contract("edge-a", recovery_check=True),
            "new-after-delta-edge-b": _event_contract("edge-b"),
        }
    if scenario == SCENARIOS[2]:
        return {
            "old-after-messages": _event_contract("edge-a"),
            "new-after-messages": _event_contract("edge-b", recovery_check=True),
        }
    if scenario == SCENARIOS[3]:
        return {
            "restart-uncertain": _event_contract(
                "edge-a", require_fail_open=True, require_backend=True
            ),
            "restart-recovered": _event_contract("edge-a", recovery_check=True),
        }
    if scenario == SCENARIOS[4]:
        return {
            "old-after-backend-prepare-a": _event_contract("edge-a"),
            "old-after-backend-prepare-b": _event_contract("edge-b"),
            "new-after-complete-activation": _event_contract("edge-a", recovery_check=True),
        }
    if scenario == SCENARIOS[5]:
        return {
            "old-after-filter-a": _event_contract("edge-a"),
            "old-backend-directory-gap": _event_contract("edge-b"),
            "new-after-directory": _event_contract("edge-a", recovery_check=True),
        }
    if scenario == SCENARIOS[6]:
        if concurrent_attempts < 2:
            raise ValueError("concurrent event contract requires at least two attempts")
        result = {
            "forced-inflight-rotation": _event_contract(
                "edge-a",
                require_fail_open=True,
            ),
            "new-after-concurrent-rotation": _event_contract("edge-a", recovery_check=True),
        }
        for worker, count in enumerate(_worker_counts(concurrent_attempts - 1)):
            for ordinal in range(count):
                edge = EDGES[(worker + ordinal + seed) % len(EDGES)]
                result[f"concurrent-{worker:02d}-{ordinal:04d}"] = _event_contract(edge)
        return result
    if scenario == SCENARIOS[7]:
        return {
            "deleted-stale-edge": _event_contract(
                "edge-a",
                expected_valid=False,
                require_fail_open=True,
                require_backend=True,
            ),
            "reused-stale-edge": _event_contract(
                "edge-a",
                require_fail_open=True,
                require_backend=True,
            ),
            "reused-recovered": _event_contract("edge-a", recovery_check=True),
        }
    if scenario == SCENARIOS[8]:
        return {
            "old-valid-before-cache": _event_contract("edge-a"),
            "mismatch-inflight-cache-insert": _event_contract("edge-a", expected_valid=False),
            "future-password-after-rotation": _event_contract("edge-b", recovery_check=True),
        }
    if scenario == SCENARIOS[9]:
        return {
            "dual-old": _event_contract("edge-a"),
            "dual-new": _event_contract("edge-b", recovery_check=True),
        }
    raise ValueError(f"unknown scenario contract: {scenario}")


def expected_guard_labels(scenario: str) -> frozenset[str]:
    return {
        SCENARIOS[0]: frozenset(),
        SCENARIOS[1]: frozenset({"activate-before-delta", "activate-before-acks"}),
        SCENARIOS[2]: frozenset(
            {
                "reordered-ack-before-publish",
                "duplicate-publish-idempotent",
                "lost-edge-b-ack-blocks-activation",
            }
        ),
        SCENARIOS[3]: frozenset(),
        SCENARIOS[4]: frozenset({"prepared-verifier-cannot-activate-without-filter"}),
        SCENARIOS[5]: frozenset({"directory-activation-completes"}),
        SCENARIOS[6]: frozenset({"forced-request-entered-before-activation"}),
        SCENARIOS[7]: frozenset(),
        SCENARIOS[8]: frozenset({"cache-insert-paused-across-rotation"}),
        SCENARIOS[9]: frozenset({"mismatch-checks-complete-dual-set"}),
    }[scenario]


def _scenario_delayed_directory(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    system = _System(config, seed)
    recorder = _Recorder(SCENARIOS[0], seed)
    system.activate(1, 1, {"v1": b"old-password"})
    system.activate(1, 2, {"v2": b"new-password"}, replicate_directory=False)
    for edge in EDGES:
        recorder.authenticate(
            system,
            f"stale-{edge}",
            edge,
            b"new-password",
            expected_valid=True,
            require_fail_open=True,
            require_backend=True,
        )
        system.directory.replicate_to_edge(edge, "alice")
        recorder.authenticate(
            system,
            f"recovered-{edge}",
            edge,
            b"new-password",
            expected_valid=True,
            recovery_check=True,
        )
    return recorder.finish(int(config["concurrent_login_attempts"]))


def _scenario_delayed_delta(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    system = _System(config, seed)
    recorder = _Recorder(SCENARIOS[1], seed)
    system.activate(1, 1, {"v1": b"old-password"})
    pending = system.prepare(1, 2, {"v2": b"new-password"})
    recorder.authenticate(
        system, "old-before-delta", "edge-a", b"old-password", expected_valid=True
    )
    recorder.expect_value_error("activate-before-delta", lambda: system.control.activate(pending))
    system.control.publish_delta(pending)
    recorder.authenticate(system, "old-before-acks", "edge-b", b"old-password", expected_valid=True)
    recorder.expect_value_error("activate-before-acks", lambda: system.control.activate(pending))
    for edge in EDGES:
        system.control.acknowledge_delta(pending, edge)
    system.control.activate(pending)
    for edge in EDGES:
        recorder.authenticate(
            system,
            f"new-after-delta-{edge}",
            edge,
            b"new-password",
            expected_valid=True,
            recovery_check=edge == "edge-a",
        )
    return recorder.finish(int(config["concurrent_login_attempts"]))


def _scenario_activation_messages(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    system = _System(config, seed)
    recorder = _Recorder(SCENARIOS[2], seed)
    system.activate(1, 1, {"v1": b"old-password"})
    pending = system.prepare(
        1,
        2,
        {"old": b"old-password", "new": b"new-password"},
    )
    recorder.expect_value_error(
        "reordered-ack-before-publish",
        lambda: system.control.acknowledge_delta(pending, "edge-b"),
    )
    first_epoch = system.control.publish_delta(pending)
    second_epoch = system.control.publish_delta(pending)
    recorder.guard(
        "duplicate-publish-idempotent",
        first_epoch == second_epoch,
        f"first={first_epoch}, second={second_epoch}",
    )
    system.control.acknowledge_delta(pending, "edge-a")
    system.control.acknowledge_delta(pending, "edge-a")
    recorder.expect_value_error(
        "lost-edge-b-ack-blocks-activation",
        lambda: system.control.activate(pending),
    )
    system.control.acknowledge_delta(pending, "edge-b")
    system.control.activate(pending)
    recorder.authenticate(
        system, "old-after-messages", "edge-a", b"old-password", expected_valid=True
    )
    recorder.authenticate(
        system,
        "new-after-messages",
        "edge-b",
        b"new-password",
        expected_valid=True,
        recovery_check=True,
    )
    return recorder.finish(int(config["concurrent_login_attempts"]))


def _scenario_restart(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    system = _System(config, seed)
    recorder = _Recorder(SCENARIOS[3], seed)
    system.activate(1, 1, {"v1": b"old-password"})
    system.control.crash_edge("edge-a")
    recorder.authenticate(
        system,
        "restart-uncertain",
        "edge-a",
        b"old-password",
        expected_valid=True,
        require_fail_open=True,
        require_backend=True,
    )
    system.control.recover_edge("edge-a", "alice")
    recorder.authenticate(
        system,
        "restart-recovered",
        "edge-a",
        b"old-password",
        expected_valid=True,
        recovery_check=True,
    )
    return recorder.finish(int(config["concurrent_login_attempts"]))


def _scenario_backend_write(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    system = _System(config, seed)
    recorder = _Recorder(SCENARIOS[4], seed)
    system.activate(1, 1, {"v1": b"old-password"})
    pending = system.prepare(1, 2, {"v2": b"new-password"})
    recorder.authenticate(
        system, "old-after-backend-prepare-a", "edge-a", b"old-password", expected_valid=True
    )
    recorder.authenticate(
        system, "old-after-backend-prepare-b", "edge-b", b"old-password", expected_valid=True
    )
    recorder.expect_value_error(
        "prepared-verifier-cannot-activate-without-filter",
        lambda: system.control.activate(pending),
    )
    system.finish_activation(pending)
    recorder.authenticate(
        system,
        "new-after-complete-activation",
        "edge-a",
        b"new-password",
        expected_valid=True,
        recovery_check=True,
    )
    return recorder.finish(int(config["concurrent_login_attempts"]))


def _scenario_filter_before_directory(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    system = _System(config, seed)
    recorder = _Recorder(SCENARIOS[5], seed)
    system.activate(1, 1, {"v1": b"old-password"})
    pending = system.prepare(1, 2, {"v2": b"new-password"})
    system.control.publish_delta(pending)
    for edge in EDGES:
        system.control.acknowledge_delta(pending, edge)
    recorder.authenticate(
        system, "old-after-filter-a", "edge-a", b"old-password", expected_valid=True
    )
    system.control.fault_backend_advance_before_directory(pending)
    recorder.authenticate(
        system, "old-backend-directory-gap", "edge-b", b"old-password", expected_valid=True
    )
    system.control.activate(pending)
    recorder.guard(
        "directory-activation-completes",
        system.directory.lookup("alice").credential_set_version == 2,
        "authoritative directory must advance to v2",
    )
    recorder.authenticate(
        system,
        "new-after-directory",
        "edge-a",
        b"new-password",
        expected_valid=True,
        recovery_check=True,
    )
    return recorder.finish(int(config["concurrent_login_attempts"]))


def _scenario_concurrent_rotation(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    backend = _PausingBackend()
    system = _System(config, seed, backend=backend)
    recorder = _Recorder(SCENARIOS[6], seed)
    system.activate(1, 1, {"v1": b"old-password"})
    pending = system.prepare(
        1,
        2,
        {"old": b"old-password", "new": b"new-password"},
    )
    system.control.publish_delta(pending)
    for edge in EDGES:
        system.control.acknowledge_delta(pending, edge)

    attempts = int(config["concurrent_login_attempts"])
    start = threading.Event()

    def login(worker: int, count: int) -> None:
        start.wait()
        for ordinal in range(count):
            edge = EDGES[(worker + ordinal + seed) % len(EDGES)]
            recorder.authenticate(
                system,
                f"concurrent-{worker:02d}-{ordinal:04d}",
                edge,
                b"old-password",
                expected_valid=True,
            )

    backend.arm(expected_version=1)
    workers = 4
    counts = _worker_counts(attempts - 1, workers)
    with ThreadPoolExecutor(max_workers=workers + 1) as pool:
        forced = pool.submit(
            recorder.authenticate,
            system,
            "forced-inflight-rotation",
            "edge-a",
            b"old-password",
            expected_valid=True,
            require_fail_open=True,
        )
        entered = backend.entered.wait(1)
        recorder.guard(
            "forced-request-entered-before-activation",
            entered,
            "a v1 request must be paused inside version-specific backend verification",
        )
        if not entered:
            backend.release.set()
            forced.result()
            return recorder.finish(attempts)
        futures = [pool.submit(login, worker, counts[worker]) for worker in range(workers)]
        system.control.activate(pending)
        backend.release.set()
        start.set()
        forced.result()
        for future in futures:
            future.result()
    recorder.authenticate(
        system,
        "new-after-concurrent-rotation",
        "edge-a",
        b"new-password",
        expected_valid=True,
        recovery_check=True,
    )
    return recorder.finish(attempts)


def _scenario_delete_reuse(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    system = _System(config, seed)
    recorder = _Recorder(SCENARIOS[7], seed)
    system.activate(1, 1, {"v1": b"old-password"})
    system.control.delete_account("alice", expected_generation=1)
    recorder.authenticate(
        system,
        "deleted-stale-edge",
        "edge-a",
        b"old-password",
        expected_valid=False,
        require_fail_open=True,
        require_backend=True,
    )
    system.activate(
        2,
        1,
        {"v1": b"reuse-password"},
        account_id="account-2",
        replicate_directory=False,
    )
    recorder.authenticate(
        system,
        "reused-stale-edge",
        "edge-a",
        b"reuse-password",
        expected_valid=True,
        require_fail_open=True,
        require_backend=True,
    )
    system.directory.replicate_to_edge("edge-a", "alice")
    recorder.authenticate(
        system,
        "reused-recovered",
        "edge-a",
        b"reuse-password",
        expected_valid=True,
        recovery_check=True,
    )
    return recorder.finish(int(config["concurrent_login_attempts"]))


def _scenario_cache_rotation(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    cache_config = config["negative_cache"]
    cache = _PausingNegativeCache(
        capacity=int(cache_config["capacity"]),
        policy=TinyLfuPolicy(reset_after=128),
        max_ttl_seconds=float(cache_config["max_ttl_seconds"]),
        max_entries_per_account=int(cache_config["max_entries_per_account"]),
        max_entries_per_region=int(cache_config["max_entries_per_region"]),
    )
    system = _System(config, seed, cache=cache)
    recorder = _Recorder(SCENARIOS[8], seed)
    system.activate(1, 1, {"v1": b"old-password"})
    recorder.authenticate(
        system, "old-valid-before-cache", "edge-a", b"old-password", expected_valid=True
    )
    cache.arm(credential_set_version=1)
    with ThreadPoolExecutor(max_workers=1) as pool:
        inflight = pool.submit(
            recorder.authenticate,
            system,
            "mismatch-inflight-cache-insert",
            "edge-a",
            b"future-password",
            expected_valid=False,
        )
        entered = cache.entered.wait(1)
        recorder.guard(
            "cache-insert-paused-across-rotation",
            entered,
            "a typed v1 mismatch must pause inside cache insertion",
        )
        system.activate(1, 2, {"v2": b"future-password"})
        cache.release.set()
        inflight.result()
    recorder.authenticate(
        system,
        "future-password-after-rotation",
        "edge-b",
        b"future-password",
        expected_valid=True,
        recovery_check=True,
    )
    return recorder.finish(int(config["concurrent_login_attempts"]))


def _scenario_dual_active(config: Mapping[str, Any], seed: int) -> dict[str, object]:
    system = _System(config, seed)
    recorder = _Recorder(SCENARIOS[9], seed)
    system.activate(1, 1, {"old": b"old-password"})
    system.activate(
        1,
        2,
        {"old": b"old-password", "new": b"new-password"},
    )
    recorder.authenticate(system, "dual-old", "edge-a", b"old-password", expected_valid=True)
    recorder.authenticate(
        system,
        "dual-new",
        "edge-b",
        b"new-password",
        expected_valid=True,
        recovery_check=True,
    )
    mismatch = system.engine.authenticate("edge-a", "alice", b"known-false-positive")
    checked = (
        frozenset()
        if mismatch.backend_result is None
        else mismatch.backend_result.checked_authenticator_ids
    )
    recorder.guard(
        "mismatch-checks-complete-dual-set",
        checked == frozenset({"old", "new"}),
        f"checked={sorted(checked)}",
    )
    return recorder.finish(int(config["concurrent_login_attempts"]))


SCENARIO_RUNNERS: dict[str, Callable[[Mapping[str, Any], int], dict[str, object]]] = {
    SCENARIOS[0]: _scenario_delayed_directory,
    SCENARIOS[1]: _scenario_delayed_delta,
    SCENARIOS[2]: _scenario_activation_messages,
    SCENARIOS[3]: _scenario_restart,
    SCENARIOS[4]: _scenario_backend_write,
    SCENARIOS[5]: _scenario_filter_before_directory,
    SCENARIOS[6]: _scenario_concurrent_rotation,
    SCENARIOS[7]: _scenario_delete_reuse,
    SCENARIOS[8]: _scenario_cache_rotation,
    SCENARIOS[9]: _scenario_dual_active,
}


def run_matrix(
    config: Mapping[str, Any],
    *,
    seeds: Sequence[int] | None = None,
    scenarios: Sequence[str] | None = None,
) -> list[dict[str, object]]:
    selected_seeds = tuple(config["seeds"] if seeds is None else seeds)
    selected_scenarios = tuple(config["scenarios"] if scenarios is None else scenarios)
    rows = []
    for seed in selected_seeds:
        for scenario in selected_scenarios:
            rows.append(SCENARIO_RUNNERS[scenario](config, int(seed)))
    return rows


def _git_state() -> dict[str, object]:
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {"commit": commit, "clean": status == "", "status": status.splitlines()}


def _require_clean_source(expected_commit: str) -> dict[str, object]:
    state = _git_state()
    if state["commit"] != expected_commit or state["clean"] is not True:
        raise RuntimeError("formal E8 consumer requires the exact clean expected commit")
    return state


def _require_unchanged_clean_source(
    expected_commit: str, before: Mapping[str, object]
) -> dict[str, object]:
    after = _git_state()
    if after != before or after.get("commit") != expected_commit or after.get("clean") is not True:
        raise RuntimeError("formal E8 source changed during deterministic execution")
    return after


def _validate_event(event: object) -> dict[str, object]:
    value = _mapping(event, "fault event")
    _exact_keys(
        value,
        {
            "label",
            "edge",
            "expected_valid",
            "require_fail_open",
            "require_backend",
            "recovery_check",
            "accepted",
            "pre_screen_rejected",
            "route",
            "directory_status",
            "directory_account_id",
            "directory_account_generation",
            "directory_credential_set_version",
            "directory_epoch",
            "positive_disposition",
            "backend_kind",
            "backend_expected_version",
            "backend_checked_version",
            "backend_checked_account_id",
            "backend_checked_account_generation",
            "backend_checked_authenticator_ids",
            "backend_calls_delta",
        },
        "fault event",
    )
    for field in (
        "expected_valid",
        "require_fail_open",
        "require_backend",
        "recovery_check",
        "accepted",
        "pre_screen_rejected",
    ):
        if type(value[field]) is not bool:
            raise ValueError(f"fault event {field} must be Boolean")
    if value["edge"] not in EDGES:
        raise ValueError("fault event edge is outside the contract")
    if value["require_backend"] is True:
        _integer(value["backend_calls_delta"], "backend_calls_delta", 1)
    elif value["backend_calls_delta"] is not None:
        raise ValueError("backend_calls_delta is attributable only on required backend paths")
    if value["route"] not in {route.value for route in AuthRoute}:
        raise ValueError("fault event route is invalid")
    if value["directory_status"] not in {status.value for status in DirectoryStatus}:
        raise ValueError("fault event directory status is invalid")
    for field in ("directory_account_id", "backend_checked_account_id"):
        if value[field] is not None and (type(value[field]) is not str or not value[field]):
            raise ValueError(f"fault event {field} must be null or a nonempty string")
    for field in (
        "directory_account_generation",
        "directory_credential_set_version",
        "backend_expected_version",
        "backend_checked_version",
        "backend_checked_account_generation",
    ):
        if value[field] is not None:
            _integer(value[field], f"fault event {field}", 1)
    _integer(value["directory_epoch"], "fault event directory_epoch")
    checked_authenticators = value["backend_checked_authenticator_ids"]
    if (
        type(checked_authenticators) is not list
        or any(type(item) is not str or not item for item in checked_authenticators)
        or checked_authenticators != sorted(set(checked_authenticators))
    ):
        raise ValueError("fault event backend_checked_authenticator_ids must be sorted and unique")
    if value["positive_disposition"] not in {
        None,
        *(disposition.value for disposition in PositiveDisposition),
    }:
        raise ValueError("fault event positive disposition is invalid")
    if value["backend_kind"] not in {
        None,
        *(kind.value for kind in BackendResultKind),
    }:
        raise ValueError("fault event backend kind is invalid")
    backend_routes = {
        AuthRoute.BACKEND_MATCH.value,
        AuthRoute.BACKEND_DENY.value,
        AuthRoute.FAIL_OPEN_BACKEND.value,
    }
    if (value["route"] in backend_routes) is (value["backend_kind"] is None):
        raise ValueError("fault event route/backend result relation is invalid")
    if value["backend_kind"] is None and any(
        value[field] is not None
        for field in (
            "backend_expected_version",
            "backend_checked_version",
            "backend_checked_account_id",
            "backend_checked_account_generation",
        )
    ):
        raise ValueError("fault event without a backend result has backend metadata")
    if value["backend_kind"] is None and checked_authenticators:
        raise ValueError("fault event without a backend result has authenticator metadata")
    expected_positive = {
        AuthRoute.BACKEND_MATCH.value: PositiveDisposition.POSITIVE.value,
        AuthRoute.BACKEND_DENY.value: PositiveDisposition.POSITIVE.value,
        AuthRoute.POSITIVE_SCREEN_REJECT.value: PositiveDisposition.NEGATIVE.value,
        AuthRoute.NEGATIVE_CACHE_REJECT.value: None,
    }
    if (
        value["route"] in expected_positive
        and value["positive_disposition"] != expected_positive[value["route"]]
    ):
        raise ValueError("fault event route/positive disposition relation is invalid")
    if value["route"] == AuthRoute.BACKEND_MATCH.value and value["accepted"] is not True:
        raise ValueError("backend match must be accepted")
    if (
        value["route"]
        not in {
            AuthRoute.BACKEND_MATCH.value,
            AuthRoute.FAIL_OPEN_BACKEND.value,
        }
        and value["accepted"] is not False
    ):
        raise ValueError("rejection routes must not be accepted")
    return value


def validate_row(
    row: object,
    config: Mapping[str, Any],
    expected_seed: int,
    expected_scenario: str,
) -> dict[str, object]:
    value = _mapping(row, "fault row")
    _exact_keys(
        value,
        {
            "schema",
            "scenario",
            "seed",
            "evidence_scope",
            "events",
            "guards",
            "summary",
            "coverage",
            "status",
            "row_id",
        },
        "fault row",
    )
    if value["schema"] != ROW_SCHEMA or value["evidence_scope"] != EVIDENCE_SCOPE:
        raise ValueError("fault row schema/scope mismatch")
    if type(value["scenario"]) is not str:
        raise ValueError("fault row scenario must be a string")
    row_seed = _integer(value["seed"], "fault row seed", 1)
    if value["scenario"] != expected_scenario or row_seed != expected_seed:
        raise ValueError("fault row coordinate mismatch")
    if type(value["events"]) is not list or type(value["guards"]) is not list:
        raise ValueError("fault row events and guards must be arrays")
    events = [_validate_event(event) for event in value["events"]]
    labels = [event["label"] for event in events]
    if any(type(label) is not str or not label for label in labels) or len(set(labels)) != len(
        labels
    ):
        raise ValueError("fault event labels must be nonempty and unique")
    expected_events = expected_event_contracts(
        expected_scenario,
        expected_seed,
        int(config["concurrent_login_attempts"]),
    )
    if labels != sorted(expected_events):
        raise ValueError("fault row does not match the fixed per-scenario event set")
    for event in events:
        contract = expected_events[str(event["label"])]
        for field, expected in contract.items():
            _exact_value(
                event[field],
                expected,
                f"fault event {event['label']}.{field}",
            )
    guards = [_mapping(guard, "fault guard") for guard in value["guards"]]
    for guard in guards:
        _exact_keys(guard, {"label", "passed", "detail"}, "fault guard")
        if type(guard["label"]) is not str or type(guard["detail"]) is not str:
            raise ValueError("fault guard labels/details must be strings")
        if type(guard["passed"]) is not bool:
            raise ValueError("fault guard passed must be Boolean")
    if len({guard["label"] for guard in guards}) != len(guards):
        raise ValueError("fault guard labels must be unique")
    guard_labels = [str(guard["label"]) for guard in guards]
    if guard_labels != sorted(expected_guard_labels(expected_scenario)):
        raise ValueError("fault row does not match the fixed per-scenario guard set")
    recomputed_summary = _summarize_observations(events, guards)
    _exact_value(value["summary"], recomputed_summary, "fault row summary")
    valid_floor, fail_open_floor, recovery_floor, guard_floor = SCENARIO_CONTRACT[expected_scenario]
    if expected_scenario == "concurrent_password_change_and_login":
        valid_floor = int(config["concurrent_login_attempts"]) + 1
    recomputed_coverage = {
        "valid_attempts_floor": valid_floor,
        "fail_open_expectations_floor": fail_open_floor,
        "recovery_checks_floor": recovery_floor,
        "guard_expectations_floor": guard_floor,
        "complete": (
            recomputed_summary["valid_attempts"] >= valid_floor
            and recomputed_summary["fail_open_expectations"] >= fail_open_floor
            and recomputed_summary["recovery_checks"] >= recovery_floor
            and recomputed_summary["guard_expectations"] >= guard_floor
        ),
    }
    _exact_value(value["coverage"], recomputed_coverage, "fault row coverage")
    failures = sum(
        recomputed_summary[field]
        for field in (
            "structural_false_rejects",
            "valid_acceptance_failures",
            "invalid_acceptance_failures",
            "fail_open_violations",
            "backend_forward_violations",
            "recovery_failures",
            "guard_failures",
        )
    )
    expected_status = "PASS" if recomputed_coverage["complete"] and failures == 0 else "FAIL"
    _exact_value(value["status"], expected_status, "fault row status")
    if expected_status != "PASS":
        raise ValueError("fault row did not pass")
    body = {key: item for key, item in value.items() if key != "row_id"}
    if value["row_id"] != _identity(body):
        raise ValueError("fault row identity mismatch")
    return value


def build_artifact(
    config: Mapping[str, Any],
    config_id: str,
    expected_commit: str,
    before: Mapping[str, object],
    after: Mapping[str, object],
    rows: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    expected_count = len(config["seeds"]) * len(config["scenarios"])
    audit = {
        "expected_rows": expected_count,
        "actual_rows": len(rows),
        "passing_rows": sum(row["status"] == "PASS" for row in rows),
        "structural_false_rejects": sum(
            int(row["summary"]["structural_false_rejects"]) for row in rows
        ),
        "valid_acceptance_failures": sum(
            int(row["summary"]["valid_acceptance_failures"]) for row in rows
        ),
        "invalid_acceptance_failures": sum(
            int(row["summary"]["invalid_acceptance_failures"]) for row in rows
        ),
        "fail_open_violations": sum(int(row["summary"]["fail_open_violations"]) for row in rows),
        "backend_forward_violations": sum(
            int(row["summary"]["backend_forward_violations"]) for row in rows
        ),
        "recovery_failures": sum(int(row["summary"]["recovery_failures"]) for row in rows),
        "guard_failures": sum(int(row["summary"]["guard_failures"]) for row in rows),
    }
    status = (
        "PASS"
        if (
            before == after
            and before.get("commit") == expected_commit
            and before.get("clean") is True
            and audit["actual_rows"] == audit["expected_rows"]
            and audit["passing_rows"] == audit["expected_rows"]
            and all(
                audit[field] == 0
                for field in audit
                if field.endswith("failures")
                or field.endswith("violations")
                or field == "structural_false_rejects"
            )
        )
        else "FAIL"
    )
    body: dict[str, object] = {
        "schema": ARTIFACT_SCHEMA,
        "experiment_id": config["experiment_id"],
        "evidence_scope": EVIDENCE_SCOPE,
        "source_commit": expected_commit,
        "config_id": config_id,
        "git_before": dict(before),
        "git_after": dict(after),
        "host": {
            "node": platform.node(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "validation_mode": "EXACT_CLEAN_SOURCE_AND_DETERMINISTIC_REEXECUTION",
        "rows": list(rows),
        "audit": audit,
        "status": status,
        "g7_status": "BLOCKED_PENDING_E9_TIMING_AND_COMPLETE_GATE_REVIEW",
    }
    return {**body, "artifact_id": _identity(body)}


def validate_artifact(
    artifact: object,
    config: Mapping[str, Any],
    config_id: str,
    expected_commit: str,
) -> dict[str, object]:
    value = _mapping(artifact, "fault artifact")
    _exact_keys(
        value,
        {
            "schema",
            "experiment_id",
            "evidence_scope",
            "source_commit",
            "config_id",
            "git_before",
            "git_after",
            "host",
            "validation_mode",
            "rows",
            "audit",
            "status",
            "g7_status",
            "artifact_id",
        },
        "fault artifact",
    )
    if value["schema"] != ARTIFACT_SCHEMA or value["evidence_scope"] != EVIDENCE_SCOPE:
        raise ValueError("fault artifact schema/scope mismatch")
    if value["experiment_id"] != config["experiment_id"]:
        raise ValueError("fault artifact experiment mismatch")
    if value["validation_mode"] != "EXACT_CLEAN_SOURCE_AND_DETERMINISTIC_REEXECUTION":
        raise ValueError("fault artifact validation mode mismatch")
    if value["source_commit"] != expected_commit or value["config_id"] != config_id:
        raise ValueError("fault artifact provenance mismatch")
    before = _mapping(value["git_before"], "git_before")
    after = _mapping(value["git_after"], "git_after")
    for label, git_state in (("git_before", before), ("git_after", after)):
        _exact_keys(git_state, {"commit", "clean", "status"}, label)
        if (
            type(git_state["commit"]) is not str
            or len(git_state["commit"]) != 40
            or any(character not in "0123456789abcdef" for character in git_state["commit"])
        ):
            raise ValueError(f"{label}.commit must be a full lowercase Git commit")
        if type(git_state["clean"]) is not bool or type(git_state["status"]) is not list:
            raise ValueError(f"{label} clean/status types are invalid")
        if any(type(line) is not str for line in git_state["status"]):
            raise ValueError(f"{label}.status entries must be strings")
    if (
        before != after
        or before.get("commit") != expected_commit
        or before.get("clean") is not True
    ):
        raise ValueError("fault artifact requires unchanged clean exact source")
    host = _mapping(value["host"], "fault artifact host")
    _exact_keys(host, {"node", "machine", "platform", "python"}, "fault artifact host")
    if any(type(item) is not str or not item for item in host.values()):
        raise ValueError("fault artifact host fields must be nonempty strings")
    expected_coordinates = [
        (int(seed), scenario) for seed in config["seeds"] for scenario in config["scenarios"]
    ]
    rows = value["rows"]
    if type(rows) is not list or len(rows) != len(expected_coordinates):
        raise ValueError("fault artifact row coverage mismatch")
    validated = [
        validate_row(row, config, seed, scenario)
        for row, (seed, scenario) in zip(rows, expected_coordinates, strict=True)
    ]
    replayed = run_matrix(config)
    _exact_value(validated, replayed, "fault artifact deterministic replay")
    rebuilt = build_artifact(config, config_id, expected_commit, before, after, validated)
    for field in ("audit", "status", "g7_status"):
        _exact_value(value[field], rebuilt[field], f"fault artifact {field}")
    body = {key: item for key, item in value.items() if key != "artifact_id"}
    if value["artifact_id"] != _identity(body):
        raise ValueError("fault artifact identity mismatch")
    if value["status"] != "PASS":
        raise ValueError("fault artifact did not pass")
    return value


def _write_json(path: Path, value: object, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("--config", type=Path, required=True)
    run.add_argument("--expected-commit", required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--overwrite", action="store_true")
    validate = subparsers.add_parser("validate")
    validate.add_argument("--config", type=Path, required=True)
    validate.add_argument("--expected-commit", required=True)
    validate.add_argument("--input", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    config, config_id = load_config(args.config)
    if args.command == "validate":
        before = _require_clean_source(args.expected_commit)
        artifact = load_json_object(args.input)
        validate_artifact(artifact, config, config_id, args.expected_commit)
        _require_unchanged_clean_source(args.expected_commit, before)
        print(json.dumps({"status": "PASS", "config_id": config_id}, sort_keys=True))
        return 0

    before = _require_clean_source(args.expected_commit)
    rows = run_matrix(config)
    after = _require_unchanged_clean_source(args.expected_commit, before)
    artifact = build_artifact(config, config_id, args.expected_commit, before, after, rows)
    validate_artifact(artifact, config, config_id, args.expected_commit)
    _require_unchanged_clean_source(args.expected_commit, before)
    _write_json(args.output, artifact, args.overwrite)
    print(json.dumps(artifact["audit"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
