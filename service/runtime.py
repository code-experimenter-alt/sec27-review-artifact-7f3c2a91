from __future__ import annotations

import queue
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from threading import Lock, RLock, Thread
from typing import Any, Protocol

from dataplane.negative_cache import (
    LruPolicy,
    NegativeCache,
    NegativeKey,
    NegativeKeyDeriver,
    TinyLfuPolicy,
)
from dataplane.types import BackendResultKind, TypedBackendResult
from reference.filters import ScreeningFilter, TokenCodec

from .metrics import FixedHistogram
from .padding import PaddingScheduler
from .singleflight import AsyncSingleflight
from .types import (
    AuthRequest,
    ServiceAccount,
    ServiceLimits,
    ServiceMethod,
    ServiceRoute,
    TrafficClass,
)


class TypedVerifier(Protocol):
    def verify(
        self,
        account: ServiceAccount | None,
        username: str,
        password: bytes,
    ) -> TypedBackendResult: ...


@dataclass
class _RequestContext:
    request: AuthRequest
    phase: str
    scheduled_ns: int
    ingress_ns: int
    deadline_ns: int
    window_start_ns: int
    window_end_ns: int
    flight_key: NegativeKey | None = None
    flight_leader: bool = False


@dataclass
class _BackendJob:
    context: _RequestContext
    account: ServiceAccount | None
    negative_key: NegativeKey | None


@dataclass
class _PhaseState:
    counters: Counter[str] = field(default_factory=Counter)
    histograms: dict[str, FixedHistogram] = field(default_factory=dict)

    def add_latency(self, name: str, value_ns: int) -> None:
        histogram = self.histograms.get(name)
        if histogram is None:
            histogram = FixedHistogram()
            self.histograms[name] = histogram
        histogram.add(value_ns)


@dataclass(frozen=True)
class ShutdownReport:
    clean: bool
    drained_before_deadline: bool
    frontend_workers_stopped: bool
    backend_workers_stopped: bool
    padding_stopped: bool
    pending_after_shutdown: int
    elapsed_seconds: float

    def __bool__(self) -> bool:
        return self.clean

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AuthenticationService:
    """Bounded in-process authentication service for open-loop experiments."""

    _STOP = object()
    _BACKEND_ERROR_KINDS = {
        BackendResultKind.TRANSIENT_FAILURE,
        BackendResultKind.VERSION_MISMATCH,
        BackendResultKind.PARTIAL_AUTHENTICATOR_FAILURE,
    }

    def __init__(
        self,
        accounts: list[ServiceAccount],
        codec: TokenCodec,
        positive_filter: ScreeningFilter,
        verifier: TypedVerifier,
        method: ServiceMethod,
        limits: ServiceLimits,
        negative_key: bytes,
    ) -> None:
        if not accounts:
            raise ValueError("at least one service account is required")
        self.accounts = {account.username.casefold(): account for account in accounts}
        if len(self.accounts) != len(accounts):
            raise ValueError("service usernames must be unique under case folding")
        self.codec = codec
        self.positive_filter = positive_filter
        self.verifier = verifier
        self.method = method
        self.limits = limits
        self.negative_keys = NegativeKeyDeriver(negative_key)
        self.negative_cache: NegativeCache | None = None
        if method.cache_policy == "lru":
            policy = LruPolicy()
        elif method.cache_policy == "tinylfu":
            policy = TinyLfuPolicy(reset_after=max(16, limits.cache_capacity * 16))
        else:
            policy = None
        if policy is not None:
            self.negative_cache = NegativeCache(
                capacity=limits.cache_capacity,
                policy=policy,
                max_ttl_seconds=limits.cache_ttl_seconds,
                max_entries_per_account=limits.cache_max_entries_per_account,
                max_entries_per_region=limits.cache_capacity,
            )
        self.singleflight: AsyncSingleflight[_RequestContext] | None = None
        if method.use_singleflight:
            self.singleflight = AsyncSingleflight(
                limits.max_waiters_per_key,
                limits.max_waiters_global,
            )

        self._frontend_queue: queue.Queue[object] = queue.Queue(
            maxsize=limits.frontend_queue_capacity
        )
        self._backend_queue: queue.Queue[object] = queue.Queue(
            maxsize=limits.backend_queue_capacity
        )
        self._padding = PaddingScheduler(limits.max_padding_timers)
        self._lock = RLock()
        # NegativeCache protects each operation, but metric deltas require one
        # serialized snapshot/insert/snapshot transaction.
        self._cache_accounting_lock = Lock()
        self._states: dict[str, _PhaseState] = {}
        self._pending: dict[int, _RequestContext] = {}
        self._accepting = True
        self._active_frontend_workers = 0
        self._active_backend_workers = 0
        self._shutdown_report: ShutdownReport | None = None
        self._frontend_threads: list[Thread] = []
        self._backend_threads: list[Thread] = []
        for index in range(limits.frontend_workers):
            thread = Thread(
                target=self._frontend_worker,
                name=f"service-frontend-{index}",
                daemon=True,
            )
            thread.start()
            self._frontend_threads.append(thread)
        for index in range(limits.backend_workers):
            thread = Thread(
                target=self._backend_worker,
                name=f"service-backend-{index}",
                daemon=True,
            )
            thread.start()
            self._backend_threads.append(thread)

    @property
    def _threads(self) -> list[Thread]:
        return [*self._frontend_threads, *self._backend_threads]

    def _state(self, phase: str) -> _PhaseState:
        state = self._states.get(phase)
        if state is None:
            state = _PhaseState()
            self._states[phase] = state
        return state

    def _count(self, phase: str, name: str, value: int = 1) -> None:
        with self._lock:
            self._state(phase).counters[name] += value

    def _latency(self, phase: str, name: str, value_ns: int) -> None:
        with self._lock:
            self._state(phase).add_latency(name, value_ns)

    def _record_event_error(
        self, phase: str, category: str, error: BaseException | None = None
    ) -> None:
        with self._lock:
            counters = self._state(phase).counters
            counters["event_errors"] += 1
            counters[f"event_error_{category}"] += 1
            if error is not None:
                counters[f"event_error_type_{type(error).__name__}"] += 1

    @staticmethod
    def _record_terminal_locked(
        state: _PhaseState,
        request: AuthRequest,
        route: ServiceRoute,
        *,
        admitted: bool,
        response_emitted: bool,
        auth_accepted: bool,
    ) -> None:
        counters = state.counters
        counters["terminal_outcomes"] += 1
        counters[f"terminal_{request.traffic_class.value}"] += 1
        counters[f"route_{route.value}"] += 1
        if admitted:
            counters["accepted_terminal_outcomes"] += 1
            if response_emitted:
                counters["responses"] += 1
            else:
                counters["admitted_no_response_terminal"] += 1
        else:
            counters["immediate_terminal_outcomes"] += 1
        if auth_accepted:
            counters["accepted"] += 1
        else:
            counters["terminal_rejections"] += 1

    def _record_immediate_terminal_locked(
        self,
        state: _PhaseState,
        request: AuthRequest,
        route: ServiceRoute,
    ) -> None:
        self._record_terminal_locked(
            state,
            request,
            route,
            admitted=False,
            response_emitted=False,
            auth_accepted=False,
        )

    def submit(
        self,
        request: AuthRequest,
        phase: str,
        scheduled_ns: int,
        window_start_ns: int,
        window_end_ns: int,
    ) -> bool:
        """Attempt one ingress submission without waiting for completion."""

        ingress_ns = time.perf_counter_ns()
        with self._lock:
            state = self._state(phase)
            counters = state.counters
            counters["offered_requests"] += 1
            counters[f"offered_{request.traffic_class.value}"] += 1
            state.add_latency("arrival_lag_ns", max(0, ingress_ns - scheduled_ns))
            if window_start_ns <= ingress_ns < window_end_ns:
                counters["ingress_within_window"] += 1
                counters[f"ingress_within_window_{request.traffic_class.value}"] += 1
            else:
                counters["ingress_outside_window"] += 1
                counters[f"ingress_outside_window_{request.traffic_class.value}"] += 1
            if not self._accepting:
                counters["shutdown_rejections"] += 1
                self._record_immediate_terminal_locked(
                    state, request, ServiceRoute.SHUTDOWN_CANCELLED
                )
                return False
            if request.request_id in self._pending:
                counters["duplicate_request_ids"] += 1
                counters["event_errors"] += 1
                counters["event_error_duplicate_request_id"] += 1
                self._record_immediate_terminal_locked(state, request, ServiceRoute.BACKEND_FAILURE)
                return False
            if len(self._pending) >= self.limits.max_connections:
                counters["connection_drops"] += 1
                self._record_immediate_terminal_locked(state, request, ServiceRoute.CONNECTION_DROP)
                return False
            context = _RequestContext(
                request=request,
                phase=phase,
                scheduled_ns=scheduled_ns,
                ingress_ns=ingress_ns,
                deadline_ns=ingress_ns + int(self.limits.request_timeout_seconds * 1_000_000_000),
                window_start_ns=window_start_ns,
                window_end_ns=window_end_ns,
            )
            self._pending[request.request_id] = context
            counters["connections_accepted"] += 1
            counters["peak_connections"] = max(counters["peak_connections"], len(self._pending))
        try:
            self._frontend_queue.put_nowait(context)
            self._count(phase, "frontend_enqueued")
            return True
        except queue.Full:
            self._count(phase, "frontend_queue_drops")
            self._defer_completion(context, ServiceRoute.FRONTEND_QUEUE_DROP, False)
            return False

    def _frontend_worker(self) -> None:
        while True:
            item = self._frontend_queue.get()
            try:
                if item is self._STOP:
                    return
                if not isinstance(item, _RequestContext):
                    continue
                with self._lock:
                    self._active_frontend_workers += 1
                try:
                    self._process_frontend(item)
                except Exception as exc:
                    self._record_event_error(item.phase, "frontend_worker", exc)
                    self._count(item.phase, "frontend_exceptions")
                    waiters = self._finish_flight(item)
                    self._defer_completion(item, ServiceRoute.BACKEND_FAILURE, False)
                    for waiter in waiters:
                        self._defer_completion(waiter, ServiceRoute.BACKEND_FAILURE, False)
                finally:
                    with self._lock:
                        self._active_frontend_workers -= 1
            finally:
                self._frontend_queue.task_done()

    def _process_frontend(self, context: _RequestContext) -> None:
        started_ns = time.perf_counter_ns()
        cpu_started_ns = time.thread_time_ns()
        self._latency(
            context.phase,
            "frontend_queue_residence_ns",
            started_ns - context.ingress_ns,
        )
        account = self.accounts.get(context.request.username.casefold())
        negative_key: NegativeKey | None = None
        local_route: ServiceRoute | None = None

        if account is not None and self.method.use_positive_screen:
            query = account.screen_query(self.codec, context.request.password)
            negative_key = self.negative_keys.derive(account.view, query.token)
            if self.negative_cache is not None:
                cache_result = self.negative_cache.lookup(negative_key, expected_view=account.view)
                self._count(context.phase, "cache_hits" if cache_result.hit else "cache_misses")
                if cache_result.hit:
                    local_route = ServiceRoute.NEGATIVE_CACHE_REJECT
            if local_route is None:
                screen_result = self.positive_filter.query(query)
                self._count(context.phase, "screen_probes", screen_result.probes)
                self._count(
                    context.phase,
                    "positive_screen_positive"
                    if screen_result.positive
                    else "positive_screen_negative",
                )
                if not screen_result.positive:
                    local_route = ServiceRoute.POSITIVE_SCREEN_REJECT

        elapsed_ns = time.perf_counter_ns() - started_ns
        ended_ns = started_ns + elapsed_ns
        overlap_ns = max(
            0,
            min(ended_ns, context.window_end_ns) - max(started_ns, context.window_start_ns),
        )
        cpu_ns = time.thread_time_ns() - cpu_started_ns
        self._latency(context.phase, "frontend_service_ns", elapsed_ns)
        self._count(context.phase, "frontend_busy_wall_ns", elapsed_ns)
        self._count(context.phase, "frontend_busy_window_ns", overlap_ns)
        self._count(context.phase, "frontend_cpu_ns", cpu_ns)
        if local_route is not None:
            self._defer_completion(context, local_route, False)
            return

        if self.singleflight is not None and negative_key is not None:
            disposition = self.singleflight.join_or_lead(negative_key, context)
            context.flight_key = negative_key
            if disposition == "joined":
                self._count(context.phase, "singleflight_suppressed")
                return
            if disposition == "rejected":
                self._count(context.phase, "singleflight_overflow")
                self._defer_completion(context, ServiceRoute.SINGLEFLIGHT_OVERFLOW, False)
                return
            context.flight_leader = True

        job = _BackendJob(context, account, negative_key)
        try:
            self._backend_queue.put_nowait(job)
            self._count(context.phase, "backend_enqueued")
        except queue.Full:
            self._count(context.phase, "backend_queue_drops")
            waiters = self._finish_flight(context)
            self._defer_completion(context, ServiceRoute.BACKEND_QUEUE_DROP, False)
            for waiter in waiters:
                self._count(waiter.phase, "backend_queue_drops")
                self._defer_completion(waiter, ServiceRoute.BACKEND_QUEUE_DROP, False)

    def _finish_flight(self, context: _RequestContext) -> list[_RequestContext]:
        if self.singleflight is None or context.flight_key is None or not context.flight_leader:
            return []
        context.flight_leader = False
        return self.singleflight.finish(context.flight_key)

    def _backend_worker(self) -> None:
        while True:
            item = self._backend_queue.get()
            try:
                if item is self._STOP:
                    return
                if not isinstance(item, _BackendJob):
                    continue
                with self._lock:
                    self._active_backend_workers += 1
                try:
                    self._process_backend(item)
                except Exception as exc:
                    self._record_event_error(item.context.phase, "backend_worker", exc)
                    self._count(item.context.phase, "backend_worker_exceptions")
                    self._fail_backend_job(item)
                finally:
                    with self._lock:
                        self._active_backend_workers -= 1
            finally:
                self._backend_queue.task_done()

    def _process_backend(self, job: _BackendJob) -> None:
        context = job.context
        started_ns = time.perf_counter_ns()
        cpu_started_ns = time.thread_time_ns()
        started_inside_window = context.window_start_ns <= started_ns < context.window_end_ns
        verifier_raised = False
        try:
            result = self.verifier.verify(
                job.account,
                context.request.username,
                context.request.password,
            )
            if not isinstance(result, TypedBackendResult):
                raise TypeError("verifier must return TypedBackendResult")
        except Exception as exc:
            verifier_raised = True
            self._record_event_error(context.phase, "verifier", exc)
            self._count(context.phase, "backend_exceptions")
            result = TypedBackendResult.transient_failure(
                None if job.account is None else job.account.credential_set_version,
                f"service verifier exception: {type(exc).__name__}",
            )
        elapsed_ns = time.perf_counter_ns() - started_ns
        ended_ns = started_ns + elapsed_ns
        overlap_ns = max(
            0,
            min(ended_ns, context.window_end_ns) - max(started_ns, context.window_start_ns),
        )
        cpu_ns = time.thread_time_ns() - cpu_started_ns
        self._latency(context.phase, "backend_service_ns", elapsed_ns)
        self._count(context.phase, "backend_busy_wall_ns", elapsed_ns)
        self._count(context.phase, "backend_busy_window_ns", overlap_ns)
        self._count(context.phase, "backend_cpu_ns", cpu_ns)
        self._count(context.phase, "backend_checks")
        if started_inside_window:
            self._count(context.phase, "backend_checks_started_within_window")

        if result.kind is BackendResultKind.MATCH:
            category = "valid"
        elif result.kind in {
            BackendResultKind.CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS,
            BackendResultKind.NO_ACCOUNT,
        }:
            category = "invalid"
        elif result.kind in self._BACKEND_ERROR_KINDS:
            category = "error"
            if not verifier_raised:
                self._record_event_error(context.phase, "typed_backend_failure")
        else:
            category = "policy"
        self._count(context.phase, f"backend_{category}_checks")
        if started_inside_window:
            self._count(
                context.phase,
                f"backend_{category}_checks_started_within_window",
            )

        if (
            self.negative_cache is not None
            and job.account is not None
            and job.negative_key is not None
            and result.is_exact_mismatch_for(job.account.view)
        ):
            with self._cache_accounting_lock:
                before = self.negative_cache.metrics_snapshot()
                inserted = self.negative_cache.insert(
                    job.negative_key,
                    job.account.view,
                    region=0,
                    ttl_seconds=self.limits.cache_ttl_seconds,
                )
                after = self.negative_cache.metrics_snapshot()
            self._count(
                context.phase,
                "cache_inserted" if inserted else "cache_admission_rejected",
            )
            for metric in (
                "evictions",
                "ttl_clamped",
                "account_quota_pressure",
                "region_quota_pressure",
            ):
                delta = after.get(metric, 0) - before.get(metric, 0)
                if delta:
                    self._count(context.phase, f"cache_{metric}", delta)

        waiters = self._finish_flight(context)
        self._complete_backend_result(context, result)
        for waiter in waiters:
            self._complete_backend_result(waiter, result)

    def _fail_backend_job(self, job: _BackendJob) -> None:
        waiters = self._finish_flight(job.context)
        self._defer_completion(job.context, ServiceRoute.BACKEND_FAILURE, False)
        for waiter in waiters:
            self._defer_completion(waiter, ServiceRoute.BACKEND_FAILURE, False)

    def _complete_backend_result(
        self, context: _RequestContext, result: TypedBackendResult
    ) -> None:
        if result.kind is BackendResultKind.MATCH:
            route, accepted = ServiceRoute.BACKEND_MATCH, True
        elif result.kind is BackendResultKind.NO_ACCOUNT:
            route, accepted = ServiceRoute.UNKNOWN_BACKEND_REJECT, False
        elif (
            result.kind is BackendResultKind.CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS
        ):
            route, accepted = ServiceRoute.BACKEND_MISMATCH, False
        else:
            route, accepted = ServiceRoute.BACKEND_FAILURE, False
            self._count(context.phase, "typed_backend_failures")
        self._defer_completion(context, route, accepted)

    def _defer_completion(
        self,
        context: _RequestContext,
        route: ServiceRoute,
        accepted: bool,
    ) -> None:
        if accepted or self.limits.failure_padding_seconds == 0:
            self._record_completion(context, route, accepted)
            return
        due_ns = max(
            time.perf_counter_ns(),
            context.ingress_ns + int(self.limits.failure_padding_seconds * 1_000_000_000),
        )
        scheduled = self._padding.schedule(
            due_ns,
            lambda: self._record_completion(context, route, accepted),
        )
        if scheduled:
            self._count(context.phase, "padding_scheduled")
        else:
            self._count(context.phase, "padding_overflow")
            self._record_event_error(context.phase, "padding_overflow")
            self._record_completion(context, route, accepted)

    def _record_completion(
        self,
        context: _RequestContext,
        route: ServiceRoute,
        accepted: bool,
        *,
        response_emitted: bool = True,
    ) -> None:
        completed_ns = time.perf_counter_ns()
        with self._lock:
            current = self._pending.get(context.request.request_id)
            if current is not context:
                return
            del self._pending[context.request.request_id]
            state = self._state(context.phase)
            self._record_terminal_locked(
                state,
                context.request,
                route,
                admitted=True,
                response_emitted=response_emitted,
                auth_accepted=accepted,
            )
            if route is ServiceRoute.SHUTDOWN_CANCELLED:
                state.counters["shutdown_cancellations"] += 1
            residence_ns = completed_ns - context.ingress_ns
            state.add_latency("residence_ns", residence_ns)
            state.add_latency(f"route_{route.value}_residence_ns", residence_ns)
            if context.request.is_legitimate:
                state.add_latency("legitimate_residence_ns", residence_ns)
                if accepted:
                    state.counters["legitimate_successes"] += 1
                    state.add_latency("legitimate_success_residence_ns", residence_ns)
                    if completed_ns <= context.window_end_ns:
                        state.counters["legitimate_successes_within_window"] += 1
            if completed_ns > context.deadline_ns:
                state.counters["late_responses"] += int(response_emitted)
                state.counters["late_terminal_outcomes"] += 1
                if context.request.is_legitimate:
                    state.counters["late_legitimate_responses"] += int(response_emitted)
                    state.counters["late_legitimate_terminal_outcomes"] += 1

    def phase_snapshot(self, phase: str, now_ns: int | None = None) -> dict[str, Any]:
        current_ns = time.perf_counter_ns() if now_ns is None else now_ns
        padding = self._padding.snapshot()
        with self._lock:
            state = self._state(phase)
            counters = dict(state.counters)
            pending = [context for context in self._pending.values() if context.phase == phase]
            overdue = [context for context in pending if context.deadline_ns <= current_ns]
            overdue_legitimate = sum(context.request.is_legitimate for context in overdue)
            histograms = {
                name: histogram.summary(
                    divisor=1_000_000 if name.endswith("residence_ns") else 1_000
                )
                for name, histogram in state.histograms.items()
            }
            route_latencies = {
                name.removeprefix("route_").removesuffix("_residence_ns"): summary
                for name, summary in histograms.items()
                if name.startswith("route_") and name.endswith("_residence_ns")
            }
            legitimate_offered = counters.get("offered_legitimate", 0)
            legitimate_timeouts = counters.get("late_legitimate_terminal_outcomes", 0) + int(
                overdue_legitimate
            )
            request_timeouts = counters.get("late_terminal_outcomes", 0) + len(overdue)
            counters["request_timeouts"] = request_timeouts
            route_total = sum(counters.get(f"route_{route.value}", 0) for route in ServiceRoute)
            offered_class_total = sum(
                counters.get(f"offered_{traffic.value}", 0) for traffic in TrafficClass
            )
            terminal_class_total = sum(
                counters.get(f"terminal_{traffic.value}", 0) for traffic in TrafficClass
            )
            backend_partition = sum(
                counters.get(f"backend_{category}_checks", 0)
                for category in ("valid", "invalid", "error", "policy")
            )
            checks = {
                "offered_equals_terminal_plus_pending": counters.get("offered_requests", 0)
                == counters.get("terminal_outcomes", 0) + len(pending),
                "offered_equals_connections_plus_immediate_terminal": counters.get(
                    "offered_requests", 0
                )
                == counters.get("connections_accepted", 0)
                + counters.get("immediate_terminal_outcomes", 0),
                "connections_equal_accepted_terminal_plus_pending": counters.get(
                    "connections_accepted", 0
                )
                == counters.get("accepted_terminal_outcomes", 0) + len(pending),
                "terminal_partition": counters.get("terminal_outcomes", 0)
                == counters.get("accepted_terminal_outcomes", 0)
                + counters.get("immediate_terminal_outcomes", 0),
                "response_partition": counters.get("accepted_terminal_outcomes", 0)
                == counters.get("responses", 0) + counters.get("admitted_no_response_terminal", 0),
                "route_partition": route_total == counters.get("terminal_outcomes", 0),
                "offered_class_partition": offered_class_total
                == counters.get("offered_requests", 0),
                "terminal_class_partition": terminal_class_total
                == counters.get("terminal_outcomes", 0),
                "ingress_window_partition": counters.get("ingress_within_window", 0)
                + counters.get("ingress_outside_window", 0)
                == counters.get("offered_requests", 0),
                "backend_check_partition": backend_partition == counters.get("backend_checks", 0),
            }
            result = {
                "counters": counters,
                "histograms": histograms,
                "route_latencies_ms": route_latencies,
                "histogram_units": {
                    name: ("milliseconds" if name.endswith("residence_ns") else "microseconds")
                    for name in histograms
                },
                "pending": len(pending),
                "overdue": len(overdue),
                "overdue_legitimate": int(overdue_legitimate),
                "request_timeouts": request_timeouts,
                "event_errors": counters.get("event_errors", 0),
                "legitimate_timeout_rate": (
                    legitimate_timeouts / legitimate_offered if legitimate_offered else None
                ),
                "conservation": {
                    "valid": all(checks.values()),
                    "checks": checks,
                    "route_total": route_total,
                    "backend_partition_total": backend_partition,
                },
                "padding": padding,
            }
            if self.negative_cache is not None:
                cache = self.negative_cache.metrics_snapshot()
                result["cache_entries"] = cache["entries"]
                result["cache_capacity"] = cache["capacity"]
                result["cache_peak_entries_per_account"] = cache["peak_entries_per_account"]
            else:
                result["cache_entries"] = 0
                result["cache_capacity"] = 0
                result["cache_peak_entries_per_account"] = 0
            result["singleflight"] = (
                self.singleflight.snapshot() if self.singleflight is not None else {}
            )
            return result

    def queue_snapshot(self) -> dict[str, int]:
        padding = self._padding.snapshot()
        with self._lock:
            return {
                "frontend_queue_length": self._frontend_queue.qsize(),
                "backend_queue_length": self._backend_queue.qsize(),
                "active_connections": len(self._pending),
                "active_frontend_workers": self._active_frontend_workers,
                "active_backend_workers": self._active_backend_workers,
                "pending_padding_timers": padding["pending"],
            }

    def wait_phase(self, phase: str, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            with self._lock:
                if not any(context.phase == phase for context in self._pending.values()):
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.002, max(0.0, deadline - time.monotonic())))

    def _wait_idle_until(self, deadline: float) -> bool:
        while True:
            snapshot = self.queue_snapshot()
            if all(value == 0 for value in snapshot.values()):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(0.002, max(0.0, deadline - time.monotonic())))

    def wait_idle(self, timeout: float) -> bool:
        return self._wait_idle_until(time.monotonic() + max(0.0, timeout))

    def _cancel_frontend_queue(self) -> None:
        while True:
            try:
                item = self._frontend_queue.get_nowait()
            except queue.Empty:
                return
            try:
                if isinstance(item, _RequestContext):
                    self._record_completion(
                        item,
                        ServiceRoute.SHUTDOWN_CANCELLED,
                        False,
                        response_emitted=False,
                    )
            finally:
                self._frontend_queue.task_done()

    def _cancel_backend_queue(self) -> None:
        while True:
            try:
                item = self._backend_queue.get_nowait()
            except queue.Empty:
                return
            try:
                if isinstance(item, _BackendJob):
                    waiters = self._finish_flight(item.context)
                    self._record_completion(
                        item.context,
                        ServiceRoute.SHUTDOWN_CANCELLED,
                        False,
                        response_emitted=False,
                    )
                    for waiter in waiters:
                        self._record_completion(
                            waiter,
                            ServiceRoute.SHUTDOWN_CANCELLED,
                            False,
                            response_emitted=False,
                        )
            finally:
                self._backend_queue.task_done()

    @staticmethod
    def _enqueue_stops(target: queue.Queue[object], count: int, deadline: float) -> bool:
        for _ in range(count):
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                try:
                    target.put(AuthenticationService._STOP, timeout=min(0.01, remaining))
                    break
                except queue.Full:
                    continue
        return True

    @staticmethod
    def _join_threads(threads: list[Thread], deadline: float) -> bool:
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))
        return all(not thread.is_alive() for thread in threads)

    def _cancel_remaining_pending(self) -> None:
        with self._lock:
            pending = list(self._pending.values())
        for context in pending:
            self._record_completion(
                context,
                ServiceRoute.SHUTDOWN_CANCELLED,
                False,
                response_emitted=False,
            )

    def shutdown(self, timeout: float = 10.0) -> ShutdownReport:
        if timeout <= 0:
            raise ValueError("shutdown timeout must be positive")
        with self._lock:
            if self._shutdown_report is not None:
                return self._shutdown_report
            self._accepting = False
        started = time.monotonic()
        deadline = started + timeout
        reserve = min(0.25, max(0.02, timeout * 0.20))
        drained = self._wait_idle_until(max(started, deadline - reserve))

        if not drained:
            self._padding.cancel_pending()
            self._cancel_frontend_queue()
        frontend_signalled = self._enqueue_stops(
            self._frontend_queue, self.limits.frontend_workers, deadline
        )
        frontend_stopped = frontend_signalled and self._join_threads(
            self._frontend_threads, deadline
        )

        if not drained or not frontend_stopped:
            self._cancel_backend_queue()
        backend_signalled = self._enqueue_stops(
            self._backend_queue, self.limits.backend_workers, deadline
        )
        backend_stopped = backend_signalled and self._join_threads(self._backend_threads, deadline)

        if not drained:
            self._padding.cancel_pending()
        padding_stopped = self._padding.shutdown(
            drain=drained,
            timeout=max(0.0, deadline - time.monotonic()),
        )
        if not drained or not frontend_stopped or not backend_stopped:
            if self.singleflight is not None:
                for waiter in self.singleflight.cancel_all():
                    self._record_completion(
                        waiter,
                        ServiceRoute.SHUTDOWN_CANCELLED,
                        False,
                        response_emitted=False,
                    )
            self._cancel_remaining_pending()
        with self._lock:
            pending_after = len(self._pending)
        clean = (
            drained
            and frontend_stopped
            and backend_stopped
            and padding_stopped
            and pending_after == 0
        )
        report = ShutdownReport(
            clean=clean,
            drained_before_deadline=drained,
            frontend_workers_stopped=frontend_stopped,
            backend_workers_stopped=backend_stopped,
            padding_stopped=padding_stopped,
            pending_after_shutdown=pending_after,
            elapsed_seconds=time.monotonic() - started,
        )
        with self._lock:
            self._shutdown_report = report
        return report
