from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field
from threading import Event, RLock
from typing import Callable, Dict, Optional

from .negative_cache import NegativeKey
from .types import TypedBackendResult


@dataclass
class _Flight:
    event: Event = field(default_factory=Event)
    result: Optional[TypedBackendResult] = None
    waiters: int = 0


class Singleflight:
    """Exact-key duplicate coalescing with per-key and global waiter caps."""

    def __init__(
        self,
        max_waiters_per_key: int = 64,
        max_waiters_global: int = 4096,
        waiter_timeout_seconds: float = 30.0,
        overload_padding_seconds: float = 0.0,
    ) -> None:
        if max_waiters_per_key < 0 or max_waiters_global < 0:
            raise ValueError("waiter caps must be non-negative")
        if waiter_timeout_seconds <= 0 or overload_padding_seconds < 0:
            raise ValueError("invalid singleflight timing configuration")
        self.max_waiters_per_key = max_waiters_per_key
        self.max_waiters_global = max_waiters_global
        self.waiter_timeout_seconds = waiter_timeout_seconds
        self.overload_padding_seconds = overload_padding_seconds
        self._lock = RLock()
        self._flights: Dict[NegativeKey, _Flight] = {}
        self._total_waiters = 0
        self._metrics: Counter[str] = Counter()

    def _bounded_failure(
        self,
        expected_version: Optional[int],
        detail: str,
    ) -> TypedBackendResult:
        if self.overload_padding_seconds:
            time.sleep(self.overload_padding_seconds)
        return TypedBackendResult.transient_failure(expected_version, detail)

    def execute(
        self,
        key: NegativeKey,
        verify_fn: Callable[[], TypedBackendResult],
        expected_version: Optional[int] = None,
    ) -> TypedBackendResult:
        overload_detail: Optional[str] = None
        with self._lock:
            flight = self._flights.get(key)
            if flight is None:
                flight = _Flight()
                self._flights[key] = flight
                self._metrics["leaders"] += 1
                leader = True
            else:
                leader = False
                if flight.waiters >= self.max_waiters_per_key:
                    self._metrics["per_key_waiter_cap"] += 1
                    overload_detail = "singleflight per-key waiter cap"
                elif self._total_waiters >= self.max_waiters_global:
                    self._metrics["global_waiter_cap"] += 1
                    overload_detail = "singleflight global waiter cap"
                else:
                    flight.waiters += 1
                    self._total_waiters += 1
                    self._metrics["coalesced_waiters"] += 1
                    self._metrics["peak_waiters"] = max(
                        self._metrics["peak_waiters"], self._total_waiters
                    )

        if overload_detail is not None:
            return self._bounded_failure(expected_version, overload_detail)

        if leader:
            try:
                result = verify_fn()
                if not isinstance(result, TypedBackendResult):
                    raise TypeError("verify_fn must return TypedBackendResult")
            except Exception as exc:  # Safety path: exceptions become fail-open backend errors.
                with self._lock:
                    self._metrics["leader_failures"] += 1
                result = TypedBackendResult.transient_failure(
                    expected_version,
                    f"singleflight verifier exception: {type(exc).__name__}",
                )
            with self._lock:
                flight.result = result
                if self._flights.get(key) is flight:
                    del self._flights[key]
                flight.event.set()
            return result

        completed = flight.event.wait(self.waiter_timeout_seconds)
        with self._lock:
            flight.waiters -= 1
            self._total_waiters -= 1
        if not completed or flight.result is None:
            with self._lock:
                self._metrics["waiter_timeouts"] += 1
            return self._bounded_failure(expected_version, "singleflight waiter timeout")
        return flight.result

    def metrics_snapshot(self) -> dict[str, int]:
        with self._lock:
            result = dict(self._metrics)
            result["inflight"] = len(self._flights)
            result["current_waiters"] = self._total_waiters
            return result
