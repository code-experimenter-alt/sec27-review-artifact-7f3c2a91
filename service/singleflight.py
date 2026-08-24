from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from threading import RLock
from typing import Generic, TypeVar

from dataplane.negative_cache import NegativeKey

T = TypeVar("T")


@dataclass
class _Flight(Generic[T]):
    waiters: list[T] = field(default_factory=list)


class AsyncSingleflight(Generic[T]):
    """Non-blocking exact-key coalescing for a separately queued backend."""

    def __init__(self, max_waiters_per_key: int, max_waiters_global: int) -> None:
        if max_waiters_per_key < 0 or max_waiters_global < 0:
            raise ValueError("waiter caps must be non-negative")
        self.max_waiters_per_key = max_waiters_per_key
        self.max_waiters_global = max_waiters_global
        self._lock = RLock()
        self._flights: dict[NegativeKey, _Flight[T]] = {}
        self._waiters = 0
        self._metrics: Counter[str] = Counter()

    def join_or_lead(self, key: NegativeKey, request: T) -> str:
        with self._lock:
            flight = self._flights.get(key)
            if flight is None:
                self._flights[key] = _Flight()
                self._metrics["leaders"] += 1
                return "leader"
            if len(flight.waiters) >= self.max_waiters_per_key:
                self._metrics["per_key_rejected"] += 1
                return "rejected"
            if self._waiters >= self.max_waiters_global:
                self._metrics["global_rejected"] += 1
                return "rejected"
            flight.waiters.append(request)
            self._waiters += 1
            self._metrics["joined"] += 1
            self._metrics["peak_waiters_per_key"] = max(
                self._metrics["peak_waiters_per_key"], len(flight.waiters)
            )
            self._metrics["peak_waiters"] = max(self._metrics["peak_waiters"], self._waiters)
            return "joined"

    def finish(self, key: NegativeKey) -> list[T]:
        with self._lock:
            flight = self._flights.pop(key, None)
            if flight is None:
                return []
            self._waiters -= len(flight.waiters)
            return flight.waiters

    def cancel_all(self) -> list[T]:
        """Remove all flights and return their queued waiters."""

        with self._lock:
            waiters = [item for flight in self._flights.values() for item in flight.waiters]
            self._flights.clear()
            self._waiters = 0
            self._metrics["cancelled_waiters"] += len(waiters)
            return waiters

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            result = dict(self._metrics)
            result["peak_waiters"] = self._metrics["peak_waiters"]
            result["peak_waiters_per_key"] = self._metrics["peak_waiters_per_key"]
            result["inflight"] = len(self._flights)
            result["current_waiters"] = self._waiters
            return result
