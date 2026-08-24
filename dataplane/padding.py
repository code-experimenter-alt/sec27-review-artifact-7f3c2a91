from __future__ import annotations

import time
from collections import Counter
from concurrent.futures import Future
from threading import RLock, Timer
from typing import Generic, Optional, TypeVar

T = TypeVar("T")


class AsyncResponsePadder(Generic[T]):
    """Complete response futures after a bounded minimum response duration.

    Timer-backed completion keeps request workers free during the padding
    interval.  `max_pending` bounds timer/future memory.  At capacity, the
    caller applies the remaining bounded delay synchronously; timing is not
    silently dropped under pressure.
    """

    def __init__(
        self,
        minimum_seconds: float,
        maximum_seconds: float,
        max_pending: int = 4096,
    ) -> None:
        if minimum_seconds < 0 or maximum_seconds < minimum_seconds:
            raise ValueError("padding bounds are invalid")
        if max_pending < 1:
            raise ValueError("max_pending must be positive")
        self.minimum_seconds = minimum_seconds
        self.maximum_seconds = maximum_seconds
        self.max_pending = max_pending
        self._lock = RLock()
        self._pending: set[Timer] = set()
        self._metrics: Counter[str] = Counter()

    def defer(
        self,
        value: T,
        started_at: Optional[float] = None,
        minimum_seconds: Optional[float] = None,
    ) -> Future[T]:
        """Defer completion using a ``time.perf_counter()`` start timestamp."""

        start = time.perf_counter() if started_at is None else started_at
        minimum = self.minimum_seconds if minimum_seconds is None else minimum_seconds
        if minimum < 0:
            raise ValueError("minimum padding must be non-negative")
        target = min(minimum, self.maximum_seconds)
        delay = max(0.0, target - (time.perf_counter() - start))
        future: Future[T] = Future()
        if delay == 0:
            future.set_result(value)
            with self._lock:
                self._metrics["immediate"] += 1
            return future

        timer: Timer

        def complete() -> None:
            try:
                future.set_result(value)
            finally:
                with self._lock:
                    self._pending.discard(timer)
                    self._metrics["completed_async"] += 1

        timer = Timer(delay, complete)
        timer.daemon = True
        with self._lock:
            if len(self._pending) >= self.max_pending:
                self._metrics["overflow_sync_fallback"] += 1
                synchronous_fallback = True
            else:
                synchronous_fallback = False
                self._pending.add(timer)
                self._metrics["scheduled_async"] += 1
                self._metrics["peak_pending"] = max(
                    self._metrics["peak_pending"], len(self._pending)
                )
        if synchronous_fallback:
            time.sleep(delay)
            future.set_result(value)
            return future
        timer.start()
        return future

    def metrics_snapshot(self) -> dict[str, int]:
        with self._lock:
            result = dict(self._metrics)
            result["pending"] = len(self._pending)
            result["max_pending"] = self.max_pending
            return result
