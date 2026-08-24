from __future__ import annotations

import heapq
import time
from collections.abc import Callable
from threading import Condition, Thread


class PaddingScheduler:
    """One bounded timer thread for asynchronous failure completion."""

    def __init__(self, max_pending: int) -> None:
        if max_pending < 1:
            raise ValueError("max_pending must be positive")
        self.max_pending = max_pending
        self._condition = Condition()
        self._heap: list[tuple[int, int, Callable[[], None]]] = []
        self._sequence = 0
        self._stopping = False
        self._peak_pending = 0
        self._thread = Thread(target=self._run, name="service-padding", daemon=True)
        self._thread.start()

    def schedule(self, due_ns: int, callback: Callable[[], None]) -> bool:
        with self._condition:
            if self._stopping or len(self._heap) >= self.max_pending:
                return False
            self._sequence += 1
            heapq.heappush(self._heap, (due_ns, self._sequence, callback))
            self._peak_pending = max(self._peak_pending, len(self._heap))
            self._condition.notify()
            return True

    def _run(self) -> None:
        while True:
            with self._condition:
                while not self._heap and not self._stopping:
                    self._condition.wait()
                if self._stopping and not self._heap:
                    return
                due_ns, _, callback = self._heap[0]
                remaining = (due_ns - time.perf_counter_ns()) / 1_000_000_000
                if remaining > 0:
                    self._condition.wait(remaining)
                    continue
                heapq.heappop(self._heap)
            try:
                callback()
            except Exception:
                # Request accounting owns callback failures; the scheduler must survive.
                continue

    def snapshot(self) -> dict[str, int]:
        with self._condition:
            return {
                "pending": len(self._heap),
                "peak_pending": self._peak_pending,
                "capacity": self.max_pending,
            }

    def cancel_pending(self) -> int:
        """Cancel queued callbacks without waiting for their due times."""

        with self._condition:
            cancelled = len(self._heap)
            self._heap.clear()
            self._condition.notify_all()
            return cancelled

    def shutdown(self, drain: bool = True, timeout: float = 5.0) -> bool:
        deadline = time.monotonic() + timeout
        if drain:
            while time.monotonic() < deadline:
                with self._condition:
                    if not self._heap:
                        break
                time.sleep(0.002)
        with self._condition:
            if not drain:
                self._heap.clear()
            self._stopping = True
            self._condition.notify_all()
        self._thread.join(max(0.0, deadline - time.monotonic()))
        return not self._thread.is_alive()
