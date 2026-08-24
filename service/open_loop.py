from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Protocol, Sequence

from .metrics import FixedHistogram
from .types import AuthRequest


class NonBlockingService(Protocol):
    def submit(
        self,
        request: AuthRequest,
        phase: str,
        scheduled_ns: int,
        window_start_ns: int,
        window_end_ns: int,
    ) -> bool:
        ...


@dataclass(frozen=True)
class ScheduledArrival:
    offset_seconds: float
    request: AuthRequest

    def __post_init__(self) -> None:
        if self.offset_seconds < 0:
            raise ValueError("arrival offset must be non-negative")


@dataclass(frozen=True)
class OpenLoopReport:
    phase: str
    duration_seconds: float
    scheduled: int
    accepted_for_queueing: int
    rejected_at_submission: int
    generator_elapsed_seconds: float
    arrival_lag_us: dict[str, float | None]


class OpenLoopLoadGenerator:
    """Drives a precomputed clock schedule without waiting for responses."""

    def run(
        self,
        service: NonBlockingService,
        arrivals: Sequence[ScheduledArrival],
        duration_seconds: float,
        phase: str,
    ) -> OpenLoopReport:
        if duration_seconds <= 0:
            raise ValueError("duration_seconds must be positive")
        if any(
            arrivals[index].offset_seconds > arrivals[index + 1].offset_seconds
            for index in range(len(arrivals) - 1)
        ):
            raise ValueError("arrivals must be ordered by offset")
        if arrivals and arrivals[-1].offset_seconds >= duration_seconds:
            raise ValueError("arrival offsets must be inside the offered-load window")

        started_ns = time.perf_counter_ns()
        window_end_ns = started_ns + int(duration_seconds * 1_000_000_000)
        lag = FixedHistogram()
        accepted = 0
        for arrival in arrivals:
            target_ns = started_ns + int(arrival.offset_seconds * 1_000_000_000)
            self._wait_until(target_ns)
            submitted_ns = time.perf_counter_ns()
            lag.add(max(0, submitted_ns - target_ns))
            accepted += int(
                service.submit(
                    arrival.request,
                    phase=phase,
                    scheduled_ns=target_ns,
                    window_start_ns=started_ns,
                    window_end_ns=window_end_ns,
                )
            )
        self._wait_until(window_end_ns)
        elapsed = (time.perf_counter_ns() - started_ns) / 1_000_000_000
        return OpenLoopReport(
            phase=phase,
            duration_seconds=duration_seconds,
            scheduled=len(arrivals),
            accepted_for_queueing=accepted,
            rejected_at_submission=len(arrivals) - accepted,
            generator_elapsed_seconds=elapsed,
            arrival_lag_us=lag.summary(divisor=1_000),
        )

    @staticmethod
    def _wait_until(target_ns: int) -> None:
        while True:
            remaining_ns = target_ns - time.perf_counter_ns()
            if remaining_ns <= 0:
                return
            if remaining_ns > 1_000_000:
                time.sleep((remaining_ns - 250_000) / 1_000_000_000)
            else:
                time.sleep(0)
