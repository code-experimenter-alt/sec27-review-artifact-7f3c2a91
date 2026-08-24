from __future__ import annotations

import math
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event, Thread
from typing import Any

try:
    import psutil
except ImportError:  # pragma: no cover - dependency is declared by the repository.
    psutil = None  # type: ignore[assignment]


class FixedHistogram:
    """Fixed-memory logarithmic latency histogram with roughly 1% buckets."""

    def __init__(self, growth: float = 1.01, max_value_ns: int = 120_000_000_000) -> None:
        if growth <= 1 or max_value_ns < 1:
            raise ValueError("invalid histogram geometry")
        self.growth = growth
        self.max_value_ns = max_value_ns
        self._log_growth = math.log(growth)
        self._max_index = math.ceil(math.log(max_value_ns) / self._log_growth)
        self._counts: Counter[int] = Counter()
        self.count = 0
        self.maximum_ns = 0

    def add(self, value_ns: int) -> None:
        value = max(0, int(value_ns))
        index = (
            0 if value <= 1 else min(self._max_index, math.ceil(math.log(value) / self._log_growth))
        )
        self._counts[index] += 1
        self.count += 1
        self.maximum_ns = max(self.maximum_ns, value)

    def percentile_ns(self, quantile: float) -> float | None:
        if not 0 <= quantile <= 1:
            raise ValueError("quantile must be in [0, 1]")
        if self.count == 0:
            return None
        target = quantile * (self.count - 1)
        cumulative = 0
        for index in sorted(self._counts):
            cumulative += self._counts[index]
            if target < cumulative:
                return min(float(self.max_value_ns), self.growth**index)
        raise AssertionError("histogram percentile is unreachable")

    def summary(self, divisor: float = 1.0) -> dict[str, float | None]:
        return {
            "p50": self._scaled(0.50, divisor),
            "p95": self._scaled(0.95, divisor),
            "p99": self._scaled(0.99, divisor),
            "max": self.maximum_ns / divisor if self.count else None,
            "count": self.count,
        }

    def _scaled(self, quantile: float, divisor: float) -> float | None:
        value = self.percentile_ns(quantile)
        return None if value is None else value / divisor


@dataclass(frozen=True)
class ResourceReport:
    resource_payload_schema_version: int
    available: bool
    metrics_complete: bool
    sample_count: int
    queue_sample_count: int
    process_cpu_user_seconds: float | None
    process_cpu_system_seconds: float | None
    process_cpu_utilization_cores: float | None
    process_rss_min_bytes: int | None
    process_rss_peak_bytes: int | None
    process_vms_peak_bytes: int | None
    process_uss_peak_bytes: int | None
    queue_mean: dict[str, float]
    queue_peak: dict[str, int]
    expected_queue_metrics: tuple[str, ...]
    missing_queue_metrics: tuple[str, ...]
    rss_window_minimum_sample_count: int
    rss_window_fraction_numerator: int
    rss_window_fraction_denominator: int
    rss_window_k_samples: int
    rss_first_window_sum_bytes: int
    rss_first_window_sample_count: int
    rss_first_window_mean_bytes: float | None
    rss_last_window_sum_bytes: int
    rss_last_window_sample_count: int
    rss_last_window_mean_bytes: float | None
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result = dict(vars(self))
        result.update(
            {
                "sampled_process_rss_min_bytes": self.process_rss_min_bytes,
                "sampled_process_rss_max_bytes": self.process_rss_peak_bytes,
                "sampled_process_vms_max_bytes": self.process_vms_peak_bytes,
                "sampled_process_uss_max_bytes": self.process_uss_peak_bytes,
                "sampled_queue_mean": self.queue_mean,
                "sampled_queue_max": self.queue_peak,
                "extrema_semantics": "sampled_not_continuous",
            }
        )
        return result


class ResourceSampler:
    """Samples real process memory/CPU and service state during measurement."""

    RESOURCE_PAYLOAD_SCHEMA_VERSION = 2
    RSS_WINDOW_MINIMUM_SAMPLE_COUNT = 100
    RSS_WINDOW_FRACTION_NUMERATOR = 1
    RSS_WINDOW_FRACTION_DENOMINATOR = 10

    DEFAULT_QUEUE_METRICS = (
        "frontend_queue_length",
        "backend_queue_length",
        "active_connections",
        "active_frontend_workers",
        "active_backend_workers",
        "pending_padding_timers",
    )

    def __init__(
        self,
        interval_seconds: float,
        queue_snapshot: Callable[[], dict[str, int]],
        expected_queue_metrics: tuple[str, ...] = DEFAULT_QUEUE_METRICS,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("resource sample interval must be positive")
        self.interval_seconds = interval_seconds
        self.queue_snapshot = queue_snapshot
        if not expected_queue_metrics:
            raise ValueError("expected_queue_metrics must be non-empty")
        self.expected_queue_metrics = tuple(expected_queue_metrics)
        self._stop = Event()
        self._thread: Thread | None = None
        self._samples: list[dict[str, int]] = []
        self._queue_sums: Counter[str] = Counter()
        self._queue_peaks: Counter[str] = Counter()
        self._queue_sample_count = 0
        self._missing_queue_metrics: set[str] = set()
        self._errors: list[str] = []
        self._started_at = 0.0
        self._cpu_start: Any = None

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("resource sampler is single-use")
        self._started_at = time.monotonic()
        if psutil is None:
            self._record_error("psutil is unavailable")
            return
        try:
            process = psutil.Process()
            self._cpu_start = process.cpu_times()
            self._sample_once(process)
        except Exception as exc:  # pragma: no cover - platform-specific failure.
            self._record_error(f"{type(exc).__name__}: {exc}")
            return
        self._thread = Thread(target=self._run, name="service-resource-sampler", daemon=True)
        self._thread.start()

    def _record_error(self, detail: str) -> None:
        if detail not in self._errors:
            self._errors.append(detail)

    def _run(self) -> None:
        assert psutil is not None
        try:
            process = psutil.Process()
        except Exception as exc:  # pragma: no cover - platform-specific failure.
            self._record_error(f"{type(exc).__name__}: {exc}")
            return
        while not self._stop.wait(self.interval_seconds):
            self._sample_once(process)

    def _sample_once(self, process: Any) -> None:
        try:
            memory = process.memory_full_info()
            sample = {
                "rss": int(memory.rss),
                "vms": int(memory.vms),
                "uss": int(getattr(memory, "uss", 0)),
            }
            self._samples.append(sample)
            queues = self.queue_snapshot()
            missing = set(self.expected_queue_metrics) - set(queues)
            if missing:
                self._missing_queue_metrics.update(missing)
                raise KeyError(f"missing queue metrics: {', '.join(sorted(missing))}")
            for name in self.expected_queue_metrics:
                value = queues[name]
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValueError(f"invalid queue metric {name}: {value!r}")
                self._queue_sums[name] += int(value)
                self._queue_peaks[name] = max(self._queue_peaks[name], int(value))
            self._queue_sample_count += 1
        except Exception as exc:  # pragma: no cover - platform-specific psutil failure.
            self._record_error(f"{type(exc).__name__}: {exc}")

    def _rss_window_statistics(self) -> dict[str, int | float | None]:
        sample_count = len(self._samples)
        if sample_count < self.RSS_WINDOW_MINIMUM_SAMPLE_COUNT:
            window_size = 0
        else:
            window_size = max(
                1,
                (sample_count * self.RSS_WINDOW_FRACTION_NUMERATOR)
                // self.RSS_WINDOW_FRACTION_DENOMINATOR,
            )
        first_sum = sum(sample["rss"] for sample in self._samples[:window_size])
        last_sum = (
            sum(sample["rss"] for sample in self._samples[-window_size:]) if window_size else 0
        )
        return {
            "rss_window_minimum_sample_count": self.RSS_WINDOW_MINIMUM_SAMPLE_COUNT,
            "rss_window_fraction_numerator": self.RSS_WINDOW_FRACTION_NUMERATOR,
            "rss_window_fraction_denominator": self.RSS_WINDOW_FRACTION_DENOMINATOR,
            "rss_window_k_samples": window_size,
            "rss_first_window_sum_bytes": first_sum,
            "rss_first_window_sample_count": window_size,
            "rss_first_window_mean_bytes": (first_sum / window_size if window_size else None),
            "rss_last_window_sum_bytes": last_sum,
            "rss_last_window_sample_count": window_size,
            "rss_last_window_mean_bytes": (last_sum / window_size if window_size else None),
        }

    def stop(self) -> ResourceReport:
        elapsed = max(0.0, time.monotonic() - self._started_at)
        if psutil is None:
            return ResourceReport(
                resource_payload_schema_version=self.RESOURCE_PAYLOAD_SCHEMA_VERSION,
                available=False,
                metrics_complete=False,
                sample_count=0,
                queue_sample_count=0,
                process_cpu_user_seconds=None,
                process_cpu_system_seconds=None,
                process_cpu_utilization_cores=None,
                process_rss_min_bytes=None,
                process_rss_peak_bytes=None,
                process_vms_peak_bytes=None,
                process_uss_peak_bytes=None,
                queue_mean={},
                queue_peak={},
                expected_queue_metrics=self.expected_queue_metrics,
                missing_queue_metrics=self.expected_queue_metrics,
                **self._rss_window_statistics(),
                error="; ".join(self._errors) or "psutil is unavailable",
            )
        self._stop.set()
        if self._thread is not None:
            self._thread.join(max(1.0, self.interval_seconds * 3))
            if self._thread.is_alive():
                self._record_error("resource sampler thread did not stop")
        if self._cpu_start is None:
            return ResourceReport(
                resource_payload_schema_version=self.RESOURCE_PAYLOAD_SCHEMA_VERSION,
                available=False,
                metrics_complete=False,
                sample_count=len(self._samples),
                queue_sample_count=self._queue_sample_count,
                process_cpu_user_seconds=None,
                process_cpu_system_seconds=None,
                process_cpu_utilization_cores=None,
                process_rss_min_bytes=None,
                process_rss_peak_bytes=None,
                process_vms_peak_bytes=None,
                process_uss_peak_bytes=None,
                queue_mean={},
                queue_peak={},
                expected_queue_metrics=self.expected_queue_metrics,
                missing_queue_metrics=tuple(sorted(self._missing_queue_metrics)),
                **self._rss_window_statistics(),
                error="; ".join(self._errors) or "sampler did not initialize",
            )
        cpu_end: Any = None
        try:
            process = psutil.Process()
            self._sample_once(process)
            cpu_end = process.cpu_times()
        except Exception as exc:  # pragma: no cover - platform-specific failure.
            self._record_error(f"{type(exc).__name__}: {exc}")
        user = None if cpu_end is None else float(cpu_end.user - self._cpu_start.user)
        system = None if cpu_end is None else float(cpu_end.system - self._cpu_start.system)
        count = len(self._samples)
        missing = tuple(sorted(self._missing_queue_metrics))
        complete = (
            bool(self._samples)
            and not self._errors
            and not missing
            and self._queue_sample_count == count
            and user is not None
            and system is not None
        )
        return ResourceReport(
            resource_payload_schema_version=self.RESOURCE_PAYLOAD_SCHEMA_VERSION,
            available=bool(self._samples),
            metrics_complete=complete,
            sample_count=count,
            queue_sample_count=self._queue_sample_count,
            process_cpu_user_seconds=user,
            process_cpu_system_seconds=system,
            process_cpu_utilization_cores=(
                (user + system) / elapsed
                if elapsed and user is not None and system is not None
                else None
            ),
            process_rss_min_bytes=min((item["rss"] for item in self._samples), default=None),
            process_rss_peak_bytes=max((item["rss"] for item in self._samples), default=None),
            process_vms_peak_bytes=max((item["vms"] for item in self._samples), default=None),
            process_uss_peak_bytes=max((item["uss"] for item in self._samples), default=None),
            queue_mean={
                key: value / self._queue_sample_count
                for key, value in sorted(self._queue_sums.items())
            }
            if self._queue_sample_count
            else {},
            queue_peak=dict(sorted(self._queue_peaks.items())),
            expected_queue_metrics=self.expected_queue_metrics,
            missing_queue_metrics=missing,
            **self._rss_window_statistics(),
            error="; ".join(self._errors) or None,
        )
