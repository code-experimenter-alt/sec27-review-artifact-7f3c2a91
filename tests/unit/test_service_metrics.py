from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

import service.metrics as metrics_module
from service.metrics import ResourceSampler


def _complete_queue_snapshot() -> dict[str, int]:
    return {
        "frontend_queue_length": 0,
        "backend_queue_length": 0,
        "active_connections": 0,
        "active_frontend_workers": 0,
        "active_backend_workers": 0,
        "pending_padding_timers": 0,
    }


def _stop_with_rss_samples(
    monkeypatch: pytest.MonkeyPatch,
    rss_samples: list[int],
) -> dict[str, object]:
    final_rss = rss_samples[-1]

    class FakeProcess:
        def memory_full_info(self) -> SimpleNamespace:
            return SimpleNamespace(rss=final_rss, vms=final_rss * 2, uss=final_rss)

        def cpu_times(self) -> SimpleNamespace:
            return SimpleNamespace(user=1.0, system=2.0)

    monkeypatch.setattr(
        metrics_module,
        "psutil",
        SimpleNamespace(Process=lambda: FakeProcess()),
    )
    sampler = ResourceSampler(1, _complete_queue_snapshot)
    sampler._samples = [{"rss": rss, "vms": rss * 2, "uss": rss} for rss in rss_samples[:-1]]
    sampler._cpu_start = SimpleNamespace(user=0.0, system=0.0)
    sampler._started_at = time.monotonic() - 1
    return sampler.stop().as_dict()


def test_resource_sampler_marks_sampled_extrema_and_complete_queue_metrics() -> None:
    sampler = ResourceSampler(0.001, _complete_queue_snapshot)
    sampler.start()
    time.sleep(0.004)
    report = sampler.stop()
    payload = report.as_dict()
    assert report.metrics_complete
    assert report.queue_sample_count == report.sample_count
    assert payload["extrema_semantics"] == "sampled_not_continuous"
    assert payload["sampled_process_rss_max_bytes"] is not None
    assert payload["resource_payload_schema_version"] == 2
    assert payload["rss_window_k_samples"] == 0
    assert payload["rss_first_window_sum_bytes"] == 0
    assert payload["rss_first_window_sample_count"] == 0
    assert payload["rss_first_window_mean_bytes"] is None
    assert payload["rss_last_window_sum_bytes"] == 0
    assert payload["rss_last_window_sample_count"] == 0
    assert payload["rss_last_window_mean_bytes"] is None
    assert set(payload["sampled_queue_max"]) == set(ResourceSampler.DEFAULT_QUEUE_METRICS)


def test_missing_queue_metric_fails_resource_completeness() -> None:
    incomplete = _complete_queue_snapshot()
    del incomplete["backend_queue_length"]
    sampler = ResourceSampler(0.001, lambda: dict(incomplete))
    sampler.start()
    time.sleep(0.003)
    report = sampler.stop()
    assert report.available
    assert not report.metrics_complete
    assert report.queue_sample_count == 0
    assert report.missing_queue_metrics == ("backend_queue_length",)
    assert "missing queue metrics" in (report.error or "")


@pytest.mark.parametrize(
    ("sample_count", "expected_k"),
    [
        (99, 0),
        (100, 10),
        (109, 10),
        (110, 11),
    ],
)
def test_rss_ten_percent_windows_have_frozen_boundaries_and_exact_totals(
    monkeypatch: pytest.MonkeyPatch,
    sample_count: int,
    expected_k: int,
) -> None:
    rss_samples = list(range(1, sample_count + 1))
    payload = _stop_with_rss_samples(monkeypatch, rss_samples)

    assert payload["resource_payload_schema_version"] == 2
    assert payload["rss_window_minimum_sample_count"] == 100
    assert payload["rss_window_fraction_numerator"] == 1
    assert payload["rss_window_fraction_denominator"] == 10
    assert payload["rss_window_k_samples"] == expected_k
    assert payload["rss_first_window_sample_count"] == expected_k
    assert payload["rss_last_window_sample_count"] == expected_k

    first_sum = sum(rss_samples[:expected_k])
    last_sum = sum(rss_samples[-expected_k:]) if expected_k else 0
    assert payload["rss_first_window_sum_bytes"] == first_sum
    assert payload["rss_last_window_sum_bytes"] == last_sum
    if expected_k:
        assert payload["rss_first_window_mean_bytes"] == first_sum / expected_k
        assert payload["rss_last_window_mean_bytes"] == last_sum / expected_k
    else:
        assert payload["rss_first_window_mean_bytes"] is None
        assert payload["rss_last_window_mean_bytes"] is None
