from __future__ import annotations

from dataplane.negative_cache import NegativeKey
from service.singleflight import AsyncSingleflight


def _key(index: int) -> NegativeKey:
    return NegativeKey(1, index.to_bytes(32, "big"))


def test_waiter_peaks_track_global_and_per_key_caps_independently() -> None:
    singleflight = AsyncSingleflight[int](max_waiters_per_key=2, max_waiters_global=3)
    first, second = _key(1), _key(2)

    assert singleflight.snapshot() == {
        "peak_waiters": 0,
        "peak_waiters_per_key": 0,
        "inflight": 0,
        "current_waiters": 0,
    }
    assert singleflight.join_or_lead(first, 0) == "leader"
    assert singleflight.join_or_lead(first, 1) == "joined"
    assert singleflight.join_or_lead(first, 2) == "joined"
    assert singleflight.join_or_lead(second, 3) == "leader"
    assert singleflight.join_or_lead(second, 4) == "joined"
    assert singleflight.join_or_lead(second, 5) == "rejected"

    at_global_cap = singleflight.snapshot()
    assert at_global_cap["peak_waiters"] == 3
    assert at_global_cap["peak_waiters_per_key"] == 2
    assert at_global_cap["global_rejected"] == 1

    assert singleflight.finish(first) == [1, 2]
    assert singleflight.join_or_lead(second, 6) == "joined"
    assert singleflight.join_or_lead(second, 7) == "rejected"
    assert singleflight.finish(second) == [4, 6]

    final = singleflight.snapshot()
    assert final["peak_waiters"] == 3
    assert final["peak_waiters_per_key"] == 2
    assert final["per_key_rejected"] == 1
    assert final["current_waiters"] == 0
    assert final["inflight"] == 0
