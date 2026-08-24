from __future__ import annotations

import random
import threading
from collections.abc import Iterable, Iterator
from typing import cast

import pytest

from dataplane.negative_cache import (
    EvictionPolicy,
    LruPolicy,
    NegativeCache,
    NegativeCacheEntry,
    NegativeKey,
    NegativeKeyDeriver,
    TinyLfuPolicy,
)
from dataplane.types import DirectoryStatus, DirectoryView


def _view(account_id: str = "account") -> DirectoryView:
    return DirectoryView(
        username=account_id,
        status=DirectoryStatus.PRESENT,
        account_id=account_id,
        account_generation=1,
        credential_set_version=1,
        salt=b"salt",
        active_authenticator_ids=frozenset({"password"}),
        directory_epoch=1,
    )


def _key(index: int) -> NegativeKey:
    return NegativeKey(1, index.to_bytes(16, "big"))


def test_negative_key_rejects_fields_that_cannot_preserve_heap_order() -> None:
    with pytest.raises(TypeError, match="exact integers"):
        NegativeKey(True, b"a" * 16)
    with pytest.raises(TypeError, match="exact bytes"):
        NegativeKey(1, memoryview(b"a" * 16))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="exact bytes"):
        NegativeKey(1, bytearray(b"a" * 16))  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="exact integer"):
        NegativeKeyDeriver(b"k" * 16, key_id=True)
    deriver = NegativeKeyDeriver(b"k" * 16)
    with pytest.raises(TypeError, match="exact integer"):
        deriver.rotate(b"n" * 16, new_key_id=True)


@pytest.mark.parametrize("capacity", [True, 1.5, float("nan"), float("inf")])
def test_cache_rejects_noninteger_capacity_before_any_mutation(capacity: object) -> None:
    with pytest.raises(TypeError, match="capacity must be an exact integer"):
        NegativeCache(capacity, LruPolicy())  # type: ignore[arg-type]


@pytest.mark.parametrize("quota", [True, 1.5, float("nan"), float("inf")])
@pytest.mark.parametrize("quota_name", ["account", "region"])
def test_cache_rejects_noninteger_scope_quotas(
    quota: object,
    quota_name: str,
) -> None:
    kwargs = {
        "max_entries_per_account": quota if quota_name == "account" else None,
        "max_entries_per_region": quota if quota_name == "region" else None,
    }
    with pytest.raises(TypeError, match="cache quotas must be exact integers"):
        NegativeCache(2, LruPolicy(), **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("reset_after", [True, 16.0, float("nan"), float("inf")])
def test_tinylfu_rejects_noninteger_reset_interval(reset_after: object) -> None:
    with pytest.raises(TypeError, match="reset_after must be an exact integer"):
        TinyLfuPolicy(reset_after=reset_after)  # type: ignore[arg-type]


def test_cache_rejects_nonexact_keys_before_policy_or_storage_mutation() -> None:
    cache = NegativeCache(2, LruPolicy(), max_ttl_seconds=10)
    view = _view()
    valid = _key(1)
    assert cache.insert(valid, view, 0, 10, now=0)
    snapshot_before = cache.resident_snapshot(now=0)
    metrics_before = cache.metrics_snapshot()

    with pytest.raises(TypeError, match="exact NegativeKey"):
        cache.insert_with_result("not-a-key", view, 0, 10, now=0)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="exact NegativeKey"):
        cache.lookup("not-a-key", view, now=0)  # type: ignore[arg-type]

    snapshot_after = cache.resident_snapshot(now=0)
    assert dict(snapshot_after.residents) == dict(snapshot_before.residents)
    assert snapshot_after.eviction_order == snapshot_before.eviction_order == (valid,)
    assert cache.metrics_snapshot() == metrics_before


class _ScriptedPolicy(EvictionPolicy):
    def __init__(self, choices: Iterable[NegativeKey | None]) -> None:
        self._choices = list(choices)
        self.calls: list[tuple[NegativeKey, tuple[NegativeKey, ...]]] = []

    def observe(self, key: NegativeKey) -> None:
        return None

    def on_hit(self, key: NegativeKey) -> None:
        return None

    def on_insert(self, key: NegativeKey) -> None:
        return None

    def on_remove(self, key: NegativeKey) -> None:
        return None

    def choose_victim(
        self,
        candidate: NegativeKey,
        eligible_victims: Iterable[NegativeKey],
    ) -> NegativeKey | None:
        self.calls.append((candidate, tuple(eligible_victims)))
        return self._choices.pop(0)


def test_resident_snapshot_is_frozen_and_distinguishes_physical_from_live() -> None:
    view = _view()
    first, second, later = _key(1), _key(2), _key(3)
    policy = LruPolicy()
    cache = NegativeCache(3, policy, max_ttl_seconds=10)
    assert cache.insert(first, view, 0, 2, now=0)
    assert cache.insert(second, view, 0, 10, now=0)
    assert cache.lookup(first, view, now=1).hit
    metrics_before = cache.metrics_snapshot()

    snapshot = cache.resident_snapshot(now=2)

    assert snapshot.eviction_order == (second, first)
    assert tuple(snapshot.residents) == snapshot.eviction_order
    expired_resident = snapshot.resident_entry(first)
    assert expired_resident is not None
    assert snapshot.lookup(first, view, now=1.999).hit
    for _ in range(2):
        expired = snapshot.lookup(first, view)
        assert not expired.hit
        assert expired.reason == "expired"
        assert expired.expired_entry is expired_resident
    assert snapshot.lookup(second, view).hit
    assert len(snapshot) == len(cache) == 2
    assert cache.metrics_snapshot() == metrics_before
    assert policy.order_snapshot() == (second, first)

    live_lookup = cache.lookup(first, view, now=2)
    assert not live_lookup.hit
    assert live_lookup.expired_entry is expired_resident
    assert cache.insert(later, view, 0, 10, now=2)

    assert first in snapshot
    assert later not in snapshot
    assert tuple(snapshot.residents) == (second, first)
    with pytest.raises(TypeError):
        cast(dict[NegativeKey, NegativeCacheEntry], snapshot.residents)[later] = snapshot.residents[
            second
        ]


def test_nonfinite_times_are_rejected_before_they_can_corrupt_expiry_order() -> None:
    view = _view()
    with pytest.raises(ValueError, match="finite and positive"):
        NegativeCache(4, LruPolicy(), max_ttl_seconds=float("nan"))
    with pytest.raises(ValueError, match="finite and positive"):
        NegativeCache(4, LruPolicy(), max_ttl_seconds=float("inf"))

    cache = NegativeCache(4, LruPolicy(), max_ttl_seconds=10)
    with pytest.raises(ValueError, match="finite and positive"):
        cache.insert_with_result(_key(10), view, 0, float("nan"), now=0)
    with pytest.raises(ValueError, match="finite and positive"):
        cache.insert_with_result(_key(10), view, 0, float("inf"), now=0)
    with pytest.raises(ValueError, match="now must be finite"):
        cache.insert_with_result(_key(10), view, 0, 1, now=float("nan"))
    assert len(cache) == 0

    huge = NegativeCache(2, LruPolicy(), max_ttl_seconds=1e308)
    with pytest.raises(ValueError, match="expiry must be finite"):
        huge.insert_with_result(_key(10), view, 0, 1e308, now=1e308)
    with pytest.raises(ValueError, match="expiry must be finite"):
        huge.insert_with_result(_key(10), view, 0, 1, now=1e308)
    assert len(huge) == 0

    assert cache.insert(_key(11), view, 0, 1, now=0)
    assert cache.insert(_key(12), view, 0, 2, now=0)
    result = cache.insert_with_result(_key(13), view, 0, 10, now=3)
    assert tuple(entry.key for entry in result.expired_entries) == (_key(11), _key(12))

    snapshot = cache.resident_snapshot(now=3)
    with pytest.raises(ValueError, match="now must be finite"):
        cache.lookup(_key(13), view, now=float("nan"))
    with pytest.raises(ValueError, match="now must be finite"):
        cache.resident_snapshot(now=float("inf"))
    with pytest.raises(ValueError, match="now must be finite"):
        snapshot.lookup(_key(13), view, now=float("nan"))


def test_resident_snapshot_copy_is_atomic_with_concurrent_insert() -> None:
    class PausingEntries(dict[NegativeKey, NegativeCacheEntry]):
        def __init__(self, entries: dict[NegativeKey, NegativeCacheEntry]) -> None:
            super().__init__(entries)
            self.armed = False
            self.copy_started = threading.Event()
            self.release_copy = threading.Event()

        def __getitem__(self, key: NegativeKey) -> NegativeCacheEntry:
            entry = super().__getitem__(key)
            if self.armed and not self.copy_started.is_set():
                self.copy_started.set()
                if not self.release_copy.wait(2):
                    raise RuntimeError("snapshot copy was not released")
            return entry

    first, second, later = _key(4), _key(5), _key(6)
    cache = NegativeCache(3, LruPolicy(), max_ttl_seconds=10)
    assert cache.insert(first, _view(), 0, 10, now=0)
    assert cache.insert(second, _view(), 0, 10, now=0)
    entries = PausingEntries(dict(cache._entries))
    cache._entries = entries
    entries.armed = True
    snapshots = []
    snapshot_errors = []

    def take_snapshot() -> None:
        try:
            snapshots.append(cache.resident_snapshot(now=0))
        except Exception as error:  # pragma: no cover - assertion reports the captured error
            snapshot_errors.append(error)

    snapshot_thread = threading.Thread(target=take_snapshot)
    snapshot_thread.start()
    assert entries.copy_started.wait(1)
    snapshot_lock_was_available = cache._lock.acquire(blocking=False)
    if snapshot_lock_was_available:
        cache._lock.release()

    insert_thread = threading.Thread(target=lambda: cache.insert(later, _view(), 0, 10, now=0))
    insert_thread.start()
    entries.release_copy.set()
    snapshot_thread.join(2)
    insert_thread.join(2)

    assert not snapshot_thread.is_alive()
    assert not insert_thread.is_alive()
    assert not snapshot_lock_was_available
    assert snapshot_errors == []
    assert len(snapshots) == 1
    assert tuple(snapshots[0].residents) == (first, second)
    assert later not in snapshots[0]
    assert later in cache.resident_snapshot(now=0)


def test_insert_result_reports_expiry_eviction_precedence_and_ttl_clamp() -> None:
    account_a = _view("a")
    account_b = _view("b")
    account_c = _view("c")
    account_d = _view("d")
    keys = [_key(index) for index in range(10, 20)]
    cache = NegativeCache(
        4,
        LruPolicy(),
        max_ttl_seconds=5,
        max_entries_per_account=2,
        max_entries_per_region=2,
    )
    assert cache.insert(keys[0], account_a, 0, 5, now=0)
    assert cache.insert(keys[1], account_a, 1, 5, now=0)
    assert cache.lookup(keys[0], account_a, now=1).hit

    account_pressure = cache.insert_with_result(keys[2], account_a, 1, 50, now=1)
    assert account_pressure.accepted and account_pressure.inserted
    assert len(account_pressure.evicted_entries) == 1
    assert account_pressure.evicted_entries[0].key == keys[1]
    assert account_pressure.eviction_reasons == ("account_quota",)
    assert account_pressure.ttl_clamped

    assert cache.insert(keys[3], account_b, 0, 5, now=1)
    region_pressure = cache.insert_with_result(keys[4], account_b, 0, 5, now=1)
    assert region_pressure.evicted_entries[0].key == keys[0]
    assert region_pressure.eviction_reasons == ("region_quota",)

    assert cache.insert(keys[5], account_c, 2, 5, now=1)
    capacity_pressure = cache.insert_with_result(keys[6], account_d, 3, 5, now=1)
    assert capacity_pressure.evicted_entries[0].key == keys[2]
    assert capacity_pressure.eviction_reasons == ("capacity",)

    expiring = NegativeCache(2, LruPolicy(), max_ttl_seconds=10)
    original = expiring.insert_with_result(keys[7], account_a, 0, 1, now=0)
    after_expiry = expiring.insert_with_result(keys[8], account_b, 1, 10, now=1)
    assert original.entry is not None
    assert after_expiry.expired_entries == (original.entry,)
    assert after_expiry.evictions == ()


def test_update_reindexes_region_and_replaces_expiration_incrementally() -> None:
    account_a = _view("a")
    account_b = _view("b")
    account_c = _view("c")
    first, second, third = _key(30), _key(31), _key(32)
    cache = NegativeCache(
        4,
        LruPolicy(),
        max_ttl_seconds=10,
        max_entries_per_region=1,
    )
    assert cache.insert(first, account_a, 0, 1, now=0)

    update = cache.insert_with_result(first, account_a, 1, 4, now=0.5)
    assert update.accepted and update.updated
    assert not update.inserted
    assert update.entry is not None
    assert update.entry.expires_at == 4.5

    old_region = cache.insert_with_result(second, account_b, 0, 4, now=1)
    assert old_region.accepted
    assert old_region.expired_entries == ()
    assert old_region.evictions == ()

    new_region = cache.insert_with_result(third, account_c, 1, 4, now=1)
    assert new_region.evicted_entries[0].key == first
    assert new_region.eviction_reasons == ("region_quota",)


def test_region_changing_update_evicts_from_a_full_target_region() -> None:
    moving, target_resident = _key(33), _key(34)
    cache = NegativeCache(
        3,
        LruPolicy(),
        max_ttl_seconds=5,
        max_entries_per_region=1,
    )
    assert cache.insert(moving, _view("a"), 0, 5, now=0)
    assert cache.insert(target_resident, _view("b"), 1, 5, now=0)

    result = cache.insert_with_result(moving, _view("a"), 1, 10, now=1)

    assert result.accepted and result.updated
    assert result.entry is not None and result.entry.region == 1
    assert result.ttl_clamped
    assert result.evicted_entries[0].key == target_resident
    assert result.eviction_reasons == ("region_quota",)
    assert tuple(cache.resident_snapshot(now=1).residents) == (moving,)
    metrics = cache.metrics_snapshot()
    assert metrics["region_quota_pressure"] == 1
    assert metrics["evictions"] == 1
    assert metrics["updates"] == 1


def test_region_changing_update_rejection_preserves_original_state() -> None:
    moving, target_resident = _key(37), _key(38)
    policy = _ScriptedPolicy([None])
    cache = NegativeCache(
        3,
        policy,
        max_ttl_seconds=5,
        max_entries_per_region=1,
    )
    assert cache.insert(moving, _view("a"), 0, 5, now=0)
    assert cache.insert(target_resident, _view("b"), 1, 5, now=0)
    original = cache.resident_snapshot(now=1)
    original_heap = tuple(cache._expiration_heap)
    original_positions = dict(cache._expiration_positions)

    result = cache.insert_with_result(moving, _view("a"), 1, 10, now=1)

    assert not result.accepted
    assert result.reason == "admission rejected"
    assert not result.updated
    assert result.entry is None
    assert result.evictions == ()
    current = cache.resident_snapshot(now=1)
    assert dict(current.residents) == dict(original.residents)
    assert current.resident_entry(moving) is original.resident_entry(moving)
    assert tuple(cache._expiration_heap) == original_heap
    assert cache._expiration_positions == original_positions
    assert policy.calls == [(moving, (target_resident,))]
    metrics = cache.metrics_snapshot()
    assert metrics["region_quota_pressure"] == 1
    assert metrics["admission_rejected"] == 1
    assert "updates" not in metrics
    assert "evictions" not in metrics


def test_cross_account_and_region_pressure_can_require_two_atomic_evictions() -> None:
    outside_region, target_region, candidate = _key(110), _key(111), _key(112)
    cache = NegativeCache(
        4,
        LruPolicy(),
        max_ttl_seconds=5,
        max_entries_per_account=2,
        max_entries_per_region=1,
    )
    assert cache.insert(outside_region, _view("a"), 0, 5, now=0)
    assert cache.insert(target_region, _view("a"), 1, 5, now=0)

    result = cache.insert_with_result(candidate, _view("a"), 1, 5, now=1)

    assert result.accepted and result.inserted
    assert tuple(eviction.entry.key for eviction in result.evictions) == (
        outside_region,
        target_region,
    )
    assert result.eviction_reasons == ("account_quota", "region_quota")
    assert result.evicted_entries == tuple(eviction.entry for eviction in result.evictions)
    assert tuple(cache.resident_snapshot(now=1).residents) == (candidate,)
    metrics = cache.metrics_snapshot()
    assert metrics["account_quota_pressure"] == 1
    assert metrics["region_quota_pressure"] == 1
    assert metrics["evictions"] == 2


def test_one_account_victim_can_resolve_account_and_region_pressure() -> None:
    shared_victim, outside_region, candidate = _key(113), _key(114), _key(115)
    cache = NegativeCache(
        4,
        LruPolicy(),
        max_ttl_seconds=5,
        max_entries_per_account=2,
        max_entries_per_region=1,
    )
    assert cache.insert(shared_victim, _view("a"), 1, 5, now=0)
    assert cache.insert(outside_region, _view("a"), 0, 5, now=0)

    result = cache.insert_with_result(candidate, _view("a"), 1, 5, now=1)

    assert result.evicted_entries[0].key == shared_victim
    assert result.eviction_reasons == ("account_quota",)
    assert len(result.evictions) == 1
    assert set(cache.resident_snapshot(now=1).residents) == {outside_region, candidate}
    metrics = cache.metrics_snapshot()
    assert metrics["account_quota_pressure"] == 1
    assert metrics["region_quota_pressure"] == 1
    assert metrics["evictions"] == 1


def test_second_quota_rejection_does_not_apply_first_planned_eviction() -> None:
    account_victim, region_victim, candidate = _key(116), _key(117), _key(118)
    policy = _ScriptedPolicy([account_victim, None])
    cache = NegativeCache(
        4,
        policy,
        max_ttl_seconds=5,
        max_entries_per_account=2,
        max_entries_per_region=1,
    )
    assert cache.insert(account_victim, _view("a"), 0, 5, now=0)
    assert cache.insert(region_victim, _view("a"), 1, 5, now=0)
    before = cache.resident_snapshot(now=1)
    before_heap = tuple(cache._expiration_heap)

    result = cache.insert_with_result(candidate, _view("a"), 1, 5, now=1)

    assert not result.accepted
    assert result.reason == "admission rejected"
    assert result.evictions == ()
    assert dict(cache.resident_snapshot(now=1).residents) == dict(before.residents)
    assert tuple(cache._expiration_heap) == before_heap
    assert policy.calls == [
        (candidate, (account_victim, region_victim)),
        (candidate, (region_victim,)),
    ]
    metrics = cache.metrics_snapshot()
    assert metrics["account_quota_pressure"] == 1
    assert metrics["region_quota_pressure"] == 1
    assert metrics["admission_rejected"] == 1
    assert "evictions" not in metrics


def test_structural_configuration_is_read_only_after_construction() -> None:
    cache = NegativeCache(
        3,
        LruPolicy(),
        max_ttl_seconds=5,
        max_entries_per_account=2,
        max_entries_per_region=1,
    )
    expected = {
        "capacity": 3,
        "max_ttl_seconds": 5,
        "max_entries_per_account": 2,
        "max_entries_per_region": 1,
    }

    for name in expected:
        with pytest.raises(AttributeError):
            setattr(cache, name, 99)

    assert {name: getattr(cache, name) for name in expected} == expected
    assert cache.insert(_key(119), _view("a"), 0, 5, now=0)
    result = cache.insert_with_result(_key(120), _view("b"), 0, 5, now=0)
    assert result.eviction_reasons == ("region_quota",)


def test_collision_and_unsafe_rejection_do_not_report_mutations() -> None:
    key = _key(35)
    original_view = _view("a")
    cache = NegativeCache(1, LruPolicy(), max_ttl_seconds=10)
    original = cache.insert_with_result(key, original_view, 0, 10, now=0)
    assert original.entry is not None

    collision = cache.insert_with_result(key, _view("b"), 1, 10, now=1)
    unsafe = cache.insert_with_result(
        _key(36),
        DirectoryView.missing("missing"),
        0,
        0,
        now=1,
    )

    for rejected in (collision, unsafe):
        assert not rejected.accepted
        assert not rejected.inserted
        assert not rejected.updated
        assert rejected.entry is None
        assert rejected.evictions == ()
        assert not rejected.ttl_clamped
    assert collision.reason == "full key collision"
    assert unsafe.reason == "unsafe directory view"
    assert cache.resident_snapshot(now=1).resident_entry(key) is original.entry


def test_custom_policy_receives_only_incrementally_indexed_quota_residents() -> None:
    class RecordingPolicy(EvictionPolicy):
        def __init__(self) -> None:
            self.eligible: tuple[NegativeKey, ...] = ()

        def observe(self, key: NegativeKey) -> None:
            return None

        def on_hit(self, key: NegativeKey) -> None:
            return None

        def on_insert(self, key: NegativeKey) -> None:
            return None

        def on_remove(self, key: NegativeKey) -> None:
            return None

        def choose_victim(
            self,
            candidate: NegativeKey,
            eligible_victims: Iterable[NegativeKey],
        ) -> NegativeKey | None:
            self.eligible = tuple(eligible_victims)
            return self.eligible[-1] if self.eligible else None

    first, second, unrelated, candidate = (_key(index) for index in range(70, 74))
    policy = RecordingPolicy()
    cache = NegativeCache(
        4,
        policy,
        max_ttl_seconds=10,
        max_entries_per_account=2,
    )
    assert cache.insert(first, _view("a"), 0, 10, now=0)
    assert cache.insert(unrelated, _view("b"), 0, 10, now=0)
    assert cache.insert(second, _view("a"), 0, 10, now=0)

    result = cache.insert_with_result(candidate, _view("a"), 0, 10, now=0)

    assert policy.eligible == (first, second)
    assert unrelated not in policy.eligible
    assert result.evicted_entries[0].key == second
    assert result.eviction_reasons == ("account_quota",)
    assert cache.resident_snapshot(now=0).eviction_order is None

    equal_policy = RecordingPolicy()
    equal_quota = NegativeCache(
        2,
        equal_policy,
        max_ttl_seconds=10,
        max_entries_per_account=2,
    )
    assert equal_quota.insert(first, _view("a"), 0, 10, now=0)
    assert equal_quota.insert(second, _view("a"), 0, 10, now=0)
    equal_result = equal_quota.insert_with_result(candidate, _view("a"), 0, 10, now=0)
    assert equal_policy.eligible == (first, second)
    assert equal_result.eviction_reasons == ("account_quota",)
    assert equal_quota._account_keys == {}


def test_custom_policy_region_pool_preserves_global_resident_insertion_order() -> None:
    class RecordingPolicy(EvictionPolicy):
        def __init__(self) -> None:
            self.eligible: tuple[NegativeKey, ...] = ()

        def observe(self, key: NegativeKey) -> None:
            return None

        def on_hit(self, key: NegativeKey) -> None:
            return None

        def on_insert(self, key: NegativeKey) -> None:
            return None

        def on_remove(self, key: NegativeKey) -> None:
            return None

        def choose_victim(
            self,
            candidate: NegativeKey,
            eligible_victims: Iterable[NegativeKey],
        ) -> NegativeKey | None:
            self.eligible = tuple(eligible_victims)
            return self.eligible[0]

    first, middle, last, candidate = (_key(index) for index in range(80, 84))
    policy = RecordingPolicy()
    cache = NegativeCache(
        5,
        policy,
        max_ttl_seconds=10,
        max_entries_per_region=3,
    )
    assert cache.insert(first, _view("a"), 0, 10, now=0)
    assert cache.insert(middle, _view("b"), 1, 10, now=0)
    assert cache.insert(last, _view("c"), 1, 10, now=0)
    assert cache.insert(first, _view("a"), 1, 10, now=1)

    result = cache.insert_with_result(candidate, _view("d"), 1, 10, now=1)

    assert policy.eligible == (first, middle, last)
    assert result.evicted_entries[0].key == first


def test_invalid_custom_policy_victim_is_rejected_without_corrupting_capacity() -> None:
    class InvalidVictimPolicy(EvictionPolicy):
        def __init__(self, victim: NegativeKey) -> None:
            self.victim = victim

        def observe(self, key: NegativeKey) -> None:
            return None

        def on_hit(self, key: NegativeKey) -> None:
            return None

        def on_insert(self, key: NegativeKey) -> None:
            return None

        def on_remove(self, key: NegativeKey) -> None:
            return None

        def choose_victim(
            self,
            candidate: NegativeKey,
            eligible_victims: Iterable[NegativeKey],
        ) -> NegativeKey | None:
            return self.victim

    resident, candidate = _key(90), _key(91)
    cache = NegativeCache(1, InvalidVictimPolicy(_key(999_999)), max_ttl_seconds=10)
    assert cache.insert(resident, _view(), 0, 10, now=0)

    result = cache.insert_with_result(candidate, _view(), 0, 10, now=0)

    assert not result.accepted
    assert result.reason == "invalid eviction victim"
    assert cache.keys() == (resident,)
    assert len(cache) == 1
    assert cache.metrics_snapshot()["admission_rejected"] == 1

    scoped, unrelated, scoped_candidate = _key(92), _key(93), _key(94)
    wrong_scope_policy = InvalidVictimPolicy(unrelated)
    quota_cache = NegativeCache(
        2,
        wrong_scope_policy,
        max_ttl_seconds=10,
        max_entries_per_account=1,
    )
    assert quota_cache.insert(scoped, _view("a"), 0, 10, now=0)
    assert quota_cache.insert(unrelated, _view("b"), 0, 10, now=0)
    wrong_scope = quota_cache.insert_with_result(
        scoped_candidate,
        _view("a"),
        0,
        10,
        now=0,
    )
    assert not wrong_scope.accepted
    assert wrong_scope.reason == "invalid eviction victim"
    assert quota_cache.keys() == (scoped, unrelated)


@pytest.mark.parametrize(
    ("quota", "accounts", "expected_reason"),
    [
        (2, ("a", "a", "a"), "account_quota"),
        (2, ("a", "b", "a"), "capacity"),
        (3, ("a", "a", "a"), "capacity"),
    ],
)
def test_account_quota_at_or_above_capacity_avoids_per_key_scope_index(
    quota: int,
    accounts: tuple[str, str, str],
    expected_reason: str,
) -> None:
    cache = NegativeCache(
        2,
        LruPolicy(),
        max_ttl_seconds=10,
        max_entries_per_account=quota,
    )
    assert cache.insert(_key(40), _view(accounts[0]), 0, 10, now=0)
    assert cache.insert(_key(41), _view(accounts[1]), 0, 10, now=0)

    result = cache.insert_with_result(_key(42), _view(accounts[2]), 0, 10, now=0)

    assert result.accepted
    assert result.eviction_reasons == (expected_reason,)
    assert cache._account_keys == {}
    if quota > cache.capacity:
        assert cache._account_counts == {}


def test_lru_subclass_keeps_custom_admission_and_has_no_exact_lru_snapshot_claim() -> None:
    class RejectingLru(LruPolicy):
        def __init__(self) -> None:
            super().__init__()
            self.choose_calls = 0

        def choose_victim(
            self,
            candidate: NegativeKey,
            eligible_victims: Iterable[NegativeKey],
        ) -> NegativeKey | None:
            self.choose_calls += 1
            tuple(eligible_victims)
            return None

    policy = RejectingLru()
    cache = NegativeCache(1, policy, max_ttl_seconds=10)
    assert cache.insert(_key(50), _view(), 0, 10, now=0)

    rejected = cache.insert_with_result(_key(51), _view(), 0, 10, now=0)

    assert not rejected.accepted
    assert rejected.reason == "admission rejected"
    assert policy.choose_calls == 1
    assert cache.keys() == (_key(50),)
    assert cache.resident_snapshot(now=0).eviction_order is None


def test_insert_and_lookup_preserve_exact_legacy_metrics() -> None:
    first, second = _key(100), _key(101)
    cache = NegativeCache(2, LruPolicy(), max_ttl_seconds=5)

    unsafe = cache.insert_with_result(
        _key(102),
        DirectoryView.missing("missing"),
        0,
        0,
        now=0,
    )
    inserted = cache.insert_with_result(first, _view("a"), 0, 10, now=0)
    updated = cache.insert_with_result(first, _view("a"), 1, 10, now=1)
    collision = cache.insert_with_result(first, _view("b"), 1, 10, now=2)
    after_purge = cache.insert_with_result(second, _view("b"), 1, 1, now=6)
    expired_lookup = cache.lookup(second, _view("b"), now=7)

    assert not unsafe.accepted
    assert inserted.ttl_clamped
    assert updated.updated and updated.ttl_clamped
    assert not collision.accepted
    assert updated.entry is not None
    assert after_purge.expired_entries == (updated.entry,)
    assert expired_lookup.expired_entry is after_purge.entry
    assert cache.metrics_snapshot() == {
        "unsafe_insert_rejected": 1,
        "inserts": 2,
        "ttl_clamped": 1,
        "updates": 1,
        "full_key_collision_fail_open": 1,
        "expired": 2,
        "misses": 1,
        "entries": 0,
        "capacity": 2,
        "peak_entries_per_account": 1,
    }


def test_peak_entries_per_account_survives_expiry_and_is_quota_independent() -> None:
    cache = NegativeCache(4, LruPolicy(), max_ttl_seconds=20)
    assert cache.metrics_snapshot()["peak_entries_per_account"] == 0

    for index in range(3):
        assert cache.insert(_key(130 + index), _view("a"), 0, 1, now=0)
    assert cache.insert(_key(133), _view("b"), 0, 10, now=0)
    assert cache.metrics_snapshot()["peak_entries_per_account"] == 3
    assert cache._account_keys == {}
    assert cache._account_counts == {}

    assert cache.insert(_key(134), _view("b"), 0, 10, now=1)
    assert cache.insert(_key(135), _view("b"), 0, 10, now=1)
    after_expiry = cache.metrics_snapshot()
    assert after_expiry["entries"] == 3
    assert after_expiry["peak_entries_per_account"] == 3

    assert cache.insert(_key(136), _view("c"), 0, 10, now=20)
    emptied = cache.metrics_snapshot()
    assert emptied["entries"] == 1
    assert emptied["peak_entries_per_account"] == 3

    quota_cache = NegativeCache(
        4,
        LruPolicy(),
        max_ttl_seconds=20,
        max_entries_per_account=2,
    )
    for index in range(3):
        assert quota_cache.insert(_key(140 + index), _view("a"), 0, 10, now=0)
    quota_metrics = quota_cache.metrics_snapshot()
    assert quota_metrics["entries"] == 2
    assert quota_metrics["peak_entries_per_account"] == 2


def test_randomized_expiration_heap_positions_survive_update_remove_and_purge() -> None:
    rng = random.Random(20260809)
    cache = NegativeCache(
        13,
        LruPolicy(),
        max_ttl_seconds=7,
        max_entries_per_account=5,
        max_entries_per_region=7,
    )
    keys = [_key(200 + index) for index in range(24)]
    now = 0.0

    for _ in range(1_000):
        now += rng.choice((0.0, 0.125, 0.5))
        key = rng.choice(keys)
        key_index = keys.index(key)
        view = _view(f"account-{key_index % 4}")
        if rng.random() < 0.7:
            result = cache.insert_with_result(
                key,
                view,
                rng.randrange(3),
                rng.choice((0.25, 1.0, 3.0, 20.0)),
                now=now,
            )
            assert result.accepted
        else:
            cache.lookup(key, view, now=now)

        snapshot = cache.resident_snapshot(now=now)
        heap = cache._expiration_heap
        positions = cache._expiration_positions
        assert len(heap) == len(positions) == len(snapshot)
        assert set(positions) == set(snapshot.residents)
        for position, (expires_at, resident_key) in enumerate(heap):
            assert positions[resident_key] == position
            entry = snapshot.resident_entry(resident_key)
            assert entry is not None
            assert expires_at == entry.expires_at
            if position:
                assert heap[(position - 1) // 2] <= heap[position]


class _CountingEntries(dict[NegativeKey, NegativeCacheEntry]):
    def __init__(self) -> None:
        super().__init__()
        self.iter_calls = 0
        self.item_calls = 0
        self.iterated_entries = 0
        self.getitem_calls = 0

    def __iter__(self) -> Iterator[NegativeKey]:
        self.iter_calls += 1
        for key in super().__iter__():
            self.iterated_entries += 1
            yield key

    def items(self) -> Iterator[tuple[NegativeKey, NegativeCacheEntry]]:
        self.item_calls += 1
        for item in super().items():
            self.iterated_entries += 1
            yield item

    def __getitem__(self, key: NegativeKey) -> NegativeCacheEntry:
        self.getitem_calls += 1
        return super().__getitem__(key)


class _CountingCache(NegativeCache):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.public_keys_calls = 0

    def keys(self) -> tuple[NegativeKey, ...]:
        self.public_keys_calls += 1
        return super().keys()


def test_lru_replay_and_expiry_purge_do_not_enumerate_resident_table() -> None:
    policy = LruPolicy()
    choose_calls = 0
    original_choose = policy.choose_victim

    def counted_choose(
        candidate: NegativeKey,
        eligible_victims: Iterable[NegativeKey],
    ) -> NegativeKey | None:
        nonlocal choose_calls
        choose_calls += 1
        return original_choose(candidate, eligible_victims)

    policy.choose_victim = counted_choose  # type: ignore[method-assign]
    cache = _CountingCache(
        32,
        policy,
        max_ttl_seconds=100,
        max_entries_per_account=8,
        max_entries_per_region=16,
    )
    entries = _CountingEntries()
    cache._entries = entries
    expired_output_count = 0

    for index in range(512):
        view = _view(f"account-{index % 8}")
        result = cache.insert_with_result(
            _key(1_000 + index),
            view,
            index % 4,
            1 if index < 32 else 100,
            now=float(index >= 32),
        )
        assert result.accepted
        expired_output_count += len(result.expired_entries)

    assert entries.iter_calls == 0
    assert entries.item_calls == 0
    assert entries.iterated_entries == 0
    assert entries.getitem_calls == 0
    assert cache.public_keys_calls == 0
    assert choose_calls == 0
    assert expired_output_count == 32
    assert cache._account_keys
    assert cache._region_keys

    snapshot = cache.resident_snapshot(now=2)

    assert len(snapshot) == len(cache)
    assert entries.getitem_calls == len(cache)
    assert entries.iter_calls == entries.item_calls == 0
    for key in tuple(snapshot.residents) * 4:
        snapshot.lookup(key, now=2)
    assert entries.getitem_calls == len(cache)


def test_disabled_quotas_keep_scope_indexes_empty() -> None:
    cache = NegativeCache(2, LruPolicy(), max_ttl_seconds=10)
    assert cache.insert(_key(60), _view("a"), 0, 10, now=0)
    assert cache.insert(_key(61), _view("b"), 1, 10, now=0)

    assert cache._account_keys == {}
    assert cache._region_keys == {}
    assert cache._account_counts == {}
    assert cache._region_counts == {}
