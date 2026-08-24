from __future__ import annotations

import math
import time
from abc import ABC, abstractmethod
from collections import Counter, OrderedDict
from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType
from typing import AbstractSet, Dict, Iterable, Iterator, Mapping, Optional

from .crypto import negative_digest
from .types import DirectoryView


@dataclass(frozen=True, order=True)
class NegativeKey:
    key_id: int
    digest: bytes

    def __post_init__(self) -> None:
        if type(self.key_id) is not int:
            raise TypeError("negative key IDs must be exact integers")
        if self.key_id < 1:
            raise ValueError("negative key IDs must be positive")
        if type(self.digest) is not bytes:
            raise TypeError("negative key digests must be exact bytes")
        if len(self.digest) < 16:
            raise ValueError("exact negative keys must be at least 128 bits")


class NegativeKeyDeriver:
    """Independently rotatable K_N derivation using the full HMAC-SHA-256 key."""

    def __init__(self, key: bytes, key_id: int = 1) -> None:
        if len(key) < 16:
            raise ValueError("K_N must be at least 128 bits")
        if type(key_id) is not int:
            raise TypeError("key_id must be an exact integer")
        if key_id < 1:
            raise ValueError("key_id must be positive")
        self._lock = RLock()
        self._key = bytes(key)
        self._key_id = key_id

    def derive(self, view: DirectoryView, credential_token: bytes) -> NegativeKey:
        account_id, generation, version = view.scope
        with self._lock:
            return NegativeKey(
                self._key_id,
                negative_digest(
                    self._key,
                    account_id,
                    generation,
                    version,
                    credential_token,
                ),
            )

    def rotate(self, new_key: bytes, new_key_id: Optional[int] = None) -> int:
        if len(new_key) < 16:
            raise ValueError("K_N must be at least 128 bits")
        with self._lock:
            if new_key_id is not None and type(new_key_id) is not int:
                raise TypeError("new_key_id must be an exact integer")
            next_id = self._key_id + 1 if new_key_id is None else new_key_id
            if next_id <= self._key_id:
                raise ValueError("negative key IDs must increase")
            self._key = bytes(new_key)
            self._key_id = next_id
            return next_id

    @property
    def key_id(self) -> int:
        with self._lock:
            return self._key_id


@dataclass(frozen=True)
class NegativeCacheEntry:
    key: NegativeKey
    account_id: str
    account_generation: int
    credential_set_version: int
    region: int
    inserted_at: float
    expires_at: float

    def matches_view(self, view: DirectoryView) -> bool:
        return (
            view.can_screen
            and (
                self.account_id,
                self.account_generation,
                self.credential_set_version,
            )
            == view.scope
        )


@dataclass(frozen=True)
class CacheLookup:
    hit: bool
    entry: Optional[NegativeCacheEntry] = None
    reason: str = ""
    expired_entry: Optional[NegativeCacheEntry] = None


@dataclass(frozen=True)
class CacheEviction:
    entry: NegativeCacheEntry
    reason: str


@dataclass(frozen=True)
class CacheInsertResult:
    """Insertion outcome and mutations caused by that single operation.

    ``expired_entries`` is bounded by the cache's pre-operation capacity. The
    cache retains no mutation history after returning this immutable tuple.
    ``evictions`` records application order (account, region, then capacity);
    the entire batch is selected and validated before any victim is removed.
    """

    accepted: bool
    inserted: bool = False
    updated: bool = False
    entry: Optional[NegativeCacheEntry] = None
    reason: str = ""
    expired_entries: tuple[NegativeCacheEntry, ...] = ()
    evictions: tuple[CacheEviction, ...] = ()
    ttl_clamped: bool = False

    @property
    def evicted_entries(self) -> tuple[NegativeCacheEntry, ...]:
        return tuple(eviction.entry for eviction in self.evictions)

    @property
    def eviction_reasons(self) -> tuple[str, ...]:
        return tuple(eviction.reason for eviction in self.evictions)


@dataclass(frozen=True)
class NegativeCacheSnapshot:
    """Frozen physical residents with pure logical lookup semantics.

    For an LRU cache, both ``residents`` iteration and ``eviction_order`` are
    ordered from the next eviction candidate to the most recently used entry.
    Other policies expose no eviction order.
    """

    captured_at: float
    residents: Mapping[NegativeKey, NegativeCacheEntry]
    eviction_order: Optional[tuple[NegativeKey, ...]] = None

    def __len__(self) -> int:
        return len(self.residents)

    def __contains__(self, key: object) -> bool:
        return key in self.residents

    def resident_entry(self, key: NegativeKey) -> Optional[NegativeCacheEntry]:
        """Return the physical resident, including one logically expired now."""

        return self.residents.get(key)

    def lookup(
        self,
        key: NegativeKey,
        expected_view: Optional[DirectoryView] = None,
        now: Optional[float] = None,
    ) -> CacheLookup:
        """Query frozen state without cleanup, policy touches, or metric changes."""

        current = self.captured_at if now is None else now
        if not math.isfinite(current):
            raise ValueError("now must be finite")
        entry = self.residents.get(key)
        if entry is None:
            return CacheLookup(False, reason="exact key miss")
        if entry.expires_at <= current:
            return CacheLookup(False, reason="expired", expired_entry=entry)
        if expected_view is not None and not entry.matches_view(expected_view):
            return CacheLookup(False, reason="entry metadata does not match directory scope")
        return CacheLookup(True, entry=entry, reason="full exact-key hit")


class EvictionPolicy(ABC):
    """Admission/eviction interface; implementations are called under cache lock."""

    @abstractmethod
    def observe(self, key: NegativeKey) -> None:
        pass

    @abstractmethod
    def on_hit(self, key: NegativeKey) -> None:
        pass

    @abstractmethod
    def on_insert(self, key: NegativeKey) -> None:
        pass

    @abstractmethod
    def on_remove(self, key: NegativeKey) -> None:
        pass

    @abstractmethod
    def choose_victim(
        self,
        candidate: NegativeKey,
        eligible_victims: Iterable[NegativeKey],
    ) -> Optional[NegativeKey]:
        """Return an eligible victim, or None to reject admission.

        Eligible keys retain resident insertion order for compatibility. A
        returned key outside this iterable is treated as admission rejection.
        """


class _ResidentOrderEligibleKeys:
    """Lazy scope filter preserving the historic resident insertion order."""

    def __init__(
        self,
        residents: Mapping[NegativeKey, NegativeCacheEntry],
        eligible: Mapping[NegativeKey, object],
    ) -> None:
        self._residents = residents
        self._eligible = eligible

    def __iter__(self) -> Iterator[NegativeKey]:
        return (key for key in self._residents if key in self._eligible)


class _WithoutKeys:
    def __init__(
        self,
        keys: Iterable[NegativeKey],
        excluded: AbstractSet[NegativeKey],
    ) -> None:
        self._keys = keys
        self._excluded = excluded

    def __iter__(self) -> Iterator[NegativeKey]:
        return (key for key in self._keys if key not in self._excluded)


class LruPolicy(EvictionPolicy):
    def __init__(self) -> None:
        self._order: OrderedDict[NegativeKey, None] = OrderedDict()

    def observe(self, key: NegativeKey) -> None:
        return None

    def on_hit(self, key: NegativeKey) -> None:
        if key in self._order:
            self._order.move_to_end(key)

    def on_insert(self, key: NegativeKey) -> None:
        self._order[key] = None
        self._order.move_to_end(key)

    def on_remove(self, key: NegativeKey) -> None:
        self._order.pop(key, None)

    def oldest(
        self,
        excluded: AbstractSet[NegativeKey] = frozenset(),
    ) -> Optional[NegativeKey]:
        """Return the oldest non-excluded resident without copying the order."""

        return next((key for key in self._order if key not in excluded), None)

    def order_snapshot(self) -> tuple[NegativeKey, ...]:
        """Return resident keys from oldest to most recently used."""

        return tuple(self._order)

    def choose_victim(
        self,
        candidate: NegativeKey,
        eligible_victims: Iterable[NegativeKey],
    ) -> Optional[NegativeKey]:
        eligible = set(eligible_victims)
        for key in self._order:
            if key in eligible:
                return key
        return min(eligible) if eligible else None


class TinyLfuPolicy(EvictionPolicy):
    """TinyLFU-style frequency admission with recency tie-breaking.

    One-hit scans are rejected once the cache is full unless a candidate has
    accumulated more observations than a resident victim.  Periodic halving
    bounds history and lets workloads change.
    """

    def __init__(self, reset_after: int = 100_000) -> None:
        if type(reset_after) is not int:
            raise TypeError("reset_after must be an exact integer")
        if reset_after < 16:
            raise ValueError("reset_after must be at least 16")
        self._frequency: Counter[NegativeKey] = Counter()
        self._recency: OrderedDict[NegativeKey, None] = OrderedDict()
        self._samples = 0
        self._reset_after = reset_after

    def observe(self, key: NegativeKey) -> None:
        self._frequency[key] = min(255, self._frequency[key] + 1)
        self._samples += 1
        if self._samples >= self._reset_after:
            self._frequency = Counter(
                {candidate: count // 2 for candidate, count in self._frequency.items() if count > 1}
            )
            self._samples = 0

    def on_hit(self, key: NegativeKey) -> None:
        if key in self._recency:
            self._recency.move_to_end(key)

    def on_insert(self, key: NegativeKey) -> None:
        self._recency[key] = None
        self._recency.move_to_end(key)

    def on_remove(self, key: NegativeKey) -> None:
        self._recency.pop(key, None)

    def choose_victim(
        self,
        candidate: NegativeKey,
        eligible_victims: Iterable[NegativeKey],
    ) -> Optional[NegativeKey]:
        eligible = set(eligible_victims)
        if not eligible:
            return None
        age = {key: index for index, key in enumerate(self._recency)}
        victim = min(
            eligible,
            key=lambda key: (self._frequency[key], age.get(key, -1), key),
        )
        if self._frequency[candidate] <= self._frequency[victim]:
            return None
        return victim


class NegativeCache:
    """Bounded, exact-key, TTL cache with optional account/region quotas."""

    def __init__(
        self,
        capacity: int,
        policy: EvictionPolicy,
        max_ttl_seconds: float = 300.0,
        max_entries_per_account: Optional[int] = None,
        max_entries_per_region: Optional[int] = None,
    ) -> None:
        if type(capacity) is not int:
            raise TypeError("capacity must be an exact integer")
        if capacity < 1:
            raise ValueError("capacity must be positive")
        if not math.isfinite(max_ttl_seconds) or max_ttl_seconds <= 0:
            raise ValueError("max_ttl_seconds must be finite and positive")
        for quota in (max_entries_per_account, max_entries_per_region):
            if quota is not None and type(quota) is not int:
                raise TypeError("cache quotas must be exact integers")
            if quota is not None and quota < 1:
                raise ValueError("cache quotas must be positive")
        self._capacity = capacity
        self._max_ttl_seconds = max_ttl_seconds
        self._max_entries_per_account = max_entries_per_account
        self._max_entries_per_region = max_entries_per_region
        self._policy = policy
        self._uses_exact_lru = type(policy) is LruPolicy
        self._indexes_accounts = (
            max_entries_per_account is not None and max_entries_per_account < capacity
        )
        self._counts_accounts = max_entries_per_account == capacity
        self._indexes_regions = (
            max_entries_per_region is not None and max_entries_per_region < capacity
        )
        self._counts_regions = max_entries_per_region == capacity
        self._entries: Dict[NegativeKey, NegativeCacheEntry] = {}
        self._expiration_heap: list[tuple[float, NegativeKey]] = []
        self._expiration_positions: dict[NegativeKey, int] = {}
        self._account_keys: dict[str, OrderedDict[NegativeKey, None]] = {}
        self._region_keys: dict[int, OrderedDict[NegativeKey, None]] = {}
        self._account_counts: Counter[str] = Counter()
        self._region_counts: Counter[int] = Counter()
        self._resident_account_counts: Counter[str] = Counter()
        self._lock = RLock()
        self._metrics: Counter[str] = Counter()

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def max_ttl_seconds(self) -> float:
        return self._max_ttl_seconds

    @property
    def max_entries_per_account(self) -> Optional[int]:
        return self._max_entries_per_account

    @property
    def max_entries_per_region(self) -> Optional[int]:
        return self._max_entries_per_region

    def _expiration_swap(self, left: int, right: int) -> None:
        heap = self._expiration_heap
        heap[left], heap[right] = heap[right], heap[left]
        self._expiration_positions[heap[left][1]] = left
        self._expiration_positions[heap[right][1]] = right

    def _expiration_sift_up(self, position: int) -> int:
        heap = self._expiration_heap
        while position:
            parent = (position - 1) // 2
            if heap[parent] <= heap[position]:
                break
            self._expiration_swap(parent, position)
            position = parent
        return position

    def _expiration_sift_down(self, position: int) -> int:
        heap = self._expiration_heap
        size = len(heap)
        while True:
            left = 2 * position + 1
            if left >= size:
                break
            right = left + 1
            smallest = right if right < size and heap[right] < heap[left] else left
            if heap[position] <= heap[smallest]:
                break
            self._expiration_swap(position, smallest)
            position = smallest
        return position

    def _set_expiration(self, key: NegativeKey, expires_at: float) -> None:
        position = self._expiration_positions.get(key)
        item = (expires_at, key)
        if position is None:
            position = len(self._expiration_heap)
            self._expiration_heap.append(item)
            self._expiration_positions[key] = position
            self._expiration_sift_up(position)
            return
        self._expiration_heap[position] = item
        position = self._expiration_sift_up(position)
        self._expiration_sift_down(position)

    def _remove_expiration(self, key: NegativeKey) -> None:
        position = self._expiration_positions.pop(key)
        last = self._expiration_heap.pop()
        if position == len(self._expiration_heap):
            return
        self._expiration_heap[position] = last
        self._expiration_positions[last[1]] = position
        position = self._expiration_sift_up(position)
        self._expiration_sift_down(position)

    @staticmethod
    def _discard_index_key(index: dict, group: object, key: NegativeKey) -> None:
        keys = index[group]
        keys.pop(key)
        if not keys:
            del index[group]

    def _index_insert(self, entry: NegativeCacheEntry) -> None:
        self._resident_account_counts[entry.account_id] += 1
        self._metrics["peak_entries_per_account"] = max(
            self._metrics["peak_entries_per_account"],
            self._resident_account_counts[entry.account_id],
        )
        if self._indexes_accounts:
            self._account_keys.setdefault(entry.account_id, OrderedDict())[entry.key] = None
        elif self._counts_accounts:
            self._account_counts[entry.account_id] += 1
        if self._indexes_regions:
            self._region_keys.setdefault(entry.region, OrderedDict())[entry.key] = None
        elif self._counts_regions:
            self._region_counts[entry.region] += 1

    def _index_touch(self, entry: NegativeCacheEntry) -> None:
        if not self._uses_exact_lru:
            return
        if self._indexes_accounts:
            self._account_keys[entry.account_id].move_to_end(entry.key)
        if self._indexes_regions:
            self._region_keys[entry.region].move_to_end(entry.key)

    def _index_update(
        self,
        existing: NegativeCacheEntry,
        candidate: NegativeCacheEntry,
    ) -> None:
        if existing.region != candidate.region:
            if self._indexes_regions:
                self._discard_index_key(self._region_keys, existing.region, existing.key)
                self._region_keys.setdefault(candidate.region, OrderedDict())[candidate.key] = None
            elif self._counts_regions:
                self._region_counts[existing.region] -= 1
                if not self._region_counts[existing.region]:
                    del self._region_counts[existing.region]
                self._region_counts[candidate.region] += 1
        if not self._uses_exact_lru:
            return
        if self._indexes_accounts:
            self._account_keys[candidate.account_id].move_to_end(candidate.key)
        if self._indexes_regions and existing.region == candidate.region:
            self._region_keys[candidate.region].move_to_end(candidate.key)

    def _index_remove(self, entry: NegativeCacheEntry) -> None:
        self._resident_account_counts[entry.account_id] -= 1
        if not self._resident_account_counts[entry.account_id]:
            del self._resident_account_counts[entry.account_id]
        if self._indexes_accounts:
            self._discard_index_key(self._account_keys, entry.account_id, entry.key)
        elif self._counts_accounts:
            self._account_counts[entry.account_id] -= 1
            if not self._account_counts[entry.account_id]:
                del self._account_counts[entry.account_id]
        if self._indexes_regions:
            self._discard_index_key(self._region_keys, entry.region, entry.key)
        elif self._counts_regions:
            self._region_counts[entry.region] -= 1
            if not self._region_counts[entry.region]:
                del self._region_counts[entry.region]

    def _remove(self, key: NegativeKey, reason: str) -> Optional[NegativeCacheEntry]:
        entry = self._entries.pop(key, None)
        if entry is None:
            return None
        self._remove_expiration(key)
        self._index_remove(entry)
        self._policy.on_remove(key)
        self._metrics[reason] += 1
        return entry

    def _purge_expired(self, now: float) -> tuple[NegativeCacheEntry, ...]:
        expired: list[NegativeCacheEntry] = []
        while self._expiration_heap and self._expiration_heap[0][0] <= now:
            entry = self._remove(self._expiration_heap[0][1], "expired")
            if entry is not None:
                expired.append(entry)
        return tuple(expired)

    def _is_eligible_victim(
        self,
        key: NegativeKey,
        pressure_reason: str,
        account_id: str,
        region: int,
    ) -> bool:
        entry = self._entries.get(key)
        if entry is None:
            return False
        if pressure_reason == "account_quota":
            return entry.account_id == account_id
        if pressure_reason == "region_quota":
            return entry.region == region
        return pressure_reason == "capacity"

    def _region_victim_pool(self, region: int) -> Optional[Iterable[NegativeKey]]:
        quota = self.max_entries_per_region
        if quota is None:
            return None
        if self._indexes_regions:
            region_keys = self._region_keys.get(region)
            if region_keys is None or len(region_keys) < quota:
                return None
            return _ResidentOrderEligibleKeys(self._entries, region_keys)
        if self._counts_regions and self._region_counts[region] >= quota:
            return self._entries
        return None

    def _account_victim_pool(self, account_id: str) -> Optional[Iterable[NegativeKey]]:
        quota = self.max_entries_per_account
        if quota is None:
            return None
        if self._indexes_accounts:
            account_keys = self._account_keys.get(account_id)
            if account_keys is None or len(account_keys) < quota:
                return None
            return _ResidentOrderEligibleKeys(self._entries, account_keys)
        if self._counts_accounts and self._account_counts[account_id] >= quota:
            return self._entries
        return None

    def _select_victim(
        self,
        candidate: NegativeKey,
        victim_pool: Iterable[NegativeKey],
        pressure_reason: str,
        account_id: str,
        region: int,
        excluded: AbstractSet[NegativeKey] = frozenset(),
    ) -> tuple[Optional[NegativeKey], str]:
        if self._uses_exact_lru:
            if pressure_reason == "account_quota" and self._indexes_accounts:
                order = self._account_keys[account_id]
                victim = next((item for item in order if item not in excluded), None)
            elif pressure_reason == "region_quota" and self._indexes_regions:
                order = self._region_keys[region]
                victim = next((item for item in order if item not in excluded), None)
            else:
                victim = self._policy.oldest(excluded)
        else:
            eligible = _WithoutKeys(victim_pool, excluded) if excluded else victim_pool
            victim = self._policy.choose_victim(candidate, eligible)
        if victim is None:
            return None, "admission rejected"
        if victim in excluded or not self._is_eligible_victim(
            victim,
            pressure_reason,
            account_id,
            region,
        ):
            return None, "invalid eviction victim"
        return victim, ""

    def lookup(
        self,
        key: NegativeKey,
        expected_view: Optional[DirectoryView] = None,
        now: Optional[float] = None,
    ) -> CacheLookup:
        if type(key) is not NegativeKey:
            raise TypeError("key must be exact NegativeKey")
        current = time.monotonic() if now is None else now
        if not math.isfinite(current):
            raise ValueError("now must be finite")
        with self._lock:
            self._policy.observe(key)
            entry = self._entries.get(key)
            if entry is None:
                self._metrics["misses"] += 1
                return CacheLookup(False, reason="exact key miss")
            if entry.expires_at <= current:
                expired_entry = self._remove(key, "expired")
                self._metrics["misses"] += 1
                return CacheLookup(False, reason="expired", expired_entry=expired_entry)
            if expected_view is not None and not entry.matches_view(expected_view):
                # A full-key collision must fail open, never reject another scope.
                self._metrics["metadata_mismatch_fail_open"] += 1
                self._metrics["misses"] += 1
                return CacheLookup(False, reason="entry metadata does not match directory scope")
            self._policy.on_hit(key)
            self._index_touch(entry)
            self._metrics["hits"] += 1
            return CacheLookup(True, entry=entry, reason="full exact-key hit")

    def insert(
        self,
        key: NegativeKey,
        view: DirectoryView,
        region: int,
        ttl_seconds: float,
        now: Optional[float] = None,
    ) -> bool:
        return self.insert_with_result(key, view, region, ttl_seconds, now).accepted

    def insert_with_result(
        self,
        key: NegativeKey,
        view: DirectoryView,
        region: int,
        ttl_seconds: float,
        now: Optional[float] = None,
    ) -> CacheInsertResult:
        """Insert while returning the exact incremental mutation metadata."""

        if type(key) is not NegativeKey:
            raise TypeError("key must be exact NegativeKey")
        if not view.can_screen:
            with self._lock:
                self._metrics["unsafe_insert_rejected"] += 1
            return CacheInsertResult(False, reason="unsafe directory view")
        if not math.isfinite(ttl_seconds) or ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be finite and positive")
        current = time.monotonic() if now is None else now
        if not math.isfinite(current):
            raise ValueError("now must be finite")
        ttl = min(ttl_seconds, self.max_ttl_seconds)
        expires_at = current + ttl
        if not math.isfinite(expires_at) or expires_at <= current:
            raise ValueError("cache expiry must be finite and follow insertion")
        account_id, generation, version = view.scope
        candidate = NegativeCacheEntry(
            key=key,
            account_id=account_id,
            account_generation=generation,
            credential_set_version=version,
            region=region,
            inserted_at=current,
            expires_at=expires_at,
        )
        with self._lock:
            expired_entries = self._purge_expired(current)
            existing = self._entries.get(key)
            if existing is not None:
                if (
                    existing.account_id,
                    existing.account_generation,
                    existing.credential_set_version,
                ) != (account_id, generation, version):
                    self._metrics["full_key_collision_fail_open"] += 1
                    return CacheInsertResult(
                        False,
                        reason="full key collision",
                        expired_entries=expired_entries,
                    )
                evictions: tuple[CacheEviction, ...] = ()
                if existing.region != region:
                    victim_pool = self._region_victim_pool(region)
                    if victim_pool is not None:
                        self._metrics["region_quota_pressure"] += 1
                        victim, rejection_reason = self._select_victim(
                            key,
                            victim_pool,
                            "region_quota",
                            account_id,
                            region,
                        )
                        if victim is None:
                            self._metrics["admission_rejected"] += 1
                            return CacheInsertResult(
                                False,
                                reason=rejection_reason,
                                expired_entries=expired_entries,
                            )
                        removed = self._remove(victim, "evictions")
                        if removed is None:  # pragma: no cover - lock-protected invariant
                            raise RuntimeError("selected cache victim disappeared")
                        evictions = (CacheEviction(removed, "region_quota"),)
                self._entries[key] = candidate
                self._set_expiration(key, candidate.expires_at)
                self._policy.on_hit(key)
                self._index_update(existing, candidate)
                self._metrics["updates"] += 1
                return CacheInsertResult(
                    True,
                    updated=True,
                    entry=candidate,
                    reason="updated",
                    expired_entries=expired_entries,
                    evictions=evictions,
                    ttl_clamped=ttl < ttl_seconds,
                )

            planned: list[tuple[NegativeKey, str]] = []
            planned_keys: set[NegativeKey] = set()
            account_pool = self._account_victim_pool(account_id)
            if account_pool is not None:
                self._metrics["account_quota_pressure"] += 1
                victim, rejection_reason = self._select_victim(
                    key,
                    account_pool,
                    "account_quota",
                    account_id,
                    region,
                    planned_keys,
                )
                if victim is None:
                    self._metrics["admission_rejected"] += 1
                    return CacheInsertResult(
                        False,
                        reason=rejection_reason,
                        expired_entries=expired_entries,
                    )
                planned.append((victim, "account_quota"))
                planned_keys.add(victim)

            region_pool = self._region_victim_pool(region)
            if region_pool is not None:
                self._metrics["region_quota_pressure"] += 1
                region_resolved = any(
                    self._entries[victim].region == region for victim in planned_keys
                )
                if not region_resolved:
                    victim, rejection_reason = self._select_victim(
                        key,
                        region_pool,
                        "region_quota",
                        account_id,
                        region,
                        planned_keys,
                    )
                    if victim is None:
                        self._metrics["admission_rejected"] += 1
                        return CacheInsertResult(
                            False,
                            reason=rejection_reason,
                            expired_entries=expired_entries,
                        )
                    planned.append((victim, "region_quota"))
                    planned_keys.add(victim)

            if len(self._entries) - len(planned) >= self.capacity:
                victim, rejection_reason = self._select_victim(
                    key,
                    self._entries,
                    "capacity",
                    account_id,
                    region,
                    planned_keys,
                )
                if victim is None:
                    self._metrics["admission_rejected"] += 1
                    return CacheInsertResult(
                        False,
                        reason=rejection_reason,
                        expired_entries=expired_entries,
                    )
                planned.append((victim, "capacity"))
                planned_keys.add(victim)

            applied_evictions: list[CacheEviction] = []
            for victim, eviction_reason in planned:
                removed = self._remove(victim, "evictions")
                if removed is None:  # pragma: no cover - lock-protected invariant
                    raise RuntimeError("selected cache victim disappeared")
                applied_evictions.append(CacheEviction(removed, eviction_reason))

            self._entries[key] = candidate
            self._set_expiration(key, candidate.expires_at)
            self._index_insert(candidate)
            self._policy.on_insert(key)
            self._metrics["inserts"] += 1
            self._metrics["ttl_clamped"] += int(ttl < ttl_seconds)
            assert len(self._entries) <= self.capacity
            return CacheInsertResult(
                True,
                inserted=True,
                entry=candidate,
                reason="inserted",
                expired_entries=expired_entries,
                evictions=tuple(applied_evictions),
                ttl_clamped=ttl < ttl_seconds,
            )

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def keys(self) -> tuple[NegativeKey, ...]:
        with self._lock:
            return tuple(self._entries)

    def resident_snapshot(self, now: Optional[float] = None) -> NegativeCacheSnapshot:
        """Copy current physical residents without cleanup or policy mutation."""

        with self._lock:
            captured_at = time.monotonic() if now is None else now
            if not math.isfinite(captured_at):
                raise ValueError("now must be finite")
            eviction_order: Optional[tuple[NegativeKey, ...]] = None
            if self._uses_exact_lru:
                eviction_order = self._policy.order_snapshot()
                resident_copy = {key: self._entries[key] for key in eviction_order}
            else:
                resident_copy = {key: entry for key, entry in self._entries.items()}
            return NegativeCacheSnapshot(
                captured_at=captured_at,
                residents=MappingProxyType(resident_copy),
                eviction_order=eviction_order,
            )

    def metrics_snapshot(self) -> dict[str, int]:
        with self._lock:
            result = dict(self._metrics)
            result["entries"] = len(self._entries)
            result["capacity"] = self.capacity
            result["peak_entries_per_account"] = self._metrics["peak_entries_per_account"]
            return result
