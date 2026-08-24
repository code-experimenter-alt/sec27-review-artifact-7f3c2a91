"""Prefix-only recurrence features and memory-bounded cache baselines."""

from __future__ import annotations

import hashlib
import math
from collections import OrderedDict, defaultdict
from dataclasses import dataclass
from typing import Hashable, Sequence

import numpy as np

from models.stable_router.model import LogisticScore
from models.synthetic_workload import AuthEvent

RECURRENCE_FEATURE_NAMES = (
    "log_same_tuple_prior_count",
    "log_ms_since_same_tuple",
    "log_account_prior_invalid_count",
    "log_account_prior_distinct_count",
    "same_to_distinct_ratio",
    "source_continuity",
    "device_continuity",
    "credential_age_fraction",
    "rotation_recent",
    "verifier_cost_weight",
    "cache_pressure",
)


@dataclass(frozen=True)
class RecurrenceExample:
    event_index: int
    tuple_key: Hashable
    features: tuple[float, ...]
    repeats_within_horizon: int
    future_repeat_count: int


class HistoryTracker:
    """Construct features from the trace prefix, then update explicitly."""

    def __init__(self) -> None:
        self.tuple_count: dict[Hashable, int] = defaultdict(int)
        self.tuple_last_ms: dict[Hashable, int] = {}
        self.account_invalid_count: dict[Hashable, int] = defaultdict(int)
        self.account_distinct: dict[Hashable, set[Hashable]] = defaultdict(set)

    @staticmethod
    def account_key(event: AuthEvent) -> tuple[int, int, int]:
        return (
            event.account_index,
            event.account_generation,
            event.credential_set_version,
        )

    def features(self, event: AuthEvent, cache_pressure: float = 0.0) -> tuple[float, ...]:
        event.validate()
        if (
            type(cache_pressure) not in {int, float}
            or not math.isfinite(cache_pressure)
            or not 0 <= cache_pressure <= 1
        ):
            raise ValueError("cache_pressure must lie in [0, 1]")
        key = event.tuple_key
        account = self.account_key(event)
        same_count = self.tuple_count[key]
        last = self.tuple_last_ms.get(key)
        since = 1e12 if last is None else max(0, event.relative_timestamp_ms - last)
        invalid_count = self.account_invalid_count[account]
        distinct_count = len(self.account_distinct[account])
        return (
            math.log1p(same_count),
            math.log1p(since),
            math.log1p(invalid_count),
            math.log1p(distinct_count),
            same_count / max(1, distinct_count),
            event.coarse_source_continuity / 3.0,
            event.coarse_device_continuity / 3.0,
            event.credential_age_fraction,
            float(event.rotation_recent),
            event.verifier_cost_weight,
            cache_pressure,
        )

    def observe(self, event: AuthEvent) -> None:
        event.validate()
        if not event.is_existing_invalid:
            return
        key = event.tuple_key
        account = self.account_key(event)
        self.tuple_count[key] += 1
        self.tuple_last_ms[key] = event.relative_timestamp_ms
        self.account_invalid_count[account] += 1
        self.account_distinct[account].add(key)


def build_recurrence_examples(
    events: Sequence[AuthEvent], horizon_ms: int
) -> tuple[RecurrenceExample, ...]:
    """Label prefix-only examples using future reuse within ``horizon_ms``."""

    if type(horizon_ms) is not int or horizon_ms <= 0:
        raise ValueError("horizon_ms must be positive")
    invalid = [event for event in events if event.is_existing_invalid]
    positions_by_key: dict[Hashable, list[int]] = defaultdict(list)
    for position, event in enumerate(invalid):
        positions_by_key[event.tuple_key].append(position)

    future_count = np.zeros(len(invalid), dtype=np.int64)
    next_within = np.zeros(len(invalid), dtype=np.int8)
    for positions in positions_by_key.values():
        right = 0
        for left, position in enumerate(positions):
            right = max(right, left + 1)
            deadline = invalid[position].relative_timestamp_ms + horizon_ms
            while (
                right < len(positions)
                and invalid[positions[right]].relative_timestamp_ms <= deadline
            ):
                right += 1
            count = right - left - 1
            future_count[position] = count
            next_within[position] = int(count > 0)

    tracker = HistoryTracker()
    examples: list[RecurrenceExample] = []
    for position, event in enumerate(invalid):
        features = tracker.features(event, cache_pressure=0.0)
        examples.append(
            RecurrenceExample(
                event_index=event.event_index,
                tuple_key=event.tuple_key,
                features=features,
                repeats_within_horizon=int(next_within[position]),
                future_repeat_count=int(future_count[position]),
            )
        )
        tracker.observe(event)
    return tuple(examples)


class RecurrenceModel:
    """Logistic probability of same-tuple reuse; never a validity predicate."""

    def __init__(self, l2: float = 1e-3) -> None:
        self.model = LogisticScore(l2=l2)

    def fit(self, examples: Sequence[RecurrenceExample]) -> "RecurrenceModel":
        if not examples:
            raise ValueError("at least one recurrence example is required")
        features = np.asarray([example.features for example in examples], dtype=np.float64)
        labels = np.asarray(
            [example.repeats_within_horizon for example in examples], dtype=np.float64
        )
        # Expected saved verifier work is the fitting weight.  It is intent
        # neutral and is computed only from future equality/multiplicity.
        weight = np.asarray(
            [1.0 + example.future_repeat_count for example in examples],
            dtype=np.float64,
        )
        self.model.fit(features, labels, weight)
        return self

    def predict(self, features: Sequence[Sequence[float]]) -> np.ndarray:
        values = np.asarray(features, dtype=np.float64)
        if values.ndim == 1:
            values = values.reshape(1, -1)
        return self.model.score(values)

    @property
    def memory_bytes(self) -> int:
        return self.model.memory_bytes + 24


def brier_score(probabilities: Sequence[float], labels: Sequence[int]) -> float:
    probability = np.asarray(probabilities, dtype=np.float64)
    target = np.asarray(labels, dtype=np.float64)
    if probability.shape != target.shape or probability.size == 0:
        raise ValueError("probabilities and labels must have the same nonempty shape")
    if not np.all(np.isfinite(probability)) or not np.all(np.isfinite(target)):
        raise ValueError("probabilities and labels must be finite")
    if np.any((probability < 0) | (probability > 1)) or np.any((target < 0) | (target > 1)):
        raise ValueError("probabilities and labels must lie in [0, 1]")
    return float(np.mean((probability - target) ** 2))


def expected_calibration_error(
    probabilities: Sequence[float], labels: Sequence[int], bins: int = 10
) -> float:
    probability = np.asarray(probabilities, dtype=np.float64)
    target = np.asarray(labels, dtype=np.float64)
    if probability.shape != target.shape or probability.size == 0:
        raise ValueError("probabilities and labels must have the same nonempty shape")
    if not np.all(np.isfinite(probability)) or not np.all(np.isfinite(target)):
        raise ValueError("probabilities and labels must be finite")
    if np.any((probability < 0) | (probability > 1)) or np.any((target < 0) | (target > 1)):
        raise ValueError("probabilities and labels must lie in [0, 1]")
    if type(bins) is not int or bins <= 0:
        raise ValueError("bins must be positive")
    bin_index = np.minimum(bins - 1, (probability * bins).astype(int))
    error = 0.0
    for index in range(bins):
        selected = bin_index == index
        if np.any(selected):
            error += float(selected.mean()) * abs(
                float(probability[selected].mean()) - float(target[selected].mean())
            )
    return error


def _key_bytes(key: Hashable) -> bytes:
    return (type(key).__qualname__ + ":" + repr(key)).encode("utf-8")


def _nonnegative_int(value: int, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")


class ExactLRUCache:
    """Exact-key LRU with an optional fixed TTL and bounded entry count."""

    def __init__(self, capacity: int, entry_bytes: int, ttl_ms: int | None = None) -> None:
        if type(capacity) is not int or type(entry_bytes) is not int:
            raise ValueError("capacity and entry_bytes must be integers")
        if capacity < 0 or entry_bytes <= 0:
            raise ValueError("capacity must be nonnegative and entry_bytes positive")
        if ttl_ms is not None and (type(ttl_ms) is not int or ttl_ms <= 0):
            raise ValueError("ttl_ms must be positive when supplied")
        self.capacity = capacity
        self.entry_bytes = entry_bytes
        self.ttl_ms = ttl_ms
        self.entries: OrderedDict[Hashable, int] = OrderedDict()
        self.evictions = 0
        self.expirations = 0
        self.admissions = 0

    def lookup(self, key: Hashable, now_ms: int) -> bool:
        _nonnegative_int(now_ms, "now_ms")
        inserted = self.entries.get(key)
        if inserted is None:
            return False
        if self.ttl_ms is not None and now_ms - inserted > self.ttl_ms:
            del self.entries[key]
            self.expirations += 1
            return False
        self.entries.move_to_end(key)
        return True

    def admit(self, key: Hashable, now_ms: int, value: float | None = None) -> bool:
        _nonnegative_int(now_ms, "now_ms")
        del value
        if self.capacity == 0:
            return False
        if key in self.entries:
            self.entries[key] = now_ms
            self.entries.move_to_end(key)
            return True
        if len(self.entries) >= self.capacity:
            self.entries.popitem(last=False)
            self.evictions += 1
        self.entries[key] = now_ms
        self.admissions += 1
        return True

    @property
    def pressure(self) -> float:
        return len(self.entries) / self.capacity if self.capacity else 1.0

    @property
    def memory_bytes(self) -> int:
        return self.capacity * self.entry_bytes


class TinyLFUCache:
    """LRU victim selection with a bounded four-row TinyLFU frequency sketch."""

    def __init__(
        self,
        budget_bytes: int,
        entry_bytes: int,
        seed: int,
        sketch_fraction: float = 0.10,
        depth: int = 4,
    ) -> None:
        if type(budget_bytes) is not int or type(entry_bytes) is not int:
            raise ValueError("budget_bytes and entry_bytes must be integers")
        if budget_bytes < 0 or entry_bytes <= 0:
            raise ValueError("budget_bytes must be nonnegative and entry_bytes positive")
        if (
            type(sketch_fraction) not in {int, float}
            or not math.isfinite(sketch_fraction)
            or not 0 <= sketch_fraction < 1
            or type(depth) is not int
            or depth <= 0
        ):
            raise ValueError("invalid sketch fraction or depth")
        reserve_limit = max(0, budget_bytes - entry_bytes)
        requested = min(reserve_limit, int(budget_bytes * sketch_fraction))
        width = requested // depth
        self.sketch = np.zeros((depth, width), dtype=np.uint8)
        self.sketch_bytes = int(self.sketch.nbytes)
        self.capacity = (budget_bytes - self.sketch_bytes) // entry_bytes
        self.entry_bytes = entry_bytes
        if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("seed must fit uint64")
        self.seed = seed
        self.entries: OrderedDict[Hashable, int] = OrderedDict()
        self.observations = 0
        self.reset_interval = max(1, 10 * self.sketch.shape[1])
        self.evictions = 0
        self.rejected_admissions = 0
        self.admissions = 0

    def _indices(self, key: Hashable) -> tuple[int, ...]:
        if self.sketch.shape[1] == 0:
            return ()
        material = _key_bytes(key)
        result = []
        for row in range(self.sketch.shape[0]):
            digest = hashlib.blake2b(
                material,
                key=hashlib.sha256(f"tinylfu:{self.seed}:{row}".encode()).digest(),
                digest_size=8,
            ).digest()
            result.append(int.from_bytes(digest, "big") % self.sketch.shape[1])
        return tuple(result)

    def _observe(self, key: Hashable) -> None:
        self.observations += 1
        for row, column in enumerate(self._indices(key)):
            if self.sketch[row, column] < 255:
                self.sketch[row, column] += 1
        if self.observations >= self.reset_interval and self.sketch.size:
            np.right_shift(self.sketch, 1, out=self.sketch)
            self.observations = 0

    def _frequency(self, key: Hashable) -> int:
        indices = self._indices(key)
        if not indices:
            return 1
        return min(int(self.sketch[row, column]) for row, column in enumerate(indices))

    def lookup(self, key: Hashable, now_ms: int) -> bool:
        _nonnegative_int(now_ms, "now_ms")
        self._observe(key)
        if key not in self.entries:
            return False
        self.entries.move_to_end(key)
        return True

    def admit(self, key: Hashable, now_ms: int, value: float | None = None) -> bool:
        _nonnegative_int(now_ms, "now_ms")
        del value
        if self.capacity == 0:
            return False
        if key in self.entries:
            self.entries[key] = now_ms
            self.entries.move_to_end(key)
            return True
        if len(self.entries) >= self.capacity:
            victim = next(iter(self.entries))
            if self._frequency(key) <= self._frequency(victim):
                self.rejected_admissions += 1
                return False
            del self.entries[victim]
            self.evictions += 1
        self.entries[key] = now_ms
        self.admissions += 1
        return True

    @property
    def pressure(self) -> float:
        return len(self.entries) / self.capacity if self.capacity else 1.0

    @property
    def memory_bytes(self) -> int:
        return self.capacity * self.entry_bytes + self.sketch_bytes


class LearnedValueCache:
    """Exact cache that admits by predicted future-reuse value."""

    def __init__(self, capacity: int, entry_bytes: int, model: RecurrenceModel) -> None:
        if type(capacity) is not int or type(entry_bytes) is not int:
            raise ValueError("capacity and entry_bytes must be integers")
        if capacity < 0 or entry_bytes <= 0:
            raise ValueError("capacity must be nonnegative and entry_bytes positive")
        self.capacity = capacity
        self.entry_bytes = entry_bytes
        self.model = model
        self.entries: OrderedDict[Hashable, tuple[float, int]] = OrderedDict()
        self.evictions = 0
        self.rejected_admissions = 0
        self.admissions = 0

    def lookup(self, key: Hashable, now_ms: int) -> bool:
        _nonnegative_int(now_ms, "now_ms")
        if key not in self.entries:
            return False
        self.entries.move_to_end(key)
        return True

    def admit(self, key: Hashable, now_ms: int, value: float | None = None) -> bool:
        _nonnegative_int(now_ms, "now_ms")
        if type(value) not in {int, float} or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError("learned admission requires a probability in [0, 1]")
        if self.capacity == 0:
            return False
        if key in self.entries:
            self.entries[key] = (value, now_ms)
            self.entries.move_to_end(key)
            return True
        if len(self.entries) >= self.capacity:
            victim, (victim_value, _) = min(
                self.entries.items(), key=lambda item: (item[1][0], item[1][1])
            )
            if value <= victim_value:
                self.rejected_admissions += 1
                return False
            del self.entries[victim]
            self.evictions += 1
        self.entries[key] = (value, now_ms)
        self.admissions += 1
        return True

    @property
    def pressure(self) -> float:
        return len(self.entries) / self.capacity if self.capacity else 1.0

    @property
    def memory_bytes(self) -> int:
        return self.capacity * self.entry_bytes


class OracleCache:
    """Belady-style future-use cache used only as a labeled upper bound."""

    def __init__(self, capacity: int, entry_bytes: int) -> None:
        if type(capacity) is not int or type(entry_bytes) is not int:
            raise ValueError("capacity and entry_bytes must be integers")
        if capacity < 0 or entry_bytes <= 0:
            raise ValueError("capacity must be nonnegative and entry_bytes positive")
        self.capacity = capacity
        self.entry_bytes = entry_bytes
        self.entries: dict[Hashable, int | None] = {}
        self.evictions = 0
        self.rejected_admissions = 0
        self.admissions = 0

    def lookup(self, key: Hashable, now_ms: int) -> bool:
        _nonnegative_int(now_ms, "now_ms")
        return key in self.entries

    def update_next_use(self, key: Hashable, next_use: int | None) -> None:
        if next_use is not None:
            _nonnegative_int(next_use, "next_use")
        if key in self.entries:
            self.entries[key] = next_use

    def admit(
        self,
        key: Hashable,
        now_ms: int,
        value: float | None = None,
        *,
        next_use: int | None = None,
    ) -> bool:
        _nonnegative_int(now_ms, "now_ms")
        if next_use is not None:
            _nonnegative_int(next_use, "next_use")
        del value
        if self.capacity == 0 or next_use is None:
            self.rejected_admissions += 1
            return False
        if key in self.entries:
            self.entries[key] = next_use
            return True
        if len(self.entries) >= self.capacity:
            victim, victim_next = max(
                self.entries.items(),
                key=lambda item: math.inf if item[1] is None else item[1],
            )
            victim_distance = math.inf if victim_next is None else victim_next
            if next_use >= victim_distance:
                self.rejected_admissions += 1
                return False
            del self.entries[victim]
            self.evictions += 1
        self.entries[key] = next_use
        self.admissions += 1
        return True

    @property
    def pressure(self) -> float:
        return len(self.entries) / self.capacity if self.capacity else 1.0

    @property
    def memory_bytes(self) -> int:
        return self.capacity * self.entry_bytes
