"""Auditable cache policies used by the controlled replay benchmark."""

from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict, deque
from math import inf
from typing import Iterable, Sequence

from dataplane.negative_cache import EvictionPolicy, NegativeKey


class ExactLfuPolicy(EvictionPolicy):
    """Exact LFU eviction with LRU tie-breaking and unconditional admission."""

    def __init__(self) -> None:
        self._frequency: Counter[NegativeKey] = Counter()
        self._recency: OrderedDict[NegativeKey, None] = OrderedDict()

    def observe(self, key: NegativeKey) -> None:
        if key in self._frequency:
            self._frequency[key] += 1

    def on_hit(self, key: NegativeKey) -> None:
        if key in self._recency:
            self._recency.move_to_end(key)

    def on_insert(self, key: NegativeKey) -> None:
        self._frequency[key] = 1
        self._recency[key] = None
        self._recency.move_to_end(key)

    def on_remove(self, key: NegativeKey) -> None:
        self._recency.pop(key, None)
        self._frequency.pop(key, None)

    def choose_victim(
        self,
        candidate: NegativeKey,
        eligible_victims: Iterable[NegativeKey],
    ) -> NegativeKey | None:
        eligible = set(eligible_victims)
        if not eligible:
            return None
        age = {key: index for index, key in enumerate(self._recency)}
        return min(
            eligible,
            key=lambda key: (self._frequency[key], age.get(key, -1), key),
        )

    @property
    def state_entry_count(self) -> int:
        """Number of resident keys carrying LFU state."""

        assert set(self._frequency) == set(self._recency)
        return len(self._frequency)


class FutureReuseOraclePolicy(EvictionPolicy):
    """Belady admission/eviction using the declared future request sequence.

    This is an offline upper-bound baseline. It is not deployable and its future
    sequence is counted as experiment input, not edge memory.
    """

    def __init__(self, request_sequence: Sequence[NegativeKey]) -> None:
        self._future: dict[NegativeKey, deque[int]] = defaultdict(deque)
        for position, key in enumerate(request_sequence):
            self._future[key].append(position)
        self._position = -1
        self.alignment_mismatches = 0

    def observe(self, key: NegativeKey) -> None:
        self._position += 1
        positions = self._future[key]
        if positions and positions[0] == self._position:
            positions.popleft()
            return

        self.alignment_mismatches += 1
        while positions and positions[0] <= self._position:
            positions.popleft()

    def on_hit(self, key: NegativeKey) -> None:
        return None

    def on_insert(self, key: NegativeKey) -> None:
        return None

    def on_remove(self, key: NegativeKey) -> None:
        return None

    def _next_use(self, key: NegativeKey) -> float:
        positions = self._future.get(key)
        return float(positions[0]) if positions else inf

    def choose_victim(
        self,
        candidate: NegativeKey,
        eligible_victims: Iterable[NegativeKey],
    ) -> NegativeKey | None:
        eligible = tuple(eligible_victims)
        if not eligible:
            return None
        victim = max(eligible, key=lambda key: (self._next_use(key), key))
        if self._next_use(candidate) >= self._next_use(victim):
            return None
        return victim
