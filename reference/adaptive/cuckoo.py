"""Adaptive Cuckoo Filter reference implementation.

This implements the two-table, four-cell construction in Section 3.3 of
Mitzenmacher, Pontarelli, and Reviriego, JEA 2020. The exact backing table and
the fingerprint table have a one-to-one slot correspondence. A confirmed false
positive swaps the colliding item with another cell in the same bucket, thereby
changing both items' cell-indexed fingerprint functions.
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from threading import RLock

from reference.filters.common import (
    TOKEN_BYTES,
    MemoryReport,
    PackedArray,
    QueryResult,
    ScreenQuery,
    alignment_padding,
    ceil_power_of_two,
    hash64,
    validate_members,
)


class AdaptiveCuckooFilterBuildError(RuntimeError):
    pass


class AdaptiveCuckooFilter:
    """Paper-faithful ACF with `d=2` tables and cell-indexed fingerprints."""

    method = "adaptive_cuckoo_d2_c4"

    def __init__(
        self,
        bucket_count: int,
        bucket_size: int = 4,
        fingerprint_bits: int = 12,
        seed: int = 0,
        max_kicks: int = 500,
    ) -> None:
        if bucket_count < 2 or bucket_count & (bucket_count - 1):
            raise ValueError("bucket_count must be a power of two >= 2")
        if bucket_size < 2 or bucket_size > 16:
            raise ValueError("bucket_size must be in [2, 16]")
        if not 4 <= fingerprint_bits <= 64:
            raise ValueError("fingerprint_bits must be in [4, 64]")
        if max_kicks <= 0:
            raise ValueError("max_kicks must be positive")
        self.bucket_count = bucket_count
        self.bucket_size = bucket_size
        self.fingerprint_bits = fingerprint_bits
        self.seed = seed
        self.max_kicks = max_kicks
        self.n_items = 0
        self._bucket_mask = bucket_count - 1
        self._fingerprint_mask = (1 << fingerprint_bits) - 1
        self._slot_count = 2 * bucket_count * bucket_size
        self._fingerprints = PackedArray(self._slot_count, fingerprint_bits)
        self._keys: list[bytes | None] = [None] * self._slot_count
        self._lock = RLock()
        self._metrics: Counter[str] = Counter()

    @classmethod
    def build(
        cls,
        members: list[ScreenQuery],
        fingerprint_bits: int = 12,
        bucket_size: int = 4,
        target_load: float = 0.90,
        seed: int = 0,
        max_kicks: int = 500,
        max_seed_attempts: int = 20,
    ) -> "AdaptiveCuckooFilter":
        if not 0.1 <= target_load < 1.0:
            raise ValueError("target_load must be in [0.1, 1.0)")
        if max_seed_attempts <= 0:
            raise ValueError("max_seed_attempts must be positive")
        items = validate_members(members)
        unique = {item.token: item for item in items}
        desired_slots = math.ceil(len(unique) / target_load)
        buckets = math.ceil(desired_slots / (2 * bucket_size))
        bucket_count = ceil_power_of_two(max(2, buckets))
        retry_step = 0x9E3779B97F4A7C15
        mask64 = 0xFFFFFFFFFFFFFFFF
        for attempt in range(max_seed_attempts):
            candidate = cls(
                bucket_count=bucket_count,
                bucket_size=bucket_size,
                fingerprint_bits=fingerprint_bits,
                seed=(seed + attempt * retry_step) & mask64,
                max_kicks=max_kicks,
            )
            if all(candidate.add(item) for item in unique.values()):
                candidate.build_attempts = attempt + 1
                return candidate
        raise AdaptiveCuckooFilterBuildError(
            f"could not insert {len(unique)} keys after {max_seed_attempts} seeds"
        )

    def _bucket(self, token: bytes, table: int) -> int:
        domain = b"acf-table-0" if table == 0 else b"acf-table-1"
        return hash64(token, self.seed, domain) & self._bucket_mask

    def _slot(self, table: int, bucket: int, offset: int) -> int:
        return ((table * self.bucket_count + bucket) * self.bucket_size) + offset

    def _fingerprint(self, token: bytes, offset: int) -> int:
        domain = b"acf-fp-" + bytes([offset])
        hashed = hash64(token, self.seed, domain)
        return ((hashed * self._fingerprint_mask) >> 64) + 1

    def _empty_slot(self, table: int, bucket: int) -> int | None:
        for offset in range(self.bucket_size):
            slot = self._slot(table, bucket, offset)
            if self._keys[slot] is None:
                return slot
        return None

    def _write(self, slot: int, token: bytes | None) -> None:
        self._keys[slot] = token
        if token is None:
            self._fingerprints.set(slot, 0)
            return
        offset = slot % self.bucket_size
        self._fingerprints.set(slot, self._fingerprint(token, offset))

    def add(self, item: ScreenQuery) -> bool:
        token = item.token
        with self._lock:
            for table in (0, 1):
                bucket = self._bucket(token, table)
                empty = self._empty_slot(table, bucket)
                if empty is not None:
                    self._write(empty, token)
                    self.n_items += 1
                    return True

            random_state = hash64(token, self.seed, b"acf-insertion")
            table = random_state & 1
            displaced = token
            undo: list[tuple[int, bytes | None]] = []
            for _ in range(self.max_kicks):
                bucket = self._bucket(displaced, table)
                random_state ^= (random_state << 13) & 0xFFFFFFFFFFFFFFFF
                random_state ^= random_state >> 7
                random_state ^= (random_state << 17) & 0xFFFFFFFFFFFFFFFF
                offset = random_state % self.bucket_size
                slot = self._slot(table, bucket, offset)
                previous = self._keys[slot]
                undo.append((slot, previous))
                self._write(slot, displaced)
                if previous is None:
                    self.n_items += 1
                    return True
                displaced = previous
                table ^= 1
                target_bucket = self._bucket(displaced, table)
                empty = self._empty_slot(table, target_bucket)
                if empty is not None:
                    self._write(empty, displaced)
                    self.n_items += 1
                    return True

            for slot, previous in reversed(undo):
                self._write(slot, previous)
            return False

    def query(self, item: ScreenQuery) -> QueryResult:
        comparisons = 0
        with self._lock:
            for table in (0, 1):
                bucket = self._bucket(item.token, table)
                for offset in range(self.bucket_size):
                    comparisons += 1
                    slot = self._slot(table, bucket, offset)
                    expected = self._fingerprint(item.token, offset)
                    if self._fingerprints.get(slot) == expected:
                        return QueryResult(True, probes=table + 1, comparisons=comparisons)
        return QueryResult(False, probes=2, comparisons=comparisons)

    def confirm_false_positive(self, item: ScreenQuery) -> bool:
        """Adapt one colliding slot after exact backend mismatch confirmation."""

        with self._lock:
            matched: tuple[int, int, int] | None = None
            exact_member = False
            for table in (0, 1):
                bucket = self._bucket(item.token, table)
                for offset in range(self.bucket_size):
                    slot = self._slot(table, bucket, offset)
                    if self._fingerprints.get(slot) != self._fingerprint(item.token, offset):
                        continue
                    if self._keys[slot] == item.token:
                        exact_member = True
                    elif matched is None:
                        matched = (table, bucket, offset)
            if exact_member:
                raise ValueError("cannot adapt a represented member as a false positive")
            if matched is None:
                self._metrics["stale_feedback"] += 1
                return False

            table, bucket, source_offset = matched
            source_slot = self._slot(table, bucket, source_offset)
            sequence = self._metrics["adaptations"]
            choice = hash64(
                item.token,
                (self.seed + sequence) & 0xFFFFFFFFFFFFFFFF,
                b"acf-adaptation",
            ) % (self.bucket_size - 1)
            target_offset = choice if choice < source_offset else choice + 1
            target_slot = self._slot(table, bucket, target_offset)
            source_key = self._keys[source_slot]
            target_key = self._keys[target_slot]
            assert source_key is not None
            self._write(source_slot, target_key)
            self._write(target_slot, source_key)
            self._metrics["adaptations"] += 1
            self._metrics["empty_cell_moves"] += int(target_key is None)
            return True

    def delete(self, item: ScreenQuery) -> bool:
        """Delete only an exact stored token; fingerprint matches are insufficient."""

        with self._lock:
            for table in (0, 1):
                bucket = self._bucket(item.token, table)
                for offset in range(self.bucket_size):
                    slot = self._slot(table, bucket, offset)
                    if self._keys[slot] != item.token:
                        continue
                    self._write(slot, None)
                    self.n_items -= 1
                    self._metrics["deletions"] += 1
                    return True
            self._metrics["deletion_misses"] += 1
            return False

    @property
    def load_factor(self) -> float:
        return self.n_items / self._slot_count

    def memory_report(self) -> MemoryReport:
        metadata = struct.pack(
            ">8sHQQHHIQI16s",
            b"RTACFv1\x00",
            1,
            self.n_items,
            self.bucket_count,
            self.bucket_size,
            self.fingerprint_bits,
            self.max_kicks,
            self.seed,
            getattr(self, "build_attempts", 1),
            b"b2-acf-d2c4-v1".ljust(16, b"\x00"),
        )
        return MemoryReport(
            payload_bytes=self._fingerprints.nbytes,
            metadata_bytes=len(metadata),
            alignment_bytes=alignment_padding(len(metadata))
            + alignment_padding(self._fingerprints.nbytes),
        )

    def backing_memory_report(self) -> MemoryReport:
        occupancy_bytes = (self._slot_count + 7) // 8
        metadata_bytes = struct.calcsize(">8sHQQH")
        payload_bytes = self._slot_count * TOKEN_BYTES + occupancy_bytes
        return MemoryReport(
            payload_bytes=payload_bytes,
            metadata_bytes=metadata_bytes,
            alignment_bytes=alignment_padding(metadata_bytes)
            + alignment_padding(payload_bytes),
        )

    def metrics_snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._metrics)

    def parameters(self) -> dict[str, int | float | str]:
        return {
            "tables": 2,
            "bucket_count_per_table": self.bucket_count,
            "bucket_size": self.bucket_size,
            "fingerprint_bits": self.fingerprint_bits,
            "n_items": self.n_items,
            "load_factor": self.load_factor,
            "hash_seed": self.seed,
            "max_kicks": self.max_kicks,
            "build_attempts": getattr(self, "build_attempts", 1),
            "adaptation": "same-bucket cell swap after exact mismatch feedback",
            "backing_table": "one-to-one exact 128-bit token slots",
        }
