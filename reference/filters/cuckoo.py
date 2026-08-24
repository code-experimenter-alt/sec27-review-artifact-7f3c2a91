"""Packed, update-capable Cuckoo filter reference baseline."""

from __future__ import annotations

import math
import struct

from .common import (
    MemoryReport,
    PackedArray,
    QueryResult,
    ScreenQuery,
    alignment_padding,
    ceil_power_of_two,
    hash64,
    validate_members,
)


class CuckooFilterBuildError(RuntimeError):
    pass


class CuckooFilter:
    """Two-choice Cuckoo filter with atomic rollback on insertion failure."""

    method = "cuckoo_filter"

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
        if not 1 <= bucket_size <= 16:
            raise ValueError("bucket_size must be in [1, 16]")
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
        self._slots = PackedArray(bucket_count * bucket_size, fingerprint_bits)

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
    ) -> "CuckooFilter":
        if not 0.1 <= target_load < 1.0:
            raise ValueError("target_load must be in [0.1, 1.0)")
        if max_seed_attempts <= 0:
            raise ValueError("max_seed_attempts must be positive")
        items = validate_members(members)
        unique: dict[bytes, ScreenQuery] = {}
        for item in items:
            unique.setdefault(item.token, item)
        desired_slots = math.ceil(len(unique) / target_load)
        bucket_count = ceil_power_of_two(max(2, math.ceil(desired_slots / bucket_size)))
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
        raise CuckooFilterBuildError(
            f"could not insert {len(unique)} keys after {max_seed_attempts} seeds"
        )

    def _alternate_delta(self, fingerprint: int) -> int:
        mixed = (fingerprint * 0x5BD1E995) & 0xFFFFFFFFFFFFFFFF
        mixed ^= mixed >> 24
        # Odd is nonzero for every power-of-two bucket count.
        return (mixed | 1) & self._bucket_mask

    def _fingerprint_and_buckets(self, token: bytes) -> tuple[int, int, int, int]:
        hashed = hash64(token, self.seed, b"cuckoo-filter-v1")
        fingerprint = ((hashed * self._fingerprint_mask) >> 64) + 1
        first = hashed & self._bucket_mask
        second = first ^ self._alternate_delta(fingerprint)
        return fingerprint, first, second, hashed

    def _slot_index(self, bucket: int, offset: int) -> int:
        return bucket * self.bucket_size + offset

    def _find(self, bucket: int, fingerprint: int) -> tuple[int | None, int]:
        comparisons = 0
        for offset in range(self.bucket_size):
            slot = self._slot_index(bucket, offset)
            comparisons += 1
            if self._slots.get(slot) == fingerprint:
                return slot, comparisons
        return None, comparisons

    def _empty(self, bucket: int) -> int | None:
        for offset in range(self.bucket_size):
            slot = self._slot_index(bucket, offset)
            if self._slots.get(slot) == 0:
                return slot
        return None

    def query(self, item: ScreenQuery) -> QueryResult:
        fingerprint, first, second, _ = self._fingerprint_and_buckets(item.token)
        slot, comparisons = self._find(first, fingerprint)
        if slot is not None:
            return QueryResult(True, probes=1, comparisons=comparisons)
        slot, more = self._find(second, fingerprint)
        return QueryResult(
            slot is not None,
            probes=2,
            comparisons=comparisons + more,
        )

    def add(self, item: ScreenQuery) -> bool:
        fingerprint, first, second, random_state = self._fingerprint_and_buckets(
            item.token
        )
        # The caller inserts each logical token at most once. Fingerprint-equivalent
        # keys still receive distinct slots so deleting one cannot remove another.
        for bucket in (first, second):
            empty = self._empty(bucket)
            if empty is not None:
                self._slots.set(empty, fingerprint)
                self.n_items += 1
                return True

        bucket = first if random_state & 1 else second
        displaced = fingerprint
        undo: list[tuple[int, int]] = []
        for _ in range(self.max_kicks):
            random_state ^= (random_state << 13) & 0xFFFFFFFFFFFFFFFF
            random_state ^= random_state >> 7
            random_state ^= (random_state << 17) & 0xFFFFFFFFFFFFFFFF
            offset = random_state % self.bucket_size
            slot = self._slot_index(bucket, offset)
            previous = self._slots.get(slot)
            undo.append((slot, previous))
            self._slots.set(slot, displaced)
            displaced = previous
            bucket ^= self._alternate_delta(displaced)
            empty = self._empty(bucket)
            if empty is not None:
                self._slots.set(empty, displaced)
                self.n_items += 1
                return True

        for slot, previous in reversed(undo):
            self._slots.set(slot, previous)
        return False

    def delete(self, item: ScreenQuery) -> bool:
        """Delete a known inserted key; deleting arbitrary nonmembers is unsafe."""

        fingerprint, first, second, _ = self._fingerprint_and_buckets(item.token)
        for bucket in (first, second):
            slot, _ = self._find(bucket, fingerprint)
            if slot is not None:
                self._slots.set(slot, 0)
                self.n_items -= 1
                return True
        return False

    @property
    def load_factor(self) -> float:
        return self.n_items / (self.bucket_count * self.bucket_size)

    @property
    def analytic_fpr_standard(self) -> float:
        comparisons = 2 * self.bucket_size
        # A query compares against every slot in its two candidate buckets.
        # Only the realized occupied fraction can match a nonzero fingerprint.
        per_slot_match = self.load_factor / self._fingerprint_mask
        return -math.expm1(comparisons * math.log1p(-per_slot_match))

    def memory_report(self) -> MemoryReport:
        metadata = struct.pack(
            ">8sHQQHHIQI16s",
            b"RTCKOv1\x00",
            1,
            self.n_items,
            self.bucket_count,
            self.bucket_size,
            self.fingerprint_bits,
            self.max_kicks,
            self.seed,
            getattr(self, "build_attempts", 1),
            b"b2-cuckoo-v1".ljust(16, b"\x00"),
        )
        return MemoryReport(
            payload_bytes=self._slots.nbytes,
            metadata_bytes=len(metadata),
            alignment_bytes=alignment_padding(len(metadata))
            + alignment_padding(self._slots.nbytes),
        )

    def parameters(self) -> dict[str, int | float | str]:
        return {
            "m_bits": self.bucket_count * self.bucket_size * self.fingerprint_bits,
            "n_items": self.n_items,
            "k_hashes": 2,
            "fingerprint_bits": self.fingerprint_bits,
            "bucket_count": self.bucket_count,
            "bucket_size": self.bucket_size,
            "load_factor": self.load_factor,
            "hash_seed": self.seed,
            "max_kicks": self.max_kicks,
            "build_attempts": getattr(self, "build_attempts", 1),
            "analytic_fpr_standard": self.analytic_fpr_standard,
            "analytic_fpr_standard_model": (
                "1-(1-load_factor/(2^fingerprint_bits-1))^(2*bucket_size)"
            ),
            "hash_scheme": "BLAKE2b-64 with fingerprint-derived alternate bucket",
        }
