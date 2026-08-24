"""Global and cache-line-blocked Bloom filter reference baselines."""

from __future__ import annotations

import math
import struct

from .common import (
    MemoryReport,
    QueryResult,
    ScreenQuery,
    alignment_padding,
    finite_bloom_fpr,
    hash128,
    reduce_u64,
    standard_bloom_fpr,
    validate_members,
)


def _bit_is_set(bits: bytearray, index: int) -> bool:
    return bool(bits[index >> 3] & (1 << (index & 7)))


def _set_bit(bits: bytearray, index: int) -> None:
    bits[index >> 3] |= 1 << (index & 7)


class GlobalBloomFilter:
    """Global Bloom filter with the configured full integer k and early exit."""

    method = "global_bloom"

    def __init__(self, m_bits: int, k_hashes: int, seed: int) -> None:
        if m_bits <= 0:
            raise ValueError("m_bits must be positive")
        if not 1 <= k_hashes <= 0xFFFF:
            raise ValueError("k_hashes must be an integer in [1, 65535]")
        self.m_bits = m_bits
        self.k_hashes = k_hashes
        self.seed = seed
        self.n_items = 0
        self._bits = bytearray((m_bits + 7) // 8)

    @classmethod
    def build(
        cls, members: list[ScreenQuery], m_bits: int, k_hashes: int, seed: int
    ) -> "GlobalBloomFilter":
        items = validate_members(members)
        result = cls(m_bits=m_bits, k_hashes=k_hashes, seed=seed)
        for item in items:
            result.add(item)
        return result

    def _positions(self, token: bytes):
        first, step = hash128(token, self.seed, b"global-bloom-v1")
        step = step or 0x9E3779B97F4A7C15
        for probe in range(self.k_hashes):
            yield (first + probe * step) % self.m_bits

    def add(self, item: ScreenQuery) -> None:
        for position in self._positions(item.token):
            _set_bit(self._bits, position)
        self.n_items += 1

    def query(self, item: ScreenQuery) -> QueryResult:
        probes = 0
        for position in self._positions(item.token):
            probes += 1
            if not _bit_is_set(self._bits, position):
                return QueryResult(False, probes=probes)
        return QueryResult(True, probes=probes)

    @property
    def analytic_fpr_finite(self) -> float:
        return finite_bloom_fpr(self.m_bits, self.n_items, self.k_hashes)

    @property
    def analytic_fpr_standard(self) -> float:
        return standard_bloom_fpr(self.m_bits, self.n_items, self.k_hashes)

    @property
    def bit_density(self) -> float:
        return sum(byte.bit_count() for byte in self._bits) / self.m_bits

    def memory_report(self) -> MemoryReport:
        metadata = struct.pack(
            ">8sHQQHQ16s",
            b"RTBLMv1\x00",
            1,
            self.m_bits,
            self.n_items,
            self.k_hashes,
            self.seed,
            b"b2-double-v1".ljust(16, b"\x00"),
        )
        return MemoryReport(
            payload_bytes=len(self._bits),
            metadata_bytes=len(metadata),
            alignment_bytes=alignment_padding(len(metadata))
            + alignment_padding(len(self._bits)),
        )

    def parameters(self) -> dict[str, int | float | str]:
        return {
            "m_bits": self.m_bits,
            "n_items": self.n_items,
            "k_hashes": self.k_hashes,
            "hash_seed": self.seed,
            "hash_scheme": "BLAKE2b-128 keyed double hashing",
            "analytic_fpr_finite": self.analytic_fpr_finite,
            "analytic_fpr_standard": self.analytic_fpr_standard,
            "analytic_fpr_realized_density": self.bit_density**self.k_hashes,
            "bit_density": self.bit_density,
        }


def blocked_bloom_fpr_finite(
    block_count: int, block_bits: int, n_items: int, k_hashes: int
) -> float:
    """Expected finite FPR over the binomial load of the selected block."""

    if block_count <= 0 or block_bits <= 0 or n_items < 0 or k_hashes <= 0:
        raise ValueError("invalid blocked Bloom parameters")
    if n_items == 0:
        return 0.0
    if block_count == 1:
        return finite_bloom_fpr(block_bits, n_items, k_hashes)

    probability = 1.0 / block_count
    mean = n_items * probability
    sigma = math.sqrt(n_items * probability * (1.0 - probability))
    lower = max(0, int(math.floor(mean - 12.0 * sigma - 8.0)))
    upper = min(n_items, int(math.ceil(mean + 12.0 * sigma + 8.0)))
    total = 0.0
    mass = 0.0
    log_p = math.log(probability)
    log_q = math.log1p(-probability)
    for load in range(lower, upper + 1):
        log_mass = (
            math.lgamma(n_items + 1)
            - math.lgamma(load + 1)
            - math.lgamma(n_items - load + 1)
            + load * log_p
            + (n_items - load) * log_q
        )
        point_mass = math.exp(log_mass)
        mass += point_mass
        total += point_mass * finite_bloom_fpr(block_bits, load, k_hashes)
    # The omitted 12-sigma tails are numerical truncation, not zero probability.
    return total / mass if mass else 0.0


class BlockedBloomFilter:
    """Bloom filter whose complete query state resides in one 64-byte block."""

    method = "blocked_bloom_64b"
    block_bytes = 64
    block_bits = block_bytes * 8

    def __init__(self, requested_m_bits: int, k_hashes: int, seed: int) -> None:
        if requested_m_bits <= 0:
            raise ValueError("requested_m_bits must be positive")
        if not 1 <= k_hashes <= 0xFFFF:
            raise ValueError("k_hashes must be an integer in [1, 65535]")
        self.requested_m_bits = requested_m_bits
        self.block_count = max(1, math.ceil(requested_m_bits / self.block_bits))
        self.m_bits = self.block_count * self.block_bits
        self.k_hashes = k_hashes
        self.seed = seed
        self.n_items = 0
        self._bits = bytearray(self.block_count * self.block_bytes)

    @classmethod
    def build(
        cls, members: list[ScreenQuery], m_bits: int, k_hashes: int, seed: int
    ) -> "BlockedBloomFilter":
        items = validate_members(members)
        result = cls(m_bits, k_hashes, seed)
        for item in items:
            result.add(item)
        return result

    def _positions(self, token: bytes):
        block_hash, local_hash = hash128(token, self.seed, b"blocked-bloom-v1")
        block = reduce_u64(block_hash, self.block_count)
        local_first = local_hash & (self.block_bits - 1)
        # An odd step traverses all 512 positions before repeating.
        local_step = ((local_hash >> 32) | 1) & (self.block_bits - 1)
        base = block * self.block_bits
        for probe in range(self.k_hashes):
            yield base + ((local_first + probe * local_step) & (self.block_bits - 1))

    def add(self, item: ScreenQuery) -> None:
        for position in self._positions(item.token):
            _set_bit(self._bits, position)
        self.n_items += 1

    def query(self, item: ScreenQuery) -> QueryResult:
        probes = 0
        for position in self._positions(item.token):
            probes += 1
            if not _bit_is_set(self._bits, position):
                return QueryResult(False, probes=probes)
        return QueryResult(True, probes=probes)

    @property
    def analytic_fpr_finite(self) -> float:
        return blocked_bloom_fpr_finite(
            self.block_count, self.block_bits, self.n_items, self.k_hashes
        )

    @property
    def analytic_fpr_standard(self) -> float:
        return standard_bloom_fpr(self.m_bits, self.n_items, self.k_hashes)

    @property
    def bit_density(self) -> float:
        return sum(byte.bit_count() for byte in self._bits) / self.m_bits

    @property
    def analytic_fpr_realized_density(self) -> float:
        total = 0.0
        for block in range(self.block_count):
            start = block * self.block_bytes
            occupied = sum(
                byte.bit_count() for byte in self._bits[start : start + self.block_bytes]
            )
            total += (occupied / self.block_bits) ** self.k_hashes
        return total / self.block_count

    def memory_report(self) -> MemoryReport:
        metadata = struct.pack(
            ">8sHQQQHQHQ16s",
            b"RTBBFv1\x00",
            1,
            self.requested_m_bits,
            self.m_bits,
            self.n_items,
            self.k_hashes,
            self.seed,
            self.block_bytes,
            self.block_count,
            b"b2-block-v1".ljust(16, b"\x00"),
        )
        # The compact payload begins at the next 64-byte boundary.
        return MemoryReport(
            len(self._bits),
            metadata_bytes=len(metadata),
            alignment_bytes=alignment_padding(len(metadata), self.block_bytes),
        )

    def parameters(self) -> dict[str, int | float | str]:
        return {
            "requested_m_bits": self.requested_m_bits,
            "m_bits": self.m_bits,
            "n_items": self.n_items,
            "k_hashes": self.k_hashes,
            "hash_seed": self.seed,
            "block_bytes": self.block_bytes,
            "block_count": self.block_count,
            "hash_scheme": "BLAKE2b-128: one block plus odd local double hash",
            "analytic_fpr_finite": self.analytic_fpr_finite,
            "analytic_fpr_standard": self.analytic_fpr_standard,
            "analytic_fpr_realized_density": self.analytic_fpr_realized_density,
            "bit_density": self.bit_density,
        }
