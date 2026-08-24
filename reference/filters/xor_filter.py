"""Dependency-free static three-way Xor filter for immutable epochs."""

from __future__ import annotations

import math
import struct
from collections import deque

from .common import (
    MemoryReport,
    PackedArray,
    QueryResult,
    ScreenQuery,
    alignment_padding,
    hash64,
    reduce_u64,
    rotate_left_64,
    validate_members,
)


class XorFilterBuildError(RuntimeError):
    pass


class StaticXorFilter:
    """A static Xor filter; this class does not claim Binary Fuse semantics."""

    method = "xor_static_3way"
    arity = 3

    def __init__(
        self,
        fingerprints: PackedArray,
        n_items: int,
        block_length: int,
        fingerprint_bits: int,
        seed: int,
        build_attempts: int,
    ) -> None:
        self._fingerprints = fingerprints
        self.n_items = n_items
        self.block_length = block_length
        self.capacity = fingerprints.count
        self.fingerprint_bits = fingerprint_bits
        self.seed = seed
        self.build_attempts = build_attempts
        self._fingerprint_mask = (1 << fingerprint_bits) - 1

    @staticmethod
    def _positions_for_hash(value: int, block_length: int) -> tuple[int, int, int]:
        return (
            reduce_u64(value, block_length),
            block_length + reduce_u64(rotate_left_64(value, 21), block_length),
            2 * block_length + reduce_u64(rotate_left_64(value, 42), block_length),
        )

    @classmethod
    def build(
        cls,
        members: list[ScreenQuery],
        fingerprint_bits: int = 12,
        seed: int = 0,
        load_factor: float = 1.23,
        max_attempts: int = 100,
    ) -> "StaticXorFilter":
        if not 4 <= fingerprint_bits <= 64:
            raise ValueError("fingerprint_bits must be in [4, 64]")
        if load_factor < 1.05:
            raise ValueError("Xor capacity factor must be at least 1.05")
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        items = validate_members(members)
        tokens = list(dict.fromkeys(item.token for item in items))
        n_items = len(tokens)
        block_length = max(1, math.ceil(load_factor * n_items / cls.arity))
        capacity = cls.arity * block_length
        mask64 = 0xFFFFFFFFFFFFFFFF
        retry_step = 0x9E3779B97F4A7C15

        for attempt in range(max_attempts):
            candidate_seed = (seed + attempt * retry_step) & mask64
            hashes = [
                hash64(token, candidate_seed, b"xor-static-v1") for token in tokens
            ]
            degree = [0] * capacity
            edge_xor = [0] * capacity
            for edge, hashed in enumerate(hashes):
                for position in cls._positions_for_hash(hashed, block_length):
                    degree[position] += 1
                    edge_xor[position] ^= edge

            singleton = deque(index for index, count in enumerate(degree) if count == 1)
            peel_order: list[tuple[int, int]] = []
            while singleton:
                position = singleton.popleft()
                if degree[position] != 1:
                    continue
                edge = edge_xor[position]
                peel_order.append((position, edge))
                for neighbor in cls._positions_for_hash(hashes[edge], block_length):
                    degree[neighbor] -= 1
                    edge_xor[neighbor] ^= edge
                    if degree[neighbor] == 1:
                        singleton.append(neighbor)

            if len(peel_order) != n_items:
                continue

            packed = PackedArray(capacity, fingerprint_bits)
            fingerprint_mask = (1 << fingerprint_bits) - 1
            for position, edge in reversed(peel_order):
                hashed = hashes[edge]
                value = (hashed ^ (hashed >> 32)) & fingerprint_mask
                for neighbor in cls._positions_for_hash(hashed, block_length):
                    if neighbor != position:
                        value ^= packed.get(neighbor)
                packed.set(position, value)
            return cls(
                packed,
                n_items=n_items,
                block_length=block_length,
                fingerprint_bits=fingerprint_bits,
                seed=candidate_seed,
                build_attempts=attempt + 1,
            )

        raise XorFilterBuildError(
            f"could not peel {n_items} keys after {max_attempts} deterministic seeds"
        )

    def query(self, item: ScreenQuery) -> QueryResult:
        hashed = hash64(item.token, self.seed, b"xor-static-v1")
        candidate = (hashed ^ (hashed >> 32)) & self._fingerprint_mask
        actual = 0
        for position in self._positions_for_hash(hashed, self.block_length):
            actual ^= self._fingerprints.get(position)
        return QueryResult(actual == candidate, probes=self.arity, comparisons=1)

    def add(self, item: ScreenQuery) -> None:
        raise TypeError("StaticXorFilter is immutable; rebuild for a new epoch")

    def delete(self, item: ScreenQuery) -> None:
        raise TypeError("StaticXorFilter is immutable; rebuild for a new epoch")

    def memory_report(self) -> MemoryReport:
        metadata = struct.pack(
            ">8sHQQQHHQI16s",
            b"RTXORv1\x00",
            1,
            self.n_items,
            self.capacity,
            self.block_length,
            self.fingerprint_bits,
            self.arity,
            self.seed,
            self.build_attempts,
            b"b2-xor3-v1".ljust(16, b"\x00"),
        )
        return MemoryReport(
            payload_bytes=self._fingerprints.nbytes,
            metadata_bytes=len(metadata),
            alignment_bytes=alignment_padding(len(metadata))
            + alignment_padding(self._fingerprints.nbytes),
        )

    def parameters(self) -> dict[str, int | float | str]:
        return {
            "m_bits": self.capacity * self.fingerprint_bits,
            "n_items": self.n_items,
            "k_hashes": self.arity,
            "fingerprint_bits": self.fingerprint_bits,
            "capacity": self.capacity,
            "capacity_factor": self.capacity / self.n_items,
            "hash_seed": self.seed,
            "build_attempts": self.build_attempts,
            "hash_scheme": "BLAKE2b-64, three disjoint segments",
        }
