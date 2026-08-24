"""Exact and truncated per-account PRF tag baselines."""

from __future__ import annotations

import hmac
import struct

from .common import (
    TOKEN_ENCODING_VERSION,
    MemoryReport,
    PackedArray,
    QueryResult,
    ScreenQuery,
    alignment_padding,
    token_as_int,
    validate_members,
)

SUPPORTED_TAG_BITS = (8, 12, 16, 20, 24, 32, 64, 128)


class PerAccountTagFilter:
    """One fixed-width PRF fingerprint in each account's directory slot."""

    def __init__(self, tags: PackedArray, tag_bits: int) -> None:
        self._tags = tags
        self.tag_bits = tag_bits
        self.n_items = tags.count
        self.method = "exact_tag_128" if tag_bits == 128 else f"truncated_tag_{tag_bits}"

    @classmethod
    def build(
        cls, members: list[ScreenQuery], tag_bits: int = 128
    ) -> "PerAccountTagFilter":
        if tag_bits not in SUPPORTED_TAG_BITS:
            raise ValueError(f"tag_bits must be one of {SUPPORTED_TAG_BITS}")
        items = validate_members(members)
        tags = PackedArray(len(items), tag_bits)
        seen = bytearray(len(items))
        for item in items:
            if item.account_index >= len(items):
                raise ValueError("account indices must be contiguous in [0, n)")
            if seen[item.account_index]:
                raise ValueError("each account slot must have exactly one member")
            seen[item.account_index] = 1
            tags.set(item.account_index, token_as_int(item.token, tag_bits))
        if not all(seen):
            raise ValueError("account indices must be contiguous in [0, n)")
        return cls(tags, tag_bits)

    def query(self, item: ScreenQuery) -> QueryResult:
        if item.account_index >= self.n_items:
            return QueryResult(False, probes=1, comparisons=0)
        expected = self._tags.get(item.account_index)
        candidate = token_as_int(item.token, self.tag_bits)
        encoded_bytes = (self.tag_bits + 7) // 8
        positive = hmac.compare_digest(
            expected.to_bytes(encoded_bytes, "big"),
            candidate.to_bytes(encoded_bytes, "big"),
        )
        return QueryResult(positive, probes=1, comparisons=1)

    def memory_report(self) -> MemoryReport:
        metadata = struct.pack(
            ">8sHQQHH",
            b"RTTAGv1\x00",
            1,
            self.n_items,
            self.n_items * self.tag_bits,
            self.tag_bits,
            TOKEN_ENCODING_VERSION,
        ).ljust(32, b"\x00")
        return MemoryReport(
            payload_bytes=self._tags.nbytes,
            metadata_bytes=len(metadata),
            alignment_bytes=alignment_padding(self._tags.nbytes),
        )

    def parameters(self) -> dict[str, int | str | None]:
        return {
            "m_bits": self.n_items * self.tag_bits,
            "n_items": self.n_items,
            "k_hashes": None,
            "tag_bits": self.tag_bits,
            "hash_scheme": "HMAC-SHA256/128 common token; network-order prefix",
        }
