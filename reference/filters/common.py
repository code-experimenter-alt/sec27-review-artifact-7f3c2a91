"""Shared token, query, hashing, and memory semantics for filter baselines."""

from __future__ import annotations

import hashlib
import hmac
import math
import struct
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Protocol, runtime_checkable

TOKEN_BYTES = 16
TOKEN_ENCODING_VERSION = 1
_TOKEN_DOMAIN = b"RTRAPS-POS-v1\x00"
_PREHASH_DOMAIN = b"RTRAPS-PREHASH-v1\x00"


def _length_prefixed(value: bytes) -> bytes:
    if len(value) > 0xFFFFFFFF:
        raise ValueError("encoded field is too large")
    return struct.pack(">I", len(value)) + value


@dataclass(frozen=True)
class CredentialInput:
    """Inputs whose exact bytes define a credential-version equality token."""

    account_index: int
    account_id: bytes
    account_generation: int
    credential_set_version: int
    password: bytes
    salt: bytes

    def __post_init__(self) -> None:
        if self.account_index < 0:
            raise ValueError("account_index must be non-negative")
        if not isinstance(self.account_id, bytes) or not self.account_id:
            raise TypeError("account_id must be non-empty bytes")
        if not isinstance(self.password, bytes):
            raise TypeError("password must be exact bytes")
        if not isinstance(self.salt, bytes):
            raise TypeError("salt must be bytes")
        for name in ("account_generation", "credential_set_version"):
            value = getattr(self, name)
            if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"{name} must fit uint64")


@dataclass(frozen=True)
class ScreenQuery:
    """Canonical input to every baseline after the common PRF/prehash path."""

    account_index: int
    token: bytes

    def __post_init__(self) -> None:
        if self.account_index < 0:
            raise ValueError("account_index must be non-negative")
        if not isinstance(self.token, bytes) or len(self.token) != TOKEN_BYTES:
            raise ValueError(f"token must be exactly {TOKEN_BYTES} bytes")


@dataclass(frozen=True)
class QueryResult:
    """True means possibly represented and therefore forwarded to the backend."""

    positive: bool
    probes: int
    comparisons: int = 0


@dataclass(frozen=True)
class MemoryReport:
    """Compact deployable state, including fixed metadata and alignment."""

    payload_bytes: int
    metadata_bytes: int
    alignment_bytes: int = 0

    @property
    def total_bytes(self) -> int:
        return self.payload_bytes + self.metadata_bytes + self.alignment_bytes


class TokenCodec:
    """The sole canonical 128-bit PRF token implementation used by baselines."""

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("PRF key must contain at least 128 bits")
        self._key = key

    @staticmethod
    def prehash(password: bytes, salt: bytes) -> bytes:
        if not isinstance(password, bytes) or not isinstance(salt, bytes):
            raise TypeError("password and salt must be exact bytes")
        payload = _PREHASH_DOMAIN + _length_prefixed(salt) + _length_prefixed(password)
        return hashlib.sha256(payload).digest()

    def encode(self, credential: CredentialInput) -> bytes:
        prehash = self.prehash(credential.password, credential.salt)
        return b"".join(
            (
                _TOKEN_DOMAIN,
                struct.pack(">H", TOKEN_ENCODING_VERSION),
                _length_prefixed(credential.account_id),
                struct.pack(">Q", credential.account_generation),
                struct.pack(">Q", credential.credential_set_version),
                prehash,
            )
        )

    def token(self, credential: CredentialInput) -> ScreenQuery:
        digest = hmac.new(self._key, self.encode(credential), hashlib.sha256).digest()
        return ScreenQuery(credential.account_index, digest[:TOKEN_BYTES])


@runtime_checkable
class ScreeningFilter(Protocol):
    """Uniform one-sided screening interface."""

    method: str
    n_items: int

    def query(self, item: ScreenQuery) -> QueryResult:
        ...

    def memory_report(self) -> MemoryReport:
        ...


class PackedArray:
    """Fixed-width integers packed without a Python object per entry."""

    __slots__ = ("count", "width", "_mask", "data")

    def __init__(self, count: int, width: int) -> None:
        if count < 0:
            raise ValueError("count must be non-negative")
        if not 1 <= width <= 128:
            raise ValueError("width must be in [1, 128]")
        self.count = count
        self.width = width
        self._mask = (1 << width) - 1
        self.data = bytearray((count * width + 7) // 8)

    @property
    def nbytes(self) -> int:
        return len(self.data)

    def _window(self, index: int) -> tuple[int, int, int]:
        if not 0 <= index < self.count:
            raise IndexError(index)
        bit_offset = index * self.width
        byte_offset, shift = divmod(bit_offset, 8)
        byte_count = (shift + self.width + 7) // 8
        return byte_offset, shift, byte_count

    def get(self, index: int) -> int:
        byte_offset, shift, byte_count = self._window(index)
        raw = int.from_bytes(
            self.data[byte_offset : byte_offset + byte_count], "little"
        )
        return (raw >> shift) & self._mask

    def set(self, index: int, value: int) -> None:
        if not 0 <= value <= self._mask:
            raise ValueError(f"value does not fit {self.width} bits")
        byte_offset, shift, byte_count = self._window(index)
        raw = int.from_bytes(
            self.data[byte_offset : byte_offset + byte_count], "little"
        )
        field_mask = self._mask << shift
        raw = (raw & ~field_mask) | (value << shift)
        self.data[byte_offset : byte_offset + byte_count] = raw.to_bytes(
            byte_count, "little"
        )


def token_as_int(token: bytes, width: int) -> int:
    """Take the first ``width`` PRF bits in network-bit order."""

    if len(token) != TOKEN_BYTES:
        raise ValueError(f"token must be exactly {TOKEN_BYTES} bytes")
    if not 1 <= width <= TOKEN_BYTES * 8:
        raise ValueError("width must be in [1, 128]")
    return int.from_bytes(token, "big") >> (TOKEN_BYTES * 8 - width)


def hash128(token: bytes, seed: int, domain: bytes) -> tuple[int, int]:
    if len(token) != TOKEN_BYTES:
        raise ValueError(f"token must be exactly {TOKEN_BYTES} bytes")
    if not 0 <= seed <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("seed must fit uint64")
    person = domain[:16].ljust(16, b"\x00")
    digest = hashlib.blake2b(
        token,
        digest_size=16,
        key=struct.pack(">Q", seed),
        person=person,
    ).digest()
    return struct.unpack(">QQ", digest)


def hash64(token: bytes, seed: int, domain: bytes) -> int:
    return hash128(token, seed, domain)[0]


def reduce_u64(value: int, modulus: int) -> int:
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    return (value * modulus) >> 64


def rotate_left_64(value: int, shift: int) -> int:
    shift %= 64
    mask = 0xFFFFFFFFFFFFFFFF
    return ((value << shift) & mask) | ((value & mask) >> (64 - shift))


def alignment_padding(payload_bytes: int, alignment: int = 8) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError("alignment must be a positive power of two")
    return (-payload_bytes) % alignment


def deep_sizeof(value: Any) -> int:
    """Measure method-specific Python resident state without double counting."""

    seen: set[int] = set()

    def visit(obj: Any) -> int:
        identity = id(obj)
        if identity in seen:
            return 0
        seen.add(identity)
        size = sys.getsizeof(obj)
        if isinstance(obj, dict):
            size += sum(visit(k) + visit(v) for k, v in obj.items())
        elif isinstance(obj, (list, tuple, set, frozenset)):
            size += sum(visit(item) for item in obj)
        elif hasattr(obj, "__dict__"):
            size += visit(vars(obj))
        elif hasattr(obj, "__slots__"):
            for slot in obj.__slots__:
                if hasattr(obj, slot):
                    size += visit(getattr(obj, slot))
        return size

    return visit(value)


def validate_members(members: Iterable[ScreenQuery]) -> list[ScreenQuery]:
    materialized = list(members)
    if not materialized:
        raise ValueError("at least one represented member is required")
    for item in materialized:
        if not isinstance(item, ScreenQuery):
            raise TypeError("members must be ScreenQuery values")
    return materialized


def ceil_power_of_two(value: int) -> int:
    if value <= 0:
        raise ValueError("value must be positive")
    return 1 << (value - 1).bit_length()


def finite_bloom_fpr(m_bits: int, n_items: int, k_hashes: int) -> float:
    """Finite-m independent-placement Bloom model used by the benchmark."""

    if m_bits <= 0 or n_items < 0 or k_hashes <= 0:
        raise ValueError("invalid Bloom parameters")
    if n_items == 0:
        return 0.0
    if m_bits == 1:
        return 1.0
    unset = math.exp(k_hashes * n_items * math.log1p(-1.0 / m_bits))
    return (1.0 - unset) ** k_hashes


def standard_bloom_fpr(m_bits: int, n_items: int, k_hashes: int) -> float:
    if m_bits <= 0 or n_items < 0 or k_hashes <= 0:
        raise ValueError("invalid Bloom parameters")
    return (-math.expm1(-k_hashes * n_items / m_bits)) ** k_hashes
