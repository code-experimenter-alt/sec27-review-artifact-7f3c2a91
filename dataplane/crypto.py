from __future__ import annotations

import hashlib
import hmac
from typing import Union

Password = Union[str, bytes, bytearray, memoryview]


def exact_password_bytes(password: Password) -> bytes:
    """Encode strings as UTF-8 without normalization; preserve byte inputs exactly."""

    if isinstance(password, str):
        return password.encode("utf-8")
    if isinstance(password, bytes):
        return password
    if isinstance(password, (bytearray, memoryview)):
        return bytes(password)
    raise TypeError("password must be str or bytes-like")


def encode_fields(*fields: object) -> bytes:
    """Length-prefix fields so tuple boundaries cannot be confused."""

    encoded = bytearray()
    for field in fields:
        if isinstance(field, bytes):
            value = field
        elif isinstance(field, str):
            value = field.encode("utf-8")
        elif isinstance(field, int):
            if field < 0:
                raise ValueError("integer fields must be non-negative")
            width = max(1, (field.bit_length() + 7) // 8)
            value = field.to_bytes(width, "big")
        else:
            raise TypeError(f"unsupported encoded field: {type(field)!r}")
        encoded.extend(len(value).to_bytes(4, "big"))
        encoded.extend(value)
    return bytes(encoded)


def positive_token(
    key: bytes,
    account_id: str,
    account_generation: int,
    credential_set_version: int,
    encoding_version: int,
    password: Password,
    salt: bytes,
) -> bytes:
    prehash_input = encode_fields(
        "R-TRAPS/PREHASH/v1",
        salt,
        exact_password_bytes(password),
    )
    prehash = hashlib.sha256(prehash_input).digest()
    message = encode_fields(
        "R-TRAPS/POSITIVE/v1",
        account_id,
        account_generation,
        credential_set_version,
        encoding_version,
        prehash,
    )
    return hmac.new(key, message, hashlib.sha256).digest()


def negative_digest(
    key: bytes,
    account_id: str,
    account_generation: int,
    credential_set_version: int,
    token: bytes,
) -> bytes:
    message = encode_fields(
        "R-TRAPS/NEGATIVE/v1",
        account_id,
        account_generation,
        credential_set_version,
        token,
    )
    return hmac.new(key, message, hashlib.sha256).digest()
