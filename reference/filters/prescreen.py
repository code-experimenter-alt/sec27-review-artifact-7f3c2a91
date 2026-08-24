"""Canonical indexed-directory-to-screen-decision frontend path."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .common import (
    CredentialInput,
    QueryResult,
    ScreeningFilter,
    TokenCodec,
)


@dataclass(frozen=True, slots=True)
class DirectoryRecord:
    """Credential-version material retrieved by an already resolved account index."""

    account_id: bytes
    account_generation: int
    credential_set_version: int
    salt: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.account_id, bytes) or not self.account_id:
            raise TypeError("account_id must be non-empty bytes")
        if not isinstance(self.salt, bytes):
            raise TypeError("salt must be bytes")
        for name in ("account_generation", "credential_set_version"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError(f"{name} must fit uint64")


@dataclass(frozen=True, slots=True)
class LoginAttempt:
    """Pre-resolved account index and exact submitted password bytes."""

    account_index: int
    password: bytes

    def __post_init__(self) -> None:
        if type(self.account_index) is not int or self.account_index < 0:
            raise ValueError("account_index must be a non-negative integer")
        if not isinstance(self.password, bytes):
            raise TypeError("password must be exact bytes")


class CanonicalPrescreenPath:
    """Execute the frozen actual-front interval from directory read to decision."""

    __slots__ = ("codec", "directory", "filter_object")

    def __init__(
        self,
        directory: Sequence[DirectoryRecord],
        codec: TokenCodec,
        filter_object: ScreeningFilter,
    ) -> None:
        if not directory:
            raise ValueError("directory must contain at least one record")
        self.directory = directory
        self.codec = codec
        self.filter_object = filter_object

    def credential(self, attempt: LoginAttempt) -> CredentialInput:
        """Materialize the credential after the timed directory record lookup."""

        record = self.directory[attempt.account_index]
        return CredentialInput(
            account_index=attempt.account_index,
            account_id=record.account_id,
            account_generation=record.account_generation,
            credential_set_version=record.credential_set_version,
            password=attempt.password,
            salt=record.salt,
        )

    def query(self, attempt: LoginAttempt) -> QueryResult:
        """Timeable adapter: directory lookup, credential/token work, then query."""

        return self.filter_object.query(self.codec.token(self.credential(attempt)))
