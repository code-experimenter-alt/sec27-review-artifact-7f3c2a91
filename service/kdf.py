from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Mapping

from dataplane.types import BackendResultKind, TypedBackendResult

from .types import ServiceAccount


@dataclass(frozen=True)
class KdfProfile:
    name: str
    algorithm: str
    parameters: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.algorithm not in {"pbkdf2_sha256", "argon2id"}:
            raise ValueError("algorithm must be pbkdf2_sha256 or argon2id")
        if not self.name:
            raise ValueError("profile name must be non-empty")
        if self.algorithm == "pbkdf2_sha256":
            if int(self.parameters.get("iterations", 0)) < 1:
                raise ValueError("PBKDF2 iterations must be positive")
            if int(self.parameters.get("dklen", 0)) < 16:
                raise ValueError("PBKDF2 dklen must be at least 16 bytes")
        else:
            for field in ("time_cost", "memory_cost_kib", "parallelism"):
                if int(self.parameters.get(field, 0)) < 1:
                    raise ValueError(f"Argon2id {field} must be positive")
            if int(self.parameters.get("hash_len", 0)) < 16:
                raise ValueError("Argon2id hash_len must be at least 16 bytes")

    @classmethod
    def from_mapping(cls, name: str, value: Mapping[str, Any]) -> "KdfProfile":
        if not isinstance(value, Mapping):
            raise TypeError("verifier profile must be a mapping")
        algorithm = str(value.get("algorithm", ""))
        parameters = {key: item for key, item in value.items() if key != "algorithm"}
        return cls(name=name, algorithm=algorithm, parameters=parameters)

    def implementation_metadata(self) -> dict[str, Any]:
        if self.algorithm == "pbkdf2_sha256":
            return {
                "algorithm": self.algorithm,
                "implementation": "hashlib.pbkdf2_hmac",
                "library": "Python/OpenSSL",
                "parameters": dict(self.parameters),
                "actual_kdf_execution": True,
            }
        try:
            version = metadata.version("argon2-cffi")
        except metadata.PackageNotFoundError:
            version = None
        return {
            "algorithm": self.algorithm,
            "implementation": "argon2.low_level.hash_secret_raw(Type.ID)",
            "library": "argon2-cffi",
            "library_version": version,
            "parameters": dict(self.parameters),
            "actual_kdf_execution": True,
        }


def derive_kdf(profile: KdfProfile, password: bytes, salt: bytes) -> bytes:
    if not isinstance(password, bytes) or not isinstance(salt, bytes):
        raise TypeError("KDF password and salt must be exact bytes")
    if profile.algorithm == "pbkdf2_sha256":
        return hashlib.pbkdf2_hmac(
            "sha256",
            password,
            salt,
            int(profile.parameters["iterations"]),
            dklen=int(profile.parameters["dklen"]),
        )

    try:
        from argon2.low_level import ARGON2_VERSION, Type, hash_secret_raw
    except ImportError as exc:
        raise RuntimeError(
            "Argon2id profile is BLOCKED: install the declared argon2-cffi dependency"
        ) from exc
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=int(profile.parameters["time_cost"]),
        memory_cost=int(profile.parameters["memory_cost_kib"]),
        parallelism=int(profile.parameters["parallelism"]),
        hash_len=int(profile.parameters["hash_len"]),
        type=Type.ID,
        version=ARGON2_VERSION,
    )


class KdfBackend:
    """Read-only typed verifier whose request path executes the configured KDF."""

    def __init__(self, profile: KdfProfile, dummy_salt: bytes) -> None:
        if len(dummy_salt) < 8:
            raise ValueError("dummy salt must contain at least eight bytes")
        self.profile = profile
        self._records: dict[str, tuple[ServiceAccount, bytes]] = {}
        self._dummy_salt = bytes(dummy_salt)
        self._dummy_verifier = derive_kdf(profile, b"dummy-password", self._dummy_salt)

    def enroll(self, account: ServiceAccount, password: bytes) -> None:
        key = account.username.casefold()
        verifier = derive_kdf(self.profile, password, account.salt)
        prior = self._records.get(key)
        candidate = (account, verifier)
        if prior is not None and prior != candidate:
            raise ValueError("service account enrollment is immutable")
        self._records[key] = candidate

    def verify(
        self,
        account: ServiceAccount | None,
        username: str,
        password: bytes,
    ) -> TypedBackendResult:
        if account is None:
            candidate = derive_kdf(self.profile, password, self._dummy_salt)
            hmac.compare_digest(candidate, self._dummy_verifier)
            return TypedBackendResult(
                kind=BackendResultKind.NO_ACCOUNT,
                expected_version=None,
                checked_version=None,
                authenticated_internal_result=True,
                detail="dummy namespace verifier path",
            )

        stored_account, verifier = self._records[username.casefold()]
        candidate = derive_kdf(self.profile, password, stored_account.salt)
        matched = hmac.compare_digest(candidate, verifier)
        return TypedBackendResult(
            kind=(
                BackendResultKind.MATCH
                if matched
                else BackendResultKind.CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS
            ),
            expected_version=stored_account.credential_set_version,
            checked_version=stored_account.credential_set_version,
            checked_account_id=stored_account.account_id,
            checked_account_generation=stored_account.account_generation,
            checked_authenticator_ids=frozenset({"password"}),
            matched_authenticator_id="password" if matched else None,
            authenticated_internal_result=True,
        )
