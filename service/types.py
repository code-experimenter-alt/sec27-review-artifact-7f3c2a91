from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from dataplane.types import DirectoryStatus, DirectoryView
from reference.filters import CredentialInput, ScreenQuery, TokenCodec


class TrafficClass(str, Enum):
    LEGITIMATE = "legitimate"
    INVALID = "invalid"
    UNKNOWN = "unknown_username"
    CORRECT_PASSWORD_ATTACK = "correct_password_attack"


class ServiceRoute(str, Enum):
    BACKEND_MATCH = "backend_match"
    BACKEND_MISMATCH = "backend_mismatch"
    UNKNOWN_BACKEND_REJECT = "unknown_backend_reject"
    POSITIVE_SCREEN_REJECT = "positive_screen_reject"
    NEGATIVE_CACHE_REJECT = "negative_cache_reject"
    BACKEND_QUEUE_DROP = "backend_queue_drop"
    FRONTEND_QUEUE_DROP = "frontend_queue_drop"
    CONNECTION_DROP = "connection_drop"
    SINGLEFLIGHT_OVERFLOW = "singleflight_overflow"
    BACKEND_FAILURE = "backend_failure"
    SHUTDOWN_CANCELLED = "shutdown_cancelled"


@dataclass(frozen=True)
class ServiceAccount:
    account_index: int
    username: str
    account_id: str
    account_generation: int
    credential_set_version: int
    salt: bytes
    directory_epoch: int = 1
    encoding_version: int = 1
    retry_class: str = "default"

    def __post_init__(self) -> None:
        if self.account_index < 0:
            raise ValueError("account_index must be non-negative")
        if not self.username or not self.account_id:
            raise ValueError("username and account_id must be non-empty")
        if self.account_generation < 1 or self.credential_set_version < 1:
            raise ValueError("generation and version must be positive")
        if len(self.salt) < 8:
            raise ValueError("service salts must contain at least eight bytes")

    @property
    def view(self) -> DirectoryView:
        return DirectoryView(
            username=self.username,
            status=DirectoryStatus.PRESENT,
            account_id=self.account_id,
            account_generation=self.account_generation,
            credential_set_version=self.credential_set_version,
            salt=self.salt,
            encoding_version=self.encoding_version,
            retry_class=self.retry_class,
            active_authenticator_ids=frozenset({"password"}),
            directory_epoch=self.directory_epoch,
        )

    def screen_query(self, codec: TokenCodec, password: bytes) -> ScreenQuery:
        return codec.token(
            CredentialInput(
                account_index=self.account_index,
                account_id=self.account_id.encode("utf-8"),
                account_generation=self.account_generation,
                credential_set_version=self.credential_set_version,
                password=password,
                salt=self.salt,
            )
        )


@dataclass(frozen=True)
class AuthRequest:
    request_id: int
    username: str
    password: bytes
    traffic_class: TrafficClass
    tuple_id: str

    def __post_init__(self) -> None:
        if self.request_id < 0:
            raise ValueError("request_id must be non-negative")
        if not self.username:
            raise ValueError("username must be non-empty")
        if not isinstance(self.password, bytes):
            raise TypeError("password must be exact bytes")
        if not self.tuple_id:
            raise ValueError("tuple_id must be non-empty")

    @property
    def is_legitimate(self) -> bool:
        return self.traffic_class is TrafficClass.LEGITIMATE

    @property
    def is_invalid(self) -> bool:
        return self.traffic_class in {TrafficClass.INVALID, TrafficClass.UNKNOWN}


@dataclass(frozen=True)
class ServiceMethod:
    name: str
    use_positive_screen: bool
    cache_policy: str | None
    use_singleflight: bool
    claim_scope: str = "mechanism_only"
    baseline_role: str = "candidate"

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("method name must be non-empty")
        if not self.claim_scope or not self.baseline_role:
            raise ValueError("method claim_scope and baseline_role must be non-empty")
        if self.cache_policy not in {None, "lru", "tinylfu"}:
            raise ValueError("cache_policy must be null, lru, or tinylfu")
        if self.cache_policy is not None and not self.use_positive_screen:
            raise ValueError("negative caching requires a positive screen")
        if self.use_singleflight and self.cache_policy is None:
            raise ValueError("singleflight is only enabled with an exact negative cache")


@dataclass(frozen=True)
class ServiceLimits:
    frontend_workers: int
    backend_workers: int
    frontend_queue_capacity: int
    backend_queue_capacity: int
    max_connections: int
    max_padding_timers: int
    max_waiters_per_key: int
    max_waiters_global: int
    failure_padding_seconds: float
    request_timeout_seconds: float
    cache_capacity: int
    cache_ttl_seconds: float
    cache_max_entries_per_account: int | None = None

    def __post_init__(self) -> None:
        positive = (
            "frontend_workers",
            "backend_workers",
            "frontend_queue_capacity",
            "backend_queue_capacity",
            "max_connections",
            "max_padding_timers",
            "cache_capacity",
        )
        for field in positive:
            if getattr(self, field) < 1:
                raise ValueError(f"{field} must be positive")
        if self.max_waiters_per_key < 0 or self.max_waiters_global < 0:
            raise ValueError("waiter caps must be non-negative")
        if self.failure_padding_seconds < 0:
            raise ValueError("failure padding must be non-negative")
        if self.request_timeout_seconds <= 0 or self.cache_ttl_seconds <= 0:
            raise ValueError("request timeout and cache TTL must be positive")
        if (
            self.cache_max_entries_per_account is not None
            and self.cache_max_entries_per_account < 1
        ):
            raise ValueError("per-account cache quota must be positive")
