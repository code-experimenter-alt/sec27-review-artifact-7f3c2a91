from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Optional


class DirectoryStatus(str, Enum):
    PRESENT = "PRESENT"
    MISSING = "MISSING"
    STALE = "STALE"
    UNCERTAIN = "UNCERTAIN"


@dataclass(frozen=True)
class DirectoryView:
    username: str
    status: DirectoryStatus
    canonical_username: Optional[str] = None
    account_id: Optional[str] = None
    account_generation: Optional[int] = None
    credential_set_version: Optional[int] = None
    salt: bytes = b""
    encoding_version: int = 1
    retry_class: str = "default"
    active_authenticator_ids: FrozenSet[str] = field(default_factory=frozenset)
    directory_epoch: int = 0
    reason: str = ""

    def __post_init__(self) -> None:
        if self.status is DirectoryStatus.PRESENT:
            if not self.account_id:
                raise ValueError("a present directory view requires account_id")
            if self.account_generation is None or self.account_generation < 1:
                raise ValueError("a present directory view requires a positive generation")
            if self.credential_set_version is None or self.credential_set_version < 1:
                raise ValueError("a present directory view requires a positive version")
            if not self.salt:
                raise ValueError("a present directory view requires a salt")
            if not self.active_authenticator_ids:
                raise ValueError("a present directory view requires an authenticator set")
            if self.directory_epoch < 1:
                raise ValueError("a present directory view requires a directory epoch")

    @property
    def can_screen(self) -> bool:
        return self.status is DirectoryStatus.PRESENT

    @property
    def backend_username(self) -> str:
        return self.canonical_username or self.username

    @property
    def scope(self) -> tuple[str, int, int]:
        if not self.can_screen:
            raise ValueError("missing, stale, and uncertain views have no screenable scope")
        assert self.account_id is not None
        assert self.account_generation is not None
        assert self.credential_set_version is not None
        return (
            self.account_id,
            self.account_generation,
            self.credential_set_version,
        )

    @classmethod
    def missing(
        cls,
        username: str,
        reason: str = "directory reports no account",
    ) -> "DirectoryView":
        return cls(username=username, status=DirectoryStatus.MISSING, reason=reason)

    @classmethod
    def uncertain(cls, username: str, reason: str) -> "DirectoryView":
        return cls(username=username, status=DirectoryStatus.UNCERTAIN, reason=reason)


class RepresentationSource(str, Enum):
    POSITIVE_DELTA = "POSITIVE_DELTA"
    COMPACTED_BASE = "COMPACTED_BASE"


@dataclass(frozen=True)
class RepresentationCertificate:
    edge_id: str
    account_id: str
    account_generation: int
    credential_set_version: int
    directory_epoch_watermark: int
    representation_epoch: int
    source: RepresentationSource
    signature: bytes


class PositiveDisposition(str, Enum):
    POSITIVE = "POSITIVE"
    NEGATIVE = "NEGATIVE"
    FAIL_OPEN = "FAIL_OPEN"


@dataclass(frozen=True)
class PositiveDecision:
    disposition: PositiveDisposition
    reason: str
    credential_token: Optional[bytes] = None
    region: Optional[int] = None
    certificate: Optional[RepresentationCertificate] = None


class BackendResultKind(str, Enum):
    MATCH = "MATCH"
    CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS = (
        "CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS"
    )
    # Compatibility name for the shorter interface spelling in Section 6.
    CREDENTIAL_MISMATCH = "CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS"
    MATCH_BUT_POLICY_DENY = "MATCH_BUT_POLICY_DENY"
    NO_ACCOUNT = "NO_ACCOUNT"
    TRANSIENT_FAILURE = "TRANSIENT_FAILURE"
    VERSION_MISMATCH = "VERSION_MISMATCH"
    PARTIAL_AUTHENTICATOR_FAILURE = "PARTIAL_AUTHENTICATOR_FAILURE"
    ACCOUNT_DISABLED_OR_LOCKED = "ACCOUNT_DISABLED_OR_LOCKED"
    MFA_OR_STEP_UP_REQUIRED = "MFA_OR_STEP_UP_REQUIRED"
    PASSWORD_EXPIRED = "PASSWORD_EXPIRED"


@dataclass(frozen=True)
class TypedBackendResult:
    kind: BackendResultKind
    expected_version: Optional[int]
    checked_version: Optional[int]
    checked_account_id: Optional[str] = None
    checked_account_generation: Optional[int] = None
    checked_authenticator_ids: FrozenSet[str] = field(default_factory=frozenset)
    matched_authenticator_id: Optional[str] = None
    authenticated_internal_result: bool = True
    detail: str = ""

    def is_exact_mismatch_for(self, view: DirectoryView) -> bool:
        """Return whether this result may create an exact negative entry."""

        return (
            view.status is DirectoryStatus.PRESENT
            and self.authenticated_internal_result
            and self.kind
            is BackendResultKind.CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS
            and self.expected_version == view.credential_set_version
            and self.checked_version == view.credential_set_version
            and self.checked_account_id == view.account_id
            and self.checked_account_generation == view.account_generation
            and self.checked_authenticator_ids == view.active_authenticator_ids
            and bool(self.checked_authenticator_ids)
        )

    @classmethod
    def transient_failure(
        cls,
        expected_version: Optional[int],
        detail: str,
    ) -> "TypedBackendResult":
        return cls(
            kind=BackendResultKind.TRANSIENT_FAILURE,
            expected_version=expected_version,
            checked_version=None,
            authenticated_internal_result=False,
            detail=detail,
        )


class AuthRoute(str, Enum):
    BACKEND_MATCH = "BACKEND_MATCH"
    BACKEND_DENY = "BACKEND_DENY"
    POSITIVE_SCREEN_REJECT = "POSITIVE_SCREEN_REJECT"
    NEGATIVE_CACHE_REJECT = "NEGATIVE_CACHE_REJECT"
    FAIL_OPEN_BACKEND = "FAIL_OPEN_BACKEND"


@dataclass(frozen=True)
class AuthDecision:
    route: AuthRoute
    accepted: bool
    reason: str
    directory_view: DirectoryView
    positive_decision: Optional[PositiveDecision] = None
    backend_result: Optional[TypedBackendResult] = None

    @property
    def pre_screen_rejected(self) -> bool:
        return self.route in {
            AuthRoute.POSITIVE_SCREEN_REJECT,
            AuthRoute.NEGATIVE_CACHE_REJECT,
        }
