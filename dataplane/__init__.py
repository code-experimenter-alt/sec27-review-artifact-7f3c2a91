"""Executable R-TRAPS data-plane reference implementation.

Rust is preferred by the project contract, but this host does not provide a
Rust toolchain.  This package intentionally uses only the Python standard
library so the safety state machine remains executable and testable.
"""

from .backend import InMemoryBackend
from .directory import Directory
from .engine import AuthDataPlane
from .negative_cache import (
    LruPolicy,
    NegativeCache,
    NegativeKeyDeriver,
    TinyLfuPolicy,
)
from .padding import AsyncResponsePadder
from .positive import PositiveScreen
from .singleflight import Singleflight
from .types import (
    AuthDecision,
    AuthRoute,
    BackendResultKind,
    DirectoryStatus,
    DirectoryView,
    PositiveDecision,
    PositiveDisposition,
    RepresentationCertificate,
    RepresentationSource,
    TypedBackendResult,
)

__all__ = [
    "AuthDataPlane",
    "AuthDecision",
    "AuthRoute",
    "AsyncResponsePadder",
    "BackendResultKind",
    "Directory",
    "DirectoryStatus",
    "DirectoryView",
    "InMemoryBackend",
    "LruPolicy",
    "NegativeCache",
    "NegativeKeyDeriver",
    "PositiveDecision",
    "PositiveDisposition",
    "PositiveScreen",
    "RepresentationCertificate",
    "RepresentationSource",
    "Singleflight",
    "TinyLfuPolicy",
    "TypedBackendResult",
]
