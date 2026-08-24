from __future__ import annotations

import time
from collections import Counter
from concurrent.futures import Future
from threading import RLock

from .backend import InMemoryBackend
from .crypto import Password
from .directory import Directory
from .negative_cache import NegativeCache, NegativeKeyDeriver
from .padding import AsyncResponsePadder
from .positive import PositiveScreen
from .singleflight import Singleflight
from .types import (
    AuthDecision,
    AuthRoute,
    BackendResultKind,
    DirectoryStatus,
    PositiveDisposition,
)


class AuthDataPlane:
    """Minimal end-to-end screening/verification state machine."""

    _BACKEND_UNCERTAINTY_KINDS = {
        BackendResultKind.NO_ACCOUNT,
        BackendResultKind.TRANSIENT_FAILURE,
        BackendResultKind.VERSION_MISMATCH,
        BackendResultKind.PARTIAL_AUTHENTICATOR_FAILURE,
    }

    def __init__(
        self,
        directory: Directory,
        positive_screen: PositiveScreen,
        negative_keys: NegativeKeyDeriver,
        negative_cache: NegativeCache,
        singleflight: Singleflight,
        backend: InMemoryBackend,
        negative_ttl_seconds: float = 60.0,
        response_padder: AsyncResponsePadder[AuthDecision] | None = None,
    ) -> None:
        self.directory = directory
        self.positive_screen = positive_screen
        self.negative_keys = negative_keys
        self.negative_cache = negative_cache
        self.singleflight = singleflight
        self.backend = backend
        self.negative_ttl_seconds = negative_ttl_seconds
        self.response_padder = response_padder
        self._metrics: Counter[str] = Counter()
        self._metrics_lock = RLock()

    def _count(self, name: str) -> None:
        with self._metrics_lock:
            self._metrics[name] += 1

    def authenticate(
        self,
        edge_id: str,
        username: str,
        password: Password,
    ) -> AuthDecision:
        view = self.directory.lookup(username, edge_id=edge_id)
        backend_username = view.backend_username
        if view.status is not DirectoryStatus.PRESENT:
            self._count(f"fail_open_{view.status.value.lower()}")
            backend_result = self.backend.verify(backend_username, password, expected_version=None)
            if backend_result.kind is BackendResultKind.MATCH:
                backend_result = self.backend.finalize_match(backend_username, backend_result)
            return AuthDecision(
                route=AuthRoute.FAIL_OPEN_BACKEND,
                accepted=backend_result.kind is BackendResultKind.MATCH,
                reason=f"{view.status.value} directory state forwarded to backend",
                directory_view=view,
                backend_result=backend_result,
            )

        token = self.positive_screen.credential_token(view, password)
        negative_key = self.negative_keys.derive(view, token)
        cache_result = self.negative_cache.lookup(negative_key, expected_view=view)
        if cache_result.hit:
            self._count("negative_cache_reject")
            return AuthDecision(
                route=AuthRoute.NEGATIVE_CACHE_REJECT,
                accepted=False,
                reason="backend-confirmed exact negative cache hit",
                directory_view=view,
            )

        positive = self.positive_screen.query(
            view,
            password,
            edge_id=edge_id,
            token=token,
        )
        if positive.disposition is PositiveDisposition.NEGATIVE:
            self._count("positive_screen_reject")
            return AuthDecision(
                route=AuthRoute.POSITIVE_SCREEN_REJECT,
                accepted=False,
                reason=positive.reason,
                directory_view=view,
                positive_decision=positive,
            )

        comparison = self.singleflight.execute(
            negative_key,
            lambda: self.backend.verify(
                backend_username,
                password,
                expected_version=view.credential_set_version,
            ),
            expected_version=view.credential_set_version,
        )
        if comparison.kind is BackendResultKind.VERSION_MISMATCH:
            # The directory/version may have advanced after this request took
            # its screenable snapshot.  A version-specific denial is therefore
            # not an authentication result.  Retry through the backend's
            # fail-open transition set and never admit a negative cache entry
            # from this uncertain path.
            refreshed_view = self.directory.lookup(username, edge_id=edge_id)
            refreshed_username = refreshed_view.backend_username
            retried = self.backend.verify(
                refreshed_username,
                password,
                expected_version=None,
            )
            result = self.backend.finalize_match(refreshed_username, retried)
            self._count("version_mismatch_fail_open_retry")
            return AuthDecision(
                route=AuthRoute.FAIL_OPEN_BACKEND,
                accepted=result.kind is BackendResultKind.MATCH,
                reason="credential version changed during screening; retried fail open",
                directory_view=refreshed_view,
                positive_decision=positive,
                backend_result=result,
            )
        if comparison.is_exact_mismatch_for(view):
            assert positive.region is not None
            if self.negative_cache.insert(
                negative_key,
                view,
                positive.region,
                self.negative_ttl_seconds,
            ):
                self._count("negative_insert")
        else:
            self._count("negative_insert_ineligible")

        result = self.backend.finalize_match(backend_username, comparison)
        screening_uncertain = positive.disposition is PositiveDisposition.FAIL_OPEN
        backend_uncertain = result.kind in self._BACKEND_UNCERTAINTY_KINDS
        fail_open = screening_uncertain or backend_uncertain
        route = (
            AuthRoute.FAIL_OPEN_BACKEND
            if fail_open
            else (
                AuthRoute.BACKEND_MATCH
                if result.kind is BackendResultKind.MATCH
                else AuthRoute.BACKEND_DENY
            )
        )
        if backend_uncertain:
            self._count("backend_uncertainty_fail_open")
        self._count(route.value.lower())
        return AuthDecision(
            route=route,
            accepted=result.kind is BackendResultKind.MATCH,
            reason=(
                positive.reason
                if screening_uncertain
                else (
                    "backend returned an uncertain typed result after forwarding"
                    if backend_uncertain
                    else "positive token forwarded for typed backend verification"
                )
            ),
            directory_view=view,
            positive_decision=positive,
            backend_result=result,
        )

    def metrics_snapshot(self) -> dict[str, int]:
        with self._metrics_lock:
            return dict(self._metrics)

    def authenticate_padded(
        self,
        edge_id: str,
        username: str,
        password: Password,
    ) -> Future[AuthDecision]:
        """Return a future whose remaining response padding is non-blocking."""

        started_at = time.perf_counter()
        decision = self.authenticate(edge_id, username, password)
        if self.response_padder is not None:
            return self.response_padder.defer(decision, started_at=started_at)
        future: Future[AuthDecision] = Future()
        future.set_result(decision)
        return future
