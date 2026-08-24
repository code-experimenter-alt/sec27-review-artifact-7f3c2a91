from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from threading import RLock
from typing import Dict, Mapping, Optional

from .crypto import Password, encode_fields, exact_password_bytes
from .types import BackendResultKind, TypedBackendResult


@dataclass(frozen=True)
class _BackendVersion:
    username: str
    account_id: str
    account_generation: int
    credential_set_version: int
    salt: bytes
    encoding_version: int
    authenticator_verifiers: Mapping[str, bytes]


class InMemoryBackend:
    """Typed verifier backend used by the executable safety reference."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._prepared: Dict[tuple[str, int, int], _BackendVersion] = {}
        self._active: Dict[str, _BackendVersion] = {}
        self._accepted_history: Dict[tuple[str, str, int, int], _BackendVersion] = {}
        self._fail_open_versions: Dict[str, set[tuple[str, int, int]]] = {}
        self._post_match: Dict[str, BackendResultKind] = {}
        self._inject_once: Dict[str, BackendResultKind] = {}
        self.verify_calls = 0

    @staticmethod
    def _key(username: str) -> str:
        return username.casefold()

    @staticmethod
    def _verifier(password: Password, salt: bytes, encoding_version: int) -> bytes:
        return hashlib.sha256(
            encode_fields(
                "R-TRAPS/BACKEND-VERIFIER/v1",
                encoding_version,
                salt,
                exact_password_bytes(password),
            )
        ).digest()

    def prepare_version(
        self,
        username: str,
        account_id: str,
        account_generation: int,
        credential_set_version: int,
        salt: bytes,
        encoding_version: int,
        authenticators: Mapping[str, Password],
    ) -> None:
        if not authenticators:
            raise ValueError("at least one active password authenticator is required")
        version = _BackendVersion(
            username=username,
            account_id=account_id,
            account_generation=account_generation,
            credential_set_version=credential_set_version,
            salt=bytes(salt),
            encoding_version=encoding_version,
            authenticator_verifiers={
                authenticator_id: self._verifier(password, salt, encoding_version)
                for authenticator_id, password in authenticators.items()
            },
        )
        with self._lock:
            key = (account_id, account_generation, credential_set_version)
            prior = self._prepared.get(key)
            if prior is not None and prior != version:
                raise ValueError("prepared version is immutable")
            self._prepared[key] = version

    def activate_version(
        self,
        username: str,
        account_id: str,
        account_generation: int,
        credential_set_version: int,
    ) -> None:
        prepared_key = (account_id, account_generation, credential_set_version)
        username_key = self._key(username)
        with self._lock:
            version = self._prepared.get(prepared_key)
            if version is None:
                raise ValueError("backend verifier was not prepared")
            prior = self._active.get(username_key)
            if prior is not None:
                same_account = (
                    prior.account_id == account_id
                    and prior.account_generation == account_generation
                )
                if same_account and credential_set_version <= prior.credential_set_version:
                    if credential_set_version == prior.credential_set_version and prior == version:
                        return
                    raise ValueError("backend version regression")
                if not same_account and account_generation <= prior.account_generation:
                    raise ValueError("backend username reuse requires a new generation")
            if prior is not None:
                self._accepted_history[
                    (
                        username_key,
                        prior.account_id,
                        prior.account_generation,
                        prior.credential_set_version,
                    )
                ] = prior
            self._active[username_key] = version
            self._accepted_history[
                (
                    username_key,
                    version.account_id,
                    version.account_generation,
                    version.credential_set_version,
                )
            ] = version
            transition_versions = {(account_id, account_generation, credential_set_version)}
            if prior is not None and (
                prior.account_id == account_id
                and prior.account_generation == account_generation
            ):
                transition_versions.add(
                    (
                        prior.account_id,
                        prior.account_generation,
                        prior.credential_set_version,
                    )
                )
            self._fail_open_versions[username_key] = transition_versions

    def commit_directory_version(
        self,
        username: str,
        account_id: str,
        account_generation: int,
        credential_set_version: int,
    ) -> None:
        """End the backend-before-directory dual-verification window."""

        username_key = self._key(username)
        with self._lock:
            active = self._active.get(username_key)
            if active is None or (
                active.account_id,
                active.account_generation,
                active.credential_set_version,
            ) != (account_id, account_generation, credential_set_version):
                raise ValueError("cannot commit a non-active backend version")
            self._fail_open_versions[username_key] = {
                (account_id, account_generation, credential_set_version)
            }
            stale_history = [
                key
                for key in self._accepted_history
                if key[0] == username_key
                and key[1] == account_id
                and key[2] == account_generation
                and key[3] != credential_set_version
            ]
            for key in stale_history:
                del self._accepted_history[key]
            stale_prepared = [
                key
                for key in self._prepared
                if key[0] == account_id
                and key[1] == account_generation
                and key[2] != credential_set_version
            ]
            for key in stale_prepared:
                del self._prepared[key]

    def delete_account(self, username: str, expected_generation: int) -> None:
        with self._lock:
            current = self._active.get(self._key(username))
            if current is None:
                return
            if current.account_generation != expected_generation:
                raise ValueError("backend deletion generation mismatch")
            del self._active[self._key(username)]
            self._fail_open_versions.pop(self._key(username), None)
            stale_history = [
                key
                for key in self._accepted_history
                if key[0] == self._key(username)
                and key[1] == current.account_id
                and key[2] == current.account_generation
            ]
            for key in stale_history:
                del self._accepted_history[key]
            stale_prepared = [
                key
                for key in self._prepared
                if key[0] == current.account_id and key[1] == current.account_generation
            ]
            for key in stale_prepared:
                del self._prepared[key]

    def set_post_match_result(self, username: str, kind: BackendResultKind) -> None:
        allowed = {
            BackendResultKind.MATCH,
            BackendResultKind.MATCH_BUT_POLICY_DENY,
            BackendResultKind.ACCOUNT_DISABLED_OR_LOCKED,
            BackendResultKind.MFA_OR_STEP_UP_REQUIRED,
            BackendResultKind.PASSWORD_EXPIRED,
        }
        if kind not in allowed:
            raise ValueError("post-match state must not impersonate a verifier mismatch")
        with self._lock:
            self._post_match[self._key(username)] = kind

    def inject_once(self, username: str, kind: BackendResultKind) -> None:
        if kind is BackendResultKind.MATCH:
            raise ValueError("MATCH injection would bypass password verification")
        with self._lock:
            self._inject_once[self._key(username)] = kind

    def _result(
        self,
        kind: BackendResultKind,
        expected_version: Optional[int],
        version: Optional[_BackendVersion],
        checked_ids: frozenset[str] = frozenset(),
        matched_id: Optional[str] = None,
        detail: str = "",
    ) -> TypedBackendResult:
        return TypedBackendResult(
            kind=kind,
            expected_version=expected_version,
            checked_version=None if version is None else version.credential_set_version,
            checked_account_id=None if version is None else version.account_id,
            checked_account_generation=None if version is None else version.account_generation,
            checked_authenticator_ids=checked_ids,
            matched_authenticator_id=matched_id,
            authenticated_internal_result=True,
            detail=detail,
        )

    def verify(
        self,
        username: str,
        password: Password,
        expected_version: Optional[int],
    ) -> TypedBackendResult:
        """Perform only the expensive password comparison; policy is finalized per request."""

        username_key = self._key(username)
        with self._lock:
            self.verify_calls += 1
            active = self._active.get(username_key)
            injected = self._inject_once.pop(username_key, None)
            versions: list[_BackendVersion] = []
            if active is not None and expected_version is None:
                scopes = self._fail_open_versions.get(
                    username_key,
                    {
                        (
                            active.account_id,
                            active.account_generation,
                            active.credential_set_version,
                        )
                    },
                )
                ordered_scopes = sorted(
                    scopes,
                    key=lambda scope: (scope[2] != active.credential_set_version, -scope[2]),
                )
                for account_id, generation, version_number in ordered_scopes:
                    candidate = self._accepted_history.get(
                        (username_key, account_id, generation, version_number)
                    )
                    if candidate is not None:
                        versions.append(candidate)
            elif active is not None:
                version = active
                if expected_version != active.credential_set_version:
                    # During the backend-before-directory activation window,
                    # retain the prior verifier under its exact expected version.
                    version = self._accepted_history.get(
                        (
                            username_key,
                            active.account_id,
                            active.account_generation,
                            expected_version,
                        )
                    )
                if version is not None:
                    versions.append(version)
        if active is None:
            return self._result(BackendResultKind.NO_ACCOUNT, expected_version, None)
        if not versions:
            return self._result(
                BackendResultKind.VERSION_MISMATCH,
                expected_version,
                active,
                detail="backend active version differs from expected_version",
            )
        version = versions[0]
        if injected is BackendResultKind.TRANSIENT_FAILURE:
            return self._result(
                injected,
                expected_version,
                None,
                detail="injected transient failure",
            )
        if injected is BackendResultKind.PARTIAL_AUTHENTICATOR_FAILURE:
            first = next(iter(sorted(version.authenticator_verifiers)))
            return self._result(
                injected,
                expected_version,
                version,
                frozenset({first}),
                detail="injected partial verifier failure",
            )
        if injected is not None:
            return self._result(
                injected,
                expected_version,
                version,
                detail="injected typed backend state",
            )

        checked: set[str] = set()
        for checked_version in versions:
            candidate = self._verifier(
                password,
                checked_version.salt,
                checked_version.encoding_version,
            )
            checked_for_version: set[str] = set()
            for authenticator_id in sorted(checked_version.authenticator_verifiers):
                checked_for_version.add(authenticator_id)
                checked.add(
                    authenticator_id
                    if len(versions) == 1
                    else f"v{checked_version.credential_set_version}:{authenticator_id}"
                )
                if hmac.compare_digest(
                    candidate,
                    checked_version.authenticator_verifiers[authenticator_id],
                ):
                    return self._result(
                        BackendResultKind.MATCH,
                        expected_version,
                        checked_version,
                        frozenset(checked_for_version),
                        matched_id=authenticator_id,
                    )
        if len(versions) > 1:
            return TypedBackendResult(
                kind=BackendResultKind.CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS,
                expected_version=expected_version,
                checked_version=None,
                checked_account_id=active.account_id,
                checked_account_generation=active.account_generation,
                checked_authenticator_ids=frozenset(checked),
                authenticated_internal_result=True,
                detail="mismatch across backend transition versions",
            )
        return self._result(
            BackendResultKind.CREDENTIAL_MISMATCH_ALL_ACTIVE_PASSWORD_AUTHENTICATORS,
            expected_version,
            version,
            frozenset(version.authenticator_verifiers),
        )

    def finalize_match(
        self,
        username: str,
        comparison_result: TypedBackendResult,
    ) -> TypedBackendResult:
        """Apply policy/MFA/session state per request, never through singleflight."""

        if comparison_result.kind is not BackendResultKind.MATCH:
            return comparison_result
        with self._lock:
            kind = self._post_match.get(self._key(username), BackendResultKind.MATCH)
        if kind is BackendResultKind.MATCH:
            return comparison_result
        return TypedBackendResult(
            kind=kind,
            expected_version=comparison_result.expected_version,
            checked_version=comparison_result.checked_version,
            checked_account_id=comparison_result.checked_account_id,
            checked_account_generation=comparison_result.checked_account_generation,
            checked_authenticator_ids=comparison_result.checked_authenticator_ids,
            matched_authenticator_id=comparison_result.matched_authenticator_id,
            authenticated_internal_result=True,
            detail="per-request post-verifier decision",
        )
