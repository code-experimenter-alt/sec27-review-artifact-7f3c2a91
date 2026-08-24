from __future__ import annotations

import hashlib
import hmac
from collections import Counter
from threading import RLock
from typing import Dict, Iterable, Mapping, Optional

from .crypto import Password, encode_fields, positive_token
from .types import (
    DirectoryStatus,
    DirectoryView,
    PositiveDecision,
    PositiveDisposition,
    RepresentationCertificate,
    RepresentationSource,
)

Scope = tuple[str, int, int]


class PositiveScreen:
    """Stable, one-sided positive screen with exact delta/base representations."""

    def __init__(
        self,
        positive_key: bytes,
        certificate_key: bytes,
        region_count: int = 8,
    ) -> None:
        if len(positive_key) < 16 or len(certificate_key) < 16:
            raise ValueError("positive and certificate keys must be at least 128 bits")
        if region_count < 1:
            raise ValueError("region_count must be positive")
        self._positive_key = bytes(positive_key)
        self._certificate_key = bytes(certificate_key)
        self._region_count = region_count
        self._lock = RLock()
        self._base: Dict[Scope, Dict[int, set[bytes]]] = {}
        self._delta: Dict[Scope, Dict[int, set[bytes]]] = {}
        self._base_epoch: Dict[Scope, int] = {}
        self._delta_epoch: Dict[Scope, int] = {}
        self._certificates: Dict[tuple[str, Scope], RepresentationCertificate] = {}
        self._next_representation_epoch = 1
        self._metrics: Counter[str] = Counter()

    @property
    def region_count(self) -> int:
        return self._region_count

    def router(self, view: DirectoryView) -> int:
        if not view.can_screen:
            raise ValueError("cannot route an uncertain directory view")
        account_id, generation, _ = view.scope
        stable = encode_fields(
            "R-TRAPS/STABLE-ROUTER/v1",
            account_id,
            generation,
            view.retry_class,
        )
        value = int.from_bytes(hashlib.sha256(stable).digest()[:8], "big")
        return value % self._region_count

    def credential_token(self, view: DirectoryView, password: Password) -> bytes:
        if not view.can_screen:
            raise ValueError("cannot derive a real-account token from uncertain state")
        account_id, generation, version = view.scope
        return positive_token(
            self._positive_key,
            account_id,
            generation,
            version,
            view.encoding_version,
            password,
            view.salt,
        )

    def tokens_for_authenticators(
        self,
        view: DirectoryView,
        authenticators: Mapping[str, Password],
    ) -> frozenset[bytes]:
        if set(authenticators) != set(view.active_authenticator_ids):
            raise ValueError("authenticator IDs do not match the directory view")
        return frozenset(
            self.credential_token(view, password)
            for password in authenticators.values()
        )

    def _allocate_representation_epoch(self) -> int:
        value = self._next_representation_epoch
        self._next_representation_epoch += 1
        return value

    def publish_delta(self, view: DirectoryView, tokens: Iterable[bytes]) -> int:
        token_set = {bytes(token) for token in tokens}
        if not token_set or any(len(token) != 32 for token in token_set):
            raise ValueError("a complete positive delta requires non-empty 256-bit tokens")
        region = self.router(view)
        with self._lock:
            epoch = self._allocate_representation_epoch()
            self._delta[view.scope] = {region: token_set}
            self._delta_epoch[view.scope] = epoch
            self._metrics["delta_published"] += 1
            return epoch

    def compact(self, view: DirectoryView) -> int:
        with self._lock:
            delta = self._delta.get(view.scope)
            if delta is None or view.scope not in self._delta_epoch:
                raise ValueError("cannot compact before a complete delta is ready")
            base = self._base.setdefault(view.scope, {})
            for region, tokens in delta.items():
                base.setdefault(region, set()).update(tokens)
            epoch = self._allocate_representation_epoch()
            self._base_epoch[view.scope] = epoch
            self._metrics["compactions"] += 1
            return epoch

    def retire_delta(self, view: DirectoryView) -> None:
        with self._lock:
            if view.scope not in self._base_epoch:
                raise ValueError("delta retirement requires a complete compacted base")
            self._delta.pop(view.scope, None)
            self._delta_epoch.pop(view.scope, None)
            self._metrics["delta_retired"] += 1

    def _certificate_message(
        self,
        edge_id: str,
        view: DirectoryView,
        representation_epoch: int,
        source: RepresentationSource,
    ) -> bytes:
        account_id, generation, version = view.scope
        return encode_fields(
            "R-TRAPS/REPRESENTATION-CERT/v1",
            edge_id,
            account_id,
            generation,
            version,
            view.directory_epoch,
            representation_epoch,
            source.value,
        )

    def issue_certificate(
        self,
        edge_id: str,
        view: DirectoryView,
        source: RepresentationSource,
    ) -> RepresentationCertificate:
        with self._lock:
            epochs = (
                self._delta_epoch
                if source is RepresentationSource.POSITIVE_DELTA
                else self._base_epoch
            )
            representation_epoch = epochs.get(view.scope)
            if representation_epoch is None:
                raise ValueError("cannot certify a missing representation")
            signature = hmac.new(
                self._certificate_key,
                self._certificate_message(edge_id, view, representation_epoch, source),
                hashlib.sha256,
            ).digest()
            account_id, generation, version = view.scope
            certificate = RepresentationCertificate(
                edge_id=edge_id,
                account_id=account_id,
                account_generation=generation,
                credential_set_version=version,
                directory_epoch_watermark=view.directory_epoch,
                representation_epoch=representation_epoch,
                source=source,
                signature=signature,
            )
            self._certificates[(edge_id, view.scope)] = certificate
            self._metrics["certificates_issued"] += 1
            return certificate

    def install_certificate(self, certificate: RepresentationCertificate) -> None:
        """Install a transported certificate after verifying its signature."""

        synthetic_view = DirectoryView(
            username="certificate-transport",
            status=DirectoryStatus.PRESENT,
            account_id=certificate.account_id,
            account_generation=certificate.account_generation,
            credential_set_version=certificate.credential_set_version,
            salt=b"not-used-for-certificate-validation",
            active_authenticator_ids=frozenset({"not-used"}),
            directory_epoch=certificate.directory_epoch_watermark,
        )
        expected = hmac.new(
            self._certificate_key,
            self._certificate_message(
                certificate.edge_id,
                synthetic_view,
                certificate.representation_epoch,
                certificate.source,
            ),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, certificate.signature):
            raise ValueError("invalid representation certificate signature")
        with self._lock:
            self._certificates[(certificate.edge_id, synthetic_view.scope)] = certificate

    def clear_edge_certificates(self, edge_id: str) -> None:
        with self._lock:
            stale = [key for key in self._certificates if key[0] == edge_id]
            for key in stale:
                del self._certificates[key]
            self._metrics["certificate_clears"] += len(stale)

    def _certificate_valid(
        self,
        certificate: RepresentationCertificate,
        edge_id: str,
        view: DirectoryView,
    ) -> bool:
        if (
            certificate.edge_id != edge_id
            or (
                certificate.account_id,
                certificate.account_generation,
                certificate.credential_set_version,
            )
            != view.scope
            or certificate.directory_epoch_watermark < view.directory_epoch
        ):
            return False
        expected = hmac.new(
            self._certificate_key,
            self._certificate_message(
                edge_id,
                view,
                certificate.representation_epoch,
                certificate.source,
            ),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, certificate.signature):
            return False
        if certificate.source is RepresentationSource.POSITIVE_DELTA:
            return self._delta_epoch.get(view.scope) == certificate.representation_epoch
        return self._base_epoch.get(view.scope) == certificate.representation_epoch

    def query(
        self,
        view: DirectoryView,
        password: Password,
        edge_id: str,
        token: Optional[bytes] = None,
    ) -> PositiveDecision:
        if view.status is not DirectoryStatus.PRESENT:
            self._metrics["fail_open_directory"] += 1
            return PositiveDecision(
                PositiveDisposition.FAIL_OPEN,
                f"directory state is {view.status.value}",
            )
        derived = self.credential_token(view, password) if token is None else bytes(token)
        region = self.router(view)
        with self._lock:
            certificate = self._certificates.get((edge_id, view.scope))
            if certificate is None or not self._certificate_valid(certificate, edge_id, view):
                self._metrics["fail_open_certificate"] += 1
                return PositiveDecision(
                    PositiveDisposition.FAIL_OPEN,
                    "missing, stale, or invalid representation certificate",
                    credential_token=derived,
                    region=region,
                    certificate=certificate,
                )
            base = self._base.get(view.scope, {}).get(region, set())
            delta = self._delta.get(view.scope, {}).get(region, set())
            if derived in base or derived in delta:
                self._metrics["positive"] += 1
                return PositiveDecision(
                    PositiveDisposition.POSITIVE,
                    "credential token is represented",
                    credential_token=derived,
                    region=region,
                    certificate=certificate,
                )
            self._metrics["negative"] += 1
            return PositiveDecision(
                PositiveDisposition.NEGATIVE,
                "complete certified representation does not contain token",
                credential_token=derived,
                region=region,
                certificate=certificate,
            )

    def metrics_snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._metrics)
