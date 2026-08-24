from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Dict, Iterable, Mapping, Optional

from dataplane.backend import InMemoryBackend
from dataplane.crypto import Password
from dataplane.directory import Directory
from dataplane.positive import PositiveScreen
from dataplane.types import (
    DirectoryStatus,
    DirectoryView,
    RepresentationCertificate,
    RepresentationSource,
)

from ..epochs import EpochTracker


class ActivationStatus(str, Enum):
    PREPARED = "PREPARED"
    EDGE_DELTA_READY = "EDGE_DELTA_READY"
    ACTIVE = "ACTIVE"
    COMPACTED = "COMPACTED"
    RETIRED = "RETIRED"


@dataclass(frozen=True, order=True)
class ActivationKey:
    username: str
    account_id: str
    account_generation: int
    credential_set_version: int


@dataclass
class ActivationRecord:
    key: ActivationKey
    view: DirectoryView
    tokens: frozenset[bytes]
    required_edges: frozenset[str]
    status: ActivationStatus = ActivationStatus.PREPARED
    delta_acknowledged_edges: set[str] = field(default_factory=set)
    compacted_acknowledged_edges: set[str] = field(default_factory=set)
    delta_epoch: Optional[int] = None
    compacted_epoch: Optional[int] = None

    @property
    def activation_ready(self) -> bool:
        return self.required_edges <= self.delta_acknowledged_edges

    @property
    def retirement_ready(self) -> bool:
        return self.required_edges <= self.compacted_acknowledged_edges


class ActivationStateMachine:
    """Executable PREPARED -> ... -> RETIRED activation protocol."""

    def __init__(
        self,
        directory: Directory,
        positive_screen: PositiveScreen,
        backend: InMemoryBackend,
        epoch_tracker: Optional[EpochTracker] = None,
    ) -> None:
        self.directory = directory
        self.positive_screen = positive_screen
        self.backend = backend
        self.epoch_tracker = epoch_tracker or EpochTracker()
        self._lock = RLock()
        self._records: Dict[ActivationKey, ActivationRecord] = {}
        self._latest_by_username: Dict[str, ActivationKey] = {}
        self._metrics: Counter[str] = Counter()

    def prepare(
        self,
        username: str,
        account_id: str,
        account_generation: int,
        credential_set_version: int,
        salt: bytes,
        authenticators: Mapping[str, Password],
        required_edges: Iterable[str],
        encoding_version: int = 1,
        retry_class: str = "default",
    ) -> ActivationKey:
        edge_set = frozenset(required_edges)
        if not edge_set:
            raise ValueError("activation requires at least one serving edge")
        if not authenticators:
            raise ValueError("activation requires an authenticator set")
        key = ActivationKey(
            username,
            account_id,
            account_generation,
            credential_set_version,
        )
        with self._lock:
            if key in self._records:
                raise ValueError("activation key is immutable and already prepared")
            last_generation = self.directory.last_generation(username)
            if account_generation < max(1, last_generation):
                raise ValueError("account generation regression")
            if last_generation and account_generation == last_generation:
                current = self.directory.lookup(username)
                if current.status is not DirectoryStatus.PRESENT:
                    raise ValueError("deleted usernames require a new account generation")
                if current.account_id != account_id:
                    raise ValueError("account ID change requires a new generation")
                assert current.credential_set_version is not None
                if credential_set_version <= current.credential_set_version:
                    raise ValueError("credential-set version must increase")

            directory_epoch = self.directory.reserve_epoch()
            view = DirectoryView(
                username=username,
                status=DirectoryStatus.PRESENT,
                account_id=account_id,
                account_generation=account_generation,
                credential_set_version=credential_set_version,
                salt=bytes(salt),
                encoding_version=encoding_version,
                retry_class=retry_class,
                active_authenticator_ids=frozenset(authenticators),
                directory_epoch=directory_epoch,
            )
            tokens = self.positive_screen.tokens_for_authenticators(view, authenticators)
            self.backend.prepare_version(
                username,
                account_id,
                account_generation,
                credential_set_version,
                salt,
                encoding_version,
                authenticators,
            )
            self._records[key] = ActivationRecord(
                key=key,
                view=view,
                tokens=tokens,
                required_edges=edge_set,
            )
            self._metrics["prepared"] += 1
            return key

    def record(self, key: ActivationKey) -> ActivationRecord:
        with self._lock:
            try:
                return self._records[key]
            except KeyError as exc:
                raise KeyError(f"unknown activation: {key}") from exc

    def publish_delta(self, key: ActivationKey) -> int:
        with self._lock:
            record = self.record(key)
            if record.status is not ActivationStatus.PREPARED:
                if record.delta_epoch is not None:
                    return record.delta_epoch
                raise ValueError("invalid delta publication state")
            record.delta_epoch = self.positive_screen.publish_delta(record.view, record.tokens)
            record.status = ActivationStatus.EDGE_DELTA_READY
            self._metrics["delta_ready"] += 1
            return record.delta_epoch

    def acknowledge_delta(
        self,
        key: ActivationKey,
        edge_id: str,
    ) -> RepresentationCertificate:
        with self._lock:
            record = self.record(key)
            if record.status is ActivationStatus.PREPARED:
                raise ValueError("edge cannot acknowledge an unpublished delta")
            if record.status is ActivationStatus.RETIRED:
                raise ValueError("delta is already retired")
            if edge_id not in record.required_edges:
                raise ValueError("edge is outside the activation certificate policy")
            certificate = self.positive_screen.issue_certificate(
                edge_id,
                record.view,
                RepresentationSource.POSITIVE_DELTA,
            )
            record.delta_acknowledged_edges.add(edge_id)
            self._metrics["delta_acknowledgments"] += 1
            self.epoch_tracker.advance(
                edge_id,
                record.view.scope,
                record.view.directory_epoch,
                certificate.representation_epoch,
            )
            return certificate

    def activate(
        self,
        key: ActivationKey,
        replicate_directory: bool = True,
    ) -> ActivationStatus:
        with self._lock:
            record = self.record(key)
            if record.status in {
                ActivationStatus.ACTIVE,
                ActivationStatus.COMPACTED,
                ActivationStatus.RETIRED,
            }:
                return record.status
            if record.status is not ActivationStatus.EDGE_DELTA_READY:
                raise ValueError("activation requires EDGE_DELTA_READY")
            if not record.activation_ready:
                missing = sorted(record.required_edges - record.delta_acknowledged_edges)
                raise ValueError(f"missing required edge certificates: {missing}")

            # Backend first enters a dual-verification window.  If execution
            # stops here, both the old externally active credential and the new
            # prepared credential remain backend-verifiable on fail-open paths.
            self.backend.activate_version(
                key.username,
                key.account_id,
                key.account_generation,
                key.credential_set_version,
            )
            self.directory.publish_active(record.view)
            self.backend.commit_directory_version(
                key.username,
                key.account_id,
                key.account_generation,
                key.credential_set_version,
            )
            record.status = ActivationStatus.ACTIVE
            self._metrics["activated"] += 1
            self._latest_by_username[key.username.casefold()] = key
            if replicate_directory:
                for edge_id in record.required_edges:
                    self.directory.replicate_to_edge(edge_id, key.username)
            return record.status

    def fault_backend_advance_before_directory(self, key: ActivationKey) -> None:
        """E8 hook: simulate a crash after the backend step, before directory ACTIVE."""

        with self._lock:
            record = self.record(key)
            if (
                record.status is not ActivationStatus.EDGE_DELTA_READY
                or not record.activation_ready
            ):
                raise ValueError("backend-only fault point requires an activation-ready delta")
            self.backend.activate_version(
                key.username,
                key.account_id,
                key.account_generation,
                key.credential_set_version,
            )
            self._metrics["fault_backend_before_directory"] += 1

    def compact(self, key: ActivationKey) -> int:
        with self._lock:
            record = self.record(key)
            if record.status in {ActivationStatus.COMPACTED, ActivationStatus.RETIRED}:
                assert record.compacted_epoch is not None
                return record.compacted_epoch
            if record.status is not ActivationStatus.ACTIVE:
                raise ValueError("compaction requires an active version")
            record.compacted_epoch = self.positive_screen.compact(record.view)
            record.status = ActivationStatus.COMPACTED
            self._metrics["compacted"] += 1
            return record.compacted_epoch

    def acknowledge_compacted(
        self,
        key: ActivationKey,
        edge_id: str,
    ) -> RepresentationCertificate:
        with self._lock:
            record = self.record(key)
            if record.status not in {ActivationStatus.COMPACTED, ActivationStatus.RETIRED}:
                raise ValueError("compacted representation is not ready")
            if edge_id not in record.required_edges:
                raise ValueError("edge is outside the activation certificate policy")
            certificate = self.positive_screen.issue_certificate(
                edge_id,
                record.view,
                RepresentationSource.COMPACTED_BASE,
            )
            record.compacted_acknowledged_edges.add(edge_id)
            self._metrics["compacted_acknowledgments"] += 1
            self.epoch_tracker.advance(
                edge_id,
                record.view.scope,
                record.view.directory_epoch,
                certificate.representation_epoch,
            )
            return certificate

    def retire(self, key: ActivationKey) -> ActivationStatus:
        with self._lock:
            record = self.record(key)
            if record.status is ActivationStatus.RETIRED:
                return record.status
            if record.status is not ActivationStatus.COMPACTED:
                raise ValueError("retirement requires COMPACTED")
            if not record.retirement_ready:
                missing = sorted(record.required_edges - record.compacted_acknowledged_edges)
                raise ValueError(f"edges lack compacted epoch: {missing}")
            self.positive_screen.retire_delta(record.view)
            record.status = ActivationStatus.RETIRED
            self._metrics["retired"] += 1
            return record.status

    def crash_edge(self, edge_id: str) -> None:
        self.directory.mark_edge_uncertain(edge_id)
        self.positive_screen.clear_edge_certificates(edge_id)
        self.epoch_tracker.mark_edge_uncertain(edge_id)
        with self._lock:
            self._metrics["edge_crashes"] += 1

    def recover_edge(
        self,
        edge_id: str,
        username: str,
    ) -> Optional[RepresentationCertificate]:
        """Recover from authoritative state; partial recovery remains fail-open."""

        authoritative = self.directory.lookup(username)
        canonical_username = authoritative.backend_username
        self.directory.recover_edge(edge_id)
        self.directory.replicate_to_edge(edge_id, username)
        with self._lock:
            key = self._latest_by_username.get(canonical_username.casefold())
            if key is None:
                return None
            record = self.record(key)
            if edge_id not in record.required_edges:
                return None
            source = (
                RepresentationSource.COMPACTED_BASE
                if record.status in {ActivationStatus.COMPACTED, ActivationStatus.RETIRED}
                else RepresentationSource.POSITIVE_DELTA
            )
            certificate = self.positive_screen.issue_certificate(edge_id, record.view, source)
            self.epoch_tracker.advance(
                edge_id,
                record.view.scope,
                record.view.directory_epoch,
                certificate.representation_epoch,
            )
            self._metrics["edge_recoveries"] += 1
            return certificate

    def delete_account(self, username: str, expected_generation: int) -> int:
        """Delete backend first; any interrupted intermediate state fails open."""

        authoritative = self.directory.lookup(username)
        canonical_username = authoritative.backend_username
        self.backend.delete_account(canonical_username, expected_generation)
        epoch = self.directory.delete(username, expected_generation)
        with self._lock:
            self._latest_by_username.pop(canonical_username.casefold(), None)
            self._metrics["deletions"] += 1
        return epoch

    def metrics_snapshot(self) -> dict[str, int]:
        with self._lock:
            result = dict(self._metrics)
            result["activation_records"] = len(self._records)
            return result
