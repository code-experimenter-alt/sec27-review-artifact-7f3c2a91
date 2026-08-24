from __future__ import annotations

from dataclasses import dataclass, replace
from threading import RLock
from typing import Dict, Optional

from .types import DirectoryStatus, DirectoryView


@dataclass(frozen=True)
class _DirectorySlot:
    view: Optional[DirectoryView]
    epoch: int
    last_generation: int


class Directory:
    """Authoritative directory plus explicitly staleable per-edge replicas."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._next_epoch = 1
        self._authoritative: Dict[str, _DirectorySlot] = {}
        self._edge: Dict[tuple[str, str], _DirectorySlot] = {}
        self._aliases: Dict[str, str] = {}
        self._crashed_edges: set[str] = set()

    @staticmethod
    def _key(username: str) -> str:
        if not isinstance(username, str) or not username:
            raise ValueError("username must be a non-empty string")
        return username.casefold()

    def reserve_epoch(self) -> int:
        with self._lock:
            value = self._next_epoch
            self._next_epoch += 1
            return value

    def publish_active(self, view: DirectoryView) -> None:
        if view.status is not DirectoryStatus.PRESENT:
            raise ValueError("only a present view can be activated")
        key = self._key(view.username)
        with self._lock:
            if key in self._aliases:
                raise ValueError("activate through the canonical username, not an alias")
            prior = self._authoritative.get(key)
            assert view.account_generation is not None
            assert view.credential_set_version is not None
            if prior is not None:
                if view.account_generation < prior.last_generation:
                    raise ValueError("account generation regression")
                if view.account_generation == prior.last_generation and prior.view is None:
                    raise ValueError("a deleted username requires a new generation")
                if prior.view is not None:
                    same_identity = (
                        view.account_id == prior.view.account_id
                        and view.account_generation == prior.view.account_generation
                    )
                    if same_identity and (
                        view.credential_set_version
                        <= prior.view.credential_set_version  # type: ignore[operator]
                    ):
                        raise ValueError("credential-set version must increase")
                    if not same_identity and view.account_generation <= prior.last_generation:
                        raise ValueError("username reuse requires a higher generation")
            if view.directory_epoch >= self._next_epoch:
                self._next_epoch = view.directory_epoch + 1
            self._authoritative[key] = _DirectorySlot(
                view=view,
                epoch=view.directory_epoch,
                last_generation=view.account_generation,
            )

    def lookup(self, username: str, edge_id: Optional[str] = None) -> DirectoryView:
        requested_key = self._key(username)
        with self._lock:
            key = self._aliases.get(requested_key, requested_key)
            authoritative = self._authoritative.get(key)
            if edge_id is None:
                if authoritative is None or authoritative.view is None:
                    return DirectoryView.missing(username)
                return self._for_requested_username(authoritative.view, username)

            if edge_id in self._crashed_edges:
                return DirectoryView.uncertain(username, "edge directory is recovering")

            replica = self._edge.get((edge_id, key))
            if replica is None:
                if authoritative is None:
                    return DirectoryView.missing(username)
                return DirectoryView.uncertain(username, "edge has no directory replica")

            if authoritative is None or replica.epoch != authoritative.epoch:
                if replica.view is None:
                    return DirectoryView.uncertain(username, "edge tombstone is stale")
                return replace(
                    self._for_requested_username(replica.view, username),
                    status=DirectoryStatus.STALE,
                    reason="edge directory epoch is stale",
                )
            if replica.view is None:
                return DirectoryView.missing(username, "replicated tombstone")
            return self._for_requested_username(replica.view, username)

    @staticmethod
    def _for_requested_username(view: DirectoryView, username: str) -> DirectoryView:
        if view.username == username:
            return view
        return replace(
            view,
            username=username,
            canonical_username=view.canonical_username or view.username,
        )

    def replicate_to_edge(self, edge_id: str, username: str) -> None:
        requested_key = self._key(username)
        with self._lock:
            key = self._aliases.get(requested_key, requested_key)
            slot = self._authoritative.get(key)
            if slot is None:
                slot = _DirectorySlot(view=None, epoch=0, last_generation=0)
            self._edge[(edge_id, key)] = slot

    def mark_edge_uncertain(self, edge_id: str) -> None:
        with self._lock:
            self._crashed_edges.add(edge_id)

    def recover_edge(self, edge_id: str) -> None:
        with self._lock:
            self._crashed_edges.discard(edge_id)

    def delete(self, username: str, expected_generation: int) -> int:
        requested_key = self._key(username)
        with self._lock:
            key = self._aliases.get(requested_key, requested_key)
            prior = self._authoritative.get(key)
            if prior is None or prior.view is None:
                raise KeyError(username)
            if prior.view.account_generation != expected_generation:
                raise ValueError("generation mismatch during deletion")
            epoch = self.reserve_epoch()
            self._authoritative[key] = _DirectorySlot(
                view=None,
                epoch=epoch,
                last_generation=expected_generation,
            )
            return epoch

    def last_generation(self, username: str) -> int:
        requested_key = self._key(username)
        with self._lock:
            key = self._aliases.get(requested_key, requested_key)
            slot = self._authoritative.get(key)
            return 0 if slot is None else slot.last_generation

    def add_alias(self, existing_username: str, alias: str) -> None:
        existing_key = self._key(existing_username)
        alias_key = self._key(alias)
        with self._lock:
            existing_key = self._aliases.get(existing_key, existing_key)
            slot = self._authoritative.get(existing_key)
            if slot is None or slot.view is None:
                raise KeyError(existing_username)
            if alias_key in self._authoritative or alias_key in self._aliases:
                raise ValueError("alias is already assigned")
            self._aliases[alias_key] = existing_key

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "next_epoch": self._next_epoch,
                "authoritative_entries": len(self._authoritative),
                "edge_replicas": len(self._edge),
                "aliases": len(self._aliases),
                "crashed_edges": tuple(sorted(self._crashed_edges)),
            }
