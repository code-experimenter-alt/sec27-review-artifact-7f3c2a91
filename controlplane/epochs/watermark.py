from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Dict, Optional

Scope = tuple[str, int, int]


@dataclass(frozen=True)
class EpochWatermark:
    edge_id: str
    scope: Scope
    directory_epoch: int
    representation_epoch: int
    certain: bool = True

    def covers(self, scope: Scope, directory_epoch: int) -> bool:
        return self.certain and self.scope == scope and self.directory_epoch >= directory_epoch


class EpochTracker:
    """Monotonic edge watermarks; unknown/recovery states never screen."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._watermarks: Dict[tuple[str, Scope], EpochWatermark] = {}
        self._uncertain_edges: set[str] = set()

    def advance(
        self,
        edge_id: str,
        scope: Scope,
        directory_epoch: int,
        representation_epoch: int,
    ) -> EpochWatermark:
        candidate = EpochWatermark(
            edge_id,
            scope,
            directory_epoch,
            representation_epoch,
        )
        with self._lock:
            prior = self._watermarks.get((edge_id, scope))
            if prior is not None and (
                directory_epoch < prior.directory_epoch
                or representation_epoch < prior.representation_epoch
            ):
                raise ValueError("epoch watermark regression")
            self._watermarks[(edge_id, scope)] = candidate
            self._uncertain_edges.discard(edge_id)
            return candidate

    def mark_edge_uncertain(self, edge_id: str) -> None:
        with self._lock:
            self._uncertain_edges.add(edge_id)

    def get(self, edge_id: str, scope: Scope) -> Optional[EpochWatermark]:
        with self._lock:
            if edge_id in self._uncertain_edges:
                return None
            return self._watermarks.get((edge_id, scope))

    def covers(self, edge_id: str, scope: Scope, directory_epoch: int) -> bool:
        watermark = self.get(edge_id, scope)
        return watermark is not None and watermark.covers(scope, directory_epoch)
