from __future__ import annotations

import hashlib
from dataclasses import dataclass

from dataplane.crypto import encode_fields

from ..delta_activation import ActivationKey, ActivationStateMachine


@dataclass(frozen=True)
class RebuildArtifact:
    activation_key: ActivationKey
    representation_epoch: int
    manifest_digest: str


class RebuildCoordinator:
    """Off-path immutable-compaction facade with a reproducible manifest ID."""

    def __init__(self, activation: ActivationStateMachine) -> None:
        self.activation = activation

    def compact(self, key: ActivationKey) -> RebuildArtifact:
        epoch = self.activation.compact(key)
        digest = hashlib.sha256(
            encode_fields(
                "R-TRAPS/REBUILD-MANIFEST/v1",
                key.username,
                key.account_id,
                key.account_generation,
                key.credential_set_version,
                epoch,
            )
        ).hexdigest()
        return RebuildArtifact(key, epoch, digest)
