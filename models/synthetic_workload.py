"""Independent, intent-neutral synthetic workloads for Phase 5 evaluation.

The two generator families intentionally use different account-access and
inter-arrival mechanisms.  Neither contains plaintext credentials.  Repeated
tokens and their stable features are scoped by account generation and complete
credential-set version.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Iterator, Sequence

import numpy as np

FEATURE_NAMES = (
    "account_rank_fraction",
    "enrollment_cohort",
    "frozen_retry_class",
    "candidate_length_normalized",
    "candidate_digit_fraction",
    "candidate_symbol_fraction",
    "verifier_cost_class",
)

VALID_CURRENT_CREDENTIAL = "VALID_CURRENT_CREDENTIAL"
INVALID_REPEATED_TUPLE = "INVALID_REPEATED_TUPLE"
INVALID_DISTINCT_TUPLE = "INVALID_DISTINCT_TUPLE"
NO_ACCOUNT = "NO_ACCOUNT"


@dataclass(frozen=True)
class SyntheticWorkloadConfig:
    family: str
    account_count: int
    event_count: int
    seed: int
    valid_fraction: float = 0.08
    no_account_fraction: float = 0.08
    repeated_invalid_fraction: float = 0.70
    zipf_alpha: float = 1.08
    offered_load_rps: float = 10_000.0
    rotation_period_events: int = 100_000
    churn_period_events: int = 1_000_000
    repeat_slots_per_account: int = 4
    drift_fraction: float = 0.70
    hotset_fraction: float = 0.05
    hotset_epoch_events: int = 5_000

    def validate(self) -> None:
        if type(self.family) is not str or self.family not in {
            "zipf_bursty_v1",
            "renewal_hotset_v1",
        }:
            raise ValueError("unsupported synthetic generator family")
        if type(self.account_count) is not int or type(self.event_count) is not int:
            raise ValueError("account_count and event_count must be integers")
        if self.account_count <= 0 or self.event_count <= 0:
            raise ValueError("account_count and event_count must be positive")
        if type(self.seed) is not int or not 0 <= self.seed <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("seed must fit uint64")
        for name in (
            "valid_fraction",
            "no_account_fraction",
            "repeated_invalid_fraction",
            "drift_fraction",
            "hotset_fraction",
        ):
            value = getattr(self, name)
            if type(value) not in {int, float} or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} must lie in [0, 1]")
        if self.valid_fraction + self.no_account_fraction > 1:
            raise ValueError("valid and no-account fractions cannot sum above one")
        for name in ("zipf_alpha", "offered_load_rps"):
            value = getattr(self, name)
            if type(value) not in {int, float} or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be finite and positive")
        for name in (
            "rotation_period_events",
            "churn_period_events",
            "repeat_slots_per_account",
            "hotset_epoch_events",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.zipf_alpha <= 0 or self.offered_load_rps <= 0:
            raise ValueError("zipf_alpha and offered_load_rps must be positive")


@dataclass(frozen=True)
class AuthEvent:
    event_id: str
    event_index: int
    relative_timestamp_ms: int
    account_index: int
    account_generation: int
    credential_set_version: int
    submitted_credential_token: str
    label: str
    backend_result_type: str
    stable_features: tuple[float, ...]
    coarse_source_continuity: int
    coarse_device_continuity: int
    credential_age_fraction: float
    rotation_recent: bool
    verifier_cost_weight: float
    generator_family: str

    def validate(self) -> None:
        for name in ("event_id", "submitted_credential_token", "generator_family"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError(f"{name} must be a nonempty string")
        for name in ("event_index", "relative_timestamp_ms", "account_index"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative integer")
        for name in ("account_generation", "credential_set_version"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.label not in {
            VALID_CURRENT_CREDENTIAL,
            INVALID_REPEATED_TUPLE,
            INVALID_DISTINCT_TUPLE,
            NO_ACCOUNT,
        }:
            raise ValueError("unsupported event label")
        expected_result = {
            VALID_CURRENT_CREDENTIAL: "MATCH",
            INVALID_REPEATED_TUPLE: "CREDENTIAL_MISMATCH",
            INVALID_DISTINCT_TUPLE: "CREDENTIAL_MISMATCH",
            NO_ACCOUNT: "NO_ACCOUNT",
        }[self.label]
        if self.backend_result_type != expected_result:
            raise ValueError("backend_result_type is inconsistent with label")
        if type(self.stable_features) is not tuple or len(self.stable_features) != len(
            FEATURE_NAMES
        ):
            raise ValueError("stable_features has the wrong shape")
        if any(
            type(value) not in {int, float} or not math.isfinite(value)
            for value in self.stable_features
        ):
            raise ValueError("stable_features must be finite")
        # Missing-account dummy identities intentionally have a rank above one;
        # all other normalized features retain their declared [0, 1] range.
        if self.stable_features[0] < 0 or any(
            not 0 <= value <= 1 for value in self.stable_features[1:]
        ):
            raise ValueError("stable feature values are outside their declared ranges")
        for name in ("coarse_source_continuity", "coarse_device_continuity"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 3:
                raise ValueError(f"{name} must be an integer in [0, 3]")
        if (
            type(self.credential_age_fraction) not in {int, float}
            or not math.isfinite(self.credential_age_fraction)
            or not 0 <= self.credential_age_fraction <= 1
        ):
            raise ValueError("credential_age_fraction must be finite and lie in [0, 1]")
        if type(self.rotation_recent) is not bool:
            raise ValueError("rotation_recent must be a boolean")
        if (
            type(self.verifier_cost_weight) not in {int, float}
            or not math.isfinite(self.verifier_cost_weight)
            or self.verifier_cost_weight <= 0
        ):
            raise ValueError("verifier_cost_weight must be finite and positive")

    @property
    def tuple_key(self) -> tuple[int, int, int, str]:
        return (
            self.account_index,
            self.account_generation,
            self.credential_set_version,
            self.submitted_credential_token,
        )

    @property
    def is_existing_invalid(self) -> bool:
        return self.label in {INVALID_REPEATED_TUPLE, INVALID_DISTINCT_TUPLE}

    @property
    def is_valid(self) -> bool:
        return self.label == VALID_CURRENT_CREDENTIAL


@dataclass(frozen=True)
class ActiveCredentialMember:
    """Current represented credential for one account at an exact event boundary."""

    snapshot_event_index: int
    account_index: int
    account_generation: int
    credential_set_version: int
    credential_token: str
    stable_features: tuple[float, ...]
    generator_family: str

    def validate(self) -> None:
        if type(self.snapshot_event_index) is not int or self.snapshot_event_index < 0:
            raise ValueError("snapshot_event_index must be a nonnegative integer")
        if type(self.account_index) is not int or self.account_index < 0:
            raise ValueError("account_index must be a nonnegative integer")
        for name in ("account_generation", "credential_set_version"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if (
            type(self.credential_token) is not str
            or len(self.credential_token) != 32
            or any(character not in "0123456789abcdef" for character in self.credential_token)
        ):
            raise ValueError("credential_token must be 16 lowercase hexadecimal bytes")
        if type(self.stable_features) is not tuple or len(self.stable_features) != len(
            FEATURE_NAMES
        ):
            raise ValueError("stable_features has the wrong shape")
        if any(
            type(value) not in {int, float} or not math.isfinite(value)
            for value in self.stable_features
        ):
            raise ValueError("stable_features must be finite")
        if any(not 0 <= value <= 1 for value in self.stable_features):
            raise ValueError("stable_features must lie in [0, 1]")
        if self.generator_family not in {"zipf_bursty_v1", "renewal_hotset_v1"}:
            raise ValueError("generator_family is unsupported")


@lru_cache(maxsize=256)
def _domain_key(seed: int, domain: str) -> bytes:
    return hashlib.sha256(f"R-TRAPS-{domain}:{seed}".encode()).digest()


def _digest_units(digest: bytes) -> tuple[float, ...]:
    if len(digest) % 8:
        raise ValueError("digest length must be a multiple of eight")
    return tuple(
        int.from_bytes(digest[offset : offset + 8], "big") / 2**64
        for offset in range(0, len(digest), 8)
    )


def _account_profile_value(
    config: SyntheticWorkloadConfig, account_index: int
) -> tuple[float, ...]:
    rank = account_index / max(1, config.account_count - 1)
    digest = hashlib.blake2b(
        str(account_index).encode(),
        key=_domain_key(config.seed, "synthetic-account-profile-v2"),
        digest_size=24,
    ).digest()
    cohort_unit, frozen_retry, verifier_unit = _digest_units(digest)
    cohort = math.floor(cohort_unit * 8) / 7
    verifier_class = float(verifier_unit >= 0.7)
    return rank, cohort, frozen_retry, verifier_class


@lru_cache(maxsize=1_000_000)
def _represented_account_profile(
    config: SyntheticWorkloadConfig, account_index: int
) -> tuple[float, ...]:
    return _account_profile_value(config, account_index)


def _account_profile(config: SyntheticWorkloadConfig, account_index: int) -> tuple[float, ...]:
    # Missing usernames are unique in the generator; retaining their profiles
    # would evict the bounded represented-account working set for no reuse.
    if 0 <= account_index < config.account_count:
        return _represented_account_profile(config, account_index)
    return _account_profile_value(config, account_index)


def _token_and_features(
    config: SyntheticWorkloadConfig,
    account_index: int,
    generation: int,
    version: int,
    tuple_name: str,
    is_current: bool,
) -> tuple[str, tuple[float, ...]]:
    scope = f"{account_index}:{generation}:{version}:{tuple_name}"
    scope_bytes = scope.encode()
    token = hashlib.blake2b(
        scope_bytes,
        key=_domain_key(config.seed, "synthetic-token-v2"),
        digest_size=16,
    ).hexdigest()
    rank, cohort, frozen_retry, verifier_class = _account_profile(config, account_index)

    feature_digest = hashlib.blake2b(
        scope_bytes,
        key=_domain_key(config.seed, "synthetic-candidate-features-v2"),
        digest_size=24,
    ).digest()
    base_length, base_digit, base_symbol = _digest_units(feature_digest)
    if config.family == "zipf_bursty_v1":
        length = (0.40 + 0.55 * base_length) if is_current else (0.10 + 0.75 * base_length)
        digit = (0.08 + 0.35 * base_digit) if is_current else (0.02 + 0.55 * base_digit)
        symbol = (0.08 + 0.30 * base_symbol) if is_current else (0.01 + 0.42 * base_symbol)
    else:
        # A separately parameterized, overlapping distribution creates a real
        # cross-generator shift without exposing the label as a feature.
        length = (0.25 + 0.65 * base_length) if is_current else (0.30 + 0.65 * base_length)
        digit = (0.03 + 0.50 * base_digit) if is_current else (0.05 + 0.44 * base_digit)
        symbol = (0.02 + 0.45 * base_symbol) if is_current else (0.10 + 0.35 * base_symbol)
    features = (
        rank,
        cohort,
        frozen_retry,
        min(1.0, length),
        min(1.0, digit),
        min(1.0, symbol),
        verifier_class,
    )
    return token, features


def _scope(config: SyntheticWorkloadConfig, event_index: int, account: int) -> tuple[int, int]:
    generation = 1 + (event_index + account * 15485863) // config.churn_period_events
    version = 1 + (event_index + account * 32452843) // config.rotation_period_events
    return int(generation), int(version)


def _event(
    config: SyntheticWorkloadConfig,
    event_index: int,
    timestamp_ms: int,
    account: int,
    kind: str,
    tuple_name: str,
) -> AuthEvent:
    generation, version = _scope(config, event_index, account)
    is_current = kind == VALID_CURRENT_CREDENTIAL
    token, features = _token_and_features(
        config, account, generation, version, tuple_name, is_current
    )
    age_events = (event_index + account * 32452843) % config.rotation_period_events
    age_fraction = age_events / config.rotation_period_events
    if kind == VALID_CURRENT_CREDENTIAL:
        result = "MATCH"
        source, device = 3, 3
    elif kind == NO_ACCOUNT:
        result = "NO_ACCOUNT"
        source, device = 0, 0
    elif kind == INVALID_REPEATED_TUPLE:
        result = "CREDENTIAL_MISMATCH"
        source = 2 + int(int(token[:8], 16) / 2**32 >= 0.5)
        device = 1 + int(2 * (int(token[8:16], 16) / 2**32))
    else:
        result = "CREDENTIAL_MISMATCH"
        source, device = 1, 0
    verifier_weight = 2.0 if features[-1] else 1.0
    event = AuthEvent(
        event_id=f"{config.family}-{config.seed:016x}-{event_index:012d}",
        event_index=event_index,
        relative_timestamp_ms=timestamp_ms,
        account_index=account,
        account_generation=generation,
        credential_set_version=version,
        submitted_credential_token=token,
        label=kind,
        backend_result_type=result,
        stable_features=features,
        coarse_source_continuity=source,
        coarse_device_continuity=device,
        credential_age_fraction=age_fraction,
        rotation_recent=age_fraction < 0.05,
        verifier_cost_weight=verifier_weight,
        generator_family=config.family,
    )
    event.validate()
    return event


def _kind_and_tuple(
    config: SyntheticWorkloadConfig,
    rng: np.random.Generator,
    event_index: int,
    account: int,
    phase_shifted: bool,
) -> tuple[str, str]:
    draw = float(rng.random())
    if draw < config.no_account_fraction:
        return NO_ACCOUNT, f"missing:{event_index}"
    if draw < config.no_account_fraction + config.valid_fraction:
        return VALID_CURRENT_CREDENTIAL, "current"

    frozen_retry = _account_profile(config, account)[2]
    if config.family == "zipf_bursty_v1":
        multiplier = 0.45 + 0.85 * frozen_retry
    else:
        multiplier = 1.25 - 0.75 * frozen_retry
    if phase_shifted:
        multiplier = 1.35 - 0.60 * multiplier
    repeat_probability = min(1.0, config.repeated_invalid_fraction * multiplier)
    if float(rng.random()) < repeat_probability:
        slot_base = (
            config.repeat_slots_per_account
            if not phase_shifted
            else 2 * config.repeat_slots_per_account
        )
        slot = slot_base + int(rng.geometric(0.55) - 1) % config.repeat_slots_per_account
        return INVALID_REPEATED_TUPLE, f"repeat:{slot}"
    return INVALID_DISTINCT_TUPLE, f"distinct:{event_index}"


def _iter_zipf(config: SyntheticWorkloadConfig) -> Iterator[AuthEvent]:
    rng = np.random.default_rng(config.seed)
    ranks = np.arange(1, config.account_count + 1, dtype=np.float64)
    weights = np.power(ranks, -config.zipf_alpha)
    cdf = np.cumsum(weights)
    cdf /= cdf[-1]
    timestamp = 0.0
    for event_index in range(config.event_count):
        account = int(np.searchsorted(cdf, rng.random(), side="left"))
        shifted = event_index >= math.floor(config.event_count * config.drift_fraction)
        if shifted:
            account = config.account_count - 1 - account
        kind, tuple_name = _kind_and_tuple(config, rng, event_index, account, shifted)
        if kind == NO_ACCOUNT:
            account = config.account_count + event_index
        timestamp += float(rng.exponential(1000.0 / config.offered_load_rps))
        yield _event(config, event_index, int(timestamp), account, kind, tuple_name)


def _iter_renewal_hotset(config: SyntheticWorkloadConfig) -> Iterator[AuthEvent]:
    rng = np.random.default_rng(config.seed ^ 0xA5A5A5A5A5A5A5A5)
    hotset_size = min(
        config.account_count,
        max(1, math.ceil(config.account_count * config.hotset_fraction)),
    )
    timestamp = 0.0
    previous_account = int(rng.integers(0, config.account_count))
    for event_index in range(config.event_count):
        epoch = event_index // config.hotset_epoch_events
        hotset_start = (epoch * max(1, hotset_size // 2)) % config.account_count
        draw = float(rng.random())
        if draw < 0.45:
            account = previous_account
        elif draw < 0.90:
            account = (hotset_start + int(rng.integers(0, hotset_size))) % config.account_count
        else:
            account = int(rng.integers(0, config.account_count))
        previous_account = account
        shifted = event_index >= math.floor(config.event_count * config.drift_fraction)
        kind, tuple_name = _kind_and_tuple(config, rng, event_index, account, shifted)
        if kind == NO_ACCOUNT:
            account = config.account_count + event_index
        # Gamma-renewal arrivals are intentionally independent from the Zipf
        # generator's Poisson arrivals.
        timestamp += float(rng.gamma(shape=2.0, scale=500.0 / config.offered_load_rps))
        yield _event(config, event_index, int(timestamp), account, kind, tuple_name)


def iter_workload(config: SyntheticWorkloadConfig) -> Iterator[AuthEvent]:
    config.validate()
    if config.family == "zipf_bursty_v1":
        yield from _iter_zipf(config)
    else:
        yield from _iter_renewal_hotset(config)


def generate_workload(config: SyntheticWorkloadConfig) -> list[AuthEvent]:
    return list(iter_workload(config))


def active_member_snapshot(
    config: SyntheticWorkloadConfig, snapshot_event_index: int
) -> tuple[ActiveCredentialMember, ...]:
    """Reconstruct every represented current credential at an event boundary.

    Synthetic accounts are continuously represented.  Churn changes their
    generation and rotation changes their credential-set version; neither is
    inferred from observed login events.  This API exposes the generator's
    authoritative state transition rule so held-out builders do not guess a
    membership set from whichever accounts happened to appear in a trace.
    """

    config.validate()
    if (
        type(snapshot_event_index) is not int
        or not 0 <= snapshot_event_index <= config.event_count
    ):
        raise ValueError("snapshot_event_index must lie in [0, event_count]")
    members: list[ActiveCredentialMember] = []
    for account_index in range(config.account_count):
        generation, version = _scope(config, snapshot_event_index, account_index)
        token, features = _token_and_features(
            config,
            account_index,
            generation,
            version,
            "current",
            True,
        )
        member = ActiveCredentialMember(
            snapshot_event_index=snapshot_event_index,
            account_index=account_index,
            account_generation=generation,
            credential_set_version=version,
            credential_token=token,
            stable_features=features,
            generator_family=config.family,
        )
        member.validate()
        members.append(member)
    return tuple(members)


def dataset_digest(config: SyntheticWorkloadConfig, events: Sequence[AuthEvent]) -> str:
    """Hash the generator declaration and the exact ordered event identities."""

    config.validate()
    digest = hashlib.sha256(
        json.dumps(asdict(config), sort_keys=True, separators=(",", ":")).encode()
    )
    for expected_index, event in enumerate(events):
        event.validate()
        if event.event_index != expected_index:
            raise ValueError("events must be in contiguous event_index order")
        digest.update(event.event_id.encode())
        digest.update(event.relative_timestamp_ms.to_bytes(8, "big", signed=False))
        digest.update(event.submitted_credential_token.encode())
        digest.update(event.label.encode())
    return digest.hexdigest()


def feature_matrix(events: Sequence[AuthEvent]) -> np.ndarray:
    if not events:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float64)
    for event in events:
        event.validate()
    return np.asarray([event.stable_features for event in events], dtype=np.float64)
