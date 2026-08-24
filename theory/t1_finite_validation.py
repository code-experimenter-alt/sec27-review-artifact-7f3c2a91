from __future__ import annotations

import argparse
import itertools
import math
import random
from dataclasses import dataclass
from typing import Callable, Hashable, Mapping, Sequence

Identity = Hashable
Predicate = Mapping[Identity, bool] | Callable[[Identity], bool]


def _screen(predicate: Predicate, identity: Identity) -> bool:
    if callable(predicate):
        return bool(predicate(identity))
    return bool(predicate.get(identity, False))


@dataclass(frozen=True)
class SequenceIdentityCertificate:
    guesses_through_success: int
    first_seen_invalid: tuple[Identity, ...]
    offline_survivors: tuple[Identity, ...]
    offline_surviving_occurrences: tuple[Identity, ...]
    online_first_seen_forwarded: tuple[Identity, ...]
    cheap_screen_work: float
    slow_verifier_work: float
    confirmation_work: float

    @property
    def identity_holds(self) -> bool:
        return self.offline_survivors == self.online_first_seen_forwarded

    @property
    def total_offline_work(self) -> float:
        return self.cheap_screen_work + self.slow_verifier_work + self.confirmation_work


def validate_sequence_identity(
    guesses: Sequence[Identity],
    first_correct_index: int,
    predicate: Predicate,
    *,
    cheap_screen_cost: float = 1.0,
    slow_verifier_cost: float = 1.0,
    confirmation_cost: float = 0.0,
) -> SequenceIdentityCertificate:
    """Check the static-screen identity on one realized ordered sequence.

    Repeated invalid identities are represented once in the first-seen lists. Cheap
    screening work still counts every guess through the first correct credential.
    """

    if not 0 <= first_correct_index < len(guesses):
        raise ValueError("first_correct_index must identify an element of guesses")
    if min(cheap_screen_cost, slow_verifier_cost, confirmation_cost) < 0:
        raise ValueError("costs must be nonnegative")

    seen: set[Identity] = set()
    first_seen: list[Identity] = []
    for identity in guesses[:first_correct_index]:
        if identity not in seen:
            seen.add(identity)
            first_seen.append(identity)

    offline = tuple(identity for identity in first_seen if _screen(predicate, identity))

    # A static online screen evaluates the same realized predicate. Only the first
    # arrival of an identity is retained here because later requests are not new guesses.
    online_seen: set[Identity] = set()
    online: list[Identity] = []
    for identity in guesses[:first_correct_index]:
        if identity in online_seen:
            continue
        online_seen.add(identity)
        if _screen(predicate, identity):
            online.append(identity)

    return SequenceIdentityCertificate(
        guesses_through_success=first_correct_index + 1,
        first_seen_invalid=tuple(first_seen),
        offline_survivors=offline,
        online_first_seen_forwarded=tuple(online),
        cheap_screen_work=(first_correct_index + 1) * cheap_screen_cost,
        offline_surviving_occurrences=tuple(
            identity
            for identity in guesses[:first_correct_index]
            if _screen(predicate, identity)
        ),
        slow_verifier_work=sum(
            _screen(predicate, identity) for identity in guesses[:first_correct_index]
        )
        * slow_verifier_cost,
        confirmation_work=confirmation_cost,
    )


def _validate_distribution(distribution: Mapping[Identity, float], name: str) -> None:
    if not distribution:
        raise ValueError(f"{name} must not be empty")
    if any((not math.isfinite(float(value))) or value < 0 for value in distribution.values()):
        raise ValueError(f"{name} contains a negative or non-finite probability")
    if not math.isclose(sum(distribution.values()), 1.0, rel_tol=0.0, abs_tol=1e-12):
        raise ValueError(f"{name} must sum to one")


def predicate_expectation(
    distribution: Mapping[Identity, float], predicate: Predicate
) -> float:
    _validate_distribution(distribution, "distribution")
    return math.fsum(
        probability
        for identity, probability in distribution.items()
        if _screen(predicate, identity)
    )


def total_variation(
    online: Mapping[Identity, float], offline: Mapping[Identity, float]
) -> float:
    _validate_distribution(online, "online")
    _validate_distribution(offline, "offline")
    support = set(online) | set(offline)
    return 0.5 * math.fsum(abs(online.get(x, 0.0) - offline.get(x, 0.0)) for x in support)


@dataclass(frozen=True)
class DistributionCertificate:
    phi_online: float
    phi_offline: float
    total_variation: float
    density_ratio_alpha: float
    density_ratio_upper_bound: float

    @property
    def tv_bound_holds(self) -> bool:
        return abs(self.phi_online - self.phi_offline) <= self.total_variation + 1e-12

    @property
    def density_ratio_bound_holds(self) -> bool:
        return self.phi_online <= self.density_ratio_upper_bound + 1e-12


def validate_distributional_bound(
    online: Mapping[Identity, float],
    offline: Mapping[Identity, float],
    predicate: Predicate,
) -> DistributionCertificate:
    phi_online = predicate_expectation(online, predicate)
    phi_offline = predicate_expectation(offline, predicate)
    positive_online = [x for x, probability in online.items() if probability > 0]
    alpha = min(offline.get(x, 0.0) / online[x] for x in positive_online)
    density_upper = math.inf if alpha == 0 else min(1.0, phi_offline / alpha)
    return DistributionCertificate(
        phi_online=phi_online,
        phi_offline=phi_offline,
        total_variation=total_variation(online, offline),
        density_ratio_alpha=alpha,
        density_ratio_upper_bound=density_upper,
    )


def exhaustive_tv_witness(
    online: Mapping[Identity, float], offline: Mapping[Identity, float]
) -> tuple[float, tuple[Identity, ...]]:
    """Enumerate all predicates and return the largest expectation difference."""

    _validate_distribution(online, "online")
    _validate_distribution(offline, "offline")
    support = tuple(sorted(set(online) | set(offline), key=repr))
    if len(support) > 20:
        raise ValueError("exhaustive predicate enumeration is limited to 20 identities")
    best_gap = -1.0
    best_subset: tuple[Identity, ...] = ()
    for bits in itertools.product((False, True), repeat=len(support)):
        subset = tuple(
            x for x, selected in zip(support, bits, strict=True) if selected
        )
        gap = abs(sum(online.get(x, 0.0) - offline.get(x, 0.0) for x in subset))
        if gap > best_gap:
            best_gap = gap
            best_subset = subset
    return best_gap, best_subset


def realized_intersection_probability(
    distribution: Mapping[Identity, float], snapshots: Sequence[Predicate]
) -> float:
    _validate_distribution(distribution, "distribution")
    if not snapshots:
        return 1.0
    return math.fsum(
        probability
        for identity, probability in distribution.items()
        if all(_screen(snapshot, identity) for snapshot in snapshots)
    )


def expected_independent_snapshot_intersection(
    distribution: Mapping[Identity, float],
    per_snapshot_survival: Sequence[Mapping[Identity, float]],
) -> float:
    """Expected survivor mass under construction-independent snapshots.

    Probabilities are multiplied per identity before averaging over the query model;
    the product of aggregate snapshot FPRs is generally not the same quantity.
    """

    _validate_distribution(distribution, "distribution")
    if not per_snapshot_survival:
        return 1.0
    total = 0.0
    for identity, query_probability in distribution.items():
        product = 1.0
        for snapshot in per_snapshot_survival:
            probability = float(snapshot.get(identity, 0.0))
            if not 0.0 <= probability <= 1.0:
                raise ValueError("snapshot survival probabilities must lie in [0, 1]")
            product *= probability
        total += query_probability * product
    return total


@dataclass(frozen=True)
class SnapshotSimulation:
    expected_survivor_probability: float
    empirical_survivor_probability: float
    trials: int
    standard_error: float


def simulate_independent_snapshot_intersection(
    distribution: Mapping[Identity, float],
    per_snapshot_survival: Sequence[Mapping[Identity, float]],
    *,
    trials: int,
    seed: int = 0,
) -> SnapshotSimulation:
    if trials <= 0:
        raise ValueError("trials must be positive")
    expected = expected_independent_snapshot_intersection(distribution, per_snapshot_survival)
    rng = random.Random(seed)
    identities = tuple(distribution)
    cumulative: list[float] = []
    running = 0.0
    for identity in identities:
        running += distribution[identity]
        cumulative.append(running)
    cumulative[-1] = 1.0

    survived = 0
    for _ in range(trials):
        draw = rng.random()
        identity = identities[next(i for i, cutoff in enumerate(cumulative) if draw <= cutoff)]
        if all(rng.random() < snapshot.get(identity, 0.0) for snapshot in per_snapshot_survival):
            survived += 1
    empirical = survived / trials
    stderr = math.sqrt(expected * (1.0 - expected) / trials)
    return SnapshotSimulation(expected, empirical, trials, stderr)


def run_random_validation(instances: int, seed: int = 0) -> dict[str, float | int]:
    if instances <= 0:
        raise ValueError("instances must be positive")
    rng = random.Random(seed)
    maximum_tv_residual = -math.inf
    for _ in range(instances):
        size = rng.randint(1, 8)
        support = tuple(range(size))
        on_raw = [rng.expovariate(1.0) for _ in support]
        off_raw = [rng.expovariate(1.0) for _ in support]
        online = {
            x: value / sum(on_raw)
            for x, value in zip(support, on_raw, strict=True)
        }
        offline = {
            x: value / sum(off_raw)
            for x, value in zip(support, off_raw, strict=True)
        }
        predicate = {x: bool(rng.getrandbits(1)) for x in support}
        certificate = validate_distributional_bound(online, offline, predicate)
        if not certificate.tv_bound_holds or not certificate.density_ratio_bound_holds:
            raise AssertionError(certificate)
        maximum_tv_residual = max(
            maximum_tv_residual,
            abs(certificate.phi_online - certificate.phi_offline) - certificate.total_variation,
        )

        guesses = [rng.randrange(size + 2) for _ in range(rng.randint(1, 15))]
        correct_index = rng.randrange(len(guesses))
        sequence = validate_sequence_identity(guesses, correct_index, predicate)
        if not sequence.identity_holds:
            raise AssertionError(sequence)
    return {"instances": instances, "maximum_tv_residual": maximum_tv_residual}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instances", type=int, default=100)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    print(run_random_validation(args.instances, args.seed))


if __name__ == "__main__":
    main()
