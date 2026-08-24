from __future__ import annotations

import argparse
import random
from collections import defaultdict
from dataclasses import dataclass
from typing import Hashable, Iterable

Identity = Hashable


@dataclass(frozen=True)
class TraceRequest:
    """One invalid request in a realized trace.

    ``confirmation_episode`` changes after eviction or expiry. All requests for a
    sticky identity must carry the same realized static-screen result.
    """

    identity: Identity
    screen_positive: bool
    confirmation_episode: Hashable = 0
    race_extras: int = 0

    def __post_init__(self) -> None:
        if self.race_extras < 0:
            raise ValueError("race_extras must be nonnegative")


@dataclass(frozen=True)
class TupleTraceAccounting:
    identity: Identity
    multiplicity: int
    screen_positive: bool
    confirmation_episodes: int
    eviction_or_expiration_episodes: int
    race_extras: int
    static_backend_checks: int
    adaptive_backend_checks: int
    adaptive_upper_bound: int


@dataclass(frozen=True)
class StickyTraceCertificate:
    per_identity: tuple[TupleTraceAccounting, ...]
    static_backend_checks: int
    adaptive_backend_checks: int
    adaptive_upper_bound: int

    @property
    def bound_holds(self) -> bool:
        return self.adaptive_backend_checks <= self.adaptive_upper_bound


def account_realized_trace(requests: Iterable[TraceRequest]) -> StickyTraceCertificate:
    events = list(requests)
    positive_by_identity: dict[Identity, bool] = {}
    multiplicity: dict[Identity, int] = defaultdict(int)
    episodes: dict[Identity, list[Hashable]] = defaultdict(list)
    seen_episode: dict[Identity, set[Hashable]] = defaultdict(set)
    last_episode: dict[Identity, Hashable] = {}
    race_totals: dict[Identity, int] = defaultdict(int)

    for request in events:
        previous = positive_by_identity.setdefault(request.identity, request.screen_positive)
        if previous != request.screen_positive:
            raise ValueError(f"non-sticky screen result for identity {request.identity!r}")
        multiplicity[request.identity] += 1
        if not request.screen_positive:
            if request.race_extras:
                raise ValueError("a screen-negative request cannot execute backend races")
            continue
        if (
            request.identity in last_episode
            and request.confirmation_episode != last_episode[request.identity]
            and request.confirmation_episode in seen_episode[request.identity]
        ):
            raise ValueError("a confirmation episode token cannot recur after a later episode")
        if request.confirmation_episode not in seen_episode[request.identity]:
            seen_episode[request.identity].add(request.confirmation_episode)
            episodes[request.identity].append(request.confirmation_episode)
            race_totals[request.identity] += request.race_extras
        elif request.race_extras:
            raise ValueError("race extras must be attached to the first request of an episode")
        last_episode[request.identity] = request.confirmation_episode

    rows: list[TupleTraceAccounting] = []
    for identity in sorted(multiplicity, key=repr):
        positive = positive_by_identity[identity]
        episode_count = len(episodes[identity]) if positive else 0
        evictions = max(0, episode_count - 1)
        races = race_totals[identity]
        static = multiplicity[identity] * int(positive)
        adaptive = (episode_count + races) * int(positive)
        upper = int(positive) * (1 + evictions + races)
        rows.append(
            TupleTraceAccounting(
                identity=identity,
                multiplicity=multiplicity[identity],
                screen_positive=positive,
                confirmation_episodes=episode_count,
                eviction_or_expiration_episodes=evictions,
                race_extras=races,
                static_backend_checks=static,
                adaptive_backend_checks=adaptive,
                adaptive_upper_bound=upper,
            )
        )

    return StickyTraceCertificate(
        per_identity=tuple(rows),
        static_backend_checks=sum(row.static_backend_checks for row in rows),
        adaptive_backend_checks=sum(row.adaptive_backend_checks for row in rows),
        adaptive_upper_bound=sum(row.adaptive_upper_bound for row in rows),
    )


def run_random_validation(instances: int, seed: int = 0) -> dict[str, int]:
    if instances <= 0:
        raise ValueError("instances must be positive")
    rng = random.Random(seed)
    maximum_saving = 0
    for _ in range(instances):
        events: list[TraceRequest] = []
        for identity in range(rng.randint(1, 20)):
            positive = bool(rng.getrandbits(1))
            multiplicity = rng.randint(1, 30)
            episode = 0
            for occurrence in range(multiplicity):
                if occurrence and rng.random() < 0.15:
                    episode += 1
                first_in_episode = (
                    occurrence == 0
                    or events[-1].identity != identity
                    or events[-1].confirmation_episode != episode
                )
                extras = (
                    rng.randint(0, 2)
                    if positive and first_in_episode and rng.random() < 0.1
                    else 0
                )
                events.append(TraceRequest(identity, positive, episode, extras))
        certificate = account_realized_trace(events)
        if not certificate.bound_holds:
            raise AssertionError(certificate)
        if certificate.adaptive_backend_checks != certificate.adaptive_upper_bound:
            raise AssertionError(
                "the reconstructed complete trace must attain its accounting bound"
            )
        maximum_saving = max(
            maximum_saving,
            certificate.static_backend_checks - certificate.adaptive_backend_checks,
        )
    return {"instances": instances, "maximum_static_minus_adaptive": maximum_saving}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instances", type=int, default=100)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    print(run_random_validation(args.instances, args.seed))


if __name__ == "__main__":
    main()
