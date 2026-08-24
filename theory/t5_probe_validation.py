from __future__ import annotations

import argparse
import math
import random
from dataclasses import dataclass
from typing import Literal, Sequence

LocationPolicy = Literal["with_replacement", "without_replacement"]


def expected_first_zero_probes(set_probability: float, hashes: int) -> float:
    if not 0.0 <= set_probability <= 1.0:
        raise ValueError("set_probability must lie in [0, 1]")
    if not isinstance(hashes, int) or hashes <= 0:
        raise ValueError("hashes must be a positive integer")
    if set_probability == 1.0:
        return float(hashes)
    return (1.0 - set_probability**hashes) / (1.0 - set_probability)


def finite_without_replacement_expected_probes(
    set_bits: int, total_bits: int, hashes: int
) -> float:
    if not 0 <= set_bits <= total_bits:
        raise ValueError("set_bits must lie in [0, total_bits]")
    if not 1 <= hashes <= total_bits:
        raise ValueError("hashes must lie in [1, total_bits]")
    probability_prefix_set = 1.0
    expected = 0.0
    for prefix in range(hashes):
        if prefix:
            numerator = set_bits - (prefix - 1)
            denominator = total_bits - (prefix - 1)
            probability_prefix_set *= max(0, numerator) / denominator
        expected += probability_prefix_set
    return expected


def expected_multilayer_probes(
    set_probabilities: Sequence[float], hashes_per_layer: Sequence[int]
) -> float:
    if len(set_probabilities) != len(hashes_per_layer):
        raise ValueError("layer arrays must have equal length")
    reach_probability = 1.0
    total = 0.0
    for probability, hashes in zip(
        set_probabilities, hashes_per_layer, strict=True
    ):
        total += reach_probability * expected_first_zero_probes(probability, hashes)
        reach_probability *= probability**hashes
    return total


def query_first_zero(bit_array: Sequence[bool], locations: Sequence[int]) -> tuple[bool, int]:
    probes = 0
    for location in locations:
        probes += 1
        if not bit_array[location]:
            return False, probes
    return True, probes


@dataclass(frozen=True)
class FiniteProbeSimulation:
    total_bits: int
    set_bits: int
    hashes: int
    queries: int
    location_policy: LocationPolicy
    empirical_mean_probes: float
    finite_prediction: float
    independent_bit_prediction: float
    empirical_pass_probability: float
    standard_error: float

    @property
    def prediction_z_score(self) -> float:
        if self.standard_error == 0:
            return 0.0 if self.empirical_mean_probes == self.finite_prediction else math.inf
        return (self.empirical_mean_probes - self.finite_prediction) / self.standard_error


@dataclass(frozen=True)
class ConstructedBloomSimulation:
    total_bits: int
    inserted_items: int
    hashes: int
    constructions: int
    queries_per_construction: int
    mean_set_probability: float
    empirical_mean_probes: float
    conditional_finite_prediction: float
    plug_in_independent_bit_prediction: float
    empirical_pass_probability: float
    repeated_query_location_fraction: float

    @property
    def finite_prediction_gap(self) -> float:
        return self.empirical_mean_probes - self.conditional_finite_prediction

    @property
    def construction_mixture_gap(self) -> float:
        return self.conditional_finite_prediction - self.plug_in_independent_bit_prediction


def simulate_finite_bitmap(
    bit_array: Sequence[bool],
    hashes: int,
    *,
    queries: int,
    seed: int = 0,
    location_policy: LocationPolicy = "with_replacement",
) -> FiniteProbeSimulation:
    total_bits = len(bit_array)
    if total_bits == 0:
        raise ValueError("bit_array must not be empty")
    if not isinstance(hashes, int) or not 1 <= hashes <= total_bits:
        raise ValueError("hashes must be an integer in [1, len(bit_array)]")
    if queries <= 0:
        raise ValueError("queries must be positive")
    if location_policy not in ("with_replacement", "without_replacement"):
        raise ValueError("unknown location policy")

    rng = random.Random(seed)
    probe_sum = 0
    probe_square_sum = 0
    passes = 0
    population = range(total_bits)
    for _ in range(queries):
        if location_policy == "with_replacement":
            locations = [rng.randrange(total_bits) for _ in range(hashes)]
        else:
            locations = rng.sample(population, hashes)
        passed, probes = query_first_zero(bit_array, locations)
        passes += int(passed)
        probe_sum += probes
        probe_square_sum += probes * probes

    mean = probe_sum / queries
    variance = max(0.0, probe_square_sum / queries - mean * mean)
    set_bits = sum(bool(bit) for bit in bit_array)
    p = set_bits / total_bits
    independent = expected_first_zero_probes(p, hashes)
    finite = (
        independent
        if location_policy == "with_replacement"
        else finite_without_replacement_expected_probes(set_bits, total_bits, hashes)
    )
    return FiniteProbeSimulation(
        total_bits=total_bits,
        set_bits=set_bits,
        hashes=hashes,
        queries=queries,
        location_policy=location_policy,
        empirical_mean_probes=mean,
        finite_prediction=finite,
        independent_bit_prediction=independent,
        empirical_pass_probability=passes / queries,
        standard_error=math.sqrt(variance / queries),
    )


def simulate_constructed_bloom(
    *,
    total_bits: int,
    inserted_items: int,
    hashes: int,
    constructions: int,
    queries_per_construction: int,
    seed: int = 0,
    location_policy: LocationPolicy = "with_replacement",
) -> ConstructedBloomSimulation:
    """Run the exact early-exit loop over finite randomly constructed Bloom states."""

    if total_bits <= 0 or inserted_items < 0:
        raise ValueError("total_bits must be positive and inserted_items nonnegative")
    if constructions <= 0 or queries_per_construction <= 0:
        raise ValueError("construction and query counts must be positive")
    if not 1 <= hashes <= total_bits:
        raise ValueError("hashes must lie in [1, total_bits]")
    if location_policy not in ("with_replacement", "without_replacement"):
        raise ValueError("unknown location policy")

    rng = random.Random(seed)
    population = range(total_bits)
    total_probes = 0
    total_passes = 0
    repeated_queries = 0
    set_probabilities: list[float] = []
    conditional_predictions: list[float] = []
    for _ in range(constructions):
        bit_array = [False] * total_bits
        for _ in range(inserted_items):
            locations = (
                [rng.randrange(total_bits) for _ in range(hashes)]
                if location_policy == "with_replacement"
                else rng.sample(population, hashes)
            )
            for location in locations:
                bit_array[location] = True
        set_bits = sum(bit_array)
        set_probability = set_bits / total_bits
        set_probabilities.append(set_probability)
        conditional_predictions.append(
            expected_first_zero_probes(set_probability, hashes)
            if location_policy == "with_replacement"
            else finite_without_replacement_expected_probes(set_bits, total_bits, hashes)
        )
        for _ in range(queries_per_construction):
            locations = (
                [rng.randrange(total_bits) for _ in range(hashes)]
                if location_policy == "with_replacement"
                else rng.sample(population, hashes)
            )
            repeated_queries += int(len(set(locations)) < hashes)
            passed, probes = query_first_zero(bit_array, locations)
            total_passes += int(passed)
            total_probes += probes

    queries = constructions * queries_per_construction
    mean_set_probability = sum(set_probabilities) / constructions
    return ConstructedBloomSimulation(
        total_bits=total_bits,
        inserted_items=inserted_items,
        hashes=hashes,
        constructions=constructions,
        queries_per_construction=queries_per_construction,
        mean_set_probability=mean_set_probability,
        empirical_mean_probes=total_probes / queries,
        conditional_finite_prediction=sum(conditional_predictions) / constructions,
        plug_in_independent_bit_prediction=expected_first_zero_probes(
            mean_set_probability, hashes
        ),
        empirical_pass_probability=total_passes / queries,
        repeated_query_location_fraction=repeated_queries / queries,
    )


def run_random_validation(instances: int, queries: int, seed: int = 0) -> dict[str, float | int]:
    if instances <= 0:
        raise ValueError("instances must be positive")
    rng = random.Random(seed)
    maximum_absolute_z = 0.0
    for instance in range(instances):
        total_bits = rng.randint(8, 128)
        hashes = rng.randint(1, min(12, total_bits))
        bit_array = [rng.random() < rng.uniform(0.05, 0.95) for _ in range(total_bits)]
        policy: LocationPolicy = "with_replacement" if instance % 2 == 0 else "without_replacement"
        result = simulate_finite_bitmap(
            bit_array,
            hashes,
            queries=queries,
            seed=rng.randrange(2**32),
            location_policy=policy,
        )
        maximum_absolute_z = max(maximum_absolute_z, abs(result.prediction_z_score))
    return {
        "instances": instances,
        "queries_per_instance": queries,
        "maximum_absolute_z": maximum_absolute_z,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instances", type=int, default=20)
    parser.add_argument("--queries", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    print(run_random_validation(args.instances, args.queries, args.seed))


if __name__ == "__main__":
    main()
