from __future__ import annotations

import argparse
import json
import math
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from reference.optimizer.joint_dp import (  # noqa: E402
    IntervalOption,
    OptionGridSpec,
    ReplayEvent,
    build_replay_option_table,
    compare_against_strong_baselines,
    exhaustive_joint_allocation,
    generate_continuous_partition_dual_dp_candidates,
    solve_exact_discretized_joint_dp,
    validate_resolution_doubling,
)


def random_option_table(rng: random.Random, n_bins: int) -> tuple[IntervalOption, ...]:
    options: list[IntervalOption] = []
    for start in range(n_bins):
        for end in range(start + 1, n_bins + 1):
            for variant in range(rng.randint(1, 3)):
                memory = rng.randint(0, 8)
                compromise = rng.randint(0, 10)
                options.append(
                    IntervalOption(
                        start_bin=start,
                        end_bin=end,
                        positive_memory_quanta=variant,
                        cache_quota=rng.randint(0, 3),
                        cache_policy="always",
                        memory_quanta=memory,
                        memory_bytes=memory * 64,
                        compromise_quanta=compromise,
                        compromise_mass=float(compromise),
                        worst_region_epsilon=rng.random(),
                        online_cost=rng.uniform(0.0, 50.0),
                        cost_standard_error=rng.uniform(0.01, 1.0),
                    )
                )
    return tuple(options)


def run_exhaustive_validation(instances: int, seed: int = 0) -> dict[str, float | int]:
    if instances <= 0:
        raise ValueError("instances must be positive")
    rng = random.Random(seed)
    maximum_cost_difference = 0.0
    maximum_state_count = 0
    total_pruned = 0
    completed = 0
    attempts = 0
    while completed < instances:
        attempts += 1
        if attempts > instances * 20:
            raise AssertionError("failed to generate enough feasible random instances")
        n_bins = rng.randint(2, 5)
        options = random_option_table(rng, n_bins)
        parameters = dict(
            n_bins=n_bins,
            memory_budget_quanta=rng.randint(n_bins, n_bins * 7),
            minimum_compromise_quanta=rng.randint(0, n_bins * 5),
            maximum_regions=rng.randint(1, n_bins),
            worst_region_epsilon_cap=rng.uniform(0.35, 1.0),
        )
        try:
            dynamic = solve_exact_discretized_joint_dp(options, **parameters)
            exhaustive = exhaustive_joint_allocation(options, **parameters)
        except ValueError:
            continue
        difference = abs(dynamic.online_cost - exhaustive.online_cost)
        if difference > 1e-10:
            raise AssertionError(
                {"parameters": parameters, "dynamic": dynamic, "exhaustive": exhaustive}
            )
        maximum_cost_difference = max(maximum_cost_difference, difference)
        maximum_state_count = max(maximum_state_count, dynamic.statistics.maximum_frontier_size)
        total_pruned += dynamic.statistics.pruned_labels
        completed += 1
    return {
        "instances": completed,
        "attempts": attempts,
        "maximum_cost_difference": maximum_cost_difference,
        "maximum_frontier_size": maximum_state_count,
        "total_pruned_labels": total_pruned,
    }


def run_replay_smoke() -> dict[str, float | int]:
    events = [
        ReplayEvent(
            timestamp=float(index),
            bin_index=index % 3,
            identity=f"x{index % 7}",
            race_extras=int(index % 13 == 0),
        )
        for index in range(60)
    ]
    intervals = [(start, end) for start in range(3) for end in range(start + 1, 4)]
    table = build_replay_option_table(
        events,
        intervals=intervals,
        occupancy_by_bin=[20.0, 18.0, 22.0],
        compromise_weight_by_bin=[4.0, 5.0, 6.0],
        interval_beta={interval: 0.5 for interval in intervals},
        positive_memory_choices=[0, 1, 2],
        cache_quota_choices=[0, 2],
        cache_policies=["always", "second_hit"],
        seeds=[11, 17, 23, 29],
        positive_quantum_bytes=16,
        cache_entry_bytes=8,
        resource_quantum_bytes=8,
        compromise_quantum=0.1,
        ttl=15.0,
    )
    solution = solve_exact_discretized_joint_dp(
        table,
        n_bins=3,
        memory_budget_quanta=14,
        minimum_compromise_quanta=20,
        maximum_regions=3,
        worst_region_epsilon_cap=1.0,
    )
    exhaustive = exhaustive_joint_allocation(
        table,
        n_bins=3,
        memory_budget_quanta=14,
        minimum_compromise_quanta=20,
        maximum_regions=3,
        worst_region_epsilon_cap=1.0,
    )
    if not math.isclose(solution.online_cost, exhaustive.online_cost, abs_tol=1e-12):
        raise AssertionError((solution, exhaustive))
    return {
        "options": len(table),
        "selected_regions": solution.regions_used,
        "selected_online_cost": solution.online_cost,
        "selected_cost_standard_error": solution.cost_standard_error,
        "generated_labels": solution.statistics.generated_labels,
        "pruned_labels": solution.statistics.pruned_labels,
        "maximum_frontier_size": solution.statistics.maximum_frontier_size,
    }


def run_resolution_and_baseline_smoke() -> dict[str, object]:
    events = [
        ReplayEvent(
            timestamp=float(index),
            bin_index=index % 3,
            identity=f"sticky-{(index * 7) % 41}",
            race_extras=int(index % 47 == 0),
        )
        for index in range(360)
    ]
    intervals = [(start, end) for start in range(3) for end in range(start + 1, 4)]
    common = {
        "events": events,
        "intervals": intervals,
        "occupancy_by_bin": [180.0, 210.0, 195.0],
        "compromise_weight_by_bin": [5.0, 6.0, 7.0],
        "interval_beta": {interval: 0.55 for interval in intervals},
        "cache_policies": ["always", "second_hit"],
        "seeds": [101, 103, 107, 109, 113, 127, 131, 137],
        "cache_entry_bytes": 8,
        "ttl": 45.0,
    }
    coarse = build_replay_option_table(
        **common,
        positive_memory_choices=list(range(7)),
        cache_quota_choices=[0, 2, 4],
        positive_quantum_bytes=16,
        resource_quantum_bytes=16,
        compromise_quantum=0.2,
    )
    fine = build_replay_option_table(
        **common,
        positive_memory_choices=list(range(13)),
        cache_quota_choices=list(range(5)),
        positive_quantum_bytes=8,
        resource_quantum_bytes=8,
        compromise_quantum=0.1,
    )
    resolution = validate_resolution_doubling(
        coarse,
        fine,
        n_bins=3,
        coarse_grid=OptionGridSpec(
            intervals=tuple(intervals),
            positive_memory_choices=tuple(range(7)),
            cache_quota_choices=(0, 2, 4),
            cache_policies=("always", "second_hit"),
            positive_quantum_bytes=16,
            cache_entry_bytes=8,
            resource_quantum_bytes=16,
            compromise_quantum=0.2,
        ),
        fine_grid=OptionGridSpec(
            intervals=tuple(intervals),
            positive_memory_choices=tuple(range(13)),
            cache_quota_choices=tuple(range(5)),
            cache_policies=("always", "second_hit"),
            positive_quantum_bytes=8,
            cache_entry_bytes=8,
            resource_quantum_bytes=8,
            compromise_quantum=0.1,
        ),
        coarse_memory_budget_quanta=10,
        fine_memory_budget_quanta=20,
        coarse_minimum_compromise_quanta=20,
        fine_minimum_compromise_quanta=40,
        maximum_regions=3,
    )
    baselines = compare_against_strong_baselines(
        fine,
        n_bins=3,
        memory_budget_quanta=20,
        minimum_compromise_quanta=40,
        maximum_regions=3,
    )
    return {
        "resolution_doubling": {
            "coarse_objective": resolution.coarse_solution.online_cost,
            "fine_objective": resolution.fine_solution.online_cost,
            "relative_objective_change": resolution.relative_objective_change,
            "threshold": resolution.threshold,
            "resource_scale": resolution.resource_scale,
            "coarse_resource_quantum_bytes": (resolution.coarse_resource_quantum_bytes),
            "fine_resource_quantum_bytes": resolution.fine_resource_quantum_bytes,
            "coarse_compromise_quantum": resolution.coarse_compromise_quantum,
            "fine_compromise_quantum": resolution.fine_compromise_quantum,
            "coarse_option_count": resolution.coarse_option_count,
            "fine_option_count": resolution.fine_option_count,
            "coarse_options_nested_in_fine": resolution.coarse_options_nested_in_fine,
            "status": "PASS" if resolution.passed else "FAIL",
        },
        "strong_baselines": {
            "joint_objective": baselines.joint_solution.online_cost,
            "finite_option_dual_dp_lower_bound": (baselines.dual_certificate.dual_lower_bound),
            "finite_option_dual_dp_candidate_upper_bound": (
                baselines.dual_certificate.candidate_upper_bound
            ),
            "finite_option_dual_dp_certified_relative_gap": (
                baselines.dual_certificate.certified_relative_gap
            ),
            "finite_option_dual_dp_relative_gap_denominator": (
                baselines.dual_certificate.relative_gap_denominator
            ),
            "finite_option_dual_dp_multiplier_pairs": (
                baselines.dual_certificate.evaluated_multiplier_pairs
            ),
            "global_filter_objective": baselines.global_filter_solution.online_cost
            if baselines.global_filter_solution is not None
            else None,
            "two_stage_objective": baselines.two_stage.solution.online_cost
            if baselines.two_stage is not None
            else None,
            "joint_reduction_vs_global": baselines.joint_reduction_vs_global,
            "joint_reduction_vs_two_stage": baselines.joint_reduction_vs_two_stage,
            "unavailable_baselines": list(baselines.unavailable_baselines),
        },
    }


def run_continuous_partition_dual_smoke() -> dict[str, object]:
    n_bins = 3
    interval_beta = {
        (start, end): (10.0 if end - start == 1 else 0.1)
        for start in range(n_bins)
        for end in range(start + 1, n_bins + 1)
    }
    certificate = generate_continuous_partition_dual_dp_candidates(
        member_occupancy_by_bin=(10.0, 10.0, 10.0),
        online_weight_by_bin=(10.0, 1.0, 10.0),
        compromise_weight_by_bin=(1.0, 1.0, 1.0),
        interval_beta=interval_beta,
        memory_budget=300.0,
        work_factor_floor=0.0,
        maximum_regions=2,
        epsilon_min=0.5,
        epsilon_cap=0.5,
        memory_multipliers=(0.0,),
        compromise_multipliers=(0.0,),
        region_count_penalties=(0.0, 1_000.0),
    )
    return {
        "certificate_kind": "continuous-partition-t4a-lagrangian",
        "evaluated_multiplier_triples": certificate.evaluated_multiplier_triples,
        "distinct_partitions_resolved": certificate.distinct_partitions_resolved,
        "candidate_region_counts": sorted(
            len(candidate.partition) for candidate in certificate.candidates
        ),
        "dual_lower_bound": certificate.dual_lower_bound,
        "candidate_upper_bound": certificate.candidate_upper_bound,
        "certified_relative_gap": certificate.certified_relative_gap,
        "relative_gap_denominator": certificate.relative_gap_denominator,
        "candidate_primal_relative_gaps": [
            candidate.certified_relative_gap_to_best_dual for candidate in certificate.candidates
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--instances", type=int, default=100)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    print(
        json.dumps(
            {
                "exhaustive_validation": run_exhaustive_validation(args.instances, args.seed),
                "replay_smoke": run_replay_smoke(),
                "resolution_and_baseline_smoke": run_resolution_and_baseline_smoke(),
                "continuous_partition_dual_smoke": (run_continuous_partition_dual_smoke()),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
