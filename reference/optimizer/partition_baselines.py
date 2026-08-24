"""Deterministic fixed-fine-grid partitions for T4b baseline comparisons.

Every cut is an integer boundary between already frozen fine-grid bins.  The
helpers in this module deliberately do not map those boundaries to continuous
score thresholds or certify anything outside the supplied grid.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext
from typing import Sequence

DECIMAL_PRECISION = 80
FIXED_FINE_GRID_DOMAIN = "FIXED_FINE_GRID_ONLY"

DP_KL_METHOD = "dp_kl"
QUANTILE_METHOD = "quantile"
EQUAL_OCCUPANCY_METHOD = "equal_occupancy"

MEMBER_MASS = "member"
EXISTING_INVALID_MASS = "existing_invalid"
MEMBER_VS_EXISTING_INVALID_MASS = "member_vs_existing_invalid"

_METHOD_MASS_BASIS = {
    DP_KL_METHOD: MEMBER_VS_EXISTING_INVALID_MASS,
    QUANTILE_METHOD: EXISTING_INVALID_MASS,
    EQUAL_OCCUPANCY_METHOD: MEMBER_MASS,
}


def _exact_int(value: object, name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{name} must be an exact integer (bool is forbidden)")
    return value


def _positive_bin_count(value: object) -> int:
    n_bins = _exact_int(value, "n_bins")
    if n_bins <= 0:
        raise ValueError("n_bins must be positive")
    return n_bins


def _region_count(value: object, *, n_bins: int, name: str = "regions") -> int:
    regions = _exact_int(value, name)
    if regions <= 0:
        raise ValueError(f"{name} must be positive")
    if regions > n_bins:
        raise ValueError(f"{name} cannot exceed the number of bins")
    return regions


def normalize_counts(counts: Sequence[int], *, name: str) -> tuple[int, ...]:
    """Return immutable nonnegative counts, rejecting bool and coercion."""

    if type(name) is not str or not name:
        raise TypeError("count name must be a nonempty string")
    if isinstance(counts, (str, bytes)):
        raise TypeError(f"{name} must be a sequence of exact integers")
    try:
        normalized = tuple(counts)
    except TypeError as error:
        raise TypeError(f"{name} must be a sequence of exact integers") from error
    if not normalized:
        raise ValueError(f"{name} must contain at least one bin")
    for index, count in enumerate(normalized):
        _exact_int(count, f"{name}[{index}]")
        if count < 0:
            raise ValueError(f"{name}[{index}] must be nonnegative")
    return normalized


def normalize_cuts(
    cuts: Sequence[int], *, n_bins: int, regions: int | None = None
) -> tuple[int, ...]:
    """Canonicalize internal grid cuts; endpoints 0 and ``n_bins`` are implicit."""

    bins = _positive_bin_count(n_bins)
    if isinstance(cuts, (str, bytes)):
        raise TypeError("cuts must be a sequence of exact integers")
    try:
        normalized = tuple(cuts)
    except TypeError as error:
        raise TypeError("cuts must be a sequence of exact integers") from error
    for index, cut in enumerate(normalized):
        _exact_int(cut, f"cuts[{index}]")
        if not 0 < cut < bins:
            raise ValueError("cuts must be internal fine-grid boundaries")
    if tuple(sorted(set(normalized))) != normalized:
        raise ValueError("cuts must be strictly increasing and unique")
    inferred_regions = len(normalized) + 1
    if regions is not None:
        declared_regions = _region_count(regions, n_bins=bins)
        if declared_regions != inferred_regions:
            raise ValueError("regions must equal len(cuts) + 1")
    if inferred_regions > bins:
        raise ValueError("regions cannot exceed the number of bins")
    return normalized


def cuts_to_intervals(
    cuts: Sequence[int], *, n_bins: int, regions: int | None = None
) -> tuple[tuple[int, int], ...]:
    """Convert internal grid cuts to a complete half-open interval partition."""

    bins = _positive_bin_count(n_bins)
    normalized = normalize_cuts(cuts, n_bins=bins, regions=regions)
    points = (0, *normalized, bins)
    return tuple(zip(points, points[1:], strict=False))


def normalize_partition(
    intervals: Sequence[Sequence[int]], *, n_bins: int, regions: int | None = None
) -> tuple[tuple[int, int], ...]:
    """Validate and canonicalize a complete, nonoverlapping fine-grid partition."""

    bins = _positive_bin_count(n_bins)
    if isinstance(intervals, (str, bytes)):
        raise TypeError("partition intervals must be a sequence of integer pairs")
    try:
        raw_intervals = tuple(intervals)
    except TypeError as error:
        raise TypeError("partition intervals must be a sequence of integer pairs") from error
    if not raw_intervals:
        raise ValueError("partition must contain at least one interval")

    normalized: list[tuple[int, int]] = []
    for index, interval in enumerate(raw_intervals):
        if isinstance(interval, (str, bytes)):
            raise TypeError(f"partition interval {index} must be an integer pair")
        try:
            pair = tuple(interval)
        except TypeError as error:
            raise TypeError(f"partition interval {index} must be an integer pair") from error
        if len(pair) != 2:
            raise ValueError(f"partition interval {index} must contain two coordinates")
        start = _exact_int(pair[0], f"partition[{index}].start")
        end = _exact_int(pair[1], f"partition[{index}].end")
        if not 0 <= start < end <= bins:
            raise ValueError("partition intervals must satisfy 0 <= start < end <= n_bins")
        normalized.append((start, end))

    if normalized[0][0] != 0 or normalized[-1][1] != bins:
        raise ValueError("partition must completely cover [0, n_bins)")
    for previous, current in zip(normalized, normalized[1:], strict=False):
        if current[0] > previous[1]:
            raise ValueError("partition contains a gap")
        if current[0] < previous[1]:
            raise ValueError("partition contains overlapping intervals")

    inferred_regions = len(normalized)
    _region_count(inferred_regions, n_bins=bins)
    if regions is not None:
        declared_regions = _region_count(regions, n_bins=bins)
        if declared_regions != inferred_regions:
            raise ValueError("regions must equal the number of partition intervals")
    return tuple(normalized)


def intervals_to_cuts(
    intervals: Sequence[Sequence[int]], *, n_bins: int, regions: int | None = None
) -> tuple[int, ...]:
    """Convert a complete fine-grid interval partition to internal cuts."""

    normalized = normalize_partition(intervals, n_bins=n_bins, regions=regions)
    return tuple(end for _, end in normalized[:-1])


@dataclass(frozen=True)
class FineGridPartitionCandidate:
    """One baseline partition whose boundaries exist only on a frozen fine grid."""

    method: str
    mass_basis: str
    n_bins: int
    regions: int
    cuts: tuple[int, ...]
    intervals: tuple[tuple[int, int], ...]
    kl_objective: Decimal | None = None
    grid_domain: str = FIXED_FINE_GRID_DOMAIN

    def __post_init__(self) -> None:
        bins = _positive_bin_count(self.n_bins)
        region_count = _region_count(self.regions, n_bins=bins)
        if type(self.method) is not str or self.method not in _METHOD_MASS_BASIS:
            raise ValueError("partition method is unsupported")
        if self.mass_basis != _METHOD_MASS_BASIS[self.method]:
            raise ValueError("mass_basis does not match the partition method")
        if self.grid_domain != FIXED_FINE_GRID_DOMAIN:
            raise ValueError("partition candidates are fixed-fine-grid only")
        cuts = normalize_cuts(self.cuts, n_bins=bins, regions=region_count)
        intervals = normalize_partition(self.intervals, n_bins=bins, regions=region_count)
        if cuts_to_intervals(cuts, n_bins=bins) != intervals:
            raise ValueError("cuts and intervals describe different partitions")
        object.__setattr__(self, "cuts", cuts)
        object.__setattr__(self, "intervals", intervals)
        if self.method == DP_KL_METHOD:
            if type(self.kl_objective) is not Decimal or not self.kl_objective.is_finite():
                raise TypeError("DP-KL candidate requires a finite Decimal objective")
        elif self.kl_objective is not None:
            raise ValueError("mass-quantile candidates do not have a KL objective")

    @property
    def continuous_thresholds_certified(self) -> bool:
        return False


def _validated_distributions(
    member_counts: Sequence[int], existing_invalid_counts: Sequence[int]
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    members = normalize_counts(member_counts, name="member_counts")
    invalid = normalize_counts(existing_invalid_counts, name="existing_invalid_counts")
    if len(members) != len(invalid):
        raise ValueError("member and existing-invalid counts must have equal bin counts")
    return members, invalid


def _smoothed_prefix_counts(
    counts: tuple[int, ...],
) -> tuple[tuple[Decimal, ...], Decimal]:
    half = Decimal(1) / Decimal(2)
    atomic = tuple(Decimal(count) + half for count in counts)
    total = sum(atomic, Decimal(0))
    prefix = [Decimal(0)]
    cumulative = Decimal(0)
    for count in atomic:
        cumulative += count
        prefix.append(cumulative)
    return tuple(prefix), total


def _segment_kl(
    member_prefix_counts: tuple[Decimal, ...],
    member_total: Decimal,
    invalid_prefix_counts: tuple[Decimal, ...],
    invalid_total: Decimal,
    start: int,
    end: int,
) -> Decimal:
    member_mass = (member_prefix_counts[end] - member_prefix_counts[start]) / member_total
    invalid_mass = (invalid_prefix_counts[end] - invalid_prefix_counts[start]) / invalid_total
    return member_mass * (member_mass / invalid_mass).ln()


def partition_kl_objective(
    member_counts: Sequence[int],
    existing_invalid_counts: Sequence[int],
    intervals: Sequence[Sequence[int]],
) -> Decimal:
    """Evaluate aggregate segment KL after atomic-bin Jeffreys-half smoothing."""

    members, invalid = _validated_distributions(member_counts, existing_invalid_counts)
    partition = normalize_partition(intervals, n_bins=len(members))
    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        member_prefix, member_total = _smoothed_prefix_counts(members)
        invalid_prefix, invalid_total = _smoothed_prefix_counts(invalid)
        objective = sum(
            (
                _segment_kl(
                    member_prefix,
                    member_total,
                    invalid_prefix,
                    invalid_total,
                    start,
                    end,
                )
                for start, end in partition
            ),
            Decimal(0),
        )
        return +objective


def dp_kl_partition(
    member_counts: Sequence[int],
    existing_invalid_counts: Sequence[int],
    *,
    regions: int,
) -> FineGridPartitionCandidate:
    """Maximize fixed-grid segmented KL with deterministic lexicographic ties.

    ``P`` is the member-count distribution and ``Q`` is the existing-invalid
    distribution.  Jeffreys ``1/2`` smoothing is applied to every atomic bin
    before either distribution is normalized.
    """

    members, invalid = _validated_distributions(member_counts, existing_invalid_counts)
    n_bins = len(members)
    region_count = _region_count(regions, n_bins=n_bins)

    with localcontext() as context:
        context.prec = DECIMAL_PRECISION
        member_prefix, member_total = _smoothed_prefix_counts(members)
        invalid_prefix, invalid_total = _smoothed_prefix_counts(invalid)
        interval_scores = {
            (start, end): _segment_kl(
                member_prefix,
                member_total,
                invalid_prefix,
                invalid_total,
                start,
                end,
            )
            for start in range(n_bins)
            for end in range(start + 1, n_bins + 1)
        }

        previous: dict[int, tuple[Decimal, tuple[int, ...]]] = {0: (Decimal(0), ())}
        for used_regions in range(1, region_count + 1):
            current: dict[int, tuple[Decimal, tuple[int, ...]]] = {}
            for end in range(used_regions, n_bins + 1):
                incumbent: tuple[Decimal, tuple[int, ...]] | None = None
                for start in range(used_regions - 1, end):
                    prefix = previous.get(start)
                    if prefix is None:
                        continue
                    cuts = prefix[1] + ((start,) if start else ())
                    candidate = (prefix[0] + interval_scores[(start, end)], cuts)
                    if (
                        incumbent is None
                        or candidate[0] > incumbent[0]
                        or (candidate[0] == incumbent[0] and candidate[1] < incumbent[1])
                    ):
                        incumbent = candidate
                if incumbent is not None:
                    current[end] = incumbent
            previous = current

        objective, cuts = previous[n_bins]
        objective = +objective
    intervals = cuts_to_intervals(cuts, n_bins=n_bins, regions=region_count)
    return FineGridPartitionCandidate(
        method=DP_KL_METHOD,
        mass_basis=MEMBER_VS_EXISTING_INVALID_MASS,
        n_bins=n_bins,
        regions=region_count,
        cuts=cuts,
        intervals=intervals,
        kl_objective=objective,
    )


def grid_quantile_partition(
    counts: Sequence[int], *, regions: int, method: str = QUANTILE_METHOD
) -> FineGridPartitionCandidate:
    """Place cumulative-mass quantiles on the nearest legal fine-grid boundaries."""

    mass = normalize_counts(counts, name="partition_mass_counts")
    n_bins = len(mass)
    region_count = _region_count(regions, n_bins=n_bins)
    if type(method) is not str or method not in {QUANTILE_METHOD, EQUAL_OCCUPANCY_METHOD}:
        raise ValueError("grid quantile method must be quantile or equal_occupancy")

    prefix = [0]
    for count in mass:
        prefix.append(prefix[-1] + count)
    total = prefix[-1]
    cuts: list[int] = []
    previous = 0
    for quantile_index in range(1, region_count):
        lower = previous + 1
        upper = n_bins - (region_count - quantile_index)
        cut = min(
            range(lower, upper + 1),
            key=lambda candidate: (
                abs(region_count * prefix[candidate] - quantile_index * total),
                candidate,
            ),
        )
        cuts.append(cut)
        previous = cut

    normalized_cuts = tuple(cuts)
    return FineGridPartitionCandidate(
        method=method,
        mass_basis=_METHOD_MASS_BASIS[method],
        n_bins=n_bins,
        regions=region_count,
        cuts=normalized_cuts,
        intervals=cuts_to_intervals(
            normalized_cuts,
            n_bins=n_bins,
            regions=region_count,
        ),
    )


def equal_occupancy_partition(
    member_counts: Sequence[int], *, regions: int
) -> FineGridPartitionCandidate:
    """Partition by member mass while retaining an explicit baseline identity."""

    return grid_quantile_partition(
        member_counts,
        regions=regions,
        method=EQUAL_OCCUPANCY_METHOD,
    )


def derive_partition_candidates(
    member_counts: Sequence[int],
    existing_invalid_counts: Sequence[int],
    *,
    maximum_regions: int,
) -> tuple[FineGridPartitionCandidate, ...]:
    """Derive all three fixed-grid baselines for every ``r`` from 1 through ``K``."""

    members, invalid = _validated_distributions(member_counts, existing_invalid_counts)
    limit = _region_count(maximum_regions, n_bins=len(members), name="maximum_regions")
    candidates: list[FineGridPartitionCandidate] = []
    for regions in range(1, limit + 1):
        candidates.extend(
            (
                dp_kl_partition(members, invalid, regions=regions),
                grid_quantile_partition(invalid, regions=regions, method=QUANTILE_METHOD),
                equal_occupancy_partition(members, regions=regions),
            )
        )
    return tuple(candidates)
