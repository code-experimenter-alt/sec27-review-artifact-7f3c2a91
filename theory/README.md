# Executable Theory Checks

The proof draft is in `proofs.tex`, with shared notation and randomness rules in
`definitions.md`. Executable validators are evidence against implementation and
algebra mistakes; they do not replace the proofs.

Core commands:

```text
python -m pytest -q tests/theory
python -m theory.t1_finite_validation --instances 10000 --seed 20260805
python -m theory.t2_trace_validation --instances 10000 --seed 20260805
python -m theory.t4b_joint_dp_validation --instances 100 --seed 20260805
python -m theory.t5_probe_validation --instances 100 --queries 20000 --seed 20260805
python -m theory.t4a_sharded_validation --start 0 --count 250 --config experiments/configs/optimizer_t4a_validation.json --output experiments/outputs/raw/t4a_validation_v3/shards/shard-0.jsonl
python -m theory.t4a_aggregate_validation experiments/outputs/raw/t4a_validation_v3/shards --config experiments/configs/optimizer_t4a_validation.json --output experiments/outputs/raw/t4a_validation_v3/summary.json
```

Dirty-tree local smoke (never formal evidence):

```text
python -m theory.t4a_sharded_validation --start 0 --count 5 --config experiments/configs/optimizer_t4a_smoke.json --output experiments/outputs/scratch/t4a-smoke.jsonl
python -m theory.t4a_aggregate_validation experiments/outputs/scratch/t4a-smoke.jsonl --config experiments/configs/optimizer_t4a_smoke.json
```

The T4a sharded runner supports disjoint `--start`/`--count` intervals. The
committed `formal` profile is immutable at 10,000 instances, seed 20260805,
CVXPY on, brute force on with 101 points per dimension, the published numerical
thresholds, and clean-Git provenance. Validation rejects any attempt to lower
one of those fields while retaining the `formal` label. The separate `smoke`
profile must be smaller, may run from a dirty tree, and is marked
`diagnostic_only` by aggregation. Every v3 row records its profile, full commit,
`git_dirty`, config and generator-corpus identifiers, seed, host, and UTC
timestamp. The formal fail-closed aggregation gate requires exactly indices
`0..9999`, one clean commit/config/dataset/seed/profile, complete provenance,
and 10,000 CVXPY and brute-force comparisons. The v3 generator reconstructs
each problem from a 13-significant-digit canonical record so ARM and x86
aggregation replay the same instance. Paths rendered into rows and
summaries are repository-relative.

T4b exposes two deliberately separate certificate paths. The continuous
partition candidate generator minimizes the T4a Lagrangian independently on
every contiguous interval for each memory, compromise, and region-count
multiplier triple. Its shortest-path DP emits partitions, re-solves continuous
T4a for every distinct candidate, and reports per-candidate plus best-candidate
primal gaps against the best weak-duality lower bound. The finite-option dual
instead relaxes resources in a declared `IntervalOption` table; only the exact
resource DP, not that finite dual, establishes optimality over the table.

Resolution doubling requires the complete physical half-step subdivision of
both positive-filter bytes and negative-cache bytes, along with halved resource
and compromise quantums, identical categorical axes, complete Cartesian
tables, and reproduced coarse points. Its formal protocol fixes the scale at
exactly two and the relative-objective threshold at exactly `0.01`; callers
cannot substitute another scale or relax the threshold. The two-stage baseline strictly minimizes
the no-cache stage for every positive-memory budget, retains all exactly tied
binary64 objectives, and optimizes cache only after that selection. Smoke
results do not discharge held-out resolution, the <=1% continuous-partition
gap, or complete-baseline obligations.
