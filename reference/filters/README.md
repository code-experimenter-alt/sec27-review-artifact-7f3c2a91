# Phase 1 filter reference semantics

Every implementation receives the same `ScreenQuery(account_index, token)`.
`token` is the first 128 bits of HMAC-SHA256 over the versioned, length-prefixed
account identity, account generation, credential-set version, and a salted hash
of the exact password bytes. `True` always means **possibly represented: forward
to the backend**. `False` means **definitely not represented: reject locally**.

The reference set contains:

- exact 128-bit and 8/12/16/20/24/32/64-bit per-account PRF tags;
- a global Bloom filter with the configured complete integer `k` and intra-query
  early exit;
- a blocked Bloom filter with one 64-byte (512-bit) block per query;
- a dependency-free, immutable, three-way static Xor filter;
- a packed two-choice Cuckoo filter with insert/delete support and atomic rollback
  when an insertion exhausts its kick budget.

`StaticXorFilter` is not a Binary Fuse implementation and results are labeled
`xor_static_3way`. No Binary Fuse performance or layout claim is made. Cuckoo
deletion is valid only for a token known to have been inserted; as with standard
Cuckoo filters, deleting arbitrary nonmembers after an approximate hit is unsafe.

## Memory accounting

`memory_report().total_bytes` is the compact deployable state: packed payload,
an actual binary metadata header containing all method-specific configuration,
item counts, integer hash counts, hash seeds and format identifiers, plus required
alignment. Every structure uses a packed
`bytearray`, with no Python object per entry. The runner additionally records a
recursive Python resident-size measurement so interpreter overhead is visible
and is never selectively hidden for one method.

Bloom rows record requested/actual `m`, inserted `n`, integer `k`, measured
early-exit probes, the finite-`m` independent-placement prediction, and the
standard exponential prediction. For blocked Bloom, the finite prediction also
averages over the binomial number of members assigned to the selected block.
The analytic formulas model ideal independent placements; the implementation's
keyed double hashing is recorded in every result row so a statistically material
discrepancy must be explained rather than silently normalized.

## Runner

`filter_bench.smoke.yaml` writes disposable output under
`experiments/outputs/scratch/`. `filter_bench.phase1.yaml` contains the checked
E1/E2 grids, ten million distinct nonmembers, and defaults to
`experiments/outputs/raw/`. The runner refuses to replace an existing file unless
`--overwrite` is explicit. Large grids can be split deterministically without
changing run IDs:

```text
python experiments/runners/filter_bench.py \
  --config reference/filters/filter_bench.phase1.yaml \
  --shard-count 16 --shard-index 0
```

Each shard receives a disjoint subset of the seed/parameter Cartesian product and
gets a `.shard-NNNN-of-NNNN.jsonl` suffix when the YAML output path is used.

The checked Phase 1 configuration uses 10 independent construction seeds for
FPR and throughput statistics. Later tail-latency and service experiments require
20 independent trials. Exact and truncated per-account tags have no randomized
construction for a fixed dataset: the runner emits each tag point once with
`seed: null` and never counts copies of that static state as independent samples.
