# Adaptive and Replay Baselines

`AdaptiveCuckooFilter` implements the `d=2`, `c=4` Adaptive Cuckoo Filter
construction from Mitzenmacher, Pontarelli, and Reviriego (JEA 2020). It keeps
the paper-required exact backing table in one-to-one correspondence with the
fingerprint slots. A filter positive is adapted only after exact mismatch
feedback, by swapping the colliding item with another cell in the same bucket.
Deletion also requires an exact backing-token match; a fingerprint collision is
never sufficient. The benchmark reports fingerprint and fully provisioned
slot-indexed backing-table memory separately.

The cache policies are resident-bounded exact LFU and an offline Belady
future-reuse oracle. The oracle is a sequential-only upper bound and is never
described as deployable. The data-plane LRU and TinyLFU-style scan-resistant
policies are reused directly. The Python TinyLFU-style counter has no packed,
fixed-memory sketch implementation, so its rows are explicitly excluded from
memory-matched comparisons and report Python policy memory separately.

No telescoping adaptive filter or Adaptive Quotient Filter is implemented in
this phase. A negative cache is not labeled as either structure: both would
require their own faithful layout and update algorithms before comparison.

Primary algorithm source: <https://doi.org/10.1145/3339504>.
