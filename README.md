# Review Artifact

This artifact contains the reference implementation, synthetic experiment
drivers, executable safety tests, and the result summary used by the paper.
It contains no operational credentials or user records.

## Quick Start

Python 3.11 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/verify_results.py
python -m pytest -q \
  tests/model/test_version_safety_model.py \
  tests/unit/test_negative_cache.py \
  tests/unit/test_service_singleflight.py \
  tests/integration/test_service_fault_evidence.py \
  tests/theory/test_t4a_fixed_partition.py
python scripts/make_figures.py
```

The verification script checks the paper-facing result summary and prints the
values used in the evaluation. The selected tests cover version-safe activation,
exception insertion, singleflight, loopback faults, and the fixed-partition
allocator. Generated figures are written to `figures/`.

## Full Experiment Drivers

The service, controlled-replay, model, and timing drivers are under
`experiments/`. Full service and timing collections are CPU-intensive; the
included paper-facing summary lets reviewers inspect the reported outcomes
without rerunning those collections. All workloads are deterministic and
synthetic.

The implementation intentionally distinguishes semantic one-sidedness from
timing indistinguishability. The timing study detected distinguishable failure
paths; the artifact preserves that negative result.

## Layout

- `controlplane/`, `dataplane/`, `service/`: reference implementation.
- `models/`, `reference/`, `theory/`: workload, filter, and optimizer code.
- `experiments/`: runners and analysis code for the reported studies.
- `tests/`: focused correctness and integration tests.
- `results/paper_results.json`: anonymized paper-facing result summary.
- `scripts/`: summary verification and figure generation.

## Scope

The service benchmark is an in-process open-loop experiment and does not measure
network or TLS overhead. The included data do not estimate recurrence in
production authentication traffic. The PreAcher comparison is descriptive
because the systems have different protocols and optimization targets.
