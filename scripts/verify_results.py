#!/usr/bin/env python3
"""Validate and print the paper-facing result summary."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    results = json.loads((ROOT / "results" / "paper_results.json").read_text())

    model = results["model"]
    assert model["canonical_states"] == 40_104
    assert model["login_transitions"] == 401_040
    assert model["structural_false_rejects"] == 0

    replay = results["controlled_replay"]
    assert replay["rows"] == 930
    assert replay["maximum_cacheable_mismatches_per_tuple_episode"] == 1

    service = results["service"]
    for profile in ("pbkdf2_310k", "argon2id_19mib"):
        capacity = service["sustainable_invalid_load"][profile]
        latency = service["legitimate_p99"][profile]
        assert capacity["simultaneous_one_sided_lower_bound"] > 1.5
        assert latency["simultaneous_one_sided_upper_bound"] < 1.05

    timing = results["failure_timing"]
    assert timing["comparisons_at_or_below_auc_boundary"] == 6
    assert timing["distinguishable_comparisons"] == 14
    assert timing["comparisons"] == 20

    preacher = results["preacher_descriptive_comparison"]
    assert preacher["expected_points"] == preacher["observed_points"] == 40
    assert preacher["inferential_comparison"] is False

    print("RESULT_SUMMARY_OK")
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
