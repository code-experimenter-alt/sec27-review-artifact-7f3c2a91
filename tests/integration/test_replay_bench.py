from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from experiments.runners import replay_bench as replay_runner
from experiments.runners import replay_e4_aggregate as replay_aggregate
from experiments.runners.filter_bench import RESULT_SCHEMA, SyntheticCredentialSet
from experiments.runners.replay_bench import (
    EXPECTED_FORMAL_POINTS_PER_SEED,
    EXPECTED_FORMAL_ROWS,
    REQUIRED_METHODS,
    REQUIRED_MULTIPLICITIES,
    _build_screen,
    _enforce_git_policy,
    _validate_screen_load,
    expected_points,
    load_config,
    run_config,
    write_rows,
)
from experiments.runners.replay_e4_aggregate import EvidenceValidationError, aggregate_rows

ROOT = Path(__file__).resolve().parents[2]
SMOKE_CONFIG = ROOT / "experiments" / "configs" / "replay_smoke.yaml"
FULL_CONFIG = ROOT / "experiments" / "configs" / "replay_e4.yaml"


@pytest.fixture(scope="module")
def smoke_rows() -> list[dict]:
    return run_config(SMOKE_CONFIG)


def _one(rows: list[dict], method: str, scenario: str, multiplicity: int) -> dict:
    matches = [
        row
        for row in rows
        if row["method"] == method
        and row["scenario"] == scenario
        and row["replay_multiplicity"] == multiplicity
    ]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.integration
def test_smoke_replays_observed_false_positives_and_emits_common_schema(
    smoke_rows: list[dict],
) -> None:
    assert len(smoke_rows) == 40
    assert {row["method"] for row in smoke_rows} == {
        "static_cuckoo_no_cache",
        "static_cuckoo_exact_lru",
        "static_cuckoo_exact_lfu",
        "static_cuckoo_tinylfu_style_scan_resistant",
        "static_cuckoo_fixed_ttl_exact_lru",
        "static_cuckoo_offline_future_reuse_oracle",
        "adaptive_cuckoo_d2_c4_no_negative_cache",
    }
    assert all(set(RESULT_SCHEMA) <= set(row) for row in smoke_rows)
    assert all(row["selection_conditioned_on_observed_false_positive"] for row in smoke_rows)
    assert all(row["false_positive_discovery_count"] > 0 for row in smoke_rows)
    assert all(row["member_false_negatives"] == 0 for row in smoke_rows)
    assert all(row["filter_load_acceptance_pass"] for row in smoke_rows)
    assert all(row["hostname"] for row in smoke_rows)
    assert all("git_dirty" in row for row in smoke_rows)
    assert all(
        row["filter_load_delta_from_target"]
        == pytest.approx(row["filter_actual_load"] - row["filter_target_load"])
        for row in smoke_rows
    )


@pytest.mark.integration
def test_resident_cache_and_singleflight_bound_backend_work(
    smoke_rows: list[dict],
) -> None:
    static = _one(
        smoke_rows,
        "static_cuckoo_no_cache",
        "e4_resident_capacity_sequential",
        10,
    )
    sequential = _one(
        smoke_rows,
        "static_cuckoo_exact_lru",
        "e4_resident_capacity_sequential",
        10,
    )
    concurrent = _one(
        smoke_rows,
        "static_cuckoo_exact_lru",
        "e4_resident_capacity_concurrent",
        10,
    )
    assert static["backend_invalid_checks"] == static["event_count"] == 40
    assert sequential["backend_invalid_checks"] == sequential["distinct_invalid_count"]
    assert sequential["cache_hits"] == 36
    assert concurrent["backend_invalid_checks"] == concurrent["distinct_invalid_count"]
    assert concurrent["singleflight_suppressed"] > 0
    assert concurrent["singleflight_peak_waiters"] > 0
    assert concurrent["singleflight_per_waiter_state_bytes"] is None
    assert concurrent["singleflight_waiter_queue_peak_bytes"] == 0
    assert concurrent["singleflight_overlap_model"] == "frozen_batch_by_concurrency_width"
    assert "not measured" in concurrent["singleflight_waiter_memory_scope"]


@pytest.mark.integration
def test_churn_quotas_and_adaptive_updates_are_exercised(
    smoke_rows: list[dict],
) -> None:
    churn = _one(
        smoke_rows,
        "static_cuckoo_exact_lru",
        "e4_over_capacity_churn_sequential",
        10,
    )
    quota = _one(
        smoke_rows,
        "static_cuckoo_exact_lru",
        "e4_per_account_quota_sequential",
        10,
    )
    adaptive = _one(
        smoke_rows,
        "adaptive_cuckoo_d2_c4_no_negative_cache",
        "e4_resident_capacity_sequential",
        10,
    )
    assert churn["cache_evictions"] > 0
    assert churn["cache_global_quota_pressure"] > 0
    assert quota["cache_account_quota_pressure"] > 0
    assert adaptive["adaptive_updates"] > 0
    assert adaptive["adaptive_invariant_checks"] >= 2
    assert adaptive["adaptive_invariant_violations"] == 0
    assert adaptive["trace_summary"]["generated_request_rate_per_second"] > 0
    assert adaptive["trace_summary"]["generated_distinct_tuple_rate_per_second"] > 0
    assert "telescoping" not in adaptive["method"]
    assert "quotient" not in adaptive["method"]


@pytest.mark.integration
def test_smoke_never_claims_g2_and_jsonl_is_strict(smoke_rows: list[dict], tmp_path: Path) -> None:
    assert all(not row["g2_gate_eligible_row"] for row in smoke_rows)
    assert all(row["g2_row_criteria_pass"] is None for row in smoke_rows)
    assert all(row["g2_legitimate_p99_regression_le_5pct"] is None for row in smoke_rows)
    assert all(row["legitimate_p99_ms"] is None for row in smoke_rows)
    assert all(
        row["g2_gate_status"] == "BLOCKED_PENDING_PHASE1_AND_E7" for row in smoke_rows
    )
    output = tmp_path / "smoke.jsonl"
    write_rows(output, smoke_rows, overwrite=False)
    assert len(output.read_text(encoding="utf-8").splitlines()) == len(smoke_rows)


@pytest.mark.integration
def test_oracle_is_sequential_only_and_has_exact_schedule(
    smoke_rows: list[dict],
) -> None:
    oracle_rows = [
        row for row in smoke_rows if row["method"] == "static_cuckoo_offline_future_reuse_oracle"
    ]
    assert oracle_rows
    assert all(row["replay_mode"] == "sequential" for row in oracle_rows)
    assert all(row["oracle_schedule_alignment_mismatches"] == 0 for row in oracle_rows)
    assert all(row["oracle_schedule_valid"] for row in oracle_rows)
    assert all(row["oracle_deployable"] is False for row in oracle_rows)
    assert all(not row["g2_replay_component_eligible"] for row in oracle_rows)


@pytest.mark.integration
def test_memory_accounting_and_source_metadata_are_explicit(
    smoke_rows: list[dict],
) -> None:
    lru = next(row for row in smoke_rows if row["cache_policy"] == "lru")
    tinylfu = next(row for row in smoke_rows if row["cache_policy"] == "tinylfu")
    oracle = next(row for row in smoke_rows if row["cache_policy"] == "future_oracle")
    assert lru["memory_cache_bytes"] == (
        lru["memory_cache_entry_compact_bytes"]
        + lru["memory_cache_policy_compact_bytes"]
        + lru["memory_cache_fixed_metadata_bytes"]
    )
    assert lru["memory_cache_policy_python_bytes"] > 0
    assert lru["cache_memory_match_eligible"]
    for unmatched in (tinylfu, oracle):
        assert unmatched["memory_cache_bytes"] is None
        assert unmatched["memory_cache_policy_compact_bytes"] is None
        assert not unmatched["cache_memory_match_eligible"]
        assert unmatched["cache_memory_match_exclusion_reason"]
    for row in smoke_rows:
        if row["cache_policy"] is None:
            assert row["memory_cache_python_bytes"] == 0
            assert row["memory_cache_policy_python_bytes"] == 0
        else:
            assert row["memory_cache_policy_python_bytes"] > 0
            assert (
                row["memory_cache_python_bytes"]
                >= row["memory_cache_policy_python_bytes"]
            )
        assert row["screen_python_bytes"] >= row["memory_filter_bytes"]
        assert row["source_metadata_complete"]
        assert row["source_metadata_schema_version"] == 1
        assert all(row["source_metadata"].values())


@pytest.mark.integration
def test_seed_shards_are_disjoint_and_complete(tmp_path: Path) -> None:
    config = yaml.safe_load(SMOKE_CONFIG.read_text(encoding="utf-8"))
    config["seeds"] = [8100, 8101, 8102, 8103]
    config["methods"] = ["static_no_cache", "lru"]
    config["replay"]["multiplicities"] = [2]
    config["replay"]["modes"] = ["sequential", "concurrent"]
    config["scenarios"] = [config["scenarios"][0]]
    config["scenarios"][0]["multiplicities"] = [2]
    config["scenarios"][0]["modes"] = ["sequential", "concurrent"]
    path = tmp_path / "four-seed-smoke.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    shards = [run_config(path, shard_index=index, shard_count=4) for index in range(4)]
    seed_sets = [{row["seed"] for row in rows} for rows in shards]
    assert seed_sets == [{8100}, {8101}, {8102}, {8103}]
    assert all(len(rows) == 4 for rows in shards)
    merged = [row for rows in shards for row in rows]
    assert len(merged) == 16
    assert len({row["run_id"] for row in merged}) == 16
    assert all(row["shard_count"] == 4 for row in merged)


@pytest.mark.integration
def test_periodic_acf_checks_cover_long_sequential_and_concurrent_replays(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = yaml.safe_load(SMOKE_CONFIG.read_text(encoding="utf-8"))
    config["seeds"] = [8300]
    config["methods"] = ["static_no_cache", "adaptive_cuckoo"]
    config["replay"]["multiplicities"] = [100]
    config["replay"]["modes"] = ["sequential", "concurrent"]
    config["scenarios"] = [config["scenarios"][0]]
    config["scenarios"][0]["multiplicities"] = [100]
    config["scenarios"][0]["modes"] = ["sequential", "concurrent"]
    path = tmp_path / "long-acf-smoke.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    rows = run_config(path)
    assert len(rows) == 4
    adaptive_rows = [row for row in rows if row["screen_kind"] == "adaptive_cuckoo"]
    assert {row["replay_mode"] for row in adaptive_rows} == {"sequential", "concurrent"}
    assert all(row["event_count"] == 400 for row in adaptive_rows)
    assert all(row["adaptive_invariant_checks"] == 3 for row in adaptive_rows)
    assert all(row["adaptive_invariant_violations"] == 0 for row in adaptive_rows)

    observed_replay_queries: dict[object, list[int]] = {}
    original_query = replay_aggregate.AdaptiveCuckooFilter.query
    original_assert = replay_aggregate._reference_assert_adaptive

    def tracking_query(screen, item):
        with screen._lock:
            represented = item.token in screen._keys
        if not represented:
            screen._e4_test_replay_queries = (
                getattr(screen, "_e4_test_replay_queries", 0) + 1
            )
        return original_query(screen, item)

    def observing_assert(screen):
        observed_replay_queries.setdefault(screen, []).append(
            getattr(screen, "_e4_test_replay_queries", 0)
        )
        original_assert(screen)

    monkeypatch.setattr(replay_aggregate.AdaptiveCuckooFilter, "query", tracking_query)
    monkeypatch.setattr(replay_aggregate, "_reference_assert_adaptive", observing_assert)
    assert aggregate_rows(rows, path)["integrity_status"] == "PASS"
    assert sorted(observed_replay_queries.values()) == [
        [0, 256, 400],
        [0, 256, 400],
    ]


def test_full_config_has_all_required_methods_multiplicities_and_seeds() -> None:
    config, _ = load_config(FULL_CONFIG)
    assert config["evidence_tier"] == "formal_replay"
    assert config["require_clean_git"] is True
    assert len(config["seeds"]) == 10
    assert REQUIRED_METHODS <= set(config["methods"])
    configured_multiplicities = {
        int(value)
        for scenario in config["scenarios"]
        for value in scenario.get("multiplicities", config["replay"]["multiplicities"])
    }
    assert REQUIRED_MULTIPLICITIES <= configured_multiplicities
    points = expected_points(config)
    assert len(points) == EXPECTED_FORMAL_ROWS == 930
    assert len(points) // len(config["seeds"]) == EXPECTED_FORMAL_POINTS_PER_SEED == 93
    assert {
        raw["name"] for raw in config["scenarios"] if raw["name"].startswith("over_capacity")
    } == {"over_capacity_churn_moderate", "over_capacity_churn_severe"}
    assert {
        raw["max_entries_per_account"]
        for raw in config["scenarios"]
        if raw["name"].startswith("per_account_quota")
    } == {1, 4}
    dataset = SyntheticCredentialSet(
        int(config["dataset"]["account_count"]),
        int(config["dataset"]["seed"]),
    )
    members = [dataset.member(index) for index in range(dataset.account_count)]
    for kind in ("static_cuckoo", "adaptive_cuckoo"):
        screen = _build_screen(members, int(config["seeds"][0]), kind, config["filter"])
        actual = _validate_screen_load(screen, config["filter"])
        assert 0.89 <= actual <= 0.91


@pytest.mark.parametrize(
    ("git", "expected_commit", "message"),
    [
        (
            {
                "commit": None,
                "status": None,
                "git_dirty": None,
                "git_error": "unreadable",
            },
            "a" * 40,
            "readable Git provenance",
        ),
        (
            {
                "commit": "a" * 40,
                "status": "?? dirty.py\n",
                "git_dirty": True,
                "git_error": None,
            },
            "a" * 40,
            "clean Git worktree",
        ),
        (
            {"commit": "a" * 40, "status": "", "git_dirty": False, "git_error": None},
            "b" * 40,
            "HEAD differs",
        ),
    ],
)
def test_formal_replay_git_policy_fails_closed(
    git: dict, expected_commit: str, message: str
) -> None:
    with pytest.raises(RuntimeError, match=message):
        _enforce_git_policy(
            {"require_clean_git": True},
            git,
            expected_commit,
        )


def test_formal_runner_cli_requires_expected_commit_and_attestation_output(
    tmp_path: Path,
) -> None:
    output = tmp_path / "formal.jsonl"
    with pytest.raises(RuntimeError, match="explicit trusted"):
        replay_runner.main(["--config", str(FULL_CONFIG), "--output", str(output)])
    with pytest.raises(RuntimeError, match="--attestation-output"):
        replay_runner.main(
            [
                "--config",
                str(FULL_CONFIG),
                "--output",
                str(output),
                "--expected-commit",
                "a" * 40,
            ]
        )


def test_formal_aggregate_cli_requires_expected_commit_and_attestations(
    tmp_path: Path,
) -> None:
    output = tmp_path / "aggregate.json"
    missing_input = tmp_path / "not-read-before-contract-check.jsonl"
    with pytest.raises(EvidenceValidationError, match="explicit trusted"):
        replay_aggregate.main(
            [
                "--config",
                str(FULL_CONFIG),
                "--input",
                str(missing_input),
                "--output",
                str(output),
            ]
        )
    with pytest.raises(EvidenceValidationError, match="--source-attestation"):
        replay_aggregate.main(
            [
                "--config",
                str(FULL_CONFIG),
                "--input",
                str(missing_input),
                "--output",
                str(output),
                "--expected-commit",
                "a" * 40,
            ]
        )


def test_full_replay_config_cannot_disable_clean_git(tmp_path: Path) -> None:
    config = yaml.safe_load(FULL_CONFIG.read_text(encoding="utf-8"))
    config["require_clean_git"] = False
    path = tmp_path / "uncontrolled-full.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    with pytest.raises(ValueError, match="frozen 10x93 contract"):
        load_config(path)
