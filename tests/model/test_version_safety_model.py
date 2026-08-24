from __future__ import annotations

import os
import pathlib
import sys
import tempfile
import unittest
from collections import Counter

MODEL_DIR = pathlib.Path(__file__).resolve().parent
if str(MODEL_DIR) not in sys.path:
    sys.path.insert(0, str(MODEL_DIR))

from randomized import SMOKE_CLASSIFICATION, SMOKE_SCHEMA, smoke_report, write_smoke  # noqa: E402
from version_safety_model import (  # noqa: E402
    COUNTEREXAMPLE_POLICY_ID,
    EDGES,
    FORMAL_EXPECTED_CONCRETE_ACTION_TRANSITIONS,
    FORMAL_EXPECTED_LOGIN_TRANSITIONS,
    FORMAL_EXPECTED_QUOTIENT_STATES,
    FORMAL_EXPECTED_STATE_SET_DIGEST,
    FORMAL_EXPECTED_TRANSITION_DIGEST,
    FORMAL_MAX_MESSAGE_COPIES,
    FORMAL_MAX_NEGATIVE_CACHE_ENTRIES,
    FORMAL_NEGATIVE_CACHE_CAPACITY,
    FORMAL_PENDING_CAPACITY,
    REDUCTION_IDS,
    SafetyViolation,
    VersionSafetyModel,
    canonicalize_formal_state_key,
    explore_formal_state,
    explore_test_fixture,
    formal_reduction_contract,
    run_formal_randomized,
    run_randomized,
)


def _action_observation(
    model: VersionSafetyModel, action: tuple[object, ...]
) -> tuple[object, ...]:
    name = str(action[0])
    if name not in {"delay", "deliver", "drop", "duplicate"}:
        return action
    message = model.pending[int(action[1])]
    scope: object = message[2]
    if model.retired_scope_projection_enabled() and scope in {(1, 1), (1, 2)}:
        scope = "OLD_G1"
    return (name, message[0], message[1], scope)


def _successor_observations(model: VersionSafetyModel) -> Counter[object]:
    observations: Counter[object] = Counter()
    for action in model.available_actions(exhaustive=True):
        child = model.clone()
        result = child.apply(action)
        child.check_invariants()
        observations[(_action_observation(model, action), result, child.state_key())] += 1
    return observations


def _reach_deleted() -> VersionSafetyModel:
    model = VersionSafetyModel(prepare_second_version=True, formal_bounds=True)
    model.publish_delta()
    for edge_id in EDGES:
        model.enqueue("delta-cert", edge_id, model.prepared_scope)
        model.deliver(0)
    model.activate()
    model.delete()
    model.check_invariants()
    return model


def _swap_edges(model: VersionSafetyModel) -> VersionSafetyModel:
    swapped = model.clone()
    swapped.delta_acks = {
        "edge-b" if edge_id == "edge-a" else "edge-a" for edge_id in model.delta_acks
    }
    swapped.compacted_acks = {
        "edge-b" if edge_id == "edge-a" else "edge-a" for edge_id in model.compacted_acks
    }
    swapped.edges = {
        "edge-a": model.edges["edge-b"],
        "edge-b": model.edges["edge-a"],
    }
    swapped.pending = [
        (kind, "edge-b" if edge_id == "edge-a" else "edge-a", scope)
        for kind, edge_id, scope in model.pending
    ]
    return swapped


def _swap_action(action: tuple[object, ...]) -> tuple[object, ...]:
    rename = {"edge-a": "edge-b", "edge-b": "edge-a"}
    if action[0] in {"login", "crash", "restart"}:
        return (action[0], rename[str(action[1])], *action[2:])
    if action[0] == "enqueue":
        return (action[0], action[1], rename[str(action[2])], *action[3:])
    return action


class VersionSafetyModelTests(unittest.TestCase):
    def test_smoke_output_is_explicitly_non_evidence_and_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "smoke.json"
            report = smoke_report(run_randomized(100, 7))
            self.assertEqual(SMOKE_SCHEMA, report["schema"])
            self.assertEqual(SMOKE_CLASSIFICATION, report["execution_classification"])
            self.assertIs(False, report["evidence_eligible"])
            self.assertEqual("BLOCKED_PENDING_SERVICE_FAULT_AND_E9", report["g7_status"])
            self.assertEqual(64, len(report["smoke_id"]))
            write_smoke(path, report)
            self.assertTrue(path.is_file())
            with self.assertRaises(FileExistsError):
                write_smoke(path, report)

    def test_backend_only_crash_window_keeps_current_version_fail_open_valid(self) -> None:
        model = VersionSafetyModel(prepare_second_version=True)
        model.publish_delta()
        for edge in EDGES:
            model.enqueue("delta-cert", edge, model.prepared_scope)
            model.deliver(len(model.pending) - 1)
        model.backend_advance_only()
        model.crash("edge-a")
        self.assertEqual("FAIL_OPEN_MATCH", model.login("edge-a", "g1-v1"))
        model.check_invariants()

    def test_state_key_includes_backend_accepted_and_formal_bounds(self) -> None:
        first = VersionSafetyModel(prepare_second_version=True, formal_bounds=True)
        changed_backend = first.clone()
        changed_backend.backend_accepted[(1, 1)] = frozenset({"different"})
        self.assertNotEqual(first.state_key(), changed_backend.state_key())

        unbounded = VersionSafetyModel(prepare_second_version=True, formal_bounds=False)
        self.assertNotEqual(first.state_key(), unbounded.state_key())

    def test_formal_canonicalization_is_idempotent_and_contract_is_frozen(self) -> None:
        model = _reach_deleted()
        key = model.state_key()
        self.assertEqual(key, canonicalize_formal_state_key(key))
        contract = formal_reduction_contract()
        self.assertEqual(list(REDUCTION_IDS), contract["reduction_ids"])
        self.assertEqual(COUNTEREXAMPLE_POLICY_ID, contract["counterexample_policy"])
        self.assertEqual(FORMAL_NEGATIVE_CACHE_CAPACITY, contract["negative_cache_capacity"])
        self.assertEqual(
            FORMAL_MAX_NEGATIVE_CACHE_ENTRIES,
            contract["maximum_reachable_negative_cache_entries"],
        )
        self.assertLess(FORMAL_MAX_NEGATIVE_CACHE_ENTRIES, FORMAL_NEGATIVE_CACHE_CAPACITY)
        contract["reduction_ids"].clear()
        self.assertEqual(list(REDUCTION_IDS), formal_reduction_contract()["reduction_ids"])

    def test_pending_multiset_and_cache_set_have_congruent_successors(self) -> None:
        pending_first = VersionSafetyModel(prepare_second_version=True, formal_bounds=True)
        pending_first.pending = [
            ("directory", "edge-a", (1, 1)),
            ("delta-cert", "edge-b", (1, 2)),
        ]
        pending_second = pending_first.clone()
        pending_second.pending.reverse()
        self.assertNotEqual(pending_first.raw_state_key(), pending_second.raw_state_key())
        self.assertEqual(pending_first.state_key(), pending_second.state_key())
        self.assertEqual(
            _successor_observations(pending_first),
            _successor_observations(pending_second),
        )

        cache_first = VersionSafetyModel(prepare_second_version=True, formal_bounds=True)
        cache_first.publish_delta()
        for edge_id in EDGES:
            cache_first.enqueue("delta-cert", edge_id, cache_first.prepared_scope)
            cache_first.deliver(0)
        cache_first.backend_advance_only()
        cache_first.negative_cache = [
            ((1, 1), "fp", cache_first.backend_accepted[(1, 1)]),
            ((1, 2), "fp", cache_first.backend_accepted[(1, 2)]),
        ]
        cache_second = cache_first.clone()
        cache_second.negative_cache.reverse()
        cache_first.check_invariants()
        cache_second.check_invariants()
        self.assertNotEqual(cache_first.raw_state_key(), cache_second.raw_state_key())
        self.assertEqual(cache_first.state_key(), cache_second.state_key())
        self.assertEqual(
            _successor_observations(cache_first),
            _successor_observations(cache_second),
        )

    def test_retired_g1_projection_is_gated_and_future_congruent(self) -> None:
        live_first = VersionSafetyModel(prepare_second_version=True, formal_bounds=True)
        live_second = live_first.clone()
        live_second.edges["edge-a"].view_scope = (1, 2)
        self.assertFalse(live_first.retired_scope_projection_enabled())
        self.assertNotEqual(live_first.state_key(), live_second.state_key())

        retired_first = _reach_deleted()
        retired_second = retired_first.clone()
        retired_first.edges["edge-a"].view_scope = (1, 1)
        retired_second.edges["edge-a"].view_scope = (1, 2)
        retired_first.edges["edge-a"].certificate_scope = (1, 1)
        retired_second.edges["edge-a"].certificate_scope = (1, 2)
        retired_first.negative_cache = [((1, 1), "fp", frozenset({"g1-v1"}))]
        retired_second.negative_cache = [((1, 2), "fp", frozenset({"g1-v2"}))]
        retired_first.check_invariants()
        retired_second.check_invariants()
        self.assertTrue(retired_first.retired_scope_projection_enabled())
        self.assertNotEqual(retired_first.raw_state_key(), retired_second.raw_state_key())
        self.assertEqual(retired_first.state_key(), retired_second.state_key())
        self.assertEqual(
            _successor_observations(retired_first),
            _successor_observations(retired_second),
        )
        retired_first.prepare_reuse()
        self.assertTrue(retired_first.retired_scope_projection_enabled())

        invalid_deleted = _reach_deleted()
        invalid_deleted.current_scope = (1, 2)
        invalid_deleted.current_valid = invalid_deleted.backend_accepted[(1, 2)]
        with self.assertRaisesRegex(SafetyViolation, "retained a live formal scope"):
            invalid_deleted.check_invariants()

        invalid_g2_prepare = _reach_deleted()
        invalid_g2_prepare.prepare_reuse()
        invalid_g2_prepare.current_scope = (1, 2)
        invalid_g2_prepare.current_valid = invalid_g2_prepare.backend_accepted[(1, 2)]
        with self.assertRaisesRegex(SafetyViolation, "g2 preparation"):
            invalid_g2_prepare.check_invariants()

        invalid_old_acceptance = _reach_deleted()
        invalid_old_acceptance.backend_accepted[(1, 1)] = frozenset({"fp"})
        with self.assertRaisesRegex(SafetyViolation, "valid-set domain"):
            invalid_old_acceptance.check_invariants()

        invalid_old_representation = _reach_deleted()
        invalid_old_representation.delta_scopes.remove((1, 2))
        with self.assertRaisesRegex(SafetyViolation, "retired g1 projection"):
            invalid_old_representation.check_invariants()

    def test_edge_swap_is_only_used_in_forward_closed_region(self) -> None:
        open_window = VersionSafetyModel(prepare_second_version=True, formal_bounds=True)
        open_window.crash("edge-a")
        open_window_swapped = _swap_edges(open_window)
        self.assertFalse(open_window.edge_permutation_forward_closed())
        self.assertNotEqual(open_window.state_key(), open_window_swapped.state_key())

        open_window.negative_cache.append(((1, 1), "fp", frozenset({"g1-v1"})))
        open_window_swapped = _swap_edges(open_window)
        open_window.check_invariants()
        open_window_swapped.check_invariants()
        self.assertTrue(open_window.edge_permutation_forward_closed())
        self.assertEqual(open_window.state_key(), open_window_swapped.state_key())
        self.assertEqual(
            {_swap_action(action) for action in open_window.available_actions(True)},
            set(open_window_swapped.available_actions(True)),
        )
        for action in open_window.available_actions(True):
            first_child = open_window.clone()
            second_child = open_window_swapped.clone()
            first_result = first_child.apply(action)
            second_result = second_child.apply(_swap_action(action))
            first_child.check_invariants()
            second_child.check_invariants()
            self.assertTrue(first_child.edge_permutation_forward_closed())
            self.assertTrue(second_child.edge_permutation_forward_closed())
            self.assertEqual(first_result, second_result)
            self.assertEqual(first_child.state_key(), second_child.state_key())

    def test_formal_transport_actions_and_bounds_are_explicit(self) -> None:
        model = VersionSafetyModel(prepare_second_version=True, formal_bounds=True)
        self.assertEqual(FORMAL_PENDING_CAPACITY, model.pending_capacity)
        self.assertEqual(FORMAL_MAX_MESSAGE_COPIES, model.max_message_copies)
        model.enqueue("directory", "edge-a", model.current_scope)
        names = {str(action[0]) for action in model.available_actions(exhaustive=True)}
        self.assertTrue({"delay", "duplicate", "drop", "deliver"} <= names)
        model.duplicate_message(0)
        self.assertEqual(2, len(model.pending))
        self.assertIn("reorder", {str(action[0]) for action in model.available_actions(True)})
        with self.assertRaises(ValueError):
            model.duplicate_message(0)
        with self.assertRaises(ValueError):
            model.enqueue("directory", "edge-b", model.current_scope)

    def test_formal_fixture_reaches_a_real_fixpoint_with_required_coverage(self) -> None:
        report = explore_test_fixture()
        self.assertEqual("TEST_FIXTURE_ONLY", report["execution_classification"])
        self.assertEqual("MODEL_CHECK_PASS", report["status"])
        self.assertIs(True, report["frontier_exhausted"])
        self.assertIs(False, report["truncated"])
        self.assertIsNone(report["counterexample"])
        self.assertEqual(0, report["structural_false_rejects"])
        self.assertGreater(report["quotient_state_count"], 50)
        for field in ("active_scopes", "valid_login_not_prescreen_rejected"):
            self.assertTrue(all(report["coverage"][field].values()))
        for edge in EDGES:
            self.assertTrue(all(report["coverage"]["edges"][edge].values()))
        self.assertTrue(all(report["coverage"]["transport"].values()))
        self.assertTrue(all(report["coverage"]["lifecycle"].values()))
        self.assertTrue(all(report["coverage"]["uncertainty_backend_forwarded"].values()))

    def test_state_cap_is_incomplete_and_never_passes(self) -> None:
        report = explore_formal_state(max_states=10)
        self.assertEqual("INCOMPLETE_STATE_CAP", report["status"])
        self.assertIs(False, report["frontier_exhausted"])
        self.assertIs(True, report["truncated"])
        self.assertIsNone(report["counterexample"])

    def test_unsafe_transition_returns_shortest_counterexample(self) -> None:
        class UnsafeModel(VersionSafetyModel):
            def check_invariants(self) -> None:
                super().check_invariants()
                if self.transitions >= 1:
                    raise SafetyViolation("injected unsafe transition")

            def state_key(self) -> tuple[object, ...]:
                if self.transitions >= 1:
                    raise AssertionError("unsafe child reached canonical merge")
                return super().state_key()

        report = explore_formal_state(max_states=100, model_factory=UnsafeModel)
        self.assertEqual("VIOLATION", report["status"])
        self.assertIs(False, report["frontier_exhausted"])
        self.assertIs(False, report["truncated"])
        self.assertEqual("injected unsafe transition", report["counterexample"]["error"])
        self.assertEqual("single-active", report["counterexample"]["rotation_mode"])
        self.assertEqual(1, len(report["counterexample"]["trace"]))

    def test_counterexample_records_the_concrete_rotation_mode_for_replay(self) -> None:
        class DualOnlyUnsafeModel(VersionSafetyModel):
            def check_invariants(self) -> None:
                super().check_invariants()
                if self.transitions >= 1 and self.prepared_valid == frozenset({"g1-v1", "g1-v2"}):
                    raise SafetyViolation("dual-only unsafe transition")

        report = explore_formal_state(max_states=100, model_factory=DualOnlyUnsafeModel)
        self.assertEqual("VIOLATION", report["status"])
        counterexample = report["counterexample"]
        self.assertEqual("dual-active", counterexample["rotation_mode"])
        self.assertEqual(1, len(counterexample["trace"]))
        action = tuple(counterexample["trace"][0])

        single = DualOnlyUnsafeModel(
            prepare_second_version=True,
            dual_active=False,
            formal_bounds=True,
        )
        single.apply(action)
        dual = DualOnlyUnsafeModel(
            prepare_second_version=True,
            dual_active=True,
            formal_bounds=True,
        )
        with self.assertRaisesRegex(SafetyViolation, "dual-only"):
            dual.apply(action)

    def test_full_formal_quotient_reaches_the_frozen_fixpoint(self) -> None:
        report = explore_formal_state()
        self.assertEqual("MODEL_CHECK_PASS", report["status"])
        self.assertIs(True, report["frontier_exhausted"])
        self.assertIs(False, report["truncated"])
        self.assertIsNone(report["counterexample"])
        self.assertEqual(0, report["structural_false_rejects"])
        self.assertEqual(FORMAL_EXPECTED_QUOTIENT_STATES, report["quotient_state_count"])
        self.assertEqual(
            FORMAL_EXPECTED_CONCRETE_ACTION_TRANSITIONS,
            report["concrete_transition_count"],
        )
        self.assertEqual(FORMAL_EXPECTED_LOGIN_TRANSITIONS, report["login_transition_count"])
        self.assertEqual(FORMAL_EXPECTED_STATE_SET_DIGEST, report["state_set_digest"])
        self.assertEqual(FORMAL_EXPECTED_TRANSITION_DIGEST, report["transition_digest"])
        self.assertEqual(list(REDUCTION_IDS), report["reduction_semantics"]["reduction_ids"])
        for field in ("active_scopes", "valid_login_not_prescreen_rejected"):
            self.assertTrue(all(report["coverage"][field].values()))
        self.assertTrue(all(report["coverage"]["rotation_modes"].values()))
        for edge_id in EDGES:
            self.assertTrue(all(report["coverage"]["edges"][edge_id].values()))
        self.assertTrue(all(report["coverage"]["transport"].values()))
        self.assertTrue(all(report["coverage"]["lifecycle"].values()))
        self.assertTrue(all(report["coverage"]["uncertainty_backend_forwarded"].values()))

    def test_formal_randomized_fixture_runs_exact_contract(self) -> None:
        report = run_formal_randomized(128, 71)
        self.assertEqual(128, report["transitions"])
        self.assertEqual(128, report["actual_transitions"])
        self.assertEqual(["g1/v1", "g1/v2", "g2/v1"], report["reached_scopes"])
        self.assertEqual("MODEL_RUN_PASS", report["status"])
        self.assertEqual(0, report["invariant_violations"])

    def test_configurable_randomized_smoke(self) -> None:
        transitions = int(os.environ.get("TRAPS_MODEL_TRANSITIONS", "2000"))
        seed = int(os.environ.get("TRAPS_MODEL_SEED", "20260805"))
        report = run_randomized(transitions, seed)
        self.assertEqual(transitions, report["transitions"])
        self.assertEqual(transitions, report["actual_transitions"])
        self.assertEqual(0, report["invariant_violations"])
        self.assertEqual(0, report["violations"])
        self.assertGreater(report["logins"], 0)
        self.assertGreater(report["fail_open_logins"], 0)
        self.assertGreater(report["edge_crashes"], 0)
        self.assertGreater(report["rotations"] + report["username_reuses"], 0)


if __name__ == "__main__":
    unittest.main()
