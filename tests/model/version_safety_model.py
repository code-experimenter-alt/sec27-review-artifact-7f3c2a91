from __future__ import annotations

import copy
import hashlib
import json
import random
from collections import Counter, deque
from dataclasses import dataclass
from typing import Callable, Optional

Scope = tuple[int, int]
Message = tuple[str, str, Optional[Scope]]
Action = tuple[object, ...]

EDGES = ("edge-a", "edge-b")
FORMAL_SCOPES: tuple[Scope, ...] = ((1, 1), (1, 2), (2, 1))
FORMAL_CREDENTIALS = ("g1-v1", "g1-v2", "g2-v1", "fp", "wrong")
FORMAL_PENDING_CAPACITY = 2
FORMAL_MAX_MESSAGE_COPIES = 2
FORMAL_NEGATIVE_CACHE_CAPACITY = 8
FORMAL_MAX_NEGATIVE_CACHE_ENTRIES = len(FORMAL_SCOPES)
FORMAL_ALLOWED_VALID_SETS: dict[Scope, frozenset[frozenset[str]]] = {
    (1, 1): frozenset({frozenset({"g1-v1"})}),
    (1, 2): frozenset(
        {
            frozenset({"g1-v2"}),
            frozenset({"g1-v1", "g1-v2"}),
        }
    ),
    (2, 1): frozenset({frozenset({"g2-v1"})}),
}

STATE_KEY_SCHEMA_ID = "traps-g7-state-key-v3-four-reduction-formal-quotient"
TRANSITION_SCHEMA_ID = "traps-g7-transition-relation-v3-concrete-before-merge"
EQUIVALENCE_RELATION_ID = (
    "traps-g7-equivalence-v1-pending-multiset-cache-set-retired-g1-forward-closed-edge-swap"
)
REDUCTION_CONTRACT_ID = "traps-g7-reduction-v1-concrete-apply-invariants-before-four-way-merge"
COUNTEREXAMPLE_POLICY_ID = "SHORTEST_QUOTIENT_BFS_TRACE_WITH_CONCRETE_LIFT"
REDUCTION_IDS = (
    "R1_PENDING_MESSAGE_MULTISET",
    "R2_NEGATIVE_CACHE_SET_BELOW_CAPACITY",
    "R3_RETIRED_G1_SCOPE_PROJECTION",
    "R4_FORWARD_CLOSED_EDGE_PERMUTATION",
)
FORMAL_EXPECTED_QUOTIENT_STATES = 40_104
FORMAL_EXPECTED_CONCRETE_ACTION_TRANSITIONS = 759_640
FORMAL_EXPECTED_LOGIN_TRANSITIONS = 401_040
FORMAL_EXPECTED_STATE_SET_DIGEST = (
    "84cc14888b4ca59c8fb5b9de188384a27b54f7ba8c9fa9474aa0184129524dfc"
)
FORMAL_EXPECTED_TRANSITION_DIGEST = (
    "6f40469009c736dd63bbd3842ecba47559df5e88fe9326023b8f87d628fd6890"
)
INVARIANT_IDS = (
    "I1_NEGATIVE_CACHE_IMMUTABLE_VALID_SET",
    "I2_DIRECTORY_CERTAINTY_REQUIRES_CURRENT_SCOPE",
    "I3_ACTIVE_BACKEND_SCOPE_CONVERGENCE",
    "I4_VALID_CREDENTIAL_NEVER_STRUCTURALLY_REJECTED",
    "I5_PENDING_CAPACITY_TWO",
    "I6_MESSAGE_MULTIPLICITY_AT_MOST_TWO",
    "I7_FORMAL_SCOPE_DOMAIN_CLOSED",
    "I8_FORMAL_QUOTIENT_PRECONDITIONS",
)
ACTION_ALPHABET_IDS = (
    "LOGIN",
    "CRASH",
    "RESTART",
    "ENQUEUE_DIRECTORY",
    "ENQUEUE_DELTA_CERTIFICATE",
    "ENQUEUE_MISMATCH",
    "DELAY",
    "DUPLICATE",
    "REORDER",
    "DROP",
    "DELIVER",
    "PUBLISH",
    "BACKEND_ADVANCE_BEFORE_DIRECTORY",
    "ACTIVATE",
    "DELETE",
    "PREPARE_REUSE",
)
UNCERTAINTY_REASON_IDS = (
    "NO_CURRENT_ACCOUNT",
    "EDGE_CRASHED",
    "DIRECTORY_UNCERTAIN",
    "DIRECTORY_SCOPE_MISMATCH",
    "CERTIFICATE_SCOPE_MISMATCH",
    "REPRESENTATION_UNAVAILABLE",
)


class SafetyViolation(AssertionError):
    pass


@dataclass
class EdgeState:
    view_scope: Optional[Scope]
    directory_certain: bool
    certificate_scope: Optional[Scope]
    certificate_source: Optional[str]
    crashed: bool = False


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _jsonable(value: object) -> object:
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(_jsonable(item) for item in value)
    return value


def _identity(value: object) -> str:
    return hashlib.sha256(_canonical_json(_jsonable(value)).encode("utf-8")).hexdigest()


def formal_reduction_contract() -> dict[str, object]:
    """Return the frozen, JSON-safe proof contract for the formal quotient."""
    return {
        "reduction_contract_id": REDUCTION_CONTRACT_ID,
        "equivalence_relation_id": EQUIVALENCE_RELATION_ID,
        "reduction_ids": list(REDUCTION_IDS),
        "concrete_transition_order": (
            "APPLY_ORIGINAL_ACTION_THEN_CHECK_ALL_INVARIANTS_THEN_CANONICAL_MERGE"
        ),
        "counterexample_policy": COUNTEREXAMPLE_POLICY_ID,
        "negative_cache_capacity": FORMAL_NEGATIVE_CACHE_CAPACITY,
        "maximum_reachable_negative_cache_entries": (FORMAL_MAX_NEGATIVE_CACHE_ENTRIES),
        "semantics": {
            "pending": "MULTISET_WITH_MULTIPLICITY_AND_CAPACITY_PRESERVED",
            "negative_cache": "SET_ONLY_WHILE_REACHABLE_CARDINALITY_IS_BELOW_CAPACITY",
            "retired_g1": "PROJECT_ONLY_AFTER_DELETE_OR_G2_PREPARE_OR_G2_ACTIVE",
            "edges": "PERMUTE_ONLY_AFTER_MISMATCH_PUBLICATION_IS_FORWARD_CLOSED",
        },
    }


def _retired_projection_enabled_from_key(key: tuple[object, ...]) -> bool:
    return key[13] == "DELETED" or key[11] == (2, 1) or key[4] == (2, 1)


def _edge_permutation_enabled_from_key(key: tuple[object, ...]) -> bool:
    current_scope = key[4]
    cache = key[20]
    assert isinstance(cache, tuple)
    current_fp_cached = any(entry[0] == current_scope and entry[1] == "fp" for entry in cache)
    return key[13] in {"ACTIVE", "DELETED"} or current_scope is None or current_fp_cached


def canonicalize_formal_state_key(
    raw_key: tuple[object, ...],
) -> tuple[object, ...]:
    """Canonicalize one frozen formal state under the proven equivalences."""
    if len(raw_key) != 21 or raw_key[0] != STATE_KEY_SCHEMA_ID:
        raise ValueError("formal state key has the wrong schema")
    if (
        raw_key[1] is not True
        or raw_key[2] != FORMAL_PENDING_CAPACITY
        or raw_key[3] != FORMAL_MAX_MESSAGE_COPIES
    ):
        raise ValueError("formal quotient requires the frozen transport bounds")

    key = list(raw_key)
    cache = key[20]
    if not isinstance(cache, tuple):
        raise ValueError("formal negative cache must be a tuple")
    if len(cache) > FORMAL_MAX_NEGATIVE_CACHE_ENTRIES:
        raise ValueError("formal negative cache exceeds its reachable scope bound")
    if FORMAL_MAX_NEGATIVE_CACHE_ENTRIES >= FORMAL_NEGATIVE_CACHE_CAPACITY:
        raise ValueError("negative-cache set quotient requires no reachable eviction")
    if any(
        not isinstance(entry, tuple)
        or len(entry) != 3
        or entry[0] not in FORMAL_SCOPES
        or entry[1] != "fp"
        for entry in cache
    ):
        raise ValueError("formal negative cache escaped the set-quotient domain")
    if len({(entry[0], entry[1]) for entry in cache}) != len(cache):
        raise ValueError("formal negative cache contains an impossible duplicate")

    if _retired_projection_enabled_from_key(tuple(key)):

        def retired_scope(scope: object) -> object:
            return "OLD_G1" if scope in {(1, 1), (1, 2)} else scope

        accepted: dict[object, tuple[object, ...]] = {}
        for scope, valid in key[8]:
            projected = retired_scope(scope)
            accepted[projected] = () if projected == "OLD_G1" else valid
        key[8] = tuple(sorted(accepted.items(), key=repr))
        for index in (9, 10, 14, 15):
            key[index] = tuple(sorted({retired_scope(scope) for scope in key[index]}, key=repr))
        key[18] = tuple(
            (
                edge_id,
                retired_scope(view_scope),
                certain,
                retired_scope(certificate_scope),
                source,
                crashed,
            )
            for edge_id, view_scope, certain, certificate_scope, source, crashed in key[18]
        )
        key[19] = tuple((kind, edge_id, retired_scope(scope)) for kind, edge_id, scope in key[19])
        key[20] = tuple(entry for entry in key[20] if retired_scope(entry[0]) != "OLD_G1")

    key[19] = tuple(sorted(key[19], key=repr))
    key[20] = tuple(sorted(key[20], key=repr))
    identity = tuple(key)
    if not _edge_permutation_enabled_from_key(identity):
        return identity

    rename = {"edge-a": "edge-b", "edge-b": "edge-a"}
    swapped = list(identity)
    swapped[16] = tuple(sorted(rename[edge_id] for edge_id in identity[16]))
    swapped[17] = tuple(sorted(rename[edge_id] for edge_id in identity[17]))
    swapped[18] = tuple(sorted((rename[edge_id], *values) for edge_id, *values in identity[18]))
    swapped[19] = tuple(
        sorted(
            ((kind, rename[edge_id], scope) for kind, edge_id, scope in identity[19]),
            key=repr,
        )
    )
    return min(identity, tuple(swapped), key=repr)


class VersionSafetyModel:
    """Executable version-safety model with an optional closed formal domain."""

    def __init__(
        self,
        prepare_second_version: bool = True,
        *,
        dual_active: bool = False,
        formal_bounds: bool = False,
    ) -> None:
        first: Scope = (1, 1)
        self.formal_bounds = formal_bounds
        self.pending_capacity = FORMAL_PENDING_CAPACITY if formal_bounds else 16
        self.max_message_copies = FORMAL_MAX_MESSAGE_COPIES if formal_bounds else 16
        self.current_scope: Optional[Scope] = first
        self.current_valid = frozenset({"g1-v1"})
        self.backend_scope: Optional[Scope] = first
        self.backend_valid = self.current_valid
        self.backend_accepted: dict[Scope, frozenset[str]] = {first: self.current_valid}
        self.backend_fail_open_scopes: set[Scope] = {first}
        self.backend_expected_scopes: set[Scope] = {first}
        self.prepared_scope: Optional[Scope] = None
        self.prepared_valid = frozenset()
        self.stage = "ACTIVE"
        self.delta_scopes: set[Scope] = {first}
        self.base_scopes: set[Scope] = set()
        self.delta_acks: set[str] = set(EDGES)
        self.compacted_acks: set[str] = set()
        self.edges = {edge: EdgeState(first, True, first, "delta") for edge in EDGES}
        self.pending: list[Message] = []
        self.negative_cache: list[tuple[Scope, str, frozenset[str]]] = []
        self.transitions = 0
        self.logins = 0
        self.valid_logins = 0
        self.fail_open_logins = 0
        self.pre_screen_rejects = 0
        self.backend_checks = 0
        self.cache_hits = 0
        self.crashes = 0
        self.restarts = 0
        self.reuses = 0
        self.rotations = 0
        self.drops = 0
        self.delays = 0
        self.duplicates = 0
        self.reorders = 0
        if prepare_second_version:
            self.prepare_rotation(dual_active=dual_active, count=False)

    def clone(self) -> VersionSafetyModel:
        return copy.deepcopy(self)

    def _record_transition(self, count: bool) -> None:
        if count:
            self.transitions += 1
            self.check_invariants()

    def _valid_for(self, scope: Scope) -> frozenset[str]:
        if scope == self.current_scope:
            return self.current_valid
        if scope == self.prepared_scope:
            return self.prepared_valid
        return self.backend_accepted.get(scope, frozenset())

    def _representation_exists(self, scope: Scope, source: Optional[str]) -> bool:
        return (source == "delta" and scope in self.delta_scopes) or (
            source == "base" and scope in self.base_scopes
        )

    def _represented(self, scope: Scope, password: str) -> bool:
        return password == "fp" or password in self._valid_for(scope)

    def _cache_contains(self, scope: Scope, password: str) -> bool:
        return any(
            item_scope == scope and item_password == password
            for item_scope, item_password, _ in self.negative_cache
        )

    def _cache_insert(self, scope: Scope, password: str, valid_set: frozenset[str]) -> None:
        if password in valid_set:
            raise SafetyViolation("backend attempted to cache a valid credential")
        entry = (scope, password, valid_set)
        if entry in self.negative_cache:
            self.negative_cache.remove(entry)
        self.negative_cache.append(entry)
        if len(self.negative_cache) > FORMAL_NEGATIVE_CACHE_CAPACITY:
            self.negative_cache.pop(0)

    def prepare_rotation(self, dual_active: bool, count: bool = True) -> None:
        if self.current_scope is None or self.stage not in {"ACTIVE", "RETIRED"}:
            raise ValueError("rotation requires an active account")
        generation, version = self.current_scope
        next_scope = (generation, version + 1)
        if self.formal_bounds and (self.current_scope, next_scope) != ((1, 1), (1, 2)):
            raise ValueError("formal domain permits exactly the g1/v1 to g1/v2 rotation")
        next_password = f"g{generation}-v{version + 1}"
        self.prepared_scope = next_scope
        self.prepared_valid = (
            self.current_valid | frozenset({next_password})
            if dual_active
            else frozenset({next_password})
        )
        self.stage = "PREPARED"
        self.delta_acks.clear()
        self.compacted_acks.clear()
        self.rotations += int(count)
        self._record_transition(count)

    def prepare_reuse(self) -> None:
        if self.current_scope is not None or self.stage != "DELETED":
            raise ValueError("reuse requires a deleted username")
        generations = [scope[0] for scope in self.backend_accepted]
        generation = max(generations, default=0) + 1
        if self.formal_bounds and generation != 2:
            raise ValueError("formal domain permits exactly one username reuse")
        self.prepared_scope = (generation, 1)
        self.prepared_valid = frozenset({f"g{generation}-v1"})
        self.stage = "PREPARED"
        self.delta_acks.clear()
        self.compacted_acks.clear()
        self.reuses += 1
        self._record_transition(True)

    def publish_delta(self) -> None:
        if self.stage != "PREPARED" or self.prepared_scope is None:
            raise ValueError("no prepared version")
        self.delta_scopes.add(self.prepared_scope)
        self.stage = "EDGE_DELTA_READY"
        self._record_transition(True)

    def backend_advance_only(self) -> None:
        if self.stage != "EDGE_DELTA_READY" or set(EDGES) - self.delta_acks:
            raise ValueError("backend fault point is not activation-ready")
        assert self.prepared_scope is not None
        if self.backend_scope == self.prepared_scope:
            raise ValueError("backend is already advanced")
        if self.current_scope is not None:
            self.backend_accepted[self.current_scope] = self.current_valid
        self.backend_scope = self.prepared_scope
        self.backend_valid = self.prepared_valid
        self.backend_accepted[self.prepared_scope] = self.prepared_valid
        self.backend_fail_open_scopes = {
            scope for scope in (self.current_scope, self.prepared_scope) if scope is not None
        }
        self.backend_expected_scopes = set(self.backend_fail_open_scopes)
        self._record_transition(True)

    def activate(self) -> None:
        if self.stage != "EDGE_DELTA_READY" or set(EDGES) - self.delta_acks:
            raise ValueError("activation requires all delta acknowledgments")
        assert self.prepared_scope is not None
        if self.current_scope is not None:
            self.backend_accepted[self.current_scope] = self.current_valid
        self.backend_scope = self.prepared_scope
        self.backend_valid = self.prepared_valid
        self.backend_accepted[self.prepared_scope] = self.prepared_valid
        self.backend_fail_open_scopes = {self.prepared_scope}
        self.backend_expected_scopes = {self.prepared_scope}
        self.current_scope = self.prepared_scope
        self.current_valid = self.prepared_valid
        self.prepared_scope = None
        self.prepared_valid = frozenset()
        self.stage = "ACTIVE"
        for edge in self.edges.values():
            edge.directory_certain = False
        self._record_transition(True)

    def compact(self) -> None:
        if self.formal_bounds:
            raise ValueError("compaction is outside the closed formal lifecycle")
        if self.stage != "ACTIVE" or self.current_scope is None:
            raise ValueError("compaction requires ACTIVE")
        self.base_scopes.add(self.current_scope)
        self.compacted_acks.clear()
        self.stage = "COMPACTED"
        self._record_transition(True)

    def retire(self) -> None:
        if self.formal_bounds:
            raise ValueError("retirement is outside the closed formal lifecycle")
        if self.stage != "COMPACTED" or set(EDGES) - self.compacted_acks:
            raise ValueError("retirement requires every compacted acknowledgment")
        assert self.current_scope is not None
        self.delta_scopes.discard(self.current_scope)
        self.stage = "RETIRED"
        self._record_transition(True)

    def delete(self) -> None:
        if self.current_scope is None or self.stage not in {"ACTIVE", "RETIRED"}:
            raise ValueError("delete requires an active username")
        if self.formal_bounds and self.current_scope != (1, 2):
            raise ValueError("formal deletion is enabled only after g1/v2 activation")
        self.current_scope = None
        self.current_valid = frozenset()
        self.backend_scope = None
        self.backend_valid = frozenset()
        self.backend_fail_open_scopes.clear()
        self.backend_expected_scopes.clear()
        self.prepared_scope = None
        self.prepared_valid = frozenset()
        self.stage = "DELETED"
        for edge in self.edges.values():
            edge.directory_certain = False
        self._record_transition(True)

    def crash(self, edge_id: str) -> None:
        edge = self.edges[edge_id]
        edge.crashed = True
        edge.directory_certain = False
        edge.certificate_scope = None
        edge.certificate_source = None
        self.crashes += 1
        self._record_transition(True)

    def restart(self, edge_id: str) -> None:
        edge = self.edges[edge_id]
        edge.crashed = False
        edge.directory_certain = False
        self.restarts += 1
        self._record_transition(True)

    def _can_enqueue(self, message: Message) -> bool:
        return (
            len(self.pending) < self.pending_capacity
            and self.pending.count(message) < self.max_message_copies
        )

    def _can_publish_new(self, message: Message) -> bool:
        """Formal publishers emit once; only DUPLICATE creates a second copy."""
        return self._can_enqueue(message) and (
            not self.formal_bounds or message not in self.pending
        )

    def enqueue(self, kind: str, edge_id: str, scope: Optional[Scope]) -> None:
        message = (kind, edge_id, scope)
        if kind not in {"directory", "delta-cert", "base-cert", "mismatch"}:
            raise ValueError("unknown message kind")
        if edge_id not in EDGES:
            raise ValueError("unknown edge")
        if not self._can_enqueue(message):
            raise ValueError("bounded transport queue or message multiplicity exceeded")
        self.pending.append(message)
        self._record_transition(True)

    def deliver(self, index: int) -> None:
        kind, edge_id, scope = self.pending.pop(index)
        edge = self.edges[edge_id]
        if not edge.crashed:
            if kind == "directory":
                edge.view_scope = scope
                edge.directory_certain = scope == self.current_scope
            elif kind == "delta-cert" and scope is not None and scope in self.delta_scopes:
                edge.certificate_scope = scope
                edge.certificate_source = "delta"
                if scope == self.prepared_scope:
                    self.delta_acks.add(edge_id)
            elif kind == "base-cert" and scope is not None and scope in self.base_scopes:
                edge.certificate_scope = scope
                edge.certificate_source = "base"
                if scope == self.current_scope:
                    self.compacted_acks.add(edge_id)
            elif kind == "mismatch" and scope is not None:
                valid_set = self.backend_accepted.get(scope, frozenset())
                self._cache_insert(scope, "fp", valid_set)
        self._record_transition(True)

    def delay_message(self, index: int) -> None:
        _ = self.pending[index]
        self.delays += 1
        self._record_transition(True)

    def drop_message(self, index: int) -> None:
        self.pending.pop(index)
        self.drops += 1
        self._record_transition(True)

    def duplicate_message(self, index: int) -> None:
        message = self.pending[index]
        if not self._can_enqueue(message):
            raise ValueError("bounded transport queue or message multiplicity exceeded")
        self.pending.append(message)
        self.duplicates += 1
        self._record_transition(True)

    def reorder_messages(self) -> None:
        if len(self.pending) != 2:
            raise ValueError("reorder requires exactly two pending messages")
        self.pending[0], self.pending[1] = self.pending[1], self.pending[0]
        self.reorders += 1
        self._record_transition(True)

    def login_classification(self, edge_id: str, password: str) -> dict[str, object]:
        edge = self.edges[edge_id]
        externally_valid = (
            self.current_scope is not None
            and self.backend_scope is not None
            and password in self.current_valid
        )
        directory_usable = (
            self.current_scope is not None
            and not edge.crashed
            and edge.directory_certain
            and edge.view_scope == self.current_scope
        )
        reasons: list[str] = []
        if self.current_scope is None:
            reasons.append("NO_CURRENT_ACCOUNT")
        if edge.crashed:
            reasons.append("EDGE_CRASHED")
        if not edge.directory_certain:
            reasons.append("DIRECTORY_UNCERTAIN")
        if edge.view_scope != self.current_scope:
            reasons.append("DIRECTORY_SCOPE_MISMATCH")
        if edge.certificate_scope != self.current_scope:
            reasons.append("CERTIFICATE_SCOPE_MISMATCH")
        if self.current_scope is not None and not self._representation_exists(
            self.current_scope, edge.certificate_source
        ):
            reasons.append("REPRESENTATION_UNAVAILABLE")
        return {
            "externally_valid": externally_valid,
            "directory_usable": directory_usable,
            "uncertain": bool(reasons),
            "uncertainty_reasons": tuple(reasons),
        }

    def login(self, edge_id: str, password: str) -> str:
        self.logins += 1
        classification = self.login_classification(edge_id, password)
        externally_valid = bool(classification["externally_valid"])
        directory_usable = bool(classification["directory_usable"])
        self.valid_logins += int(externally_valid)
        if classification["uncertain"]:
            self.fail_open_logins += 1
            self.backend_checks += 1
            outcome = self._backend_verify(
                self.current_scope if directory_usable else None,
                password,
            )
            if externally_valid and outcome != "MATCH":
                raise SafetyViolation("fail-open path lost a currently valid credential")
            self._record_transition(True)
            return "FAIL_OPEN_" + outcome

        assert self.current_scope is not None
        if self._cache_contains(self.current_scope, password):
            self.cache_hits += 1
            if externally_valid:
                raise SafetyViolation("exact negative cache rejected a valid credential")
            self._record_transition(True)
            return "NEGATIVE_CACHE_REJECT"
        if not self._represented(self.current_scope, password):
            self.pre_screen_rejects += 1
            if externally_valid:
                raise SafetyViolation("positive representation rejected a valid credential")
            self._record_transition(True)
            return "POSITIVE_REJECT"

        self.backend_checks += 1
        outcome = self._backend_verify(self.current_scope, password)
        if outcome == "MISMATCH":
            valid_set = self.backend_accepted.get(self.current_scope, frozenset())
            self._cache_insert(self.current_scope, password, valid_set)
        if externally_valid and outcome != "MATCH":
            raise SafetyViolation("backend rejected a currently valid credential")
        self._record_transition(True)
        return "BACKEND_" + outcome

    def _backend_verify(self, expected_scope: Optional[Scope], password: str) -> str:
        if self.backend_scope is None:
            return "NO_ACCOUNT"
        if expected_scope is None:
            return (
                "MATCH"
                if any(
                    password in self.backend_accepted.get(scope, frozenset())
                    for scope in self.backend_fail_open_scopes
                )
                else "MISMATCH"
            )
        valid = self.backend_accepted.get(expected_scope)
        if valid is None or expected_scope not in self.backend_expected_scopes:
            return "VERSION_MISMATCH"
        return "MATCH" if password in valid else "MISMATCH"

    def check_invariants(self) -> None:
        for _scope, password, valid_set in self.negative_cache:
            if password in valid_set:
                raise SafetyViolation("negative cache proof contradicts immutable valid set")
        for edge in self.edges.values():
            if edge.directory_certain and edge.view_scope != self.current_scope:
                raise SafetyViolation("edge calls a stale directory version certain")
        if (
            self.stage in {"ACTIVE", "COMPACTED", "RETIRED"}
            and self.current_scope is not None
            and self.backend_scope != self.current_scope
        ):
            raise SafetyViolation("directory ACTIVE and backend version diverged")
        if len(self.pending) > self.pending_capacity:
            raise SafetyViolation("pending transport capacity exceeded")
        if any(count > self.max_message_copies for count in Counter(self.pending).values()):
            raise SafetyViolation("pending message multiplicity exceeded")
        if self.formal_bounds:
            scopes: set[Scope] = set(self.backend_accepted)
            scopes.update(self.delta_scopes)
            scopes.update(self.base_scopes)
            scopes.update(scope for scope, _, _ in self.negative_cache)
            scopes.update(scope for _, _, scope in self.pending if scope is not None)
            scopes.update(
                scope
                for scope in (
                    self.current_scope,
                    self.backend_scope,
                    self.prepared_scope,
                    *(edge.view_scope for edge in self.edges.values()),
                    *(edge.certificate_scope for edge in self.edges.values()),
                )
                if scope is not None
            )
            if not scopes <= set(FORMAL_SCOPES):
                raise SafetyViolation("state escaped the frozen formal scope domain")

            valid_bindings = (
                (self.current_scope, self.current_valid),
                (self.backend_scope, self.backend_valid),
                (self.prepared_scope, self.prepared_valid),
            )
            if any(
                (scope is None and valid)
                or (scope is not None and valid not in FORMAL_ALLOWED_VALID_SETS[scope])
                for scope, valid in valid_bindings
            ) or any(
                valid not in FORMAL_ALLOWED_VALID_SETS[scope]
                for scope, valid in self.backend_accepted.items()
            ):
                raise SafetyViolation("formal valid-set domain precondition failed")
            if any(
                scope is not None and self.backend_accepted.get(scope) != valid
                for scope, valid in (
                    (self.current_scope, self.current_valid),
                    (self.backend_scope, self.backend_valid),
                )
            ):
                raise SafetyViolation("formal live scope lacks its immutable valid set")

            cache_identities = [(scope, password) for scope, password, _ in self.negative_cache]
            if (
                len(self.negative_cache) > FORMAL_MAX_NEGATIVE_CACHE_ENTRIES
                or len(set(cache_identities)) != len(cache_identities)
                or any(password != "fp" for _, password in cache_identities)
                or any(
                    valid_set != self.backend_accepted.get(scope)
                    for scope, _, valid_set in self.negative_cache
                )
                or FORMAL_MAX_NEGATIVE_CACHE_ENTRIES >= FORMAL_NEGATIVE_CACHE_CAPACITY
            ):
                raise SafetyViolation("formal quotient negative-cache precondition failed")
            if (
                set(self.edges) != set(EDGES)
                or not self.delta_acks <= set(EDGES)
                or not self.compacted_acks <= set(EDGES)
                or any(
                    kind not in {"directory", "delta-cert", "base-cert", "mismatch"}
                    or edge_id not in EDGES
                    for kind, edge_id, _ in self.pending
                )
            ):
                raise SafetyViolation("formal quotient edge/message domain precondition failed")
            if self.stage == "DELETED" and any(
                scope is not None
                for scope in (self.current_scope, self.backend_scope, self.prepared_scope)
            ):
                raise SafetyViolation("deleted state retained a live formal scope")
            if self.prepared_scope == (2, 1) and (
                self.current_scope is not None or self.stage not in {"PREPARED", "EDGE_DELTA_READY"}
            ):
                raise SafetyViolation("g2 preparation escaped its retired-scope phase")
            if self.current_scope == (2, 1) and (
                self.prepared_scope is not None or self.stage != "ACTIVE"
            ):
                raise SafetyViolation("g2 activation escaped its retired-scope phase")
            if self.retired_scope_projection_enabled():
                old_scopes = {(1, 1), (1, 2)}
                if (
                    not old_scopes <= self.backend_accepted.keys()
                    or not old_scopes <= self.delta_scopes
                    or bool(old_scopes & self.base_scopes)
                    or bool(old_scopes & self.backend_fail_open_scopes)
                    or bool(old_scopes & self.backend_expected_scopes)
                ):
                    raise SafetyViolation("retired g1 projection precondition failed")

    def retired_scope_projection_enabled(self) -> bool:
        return (
            self.stage == "DELETED" or self.prepared_scope == (2, 1) or self.current_scope == (2, 1)
        )

    def edge_permutation_forward_closed(self) -> bool:
        return (
            self.stage in {"ACTIVE", "DELETED"}
            or self.current_scope is None
            or self._cache_contains(self.current_scope, "fp")
        )

    def raw_state_key(self) -> tuple[object, ...]:
        edges = tuple(
            (
                edge_id,
                edge.view_scope,
                edge.directory_certain,
                edge.certificate_scope,
                edge.certificate_source,
                edge.crashed,
            )
            for edge_id, edge in sorted(self.edges.items())
        )
        backend_accepted = tuple(
            (scope, tuple(sorted(valid))) for scope, valid in sorted(self.backend_accepted.items())
        )
        return (
            STATE_KEY_SCHEMA_ID,
            self.formal_bounds,
            self.pending_capacity,
            self.max_message_copies,
            self.current_scope,
            tuple(sorted(self.current_valid)),
            self.backend_scope,
            tuple(sorted(self.backend_valid)),
            backend_accepted,
            tuple(sorted(self.backend_fail_open_scopes)),
            tuple(sorted(self.backend_expected_scopes)),
            self.prepared_scope,
            tuple(sorted(self.prepared_valid)),
            self.stage,
            tuple(sorted(self.delta_scopes)),
            tuple(sorted(self.base_scopes)),
            tuple(sorted(self.delta_acks)),
            tuple(sorted(self.compacted_acks)),
            edges,
            tuple(self.pending),
            tuple(self.negative_cache),
        )

    def state_key(self) -> tuple[object, ...]:
        raw_key = self.raw_state_key()
        if not self.formal_bounds:
            return raw_key
        return canonicalize_formal_state_key(raw_key)

    def _formal_lifecycle_actions(self) -> list[Action]:
        actions: list[Action] = []
        if self.stage == "PREPARED":
            actions.append(("publish",))
        elif self.stage == "EDGE_DELTA_READY" and self.prepared_scope is not None:
            for edge_id in EDGES:
                message: Message = ("delta-cert", edge_id, self.prepared_scope)
                if edge_id not in self.delta_acks and self._can_publish_new(message):
                    actions.append(("enqueue", *message))
            if not (set(EDGES) - self.delta_acks):
                if self.backend_scope != self.prepared_scope:
                    actions.append(("backend-only",))
                actions.append(("activate",))
        elif self.stage == "ACTIVE" and self.current_scope == (1, 2):
            actions.append(("delete",))
        elif self.stage == "DELETED" and (2, 1) not in self.backend_accepted:
            actions.append(("prepare-reuse",))
        return actions

    def available_actions(self, exhaustive: bool = False) -> list[Action]:
        actions: list[Action] = []
        formal = self.formal_bounds or exhaustive
        passwords = set(FORMAL_CREDENTIALS if formal else ("wrong", "fp"))
        if not formal:
            passwords.update(self.current_valid)
        for edge_id in EDGES:
            for password in sorted(passwords):
                actions.append(("login", edge_id, password))
            edge = self.edges[edge_id]
            actions.append(("restart" if edge.crashed else "crash", edge_id))
            message: Message = ("directory", edge_id, self.current_scope)
            directory_needed = not (
                edge.directory_certain and edge.view_scope == self.current_scope
            )
            if directory_needed and self._can_publish_new(message):
                actions.append(("enqueue", *message))

        if formal:
            actions.extend(self._formal_lifecycle_actions())
        else:
            if self.stage == "PREPARED":
                actions.append(("publish",))
            if self.stage == "EDGE_DELTA_READY" and self.prepared_scope is not None:
                for edge_id in EDGES:
                    message = ("delta-cert", edge_id, self.prepared_scope)
                    if self._can_enqueue(message):
                        actions.append(("enqueue", *message))
                if not (set(EDGES) - self.delta_acks):
                    if self.backend_scope != self.prepared_scope:
                        actions.append(("backend-only",))
                    actions.append(("activate",))
            if self.stage == "ACTIVE":
                actions.extend(
                    (("compact",), ("prepare-rotation", False), ("prepare-rotation", True))
                )
                actions.append(("delete",))
            if self.stage == "COMPACTED" and self.current_scope is not None:
                for edge_id in EDGES:
                    message = ("base-cert", edge_id, self.current_scope)
                    if self._can_enqueue(message):
                        actions.append(("enqueue", *message))
                if not (set(EDGES) - self.compacted_acks):
                    actions.append(("retire",))
            if self.stage == "RETIRED":
                actions.extend((("prepare-rotation", False), ("delete",)))
            if self.stage == "DELETED":
                actions.append(("prepare-reuse",))

        if self.current_scope is not None:
            message = ("mismatch", EDGES[0], self.current_scope)
            cache_missing = not self._cache_contains(self.current_scope, "fp")
            formal_race_window = self.stage in {"PREPARED", "EDGE_DELTA_READY"}
            if (
                cache_missing
                and (not formal or formal_race_window)
                and self._can_publish_new(message)
            ):
                actions.append(("enqueue", *message))
        for index, message in enumerate(self.pending):
            actions.append(("delay", index))
            actions.append(("deliver", index))
            actions.append(("drop", index))
            if self._can_enqueue(message):
                actions.append(("duplicate", index))
        if len(self.pending) == 2:
            actions.append(("reorder",))
        return actions

    def apply(self, action: Action) -> str:
        name = action[0]
        if name == "login":
            return self.login(str(action[1]), str(action[2]))
        if name == "crash":
            self.crash(str(action[1]))
        elif name == "restart":
            self.restart(str(action[1]))
        elif name == "enqueue":
            self.enqueue(str(action[1]), str(action[2]), action[3])  # type: ignore[arg-type]
        elif name == "delay":
            self.delay_message(int(action[1]))
        elif name == "deliver":
            self.deliver(int(action[1]))
        elif name == "drop":
            self.drop_message(int(action[1]))
        elif name == "duplicate":
            self.duplicate_message(int(action[1]))
        elif name == "reorder":
            self.reorder_messages()
        elif name == "publish":
            self.publish_delta()
        elif name == "backend-only":
            self.backend_advance_only()
        elif name == "activate":
            self.activate()
        elif name == "compact":
            self.compact()
        elif name == "retire":
            self.retire()
        elif name == "prepare-rotation":
            self.prepare_rotation(bool(action[1]))
        elif name == "delete":
            self.delete()
        elif name == "prepare-reuse":
            self.prepare_reuse()
        else:
            raise ValueError(f"unknown action: {action}")
        return str(name)

    def step(self, rng: random.Random) -> None:
        actions = self.available_actions(exhaustive=self.formal_bounds)
        self.apply(actions[rng.randrange(len(actions))])

    def report(self, seed: int) -> dict[str, int]:
        return {
            "seed": seed,
            "transitions": self.transitions,
            "actual_transitions": self.transitions,
            "logins": self.logins,
            "valid_logins": self.valid_logins,
            "fail_open_logins": self.fail_open_logins,
            "pre_screen_rejects": self.pre_screen_rejects,
            "backend_checks": self.backend_checks,
            "negative_cache_hits": self.cache_hits,
            "edge_crashes": self.crashes,
            "edge_restarts": self.restarts,
            "rotations": self.rotations,
            "username_reuses": self.reuses,
            "message_delays": self.delays,
            "message_duplicates": self.duplicates,
            "message_reorders": self.reorders,
            "message_drops": self.drops,
            "invariant_violations": 0,
            "violations": 0,
        }


def run_randomized(transitions: int, seed: int) -> dict[str, int]:
    if isinstance(transitions, bool) or not isinstance(transitions, int) or transitions < 1:
        raise ValueError("transitions must be a positive integer")
    if isinstance(seed, bool) or not isinstance(seed, int):
        raise ValueError("seed must be an integer")
    rng = random.Random(seed)
    model = VersionSafetyModel(prepare_second_version=True)
    while model.transitions < transitions:
        model.step(rng)
    model.check_invariants()
    report = model.report(seed)
    report["transitions"] = transitions
    report["actual_transitions"] = model.transitions
    return report


def _formal_randomized_prelude(model: VersionSafetyModel) -> None:
    actions: tuple[Action, ...] = (
        ("enqueue", "mismatch", "edge-a", (1, 1)),
        ("publish",),
        ("delay", 0),
        ("deliver", 0),
        ("enqueue", "delta-cert", "edge-a", (1, 2)),
        ("duplicate", 0),
        ("reorder",),
        ("drop", 1),
        ("deliver", 0),
        ("enqueue", "delta-cert", "edge-b", (1, 2)),
        ("deliver", 0),
        ("backend-only",),
        ("login", "edge-a", "g1-v1"),
        ("activate",),
        ("enqueue", "directory", "edge-a", (1, 2)),
        ("deliver", 0),
        ("enqueue", "directory", "edge-b", (1, 2)),
        ("crash", "edge-b"),
        ("deliver", 0),
        ("restart", "edge-b"),
        ("enqueue", "directory", "edge-b", (1, 2)),
        ("deliver", 0),
        ("login", "edge-a", "g1-v2"),
        ("login", "edge-b", "g1-v2"),
        ("delete",),
        ("prepare-reuse",),
        ("publish",),
        ("enqueue", "delta-cert", "edge-a", (2, 1)),
        ("deliver", 0),
        ("enqueue", "delta-cert", "edge-b", (2, 1)),
        ("deliver", 0),
        ("activate",),
        ("enqueue", "directory", "edge-a", (2, 1)),
        ("deliver", 0),
        ("enqueue", "directory", "edge-b", (2, 1)),
        ("deliver", 0),
        ("login", "edge-a", "g2-v1"),
        ("login", "edge-b", "g2-v1"),
    )
    for action in actions:
        model.apply(action)


class FormalFixtureModel(VersionSafetyModel):
    """Deterministic complete graph used only to attack the artifact consumer."""

    _ACTIONS: tuple[Action, ...] = (
        ("enqueue", "mismatch", "edge-a", (1, 1)),
        ("publish",),
        ("delay", 0),
        ("enqueue", "delta-cert", "edge-a", (1, 2)),
        ("reorder",),
        ("deliver", 0),
        ("duplicate", 0),
        ("drop", 1),
        ("deliver", 0),
        ("enqueue", "delta-cert", "edge-b", (1, 2)),
        ("duplicate", 0),
        ("deliver", 0),
        ("backend-only",),
        ("login", "edge-a", "g1-v1"),
        ("activate",),
        ("login", "edge-a", "g1-v2"),
        ("enqueue", "directory", "edge-a", (1, 2)),
        ("deliver", 1),
        ("login", "edge-a", "g1-v2"),
        ("delete",),
        ("login", "edge-a", "g1-v2"),
        ("prepare-reuse",),
        ("publish",),
        ("deliver", 0),
        ("enqueue", "delta-cert", "edge-a", (2, 1)),
        ("deliver", 0),
        ("enqueue", "delta-cert", "edge-b", (2, 1)),
        ("deliver", 0),
        ("activate",),
        ("login", "edge-a", "g2-v1"),
        ("enqueue", "directory", "edge-a", (2, 1)),
        ("deliver", 0),
        ("login", "edge-a", "g2-v1"),
        ("enqueue", "directory", "edge-b", (2, 1)),
        ("crash", "edge-b"),
        ("login", "edge-b", "g2-v1"),
        ("deliver", 0),
        ("restart", "edge-b"),
        ("enqueue", "directory", "edge-b", (2, 1)),
        ("deliver", 0),
        ("login", "edge-b", "g2-v1"),
        ("enqueue", "directory", "edge-a", (2, 1)),
        ("crash", "edge-a"),
        ("login", "edge-a", "g2-v1"),
        ("drop", 0),
        ("restart", "edge-a"),
        ("enqueue", "directory", "edge-a", (2, 1)),
        ("deliver", 0),
        ("login", "edge-a", "g2-v1"),
    )

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.fixture_phase = 0

    def state_key(self) -> tuple[object, ...]:
        return (*super().state_key(), "TEST_FIXTURE_ONLY", self.fixture_phase)

    def available_actions(self, exhaustive: bool = False) -> list[Action]:
        del exhaustive
        if self.fixture_phase >= len(self._ACTIONS):
            return []
        return [self._ACTIONS[self.fixture_phase]]

    def apply(self, action: Action) -> str:
        if self.fixture_phase >= len(self._ACTIONS) or action != self._ACTIONS[self.fixture_phase]:
            raise ValueError("test fixture action is out of sequence")
        result = super().apply(action)
        self.fixture_phase += 1
        return result


def run_formal_randomized(transitions: int, seed: int) -> dict[str, object]:
    if isinstance(transitions, bool) or not isinstance(transitions, int) or transitions < 64:
        raise ValueError("formal randomized transitions must be an integer >= 64")
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 1:
        raise ValueError("formal randomized seed must be a positive integer")
    model = VersionSafetyModel(
        prepare_second_version=True,
        dual_active=bool(seed % 2),
        formal_bounds=True,
    )
    _formal_randomized_prelude(model)
    rng = random.Random(seed)
    while model.transitions < transitions:
        model.step(rng)
    model.check_invariants()
    report: dict[str, object] = model.report(seed)
    report["transitions"] = transitions
    report["actual_transitions"] = model.transitions
    report["rotation_mode"] = "dual-active" if seed % 2 else "single-active"
    report["reached_scopes"] = ["g1/v1", "g1/v2", "g2/v1"]
    report["status"] = "MODEL_RUN_PASS"
    return report


def _empty_coverage() -> dict[str, object]:
    return {
        "rotation_modes": {"single-active": 0, "dual-active": 0},
        "edges": {
            edge: {
                "login": 0,
                "crash": 0,
                "restart": 0,
                "directory_delivery": 0,
                "certificate_delivery": 0,
            }
            for edge in EDGES
        },
        "active_scopes": {"g1/v1": 0, "g1/v2": 0, "g2/v1": 0},
        "valid_login_not_prescreen_rejected": {
            "g1/v1": 0,
            "g1/v2": 0,
            "g2/v1": 0,
        },
        "transport": {name: 0 for name in ("delay", "duplicate", "reorder", "drop")},
        "lifecycle": {
            "backend_before_directory": 0,
            "stale_certificate_delivery": 0,
            "crash_with_pending": 0,
            "delete": 0,
            "reuse": 0,
            "cache_insert_during_rotation": 0,
        },
        "uncertainty_backend_forwarded": {reason: 0 for reason in UNCERTAINTY_REASON_IDS},
    }


def _scope_label(scope: Optional[Scope]) -> Optional[str]:
    if scope is None:
        return None
    return f"g{scope[0]}/v{scope[1]}"


def _record_coverage(
    coverage: dict[str, object],
    model: VersionSafetyModel,
    action: Action,
    result: str,
    child: VersionSafetyModel,
) -> int:
    name = str(action[0])
    edges = coverage["edges"]
    assert isinstance(edges, dict)
    transport = coverage["transport"]
    lifecycle = coverage["lifecycle"]
    uncertainty = coverage["uncertainty_backend_forwarded"]
    assert isinstance(transport, dict) and isinstance(lifecycle, dict)
    assert isinstance(uncertainty, dict)
    structural_false_rejects = 0
    if name == "login":
        edge_id, password = str(action[1]), str(action[2])
        edges[edge_id]["login"] += 1
        classification = model.login_classification(edge_id, password)
        if classification["uncertain"]:
            if not result.startswith("FAIL_OPEN_"):
                structural_false_rejects += 1
            for reason in classification["uncertainty_reasons"]:
                uncertainty[reason] += int(result.startswith("FAIL_OPEN_"))
        if classification["externally_valid"]:
            label = _scope_label(model.current_scope)
            valid_coverage = coverage["valid_login_not_prescreen_rejected"]
            assert isinstance(valid_coverage, dict) and label is not None
            if result not in {"NEGATIVE_CACHE_REJECT", "POSITIVE_REJECT"}:
                valid_coverage[label] += 1
            else:
                structural_false_rejects += 1
    elif name in {"crash", "restart"}:
        edge_id = str(action[1])
        edges[edge_id][name] += 1
        if name == "crash" and model.pending:
            lifecycle["crash_with_pending"] += 1
    elif name == "deliver":
        message = model.pending[int(action[1])]
        kind, edge_id, scope = message
        if kind == "directory":
            edges[edge_id]["directory_delivery"] += int(not model.edges[edge_id].crashed)
        if kind in {"delta-cert", "base-cert"}:
            edges[edge_id]["certificate_delivery"] += int(not model.edges[edge_id].crashed)
            if (
                scope != model.current_scope
                and scope != model.prepared_scope
                and scope in model.backend_accepted
            ):
                lifecycle["stale_certificate_delivery"] += 1
        if kind == "mismatch" and model.stage in {"PREPARED", "EDGE_DELTA_READY"}:
            lifecycle["cache_insert_during_rotation"] += 1
    elif name in transport:
        if name != "reorder" or (len(model.pending) == 2 and model.pending[0] != model.pending[1]):
            transport[name] += 1
    elif name == "backend-only":
        lifecycle["backend_before_directory"] += 1
    elif name == "delete":
        lifecycle["delete"] += 1
    elif name == "prepare-reuse":
        lifecycle["reuse"] += 1
    if child.stage == "ACTIVE" and child.current_scope != model.current_scope:
        label = _scope_label(child.current_scope)
        active_scopes = coverage["active_scopes"]
        assert isinstance(active_scopes, dict) and label is not None
        active_scopes[label] += 1
    return structural_false_rejects


def _trace_for(
    parent: dict[tuple[object, ...], tuple[Optional[tuple[object, ...]], Optional[Action]]],
    key: tuple[object, ...],
    final_action: Optional[Action],
) -> list[list[object]]:
    trace: list[Action] = [] if final_action is None else [final_action]
    cursor: Optional[tuple[object, ...]] = key
    while cursor is not None:
        previous, action = parent[cursor]
        if action is not None:
            trace.append(action)
        cursor = previous
    trace.reverse()
    return [list(action) for action in trace]


def _counterexample_for(
    error: SafetyViolation,
    parent: dict[tuple[object, ...], tuple[Optional[tuple[object, ...]], Optional[Action]]],
    key: tuple[object, ...],
    final_action: Optional[Action],
) -> dict[str, object]:
    return {
        "error": str(error),
        "rotation_mode": str(key[0]),
        "trace": _trace_for(parent, key, final_action),
    }


def explore_formal_state(
    max_states: int = 1_000_000,
    *,
    model_factory: Callable[..., VersionSafetyModel] = VersionSafetyModel,
) -> dict[str, object]:
    """BFS the complete frozen domain; a cap hit is explicitly incomplete."""
    if isinstance(max_states, bool) or not isinstance(max_states, int) or max_states < 2:
        raise ValueError("max_states must be an integer >= 2")
    coverage = _empty_coverage()
    rotation_modes = coverage["rotation_modes"]
    active_scopes = coverage["active_scopes"]
    assert isinstance(rotation_modes, dict) and isinstance(active_scopes, dict)
    frontier: deque[tuple[VersionSafetyModel, tuple[object, ...]]] = deque()
    parent: dict[tuple[object, ...], tuple[Optional[tuple[object, ...]], Optional[Action]]] = {}
    seen: set[tuple[object, ...]] = set()
    state_hasher = hashlib.sha256()
    transition_hasher = hashlib.sha256()
    for mode, dual_active in (("single-active", False), ("dual-active", True)):
        model = model_factory(
            prepare_second_version=True,
            dual_active=dual_active,
            formal_bounds=True,
        )
        model.check_invariants()
        key = (mode, *model.state_key())
        seen.add(key)
        parent[key] = (None, None)
        frontier.append((model, key))
        state_hasher.update((_identity(key) + "\n").encode("ascii"))
        rotation_modes[mode] += 1
        active_scopes["g1/v1"] += 1

    explored_transitions = 0
    login_transitions = 0
    structural_false_rejects = 0
    while frontier:
        model, key = frontier.popleft()
        try:
            model.check_invariants()
        except SafetyViolation as error:
            return {
                "status": "VIOLATION",
                "frontier_exhausted": False,
                "truncated": False,
                "quotient_state_count": len(seen),
                "concrete_transition_count": explored_transitions,
                "login_transition_count": login_transitions,
                "structural_false_rejects": structural_false_rejects,
                "counterexample": _counterexample_for(error, parent, key, None),
                "coverage": coverage,
                "state_key_schema_id": STATE_KEY_SCHEMA_ID,
                "transition_schema_id": TRANSITION_SCHEMA_ID,
                "equivalence_relation_id": EQUIVALENCE_RELATION_ID,
                "reduction_contract_id": REDUCTION_CONTRACT_ID,
                "reduction_semantics": formal_reduction_contract(),
                "state_set_digest": state_hasher.hexdigest(),
                "transition_digest": transition_hasher.hexdigest(),
            }
        for action in model.available_actions(exhaustive=True):
            child = model.clone()
            try:
                result = child.apply(action)
                child.check_invariants()
            except SafetyViolation as error:
                return {
                    "status": "VIOLATION",
                    "frontier_exhausted": False,
                    "truncated": False,
                    "quotient_state_count": len(seen),
                    "concrete_transition_count": explored_transitions + 1,
                    "login_transition_count": login_transitions + int(action[0] == "login"),
                    "structural_false_rejects": structural_false_rejects
                    + int(action[0] == "login"),
                    "counterexample": _counterexample_for(error, parent, key, action),
                    "coverage": coverage,
                    "state_key_schema_id": STATE_KEY_SCHEMA_ID,
                    "transition_schema_id": TRANSITION_SCHEMA_ID,
                    "equivalence_relation_id": EQUIVALENCE_RELATION_ID,
                    "reduction_contract_id": REDUCTION_CONTRACT_ID,
                    "reduction_semantics": formal_reduction_contract(),
                    "state_set_digest": state_hasher.hexdigest(),
                    "transition_digest": transition_hasher.hexdigest(),
                }
            explored_transitions += 1
            login_transitions += int(action[0] == "login")
            structural_false_rejects += _record_coverage(coverage, model, action, result, child)
            mode = str(key[0])
            child_key = (mode, *child.state_key())
            transition_hasher.update(
                (
                    _canonical_json(
                        {
                            "source": _identity(key),
                            "action": _jsonable(action),
                            "result": result,
                            "target": _identity(child_key),
                        }
                    )
                    + "\n"
                ).encode("utf-8")
            )
            if child_key in seen:
                continue
            if len(seen) >= max_states:
                return {
                    "status": "INCOMPLETE_STATE_CAP",
                    "frontier_exhausted": False,
                    "truncated": True,
                    "quotient_state_count": len(seen),
                    "concrete_transition_count": explored_transitions,
                    "login_transition_count": login_transitions,
                    "structural_false_rejects": structural_false_rejects,
                    "counterexample": None,
                    "coverage": coverage,
                    "state_key_schema_id": STATE_KEY_SCHEMA_ID,
                    "transition_schema_id": TRANSITION_SCHEMA_ID,
                    "equivalence_relation_id": EQUIVALENCE_RELATION_ID,
                    "reduction_contract_id": REDUCTION_CONTRACT_ID,
                    "reduction_semantics": formal_reduction_contract(),
                    "state_set_digest": state_hasher.hexdigest(),
                    "transition_digest": transition_hasher.hexdigest(),
                }
            seen.add(child_key)
            parent[child_key] = (key, action)
            frontier.append((child, child_key))
            state_hasher.update((_identity(child_key) + "\n").encode("ascii"))
    return {
        "status": "MODEL_CHECK_PASS",
        "frontier_exhausted": True,
        "truncated": False,
        "quotient_state_count": len(seen),
        "concrete_transition_count": explored_transitions,
        "login_transition_count": login_transitions,
        "structural_false_rejects": structural_false_rejects,
        "counterexample": None,
        "coverage": coverage,
        "state_key_schema_id": STATE_KEY_SCHEMA_ID,
        "transition_schema_id": TRANSITION_SCHEMA_ID,
        "equivalence_relation_id": EQUIVALENCE_RELATION_ID,
        "reduction_contract_id": REDUCTION_CONTRACT_ID,
        "reduction_semantics": formal_reduction_contract(),
        "state_set_digest": state_hasher.hexdigest(),
        "transition_digest": transition_hasher.hexdigest(),
    }


def explore_test_fixture(max_states: int = 1_000) -> dict[str, object]:
    """Return a complete, visibly non-evidentiary consumer-test fixture."""
    report = explore_formal_state(max_states=max_states, model_factory=FormalFixtureModel)
    return {**report, "execution_classification": "TEST_FIXTURE_ONLY"}


def explore_small_state(max_depth: int = 8, max_states: int = 25_000) -> dict[str, int]:
    """Legacy bounded smoke explorer; it is intentionally not formal evidence."""
    initial = VersionSafetyModel(prepare_second_version=True, formal_bounds=True)
    frontier: list[tuple[VersionSafetyModel, int]] = [(initial, 0)]
    seen = {initial.state_key()}
    explored_transitions = 0
    login_transitions = 0
    reached_version_two = False
    while frontier:
        model, depth = frontier.pop()
        model.check_invariants()
        reached_version_two |= model.current_scope == (1, 2)
        if depth >= max_depth:
            continue
        for action in model.available_actions(exhaustive=True):
            child = model.clone()
            child.apply(action)
            child.check_invariants()
            explored_transitions += 1
            login_transitions += int(action[0] == "login")
            key = child.state_key()
            if key in seen:
                continue
            seen.add(key)
            if len(seen) >= max_states:
                return {
                    "states": len(seen),
                    "transitions": explored_transitions,
                    "login_transitions": login_transitions,
                    "reached_version_two": int(reached_version_two),
                    "truncated": 1,
                    "invariant_violations": 0,
                }
            frontier.append((child, depth + 1))
    return {
        "states": len(seen),
        "transitions": explored_transitions,
        "login_transitions": login_transitions,
        "reached_version_two": int(reached_version_two),
        "truncated": 0,
        "invariant_violations": 0,
    }


def format_report(report: dict[str, object]) -> str:
    return json.dumps(report, sort_keys=True, allow_nan=False)
