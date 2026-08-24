#!/usr/bin/env python3
"""Fail-closed validator and paired-seed aggregator for E4 replay rows."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import ROUND_HALF_EVEN, Decimal, localcontext
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dataplane.negative_cache import (  # noqa: E402
    EvictionPolicy,
    LruPolicy,
    NegativeCache,
    NegativeKey,
    NegativeKeyDeriver,
    TinyLfuPolicy,
)
from dataplane.types import DirectoryStatus, DirectoryView  # noqa: E402
from experiments.runners.filter_bench import SyntheticCredentialSet  # noqa: E402
from experiments.runners.replay_bench import (  # noqa: E402
    ADAPTIVE_INVARIANT_PERIOD_EVENTS,
    AGGREGATE_FLOAT_QUANTA,
    CACHE_ALLOCATOR_OVERHEAD_BYTES_PER_SLOT,
    CACHE_ENTRY_BYTES_PER_SLOT,
    CACHE_ENTRY_FIELDS_BYTES,
    CACHE_FIXED_FIELDS_BYTES,
    CACHE_FIXED_METADATA_BYTES,
    CACHE_HASH_TABLE_MAX_LOAD,
    CACHE_HASH_TABLE_MAX_LOAD_DENOMINATOR,
    CACHE_HASH_TABLE_MAX_LOAD_NUMERATOR,
    CACHE_MEMORY_LAYOUT_VERSION,
    CACHE_POLICY_BYTES_PER_SLOT,
    EXPECTED_FORMAL_ROWS,
    FORMAL_CONTRACT_ID,
    FRONTEND_MEASUREMENT_SCOPE,
    G2_CHECKS_PER_TUPLE_MAX,
    G2_STATIC_WORK_IMPROVEMENT_MIN,
    METHODS_BY_RESULT_NAME,
    NUMERIC_CONTRACT_ID,
    NUMERIC_DECIMAL_PRECISION,
    REPLAY_ROW_FIELDS,
    ROW_SCHEMA,
    SOURCE_ATTESTATION_FIELDS,
    SOURCE_ATTESTATION_SCHEMA,
    SOURCE_STATUS_SCOPE,
    Scenario,
    _canonical_cuckoo_analytic_fpr,
    _canonical_row_float,
    _canonical_screen_parameters,
    _decimal_ratio,
    _enforce_git_policy,
    _exact_filter_load_accepted,
    _git_metadata,
    _parse_scenarios,
    _ratio_at_least,
    _ratio_at_most,
    _row_difference,
    _row_product,
    _row_ratio,
    _source_metadata,
    _to_decimal,
    expected_points,
    load_config,
)
from reference.adaptive import (  # noqa: E402
    AdaptiveCuckooFilter,
    ExactLfuPolicy,
    FutureReuseOraclePolicy,
)
from reference.filters import CuckooFilter, ScreenQuery  # noqa: E402
from reference.filters.common import TOKEN_BYTES, alignment_padding  # noqa: E402

AGGREGATE_SCHEMA = "traps-e4-controlled-replay-aggregate-v3"
TRACE_SCHEMA = "traps-e4-generated-trace-summary-v2"
STATIC_METHOD = "static_cuckoo_no_cache"
G2_BLOCKED_STATUS = "BLOCKED_PENDING_PHASE1_AND_E7"
EXTERNAL_STATUS = "TAF_AND_AQF_REQUIRE_SEPARATE_HARNESS"
_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_T_CRITICAL_95 = {
    1: "12.7062047364",
    2: "4.30265272975",
    3: "3.18244630528",
    4: "2.7764451052",
    5: "2.57058183564",
    6: "2.44691184879",
    7: "2.36462425101",
    8: "2.30600413503",
    9: "2.26215716285",
    10: "2.22813885196",
    11: "2.20098516008",
    12: "2.17881282966",
    13: "2.16036865646",
    14: "2.14478668792",
    15: "2.13144954556",
    16: "2.11990529922",
    17: "2.10981557783",
    18: "2.10092204024",
    19: "2.09302405441",
    20: "2.08596344727",
    21: "2.07961384473",
    22: "2.0738730679",
    23: "2.06865761042",
    24: "2.06389856163",
    25: "2.05953855275",
    26: "2.05552943864",
    27: "2.05183051648",
    28: "2.0484071418",
    29: "2.04522964213",
    30: "2.0422724563",
}


class EvidenceValidationError(ValueError):
    pass


@dataclass(frozen=True)
class _ReferenceDiscovery:
    queries: tuple[ScreenQuery, ...]
    scanned: int
    false_positives: int


@dataclass(frozen=True)
class _ReferenceEvent:
    query: ScreenQuery
    view: DirectoryView
    negative_key: NegativeKey
    occurrence: int
    logical_time: float


def _canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _filter_seed(seed: int, screen_kind: str) -> int:
    material = f"R-TRAPS/E4/{screen_kind}/{seed}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def _query_set_id(queries: Sequence[ScreenQuery]) -> str:
    digest = hashlib.sha256(b"TRAPS/E4/query-set/v1\x00")
    digest.update(len(queries).to_bytes(8, "big"))
    for query in queries:
        digest.update(query.account_index.to_bytes(8, "big"))
        digest.update(query.token)
    return digest.hexdigest()


def _reference_view(account_index: int) -> DirectoryView:
    account_id = f"replay-account-{account_index}"
    return DirectoryView(
        username=account_id,
        canonical_username=account_id,
        status=DirectoryStatus.PRESENT,
        account_id=account_id,
        account_generation=1,
        credential_set_version=1,
        salt=b"controlled-replay",
        encoding_version=1,
        retry_class="controlled",
        active_authenticator_ids=frozenset({"password"}),
        directory_epoch=1,
        reason="controlled E4 replay view",
    )


def _reference_build_screen(
    members: list[ScreenQuery], seed: int, screen_kind: str, config: Mapping[str, Any]
):
    parameters = {
        "fingerprint_bits": int(config["fingerprint_bits"]),
        "bucket_size": int(config["bucket_size"]),
        "target_load": float(config["target_load"]),
        "seed": _filter_seed(seed, screen_kind),
        "max_kicks": int(config["max_kicks"]),
        "max_seed_attempts": int(config["max_seed_attempts"]),
    }
    if screen_kind == "static_cuckoo":
        return CuckooFilter.build(members, **parameters)
    if screen_kind == "adaptive_cuckoo":
        return AdaptiveCuckooFilter.build(members, **parameters)
    raise EvidenceValidationError(f"unknown reference screen kind {screen_kind!r}")


def _reference_assert_adaptive(screen: AdaptiveCuckooFilter) -> None:
    with screen._lock:
        slots_per_table = screen.bucket_count * screen.bucket_size
        represented: set[bytes] = set()
        occupied = 0
        for slot, key in enumerate(screen._keys):
            if key is None:
                continue
            occupied += 1
            if key in represented:
                raise EvidenceValidationError("reference ACF contains a duplicate key")
            represented.add(key)
            table, table_slot = divmod(slot, slots_per_table)
            bucket, offset = divmod(table_slot, screen.bucket_size)
            if table not in (0, 1) or screen._bucket(key, table) != bucket:
                raise EvidenceValidationError("reference ACF key is in the wrong bucket")
            if screen._fingerprints.get(slot) != screen._fingerprint(key, offset):
                raise EvidenceValidationError("reference ACF fingerprint/key mismatch")
            if not screen.query(ScreenQuery(0, key)).positive:
                raise EvidenceValidationError("reference ACF lost a represented key")
        if occupied != screen.n_items:
            raise EvidenceValidationError("reference ACF occupancy differs from n_items")


class _ReferenceReplay:
    """Independent, no-timing semantic replay reconstructed from frozen coordinates."""

    def __init__(
        self,
        config: Mapping[str, Any],
        dataset: SyntheticCredentialSet,
        members: list[ScreenQuery],
        scenarios: Mapping[str, Scenario],
    ) -> None:
        self.config = config
        self.dataset = dataset
        self.members = members
        self.scenarios = scenarios
        self.required_total = max(scenario.key_count for scenario in scenarios.values())
        self.required_same = max(
            (scenario.key_count for scenario in scenarios.values() if scenario.same_account),
            default=0,
        )
        self._discoveries: dict[tuple[int, str], _ReferenceDiscovery] = {}
        self._results: dict[tuple[int, str, str, int, str], dict[str, Any]] = {}

    def _discovery(self, seed: int, screen_kind: str) -> _ReferenceDiscovery:
        cache_key = (seed, screen_kind)
        cached = self._discoveries.get(cache_key)
        if cached is not None:
            return cached
        screen = _reference_build_screen(
            self.members, seed, screen_kind, self.config["filter"]
        )
        found: list[ScreenQuery] = []
        per_account: dict[int, int] = {}
        false_positive_count = 0
        search_limit = int(self.config["dataset"]["false_positive_search_limit"])
        for invalid_index in range(search_limit):
            query = self.dataset.nonmember(invalid_index)
            if not screen.query(query).positive:
                continue
            false_positive_count += 1
            found.append(query)
            per_account[query.account_index] = per_account.get(query.account_index, 0) + 1
            enough_account = (
                self.required_same == 0
                or max(per_account.values(), default=0) >= self.required_same
            )
            if len(found) >= self.required_total and enough_account:
                discovery = _ReferenceDiscovery(
                    tuple(found), invalid_index + 1, false_positive_count
                )
                self._discoveries[cache_key] = discovery
                return discovery
        raise EvidenceValidationError(
            "reference false-positive discovery exhausted the frozen search limit"
        )

    @staticmethod
    def _select_queries(
        discovery: _ReferenceDiscovery, scenario: Scenario
    ) -> list[ScreenQuery]:
        if not scenario.same_account:
            return list(discovery.queries[: scenario.key_count])
        grouped: dict[int, list[ScreenQuery]] = {}
        for query in discovery.queries:
            grouped.setdefault(query.account_index, []).append(query)
        eligible = [
            values for values in grouped.values() if len(values) >= scenario.key_count
        ]
        if not eligible:
            raise EvidenceValidationError(
                f"reference discovery has no account with {scenario.key_count} positives"
            )
        eligible.sort(key=lambda values: (values[0].account_index, values[0].token))
        return eligible[0][: scenario.key_count]

    @staticmethod
    def _negative_deriver(seed: int) -> NegativeKeyDeriver:
        key = hashlib.sha256(f"R-TRAPS/E4/negative-key/{seed}".encode()).digest()
        return NegativeKeyDeriver(key)

    def _build_events(
        self,
        seed: int,
        selected: Sequence[ScreenQuery],
        multiplicity: int,
        scenario: Scenario,
    ) -> list[_ReferenceEvent]:
        if scenario.order == "grouped":
            indexed = [
                (query, occurrence)
                for query in selected
                for occurrence in range(multiplicity)
            ]
        else:
            indexed = [
                (query, occurrence)
                for occurrence in range(multiplicity)
                for query in selected
            ]
        deriver = self._negative_deriver(seed)
        events: list[_ReferenceEvent] = []
        for index, (query, occurrence) in enumerate(indexed):
            view = _reference_view(query.account_index)
            events.append(
                _ReferenceEvent(
                    query=query,
                    view=view,
                    negative_key=deriver.derive(view, query.token),
                    occurrence=occurrence,
                    logical_time=index * scenario.event_interval_seconds,
                )
            )
        return events

    def _policy(
        self, name: str, sequence: Sequence[NegativeKey]
    ) -> EvictionPolicy:
        if name in {"lru", "fixed_ttl"}:
            return LruPolicy()
        if name == "lfu":
            return ExactLfuPolicy()
        if name == "tinylfu":
            return TinyLfuPolicy(
                reset_after=int(self.config["cache"]["tinylfu_reset_after"])
            )
        if name == "future_oracle":
            return FutureReuseOraclePolicy(sequence)
        raise EvidenceValidationError(f"unknown reference cache policy {name!r}")

    def _cache(
        self,
        method_name: str,
        scenario: Scenario,
        events: Sequence[_ReferenceEvent],
    ) -> tuple[NegativeCache | None, EvictionPolicy | None, float]:
        method = METHODS_BY_RESULT_NAME[method_name]
        if method.cache_policy is None:
            return None, None, 0.0
        policy = self._policy(
            method.cache_policy, [event.negative_key for event in events]
        )
        ttl = float(
            self.config["cache"]["fixed_ttl_seconds"]
            if method.cache_policy == "fixed_ttl"
            else self.config["cache"]["retention_ttl_seconds"]
        )
        cache = NegativeCache(
            capacity=scenario.cache_capacity,
            policy=policy,
            max_ttl_seconds=ttl,
            max_entries_per_account=scenario.max_entries_per_account,
        )
        return cache, policy, ttl

    @staticmethod
    def _insert(
        cache: NegativeCache | None,
        event: _ReferenceEvent,
        ttl: float,
        logical_time: float,
    ) -> None:
        if cache is not None:
            cache.insert(
                event.negative_key,
                event.view,
                region=0,
                ttl_seconds=ttl,
                now=logical_time,
            )

    def _replay(
        self,
        screen,
        method_name: str,
        scenario: Scenario,
        events: Sequence[_ReferenceEvent],
        mode: str,
    ) -> dict[str, Any]:
        method = METHODS_BY_RESULT_NAME[method_name]
        cache, policy, ttl = self._cache(method_name, scenario, events)
        backend_calls = 0
        screen_forwards = 0
        first_seen_forwards = 0
        adaptation_attempts = 0
        adaptations = 0
        leaders = 0
        suppressed = 0
        peak_waiters = 0
        processed_events = 0
        invariant_checks = 0

        if method.adaptive:
            if not isinstance(screen, AdaptiveCuckooFilter):
                raise EvidenceValidationError("adaptive reference requires an ACF screen")
            _reference_assert_adaptive(screen)
            invariant_checks = 1

        def record_processed() -> None:
            nonlocal processed_events, invariant_checks
            processed_events += 1
            if method.adaptive and processed_events % ADAPTIVE_INVARIANT_PERIOD_EVENTS == 0:
                assert isinstance(screen, AdaptiveCuckooFilter)
                _reference_assert_adaptive(screen)
                invariant_checks += 1

        def lookup(event: _ReferenceEvent, now: float) -> bool:
            if cache is None:
                return False
            return cache.lookup(
                event.negative_key, expected_view=event.view, now=now
            ).hit

        if mode == "sequential":
            for event in events:
                hit = lookup(event, event.logical_time)
                positive = False if hit else screen.query(event.query).positive
                if positive:
                    screen_forwards += 1
                    first_seen_forwards += int(event.occurrence == 0)
                    backend_calls += 1
                    leaders += int(method.singleflight)
                    if method.adaptive:
                        adaptation_attempts += 1
                        adaptations += int(screen.confirm_false_positive(event.query))
                    self._insert(cache, event, ttl, event.logical_time)
                record_processed()
        elif mode == "concurrent":
            width = int(self.config["replay"]["concurrency"])
            for start in range(0, len(events), width):
                batch = events[start : start + width]
                batch_time = batch[0].logical_time
                positive: list[_ReferenceEvent] = []
                for event in batch:
                    if lookup(event, batch_time):
                        continue
                    if not screen.query(event.query).positive:
                        continue
                    positive.append(event)
                    screen_forwards += 1
                    first_seen_forwards += int(event.occurrence == 0)
                if method.singleflight:
                    groups: dict[NegativeKey, int] = {}
                    for event in positive:
                        groups[event.negative_key] = groups.get(event.negative_key, 0) + 1
                    batch_suppressed = len(positive) - len(groups)
                    if any(
                        count - 1 > int(self.config["replay"]["max_waiters_per_key"])
                        for count in groups.values()
                    ) or batch_suppressed > int(
                        self.config["replay"]["max_waiters_global"]
                    ):
                        raise EvidenceValidationError(
                            "frozen reference replay exceeds singleflight waiter caps"
                        )
                    backend_calls += len(groups)
                    leaders += len(groups)
                    suppressed += batch_suppressed
                    peak_waiters = max(peak_waiters, batch_suppressed)
                else:
                    backend_calls += len(positive)
                for event in positive:
                    if method.adaptive:
                        adaptation_attempts += 1
                        adaptations += int(screen.confirm_false_positive(event.query))
                    self._insert(cache, event, ttl, batch_time)
                for _ in batch:
                    record_processed()
        else:
            raise EvidenceValidationError(f"unknown reference replay mode {mode!r}")

        if method.adaptive:
            assert isinstance(screen, AdaptiveCuckooFilter)
            _reference_assert_adaptive(screen)
            invariant_checks += 1

        cache_metrics = cache.metrics_snapshot() if cache is not None else {}
        oracle_mismatches = (
            policy.alignment_mismatches
            if isinstance(policy, FutureReuseOraclePolicy)
            else None
        )
        member_false_negatives = sum(
            not screen.query(member).positive for member in self.members
        )
        return {
            "backend_invalid_checks": backend_calls,
            "screen_positive_forwards": screen_forwards,
            "first_seen_positive_forwards": first_seen_forwards,
            "cache_hits": int(cache_metrics.get("hits", 0)),
            "cache_misses": int(cache_metrics.get("misses", 0)),
            "cache_evictions": int(cache_metrics.get("evictions", 0)),
            "cache_admissions": int(cache_metrics.get("inserts", 0)),
            "cache_admission_rejected": int(cache_metrics.get("admission_rejected", 0)),
            "cache_updates": int(cache_metrics.get("updates", 0)),
            "cache_expirations": int(cache_metrics.get("expired", 0)),
            "cache_account_quota_pressure": int(
                cache_metrics.get("account_quota_pressure", 0)
            ),
            "singleflight_leaders": leaders,
            "singleflight_suppressed": suppressed,
            "singleflight_peak_waiters": peak_waiters,
            "singleflight_waiter_timeouts": 0,
            "adaptive_feedback_attempts": adaptation_attempts,
            "adaptive_updates": adaptations,
            "adaptive_invariant_checks": invariant_checks,
            "adaptive_invariant_violations": 0,
            "oracle_schedule_alignment_mismatches": oracle_mismatches,
            "member_false_negatives": member_false_negatives,
        }

    def result(
        self, key: tuple[int, str, str, int, str]
    ) -> dict[str, Any]:
        cached = self._results.get(key)
        if cached is not None:
            return cached
        seed, method_name, scenario_name, multiplicity, mode = key
        method = METHODS_BY_RESULT_NAME[method_name]
        scenario = self.scenarios[scenario_name]
        discovery = self._discovery(seed, method.screen_kind)
        selected = self._select_queries(discovery, scenario)
        events = self._build_events(seed, selected, multiplicity, scenario)
        screen = _reference_build_screen(
            self.members, seed, method.screen_kind, self.config["filter"]
        )
        initial_screen_parameters = _canonical_screen_parameters(screen)
        result = self._replay(screen, method_name, scenario, events, mode)
        final_screen_parameters = _canonical_screen_parameters(screen)
        result.update(
            {
                "discovery_scanned": discovery.scanned,
                "discovery_count": discovery.false_positives,
                "discovery_positive_set_id": _query_set_id(discovery.queries),
                "selected_query_set_id": _query_set_id(selected),
                "initial_screen_parameters": initial_screen_parameters,
                "final_screen_parameters": final_screen_parameters,
            }
        )
        self._results[key] = result
        return result


def _strict_json(text: str, source: str) -> Any:
    def reject_constant(value: str) -> None:
        raise EvidenceValidationError(f"{source}: non-finite JSON constant {value}")

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceValidationError(f"{source}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    def parse_float(value: str) -> float:
        result = float(value)
        if not math.isfinite(result):
            raise EvidenceValidationError(f"{source}: non-finite JSON number {value}")
        if result == 0.0 and value.startswith("-"):
            raise EvidenceValidationError(f"{source}: negative zero is not canonical JSON")
        return result

    def parse_int(value: str) -> int:
        result = int(value)
        if result == 0 and value.startswith("-"):
            raise EvidenceValidationError(f"{source}: negative zero is not canonical JSON")
        return result

    try:
        return json.loads(
            text,
            parse_constant=reject_constant,
            parse_float=parse_float,
            parse_int=parse_int,
            object_pairs_hook=reject_duplicate_keys,
        )
    except json.JSONDecodeError as error:
        raise EvidenceValidationError(f"{source}: invalid JSON: {error}") from error


def _walk_finite_nonnegative(value: Any, path: str = "row") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise EvidenceValidationError(f"{path} must be finite")
        if isinstance(value, float) and value == 0.0 and math.copysign(1.0, value) < 0:
            raise EvidenceValidationError(f"{path} must not be negative zero")
        if value < 0 and path != "row.filter_load_delta_from_target":
            raise EvidenceValidationError(f"{path} must be non-negative")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _walk_finite_nonnegative(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _walk_finite_nonnegative(item, f"{path}.{key}")
        return
    raise EvidenceValidationError(f"{path} has unsupported type {type(value).__name__}")


def _require_int(row: Mapping[str, Any], field: str) -> int:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceValidationError(f"{field} must be a non-negative integer")
    return value


def _require_number(row: Mapping[str, Any], field: str) -> float:
    value = row.get(field)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvidenceValidationError(f"{field} must be numeric")
    result = float(value)
    if (
        not math.isfinite(result)
        or result < 0.0
        or (result == 0.0 and math.copysign(1.0, result) < 0)
    ):
        raise EvidenceValidationError(f"{field} must be finite and non-negative")
    return result


def _parse_utc(value: Any, context: str) -> datetime:
    if not isinstance(value, str):
        raise EvidenceValidationError(f"{context} must be a canonical UTC ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise EvidenceValidationError(
            f"{context} must be a canonical UTC ISO-8601 string"
        ) from error
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() != timezone.utc.utcoffset(parsed)
        or parsed.isoformat() != value
    ):
        raise EvidenceValidationError(f"{context} must be canonical UTC with +00:00 offset")
    return parsed


def _require_exact(actual: Any, expected: Any, context: str) -> None:
    if not _typed_equal(actual, expected):
        raise EvidenceValidationError(
            f"{context} differs: expected {expected!r}, found {actual!r}"
        )


def _typed_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _typed_equal(actual[key], expected[key]) for key in expected
        )
    if isinstance(expected, (list, tuple)):
        return len(actual) == len(expected) and all(
            _typed_equal(left, right) for left, right in zip(actual, expected, strict=True)
        )
    if isinstance(expected, float) and expected == 0.0:
        return actual == expected and math.copysign(1.0, actual) == math.copysign(
            1.0, expected
        )
    return actual == expected


def _expected_layout_manifest() -> dict[str, Any]:
    entry_fields_total = sum(CACHE_ENTRY_FIELDS_BYTES.values())
    entry_aligned = ((entry_fields_total + 7) // 8) * 8
    hash_slack = (
        (
            entry_aligned * CACHE_HASH_TABLE_MAX_LOAD_DENOMINATOR
            + CACHE_HASH_TABLE_MAX_LOAD_NUMERATOR
            - 1
        )
        // CACHE_HASH_TABLE_MAX_LOAD_NUMERATOR
        - entry_aligned
    )
    entry_total = entry_aligned + hash_slack + CACHE_ALLOCATOR_OVERHEAD_BYTES_PER_SLOT
    fixed_total = ((sum(CACHE_FIXED_FIELDS_BYTES.values()) + 7) // 8) * 8
    _require_exact(entry_total, CACHE_ENTRY_BYTES_PER_SLOT, "compiled cache entry layout")
    _require_exact(fixed_total, CACHE_FIXED_METADATA_BYTES, "compiled cache fixed layout")
    return {
        "schema": CACHE_MEMORY_LAYOUT_VERSION,
        "entry_fields_bytes": dict(CACHE_ENTRY_FIELDS_BYTES),
        "entry_fields_total_bytes": entry_fields_total,
        "entry_aligned_bytes": entry_aligned,
        "hash_table_max_load": _canonical_row_float(
            "memory_cache_layout_manifest.hash_table_max_load",
            CACHE_HASH_TABLE_MAX_LOAD,
        ),
        "hash_table_slack_bytes_per_slot": hash_slack,
        "allocator_overhead_bytes_per_slot": CACHE_ALLOCATOR_OVERHEAD_BYTES_PER_SLOT,
        "entry_bytes_per_slot": entry_total,
        "fixed_fields_bytes": dict(CACHE_FIXED_FIELDS_BYTES),
        "fixed_metadata_bytes": fixed_total,
        "policy_bytes_per_slot": dict(CACHE_POLICY_BYTES_PER_SLOT),
        "scope": (
            "packed in-memory capacity allocation; Python object-graph measurements "
            "are reported separately"
        ),
    }


def _cache_memory_expected(
    method_name: str, scenario: Scenario
) -> tuple[int, int | None, int, int | None, int, int | None, bool, str | None]:
    method = METHODS_BY_RESULT_NAME[method_name]
    if method.cache_policy is None:
        return 0, 0, 0, 0, 0, 0, True, None
    entry = scenario.cache_capacity * CACHE_ENTRY_BYTES_PER_SLOT
    if method.cache_policy in CACHE_POLICY_BYTES_PER_SLOT:
        policy_per_slot = CACHE_POLICY_BYTES_PER_SLOT[method.cache_policy]
        policy = scenario.cache_capacity * policy_per_slot
        total = entry + policy + CACHE_FIXED_METADATA_BYTES
        return (
            entry,
            policy,
            CACHE_FIXED_METADATA_BYTES,
            total,
            CACHE_ENTRY_BYTES_PER_SLOT,
            policy_per_slot,
            True,
            None,
        )
    reason = (
        "Python Counter baseline has no packed fixed-memory TinyLFU sketch layout"
        if method.cache_policy == "tinylfu"
        else "offline future sequence is non-deployable and excluded from edge memory"
    )
    return (
        entry,
        None,
        CACHE_FIXED_METADATA_BYTES,
        None,
        CACHE_ENTRY_BYTES_PER_SLOT,
        None,
        False,
        reason,
    )


def _screen_memory_expected(row: Mapping[str, Any]) -> tuple[int, int]:
    parameters = row["filter_parameters"]
    if not isinstance(parameters, dict):
        raise EvidenceValidationError("filter_parameters must be a mapping")
    fingerprint_bits = _require_int(parameters, "fingerprint_bits")
    bucket_size = _require_int(parameters, "bucket_size")
    metadata_bytes = struct.calcsize(">8sHQQHHIQI16s")
    if row["screen_kind"] == "static_cuckoo":
        bucket_count = _require_int(parameters, "bucket_count")
        slots = bucket_count * bucket_size
        _require_exact(parameters["m_bits"], slots * fingerprint_bits, "filter m_bits")
        backing = 0
    elif row["screen_kind"] == "adaptive_cuckoo":
        bucket_count = _require_int(parameters, "bucket_count_per_table")
        slots = 2 * bucket_count * bucket_size
        _require_exact(parameters["tables"], 2, "adaptive table count")
        occupancy_bytes = (slots + 7) // 8
        backing_payload = slots * TOKEN_BYTES + occupancy_bytes
        backing_metadata = struct.calcsize(">8sHQQH")
        backing = (
            backing_payload
            + backing_metadata
            + alignment_padding(backing_payload)
            + alignment_padding(backing_metadata)
        )
    else:
        raise EvidenceValidationError(f"unknown screen_kind {row['screen_kind']!r}")
    payload = (slots * fingerprint_bits + 7) // 8
    screen = payload + metadata_bytes + alignment_padding(payload) + alignment_padding(
        metadata_bytes
    )
    return screen, backing


def _scenario_map(config: Mapping[str, Any]) -> dict[str, Scenario]:
    return {scenario.name: scenario for scenario in _parse_scenarios(dict(config))}


def _trace_summary_expected(
    config: Mapping[str, Any], scenario: Scenario, multiplicity: int, mode: str
) -> dict[str, Any]:
    event_count = scenario.key_count * multiplicity
    interval = _canonical_row_float(
        "trace_summary.event_interval_seconds", scenario.event_interval_seconds
    )
    logical_start = _canonical_row_float("trace_summary.logical_start_seconds", 0)
    logical_end = _row_product(
        "trace_summary.logical_end_seconds", event_count - 1, interval
    )
    logical_window = _row_product(
        "trace_summary.logical_window_seconds", event_count, interval
    )
    return {
        "schema": TRACE_SCHEMA,
        "event_count": event_count,
        "distinct_tuple_count": scenario.key_count,
        "multiplicity": multiplicity,
        "order": scenario.order,
        "mode": mode,
        "event_interval_seconds": interval,
        "logical_start_seconds": logical_start,
        "logical_end_seconds": logical_end,
        "logical_window_seconds": logical_window,
        "generated_request_rate_per_second": _row_ratio(
            "trace_summary.generated_request_rate_per_second",
            event_count,
            _to_decimal(logical_window),
        ),
        "generated_distinct_tuple_rate_per_second": _row_ratio(
            "trace_summary.generated_distinct_tuple_rate_per_second",
            scenario.key_count,
            _to_decimal(logical_window),
        ),
        "concurrent_execution_width": (
            int(config["replay"]["concurrency"]) if mode == "concurrent" else 1
        ),
    }


def _validate_row(
    row: Mapping[str, Any],
    *,
    config: Mapping[str, Any],
    config_hash: str,
    dataset_hash: str,
    scenarios: Mapping[str, Scenario],
    expected_points_set: set[tuple[int, str, str, int, str]],
    reference: _ReferenceReplay,
) -> tuple[int, str, str, int, str]:
    if set(row) != REPLAY_ROW_FIELDS:
        missing = sorted(REPLAY_ROW_FIELDS - set(row))
        extra = sorted(set(row) - REPLAY_ROW_FIELDS)
        raise EvidenceValidationError(
            f"row schema fields differ: missing={missing}, extra={extra}"
        )
    _walk_finite_nonnegative(row)
    _require_exact(row["row_schema"], ROW_SCHEMA, "row_schema")
    _require_exact(row["config_contract_id"], config["contract_id"], "config contract")
    _require_exact(
        row["numeric_contract_id"], NUMERIC_CONTRACT_ID, "numeric contract"
    )
    _require_exact(row["config_hash"], config_hash, "config_hash")
    _require_exact(row["dataset_hash"], dataset_hash, "dataset_hash")
    _require_exact(row["evidence_tier"], config["evidence_tier"], "evidence tier")
    _require_exact(row["experiment"], "E4_controlled_false_positive_replay", "experiment")
    _require_exact(row["research_status"], "RESEARCH_IN_PROGRESS", "research status")
    _require_exact(row["external_baselines_included"], [], "external baseline coverage")
    _require_exact(row["external_baseline_status"], EXTERNAL_STATUS, "external baseline status")
    if row["commit"] is not None and (
        not isinstance(row["commit"], str) or _COMMIT_RE.fullmatch(row["commit"]) is None
    ):
        raise EvidenceValidationError("commit must be null or a 40-character lowercase Git ID")
    if row["git_dirty"] is not None and type(row["git_dirty"]) is not bool:
        raise EvidenceValidationError("git_dirty must be boolean or null")
    _require_exact(row["git_status_scope"], SOURCE_STATUS_SCOPE, "Git status scope")

    seed = _require_int(row, "seed")
    method_name = row["method"]
    scenario_name = row["scenario_name"]
    multiplicity = _require_int(row, "replay_multiplicity")
    mode = row["replay_mode"]
    if method_name not in METHODS_BY_RESULT_NAME:
        raise EvidenceValidationError(f"unknown result method {method_name!r}")
    if scenario_name not in scenarios:
        raise EvidenceValidationError(f"unknown scenario {scenario_name!r}")
    scenario = scenarios[scenario_name]
    method = METHODS_BY_RESULT_NAME[method_name]
    point_key = (seed, method_name, scenario_name, multiplicity, mode)
    if point_key not in expected_points_set:
        raise EvidenceValidationError(f"row point is outside the frozen grid: {point_key!r}")
    point_material = {
        "method": method_name,
        "scenario": scenario_name,
        "multiplicity": multiplicity,
        "mode": mode,
    }
    point_id = _canonical_hash(point_material)[:24]
    _require_exact(row["point_id"], point_id, "point_id")
    run_material = {
        "row_schema": ROW_SCHEMA,
        "commit": row["commit"],
        "config_hash": config_hash,
        "dataset_hash": dataset_hash,
        "seed": seed,
        "point_id": point_id,
    }
    _require_exact(row["run_id"], _canonical_hash(run_material)[:24], "run_id")
    _require_exact(row["seed_shard_ordinal"], list(config["seeds"]).index(seed), "seed ordinal")
    _require_exact(row["scenario"], f"e4_{scenario_name}_{mode}", "scenario label")
    _require_exact(row["replay_order"], scenario.order, "replay order")
    _require_exact(row["screen_kind"], method.screen_kind, "screen kind")
    _require_exact(row["cache_policy"], method.cache_policy, "cache policy")
    _require_exact(row["singleflight_enabled"], method.singleflight, "singleflight flag")
    _require_exact(
        row["cache_capacity_entries"],
        scenario.cache_capacity if method.cache_policy else 0,
        "cache capacity",
    )
    _require_exact(
        row["cache_max_entries_per_account"],
        scenario.max_entries_per_account if method.cache_policy else None,
        "account quota",
    )

    event_count = scenario.key_count * multiplicity
    _require_exact(row["account_count"], config["dataset"]["account_count"], "account count")
    _require_exact(row["distinct_invalid_count"], scenario.key_count, "distinct count")
    _require_exact(row["event_count"], event_count, "event count")
    _require_exact(
        row["replay_request_amplification"],
        _row_ratio("replay_request_amplification", event_count, scenario.key_count),
        "amplification",
    )
    _require_exact(
        row["trace_summary"],
        _trace_summary_expected(config, scenario, multiplicity, mode),
        "trace summary",
    )

    discovery_queries = _require_int(row, "false_positive_discovery_queries")
    discovery_count = _require_int(row, "false_positive_discovery_count")
    reference_result = reference.result(point_key)
    _require_exact(
        row["false_positive_discovery_search_limit"],
        config["dataset"]["false_positive_search_limit"],
        "discovery search limit",
    )
    _require_exact(
        row["false_positive_discovery_required_total"],
        reference.required_total,
        "discovery required total",
    )
    _require_exact(
        row["false_positive_discovery_required_same_account"],
        reference.required_same,
        "discovery same-account requirement",
    )
    _require_exact(
        discovery_queries, reference_result["discovery_scanned"], "discovery scan count"
    )
    _require_exact(
        discovery_count, reference_result["discovery_count"], "discovery positive count"
    )
    _require_exact(
        row["false_positive_discovery_positive_set_id"],
        reference_result["discovery_positive_set_id"],
        "discovery positive set",
    )
    _require_exact(
        row["selected_query_set_id"],
        reference_result["selected_query_set_id"],
        "selected query set",
    )
    if not 0 < discovery_count <= discovery_queries:
        raise EvidenceValidationError("false-positive discovery counts are inconsistent")
    _require_exact(
        row["false_positive_discovery_observed_fpr"],
        _row_ratio(
            "false_positive_discovery_observed_fpr",
            discovery_count,
            discovery_queries,
        ),
        "discovery rate",
    )
    _require_exact(
        row["selection_conditioned_on_observed_false_positive"],
        True,
        "selection condition",
    )

    screen_forwards = _require_int(row, "screen_positive_forwards")
    first_seen = _require_int(row, "first_seen_positive_forwards")
    backend_checks = _require_int(row, "backend_invalid_checks")
    for field in (
        "backend_invalid_checks",
        "screen_positive_forwards",
        "first_seen_positive_forwards",
        "cache_hits",
        "cache_misses",
        "cache_evictions",
        "cache_admissions",
        "cache_admission_rejected",
        "cache_updates",
        "cache_expirations",
        "cache_account_quota_pressure",
        "singleflight_leaders",
        "singleflight_suppressed",
        "singleflight_peak_waiters",
        "singleflight_waiter_timeouts",
        "adaptive_feedback_attempts",
        "adaptive_updates",
        "oracle_schedule_alignment_mismatches",
        "member_false_negatives",
    ):
        _require_exact(row[field], reference_result[field], f"reference replay {field}")
    if screen_forwards > event_count or first_seen > scenario.key_count:
        raise EvidenceValidationError("screen-forward counts exceed trace cardinality")
    if backend_checks > screen_forwards:
        raise EvidenceValidationError("backend checks exceed positive screen forwards")
    _require_exact(row["backend_valid_checks"], 0, "backend valid checks")
    _require_exact(
        row["observed_first_seen_ffr"],
        _row_ratio("observed_first_seen_ffr", first_seen, scenario.key_count),
        "first-seen FFR",
    )
    _require_exact(
        row["observed_request_weighted_ffr"],
        _row_ratio("observed_request_weighted_ffr", screen_forwards, event_count),
        "request-weighted FFR",
    )
    _require_exact(
        row["worst_region_ffr"],
        _row_ratio("worst_region_ffr", screen_forwards, event_count),
        "worst FFR",
    )
    _require_exact(
        row["backend_checks_per_distinct_invalid"],
        _row_ratio(
            "backend_checks_per_distinct_invalid",
            backend_checks,
            scenario.key_count,
        ),
        "checks per distinct tuple",
    )
    _require_exact(
        row["backend_work_amplification_per_tuple"],
        _row_ratio(
            "backend_work_amplification_per_tuple",
            backend_checks,
            scenario.key_count,
        ),
        "backend amplification",
    )

    count_fields = (
        "cache_hits",
        "cache_misses",
        "cache_evictions",
        "cache_admissions",
        "cache_admission_rejected",
        "cache_updates",
        "cache_expirations",
        "cache_account_quota_pressure",
        "cache_global_quota_pressure",
        "singleflight_leaders",
        "singleflight_peak_waiters",
        "singleflight_waiter_timeouts",
        "singleflight_suppressed",
        "singleflight_waiter_queue_peak_bytes",
        "singleflight_idle_python_bytes",
        "singleflight_peak_python_bytes",
        "memory_cache_python_bytes",
        "memory_cache_policy_python_bytes",
        "screen_python_bytes",
        "adaptive_feedback_attempts",
        "adaptive_updates",
        "adaptive_invariant_checks",
        "adaptive_invariant_violations",
        "oracle_future_input_count",
        "member_false_negatives",
        "member_validation_count",
    )
    for field in count_fields:
        _require_int(row, field)
    for field in ("frontend_p50_us", "frontend_p95_us", "frontend_p99_us"):
        _require_exact(row[field], None, field)
    _require_exact(
        row["frontend_measurement_scope"],
        FRONTEND_MEASUREMENT_SCOPE,
        "frontend measurement scope",
    )

    if method.cache_policy is None:
        for field in (
            "cache_hits",
            "cache_misses",
            "cache_evictions",
            "cache_admissions",
            "cache_admission_rejected",
            "cache_updates",
            "cache_expirations",
            "cache_account_quota_pressure",
            "cache_global_quota_pressure",
        ):
            _require_exact(row[field], 0, field)
    else:
        hits = _require_int(row, "cache_hits")
        misses = _require_int(row, "cache_misses")
        if hits + misses != event_count:
            raise EvidenceValidationError("cache hits plus misses must equal event count")
    expected_global_pressure = (
        int(row["cache_evictions"]) + int(row["cache_admission_rejected"])
        if scenario.max_entries_per_account is None
        else 0
    )
    _require_exact(
        row["cache_global_quota_pressure"], expected_global_pressure, "global cache pressure"
    )
    leaders = _require_int(row, "singleflight_leaders")
    suppressed = _require_int(row, "singleflight_suppressed")
    if method.singleflight:
        _require_exact(leaders, backend_checks, "singleflight leaders")
        _require_exact(suppressed, screen_forwards - backend_checks, "singleflight suppression")
    else:
        _require_exact(leaders, 0, "singleflight leaders")
        _require_exact(suppressed, 0, "singleflight suppression")
        _require_exact(backend_checks, screen_forwards, "non-singleflight backend work")
    if row["singleflight_peak_python_bytes"] < row["singleflight_idle_python_bytes"]:
        raise EvidenceValidationError("singleflight peak memory is below idle memory")
    _require_exact(row["singleflight_overlap_delay_seconds"], None, "singleflight delay")
    _require_exact(
        row["singleflight_overlap_model"],
        "frozen_batch_by_concurrency_width",
        "singleflight overlap model",
    )
    _require_exact(row["singleflight_per_waiter_state_bytes"], None, "waiter state size")
    _require_exact(
        row["singleflight_waiter_queue_peak_bytes"], 0, "unmeasured waiter queue memory"
    )
    _require_exact(
        row["singleflight_waiter_memory_scope"],
        "not measured by deterministic E4 semantic replay; E7 owns runtime waiter memory",
        "waiter memory scope",
    )

    layout_expected = _expected_layout_manifest()
    _require_exact(row["memory_cache_layout_manifest"], layout_expected, "cache layout")
    memory_expected = _cache_memory_expected(method_name, scenario)
    memory_fields = (
        "memory_cache_entry_compact_bytes",
        "memory_cache_policy_compact_bytes",
        "memory_cache_fixed_metadata_bytes",
        "memory_cache_bytes",
        "memory_cache_entry_bytes_per_slot",
        "memory_cache_policy_bytes_per_slot",
        "cache_memory_match_eligible",
        "cache_memory_match_exclusion_reason",
    )
    for field, expected in zip(memory_fields, memory_expected, strict=True):
        _require_exact(row[field], expected, field)
    filter_bytes, backing_bytes = _screen_memory_expected(row)
    _require_exact(row["memory_filter_bytes"], filter_bytes, "filter memory")
    _require_exact(row["memory_directory_extra_bytes"], backing_bytes, "backing memory")
    _require_exact(row["memory_model_bytes"], 0, "model memory")
    expected_total = (
        filter_bytes + backing_bytes + memory_expected[3]
        if memory_expected[3] is not None
        else None
    )
    _require_exact(row["memory_total_edge_bytes"], expected_total, "total edge memory")
    if row["screen_python_bytes"] < filter_bytes:
        raise EvidenceValidationError("Python screen memory is below compact filter memory")
    cache_python_bytes = row["memory_cache_python_bytes"]
    policy_python_bytes = row["memory_cache_policy_python_bytes"]
    if method.cache_policy is None:
        _require_exact(cache_python_bytes, 0, "no-cache Python cache memory")
        _require_exact(policy_python_bytes, 0, "no-cache Python policy memory")
    else:
        if policy_python_bytes <= 0:
            raise EvidenceValidationError(
                "cache-enabled Python policy memory must be positive"
            )
        if cache_python_bytes < policy_python_bytes:
            raise EvidenceValidationError(
                "Python cache memory is below its Python policy memory"
            )

    parameters = row["filter_parameters"]
    _require_exact(
        parameters,
        reference_result["initial_screen_parameters"],
        "reference initial screen parameters",
    )
    _require_exact(
        parameters,
        reference_result["final_screen_parameters"],
        "reference final screen parameters",
    )
    expected_parameter_fields = (
        {
            "m_bits",
            "n_items",
            "k_hashes",
            "fingerprint_bits",
            "bucket_count",
            "bucket_size",
            "load_factor",
            "hash_seed",
            "max_kicks",
            "build_attempts",
            "analytic_fpr_standard",
            "analytic_fpr_standard_model",
            "hash_scheme",
        }
        if method.screen_kind == "static_cuckoo"
        else {
            "tables",
            "bucket_count_per_table",
            "bucket_size",
            "fingerprint_bits",
            "n_items",
            "load_factor",
            "hash_seed",
            "max_kicks",
            "build_attempts",
            "adaptation",
            "backing_table",
        }
    )
    _require_exact(set(parameters), expected_parameter_fields, "filter parameter fields")
    _require_exact(
        parameters["fingerprint_bits"],
        config["filter"]["fingerprint_bits"],
        "fingerprint bits",
    )
    _require_exact(parameters["bucket_size"], config["filter"]["bucket_size"], "bucket size")
    _require_exact(parameters["n_items"], config["dataset"]["account_count"], "filter item count")
    _require_exact(parameters["max_kicks"], config["filter"]["max_kicks"], "max kicks")
    build_attempts = _require_int(parameters, "build_attempts")
    if not 1 <= build_attempts <= config["filter"]["max_seed_attempts"]:
        raise EvidenceValidationError("filter build attempts exceed the frozen retry budget")
    expected_hash_seed = (
        _filter_seed(seed, method.screen_kind)
        + (build_attempts - 1) * 0x9E3779B97F4A7C15
    ) & 0xFFFFFFFFFFFFFFFF
    _require_exact(parameters["hash_seed"], expected_hash_seed, "filter hash seed")
    if method.screen_kind == "static_cuckoo":
        slots = parameters["bucket_count"] * parameters["bucket_size"]
        expected_fpr = _canonical_cuckoo_analytic_fpr(
            n_items=parameters["n_items"],
            slots=slots,
            fingerprint_bits=parameters["fingerprint_bits"],
            bucket_size=parameters["bucket_size"],
        )
        _require_exact(parameters["k_hashes"], 2, "cuckoo hash count")
        _require_exact(parameters["analytic_fpr_standard"], expected_fpr, "analytic FPR")
        _require_exact(
            parameters["analytic_fpr_standard_model"],
            "1-(1-load_factor/(2^fingerprint_bits-1))^(2*bucket_size)",
            "analytic FPR model",
        )
        _require_exact(
            parameters["hash_scheme"],
            "BLAKE2b-64 with fingerprint-derived alternate bucket",
            "filter hash scheme",
        )
    else:
        slots = (
            parameters["tables"]
            * parameters["bucket_count_per_table"]
            * parameters["bucket_size"]
        )
        _require_exact(
            parameters["adaptation"],
            "same-bucket cell swap after exact mismatch feedback",
            "adaptive mechanism",
        )
        _require_exact(
            parameters["backing_table"],
            "one-to-one exact 128-bit token slots",
            "adaptive backing table",
        )
    _require_exact(
        parameters["load_factor"],
        _row_ratio(
            "filter_parameters.load_factor",
            config["dataset"]["account_count"],
            slots,
        ),
        "filter load factor",
    )
    _require_exact(row["filter_actual_load"], parameters["load_factor"], "actual filter load")
    _require_exact(
        row["filter_target_load"],
        _canonical_row_float("filter_target_load", config["filter"]["target_load"]),
        "target load",
    )
    _require_exact(
        row["filter_load_acceptance_min"],
        _canonical_row_float(
            "filter_load_acceptance_min",
            config["filter"]["actual_load_acceptance_min"],
        ),
        "load lower bound",
    )
    _require_exact(
        row["filter_load_acceptance_max"],
        _canonical_row_float(
            "filter_load_acceptance_max",
            config["filter"]["actual_load_acceptance_max"],
        ),
        "load upper bound",
    )
    load_pass = _exact_filter_load_accepted(
        _require_int(parameters, "n_items"), slots, config["filter"]
    )
    _require_exact(row["filter_load_acceptance_pass"], load_pass, "load acceptance")
    if not load_pass:
        raise EvidenceValidationError("filter load is outside the accepted interval")
    _require_exact(
        row["filter_load_delta_from_target"],
        _row_difference(
            "filter_load_delta_from_target",
            row["filter_actual_load"],
            row["filter_target_load"],
        ),
        "load delta",
    )
    _require_exact(row["member_validation_count"], row["account_count"], "member validation")
    _require_exact(row["member_false_negatives"], 0, "member false negatives")

    if method.adaptive:
        _require_exact(
            row["adaptive_invariant_check_period_events"],
            ADAPTIVE_INVARIANT_PERIOD_EVENTS,
            "adaptive invariant period",
        )
        expected_checks = 2 + event_count // ADAPTIVE_INVARIANT_PERIOD_EVENTS
        _require_exact(row["adaptive_invariant_checks"], expected_checks, "adaptive checks")
        _require_exact(row["adaptive_invariant_violations"], 0, "adaptive violations")
        if row["adaptive_updates"] > row["adaptive_feedback_attempts"]:
            raise EvidenceValidationError("adaptive updates exceed feedback attempts")
    else:
        _require_exact(row["adaptive_invariant_check_period_events"], None, "adaptive period")
        _require_exact(row["adaptive_invariant_checks"], 0, "adaptive checks")
        _require_exact(row["adaptive_invariant_violations"], 0, "adaptive violations")

    if method.cache_policy == "future_oracle":
        _require_exact(row["oracle_future_input_count"], event_count, "oracle input count")
        _require_exact(row["oracle_schedule_alignment_mismatches"], 0, "oracle alignment")
        _require_exact(row["oracle_schedule_valid"], True, "oracle schedule")
        _require_exact(row["oracle_deployable"], False, "oracle deployability")
    else:
        _require_exact(row["oracle_future_input_count"], 0, "oracle input count")
        _require_exact(row["oracle_schedule_alignment_mismatches"], None, "oracle alignment")
        _require_exact(row["oracle_schedule_valid"], None, "oracle schedule")
        _require_exact(row["oracle_deployable"], None, "oracle deployability")

    _require_exact(row["source_metadata"], _source_metadata(method), "source metadata")
    _require_exact(row["source_metadata_complete"], True, "source metadata completeness")
    _require_exact(row["source_metadata_schema_version"], 1, "source metadata schema")
    _require_exact(
        row["false_positive_discovery_stopping_rule"],
        "stop after required total and same-account group; rate is descriptive and "
        "conditioned on this stopping rule",
        "discovery stopping rule",
    )
    _parse_utc(row["timestamp_utc"], "timestamp_utc")
    for field in ("hostname", "host_platform", "python_version"):
        if not isinstance(row[field], str) or not row[field]:
            raise EvidenceValidationError(f"{field} must be non-empty")
    if _require_int(row, "cpu_count") < 1:
        raise EvidenceValidationError("cpu_count must be positive")

    reuse_stride = 1 if scenario.order == "grouped" else scenario.key_count
    with localcontext() as decimal_context:
        decimal_context.prec = NUMERIC_DECIMAL_PRECISION
        reuse_horizon = (
            Decimal(multiplicity - 1)
            * Decimal(reuse_stride)
            * _to_decimal(scenario.event_interval_seconds)
        )
    ttl = _to_decimal(
        config["cache"]["fixed_ttl_seconds"]
        if method.cache_policy == "fixed_ttl"
        else config["cache"]["retention_ttl_seconds"]
    )
    capacity_condition = bool(
        method.cache_policy is not None
        and scenario.cache_capacity >= scenario.key_count
        and scenario.max_entries_per_account is None
        and ttl > reuse_horizon
    )
    replay_eligible = bool(
        config["profile"] == "formal"
        and multiplicity >= 100
        and method.singleflight
        and capacity_condition
        and memory_expected[6]
        and method.cache_policy != "future_oracle"
    )
    checks_pass = _ratio_at_most(
        backend_checks, scenario.key_count, G2_CHECKS_PER_TUPLE_MAX
    )
    reduction = (
        _row_ratio(
            "backend_work_reduction_factor_vs_static", event_count, backend_checks
        )
        if backend_checks
        else None
    )
    improvement_pass = backend_checks == 0 or (
        reduction is not None
        and _ratio_at_least(
            event_count, backend_checks, G2_STATIC_WORK_IMPROVEMENT_MIN
        )
    )
    _require_exact(row["g2_capacity_condition_met"], capacity_condition, "G2 capacity")
    _require_exact(row["g2_replay_component_eligible"], replay_eligible, "G2 replay eligibility")
    _require_exact(
        row["g2_replay_component_criteria_pass"],
        checks_pass and improvement_pass if replay_eligible else None,
        "G2 replay criteria",
    )
    _require_exact(row["g2_checks_per_tuple_le_1_1"], checks_pass, "G2 checks criterion")
    _require_exact(
        row["g2_static_work_improvement_ge_10x"], improvement_pass, "G2 improvement"
    )
    _require_exact(row["g2_gate_eligible_row"], False, "G2 row eligibility")
    _require_exact(row["g2_row_criteria_pass"], None, "G2 row result")
    _require_exact(row["g2_legitimate_p99_regression_le_5pct"], None, "G2 p99 result")
    _require_exact(row["g2_gate_status"], G2_BLOCKED_STATUS, "G2 status")
    for field in (
        "legitimate_p99_ms",
        "legitimate_timeout_rate",
        "service_saturation_rps",
        "legitimate_static_p99_ms",
        "legitimate_p99_regression_fraction_vs_static",
    ):
        _require_exact(row[field], None, field)
    _require_exact(row["legitimate_p99_required_source"], "E7 service benchmark", "p99 source")
    _require_exact(
        row["legitimate_latency_method"],
        "not measured by E4 replay runner",
        "legitimate latency method",
    )
    _require_exact(
        row["comparison_reference_method"], STATIC_METHOD, "comparison reference method"
    )
    _require_exact(
        row["static_reference_role"],
        "controlled same-filter static reference; strongest Phase1 baseline selection "
        "remains external",
        "static reference role",
    )
    return point_key


def _canonical_aggregate_float(name: str, value: Decimal) -> float:
    try:
        quantum = AGGREGATE_FLOAT_QUANTA[name]
    except KeyError as error:
        raise KeyError(f"undeclared E4 aggregate statistic: {name}") from error
    with localcontext() as context:
        context.prec = NUMERIC_DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        canonical = value.quantize(quantum)
    result = float(canonical)
    if not math.isfinite(result):
        raise EvidenceValidationError(f"aggregate statistic {name} is not finite")
    return 0.0 if result == 0.0 else result


def _mean_ci95(values: Sequence[Decimal], statistic: str) -> dict[str, Any]:
    if not values:
        return {"n": 0, "mean": None, "ci95_low": None, "ci95_high": None}
    with localcontext() as context:
        context.prec = NUMERIC_DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        mean = sum(values, Decimal(0)) / Decimal(len(values))
    if len(values) == 1:
        return {
            "n": 1,
            "mean": _canonical_aggregate_float(statistic, mean),
            "ci95_low": None,
            "ci95_high": None,
        }
    with localcontext() as context:
        context.prec = NUMERIC_DECIMAL_PRECISION
        context.rounding = ROUND_HALF_EVEN
        squared_deviations = sum(
            ((value - mean) ** 2 for value in values), Decimal(0)
        )
        sample_variance = squared_deviations / Decimal(len(values) - 1)
        standard_error = (sample_variance / Decimal(len(values))).sqrt()
        critical = Decimal(_T_CRITICAL_95.get(len(values) - 1, "1.95996398454"))
        half_width = critical * standard_error
        ci95_low = mean - half_width
        ci95_high = mean + half_width
    return {
        "n": len(values),
        "mean": _canonical_aggregate_float(statistic, mean),
        "ci95_low": _canonical_aggregate_float(statistic, ci95_low),
        "ci95_high": _canonical_aggregate_float(statistic, ci95_high),
        "method": "paired-seed Student-t interval",
    }


def _paired_summaries(
    rows_by_key: Mapping[tuple[int, str, str, int, str], Mapping[str, Any]]
) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, int, str], list[Mapping[str, Any]]] = defaultdict(list)
    for (_, method, scenario, multiplicity, mode), row in rows_by_key.items():
        groups[(method, scenario, multiplicity, mode)].append(row)
    summaries: list[dict[str, Any]] = []
    for (method, scenario, multiplicity, mode), rows in sorted(groups.items()):
        ordered = sorted(rows, key=lambda row: row["seed"])
        checks_per_tuple: list[Decimal] = []
        static_fractions: list[Decimal] = []
        static_differences: list[Decimal] = []
        reduction_factors: list[Decimal] = []
        zero_backend_seeds = 0
        for row in ordered:
            static_key = (row["seed"], STATIC_METHOD, scenario, multiplicity, mode)
            static = rows_by_key[static_key]
            candidate_checks = int(row["backend_invalid_checks"])
            static_checks = int(static["backend_invalid_checks"])
            checks_per_tuple.append(
                _decimal_ratio(candidate_checks, int(row["distinct_invalid_count"]))
            )
            static_fractions.append(_decimal_ratio(candidate_checks, static_checks))
            static_differences.append(Decimal(static_checks - candidate_checks))
            if candidate_checks:
                reduction_factors.append(_decimal_ratio(static_checks, candidate_checks))
            else:
                zero_backend_seeds += 1
        summaries.append(
            {
                "method": method,
                "scenario": scenario,
                "multiplicity": multiplicity,
                "mode": mode,
                "seed_count": len(ordered),
                "seed_set": [int(row["seed"]) for row in ordered],
                "backend_checks_per_tuple": _mean_ci95(
                    checks_per_tuple, "backend_checks_per_tuple"
                ),
                "paired_backend_work_fraction_of_static": _mean_ci95(
                    static_fractions, "paired_backend_work_fraction_of_static"
                ),
                "paired_backend_checks_saved_vs_static": _mean_ci95(
                    static_differences, "paired_backend_checks_saved_vs_static"
                ),
                "paired_static_reduction_factor_finite": _mean_ci95(
                    reduction_factors, "paired_static_reduction_factor_finite"
                ),
                "zero_backend_seed_count": zero_backend_seeds,
                "g2_replay_component_eligible_seed_count": sum(
                    bool(row["g2_replay_component_eligible"]) for row in ordered
                ),
                "g2_replay_component_all_eligible_rows_pass": (
                    all(
                        row["g2_replay_component_criteria_pass"] is True
                        for row in ordered
                        if row["g2_replay_component_eligible"]
                    )
                    if any(row["g2_replay_component_eligible"] for row in ordered)
                    else None
                ),
            }
        )
    return summaries


def _require_trusted_expected_commit(expected_commit: str | None) -> str:
    if not isinstance(expected_commit, str) or _COMMIT_RE.fullmatch(expected_commit) is None:
        raise EvidenceValidationError(
            "formal E4 aggregation requires an explicit trusted 40-character expected commit"
        )
    return expected_commit


def _validate_formal_repository(
    config: Mapping[str, Any], expected_commit: str
) -> Mapping[str, Any]:
    git = _git_metadata()
    try:
        _enforce_git_policy(config, git, expected_commit)
    except RuntimeError as error:
        raise EvidenceValidationError(str(error)) from error
    _require_exact(git.get("git_status_scope"), SOURCE_STATUS_SCOPE, "live Git status scope")
    _require_exact(
        git.get("checkout_absolute"),
        str(ROOT.resolve()),
        "live Git checkout path",
    )
    return git


def _is_strict_absolute_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or value.strip() != value or "\x00" in value:
        return False
    windows = PureWindowsPath(value)
    posix = PurePosixPath(value)
    if not (windows.is_absolute() or posix.is_absolute()):
        return False
    return ".." not in windows.parts and ".." not in posix.parts


def _group_rows_by_logical_shard(
    rows: Sequence[Mapping[str, Any]],
) -> list[list[Mapping[str, Any]]]:
    grouped: dict[tuple[int, int], list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        key = (_require_int(row, "shard_index"), _require_int(row, "shard_count"))
        grouped[key].append(row)
    return [grouped[key] for key in sorted(grouped)]


def _validate_source_attestations(
    *,
    attestations: Sequence[Mapping[str, Any]],
    input_shards: Sequence[Sequence[Mapping[str, Any]]],
    rows: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
    config_hash: str,
    expected_commit: str,
) -> None:
    if not attestations:
        raise EvidenceValidationError("formal E4 aggregation requires source attestations")
    if not input_shards:
        raise EvidenceValidationError("formal E4 aggregation discovered no input shards")
    all_run_ids = {row["run_id"] for row in rows}
    discovered_run_ids: list[str] = []
    shards_by_key: dict[tuple[int, int], Sequence[Mapping[str, Any]]] = {}
    for input_shard in input_shards:
        if not input_shard:
            raise EvidenceValidationError("discovered E4 input shard is empty")
        keys = {
            (_require_int(row, "shard_index"), _require_int(row, "shard_count"))
            for row in input_shard
        }
        if len(keys) != 1:
            raise EvidenceValidationError("one discovered input file spans multiple logical shards")
        key = next(iter(keys))
        if key in shards_by_key:
            raise EvidenceValidationError(
                f"logical input shard {key!r} was discovered more than once"
            )
        shards_by_key[key] = input_shard
        discovered_run_ids.extend(str(row["run_id"]) for row in input_shard)
    if len(discovered_run_ids) != len(set(discovered_run_ids)):
        raise EvidenceValidationError("discovered input shards repeat E4 rows")
    if set(discovered_run_ids) != all_run_ids:
        raise EvidenceValidationError(
            "discovered input shards do not cover the validated rows exactly"
        )

    shard_counts = {key[1] for key in shards_by_key}
    if len(shard_counts) != 1:
        raise EvidenceValidationError("source-attested shards must share one shard_count")
    shard_count = next(iter(shard_counts))
    expected_keys = {(index, shard_count) for index in range(shard_count)}
    if set(shards_by_key) != expected_keys:
        raise EvidenceValidationError(
            "discovered inputs do not cover every logical shard exactly once"
        )

    attestations_by_key: dict[tuple[int, int], Mapping[str, Any]] = {}
    for attestation in attestations:
        if not isinstance(attestation, Mapping):
            raise EvidenceValidationError("source attestation must be a mapping")
        if set(attestation) != SOURCE_ATTESTATION_FIELDS:
            missing = sorted(SOURCE_ATTESTATION_FIELDS - set(attestation))
            extra = sorted(set(attestation) - SOURCE_ATTESTATION_FIELDS)
            raise EvidenceValidationError(
                f"source attestation fields differ: missing={missing}, extra={extra}"
            )
        shard_index = _require_int(attestation, "shard_index")
        attested_shard_count = _require_int(attestation, "shard_count")
        if attested_shard_count < 1 or shard_index >= attested_shard_count:
            raise EvidenceValidationError("source attestation has invalid shard index/count")
        key = (shard_index, attested_shard_count)
        if key in attestations_by_key:
            raise EvidenceValidationError(f"duplicate source attestation for shard {key!r}")
        attestations_by_key[key] = attestation
    if set(attestations_by_key) != set(shards_by_key):
        raise EvidenceValidationError(
            "source attestations must cover every discovered input shard exactly once"
        )

    for key, input_shard in shards_by_key.items():
        attestation = attestations_by_key[key]
        _require_exact(attestation["schema"], SOURCE_ATTESTATION_SCHEMA, "attestation schema")
        _require_exact(
            attestation["config_contract_id"],
            config["contract_id"],
            "attestation config contract",
        )
        _require_exact(attestation["config_hash"], config_hash, "attestation config hash")
        _require_exact(attestation["row_schema"], ROW_SCHEMA, "attestation row schema")
        _require_exact(
            attestation["trusted_expected_commit"],
            expected_commit,
            "attestation trusted expected commit",
        )
        _require_exact(
            attestation["source_commit_before"],
            expected_commit,
            "attestation source commit before",
        )
        _require_exact(
            attestation["source_commit_after"],
            expected_commit,
            "attestation source commit after",
        )
        _require_exact(
            attestation["source_status_scope"],
            SOURCE_STATUS_SCOPE,
            "attestation source status scope",
        )
        _require_exact(attestation["source_status_before"], "", "source status before")
        _require_exact(attestation["source_status_after"], "", "source status after")
        hostname = attestation["source_hostname"]
        if not isinstance(hostname, str) or not hostname or hostname.strip() != hostname:
            raise EvidenceValidationError("attestation source_hostname must be non-empty")
        if not _is_strict_absolute_path(attestation["source_checkout_absolute"]):
            raise EvidenceValidationError("attestation checkout must be a strict absolute path")
        if any(row["hostname"] != hostname for row in input_shard):
            raise EvidenceValidationError("attested hostname differs from shard rows")
        if any(row["commit"] != expected_commit for row in input_shard):
            raise EvidenceValidationError("attested source commit differs from shard rows")
        if any(
            row["shard_index"] != key[0] or row["shard_count"] != key[1]
            for row in input_shard
        ):
            raise EvidenceValidationError("attested shard coordinates differ from shard rows")
        _require_exact(
            _require_int(attestation, "row_count"),
            len(input_shard),
            "attestation row count",
        )
        row_times = [
            _parse_utc(row["timestamp_utc"], "row timestamp_utc") for row in input_shard
        ]
        if row_times != sorted(row_times):
            raise EvidenceValidationError("row timestamps within a shard must be nondecreasing")
        _require_exact(
            attestation["first_row_timestamp_utc"],
            input_shard[0]["timestamp_utc"],
            "attestation first row timestamp",
        )
        _require_exact(
            attestation["last_row_timestamp_utc"],
            input_shard[-1]["timestamp_utc"],
            "attestation last row timestamp",
        )
        started = _parse_utc(attestation["run_started_utc"], "run_started_utc")
        ended = _parse_utc(attestation["run_ended_utc"], "run_ended_utc")
        verified = _parse_utc(attestation["verified_utc"], "verified_utc")
        if not started <= row_times[0] <= row_times[-1] <= ended <= verified:
            raise EvidenceValidationError("source attestation timestamps are inverted or stale")


def aggregate_rows(
    rows: Sequence[Mapping[str, Any]],
    config_path: Path,
    *,
    expected_commit: str | None = None,
    source_attestations: Sequence[Mapping[str, Any]] | None = None,
    input_shards: Sequence[Sequence[Mapping[str, Any]]] | None = None,
) -> dict[str, Any]:
    config, config_hash = load_config(config_path)
    is_formal = config["profile"] == "formal"
    trusted_commit: str | None = None
    if is_formal:
        trusted_commit = _require_trusted_expected_commit(expected_commit)
        if not source_attestations:
            raise EvidenceValidationError(
                "formal E4 aggregation requires explicit source attestations"
            )
        _validate_formal_repository(config, trusted_commit)
    dataset = SyntheticCredentialSet(
        int(config["dataset"]["account_count"]), int(config["dataset"]["seed"])
    )
    members = [dataset.member(index) for index in range(dataset.account_count)]
    dataset_hash = dataset.manifest_hash(
        members, int(config["dataset"]["false_positive_search_limit"])
    )
    expected = set(expected_points(config))
    scenarios = _scenario_map(config)
    reference = _ReferenceReplay(config, dataset, members, scenarios)
    rows_by_key: dict[tuple[int, str, str, int, str], Mapping[str, Any]] = {}
    run_ids: set[str] = set()
    shard_counts: set[int] = set()
    commits: set[Any] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise EvidenceValidationError("every JSONL record must be a mapping")
        key = _validate_row(
            row,
            config=config,
            config_hash=config_hash,
            dataset_hash=dataset_hash,
            scenarios=scenarios,
            expected_points_set=expected,
            reference=reference,
        )
        if key in rows_by_key:
            raise EvidenceValidationError(f"duplicate E4 point {key!r}")
        if row["run_id"] in run_ids:
            raise EvidenceValidationError(f"duplicate run_id {row['run_id']!r}")
        rows_by_key[key] = row
        run_ids.add(row["run_id"])
        shard_count = _require_int(row, "shard_count")
        shard_index = _require_int(row, "shard_index")
        if shard_count < 1 or shard_index >= shard_count:
            raise EvidenceValidationError("invalid shard index/count in row")
        expected_shard = int(row["seed_shard_ordinal"]) % shard_count
        _require_exact(shard_index, expected_shard, "seed-to-shard assignment")
        shard_counts.add(shard_count)
        commits.add(row["commit"])
    if set(rows_by_key) != expected:
        missing = sorted(expected - set(rows_by_key))
        extra = sorted(set(rows_by_key) - expected)
        raise EvidenceValidationError(
            f"E4 grid differs: missing={missing[:5]} ({len(missing)} total), "
            f"extra={extra[:5]} ({len(extra)} total)"
        )
    if len(shard_counts) != 1:
        raise EvidenceValidationError("all E4 rows must use one shard_count")
    if is_formal:
        if len(rows) != EXPECTED_FORMAL_ROWS or config["contract_id"] != FORMAL_CONTRACT_ID:
            raise EvidenceValidationError("formal E4 evidence must contain exactly 930 frozen rows")
        assert trusted_commit is not None
        commit = trusted_commit
        if commits != {trusted_commit}:
            raise EvidenceValidationError(
                "formal E4 row commits differ from the trusted expected commit"
            )
        if any(row["git_dirty"] is not False for row in rows):
            raise EvidenceValidationError(
                "formal E4 rows must consistently record the attested clean worktree"
            )
        bound_input_shards = (
            input_shards if input_shards is not None else _group_rows_by_logical_shard(rows)
        )
        assert source_attestations is not None
        _validate_source_attestations(
            attestations=source_attestations,
            input_shards=bound_input_shards,
            rows=rows,
            config=config,
            config_hash=config_hash,
            expected_commit=trusted_commit,
        )
    else:
        commit = next(iter(commits)) if len(commits) == 1 else None

    for key, row in rows_by_key.items():
        seed, _, scenario, multiplicity, mode = key
        static = rows_by_key[(seed, STATIC_METHOD, scenario, multiplicity, mode)]
        static_checks = int(static["backend_invalid_checks"])
        candidate_checks = int(row["backend_invalid_checks"])
        _require_exact(static_checks, int(static["event_count"]), "static backend checks")
        _require_exact(static["screen_positive_forwards"], static_checks, "static forwards")
        _require_exact(row["static_backend_checks_reference"], static_checks, "static reference")
        _require_exact(
            row["backend_work_fraction_of_static"],
            _row_ratio(
                "backend_work_fraction_of_static", candidate_checks, static_checks
            ),
            "backend fraction of static",
        )
        expected_reduction = (
            _row_ratio(
                "backend_work_reduction_factor_vs_static",
                static_checks,
                candidate_checks,
            )
            if candidate_checks
            else None
        )
        _require_exact(
            row["backend_work_reduction_factor_vs_static"],
            expected_reduction,
            "backend reduction factor",
        )

    summaries = _paired_summaries(rows_by_key)
    generated_rates = [
        float(row["trace_summary"]["generated_request_rate_per_second"]) for row in rows
    ]
    if is_formal:
        assert trusted_commit is not None
        _validate_formal_repository(config, trusted_commit)
    return {
        "schema": AGGREGATE_SCHEMA,
        "integrity_status": "PASS",
        "evidence_status": (
            "FORMAL_REPLAY_VALID" if config["profile"] == "formal" else "SMOKE_DIAGNOSTIC_ONLY"
        ),
        "config_contract_id": config["contract_id"],
        "numeric_contract_id": NUMERIC_CONTRACT_ID,
        "config_hash": config_hash,
        "dataset_hash": dataset_hash,
        "row_count": len(rows),
        "expected_row_count": len(expected),
        "seed_count": len(config["seeds"]),
        "points_per_seed": len(expected) // len(config["seeds"]),
        "commit": commit,
        "source_attestation_status": (
            "TRUSTED_MANIFESTS_BOUND" if is_formal else "NOT_REQUIRED_SMOKE"
        ),
        "shard_count": next(iter(shard_counts)),
        "generated_request_rate_per_second_min": _canonical_aggregate_float(
            "generated_request_rate_per_second_min",
            _to_decimal(min(generated_rates)),
        ),
        "generated_request_rate_per_second_max": _canonical_aggregate_float(
            "generated_request_rate_per_second_max",
            _to_decimal(max(generated_rates)),
        ),
        "paired_seed_summaries": summaries,
        "timing_evidence_status": "NOT_MEASURED_E7_REQUIRED",
        "g2_gate_status": G2_BLOCKED_STATUS,
        "g2_blockers": [
            "strongest matched static reference from Phase1 is not bound to this aggregate",
            "legitimate-request p99 from E7 is not bound to this aggregate",
        ],
        "external_baseline_coverage": {
            "TAF": "NOT_INCLUDED_REQUIRES_SEPARATE_HARNESS",
            "AQF": "NOT_INCLUDED_REQUIRES_SEPARATE_HARNESS",
        },
    }


def _discover_files(paths: Iterable[Path], pattern: str, context: str) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            files.extend(sorted(path.rglob(pattern)))
        elif path.is_file():
            files.append(path)
        else:
            raise EvidenceValidationError(f"{context} does not exist: {path}")
    resolved = [path.resolve() for path in files]
    if not resolved:
        raise EvidenceValidationError(f"no {context} files found")
    if len(resolved) != len(set(resolved)):
        raise EvidenceValidationError(f"duplicate {context} path")
    return resolved


def load_row_shards(paths: Iterable[Path]) -> list[list[Mapping[str, Any]]]:
    shards: list[list[Mapping[str, Any]]] = []
    for path in _discover_files(paths, "*.jsonl", "JSONL input"):
        rows: list[Mapping[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    raise EvidenceValidationError(f"{path}:{line_number}: blank JSONL line")
                value = _strict_json(line, f"{path}:{line_number}")
                if not isinstance(value, dict):
                    raise EvidenceValidationError(f"{path}:{line_number}: row must be a mapping")
                rows.append(value)
        if not rows:
            raise EvidenceValidationError(f"{path}: discovered JSONL shard is empty")
        shards.append(rows)
    return shards


def load_rows(paths: Iterable[Path]) -> list[Mapping[str, Any]]:
    return [row for shard in load_row_shards(paths) for row in shard]


def load_source_attestations(paths: Iterable[Path]) -> list[Mapping[str, Any]]:
    attestations: list[Mapping[str, Any]] = []
    for path in _discover_files(paths, "*.json", "source attestation"):
        text = path.read_text(encoding="utf-8")
        if not text.strip():
            raise EvidenceValidationError(f"{path}: blank source attestation")
        value = _strict_json(text, str(path))
        if not isinstance(value, dict):
            raise EvidenceValidationError(f"{path}: source attestation must be a mapping")
        attestations.append(value)
    return attestations


def aggregate_paths(
    paths: Iterable[Path],
    config_path: Path,
    *,
    expected_commit: str | None = None,
    source_attestation_paths: Iterable[Path] | None = None,
) -> dict[str, Any]:
    input_shards = load_row_shards(paths)
    rows = [row for shard in input_shards for row in shard]
    attestations = (
        load_source_attestations(source_attestation_paths)
        if source_attestation_paths is not None
        else None
    )
    return aggregate_rows(
        rows,
        config_path,
        expected_commit=expected_commit,
        source_attestations=attestations,
        input_shards=input_shards,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--input", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--expected-commit")
    parser.add_argument("--source-attestation", type=Path, action="append")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config, _ = load_config(args.config)
    if config["profile"] == "formal":
        _require_trusted_expected_commit(args.expected_commit)
        if not args.source_attestation:
            raise EvidenceValidationError(
                "formal E4 CLI requires at least one --source-attestation"
            )
    summary = aggregate_paths(
        args.input,
        args.config,
        expected_commit=args.expected_commit,
        source_attestation_paths=args.source_attestation,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w" if args.overwrite else "x", encoding="utf-8") as handle:
        handle.write(json.dumps(summary, sort_keys=True, indent=2, allow_nan=False) + "\n")
    print(
        f"validated {summary['row_count']} E4 rows; "
        f"G2={summary['g2_gate_status']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
