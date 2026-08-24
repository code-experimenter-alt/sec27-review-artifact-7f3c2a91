from __future__ import annotations

import copy
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
import yaml

from experiments.runners import service_fault_evidence as service_fault

CONFIG_PATH = Path("experiments/configs/service_fault.g7.yaml")
COMMIT = "a" * 40


def _clean_state(commit: str = COMMIT) -> dict[str, object]:
    return {
        "commit": commit,
        "clean": True,
        "status": {
            "format": service_fault.GIT_STATUS_FORMAT,
            "payload_hex": "",
        },
    }


def test_child_runtime_launch_preserves_active_environment_and_process_identity() -> None:
    executable, environment = service_fault._python_child_launch()
    expected = Path(service_fault.sys.executable)
    base_executable = getattr(service_fault.sys, "_base_executable", None)
    if service_fault.os.name == "nt" and type(base_executable) is str and base_executable:
        expected = Path(base_executable)
    assert executable == expected
    if executable != Path(service_fault.sys.executable):
        assert environment is not None
        assert environment is not service_fault.os.environ
        assert environment["__PYVENV_LAUNCHER__"] == service_fault.sys.executable
    else:
        assert environment is None


def _rehash(artifact: dict[str, object]) -> None:
    body = {key: value for key, value in artifact.items() if key != "artifact_id"}
    artifact["artifact_id"] = service_fault._identity(body)


def _refresh_rows_and_artifact(artifact: dict[str, object], *row_indexes: int) -> None:
    rows = artifact["rows"]
    for row_index in row_indexes:
        row = rows[row_index]
        row["summary"] = service_fault._derive_row_summary(
            row["logins"], row["transport_events"], row["process_events"], row["checks"]
        )
        row_body = {key: value for key, value in row.items() if key != "row_id"}
        row["row_id"] = service_fault._identity(row_body)
    artifact["summary"] = service_fault._derive_artifact_summary(rows)
    _rehash(artifact)


def _rebind_rpc_callee(rpc: dict[str, object], process: dict[str, object]) -> None:
    rpc["callee_pid"] = process["pid"]
    rpc["callee_session_id"] = process["session_id"]
    rpc["callee_endpoint"] = process["endpoint"]
    rpc["server_port"] = int(str(process["endpoint"]).rsplit(":", 1)[1])
    rpc["connection_id"] = service_fault._connection_id(rpc)


@pytest.fixture(scope="module")
def formal_evidence(tmp_path_factory: pytest.TempPathFactory):
    config, config_id = service_fault.load_config(CONFIG_PATH)
    directory = tmp_path_factory.mktemp("service-fault-formal")
    rows = service_fault._execute_matrix(config, directory / "matrix")
    artifact = service_fault.build_artifact(
        config,
        config_id,
        COMMIT,
        _clean_state(),
        _clean_state(),
        rows,
    )
    return config, config_id, rows, artifact


def test_formal_matrix_uses_real_tcp_processes_and_core_components(formal_evidence) -> None:
    config, config_id, rows, artifact = formal_evidence
    assert tuple(row["coordinate"] for row in rows) == service_fault.COORDINATES
    assert len(rows) == len(config["coordinates"]) == 13
    assert all(row["status"] == "PASS" for row in rows)

    summary = artifact["summary"]
    assert summary["valid_attempts"] == 22
    assert summary["structural_false_rejects"] == 0
    assert summary["unavailable_authentications"] == 6
    assert summary["uncertainty_attempts"] == 9
    assert summary["uncertainty_backend_forwarded"] == 9
    assert summary["process_exit_events"] == 4
    assert summary["process_restart_events"] == 4
    assert summary["recorded_coordinator_edge_login_rpc_count"] == 24
    assert summary["recorded_coordinator_edge_lease_expire_rpc_count"] == 4
    assert summary["recorded_coordinator_proxy_produce_rpc_count"] == 6
    assert summary["recorded_coordinator_proxy_delay_barrier_wait_rpc_count"] == 1
    assert summary["recorded_coordinator_proxy_delay_release_rpc_count"] == 1
    assert summary["recorded_proxy_edge_delivery_rpc_count"] == 7
    assert summary["recorded_edge_backend_rpc_count"] == 39
    assert summary["recorded_producer_message_count"] == 7

    core = rows[0]
    final_metrics = core["logins"][-1]["component_metrics"]
    assert final_metrics["negative_cache"]["inserts"] >= 1
    assert final_metrics["negative_cache"]["hits"] >= 1
    assert final_metrics["singleflight"]["leaders"] >= 2
    assert [event["role"] for event in core["process_events"]] == [
        "coordinator",
        "backend",
        "edge",
        "transport-proxy",
    ]
    assert len({event["session_id"] for event in core["process_events"]}) == 4
    assert all(
        login["rpc"]["protocol"] == "TCP"
        and login["rpc"]["server_host"] == "127.0.0.1"
        and login["rpc"]["client_host"] == "127.0.0.1"
        and login["rpc"]["client_port"] > 0
        for row in rows
        for login in row["logins"]
    )
    service_fault.validate_artifact(artifact, config, config_id, COMMIT)


def test_transport_matrix_covers_delay_loss_duplicate_and_reorder(formal_evidence) -> None:
    _, _, rows, _ = formal_evidence
    indexed = {row["coordinate"]: row for row in rows}
    delay = indexed["transport_delay"]
    assert delay["transport_events"][0]["delay_ms"] == 120
    assert delay["transport_events"][0]["edge_outcomes"] == ["APPLIED"]
    assert len(delay["transport_events"][0]["deliveries"]) == 1
    assert delay["transport_events"][0]["producer_rpc"]["elapsed_class"] == (
        "CONFIGURED_PROXY_DELAY_WINDOW"
    )
    assert delay["logins"][0]["directory_status"] == "UNCERTAIN"
    assert delay["logins"][0]["route"] == "FAIL_OPEN_BACKEND"
    barrier = delay["transport_events"][0]["delay_barrier"]
    assert barrier["causal_order"] == [
        "DELAY_ENTERED",
        "LOGIN_COMPLETED",
        "DELAY_RELEASED",
        "EDGE_DELIVERY",
    ]
    assert barrier["entered_observation"]["status"] == "DELAY_ENTERED"
    assert barrier["entered_observation"]["event_ordinal"] == 0
    assert barrier["entered_observation"]["release_received"] is False
    assert barrier["login_completion"]["event_ordinal"] == 1
    assert barrier["login_completion"]["login_completion_id"] == (
        service_fault._login_completion_id(delay["logins"][0])
    )
    assert barrier["release"]["event_ordinal"] == 2
    assert barrier["release"]["status"] == "DELAY_RELEASED"
    assert barrier["delivery_gate"] == {
        "event_ordinal": 3,
        "status": "DELIVERY_PERMITTED",
        "barrier_id": barrier["barrier_id"],
        "message_id": "message-delay-1",
        "sequence": 1,
        "login_completion_id": barrier["login_completion"]["login_completion_id"],
        "minimum_delay_satisfied": True,
        "release_received": True,
        "delivery_started_after_release": True,
    }
    assert barrier["barrier_id"] == service_fault._delay_barrier_id(
        delay["transport_events"][0]["proxy_session_id"],
        "message-delay-1",
        1,
    )
    causal_connection_ids = {
        delay["transport_events"][0]["producer_rpc"]["connection_id"],
        barrier["entered_observation"]["rpc"]["connection_id"],
        barrier["login_completion"]["login_rpc_connection_id"],
        barrier["release"]["rpc"]["connection_id"],
        delay["transport_events"][0]["deliveries"][0]["rpc"]["connection_id"],
    }
    assert len(causal_connection_ids) == 5

    loss = indexed["transport_loss"]
    assert loss["transport_events"][0]["edge_outcomes"] == []
    assert loss["transport_events"][0]["deliveries"] == []
    assert loss["transport_events"][0]["proxy_drop_count"] == 1
    assert loss["transport_events"][1]["edge_outcomes"] == ["APPLIED"]
    assert loss["logins"][0]["backend_forwarded"] is True
    assert loss["logins"][0]["pre_screen_rejected"] is False

    duplicate = indexed["transport_duplicate"]["transport_events"][0]
    assert duplicate["producer_message_ids"] == ["message-duplicate-3"]
    assert duplicate["edge_outcomes"] == ["APPLIED", "DUPLICATE"]
    assert len(duplicate["deliveries"]) == 2
    assert len({item["rpc"]["connection_id"] for item in duplicate["deliveries"]}) == 2
    reorder = indexed["transport_reorder"]["transport_events"][0]
    assert reorder["producer_sequences"] == [4, 5]
    assert reorder["delivery_sequences"] == [5, 4]
    assert reorder["edge_outcomes"] == ["APPLIED", "STALE"]
    assert len({item["rpc"]["connection_id"] for item in reorder["deliveries"]}) == 2


def test_proxy_runtime_delay_gate_rejects_early_release_and_blocks_until_release() -> None:
    config, _ = service_fault.load_config(CONFIG_PATH)
    pid = service_fault.os.getpid()
    nonce = "1" * 64
    session_id = service_fault._session_id("transport-proxy", pid, nonce)
    application = service_fault._TransportProxyApplication(
        config,
        (service_fault.HOST, 40001),
        40002,
        "2" * 64,
    )
    application.bind_process(nonce, session_id, (service_fault.HOST, 40003))
    message = service_fault._message("runtime-delay-message", 91)
    barrier_id = service_fault._delay_barrier_id(
        session_id,
        str(message["message_id"]),
        int(message["sequence"]),
    )
    login_completion_id = "3" * 64
    release_request = {
        "op": "delay_release",
        "barrier_id": barrier_id,
        "message_id": message["message_id"],
        "sequence": message["sequence"],
        "login_completion_id": login_completion_id,
    }
    with pytest.raises(ValueError, match="entered barrier"):
        application.dispatch(release_request)

    deliveries: list[tuple[str, int]] = []

    def fake_deliver(item, delivery_index):
        deliveries.append((str(item["message_id"]), delivery_index))
        return {
            "delivery_index": delivery_index,
            "message_id": item["message_id"],
            "sequence": item["sequence"],
            "edge_outcome": "APPLIED",
        }

    result: dict[str, object] = {}

    def produce() -> None:
        result["response"] = application.dispatch(
            {
                "op": "produce",
                "action": "delay",
                "messages": [message],
                "delay_ms": config["transport"]["logical_delay_ms"],
                "barrier_id": barrier_id,
            }
        )

    with mock.patch.object(application, "_deliver", side_effect=fake_deliver):
        thread = threading.Thread(target=produce, daemon=True)
        thread.start()
        entered = application.dispatch(
            {
                "op": "delay_barrier_wait",
                "barrier_id": barrier_id,
                "message_id": message["message_id"],
                "sequence": message["sequence"],
            }
        )
        assert entered["status"] == "DELAY_ENTERED"
        time.sleep((int(config["transport"]["logical_delay_ms"]) + 40) / 1000.0)
        assert thread.is_alive()
        assert deliveries == []

        released = application.dispatch(release_request)
        assert released["status"] == "DELAY_RELEASED"
        thread.join(timeout=1.0)
        assert not thread.is_alive()

    assert deliveries == [("runtime-delay-message", 0)]
    response = result["response"]
    assert response["delay_barrier"]["minimum_delay_satisfied"] is True
    assert response["delay_barrier"]["release_received"] is True


def test_edge_and_backend_process_lifecycle_evidence_is_explicit(formal_evidence) -> None:
    _, _, rows, _ = formal_evidence
    indexed = {row["coordinate"]: row for row in rows}

    persistence = indexed["edge_kill_restart_persistence"]
    before, after = persistence["process_events"]
    assert before["action"] == "EXIT"
    assert after["action"] == "RESTART"
    assert before["pid"] != after["pid"]
    assert before["state_id"] == after["state_id"]
    assert persistence["logins"][0]["accepted"] is True

    corruption = indexed["edge_corrupt_state_fail_open"]
    assert corruption["process_events"][1]["action"] == "CORRUPT_STATE"
    assert corruption["process_events"][2]["state_trusted"] is False
    assert corruption["logins"][0]["directory_status"] == "UNCERTAIN"
    assert corruption["logins"][0]["backend_forwarded"] is True
    assert corruption["logins"][0]["pre_screen_rejected"] is False
    assert corruption["process_events"][-1]["state_trusted"] is True

    crash = indexed["backend_crash_restart"]
    assert crash["process_events"][0]["exit_code"] == 73
    assert crash["process_events"][0]["pid"] != crash["process_events"][1]["pid"]
    assert crash["logins"][0]["unavailable_authentication"] is True
    assert crash["logins"][0]["pre_screen_rejected"] is False
    assert crash["logins"][1]["accepted"] is True


def test_rpc_sessions_endpoints_and_timeout_classes_are_cross_bound(formal_evidence) -> None:
    _, _, rows, _ = formal_evidence
    indexed = {row["coordinate"]: row for row in rows}
    timeout = indexed["backend_timeout"]["logins"][0]["backend_interactions"][0]
    assert timeout["backend_identity_source"] == ("READY_REGISTRY_EXPECTED_NO_VALID_RESPONSE")
    assert timeout["transport"]["outcome"] == "TIMEOUT"
    assert timeout["transport"]["elapsed_class"] == "CONFIGURED_BACKEND_TIMEOUT_WINDOW"
    assert timeout["transport"]["elapsed_ns"] >= 60_000_000
    assert timeout["transport"]["callee_pid"] == timeout["backend_pid"]
    assert timeout["transport"]["callee_session_id"] == timeout["backend_session_id"]
    assert timeout["transport"]["callee_endpoint"] == timeout["backend_endpoint"]

    malformed = indexed["backend_malformed"]["logins"][0]["backend_interactions"][0]
    assert malformed["transport"]["outcome"] == "ERROR"
    assert malformed["transport"]["response_present"] is True
    assert malformed["completed_response"] is False


def test_static_validator_rejects_unbound_raw_observation_tampering(
    formal_evidence,
) -> None:
    config, config_id, _, artifact = formal_evidence
    attacks: list[dict[str, object]] = []

    changed_login_pid = copy.deepcopy(artifact)
    changed_login_pid["rows"][0]["logins"][0]["edge_pid"] += 1
    _refresh_rows_and_artifact(changed_login_pid, 0)
    attacks.append(changed_login_pid)

    changed_proxy_pid = copy.deepcopy(artifact)
    changed_proxy_pid["rows"][1]["transport_events"][0]["proxy_pid"] += 1
    _refresh_rows_and_artifact(changed_proxy_pid, 1)
    attacks.append(changed_proxy_pid)

    changed_process_pid = copy.deepcopy(artifact)
    changed_process_pid["rows"][0]["process_events"][2]["pid"] += 1
    _refresh_rows_and_artifact(changed_process_pid, 0)
    attacks.append(changed_process_pid)

    changed_rpc_port = copy.deepcopy(artifact)
    rpc = changed_rpc_port["rows"][0]["logins"][0]["rpc"]
    rpc["server_port"] += 1
    rpc["connection_id"] = service_fault._connection_id(rpc)
    _refresh_rows_and_artifact(changed_rpc_port, 0)
    attacks.append(changed_rpc_port)

    changed_elapsed = copy.deepcopy(artifact)
    changed_elapsed["rows"][0]["logins"][0]["rpc"]["elapsed_ns"] = 0
    _refresh_rows_and_artifact(changed_elapsed, 0)
    attacks.append(changed_elapsed)

    changed_backend_pid = copy.deepcopy(artifact)
    changed_backend_pid["rows"][0]["logins"][0]["backend_interactions"][0]["backend_pid"] += 1
    _refresh_rows_and_artifact(changed_backend_pid, 0)
    attacks.append(changed_backend_pid)

    changed_exit = copy.deepcopy(artifact)
    changed_exit["rows"][5]["process_events"][0]["exit_code"] = 0
    changed_exit["rows"][5]["process_events"][0]["exit_class"] = "CLEAN_EXIT"
    _refresh_rows_and_artifact(changed_exit, 5)
    attacks.append(changed_exit)

    changed_delta = copy.deepcopy(artifact)
    changed_delta["rows"][0]["logins"][0]["negative_cache_delta"]["entries"] += 1
    _refresh_rows_and_artifact(changed_delta, 0)
    attacks.append(changed_delta)

    for attack in attacks:
        with pytest.raises(ValueError):
            service_fault.validate_artifact(attack, config, config_id, COMMIT)


def test_coordinated_relationship_rewrites_are_rejected_after_rehash(
    formal_evidence,
) -> None:
    config, config_id, _, artifact = formal_evidence
    final_edge = artifact["rows"][6]["process_events"][4]
    restarted_backend = artifact["rows"][12]["process_events"][1]
    attacks: list[dict[str, object]] = []

    moved_login = copy.deepcopy(artifact)
    login = moved_login["rows"][0]["logins"][0]
    login["edge_pid"] = final_edge["pid"]
    login["edge_session_id"] = final_edge["session_id"]
    login["edge_endpoint"] = final_edge["endpoint"]
    _rebind_rpc_callee(login["rpc"], final_edge)
    for interaction in login["backend_interactions"]:
        interaction["transport"]["caller_pid"] = final_edge["pid"]
        interaction["transport"]["caller_session_id"] = final_edge["session_id"]
    _refresh_rows_and_artifact(moved_login, 0)
    attacks.append(moved_login)

    moved_delivery = copy.deepcopy(artifact)
    delivery = moved_delivery["rows"][3]["transport_events"][0]["deliveries"][0]
    delivery["edge_pid"] = final_edge["pid"]
    delivery["edge_session_id"] = final_edge["session_id"]
    delivery["edge_endpoint"] = final_edge["endpoint"]
    _rebind_rpc_callee(delivery["rpc"], final_edge)
    _refresh_rows_and_artifact(moved_delivery, 3)
    attacks.append(moved_delivery)

    moved_backend = copy.deepcopy(artifact)
    interaction = moved_backend["rows"][7]["logins"][0]["backend_interactions"][0]
    interaction["backend_pid"] = restarted_backend["pid"]
    interaction["backend_session_id"] = restarted_backend["session_id"]
    interaction["backend_endpoint"] = restarted_backend["endpoint"]
    _rebind_rpc_callee(interaction["transport"], restarted_backend)
    _refresh_rows_and_artifact(moved_backend, 7)
    attacks.append(moved_backend)

    for attack in attacks:
        with pytest.raises(ValueError):
            service_fault.validate_artifact(attack, config, config_id, COMMIT)


def test_delay_barrier_race_and_cross_binding_tampering_is_rejected(formal_evidence) -> None:
    config, config_id, _, artifact = formal_evidence
    attacks: list[dict[str, object]] = []

    reordered = copy.deepcopy(artifact)
    barrier = reordered["rows"][1]["transport_events"][0]["delay_barrier"]
    barrier["causal_order"] = [
        "LOGIN_COMPLETED",
        "DELAY_ENTERED",
        "DELAY_RELEASED",
        "EDGE_DELIVERY",
    ]
    _refresh_rows_and_artifact(reordered, 1)
    attacks.append(reordered)

    early_delivery = copy.deepcopy(artifact)
    gate = early_delivery["rows"][1]["transport_events"][0]["delay_barrier"]["delivery_gate"]
    gate["minimum_delay_satisfied"] = False
    _refresh_rows_and_artifact(early_delivery, 1)
    attacks.append(early_delivery)

    wrong_login = copy.deepcopy(artifact)
    row = wrong_login["rows"][1]
    barrier = row["transport_events"][0]["delay_barrier"]
    replacement = service_fault._login_completion_id(row["logins"][1])
    barrier["login_completion"]["login_completion_id"] = replacement
    barrier["login_completion"]["login_label"] = row["logins"][1]["label"]
    barrier["login_completion"]["edge_session_id"] = row["logins"][1]["edge_session_id"]
    barrier["login_completion"]["login_rpc_connection_id"] = row["logins"][1]["rpc"][
        "connection_id"
    ]
    barrier["release"]["login_completion_id"] = replacement
    barrier["delivery_gate"]["login_completion_id"] = replacement
    _refresh_rows_and_artifact(wrong_login, 1)
    attacks.append(wrong_login)

    reused_connection = copy.deepcopy(artifact)
    event = reused_connection["rows"][1]["transport_events"][0]
    event["delay_barrier"]["entered_observation"]["rpc"] = copy.deepcopy(event["producer_rpc"])
    _refresh_rows_and_artifact(reused_connection, 1)
    attacks.append(reused_connection)

    for attack in attacks:
        with pytest.raises(ValueError):
            service_fault.validate_artifact(attack, config, config_id, COMMIT)


def test_exit_projection_allows_platform_edge_code_but_freezes_backend_crash_73(
    formal_evidence,
) -> None:
    config, config_id, _, artifact = formal_evidence

    rewritten_edge_exit = copy.deepcopy(artifact)
    edge_exit = rewritten_edge_exit["rows"][5]["process_events"][0]
    edge_exit["exit_code"] = 91 if edge_exit["exit_code"] != 91 else 92
    edge_exit["exit_class"] = "FORCED_TERMINATION_NONZERO"
    _refresh_rows_and_artifact(rewritten_edge_exit, 5)
    service_fault.validate_artifact(rewritten_edge_exit, config, config_id, COMMIT)
    assert service_fault._semantic_projection(rewritten_edge_exit["rows"]) == (
        service_fault._semantic_projection(artifact["rows"])
    )

    rewritten_backend_exit = copy.deepcopy(artifact)
    backend_exit = rewritten_backend_exit["rows"][12]["process_events"][0]
    backend_exit["exit_code"] = 74
    backend_exit["exit_class"] = "FORCED_TERMINATION_NONZERO"
    backend_row = rewritten_backend_exit["rows"][12]
    backend_body = {key: value for key, value in backend_row.items() if key != "row_id"}
    backend_row["row_id"] = service_fault._identity(backend_body)
    _rehash(rewritten_backend_exit)
    with pytest.raises(ValueError, match="frozen code"):
        service_fault.validate_artifact(rewritten_backend_exit, config, config_id, COMMIT)


def test_full_metrics_are_claim_bearing_in_fresh_semantic_replay(formal_evidence) -> None:
    config, config_id, rows, artifact = formal_evidence
    changed = copy.deepcopy(artifact)
    login = changed["rows"][0]["logins"][0]
    login["negative_cache_before"]["forged_nongating_counter"] = 7
    login["negative_cache_after"]["forged_nongating_counter"] = 7
    login["negative_cache_delta"]["forged_nongating_counter"] = 0
    login["component_metrics"]["negative_cache"]["forged_nongating_counter"] = 7
    _refresh_rows_and_artifact(changed, 0)
    service_fault.validate_artifact(changed, config, config_id, COMMIT)

    with (
        mock.patch.object(service_fault, "_git_state", return_value=_clean_state()),
        mock.patch.object(service_fault, "_fresh_matrix", return_value=rows),
    ):
        with pytest.raises(ValueError, match="fresh service-fault semantic replay"):
            service_fault.validate_with_reexecution(changed, config, config_id, COMMIT)


def test_normalized_replay_excludes_raw_random_scalars_but_keeps_relationships(
    formal_evidence,
) -> None:
    _, _, rows, artifact = formal_evidence
    projection = service_fault._semantic_projection(rows)
    observed_keys: set[str] = set()

    def visit(value) -> None:
        if isinstance(value, dict):
            observed_keys.update(value)
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(projection)
    assert {
        "pid",
        "session_id",
        "session_nonce_hex",
        "connection_id",
        "connection_nonce_hex",
        "server_port",
        "client_port",
        "elapsed_ns",
        "request_bytes",
        "response_bytes",
        "exit_code",
    }.isdisjoint(observed_keys)
    assert projection[0]["process"][0]["process"] == "coordinator#0"
    assert projection[0]["process"][3]["process"] == "transport-proxy#0"
    assert projection[1]["transport"][0]["producer_rpc"]["callee"] == ("transport-proxy#0")
    normalized_barrier = projection[1]["transport"][0]["delay_barrier"]
    assert normalized_barrier["causal_order"] == [
        "DELAY_ENTERED",
        "LOGIN_COMPLETED",
        "DELAY_RELEASED",
        "EDGE_DELIVERY",
    ]
    assert normalized_barrier["proxy"] == "transport-proxy#0"
    assert normalized_barrier["login_completion"]["login"] == "login#0"
    assert normalized_barrier["delivery_gate"]["minimum_delay_satisfied"] is True
    assert normalized_barrier["independent_rpc_connections"] is True
    assert artifact["random_observations"]["classification"] == (
        "SESSION_LOCAL_RELATIONAL_EVIDENCE_NOT_CROSS_RUN_SCALAR_EQUALITY"
    )


def test_backend_crash_transport_termination_is_portable_and_fail_closed(
    formal_evidence,
) -> None:
    config, config_id, rows, artifact = formal_evidence
    crash_index = service_fault.COORDINATES.index("backend_crash_restart")
    original_projection = service_fault._semantic_projection(rows)
    original_interaction = rows[crash_index]["logins"][0]["backend_interactions"][0]
    original_termination = (
        original_interaction["failure_category"],
        original_interaction["transport"]["outcome"],
    )
    alternate_rows = None
    for failure_category, outcome in service_fault.BACKEND_CRASH_TRANSPORT_TERMINATIONS:
        portable_rows = copy.deepcopy(rows)
        crash_row = portable_rows[crash_index]
        interaction = crash_row["logins"][0]["backend_interactions"][0]
        interaction["failure_category"] = failure_category
        interaction["transport"]["outcome"] = outcome
        row_body = {key: value for key, value in crash_row.items() if key != "row_id"}
        crash_row["row_id"] = service_fault._identity(row_body)

        portable_projection = service_fault._semantic_projection(portable_rows)
        assert portable_projection == original_projection
        normalized = portable_projection[crash_index]["logins"][0]["backend_interactions"][0]
        assert normalized["failure_category"] == (
            service_fault.NORMALIZED_BACKEND_CRASH_TERMINATION
        )
        assert normalized["rpc"]["outcome"] == (service_fault.NORMALIZED_BACKEND_CRASH_TERMINATION)
        if (failure_category, outcome) != original_termination:
            alternate_rows = portable_rows

    assert alternate_rows is not None

    with (
        mock.patch.object(service_fault, "_git_state", return_value=_clean_state()),
        mock.patch.object(service_fault, "_fresh_matrix", return_value=alternate_rows),
    ):
        service_fault.validate_with_reexecution(artifact, config, config_id, COMMIT)

    for failure_category, outcome in (
        ("EOF", "ERROR"),
        ("ConnectionResetError", "EOF"),
        ("OSError", "ERROR"),
    ):
        unsupported = copy.deepcopy(artifact)
        unsupported_interaction = unsupported["rows"][crash_index]["logins"][0][
            "backend_interactions"
        ][0]
        unsupported_interaction["failure_category"] = failure_category
        unsupported_interaction["transport"]["outcome"] = outcome
        unsupported_row = unsupported["rows"][crash_index]
        unsupported_body = {key: value for key, value in unsupported_row.items() if key != "row_id"}
        unsupported_row["row_id"] = service_fault._identity(unsupported_body)
        _rehash(unsupported)
        with pytest.raises(ValueError, match="not bound to the observed application crash"):
            service_fault.validate_artifact(unsupported, config, config_id, COMMIT)

    noncrash_rows = copy.deepcopy(rows)
    drop_index = service_fault.COORDINATES.index("backend_drop")
    drop_interaction = noncrash_rows[drop_index]["logins"][0]["backend_interactions"][0]
    drop_interaction["failure_category"] = "ConnectionResetError"
    drop_interaction["transport"]["outcome"] = "ERROR"
    assert service_fault._semantic_projection(noncrash_rows) != original_projection


@pytest.mark.parametrize(
    ("coordinate", "fault", "kind", "completed"),
    [
        ("backend_timeout", "timeout", "TRANSIENT_FAILURE", False),
        ("backend_drop", "drop", "TRANSIENT_FAILURE", False),
        ("backend_malformed", "malformed", "TRANSIENT_FAILURE", False),
        (
            "backend_typed_transient_failure",
            "typed_transient_failure",
            "TRANSIENT_FAILURE",
            True,
        ),
        (
            "backend_typed_partial_failure",
            "typed_partial_failure",
            "PARTIAL_AUTHENTICATOR_FAILURE",
            True,
        ),
    ],
)
def test_backend_fault_is_typed_and_not_a_structural_false_reject(
    formal_evidence, coordinate: str, fault: str, kind: str, completed: bool
) -> None:
    _, _, rows, _ = formal_evidence
    row = next(row for row in rows if row["coordinate"] == coordinate)
    faulted, recovered = row["logins"]
    verify = faulted["backend_interactions"][0]
    assert verify["operation"] == "verify"
    assert verify["fault"] == fault
    assert verify["completed_response"] is completed
    assert faulted["backend_kind"] == kind
    assert faulted["route"] == "FAIL_OPEN_BACKEND"
    assert faulted["accepted"] is False
    assert faulted["pre_screen_rejected"] is False
    assert faulted["unavailable_authentication"] is True
    assert recovered["accepted"] is True


def test_config_is_frozen_strictly_typed_and_rejects_duplicate_yaml(tmp_path: Path) -> None:
    original, config_id = service_fault.load_config(CONFIG_PATH)
    assert len(config_id) == 64
    assert original["evidence_scope"] == service_fault.EVIDENCE_SCOPE
    assert original["g7_status"] == service_fault.G7_STATUS
    assert original["blockers"] == list(service_fault.BLOCKERS)
    assert original["fault_layer"] == {
        "transport_proxy_process": "REQUIRED_INDEPENDENT_OS_PROCESS",
        "producer_to_proxy_transport": "IPV4_LOOPBACK_TCP",
        "proxy_to_edge_transport": "IPV4_LOOPBACK_TCP_ONE_CONNECTION_PER_DELIVERY",
        "edge_fault_injection_rpc": "FORBIDDEN",
        "loopback_only": True,
        "kernel_netem": False,
        "production_network_claim": False,
        "claim": "USERSPACE_LOGICAL_DELIVERY_FAULTS_ACROSS_REAL_LOOPBACK_TCP_BOUNDARIES",
    }
    assert original["rpc_accounting"]["classification"] == ("RECORDED_CLAIM_BEARING_RPCS_ONLY")
    assert (
        "exact_elapsed_ns"
        in original["random_observations"]["excluded_from_cross_run_scalar_equality"]
    )
    assert {
        "platform_specific_nonzero_edge_kill_exit_code",
        "platform_specific_backend_crash_failure_category",
        "platform_specific_backend_crash_transport_outcome",
        "derived_session_id",
        "derived_connection_id",
        "exact_request_bytes",
        "exact_response_bytes",
    } <= set(original["random_observations"]["excluded_from_cross_run_scalar_equality"])
    assert {
        "exit_class",
        "backend_application_crash_exit_code_73",
        "backend_application_crash_no_response_transport_class",
        "delay_barrier_causal_order",
    } <= set(original["random_observations"]["claim_bearing_normalization"])

    attacks = []
    missing_coordinate = copy.deepcopy(original)
    missing_coordinate["coordinates"].pop()
    attacks.append(missing_coordinate)
    wrong_order = copy.deepcopy(original)
    wrong_order["coordinates"][0], wrong_order["coordinates"][1] = (
        wrong_order["coordinates"][1],
        wrong_order["coordinates"][0],
    )
    attacks.append(wrong_order)
    bool_timeout = copy.deepcopy(original)
    bool_timeout["transport"]["rpc_timeout_ms"] = True
    attacks.append(bool_timeout)
    removed_blocker = copy.deepcopy(original)
    removed_blocker["blockers"].pop()
    attacks.append(removed_blocker)
    promoted_scope = copy.deepcopy(original)
    promoted_scope["evidence_scope"] = "G7"
    attacks.append(promoted_scope)

    for index, attack in enumerate(attacks):
        path = tmp_path / f"attack-{index}.yaml"
        path.write_text(yaml.safe_dump(attack, sort_keys=False), encoding="utf-8")
        with pytest.raises(ValueError):
            service_fault.load_config(path)

    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        CONFIG_PATH.read_text(encoding="utf-8") + "\nformal: false\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate YAML"):
        service_fault.load_config(duplicate)


def test_artifact_rejects_coordinated_coordinate_count_and_boundary_tampering(
    formal_evidence,
) -> None:
    config, config_id, _, artifact = formal_evidence
    attacks: list[dict[str, object]] = []

    deleted_coordinate = copy.deepcopy(artifact)
    deleted_coordinate["rows"].pop()
    deleted_coordinate["coordinates"].pop()
    deleted_coordinate["summary"]["coordinate_count"] -= 1
    deleted_coordinate["summary"]["passing_rows"] -= 1
    _rehash(deleted_coordinate)
    attacks.append(deleted_coordinate)

    changed_count = copy.deepcopy(artifact)
    changed_count["summary"]["valid_attempts"] += 1
    _rehash(changed_count)
    attacks.append(changed_count)

    changed_scope = copy.deepcopy(artifact)
    changed_scope["evidence_scope"] = "G7_COMPLETE"
    changed_scope["g7_claim_eligible"] = True
    _rehash(changed_scope)
    attacks.append(changed_scope)

    changed_status = copy.deepcopy(artifact)
    changed_status["status"] = "PASS"
    changed_status["g7_status"] = "PASS"
    changed_status["blockers"] = []
    _rehash(changed_status)
    attacks.append(changed_status)

    changed_commit = copy.deepcopy(artifact)
    changed_commit["source_commit"] = "b" * 40
    changed_commit["git_before"]["commit"] = "b" * 40
    changed_commit["git_after"]["commit"] = "b" * 40
    _rehash(changed_commit)
    attacks.append(changed_commit)

    changed_config = copy.deepcopy(artifact)
    changed_config["config_id"] = "0" * 64
    _rehash(changed_config)
    attacks.append(changed_config)

    changed_id = copy.deepcopy(artifact)
    changed_id["artifact_id"] = "0" * 64
    attacks.append(changed_id)

    for attack in attacks:
        with pytest.raises(ValueError):
            service_fault.validate_artifact(attack, config, config_id, COMMIT)


def test_coordinated_login_relabel_and_deleted_check_are_rejected(formal_evidence) -> None:
    config, config_id, _, artifact = formal_evidence

    relabeled = copy.deepcopy(artifact)
    login = relabeled["rows"][0]["logins"][-1]
    login["credential_class"] = "INVALID"
    login["expected_valid"] = False
    row = relabeled["rows"][0]
    row["summary"] = service_fault._derive_row_summary(
        row["logins"], row["transport_events"], row["process_events"], row["checks"]
    )
    row_body = {key: value for key, value in row.items() if key != "row_id"}
    row["row_id"] = service_fault._identity(row_body)
    relabeled["summary"] = service_fault._derive_artifact_summary(relabeled["rows"])
    _rehash(relabeled)
    with pytest.raises(ValueError, match="login contract"):
        service_fault.validate_artifact(relabeled, config, config_id, COMMIT)

    deleted_check = copy.deepcopy(artifact)
    row = deleted_check["rows"][0]
    row["checks"].pop()
    row["summary"] = service_fault._derive_row_summary(
        row["logins"], row["transport_events"], row["process_events"], row["checks"]
    )
    row_body = {key: value for key, value in row.items() if key != "row_id"}
    row["row_id"] = service_fault._identity(row_body)
    deleted_check["summary"] = service_fault._derive_artifact_summary(deleted_check["rows"])
    _rehash(deleted_check)
    with pytest.raises(ValueError, match="check names"):
        service_fault.validate_artifact(deleted_check, config, config_id, COMMIT)


def test_exported_boundary_mutation_cannot_promote_artifact(
    formal_evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, config_id, rows, _ = formal_evidence
    monkeypatch.setattr(service_fault, "ARTIFACT_SCHEMA", "attacker-schema")
    monkeypatch.setattr(service_fault, "EVIDENCE_SCOPE", "G7_COMPLETE")
    monkeypatch.setattr(service_fault, "G7_STATUS", "PASS")
    monkeypatch.setattr(service_fault, "STATUS", "PASS")
    monkeypatch.setattr(service_fault, "BLOCKERS", ())
    monkeypatch.setitem(service_fault.FORMAL_CONFIG, "evidence_scope", "G7_COMPLETE")
    artifact = service_fault.build_artifact(
        config,
        config_id,
        COMMIT,
        _clean_state(),
        _clean_state(),
        rows,
    )
    assert artifact["schema"] == "traps-g7-service-fault-artifact-v1"
    assert artifact["evidence_scope"] == (
        "LOOPBACK_USERSPACE_PROXY_PROCESS_BACKEND_FAULT_COMPONENT"
    )
    assert artifact["fault_layer"]["edge_fault_injection_rpc"] == "FORBIDDEN"
    assert artifact["fault_layer"]["kernel_netem"] is False
    assert artifact["fault_layer"]["production_network_claim"] is False
    assert artifact["unfrozen_artifact_integrity_boundary"] == (
        "RAW_VALUES_NOT_TAMPER_EVIDENT_UNTIL_CONTENT_ADDRESSED_FREEZE_AND_INDEPENDENT_AUDIT"
    )
    assert artifact["g7_claim_eligible"] is False
    assert artifact["g7_status"] == "BLOCKED_PENDING_E9_AND_INDEPENDENT_FREEZE_AUDIT"
    assert artifact["status"] == "COMPONENT_CHECK_PASS_G7_BLOCKED"
    assert len(artifact["blockers"]) == 3
    service_fault.validate_artifact(artifact, config, config_id, COMMIT)


def test_public_validator_reexecutes_fresh_matrix_outside_checkout(
    formal_evidence, monkeypatch: pytest.MonkeyPatch
) -> None:
    config, config_id, _, artifact = formal_evidence
    real_fresh_matrix = service_fault._fresh_matrix
    calls = []

    def traced_fresh_matrix(value):
        calls.append(value["experiment_id"])
        return real_fresh_matrix(value)

    monkeypatch.setattr(service_fault, "_git_state", lambda: _clean_state())
    monkeypatch.setattr(service_fault, "_fresh_matrix", traced_fresh_matrix)
    validated = service_fault.validate_with_reexecution(
        artifact,
        config,
        config_id,
        COMMIT,
    )
    assert validated["status"] == service_fault.STATUS
    assert calls == [service_fault.EXPERIMENT_ID]


def test_public_validator_rejects_source_change_after_reexecution(formal_evidence) -> None:
    config, config_id, rows, artifact = formal_evidence
    with (
        mock.patch.object(
            service_fault,
            "_git_state",
            side_effect=[_clean_state(), _clean_state("b" * 40)],
        ),
        mock.patch.object(service_fault, "_fresh_matrix", return_value=rows),
    ):
        with pytest.raises(RuntimeError, match="exact clean"):
            service_fault.validate_with_reexecution(
                artifact,
                config,
                config_id,
                COMMIT,
            )


def test_json_loader_and_output_writer_are_fail_closed(tmp_path: Path) -> None:
    for index, payload in enumerate(("[]", '{"x":1,"x":2}', '{"x":NaN}')):
        path = tmp_path / f"bad-{index}.json"
        path.write_text(payload, encoding="utf-8")
        with pytest.raises(ValueError):
            service_fault.load_json_object(path)

    output = tmp_path / "artifact.json"
    service_fault._write_json_exclusive(output, {"value": 1})
    with pytest.raises(FileExistsError):
        service_fault._write_json_exclusive(output, {"value": 2})
    with pytest.raises(ValueError, match="outside"):
        service_fault._write_json_exclusive(
            service_fault.ROOT / "forbidden-service-fault-output.json",
            {},
        )
