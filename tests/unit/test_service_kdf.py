from __future__ import annotations

import importlib.util

import pytest

from dataplane.types import BackendResultKind
from service import KdfBackend, KdfProfile, ServiceAccount, derive_kdf


def _account() -> ServiceAccount:
    return ServiceAccount(
        account_index=0,
        username="alice",
        account_id="account-0",
        account_generation=1,
        credential_set_version=1,
        salt=b"0123456789abcdef",
    )


def test_pbkdf2_backend_executes_typed_match_mismatch_and_dummy_paths() -> None:
    profile = KdfProfile(
        "pbkdf2-test",
        "pbkdf2_sha256",
        {"iterations": 100, "dklen": 32},
    )
    expected = derive_kdf(profile, b"correct", _account().salt)
    assert len(expected) == 32
    backend = KdfBackend(profile, dummy_salt=b"dummy-salt-00000")
    backend.enroll(_account(), b"correct")

    match = backend.verify(_account(), "alice", b"correct")
    mismatch = backend.verify(_account(), "alice", b"wrong")
    unknown = backend.verify(None, "missing", b"wrong")

    assert match.kind is BackendResultKind.MATCH
    assert mismatch.kind is BackendResultKind.CREDENTIAL_MISMATCH
    assert mismatch.is_exact_mismatch_for(_account().view)
    assert unknown.kind is BackendResultKind.NO_ACCOUNT
    assert profile.implementation_metadata()["actual_kdf_execution"] is True


@pytest.mark.skipif(
    importlib.util.find_spec("argon2") is None,
    reason="argon2-cffi is not installed on this host",
)
def test_argon2id_profile_executes_real_low_level_type_id() -> None:
    profile = KdfProfile(
        "argon2id-test",
        "argon2id",
        {
            "time_cost": 1,
            "memory_cost_kib": 32,
            "parallelism": 1,
            "hash_len": 16,
        },
    )
    first = derive_kdf(profile, b"password", b"0123456789abcdef")
    second = derive_kdf(profile, b"password", b"0123456789abcdef")
    changed = derive_kdf(profile, b"password-2", b"0123456789abcdef")
    assert first == second
    assert first != changed
    assert profile.implementation_metadata()["implementation"].endswith("(Type.ID)")
