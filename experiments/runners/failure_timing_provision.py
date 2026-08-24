#!/usr/bin/env python3
"""Provision untrusted local candidates for the E9 formal evidence workflow.

This producer-side tool has no authority to enable formal collection.  It never
creates an auditor registry identity, a formal contract, a freshness challenge,
a nonce marker, raw evidence, or an attestation.  Auditor custody and signing
remain separate, mandatory steps.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from experiments.runners import failure_timing_bench as bench  # noqa: E402

REGISTRY_CANDIDATE_SCHEMA = "traps-e9-replay-registry-identity-candidate-v1"
REGISTRY_CANDIDATE_FILENAME = "registry.identity.candidate.json"
ANCHOR_CANDIDATE_SCHEMA = "traps-e9-exclusive-lock-anchor-candidate-v1"
ANCHOR_CANDIDATE_SUFFIX = ".candidate.json"

PENDING_AUDITOR_CUSTODY = "PENDING_AUDITOR_CUSTODY"
UNSIGNED_PRODUCER_PROPOSAL = "UNSIGNED_PRODUCER_PROPOSAL_NOT_AUTHORIZATION"
NOT_AUTHORIZATION = "NOT_AUTHORIZATION"
MARKER_ABSENCE = "ABSENT_NOT_CREATED_BY_PROVISIONER"
REGISTRY_NAMESPACES = ("collection", "verification")


class ProvisioningError(ValueError):
    """Raised when a producer-side provisioning invariant is not satisfied."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ProvisioningError(
            f"{label} keys differ: missing={sorted(expected - actual)}, "
            f"unexpected={sorted(actual - expected)}"
        )


def _exact_value(value: object, expected: object, label: str) -> None:
    if type(value) is not type(expected) or value != expected:
        raise ProvisioningError(f"{label} differs from its fixed value")


def _lower_hex(value: object, byte_count: int, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != byte_count * 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProvisioningError(f"{label} must be {byte_count} lowercase-hex bytes")
    return value


def _integer(value: object, minimum: int, label: str) -> int:
    if type(value) is not int or value < minimum:
        raise ProvisioningError(f"{label} must be an integer >= {minimum}")
    return value


def _absolute_lexical(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _entry_exists(path: Path) -> bool:
    return os.path.lexists(path)


def _require_named_target(path: Path, label: str) -> Path:
    target = _absolute_lexical(path)
    if not target.name:
        raise ProvisioningError(f"{label} must name a child entry")
    return target


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(_absolute_lexical(left))) == os.path.normcase(
        str(_absolute_lexical(right))
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _random_bytes(byte_count: int) -> bytes:
    payload = secrets.token_bytes(byte_count)
    if type(payload) is not bytes or len(payload) != byte_count:
        raise ProvisioningError("the operating-system random source returned invalid bytes")
    return payload


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("exclusive provisioning write made no progress")
        offset += written


def _fsync_file(descriptor: int) -> None:
    os.fsync(descriptor)


def _flush_windows_directory(path: Path) -> None:
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    flush_file_buffers = kernel32.FlushFileBuffers
    flush_file_buffers.argtypes = (wintypes.HANDLE,)
    flush_file_buffers.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    handle = create_file(
        str(path),
        0x40000000,  # GENERIC_WRITE
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,  # OPEN_EXISTING
        0x02000000,  # FILE_FLAG_BACKUP_SEMANTICS
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise OSError(
            ctypes.get_last_error(),
            f"cannot open directory for durable flush: {path}",
        )
    try:
        ctypes.set_last_error(0)
        if not flush_file_buffers(handle):
            raise OSError(
                ctypes.get_last_error(),
                f"cannot durably flush directory: {path}",
            )
    finally:
        close_handle(handle)


def _fsync_directory(directory: bench._PinnedDirectory) -> None:
    directory.verify("provisioning directory flush")
    if directory.descriptor is not None:
        os.fsync(directory.descriptor)
    elif os.name == "nt":
        _flush_windows_directory(directory.resolved_path)
    else:
        raise ProvisioningError("this platform cannot durably flush a directory")
    directory.verify("provisioning directory flush")


def _open_exclusive_child_owned(
    parent: bench._PinnedDirectory,
    name: str,
    label: str,
) -> tuple[int, os.stat_result]:
    """Create a child while retaining enough state to fail closed after open."""
    parent.verify(f"{label} parent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    if parent.descriptor is not None and os.open in os.supports_dir_fd:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent.descriptor)
    else:
        descriptor = os.open(parent.resolved_path / name, flags, 0o600)
    try:
        identity = os.fstat(descriptor)
        if not stat.S_ISREG(identity.st_mode):
            raise ProvisioningError(f"{label} is not a regular file")
        bench._verify_open_child(
            parent,
            name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            label,
        )
        return descriptor, identity
    except BaseException as exc:
        try:
            os.close(descriptor)
        except OSError as close_exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise exc from close_exc
            raise ProvisioningError(
                f"{label} creation could not be verified and its descriptor could not "
                "be closed; its exclusive blocking output is retained and no name-based "
                "rollback was attempted"
            ) from exc
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ProvisioningError(
            f"{label} creation could not be verified; its exclusive blocking output "
            "is retained and no name-based rollback was attempted"
        ) from exc


def _write_exclusive_bytes(
    parent: bench._PinnedDirectory,
    name: str,
    payload: bytes,
    label: str,
) -> os.stat_result:
    opened_descriptor, identity = _open_exclusive_child_owned(parent, name, label)
    descriptor: int | None = opened_descriptor
    try:
        _write_all(opened_descriptor, payload)
        _fsync_file(opened_descriptor)
        bench._verify_open_child(
            parent,
            name,
            opened_descriptor,
            identity.st_dev,
            identity.st_ino,
            label,
        )
        os.close(opened_descriptor)
        descriptor = None
        _fsync_directory(parent)
        return identity
    except BaseException as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        raise ProvisioningError(
            f"{label} publication failed; its exclusive blocking output is retained "
            "and no name-based rollback was attempted"
        ) from exc


def _read_owned_bytes(
    parent: bench._PinnedDirectory,
    name: str,
    identity: os.stat_result,
    maximum_bytes: int,
    label: str,
) -> bytes:
    descriptor, observed = bench._open_existing_child(parent, name, label)
    try:
        if not _same_identity(observed, identity):
            raise ProvisioningError(f"{label} identity changed after publication")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > maximum_bytes:
            raise ProvisioningError(f"{label} exceeds its fixed byte limit")
        bench._verify_open_child(
            parent,
            name,
            descriptor,
            identity.st_dev,
            identity.st_ino,
            label,
        )
        return payload
    finally:
        os.close(descriptor)


def _require_canonical_file_uri(value: object, label: str) -> Path:
    if type(value) is not str or not value.isascii():
        raise ProvisioningError(f"{label} must be an ASCII file URI")
    try:
        path = bench._file_uri_path(value, label)
    except bench.EvidenceError as exc:
        raise ProvisioningError(str(exc)) from exc
    if path.absolute().as_uri() != value:
        raise ProvisioningError(f"{label} must be canonical")
    return path


def _list_pinned_directory(directory: bench._PinnedDirectory) -> list[str]:
    directory.verify("pre-existing replay registry candidate directory")
    listing_target: int | Path = (
        directory.descriptor
        if directory.descriptor is not None
        else directory.resolved_path
    )
    try:
        entries = os.listdir(listing_target)
    except OSError as exc:
        raise ProvisioningError("cannot enumerate replay registry candidate directory") from exc
    directory.verify("pre-existing replay registry candidate directory")
    return entries


def _require_empty_registry(directory: bench._PinnedDirectory) -> None:
    entries = _list_pinned_directory(directory)
    if entries:
        if REGISTRY_CANDIDATE_FILENAME in entries:
            raise FileExistsError(
                "replay registry identity candidate already exists: "
                f"{directory.resolved_path / REGISTRY_CANDIDATE_FILENAME}"
            )
        raise ProvisioningError(
            "registry-init requires a pre-existing empty, real registry directory"
        )


def _require_only_registry_candidate(directory: bench._PinnedDirectory) -> None:
    entries = _list_pinned_directory(directory)
    if entries != [REGISTRY_CANDIDATE_FILENAME]:
        raise ProvisioningError(
            "replay registry directory changed during candidate publication; the blocking "
            "candidate is retained and auditor disposition is required"
        )


def _registry_candidate(
    registry_path: Path,
    candidate_path: Path,
    namespace: str,
    registry_id: str,
) -> dict[str, object]:
    candidate = {
        "schema": REGISTRY_CANDIDATE_SCHEMA,
        "registry_id": registry_id,
        "namespace": namespace,
        "registry_uri": registry_path.resolve(strict=True).as_uri(),
        "candidate_uri": candidate_path.resolve(strict=False).as_uri(),
        "custody_status": PENDING_AUDITOR_CUSTODY,
        "formal_evidence": False,
        "authorization": NOT_AUTHORIZATION,
    }
    return validate_registry_candidate(candidate)


def validate_registry_candidate(value: object) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ProvisioningError("registry identity candidate must be a string-keyed object")
    candidate = value
    _exact_keys(
        candidate,
        {
            "schema",
            "registry_id",
            "namespace",
            "registry_uri",
            "candidate_uri",
            "custody_status",
            "formal_evidence",
            "authorization",
        },
        "registry identity candidate",
    )
    _exact_value(candidate["schema"], REGISTRY_CANDIDATE_SCHEMA, "candidate schema")
    _lower_hex(candidate["registry_id"], 32, "candidate registry ID")
    if candidate["namespace"] not in REGISTRY_NAMESPACES:
        raise ProvisioningError("candidate registry namespace is unsupported")
    registry_path = _require_canonical_file_uri(
        candidate["registry_uri"], "candidate registry_uri"
    )
    candidate_path = _require_canonical_file_uri(
        candidate["candidate_uri"], "candidate candidate_uri"
    )
    expected_candidate = registry_path / REGISTRY_CANDIDATE_FILENAME
    if not _same_path(candidate_path, expected_candidate):
        raise ProvisioningError(
            "candidate URI must use the fixed registry identity candidate filename"
        )
    _exact_value(
        candidate["custody_status"],
        PENDING_AUDITOR_CUSTODY,
        "candidate custody status",
    )
    _exact_value(candidate["formal_evidence"], False, "candidate evidence status")
    _exact_value(candidate["authorization"], NOT_AUTHORIZATION, "candidate authorization")
    return candidate


def provision_registry(registry_path: Path, namespace: str) -> dict[str, object]:
    """Publish one candidate inside a pre-existing empty real registry directory."""
    if namespace not in REGISTRY_NAMESPACES:
        raise ProvisioningError("registry namespace must be collection or verification")
    target = _require_named_target(registry_path, "replay registry candidate")
    target_pin = bench._pin_directory(
        target, "pre-existing replay registry candidate directory"
    )
    try:
        _require_empty_registry(target_pin)
        registry_id = _random_bytes(32).hex()
        candidate_path = target / REGISTRY_CANDIDATE_FILENAME
        candidate = _registry_candidate(target, candidate_path, namespace, registry_id)
        payload = _canonical(candidate)
        candidate_identity = _write_exclusive_bytes(
            target_pin,
            REGISTRY_CANDIDATE_FILENAME,
            payload,
            "replay registry identity candidate",
        )
        target_pin.verify("replay registry candidate")
        try:
            _require_only_registry_candidate(target_pin)
            if (
                _read_owned_bytes(
                    target_pin,
                    REGISTRY_CANDIDATE_FILENAME,
                    candidate_identity,
                    len(payload),
                    "replay registry identity candidate",
                )
                != payload
            ):
                raise ProvisioningError("registry identity candidate content changed")
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ProvisioningError(
                "registry identity candidate could not be revalidated; its blocking "
                "output is retained, no name-based rollback was attempted, and auditor "
                "disposition is required"
            ) from exc
        return candidate
    finally:
        target_pin.close()


def _anchor_candidate(
    anchor_path: Path,
    marker_path: Path,
    candidate_path: Path,
    payload: bytes,
    identity: os.stat_result,
    filesystem: Mapping[str, object],
) -> dict[str, object]:
    candidate = {
        "schema": ANCHOR_CANDIDATE_SCHEMA,
        "candidate_status": UNSIGNED_PRODUCER_PROPOSAL,
        "formal_evidence": False,
        "authorization": NOT_AUTHORIZATION,
        "anchor_uri": anchor_path.resolve(strict=True).as_uri(),
        "candidate_uri": candidate_path.resolve(strict=False).as_uri(),
        "anchor_bytes_hex": payload.hex(),
        "anchor_sha256": hashlib.sha256(payload).hexdigest(),
        "anchor_device": identity.st_dev,
        "anchor_inode": identity.st_ino,
        "lock_byte_offset": 0,
        "lock_byte_length": len(payload),
        "expected_lock_api": bench._expected_lock_api(bench.platform.system()),
        "filesystem": dict(filesystem),
        "marker_uri": marker_path.resolve(strict=False).as_uri(),
        "marker_state": MARKER_ABSENCE,
    }
    return validate_anchor_candidate(candidate)


def validate_anchor_candidate(value: object) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ProvisioningError("lock anchor candidate must be a string-keyed object")
    candidate = value
    _exact_keys(
        candidate,
        {
            "schema",
            "candidate_status",
            "formal_evidence",
            "authorization",
            "anchor_uri",
            "candidate_uri",
            "anchor_bytes_hex",
            "anchor_sha256",
            "anchor_device",
            "anchor_inode",
            "lock_byte_offset",
            "lock_byte_length",
            "expected_lock_api",
            "filesystem",
            "marker_uri",
            "marker_state",
        },
        "lock anchor candidate",
    )
    _exact_value(candidate["schema"], ANCHOR_CANDIDATE_SCHEMA, "anchor candidate schema")
    _exact_value(
        candidate["candidate_status"],
        UNSIGNED_PRODUCER_PROPOSAL,
        "anchor candidate status",
    )
    _exact_value(candidate["formal_evidence"], False, "anchor evidence status")
    _exact_value(candidate["authorization"], NOT_AUTHORIZATION, "anchor authorization")
    anchor_hex = _lower_hex(
        candidate["anchor_bytes_hex"],
        bench.LOCK_ANCHOR_BYTE_COUNT,
        "anchor candidate bytes",
    )
    _exact_value(
        candidate["anchor_sha256"],
        hashlib.sha256(bytes.fromhex(anchor_hex)).hexdigest(),
        "anchor candidate digest",
    )
    _integer(candidate["anchor_device"], 0, "anchor device")
    _integer(candidate["anchor_inode"], 1, "anchor inode")
    _exact_value(candidate["lock_byte_offset"], 0, "anchor lock byte offset")
    _exact_value(
        candidate["lock_byte_length"],
        bench.LOCK_ANCHOR_BYTE_COUNT,
        "anchor lock byte length",
    )
    _exact_value(
        candidate["expected_lock_api"],
        bench._expected_lock_api(bench.platform.system()),
        "anchor lock API",
    )
    bench._validate_lock_filesystem(candidate["filesystem"], bench.platform.system())
    anchor_path = _require_canonical_file_uri(
        candidate["anchor_uri"], "anchor candidate anchor_uri"
    )
    candidate_path = _require_canonical_file_uri(
        candidate["candidate_uri"], "anchor candidate candidate_uri"
    )
    marker_path = _require_canonical_file_uri(
        candidate["marker_uri"], "anchor candidate marker_uri"
    )
    expected_candidate = anchor_path.with_name(anchor_path.name + ANCHOR_CANDIDATE_SUFFIX)
    if not _same_path(candidate_path, expected_candidate):
        raise ProvisioningError(
            "anchor candidate URI must use the fixed suffix adjacent to its anchor"
        )
    if (
        _same_path(anchor_path, candidate_path)
        or _same_path(anchor_path, marker_path)
        or _same_path(candidate_path, marker_path)
    ):
        raise ProvisioningError("anchor, candidate, and marker URIs must be distinct")
    _exact_value(candidate["marker_state"], MARKER_ABSENCE, "anchor marker state")
    return candidate


def _assert_absent(path: Path, label: str) -> None:
    if _entry_exists(path) or bench._is_link_or_junction(path):
        raise FileExistsError(f"{label} already exists: {path}")


def provision_anchor(anchor_path: Path, marker_path: Path) -> dict[str, object]:
    """Create one lock anchor and a clearly non-authorizing adjacent candidate."""
    anchor = _require_named_target(anchor_path, "exclusive lock anchor")
    marker = _require_named_target(marker_path, "exclusive lock marker")
    candidate_path = anchor.with_name(anchor.name + ANCHOR_CANDIDATE_SUFFIX)
    if _same_path(anchor, marker) or _same_path(candidate_path, marker):
        raise ProvisioningError("lock anchor, candidate, and marker paths must be distinct")

    anchor_parent = bench._pin_directory(anchor.parent, "exclusive lock anchor parent")
    marker_parent = bench._pin_directory(marker.parent, "exclusive lock marker parent")
    try:
        filesystem = bench._probe_lock_filesystem(anchor_parent.resolved_path)
        marker_filesystem = bench._probe_lock_filesystem(marker_parent.resolved_path)
        if (
            anchor_parent.device != marker_parent.device
            or filesystem != marker_filesystem
        ):
            raise ProvisioningError(
                "lock anchor and marker parents must use the same exact local filesystem"
            )
        _assert_absent(anchor, "exclusive lock anchor")
        _assert_absent(candidate_path, "exclusive lock anchor candidate")
        _assert_absent(marker, "exclusive lock marker")

        payload = _random_bytes(bench.LOCK_ANCHOR_BYTE_COUNT)
        anchor_identity = _write_exclusive_bytes(
            anchor_parent,
            anchor.name,
            payload,
            "exclusive lock anchor",
        )
        try:
            _assert_absent(marker, "exclusive lock marker")
            candidate = _anchor_candidate(
                anchor,
                marker,
                candidate_path,
                payload,
                anchor_identity,
                filesystem,
            )
            candidate_payload = _canonical(candidate)
            candidate_identity = _write_exclusive_bytes(
                anchor_parent,
                candidate_path.name,
                candidate_payload,
                "exclusive lock anchor candidate",
            )
            _assert_absent(marker, "exclusive lock marker")
            anchor_parent.verify("exclusive lock anchor parent")
            marker_parent.verify("exclusive lock marker parent")
            if (
                _read_owned_bytes(
                    anchor_parent,
                    anchor.name,
                    anchor_identity,
                    len(payload),
                    "exclusive lock anchor",
                )
                != payload
            ):
                raise ProvisioningError("exclusive lock anchor content changed")
            if (
                _read_owned_bytes(
                    anchor_parent,
                    candidate_path.name,
                    candidate_identity,
                    len(candidate_payload),
                    "exclusive lock anchor candidate",
                )
                != candidate_payload
            ):
                raise ProvisioningError("exclusive lock anchor candidate content changed")
            return candidate
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise ProvisioningError(
                "anchor provisioning failed after exclusive anchor publication; every "
                "visible blocking output is retained and no name-based rollback was attempted"
            ) from exc
    finally:
        marker_parent.close()
        anchor_parent.close()


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    registry = subparsers.add_parser(
        "registry-init",
        help="publish a candidate in a pre-existing empty real registry directory",
    )
    registry.add_argument("--registry", type=Path, required=True)
    registry.add_argument("--namespace", choices=REGISTRY_NAMESPACES, required=True)

    anchor = subparsers.add_parser(
        "anchor-init",
        help="create a local lock anchor without creating its marker",
    )
    anchor.add_argument("--anchor", type=Path, required=True)
    anchor.add_argument("--marker", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.command == "registry-init":
            result = provision_registry(args.registry, args.namespace)
        else:
            result = provision_anchor(args.anchor, args.marker)
    except (bench.EvidenceError, ProvisioningError, FileExistsError, OSError) as exc:
        error = {
            "status": "FAILED",
            "command": args.command,
            "error_type": type(exc).__name__,
            "message": str(exc),
        }
        sys.stderr.buffer.write(_canonical(error) + b"\n")
        return 2
    sys.stdout.buffer.write(_canonical(result) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
