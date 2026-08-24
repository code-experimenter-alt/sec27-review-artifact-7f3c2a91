from __future__ import annotations

import hashlib
import json
import math
import re
import socket
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
FULL_COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FROZEN_GENERATOR_SPEC = {
    "name": "random_feasible_problem",
    "version": 3,
    "dimensions": [1, 2],
    "index_seed_derivation": "splitmix64-v1",
    "numeric_canonicalization": "decimal-13-significant-v1",
}
FORMAL_PROFILE_SPEC = {
    "expected_instances": 10_000,
    "seed": 20260805,
    "references": {
        "cvxpy": True,
        "brute_force": True,
        "brute_force_points": 101,
    },
    "thresholds": {
        "maximum_relative_gap": 1e-8,
        "maximum_primal_violation": 1e-8,
        "maximum_cvxpy_difference": 1e-7,
        "maximum_cvxpy_primal_violation": 1e-7,
        "maximum_dual_above_primal": 1e-8,
        "brute_force_tolerance": 1e-8,
    },
    "require_clean_git": True,
}
THRESHOLD_FIELDS = set(FORMAL_PROFILE_SPEC["thresholds"])


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def display_path(path: str | Path, *, root: Path = ROOT) -> str:
    resolved = Path(path).resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return f"external/{resolved.name}"


def redact_user_paths(value: Any) -> str:
    text = str(value)
    replacements = {
        str(ROOT.resolve()): "<REPO>",
        str(Path.home().resolve()): "<HOME>",
    }
    for original, replacement in replacements.items():
        text = text.replace(original, replacement)
        text = text.replace(original.replace("\\", "/"), replacement)
    return text


def git_metadata(*, root: Path = ROOT) -> dict[str, Any]:
    def run(*arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )

    commit_result = run("rev-parse", "HEAD")
    status_result = run("status", "--porcelain=v1", "--untracked-files=normal")
    commit = commit_result.stdout.strip().lower() if commit_result.returncode == 0 else None
    dirty = bool(status_result.stdout) if status_result.returncode == 0 else None
    return {"commit": commit, "git_dirty": dirty}


def validate_validation_config(value: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
    try:
        config = json.loads(json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False))
    except (TypeError, ValueError) as error:
        raise ValueError("optimizer validation config must be finite JSON data") from error
    if not isinstance(config, dict):
        raise ValueError("optimizer validation config must be a JSON object")
    required = {
        "schema",
        "experiment",
        "profile",
        "expected_instances",
        "seed",
        "generator",
        "references",
        "thresholds",
        "require_clean_git",
    }
    missing = sorted(required - set(config))
    if missing:
        raise ValueError(f"optimizer validation config misses {missing}")
    extra = sorted(set(config) - required)
    if extra:
        raise ValueError(f"optimizer validation config has unknown fields {extra}")
    if config["schema"] != "traps-t4a-validation-config-v3":
        raise ValueError("unsupported optimizer validation config schema")
    if config["experiment"] != "t4a_fixed_partition_validation":
        raise ValueError("config experiment is not T4a fixed-partition validation")
    if config["profile"] not in ("formal", "smoke"):
        raise ValueError("optimizer profile must be formal or smoke")
    if type(config["expected_instances"]) is not int or config["expected_instances"] <= 0:
        raise ValueError("expected_instances must be a positive integer")
    if type(config["seed"]) is not int:
        raise ValueError("seed must be an integer")
    if config["generator"] != FROZEN_GENERATOR_SPEC:
        raise ValueError(
            "generator must exactly match the frozen random_feasible_problem v3 specification"
        )
    references = config["references"]
    if not isinstance(references, dict):
        raise ValueError("references must be a JSON object")
    missing_references = sorted({"cvxpy", "brute_force", "brute_force_points"} - set(references))
    if missing_references:
        raise ValueError(f"optimizer references miss {missing_references}")
    extra_references = sorted(set(references) - {"cvxpy", "brute_force", "brute_force_points"})
    if extra_references:
        raise ValueError(f"optimizer references have unknown fields {extra_references}")
    if type(references["cvxpy"]) is not bool or type(references["brute_force"]) is not bool:
        raise ValueError("reference switches must be Boolean")
    if type(references["brute_force_points"]) is not int or references["brute_force_points"] < 2:
        raise ValueError("brute_force_points must be an integer of at least two")
    thresholds = config["thresholds"]
    if not isinstance(thresholds, dict):
        raise ValueError("thresholds must be a JSON object")
    missing_thresholds = sorted(THRESHOLD_FIELDS - set(thresholds))
    if missing_thresholds:
        raise ValueError(f"optimizer thresholds miss {missing_thresholds}")
    extra_thresholds = sorted(set(thresholds) - THRESHOLD_FIELDS)
    if extra_thresholds:
        raise ValueError(f"optimizer thresholds have unknown fields {extra_thresholds}")
    for field in THRESHOLD_FIELDS:
        value = thresholds[field]
        if type(value) not in {int, float} or not math.isfinite(value) or value < 0:
            raise ValueError(f"{field} must be finite and nonnegative")
    if type(config["require_clean_git"]) is not bool:
        raise ValueError("require_clean_git must be Boolean")
    if config["profile"] == "formal":
        for field in ("expected_instances", "seed", "references", "thresholds"):
            if config[field] != FORMAL_PROFILE_SPEC[field]:
                raise ValueError(f"formal optimizer profile fixes {field}")
        if config["require_clean_git"] is not True:
            raise ValueError("formal optimizer profile requires clean Git")
    else:
        if config["require_clean_git"] is not False:
            raise ValueError("smoke optimizer profile cannot claim clean formal evidence")
        if config["expected_instances"] >= FORMAL_PROFILE_SPEC["expected_instances"]:
            raise ValueError("smoke optimizer profile must remain smaller than formal")
    return config, canonical_hash(config)


def load_validation_config(path: str | Path) -> tuple[dict[str, Any], str]:
    config_path = Path(path)
    value = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("optimizer validation config must be a JSON object")
    return validate_validation_config(value)


def dataset_spec(config: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "experiment": config["experiment"],
        "profile": config["profile"],
        "expected_indices": [0, int(config["expected_instances"]) - 1],
        "seed": int(config["seed"]),
        "generator": config["generator"],
    }


def build_provenance(
    config: Mapping[str, Any],
    *,
    config_hash: str | None = None,
    root: Path = ROOT,
    git: Mapping[str, Any] | None = None,
    host: str | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    metadata = dict(git if git is not None else git_metadata(root=root))
    return {
        "commit": metadata.get("commit"),
        "git_dirty": metadata.get("git_dirty"),
        "config_hash": config_hash or canonical_hash(config),
        "dataset_hash": canonical_hash(dataset_spec(config)),
        "seed": int(config["seed"]),
        "profile": config["profile"],
        "host": host or socket.gethostname(),
        "timestamp_utc": timestamp or utc_timestamp(),
    }


def require_formal_provenance(provenance: Mapping[str, Any]) -> None:
    if provenance.get("profile") != "formal":
        raise RuntimeError("formal optimizer evidence requires the formal profile")
    commit = provenance.get("commit")
    if not isinstance(commit, str) or FULL_COMMIT_RE.fullmatch(commit) is None:
        raise RuntimeError("formal optimizer evidence requires a full Git commit hash")
    if provenance.get("git_dirty") is not False:
        raise RuntimeError("formal optimizer evidence requires a clean Git worktree")
    for field in ("config_hash", "dataset_hash"):
        value = provenance.get(field)
        if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
            raise RuntimeError(f"formal optimizer evidence requires a valid {field}")
