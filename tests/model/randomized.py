"""Developer smoke runner for the version-safety model.

This command is intentionally non-evidentiary. Formal G7 execution is owned by
experiments/runners/g7_model_evidence.py and remains fail-closed until its
reachable-state fixpoint blocker is resolved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import platform
import sys
from datetime import datetime, timezone
from typing import Any

MODEL_DIR = pathlib.Path(__file__).resolve().parent
if str(MODEL_DIR) not in sys.path:
    sys.path.insert(0, str(MODEL_DIR))

from version_safety_model import format_report, run_randomized  # noqa: E402

SMOKE_SCHEMA = "traps-version-safety-smoke-v2"
SMOKE_CLASSIFICATION = "SMOKE_ONLY_NON_EVIDENCE"
G7_STATUS = "BLOCKED_PENDING_SERVICE_FAULT_AND_E9"
LIMITATIONS = (
    "No clean-source provenance or independent deterministic consumer is provided.",
    "This output cannot satisfy G7 and cannot be promoted to model evidence.",
)


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _identity(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def smoke_report(report: dict[str, int]) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()
    body: dict[str, Any] = {
        **report,
        "schema": SMOKE_SCHEMA,
        "execution_classification": SMOKE_CLASSIFICATION,
        "evidence_eligible": False,
        "g7_status": G7_STATUS,
        "limitations": list(LIMITATIONS),
        "generated_at_utc": timestamp,
        "host_metadata": {
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
    }
    return {**body, "smoke_id": _identity(body)}


def write_smoke(path: pathlib.Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transitions", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=20_260_805)
    parser.add_argument("--output", type=pathlib.Path)
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    report = smoke_report(run_randomized(args.transitions, args.seed))
    if args.output is not None:
        try:
            write_smoke(args.output, report)
        except FileExistsError:
            raise SystemExit(
                f"refusing to overwrite existing smoke output: {args.output}"
            ) from None
    print(format_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
