"""Worker replacement drill proof for disposable OCI runners."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fusekit.security import contains_durable_secret_text

WORKER_REPLACEMENT_DRILL_SCHEMA_VERSION = "fusekit.worker-replacement-drill.v1"
WORKER_REPLACEMENT_SOURCE_IDS = (
    "encrypted_vault",
    "job_state",
    "run_state",
    "checkpoints",
    "gates",
    "gate_events",
    "provider_strategies",
    "runner_readiness",
)
WORKER_REPLACEMENT_DRILL_STATEMENT = (
    "FuseKit recreated the disposable worker from encrypted/redacted survivor "
    "state with no host-machine state and no VM-local plaintext."
)


def build_worker_replacement_drill(
    *,
    status: str = "pending",
    worker_destroyed: bool = False,
    replacement_runner_profile_ready: bool = False,
    control_room_reopened: bool = False,
    resume_checkpoint_restored: bool = False,
    gate_or_verifier_resumed: bool = False,
    host_machine_state_required: bool = False,
    volatile_state_reused: bool = False,
    restored_from: list[str] | None = None,
    statement: str = WORKER_REPLACEMENT_DRILL_STATEMENT,
    pending_reason: str | None = None,
) -> dict[str, object]:
    """Build the redacted proof object for the kill/recreate drill."""

    payload: dict[str, object] = {
        "schema_version": WORKER_REPLACEMENT_DRILL_SCHEMA_VERSION,
        "status": status,
        "worker_destroyed": worker_destroyed,
        "replacement_runner_profile_ready": replacement_runner_profile_ready,
        "control_room_reopened": control_room_reopened,
        "resume_checkpoint_restored": resume_checkpoint_restored,
        "gate_or_verifier_resumed": gate_or_verifier_resumed,
        "host_machine_state_required": host_machine_state_required,
        "volatile_state_reused": volatile_state_reused,
        "restored_from": restored_from or list(WORKER_REPLACEMENT_SOURCE_IDS),
        "statement": statement,
    }
    if pending_reason:
        payload["pending_reason"] = pending_reason
    return payload


def build_passed_worker_replacement_drill() -> dict[str, object]:
    """Return the passed drill proof shape used by live replacement rehearsals."""

    return build_worker_replacement_drill(
        status="passed",
        worker_destroyed=True,
        replacement_runner_profile_ready=True,
        control_room_reopened=True,
        resume_checkpoint_restored=True,
        gate_or_verifier_resumed=True,
    )


def ensure_pending_worker_replacement_drill(path: Path) -> Path:
    """Ensure a truthful non-passing drill artifact exists for resume/detonation UX."""

    if path.is_file():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = None
        if isinstance(raw, dict) and str(raw.get("status", "") or "") == "passed":
            return path
    write_worker_replacement_drill(
        path,
        build_worker_replacement_drill(
            pending_reason=(
                "A live worker replacement drill has not passed yet, so FuseKit "
                "must not mark OCI detonation or recording readiness green."
            )
        ),
    )
    return path


def write_worker_replacement_drill(path: Path, payload: dict[str, object]) -> Path:
    """Write worker replacement proof with private artifact permissions."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def worker_replacement_drill_failures(payload: dict[str, Any]) -> list[str]:
    """Return validation failures for a passed replacement-drill proof."""

    failures: list[str] = []
    if not payload:
        return ["worker replacement drill could not be read"]
    if str(payload.get("schema_version", "") or "") != WORKER_REPLACEMENT_DRILL_SCHEMA_VERSION:
        failures.append("worker replacement drill has unsupported schema")
    if str(payload.get("status", "") or "") != "passed":
        failures.append("worker replacement drill did not pass")
    for key in (
        "worker_destroyed",
        "replacement_runner_profile_ready",
        "control_room_reopened",
        "resume_checkpoint_restored",
        "gate_or_verifier_resumed",
    ):
        if payload.get(key) is not True:
            failures.append(f"worker replacement drill missing {key}")
    if payload.get("host_machine_state_required") is not False:
        failures.append("worker replacement drill requires host-machine state")
    if payload.get("volatile_state_reused") is not False:
        failures.append("worker replacement drill reused volatile state")
    restored_from = payload.get("restored_from", [])
    restored = {str(item) for item in restored_from} if isinstance(restored_from, list) else set()
    if not set(WORKER_REPLACEMENT_SOURCE_IDS).issubset(restored):
        failures.append("worker replacement drill restore sources are incomplete")
    for path, value in _walk_json_strings(payload, path="worker replacement drill"):
        if contains_durable_secret_text(value):
            failures.append(f"{path} contains credential-looking text")
            break
    return failures


def _walk_json_strings(value: object, *, path: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        items: list[tuple[str, str]] = []
        for key, child in value.items():
            items.extend(_walk_json_strings(child, path=f"{path}.{key}"))
        return items
    if isinstance(value, list):
        items = []
        for index, child in enumerate(value):
            items.extend(_walk_json_strings(child, path=f"{path}[{index}]"))
        return items
    return []
