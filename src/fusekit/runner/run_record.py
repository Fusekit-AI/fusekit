"""Central non-secret run record for launch, resume, and audit surfaces."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fusekit.runner.gates import GateRecord
from fusekit.runner.job import JobState
from fusekit.runner.run_state import LaunchRunState

RUN_RECORD_SCHEMA_VERSION = "fusekit.run-record.v1"


def build_run_record(
    job: JobState,
    *,
    root: Path,
    vault_index: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a single non-secret record that ties together launch state."""

    gates = _read_gates(root / "gates.json")
    verification = _read_json_object(root / "verification_report.json")
    acceptance = _read_json_object(root / "acceptance" / "report.json")
    workspace_detonation = _read_json_object(root / "workspace_detonation.json")
    provider_strategies = _read_json_object(root / "provider_strategies.json")
    run_state = _read_run_state(root / "run_state.json")
    artifacts = _artifact_records(job, root)
    return {
        "schema_version": RUN_RECORD_SCHEMA_VERSION,
        "id": job.id,
        "status": job.status,
        "app_path": job.app_path,
        "runner": job.runner,
        "created_at": job.created_at,
        "updated_at": time.time(),
        "state": run_state,
        "steps": [step.to_dict() for step in job.steps],
        "checkpoints": [checkpoint.to_dict() for checkpoint in job.checkpoints],
        "provider_gates": _gate_summary(gates),
        "provider_strategies": provider_strategies or {"providers": []},
        "vault": {
            "records": vault_index or [],
            "record_count": len(vault_index or []),
        },
        "artifacts": artifacts,
        "verification": verification,
        "acceptance": _acceptance_summary(acceptance),
        "detonation": _detonation_summary(run_state, workspace_detonation),
        "approvals": _approval_summary(gates),
        "errors": _error_summary(job, gates, verification, acceptance, workspace_detonation),
    }


def write_run_record(
    job: JobState,
    *,
    path: Path,
    vault_index: list[dict[str, Any]] | None = None,
) -> Path:
    """Write the central non-secret run record."""

    path.parent.mkdir(parents=True, exist_ok=True)
    record = build_run_record(job, root=path.parent, vault_index=vault_index)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", "utf-8")
    return path


def _read_run_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return LaunchRunState().to_dict()
    try:
        return LaunchRunState.load(path).to_dict()
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        state = LaunchRunState()
        state.notes = ("Run state could not be read; FuseKit will rebuild it.",)
        return state.to_dict()


def _read_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"error": f"{path.name} could not be read"}
    if not isinstance(raw, dict):
        return {"error": f"{path.name} was not a JSON object"}
    return raw


def _read_gates(path: Path) -> list[dict[str, Any]]:
    raw = _read_json_object(path)
    gates = raw.get("gates", [])
    records: list[dict[str, Any]] = []
    if not isinstance(gates, list):
        return records
    for item in gates:
        if not isinstance(item, dict):
            continue
        try:
            records.append(GateRecord.from_dict(item).to_dict())
        except (KeyError, TypeError, ValueError):
            records.append({"id": str(item.get("id", "unknown")), "status": "invalid"})
    return records


def _gate_summary(gates: list[dict[str, Any]]) -> dict[str, Any]:
    statuses: dict[str, int] = {}
    providers: set[str] = set()
    for gate in gates:
        status = str(gate.get("status", "unknown") or "unknown")
        statuses[status] = statuses.get(status, 0) + 1
        provider = str(gate.get("provider", "") or "").strip()
        if provider:
            providers.add(provider)
    return {
        "total": len(gates),
        "statuses": statuses,
        "providers": sorted(providers),
        "records": gates,
    }


def _artifact_records(job: JobState, root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for name, value in sorted(job.artifacts.items()):
        path = Path(value)
        records.append(
            {
                "name": name,
                "path": str(path),
                "exists": path.exists(),
            }
        )
    for name in (
        "job",
        "checkpoints",
        "run_state",
        "gates",
        "workspace_detonation",
        "run_record",
    ):
        path = root / f"{name}.json"
        if any(record["name"] == name for record in records):
            continue
        if path.exists():
            records.append({"name": name, "path": str(path), "exists": True})
    return records


def _acceptance_summary(acceptance: dict[str, Any]) -> dict[str, Any]:
    if not acceptance:
        return {}
    return {
        "launch_ready": acceptance.get("launch_ready") is True,
        "public_launch_ready": acceptance.get("public_launch_ready") is True,
        "recording_ready": acceptance.get("recording_ready") is True,
        "blockers": acceptance.get("blockers", [])
        if isinstance(acceptance.get("blockers", []), list)
        else [],
        "error": acceptance.get("error", ""),
    }


def _detonation_summary(
    run_state: dict[str, Any],
    workspace_detonation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "preflight_safe": run_state.get("detonation_safe") is True,
        "workspace_detonated": run_state.get("workspace_detonated") is True,
        "workspace_receipt": workspace_detonation,
    }


def _approval_summary(gates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    approvals: list[dict[str, Any]] = []
    for gate in gates:
        status = str(gate.get("status", "") or "")
        if status not in {"resume_requested", "resolved"}:
            continue
        approvals.append(
            {
                "id": str(gate.get("id", "")),
                "provider": str(gate.get("provider", "")),
                "status": status,
                "reason": str(gate.get("reason", "")),
                "updated_at": gate.get("updated_at", 0),
            }
        )
    return approvals


def _error_summary(
    job: JobState,
    gates: list[dict[str, Any]],
    verification: dict[str, Any],
    acceptance: dict[str, Any],
    workspace_detonation: dict[str, Any],
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    for step in job.steps:
        if step.status == "failed":
            errors.append({"source": "step", "id": step.id, "detail": step.detail})
    for gate in gates:
        if str(gate.get("status", "")) in {"failed", "invalid"}:
            errors.append(
                {
                    "source": "gate",
                    "id": str(gate.get("id", "unknown")),
                    "detail": str(gate.get("reason", "")),
                }
            )
    for source, payload in (
        ("verification", verification),
        ("acceptance", acceptance),
        ("workspace_detonation", workspace_detonation),
    ):
        error = str(payload.get("error", "") or "")
        if error:
            errors.append({"source": source, "id": source, "detail": error})
    failures = workspace_detonation.get("failures", {})
    if isinstance(failures, dict):
        for key, value in sorted(failures.items()):
            errors.append(
                {
                    "source": "workspace_detonation",
                    "id": str(key),
                    "detail": str(value),
                }
            )
    return errors
