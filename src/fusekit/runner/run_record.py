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
    runner_readiness = _read_json_object(root / "runner_readiness.json")
    wake_events = _read_gate_wake_events(root / "gate_events.jsonl")
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
        "runner_profile": _runner_profile_summary(runner_readiness),
        "wake_events": _wake_event_summary(wake_events),
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


def _read_gate_wake_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [
            {
                "schema_version": "fusekit.gate-wake.v1",
                "event": "unreadable",
                "gate_id": "unknown",
                "provider": "",
                "status": "invalid",
                "target": "",
                "created_at": 0,
            }
        ]
    for line in lines:
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            events.append(
                {
                    "schema_version": "fusekit.gate-wake.v1",
                    "event": "invalid",
                    "gate_id": "unknown",
                    "provider": "",
                    "status": "invalid",
                    "target": "",
                    "created_at": 0,
                }
            )
            continue
        if isinstance(raw, dict):
            events.append(_redacted_wake_event(raw))
    return events


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


def _wake_event_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for event in events:
        name = str(event.get("event", "unknown") or "unknown")
        counts[name] = counts.get(name, 0) + 1
    return {
        "total": len(events),
        "event_counts": counts,
        "events": events[-50:],
    }


def _redacted_wake_event(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": str(raw.get("schema_version", "fusekit.gate-wake.v1")),
        "id": str(raw.get("id", "")),
        "event": str(raw.get("event", "unknown") or "unknown"),
        "gate_id": str(raw.get("gate_id", "unknown") or "unknown"),
        "provider": str(raw.get("provider", "") or ""),
        "classification": str(raw.get("classification", "") or ""),
        "status": str(raw.get("status", "unknown") or "unknown"),
        "target": str(raw.get("target", "") or ""),
        "target_count": _safe_int(raw.get("target_count"), 0),
        "captured_targets": _safe_string_list(raw.get("captured_targets", [])),
        "created_at": _safe_float(raw.get("created_at"), 0),
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
        "gate_events",
        "runner_readiness",
        "workspace_detonation",
        "run_record",
    ):
        suffix = "jsonl" if name == "gate_events" else "json"
        path = root / f"{name}.{suffix}"
        if any(record["name"] == name for record in records):
            continue
        if path.exists():
            records.append({"name": name, "path": str(path), "exists": True})
    return records


def _runner_profile_summary(runner_readiness: dict[str, Any]) -> dict[str, Any]:
    if not runner_readiness:
        return {}
    profile = runner_readiness.get("profile_contract", {})
    observed = runner_readiness.get("observed", {})
    checks = runner_readiness.get("checks", {})
    return {
        "status": str(runner_readiness.get("status", "")),
        "architecture": str(runner_readiness.get("architecture", "")),
        "profile_contract": profile if isinstance(profile, dict) else {},
        "observed": observed if isinstance(observed, dict) else {},
        "checks": checks if isinstance(checks, dict) else {},
        "provider_browser_profile": str(runner_readiness.get("provider_browser_profile", "")),
        "playwright_browsers_path": str(runner_readiness.get("playwright_browsers_path", "")),
    }


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


def _safe_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _safe_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _safe_float(value: object, default: float) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default
