"""Control-room payload and durable state readers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fusekit.runner.gates import GateRecord
from fusekit.runner.job import JobState
from fusekit.runner.run_state import LaunchRunState


def control_room_payload(job: JobState, *, gate_path: Path | None = None) -> dict[str, Any]:
    """Build the embedded control-room payload with durable launch state."""

    payload = job.to_dict()
    payload["verification"] = _read_verification_report(_verification_report_path(job, gate_path))
    payload["run_state"] = _read_run_state(_run_state_path(job, gate_path))
    payload["visual"] = _read_visual_state(_visual_state_path(job, gate_path))
    if gate_path is None:
        payload.setdefault("gates", [])
        return payload
    gates, error = _read_gate_records(gate_path)
    payload["gates"] = gates
    if error:
        payload["gate_state_error"] = error
    return payload


def _read_gate_records(
    gate_path: Path,
) -> tuple[list[dict[str, str | int | float | list[str]]], str]:
    if not gate_path.exists():
        return [], ""
    try:
        raw = json.loads(gate_path.read_text(encoding="utf-8"))
        records = [
            GateRecord.from_dict(item).to_dict()
            for item in raw.get("gates", [])
            if isinstance(item, dict)
        ]
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return [], f"Gate state could not be read from {gate_path.name}: {type(exc).__name__}"
    return records, ""


def _verification_report_path(job: JobState, gate_path: Path | None) -> Path | None:
    artifact = job.artifacts.get("verification_report", "")
    if artifact:
        return Path(artifact)
    if gate_path is not None:
        return gate_path.parent / "verification_report.json"
    return None


def _read_verification_report(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "overall": "failed",
            "checks": [],
            "error": f"Verification report could not be read from {path.name}",
        }
    if not isinstance(raw, dict):
        return {
            "overall": "failed",
            "checks": [],
            "error": f"Verification report from {path.name} was not a JSON object",
        }
    return raw


def _run_state_path(job: JobState, gate_path: Path | None) -> Path | None:
    artifact = job.artifacts.get("run_state", "")
    if artifact:
        return Path(artifact)
    if gate_path is not None:
        return gate_path.parent / "run_state.json"
    return None


def _read_run_state(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return LaunchRunState().to_dict()
    try:
        return LaunchRunState.load(path).to_dict()
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        state = LaunchRunState()
        state.notes = ("Run state could not be read; FuseKit will rebuild it from checkpoints.",)
        return state.to_dict()


def _visual_state_path(job: JobState, gate_path: Path | None) -> Path | None:
    artifact = job.artifacts.get("visual_session", "")
    if artifact:
        return Path(artifact)
    if gate_path is not None:
        return gate_path.parent / "visual.json"
    return None


def _read_visual_state(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "unavailable", "error": "Visual session state could not be read."}
    if not isinstance(raw, dict):
        return {"status": "unavailable", "error": "Visual session state was not a JSON object."}
    return raw
