"""Control-room payload and durable state readers."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fusekit.runner.control_room.redaction import redact_gate_target
from fusekit.runner.gates import GateRecord
from fusekit.runner.job import JobState
from fusekit.runner.run_state import LaunchRunState

SAFE_URL_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,256}$")


def control_room_payload(job: JobState, *, gate_path: Path | None = None) -> dict[str, Any]:
    """Build the embedded control-room payload with durable launch state."""

    payload = job.to_dict()
    payload["verification"] = _read_verification_report(_verification_report_path(job, gate_path))
    payload["run_state"] = _read_run_state(_run_state_path(job, gate_path))
    payload["visual"] = _read_visual_state(_visual_state_path(job, gate_path))
    payload["provider_strategies"] = _read_provider_strategies(
        _provider_strategies_path(job, gate_path)
    )
    payload["acceptance"] = _read_acceptance_report(_acceptance_report_path(job, gate_path))
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
            _redacted_gate_record(GateRecord.from_dict(item).to_dict())
            for item in raw.get("gates", [])
            if isinstance(item, dict)
        ]
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        return [], f"Gate state could not be read from {gate_path.name}: {type(exc).__name__}"
    return records, ""


def _redacted_gate_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a gate record safe for browser/control-room display."""

    target = record.get("target", "")
    if isinstance(target, str):
        record = {**record, "target": redact_gate_target(target)}
    return record


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
    return _sanitized_visual_state(raw)


def _sanitized_visual_state(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a visual-session payload safe to embed with clipboard permissions."""

    visual = dict(raw)
    novnc_url = str(visual.get("novnc_url", "") or "").strip()
    if not novnc_url:
        return visual
    safe_novnc_url, novnc_host = _safe_visual_url(
        novnc_url,
        require_vnc_path=True,
        allowed_query_keys={"autoconnect", "resize"},
    )
    if not safe_novnc_url:
        return _unavailable_visual("Visual session noVNC URL was not safe to embed.")
    visual["novnc_url"] = safe_novnc_url
    control_room_url = str(visual.get("control_room_url", "") or "").strip()
    if control_room_url:
        safe_control_url, control_host = _safe_visual_url(
            control_room_url,
            require_vnc_path=False,
            allowed_query_keys={"token"},
        )
        if not safe_control_url or control_host != novnc_host:
            visual.pop("control_room_url", None)
        else:
            visual["control_room_url"] = safe_control_url
    password = str(visual.get("novnc_password", "") or "")
    if not _safe_visual_password(password):
        visual.pop("novnc_password", None)
    return visual


def _safe_visual_url(
    value: str,
    *,
    require_vnc_path: bool,
    allowed_query_keys: set[str],
) -> tuple[str, str]:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return "", ""
    if parsed.username or parsed.password or not parsed.hostname:
        return "", ""
    if require_vnc_path and not parsed.path.endswith("/vnc.html"):
        return "", ""
    query_pairs: list[tuple[str, str]] = []
    for key, item in parse_qsl(parsed.query, keep_blank_values=False):
        if key not in allowed_query_keys:
            continue
        if key == "token" and not SAFE_URL_TOKEN_PATTERN.fullmatch(item):
            return "", ""
        query_pairs.append((key, item))
    query = urlencode(query_pairs)
    safe_url = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", query, "")
    )
    return safe_url, parsed.hostname.lower().strip("[]")


def _safe_visual_password(value: str) -> bool:
    if not value:
        return True
    if len(value) > 256:
        return False
    return not any(ord(char) < 32 or ord(char) == 127 for char in value)


def _unavailable_visual(error: str) -> dict[str, Any]:
    return {
        "status": "unavailable",
        "error": error,
    }


def _provider_strategies_path(job: JobState, gate_path: Path | None) -> Path | None:
    artifact = job.artifacts.get("provider_strategies", "")
    if artifact:
        return Path(artifact)
    if gate_path is not None:
        return gate_path.parent / "provider_strategies.json"
    return None


def _acceptance_report_path(job: JobState, gate_path: Path | None) -> Path | None:
    artifact = job.artifacts.get("acceptance_report", "")
    if artifact:
        return Path(artifact)
    if gate_path is not None:
        return gate_path.parent / "acceptance" / "report.json"
    return None


def _read_acceptance_report(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "launch_ready": False,
            "blockers": [],
            "error": f"Acceptance report could not be read from {path.name}",
        }
    if not isinstance(raw, dict):
        return {
            "launch_ready": False,
            "blockers": [],
            "error": f"Acceptance report from {path.name} was not a JSON object",
        }
    blockers = raw.get("blockers", [])
    if not isinstance(blockers, list):
        raw["blockers"] = []
    return raw


def _read_provider_strategies(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {"providers": []}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "providers": [],
            "error": f"Provider strategy state could not be read from {path.name}",
        }
    if not isinstance(raw, dict):
        return {
            "providers": [],
            "error": f"Provider strategy state from {path.name} was not a JSON object",
        }
    providers = raw.get("providers", [])
    if not isinstance(providers, list):
        raw["providers"] = []
    return raw
