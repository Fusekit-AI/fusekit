"""Control-room payload and durable state readers."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fusekit.runner.control_room.redaction import redact_gate_target
from fusekit.runner.control_room.surfaces import public_control_room_security_surface
from fusekit.runner.gates import GateRecord
from fusekit.runner.job import JobState
from fusekit.runner.readiness import EXPECTED_PROVIDER_BROWSER_PROFILE
from fusekit.runner.recording_contract import (
    RECORDING_CONTRACT_CHECK_KEYS,
    RECORDING_CONTRACT_SCHEMA_VERSION,
)
from fusekit.runner.run_state import LaunchRunState
from fusekit.security import contains_durable_secret_text, redact_public_path, redact_public_text

SAFE_URL_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
EXPECTED_NOVNC_PORT = 6080
EXPECTED_CONTROL_ROOM_PORT = 8765
SAFE_NOVNC_QUERY_VALUES = {
    "autoconnect": {"1"},
    "resize": {"scale"},
}


def control_room_payload(job: JobState, *, gate_path: Path | None = None) -> dict[str, Any]:
    """Build the embedded control-room payload with durable launch state."""

    raw_job_payload = job.to_dict()
    payload = _redacted_public_value(raw_job_payload)
    payload = payload if isinstance(payload, dict) else raw_job_payload
    payload["verification"] = _read_verification_report(_verification_report_path(job, gate_path))
    payload["run_state"] = _read_run_state(_run_state_path(job, gate_path))
    run_record = _read_run_record(_run_record_path(job, gate_path))
    payload["run_record"] = run_record
    payload["llm_contract"] = _read_llm_contract(_llm_contract_path(job, gate_path))
    payload["visual"] = _read_visual_state(_visual_state_path(job, gate_path))
    payload["provider_strategies"] = _read_provider_strategies(
        _provider_strategies_path(job, gate_path)
    )
    payload["acceptance"] = _read_acceptance_report(_acceptance_report_path(job, gate_path))
    run_record_security = (
        run_record.get("control_room_security", {}) if isinstance(run_record, dict) else {}
    )
    payload["security_surface"] = (
        run_record_security
        if isinstance(run_record_security, dict) and run_record_security
        else public_control_room_security_surface()
    )
    if gate_path is None:
        payload.setdefault("gates", [])
        return payload
    gates, error = _read_gate_records(gate_path)
    payload["gates"] = gates
    if error:
        payload["gate_state_error"] = error
    return payload


def redacted_public_payload(value: Any) -> Any:
    """Return a value safe for browser-visible control-room payloads."""

    return _redacted_public_value(value)


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

    redacted = _redacted_public_value(record)
    record = redacted if isinstance(redacted, dict) else record
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
    redacted = _redacted_public_value(raw)
    return redacted if isinstance(redacted, dict) else {"overall": "failed", "checks": []}


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
        payload = LaunchRunState.load(path).to_dict()
        redacted = _redacted_public_value(payload)
        return redacted if isinstance(redacted, dict) else payload
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        fallback = LaunchRunState()
        fallback.notes = (
            "Run state could not be read; FuseKit will rebuild it from checkpoints.",
        )
        return fallback.to_dict()


def _run_record_path(job: JobState, gate_path: Path | None) -> Path | None:
    artifact = job.artifacts.get("run_record", "")
    if artifact:
        return Path(artifact)
    if gate_path is not None:
        return gate_path.parent / "run_record.json"
    return None


def _read_run_record(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"error": f"Run record could not be read from {path.name}"}
    if not isinstance(raw, dict):
        return {"error": f"Run record from {path.name} was not a JSON object"}
    if raw.get("schema_version") != "fusekit.run-record.v1":
        return {"error": f"Run record from {path.name} has an unsupported schema"}
    redacted = _redacted_public_value(raw)
    return redacted if isinstance(redacted, dict) else {}


PUBLIC_TEXT_KEYS = {
    "body",
    "blocker",
    "blockers",
    "detail",
    "details",
    "description",
    "error",
    "errors",
    "failure",
    "failures",
    "avoid_steps",
    "follow_steps",
    "instruction",
    "last_opened_url",
    "message",
    "next_action",
    "note",
    "notes",
    "proof",
    "reason",
    "repair",
    "resume_hint",
    "resume_url",
    "statement",
    "success_criteria",
    "summary",
}
PUBLIC_PATH_KEYS = {
    "app_path",
    "artifact",
    "directory",
    "dir",
    "file",
    "ledger_path",
    "path",
    "report_path",
    "root",
}
PUBLIC_PATH_KEY_PATTERNS = (
    re.compile(r".*_(?:path|file|dir|directory|root)$"),
)
PUBLIC_STRUCTURAL_KEY_PATTERNS = (
    re.compile(r"^(?:last_)?wake_event_id$"),
    re.compile(r"^(?:capture|resume)_wake_event_id$"),
)


def _redacted_public_value(value: Any, *, key: str = "") -> Any:
    if isinstance(value, dict):
        if key == "artifacts":
            return {
                _redacted_public_key(raw_key): _redacted_artifact_path(item)
                for raw_key, item in value.items()
            }
        return {
            _redacted_public_key(raw_key): _redacted_public_value(
                item,
                key=str(raw_key),
            )
            for raw_key, item in value.items()
        }
    if isinstance(value, list):
        return [_redacted_public_value(item, key=key) for item in value]
    if isinstance(value, str):
        redacted = (
            redact_public_text(value)
            if key in PUBLIC_TEXT_KEYS or contains_durable_secret_text(value)
            else value
        )
        return redact_public_path(redacted) if _is_public_path_key(key) else redacted
    if isinstance(value, bool | int | float) or value is None:
        return value
    return redact_public_text(value)


def _redacted_public_key(value: Any) -> str:
    key = str(value)
    if any(pattern.fullmatch(key) for pattern in PUBLIC_STRUCTURAL_KEY_PATTERNS):
        return key
    redacted = redact_public_text(key)
    return redacted if "[redacted]" in redacted else key


def _is_public_path_key(key: str) -> bool:
    return key in PUBLIC_PATH_KEYS or any(
        pattern.fullmatch(key) for pattern in PUBLIC_PATH_KEY_PATTERNS
    )


def _redacted_artifact_path(value: Any) -> str:
    redacted = redact_public_text(value)
    return redact_public_path(redacted)


def _llm_contract_path(job: JobState, gate_path: Path | None) -> Path | None:
    artifact = job.artifacts.get("llm_contract", "")
    if artifact:
        return Path(artifact)
    if gate_path is not None:
        return gate_path.parent / "llm_contract.json"
    return None


def _read_llm_contract(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"error": f"Model/inference contract could not be read from {path.name}"}
    if not isinstance(raw, dict):
        return {"error": f"Model/inference contract from {path.name} was not a JSON object"}
    if raw.get("schema_version") != "fusekit.llm-contract.v1":
        return {"error": f"Model/inference contract from {path.name} has an unsupported schema"}
    redacted = _redacted_public_value(raw)
    return redacted if isinstance(redacted, dict) else {}


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
        visual.pop("control_room_url", None)
        visual.pop("novnc_password", None)
        redacted = _redacted_public_value(visual)
        return redacted if isinstance(redacted, dict) else {}
    safe_novnc_url, novnc_host = _safe_visual_url(
        novnc_url,
        require_vnc_path=True,
        allowed_query_keys={"autoconnect", "resize"},
        expected_port=EXPECTED_NOVNC_PORT,
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
            expected_port=EXPECTED_CONTROL_ROOM_PORT,
        )
        if not safe_control_url or control_host != novnc_host:
            visual.pop("control_room_url", None)
        else:
            visual["control_room_url"] = safe_control_url
    password = str(visual.get("novnc_password", "") or "")
    if not _safe_visual_password(password):
        visual.pop("novnc_password", None)
    profile = str(visual.get("provider_browser_profile", "") or "").strip()
    if profile and profile != EXPECTED_PROVIDER_BROWSER_PROFILE:
        visual.pop("provider_browser_profile", None)
        profile = ""
    redacted = _redacted_public_value(visual)
    if not isinstance(redacted, dict):
        return {}
    redacted["novnc_url"] = safe_novnc_url
    if "control_room_url" in visual:
        redacted["control_room_url"] = str(visual["control_room_url"])
    if "novnc_password" in visual:
        redacted["novnc_password"] = password
    if profile:
        redacted["provider_browser_profile"] = profile
    return redacted


def _safe_visual_url(
    value: str,
    *,
    require_vnc_path: bool,
    allowed_query_keys: set[str],
    expected_port: int,
) -> tuple[str, str]:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return "", ""
    if parsed.username or parsed.password or not parsed.hostname:
        return "", ""
    try:
        port = parsed.port
    except ValueError:
        return "", ""
    if port != expected_port:
        return "", ""
    if not _safe_visual_host(parsed.hostname):
        return "", ""
    if require_vnc_path and not parsed.path.endswith("/vnc.html"):
        return "", ""
    query_pairs: list[tuple[str, str]] = []
    for key, item in parse_qsl(parsed.query, keep_blank_values=False):
        if key not in allowed_query_keys:
            continue
        if key == "token" and not SAFE_URL_TOKEN_PATTERN.fullmatch(item):
            return "", ""
        if require_vnc_path and item not in SAFE_NOVNC_QUERY_VALUES.get(key, set()):
            return "", ""
        query_pairs.append((key, item))
    query = urlencode(query_pairs)
    safe_url = urlunparse(
        (parsed.scheme, parsed.netloc, parsed.path or "/", "", query, "")
    )
    return safe_url, parsed.hostname.lower().strip("[]")


def _safe_visual_host(hostname: str) -> bool:
    """Allow only public IP VM hosts for embeddable visual sessions."""

    try:
        address = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return False
    return address.is_global


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
            "public_launch_ready": False,
            "recording_ready": False,
            "blockers": [],
            "error": f"Acceptance report could not be read from {path.name}",
        }
    if not isinstance(raw, dict):
        return {
            "launch_ready": False,
            "public_launch_ready": False,
            "recording_ready": False,
            "blockers": [],
            "error": f"Acceptance report from {path.name} was not a JSON object",
        }
    mode = str(raw.get("mode", "") or "").strip().lower()
    launch_ready = raw.get("launch_ready") is True
    raw_contract = raw.get("recording_contract", {})
    contract_recording_ready = _acceptance_recording_contract_ready(raw_contract)
    checks = _redacted_acceptance_checks(raw.get("checks", []))
    missing = _redacted_acceptance_string_list(raw.get("missing", []))
    blockers = _redacted_acceptance_blockers(raw.get("blockers", []))
    error = redact_public_text(raw.get("error", "")) if "error" in raw else ""
    has_unresolved_evidence = bool(missing) or bool(blockers) or bool(error.strip())
    launch_ready = launch_ready and not has_unresolved_evidence
    public_ready = (
        raw.get("public_launch_ready") is True and launch_ready and mode == "live"
    )
    remote_artifacts_ready = _acceptance_remote_artifacts_ready(checks)
    recording_proof_ready = (
        raw.get("recording_proof_ready") is True
        and contract_recording_ready
        and remote_artifacts_ready
    )
    recording_ready = raw.get("recording_ready") is True and public_ready and recording_proof_ready
    report: dict[str, Any] = {
        "mode": redact_public_text(mode),
        "launch_ready": launch_ready,
        "public_launch_ready": public_ready,
        "remote_artifacts_ready": remote_artifacts_ready,
        "recording_ready": recording_ready,
        "recording_proof_ready": recording_proof_ready,
        "missing": missing,
        "blockers": blockers,
        "checks": checks,
    }
    for key in ("app_path", "ledger_path", "report_path"):
        if key in raw:
            report[key] = redact_public_path(redact_public_text(raw.get(key, "")))
    if "error" in raw:
        report["error"] = error
    contract = _redacted_acceptance_recording_contract(
        raw_contract,
        recording_ready=recording_ready,
    )
    if contract:
        report["recording_contract"] = contract
    return report


def _redacted_acceptance_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [redact_public_text(item) for item in value if str(item or "").strip()]


def _redacted_acceptance_blockers(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    blockers: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        blockers.append(
            {
                "category": redact_public_text(item.get("category", "")),
                "item": redact_public_text(item.get("item", "")),
                "next_action": redact_public_text(item.get("next_action", "")),
                "detail": redact_public_text(item.get("detail", "")),
            }
        )
    return blockers


def _redacted_acceptance_checks(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    checks: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        checks.append(
            {
                "id": redact_public_text(item.get("id", "")),
                "status": redact_public_text(item.get("status", "")),
                "detail": redact_public_text(item.get("detail", "")),
                "artifact": redact_public_path(redact_public_text(item.get("artifact", ""))),
            }
        )
    return checks


def _acceptance_remote_artifacts_ready(checks: list[dict[str, str]]) -> bool:
    return any(
        check.get("id") == "remote_artifacts.loaded" and check.get("status") == "ok"
        for check in checks
    )


def _redacted_acceptance_recording_contract(
    value: Any,
    *,
    recording_ready: bool,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    raw_checks = value.get("checks", {})
    checks = (
        {
            key: item is True
            for key, item in sorted(
                (str(raw_key), raw_item)
                for raw_key, raw_item in raw_checks.items()
                if isinstance(raw_key, str)
            )
        }
        if isinstance(raw_checks, dict)
        else {}
    )
    raw_blockers = value.get("blockers", [])
    blockers = (
        [redact_public_text(item) for item in raw_blockers]
        if isinstance(raw_blockers, list)
        else []
    )
    return {
        "schema_version": redact_public_text(value.get("schema_version", "")),
        "recording_ready": value.get("recording_ready") is True and recording_ready,
        "checks": checks,
        "blockers": blockers,
        "check_count": len(checks),
        "statement": redact_public_text(value.get("statement", "")),
    }


def _acceptance_recording_contract_ready(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("schema_version") != RECORDING_CONTRACT_SCHEMA_VERSION:
        return False
    if value.get("recording_ready") is not True:
        return False
    checks = value.get("checks", {})
    if not isinstance(checks, dict) or not checks:
        return False
    if set(checks) != frozenset(RECORDING_CONTRACT_CHECK_KEYS):
        return False
    if any(item is not True for item in checks.values()):
        return False
    blockers = value.get("blockers", [])
    return isinstance(blockers, list) and not blockers


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
    redacted = _redacted_public_value(raw)
    return redacted if isinstance(redacted, dict) else {"providers": []}
