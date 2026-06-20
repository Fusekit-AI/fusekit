"""Central non-secret run record for launch, resume, and audit surfaces."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from fusekit.llm.contract import (
    LLM_CONTRACT_KEYS,
    LLM_CONTRACT_LANE_KEYS,
    LLM_CONTRACT_SECURITY_KEYS,
    MODEL_INFERENCE_KEYS,
)
from fusekit.runner import worker_replacement as worker_replacement_contract
from fusekit.runner.acceptance_summary import (
    ACCEPTANCE_BLOCKER_REQUIRED_FIELDS,
    RUN_RECORD_ERROR_FIELDS,
)
from fusekit.runner.approval_summary import (
    APPROVAL_SUMMARY_ID_FIELD,
    APPROVAL_SUMMARY_PROVIDER_FIELD,
    APPROVAL_SUMMARY_READY_STATUSES,
    APPROVAL_SUMMARY_REASON_FIELD,
    APPROVAL_SUMMARY_STATUS_FIELD,
    APPROVAL_SUMMARY_UPDATED_AT_FIELD,
)
from fusekit.runner.audit_trail import (
    AUDIT_TRAIL_CATEGORIES,
    AUDIT_TRAIL_ENTRY_KEYS,
    AUDIT_TRAIL_KEYS,
    AUDIT_TRAIL_SCHEMA_VERSION,
)
from fusekit.runner.automation_boundary import (
    AUTOMATION_BOUNDARY_COUNTS_KEYS,
    AUTOMATION_BOUNDARY_DETONATION_SCOPE,
    AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS,
    AUTOMATION_BOUNDARY_HUMAN_GATE_ROUTE_KINDS,
    AUTOMATION_BOUNDARY_KEYS,
    AUTOMATION_BOUNDARY_POST_GATE_KEYS,
    AUTOMATION_BOUNDARY_READY_STATUS,
    AUTOMATION_BOUNDARY_REPAIR_STATUS,
    AUTOMATION_BOUNDARY_REQUIRED_VNC_ALLOWLIST,
    AUTOMATION_BOUNDARY_ROUTE_KEYS,
    AUTOMATION_BOUNDARY_ROUTE_OWNERS,
    AUTOMATION_BOUNDARY_SCHEMA_VERSION,
    AUTOMATION_BOUNDARY_STATEMENT_TERMS,
)
from fusekit.runner.control_room.surfaces import public_control_room_security_surface
from fusekit.runner.control_room_security import (
    CONTROL_ROOM_PROTECTED_MUTATION_ROUTES,
    CONTROL_ROOM_REQUIRED_POST_PROTECTION_TERMS,
    CONTROL_ROOM_SECURITY_KEYS,
    CONTROL_ROOM_SECURITY_ROUTE_KEYS,
    CONTROL_ROOM_SECURITY_SCHEMA_VERSION,
    CONTROL_ROOM_SECURITY_STATEMENT_TERMS,
    CONTROL_ROOM_UNKNOWN_ROUTE_PROTECTION,
)
from fusekit.runner.detonation_proof import (
    DETONATION_KEYS,
    REMOTE_WORKER_CLEANUP_RECEIPT_KEYS,
    REMOTE_WORKER_CLEANUP_RECEIPT_LIST_FIELDS,
    REMOTE_WORKER_CLEANUP_RECEIPT_TEXT_FIELDS,
    WORKSPACE_DETONATION_RECEIPT_KEYS,
    WORKSPACE_DETONATION_RESOURCE_SUMMARY_BOOLEAN_FIELDS,
    WORKSPACE_DETONATION_RESOURCE_SUMMARY_KEYS,
    WORKSPACE_DETONATION_RESOURCE_SUMMARY_LIST_FIELDS,
    WORKSPACE_DETONATION_RESOURCE_SUMMARY_TEXT_FIELDS,
)
from fusekit.runner.durable_state_proof import (
    DETONATION_SCOPE_NO_TRACE_TERMS,
    DETONATION_SCOPE_SCHEMA_VERSION,
    DURABLE_STATE_SCHEMA_VERSION,
    DURABLE_STATE_STATEMENT_TERMS,
    WORKER_REPLACEMENT_STATE_OWNER,
    WORKER_REPLACEMENT_STATEMENT_TERMS,
)
from fusekit.runner.evidence_inventory import (
    ARTIFACT_RECORD_KEYS,
    EVIDENCE_COUNT_KEYS,
    EVIDENCE_INVENTORY_KEYS,
    EVIDENCE_INVENTORY_SCHEMA_VERSION,
    EVIDENCE_RECORD_KEYS,
)
from fusekit.runner.gate_proof import (
    PROVIDER_GATE_RECORD_KEYS,
    PROVIDER_GATES_KEYS,
    WAKE_EVENT_RECORD_KEYS,
    WAKE_EVENTS_KEYS,
)
from fusekit.runner.gates import GateRecord
from fusekit.runner.job import JobState
from fusekit.runner.provider_playbook import (
    PROVIDER_PLAYBOOK_FAMILIES,
    PROVIDER_PLAYBOOK_STEP_FIELDS,
)
from fusekit.runner.provider_playbook import (
    PROVIDER_PLAYBOOK_STEP_KEYS as _PROVIDER_PLAYBOOK_STEP_KEYS,
)
from fusekit.runner.provider_strategy import (
    PROVIDER_STRATEGY_RECORD_LIST_FIELDS,
    PROVIDER_STRATEGY_RECORD_OPTIONAL_TEXT_FIELDS,
    PROVIDER_STRATEGY_RECORD_REQUIRED_FIELDS,
    PROVIDER_STRATEGY_ROUTE_CANDIDATE_REQUIRED_FIELDS,
    PROVIDER_STRATEGY_ROUTE_REQUIRED_FIELDS,
)
from fusekit.runner.readiness import (
    EXPECTED_PROVIDER_BROWSER_PROFILE,
    EXPECTED_RUNNER_PORTS,
    EXPECTED_RUNNER_PROFILE,
    REQUIRED_RUNNER_BINARIES,
    REQUIRED_RUNNER_READINESS_CHECKS,
    RUNNER_BROWSER_STACK_KEYS,
    RUNNER_OBSERVED_KEYS,
    RUNNER_PROFILE_CONTRACT_KEYS,
    RUNNER_READINESS_KEYS,
    runner_readiness_failures,
)
from fusekit.runner.recording_contract import (
    RECORDING_CONTRACT_CHECK_KEYS,
    RECORDING_CONTRACT_SCHEMA_VERSION,
)
from fusekit.runner.rehearsal_proof import (
    CAPTURE_VM_CLIPBOARD_ACTION,
    CONFIRM_GATE_FINISHED_ACTION,
    FINISH_VISIBLE_CONTROLS,
    HUMAN_ACTION_COUNT_KEYS,
    HUMAN_ACTION_KEYS,
    HUMAN_ACTION_TRACE_SCHEMA_VERSION,
    OPEN_PROVIDER_GATE_ACTION,
    OPEN_PROVIDER_GATE_CONTROL,
    REHEARSAL_REVIEW_ACTION_KEYS,
    REHEARSAL_REVIEW_SCHEMA_VERSION,
    capture_vm_clipboard_control,
    rehearsal_review_proof_source,
)
from fusekit.runner.remote import (
    REMOTE_WORKER_CLEANUP_SCHEMA_VERSION,
    REMOTE_WORKER_PATH_TARGETS,
    REMOTE_WORKER_PROCESS_PATTERNS,
)
from fusekit.runner.run_state import LaunchRunState
from fusekit.runner.setup_receipt_proof import (
    SETUP_RECEIPT_ACTION_NAME_FIELD,
    SETUP_RECEIPT_ACTION_STATUS_FIELD,
    SETUP_RECEIPT_ACTIONS_FIELD,
)
from fusekit.runner.timeline_proof import (
    TIMELINE_CHECKPOINT_KEYS,
    TIMELINE_CHECKPOINT_OPTIONAL_TEXT_FIELDS,
    TIMELINE_ENTRY_KEYS,
    TIMELINE_OPTIONAL_TEXT_FIELDS,
    TIMELINE_REQUIRED_TEXT_FIELDS,
    TIMELINE_STEP_KEYS,
    TIMELINE_STEP_OPTIONAL_TEXT_FIELDS,
    TIMELINE_TIMESTAMP_FIELD,
)
from fusekit.runner.vault_proof import (
    VAULT_KEYS,
    VAULT_RECORD_FIELDS,
    VAULT_RECORD_KEYS,
    VAULT_SECRET_FIELD_NAMES,
)
from fusekit.runner.verifier_summary import (
    VERIFIER_SUMMARY_CHECK_KEYS,
    VERIFIER_SUMMARY_COUNT_KEYS,
    VERIFIER_SUMMARY_KEYS,
    VERIFIER_SUMMARY_SCHEMA_VERSION,
)
from fusekit.security import (
    contains_durable_secret_text,
    redact_public_path,
    redact_public_text,
)

RUN_RECORD_SCHEMA_VERSION = "fusekit.run-record.v1"
RUN_RECORD_KEYS = frozenset(
    {
        "schema_version",
        "id",
        "status",
        "app_path",
        "runner",
        "created_at",
        "updated_at",
        "state",
        "steps",
        "checkpoints",
        "provider_gates",
        "durable_state",
        "runner_profile",
        "worker_replacement_drill",
        "provider_playbook",
        "model_inference",
        "verifiers",
        "wake_events",
        "human_actions",
        "rehearsal_review",
        "automation_boundary",
        "control_room_security",
        "provider_strategies",
        "vault",
        "audit_trail",
        "artifacts",
        "evidence",
        "verification",
        "llm_contract",
        "acceptance",
        "detonation",
        "approvals",
        "errors",
        "recording_contract",
    }
)
PUBLIC_PROVIDER_BROWSER_PROFILE = "shared-provider-browser-profile"
PUBLIC_PLAYWRIGHT_BROWSERS_PATH = "playwright-browser-cache"
WORKER_REPLACEMENT_DRILL_SCHEMA_VERSION = (
    worker_replacement_contract.WORKER_REPLACEMENT_DRILL_SCHEMA_VERSION
)
WORKER_REPLACEMENT_DRILL_KEYS = worker_replacement_contract.WORKER_REPLACEMENT_DRILL_KEYS
WORKER_REPLACEMENT_SOURCE_IDS = worker_replacement_contract.WORKER_REPLACEMENT_SOURCE_IDS
DURABLE_STATE_SOURCES = (
    ("encrypted_vault", "fusekit.vault.json", "encrypted capability vault", "encrypted"),
    ("job_state", "job.json", "runner job state", "non-secret"),
    ("run_state", "run_state.json", "launch state contract", "non-secret"),
    ("checkpoints", "checkpoints.json", "resume checkpoints", "non-secret"),
    ("gates", "gates.json", "provider gate state", "non-secret"),
    ("gate_events", "gate_events.jsonl", "evented resume wake proof", "non-secret"),
    ("provider_strategies", "provider_strategies.json", "provider route decisions", "non-secret"),
    ("llm_contract", "llm_contract.json", "model/inference contract", "non-secret"),
    ("runner_readiness", "runner_readiness.json", "runner profile readiness proof", "non-secret"),
    (
        "worker_replacement_drill",
        "worker_replacement_drill.json",
        "replacement drill proof",
        "non-secret",
    ),
    ("setup_receipt", "setup_receipt.json", "redacted provider setup receipt", "non-secret"),
    (
        "verification_report",
        "verification_report.json",
        "live provider verifier proof",
        "non-secret",
    ),
    ("rollback_plan", "rollback_plan.json", "provider rollback metadata", "non-secret"),
    (
        "workspace_detonation",
        "workspace_detonation.json",
        "OCI workspace detonation receipt",
        "non-secret",
    ),
    ("run_record", "run_record.json", "central run record", "non-secret"),
)
VOLATILE_WORKER_SURFACES = (
    "worker",
    "tmp",
    "browser",
    "browser-profile",
    "chrome-profile",
    "playwright-profile",
    "provider-auth",
    "auth-state",
    "openclaw",
    "openclaw-state",
    "visual",
    "passphrase",
    "app.tar.gz",
    "control-room.log",
    "openclaw-gateway.log",
    "x11vnc.log",
    "websockify.log",
    "chrome.log",
)
OCI_WORKSPACE_DETONATION_SURFACES = (
    "instance",
    "boot_volume",
    "ephemeral_public_ip",
    "internet_gateway",
    "network_security_group",
    "route_table",
    "security_list",
    "subnet",
    "vcn",
)
RECORDING_DETONATION_AUDIT_RESOURCES = frozenset(
    {
        "boot_volume",
        "ephemeral_public_ip",
        "instance",
        "internet_gateway",
        "network_security_group",
        "remote_worker",
        "route_table",
        "security_list",
        "subnet",
        "vcn",
    }
)
RECORDING_PROVIDER_PLAYBOOK_FAMILIES = PROVIDER_PLAYBOOK_FAMILIES
PROVIDER_PLAYBOOK_STEP_KEYS = _PROVIDER_PLAYBOOK_STEP_KEYS
EVIDENCE_INVENTORY_COUNTS_KEYS = EVIDENCE_COUNT_KEYS
VOLATILE_DURABLE_STATE_MARKERS = tuple(
    sorted(
        {
            *VOLATILE_WORKER_SURFACES,
            ".log",
            "clipboard-history",
            "local-browser",
            "vm-scratch",
        },
        key=len,
        reverse=True,
    )
)
DETONATION_PRESERVES = (
    "encrypted_vault",
    "job_state",
    "run_state",
    "checkpoints",
    "gates",
    "gate_events",
    "provider_strategies",
    "llm_contract",
    "runner_readiness",
    "worker_replacement_drill",
    "setup_receipt",
    "workspace_detonation",
    "verification_report",
    "rollback_plan",
    "run_record",
)
EXPECTED_DURABLE_STATE_SOURCE_PATHS = {
    source_id: path for source_id, path, _role, _secret in DURABLE_STATE_SOURCES
}
LOG_EVIDENCE_FILENAMES = frozenset(
    {
        "audit.jsonl",
        "gate_events.jsonl",
        "ledger.jsonl",
        "control-room.log",
        "openclaw-gateway.log",
        "x11vnc.log",
        "websockify.log",
        "chrome.log",
        "openclaw-auth-pty.log",
    }
)
VISUAL_EVIDENCE_FILENAMES = frozenset(
    {
        "visual.json",
        "runner_readiness.json",
    }
)
SCREENSHOT_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".webp"})
def build_run_record(
    job: JobState,
    *,
    root: Path,
    vault_index: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a single non-secret record that ties together launch state."""

    gates = _canonical_gate_records(_read_gates(root / "gates.json"))
    verification = _redacted_public_json(_read_json_object(root / "verification_report.json"))
    llm_contract = _redacted_public_json(_read_json_object(root / "llm_contract.json"))
    acceptance = _read_json_object(root / "acceptance" / "report.json")
    receipt = _redacted_public_json(_read_json_object(root / "setup_receipt.json"))
    workspace_detonation = _redacted_public_json(
        _read_json_object(root / "workspace_detonation.json")
    )
    provider_strategies_artifact = _redacted_public_json(
        _read_json_object(root / "provider_strategies.json")
    )
    provider_playbook = _provider_playbook_summary(provider_strategies_artifact)
    provider_strategies = _provider_strategies_summary_with_playbook(
        provider_strategies_artifact,
        provider_playbook,
    )
    runner_readiness = _read_json_object(root / "runner_readiness.json")
    worker_replacement_drill = _read_json_object(root / "worker_replacement_drill.json")
    wake_events = _canonical_wake_events(_read_gate_wake_events(root / "gate_events.jsonl"))
    raw_run_state = _read_run_state(root / "run_state.json")
    run_state = _redacted_public_json(raw_run_state)
    run_state = run_state if isinstance(run_state, dict) else {}
    artifacts = _artifact_records(job, root)
    durable_state = _durable_state_summary(root, run_state, artifacts, runner_readiness)
    evidence = _evidence_inventory(root, artifacts)
    human_actions = _human_action_trace(gates, wake_events)
    automation_boundary = _automation_boundary_summary(
        provider_strategies_artifact,
        human_actions,
        durable_state,
    )
    human_actions_required = (
        bool(gates)
        or bool(wake_events)
        or _automation_boundary_requires_human_actions(automation_boundary)
    )
    rehearsal_review = _rehearsal_review_summary(
        human_actions,
        human_actions_required=human_actions_required,
    )
    vault = _vault_summary(vault_index or [])
    errors = _error_summary(job, gates, verification, acceptance, workspace_detonation)
    record = {
        "schema_version": RUN_RECORD_SCHEMA_VERSION,
        "id": job.id,
        "status": job.status,
        "app_path": redact_public_path(job.app_path),
        "runner": job.runner,
        "created_at": job.created_at,
        "updated_at": time.time(),
        "state": run_state,
        "steps": _timeline_record_entries(step.to_dict() for step in job.steps),
        "checkpoints": _timeline_record_entries(
            checkpoint.to_dict() for checkpoint in job.checkpoints
        ),
        "provider_gates": _gate_summary(gates),
        "durable_state": durable_state,
        "runner_profile": _runner_profile_summary(runner_readiness),
        "worker_replacement_drill": _worker_replacement_drill_summary(
            worker_replacement_drill
        ),
        "provider_playbook": provider_playbook,
        "model_inference": _model_inference_summary(llm_contract),
        "verifiers": _verifier_summary(verification),
        "wake_events": _wake_event_summary(wake_events),
        "human_actions": human_actions,
        "rehearsal_review": rehearsal_review,
        "automation_boundary": automation_boundary,
        "control_room_security": public_control_room_security_surface(),
        "provider_strategies": provider_strategies or {"providers": []},
        "vault": vault,
        "audit_trail": _audit_trail_summary(
            root,
            gates,
            wake_events,
            receipt,
            workspace_detonation,
            vault["records"],
        ),
        "artifacts": artifacts,
        "evidence": evidence,
        "verification": verification,
        "llm_contract": llm_contract,
        "acceptance": _acceptance_summary(acceptance, errors=errors),
        "detonation": _detonation_summary(run_state, workspace_detonation),
        "approvals": _approval_summary(gates),
        "errors": errors,
    }
    record["recording_contract"] = _recording_contract_summary(record)
    _align_detonation_preflight_summary(record, run_state)
    record["recording_contract"] = _recording_contract_summary(record)
    record["acceptance"] = _acceptance_summary(
        acceptance,
        errors=errors,
        recording_contract=record["recording_contract"],
    )
    return record


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
            records.append(_redacted_gate_record(GateRecord.from_dict(item).to_dict()))
        except (KeyError, TypeError, ValueError):
            records.append(
                {
                    "id": _redacted_error_text(item.get("id", "unknown")),
                    "status": "invalid",
                }
            )
    return records


def _redacted_gate_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        str(key): _redacted_gate_value(value)
        for key, value in record.items()
    }


def _redacted_gate_value(value: object) -> object:
    if isinstance(value, str):
        return _redacted_error_text(value)
    if isinstance(value, list):
        return [_redacted_gate_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redacted_gate_value(item) for key, item in value.items()}
    return value


def _redacted_public_json(value: object) -> Any:
    if isinstance(value, str):
        return _redacted_error_text(value)
    if isinstance(value, list):
        return [_redacted_public_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redacted_public_json(item) for key, item in value.items()}
    return value


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
    records: list[dict[str, Any]] = []
    for gate in gates:
        gate_id = str(gate.get("id", "") or "").strip()
        status = str(gate.get("status", "") or "").strip()
        provider = str(gate.get("provider", "") or "").strip()
        if not gate_id or not status or not provider:
            continue
        statuses[status] = statuses.get(status, 0) + 1
        providers.add(provider)
        records.append(gate)
    return {
        "total": len(records),
        "statuses": statuses,
        "providers": sorted(providers),
        "records": records,
    }


def _canonical_gate_records(gates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for gate in gates:
        record = _canonical_gate_record(gate)
        if record is None:
            continue
        gate_id = record["id"]
        if gate_id in seen_ids:
            continue
        seen_ids.add(gate_id)
        records.append(record)
    return records


def _canonical_gate_record(gate: dict[str, Any]) -> dict[str, Any] | None:
    required: dict[str, str] = {}
    for key in ("id", "provider", "status"):
        value = _public_gate_text(gate.get(key, ""))
        if value is None:
            return None
        required[key] = value
    record: dict[str, Any] = dict(required)
    for key in (
        "classification",
        "target",
        "reason",
        "resume_url",
        "last_opened_url",
        "next_action",
        "resume_hint",
        "last_wake_event",
        "last_wake_event_id",
    ):
        value = _public_gate_text(gate.get(key, ""))
        if value is not None:
            record[key] = value
    for key in ("captured_targets", "follow_steps", "success_criteria", "avoid_steps"):
        record[key] = _public_gate_text_list(gate.get(key, []))
    record["attempts"] = _public_gate_int(gate.get("attempts", 0))
    for key in ("last_opened_at", "last_wake_event_at", "created_at", "updated_at"):
        record[key] = _public_gate_timestamp(gate.get(key, 0))
    return record


def _public_gate_text(value: object) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text or contains_durable_secret_text(text):
        return None
    return text


def _public_gate_text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = _public_gate_text(item)
        if text is not None:
            items.append(text)
    return items


def _public_gate_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _public_gate_timestamp(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return 0.0
    return float(value)


def _wake_event_summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    records: list[dict[str, Any]] = []
    for event in events:
        name = str(event.get("event", "") or "").strip()
        if not name:
            continue
        counts[name] = counts.get(name, 0) + 1
        records.append(event)
    return {
        "total": len(records),
        "event_counts": counts,
        "events": records,
    }


def _canonical_wake_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_proofs: set[tuple[str, str, str]] = set()
    for event in events:
        record = _canonical_wake_event(event)
        if record is None:
            continue
        event_id = record["id"]
        if event_id:
            if event_id in seen_ids:
                continue
            seen_ids.add(event_id)
        proof = (record["event"], record["gate_id"], record["target"])
        if proof in seen_proofs:
            continue
        seen_proofs.add(proof)
        records.append(record)
    return records


def _canonical_wake_event(event: dict[str, Any]) -> dict[str, Any] | None:
    schema_version = _public_wake_text(
        event.get("schema_version", "fusekit.gate-wake.v1"),
        fallback="fusekit.gate-wake.v1",
    )
    event_name = _public_wake_text(event.get("event", "unknown"), fallback="unknown")
    gate_id = _public_wake_text(event.get("gate_id", "unknown"), fallback="unknown")
    if schema_version is None or event_name is None or gate_id is None:
        return None
    return {
        "schema_version": schema_version,
        "id": _public_wake_text(event.get("id", ""), fallback="") or "",
        "event": event_name,
        "gate_id": gate_id,
        "provider": _public_wake_text(event.get("provider", ""), fallback="") or "",
        "classification": _public_wake_text(
            event.get("classification", ""),
            fallback="",
        )
        or "",
        "status": _public_wake_text(event.get("status", "unknown"), fallback="unknown")
        or "unknown",
        "target": _public_wake_text(event.get("target", ""), fallback="") or "",
        "target_count": _public_wake_int(event.get("target_count", 0)),
        "captured_targets": _public_wake_text_list(event.get("captured_targets", [])),
        "created_at": _public_wake_timestamp(event.get("created_at", 0)),
    }


def _public_wake_text(value: object, *, fallback: str) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        text = fallback
    lowered = text.lower()
    if any(marker in lowered for marker in ("token=", "password=", "secret=")):
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _public_wake_text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = _public_wake_text(item, fallback="")
        if text:
            items.append(text)
    return items


def _public_wake_int(value: object) -> int:
    number = _safe_int(value, 0)
    if number < 0:
        return 0
    return number


def _public_wake_timestamp(value: object) -> float:
    timestamp = _safe_float(value, 0)
    if timestamp < 0:
        return 0.0
    return timestamp


def _redacted_wake_event(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": _redacted_error_text(
            raw.get("schema_version", "fusekit.gate-wake.v1")
        ),
        "id": _redacted_error_text(raw.get("id", "")),
        "event": _redacted_error_text(raw.get("event", "unknown") or "unknown"),
        "gate_id": _redacted_error_text(raw.get("gate_id", "unknown") or "unknown"),
        "provider": _redacted_error_text(raw.get("provider", "") or ""),
        "classification": _redacted_error_text(raw.get("classification", "") or ""),
        "status": _redacted_error_text(raw.get("status", "unknown") or "unknown"),
        "target": _redacted_error_text(raw.get("target", "") or ""),
        "target_count": _safe_int(raw.get("target_count"), 0),
        "captured_targets": [
            _redacted_error_text(target)
            for target in _safe_string_list(raw.get("captured_targets", []))
        ],
        "created_at": _safe_float(raw.get("created_at"), 0),
    }


def _human_action_trace(
    gates: list[dict[str, Any]],
    wake_events: list[dict[str, Any]],
) -> dict[str, Any]:
    """Summarize visible human actions for rehearsal review."""

    known_gates = {str(gate.get("id", "") or ""): gate for gate in gates}
    actions: list[dict[str, Any]] = []
    for gate in gates:
        opened_at = _safe_float(gate.get("last_opened_at"), 0)
        if opened_at > 0:
            actions.append(
                _human_action_record(
                    gate,
                    action=OPEN_PROVIDER_GATE_ACTION,
                    visible_control=OPEN_PROVIDER_GATE_CONTROL,
                    created_at=opened_at,
                    target="",
                    known_gate=True,
                )
            )
    for event in wake_events:
        if not isinstance(event, dict):
            continue
        gate_id = str(event.get("gate_id", "") or "")
        gate = known_gates.get(
            gate_id,
            {
                "id": gate_id,
                "provider": str(event.get("provider", "") or ""),
                "classification": str(event.get("classification", "") or ""),
            },
        )
        event_name = str(event.get("event", "") or "")
        target = str(event.get("target", "") or "")
        if event_name == "clipboard_captured":
            control = capture_vm_clipboard_control(target) if target else (
                "Capture from VM clipboard"
            )
            action = CAPTURE_VM_CLIPBOARD_ACTION
        elif event_name == "resume_requested":
            if _resume_event_is_capture_auto_wake(event):
                continue
            control = _resume_visible_control(gate)
            action = CONFIRM_GATE_FINISHED_ACTION
        else:
            continue
        actions.append(
            _human_action_record(
                gate,
                action=action,
                visible_control=control,
                created_at=_safe_float(event.get("created_at"), 0),
                target=target,
                known_gate=gate_id in known_gates,
            )
    )
    actions.sort(key=lambda item: (_safe_float(item.get("created_at"), 0), item["gate_id"]))
    counts: dict[str, int] = {name: 0 for name in sorted(HUMAN_ACTION_COUNT_KEYS)}
    for action_record in actions:
        name = str(action_record.get("action", "") or "unknown")
        if name in counts:
            counts[name] += 1
    unguided = [
        {
            "gate_id": str(action_record.get("gate_id", "")),
            "action": str(action_record.get("action", "")),
            "reason": str(action_record.get("guidance_gap", "")),
        }
        for action_record in actions
        if action_record.get("guided") is not True
    ]
    return {
        "schema_version": HUMAN_ACTION_TRACE_SCHEMA_VERSION,
        "total": len(actions),
        "counts": counts,
        "actions": actions,
        "unguided": unguided,
        "statement": (
            "Every recorded human action should map to one visible control-room gate "
            "and its current follow-me instructions; the trace contains no raw provider "
            "URLs, clipboard values, passwords, tokens, or screenshots."
        ),
    }


def _rehearsal_review_summary(
    human_actions: dict[str, Any],
    *,
    human_actions_required: bool = False,
) -> dict[str, Any]:
    """Prove recorded human actions were compared to launcher-visible instructions."""

    actions = human_actions.get("actions", []) if isinstance(human_actions, dict) else []
    actions = actions if isinstance(actions, list) else []
    unguided = human_actions.get("unguided", []) if isinstance(human_actions, dict) else []
    unguided = unguided if isinstance(unguided, list) else []
    matched_controls = [
        action
        for action in actions
        if isinstance(action, dict)
        and str(action.get("gate_id", "") or "").strip()
        and action.get("guided") is True
        and _recording_human_action_control_ready(action)
    ]
    side_channel_count = sum(
        1 for action in actions if isinstance(action, dict) and _human_action_side_channel(action)
    )
    missing_required_actions = human_actions_required and not actions
    status = (
        "ready"
        if (
            len(matched_controls) == len(actions)
            and not unguided
            and side_channel_count == 0
            and not missing_required_actions
        )
        else "needs_review"
    )
    reviewed_actions = [
        _rehearsal_review_action(action)
        for action in actions
        if isinstance(action, dict)
    ]
    return {
        "schema_version": REHEARSAL_REVIEW_SCHEMA_VERSION,
        "status": status,
        "action_count": len(actions),
        "compared_action_count": len(actions),
        "matched_control_count": len(matched_controls),
        "unguided_count": len(unguided),
        "side_channel_count": side_channel_count,
        "requires_user_thinking": status != "ready",
        "reviewed_actions": reviewed_actions,
        "statement": (
            "Every recorded human action is compared against the visible control-room "
            "instructions before public recording readiness. The review fails if an "
            "action needs host-browser, terminal, side-channel, or unsupported manual steps."
        ),
    }


def _rehearsal_review_action(action: dict[str, Any]) -> dict[str, Any]:
    action_name = str(action.get("action", "") or "")
    return {
        "gate_id": str(action.get("gate_id", "") or ""),
        "action": action_name,
        "visible_control": str(action.get("visible_control", "") or ""),
        "target": str(action.get("target", "") or ""),
        "matched": (
            str(action.get("gate_id", "") or "").strip() != ""
            and action.get("guided") is True
            and _recording_human_action_control_ready(action)
            and not _human_action_side_channel(action)
        ),
        "proof_source": rehearsal_review_proof_source(action_name),
    }


def _rehearsal_review_proof_source(action_name: str) -> str:
    return rehearsal_review_proof_source(action_name)


def _human_action_side_channel(action: dict[str, Any]) -> bool:
    text = " ".join(
        str(action.get(key, "") or "")
        for key in ("action", "visible_control", "target", "guidance_gap")
    ).lower()
    return any(
        marker in text
        for marker in (
            "host browser",
            "local browser",
            "terminal",
            "side-channel",
            "side channel",
            "manual step",
            "unsupported",
        )
    )


def _resume_event_is_capture_auto_wake(event: dict[str, Any]) -> bool:
    target_count = _safe_int(event.get("target_count"), 0)
    captured_targets = _safe_string_list(event.get("captured_targets", []))
    return target_count > 0 and len(captured_targets) >= target_count


def _human_action_record(
    gate: dict[str, Any],
    *,
    action: str,
    visible_control: str,
    created_at: float,
    target: str,
    known_gate: bool,
) -> dict[str, Any]:
    gate_id = str(gate.get("id", "") or "")
    provider = str(gate.get("provider", "") or "")
    classification = str(gate.get("classification", "") or "")
    guided, gap = _human_action_guidance_status(
        gate,
        action=action,
        target=target,
        known_gate=known_gate,
    )
    return {
        "gate_id": gate_id,
        "provider": provider,
        "classification": classification,
        "action": action,
        "visible_control": visible_control,
        "target": target,
        "guided": guided,
        "guidance_gap": gap,
        "created_at": created_at,
    }


def _human_action_guidance_status(
    gate: dict[str, Any],
    *,
    action: str,
    target: str,
    known_gate: bool,
) -> tuple[bool, str]:
    if not known_gate:
        return False, "action did not match a durable gate"
    text = " ".join(
        (
            str(gate.get("next_action", "") or ""),
            str(gate.get("resume_hint", "") or ""),
            " ".join(_safe_string_list(gate.get("follow_steps", []))),
            " ".join(_safe_string_list(gate.get("success_criteria", []))),
        )
    )
    if action == "open_provider_gate":
        if str(gate.get("resume_url", "") or "").strip() and "Open provider gate in VM" in text:
            return True, ""
        return False, "provider gate open lacked visible VM-browser guidance"
    if action == "capture_vm_clipboard":
        if target and f"Capture {target} from VM clipboard" in text:
            return True, ""
        return False, "clipboard capture lacked exact env-named Capture guidance"
    if action == "confirm_gate_finished":
        if _resume_visible_control(gate) in text:
            return True, ""
        return False, "resume click lacked exact finished/approval guidance"
    return False, "unsupported human action"


def _resume_visible_control(gate: dict[str, Any]) -> str:
    classification = str(gate.get("classification", "") or "")
    if classification == "dns-approval":
        return "Approve DNS apply"
    if classification == "setup-approval":
        return "Approve setup plan"
    return "I finished this step"


def _artifact_records(job: JobState, root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    for name, value in sorted(job.artifacts.items()):
        path = _artifact_filesystem_path(root, Path(value))
        _append_artifact_record(
            records,
            seen_names=seen_names,
            seen_paths=seen_paths,
            root=root,
            name=name,
            path=path,
            exists=path.is_file(),
        )
    for name in (
        "job",
        "checkpoints",
        "run_state",
        "gates",
        "gate_events",
        "runner_readiness",
        "setup_receipt",
        "verification_report",
        "rollback_plan",
        "workspace_detonation",
        "run_record",
    ):
        suffix = "jsonl" if name == "gate_events" else "json"
        path = root / f"{name}.{suffix}"
        if name in seen_names:
            continue
        if path.is_file():
            _append_artifact_record(
                records,
                seen_names=seen_names,
                seen_paths=seen_paths,
                root=root,
                name=name,
                path=path,
                exists=True,
            )
    return records


def _append_artifact_record(
    records: list[dict[str, Any]],
    *,
    seen_names: set[str],
    seen_paths: set[str],
    root: Path,
    name: object,
    path: Path,
    exists: bool,
) -> None:
    public_name = _public_artifact_name(name)
    public_path = _safe_public_artifact_path(root, path)
    if public_name is None or public_path is None:
        return
    if public_name in seen_names or public_path in seen_paths:
        return
    seen_names.add(public_name)
    seen_paths.add(public_path)
    records.append({"name": public_name, "path": public_path, "exists": exists})


def _public_artifact_name(value: object) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in ("token=", "password=", "secret=")):
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _safe_public_artifact_path(root: Path, path: Path) -> str | None:
    public_path = _public_artifact_path(root, path).strip()
    if not public_path:
        return None
    artifact_path = Path(public_path)
    if artifact_path.is_absolute() or ".." in artifact_path.parts:
        return None
    lowered = public_path.lower()
    if any(marker in lowered for marker in ("token=", "password=", "secret=")):
        return None
    if contains_durable_secret_text(public_path):
        return None
    return public_path


def _artifact_filesystem_path(root: Path, path: Path) -> Path:
    if path.is_absolute():
        return path
    return root / path


def _public_artifact_path(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return redact_public_path(path)


def _evidence_inventory(
    root: Path,
    artifacts: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a non-secret inventory of proof logs and visual evidence."""

    candidates = _evidence_candidates(root, artifacts)
    logs = _evidence_records(candidates, kind="log")
    screenshots = _evidence_records(candidates, kind="screenshot")
    visual = _evidence_records(candidates, kind="visual")
    receipts = _evidence_records(candidates, kind="receipt")
    return {
        "schema_version": EVIDENCE_INVENTORY_SCHEMA_VERSION,
        "logs": logs,
        "screenshots": screenshots,
        "visual": visual,
        "receipts": receipts,
        "counts": {
            "logs": len(logs),
            "screenshots": len(screenshots),
            "visual": len(visual),
            "receipts": len(receipts),
        },
        "statement": (
            "Run evidence is inventoried by path and type only; log contents, "
            "screenshots, provider URLs, clipboard values, and raw secrets are not "
            "embedded in the Run Record."
        ),
    }


def _evidence_candidates(
    root: Path,
    artifacts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: dict[str, dict[str, Any]] = {}
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        raw_path = str(artifact.get("path", "") or "").strip()
        if not raw_path:
            continue
        path = _artifact_filesystem_path(root, Path(raw_path))
        _add_evidence_candidate(
            candidates,
            root=root,
            path=path,
            source=str(artifact.get("name", "") or "artifact"),
            exists=artifact.get("exists") is True,
        )
    for relative in (
        "audit.jsonl",
        "gate_events.jsonl",
        "acceptance/ledger.jsonl",
        "setup_receipt.json",
        "setup_receipt.md",
        "verification_report.json",
        "acceptance/report.json",
        "rollback.json",
        "rollback_metadata.json",
        "rollback_plan.json",
        "workspace_detonation.json",
        "run_record.json",
        "visual.json",
        "runner_readiness.json",
        "visual/control-room.log",
        "visual/openclaw-gateway.log",
        "visual/x11vnc.log",
        "visual/websockify.log",
        "visual/chrome.log",
    ):
        path = root / relative
        if path.exists():
            _add_evidence_candidate(
                candidates,
                root=root,
                path=path,
                source="known-proof",
                exists=True,
            )
    for directory in (root / "visual", root / "screenshots", root / "acceptance" / "artifacts"):
        if not directory.is_dir():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file() and (
                path.suffix.lower() in SCREENSHOT_SUFFIXES or path.name in LOG_EVIDENCE_FILENAMES
            ):
                _add_evidence_candidate(
                    candidates,
                    root=root,
                    path=path,
                    source="discovered-proof",
                    exists=True,
                )
    return list(candidates.values())


def _add_evidence_candidate(
    candidates: dict[str, dict[str, Any]],
    *,
    root: Path,
    path: Path,
    source: str,
    exists: bool,
) -> None:
    if not exists or not path.is_file():
        return
    display_path = _display_evidence_path(root, path)
    if display_path is None:
        return
    kind = _evidence_kind(path)
    if kind == "artifact":
        return
    candidates[display_path] = {
        "path": display_path,
        "kind": kind,
        "source": source,
        "exists": True,
    }


def _display_evidence_path(root: Path, path: Path) -> str | None:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None


def _evidence_kind(path: Path) -> str:
    name = path.name
    suffix = path.suffix.lower()
    if suffix in SCREENSHOT_SUFFIXES or "screenshot" in name.lower():
        return "screenshot"
    if name in LOG_EVIDENCE_FILENAMES or suffix in {".log", ".jsonl"}:
        return "log"
    if name in VISUAL_EVIDENCE_FILENAMES:
        return "visual"
    if name in {
        "setup_receipt.json",
        "setup_receipt.md",
        "verification_report.json",
        "report.json",
        "rollback.json",
        "rollback_metadata.json",
        "rollback_plan.json",
        "workspace_detonation.json",
        "run_record.json",
    }:
        return "receipt"
    return "artifact"


def _evidence_records(candidates: list[dict[str, Any]], *, kind: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    for candidate in sorted(candidates, key=lambda item: str(item.get("path", ""))):
        if candidate.get("kind") != kind:
            continue
        path = _public_evidence_text(candidate.get("path", ""))
        source = _public_evidence_text(candidate.get("source", ""))
        if path is None or source is None or not _recording_public_relative_path(path):
            continue
        if path in seen_paths:
            continue
        seen_paths.add(path)
        records.append(
            {
                "path": path,
                "kind": kind,
                "source": source,
                "exists": True,
            }
        )
    return records


def _public_evidence_text(value: object) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in ("token=", "password=", "secret=")):
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _durable_state_summary(
    root: Path,
    run_state: dict[str, Any],
    artifacts: list[dict[str, Any]],
    runner_readiness: dict[str, Any],
) -> dict[str, Any]:
    """Summarize whether a run can survive replacing the disposable worker."""

    artifact_names = {
        str(record.get("name", "")): record.get("exists") is True
        for record in artifacts
        if isinstance(record, dict)
    }
    sources: list[dict[str, Any]] = []
    for source_id, filename, role, secret_class in DURABLE_STATE_SOURCES:
        path = root / filename
        exists = (
            source_id == "run_record"
            or path.exists()
            or artifact_names.get(source_id, False)
        )
        sources.append(
            {
                "id": source_id,
                "path": filename,
                "role": role,
                "secret_class": secret_class,
                "exists": exists,
            }
        )
    replacement_source_ids = set(WORKER_REPLACEMENT_SOURCE_IDS)
    missing = [
        source["id"]
        for source in sources
        if source["id"] in replacement_source_ids and not source["exists"]
    ]
    final_proof_missing = [
        source["id"]
        for source in sources
        if source["id"] not in replacement_source_ids and not source["exists"]
    ]
    runner_failures = runner_readiness_failures(runner_readiness)
    resume_ready = not missing and not runner_failures
    return {
        "schema_version": DURABLE_STATE_SCHEMA_VERSION,
        "resume_ready": resume_ready,
        "missing": missing,
        "final_proof_missing": final_proof_missing,
        "runner_profile_ready": not runner_failures,
        "runner_profile_failures": runner_failures,
        "sources": sources,
        "volatile_worker_surfaces": list(VOLATILE_WORKER_SURFACES),
        "detonation_preserves": list(DETONATION_PRESERVES),
        "detonation_scope": {
            "schema_version": DETONATION_SCOPE_SCHEMA_VERSION,
            "mode": AUTOMATION_BOUNDARY_DETONATION_SCOPE,
            "must_delete": [
                *VOLATILE_WORKER_SURFACES,
                *OCI_WORKSPACE_DETONATION_SURFACES,
            ],
            "must_preserve": list(DETONATION_PRESERVES),
            "resume_until_complete": True,
            "host_machine_state_required": False,
            "no_trace_statement": (
                "Public OCI runs keep durable encrypted/redacted state outside the "
                "disposable VM until completion, then detonate VM/browser/auth scratch "
                "so no FuseKit worker state remains on the user's machine or in the "
                "OCI workspace."
            ),
        },
        "worker_replacement_contract": {
            "worker_is_disposable": resume_ready,
            "can_recreate_worker": resume_ready,
            "runner_profile_ready": not runner_failures,
            "required_runner_profile": EXPECTED_RUNNER_PROFILE,
            "host_machine_state_required": False,
            "state_owner": WORKER_REPLACEMENT_STATE_OWNER,
            "resume_sources": list(WORKER_REPLACEMENT_SOURCE_IDS),
            "runner_profile_failures": runner_failures,
            "volatile_surfaces": list(VOLATILE_WORKER_SURFACES),
            "statement": (
                "If the OCI VM is killed mid-run, FuseKit must recreate the runner "
                "from encrypted/redacted run state instead of relying on local "
                "browser profiles, host clipboard history, or plaintext VM scratch."
            ),
        },
        "workspace_detonated": run_state.get("workspace_detonated") is True,
        "statement": (
            "FuseKit can replace or detonate the disposable OCI worker without losing "
            "the run when resume_ready is true; plaintext VM/browser/auth scratch is "
            "volatile and encrypted/redacted state is the source of truth."
        ),
    }


def _runner_profile_summary(runner_readiness: dict[str, Any]) -> dict[str, Any]:
    if not runner_readiness:
        return {}
    return _public_runner_readiness_summary(runner_readiness)


def _public_runner_readiness_summary(raw: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in RUNNER_READINESS_KEYS:
        if key in {
            "checks",
            "installed_binaries",
            "observed",
            "profile_contract",
        }:
            continue
        text = _public_runner_text(raw.get(key, ""))
        if text is not None:
            summary[key] = text
    summary["profile_contract"] = _public_runner_profile_contract(
        raw.get("profile_contract", {})
    )
    summary["observed"] = _public_runner_observed(raw.get("observed", {}))
    summary["checks"] = _public_runner_checks(raw.get("checks", {}))
    summary["installed_binaries"] = _public_installed_binary_paths(
        raw.get("installed_binaries", {})
    )
    summary["provider_browser_profile"] = _public_provider_profile_label(
        raw.get("provider_browser_profile")
    )
    summary["playwright_browsers_path"] = _public_playwright_path_label(
        raw.get("playwright_browsers_path")
    )
    return summary


def _public_runner_profile_contract(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    profile: dict[str, Any] = {}
    for key in RUNNER_PROFILE_CONTRACT_KEYS:
        if key in {
            "browser_stack",
            "min_memory_mib",
            "ports",
            "required_binaries",
            "required_health_checks",
            "supported_os_ids",
        }:
            continue
        text = _public_runner_text(value.get(key, ""))
        if text is not None:
            profile[key] = text
    memory_mib = _public_runner_int(value.get("min_memory_mib"))
    if memory_mib is not None:
        profile["min_memory_mib"] = memory_mib
    ports = value.get("ports", {})
    public_ports: dict[str, int] = {}
    if isinstance(ports, dict):
        for key in EXPECTED_RUNNER_PORTS:
            port = _public_runner_int(ports.get(key))
            if port is not None:
                public_ports[key] = port
    profile["ports"] = public_ports
    profile["browser_stack"] = _public_runner_browser_stack(
        value.get("browser_stack", {})
    )
    profile["supported_os_ids"] = _public_runner_string_list(
        value.get("supported_os_ids", [])
    )
    profile["required_health_checks"] = _public_runner_string_list(
        value.get("required_health_checks", [])
    )
    profile["required_binaries"] = _public_runner_string_list(
        value.get("required_binaries", [])
    )
    return profile


def _public_runner_browser_stack(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    browser_stack: dict[str, str] = {}
    for key in RUNNER_BROWSER_STACK_KEYS:
        if key == "shared_provider_profile":
            profile = _public_provider_profile_label(value.get(key))
            if profile:
                browser_stack[key] = profile
            continue
        text = _public_runner_text(value.get(key, ""))
        if text is not None:
            browser_stack[key] = text
    return browser_stack


def _public_runner_observed(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    observed: dict[str, Any] = {}
    for key in RUNNER_OBSERVED_KEYS:
        if key == "memory_mib":
            memory_mib = _public_runner_int(value.get(key))
            if memory_mib is not None:
                observed[key] = memory_mib
            continue
        text = _public_runner_text(value.get(key, ""))
        if text is not None:
            observed[key] = text
    return observed


def _public_runner_checks(value: object) -> dict[str, bool]:
    if not isinstance(value, dict):
        return {}
    checks: dict[str, bool] = {}
    for key in REQUIRED_RUNNER_READINESS_CHECKS:
        check_value = value.get(key)
        if isinstance(check_value, bool):
            checks[key] = check_value
    return checks


def _public_provider_profile_label(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw in {EXPECTED_PROVIDER_BROWSER_PROFILE, PUBLIC_PROVIDER_BROWSER_PROFILE}:
        return PUBLIC_PROVIDER_BROWSER_PROFILE
    return redact_public_path(raw)


def _public_playwright_path_label(value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw == PUBLIC_PLAYWRIGHT_BROWSERS_PATH:
        return PUBLIC_PLAYWRIGHT_BROWSERS_PATH
    return PUBLIC_PLAYWRIGHT_BROWSERS_PATH if raw.startswith("/") else raw


def _public_installed_binary_paths(installed: object) -> dict[str, Any]:
    if not isinstance(installed, dict):
        return {}
    public: dict[str, Any] = {}
    for name in REQUIRED_RUNNER_BINARIES:
        record = installed.get(name)
        if not isinstance(record, dict):
            continue
        item: dict[str, Any] = {}
        present = record.get("present")
        if isinstance(present, bool):
            item["present"] = present
        path = _public_runner_text(record.get("path", ""))
        if path is not None:
            item["path"] = redact_public_path(path)
        version = record.get("version")
        if version is None:
            item["version"] = None
        else:
            version_text = _public_runner_text(version)
            if version_text is not None:
                item["version"] = version_text
        public[name] = item
    return public


def _public_runner_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = _public_runner_text(item)
        if text is None or text in seen:
            continue
        seen.add(text)
        items.append(text)
    return items


def _public_runner_text(value: object) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _public_runner_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _worker_replacement_drill_summary(drill: dict[str, Any]) -> dict[str, Any]:
    """Summarize the non-secret kill/recreate drill proof for public demos."""

    if not drill:
        return {}
    if not _worker_replacement_drill_shape_ready(drill):
        return {}
    summary: dict[str, Any] = {
        "schema_version": str(drill.get("schema_version", "") or ""),
        "status": str(drill.get("status", "") or ""),
        "worker_destroyed": drill.get("worker_destroyed") is True,
        "replacement_runner_profile_ready": (
            drill.get("replacement_runner_profile_ready") is True
        ),
        "control_room_reopened": drill.get("control_room_reopened") is True,
        "resume_checkpoint_restored": drill.get("resume_checkpoint_restored") is True,
        "gate_or_verifier_resumed": drill.get("gate_or_verifier_resumed") is True,
        "host_machine_state_required": drill.get("host_machine_state_required") is True,
        "volatile_state_reused": drill.get("volatile_state_reused") is True,
        "restored_from": _safe_string_list(drill.get("restored_from")),
        "statement": str(drill.get("statement", "") or ""),
    }
    redacted = _redacted_public_json(summary)
    return redacted if isinstance(redacted, dict) else {}


def _vault_summary(vault_index: list[dict[str, Any]]) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for record in vault_index:
        if not isinstance(record, dict):
            continue
        public_record = _public_vault_record(record)
        if public_record is None:
            continue
        record_id = public_record["id"]
        if record_id in seen_ids:
            continue
        seen_ids.add(record_id)
        records.append(public_record)
    return {
        "records": records,
        "record_count": len(records),
    }


def _public_vault_record(record: dict[str, Any]) -> dict[str, Any] | None:
    fields: dict[str, str] = {}
    for key in VAULT_RECORD_FIELDS:
        value = _public_vault_field(record.get(key, ""))
        if value is None:
            return None
        fields[key] = value
    return fields


def _public_vault_field(value: object) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in ("token=", "password=", "secret=")):
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _drop_vault_secret_fields(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): _drop_vault_secret_fields(item)
            for key, item in value.items()
            if str(key).strip().lower() not in VAULT_SECRET_FIELD_NAMES
        }
    if isinstance(value, list):
        return [_drop_vault_secret_fields(item) for item in value]
    return value


def _provider_strategies_summary_with_playbook(
    provider_strategies: Any,
    provider_playbook: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(provider_strategies, dict):
        return {"providers": []}
    summary: dict[str, Any] = {
        "schema_version": _public_provider_strategy_text(
            provider_strategies.get("schema_version", ""),
            fallback="",
        )
        or "",
        "providers": _canonical_provider_strategy_providers(
            provider_strategies.get("providers", [])
        ),
    }
    if provider_playbook:
        summary["playbook"] = {
            "schema_version": provider_playbook.get("schema_version", ""),
            "steps": provider_playbook.get("steps", []),
            "safety_notes": provider_playbook.get("safety_notes", []),
        }
    return summary


def _canonical_provider_strategy_providers(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    providers: list[dict[str, Any]] = []
    for provider_record in value:
        if not isinstance(provider_record, dict):
            continue
        provider = _public_provider_strategy_text(provider_record.get("provider", ""))
        if provider is None:
            continue
        strategies = _canonical_provider_strategy_records(
            provider_record.get("strategies", [])
        )
        providers.append(
            {
                "provider": provider,
                "strategies": strategies,
            }
        )
    return providers


def _canonical_provider_strategy_records(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    strategies: list[dict[str, Any]] = []
    for strategy in value:
        if not isinstance(strategy, dict):
            continue
        record: dict[str, Any] = {}
        missing_required = False
        for key in PROVIDER_STRATEGY_RECORD_REQUIRED_FIELDS:
            text = _public_provider_strategy_text(strategy.get(key, ""))
            if text is None:
                missing_required = True
                break
            record[key] = text
        if missing_required:
            continue
        decision = _canonical_provider_strategy_decision(strategy.get("decision", {}))
        if decision:
            record["decision"] = decision
        for key in PROVIDER_STRATEGY_RECORD_OPTIONAL_TEXT_FIELDS:
            text = _public_provider_strategy_text(strategy.get(key, ""))
            if text is not None:
                record[key] = text
        for key in PROVIDER_STRATEGY_RECORD_LIST_FIELDS:
            items = _public_provider_strategy_text_list(strategy.get(key, []))
            if items:
                record[key] = items
        strategies.append(record)
    return strategies


def _canonical_provider_strategy_decision(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    decision: dict[str, Any] = {}
    for key in ("provider", "recipe_kind"):
        text = _public_provider_strategy_text(value.get(key, ""))
        if text is not None:
            decision[key] = text
    selected = _canonical_provider_strategy_route(
        value.get("selected", {}),
        require_route_proof=True,
    )
    if selected:
        decision["selected"] = selected
    candidates = _canonical_provider_strategy_candidates(value.get("candidates", []))
    if candidates:
        decision["candidates"] = candidates
    return decision


def _canonical_provider_strategy_candidates(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in value:
        route = _canonical_provider_strategy_route(
            candidate,
            require_route_proof=False,
        )
        if not route:
            continue
        signature = (route["kind"], route["status"])
        if signature in seen:
            continue
        seen.add(signature)
        candidates.append(route)
    return candidates


def _canonical_provider_strategy_route(
    value: object,
    *,
    require_route_proof: bool,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    route: dict[str, Any] = {}
    required_keys = (
        PROVIDER_STRATEGY_ROUTE_REQUIRED_FIELDS
        if require_route_proof
        else PROVIDER_STRATEGY_ROUTE_CANDIDATE_REQUIRED_FIELDS
    )
    for key in required_keys:
        text = _public_provider_strategy_text(
            value.get(key, ""),
            allow_redacted_secret_marker=key == "reason",
        )
        if text is None:
            return {}
        route[key] = text
    label = _public_provider_strategy_text(value.get("label", ""))
    if label is not None:
        route["label"] = label
    priority = value.get("priority")
    if isinstance(priority, int) and not isinstance(priority, bool):
        route["priority"] = priority
    for key in ("deterministic", "implemented"):
        flag = value.get(key)
        if isinstance(flag, bool):
            route[key] = flag
        elif require_route_proof:
            return {}
    evidence = _canonical_provider_strategy_evidence(value.get("evidence", {}))
    if evidence:
        route["evidence"] = evidence
    return route


def _canonical_provider_strategy_evidence(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    public = _redacted_public_json(value)
    if not isinstance(public, dict):
        return {}
    evidence = _drop_unsafe_provider_strategy_evidence(public)
    return evidence if isinstance(evidence, dict) else {}


def _drop_unsafe_provider_strategy_evidence(value: object) -> Any:
    if isinstance(value, dict):
        evidence: dict[str, Any] = {}
        for key, item in value.items():
            text_key = _public_provider_strategy_text(key)
            if text_key is None:
                continue
            public_item = _drop_unsafe_provider_strategy_evidence(item)
            if public_item is not None:
                evidence[text_key] = public_item
        return evidence
    if isinstance(value, list):
        items = [
            item
            for item in (_drop_unsafe_provider_strategy_evidence(item) for item in value)
            if item is not None
        ]
        return items
    if isinstance(value, str):
        return _public_provider_strategy_text(value, allow_redacted_secret_marker=True)
    if isinstance(value, int | float | bool) or value is None:
        return value
    return None


def _public_provider_strategy_text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = _public_provider_strategy_text(item, allow_redacted_secret_marker=True)
        if text is None or text in seen:
            continue
        seen.add(text)
        items.append(text)
    return items


def _public_provider_strategy_text(
    value: object,
    *,
    fallback: str = "",
    allow_redacted_secret_marker: bool = False,
) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        text = fallback
    if not text:
        return None
    lowered = text.lower()
    if any(
        marker in lowered
        for marker in ("token=", "password=", "secret=", "api_key=")
    ) and not allow_redacted_secret_marker:
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _provider_playbook_summary(provider_strategies: dict[str, Any]) -> dict[str, Any]:
    playbook = provider_strategies.get("playbook", {})
    if not isinstance(playbook, dict):
        return {}
    steps = _canonical_provider_playbook_steps(playbook.get("steps", []))
    safety_notes = _canonical_provider_playbook_safety_notes(
        playbook.get("safety_notes", [])
    )
    return {
        "schema_version": _public_provider_playbook_text(
            playbook.get("schema_version", ""),
            fallback="",
        )
        or "",
        "step_count": len(steps),
        "steps": steps,
        "safety_notes": safety_notes,
    }


def _canonical_provider_playbook_steps(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    records: list[dict[str, Any]] = []
    for step in value:
        if not isinstance(step, dict):
            continue
        record: dict[str, Any] = {}
        missing_public_field = False
        for key in PROVIDER_PLAYBOOK_STEP_FIELDS:
            if key == "human_action_required":
                human_action_required = step.get(key)
                if not isinstance(human_action_required, bool):
                    missing_public_field = True
                    break
                record[key] = human_action_required
                continue
            text = _public_provider_playbook_text(
                step.get(key, ""),
                allow_redacted_secret_marker=key == "instruction",
            )
            if text is None:
                missing_public_field = True
                break
            record[key] = text
        if missing_public_field:
            continue
        records.append(record)
    return records


def _canonical_provider_playbook_safety_notes(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    notes: list[str] = []
    for note in value:
        if not isinstance(note, str):
            continue
        text = _public_provider_playbook_text(note)
        if text is None:
            continue
        notes.append(text)
    return notes


def _public_provider_playbook_text(
    value: object,
    *,
    fallback: str = "",
    allow_redacted_secret_marker: bool = False,
) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        text = fallback
    if not text:
        return None
    lowered = text.lower()
    if any(
        marker in lowered
        for marker in ("token=", "password=", "secret=", "api_key=")
    ) and not allow_redacted_secret_marker:
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _model_inference_summary(llm_contract: dict[str, Any]) -> dict[str, Any]:
    """Summarize the LLM lane without exposing keys or auth-state."""

    if not llm_contract:
        return {
            "schema_version": "fusekit.model-inference-summary.v1",
            "status": "pending",
            "ready": False,
            "provider": "openai",
            "model": "gpt-5.5",
            "next_action": (
                "Waiting for FuseKit to write the non-secret model/inference contract."
            ),
            "statement": (
                "FuseKit must have either an encrypted LLM API key or a supported "
                "OpenClaw authorization lane before it can reason about provider pages."
            ),
        }
    status = str(llm_contract.get("status", "") or "pending")
    ready = status in {
        "api_key_encrypted",
        "openclaw_profile_encrypted",
        "optional_for_rehearsal",
    }
    lanes = llm_contract.get("lanes", [])
    return _redacted_record_entry(
        {
            "schema_version": "fusekit.model-inference-summary.v1",
            "status": status,
            "ready": ready,
            "provider": str(llm_contract.get("provider", "") or "openai"),
            "model": str(llm_contract.get("model", "") or "gpt-5.5"),
            "base_url": str(llm_contract.get("base_url", "") or ""),
            "api_key_env": str(llm_contract.get("api_key_env", "") or "OPENAI_API_KEY"),
            "auth_mode": str(llm_contract.get("auth_mode", "") or "auto"),
            "required": llm_contract.get("required") is True,
            "can_proceed_without_api_key": (
                llm_contract.get("can_proceed_without_api_key") is True
            ),
            "default_lane": str(llm_contract.get("default_lane", "") or ""),
            "next_action": str(llm_contract.get("next_action", "") or ""),
            "lane_count": len(lanes) if isinstance(lanes, list) else 0,
            "statement": (
                "The model/inference lane is explicit: API keys are captured into the "
                "encrypted vault, OpenClaw/OpenAI auth is a human-gated fallback only "
                "for the default OpenAI lane, and raw secrets never appear in the "
                "control room, audit log, or receipt."
            ),
        }
    )


def _automation_boundary_summary(
    provider_strategies: dict[str, Any],
    human_actions: dict[str, Any],
    durable_state: dict[str, Any],
) -> dict[str, Any]:
    routes = _automation_route_records(provider_strategies)
    fusekit_owned = [
        route for route in routes if route["owner"] == "fusekit" and route["implemented"] is True
    ]
    human_gate_routes = [route for route in routes if route["owner"] == "human_gate"]
    unsupported = [route for route in routes if route["owner"] == "blocked"]
    allowed_human_actions = sorted(AUTOMATION_BOUNDARY_REQUIRED_VNC_ALLOWLIST)
    counts = human_actions.get("counts", {}) if isinstance(human_actions, dict) else {}
    status = (
        AUTOMATION_BOUNDARY_READY_STATUS
        if not unsupported
        else AUTOMATION_BOUNDARY_REPAIR_STATUS
    )
    return {
        "schema_version": AUTOMATION_BOUNDARY_SCHEMA_VERSION,
        "status": status,
        "resume_after_worker_replace": durable_state.get("resume_ready") is True,
        "detonation_scope": AUTOMATION_BOUNDARY_DETONATION_SCOPE,
        "no_user_machine_state": True,
        "vnc_allowed_for": allowed_human_actions,
        "routes": routes,
        "counts": {
            "fusekit_owned": len(fusekit_owned),
            "human_gate": len(human_gate_routes),
            "blocked": len(unsupported),
            "guided_human_actions": sum(
                int(value)
                for value in counts.values()
                if isinstance(value, int) and not isinstance(value, bool)
            )
            if isinstance(counts, dict)
            else 0,
        },
        "post_gate_automation": {
            "api_or_cli_routes": [
                f"{route['provider']}:{route['recipe']}"
                for route in fusekit_owned
                if route["route"] in AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS
            ],
            "human_gate_routes": [
                f"{route['provider']}:{route['recipe']}" for route in human_gate_routes
            ],
        },
        "statement": (
            "Humans use VNC only for login, MFA, CAPTCHA, consent, payment, or "
            "copy-once secret gates. After capture or approval, FuseKit owns "
            "provider mutations through API, official CLI, or local vault routes; "
            "durable encrypted state survives worker replacement until the OCI "
            "workspace and VM state detonate."
        ),
    }


def _automation_boundary_requires_human_actions(boundary: dict[str, Any]) -> bool:
    counts = boundary.get("counts", {}) if isinstance(boundary, dict) else {}
    return isinstance(counts, dict) and _safe_int(counts.get("human_gate"), 0) > 0


def _automation_route_records(provider_strategies: dict[str, Any]) -> list[dict[str, Any]]:
    providers = provider_strategies.get("providers", [])
    if not isinstance(providers, list):
        return []
    routes: list[dict[str, Any]] = []
    seen_signatures: set[str] = set()
    for provider_record in providers:
        if not isinstance(provider_record, dict):
            continue
        provider = _public_automation_route_text(provider_record.get("provider", ""))
        if provider is None:
            continue
        provider = provider.lower()
        strategies = provider_record.get("strategies", [])
        if not isinstance(strategies, list):
            continue
        for strategy in strategies:
            if not isinstance(strategy, dict):
                continue
            decision = strategy.get("decision", {})
            selected = decision.get("selected", {}) if isinstance(decision, dict) else {}
            selected = selected if isinstance(selected, dict) else {}
            route = _public_automation_route_text(
                strategy.get("strategy", selected.get("kind", ""))
            )
            recipe = _public_automation_route_text(strategy.get("recipe", ""))
            status = _public_automation_route_text(
                strategy.get("status", selected.get("status", ""))
            )
            if route is None or recipe is None or status is None:
                continue
            deterministic = selected.get("deterministic") is True
            implemented = selected.get("implemented") is True
            owner = _automation_route_owner(route, deterministic, implemented)
            if owner not in AUTOMATION_BOUNDARY_ROUTE_OWNERS:
                continue
            signature = f"{provider}:{recipe}"
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            routes.append(
                {
                    "provider": provider,
                    "recipe": recipe,
                    "route": route,
                    "owner": owner,
                    "deterministic": deterministic,
                    "implemented": implemented,
                    "status": status,
                }
            )
    return routes


def _public_automation_route_text(value: object) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in ("token=", "password=", "secret=", "api_key=")):
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _automation_route_owner(route: str, deterministic: bool, implemented: bool) -> str:
    if route in AUTOMATION_BOUNDARY_HUMAN_GATE_ROUTE_KINDS:
        return "human_gate"
    if (
        route in AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS
        and deterministic
        and implemented
    ):
        return "fusekit"
    return "blocked"


def _verifier_summary(verification: dict[str, Any]) -> dict[str, Any]:
    checks = verification.get("checks", [])
    checks = checks if isinstance(checks, list) else []
    records: list[dict[str, Any]] = []
    counts = {
        "passed": 0,
        "pending_safe": 0,
        "pending": 0,
        "repairing": 0,
        "failed": 0,
        "skipped": 0,
        "needs_human_gate": 0,
        "unknown": 0,
    }
    for check in checks:
        if not isinstance(check, dict):
            continue
        record = _canonical_verifier_record(check)
        records.append(record)
        status = str(record.get("status", "") or "")
        if status in counts:
            counts[status] += 1
        else:
            counts["unknown"] += 1
    blocking = (
        counts["failed"]
        + counts["repairing"]
        + counts["needs_human_gate"]
        + counts["pending"]
        + counts["unknown"]
    )
    overall = "passed" if records and not blocking else "pending" if not records else "blocked"
    return {
        "schema_version": VERIFIER_SUMMARY_SCHEMA_VERSION,
        "overall": overall,
        "all_passed_or_pending_safe": bool(records) and blocking == 0,
        "counts": counts,
        "checks": records,
        "statement": (
            "Live provider verifiers are summarized as green checks or pending-safe "
            "checks before launch readiness and detonation proof are trusted. Optional "
            "skipped verifier rows are recorded for transparency but do not count as "
            "provider or live-app launch proof."
        ),
    }


def _canonical_verifier_record(check: dict[str, Any]) -> dict[str, Any]:
    provider = _public_verifier_text(check.get("provider", ""))
    check_name = _public_verifier_text(check.get("check", ""), fallback="provider_status")
    raw_status = _public_verifier_text(check.get("status", ""))
    invalid_identity = provider is None or check_name is None or raw_status is None
    provider = provider or "unknown"
    check_name = check_name or "provider_status"
    raw_status = raw_status or "unknown"
    details = check.get("details", {})
    details = details if isinstance(details, dict) else {}
    pending_safe = raw_status == "pending_safe" or (
        raw_status == "pending" and details.get("pending_safe") is True
    )
    effective_status = "pending_safe" if pending_safe else raw_status
    if invalid_identity:
        effective_status = "unknown"
        pending_safe = False
    return {
        "provider": provider,
        "check": check_name,
        "status": effective_status,
        "pending_safe": pending_safe,
    }


def _public_verifier_text(value: object, *, fallback: str = "") -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        text = fallback
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in ("token=", "password=", "secret=", "api_key=")):
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _audit_trail_summary(
    root: Path,
    gates: list[dict[str, Any]],
    wake_events: list[dict[str, Any]],
    receipt: dict[str, Any],
    workspace_detonation: dict[str, Any],
    vault_index: list[dict[str, Any]],
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    known_gates = {str(gate.get("id", "") or ""): gate for gate in gates}
    for event in wake_events:
        if not isinstance(event, dict):
            continue
        entries.extend(_audit_entries_from_wake_event(event, known_gates))
    entries.extend(_audit_entries_from_receipt(receipt))
    entries.extend(_audit_entries_from_audit_log(root / "audit.jsonl"))
    entries.extend(_audit_entries_from_workspace_detonation(workspace_detonation))
    for record in vault_index:
        if not isinstance(record, dict):
            continue
        entries.append(
            {
                "category": "credential_capture",
                "action": "vault.record",
                "provider": str(record.get("provider", "") or ""),
                "status": "stored",
                "source": "vault_index",
                "summary": "Encrypted vault metadata records an approved credential capture.",
            }
        )
    entries = _dedupe_audit_entries(entries)
    counts: dict[str, int] = {}
    for entry in entries:
        category = str(entry.get("category", "unknown") or "unknown")
        counts[category] = counts.get(category, 0) + 1
    return {
        "schema_version": AUDIT_TRAIL_SCHEMA_VERSION,
        "entry_count": len(entries),
        "counts": counts,
        "entries": entries,
        "statement": (
            "Credential captures, provider actions, DNS writes, human approvals, "
            "and detonation events are summarized from redacted runtime evidence "
            "without storing provider URLs, clipboard values, raw tokens, or secrets."
        ),
    }


def _audit_entries_from_wake_event(
    event: dict[str, Any],
    known_gates: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    event_name = str(event.get("event", "") or "")
    gate_id = str(event.get("gate_id", "") or "")
    gate = known_gates.get(gate_id, {})
    provider = str(event.get("provider", gate.get("provider", "")) or "")
    classification = str(event.get("classification", gate.get("classification", "")) or "")
    if event_name == "clipboard_captured":
        target = str(event.get("target", "") or "")
        return [
            {
                "category": "credential_capture",
                "action": "control_room.capture_vm_clipboard",
                "provider": provider,
                "target": target,
                "status": "captured",
                "source": "gate_events.jsonl",
                "wake_event_id": str(event.get("id", "") or ""),
                "summary": f"{target or 'Provider value'} was captured from the VM clipboard.",
            }
        ]
    if event_name == "resume_requested":
        action = (
            "control_room.approve_dns_apply"
            if classification == "dns-approval"
            else ("control_room.confirm_gate_finished")
        )
        return [
            {
                "category": "human_approval",
                "action": action,
                "provider": provider,
                "status": "approved",
                "source": "gate_events.jsonl",
                "wake_event_id": str(event.get("id", "") or ""),
                "summary": "A visible control-room approval woke the setup worker.",
            }
        ]
    return []


def _audit_entries_from_receipt(receipt: dict[str, Any]) -> list[dict[str, Any]]:
    actions = receipt.get(SETUP_RECEIPT_ACTIONS_FIELD, [])
    if not isinstance(actions, list):
        return []
    entries: list[dict[str, Any]] = []
    for receipt_action_index, action in enumerate(actions, start=1):
        if not isinstance(action, dict):
            continue
        action_name = str(action.get(SETUP_RECEIPT_ACTION_NAME_FIELD, "") or "").strip()
        if not action_name:
            continue
        category = _receipt_action_category(action_name)
        entries.append(
            {
                "category": category,
                "action": action_name,
                "provider": _provider_from_action(action_name),
                "status": str(
                    action.get(SETUP_RECEIPT_ACTION_STATUS_FIELD, "") or "recorded"
                ),
                "source": "setup_receipt.json",
                "receipt_action_index": receipt_action_index,
                "summary": _receipt_action_summary(category, action_name),
            }
        )
    return entries


def _audit_entries_from_workspace_detonation(
    workspace_detonation: dict[str, Any],
) -> list[dict[str, Any]]:
    """Summarize OCI detonation proof without embedding provider/resource secrets."""

    status = str(workspace_detonation.get("status", "") or "").strip()
    if not status:
        return []
    entries: list[dict[str, Any]] = [
        {
            "category": "detonation",
            "action": "oci.workspace.detonate",
            "provider": "oci",
            "status": status,
            "source": "workspace_detonation.json",
            "summary": "FuseKit recorded disposable OCI worker and workspace cleanup.",
        }
    ]
    deleted = workspace_detonation.get("deleted", [])
    if isinstance(deleted, list):
        for resource in sorted({str(item).strip() for item in deleted if str(item).strip()}):
            entries.append(
                {
                    "category": "detonation",
                    "action": _detonation_resource_action(resource),
                    "provider": "oci",
                    "resource": resource,
                    "status": _detonation_resource_status(resource),
                    "source": "workspace_detonation.json",
                    "summary": _detonation_resource_summary(resource),
                }
            )
    failures = workspace_detonation.get("failures", {})
    if isinstance(failures, dict):
        for resource in sorted(str(key).strip() for key in failures if str(key).strip()):
            entries.append(
                {
                    "category": "detonation",
                    "action": "oci.workspace.resource_delete_failed",
                    "provider": "oci",
                    "resource": resource,
                    "status": "failed",
                    "source": "workspace_detonation.json",
                    "summary": (
                        "FuseKit recorded an OCI cleanup failure for this resource class; "
                        "review workspace_detonation.json for the redacted provider error."
                    ),
                }
            )
    return entries


def _detonation_resource_action(resource: str) -> str:
    normalized = resource.replace("-", "_")
    if normalized == "remote_worker":
        return "oci.workspace.remote_worker_state.deleted"
    if normalized == "ephemeral_public_ip":
        return "oci.workspace.ephemeral_public_ip.released"
    return f"oci.workspace.{normalized}.deleted"


def _detonation_resource_status(resource: str) -> str:
    return "released" if resource.replace("-", "_") == "ephemeral_public_ip" else "deleted"


def _detonation_resource_summary(resource: str) -> str:
    normalized = resource.replace("-", "_")
    if normalized == "remote_worker":
        return "FuseKit deleted disposable worker files, browser state, logs, and helpers."
    if normalized == "instance":
        return "FuseKit terminated the disposable OCI VM."
    if normalized == "boot_volume":
        return "FuseKit verified the disposable OCI boot volume was deleted."
    if normalized == "ephemeral_public_ip":
        return "FuseKit verified the ephemeral public IP was released."
    if normalized in {
        "internet_gateway",
        "network_security_group",
        "route_table",
        "security_list",
        "subnet",
        "vcn",
    }:
        return "FuseKit deleted a disposable OCI network resource."
    return "FuseKit recorded deletion of a disposable OCI workspace resource."


def _audit_entries_from_audit_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        raw_event_name = str(raw.get("event", "") or "").strip()
        if not raw_event_name:
            continue
        event_name = _redacted_error_text(raw_event_name)
        entries.append(
            {
                "category": _audit_event_category(raw_event_name),
                "action": event_name,
                "provider": _provider_from_action(raw_event_name),
                "status": "recorded",
                "source": "audit.jsonl",
                "audit_log_index": line_number,
                "summary": _audit_event_summary(event_name),
            }
        )
    return entries


def _receipt_action_category(action_name: str) -> str:
    lowered = action_name.lower()
    if "dns" in lowered and ("apply" in lowered or "record" in lowered):
        return "dns_write"
    if "vault" in lowered or "secret" in lowered or "token" in lowered:
        return "credential_capture"
    if "approval" in lowered or "approve" in lowered:
        return "human_approval"
    return "provider_action"


def _audit_event_category(event_name: str) -> str:
    lowered = event_name.lower()
    if "capture" in lowered or "vault" in lowered:
        return "credential_capture"
    if "approval" in lowered or "resume" in lowered:
        return "human_approval"
    if "dns" in lowered and ("apply" in lowered or "record" in lowered):
        return "dns_write"
    if "detonation" in lowered or "detonate" in lowered:
        return "detonation"
    return "provider_action"


def _provider_from_action(action_name: str) -> str:
    prefix = action_name.split(".", 1)[0].strip().lower()
    if prefix in {"dns", "cloudflare", "github", "resend", "vercel", "oci", "openai"}:
        return prefix
    return ""


def _receipt_action_summary(category: str, action_name: str) -> str:
    if category == "dns_write":
        return "FuseKit recorded a DNS write or DNS-record apply action."
    if category == "credential_capture":
        return "FuseKit recorded credential material only through encrypted/redacted handling."
    if category == "human_approval":
        return "FuseKit recorded an explicit human approval."
    return f"FuseKit recorded provider action {action_name}."


def _audit_event_summary(event_name: str) -> str:
    return f"FuseKit recorded audit event {event_name} with secret values redacted."


def _dedupe_audit_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str, str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for entry in entries:
        category = _public_audit_text(entry.get("category", ""))
        action = _public_audit_text(entry.get("action", ""))
        status = _public_audit_text(entry.get("status", ""), fallback="recorded")
        source = _public_audit_text(entry.get("source", ""))
        summary = _public_audit_text(
            entry.get("summary", ""),
            fallback="FuseKit recorded redacted runtime evidence.",
        )
        if (
            category not in AUDIT_TRAIL_CATEGORIES
            or action is None
            or status is None
            or source is None
            or summary is None
        ):
            continue
        normalized: dict[str, Any] = {
            "category": category,
            "action": action,
            "provider": _public_audit_text(entry.get("provider", "")) or "",
            "status": status,
            "source": source,
            "summary": summary,
        }
        target = _public_audit_text(entry.get("target", ""))
        if target:
            normalized["target"] = target
        wake_event_id = _public_audit_text(entry.get("wake_event_id", ""))
        if wake_event_id:
            normalized["wake_event_id"] = wake_event_id
        audit_log_index = entry.get("audit_log_index")
        if audit_log_index is not None:
            normalized["audit_log_index"] = _safe_int(audit_log_index, 0)
        receipt_action_index = entry.get("receipt_action_index")
        if receipt_action_index is not None:
            normalized["receipt_action_index"] = _safe_int(receipt_action_index, 0)
        resource = _public_audit_text(entry.get("resource", ""))
        if resource:
            normalized["resource"] = resource
        key = (
            normalized["category"],
            normalized["action"],
            normalized["provider"],
            normalized.get("target", ""),
            normalized.get("wake_event_id", ""),
            normalized.get("resource", ""),
            str(normalized.get("audit_log_index", "")),
            str(normalized.get("receipt_action_index", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(normalized)
    return unique


def _public_audit_text(value: object, *, fallback: str = "") -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        text = fallback
    if not text:
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _acceptance_summary(
    acceptance: dict[str, Any],
    *,
    errors: list[dict[str, Any]] | None = None,
    recording_contract: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not acceptance:
        return {}
    missing = _acceptance_missing_summary(acceptance.get("missing", []))
    blockers = _acceptance_blocker_summary(acceptance.get("blockers", []), missing)
    mode = acceptance.get("mode")
    mode = mode if mode in {"live", "rehearsal"} else ""
    error = _redacted_error_text(acceptance.get("error", "")).strip()
    has_errors = bool(error) or bool(errors)
    launch_ready = (
        acceptance.get("launch_ready") is True
        and not missing
        and not blockers
        and not has_errors
    )
    public_launch_ready = mode == "live" and launch_ready
    remote_artifacts_ready = _acceptance_remote_artifacts_ready(acceptance)
    recording_contract_ready = (
        isinstance(recording_contract, dict)
        and recording_contract.get("recording_ready") is True
    )
    recording_proof_ready = (
        acceptance.get("recording_proof_ready") is True
        and remote_artifacts_ready
        and recording_contract_ready
    )
    recording_ready = public_launch_ready and recording_proof_ready
    return {
        "mode": mode,
        "launch_ready": launch_ready,
        "public_launch_ready": public_launch_ready,
        "remote_artifacts_ready": remote_artifacts_ready,
        "recording_proof_ready": recording_proof_ready,
        "recording_ready": recording_ready,
        "missing": missing,
        "blockers": blockers,
        "error": error,
    }


def _acceptance_remote_artifacts_ready(acceptance: dict[str, Any]) -> bool:
    if acceptance.get("remote_artifacts_ready") is True:
        return True
    checks = acceptance.get("checks", [])
    if not isinstance(checks, list):
        return False
    return any(
        isinstance(check, dict)
        and check.get("id") == "remote_artifacts.loaded"
        and check.get("status") == "ok"
        for check in checks
    )


def _acceptance_missing_summary(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    seen: set[str] = set()
    missing: list[str] = []
    for item in value:
        text = _redacted_error_text(item).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        missing.append(text)
    return missing


def _acceptance_blocker_summary(value: object, missing: list[str]) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    seen_items: set[str] = set()
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, dict):
                continue
            blocker = _acceptance_blocker_card(item)
            if blocker is None:
                continue
            blocker_item = blocker["item"]
            if blocker_item in seen_items:
                continue
            seen_items.add(blocker_item)
            blockers.append(blocker)
    for item in missing:
        if item in seen_items:
            continue
        seen_items.add(item)
        blockers.append(
            {
                "item": item,
                "category": "Launch evidence",
                "next_action": (
                    "Keep the control room open while FuseKit rebuilds this "
                    "launch-evidence proof."
                ),
            }
        )
    return blockers


def _acceptance_blocker_card(item: dict[str, Any]) -> dict[str, str] | None:
    blocker: dict[str, str] = {}
    for key in ACCEPTANCE_BLOCKER_REQUIRED_FIELDS:
        value = _redacted_error_text(item.get(key, "")).strip()
        if not value:
            return None
        blocker[key] = value
    detail = _redacted_error_text(item.get("detail", "")).strip()
    if detail:
        blocker["detail"] = detail
    return blocker


def _detonation_summary(
    run_state: dict[str, Any],
    workspace_detonation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "preflight_safe": run_state.get("detonation_safe") is True,
        "workspace_detonated": run_state.get("workspace_detonated") is True,
        "workspace_receipt": _canonical_workspace_detonation_receipt(
            workspace_detonation
        ),
    }


def _align_detonation_preflight_summary(
    record: dict[str, Any],
    run_state: dict[str, Any],
) -> None:
    detonation = record.get("detonation")
    if not isinstance(detonation, dict):
        return
    contract = record.get("recording_contract", {})
    checks = contract.get("checks", {}) if isinstance(contract, dict) else {}
    non_detonation_ready = (
        isinstance(checks, dict)
        and all(
            checks.get(key) is True
            for key in RECORDING_CONTRACT_CHECK_KEYS
            if key != "detonation"
        )
    )
    aligned = dict(detonation)
    aligned["preflight_safe"] = (
        run_state.get("detonation_safe") is True and non_detonation_ready
    )
    record["detonation"] = aligned


def _canonical_workspace_detonation_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    if not receipt:
        return {}
    summary = _canonical_workspace_detonation_resource_summary(
        receipt.get("resource_summary", {})
    )
    canonical: dict[str, Any] = {
        "status": _public_detonation_text(receipt.get("status", ""), fallback="")
        or "",
        "reason": _public_detonation_text(receipt.get("reason", ""), fallback="")
        or "",
        "deleted": _public_detonation_text_list(receipt.get("deleted", [])),
        "failures": _public_detonation_failures(receipt.get("failures", {})),
        "resource_summary": summary,
    }
    updated_at = _public_detonation_timestamp(receipt.get("updated_at"))
    if updated_at is not None:
        canonical["updated_at"] = updated_at
    return canonical


def _canonical_workspace_detonation_resource_summary(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    summary: dict[str, Any] = {}
    for key in WORKSPACE_DETONATION_RESOURCE_SUMMARY_TEXT_FIELDS:
        summary[key] = (
            _public_detonation_text(
                value.get(key, ""),
                fallback="",
                allow_redacted_secret_marker=key == "statement",
            )
            or ""
        )
    for key in WORKSPACE_DETONATION_RESOURCE_SUMMARY_BOOLEAN_FIELDS:
        if isinstance(value.get(key), bool):
            summary[key] = value.get(key)
    summary["remote_worker_cleanup"] = _canonical_remote_worker_cleanup_receipt(
        value.get("remote_worker_cleanup", {})
    )
    for key in WORKSPACE_DETONATION_RESOURCE_SUMMARY_LIST_FIELDS:
        summary[key] = _public_detonation_text_list(value.get(key, []))
    return summary


def _canonical_remote_worker_cleanup_receipt(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    cleanup: dict[str, Any] = {}
    for key in REMOTE_WORKER_CLEANUP_RECEIPT_TEXT_FIELDS:
        cleanup[key] = _public_detonation_text(value.get(key, ""), fallback="") or ""
    if isinstance(value.get("host_machine_state_required"), bool):
        cleanup["host_machine_state_required"] = value.get("host_machine_state_required")
    for key in REMOTE_WORKER_CLEANUP_RECEIPT_LIST_FIELDS:
        cleanup[key] = _public_detonation_text_list(value.get(key, []))
    return cleanup


def _public_detonation_failures(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    failures: dict[str, str] = {}
    for key, raw_detail in value.items():
        public_key = _public_detonation_text(key, fallback="")
        public_detail = _public_detonation_text(raw_detail, fallback="")
        if public_key is None or public_detail is None:
            failures["redacted_failure"] = "Workspace detonation failure detail redacted."
            continue
        if not public_key:
            public_key = "workspace_detonation"
        if not public_detail:
            public_detail = "Workspace detonation failure detail omitted."
        failures[public_key] = public_detail
    return failures


def _public_detonation_text_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = _public_detonation_text(item, fallback="")
        if text is None or not text or text in seen:
            continue
        seen.add(text)
        items.append(text)
    return items


def _public_detonation_text(
    value: object,
    *,
    fallback: str = "",
    allow_redacted_secret_marker: bool = False,
) -> str | None:
    text = _redacted_error_text(value).strip()
    if not text:
        text = fallback
    if not text:
        return None
    lowered = text.lower()
    if any(
        marker in lowered
        for marker in ("token=", "password=", "secret=", "api_key=")
    ) and not allow_redacted_secret_marker:
        return None
    if contains_durable_secret_text(text):
        return None
    return text


def _public_detonation_timestamp(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return max(0.0, float(value))


def _recording_contract_summary(record: dict[str, Any]) -> dict[str, Any]:
    """Summarize whether the OCI lane is safe to demo-record and publish."""

    checks_by_name = {
        "durable_state": _recording_durable_state_ready(record),
        "worker_replacement": _recording_worker_replacement_ready(record),
        "runner_profile": _recording_runner_profile_ready(record),
        "provider_playbook": _recording_provider_playbook_ready(record),
        "model_inference": _recording_model_inference_ready(record),
        "timeline": _recording_timeline_ready(record),
        "provider_gates": _recording_provider_gates_ready(record),
        "vault": _recording_vault_ready(record),
        "wake_events": _recording_wake_events_ready(record),
        "human_actions": _recording_human_actions_ready(record),
        "rehearsal_review": _recording_rehearsal_review_ready(record),
        "automation_boundary": _recording_automation_boundary_ready(record),
        "control_room_security": _recording_control_room_security_ready(record),
        "verifiers": _recording_verifiers_ready(record),
        "audit_trail": _recording_audit_trail_ready(record),
        "artifacts": _recording_artifacts_ready(record),
        "evidence": _recording_evidence_ready(record),
        "detonation": _recording_detonation_ready(record),
        "errors_empty": not record.get("errors"),
    }
    checks = {key: checks_by_name[key] for key in RECORDING_CONTRACT_CHECK_KEYS}
    blockers = [name for name, ready in checks.items() if ready is not True]
    return {
        "schema_version": RECORDING_CONTRACT_SCHEMA_VERSION,
        "recording_ready": not blockers,
        "checks": checks,
        "blockers": blockers,
        "statement": (
            "A public demo is recordable only when the Run Record proves durable "
            "OCI state, worker replacement from encrypted/redacted sources, the "
            "x86 visual runner, ordered provider playbooks, verified model inference, "
            "guided human actions, rehearsal review against control-room instructions, "
            "post-gate automation, a protected control-room mutation surface, live "
            "provider verifiers, audit evidence, and no-trace detonation all agree."
        ),
    }


def _recording_timeline_ready(record: dict[str, Any]) -> bool:
    steps = record.get("steps", [])
    checkpoints = record.get("checkpoints", [])
    return _recording_timeline_entries_ready(
        steps,
        allowed_keys=TIMELINE_STEP_KEYS,
        optional_text_fields=TIMELINE_STEP_OPTIONAL_TEXT_FIELDS,
    ) and _recording_timeline_entries_ready(
        checkpoints,
        allowed_keys=TIMELINE_CHECKPOINT_KEYS,
        optional_text_fields=TIMELINE_CHECKPOINT_OPTIONAL_TEXT_FIELDS,
    )


def _recording_timeline_entries_ready(
    entries: object,
    *,
    allowed_keys: frozenset[str],
    optional_text_fields: tuple[str, ...],
) -> bool:
    if not isinstance(entries, list):
        return False
    seen_ids: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            return False
        if set(entry) - allowed_keys:
            return False
        entry_id = entry.get("id", "")
        if not _recording_exact_nonempty_text(entry_id):
            return False
        for field in TIMELINE_REQUIRED_TEXT_FIELDS[1:]:
            if not _recording_exact_nonempty_text(entry.get(field, "")):
                return False
        for field in optional_text_fields:
            value = entry.get(field, "")
            if value is None:
                continue
            if not isinstance(value, str):
                return False
            if value and value != value.strip():
                return False
            if contains_durable_secret_text(value):
                return False
        updated_at = entry.get("updated_at", 0)
        if not isinstance(updated_at, int | float) or isinstance(updated_at, bool):
            return False
        if updated_at < 0:
            return False
        entry_id = str(entry_id)
        if entry_id in seen_ids:
            return False
        seen_ids.add(entry_id)
    return True


def _recording_artifacts_ready(record: dict[str, Any]) -> bool:
    artifacts = record.get("artifacts", [])
    if not isinstance(artifacts, list):
        return False
    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            return False
        if set(artifact) - ARTIFACT_RECORD_KEYS:
            return False
        name = artifact.get("name", "")
        path = artifact.get("path", "")
        if not _recording_exact_nonempty_text(name):
            return False
        if not _recording_public_relative_path(path):
            return False
        name = str(name)
        path = str(path)
        if artifact.get("exists") not in {True, False}:
            return False
        if name in seen_names or path in seen_paths:
            return False
        if contains_durable_secret_text(name):
            return False
        if any(marker in name.lower() for marker in ("token=", "password=", "secret=")):
            return False
        seen_names.add(name)
        seen_paths.add(path)
    return True


def _recording_vault_ready(record: dict[str, Any]) -> bool:
    vault = record.get("vault", {})
    if not isinstance(vault, dict):
        return False
    if set(vault) - VAULT_KEYS:
        return False
    records = vault.get("records", [])
    if not isinstance(records, list):
        return False
    record_count = vault.get("record_count")
    if not isinstance(record_count, int) or isinstance(record_count, bool):
        return False
    if record_count != len(records):
        return False
    seen_record_ids: set[str] = set()
    for vault_record in records:
        if not isinstance(vault_record, dict):
            return False
        if set(vault_record) - VAULT_RECORD_KEYS:
            return False
        for field in ("id", "kind", "provider", "label"):
            value = vault_record.get(field, "")
            if not _recording_exact_nonempty_text(value):
                return False
            if contains_durable_secret_text(str(value)):
                return False
        record_id = str(vault_record.get("id", ""))
        if not record_id or record_id in seen_record_ids:
            return False
        seen_record_ids.add(record_id)
        if _vault_record_exposes_secret_field(vault_record):
            return False
    return True


def _vault_record_exposes_secret_field(value: object) -> bool:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).strip().lower() in VAULT_SECRET_FIELD_NAMES:
                return True
            if _vault_record_exposes_secret_field(nested):
                return True
    if isinstance(value, list):
        return any(_vault_record_exposes_secret_field(item) for item in value)
    return False


def _recording_provider_gates_ready(record: dict[str, Any]) -> bool:
    provider_gates = record.get("provider_gates", {})
    if not isinstance(provider_gates, dict):
        return False
    if set(provider_gates) - PROVIDER_GATES_KEYS:
        return False
    records = provider_gates.get("records", [])
    statuses = provider_gates.get("statuses", {})
    providers = provider_gates.get("providers", [])
    if (
        not isinstance(records, list)
        or not isinstance(statuses, dict)
        or not isinstance(providers, list)
    ):
        return False
    if not all(_recording_exact_nonempty_text(provider) for provider in providers):
        return False
    if _safe_int(provider_gates.get("total"), -1) != len(records):
        return False
    actual_statuses: dict[str, int] = {}
    actual_providers: set[str] = set()
    seen_gate_ids: set[str] = set()
    for gate in records:
        if not isinstance(gate, dict):
            return False
        if not _recording_provider_gate_exact(gate):
            return False
        gate_id = str(gate.get("id", "") or "").strip()
        if not gate_id or gate_id in seen_gate_ids:
            return False
        seen_gate_ids.add(gate_id)
        status = str(gate.get("status", "") or "").strip()
        if not status:
            return False
        actual_statuses[status] = actual_statuses.get(status, 0) + 1
        provider = str(gate.get("provider", "") or "").strip()
        if provider:
            actual_providers.add(provider)
    if set(str(provider) for provider in providers) != actual_providers:
        return False
    status_keys = {str(key) for key in statuses}
    if status_keys != set(actual_statuses):
        return False
    return all(
        _safe_int(statuses.get(status), -1) == count
        for status, count in actual_statuses.items()
    )


def _recording_provider_gate_exact(gate: dict[str, Any]) -> bool:
    if set(gate) - PROVIDER_GATE_RECORD_KEYS:
        return False
    for key in (
        "id",
        "provider",
        "status",
        "classification",
        "target",
        "reason",
        "resume_url",
        "last_opened_url",
        "next_action",
        "resume_hint",
        "last_wake_event",
        "last_wake_event_id",
    ):
        value = gate.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            return False
        if value and value != value.strip():
            return False
    captured_targets = gate.get("captured_targets", [])
    if captured_targets is not None:
        if not isinstance(captured_targets, list):
            return False
        if not all(isinstance(item, str) and item == item.strip() for item in captured_targets):
            return False
    follow_steps = gate.get("follow_steps", [])
    if follow_steps is not None:
        if not isinstance(follow_steps, list):
            return False
        if not all(isinstance(item, str) and item == item.strip() for item in follow_steps):
            return False
    success_criteria = gate.get("success_criteria", [])
    if success_criteria is not None:
        if not isinstance(success_criteria, list):
            return False
        if not all(isinstance(item, str) and item == item.strip() for item in success_criteria):
            return False
    avoid_steps = gate.get("avoid_steps", [])
    if avoid_steps is not None:
        if not isinstance(avoid_steps, list):
            return False
        if not all(isinstance(item, str) and item == item.strip() for item in avoid_steps):
            return False
    attempts = gate.get("attempts", 0)
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
        return False
    for key in ("last_opened_at", "last_wake_event_at", "created_at", "updated_at"):
        value = gate.get(key, 0)
        if not isinstance(value, int | float) or isinstance(value, bool) or value < 0:
            return False
    return True


def _recording_wake_events_ready(record: dict[str, Any]) -> bool:
    wake_events = record.get("wake_events", {})
    if not isinstance(wake_events, dict):
        return False
    if set(wake_events) - WAKE_EVENTS_KEYS:
        return False
    events = wake_events.get("events", [])
    counts = wake_events.get("event_counts", {})
    if not isinstance(events, list) or not isinstance(counts, dict):
        return False
    total = wake_events.get("total")
    if not isinstance(total, int) or isinstance(total, bool):
        return False
    if total != len(events):
        return False
    actual_counts: dict[str, int] = {}
    seen_event_ids: set[str] = set()
    seen_event_proofs: set[tuple[str, str, str]] = set()
    for event in events:
        if not isinstance(event, dict):
            return False
        if not _recording_wake_event_exact(event):
            return False
        event_name = str(event.get("event", "") or "").strip()
        gate_id = str(event.get("gate_id", "") or "").strip()
        if not event_name or not gate_id:
            return False
        actual_counts[event_name] = actual_counts.get(event_name, 0) + 1
        event_id = str(event.get("id", "") or "").strip()
        if event_id:
            if event_id in seen_event_ids:
                return False
            seen_event_ids.add(event_id)
        identity = (event_name, gate_id, str(event.get("target", "") or "").strip())
        if identity in seen_event_proofs:
            return False
        seen_event_proofs.add(identity)
    if {str(name) for name in counts} != set(actual_counts):
        return False
    for name, count in counts.items():
        if not _recording_exact_nonempty_text(name):
            return False
        if not isinstance(count, int) or isinstance(count, bool):
            return False
        if actual_counts.get(name) != count:
            return False
    return True


def _recording_wake_event_exact(event: dict[str, Any]) -> bool:
    if set(event) - WAKE_EVENT_RECORD_KEYS:
        return False
    for key in (
        "schema_version",
        "id",
        "event",
        "gate_id",
        "provider",
        "classification",
        "status",
        "target",
    ):
        value = event.get(key, "")
        if not isinstance(value, str):
            return False
        if value and value != value.strip():
            return False
        if value and contains_durable_secret_text(value):
            return False
    if not event.get("schema_version") or not event.get("event") or not event.get("gate_id"):
        return False
    target_count = event.get("target_count", 0)
    if not isinstance(target_count, int) or isinstance(target_count, bool) or target_count < 0:
        return False
    captured_targets = event.get("captured_targets", [])
    if not isinstance(captured_targets, list):
        return False
    if not all(
        isinstance(item, str)
        and item == item.strip()
        and not contains_durable_secret_text(item)
        for item in captured_targets
    ):
        return False
    created_at = event.get("created_at", 0)
    return (
        isinstance(created_at, int | float)
        and not isinstance(created_at, bool)
        and created_at >= 0
    )


def _recording_durable_state_ready(record: dict[str, Any]) -> bool:
    durable = record.get("durable_state", {})
    if not isinstance(durable, dict):
        return False
    scope = durable.get("detonation_scope", {})
    replacement = durable.get("worker_replacement_contract", {})
    sources = durable.get("sources", [])
    runner_failures = durable.get("runner_profile_failures", [])
    volatile_surfaces = durable.get("volatile_worker_surfaces", [])
    preserves = durable.get("detonation_preserves", [])
    if (
        not isinstance(scope, dict)
        or not isinstance(replacement, dict)
        or not isinstance(sources, list)
        or not isinstance(runner_failures, list)
        or not isinstance(volatile_surfaces, list)
        or not isinstance(preserves, list)
    ):
        return False
    if (
        _recording_duplicate_durable_source_ids(sources)
        or _recording_duplicate_text_values(volatile_surfaces)
        or _recording_duplicate_text_values(preserves)
    ):
        return False
    required_sources = {source[0] for source in DURABLE_STATE_SOURCES}
    source_ids = {
        str(source.get("id", "") or "")
        for source in sources
        if isinstance(source, dict) and source.get("exists") is True
    }
    preserve_values = {str(item) for item in preserves}
    scope_preserves = scope.get("must_preserve", [])
    scope_deletes = scope.get("must_delete", [])
    if not isinstance(scope_preserves, list) or not isinstance(scope_deletes, list):
        return False
    if _recording_duplicate_text_values(scope_preserves) or _recording_duplicate_text_values(
        scope_deletes
    ):
        return False
    return (
        str(durable.get("schema_version", "") or "") == DURABLE_STATE_SCHEMA_VERSION
        and durable.get("resume_ready") is True
        and durable.get("runner_profile_ready") is True
        and not runner_failures
        and not durable.get("missing")
        and all(
            term in str(durable.get("statement", "") or "")
            for term in DURABLE_STATE_STATEMENT_TERMS
        )
        and required_sources.issubset(source_ids)
        and all(_recording_durable_source_ready(source) for source in sources)
        and set(VOLATILE_WORKER_SURFACES).issubset({str(item) for item in volatile_surfaces})
        and preserve_values == set(DETONATION_PRESERVES)
        and not any(_recording_volatile_marker(item) for item in preserve_values)
        and str(scope.get("schema_version", "") or "") == DETONATION_SCOPE_SCHEMA_VERSION
        and scope.get("resume_until_complete") is True
        and scope.get("host_machine_state_required") is False
        and str(scope.get("mode", "") or "") == AUTOMATION_BOUNDARY_DETONATION_SCOPE
        and set(VOLATILE_WORKER_SURFACES).issubset({str(item) for item in scope_deletes})
        and {str(item) for item in scope_preserves} == preserve_values
        and not any(_recording_volatile_marker(item) for item in scope_preserves)
        and replacement.get("can_recreate_worker") is True
        and replacement.get("host_machine_state_required") is False
        and all(
            term in str(scope.get("no_trace_statement", "") or "")
            for term in DETONATION_SCOPE_NO_TRACE_TERMS
        )
    )


def _recording_durable_source_ready(source: object) -> bool:
    if not isinstance(source, dict):
        return False
    source_id = str(source.get("id", "") or "")
    path = str(source.get("path", "") or "")
    secret_class = str(source.get("secret_class", "") or "")
    expected_path = EXPECTED_DURABLE_STATE_SOURCE_PATHS.get(source_id)
    return (
        bool(source_id)
        and bool(path)
        and expected_path is not None
        and path == expected_path
        and not path.startswith("/")
        and source.get("exists") is True
        and secret_class in {"encrypted", "non-secret"}
        and not _recording_durable_source_volatile_marker(source)
    )


def _recording_duplicate_durable_source_ids(sources: list[Any]) -> bool:
    seen_ids: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            continue
        source_id = str(source.get("id", "") or "").strip()
        if not source_id:
            continue
        if source_id in seen_ids:
            return True
        seen_ids.add(source_id)
    return False


def _recording_duplicate_text_values(values: list[Any]) -> bool:
    seen_values: set[str] = set()
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        if text in seen_values:
            return True
        seen_values.add(text)
    return False


def _recording_durable_source_volatile_marker(source: dict[str, Any]) -> str:
    source_id = str(source.get("id", "") or "")
    if source_id == "worker_replacement_drill":
        return _recording_volatile_marker(str(source.get("role", "") or ""))
    return _recording_volatile_marker(
        " ".join(
            str(source.get(field, "") or "") for field in ("id", "path", "role")
        )
    )


def _recording_worker_replacement_ready(record: dict[str, Any]) -> bool:
    durable = record.get("durable_state", {})
    if not isinstance(durable, dict):
        return False
    if not _worker_replacement_drill_ready(record.get("worker_replacement_drill", {})):
        return False
    sources = durable.get("sources", [])
    if not isinstance(sources, list) or _recording_duplicate_durable_source_ids(sources):
        return False
    source_ids = {
        str(source.get("id", "") or "")
        for source in sources
        if isinstance(source, dict) and source.get("exists") is True
    }
    replacement = durable.get("worker_replacement_contract", {})
    if not isinstance(replacement, dict):
        return False
    resume_sources = replacement.get("resume_sources", [])
    volatile_surfaces = replacement.get("volatile_surfaces", [])
    if not isinstance(resume_sources, list) or not isinstance(volatile_surfaces, list):
        return False
    if _recording_duplicate_text_values(resume_sources) or _recording_duplicate_text_values(
        volatile_surfaces
    ):
        return False
    required_resume_sources = set(WORKER_REPLACEMENT_SOURCE_IDS)
    required_volatile = set(VOLATILE_WORKER_SURFACES)
    resume_source_values = {str(item) for item in resume_sources}
    volatile_surface_values = {str(item) for item in volatile_surfaces}
    return (
        replacement.get("worker_is_disposable") is True
        and replacement.get("can_recreate_worker") is True
        and replacement.get("runner_profile_ready") is True
        and str(replacement.get("required_runner_profile", "") or "")
        == EXPECTED_RUNNER_PROFILE
        and replacement.get("host_machine_state_required") is False
        and str(replacement.get("state_owner", "") or "")
        == WORKER_REPLACEMENT_STATE_OWNER
        and required_resume_sources.issubset(resume_source_values)
        and resume_source_values.issubset(source_ids)
        and not any(_recording_volatile_marker(item) for item in resume_source_values)
        and required_volatile.issubset(volatile_surface_values)
        and "encrypted/redacted" in str(replacement.get("statement", "") or "")
        and "host clipboard history" in str(replacement.get("statement", "") or "")
        and all(
            term in str(replacement.get("statement", "") or "")
            for term in WORKER_REPLACEMENT_STATEMENT_TERMS
        )
    )


def _worker_replacement_drill_ready(drill: object) -> bool:
    if not isinstance(drill, dict):
        return False
    if not _worker_replacement_drill_shape_ready(drill):
        return False
    restored_from = drill.get("restored_from", [])
    restored_values = (
        {str(item) for item in restored_from} if isinstance(restored_from, list) else set()
    )
    required_restore = set(WORKER_REPLACEMENT_SOURCE_IDS)
    statement = str(drill.get("statement", "") or "")
    if isinstance(restored_from, list) and _recording_duplicate_text_values(restored_from):
        return False
    return (
        str(drill.get("schema_version", "") or "") == WORKER_REPLACEMENT_DRILL_SCHEMA_VERSION
        and str(drill.get("status", "") or "") == "passed"
        and drill.get("worker_destroyed") is True
        and drill.get("replacement_runner_profile_ready") is True
        and drill.get("control_room_reopened") is True
        and drill.get("resume_checkpoint_restored") is True
        and drill.get("gate_or_verifier_resumed") is True
        and drill.get("host_machine_state_required") is False
        and drill.get("volatile_state_reused") is False
        and restored_values == required_restore
        and not any(_recording_volatile_marker(item) for item in restored_values)
        and "encrypted/redacted" in statement
        and "no host-machine state" in statement
        and "no VM-local plaintext" in statement
    )


def _worker_replacement_drill_shape_ready(drill: dict[str, Any]) -> bool:
    if set(drill) - WORKER_REPLACEMENT_DRILL_KEYS:
        return False
    for field in ("schema_version", "status", "statement", "pending_reason"):
        if field not in drill:
            continue
        value = drill.get(field)
        if not isinstance(value, str) or value != value.strip():
            return False
        if _recording_public_text_is_unsafe(value):
            return False
    restored_from = drill.get("restored_from")
    if restored_from is not None:
        if not isinstance(restored_from, list):
            return False
        for item in restored_from:
            if (
                not isinstance(item, str)
                or not item
                or item != item.strip()
                or _recording_public_text_is_unsafe(item)
            ):
                return False
        if _recording_duplicate_text_values(restored_from):
            return False
    for field in (
        "worker_destroyed",
        "replacement_runner_profile_ready",
        "control_room_reopened",
        "resume_checkpoint_restored",
        "gate_or_verifier_resumed",
        "host_machine_state_required",
        "volatile_state_reused",
    ):
        if field in drill and not isinstance(drill.get(field), bool):
            return False
    return not _recording_json_contains_public_unsafe_text(drill)


def _recording_json_contains_public_unsafe_text(value: object) -> bool:
    if isinstance(value, str):
        return _recording_public_text_is_unsafe(value)
    if isinstance(value, list):
        return any(_recording_json_contains_public_unsafe_text(item) for item in value)
    if isinstance(value, dict):
        return any(
            _recording_public_text_is_unsafe(str(key))
            or _recording_json_contains_public_unsafe_text(item)
            for key, item in value.items()
        )
    return False


def _recording_public_text_is_unsafe(value: str) -> bool:
    if re.search(r"https?://[^\s\"'<>]*callback[^\s\"'<>]*", value, re.IGNORECASE):
        return True
    return contains_durable_secret_text(value)


def _recording_volatile_marker(value: object) -> str:
    text = str(value or "").strip().lower().replace("_", "-")
    if not text:
        return ""
    if text == "worker-replacement-drill":
        return ""
    for marker in VOLATILE_DURABLE_STATE_MARKERS:
        normalized = marker.lower().replace("_", "-")
        if normalized in text:
            return marker
    return ""


def _recording_runner_profile_ready(record: dict[str, Any]) -> bool:
    runner = record.get("runner_profile", {})
    if not isinstance(runner, dict):
        return False
    return not runner_readiness_failures(_private_runner_readiness_for_validation(runner))


def _private_runner_readiness_for_validation(runner: dict[str, Any]) -> dict[str, Any]:
    """Map public Run Record labels back to validation-only runner paths."""

    private = dict(runner)
    profile = private.get("profile_contract", {})
    if isinstance(profile, dict):
        profile = dict(profile)
        browser_stack = profile.get("browser_stack", {})
        if isinstance(browser_stack, dict):
            browser_stack = dict(browser_stack)
            if browser_stack.get("shared_provider_profile") == PUBLIC_PROVIDER_BROWSER_PROFILE:
                browser_stack["shared_provider_profile"] = EXPECTED_PROVIDER_BROWSER_PROFILE
            profile["browser_stack"] = browser_stack
        private["profile_contract"] = profile
    if private.get("provider_browser_profile") == PUBLIC_PROVIDER_BROWSER_PROFILE:
        private["provider_browser_profile"] = EXPECTED_PROVIDER_BROWSER_PROFILE
    if private.get("playwright_browsers_path") == PUBLIC_PLAYWRIGHT_BROWSERS_PATH:
        private["playwright_browsers_path"] = "/opt/fusekit-playwright-browsers"
    return private


def _recording_model_inference_ready(record: dict[str, Any]) -> bool:
    model = record.get("model_inference", {})
    if not isinstance(model, dict):
        return False
    contract = record.get("llm_contract", {})
    if not isinstance(contract, dict):
        return False
    status = str(model.get("status", "") or "")
    next_action = str(model.get("next_action", "") or "")
    statement = str(model.get("statement", "") or "").lower()
    return (
        not (set(model) - MODEL_INFERENCE_KEYS)
        and model.get("schema_version") == "fusekit.model-inference-summary.v1"
        and model.get("ready") is True
        and status in {"api_key_encrypted", "openclaw_profile_encrypted"}
        and _recording_public_model_text(model.get("provider"))
        and _recording_public_model_text(model.get("model"))
        and _recording_public_model_text(model.get("base_url"), check_secretish=False)
        and _recording_public_model_text(model.get("api_key_env"))
        and _recording_public_model_text(model.get("auth_mode"))
        and str(model.get("auth_mode", "") or "") in {"auto", "api-key", "openclaw"}
        and isinstance(model.get("required"), bool)
        and isinstance(model.get("can_proceed_without_api_key"), bool)
        and _recording_public_model_text(model.get("default_lane"))
        and _recording_public_model_text(model.get("next_action"))
        and _recording_public_model_text(model.get("statement"))
        and ("encrypted" in next_action or "continue" in next_action)
        and "api keys are captured into the encrypted vault" in statement
        and "raw secrets never appear" in statement
        and _recording_llm_contract_ready(contract)
        and _recording_model_inference_contract_ready(model, contract)
    )


def _recording_llm_contract_ready(contract: dict[str, Any]) -> bool:
    status = str(contract.get("status", "") or "")
    lanes = contract.get("lanes")
    security = contract.get("security", {})
    return (
        not (set(contract) - LLM_CONTRACT_KEYS)
        and contract.get("schema_version") == "fusekit.llm-contract.v1"
        and status in {"api_key_encrypted", "openclaw_profile_encrypted"}
        and _recording_public_model_text(contract.get("provider"))
        and _recording_public_model_text(contract.get("model"))
        and _recording_public_model_text(contract.get("base_url"), check_secretish=False)
        and _recording_public_model_text(contract.get("api_key_env"))
        and _recording_public_model_text(contract.get("record_id"))
        and _recording_public_model_text(contract.get("auth_mode"))
        and str(contract.get("auth_mode", "") or "") in {"auto", "api-key", "openclaw"}
        and isinstance(contract.get("required"), bool)
        and isinstance(contract.get("can_proceed_without_api_key"), bool)
        and _recording_public_model_text(contract.get("next_action"))
        and isinstance(security, dict)
        and not set(security) - LLM_CONTRACT_SECURITY_KEYS
        and security.get("raw_secret_export") == "denied"
        and _recording_public_model_text(security.get("storage"))
        and _recording_public_model_text(security.get("public_surfaces"))
        and _recording_public_model_text(security.get("detonation"))
        and "encrypted" in str(security.get("storage", "") or "").lower()
        and "vault" in str(security.get("storage", "") or "").lower()
        and isinstance(lanes, list)
        and _recording_llm_contract_lanes_ready(lanes, contract)
    )


def _recording_llm_contract_lanes_ready(
    lanes: list[Any],
    contract: dict[str, Any],
) -> bool:
    if not lanes:
        return False
    seen: set[str] = set()
    lane_by_id: dict[str, dict[str, Any]] = {}
    for lane in lanes:
        if not isinstance(lane, dict):
            return False
        if set(lane) - LLM_CONTRACT_LANE_KEYS:
            return False
        if not _recording_public_model_text(lane.get("id")):
            return False
        lane_id = str(lane.get("id"))
        if lane_id in seen:
            return False
        seen.add(lane_id)
        lane_by_id[lane_id] = lane
        if not _recording_public_model_text(lane.get("label")):
            return False
        if not isinstance(lane.get("available"), bool):
            return False
        if not isinstance(lane.get("requires_user_action"), bool):
            return False
        if not _recording_public_model_text(lane.get("description")):
            return False
    default_lane = str(contract.get("default_lane", "") or "").strip()
    status = str(contract.get("status", "") or "")
    status_lane = {
        "api_key_encrypted": "api-key",
        "openclaw_profile_encrypted": "openclaw-openai",
    }.get(status)
    ready_lane_ids = {default_lane}
    if status_lane is not None:
        ready_lane_ids.add(status_lane)
    return (
        default_lane in seen
        and (status != "api_key_encrypted" or "api-key" in seen)
        and (status != "openclaw_profile_encrypted" or "openclaw-openai" in seen)
        and all(
            lane_by_id[lane_id].get("available") is True
            and lane_by_id[lane_id].get("requires_user_action") is False
            for lane_id in ready_lane_ids
            if lane_id in lane_by_id
        )
    )


def _recording_model_inference_contract_ready(
    model: dict[str, Any],
    contract: dict[str, Any],
) -> bool:
    fields = (
        "provider",
        "model",
        "base_url",
        "api_key_env",
        "auth_mode",
        "required",
        "can_proceed_without_api_key",
        "default_lane",
        "status",
    )
    if any(
        str(model.get(field, "") or "") != str(contract.get(field, "") or "")
        for field in fields
    ):
        return False
    if not isinstance(model.get("required"), bool):
        return False
    if not isinstance(model.get("can_proceed_without_api_key"), bool):
        return False
    lanes = contract.get("lanes", [])
    return isinstance(lanes, list) and _safe_int(model.get("lane_count"), -1) == len(lanes)


def _recording_provider_playbook_ready(record: dict[str, Any]) -> bool:
    playbook = record.get("provider_playbook", {})
    if not isinstance(playbook, dict):
        return False
    steps = playbook.get("steps", [])
    safety_notes = playbook.get("safety_notes", [])
    if (
        str(playbook.get("schema_version", "") or "") != "fusekit.provider-playbook.v1"
        or not isinstance(steps, list)
        or not steps
        or not isinstance(safety_notes, list)
        or not safety_notes
    ):
        return False
    if not all(
        isinstance(step, dict)
        and str(step.get("id", "") or "").strip()
        and str(step.get("instruction", "") or "").strip()
        and not _provider_playbook_instruction_unsafe(
            str(step.get("instruction", "") or "")
        )
        and str(step.get("provider", "") or "").strip()
        and _provider_playbook_step_route_ready(step)
        and _provider_playbook_step_actor_ready(step)
        and _provider_playbook_step_control_ready(step)
        and _provider_playbook_step_proof_ready(step)
        for step in steps
    ):
        return False
    if not _provider_playbook_provider_coverage_ready(steps):
        return False
    if _provider_playbook_order_failures(steps):
        return False
    joined = " ".join(str(note) for note in safety_notes)
    return (
        "VM browser" in joined
        and "Do not create Resend domains or audiences manually" in joined
        and "Do not paste provider secrets into the host computer" in joined
        and _provider_playbook_safety_notes_ready(safety_notes)
    )


def _provider_playbook_step_route_ready(step: dict[str, Any]) -> bool:
    return str(step.get("route", "") or "").strip() in {
        "api",
        "official_cli",
        "browser_guided",
        "human_follow_me",
        "local_vault",
    }


def _provider_playbook_provider_coverage_ready(steps: list[Any]) -> bool:
    providers = {
        str(step.get("provider", "") or "").strip().lower()
        for step in steps
        if isinstance(step, dict)
    }
    return all(
        bool(accepted & providers)
        for accepted in RECORDING_PROVIDER_PLAYBOOK_FAMILIES.values()
    )


def _provider_playbook_step_control_ready(step: dict[str, Any]) -> bool:
    step_id = str(step.get("id", "") or "").strip()
    route = str(step.get("route", "") or "").strip()
    control = str(step.get("control", "") or "").strip()
    if not control:
        return False
    if route == "api":
        return control == "FuseKit API worker"
    if route in {"browser_guided", "local_vault"}:
        if (
            step_id.startswith("resend.")
            and route == "browser_guided"
            and control != "Capture RESEND_API_KEY from VM clipboard"
        ):
            return False
        return control.startswith("Capture ") and control.endswith(" from VM clipboard")
    if route == "human_follow_me":
        return control in {
            "I finished this step",
            "Approve DNS apply",
            "Approve setup plan",
        }
    if route == "official_cli":
        return control in {"FuseKit CLI worker", "FuseKit API worker"}
    return False


def _provider_playbook_step_actor_ready(step: dict[str, Any]) -> bool:
    route = str(step.get("route", "") or "").strip()
    actor = str(step.get("actor", "") or "").strip()
    human_action_required = step.get("human_action_required")
    if route in {"api", "official_cli"}:
        return actor == "FuseKit" and human_action_required is False
    if route in {"browser_guided", "human_follow_me", "local_vault"}:
        return actor == "You" and human_action_required is True
    return False


def _provider_playbook_step_proof_ready(step: dict[str, Any]) -> bool:
    route = str(step.get("route", "") or "").strip()
    proof_source = str(step.get("proof_source", "") or "").strip()
    resume_event = str(step.get("resume_event", "") or "").strip()
    if not proof_source or not resume_event:
        return False
    if route in {"api", "official_cli"}:
        return proof_source == "setup_receipt.json" and resume_event == (
            "provider_action_recorded"
        )
    if route in {"browser_guided", "local_vault"}:
        return proof_source == "gate_events.jsonl" and resume_event == (
            "clipboard_captured -> resume_requested"
        )
    if route == "human_follow_me":
        return proof_source == "gate_events.jsonl" and resume_event in {
            "resume_requested",
            "dns_apply_approved -> resume_requested",
            "setup_plan_approved -> resume_requested",
        }
    return False


def _provider_playbook_safety_notes_ready(safety_notes: list[Any]) -> bool:
    seen: set[str] = set()
    for note in safety_notes:
        text = str(note or "").strip().lower()
        if not text:
            return False
        if text in seen:
            return False
        seen.add(text)
        if "capture <target>" in text or "capture <env>" in text:
            return False
        if _provider_playbook_local_browser_unsafe(text):
            return False
        if _provider_playbook_manual_action_unsafe(text):
            return False
    return True


def _provider_playbook_local_browser_unsafe(text: str) -> bool:
    markers = ("local browser", "local tab", "host browser", "host tab")
    for marker in markers:
        index = text.find(marker)
        if index >= 0 and not _provider_playbook_negated(text, index):
            return True
    return False


def _provider_playbook_manual_action_unsafe(text: str) -> bool:
    for marker in ("manual", "manually"):
        index = text.find(marker)
        if index >= 0 and not _provider_playbook_negated(text, index):
            return True
    return False


def _provider_playbook_negated(text: str, match_start: int) -> bool:
    prefix = text[max(0, match_start - 64) : match_start]
    clause = re.split(r"[.;:!?]\s*", prefix)[-1]
    if re.search(r"\b(?:do not|don't|never)\b", clause):
        return True
    return (
        re.search(
            r"\b(?:do not|don't|never|no|nothing to)\s+"
            r"(?:(?:do|perform|complete|use|create|copy|paste|enter|apply|add)\s+)?"
            r"(?:(?:a|the|your)\s+)?$",
            clause,
        )
        is not None
    )


def _provider_playbook_instruction_unsafe(instruction: str) -> bool:
    text = instruction.lower()
    unsafe_patterns = (
        "paste provider secrets into the host",
        "create resend domains manually",
        "create resend audiences manually",
        "click add domain in resend",
        "click add audience in resend",
    )
    return any(pattern in text for pattern in unsafe_patterns)


def _provider_playbook_order_failures(steps: list[Any]) -> list[str]:
    step_ids = [
        str(step.get("id", "") or "").strip()
        for step in steps
        if isinstance(step, dict) and str(step.get("id", "") or "").strip()
    ]
    duplicates = sorted(
        step_id for step_id in set(step_ids) if step_ids.count(step_id) > 1
    )
    positions = {step_id: index for index, step_id in enumerate(step_ids)}
    required_pairs = (
        ("resend.capture_key", "resend.domain_api"),
        ("resend.domain_api", "resend.audience_api"),
        ("resend.domain_api", "vercel.env_api"),
        ("resend.audience_api", "vercel.env_api"),
        ("resend.domain_api", "dns.approval"),
        ("vercel.env_api", "dns.approval"),
    )
    failures = [f"duplicate provider playbook step id: {step_id}" for step_id in duplicates]
    for before, after in required_pairs:
        before_position = positions.get(before)
        after_position = positions.get(after)
        if before_position is None or after_position is None:
            continue
        if before_position > after_position:
            failures.append(f"{before} must precede {after}")
    return failures


def _recording_human_actions_ready(record: dict[str, Any]) -> bool:
    human_actions = record.get("human_actions", {})
    if not isinstance(human_actions, dict):
        return False
    actions = human_actions.get("actions", [])
    counts = human_actions.get("counts", {})
    unguided = human_actions.get("unguided", [])
    if (
        not isinstance(actions, list)
        or not isinstance(counts, dict)
        or not isinstance(unguided, list)
    ):
        return False
    if _recording_human_actions_required(record) and not actions:
        return False
    gate_targets_by_id = _provider_gate_targets_by_id(record.get("provider_gates", {}))
    actual_counts: dict[str, int] = {}
    seen_identities: set[tuple[str, str, str, str]] = set()
    for action in actions:
        if not isinstance(action, dict):
            return False
        if set(action) - HUMAN_ACTION_KEYS:
            return False
        identity = _human_action_identity(action)
        if identity in seen_identities:
            return False
        seen_identities.add(identity)
        action_name = str(action.get("action", "") or "")
        actual_counts[action_name] = actual_counts.get(action_name, 0) + 1
    return (
        str(human_actions.get("schema_version", "") or "") == HUMAN_ACTION_TRACE_SCHEMA_VERSION
        and _safe_int(human_actions.get("total"), -1) == len(actions)
        and all(_safe_int(counts.get(name), -1) == count for name, count in actual_counts.items())
        and all(
            _safe_int(counts.get(name), 0) == 0
            for name in HUMAN_ACTION_COUNT_KEYS - set(actual_counts)
        )
        and not unguided
        and all(
            isinstance(action, dict)
            and str(action.get("gate_id", "") or "").strip()
            and action.get("guided") is True
            and _recording_human_action_control_ready(action)
            and _recording_human_action_gate_ready(action, gate_targets_by_id)
            for action in actions
        )
    )


def _human_action_identity(action: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(action.get("gate_id", "") or "").strip().lower(),
        str(action.get("action", "") or "").strip().lower(),
        str(action.get("visible_control", "") or "").strip(),
        str(action.get("target", "") or "").strip(),
    )


def _recording_human_action_control_ready(action: dict[str, Any]) -> bool:
    action_name = str(action.get("action", "") or "")
    visible_control = str(action.get("visible_control", "") or "")
    if action_name == OPEN_PROVIDER_GATE_ACTION:
        return visible_control == OPEN_PROVIDER_GATE_CONTROL
    if action_name == CAPTURE_VM_CLIPBOARD_ACTION:
        target = str(action.get("target", "") or "")
        return bool(target) and visible_control == capture_vm_clipboard_control(target)
    if action_name == CONFIRM_GATE_FINISHED_ACTION:
        return visible_control in FINISH_VISIBLE_CONTROLS
    return False


def _recording_human_action_gate_ready(
    action: dict[str, Any],
    gate_targets_by_id: dict[str, set[str]],
) -> bool:
    gate_id = str(action.get("gate_id", "") or "").strip()
    if not gate_id:
        return False
    if gate_id not in gate_targets_by_id:
        return False
    if str(action.get("action", "") or "") == CAPTURE_VM_CLIPBOARD_ACTION:
        action_targets = _env_targets_from_text(str(action.get("target", "") or ""))
        expected_targets = gate_targets_by_id.get(gate_id, set())
        return bool(action_targets) and action_targets.issubset(expected_targets)
    return True


def _provider_gate_targets_by_id(provider_gates: Any) -> dict[str, set[str]]:
    if not isinstance(provider_gates, dict):
        return {}
    records = provider_gates.get("records", [])
    if not isinstance(records, list):
        return {}
    gate_targets: dict[str, set[str]] = {}
    for gate in records:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "") or "").strip()
        if not gate_id:
            continue
        targets = _env_targets_from_text(str(gate.get("target", "") or ""))
        for captured_target in _safe_string_list(gate.get("captured_targets", [])):
            targets.update(_env_targets_from_text(captured_target))
        gate_targets[gate_id] = targets
    return gate_targets


def _env_targets_from_text(text: str) -> set[str]:
    return set(re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", text))


def _recording_rehearsal_review_ready(record: dict[str, Any]) -> bool:
    review = record.get("rehearsal_review", {})
    human_actions = record.get("human_actions", {})
    if not isinstance(review, dict) or not isinstance(human_actions, dict):
        return False
    actions = human_actions.get("actions", [])
    unguided = human_actions.get("unguided", [])
    reviewed_actions = review.get("reviewed_actions", [])
    if not isinstance(actions, list) or not isinstance(unguided, list):
        return False
    if not isinstance(reviewed_actions, list) or len(reviewed_actions) != len(actions):
        return False
    if _recording_human_actions_required(record) and not actions:
        return False
    statement = str(review.get("statement", "") or "").lower()
    action_count = len(actions)
    unguided_count = len(unguided)
    return (
        str(review.get("schema_version", "") or "") == REHEARSAL_REVIEW_SCHEMA_VERSION
        and str(review.get("status", "") or "") == "ready"
        and _safe_int(review.get("action_count"), -1) == action_count
        and _safe_int(review.get("compared_action_count"), -1) == action_count
        and _safe_int(review.get("matched_control_count"), -1) == action_count
        and _safe_int(review.get("unguided_count"), -1) == unguided_count == 0
        and _safe_int(review.get("side_channel_count"), -1) == 0
        and review.get("requires_user_thinking") is False
        and "control-room instructions" in statement
        and "public recording" in statement
        and all(
            isinstance(action, dict)
            and action.get("guided") is True
            and _recording_human_action_control_ready(action)
            and not _human_action_side_channel(action)
            for action in actions
        )
        and all(
            _reviewed_action_matches(action, reviewed)
            for action, reviewed in zip(actions, reviewed_actions, strict=False)
            if isinstance(action, dict)
        )
    )


def _reviewed_action_matches(action: dict[str, Any], reviewed: Any) -> bool:
    if not isinstance(reviewed, dict):
        return False
    if set(reviewed) - REHEARSAL_REVIEW_ACTION_KEYS:
        return False
    action_name = str(action.get("action", "") or "")
    return (
        str(reviewed.get("gate_id", "") or "") == str(action.get("gate_id", "") or "")
        and str(reviewed.get("action", "") or "") == action_name
        and str(reviewed.get("visible_control", "") or "")
        == str(action.get("visible_control", "") or "")
        and str(reviewed.get("target", "") or "") == str(action.get("target", "") or "")
        and reviewed.get("matched") is True
        and str(reviewed.get("proof_source", "") or "")
        == _rehearsal_review_proof_source(action_name)
    )


def _recording_human_actions_required(record: dict[str, Any]) -> bool:
    provider_gates = record.get("provider_gates", {})
    if isinstance(provider_gates, dict) and _safe_int(provider_gates.get("total"), 0) > 0:
        return True
    wake_events = record.get("wake_events", {})
    if isinstance(wake_events, dict) and _safe_int(wake_events.get("total"), 0) > 0:
        return True
    boundary = record.get("automation_boundary", {})
    counts = boundary.get("counts", {}) if isinstance(boundary, dict) else {}
    return isinstance(counts, dict) and _safe_int(counts.get("human_gate"), 0) > 0


def _recording_automation_boundary_ready(record: dict[str, Any]) -> bool:
    boundary = record.get("automation_boundary", {})
    if not isinstance(boundary, dict):
        return False
    if set(boundary) - AUTOMATION_BOUNDARY_KEYS:
        return False
    counts = boundary.get("counts", {})
    routes = boundary.get("routes", [])
    post_gate = boundary.get("post_gate_automation", {})
    allowed = boundary.get("vnc_allowed_for", [])
    statement = str(boundary.get("statement", "") or "")
    if not statement or statement != statement.strip():
        return False
    lowered_statement = statement.lower()
    required_allowed = AUTOMATION_BOUNDARY_REQUIRED_VNC_ALLOWLIST
    if not isinstance(counts, dict) or set(counts) - AUTOMATION_BOUNDARY_COUNTS_KEYS:
        return False
    if not isinstance(routes, list):
        return False
    if not isinstance(allowed, list):
        return False
    if not all(isinstance(item, str) and item and item == item.strip() for item in allowed):
        return False
    if not all(isinstance(route, dict) for route in routes):
        return False
    if not all(_recording_automation_route_exact(route) for route in routes):
        return False
    route_signatures = [_automation_route_signature(route) for route in routes]
    if _recording_duplicate_text_values(route_signatures):
        return False
    fusekit_owned = [
        route for route in routes if isinstance(route, dict) and route.get("owner") == "fusekit"
    ]
    human_gate = [
        route for route in routes if isinstance(route, dict) and route.get("owner") == "human_gate"
    ]
    if any(
        route.get("deterministic") is not True or route.get("implemented") is not True
        for route in fusekit_owned
    ):
        return False
    if not isinstance(post_gate, dict) or set(post_gate) - AUTOMATION_BOUNDARY_POST_GATE_KEYS:
        return False
    api_or_cli_routes = post_gate.get("api_or_cli_routes", [])
    human_gate_routes = post_gate.get("human_gate_routes", [])
    if not isinstance(api_or_cli_routes, list) or not isinstance(human_gate_routes, list):
        return False
    if not all(_recording_exact_nonempty_text(item) for item in api_or_cli_routes):
        return False
    if not all(_recording_exact_nonempty_text(item) for item in human_gate_routes):
        return False
    return (
        str(boundary.get("status", "") or "") == AUTOMATION_BOUNDARY_READY_STATUS
        and boundary.get("resume_after_worker_replace") is True
        and boundary.get("no_user_machine_state") is True
        and str(boundary.get("detonation_scope", "") or "")
        == AUTOMATION_BOUNDARY_DETONATION_SCOPE
        and all(term in lowered_statement for term in AUTOMATION_BOUNDARY_STATEMENT_TERMS)
        and isinstance(allowed, list)
        and not _recording_duplicate_text_values(allowed)
        and required_allowed.issubset({str(item) for item in allowed})
        and _safe_int(counts.get("blocked"), 1) == 0
        and _safe_int(counts.get("fusekit_owned"), -1) == len(fusekit_owned)
        and _safe_int(counts.get("human_gate"), -1) == len(human_gate)
        and not _recording_duplicate_text_values(api_or_cli_routes)
        and not _recording_duplicate_text_values(human_gate_routes)
        and sorted(str(item) for item in api_or_cli_routes)
        == sorted(
            _automation_route_signature(route)
            for route in fusekit_owned
        if route.get("route") in AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS
        )
        and sorted(str(item) for item in human_gate_routes)
        == sorted(_automation_route_signature(route) for route in human_gate)
    )


def _recording_automation_route_exact(route: dict[str, Any]) -> bool:
    if set(route) - AUTOMATION_BOUNDARY_ROUTE_KEYS:
        return False
    for key in ("provider", "recipe", "route", "owner", "status"):
        if not _recording_exact_nonempty_text(route.get(key)):
            return False
    owner = str(route.get("owner", "") or "")
    route_kind = str(route.get("route", "") or "")
    if owner not in AUTOMATION_BOUNDARY_ROUTE_OWNERS:
        return False
    if (
        owner == "fusekit"
        and route_kind not in AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS
    ):
        return False
    if (
        owner == "human_gate"
        and route_kind not in AUTOMATION_BOUNDARY_HUMAN_GATE_ROUTE_KINDS
    ):
        return False
    if not isinstance(route.get("deterministic"), bool):
        return False
    if not isinstance(route.get("implemented"), bool):
        return False
    return True


def _recording_exact_nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value) and value == value.strip()


def _recording_plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _recording_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _recording_public_model_text(
    value: object,
    *,
    check_secretish: bool = True,
) -> bool:
    if not _recording_exact_nonempty_text(value):
        return False
    text = str(value)
    if re.search(r"https?://[^\s\"'<>]*callback[^\s\"'<>]*", text, re.IGNORECASE):
        return False
    return not (check_secretish and contains_durable_secret_text(text))


def _automation_route_signature(route: dict[str, Any]) -> str:
    provider = str(route.get("provider", "") or "").strip()
    recipe = str(route.get("recipe", "") or "").strip()
    return f"{provider}:{recipe}"


def _recording_control_room_security_ready(record: dict[str, Any]) -> bool:
    surface = record.get("control_room_security", {})
    if not isinstance(surface, dict):
        return False
    if set(surface) - CONTROL_ROOM_SECURITY_KEYS:
        return False
    routes = surface.get("routes", [])
    state_routes = surface.get("state_changing_routes", [])
    if not isinstance(routes, list) or not isinstance(state_routes, list):
        return False
    if not routes or not all(isinstance(route, dict) for route in routes):
        return False
    if not all(_recording_control_room_route_exact(route) for route in routes):
        return False
    if not all(_recording_exact_nonempty_text(route) for route in state_routes):
        return False
    expected_state_routes = CONTROL_ROOM_PROTECTED_MUTATION_ROUTES
    route_values = {str(route.get("route", "") or "") for route in routes}
    state_route_values = {str(route) for route in state_routes}
    state_route_count = sum(1 for route in routes if route.get("state_change") is True)
    required_protection = str(surface.get("required_post_protection", "") or "")
    unknown_protection = str(surface.get("unknown_route_protection", "") or "")
    statement = str(surface.get("statement", "") or "")
    if not required_protection or required_protection != required_protection.strip():
        return False
    if not unknown_protection or unknown_protection != unknown_protection.strip():
        return False
    if not statement or statement != statement.strip():
        return False
    lowered_statement = statement.lower()
    if _recording_duplicate_text_values([str(route.get("route", "") or "") for route in routes]):
        return False
    if _recording_duplicate_text_values(state_routes):
        return False
    return (
        str(surface.get("schema_version", "") or "") == CONTROL_ROOM_SECURITY_SCHEMA_VERSION
        and _safe_int(surface.get("route_count"), -1) == len(routes)
        and _safe_int(surface.get("state_changing_route_count"), -1) == state_route_count
        and expected_state_routes.issubset(route_values)
        and expected_state_routes.issubset(state_route_values)
        and len(state_route_values) == state_route_count
        and surface.get("unknown_route_protection")
        == CONTROL_ROOM_UNKNOWN_ROUTE_PROTECTION
        and all(term in required_protection for term in CONTROL_ROOM_REQUIRED_POST_PROTECTION_TERMS)
        and all(term in lowered_statement for term in CONTROL_ROOM_SECURITY_STATEMENT_TERMS)
    )


def _recording_control_room_route_exact(route: dict[str, Any]) -> bool:
    if set(route) - CONTROL_ROOM_SECURITY_ROUTE_KEYS:
        return False
    if not _recording_exact_nonempty_text(route.get("route")):
        return False
    if not _recording_exact_nonempty_text(route.get("protection")):
        return False
    if not isinstance(route.get("state_change"), bool):
        return False
    methods = route.get("methods")
    if not isinstance(methods, list) or not methods:
        return False
    return all(_recording_exact_nonempty_text(method) for method in methods)


def _recording_verifiers_ready(record: dict[str, Any]) -> bool:
    verifiers = record.get("verifiers", {})
    if not isinstance(verifiers, dict):
        return False
    if set(verifiers) - VERIFIER_SUMMARY_KEYS:
        return False
    checks = verifiers.get("checks", [])
    counts = verifiers.get("counts", {})
    if not isinstance(checks, list) or not checks or not isinstance(counts, dict):
        return False
    if set(counts) - VERIFIER_SUMMARY_COUNT_KEYS:
        return False
    statement = str(verifiers.get("statement", "") or "")
    if not statement or statement != statement.strip():
        return False
    lowered_statement = statement.lower()
    if (
        "live provider verifiers" not in lowered_statement
        or "green checks" not in lowered_statement
    ):
        return False
    blocking_count_keys = ("pending", "repairing", "failed", "needs_human_gate", "unknown")
    allowed_statuses = {"passed", "pending_safe", "skipped"}
    actual_counts = {key: 0 for key in (*allowed_statuses, *blocking_count_keys)}
    seen_identities: set[tuple[str, str]] = set()
    for check in checks:
        if not isinstance(check, dict):
            return False
        if set(check) - VERIFIER_SUMMARY_CHECK_KEYS:
            return False
        if not _recording_verifier_check_exact(check):
            return False
        identity = (
            str(check.get("provider", "") or "").lower(),
            str(check.get("check", "") or "").lower(),
        )
        if not all(identity) or identity in seen_identities:
            return False
        seen_identities.add(identity)
        status = str(check.get("status", "") or "")
        actual_counts[status] += 1
    if actual_counts["skipped"] > 0 and (
        "skipped" not in lowered_statement or "do not count" not in lowered_statement
    ):
        return False
    return (
        str(verifiers.get("schema_version", "") or "") == VERIFIER_SUMMARY_SCHEMA_VERSION
        and verifiers.get("all_passed_or_pending_safe") is True
        and str(verifiers.get("overall", "") or "") == "passed"
        and all(_recording_plain_int(counts.get(key)) for key in VERIFIER_SUMMARY_COUNT_KEYS)
        and all(counts.get(key) == 0 for key in blocking_count_keys)
        and all(counts.get(key) == actual_counts[key] for key in actual_counts)
        and _recording_verifier_provider_coverage_ready(record, checks)
    )


def _recording_verifier_check_exact(check: dict[str, Any]) -> bool:
    for key in ("provider", "check", "status"):
        if not _recording_exact_nonempty_text(check.get(key)):
            return False
    if not isinstance(check.get("pending_safe"), bool):
        return False
    status = str(check.get("status", "") or "")
    if status not in {"passed", "pending_safe", "skipped"}:
        return False
    return status != "pending_safe" or check.get("pending_safe") is True


def _recording_verifier_provider_coverage_ready(
    record: dict[str, Any],
    checks: list[Any],
) -> bool:
    """Require verifier coverage for the providers the playbook promises to wire."""

    playbook = record.get("provider_playbook", {})
    if not isinstance(playbook, dict):
        return True
    playbook_steps = playbook.get("steps", [])
    if not isinstance(playbook_steps, list) or not playbook_steps:
        return True
    verifier_providers = {
        str(check.get("provider", "") or "").strip().lower()
        for check in checks
        if isinstance(check, dict) and _recording_verifier_coverage_check_ready(check)
    }
    playbook_providers = {
        str(step.get("provider", "") or "").strip().lower()
        for step in playbook_steps
        if isinstance(step, dict)
    }
    required = [
        accepted
        for accepted in RECORDING_PROVIDER_PLAYBOOK_FAMILIES.values()
        if accepted & playbook_providers
    ]
    return all(bool(accepted & verifier_providers) for accepted in required) and (
        "live_app" in verifier_providers
    )


def _recording_verifier_coverage_check_ready(check: dict[str, Any]) -> bool:
    status = str(check.get("status", "") or "")
    return status == "passed" or (
        status == "pending_safe" and check.get("pending_safe") is True
    )


def _recording_audit_trail_ready(record: dict[str, Any]) -> bool:
    audit_trail = record.get("audit_trail", {})
    if not isinstance(audit_trail, dict):
        return False
    if set(audit_trail) - AUDIT_TRAIL_KEYS:
        return False
    if str(audit_trail.get("schema_version", "") or "") != AUDIT_TRAIL_SCHEMA_VERSION:
        return False
    entries = audit_trail.get("entries", [])
    if not isinstance(entries, list) or not entries:
        return False
    actual_counts: dict[str, int] = {}
    seen_identities: set[tuple[str, str, str, str, str, str, str, str, str]] = set()
    wake_ids_by_name = _recording_wake_event_ids_by_name(record)
    for entry in entries:
        if not isinstance(entry, dict):
            return False
        if set(entry) - AUDIT_TRAIL_ENTRY_KEYS:
            return False
        if not _recording_audit_entry_exact(entry, wake_ids_by_name):
            return False
        identity = _audit_entry_identity(entry)
        if identity in seen_identities:
            return False
        seen_identities.add(identity)
        category = str(entry.get("category", "") or "")
        actual_counts[category] = actual_counts.get(category, 0) + 1
    counts = audit_trail.get("counts", {})
    if not isinstance(counts, dict):
        return False
    if set(counts) - AUDIT_TRAIL_CATEGORIES:
        return False
    if not all(_recording_plain_int(value) for value in counts.values()):
        return False
    statement = str(audit_trail.get("statement", "") or "")
    if not statement or statement != statement.strip():
        return False
    lowered_statement = statement.lower()
    if any(
        required not in lowered_statement
        for required in ("credential captures", "dns writes", "human approvals", "without storing")
    ):
        return False
    required_categories = _recording_required_audit_categories(record)
    return (
        _recording_plain_int(audit_trail.get("entry_count"))
        and audit_trail.get("entry_count") == len(entries)
        and all(
            counts.get(category) == count
            for category, count in actual_counts.items()
        )
        and all(actual_counts.get(category, 0) >= 1 for category in required_categories)
        and _recording_required_audit_sources_present(record, entries)
        and _recording_detonation_audit_resources_present(record, entries)
    )


def _recording_audit_entry_exact(
    entry: dict[str, Any],
    wake_ids_by_name: dict[str, set[str]],
) -> bool:
    for key in ("category", "action", "status", "source", "summary"):
        value = str(entry.get(key, "") or "")
        if not value.strip() or value != value.strip():
            return False
    category = str(entry.get("category", "") or "")
    if category not in AUDIT_TRAIL_CATEGORIES:
        return False
    for key in ("provider", "target", "resource"):
        value = str(entry.get(key, "") or "")
        if value and value != value.strip():
            return False
    for key in ("summary", "action", "provider", "target", "resource"):
        if contains_durable_secret_text(str(entry.get(key, "") or "")):
            return False
    source = str(entry.get("source", "") or "")
    if source == "audit.jsonl" and not _recording_positive_int(
        entry.get("audit_log_index")
    ):
        return False
    if source == "setup_receipt.json" and not _recording_positive_int(
        entry.get("receipt_action_index")
    ):
        return False
    expected_wake_event = _recording_audit_entry_expected_wake_event(entry)
    if expected_wake_event:
        wake_event_id = str(entry.get("wake_event_id", "") or "").strip()
        if not wake_event_id:
            return False
        if wake_event_id not in wake_ids_by_name.get(expected_wake_event, set()):
            return False
    return True


def _recording_wake_event_ids_by_name(record: dict[str, Any]) -> dict[str, set[str]]:
    wake_events = record.get("wake_events", {})
    events = wake_events.get("events", []) if isinstance(wake_events, dict) else []
    ids: dict[str, set[str]] = {}
    if not isinstance(events, list):
        return ids
    for event in events:
        if not isinstance(event, dict):
            continue
        event_name = str(event.get("event", "") or "").strip()
        event_id = str(event.get("id", "") or "").strip()
        if event_name and event_id:
            ids.setdefault(event_name, set()).add(event_id)
    return ids


def _recording_audit_entry_expected_wake_event(entry: dict[str, Any]) -> str:
    if str(entry.get("source", "") or "") != "gate_events.jsonl":
        return ""
    action = str(entry.get("action", "") or "")
    if action == "control_room.capture_vm_clipboard":
        return "clipboard_captured"
    if action in {"control_room.approve_dns_apply", "control_room.confirm_gate_finished"}:
        return "resume_requested"
    return ""


def _audit_entry_identity(
    entry: dict[str, Any],
) -> tuple[str, str, str, str, str, str, str, str, str]:
    return (
        str(entry.get("category", "") or "").strip(),
        str(entry.get("action", "") or "").strip(),
        str(entry.get("provider", "") or "").strip(),
        str(entry.get("source", "") or "").strip(),
        str(entry.get("target", "") or "").strip(),
        str(entry.get("wake_event_id", "") or "").strip(),
        str(entry.get("resource", "") or "").strip(),
        str(entry.get("audit_log_index", "") or "").strip(),
        str(entry.get("receipt_action_index", "") or "").strip(),
    )


def _recording_required_audit_categories(record: dict[str, Any]) -> set[str]:
    required: set[str] = set()
    wake_events = record.get("wake_events", {})
    events = wake_events.get("events", []) if isinstance(wake_events, dict) else []
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            event_name = str(event.get("event", "") or "")
            classification = str(event.get("classification", "") or "")
            if event_name == "clipboard_captured":
                required.add("credential_capture")
            if event_name == "resume_requested":
                required.add("human_approval")
            if event_name == "resume_requested" and classification == "dns-approval":
                required.add("dns_write")
    approvals = record.get("approvals", [])
    if isinstance(approvals, list) and approvals:
        required.add("human_approval")
    vault = record.get("vault", {})
    if isinstance(vault, dict) and _safe_int(vault.get("record_count"), 0) > 0:
        required.add("credential_capture")
    detonation = record.get("detonation", {})
    if isinstance(detonation, dict) and detonation.get("workspace_detonated") is True:
        required.add("detonation")
    verification = record.get("verification", {})
    checks = verification.get("checks", []) if isinstance(verification, dict) else []
    if isinstance(checks, list) and checks:
        required.add("provider_action")
    return required


def _recording_required_audit_sources_present(
    record: dict[str, Any],
    entries: list[Any],
) -> bool:
    required_sources = _recording_required_audit_sources(record)
    for category, sources in required_sources.items():
        if not any(
            isinstance(entry, dict)
            and str(entry.get("category", "") or "") == category
            and str(entry.get("source", "") or "") in sources
            for entry in entries
        ):
            return False
    return True


def _recording_required_audit_sources(record: dict[str, Any]) -> dict[str, set[str]]:
    required: dict[str, set[str]] = {}
    wake_events = record.get("wake_events", {})
    events = wake_events.get("events", []) if isinstance(wake_events, dict) else []
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            event_name = str(event.get("event", "") or "")
            classification = str(event.get("classification", "") or "")
            if event_name == "clipboard_captured":
                required.setdefault("credential_capture", set()).add("gate_events.jsonl")
            if event_name == "resume_requested":
                required.setdefault("human_approval", set()).add("gate_events.jsonl")
            if event_name == "resume_requested" and classification == "dns-approval":
                required.setdefault("dns_write", set()).add("setup_receipt.json")
    approvals = record.get("approvals", [])
    if isinstance(approvals, list) and approvals:
        required.setdefault("human_approval", set()).add("gate_events.jsonl")
    verification = record.get("verification", {})
    checks = verification.get("checks", []) if isinstance(verification, dict) else []
    if isinstance(checks, list) and checks:
        required.setdefault("provider_action", set()).add("setup_receipt.json")
    return required


def _recording_detonation_audit_resources_present(
    record: dict[str, Any],
    entries: list[Any],
) -> bool:
    detonation = record.get("detonation", {})
    if not isinstance(detonation, dict) or detonation.get("workspace_detonated") is not True:
        return True
    resources = {
        str(entry.get("resource", "") or "").strip()
        for entry in entries
        if isinstance(entry, dict)
        and str(entry.get("category", "") or "") == "detonation"
        and str(entry.get("source", "") or "") == "workspace_detonation.json"
        and str(entry.get("status", "") or "") in {"deleted", "released"}
    }
    return RECORDING_DETONATION_AUDIT_RESOURCES.issubset(resources)


def _recording_evidence_ready(record: dict[str, Any]) -> bool:
    evidence = record.get("evidence", {})
    if not isinstance(evidence, dict):
        return False
    if set(evidence) - EVIDENCE_INVENTORY_KEYS:
        return False
    if str(evidence.get("schema_version", "") or "") != EVIDENCE_INVENTORY_SCHEMA_VERSION:
        return False
    counts = evidence.get("counts", {})
    if not isinstance(counts, dict):
        return False
    if set(counts) - EVIDENCE_INVENTORY_COUNTS_KEYS:
        return False
    statement = str(evidence.get("statement", "") or "")
    if statement != statement.strip():
        return False
    lowered_statement = statement.lower()
    if "path and type only" not in lowered_statement or "raw secrets" not in lowered_statement:
        return False
    evidence_fields = {
        "logs": "log",
        "screenshots": "screenshot",
        "visual": "visual",
        "receipts": "receipt",
    }
    seen_paths: set[tuple[str, str]] = set()
    for field, expected_kind in evidence_fields.items():
        records = evidence.get(field)
        if not isinstance(records, list):
            return False
        count = counts.get(field)
        if not isinstance(count, int) or isinstance(count, bool) or count != len(records):
            return False
        for item in records:
            if not isinstance(item, dict):
                return False
            if set(item) - EVIDENCE_RECORD_KEYS:
                return False
            path = item.get("path", "")
            if not _recording_public_relative_path(path):
                return False
            kind = item.get("kind", "")
            if kind != expected_kind:
                return False
            source = item.get("source", "")
            if not _recording_exact_nonempty_text(source):
                return False
            if contains_durable_secret_text(source):
                return False
            if item.get("exists") is not True:
                return False
            path = str(path)
            identity = (field, path)
            if identity in seen_paths:
                return False
            seen_paths.add(identity)
    screenshot_required = _recording_screenshot_evidence_required(record)
    return (
        _safe_int(counts.get("logs"), 0) >= 1
        and (
            not screenshot_required
            or _safe_int(counts.get("screenshots"), 0) >= 1
        )
        and _safe_int(counts.get("visual"), 0) >= 1
        and _safe_int(counts.get("receipts"), 0) >= 1
    )


def _recording_public_relative_path(value: object) -> bool:
    if not _recording_exact_nonempty_text(value):
        return False
    path = str(value)
    lowered = path.lower()
    artifact_path = Path(path)
    if artifact_path.is_absolute() or ".." in artifact_path.parts:
        return False
    if path.startswith("~") or "://" in path:
        return False
    if any(marker in lowered for marker in ("token=", "password=", "secret=")):
        return False
    return not contains_durable_secret_text(path)


def _recording_screenshot_evidence_required(record: dict[str, Any]) -> bool:
    runner = record.get("runner_profile", {})
    if not isinstance(runner, dict):
        return False
    profile = runner.get("profile_contract", {})
    if not isinstance(profile, dict):
        return False
    browser_stack = profile.get("browser_stack", {})
    return (
        str(profile.get("name", "") or "") == EXPECTED_RUNNER_PROFILE
        or isinstance(browser_stack, dict)
        and bool(str(browser_stack.get("shared_provider_profile", "") or "").strip())
    )


def _recording_detonation_ready(record: dict[str, Any]) -> bool:
    detonation = record.get("detonation", {})
    if not isinstance(detonation, dict):
        return False
    if set(detonation) - DETONATION_KEYS:
        return False
    receipt = detonation.get("workspace_receipt", {})
    if not isinstance(receipt, dict):
        return False
    if set(receipt) - WORKSPACE_DETONATION_RECEIPT_KEYS:
        return False
    failures = receipt.get("failures", {}) if isinstance(receipt, dict) else {}
    resource_summary = receipt.get("resource_summary", {}) if isinstance(receipt, dict) else {}
    if not isinstance(resource_summary, dict):
        return False
    if set(resource_summary) - WORKSPACE_DETONATION_RESOURCE_SUMMARY_KEYS:
        return False
    deleted = receipt.get("deleted", []) if isinstance(receipt, dict) else []
    required_network_resources = {
        "internet_gateway",
        "network_security_group",
        "route_table",
        "security_list",
        "subnet",
        "vcn",
    }
    required_deleted_resources = required_network_resources | {
        "boot_volume",
        "ephemeral_public_ip",
        "instance",
        "remote_worker",
    }
    network_resources = (
        resource_summary.get("network_resources", []) if isinstance(resource_summary, dict) else []
    )
    network_resources_missing = (
        resource_summary.get("network_resources_missing", [])
        if isinstance(resource_summary, dict)
        else ["network_resources_missing"]
    )
    missing = (
        resource_summary.get("missing", [])
        if isinstance(resource_summary, dict)
        else ["resource_summary"]
    )
    survivors = (
        resource_summary.get("survivors", [])
        if isinstance(resource_summary, dict)
        else []
    )
    survivor_values = {str(item) for item in survivors} if isinstance(survivors, list) else set()
    cleanup = (
        resource_summary.get("remote_worker_cleanup", {})
        if isinstance(resource_summary, dict)
        else {}
    )
    if not _recording_exact_nonempty_text(receipt.get("status")):
        return False
    reason = receipt.get("reason", "")
    if reason and not _recording_exact_nonempty_text(reason):
        return False
    for key in ("schema_version", "compartment_scope", "statement"):
        if not _recording_exact_nonempty_text(resource_summary.get(key)):
            return False
    if not all(
        _recording_public_text_list(value)
        for value in (deleted, network_resources, network_resources_missing, missing, survivors)
    ):
        return False
    if (
        isinstance(deleted, list)
        and isinstance(network_resources, list)
        and isinstance(survivors, list)
        and (
            _recording_duplicate_text_values(deleted)
            or _recording_duplicate_text_values(network_resources)
            or _recording_duplicate_text_values(survivors)
        )
    ):
        return False
    return (
        detonation.get("preflight_safe") is True
        and detonation.get("workspace_detonated") is True
        and str(receipt.get("status", "") or "") == "complete"
        and isinstance(deleted, list)
        and not (required_deleted_resources - {str(item) for item in deleted})
        and isinstance(failures, dict)
        and not failures
        and isinstance(resource_summary, dict)
        and resource_summary.get("remote_worker") is True
        and _recording_remote_worker_cleanup_ready(cleanup)
        and resource_summary.get("compute_instance") is True
        and resource_summary.get("boot_volume_deleted") is True
        and resource_summary.get("ephemeral_public_ip_released") is True
        and resource_summary.get("network_resources_deleted") is True
        and resource_summary.get("compartment_deleted") is False
        and str(resource_summary.get("compartment_scope", "") or "") == "preserved"
        and isinstance(network_resources, list)
        and not (required_network_resources - {str(item) for item in network_resources})
        and isinstance(network_resources_missing, list)
        and not network_resources_missing
        and isinstance(missing, list)
        and not missing
        and isinstance(survivors, list)
        and survivor_values == set(DETONATION_PRESERVES)
        and _recording_detonation_statement_ready(resource_summary.get("statement", ""))
    )


def _recording_detonation_statement_ready(raw: object) -> bool:
    statement = str(raw or "").lower()
    return all(
        required in statement
        for required in (
            "remote worker",
            "oci vm",
            "boot volume",
            "network resources",
            "encrypted vault",
            "run record",
            "artifacts",
            "resume",
            "host-machine state",
        )
    )


def _recording_remote_worker_cleanup_ready(raw: object) -> bool:
    if not isinstance(raw, dict):
        return False
    if set(raw) - REMOTE_WORKER_CLEANUP_RECEIPT_KEYS:
        return False
    process_patterns = raw.get("process_patterns", [])
    paths = raw.get("paths", [])
    if not isinstance(process_patterns, list) or not isinstance(paths, list):
        return False
    if not _recording_public_text_list(process_patterns) or not _recording_public_text_list(paths):
        return False
    if _recording_duplicate_text_values(process_patterns) or _recording_duplicate_text_values(
        paths
    ):
        return False
    statement = str(raw.get("statement", "") or "").lower()
    return (
        str(raw.get("schema_version", "") or "") == REMOTE_WORKER_CLEANUP_SCHEMA_VERSION
        and str(raw.get("status", "") or "") == "detonated"
        and raw.get("host_machine_state_required") is False
        and "user" in statement
        and "machine" in statement
        and set(REMOTE_WORKER_PROCESS_PATTERNS).issubset({str(item) for item in process_patterns})
        and set(REMOTE_WORKER_PATH_TARGETS).issubset({str(item) for item in paths})
    )


def _recording_public_text_list(raw: object) -> bool:
    if not isinstance(raw, list):
        return False
    return all(
        _recording_exact_nonempty_text(item)
        and not contains_durable_secret_text(str(item))
        for item in raw
    )


def _approval_summary(gates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    approvals: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for gate in gates:
        status = _public_approval_text(gate.get("status", ""), "")
        if status not in APPROVAL_SUMMARY_READY_STATUSES:
            continue
        approval_id = _public_approval_text(gate.get(APPROVAL_SUMMARY_ID_FIELD, ""), "")
        if not approval_id:
            continue
        if approval_id in seen_ids:
            continue
        seen_ids.add(approval_id)
        updated_at = gate.get(APPROVAL_SUMMARY_UPDATED_AT_FIELD, 0)
        if isinstance(updated_at, bool) or not isinstance(updated_at, int | float):
            updated_at = 0.0
        elif updated_at < 0:
            updated_at = 0.0
        approvals.append(
            {
                APPROVAL_SUMMARY_ID_FIELD: approval_id,
                APPROVAL_SUMMARY_PROVIDER_FIELD: _public_approval_text(
                    gate.get(APPROVAL_SUMMARY_PROVIDER_FIELD, ""),
                    "unknown",
                ),
                APPROVAL_SUMMARY_STATUS_FIELD: status,
                APPROVAL_SUMMARY_REASON_FIELD: _public_approval_text(
                    gate.get(APPROVAL_SUMMARY_REASON_FIELD, ""),
                    "Approval recorded in the control room.",
                ),
                APPROVAL_SUMMARY_UPDATED_AT_FIELD: updated_at,
            }
        )
    return approvals


def _public_approval_text(value: object, fallback: str) -> str:
    text = _redacted_error_text(value).strip()
    if not text:
        return fallback
    return text


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
            errors.append(
                {
                    "source": "step",
                    "id": _redacted_error_text(step.id),
                    "detail": _redacted_error_text(step.detail),
                }
            )
    for gate in gates:
        if str(gate.get("status", "")) in {"failed", "invalid"}:
            errors.append(
                {
                    "source": "gate",
                    "id": _redacted_error_text(gate.get("id", "unknown")),
                    "detail": _redacted_error_text(gate.get("reason", "")),
                }
            )
    for source, payload in (
        ("verification", verification),
        ("acceptance", acceptance),
        ("workspace_detonation", workspace_detonation),
    ):
        error = str(payload.get("error", "") or "")
        if error:
            errors.append({"source": source, "id": source, "detail": _redacted_error_text(error)})
    failures = workspace_detonation.get("failures", {})
    if isinstance(failures, dict):
        for key, value in sorted(failures.items()):
            errors.append(
                {
                    "source": "workspace_detonation",
                    "id": _redacted_error_text(key),
                    "detail": _redacted_error_text(value),
                }
            )
    return _canonical_error_rows(errors)


def _canonical_error_rows(errors: list[dict[str, Any]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for error in errors:
        source = _public_error_field(error.get("source", ""), "run")
        error_id = _public_error_field(error.get("id", ""), source)
        detail = _public_error_field(
            error.get("detail", ""),
            "No public error detail recorded.",
        )
        identity = (source, error_id)
        if identity in seen:
            continue
        seen.add(identity)
        values = {"source": source, "id": error_id, "detail": detail}
        rows.append({key: values[key] for key in RUN_RECORD_ERROR_FIELDS})
    return rows


def _timeline_record_entries(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for entry in entries:
        row = _redacted_record_entry(entry)
        entry_id = _public_timeline_text(row.get("id", ""), "unknown")
        if entry_id in seen_ids:
            continue
        seen_ids.add(entry_id)
        row["id"] = entry_id
        row["label"] = _public_timeline_text(row.get("label", ""), entry_id)
        row["status"] = _public_timeline_text(row.get("status", ""), "unknown")
        for key in TIMELINE_OPTIONAL_TEXT_FIELDS:
            if key in row:
                row[key] = _public_timeline_text(row.get(key, ""), "")
        updated_at = row.get(TIMELINE_TIMESTAMP_FIELD, 0)
        if isinstance(updated_at, bool) or not isinstance(updated_at, int | float):
            row[TIMELINE_TIMESTAMP_FIELD] = 0.0
        elif updated_at < 0:
            row[TIMELINE_TIMESTAMP_FIELD] = 0.0
        returnable = {
            key: value
            for key, value in row.items()
            if key in TIMELINE_ENTRY_KEYS
        }
        rows.append(returnable)
    return rows


def _public_timeline_text(value: object, fallback: str) -> str:
    text = _redacted_error_text(value).strip()
    if not text:
        return fallback
    return text


def _public_error_field(value: object, fallback: str) -> str:
    text = _redacted_error_text(value).strip()
    if not text:
        return fallback
    return text


def _redacted_error_text(value: object) -> str:
    redacted = redact_public_text(value)
    return re.sub(r"https?://[^\s\"'<>]+", "[redacted-url]", redacted)


def _redacted_record_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        str(key): _redacted_error_text(value) if isinstance(value, str) else value
        for key, value in entry.items()
    }


def _safe_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str)]


def _safe_int(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
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
