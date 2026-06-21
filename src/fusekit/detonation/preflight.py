"""Detonation preflight checks for survivor artifacts."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from fusekit.llm.contract import (
    LLM_CONTRACT_KEYS,
    LLM_CONTRACT_LANE_KEYS,
    LLM_CONTRACT_SECURITY_KEYS,
    MODEL_INFERENCE_KEYS,
)
from fusekit.runner.acceptance_summary import (
    ACCEPTANCE_BLOCKER_KEYS,
    ACCEPTANCE_BLOCKER_REQUIRED_FIELDS,
    ACCEPTANCE_SUMMARY_KEYS,
    ACCEPTANCE_SUMMARY_READY_FIELDS,
    RUN_RECORD_ERROR_FIELDS,
    RUN_RECORD_ERROR_KEYS,
)
from fusekit.runner.approval_summary import (
    APPROVAL_SUMMARY_ID_FIELD,
    APPROVAL_SUMMARY_KEYS,
    APPROVAL_SUMMARY_PROVIDER_FIELD,
    APPROVAL_SUMMARY_READY_STATUSES,
    APPROVAL_SUMMARY_REASON_FIELD,
    APPROVAL_SUMMARY_STATUS_FIELD,
    APPROVAL_SUMMARY_TEXT_FIELDS,
    APPROVAL_SUMMARY_UPDATED_AT_FIELD,
)
from fusekit.runner.audit_log_proof import (
    AUDIT_LOG_DATA_FIELD,
    AUDIT_LOG_EVENT_FIELD,
    AUDIT_LOG_ROW_KEYS,
    AUDIT_LOG_TIMESTAMP_FIELD,
)
from fusekit.runner.audit_trail import AUDIT_TRAIL_ENTRY_KEYS, AUDIT_TRAIL_SCHEMA_VERSION
from fusekit.runner.automation_boundary import (
    AUTOMATION_BOUNDARY_COUNTS_KEYS,
    AUTOMATION_BOUNDARY_DETONATION_SCOPE,
    AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS,
    AUTOMATION_BOUNDARY_HUMAN_GATE_ROUTE_KINDS,
    AUTOMATION_BOUNDARY_KEYS,
    AUTOMATION_BOUNDARY_POST_GATE_KEYS,
    AUTOMATION_BOUNDARY_READY_STATUS,
    AUTOMATION_BOUNDARY_REQUIRED_VNC_ALLOWLIST,
    AUTOMATION_BOUNDARY_ROUTE_KEYS,
    AUTOMATION_BOUNDARY_ROUTE_OWNERS,
    AUTOMATION_BOUNDARY_SCHEMA_VERSION,
    AUTOMATION_BOUNDARY_STATEMENT_TERMS,
)
from fusekit.runner.control_room_security import (
    CONTROL_ROOM_PROTECTED_MUTATION_ROUTES,
    CONTROL_ROOM_REQUIRED_POST_PROTECTION_TERMS,
    CONTROL_ROOM_SECURITY_KEYS,
    CONTROL_ROOM_SECURITY_ROUTE_KEYS,
    CONTROL_ROOM_SECURITY_SCHEMA_VERSION,
    CONTROL_ROOM_SECURITY_STATEMENT_TERMS,
)
from fusekit.runner.detonation_proof import DETONATION_KEYS
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
    PROVIDER_GATES_ARTIFACT_GATES_FIELD,
    PROVIDER_GATES_ARTIFACT_KEYS,
    PROVIDER_GATES_KEYS,
    WAKE_EVENT_RECORD_KEYS,
    WAKE_EVENTS_KEYS,
)
from fusekit.runner.provider_playbook import (
    PROVIDER_PLAYBOOK_FAMILIES,
    PROVIDER_PLAYBOOK_STEP_KEYS,
)
from fusekit.runner.provider_strategy import (
    PROVIDER_STRATEGIES_ARTIFACT_KEYS,
    PROVIDER_STRATEGIES_SCHEMA_VERSION,
    PROVIDER_STRATEGY_CANDIDATE_KEYS,
    PROVIDER_STRATEGY_DECISION_KEYS,
    PROVIDER_STRATEGY_PROVIDER_KEYS,
    PROVIDER_STRATEGY_RECORD_KEYS,
    PROVIDER_STRATEGY_SELECTED_KEYS,
)
from fusekit.runner.readiness import (
    EXPECTED_PROVIDER_BROWSER_PROFILE,
    EXPECTED_RUNNER_PROFILE,
    runner_readiness_failures,
)
from fusekit.runner.recording_contract import (
    RECORDING_CONTRACT_CHECK_KEYS,
    RECORDING_CONTRACT_FIELD_KEYS,
    RECORDING_CONTRACT_SCHEMA_VERSION,
    RECORDING_CONTRACT_SECTION_KEYS,
)
from fusekit.runner.rehearsal_proof import (
    CAPTURE_VM_CLIPBOARD_ACTION,
    CONFIRM_GATE_FINISHED_ACTION,
    FINISH_VISIBLE_CONTROLS,
    HUMAN_ACTION_COUNT_KEYS,
    HUMAN_ACTION_TRACE_SCHEMA_VERSION,
    OPEN_PROVIDER_GATE_ACTION,
    OPEN_PROVIDER_GATE_CONTROL,
    REHEARSAL_REVIEW_SCHEMA_VERSION,
    capture_vm_clipboard_control,
)
from fusekit.runner.rehearsal_proof import (
    HUMAN_ACTION_KEYS as _HUMAN_ACTION_KEYS,
)
from fusekit.runner.rehearsal_proof import (
    REHEARSAL_REVIEW_ACTION_KEYS as _REHEARSAL_REVIEW_ACTION_KEYS,
)
from fusekit.runner.rehearsal_proof import (
    rehearsal_review_proof_source as _rehearsal_proof_source,
)
from fusekit.runner.remote_survivors import (
    REMOTE_RUN_STATE_KEYS,
    REMOTE_RUN_STATE_MISSING_FOR_DETONATION_FIELD,
    REMOTE_RUN_STATE_NOTES_FIELD,
    REMOTE_RUN_STATE_READY_TO_DETONATE_FIELD,
    REMOTE_RUN_STATE_UPDATED_AT_FIELD,
)
from fusekit.runner.rollback_proof import (
    ROLLBACK_METADATA_ACTION_KEYS,
    ROLLBACK_METADATA_ACTION_TEXT_FIELDS,
    ROLLBACK_METADATA_KEYS,
    ROLLBACK_PROOF_STATUSES,
)
from fusekit.runner.run_record import (
    DETONATION_PRESERVES,
    DURABLE_STATE_SOURCES,
    OCI_WORKSPACE_DETONATION_SURFACES,
    PUBLIC_PLAYWRIGHT_BROWSERS_PATH,
    PUBLIC_PROVIDER_BROWSER_PROFILE,
    RUN_RECORD_KEYS,
    RUN_RECORD_SCHEMA_VERSION,
    VOLATILE_WORKER_SURFACES,
    WORKER_REPLACEMENT_SOURCE_IDS,
)
from fusekit.runner.run_state import RUN_STATE_FIELDS
from fusekit.runner.setup_receipt_proof import (
    SETUP_RECEIPT_ACTION_KEYS,
    SETUP_RECEIPT_ACTION_REQUIRED_TEXT_FIELDS,
    SETUP_RECEIPT_ACTIONS_FIELD,
    SETUP_RECEIPT_KEYS,
    SETUP_RECEIPT_RAW_SECRET_COUNT_FIELD,
    SETUP_RECEIPT_TEXT_FIELDS,
)
from fusekit.runner.timeline_proof import (
    TIMELINE_ENTRY_KEYS,
    TIMELINE_OPTIONAL_TEXT_FIELDS,
    TIMELINE_REQUIRED_TEXT_FIELDS,
    TIMELINE_TIMESTAMP_FIELD,
)
from fusekit.runner.vault_proof import (
    VAULT_KEYS,
    VAULT_RECORD_KEYS,
    VAULT_SECRET_FIELD_NAMES,
)
from fusekit.runner.verifier_summary import (
    VERIFIER_SUMMARY_CHECK_KEYS,
    VERIFIER_SUMMARY_SCHEMA_VERSION,
)
from fusekit.runner.visual_state_proof import (
    VISUAL_STATE_DISPLAY,
    VISUAL_STATE_KEYS,
    VISUAL_STATE_NOTES,
    VISUAL_STATE_RUNNER,
    VISUAL_STATE_STATUS,
    VISUAL_STATE_TEXT_FIELDS,
    VISUAL_TRANSPORT_FIELDS,
)
from fusekit.runner.worker_replacement import worker_replacement_drill_failures
from fusekit.security import (
    contains_durable_secret_text,
    redact_public_path,
    scan_for_secret_leaks,
)
from fusekit.verification_report import (
    VERIFICATION_REPORT_CHECK_FIELD,
    VERIFICATION_REPORT_CHECK_KEYS,
    VERIFICATION_REPORT_DETAILS_FIELD,
    VERIFICATION_REPORT_OPTIONAL_TEXT_FIELDS,
    VERIFICATION_REPORT_PENDING_SAFE_CHECKS,
    VERIFICATION_REPORT_PROVIDER_FIELD,
    VERIFICATION_REPORT_REQUIRED_TEXT_FIELDS,
    VERIFICATION_REPORT_SAFE_STATUSES,
    VERIFICATION_REPORT_STATUS_FIELD,
    VERIFICATION_STATUS_NEEDS_HUMAN_GATE,
    VERIFICATION_STATUS_PENDING,
)

SAFE_URL_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
EXPECTED_NOVNC_PORT = 6080
EXPECTED_CONTROL_ROOM_PORT = 8765
SAFE_NOVNC_QUERY_VALUES = {
    "autoconnect": {"1"},
    "resize": {"scale"},
}
PUBLIC_PROVIDER_FAMILIES = PROVIDER_PLAYBOOK_FAMILIES
_LOCAL_BROWSER_GUIDANCE_PATTERNS = (
    (
        r"\b(?:open|use|launch|complete|finish|copy|paste)\b.{0,48}"
        r"\b(?:local browser|local tab|host browser|host tab)\b"
    ),
    (
        r"\b(?:local browser|local tab|host browser|host tab)\b.{0,48}"
        r"\b(?:open|use|copy|paste|complete|finish)\b"
    ),
)
_MANUAL_ACTION_GUIDANCE_PATTERNS = (
    r"\bmanual(?:ly)?\b.{0,32}\b(?:setup|set up|create|configure|copy|paste|enter|apply|add)\b",
    r"\b(?:setup|set up|create|configure|copy|paste|enter|apply|add)\b.{0,32}\bmanually\b",
)
EXPECTED_DURABLE_STATE_SOURCE_PATHS = {
    source_id: path for source_id, path, _role, _secret in DURABLE_STATE_SOURCES
}

@dataclass(frozen=True)
class DetonationPreflightResult:
    """Redacted detonation preflight outcome."""

    ok: bool
    failures: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "failures": list(self.failures)}


def run_detonation_preflight(
    *,
    root: Path,
    vault: Path,
    audit: Path,
    receipt: Path,
    verification_report: Path,
    provider_strategies: Path | None = None,
    rollback_metadata: Path,
    run_record: Path,
    llm_contract: Path | None = None,
    runner_readiness: Path | None = None,
    visual_state: Path | None = None,
    gates: Path | None = None,
    gate_events: Path | None = None,
    worker_replacement_drill: Path | None = None,
) -> DetonationPreflightResult:
    """Verify survivor artifacts before plaintext worker state is destroyed."""

    failures: list[str] = []
    llm_contract = llm_contract or run_record.with_name("llm_contract.json")
    provider_strategies = provider_strategies or run_record.with_name(
        "provider_strategies.json"
    )
    runner_readiness = runner_readiness or run_record.with_name("runner_readiness.json")
    visual_state = visual_state or run_record.with_name("visual.json")
    gates = gates or run_record.with_name("gates.json")
    gate_events = gate_events or run_record.with_name("gate_events.jsonl")
    for label, path in (
        ("encrypted vault", vault),
        ("audit log", audit),
        ("redacted receipt", receipt),
        ("verification report", verification_report),
        ("provider strategies", provider_strategies),
        ("rollback metadata", rollback_metadata),
        ("central run record", run_record),
        ("model/inference contract", llm_contract),
        ("runner readiness", runner_readiness),
        ("visual state", visual_state),
        ("provider gates", gates),
        ("gate events", gate_events),
        *(
            (("worker replacement drill", worker_replacement_drill),)
            if worker_replacement_drill is not None
            else ()
        ),
    ):
        if not path.is_file():
            failures.append(f"missing {label}: {path}")

    receipt_payload, read_failures = _read_json_artifact(receipt, "redacted receipt")
    failures.extend(read_failures)
    verification_payload, read_failures = _read_json_artifact(
        verification_report,
        "verification report",
    )
    failures.extend(read_failures)
    provider_strategy_payload, read_failures = _read_json_artifact(
        provider_strategies,
        "provider strategies",
    )
    failures.extend(read_failures)
    runner_readiness_payload, read_failures = _read_json_artifact(
        runner_readiness,
        "runner readiness",
    )
    failures.extend(read_failures)
    visual_state_payload, read_failures = _read_json_artifact(visual_state, "visual state")
    failures.extend(read_failures)
    gates_payload, read_failures = _read_json_artifact(gates, "provider gates")
    failures.extend(read_failures)
    gate_events_signature: tuple[tuple[Any, ...], ...] = ()
    gate_events_error = ""
    rollback_payload, read_failures = _read_json_artifact(
        rollback_metadata,
        "rollback metadata",
    )
    failures.extend(read_failures)
    if vault.is_file():
        failures.extend(_vault_survivor_failures(vault))
    if audit.is_file():
        failures.extend(_public_jsonl_survivor_failures(audit, "audit log"))
    if receipt.is_file():
        failures.extend(_receipt_survivor_failures(receipt_payload))
    if verification_report.is_file():
        failures.extend(_verification_failures(verification_payload))
        failures.extend(
            _public_json_survivor_failures(verification_payload, "verification report")
        )
    if provider_strategies.is_file():
        failures.extend(
            _provider_strategy_artifact_failures(
                provider_strategy_payload,
            )
        )
        failures.extend(
            _public_json_survivor_failures(
                provider_strategy_payload,
                "provider strategies",
            )
        )
    if runner_readiness.is_file():
        failures.extend(_runner_readiness_artifact_failures(runner_readiness_payload))
        failures.extend(
            _public_json_survivor_failures(
                runner_readiness_payload,
                "runner readiness",
            )
        )
    if visual_state.is_file():
        failures.extend(_visual_state_artifact_failures(visual_state_payload))
        failures.extend(
            _visual_state_public_safety_failures(
                visual_state_payload,
                "visual state",
            )
        )
    if gates.is_file():
        failures.extend(_provider_gates_artifact_failures(gates_payload))
    if gate_events.is_file():
        gate_events_signature, gate_events_error = _gate_events_jsonl_signature(gate_events)
        if gate_events_error:
            failures.append(gate_events_error)
    if rollback_metadata.is_file():
        failures.extend(_rollback_failures(rollback_payload))
        failures.extend(_public_json_survivor_failures(rollback_payload, "rollback metadata"))
    run_record_payload, read_failures = _read_json_artifact(
        run_record,
        "central run record",
    )
    failures.extend(read_failures)
    llm_contract_payload, read_failures = _read_json_artifact(
        llm_contract,
        "model/inference contract",
    )
    failures.extend(read_failures)
    if run_record.is_file():
        failures.extend(
            _run_record_failures(
                run_record_payload,
                evidence_root=run_record.parent,
            )
        )
    if llm_contract.is_file():
        failures.extend(_llm_contract_artifact_failures(llm_contract_payload))
    if run_record_payload and llm_contract_payload:
        failures.extend(
            _run_record_llm_contract_artifact_failures(
                run_record_payload,
                llm_contract_payload,
            )
        )
    if run_record_payload and verification_payload:
        failures.extend(
            _run_record_verification_artifact_failures(
                run_record_payload,
                verification_payload,
            )
        )
    if run_record_payload and provider_strategy_payload:
        failures.extend(
            _run_record_provider_strategy_artifact_failures(
                run_record_payload,
                provider_strategy_payload,
            )
        )
    if run_record_payload and runner_readiness_payload:
        failures.extend(
            _run_record_runner_readiness_artifact_failures(
                run_record_payload,
                runner_readiness_payload,
            )
        )
    if run_record_payload and gates_payload:
        failures.extend(
            _run_record_provider_gates_artifact_failures(
                run_record_payload,
                gates_payload,
            )
        )
    if run_record_payload and gate_events.is_file() and not gate_events_error:
        failures.extend(
            _run_record_gate_events_artifact_failures(
                run_record_payload,
                gate_events_signature,
            )
        )
    if worker_replacement_drill is not None and worker_replacement_drill.is_file():
        drill_payload, read_failures = _read_json_artifact(
            worker_replacement_drill,
            "worker replacement drill",
        )
        failures.extend(read_failures)
        failures.extend(worker_replacement_drill_failures(drill_payload))
        failures.extend(
            _public_json_survivor_failures(drill_payload, "worker replacement drill")
        )

    leaks = scan_for_secret_leaks(root)
    if leaks:
        failures.append(f"secret leak scan found {len(leaks)} finding(s)")

    return DetonationPreflightResult(ok=not failures, failures=tuple(failures))


def verification_report_failures(report: dict[str, Any]) -> list[str]:
    """Return redacted verification failures using detonation-preflight semantics."""

    return _verification_failures(report)


def verification_report_allows_detonation(report: dict[str, Any]) -> bool:
    """Return true when a verification report is passed or explicitly pending-safe."""

    return not verification_report_failures(report)


def verification_report_allows_launch_progress(report: dict[str, Any]) -> bool:
    """Return true when a launch can safely pause without treating human gates as failure."""

    return not _verification_failures(report, allow_human_gate=True)


def _vault_survivor_failures(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ["encrypted vault could not be read"]
    markers = (
        "WEBHOOK_SECRET",
        "BEGIN PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
    )
    if any(marker in text for marker in markers) or contains_durable_secret_text(text):
        return ["encrypted vault contains plaintext or credential-looking markers"]
    return []


def _verification_failures(
    report: dict[str, Any],
    *,
    allow_human_gate: bool = False,
) -> list[str]:
    checks = report.get("checks", [])
    if not isinstance(checks, list) or not checks:
        return ["verification report has no checks"]
    failures: list[str] = []
    seen_identities: set[tuple[str, str]] = set()
    for index, item in enumerate(checks):
        if not isinstance(item, dict):
            failures.append("verification report contains an invalid check")
            continue
        provider = str(item.get(VERIFICATION_REPORT_PROVIDER_FIELD, "") or "").strip()
        check = str(item.get(VERIFICATION_REPORT_CHECK_FIELD, "") or "").strip()
        status = str(item.get(VERIFICATION_REPORT_STATUS_FIELD, "") or "").strip()
        label = f"verification report checks[{index}]"
        unexpected = sorted(set(item) - VERIFICATION_REPORT_CHECK_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        required_values = {
            VERIFICATION_REPORT_PROVIDER_FIELD: provider,
            VERIFICATION_REPORT_CHECK_FIELD: check,
            VERIFICATION_REPORT_STATUS_FIELD: status,
        }
        for key in VERIFICATION_REPORT_REQUIRED_TEXT_FIELDS:
            value = required_values[key]
            if not value:
                failures.append(f"{label}.{key} is missing")
            elif str(item.get(key, "") or "") != value:
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        for key in VERIFICATION_REPORT_OPTIONAL_TEXT_FIELDS:
            if key not in item:
                continue
            value = str(item.get(key, "") or "")
            if not value.strip():
                failures.append(f"{label}.{key} must not be empty")
            elif value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        if (
            VERIFICATION_REPORT_DETAILS_FIELD in item
            and not isinstance(item.get(VERIFICATION_REPORT_DETAILS_FIELD), dict)
        ):
            failures.append(f"{label}.details must be an object")
        if not provider or not check or not status:
            continue
        identity = (provider.lower(), check.lower())
        if identity in seen_identities:
            failures.append(f"{provider}.{check} is duplicated")
            continue
        seen_identities.add(identity)
        details = item.get(VERIFICATION_REPORT_DETAILS_FIELD, {})
        pending_safe = _check_pending_safe(details)
        if status in VERIFICATION_REPORT_SAFE_STATUSES:
            continue
        if status == VERIFICATION_STATUS_PENDING and (
            pending_safe or check in VERIFICATION_REPORT_PENDING_SAFE_CHECKS
        ):
            continue
        if allow_human_gate and status == VERIFICATION_STATUS_NEEDS_HUMAN_GATE:
            continue
        failures.append(f"{provider}.{check} is {status or 'unknown'}")
    return failures


def _check_pending_safe(details: Any) -> bool:
    if not isinstance(details, dict):
        return False
    if details.get("pending_safe") is True:
        return True
    nested = details.get("details")
    return isinstance(nested, dict) and nested.get("pending_safe") is True


def _rollback_failures(payload: dict[str, Any]) -> list[str]:
    failures = _rollback_metadata_shape_failures(payload)
    actions = payload.get("rollback", payload.get("actions", []))
    if not isinstance(actions, list) or not actions:
        failures.append("rollback metadata has no actions")
        return failures
    actionable = [
        item
        for item in actions
        if isinstance(item, dict)
        and str(item.get("action", "")).startswith("rollback.")
        and str(item.get("status", "")) in ROLLBACK_PROOF_STATUSES
    ]
    if not actionable:
        failures.append("rollback metadata has no provider rollback actions")
    return failures


def _rollback_metadata_shape_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(payload) - ROLLBACK_METADATA_KEYS)
    if unexpected:
        failures.append("rollback metadata has unexpected fields: " + ", ".join(unexpected))
    actions = payload.get("rollback", payload.get("actions", []))
    if not isinstance(actions, list):
        return failures
    for index, action in enumerate(actions):
        label = f"rollback metadata.rollback[{index}]"
        if not isinstance(action, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected_action_keys = sorted(set(action) - ROLLBACK_METADATA_ACTION_KEYS)
        if unexpected_action_keys:
            failures.append(
                f"{label} has unexpected fields: " + ", ".join(unexpected_action_keys)
            )
        for key in ROLLBACK_METADATA_ACTION_TEXT_FIELDS:
            if key in action:
                value = action.get(key)
                field_label = f"{label}.{key}"
                if not isinstance(value, str):
                    failures.append(f"{field_label} must be text")
                elif value != value.strip():
                    failures.append(f"{field_label} must not have surrounding whitespace")
                elif contains_durable_secret_text(value):
                    failures.append(f"{field_label} contains credential-looking text")
    return failures


def _run_record_failures(
    payload: dict[str, Any],
    *,
    evidence_root: Path | None = None,
) -> list[str]:
    failures: list[str] = []
    if not payload:
        return ["central run record could not be read"]
    unexpected = sorted(set(payload) - RUN_RECORD_KEYS)
    if unexpected:
        failures.append(
            "central run record has unexpected fields: " + ", ".join(unexpected)
        )
    missing = sorted(RUN_RECORD_KEYS - set(payload))
    if missing:
        failures.append("central run record is missing fields: " + ", ".join(missing))
    if str(payload.get("schema_version", "") or "") != RUN_RECORD_SCHEMA_VERSION:
        failures.append("central run record has unsupported schema")
    failures.extend(_run_record_base_identity_failures(payload))
    for key in ("created_at", "updated_at"):
        value = payload.get(key)
        if not isinstance(value, int | float) or isinstance(value, bool) or value < 0:
            failures.append(f"central run record {key} must be a non-negative number")
    failures.extend(_required_run_record_section_preflight_failures(payload))
    acceptance = payload.get("acceptance")
    if not isinstance(acceptance, dict):
        failures.append("central run record acceptance is missing")
    elif acceptance:
        failures.extend(_acceptance_summary_preflight_failures(acceptance, payload))
    run_state = payload.get("state", {})
    if isinstance(run_state, dict) and run_state:
        failures.extend(_run_state_preflight_failures(run_state))
    durable = payload.get("durable_state", {})
    if isinstance(durable, dict):
        failures.extend(_durable_state_preflight_failures(durable))
    model_inference = payload.get("model_inference", {})
    if isinstance(model_inference, dict) and model_inference:
        failures.extend(_model_inference_failures(model_inference))
    llm_contract = payload.get("llm_contract", {})
    if isinstance(llm_contract, dict) and llm_contract:
        failures.extend(_llm_contract_failures(llm_contract))
    if isinstance(model_inference, dict) and isinstance(llm_contract, dict):
        failures.extend(_model_inference_contract_failures(model_inference, llm_contract))
    security = payload.get("control_room_security", {})
    if isinstance(security, dict) and security:
        failures.extend(_control_room_security_failures(security))
    automation_boundary = payload.get("automation_boundary", {})
    if isinstance(automation_boundary, dict) and automation_boundary:
        failures.extend(_automation_boundary_preflight_failures(automation_boundary))
    audit_trail = payload.get("audit_trail", {})
    if isinstance(audit_trail, dict) and audit_trail:
        failures.extend(_audit_trail_preflight_failures(audit_trail, payload))
    provider_gates = payload.get("provider_gates", {})
    wake_events = payload.get("wake_events", {})
    if isinstance(provider_gates, dict) and provider_gates:
        failures.extend(_provider_gates_preflight_failures(provider_gates))
    if isinstance(wake_events, dict) and wake_events:
        failures.extend(_wake_events_preflight_failures(wake_events))
    if isinstance(provider_gates, dict) and isinstance(wake_events, dict):
        failures.extend(_gate_wake_consistency_failures(provider_gates, wake_events))
    approvals = payload.get("approvals")
    if isinstance(approvals, list):
        failures.extend(
            _approval_summary_preflight_failures(approvals, provider_gates, wake_events)
        )
    else:
        failures.append("central run record approvals are missing")
    errors = payload.get("errors")
    if isinstance(errors, list):
        failures.extend(_run_record_error_preflight_failures(errors))
    else:
        failures.append("central run record errors are missing")
    vault_summary = payload.get("vault", {})
    if isinstance(vault_summary, dict) and vault_summary:
        failures.extend(_vault_summary_preflight_failures(vault_summary))
    for timeline_key in ("steps", "checkpoints"):
        timeline = payload.get(timeline_key, [])
        if isinstance(timeline, list) and timeline:
            failures.extend(_timeline_preflight_failures(timeline_key, timeline))
        elif timeline:
            failures.append(f"central run record {timeline_key} are missing")
    provider_playbook = payload.get("provider_playbook", {})
    if isinstance(provider_playbook, dict) and provider_playbook:
        failures.extend(_provider_playbook_preflight_failures(provider_playbook))
    provider_strategies = payload.get("provider_strategies", {})
    if isinstance(provider_strategies, dict) and provider_strategies:
        failures.extend(
            _provider_strategy_summary_preflight_failures(
                provider_strategies,
                provider_playbook,
            )
        )
    verifiers = payload.get("verifiers", {})
    if isinstance(verifiers, dict) and verifiers:
        failures.extend(_verifier_summary_preflight_failures(verifiers, provider_playbook))
    embedded_verification = payload.get("verification", {})
    if isinstance(embedded_verification, dict) and embedded_verification:
        failures.extend(_embedded_verification_preflight_failures(embedded_verification))
    detonation = payload.get("detonation", {})
    if isinstance(detonation, dict) and detonation:
        failures.extend(_detonation_section_preflight_failures(detonation))
    human_actions = payload.get("human_actions", {})
    human_actions_required = _preflight_human_actions_required(payload)
    if isinstance(human_actions, dict) and human_actions:
        failures.extend(
            _human_action_trace_preflight_failures(
                human_actions,
                provider_gates,
                human_actions_required=human_actions_required,
            )
        )
    rehearsal_review = payload.get("rehearsal_review", {})
    if isinstance(rehearsal_review, dict) and rehearsal_review:
        failures.extend(
            _rehearsal_review_preflight_failures(
                rehearsal_review,
                human_actions,
                human_actions_required=human_actions_required,
            )
        )
    artifacts = payload.get("artifacts", [])
    if isinstance(artifacts, list) and artifacts:
        failures.extend(
            _artifact_list_preflight_failures(
                artifacts,
                artifact_root=evidence_root,
            )
        )
    evidence = payload.get("evidence", {})
    runner_profile = payload.get("runner_profile", {})
    if isinstance(evidence, dict) and evidence:
        failures.extend(
            _evidence_inventory_preflight_failures(
                evidence,
                runner_profile,
                evidence_root=evidence_root,
            )
        )
    worker_replacement_drill = payload.get("worker_replacement_drill", {})
    if isinstance(worker_replacement_drill, dict) and worker_replacement_drill:
        failures.extend(
            "central run record " + failure
            for failure in worker_replacement_drill_failures(worker_replacement_drill)
        )
    recording_contract = payload.get("recording_contract", {})
    if isinstance(recording_contract, dict) and recording_contract:
        failures.extend(_recording_contract_preflight_failures(recording_contract, payload))
    for path, value in _walk_json_strings(payload, path="central run record"):
        if contains_durable_secret_text(value):
            failures.append(f"{path} contains credential-looking text")
            if len(failures) >= 20:
                failures.append("central run record contains additional credential-looking text")
                break
        elif _contains_callback_url(value):
            failures.append(f"{path} contains callback URL")
            if len(failures) >= 20:
                failures.append("central run record contains additional unsafe public text")
                break
    return failures


_RUN_RECORD_REQUIRED_OBJECT_SECTIONS = (
    "state",
    "durable_state",
    "provider_gates",
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
    "evidence",
    "verification",
    "llm_contract",
    "detonation",
    "recording_contract",
)
_RUN_RECORD_REQUIRED_LIST_SECTIONS = ("steps", "checkpoints", "artifacts")


def _required_run_record_section_preflight_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for key in _RUN_RECORD_REQUIRED_OBJECT_SECTIONS:
        value = payload.get(key)
        if not isinstance(value, dict) or not value:
            failures.append(f"central run record is missing {key}")
    for key in _RUN_RECORD_REQUIRED_LIST_SECTIONS:
        value = payload.get(key)
        if not isinstance(value, list) or not value:
            failures.append(f"central run record is missing {key}")
    return failures


def _run_record_base_identity_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    for key in ("id", "status", "app_path", "runner"):
        if not str(payload.get(key, "") or "").strip():
            failures.append(f"central run record is missing {key}")
    app_path = str(payload.get("app_path", "") or "")
    if app_path and Path(app_path).is_absolute():
        failures.append("central run record app_path must be a public path label")
    return failures


def _run_state_preflight_failures(run_state: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(run_state) - REMOTE_RUN_STATE_KEYS)
    if unexpected:
        failures.append(
            "central run record state has unexpected fields: " + ", ".join(unexpected)
        )
    for name in RUN_STATE_FIELDS:
        if not isinstance(run_state.get(name), bool):
            failures.append(f"central run record state.{name} must be boolean")
    if run_state.get("detonation_safe") is not True:
        failures.append("central run record state.detonation_safe must be true")
    if not isinstance(run_state.get("workspace_detonated"), bool):
        failures.append("central run record state.workspace_detonated must be boolean")
    updated_at = run_state.get(REMOTE_RUN_STATE_UPDATED_AT_FIELD)
    if (
        not isinstance(updated_at, int | float)
        or isinstance(updated_at, bool)
        or updated_at < 0
    ):
        failures.append(
            f"central run record state.{REMOTE_RUN_STATE_UPDATED_AT_FIELD} "
            "must be a non-negative number"
        )
    ready_to_detonate = run_state.get(REMOTE_RUN_STATE_READY_TO_DETONATE_FIELD)
    if not isinstance(ready_to_detonate, bool):
        failures.append(
            f"central run record state.{REMOTE_RUN_STATE_READY_TO_DETONATE_FIELD} "
            "must be boolean"
        )
    notes = run_state.get(REMOTE_RUN_STATE_NOTES_FIELD, [])
    failures.extend(
        _run_state_public_string_list_preflight_failures(
            notes,
            f"central run record state.{REMOTE_RUN_STATE_NOTES_FIELD}",
        )
    )
    missing = run_state.get(REMOTE_RUN_STATE_MISSING_FOR_DETONATION_FIELD, [])
    failures.extend(
        _run_state_public_string_list_preflight_failures(
            missing,
            f"central run record state.{REMOTE_RUN_STATE_MISSING_FOR_DETONATION_FIELD}",
        )
    )
    if isinstance(missing, list):
        unknown_missing = sorted(
            {str(item).strip() for item in missing if isinstance(item, str)}
            - set(RUN_STATE_FIELDS)
        )
        if unknown_missing:
            failures.append(
                f"central run record state.{REMOTE_RUN_STATE_MISSING_FOR_DETONATION_FIELD} "
                "has unknown fields: "
                + ", ".join(unknown_missing)
            )
    return failures


def _run_state_public_string_list_preflight_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        return [f"{label} must be a list"]
    failures: list[str] = []
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        if not isinstance(item, str):
            failures.append(f"{item_label} must be text")
        elif item != item.strip():
            failures.append(f"{item_label} must not have surrounding whitespace")
        elif contains_durable_secret_text(item):
            failures.append(f"{item_label} contains credential-looking text")
    return failures


def _durable_state_preflight_failures(durable_state: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(durable_state.get("schema_version", "") or "").strip() != (
        DURABLE_STATE_SCHEMA_VERSION
    ):
        failures.append("central run record durable_state schema is unsupported")
    if durable_state.get("resume_ready") is not True:
        failures.append("central run record durable_state resume_ready must be true")
    sources = durable_state.get("sources", [])
    source_ids: set[str] = set()
    if not isinstance(sources, list) or not sources:
        failures.append("central run record durable_state sources are missing")
    else:
        for index, source in enumerate(sources):
            label = f"central run record durable_state sources[{index}]"
            if not isinstance(source, dict):
                failures.append(f"{label} is not an object")
                continue
            source_id = str(source.get("id", "") or "").strip()
            if not source_id:
                failures.append(f"{label}.id is missing")
            elif source_id in source_ids:
                failures.append(f"{label}.id duplicates durable source {source_id}")
            else:
                source_ids.add(source_id)
            if source.get("exists") is not True:
                failures.append(f"{label}.exists must be true")
            source_path = str(source.get("path", "") or "").strip()
            if source_path.startswith("/"):
                failures.append(f"{label}.path must be relative")
            expected_path = EXPECTED_DURABLE_STATE_SOURCE_PATHS.get(source_id)
            if expected_path is not None and source_path != expected_path:
                failures.append(f"{label}.path must be {expected_path}")
            if str(source.get("secret_class", "") or "") not in {"encrypted", "non-secret"}:
                failures.append(f"{label}.secret_class is unsupported")
            volatile_marker = _volatile_durable_source_marker(source)
            if volatile_marker:
                failures.append(f"{label} preserves volatile worker state: {volatile_marker}")
        required = {source_id for source_id, _path, _role, _secret in DURABLE_STATE_SOURCES}
        missing_ids = sorted(required - source_ids)
        if missing_ids:
            failures.append(
                "central run record durable_state sources missing " + ", ".join(missing_ids)
            )
    runner_failures = durable_state.get("runner_profile_failures", [])
    if durable_state.get("runner_profile_ready") is not True:
        failures.append("central run record durable_state runner_profile_ready must be true")
    if not isinstance(runner_failures, list):
        failures.append("central run record durable_state runner_profile_failures must be a list")
    elif runner_failures:
        failures.append(
            "central run record durable_state runner_profile_failures must be empty: "
            + ", ".join(str(item) for item in runner_failures)
        )
    volatile = durable_state.get("volatile_worker_surfaces", [])
    volatile_values = {str(item) for item in volatile} if isinstance(volatile, list) else set()
    if not isinstance(volatile, list) or not set(VOLATILE_WORKER_SURFACES).issubset(
        volatile_values
    ):
        failures.append("central run record durable_state volatile_worker_surfaces is incomplete")
    elif _duplicate_text_values(volatile):
        failures.append("central run record durable_state volatile_worker_surfaces is duplicated")
    preserves = durable_state.get("detonation_preserves", [])
    preserve_values = {str(item) for item in preserves} if isinstance(preserves, list) else set()
    if not isinstance(preserves, list) or preserve_values != set(DETONATION_PRESERVES):
        failures.append("central run record durable_state detonation_preserves is incomplete")
    elif _duplicate_text_values(preserves):
        failures.append("central run record durable_state detonation_preserves is duplicated")
    scope = durable_state.get("detonation_scope")
    if not isinstance(scope, dict):
        failures.append("central run record is missing detonation scope")
    else:
        if str(scope.get("schema_version", "") or "").strip() != (
            DETONATION_SCOPE_SCHEMA_VERSION
        ):
            failures.append(
                "central run record durable_state detonation_scope schema is unsupported"
            )
        if (
            str(scope.get("mode", "") or "").strip()
            != AUTOMATION_BOUNDARY_DETONATION_SCOPE
        ):
            failures.append("central run record durable_state detonation_scope mode is unsupported")
        must_delete = scope.get("must_delete", [])
        required_delete = {*VOLATILE_WORKER_SURFACES, *OCI_WORKSPACE_DETONATION_SURFACES}
        delete_values = (
            {str(item) for item in must_delete}
            if isinstance(must_delete, list)
            else set()
        )
        if not isinstance(must_delete, list) or not required_delete.issubset(delete_values):
            failures.append(
                "central run record durable_state detonation_scope must_delete is incomplete"
            )
        elif _duplicate_text_values(must_delete):
            failures.append(
                "central run record durable_state detonation_scope must_delete is duplicated"
            )
        must_preserve = scope.get("must_preserve", [])
        preserve_scope_values = (
            {str(item) for item in must_preserve} if isinstance(must_preserve, list) else set()
        )
        if not isinstance(must_preserve, list) or preserve_scope_values != set(
            DETONATION_PRESERVES
        ):
            failures.append(
                "central run record durable_state detonation_scope must_preserve is incomplete"
            )
        elif _duplicate_text_values(must_preserve):
            failures.append(
                "central run record durable_state detonation_scope must_preserve is duplicated"
            )
        if scope.get("resume_until_complete") is not True:
            failures.append(
                "central run record durable_state detonation_scope "
                "resume_until_complete must be true"
            )
        if scope.get("host_machine_state_required") is not False:
            failures.append("central run record requires host-machine state")
        no_trace_statement = str(scope.get("no_trace_statement", "") or "")
        if not all(term in no_trace_statement for term in DETONATION_SCOPE_NO_TRACE_TERMS):
            failures.append(
                "central run record durable_state detonation_scope "
                "no_trace_statement is incomplete"
            )
    statement = str(durable_state.get("statement", "") or "")
    if not all(term in statement for term in DURABLE_STATE_STATEMENT_TERMS):
        failures.append(
            "central run record durable_state statement is missing durable-worker guidance"
        )
    replacement = durable_state.get("worker_replacement_contract")
    if not isinstance(replacement, dict):
        failures.append("central run record durable_state worker_replacement_contract is missing")
    else:
        if replacement.get("worker_is_disposable") is not True:
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "worker_is_disposable must be true"
            )
        if replacement.get("can_recreate_worker") is not True:
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "can_recreate_worker must be true"
            )
        if replacement.get("runner_profile_ready") is not True:
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "runner_profile_ready must be true"
            )
        if (
            str(replacement.get("required_runner_profile", "") or "")
            != EXPECTED_RUNNER_PROFILE
        ):
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "required_runner_profile is unsupported"
            )
        if replacement.get("host_machine_state_required") is not False:
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "host_machine_state_required must be false"
            )
        if str(replacement.get("state_owner", "") or "") != WORKER_REPLACEMENT_STATE_OWNER:
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "state_owner is unsupported"
            )
        resume_sources = replacement.get("resume_sources", [])
        resume_values = (
            {str(item) for item in resume_sources} if isinstance(resume_sources, list) else set()
        )
        required_resume = set(WORKER_REPLACEMENT_SOURCE_IDS)
        if not isinstance(resume_sources, list) or not required_resume.issubset(resume_values):
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "resume_sources is incomplete"
            )
        elif source_ids and not resume_values.issubset(source_ids):
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "resume_sources must reference durable_state sources"
            )
        elif _duplicate_text_values(resume_sources):
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "resume_sources is duplicated"
            )
        replacement_volatile = replacement.get("volatile_surfaces", [])
        replacement_volatile_values = (
            {str(item) for item in replacement_volatile}
            if isinstance(replacement_volatile, list)
            else set()
        )
        if not isinstance(replacement_volatile, list) or not volatile_values.issubset(
            replacement_volatile_values
        ):
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "volatile_surfaces must cover volatile_worker_surfaces"
            )
        elif _duplicate_text_values(replacement_volatile):
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "volatile_surfaces is duplicated"
            )
        replacement_statement = str(replacement.get("statement", "") or "")
        if not all(term in replacement_statement for term in WORKER_REPLACEMENT_STATEMENT_TERMS):
            failures.append(
                "central run record durable_state worker_replacement_contract "
                "statement is incomplete"
            )
    return failures


def _public_json_survivor_failures(payload: dict[str, Any], label: str) -> list[str]:
    if not payload:
        return []
    failures: list[str] = []
    for path, value in _walk_json_strings(payload, path=label):
        if contains_durable_secret_text(value):
            failures.append(f"{path} contains credential-looking text")
        elif _contains_callback_url(value):
            failures.append(f"{path} contains callback URL")
        if len(failures) >= 20:
            failures.append(f"{label} contains additional unsafe public text")
            break
    return failures


def _receipt_survivor_failures(payload: dict[str, Any]) -> list[str]:
    failures = _public_json_survivor_failures(payload, "redacted receipt")
    failures.extend(_receipt_shape_failures(payload))
    raw_secret_count = payload.get(SETUP_RECEIPT_RAW_SECRET_COUNT_FIELD)
    if not isinstance(raw_secret_count, int) or isinstance(raw_secret_count, bool):
        failures.append("redacted receipt raw_secrets_exposed must be literal 0")
    elif raw_secret_count != 0:
        failures.append("redacted receipt raw_secrets_exposed must be literal 0")
    return failures


def _receipt_shape_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(payload) - SETUP_RECEIPT_KEYS)
    if unexpected:
        failures.append("redacted receipt has unexpected fields: " + ", ".join(unexpected))
    for key in SETUP_RECEIPT_TEXT_FIELDS:
        if key not in payload:
            continue
        value = payload.get(key)
        label = f"redacted receipt.{key}"
        if not isinstance(value, str):
            failures.append(f"{label} must be a string")
        elif value != value.strip():
            failures.append(f"{label} must be trimmed")
        elif contains_durable_secret_text(value):
            failures.append(f"{label} contains credential-looking text")
    actions = payload.get(SETUP_RECEIPT_ACTIONS_FIELD, [])
    if not isinstance(actions, list):
        failures.append("redacted receipt.actions must be a list")
        return failures
    for index, action in enumerate(actions):
        label = f"redacted receipt.actions[{index}]"
        if not isinstance(action, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected_action = sorted(set(action) - SETUP_RECEIPT_ACTION_KEYS)
        if unexpected_action:
            failures.append(
                f"{label} has unexpected fields: " + ", ".join(unexpected_action)
            )
        for key in SETUP_RECEIPT_ACTION_REQUIRED_TEXT_FIELDS:
            value = action.get(key)
            field_label = f"{label}.{key}"
            if not isinstance(value, str) or not value:
                failures.append(f"{field_label} is missing")
            elif value != value.strip():
                failures.append(f"{field_label} must be trimmed")
            elif contains_durable_secret_text(value):
                failures.append(f"{field_label} contains credential-looking text")
    return failures


def _visual_state_artifact_failures(payload: dict[str, Any]) -> list[str]:
    if not payload:
        return ["visual state could not be read"]
    return [f"visual state {failure}" for failure in _visual_state_shape_failures(payload)]


def _visual_state_public_safety_failures(
    payload: dict[str, Any],
    label: str,
) -> list[str]:
    if not payload:
        return []
    failures: list[str] = []
    for name in VISUAL_TRANSPORT_FIELDS:
        value = payload.get(name)
        if not isinstance(value, str):
            continue
        if _contains_callback_url(value):
            failures.append(f"{label}.{name} contains callback URL")
            continue
        if name == "novnc_password" and contains_durable_secret_text(value):
            failures.append(f"{label}.{name} contains credential-looking text")
    extra = {key: value for key, value in payload.items() if key not in VISUAL_TRANSPORT_FIELDS}
    failures.extend(_public_json_survivor_failures(extra, label))
    return failures


def _visual_state_shape_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(payload) - VISUAL_STATE_KEYS)
    if unexpected:
        failures.append("artifact has unexpected fields: " + ", ".join(unexpected))
    missing = sorted(VISUAL_STATE_KEYS - set(payload))
    if missing:
        failures.append("artifact is missing generated fields: " + ", ".join(missing))
    for field in VISUAL_STATE_TEXT_FIELDS:
        if field not in payload:
            continue
        value = payload[field]
        if not isinstance(value, str):
            failures.append(f"{field} must be text")
            continue
        if value != value.strip():
            failures.append(f"{field} must be trimmed")
    if payload.get("runner") != VISUAL_STATE_RUNNER:
        failures.append(f"runner must be {VISUAL_STATE_RUNNER}")
    if payload.get("status") != VISUAL_STATE_STATUS:
        failures.append(f"status must be {VISUAL_STATE_STATUS}")
    if payload.get("interactive") is not True:
        failures.append("interactive must be true")
    if payload.get("display") != VISUAL_STATE_DISPLAY:
        failures.append(f"display must be {VISUAL_STATE_DISPLAY}")
    url_failures = _visual_transport_failures(payload)
    failures.extend(url_failures)
    password = payload.get("novnc_password")
    if not isinstance(password, str) or not password.strip():
        failures.append("novnc_password is required")
    elif len(password) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in password):
        failures.append("novnc_password must be safe metadata")
    if payload.get("provider_browser_profile") != EXPECTED_PROVIDER_BROWSER_PROFILE:
        failures.append("provider_browser_profile must match shared provider profile")
    notes = payload.get("notes")
    if not isinstance(notes, list):
        failures.append("notes must be a list")
    else:
        if _duplicate_text_values(notes):
            failures.append("notes is duplicated")
        if tuple(notes) != VISUAL_STATE_NOTES:
            failures.append("notes must match generated visual-session guidance")
        for index, note in enumerate(notes):
            if not isinstance(note, str):
                failures.append(f"notes[{index}] must be text")
                continue
            if note != note.strip():
                failures.append(f"notes[{index}] must be trimmed")
    return failures


def _visual_transport_failures(payload: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    novnc_url = payload.get("novnc_url")
    control_room_url = payload.get("control_room_url")
    if not isinstance(novnc_url, str) or not novnc_url.strip():
        failures.append("safe noVNC URL is required")
        novnc_host = ""
    else:
        novnc_host = _safe_visual_url_host(
            novnc_url,
            require_vnc_path=True,
            allowed_query_keys={"autoconnect", "resize"},
            expected_port=EXPECTED_NOVNC_PORT,
        )
        if not novnc_host:
            failures.append("novnc_url must be a safe public noVNC URL")
    if not isinstance(control_room_url, str) or not control_room_url.strip():
        failures.append("safe control-room URL is required")
        return failures
    control_host = _safe_visual_url_host(
        control_room_url,
        require_vnc_path=False,
        allowed_query_keys={"token"},
        expected_port=EXPECTED_CONTROL_ROOM_PORT,
    )
    if not control_host:
        failures.append("control_room_url must be a safe public control-room URL")
    elif novnc_host and control_host != novnc_host:
        failures.append("control_room_url must use the noVNC host")
    return failures


def _safe_visual_url_host(
    value: str,
    *,
    require_vnc_path: bool,
    allowed_query_keys: set[str],
    expected_port: int,
) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if parsed.username or parsed.password or not parsed.hostname:
        return ""
    try:
        port = parsed.port
    except ValueError:
        return ""
    if port != expected_port:
        return ""
    if not _safe_visual_host(parsed.hostname):
        return ""
    if require_vnc_path and not parsed.path.endswith("/vnc.html"):
        return ""
    if not require_vnc_path and "callback" in parsed.path.lower():
        return ""
    seen_keys: set[str] = set()
    for key, item in parse_qsl(parsed.query, keep_blank_values=False):
        if key not in allowed_query_keys:
            return ""
        if key in seen_keys:
            return ""
        seen_keys.add(key)
        if key == "token" and not SAFE_URL_TOKEN_PATTERN.fullmatch(item):
            return ""
        if require_vnc_path and item not in SAFE_NOVNC_QUERY_VALUES.get(key, set()):
            return ""
    if "token" in allowed_query_keys and "token" not in seen_keys:
        return ""
    return parsed.hostname.lower().strip("[]")


def _safe_visual_host(hostname: str) -> bool:
    try:
        address = ipaddress.ip_address(hostname.strip("[]"))
    except ValueError:
        return False
    return address.is_global


def _runner_readiness_artifact_failures(payload: dict[str, Any]) -> list[str]:
    if not payload:
        return ["runner readiness could not be read"]
    return [f"runner readiness {failure}" for failure in runner_readiness_failures(payload)]


def _provider_gates_artifact_failures(payload: dict[str, Any]) -> list[str]:
    if not payload:
        return ["provider gates could not be read"]
    failures = _public_json_survivor_failures(payload, "provider gates")
    unexpected_keys = sorted(set(payload) - PROVIDER_GATES_ARTIFACT_KEYS)
    if unexpected_keys:
        failures.append(
            "provider gates has unexpected fields: " + ", ".join(unexpected_keys)
        )
    gates = payload.get(PROVIDER_GATES_ARTIFACT_GATES_FIELD, [])
    if not isinstance(gates, list):
        failures.append("provider gates.gates must be a list")
        return failures
    for index, gate in enumerate(gates):
        label = f"provider gates.gates[{index}]"
        if not isinstance(gate, dict):
            failures.append(f"{label} is not an object")
            continue
        failures.extend(_provider_gate_record_shape_failures(gate, label))
        for key in ("id", "provider", "status"):
            value = gate.get(key, "")
            field_label = f"{label}.{key}"
            if not isinstance(value, str) or not value:
                failures.append(f"{field_label} is missing")
            elif value != value.strip():
                failures.append(f"{field_label} must be trimmed")
            elif contains_durable_secret_text(value):
                failures.append(f"{field_label} contains credential-looking text")
    return failures


def _provider_strategy_artifact_failures(payload: dict[str, Any]) -> list[str]:
    if not payload:
        return ["provider strategies could not be read"]
    failures = _public_json_survivor_failures(payload, "provider strategies")
    unexpected_keys = sorted(set(payload) - PROVIDER_STRATEGIES_ARTIFACT_KEYS)
    if unexpected_keys:
        failures.append(
            "provider strategies has unexpected fields: " + ", ".join(unexpected_keys)
        )
    if str(payload.get("schema_version", "") or "") != PROVIDER_STRATEGIES_SCHEMA_VERSION:
        failures.append("provider strategies schema is unsupported")
    providers = payload.get("providers", [])
    if not isinstance(providers, list) or not providers:
        failures.append("provider strategies.providers is missing")
        providers = []
    for index, provider_record in enumerate(providers):
        label = f"provider strategies.providers[{index}]"
        if not isinstance(provider_record, dict):
            failures.append(f"{label} is not an object")
            continue
        failures.extend(_provider_strategy_provider_artifact_failures(provider_record, label))
    playbook = payload.get("playbook")
    if not isinstance(playbook, dict):
        failures.append("provider strategies.playbook is missing")
    else:
        failures.extend(
            failure.replace(
                "central run record provider playbook",
                "provider strategies.playbook",
            )
            for failure in _provider_playbook_preflight_failures(playbook)
        )
    return failures


def _provider_strategy_provider_artifact_failures(
    provider_record: dict[str, Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected_keys = sorted(set(provider_record) - PROVIDER_STRATEGY_PROVIDER_KEYS)
    if unexpected_keys:
        failures.append(f"{label} has unexpected fields: " + ", ".join(unexpected_keys))
    provider = provider_record.get("provider", "")
    failures.extend(_public_string_field_failures(provider, f"{label}.provider"))
    strategies = provider_record.get("strategies", [])
    if not isinstance(strategies, list) or not strategies:
        failures.append(f"{label}.strategies is missing")
        return failures
    for index, strategy in enumerate(strategies):
        strategy_label = f"{label}.strategies[{index}]"
        if not isinstance(strategy, dict):
            failures.append(f"{strategy_label} is not an object")
            continue
        failures.extend(_provider_strategy_record_artifact_failures(strategy, strategy_label))
    return failures


def _provider_strategy_record_artifact_failures(
    strategy: dict[str, Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected_keys = sorted(set(strategy) - PROVIDER_STRATEGY_RECORD_KEYS)
    if unexpected_keys:
        failures.append(f"{label} has unexpected fields: " + ", ".join(unexpected_keys))
    for key in ("recipe", "strategy", "status"):
        failures.extend(_public_string_field_failures(strategy.get(key, ""), f"{label}.{key}"))
    for key in ("resume_url", "target", "next_action", "resume_hint"):
        if key in strategy:
            failures.extend(
                _public_string_field_failures(
                    strategy.get(key, ""),
                    f"{label}.{key}",
                )
            )
    for key in ("follow_steps", "success_criteria", "avoid_steps"):
        if key in strategy:
            failures.extend(
                _public_string_list_field_failures(
                    strategy.get(key),
                    f"{label}.{key}",
                )
            )
    decision = strategy.get("decision", {})
    if not isinstance(decision, dict):
        failures.append(f"{label}.decision is missing")
        return failures
    failures.extend(_provider_strategy_decision_artifact_failures(decision, f"{label}.decision"))
    return failures


def _provider_strategy_decision_artifact_failures(
    decision: dict[str, Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected_keys = sorted(set(decision) - PROVIDER_STRATEGY_DECISION_KEYS)
    if unexpected_keys:
        failures.append(f"{label} has unexpected fields: " + ", ".join(unexpected_keys))
    for key in ("provider", "recipe_kind"):
        if key in decision:
            failures.extend(_public_string_field_failures(decision.get(key, ""), f"{label}.{key}"))
    selected = decision.get("selected", {})
    if not isinstance(selected, dict):
        failures.append(f"{label}.selected is missing")
    else:
        failures.extend(
            _provider_strategy_route_artifact_failures(
                selected,
                f"{label}.selected",
                require_route_proof=True,
            )
        )
    candidates = decision.get("candidates", [])
    if not isinstance(candidates, list) or not candidates:
        failures.append(f"{label}.candidates is missing")
    else:
        for index, candidate in enumerate(candidates):
            candidate_label = f"{label}.candidates[{index}]"
            if not isinstance(candidate, dict):
                failures.append(f"{candidate_label} is not an object")
                continue
            failures.extend(
                _provider_strategy_route_artifact_failures(
                    candidate,
                    candidate_label,
                    require_route_proof=False,
                )
            )
    return failures


def _provider_strategy_route_artifact_failures(
    route: dict[str, Any],
    label: str,
    *,
    require_route_proof: bool,
) -> list[str]:
    failures: list[str] = []
    allowed_keys = (
        PROVIDER_STRATEGY_SELECTED_KEYS
        if require_route_proof
        else PROVIDER_STRATEGY_CANDIDATE_KEYS
    )
    unexpected_keys = sorted(set(route) - allowed_keys)
    if unexpected_keys:
        failures.append(f"{label} has unexpected fields: " + ", ".join(unexpected_keys))
    required_string_keys = (
        ("kind", "status", "reason") if require_route_proof else ("kind", "status")
    )
    for key in required_string_keys:
        failures.extend(_public_string_field_failures(route.get(key, ""), f"{label}.{key}"))
    for key in ("label",):
        if key in route:
            failures.extend(_public_string_field_failures(route.get(key, ""), f"{label}.{key}"))
    if "priority" in route and not (
        isinstance(route["priority"], int) and not isinstance(route["priority"], bool)
    ):
        failures.append(f"{label}.priority must be an integer")
    for key in ("deterministic", "implemented"):
        if require_route_proof and route.get(key) not in {True, False}:
            failures.append(f"{label}.{key} must be boolean")
        elif key in route and route.get(key) not in {True, False}:
            failures.append(f"{label}.{key} must be boolean")
    evidence = route.get("evidence", {})
    if "evidence" in route and not isinstance(evidence, dict):
        failures.append(f"{label}.evidence must be an object")
    return failures


def _public_string_field_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, str) or not value:
        return [f"{label} is missing"]
    if value != value.strip():
        return [f"{label} must not have surrounding whitespace"]
    if contains_durable_secret_text(value):
        return [f"{label} contains credential-looking text"]
    return []


def _public_string_list_field_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        return [f"{label} is missing"]
    failures: list[str] = []
    for index, item in enumerate(value):
        item_label = f"{label}[{index}]"
        failures.extend(_public_string_field_failures(item, item_label))
    return failures


def _run_record_verification_artifact_failures(
    run_record: dict[str, Any],
    verification_report: dict[str, Any],
) -> list[str]:
    artifact_signature = _verification_report_signature(verification_report)
    if not artifact_signature:
        return []
    run_record_signature = _run_record_verifier_signature(run_record.get("verifiers", {}))
    failures: list[str] = []
    if run_record_signature != artifact_signature:
        failures.append("central run record verifiers must match verification_report.json")
    embedded_signature = _verification_report_signature(run_record.get("verification", {}))
    if embedded_signature != artifact_signature:
        failures.append("central run record verification must match verification_report.json")
    return failures


def _run_record_provider_strategy_artifact_failures(
    run_record: dict[str, Any],
    provider_strategies: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    artifact_strategy_signature = _provider_strategy_signature(provider_strategies)
    if artifact_strategy_signature:
        run_strategy_signature = _provider_strategy_signature(
            run_record.get("provider_strategies", {})
        )
        if run_strategy_signature != artifact_strategy_signature:
            failures.append(
                "central run record provider_strategies must match "
                "provider_strategies.json route decisions"
            )
    artifact_playbook_signature = _provider_playbook_signature(
        provider_strategies.get("playbook", {})
    )
    if artifact_playbook_signature:
        run_playbook_signature = _provider_playbook_signature(
            run_record.get("provider_playbook", {})
        )
        if run_playbook_signature != artifact_playbook_signature:
            failures.append(
                "central run record provider_playbook must match "
                "provider_strategies.json playbook"
            )
    return failures


def _run_record_runner_readiness_artifact_failures(
    run_record: dict[str, Any],
    runner_readiness: dict[str, Any],
) -> list[str]:
    artifact_signature = _runner_readiness_signature(runner_readiness)
    if not artifact_signature:
        return []
    run_signature = _runner_readiness_signature(run_record.get("runner_profile", {}))
    if run_signature != artifact_signature:
        return ["central run record runner_profile must match runner_readiness.json"]
    return []


def _run_record_provider_gates_artifact_failures(
    run_record: dict[str, Any],
    gates: dict[str, Any],
) -> list[str]:
    artifact_signature = _provider_gates_artifact_signature(gates)
    if not artifact_signature:
        return []
    run_signature = _provider_gates_summary_signature(
        run_record.get("provider_gates", {})
    )
    if run_signature != artifact_signature:
        return ["central run record provider_gates must match gates.json"]
    return []


def _run_record_gate_events_artifact_failures(
    run_record: dict[str, Any],
    gate_events_signature: tuple[tuple[Any, ...], ...],
) -> list[str]:
    wake_events = run_record.get("wake_events", {})
    run_events = wake_events.get("events", []) if isinstance(wake_events, dict) else []
    run_signature = _wake_event_signature(run_events)
    if not run_signature:
        return []
    if run_signature != gate_events_signature:
        return ["central run record wake_events must match gate_events.jsonl"]
    return []


def _provider_gates_artifact_signature(raw: Any) -> tuple[tuple[Any, ...], ...]:
    if not isinstance(raw, dict):
        return ()
    return _provider_gate_records_signature(raw.get("gates", []))


def _provider_gates_summary_signature(raw: Any) -> tuple[tuple[Any, ...], ...]:
    if not isinstance(raw, dict):
        return ()
    return _provider_gate_records_signature(raw.get("records", []))


def _provider_gate_records_signature(records: Any) -> tuple[tuple[Any, ...], ...]:
    if not isinstance(records, list):
        return ()
    rows: list[tuple[Any, ...]] = []
    for gate in records:
        if not isinstance(gate, dict):
            continue
        captured_targets = gate.get("captured_targets", [])
        if not isinstance(captured_targets, list):
            captured_targets = []
        rows.append(
            (
                str(gate.get("id", "") or "").strip(),
                str(gate.get("provider", "") or "").strip(),
                str(gate.get("status", "") or "unknown").strip(),
                str(gate.get("classification", "") or "").strip(),
                str(gate.get("target", "") or "").strip(),
                tuple(sorted(str(target) for target in captured_targets if str(target))),
                str(gate.get("last_wake_event_id", "") or "").strip(),
                str(gate.get("last_wake_event", "") or "").strip(),
            )
        )
    return tuple(sorted(rows))


def _gate_events_jsonl_signature(path: Path) -> tuple[tuple[tuple[Any, ...], ...], str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return (), "gate_events.jsonl could not be read for preflight proof"
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return (), f"gate_events.jsonl line {line_number} is malformed JSON"
        if not isinstance(raw, dict):
            return (), f"gate_events.jsonl line {line_number} is not an object"
        public_safety_failures = _public_json_survivor_failures(
            raw,
            f"gate_events[{line_number}]",
        )
        if public_safety_failures:
            return (), public_safety_failures[0]
        shape_failures = _wake_event_record_shape_failures(raw, f"gate_events[{line_number}]")
        if shape_failures:
            return (), shape_failures[0]
        events.append(raw)
    return _wake_event_signature(events), ""


def _wake_event_signature(events: Any) -> tuple[tuple[Any, ...], ...]:
    if not isinstance(events, list):
        return ()
    rows: list[tuple[Any, ...]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        captured_targets = event.get("captured_targets", [])
        if not isinstance(captured_targets, list):
            captured_targets = []
        rows.append(
            (
                str(event.get("id", "") or "").strip(),
                str(event.get("event", "") or "unknown").strip(),
                str(event.get("gate_id", "") or "unknown").strip(),
                str(event.get("provider", "") or "").strip(),
                str(event.get("classification", "") or "").strip(),
                str(event.get("status", "") or "unknown").strip(),
                str(event.get("target", "") or "").strip(),
                tuple(sorted(str(target) for target in captured_targets if str(target))),
            )
        )
    return tuple(sorted(rows))


def _provider_strategy_signature(raw: Any) -> tuple[tuple[Any, ...], ...]:
    if not isinstance(raw, dict):
        return ()
    providers = raw.get("providers", [])
    if not isinstance(providers, list):
        return ()
    rows: list[tuple[Any, ...]] = []
    for provider_record in providers:
        if not isinstance(provider_record, dict):
            continue
        provider = str(provider_record.get("provider", "") or "").strip().lower()
        strategies = provider_record.get("strategies", [])
        if not provider or not isinstance(strategies, list):
            continue
        for strategy in strategies:
            if not isinstance(strategy, dict):
                continue
            decision = strategy.get("decision", {})
            selected = decision.get("selected", {}) if isinstance(decision, dict) else {}
            candidates = decision.get("candidates", []) if isinstance(decision, dict) else []
            selected = selected if isinstance(selected, dict) else {}
            rows.append(
                (
                    provider,
                    str(strategy.get("recipe", "") or "").strip().lower(),
                    str(strategy.get("strategy", "") or "").strip(),
                    str(strategy.get("status", "") or "").strip(),
                    str(selected.get("kind", "") or "").strip(),
                    str(selected.get("status", "") or "").strip(),
                    selected.get("deterministic"),
                    selected.get("implemented"),
                    str(selected.get("reason", "") or "").strip(),
                    _provider_strategy_evidence_signature(selected.get("evidence", {})),
                    tuple(str(step).strip() for step in strategy.get("follow_steps", []))
                    if isinstance(strategy.get("follow_steps", []), list)
                    else (),
                    str(strategy.get("next_action", "") or "").strip(),
                    str(strategy.get("resume_hint", "") or "").strip(),
                    tuple(
                        str(item).strip()
                        for item in strategy.get("success_criteria", [])
                    )
                    if isinstance(strategy.get("success_criteria", []), list)
                    else (),
                    tuple(str(item).strip() for item in strategy.get("avoid_steps", []))
                    if isinstance(strategy.get("avoid_steps", []), list)
                    else (),
                    _provider_strategy_candidate_signature(candidates),
                )
            )
    return tuple(sorted(rows))


def _provider_strategy_evidence_signature(evidence: Any) -> str:
    if not isinstance(evidence, dict):
        return ""
    return _canonical_json_signature(evidence)


def _provider_strategy_candidate_signature(candidates: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(candidates, list):
        return ()
    rows: list[tuple[str, str]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        rows.append(
            (
                str(candidate.get("kind", "") or "").strip(),
                str(candidate.get("status", "") or "").strip(),
            )
        )
    return tuple(sorted(rows))


def _provider_playbook_signature(raw: Any) -> tuple[Any, ...]:
    if not isinstance(raw, dict):
        return ()
    steps = raw.get("steps", [])
    notes = raw.get("safety_notes", [])
    if not isinstance(steps, list) or not isinstance(notes, list):
        return ()
    step_rows: list[tuple[str, str, str, str, str, str, str]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        step_rows.append(
            (
                str(step.get("id", "") or "").strip(),
                str(step.get("provider", "") or "").strip(),
                str(step.get("route", "") or "").strip(),
                str(step.get("control", "") or "").strip(),
                str(step.get("instruction", "") or "").strip(),
                str(step.get("proof_source", "") or "").strip(),
                str(step.get("resume_event", "") or "").strip(),
            )
        )
    return (
        str(raw.get("schema_version", "") or "").strip(),
        tuple(step_rows),
        tuple(str(note).strip() for note in notes),
    )


def _runner_readiness_signature(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return ()
    return _canonical_json_signature(_public_runner_readiness_summary(raw))


def _public_runner_readiness_summary(raw: dict[str, Any]) -> dict[str, Any]:
    profile = raw.get("profile_contract", {})
    observed = raw.get("observed", {})
    checks = raw.get("checks", {})
    installed = raw.get("installed_binaries", {})
    public: dict[str, Any] = {
        "schema_version": str(raw.get("schema_version", "") or ""),
        "status": str(raw.get("status", "") or ""),
        "architecture": str(raw.get("architecture", "") or ""),
        "profile_contract": profile if isinstance(profile, dict) else {},
        "observed": observed if isinstance(observed, dict) else {},
        "checks": checks if isinstance(checks, dict) else {},
        "installed_binaries": installed if isinstance(installed, dict) else {},
        "provider_browser_profile": str(raw.get("provider_browser_profile", "") or ""),
        "playwright_browsers_path": str(raw.get("playwright_browsers_path", "") or ""),
    }
    profile = public.get("profile_contract", {})
    if isinstance(profile, dict):
        browser_stack = profile.get("browser_stack", {})
        if isinstance(browser_stack, dict):
            browser_stack["shared_provider_profile"] = _public_provider_profile_label(
                browser_stack.get("shared_provider_profile")
            )
            profile["browser_stack"] = browser_stack
        else:
            profile["browser_stack"] = {}
        public["profile_contract"] = profile
    else:
        public["profile_contract"] = {}
    public["provider_browser_profile"] = _public_provider_profile_label(
        public.get("provider_browser_profile")
    )
    public["playwright_browsers_path"] = _public_playwright_path_label(
        public.get("playwright_browsers_path")
    )
    installed = public.get("installed_binaries", {})
    public["installed_binaries"] = (
        _public_installed_binary_paths(installed) if isinstance(installed, dict) else {}
    )
    return public


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


def _public_installed_binary_paths(installed: dict[str, Any]) -> dict[str, Any]:
    public: dict[str, Any] = {}
    for name, record in installed.items():
        if isinstance(record, dict):
            item = dict(record)
            if "path" in item:
                item["path"] = redact_public_path(item.get("path"))
            public[str(name)] = item
        else:
            public[str(name)] = record
    return public


def _canonical_json_signature(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _verification_report_signature(raw: Any) -> tuple[tuple[str, str, str, bool], ...]:
    if not isinstance(raw, dict):
        return ()
    checks = raw.get("checks", [])
    if not isinstance(checks, list):
        return ()
    rows: list[tuple[str, str, str, bool]] = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        details = check.get("details", {})
        details = details if isinstance(details, dict) else {}
        raw_status = str(check.get("status", "") or "").strip()
        pending_safe = raw_status == "pending_safe" or (
            raw_status == "pending" and details.get("pending_safe") is True
        )
        effective_status = "pending_safe" if pending_safe else raw_status or "unknown"
        rows.append(
            (
                str(check.get("provider", "") or "").strip().lower(),
                str(check.get("check", "") or "provider_status").strip().lower(),
                effective_status,
                pending_safe,
            )
        )
    return tuple(sorted(rows))


def _run_record_verifier_signature(raw: Any) -> tuple[tuple[str, str, str, bool], ...]:
    if not isinstance(raw, dict):
        return ()
    checks = raw.get("checks", [])
    if not isinstance(checks, list):
        return ()
    rows: list[tuple[str, str, str, bool]] = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        rows.append(
            (
                str(check.get("provider", "") or "").strip().lower(),
                str(check.get("check", "") or "provider_status").strip().lower(),
                str(check.get("status", "") or "unknown").strip(),
                check.get("pending_safe") is True,
            )
        )
    return tuple(sorted(rows))


def _public_jsonl_survivor_failures(path: Path, label: str) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [f"{label} could not be read"]
    failures: list[str] = []
    object_rows = 0
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            failures.append(f"{label} line {line_number} is malformed JSON")
            continue
        if not isinstance(event, dict):
            failures.append(f"{label} line {line_number} is not an object")
            continue
        object_rows += 1
        failures.extend(_audit_log_row_shape_failures(event, f"{label}[{line_number}]"))
        failures.extend(
            _public_json_survivor_failures(
                event,
                f"{label}[{line_number}]",
            )
        )
        if len(failures) >= 20:
            failures.append(f"{label} contains additional unsafe public text")
            break
    if object_rows == 0:
        failures.append(f"{label} has no JSON object rows")
    return failures


def _audit_log_row_shape_failures(event: dict[str, Any], label: str) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(event) - AUDIT_LOG_ROW_KEYS)
    if unexpected:
        failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
    event_name = event.get(AUDIT_LOG_EVENT_FIELD)
    if not isinstance(event_name, str) or not event_name:
        failures.append(f"{label}.{AUDIT_LOG_EVENT_FIELD} is missing")
    elif event_name != event_name.strip():
        failures.append(f"{label}.{AUDIT_LOG_EVENT_FIELD} must be trimmed")
    data = event.get(AUDIT_LOG_DATA_FIELD)
    if data is not None and not isinstance(data, dict):
        failures.append(f"{label}.{AUDIT_LOG_DATA_FIELD} must be an object")
    timestamp = event.get(AUDIT_LOG_TIMESTAMP_FIELD)
    if timestamp is not None:
        if not isinstance(timestamp, str):
            failures.append(f"{label}.{AUDIT_LOG_TIMESTAMP_FIELD} must be a string")
        elif timestamp != timestamp.strip():
            failures.append(f"{label}.{AUDIT_LOG_TIMESTAMP_FIELD} must be trimmed")
    return failures


def _contains_callback_url(value: str) -> bool:
    return bool(re.search(r"https?://[^\s\"'<>]*callback[^\s\"'<>]*", value, re.IGNORECASE))


def _model_inference_failures(model: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(model) - MODEL_INFERENCE_KEYS)
    if unexpected:
        failures.append(
            "central run record model inference has unexpected fields: "
            + ", ".join(unexpected)
        )
    if str(model.get("schema_version", "") or "") != "fusekit.model-inference-summary.v1":
        failures.append("central run record model inference schema is unsupported")
    status = str(model.get("status", "") or "")
    if status not in {"api_key_encrypted", "openclaw_profile_encrypted"}:
        failures.append(
            "central run record model inference has no encrypted API key or OpenClaw auth"
        )
    if model.get("ready") is not True:
        failures.append("central run record model inference is not ready")
    for key in ("required", "can_proceed_without_api_key"):
        if not isinstance(model.get(key), bool):
            failures.append(f"central run record model inference {key} must be boolean")
    if _safe_int(model.get("lane_count"), -1) < 0:
        failures.append("central run record model inference lane_count must be integer")
    for key in (
        "provider",
        "model",
        "base_url",
        "api_key_env",
        "auth_mode",
        "default_lane",
        "next_action",
        "statement",
    ):
        failures.extend(
            _llm_public_string_preflight_failures(
                model.get(key),
                f"central run record model inference {key}",
                check_secretish=key != "base_url",
            )
        )
    if str(model.get("auth_mode", "") or "") not in {"auto", "api-key", "openclaw"}:
        failures.append("central run record model inference auth mode is unsupported")
    next_action = str(model.get("next_action", "") or "").lower()
    if "encrypted" not in next_action and "continue" not in next_action:
        failures.append(
            "central run record model inference next action does not prove readiness"
        )
    statement = str(model.get("statement", "") or "").lower()
    if (
        "api keys are captured into the encrypted vault" not in statement
        or "raw secrets never appear" not in statement
    ):
        failures.append(
            "central run record model inference statement is missing secret-boundary proof"
        )
    return failures


def _llm_contract_failures(contract: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(contract) - LLM_CONTRACT_KEYS)
    if unexpected:
        failures.append(
            "central run record LLM contract has unexpected fields: "
            + ", ".join(unexpected)
        )
    if str(contract.get("schema_version", "") or "") != "fusekit.llm-contract.v1":
        failures.append("central run record LLM contract schema is unsupported")
    status = str(contract.get("status", "") or "")
    if status not in {"api_key_encrypted", "openclaw_profile_encrypted"}:
        failures.append(
            "central run record LLM contract has no encrypted API key or OpenClaw auth"
        )
    for key in ("required", "can_proceed_without_api_key"):
        if not isinstance(contract.get(key), bool):
            failures.append(f"central run record LLM contract {key} must be boolean")
    for key in (
        "provider",
        "model",
        "base_url",
        "api_key_env",
        "record_id",
        "auth_mode",
        "default_lane",
        "next_action",
    ):
        failures.extend(
            _llm_public_string_preflight_failures(
                contract.get(key),
                f"central run record LLM contract {key}",
                check_secretish=key != "base_url",
            )
        )
    if str(contract.get("auth_mode", "") or "") not in {"auto", "api-key", "openclaw"}:
        failures.append("central run record LLM contract auth mode is unsupported")
    lanes = contract.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        failures.append("central run record LLM contract lanes are missing")
        lanes = []
    else:
        failures.extend(_llm_contract_lane_failures(lanes, contract))
    security = contract.get("security", {})
    if not isinstance(security, dict):
        failures.append("central run record LLM contract security proof is missing")
    else:
        unexpected_security = sorted(set(security) - LLM_CONTRACT_SECURITY_KEYS)
        if unexpected_security:
            failures.append(
                "central run record LLM contract security has unexpected fields: "
                + ", ".join(unexpected_security)
            )
        if str(security.get("raw_secret_export", "") or "") != "denied":
            failures.append("central run record LLM contract raw secret export is not denied")
        for key in ("storage", "public_surfaces", "detonation"):
            failures.extend(
                _llm_public_string_preflight_failures(
                    security.get(key),
                    f"central run record LLM contract security {key}",
                )
            )
        storage = str(security.get("storage", "") or "").lower()
        if "encrypted" not in storage or "vault" not in storage:
            failures.append(
                "central run record LLM contract storage proof is not encrypted vault"
            )
    return failures


def _llm_contract_lane_failures(
    lanes: list[Any],
    contract: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    seen: set[str] = set()
    lane_by_id: dict[str, dict[str, Any]] = {}
    for index, lane in enumerate(lanes):
        label = f"central run record LLM contract lanes[{index}]"
        if not isinstance(lane, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(lane) - LLM_CONTRACT_LANE_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        raw_lane_id = str(lane.get("id", "") or "")
        lane_id = raw_lane_id.strip()
        if not lane_id:
            failures.append(f"{label}.id is missing")
        else:
            if raw_lane_id != lane_id:
                failures.append(f"{label}.id must not have surrounding whitespace")
            if lane_id in seen:
                failures.append(f"{label}.id duplicates LLM contract lane {lane_id}")
            else:
                lane_by_id[lane_id] = lane
            seen.add(lane_id)
        raw_label = str(lane.get("label", "") or "")
        label_value = raw_label.strip()
        if not label_value:
            failures.append(f"{label}.label is missing")
        elif raw_label != label_value:
            failures.append(f"{label}.label must not have surrounding whitespace")
        if not isinstance(lane.get("available"), bool):
            failures.append(f"{label}.available must be boolean")
        if not isinstance(lane.get("requires_user_action"), bool):
            failures.append(f"{label}.requires_user_action must be boolean")
        raw_description = str(lane.get("description", "") or "")
        description = raw_description.strip()
        if not description:
            failures.append(f"{label}.description is missing")
        elif raw_description != description:
            failures.append(f"{label}.description must not have surrounding whitespace")
        elif contains_durable_secret_text(description) or _contains_callback_url(description):
            failures.append(f"{label}.description contains unsafe public text")
    default_lane = str(contract.get("default_lane", "") or "").strip()
    if not default_lane:
        failures.append("central run record LLM contract default_lane is missing")
    elif default_lane not in seen:
        failures.append("central run record LLM contract default_lane must match lanes")
    elif default_lane in lane_by_id:
        default = lane_by_id[default_lane]
        if default.get("available") is not True:
            failures.append("central run record LLM contract default_lane must be available")
        if default.get("requires_user_action") is not False:
            failures.append(
                "central run record LLM contract default_lane must not require user "
                "action when ready"
            )
    status = str(contract.get("status", "") or "")
    if status == "api_key_encrypted" and "api-key" not in seen:
        failures.append("central run record LLM contract lanes must include api-key")
    elif status == "api_key_encrypted" and "api-key" in lane_by_id:
        lane = lane_by_id["api-key"]
        if lane.get("available") is not True:
            failures.append(
                "central run record LLM contract lanes must mark api-key available"
            )
        if lane.get("requires_user_action") is not False:
            failures.append(
                "central run record LLM contract lanes must mark api-key ready "
                "without user action"
            )
    if status == "openclaw_profile_encrypted" and "openclaw-openai" not in seen:
        failures.append("central run record LLM contract lanes must include openclaw-openai")
    elif status == "openclaw_profile_encrypted" and "openclaw-openai" in lane_by_id:
        lane = lane_by_id["openclaw-openai"]
        if lane.get("available") is not True:
            failures.append(
                "central run record LLM contract lanes must mark openclaw-openai "
                "available"
            )
        if lane.get("requires_user_action") is not False:
            failures.append(
                "central run record LLM contract lanes must mark openclaw-openai "
                "ready without user action"
            )
    return failures


def _llm_public_string_preflight_failures(
    value: Any,
    label: str,
    *,
    check_secretish: bool = True,
) -> list[str]:
    raw = str(value or "")
    text = raw.strip()
    if not text:
        return [f"{label} is missing"]
    failures: list[str] = []
    if raw != text:
        failures.append(f"{label} must not have surrounding whitespace")
    if _contains_callback_url(text) or (
        check_secretish and contains_durable_secret_text(text)
    ):
        failures.append(f"{label} contains unsafe public text")
    return failures


def _model_inference_contract_failures(
    model: dict[str, Any],
    contract: dict[str, Any],
) -> list[str]:
    if not model or not contract:
        return []
    failures: list[str] = []
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
    mismatched = [
        field
        for field in fields
        if str(model.get(field, "") or "") != str(contract.get(field, "") or "")
    ]
    if mismatched:
        failures.append(
            "central run record model inference does not match LLM contract: "
            + ", ".join(sorted(mismatched))
        )
    lanes = contract.get("lanes", [])
    if isinstance(lanes, list) and _safe_int(model.get("lane_count"), -1) != len(lanes):
        failures.append(
            "central run record model inference lane_count must match LLM contract lanes"
        )
    return failures


def _llm_contract_artifact_failures(contract: dict[str, Any]) -> list[str]:
    if not contract:
        return ["model/inference contract could not be read"]
    failures = [
        failure.replace("central run record LLM contract", "model/inference contract")
        for failure in _llm_contract_failures(contract)
    ]
    failures.extend(_public_json_survivor_failures(contract, "model/inference contract"))
    return failures


def _run_record_llm_contract_artifact_failures(
    run_record: dict[str, Any],
    contract: dict[str, Any],
) -> list[str]:
    embedded = run_record.get("llm_contract", {})
    if not isinstance(embedded, dict) or not embedded:
        return []
    if json.dumps(embedded, sort_keys=True, separators=(",", ":")) == json.dumps(
        contract,
        sort_keys=True,
        separators=(",", ":"),
    ):
        return []
    return [
        "central run record LLM contract does not match llm_contract.json artifact"
    ]


def _provider_gates_preflight_failures(provider_gates: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_summary_keys = sorted(set(provider_gates) - PROVIDER_GATES_KEYS)
    if unexpected_summary_keys:
        failures.append(
            "central run record provider gates has unexpected fields: "
            + ", ".join(unexpected_summary_keys)
        )
    records = provider_gates.get("records")
    statuses = provider_gates.get("statuses")
    providers = provider_gates.get("providers")
    if not isinstance(records, list):
        failures.append("central run record provider gates records are missing")
        records = []
    if not isinstance(statuses, dict):
        failures.append("central run record provider gates statuses are missing")
        statuses = {}
    if not isinstance(providers, list):
        failures.append("central run record provider gates providers are missing")
        providers = []
    total = provider_gates.get("total")
    if not isinstance(total, int) or isinstance(total, bool):
        failures.append("central run record provider gates total must be a literal integer")
    elif total != len(records):
        failures.append("central run record provider gates total must match records")
    actual_statuses: dict[str, int] = {}
    actual_providers: set[str] = set()
    seen_gate_ids: set[str] = set()
    for index, provider_value in enumerate(providers):
        label = f"central run record provider gates providers[{index}]"
        if not isinstance(provider_value, str) or not provider_value:
            failures.append(f"{label} is missing")
        elif provider_value != provider_value.strip():
            failures.append(f"{label} must be trimmed")
        elif contains_durable_secret_text(provider_value):
            failures.append(f"{label} contains credential-looking text")
    for index, gate in enumerate(records):
        label = f"central run record provider gates records[{index}]"
        if not isinstance(gate, dict):
            failures.append(f"{label} is not an object")
            continue
        failures.extend(_provider_gate_record_shape_failures(gate, label))
        gate_id = gate.get("id", "")
        status = gate.get("status", "")
        provider = gate.get("provider", "")
        if not gate_id:
            failures.append(f"{label}.id is missing")
        elif not isinstance(gate_id, str):
            failures.append(f"{label}.id must be text")
        elif gate_id != gate_id.strip():
            failures.append(f"{label}.id must be trimmed")
        elif gate_id in seen_gate_ids:
            failures.append(f"{label}.id is duplicated")
        else:
            seen_gate_ids.add(gate_id)
        if not status:
            failures.append(f"{label}.status is missing")
        elif not isinstance(status, str):
            failures.append(f"{label}.status must be text")
        elif status != status.strip():
            failures.append(f"{label}.status must be trimmed")
        else:
            actual_statuses[status] = actual_statuses.get(status, 0) + 1
        if not provider:
            failures.append(f"{label}.provider is missing")
        elif not isinstance(provider, str):
            failures.append(f"{label}.provider must be text")
        elif provider != provider.strip():
            failures.append(f"{label}.provider must be trimmed")
        else:
            actual_providers.add(provider)
    provider_values = {str(provider) for provider in providers}
    if provider_values != actual_providers:
        failures.append("central run record provider gates providers must match records")
    for status, count in statuses.items():
        if not isinstance(status, str) or not status:
            failures.append("central run record provider gates statuses key is missing")
        elif status != status.strip():
            failures.append(
                f"central run record provider gates statuses.{status} must be trimmed"
            )
        if not isinstance(count, int) or isinstance(count, bool):
            failures.append(
                f"central run record provider gates statuses.{status} "
                "must be a literal integer"
            )
    status_values = {str(status) for status in statuses}
    if status_values != set(actual_statuses):
        failures.append("central run record provider gates statuses must match records")
    for status, expected in actual_statuses.items():
        status_count = statuses.get(status)
        if isinstance(status_count, int) and not isinstance(status_count, bool):
            matches_expected = status_count == expected
        else:
            matches_expected = False
        if not matches_expected:
            failures.append(
                f"central run record provider gates statuses.{status} must match records"
            )
    return failures


def _provider_gate_record_shape_failures(
    gate: dict[str, Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected_keys = sorted(set(gate) - PROVIDER_GATE_RECORD_KEYS)
    if unexpected_keys:
        failures.append(f"{label} has unexpected fields: " + ", ".join(unexpected_keys))
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
        value = gate.get(key)
        if value is None:
            continue
        field_label = f"{label}.{key}"
        if not isinstance(value, str):
            failures.append(f"{field_label} must be text")
        elif value and value != value.strip():
            failures.append(f"{field_label} must be trimmed")
        elif contains_durable_secret_text(value):
            failures.append(f"{field_label} contains credential-looking text")
    for key in ("captured_targets", "follow_steps", "success_criteria", "avoid_steps"):
        values = gate.get(key)
        if values is None:
            continue
        field_label = f"{label}.{key}"
        if not isinstance(values, list):
            failures.append(f"{field_label} must be a list")
            continue
        for index, value in enumerate(values):
            item_label = f"{field_label}[{index}]"
            if not isinstance(value, str):
                failures.append(f"{item_label} must be text")
            elif value != value.strip():
                failures.append(f"{item_label} must be trimmed")
            elif contains_durable_secret_text(value):
                failures.append(f"{item_label} contains credential-looking text")
    attempts = gate.get("attempts", 0)
    if not isinstance(attempts, int) or isinstance(attempts, bool) or attempts < 0:
        failures.append(f"{label}.attempts must be a non-negative integer")
    for key in ("last_opened_at", "last_wake_event_at", "created_at", "updated_at"):
        value = gate.get(key, 0)
        if not isinstance(value, int | float) or isinstance(value, bool) or value < 0:
            failures.append(f"{label}.{key} must be a non-negative timestamp")
    return failures


def _wake_events_preflight_failures(wake_events: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_summary_keys = sorted(set(wake_events) - WAKE_EVENTS_KEYS)
    if unexpected_summary_keys:
        failures.append(
            "central run record wake events has unexpected fields: "
            + ", ".join(unexpected_summary_keys)
        )
    events = wake_events.get("events")
    counts = wake_events.get("event_counts")
    if not isinstance(events, list):
        failures.append("central run record wake events are missing")
        events = []
    if not isinstance(counts, dict):
        failures.append("central run record wake event counts are missing")
        counts = {}
    total = wake_events.get("total")
    if not isinstance(total, int) or isinstance(total, bool):
        failures.append("central run record wake events total must be a literal integer")
    elif total != len(events):
        failures.append("central run record wake events total must match events")
    actual_counts: dict[str, int] = {}
    seen_event_ids: set[str] = set()
    seen_event_proofs: set[tuple[str, str, str]] = set()
    for index, event in enumerate(events):
        label = f"central run record wake events[{index}]"
        if not isinstance(event, dict):
            failures.append(f"{label} is not an object")
            continue
        failures.extend(_wake_event_record_shape_failures(event, label))
        event_name = event.get("event", "")
        gate_id = event.get("gate_id", "")
        target = event.get("target", "")
        event_id = event.get("id", "")
        if not event_name:
            failures.append(f"{label}.event is missing")
        elif not isinstance(event_name, str):
            failures.append(f"{label}.event must be text")
        elif event_name != event_name.strip():
            failures.append(f"{label}.event must be trimmed")
        elif contains_durable_secret_text(event_name):
            failures.append(f"{label}.event contains credential-looking text")
        else:
            actual_counts[event_name] = actual_counts.get(event_name, 0) + 1
        if not gate_id:
            failures.append(f"{label}.gate_id is missing")
        elif not isinstance(gate_id, str):
            failures.append(f"{label}.gate_id must be text")
        elif gate_id != gate_id.strip():
            failures.append(f"{label}.gate_id must be trimmed")
        elif contains_durable_secret_text(gate_id):
            failures.append(f"{label}.gate_id contains credential-looking text")
        if isinstance(event_id, str) and event_id:
            if event_id != event_id.strip():
                failures.append(f"{label}.id must be trimmed")
            elif contains_durable_secret_text(event_id):
                failures.append(f"{label}.id contains credential-looking text")
            elif event_id in seen_event_ids:
                failures.append(f"{label}.id is duplicated")
            seen_event_ids.add(event_id)
        elif event_id:
            failures.append(f"{label}.id must be text")
        if isinstance(event_name, str) and isinstance(gate_id, str):
            target_text = target if isinstance(target, str) else ""
            identity = (event_name, gate_id, target_text)
        else:
            identity = ("", "", "")
        if all(identity[:2]):
            if identity in seen_event_proofs:
                failures.append(f"{label} is duplicated")
            seen_event_proofs.add(identity)
    for event_name, count in counts.items():
        if not isinstance(event_name, str) or not event_name:
            failures.append("central run record wake event counts key is missing")
        elif event_name != event_name.strip():
            failures.append(
                f"central run record wake event counts.{event_name} must be trimmed"
            )
        elif contains_durable_secret_text(event_name):
            failures.append(
                f"central run record wake event counts.{event_name} "
                "contains credential-looking text"
            )
        if not isinstance(count, int) or isinstance(count, bool):
            failures.append(
                f"central run record wake event counts.{event_name} "
                "must be a literal integer"
            )
    for event_name, expected in actual_counts.items():
        count = counts.get(event_name)
        if isinstance(count, int) and not isinstance(count, bool):
            matches_expected = count == expected
        else:
            matches_expected = False
        if not matches_expected:
            failures.append(
                f"central run record wake event counts.{event_name} must match events"
            )
    return failures


def _wake_event_record_shape_failures(
    event: dict[str, Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected_keys = sorted(set(event) - WAKE_EVENT_RECORD_KEYS)
    if unexpected_keys:
        failures.append(f"{label} has unexpected fields: " + ", ".join(unexpected_keys))
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
        field_label = f"{label}.{key}"
        if not isinstance(value, str):
            failures.append(f"{field_label} must be text")
        elif value and value != value.strip():
            failures.append(f"{field_label} must be trimmed")
        elif value and contains_durable_secret_text(value):
            failures.append(f"{field_label} contains credential-looking text")
    if not event.get("schema_version"):
        failures.append(f"{label}.schema_version is missing")
    if not event.get("event"):
        failures.append(f"{label}.event is missing")
    if not event.get("gate_id"):
        failures.append(f"{label}.gate_id is missing")
    target_count = event.get("target_count", 0)
    if not isinstance(target_count, int) or isinstance(target_count, bool) or target_count < 0:
        failures.append(f"{label}.target_count must be a non-negative integer")
    captured_targets = event.get("captured_targets", [])
    if not isinstance(captured_targets, list):
        failures.append(f"{label}.captured_targets must be a list")
    else:
        for index, captured_target in enumerate(captured_targets):
            item_label = f"{label}.captured_targets[{index}]"
            if not isinstance(captured_target, str):
                failures.append(f"{item_label} must be text")
            elif captured_target != captured_target.strip():
                failures.append(f"{item_label} must be trimmed")
            elif contains_durable_secret_text(captured_target):
                failures.append(f"{item_label} contains credential-looking text")
    created_at = event.get("created_at", 0)
    if not isinstance(created_at, int | float) or isinstance(created_at, bool) or created_at < 0:
        failures.append(f"{label}.created_at must be a non-negative timestamp")
    return failures


def _gate_wake_consistency_failures(
    provider_gates: dict[str, Any],
    wake_events: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    records = provider_gates.get("records", [])
    events = wake_events.get("events", [])
    if not isinstance(records, list) or not isinstance(events, list):
        return failures
    captured_pairs = {
        (
            str(event.get("gate_id", "") or "").strip(),
            str(event.get("target", "") or "").strip(),
        )
        for event in events
        if isinstance(event, dict)
        and str(event.get("event", "") or "").strip() == "clipboard_captured"
    }
    for gate in records:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "") or "").strip()
        if not gate_id:
            continue
        captured_targets = gate.get("captured_targets", [])
        if not isinstance(captured_targets, list):
            continue
        for target in captured_targets:
            target_text = str(target or "").strip()
            if target_text and (gate_id, target_text) not in captured_pairs:
                failures.append(
                    "central run record provider gate "
                    f"{gate_id} captured target {target_text} has no wake event"
            )
    return failures


def _approval_summary_preflight_failures(
    approvals: list[Any],
    provider_gates: Any,
    wake_events: Any,
) -> list[str]:
    failures: list[str] = []
    gate_records = provider_gates.get("records", []) if isinstance(provider_gates, dict) else []
    gate_records = gate_records if isinstance(gate_records, list) else []
    gate_statuses: dict[str, str] = {}
    for gate in gate_records:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "") or "").strip()
        if gate_id:
            gate_statuses[gate_id] = str(gate.get("status", "") or "").strip()
    raw_events = wake_events.get("events", []) if isinstance(wake_events, dict) else []
    raw_events = raw_events if isinstance(raw_events, list) else []
    resumed_gate_ids = {
        str(event.get("gate_id", "") or "").strip()
        for event in raw_events
        if isinstance(event, dict)
        and str(event.get("event", "") or "").strip() == "resume_requested"
    }
    seen_approval_ids: set[str] = set()
    for index, approval in enumerate(approvals):
        label = f"central run record approvals[{index}]"
        if not isinstance(approval, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(approval) - APPROVAL_SUMMARY_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        approval_id = str(approval.get("id", "") or "").strip()
        if approval_id:
            if approval_id in seen_approval_ids:
                failures.append(f"{label}.id duplicates approval summary for {approval_id}")
            seen_approval_ids.add(approval_id)
        provider = str(approval.get("provider", "") or "").strip()
        status = str(approval.get("status", "") or "").strip()
        reason = str(approval.get("reason", "") or "").strip()
        values_by_field = {
            APPROVAL_SUMMARY_ID_FIELD: approval_id,
            APPROVAL_SUMMARY_PROVIDER_FIELD: provider,
            APPROVAL_SUMMARY_REASON_FIELD: reason,
            APPROVAL_SUMMARY_STATUS_FIELD: status,
        }
        for key in APPROVAL_SUMMARY_TEXT_FIELDS:
            value = values_by_field[key]
            if not value:
                failures.append(f"{label}.{key} is missing")
            elif str(approval.get(key, "") or "") != value:
                failures.append(f"{label}.{key} must not have surrounding whitespace")
            if value and contains_durable_secret_text(value):
                failures.append(f"{label}.{key} contains credential-looking text")
        if status and status not in APPROVAL_SUMMARY_READY_STATUSES:
            failures.append(f"{label}.status is unsupported")
        updated_at = approval.get(APPROVAL_SUMMARY_UPDATED_AT_FIELD)
        if (
            not isinstance(updated_at, int | float)
            or isinstance(updated_at, bool)
            or updated_at < 0
        ):
            failures.append(
                f"{label}.{APPROVAL_SUMMARY_UPDATED_AT_FIELD} "
                "must be a non-negative number"
            )
        if approval_id and gate_statuses and approval_id not in gate_statuses:
            failures.append(f"{label}.id must match provider_gates.records")
        if approval_id and status == "resume_requested":
            gate_status = gate_statuses.get(approval_id, "")
            if gate_status and gate_status != "resume_requested":
                failures.append(f"{label}.status must match provider_gates.records")
            if resumed_gate_ids and approval_id not in resumed_gate_ids:
                failures.append(f"{label}.id must match a resume_requested wake event")
    return failures

def _run_record_error_preflight_failures(errors: list[Any]) -> list[str]:
    failures: list[str] = []
    seen_error_ids: set[tuple[str, str]] = set()
    for index, error in enumerate(errors):
        label = f"central run record errors[{index}]"
        if not isinstance(error, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(error) - RUN_RECORD_ERROR_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        for key in RUN_RECORD_ERROR_FIELDS:
            value = str(error.get(key, "") or "")
            if not value.strip():
                failures.append(f"{label}.{key} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
            elif contains_durable_secret_text(value):
                failures.append(f"{label}.{key} contains credential-looking text")
        source = str(error.get("source", "") or "").strip()
        error_id = str(error.get("id", "") or "").strip()
        if source and error_id:
            identity = (source, error_id)
            if identity in seen_error_ids:
                failures.append(f"{label} duplicates error {source}:{error_id}")
            seen_error_ids.add(identity)
    return failures


def _acceptance_summary_preflight_failures(
    summary: dict[str, Any],
    payload: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(summary) - _ACCEPTANCE_SUMMARY_KEYS)
    if unexpected:
        failures.append(
            "central run record acceptance has unexpected fields: "
            + ", ".join(unexpected)
        )
    raw_mode = summary.get("mode")
    mode = raw_mode if isinstance(raw_mode, str) else ""
    if mode not in {"live", "rehearsal"}:
        failures.append("central run record acceptance.mode must be live or rehearsal")
    for key in ACCEPTANCE_SUMMARY_READY_FIELDS:
        if not isinstance(summary.get(key), bool):
            failures.append(f"central run record acceptance.{key} must be boolean")
    blockers = summary.get("blockers")
    if not isinstance(blockers, list):
        failures.append("central run record acceptance.blockers must be a list")
    else:
        failures.extend(_acceptance_blocker_preflight_failures(blockers))
    missing = summary.get("missing")
    if not isinstance(missing, list):
        failures.append("central run record acceptance.missing must be a list")
    else:
        failures.extend(_acceptance_missing_preflight_failures(missing))
    if isinstance(missing, list) and isinstance(blockers, list):
        failures.extend(
            _acceptance_missing_blocker_preflight_consistency_failures(
                missing,
                blockers,
            )
        )
    error = summary.get("error")
    if not isinstance(error, str):
        failures.append("central run record acceptance.error must be a string")
    else:
        failures.extend(_acceptance_error_preflight_failures(error))
    launch_ready = summary.get("launch_ready")
    public_launch_ready = summary.get("public_launch_ready")
    remote_artifacts_ready = summary.get("remote_artifacts_ready")
    recording_proof_ready = summary.get("recording_proof_ready")
    recording_ready = summary.get("recording_ready")
    if isinstance(launch_ready, bool) and isinstance(public_launch_ready, bool):
        if public_launch_ready is not (mode == "live" and launch_ready is True):
            failures.append(
                "central run record acceptance.public_launch_ready must equal "
                "live launch_ready"
            )
    if (
        isinstance(public_launch_ready, bool)
        and isinstance(remote_artifacts_ready, bool)
        and isinstance(recording_proof_ready, bool)
        and isinstance(recording_ready, bool)
    ):
        if recording_ready is not (
            public_launch_ready is True
            and remote_artifacts_ready is True
            and recording_proof_ready is True
        ):
            failures.append(
                "central run record acceptance.recording_ready must equal "
                "public_launch_ready and remote_artifacts_ready and recording_proof_ready"
            )
    if summary.get("public_launch_ready") is True and summary.get("launch_ready") is not True:
        failures.append(
            "central run record acceptance.public_launch_ready must require launch_ready"
        )
    if summary.get("public_launch_ready") is True and mode != "live":
        failures.append(
            "central run record acceptance.public_launch_ready must require live mode"
        )
    if summary.get("recording_ready") is True and summary.get("public_launch_ready") is not True:
        failures.append(
            "central run record acceptance.recording_ready must require public_launch_ready"
        )
    if summary.get("recording_ready") is True and summary.get("recording_proof_ready") is not True:
        failures.append(
            "central run record acceptance.recording_ready must require recording_proof_ready"
        )
    if summary.get("recording_ready") is True and summary.get("remote_artifacts_ready") is not True:
        failures.append(
            "central run record acceptance.recording_ready must require remote_artifacts_ready"
        )
    if summary.get("recording_ready") is True and mode != "live":
        failures.append("central run record acceptance.recording_ready must require live mode")
    if isinstance(blockers, list) and blockers and any(
        summary.get(key) is True
        for key in ("launch_ready", "public_launch_ready", "recording_ready")
    ):
        failures.append(
            "central run record acceptance.blockers must be empty when readiness is true"
        )
    if isinstance(missing, list) and missing and any(
        summary.get(key) is True
        for key in ("launch_ready", "public_launch_ready", "recording_ready")
    ):
        failures.append(
            "central run record acceptance.missing must be empty when readiness is true"
        )
    if isinstance(error, str) and error.strip() and any(
        summary.get(key) is True
        for key in ("launch_ready", "public_launch_ready", "recording_ready")
    ):
        failures.append(
            "central run record acceptance.error must be empty when readiness is true"
        )
    errors = payload.get("errors", [])
    if isinstance(errors, list) and errors and any(
        summary.get(key) is True
        for key in ("launch_ready", "public_launch_ready", "recording_ready")
    ):
        failures.append(
            "central run record acceptance readiness must be false when errors are present"
        )
    if summary.get("recording_ready") is True and isinstance(errors, list) and errors:
        failures.append(
            "central run record acceptance.recording_ready must be false when errors are present"
        )
    recording_contract = payload.get("recording_contract", {})
    if isinstance(recording_contract, dict) and "recording_ready" in recording_contract:
        if summary.get("recording_proof_ready") is not recording_contract.get(
            "recording_ready"
        ):
            failures.append(
                "central run record acceptance.recording_proof_ready must match "
                "recording_contract.recording_ready"
            )
    return failures


_ACCEPTANCE_SUMMARY_KEYS = ACCEPTANCE_SUMMARY_KEYS


def _acceptance_error_preflight_failures(error: str) -> list[str]:
    if not error:
        return []
    if not error.strip():
        return ["central run record acceptance.error must be empty or non-empty text"]
    if error != error.strip():
        return ["central run record acceptance.error must not have surrounding whitespace"]
    return []


def _acceptance_missing_preflight_failures(missing: list[Any]) -> list[str]:
    failures: list[str] = []
    seen_items: set[str] = set()
    for index, item in enumerate(missing):
        label = f"central run record acceptance.missing[{index}]"
        if not isinstance(item, str):
            failures.append("central run record acceptance.missing must contain only strings")
            continue
        normalized = item.strip()
        if not normalized:
            failures.append(f"{label} must be non-empty")
            continue
        if item != normalized:
            failures.append(f"{label} must not have surrounding whitespace")
        if normalized in seen_items:
            failures.append(
                f"{label} duplicates acceptance missing proof {normalized}"
            )
        seen_items.add(normalized)
    return failures


def _acceptance_blocker_preflight_failures(blockers: list[Any]) -> list[str]:
    failures: list[str] = []
    seen_items: set[str] = set()
    for index, blocker in enumerate(blockers):
        label = f"central run record acceptance.blockers[{index}]"
        if not isinstance(blocker, dict):
            failures.append(f"{label} must be an object")
            continue
        unexpected = sorted(str(key) for key in blocker if str(key) not in ACCEPTANCE_BLOCKER_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        for key in ACCEPTANCE_BLOCKER_REQUIRED_FIELDS:
            value = blocker.get(key)
            if not isinstance(value, str) or not value.strip():
                failures.append(f"{label}.{key} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        item = blocker.get("item")
        if isinstance(item, str) and item.strip():
            normalized_item = item.strip()
            if normalized_item in seen_items:
                failures.append(
                    f"{label}.item duplicates acceptance blocker {normalized_item}"
                )
            seen_items.add(normalized_item)
        detail = blocker.get("detail")
        if "detail" in blocker:
            if not isinstance(detail, str):
                failures.append(f"{label}.detail must be a string")
            elif not detail:
                failures.append(f"{label}.detail must be non-empty when present")
            elif detail != detail.strip():
                failures.append(f"{label}.detail must not have surrounding whitespace")
    return failures


def _acceptance_missing_blocker_preflight_consistency_failures(
    missing: list[Any],
    blockers: list[Any],
) -> list[str]:
    blocker_items = {
        str(blocker.get("item", "")).strip()
        for blocker in blockers
        if isinstance(blocker, dict) and str(blocker.get("item", "")).strip()
    }
    failures: list[str] = []
    for index, item in enumerate(missing):
        if not isinstance(item, str):
            continue
        normalized = item.strip()
        if normalized and normalized not in blocker_items:
            failures.append(
                "central run record "
                f"acceptance.missing[{index}] has no matching blocker item {normalized}"
            )
    return failures


def _vault_summary_preflight_failures(vault: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_vault_keys = sorted(set(vault) - VAULT_KEYS)
    if unexpected_vault_keys:
        failures.append(
            "central run record vault has unexpected fields: "
            + ", ".join(unexpected_vault_keys)
        )
    records = vault.get("records", [])
    if not isinstance(records, list):
        failures.append("central run record vault records are missing")
        records = []
    record_count = vault.get("record_count")
    if not isinstance(record_count, int) or isinstance(record_count, bool):
        failures.append("central run record vault record_count must be a literal integer")
    elif record_count != len(records):
        failures.append("central run record vault record_count must match records")
    seen_record_ids: set[str] = set()
    for index, record in enumerate(records):
        label = f"central run record vault records[{index}]"
        if not isinstance(record, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected_record_keys = sorted(set(record) - VAULT_RECORD_KEYS)
        if unexpected_record_keys:
            failures.append(
                f"{label} has unexpected fields: " + ", ".join(unexpected_record_keys)
            )
        for field in ("id", "kind", "provider", "label"):
            value = record.get(field, "")
            if not isinstance(value, str) or not value:
                failures.append(f"{label}.{field} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{field} must be trimmed")
            elif contains_durable_secret_text(value):
                failures.append(f"{label}.{field} contains credential-looking text")
        record_id = record.get("id", "")
        if isinstance(record_id, str) and record_id:
            if record_id in seen_record_ids:
                failures.append(f"{label}.id duplicates vault record {record_id}")
            seen_record_ids.add(record_id)
        failures.extend(_vault_record_secret_field_failures(record, label))
    return failures


def _vault_record_secret_field_failures(value: Any, label: str) -> list[str]:
    failures: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            field_label = f"{label}.{key_text}"
            if key_text.strip().lower() in VAULT_SECRET_FIELD_NAMES:
                if label.startswith("central run record vault records[") and key_text == "value":
                    failures.append(f"{label} exposes a raw value")
                else:
                    failures.append(f"{field_label} exposes raw secret metadata")
                continue
            failures.extend(_vault_record_secret_field_failures(nested, field_label))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            failures.extend(_vault_record_secret_field_failures(nested, f"{label}[{index}]"))
    return failures


def _timeline_preflight_failures(label: str, entries: list[Any]) -> list[str]:
    failures: list[str] = []
    seen_entry_ids: set[str] = set()
    for index, entry in enumerate(entries):
        entry_label = f"central run record {label}[{index}]"
        if not isinstance(entry, dict):
            failures.append(f"{entry_label} is not an object")
            continue
        unexpected = sorted(set(entry) - _RUN_RECORD_TIMELINE_KEYS)
        if unexpected:
            failures.append(f"{entry_label} has unexpected fields: {', '.join(unexpected)}")
        for key in TIMELINE_REQUIRED_TEXT_FIELDS:
            value = str(entry.get(key, "") or "")
            if not value.strip():
                failures.append(f"{entry_label}.{key} is missing")
            elif value != value.strip():
                failures.append(f"{entry_label}.{key} must not have surrounding whitespace")
        entry_id = str(entry.get("id", "") or "").strip()
        if entry_id:
            if entry_id in seen_entry_ids:
                failures.append(f"{entry_label}.id duplicates {label} entry {entry_id}")
            seen_entry_ids.add(entry_id)
        for key in TIMELINE_OPTIONAL_TEXT_FIELDS:
            value = str(entry.get(key, "") or "")
            if not value:
                continue
            if value != value.strip():
                failures.append(f"{entry_label}.{key} must not have surrounding whitespace")
            if contains_durable_secret_text(value):
                failures.append(f"{entry_label}.{key} contains credential-looking text")
        updated_at = entry.get(TIMELINE_TIMESTAMP_FIELD, 0)
        if (
            not isinstance(updated_at, int | float)
            or isinstance(updated_at, bool)
            or updated_at < 0
        ):
            failures.append(
                f"{entry_label}.{TIMELINE_TIMESTAMP_FIELD} must be a non-negative number"
            )
    return failures


_RUN_RECORD_TIMELINE_KEYS = TIMELINE_ENTRY_KEYS


def _provider_playbook_preflight_failures(playbook: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(playbook.get("schema_version", "") or "").strip() != "fusekit.provider-playbook.v1":
        failures.append("central run record provider playbook schema is unsupported")
    steps = playbook.get("steps", [])
    safety_notes = playbook.get("safety_notes", [])
    if not isinstance(steps, list) or not steps:
        failures.append("central run record provider playbook steps are missing")
        steps = []
    if not isinstance(safety_notes, list) or not safety_notes:
        failures.append("central run record provider playbook safety notes are missing")
        safety_notes = []
    seen_step_ids: set[str] = set()
    step_ids: list[str] = []
    providers: set[str] = set()
    for index, step in enumerate(steps):
        label = f"central run record provider playbook steps[{index}]"
        if not isinstance(step, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(step) - _PROVIDER_PLAYBOOK_STEP_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        for key in (
            "id",
            "provider",
            "route",
            "control",
            "instruction",
            "actor",
            "proof_source",
            "resume_event",
        ):
            value = str(step.get(key, "") or "")
            if value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        step_id = str(step.get("id", "") or "").strip()
        provider = str(step.get("provider", "") or "").strip().lower()
        route = str(step.get("route", "") or "").strip()
        if step_id:
            if step_id in seen_step_ids:
                failures.append(f"{label}.id is duplicated")
            seen_step_ids.add(step_id)
            step_ids.append(step_id)
        else:
            failures.append(f"{label}.id is missing")
        if provider:
            providers.add(provider)
        instruction = str(step.get("instruction", "") or "")
        for key in ("provider", "instruction", "control", "actor", "proof_source", "resume_event"):
            if not str(step.get(key, "") or "").strip():
                failures.append(f"{label}.{key} is missing")
        if _provider_playbook_instruction_is_unsafe(instruction):
            failures.append(f"{label}.instruction asks for unsafe provider work")
        if route not in {"api", "official_cli", "browser_guided", "human_follow_me", "local_vault"}:
            failures.append(f"{label}.route is unsupported")
        if route in {"api", "official_cli"} and step.get("human_action_required") is not False:
            failures.append(f"{label}.human_action_required must be false")
        if route in {"browser_guided", "human_follow_me", "local_vault"} and (
            step.get("human_action_required") is not True
        ):
            failures.append(f"{label}.human_action_required must be true")
        failures.extend(
            _provider_playbook_actor_preflight_failures(
                label,
                route=route,
                actor=str(step.get("actor", "") or "").strip(),
                human_action_required=step.get("human_action_required"),
            )
        )
        failures.extend(
            _provider_playbook_control_preflight_failures(
                label,
                step_id=step_id,
                route=route,
                control=str(step.get("control", "") or "").strip(),
            )
        )
        failures.extend(
            _provider_playbook_proof_preflight_failures(
                label,
                route=route,
                proof_source=str(step.get("proof_source", "") or "").strip(),
                resume_event=str(step.get("resume_event", "") or "").strip(),
            )
        )
    failures.extend(_provider_playbook_order_preflight_failures(step_ids))
    missing = [
        label
        for label, accepted in PUBLIC_PROVIDER_FAMILIES.items()
        if not accepted & providers
    ]
    if missing:
        failures.append(
            "central run record provider playbook is missing public provider coverage: "
            + ", ".join(sorted(missing))
        )
    joined_notes = " ".join(str(note) for note in safety_notes)
    for phrase in (
        "VM browser",
        "Do not create Resend domains or audiences manually",
        "Do not paste provider secrets into the host computer",
    ):
        if phrase not in joined_notes:
            failures.append("central run record provider playbook safety notes are incomplete")
            break
    failures.extend(_provider_playbook_safety_note_preflight_failures(safety_notes))
    return failures


_PROVIDER_PLAYBOOK_STEP_KEYS = PROVIDER_PLAYBOOK_STEP_KEYS


def _provider_playbook_actor_preflight_failures(
    label: str,
    *,
    route: str,
    actor: str,
    human_action_required: object,
) -> list[str]:
    if not route:
        return []
    expected: tuple[str, bool] | None = None
    if route in {"api", "official_cli"}:
        expected = ("FuseKit", False)
    elif route in {"browser_guided", "human_follow_me", "local_vault"}:
        expected = ("You", True)
    if expected is None:
        return []
    expected_actor, expected_human_action = expected
    failures: list[str] = []
    if actor != expected_actor:
        failures.append(f"{label}.actor must be {expected_actor} for {route} routes")
    if human_action_required is not expected_human_action:
        expected_value = str(expected_human_action).lower()
        failures.append(
            f"{label}.human_action_required must be {expected_value} for {route} routes"
        )
    return failures


def _provider_playbook_control_preflight_failures(
    label: str,
    *,
    step_id: str,
    route: str,
    control: str,
) -> list[str]:
    if not route or not control:
        return []
    failures: list[str] = []
    if route == "api" and control != "FuseKit API worker":
        failures.append(f"{label}.control must be FuseKit API worker for api routes")
    if route in {"browser_guided", "local_vault"} and not (
        control.startswith("Capture ") and control.endswith(" from VM clipboard")
    ):
        failures.append(f"{label}.control must be an env-named Capture control")
    if route == "human_follow_me" and control not in {
        "I finished this step",
        "Approve DNS apply",
        "Approve setup plan",
    }:
        failures.append(f"{label}.control must be a known follow-me control")
    if (
        step_id.startswith("resend.")
        and route == "browser_guided"
        and control != "Capture RESEND_API_KEY from VM clipboard"
    ):
        failures.append(
            f"{label}.control must capture RESEND_API_KEY before Resend API setup"
        )
    return failures


def _provider_playbook_proof_preflight_failures(
    label: str,
    *,
    route: str,
    proof_source: str,
    resume_event: str,
) -> list[str]:
    if not route:
        return []
    failures: list[str] = []
    if not proof_source or not resume_event:
        return failures
    if route in {"api", "official_cli"}:
        if proof_source != "setup_receipt.json":
            failures.append(
                f"{label}.proof_source must be setup_receipt.json for deterministic routes"
            )
        if resume_event != "provider_action_recorded":
            failures.append(
                f"{label}.resume_event must be provider_action_recorded for deterministic routes"
            )
    elif route in {"browser_guided", "local_vault"}:
        if proof_source != "gate_events.jsonl":
            failures.append(f"{label}.proof_source must be gate_events.jsonl for capture routes")
        if resume_event != "clipboard_captured -> resume_requested":
            failures.append(
                f"{label}.resume_event must be clipboard_captured -> resume_requested "
                "for capture routes"
            )
    elif route == "human_follow_me":
        if proof_source != "gate_events.jsonl":
            failures.append(
                f"{label}.proof_source must be gate_events.jsonl for follow-me routes"
            )
        if resume_event not in {
            "resume_requested",
            "dns_apply_approved -> resume_requested",
            "setup_plan_approved -> resume_requested",
        }:
            failures.append(f"{label}.resume_event must be a known follow-me wake event")
    return failures


def _provider_playbook_order_preflight_failures(step_ids: list[str]) -> list[str]:
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
    failures = [
        f"central run record provider playbook steps has duplicate id {step_id}"
        for step_id in duplicates
    ]
    for before, after in required_pairs:
        before_position = positions.get(before)
        after_position = positions.get(after)
        if before_position is None or after_position is None:
            continue
        if before_position > after_position:
            failures.append(
                "central run record provider playbook steps must place "
                f"{before} before {after}"
            )
    return failures


def _provider_playbook_safety_note_preflight_failures(safety_notes: list[Any]) -> list[str]:
    failures: list[str] = []
    seen: set[str] = set()
    for index, note in enumerate(safety_notes):
        label = f"central run record provider playbook safety_notes[{index}]"
        if not isinstance(note, str):
            failures.append(f"{label} must be text")
        text = str(note or "")
        stripped = text.strip()
        if not stripped:
            failures.append(f"{label} must not be empty")
            continue
        if text != stripped:
            failures.append(f"{label} must not have surrounding whitespace")
        if stripped in seen:
            failures.append(f"{label} duplicates generated safety guidance")
        seen.add(stripped)
        lowered = stripped.lower()
        if "capture <target>" in lowered or "capture <env>" in lowered:
            failures.append(f"{label} uses placeholder Capture guidance")
        local_browser_failure = _local_browser_guidance_failure(lowered)
        if local_browser_failure:
            failures.append(f"{label} contains non-launcher wording: {local_browser_failure}")
        manual_action_failure = _manual_action_guidance_failure(lowered)
        if manual_action_failure:
            failures.append(f"{label} contains non-launcher wording: {manual_action_failure}")
    return failures


def _provider_playbook_instruction_is_unsafe(instruction: str) -> bool:
    text = instruction.lower()
    unsafe_patterns = (
        "paste provider secrets into the host",
        "create resend domains manually",
        "create resend audiences manually",
        "click add domain in resend",
        "click add audience in resend",
    )
    return any(pattern in text for pattern in unsafe_patterns)


def _local_browser_guidance_failure(text: str) -> str:
    for pattern in _LOCAL_BROWSER_GUIDANCE_PATTERNS:
        for match in re.finditer(pattern, text):
            if not _local_browser_match_is_negated(text, match.start()):
                return "local browser/host browser"
    return ""


def _manual_action_guidance_failure(text: str) -> str:
    for pattern in _MANUAL_ACTION_GUIDANCE_PATTERNS:
        for match in re.finditer(pattern, text):
            if not _manual_action_match_is_negated(text, match.start()):
                return "manual action"
    return ""


def _manual_action_match_is_negated(text: str, match_start: int) -> bool:
    prefix = text[max(0, match_start - 64) : match_start]
    clause = re.split(r"[.;:!?]\s*", prefix)[-1]
    if re.search(r"\b(?:do not|don't|never)\b", clause):
        return True
    return (
        re.search(
            r"\b(?:do not|don't|never|no|nothing to)\s+"
            r"(?:(?:do|perform|complete|use|create|copy|paste|enter|apply|add)\s+)?$",
            clause,
        )
        is not None
    )


def _local_browser_match_is_negated(text: str, match_start: int) -> bool:
    prefix = text[max(0, match_start - 64) : match_start]
    clause = re.split(r"[.;:!?]\s*", prefix)[-1]
    return (
        re.search(
            r"\b(?:do not|don't|never)\s+"
            r"(?:(?:use|open|launch|copy|paste|complete|finish)\s+)?"
            r"(?:(?:a|the|your)\s+)?$",
            clause,
        )
        is not None
    )


def _provider_strategy_summary_preflight_failures(
    strategies: dict[str, Any],
    provider_playbook: Any,
) -> list[str]:
    failures: list[str] = []
    if str(strategies.get("schema_version", "") or "").strip() != (
        PROVIDER_STRATEGIES_SCHEMA_VERSION
    ):
        failures.append("central run record provider_strategies schema is unsupported")
    providers = strategies.get("providers", [])
    if not isinstance(providers, list) or not providers:
        failures.append("central run record provider_strategies providers are missing")
        return failures
    route_providers: set[str] = set()
    for provider_index, provider_record in enumerate(providers):
        label = f"central run record provider_strategies providers[{provider_index}]"
        if not isinstance(provider_record, dict):
            failures.append(f"{label} is not an object")
            continue
        provider = str(provider_record.get("provider", "") or "").strip().lower()
        if not provider:
            failures.append(f"{label}.provider is missing")
        else:
            route_providers.add(provider)
        strategy_records = provider_record.get("strategies", [])
        if not isinstance(strategy_records, list) or not strategy_records:
            failures.append(f"{label}.strategies is missing")
            continue
        for strategy_index, strategy in enumerate(strategy_records):
            strategy_label = f"{label}.strategies[{strategy_index}]"
            if not isinstance(strategy, dict):
                failures.append(f"{strategy_label} is not an object")
                continue
            for key in ("recipe", "strategy", "status"):
                if not str(strategy.get(key, "") or "").strip():
                    failures.append(f"{strategy_label}.{key} is missing")
            decision = strategy.get("decision", {})
            if not isinstance(decision, dict):
                failures.append(f"{strategy_label}.decision is missing")
                continue
            selected = decision.get("selected", {})
            if not isinstance(selected, dict):
                failures.append(f"{strategy_label}.decision.selected is missing")
                selected = {}
            for key in ("kind", "status"):
                if not str(selected.get(key, "") or "").strip():
                    failures.append(f"{strategy_label}.decision.selected.{key} is missing")
            for key in ("deterministic", "implemented"):
                if selected.get(key) not in {True, False}:
                    failures.append(f"{strategy_label}.decision.selected.{key} must be boolean")
            if not str(selected.get("reason", "") or "").strip():
                failures.append(f"{strategy_label}.decision.selected.reason is missing")
            candidates = decision.get("candidates", [])
            if not isinstance(candidates, list) or not candidates:
                failures.append(f"{strategy_label}.decision.candidates is missing")
            else:
                failures.extend(
                    _provider_strategy_candidate_preflight_failures(
                        candidates,
                        f"{strategy_label}.decision.candidates",
                    )
                )
            if str(strategy.get("status", "") or "").strip() == "needs_human_gate":
                follow_steps = strategy.get("follow_steps", [])
                if not _has_non_empty_string_list(follow_steps):
                    failures.append(f"{strategy_label}.follow_steps is missing")
                for key in ("next_action", "resume_hint"):
                    if not str(strategy.get(key, "") or "").strip():
                        failures.append(f"{strategy_label}.{key} is missing")
                for key in ("success_criteria", "avoid_steps"):
                    if not _has_non_empty_string_list(strategy.get(key)):
                        failures.append(f"{strategy_label}.{key} is missing")
            failures.extend(
                _provider_specific_strategy_preflight_failures(
                    provider,
                    strategy,
                    selected,
                    strategy_label,
                )
            )
    required = _required_verifier_families(provider_playbook)
    missing = [
        label
        for label, accepted in required.items()
        if not accepted & route_providers
    ]
    if missing:
        failures.append(
            "central run record provider_strategies are missing public provider coverage: "
            + ", ".join(sorted(missing))
        )
    return failures


def _provider_strategy_candidate_preflight_failures(
    candidates: list[Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    for index, candidate in enumerate(candidates):
        candidate_label = f"{label}[{index}]"
        if not isinstance(candidate, dict):
            failures.append(f"{candidate_label} is not an object")
            continue
        for key in ("kind", "status"):
            if not str(candidate.get(key, "") or "").strip():
                failures.append(f"{candidate_label}.{key} is missing")
    return failures


def _provider_specific_strategy_preflight_failures(
    provider: str,
    strategy: dict[str, Any],
    selected: dict[str, Any],
    label: str,
) -> list[str]:
    if provider != "resend":
        return []
    if str(strategy.get("strategy", selected.get("kind", "")) or "").strip() != "api":
        return []
    if str(strategy.get("status", "") or "").strip() != "ok":
        return []
    recipe = str(strategy.get("recipe", "") or "").strip()
    evidence = selected.get("evidence", {})
    if not isinstance(evidence, dict):
        return [f"{label}.decision.selected.evidence is missing"]
    if recipe == "resend-domain":
        return _required_provider_strategy_evidence_preflight_failures(
            evidence,
            label,
            {
                "api_owns": "domain",
                "user_manual_domain_step": "false",
                "downstream_order": "before_dns_apply",
            },
        )
    if recipe == "resend-audience":
        return _required_provider_strategy_evidence_preflight_failures(
            evidence,
            label,
            {
                "api_owns": "audience",
                "user_manual_audience_step": "false",
                "conditional": "only_when_app_requires_audience",
            },
        )
    return []


def _required_provider_strategy_evidence_preflight_failures(
    evidence: dict[str, Any],
    label: str,
    required: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    for key, expected in required.items():
        if str(evidence.get(key, "") or "").strip() != expected:
            failures.append(
                f"{label}.decision.selected.evidence.{key} must be {expected}"
            )
    return failures


def _has_non_empty_string_list(value: Any) -> bool:
    return isinstance(value, list) and any(str(item).strip() for item in value)


def _is_verifier_coverage_check(check: dict[str, Any]) -> bool:
    status = str(check.get("status", "") or "").strip()
    return status == "passed" or (
        status == "pending_safe" and check.get("pending_safe") is True
    )


def _verifier_summary_preflight_failures(
    verifiers: dict[str, Any],
    provider_playbook: Any,
) -> list[str]:
    failures: list[str] = []
    if (
        str(verifiers.get("schema_version", "") or "").strip()
        != VERIFIER_SUMMARY_SCHEMA_VERSION
    ):
        failures.append("central run record verifier summary schema is unsupported")
    if verifiers.get("all_passed_or_pending_safe") is not True:
        failures.append("central run record verifier summary is not launch-safe")
    if str(verifiers.get("overall", "") or "").strip() != "passed":
        failures.append("central run record verifier summary overall must be passed")
    statement = str(verifiers.get("statement", "") or "").lower()
    if "live provider verifiers" not in statement or "green checks" not in statement:
        failures.append(
            "central run record verifier summary statement is missing live-verifier guidance"
        )
    checks = verifiers.get("checks", [])
    counts = verifiers.get("counts", {})
    if not isinstance(checks, list) or not checks:
        failures.append("central run record verifier summary checks are missing")
        checks = []
    if not isinstance(counts, dict):
        failures.append("central run record verifier summary counts are missing")
        counts = {}
    seen: set[tuple[str, str]] = set()
    actual_counts = {
        "passed": 0,
        "pending_safe": 0,
        "skipped": 0,
        "pending": 0,
        "repairing": 0,
        "failed": 0,
        "needs_human_gate": 0,
        "unknown": 0,
    }
    providers: set[str] = set()
    for index, check in enumerate(checks):
        label = f"central run record verifier summary checks[{index}]"
        if not isinstance(check, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(check) - _VERIFIER_SUMMARY_CHECK_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        provider = str(check.get("provider", "") or "").strip().lower()
        check_name = str(check.get("check", "") or "").strip().lower()
        status = str(check.get("status", "") or "").strip()
        for key in ("provider", "check", "status"):
            value = str(check.get(key, "") or "")
            if not value.strip():
                failures.append(f"{label}.{key} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        if not isinstance(check.get("pending_safe"), bool):
            failures.append(f"{label}.pending_safe must be boolean")
        if provider and _is_verifier_coverage_check(check):
            providers.add(provider)
        identity = (provider, check_name)
        if all(identity):
            if identity in seen:
                failures.append(f"{label} is duplicated")
            seen.add(identity)
        if status not in {"passed", "pending_safe", "skipped"}:
            failures.append(f"{label}.status must be passed, pending_safe, or skipped")
            actual_counts["unknown"] += 1
        else:
            actual_counts[status] += 1
        if status == "pending_safe" and check.get("pending_safe") is not True:
            failures.append(f"{label}.pending_safe must be true")
    for key in ("pending", "repairing", "failed", "needs_human_gate", "unknown"):
        if counts.get(key) != 0:
            failures.append(f"central run record verifier summary counts.{key} must be 0")
    for key, expected in actual_counts.items():
        if counts.get(key) != expected:
            failures.append(
                f"central run record verifier summary counts.{key} must match checks"
            )
    if actual_counts["skipped"] > 0 and (
        "skipped" not in statement or "do not count" not in statement
    ):
        failures.append(
            "central run record verifier summary statement must explain skipped "
            "verifier rows do not count as proof"
        )
    required = _required_verifier_families(provider_playbook)
    missing = [
        label
        for label, accepted in required.items()
        if not accepted & providers
    ]
    if missing:
        failures.append(
            "central run record verifier summary is missing public provider coverage: "
            + ", ".join(sorted(missing))
        )
    if not {"live_app"} & providers:
        failures.append("central run record verifier summary is missing live_app coverage")
    return failures


_VERIFIER_SUMMARY_CHECK_KEYS = VERIFIER_SUMMARY_CHECK_KEYS


def _embedded_verification_preflight_failures(verification: dict[str, Any]) -> list[str]:
    checks = verification.get("checks", [])
    if not isinstance(checks, list) or not checks:
        return ["central run record verification checks are missing"]
    return [
        f"central run record {failure}"
        for failure in _verification_failures(verification)
    ]


def _detonation_section_preflight_failures(detonation: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(detonation) - DETONATION_KEYS)
    if unexpected:
        failures.append(
            "central run record detonation has unexpected fields: "
            + ", ".join(unexpected)
        )
    if detonation.get("preflight_safe") is not True:
        failures.append("central run record detonation.preflight_safe must be true")
    if not isinstance(detonation.get("workspace_detonated"), bool):
        failures.append("central run record detonation.workspace_detonated must be boolean")
    return failures


def _required_verifier_families(provider_playbook: Any) -> dict[str, frozenset[str]]:
    if not isinstance(provider_playbook, dict):
        return {}
    steps = provider_playbook.get("steps", [])
    if not isinstance(steps, list):
        return {}
    providers = {
        str(step.get("provider", "") or "").strip().lower()
        for step in steps
        if isinstance(step, dict)
    }
    return {
        label: accepted
        for label, accepted in PUBLIC_PROVIDER_FAMILIES.items()
        if accepted & providers
    }


def _audit_trail_preflight_failures(
    audit_trail: dict[str, Any],
    run_record: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    if str(audit_trail.get("schema_version", "") or "").strip() != (
        AUDIT_TRAIL_SCHEMA_VERSION
    ):
        failures.append("central run record audit trail schema is unsupported")
    entries = audit_trail.get("entries", [])
    if not isinstance(entries, list) or not entries:
        failures.append("central run record audit trail entries are missing")
        entries = []
    counts = audit_trail.get("counts", {})
    if not isinstance(counts, dict):
        failures.append("central run record audit trail counts are missing")
        counts = {}
    if _safe_int(audit_trail.get("entry_count"), -1) != len(entries):
        failures.append("central run record audit trail entry_count must match entries")
    actual_counts: dict[str, int] = {}
    seen_identities: set[tuple[str, str, str, str, str, str, str, str, str]] = set()
    wake_ids_by_name = _wake_event_ids_by_name(run_record)
    for index, entry in enumerate(entries):
        label = f"central run record audit trail entries[{index}]"
        if not isinstance(entry, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(entry) - _AUDIT_TRAIL_ENTRY_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        identity = _audit_entry_identity(entry)
        if identity in seen_identities:
            failures.append(f"{label} is duplicated")
        seen_identities.add(identity)
        for key in ("category", "action", "status", "source", "summary"):
            value = str(entry.get(key, "") or "")
            if not value.strip():
                failures.append(f"{label}.{key} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        category = str(entry.get("category", "") or "").strip()
        if category not in {
            "credential_capture",
            "provider_action",
            "dns_write",
            "human_approval",
            "detonation",
        }:
            failures.append(f"{label}.category is unsupported")
        else:
            actual_counts[category] = actual_counts.get(category, 0) + 1
        for field in ("summary", "action", "provider", "target", "resource"):
            value = str(entry.get(field, "") or "")
            if field not in {"summary", "action"} and value and value != value.strip():
                failures.append(f"{label}.{field} must not have surrounding whitespace")
            if contains_durable_secret_text(value):
                failures.append(f"{label}.{field} contains credential-looking text")
        source = str(entry.get("source", "") or "").strip()
        if source == "audit.jsonl" and _safe_int(entry.get("audit_log_index"), 0) <= 0:
            failures.append(f"{label}.audit_log_index is missing")
        if (
            source == "setup_receipt.json"
            and _safe_int(entry.get("receipt_action_index"), 0) <= 0
        ):
            failures.append(f"{label}.receipt_action_index is missing")
        expected_wake = _audit_entry_expected_wake_event(entry)
        if expected_wake:
            wake_event_id = str(entry.get("wake_event_id", "") or "").strip()
            if not wake_event_id:
                failures.append(f"{label}.wake_event_id is missing")
            elif wake_event_id not in wake_ids_by_name.get(expected_wake, set()):
                failures.append(f"{label}.wake_event_id does not match wake_events")
    for category, expected in actual_counts.items():
        if _safe_int(counts.get(category), -1) != expected:
            failures.append(
                "central run record audit trail counts."
                f"{category} must match entries"
            )
    for category in _required_audit_categories(run_record):
        if actual_counts.get(category, 0) < 1:
            failures.append(f"central run record audit trail must include {category}")
    for category, sources in sorted(_required_audit_sources(run_record).items()):
        if not _audit_category_has_source(entries, category, sources):
            source_list = ", ".join(sorted(sources))
            failures.append(
                "central run record audit trail "
                f"{category} must include source {source_list}"
            )
    statement = str(audit_trail.get("statement", "") or "").lower()
    for required in ("credential captures", "dns writes", "human approvals", "without storing"):
        if required not in statement:
            failures.append("central run record audit trail statement is incomplete")
            break
    return failures


_AUDIT_TRAIL_ENTRY_KEYS = AUDIT_TRAIL_ENTRY_KEYS


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


def _wake_event_ids_by_name(run_record: dict[str, Any]) -> dict[str, set[str]]:
    wake_events = run_record.get("wake_events", {})
    events = wake_events.get("events", []) if isinstance(wake_events, dict) else []
    ids_by_name: dict[str, set[str]] = {}
    if not isinstance(events, list):
        return ids_by_name
    for event in events:
        if not isinstance(event, dict):
            continue
        event_name = str(event.get("event", "") or "").strip()
        event_id = str(event.get("id", "") or "").strip()
        if event_name and event_id:
            ids_by_name.setdefault(event_name, set()).add(event_id)
    return ids_by_name


def _audit_entry_expected_wake_event(entry: dict[str, Any]) -> str:
    category = str(entry.get("category", "") or "").strip()
    action = str(entry.get("action", "") or "").strip()
    if category == "credential_capture" or "capture" in action:
        return "clipboard_captured"
    if category in {"human_approval", "dns_write"} or "approve" in action:
        return "resume_requested"
    return ""


def _required_audit_categories(run_record: dict[str, Any]) -> set[str]:
    required: set[str] = set()
    wake_events = run_record.get("wake_events", {})
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
    approvals = run_record.get("approvals", [])
    if isinstance(approvals, list) and approvals:
        required.add("human_approval")
    vault = run_record.get("vault", {})
    records = vault.get("records", []) if isinstance(vault, dict) else []
    if isinstance(records, list) and records:
        required.add("credential_capture")
    detonation = run_record.get("detonation", {})
    if isinstance(detonation, dict) and detonation.get("workspace_detonated") is True:
        required.add("detonation")
    verification = run_record.get("verification", {})
    checks = verification.get("checks", []) if isinstance(verification, dict) else []
    if isinstance(checks, list) and checks:
        required.add("provider_action")
    return required


def _required_audit_sources(run_record: dict[str, Any]) -> dict[str, set[str]]:
    required: dict[str, set[str]] = {}
    wake_events = run_record.get("wake_events", {})
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
    approvals = run_record.get("approvals", [])
    if isinstance(approvals, list) and approvals:
        required.setdefault("human_approval", set()).add("gate_events.jsonl")
    verification = run_record.get("verification", {})
    checks = verification.get("checks", []) if isinstance(verification, dict) else []
    if isinstance(checks, list) and checks:
        required.setdefault("provider_action", set()).add("setup_receipt.json")
    return required


def _audit_category_has_source(
    entries: list[Any],
    category: str,
    sources: set[str],
) -> bool:
    found = {
        str(entry.get("source", "") or "").strip()
        for entry in entries
        if isinstance(entry, dict)
        and str(entry.get("category", "") or "").strip() == category
    }
    return sources.issubset(found)


def _human_action_trace_preflight_failures(
    human_actions: dict[str, Any],
    provider_gates: Any,
    *,
    human_actions_required: bool = False,
) -> list[str]:
    failures: list[str] = []
    if str(human_actions.get("schema_version", "") or "").strip() != (
        HUMAN_ACTION_TRACE_SCHEMA_VERSION
    ):
        failures.append("central run record human action trace schema is unsupported")
    actions = human_actions.get("actions", [])
    counts = human_actions.get("counts", {})
    unguided = human_actions.get("unguided", [])
    if not isinstance(actions, list):
        failures.append("central run record human action trace actions are missing")
        actions = []
    if not isinstance(counts, dict):
        failures.append("central run record human action trace counts are missing")
        counts = {}
    if not isinstance(unguided, list):
        failures.append("central run record human action trace unguided actions are missing")
        unguided = []
    gate_targets = _public_provider_gate_targets(provider_gates)
    if actions and not gate_targets:
        failures.append("central run record human action trace provider gates are missing")
    if gate_targets and not actions:
        failures.append("central run record human action trace actions are missing")
    if human_actions_required and not actions:
        failures.append(
            "central run record human action trace actions are required when "
            "provider gates or wake events exist"
        )
    if _safe_int(human_actions.get("total"), -1) != len(actions):
        failures.append("central run record human action trace total must match actions")

    seen: set[tuple[str, str, str, str]] = set()
    actual_counts = {name: 0 for name in sorted(HUMAN_ACTION_COUNT_KEYS)}
    for index, action in enumerate(actions):
        label = f"central run record human action trace actions[{index}]"
        if not isinstance(action, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(action) - _HUMAN_ACTION_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        for key in (
            "gate_id",
            "provider",
            "classification",
            "action",
            "visible_control",
            "target",
            "guidance_gap",
        ):
            value = str(action.get(key, "") or "")
            if value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        identity = _human_action_identity(action)
        if identity in seen:
            failures.append(f"{label} is duplicated")
        seen.add(identity)
        gate_id = str(action.get("gate_id", "") or "").strip()
        action_name = str(action.get("action", "") or "").strip()
        visible_control = str(action.get("visible_control", "") or "").strip()
        target = str(action.get("target", "") or "").strip()
        if not gate_id:
            failures.append(f"{label}.gate_id is missing")
        elif gate_targets and gate_id not in gate_targets:
            failures.append(f"{label}.gate_id must match provider_gates.records")
        if action_name not in HUMAN_ACTION_COUNT_KEYS:
            failures.append(f"{label}.action is unsupported")
        else:
            actual_counts[action_name] += 1
        if not visible_control:
            failures.append(f"{label}.visible_control is missing")
        if action.get("guided") is not True:
            failures.append(f"{label}.guided must be true")
        if (
            action_name == OPEN_PROVIDER_GATE_ACTION
            and visible_control != OPEN_PROVIDER_GATE_CONTROL
        ):
            failures.append(f"{label}.visible_control must be Open provider gate in VM")
        if action_name == CAPTURE_VM_CLIPBOARD_ACTION:
            if not target or visible_control != capture_vm_clipboard_control(target):
                failures.append(f"{label}.visible_control must match the captured target")
            expected_targets = gate_targets.get(gate_id, set())
            action_targets = _env_targets_from_text(target)
            if expected_targets and (
                not action_targets or not action_targets.issubset(expected_targets)
            ):
                failures.append(f"{label}.target must match provider_gates.records target")
        if (
            action_name == CONFIRM_GATE_FINISHED_ACTION
            and visible_control not in FINISH_VISIBLE_CONTROLS
        ):
            failures.append(f"{label}.visible_control must be a known finish/approval control")
    for action_name, expected in actual_counts.items():
        if _safe_int(counts.get(action_name), -1) != expected:
            failures.append(
                "central run record human action trace counts."
                f"{action_name} must match actions"
            )
    if unguided:
        failures.append("central run record human action trace unguided actions must be empty")
    statement = str(human_actions.get("statement", "") or "").lower()
    if "visible control-room gate" not in statement or "no raw provider" not in statement:
        failures.append("central run record human action trace statement is incomplete")
    return failures


def _preflight_human_actions_required(payload: dict[str, Any]) -> bool:
    provider_gates = payload.get("provider_gates", {})
    if isinstance(provider_gates, dict) and _safe_int(
        provider_gates.get("total"),
        0,
    ) > 0:
        return True
    wake_events = payload.get("wake_events", {})
    if isinstance(wake_events, dict) and _safe_int(wake_events.get("total"), 0) > 0:
        return True
    automation_boundary = payload.get("automation_boundary", {})
    counts = (
        automation_boundary.get("counts", {})
        if isinstance(automation_boundary, dict)
        else {}
    )
    return isinstance(counts, dict) and _safe_int(counts.get("human_gate"), 0) > 0


def _rehearsal_review_preflight_failures(
    review: dict[str, Any],
    human_actions: Any,
    *,
    human_actions_required: bool = False,
) -> list[str]:
    failures: list[str] = []
    if str(review.get("schema_version", "") or "").strip() != REHEARSAL_REVIEW_SCHEMA_VERSION:
        failures.append("central run record rehearsal review schema is unsupported")
    if str(review.get("status", "") or "").strip() != "ready":
        failures.append("central run record rehearsal review status must be ready")
    actions = human_actions.get("actions", []) if isinstance(human_actions, dict) else []
    unguided = human_actions.get("unguided", []) if isinstance(human_actions, dict) else []
    if not isinstance(actions, list):
        actions = []
    if not isinstance(unguided, list):
        unguided = []
    reviewed_actions = review.get("reviewed_actions", [])
    if not isinstance(reviewed_actions, list):
        failures.append("central run record rehearsal review reviewed actions are missing")
        reviewed_actions = []
    if human_actions_required and not actions:
        failures.append(
            "central run record rehearsal review reviewed actions must include "
            "guided human actions when provider gates or wake events exist"
        )
    if _safe_int(review.get("action_count"), -1) != len(actions):
        failures.append(
            "central run record rehearsal review action count must match human actions"
        )
    if _safe_int(review.get("compared_action_count"), -1) != len(actions):
        failures.append(
            "central run record rehearsal review compared count must match human actions"
        )
    if _safe_int(review.get("matched_control_count"), -1) != len(actions):
        failures.append(
            "central run record rehearsal review matched count must match human actions"
        )
    if _safe_int(review.get("unguided_count"), -1) != len(unguided):
        failures.append(
            "central run record rehearsal review unguided count must match human actions"
        )
    if _safe_int(review.get("side_channel_count"), -1) != 0:
        failures.append("central run record rehearsal review side channel count must be 0")
    if review.get("requires_user_thinking") is not False:
        failures.append("central run record rehearsal review must require no user thinking")
    if len(reviewed_actions) != len(actions):
        failures.append(
            "central run record rehearsal review reviewed actions must match human actions"
        )
    for index, (action, reviewed) in enumerate(
        zip(actions, reviewed_actions, strict=False)
    ):
        label = f"central run record rehearsal review reviewed_actions[{index}]"
        if not isinstance(action, dict) or not isinstance(reviewed, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(reviewed) - _REHEARSAL_REVIEW_ACTION_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        for key in ("gate_id", "action", "visible_control", "target", "proof_source"):
            value = str(reviewed.get(key, "") or "")
            if value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        for key in ("gate_id", "action", "visible_control", "target"):
            if str(reviewed.get(key, "") or "") != str(action.get(key, "") or ""):
                failures.append(f"{label}.{key} must match human_actions.actions")
        if reviewed.get("matched") is not True:
            failures.append(f"{label}.matched must be true")
        if str(reviewed.get("proof_source", "") or "") != _rehearsal_proof_source(
            str(action.get("action", "") or "")
        ):
            failures.append(f"{label}.proof_source must match the action")
    statement = str(review.get("statement", "") or "").lower()
    if "control-room instructions" not in statement or "public recording" not in statement:
        failures.append("central run record rehearsal review statement is incomplete")
    return failures


def _artifact_list_preflight_failures(
    artifacts: list[Any],
    *,
    artifact_root: Path | None = None,
) -> list[str]:
    failures: list[str] = []
    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    for index, artifact in enumerate(artifacts):
        label = f"central run record artifacts[{index}]"
        if not isinstance(artifact, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected_artifact = sorted(set(artifact) - ARTIFACT_RECORD_KEYS)
        if unexpected_artifact:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected_artifact)}")
        name = str(artifact.get("name", "") or "")
        path = str(artifact.get("path", "") or "")
        if not name:
            failures.append(f"{label}.name is missing")
        elif name != name.strip():
            failures.append(f"{label}.name must not have surrounding whitespace")
        elif name in seen_names:
            failures.append(f"{label}.name is duplicated")
        else:
            seen_names.add(name)
        if not path:
            failures.append(f"{label}.path is missing")
        elif path != path.strip():
            failures.append(f"{label}.path must not have surrounding whitespace")
        elif path in seen_paths:
            failures.append(f"{label}.path is duplicated")
        else:
            seen_paths.add(path)
        if not isinstance(artifact.get("exists"), bool):
            failures.append(f"{label}.exists must be boolean")
        if path:
            path_failures = _public_relative_path_failures(path, f"{label}.path")
            failures.extend(path_failures)
            if (
                artifact_root is not None
                and not path_failures
                and artifact.get("exists") is True
                and not _evidence_path_exists(artifact_root, path)
            ):
                failures.append(f"{label}.path must exist in survivor artifacts")
        if _contains_credential_query_text(name):
            failures.append(f"{label}.name contains credential query text")
    return failures


def _evidence_inventory_preflight_failures(
    evidence: dict[str, Any],
    runner_profile: Any,
    *,
    evidence_root: Path | None = None,
) -> list[str]:
    failures: list[str] = []
    unexpected_evidence = sorted(set(evidence) - EVIDENCE_INVENTORY_KEYS)
    if unexpected_evidence:
        failures.append(
            "central run record evidence inventory has unexpected fields: "
            + ", ".join(unexpected_evidence)
        )
    schema_version = str(evidence.get("schema_version", "") or "")
    if schema_version != schema_version.strip():
        failures.append(
            "central run record evidence inventory schema_version "
            "must not have surrounding whitespace"
        )
    if schema_version != EVIDENCE_INVENTORY_SCHEMA_VERSION:
        failures.append("central run record evidence inventory schema is unsupported")
    counts = evidence.get("counts", {})
    if not isinstance(counts, dict):
        failures.append("central run record evidence inventory counts are missing")
        counts = {}
    unexpected_counts = sorted(set(counts) - EVIDENCE_COUNT_KEYS)
    if unexpected_counts:
        failures.append(
            "central run record evidence inventory counts has unexpected fields: "
            + ", ".join(unexpected_counts)
        )
    evidence_fields = {
        "logs": "log",
        "screenshots": "screenshot",
        "visual": "visual",
        "receipts": "receipt",
    }
    seen_paths: set[tuple[str, str]] = set()
    for field, expected_kind in evidence_fields.items():
        records = evidence.get(field, [])
        label = f"central run record evidence inventory {field}"
        if not isinstance(records, list):
            failures.append(f"{label} are missing")
            records = []
        count_value = counts.get(field)
        if not isinstance(count_value, int) or isinstance(count_value, bool):
            failures.append(f"{label} count must be an integer")
        elif count_value != len(records):
            failures.append(f"{label} count must match rows")
        for index, item in enumerate(records):
            item_label = f"{label}[{index}]"
            if not isinstance(item, dict):
                failures.append(f"{item_label} is not an object")
                continue
            unexpected_item = sorted(set(item) - EVIDENCE_RECORD_KEYS)
            if unexpected_item:
                failures.append(
                    f"{item_label} has unexpected fields: {', '.join(unexpected_item)}"
                )
            path = str(item.get("path", "") or "")
            kind = str(item.get("kind", "") or "")
            if not path:
                failures.append(f"{item_label}.path is missing")
            elif path != path.strip():
                failures.append(f"{item_label}.path must not have surrounding whitespace")
            else:
                identity = (field, path)
                if identity in seen_paths:
                    failures.append(f"{item_label}.path is duplicated")
                seen_paths.add(identity)
                path_failures = _public_relative_path_failures(path, f"{item_label}.path")
                failures.extend(path_failures)
                if (
                    evidence_root is not None
                    and not path_failures
                    and item.get("exists") is True
                    and not _evidence_path_exists(evidence_root, path)
                ):
                    failures.append(f"{item_label}.path must exist in survivor artifacts")
            if not kind:
                failures.append(f"{item_label}.kind is missing")
            elif kind != kind.strip():
                failures.append(f"{item_label}.kind must not have surrounding whitespace")
            elif kind != expected_kind:
                failures.append(f"{item_label}.kind must be {expected_kind}")
            source = str(item.get("source", "") or "")
            if not source.strip():
                failures.append(f"{item_label}.source is missing")
            elif source != source.strip():
                failures.append(f"{item_label}.source must not have surrounding whitespace")
            if item.get("exists") is not True:
                failures.append(f"{item_label}.exists must be true")
    if _safe_int(counts.get("logs"), 0) < 1:
        failures.append("central run record evidence inventory must include logs")
    if _safe_int(counts.get("visual"), 0) < 1:
        failures.append("central run record evidence inventory must include visual proof")
    if _safe_int(counts.get("receipts"), 0) < 1:
        failures.append("central run record evidence inventory must include receipts")
    if _evidence_screenshot_required(runner_profile) and _safe_int(
        counts.get("screenshots"), 0
    ) < 1:
        failures.append("central run record evidence inventory must include screenshots")
    statement = str(evidence.get("statement", "") or "")
    if statement != statement.strip():
        failures.append(
            "central run record evidence inventory statement "
            "must not have surrounding whitespace"
        )
    lowered_statement = statement.lower()
    if "path and type only" not in lowered_statement or "raw secrets" not in lowered_statement:
        failures.append("central run record evidence inventory statement is incomplete")
    return failures


def _evidence_path_exists(root: Path, path: str) -> bool:
    evidence_root = root.resolve()
    candidate = (evidence_root / path).resolve()
    try:
        candidate.relative_to(evidence_root)
    except ValueError:
        return False
    return candidate.is_file()


def _public_relative_path_failures(path: str, label: str) -> list[str]:
    failures: list[str] = []
    artifact_path = Path(path)
    if artifact_path.is_absolute() or ".." in artifact_path.parts:
        failures.append(f"{label} must be public-relative")
    if _contains_credential_query_text(path):
        failures.append(f"{label} contains credential query text")
    return failures


def _contains_credential_query_text(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in ("token=", "password=", "secret="))


def _evidence_screenshot_required(runner_profile: Any) -> bool:
    if not isinstance(runner_profile, dict):
        return False
    profile = runner_profile.get("profile_contract", {})
    if not isinstance(profile, dict):
        return False
    browser_stack = profile.get("browser_stack", {})
    return (
        str(profile.get("name", "") or "") == EXPECTED_RUNNER_PROFILE
        or isinstance(browser_stack, dict)
        and bool(str(browser_stack.get("shared_provider_profile", "") or "").strip())
    )


def _public_provider_gate_targets(provider_gates: Any) -> dict[str, set[str]]:
    if not isinstance(provider_gates, dict):
        return {}
    records = provider_gates.get("records", [])
    if not isinstance(records, list):
        return {}
    targets_by_id: dict[str, set[str]] = {}
    for gate in records:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "") or "").strip()
        if not gate_id:
            continue
        targets = _env_targets_from_text(str(gate.get("target", "") or ""))
        captured_targets = gate.get("captured_targets", [])
        if isinstance(captured_targets, list):
            for target in captured_targets:
                targets.update(_env_targets_from_text(str(target or "")))
        targets_by_id[gate_id] = targets
    return targets_by_id


def _human_action_identity(action: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(action.get("gate_id", "") or "").strip().lower(),
        str(action.get("action", "") or "").strip().lower(),
        str(action.get("visible_control", "") or "").strip(),
        str(action.get("target", "") or "").strip(),
    )


def _env_targets_from_text(text: str) -> set[str]:
    return set(re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", text))


def _safe_int(value: Any, default: int) -> int:
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


_RECORDING_CONTRACT_SECTION_KEYS = {
    key: sections
    for key, sections in RECORDING_CONTRACT_SECTION_KEYS.items()
    if key != "detonation"
}
_RECORDING_CONTRACT_KEYS = RECORDING_CONTRACT_FIELD_KEYS
_RECORDING_CONTRACT_CHECK_KEYS = frozenset(RECORDING_CONTRACT_CHECK_KEYS)


def _recording_contract_preflight_failures(
    contract: dict[str, Any],
    run_record: dict[str, Any],
) -> list[str]:
    """Validate recording proof before detonation without requiring detonation itself."""

    failures: list[str] = []
    unexpected = sorted(set(contract) - _RECORDING_CONTRACT_KEYS)
    if unexpected:
        failures.append(
            "central run record recording contract has unexpected fields: "
            + ", ".join(unexpected)
        )
    if str(contract.get("schema_version", "") or "").strip() != RECORDING_CONTRACT_SCHEMA_VERSION:
        failures.append("central run record recording contract schema is unsupported")
    checks = contract.get("checks", {})
    if not isinstance(checks, dict):
        failures.append("central run record recording contract checks are missing")
        checks = {}
    else:
        unexpected_checks = sorted(set(checks) - _RECORDING_CONTRACT_CHECK_KEYS)
        if unexpected_checks:
            failures.append(
                "central run record recording contract checks has unexpected fields: "
                + ", ".join(unexpected_checks)
            )
        missing = sorted(_RECORDING_CONTRACT_CHECK_KEYS - set(checks))
        if missing:
            failures.append(
                "central run record recording contract checks missing "
                + ", ".join(missing)
            )
        for key in sorted(_RECORDING_CONTRACT_CHECK_KEYS - {"detonation"}):
            if key in checks and checks.get(key) is not True:
                failures.append(
                    f"central run record recording contract checks.{key} must be true"
                )
            elif checks.get(key) is True:
                for section in _RECORDING_CONTRACT_SECTION_KEYS.get(key, ()):
                    if not _run_record_section_present(run_record.get(section)):
                        failures.append(
                            "central run record recording contract checks."
                            f"{key} has no {section} proof"
                        )
        if "detonation" in checks and checks.get("detonation") not in {True, False}:
            failures.append(
                "central run record recording contract checks.detonation must be boolean"
            )
        if checks.get("errors_empty") is True and run_record.get("errors"):
            failures.append(
                "central run record recording contract checks.errors_empty must match errors"
            )
    blockers = contract.get("blockers", [])
    if not isinstance(blockers, list):
        failures.append("central run record recording contract blockers are missing")
        blockers = []
    blocker_values: set[str] = set()
    seen_blockers: set[str] = set()
    for index, blocker in enumerate(blockers):
        label = f"central run record recording contract blockers[{index}]"
        if not isinstance(blocker, str):
            failures.append(f"{label} must be a string")
            continue
        if not blocker:
            failures.append(f"{label} must be non-empty")
            continue
        if blocker != blocker.strip():
            failures.append(f"{label} must not have surrounding whitespace")
        normalized = blocker.strip()
        if normalized in seen_blockers:
            failures.append(f"{label} duplicates recording contract blocker {normalized}")
        seen_blockers.add(normalized)
        blocker_values.add(normalized)
    detonation_ready = checks.get("detonation") is True
    if detonation_ready:
        if contract.get("recording_ready") is not True:
            failures.append("central run record recording contract ready flag drifted")
        if blocker_values:
            failures.append("central run record recording contract blockers must be empty")
    else:
        if contract.get("recording_ready") is not False:
            failures.append(
                "central run record recording contract must stay unready before detonation"
            )
        unexpected = sorted(blocker_values - {"detonation"})
        if unexpected:
            failures.append(
                "central run record recording contract has non-detonation blockers: "
                + ", ".join(unexpected)
            )
        if blocker_values != {"detonation"}:
            failures.append(
                "central run record recording contract must name detonation as "
                "the only preflight blocker"
            )
    statement = str(contract.get("statement", "") or "").lower()
    for required in ("public demo", "detonation", "provider playbooks"):
        if required not in statement:
            failures.append(
                "central run record recording contract statement is missing "
                + required
                + " guidance"
            )
            break
    return failures


def _run_record_section_present(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, list):
        return bool(value)
    return False


def _control_room_security_failures(surface: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_surface = sorted(set(surface) - CONTROL_ROOM_SECURITY_KEYS)
    if unexpected_surface:
        failures.append(
            "central run record control-room security has unexpected fields: "
            + ", ".join(unexpected_surface)
        )
    if str(surface.get("schema_version", "") or "") != CONTROL_ROOM_SECURITY_SCHEMA_VERSION:
        failures.append("central run record control-room security schema is unsupported")
    routes = surface.get("routes", [])
    state_routes = surface.get("state_changing_routes", [])
    if not isinstance(routes, list):
        routes = []
    if not isinstance(state_routes, list):
        state_routes = []
    expected = CONTROL_ROOM_PROTECTED_MUTATION_ROUTES
    route_values = {
        str(route.get("route", "") or "")
        for route in routes
        if isinstance(route, dict)
    }
    state_route_values = {str(route) for route in state_routes}
    state_route_count = sum(
        1 for route in routes if isinstance(route, dict) and route.get("state_change") is True
    )
    route_list = [
        str(route.get("route", "") or "")
        for route in routes
        if isinstance(route, dict)
    ]
    for index, route in enumerate(routes):
        label = f"central run record control-room security routes[{index}]"
        if not isinstance(route, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected_route = sorted(set(route) - CONTROL_ROOM_SECURITY_ROUTE_KEYS)
        if unexpected_route:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected_route)}")
        route_value = str(route.get("route", "") or "")
        if route_value != route_value.strip():
            failures.append(f"{label}.route must not have surrounding whitespace")
        methods = route.get("methods", [])
        if isinstance(methods, list):
            for method_index, method in enumerate(methods):
                method_value = str(method or "")
                if method_value != method_value.strip():
                    failures.append(
                        f"{label}.methods[{method_index}] must not have surrounding whitespace"
                    )
        protection = str(route.get("protection", "") or "")
        if protection != protection.strip():
            failures.append(f"{label}.protection must not have surrounding whitespace")
    for index, route in enumerate(state_routes):
        route_value = str(route or "")
        if route_value != route_value.strip():
            failures.append(
                "central run record control-room security "
                f"state_changing_routes[{index}] must not have surrounding whitespace"
            )
    if _duplicate_text_values(route_list) or _duplicate_text_values(state_routes):
        failures.append("central run record control-room mutation routes are duplicated")
    if not expected.issubset(route_values) or not expected.issubset(state_route_values):
        failures.append("central run record is missing protected control-room mutation routes")
    if _safe_int(surface.get("route_count"), -1) != len(routes):
        failures.append("central run record control-room route counts drifted")
    state_changing_route_count = _safe_int(surface.get("state_changing_route_count"), -1)
    if state_changing_route_count != state_route_count or state_changing_route_count != len(
        state_route_values
    ):
        failures.append("central run record control-room route counts drifted")
    protection = str(surface.get("required_post_protection", "") or "")
    statement = str(surface.get("statement", "") or "").lower()
    if not all(term in protection for term in CONTROL_ROOM_REQUIRED_POST_PROTECTION_TERMS):
        failures.append("central run record control-room POST protection is incomplete")
    if not all(term in statement for term in CONTROL_ROOM_SECURITY_STATEMENT_TERMS):
        failures.append("central run record control-room no-CORS/action-token proof is incomplete")
    return failures


def _automation_boundary_preflight_failures(boundary: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_boundary = sorted(set(boundary) - AUTOMATION_BOUNDARY_KEYS)
    if unexpected_boundary:
        failures.append(
            "central run record automation-boundary has unexpected fields: "
            + ", ".join(unexpected_boundary)
        )
    for key in ("schema_version", "status", "detonation_scope", "statement"):
        value = str(boundary.get(key, "") or "")
        if value != value.strip():
            failures.append(
                f"central run record automation-boundary {key} "
                "must not have surrounding whitespace"
            )
    if str(boundary.get("schema_version", "") or "") != AUTOMATION_BOUNDARY_SCHEMA_VERSION:
        failures.append("central run record automation-boundary schema is unsupported")
    if str(boundary.get("status", "") or "") != AUTOMATION_BOUNDARY_READY_STATUS:
        failures.append("central run record automation-boundary status must be ready")
    if boundary.get("resume_after_worker_replace") is not True:
        failures.append(
            "central run record automation-boundary resume_after_worker_replace must be true"
        )
    if boundary.get("no_user_machine_state") is not True:
        failures.append(
            "central run record automation-boundary no_user_machine_state must be true"
        )
    if (
        str(boundary.get("detonation_scope", "") or "")
        != AUTOMATION_BOUNDARY_DETONATION_SCOPE
    ):
        failures.append("central run record automation-boundary detonation scope is unsupported")

    allowed = boundary.get("vnc_allowed_for", [])
    allowed_values: set[str] = set()
    if not isinstance(allowed, list):
        failures.append("central run record automation-boundary vnc_allowed_for is missing")
    else:
        allowed_values = {str(item).strip() for item in allowed if str(item).strip()}
        for index, item in enumerate(allowed):
            value = str(item or "")
            if not value.strip():
                failures.append(
                    f"central run record automation-boundary vnc_allowed_for[{index}] "
                    "is missing"
                )
            elif value != value.strip():
                failures.append(
                    f"central run record automation-boundary vnc_allowed_for[{index}] "
                    "must not have surrounding whitespace"
                )
        if _duplicate_text_values(allowed):
            failures.append("central run record automation-boundary vnc_allowed_for is duplicated")
    required_allowed = AUTOMATION_BOUNDARY_REQUIRED_VNC_ALLOWLIST
    if not required_allowed.issubset(allowed_values):
        failures.append("central run record automation-boundary vnc_allowed_for is incomplete")

    routes = boundary.get("routes", [])
    if not isinstance(routes, list):
        failures.append("central run record automation-boundary routes are missing")
        routes = []
    route_signatures: list[str] = []
    for index, route in enumerate(routes):
        label = f"central run record automation-boundary routes[{index}]"
        if not isinstance(route, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected_route = sorted(set(route) - AUTOMATION_BOUNDARY_ROUTE_KEYS)
        if unexpected_route:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected_route)}")
        for key in ("provider", "recipe", "route", "owner", "status"):
            value = str(route.get(key, "") or "")
            if not value.strip():
                failures.append(f"{label}.{key} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        owner = str(route.get("owner", "") or "")
        route_kind = str(route.get("route", "") or "")
        if owner not in AUTOMATION_BOUNDARY_ROUTE_OWNERS:
            failures.append(f"{label}.owner is unsupported")
        if owner == "fusekit":
            if route.get("deterministic") is not True:
                failures.append(f"{label}.deterministic must be true")
            if route.get("implemented") is not True:
                failures.append(f"{label}.implemented must be true")
            if route_kind not in AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS:
                failures.append(f"{label}.route must be an automation route")
        if (
            owner == "human_gate"
            and route_kind not in AUTOMATION_BOUNDARY_HUMAN_GATE_ROUTE_KINDS
        ):
            failures.append(f"{label}.route must be a human gate route")
        signature = _automation_boundary_route_signature(route)
        if signature != ":":
            route_signatures.append(signature)
    if _duplicate_text_values(route_signatures):
        failures.append("central run record automation-boundary routes are duplicated")

    counts = boundary.get("counts")
    if not isinstance(counts, dict):
        failures.append("central run record automation-boundary counts are missing")
        counts = {}
    unexpected_counts = sorted(set(counts) - AUTOMATION_BOUNDARY_COUNTS_KEYS)
    if unexpected_counts:
        failures.append(
            "central run record automation-boundary counts has unexpected fields: "
            + ", ".join(unexpected_counts)
        )
    for key in AUTOMATION_BOUNDARY_COUNTS_KEYS:
        count_value = counts.get(key)
        if not isinstance(count_value, int) or isinstance(count_value, bool):
            failures.append(
                f"central run record automation-boundary {key} count must be an integer"
            )
    blocked_count = counts.get("blocked")
    if blocked_count != 0 or isinstance(blocked_count, bool):
        failures.append("central run record automation-boundary blocked count must be 0")
    fusekit_owned_count = sum(
        1 for route in routes if isinstance(route, dict) and route.get("owner") == "fusekit"
    )
    human_gate_count = sum(
        1 for route in routes if isinstance(route, dict) and route.get("owner") == "human_gate"
    )
    if counts.get("fusekit_owned") != fusekit_owned_count:
        failures.append("central run record automation-boundary fusekit count must match routes")
    if counts.get("human_gate") != human_gate_count:
        failures.append("central run record automation-boundary human-gate count must match routes")

    post_gate = boundary.get("post_gate_automation")
    if not isinstance(post_gate, dict):
        failures.append("central run record automation-boundary post-gate automation is missing")
    else:
        unexpected_post_gate = sorted(set(post_gate) - AUTOMATION_BOUNDARY_POST_GATE_KEYS)
        if unexpected_post_gate:
            failures.append(
                "central run record automation-boundary post-gate automation "
                "has unexpected fields: "
                + ", ".join(unexpected_post_gate)
            )
        api_or_cli_routes = post_gate.get("api_or_cli_routes")
        human_gate_routes = post_gate.get("human_gate_routes")
        expected_api_or_cli = sorted(
            _automation_boundary_route_signature(route)
            for route in routes
            if isinstance(route, dict)
            and route.get("owner") == "fusekit"
            and str(route.get("route", "") or "").strip()
            in AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS
        )
        expected_human_gate = sorted(
            _automation_boundary_route_signature(route)
            for route in routes
            if isinstance(route, dict) and route.get("owner") == "human_gate"
        )
        if not isinstance(api_or_cli_routes, list):
            failures.append(
                "central run record automation-boundary api/cli route list is missing"
            )
        else:
            if sorted(str(item) for item in api_or_cli_routes) != expected_api_or_cli:
                failures.append(
                    "central run record automation-boundary api/cli routes must match routes"
                )
            for index, item in enumerate(api_or_cli_routes):
                value = str(item or "")
                if value != value.strip():
                    failures.append(
                        "central run record automation-boundary api/cli routes"
                        f"[{index}] must not have surrounding whitespace"
                    )
            if _duplicate_text_values(api_or_cli_routes):
                failures.append(
                    "central run record automation-boundary api/cli routes are duplicated"
                )
        if not isinstance(human_gate_routes, list):
            failures.append(
                "central run record automation-boundary human-gate route list is missing"
            )
        else:
            if sorted(str(item) for item in human_gate_routes) != expected_human_gate:
                failures.append(
                    "central run record automation-boundary human-gate routes must match routes"
                )
            for index, item in enumerate(human_gate_routes):
                value = str(item or "")
                if value != value.strip():
                    failures.append(
                        "central run record automation-boundary human-gate routes"
                        f"[{index}] must not have surrounding whitespace"
                    )
            if _duplicate_text_values(human_gate_routes):
                failures.append(
                    "central run record automation-boundary human-gate routes are duplicated"
                )

    statement = str(boundary.get("statement", "") or "").lower()
    if not all(term in statement for term in AUTOMATION_BOUNDARY_STATEMENT_TERMS):
        failures.append("central run record automation-boundary statement is incomplete")
    return failures


def _automation_boundary_route_signature(route: dict[str, Any]) -> str:
    provider = str(route.get("provider", "") or "").strip()
    recipe = str(route.get("recipe", "") or "").strip()
    return f"{provider}:{recipe}"


def _duplicate_text_values(values: list[Any]) -> bool:
    seen_values: set[str] = set()
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        if text in seen_values:
            return True
        seen_values.add(text)
    return False


def _volatile_durable_source_marker(source: dict[str, Any]) -> str:
    if str(source.get("id", "") or "") == "worker_replacement_drill":
        return ""
    text = " ".join(
        str(source.get(field, "") or "").lower()
        for field in ("id", "path", "role")
    )
    for marker in VOLATILE_WORKER_SURFACES:
        if marker.lower() in text:
            return marker
    return ""


def _walk_json_strings(value: Any, *, path: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        items: list[tuple[str, str]] = []
        for key, nested in value.items():
            key_label = str(key).replace(".", "_")
            items.extend(_walk_json_strings(nested, path=f"{path}.{key_label}"))
        return items
    if isinstance(value, list):
        items = []
        for index, nested in enumerate(value):
            items.extend(_walk_json_strings(nested, path=f"{path}[{index}]"))
        return items
    return []


def _read_json_artifact(path: Path, label: str) -> tuple[dict[str, Any], list[str]]:
    if not path.is_file():
        return {}, []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, [f"{label} artifact could not be read"]
    if not isinstance(raw, dict):
        return {}, [f"{label} artifact must be a JSON object"]
    return raw, []
