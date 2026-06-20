"""Acceptance harness for FuseKit launch readiness."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fusekit.detonation.preflight import (
    verification_report_failures,
)
from fusekit.errors import FuseKitError, ProviderError, VaultError
from fusekit.harness.ledger import HarnessLedger
from fusekit.llm.contract import (
    LLM_CONTRACT_KEYS,
    LLM_CONTRACT_LANE_KEYS,
    LLM_CONTRACT_SECURITY_KEYS,
    MODEL_INFERENCE_KEYS,
)
from fusekit.manifest import SetupManifest, load_manifest, write_manifest
from fusekit.planner import build_plan
from fusekit.providers.capability_pack import (
    load_provider_pack,
    pack_default_path,
    synthesize_provider_pack,
    validate_provider_pack,
    write_provider_pack,
)
from fusekit.providers.resend import RESEND_ALLOWED_REGIONS
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
from fusekit.runner.control_room.state import _sanitized_visual_state
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
    WORKSPACE_DETONATION_RECEIPT_LIST_FIELDS,
    WORKSPACE_DETONATION_RECEIPT_TEXT_FIELDS,
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
    PROVIDER_STRATEGY_DECISION_KEYS,
    PROVIDER_STRATEGY_PROVIDER_KEYS,
    PROVIDER_STRATEGY_RECORD_KEYS,
    PROVIDER_STRATEGY_ROUTE_KEYS,
)
from fusekit.runner.readiness import (
    EXPECTED_PROVIDER_BROWSER_PROFILE,
    EXPECTED_RUNNER_PROFILE,
)
from fusekit.runner.readiness import (
    runner_profile_contract_failures as _runner_profile_contract_failures,
)
from fusekit.runner.readiness import (
    runner_readiness_failures as _runner_readiness_failures,
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
    rehearsal_review_proof_source as _rehearsal_review_proof_source,
)
from fusekit.runner.remote import (
    REMOTE_WORKER_CLEANUP_SCHEMA_VERSION,
    REMOTE_WORKER_PATH_TARGETS,
    REMOTE_WORKER_PROCESS_PATTERNS,
)
from fusekit.runner.remote_survivors import (
    REMOTE_ALLOWED_SURVIVOR_FILE_SET,
    REMOTE_ALLOWED_SURVIVOR_FILES,
    REMOTE_CHECKPOINTS_CHECKPOINTS_FIELD,
    REMOTE_CHECKPOINTS_JOB_ID_FIELD,
    REMOTE_CHECKPOINTS_KEYS,
    REMOTE_CHECKPOINTS_STATUS_FIELD,
    REMOTE_CHECKPOINTS_UPDATED_AT_FIELD,
    REMOTE_JOB_APP_PATH_FIELD,
    REMOTE_JOB_ARTIFACTS_FIELD,
    REMOTE_JOB_CHECKPOINT_KEYS,
    REMOTE_JOB_CHECKPOINT_REQUIRED_FIELDS,
    REMOTE_JOB_CHECKPOINTS_FIELD,
    REMOTE_JOB_CREATED_AT_FIELD,
    REMOTE_JOB_ID_FIELD,
    REMOTE_JOB_RUNNER_FIELD,
    REMOTE_JOB_STATE_KEYS,
    REMOTE_JOB_STATUS_FIELD,
    REMOTE_JOB_STEP_KEYS,
    REMOTE_JOB_STEP_REQUIRED_FIELDS,
    REMOTE_JOB_STEPS_FIELD,
    REMOTE_JOB_UPDATED_AT_FIELD,
    REMOTE_PUBLIC_SURVIVOR_JSON_LABELS,
    REMOTE_REQUIRED_SURVIVOR_FILES,
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
    WORKER_REPLACEMENT_DRILL_SCHEMA_VERSION,
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
from fusekit.runner.worker_replacement import WORKER_REPLACEMENT_DRILL_KEYS
from fusekit.scanner import scan_repo
from fusekit.security import (
    contains_durable_secret_text,
    redact_public_path,
    redact_public_text,
    scan_for_secret_leaks,
)
from fusekit.vault.bundle import Vault

DETONATION_PLAINTEXT_PATHS = (
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

VOLATILE_DURABLE_STATE_MARKERS = tuple(
    sorted(
        {
            *DETONATION_PLAINTEXT_PATHS,
            ".log",
            "clipboard-history",
            "local-browser",
            "vm-scratch",
        },
        key=len,
        reverse=True,
    )
)

EXPECTED_DURABLE_STATE_SOURCE_PATHS = {
    source_id: path for source_id, path, _role, _secret in DURABLE_STATE_SOURCES
}
@dataclass(frozen=True)
class AcceptanceCheck:
    """One launch-readiness assertion."""

    id: str
    status: str
    detail: str
    artifact: str = ""

    def to_dict(self) -> dict[str, str]:
        """Serialize the check."""

        return {
            "id": self.id,
            "status": self.status,
            "detail": redact_public_text(self.detail),
            "artifact": redact_public_path(self.artifact),
        }


@dataclass(frozen=True)
class AcceptanceReport:
    """Public, redacted acceptance report."""

    mode: str
    app_path: str
    launch_ready: bool
    checks: tuple[AcceptanceCheck, ...]
    ledger_path: str
    report_path: str
    missing: tuple[str, ...] = ()
    blockers: tuple[dict[str, str], ...] = ()
    recording_proof_ready: bool = False
    recording_contract: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    @property
    def public_launch_ready(self) -> bool:
        """True only when live provider evidence proves public launch readiness."""

        return self.mode == "live" and self.launch_ready

    @property
    def recording_contract_ready(self) -> bool:
        """True only when the embedded recording contract is also green."""

        return _recording_contract_ready(self.recording_contract)

    @property
    def remote_artifacts_ready(self) -> bool:
        """True only when retrieved OCI survivor evidence is present."""

        return _remote_artifacts_ready(self.checks)

    @property
    def effective_recording_proof_ready(self) -> bool:
        """True only when the proof flag, contract, and survivor bundle agree."""

        return (
            self.recording_proof_ready
            and self.recording_contract_ready
            and self.remote_artifacts_ready
        )

    @property
    def recording_ready(self) -> bool:
        """True only when live evidence proves the run is safe to demo-record."""

        return self.public_launch_ready and self.effective_recording_proof_ready

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report."""

        return {
            "mode": self.mode,
            "app_path": redact_public_path(self.app_path),
            "launch_ready": self.launch_ready,
            "public_launch_ready": self.public_launch_ready,
            "remote_artifacts_ready": self.remote_artifacts_ready,
            "recording_proof_ready": self.effective_recording_proof_ready,
            "recording_ready": self.recording_ready,
            "checks": [check.to_dict() for check in self.checks],
            "missing": list(self.missing),
            "blockers": [_redacted_blocker(blocker) for blocker in self.blockers],
            "recording_contract": _redacted_recording_contract(self.recording_contract),
            "ledger_path": redact_public_path(self.ledger_path),
            "report_path": redact_public_path(self.report_path),
            "created_at": self.created_at,
        }


def run_acceptance(
    app_path: Path,
    *,
    mode: str = "rehearsal",
    manifest_path: Path | None = None,
    vault_path: Path | None = None,
    passphrase: str | None = None,
    receipt_path: Path | None = None,
    audit_log_path: Path | None = None,
    remote_artifacts_path: Path | None = None,
    output_dir: Path | None = None,
) -> AcceptanceReport:
    """Run a redacted harness pass for launch readiness.

    Rehearsal mode proves local invariants. Live mode requires real provider evidence and
    intentionally refuses to mark the run ready until those artifacts exist.
    """

    if mode not in {"rehearsal", "live"}:
        raise FuseKitError("acceptance mode must be rehearsal or live.")
    app_path = app_path.resolve()
    if not app_path.exists():
        raise FuseKitError(f"App path does not exist: {app_path}")
    fusekit_dir = app_path / ".fusekit"
    output_dir = _app_relative(app_path, output_dir) or (fusekit_dir / "acceptance")
    remote_fusekit_dir = _resolve_remote_fusekit_dir(app_path, remote_artifacts_path)
    evidence_fusekit_dir = remote_fusekit_dir or fusekit_dir
    ledger = HarnessLedger.create(output_dir)
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger.record("acceptance.started", {"mode": mode, "app_path": redact_public_path(app_path)})
    if remote_fusekit_dir is not None:
        _record_remote_artifacts(remote_fusekit_dir, checks, ledger)
    recording_contract = _check_run_record(
        evidence_fusekit_dir / "run_record.json",
        evidence_fusekit_dir / "job.json",
        evidence_fusekit_dir / "checkpoints.json",
        evidence_fusekit_dir / "provider_strategies.json",
        evidence_fusekit_dir / "llm_contract.json",
        evidence_fusekit_dir / "verification_report.json",
        evidence_fusekit_dir / "workspace_detonation.json",
        evidence_fusekit_dir / "gate_events.jsonl",
        evidence_fusekit_dir / "runner_readiness.json",
        mode,
        checks,
        missing,
        ledger,
    )

    manifest_path = _app_relative(app_path, manifest_path) or (app_path / "fusekit.yaml")
    manifest = _load_or_scan_manifest(app_path, manifest_path, checks, ledger)
    plan = build_plan(manifest)
    plan_path = ledger.snapshot_json("setup-plan", plan.to_dict())
    checks.append(AcceptanceCheck("plan.generated", "ok", "Setup plan generated.", str(plan_path)))

    pack_paths = _ensure_acceptance_packs(app_path, manifest, checks, missing, ledger)
    pack_failures = [
        check for check in checks if check.id.startswith("provider_pack.") and check.status != "ok"
    ]
    if pack_paths and not pack_failures:
        checks.append(
            AcceptanceCheck(
                "provider_packs.validated",
                "ok",
                f"Validated {len(pack_paths)} provider capability pack(s).",
            )
        )
    elif mode == "live":
        missing.append("validated provider capability packs")
        checks.append(
            AcceptanceCheck(
                "provider_packs.validated",
                "failed" if pack_failures else "missing",
                "Provider capability packs did not all validate for public launch."
                if pack_failures
                else "Live launch needs at least one validated provider capability pack.",
            )
        )

    vault_path = _app_relative(app_path, vault_path) or (
        evidence_fusekit_dir / "fusekit.vault.json"
    )
    _check_vault(vault_path, passphrase, mode, checks, missing, ledger)

    audit_log_path = _app_relative(app_path, audit_log_path) or (
        evidence_fusekit_dir / "audit.jsonl"
    )
    receipt_path = _app_relative(app_path, receipt_path) or (
        evidence_fusekit_dir / "setup_receipt.json"
    )
    _check_receipt(receipt_path, manifest, mode, audit_log_path, checks, missing, ledger)

    _check_audit_log(audit_log_path, mode, checks, missing)
    _check_verification_report(
        evidence_fusekit_dir / "verification_report.json",
        manifest,
        mode,
        checks,
        missing,
        ledger,
    )
    _check_provider_strategies(
        evidence_fusekit_dir / "provider_strategies.json",
        manifest,
        mode,
        checks,
        missing,
        ledger,
    )
    _check_provider_strategy_checkpoints(
        evidence_fusekit_dir / "provider_strategies.json",
        evidence_fusekit_dir / "checkpoints.json",
        mode,
        checks,
        missing,
        ledger,
    )
    _check_gate_state(
        evidence_fusekit_dir / "gates.json",
        mode,
        checks,
        missing,
        ledger,
    )
    _check_gate_audit_events(
        evidence_fusekit_dir / "gates.json",
        audit_log_path,
        mode,
        checks,
        missing,
        ledger,
    )
    _check_rollback_metadata(
        evidence_fusekit_dir / "rollback_plan.json",
        manifest,
        mode,
        checks,
        missing,
        ledger,
    )
    _check_runner_readiness(
        evidence_fusekit_dir / "runner_readiness.json",
        mode,
        checks,
        missing,
        ledger,
    )
    _check_visual_state(evidence_fusekit_dir / "visual.json", mode, checks, missing, ledger)
    _check_detonation(evidence_fusekit_dir, mode, checks, missing)
    _check_leaks(app_path, checks, missing, ledger)

    launch_ready = all(check.status == "ok" for check in checks) and not missing
    if mode == "rehearsal":
        launch_ready = all(check.status in {"ok", "skipped"} for check in checks)
    recording_proof_ready = _recording_proof_ready(checks)
    report_path = output_dir / "report.json"
    report = AcceptanceReport(
        mode=mode,
        app_path=str(app_path),
        launch_ready=launch_ready,
        checks=tuple(checks),
        ledger_path=str(output_dir / "ledger.jsonl"),
        report_path=str(report_path),
        missing=tuple(missing),
        blockers=tuple(_acceptance_blockers(checks, missing)),
        recording_proof_ready=recording_proof_ready,
        recording_contract=recording_contract,
    )
    report_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")
    ledger_recording_contract = _redacted_recording_contract(recording_contract)
    ledger.record(
        "acceptance.finished",
        {
            "launch_ready": launch_ready,
            "public_launch_ready": report.public_launch_ready,
            "recording_proof_ready": report.effective_recording_proof_ready,
            "recording_ready": report.recording_ready,
            "recording_contract": {
                "recording_ready": ledger_recording_contract.get("recording_ready") is True,
                "check_count": ledger_recording_contract.get("check_count", 0),
                "blockers": ledger_recording_contract.get("blockers", []),
            },
            "missing": missing,
        },
    )
    return report


def _recording_proof_ready(checks: Iterable[AcceptanceCheck]) -> bool:
    """True when live acceptance includes the complete demo-recording contract."""

    return any(check.id == "run_record.complete" and check.status == "ok" for check in checks)


def _remote_artifacts_ready(checks: Iterable[AcceptanceCheck]) -> bool:
    """True when live acceptance used retrieved disposable-worker survivors."""

    return any(check.id == "remote_artifacts.loaded" and check.status == "ok" for check in checks)


def _redacted_recording_contract(contract: dict[str, Any]) -> dict[str, Any]:
    """Return only report-safe recording-contract fields."""

    if not isinstance(contract, dict):
        return {}
    raw_checks = contract.get("checks", {})
    checks = (
        {
            str(key): value is True
            for key, value in sorted(raw_checks.items())
            if isinstance(key, str)
        }
        if isinstance(raw_checks, dict)
        else {}
    )
    raw_blockers = contract.get("blockers", [])
    blockers = (
        [redact_public_text(str(item)) for item in raw_blockers]
        if isinstance(raw_blockers, list)
        else []
    )
    return {
        "schema_version": redact_public_text(str(contract.get("schema_version", "") or "")),
        "recording_ready": contract.get("recording_ready") is True,
        "checks": checks,
        "blockers": blockers,
        "check_count": len(checks),
        "statement": redact_public_text(str(contract.get("statement", "") or "")),
    }


def _recording_contract_ready(contract: dict[str, Any]) -> bool:
    if not isinstance(contract, dict):
        return False
    if contract.get("schema_version") != RECORDING_CONTRACT_SCHEMA_VERSION:
        return False
    if contract.get("recording_ready") is not True:
        return False
    checks = contract.get("checks", {})
    if not isinstance(checks, dict) or not checks:
        return False
    if set(checks) != _RECORDING_CONTRACT_CHECK_KEYS:
        return False
    if any(value is not True for value in checks.values()):
        return False
    blockers = contract.get("blockers", [])
    return isinstance(blockers, list) and not blockers


def _app_relative(app_path: Path, path: Path | None) -> Path | None:
    if path is None:
        return None
    if path.is_absolute():
        return path
    return app_path / path


def _resolve_remote_fusekit_dir(app_path: Path, path: Path | None) -> Path | None:
    requested_root = _app_relative(app_path, path)
    if requested_root is None:
        return None
    if requested_root.is_symlink():
        raise FuseKitError(
            "Remote artifact path must be a retrieved OCI artifact directory, "
            "not a symlink."
        )
    root = requested_root.resolve()
    requested_fusekit_dir = (
        requested_root if requested_root.name == ".fusekit" else requested_root / ".fusekit"
    )
    if requested_fusekit_dir.is_symlink():
        raise FuseKitError(
            "Remote artifact path must contain a real retrieved .fusekit directory, "
            "not a symlink."
        )
    if not root.exists():
        raise FuseKitError(f"Remote artifact path does not exist: {root}")
    fusekit_dir = root if root.name == ".fusekit" else root / ".fusekit"
    if not fusekit_dir.is_dir():
        raise FuseKitError(
            "Remote artifact path must be a retrieved OCI artifact directory "
            f"containing .fusekit: {root}"
        )
    if fusekit_dir.resolve() == (app_path / ".fusekit").resolve():
        raise FuseKitError(
            "Remote artifact path must point to a retrieved OCI artifact bundle, "
            "not the app's live .fusekit scratch directory."
        )
    return fusekit_dir


def _record_remote_artifacts(
    remote_fusekit_dir: Path,
    checks: list[AcceptanceCheck],
    ledger: HarnessLedger,
) -> None:
    inventory = {
        name: _remote_survivor_inventory_entry(remote_fusekit_dir / name)
        for name in REMOTE_ALLOWED_SURVIVOR_FILES
    }
    missing = [
        name
        for name, details in inventory.items()
        if name in REMOTE_REQUIRED_SURVIVOR_FILES
        and not details["exists"]
        and not details["linked"]
    ]
    linked_files = [name for name, details in inventory.items() if details["linked"]]
    non_files = [
        name
        for name, details in inventory.items()
        if details["exists"] and not details["present"] and not details["linked"]
    ]
    empty_files = [
        name
        for name, details in inventory.items()
        if details["present"] and details["empty"] and name != "gate_events.jsonl"
    ]
    unexpected_entries = _remote_unexpected_artifact_entries(remote_fusekit_dir)
    public_safety_failures = _remote_survivor_public_safety_failures(remote_fusekit_dir)
    snapshot = ledger.snapshot_json(
        "remote-artifact-inventory",
        {
            "fusekit_dir": redact_public_path(remote_fusekit_dir),
            "files": inventory,
            "unexpected": unexpected_entries,
        },
    )
    status = (
        "failed"
        if (
            missing
            or linked_files
            or non_files
            or empty_files
            or unexpected_entries
            or public_safety_failures
        )
        else "ok"
    )
    detail_parts: list[str] = []
    if missing:
        detail_parts.append("missing " + ", ".join(missing))
    if linked_files:
        detail_parts.append("linked survivors " + ", ".join(linked_files))
    if non_files:
        detail_parts.append("non-file survivors " + ", ".join(non_files))
    if empty_files:
        detail_parts.append("empty survivors " + ", ".join(empty_files))
    if unexpected_entries:
        detail_parts.append("unexpected survivors " + ", ".join(unexpected_entries))
    if public_safety_failures:
        detail_parts.append(
            "unsafe public survivor text: " + "; ".join(public_safety_failures[:20])
        )
    detail = (
        "Retrieved OCI artifact bundle is incomplete: " + ". ".join(detail_parts) + "."
        if detail_parts
        else "Using retrieved OCI artifacts as live acceptance evidence."
    )
    checks.append(
        AcceptanceCheck(
            "remote_artifacts.loaded",
            status,
            detail,
            str(snapshot),
        )
    )


def _remote_unexpected_artifact_entries(remote_fusekit_dir: Path) -> list[str]:
    """Return non-survivor entries that should not exist in retrieved proof bundles."""

    unexpected: list[str] = []
    try:
        children = list(remote_fusekit_dir.iterdir())
    except OSError:
        return []
    for child in children:
        if child.name in REMOTE_ALLOWED_SURVIVOR_FILE_SET:
            continue
        suffix = "/" if child.is_dir() and not child.is_symlink() else ""
        unexpected.append(child.name + suffix)
    return sorted(unexpected)


def _remote_survivor_inventory_entry(path: Path) -> dict[str, Any]:
    """Return file-proof inventory for a retrieved OCI survivor."""

    is_link = path.is_symlink()
    exists = path.exists() or is_link
    is_file = path.is_file() if exists and not is_link else False
    size = path.stat().st_size if is_file else 0
    return {
        "exists": exists,
        "present": is_file,
        "linked": is_link,
        "bytes": size,
        "empty": is_file and size == 0,
    }


def _remote_survivor_public_safety_failures(remote_fusekit_dir: Path) -> list[str]:
    """Reject unsafe public text in non-secret durable survivors read by inventory."""

    failures: list[str] = []
    sources_by_id = {
        source_id: filename for source_id, filename, _role, _secret in DURABLE_STATE_SOURCES
    }
    for source_id, label in REMOTE_PUBLIC_SURVIVOR_JSON_LABELS.items():
        filename = sources_by_id.get(source_id)
        if not filename:
            continue
        path = remote_fusekit_dir / filename
        if path.is_symlink():
            continue
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            failures.append(f"{filename} could not be read for public-safety scan")
            continue
        failures.extend(_standalone_artifact_public_safety_failures(raw, label))
        failures.extend(_remote_survivor_shape_failures(source_id, label, raw))
    return failures


def _remote_survivor_shape_failures(source_id: str, label: str, raw: Any) -> list[str]:
    if source_id == "job_state":
        if not isinstance(raw, dict):
            return [f"{label} must be a JSON object"]
        return _remote_job_state_shape_failures(raw, label)
    if source_id == "run_state":
        if not isinstance(raw, dict):
            return [f"{label} must be a JSON object"]
        return _remote_run_state_shape_failures(raw, label)
    if source_id == "checkpoints":
        return _remote_checkpoints_shape_failures(raw, label)
    if source_id == "worker_replacement_drill":
        if not isinstance(raw, dict):
            return [f"{label} must be a JSON object"]
        return _remote_worker_replacement_drill_shape_failures(raw, label)
    return []


def _remote_run_state_shape_failures(raw: dict[str, Any], label: str) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(raw) - REMOTE_RUN_STATE_KEYS)
    if unexpected:
        failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
    for name in RUN_STATE_FIELDS:
        value = raw.get(name)
        if not isinstance(value, bool):
            failures.append(f"{label}.{name} must be boolean")
    failures.extend(
        _plain_number_failures(
            raw.get(REMOTE_RUN_STATE_UPDATED_AT_FIELD),
            f"{label}.{REMOTE_RUN_STATE_UPDATED_AT_FIELD}",
        )
    )
    ready_to_detonate = raw.get(REMOTE_RUN_STATE_READY_TO_DETONATE_FIELD)
    if not isinstance(ready_to_detonate, bool):
        failures.append(f"{label}.{REMOTE_RUN_STATE_READY_TO_DETONATE_FIELD} must be boolean")
    notes = raw.get(REMOTE_RUN_STATE_NOTES_FIELD, [])
    if not isinstance(notes, list):
        failures.append(f"{label}.{REMOTE_RUN_STATE_NOTES_FIELD} must be a list")
    else:
        failures.extend(
            _trimmed_string_list_failures(
                notes,
                f"{label}.{REMOTE_RUN_STATE_NOTES_FIELD}",
            )
        )
    missing = raw.get(REMOTE_RUN_STATE_MISSING_FOR_DETONATION_FIELD, [])
    if not isinstance(missing, list):
        failures.append(
            f"{label}.{REMOTE_RUN_STATE_MISSING_FOR_DETONATION_FIELD} must be a list"
        )
    else:
        failures.extend(
            _trimmed_string_list_failures(
                missing,
                f"{label}.{REMOTE_RUN_STATE_MISSING_FOR_DETONATION_FIELD}",
            )
        )
        unknown_missing = sorted(
            {str(item).strip() for item in missing if isinstance(item, str)}
            - set(RUN_STATE_FIELDS)
        )
        if unknown_missing:
            failures.append(
                f"{label}.{REMOTE_RUN_STATE_MISSING_FOR_DETONATION_FIELD} "
                "has unknown fields: "
                + ", ".join(unknown_missing)
            )
    return failures


def _run_record_state_shape_failures(state: dict[str, Any]) -> list[str]:
    failures = _remote_run_state_shape_failures(state, "state")
    if state.get("detonation_safe") is not True:
        failures.append("state.detonation_safe must be true")
    if state.get("workspace_detonated") is not True:
        failures.append("state.workspace_detonated must be true")
    return failures


def _remote_job_state_shape_failures(raw: dict[str, Any], label: str) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(raw) - REMOTE_JOB_STATE_KEYS)
    if unexpected:
        failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
    for name in (
        REMOTE_JOB_ID_FIELD,
        REMOTE_JOB_APP_PATH_FIELD,
        REMOTE_JOB_RUNNER_FIELD,
        REMOTE_JOB_STATUS_FIELD,
    ):
        failures.extend(_trimmed_optional_string_failures(raw.get(name), f"{label}.{name}"))
    for name in (REMOTE_JOB_CREATED_AT_FIELD, REMOTE_JOB_UPDATED_AT_FIELD):
        failures.extend(_plain_number_failures(raw.get(name), f"{label}.{name}"))
    steps = raw.get(REMOTE_JOB_STEPS_FIELD, [])
    if not isinstance(steps, list):
        failures.append(f"{label}.{REMOTE_JOB_STEPS_FIELD} must be a list")
    else:
        failures.extend(
            _remote_job_rows_shape_failures(
                steps,
                f"{label}.{REMOTE_JOB_STEPS_FIELD}",
                REMOTE_JOB_STEP_KEYS,
                required=REMOTE_JOB_STEP_REQUIRED_FIELDS,
            )
        )
    checkpoints = raw.get(REMOTE_JOB_CHECKPOINTS_FIELD, [])
    if not isinstance(checkpoints, list):
        failures.append(f"{label}.{REMOTE_JOB_CHECKPOINTS_FIELD} must be a list")
    else:
        failures.extend(
            _remote_job_rows_shape_failures(
                checkpoints,
                f"{label}.{REMOTE_JOB_CHECKPOINTS_FIELD}",
                REMOTE_JOB_CHECKPOINT_KEYS,
                required=REMOTE_JOB_CHECKPOINT_REQUIRED_FIELDS,
            )
        )
    artifacts = raw.get(REMOTE_JOB_ARTIFACTS_FIELD, {})
    if not isinstance(artifacts, dict):
        failures.append(f"{label}.{REMOTE_JOB_ARTIFACTS_FIELD} must be a JSON object")
    else:
        for name, value in artifacts.items():
            failures.extend(_trimmed_optional_string_failures(str(name), f"{label}.artifacts key"))
            failures.extend(_trimmed_optional_string_failures(value, f"{label}.artifacts.{name}"))
    return failures


def _remote_checkpoints_shape_failures(raw: Any, label: str) -> list[str]:
    if not isinstance(raw, dict):
        return [f"{label} must be generated checkpoints object"]
    failures: list[str] = []
    unexpected = sorted(set(raw) - REMOTE_CHECKPOINTS_KEYS)
    if unexpected:
        failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
    for name in (REMOTE_CHECKPOINTS_JOB_ID_FIELD, REMOTE_CHECKPOINTS_STATUS_FIELD):
        failures.extend(_trimmed_optional_string_failures(raw.get(name), f"{label}.{name}"))
    failures.extend(
        _plain_number_failures(
            raw.get(REMOTE_CHECKPOINTS_UPDATED_AT_FIELD),
            f"{label}.{REMOTE_CHECKPOINTS_UPDATED_AT_FIELD}",
        )
    )
    checkpoints = raw.get(REMOTE_CHECKPOINTS_CHECKPOINTS_FIELD, [])
    if not isinstance(checkpoints, list):
        failures.append(f"{label}.{REMOTE_CHECKPOINTS_CHECKPOINTS_FIELD} must be a list")
    else:
        failures.extend(
            _remote_job_rows_shape_failures(
                checkpoints,
                f"{label}.{REMOTE_CHECKPOINTS_CHECKPOINTS_FIELD}",
                REMOTE_JOB_CHECKPOINT_KEYS,
                required=REMOTE_JOB_CHECKPOINT_REQUIRED_FIELDS,
            )
        )
    return failures


def _remote_worker_replacement_drill_shape_failures(
    raw: dict[str, Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(raw) - WORKER_REPLACEMENT_DRILL_KEYS)
    if unexpected:
        failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
    schema_version = raw.get("schema_version")
    if schema_version != WORKER_REPLACEMENT_DRILL_SCHEMA_VERSION:
        failures.append(f"{label}.schema_version is unsupported")
    status = raw.get("status")
    if status != "passed":
        failures.append(f"{label}.status must be passed")
    failures.extend(_trimmed_optional_string_failures(status, f"{label}.status"))
    for name in (
        "worker_destroyed",
        "replacement_runner_profile_ready",
        "control_room_reopened",
        "resume_checkpoint_restored",
        "gate_or_verifier_resumed",
    ):
        if raw.get(name) is not True:
            failures.append(f"{label}.{name} must be true")
    if raw.get("host_machine_state_required") is not False:
        failures.append(f"{label}.host_machine_state_required must be false")
    if raw.get("volatile_state_reused") is not False:
        failures.append(f"{label}.volatile_state_reused must be false")
    restored_from = raw.get("restored_from", [])
    if not isinstance(restored_from, list):
        failures.append(f"{label}.restored_from must be a list")
    else:
        failures.extend(_trimmed_string_list_failures(restored_from, f"{label}.restored_from"))
        restored_values = {item for item in restored_from if isinstance(item, str)}
        if restored_values != set(WORKER_REPLACEMENT_SOURCE_IDS):
            failures.append(
                f"{label}.restored_from must match durable replacement source ids"
            )
        duplicates = _duplicate_text_values(restored_from)
        if duplicates:
            failures.append(
                f"{label}.restored_from contains duplicate {', '.join(duplicates)}"
            )
    for name in ("statement", "pending_reason"):
        if name in raw:
            failures.extend(_trimmed_optional_string_failures(raw.get(name), f"{label}.{name}"))
    statement = str(raw.get("statement", "") or "")
    if (
        "encrypted/redacted" not in statement
        or "no host-machine state" not in statement
        or "no VM-local plaintext" not in statement
    ):
        failures.append(f"{label}.statement is incomplete")
    return failures


def _remote_job_rows_shape_failures(
    rows: list[Any],
    label: str,
    allowed: AbstractSet[str],
    *,
    required: tuple[str, ...],
) -> list[str]:
    failures: list[str] = []
    for index, row in enumerate(rows):
        row_label = f"{label}[{index}]"
        if not isinstance(row, dict):
            failures.append(f"{row_label} must be a JSON object")
            continue
        unexpected = sorted(set(row) - allowed)
        if unexpected:
            failures.append(f"{row_label} has unexpected fields: {', '.join(unexpected)}")
        for name in required:
            value = row.get(name)
            if not isinstance(value, str) or not value:
                failures.append(f"{row_label}.{name} is missing")
        for name in set(allowed) - {"updated_at"}:
            if name in row:
                failures.extend(
                    _trimmed_optional_string_failures(row.get(name), f"{row_label}.{name}")
                )
        if "updated_at" in row:
            failures.extend(
                _plain_number_failures(row.get("updated_at"), f"{row_label}.updated_at")
            )
    return failures


def _trimmed_optional_string_failures(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, str):
        return [f"{label} must be a string"]
    if value != value.strip():
        return [f"{label} must be trimmed"]
    return []


def _trimmed_string_list_failures(values: list[Any], label: str) -> list[str]:
    failures: list[str] = []
    for index, item in enumerate(values):
        item_label = f"{label}[{index}]"
        if not isinstance(item, str):
            failures.append(f"{item_label} must be a string")
        elif item != item.strip():
            failures.append(f"{item_label} must be trimmed")
    return failures


def _plain_number_failures(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, int | float) or isinstance(value, bool):
        return [f"{label} must be a number"]
    return []


def _plain_non_negative_number_failures(value: Any, label: str) -> list[str]:
    failures = _plain_number_failures(value, label)
    if failures or value is None:
        return failures
    if value < 0:
        return [f"{label} must be a non-negative number"]
    return []


def _check_run_record(
    path: Path,
    job_state_path: Path,
    checkpoints_path: Path,
    provider_strategies_path: Path,
    llm_contract_path: Path,
    verification_report_path: Path,
    workspace_detonation_path: Path,
    gate_events_path: Path,
    runner_readiness_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> dict[str, Any]:
    if mode != "live":
        checks.append(
            AcceptanceCheck(
                "run_record.complete",
                "skipped",
                "Central Run Record is required only for live OCI evidence.",
            )
        )
        return {}
    if not path.exists():
        missing.append("central run record")
        checks.append(
            AcceptanceCheck(
                "run_record.complete",
                "missing",
                "Live launch evidence must include .fusekit/run_record.json.",
            )
        )
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        missing.append("central run record")
        checks.append(
            AcceptanceCheck(
                "run_record.complete",
                "failed",
                f"Run Record could not be read: {type(exc).__name__}.",
                str(path),
            )
        )
        return {}
    if not isinstance(raw, dict):
        missing.append("central run record")
        checks.append(
            AcceptanceCheck(
                "run_record.complete",
                "failed",
                "Run Record must be a JSON object.",
                str(path),
            )
        )
        return {}
    failures = _run_record_shape_failures(raw)
    failures.extend(
        _run_record_timeline_survivor_consistency_failures(
            raw,
            job_state_path,
            checkpoints_path,
        )
    )
    failures.extend(
        _run_record_provider_strategy_consistency_failures(raw, provider_strategies_path)
    )
    failures.extend(
        _run_record_provider_playbook_consistency_failures(raw, provider_strategies_path)
    )
    failures.extend(_run_record_llm_contract_artifact_consistency_failures(raw, llm_contract_path))
    failures.extend(_run_record_verifier_consistency_failures(raw, verification_report_path))
    failures.extend(_run_record_detonation_consistency_failures(raw, workspace_detonation_path))
    failures.extend(_run_record_artifact_consistency_failures(raw, path.parent))
    failures.extend(_run_record_evidence_inventory_consistency_failures(raw, path.parent))
    failures.extend(_run_record_wake_events_consistency_failures(raw, gate_events_path))
    failures.extend(_run_record_runner_profile_consistency_failures(raw, runner_readiness_path))
    recording_contract_summary = _recording_contract_report_summary(raw)
    summary = {
        "schema_version": raw.get("schema_version"),
        "id": raw.get("id"),
        "status": raw.get("status"),
        "field_count": len(raw),
        "providers": raw.get("provider_gates", {}).get("providers", [])
        if isinstance(raw.get("provider_gates"), dict)
        else [],
        "artifact_count": len(raw.get("artifacts", []))
        if isinstance(raw.get("artifacts"), list)
        else 0,
        "vault_record_count": raw.get("vault", {}).get("record_count")
        if isinstance(raw.get("vault"), dict)
        else None,
        "recording_contract": recording_contract_summary,
    }
    snapshot = ledger.snapshot_json("run-record-summary", summary)
    if failures:
        missing.append("central run record")
        checks.append(
            AcceptanceCheck(
                "run_record.complete",
                "failed",
                "Run Record is incomplete: " + "; ".join(failures),
                str(snapshot),
            )
        )
        return recording_contract_summary
    checks.append(
        AcceptanceCheck(
            "run_record.complete",
            "ok",
            "Central Run Record ties launch state, gates, provider routes, artifacts, "
            "evidence logs/screenshots, approvals, errors, verification, vault metadata, "
            "and detonation proof.",
            str(snapshot),
        )
    )
    return recording_contract_summary


def _recording_contract_report_summary(run_record: dict[str, Any]) -> dict[str, Any]:
    contract = run_record.get("recording_contract", {})
    if not isinstance(contract, dict):
        return {}
    return _redacted_recording_contract(contract)


def _run_record_shape_failures(raw: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(raw) - RUN_RECORD_KEYS)
    if unexpected:
        failures.append("run_record has unexpected fields: " + ", ".join(unexpected))
    missing = sorted(RUN_RECORD_KEYS - set(raw))
    if missing:
        failures.append("run_record is missing fields: " + ", ".join(missing))
    if raw.get("schema_version") != RUN_RECORD_SCHEMA_VERSION:
        failures.append("schema_version is unsupported")
    failures.extend(_run_record_public_safety_failures(raw))
    for key in ("id", "status", "app_path", "runner"):
        if not str(raw.get(key, "") or "").strip():
            failures.append(f"{key} is missing")
    for key in ("created_at", "updated_at"):
        failures.extend(_plain_non_negative_number_failures(raw.get(key), key))
    app_path = str(raw.get("app_path", "") or "")
    if Path(app_path).is_absolute():
        failures.append("app_path must be a public path label")
    state = _require_dict_field(raw, "state", failures)
    if state is not None:
        failures.extend(_run_record_state_shape_failures(state))
    steps = _require_list_field(raw, "steps", failures)
    if steps is not None:
        failures.extend(_run_record_timeline_shape_failures("steps", steps))
    checkpoints = _require_list_field(raw, "checkpoints", failures)
    if checkpoints is not None:
        failures.extend(_run_record_timeline_shape_failures("checkpoints", checkpoints))
    provider_gates = _require_dict_field(raw, "provider_gates", failures)
    if provider_gates is not None:
        unexpected_provider_gate_keys = sorted(set(provider_gates) - PROVIDER_GATES_KEYS)
        if unexpected_provider_gate_keys:
            failures.append(
                "provider_gates has unexpected fields: "
                + ", ".join(unexpected_provider_gate_keys)
            )
        provider_gate_total = provider_gates.get("total")
        if not _is_plain_int(provider_gate_total):
            failures.append("provider_gates.total is missing")
        provider_gate_records = _require_list_field(
            provider_gates,
            "records",
            failures,
            prefix="provider_gates",
        )
        if (
            provider_gate_records is not None
            and _is_plain_int(provider_gate_total)
            and provider_gate_total != len(provider_gate_records)
        ):
            failures.append("provider_gates.total must match provider_gates.records")
        provider_gate_statuses = _require_dict_field(
            provider_gates,
            "statuses",
            failures,
            prefix="provider_gates",
        )
        provider_gate_providers = _require_list_field(
            provider_gates,
            "providers",
            failures,
            prefix="provider_gates",
        )
        if (
            provider_gate_records is not None
            and provider_gate_statuses is not None
            and provider_gate_providers is not None
        ):
            failures.extend(
                _provider_gate_summary_shape_failures(
                    provider_gate_records,
                    provider_gate_statuses,
                    provider_gate_providers,
                )
            )
    durable_state = _require_dict_field(raw, "durable_state", failures)
    if durable_state is not None:
        failures.extend(_durable_state_shape_failures(durable_state))
    wake_events = _require_dict_field(raw, "wake_events", failures)
    if wake_events is not None:
        failures.extend(_wake_event_summary_shape_failures(wake_events))
    human_actions_required = _run_record_human_actions_required(raw)
    human_actions = _require_dict_field(raw, "human_actions", failures)
    if human_actions is not None:
        failures.extend(
            _human_action_trace_shape_failures(
                human_actions,
                provider_gates,
                human_actions_required=human_actions_required,
            )
        )
    rehearsal_review = _require_dict_field(raw, "rehearsal_review", failures)
    if rehearsal_review is not None:
        failures.extend(
            _rehearsal_review_shape_failures(
                rehearsal_review,
                human_actions,
                human_actions_required=human_actions_required,
            )
        )
    automation_boundary = _require_dict_field(raw, "automation_boundary", failures)
    if automation_boundary is not None:
        failures.extend(_automation_boundary_shape_failures(automation_boundary))
    control_room_security = _require_dict_field(raw, "control_room_security", failures)
    if control_room_security is not None:
        failures.extend(_control_room_security_shape_failures(control_room_security))
    if provider_gates is not None and wake_events is not None:
        failures.extend(_run_record_wake_event_failures(provider_gates, wake_events))
    provider_playbook = _require_dict_field(raw, "provider_playbook", failures)
    if provider_playbook is not None:
        failures.extend(_provider_playbook_shape_failures(provider_playbook))
    model_inference = _require_dict_field(raw, "model_inference", failures)
    if model_inference is not None:
        failures.extend(_model_inference_shape_failures(model_inference))
    llm_contract = _require_dict_field(raw, "llm_contract", failures)
    if llm_contract is not None:
        failures.extend(_llm_contract_shape_failures(llm_contract))
    failures.extend(_run_record_model_inference_consistency_failures(raw))
    provider_strategies = _require_dict_field(raw, "provider_strategies", failures)
    if provider_strategies is not None:
        failures.extend(_provider_strategy_summary_shape_failures(provider_strategies))
        if provider_playbook is not None:
            failures.extend(
                _provider_strategy_provider_coverage_failures(
                    provider_strategies,
                    provider_playbook,
                )
            )
    runner_profile = _require_dict_field(raw, "runner_profile", failures)
    if runner_profile is not None:
        profile_contract = _require_dict_field(
            runner_profile,
            "profile_contract",
            failures,
            prefix="runner_profile",
        )
        if profile_contract is not None:
            failures.extend(_runner_profile_public_contract_failures(profile_contract))
        _require_dict_field(runner_profile, "checks", failures, prefix="runner_profile")
        _require_dict_field(runner_profile, "observed", failures, prefix="runner_profile")
    worker_replacement_drill = _require_dict_field(raw, "worker_replacement_drill", failures)
    if worker_replacement_drill is not None:
        failures.extend(_worker_replacement_drill_shape_failures(worker_replacement_drill))
    verifiers = _require_dict_field(raw, "verifiers", failures)
    if verifiers is not None:
        failures.extend(_verifier_summary_shape_failures(verifiers))
        if provider_playbook is not None:
            failures.extend(_verifier_provider_coverage_failures(verifiers, provider_playbook))
    vault = _require_dict_field(raw, "vault", failures)
    if vault is not None:
        failures.extend(_vault_summary_shape_failures(vault))
    audit_trail = _require_dict_field(raw, "audit_trail", failures)
    if audit_trail is not None:
        failures.extend(_audit_trail_shape_failures(audit_trail, raw))
    recording_contract = _require_dict_field(raw, "recording_contract", failures)
    if recording_contract is not None:
        failures.extend(
            _recording_contract_shape_failures(
                recording_contract,
                raw,
                raw.get("errors", []),
            )
        )
    artifacts = _require_list_field(raw, "artifacts", failures)
    if artifacts is not None:
        failures.extend(_artifact_records_shape_failures(artifacts))
    evidence = _require_dict_field(raw, "evidence", failures)
    if evidence is not None:
        failures.extend(_evidence_inventory_shape_failures(evidence))
    verification = _require_dict_field(raw, "verification", failures)
    if verification is not None:
        failures.extend(_embedded_verification_shape_failures(verification))
    acceptance = _require_dict_field(raw, "acceptance", failures)
    if acceptance:
        failures.extend(_acceptance_summary_shape_failures(acceptance, raw))
    detonation = _require_dict_field(raw, "detonation", failures)
    if detonation is not None:
        unexpected = sorted(set(detonation) - DETONATION_KEYS)
        if unexpected:
            failures.append("detonation has unexpected fields: " + ", ".join(unexpected))
        if detonation.get("preflight_safe") is not True:
            failures.append("detonation.preflight_safe must be true")
        if detonation.get("workspace_detonated") is not True:
            failures.append("detonation.workspace_detonated must be true")
        workspace_receipt = _require_dict_field(
            detonation, "workspace_receipt", failures, prefix="detonation"
        )
        if workspace_receipt is not None:
            failures.extend(_workspace_detonation_receipt_failures(workspace_receipt))
    approvals = _require_list_field(raw, "approvals", failures)
    if approvals is not None:
        failures.extend(_approval_summary_shape_failures(approvals, provider_gates, wake_events))
    errors = _require_list_field(raw, "errors", failures)
    if errors is not None:
        failures.extend(_run_record_error_shape_failures(errors))
    return failures


def _run_record_public_safety_failures(raw: dict[str, Any]) -> list[str]:
    """Reject unsafe public text anywhere in the durable Run Record."""

    failures: list[str] = []
    for path, value in _walk_run_record_strings(raw):
        if contains_durable_secret_text(value):
            failures.append(f"{path} contains credential-looking text")
            if len(failures) >= 20:
                failures.append("run_record contains additional credential-looking text")
                break
        elif _contains_callback_url(value):
            failures.append(f"{path} contains callback URL")
            if len(failures) >= 20:
                failures.append("run_record contains additional unsafe public text")
                break
    return failures


def _standalone_artifact_public_safety_failures(raw: dict[str, Any], label: str) -> list[str]:
    """Reject standalone survivor text that cannot be public launch proof."""

    failures: list[str] = []
    for path, value in _walk_run_record_strings(raw, label):
        if contains_durable_secret_text(value):
            failures.append(f"{path} contains credential-looking text")
        elif _contains_callback_url(value):
            failures.append(f"{path} contains callback URL")
        if len(failures) >= 20:
            failures.append(f"{label} contains additional unsafe public text")
            break
    return failures


def _setup_receipt_shape_failures(raw: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(raw) - SETUP_RECEIPT_KEYS)
    if unexpected:
        failures.append("setup_receipt has unexpected fields: " + ", ".join(unexpected))
    for key in SETUP_RECEIPT_TEXT_FIELDS:
        if key not in raw:
            continue
        value = raw.get(key)
        label = f"setup_receipt.{key}"
        if not isinstance(value, str):
            failures.append(f"{label} must be a string")
        elif value != value.strip():
            failures.append(f"{label} must be trimmed")
        elif contains_durable_secret_text(value):
            failures.append(f"{label} contains credential-looking text")
    actions = raw.get(SETUP_RECEIPT_ACTIONS_FIELD, [])
    if not isinstance(actions, list):
        failures.append("setup_receipt.actions must be a list")
        return failures
    for index, action in enumerate(actions):
        label = f"setup_receipt.actions[{index}]"
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


def _contains_callback_url(value: str) -> bool:
    return bool(re.search(r"https?://[^\s\"'<>]*callback[^\s\"'<>]*", value, re.IGNORECASE))


def _vault_summary_shape_failures(vault: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_vault_keys = sorted(set(vault) - VAULT_KEYS)
    if unexpected_vault_keys:
        failures.append(
            "vault has unexpected fields: " + ", ".join(unexpected_vault_keys)
        )
    records = vault.get("records", [])
    if not isinstance(records, list):
        failures.append("vault.records is missing")
        records = []
    record_count = vault.get("record_count")
    if not isinstance(record_count, int) or isinstance(record_count, bool):
        failures.append("vault.record_count must be a literal integer")
    elif record_count != len(records):
        failures.append("vault.record_count must match vault.records")
    seen_record_ids: set[str] = set()
    for index, record in enumerate(records):
        label = f"vault.records[{index}]"
        if not isinstance(record, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected_record_keys = sorted(set(record) - VAULT_RECORD_KEYS)
        if unexpected_record_keys:
            failures.append(
                f"{label} has unexpected fields: " + ", ".join(unexpected_record_keys)
            )
        for field_name in ("id", "kind", "provider", "label"):
            value = record.get(field_name, "")
            if not isinstance(value, str) or not value:
                failures.append(f"{label}.{field_name} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{field_name} must be trimmed")
            elif contains_durable_secret_text(value):
                failures.append(
                    f"{label}.{field_name} contains credential-looking text"
                )
        record_id = record.get("id", "")
        if isinstance(record_id, str) and record_id:
            if record_id in seen_record_ids:
                failures.append(f"{label}.id duplicates vault record {record_id}")
            seen_record_ids.add(record_id)
        failures.extend(_vault_record_secret_field_failures(record, label))
    return failures


def _vault_record_secret_field_failures(value: Any, label: str) -> list[str]:
    """Reject fields the Run Record writer strips from vault proof metadata."""

    failures: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            field_label = f"{label}.{key_text}"
            if key_text.strip().lower() in VAULT_SECRET_FIELD_NAMES:
                if label.startswith("vault.records[") and key_text == "value":
                    failures.append(f"{label} exposes a raw value")
                else:
                    failures.append(f"{field_label} exposes raw secret metadata")
                continue
            failures.extend(_vault_record_secret_field_failures(nested, field_label))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            failures.extend(_vault_record_secret_field_failures(nested, f"{label}[{index}]"))
    return failures


def _walk_run_record_strings(value: Any, path: str = "run_record") -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        items: list[tuple[str, str]] = []
        for key, nested in value.items():
            key_label = str(key).replace(".", "_")
            items.extend(_walk_run_record_strings(nested, f"{path}.{key_label}"))
        return items
    if isinstance(value, list):
        items = []
        for index, nested in enumerate(value):
            items.extend(_walk_run_record_strings(nested, f"{path}[{index}]"))
        return items
    return []


def _provider_gate_summary_shape_failures(
    records: list[Any],
    statuses: dict[str, Any],
    providers: list[Any],
) -> list[str]:
    failures: list[str] = []
    actual_statuses: dict[str, int] = {}
    actual_providers: set[str] = set()
    seen_gate_ids: set[str] = set()
    for index, gate in enumerate(records):
        label = f"provider_gates.records[{index}]"
        if not isinstance(gate, dict):
            failures.append(f"{label} is not an object")
            continue
        failures.extend(_provider_gate_record_shape_failures(gate, label))
        gate_id = str(gate.get("id", "") or "").strip()
        if not gate_id:
            failures.append(f"{label}.id is missing")
        elif gate_id in seen_gate_ids:
            failures.append(f"{label}.id duplicates provider gate {gate_id}")
        else:
            seen_gate_ids.add(gate_id)
        status = str(gate.get("status", "") or "").strip()
        if not status:
            failures.append(f"{label}.status is missing")
        else:
            actual_statuses[status] = actual_statuses.get(status, 0) + 1
        provider = str(gate.get("provider", "") or "").strip()
        if provider:
            actual_providers.add(provider)
    for status, count in actual_statuses.items():
        if not _is_plain_int(statuses.get(status)) or statuses.get(status) != count:
            failures.append(f"provider_gates.statuses.{status} must match records")
    for status in sorted(str(key) for key in statuses if str(key) not in actual_statuses):
        failures.append(f"provider_gates.statuses.{status} must match records")
    provider_values = {str(provider) for provider in providers if str(provider).strip()}
    if provider_values != actual_providers:
        failures.append("provider_gates.providers must match records")
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
        failures.append(f"{label}.attempts must be a non-negative literal integer")
    for key in ("last_opened_at", "last_wake_event_at", "created_at", "updated_at"):
        value = gate.get(key, 0)
        if (
            not isinstance(value, int | float)
            or isinstance(value, bool)
            or value < 0
        ):
            failures.append(f"{label}.{key} must be a non-negative number")
    return failures


def _wake_event_summary_shape_failures(wake_events: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_keys = sorted(set(wake_events) - WAKE_EVENTS_KEYS)
    if unexpected_keys:
        failures.append("wake_events has unexpected fields: " + ", ".join(unexpected_keys))
    events = wake_events.get("events")
    counts = wake_events.get("event_counts")
    total = wake_events.get("total")
    if not isinstance(events, list):
        failures.append("wake_events.events is missing")
        events = []
    if not isinstance(counts, dict):
        failures.append("wake_events.event_counts is missing")
        counts = {}
    if not _is_plain_int(total):
        failures.append("wake_events.total is missing")
    elif total != len(events):
        failures.append("wake_events.total must match wake_events.events")

    actual_counts: dict[str, int] = {}
    for index, event in enumerate(events):
        label = f"wake_events.events[{index}]"
        if not isinstance(event, dict):
            failures.append(f"{label} is not an object")
            continue
        failures.extend(_wake_event_record_shape_failures(event, label))
        event_name = event.get("event")
        if isinstance(event_name, str) and event_name and event_name == event_name.strip():
            actual_counts[event_name] = actual_counts.get(event_name, 0) + 1

    for event_name, count in counts.items():
        if not isinstance(event_name, str) or not event_name:
            failures.append("wake_events.event_counts key is missing")
        elif event_name != event_name.strip():
            failures.append(f"wake_events.event_counts.{event_name} must be trimmed")
        elif contains_durable_secret_text(event_name):
            failures.append(
                f"wake_events.event_counts.{event_name} contains credential-looking text"
            )
        if not _is_plain_int(count):
            failures.append(f"wake_events.event_counts.{event_name} is missing")
    for event_name, expected in actual_counts.items():
        if counts.get(event_name) != expected:
            failures.append(f"wake_events.event_counts.{event_name} must match events")
    for event_name in sorted(str(key) for key in counts if str(key) not in actual_counts):
        failures.append(f"wake_events.event_counts.{event_name} must match events")
    return failures


def _evidence_inventory_shape_failures(evidence: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_evidence = sorted(set(evidence) - EVIDENCE_INVENTORY_KEYS)
    if unexpected_evidence:
        failures.append("evidence has unexpected fields: " + ", ".join(unexpected_evidence))
    schema_version = str(evidence.get("schema_version", "") or "")
    if schema_version != schema_version.strip():
        failures.append("evidence.schema_version must not have surrounding whitespace")
    if schema_version != EVIDENCE_INVENTORY_SCHEMA_VERSION:
        failures.append("evidence.schema_version is unsupported")
    evidence_lengths: dict[str, int] = {}
    expected_kinds = {
        "logs": "log",
        "screenshots": "screenshot",
        "visual": "visual",
        "receipts": "receipt",
    }
    for evidence_field, expected_kind in expected_kinds.items():
        records = evidence.get(evidence_field)
        if not isinstance(records, list):
            failures.append(f"evidence.{evidence_field} is missing")
            continue
        evidence_lengths[evidence_field] = len(records)
        seen_paths: set[str] = set()
        for index, record in enumerate(records):
            label = f"evidence.{evidence_field}[{index}]"
            if not isinstance(record, dict):
                failures.append(f"{label} is not an object")
                continue
            unexpected_record = sorted(set(record) - EVIDENCE_RECORD_KEYS)
            if unexpected_record:
                failures.append(f"{label} has unexpected fields: {', '.join(unexpected_record)}")
            path = str(record.get("path", "") or "")
            if not path.strip():
                failures.append(f"{label}.path is missing")
            elif path != path.strip():
                failures.append(f"{label}.path must not have surrounding whitespace")
            elif path in seen_paths:
                failures.append(f"{label}.path duplicates evidence path {path}")
            else:
                seen_paths.add(path)
            if path:
                path_parts = Path(path).parts
                if Path(path).is_absolute():
                    failures.append(f"{label}.path must be a public path label")
                if ".." in path_parts:
                    failures.append(f"{label}.path must stay inside the artifact bundle")
            if "token=" in path.lower() or "password=" in path.lower():
                failures.append(f"{label}.path contains credential query text")
            if record.get("exists") is not True:
                failures.append(f"{label}.exists must be true")
            kind = str(record.get("kind", "") or "")
            if not kind.strip():
                failures.append(f"{label}.kind is missing")
            elif kind != kind.strip():
                failures.append(f"{label}.kind must not have surrounding whitespace")
            elif kind != expected_kind:
                failures.append(f"{label}.kind must be {expected_kind}")
            source = str(record.get("source", "") or "")
            if not source.strip():
                failures.append(f"{label}.source is missing")
            elif source != source.strip():
                failures.append(f"{label}.source must not have surrounding whitespace")
    counts = evidence.get("counts", {})
    if not isinstance(counts, dict):
        failures.append("evidence.counts is missing")
    else:
        unexpected_counts = sorted(set(counts) - EVIDENCE_COUNT_KEYS)
        if unexpected_counts:
            failures.append(
                "evidence.counts has unexpected fields: " + ", ".join(unexpected_counts)
            )
        for evidence_field in EVIDENCE_COUNT_KEYS:
            if not _is_plain_int(counts.get(evidence_field)):
                failures.append(f"evidence.counts.{evidence_field} is missing")
            elif (
                evidence_field in evidence_lengths
                and counts.get(evidence_field) != evidence_lengths[evidence_field]
            ):
                failures.append(
                    f"evidence.counts.{evidence_field} must match evidence.{evidence_field}"
                )
    statement = str(evidence.get("statement", "") or "")
    if statement != statement.strip():
        failures.append("evidence.statement must not have surrounding whitespace")
    if "path and type only" not in statement or "raw secrets are not embedded" not in statement:
        failures.append("evidence.statement is missing non-secret inventory guidance")
    return failures


def _artifact_records_shape_failures(artifacts: list[Any]) -> list[str]:
    failures: list[str] = []
    seen_names: set[str] = set()
    seen_paths: set[str] = set()
    for index, artifact in enumerate(artifacts):
        label = f"artifacts[{index}]"
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
        elif _contains_secretish_audit_text(name):
            failures.append(f"{label}.name contains credential-looking text")
        elif name in seen_names:
            failures.append(f"{label}.name duplicates artifact {name}")
        else:
            seen_names.add(name)
        if not path:
            failures.append(f"{label}.path is missing")
        elif path != path.strip():
            failures.append(f"{label}.path must not have surrounding whitespace")
        else:
            artifact_path = Path(path)
            if artifact_path.is_absolute():
                failures.append(f"{label}.path must be a public path label")
            if ".." in artifact_path.parts:
                failures.append(f"{label}.path must stay inside the artifact bundle")
            if "token=" in path.lower() or "password=" in path.lower():
                failures.append(f"{label}.path contains credential query text")
            if _contains_secretish_audit_text(path):
                failures.append(f"{label}.path contains credential-looking text")
            if path in seen_paths:
                failures.append(f"{label}.path duplicates artifact path {path}")
            else:
                seen_paths.add(path)
        if not isinstance(artifact.get("exists"), bool):
            failures.append(f"{label}.exists must be boolean")
    return failures


def _run_record_artifact_consistency_failures(
    run_record: dict[str, Any],
    artifact_root: Path,
) -> list[str]:
    artifacts = run_record.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []
    failures: list[str] = []
    root = artifact_root.resolve()
    for index, artifact in enumerate(artifacts):
        label = f"artifacts[{index}]"
        if not isinstance(artifact, dict):
            continue
        path_text = str(artifact.get("path", "") or "").strip()
        if not path_text:
            continue
        artifact_path = Path(path_text)
        if artifact_path.is_absolute() or ".." in artifact_path.parts:
            continue
        candidate = (root / artifact_path).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if artifact.get("exists") is True and not candidate.is_file():
                failures.append(f"{label}.path must exist in retrieved artifacts")
    return failures


def _run_record_timeline_survivor_consistency_failures(
    run_record: dict[str, Any],
    job_state_path: Path,
    checkpoints_path: Path,
) -> list[str]:
    failures: list[str] = []
    job_state, job_failures = _read_run_record_standalone_json_artifact(
        job_state_path,
        "job.json",
        required=True,
    )
    checkpoints, checkpoint_failures = _read_run_record_standalone_json_artifact(
        checkpoints_path,
        "checkpoints.json",
        required=True,
    )
    failures.extend(job_failures)
    failures.extend(checkpoint_failures)
    run_steps = _timeline_status_by_id(run_record.get("steps", []))
    run_checkpoints = _timeline_status_by_id(run_record.get("checkpoints", []))
    if job_state is not None:
        failures.extend(
            _timeline_status_drift_failures(
                "job.json steps",
                run_steps,
                _timeline_status_by_id(job_state.get(REMOTE_JOB_STEPS_FIELD, [])),
            )
        )
        failures.extend(
            _timeline_status_drift_failures(
                "job.json checkpoints",
                run_checkpoints,
                _timeline_status_by_id(job_state.get(REMOTE_JOB_CHECKPOINTS_FIELD, [])),
            )
        )
    if checkpoints is not None:
        failures.extend(
            _timeline_status_drift_failures(
                "checkpoints.json checkpoints",
                run_checkpoints,
                _timeline_status_by_id(
                    checkpoints.get(REMOTE_CHECKPOINTS_CHECKPOINTS_FIELD, [])
                ),
            )
        )
    return failures


def _timeline_status_by_id(rows: Any) -> dict[str, str]:
    if not isinstance(rows, list):
        return {}
    statuses: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        row_id = str(row.get("id", "") or "").strip()
        status = str(row.get("status", "") or "").strip()
        if row_id and status:
            statuses[row_id] = status
    return statuses


def _timeline_status_drift_failures(
    label: str,
    run_statuses: dict[str, str],
    survivor_statuses: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    for row_id in sorted(set(run_statuses) & set(survivor_statuses)):
        if survivor_statuses[row_id] != run_statuses[row_id]:
            failures.append(f"{label}.{row_id} status must match Run Record")
    return failures


def _run_record_evidence_inventory_consistency_failures(
    run_record: dict[str, Any],
    evidence_root: Path,
) -> list[str]:
    evidence = run_record.get("evidence", {})
    if not isinstance(evidence, dict):
        return []
    failures: list[str] = []
    root = evidence_root.resolve()
    expected_kinds = {
        "logs": "log",
        "screenshots": "screenshot",
        "visual": "visual",
        "receipts": "receipt",
    }
    counts = evidence.get("counts", {})
    counts = counts if isinstance(counts, dict) else {}
    for evidence_field, expected_kind in expected_kinds.items():
        records = evidence.get(evidence_field, [])
        if not isinstance(records, list):
            continue
        if counts.get(evidence_field) != len(records):
            failures.append(
                f"evidence.counts.{evidence_field} must match evidence.{evidence_field}"
            )
        for index, record in enumerate(records):
            label = f"evidence.{evidence_field}[{index}]"
            if not isinstance(record, dict):
                continue
            if str(record.get("kind", "") or "") != expected_kind:
                failures.append(f"{label}.kind must be {expected_kind}")
            path_text = str(record.get("path", "") or "").strip()
            if not path_text:
                continue
            evidence_path = Path(path_text)
            if evidence_path.is_absolute():
                failures.append(f"{label}.path must be relative to .fusekit")
                continue
            if ".." in evidence_path.parts:
                failures.append(f"{label}.path must stay inside .fusekit")
                continue
            candidate = (root / evidence_path).resolve()
            try:
                candidate.relative_to(root)
            except ValueError:
                failures.append(f"{label}.path must stay inside .fusekit")
                continue
            if record.get("exists") is True and not candidate.is_file():
                failures.append(f"{label}.path must exist in retrieved artifacts")
    return failures


def _human_action_trace_shape_failures(
    human_actions: dict[str, Any],
    provider_gates: dict[str, Any] | None = None,
    *,
    human_actions_required: bool = False,
) -> list[str]:
    failures: list[str] = []
    if str(human_actions.get("schema_version", "")).strip() != (
        HUMAN_ACTION_TRACE_SCHEMA_VERSION
    ):
        failures.append("human_actions.schema_version is unsupported")
    actions = human_actions.get("actions", [])
    counts = human_actions.get("counts", {})
    unguided = human_actions.get("unguided", [])
    if not isinstance(actions, list):
        failures.append("human_actions.actions is missing")
        actions = []
    if not isinstance(counts, dict):
        failures.append("human_actions.counts is missing")
        counts = {}
    if not isinstance(unguided, list):
        failures.append("human_actions.unguided is missing")
        unguided = []
    if _safe_int(human_actions.get("total")) != len(actions):
        failures.append("human_actions.total must match human_actions.actions")
    if human_actions_required and not actions:
        failures.append(
            "human_actions.actions are required when provider gates or wake events exist"
        )
    actual_counts: dict[str, int] = {}
    gate_targets_by_id: dict[str, set[str]] = {}
    if provider_gates is not None:
        gate_records = provider_gates.get("records", [])
        if isinstance(gate_records, list):
            for gate in gate_records:
                if not isinstance(gate, dict):
                    continue
                gate_id = str(gate.get("id", "") or "").strip()
                if not gate_id:
                    continue
                targets: set[str] = set()
                targets.update(_env_targets_from_text(str(gate.get("target", "") or "")))
                captured_targets = gate.get("captured_targets", [])
                if isinstance(captured_targets, list):
                    for target in captured_targets:
                        targets.update(_env_targets_from_text(str(target or "")))
                gate_targets_by_id[gate_id] = targets
    seen_identities: set[tuple[str, str, str, str]] = set()
    for index, action in enumerate(actions):
        label = f"human_actions.actions[{index}]"
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
        if identity in seen_identities:
            failures.append(f"{label} duplicates human action proof")
        seen_identities.add(identity)
        action_name = str(action.get("action", "") or "")
        if action_name not in HUMAN_ACTION_COUNT_KEYS:
            failures.append(f"{label}.action is unsupported")
        else:
            actual_counts[action_name] = actual_counts.get(action_name, 0) + 1
        gate_id = str(action.get("gate_id", "") or "").strip()
        if not gate_id:
            failures.append(f"{label}.gate_id is missing")
        elif gate_targets_by_id and gate_id not in gate_targets_by_id:
            failures.append(f"{label}.gate_id must match provider_gates.records")
        if not str(action.get("visible_control", "") or "").strip():
            failures.append(f"{label}.visible_control is missing")
        if action.get("guided") is not True:
            failures.append(f"{label}.guided must be true")
        visible_control = str(action.get("visible_control", "") or "")
        if (
            action_name == OPEN_PROVIDER_GATE_ACTION
            and visible_control != OPEN_PROVIDER_GATE_CONTROL
        ):
            failures.append(f"{label}.visible_control must be Open provider gate in VM")
        if action_name == CAPTURE_VM_CLIPBOARD_ACTION:
            target = str(action.get("target", "") or "")
            if not target or capture_vm_clipboard_control(target) != visible_control:
                failures.append(f"{label}.visible_control must match the captured target")
            normalized_targets = _env_targets_from_text(target)
            expected_targets = gate_targets_by_id.get(gate_id, set())
            if (
                normalized_targets
                and expected_targets
                and not set(normalized_targets).issubset(expected_targets)
            ):
                failures.append(f"{label}.target must match provider_gates.records target")
        if (
            action_name == CONFIRM_GATE_FINISHED_ACTION
            and visible_control not in FINISH_VISIBLE_CONTROLS
        ):
            failures.append(f"{label}.visible_control must be a known finish/approval control")
    for action_name, expected in actual_counts.items():
        if _safe_int(counts.get(action_name)) != expected:
            failures.append(f"human_actions.counts.{action_name} must match actions")
    if unguided:
        failures.append("human_actions.unguided must be empty")
    statement = str(human_actions.get("statement", "") or "")
    if "visible control-room gate" not in statement or "no raw provider" not in statement:
        failures.append("human_actions.statement is missing guided-action guidance")
    return failures


def _run_record_human_actions_required(record: dict[str, Any]) -> bool:
    provider_gates = record.get("provider_gates", {})
    if isinstance(provider_gates, dict) and _safe_int(
        provider_gates.get("total"),
        default=0,
    ) > 0:
        return True
    wake_events = record.get("wake_events", {})
    if isinstance(wake_events, dict) and _safe_int(
        wake_events.get("total"),
        default=0,
    ) > 0:
        return True
    automation_boundary = record.get("automation_boundary", {})
    counts = (
        automation_boundary.get("counts", {})
        if isinstance(automation_boundary, dict)
        else {}
    )
    return isinstance(counts, dict) and _safe_int(counts.get("human_gate"), default=0) > 0


def _human_action_identity(action: dict[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(action.get("gate_id", "") or "").strip().lower(),
        str(action.get("action", "") or "").strip().lower(),
        str(action.get("visible_control", "") or "").strip(),
        str(action.get("target", "") or "").strip(),
    )


def _rehearsal_review_shape_failures(
    review: dict[str, Any],
    human_actions: dict[str, Any] | None = None,
    *,
    human_actions_required: bool = False,
) -> list[str]:
    failures: list[str] = []
    if str(review.get("schema_version", "")).strip() != REHEARSAL_REVIEW_SCHEMA_VERSION:
        failures.append("rehearsal_review.schema_version is unsupported")
    if str(review.get("status", "")).strip() != "ready":
        failures.append("rehearsal_review.status must be ready")
    actions: list[Any] = []
    unguided: list[Any] = []
    if isinstance(human_actions, dict):
        raw_actions = human_actions.get("actions", [])
        raw_unguided = human_actions.get("unguided", [])
        actions = raw_actions if isinstance(raw_actions, list) else []
        unguided = raw_unguided if isinstance(raw_unguided, list) else []
    action_count = len(actions)
    unguided_count = len(unguided)
    if human_actions_required and action_count == 0:
        failures.append(
            "rehearsal_review.reviewed_actions must include guided human actions "
            "when provider gates or wake events exist"
        )
    if _safe_int(review.get("action_count")) != action_count:
        failures.append("rehearsal_review.action_count must match human_actions.actions")
    if _safe_int(review.get("compared_action_count")) != action_count:
        failures.append(
            "rehearsal_review.compared_action_count must match human_actions.actions"
        )
    if _safe_int(review.get("matched_control_count")) != action_count:
        failures.append(
            "rehearsal_review.matched_control_count must match human_actions.actions"
        )
    if _safe_int(review.get("unguided_count")) != unguided_count:
        failures.append("rehearsal_review.unguided_count must match human_actions.unguided")
    if unguided_count:
        failures.append("rehearsal_review.unguided_count must be zero")
    if _safe_int(review.get("side_channel_count")) != 0:
        failures.append("rehearsal_review.side_channel_count must be zero")
    if review.get("requires_user_thinking") is not False:
        failures.append("rehearsal_review.requires_user_thinking must be false")
    reviewed_actions = review.get("reviewed_actions", [])
    if not isinstance(reviewed_actions, list):
        failures.append("rehearsal_review.reviewed_actions is missing")
        reviewed_actions = []
    if len(reviewed_actions) != action_count:
        failures.append("rehearsal_review.reviewed_actions must match human_actions.actions")
    for index, action in enumerate(actions):
        label = f"rehearsal_review.reviewed_actions[{index}]"
        if not isinstance(action, dict):
            continue
        if index >= len(reviewed_actions):
            continue
        reviewed = reviewed_actions[index]
        if not isinstance(reviewed, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(reviewed) - _REHEARSAL_REVIEW_ACTION_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        for key in ("gate_id", "action", "visible_control", "target", "proof_source"):
            value = str(reviewed.get(key, "") or "")
            if value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        action_name = str(action.get("action", "") or "")
        if str(reviewed.get("gate_id", "") or "") != str(action.get("gate_id", "") or ""):
            failures.append(f"{label}.gate_id must match human_actions.actions")
        if str(reviewed.get("action", "") or "") != action_name:
            failures.append(f"{label}.action must match human_actions.actions")
        if str(reviewed.get("visible_control", "") or "") != str(
            action.get("visible_control", "") or ""
        ):
            failures.append(f"{label}.visible_control must match human_actions.actions")
        if str(reviewed.get("target", "") or "") != str(action.get("target", "") or ""):
            failures.append(f"{label}.target must match human_actions.actions")
        if reviewed.get("matched") is not True:
            failures.append(f"{label}.matched must be true")
        expected_proof = _rehearsal_review_proof_source(action_name)
        if str(reviewed.get("proof_source", "") or "") != expected_proof:
            failures.append(f"{label}.proof_source must be {expected_proof}")
    statement = str(review.get("statement", "") or "").lower()
    if "control-room instructions" not in statement or "public recording" not in statement:
        failures.append("rehearsal_review.statement is missing rehearsal guidance")
    return failures


def _automation_boundary_shape_failures(boundary: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_boundary = sorted(set(boundary) - AUTOMATION_BOUNDARY_KEYS)
    if unexpected_boundary:
        failures.append(
            "automation_boundary has unexpected fields: "
            + ", ".join(unexpected_boundary)
        )
    for key in ("schema_version", "status", "detonation_scope", "statement"):
        value = str(boundary.get(key, "") or "")
        if value != value.strip():
            failures.append(f"automation_boundary.{key} must not have surrounding whitespace")
    if str(boundary.get("schema_version", "")) != AUTOMATION_BOUNDARY_SCHEMA_VERSION:
        failures.append("automation_boundary.schema_version is unsupported")
    if str(boundary.get("status", "")) != AUTOMATION_BOUNDARY_READY_STATUS:
        failures.append("automation_boundary.status must be ready")
    if boundary.get("resume_after_worker_replace") is not True:
        failures.append("automation_boundary.resume_after_worker_replace must be true")
    if boundary.get("no_user_machine_state") is not True:
        failures.append("automation_boundary.no_user_machine_state must be true")
    if str(boundary.get("detonation_scope", "")) != AUTOMATION_BOUNDARY_DETONATION_SCOPE:
        failures.append("automation_boundary.detonation_scope is unsupported")
    allowed = boundary.get("vnc_allowed_for", [])
    allowed_values: set[str] = set()
    if not isinstance(allowed, list):
        failures.append("automation_boundary.vnc_allowed_for is missing")
    else:
        allowed_values = {str(item).strip() for item in allowed if str(item).strip()}
        for index, item in enumerate(allowed):
            value = str(item or "")
            if not value.strip():
                failures.append(f"automation_boundary.vnc_allowed_for[{index}] is missing")
            elif value != value.strip():
                failures.append(
                    f"automation_boundary.vnc_allowed_for[{index}] "
                    "must not have surrounding whitespace"
                )
        _append_duplicate_text_failures(
            failures,
            "automation_boundary.vnc_allowed_for",
            allowed,
        )
    required_allowed = AUTOMATION_BOUNDARY_REQUIRED_VNC_ALLOWLIST
    if not required_allowed.issubset(allowed_values):
        failures.append("automation_boundary.vnc_allowed_for is incomplete")
    routes = boundary.get("routes", [])
    if not isinstance(routes, list):
        failures.append("automation_boundary.routes is missing")
        routes = []
    seen_route_signatures: set[str] = set()
    for index, route in enumerate(routes):
        label = f"automation_boundary.routes[{index}]"
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
        if owner not in AUTOMATION_BOUNDARY_ROUTE_OWNERS:
            failures.append(f"{label}.owner is unsupported")
        if owner == "fusekit":
            if route.get("deterministic") is not True:
                failures.append(f"{label}.deterministic must be true")
            if route.get("implemented") is not True:
                failures.append(f"{label}.implemented must be true")
            if (
                str(route.get("route", ""))
                not in AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS
            ):
                failures.append(f"{label}.route must be an automation route")
        if (
            owner == "human_gate"
            and str(route.get("route", ""))
            not in AUTOMATION_BOUNDARY_HUMAN_GATE_ROUTE_KINDS
        ):
            failures.append(f"{label}.route must be a human gate route")
        route_signature = _automation_boundary_route_signature(route)
        if route_signature != ":":
            if route_signature in seen_route_signatures:
                failures.append(f"{label} duplicates automation route {route_signature}")
            seen_route_signatures.add(route_signature)
    counts = boundary.get("counts", {})
    if not isinstance(counts, dict):
        failures.append("automation_boundary.counts is missing")
    else:
        unexpected_counts = sorted(set(counts) - AUTOMATION_BOUNDARY_COUNTS_KEYS)
        if unexpected_counts:
            failures.append(
                "automation_boundary.counts has unexpected fields: "
                + ", ".join(unexpected_counts)
            )
        for key in AUTOMATION_BOUNDARY_COUNTS_KEYS:
            count_value = counts.get(key)
            if not isinstance(count_value, int) or isinstance(count_value, bool):
                failures.append(f"automation_boundary.counts.{key} must be an integer")
        blocked_count = counts.get("blocked")
        if blocked_count != 0 or isinstance(blocked_count, bool):
            failures.append("automation_boundary.counts.blocked must be 0")
        fusekit_owned_count = sum(
            1 for route in routes if isinstance(route, dict) and route.get("owner") == "fusekit"
        )
        human_gate_count = sum(
            1 for route in routes if isinstance(route, dict) and route.get("owner") == "human_gate"
        )
        if counts.get("fusekit_owned") != fusekit_owned_count:
            failures.append("automation_boundary.counts.fusekit_owned must match routes")
        if counts.get("human_gate") != human_gate_count:
            failures.append("automation_boundary.counts.human_gate must match routes")
    post_gate = boundary.get("post_gate_automation", {})
    if not isinstance(post_gate, dict):
        failures.append("automation_boundary.post_gate_automation is missing")
    else:
        unexpected_post_gate = sorted(set(post_gate) - AUTOMATION_BOUNDARY_POST_GATE_KEYS)
        if unexpected_post_gate:
            failures.append(
                "automation_boundary.post_gate_automation has unexpected fields: "
                + ", ".join(unexpected_post_gate)
            )
        api_or_cli_routes = post_gate.get("api_or_cli_routes")
        human_gate_routes = post_gate.get("human_gate_routes")
        if not isinstance(api_or_cli_routes, list):
            failures.append("automation_boundary.post_gate_automation.api_or_cli_routes is missing")
        else:
            expected_api_or_cli = sorted(
                _automation_boundary_route_signature(route)
                for route in routes
                if isinstance(route, dict)
                and route.get("owner") == "fusekit"
                and str(route.get("route", "") or "").strip()
                in AUTOMATION_BOUNDARY_FUSEKIT_ROUTE_KINDS
            )
            if sorted(str(item) for item in api_or_cli_routes) != expected_api_or_cli:
                failures.append(
                    "automation_boundary.post_gate_automation.api_or_cli_routes "
                    "must match fusekit-owned routes"
                )
            for index, item in enumerate(api_or_cli_routes):
                value = str(item or "")
                if value != value.strip():
                    failures.append(
                        "automation_boundary.post_gate_automation.api_or_cli_routes"
                        f"[{index}] must not have surrounding whitespace"
                    )
            _append_duplicate_text_failures(
                failures,
                "automation_boundary.post_gate_automation.api_or_cli_routes",
                api_or_cli_routes,
            )
        if not isinstance(human_gate_routes, list):
            failures.append("automation_boundary.post_gate_automation.human_gate_routes is missing")
        else:
            expected_human_gate = sorted(
                _automation_boundary_route_signature(route)
                for route in routes
                if isinstance(route, dict) and route.get("owner") == "human_gate"
            )
            if sorted(str(item) for item in human_gate_routes) != expected_human_gate:
                failures.append(
                    "automation_boundary.post_gate_automation.human_gate_routes "
                    "must match human-gate routes"
                )
            for index, item in enumerate(human_gate_routes):
                value = str(item or "")
                if value != value.strip():
                    failures.append(
                        "automation_boundary.post_gate_automation.human_gate_routes"
                        f"[{index}] must not have surrounding whitespace"
                    )
            _append_duplicate_text_failures(
                failures,
                "automation_boundary.post_gate_automation.human_gate_routes",
                human_gate_routes,
            )
    statement = str(boundary.get("statement", "") or "")
    lowered = statement.lower()
    for term in AUTOMATION_BOUNDARY_STATEMENT_TERMS:
        if term not in lowered:
            failures.append("automation_boundary.statement is missing " + term + " guidance")
            break
    return failures


def _automation_boundary_route_signature(route: dict[str, Any]) -> str:
    provider = str(route.get("provider", "") or "").strip()
    recipe = str(route.get("recipe", "") or "").strip()
    return f"{provider}:{recipe}"


def _control_room_security_shape_failures(surface: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_surface = sorted(set(surface) - CONTROL_ROOM_SECURITY_KEYS)
    if unexpected_surface:
        failures.append(
            "control_room_security has unexpected fields: "
            + ", ".join(unexpected_surface)
        )
    if str(surface.get("schema_version", "") or "") != CONTROL_ROOM_SECURITY_SCHEMA_VERSION:
        failures.append("control_room_security.schema_version is unsupported")
    routes = surface.get("routes", [])
    state_routes = surface.get("state_changing_routes", [])
    if not isinstance(routes, list) or not routes:
        failures.append("control_room_security.routes is missing")
        routes = []
    if not isinstance(state_routes, list) or not state_routes:
        failures.append("control_room_security.state_changing_routes is missing")
        state_routes = []
    expected_state_routes = CONTROL_ROOM_PROTECTED_MUTATION_ROUTES
    route_values: set[str] = set()
    state_route_values: set[str] = set()
    state_change_count = 0
    for index, route in enumerate(routes):
        label = f"control_room_security.routes[{index}]"
        if not isinstance(route, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected_route = sorted(set(route) - CONTROL_ROOM_SECURITY_ROUTE_KEYS)
        if unexpected_route:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected_route)}")
        raw_route_value = str(route.get("route", "") or "")
        route_value = raw_route_value.strip()
        methods = route.get("methods", [])
        if not route_value:
            failures.append(f"{label}.route is missing")
        elif raw_route_value != route_value:
            failures.append(f"{label}.route must not have surrounding whitespace")
        elif route_value in route_values:
            failures.append(f"{label}.route duplicates control-room route {route_value}")
        if not isinstance(methods, list) or not methods:
            failures.append(f"{label}.methods is missing")
        else:
            for method_index, method in enumerate(methods):
                method_label = f"{label}.methods[{method_index}]"
                method_value = str(method or "")
                if not method_value.strip():
                    failures.append(f"{method_label} is missing")
                elif method_value != method_value.strip():
                    failures.append(f"{method_label} must not have surrounding whitespace")
        protection = str(route.get("protection", "") or "")
        if not protection.strip():
            failures.append(f"{label}.protection is missing")
        elif protection != protection.strip():
            failures.append(f"{label}.protection must not have surrounding whitespace")
        if route.get("state_change") is True:
            state_change_count += 1
        if route_value:
            route_values.add(route_value)
    for index, route in enumerate(state_routes):
        label = f"control_room_security.state_changing_routes[{index}]"
        route_value = str(route or "").strip()
        if not route_value:
            failures.append(f"{label} is missing")
        elif str(route or "") != route_value:
            failures.append(f"{label} must not have surrounding whitespace")
        elif route_value in state_route_values:
            failures.append(f"{label} duplicates state-changing route {route_value}")
        if route_value:
            state_route_values.add(route_value)
    route_count = surface.get("route_count")
    if not isinstance(route_count, int) or isinstance(route_count, bool):
        route_count = -1
    if route_count != len(routes):
        failures.append("control_room_security.route_count must match routes")
    state_changing_route_count = surface.get("state_changing_route_count")
    if not isinstance(state_changing_route_count, int) or isinstance(
        state_changing_route_count, bool
    ):
        state_changing_route_count = -1
    if state_changing_route_count != state_change_count:
        failures.append("control_room_security.state_changing_route_count must match routes")
    if not expected_state_routes.issubset(route_values):
        failures.append("control_room_security.routes missing protected gate mutation routes")
    if not expected_state_routes.issubset(state_route_values):
        failures.append(
            "control_room_security.state_changing_routes missing protected gate mutation routes"
        )
    required_protection = str(surface.get("required_post_protection", "") or "")
    for term in CONTROL_ROOM_REQUIRED_POST_PROTECTION_TERMS:
        if term not in required_protection:
            failures.append("control_room_security.required_post_protection is incomplete")
            break
    if surface.get("unknown_route_protection") != CONTROL_ROOM_UNKNOWN_ROUTE_PROTECTION:
        failures.append("control_room_security.unknown_route_protection is unsupported")
    statement = str(surface.get("statement", "") or "").lower()
    for term in CONTROL_ROOM_SECURITY_STATEMENT_TERMS:
        if term not in statement:
            failures.append("control_room_security.statement is incomplete")
            break
    return failures


def _provider_strategy_summary_shape_failures(strategies: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(strategies.get("schema_version", "")).strip() != (
        PROVIDER_STRATEGIES_SCHEMA_VERSION
    ):
        failures.append("provider_strategies.schema_version is unsupported")
    providers = strategies.get("providers", [])
    if not isinstance(providers, list) or not providers:
        failures.append("provider_strategies.providers is missing")
        return failures
    for provider_index, provider_record in enumerate(providers):
        label = f"provider_strategies.providers[{provider_index}]"
        if not isinstance(provider_record, dict):
            failures.append(f"{label} is not an object")
            continue
        provider = str(provider_record.get("provider", "") or "").strip()
        if not provider:
            failures.append(f"{label}.provider is missing")
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
                if not isinstance(selected.get(key), bool):
                    failures.append(
                        f"{strategy_label}.decision.selected.{key} must be boolean"
                    )
            if not str(selected.get("reason", "") or "").strip():
                failures.append(f"{strategy_label}.decision.selected.reason is missing")
            candidates = decision.get("candidates", [])
            if not isinstance(candidates, list) or not candidates:
                failures.append(f"{strategy_label}.decision.candidates is missing")
            else:
                failures.extend(
                    _provider_strategy_candidate_shape_failures(
                        candidates,
                        f"{strategy_label}.decision.candidates",
                    )
                )
            if str(strategy.get("status", "")).strip() == "needs_human_gate":
                follow_steps = strategy.get("follow_steps", [])
                if not isinstance(follow_steps, list) or not any(
                    str(step).strip() for step in follow_steps
                ):
                    failures.append(f"{strategy_label}.follow_steps is missing")
                for key in ("next_action", "resume_hint"):
                    if not str(strategy.get(key, "")).strip():
                        failures.append(f"{strategy_label}.{key} is missing")
                for key in ("success_criteria", "avoid_steps"):
                    if not _string_list_field(strategy.get(key)):
                        failures.append(f"{strategy_label}.{key} is missing")
            failures.extend(
                _provider_specific_strategy_shape_failures(
                    provider,
                    strategy,
                    selected,
                    strategy_label,
                )
            )
    return failures


def _provider_strategy_provider_coverage_failures(
    strategies: dict[str, Any],
    provider_playbook: dict[str, Any],
) -> list[str]:
    providers = strategies.get("providers", [])
    steps = provider_playbook.get("steps", [])
    if not isinstance(providers, list) or not isinstance(steps, list) or not steps:
        return []
    route_providers = {
        str(provider.get("provider", "") or "").strip().lower()
        for provider in providers
        if isinstance(provider, dict)
    }
    playbook_providers = {
        str(step.get("provider", "") or "").strip().lower()
        for step in steps
        if isinstance(step, dict)
    }
    required = {
        "GitHub": RECORDING_PROVIDER_PLAYBOOK_FAMILIES["github"],
        "Resend": RECORDING_PROVIDER_PLAYBOOK_FAMILIES["resend"],
        "Vercel": RECORDING_PROVIDER_PLAYBOOK_FAMILIES["vercel"],
        "DNS/Cloudflare": RECORDING_PROVIDER_PLAYBOOK_FAMILIES["dns"],
    }
    missing = [
        label
        for label, accepted in required.items()
        if accepted & playbook_providers and not accepted & route_providers
    ]
    if not missing:
        return []
    return [
        "provider_strategies.providers missing public demo provider coverage: "
        + ", ".join(sorted(missing))
    ]


def _model_inference_shape_failures(model: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(model) - _MODEL_INFERENCE_KEYS)
    if unexpected:
        failures.append(f"model_inference has unexpected fields: {', '.join(unexpected)}")
    if str(model.get("schema_version", "") or "") != "fusekit.model-inference-summary.v1":
        failures.append("model_inference.schema_version is unsupported")
    status = str(model.get("status", "") or "")
    if status not in {"api_key_encrypted", "openclaw_profile_encrypted"}:
        failures.append("model_inference.status must prove encrypted API key or OpenClaw auth")
    if model.get("ready") is not True:
        failures.append("model_inference.ready must be true")
    for key in ("required", "can_proceed_without_api_key"):
        if not isinstance(model.get(key), bool):
            failures.append(f"model_inference.{key} must be boolean")
    if _safe_int(model.get("lane_count")) < 0:
        failures.append("model_inference.lane_count must be integer")
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
            _llm_public_string_failures(
                model.get(key),
                f"model_inference.{key}",
                check_secretish=key != "base_url",
            )
        )
    if str(model.get("auth_mode", "") or "") not in {"auto", "api-key", "openclaw"}:
        failures.append("model_inference.auth_mode is unsupported")
    next_action = str(model.get("next_action", "") or "").lower()
    if "encrypted" not in next_action and "continue" not in next_action:
        failures.append("model_inference.next_action must explain the ready auth lane")
    statement = str(model.get("statement", "") or "").lower()
    if (
        "api keys are captured into the encrypted vault" not in statement
        or "raw secrets never appear" not in statement
    ):
        failures.append("model_inference.statement is missing secret-boundary guidance")
    return failures


def _run_record_model_inference_consistency_failures(
    run_record: dict[str, Any],
) -> list[str]:
    llm_contract = run_record.get("llm_contract", {})
    model = run_record.get("model_inference", {})
    if not isinstance(llm_contract, dict) or not llm_contract:
        return ["Run Record must include llm_contract for model_inference proof"]
    if not isinstance(model, dict):
        return []
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
        if str(model.get(field, "") or "") != str(llm_contract.get(field, "") or "")
    ]
    if mismatched:
        return [
            "model_inference must match llm_contract fields: " + ", ".join(sorted(mismatched))
        ]
    lanes = llm_contract.get("lanes", [])
    if isinstance(lanes, list) and _safe_int(model.get("lane_count")) != len(lanes):
        return ["model_inference.lane_count must match llm_contract.lanes"]
    return []


def _llm_contract_shape_failures(contract: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(contract) - _LLM_CONTRACT_KEYS)
    if unexpected:
        failures.append(f"llm_contract has unexpected fields: {', '.join(unexpected)}")
    if str(contract.get("schema_version", "") or "") != "fusekit.llm-contract.v1":
        failures.append("llm_contract.schema_version is unsupported")
    status = str(contract.get("status", "") or "")
    if status not in {"api_key_encrypted", "openclaw_profile_encrypted"}:
        failures.append("llm_contract.status must prove encrypted API key or OpenClaw auth")
    for key in ("required", "can_proceed_without_api_key"):
        if not isinstance(contract.get(key), bool):
            failures.append(f"llm_contract.{key} must be boolean")
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
            _llm_public_string_failures(
                contract.get(key),
                f"llm_contract.{key}",
                check_secretish=key != "base_url",
            )
        )
    if str(contract.get("auth_mode", "") or "") not in {"auto", "api-key", "openclaw"}:
        failures.append("llm_contract.auth_mode is unsupported")
    lanes = contract.get("lanes")
    if not isinstance(lanes, list) or not lanes:
        failures.append("llm_contract.lanes is missing")
        lanes = []
    else:
        failures.extend(_llm_contract_lane_shape_failures(lanes, contract))
    security = contract.get("security", {})
    if not isinstance(security, dict):
        failures.append("llm_contract.security is missing")
    else:
        unexpected_security = sorted(set(security) - _LLM_CONTRACT_SECURITY_KEYS)
        if unexpected_security:
            failures.append(
                "llm_contract.security has unexpected fields: "
                + ", ".join(unexpected_security)
            )
        if str(security.get("raw_secret_export", "") or "") != "denied":
            failures.append("llm_contract.security.raw_secret_export must be denied")
        for key in ("storage", "public_surfaces", "detonation"):
            failures.extend(
                _llm_public_string_failures(
                    security.get(key),
                    f"llm_contract.security.{key}",
                )
            )
        storage = str(security.get("storage", "") or "").lower()
        if "encrypted" not in storage or "vault" not in storage:
            failures.append("llm_contract.security.storage must mention encrypted vault")
    return failures


def _llm_contract_lane_shape_failures(
    lanes: list[Any],
    contract: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    seen: set[str] = set()
    lane_by_id: dict[str, dict[str, Any]] = {}
    for index, lane in enumerate(lanes):
        label = f"llm_contract.lanes[{index}]"
        if not isinstance(lane, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(lane) - _LLM_CONTRACT_LANE_KEYS)
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
        elif _contains_secretish_audit_text(description):
            failures.append(f"{label}.description contains credential-looking text")
    default_lane = str(contract.get("default_lane", "") or "").strip()
    if not default_lane:
        failures.append("llm_contract.default_lane is missing")
    elif default_lane not in seen:
        failures.append("llm_contract.default_lane must match llm_contract.lanes")
    elif default_lane in lane_by_id:
        default = lane_by_id[default_lane]
        if default.get("available") is not True:
            failures.append("llm_contract.default_lane must be available")
        if default.get("requires_user_action") is not False:
            failures.append(
                "llm_contract.default_lane must not require user action when ready"
            )
    status = str(contract.get("status", "") or "")
    if status == "api_key_encrypted" and "api-key" not in seen:
        failures.append("llm_contract.lanes must include api-key")
    elif status == "api_key_encrypted" and "api-key" in lane_by_id:
        lane = lane_by_id["api-key"]
        if lane.get("available") is not True:
            failures.append("llm_contract.lanes must mark api-key available")
        if lane.get("requires_user_action") is not False:
            failures.append(
                "llm_contract.lanes must mark api-key ready without user action"
            )
    if status == "openclaw_profile_encrypted" and "openclaw-openai" not in seen:
        failures.append("llm_contract.lanes must include openclaw-openai")
    elif status == "openclaw_profile_encrypted" and "openclaw-openai" in lane_by_id:
        lane = lane_by_id["openclaw-openai"]
        if lane.get("available") is not True:
            failures.append("llm_contract.lanes must mark openclaw-openai available")
        if lane.get("requires_user_action") is not False:
            failures.append(
                "llm_contract.lanes must mark openclaw-openai ready without user action"
            )
    return failures


def _llm_public_string_failures(
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
    if _contains_callback_url(text):
        failures.append(f"{label} contains callback URL")
    elif check_secretish and _contains_secretish_audit_text(text):
        failures.append(f"{label} contains credential-looking text")
    return failures


_MODEL_INFERENCE_KEYS = MODEL_INFERENCE_KEYS
_LLM_CONTRACT_KEYS = LLM_CONTRACT_KEYS
_LLM_CONTRACT_SECURITY_KEYS = LLM_CONTRACT_SECURITY_KEYS
_LLM_CONTRACT_LANE_KEYS = LLM_CONTRACT_LANE_KEYS


def _run_record_llm_contract_artifact_consistency_failures(
    run_record: dict[str, Any],
    llm_contract_path: Path,
) -> list[str]:
    artifact, failures = _read_run_record_standalone_json_artifact(
        llm_contract_path,
        "llm_contract.json",
        required=True,
    )
    if failures:
        return failures
    if artifact is None:
        return []
    public_safety_failures = _standalone_artifact_public_safety_failures(
        artifact,
        "llm_contract",
    )
    if public_safety_failures:
        return public_safety_failures[:20]
    run_contract = run_record.get("llm_contract", {})
    if not isinstance(run_contract, dict) or not run_contract:
        return []
    if _canonical_json_signature(_redacted_public_json(run_contract)) != (
        _canonical_json_signature(_redacted_public_json(artifact))
    ):
        return ["llm_contract in Run Record must match llm_contract.json artifact"]
    return []


def _read_run_record_standalone_json_artifact(
    path: Path,
    label: str,
    *,
    required: bool = False,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not path.exists():
        return None, [f"{label} artifact is missing"] if required else []
    if not path.is_file():
        return None, [f"{label} artifact is not a file"]
    try:
        artifact = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, [f"{label} artifact could not be read"]
    if not isinstance(artifact, dict):
        return None, [f"{label} artifact must be a JSON object"]
    return artifact, []


def _canonical_json_signature(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _redacted_public_json(value: Any) -> Any:
    if isinstance(value, str):
        return _redacted_public_text(value)
    if isinstance(value, list):
        return [_redacted_public_json(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redacted_public_json(item) for key, item in value.items()}
    return value


def _redacted_public_text(value: object) -> str:
    redacted = redact_public_text(value)
    return re.sub(r"https?://[^\s\"'<>]+", "[redacted-url]", redacted)


def _run_record_provider_strategy_consistency_failures(
    run_record: dict[str, Any],
    provider_strategies_path: Path,
) -> list[str]:
    artifact, failures = _read_run_record_standalone_json_artifact(
        provider_strategies_path,
        "provider_strategies.json",
    )
    if failures:
        return failures
    if artifact is None:
        return []
    public_safety_failures = _standalone_artifact_public_safety_failures(
        artifact,
        "provider_strategies",
    )
    if public_safety_failures:
        return public_safety_failures[:20]
    run_signature = _provider_strategy_signature(run_record.get("provider_strategies", {}))
    artifact_signature = _provider_strategy_signature(artifact)
    if not artifact_signature:
        return []
    if run_signature != artifact_signature:
        return [
            (
                "provider_strategies in Run Record must match "
                "provider_strategies.json route decisions"
            )
        ]
    return []


def _run_record_provider_playbook_consistency_failures(
    run_record: dict[str, Any],
    provider_strategies_path: Path,
) -> list[str]:
    artifact, failures = _read_run_record_standalone_json_artifact(
        provider_strategies_path,
        "provider_strategies.json",
    )
    if failures:
        return failures
    if artifact is None:
        return []
    public_safety_failures = _standalone_artifact_public_safety_failures(
        artifact,
        "provider_strategies",
    )
    if public_safety_failures:
        return public_safety_failures[:20]
    artifact_signature = _provider_playbook_signature(artifact.get("playbook", {}))
    if not artifact_signature:
        return []
    run_signature = _provider_playbook_signature(run_record.get("provider_playbook", {}))
    if run_signature != artifact_signature:
        return [("provider_playbook in Run Record must match provider_strategies.json playbook")]
    return []


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
    return _canonical_json_signature(_redacted_public_json(evidence))


def _provider_strategy_candidate_signature(candidates: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(candidates, list):
        return ()
    rows = []
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


def _run_record_verifier_consistency_failures(
    run_record: dict[str, Any],
    verification_report_path: Path,
) -> list[str]:
    artifact, failures = _read_run_record_standalone_json_artifact(
        verification_report_path,
        "verification_report.json",
    )
    if failures:
        return failures
    if artifact is None:
        return []
    public_safety_failures = _standalone_artifact_public_safety_failures(
        artifact,
        "verification_report",
    )
    if public_safety_failures:
        return public_safety_failures[:20]
    artifact_signature = _verification_report_signature(artifact)
    if not artifact_signature:
        return []
    run_signature = _run_record_verifier_signature(run_record.get("verifiers", {}))
    drift_failures: list[str] = []
    if run_signature != artifact_signature:
        drift_failures.append(
            "verifiers in Run Record must match verification_report.json provider checks"
        )
    embedded_signature = _verification_report_signature(run_record.get("verification", {}))
    if embedded_signature != artifact_signature:
        drift_failures.append(
            "verification in Run Record must match verification_report.json provider checks"
        )
    return drift_failures


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


def _run_record_detonation_consistency_failures(
    run_record: dict[str, Any],
    workspace_detonation_path: Path,
) -> list[str]:
    artifact, failures = _read_run_record_standalone_json_artifact(
        workspace_detonation_path,
        "workspace_detonation.json",
    )
    if failures:
        return failures
    if artifact is None:
        return []
    public_safety_failures = _standalone_artifact_public_safety_failures(
        artifact,
        "workspace_detonation",
    )
    if public_safety_failures:
        return public_safety_failures[:20]
    detonation = run_record.get("detonation", {})
    receipt = detonation.get("workspace_receipt", {}) if isinstance(detonation, dict) else {}
    if _detonation_receipt_signature(_redacted_public_json(receipt)) != (
        _detonation_receipt_signature(_redacted_public_json(artifact))
    ):
        return [("detonation.workspace_receipt in Run Record must match workspace_detonation.json")]
    return []


def _run_record_wake_events_consistency_failures(
    run_record: dict[str, Any],
    gate_events_path: Path,
) -> list[str]:
    run_signature = _run_record_wake_event_signature(run_record)
    if not run_signature:
        return []
    if not gate_events_path.exists():
        return ["wake_events in Run Record require gate_events.jsonl"]
    artifact_signature, error = _gate_events_jsonl_signature(gate_events_path)
    if error:
        return [error]
    if run_signature != artifact_signature:
        return ["wake_events in Run Record must match gate_events.jsonl"]
    return []


def _run_record_wake_event_signature(run_record: dict[str, Any]) -> tuple[tuple[Any, ...], ...]:
    wake_events = run_record.get("wake_events", {})
    events = wake_events.get("events", []) if isinstance(wake_events, dict) else []
    return _wake_event_signature(events)


def _gate_events_jsonl_signature(path: Path) -> tuple[tuple[tuple[Any, ...], ...], str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return (), "gate_events.jsonl could not be read for Run Record wake proof"
    events: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return (), f"gate_events.jsonl contains malformed JSONL at line {line_number}"
        if not isinstance(raw, dict):
            return (), f"gate_events.jsonl line {line_number} is not an object"
        public_safety_failures = _standalone_artifact_public_safety_failures(
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


def _wake_event_record_shape_failures(event: dict[str, Any], label: str) -> list[str]:
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
    created_at = event.get("created_at")
    if not isinstance(created_at, (int, float)) or isinstance(created_at, bool) or created_at < 0:
        failures.append(f"{label}.created_at must be a non-negative number")
    return failures


def _run_record_runner_profile_consistency_failures(
    run_record: dict[str, Any],
    runner_readiness_path: Path,
) -> list[str]:
    artifact, failures = _read_run_record_standalone_json_artifact(
        runner_readiness_path,
        "runner_readiness.json",
    )
    if failures:
        return failures
    if artifact is None:
        return []
    artifact_signature = _runner_readiness_signature(artifact)
    if not artifact_signature:
        return []
    run_signature = _runner_profile_signature(run_record.get("runner_profile", {}))
    if run_signature != artifact_signature:
        return ["runner_profile in Run Record must match runner_readiness.json"]
    return []


def _runner_readiness_signature(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return ()
    return _detonation_receipt_signature(_public_runner_readiness_summary(raw))


def _runner_profile_signature(raw: Any) -> Any:
    if not isinstance(raw, dict):
        return ()
    return _detonation_receipt_signature(_public_runner_readiness_summary(raw))


def _public_runner_readiness_summary(raw: dict[str, Any]) -> dict[str, Any]:
    profile = raw.get("profile_contract", {})
    observed = raw.get("observed", {})
    checks = raw.get("checks", {})
    installed = raw.get("installed_binaries", {})
    summary = {
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
    public = _redacted_public_json(summary)
    if not isinstance(public, dict):
        return {}
    profile = public.get("profile_contract", {})
    if isinstance(profile, dict):
        browser_stack = profile.get("browser_stack", {})
        if isinstance(browser_stack, dict):
            browser_stack["shared_provider_profile"] = _public_provider_profile_label(
                browser_stack.get("shared_provider_profile")
            )
        profile["browser_stack"] = browser_stack if isinstance(browser_stack, dict) else {}
    public["profile_contract"] = profile if isinstance(profile, dict) else {}
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


def _runner_profile_public_contract_failures(profile: dict[str, Any]) -> list[str]:
    private = dict(profile)
    browser_stack = private.get("browser_stack", {})
    if isinstance(browser_stack, dict):
        browser_stack = dict(browser_stack)
        if browser_stack.get("shared_provider_profile") == PUBLIC_PROVIDER_BROWSER_PROFILE:
            browser_stack["shared_provider_profile"] = EXPECTED_PROVIDER_BROWSER_PROFILE
        private["browser_stack"] = browser_stack
    return _runner_profile_contract_failures(private)


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


def _detonation_receipt_signature(raw: Any) -> Any:
    if isinstance(raw, dict):
        return tuple(
            sorted((str(key), _detonation_receipt_signature(value)) for key, value in raw.items())
        )
    if isinstance(raw, list):
        normalized = [_detonation_receipt_signature(item) for item in raw]
        return tuple(sorted(normalized, key=repr))
    if isinstance(raw, str | int | float | bool) or raw is None:
        return raw
    return str(raw)


def _verifier_summary_shape_failures(verifiers: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(verifiers.get("schema_version", "")).strip() != VERIFIER_SUMMARY_SCHEMA_VERSION:
        failures.append("verifiers.schema_version is unsupported")
    if verifiers.get("all_passed_or_pending_safe") is not True:
        failures.append("verifiers.all_passed_or_pending_safe must be true")
    if str(verifiers.get("overall", "")).strip() not in {"passed"}:
        failures.append("verifiers.overall must be passed")
    checks = verifiers.get("checks", [])
    actual_counts = {
        "passed": 0,
        "pending_safe": 0,
        "pending": 0,
        "repairing": 0,
        "failed": 0,
        "skipped": 0,
        "needs_human_gate": 0,
        "unknown": 0,
    }
    if not isinstance(checks, list) or not checks:
        failures.append("verifiers.checks is missing")
        checks = []
    seen_identities: set[tuple[str, str]] = set()
    for index, check in enumerate(checks):
        label = f"verifiers.checks[{index}]"
        if not isinstance(check, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(check) - _VERIFIER_SUMMARY_CHECK_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        for key in ("provider", "check", "status"):
            value = str(check.get(key, "") or "")
            if not value.strip():
                failures.append(f"{label}.{key} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        if not isinstance(check.get("pending_safe"), bool):
            failures.append(f"{label}.pending_safe must be boolean")
        identity = (
            str(check.get("provider", "") or "").strip().lower(),
            str(check.get("check", "") or "").strip().lower(),
        )
        if all(identity):
            if identity in seen_identities:
                failures.append(f"{label} duplicates verifier identity {identity[0]}.{identity[1]}")
            seen_identities.add(identity)
        status = str(check.get("status", "") or "").strip()
        if status not in {"passed", "pending_safe", "skipped"}:
            failures.append(f"{label}.status must be passed, pending_safe, or skipped")
        if status in actual_counts:
            actual_counts[status] += 1
        else:
            actual_counts["unknown"] += 1
        if status == "pending_safe" and check.get("pending_safe") is not True:
            failures.append(f"{label}.pending_safe must be true")
    counts = verifiers.get("counts", {})
    if not isinstance(counts, dict):
        failures.append("verifiers.counts is missing")
    else:
        for key in (
            "passed",
            "pending_safe",
            "pending",
            "repairing",
            "failed",
            "skipped",
            "needs_human_gate",
            "unknown",
        ):
            if not _is_plain_int(counts.get(key)):
                failures.append(f"verifiers.counts.{key} is missing")
        for key in ("pending", "repairing", "failed", "needs_human_gate", "unknown"):
            if _safe_int(counts.get(key)) != 0:
                failures.append(f"verifiers.counts.{key} must be 0")
        for key, expected in actual_counts.items():
            raw_count = counts.get(key)
            count = (
                raw_count
                if isinstance(raw_count, int) and not isinstance(raw_count, bool)
                else -1
            )
            if count != expected:
                failures.append(
                    f"verifiers.counts.{key} must match verifiers.checks: {expected}"
                )
    statement = str(verifiers.get("statement", "") or "").lower()
    if "live provider verifiers" not in statement or "green checks" not in statement:
        failures.append("verifiers.statement is missing live-verifier guidance")
    if actual_counts["skipped"] > 0 and (
        "skipped" not in statement or "do not count" not in statement
    ):
        failures.append(
            "verifiers.statement must explain skipped verifier rows do not count as proof"
        )
    return failures


_VERIFIER_SUMMARY_CHECK_KEYS = VERIFIER_SUMMARY_CHECK_KEYS


def _verifier_provider_coverage_failures(
    verifiers: dict[str, Any],
    provider_playbook: dict[str, Any],
) -> list[str]:
    checks = verifiers.get("checks", [])
    steps = provider_playbook.get("steps", [])
    if not isinstance(checks, list) or not isinstance(steps, list) or not steps:
        return []
    verifier_providers = {
        str(check.get("provider", "") or "").strip().lower()
        for check in checks
        if isinstance(check, dict) and _is_run_record_verifier_coverage_check(check)
    }
    playbook_providers = {
        str(step.get("provider", "") or "").strip().lower()
        for step in steps
        if isinstance(step, dict)
    }
    required = {
        "GitHub": RECORDING_PROVIDER_PLAYBOOK_FAMILIES["github"],
        "Resend": RECORDING_PROVIDER_PLAYBOOK_FAMILIES["resend"],
        "Vercel": RECORDING_PROVIDER_PLAYBOOK_FAMILIES["vercel"],
        "DNS/Cloudflare": RECORDING_PROVIDER_PLAYBOOK_FAMILIES["dns"],
    }
    missing = [
        label
        for label, accepted in required.items()
        if accepted & playbook_providers and not accepted & verifier_providers
    ]
    if "live_app" not in verifier_providers:
        missing.append("Live app")
    if not missing:
        return []
    return [
        "verifiers.checks missing public demo provider coverage: "
        + ", ".join(sorted(missing))
    ]


def _is_run_record_verifier_coverage_check(check: dict[str, Any]) -> bool:
    status = str(check.get("status", "") or "").strip()
    return status == "passed" or (
        status == "pending_safe" and check.get("pending_safe") is True
    )


def _audit_trail_shape_failures(
    audit_trail: dict[str, Any],
    run_record: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    wake_ids_by_name = _run_record_wake_event_ids_by_name(run_record)
    if str(audit_trail.get("schema_version", "")).strip() != AUDIT_TRAIL_SCHEMA_VERSION:
        failures.append("audit_trail.schema_version is unsupported")
    entries = audit_trail.get("entries", [])
    if not isinstance(entries, list) or not entries:
        failures.append("audit_trail.entries is missing")
        entries = []
    counts = audit_trail.get("counts", {})
    if not isinstance(counts, dict):
        failures.append("audit_trail.counts is missing")
        counts = {}
    if _safe_int(audit_trail.get("entry_count")) != len(entries):
        failures.append("audit_trail.entry_count must match entries")
    actual_counts: dict[str, int] = {}
    seen_identities: set[tuple[str, str, str, str, str, str, str, str, str]] = set()
    for index, entry in enumerate(entries):
        label = f"audit_trail.entries[{index}]"
        if not isinstance(entry, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(entry) - _AUDIT_TRAIL_ENTRY_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        identity = _audit_entry_identity(entry)
        if identity in seen_identities:
            failures.append(f"{label} duplicates audit trail proof")
        seen_identities.add(identity)
        for key in ("category", "action", "status", "source", "summary"):
            value = str(entry.get(key, "") or "")
            if not value.strip():
                failures.append(f"{label}.{key} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
        category = str(entry.get("category", "") or "")
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
        for text_field in ("summary", "action", "provider", "target", "resource"):
            value = str(entry.get(text_field, "") or "")
            if (
                text_field not in {"summary", "action"}
                and value
                and value != value.strip()
            ):
                failures.append(f"{label}.{text_field} must not have surrounding whitespace")
            if _contains_secretish_audit_text(value):
                failures.append(f"{label}.{text_field} contains credential-looking text")
        source = str(entry.get("source", "") or "").strip()
        if source == "audit.jsonl" and _safe_int(entry.get("audit_log_index")) <= 0:
            failures.append(f"{label}.audit_log_index is missing")
        if source == "setup_receipt.json" and _safe_int(entry.get("receipt_action_index")) <= 0:
            failures.append(f"{label}.receipt_action_index is missing")
        expected_wake_name = _audit_entry_expected_wake_event(entry)
        if expected_wake_name:
            wake_event_id = str(entry.get("wake_event_id", "") or "").strip()
            if not wake_event_id:
                failures.append(f"{label}.wake_event_id is missing")
            elif wake_event_id not in wake_ids_by_name.get(expected_wake_name, set()):
                failures.append(f"{label}.wake_event_id does not match wake_events")
    for category, expected in actual_counts.items():
        if _safe_int(counts.get(category)) != expected:
            failures.append(f"audit_trail.counts.{category} must match entries")
    for category in _required_audit_categories(run_record):
        if actual_counts.get(category, 0) < 1:
            failures.append(f"audit_trail must include {category}")
    required_sources = _required_audit_category_sources(run_record)
    for category, sources in sorted(required_sources.items()):
        if not _audit_category_has_source(entries, category, sources):
            source_list = ", ".join(sorted(sources))
            failures.append(f"audit_trail.{category} must include source {source_list}")
    statement = str(audit_trail.get("statement", "") or "").lower()
    for required in ("credential captures", "dns writes", "human approvals", "without storing"):
        if required not in statement:
            failures.append("audit_trail.statement is missing audit-first guidance")
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


def _run_record_wake_event_ids_by_name(
    run_record: dict[str, Any],
) -> dict[str, set[str]]:
    wake_events = run_record.get("wake_events", {})
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


def _audit_entry_expected_wake_event(entry: dict[str, Any]) -> str:
    if str(entry.get("source", "") or "") != "gate_events.jsonl":
        return ""
    action = str(entry.get("action", "") or "")
    if action == "control_room.capture_vm_clipboard":
        return "clipboard_captured"
    if action in {
        "control_room.approve_dns_apply",
        "control_room.confirm_gate_finished",
    }:
        return "resume_requested"
    return ""


_RECORDING_CONTRACT_SECTION_KEYS = RECORDING_CONTRACT_SECTION_KEYS
_RECORDING_CONTRACT_KEYS = RECORDING_CONTRACT_FIELD_KEYS
_RECORDING_CONTRACT_CHECK_KEYS = frozenset(RECORDING_CONTRACT_CHECK_KEYS)


def _recording_contract_shape_failures(
    contract: dict[str, Any],
    run_record: dict[str, Any],
    errors: Any = (),
) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(contract) - _RECORDING_CONTRACT_KEYS)
    if unexpected:
        failures.append("recording_contract has unexpected fields: " + ", ".join(unexpected))
    if str(contract.get("schema_version", "")).strip() != RECORDING_CONTRACT_SCHEMA_VERSION:
        failures.append("recording_contract.schema_version is unsupported")
    if contract.get("recording_ready") is not True:
        failures.append("recording_contract.recording_ready must be true")
    checks = contract.get("checks", {})
    if not isinstance(checks, dict):
        failures.append("recording_contract.checks is missing")
        checks = {}
    else:
        unexpected_checks = sorted(set(checks) - _RECORDING_CONTRACT_CHECK_KEYS)
        if unexpected_checks:
            failures.append(
                "recording_contract.checks has unexpected fields: "
                + ", ".join(unexpected_checks)
            )
        missing = sorted(_RECORDING_CONTRACT_CHECK_KEYS - set(checks))
        if missing:
            failures.append("recording_contract.checks missing " + ", ".join(missing))
        for key in sorted(_RECORDING_CONTRACT_CHECK_KEYS & set(checks)):
            if checks.get(key) is not True:
                failures.append(f"recording_contract.checks.{key} must be true")
            else:
                for section in _RECORDING_CONTRACT_SECTION_KEYS.get(key, ()):
                    if not _run_record_section_present(run_record.get(section)):
                        failures.append(
                            f"recording_contract.checks.{key} has no {section} proof"
                        )
    blockers = contract.get("blockers", [])
    if not isinstance(blockers, list):
        failures.append("recording_contract.blockers is missing")
        blockers = []
    else:
        failures.extend(_recording_contract_blocker_shape_failures(blockers))
        if blockers:
            failures.append(
                "recording_contract.blockers must be empty: "
                + ", ".join(str(item) for item in blockers)
            )
    if isinstance(errors, list) and errors:
        failures.append("recording_contract.checks.errors_empty must match errors")
    statement = str(contract.get("statement", "") or "").lower()
    for required in (
        "public demo",
        "worker replacement",
        "provider playbooks",
        "model inference",
        "guided human actions",
        "rehearsal review",
        "control-room",
        "detonation",
    ):
        if required not in statement:
            failures.append("recording_contract.statement is missing " + required + " guidance")
            break
    return failures


def _recording_contract_blocker_shape_failures(blockers: list[Any]) -> list[str]:
    failures: list[str] = []
    seen: set[str] = set()
    for index, blocker in enumerate(blockers):
        label = f"recording_contract.blockers[{index}]"
        if not isinstance(blocker, str):
            failures.append(f"{label} must be a string")
            continue
        if not blocker:
            failures.append(f"{label} must be non-empty")
            continue
        if blocker != blocker.strip():
            failures.append(f"{label} must not have surrounding whitespace")
        normalized = blocker.strip()
        if normalized in seen:
            failures.append(f"{label} duplicates recording contract blocker {normalized}")
        seen.add(normalized)
    return failures


def _run_record_section_present(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value)
    if isinstance(value, list):
        return bool(value)
    return False


def _acceptance_summary_shape_failures(
    summary: dict[str, Any],
    run_record: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(summary) - _ACCEPTANCE_SUMMARY_KEYS)
    if unexpected:
        failures.append(f"acceptance has unexpected fields: {', '.join(unexpected)}")
    raw_mode = summary.get("mode")
    mode = raw_mode if isinstance(raw_mode, str) else ""
    if mode not in {"live", "rehearsal"}:
        failures.append("acceptance.mode must be live or rehearsal")
    for key in ACCEPTANCE_SUMMARY_READY_FIELDS:
        if not isinstance(summary.get(key), bool):
            failures.append(f"acceptance.{key} must be boolean")
    blockers = summary.get("blockers")
    if not isinstance(blockers, list):
        failures.append("acceptance.blockers must be a list")
    else:
        failures.extend(_acceptance_blocker_shape_failures(blockers))
    missing = summary.get("missing")
    if not isinstance(missing, list):
        failures.append("acceptance.missing must be a list")
    else:
        failures.extend(_acceptance_missing_shape_failures(missing))
    if isinstance(missing, list) and isinstance(blockers, list):
        failures.extend(_acceptance_missing_blocker_consistency_failures(missing, blockers))
    error = summary.get("error")
    if not isinstance(error, str):
        failures.append("acceptance.error must be a string")
    else:
        failures.extend(_acceptance_error_shape_failures(error))
    launch_ready = summary.get("launch_ready")
    public_launch_ready = summary.get("public_launch_ready")
    remote_artifacts_ready = summary.get("remote_artifacts_ready")
    recording_proof_ready = summary.get("recording_proof_ready")
    recording_ready = summary.get("recording_ready")
    if isinstance(launch_ready, bool) and isinstance(public_launch_ready, bool):
        if public_launch_ready is not (mode == "live" and launch_ready is True):
            failures.append("acceptance.public_launch_ready must equal live launch_ready")
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
                "acceptance.recording_ready must equal public_launch_ready "
                "and remote_artifacts_ready and recording_proof_ready"
            )
    if summary.get("public_launch_ready") is True and summary.get("launch_ready") is not True:
        failures.append("acceptance.public_launch_ready must require launch_ready")
    if summary.get("public_launch_ready") is True and mode != "live":
        failures.append("acceptance.public_launch_ready must require live mode")
    if summary.get("recording_ready") is True and summary.get("public_launch_ready") is not True:
        failures.append("acceptance.recording_ready must require public_launch_ready")
    if summary.get("recording_ready") is True and summary.get("recording_proof_ready") is not True:
        failures.append("acceptance.recording_ready must require recording_proof_ready")
    if summary.get("recording_ready") is True and summary.get("remote_artifacts_ready") is not True:
        failures.append("acceptance.recording_ready must require remote_artifacts_ready")
    if summary.get("recording_ready") is True and mode != "live":
        failures.append("acceptance.recording_ready must require live mode")
    if isinstance(blockers, list) and blockers and any(
        summary.get(key) is True
        for key in ("launch_ready", "public_launch_ready", "recording_ready")
    ):
        failures.append("acceptance.blockers must be empty when readiness is true")
    if isinstance(missing, list) and missing and any(
        summary.get(key) is True
        for key in ("launch_ready", "public_launch_ready", "recording_ready")
    ):
        failures.append("acceptance.missing must be empty when readiness is true")
    if isinstance(error, str) and error.strip() and any(
        summary.get(key) is True
        for key in ("launch_ready", "public_launch_ready", "recording_ready")
    ):
        failures.append("acceptance.error must be empty when readiness is true")
    errors = run_record.get("errors", [])
    if isinstance(errors, list) and errors and any(
        summary.get(key) is True
        for key in ("launch_ready", "public_launch_ready", "recording_ready")
    ):
        failures.append("acceptance readiness must be false when errors are present")
    if summary.get("recording_ready") is True and isinstance(errors, list) and errors:
        failures.append("acceptance.recording_ready must be false when errors are present")
    recording_contract = run_record.get("recording_contract", {})
    if isinstance(recording_contract, dict) and "recording_ready" in recording_contract:
        if summary.get("recording_proof_ready") is not recording_contract.get(
            "recording_ready"
        ):
            failures.append(
                "acceptance.recording_proof_ready must match "
                "recording_contract.recording_ready"
            )
    return failures


_ACCEPTANCE_SUMMARY_KEYS = ACCEPTANCE_SUMMARY_KEYS


def _acceptance_error_shape_failures(error: str) -> list[str]:
    if not error:
        return []
    if not error.strip():
        return ["acceptance.error must be empty or non-empty text"]
    if error != error.strip():
        return ["acceptance.error must not have surrounding whitespace"]
    return []


def _acceptance_missing_shape_failures(missing: list[Any]) -> list[str]:
    failures: list[str] = []
    seen_items: set[str] = set()
    for index, item in enumerate(missing):
        label = f"acceptance.missing[{index}]"
        if not isinstance(item, str):
            failures.append("acceptance.missing must contain only strings")
            continue
        normalized = item.strip()
        if not normalized:
            failures.append(f"{label} must be non-empty")
            continue
        if item != normalized:
            failures.append(f"{label} must not have surrounding whitespace")
        if normalized in seen_items:
            failures.append(f"{label} duplicates acceptance missing proof {normalized}")
        seen_items.add(normalized)
    return failures


def _acceptance_blocker_shape_failures(blockers: list[Any]) -> list[str]:
    failures: list[str] = []
    seen_items: set[str] = set()
    for index, blocker in enumerate(blockers):
        label = f"acceptance.blockers[{index}]"
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


def _acceptance_missing_blocker_consistency_failures(
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
                f"acceptance.missing[{index}] has no matching blocker item {normalized}"
            )
    return failures


def _embedded_verification_shape_failures(verification: dict[str, Any]) -> list[str]:
    checks = verification.get("checks", [])
    if not isinstance(checks, list) or not checks:
        return ["verification.checks is missing"]
    return [
        "verification " + failure.replace("verification report ", "")
        for failure in verification_report_failures(verification)
    ]


def _run_record_error_shape_failures(errors: list[Any]) -> list[str]:
    failures: list[str] = []
    seen_error_ids: set[tuple[str, str]] = set()
    for index, error in enumerate(errors):
        label = f"errors[{index}]"
        if not isinstance(error, dict):
            failures.append(f"{label} is not an object")
            continue
        unexpected = sorted(set(error) - _RUN_RECORD_ERROR_KEYS)
        if unexpected:
            failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
        for key in RUN_RECORD_ERROR_FIELDS:
            value = str(error.get(key, "") or "")
            if not value.strip():
                failures.append(f"{label}.{key} is missing")
            elif value != value.strip():
                failures.append(f"{label}.{key} must not have surrounding whitespace")
            elif _contains_secretish_audit_text(value):
                failures.append(f"{label}.{key} contains credential-looking text")
        source = str(error.get("source", "") or "").strip()
        error_id = str(error.get("id", "") or "").strip()
        if source and error_id:
            identity = (source, error_id)
            if identity in seen_error_ids:
                failures.append(f"{label} duplicates error {source}:{error_id}")
            seen_error_ids.add(identity)
    return failures


_RUN_RECORD_ERROR_KEYS = RUN_RECORD_ERROR_KEYS


def _run_record_timeline_shape_failures(label: str, entries: list[Any]) -> list[str]:
    failures: list[str] = []
    seen_entry_ids: set[str] = set()
    for index, entry in enumerate(entries):
        entry_label = f"{label}[{index}]"
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
            if _contains_secretish_audit_text(value):
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


def _approval_summary_shape_failures(
    approvals: list[Any],
    provider_gates: dict[str, Any] | None,
    wake_events: dict[str, Any] | None,
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
        label = f"approvals[{index}]"
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
            if value and _contains_secretish_audit_text(value):
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
    if isinstance(vault, dict) and _safe_int(vault.get("record_count")) > 0:
        required.add("credential_capture")
    detonation = run_record.get("detonation", {})
    if isinstance(detonation, dict) and detonation.get("workspace_detonated") is True:
        required.add("detonation")
    verification = run_record.get("verification", {})
    checks = verification.get("checks", []) if isinstance(verification, dict) else []
    if isinstance(checks, list) and checks:
        required.add("provider_action")
    return required


def _required_audit_category_sources(run_record: dict[str, Any]) -> dict[str, set[str]]:
    """Return source artifacts required for audit categories with stronger proof."""

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
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("category", "") or "") != category:
            continue
        if str(entry.get("source", "") or "") in sources:
            return True
    return False


def _contains_secretish_audit_text(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in ("http://", "https://", "bearer ")):
        return True
    if re.search(r"\b(?:token|secret|password|private[-_ ]?key)\s*[:=]", lowered):
        return True
    if re.search(r"\b[A-Za-z0-9_-]{32,}\b", value):
        return True
    return False


def _workspace_detonation_receipt_failures(
    receipt: dict[str, Any],
    *,
    label: str = "detonation.workspace_receipt",
) -> list[str]:
    failures: list[str] = []
    failures.extend(_workspace_detonation_receipt_shape_failures(receipt, label=label))
    if str(receipt.get("status", "")).strip() != "complete":
        failures.append(f"{label}.status must be complete")
    deleted = receipt.get("deleted", [])
    required_network_resources = {
        "internet_gateway",
        "network_security_group",
        "route_table",
        "security_list",
        "subnet",
        "vcn",
    }
    deleted_set = {str(item) for item in deleted} if isinstance(deleted, list) else set()
    if not isinstance(deleted, list) or not deleted:
        failures.append(f"{label}.deleted is missing")
    else:
        if "instance" not in deleted_set:
            failures.append(f"{label}.deleted must include instance")
        if "boot_volume" not in deleted_set:
            failures.append(f"{label}.deleted must include boot volume")
        if "ephemeral_public_ip" not in deleted_set:
            failures.append(f"{label}.deleted must include ephemeral public IP")
        if required_network_resources - deleted_set:
            failures.append(f"{label}.deleted must include all network resources")
        _append_duplicate_text_failures(
            failures,
            f"{label}.deleted",
            deleted,
        )
    failures_field = receipt.get("failures")
    if not isinstance(failures_field, dict):
        failures.append(f"{label}.failures is missing")
    elif failures_field:
        failures.append(f"{label}.failures must be empty")
    if not str(receipt.get("reason", "") or "").strip():
        failures.append(f"{label}.reason is missing")
    if not isinstance(receipt.get("updated_at"), int | float) or isinstance(
        receipt.get("updated_at"), bool
    ):
        failures.append(f"{label}.updated_at is missing")
    resource_summary = receipt.get("resource_summary")
    if not isinstance(resource_summary, dict) or not resource_summary:
        failures.append(f"{label}.resource_summary is missing")
    else:
        if (
            str(resource_summary.get("schema_version", "")).strip()
            != "fusekit.workspace-detonation-resources.v1"
        ):
            failures.append(f"{label}.resource_summary.schema_version is unsupported")
        if resource_summary.get("remote_worker") is not True:
            failures.append(f"{label}.remote_worker must be true")
        failures.extend(
            _remote_worker_cleanup_receipt_failures(
                resource_summary.get("remote_worker_cleanup"),
                label=f"{label}.remote_worker_cleanup",
            )
        )
        if resource_summary.get("compute_instance") is not True:
            failures.append(f"{label}.compute_instance must be true")
        if resource_summary.get("boot_volume_deleted") is not True:
            failures.append(f"{label}.boot_volume must be deleted")
        if resource_summary.get("ephemeral_public_ip_released") is not True:
            failures.append(f"{label}.ephemeral_public_ip must be released")
        if resource_summary.get("network_resources_deleted") is not True:
            failures.append(f"{label}.network_resources must be deleted")
        if resource_summary.get("compartment_deleted") is not False:
            failures.append(f"{label}.compartment_deleted must be false")
        if str(resource_summary.get("compartment_scope", "") or "") != "preserved":
            failures.append(f"{label}.compartment_scope must be preserved")
        network_resources = resource_summary.get("network_resources", [])
        if not isinstance(network_resources, list):
            failures.append(f"{label}.resource_summary.network_resources is missing")
        elif required_network_resources - {str(item) for item in network_resources}:
            failures.append(f"{label}.resource_summary.network_resources is incomplete")
        else:
            _append_duplicate_text_failures(
                failures,
                f"{label}.resource_summary.network_resources",
                network_resources,
            )
        network_missing = resource_summary.get("network_resources_missing", [])
        if not isinstance(network_missing, list):
            failures.append(
                f"{label}.resource_summary.network_resources_missing is missing"
            )
        elif network_missing:
            failures.append(
                f"{label}.resource_summary.network_resources_missing must be empty"
            )
        missing = resource_summary.get("missing", [])
        if not isinstance(missing, list):
            failures.append(f"{label}.resource_summary.missing is missing")
        elif missing:
            failures.append(f"{label}.resource_summary.missing must be empty")
        survivors = resource_summary.get("survivors", [])
        survivor_set = {str(item) for item in survivors} if isinstance(survivors, list) else set()
        if not isinstance(survivors, list) or survivor_set != set(DETONATION_PRESERVES):
            failures.append(f"{label}.resource_summary.survivors is incomplete")
        elif survivors:
            _append_duplicate_text_failures(
                failures,
                f"{label}.resource_summary.survivors",
                survivors,
            )
        volatile_survivors = sorted(survivor_set & set(VOLATILE_WORKER_SURFACES))
        if volatile_survivors:
            failures.append(
                f"{label}.resource_summary.survivors must not include volatile worker state: "
                + ", ".join(volatile_survivors)
            )
        statement = str(resource_summary.get("statement", "") or "").lower()
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
        ):
            if required not in statement:
                failures.append(f"{label}.resource_summary.statement is incomplete")
                break
    return failures


def _workspace_detonation_receipt_shape_failures(
    receipt: dict[str, Any],
    *,
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(receipt) - WORKSPACE_DETONATION_RECEIPT_KEYS)
    if unexpected:
        failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
    for key in WORKSPACE_DETONATION_RECEIPT_TEXT_FIELDS:
        value = receipt.get(key)
        field_label = f"{label}.{key}"
        if key not in receipt:
            continue
        if not isinstance(value, str):
            failures.append(f"{field_label} must be a string")
        elif value != value.strip():
            failures.append(f"{field_label} must be trimmed")
        elif contains_durable_secret_text(value):
            failures.append(f"{field_label} contains credential-looking text")
    for key in WORKSPACE_DETONATION_RECEIPT_LIST_FIELDS:
        _append_trimmed_public_list_failures(
            failures,
            receipt.get(key, []),
            f"{label}.{key}",
        )
    resource_summary = receipt.get("resource_summary")
    if isinstance(resource_summary, dict):
        unexpected_summary = sorted(
            set(resource_summary) - WORKSPACE_DETONATION_RESOURCE_SUMMARY_KEYS
        )
        if unexpected_summary:
            failures.append(
                f"{label}.resource_summary has unexpected fields: "
                + ", ".join(unexpected_summary)
            )
        for key in WORKSPACE_DETONATION_RESOURCE_SUMMARY_TEXT_FIELDS:
            value = resource_summary.get(key)
            field_label = f"{label}.resource_summary.{key}"
            if key not in resource_summary:
                continue
            if not isinstance(value, str):
                failures.append(f"{field_label} must be a string")
            elif value != value.strip():
                failures.append(f"{field_label} must be trimmed")
            elif contains_durable_secret_text(value):
                failures.append(f"{field_label} contains credential-looking text")
        for key in WORKSPACE_DETONATION_RESOURCE_SUMMARY_LIST_FIELDS:
            _append_trimmed_public_list_failures(
                failures,
                resource_summary.get(key, []),
                f"{label}.resource_summary.{key}",
            )
        cleanup = resource_summary.get("remote_worker_cleanup")
        if isinstance(cleanup, dict):
            failures.extend(
                _remote_worker_cleanup_receipt_shape_failures(
                    cleanup,
                    label=f"{label}.remote_worker_cleanup",
                )
            )
    return failures


def _append_trimmed_public_list_failures(
    failures: list[str],
    raw: Any,
    label: str,
) -> None:
    if not isinstance(raw, list):
        return
    for index, item in enumerate(raw):
        item_label = f"{label}[{index}]"
        if not isinstance(item, str):
            failures.append(f"{item_label} must be a string")
        elif item != item.strip():
            failures.append(f"{item_label} must be trimmed")
        elif contains_durable_secret_text(item):
            failures.append(f"{item_label} contains credential-looking text")


def _remote_worker_cleanup_receipt_shape_failures(
    raw: dict[str, Any],
    *,
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(raw) - REMOTE_WORKER_CLEANUP_RECEIPT_KEYS)
    if unexpected:
        failures.append(f"{label} has unexpected fields: {', '.join(unexpected)}")
    for key in REMOTE_WORKER_CLEANUP_RECEIPT_TEXT_FIELDS:
        value = raw.get(key)
        field_label = f"{label}.{key}"
        if key not in raw:
            continue
        if not isinstance(value, str):
            failures.append(f"{field_label} must be a string")
        elif value != value.strip():
            failures.append(f"{field_label} must be trimmed")
        elif contains_durable_secret_text(value):
            failures.append(f"{field_label} contains credential-looking text")
    for key in REMOTE_WORKER_CLEANUP_RECEIPT_LIST_FIELDS:
        _append_trimmed_public_list_failures(failures, raw.get(key, []), f"{label}.{key}")
    return failures


def _remote_worker_cleanup_receipt_failures(
    raw: object,
    *,
    label: str = "detonation.workspace_receipt.remote_worker_cleanup",
) -> list[str]:
    if not isinstance(raw, dict):
        return [f"{label} is missing"]
    failures: list[str] = []
    if str(raw.get("schema_version", "") or "") != REMOTE_WORKER_CLEANUP_SCHEMA_VERSION:
        failures.append(f"{label}.schema_version is unsupported")
    if str(raw.get("status", "") or "") != "detonated":
        failures.append(f"{label}.status must be detonated")
    process_patterns = raw.get("process_patterns", [])
    if not isinstance(process_patterns, list) or set(REMOTE_WORKER_PROCESS_PATTERNS) - {
        str(item) for item in process_patterns
    }:
        failures.append(f"{label}.process_patterns is incomplete")
    else:
        _append_duplicate_text_failures(
            failures,
            f"{label}.process_patterns",
            process_patterns,
        )
    paths = raw.get("paths", [])
    if not isinstance(paths, list) or set(REMOTE_WORKER_PATH_TARGETS) - {
        str(item) for item in paths
    }:
        failures.append(f"{label}.paths is incomplete")
    else:
        _append_duplicate_text_failures(
            failures,
            f"{label}.paths",
            paths,
        )
    if raw.get("host_machine_state_required") is not False:
        failures.append(f"{label}.host_machine_state_required must be false")
    statement = str(raw.get("statement", "") or "").lower()
    if "user" not in statement or "machine" not in statement:
        failures.append(f"{label}.statement is incomplete")
    return failures


def _run_record_wake_event_failures(
    provider_gates: dict[str, Any],
    wake_events: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    records = provider_gates.get("records", [])
    events = wake_events.get("events", [])
    counts = wake_events.get("event_counts", {})
    if (
        not isinstance(records, list)
        or not isinstance(events, list)
        or not isinstance(counts, dict)
    ):
        return failures
    if _safe_int(wake_events.get("total")) != len(events):
        failures.append("wake_events.total must match wake_events.events")
    actual_counts: dict[str, int] = {}
    seen_event_ids: set[str] = set()
    seen_event_proofs: set[tuple[str, str, str]] = set()
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            continue
        label = f"wake_events.events[{index}]"
        name = str(event.get("event", "") or "")
        if name:
            actual_counts[name] = actual_counts.get(name, 0) + 1
        event_id = str(event.get("id", "") or "").strip()
        if event_id:
            if event_id in seen_event_ids:
                failures.append(f"{label}.id duplicates wake event {event_id}")
            seen_event_ids.add(event_id)
        identity = _wake_event_identity(event)
        if identity is not None:
            if identity in seen_event_proofs:
                failures.append(f"{label} duplicates wake event proof")
            seen_event_proofs.add(identity)
    for name, expected in actual_counts.items():
        if _safe_int(counts.get(name)) != expected:
            failures.append(f"wake_events.event_counts.{name} must match events")

    captured_pairs = _wake_event_pairs(events, "clipboard_captured")
    resumed_gate_ids = {
        gate_id for gate_id, _target in _wake_event_pairs(events, "resume_requested")
    }
    event_ids = _wake_event_ids(events)
    event_ids_by_name = {
        name: ids
        for name, ids in (
            ("clipboard_captured", _wake_event_ids(events, "clipboard_captured")),
            ("resume_requested", _wake_event_ids(events, "resume_requested")),
        )
    }
    for gate in records:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "") or "").strip()
        if not gate_id:
            continue
        for target in _gate_secret_targets(gate):
            if (gate_id, target) not in captured_pairs:
                failures.append(f"wake_events missing clipboard_captured for {gate_id}:{target}")
        if str(gate.get("status", "") or "") in APPROVAL_SUMMARY_READY_STATUSES:
            if gate_id not in resumed_gate_ids:
                failures.append(f"wake_events missing resume_requested for {gate_id}")
            wake_id = str(gate.get("last_wake_event_id", "") or "").strip()
            if not wake_id:
                failures.append(f"provider_gates.records[{gate_id}].last_wake_event_id is missing")
            elif wake_id not in event_ids_by_name["resume_requested"]:
                failures.append(
                    "provider_gates.records"
                    f"[{gate_id}].last_wake_event_id must match a resume_requested wake event"
                )
            if str(gate.get("last_wake_event", "") or "") != "resume_requested":
                failures.append(
                    f"provider_gates.records[{gate_id}].last_wake_event must be resume_requested"
                )
        elif gate.get("captured_targets"):
            wake_id = str(gate.get("last_wake_event_id", "") or "").strip()
            if not wake_id:
                failures.append(f"provider_gates.records[{gate_id}].last_wake_event_id is missing")
            elif wake_id not in event_ids_by_name["clipboard_captured"]:
                failures.append(
                    "provider_gates.records"
                    f"[{gate_id}].last_wake_event_id must match a clipboard_captured wake event"
                )
        wake_id = str(gate.get("last_wake_event_id", "") or "").strip()
        if wake_id and wake_id not in event_ids:
            failures.append(
                f"provider_gates.records[{gate_id}].last_wake_event_id has no wake event"
            )
    return failures


def _wake_event_identity(event: dict[str, Any]) -> tuple[str, str, str] | None:
    event_name = str(event.get("event", "") or "").strip()
    gate_id = str(event.get("gate_id", "") or "").strip()
    if not event_name or not gate_id:
        return None
    target = str(event.get("target", "") or "").strip()
    return (event_name, gate_id, target)


def _wake_event_ids(events: list[Any], event_name: str = "") -> set[str]:
    ids: set[str] = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        if event_name and str(event.get("event", "") or "") != event_name:
            continue
        event_id = str(event.get("id", "") or "").strip()
        if event_id:
            ids.add(event_id)
    return ids


def _wake_event_pairs(events: list[Any], event_name: str) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for event in events:
        if not isinstance(event, dict):
            continue
        if str(event.get("event", "") or "") != event_name:
            continue
        gate_id = str(event.get("gate_id", "") or "").strip()
        if not gate_id:
            continue
        target = str(event.get("target", "") or "").strip()
        pairs.add((gate_id, target))
    return pairs


def _require_dict_field(
    raw: dict[str, Any],
    key: str,
    failures: list[str],
    *,
    prefix: str = "",
) -> dict[str, Any] | None:
    value = raw.get(key)
    label = f"{prefix}.{key}" if prefix else key
    if not isinstance(value, dict):
        failures.append(f"{label} is missing")
        return None
    return value


def _require_list_field(
    raw: dict[str, Any],
    key: str,
    failures: list[str],
    *,
    prefix: str = "",
) -> list[Any] | None:
    value = raw.get(key)
    label = f"{prefix}.{key}" if prefix else key
    if not isinstance(value, list):
        failures.append(f"{label} is missing")
        return None
    return value


def _is_plain_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _acceptance_blockers(
    checks: list[AcceptanceCheck],
    missing: list[str],
) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in missing:
        if item in seen:
            continue
        seen.add(item)
        category, action = _missing_item_blocker_guidance(item, checks)
        blockers.append({"item": item, "category": category, "next_action": action})
    for check in checks:
        if check.status == "ok" or check.id in seen:
            continue
        if check.status == "skipped":
            continue
        item = check.id
        if item in seen:
            continue
        seen.add(item)
        category, action = _check_blocker_guidance(check)
        blockers.append(
            {
                "item": item,
                "category": category,
                "next_action": action,
                "detail": redact_public_text(check.detail),
            }
        )
    return blockers


def _redacted_blocker(blocker: dict[str, str]) -> dict[str, str]:
    """Return a public-safe launch blocker."""

    return {str(key): redact_public_text(value) for key, value in blocker.items()}


def _blocker_guidance(item: str) -> tuple[str, str]:
    guidance = {
        "encrypted vault": (
            "Vault",
            "Keep the live launcher/control room open with vault capture enabled "
            "so provider secrets enter only through VM clipboard Capture controls "
            "and FuseKit saves the encrypted vault proof.",
        ),
        "redacted setup receipt": (
            "Receipt",
            "Keep the live launcher/control room open and let the setup worker finish "
            "provider setup so FuseKit can save a redacted receipt with no raw secrets.",
        ),
        "central run record": (
            "Run record",
            "Keep the current control room open while FuseKit writes the central Run "
            "Record that ties together state, gates, provider routes, verifier checks, "
            "approvals, artifacts, errors, vault metadata, and detonation proof.",
        ),
        "safe verification report": (
            "Verification",
            "Keep the live launcher/control room open while FuseKit verifies every "
            "provider, resolves visible VM-browser gates, and marks DNS/deploy waits "
            "pending-safe only when they are safe to keep watching.",
        ),
        "complete provider verification coverage": (
            "Verification",
            "Let FuseKit verify every provider declared by the manifest before acceptance.",
        ),
        "rollback metadata": (
            "Rollback",
            "Keep the live launcher/control room open after the redacted receipt is "
            "saved so FuseKit can write provider rollback actions before launch.",
        ),
        "complete rollback coverage": (
            "Rollback",
            "Let FuseKit write rollback actions for every provider declared by the manifest.",
        ),
        "provider strategy decisions": (
            "Provider routes",
            "Keep the live launcher/control room open and let the setup worker record "
            "whether each provider uses API, vault capture, or VM follow-me controls "
            "before acceptance.",
        ),
        "complete provider strategy evidence": (
            "Provider routes",
            "Keep the live launcher/control room open while FuseKit writes the "
            "selected provider route, deterministic/implemented status, reason, "
            "and fallback candidates for every provider route.",
        ),
        "complete provider strategy coverage": (
            "Provider routes",
            "Keep the live launcher/control room open until every manifest provider "
            "has provider-route proof before acceptance.",
        ),
        "provider playbook": (
            "Provider playbook",
            "Keep the live launcher/control room open until the Provider playbook shows "
            "the ordered VM-browser actions, exact Capture controls, DNS approval, and "
            "Resend no-manual-setup safety notes.",
        ),
        "model inference": (
            "Model inference",
            "Keep the live launcher/control room open until the model/inference card "
            "shows an encrypted API-key lane or encrypted OpenClaw OpenAI authorization. "
            "Use Capture OPENAI_API_KEY from VM clipboard when the API-key lane is "
            "required, or complete the visible OpenClaw authorization gate; FuseKit "
            "writes only the non-secret llm_contract.json proof.",
        ),
        "model inference contract": (
            "Model inference",
            "Keep the live launcher/control room open until FuseKit writes "
            "llm_contract.json and the Run Record model_inference summary from an "
            "encrypted API-key lane or encrypted OpenClaw OpenAI authorization.",
        ),
        "provider route recovery checkpoints": (
            "Provider routes",
            "Keep the live launcher/control room open until provider-route cards show "
            "the next action and resume hint, including Resend API setup, downstream "
            "Vercel env wiring, and DNS approval with the complete generated record "
            "set. If this report came from an older artifact set, keep this live "
            "control room open while FuseKit rebuilds the provider-route proof.",
        ),
        "Resend-before-DNS provider setup order": (
            "Provider order",
            "Capture RESEND_API_KEY first, then let FuseKit create or reuse the "
            "Resend domain by API before you approve DNS apply.",
        ),
        "Resend DNS records in receipt DNS proposal": (
            "Provider order",
            "Capture RESEND_API_KEY first, let FuseKit create or reuse the Resend "
            "sending domain by API, then approve DNS apply only after Cloudflare/DNS "
            "shows the exact Resend verification records.",
        ),
        "DNS apply approval audit proof": (
            "DNS approval",
            "Use the visible Approve DNS apply control in the launcher before DNS records "
            "are applied.",
        ),
        "Resend runtime env in Vercel receipt": (
            "Deployment env",
            "Capture RESEND_API_KEY in the launcher; FuseKit must then create or reuse "
            "Resend domain/audience values by API and record every app-required RESEND_* "
            "runtime key in Vercel env setup.",
        ),
        "provider contract-health receipt proof": (
            "Provider routes",
            "Let the setup worker run each API-backed provider route again so it "
            "records a read-only provider health check before mutation; if a token "
            "gate appears, use the exact env-named Capture button.",
        ),
        "guided human gates": (
            "Human gates",
            "Keep the live launcher/control room open while FuseKit rebuilds each "
            "gate card with follow-me steps, next action, and resume hint.",
        ),
        "safe gate state": (
            "Human gates",
            "Keep the live launcher/control room open while FuseKit rewrites durable "
            "gate and wake proof without callback URLs, token-shaped text, or raw "
            "provider return data.",
        ),
        "audited human gate interventions": (
            "Human gates",
            "Use the visible launcher controls for each gate: Open provider gate "
            "in VM, exact env-named Capture buttons for copy-once values, or "
            "I finished this step after a non-secret provider confirmation.",
        ),
        "resolved human gates": (
            "Human gates",
            "Finish or repair every waiting/resurfaced/retrying control-room gate "
            "before acceptance.",
        ),
        "validated provider capability packs": (
            "Provider packs",
            "Keep the live launcher/control room open while FuseKit loads and "
            "validates provider capability packs for the services in the manifest.",
        ),
        "safe visual session state": (
            "Visual session",
            "Keep the live launcher/control room open while FuseKit refreshes visual "
            "session metadata with only safe noVNC/control-room URLs and safe noVNC "
            "password metadata.",
        ),
        "prepared runner readiness proof": (
            "Runner readiness",
            "Keep the live launcher/control room open while FuseKit verifies the OCI "
            "visual runner: x86_64 architecture, OpenClaw, Playwright Chromium, noVNC, "
            "shared provider browser profile, helper binaries, and encrypted vault "
            "access must be proven before provider gates continue.",
        ),
        "verified live URL": (
            "Deployment",
            "Verify the deployed live URL and write it into the redacted setup receipt.",
        ),
        "clean leak scan": (
            "Security",
            "Keep the launcher/control room open while FuseKit runs the leak scan; "
            "if it flags plaintext setup secrets, move them out of app files and "
            "back into vault Capture/provider secret storage.",
        ),
        "detonated worker state": (
            "Detonation",
            "Keep the launcher/control room open while FuseKit detonates plaintext "
            "worker, browser, visual, provider-auth, control-room, and gateway "
            "scratch state after encrypted artifacts are preserved.",
        ),
        "OCI workspace detonation receipt": (
            "Detonation",
            "Keep the launcher/control room open until FuseKit writes the OCI "
            "workspace detonation receipt proving the VM, boot volume, ephemeral "
            "public IP, network resources, and remote worker cleanup were destroyed.",
        ),
    }
    return guidance.get(
        item,
        ("Launch evidence", _unknown_launch_evidence_action(item)),
    )


def _missing_item_blocker_guidance(
    item: str,
    checks: list[AcceptanceCheck],
) -> tuple[str, str]:
    check_id_by_missing_item = {
        "audited human gate interventions": "gates.audited",
    }
    check_id = check_id_by_missing_item.get(item)
    if check_id:
        for check in checks:
            if check.id == check_id and check.status not in {"ok", "skipped"}:
                return _check_blocker_guidance(check)
    return _blocker_guidance(item)


def _check_blocker_guidance(check: AcceptanceCheck) -> tuple[str, str]:
    if check.id == "remote_artifacts.loaded":
        return (
            "Remote artifacts",
            "Keep the live launcher/control room open while FuseKit retrieves the "
            "complete OCI artifact bundle before detonation; missing survivor files "
            "mean the run cannot be recorded or trusted for public launch.",
        )
    if check.id.startswith("gates."):
        detail = check.detail.lower()
        if check.id == "gates.guided":
            if "api-generated resend values" in detail:
                return (
                    "Human gates",
                    "Keep the live launcher/control room open while FuseKit rebuilds "
                    "the Resend runtime gate so Capture is used only for RESEND_API_KEY; "
                    "generated sender and audience values must use Resend API setup retry.",
                )
            if "manual resend domain/audience setup" in detail:
                return (
                    "Human gates",
                    "Keep the live launcher/control room open while FuseKit rebuilds the "
                    "Resend gate so the user captures only the setup key; FuseKit must "
                    "create or reuse domains and audiences through Resend API.",
                )
            if (
                "resend setup-key selectors" in detail
                or "existing resend key rows are not enough" in detail
            ):
                return (
                    "Human gates",
                    "Keep the live launcher/control room open while FuseKit rebuilds the "
                    "Resend API-key gate so it opens API Keys, names Permission: Full "
                    "access and Domain: All domains, explains existing key rows are not "
                    "enough without the raw key value, and shows Capture RESEND_API_KEY "
                    "from VM clipboard.",
                )
            if "missing resume_url" in detail:
                return (
                    "Human gates",
                    "Keep the live launcher/control room open while FuseKit rebuilds the "
                    "provider gate with an Open provider gate in VM URL.",
                )
            if "non-launcher wording" in detail:
                return (
                    "Human gates",
                    "Keep the live launcher/control room open while FuseKit rebuilds gate "
                    "guidance so it names only visible launcher controls.",
                )
            if "exact capture controls" in detail:
                exact_controls = _capture_controls_from_text(check.detail)
                if exact_controls:
                    return (
                        "Human gates",
                        "Keep the live launcher/control room open while FuseKit rebuilds "
                        "copy-once secret gates so they name the exact "
                        + ", ".join(exact_controls)
                        + " control.",
                    )
            if "capture from vm clipboard" in detail:
                exact_controls = _capture_controls_from_text(check.detail)
                if exact_controls:
                    return (
                        "Human gates",
                        "Keep the live launcher/control room open while FuseKit rebuilds "
                        "copy-once secret gates so they name the exact "
                        + ", ".join(exact_controls)
                        + " control.",
                    )
                return (
                    "Human gates",
                    "Keep the live launcher/control room open while FuseKit rebuilds "
                    "copy-once secret gates so they name an exact env-named Capture "
                    "button such as Capture RESEND_API_KEY from VM clipboard.",
                )
            if "vm browser path" in detail:
                return (
                    "Human gates",
                    "Keep the live launcher/control room open while FuseKit rebuilds "
                    "provider gates so follow-me steps name the VM browser path.",
                )
        if check.id == "gates.audited":
            if "control_room.gate_open" in detail:
                return (
                    "Human gates",
                    "Open each provider gate through Open provider gate in VM so "
                    "FuseKit can audit it.",
                )
            if "control_room.clipboard_capture" in detail:
                exact_controls = _capture_controls_from_text(check.detail)
                if exact_controls:
                    return (
                        "Human gates",
                        "Copy the provider token in the VM browser, then click "
                        + ", ".join(exact_controls)
                        + ".",
                    )
                return (
                    "Human gates",
                    "Copy the provider token in the VM browser, then click the "
                    "exact env-named Capture button shown for that value, such as "
                    "Capture RESEND_API_KEY from VM clipboard.",
                )
            if "control_room.gate_resume_requested" in detail:
                return (
                    "Human gates",
                    "After the provider confirms the step, click the visible I finished "
                    "this step or approval button.",
                )
            if "missing gate events" in detail:
                return (
                    "Human gates",
                    "Use the visible launcher controls for each gate: Open provider gate "
                    "in VM, exact env-named Capture buttons for copy-once values, or "
                    "I finished this step after a non-secret provider confirmation.",
                )
        if check.id == "gates.resolved":
            exact_controls = _capture_controls_from_text(check.detail)
            if exact_controls:
                return (
                    "Human gates",
                    "Finish the visible VM-browser gate, then click "
                    + ", ".join(exact_controls)
                    + ".",
                )
            return (
                "Human gates",
                "Finish the visible VM-browser gate, then use the exact env-named "
                "Capture button shown on the active launcher gate, or the "
                "I finished this step button.",
            )
        return (
            "Human gates",
            "Keep the live launcher/control room open while FuseKit rebuilds the gate "
            "so it shows Open provider gate in VM, an exact env-named Capture button "
            "for copy-once values, or I finished this step as the next visible action.",
        )
    if check.id == "provider_strategies.order":
        return (
            "Provider order",
            "Capture RESEND_API_KEY first, then let FuseKit create or reuse the "
            "Resend domain by API before you approve DNS apply.",
        )
    if check.id.startswith("provider_strategies."):
        if check.id == "provider_strategies.playbook":
            return (
                "Provider playbook",
                "Keep the live launcher/control room open until the Provider playbook "
                "shows the ordered VM-browser actions, exact Capture controls, DNS "
                "approval, and Resend no-manual-setup safety notes.",
            )
        if check.id == "provider_strategies.checkpoints":
            return (
                "Provider routes",
                "Keep the live launcher/control room open until each provider-route card "
                "shows a selected route, next action, and resume hint, including Resend "
                "API setup, downstream Vercel env wiring, and DNS approval with the "
                "complete generated record set.",
            )
        if "resend.strategies" in check.detail.lower() and "evidence" in check.detail.lower():
            return (
                "Provider routes",
                (
                    "Capture RESEND_API_KEY, then let FuseKit record that it owns "
                    "Resend domain/audience API setup after key capture."
                ),
            )
        return (
            "Provider routes",
            "Keep the live launcher/control room open and let the setup worker record "
            "provider route decisions in the correct order.",
        )
    if check.id == "provider_packs.validated" or check.id.startswith("provider_pack."):
        return (
            "Provider packs",
            "Keep the live launcher/control room open while FuseKit loads and "
            "validates provider capability packs for the services in the manifest "
            "before provider setup, route planning, or verification continues.",
        )
    if check.id.startswith("manifest."):
        return (
            "Manifest",
            "Keep the launcher/control room open while FuseKit rescans the app, "
            "loads `fusekit.yaml`, and snapshots the setup manifest before "
            "provider planning continues.",
        )
    if check.id == "plan.generated":
        return (
            "Setup plan",
            "Keep the launcher/control room open while FuseKit rebuilds the setup "
            "plan from the current manifest and waits for the visible Approve setup "
            "plan control before provider mutations continue.",
        )
    if check.id == "run_record.complete":
        detail = check.detail.lower()
        if "model_inference" in detail or "llm_contract" in detail:
            return (
                "Model inference",
                "Keep the live launcher/control room open until the model/inference "
                "card shows an encrypted API-key lane or encrypted OpenClaw OpenAI "
                "authorization. Use Capture OPENAI_API_KEY from VM clipboard when "
                "the API-key lane is required, or complete the visible OpenClaw "
                "authorization gate; FuseKit writes only the non-secret "
                "llm_contract.json proof.",
            )
        if "rehearsal_review" in detail:
            return (
                "Rehearsal review",
                "Keep the live launcher/control room open while FuseKit writes a "
                "clean rehearsal review: every human action must match visible "
                "control-room instructions, with no host browser, terminal, side "
                "channel, or user interpretation.",
            )
        if "worker_replacement" in detail:
            return (
                "Worker replacement",
                "Keep the live launcher/control room open while FuseKit runs the "
                "worker replacement drill: destroy the original OCI worker, restore "
                "only encrypted/redacted durable sources onto a replacement runner, "
                "reopen the control room, and resume a gate or verifier without "
                "host-machine state.",
            )
        return (
            "Run record",
            "Keep the current control room open while FuseKit rebuilds the central "
            "Run Record from the latest job state, gates, provider routes, verifier "
            "checks, approvals, artifacts, errors, vault metadata, and detonation proof.",
        )
    if check.id.startswith("verification_report."):
        return (
            "Verification",
            "Keep the live launcher/control room open while FuseKit verifies every "
            "provider, resolves visible VM-browser gates, and keeps only safe pending "
            "DNS/deploy waits.",
        )
    if check.id.startswith("rollback_metadata."):
        return (
            "Rollback",
            "Keep the live launcher/control room open after the redacted receipt is "
            "saved so FuseKit writes provider rollback actions for every provider "
            "declared by the manifest before launch.",
        )
    if check.id.startswith("audit."):
        return (
            "Audit log",
            "Keep the live launcher/control room open while FuseKit writes the "
            "redacted JSONL audit log for vault captures, provider actions, "
            "approvals, verifier checks, and detonation without raw secrets.",
        )
    if check.id.startswith("vault."):
        return (
            "Vault",
            "Keep the live launcher/control room open with vault capture enabled; "
            "use the visible VM clipboard Capture controls for provider secrets so "
            "FuseKit can save and unlock encrypted vault proof.",
        )
    if check.id.startswith("receipt."):
        if check.id == "receipt.resend_dns_flow":
            return (
                "Provider order",
                "Capture RESEND_API_KEY first, let FuseKit create or reuse the Resend "
                "sending domain by API, then approve the DNS apply gate when it shows "
                "the exact Resend verification records.",
            )
        if check.id == "receipt.dns_apply_approval":
            return (
                "DNS approval",
                "Reopen the DNS approval gate in the launcher and click the visible "
                "Approve DNS apply control before FuseKit applies DNS records.",
            )
        if check.id == "receipt.resend_vercel_env":
            return (
                "Deployment env",
                "Capture RESEND_API_KEY in the launcher; FuseKit must then create or reuse "
                "Resend domain/audience values by API before Vercel env setup runs.",
            )
        if check.id == "receipt.provider_contract_health":
            return (
                "Provider routes",
                "Let the setup worker rerun the API-backed route so it proves a "
                "read-only provider health check before mutation; if the token is "
                "expired or scoped wrong, use the exact env-named Capture button.",
            )
        return (
            "Receipt",
            "Keep the live launcher/control room open and let the setup worker finish "
            "provider setup so FuseKit can save a redacted receipt with no raw secrets.",
        )
    if check.id == "detonation.worker_state":
        return (
            "Detonation",
            "Keep the launcher/control room open while FuseKit detonates plaintext "
            "worker, browser, visual, provider-auth, control-room, and gateway "
            "scratch state after encrypted artifacts are preserved.",
        )
    if check.id == "detonation.workspace_receipt":
        return (
            "Workspace detonation",
            "Keep the launcher/control room open until FuseKit writes the OCI "
            "workspace detonation receipt proving the VM, boot volume, ephemeral "
            "public IP, network resources, and remote worker cleanup were destroyed.",
        )
    if check.id == "runner_readiness.prepared":
        return (
            "Runner readiness",
            "Keep the live launcher/control room open while FuseKit verifies the OCI "
            "visual runner: x86_64 architecture, OpenClaw, Playwright Chromium, noVNC, "
            "shared provider browser profile, helper binaries, and encrypted vault "
            "access must be proven before provider gates continue.",
        )
    if check.id == "visual_state.safe":
        return (
            "Visual session",
            "Keep the live launcher/control room open while FuseKit refreshes visual "
            "session metadata with only safe noVNC/control-room URLs and safe noVNC "
            "password metadata.",
        )
    if check.id == "leak_scan.clean":
        return (
            "Security",
            "Keep the launcher/control room open while FuseKit runs the leak scan; "
            "if it flags plaintext setup secrets, move them out of app files and "
            "back into vault Capture/provider secret storage.",
        )
    return ("Launch evidence", _unknown_launch_evidence_action(check.id))


def _unknown_launch_evidence_action(item: str) -> str:
    """Return a launcher-first recovery action for unfamiliar acceptance blockers."""

    return (
        f"Keep the control room open while FuseKit regenerates launch evidence for {item}. "
        "Follow the single highlighted next action on the matching launcher card; FuseKit "
        "will name the exact Open provider gate in VM, env-named Capture button, "
        "I finished this step, Approve setup plan, or Approve DNS apply control when "
        "one is required. If no specific control appears, keep this live control room "
        "open while FuseKit rebuilds this proof artifact."
    )


def _capture_controls_from_text(value: str) -> list[str]:
    targets = _copy_once_targets_mentioned(value)
    if not targets:
        targets = _env_targets_from_text(value)
    return [f"Capture {target} from VM clipboard" for target in targets]


def _load_or_scan_manifest(
    app_path: Path,
    manifest_path: Path,
    checks: list[AcceptanceCheck],
    ledger: HarnessLedger,
) -> SetupManifest:
    if manifest_path.exists():
        manifest = load_manifest(manifest_path)
        checks.append(AcceptanceCheck("manifest.loaded", "ok", "Existing setup manifest loaded."))
    else:
        manifest = scan_repo(app_path)
        write_manifest(manifest, manifest_path)
        checks.append(
            AcceptanceCheck("manifest.scanned", "ok", "App scanned and setup manifest written.")
        )
    manifest_snapshot = ledger.snapshot_json("manifest", manifest.to_dict())
    checks.append(
        AcceptanceCheck(
            "manifest.snapshotted",
            "ok",
            "Manifest snapshot recorded.",
            str(manifest_snapshot),
        )
    )
    return manifest


def _ensure_acceptance_packs(
    app_path: Path,
    manifest: SetupManifest,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> list[Path]:
    providers = {service.provider.lower() for service in manifest.services}
    if manifest.domains:
        providers.add("cloudflare")
    pack_paths: list[Path] = []
    for provider in sorted(providers):
        pack_path = pack_default_path(app_path, provider)
        if not pack_path.exists():
            pack = synthesize_provider_pack(provider, app_path)
            write_provider_pack(pack, pack_path)
        try:
            pack = load_provider_pack(pack_path)
            validate_provider_pack(pack)
        except ProviderError as exc:
            checks.append(
                AcceptanceCheck(
                    f"provider_pack.{provider}",
                    "failed",
                    "Provider capability pack could not be validated: " + str(exc),
                )
            )
            missing.append("validated provider capability packs")
            continue
        pack_payload = pack.to_dict()
        pack_snapshot = ledger.snapshot_json(f"provider-pack-{provider}", pack_payload)
        public_safety_failures = _standalone_artifact_public_safety_failures(
            pack_payload,
            f"provider_pack.{provider}",
        )
        if public_safety_failures:
            checks.append(
                AcceptanceCheck(
                    f"provider_pack.{provider}",
                    "failed",
                    "Provider capability pack contains unsafe public text: "
                    + "; ".join(public_safety_failures[:20]),
                    str(pack_snapshot),
                )
            )
            missing.append("validated provider capability packs")
            continue
        checks.append(
            AcceptanceCheck(
                f"provider_pack.{provider}",
                "ok",
                "Provider capability pack validated and snapshotted.",
                str(pack_snapshot),
            )
        )
        pack_paths.append(pack_path)
    return pack_paths


def _check_vault(
    vault_path: Path,
    passphrase: str | None,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not vault_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(AcceptanceCheck("vault.exists", status, f"Vault not found: {vault_path}"))
        if mode == "live":
            missing.append("encrypted vault")
        return
    try:
        text = vault_path.read_text(encoding="utf-8")
    except OSError:
        checks.append(
            AcceptanceCheck(
                "vault.ciphertext_only",
                "failed",
                "Vault bundle could not be read.",
            )
        )
        missing.append("ciphertext-only vault")
        return
    if _vault_plaintext_marker_found(text):
        checks.append(
            AcceptanceCheck(
                "vault.ciphertext_only",
                "failed",
                "Vault contains plaintext or credential-looking markers.",
            )
        )
        missing.append("ciphertext-only vault")
        return
    else:
        checks.append(
            AcceptanceCheck(
                "vault.ciphertext_only",
                "ok",
                "Vault has no obvious plaintext markers.",
            )
        )
    if passphrase is None:
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "vault.unlock",
                status,
                "Passphrase not supplied for vault unlock proof.",
            )
        )
        if mode == "live":
            missing.append("vault unlock proof")
        return
    try:
        vault = Vault.open(vault_path, passphrase)
    except VaultError:
        checks.append(
            AcceptanceCheck(
                "vault.unlock",
                "failed",
                "Vault could not be unlocked with the supplied passphrase.",
            )
        )
        if mode == "live":
            missing.append("vault unlock proof")
        return
    index = vault.public_index()
    snapshot = ledger.snapshot_json("vault-public-index", {"records": index})
    checks.append(
        AcceptanceCheck(
            "vault.unlock",
            "ok",
            "Vault unlock proof succeeded.",
            str(snapshot),
        )
    )
    wrong_passphrase = passphrase + "\n-fusekit-wrong-passphrase-proof"
    try:
        Vault.open(vault_path, wrong_passphrase)
    except VaultError:
        checks.append(
            AcceptanceCheck(
                "vault.wrong_passphrase",
                "ok",
                "Wrong-passphrase proof failed as expected.",
            )
        )
    else:
        checks.append(
            AcceptanceCheck(
                "vault.wrong_passphrase",
                "failed",
                "Vault opened with an incorrect passphrase.",
            )
        )
        missing.append("wrong-passphrase rejection")


def _vault_plaintext_marker_found(text: str) -> bool:
    markers = (
        "WEBHOOK_SECRET",
        "BEGIN PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
    )
    return any(marker in text for marker in markers) or contains_durable_secret_text(text)


def _check_receipt(
    receipt_path: Path,
    manifest: SetupManifest,
    mode: str,
    audit_log_path: Path,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not receipt_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck("receipt.exists", status, f"Receipt not found: {receipt_path}")
        )
        if mode == "live":
            missing.append("redacted setup receipt")
        return
    raw = json.loads(receipt_path.read_text(encoding="utf-8"))
    snapshot = ledger.snapshot_json("setup-receipt", raw)
    secret_failures = [
        *_setup_receipt_shape_failures(raw),
        *_standalone_artifact_public_safety_failures(raw, "setup_receipt"),
    ]
    if secret_failures:
        checks.append(
            AcceptanceCheck(
                "receipt.redacted",
                "failed",
                "; ".join(secret_failures[:20]),
                str(snapshot),
            )
        )
        missing.append("redacted receipt")
        return
    raw_secret_count = raw.get(SETUP_RECEIPT_RAW_SECRET_COUNT_FIELD, 0)
    if not _is_plain_int(raw_secret_count) or raw_secret_count != 0:
        checks.append(
            AcceptanceCheck(
                "receipt.redacted",
                "failed",
                "Receipt raw secret exposure count must be literal zero.",
            )
        )
        missing.append("redacted receipt")
    else:
        checks.append(
            AcceptanceCheck(
                "receipt.redacted",
                "ok",
                "Receipt reports zero raw secrets.",
                str(snapshot),
            )
        )
    live_url = str(raw.get("live_url", ""))
    if mode == "live" and not live_url:
        checks.append(
            AcceptanceCheck(
                "receipt.live_url",
                "missing",
                "Live launch requires a verified live URL.",
            )
        )
        missing.append("verified live URL")
    elif live_url:
        checks.append(
            AcceptanceCheck(
                "receipt.live_url",
                "ok",
                f"Receipt includes live URL: {live_url}",
            )
        )
    _check_receipt_resend_dns_flow(raw, manifest, mode, checks, missing, str(snapshot))
    _check_receipt_dns_apply_approval(raw, mode, audit_log_path, checks, missing, str(snapshot))
    _check_receipt_resend_vercel_env_flow(raw, manifest, mode, checks, missing, str(snapshot))
    _check_receipt_provider_contract_health(raw, mode, checks, missing, str(snapshot))


def _check_receipt_dns_apply_approval(
    raw: Any,
    mode: str,
    audit_log_path: Path,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Prove live DNS mutation had explicit protected launcher approval."""

    if mode != "live":
        return
    actions = raw.get("actions", []) if isinstance(raw, dict) else []
    if not isinstance(actions, list):
        return
    apply_actions = [
        action
        for action in actions
        if isinstance(action, dict)
        and str(action.get("action", "")).strip() == "dns.apply"
        and str(action.get("status", "")).strip() == "ok"
    ]
    if not apply_actions:
        return
    applied_domains = sorted(
        {
            str(action.get("details", {}).get("domain", "")).strip()
            for action in apply_actions
            if isinstance(action.get("details", {}), dict)
        }
    )
    applied_domains = [domain for domain in applied_domains if domain]
    if not applied_domains:
        _fail_dns_apply_approval(
            checks,
            missing,
            "Receipt contains successful dns.apply without a domain.",
            artifact,
        )
        return
    audit_events, audit_error = _control_room_audit_events(audit_log_path)
    if audit_error:
        _fail_dns_apply_approval(checks, missing, audit_error, artifact)
        return
    approved_domains = _dns_apply_approval_domains(audit_events)
    missing_domains = sorted(
        domain for domain in applied_domains if domain.lower() not in approved_domains
    )
    if missing_domains:
        _fail_dns_apply_approval(
            checks,
            missing,
            "Receipt applied DNS changes without protected per-domain Approve DNS apply "
            "audit proof for: " + ", ".join(missing_domains),
            artifact,
        )
        return
    checks.append(
        AcceptanceCheck(
            "receipt.dns_apply_approval",
            "ok",
            "Receipt DNS apply is backed by protected Approve DNS apply audit proof.",
            artifact,
        )
    )


def _fail_dns_apply_approval(
    checks: list[AcceptanceCheck],
    missing: list[str],
    detail: str,
    artifact: str,
) -> None:
    checks.append(
        AcceptanceCheck(
            "receipt.dns_apply_approval",
            "failed",
            detail,
            artifact,
        )
    )
    missing.append("DNS apply approval audit proof")


def _check_receipt_provider_contract_health(
    raw: Any,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Prove token-backed provider setup ran read-only API preflight first."""

    if mode != "live":
        return
    actions = raw.get("actions", []) if isinstance(raw, dict) else []
    if not isinstance(actions, list):
        checks.append(
            AcceptanceCheck(
                "receipt.provider_contract_health",
                "failed",
                "Receipt actions are missing or malformed.",
                artifact,
            )
        )
        missing.append("provider contract-health receipt proof")
        return
    required = _providers_requiring_contract_health(actions)
    if not required:
        return
    ok_before_setup = _contract_health_ok_before_provider_setup(actions)
    missing_proof = sorted(required - ok_before_setup)
    if missing_proof:
        checks.append(
            AcceptanceCheck(
                "receipt.provider_contract_health",
                "failed",
                "Receipt is missing provider API contract-health proof before setup for: "
                + ", ".join(missing_proof),
                artifact,
            )
        )
        missing.append("provider contract-health receipt proof")
        return
    checks.append(
        AcceptanceCheck(
            "receipt.provider_contract_health",
            "ok",
            "Receipt proves provider API contract health before token-backed setup.",
            artifact,
        )
    )


def _providers_requiring_contract_health(actions: list[Any]) -> set[str]:
    providers: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        if str(action.get("action", "")) != "provider_pack.setup":
            continue
        if str(action.get("status", "")) != "ok":
            continue
        details = action.get("details", {})
        if not isinstance(details, dict):
            continue
        provider = str(details.get("provider", "")).strip().lower()
        setup = details.get("setup", [])
        if not provider or not isinstance(setup, list):
            continue
        if any(_setup_item_used_successful_api(item) for item in setup):
            providers.add(provider)
    return providers


def _setup_item_used_successful_api(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    if str(item.get("status", "")).strip() != "ok":
        return False
    decision = item.get("strategy_decision", {})
    if not isinstance(decision, dict):
        return False
    selected = decision.get("selected", {})
    if not isinstance(selected, dict):
        return False
    return str(selected.get("kind", "")).strip() == "api"


def _contract_health_ok_before_provider_setup(actions: list[Any]) -> set[str]:
    ok: set[str] = set()
    proven: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        name = str(action.get("action", "")).strip()
        status = str(action.get("status", "")).strip()
        if name.endswith(".contract_health") and status == "ok":
            provider = name[: -len(".contract_health")].strip().lower()
            if provider:
                ok.add(provider)
            continue
        if name == "provider_pack.setup" and status == "ok":
            details = action.get("details", {})
            provider = (
                str(details.get("provider", "")).strip().lower()
                if isinstance(details, dict)
                else ""
            )
            if provider in ok:
                proven.add(provider)
    return proven


def _check_receipt_resend_dns_flow(
    raw: Any,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Prove Resend-generated domain DNS reached the DNS proposal in live evidence."""

    if mode != "live" or not _manifest_requires_resend_dns(manifest):
        return
    actions = raw.get("actions", []) if isinstance(raw, dict) else []
    if not isinstance(actions, list):
        _fail_resend_dns_receipt(
            checks,
            missing,
            "Receipt actions are missing or malformed.",
            artifact,
        )
        return
    resend_index = _first_receipt_action(actions, "resend.domain", status="ok")
    if resend_index is None:
        _fail_resend_dns_receipt(
            checks,
            missing,
            "Receipt must include a successful resend.domain action.",
            artifact,
        )
        return
    contract_failure = _resend_receipt_domain_contract_failure(actions[resend_index])
    if contract_failure:
        _fail_resend_dns_receipt(
            checks,
            missing,
            contract_failure,
            artifact,
        )
        return
    resend_domain = _receipt_action_domain(actions[resend_index])
    manifest_domains = _manifest_domain_names(manifest)
    if manifest_domains and resend_domain not in manifest_domains:
        _fail_resend_dns_receipt(
            checks,
            missing,
            "Receipt resend.domain must target a manifest domain before DNS proposal.",
            artifact,
        )
        return
    dns_index = _first_dns_proposal_for_domain(actions, resend_domain, status="ok")
    if dns_index is None:
        _fail_resend_dns_receipt(
            checks,
            missing,
            f"Receipt must include a successful dns.propose action for {resend_domain}.",
            artifact,
        )
        return
    if resend_index > dns_index:
        _fail_resend_dns_receipt(
            checks,
            missing,
            "Receipt put DNS proposal for the Resend domain before Resend domain setup.",
            artifact,
        )
        return
    resend_records = _resend_receipt_dns_records(actions[resend_index])
    dns_records = _dns_proposal_receipt_records(actions[dns_index])
    if not resend_records:
        _fail_resend_dns_receipt(
            checks,
            missing,
            "Receipt does not include Resend-generated DNS records.",
            artifact,
        )
        return
    missing_records = sorted(resend_records - dns_records)
    if missing_records:
        _fail_resend_dns_receipt(
            checks,
            missing,
            "Receipt DNS proposal is missing Resend-generated records: "
            + ", ".join(f"{kind} {name}" for kind, name, _value in missing_records),
            artifact,
        )
        return
    checks.append(
        AcceptanceCheck(
            "receipt.resend_dns_flow",
            "ok",
            "Receipt proves Resend domain setup emitted DNS records before DNS proposal "
            f"for {resend_domain} with a deterministic sending-domain contract.",
            artifact,
        )
    )


def _manifest_requires_resend_dns(manifest: SetupManifest) -> bool:
    providers = _manifest_provider_names(manifest)
    return "resend" in providers and bool(manifest.domains)


def _fail_resend_dns_receipt(
    checks: list[AcceptanceCheck],
    missing: list[str],
    detail: str,
    artifact: str,
) -> None:
    checks.append(
        AcceptanceCheck(
            "receipt.resend_dns_flow",
            "failed",
            detail,
            artifact,
        )
    )
    missing.append("Resend DNS records in receipt DNS proposal")


def _resend_receipt_domain_contract_failure(action: dict[str, Any]) -> str:
    details = action.get("details", {})
    if not isinstance(details, dict):
        return "Receipt resend.domain details are missing or malformed."
    domain = _receipt_action_domain(action)
    if not domain:
        return "Receipt resend.domain is missing the Resend domain name."
    domain_id = str(details.get("domain_id", "") or "").strip()
    if not domain_id:
        return "Receipt resend.domain is missing the Resend domain id."
    region = str(details.get("region", "") or "").strip().lower()
    if region not in RESEND_ALLOWED_REGIONS:
        allowed = ", ".join(sorted(RESEND_ALLOWED_REGIONS))
        return f"Receipt resend.domain is missing a supported Resend region ({allowed})."
    requested_region = str(details.get("requested_region", "") or "").strip().lower()
    if requested_region and requested_region not in RESEND_ALLOWED_REGIONS:
        allowed = ", ".join(sorted(RESEND_ALLOWED_REGIONS))
        return f"Receipt resend.domain has an unsupported requested Resend region ({allowed})."
    capabilities = details.get("capabilities", {})
    if not isinstance(capabilities, dict):
        return "Receipt resend.domain is missing sending-only capability details."
    sending = str(capabilities.get("sending", "") or "").strip().lower()
    receiving = str(capabilities.get("receiving", "") or "").strip().lower()
    if sending != "enabled" or receiving != "disabled":
        return "Receipt resend.domain must prove sending is enabled and receiving is disabled."
    generated = _receipt_generated_env_names(action)
    if "RESEND_FROM_EMAIL" not in generated:
        return "Receipt resend.domain must prove FuseKit generated RESEND_FROM_EMAIL."
    return ""


def _first_receipt_action(
    actions: list[Any],
    name: str,
    *,
    status: str = "",
) -> int | None:
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            continue
        if str(action.get("action", "")) != name:
            continue
        if status and str(action.get("status", "")) != status:
            continue
        return index
    return None


def _first_dns_proposal_for_domain(
    actions: list[Any],
    domain: str,
    *,
    status: str = "",
) -> int | None:
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            continue
        if str(action.get("action", "")).strip() != "dns.propose":
            continue
        if status and str(action.get("status", "")).strip() != status:
            continue
        if _receipt_action_domain(action) == domain:
            return index
    return None


def _receipt_action_domain(action: dict[str, Any]) -> str:
    details = action.get("details", {})
    if not isinstance(details, dict):
        return ""
    return str(details.get("domain", "") or "").strip().lower()


def _manifest_domain_names(manifest: SetupManifest) -> set[str]:
    return {domain.domain.strip().lower() for domain in manifest.domains if domain.domain.strip()}


def _resend_receipt_dns_records(action: dict[str, Any]) -> set[tuple[str, str, str]]:
    details = action.get("details", {})
    raw_records = details.get("dns_records", []) if isinstance(details, dict) else []
    return {
        _receipt_dns_record_key(record)
        for record in raw_records
        if isinstance(record, dict) and all(_receipt_dns_record_key(record))
    }


def _dns_proposal_receipt_records(action: dict[str, Any]) -> set[tuple[str, str, str]]:
    details = action.get("details", {})
    raw_changes = details.get("changes", []) if isinstance(details, dict) else []
    records: set[tuple[str, str, str]] = set()
    for change in raw_changes:
        if not isinstance(change, dict):
            continue
        record = change.get("record", {})
        if not isinstance(record, dict):
            continue
        key = _receipt_dns_record_key(record)
        if all(key):
            records.add(key)
    return records


def _receipt_dns_record_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(record.get("type", "")).strip().upper(),
        str(record.get("name", "")).strip().lower(),
        str(record.get("value", "")).strip(),
    )


def _check_receipt_resend_vercel_env_flow(
    raw: Any,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Prove Resend runtime env keys were pushed to Vercel when the app requires them."""

    required = _manifest_resend_runtime_env_names(manifest)
    if mode != "live" or not required:
        return
    actions = raw.get("actions", []) if isinstance(raw, dict) else []
    if not isinstance(actions, list):
        _fail_resend_vercel_env_receipt(
            checks,
            missing,
            "Receipt actions are missing or malformed.",
            artifact,
        )
        return
    configured = _receipt_vercel_env_names(actions)
    missing_env = sorted(required - configured)
    if missing_env:
        _fail_resend_vercel_env_receipt(
            checks,
            missing,
            "Receipt Vercel env setup is missing Resend runtime keys: " + ", ".join(missing_env),
            artifact,
        )
        return
    generated_missing = _receipt_resend_generated_envs_missing_before_vercel(actions, required)
    if generated_missing:
        _fail_resend_vercel_env_receipt(
            checks,
            missing,
            "Receipt Vercel env setup lacks prior Resend API-generated runtime proof for: "
            + ", ".join(generated_missing),
            artifact,
        )
        return
    checks.append(
        AcceptanceCheck(
            "receipt.resend_vercel_env",
            "ok",
            "Receipt proves Resend-owned runtime env keys were generated before Vercel setup.",
            artifact,
        )
    )


def _manifest_resend_runtime_env_names(manifest: SetupManifest) -> set[str]:
    providers = _manifest_provider_names(manifest)
    if not {"resend", "vercel"} <= providers:
        return set()
    names: set[str] = set(manifest.required_env)
    for service in manifest.services:
        names.update(service.secrets)
        names.update(service.env)
    return {name.upper() for name in names if name.upper().startswith("RESEND_")}


def _receipt_vercel_env_names(actions: list[Any]) -> set[str]:
    configured: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        if str(action.get("action", "")) != "vercel.env":
            continue
        if str(action.get("status", "")) != "ok":
            continue
        details = action.get("details", {})
        if not isinstance(details, dict):
            continue
        env_name = str(details.get("env", "")).strip().upper()
        if env_name:
            configured.add(env_name)
    return configured


def _receipt_resend_generated_envs_missing_before_vercel(
    actions: list[Any],
    required: set[str],
) -> list[str]:
    generated_required = required & {"RESEND_FROM_EMAIL", "RESEND_AUDIENCE_ID"}
    if not generated_required:
        return []
    generated: set[str] = set()
    missing: set[str] = set()
    for action in actions:
        if not isinstance(action, dict):
            continue
        name = str(action.get("action", "")).strip()
        status = str(action.get("status", "")).strip()
        if status != "ok":
            continue
        if name in {"resend.domain", "resend.audience"}:
            generated.update(_receipt_generated_env_names(action) & generated_required)
            continue
        if name != "vercel.env":
            continue
        details = action.get("details", {})
        if not isinstance(details, dict):
            continue
        env_name = str(details.get("env", "")).strip().upper()
        if env_name in generated_required and env_name not in generated:
            missing.add(env_name)
    return sorted(missing)


def _receipt_generated_env_names(action: dict[str, Any]) -> set[str]:
    details = action.get("details", {})
    if not isinstance(details, dict):
        return set()
    raw_names = details.get("generated_env", [])
    if isinstance(raw_names, str):
        raw_names = [raw_names]
    if not isinstance(raw_names, list):
        return set()
    return {str(name).strip().upper() for name in raw_names if str(name).strip()}


def _fail_resend_vercel_env_receipt(
    checks: list[AcceptanceCheck],
    missing: list[str],
    detail: str,
    artifact: str,
) -> None:
    checks.append(
        AcceptanceCheck(
            "receipt.resend_vercel_env",
            "failed",
            detail,
            artifact,
        )
    )
    missing.append("Resend runtime env in Vercel receipt")


def _check_audit_log(
    audit_log_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
) -> None:
    if audit_log_path.exists():
        public_safety_failures = _audit_log_public_safety_failures(audit_log_path)
        if public_safety_failures:
            checks.append(
                AcceptanceCheck(
                    "audit.exists",
                    "failed",
                    "Audit log is not safe public JSONL proof: "
                    + "; ".join(public_safety_failures[:20]),
                    str(audit_log_path),
                )
            )
            if mode == "live":
                missing.append("redacted audit log")
            return
        checks.append(AcceptanceCheck("audit.exists", "ok", "Redacted audit log exists."))
        return
    status = "skipped" if mode == "rehearsal" else "missing"
    checks.append(AcceptanceCheck("audit.exists", status, f"Audit log not found: {audit_log_path}"))
    if mode == "live":
        missing.append("redacted audit log")


def _audit_log_public_safety_failures(audit_log_path: Path) -> list[str]:
    try:
        lines = audit_log_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ["audit log could not be read"]
    failures: list[str] = []
    object_rows = 0
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            failures.append(f"audit.jsonl line {line_number} is malformed JSON")
            continue
        if not isinstance(event, dict):
            failures.append(f"audit.jsonl line {line_number} is not an object")
            continue
        object_rows += 1
        failures.extend(_audit_log_row_shape_failures(event, f"audit.jsonl[{line_number}]"))
        failures.extend(
            _standalone_artifact_public_safety_failures(
                event,
                f"audit[{line_number}]",
            )
        )
        if len(failures) >= 20:
            failures.append("audit.jsonl contains additional unsafe public text")
            break
    if object_rows == 0:
        failures.append("audit.jsonl has no JSON object rows")
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


def _check_verification_report(
    report_path: Path,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not report_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "verification_report.safe",
                status,
                f"Verification report not found: {report_path}",
            )
        )
        if mode == "live":
            missing.append("safe verification report")
        return
    try:
        raw = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "verification_report.safe",
                "failed",
                "Verification report could not be read.",
            )
        )
        missing.append("safe verification report")
        return
    snapshot = ledger.snapshot_json("verification-report", raw)
    if isinstance(raw, dict):
        public_safety_failures = _standalone_artifact_public_safety_failures(
            raw,
            "verification_report",
        )
    else:
        public_safety_failures = []
    if public_safety_failures:
        checks.append(
            AcceptanceCheck(
                "verification_report.safe",
                "failed" if mode == "live" else "skipped",
                "Verification report contains unsafe public text: "
                + "; ".join(public_safety_failures[:20]),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("safe verification report")
        return
    failures = verification_report_failures(raw if isinstance(raw, dict) else {})
    if failures:
        checks.append(
            AcceptanceCheck(
                "verification_report.safe",
                "failed" if mode == "live" else "skipped",
                "Verification is not passed or pending-safe: " + "; ".join(failures),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("safe verification report")
        return
    _check_verification_provider_coverage(
        raw if isinstance(raw, dict) else {},
        manifest,
        mode,
        checks,
        missing,
        str(snapshot),
    )
    checks.append(
        AcceptanceCheck(
            "verification_report.safe",
            "ok",
            "Verification report is passed or explicitly pending-safe.",
            str(snapshot),
        )
    )


def _check_verification_provider_coverage(
    report: dict[str, Any],
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require verification evidence for every provider requested by the manifest."""

    required = _manifest_provider_names(manifest)
    if not required:
        return
    recorded = _verification_provider_names(report)
    absent = sorted(required - recorded)
    if absent:
        checks.append(
            AcceptanceCheck(
                "verification_report.coverage",
                "failed" if mode == "live" else "skipped",
                "Verification report is missing manifest providers: " + ", ".join(absent),
                artifact,
            )
        )
        if mode == "live":
            missing.append("complete provider verification coverage")
        return
    checks.append(
        AcceptanceCheck(
            "verification_report.coverage",
            "ok",
            "Verification report covers every provider declared by the manifest.",
            artifact,
        )
    )


def _verification_provider_names(report: dict[str, Any]) -> set[str]:
    checks = report.get("checks", [])
    if not isinstance(checks, list):
        return set()
    return {
        str(check.get("provider", "")).strip().lower()
        for check in checks
        if isinstance(check, dict)
        and str(check.get("provider", "")).strip()
        and _is_verification_report_coverage_check(check)
    }


def _is_verification_report_coverage_check(check: dict[str, Any]) -> bool:
    status = str(check.get("status", "") or "").strip()
    details = check.get("details", {})
    details = details if isinstance(details, dict) else {}
    return status == "passed" or (
        status in {"pending", "pending_safe"} and details.get("pending_safe") is True
    )


def _check_provider_strategies(
    strategies_path: Path,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not strategies_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "provider_strategies.recorded",
                status,
                f"Provider strategy artifact not found: {strategies_path}",
            )
        )
        if mode == "live":
            missing.append("provider strategy decisions")
        return
    try:
        raw = json.loads(strategies_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "provider_strategies.recorded",
                "failed",
                "Provider strategy artifact could not be read.",
            )
        )
        missing.append("provider strategy decisions")
        return
    snapshot = ledger.snapshot_json("provider-strategies", raw)
    if isinstance(raw, dict):
        public_safety_failures = _standalone_artifact_public_safety_failures(
            raw,
            "provider_strategies",
        )
    else:
        public_safety_failures = []
    if public_safety_failures:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.recorded",
                "failed" if mode == "live" else "skipped",
                "Provider strategy artifact contains unsafe public text: "
                + "; ".join(public_safety_failures[:20]),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("provider strategy decisions")
        return
    providers = raw.get("providers", []) if isinstance(raw, dict) else []
    schema_version = str(raw.get("schema_version", "")) if isinstance(raw, dict) else ""
    if schema_version != PROVIDER_STRATEGIES_SCHEMA_VERSION:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.recorded",
                "failed" if mode == "live" else "skipped",
                "Provider strategy artifact has an unsupported schema.",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("provider strategy decisions")
        return
    if not _has_strategy_decisions(providers):
        checks.append(
            AcceptanceCheck(
                "provider_strategies.recorded",
                "failed" if mode == "live" else "skipped",
                "Provider strategy artifact has no provider route decisions.",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("provider strategy decisions")
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.recorded",
            "ok",
            "Provider strategy route decisions were recorded.",
            str(snapshot),
        )
    )
    _check_provider_strategy_playbook(raw, mode, checks, missing, str(snapshot))
    _check_provider_strategy_decision_shape(raw, mode, checks, missing, str(snapshot))
    _check_provider_strategy_coverage(
        providers,
        manifest,
        mode,
        checks,
        missing,
        str(snapshot),
    )
    _check_provider_strategy_order(providers, mode, checks, missing, str(snapshot))


def _has_strategy_decisions(providers: Any) -> bool:
    if not isinstance(providers, list):
        return False
    for provider in providers:
        if not isinstance(provider, dict) or not str(provider.get("provider", "")):
            continue
        strategies = provider.get("strategies", [])
        if not isinstance(strategies, list):
            continue
        if any(isinstance(strategy, dict) and strategy.get("decision") for strategy in strategies):
            return True
    return False


def _check_provider_strategy_decision_shape(
    raw: Any,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require route decisions to include the fields needed for proof and UX."""

    failures = _provider_strategy_artifact_shape_failures(raw)
    if failures:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.complete",
                "failed" if mode == "live" else "skipped",
                "Provider strategy decisions are incomplete: " + "; ".join(failures),
                artifact,
            )
        )
        if mode == "live":
            missing.append("complete provider strategy evidence")
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.complete",
            "ok",
            "Provider strategy decisions include selected route evidence.",
            artifact,
        )
    )


def _check_provider_strategy_playbook(
    raw: dict[str, Any],
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require the durable no-thinking provider checklist to be present and safe."""

    playbook = raw.get("playbook")
    if not isinstance(playbook, dict):
        checks.append(
            AcceptanceCheck(
                "provider_strategies.playbook",
                "failed" if mode == "live" else "skipped",
                "Provider strategy artifact is missing the ordered provider playbook.",
                artifact,
            )
        )
        if mode == "live":
            missing.append("provider playbook")
        return
    failures = _provider_playbook_shape_failures(playbook)
    if failures:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.playbook",
                "failed" if mode == "live" else "skipped",
                "Provider playbook is incomplete: " + "; ".join(failures),
                artifact,
            )
        )
        if mode == "live":
            missing.append("provider playbook")
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.playbook",
            "ok",
            "Provider playbook gives the ordered launcher actions and safety notes.",
            artifact,
        )
    )


def _check_provider_strategy_coverage(
    providers: Any,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require strategy proof for every provider requested by the manifest."""

    required = _manifest_provider_names(manifest)
    if not required:
        return
    recorded = {
        str(provider.get("provider", "")).strip().lower()
        for provider in providers
        if isinstance(provider, dict)
    }
    absent = sorted(required - recorded)
    if absent:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.coverage",
                "failed" if mode == "live" else "skipped",
                "Provider strategy artifact is missing manifest providers: " + ", ".join(absent),
                artifact,
            )
        )
        if mode == "live":
            missing.append("complete provider strategy coverage")
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.coverage",
            "ok",
            "Provider strategy artifact covers every provider declared by the manifest.",
            artifact,
        )
    )


def _manifest_provider_names(manifest: SetupManifest) -> set[str]:
    providers: set[str] = set()
    for service in manifest.services:
        provider = service.provider.strip().lower()
        if provider:
            providers.add(provider)
    for domain in manifest.domains:
        provider = domain.provider.strip().lower()
        if provider:
            providers.add(provider)
    return providers


_PROVIDER_STRATEGIES_ARTIFACT_KEYS = PROVIDER_STRATEGIES_ARTIFACT_KEYS
_PROVIDER_STRATEGY_PROVIDER_KEYS = PROVIDER_STRATEGY_PROVIDER_KEYS
_PROVIDER_STRATEGY_RECORD_KEYS = PROVIDER_STRATEGY_RECORD_KEYS
_PROVIDER_STRATEGY_DECISION_KEYS = PROVIDER_STRATEGY_DECISION_KEYS
_PROVIDER_STRATEGY_ROUTE_KEYS = PROVIDER_STRATEGY_ROUTE_KEYS


def _provider_strategy_artifact_shape_failures(raw: Any) -> list[str]:
    if not isinstance(raw, dict):
        return ["provider_strategies is not an object"]
    failures: list[str] = []
    unexpected = sorted(set(raw) - _PROVIDER_STRATEGIES_ARTIFACT_KEYS)
    if unexpected:
        failures.append("provider_strategies has unexpected fields: " + ", ".join(unexpected))
    providers = raw.get("providers", [])
    failures.extend(_provider_strategy_shape_failures(providers))
    if isinstance(providers, list):
        for provider_index, provider in enumerate(providers):
            label = f"provider_strategies.providers[{provider_index}]"
            if not isinstance(provider, dict):
                continue
            unexpected_provider_keys = sorted(set(provider) - _PROVIDER_STRATEGY_PROVIDER_KEYS)
            if unexpected_provider_keys:
                failures.append(
                    f"{label} has unexpected fields: " + ", ".join(unexpected_provider_keys)
                )
            provider_name = str(provider.get("provider", "") or "")
            if provider_name != provider_name.strip():
                failures.append(f"{label}.provider must not have surrounding whitespace")
            strategies = provider.get("strategies", [])
            if not isinstance(strategies, list):
                continue
            for strategy_index, strategy in enumerate(strategies):
                strategy_label = f"{label}.strategies[{strategy_index}]"
                if not isinstance(strategy, dict):
                    continue
                failures.extend(
                    _provider_strategy_record_exact_shape_failures(
                        strategy,
                        strategy_label,
                    )
                )
    return failures


def _provider_strategy_record_exact_shape_failures(
    strategy: dict[str, Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(strategy) - _PROVIDER_STRATEGY_RECORD_KEYS)
    if unexpected:
        failures.append(f"{label} has unexpected fields: " + ", ".join(unexpected))
    for key in (
        "recipe",
        "strategy",
        "status",
        "resume_url",
        "target",
        "next_action",
        "resume_hint",
    ):
        if key in strategy:
            failures.extend(_trimmed_public_string_failures(strategy.get(key), f"{label}.{key}"))
    for key in ("follow_steps", "success_criteria", "avoid_steps"):
        if key in strategy:
            failures.extend(
                _trimmed_public_string_list_failures(strategy.get(key), f"{label}.{key}")
            )
    decision = strategy.get("decision", {})
    if not isinstance(decision, dict):
        return failures
    unexpected_decision_keys = sorted(set(decision) - _PROVIDER_STRATEGY_DECISION_KEYS)
    if unexpected_decision_keys:
        failures.append(
            f"{label}.decision has unexpected fields: "
            + ", ".join(unexpected_decision_keys)
        )
    for key in ("provider", "recipe_kind"):
        if key in decision:
            failures.extend(
                _trimmed_public_string_failures(
                    decision.get(key),
                    f"{label}.decision.{key}",
                )
            )
    selected = decision.get("selected", {})
    if isinstance(selected, dict):
        failures.extend(
            _provider_strategy_route_exact_shape_failures(
                selected,
                f"{label}.decision.selected",
            )
        )
    candidates = decision.get("candidates", [])
    if isinstance(candidates, list):
        for index, candidate in enumerate(candidates):
            if isinstance(candidate, dict):
                failures.extend(
                    _provider_strategy_route_exact_shape_failures(
                        candidate,
                        f"{label}.decision.candidates[{index}]",
                    )
                )
    return failures


def _provider_strategy_route_exact_shape_failures(
    route: dict[str, Any],
    label: str,
) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(route) - _PROVIDER_STRATEGY_ROUTE_KEYS)
    if unexpected:
        failures.append(f"{label} has unexpected fields: " + ", ".join(unexpected))
    for key in ("kind", "label", "status", "reason"):
        if key in route:
            failures.extend(_trimmed_public_string_failures(route.get(key), f"{label}.{key}"))
    if "priority" in route and not (
        isinstance(route["priority"], int) and not isinstance(route["priority"], bool)
    ):
        failures.append(f"{label}.priority must be an integer")
    for key in ("deterministic", "implemented"):
        if key in route and route[key] not in {True, False}:
            failures.append(f"{label}.{key} must be boolean")
    evidence = route.get("evidence", {})
    if "evidence" in route and not isinstance(evidence, dict):
        failures.append(f"{label}.evidence must be an object")
    return failures


def _trimmed_public_string_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, str):
        return [f"{label} must be text"]
    if value != value.strip():
        return [f"{label} must not have surrounding whitespace"]
    if contains_durable_secret_text(value):
        return [f"{label} contains credential-looking text"]
    return []


def _trimmed_public_string_list_failures(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        return [f"{label} must be a list"]
    failures: list[str] = []
    for index, item in enumerate(value):
        failures.extend(_trimmed_public_string_failures(item, f"{label}[{index}]"))
    return failures


def _provider_strategy_shape_failures(providers: Any) -> list[str]:
    if not isinstance(providers, list):
        return ["providers is not a list"]
    failures: list[str] = []
    for provider_index, provider in enumerate(providers):
        if not isinstance(provider, dict):
            failures.append(f"provider[{provider_index}] is not an object")
            continue
        provider_name = str(provider.get("provider", "")).strip() or f"provider[{provider_index}]"
        strategies = provider.get("strategies", [])
        if not isinstance(strategies, list) or not strategies:
            failures.append(f"{provider_name} has no strategies")
            continue
        for strategy_index, strategy in enumerate(strategies):
            label = f"{provider_name}.strategies[{strategy_index}]"
            if not isinstance(strategy, dict):
                failures.append(f"{label} is not an object")
                continue
            decision = strategy.get("decision")
            if not isinstance(decision, dict):
                failures.append(f"{label} is missing decision")
                continue
            selected = decision.get("selected")
            if not isinstance(selected, dict):
                failures.append(f"{label} is missing selected route")
                continue
            _require_strategy_string(selected, "kind", label, failures)
            _require_strategy_string(selected, "status", label, failures)
            _require_strategy_bool(selected, "deterministic", label, failures)
            _require_strategy_bool(selected, "implemented", label, failures)
            _require_strategy_string(selected, "reason", label, failures)
            candidates = decision.get("candidates", [])
            if not isinstance(candidates, list) or not candidates:
                failures.append(f"{label} is missing considered candidates")
            else:
                failures.extend(
                    _provider_strategy_candidate_shape_failures(
                        candidates,
                        f"{label}.decision.candidates",
                    )
                )
            if str(strategy.get("status", "")).strip() == "needs_human_gate":
                follow_steps = strategy.get("follow_steps", [])
                if not isinstance(follow_steps, list) or not any(
                    str(step).strip() for step in follow_steps
                ):
                    failures.append(f"{label}.follow_steps is missing")
                if not str(strategy.get("next_action", "")).strip():
                    failures.append(f"{label}.next_action is missing")
                if not str(strategy.get("resume_hint", "")).strip():
                    failures.append(f"{label}.resume_hint is missing")
                if not _string_list_field(strategy.get("success_criteria")):
                    failures.append(f"{label}.success_criteria is missing")
                if not _string_list_field(strategy.get("avoid_steps")):
                    failures.append(f"{label}.avoid_steps is missing")
                failures.extend(
                    _guidance_quality_failures(
                        label,
                        follow_steps=follow_steps,
                        next_action=str(strategy.get("next_action", "")),
                        resume_hint=str(strategy.get("resume_hint", "")),
                        target=str(strategy.get("target", "")),
                        success_criteria=strategy.get("success_criteria", []),
                        avoid_steps=strategy.get("avoid_steps", []),
                        requires_vm=True,
                        require_capture_resume=True,
                    )
                )
            failures.extend(
                _provider_specific_strategy_shape_failures(
                    provider_name,
                    strategy,
                    selected,
                    label,
                )
            )
    return failures


def _provider_strategy_candidate_shape_failures(
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


def _provider_specific_strategy_shape_failures(
    provider_name: str,
    strategy: dict[str, Any],
    selected: dict[str, Any],
    label: str,
) -> list[str]:
    """Require provider-specific proof that keeps public guidance honest."""

    if provider_name.lower() != "resend":
        return []
    if str(strategy.get("strategy", selected.get("kind", ""))) != "api":
        return []
    if str(strategy.get("status", "")).strip() != "ok":
        return []
    recipe = str(strategy.get("recipe", "")).strip()
    evidence = selected.get("evidence", {})
    if not isinstance(evidence, dict):
        return [f"{label}.selected.evidence is missing"]
    if recipe == "resend-domain":
        return _required_strategy_evidence(
            evidence,
            label,
            {
                "api_owns": "domain",
                "user_manual_domain_step": "false",
                "downstream_order": "before_dns_apply",
            },
        )
    if recipe == "resend-audience":
        return _required_strategy_evidence(
            evidence,
            label,
            {
                "api_owns": "audience",
                "user_manual_audience_step": "false",
                "conditional": "only_when_app_requires_audience",
            },
        )
    return []


def _required_strategy_evidence(
    evidence: dict[str, Any],
    label: str,
    required: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    for key, expected in required.items():
        if str(evidence.get(key, "")).strip() != expected:
            failures.append(f"{label}.selected.evidence.{key} must be {expected}")
    return failures


def _require_strategy_string(
    selected: dict[str, Any],
    key: str,
    label: str,
    failures: list[str],
) -> None:
    if not str(selected.get(key, "")).strip():
        failures.append(f"{label}.selected.{key} is missing")


def _require_strategy_bool(
    selected: dict[str, Any],
    key: str,
    label: str,
    failures: list[str],
) -> None:
    if not isinstance(selected.get(key), bool):
        failures.append(f"{label}.selected.{key} is missing")


def _check_provider_strategy_order(
    providers: Any,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Assert provider strategy order proves Resend emitted DNS before DNS apply."""

    if not isinstance(providers, list):
        return
    ordered = [
        str(provider.get("provider", "")).lower()
        for provider in providers
        if isinstance(provider, dict) and str(provider.get("provider", "")).strip()
    ]
    if "resend" not in ordered or not any(
        provider in ordered for provider in {"cloudflare", "dns"}
    ):
        return
    resend_index = ordered.index("resend")
    dns_index = min(
        ordered.index(provider) for provider in ("cloudflare", "dns") if provider in ordered
    )
    if resend_index < dns_index:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.order",
                "ok",
                "Provider setup order proves Resend ran before DNS so Resend domain "
                "records can be applied.",
                artifact,
            )
        )
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.order",
            "failed" if mode == "live" else "skipped",
            "Provider setup order put DNS before Resend; Resend domain DNS records may be missing.",
            artifact,
        )
    )
    if mode == "live":
        missing.append("Resend-before-DNS provider setup order")


def _check_provider_strategy_checkpoints(
    strategies_path: Path,
    checkpoints_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    """Require provider strategy decisions to survive in durable resume checkpoints."""

    required = _provider_strategy_checkpoint_requirements(strategies_path)
    if not required:
        return
    if not checkpoints_path.exists():
        checks.append(
            AcceptanceCheck(
                "provider_strategies.checkpoints",
                "failed" if mode == "live" else "skipped",
                f"Provider route checkpoints not found: {checkpoints_path}",
            )
        )
        if mode == "live":
            missing.append("provider route recovery checkpoints")
        return
    try:
        raw = json.loads(checkpoints_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "provider_strategies.checkpoints",
                "failed",
                "Provider route checkpoints could not be read.",
            )
        )
        missing.append("provider route recovery checkpoints")
        return
    snapshot = ledger.snapshot_json("checkpoints", raw)
    checkpoints = raw.get("checkpoints", []) if isinstance(raw, dict) else []
    failures = _provider_strategy_checkpoint_failures(required, checkpoints)
    if failures:
        checks.append(
            AcceptanceCheck(
                "provider_strategies.checkpoints",
                "failed" if mode == "live" else "skipped",
                "Provider route checkpoints are incomplete: " + "; ".join(failures),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("provider route recovery checkpoints")
        return
    checks.append(
        AcceptanceCheck(
            "provider_strategies.checkpoints",
            "ok",
            "Provider route decisions are present in durable recovery checkpoints.",
            str(snapshot),
        )
    )


def _provider_strategy_checkpoint_requirements(
    strategies_path: Path,
) -> dict[str, set[str]]:
    try:
        raw = json.loads(strategies_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    providers = raw.get("providers", []) if isinstance(raw, dict) else []
    if not _has_strategy_decisions(providers):
        return {}
    requirements: dict[str, set[str]] = {}
    for provider in providers:
        if not isinstance(provider, dict):
            continue
        provider_name = str(provider.get("provider", "") or "").strip().lower()
        if not provider_name:
            continue
        strategies = provider.get("strategies", [])
        if not isinstance(strategies, list):
            continue
        recipes = {
            str(strategy.get("recipe", "") or "").strip().lower()
            for strategy in strategies
            if isinstance(strategy, dict) and isinstance(strategy.get("decision"), dict)
        }
        if recipes:
            requirements[provider_name] = recipes
    return requirements


def _provider_strategy_checkpoint_failures(
    required: dict[str, set[str]],
    checkpoints: Any,
) -> list[str]:
    if not isinstance(checkpoints, list):
        return ["checkpoints is not a list"]
    by_id = {
        str(checkpoint.get("id", "") or "").strip(): checkpoint
        for checkpoint in checkpoints
        if isinstance(checkpoint, dict)
    }
    failures: list[str] = []
    for provider, recipes in sorted(required.items()):
        checkpoint_id = f"provider.{_provider_route_slug(provider)}.routes"
        checkpoint = by_id.get(checkpoint_id)
        if checkpoint is None:
            failures.append(f"{checkpoint_id} is missing")
            continue
        fields = ("status", "detail", "next_action", "resume_hint")
        missing_fields = [
            field for field in fields if not str(checkpoint.get(field, "") or "").strip()
        ]
        if missing_fields:
            failures.append(f"{checkpoint_id} missing {', '.join(missing_fields)}")
        status = str(checkpoint.get("status", "") or "").strip()
        if status not in {"done", "waiting", "running", "failed"}:
            failures.append(f"{checkpoint_id} has unsupported status {status or 'empty'}")
        guidance_failure = _checkpoint_guidance_quality_failure(
            checkpoint_id,
            checkpoint,
            provider=provider,
        )
        if guidance_failure:
            failures.append(guidance_failure)
        if provider == "resend" and "resend-domain" in recipes:
            text = " ".join(
                str(checkpoint.get(field, "") or "")
                for field in ("detail", "next_action", "resume_hint")
            ).lower()
            if "resend" not in text or "dns" not in text:
                failures.append(f"{checkpoint_id} is missing Resend-before-DNS recovery guidance")
            if "vercel" in required and ("vercel" not in text or "env" not in text):
                failures.append(
                    f"{checkpoint_id} is missing Resend-to-Vercel-env recovery guidance"
                )
    return failures


def _checkpoint_guidance_quality_failure(
    checkpoint_id: str,
    checkpoint: dict[str, Any],
    *,
    provider: str,
) -> str:
    text = " ".join(
        str(checkpoint.get(field, "") or "") for field in ("detail", "next_action", "resume_hint")
    ).lower()
    for phrase in _FORBIDDEN_GUIDANCE_PHRASES:
        if phrase in text:
            return f"{checkpoint_id} guidance contains non-launcher wording: {phrase}"
    local_browser_failure = _local_browser_guidance_failure(text)
    if local_browser_failure:
        return f"{checkpoint_id} guidance contains non-launcher wording: {local_browser_failure}"
    manual_action_failure = _manual_action_guidance_failure(text)
    if manual_action_failure:
        return f"{checkpoint_id} guidance contains non-launcher wording: {manual_action_failure}"
    if provider == "resend":
        for field in ("detail", "next_action", "resume_hint"):
            if _field_asks_for_manual_resend_setup(str(checkpoint.get(field, "") or "")):
                return f"{checkpoint_id} guidance asks for manual Resend domain/audience setup"
    waiting_for_human_gate = (
        str(checkpoint.get("status", "") or "").strip().lower() == "waiting"
        or "needs_human_gate" in text
        or "browser_guided" in text
        or "human_follow_me" in text
    )
    if waiting_for_human_gate and "open provider gate in vm" not in text:
        return f"{checkpoint_id} guidance does not name Open provider gate in VM"
    secret_targets = _copy_once_targets_mentioned(text)
    if secret_targets:
        if "capture <target> from vm clipboard" in text:
            return (
                f"{checkpoint_id} guidance uses placeholder Capture <TARGET> despite "
                "concrete secret targets"
            )
        missing_exact = _missing_exact_capture_controls(secret_targets, text)
        if "capture from vm clipboard" not in text and len(missing_exact) == len(secret_targets):
            return (
                f"{checkpoint_id} guidance does not name Capture from VM clipboard for "
                + ", ".join(secret_targets)
            )
        if missing_exact:
            return (
                f"{checkpoint_id} guidance does not name exact Capture controls: "
                + ", ".join(missing_exact)
            )
        if not _capture_resume_guidance_ready(text):
            return (
                f"{checkpoint_id} guidance does not explain FuseKit resumes after "
                "clipboard capture"
            )
    return ""


def _provider_route_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "provider"


def _check_gate_state(
    gates_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    """Require live runs to prove no durable human gates remain unresolved."""

    if not gates_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                status,
                f"Gate state not found: {gates_path}",
            )
        )
        if mode == "live":
            missing.append("resolved human gates")
        return
    try:
        raw = json.loads(gates_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                "failed",
                "Gate state could not be read.",
            )
        )
        missing.append("resolved human gates")
        return
    if not isinstance(raw, dict) or not isinstance(raw.get("gates"), list):
        snapshot = ledger.snapshot_json("gates", _redacted_gate_state(raw))
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                "failed" if mode == "live" else "skipped",
                "Gate state has an unsupported schema.",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("resolved human gates")
        return
    gates = raw["gates"]
    snapshot = ledger.snapshot_json("gates", _redacted_gate_state(raw))
    shape_failures = _gate_state_shape_failures(raw)
    if shape_failures:
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                "failed" if mode == "live" else "skipped",
                "Gate state uses unsupported generated shape: "
                + "; ".join(shape_failures[:20]),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("safe gate state")
        return
    public_safety_failures = _standalone_artifact_public_safety_failures(raw, "gates")
    if public_safety_failures:
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                "failed" if mode == "live" else "skipped",
                "Gate state contains unsafe public survivor text: "
                + "; ".join(public_safety_failures[:20]),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("safe gate state")
        return
    unguided = _unguided_gates(gates)
    if unguided:
        detail = ", ".join(unguided)
        checks.append(
            AcceptanceCheck(
                "gates.guided",
                "failed" if mode == "live" else "skipped",
                "Control-room gates are missing durable guidance: " + detail,
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("guided human gates")
        return
    checks.append(
        AcceptanceCheck(
            "gates.guided",
            "ok",
            "Every durable control-room gate includes next-action guidance.",
            str(snapshot),
        )
    )
    unresolved = [
        {
            "id": str(gate.get("id", "")),
            "provider": str(gate.get("provider", "")),
            "status": str(gate.get("status", "")),
        }
        for gate in gates
        if isinstance(gate, dict) and str(gate.get("status", "")) != "passed"
    ]
    if unresolved:
        detail = ", ".join(f"{gate['id']}:{gate['status']}" for gate in unresolved if gate["id"])
        checks.append(
            AcceptanceCheck(
                "gates.resolved",
                "failed" if mode == "live" else "skipped",
                "Unresolved control-room gates remain: " + (detail or "unknown gate"),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("resolved human gates")
        return
    checks.append(
        AcceptanceCheck(
            "gates.resolved",
            "ok",
            "No unresolved control-room gates remain.",
            str(snapshot),
        )
    )


def _gate_state_shape_failures(raw: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected_keys = sorted(set(raw) - PROVIDER_GATES_ARTIFACT_KEYS)
    if unexpected_keys:
        failures.append("gates has unexpected fields: " + ", ".join(unexpected_keys))
    gates = raw.get("gates", [])
    if not isinstance(gates, list):
        failures.append("gates.gates must be a list")
        return failures
    for index, gate in enumerate(gates):
        label = f"gates.gates[{index}]"
        if not isinstance(gate, dict):
            failures.append(f"{label} is not an object")
            continue
        failures.extend(_provider_gate_record_shape_failures(gate, label))
    return failures


def _unguided_gates(gates: Any) -> list[str]:
    if not isinstance(gates, list):
        return ["gates"]
    missing: list[str] = []
    for index, gate in enumerate(gates):
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "") or f"gate[{index}]")
        follow_steps = gate.get("follow_steps", [])
        missing_fields = [
            field
            for field in ("next_action", "resume_hint")
            if not str(gate.get(field, "")).strip()
        ]
        if not isinstance(follow_steps, list) or not any(
            str(step).strip() for step in follow_steps
        ):
            missing_fields.append("follow_steps")
        if _gate_requires_resume_url(gate) and not str(gate.get("resume_url", "")).strip():
            missing_fields.append("resume_url")
        if not _string_list_field(gate.get("success_criteria")):
            missing_fields.append("success_criteria")
        if not _string_list_field(gate.get("avoid_steps")):
            missing_fields.append("avoid_steps")
        if missing_fields:
            missing.append(f"{gate_id} missing {', '.join(missing_fields)}")
        generated_resend_target_failure = _generated_resend_runtime_capture_failure(gate)
        if generated_resend_target_failure:
            missing.append(generated_resend_target_failure)
        manual_resend_setup_failure = _manual_resend_setup_gate_failure(gate)
        if manual_resend_setup_failure:
            missing.append(manual_resend_setup_failure)
        resend_selector_failure = _resend_setup_key_selector_failure(gate)
        if resend_selector_failure:
            missing.append(resend_selector_failure)
        quality_failures = _guidance_quality_failures(
            gate_id,
            follow_steps=follow_steps,
            next_action=str(gate.get("next_action", "")),
            resume_hint=str(gate.get("resume_hint", "")),
            target=str(gate.get("target", "")),
            success_criteria=gate.get("success_criteria", []),
            avoid_steps=gate.get("avoid_steps", []),
            requires_vm=bool(str(gate.get("resume_url", "")).strip()),
            require_capture_resume=str(gate.get("status", "")).strip().lower()
            not in {"passed", "resume_requested"},
        )
        missing.extend(quality_failures)
    return missing


def _generated_resend_runtime_capture_failure(gate: dict[str, Any]) -> str:
    """Reject stale Resend gates that ask humans to copy API-generated values."""

    provider = str(gate.get("provider", "")).strip().lower()
    classification = str(gate.get("classification", "")).strip().lower()
    if provider != "resend" or classification != "provider-runtime-values":
        return ""
    generated_targets = {
        target
        for target in _env_targets_from_text(str(gate.get("target", "")))
        if target in {"RESEND_FROM_EMAIL", "RESEND_AUDIENCE_ID"}
    }
    if not generated_targets:
        return ""
    gate_id = str(gate.get("id", "") or "resend.runtime-values")
    return f"{gate_id}.target asks the user to capture API-generated Resend values: " + ", ".join(
        sorted(generated_targets)
    )


_RESEND_MANUAL_SETUP_PATTERNS = (
    r"\b(?:click|press|choose|use|open)\s+(?:the\s+)?(?:\+\s*)?add domain\b",
    r"\b(?:click|press|choose|use|open)\s+(?:the\s+)?(?:\+\s*)?add audience\b",
    r"\badd\s+and\s+verify\s+(?:the\s+)?resend\s+sending\s+domain\b",
    r"\bcreate\s+(?:a|the)\s+resend\s+domain\b",
    r"\bcreate\s+(?:a|the)\s+domain\s+in\s+resend\b",
    r"\bcreate\s+(?:a|the)\s+resend\s+audience\b",
    r"\bcreate\s+(?:a|the)\s+audience\s+in\s+resend\b",
    r"\bdomain\s+ownership\s+(?:gate|step|verification)\b",
)


def _manual_resend_setup_gate_failure(gate: dict[str, Any]) -> str:
    """Reject stale Resend gates that route API-owned setup back to provider UI."""

    provider = str(gate.get("provider", "")).strip().lower()
    if provider != "resend":
        return ""
    fields = (
        gate.get("reason", ""),
        gate.get("target", ""),
        gate.get("next_action", ""),
        gate.get("resume_hint", ""),
        *(gate.get("follow_steps", []) if isinstance(gate.get("follow_steps"), list) else []),
        *(
            gate.get("success_criteria", [])
            if isinstance(gate.get("success_criteria"), list)
            else []
        ),
        *(gate.get("avoid_steps", []) if isinstance(gate.get("avoid_steps"), list) else []),
    )
    for value in fields:
        if _field_asks_for_manual_resend_setup(str(value)):
            gate_id = str(gate.get("id", "") or "provider.resend")
            return (
                f"{gate_id}.guidance asks for manual Resend domain/audience setup; "
                "FuseKit must own that setup through Resend API after key capture"
            )
    return ""


def _field_asks_for_manual_resend_setup(value: str) -> bool:
    text = value.lower()
    for pattern in _RESEND_MANUAL_SETUP_PATTERNS:
        for match in re.finditer(pattern, text):
            if not _manual_setup_match_is_negated(text, match.start()):
                return True
    return False


def _resend_setup_key_selector_failure(gate: dict[str, Any]) -> str:
    """Require exact Resend setup-key selector copy on secret capture gates."""

    provider = str(gate.get("provider", "")).strip().lower()
    if provider != "resend":
        return ""
    targets = _env_targets_from_text(str(gate.get("target", "")))
    if "RESEND_API_KEY" not in targets:
        return ""
    classification = str(gate.get("classification", "")).strip().lower()
    if classification not in {"provider-authorization", "provider-runtime-values"}:
        return ""
    fields = (
        gate.get("reason", ""),
        gate.get("next_action", ""),
        gate.get("resume_hint", ""),
        *(gate.get("follow_steps", []) if isinstance(gate.get("follow_steps"), list) else []),
        *(
            gate.get("success_criteria", [])
            if isinstance(gate.get("success_criteria"), list)
            else []
        ),
        *(gate.get("avoid_steps", []) if isinstance(gate.get("avoid_steps"), list) else []),
    )
    text = "\n".join(str(value) for value in fields)
    missing = [
        selector
        for selector in ("Permission: Full access", "Domain: All domains")
        if selector not in text
    ]
    gate_id = str(gate.get("id", "") or "provider.resend")
    if missing:
        return (
            f"{gate_id}.guidance must name exact Resend setup-key selectors: "
            + ", ".join(missing)
        )
    lowered = text.lower()
    raw_key_warning_ready = "raw key value" in lowered and (
        "not enough" in lowered or "does not reveal old key" in lowered
    )
    if not raw_key_warning_ready:
        return (
            f"{gate_id}.guidance must explain existing Resend key rows are not "
            "enough without the raw key value"
        )
    return ""


def _manual_setup_match_is_negated(text: str, match_start: int) -> bool:
    prefix = text[max(0, match_start - 48) : match_start]
    clause = re.split(r"[.;:!?]\s*", prefix)[-1]
    return re.search(r"\b(?:do not|don't|never)\s+(?:manually\s+)?$", clause) is not None


_PROVIDER_GATE_CLASSIFICATIONS = {
    "provider-authorization",
    "provider-domain",
    "provider-runtime-values",
    "provider-setup-retry",
    "provider-verification",
}


def _gate_requires_resume_url(gate: dict[str, Any]) -> bool:
    classification = str(gate.get("classification", "")).strip().lower()
    if classification in _PROVIDER_GATE_CLASSIFICATIONS:
        return True
    provider = str(gate.get("provider", "")).strip().lower()
    if provider in {"", "dns", "fusekit"}:
        return False
    return str(gate.get("id", "")).startswith("provider.")


def _string_list_field(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


_FORBIDDEN_GUIDANCE_PHRASES = (
    "figure",
    "yourself",
    "hidden prompt",
    "hidden prompts",
    "paste into fusekit",
    "terminal prompt",
    "terminal prompts",
    "return to fusekit",
    "return here",
    "side-channel",
    "side channel",
)

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


def _guidance_quality_failures(
    label: str,
    *,
    follow_steps: Any,
    next_action: str,
    resume_hint: str,
    target: str,
    success_criteria: Any = (),
    avoid_steps: Any = (),
    requires_vm: bool,
    require_capture_resume: bool = True,
) -> list[str]:
    """Return launch-readiness failures for non-actionable human-gate guidance."""

    steps = follow_steps if isinstance(follow_steps, list) else []
    action_text = " ".join(str(item) for item in (*steps, next_action, resume_hint)).strip()
    detail_text = " ".join(
        str(item)
        for item in (
            *_string_list_field(success_criteria),
            *_string_list_field(avoid_steps),
        )
    )
    lowered = " ".join((action_text, detail_text)).strip().lower()
    action_lowered = action_text.lower()
    failures: list[str] = []
    for phrase in _FORBIDDEN_GUIDANCE_PHRASES:
        if phrase in lowered:
            failures.append(f"{label}.guidance contains non-launcher wording: {phrase}")
            break
    local_browser_failure = _local_browser_guidance_failure(lowered)
    if local_browser_failure:
        failures.append(f"{label}.guidance contains non-launcher wording: {local_browser_failure}")
    manual_action_failure = _manual_action_guidance_failure(lowered)
    if manual_action_failure:
        failures.append(f"{label}.guidance contains non-launcher wording: {manual_action_failure}")
    if requires_vm and "open provider gate in vm" not in action_lowered:
        failures.append(
            f"{label}.guidance does not name Open provider gate in VM for the VM browser path"
        )
    secret_targets = _env_targets_from_text(target)
    if secret_targets:
        if "capture <target> from vm clipboard" in action_lowered:
            failures.append(
                f"{label}.guidance uses placeholder Capture <TARGET> despite concrete "
                "secret targets"
            )
        missing_exact = _missing_exact_capture_controls(secret_targets, action_lowered)
        if "capture from vm clipboard" not in action_lowered and len(missing_exact) == len(
            secret_targets
        ):
            failures.append(
                f"{label}.guidance does not name Capture from VM clipboard for "
                + ", ".join(secret_targets)
            )
        if missing_exact:
            failures.append(
                f"{label}.guidance does not name exact Capture controls: "
                + ", ".join(missing_exact)
            )
        if require_capture_resume and not _capture_resume_guidance_ready(action_lowered):
            failures.append(
                f"{label}.guidance does not explain FuseKit resumes after clipboard capture"
            )
        next_lower = next_action.lower()
        if "i finished this step" in next_lower and "capture" not in next_lower:
            failures.append(f"{label}.next_action points secret targets at I finished this step")
    return failures


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


def _env_targets_from_text(value: str) -> list[str]:
    return list(
        dict.fromkeys(
            part.strip().upper()
            for part in str(value or "").split(",")
            if _ENV_TARGET_RE.match(part.strip().upper())
        )
    )


def _missing_exact_capture_controls(targets: list[str], text: str) -> list[str]:
    return [
        f"Capture {target} from VM clipboard"
        for target in targets
        if f"capture {target.lower()} from vm clipboard" not in text
    ]


def _capture_resume_guidance_ready(text: str) -> bool:
    lowered = str(text or "").lower()
    if "capture" not in lowered:
        return False
    if "resume automatically" in lowered or "continue automatically" in lowered:
        return True
    if re.search(r"\bfusekit\b.{0,96}\b(?:resume|continue|retry|verify|recheck)\b", lowered):
        return True
    return "requested verification automatically" in lowered


def _copy_once_targets_mentioned(value: str) -> list[str]:
    return list(
        dict.fromkeys(
            match.group(0).upper()
            for match in _COPY_ONCE_TARGET_RE.finditer(str(value or "").upper())
        )
    )


def _redacted_gate_state(raw: Any) -> dict[str, Any]:
    """Return non-secret gate proof data for public acceptance artifacts."""

    if not isinstance(raw, dict):
        return {"schema": "invalid", "gates": []}
    gates = raw.get("gates", [])
    if not isinstance(gates, list):
        return {"schema": "invalid", "gates": []}
    safe_gates: list[dict[str, Any]] = []
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        follow_steps = gate.get("follow_steps", [])
        captured_targets = gate.get("captured_targets", [])
        safe_gates.append(
            {
                "id": str(gate.get("id", "")),
                "provider": str(gate.get("provider", "")),
                "status": str(gate.get("status", "")),
                "classification": str(gate.get("classification", "")),
                "target": redact_public_text(str(gate.get("target", ""))),
                "attempts": _safe_int(gate.get("attempts"), default=0),
                "follow_step_count": len(follow_steps) if isinstance(follow_steps, list) else 0,
                "has_next_action": bool(str(gate.get("next_action", ""))),
                "has_resume_hint": bool(str(gate.get("resume_hint", ""))),
                "captured_count": (
                    len(captured_targets) if isinstance(captured_targets, list) else 0
                ),
                "has_resume_url": bool(str(gate.get("resume_url", ""))),
                "has_last_opened_url": bool(str(gate.get("last_opened_url", ""))),
            }
        )
    return {"schema": "fusekit.gates.redacted.v1", "gates": safe_gates}


def _safe_int(value: Any, *, default: int = -1) -> int:
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


def _check_gate_audit_events(
    gates_path: Path,
    audit_log_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    """Require control-room human interventions to leave redacted audit proof."""

    if not gates_path.exists() or not audit_log_path.exists():
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "skipped" if mode == "rehearsal" else "missing",
                "Gate/audit artifacts were not both available for intervention audit proof.",
            )
        )
        if mode == "live":
            missing.append("audited human gate interventions")
        return
    try:
        gate_raw = json.loads(gates_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "failed" if mode == "live" else "skipped",
                "Gate state could not be read for audit proof.",
            )
        )
        if mode == "live":
            missing.append("audited human gate interventions")
        return
    gates = gate_raw.get("gates", []) if isinstance(gate_raw, dict) else []
    gate_ids = [
        str(gate.get("id", ""))
        for gate in gates
        if isinstance(gate, dict) and str(gate.get("id", "")).strip()
    ]
    capture_requirements = _gate_capture_audit_requirements(gates)
    open_requirements = _gate_open_audit_requirements(gates)
    resume_requirements = _gate_resume_audit_requirements(gates)
    snapshot = ledger.snapshot_json(
        "gate-audit-proof",
        {
            "schema": "fusekit.gate-audit-proof.v1",
            "gate_count": len(gate_ids),
            "gates": [{"id": gate_id} for gate_id in gate_ids],
            "capture_requirements": [
                {"gate_id": gate_id, "target": target} for gate_id, target in capture_requirements
            ],
            "open_requirements": [{"gate_id": gate_id} for gate_id in open_requirements],
            "resume_requirements": [{"gate_id": gate_id} for gate_id in resume_requirements],
        },
    )
    if not gate_ids:
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "ok",
                "No control-room gates required intervention audit proof.",
                str(snapshot),
            )
        )
        return
    audit_events, audit_error = _control_room_audit_events(audit_log_path)
    if audit_error:
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "failed" if mode == "live" else "skipped",
                audit_error,
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("audited human gate interventions")
        return
    wake_path = gates_path.with_name("gate_events.jsonl")
    wake_ids_by_name, wake_error = _control_room_wake_event_ids(gates_path)
    if wake_error and wake_path.exists():
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "failed" if mode == "live" else "skipped",
                wake_error,
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("audited human gate interventions")
        return
    captured_targets = {
        (
            str(event.get("data", {}).get("gate_id", "")),
            str(event.get("data", {}).get("target", "")),
        )
        for event in audit_events
        if _gate_capture_audit_event_proves_vault_capture(
            event,
            wake_ids_by_name.get("clipboard_captured", set()),
        )
    }
    opened_gate_ids = {
        str(event.get("data", {}).get("gate_id", ""))
        for event in audit_events
        if _gate_open_audit_event_proves_vm_open(event)
    }
    resumed_gate_ids = {
        str(event.get("data", {}).get("gate_id", ""))
        for event in audit_events
        if _gate_resume_audit_event_proves_finished_click(
            event,
            wake_ids_by_name.get("resume_requested", set()),
        )
    }
    audited_gate_ids = (
        {gate_id for gate_id, _target in captured_targets} | opened_gate_ids | resumed_gate_ids
    )
    missing_gate_ids = [gate_id for gate_id in gate_ids if gate_id not in audited_gate_ids]
    missing_captures = [
        (gate_id, target)
        for gate_id, target in capture_requirements
        if (gate_id, target) not in captured_targets
    ]
    missing_opens = [gate_id for gate_id in open_requirements if gate_id not in opened_gate_ids]
    missing_resumes = [
        gate_id for gate_id in resume_requirements if gate_id not in resumed_gate_ids
    ]
    if missing_gate_ids or missing_captures or missing_opens or missing_resumes:
        details: list[str] = []
        if missing_gate_ids:
            details.append("missing gate events: " + ", ".join(missing_gate_ids))
        if missing_opens:
            details.append("missing control_room.gate_open: " + ", ".join(missing_opens))
        if missing_captures:
            details.append(
                "missing control_room.clipboard_capture: "
                + ", ".join(f"{gate_id}:{target}" for gate_id, target in missing_captures)
            )
        if missing_resumes:
            details.append(
                "missing control_room.gate_resume_requested: " + ", ".join(missing_resumes)
            )
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "failed" if mode == "live" else "skipped",
                "Control-room gates are missing redacted audit events: " + "; ".join(details),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("audited human gate interventions")
        return
    checks.append(
        AcceptanceCheck(
            "gates.audited",
            "ok",
            "Every durable control-room gate has redacted intervention audit proof.",
            str(snapshot),
        )
    )


_ENV_TARGET_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")
_COPY_ONCE_TARGET_RE = re.compile(
    r"\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PRIVATE_KEY)\b"
)


def _gate_capture_audit_requirements(gates: Any) -> list[tuple[str, str]]:
    """Return gate/target pairs that must prove launcher clipboard capture."""

    if not isinstance(gates, list):
        return []
    requirements: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "")).strip()
        if not gate_id:
            continue
        for target in _gate_secret_targets(gate):
            key = (gate_id, target)
            if key not in seen:
                requirements.append(key)
                seen.add(key)
    return requirements


def _gate_open_audit_requirements(gates: Any) -> list[str]:
    """Return gate ids that must prove launch through the control-room VM browser."""

    if not isinstance(gates, list):
        return []
    requirements: list[str] = []
    seen: set[str] = set()
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "")).strip()
        if not gate_id or gate_id in seen:
            continue
        if str(gate.get("resume_url", "")).strip():
            requirements.append(gate_id)
            seen.add(gate_id)
    return requirements


def _gate_resume_audit_requirements(gates: Any) -> list[str]:
    """Return gate ids that must prove a visible approve/finished click."""

    if not isinstance(gates, list):
        return []
    requirements: list[str] = []
    seen: set[str] = set()
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        gate_id = str(gate.get("id", "")).strip()
        if not gate_id or gate_id in seen:
            continue
        if _gate_secret_targets(gate):
            continue
        if _gate_requires_visible_resume(gate):
            requirements.append(gate_id)
            seen.add(gate_id)
    return requirements


def _gate_requires_visible_resume(gate: dict[str, Any]) -> bool:
    classification = str(gate.get("classification", "")).strip().lower()
    if classification in {"dns-approval", "setup-approval"} | _PROVIDER_GATE_CLASSIFICATIONS:
        return True
    provider = str(gate.get("provider", "")).strip().lower()
    if provider in {"dns", "fusekit"}:
        return True
    return str(gate.get("id", "")).startswith("provider.")


def _gate_open_audit_event_proves_vm_open(event: dict[str, Any]) -> bool:
    """Return whether an audit event proves a real control-room VM browser open."""

    data = event.get("data")
    return (
        str(event.get("event", "")) == "control_room.gate_open"
        and isinstance(data, dict)
        and data.get("protected_action") is True
        and data.get("reused") is False
        and data.get("has_resume_url") is True
        and data.get("has_last_opened_url") is True
        and bool(str(data.get("gate_id", "")).strip())
    )


def _gate_capture_audit_event_proves_vault_capture(
    event: dict[str, Any],
    wake_event_ids: set[str] | None = None,
) -> bool:
    """Return whether an audit event proves safe VM clipboard capture."""

    data = event.get("data")
    wake_event_id = ""
    if isinstance(data, dict):
        wake_event_id = str(data.get("capture_wake_event_id", "") or "").strip()
    return (
        str(event.get("event", "")) == "control_room.clipboard_capture"
        and isinstance(data, dict)
        and data.get("protected_action") is True
        and data.get("source") == "vm-clipboard"
        and data.get("storage") == "encrypted-vault"
        and (wake_event_ids is None or (bool(wake_event_id) and wake_event_id in wake_event_ids))
        and bool(str(data.get("gate_id", "")).strip())
        and bool(str(data.get("target", "")).strip())
        and bool(str(data.get("record_id", "")).strip())
    )


def _gate_resume_audit_event_proves_finished_click(
    event: dict[str, Any],
    wake_event_ids: set[str] | None = None,
) -> bool:
    """Return whether an audit event proves the protected finished-step action."""

    data = event.get("data")
    wake_event_id = ""
    if isinstance(data, dict):
        wake_event_id = str(data.get("wake_event_id", "") or "").strip()
    return (
        str(event.get("event", "")) == "control_room.gate_resume_requested"
        and isinstance(data, dict)
        and data.get("protected_action") is True
        and data.get("status") == "resume_requested"
        and (wake_event_ids is None or (bool(wake_event_id) and wake_event_id in wake_event_ids))
        and bool(str(data.get("gate_id", "")).strip())
    )


def _dns_apply_approval_domains(events: list[dict[str, Any]]) -> set[str]:
    """Return domains with protected DNS approval events."""

    domains: set[str] = set()
    for event in events:
        domain = _gate_resume_audit_event_dns_apply_domain(event)
        if domain:
            domains.add(domain)
    return domains


def _gate_resume_audit_event_dns_apply_domain(event: dict[str, Any]) -> str:
    """Return the approved DNS domain from a protected DNS approval event."""

    if not _gate_resume_audit_event_proves_finished_click(event):
        return ""
    data = event.get("data", {})
    if not isinstance(data, dict):
        return ""
    gate_id = str(data.get("gate_id", "")).strip().lower()
    provider = str(data.get("provider", "")).strip().lower()
    classification = str(data.get("classification", "")).strip().lower()
    if provider != "dns" and classification != "dns-approval" and not gate_id.startswith("dns."):
        return ""
    if not gate_id.startswith("dns.") or not gate_id.endswith(".approval"):
        return ""
    domain = gate_id.removeprefix("dns.").removesuffix(".approval").strip()
    return domain if domain else ""


def _gate_resume_audit_event_proves_dns_apply_approval(event: dict[str, Any]) -> bool:
    """Return whether an audit event proves the protected DNS approval action."""

    return bool(_gate_resume_audit_event_dns_apply_domain(event))


def _gate_secret_targets(gate: dict[str, Any]) -> list[str]:
    targets: list[str] = []
    target = str(gate.get("target", "")).strip()
    if target:
        targets.extend(part.strip() for part in target.split(","))
    captured_targets = gate.get("captured_targets", [])
    if isinstance(captured_targets, list):
        targets.extend(str(target).strip() for target in captured_targets)
    return list(dict.fromkeys(part for part in targets if _ENV_TARGET_RE.match(part)))


def _control_room_audit_events(audit_log_path: Path) -> tuple[list[dict[str, Any]], str]:
    allowed_events = {
        "control_room.gate_open",
        "control_room.gate_resume_requested",
        "control_room.clipboard_capture",
    }
    events: list[dict[str, Any]] = []
    try:
        lines = audit_log_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], "Audit log could not be read for gate intervention proof."
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return [], f"Audit log contains malformed JSONL at line {line_number}."
        if not isinstance(event, dict):
            return [], f"Audit log line {line_number} is not a JSON object."
        if str(event.get("event", "")) in allowed_events:
            events.append(event)
    return events, ""


def _control_room_wake_event_ids(gates_path: Path) -> tuple[dict[str, set[str]], str]:
    """Return non-secret gate wake event ids grouped by event name."""

    wake_path = gates_path.with_name("gate_events.jsonl")
    ids: dict[str, set[str]] = {}
    if not wake_path.exists():
        return ids, "Gate wake events were not available for audit proof."
    try:
        lines = wake_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ids, "Gate wake events could not be read for audit proof."
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return ids, f"Gate wake events contain malformed JSONL at line {line_number}."
        if not isinstance(event, dict):
            return ids, f"Gate wake event line {line_number} is not a JSON object."
        public_safety_failures = _standalone_artifact_public_safety_failures(
            event,
            f"gate_events[{line_number}]",
        )
        if public_safety_failures:
            return ids, public_safety_failures[0]
        event_name = str(event.get("event", "") or "").strip()
        event_id = str(event.get("id", "") or "").strip()
        if event_name and event_id:
            ids.setdefault(event_name, set()).add(event_id)
    return ids, ""


def _check_rollback_metadata(
    rollback_path: Path,
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not rollback_path.exists():
        status = "skipped" if mode == "rehearsal" else "missing"
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.actionable",
                status,
                f"Rollback metadata not found: {rollback_path}",
            )
        )
        if mode == "live":
            missing.append("rollback metadata")
        return
    try:
        raw = json.loads(rollback_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.actionable",
                "failed",
                "Rollback metadata could not be read.",
            )
        )
        missing.append("rollback metadata")
        return
    snapshot = ledger.snapshot_json("rollback-metadata", raw)
    if isinstance(raw, dict):
        public_safety_failures = _standalone_artifact_public_safety_failures(
            raw,
            "rollback_metadata",
        )
    else:
        public_safety_failures = []
    if public_safety_failures:
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.actionable",
                "failed" if mode == "live" else "skipped",
                "Rollback metadata contains unsafe public text: "
                + "; ".join(public_safety_failures[:20]),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("rollback metadata")
        return
    actions_raw = raw.get("rollback", raw.get("actions", [])) if isinstance(raw, dict) else []
    actions = actions_raw if isinstance(actions_raw, list) else []
    shape_failures = _rollback_metadata_shape_failures(raw if isinstance(raw, dict) else {})
    if shape_failures:
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.actionable",
                "failed" if mode == "live" else "skipped",
                "Rollback metadata has loose public proof: "
                + "; ".join(shape_failures[:20]),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("rollback metadata")
        return
    actionable = [
        item
        for item in actions
        if isinstance(item, dict)
        and str(item.get("action", "")).startswith("rollback.")
        and str(item.get("status", "")) in ROLLBACK_PROOF_STATUSES
    ]
    if not actionable:
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.actionable",
                "failed" if mode == "live" else "skipped",
                "Rollback metadata has no provider rollback actions.",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("rollback metadata")
        return
    checks.append(
        AcceptanceCheck(
            "rollback_metadata.actionable",
            "ok",
            f"Rollback metadata contains {len(actionable)} provider action(s).",
            str(snapshot),
        )
    )
    _check_rollback_provider_coverage(
        actionable,
        manifest,
        mode,
        checks,
        missing,
        str(snapshot),
    )


def _rollback_metadata_shape_failures(raw: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(raw) - ROLLBACK_METADATA_KEYS)
    if unexpected:
        failures.append("rollback_metadata has unexpected fields: " + ", ".join(unexpected))
    actions = raw.get("rollback", raw.get("actions", []))
    if not isinstance(actions, list):
        return failures
    for index, action in enumerate(actions):
        label = f"rollback_metadata.rollback[{index}]"
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


def _check_rollback_provider_coverage(
    actions: list[Any],
    manifest: SetupManifest,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require rollback evidence for every provider requested by the manifest."""

    required = _manifest_provider_names(manifest)
    if not required:
        return
    recorded = _rollback_provider_names(actions)
    absent = sorted(required - recorded)
    if absent:
        checks.append(
            AcceptanceCheck(
                "rollback_metadata.coverage",
                "failed" if mode == "live" else "skipped",
                "Rollback metadata is missing manifest providers: " + ", ".join(absent),
                artifact,
            )
        )
        if mode == "live":
            missing.append("complete rollback coverage")
        return
    checks.append(
        AcceptanceCheck(
            "rollback_metadata.coverage",
            "ok",
            "Rollback metadata covers every provider declared by the manifest.",
            artifact,
        )
    )


def _rollback_provider_names(actions: list[Any]) -> set[str]:
    providers: set[str] = set()
    for item in actions:
        if not isinstance(item, dict):
            continue
        provider = str(item.get("provider", "")).strip().lower()
        if provider:
            providers.add(provider)
            continue
        action = str(item.get("action", "")).strip().lower()
        parts = action.split(".")
        if len(parts) >= 3 and parts[0] == "rollback" and parts[1] == "dns":
            providers.add(parts[2])
            continue
        if len(parts) >= 2 and parts[0] == "rollback" and parts[1]:
            providers.add(parts[1])
    return providers


def _check_detonation(
    fusekit_dir: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
) -> None:
    survivors = [
        path
        for name in DETONATION_PLAINTEXT_PATHS
        if _detonation_survivor(path := fusekit_dir / name)
    ]
    if survivors:
        checks.append(
            AcceptanceCheck(
                "detonation.worker_state",
                "failed",
                "Plaintext worker/browser/visual state still exists: "
                + ", ".join(redact_public_path(path) for path in survivors),
            )
        )
        missing.append("detonated worker state")
        return
    checks.append(
        AcceptanceCheck(
            "detonation.worker_state",
            "ok",
            "Worker, browser, visual, and auth scratch state is detonated or absent.",
        )
    )
    if mode == "live" and not fusekit_dir.exists():
        missing.append("FuseKit artifact directory")
    _check_workspace_detonation_receipt(fusekit_dir, mode, checks, missing)


def _check_workspace_detonation_receipt(
    fusekit_dir: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
) -> None:
    """Require proof that the disposable OCI workspace was actually destroyed."""

    receipt_path = fusekit_dir / "workspace_detonation.json"
    if not receipt_path.exists():
        if mode == "live":
            checks.append(
                AcceptanceCheck(
                    "detonation.workspace_receipt",
                    "missing",
                    "Live OCI workspace detonation receipt not found: "
                    + redact_public_path(receipt_path),
                )
            )
            missing.append("OCI workspace detonation receipt")
            return
        checks.append(
            AcceptanceCheck(
                "detonation.workspace_receipt",
                "ok",
                "Workspace detonation receipt not present; rehearsal does not require OCI.",
            )
        )
        return
    try:
        raw = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "detonation.workspace_receipt",
                "failed",
                "Workspace detonation receipt could not be read as a JSON object.",
                str(receipt_path),
            )
        )
        if mode == "live":
            missing.append("OCI workspace detonation receipt")
        return
    if not isinstance(raw, dict):
        checks.append(
            AcceptanceCheck(
                "detonation.workspace_receipt",
                "failed",
                "Workspace detonation receipt was not a JSON object.",
                str(receipt_path),
            )
        )
        if mode == "live":
            missing.append("OCI workspace detonation receipt")
        return
    failures = _workspace_detonation_receipt_failures(raw, label="workspace_detonation")
    if failures:
        checks.append(
            AcceptanceCheck(
                "detonation.workspace_receipt",
                "failed" if mode == "live" else "skipped",
                "Workspace detonation receipt is incomplete: " + "; ".join(failures),
                str(receipt_path),
            )
        )
        if mode == "live":
            missing.append("OCI workspace detonation receipt")
        return
    checks.append(
        AcceptanceCheck(
            "detonation.workspace_receipt",
            "ok",
            "OCI workspace detonation receipt proves VM, boot volume, public IP, "
            "network resources, and remote worker cleanup.",
            str(receipt_path),
        )
    )


def _detonation_survivor(path: Path) -> bool:
    if not path.exists():
        return False
    if path.is_dir():
        return any(path.iterdir())
    return True


def _check_visual_state(
    visual_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if not visual_path.exists():
        if mode == "live":
            checks.append(
                AcceptanceCheck(
                    "visual_state.safe",
                    "missing",
                    "Live visual session state not found: " + redact_public_path(visual_path),
                )
            )
            missing.append("safe visual session state")
            return
        checks.append(
            AcceptanceCheck(
                "visual_state.safe",
                "ok",
                "Visual session state not present; no surviving visual state to validate.",
            )
        )
        return
    try:
        raw = json.loads(visual_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "visual_state.safe",
                "failed",
                "Visual session state could not be read as a JSON object.",
            )
        )
        if mode == "live":
            missing.append("safe visual session state")
        return
    if not isinstance(raw, dict):
        checks.append(
            AcceptanceCheck(
                "visual_state.safe",
                "failed",
                "Visual session state was not a JSON object.",
            )
        )
        if mode == "live":
            missing.append("safe visual session state")
        return

    sanitized = _sanitized_visual_state(raw)
    snapshot = ledger.snapshot_json("visual-state", sanitized)
    live_failures = _live_visual_state_failures(sanitized) if mode == "live" else []
    if mode == "live" and not str(raw.get("novnc_url", "") or "").strip() and live_failures:
        checks.append(
            AcceptanceCheck(
                "visual_state.safe",
                "failed",
                "Live visual session state is incomplete: " + ", ".join(live_failures) + ".",
                str(snapshot),
            )
        )
        missing.append("safe visual session state")
        return
    unsafe_fields = _unsafe_visual_state_fields(raw, sanitized)
    if unsafe_fields:
        checks.append(
            AcceptanceCheck(
                "visual_state.safe",
                "failed",
                "Visual session state contains unsafe " + ", ".join(unsafe_fields) + ".",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("safe visual session state")
        return
    public_safety_failures = _visual_state_public_safety_failures(raw)
    if public_safety_failures:
        checks.append(
            AcceptanceCheck(
                "visual_state.safe",
                "failed",
                "Visual session state contains unsafe public text: "
                + "; ".join(public_safety_failures[:20]),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("safe visual session state")
        return
    shape_failures = _visual_state_shape_failures(raw) if mode == "live" else []
    if live_failures:
        failures = [*shape_failures, *live_failures]
        checks.append(
            AcceptanceCheck(
                "visual_state.safe",
                "failed",
                "Live visual session state is incomplete: " + ", ".join(failures) + ".",
                str(snapshot),
            )
        )
        missing.append("safe visual session state")
        return
    if shape_failures:
        checks.append(
            AcceptanceCheck(
                "visual_state.safe",
                "failed",
                "Visual session state does not match generated launch proof: "
                + ", ".join(shape_failures)
                + ".",
                str(snapshot),
            )
        )
        missing.append("safe visual session state")
        return
    checks.append(
        AcceptanceCheck(
            "visual_state.safe",
            "ok",
            "Visual session state is safe to preserve and embed.",
            str(snapshot),
        )
    )


def _check_runner_readiness(
    readiness_path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    """Require proof that the disposable runner was prepared before provider gates."""

    if not readiness_path.exists():
        if mode == "live":
            checks.append(
                AcceptanceCheck(
                    "runner_readiness.prepared",
                    "missing",
                    "Live runner readiness proof not found: " + redact_public_path(readiness_path),
                )
            )
            missing.append("prepared runner readiness proof")
            return
        checks.append(
            AcceptanceCheck(
                "runner_readiness.prepared",
                "ok",
                "Runner readiness proof not present; rehearsal does not require a live runner.",
            )
        )
        return
    try:
        raw = json.loads(readiness_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        checks.append(
            AcceptanceCheck(
                "runner_readiness.prepared",
                "failed",
                "Runner readiness proof could not be read as a JSON object.",
            )
        )
        if mode == "live":
            missing.append("prepared runner readiness proof")
        return
    if not isinstance(raw, dict):
        checks.append(
            AcceptanceCheck(
                "runner_readiness.prepared",
                "failed",
                "Runner readiness proof was not a JSON object.",
            )
        )
        if mode == "live":
            missing.append("prepared runner readiness proof")
        return
    snapshot = ledger.snapshot_json("runner-readiness", _public_runner_readiness_summary(raw))
    public_safety_failures = _standalone_artifact_public_safety_failures(
        raw,
        "runner_readiness",
    )
    if public_safety_failures:
        checks.append(
            AcceptanceCheck(
                "runner_readiness.prepared",
                "failed" if mode == "live" else "skipped",
                "Runner readiness proof contains unsafe public text: "
                + "; ".join(public_safety_failures[:20]),
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("prepared runner readiness proof")
        return
    failures = _runner_readiness_failures(raw)
    if failures:
        checks.append(
            AcceptanceCheck(
                "runner_readiness.prepared",
                "failed",
                "Runner readiness proof is incomplete: " + ", ".join(failures) + ".",
                str(snapshot),
            )
        )
        if mode == "live":
            missing.append("prepared runner readiness proof")
        return
    checks.append(
        AcceptanceCheck(
            "runner_readiness.prepared",
            "ok",
            "Prepared x86_64 browser runner proof is present.",
            str(snapshot),
        )
    )


def _durable_state_shape_failures(durable_state: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(durable_state.get("schema_version", "")).strip() != DURABLE_STATE_SCHEMA_VERSION:
        failures.append("durable_state.schema_version is unsupported")
    if durable_state.get("resume_ready") is not True:
        missing = durable_state.get("missing", [])
        detail = ", ".join(str(item) for item in missing) if isinstance(missing, list) else ""
        failures.append(f"durable_state.resume_ready is not true{': ' + detail if detail else ''}")
    sources = durable_state.get("sources", [])
    source_ids: set[str] = set()
    if not isinstance(sources, list) or not sources:
        failures.append("durable_state.sources is missing")
    else:
        for index, source in enumerate(sources):
            label = f"durable_state.sources[{index}]"
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
            volatile_marker = _volatile_durable_state_marker(source)
            if volatile_marker:
                failures.append(f"{label} preserves volatile worker state: {volatile_marker}")
        required = {source_id for source_id, _path, _role, _secret in DURABLE_STATE_SOURCES}
        missing_ids = sorted(required - source_ids)
        if missing_ids:
            failures.append("durable_state.sources missing " + ", ".join(missing_ids))
    runner_failures = durable_state.get("runner_profile_failures", [])
    if durable_state.get("runner_profile_ready") is not True:
        failures.append("durable_state.runner_profile_ready must be true")
    if not isinstance(runner_failures, list):
        failures.append("durable_state.runner_profile_failures must be a list")
    elif runner_failures:
        failures.append(
            "durable_state.runner_profile_failures must be empty: "
            + ", ".join(str(item) for item in runner_failures)
        )
    volatile = durable_state.get("volatile_worker_surfaces", [])
    volatile_values = {str(item) for item in volatile} if isinstance(volatile, list) else set()
    if not isinstance(volatile, list) or not {"worker", "visual", "openclaw-state"}.issubset(
        volatile_values
    ):
        failures.append("durable_state.volatile_worker_surfaces is incomplete")
    else:
        _append_duplicate_text_failures(
            failures,
            "durable_state.volatile_worker_surfaces",
            volatile,
        )
    preserves = durable_state.get("detonation_preserves", [])
    preserve_values = {str(item) for item in preserves} if isinstance(preserves, list) else set()
    if not isinstance(preserves, list) or preserve_values != set(DETONATION_PRESERVES):
        failures.append("durable_state.detonation_preserves is incomplete")
    else:
        _append_duplicate_text_failures(
            failures,
            "durable_state.detonation_preserves",
            preserves,
        )
        volatile_preserves = sorted(
            value for value in preserve_values if _volatile_durable_text_marker(value)
        )
        if volatile_preserves:
            failures.append(
                "durable_state.detonation_preserves must not include volatile worker state: "
                + ", ".join(volatile_preserves)
            )
    detonation_scope = durable_state.get("detonation_scope")
    if not isinstance(detonation_scope, dict):
        failures.append("durable_state.detonation_scope is missing")
    else:
        if (
            str(detonation_scope.get("schema_version", "")).strip()
            != DETONATION_SCOPE_SCHEMA_VERSION
        ):
            failures.append("durable_state.detonation_scope.schema_version is unsupported")
        if (
            str(detonation_scope.get("mode", "")).strip()
            != AUTOMATION_BOUNDARY_DETONATION_SCOPE
        ):
            failures.append("durable_state.detonation_scope.mode is unsupported")
        must_delete = detonation_scope.get("must_delete", [])
        required_delete = {
            *VOLATILE_WORKER_SURFACES,
            *OCI_WORKSPACE_DETONATION_SURFACES,
        }
        if not isinstance(must_delete, list) or not required_delete.issubset(
            {str(item) for item in must_delete}
        ):
            failures.append("durable_state.detonation_scope.must_delete is incomplete")
        elif volatile_values and not volatile_values.issubset({str(item) for item in must_delete}):
            failures.append(
                "durable_state.detonation_scope.must_delete must cover volatile_worker_surfaces"
            )
        else:
            _append_duplicate_text_failures(
                failures,
                "durable_state.detonation_scope.must_delete",
                must_delete,
            )
        must_preserve = detonation_scope.get("must_preserve", [])
        must_preserve_values = (
            {str(item) for item in must_preserve} if isinstance(must_preserve, list) else set()
        )
        if not isinstance(must_preserve, list) or not {"encrypted_vault", "run_record"}.issubset(
            must_preserve_values
        ):
            failures.append("durable_state.detonation_scope.must_preserve is incomplete")
        elif any(_volatile_durable_text_marker(value) for value in must_preserve_values):
            volatile_preserves = sorted(
                value for value in must_preserve_values if _volatile_durable_text_marker(value)
            )
            failures.append(
                "durable_state.detonation_scope.must_preserve must not include "
                "volatile worker state: " + ", ".join(volatile_preserves)
            )
        elif preserve_values and preserve_values != must_preserve_values:
            failures.append(
                "durable_state.detonation_scope.must_preserve must match detonation_preserves"
            )
        else:
            _append_duplicate_text_failures(
                failures,
                "durable_state.detonation_scope.must_preserve",
                must_preserve,
            )
        if detonation_scope.get("resume_until_complete") is not True:
            failures.append("durable_state.detonation_scope.resume_until_complete must be true")
        if detonation_scope.get("host_machine_state_required") is not False:
            failures.append(
                "durable_state.detonation_scope.host_machine_state_required must be false"
            )
        no_trace_statement = str(detonation_scope.get("no_trace_statement", "") or "")
        if not all(term in no_trace_statement for term in DETONATION_SCOPE_NO_TRACE_TERMS):
            failures.append("durable_state.detonation_scope.no_trace_statement is incomplete")
    statement = str(durable_state.get("statement", "") or "")
    if not all(term in statement for term in DURABLE_STATE_STATEMENT_TERMS):
        failures.append("durable_state.statement is missing durable-worker guidance")
    replacement = durable_state.get("worker_replacement_contract")
    if not isinstance(replacement, dict):
        failures.append("durable_state.worker_replacement_contract is missing")
    else:
        if replacement.get("worker_is_disposable") is not True:
            failures.append(
                "durable_state.worker_replacement_contract.worker_is_disposable must be true"
            )
        if replacement.get("can_recreate_worker") is not True:
            failures.append(
                "durable_state.worker_replacement_contract.can_recreate_worker must be true"
            )
        if replacement.get("runner_profile_ready") is not True:
            failures.append(
                "durable_state.worker_replacement_contract.runner_profile_ready must be true"
            )
        if (
            str(replacement.get("required_runner_profile", "") or "")
            != EXPECTED_RUNNER_PROFILE
        ):
            failures.append(
                "durable_state.worker_replacement_contract.required_runner_profile is unsupported"
            )
        if replacement.get("host_machine_state_required") is not False:
            failures.append(
                "durable_state.worker_replacement_contract.host_machine_state_required "
                "must be false"
            )
        if str(replacement.get("state_owner", "") or "") != WORKER_REPLACEMENT_STATE_OWNER:
            failures.append("durable_state.worker_replacement_contract.state_owner is unsupported")
        resume_sources = replacement.get("resume_sources", [])
        resume_source_values = (
            {str(item) for item in resume_sources} if isinstance(resume_sources, list) else set()
        )
        required_resume_sources = set(WORKER_REPLACEMENT_SOURCE_IDS)
        if not isinstance(resume_sources, list) or not required_resume_sources.issubset(
            resume_source_values
        ):
            failures.append(
                "durable_state.worker_replacement_contract.resume_sources is incomplete"
            )
        elif any(_volatile_durable_text_marker(value) for value in resume_source_values):
            volatile_resume_sources = sorted(
                value for value in resume_source_values if _volatile_durable_text_marker(value)
            )
            failures.append(
                "durable_state.worker_replacement_contract.resume_sources must not include "
                "volatile worker state: " + ", ".join(volatile_resume_sources)
            )
        elif source_ids and not resume_source_values.issubset(source_ids):
            failures.append(
                "durable_state.worker_replacement_contract.resume_sources must "
                "reference durable_state.sources"
            )
        else:
            _append_duplicate_text_failures(
                failures,
                "durable_state.worker_replacement_contract.resume_sources",
                resume_sources,
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
                "durable_state.worker_replacement_contract.volatile_surfaces must "
                "cover volatile_worker_surfaces"
            )
        else:
            _append_duplicate_text_failures(
                failures,
                "durable_state.worker_replacement_contract.volatile_surfaces",
                replacement_volatile,
            )
        replacement_statement = str(replacement.get("statement", "") or "")
        if not all(term in replacement_statement for term in WORKER_REPLACEMENT_STATEMENT_TERMS):
            failures.append("durable_state.worker_replacement_contract.statement is incomplete")
    return failures


def _append_duplicate_text_failures(
    failures: list[str],
    label: str,
    values: list[Any],
) -> None:
    for value in _duplicate_text_values(values):
        failures.append(f"{label} contains duplicate {value}")


def _duplicate_text_values(values: list[Any]) -> list[str]:
    seen_values: set[str] = set()
    duplicate_values: list[str] = []
    for value in values:
        text = str(value).strip()
        if not text:
            continue
        if text in seen_values and text not in duplicate_values:
            duplicate_values.append(text)
        seen_values.add(text)
    return duplicate_values


def _worker_replacement_drill_shape_failures(drill: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(drill) - WORKER_REPLACEMENT_DRILL_KEYS)
    if unexpected:
        failures.append(
            "worker_replacement_drill has unexpected fields: " + ", ".join(unexpected)
        )
    schema_version = str(drill.get("schema_version", "") or "")
    if schema_version != schema_version.strip():
        failures.append(
            "worker_replacement_drill.schema_version must not have surrounding whitespace"
        )
    if schema_version != WORKER_REPLACEMENT_DRILL_SCHEMA_VERSION:
        failures.append("worker_replacement_drill.schema_version is unsupported")
    status = str(drill.get("status", "") or "")
    if status != status.strip():
        failures.append(
            "worker_replacement_drill.status must not have surrounding whitespace"
        )
    if status != "passed":
        failures.append("worker_replacement_drill.status must be passed")
    for drill_field in (
        "worker_destroyed",
        "replacement_runner_profile_ready",
        "control_room_reopened",
        "resume_checkpoint_restored",
        "gate_or_verifier_resumed",
    ):
        if drill.get(drill_field) is not True:
            failures.append(f"worker_replacement_drill.{drill_field} must be true")
    if drill.get("host_machine_state_required") is not False:
        failures.append("worker_replacement_drill.host_machine_state_required must be false")
    if drill.get("volatile_state_reused") is not False:
        failures.append("worker_replacement_drill.volatile_state_reused must be false")
    restored_from = drill.get("restored_from", [])
    if isinstance(restored_from, list):
        for index, item in enumerate(restored_from):
            if not isinstance(item, str) or not item:
                failures.append(f"worker_replacement_drill.restored_from[{index}] must be text")
            elif item != item.strip():
                failures.append(
                    "worker_replacement_drill.restored_from"
                    f"[{index}] must not have surrounding whitespace"
                )
    restored_values = (
        {str(item) for item in restored_from} if isinstance(restored_from, list) else set()
    )
    required_restore = set(WORKER_REPLACEMENT_SOURCE_IDS)
    if not isinstance(restored_from, list) or restored_values != required_restore:
        failures.append(
            "worker_replacement_drill.restored_from must match durable replacement source ids"
        )
    else:
        _append_duplicate_text_failures(
            failures,
            "worker_replacement_drill.restored_from",
            restored_from,
        )
        volatile_restores = sorted(
            value for value in restored_values if _volatile_durable_text_marker(value)
        )
        if volatile_restores:
            failures.append(
                "worker_replacement_drill.restored_from must not include volatile "
                "worker state: " + ", ".join(volatile_restores)
            )
    statement = str(drill.get("statement", "") or "")
    if statement != statement.strip():
        failures.append(
            "worker_replacement_drill.statement must not have surrounding whitespace"
        )
    if (
        "encrypted/redacted" not in statement
        or "no host-machine state" not in statement
        or "no VM-local plaintext" not in statement
    ):
        failures.append("worker_replacement_drill.statement is incomplete")
    if "pending_reason" in drill:
        pending_reason = drill.get("pending_reason")
        if not isinstance(pending_reason, str):
            failures.append("worker_replacement_drill.pending_reason must be text")
        elif pending_reason != pending_reason.strip():
            failures.append(
                "worker_replacement_drill.pending_reason must not have surrounding whitespace"
            )
    return failures


def _volatile_durable_state_marker(source: dict[str, Any]) -> str:
    if str(source.get("id", "") or "") == "worker_replacement_drill":
        return _volatile_durable_text_marker(str(source.get("role", "") or ""))
    text = " ".join(str(source.get(field, "") or "") for field in ("id", "path", "role"))
    return _volatile_durable_text_marker(text)


def _volatile_durable_text_marker(value: str) -> str:
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


def _provider_playbook_shape_failures(playbook: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(playbook.get("schema_version", "")).strip() != "fusekit.provider-playbook.v1":
        failures.append("provider_playbook.schema_version is unsupported")
    steps = playbook.get("steps", [])
    if not isinstance(steps, list) or not steps:
        failures.append("provider_playbook.steps is missing")
    else:
        step_ids: list[str] = []
        for index, step in enumerate(steps):
            label = f"provider_playbook.steps[{index}]"
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
            if not step_id:
                failures.append(f"{label}.id is missing")
            else:
                step_ids.append(step_id)
            provider = str(step.get("provider", "") or "").strip()
            if not provider:
                failures.append(f"{label}.provider is missing")
            route = str(step.get("route", "") or "").strip()
            if route not in {
                "api",
                "official_cli",
                "browser_guided",
                "human_follow_me",
                "local_vault",
            }:
                failures.append(f"{label}.route is unsupported")
            control = str(step.get("control", "") or "").strip()
            if not control:
                failures.append(f"{label}.control is missing")
            instruction = str(step.get("instruction", "") or "")
            if not instruction.strip():
                failures.append(f"{label}.instruction is missing")
            if _provider_playbook_instruction_is_unsafe(instruction):
                failures.append(f"{label}.instruction asks for unsafe provider work")
            failures.extend(
                _provider_playbook_actor_failures(
                    label,
                    route=route,
                    actor=str(step.get("actor", "") or "").strip(),
                    human_action_required=step.get("human_action_required"),
                )
            )
            failures.extend(
                _provider_playbook_control_failures(
                    label,
                    step_id=step_id,
                    route=route,
                    control=control,
                )
            )
            failures.extend(
                _provider_playbook_proof_failures(
                    label,
                    route=route,
                    proof_source=str(step.get("proof_source", "") or "").strip(),
                    resume_event=str(step.get("resume_event", "") or "").strip(),
                )
            )
        failures.extend(_provider_playbook_order_failures(step_ids))
        failures.extend(_provider_playbook_provider_coverage_failures(steps))
    safety_notes = playbook.get("safety_notes", [])
    if not isinstance(safety_notes, list) or not safety_notes:
        failures.append("provider_playbook.safety_notes is missing")
    else:
        notes = " ".join(str(note) for note in safety_notes)
        failures.extend(_provider_playbook_safety_note_failures(safety_notes))
        for required in (
            "VM browser",
            "Do not create Resend domains or audiences manually",
            "Do not paste provider secrets into the host computer",
        ):
            if required not in notes:
                failures.append(f"provider_playbook.safety_notes must include {required}")
    return failures


RECORDING_PROVIDER_PLAYBOOK_FAMILIES = PROVIDER_PLAYBOOK_FAMILIES
_PROVIDER_PLAYBOOK_STEP_KEYS = PROVIDER_PLAYBOOK_STEP_KEYS


def _provider_playbook_actor_failures(
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


def _provider_playbook_provider_coverage_failures(steps: list[Any]) -> list[str]:
    providers = {
        str(step.get("provider", "") or "").strip().lower()
        for step in steps
        if isinstance(step, dict)
    }
    required = {
        "GitHub": {"github"},
        "Resend": {"resend"},
        "Vercel": {"vercel"},
        "DNS/Cloudflare": {"dns", "cloudflare"},
    }
    missing = sorted(label for label, accepted in required.items() if not accepted & providers)
    if not missing:
        return []
    return [
        "provider_playbook.steps missing public demo provider coverage: "
        + ", ".join(missing)
    ]


def _provider_playbook_safety_note_failures(safety_notes: list[Any]) -> list[str]:
    failures: list[str] = []
    seen: set[str] = set()
    for index, note in enumerate(safety_notes):
        label = f"provider_playbook.safety_notes[{index}]"
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


def _provider_playbook_control_failures(
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
        and control != ("Capture RESEND_API_KEY from VM clipboard")
    ):
        failures.append(f"{label}.control must capture RESEND_API_KEY before Resend API setup")
    return failures


def _provider_playbook_proof_failures(
    label: str,
    *,
    route: str,
    proof_source: str,
    resume_event: str,
) -> list[str]:
    if not route:
        return []
    failures: list[str] = []
    if not proof_source:
        failures.append(f"{label}.proof_source is missing")
    if not resume_event:
        failures.append(f"{label}.resume_event is missing")
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
            failures.append(
                f"{label}.resume_event must be a known follow-me wake event"
            )
    return failures


def _provider_playbook_order_failures(step_ids: list[str]) -> list[str]:
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
        f"provider_playbook.steps has duplicate id {step_id}" for step_id in duplicates
    ]
    for before, after in required_pairs:
        before_position = positions.get(before)
        after_position = positions.get(after)
        if before_position is None or after_position is None:
            continue
        if before_position > after_position:
            failures.append(f"provider_playbook.steps must place {before} before {after}")
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


def _int_field(value: object, default: int) -> int:
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


def _visual_state_public_safety_failures(raw: dict[str, Any]) -> list[str]:
    """Reject unsafe survivor text without treating expected visual transport as leaks."""

    failures: list[str] = []
    for name in VISUAL_TRANSPORT_FIELDS:
        value = raw.get(name)
        if not isinstance(value, str):
            continue
        if _contains_callback_url(value):
            failures.append(f"visual_state.{name} contains callback URL")
            continue
        if name == "novnc_password" and contains_durable_secret_text(value):
            failures.append(f"visual_state.{name} contains credential-looking text")
    extra = {key: value for key, value in raw.items() if key not in VISUAL_TRANSPORT_FIELDS}
    failures.extend(_standalone_artifact_public_safety_failures(extra, "visual_state"))
    return failures


def _visual_state_shape_failures(raw: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    unexpected = sorted(set(raw) - VISUAL_STATE_KEYS)
    if unexpected:
        failures.append("artifact has unexpected fields: " + ", ".join(unexpected))
    missing = sorted(VISUAL_STATE_KEYS - set(raw))
    if missing:
        failures.append("artifact is missing generated fields: " + ", ".join(missing))
    for visual_field in VISUAL_STATE_TEXT_FIELDS:
        if visual_field not in raw:
            continue
        value = raw[visual_field]
        if not isinstance(value, str):
            failures.append(f"{visual_field} must be text")
            continue
        if value != value.strip():
            failures.append(f"{visual_field} must be trimmed")
    if raw.get("display") != VISUAL_STATE_DISPLAY:
        failures.append(f"display must be {VISUAL_STATE_DISPLAY}")
    notes = raw.get("notes")
    if not isinstance(notes, list):
        failures.append("notes must be a list")
    else:
        _append_duplicate_text_failures(failures, "notes", notes)
        if tuple(notes) != VISUAL_STATE_NOTES:
            failures.append("notes must match generated visual-session guidance")
        for index, note in enumerate(notes):
            if not isinstance(note, str):
                failures.append(f"notes[{index}] must be text")
                continue
            if note != note.strip():
                failures.append(f"notes[{index}] must be trimmed")
    return failures


def _unsafe_visual_state_fields(raw: dict[str, Any], sanitized: dict[str, Any]) -> list[str]:
    unsafe: list[str] = []
    if "novnc_url" in raw and raw.get("novnc_url") != sanitized.get("novnc_url"):
        unsafe.append("noVNC URL")
    if "control_room_url" in raw and raw.get("control_room_url") != sanitized.get(
        "control_room_url"
    ):
        unsafe.append("control-room URL")
    if "novnc_password" in raw and raw.get("novnc_password") != sanitized.get("novnc_password"):
        unsafe.append("noVNC password metadata")
    if "provider_browser_profile" in raw and raw.get("provider_browser_profile") != sanitized.get(
        "provider_browser_profile"
    ):
        unsafe.append("provider browser profile metadata")
    return unsafe


def _live_visual_state_failures(visual: dict[str, Any]) -> list[str]:
    """Return missing live-session guarantees for public demo readiness."""

    failures: list[str] = []
    if str(visual.get("runner", "")).strip() != VISUAL_STATE_RUNNER:
        failures.append(f"runner must be {VISUAL_STATE_RUNNER}")
    if str(visual.get("status", "")).strip() != VISUAL_STATE_STATUS:
        failures.append(f"status must be {VISUAL_STATE_STATUS}")
    if visual.get("interactive") is not True:
        failures.append("interactive must be true")
    if not str(visual.get("novnc_url", "") or "").strip():
        failures.append("safe noVNC URL is required")
    if not str(visual.get("control_room_url", "") or "").strip():
        failures.append("safe control-room URL is required")
    if not str(visual.get("novnc_password", "") or "").strip():
        failures.append("noVNC password metadata is required")
    if str(visual.get("provider_browser_profile", "")).strip() != (
        EXPECTED_PROVIDER_BROWSER_PROFILE
    ):
        failures.append("shared provider browser profile metadata is required")
    return failures


def _check_leaks(
    app_path: Path,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    findings = scan_for_secret_leaks(app_path)
    snapshot = ledger.snapshot_json(
        "leak-scan",
        {"findings": [finding.to_dict() for finding in findings]},
    )
    if findings:
        checks.append(
            AcceptanceCheck(
                "leak_scan.clean",
                "failed",
                f"Secret-looking plaintext findings: {len(findings)}",
                str(snapshot),
            )
        )
        missing.append("clean leak scan")
    else:
        checks.append(
            AcceptanceCheck(
                "leak_scan.clean",
                "ok",
                "No plaintext secret findings.",
                str(snapshot),
            )
        )
