"""Acceptance harness for FuseKit launch readiness."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fusekit.detonation.preflight import (
    verification_report_failures,
)
from fusekit.errors import FuseKitError, VaultError
from fusekit.harness.ledger import HarnessLedger
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
from fusekit.runner.control_room.state import _sanitized_visual_state
from fusekit.runner.readiness import (
    EXPECTED_PROVIDER_BROWSER_PROFILE,
)
from fusekit.runner.readiness import (
    runner_profile_contract_failures as _runner_profile_contract_failures,
)
from fusekit.runner.readiness import (
    runner_readiness_failures as _runner_readiness_failures,
)
from fusekit.runner.run_record import (
    AUDIT_TRAIL_SCHEMA_VERSION,
    AUTOMATION_BOUNDARY_SCHEMA_VERSION,
    RECORDING_CONTRACT_SCHEMA_VERSION,
    RUN_RECORD_SCHEMA_VERSION,
    VERIFIER_SUMMARY_SCHEMA_VERSION,
)
from fusekit.scanner import scan_repo
from fusekit.security import redact_public_path, redact_public_text, scan_for_secret_leaks
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
    created_at: float = field(default_factory=time.time)

    @property
    def public_launch_ready(self) -> bool:
        """True only when live provider evidence proves public launch readiness."""

        return self.mode == "live" and self.launch_ready

    @property
    def recording_ready(self) -> bool:
        """True only when live evidence proves the run is safe to demo-record."""

        return self.public_launch_ready

    def to_dict(self) -> dict[str, Any]:
        """Serialize the report."""

        return {
            "mode": self.mode,
            "app_path": redact_public_path(self.app_path),
            "launch_ready": self.launch_ready,
            "public_launch_ready": self.public_launch_ready,
            "recording_ready": self.recording_ready,
            "checks": [check.to_dict() for check in self.checks],
            "missing": list(self.missing),
            "blockers": [_redacted_blocker(blocker) for blocker in self.blockers],
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
    _check_run_record(
        evidence_fusekit_dir / "run_record.json",
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

    pack_paths = _ensure_acceptance_packs(app_path, manifest, checks, ledger)
    if pack_paths:
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
                "missing",
                "Live launch needs at least one validated provider capability pack.",
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
    )
    report_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", "utf-8")
    ledger.record(
        "acceptance.finished",
        {
            "launch_ready": launch_ready,
            "public_launch_ready": report.public_launch_ready,
            "recording_ready": report.recording_ready,
            "missing": missing,
        },
    )
    return report


def _app_relative(app_path: Path, path: Path | None) -> Path | None:
    if path is None:
        return None
    if path.is_absolute():
        return path
    return app_path / path


def _resolve_remote_fusekit_dir(app_path: Path, path: Path | None) -> Path | None:
    root = _app_relative(app_path, path)
    if root is None:
        return None
    root = root.resolve()
    if not root.exists():
        raise FuseKitError(f"Remote artifact path does not exist: {root}")
    fusekit_dir = root if root.name == ".fusekit" else root / ".fusekit"
    if not fusekit_dir.is_dir():
        raise FuseKitError(
            "Remote artifact path must be a retrieved OCI artifact directory "
            f"containing .fusekit: {root}"
        )
    return fusekit_dir


def _record_remote_artifacts(
    remote_fusekit_dir: Path,
    checks: list[AcceptanceCheck],
    ledger: HarnessLedger,
) -> None:
    expected = (
        "fusekit.vault.json",
        "setup_receipt.json",
        "audit.jsonl",
        "verification_report.json",
        "rollback_plan.json",
        "provider_strategies.json",
        "checkpoints.json",
        "run_record.json",
        "gates.json",
    )
    inventory = {
        name: {
            "present": (remote_fusekit_dir / name).exists(),
            "bytes": (remote_fusekit_dir / name).stat().st_size
            if (remote_fusekit_dir / name).exists()
            else 0,
        }
        for name in expected
    }
    snapshot = ledger.snapshot_json(
        "remote-artifact-inventory",
        {"fusekit_dir": redact_public_path(remote_fusekit_dir), "files": inventory},
    )
    checks.append(
        AcceptanceCheck(
            "remote_artifacts.loaded",
            "ok",
            "Using retrieved OCI artifacts as live acceptance evidence.",
            str(snapshot),
        )
    )


def _check_run_record(
    path: Path,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    ledger: HarnessLedger,
) -> None:
    if mode != "live":
        checks.append(
            AcceptanceCheck(
                "run_record.complete",
                "skipped",
                "Central Run Record is required only for live OCI evidence.",
            )
        )
        return
    if not path.exists():
        missing.append("central run record")
        checks.append(
            AcceptanceCheck(
                "run_record.complete",
                "missing",
                "Live launch evidence must include .fusekit/run_record.json.",
            )
        )
        return
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
        return
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
        return
    failures = _run_record_shape_failures(raw)
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
        return
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


def _run_record_shape_failures(raw: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if raw.get("schema_version") != RUN_RECORD_SCHEMA_VERSION:
        failures.append("schema_version is unsupported")
    for key in ("id", "status", "app_path", "runner"):
        if not str(raw.get(key, "") or "").strip():
            failures.append(f"{key} is missing")
    state = _require_dict_field(raw, "state", failures)
    if state is not None:
        if state.get("detonation_safe") is not True:
            failures.append("state.detonation_safe must be true")
        if state.get("workspace_detonated") is not True:
            failures.append("state.workspace_detonated must be true")
    _require_list_field(raw, "steps", failures)
    _require_list_field(raw, "checkpoints", failures)
    provider_gates = _require_dict_field(raw, "provider_gates", failures)
    if provider_gates is not None:
        if not isinstance(provider_gates.get("total"), int):
            failures.append("provider_gates.total is missing")
        _require_list_field(provider_gates, "records", failures, prefix="provider_gates")
        _require_dict_field(provider_gates, "statuses", failures, prefix="provider_gates")
        _require_list_field(provider_gates, "providers", failures, prefix="provider_gates")
    durable_state = _require_dict_field(raw, "durable_state", failures)
    if durable_state is not None:
        failures.extend(_durable_state_shape_failures(durable_state))
    wake_events = _require_dict_field(raw, "wake_events", failures)
    if wake_events is not None:
        if not isinstance(wake_events.get("total"), int):
            failures.append("wake_events.total is missing")
        _require_dict_field(wake_events, "event_counts", failures, prefix="wake_events")
        _require_list_field(wake_events, "events", failures, prefix="wake_events")
    human_actions = _require_dict_field(raw, "human_actions", failures)
    if human_actions is not None:
        failures.extend(_human_action_trace_shape_failures(human_actions))
    automation_boundary = _require_dict_field(raw, "automation_boundary", failures)
    if automation_boundary is not None:
        failures.extend(_automation_boundary_shape_failures(automation_boundary))
    if provider_gates is not None and wake_events is not None:
        failures.extend(_run_record_wake_event_failures(provider_gates, wake_events))
    _require_dict_field(raw, "provider_strategies", failures)
    runner_profile = _require_dict_field(raw, "runner_profile", failures)
    if runner_profile is not None:
        profile_contract = _require_dict_field(
            runner_profile,
            "profile_contract",
            failures,
            prefix="runner_profile",
        )
        if profile_contract is not None:
            failures.extend(_runner_profile_contract_failures(profile_contract))
        _require_dict_field(runner_profile, "checks", failures, prefix="runner_profile")
        _require_dict_field(runner_profile, "observed", failures, prefix="runner_profile")
    provider_playbook = _require_dict_field(raw, "provider_playbook", failures)
    if provider_playbook is not None:
        failures.extend(_provider_playbook_shape_failures(provider_playbook))
    verifiers = _require_dict_field(raw, "verifiers", failures)
    if verifiers is not None:
        failures.extend(_verifier_summary_shape_failures(verifiers))
    vault = _require_dict_field(raw, "vault", failures)
    if vault is not None:
        if not isinstance(vault.get("record_count"), int):
            failures.append("vault.record_count is missing")
        records = _require_list_field(vault, "records", failures, prefix="vault")
        if records is not None:
            for index, record in enumerate(records):
                if isinstance(record, dict) and "value" in record:
                    failures.append(f"vault.records[{index}] exposes a raw value")
    audit_trail = _require_dict_field(raw, "audit_trail", failures)
    if audit_trail is not None:
        failures.extend(_audit_trail_shape_failures(audit_trail, raw))
    recording_contract = _require_dict_field(raw, "recording_contract", failures)
    if recording_contract is not None:
        failures.extend(_recording_contract_shape_failures(recording_contract))
    _require_list_field(raw, "artifacts", failures)
    evidence = _require_dict_field(raw, "evidence", failures)
    if evidence is not None:
        failures.extend(_evidence_inventory_shape_failures(evidence))
    _require_dict_field(raw, "verification", failures)
    detonation = _require_dict_field(raw, "detonation", failures)
    if detonation is not None:
        if detonation.get("preflight_safe") is not True:
            failures.append("detonation.preflight_safe must be true")
        if detonation.get("workspace_detonated") is not True:
            failures.append("detonation.workspace_detonated must be true")
        workspace_receipt = _require_dict_field(
            detonation, "workspace_receipt", failures, prefix="detonation"
        )
        if workspace_receipt is not None:
            failures.extend(_workspace_detonation_receipt_failures(workspace_receipt))
    _require_list_field(raw, "approvals", failures)
    _require_list_field(raw, "errors", failures)
    return failures


def _evidence_inventory_shape_failures(evidence: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(evidence.get("schema_version", "")).strip() != "fusekit.evidence-inventory.v1":
        failures.append("evidence.schema_version is unsupported")
    for evidence_field in ("logs", "screenshots", "visual", "receipts"):
        records = evidence.get(evidence_field)
        if not isinstance(records, list):
            failures.append(f"evidence.{evidence_field} is missing")
            continue
        for index, record in enumerate(records):
            label = f"evidence.{evidence_field}[{index}]"
            if not isinstance(record, dict):
                failures.append(f"{label} is not an object")
                continue
            path = str(record.get("path", "") or "")
            if not path.strip():
                failures.append(f"{label}.path is missing")
            if "token=" in path.lower() or "password=" in path.lower():
                failures.append(f"{label}.path contains credential query text")
            if record.get("exists") is not True:
                failures.append(f"{label}.exists must be true")
            if str(record.get("kind", "") or "") not in {
                "log",
                "screenshot",
                "visual",
                "receipt",
            }:
                failures.append(f"{label}.kind is unsupported")
    counts = evidence.get("counts", {})
    if not isinstance(counts, dict):
        failures.append("evidence.counts is missing")
    else:
        for evidence_field in ("logs", "screenshots", "visual", "receipts"):
            if not isinstance(counts.get(evidence_field), int):
                failures.append(f"evidence.counts.{evidence_field} is missing")
    statement = str(evidence.get("statement", "") or "")
    if "path and type only" not in statement or "raw secrets are not embedded" not in statement:
        failures.append("evidence.statement is missing non-secret inventory guidance")
    return failures


def _human_action_trace_shape_failures(human_actions: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(human_actions.get("schema_version", "")).strip() != "fusekit.human-action-trace.v1":
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
    actual_counts: dict[str, int] = {}
    for index, action in enumerate(actions):
        label = f"human_actions.actions[{index}]"
        if not isinstance(action, dict):
            failures.append(f"{label} is not an object")
            continue
        action_name = str(action.get("action", "") or "")
        if action_name not in {
            "open_provider_gate",
            "capture_vm_clipboard",
            "confirm_gate_finished",
        }:
            failures.append(f"{label}.action is unsupported")
        else:
            actual_counts[action_name] = actual_counts.get(action_name, 0) + 1
        if not str(action.get("gate_id", "") or "").strip():
            failures.append(f"{label}.gate_id is missing")
        if not str(action.get("visible_control", "") or "").strip():
            failures.append(f"{label}.visible_control is missing")
        if action.get("guided") is not True:
            failures.append(f"{label}.guided must be true")
        if action_name == "capture_vm_clipboard":
            target = str(action.get("target", "") or "")
            visible_control = str(action.get("visible_control", "") or "")
            if not target or f"Capture {target} from VM clipboard" != visible_control:
                failures.append(f"{label}.visible_control must match the captured target")
    for action_name, expected in actual_counts.items():
        if _safe_int(counts.get(action_name)) != expected:
            failures.append(f"human_actions.counts.{action_name} must match actions")
    if unguided:
        failures.append("human_actions.unguided must be empty")
    statement = str(human_actions.get("statement", "") or "")
    if "visible control-room gate" not in statement or "no raw provider" not in statement:
        failures.append("human_actions.statement is missing guided-action guidance")
    return failures


def _automation_boundary_shape_failures(boundary: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(boundary.get("schema_version", "")).strip() != AUTOMATION_BOUNDARY_SCHEMA_VERSION:
        failures.append("automation_boundary.schema_version is unsupported")
    if str(boundary.get("status", "")).strip() != "ready":
        failures.append("automation_boundary.status must be ready")
    if boundary.get("resume_after_worker_replace") is not True:
        failures.append("automation_boundary.resume_after_worker_replace must be true")
    if boundary.get("no_user_machine_state") is not True:
        failures.append("automation_boundary.no_user_machine_state must be true")
    if str(boundary.get("detonation_scope", "")).strip() != "worker-and-oci-workspace":
        failures.append("automation_boundary.detonation_scope is unsupported")
    allowed = boundary.get("vnc_allowed_for", [])
    allowed_values: set[str] = set()
    if not isinstance(allowed, list):
        failures.append("automation_boundary.vnc_allowed_for is missing")
    else:
        allowed_values = {str(item).strip() for item in allowed if str(item).strip()}
    required_allowed = {
        "login",
        "mfa",
        "captcha",
        "consent",
        "payment",
        "copy_once_secret",
    }
    if not required_allowed.issubset(allowed_values):
        failures.append("automation_boundary.vnc_allowed_for is incomplete")
    routes = boundary.get("routes", [])
    if not isinstance(routes, list):
        failures.append("automation_boundary.routes is missing")
        routes = []
    for index, route in enumerate(routes):
        label = f"automation_boundary.routes[{index}]"
        if not isinstance(route, dict):
            failures.append(f"{label} is not an object")
            continue
        for key in ("provider", "recipe", "route", "owner", "status"):
            if not str(route.get(key, "") or "").strip():
                failures.append(f"{label}.{key} is missing")
        owner = str(route.get("owner", "") or "").strip()
        if owner not in {"fusekit", "human_gate"}:
            failures.append(f"{label}.owner is unsupported")
        if owner == "fusekit":
            if route.get("deterministic") is not True:
                failures.append(f"{label}.deterministic must be true")
            if route.get("implemented") is not True:
                failures.append(f"{label}.implemented must be true")
            if str(route.get("route", "")).strip() not in {"api", "official_cli", "local_vault"}:
                failures.append(f"{label}.route must be an automation route")
        if owner == "human_gate" and str(route.get("route", "")).strip() not in {
            "browser_guided",
            "human_follow_me",
        }:
            failures.append(f"{label}.route must be a human gate route")
    counts = boundary.get("counts", {})
    if not isinstance(counts, dict):
        failures.append("automation_boundary.counts is missing")
    else:
        if _safe_int(counts.get("blocked")) != 0:
            failures.append("automation_boundary.counts.blocked must be 0")
        fusekit_owned_count = sum(
            1 for route in routes if isinstance(route, dict) and route.get("owner") == "fusekit"
        )
        human_gate_count = sum(
            1
            for route in routes
            if isinstance(route, dict) and route.get("owner") == "human_gate"
        )
        if _safe_int(counts.get("fusekit_owned")) != fusekit_owned_count:
            failures.append("automation_boundary.counts.fusekit_owned must match routes")
        if _safe_int(counts.get("human_gate")) != human_gate_count:
            failures.append("automation_boundary.counts.human_gate must match routes")
    post_gate = boundary.get("post_gate_automation", {})
    if not isinstance(post_gate, dict):
        failures.append("automation_boundary.post_gate_automation is missing")
    else:
        if not isinstance(post_gate.get("api_or_cli_routes", []), list):
            failures.append("automation_boundary.post_gate_automation.api_or_cli_routes is missing")
        if not isinstance(post_gate.get("human_gate_routes", []), list):
            failures.append("automation_boundary.post_gate_automation.human_gate_routes is missing")
    statement = str(boundary.get("statement", "") or "")
    lowered = statement.lower()
    for term in ("vnc", "api", "detonate"):
        if term not in lowered:
            failures.append("automation_boundary.statement is missing " + term + " guidance")
            break
    return failures


def _verifier_summary_shape_failures(verifiers: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(verifiers.get("schema_version", "")).strip() != VERIFIER_SUMMARY_SCHEMA_VERSION:
        failures.append("verifiers.schema_version is unsupported")
    if verifiers.get("all_passed_or_pending_safe") is not True:
        failures.append("verifiers.all_passed_or_pending_safe must be true")
    if str(verifiers.get("overall", "")).strip() not in {"passed"}:
        failures.append("verifiers.overall must be passed")
    checks = verifiers.get("checks", [])
    if not isinstance(checks, list) or not checks:
        failures.append("verifiers.checks is missing")
        checks = []
    for index, check in enumerate(checks):
        label = f"verifiers.checks[{index}]"
        if not isinstance(check, dict):
            failures.append(f"{label} is not an object")
            continue
        for key in ("provider", "check", "status"):
            if not str(check.get(key, "") or "").strip():
                failures.append(f"{label}.{key} is missing")
        status = str(check.get("status", "") or "").strip()
        if status not in {"passed", "pending_safe", "skipped"}:
            failures.append(f"{label}.status must be passed, pending_safe, or skipped")
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
            if not isinstance(counts.get(key), int):
                failures.append(f"verifiers.counts.{key} is missing")
        for key in ("pending", "repairing", "failed", "needs_human_gate", "unknown"):
            if _safe_int(counts.get(key)) != 0:
                failures.append(f"verifiers.counts.{key} must be 0")
    statement = str(verifiers.get("statement", "") or "").lower()
    if "live provider verifiers" not in statement or "green checks" not in statement:
        failures.append("verifiers.statement is missing live-verifier guidance")
    return failures


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
    for index, entry in enumerate(entries):
        label = f"audit_trail.entries[{index}]"
        if not isinstance(entry, dict):
            failures.append(f"{label} is not an object")
            continue
        for key in ("category", "action", "status", "source", "summary"):
            if not str(entry.get(key, "") or "").strip():
                failures.append(f"{label}.{key} is missing")
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
        for text_field in ("summary", "action", "provider", "target"):
            value = str(entry.get(text_field, "") or "")
            if _contains_secretish_audit_text(value):
                failures.append(f"{label}.{text_field} contains credential-looking text")
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
    statement = str(audit_trail.get("statement", "") or "").lower()
    for required in ("credential captures", "dns writes", "human approvals", "without storing"):
        if required not in statement:
            failures.append("audit_trail.statement is missing audit-first guidance")
            break
    return failures


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


def _recording_contract_shape_failures(contract: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if (
        str(contract.get("schema_version", "")).strip()
        != RECORDING_CONTRACT_SCHEMA_VERSION
    ):
        failures.append("recording_contract.schema_version is unsupported")
    if contract.get("recording_ready") is not True:
        failures.append("recording_contract.recording_ready must be true")
    checks = contract.get("checks", {})
    required_checks = {
        "durable_state",
        "runner_profile",
        "provider_playbook",
        "human_actions",
        "automation_boundary",
        "verifiers",
        "audit_trail",
        "evidence",
        "detonation",
        "errors_empty",
    }
    if not isinstance(checks, dict):
        failures.append("recording_contract.checks is missing")
        checks = {}
    else:
        missing = sorted(required_checks - set(checks))
        if missing:
            failures.append("recording_contract.checks missing " + ", ".join(missing))
        for key in sorted(required_checks & set(checks)):
            if checks.get(key) is not True:
                failures.append(f"recording_contract.checks.{key} must be true")
    blockers = contract.get("blockers", [])
    if not isinstance(blockers, list):
        failures.append("recording_contract.blockers is missing")
    elif blockers:
        failures.append(
            "recording_contract.blockers must be empty: "
            + ", ".join(str(item) for item in blockers)
        )
    statement = str(contract.get("statement", "") or "").lower()
    for required in ("public demo", "provider playbooks", "guided human actions", "detonation"):
        if required not in statement:
            failures.append("recording_contract.statement is missing " + required + " guidance")
            break
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


def _contains_secretish_audit_text(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in ("http://", "https://", "bearer ")):
        return True
    if re.search(r"\b(?:token|secret|password|private[-_ ]?key)\s*[:=]", lowered):
        return True
    if re.search(r"\b[A-Za-z0-9_-]{32,}\b", value):
        return True
    return False


def _workspace_detonation_receipt_failures(receipt: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(receipt.get("status", "")).strip() != "complete":
        failures.append("detonation.workspace_receipt.status must be complete")
    deleted = receipt.get("deleted", [])
    if not isinstance(deleted, list) or not deleted:
        failures.append("detonation.workspace_receipt.deleted is missing")
    elif "instance" not in {str(item) for item in deleted}:
        failures.append("detonation.workspace_receipt.deleted must include instance")
    failures_field = receipt.get("failures")
    if not isinstance(failures_field, dict):
        failures.append("detonation.workspace_receipt.failures is missing")
    elif failures_field:
        failures.append("detonation.workspace_receipt.failures must be empty")
    if not str(receipt.get("reason", "") or "").strip():
        failures.append("detonation.workspace_receipt.reason is missing")
    if not isinstance(receipt.get("updated_at"), int | float):
        failures.append("detonation.workspace_receipt.updated_at is missing")
    resource_summary = receipt.get("resource_summary")
    if not isinstance(resource_summary, dict) or not resource_summary:
        failures.append("detonation.workspace_receipt.resource_summary is missing")
    else:
        if (
            str(resource_summary.get("schema_version", "")).strip()
            != "fusekit.workspace-detonation-resources.v1"
        ):
            failures.append(
                "detonation.workspace_receipt.resource_summary.schema_version is unsupported"
            )
        if resource_summary.get("remote_worker") is not True:
            failures.append("detonation.workspace_receipt.remote_worker must be true")
        if resource_summary.get("compute_instance") is not True:
            failures.append("detonation.workspace_receipt.compute_instance must be true")
        if resource_summary.get("network_resources_deleted") is not True:
            failures.append("detonation.workspace_receipt.network_resources must be deleted")
        missing = resource_summary.get("missing", [])
        if not isinstance(missing, list):
            failures.append("detonation.workspace_receipt.resource_summary.missing is missing")
        elif missing:
            failures.append(
                "detonation.workspace_receipt.resource_summary.missing must be empty"
            )
        statement = str(resource_summary.get("statement", "") or "").lower()
        for required in ("remote worker", "oci vm", "network resources"):
            if required not in statement:
                failures.append(
                    "detonation.workspace_receipt.resource_summary.statement is incomplete"
                )
                break
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
    for event in events:
        if not isinstance(event, dict):
            continue
        name = str(event.get("event", "") or "")
        if name:
            actual_counts[name] = actual_counts.get(name, 0) + 1
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
                failures.append(
                    "wake_events missing clipboard_captured for "
                    f"{gate_id}:{target}"
                )
        if str(gate.get("status", "") or "") in {"resume_requested", "resolved"}:
            if gate_id not in resumed_gate_ids:
                failures.append(f"wake_events missing resume_requested for {gate_id}")
            wake_id = str(gate.get("last_wake_event_id", "") or "").strip()
            if not wake_id:
                failures.append(
                    f"provider_gates.records[{gate_id}].last_wake_event_id is missing"
                )
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
                failures.append(
                    f"provider_gates.records[{gate_id}].last_wake_event_id is missing"
                )
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

    return {
        str(key): redact_public_text(value)
        for key, value in blocker.items()
    }


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
        "provider route recovery checkpoints": (
            "Provider routes",
            "Keep the live launcher/control room open until provider-route cards show "
            "the next action and resume hint. If this report came from an older "
            "artifact set, keep this live control room open while FuseKit rebuilds "
            "the provider-route proof.",
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
                "shows a selected route, next action, and resume hint.",
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
    if check.id == "run_record.complete":
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
        checks.append(
            AcceptanceCheck("manifest.loaded", "ok", "Existing setup manifest loaded.")
        )
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
        pack = load_provider_pack(pack_path)
        validate_provider_pack(pack)
        pack_snapshot = ledger.snapshot_json(f"provider-pack-{provider}", pack.to_dict())
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
    text = vault_path.read_text(encoding="utf-8")
    if "WEBHOOK_SECRET" in text or "BEGIN PRIVATE KEY" in text:
        checks.append(
            AcceptanceCheck(
                "vault.ciphertext_only",
                "failed",
                "Vault contains plaintext markers.",
            )
        )
        missing.append("ciphertext-only vault")
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
    vault = Vault.open(vault_path, passphrase)
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
    if int(raw.get("raw_secrets_exposed", 0)) != 0:
        checks.append(
            AcceptanceCheck(
                "receipt.redacted",
                "failed",
                "Receipt reports raw secrets exposed.",
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
            "audit proof for: "
            + ", ".join(missing_domains),
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
    dns_index = _first_receipt_action(actions, "dns.propose", status="ok")
    if resend_index is None or dns_index is None:
        _fail_resend_dns_receipt(
            checks,
            missing,
            "Receipt must include successful resend.domain and dns.propose actions.",
            artifact,
        )
        return
    if resend_index > dns_index:
        _fail_resend_dns_receipt(
            checks,
            missing,
            "Receipt put DNS proposal before Resend domain setup.",
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
            "with a deterministic sending-domain contract.",
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
        return (
            "Receipt resend.domain has an unsupported requested Resend region "
            f"({allowed})."
        )
    capabilities = details.get("capabilities", {})
    if not isinstance(capabilities, dict):
        return "Receipt resend.domain is missing sending-only capability details."
    sending = str(capabilities.get("sending", "") or "").strip().lower()
    receiving = str(capabilities.get("receiving", "") or "").strip().lower()
    if sending != "enabled" or receiving != "disabled":
        return (
            "Receipt resend.domain must prove sending is enabled and receiving is disabled."
        )
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


def _resend_receipt_dns_records(action: dict[str, Any]) -> set[tuple[str, str, str]]:
    details = action.get("details", {})
    raw_records = details.get("dns_records", []) if isinstance(details, dict) else []
    return {
        _receipt_dns_record_key(record)
        for record in raw_records
        if isinstance(record, dict) and _receipt_dns_record_key(record)[0]
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
        if key[0]:
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
            "Receipt Vercel env setup is missing Resend runtime keys: "
            + ", ".join(missing_env),
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
        checks.append(AcceptanceCheck("audit.exists", "ok", "Redacted audit log exists."))
        return
    status = "skipped" if mode == "rehearsal" else "missing"
    checks.append(AcceptanceCheck("audit.exists", status, f"Audit log not found: {audit_log_path}"))
    if mode == "live":
        missing.append("redacted audit log")


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
        if isinstance(check, dict) and str(check.get("provider", "")).strip()
    }


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
    providers = raw.get("providers", []) if isinstance(raw, dict) else []
    schema_version = str(raw.get("schema_version", "")) if isinstance(raw, dict) else ""
    if schema_version != "fusekit.provider-strategies.v1":
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
    _check_provider_strategy_decision_shape(providers, mode, checks, missing, str(snapshot))
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
    providers: Any,
    mode: str,
    checks: list[AcceptanceCheck],
    missing: list[str],
    artifact: str,
) -> None:
    """Require route decisions to include the fields needed for proof and UX."""

    failures = _provider_strategy_shape_failures(providers)
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
                "Provider strategy artifact is missing manifest providers: "
                + ", ".join(absent),
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
        ordered.index(provider)
        for provider in ("cloudflare", "dns")
        if provider in ordered
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
                failures.append(
                    f"{checkpoint_id} is missing Resend-before-DNS recovery guidance"
                )
    return failures


def _checkpoint_guidance_quality_failure(
    checkpoint_id: str,
    checkpoint: dict[str, Any],
    *,
    provider: str,
) -> str:
    text = " ".join(
        str(checkpoint.get(field, "") or "")
        for field in ("detail", "next_action", "resume_hint")
    ).lower()
    for phrase in _FORBIDDEN_GUIDANCE_PHRASES:
        if phrase in text:
            return f"{checkpoint_id} guidance contains non-launcher wording: {phrase}"
    local_browser_failure = _local_browser_guidance_failure(text)
    if local_browser_failure:
        return (
            f"{checkpoint_id} guidance contains non-launcher wording: "
            f"{local_browser_failure}"
        )
    manual_action_failure = _manual_action_guidance_failure(text)
    if manual_action_failure:
        return (
            f"{checkpoint_id} guidance contains non-launcher wording: "
            f"{manual_action_failure}"
        )
    if provider == "resend":
        for field in ("detail", "next_action", "resume_hint"):
            if _field_asks_for_manual_resend_setup(str(checkpoint.get(field, "") or "")):
                return (
                    f"{checkpoint_id} guidance asks for manual Resend "
                    "domain/audience setup"
                )
    waiting_for_human_gate = (
        str(checkpoint.get("status", "") or "").strip().lower() == "waiting"
        or "needs_human_gate" in text
        or "browser_guided" in text
        or "human_follow_me" in text
    )
    if waiting_for_human_gate and "open provider gate in vm" not in text:
        return f"{checkpoint_id} guidance does not name Open provider gate in VM"
    secret_targets = _copy_once_targets_mentioned(text)
    if secret_targets and "capture from vm clipboard" not in text:
        return (
            f"{checkpoint_id} guidance does not name Capture from VM clipboard for "
            + ", ".join(secret_targets)
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
        detail = ", ".join(
            f"{gate['id']}:{gate['status']}" for gate in unresolved if gate["id"]
        )
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
        if _gate_requires_resume_url(gate):
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
    return (
        f"{gate_id}.target asks the user to capture API-generated Resend values: "
        + ", ".join(sorted(generated_targets))
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
    if not missing:
        return ""
    gate_id = str(gate.get("id", "") or "provider.resend")
    return (
        f"{gate_id}.guidance must name exact Resend setup-key selectors: "
        + ", ".join(missing)
    )


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
        failures.append(
            f"{label}.guidance contains non-launcher wording: {local_browser_failure}"
        )
    manual_action_failure = _manual_action_guidance_failure(lowered)
    if manual_action_failure:
        failures.append(
            f"{label}.guidance contains non-launcher wording: {manual_action_failure}"
        )
    if requires_vm and "open provider gate in vm" not in action_lowered:
        failures.append(
            f"{label}.guidance does not name Open provider gate in VM for the "
            "VM browser path"
        )
    secret_targets = _env_targets_from_text(target)
    if secret_targets:
        if "capture <target> from vm clipboard" in action_lowered:
            failures.append(
                f"{label}.guidance uses placeholder Capture <TARGET> despite concrete "
                "secret targets"
            )
        missing_exact = _missing_exact_capture_controls(secret_targets, action_lowered)
        if (
            "capture from vm clipboard" not in action_lowered
            and len(missing_exact) == len(secret_targets)
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
        next_lower = next_action.lower()
        if "i finished this step" in next_lower and "capture" not in next_lower:
            failures.append(
                f"{label}.next_action points secret targets at I finished this step"
            )
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
                "attempts": _safe_int(gate.get("attempts")),
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


def _safe_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


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
                {"gate_id": gate_id, "target": target}
                for gate_id, target in capture_requirements
            ],
            "open_requirements": [{"gate_id": gate_id} for gate_id in open_requirements],
            "resume_requirements": [
                {"gate_id": gate_id} for gate_id in resume_requirements
            ],
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
    wake_ids_by_name, _wake_error = _control_room_wake_event_ids(gates_path)
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
    audited_gate_ids = {
        gate_id for gate_id, _target in captured_targets
    } | opened_gate_ids | resumed_gate_ids
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
            details.append(
                "missing gate events: " + ", ".join(missing_gate_ids)
            )
        if missing_opens:
            details.append(
                "missing control_room.gate_open: " + ", ".join(missing_opens)
            )
        if missing_captures:
            details.append(
                "missing control_room.clipboard_capture: "
                + ", ".join(
                    f"{gate_id}:{target}" for gate_id, target in missing_captures
                )
            )
        if missing_resumes:
            details.append(
                "missing control_room.gate_resume_requested: "
                + ", ".join(missing_resumes)
            )
        checks.append(
            AcceptanceCheck(
                "gates.audited",
                "failed" if mode == "live" else "skipped",
                "Control-room gates are missing redacted audit events: "
                + "; ".join(details),
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
        and (
            wake_event_ids is None
            or (bool(wake_event_id) and wake_event_id in wake_event_ids)
        )
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
        and (
            wake_event_ids is None
            or (bool(wake_event_id) and wake_event_id in wake_event_ids)
        )
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
    actions_raw = raw.get("rollback", raw.get("actions", [])) if isinstance(raw, dict) else []
    actions = actions_raw if isinstance(actions_raw, list) else []
    actionable = [
        item
        for item in actions
        if isinstance(item, dict)
        and str(item.get("action", "")).startswith("rollback.")
        and str(item.get("status", "")) not in {"missing", "failed"}
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
    live_failures = _live_visual_state_failures(sanitized) if mode == "live" else []
    if live_failures:
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
                    "Live runner readiness proof not found: "
                    + redact_public_path(readiness_path),
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
    snapshot = ledger.snapshot_json("runner-readiness", raw)
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
    if str(durable_state.get("schema_version", "")).strip() != "fusekit.durable-state.v1":
        failures.append("durable_state.schema_version is unsupported")
    if durable_state.get("resume_ready") is not True:
        missing = durable_state.get("missing", [])
        detail = ", ".join(str(item) for item in missing) if isinstance(missing, list) else ""
        failures.append(f"durable_state.resume_ready is not true{': ' + detail if detail else ''}")
    sources = durable_state.get("sources", [])
    if not isinstance(sources, list) or not sources:
        failures.append("durable_state.sources is missing")
    else:
        source_ids: set[str] = set()
        for index, source in enumerate(sources):
            label = f"durable_state.sources[{index}]"
            if not isinstance(source, dict):
                failures.append(f"{label} is not an object")
                continue
            source_id = str(source.get("id", "") or "").strip()
            if not source_id:
                failures.append(f"{label}.id is missing")
            else:
                source_ids.add(source_id)
            if source.get("exists") is not True:
                failures.append(f"{label}.exists must be true")
            if str(source.get("path", "") or "").startswith("/"):
                failures.append(f"{label}.path must be relative")
            if str(source.get("secret_class", "") or "") not in {"encrypted", "non-secret"}:
                failures.append(f"{label}.secret_class is unsupported")
        required = {
            "encrypted_vault",
            "job_state",
            "run_state",
            "checkpoints",
            "gates",
            "provider_strategies",
        }
        missing_ids = sorted(required - source_ids)
        if missing_ids:
            failures.append("durable_state.sources missing " + ", ".join(missing_ids))
    volatile = durable_state.get("volatile_worker_surfaces", [])
    if not isinstance(volatile, list) or not {"worker", "visual", "openclaw-state"}.issubset(
        {str(item) for item in volatile}
    ):
        failures.append("durable_state.volatile_worker_surfaces is incomplete")
    preserves = durable_state.get("detonation_preserves", [])
    if not isinstance(preserves, list) or not {"encrypted_vault", "run_record"}.issubset(
        {str(item) for item in preserves}
    ):
        failures.append("durable_state.detonation_preserves is incomplete")
    detonation_scope = durable_state.get("detonation_scope")
    if not isinstance(detonation_scope, dict):
        failures.append("durable_state.detonation_scope is missing")
    else:
        if (
            str(detonation_scope.get("schema_version", "")).strip()
            != "fusekit.detonation-scope.v1"
        ):
            failures.append("durable_state.detonation_scope.schema_version is unsupported")
        if str(detonation_scope.get("mode", "")).strip() != "worker-and-oci-workspace":
            failures.append("durable_state.detonation_scope.mode is unsupported")
        must_delete = detonation_scope.get("must_delete", [])
        required_delete = {
            "worker",
            "browser-profile",
            "provider-auth",
            "passphrase",
            "app.tar.gz",
            "control-room.log",
            "openclaw-gateway.log",
        }
        if not isinstance(must_delete, list) or not required_delete.issubset(
            {str(item) for item in must_delete}
        ):
            failures.append("durable_state.detonation_scope.must_delete is incomplete")
        must_preserve = detonation_scope.get("must_preserve", [])
        if not isinstance(must_preserve, list) or not {"encrypted_vault", "run_record"}.issubset(
            {str(item) for item in must_preserve}
        ):
            failures.append("durable_state.detonation_scope.must_preserve is incomplete")
        if detonation_scope.get("resume_until_complete") is not True:
            failures.append("durable_state.detonation_scope.resume_until_complete must be true")
        no_trace_statement = str(detonation_scope.get("no_trace_statement", "") or "")
        if (
            "no FuseKit worker state remains" not in no_trace_statement
            or "OCI workspace" not in no_trace_statement
        ):
            failures.append("durable_state.detonation_scope.no_trace_statement is incomplete")
    statement = str(durable_state.get("statement", "") or "")
    if "disposable OCI worker" not in statement or "encrypted/redacted state" not in statement:
        failures.append("durable_state.statement is missing durable-worker guidance")
    return failures


def _provider_playbook_shape_failures(playbook: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if str(playbook.get("schema_version", "")).strip() != "fusekit.provider-playbook.v1":
        failures.append("provider_playbook.schema_version is unsupported")
    steps = playbook.get("steps", [])
    if not isinstance(steps, list) or not steps:
        failures.append("provider_playbook.steps is missing")
    else:
        for index, step in enumerate(steps):
            label = f"provider_playbook.steps[{index}]"
            if not isinstance(step, dict):
                failures.append(f"{label} is not an object")
                continue
            if not str(step.get("id", "")).strip():
                failures.append(f"{label}.id is missing")
            instruction = str(step.get("instruction", "") or "")
            if not instruction.strip():
                failures.append(f"{label}.instruction is missing")
            if _provider_playbook_instruction_is_unsafe(instruction):
                failures.append(f"{label}.instruction asks for unsafe provider work")
    safety_notes = playbook.get("safety_notes", [])
    if not isinstance(safety_notes, list) or not safety_notes:
        failures.append("provider_playbook.safety_notes is missing")
    else:
        notes = " ".join(str(note) for note in safety_notes)
        for required in (
            "VM browser",
            "Do not create Resend domains or audiences manually",
            "Do not paste provider secrets into the host computer",
        ):
            if required not in notes:
                failures.append(f"provider_playbook.safety_notes must include {required}")
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


def _unsafe_visual_state_fields(raw: dict[str, Any], sanitized: dict[str, Any]) -> list[str]:
    unsafe: list[str] = []
    if "novnc_url" in raw and raw.get("novnc_url") != sanitized.get("novnc_url"):
        unsafe.append("noVNC URL")
    if "control_room_url" in raw and raw.get("control_room_url") != sanitized.get(
        "control_room_url"
    ):
        unsafe.append("control-room URL")
    if "novnc_password" in raw and raw.get("novnc_password") != sanitized.get(
        "novnc_password"
    ):
        unsafe.append("noVNC password metadata")
    if "provider_browser_profile" in raw and raw.get(
        "provider_browser_profile"
    ) != sanitized.get("provider_browser_profile"):
        unsafe.append("provider browser profile metadata")
    return unsafe


def _live_visual_state_failures(visual: dict[str, Any]) -> list[str]:
    """Return missing live-session guarantees for public demo readiness."""

    failures: list[str] = []
    if str(visual.get("runner", "")).strip() != "novnc":
        failures.append("runner must be novnc")
    if str(visual.get("status", "")).strip() != "ready":
        failures.append("status must be ready")
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
