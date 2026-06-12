"""Central non-secret run record for launch, resume, and audit surfaces."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from fusekit.runner.gates import GateRecord
from fusekit.runner.job import JobState
from fusekit.runner.readiness import runner_readiness_failures
from fusekit.runner.run_state import LaunchRunState
from fusekit.security import redact_public_text

RUN_RECORD_SCHEMA_VERSION = "fusekit.run-record.v1"
DURABLE_STATE_SCHEMA_VERSION = "fusekit.durable-state.v1"
DETONATION_SCOPE_SCHEMA_VERSION = "fusekit.detonation-scope.v1"
EVIDENCE_INVENTORY_SCHEMA_VERSION = "fusekit.evidence-inventory.v1"
HUMAN_ACTION_TRACE_SCHEMA_VERSION = "fusekit.human-action-trace.v1"
AUTOMATION_BOUNDARY_SCHEMA_VERSION = "fusekit.automation-boundary.v1"
VERIFIER_SUMMARY_SCHEMA_VERSION = "fusekit.verifier-summary.v1"
AUDIT_TRAIL_SCHEMA_VERSION = "fusekit.audit-trail.v1"
RECORDING_CONTRACT_SCHEMA_VERSION = "fusekit.recording-contract.v1"
DURABLE_STATE_SOURCES = (
    ("encrypted_vault", "fusekit.vault.json", "encrypted capability vault", "encrypted"),
    ("job_state", "job.json", "runner job state", "non-secret"),
    ("run_state", "run_state.json", "launch state contract", "non-secret"),
    ("checkpoints", "checkpoints.json", "resume checkpoints", "non-secret"),
    ("gates", "gates.json", "provider gate state", "non-secret"),
    ("provider_strategies", "provider_strategies.json", "provider route decisions", "non-secret"),
    ("runner_readiness", "runner_readiness.json", "runner profile readiness proof", "non-secret"),
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
DETONATION_PRESERVES = (
    "encrypted_vault",
    "job_state",
    "run_state",
    "checkpoints",
    "gates",
    "gate_events",
    "provider_strategies",
    "workspace_detonation",
    "verification_report",
    "rollback_plan",
    "run_record",
)
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

    gates = _read_gates(root / "gates.json")
    verification = _read_json_object(root / "verification_report.json")
    acceptance = _read_json_object(root / "acceptance" / "report.json")
    receipt = _read_json_object(root / "setup_receipt.json")
    workspace_detonation = _read_json_object(root / "workspace_detonation.json")
    provider_strategies = _read_json_object(root / "provider_strategies.json")
    runner_readiness = _read_json_object(root / "runner_readiness.json")
    wake_events = _read_gate_wake_events(root / "gate_events.jsonl")
    run_state = _read_run_state(root / "run_state.json")
    artifacts = _artifact_records(job, root)
    durable_state = _durable_state_summary(root, run_state, artifacts, runner_readiness)
    evidence = _evidence_inventory(root, artifacts)
    human_actions = _human_action_trace(gates, wake_events)
    record = {
        "schema_version": RUN_RECORD_SCHEMA_VERSION,
        "id": job.id,
        "status": job.status,
        "app_path": job.app_path,
        "runner": job.runner,
        "created_at": job.created_at,
        "updated_at": time.time(),
        "state": run_state,
        "steps": [_redacted_record_entry(step.to_dict()) for step in job.steps],
        "checkpoints": [
            _redacted_record_entry(checkpoint.to_dict()) for checkpoint in job.checkpoints
        ],
        "provider_gates": _gate_summary(gates),
        "durable_state": durable_state,
        "runner_profile": _runner_profile_summary(runner_readiness),
        "provider_playbook": _provider_playbook_summary(provider_strategies),
        "verifiers": _verifier_summary(verification),
        "wake_events": _wake_event_summary(wake_events),
        "human_actions": human_actions,
        "automation_boundary": _automation_boundary_summary(
            provider_strategies,
            human_actions,
            durable_state,
        ),
        "provider_strategies": provider_strategies or {"providers": []},
        "vault": {
            "records": vault_index or [],
            "record_count": len(vault_index or []),
        },
        "audit_trail": _audit_trail_summary(
            root,
            gates,
            wake_events,
            receipt,
            workspace_detonation,
            vault_index or [],
        ),
        "artifacts": artifacts,
        "evidence": evidence,
        "verification": verification,
        "acceptance": _acceptance_summary(acceptance),
        "detonation": _detonation_summary(run_state, workspace_detonation),
        "approvals": _approval_summary(gates),
        "errors": _error_summary(job, gates, verification, acceptance, workspace_detonation),
    }
    record["recording_contract"] = _recording_contract_summary(record)
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
        "events": events,
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
                    action="open_provider_gate",
                    visible_control="Open provider gate in VM",
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
            control = (
                f"Capture {target} from VM clipboard"
                if target
                else "Capture from VM clipboard"
            )
            action = "capture_vm_clipboard"
        elif event_name == "resume_requested":
            if _resume_event_is_capture_auto_wake(event):
                continue
            control = _resume_visible_control(gate)
            action = "confirm_gate_finished"
        else:
            control = event_name or "unknown"
            action = event_name or "unknown"
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
    counts: dict[str, int] = {}
    for action_record in actions:
        name = str(action_record.get("action", "") or "unknown")
        counts[name] = counts.get(name, 0) + 1
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
        if _resume_visible_control(gate) in text or str(gate.get("classification", "")) in {
            "dns-approval",
            "setup-approval",
        }:
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
        path = Path(raw_path)
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
                path.suffix.lower() in SCREENSHOT_SUFFIXES
                or path.name in LOG_EVIDENCE_FILENAMES
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
    if not exists:
        return
    display_path = _display_evidence_path(root, path)
    kind = _evidence_kind(path)
    if kind == "artifact":
        return
    candidates[display_path] = {
        "path": display_path,
        "kind": kind,
        "source": source,
        "exists": True,
    }


def _display_evidence_path(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


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
    }:
        return "receipt"
    return "artifact"


def _evidence_records(candidates: list[dict[str, Any]], *, kind: str) -> list[dict[str, Any]]:
    return [
        candidate
        for candidate in sorted(candidates, key=lambda item: str(item.get("path", "")))
        if candidate.get("kind") == kind
    ]


def _durable_state_summary(
    root: Path,
    run_state: dict[str, Any],
    artifacts: list[dict[str, Any]],
    runner_readiness: dict[str, Any],
) -> dict[str, Any]:
    """Summarize whether a run can survive replacing the disposable worker."""

    artifact_names = {
        str(record.get("name", "")): bool(record.get("exists"))
        for record in artifacts
        if isinstance(record, dict)
    }
    sources: list[dict[str, Any]] = []
    for source_id, filename, role, secret_class in DURABLE_STATE_SOURCES:
        path = root / filename
        exists = path.exists() or artifact_names.get(source_id, False)
        sources.append(
            {
                "id": source_id,
                "path": filename,
                "role": role,
                "secret_class": secret_class,
                "exists": exists,
            }
        )
    missing = [source["id"] for source in sources if not source["exists"]]
    runner_failures = runner_readiness_failures(runner_readiness)
    resume_ready = not missing and not runner_failures
    return {
        "schema_version": DURABLE_STATE_SCHEMA_VERSION,
        "resume_ready": resume_ready,
        "missing": missing,
        "runner_profile_ready": not runner_failures,
        "runner_profile_failures": runner_failures,
        "sources": sources,
        "volatile_worker_surfaces": list(VOLATILE_WORKER_SURFACES),
        "detonation_preserves": list(DETONATION_PRESERVES),
        "detonation_scope": {
            "schema_version": DETONATION_SCOPE_SCHEMA_VERSION,
            "mode": "worker-and-oci-workspace",
            "must_delete": list(VOLATILE_WORKER_SURFACES),
            "must_preserve": list(DETONATION_PRESERVES),
            "resume_until_complete": True,
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
            "required_runner_profile": "oci-visual-browser-x86_64",
            "host_machine_state_required": False,
            "state_owner": "encrypted-vault-and-run-record",
            "resume_sources": [source["id"] for source in sources],
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
    profile = runner_readiness.get("profile_contract", {})
    observed = runner_readiness.get("observed", {})
    checks = runner_readiness.get("checks", {})
    return {
        "schema_version": str(runner_readiness.get("schema_version", "")),
        "status": str(runner_readiness.get("status", "")),
        "architecture": str(runner_readiness.get("architecture", "")),
        "profile_contract": profile if isinstance(profile, dict) else {},
        "observed": observed if isinstance(observed, dict) else {},
        "checks": checks if isinstance(checks, dict) else {},
        "provider_browser_profile": str(runner_readiness.get("provider_browser_profile", "")),
        "playwright_browsers_path": str(runner_readiness.get("playwright_browsers_path", "")),
    }


def _provider_playbook_summary(provider_strategies: dict[str, Any]) -> dict[str, Any]:
    playbook = provider_strategies.get("playbook", {})
    if not isinstance(playbook, dict):
        return {}
    steps = playbook.get("steps", [])
    notes = playbook.get("safety_notes", [])
    return {
        "schema_version": str(playbook.get("schema_version", "")),
        "step_count": len(steps) if isinstance(steps, list) else 0,
        "steps": steps if isinstance(steps, list) else [],
        "safety_notes": notes if isinstance(notes, list) else [],
    }


def _automation_boundary_summary(
    provider_strategies: dict[str, Any],
    human_actions: dict[str, Any],
    durable_state: dict[str, Any],
) -> dict[str, Any]:
    routes = _automation_route_records(provider_strategies)
    fusekit_owned = [
        route
        for route in routes
        if route["owner"] == "fusekit" and route["implemented"] is True
    ]
    human_gate_routes = [route for route in routes if route["owner"] == "human_gate"]
    unsupported = [route for route in routes if route["owner"] == "blocked"]
    allowed_human_actions = [
        "login",
        "mfa",
        "captcha",
        "consent",
        "payment",
        "copy_once_secret",
    ]
    counts = human_actions.get("counts", {}) if isinstance(human_actions, dict) else {}
    status = "ready" if not unsupported else "needs_route_repair"
    return {
        "schema_version": AUTOMATION_BOUNDARY_SCHEMA_VERSION,
        "status": status,
        "resume_after_worker_replace": durable_state.get("resume_ready") is True,
        "detonation_scope": "worker-and-oci-workspace",
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
                if route["route"] in {"api", "official_cli", "local_vault"}
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


def _automation_route_records(provider_strategies: dict[str, Any]) -> list[dict[str, Any]]:
    providers = provider_strategies.get("providers", [])
    if not isinstance(providers, list):
        return []
    routes: list[dict[str, Any]] = []
    for provider_record in providers:
        if not isinstance(provider_record, dict):
            continue
        provider = str(provider_record.get("provider", "") or "provider").strip().lower()
        strategies = provider_record.get("strategies", [])
        if not isinstance(strategies, list):
            continue
        for strategy in strategies:
            if not isinstance(strategy, dict):
                continue
            decision = strategy.get("decision", {})
            selected = decision.get("selected", {}) if isinstance(decision, dict) else {}
            selected = selected if isinstance(selected, dict) else {}
            route = str(strategy.get("strategy", selected.get("kind", "")) or "").strip()
            deterministic = selected.get("deterministic") is True
            implemented = selected.get("implemented") is True
            owner = _automation_route_owner(route, deterministic, implemented)
            routes.append(
                {
                    "provider": provider,
                    "recipe": str(strategy.get("recipe", "") or "").strip(),
                    "route": route,
                    "owner": owner,
                    "deterministic": deterministic,
                    "implemented": implemented,
                    "status": str(strategy.get("status", selected.get("status", "")) or ""),
                }
            )
    return routes


def _automation_route_owner(route: str, deterministic: bool, implemented: bool) -> str:
    if route in {"browser_guided", "human_follow_me"}:
        return "human_gate"
    if route in {"api", "official_cli", "local_vault"} and deterministic and implemented:
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
        details = check.get("details", {})
        details = details if isinstance(details, dict) else {}
        raw_status = str(check.get("status", "") or "").strip()
        pending_safe = raw_status == "pending_safe" or (
            raw_status == "pending" and details.get("pending_safe") is True
        )
        effective_status = "pending_safe" if pending_safe else raw_status or "unknown"
        if effective_status in counts:
            counts[effective_status] += 1
        else:
            counts["unknown"] += 1
        records.append(
            {
                "provider": str(check.get("provider", "") or "").strip(),
                "check": str(check.get("check", "") or "provider_status").strip(),
                "status": effective_status,
                "pending_safe": pending_safe,
            }
        )
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
            "checks before launch readiness and detonation proof are trusted."
        ),
    }


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
    if workspace_detonation.get("status"):
        entries.append(
            {
                "category": "detonation",
                "action": "oci.workspace.detonate",
                "provider": "oci",
                "status": str(workspace_detonation.get("status", "unknown") or "unknown"),
                "source": "workspace_detonation.json",
                "summary": "FuseKit recorded disposable OCI worker and workspace cleanup.",
            }
        )
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
        action = "control_room.approve_dns_apply" if classification == "dns-approval" else (
            "control_room.confirm_gate_finished"
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
    actions = receipt.get("actions", [])
    if not isinstance(actions, list):
        return []
    entries: list[dict[str, Any]] = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        action_name = str(action.get("action", "") or "").strip()
        if not action_name:
            continue
        category = _receipt_action_category(action_name)
        entries.append(
            {
                "category": category,
                "action": action_name,
                "provider": _provider_from_action(action_name),
                "status": str(action.get("status", "") or "recorded"),
                "source": "setup_receipt.json",
                "summary": _receipt_action_summary(category, action_name),
            }
        )
    return entries


def _audit_entries_from_audit_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries: list[dict[str, Any]] = []
    for line in lines[-20:]:
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict):
            continue
        event_name = str(raw.get("event", "") or "").strip()
        if not event_name:
            continue
        entries.append(
            {
                "category": _audit_event_category(event_name),
                "action": event_name,
                "provider": _provider_from_action(event_name),
                "status": "recorded",
                "source": "audit.jsonl",
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
    seen: set[tuple[str, str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for entry in entries:
        normalized = {
            "category": str(entry.get("category", "") or ""),
            "action": str(entry.get("action", "") or ""),
            "provider": str(entry.get("provider", "") or ""),
            "status": str(entry.get("status", "") or ""),
            "source": str(entry.get("source", "") or ""),
            "summary": str(entry.get("summary", "") or ""),
        }
        target = str(entry.get("target", "") or "")
        if target:
            normalized["target"] = target
        wake_event_id = str(entry.get("wake_event_id", "") or "")
        if wake_event_id:
            normalized["wake_event_id"] = wake_event_id
        key = (
            normalized["category"],
            normalized["action"],
            normalized["provider"],
            normalized.get("target", ""),
            normalized.get("wake_event_id", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(normalized)
    return unique


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


def _recording_contract_summary(record: dict[str, Any]) -> dict[str, Any]:
    """Summarize whether the OCI lane is safe to demo-record and publish."""

    checks = {
        "durable_state": _recording_durable_state_ready(record),
        "runner_profile": _recording_runner_profile_ready(record),
        "provider_playbook": _recording_provider_playbook_ready(record),
        "human_actions": _recording_human_actions_ready(record),
        "automation_boundary": _recording_automation_boundary_ready(record),
        "verifiers": _recording_verifiers_ready(record),
        "audit_trail": _recording_audit_trail_ready(record),
        "evidence": _recording_evidence_ready(record),
        "detonation": _recording_detonation_ready(record),
        "errors_empty": not record.get("errors"),
    }
    blockers = [name for name, ready in checks.items() if ready is not True]
    return {
        "schema_version": RECORDING_CONTRACT_SCHEMA_VERSION,
        "recording_ready": not blockers,
        "checks": checks,
        "blockers": blockers,
        "statement": (
            "A public demo is recordable only when the Run Record proves durable "
            "OCI state, the x86 visual runner, ordered provider playbooks, guided "
            "human actions, post-gate automation, live provider verifiers, audit "
            "evidence, and no-trace detonation all agree."
        ),
    }


def _recording_durable_state_ready(record: dict[str, Any]) -> bool:
    durable = record.get("durable_state", {})
    if not isinstance(durable, dict):
        return False
    scope = durable.get("detonation_scope", {})
    replacement = durable.get("worker_replacement_contract", {})
    return (
        durable.get("resume_ready") is True
        and isinstance(scope, dict)
        and scope.get("resume_until_complete") is True
        and str(scope.get("mode", "") or "") == "worker-and-oci-workspace"
        and isinstance(replacement, dict)
        and replacement.get("can_recreate_worker") is True
        and replacement.get("host_machine_state_required") is False
    )


def _recording_runner_profile_ready(record: dict[str, Any]) -> bool:
    runner = record.get("runner_profile", {})
    if not isinstance(runner, dict):
        return False
    return not runner_readiness_failures(runner)


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
        isinstance(step, dict) and str(step.get("instruction", "") or "").strip()
        for step in steps
    ):
        return False
    joined = " ".join(str(note) for note in safety_notes)
    return (
        "VM browser" in joined
        and "Do not create Resend domains or audiences manually" in joined
        and "Do not paste provider secrets into the host computer" in joined
    )


def _recording_human_actions_ready(record: dict[str, Any]) -> bool:
    human_actions = record.get("human_actions", {})
    if not isinstance(human_actions, dict):
        return False
    actions = human_actions.get("actions", [])
    unguided = human_actions.get("unguided", [])
    if not isinstance(actions, list) or not isinstance(unguided, list):
        return False
    return (
        _safe_int(human_actions.get("total"), -1) == len(actions)
        and not unguided
        and all(
            isinstance(action, dict)
            and action.get("guided") is True
            and _recording_human_action_control_ready(action)
            for action in actions
        )
    )


def _recording_human_action_control_ready(action: dict[str, Any]) -> bool:
    action_name = str(action.get("action", "") or "")
    visible_control = str(action.get("visible_control", "") or "")
    if action_name == "open_provider_gate":
        return visible_control == "Open provider gate in VM"
    if action_name == "capture_vm_clipboard":
        target = str(action.get("target", "") or "")
        return bool(target) and visible_control == f"Capture {target} from VM clipboard"
    if action_name == "confirm_gate_finished":
        return visible_control in {
            "I finished this step",
            "Approve DNS apply",
            "Approve setup plan",
        }
    return False


def _recording_automation_boundary_ready(record: dict[str, Any]) -> bool:
    boundary = record.get("automation_boundary", {})
    if not isinstance(boundary, dict):
        return False
    counts = boundary.get("counts", {})
    return (
        str(boundary.get("status", "") or "") == "ready"
        and boundary.get("resume_after_worker_replace") is True
        and boundary.get("no_user_machine_state") is True
        and isinstance(counts, dict)
        and _safe_int(counts.get("blocked"), 1) == 0
    )


def _recording_verifiers_ready(record: dict[str, Any]) -> bool:
    verifiers = record.get("verifiers", {})
    if not isinstance(verifiers, dict):
        return False
    checks = verifiers.get("checks", [])
    return (
        verifiers.get("all_passed_or_pending_safe") is True
        and str(verifiers.get("overall", "") or "") == "passed"
        and isinstance(checks, list)
        and bool(checks)
    )


def _recording_audit_trail_ready(record: dict[str, Any]) -> bool:
    audit_trail = record.get("audit_trail", {})
    if not isinstance(audit_trail, dict):
        return False
    entries = audit_trail.get("entries", [])
    if not isinstance(entries, list) or not entries:
        return False
    categories = {
        str(entry.get("category", "") or "")
        for entry in entries
        if isinstance(entry, dict)
    }
    return (
        _safe_int(audit_trail.get("entry_count"), -1) == len(entries)
        and "detonation" in categories
        and ("provider_action" in categories or "credential_capture" in categories)
    )


def _recording_evidence_ready(record: dict[str, Any]) -> bool:
    evidence = record.get("evidence", {})
    if not isinstance(evidence, dict):
        return False
    counts = evidence.get("counts", {})
    return (
        isinstance(counts, dict)
        and _safe_int(counts.get("logs"), 0) >= 1
        and _safe_int(counts.get("visual"), 0) >= 1
        and _safe_int(counts.get("receipts"), 0) >= 1
    )


def _recording_detonation_ready(record: dict[str, Any]) -> bool:
    detonation = record.get("detonation", {})
    if not isinstance(detonation, dict):
        return False
    receipt = detonation.get("workspace_receipt", {})
    failures = receipt.get("failures", {}) if isinstance(receipt, dict) else {}
    resource_summary = receipt.get("resource_summary", {}) if isinstance(receipt, dict) else {}
    required_network_resources = {
        "internet_gateway",
        "network_security_group",
        "route_table",
        "security_list",
        "subnet",
        "vcn",
    }
    network_resources = (
        resource_summary.get("network_resources", [])
        if isinstance(resource_summary, dict)
        else []
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
    return (
        detonation.get("preflight_safe") is True
        and detonation.get("workspace_detonated") is True
        and isinstance(receipt, dict)
        and str(receipt.get("status", "") or "") == "complete"
        and isinstance(failures, dict)
        and not failures
        and isinstance(resource_summary, dict)
        and resource_summary.get("remote_worker") is True
        and resource_summary.get("compute_instance") is True
        and resource_summary.get("network_resources_deleted") is True
        and isinstance(network_resources, list)
        and not (required_network_resources - {str(item) for item in network_resources})
        and isinstance(network_resources_missing, list)
        and not network_resources_missing
        and isinstance(missing, list)
        and not missing
    )


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
    return errors


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
