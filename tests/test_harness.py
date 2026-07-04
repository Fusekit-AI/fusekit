from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from fusekit.cli import main
from fusekit.errors import FuseKitError
from fusekit.harness import run_acceptance
from fusekit.harness.acceptance import (
    REMOTE_ALLOWED_SURVIVOR_FILES,
    AcceptanceCheck,
    AcceptanceReport,
    _acceptance_blockers,
    _check_audit_log,
    _check_detonation,
    _check_runner_readiness,
    _check_vault,
    _check_visual_state,
    _gate_capture_audit_event_proves_vault_capture,
    _gate_open_audit_event_proves_vm_open,
    _gate_resume_audit_event_proves_finished_click,
    _gate_resume_audit_requirements,
    _provider_strategy_artifact_shape_failures,
    _provider_strategy_checkpoint_failures,
    _provider_strategy_shape_failures,
    _rollback_provider_names,
    _run_record_runner_profile_consistency_failures,
    _run_record_shape_failures,
    _unguided_gates,
)
from fusekit.harness.ledger import HarnessLedger
from fusekit.providers.capability_pack import synthesize_provider_pack, write_provider_pack
from fusekit.runner.control_room.surfaces import public_control_room_security_surface
from fusekit.runner.gate_guidance import provider_gate_guidance
from fusekit.runner.gates import GateService
from fusekit.runner.readiness import REQUIRED_RUNNER_BINARIES
from fusekit.runner.remote import remote_worker_cleanup_proof
from fusekit.runner.run_record import (
    DETONATION_PRESERVES,
    DURABLE_STATE_SOURCES,
    OCI_WORKSPACE_DETONATION_SURFACES,
    VOLATILE_WORKER_SURFACES,
    WORKER_REPLACEMENT_SOURCE_IDS,
)
from fusekit.runner.run_state import RUN_STATE_FIELDS
from fusekit.vault import Vault


def _strategy_decision(
    kind: str = "api",
    status: str = "available",
    *,
    evidence: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "selected": {
            "kind": kind,
            "status": status,
            "deterministic": True,
            "implemented": True,
            "reason": "deterministic provider API is available",
            "evidence": evidence or {},
        },
        "candidates": [
            {
                "kind": kind,
                "status": status,
                "deterministic": True,
                "implemented": True,
                "reason": "deterministic provider API is available",
            }
        ],
    }


def _resend_domain_strategy_decision() -> dict[str, object]:
    return _strategy_decision(
        evidence={
            "api_owns": "domain",
            "user_manual_domain_step": "false",
            "downstream_order": "before_dns_apply",
        }
    )


def _resend_audience_strategy_decision() -> dict[str, object]:
    return _strategy_decision(
        evidence={
            "api_owns": "audience",
            "user_manual_audience_step": "false",
            "conditional": "only_when_app_requires_audience",
        }
    )


def _human_gate_strategy_guidance(target: str) -> dict[str, object]:
    capture_label = f"Capture {target} from VM clipboard"
    return {
        "follow_steps": [
            "Open the provider gate in the shared VM browser.",
            capture_label,
            "Click I finished this step after the capture succeeds.",
        ],
        "next_action": capture_label,
        "resume_hint": "FuseKit resumes from gate_events.jsonl after capture.",
        "success_criteria": [
            f"{target} is captured into the encrypted vault.",
            "The worker resumes from the recorded wake event.",
        ],
        "avoid_steps": [
            "Do not paste the token into the host browser.",
            "Do not send the token to the generated app.",
        ],
    }


def _provider_playbook() -> dict[str, object]:
    return {
        "schema_version": "fusekit.provider-playbook.v1",
        "steps": [
            {
                "id": "github.capture_token",
                "provider": "github",
                "route": "browser_guided",
                "actor": "You",
                "human_action_required": True,
                "control": "Capture GITHUB_TOKEN from VM clipboard",
                "proof_source": "gate_events.jsonl",
                "resume_event": "clipboard_captured -> resume_requested",
                "instruction": "Capture GITHUB_TOKEN from VM clipboard.",
            },
            {
                "id": "resend.capture_key",
                "provider": "resend",
                "route": "browser_guided",
                "actor": "You",
                "human_action_required": True,
                "control": "Capture RESEND_API_KEY from VM clipboard",
                "proof_source": "gate_events.jsonl",
                "resume_event": "clipboard_captured -> resume_requested",
                "instruction": (
                    "Capture RESEND_API_KEY from VM clipboard if the Resend API route "
                    "is not already authorized."
                ),
            },
            {
                "id": "resend.domain_api",
                "provider": "resend",
                "route": "api",
                "actor": "FuseKit",
                "human_action_required": False,
                "control": "FuseKit API worker",
                "proof_source": "setup_receipt.json",
                "resume_event": "provider_action_recorded",
                "instruction": (
                    "FuseKit creates or reuses the Resend sending domain through the Resend API."
                ),
            },
            {
                "id": "vercel.env_api",
                "provider": "vercel",
                "route": "api",
                "actor": "FuseKit",
                "human_action_required": False,
                "control": "FuseKit API worker",
                "proof_source": "setup_receipt.json",
                "resume_event": "provider_action_recorded",
                "instruction": "FuseKit writes required runtime variables into Vercel.",
            },
            {
                "id": "dns.approval",
                "provider": "dns",
                "route": "human_follow_me",
                "actor": "You",
                "human_action_required": True,
                "control": "Approve DNS apply",
                "proof_source": "gate_events.jsonl",
                "resume_event": "dns_apply_approved -> resume_requested",
                "instruction": "Approve DNS apply.",
            },
        ],
        "safety_notes": [
            "Use the launcher and shared VM browser for provider gates.",
            (
                "Do not create Resend domains or audiences manually; FuseKit owns "
                "those API setup steps."
            ),
            "Do not paste provider secrets into the host computer; Capture reads the VM clipboard.",
        ],
    }


def _runner_binary_records() -> dict[str, dict[str, object]]:
    return {
        name: {
            "path": f"/usr/local/bin/{name.replace('_', '-')}",
            "present": True,
            "version": "",
        }
        for name in REQUIRED_RUNNER_BINARIES
    }


def _run_record_provider_strategies(fusekit_dir: Path | None = None) -> dict[str, object]:
    if fusekit_dir is not None:
        path = fusekit_dir / "provider_strategies.json"
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        if isinstance(raw, dict) and raw.get("schema_version") == "fusekit.provider-strategies.v1":
            return raw
    return {
        "schema_version": "fusekit.provider-strategies.v1",
        "providers": [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "strategy": "browser_guided",
                        "status": "needs_human_gate",
                        **_human_gate_strategy_guidance("GITHUB_TOKEN"),
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": (
                                    "GitHub token is captured through the VM browser gate."
                                ),
                            },
                            "candidates": [
                                {
                                    "kind": "browser_guided",
                                    "status": "available",
                                    "deterministic": False,
                                    "implemented": False,
                                    "reason": (
                                        "GitHub token is captured through the VM browser gate."
                                    ),
                                }
                            ],
                        },
                    }
                ],
            },
            {
                "provider": "resend",
                "strategies": [
                    {
                        "recipe": "resend-domain",
                        "strategy": "api",
                        "status": "ok",
                        "decision": _resend_domain_strategy_decision(),
                    },
                    {
                        "recipe": "resend-api-key",
                        "strategy": "browser_guided",
                        "status": "needs_human_gate",
                        **_human_gate_strategy_guidance("RESEND_API_KEY"),
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": (
                                    "Provider token is captured through the VM browser gate."
                                ),
                            },
                            "candidates": [
                                {
                                    "kind": "browser_guided",
                                    "status": "available",
                                    "deterministic": False,
                                    "implemented": False,
                                    "reason": (
                                        "Provider token is captured through the VM browser gate."
                                    ),
                                }
                            ],
                        },
                    },
                ],
            },
            {
                "provider": "vercel",
                "strategies": [
                    {
                        "recipe": "vercel-env",
                        "strategy": "api",
                        "status": "ok",
                        "decision": _strategy_decision(),
                    }
                ],
            },
            {
                "provider": "cloudflare",
                "strategies": [
                    {
                        "recipe": "cloudflare-dns",
                        "strategy": "api",
                        "status": "ok",
                        "decision": _strategy_decision(),
                    }
                ],
            },
        ],
    }


def _workspace_detonation_receipt() -> dict[str, object]:
    return {
        "status": "complete",
        "reason": "remote worker and OCI workspace detonated",
        "deleted": [
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
        ],
        "failures": {},
        "resource_summary": {
            "schema_version": "fusekit.workspace-detonation-resources.v1",
            "remote_worker": True,
            "remote_worker_cleanup": remote_worker_cleanup_proof(),
            "compute_instance": True,
            "boot_volume_deleted": True,
            "ephemeral_public_ip_released": True,
            "network_resources": [
                "internet_gateway",
                "network_security_group",
                "route_table",
                "security_list",
                "subnet",
                "vcn",
            ],
            "network_resources_missing": [],
            "network_resources_deleted": True,
            "compartment_deleted": False,
            "compartment_scope": "preserved",
            "survivors": list(DETONATION_PRESERVES),
            "missing": [],
            "statement": (
                "FuseKit detonation must remove the remote worker process state, "
                "terminate the OCI VM, delete the boot volume, and delete "
                "FuseKit-created network resources. The encrypted vault, run "
                "record, redacted artifacts, and resume checkpoints survive "
                "outside the disposable VM without host-machine state."
            ),
        },
        "updated_at": 2.0,
    }


def _worker_replacement_drill() -> dict[str, object]:
    return {
        "schema_version": "fusekit.worker-replacement-drill.v1",
        "status": "passed",
        "worker_destroyed": True,
        "replacement_runner_profile_ready": True,
        "control_room_reopened": True,
        "resume_checkpoint_restored": True,
        "gate_or_verifier_resumed": True,
        "host_machine_state_required": False,
        "volatile_state_reused": False,
        "restored_from": list(WORKER_REPLACEMENT_SOURCE_IDS),
        "statement": (
            "FuseKit recreated the disposable worker from encrypted/redacted "
            "survivor state with no host-machine state and no VM-local plaintext."
        ),
    }


def _durable_state() -> dict[str, object]:
    return {
        "schema_version": "fusekit.durable-state.v1",
        "resume_ready": True,
        "missing": [],
        "sources": [
            {
                "id": source_id,
                "path": path,
                "role": role,
                "secret_class": secret_class,
                "exists": True,
            }
            for source_id, path, role, secret_class in DURABLE_STATE_SOURCES
        ],
        "volatile_worker_surfaces": list(VOLATILE_WORKER_SURFACES),
        "detonation_preserves": list(DETONATION_PRESERVES),
        "detonation_scope": {
            "schema_version": "fusekit.detonation-scope.v1",
            "mode": "worker-and-oci-workspace",
            "must_delete": [
                *VOLATILE_WORKER_SURFACES,
                *OCI_WORKSPACE_DETONATION_SURFACES,
            ],
            "must_preserve": list(DETONATION_PRESERVES),
            "resume_until_complete": True,
            "host_machine_state_required": False,
            "no_trace_statement": (
                "Public OCI runs preserve encrypted state until completion, then "
                "detonate the disposable VM so no FuseKit worker state remains in "
                "the OCI workspace."
            ),
        },
        "runner_profile_ready": True,
        "runner_profile_failures": [],
        "worker_replacement_contract": {
            "worker_is_disposable": True,
            "can_recreate_worker": True,
            "runner_profile_ready": True,
            "required_runner_profile": "oci-visual-browser-x86_64",
            "host_machine_state_required": False,
            "state_owner": "encrypted-vault-and-run-record",
            "resume_sources": list(WORKER_REPLACEMENT_SOURCE_IDS),
            "runner_profile_failures": [],
            "volatile_surfaces": list(VOLATILE_WORKER_SURFACES),
            "statement": (
                "If the OCI VM is killed mid-run, FuseKit recreates the runner "
                "from encrypted/redacted run state instead of relying on local "
                "browser profiles, host clipboard history, or plaintext VM scratch."
            ),
        },
        "workspace_detonated": True,
        "statement": (
            "FuseKit can replace or detonate the disposable OCI worker without losing "
            "the run because encrypted/redacted state is the source of truth."
        ),
    }


def _run_state() -> dict[str, object]:
    state: dict[str, object] = {field: True for field in RUN_STATE_FIELDS}
    state["updated_at"] = 2.0
    state["notes"] = []
    state["missing_for_detonation"] = []
    state["ready_to_detonate"] = True
    return state


def _evidence_inventory() -> dict[str, object]:
    return {
        "schema_version": "fusekit.evidence-inventory.v1",
        "logs": [
            {
                "path": "audit.jsonl",
                "kind": "log",
                "source": "known-proof",
                "exists": True,
            }
        ],
        "screenshots": [],
        "visual": [
            {
                "path": "visual.json",
                "kind": "visual",
                "source": "known-proof",
                "exists": True,
            }
        ],
        "receipts": [
            {
                "path": "setup_receipt.json",
                "kind": "receipt",
                "source": "known-proof",
                "exists": True,
            }
        ],
        "counts": {
            "logs": 1,
            "screenshots": 0,
            "visual": 1,
            "receipts": 1,
        },
        "statement": (
            "Run evidence is inventoried by path and type only; raw secrets are not "
            "embedded in the Run Record."
        ),
    }


def _human_action_trace() -> dict[str, object]:
    return {
        "schema_version": "fusekit.human-action-trace.v1",
        "total": 0,
        "counts": {},
        "actions": [],
        "unguided": [],
        "statement": (
            "Every recorded human action should map to one visible control-room gate "
            "and its current follow-me instructions; the trace contains no raw provider "
            "URLs, clipboard values, passwords, tokens, or screenshots."
        ),
    }


def _human_action_trace_for(actions: list[dict[str, object]]) -> dict[str, object]:
    counts = {
        "capture_vm_clipboard": 0,
        "confirm_gate_finished": 0,
        "open_provider_gate": 0,
    }
    for action in actions:
        name = str(action.get("action", "") or "")
        if name in counts:
            counts[name] += 1
    return {
        "schema_version": "fusekit.human-action-trace.v1",
        "total": len(actions),
        "counts": counts,
        "actions": actions,
        "unguided": [],
        "statement": (
            "Every recorded human action should map to one visible control-room gate "
            "and its current follow-me instructions; the trace contains no raw provider "
            "URLs, clipboard values, passwords, tokens, or screenshots."
        ),
    }


def _rehearsal_review() -> dict[str, object]:
    return {
        "schema_version": "fusekit.rehearsal-review.v1",
        "status": "ready",
        "action_count": 0,
        "compared_action_count": 0,
        "matched_control_count": 0,
        "unguided_count": 0,
        "side_channel_count": 0,
        "requires_user_thinking": False,
        "reviewed_actions": [],
        "statement": (
            "Every recorded human action is compared against the visible control-room "
            "instructions before public recording readiness; no host browser, terminal, "
            "or side-channel action is required."
        ),
    }


def _rehearsal_review_for(actions: list[dict[str, object]]) -> dict[str, object]:
    reviewed_actions: list[dict[str, object]] = []
    for action in actions:
        action_name = str(action.get("action", "") or "")
        proof_source = (
            "gates.json"
            if action_name == "open_provider_gate"
            else "gates.json + gate_events.jsonl"
        )
        reviewed_actions.append(
            {
                "gate_id": str(action.get("gate_id", "") or ""),
                "action": action_name,
                "visible_control": str(action.get("visible_control", "") or ""),
                "target": str(action.get("target", "") or ""),
                "matched": True,
                "proof_source": proof_source,
            }
        )
    return {
        "schema_version": "fusekit.rehearsal-review.v1",
        "status": "ready",
        "action_count": len(actions),
        "compared_action_count": len(actions),
        "matched_control_count": len(actions),
        "unguided_count": 0,
        "side_channel_count": 0,
        "requires_user_thinking": False,
        "reviewed_actions": reviewed_actions,
        "statement": (
            "Every recorded human action is compared against the visible control-room "
            "instructions before public recording readiness; no host browser, terminal, "
            "or side-channel action is required."
        ),
    }


def _automation_boundary() -> dict[str, object]:
    return {
        "schema_version": "fusekit.automation-boundary.v1",
        "status": "ready",
        "resume_after_worker_replace": True,
        "detonation_scope": "worker-and-oci-workspace",
        "no_user_machine_state": True,
        "vnc_allowed_for": [
            "login",
            "mfa",
            "captcha",
            "consent",
            "payment",
            "copy_once_secret",
        ],
        "routes": [
            {
                "provider": "resend",
                "recipe": "resend-domain",
                "route": "api",
                "owner": "fusekit",
                "deterministic": True,
                "implemented": True,
                "status": "ok",
            },
            {
                "provider": "resend",
                "recipe": "resend-api-key",
                "route": "browser_guided",
                "owner": "human_gate",
                "deterministic": False,
                "implemented": False,
                "status": "needs_human_gate",
            },
        ],
        "counts": {
            "fusekit_owned": 1,
            "human_gate": 1,
            "blocked": 0,
            "guided_human_actions": 0,
        },
        "post_gate_automation": {
            "api_or_cli_routes": ["resend:resend-domain"],
            "human_gate_routes": ["resend:resend-api-key"],
        },
        "statement": (
            "Humans use VNC only for provider gates. After capture, FuseKit owns "
            "provider mutations by API and can detonate the OCI worker."
        ),
    }


def _verifier_summary() -> dict[str, object]:
    checks = [
        {
            "provider": "github",
            "check": "repo_access",
            "status": "passed",
            "pending_safe": False,
        },
        {
            "provider": "resend",
            "check": "domain_verified",
            "status": "passed",
            "pending_safe": False,
        },
        {
            "provider": "vercel",
            "check": "deployment",
            "status": "passed",
            "pending_safe": False,
        },
        {
            "provider": "cloudflare",
            "check": "dns_propagated",
            "status": "pending_safe",
            "pending_safe": True,
        },
        {
            "provider": "live_app",
            "check": "live_url_healthy",
            "status": "passed",
            "pending_safe": False,
        },
    ]
    return {
        "schema_version": "fusekit.verifier-summary.v1",
        "overall": "passed",
        "all_passed_or_pending_safe": True,
        "counts": {
            "passed": 4,
            "pending_safe": 1,
            "pending": 0,
            "repairing": 0,
            "failed": 0,
            "skipped": 0,
            "needs_human_gate": 0,
            "unknown": 0,
        },
        "checks": checks,
        "statement": (
            "Live provider verifiers are summarized as green checks or pending-safe "
            "checks before launch readiness is trusted."
        ),
    }


def _verification_report_checks() -> list[dict[str, object]]:
    return [
        {"provider": "github", "check": "repo_access", "status": "passed"},
        {"provider": "resend", "check": "domain_verified", "status": "passed"},
        {"provider": "vercel", "check": "deployment", "status": "passed"},
        {
            "provider": "cloudflare",
            "check": "dns_propagated",
            "status": "pending",
            "details": {"pending_safe": True},
        },
        {"provider": "live_app", "check": "live_url_healthy", "status": "passed"},
    ]


def _verifier_summary_from_report(fusekit_dir: Path) -> dict[str, object]:
    report_path = fusekit_dir / "verification_report.json"
    if not report_path.exists():
        return _verifier_summary()
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return _verifier_summary()
    checks = report.get("checks", []) if isinstance(report, dict) else []
    if not isinstance(checks, list):
        return _verifier_summary()
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
    records = []
    for check in checks:
        if not isinstance(check, dict):
            continue
        details = check.get("details", {})
        details = details if isinstance(details, dict) else {}
        raw_status = str(check.get("status", "") or "").strip()
        pending_safe = raw_status == "pending_safe" or (
            raw_status == "pending" and details.get("pending_safe") is True
        )
        status = "pending_safe" if pending_safe else raw_status or "unknown"
        counts[status if status in counts else "unknown"] += 1
        records.append(
            {
                "provider": str(check.get("provider", "") or "").strip(),
                "check": str(check.get("check", "") or "provider_status").strip(),
                "status": status,
                "pending_safe": pending_safe,
            }
        )
    if not records:
        return _verifier_summary()
    blocking = (
        counts["pending"]
        + counts["repairing"]
        + counts["failed"]
        + counts["needs_human_gate"]
        + counts["unknown"]
    )
    return {
        "schema_version": "fusekit.verifier-summary.v1",
        "overall": "passed" if blocking == 0 else "blocked",
        "all_passed_or_pending_safe": blocking == 0,
        "counts": counts,
        "checks": records,
        "statement": (
            "Live provider verifiers are summarized as green checks or pending-safe "
            "checks before launch readiness is trusted."
        ),
    }


def _audit_trail() -> dict[str, object]:
    return {
        "schema_version": "fusekit.audit-trail.v1",
        "entry_count": 5,
        "counts": {
            "credential_capture": 1,
            "provider_action": 1,
            "dns_write": 1,
            "human_approval": 1,
            "detonation": 1,
        },
        "entries": [
            {
                "category": "credential_capture",
                "action": "control_room.capture_vm_clipboard",
                "provider": "resend",
                "target": "RESEND_API_KEY",
                "status": "captured",
                "source": "gate_events.jsonl",
                "wake_event_id": "wake-resend-capture",
                "summary": "RESEND_API_KEY was captured from the VM clipboard.",
            },
            {
                "category": "provider_action",
                "action": "resend.domain",
                "provider": "resend",
                "status": "passed",
                "source": "setup_receipt.json",
                "summary": "FuseKit recorded provider action resend.domain.",
            },
            {
                "category": "dns_write",
                "action": "dns.apply",
                "provider": "dns",
                "status": "passed",
                "source": "setup_receipt.json",
                "summary": "FuseKit recorded a DNS write or DNS-record apply action.",
            },
            {
                "category": "human_approval",
                "action": "control_room.approve_dns_apply",
                "provider": "dns",
                "status": "approved",
                "source": "gate_events.jsonl",
                "wake_event_id": "wake-dns-approval",
                "summary": "A visible control-room approval woke the setup worker.",
            },
            {
                "category": "detonation",
                "action": "oci.workspace.detonate",
                "provider": "oci",
                "status": "complete",
                "source": "workspace_detonation.json",
                "summary": "FuseKit recorded disposable OCI worker and workspace cleanup.",
            },
        ],
        "statement": (
            "Credential captures, provider actions, DNS writes, human approvals, "
            "and detonation events are summarized without storing raw secrets."
        ),
    }


def _read_gate_events_fixture(fusekit_dir: Path) -> list[dict[str, object]]:
    path = fusekit_dir / "gate_events.jsonl"
    if not path.exists():
        return _minimum_gate_wake_events()
    events: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        if isinstance(raw, dict):
            events.append(raw)
    return events or _minimum_gate_wake_events()


def _wake_event_summary_fixture(fusekit_dir: Path) -> dict[str, object]:
    events = _read_gate_events_fixture(fusekit_dir)
    counts: dict[str, int] = {}
    for event in events:
        event_name = str(event.get("event", "") or "unknown")
        counts[event_name] = counts.get(event_name, 0) + 1
    return {"total": len(events), "event_counts": counts, "events": events}


def _audit_trail_from_gate_events(fusekit_dir: Path) -> dict[str, object]:
    events = _read_gate_events_fixture(fusekit_dir)
    entries: list[dict[str, object]] = []
    has_dns_approval = False
    for event in events:
        event_name = str(event.get("event", "") or "")
        classification = str(event.get("classification", "") or "")
        provider = str(event.get("provider", "") or "")
        wake_event_id = str(event.get("id", "") or "")
        if event_name == "clipboard_captured":
            target = str(event.get("target", "") or "")
            entries.append(
                {
                    "category": "credential_capture",
                    "action": "control_room.capture_vm_clipboard",
                    "provider": provider,
                    "target": target,
                    "status": "captured",
                    "source": "gate_events.jsonl",
                    "wake_event_id": wake_event_id,
                    "summary": f"{target or 'Provider value'} was captured from the VM clipboard.",
                }
            )
        if event_name == "resume_requested":
            has_dns_approval = has_dns_approval or classification == "dns-approval"
            entries.append(
                {
                    "category": "human_approval",
                    "action": "control_room.approve_dns_apply"
                    if classification == "dns-approval"
                    else "control_room.confirm_gate_finished",
                    "provider": provider,
                    "status": "approved",
                    "source": "gate_events.jsonl",
                    "wake_event_id": wake_event_id,
                    "summary": "A visible control-room approval woke the setup worker.",
                }
            )
    entries.append(
        {
            "category": "provider_action",
            "action": "resend.domain",
            "provider": "resend",
            "status": "passed",
            "source": "setup_receipt.json",
            "receipt_action_index": 1,
            "summary": "FuseKit recorded provider action resend.domain.",
        }
    )
    if has_dns_approval:
        entries.append(
            {
                "category": "dns_write",
                "action": "dns.apply",
                "provider": "dns",
                "status": "passed",
                "source": "setup_receipt.json",
                "receipt_action_index": 2,
                "summary": "FuseKit recorded a DNS write or DNS-record apply action.",
            }
        )
    entries.append(
        {
            "category": "detonation",
            "action": "oci.workspace.detonate",
            "provider": "oci",
            "status": "complete",
            "source": "workspace_detonation.json",
            "summary": "FuseKit recorded disposable OCI worker and workspace cleanup.",
        }
    )
    for resource in (
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
    ):
        entries.append(
            {
                "category": "detonation",
                "action": "oci.workspace.ephemeral_public_ip.released"
                if resource == "ephemeral_public_ip"
                else (
                    "oci.workspace.remote_worker_state.deleted"
                    if resource == "remote_worker"
                    else f"oci.workspace.{resource}.deleted"
                ),
                "provider": "oci",
                "resource": resource,
                "status": "released" if resource == "ephemeral_public_ip" else "deleted",
                "source": "workspace_detonation.json",
                "summary": "FuseKit recorded deletion of a disposable OCI workspace resource.",
            }
        )
    counts: dict[str, int] = {}
    for entry in entries:
        category = str(entry.get("category", "") or "")
        counts[category] = counts.get(category, 0) + 1
    return {
        "schema_version": "fusekit.audit-trail.v1",
        "entry_count": len(entries),
        "counts": counts,
        "entries": entries,
        "statement": (
            "Credential captures, provider actions, DNS writes, human approvals, "
            "and detonation events are summarized without storing raw secrets."
        ),
    }


def _recording_contract() -> dict[str, object]:
    return {
        "schema_version": "fusekit.recording-contract.v1",
        "recording_ready": True,
        "checks": {
            "durable_state": True,
            "worker_replacement": True,
            "runner_profile": True,
            "provider_playbook": True,
            "model_inference": True,
            "timeline": True,
            "provider_gates": True,
            "vault": True,
            "wake_events": True,
            "human_actions": True,
            "rehearsal_review": True,
            "automation_boundary": True,
            "control_room_security": True,
            "verifiers": True,
            "audit_trail": True,
            "artifacts": True,
            "evidence": True,
            "detonation": True,
            "errors_empty": True,
        },
        "blockers": [],
        "statement": (
            "A public demo is recordable only when durable OCI state, worker "
            "replacement from encrypted/redacted sources, ordered provider "
            "playbooks, model inference, guided human actions, rehearsal review, protected "
            "control-room state changes, live provider verifiers, and no-trace "
            "detonation all agree."
        ),
    }


def _model_inference() -> dict[str, object]:
    return {
        "schema_version": "fusekit.model-inference-summary.v1",
        "status": "api_key_encrypted",
        "ready": True,
        "provider": "openai",
        "model": "gpt-5.5",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "auth_mode": "auto",
        "required": True,
        "can_proceed_without_api_key": True,
        "default_lane": "openclaw-openai",
        "next_action": (
            "FuseKit has an encrypted LLM API key and can use it internally for "
            "provider-page reasoning."
        ),
        "lane_count": 2,
        "statement": (
            "The model/inference lane is explicit: API keys are captured into the "
            "encrypted vault, OpenClaw/OpenAI auth is a human-gated fallback only "
            "for the default OpenAI lane, and raw secrets never appear in the "
            "control room, audit log, or receipt."
        ),
    }


def _llm_contract() -> dict[str, object]:
    return {
        "schema_version": "fusekit.llm-contract.v1",
        "provider": "openai",
        "model": "gpt-5.5",
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "record_id": "llm.openai.api_key",
        "auth_mode": "auto",
        "required": True,
        "status": "api_key_encrypted",
        "can_proceed_without_api_key": True,
        "default_lane": "openclaw-openai",
        "next_action": (
            "FuseKit has an encrypted LLM API key and can use it internally for "
            "provider-page reasoning."
        ),
        "lanes": [
            {
                "id": "api-key",
                "label": "Encrypted API key",
                "available": True,
                "requires_user_action": False,
                "description": (
                    "FuseKit stores the key only inside the encrypted vault and resolves "
                    "it in memory when provider-page reasoning is needed."
                ),
            },
            {
                "id": "openclaw-openai",
                "label": "OpenClaw OpenAI authorization",
                "available": True,
                "requires_user_action": False,
                "description": (
                    "Default OpenAI lane only. FuseKit encrypts captured OpenClaw "
                    "auth-state metadata and detonates plaintext worker state later."
                ),
            },
        ],
        "security": {
            "raw_secret_export": "denied",
            "storage": "encrypted vault only",
            "public_surfaces": "metadata and redacted status only",
            "detonation": "plaintext OpenClaw/browser auth state is a worker cleanup target",
        },
    }


def _resend_domain_receipt_details(
    *,
    dns_records: list[dict[str, str]] | None = None,
    generated_env: list[str] | None = None,
) -> dict[str, object]:
    return {
        "domain": "moonlite.rsvp",
        "domain_id": "domain-1",
        "domain_status": "pending",
        "region": "us-east-1",
        "requested_region": "us-east-1",
        "capabilities": {"sending": "enabled", "receiving": "disabled"},
        "generated_env": generated_env or ["RESEND_FROM_EMAIL"],
        "dns_records": dns_records or [],
    }


def _gate_guidance_fields(provider: str) -> dict[str, list[str]]:
    guidance = provider_gate_guidance(provider)
    return {
        "success_criteria": list(guidance.success),
        "avoid_steps": list(guidance.avoid),
    }


def _strategy_guidance_fields(target: str = "GITHUB_TOKEN") -> dict[str, list[str]]:
    return {
        "success_criteria": [
            "The provider account named by FuseKit is selected.",
            f"The visible Capture {target} from VM clipboard control captured the value.",
        ],
        "avoid_steps": [
            "Do not use a local browser or host tab for this provider gate.",
            f"Do not click I finished this step for {target}; use Capture {target} "
            "from VM clipboard.",
        ],
    }


def _write_resend_cloudflare_manifest(app: Path) -> None:
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_resend_vercel_manifest(app: Path) -> None:
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env:
  - RESEND_API_KEY
  - RESEND_FROM_EMAIL
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
  - provider: vercel
    kind: hosting
    name: hosting
    capabilities: []
    secrets: []
    settings: {}
domains: []
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_resend_audience_vercel_manifest(app: Path) -> None:
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env:
  - RESEND_API_KEY
  - RESEND_FROM_EMAIL
  - RESEND_AUDIENCE_ID
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities:
      - audience
    secrets: []
    settings: {}
  - provider: vercel
    kind: hosting
    name: hosting
    capabilities: []
    secrets: []
    settings: {}
domains: []
""".strip()
        + "\n",
        encoding="utf-8",
    )


def _write_minimum_live_artifacts(remote_fusekit: Path) -> None:
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    _write_minimum_gate_events(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "workspace_detonation.json").write_text(
        json.dumps(_workspace_detonation_receipt()),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": _verification_report_checks()}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.domain", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "playbook": _provider_playbook(),
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")
    (remote_fusekit / "llm_contract.json").write_text(json.dumps(_llm_contract()), "utf-8")
    _write_runner_readiness(remote_fusekit)
    _write_durable_survivor_stubs(remote_fusekit)
    _write_minimum_run_record(remote_fusekit)


def _dns_apply_approval_event(
    domain: str = "moonlite.rsvp",
    *,
    wake_event_id: str = "",
) -> dict[str, object]:
    data: dict[str, object] = {
        "gate_id": f"dns.{domain}.approval",
        "provider": "dns",
        "classification": "dns-approval",
        "status": "resume_requested",
        "protected_action": True,
    }
    if wake_event_id:
        data["wake_event_id"] = wake_event_id
    return {
        "event": "control_room.gate_resume_requested",
        "data": data,
    }


def _gate_wake_event(
    event_id: str,
    event: str,
    gate_id: str,
    *,
    provider: str,
    classification: str = "",
    status: str = "resume_requested",
    target: str = "",
    captured_targets: list[str] | None = None,
) -> dict[str, object]:
    return {
        "schema_version": "fusekit.gate-wake.v1",
        "id": event_id,
        "event": event,
        "gate_id": gate_id,
        "provider": provider,
        "classification": classification,
        "status": status,
        "target": target,
        "target_count": len(captured_targets or []),
        "captured_targets": captured_targets or [],
        "created_at": 1780000000.0,
    }


def _minimum_gate_wake_events() -> list[dict[str, object]]:
    return [
        _gate_wake_event(
            "wake-resend-capture",
            "clipboard_captured",
            "provider.resend.authorization",
            provider="resend",
            classification="provider-authorization",
            status="passed",
            target="RESEND_API_KEY",
            captured_targets=["RESEND_API_KEY"],
        ),
        _gate_wake_event(
            "wake-dns-approval",
            "resume_requested",
            "dns.moonlite.rsvp.approval",
            provider="dns",
            classification="dns-approval",
            status="resume_requested",
        ),
    ]


def _write_minimum_gate_events(fusekit_dir: Path) -> None:
    fusekit_dir.joinpath("gate_events.jsonl").write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in _minimum_gate_wake_events())
        + "\n",
        encoding="utf-8",
    )


def _write_safe_visual_state(fusekit_dir: Path) -> None:
    (fusekit_dir / "visual.json").write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "interactive": True,
                "display": ":99",
                "novnc_url": "http://93.184.216.34:6080/vnc.html?autoconnect=1",
                "control_room_url": (
                    "http://93.184.216.34:8765/"
                    "?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
                ),
                "novnc_password": "viewer-password",
                "provider_browser_profile": (
                    "/var/lib/fusekit-runner/visual/chrome-provider-profile"
                ),
                "notes": [
                    "The browser is running on the disposable OCI VM.",
                    "Use the noVNC window to complete human gates in the same session "
                    "FuseKit observes.",
                ],
            }
        ),
        "utf-8",
    )


def _write_runner_readiness(fusekit_dir: Path) -> None:
    (fusekit_dir / "runner_readiness.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.runner-readiness.v1",
                "status": "ready",
                "architecture": "x86_64",
                "profile_contract": {
                    "schema_version": "fusekit.runner-profile.v1",
                    "name": "oci-visual-browser-x86_64",
                    "architecture": "x86_64",
                    "os_family": "linux",
                    "supported_os_ids": ["ubuntu", "ol"],
                    "min_memory_mib": 15360,
                    "ports": {
                        "ssh": 22,
                        "control_room": 8765,
                        "novnc": 6080,
                        "vnc_loopback": 5900,
                        "openclaw_gateway_loopback": 19002,
                    },
                    "browser_stack": {
                        "spine": "openclaw",
                        "automation": "playwright",
                        "browser": "chromium",
                        "shared_provider_profile": (
                            "/var/lib/fusekit-runner/visual/chrome-provider-profile"
                        ),
                    },
                    "required_health_checks": [
                        "x86_64_architecture",
                        "runner_helpers",
                        "visual_commands",
                        "novnc",
                        "openclaw",
                        "playwright_chromium",
                        "shared_provider_browser_profile",
                    ],
                    "required_binaries": list(REQUIRED_RUNNER_BINARIES),
                },
                "observed": {
                    "os_id": "ubuntu",
                    "os_version": "24.04",
                    "memory_mib": 24576,
                    "python": "3.12.0",
                },
                "checks": {
                    "x86_64_architecture": True,
                    "runner_helpers": True,
                    "visual_commands": True,
                    "novnc": True,
                    "openclaw": True,
                    "playwright_chromium": True,
                    "shared_provider_browser_profile": True,
                },
                "installed_binaries": _runner_binary_records(),
                "provider_browser_profile": (
                    "/var/lib/fusekit-runner/visual/chrome-provider-profile"
                ),
                "playwright_browsers_path": "/opt/fusekit-playwright-browsers",
            }
        ),
        "utf-8",
    )


def _runner_profile_from_readiness_fixture(fusekit_dir: Path) -> dict[str, object]:
    path = fusekit_dir / "runner_readiness.json"
    if path.exists():
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return {
                "schema_version": str(raw.get("schema_version", "") or ""),
                "status": str(raw.get("status", "") or ""),
                "architecture": str(raw.get("architecture", "") or ""),
                "profile_contract": raw.get("profile_contract", {})
                if isinstance(raw.get("profile_contract"), dict)
                else {},
                "observed": raw.get("observed", {})
                if isinstance(raw.get("observed"), dict)
                else {},
                "checks": raw.get("checks", {}) if isinstance(raw.get("checks"), dict) else {},
                "installed_binaries": raw.get("installed_binaries", {})
                if isinstance(raw.get("installed_binaries"), dict)
                else {},
                "provider_browser_profile": str(raw.get("provider_browser_profile", "") or ""),
                "playwright_browsers_path": str(raw.get("playwright_browsers_path", "") or ""),
            }
    return {
        "schema_version": "fusekit.runner-readiness.v1",
        "status": "ready",
        "architecture": "x86_64",
        "profile_contract": {
            "schema_version": "fusekit.runner-profile.v1",
            "name": "oci-visual-browser-x86_64",
            "architecture": "x86_64",
            "os_family": "linux",
            "supported_os_ids": ["ubuntu", "ol"],
            "min_memory_mib": 15360,
            "ports": {
                "ssh": 22,
                "control_room": 8765,
                "novnc": 6080,
                "vnc_loopback": 5900,
                "openclaw_gateway_loopback": 19002,
            },
            "browser_stack": {
                "spine": "openclaw",
                "automation": "playwright",
                "browser": "chromium",
                "shared_provider_profile": (
                    "/var/lib/fusekit-runner/visual/chrome-provider-profile"
                ),
            },
            "required_health_checks": [
                "x86_64_architecture",
                "runner_helpers",
                "visual_commands",
                "novnc",
                "openclaw",
                "playwright_chromium",
                "shared_provider_browser_profile",
            ],
            "required_binaries": list(REQUIRED_RUNNER_BINARIES),
        },
        "observed": {
            "os_id": "ubuntu",
            "os_version": "24.04",
            "memory_mib": 24576,
            "python": "3.12.0",
        },
        "checks": {
            "x86_64_architecture": True,
            "runner_helpers": True,
            "visual_commands": True,
            "novnc": True,
            "openclaw": True,
            "playwright_chromium": True,
            "shared_provider_browser_profile": True,
        },
        "installed_binaries": _runner_binary_records(),
        "provider_browser_profile": "/var/lib/fusekit-runner/visual/chrome-provider-profile",
        "playwright_browsers_path": "/opt/fusekit-playwright-browsers",
    }


def _write_minimum_run_record(fusekit_dir: Path) -> None:
    (fusekit_dir / "run_record.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.run-record.v1",
                "id": "fk-live-test",
                "status": "done",
                "app_path": "app",
                "runner": "local",
                "created_at": 1.0,
                "updated_at": 2.0,
                "state": _run_state(),
                "steps": [{"id": "scan", "label": "Scan app", "status": "passed"}],
                "checkpoints": [
                    {"id": "vault", "label": "Vault sealed", "status": "passed"}
                ],
                "provider_gates": {
                    "total": 0,
                    "statuses": {},
                    "providers": [],
                    "records": [],
                },
                "durable_state": _durable_state(),
                "provider_playbook": _provider_playbook(),
                "model_inference": _model_inference(),
                "runner_profile": _runner_profile_from_readiness_fixture(fusekit_dir),
                "worker_replacement_drill": _worker_replacement_drill(),
                "wake_events": _wake_event_summary_fixture(fusekit_dir),
                "human_actions": _human_action_trace(),
                "rehearsal_review": _rehearsal_review(),
                "automation_boundary": _automation_boundary(),
                "control_room_security": public_control_room_security_surface(),
                "verifiers": _verifier_summary_from_report(fusekit_dir),
                "provider_strategies": _run_record_provider_strategies(fusekit_dir),
                "vault": {"record_count": 0, "records": []},
                "audit_trail": _audit_trail_from_gate_events(fusekit_dir),
                "recording_contract": _recording_contract(),
                "artifacts": [
                    {"name": "run_record", "path": "run_record.json", "exists": True},
                    {"name": "audit_log", "path": "audit.jsonl", "exists": True},
                    {
                        "name": "setup_receipt",
                        "path": "setup_receipt.json",
                        "exists": True,
                    },
                ],
                "evidence": _evidence_inventory(),
                "llm_contract": _llm_contract(),
                "verification": {
                    "checks": _verification_report_checks()
                },
                "acceptance": {},
                "detonation": {
                    "preflight_safe": True,
                    "workspace_detonated": True,
                    "workspace_receipt": _workspace_detonation_receipt(),
                },
                "approvals": [],
                "errors": [],
            }
        ),
        "utf-8",
    )


def _write_durable_survivor_stubs(fusekit_dir: Path) -> None:
    if not (fusekit_dir / "job.json").exists():
        (fusekit_dir / "job.json").write_text(
            json.dumps(
                {
                    "id": "fk-live-test",
                    "app_path": "app",
                    "status": "done",
                    "runner": "oci-free",
                    "steps": [],
                    "checkpoints": [],
                    "artifacts": {},
                    "created_at": 2.0,
                    "updated_at": 2.0,
                }
            ),
            encoding="utf-8",
        )
    if not (fusekit_dir / "run_state.json").exists():
        (fusekit_dir / "run_state.json").write_text(
            json.dumps(
                {
                    **{field: True for field in RUN_STATE_FIELDS},
                    "updated_at": 2.0,
                    "notes": [],
                    "missing_for_detonation": [],
                    "ready_to_detonate": True,
                }
            ),
            encoding="utf-8",
        )
    if not (fusekit_dir / "checkpoints.json").exists():
        (fusekit_dir / "checkpoints.json").write_text(
            json.dumps(
                {
                    "job_id": "fk-live-test",
                    "status": "done",
                    "updated_at": 2.0,
                    "checkpoints": [],
                }
            )
            + "\n",
            encoding="utf-8",
        )
    if not (fusekit_dir / "worker_replacement_drill.json").exists():
        (fusekit_dir / "worker_replacement_drill.json").write_text(
            json.dumps(_worker_replacement_drill()),
            encoding="utf-8",
        )


def _write_minimum_resend_vercel_live_artifacts(remote_fusekit: Path) -> None:
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    _write_minimum_gate_events(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "workspace_detonation.json").write_text(
        json.dumps(_workspace_detonation_receipt()),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": _verification_report_checks()}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps(
            {
                "rollback": [
                    {"action": "rollback.resend.domain", "status": "planned"},
                    {"action": "rollback.vercel.env", "status": "planned"},
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "playbook": _provider_playbook(),
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "vercel",
                        "strategies": [
                            {
                                "recipe": "vercel-env",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")
    (remote_fusekit / "llm_contract.json").write_text(json.dumps(_llm_contract()), "utf-8")
    _write_runner_readiness(remote_fusekit)
    _write_safe_visual_state(remote_fusekit)
    _write_durable_survivor_stubs(remote_fusekit)
    _write_minimum_run_record(remote_fusekit)


def _provider_pack_api_setup_action(provider: str, recipe: str) -> dict[str, object]:
    return {
        "action": "provider_pack.setup",
        "status": "ok",
        "details": {
            "provider": provider,
            "setup": [
                {
                    "kind": recipe,
                    "status": "ok",
                    "strategy_decision": _strategy_decision(),
                }
            ],
        },
    }


def test_rollback_provider_names_accepts_current_and_legacy_dns_actions() -> None:
    providers = _rollback_provider_names(
        [
            {"action": "rollback.cloudflare.dns", "status": "planned"},
            {"action": "rollback.dns.cloudflare", "status": "planned"},
            {"action": "rollback.resend.domain", "status": "planned"},
        ]
    )

    assert providers == {"cloudflare", "resend"}


def test_acceptance_rehearsal_writes_ledger_and_report(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    report = run_acceptance(app, mode="rehearsal")

    assert report.launch_ready is True
    assert report.public_launch_ready is False
    assert report.recording_ready is False
    assert (app / "fusekit.yaml").exists()
    assert (app / ".fusekit" / "acceptance" / "ledger.jsonl").exists()
    report_json = json.loads((app / ".fusekit" / "acceptance" / "report.json").read_text())
    assert report_json["launch_ready"] is True
    assert report_json["public_launch_ready"] is False
    assert report_json["recording_ready"] is False
    assert report_json["blockers"] == []
    assert any(check["id"] == "manifest.scanned" for check in report_json["checks"])
    ledger_events = [
        json.loads(line)
        for line in (app / ".fusekit" / "acceptance" / "ledger.jsonl").read_text().splitlines()
    ]
    finished = next(event for event in ledger_events if event["event"] == "acceptance.finished")
    assert finished["data"]["recording_proof_ready"] is False
    assert finished["data"]["recording_ready"] is False
    assert finished["data"]["recording_contract"] == {
        "recording_ready": False,
        "check_count": 0,
        "blockers": [],
    }


def test_acceptance_report_serializes_public_paths(tmp_path) -> None:
    app = tmp_path / "app"
    artifact = app / ".fusekit" / "acceptance" / "artifacts" / "gates.json"
    report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=False,
        checks=(AcceptanceCheck("gates.resolved", "failed", "Needs repair.", str(artifact)),),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
        recording_contract={
            "schema_version": "fusekit.recording-contract.v1",
            "recording_ready": False,
            "checks": {
                "rehearsal_review": False,
                "detonation": True,
                "timeline": "true",
                "provider_gates": 1,
            },
            "blockers": ["rehearsal_review"],
            "statement": "Public demo proof waits on rehearsal review.",
        },
    )

    payload = report.to_dict()
    text = json.dumps(payload)

    assert str(tmp_path) not in text
    assert payload["app_path"] == "app"
    assert payload["public_launch_ready"] is False
    assert payload["recording_proof_ready"] is False
    assert payload["recording_ready"] is False
    assert payload["recording_contract"] == {
        "schema_version": "fusekit.recording-contract.v1",
        "recording_ready": False,
        "checks": {
            "detonation": True,
            "provider_gates": False,
            "rehearsal_review": False,
            "timeline": False,
        },
        "blockers": ["rehearsal_review"],
        "check_count": 4,
        "statement": "Public demo proof waits on rehearsal review.",
    }
    assert payload["ledger_path"] == ".fusekit/acceptance/ledger.jsonl"
    assert payload["report_path"] == ".fusekit/acceptance/report.json"
    assert payload["checks"][0]["artifact"] == ".fusekit/acceptance/artifacts/gates.json"


def test_acceptance_report_names_recording_readiness_contract(tmp_path) -> None:
    app = tmp_path / "app"
    remote_artifacts_check = AcceptanceCheck(
        "remote_artifacts.loaded",
        "ok",
        "Using retrieved OCI artifacts as live acceptance evidence.",
    )
    contracted_live_report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=True,
        checks=(
            remote_artifacts_check,
            AcceptanceCheck("run_record.complete", "ok", "Run Record complete."),
        ),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
        recording_proof_ready=True,
        recording_contract=_recording_contract(),
    )
    local_live_report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=True,
        checks=(AcceptanceCheck("run_record.complete", "ok", "Run Record complete."),),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
        recording_proof_ready=True,
        recording_contract=_recording_contract(),
    )
    uncontracted_live_report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=True,
        checks=(
            remote_artifacts_check,
            AcceptanceCheck("run_record.complete", "ok", "Run Record complete."),
        ),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
        recording_proof_ready=True,
    )
    hollow_contract_report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=True,
        checks=(AcceptanceCheck("run_record.complete", "ok", "Run Record complete."),),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
        recording_proof_ready=True,
        recording_contract={
            "schema_version": "fusekit.recording-contract.v1",
            "recording_ready": True,
            "checks": {},
            "blockers": [],
        },
    )
    partial_contract_report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=True,
        checks=(AcceptanceCheck("run_record.complete", "ok", "Run Record complete."),),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
        recording_proof_ready=True,
        recording_contract={
            "schema_version": "fusekit.recording-contract.v1",
            "recording_ready": True,
            "checks": {"worker_replacement": True},
            "blockers": [],
        },
    )
    unproved_live_report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=True,
        checks=(),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
    )
    rehearsal_report = AcceptanceReport(
        mode="rehearsal",
        app_path=str(app),
        launch_ready=True,
        checks=(AcceptanceCheck("run_record.complete", "ok", "Run Record complete."),),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
        recording_proof_ready=True,
    )

    assert contracted_live_report.public_launch_ready is True
    assert contracted_live_report.remote_artifacts_ready is True
    assert contracted_live_report.recording_proof_ready is True
    assert contracted_live_report.effective_recording_proof_ready is True
    assert contracted_live_report.recording_ready is True
    assert contracted_live_report.to_dict()["remote_artifacts_ready"] is True
    assert contracted_live_report.to_dict()["recording_proof_ready"] is True
    assert contracted_live_report.to_dict()["recording_ready"] is True
    assert local_live_report.public_launch_ready is True
    assert local_live_report.remote_artifacts_ready is False
    assert local_live_report.effective_recording_proof_ready is False
    assert local_live_report.recording_ready is False
    assert local_live_report.to_dict()["remote_artifacts_ready"] is False
    assert local_live_report.to_dict()["recording_proof_ready"] is False
    assert local_live_report.to_dict()["recording_ready"] is False
    assert uncontracted_live_report.public_launch_ready is True
    assert uncontracted_live_report.recording_proof_ready is True
    assert uncontracted_live_report.effective_recording_proof_ready is False
    assert uncontracted_live_report.recording_ready is False
    assert uncontracted_live_report.to_dict()["recording_proof_ready"] is False
    assert uncontracted_live_report.to_dict()["recording_ready"] is False
    assert hollow_contract_report.recording_contract_ready is False
    assert hollow_contract_report.effective_recording_proof_ready is False
    assert hollow_contract_report.to_dict()["recording_proof_ready"] is False
    assert hollow_contract_report.to_dict()["recording_ready"] is False
    assert partial_contract_report.recording_contract_ready is False
    assert partial_contract_report.effective_recording_proof_ready is False
    assert partial_contract_report.to_dict()["recording_proof_ready"] is False
    assert partial_contract_report.to_dict()["recording_ready"] is False
    assert unproved_live_report.public_launch_ready is True
    assert unproved_live_report.recording_proof_ready is False
    assert unproved_live_report.recording_ready is False
    assert unproved_live_report.to_dict()["recording_ready"] is False
    assert rehearsal_report.public_launch_ready is False
    assert rehearsal_report.recording_ready is False
    assert rehearsal_report.to_dict()["recording_ready"] is False


def test_live_acceptance_rejects_local_fusekit_as_remote_artifacts(tmp_path) -> None:
    app = tmp_path / "app"
    fusekit_dir = app / ".fusekit"
    fusekit_dir.mkdir(parents=True)

    with pytest.raises(FuseKitError, match="retrieved OCI artifact bundle"):
        run_acceptance(
            app,
            mode="live",
            remote_artifacts_path=fusekit_dir,
        )


def test_live_acceptance_rejects_linked_remote_artifact_root(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    target = tmp_path / "retrieved-artifacts"
    (target / ".fusekit").mkdir(parents=True)
    linked_remote = tmp_path / "linked-remote-artifacts"
    try:
        linked_remote.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(FuseKitError, match="not a symlink"):
        run_acceptance(
            app,
            mode="live",
            remote_artifacts_path=linked_remote,
        )


def test_live_acceptance_rejects_linked_remote_fusekit_dir(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    remote = tmp_path / "remote-artifacts"
    remote.mkdir()
    target_fusekit = tmp_path / "host-fusekit"
    target_fusekit.mkdir()
    try:
        (remote / ".fusekit").symlink_to(target_fusekit, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(FuseKitError, match="not a symlink"):
        run_acceptance(
            app,
            mode="live",
            remote_artifacts_path=remote,
        )


def test_live_acceptance_rejects_unexpected_remote_artifact_entries(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / ".env").write_text("RESEND_API_KEY=re_leftover", "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "unexpected survivors .env" in remote_check.detail
    assert report.remote_artifacts_ready is False


def test_harness_ledger_records_public_artifact_paths(tmp_path) -> None:
    ledger = HarnessLedger.create(tmp_path / "app" / ".fusekit" / "acceptance")

    artifact = ledger.snapshot_json("provider proof", {"ok": True})
    ledger_text = (tmp_path / "app" / ".fusekit" / "acceptance" / "ledger.jsonl").read_text(
        encoding="utf-8"
    )

    assert artifact.exists()
    assert str(tmp_path) not in ledger_text
    assert ".fusekit/acceptance/artifacts/provider-proof" in ledger_text


def test_harness_ledger_snapshot_redacts_public_token_shapes(tmp_path) -> None:
    ledger = HarnessLedger.create(tmp_path / "app" / ".fusekit" / "acceptance")

    artifact = ledger.snapshot_json(
        "provider callback",
        {
            "url": "https://provider.example/callback?code=secret-code-1234567890&state=ok",
            "notes": [
                "copied github_pat_abcdefghijklmnopqrstuvwxyz1234567890",
                str(tmp_path / "app" / ".fusekit" / "acceptance" / "report.json"),
            ],
        },
    )
    text = artifact.read_text(encoding="utf-8")

    assert "secret-code-1234567890" not in text
    assert "github_pat_abcdefghijklmnopqrstuvwxyz1234567890" not in text
    assert str(tmp_path) not in text
    assert "code=[redacted]" in text
    assert "[redacted]" in text
    assert ".fusekit/acceptance/report.json" in text


def test_acceptance_detonation_blocks_browser_visual_scratch(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    (fusekit_dir / "browser" / "Default").mkdir(parents=True)
    (fusekit_dir / "browser" / "Default" / "Cookies").write_text("session cookie", encoding="utf-8")
    (fusekit_dir / "visual").mkdir()
    (fusekit_dir / "visual" / "x11vnc.log").write_text("visual log", encoding="utf-8")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_detonation(fusekit_dir, "live", checks, missing)

    assert checks[-1].id == "detonation.worker_state"
    assert checks[-1].status == "failed"
    assert "worker/browser/visual state" in checks[-1].detail
    assert "browser" in checks[-1].detail
    assert "visual" in checks[-1].detail
    assert str(tmp_path) not in checks[-1].detail
    assert "detonated worker state" in missing


def test_acceptance_detonation_allows_redacted_survivor_artifacts(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    for name in (
        "visual.json",
        "fusekit.vault.json",
        "audit.jsonl",
        "setup_receipt.json",
        "verification_report.json",
        "rollback_plan.json",
        "provider_strategies.json",
        "gates.json",
    ):
        (fusekit_dir / name).write_text("{}", encoding="utf-8")
    (fusekit_dir / "workspace_detonation.json").write_text(
        json.dumps(_workspace_detonation_receipt()),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_detonation(fusekit_dir, "live", checks, missing)

    assert [check.id for check in checks[-2:]] == [
        "detonation.worker_state",
        "detonation.workspace_receipt",
    ]
    assert checks[-2].status == "ok"
    assert checks[-1].status == "ok"
    assert "browser, visual, and auth scratch" in checks[-2].detail
    assert "VM, boot volume, public IP" in checks[-1].detail
    assert missing == []


def test_acceptance_requires_workspace_detonation_receipt_in_live_mode(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_detonation(fusekit_dir, "live", checks, missing)

    assert checks[-2].id == "detonation.worker_state"
    assert checks[-2].status == "ok"
    assert checks[-1].id == "detonation.workspace_receipt"
    assert checks[-1].status == "missing"
    assert "workspace_detonation.json" in checks[-1].detail
    assert "OCI workspace detonation receipt" in missing


def test_acceptance_rejects_incomplete_workspace_detonation_receipt(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    (fusekit_dir / "workspace_detonation.json").write_text(
        json.dumps(
            {
                "status": "complete",
                "deleted": ["instance"],
                "failures": {},
                "reason": "claimed cleanup",
                "updated_at": 1.0,
                "resource_summary": {
                    "schema_version": "fusekit.workspace-detonation-resources.v1",
                    "remote_worker": True,
                    "compute_instance": True,
                    "boot_volume_deleted": False,
                    "ephemeral_public_ip_released": False,
                    "network_resources_deleted": False,
                    "network_resources": ["subnet"],
                    "network_resources_missing": ["vcn"],
                    "missing": ["boot_volume"],
                    "statement": "instance deleted",
                },
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_detonation(fusekit_dir, "live", checks, missing)

    assert checks[-1].id == "detonation.workspace_receipt"
    assert checks[-1].status == "failed"
    assert "remote_worker_cleanup is missing" in checks[-1].detail
    assert "boot_volume must be deleted" in checks[-1].detail
    assert "network_resources must be deleted" in checks[-1].detail
    assert "compartment_deleted must be false" in checks[-1].detail
    assert "compartment_scope must be preserved" in checks[-1].detail
    assert "OCI workspace detonation receipt" in missing


def test_acceptance_requires_visual_state_in_live_mode(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(fusekit_dir / "visual.json", "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "missing"
    assert "Live visual session state not found" in checks[-1].detail
    assert str(tmp_path) not in checks[-1].detail
    assert "safe visual session state" in missing


def test_acceptance_allows_missing_visual_state_in_rehearsal_mode(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(fusekit_dir / "visual.json", "rehearsal", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "ok"
    assert "Visual session state not present" in checks[-1].detail
    assert missing == []


def test_acceptance_requires_runner_readiness_in_live_mode(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_runner_readiness(fusekit_dir / "runner_readiness.json", "live", checks, missing, ledger)

    assert checks[-1].id == "runner_readiness.prepared"
    assert checks[-1].status == "missing"
    assert "Live runner readiness proof not found" in checks[-1].detail
    assert str(tmp_path) not in checks[-1].detail
    assert "prepared runner readiness proof" in missing


def test_acceptance_rejects_incomplete_runner_readiness(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    readiness = fusekit_dir / "runner_readiness.json"
    readiness.write_text(
        json.dumps(
            {
                "schema_version": "fusekit.runner-readiness.v1",
                "status": "ready",
                "architecture": "aarch64",
                "profile_contract": {
                    "schema_version": "fusekit.runner-profile.v1",
                    "name": "tiny-arm",
                    "architecture": "aarch64",
                    "os_family": "linux",
                    "supported_os_ids": ["ubuntu"],
                    "min_memory_mib": 1024,
                    "ports": {"novnc": 6080},
                    "browser_stack": {"spine": "openclaw"},
                    "required_health_checks": ["x86_64_architecture"],
                },
                "observed": {
                    "os_id": "ubuntu",
                    "os_version": "24.04",
                    "memory_mib": 1024,
                },
                "checks": {
                    "x86_64_architecture": False,
                    "runner_helpers": True,
                    "visual_commands": True,
                    "novnc": True,
                    "openclaw": True,
                    "playwright_chromium": False,
                    "shared_provider_browser_profile": True,
                },
                "provider_browser_profile": "/tmp/profile",
                "playwright_browsers_path": "",
            }
        ),
        "utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_runner_readiness(readiness, "live", checks, missing, ledger)

    assert checks[-1].id == "runner_readiness.prepared"
    assert checks[-1].status == "failed"
    assert "architecture must be x86_64" in checks[-1].detail
    assert "runner profile name must be oci-visual-browser_x86_64" not in checks[-1].detail
    assert "runner profile name must be oci-visual-browser-x86_64" in checks[-1].detail
    assert "runner profile min_memory_mib must be at least 16 GB" in checks[-1].detail
    assert "runner profile required_binaries must be a list" in checks[-1].detail
    assert "observed memory must be at least 16 GB" in checks[-1].detail
    assert "x86_64_architecture must be true" in checks[-1].detail
    assert "playwright_chromium must be true" in checks[-1].detail
    assert "shared provider browser profile path is required" in checks[-1].detail
    assert "Playwright browser cache path is required" in checks[-1].detail
    assert "installed_binaries must be a JSON object" in checks[-1].detail
    assert "prepared runner readiness proof" in missing
    blockers = {blocker["item"]: blocker for blocker in _acceptance_blockers(checks, missing)}
    assert blockers["runner_readiness.prepared"]["category"] == "Runner readiness"
    assert "x86_64 architecture" in blockers["runner_readiness.prepared"]["next_action"]
    assert "OpenClaw, Playwright Chromium, noVNC" in blockers[
        "runner_readiness.prepared"
    ]["next_action"]
    assert "shared provider browser profile" in blockers[
        "runner_readiness.prepared"
    ]["next_action"]
    assert "encrypted vault access" in blockers["runner_readiness.prepared"]["next_action"]
    assert blockers["prepared runner readiness proof"]["category"] == "Runner readiness"


def test_acceptance_allows_complete_runner_readiness(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    _write_runner_readiness(fusekit_dir)
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_runner_readiness(fusekit_dir / "runner_readiness.json", "live", checks, missing, ledger)

    assert checks[-1].id == "runner_readiness.prepared"
    assert checks[-1].status == "ok"
    assert "Prepared x86_64 browser runner proof is present" in checks[-1].detail
    snapshot = json.loads(Path(str(checks[-1].artifact)).read_text(encoding="utf-8"))
    assert snapshot["provider_browser_profile"] == "shared-provider-browser-profile"
    assert snapshot["playwright_browsers_path"] == "playwright-browser-cache"
    assert "/var/lib/fusekit-runner" not in json.dumps(snapshot)
    assert "/opt/fusekit-playwright-browsers" not in json.dumps(snapshot)
    assert missing == []


def test_acceptance_rejects_runner_readiness_callback_url_artifact(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    _write_runner_readiness(fusekit_dir)
    readiness = fusekit_dir / "runner_readiness.json"
    raw = json.loads(readiness.read_text(encoding="utf-8"))
    raw["observed"]["recovery_note"] = "provider callback at https://provider.example/callback"
    readiness.write_text(json.dumps(raw), encoding="utf-8")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_runner_readiness(readiness, "live", checks, missing, ledger)

    assert checks[-1].id == "runner_readiness.prepared"
    assert checks[-1].status == "failed"
    assert "runner_readiness.observed.recovery_note contains callback URL" in checks[-1].detail
    assert "prepared runner readiness proof" in missing


def test_acceptance_rejects_loose_runner_readiness_artifact(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    _write_runner_readiness(fusekit_dir)
    readiness = fusekit_dir / "runner_readiness.json"
    raw = json.loads(readiness.read_text(encoding="utf-8"))
    raw["private_note"] = "sidecar readiness note"
    raw["status"] = " ready "
    raw["checks"]["openclaw "] = True
    raw["profile_contract"]["private_note"] = "sidecar profile note"
    raw["profile_contract"]["browser_stack"]["private_note"] = "sidecar browser note"
    raw["profile_contract"]["required_health_checks"][0] = (
        f" {raw['profile_contract']['required_health_checks'][0]} "
    )
    raw["observed"]["private_note"] = "sidecar observed note"
    raw["installed_binaries"]["python"]["private_note"] = "sidecar binary note"
    raw["installed_binaries"]["python"]["path"] = (
        f" {raw['installed_binaries']['python']['path']} "
    )
    readiness.write_text(json.dumps(raw), encoding="utf-8")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_runner_readiness(readiness, "live", checks, missing, ledger)

    assert checks[-1].id == "runner_readiness.prepared"
    assert checks[-1].status == "failed"
    assert "artifact has unexpected fields: private_note" in checks[-1].detail
    assert "status must be trimmed" in checks[-1].detail
    assert "checks.openclaw  must be trimmed" in checks[-1].detail
    assert "runner profile has unexpected fields: private_note" in checks[-1].detail
    assert (
        "runner profile browser_stack has unexpected fields: private_note"
        in checks[-1].detail
    )
    assert (
        "runner profile required_health_checks[0] must be trimmed"
        in checks[-1].detail
    )
    assert "observed has unexpected fields: private_note" in checks[-1].detail
    assert (
        "installed_binaries.python has unexpected fields: private_note"
        in checks[-1].detail
    )
    assert "installed_binaries.python.path must be trimmed" in checks[-1].detail
    assert "prepared runner readiness proof" in missing


def test_live_acceptance_requires_visual_session_artifact(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "visual.json").unlink()
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [
                    {"action": "resend.contract_health", "status": "ok", "details": {}},
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[
                                {
                                    "name": "send.moonlite.rsvp",
                                    "type": "MX",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                    "ttl": 300,
                                    "priority": 10,
                                }
                            ]
                        ),
                    },
                    {"action": "vercel.contract_health", "status": "ok", "details": {}},
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                ],
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    visual_check = next(check for check in report.checks if check.id == "visual_state.safe")
    assert report.launch_ready is False
    assert visual_check.status == "missing"
    assert "Live visual session state not found" in visual_check.detail
    assert "safe visual session state" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["safe visual session state"]["category"] == "Visual session"
    assert "noVNC/control-room URLs" in blockers["safe visual session state"]["next_action"]


def test_acceptance_rejects_unsafe_visual_state_survivor(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    visual_path = fusekit_dir / "visual.json"
    visual_path.write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "novnc_url": (
                    "http://93.184.216.34:6080/vnc.html?autoconnect=1&password=leaked#frag"
                ),
                "control_room_url": "http://evil.example:8765/?token=stolen",
                "novnc_password": "bad\npassword",
                "provider_browser_profile": "/tmp/disconnected-profile",
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "failed"
    assert "noVNC URL" in checks[-1].detail
    assert "control-room URL" in checks[-1].detail
    assert "noVNC password metadata" in checks[-1].detail
    assert "provider browser profile metadata" in checks[-1].detail
    assert "leaked" not in checks[-1].detail
    assert "stolen" not in checks[-1].detail
    assert "safe visual session state" in missing
    blockers = {blocker["item"]: blocker for blocker in _acceptance_blockers(checks, missing)}
    assert blockers["visual_state.safe"]["category"] == "Visual session"
    assert "safe noVNC/control-room URLs" in blockers["visual_state.safe"]["next_action"]
    assert "safe noVNC password metadata" in blockers["visual_state.safe"]["next_action"]
    assert blockers["safe visual session state"]["category"] == "Visual session"


def test_acceptance_rejects_unexpected_visual_query_values(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    visual_path = fusekit_dir / "visual.json"
    visual_path.write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "interactive": True,
                "novnc_url": (
                    "http://93.184.216.34:6080/vnc.html?autoconnect=javascript&resize=evil"
                ),
                "control_room_url": (
                    "http://93.184.216.34:8765/"
                    "?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
                ),
                "novnc_password": "viewer-password",
                "provider_browser_profile": (
                    "/var/lib/fusekit-runner/visual/chrome-provider-profile"
                ),
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "failed"
    assert "noVNC URL" in checks[-1].detail
    assert "javascript" not in checks[-1].detail
    assert "safe visual session state" in missing


def test_acceptance_allows_sanitized_visual_state_survivor(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    visual_path = fusekit_dir / "visual.json"
    control_room_token = "viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
    visual_path.write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "interactive": True,
                "display": ":99",
                "novnc_url": "http://93.184.216.34:6080/vnc.html?autoconnect=1&resize=scale",
                "control_room_url": f"http://93.184.216.34:8765/?token={control_room_token}",
                "novnc_password": "viewer-password",
                "provider_browser_profile": (
                    "/var/lib/fusekit-runner/visual/chrome-provider-profile"
                ),
                "notes": [
                    "The browser is running on the disposable OCI VM.",
                    "Use the noVNC window to complete human gates in the same session "
                    "FuseKit observes.",
                ],
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "ok"
    assert missing == []
    snapshot = Path(checks[-1].artifact).read_text(encoding="utf-8")
    assert "password=" not in snapshot
    assert "viewer-password" not in snapshot
    assert control_room_token not in snapshot
    assert "[REDACTED sha256:" in snapshot


def test_acceptance_rejects_loose_visual_state_survivor(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    _write_safe_visual_state(fusekit_dir)
    visual_path = fusekit_dir / "visual.json"
    raw = json.loads(visual_path.read_text(encoding="utf-8"))
    raw["private_note"] = "sidecar visual metadata"
    raw["status"] = " ready "
    raw["display"] = ":44"
    raw["notes"] = [
        "The browser is running on the disposable OCI VM.",
        " The browser is running on the disposable OCI VM. ",
    ]
    visual_path.write_text(json.dumps(raw), encoding="utf-8")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "failed"
    assert "does not match generated launch proof" in checks[-1].detail
    assert "artifact has unexpected fields: private_note" in checks[-1].detail
    assert "status must be trimmed" in checks[-1].detail
    assert "display must be :99" in checks[-1].detail
    assert "notes contains duplicate" in checks[-1].detail
    assert "notes must match generated visual-session guidance" in checks[-1].detail
    assert "notes[1] must be trimmed" in checks[-1].detail
    assert "safe visual session state" in missing


def test_acceptance_rejects_visual_state_callback_url_artifact(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    visual_path = fusekit_dir / "visual.json"
    control_room_token = "viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
    visual_path.write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "interactive": True,
                "novnc_url": "http://93.184.216.34:6080/vnc.html?autoconnect=1",
                "control_room_url": f"http://93.184.216.34:8765/?token={control_room_token}",
                "novnc_password": "viewer-password",
                "provider_browser_profile": (
                    "/var/lib/fusekit-runner/visual/chrome-provider-profile"
                ),
                "recovery_note": "provider returned https://provider.example/callback",
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "failed"
    assert "visual_state.recovery_note contains callback URL" in checks[-1].detail
    assert control_room_token not in checks[-1].detail
    assert "safe visual session state" in missing


def test_acceptance_rejects_visual_control_room_callback_url(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    visual_path = fusekit_dir / "visual.json"
    visual_path.write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "interactive": True,
                "novnc_url": "http://93.184.216.34:6080/vnc.html?autoconnect=1",
                "control_room_url": (
                    "http://93.184.216.34:8765/callback"
                    "?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
                ),
                "novnc_password": "viewer-password",
                "provider_browser_profile": (
                    "/var/lib/fusekit-runner/visual/chrome-provider-profile"
                ),
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "failed"
    assert "visual_state.control_room_url contains callback URL" in checks[-1].detail
    assert "viewer_token_" not in checks[-1].detail
    assert "safe visual session state" in missing


def test_acceptance_live_visual_state_requires_ready_interactive_novnc_session(
    tmp_path,
) -> None:
    cases: list[tuple[str, dict[str, object], str]] = [
        ("missing-runner", {"runner": "xvfb"}, "runner must be novnc"),
        ("not-ready", {"status": "starting"}, "status must be ready"),
        ("not-interactive", {"interactive": False}, "interactive must be true"),
        ("missing-novnc", {"novnc_url": ""}, "safe noVNC URL is required"),
        (
            "missing-control-room",
            {"control_room_url": ""},
            "safe control-room URL is required",
        ),
        (
            "missing-password",
            {"novnc_password": ""},
            "noVNC password metadata is required",
        ),
        (
            "missing-provider-profile",
            {"provider_browser_profile": ""},
            "shared provider browser profile metadata is required",
        ),
    ]
    for name, patch, expected in cases:
        fusekit_dir = tmp_path / name / ".fusekit"
        fusekit_dir.mkdir(parents=True)
        visual_path = fusekit_dir / "visual.json"
        visual = {
            "runner": "novnc",
            "status": "ready",
            "interactive": True,
            "display": ":99",
            "novnc_url": "http://93.184.216.34:6080/vnc.html?autoconnect=1",
            "control_room_url": (
                "http://93.184.216.34:8765/?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
            ),
            "novnc_password": "viewer-password",
            "provider_browser_profile": ("/var/lib/fusekit-runner/visual/chrome-provider-profile"),
            "notes": [
                "The browser is running on the disposable OCI VM.",
                "Use the noVNC window to complete human gates in the same session "
                "FuseKit observes.",
            ],
        }
        visual.update(patch)
        visual_path.write_text(json.dumps(visual), encoding="utf-8")
        checks: list[AcceptanceCheck] = []
        missing: list[str] = []
        ledger = HarnessLedger.create(fusekit_dir / "acceptance")

        _check_visual_state(visual_path, "live", checks, missing, ledger)

        assert checks[-1].id == "visual_state.safe"
        assert checks[-1].status == "failed"
        assert expected in checks[-1].detail
        assert "safe visual session state" in missing


def test_live_acceptance_rejects_partial_visual_session_artifact(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "visual.json").write_text(
        json.dumps({"runner": "novnc", "status": "ready"}),
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [
                    {"action": "resend.contract_health", "status": "ok", "details": {}},
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[
                                {
                                    "name": "send.moonlite.rsvp",
                                    "type": "MX",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                    "ttl": 300,
                                    "priority": 10,
                                }
                            ]
                        ),
                    },
                    {"action": "vercel.contract_health", "status": "ok", "details": {}},
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                ],
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    visual_check = next(check for check in report.checks if check.id == "visual_state.safe")
    assert report.launch_ready is False
    assert visual_check.status == "failed"
    assert "safe noVNC URL is required" in visual_check.detail
    assert "safe control-room URL is required" in visual_check.detail
    assert "interactive must be true" in visual_check.detail
    assert "shared provider browser profile metadata is required" in visual_check.detail
    assert "safe visual session state" in report.missing


def test_acceptance_rejects_weak_visual_control_room_token(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    visual_path = fusekit_dir / "visual.json"
    visual_path.write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "novnc_url": "http://93.184.216.34:6080/vnc.html?autoconnect=1",
                "control_room_url": "http://93.184.216.34:8765/?token=short",
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "failed"
    assert "control-room URL" in checks[-1].detail
    assert "safe visual session state" in missing


def test_acceptance_rejects_visual_hostname_or_private_ip(tmp_path) -> None:
    for host in ("attacker.example", "10.0.0.5"):
        fusekit_dir = tmp_path / host.replace(".", "-") / ".fusekit"
        fusekit_dir.mkdir(parents=True)
        visual_path = fusekit_dir / "visual.json"
        visual_path.write_text(
            json.dumps(
                {
                    "runner": "novnc",
                    "status": "ready",
                    "novnc_url": f"http://{host}:6080/vnc.html?autoconnect=1",
                    "control_room_url": (
                        f"http://{host}:8765/"
                        "?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
                    ),
                }
            ),
            encoding="utf-8",
        )
        checks: list[AcceptanceCheck] = []
        missing: list[str] = []
        ledger = HarnessLedger.create(fusekit_dir / "acceptance")

        _check_visual_state(visual_path, "live", checks, missing, ledger)

        assert checks[-1].id == "visual_state.safe"
        assert checks[-1].status == "failed"
        assert "noVNC URL" in checks[-1].detail
        assert "control-room URL" in checks[-1].detail
        assert "safe visual session state" in missing


def test_acceptance_rejects_visual_session_wrong_ports(tmp_path) -> None:
    fusekit_dir = tmp_path / "app" / ".fusekit"
    fusekit_dir.mkdir(parents=True)
    visual_path = fusekit_dir / "visual.json"
    visual_path.write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "novnc_url": "http://93.184.216.34:4444/vnc.html?autoconnect=1",
                "control_room_url": (
                    "http://93.184.216.34:8766/"
                    "?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
                ),
            }
        ),
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []
    ledger = HarnessLedger.create(fusekit_dir / "acceptance")

    _check_visual_state(visual_path, "live", checks, missing, ledger)

    assert checks[-1].id == "visual_state.safe"
    assert checks[-1].status == "failed"
    assert "noVNC URL" in checks[-1].detail
    assert "control-room URL" in checks[-1].detail
    assert "safe visual session state" in missing


def test_acceptance_gate_guidance_rejects_hidden_prompt_or_wrong_button() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.custom.authorization",
                "provider": "custom",
                "status": "passed",
                "resume_url": "https://provider.example/token",
                "target": "CUSTOM_API_KEY",
                "follow_steps": ["Open the provider page and paste into FuseKit's hidden prompt."],
                "next_action": "Click I finished this step after copying CUSTOM_API_KEY.",
                "resume_hint": "FuseKit will retry verification.",
            }
        ]
    )

    assert any("hidden prompt" in item for item in failures)
    assert any("Capture from VM clipboard" in item for item in failures)
    assert any("secret targets at I finished this step" in item for item in failures)


def test_acceptance_gate_guidance_requires_exact_capture_control_label() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Copy the token inside the VM browser.",
                    "Click Capture from VM clipboard after copying GITHUB_TOKEN.",
                ],
                "next_action": "Click Capture from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": ["A GitHub token is captured in the encrypted vault."],
                "avoid_steps": ["Do not grant unrelated permissions."],
            }
        ]
    )

    assert any("exact Capture controls" in item for item in failures)
    assert any("Capture GITHUB_TOKEN from VM clipboard" in item for item in failures)


def test_acceptance_gate_guidance_rejects_placeholder_capture_label() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Copy the token inside the VM browser.",
                    (
                        "Click Capture GITHUB_TOKEN from VM clipboard, not the generic "
                        "Capture <TARGET> from VM clipboard placeholder."
                    ),
                ],
                "next_action": "Click Capture GITHUB_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
            }
        ]
    )

    assert any("placeholder Capture <TARGET>" in item for item in failures)


def test_acceptance_gate_guidance_rejects_local_browser_side_channel() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Use your local browser tab to copy the token.",
                    "Click Capture GITHUB_TOKEN from VM clipboard after copying it.",
                ],
                "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": ["A GitHub token is captured in the encrypted vault."],
                "avoid_steps": ["Do not grant unrelated permissions."],
            }
        ]
    )

    assert any("local browser" in item for item in failures)


def test_acceptance_gate_guidance_rejects_host_browser_side_channel() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Use the host browser tab to finish token setup.",
                    "Click Capture GITHUB_TOKEN from VM clipboard after copying it.",
                ],
                "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": ["A GitHub token is captured in the encrypted vault."],
                "avoid_steps": ["Do not grant unrelated permissions."],
            }
        ]
    )

    assert any("host browser" in item for item in failures)


def test_acceptance_gate_guidance_rejects_return_to_fusekit_wording() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.vercel.login-connection",
                "provider": "vercel",
                "status": "waiting",
                "classification": "provider-authorization",
                "resume_url": "https://vercel.com/account/settings/login-connections",
                "target": "",
                "follow_steps": [
                    "Click Open provider gate in VM so Vercel opens in the VM browser.",
                    "Return to FuseKit and click I finished this step after Vercel confirms.",
                ],
                "next_action": (
                    "Click Open provider gate in VM, approve the connection, then click "
                    "I finished this step."
                ),
                "resume_hint": "FuseKit will retry Vercel setup.",
                "success_criteria": ["The Vercel connection is approved."],
                "avoid_steps": ["Do not use a local browser tab."],
            }
        ]
    )

    assert any("return to fusekit" in item for item in failures)


def test_acceptance_gate_guidance_requires_success_and_avoid_for_all_gates() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "dns.approval",
                "provider": "dns",
                "status": "waiting",
                "classification": "dns-approval",
                "target": "",
                "follow_steps": [
                    "Review the DNS changes in the control room.",
                    "Click Approve DNS apply only if the records match the plan.",
                ],
                "next_action": "Click Approve DNS apply.",
                "resume_hint": "FuseKit will apply DNS after approval.",
            }
        ]
    )

    assert "dns.approval missing success_criteria, avoid_steps" in failures


def test_acceptance_gate_guidance_allows_local_browser_warning() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Do not use a local browser tab for this gate.",
                    ("Copy the token inside the VM browser and click Capture from VM clipboard."),
                ],
                "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": ["A GitHub token is captured in the encrypted vault."],
                "avoid_steps": ["Do not grant unrelated permissions."],
            }
        ]
    )

    assert failures == []


def test_acceptance_gate_guidance_allows_host_browser_warning() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Do not use the host browser tab for this gate.",
                    ("Copy the token inside the VM browser and click Capture from VM clipboard."),
                ],
                "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": ["A GitHub token is captured in the encrypted vault."],
                "avoid_steps": ["Never paste secrets into the host browser."],
            }
        ]
    )

    assert failures == []


def test_acceptance_gate_guidance_requires_open_gate_control() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.cloudflare.authorization",
                "provider": "cloudflare",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://dash.cloudflare.com/profile/api-tokens",
                "target": "CLOUDFLARE_API_TOKEN",
                "follow_steps": [
                    "Use the VM browser to create the exact Cloudflare token.",
                    ("Copy the token inside the VM browser and click Capture from VM clipboard."),
                ],
                "next_action": "Capture CLOUDFLARE_API_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry Cloudflare setup.",
                "success_criteria": ["The token is captured in the encrypted vault."],
                "avoid_steps": ["Do not grant unrelated zones."],
            }
        ]
    )

    assert any("Open provider gate in VM" in item for item in failures)


def test_acceptance_gate_guidance_rejects_bad_success_or_avoid_panels() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "resume_url": "https://github.com/settings/tokens",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    "Copy the token inside the VM browser.",
                    "Click Capture GITHUB_TOKEN from VM clipboard after copying it.",
                ],
                "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": [
                    "If the VM browser is busy, use a local browser tab to finish setup."
                ],
                "avoid_steps": [
                    "Manually create extra webhook integrations if verification stalls."
                ],
            }
        ]
    )

    assert any("local browser" in item for item in failures)
    assert any("manual action" in item for item in failures)


def test_acceptance_gate_guidance_rejects_affirmative_manual_setup() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.custom.authorization",
                "provider": "custom",
                "status": "passed",
                "classification": "provider-verification",
                "resume_url": "https://provider.example/setup",
                "target": "",
                "follow_steps": [
                    "Click Open provider gate in VM so the provider opens in the VM browser.",
                    "Manually create the provider integration in the dashboard.",
                    "Click I finished this step after setup is done.",
                ],
                "next_action": "Click I finished this step after manual setup.",
                "resume_hint": "FuseKit will retry provider setup.",
                "success_criteria": ["The provider integration is created."],
                "avoid_steps": ["Do not paste secrets into chat."],
            }
        ]
    )

    assert any("manual action" in item for item in failures)


def test_acceptance_gate_guidance_allows_negated_manual_warning() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.domain-setup-retry",
                "provider": "resend",
                "status": "passed",
                "classification": "provider-setup-retry",
                "resume_url": "https://resend.com/api-keys",
                "target": "",
                "follow_steps": [
                    "Click Open provider gate in VM so Resend opens in the VM browser.",
                    "No manual Resend domain or DNS step is needed here.",
                    "Do not manually create moonlite.rsvp in Resend for this step.",
                    "Click I finished this step so FuseKit retries Resend API setup.",
                ],
                "next_action": (
                    "No manual Resend domain work is needed. Click I finished this step "
                    "so FuseKit retries Resend domain setup through the API."
                ),
                "resume_hint": "FuseKit will rerun Resend API setup before Cloudflare DNS.",
                "success_criteria": ["FuseKit owns the Resend setup retry."],
                "avoid_steps": ["Do not click Add domain."],
            }
        ]
    )

    assert failures == []


def test_acceptance_provider_gates_require_openable_resume_url() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "status": "passed",
                "classification": "provider-authorization",
                "target": "GITHUB_TOKEN",
                "follow_steps": [
                    "Click Open provider gate in VM so GitHub opens in the VM browser.",
                    ("Copy the token inside the VM browser and click Capture from VM clipboard."),
                ],
                "next_action": "No action needed.",
                "resume_hint": "FuseKit verified this gate as passed.",
            }
        ]
    )

    assert any(
        item.startswith("provider.github.authorization missing resume_url") for item in failures
    )


def test_acceptance_rejects_resend_generated_values_as_capture_targets() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.runtime-values",
                "provider": "resend",
                "status": "passed",
                "classification": "provider-runtime-values",
                "resume_url": "https://resend.com/api-keys",
                "target": "RESEND_API_KEY,RESEND_FROM_EMAIL,RESEND_AUDIENCE_ID",
                "follow_steps": [
                    "Copy the API key inside the VM browser and click Capture from VM clipboard."
                ],
                "next_action": "No action needed.",
                "resume_hint": "FuseKit verified this gate as passed.",
            }
        ]
    )

    assert (
        "provider.resend.runtime-values.target asks the user to capture "
        "API-generated Resend values: RESEND_AUDIENCE_ID, RESEND_FROM_EMAIL"
    ) in failures


def test_acceptance_rejects_vague_resend_setup_key_selector_guidance() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.authorization",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-authorization",
                "resume_url": "https://resend.com/api-keys",
                "target": "RESEND_API_KEY",
                "reason": "Create a Full access Resend setup key for all domains.",
                "follow_steps": [
                    "Click Open provider gate in VM so Resend opens in the VM browser.",
                    "Create a Full access API key that works for all domains.",
                    "Copy the key inside the VM browser and click "
                    "Capture RESEND_API_KEY from VM clipboard.",
                ],
                "next_action": (
                    "Click Open provider gate in VM, then click "
                    "Capture RESEND_API_KEY from VM clipboard after the key is copied."
                ),
                "resume_hint": "FuseKit will continue after RESEND_API_KEY capture.",
                "success_criteria": ["A Resend setup API key was captured."],
                "avoid_steps": ["Do not create Resend domains or audiences by hand."],
            }
        ]
    )

    assert (
        "provider.resend.authorization.guidance must name exact Resend "
        "setup-key selectors: Permission: Full access, Domain: All domains"
    ) in failures


def test_acceptance_rejects_resend_setup_key_without_raw_value_warning() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.authorization",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-authorization",
                "resume_url": "https://resend.com/api-keys",
                "target": "RESEND_API_KEY",
                "reason": (
                    "Create a Resend setup key with Permission: Full access and "
                    "Domain: All domains."
                ),
                "follow_steps": [
                    "Click Open provider gate in VM so Resend opens in the VM browser.",
                    (
                        "Create or open a Resend API key with Permission: Full access "
                        "and Domain: All domains."
                    ),
                    "Copy the key inside the VM browser and click "
                    "Capture RESEND_API_KEY from VM clipboard.",
                    "Do not click Add domain or Add audience; FuseKit owns those steps.",
                ],
                "next_action": (
                    "Click Open provider gate in VM, then click "
                    "Capture RESEND_API_KEY from VM clipboard after the key is copied."
                ),
                "resume_hint": (
                    "FuseKit will continue automatically after RESEND_API_KEY capture, "
                    "then create or reuse Resend domains and audiences by API."
                ),
                "success_criteria": [
                    "A Resend setup API key with Permission: Full access and "
                    "Domain: All domains was captured."
                ],
                "avoid_steps": [
                    "Do not click Add domain in Resend.",
                    "Do not click Add audience in Resend.",
                ],
            }
        ]
    )

    assert (
        "provider.resend.authorization.guidance must explain existing Resend key "
        "rows are not enough without the raw key value"
    ) in failures


def test_acceptance_allows_exact_resend_setup_key_selector_guidance() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.authorization",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-authorization",
                "resume_url": "https://resend.com/api-keys",
                "target": "RESEND_API_KEY",
                "reason": (
                    "Create a Resend setup key with Permission: Full access and "
                    "Domain: All domains."
                ),
                "follow_steps": [
                    "Click Open provider gate in VM so Resend opens in the VM browser.",
                    (
                        "Create or open a Resend API key with Permission: Full access "
                        "and Domain: All domains."
                    ),
                    (
                        "An existing key row with Permission: Full access and Domain: "
                        "All domains is not enough by itself; FuseKit needs the raw "
                        "key value captured into the encrypted vault."
                    ),
                    "Copy the key inside the VM browser and click "
                    "Capture RESEND_API_KEY from VM clipboard.",
                    "Do not click Add domain or Add audience; FuseKit owns those steps.",
                ],
                "next_action": (
                    "Click Open provider gate in VM, then click "
                    "Capture RESEND_API_KEY from VM clipboard after the key is copied."
                ),
                "resume_hint": (
                    "FuseKit will continue automatically after RESEND_API_KEY capture, "
                    "then create or reuse Resend domains and audiences by API."
                ),
                "success_criteria": [
                    "A Resend setup API key with Permission: Full access and "
                    "Domain: All domains was captured."
                ],
                "avoid_steps": [
                    "Do not click Add domain in Resend.",
                    "Do not click Add audience in Resend.",
                ],
            }
        ]
    )

    assert failures == []


def test_acceptance_resume_audit_is_required_for_non_secret_gate_clicks() -> None:
    requirements = _gate_resume_audit_requirements(
        [
            {
                "id": "provider.cloudflare.domain-review",
                "provider": "cloudflare",
                "classification": "provider-verification",
                "target": "",
            },
            {
                "id": "dns.moonlite.rsvp.approval",
                "provider": "dns",
                "classification": "dns-approval",
                "target": "",
            },
            {
                "id": "provider.resend.api-key",
                "provider": "resend",
                "classification": "provider-authorization",
                "target": "RESEND_API_KEY",
            },
        ]
    )

    assert requirements == [
        "provider.cloudflare.domain-review",
        "dns.moonlite.rsvp.approval",
    ]


def test_acceptance_provider_gate_open_proof_requires_non_reused_launch() -> None:
    base_event = {
        "event": "control_room.gate_open",
        "data": {
            "gate_id": "provider.cloudflare.authorization",
            "protected_action": True,
            "reused": False,
            "has_resume_url": True,
            "has_last_opened_url": True,
        },
    }
    reused_event = {
        **base_event,
        "data": {
            **base_event["data"],
            "reused": True,
        },
    }

    assert _gate_open_audit_event_proves_vm_open(base_event) is True
    assert _gate_open_audit_event_proves_vm_open(reused_event) is False


def test_acceptance_gate_audit_proof_requires_matching_wake_event_id() -> None:
    capture_event = {
        "event": "control_room.clipboard_capture",
        "data": {
            "gate_id": "provider.openai.authorization",
            "target": "OPENAI_API_KEY",
            "record_id": "provider.openai.token",
            "protected_action": True,
            "source": "vm-clipboard",
            "storage": "encrypted-vault",
            "capture_wake_event_id": "wake-capture-1",
        },
    }
    resume_event = {
        "event": "control_room.gate_resume_requested",
        "data": {
            "gate_id": "provider.cloudflare.authorization",
            "protected_action": True,
            "status": "resume_requested",
            "wake_event_id": "wake-resume-1",
        },
    }

    assert (
        _gate_capture_audit_event_proves_vault_capture(
            capture_event,
            {"wake-capture-1"},
        )
        is True
    )
    assert (
        _gate_capture_audit_event_proves_vault_capture(
            capture_event,
            {"stale-capture-id"},
        )
        is False
    )
    assert (
        _gate_resume_audit_event_proves_finished_click(
            resume_event,
            {"wake-resume-1"},
        )
        is True
    )
    assert (
        _gate_resume_audit_event_proves_finished_click(
            resume_event,
            {"stale-resume-id"},
        )
        is False
    )


def test_acceptance_human_strategy_guidance_must_be_launcher_actionable() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "custom",
                "strategies": [
                    {
                        "status": "needs_human_gate",
                        "target": "CUSTOM_API_KEY",
                        "follow_steps": ["Figure out the token page yourself."],
                        "next_action": "Paste into FuseKit after manual setup.",
                        "resume_hint": "Retry later.",
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided", "status": "available"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("non-launcher wording" in item for item in failures)
    assert any("VM browser path" in item for item in failures)
    assert any("Capture from VM clipboard" in item for item in failures)


def test_acceptance_provider_strategy_artifact_rejects_loose_public_proof() -> None:
    strategies = _run_record_provider_strategies()
    strategies["private_note"] = "sidecar"
    providers = strategies["providers"]
    assert isinstance(providers, list)
    first_provider = providers[0]
    assert isinstance(first_provider, dict)
    first_provider["private_note"] = "sidecar"
    strategy_rows = first_provider["strategies"]
    assert isinstance(strategy_rows, list)
    first_strategy = strategy_rows[0]
    assert isinstance(first_strategy, dict)
    first_strategy["private_note"] = "sidecar"
    first_strategy["recipe"] = f" {first_strategy['recipe']} "
    decision = first_strategy["decision"]
    assert isinstance(decision, dict)
    decision["private_note"] = "sidecar"
    selected = decision["selected"]
    assert isinstance(selected, dict)
    selected["private_note"] = "sidecar"
    candidates = decision["candidates"]
    assert isinstance(candidates, list)
    first_candidate = candidates[0]
    assert isinstance(first_candidate, dict)
    first_candidate["private_note"] = "sidecar"

    failures = _provider_strategy_artifact_shape_failures(strategies)

    assert "provider_strategies has unexpected fields: private_note" in failures
    assert (
        "provider_strategies.providers[0] has unexpected fields: private_note"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0] has unexpected fields: "
        "private_note"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].recipe must not have "
        "surrounding whitespace"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].decision has unexpected "
        "fields: private_note"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].decision.selected has "
        "unexpected fields: private_note"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].decision.candidates[0] "
        "has unexpected fields: private_note"
        in failures
    )


def test_acceptance_human_strategy_accepts_success_and_avoid_panels() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "status": "needs_human_gate",
                        "target": "GITHUB_TOKEN",
                        "follow_steps": [
                            ("Click Open provider gate in VM so GitHub opens in the VM browser."),
                            "Copy the token inside the shared VM browser.",
                            "Click Capture GITHUB_TOKEN from VM clipboard.",
                        ],
                        "next_action": (
                            "Click Open provider gate in VM, copy the token inside "
                            "the VM browser, then click Capture GITHUB_TOKEN from "
                            "VM clipboard."
                        ),
                        "resume_hint": "FuseKit will retry GitHub setup after capture.",
                        **_strategy_guidance_fields("GITHUB_TOKEN"),
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided", "status": "available"}],
                        },
                    }
                ],
            }
        ]
    )

    assert failures == []


def test_acceptance_human_strategy_rejects_local_browser_side_channel() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "status": "needs_human_gate",
                        "target": "GITHUB_TOKEN",
                        "follow_steps": [
                            ("Click Open provider gate in VM so GitHub opens in the VM browser."),
                            "Use a local browser tab to create the token.",
                            "Click Capture GITHUB_TOKEN from VM clipboard after copying it.",
                        ],
                        "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                        "resume_hint": "FuseKit will retry GitHub setup.",
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided", "status": "available"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("local browser" in item for item in failures)


def test_acceptance_human_strategy_rejects_host_browser_side_channel() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "status": "needs_human_gate",
                        "target": "GITHUB_TOKEN",
                        "follow_steps": [
                            ("Click Open provider gate in VM so GitHub opens in the VM browser."),
                            "Use the host browser tab to finish token setup.",
                            "Click Capture GITHUB_TOKEN from VM clipboard after copying it.",
                        ],
                        "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                        "resume_hint": "FuseKit will retry GitHub setup.",
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided", "status": "available"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("host browser" in item for item in failures)


def test_acceptance_human_strategy_requires_exact_capture_control_label() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "status": "needs_human_gate",
                        "target": "GITHUB_TOKEN",
                        "follow_steps": [
                            ("Click Open provider gate in VM so GitHub opens in the VM browser."),
                            "Copy the token inside the VM browser.",
                            "Click Capture from VM clipboard after copying GITHUB_TOKEN.",
                        ],
                        "next_action": "Click Capture from VM clipboard.",
                        "resume_hint": "FuseKit will retry GitHub setup.",
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided", "status": "available"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("exact Capture controls" in item for item in failures)
    assert any("Capture GITHUB_TOKEN from VM clipboard" in item for item in failures)


def test_acceptance_human_strategy_rejects_placeholder_capture_label() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "status": "needs_human_gate",
                        "target": "GITHUB_TOKEN",
                        "follow_steps": [
                            ("Click Open provider gate in VM so GitHub opens in the VM browser."),
                            "Copy the token inside the VM browser.",
                            (
                                "Click Capture GITHUB_TOKEN from VM clipboard; ignore "
                                "Capture <TARGET> from VM clipboard fallback copy."
                            ),
                        ],
                        "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                        "resume_hint": "FuseKit will retry GitHub setup.",
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided", "status": "available"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("placeholder Capture <TARGET>" in item for item in failures)


def test_acceptance_human_strategy_rejects_bad_success_or_avoid_panels() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "status": "needs_human_gate",
                        "target": "GITHUB_TOKEN",
                        "follow_steps": [
                            ("Click Open provider gate in VM so GitHub opens in the VM browser."),
                            "Copy the token inside the VM browser.",
                            "Click Capture GITHUB_TOKEN from VM clipboard after copying it.",
                        ],
                        "next_action": "Capture GITHUB_TOKEN from VM clipboard.",
                        "resume_hint": "FuseKit will retry GitHub setup.",
                        "success_criteria": [
                            "Use your local browser tab if the VM browser is slow."
                        ],
                        "avoid_steps": ["Manually add provider secrets if capture fails."],
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Missing provider token.",
                            },
                            "candidates": [{"kind": "browser_guided", "status": "available"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("local browser" in item for item in failures)
    assert any("manual action" in item for item in failures)


def test_acceptance_checkpoint_guidance_rejects_side_channels() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"github": {"github-repo-secrets"}},
        [
            {
                "id": "provider.github.routes",
                "status": "waiting",
                "detail": "github-repo-secrets uses browser_guided (needs_human_gate)",
                "next_action": "Use your local browser tab to create the token.",
                "resume_hint": "Manually add provider secrets if the route fails.",
            }
        ],
    )

    assert any("local browser" in item for item in failures)


def test_acceptance_checkpoint_guidance_rejects_host_browser_side_channels() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"github": {"github-repo-secrets"}},
        [
            {
                "id": "provider.github.routes",
                "status": "waiting",
                "detail": "github-repo-secrets uses browser_guided (needs_human_gate)",
                "next_action": "Use the host browser tab to create the token.",
                "resume_hint": "Click Capture GITHUB_TOKEN from VM clipboard after copy.",
            }
        ],
    )

    assert any("host browser" in item for item in failures)


def test_acceptance_checkpoint_guidance_requires_open_gate_control() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"cloudflare": {"cloudflare-consent"}},
        [
            {
                "id": "provider.cloudflare.routes",
                "status": "waiting",
                "detail": "cloudflare-consent uses human_follow_me (needs_human_gate)",
                "next_action": "Use the VM browser to approve the named zone.",
                "resume_hint": "Click I finished this step after Cloudflare confirms.",
            }
        ],
    )

    assert any("Open provider gate in VM" in item for item in failures)


def test_acceptance_checkpoint_guidance_requires_capture_for_copy_once_target() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"github": {"github-repo-secrets"}},
        [
            {
                "id": "provider.github.routes",
                "status": "waiting",
                "detail": "github-repo-secrets uses browser_guided (needs_human_gate)",
                "next_action": ("Click Open provider gate in VM and copy the GITHUB_TOKEN value."),
                "resume_hint": "FuseKit will retry provider setup after the value is copied.",
            }
        ],
    )

    assert any("Capture from VM clipboard" in item for item in failures)


def test_acceptance_checkpoint_guidance_requires_capture_resume_copy() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"github": {"github-repo-secrets"}},
        [
            {
                "id": "provider.github.routes",
                "status": "waiting",
                "detail": "github-repo-secrets uses browser_guided (needs_human_gate)",
                "next_action": (
                    "Click Open provider gate in VM, copy GITHUB_TOKEN inside the shared "
                    "VM browser, then click Capture GITHUB_TOKEN from VM clipboard."
                ),
                "resume_hint": "The value is now safely stored.",
            }
        ],
    )

    assert any("resumes after clipboard capture" in item for item in failures)


def test_acceptance_checkpoint_guidance_accepts_exact_launcher_controls() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"github": {"github-repo-secrets"}},
        [
            {
                "id": "provider.github.routes",
                "status": "waiting",
                "detail": "github-repo-secrets uses browser_guided (needs_human_gate)",
                "next_action": (
                    "Click Open provider gate in VM, copy GITHUB_TOKEN inside the shared "
                    "VM browser, then click Capture GITHUB_TOKEN from VM clipboard."
                ),
                "resume_hint": "FuseKit will retry provider setup after capture.",
            }
        ],
    )

    assert failures == []


def test_acceptance_checkpoint_guidance_rejects_manual_resend_setup() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"resend": {"resend-domain"}},
        [
            {
                "id": "provider.resend.routes",
                "status": "waiting",
                "detail": "resend-domain uses browser_guided (needs_human_gate)",
                "next_action": "Click Add domain in Resend, then continue.",
                "resume_hint": "FuseKit will wait for DNS after the domain exists.",
            }
        ],
    )

    assert any("manual Resend domain/audience setup" in item for item in failures)


def test_acceptance_checkpoint_guidance_allows_negated_manual_copy_warning() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"vercel": {"vercel-deploy"}},
        [
            {
                "id": "provider.vercel.routes",
                "status": "done",
                "detail": "vercel-deploy uses api (ok)",
                "next_action": "Nothing to copy manually into Vercel.",
                "resume_hint": "FuseKit recorded the deterministic provider route.",
            }
        ],
    )

    assert failures == []


def test_resend_route_checkpoint_requires_vercel_env_before_dns_when_vercel_present() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {
            "resend": {"resend-domain"},
            "vercel": {"vercel-env"},
        },
        [
            {
                "id": "provider.resend.routes",
                "status": "done",
                "detail": "resend-domain uses api (ok)",
                "next_action": (
                    "Nothing to do manually in Resend; FuseKit creates or reuses "
                    "the domain by API, then waits for DNS approval."
                ),
                "resume_hint": (
                    "FuseKit will retry Resend setup and carry the complete record "
                    "set into the DNS approval gate."
                ),
            },
            {
                "id": "provider.vercel.routes",
                "status": "done",
                "detail": "vercel-env uses api (ok)",
                "next_action": "Nothing to copy manually into Vercel.",
                "resume_hint": "FuseKit recorded the deterministic provider route.",
            },
        ],
    )

    assert "provider.resend.routes is missing Resend-to-Vercel-env recovery guidance" in failures


def test_acceptance_live_requires_real_provider_evidence(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    report = run_acceptance(app, mode="live")

    assert report.launch_ready is False
    assert "encrypted vault" in report.missing
    assert "redacted setup receipt" in report.missing
    assert "safe verification report" in report.missing
    assert "rollback metadata" in report.missing
    assert "provider strategy decisions" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["encrypted vault"]["category"] == "Vault"
    assert "vault capture enabled" in blockers["encrypted vault"]["next_action"]
    assert "live launcher/control room" in blockers["encrypted vault"]["next_action"]
    assert "VM clipboard Capture controls" in blockers["encrypted vault"]["next_action"]
    assert "encrypted vault proof" in blockers["encrypted vault"]["next_action"]
    assert ".fusekit/fusekit.vault.json" not in blockers["encrypted vault"]["next_action"]
    assert blockers["redacted setup receipt"]["category"] == "Receipt"
    assert "live launcher/control room" in blockers["redacted setup receipt"]["next_action"]
    assert (
        "redacted receipt with no raw secrets" in blockers["redacted setup receipt"]["next_action"]
    )
    assert "Rerun setup" not in blockers["redacted setup receipt"]["next_action"]
    assert blockers["safe verification report"]["category"] == "Verification"
    assert "live launcher/control room" in blockers["safe verification report"]["next_action"]
    assert "VM-browser gates" in blockers["safe verification report"]["next_action"]
    assert "pending-safe" in blockers["safe verification report"]["next_action"]
    assert "Run provider verification" not in blockers["safe verification report"]["next_action"]
    assert blockers["rollback metadata"]["category"] == "Rollback"
    assert "live launcher/control room" in blockers["rollback metadata"]["next_action"]
    assert "provider rollback actions before launch" in blockers["rollback metadata"]["next_action"]
    assert "Generate rollback metadata" not in blockers["rollback metadata"]["next_action"]
    assert blockers["provider strategy decisions"]["category"] == "Provider routes"
    assert "live launcher/control room" in blockers["provider strategy decisions"]["next_action"]
    assert "setup worker record" in blockers["provider strategy decisions"]["next_action"]


def test_live_acceptance_rejects_unredacted_setup_receipt_artifact(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    receipt_path = remote_fusekit / "setup_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["actions"] = [
        {
            "action": "github.secret.upsert",
            "status": "ok api_key=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        }
    ]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.redacted")
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "setup_receipt.actions[0].status contains credential-looking text" in (
        receipt_check.detail
    )
    assert "redacted receipt" in report.missing


def test_live_acceptance_rejects_setup_receipt_callback_url_artifact(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    receipt_path = remote_fusekit / "setup_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["actions"] = [
        {
            "action": "github.oauth.callback",
            "status": "reviewed https://provider.example/callback",
        }
    ]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.redacted")
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "setup_receipt.actions[0].status contains callback URL" in receipt_check.detail
    assert "redacted receipt" in report.missing


def test_live_acceptance_rejects_loose_setup_receipt_shape(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    receipt_path = remote_fusekit / "setup_receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["private_note"] = "sidecar"
    receipt["actions"] = [
        {
            "action": " github.secret.upsert ",
            "status": "ok",
            "details": {"provider": "github"},
            "private_note": "sidecar",
        }
    ]
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.redacted")
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "setup_receipt has unexpected fields: private_note" in receipt_check.detail
    assert (
        "setup_receipt.actions[0] has unexpected fields: private_note"
        in receipt_check.detail
    )
    assert "setup_receipt.actions[0].action must be trimmed" in receipt_check.detail
    assert "redacted receipt" in report.missing


def test_live_acceptance_rejects_malformed_raw_secret_exposure_count(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    for index, malformed_count in enumerate((0.1, "0")):
        remote = tmp_path / f"remote-artifacts-{index}"
        remote_fusekit = remote / ".fusekit"
        remote_fusekit.mkdir(parents=True)
        vault = Vault.empty()
        vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
        _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
        receipt_path = remote_fusekit / "setup_receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["raw_secrets_exposed"] = malformed_count
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

        report = run_acceptance(
            app,
            mode="live",
            passphrase="passphrase",
            remote_artifacts_path=remote,
        )

        receipt_check = next(
            check for check in report.checks if check.id == "receipt.redacted"
        )
        assert report.launch_ready is False
        assert receipt_check.status == "failed"
        assert "raw secret exposure count must be literal zero" in receipt_check.detail
        assert "redacted receipt" in report.missing


def test_acceptance_vault_check_blocker_is_launcher_actionable() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "vault.exists",
                    "failed",
                    "Vault not found: .fusekit/fusekit.vault.json",
                )
            ],
            [],
        )
    }

    next_action = blockers["vault.exists"]["next_action"]
    assert blockers["vault.exists"]["category"] == "Vault"
    assert "live launcher/control room" in next_action
    assert "VM clipboard Capture controls" in next_action
    assert "encrypted vault proof" in next_action
    assert "Regenerate or unlock" not in next_action


def test_acceptance_model_inference_blocker_is_launcher_actionable() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "run_record.complete",
                    "failed",
                    "model_inference.status must prove encrypted API key; "
                    "llm_contract.json is missing.",
                )
            ],
            ["model inference contract"],
        )
    }

    missing_action = blockers["model inference contract"]["next_action"]
    check_action = blockers["run_record.complete"]["next_action"]
    assert blockers["model inference contract"]["category"] == "Model inference"
    assert "llm_contract.json" in missing_action
    assert "encrypted API-key lane" in missing_action
    assert blockers["run_record.complete"]["category"] == "Model inference"
    assert "model/inference card" in check_action
    assert "Capture OPENAI_API_KEY from VM clipboard" in check_action
    assert "OpenClaw authorization gate" in check_action
    assert "non-secret llm_contract.json proof" in check_action
    assert "Run acceptance again" not in check_action


def test_acceptance_rehearsal_review_blocker_is_launcher_actionable() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "run_record.complete",
                    "failed",
                    "rehearsal_review.status must be ready; "
                    "rehearsal_review.requires_user_thinking must be false.",
                )
            ],
            [],
        )
    }

    next_action = blockers["run_record.complete"]["next_action"]
    assert blockers["run_record.complete"]["category"] == "Rehearsal review"
    assert "clean rehearsal review" in next_action
    assert "visible control-room instructions" in next_action
    assert "no host browser, terminal, side channel, or user interpretation" in next_action
    assert "Run acceptance again" not in next_action


def test_acceptance_worker_replacement_blocker_is_launcher_actionable() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "run_record.complete",
                    "failed",
                    "recording_contract.checks.worker_replacement must be true; "
                    "worker_replacement_drill.status must be passed.",
                )
            ],
            [],
        )
    }

    next_action = blockers["run_record.complete"]["next_action"]
    assert blockers["run_record.complete"]["category"] == "Worker replacement"
    assert "worker replacement drill" in next_action
    assert "destroy the original OCI worker" in next_action
    assert "encrypted/redacted durable sources" in next_action
    assert "resume a gate or verifier without host-machine state" in next_action
    assert "Run acceptance again" not in next_action


def test_acceptance_unknown_blocker_stays_in_current_control_room() -> None:
    blockers = _acceptance_blockers(
        [
            AcceptanceCheck(
                "custom.launch_proof",
                "failed",
                "Custom launch proof is missing.",
            )
        ],
        [],
    )

    next_action = blockers[0]["next_action"]

    assert blockers[0]["category"] == "Launch evidence"
    assert "keep this live control room open while FuseKit rebuilds" in next_action
    assert "rerun the same live launch/acceptance" not in next_action
    assert "Run acceptance again" not in next_action


def test_acceptance_report_redacts_check_and_blocker_details(tmp_path) -> None:
    raw_code = "abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    check = AcceptanceCheck(
        "provider.callback",
        "failed",
        f"Provider callback failed: https://provider.example/callback?code={raw_code}&state=ok",
    )
    blockers = _acceptance_blockers([check], [])
    report = AcceptanceReport(
        mode="live",
        app_path=str(tmp_path),
        launch_ready=False,
        checks=(check,),
        ledger_path=str(tmp_path / "ledger.jsonl"),
        report_path=str(tmp_path / "report.json"),
        blockers=(
            *blockers,
            {
                "item": "provider callback",
                "category": "Provider",
                "next_action": "Rerun the provider gate.",
                "detail": (
                    "Raw callback detail: "
                    f"https://provider.example/callback?code={raw_code}&state=ok"
                ),
            },
        ),
    )

    payload = report.to_dict()
    text = json.dumps(payload)

    assert raw_code not in text
    assert "code=[redacted]" in text
    assert payload["checks"][0]["detail"].endswith("?code=[redacted]&state=ok")
    assert payload["blockers"][0]["detail"].endswith("?code=[redacted]&state=ok")
    assert payload["blockers"][1]["detail"].endswith("?code=[redacted]&state=ok")


def test_acceptance_blockers_use_launcher_actionable_check_guidance() -> None:
    checks = [
        AcceptanceCheck(
            "gates.guided",
            "failed",
            "provider.cloudflare.authorization missing resume_url",
        ),
        AcceptanceCheck(
            "gates.audited",
            "failed",
            "missing control_room.gate_resume_requested: provider.cloudflare.authorization",
        ),
        AcceptanceCheck(
            "receipt.resend_dns_flow",
            "failed",
            "Receipt DNS proposal is missing Resend-generated records: MX send.moonlite.rsvp",
        ),
        AcceptanceCheck(
            "receipt.provider_contract_health",
            "failed",
            "Receipt is missing provider API contract-health proof before setup for: vercel",
        ),
        AcceptanceCheck(
            "detonation.worker_state",
            "failed",
            "Plaintext worker/browser/visual state still exists: .fusekit/browser",
        ),
        AcceptanceCheck(
            "detonation.workspace_receipt",
            "missing",
            "Live OCI workspace detonation receipt not found: .fusekit/workspace_detonation.json",
        ),
        AcceptanceCheck(
            "gates.resolved",
            "failed",
            "Waiting provider gate still exists: provider.cloudflare.authorization",
        ),
        AcceptanceCheck(
            "provider_packs.validated",
            "missing",
            "Live launch needs at least one validated provider capability pack.",
        ),
        AcceptanceCheck(
            "provider_pack.resend",
            "failed",
            "Provider capability pack could not be snapshotted.",
        ),
        AcceptanceCheck(
            "manifest.snapshotted",
            "failed",
            "Manifest snapshot could not be recorded.",
        ),
        AcceptanceCheck(
            "plan.generated",
            "failed",
            "Setup plan could not be generated.",
        ),
        AcceptanceCheck(
            "rollback_metadata.coverage",
            "failed",
            "Rollback metadata is missing manifest providers: cloudflare",
        ),
        AcceptanceCheck(
            "audit.exists",
            "missing",
            "Audit log not found: .fusekit/audit.jsonl",
        ),
    ]

    blockers = {blocker["item"]: blocker for blocker in _acceptance_blockers(checks, [])}

    assert "live launcher/control room" in blockers["gates.guided"]["next_action"]
    assert "Open provider gate in VM URL" in blockers["gates.guided"]["next_action"]
    assert "I finished this step" in blockers["gates.audited"]["next_action"]
    assert "approve the DNS apply gate" in blockers["receipt.resend_dns_flow"]["next_action"]
    assert (
        "read-only provider health check before mutation"
        in blockers["receipt.provider_contract_health"]["next_action"]
    )
    assert (
        "Keep the launcher/control room open while FuseKit detonates plaintext "
        "worker, browser, visual, provider-auth, control-room, and gateway scratch state"
        in blockers["detonation.worker_state"]["next_action"]
    )
    assert (
        "after encrypted artifacts are preserved"
        in blockers["detonation.worker_state"]["next_action"]
    )
    assert "Run detonation" not in blockers["detonation.worker_state"]["next_action"]
    assert (
        "plaintext worker, browser, visual, and auth scratch state"
        not in blockers["detonation.worker_state"]["next_action"]
    )
    assert (
        "proving the VM, boot volume, ephemeral public IP, network resources, and "
        "remote worker cleanup were destroyed"
        in blockers["detonation.workspace_receipt"]["next_action"]
    )
    assert blockers["detonation.workspace_receipt"]["category"] == "Workspace detonation"
    assert blockers["provider_packs.validated"]["category"] == "Provider packs"
    assert "validates provider capability packs" in blockers[
        "provider_packs.validated"
    ]["next_action"]
    assert "route planning, or verification continues" in blockers[
        "provider_packs.validated"
    ]["next_action"]
    assert blockers["provider_pack.resend"]["category"] == "Provider packs"
    assert "validates provider capability packs" in blockers["provider_pack.resend"][
        "next_action"
    ]
    assert blockers["manifest.snapshotted"]["category"] == "Manifest"
    assert "snapshots the setup manifest" in blockers["manifest.snapshotted"]["next_action"]
    assert blockers["plan.generated"]["category"] == "Setup plan"
    assert "visible Approve setup plan control" in blockers["plan.generated"]["next_action"]
    assert blockers["rollback_metadata.coverage"]["category"] == "Rollback"
    assert "provider rollback actions for every provider declared by the manifest" in blockers[
        "rollback_metadata.coverage"
    ]["next_action"]
    assert "before launch" in blockers["rollback_metadata.coverage"]["next_action"]
    assert blockers["audit.exists"]["category"] == "Audit log"
    assert "redacted JSONL audit log" in blockers["audit.exists"]["next_action"]
    assert "without raw secrets" in blockers["audit.exists"]["next_action"]
    assert "I finished this step button" in blockers["gates.resolved"]["next_action"]
    assert "resume button" not in blockers["gates.resolved"]["next_action"]


def test_acceptance_rejects_audit_log_callback_url_survivor(tmp_path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text(
        json.dumps(
            {
                "event": "provider.callback",
                "detail": "Provider returned https://provider.example/callback",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_audit_log(audit_log, "live", checks, missing)

    assert checks[-1].id == "audit.exists"
    assert checks[-1].status == "failed"
    assert "audit[1].detail contains callback URL" in checks[-1].detail
    assert "redacted audit log" in missing


def test_acceptance_rejects_malformed_audit_log_survivor(tmp_path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text('{"event":"ok"}\nnot-json\n[]\n', encoding="utf-8")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_audit_log(audit_log, "live", checks, missing)

    assert checks[-1].id == "audit.exists"
    assert checks[-1].status == "failed"
    assert "audit.jsonl line 2 is malformed JSON" in checks[-1].detail
    assert "audit.jsonl line 3 is not an object" in checks[-1].detail
    assert "redacted audit log" in missing


def test_acceptance_rejects_empty_audit_log_survivor(tmp_path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text("\n\n", encoding="utf-8")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_audit_log(audit_log, "live", checks, missing)

    assert checks[-1].id == "audit.exists"
    assert checks[-1].status == "failed"
    assert "audit.jsonl has no JSON object rows" in checks[-1].detail
    assert "redacted audit log" in missing


def test_acceptance_rejects_loose_audit_log_survivor_rows(tmp_path) -> None:
    audit_log = tmp_path / "audit.jsonl"
    audit_log.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event": " provider.verify ",
                        "data": "not-object",
                        "ts": 2.0,
                        "private_note": "sidecar audit note",
                    },
                    sort_keys=True,
                ),
                json.dumps({"data": {}, "event": "", "ts": " 2026-06-19T00:00:00Z "}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_audit_log(audit_log, "live", checks, missing)

    assert checks[-1].id == "audit.exists"
    assert checks[-1].status == "failed"
    assert "audit.jsonl[1] has unexpected fields: private_note" in checks[-1].detail
    assert "audit.jsonl[1].event must be trimmed" in checks[-1].detail
    assert "audit.jsonl[1].data must be an object" in checks[-1].detail
    assert "audit.jsonl[1].ts must be a string" in checks[-1].detail
    assert "audit.jsonl[2].event is missing" in checks[-1].detail
    assert "audit.jsonl[2].ts must be trimmed" in checks[-1].detail
    assert "redacted audit log" in missing


def test_acceptance_rejects_credential_text_in_vault_bundle(tmp_path) -> None:
    vault_path = tmp_path / "fusekit.vault.json"
    vault_path.write_text(
        "provider token=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
        encoding="utf-8",
    )
    ledger = HarnessLedger.create(tmp_path / "acceptance")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_vault(vault_path, "passphrase", "live", checks, missing, ledger)

    assert checks[-1].id == "vault.ciphertext_only"
    assert checks[-1].status == "failed"
    assert "plaintext or credential-looking markers" in checks[-1].detail
    assert "ciphertext-only vault" in missing


def test_acceptance_records_failed_vault_unlock_without_crashing(tmp_path) -> None:
    vault_path = tmp_path / "fusekit.vault.json"
    vault_path.write_text('{"version":1,"ciphertext":"not-a-valid-bundle"}\n', encoding="utf-8")
    ledger = HarnessLedger.create(tmp_path / "acceptance")
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_vault(vault_path, "passphrase", "live", checks, missing, ledger)

    assert [check.id for check in checks] == ["vault.ciphertext_only", "vault.unlock"]
    assert checks[0].status == "ok"
    assert checks[1].status == "failed"
    assert "could not be unlocked" in checks[1].detail
    assert "vault unlock proof" in missing


def test_live_acceptance_rejects_provider_pack_callback_url_artifact(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env:
  - OPENAI_API_KEY
webhooks: []
approvals: []
services:
  - provider: openai
    kind: ai
    name: ai
    capabilities: []
    secrets: []
    settings: {}
domains: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    pack = synthesize_provider_pack("openai", app)
    pack = replace(
        pack,
        handoff=replace(
            pack.handoff,
            token_url="https://provider.example/callback",
        ),
    )
    write_provider_pack(pack, app / ".fusekit" / "provider-packs" / "openai.json")

    report = run_acceptance(app, mode="live")

    pack_check = next(check for check in report.checks if check.id == "provider_pack.openai")
    aggregate_check = next(
        check for check in report.checks if check.id == "provider_packs.validated"
    )
    assert report.launch_ready is False
    assert pack_check.status == "failed"
    assert "provider_pack.openai.handoff.token_url contains callback URL" in pack_check.detail
    assert aggregate_check.status == "failed"
    assert "Provider capability packs did not all validate" in aggregate_check.detail
    assert "validated provider capability packs" in report.missing


def test_acceptance_resolved_blocker_names_exact_capture_control() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "gates.resolved",
                    "failed",
                    (
                        "Waiting provider gate still exists: "
                        "provider.resend.authorization target RESEND_API_KEY"
                    ),
                )
            ],
            [],
        )
    }

    next_action = blockers["gates.resolved"]["next_action"]
    assert "Capture RESEND_API_KEY from VM clipboard" in next_action
    assert "matching Capture" not in next_action
    assert "target-specific Capture" not in next_action


def test_acceptance_blockers_keep_unknown_items_launcher_actionable() -> None:
    blockers = _acceptance_blockers(
        [
            AcceptanceCheck(
                "provider_custom.unexpected_artifact",
                "failed",
                "provider-specific proof is missing",
            )
        ],
        ["custom launch proof"],
    )

    by_item = {blocker["item"]: blocker for blocker in blockers}
    for item in ("custom launch proof", "provider_custom.unexpected_artifact"):
        next_action = by_item[item]["next_action"]
        assert "Keep the control room open" in next_action
        assert "single highlighted next action" in next_action
        assert "Open provider gate in VM" in next_action
        assert "env-named Capture button" in next_action
        assert "I finished this step" in next_action
        assert "Approve DNS apply" in next_action
        assert "Use any visible" not in next_action
        assert "Capture RESEND_API_KEY from VM clipboard" not in next_action
        assert "Repair missing launch evidence" not in next_action
        assert "Repair failed acceptance check" not in next_action
        assert "Repair this acceptance item" not in next_action


def test_acceptance_blockers_explain_missing_gate_event_controls() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "gates.audited",
                    "failed",
                    "missing gate events: provider.custom.review",
                )
            ],
            [],
        )
    }

    next_action = blockers["gates.audited"]["next_action"]
    assert "Open provider gate in VM" in next_action
    assert "exact env-named Capture buttons" in next_action
    assert "Capture RESEND_API_KEY from VM clipboard" not in next_action
    assert "I finished this step" in next_action


def test_acceptance_blockers_name_exact_capture_control_from_guidance_failure() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "gates.guided",
                    "failed",
                    (
                        "provider.github.authorization.guidance does not name exact "
                        "Capture controls: Capture GITHUB_TOKEN from VM clipboard"
                    ),
                )
            ],
            [],
        )
    }

    next_action = blockers["gates.guided"]["next_action"]
    assert "Capture GITHUB_TOKEN from VM clipboard" in next_action
    assert "Capture from VM clipboard." not in next_action
    assert "Regenerate copy-once secret gates" not in next_action


def test_acceptance_blockers_name_exact_capture_control_from_audit_failure() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "gates.audited",
                    "failed",
                    (
                        "Control-room gates are missing redacted audit events: "
                        "missing control_room.clipboard_capture: "
                        "provider.openai.authorization:OPENAI_API_KEY"
                    ),
                )
            ],
            [],
        )
    }

    next_action = blockers["gates.audited"]["next_action"]
    assert "Capture OPENAI_API_KEY from VM clipboard" in next_action
    assert "matching Capture from VM clipboard button" not in next_action


def test_acceptance_blockers_prioritize_exact_audit_action_over_generic_gate_events() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "gates.audited",
                    "failed",
                    (
                        "Control-room gates are missing redacted audit events: "
                        "missing gate events: provider.openai.authorization; "
                        "missing control_room.clipboard_capture: "
                        "provider.openai.authorization:OPENAI_API_KEY"
                    ),
                )
            ],
            ["audited human gate interventions"],
        )
    }

    for item in ("gates.audited", "audited human gate interventions"):
        next_action = blockers[item]["next_action"]
        assert "Capture OPENAI_API_KEY from VM clipboard" in next_action
        assert "Open provider gate in VM, exact env-named Capture buttons" not in next_action
        assert "or I finished this step" not in next_action


def test_acceptance_blockers_missing_gate_item_names_exact_open_control() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "gates.audited",
                    "failed",
                    (
                        "Control-room gates are missing redacted audit events: "
                        "missing gate events: provider.cloudflare.authorization; "
                        "missing control_room.gate_open: provider.cloudflare.authorization"
                    ),
                )
            ],
            ["audited human gate interventions"],
        )
    }

    next_action = blockers["audited human gate interventions"]["next_action"]
    assert "Open each provider gate through Open provider gate in VM" in next_action
    assert "exact env-named Capture buttons" not in next_action
    assert "I finished this step" not in next_action


def test_acceptance_blockers_missing_gate_item_names_exact_finished_control() -> None:
    blockers = {
        blocker["item"]: blocker
        for blocker in _acceptance_blockers(
            [
                AcceptanceCheck(
                    "gates.audited",
                    "failed",
                    (
                        "Control-room gates are missing redacted audit events: "
                        "missing gate events: provider.cloudflare.authorization; "
                        "missing control_room.gate_resume_requested: "
                        "provider.cloudflare.authorization"
                    ),
                )
            ],
            ["audited human gate interventions"],
        )
    }

    next_action = blockers["audited human gate interventions"]["next_action"]
    assert "click the visible I finished this step" in next_action
    assert "Open provider gate in VM" not in next_action
    assert "exact env-named Capture buttons" not in next_action


def test_acceptance_blockers_explain_resend_generated_value_recovery() -> None:
    blockers = _acceptance_blockers(
        [
            AcceptanceCheck(
                "gates.guided",
                "failed",
                (
                    "provider.resend.runtime-values.target asks the user to capture "
                    "API-generated Resend values: RESEND_FROM_EMAIL"
                ),
            )
        ],
        [],
    )

    assert blockers[0]["item"] == "gates.guided"
    assert "live launcher/control room" in blockers[0]["next_action"]
    assert "Capture is used only for RESEND_API_KEY" in blockers[0]["next_action"]
    assert "Resend API setup retry" in blockers[0]["next_action"]
    assert "Regenerate the Resend runtime gate" not in blockers[0]["next_action"]


def test_acceptance_blockers_explain_manual_resend_setup_recovery() -> None:
    blockers = _acceptance_blockers(
        [
            AcceptanceCheck(
                "gates.guided",
                "failed",
                ("provider.resend.domain.guidance asks for manual Resend domain/audience setup"),
            )
        ],
        [],
    )

    assert blockers[0]["item"] == "gates.guided"
    assert "live launcher/control room" in blockers[0]["next_action"]
    assert "captures only the setup key" in blockers[0]["next_action"]
    assert "domains and audiences through Resend API" in blockers[0]["next_action"]
    assert "Regenerate the Resend gate" not in blockers[0]["next_action"]


def test_acceptance_blockers_explain_resend_setup_key_guidance_recovery() -> None:
    blockers = _acceptance_blockers(
        [
            AcceptanceCheck(
                "gates.guided",
                "failed",
                (
                    "provider.resend.authorization.guidance must explain existing "
                    "Resend key rows are not enough without the raw key value"
                ),
            )
        ],
        [],
    )

    assert blockers[0]["item"] == "gates.guided"
    next_action = blockers[0]["next_action"]
    assert "Resend API-key gate" in next_action
    assert "Permission: Full access" in next_action
    assert "Domain: All domains" in next_action
    assert "raw key value" in next_action
    assert "Capture RESEND_API_KEY from VM clipboard" in next_action
    assert "I finished this step" not in next_action


def test_resend_api_strategy_requires_domain_ownership_evidence() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "resend",
                "strategies": [
                    {
                        "recipe": "resend-domain",
                        "strategy": "api",
                        "status": "ok",
                        "decision": _strategy_decision(),
                    }
                ],
            }
        ]
    )

    assert "resend.strategies[0].selected.evidence.api_owns must be domain" in failures
    assert (
        "resend.strategies[0].selected.evidence.downstream_order must be before_dns_apply"
        in failures
    )


def test_resend_audience_strategy_requires_conditional_api_evidence() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "resend",
                "strategies": [
                    {
                        "recipe": "resend-audience",
                        "strategy": "api",
                        "status": "ok",
                        "decision": _strategy_decision(),
                    }
                ],
            }
        ]
    )

    assert "resend.strategies[0].selected.evidence.api_owns must be audience" in failures
    assert (
        "resend.strategies[0].selected.evidence.conditional must be only_when_app_requires_audience"
    ) in failures


def test_acceptance_rejects_manual_resend_domain_or_audience_gate_guidance() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.domain-verification",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-domain",
                "reason": "Add and verify the Resend sending domain moonlite.rsvp.",
                "resume_url": "https://resend.com/domains",
                "target": "moonlite.rsvp",
                "follow_steps": [
                    "Open Resend in the VM browser.",
                    "Click Add domain and create a Resend domain for moonlite.rsvp.",
                ],
                "next_action": "Click I finished this step after the domain exists.",
                "resume_hint": "FuseKit will continue after the domain is present.",
                "success_criteria": ["A Resend domain exists for moonlite.rsvp."],
                "avoid_steps": ["Do not create broad API keys."],
            },
            {
                "id": "provider.resend.audience",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-runtime-values",
                "resume_url": "https://resend.com/audiences",
                "target": "",
                "follow_steps": [
                    "Open Resend in the VM browser.",
                    "Click Add audience and create the audience in Resend.",
                ],
                "next_action": "Click I finished this step after the audience exists.",
                "resume_hint": "FuseKit will continue after the audience is present.",
                "success_criteria": ["A Resend audience exists."],
                "avoid_steps": ["Do not create broad API keys."],
            },
            {
                "id": "provider.resend.account",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-authorization",
                "resume_url": "https://resend.com/api-keys",
                "target": "RESEND_API_KEY",
                "follow_steps": [
                    "Click Open provider gate in VM so Resend opens in the VM browser.",
                    "Complete the highlighted domain ownership gate.",
                    "Copy RESEND_API_KEY inside the VM browser and click Capture "
                    "from VM clipboard.",
                ],
                "next_action": (
                    "Click Open provider gate in VM, then click Capture from VM clipboard "
                    "after the key is copied."
                ),
                "resume_hint": "FuseKit will continue after RESEND_API_KEY capture.",
                "success_criteria": ["The Resend domain ownership verification passed."],
                "avoid_steps": ["Do not click Add domain."],
            },
        ]
    )

    assert any(
        "provider.resend.domain-verification.guidance asks for manual Resend "
        "domain/audience setup" in failure
        for failure in failures
    )
    assert any(
        "provider.resend.audience.guidance asks for manual Resend domain/audience setup" in failure
        for failure in failures
    )
    assert any(
        "provider.resend.account.guidance asks for manual Resend domain/audience setup" in failure
        for failure in failures
    )


def test_acceptance_rejects_manual_resend_setup_in_success_or_avoid_panels() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.domain-setup-retry",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-setup-retry",
                "resume_url": "https://resend.com/api-keys",
                "target": "",
                "follow_steps": [
                    "Open provider gate in VM and stay on Resend API Keys.",
                    "Click I finished this step so FuseKit retries Resend API setup.",
                ],
                "next_action": ("Click I finished this step so FuseKit retries Resend API setup."),
                "resume_hint": "FuseKit will create or reuse the sending domain by API.",
                "success_criteria": ["Create a Resend domain for moonlite.rsvp."],
                "avoid_steps": ["If blocked, click Add domain in Resend."],
            }
        ]
    )

    assert any(
        "provider.resend.domain-setup-retry.guidance asks for manual Resend "
        "domain/audience setup" in failure
        for failure in failures
    )


def test_acceptance_allows_resend_api_owned_domain_retry_guidance() -> None:
    failures = _unguided_gates(
        [
            {
                "id": "provider.resend.domain-setup-retry",
                "provider": "resend",
                "status": "waiting",
                "classification": "provider-setup-retry",
                "resume_url": "https://resend.com/api-keys",
                "target": "",
                "follow_steps": [
                    "Open provider gate in VM and stay on Resend API Keys.",
                    "Do not click Add domain; FuseKit creates or reuses the domain.",
                    "Click I finished this step so FuseKit retries Resend API setup.",
                ],
                "next_action": ("Click I finished this step so FuseKit retries Resend API setup."),
                "resume_hint": (
                    "FuseKit will create or reuse the sending domain through Resend API, "
                    "then hand returned DNS records to Cloudflare."
                ),
                "success_criteria": ["Resend API key has been captured through the launcher."],
                "avoid_steps": ["Do not click Add domain in Resend."],
            }
        ]
    )

    assert failures == []


def test_acceptance_allows_gate_service_default_provider_guidance(tmp_path) -> None:
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.github.authorization",
        provider="github",
        reason="GitHub setup token",
        resume_url="https://github.com/settings/tokens?type=beta",
        classification="provider-authorization",
        target="GITHUB_TOKEN",
    )

    gates = json.loads((tmp_path / "gates.json").read_text(encoding="utf-8"))["gates"]

    assert _unguided_gates(gates) == []
    assert any("Open provider gate in VM" in step for step in gates[0]["follow_steps"])
    assert any(
        "Capture GITHUB_TOKEN from VM clipboard" in step for step in gates[0]["follow_steps"]
    )


def test_acceptance_live_ingests_retrieved_oci_artifacts(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    (app / "vercel.json").write_text(
        json.dumps({"domains": ["moonlite.example"]}),
        encoding="utf-8",
    )
    (app / "index.js").write_text("console.log(process.env.WEBHOOK_SECRET)", encoding="utf-8")

    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.put(
        "provider.github.token",
        "provider_token",
        "github",
        "GitHub token",
        "ghp_secret_for_harness",
    )
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    openai_capture_wake_id = "wake-openai-capture"
    provider_review_wake_id = "wake-provider-review-resume"
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_open",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "protected_action": True,
                            "has_last_opened_url": True,
                            "has_resume_url": True,
                            "reused": False,
                            "status": "waiting",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.clipboard_capture",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "protected_action": True,
                            "status": "passed",
                            "target": "OPENAI_API_KEY",
                            "record_id": "provider.openai.token",
                            "source": "vm-clipboard",
                            "storage": "encrypted-vault",
                            "capture_wake_event_id": openai_capture_wake_id,
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_open",
                        "data": {
                            "gate_id": "provider.review",
                            "provider": "provider",
                            "protected_action": True,
                            "has_last_opened_url": True,
                            "has_resume_url": True,
                            "reused": False,
                            "status": "waiting",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.review",
                            "provider": "provider",
                            "protected_action": True,
                            "status": "resume_requested",
                            "wake_event_id": provider_review_wake_id,
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "gate_events.jsonl").write_text(
        "\n".join(
            [
                json.dumps(
                    _gate_wake_event(
                        openai_capture_wake_id,
                        "clipboard_captured",
                        "provider.openai.authorization",
                        provider="openai",
                        classification="provider-authorization",
                        status="passed",
                        target="OPENAI_API_KEY",
                        captured_targets=["OPENAI_API_KEY"],
                    ),
                    sort_keys=True,
                ),
                json.dumps(
                    _gate_wake_event(
                        provider_review_wake_id,
                        "resume_requested",
                        "provider.review",
                        provider="provider",
                        classification="provider-verification",
                    ),
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
                {
                    "live_url": "https://moonlite.example",
                    "raw_secrets_exposed": 0,
                    "actions": [
                        {
                            "action": "github.secret.upsert",
                            "status": "ok",
                            "details": {"provider": "github"},
                        }
                    ],
                }
            ),
            "utf-8",
        )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": _verification_report_checks()}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps(
            {
                "rollback": [
                    {"action": "rollback.github.secret", "status": "planned"},
                    {"action": "rollback.vercel.env", "status": "planned"},
                    {"action": "rollback.cloudflare.dns", "status": "planned"},
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "playbook": _provider_playbook(),
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "github",
                                    "recipe_kind": "github-repo-secrets",
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    },
                    {
                        "provider": "vercel",
                        "strategies": [
                            {
                                "recipe": "vercel-deploy",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "vercel",
                                    "recipe_kind": "vercel-deploy",
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    },
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "cloudflare",
                                    "recipe_kind": "cloudflare-dns",
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "checkpoints.json").write_text(
        json.dumps(
            {
                "job_id": "fk-test",
                "status": "running",
                "checkpoints": [
                    {
                        "id": "provider.github.routes",
                        "label": "Provider route: github",
                        "status": "done",
                        "detail": "github-repo-secrets uses api (ok)",
                        "next_action": "Nothing to do manually unless FuseKit surfaces a gate.",
                        "resume_hint": "FuseKit recorded the deterministic provider route.",
                        "mascot_state": "verify",
                    },
                    {
                        "id": "provider.vercel.routes",
                        "label": "Provider route: vercel",
                        "status": "done",
                        "detail": "vercel-deploy uses api (ok)",
                        "next_action": "Nothing to copy manually into Vercel.",
                        "resume_hint": "FuseKit recorded the deterministic provider route.",
                        "mascot_state": "verify",
                    },
                    {
                        "id": "provider.resend.routes",
                        "label": "Provider route: resend",
                        "status": "done",
                        "detail": "resend-domain uses api (ok)",
                        "next_action": (
                            "Nothing to create manually in Resend; FuseKit creates or "
                            "reuses the domain by API, carries the DNS records into the "
                            "DNS approval gate, then applies the Resend values into "
                            "Vercel env by API."
                        ),
                        "resume_hint": (
                            "FuseKit will retry Resend setup, DNS verification, and "
                            "Vercel env wiring from the recorded route."
                        ),
                        "mascot_state": "verify",
                    },
                    {
                        "id": "provider.cloudflare.routes",
                        "label": "Provider route: cloudflare",
                        "status": "done",
                        "detail": "cloudflare-dns uses api (ok)",
                        "next_action": "Approve the DNS apply step only if FuseKit asks.",
                        "resume_hint": "FuseKit recorded the deterministic provider route.",
                        "mascot_state": "verify",
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.openai.authorization",
                        "provider": "openai",
                        "reason": "OpenAI auth complete",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "target": "OPENAI_API_KEY",
                        "attempts": 1,
                        "follow_steps": [
                            ("Click Open provider gate in VM so OpenAI opens in the VM browser."),
                            "Complete login in the VM browser.",
                            (
                                "Copy the OpenAI key inside the VM browser and click "
                                "Capture OPENAI_API_KEY from VM clipboard."
                            ),
                        ],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                        "captured_targets": ["OPENAI_API_KEY"],
                        "resume_url": "https://platform.openai.com/api-keys",
                        "last_opened_url": "https://platform.openai.com/api-keys",
                        **_gate_guidance_fields("openai"),
                    },
                    {
                        "id": "provider.review",
                        "provider": "provider",
                        "reason": "Provider review completed",
                        "status": "passed",
                        "classification": "provider-verification",
                        "target": "provider review confirmation",
                        "attempts": 1,
                        "follow_steps": [
                            "Click Open provider gate in VM so the provider review opens.",
                            "Review the highlighted provider confirmation.",
                        ],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                        "resume_url": "https://provider.example/review",
                        **_gate_guidance_fields("provider"),
                    },
                ]
            }
        ),
        "utf-8",
    )
    _write_runner_readiness(remote_fusekit)
    _write_safe_visual_state(remote_fusekit)
    (remote_fusekit / "llm_contract.json").write_text(json.dumps(_llm_contract()), "utf-8")
    (remote_fusekit / "workspace_detonation.json").write_text(
        json.dumps(_workspace_detonation_receipt()),
        encoding="utf-8",
    )
    _write_durable_survivor_stubs(remote_fusekit)
    _write_minimum_run_record(remote_fusekit)
    run_record_path = remote_fusekit / "run_record.json"
    run_record = json.loads(run_record_path.read_text(encoding="utf-8"))
    run_record["provider_gates"] = {
        "total": 2,
        "statuses": {"passed": 2},
        "providers": ["openai", "provider"],
        "records": [
            {
                "id": "provider.openai.authorization",
                "provider": "openai",
                "status": "passed",
                "target": "OPENAI_API_KEY",
                "captured_targets": ["OPENAI_API_KEY"],
                "last_wake_event_id": openai_capture_wake_id,
                "last_wake_event": "clipboard_captured",
                "last_wake_event_at": 1.0,
            },
            {
                "id": "provider.review",
                "provider": "provider",
                "status": "passed",
                "target": "provider review confirmation",
                "captured_targets": [],
                "last_wake_event_id": provider_review_wake_id,
                "last_wake_event": "resume_requested",
                "last_wake_event_at": 2.0,
            },
        ],
    }
    run_record_actions = [
        {
            "gate_id": "provider.openai.authorization",
            "provider": "openai",
            "classification": "provider-authorization",
            "action": "capture_vm_clipboard",
            "visible_control": "Capture OPENAI_API_KEY from VM clipboard",
            "target": "OPENAI_API_KEY",
            "guided": True,
            "created_at": 1.0,
        },
        {
            "gate_id": "provider.review",
            "provider": "provider",
            "classification": "provider-verification",
            "action": "confirm_gate_finished",
            "visible_control": "I finished this step",
            "target": "",
            "guided": True,
            "created_at": 2.0,
        },
    ]
    run_record["human_actions"] = _human_action_trace_for(run_record_actions)
    run_record["rehearsal_review"] = _rehearsal_review_for(run_record_actions)
    run_record_path.write_text(json.dumps(run_record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    assert report.launch_ready is True
    assert report.public_launch_ready is True
    assert report.recording_ready is True
    check_ids = {check.id for check in report.checks}
    assert "remote_artifacts.loaded" in check_ids
    assert "run_record.complete" in check_ids
    assert "verification_report.safe" in check_ids
    assert "provider_strategies.recorded" in check_ids
    assert "provider_strategies.playbook" in check_ids
    assert "provider_strategies.checkpoints" in check_ids
    assert "gates.resolved" in check_ids
    assert "gates.audited" in check_ids
    assert report.missing == ()
    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    remote_inventory = json.loads(Path(remote_check.artifact).read_text(encoding="utf-8"))
    assert remote_inventory["files"]["llm_contract.json"]["present"] is True
    for _, path, _, _ in DURABLE_STATE_SOURCES:
        assert remote_inventory["files"][path]["present"] is True
    assert remote_inventory["files"]["audit.jsonl"]["present"] is True
    gates_check = next(check for check in report.checks if check.id == "gates.resolved")
    gates_artifact = gates_check.artifact
    gates_text = Path(gates_artifact).read_text(encoding="utf-8")
    assert "secret-code" not in gates_text
    assert "secret-token" not in gates_text
    assert "abcdefghijklmnopqrstuvwxyz1234567890abcdef" not in gates_text
    assert "platform.openai.com" not in gates_text
    assert "provider.example/review" not in gates_text
    assert "has_resume_url" in gates_text
    assert "captured_count" in gates_text
    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    audit_text = Path(audit_check.artifact).read_text(encoding="utf-8")
    assert "secret-code" not in audit_text
    assert "secret-token" not in audit_text
    assert "provider.openai.authorization" in audit_text
    report_json = json.loads((app / ".fusekit" / "acceptance" / "report.json").read_text())
    assert report_json["launch_ready"] is True
    assert report_json["public_launch_ready"] is True
    assert report_json["recording_proof_ready"] is True
    assert report_json["recording_ready"] is True
    assert report_json["recording_contract"]["schema_version"] == (
        "fusekit.recording-contract.v1"
    )
    assert report_json["recording_contract"]["recording_ready"] is True
    assert report_json["recording_contract"]["checks"]["rehearsal_review"] is True
    assert report_json["recording_contract"]["checks"]["worker_replacement"] is True
    assert report_json["recording_contract"]["checks"]["model_inference"] is True
    assert report_json["recording_contract"]["blockers"] == []
    assert report_json["recording_contract"]["check_count"] >= 14
    assert "public demo" in report_json["recording_contract"]["statement"]
    assert report_json["blockers"] == []
    assert any(check["id"] == "remote_artifacts.loaded" for check in report_json["checks"])
    ledger_events = [
        json.loads(line)
        for line in (app / ".fusekit" / "acceptance" / "ledger.jsonl").read_text().splitlines()
    ]
    finished = next(event for event in ledger_events if event["event"] == "acceptance.finished")
    assert finished["data"]["recording_proof_ready"] is True
    assert finished["data"]["recording_ready"] is True
    assert finished["data"]["recording_contract"] == {
        "recording_ready": True,
        "check_count": report_json["recording_contract"]["check_count"],
        "blockers": [],
    }


def test_live_acceptance_requires_provider_route_recovery_checkpoints(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "playbook": _provider_playbook(),
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "github",
                                    "recipe_kind": "github-repo-secrets",
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    checkpoint_check = next(
        check for check in report.checks if check.id == "provider_strategies.checkpoints"
    )
    assert report.launch_ready is False
    assert checkpoint_check.status == "failed"
    assert "Provider route checkpoints not found" in checkpoint_check.detail
    assert "provider route recovery checkpoints" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["provider route recovery checkpoints"]["category"] == "Provider routes"
    next_action = blockers["provider route recovery checkpoints"]["next_action"]
    assert "live launcher/control room" in next_action
    assert "provider-route cards" in next_action
    assert "next action and resume hint" in next_action
    assert "Resend API setup" in next_action
    assert "Vercel env wiring" in next_action
    assert "DNS approval" in next_action
    assert "complete generated record set" in next_action
    assert "keep this live control room open" in next_action
    assert "rerun the same live launcher" not in next_action
    assert "checkpoints.json" not in next_action


def test_provider_route_checkpoints_require_exact_capture_control_labels() -> None:
    failures = _provider_strategy_checkpoint_failures(
        {"github": {"github-repo-secrets"}},
        [
            {
                "id": "provider.github.routes",
                "label": "Provider route: github",
                "status": "waiting",
                "detail": (
                    "github-repo-secrets needs_human_gate for GITHUB_TOKEN in the VM browser."
                ),
                "next_action": (
                    "Click Open provider gate in VM, copy GITHUB_TOKEN, then click "
                    "Capture from VM clipboard."
                ),
                "resume_hint": "FuseKit will retry setup after capture.",
            }
        ],
    )

    assert any("exact Capture controls" in failure for failure in failures)
    assert any("Capture GITHUB_TOKEN from VM clipboard" in failure for failure in failures)


def test_live_acceptance_requires_provider_playbook(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {
                                    "provider": "github",
                                    "recipe_kind": "github-repo-secrets",
                                    **_strategy_decision(),
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "checkpoints.json").write_text(
        json.dumps(
            {
                "job_id": "fk-test",
                "status": "running",
                "checkpoints": [
                    {
                        "id": "provider.github.routes",
                        "label": "Provider route: github",
                        "status": "done",
                        "detail": "github-repo-secrets uses api (ok)",
                        "next_action": "Nothing to do manually unless FuseKit surfaces a gate.",
                        "resume_hint": "FuseKit recorded the deterministic provider route.",
                        "mascot_state": "verify",
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    playbook_check = next(
        check for check in report.checks if check.id == "provider_strategies.playbook"
    )
    assert report.launch_ready is False
    assert playbook_check.status == "failed"
    assert "missing the ordered provider playbook" in playbook_check.detail
    assert "provider playbook" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["provider playbook"]["category"] == "Provider playbook"
    next_action = blockers["provider playbook"]["next_action"]
    assert "live launcher/control room" in next_action
    assert "ordered VM-browser actions" in next_action
    assert "exact Capture controls" in next_action
    assert "DNS approval" in next_action
    assert "Resend no-manual-setup" in next_action


def test_acceptance_run_record_requires_provider_playbook_public_order(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["provider_playbook"] = _provider_playbook()
    record["provider_playbook"]["steps"] = [
        {
            "id": "resend.capture_key",
            "provider": "resend",
            "route": "browser_guided",
            "control": "Capture RESEND_API_KEY from VM clipboard",
            "instruction": "Capture RESEND_API_KEY from VM clipboard.",
        },
        {
            "id": "dns.approval",
            "provider": "dns",
            "route": "human_follow_me",
            "control": "Approve DNS apply",
            "instruction": "FuseKit carries DNS records into the DNS approval gate.",
        },
        {
            "id": "resend.domain_api",
            "provider": "resend",
            "route": "api",
            "control": "FuseKit API worker",
            "instruction": "FuseKit creates or reuses the Resend sending domain by API.",
        },
        {
            "id": "vercel.env_api",
            "provider": "vercel",
            "route": "api",
            "control": "FuseKit API worker",
            "instruction": "FuseKit writes runtime variables into Vercel.",
        },
    ]

    failures = _run_record_shape_failures(record)

    assert "provider_playbook.steps must place resend.domain_api before dns.approval" in failures
    assert "provider_playbook.steps must place vercel.env_api before dns.approval" in failures


def test_acceptance_run_record_rejects_duplicate_provider_playbook_step_ids(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["provider_playbook"] = _provider_playbook()
    duplicate = dict(record["provider_playbook"]["steps"][2])
    duplicate["instruction"] = "Conflicting duplicate Resend domain proof row."
    record["provider_playbook"]["steps"].insert(4, duplicate)

    failures = _run_record_shape_failures(record)

    assert "provider_playbook.steps has duplicate id resend.domain_api" in failures


def test_acceptance_run_record_rejects_duplicate_verifier_identities(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    duplicate = dict(record["verifiers"]["checks"][1])
    record["verifiers"]["checks"].append(duplicate)
    record["verifiers"]["counts"]["passed"] += 1

    failures = _run_record_shape_failures(record)

    assert "verifiers.checks[5] duplicates verifier identity resend.domain_verified" in failures


def test_acceptance_run_record_requires_provider_playbook_route_controls(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_playbook"] = _provider_playbook()
    record["provider_playbook"]["steps"] = [
        {
            "id": "resend.capture_key",
            "provider": "resend",
            "route": "browser_guided",
            "actor": " FuseKit ",
            "human_action_required": False,
            "control": "I finished this step",
            "instruction": "Capture RESEND_API_KEY from VM clipboard.",
            "private_note": "sidecar route-plan note",
        },
        {
            "id": "resend.domain_api",
            "provider": "resend",
            "route": "api",
            "actor": "You",
            "human_action_required": True,
            "control": "Approve DNS apply",
            "instruction": "FuseKit creates or reuses the Resend sending domain by API.",
        },
        {
            "id": "provider.finished_step",
            "provider": "provider",
            "route": "human_follow_me",
            "actor": "You",
            "human_action_required": True,
            "control": "Continue",
            "instruction": "Finish the provider prompt in the VM browser.",
        },
    ]

    failures = _run_record_shape_failures(record)

    assert "provider_playbook.steps[0].actor must not have surrounding whitespace" in failures
    assert "provider_playbook.steps[0] has unexpected fields: private_note" in failures
    assert "provider_playbook.steps[0].actor must be You for browser_guided routes" in failures
    assert (
        "provider_playbook.steps[0].human_action_required must be true "
        "for browser_guided routes"
    ) in failures
    assert "provider_playbook.steps[0].control must be an env-named Capture control" in failures
    assert (
        "provider_playbook.steps[0].control must capture RESEND_API_KEY before "
        "Resend API setup" in failures
    )
    assert "provider_playbook.steps[1].actor must be FuseKit for api routes" in failures
    assert (
        "provider_playbook.steps[1].human_action_required must be false "
        "for api routes"
    ) in failures
    assert (
        "provider_playbook.steps[1].control must be FuseKit API worker for api routes" in failures
    )
    assert "provider_playbook.steps[2].control must be a known follow-me control" in failures


def test_acceptance_run_record_rejects_unsafe_provider_playbook_safety_notes(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_playbook"] = _provider_playbook()
    record["provider_playbook"]["safety_notes"].append(
        "If the VM browser is slow, use a local browser tab to manually finish provider setup."
    )

    failures = _run_record_shape_failures(record)

    assert (
        "provider_playbook.safety_notes[3] contains non-launcher wording: "
        "local browser/host browser"
    ) in failures
    assert any("manual action" in failure for failure in failures)

    record["provider_playbook"]["safety_notes"][-1] = (
        "Use the visible Capture <TARGET> from VM clipboard button."
    )
    failures = _run_record_shape_failures(record)

    assert "provider_playbook.safety_notes[3] uses placeholder Capture guidance" in failures

    record["provider_playbook"]["safety_notes"][-1] = (
        "Do not use a local browser tab for provider gates."
    )
    failures = _run_record_shape_failures(record)

    assert not any("provider_playbook.safety_notes[3]" in failure for failure in failures)


def test_acceptance_run_record_rejects_loose_provider_playbook_safety_notes(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_playbook"] = _provider_playbook()
    safety_notes = record["provider_playbook"]["safety_notes"]
    assert isinstance(safety_notes, list)
    safety_notes[0] = f" {safety_notes[0]} "
    safety_notes.append(safety_notes[1])
    safety_notes.append("")
    safety_notes.append({"text": "sidecar safety note"})

    failures = _run_record_shape_failures(record)

    assert "provider_playbook.safety_notes[0] must not have surrounding whitespace" in failures
    assert (
        "provider_playbook.safety_notes[3] duplicates generated safety guidance"
        in failures
    )
    assert "provider_playbook.safety_notes[4] must not be empty" in failures
    assert "provider_playbook.safety_notes[5] must be text" in failures


def test_live_acceptance_requires_central_run_record(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "run_record.json").unlink()
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [
                    {"action": "resend.contract_health", "status": "ok", "details": {}},
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[
                                {
                                    "name": "send.moonlite.rsvp",
                                    "type": "MX",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                    "ttl": 300,
                                    "priority": 10,
                                }
                            ]
                        ),
                    },
                    {"action": "vercel.contract_health", "status": "ok", "details": {}},
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                ],
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "missing"
    assert "central run record" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["central run record"]["category"] == "Run record"
    assert "current control room" in blockers["central run record"]["next_action"]


def test_live_acceptance_requires_run_record_provider_strategies_to_match_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["provider_strategies"]["providers"][0]["strategies"][0]["status"] = "stale"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert (
        "provider_strategies in Run Record must match provider_strategies.json"
        in run_record_check.detail
    )
    assert "central run record" in report.missing


def test_live_acceptance_rejects_run_record_provider_strategy_reason_drift(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    selected = record["provider_strategies"]["providers"][0]["strategies"][0]["decision"][
        "selected"
    ]
    selected["reason"] = "stale route rationale"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert (
        "provider_strategies in Run Record must match provider_strategies.json"
        in run_record_check.detail
    )
    assert "central run record" in report.missing


def test_live_acceptance_requires_run_record_provider_playbook_to_match_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["provider_playbook"]["steps"][0]["instruction"] = (
        "Stale instruction: open a local provider tab and figure out the setup."
    )
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert (
        "provider_playbook in Run Record must match provider_strategies.json playbook"
        in run_record_check.detail
    )
    assert "central run record" in report.missing


def test_live_acceptance_rejects_provider_strategies_callback_url_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    artifact_path = remote_fusekit / "provider_strategies.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["playbook"]["safety_notes"].append(
        "Provider callback reviewed at https://provider.example/callback"
    )
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["provider_playbook"]["safety_notes"].append(
        "Provider callback reviewed at https://provider.example/callback"
    )
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    strategies_check = next(
        check for check in report.checks if check.id == "provider_strategies.recorded"
    )
    assert report.launch_ready is False
    assert strategies_check.status == "failed"
    assert "provider_strategies.playbook.safety_notes[" in strategies_check.detail
    assert "contains callback URL" in strategies_check.detail
    assert "provider strategy decisions" in report.missing


def test_live_acceptance_requires_llm_contract_artifact(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "llm_contract.json").unlink()

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "llm_contract.json artifact is missing" in run_record_check.detail
    assert "central run record" in report.missing


def test_live_acceptance_fails_remote_artifact_inventory_when_survivor_missing(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "llm_contract.json").unlink()

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "missing llm_contract.json" in remote_check.detail
    remote_inventory = json.loads(Path(remote_check.artifact).read_text(encoding="utf-8"))
    assert remote_inventory["files"]["llm_contract.json"]["present"] is False
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["remote_artifacts.loaded"]["category"] == "Remote artifacts"
    assert "complete OCI artifact bundle" in blockers["remote_artifacts.loaded"]["next_action"]


def test_live_acceptance_inventory_tracks_all_durable_survivors(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "run_state.json").unlink()

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "missing run_state.json" in remote_check.detail
    remote_inventory = json.loads(Path(remote_check.artifact).read_text(encoding="utf-8"))
    assert sorted(remote_inventory["files"]) == sorted(REMOTE_ALLOWED_SURVIVOR_FILES)
    assert remote_inventory["files"]["run_state.json"]["present"] is False


def test_live_acceptance_fails_remote_artifact_inventory_when_survivor_is_not_file(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "run_state.json").unlink()
    (remote_fusekit / "run_state.json").mkdir()

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "non-file survivors run_state.json" in remote_check.detail
    remote_inventory = json.loads(Path(remote_check.artifact).read_text(encoding="utf-8"))
    assert remote_inventory["files"]["run_state.json"]["exists"] is True
    assert remote_inventory["files"]["run_state.json"]["present"] is False
    assert remote_inventory["files"]["run_state.json"]["bytes"] == 0


def test_live_acceptance_fails_remote_artifact_inventory_when_survivor_is_linked(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    host_run_state = tmp_path / "host-run-state.json"
    host_run_state.write_text('{"host":"state"}', encoding="utf-8")
    (remote_fusekit / "run_state.json").unlink()
    try:
        (remote_fusekit / "run_state.json").symlink_to(host_run_state)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "linked survivors run_state.json" in remote_check.detail
    remote_inventory = json.loads(Path(remote_check.artifact).read_text(encoding="utf-8"))
    assert remote_inventory["files"]["run_state.json"]["exists"] is True
    assert remote_inventory["files"]["run_state.json"]["present"] is False
    assert remote_inventory["files"]["run_state.json"]["linked"] is True
    assert remote_inventory["files"]["run_state.json"]["bytes"] == 0


def test_live_acceptance_fails_remote_artifact_inventory_when_survivor_is_empty(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "run_state.json").write_text("", encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "empty survivors run_state.json" in remote_check.detail
    remote_inventory = json.loads(Path(remote_check.artifact).read_text(encoding="utf-8"))
    assert remote_inventory["files"]["run_state.json"]["exists"] is True
    assert remote_inventory["files"]["run_state.json"]["present"] is True
    assert remote_inventory["files"]["run_state.json"]["bytes"] == 0
    assert remote_inventory["files"]["run_state.json"]["empty"] is True


def test_live_acceptance_inventory_allows_empty_gate_events_for_no_gate_runs(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "run_state.json").unlink()
    (remote_fusekit / "gate_events.jsonl").write_text("", encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "missing run_state.json" in remote_check.detail
    assert "empty survivors gate_events.jsonl" not in remote_check.detail
    remote_inventory = json.loads(Path(remote_check.artifact).read_text(encoding="utf-8"))
    assert remote_inventory["files"]["gate_events.jsonl"]["present"] is True
    assert remote_inventory["files"]["gate_events.jsonl"]["empty"] is True


def test_live_acceptance_rejects_run_state_callback_url_survivor(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    run_state_path = remote_fusekit / "run_state.json"
    run_state = json.loads(run_state_path.read_text(encoding="utf-8"))
    run_state["recovery_note"] = "Provider callback returned https://provider.example/callback"
    run_state_path.write_text(json.dumps(run_state), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "unsafe public survivor text" in remote_check.detail
    assert "run_state.recovery_note contains callback URL" in remote_check.detail


def test_live_acceptance_rejects_loose_run_state_survivor(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    run_state_path = remote_fusekit / "run_state.json"
    run_state = json.loads(run_state_path.read_text(encoding="utf-8"))
    run_state["private_note"] = "sidecar run-state note"
    run_state["detonation_safe"] = "true"
    run_state["ready_to_detonate"] = 1
    run_state["notes"] = [" recovery note "]
    run_state["missing_for_detonation"] = [" vault_created ", "unknown_field"]
    run_state_path.write_text(json.dumps(run_state), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "run_state has unexpected fields: private_note" in remote_check.detail
    assert "run_state.detonation_safe must be boolean" in remote_check.detail
    assert "run_state.ready_to_detonate must be boolean" in remote_check.detail
    assert "run_state.notes[0] must be trimmed" in remote_check.detail
    assert "run_state.missing_for_detonation[0] must be trimmed" in remote_check.detail
    assert (
        "run_state.missing_for_detonation has unknown fields: unknown_field"
        in remote_check.detail
    )


def test_acceptance_run_record_rejects_loose_embedded_run_state(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["state"]["private_note"] = "sidecar state proof"
    record["state"]["detonation_safe"] = "true"
    record["state"]["ready_to_detonate"] = 1
    record["state"]["notes"] = [" recovery note "]
    record["state"]["missing_for_detonation"] = [" vault_created ", "unknown_field"]

    failures = _run_record_shape_failures(record)

    assert "state has unexpected fields: private_note" in failures
    assert "state.detonation_safe must be boolean" in failures
    assert "state.detonation_safe must be true" in failures
    assert "state.ready_to_detonate must be boolean" in failures
    assert "state.notes[0] must be trimmed" in failures
    assert "state.missing_for_detonation[0] must be trimmed" in failures
    assert "state.missing_for_detonation has unknown fields: unknown_field" in failures


def test_acceptance_run_record_rejects_loose_top_level_envelope(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["private_note"] = "sidecar run record proof"
    record["created_at"] = True
    record["updated_at"] = -1

    failures = _run_record_shape_failures(record)

    assert "run_record has unexpected fields: private_note" in failures
    assert "created_at must be a number" in failures
    assert "updated_at must be a non-negative number" in failures


def test_live_acceptance_rejects_checkpoint_callback_url_survivor(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "checkpoints.json").write_text(
        json.dumps(
            [
                {
                    "phase": "provider_strategy",
                    "detail": "Resume after https://provider.example/callback",
                }
            ]
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "unsafe public survivor text" in remote_check.detail
    assert "checkpoints[0].detail contains callback URL" in remote_check.detail


def test_live_acceptance_rejects_loose_remote_job_and_checkpoint_survivors(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    job_path = remote_fusekit / "job.json"
    job = json.loads(job_path.read_text(encoding="utf-8"))
    job["private_note"] = "sidecar job note"
    job["status"] = " done "
    job["steps"] = [
        {
            "id": " setup.execute ",
            "label": "Setup worker",
            "status": "done",
            "detail": "Ready",
            "updated_at": 2.0,
            "private_note": "sidecar step note",
        }
    ]
    job["checkpoints"] = [
        {
            "id": "setup.execute",
            "label": " Setup worker ",
            "status": "done",
            "detail": "Ready",
            "next_action": "No action.",
            "resume_hint": "Done.",
            "mascot_state": "verify",
            "updated_at": 2.0,
            "private_note": "sidecar checkpoint note",
        }
    ]
    job_path.write_text(json.dumps(job), encoding="utf-8")
    checkpoints_path = remote_fusekit / "checkpoints.json"
    checkpoints = json.loads(checkpoints_path.read_text(encoding="utf-8"))
    checkpoints["private_note"] = "sidecar checkpoint file note"
    checkpoints["status"] = " done "
    checkpoints["checkpoints"] = [
        {
            "id": "setup.execute",
            "label": " Setup worker ",
            "status": "done",
            "detail": "Ready",
            "next_action": "No action.",
            "resume_hint": "Done.",
            "mascot_state": "verify",
            "updated_at": 2.0,
            "private_note": "sidecar checkpoint note",
        }
    ]
    checkpoints_path.write_text(json.dumps(checkpoints), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "job has unexpected fields: private_note" in remote_check.detail
    assert "job.status must be trimmed" in remote_check.detail
    assert "job.steps[0] has unexpected fields: private_note" in remote_check.detail
    assert "job.steps[0].id must be trimmed" in remote_check.detail
    assert "job.checkpoints[0] has unexpected fields: private_note" in remote_check.detail
    assert "job.checkpoints[0].label must be trimmed" in remote_check.detail
    assert "checkpoints has unexpected fields: private_note" in remote_check.detail
    assert "checkpoints.status must be trimmed" in remote_check.detail
    assert (
        "checkpoints.checkpoints[0] has unexpected fields: private_note"
        in remote_check.detail
    )
    assert "checkpoints.checkpoints[0].label must be trimmed" in remote_check.detail


def test_live_acceptance_rejects_loose_worker_replacement_drill_survivor(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    drill_path = remote_fusekit / "worker_replacement_drill.json"
    drill = json.loads(drill_path.read_text(encoding="utf-8"))
    drill["private_note"] = "sidecar drill note"
    drill["status"] = " passed "
    drill["worker_destroyed"] = "true"
    drill["replacement_runner_profile_ready"] = 1
    drill["host_machine_state_required"] = True
    drill["volatile_state_reused"] = "false"
    drill["restored_from"] = [
        *WORKER_REPLACEMENT_SOURCE_IDS,
        f" {WORKER_REPLACEMENT_SOURCE_IDS[0]} ",
        WORKER_REPLACEMENT_SOURCE_IDS[0],
        "browser-profile",
    ]
    drill["pending_reason"] = " already passed "
    drill["statement"] = "Worker replacement reused local state."
    drill_path.write_text(json.dumps(drill), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert remote_check.status == "failed"
    assert "worker_replacement_drill has unexpected fields: private_note" in (
        remote_check.detail
    )
    assert "worker_replacement_drill.status must be passed" in remote_check.detail
    assert "worker_replacement_drill.status must be trimmed" in remote_check.detail
    assert "worker_replacement_drill.worker_destroyed must be true" in remote_check.detail
    assert (
        "worker_replacement_drill.replacement_runner_profile_ready must be true"
        in remote_check.detail
    )
    assert (
        "worker_replacement_drill.host_machine_state_required must be false"
        in remote_check.detail
    )
    assert "worker_replacement_drill.volatile_state_reused must be false" in (
        remote_check.detail
    )
    assert "worker_replacement_drill.restored_from[9] must be trimmed" in (
        remote_check.detail
    )
    assert (
        "worker_replacement_drill.restored_from must match durable replacement source ids"
        in remote_check.detail
    )
    assert "worker_replacement_drill.restored_from contains duplicate encrypted_vault" in (
        remote_check.detail
    )
    assert "worker_replacement_drill.pending_reason must be trimmed" in remote_check.detail
    assert "worker_replacement_drill.statement is incomplete" in remote_check.detail


def test_live_acceptance_requires_llm_contract_artifact_to_match_run_record(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    artifact_path = remote_fusekit / "llm_contract.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["model"] = "stale-model"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert (
        "llm_contract in Run Record must match llm_contract.json artifact"
        in run_record_check.detail
    )
    assert "central run record" in report.missing


def test_live_acceptance_rejects_unredacted_llm_contract_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    artifact_path = remote_fusekit / "llm_contract.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["next_action"] = "capture api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "llm_contract.next_action contains credential-looking text" in (
        run_record_check.detail
    )
    assert "central run record" in report.missing


def test_live_acceptance_rejects_llm_contract_callback_url_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    artifact_path = remote_fusekit / "llm_contract.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["lanes"][0]["description"] = "Continue at https://provider.example/callback"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["llm_contract"]["lanes"][0]["description"] = (
        "Continue at https://provider.example/callback"
    )
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "llm_contract.lanes[0].description contains callback URL" in (
        run_record_check.detail
    )
    assert "central run record" in report.missing


def test_live_acceptance_requires_run_record_verifiers_to_match_report(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["verifiers"]["checks"][0]["status"] = "skipped"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "verifiers in Run Record must match verification_report.json" in run_record_check.detail
    assert "central run record" in report.missing


def test_live_acceptance_requires_embedded_verification_to_match_report(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["verification"]["checks"][0]["status"] = "skipped"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "verification in Run Record must match verification_report.json" in (
        run_record_check.detail
    )
    assert "central run record" in report.missing


def test_live_acceptance_run_record_rejects_non_file_verification_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    artifact_path = remote_fusekit / "verification_report.json"
    artifact_path.unlink()
    artifact_path.mkdir()

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    remote_check = next(check for check in report.checks if check.id == "remote_artifacts.loaded")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "verification_report.json artifact is not a file" in run_record_check.detail
    assert remote_check.status == "failed"
    assert "non-file survivors verification_report.json" in remote_check.detail
    assert "central run record" in report.missing


def test_live_acceptance_rejects_unshaped_embedded_verification(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["verification"]["checks"].append("not-a-check")
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "verification contains an invalid check" in run_record_check.detail
    assert "central run record" in report.missing


def test_live_acceptance_rejects_verification_report_callback_url_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    report_path = remote_fusekit / "verification_report.json"
    artifact = json.loads(report_path.read_text(encoding="utf-8"))
    artifact["checks"][0]["details"] = {
        "callback": "https://provider.example/callback",
        "pending_safe": False,
    }
    report_path.write_text(json.dumps(artifact), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    verification_check = next(
        check for check in report.checks if check.id == "verification_report.safe"
    )
    assert report.launch_ready is False
    assert verification_check.status == "failed"
    assert (
        "verification_report.checks[0].details.callback contains callback URL"
        in verification_check.detail
    )
    assert "safe verification report" in report.missing


def test_live_acceptance_requires_run_record_detonation_to_match_receipt(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["detonation"]["workspace_receipt"]["reason"] = "stale receipt"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert (
        "detonation.workspace_receipt in Run Record must match workspace_detonation.json"
        in run_record_check.detail
    )
    assert "central run record" in report.missing


def test_live_acceptance_rejects_unredacted_workspace_detonation_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    artifact_path = remote_fusekit / "workspace_detonation.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["reason"] = "cleanup api_key=ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert (
        "workspace_detonation.reason contains credential-looking text"
        in run_record_check.detail
    )
    assert "central run record" in report.missing


def test_live_acceptance_rejects_workspace_detonation_callback_url_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    artifact_path = remote_fusekit / "workspace_detonation.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["reason"] = "cleanup after https://provider.example/callback"
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["detonation"]["workspace_receipt"]["reason"] = (
        "cleanup after https://provider.example/callback"
    )
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "workspace_detonation.reason contains callback URL" in run_record_check.detail
    assert "central run record" in report.missing


def test_live_acceptance_rejects_loose_workspace_detonation_artifact(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    artifact_path = remote_fusekit / "workspace_detonation.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    artifact["private_note"] = "sidecar workspace cleanup note"
    artifact["status"] = " complete "
    artifact["resource_summary"]["private_note"] = "sidecar resource note"
    artifact["resource_summary"]["remote_worker_cleanup"]["private_note"] = (
        "sidecar cleanup note"
    )
    artifact["resource_summary"]["remote_worker_cleanup"]["paths"][0] = (
        f" {artifact['resource_summary']['remote_worker_cleanup']['paths'][0]} "
    )
    artifact_path.write_text(json.dumps(artifact), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "detonation.workspace_receipt"
    )
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "workspace_detonation has unexpected fields: private_note" in receipt_check.detail
    assert "workspace_detonation.status must be trimmed" in receipt_check.detail
    assert (
        "workspace_detonation.resource_summary has unexpected fields: private_note"
        in receipt_check.detail
    )
    assert (
        "workspace_detonation.remote_worker_cleanup has unexpected fields: private_note"
        in receipt_check.detail
    )
    assert (
        "workspace_detonation.remote_worker_cleanup.paths[0] must be trimmed"
        in receipt_check.detail
    )
    assert "OCI workspace detonation receipt" in report.missing


def test_live_acceptance_requires_run_record_evidence_inventory_to_match_files(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["evidence"]["logs"][0]["path"] = "missing-audit.jsonl"
    record["evidence"]["receipts"][0]["kind"] = "log"
    record["evidence"]["counts"]["visual"] = 99
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "evidence.logs[0].path must exist in retrieved artifacts" in run_record_check.detail
    assert "evidence.receipts[0].kind must be receipt" in run_record_check.detail
    assert "evidence.counts.visual must match evidence.visual" in run_record_check.detail
    assert "central run record" in report.missing


def test_live_acceptance_requires_run_record_artifacts_to_match_files(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["artifacts"] = [
        {"name": "phantom_artifact", "path": "phantom.json", "exists": True}
    ]
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "artifacts[0].path must exist in retrieved artifacts" in run_record_check.detail
    assert "central run record" in report.missing


def test_live_acceptance_requires_run_record_wake_events_to_match_gate_events(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["wake_events"]["events"][0]["target"] = "STALE_API_KEY"
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "wake_events in Run Record must match gate_events.jsonl" in run_record_check.detail
    assert "central run record" in report.missing


def test_live_acceptance_rejects_gates_callback_url_artifact(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    gates_path = remote_fusekit / "gates.json"
    gates = json.loads(gates_path.read_text(encoding="utf-8"))
    gates["gates"] = [
        {
            "id": "provider.github.authorization",
            "provider": "github",
            "reason": "GitHub token captured",
            "status": "passed",
            "classification": "provider-authorization",
            "target": "GITHUB_TOKEN",
            "follow_steps": [
                "Click Open provider gate in VM so GitHub opens in the VM browser.",
                "Capture GITHUB_TOKEN from VM clipboard.",
            ],
            "next_action": "No action needed.",
            "resume_hint": "FuseKit verified this gate as passed.",
            "captured_targets": ["GITHUB_TOKEN"],
            "resume_url": "https://provider.example/callback",
            **_gate_guidance_fields("github"),
        }
    ]
    gates_path.write_text(json.dumps(gates), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    gates_check = next(check for check in report.checks if check.id == "gates.resolved")
    assert report.launch_ready is False
    assert gates_check.status == "failed"
    assert "gates.gates[0].resume_url contains callback URL" in gates_check.detail
    assert "safe gate state" in report.missing


def test_live_acceptance_rejects_loose_gates_artifact_shape(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    gates_path = remote_fusekit / "gates.json"
    gates = json.loads(gates_path.read_text(encoding="utf-8"))
    gates["sidecar"] = "loose provider gate proof"
    gates["gates"] = [
        {
            "id": "provider.resend.authorization",
            "provider": "resend",
            "reason": "Resend token captured",
            "status": "passed",
            "classification": "provider-authorization",
            "target": "RESEND_API_KEY",
            "follow_steps": [
                "Click Open provider gate in VM so Resend opens in the VM browser.",
                "Capture RESEND_API_KEY from VM clipboard.",
            ],
            "next_action": "No action needed.",
            "resume_hint": "FuseKit verified this gate as passed.",
            "captured_targets": ["RESEND_API_KEY"],
            "resume_url": "https://resend.com/api-keys",
            "sidecar": "loose provider gate proof",
            **_gate_guidance_fields("resend"),
        }
    ]
    gates_path.write_text(json.dumps(gates), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    gates_check = next(check for check in report.checks if check.id == "gates.resolved")
    assert report.launch_ready is False
    assert gates_check.status == "failed"
    assert "gates has unexpected fields: sidecar" in gates_check.detail
    assert "gates.gates[0] has unexpected fields: sidecar" in gates_check.detail
    assert "safe gate state" in report.missing


def test_live_acceptance_rejects_gate_events_callback_url_artifact(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    gates_path = remote_fusekit / "gates.json"
    gates = json.loads(gates_path.read_text(encoding="utf-8"))
    gates["gates"] = [
        {
            "id": "provider.resend.authorization",
            "provider": "resend",
            "reason": "Resend token captured",
            "status": "passed",
            "classification": "provider-authorization",
            "target": "RESEND_API_KEY",
            "follow_steps": [
                "Click Open provider gate in VM so Resend opens in the VM browser.",
                "Capture RESEND_API_KEY from VM clipboard.",
            ],
            "next_action": "No action needed.",
            "resume_hint": "FuseKit verified this gate as passed.",
            "captured_targets": ["RESEND_API_KEY"],
            "resume_url": "https://resend.com/api-keys",
            **_gate_guidance_fields("resend"),
        }
    ]
    gates_path.write_text(json.dumps(gates), encoding="utf-8")
    gate_events_path = remote_fusekit / "gate_events.jsonl"
    events = _read_gate_events_fixture(remote_fusekit)
    events[0]["target"] = "https://provider.example/callback"
    gate_events_path.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["wake_events"] = _wake_event_summary_fixture(remote_fusekit)
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "gate_events[1].target contains callback URL" in run_record_check.detail
    assert audit_check.status == "failed"
    assert "gate_events[1].target contains callback URL" in audit_check.detail
    assert "central run record" in report.missing
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_rejects_loose_gate_events_artifact_shape(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    gate_events_path = remote_fusekit / "gate_events.jsonl"
    events = _read_gate_events_fixture(remote_fusekit)
    events[0]["sidecar"] = "loose wake proof"
    gate_events_path.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "gate_events[1] has unexpected fields: sidecar" in run_record_check.detail
    assert "central run record" in report.missing


def test_live_acceptance_requires_run_record_runner_profile_to_match_readiness(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    record_path = remote_fusekit / "run_record.json"
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["runner_profile"]["observed"]["memory_mib"] = 1024
    record_path.write_text(json.dumps(record), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(check for check in report.checks if check.id == "run_record.complete")
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert (
        "runner_profile in Run Record must match runner_readiness.json" in run_record_check.detail
    )
    assert "central run record" in report.missing


def test_run_record_public_runner_profile_matches_raw_readiness(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_runner_readiness(fusekit_dir)
    record = {
        "runner_profile": _runner_profile_from_readiness_fixture(fusekit_dir),
    }
    record["runner_profile"]["profile_contract"]["browser_stack"][
        "shared_provider_profile"
    ] = "shared-provider-browser-profile"
    record["runner_profile"]["provider_browser_profile"] = "shared-provider-browser-profile"
    record["runner_profile"]["playwright_browsers_path"] = "playwright-browser-cache"
    for binary in record["runner_profile"]["installed_binaries"].values():
        if isinstance(binary, dict):
            binary["path"] = Path(str(binary["path"])).name

    failures = _run_record_runner_profile_consistency_failures(
        record,
        fusekit_dir / "runner_readiness.json",
    )

    assert failures == []


def test_acceptance_run_record_rejects_absolute_app_path(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["app_path"] = "/var/lib/fusekit-runner/app"

    failures = _run_record_shape_failures(record)

    assert "app_path must be a public path label" in failures


def test_acceptance_run_record_requires_complete_workspace_detonation_receipt(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["state"]["detonation_safe"] = False
    record["state"]["workspace_detonated"] = False
    record["detonation"] = {
        "preflight_safe": False,
        "workspace_detonated": False,
        "private_note": "sidecar detonation proof",
        "workspace_receipt": {
            "status": "incomplete",
            "deleted": ["subnet"],
            "failures": {"failed.instance": "409 Conflict"},
        },
    }

    failures = _run_record_shape_failures(record)

    assert "state.detonation_safe must be true" in failures
    assert "state.workspace_detonated must be true" in failures
    assert "detonation has unexpected fields: private_note" in failures
    assert "detonation.preflight_safe must be true" in failures
    assert "detonation.workspace_detonated must be true" in failures
    assert "detonation.workspace_receipt.status must be complete" in failures
    assert "detonation.workspace_receipt.deleted must include instance" in failures
    assert "detonation.workspace_receipt.deleted must include boot volume" in failures
    assert "detonation.workspace_receipt.deleted must include ephemeral public IP" in failures
    assert "detonation.workspace_receipt.failures must be empty" in failures
    assert "detonation.workspace_receipt.reason is missing" in failures
    assert "detonation.workspace_receipt.updated_at is missing" in failures
    assert "detonation.workspace_receipt.resource_summary is missing" in failures


def test_acceptance_run_record_requires_preserved_compartment_scope(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["detonation"]["workspace_receipt"]["deleted"].append("compartment")
    record["detonation"]["workspace_receipt"]["resource_summary"][
        "compartment_deleted"
    ] = True
    record["detonation"]["workspace_receipt"]["resource_summary"][
        "compartment_scope"
    ] = "detonated"

    failures = _run_record_shape_failures(record)

    assert "detonation.workspace_receipt.compartment_deleted must be false" in failures
    assert "detonation.workspace_receipt.compartment_scope must be preserved" in failures


def test_acceptance_run_record_requires_durable_survivor_statement(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["detonation"]["workspace_receipt"]["resource_summary"]["statement"] = (
        "FuseKit detonation removed the remote worker process state, OCI VM, "
        "boot volume, and network resources."
    )

    failures = _run_record_shape_failures(record)

    assert "detonation.workspace_receipt.resource_summary.statement is incomplete" in failures


def test_acceptance_run_record_requires_detonation_survivor_set(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    resource_summary = record["detonation"]["workspace_receipt"]["resource_summary"]
    resource_summary["survivors"] = ["encrypted_vault", "run_record", "browser-profile"]

    failures = _run_record_shape_failures(record)

    assert "detonation.workspace_receipt.resource_summary.survivors is incomplete" in failures
    assert (
        "detonation.workspace_receipt.resource_summary.survivors must not include "
        "volatile worker state: browser-profile"
    ) in failures


def test_acceptance_run_record_rejects_duplicate_detonation_receipt_rows(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    receipt = record["detonation"]["workspace_receipt"]
    resource_summary = receipt["resource_summary"]
    cleanup = resource_summary["remote_worker_cleanup"]

    receipt["deleted"].append("instance")
    resource_summary["network_resources"].append("vcn")
    resource_summary["survivors"].append("run_record")
    cleanup["process_patterns"].append(cleanup["process_patterns"][0])
    cleanup["paths"].append(cleanup["paths"][0])

    failures = _run_record_shape_failures(record)

    assert "detonation.workspace_receipt.deleted contains duplicate instance" in failures
    assert (
        "detonation.workspace_receipt.resource_summary.network_resources "
        "contains duplicate vcn" in failures
    )
    assert (
        "detonation.workspace_receipt.resource_summary.survivors "
        "contains duplicate run_record" in failures
    )
    assert (
        "detonation.workspace_receipt.remote_worker_cleanup.process_patterns "
        f"contains duplicate {cleanup['process_patterns'][0]}" in failures
    )
    assert (
        "detonation.workspace_receipt.remote_worker_cleanup.paths "
        f"contains duplicate {cleanup['paths'][0]}" in failures
    )


def test_acceptance_run_record_rejects_loose_workspace_detonation_receipt(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    receipt = record["detonation"]["workspace_receipt"]
    resource_summary = receipt["resource_summary"]
    cleanup = resource_summary["remote_worker_cleanup"]

    receipt["private_note"] = "sidecar workspace cleanup note"
    receipt["status"] = " complete "
    receipt["deleted"][0] = f" {receipt['deleted'][0]} "
    resource_summary["private_note"] = "sidecar resource note"
    resource_summary["compartment_scope"] = " preserved "
    resource_summary["network_resources"][0] = f" {resource_summary['network_resources'][0]} "
    cleanup["private_note"] = "sidecar cleanup note"
    cleanup["status"] = " detonated "
    cleanup["paths"][0] = f" {cleanup['paths'][0]} "

    failures = _run_record_shape_failures(record)

    assert "detonation.workspace_receipt has unexpected fields: private_note" in failures
    assert "detonation.workspace_receipt.status must be trimmed" in failures
    assert "detonation.workspace_receipt.deleted[0] must be trimmed" in failures
    assert (
        "detonation.workspace_receipt.resource_summary has unexpected fields: private_note"
        in failures
    )
    assert (
        "detonation.workspace_receipt.resource_summary.compartment_scope must be trimmed"
        in failures
    )
    assert (
        "detonation.workspace_receipt.resource_summary.network_resources[0] "
        "must be trimmed" in failures
    )
    assert (
        "detonation.workspace_receipt.remote_worker_cleanup has unexpected fields: "
        "private_note" in failures
    )
    assert (
        "detonation.workspace_receipt.remote_worker_cleanup.status must be trimmed"
        in failures
    )
    assert (
        "detonation.workspace_receipt.remote_worker_cleanup.paths[0] must be trimmed"
        in failures
    )


def test_acceptance_run_record_requires_no_trace_detonation_scope(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["durable_state"]["detonation_scope"] = {
        "schema_version": "fusekit.detonation-scope.v1",
        "mode": "worker-only",
        "must_delete": ["worker"],
        "must_preserve": ["encrypted_vault"],
        "resume_until_complete": False,
        "host_machine_state_required": True,
        "no_trace_statement": "cleanup ran",
    }

    failures = _run_record_shape_failures(record)

    assert "durable_state.detonation_scope.mode is unsupported" in failures
    assert "durable_state.detonation_scope.must_delete is incomplete" in failures
    assert "durable_state.detonation_scope.must_preserve is incomplete" in failures
    assert "durable_state.detonation_scope.resume_until_complete must be true" in failures
    assert (
        "durable_state.detonation_scope.host_machine_state_required must be false"
        in failures
    )
    assert "durable_state.detonation_scope.no_trace_statement is incomplete" in failures


def test_acceptance_run_record_requires_oci_workspace_in_detonation_scope(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["durable_state"]["detonation_scope"]["must_delete"] = [
        surface
        for surface in record["durable_state"]["detonation_scope"]["must_delete"]
        if surface not in OCI_WORKSPACE_DETONATION_SURFACES
    ]

    failures = _run_record_shape_failures(record)

    assert "durable_state.detonation_scope.must_delete is incomplete" in failures


def test_acceptance_run_record_requires_runner_profile_for_worker_replacement(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["durable_state"]["runner_profile_ready"] = False
    record["durable_state"]["runner_profile_failures"] = [
        "runner profile browser_stack.browser must be chromium"
    ]
    record["durable_state"]["worker_replacement_contract"] = {
        "worker_is_disposable": True,
        "can_recreate_worker": True,
        "runner_profile_ready": False,
        "required_runner_profile": "ad-hoc-runner",
        "host_machine_state_required": True,
    }
    record["durable_state"]["sources"] = [
        source
        for source in record["durable_state"]["sources"]
        if source.get("id") not in {"runner_readiness", "gate_events"}
    ]

    failures = _run_record_shape_failures(record)

    assert "durable_state.sources missing gate_events, runner_readiness" in failures
    assert "durable_state.runner_profile_ready must be true" in failures
    assert any(
        failure.startswith("durable_state.runner_profile_failures must be empty")
        for failure in failures
    )
    assert "durable_state.worker_replacement_contract.runner_profile_ready must be true" in failures
    assert (
        "durable_state.worker_replacement_contract.required_runner_profile is unsupported"
        in failures
    )
    assert (
        "durable_state.worker_replacement_contract.host_machine_state_required must be false"
        in failures
    )
    assert "durable_state.worker_replacement_contract.state_owner is unsupported" in failures
    assert "durable_state.worker_replacement_contract.resume_sources is incomplete" in failures
    assert (
        "durable_state.worker_replacement_contract.volatile_surfaces must cover "
        "volatile_worker_surfaces" in failures
    )
    assert "durable_state.worker_replacement_contract.statement is incomplete" in failures


def test_acceptance_run_record_requires_canonical_durable_source_paths(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    run_state_source = next(
        source
        for source in record["durable_state"]["sources"]
        if source.get("id") == "run_state"
    )
    run_state_source["path"] = "survivors/run_state.json"

    failures = _run_record_shape_failures(record)

    assert "durable_state.sources[2].path must be run_state.json" in failures


def test_acceptance_run_record_requires_worker_replacement_drill(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["worker_replacement_drill"] = {
        "schema_version": "fusekit.worker-replacement-drill.v1",
        "status": "skipped",
        "worker_destroyed": False,
        "replacement_runner_profile_ready": False,
        "control_room_reopened": False,
        "resume_checkpoint_restored": False,
        "gate_or_verifier_resumed": False,
        "host_machine_state_required": True,
        "volatile_state_reused": True,
        "restored_from": ["encrypted_vault", "browser-profile"],
        "statement": "worker was checked",
    }

    failures = _run_record_shape_failures(record)

    assert "worker_replacement_drill.status must be passed" in failures
    assert "worker_replacement_drill.worker_destroyed must be true" in failures
    assert (
        "worker_replacement_drill.replacement_runner_profile_ready must be true"
        in failures
    )
    assert "worker_replacement_drill.control_room_reopened must be true" in failures
    assert (
        "worker_replacement_drill.resume_checkpoint_restored must be true"
        in failures
    )
    assert "worker_replacement_drill.gate_or_verifier_resumed must be true" in failures
    assert (
        "worker_replacement_drill.host_machine_state_required must be false"
        in failures
    )
    assert "worker_replacement_drill.volatile_state_reused must be false" in failures
    assert (
        "worker_replacement_drill.restored_from must match durable replacement source ids"
        in failures
    )
    assert "worker_replacement_drill.statement is incomplete" in failures


def test_acceptance_run_record_rejects_loose_worker_replacement_drill(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    drill = record["worker_replacement_drill"]
    drill["private_note"] = "sidecar drill note"
    drill["schema_version"] = " fusekit.worker-replacement-drill.v1 "
    drill["status"] = " passed "
    drill["restored_from"][0] = f" {drill['restored_from'][0]} "
    drill["pending_reason"] = " already passed "
    drill["statement"] = f" {drill['statement']} "

    failures = _run_record_shape_failures(record)

    assert "worker_replacement_drill has unexpected fields: private_note" in failures
    assert (
        "worker_replacement_drill.schema_version must not have surrounding whitespace"
        in failures
    )
    assert "worker_replacement_drill.schema_version is unsupported" in failures
    assert (
        "worker_replacement_drill.status must not have surrounding whitespace"
        in failures
    )
    assert "worker_replacement_drill.status must be passed" in failures
    assert (
        "worker_replacement_drill.restored_from[0] must not have surrounding whitespace"
        in failures
    )
    assert (
        "worker_replacement_drill.restored_from must match durable replacement source ids"
        in failures
    )
    assert (
        "worker_replacement_drill.pending_reason must not have surrounding whitespace"
        in failures
    )
    assert (
        "worker_replacement_drill.statement must not have surrounding whitespace"
        in failures
    )


def test_acceptance_run_record_rejects_extra_worker_replacement_sources(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["worker_replacement_drill"]["restored_from"] = [
        *WORKER_REPLACEMENT_SOURCE_IDS,
        "extra_durable_state",
    ]

    failures = _run_record_shape_failures(record)

    assert (
        "worker_replacement_drill.restored_from must match durable replacement source ids"
        in failures
    )


def test_acceptance_run_record_requires_coherent_worker_replacement_contract(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["durable_state"]["worker_replacement_contract"]["resume_sources"] = [
        *WORKER_REPLACEMENT_SOURCE_IDS,
        "external_checkpoint",
    ]
    record["durable_state"]["worker_replacement_contract"]["volatile_surfaces"] = ["worker"]
    record["durable_state"]["detonation_scope"]["must_preserve"] = [
        "encrypted_vault",
        "run_record",
    ]

    failures = _run_record_shape_failures(record)

    assert (
        "durable_state.worker_replacement_contract.resume_sources must reference "
        "durable_state.sources" in failures
    )
    assert (
        "durable_state.worker_replacement_contract.volatile_surfaces must cover "
        "volatile_worker_surfaces" in failures
    )
    assert (
        "durable_state.detonation_scope.must_preserve must match detonation_preserves" in failures
    )


def test_acceptance_run_record_rejects_duplicate_durable_state_proof(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    durable_state = record["durable_state"]
    replacement = durable_state["worker_replacement_contract"]

    durable_state["sources"].append(dict(durable_state["sources"][0]))
    durable_state["volatile_worker_surfaces"].append("worker")
    durable_state["detonation_preserves"].append("run_record")
    durable_state["detonation_scope"]["must_delete"].append("worker")
    durable_state["detonation_scope"]["must_preserve"].append("run_record")
    replacement["resume_sources"].append(WORKER_REPLACEMENT_SOURCE_IDS[0])
    replacement["volatile_surfaces"].append("worker")
    record["worker_replacement_drill"]["restored_from"].append(WORKER_REPLACEMENT_SOURCE_IDS[0])

    failures = _run_record_shape_failures(record)

    duplicate_source = durable_state["sources"][0]["id"]
    assert any(
        failure.endswith(f".id duplicates durable source {duplicate_source}")
        for failure in failures
    )
    assert "durable_state.volatile_worker_surfaces contains duplicate worker" in failures
    assert "durable_state.detonation_preserves contains duplicate run_record" in failures
    assert "durable_state.detonation_scope.must_delete contains duplicate worker" in failures
    assert "durable_state.detonation_scope.must_preserve contains duplicate run_record" in failures
    assert (
        "durable_state.worker_replacement_contract.resume_sources contains duplicate "
        f"{WORKER_REPLACEMENT_SOURCE_IDS[0]}" in failures
    )
    assert (
        "durable_state.worker_replacement_contract.volatile_surfaces contains duplicate worker"
        in failures
    )
    assert (
        "worker_replacement_drill.restored_from contains duplicate "
        f"{WORKER_REPLACEMENT_SOURCE_IDS[0]}" in failures
    )


def test_acceptance_run_record_rejects_volatile_durable_state_survivors(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["durable_state"]["sources"].append(
        {
            "id": "local_browser_profile",
            "path": "browser-profile/Default",
            "role": "local browser profile",
            "secret_class": "non-secret",
            "exists": True,
        }
    )
    record["durable_state"]["detonation_preserves"].append("browser-profile")
    record["durable_state"]["detonation_scope"]["must_preserve"].append("browser-profile")
    record["durable_state"]["worker_replacement_contract"]["resume_sources"].append(
        "local_browser_profile"
    )
    record["durable_state"]["worker_replacement_contract"]["resume_sources"].append("passphrase")

    failures = _run_record_shape_failures(record)

    assert any(
        failure.endswith("preserves volatile worker state: browser-profile")
        for failure in failures
    )
    assert "durable_state.detonation_preserves is incomplete" in failures
    assert (
        "durable_state.detonation_scope.must_preserve must not include volatile "
        "worker state: browser-profile" in failures
    )
    assert (
        "durable_state.worker_replacement_contract.resume_sources must not include "
        "volatile worker state: local_browser_profile, passphrase" in failures
    )


def test_acceptance_run_record_requires_non_secret_evidence_inventory(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["evidence"] = {
        "schema_version": "fusekit.evidence-inventory.v1",
        "logs": [
            {
                "path": "control-room.log?token=secret",
                "kind": "log",
                "source": "known-proof",
                "exists": True,
            }
        ],
        "screenshots": "missing",
        "visual": [{"path": "", "kind": "visual", "exists": False}],
        "receipts": [{"path": "setup_receipt.json", "kind": "artifact", "exists": True}],
        "counts": {"logs": 1},
        "statement": "evidence files",
    }

    failures = _run_record_shape_failures(record)

    assert "evidence.logs[0].path contains credential query text" in failures
    assert "evidence.screenshots is missing" in failures
    assert "evidence.visual[0].path is missing" in failures
    assert "evidence.visual[0].exists must be true" in failures
    assert "evidence.receipts[0].kind must be receipt" in failures
    assert "evidence.counts.screenshots is missing" in failures
    assert "evidence.statement is missing non-secret inventory guidance" in failures


def test_acceptance_run_record_rejects_duplicate_evidence_rows(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    duplicate = dict(record["evidence"]["logs"][0])
    record["evidence"]["logs"].append(duplicate)
    record["evidence"]["counts"]["logs"] = 2
    record["evidence"]["counts"]["receipts"] = 99

    failures = _run_record_shape_failures(record)

    assert "evidence.logs[1].path duplicates evidence path audit.jsonl" in failures
    assert "evidence.counts.receipts must match evidence.receipts" in failures


def test_acceptance_run_record_requires_public_artifact_records(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["artifacts"] = [
        "bad",
        {"name": "", "path": "", "exists": "yes"},
        {
            "name": "debug token=leaked-value",
            "path": "/var/lib/fusekit-runner/app/.fusekit/debug.log?token=leaked-value",
            "exists": True,
        },
        {"name": "outside", "path": "../worker.log", "exists": True},
        {"name": "audit_log", "path": "audit.jsonl", "exists": True},
        {"name": "audit_log", "path": "gate_events.jsonl", "exists": True},
        {"name": "gate_events", "path": "audit.jsonl", "exists": True},
    ]

    failures = _run_record_shape_failures(record)

    assert "artifacts[0] is not an object" in failures
    assert "artifacts[1].name is missing" in failures
    assert "artifacts[1].path is missing" in failures
    assert "artifacts[1].exists must be boolean" in failures
    assert "artifacts[2].name contains credential-looking text" in failures
    assert "artifacts[2].path must be a public path label" in failures
    assert "artifacts[2].path contains credential query text" in failures
    assert "artifacts[2].path contains credential-looking text" in failures
    assert "artifacts[3].path must stay inside the artifact bundle" in failures
    assert "artifacts[5].name duplicates artifact audit_log" in failures
    assert "artifacts[6].path duplicates artifact path audit.jsonl" in failures


def test_acceptance_run_record_rejects_loose_artifact_and_evidence_rows(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    artifact = record["artifacts"][0]
    artifact["private_note"] = "sidecar artifact note"
    artifact["name"] = " run_record "
    artifact["path"] = " run_record.json "
    artifact["exists"] = 1

    evidence = record["evidence"]
    evidence["private_note"] = "sidecar evidence note"
    evidence["schema_version"] = " fusekit.evidence-inventory.v1 "
    evidence["statement"] = f" {evidence['statement']} "
    evidence["counts"]["private_note"] = 1
    evidence["counts"]["logs"] = True
    log = evidence["logs"][0]
    log["private_note"] = "sidecar log note"
    log["path"] = " audit.jsonl "
    log["kind"] = " log "
    log["source"] = " known-proof "

    failures = _run_record_shape_failures(record)

    assert "artifacts[0] has unexpected fields: private_note" in failures
    assert "artifacts[0].name must not have surrounding whitespace" in failures
    assert "artifacts[0].path must not have surrounding whitespace" in failures
    assert "artifacts[0].exists must be boolean" in failures
    assert "evidence has unexpected fields: private_note" in failures
    assert "evidence.schema_version must not have surrounding whitespace" in failures
    assert "evidence.schema_version is unsupported" in failures
    assert "evidence.statement must not have surrounding whitespace" in failures
    assert "evidence.counts has unexpected fields: private_note" in failures
    assert "evidence.counts.logs is missing" in failures
    assert "evidence.logs[0] has unexpected fields: private_note" in failures
    assert "evidence.logs[0].path must not have surrounding whitespace" in failures
    assert "evidence.logs[0].kind must not have surrounding whitespace" in failures
    assert "evidence.logs[0].source must not have surrounding whitespace" in failures


def test_acceptance_run_record_rejects_boolean_numeric_proof_counts(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_gates"]["total"] = True
    record["wake_events"]["total"] = True
    record["wake_events"]["event_counts"]["clipboard_captured"] = True
    record["evidence"]["counts"]["logs"] = True
    record["human_actions"]["total"] = False
    record["rehearsal_review"]["side_channel_count"] = False
    record["automation_boundary"]["counts"]["blocked"] = False
    record["verifiers"]["counts"]["pending"] = False
    record["audit_trail"]["entry_count"] = True
    record["audit_trail"]["counts"]["credential_capture"] = True

    failures = _run_record_shape_failures(record)

    assert "provider_gates.total is missing" in failures
    assert "wake_events.total is missing" in failures
    assert "wake_events.total must match wake_events.events" in failures
    assert "wake_events.event_counts.clipboard_captured must match events" in failures
    assert "evidence.counts.logs is missing" in failures
    assert "human_actions.total must match human_actions.actions" in failures
    assert "rehearsal_review.side_channel_count must be zero" in failures
    assert "automation_boundary.counts.blocked must be 0" in failures
    assert "verifiers.counts.pending is missing" in failures
    assert "verifiers.counts.pending must be 0" in failures
    assert "audit_trail.entry_count must match entries" in failures
    assert "audit_trail.counts.credential_capture must match entries" in failures


def test_acceptance_run_record_rejects_float_numeric_proof_counts(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_gates"]["total"] = 0.1
    record["wake_events"]["total"] = 2.1
    record["wake_events"]["event_counts"]["clipboard_captured"] = 1.1
    record["model_inference"]["lane_count"] = 2.1
    record["human_actions"]["total"] = 3.1
    record["rehearsal_review"]["side_channel_count"] = 0.1
    record["automation_boundary"]["counts"]["blocked"] = 0.1
    record["automation_boundary"]["counts"]["fusekit_owned"] = 3.1
    record["verifiers"]["counts"]["pending"] = 0.1
    record["audit_trail"]["entry_count"] = 5.1
    record["audit_trail"]["counts"]["credential_capture"] = 1.1

    failures = _run_record_shape_failures(record)

    assert "provider_gates.total is missing" in failures
    assert "wake_events.total is missing" in failures
    assert "wake_events.total must match wake_events.events" in failures
    assert "wake_events.event_counts.clipboard_captured must match events" in failures
    assert "model_inference.lane_count must match llm_contract.lanes" in failures
    assert "human_actions.total must match human_actions.actions" in failures
    assert "rehearsal_review.side_channel_count must be zero" in failures
    assert "automation_boundary.counts.blocked must be 0" in failures
    assert "automation_boundary.counts.fusekit_owned must match routes" in failures
    assert "verifiers.counts.pending is missing" in failures
    assert "verifiers.counts.pending must be 0" in failures
    assert "audit_trail.entry_count must match entries" in failures
    assert "audit_trail.counts.credential_capture must match entries" in failures


def test_acceptance_run_record_rejects_duplicate_wake_event_proof(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    duplicate_event = dict(record["wake_events"]["events"][0])
    record["wake_events"]["events"].append(duplicate_event)
    record["wake_events"]["total"] = 3
    record["wake_events"]["event_counts"] = {
        "clipboard_captured": 2,
        "resume_requested": 1,
    }

    failures = _run_record_shape_failures(record)

    assert "wake_events.events[2].id duplicates wake event wake-resend-capture" in failures
    assert "wake_events.events[2] duplicates wake event proof" in failures


def test_acceptance_run_record_rejects_loose_wake_event_proof(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["wake_events"]["sidecar"] = "loose wake proof"
    record["wake_events"]["events"][0]["sidecar"] = "ignored by signature"
    record["wake_events"]["events"][0]["event"] = " clipboard_captured "

    failures = _run_record_shape_failures(record)

    assert "wake_events has unexpected fields: sidecar" in failures
    assert "wake_events.events[0] has unexpected fields: sidecar" in failures
    assert "wake_events.events[0].event must be trimmed" in failures


def test_acceptance_run_record_rejects_duplicate_provider_gate_records(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    gate = {
        "id": "provider.resend.authorization",
        "provider": "resend",
        "status": "waiting",
    }
    record["provider_gates"] = {
        "total": 2,
        "statuses": {"waiting": 1},
        "providers": [],
        "records": [dict(gate), dict(gate)],
    }

    failures = _run_record_shape_failures(record)

    assert (
        "provider_gates.records[1].id duplicates provider gate "
        "provider.resend.authorization"
    ) in failures
    assert "provider_gates.statuses.waiting must match records" in failures
    assert "provider_gates.providers must match records" in failures


def test_acceptance_run_record_rejects_loose_provider_gate_shape(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_gates"] = {
        "total": 1,
        "statuses": {" captured ": 1},
        "providers": [" github "],
        "private_note": "sidecar provider gate summary",
        "records": [
            {
                "id": " provider.github.authorization",
                "provider": "github",
                "status": "captured",
                "target": " GITHUB_TOKEN ",
                "captured_targets": [" GITHUB_TOKEN "],
                "follow_steps": ["Open provider gate in VM "],
                "private_note": "sidecar provider gate",
                "attempts": True,
                "updated_at": -1,
            }
        ],
    }

    failures = _run_record_shape_failures(record)

    assert "provider_gates has unexpected fields: private_note" in failures
    assert (
        "provider_gates.records[0] has unexpected fields: private_note"
        in failures
    )
    assert "provider_gates.records[0].id must be trimmed" in failures
    assert "provider_gates.records[0].target must be trimmed" in failures
    assert "provider_gates.records[0].captured_targets[0] must be trimmed" in failures
    assert "provider_gates.records[0].follow_steps[0] must be trimmed" in failures
    assert (
        "provider_gates.records[0].attempts must be a non-negative literal integer"
        in failures
    )
    assert "provider_gates.records[0].updated_at must be a non-negative number" in failures
    assert "provider_gates.statuses. captured  must match records" in failures
    assert "provider_gates.providers must match records" in failures


def test_acceptance_run_record_requires_vault_count_to_match_records(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["vault"] = {
        "record_count": 2,
        "records": [
            {
                "id": "provider.resend.token",
                "kind": "provider_token",
                "provider": "resend",
                "label": "Resend API key",
            }
        ],
    }

    failures = _run_record_shape_failures(record)

    assert "vault.record_count must match vault.records" in failures


def test_acceptance_run_record_rejects_loose_vault_summary_shape(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["vault"] = {
        "record_count": "1",
        "note": "sidecar vault proof",
        "records": [
            {
                "id": " provider.resend.token",
                "kind": "provider_token",
                "provider": "resend",
                "label": "Resend API key ",
                "note": "sidecar vault proof",
            },
            {
                "id": "provider.resend.webhook",
                "kind": "provider_token",
                "provider": "resend",
                "label": "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
            },
        ],
    }

    failures = _run_record_shape_failures(record)

    assert "vault.record_count must be a literal integer" in failures
    assert "vault has unexpected fields: note" in failures
    assert "vault.records[0] has unexpected fields: note" in failures
    assert "vault.records[0].id must be trimmed" in failures
    assert "vault.records[0].label must be trimmed" in failures
    assert "vault.records[1].label contains credential-looking text" in failures


def test_acceptance_run_record_rejects_duplicate_vault_records(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    vault_record = {
        "id": "provider.resend.token",
        "kind": "provider_token",
        "provider": "resend",
        "label": "Resend API key",
    }
    record["vault"] = {
        "record_count": 2,
        "records": [dict(vault_record), dict(vault_record)],
    }

    failures = _run_record_shape_failures(record)

    assert "vault.records[1].id duplicates vault record provider.resend.token" in failures


def test_acceptance_run_record_requires_shaped_vault_metadata(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["vault"] = {
        "record_count": 1,
        "records": [
            {
                "id": "",
                "kind": "",
                "provider": "",
                "label": "",
                "value": "secret-should-not-survive",
            }
        ],
    }

    failures = _run_record_shape_failures(record)

    assert "vault.records[0] has unexpected fields: value" in failures
    assert "vault.records[0].id is missing" in failures
    assert "vault.records[0].kind is missing" in failures
    assert "vault.records[0].provider is missing" in failures
    assert "vault.records[0].label is missing" in failures
    assert "vault.records[0] exposes a raw value" in failures


def test_acceptance_run_record_rejects_vault_secret_metadata_fields(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["vault"] = {
        "record_count": 1,
        "records": [
            {
                "id": "provider.resend.token",
                "kind": "provider_token",
                "provider": "resend",
                "label": "Resend API key",
                "private_key": "not-secret-looking",
                "metadata": {
                    "password": "plain-word",
                    "nested": [{"raw_value": "short"}],
                },
            }
        ],
    }

    failures = _run_record_shape_failures(record)

    assert (
        "vault.records[0] has unexpected fields: metadata, private_key"
        in failures
    )
    assert "vault.records[0].private_key exposes raw secret metadata" in failures
    assert "vault.records[0].metadata.password exposes raw secret metadata" in failures
    assert (
        "vault.records[0].metadata.nested[0].raw_value exposes raw secret metadata"
        in failures
    )


def test_acceptance_run_record_requires_guided_human_action_trace(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["human_actions"] = {
        "schema_version": "fusekit.human-action-trace.v1",
        "total": 2,
        "counts": {"capture_vm_clipboard": 1},
        "actions": [
            {
                "gate_id": " provider.resend.authorization ",
                "provider": "resend",
                "classification": "authorization",
                "action": "capture_vm_clipboard",
                "visible_control": "Capture GITHUB_TOKEN from VM clipboard",
                "target": "RESEND_API_KEY",
                "guided": True,
                "created_at": 1.0,
                "private_note": "sidecar human-action note",
            },
            {
                "gate_id": "",
                "provider": "resend",
                "classification": "authorization",
                "action": "open_provider_gate",
                "visible_control": "",
                "guided": False,
                "created_at": 2.0,
            },
        ],
        "unguided": [
            {
                "gate_id": "",
                "action": "open_provider_gate",
                "reason": "action did not match a durable gate",
            }
        ],
        "statement": "human clicked around",
    }

    failures = _run_record_shape_failures(record)

    assert "human_actions.total must match human_actions.actions" not in failures
    assert "human_actions.actions[0].gate_id must not have surrounding whitespace" in failures
    assert "human_actions.actions[0] has unexpected fields: private_note" in failures
    assert "human_actions.actions[0].visible_control must match the captured target" in failures
    assert "human_actions.actions[1].gate_id is missing" in failures
    assert "human_actions.actions[1].visible_control is missing" in failures
    assert "human_actions.actions[1].guided must be true" in failures
    assert "human_actions.counts.open_provider_gate must match actions" in failures
    assert "human_actions.unguided must be empty" in failures
    assert "human_actions.statement is missing guided-action guidance" in failures


def test_acceptance_run_record_requires_exact_human_action_controls(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["human_actions"] = {
        "schema_version": "fusekit.human-action-trace.v1",
        "total": 3,
        "counts": {
            "open_provider_gate": 1,
            "capture_vm_clipboard": 1,
            "confirm_gate_finished": 1,
        },
        "actions": [
            {
                "gate_id": "provider.resend.authorization",
                "provider": "resend",
                "classification": "authorization",
                "action": "open_provider_gate",
                "visible_control": "Open provider page",
                "guided": True,
                "created_at": 1.0,
            },
            {
                "gate_id": "provider.resend.authorization",
                "provider": "resend",
                "classification": "authorization",
                "action": "capture_vm_clipboard",
                "visible_control": "Capture key",
                "target": "RESEND_API_KEY",
                "guided": True,
                "created_at": 2.0,
            },
            {
                "gate_id": "provider.cloudflare.callback",
                "provider": "cloudflare",
                "classification": "provider-authorization",
                "action": "confirm_gate_finished",
                "visible_control": "Continue",
                "guided": True,
                "created_at": 3.0,
            },
        ],
        "unguided": [],
        "statement": (
            "Every action maps to a visible control-room gate with no raw provider secret details."
        ),
    }

    failures = _run_record_shape_failures(record)

    assert "human_actions.actions[0].visible_control must be Open provider gate in VM" in failures
    assert "human_actions.actions[1].visible_control must match the captured target" in failures
    assert (
        "human_actions.actions[2].visible_control must be a known finish/approval control"
        in failures
    )
    assert "human_actions.counts.open_provider_gate must match actions" not in failures


def test_acceptance_run_record_rejects_duplicate_human_action_proof(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    action = {
        "gate_id": "provider.resend.authorization",
        "provider": "resend",
        "classification": "authorization",
        "action": "capture_vm_clipboard",
        "visible_control": "Capture RESEND_API_KEY from VM clipboard",
        "target": "RESEND_API_KEY",
        "guided": True,
        "created_at": 1.0,
    }
    record["human_actions"] = {
        "schema_version": "fusekit.human-action-trace.v1",
        "total": 2,
        "counts": {
            "open_provider_gate": 0,
            "capture_vm_clipboard": 2,
            "confirm_gate_finished": 0,
        },
        "actions": [dict(action), dict(action)],
        "unguided": [],
        "statement": (
            "Every recorded human action should map to one visible control-room gate "
            "and its current follow-me instructions; the trace contains no raw provider "
            "URLs, clipboard values, passwords, tokens, or screenshots."
        ),
    }

    failures = _run_record_shape_failures(record)

    assert "human_actions.actions[1] duplicates human action proof" in failures


def test_acceptance_run_record_requires_human_actions_to_match_provider_gates(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["provider_gates"] = {
        "total": 1,
        "statuses": {"waiting": 1},
        "providers": ["resend"],
        "records": [
            {
                "id": "provider.resend.authorization",
                "provider": "resend",
                "status": "waiting",
                "target": "RESEND_API_KEY",
            }
        ],
    }
    record["human_actions"] = {
        "schema_version": "fusekit.human-action-trace.v1",
        "total": 2,
        "counts": {
            "open_provider_gate": 1,
            "capture_vm_clipboard": 1,
        },
        "actions": [
            {
                "gate_id": "provider.github.authorization",
                "provider": "github",
                "classification": "authorization",
                "action": "open_provider_gate",
                "visible_control": "Open provider gate in VM",
                "guided": True,
                "created_at": 1.0,
            },
            {
                "gate_id": "provider.resend.authorization",
                "provider": "resend",
                "classification": "authorization",
                "action": "capture_vm_clipboard",
                "visible_control": "Capture GITHUB_TOKEN from VM clipboard",
                "target": "GITHUB_TOKEN",
                "guided": True,
                "created_at": 2.0,
            },
        ],
        "unguided": [],
        "statement": (
            "Every action maps to a visible control-room gate with no raw provider secret details."
        ),
    }

    failures = _run_record_shape_failures(record)

    assert "human_actions.actions[0].gate_id must match provider_gates.records" in failures
    assert "human_actions.actions[1].target must match provider_gates.records target" in failures


def test_acceptance_run_record_requires_rehearsal_review_to_match_human_actions(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["human_actions"] = {
        "schema_version": "fusekit.human-action-trace.v1",
        "total": 1,
        "counts": {"capture_vm_clipboard": 1},
        "actions": [
            {
                "gate_id": "provider.resend.authorization",
                "provider": "resend",
                "classification": "authorization",
                "action": "capture_vm_clipboard",
                "visible_control": "Capture RESEND_API_KEY from VM clipboard",
                "target": "RESEND_API_KEY",
                "guided": True,
                "created_at": 1.0,
            }
        ],
        "unguided": [],
        "statement": (
            "Every recorded human action should map to one visible control-room gate "
            "and its current follow-me instructions; the trace contains no raw provider "
            "URLs, clipboard values, passwords, tokens, or screenshots."
        ),
    }
    record["rehearsal_review"] = {
        "schema_version": "fusekit.rehearsal-review.v1",
        "status": "needs_review",
        "action_count": 0,
        "compared_action_count": 0,
        "matched_control_count": 0,
        "unguided_count": 0,
        "side_channel_count": 1,
        "requires_user_thinking": True,
        "reviewed_actions": [
            {
                "gate_id": "provider.other.authorization",
                "action": "capture_vm_clipboard",
                "visible_control": " Capture OTHER_TOKEN from VM clipboard ",
                "target": "OTHER_TOKEN",
                "matched": False,
                "proof_source": "gates.json",
                "private_note": "sidecar review note",
            }
        ],
        "statement": "human figured it out",
    }

    failures = _run_record_shape_failures(record)

    assert "rehearsal_review.status must be ready" in failures
    assert "rehearsal_review.action_count must match human_actions.actions" in failures
    assert (
        "rehearsal_review.compared_action_count must match human_actions.actions"
        in failures
    )
    assert (
        "rehearsal_review.matched_control_count must match human_actions.actions"
        in failures
    )
    assert "rehearsal_review.side_channel_count must be zero" in failures
    assert "rehearsal_review.requires_user_thinking must be false" in failures
    assert (
        "rehearsal_review.reviewed_actions[0].gate_id must match human_actions.actions"
        in failures
    )
    assert (
        "rehearsal_review.reviewed_actions[0].visible_control must match human_actions.actions"
        in failures
    )
    assert (
        "rehearsal_review.reviewed_actions[0].visible_control must not have "
        "surrounding whitespace"
        in failures
    )
    assert (
        "rehearsal_review.reviewed_actions[0].target must match human_actions.actions"
        in failures
    )
    assert (
        "rehearsal_review.reviewed_actions[0] has unexpected fields: private_note"
        in failures
    )
    assert "rehearsal_review.reviewed_actions[0].matched must be true" in failures
    assert (
        "rehearsal_review.reviewed_actions[0].proof_source must be "
        "gates.json + gate_events.jsonl"
    ) in failures
    assert "rehearsal_review.statement is missing rehearsal guidance" in failures


def test_acceptance_run_record_requires_human_actions_when_gates_exist(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_gates"] = {
        "total": 1,
        "statuses": {"captured": 1},
        "providers": ["resend"],
        "records": [
            {
                "id": "provider.resend.authorization",
                "provider": "resend",
                "status": "captured",
                "target": "RESEND_API_KEY",
                "captured_targets": ["RESEND_API_KEY"],
            }
        ],
    }
    record["human_actions"] = {
        "schema_version": "fusekit.human-action-trace.v1",
        "total": 0,
        "counts": {},
        "actions": [],
        "unguided": [],
        "statement": (
            "Every recorded human action maps to one visible control-room gate "
            "with no raw provider secret details."
        ),
    }
    record["rehearsal_review"] = {
        "schema_version": "fusekit.rehearsal-review.v1",
        "status": "ready",
        "action_count": 0,
        "compared_action_count": 0,
        "matched_control_count": 0,
        "unguided_count": 0,
        "side_channel_count": 0,
        "requires_user_thinking": False,
        "reviewed_actions": [],
        "statement": (
            "Every recorded human action is compared against the visible "
            "control-room instructions before public recording readiness."
        ),
    }

    failures = _run_record_shape_failures(record)

    assert (
        "human_actions.actions are required when provider gates or wake events exist"
        in failures
    )
    assert (
        "rehearsal_review.reviewed_actions must include guided human actions "
        "when provider gates or wake events exist"
        in failures
    )


def test_acceptance_run_record_requires_automation_boundary(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["automation_boundary"] = {
        "schema_version": "fusekit.automation-boundary.v1",
        "status": "needs_route_repair",
        "resume_after_worker_replace": False,
        "detonation_scope": "host-and-worker",
        "no_user_machine_state": False,
        "vnc_allowed_for": ["login"],
        "routes": [
            {
                "provider": "resend",
                "recipe": "resend-domain",
                "route": "api",
                "owner": "human_gate",
                "deterministic": False,
                "implemented": False,
                "status": "ok",
            },
            {
                "provider": "cloudflare",
                "recipe": "cloudflare-dns",
                "route": "api",
                "owner": "blocked",
                "deterministic": False,
                "implemented": False,
                "status": "blocked",
            },
        ],
        "counts": {"fusekit_owned": 1, "human_gate": 1, "blocked": 1},
        "post_gate_automation": {"api_or_cli_routes": "resend:resend-domain"},
        "statement": "Humans do work manually.",
    }

    failures = _run_record_shape_failures(record)

    assert "automation_boundary.status must be ready" in failures
    assert "automation_boundary.resume_after_worker_replace must be true" in failures
    assert "automation_boundary.no_user_machine_state must be true" in failures
    assert "automation_boundary.vnc_allowed_for is incomplete" in failures
    assert "automation_boundary.routes[0].route must be a human gate route" in failures
    assert "automation_boundary.routes[1].owner is unsupported" in failures
    assert "automation_boundary.counts.blocked must be 0" in failures
    assert "automation_boundary.counts.fusekit_owned must match routes" in failures
    assert "automation_boundary.post_gate_automation.api_or_cli_routes is missing" in failures
    assert (
        "automation_boundary.post_gate_automation.human_gate_routes is missing" in failures
    )
    assert "automation_boundary.statement is missing vnc guidance" in failures


def test_acceptance_run_record_requires_post_gate_routes_to_match_boundary(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["automation_boundary"] = _automation_boundary()
    record["automation_boundary"]["post_gate_automation"] = {
        "api_or_cli_routes": ["resend:wrong-domain"],
        "human_gate_routes": ["resend:resend-api-key", "github:extra-login"],
    }

    failures = _run_record_shape_failures(record)

    assert (
        "automation_boundary.post_gate_automation.api_or_cli_routes must match "
        "fusekit-owned routes"
    ) in failures
    assert (
        "automation_boundary.post_gate_automation.human_gate_routes must match "
        "human-gate routes"
    ) in failures


def test_acceptance_run_record_rejects_duplicate_automation_boundary_routes(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["automation_boundary"] = _automation_boundary()
    boundary = record["automation_boundary"]

    boundary["vnc_allowed_for"].append("login")
    boundary["routes"].append(dict(boundary["routes"][0]))
    boundary["counts"]["fusekit_owned"] = 2
    boundary["post_gate_automation"]["api_or_cli_routes"].append("resend:resend-domain")
    boundary["post_gate_automation"]["human_gate_routes"].append("resend:resend-api-key")

    failures = _run_record_shape_failures(record)

    assert "automation_boundary.vnc_allowed_for contains duplicate login" in failures
    assert (
        "automation_boundary.routes[2] duplicates automation route resend:resend-domain"
        in failures
    )
    assert (
        "automation_boundary.post_gate_automation.api_or_cli_routes "
        "contains duplicate resend:resend-domain" in failures
    )
    assert (
        "automation_boundary.post_gate_automation.human_gate_routes "
        "contains duplicate resend:resend-api-key" in failures
    )


def test_acceptance_run_record_rejects_loose_automation_boundary_rows(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["automation_boundary"] = _automation_boundary()
    boundary = record["automation_boundary"]

    boundary["private_note"] = "sidecar boundary note"
    boundary["status"] = " ready "
    boundary["statement"] = f" {boundary['statement']} "
    boundary["vnc_allowed_for"][0] = " login "
    boundary["routes"][0]["private_note"] = "sidecar route note"
    boundary["routes"][0]["provider"] = " resend "
    boundary["routes"][0]["route"] = " api "
    boundary["routes"][0]["owner"] = " fusekit "
    boundary["counts"]["private_note"] = 1
    boundary["counts"]["blocked"] = False
    boundary["post_gate_automation"]["private_note"] = "sidecar post-gate note"
    boundary["post_gate_automation"]["api_or_cli_routes"][0] = " resend:resend-domain "
    boundary["post_gate_automation"]["human_gate_routes"][0] = (
        " resend:resend-api-key "
    )

    failures = _run_record_shape_failures(record)

    assert "automation_boundary has unexpected fields: private_note" in failures
    assert "automation_boundary.status must not have surrounding whitespace" in failures
    assert "automation_boundary.status must be ready" in failures
    assert "automation_boundary.statement must not have surrounding whitespace" in failures
    assert (
        "automation_boundary.vnc_allowed_for[0] must not have surrounding whitespace"
        in failures
    )
    assert "automation_boundary.routes[0] has unexpected fields: private_note" in failures
    assert (
        "automation_boundary.routes[0].provider must not have surrounding whitespace"
        in failures
    )
    assert (
        "automation_boundary.routes[0].route must not have surrounding whitespace"
        in failures
    )
    assert (
        "automation_boundary.routes[0].owner must not have surrounding whitespace"
        in failures
    )
    assert "automation_boundary.counts has unexpected fields: private_note" in failures
    assert "automation_boundary.counts.blocked must be an integer" in failures
    assert "automation_boundary.counts.blocked must be 0" in failures
    assert (
        "automation_boundary.post_gate_automation has unexpected fields: private_note"
        in failures
    )
    assert (
        "automation_boundary.post_gate_automation.api_or_cli_routes[0] "
        "must not have surrounding whitespace"
        in failures
    )
    assert (
        "automation_boundary.post_gate_automation.human_gate_routes[0] "
        "must not have surrounding whitespace"
        in failures
    )


def test_acceptance_run_record_requires_provider_strategy_summary(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_strategies"] = {
        "schema_version": "fusekit.provider-strategies.v1",
        "providers": [
            {
                "provider": "resend",
                "strategies": [
                    {
                        "recipe": "resend-domain",
                        "strategy": "api",
                        "status": "ok",
                        "decision": {"selected": {"kind": "api"}},
                    }
                ],
            }
        ],
    }

    failures = _run_record_shape_failures(record)

    assert "provider_strategies.providers is missing" not in failures
    assert (
        "provider_strategies.providers[0].strategies[0].decision.selected.status is missing"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].decision.selected.deterministic "
        "must be boolean"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].decision.selected.implemented "
        "must be boolean"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].decision.selected.reason is missing"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].decision.candidates is missing" in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].selected.evidence.api_owns "
        "must be domain"
        in failures
    )
    assert (
        "provider_strategies.providers[0].strategies[0].selected.evidence.downstream_order "
        "must be before_dns_apply"
        in failures
    )

    record["provider_strategies"] = {"providers": []}

    failures = _run_record_shape_failures(record)

    assert "provider_strategies.schema_version is unsupported" in failures
    assert "provider_strategies.providers is missing" in failures


def test_acceptance_provider_strategy_requires_capture_resume_guidance() -> None:
    failures = _provider_strategy_shape_failures(
        [
            {
                "provider": "github",
                "strategies": [
                    {
                        "recipe": "github-repo-secrets",
                        "strategy": "browser_guided",
                        "status": "needs_human_gate",
                        "target": "GITHUB_TOKEN",
                        "follow_steps": [
                            "Click Open provider gate in VM.",
                            (
                                "Copy the token inside the VM browser, then click "
                                "Capture GITHUB_TOKEN from VM clipboard."
                            ),
                        ],
                        "next_action": (
                            "Click Open provider gate in VM, then click "
                            "Capture GITHUB_TOKEN from VM clipboard."
                        ),
                        "resume_hint": "The value is now safely stored.",
                        "success_criteria": ["GITHUB_TOKEN is copied once."],
                        "avoid_steps": ["Do not use the local browser."],
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "Provider token is missing.",
                            },
                            "candidates": [
                                {
                                    "kind": "browser_guided",
                                    "status": "available",
                                }
                            ],
                        },
                    }
                ],
            }
        ]
    )

    assert (
        "github.strategies[0].guidance does not explain FuseKit resumes after "
        "clipboard capture"
    ) in failures


def test_acceptance_run_record_requires_strategy_routes_to_cover_playbook_providers(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_strategies"] = {
        "schema_version": "fusekit.provider-strategies.v1",
        "providers": [
            {
                "provider": "resend",
                "strategies": [
                    {
                        "recipe": "resend-domain",
                        "strategy": "api",
                        "status": "ok",
                        "decision": _resend_domain_strategy_decision(),
                    }
                ],
            },
            {
                "provider": "cloudflare",
                "strategies": [
                    {
                        "recipe": "cloudflare-dns",
                        "strategy": "api",
                        "status": "ok",
                        "decision": _strategy_decision(),
                    }
                ],
            },
        ],
    }

    failures = _run_record_shape_failures(record)

    assert (
        "provider_strategies.providers missing public demo provider coverage: GitHub, Vercel"
        in failures
    )


def test_acceptance_run_record_requires_live_verifier_summary(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["verifiers"] = {
        "schema_version": "fusekit.verifier-summary.v1",
        "overall": "blocked",
        "all_passed_or_pending_safe": False,
        "counts": {
            "passed": 0,
            "pending_safe": 0,
            "pending": 1,
            "repairing": 0,
            "failed": 1,
            "skipped": 0,
            "needs_human_gate": 1,
            "unknown": 1,
        },
        "checks": [
            {
                "provider": "cloudflare",
                "check": "dns_propagated",
                "status": "pending",
                "pending_safe": False,
            },
            {
                "provider": "resend",
                "check": "domain_verified",
                "status": "pending_safe",
                "pending_safe": False,
            },
            {
                "provider": "",
                "check": "",
                "status": "failed",
                "pending_safe": False,
            },
        ],
        "statement": "provider checks happened",
    }

    failures = _run_record_shape_failures(record)

    assert "verifiers.all_passed_or_pending_safe must be true" in failures
    assert "verifiers.overall must be passed" in failures
    assert "verifiers.checks[0].status must be passed, pending_safe, or skipped" in failures
    assert "verifiers.checks[1].pending_safe must be true" in failures
    assert "verifiers.checks[2].provider is missing" in failures
    assert "verifiers.checks[2].check is missing" in failures
    assert "verifiers.counts.pending must be 0" in failures
    assert "verifiers.counts.failed must be 0" in failures
    assert "verifiers.counts.needs_human_gate must be 0" in failures
    assert "verifiers.counts.unknown must be 0" in failures
    assert "verifiers.statement is missing live-verifier guidance" in failures


def test_acceptance_run_record_requires_verifier_counts_to_match_checks(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["verifiers"]["counts"]["passed"] = 2
    record["verifiers"]["counts"]["pending_safe"] = 0

    failures = _run_record_shape_failures(record)

    assert "verifiers.counts.passed must match verifiers.checks: 4" in failures
    assert "verifiers.counts.pending_safe must match verifiers.checks: 1" in failures


def test_acceptance_run_record_rejects_loose_verifier_summary_rows(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    checks = record["verifiers"]["checks"]
    assert isinstance(checks, list)
    first = checks[0]
    assert isinstance(first, dict)
    first["provider"] = " github "
    first["check"] = " repo_access "
    first["status"] = " passed "
    first["pending_safe"] = "false"
    first["private_note"] = "sidecar verifier note"

    failures = _run_record_shape_failures(record)

    assert "verifiers.checks[0].provider must not have surrounding whitespace" in failures
    assert "verifiers.checks[0].check must not have surrounding whitespace" in failures
    assert "verifiers.checks[0].status must not have surrounding whitespace" in failures
    assert "verifiers.checks[0].pending_safe must be boolean" in failures
    assert "verifiers.checks[0] has unexpected fields: private_note" in failures


def test_acceptance_run_record_requires_verifiers_to_cover_playbook_providers(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["verifiers"] = {
        "schema_version": "fusekit.verifier-summary.v1",
        "overall": "passed",
        "all_passed_or_pending_safe": True,
        "counts": {
            "passed": 2,
            "pending_safe": 1,
            "pending": 0,
            "repairing": 0,
            "failed": 0,
            "skipped": 0,
            "needs_human_gate": 0,
            "unknown": 0,
        },
        "checks": [
            {
                "provider": "resend",
                "check": "domain_verified",
                "status": "passed",
                "pending_safe": False,
            },
            {
                "provider": "cloudflare",
                "check": "dns_propagated",
                "status": "pending_safe",
                "pending_safe": True,
            },
            {
                "provider": "live_app",
                "check": "live_url_healthy",
                "status": "passed",
                "pending_safe": False,
            },
        ],
        "statement": (
            "Live provider verifiers are summarized as green checks or pending-safe "
            "checks before launch readiness is trusted."
        ),
    }

    failures = _run_record_shape_failures(record)

    assert (
        "verifiers.checks missing public demo provider coverage: GitHub, Vercel"
        in failures
    )


def test_acceptance_run_record_does_not_count_skipped_verifier_coverage(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    vercel = next(
        check
        for check in record["verifiers"]["checks"]
        if check["provider"] == "vercel"
    )
    vercel["status"] = "skipped"
    record["verifiers"]["counts"]["passed"] = 3
    record["verifiers"]["counts"]["skipped"] = 1

    failures = _run_record_shape_failures(record)

    assert "verifiers.checks missing public demo provider coverage: Vercel" in failures
    assert (
        "verifiers.statement must explain skipped verifier rows do not count as proof"
        in failures
    )


def test_acceptance_run_record_requires_redacted_audit_trail(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["wake_events"] = {
        "total": 2,
        "event_counts": {"clipboard_captured": 1, "resume_requested": 1},
        "events": [
            {
                "event": "clipboard_captured",
                "gate_id": "provider.resend.authorization",
                "provider": "resend",
                "target": "RESEND_API_KEY",
            },
            {
                "event": "resume_requested",
                "gate_id": "dns.moonlite.rsvp.approval",
                "provider": "dns",
                "classification": "dns-approval",
            },
        ],
    }
    record["approvals"] = [{"id": "dns.moonlite.rsvp.approval", "provider": "dns"}]
    record["vault"] = {
        "record_count": 1,
        "records": [
            {
                "id": "provider.resend.token",
                "kind": "provider_token",
                "provider": "resend",
                "label": "Resend API key",
            }
        ],
    }
    record["detonation"]["workspace_detonated"] = True
    record["verification"] = {
        "checks": [{"provider": "resend", "check": "domain_verified", "status": "passed"}]
    }
    record["audit_trail"] = {
        "schema_version": "fusekit.audit-trail.v1",
        "entry_count": 3,
            "counts": {"credential_capture": 1, "provider_action": 2},
            "entries": [
                {
                    "category": "credential_capture",
                    "action": "control_room.capture_vm_clipboard",
                    "provider": "resend",
                    "target": "RESEND_API_KEY",
                    "status": " captured ",
                    "source": "gate_events.jsonl",
                    "summary": " token=leaked-value ",
                    "private_note": "sidecar audit note",
                },
                {
                    "category": "provider_action",
                    "action": " resend.domain ",
                    "provider": " resend ",
                    "status": "passed",
                    "source": "setup_receipt.json",
                    "summary": "FuseKit recorded provider action resend.domain.",
                },
                {
                    "category": "provider_action",
                    "action": "provider.retry",
                    "provider": "",
                    "status": "recorded",
                    "source": "audit.jsonl",
                    "summary": (
                        "FuseKit recorded audit event provider.retry with secret values redacted."
                    ),
                },
                {
                    "category": "detonation",
                    "action": "oci.workspace.resource_delete_failed",
                    "provider": "oci",
                    "resource": "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
                    "status": "failed",
                    "source": "workspace_detonation.json",
                    "summary": "FuseKit recorded a cleanup failure.",
                },
            ],
            "statement": "Audit happened.",
        }

    failures = _run_record_shape_failures(record)

    assert "audit_trail.entries[0] has unexpected fields: private_note" in failures
    assert "audit_trail.entries[1].action must not have surrounding whitespace" in failures
    assert "audit_trail.entries[0].status must not have surrounding whitespace" in failures
    assert "audit_trail.entries[0].summary must not have surrounding whitespace" in failures
    assert "audit_trail.entries[1].provider must not have surrounding whitespace" in failures
    assert "audit_trail.entries[0].summary contains credential-looking text" in failures
    assert "audit_trail.entries[0].wake_event_id is missing" in failures
    assert "audit_trail.entries[1].receipt_action_index is missing" in failures
    assert "audit_trail.entries[2].audit_log_index is missing" in failures
    assert "audit_trail.entries[3].resource contains credential-looking text" in failures
    assert "audit_trail must include dns_write" in failures
    assert "audit_trail must include human_approval" in failures
    assert "audit_trail.dns_write must include source setup_receipt.json" in failures
    assert "audit_trail.human_approval must include source gate_events.jsonl" in failures
    assert "audit_trail.counts.detonation must match entries" in failures
    assert "audit_trail.statement is missing audit-first guidance" in failures


def test_acceptance_run_record_rejects_duplicate_audit_trail_entries(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["audit_trail"] = _audit_trail()
    duplicate = dict(record["audit_trail"]["entries"][0])
    record["audit_trail"]["entries"].append(duplicate)
    record["audit_trail"]["entry_count"] += 1
    record["audit_trail"]["counts"]["credential_capture"] += 1

    failures = _run_record_shape_failures(record)

    assert "audit_trail.entries[5] duplicates audit trail proof" in failures


def test_acceptance_run_record_requires_receipt_indexed_provider_actions(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    for entry in record["audit_trail"]["entries"]:
        if entry.get("category") == "provider_action":
            entry["source"] = "audit.jsonl"
            entry["audit_log_index"] = 1
            entry.pop("receipt_action_index", None)

    failures = _run_record_shape_failures(record)

    assert "audit_trail.provider_action must include source setup_receipt.json" in failures


def test_acceptance_run_record_requires_recording_contract(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["recording_contract"] = {
        "schema_version": "fusekit.recording-contract.v0",
        "recording_ready": False,
        "private_note": "sidecar recording proof",
        "checks": {
            "durable_state": True,
            "worker_replacement": True,
            "runner_profile": True,
            "provider_playbook": True,
            "human_actions": False,
            "rehearsal_review": False,
            "automation_boundary": True,
            "control_room_security": True,
            "verifiers": True,
            "audit_trail": True,
            "evidence": True,
            "detonation": True,
            "errors_empty": True,
            "private_check": True,
        },
        "blockers": [" human_actions", "human_actions", "", 7],
        "statement": "ready",
    }

    failures = _run_record_shape_failures(record)

    assert "recording_contract has unexpected fields: private_note" in failures
    assert (
        "recording_contract.checks has unexpected fields: private_check"
        in failures
    )
    assert "recording_contract.schema_version is unsupported" in failures
    assert "recording_contract.recording_ready must be true" in failures
    assert "recording_contract.checks.human_actions must be true" in failures
    assert "recording_contract.checks.rehearsal_review must be true" in failures
    assert (
        "recording_contract.checks missing artifacts, model_inference, provider_gates, "
        "timeline, vault, wake_events"
        in failures
    )
    assert (
        "recording_contract.blockers[0] must not have surrounding whitespace"
        in failures
    )
    assert (
        "recording_contract.blockers[1] duplicates recording contract blocker human_actions"
        in failures
    )
    assert "recording_contract.blockers[2] must be non-empty" in failures
    assert "recording_contract.blockers[3] must be a string" in failures
    assert (
        "recording_contract.blockers must be empty:  human_actions, human_actions, , 7"
        in failures
    )
    assert "recording_contract.statement is missing public demo guidance" in failures


def test_acceptance_run_record_rejects_recording_contract_section_drift(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["steps"] = []
    record["artifacts"] = []

    failures = _run_record_shape_failures(record)

    assert "recording_contract.checks.timeline has no steps proof" in failures
    assert "recording_contract.checks.artifacts has no artifacts proof" in failures


def test_acceptance_run_record_rejects_unshaped_acceptance_summary(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["acceptance"] = {
        "mode": "sideways",
        "launch_ready": "true",
        "public_launch_ready": 1,
        "remote_artifacts_ready": "yes",
        "recording_proof_ready": "yes",
        "recording_ready": True,
        "missing": "none",
        "blockers": "none",
        "error": {"detail": "bad"},
        "private_note": "stale sidecar field",
    }

    failures = _run_record_shape_failures(record)

    assert "acceptance has unexpected fields: private_note" in failures
    assert "acceptance.mode must be live or rehearsal" in failures
    assert "acceptance.launch_ready must be boolean" in failures
    assert "acceptance.public_launch_ready must be boolean" in failures
    assert "acceptance.remote_artifacts_ready must be boolean" in failures
    assert "acceptance.recording_proof_ready must be boolean" in failures
    assert "acceptance.missing must be a list" in failures
    assert "acceptance.blockers must be a list" in failures
    assert "acceptance.error must be a string" in failures


def test_acceptance_run_record_rejects_stale_acceptance_summary(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["acceptance"] = {
        "mode": " rehearsal ",
        "launch_ready": False,
        "public_launch_ready": True,
        "remote_artifacts_ready": True,
        "recording_proof_ready": True,
        "recording_ready": True,
        "missing": ["verified live URL"],
        "blockers": ["detonation"],
        "error": "Acceptance still has a live verifier error.",
    }
    record["errors"] = [
        {
            "source": "verification",
            "id": "live_url_healthy",
            "detail": "Live URL verification is not ready.",
        }
    ]

    failures = _run_record_shape_failures(record)

    assert "acceptance.mode must be live or rehearsal" in failures
    assert "acceptance.public_launch_ready must equal live launch_ready" in failures
    assert "acceptance.public_launch_ready must require launch_ready" in failures
    assert "acceptance.public_launch_ready must require live mode" in failures
    assert "acceptance.recording_ready must require live mode" in failures
    assert "acceptance.blockers[0] must be an object" in failures
    assert "acceptance.blockers must be empty when readiness is true" in failures
    assert "acceptance.missing must be empty when readiness is true" in failures
    assert "acceptance.error must be empty when readiness is true" in failures
    assert "acceptance readiness must be false when errors are present" in failures
    assert "acceptance.recording_ready must be false when errors are present" in failures

    record["acceptance"] = {
        "mode": "live",
        "launch_ready": True,
        "public_launch_ready": False,
        "remote_artifacts_ready": True,
        "recording_proof_ready": True,
        "recording_ready": False,
        "missing": [],
        "blockers": [],
        "error": "",
    }
    record["errors"] = []

    failures = _run_record_shape_failures(record)

    assert "acceptance.public_launch_ready must equal live launch_ready" in failures

    record["acceptance"] = {
        "mode": "rehearsal",
        "launch_ready": False,
        "public_launch_ready": False,
        "remote_artifacts_ready": False,
        "recording_proof_ready": False,
        "recording_ready": False,
        "missing": [],
        "blockers": [],
        "error": " unresolved verifier failure ",
    }

    failures = _run_record_shape_failures(record)

    assert "acceptance.error must not have surrounding whitespace" in failures

    record["acceptance"]["error"] = "   "

    failures = _run_record_shape_failures(record)

    assert "acceptance.error must be empty or non-empty text" in failures

    record["acceptance"] = {
        "mode": "rehearsal",
        "launch_ready": True,
        "public_launch_ready": False,
        "remote_artifacts_ready": False,
        "recording_proof_ready": False,
        "recording_ready": False,
        "missing": [],
        "blockers": [],
        "error": "",
    }
    record["errors"] = [
        {
            "source": "verification",
            "id": "live_app",
            "detail": "Live app verification is unresolved.",
        }
    ]

    failures = _run_record_shape_failures(record)

    assert "acceptance readiness must be false when errors are present" in failures
    assert "acceptance.recording_ready must be false when errors are present" not in failures

    record["acceptance"] = {
        "mode": "rehearsal",
        "launch_ready": False,
        "public_launch_ready": False,
        "remote_artifacts_ready": False,
        "recording_proof_ready": False,
        "recording_ready": False,
        "missing": [" verified live URL ", " ", "verified live URL"],
        "blockers": [],
        "error": "",
    }
    record["errors"] = []

    failures = _run_record_shape_failures(record)

    assert "acceptance.missing[0] must not have surrounding whitespace" in failures
    assert "acceptance.missing[1] must be non-empty" in failures
    assert (
        "acceptance.missing[0] has no matching blocker item verified live URL"
        in failures
    )
    assert (
        "acceptance.missing[2] duplicates acceptance missing proof verified live URL"
        in failures
    )

    record["acceptance"] = {
        "mode": "rehearsal",
        "launch_ready": False,
        "public_launch_ready": False,
        "remote_artifacts_ready": False,
        "recording_proof_ready": False,
        "recording_ready": False,
        "missing": ["vault"],
        "blockers": [
            {"item": "vault", "category": "", "next_action": "Open Capture."},
            {
                "item": " vault ",
                "category": "Vault",
                "next_action": "Open Capture.",
                "private_note": "stale sidecar field",
            },
            {
                "item": "verifier",
                "category": "Verification",
                "next_action": 7,
                "detail": {"bad": "shape"},
            },
            {
                "item": "empty-detail",
                "category": "Verification",
                "next_action": "Review verifier proof.",
                "detail": "",
            },
        ],
        "error": "",
    }
    record["errors"] = []

    failures = _run_record_shape_failures(record)

    assert "acceptance.blockers[0].category is missing" in failures
    assert "acceptance.blockers[1].item must not have surrounding whitespace" in failures
    assert "acceptance.blockers[1].item duplicates acceptance blocker vault" in failures
    assert "acceptance.blockers[1] has unexpected fields: private_note" in failures
    assert "acceptance.blockers[2].next_action is missing" in failures
    assert "acceptance.blockers[2].detail must be a string" in failures
    assert "acceptance.blockers[3].detail must be non-empty when present" in failures

    record["acceptance"] = {
        "mode": "live",
        "launch_ready": True,
        "public_launch_ready": True,
        "remote_artifacts_ready": True,
        "recording_proof_ready": False,
        "recording_ready": True,
        "missing": [],
        "blockers": [],
        "error": "",
    }

    failures = _run_record_shape_failures(record)

    assert (
        "acceptance.recording_ready must equal public_launch_ready "
        "and remote_artifacts_ready and recording_proof_ready"
        in failures
    )

    record["acceptance"] = {
        "mode": "live",
        "launch_ready": True,
        "public_launch_ready": True,
        "remote_artifacts_ready": False,
        "recording_proof_ready": True,
        "recording_ready": True,
        "missing": [],
        "blockers": [],
        "error": "",
    }

    failures = _run_record_shape_failures(record)

    assert (
        "acceptance.recording_ready must equal public_launch_ready "
        "and remote_artifacts_ready and recording_proof_ready"
        in failures
    )
    assert "acceptance.recording_ready must require remote_artifacts_ready" in failures

    record["acceptance"] = {
        "mode": "live",
        "launch_ready": True,
        "public_launch_ready": True,
        "remote_artifacts_ready": True,
        "recording_proof_ready": False,
        "recording_ready": False,
        "missing": [],
        "blockers": [],
        "error": "",
    }
    record["errors"] = []

    failures = _run_record_shape_failures(record)

    assert (
        "acceptance.recording_proof_ready must match "
        "recording_contract.recording_ready"
        in failures
    )


def test_acceptance_run_record_requires_ready_model_inference(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["model_inference"] = {
        **_model_inference(),
        "status": "needs_openclaw_or_api_key",
        "ready": False,
        "next_action": "Use the OpenClaw/OpenAI human-gated authorization step.",
    }
    record["llm_contract"] = {
        **_llm_contract(),
        "status": "needs_openclaw_or_api_key",
        "next_action": "Use the OpenClaw/OpenAI human-gated authorization step.",
    }
    record["recording_contract"]["recording_ready"] = False
    record["recording_contract"]["checks"]["model_inference"] = False
    record["recording_contract"]["blockers"] = ["model_inference"]

    failures = _run_record_shape_failures(record)

    assert "model_inference.status must prove encrypted API key or OpenClaw auth" in failures
    assert "model_inference.ready must be true" in failures
    assert "model_inference.next_action must explain the ready auth lane" in failures
    assert "recording_contract.checks.model_inference must be true" in failures
    assert "recording_contract.blockers must be empty: model_inference" in failures


def test_acceptance_run_record_requires_llm_contract_for_model_inference(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record.pop("llm_contract")

    failures = _run_record_shape_failures(record)

    assert "llm_contract is missing" in failures
    assert "Run Record must include llm_contract for model_inference proof" in failures


def test_acceptance_run_record_requires_llm_contract_to_match_model_inference(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["llm_contract"]["status"] = "needs_openclaw_or_api_key"
    record["llm_contract"]["base_url"] = "https://llm.example/v1"
    record["llm_contract"]["required"] = False
    record["llm_contract"]["can_proceed_without_api_key"] = False
    record["llm_contract"]["default_lane"] = "api-key"
    record["llm_contract"]["security"]["raw_secret_export"] = "allowed"

    failures = _run_record_shape_failures(record)

    assert "llm_contract.status must prove encrypted API key or OpenClaw auth" in failures
    assert "llm_contract.security.raw_secret_export must be denied" in failures
    assert (
        "model_inference must match llm_contract fields: "
        "base_url, can_proceed_without_api_key, default_lane, required, status"
        in failures
    )


def test_acceptance_run_record_requires_shaped_llm_contract_lanes(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["model_inference"]["provider"] = " openai "
    record["model_inference"]["next_action"] = "Continue at https://provider.example/callback"
    record["model_inference"]["required"] = "true"
    record["model_inference"]["can_proceed_without_api_key"] = 1
    record["model_inference"]["lane_count"] = True
    record["model_inference"]["private_note"] = "sidecar model proof"
    record["llm_contract"]["provider"] = " openai "
    record["llm_contract"]["record_id"] = " llm.openai.api_key "
    record["llm_contract"]["required"] = "true"
    record["llm_contract"]["can_proceed_without_api_key"] = 1
    record["llm_contract"]["default_lane"] = "missing-lane"
    record["llm_contract"]["private_note"] = "sidecar LLM contract proof"
    record["llm_contract"]["security"]["storage"] = " encrypted vault only "
    record["llm_contract"]["security"]["public_surfaces"] = (
        "Review https://provider.example/callback"
    )
    record["llm_contract"]["security"]["private_note"] = "sidecar security proof"
    record["llm_contract"]["lanes"] = [
        "bad",
        {
            "id": "",
            "label": "",
            "available": "yes",
            "requires_user_action": "no",
            "description": "",
        },
        {
            "id": "openclaw-openai",
            "label": "OpenClaw OpenAI authorization",
            "available": True,
            "requires_user_action": False,
            "description": "capture api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890",
            "private_note": "sidecar lane proof",
        },
        {
            "id": " openclaw-openai ",
            "label": " Duplicate OpenClaw lane ",
            "available": True,
            "requires_user_action": False,
            "description": " Duplicate model auth lane. ",
        },
    ]

    failures = _run_record_shape_failures(record)

    assert "model_inference has unexpected fields: private_note" in failures
    assert "model_inference.provider must not have surrounding whitespace" in failures
    assert "model_inference.next_action contains callback URL" in failures
    assert "model_inference.required must be boolean" in failures
    assert "model_inference.can_proceed_without_api_key must be boolean" in failures
    assert "model_inference.lane_count must be integer" in failures
    assert "llm_contract has unexpected fields: private_note" in failures
    assert "llm_contract.provider must not have surrounding whitespace" in failures
    assert "llm_contract.record_id must not have surrounding whitespace" in failures
    assert "llm_contract.required must be boolean" in failures
    assert "llm_contract.can_proceed_without_api_key must be boolean" in failures
    assert "llm_contract.security has unexpected fields: private_note" in failures
    assert "llm_contract.security.storage must not have surrounding whitespace" in failures
    assert "llm_contract.security.public_surfaces contains callback URL" in failures
    assert "llm_contract.lanes[0] is not an object" in failures
    assert "llm_contract.lanes[1].id is missing" in failures
    assert "llm_contract.lanes[1].label is missing" in failures
    assert "llm_contract.lanes[1].available must be boolean" in failures
    assert "llm_contract.lanes[1].requires_user_action must be boolean" in failures
    assert "llm_contract.lanes[1].description is missing" in failures
    assert "llm_contract.lanes[2] has unexpected fields: private_note" in failures
    assert "llm_contract.lanes[2].description contains credential-looking text" in failures
    assert "llm_contract.lanes[3].id must not have surrounding whitespace" in failures
    assert "llm_contract.lanes[3].id duplicates LLM contract lane openclaw-openai" in (
        failures
    )
    assert "llm_contract.lanes[3].label must not have surrounding whitespace" in failures
    assert (
        "llm_contract.lanes[3].description must not have surrounding whitespace"
        in failures
    )
    assert "llm_contract.default_lane must match llm_contract.lanes" in failures
    assert "llm_contract.lanes must include api-key" in failures


def test_acceptance_run_record_requires_ready_default_and_status_llm_lanes(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    model = record["model_inference"]
    assert isinstance(model, dict)
    model["default_lane"] = "api-key"
    contract = record["llm_contract"]
    assert isinstance(contract, dict)
    contract["default_lane"] = "api-key"
    lanes = contract["lanes"]
    assert isinstance(lanes, list)
    api_key_lane = lanes[0]
    assert isinstance(api_key_lane, dict)
    api_key_lane["available"] = False
    api_key_lane["requires_user_action"] = True

    failures = _run_record_shape_failures(record)

    assert "llm_contract.default_lane must be available" in failures
    assert (
        "llm_contract.default_lane must not require user action when ready" in failures
    )
    assert "llm_contract.lanes must mark api-key available" in failures
    assert (
        "llm_contract.lanes must mark api-key ready without user action" in failures
    )


def test_acceptance_run_record_requires_recording_worker_replacement_check(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["recording_contract"]["recording_ready"] = False
    record["recording_contract"]["checks"]["worker_replacement"] = False
    record["recording_contract"]["blockers"] = ["worker_replacement"]

    failures = _run_record_shape_failures(record)

    assert "recording_contract.checks.worker_replacement must be true" in failures
    assert "recording_contract.blockers must be empty: worker_replacement" in failures


def test_acceptance_run_record_requires_control_room_security_proof(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["control_room_security"]["routes"] = [
        route
        for route in record["control_room_security"]["routes"]
        if route["route"] != "/api/gates/<gate_id>/capture-clipboard"
    ]
    record["control_room_security"]["route_count"] = len(
        record["control_room_security"]["routes"]
    )
    record["control_room_security"]["state_changing_routes"] = [
        route
        for route in record["control_room_security"]["state_changing_routes"]
        if route != "/api/gates/<gate_id>/capture-clipboard"
    ]
    record["control_room_security"]["state_changing_route_count"] = len(
        record["control_room_security"]["state_changing_routes"]
    )
    record["recording_contract"]["recording_ready"] = False
    record["recording_contract"]["checks"]["control_room_security"] = False
    record["recording_contract"]["blockers"] = ["control_room_security"]

    failures = _run_record_shape_failures(record)

    assert "control_room_security.routes missing protected gate mutation routes" in failures
    assert (
        "control_room_security.state_changing_routes missing protected gate mutation routes"
        in failures
    )
    assert "recording_contract.checks.control_room_security must be true" in failures
    assert (
        "recording_contract.blockers must be empty: control_room_security" in failures
    )


def test_acceptance_run_record_rejects_duplicate_control_room_security_routes(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    security = record["control_room_security"]
    duplicate_route = dict(
        next(route for route in security["routes"] if route.get("state_change") is True)
    )
    security["routes"].append(duplicate_route)
    security["state_changing_routes"].append(duplicate_route["route"])
    security["route_count"] = len(security["routes"])
    security["state_changing_route_count"] = sum(
        1 for route in security["routes"] if route.get("state_change") is True
    )

    failures = _run_record_shape_failures(record)

    assert any(
        failure.endswith(
            "duplicates control-room route " f"{duplicate_route['route']}"
        )
        for failure in failures
    )
    assert any(
        failure.endswith(
            "duplicates state-changing route " f"{duplicate_route['route']}"
        )
        for failure in failures
    )


def test_acceptance_run_record_rejects_loose_control_room_security_rows(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    security = record["control_room_security"]
    route_index, route = next(
        (index, route)
        for index, route in enumerate(security["routes"])
        if route.get("state_change") is True
    )
    route["private_note"] = "sidecar route note"
    route["route"] = f" {route['route']} "
    route["methods"][0] = f" {route['methods'][0]} "
    route["protection"] = f" {route['protection']} "
    security["private_note"] = "sidecar security note"
    security["state_changing_routes"][0] = f" {security['state_changing_routes'][0]} "

    failures = _run_record_shape_failures(record)

    assert "control_room_security has unexpected fields: private_note" in failures
    assert (
        f"control_room_security.routes[{route_index}] has unexpected fields: private_note"
        in failures
    )
    assert (
        f"control_room_security.routes[{route_index}].route must not have surrounding whitespace"
        in failures
    )
    assert (
        f"control_room_security.routes[{route_index}].methods[0] "
        "must not have surrounding whitespace"
        in failures
    )
    assert (
        f"control_room_security.routes[{route_index}].protection "
        "must not have surrounding whitespace"
        in failures
    )
    assert (
        "control_room_security.state_changing_routes[0] must not have surrounding whitespace"
        in failures
    )


def test_acceptance_run_record_recording_contract_errors_empty_matches_errors(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["errors"] = [
        {
            "source": "verification",
            "id": "resend",
            "detail": "Resend verification still needs repair.",
        }
    ]

    failures = _run_record_shape_failures(record)

    assert "recording_contract.checks.errors_empty must match errors" in failures


def test_acceptance_run_record_rejects_unredacted_errors(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["errors"] = [
        {
            "source": "verification",
            "id": "https://provider.example/callback?code=secret-code",
            "detail": "token=abcdefghijklmnopqrstuvwxyz1234567890",
        },
        {
            "source": " verification ",
            "id": "resend.domain",
            "detail": "Resend domain verification still needs repair.",
            "private_note": "stale sidecar error detail",
        },
        {
            "source": "verification",
            "id": "resend.domain",
            "detail": "Duplicate unresolved error identity.",
        },
        "not-an-object",
    ]

    failures = _run_record_shape_failures(record)

    assert "errors[0].id contains credential-looking text" in failures
    assert "errors[0].detail contains credential-looking text" in failures
    assert "errors[1] has unexpected fields: private_note" in failures
    assert "errors[1].source must not have surrounding whitespace" in failures
    assert "errors[2] duplicates error verification:resend.domain" in failures
    assert "errors[3] is not an object" in failures


def test_acceptance_run_record_rejects_bare_callback_url(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["errors"] = [
        {
            "source": "verification",
            "id": "provider.callback",
            "detail": "Provider returned https://provider.example/callback",
        }
    ]

    failures = _run_record_shape_failures(record)

    assert "run_record.errors[0].detail contains callback URL" in failures


def test_acceptance_run_record_rejects_unredacted_timeline_entries(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["steps"] = [
        {
            "id": " setup.execute ",
            "label": " Run setup worker ",
            "status": "failed",
            "detail": " Callback failed at https://provider.example/callback?code=secret ",
            "updated_at": True,
            "private_note": "sidecar timeline note",
        },
        {
            "id": "setup.execute",
            "label": "Duplicate setup worker",
            "status": "failed",
        },
    ]
    record["checkpoints"] = [
        {
            "id": "setup.execute",
            "label": "Run setup worker",
            "status": "failed",
            "detail": " Bearer abcdefghijklmnopqrstuvwxyz1234567890 ",
            "mascot_state": " gate ",
            "resume_hint": " Stay in the control room. ",
            "updated_at": -1,
            "private_note": "sidecar checkpoint note",
        },
        {
            "id": "setup.execute",
            "label": "Duplicate setup worker",
            "status": "failed",
        },
    ]

    failures = _run_record_shape_failures(record)

    assert "steps[0] has unexpected fields: private_note" in failures
    assert "steps[0].id must not have surrounding whitespace" in failures
    assert "steps[0].label must not have surrounding whitespace" in failures
    assert "steps[0].detail must not have surrounding whitespace" in failures
    assert "steps[0].detail contains credential-looking text" in failures
    assert "steps[0].updated_at must be a non-negative number" in failures
    assert "steps[1].id duplicates steps entry setup.execute" in failures
    assert "checkpoints[0] has unexpected fields: private_note" in failures
    assert "checkpoints[0].detail must not have surrounding whitespace" in failures
    assert "checkpoints[0].mascot_state must not have surrounding whitespace" in failures
    assert "checkpoints[0].resume_hint must not have surrounding whitespace" in failures
    assert "checkpoints[0].detail contains credential-looking text" in failures
    assert "checkpoints[0].updated_at must be a non-negative number" in failures
    assert "checkpoints[1].id duplicates checkpoints entry setup.execute" in failures


def test_acceptance_run_record_rejects_nested_unredacted_survivor_values(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    resend = next(
        provider
        for provider in record["provider_strategies"]["providers"]
        if provider["provider"] == "resend"
    )
    resend_domain = next(
        strategy
        for strategy in resend["strategies"]
        if strategy["recipe"] == "resend-domain"
    )
    resend_domain["decision"]["selected"]["evidence"][
        "debug_token"
    ] = "token=leaked-provider-token"
    record["verification"]["checks"][0]["details"] = {
        "callback": "https://provider.example/callback?code=secret-code"
    }
    record["detonation"]["workspace_receipt"]["failures"] = {
        "cleanup": "Bearer abcdefghijklmnopqrstuvwxyz1234567890"
    }

    failures = _run_record_shape_failures(record)

    assert any(
        failure.endswith(
            "selected.evidence.debug_token contains credential-looking text"
        )
        for failure in failures
    )
    assert (
        "run_record.verification.checks[0].details.callback contains credential-looking text"
    ) in failures
    assert (
        "run_record.detonation.workspace_receipt.failures.cleanup contains credential-looking text"
    ) in failures


def test_acceptance_run_record_rejects_loose_embedded_verification_rows(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    check = record["verification"]["checks"][0]
    assert isinstance(check, dict)
    check["provider"] = " github "
    check["check"] = " repo_access "
    check["status"] = " passed "
    check["summary"] = " Repo access passed. "
    check["details"] = "ok"
    check["private_note"] = "sidecar verifier detail"

    failures = _run_record_shape_failures(record)

    assert "verification checks[0] has unexpected fields: private_note" in failures
    assert "verification checks[0].provider must not have surrounding whitespace" in failures
    assert "verification checks[0].check must not have surrounding whitespace" in failures
    assert "verification checks[0].status must not have surrounding whitespace" in failures
    assert "verification checks[0].summary must not have surrounding whitespace" in failures
    assert "verification checks[0].details must be an object" in failures


def test_acceptance_run_record_requires_evented_gate_wake_proof(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_gates"] = {
        "total": 1,
        "statuses": {"resume_requested": 1},
        "providers": ["cloudflare"],
        "records": [
            {
                "id": "provider.cloudflare.authorization",
                "provider": "cloudflare",
                "status": "resume_requested",
                "target": "CLOUDFLARE_API_TOKEN",
                "captured_targets": ["CLOUDFLARE_API_TOKEN"],
            }
        ],
    }
    record["wake_events"] = {
        "total": 1,
        "event_counts": {"resume_requested": 1},
        "events": [
            {
                "schema_version": "fusekit.gate-wake.v1",
                "event": "resume_requested",
                "gate_id": "provider.cloudflare.authorization",
                "provider": "cloudflare",
                "status": "resume_requested",
                "created_at": 2.0,
            }
        ],
    }

    failures = _run_record_shape_failures(record)

    assert (
        "wake_events missing clipboard_captured for "
        "provider.cloudflare.authorization:CLOUDFLARE_API_TOKEN"
    ) in failures
    assert (
        "provider_gates.records[provider.cloudflare.authorization].last_wake_event_id is missing"
    ) in failures
    assert (
        "provider_gates.records[provider.cloudflare.authorization].last_wake_event "
        "must be resume_requested"
    ) in failures

    record["provider_gates"]["records"][0]["last_wake_event_id"] = "wake-resume-1"
    record["provider_gates"]["records"][0]["last_wake_event"] = "resume_requested"
    record["provider_gates"]["records"][0]["last_wake_event_at"] = 2.0
    record["wake_events"] = {
        "total": 2,
        "event_counts": {"clipboard_captured": 1, "resume_requested": 1},
        "events": [
            {
                "schema_version": "fusekit.gate-wake.v1",
                "id": "wake-capture-1",
                "event": "clipboard_captured",
                "gate_id": "provider.cloudflare.authorization",
                "provider": "cloudflare",
                "target": "CLOUDFLARE_API_TOKEN",
                "captured_targets": ["CLOUDFLARE_API_TOKEN"],
                "created_at": 1.0,
            },
            {
                "schema_version": "fusekit.gate-wake.v1",
                "id": "wake-resume-1",
                "event": "resume_requested",
                "gate_id": "provider.cloudflare.authorization",
                "provider": "cloudflare",
                "status": "resume_requested",
                "created_at": 2.0,
            },
        ],
    }
    record["audit_trail"] = {
        "schema_version": "fusekit.audit-trail.v1",
        "entry_count": 4,
        "counts": {
            "credential_capture": 1,
            "human_approval": 1,
            "provider_action": 1,
            "detonation": 1,
        },
        "entries": [
            {
                "category": "credential_capture",
                "action": "control_room.capture_vm_clipboard",
                "provider": "cloudflare",
                "target": "CLOUDFLARE_API_TOKEN",
                "status": "captured",
                "source": "gate_events.jsonl",
                "wake_event_id": "wake-capture-1",
                "summary": "CLOUDFLARE_API_TOKEN was captured from the VM clipboard.",
            },
            {
                "category": "human_approval",
                "action": "control_room.confirm_gate_finished",
                "provider": "cloudflare",
                "status": "approved",
                "source": "gate_events.jsonl",
                "wake_event_id": "wake-resume-1",
                "summary": "A visible control-room approval woke the setup worker.",
            },
            {
                "category": "provider_action",
                "action": "cloudflare.dns",
                "provider": "cloudflare",
                "status": "passed",
                "source": "setup_receipt.json",
                "receipt_action_index": 1,
                "summary": "FuseKit recorded provider action cloudflare.dns.",
            },
            {
                "category": "detonation",
                "action": "oci.workspace.detonate",
                "provider": "oci",
                "status": "complete",
                "source": "workspace_detonation.json",
                "summary": "FuseKit recorded disposable OCI worker and workspace cleanup.",
            },
        ],
        "statement": (
            "Credential captures, provider actions, DNS writes, human approvals, "
            "and detonation events are summarized without storing raw secrets."
        ),
    }
    actions = [
        {
            "gate_id": "provider.cloudflare.authorization",
            "provider": "cloudflare",
            "classification": "authorization",
            "action": "capture_vm_clipboard",
            "visible_control": "Capture CLOUDFLARE_API_TOKEN from VM clipboard",
            "target": "CLOUDFLARE_API_TOKEN",
            "guided": True,
            "created_at": 1.0,
        },
        {
            "gate_id": "provider.cloudflare.authorization",
            "provider": "cloudflare",
            "classification": "authorization",
            "action": "confirm_gate_finished",
            "visible_control": "I finished this step",
            "target": "",
            "guided": True,
            "created_at": 2.0,
        },
    ]
    record["human_actions"] = _human_action_trace_for(actions)
    record["rehearsal_review"] = _rehearsal_review_for(actions)

    assert _run_record_shape_failures(record) == []


def test_acceptance_run_record_requires_shaped_approval_summary(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_gates"] = {
        "total": 1,
        "statuses": {"resume_requested": 1},
        "providers": ["dns"],
        "records": [
            {
                "id": "dns.moonlite.rsvp.approval",
                "provider": "dns",
                "status": "resume_requested",
            }
        ],
    }
    record["wake_events"] = {
        "total": 1,
        "event_counts": {"resume_requested": 1},
        "events": [
            {
                "schema_version": "fusekit.gate-wake.v1",
                "id": "wake-other",
                "event": "resume_requested",
                "gate_id": "dns.other.approval",
                "provider": "dns",
                "status": "resume_requested",
                "created_at": 2.0,
            }
        ],
    }
    record["approvals"] = [
        {
            "id": " dns.stale.approval ",
            "provider": "",
            "status": " passed ",
            "reason": " approved with token=leaked-value ",
            "updated_at": True,
            "private_note": "sidecar approval note",
        },
        {
            "id": "dns.moonlite.rsvp.approval",
            "provider": "dns",
            "status": "resume_requested",
            "reason": "explicit DNS apply approval",
            "updated_at": 2.0,
        },
        {
            "id": "dns.moonlite.rsvp.approval",
            "provider": "dns",
            "status": "resume_requested",
            "reason": "duplicate DNS apply approval",
            "updated_at": -1,
        },
    ]

    failures = _run_record_shape_failures(record)

    assert "approvals[0] has unexpected fields: private_note" in failures
    assert "approvals[0].id must not have surrounding whitespace" in failures
    assert "approvals[0].provider is missing" in failures
    assert "approvals[0].status must not have surrounding whitespace" in failures
    assert "approvals[0].status is unsupported" in failures
    assert "approvals[0].reason must not have surrounding whitespace" in failures
    assert "approvals[0].reason contains credential-looking text" in failures
    assert "approvals[0].updated_at must be a non-negative number" in failures
    assert "approvals[0].id must match provider_gates.records" in failures
    assert "approvals[1].id must match a resume_requested wake event" in failures
    assert (
        "approvals[2].id duplicates approval summary for dns.moonlite.rsvp.approval"
        in failures
    )
    assert "approvals[2].updated_at must be a non-negative number" in failures
    assert "approvals[2].id must match a resume_requested wake event" in failures


def test_acceptance_cli_checks_vault_without_leaking_secret(tmp_path, capsys) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"dependencies": {"resend": "latest"}}),
        encoding="utf-8",
    )
    (app / "mail.ts").write_text("process.env.RESEND_API_KEY", encoding="utf-8")
    vault_path = app / ".fusekit" / "fusekit.vault.json"
    vault_path.parent.mkdir(parents=True)
    passphrase = tmp_path / "pass.txt"
    passphrase.write_text("passphrase\n", encoding="utf-8")
    secret = "re_super_secret_value"
    vault = Vault.empty()
    vault.put("provider.resend.token", "provider_token", "resend", "Resend token", secret)
    vault.save(vault_path, "passphrase")

    assert (
        main(
            [
                "acceptance",
                "run",
                str(app),
                "--mode",
                "rehearsal",
                "--vault",
                str(vault_path),
                "--passphrase-file",
                str(passphrase),
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "vault.unlock" in output
    assert "vault.wrong_passphrase" in output
    assert secret not in output
    assert secret not in (app / ".fusekit" / "acceptance" / "ledger.jsonl").read_text(
        encoding="utf-8"
    )


def test_live_acceptance_requires_resend_before_dns_when_both_are_present(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps({"actions": [], "raw_secrets_exposed": 0, "live_url": "https://moonlite.rsvp"}),
        encoding="utf-8",
    )
    (remote_fusekit / "audit.jsonl").write_text("{}", encoding="utf-8")
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        encoding="utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.dns", "status": "planned"}]}),
        encoding="utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    order_check = next(check for check in report.checks if check.id == "provider_strategies.order")
    assert report.launch_ready is False
    assert order_check.status == "failed"
    assert "Resend-before-DNS provider setup order" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["Resend-before-DNS provider setup order"]["category"] == "Provider order"
    next_action = blockers["Resend-before-DNS provider setup order"]["next_action"]
    assert "Capture RESEND_API_KEY first" in next_action
    assert "Resend domain by API" in next_action
    assert "approve DNS apply" in next_action
    assert "Run Resend domain setup before Cloudflare/DNS" not in next_action


def test_live_acceptance_requires_receipt_resend_dns_flow(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "changes": [
                                {
                                    "record": {
                                        "type": "A",
                                        "name": "moonlite.rsvp",
                                        "value": "76.76.21.21",
                                    }
                                }
                            ],
                        },
                    },
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[
                                {
                                    "type": "MX",
                                    "name": "send.moonlite.rsvp",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                }
                            ],
                        ),
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.resend_dns_flow")
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "DNS proposal for the Resend domain before Resend domain setup" in receipt_check.detail
    assert "Resend DNS records in receipt DNS proposal" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["Resend DNS records in receipt DNS proposal"]["category"] == "Provider order"
    next_action = blockers["Resend DNS records in receipt DNS proposal"]["next_action"]
    assert "Capture RESEND_API_KEY first" in next_action
    assert "Resend sending domain by API" in next_action
    assert "approve DNS apply only after Cloudflare/DNS shows" in next_action
    assert "exact Resend verification records" in next_action
    assert "Rerun setup so the receipt proves" not in next_action


def test_live_acceptance_requires_resend_domain_contract_before_dns(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "dns_records": [
                                {
                                    "type": "MX",
                                    "name": "send.moonlite.rsvp",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                }
                            ],
                        },
                    },
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "changes": [
                                {
                                    "record": {
                                        "type": "MX",
                                        "name": "send.moonlite.rsvp",
                                        "value": "feedback-smtp.us-east-1.amazonses.com",
                                    }
                                }
                            ],
                        },
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.resend_dns_flow")
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "missing the Resend domain id" in receipt_check.detail
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    next_action = blockers["Resend DNS records in receipt DNS proposal"]["next_action"]
    assert "Resend sending domain by API" in next_action
    assert "approve DNS apply" in next_action


def test_live_acceptance_accepts_receipt_resend_records_before_dns(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[
                                {
                                    "type": "MX",
                                    "name": "send.moonlite.rsvp",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                }
                            ],
                        ),
                    },
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "changes": [
                                {
                                    "record": {
                                        "type": "A",
                                        "name": "moonlite.rsvp",
                                        "value": "76.76.21.21",
                                    }
                                },
                                {
                                    "record": {
                                        "type": "MX",
                                        "name": "send.moonlite.rsvp",
                                        "value": "feedback-smtp.us-east-1.amazonses.com",
                                    }
                                },
                            ],
                        },
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.resend_dns_flow")
    assert receipt_check.status == "ok"
    assert "deterministic sending-domain contract" in receipt_check.detail


def test_live_acceptance_rejects_incomplete_resend_receipt_dns_records(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    incomplete_record = {
        "type": "MX",
        "name": "send.moonlite.rsvp",
        "value": "",
    }
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[incomplete_record],
                        ),
                    },
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "changes": [{"record": incomplete_record}],
                        },
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.resend_dns_flow")
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "Receipt does not include Resend-generated DNS records" in receipt_check.detail
    assert "Resend DNS records in receipt DNS proposal" in report.missing


def test_live_acceptance_requires_resend_dns_proposal_for_same_domain(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    resend_record = {
        "type": "MX",
        "name": "send.moonlite.rsvp",
        "value": "feedback-smtp.us-east-1.amazonses.com",
    }
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[resend_record],
                        ),
                    },
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "other.example",
                            "changes": [{"record": resend_record}],
                        },
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(check for check in report.checks if check.id == "receipt.resend_dns_flow")
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "dns.propose action for moonlite.rsvp" in receipt_check.detail


def test_live_acceptance_requires_dns_apply_launcher_approval(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[
                                {
                                    "type": "MX",
                                    "name": "send.moonlite.rsvp",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                }
                            ],
                        ),
                    },
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "changes": [
                                {
                                    "record": {
                                        "type": "MX",
                                        "name": "send.moonlite.rsvp",
                                        "value": "feedback-smtp.us-east-1.amazonses.com",
                                    }
                                }
                            ],
                        },
                    },
                    {
                        "action": "dns.apply",
                        "status": "ok",
                        "details": {"domain": "moonlite.rsvp", "applied": [{"id": "dns-1"}]},
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    approval_check = next(
        check for check in report.checks if check.id == "receipt.dns_apply_approval"
    )
    assert report.launch_ready is False
    assert approval_check.status == "failed"
    assert "without protected per-domain Approve DNS apply audit proof" in approval_check.detail
    assert "DNS apply approval audit proof" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["DNS apply approval audit proof"]["category"] == "DNS approval"
    assert "Approve DNS apply" in blockers["DNS apply approval audit proof"]["next_action"]


def test_live_acceptance_accepts_dns_apply_launcher_approval(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    dns_resume_wake_id = "wake-dns-approval"
    (remote_fusekit / "audit.jsonl").write_text(
        '{"event":"provider.verify"}\n'
        + json.dumps(_dns_apply_approval_event(wake_event_id=dns_resume_wake_id), sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (remote_fusekit / "gate_events.jsonl").write_text(
        json.dumps(
            _gate_wake_event(
                dns_resume_wake_id,
                "resume_requested",
                "dns.moonlite.rsvp.approval",
                provider="dns",
                classification="dns-approval",
            ),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[
                                {
                                    "type": "MX",
                                    "name": "send.moonlite.rsvp",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                }
                            ],
                        ),
                    },
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "changes": [
                                {
                                    "record": {
                                        "type": "MX",
                                        "name": "send.moonlite.rsvp",
                                        "value": "feedback-smtp.us-east-1.amazonses.com",
                                    }
                                }
                            ],
                        },
                    },
                    {
                        "action": "dns.apply",
                        "status": "ok",
                        "details": {"domain": "moonlite.rsvp", "applied": [{"id": "dns-1"}]},
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    approval_check = next(
        check for check in report.checks if check.id == "receipt.dns_apply_approval"
    )
    assert approval_check.status == "ok"
    assert "protected Approve DNS apply audit proof" in approval_check.detail


def test_live_acceptance_requires_dns_apply_approval_for_each_applied_domain(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_cloudflare_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_live_artifacts(remote_fusekit)
    (remote_fusekit / "audit.jsonl").write_text(
        '{"event":"provider.verify"}\n'
        + json.dumps(_dns_apply_approval_event("moonlite.rsvp"), sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": _resend_domain_receipt_details(
                            dns_records=[
                                {
                                    "type": "MX",
                                    "name": "send.moonlite.rsvp",
                                    "value": "feedback-smtp.us-east-1.amazonses.com",
                                }
                            ],
                        ),
                    },
                    {
                        "action": "dns.propose",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "changes": [
                                {
                                    "record": {
                                        "type": "MX",
                                        "name": "send.moonlite.rsvp",
                                        "value": "feedback-smtp.us-east-1.amazonses.com",
                                    }
                                }
                            ],
                        },
                    },
                    {
                        "action": "dns.apply",
                        "status": "ok",
                        "details": {"domain": "moonlite.rsvp", "applied": [{"id": "dns-1"}]},
                    },
                    {
                        "action": "dns.apply",
                        "status": "ok",
                        "details": {
                            "domain": "api.moonlite.rsvp",
                            "applied": [{"id": "dns-2"}],
                        },
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    approval_check = next(
        check for check in report.checks if check.id == "receipt.dns_apply_approval"
    )
    assert report.launch_ready is False
    assert approval_check.status == "failed"
    assert "api.moonlite.rsvp" in approval_check.detail
    assert "DNS apply approval audit proof" in report.missing


def test_live_acceptance_requires_receipt_resend_runtime_env_in_vercel(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "generated_env": ["RESEND_FROM_EMAIL"],
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.resend_vercel_env"
    )
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "RESEND_FROM_EMAIL" in receipt_check.detail
    assert "Resend runtime env in Vercel receipt" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["Resend runtime env in Vercel receipt"]["category"] == "Deployment env"
    assert (
        "Capture RESEND_API_KEY in the launcher"
        in blockers["Resend runtime env in Vercel receipt"]["next_action"]
    )
    assert (
        "Resend domain/audience values by API"
        in blockers["Resend runtime env in Vercel receipt"]["next_action"]
    )
    assert (
        "captures or generates those values"
        not in blockers["Resend runtime env in Vercel receipt"]["next_action"]
    )
    assert (
        "Capture or generate the required RESEND_* values"
        not in blockers["Resend runtime env in Vercel receipt"]["next_action"]
    )
    assert (
        "Capture RESEND_API_KEY in the launcher"
        in blockers["receipt.resend_vercel_env"]["next_action"]
    )
    assert (
        "Resend domain/audience values by API"
        in blockers["receipt.resend_vercel_env"]["next_action"]
    )
    assert (
        "Capture or generate the required RESEND_* values"
        not in blockers["receipt.resend_vercel_env"]["next_action"]
    )


def test_live_acceptance_requires_receipt_resend_generated_env_proof_before_vercel(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.resend_vercel_env"
    )
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "prior Resend API-generated runtime proof" in receipt_check.detail
    assert "RESEND_FROM_EMAIL" in receipt_check.detail


def test_live_acceptance_requires_resend_generation_before_vercel_env_write(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "generated_env": ["RESEND_FROM_EMAIL"],
                            "dns_records": [],
                        },
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.resend_vercel_env"
    )
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "prior Resend API-generated runtime proof" in receipt_check.detail
    assert "RESEND_FROM_EMAIL" in receipt_check.detail


def test_live_acceptance_requires_resend_audience_before_vercel_env_write(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_audience_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "generated_env": ["RESEND_FROM_EMAIL"],
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_AUDIENCE_ID"},
                    },
                    {
                        "action": "resend.audience",
                        "status": "ok",
                        "details": {
                            "name": "Moonlite RSVP audience",
                            "generated_env": ["RESEND_AUDIENCE_ID"],
                        },
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.resend_vercel_env"
    )
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "prior Resend API-generated runtime proof" in receipt_check.detail
    assert "RESEND_AUDIENCE_ID" in receipt_check.detail


def test_live_acceptance_accepts_resend_audience_before_vercel_env_write(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_audience_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "generated_env": ["RESEND_FROM_EMAIL"],
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "resend.audience",
                        "status": "ok",
                        "details": {
                            "name": "Moonlite RSVP audience",
                            "generated_env": ["RESEND_AUDIENCE_ID"],
                        },
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_AUDIENCE_ID"},
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.resend_vercel_env"
    )
    assert receipt_check.status == "ok"
    assert "Resend-owned runtime env keys were generated before Vercel setup" in (
        receipt_check.detail
    )


def test_live_acceptance_accepts_receipt_resend_runtime_env_in_vercel(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "generated_env": ["RESEND_FROM_EMAIL"],
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.resend_vercel_env"
    )
    assert receipt_check.status == "ok"
    assert "Resend-owned runtime env keys were generated before Vercel setup" in (
        receipt_check.detail
    )


def test_live_acceptance_requires_provider_contract_health_before_api_setup(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "generated_env": ["RESEND_FROM_EMAIL"],
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                    _provider_pack_api_setup_action("vercel", "vercel-env"),
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.provider_contract_health"
    )
    assert report.launch_ready is False
    assert receipt_check.status == "failed"
    assert "vercel" in receipt_check.detail
    assert "provider contract-health receipt proof" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["provider contract-health receipt proof"]["category"] == "Provider routes"
    assert (
        "read-only provider health check before mutation"
        in blockers["provider contract-health receipt proof"]["next_action"]
    )
    assert (
        "exact env-named Capture button"
        in blockers["provider contract-health receipt proof"]["next_action"]
    )


def test_live_acceptance_accepts_provider_contract_health_before_api_setup(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "resend.domain",
                        "status": "ok",
                        "details": {
                            "domain": "moonlite.rsvp",
                            "generated_env": ["RESEND_FROM_EMAIL"],
                            "dns_records": [],
                        },
                    },
                    {
                        "action": "vercel.contract_health",
                        "status": "ok",
                        "details": {"provider": "vercel", "checked": True},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_API_KEY"},
                    },
                    {
                        "action": "vercel.env",
                        "status": "ok",
                        "details": {"project": "moonlite", "env": "RESEND_FROM_EMAIL"},
                    },
                    _provider_pack_api_setup_action("vercel", "vercel-env"),
                ],
                "raw_secrets_exposed": 0,
                "live_url": "https://moonlite.rsvp",
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    receipt_check = next(
        check for check in report.checks if check.id == "receipt.provider_contract_health"
    )
    assert receipt_check.status == "ok"
    assert "provider API contract health before token-backed setup" in receipt_check.detail


def test_live_acceptance_requires_complete_provider_strategy_evidence(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": {"selected": {"kind": "api"}},
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    strategy_check = next(
        check for check in report.checks if check.id == "provider_strategies.complete"
    )
    assert report.launch_ready is False
    assert strategy_check.status == "failed"
    assert "selected.status is missing" in strategy_check.detail
    assert "complete provider strategy evidence" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    next_action = blockers["complete provider strategy evidence"]["next_action"]
    assert "live launcher/control room" in next_action
    assert "selected provider route" in next_action
    assert "fallback candidates" in next_action
    assert "Record selected-route" not in next_action


def test_live_acceptance_rejects_loose_provider_strategy_artifact_shape(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    strategies = _run_record_provider_strategies()
    strategies["private_note"] = "sidecar"
    providers = strategies["providers"]
    assert isinstance(providers, list)
    first_provider = providers[0]
    assert isinstance(first_provider, dict)
    first_provider["private_note"] = "sidecar"
    strategy_rows = first_provider["strategies"]
    assert isinstance(strategy_rows, list)
    first_strategy = strategy_rows[0]
    assert isinstance(first_strategy, dict)
    first_strategy["private_note"] = "sidecar"
    first_strategy["recipe"] = f" {first_strategy['recipe']} "
    decision = first_strategy["decision"]
    assert isinstance(decision, dict)
    decision["private_note"] = "sidecar"
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(strategies),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    strategy_check = next(
        check for check in report.checks if check.id == "provider_strategies.complete"
    )
    assert report.launch_ready is False
    assert strategy_check.status == "failed"
    assert "provider_strategies has unexpected fields: private_note" in strategy_check.detail
    assert (
        "provider_strategies.providers[0].strategies[0].recipe must not have "
        "surrounding whitespace"
        in strategy_check.detail
    )
    assert "complete provider strategy evidence" in report.missing


def test_live_acceptance_requires_guided_human_provider_strategy(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-deploy-key",
                                "strategy": "browser_guided",
                                "status": "needs_human_gate",
                                "decision": {
                                    "selected": {
                                        "kind": "browser_guided",
                                        "status": "available",
                                        "deterministic": False,
                                        "implemented": False,
                                        "reason": "Provider token is missing.",
                                    },
                                    "candidates": [
                                        {
                                            "kind": "browser_guided",
                                            "status": "available",
                                        }
                                    ],
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    strategy_check = next(
        check for check in report.checks if check.id == "provider_strategies.complete"
    )
    assert report.launch_ready is False
    assert strategy_check.status == "failed"
    assert "github.strategies[0].follow_steps is missing" in strategy_check.detail
    assert "github.strategies[0].next_action is missing" in strategy_check.detail
    assert "github.strategies[0].resume_hint is missing" in strategy_check.detail
    assert "github.strategies[0].success_criteria is missing" in strategy_check.detail
    assert "github.strategies[0].avoid_steps is missing" in strategy_check.detail
    assert "complete provider strategy evidence" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    next_action = blockers["complete provider strategy evidence"]["next_action"]
    assert "live launcher/control room" in next_action
    assert "selected provider route" in next_action
    assert "Record selected-route" not in next_action


def test_live_acceptance_requires_strategy_coverage_for_manifest_providers(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.domain", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "provider_strategies.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "cloudflare" in coverage_check.detail
    assert "complete provider strategy coverage" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["complete provider strategy coverage"]["category"] == "Provider routes"
    next_action = blockers["complete provider strategy coverage"]["next_action"]
    assert "live launcher/control room" in next_action
    assert "every manifest provider has provider-route proof" in next_action
    assert "Record provider strategy evidence" not in next_action


def test_live_acceptance_requires_verification_coverage_for_manifest_providers(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "resend",
                        "check": "domain_verified",
                        "status": "passed",
                    }
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.dns", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "verification_report.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "cloudflare" in coverage_check.detail
    assert "complete provider verification coverage" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["complete provider verification coverage"]["category"] == "Verification"
    next_action = blockers["complete provider verification coverage"]["next_action"]
    assert "Let FuseKit verify every provider declared by the manifest" in next_action
    assert "Record verification checks" not in next_action


def test_live_acceptance_does_not_count_skipped_verification_coverage(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    report_path = remote_fusekit / "verification_report.json"
    report_payload = json.loads(report_path.read_text(encoding="utf-8"))
    vercel = next(
        check
        for check in report_payload["checks"]
        if check["provider"] == "vercel"
    )
    vercel["status"] = "skipped"
    report_path.write_text(json.dumps(report_payload), "utf-8")
    _write_minimum_run_record(remote_fusekit)

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "verification_report.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "vercel" in coverage_check.detail
    assert "complete provider verification coverage" in report.missing


def test_live_acceptance_rejects_job_checkpoint_run_record_timeline_drift(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)

    run_record_path = remote_fusekit / "run_record.json"
    run_record = json.loads(run_record_path.read_text(encoding="utf-8"))
    run_record["steps"].append(
        {
            "id": "detonate.workspace",
            "label": "Detonate runner workspace",
            "status": "pending",
        }
    )
    run_record["checkpoints"].append(
        {
            "id": "detonate.workspace",
            "label": "Detonate runner workspace",
            "status": "pending",
        }
    )
    run_record_path.write_text(json.dumps(run_record), encoding="utf-8")

    job_path = remote_fusekit / "job.json"
    job = json.loads(job_path.read_text(encoding="utf-8"))
    final_step = {
        "id": "detonate.workspace",
        "label": "Detonate runner workspace",
        "status": "done",
        "detail": "remote worker and OCI workspace detonated",
        "updated_at": 3.0,
    }
    final_checkpoint = {
        "id": "detonate.workspace",
        "label": "Detonate runner workspace",
        "status": "done",
        "detail": "remote worker and OCI workspace detonated",
        "next_action": "Review the redacted survivor bundle.",
        "resume_hint": "The disposable worker is gone.",
        "mascot_state": "complete",
        "updated_at": 3.0,
    }
    job["steps"] = [final_step]
    job["checkpoints"] = [final_checkpoint]
    job_path.write_text(json.dumps(job), encoding="utf-8")
    (remote_fusekit / "checkpoints.json").write_text(
        json.dumps(
            {
                "job_id": "fk-live-test",
                "status": "done",
                "updated_at": 3.0,
                "checkpoints": [final_checkpoint],
            }
        ),
        encoding="utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    run_record_check = next(
        check for check in report.checks if check.id == "run_record.complete"
    )
    assert report.launch_ready is False
    assert run_record_check.status == "failed"
    assert "job.json steps.detonate.workspace status must match Run Record" in (
        run_record_check.detail
    )
    assert (
        "checkpoints.json checkpoints.detonate.workspace status must match Run Record"
        in run_record_check.detail
    )


def test_live_acceptance_requires_rollback_coverage_for_manifest_providers(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "fusekit.yaml").write_text(
        """
app_name: app
app_path: .
required_env: []
webhooks: []
approvals: []
services:
  - provider: resend
    kind: email
    name: email
    capabilities: []
    secrets: []
    settings: {}
domains:
  - domain: moonlite.rsvp
    provider: cloudflare
    records: []
""".strip()
        + "\n",
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "resend",
                        "check": "domain_verified",
                        "status": "passed",
                    },
                    {
                        "provider": "cloudflare",
                        "check": "dns_record_exists",
                        "status": "passed",
                    },
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.domain", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _resend_domain_strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(json.dumps({"gates": []}), "utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "rollback_metadata.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "cloudflare" in coverage_check.detail
    assert "complete rollback coverage" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["complete rollback coverage"]["category"] == "Rollback"
    next_action = blockers["complete rollback coverage"]["next_action"]
    assert (
        "Let FuseKit write rollback actions for every provider declared by the manifest"
        in next_action
    )
    assert "Record rollback metadata" not in next_action


def test_live_acceptance_does_not_count_skipped_rollback_coverage(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    rollback_path = remote_fusekit / "rollback_plan.json"
    rollback = json.loads(rollback_path.read_text(encoding="utf-8"))
    vercel = next(
        action
        for action in rollback["rollback"]
        if action["action"] == "rollback.vercel.env"
    )
    vercel["status"] = "skipped"
    vercel["detail"] = "missing project or env"
    rollback_path.write_text(json.dumps(rollback), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    coverage_check = next(
        check for check in report.checks if check.id == "rollback_metadata.coverage"
    )
    assert report.launch_ready is False
    assert coverage_check.status == "failed"
    assert "vercel" in coverage_check.detail
    assert "complete rollback coverage" in report.missing


def test_live_acceptance_rejects_rollback_callback_url_artifact(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    rollback_path = remote_fusekit / "rollback_plan.json"
    rollback = json.loads(rollback_path.read_text(encoding="utf-8"))
    rollback["rollback"].append(
        {
            "action": "rollback.github.oauth",
            "status": "planned after https://provider.example/callback",
        }
    )
    rollback_path.write_text(json.dumps(rollback), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    rollback_check = next(
        check for check in report.checks if check.id == "rollback_metadata.actionable"
    )
    assert report.launch_ready is False
    assert rollback_check.status == "failed"
    assert "rollback_metadata.rollback[2].status contains callback URL" in rollback_check.detail
    assert "rollback metadata" in report.missing


def test_live_acceptance_rejects_loose_rollback_metadata_shape(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    _write_resend_vercel_manifest(app)
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    _write_minimum_resend_vercel_live_artifacts(remote_fusekit)
    rollback_path = remote_fusekit / "rollback_plan.json"
    rollback = json.loads(rollback_path.read_text(encoding="utf-8"))
    rollback["private_note"] = "sidecar"
    first = rollback["rollback"][0]
    assert isinstance(first, dict)
    first["private_note"] = "sidecar"
    first["action"] = f" {first['action']} "
    rollback_path.write_text(json.dumps(rollback), encoding="utf-8")

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    rollback_check = next(
        check for check in report.checks if check.id == "rollback_metadata.actionable"
    )
    assert report.launch_ready is False
    assert rollback_check.status == "failed"
    assert "rollback_metadata has unexpected fields: private_note" in rollback_check.detail
    assert (
        "rollback_metadata.rollback[0] has unexpected fields: private_note"
        in rollback_check.detail
    )
    assert (
        "rollback_metadata.rollback[0].action must not have surrounding whitespace"
        in rollback_check.detail
    )
    assert "rollback metadata" in report.missing


def test_live_acceptance_requires_guided_control_room_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.github.authorization",
                        "provider": "github",
                        "reason": "GitHub token captured",
                        "status": "passed",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    guided_check = next(check for check in report.checks if check.id == "gates.guided")
    assert report.launch_ready is False
    assert guided_check.status == "failed"
    assert (
        "provider.github.authorization missing next_action, resume_hint, follow_steps, "
        "resume_url, success_criteria, avoid_steps" in guided_check.detail
    )
    assert "guided human gates" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    next_action = blockers["guided human gates"]["next_action"]
    assert "live launcher/control room" in next_action
    assert "follow-me steps, next action, and resume hint" in next_action
    assert "Regenerate gate state" not in next_action


def test_live_acceptance_requires_audited_control_room_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.github.secret", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.github.authorization",
                        "provider": "github",
                        "reason": "GitHub token captured",
                        "status": "passed",
                        "follow_steps": ["Copy the GitHub token in the VM browser."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "provider.github.authorization" in audit_check.detail
    assert "audited human gate interventions" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    assert blockers["audited human gate interventions"]["category"] == "Human gates"
    assert (
        "click the visible I finished this step"
        in blockers["audited human gate interventions"]["next_action"]
    )
    assert (
        "Open provider gate in VM"
        not in blockers["audited human gate interventions"]["next_action"]
    )
    assert (
        "exact env-named Capture buttons"
        not in blockers["audited human gate interventions"]["next_action"]
    )


def test_live_acceptance_requires_clipboard_capture_for_secret_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.clipboard_capture",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "target": "OPENAI_API_KEY",
                            "record_id": "provider.openai.token",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.openai.authorization",
                            "provider": "openai",
                            "status": "resume_requested",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.openai.token", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "openai",
                        "strategies": [
                            {
                                "recipe": "openai-token",
                                "strategy": "control-room-capture",
                                "status": "ok",
                                "decision": _strategy_decision("human", "available"),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.openai.authorization",
                        "provider": "openai",
                        "reason": "OpenAI token captured",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "target": "OPENAI_API_KEY",
                        "captured_targets": ["OPENAI_API_KEY"],
                        "follow_steps": ["Copy OPENAI_API_KEY inside the VM browser."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "control_room.clipboard_capture" in audit_check.detail
    assert "provider.openai.authorization:OPENAI_API_KEY" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_requires_all_multi_value_gate_captures(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.clipboard_capture",
                        "data": {
                            "gate_id": "provider.resend.runtime-values",
                            "provider": "resend",
                            "target": "RESEND_AUDIENCE_ID",
                            "record_id": "app.resend.resend_audience_id",
                            "source": "vm-clipboard",
                            "storage": "encrypted-vault",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.resend.runtime-values",
                            "provider": "resend",
                            "status": "resume_requested",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.resend.env", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-runtime-values",
                                "strategy": "control-room-capture",
                                "status": "ok",
                                "decision": _strategy_decision("human", "available"),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.resend.runtime-values",
                        "provider": "resend",
                        "reason": "Resend runtime values captured",
                        "status": "passed",
                        "classification": "provider-runtime-values",
                        "target": "RESEND_AUDIENCE_ID,RESEND_FROM_EMAIL",
                        "captured_targets": ["RESEND_AUDIENCE_ID"],
                        "follow_steps": ["Copy each Resend value inside the VM browser."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "provider.resend.runtime-values:RESEND_FROM_EMAIL" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_requires_provider_gate_open_audit(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_open",
                        "data": {
                            "gate_id": "provider.cloudflare.authorization",
                            "provider": "cloudflare",
                            "reused": False,
                            "status": "waiting",
                        },
                    },
                    sort_keys=True,
                ),
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.cloudflare.authorization",
                            "provider": "cloudflare",
                            "status": "resume_requested",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.dns", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns-records",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.cloudflare.authorization",
                        "provider": "cloudflare",
                        "reason": "Cloudflare authorization complete",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "resume_url": "https://dash.cloudflare.com/profile/api-tokens",
                        "follow_steps": [
                            (
                                "Click Open provider gate in VM so Cloudflare opens "
                                "in the VM browser."
                            )
                        ],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "control_room.gate_open" in audit_check.detail
    assert "provider.cloudflare.authorization" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_requires_concrete_finished_click_audit(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "provider.cloudflare.authorization",
                            "provider": "cloudflare",
                            "status": "passed",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.cloudflare.auth", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-authorization",
                                "strategy": "human_follow_me",
                                "status": "ok",
                                "decision": _strategy_decision("human", "available"),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.cloudflare.authorization",
                        "provider": "cloudflare",
                        "reason": "Cloudflare authorization complete",
                        "status": "passed",
                        "classification": "provider-authorization",
                        "follow_steps": ["Approve the visible Cloudflare authorization."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "control_room.gate_resume_requested" in audit_check.detail
    assert "provider.cloudflare.authorization" in audit_check.detail
    assert "audited human gate interventions" in report.missing


def test_live_acceptance_rejects_malformed_gate_audit_event(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text(
        "\n".join(
            [
                '{"event":"provider.verify"}',
                json.dumps(
                    {
                        "event": "control_room.gate_resume_requested",
                        "data": {
                            "gate_id": "custom.review",
                            "provider": "custom",
                            "status": "passed",
                        },
                    },
                    sort_keys=True,
                ),
            ]
        )
        + "\n",
        "utf-8",
    )
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.custom.review", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps({"schema_version": "fusekit.provider-strategies.v1", "providers": []}),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "custom.review",
                        "provider": "custom",
                        "reason": "Custom review gate complete",
                        "status": "passed",
                        "classification": "review",
                        "follow_steps": ["Review the custom provider result in the VM browser."],
                        "next_action": "No action needed.",
                        "resume_hint": "FuseKit verified this gate as passed.",
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    audit_check = next(check for check in report.checks if check.id == "gates.audited")
    assert report.launch_ready is False
    assert audit_check.status == "failed"
    assert "missing gate events: custom.review" in audit_check.detail
    assert "audited human gate interventions" in report.missing
    blockers = {blocker["item"]: blocker for blocker in report.blockers}
    next_action = blockers["audited human gate interventions"]["next_action"]
    assert "Open provider gate in VM" in next_action
    assert "exact env-named Capture buttons" in next_action
    assert "Capture RESEND_API_KEY from VM clipboard" not in next_action
    assert "I finished this step" in next_action


def test_live_acceptance_requires_resolved_control_room_gates(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text(
        json.dumps({"name": "moonlite-rsvp", "dependencies": {"next": "latest"}}),
        encoding="utf-8",
    )
    remote = tmp_path / "remote-artifacts"
    remote_fusekit = remote / ".fusekit"
    remote_fusekit.mkdir(parents=True)
    vault = Vault.empty()
    vault.save(remote_fusekit / "fusekit.vault.json", "passphrase")
    (remote_fusekit / "audit.jsonl").write_text('{"event":"provider.verify"}\n', "utf-8")
    (remote_fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "live_url": "https://moonlite.example",
                "raw_secrets_exposed": 0,
                "actions": [],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "live_app", "check": "health", "status": "passed"}]}),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps({"rollback": [{"action": "rollback.vercel.env", "status": "planned"}]}),
        "utf-8",
    )
    (remote_fusekit / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-repo-secrets",
                                "strategy": "api",
                                "status": "ok",
                                "decision": _strategy_decision(),
                            }
                        ],
                    }
                ],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "gates.json").write_text(
        json.dumps(
            {
                "gates": [
                    {
                        "id": "provider.cloudflare.authorization",
                        "provider": "cloudflare",
                        "reason": "Cloudflare token creation",
                        "status": "waiting",
                        "classification": "provider-authorization",
                        "resume_url": "https://dash.cloudflare.com/profile/api-tokens",
                        "follow_steps": [
                            (
                                "Click Open provider gate in VM so Cloudflare opens "
                                "in the VM browser."
                            )
                        ],
                        "next_action": "Finish Cloudflare login in the VM browser.",
                        "resume_hint": "FuseKit will retry verification after resume.",
                        **_gate_guidance_fields("cloudflare"),
                    }
                ]
            }
        ),
        "utf-8",
    )

    report = run_acceptance(
        app,
        mode="live",
        passphrase="passphrase",
        remote_artifacts_path=remote,
    )

    gate_check = next(check for check in report.checks if check.id == "gates.resolved")
    assert report.launch_ready is False
    assert gate_check.status == "failed"
    assert "provider.cloudflare.authorization:waiting" in gate_check.detail
    assert "resolved human gates" in report.missing
