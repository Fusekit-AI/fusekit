from __future__ import annotations

import json
from pathlib import Path

from fusekit.cli import main
from fusekit.harness import run_acceptance
from fusekit.harness.acceptance import (
    AcceptanceCheck,
    AcceptanceReport,
    _acceptance_blockers,
    _check_detonation,
    _check_runner_readiness,
    _check_visual_state,
    _gate_capture_audit_event_proves_vault_capture,
    _gate_open_audit_event_proves_vm_open,
    _gate_resume_audit_event_proves_finished_click,
    _gate_resume_audit_requirements,
    _provider_strategy_checkpoint_failures,
    _provider_strategy_shape_failures,
    _rollback_provider_names,
    _run_record_shape_failures,
    _unguided_gates,
)
from fusekit.harness.ledger import HarnessLedger
from fusekit.runner.gate_guidance import provider_gate_guidance
from fusekit.runner.gates import GateService
from fusekit.runner.remote import remote_worker_cleanup_proof
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


def _provider_playbook() -> dict[str, object]:
    return {
        "schema_version": "fusekit.provider-playbook.v1",
        "steps": [
            {
                "id": "resend.capture_key",
                "provider": "resend",
                "route": "browser_guided",
                "control": "Capture RESEND_API_KEY from VM clipboard",
                "instruction": (
                    "Capture RESEND_API_KEY from VM clipboard if the Resend API route "
                    "is not already authorized."
                ),
            },
            {
                "id": "resend.domain_api",
                "provider": "resend",
                "route": "api",
                "control": "FuseKit API worker",
                "instruction": (
                    "FuseKit creates or reuses the Resend sending domain through the Resend API."
                ),
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
        ],
    }


def _workspace_detonation_receipt() -> dict[str, object]:
    return {
        "status": "complete",
        "reason": "remote worker and OCI workspace detonated",
        "deleted": [
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
            "missing": [],
            "statement": (
                "FuseKit detonation must remove the remote worker process state, "
                "terminate the OCI VM, and delete FuseKit-created network resources."
            ),
        },
        "updated_at": 2.0,
    }


def _durable_state() -> dict[str, object]:
    return {
        "schema_version": "fusekit.durable-state.v1",
        "resume_ready": True,
        "missing": [],
        "sources": [
            {
                "id": "encrypted_vault",
                "path": "fusekit.vault.json",
                "role": "encrypted capability vault",
                "secret_class": "encrypted",
                "exists": True,
            },
            {
                "id": "job_state",
                "path": "job.json",
                "role": "runner job state",
                "secret_class": "non-secret",
                "exists": True,
            },
            {
                "id": "run_state",
                "path": "run_state.json",
                "role": "launch state contract",
                "secret_class": "non-secret",
                "exists": True,
            },
            {
                "id": "checkpoints",
                "path": "checkpoints.json",
                "role": "resume checkpoints",
                "secret_class": "non-secret",
                "exists": True,
            },
            {
                "id": "gates",
                "path": "gates.json",
                "role": "provider gate state",
                "secret_class": "non-secret",
                "exists": True,
            },
            {
                "id": "gate_events",
                "path": "gate_events.jsonl",
                "role": "evented resume wake proof",
                "secret_class": "non-secret",
                "exists": True,
            },
            {
                "id": "provider_strategies",
                "path": "provider_strategies.json",
                "role": "provider route decisions",
                "secret_class": "non-secret",
                "exists": True,
            },
            {
                "id": "runner_readiness",
                "path": "runner_readiness.json",
                "role": "runner profile readiness proof",
                "secret_class": "non-secret",
                "exists": True,
            },
            {
                "id": "workspace_detonation",
                "path": "workspace_detonation.json",
                "role": "OCI detonation receipt",
                "secret_class": "non-secret",
                "exists": True,
            },
        ],
        "volatile_worker_surfaces": ["worker", "visual", "openclaw-state"],
        "detonation_preserves": ["encrypted_vault", "workspace_detonation", "run_record"],
        "detonation_scope": {
            "schema_version": "fusekit.detonation-scope.v1",
            "mode": "worker-and-oci-workspace",
            "must_delete": [
                "worker",
                "visual",
                "openclaw-state",
                "browser-profile",
                "provider-auth",
                "passphrase",
                "app.tar.gz",
                "control-room.log",
                "openclaw-gateway.log",
            ],
            "must_preserve": [
                "encrypted_vault",
                "workspace_detonation",
                "run_record",
            ],
            "resume_until_complete": True,
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
            "resume_sources": [
                "encrypted_vault",
                "job_state",
                "run_state",
                "checkpoints",
                "gates",
                "gate_events",
                "provider_strategies",
                "runner_readiness",
            ],
            "runner_profile_failures": [],
            "volatile_surfaces": ["worker", "visual", "openclaw-state"],
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
    return {
        "schema_version": "fusekit.verifier-summary.v1",
        "overall": "passed",
        "all_passed_or_pending_safe": True,
        "counts": {
            "passed": 1,
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
                "provider": "live_app",
                "check": "live_url_healthy",
                "status": "passed",
                "pending_safe": False,
            },
            {
                "provider": "cloudflare",
                "check": "dns_propagated",
                "status": "pending_safe",
                "pending_safe": True,
            },
        ],
        "statement": (
            "Live provider verifiers are summarized as green checks or pending-safe "
            "checks before launch readiness is trusted."
        ),
    }


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
            "human_actions": True,
            "automation_boundary": True,
            "verifiers": True,
            "audit_trail": True,
            "evidence": True,
            "detonation": True,
            "errors_empty": True,
        },
        "blockers": [],
        "statement": (
            "A public demo is recordable only when durable OCI state, worker "
            "replacement from encrypted/redacted sources, ordered provider "
            "playbooks, guided human actions, live provider verifiers, and "
            "no-trace detonation all agree."
        ),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
    _write_runner_readiness(remote_fusekit)
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
                "novnc_url": "http://93.184.216.34:6080/vnc.html?autoconnect=1",
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
                "app_path": "/var/lib/fusekit-runner/app",
                "runner": "local",
                "created_at": 1.0,
                "updated_at": 2.0,
                "state": {
                    "app_repo_known": True,
                    "runner_selected": True,
                    "vault_created": True,
                    "detonation_safe": True,
                    "workspace_detonated": True,
                },
                "steps": [],
                "checkpoints": [],
                "provider_gates": {
                    "total": 0,
                    "statuses": {},
                    "providers": [],
                    "records": [],
                },
                "durable_state": _durable_state(),
                "provider_playbook": _provider_playbook(),
                "runner_profile": _runner_profile_from_readiness_fixture(fusekit_dir),
                "wake_events": _wake_event_summary_fixture(fusekit_dir),
                "human_actions": _human_action_trace(),
                "automation_boundary": _automation_boundary(),
                "verifiers": _verifier_summary_from_report(fusekit_dir),
                "provider_strategies": _run_record_provider_strategies(fusekit_dir),
                "vault": {"record_count": 0, "records": []},
                "audit_trail": _audit_trail_from_gate_events(fusekit_dir),
                "recording_contract": _recording_contract(),
                "artifacts": [],
                "evidence": _evidence_inventory(),
                "verification": {
                    "checks": [
                        {"provider": "live_app", "status": "passed"},
                        {
                            "provider": "cloudflare",
                            "status": "pending",
                            "details": {"pending_safe": True},
                        },
                    ]
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
        json.dumps(
            {
                "checks": [
                    {"provider": "resend", "status": "passed"},
                    {"provider": "vercel", "status": "passed"},
                    {"provider": "live_app", "status": "passed"},
                ]
            }
        ),
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
    _write_runner_readiness(remote_fusekit)
    _write_safe_visual_state(remote_fusekit)
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
    )

    payload = report.to_dict()
    text = json.dumps(payload)

    assert str(tmp_path) not in text
    assert payload["app_path"] == "app"
    assert payload["public_launch_ready"] is False
    assert payload["recording_proof_ready"] is False
    assert payload["recording_ready"] is False
    assert payload["ledger_path"] == ".fusekit/acceptance/ledger.jsonl"
    assert payload["report_path"] == ".fusekit/acceptance/report.json"
    assert payload["checks"][0]["artifact"] == ".fusekit/acceptance/artifacts/gates.json"


def test_acceptance_report_names_recording_readiness_contract(tmp_path) -> None:
    app = tmp_path / "app"
    live_report = AcceptanceReport(
        mode="live",
        app_path=str(app),
        launch_ready=True,
        checks=(AcceptanceCheck("run_record.complete", "ok", "Run Record complete."),),
        ledger_path=str(app / ".fusekit" / "acceptance" / "ledger.jsonl"),
        report_path=str(app / ".fusekit" / "acceptance" / "report.json"),
        recording_proof_ready=True,
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

    assert live_report.public_launch_ready is True
    assert live_report.recording_proof_ready is True
    assert live_report.recording_ready is True
    assert live_report.to_dict()["recording_proof_ready"] is True
    assert live_report.to_dict()["recording_ready"] is True
    assert unproved_live_report.public_launch_ready is True
    assert unproved_live_report.recording_proof_ready is False
    assert unproved_live_report.recording_ready is False
    assert unproved_live_report.to_dict()["recording_ready"] is False
    assert rehearsal_report.public_launch_ready is False
    assert rehearsal_report.recording_ready is False
    assert rehearsal_report.to_dict()["recording_ready"] is False


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
    checks: list[AcceptanceCheck] = []
    missing: list[str] = []

    _check_detonation(fusekit_dir, "live", checks, missing)

    assert checks[-1].id == "detonation.worker_state"
    assert checks[-1].status == "ok"
    assert "browser, visual, and auth scratch" in checks[-1].detail
    assert missing == []


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
    assert "observed memory must be at least 16 GB" in checks[-1].detail
    assert "x86_64_architecture must be true" in checks[-1].detail
    assert "playwright_chromium must be true" in checks[-1].detail
    assert "shared provider browser profile path is required" in checks[-1].detail
    assert "Playwright browser cache path is required" in checks[-1].detail
    assert "prepared runner readiness proof" in missing


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
    assert missing == []


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
                "novnc_url": "http://93.184.216.34:6080/vnc.html?autoconnect=1&resize=scale",
                "control_room_url": f"http://93.184.216.34:8765/?token={control_room_token}",
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
    assert checks[-1].status == "ok"
    assert missing == []
    snapshot = Path(checks[-1].artifact).read_text(encoding="utf-8")
    assert "password=" not in snapshot
    assert "viewer-password" not in snapshot
    assert control_room_token not in snapshot
    assert "[REDACTED sha256:" in snapshot


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
            "novnc_url": "http://93.184.216.34:6080/vnc.html?autoconnect=1",
            "control_room_url": (
                "http://93.184.216.34:8765/?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
            ),
            "novnc_password": "viewer-password",
            "provider_browser_profile": ("/var/lib/fusekit-runner/visual/chrome-provider-profile"),
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
                    "Copy the key inside the VM browser and click "
                    "Capture RESEND_API_KEY from VM clipboard.",
                    "Do not click Add domain or Add audience; FuseKit owns those steps.",
                ],
                "next_action": (
                    "Click Open provider gate in VM, then click "
                    "Capture RESEND_API_KEY from VM clipboard after the key is copied."
                ),
                "resume_hint": (
                    "FuseKit will create or reuse Resend domains and audiences by API "
                    "after RESEND_API_KEY capture."
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
                            "candidates": [{"kind": "browser_guided"}],
                        },
                    }
                ],
            }
        ]
    )

    assert any("non-launcher wording" in item for item in failures)
    assert any("VM browser path" in item for item in failures)
    assert any("Capture from VM clipboard" in item for item in failures)


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
                            "candidates": [{"kind": "browser_guided"}],
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
                            "candidates": [{"kind": "browser_guided"}],
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
                            "candidates": [{"kind": "browser_guided"}],
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
                            "candidates": [{"kind": "browser_guided"}],
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
                            "candidates": [{"kind": "browser_guided"}],
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
                            "candidates": [{"kind": "browser_guided"}],
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
                    "VM browser, then click Capture from VM clipboard."
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
            "gates.resolved",
            "failed",
            "Waiting provider gate still exists: provider.cloudflare.authorization",
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
    assert "I finished this step button" in blockers["gates.resolved"]["next_action"]
    assert "resume button" not in blockers["gates.resolved"]["next_action"]


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
    callback_resume_wake_id = "wake-callback-resume"
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
                            "gate_id": "provider.callback.review",
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
                            "gate_id": "provider.callback.review",
                            "provider": "provider",
                            "protected_action": True,
                            "status": "resume_requested",
                            "wake_event_id": callback_resume_wake_id,
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
                        callback_resume_wake_id,
                        "resume_requested",
                        "provider.callback.review",
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
                "actions": [{"provider": "github", "action": "secret.upsert"}],
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "verification_report.json").write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "github",
                        "check": "repo_secret_exists",
                        "status": "passed",
                    },
                    {
                        "provider": "vercel",
                        "check": "deployment_ready",
                        "status": "passed",
                    },
                    {
                        "provider": "live_app",
                        "check": "live_url_healthy",
                        "status": "passed",
                    },
                ]
            }
        ),
        "utf-8",
    )
    (remote_fusekit / "rollback_plan.json").write_text(
        json.dumps(
            {
                "rollback": [
                    {"action": "rollback.github.secret", "status": "planned"},
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
                        "resume_url": "http://localhost:1455/auth/callback?code=secret-code",
                        "last_opened_url": "https://provider.example/?token=secret-token",
                        **_gate_guidance_fields("openai"),
                    },
                    {
                        "id": "provider.callback.review",
                        "provider": "provider",
                        "reason": "Provider callback reviewed",
                        "status": "passed",
                        "classification": "provider-verification",
                        "target": (
                            "https://provider.example/callback?"
                            "code=abcdefghijklmnopqrstuvwxyz1234567890abcdef&state=ok"
                        ),
                        "attempts": 1,
                        "follow_steps": [
                            (
                                "Click Open provider gate in VM so the provider callback "
                                "opens in the VM browser."
                            ),
                            "Review the highlighted callback.",
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
    _write_minimum_run_record(remote_fusekit)

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
    gates_check = next(check for check in report.checks if check.id == "gates.resolved")
    gates_artifact = gates_check.artifact
    gates_text = Path(gates_artifact).read_text(encoding="utf-8")
    assert "secret-code" not in gates_text
    assert "secret-token" not in gates_text
    assert "abcdefghijklmnopqrstuvwxyz1234567890abcdef" not in gates_text
    assert "code=[redacted]" in gates_text
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
    assert report_json["blockers"] == []
    assert any(check["id"] == "remote_artifacts.loaded" for check in report_json["checks"])


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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
    assert "keep this live control room open" in next_action
    assert "rerun the same live launcher" not in next_action
    assert "checkpoints.json" not in next_action


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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
            "route": "browser_guided",
            "control": "I finished this step",
            "instruction": "Capture RESEND_API_KEY from VM clipboard.",
        },
        {
            "id": "resend.domain_api",
            "provider": "resend",
            "route": "api",
            "control": "Approve DNS apply",
            "instruction": "FuseKit creates or reuses the Resend sending domain by API.",
        },
        {
            "id": "provider.finished_step",
            "provider": "provider",
            "route": "human_follow_me",
            "control": "Continue",
            "instruction": "Finish the provider prompt in the VM browser.",
        },
    ]

    failures = _run_record_shape_failures(record)

    assert "provider_playbook.steps[0].provider is missing" in failures
    assert "provider_playbook.steps[0].control must be an env-named Capture control" in failures
    assert (
        "provider_playbook.steps[0].control must capture RESEND_API_KEY before "
        "Resend API setup" in failures
    )
    assert (
        "provider_playbook.steps[1].control must be FuseKit API worker for api routes" in failures
    )
    assert "provider_playbook.steps[2].control must be a known follow-me control" in failures


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
        "workspace_receipt": {
            "status": "incomplete",
            "deleted": ["subnet"],
            "failures": {"failed.instance": "409 Conflict"},
        },
    }

    failures = _run_record_shape_failures(record)

    assert "state.detonation_safe must be true" in failures
    assert "state.workspace_detonated must be true" in failures
    assert "detonation.preflight_safe must be true" in failures
    assert "detonation.workspace_detonated must be true" in failures
    assert "detonation.workspace_receipt.status must be complete" in failures
    assert "detonation.workspace_receipt.deleted must include instance" in failures
    assert "detonation.workspace_receipt.deleted must include ephemeral public IP" in failures
    assert "detonation.workspace_receipt.failures must be empty" in failures
    assert "detonation.workspace_receipt.reason is missing" in failures
    assert "detonation.workspace_receipt.updated_at is missing" in failures
    assert "detonation.workspace_receipt.resource_summary is missing" in failures


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
        "no_trace_statement": "cleanup ran",
    }

    failures = _run_record_shape_failures(record)

    assert "durable_state.detonation_scope.mode is unsupported" in failures
    assert "durable_state.detonation_scope.must_delete is incomplete" in failures
    assert "durable_state.detonation_scope.must_preserve is incomplete" in failures
    assert "durable_state.detonation_scope.resume_until_complete must be true" in failures
    assert "durable_state.detonation_scope.no_trace_statement is incomplete" in failures


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


def test_acceptance_run_record_requires_coherent_worker_replacement_contract(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["durable_state"]["worker_replacement_contract"]["resume_sources"] = [
        "encrypted_vault",
        "job_state",
        "run_state",
        "checkpoints",
        "gates",
        "gate_events",
        "provider_strategies",
        "runner_readiness",
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

    assert "durable_state.sources[9] preserves volatile worker state: browser-profile" in failures
    assert (
        "durable_state.detonation_preserves must not include volatile worker state: "
        "browser-profile" in failures
    )
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
    assert "evidence.receipts[0].kind is unsupported" in failures
    assert "evidence.counts.screenshots is missing" in failures
    assert "evidence.statement is missing non-secret inventory guidance" in failures


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

    assert "vault.records[0].id is missing" in failures
    assert "vault.records[0].kind is missing" in failures
    assert "vault.records[0].provider is missing" in failures
    assert "vault.records[0].label is missing" in failures
    assert "vault.records[0] exposes a raw value" in failures


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
                "gate_id": "provider.resend.authorization",
                "provider": "resend",
                "classification": "authorization",
                "action": "capture_vm_clipboard",
                "visible_control": "Capture GITHUB_TOKEN from VM clipboard",
                "target": "RESEND_API_KEY",
                "guided": True,
                "created_at": 1.0,
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
    assert "automation_boundary.statement is missing vnc guidance" in failures


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
        "provider_strategies.providers[0].strategies[0].decision.candidates is missing" in failures
    )

    record["provider_strategies"] = {"providers": []}

    failures = _run_record_shape_failures(record)

    assert "provider_strategies.schema_version is unsupported" in failures
    assert "provider_strategies.providers is missing" in failures


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
    record["verification"] = {"checks": [{"provider": "resend", "status": "passed"}]}
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
                "status": "captured",
                "source": "gate_events.jsonl",
                "summary": "token=leaked-value",
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
                "category": "provider_action",
                "action": "provider.retry",
                "provider": "",
                "status": "recorded",
                "source": "audit.jsonl",
                "summary": (
                    "FuseKit recorded audit event provider.retry with secret values redacted."
                ),
            },
        ],
        "statement": "Audit happened.",
    }

    failures = _run_record_shape_failures(record)

    assert "audit_trail.entries[0].summary contains credential-looking text" in failures
    assert "audit_trail.entries[0].wake_event_id is missing" in failures
    assert "audit_trail.entries[1].receipt_action_index is missing" in failures
    assert "audit_trail.entries[2].audit_log_index is missing" in failures
    assert "audit_trail must include dns_write" in failures
    assert "audit_trail must include human_approval" in failures
    assert "audit_trail must include detonation" in failures
    assert "audit_trail.statement is missing audit-first guidance" in failures


def test_acceptance_run_record_requires_recording_contract(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))

    record["recording_contract"] = {
        "schema_version": "fusekit.recording-contract.v0",
        "recording_ready": False,
        "checks": {
            "durable_state": True,
            "worker_replacement": True,
            "runner_profile": True,
            "provider_playbook": True,
            "human_actions": False,
            "automation_boundary": True,
            "verifiers": True,
            "audit_trail": True,
            "evidence": True,
            "detonation": True,
            "errors_empty": True,
        },
        "blockers": ["human_actions"],
        "statement": "ready",
    }

    failures = _run_record_shape_failures(record)

    assert "recording_contract.schema_version is unsupported" in failures
    assert "recording_contract.recording_ready must be true" in failures
    assert "recording_contract.checks.human_actions must be true" in failures
    assert "recording_contract.blockers must be empty: human_actions" in failures
    assert "recording_contract.statement is missing public demo guidance" in failures


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
        "not-an-object",
    ]

    failures = _run_record_shape_failures(record)

    assert "errors[0].id contains credential-looking text" in failures
    assert "errors[0].detail contains credential-looking text" in failures
    assert "errors[1] is not an object" in failures


def test_acceptance_run_record_rejects_unredacted_timeline_entries(tmp_path) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["steps"] = [
        {
            "id": "setup.execute",
            "label": "Run setup worker",
            "status": "failed",
            "detail": "Callback failed at https://provider.example/callback?code=secret",
        }
    ]
    record["checkpoints"] = [
        {
            "id": "setup.execute",
            "label": "Run setup worker",
            "status": "failed",
            "detail": "Bearer abcdefghijklmnopqrstuvwxyz1234567890",
        }
    ]

    failures = _run_record_shape_failures(record)

    assert "steps[0].detail contains credential-looking text" in failures
    assert "checkpoints[0].detail contains credential-looking text" in failures


def test_acceptance_run_record_rejects_nested_unredacted_survivor_values(
    tmp_path,
) -> None:
    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    _write_minimum_run_record(fusekit_dir)
    record = json.loads((fusekit_dir / "run_record.json").read_text(encoding="utf-8"))
    record["provider_strategies"]["providers"][0]["strategies"][0]["decision"]["selected"][
        "evidence"
    ]["debug_token"] = "token=leaked-provider-token"
    record["verification"]["checks"][0]["details"] = {
        "callback": "https://provider.example/callback?code=secret-code"
    }
    record["detonation"]["workspace_receipt"]["failures"] = {
        "cleanup": "Bearer abcdefghijklmnopqrstuvwxyz1234567890"
    }

    failures = _run_record_shape_failures(record)

    assert (
        "run_record.provider_strategies.providers[0].strategies[0].decision."
        "selected.evidence.debug_token contains credential-looking text"
    ) in failures
    assert (
        "run_record.verification.checks[0].details.callback contains credential-looking text"
    ) in failures
    assert (
        "run_record.detonation.workspace_receipt.failures.cleanup contains credential-looking text"
    ) in failures


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

    assert _run_record_shape_failures(record) == []


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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
        json.dumps({"checks": [{"provider": "live_app", "status": "passed"}]}),
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
