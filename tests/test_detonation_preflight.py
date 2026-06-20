from __future__ import annotations

import json
from pathlib import Path

from fusekit.detonation.preflight import (
    run_detonation_preflight,
    verification_report_allows_launch_progress,
    verification_report_failures,
)
from fusekit.runner.control_room.surfaces import public_control_room_security_surface
from fusekit.runner.readiness import (
    EXPECTED_PROVIDER_BROWSER_PROFILE,
    REQUIRED_RUNNER_BINARIES,
)
from fusekit.runner.run_record import (
    DETONATION_PRESERVES,
    DURABLE_STATE_SOURCES,
    OCI_WORKSPACE_DETONATION_SURFACES,
    VOLATILE_WORKER_SURFACES,
    WORKER_REPLACEMENT_SOURCE_IDS,
)
from fusekit.runner.run_state import RUN_STATE_FIELDS
from fusekit.runner.worker_replacement import build_passed_worker_replacement_drill


def _provider_playbook() -> dict[str, object]:
    steps = [
        {
            "id": "github.capture_token",
            "provider": "github",
            "route": "browser_guided",
            "instruction": "Capture the GitHub token from the VM browser.",
            "control": "Capture GITHUB_TOKEN from VM clipboard",
            "actor": "You",
            "human_action_required": True,
            "proof_source": "gate_events.jsonl",
            "resume_event": "clipboard_captured -> resume_requested",
        },
        {
            "id": "resend.capture_key",
            "provider": "resend",
            "route": "browser_guided",
            "instruction": "Capture the Resend API key from the VM browser.",
            "control": "Capture RESEND_API_KEY from VM clipboard",
            "actor": "You",
            "human_action_required": True,
            "proof_source": "gate_events.jsonl",
            "resume_event": "clipboard_captured -> resume_requested",
        },
        {
            "id": "resend.domain_api",
            "provider": "resend",
            "route": "api",
            "instruction": "FuseKit creates or reuses the Resend sending domain by API.",
            "control": "FuseKit API worker",
            "actor": "FuseKit",
            "human_action_required": False,
            "proof_source": "setup_receipt.json",
            "resume_event": "provider_action_recorded",
        },
        {
            "id": "resend.audience_api",
            "provider": "resend",
            "route": "api",
            "instruction": "FuseKit creates or reuses the Resend audience by API.",
            "control": "FuseKit API worker",
            "actor": "FuseKit",
            "human_action_required": False,
            "proof_source": "setup_receipt.json",
            "resume_event": "provider_action_recorded",
        },
        {
            "id": "vercel.env_api",
            "provider": "vercel",
            "route": "api",
            "instruction": "FuseKit writes approved environment variables by API.",
            "control": "FuseKit API worker",
            "actor": "FuseKit",
            "human_action_required": False,
            "proof_source": "setup_receipt.json",
            "resume_event": "provider_action_recorded",
        },
        {
            "id": "dns.approval",
            "provider": "cloudflare",
            "route": "human_follow_me",
            "instruction": "Approve the exact DNS records in the control room.",
            "control": "Approve DNS apply",
            "actor": "You",
            "human_action_required": True,
            "proof_source": "gate_events.jsonl",
            "resume_event": "dns_apply_approved -> resume_requested",
        },
    ]
    return {
        "schema_version": "fusekit.provider-playbook.v1",
        "steps": steps,
        "safety_notes": [
            "Use the VM browser and visible FuseKit controls.",
            "Do not create Resend domains or audiences manually.",
            "Do not paste provider secrets into the host computer.",
        ],
    }


def _verifier_summary() -> dict[str, object]:
    checks = [
        {
            "provider": "github",
            "check": "repo_secret_exists",
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
            "check": "deployment_url_exists",
            "status": "passed",
            "pending_safe": False,
        },
        {
            "provider": "cloudflare",
            "check": "dns_record_exists",
            "status": "passed",
            "pending_safe": False,
        },
        {
            "provider": "live_app",
            "check": "health",
            "status": "passed",
            "pending_safe": False,
        },
    ]
    return {
        "schema_version": "fusekit.verifier-summary.v1",
        "overall": "passed",
        "all_passed_or_pending_safe": True,
        "counts": {
            "passed": len(checks),
            "pending_safe": 0,
            "skipped": 0,
            "pending": 0,
            "repairing": 0,
            "failed": 0,
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
    rows: list[dict[str, object]] = []
    for check in _verifier_summary()["checks"]:
        assert isinstance(check, dict)
        rows.append({key: value for key, value in check.items() if key != "pending_safe"})
    return rows


def _runner_binary_records() -> dict[str, dict[str, object]]:
    return {
        name: {
            "path": f"/usr/local/bin/{name.replace('_', '-')}",
            "present": True,
            "version": "",
        }
        for name in REQUIRED_RUNNER_BINARIES
    }


def _runner_readiness() -> dict[str, object]:
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
                "shared_provider_profile": EXPECTED_PROVIDER_BROWSER_PROFILE,
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
        "provider_browser_profile": EXPECTED_PROVIDER_BROWSER_PROFILE,
        "playwright_browsers_path": "/opt/fusekit-playwright-browsers",
    }


def _visual_state() -> dict[str, object]:
    return {
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
        "provider_browser_profile": EXPECTED_PROVIDER_BROWSER_PROFILE,
        "notes": [
            "The browser is running on the disposable OCI VM.",
            "Use the noVNC window to complete human gates in the same session "
            "FuseKit observes.",
        ],
    }


def _provider_strategies() -> dict[str, object]:
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
                        "decision": {
                            "selected": {
                                "kind": "browser_guided",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "GitHub token is captured through the VM browser.",
                            },
                            "candidates": [
                                {"kind": "browser_guided", "status": "available"}
                            ],
                        },
                        "follow_steps": ["Use the VM browser to create or reveal the token."],
                        "next_action": "Capture GITHUB_TOKEN from VM clipboard",
                        "resume_hint": "FuseKit resumes after the clipboard capture event.",
                        "success_criteria": ["GITHUB_TOKEN was captured into the vault."],
                        "avoid_steps": ["Do not paste provider secrets into the host computer."],
                        "target": "GITHUB_TOKEN",
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
                        "decision": {
                            "selected": {
                                "kind": "api",
                                "status": "available",
                                "deterministic": True,
                                "implemented": True,
                                "reason": "Resend domain setup is provider-native.",
                                "evidence": {
                                    "api_owns": "domain",
                                    "user_manual_domain_step": "false",
                                    "downstream_order": "before_dns_apply",
                                },
                            },
                            "candidates": [{"kind": "api", "status": "available"}],
                        },
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
                        "decision": {
                            "selected": {
                                "kind": "api",
                                "status": "available",
                                "deterministic": True,
                                "implemented": True,
                                "reason": "Vercel env setup is provider-native.",
                            },
                            "candidates": [{"kind": "api", "status": "available"}],
                        },
                    }
                ],
            },
            {
                "provider": "cloudflare",
                "strategies": [
                    {
                        "recipe": "cloudflare-dns",
                        "strategy": "human_follow_me",
                        "status": "needs_human_gate",
                        "decision": {
                            "selected": {
                                "kind": "human_follow_me",
                                "status": "available",
                                "deterministic": False,
                                "implemented": False,
                                "reason": "DNS apply waits for explicit approval.",
                            },
                            "candidates": [
                                {"kind": "human_follow_me", "status": "available"}
                            ],
                        },
                        "follow_steps": ["Review the exact DNS records in the control room."],
                        "next_action": "Approve DNS apply",
                        "resume_hint": "FuseKit resumes after DNS approval is recorded.",
                        "success_criteria": ["The DNS apply approval was recorded."],
                        "avoid_steps": ["Do not create Resend domains or audiences manually."],
                    }
                ],
            },
        ],
        "playbook": _provider_playbook(),
    }


def _pre_detonation_recording_contract() -> dict[str, object]:
    checks = {
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
        "detonation": False,
        "errors_empty": True,
    }
    return {
        "schema_version": "fusekit.recording-contract.v1",
        "recording_ready": False,
        "checks": checks,
        "blockers": ["detonation"],
        "statement": (
            "Public demo recording waits only on detonation; provider playbooks, "
            "guided human actions, model inference, verifiers, and audit proof are ready."
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
                "provider": "github",
                "recipe": "github-repo-env",
                "route": "local_vault",
                "owner": "fusekit",
                "deterministic": True,
                "implemented": True,
                "status": "ok",
            },
            {
                "provider": "github",
                "recipe": "github-authorization",
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
            "guided_human_actions": 1,
        },
        "post_gate_automation": {
            "api_or_cli_routes": ["github:github-repo-env"],
            "human_gate_routes": ["github:github-authorization"],
        },
        "statement": (
            "Humans use VNC only for provider gates. After capture, FuseKit owns "
            "provider mutations by API and can detonate the OCI worker."
        ),
    }


def _provider_gates() -> dict[str, object]:
    return {
        "gates": [
            {
                "id": "provider.github.authorization",
                "provider": "github",
                "reason": "GitHub token captured",
                "status": "captured",
                "target": "GITHUB_TOKEN",
                "captured_targets": ["GITHUB_TOKEN"],
            }
        ]
    }


def _gate_events() -> list[dict[str, object]]:
    return [
        {
            "schema_version": "fusekit.gate-wake.v1",
            "id": "wake-github-token",
            "event": "clipboard_captured",
            "gate_id": "provider.github.authorization",
            "provider": "github",
            "classification": "authorization",
            "status": "captured",
            "target": "GITHUB_TOKEN",
            "target_count": 1,
            "captured_targets": ["GITHUB_TOKEN"],
            "created_at": 1.0,
        }
    ]


def _durable_state(*, host_machine_state_required: bool = False) -> dict[str, object]:
    return {
        "schema_version": "fusekit.durable-state.v1",
        "resume_ready": True,
        "missing": [],
        "runner_profile_ready": True,
        "runner_profile_failures": [],
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
            "host_machine_state_required": host_machine_state_required,
            "no_trace_statement": (
                "Public OCI runs keep durable encrypted/redacted state outside the "
                "disposable VM until completion, then detonate VM/browser/auth scratch "
                "so no FuseKit worker state remains on the user's machine or in the "
                "OCI workspace."
            ),
        },
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
                "If the OCI VM is killed mid-run, FuseKit must recreate the runner "
                "from encrypted/redacted run state instead of relying on local "
                "browser profiles, host clipboard history, or plaintext VM scratch."
            ),
        },
        "statement": (
            "FuseKit can replace or detonate the disposable OCI worker without losing "
            "the run when resume_ready is true; plaintext VM/browser/auth scratch is "
            "volatile and encrypted/redacted state is the source of truth."
        ),
    }


def _audit_trail() -> dict[str, object]:
    return {
        "schema_version": "fusekit.audit-trail.v1",
        "entry_count": 2,
        "counts": {"credential_capture": 1, "provider_action": 1},
        "entries": [
            {
                "category": "credential_capture",
                "action": "control_room.capture_vm_clipboard",
                "provider": "github",
                "target": "GITHUB_TOKEN",
                "status": "captured",
                "source": "gate_events.jsonl",
                "wake_event_id": "wake-github-token",
                "summary": "GITHUB_TOKEN was captured from the VM clipboard.",
            },
            {
                "category": "provider_action",
                "action": "verification.checks_passed",
                "provider": "github",
                "target": "",
                "status": "passed",
                "source": "setup_receipt.json",
                "receipt_action_index": 1,
                "summary": "Provider verification checks passed or are pending-safe.",
            },
        ],
        "statement": (
            "Credential captures, provider actions, DNS writes, human approvals, "
            "and detonation events are summarized without storing raw secrets."
        ),
    }


def _vault_summary() -> dict[str, object]:
    return {
        "record_count": 1,
        "records": [
            {
                "id": "provider.github.token",
                "kind": "provider_token",
                "provider": "github",
                "label": "GitHub token",
            }
        ],
    }


def _run_state() -> dict[str, object]:
    state: dict[str, object] = {field: True for field in RUN_STATE_FIELDS}
    state["workspace_detonated"] = False
    state["updated_at"] = 2.0
    state["notes"] = []
    state["missing_for_detonation"] = []
    state["ready_to_detonate"] = True
    return state


def _llm_lanes() -> list[dict[str, object]]:
    return [
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
    ]


def _run_record_payload(
    *,
    host_machine_state_required: bool = False,
) -> dict[str, object]:
    return {
        "schema_version": "fusekit.run-record.v1",
        "id": "fk-test",
        "status": "pre_detonation_ready",
        "app_path": "app",
        "runner": "oci-free",
        "created_at": 1.0,
        "updated_at": 2.0,
        "state": _run_state(),
        "durable_state": _durable_state(
            host_machine_state_required=host_machine_state_required,
        ),
        "provider_gates": {
            "total": 1,
            "statuses": {"captured": 1},
            "providers": ["github"],
            "records": [
                {
                    "id": "provider.github.authorization",
                    "provider": "github",
                    "status": "captured",
                    "target": "GITHUB_TOKEN",
                    "captured_targets": ["GITHUB_TOKEN"],
                }
            ]
        },
        "steps": [{"id": "scan", "label": "Scan", "status": "passed"}],
        "checkpoints": [{"id": "vault", "label": "Vault", "status": "passed"}],
        "runner_profile": _runner_readiness(),
        "worker_replacement_drill": build_passed_worker_replacement_drill(),
        "provider_playbook": _provider_playbook(),
        "provider_strategies": _provider_strategies(),
        "vault": _vault_summary(),
        "wake_events": {
            "total": 1,
            "event_counts": {"clipboard_captured": 1},
            "events": [
                {
                    "schema_version": "fusekit.gate-wake.v1",
                    "id": "wake-github-token",
                    "event": "clipboard_captured",
                    "gate_id": "provider.github.authorization",
                    "provider": "github",
                    "classification": "authorization",
                    "status": "captured",
                    "target": "GITHUB_TOKEN",
                    "target_count": 1,
                    "captured_targets": ["GITHUB_TOKEN"],
                    "created_at": 1.0,
                }
            ],
        },
        "approvals": [],
        "errors": [],
        "human_actions": {
            "schema_version": "fusekit.human-action-trace.v1",
            "total": 1,
            "counts": {
                "open_provider_gate": 0,
                "capture_vm_clipboard": 1,
                "confirm_gate_finished": 0,
            },
            "actions": [
                {
                    "gate_id": "provider.github.authorization",
                    "provider": "github",
                    "classification": "authorization",
                    "action": "capture_vm_clipboard",
                    "visible_control": "Capture GITHUB_TOKEN from VM clipboard",
                    "target": "GITHUB_TOKEN",
                    "guided": True,
                }
            ],
            "unguided": [],
            "statement": (
                "Every recorded human action maps to one visible control-room gate "
                "with no raw provider secret details."
            ),
        },
        "rehearsal_review": {
            "schema_version": "fusekit.rehearsal-review.v1",
            "status": "ready",
            "action_count": 1,
            "compared_action_count": 1,
            "matched_control_count": 1,
            "unguided_count": 0,
            "side_channel_count": 0,
            "requires_user_thinking": False,
            "reviewed_actions": [
                {
                    "gate_id": "provider.github.authorization",
                    "action": "capture_vm_clipboard",
                    "visible_control": "Capture GITHUB_TOKEN from VM clipboard",
                    "target": "GITHUB_TOKEN",
                    "matched": True,
                    "proof_source": "gates.json + gate_events.jsonl",
                }
            ],
            "statement": (
                "Every recorded human action is compared against the visible "
                "control-room instructions before public recording readiness."
            ),
        },
        "automation_boundary": _automation_boundary(),
        "verifiers": _verifier_summary(),
        "verification": {"checks": _verification_report_checks()},
        "artifacts": [
            {"name": "run_record", "path": "run_record.json", "exists": True},
            {"name": "audit_log", "path": "audit.jsonl", "exists": True},
            {"name": "visual_state", "path": "visual.json", "exists": True},
            {"name": "setup_receipt", "path": "setup_receipt.json", "exists": True},
        ],
        "evidence": {
            "schema_version": "fusekit.evidence-inventory.v1",
            "logs": [
                {"path": "audit.jsonl", "kind": "log", "source": "known-proof", "exists": True}
            ],
            "screenshots": [
                {
                    "path": "screenshots/control-room-ready.png",
                    "kind": "screenshot",
                    "source": "artifact",
                    "exists": True,
                }
            ],
            "visual": [
                {"path": "visual.json", "kind": "visual", "source": "artifact", "exists": True}
            ],
            "receipts": [
                {
                    "path": "setup_receipt.json",
                    "kind": "receipt",
                    "source": "artifact",
                    "exists": True,
                }
            ],
            "counts": {"logs": 1, "screenshots": 1, "visual": 1, "receipts": 1},
            "statement": (
                "Run evidence is inventoried by path and type only; raw secrets are "
                "not embedded in the Run Record."
            ),
        },
        "model_inference": {
            "schema_version": "fusekit.model-inference-summary.v1",
            "provider": "openai",
            "model": "gpt-5.5",
            "base_url": "https://api.openai.com/v1",
            "api_key_env": "OPENAI_API_KEY",
            "auth_mode": "auto",
            "required": True,
            "can_proceed_without_api_key": True,
            "default_lane": "openclaw-openai",
            "status": "api_key_encrypted",
            "ready": True,
            "lane_count": 2,
            "next_action": "FuseKit has an encrypted LLM API key and can continue.",
            "statement": (
                "The model/inference lane is explicit: API keys are captured into the "
                "encrypted vault; raw secrets never appear in the public Run Record."
            ),
        },
        "llm_contract": {
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
            "next_action": "FuseKit has an encrypted LLM API key and can continue.",
            "lanes": _llm_lanes(),
            "security": {
                "raw_secret_export": "denied",
                "storage": "encrypted vault only",
                "public_surfaces": "metadata and redacted status only",
                "detonation": "plaintext OpenClaw/browser auth state is a cleanup target",
            },
        },
        "audit_trail": _audit_trail(),
        "control_room_security": public_control_room_security_surface(),
        "acceptance": {},
        "detonation": {"preflight_safe": True, "workspace_detonated": False},
        "recording_contract": _pre_detonation_recording_contract(),
    }


def _write_run_record(path: Path, *, host_machine_state_required: bool = False) -> None:
    path.write_text(
        json.dumps(_run_record_payload(host_machine_state_required=host_machine_state_required)),
        encoding="utf-8",
    )


def _write_llm_contract(path: Path) -> None:
    path.write_text(json.dumps(_run_record_payload()["llm_contract"]), encoding="utf-8")


def _write_preflight_evidence_files(fusekit: Path) -> None:
    (fusekit / "visual.json").write_text(json.dumps(_visual_state()), encoding="utf-8")
    screenshots = fusekit / "screenshots"
    screenshots.mkdir(exist_ok=True)
    (screenshots / "control-room-ready.png").write_bytes(b"png")


def _write_preflight_survivors(fusekit: Path) -> dict[str, Path]:
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    provider_strategies = fusekit / "provider_strategies.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
    runner_readiness = fusekit / "runner_readiness.json"
    visual_state = fusekit / "visual.json"
    gates = fusekit / "gates.json"
    gate_events = fusekit / "gate_events.jsonl"
    llm_contract = fusekit / "llm_contract.json"
    worker_replacement_drill = fusekit / "worker_replacement_drill.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[],"raw_secrets_exposed":0}', encoding="utf-8")
    _write_preflight_evidence_files(fusekit)
    report.write_text(json.dumps({"checks": _verification_report_checks()}), encoding="utf-8")
    provider_strategies.write_text(json.dumps(_provider_strategies()), encoding="utf-8")
    rollback.write_text(
        '{"rollback":[{"action":"rollback.github.secret","status":"planned"}]}',
        encoding="utf-8",
    )
    _write_run_record(run_record)
    _write_llm_contract(llm_contract)
    runner_readiness.write_text(json.dumps(_runner_readiness()), encoding="utf-8")
    gates.write_text(json.dumps(_provider_gates()), encoding="utf-8")
    gate_events.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in _gate_events()) + "\n",
        encoding="utf-8",
    )
    worker_replacement_drill.write_text(
        json.dumps(build_passed_worker_replacement_drill()),
        encoding="utf-8",
    )
    return {
        "vault": vault,
        "audit": audit,
        "receipt": receipt,
        "verification_report": report,
        "provider_strategies": provider_strategies,
        "rollback_metadata": rollback,
        "run_record": run_record,
        "llm_contract": llm_contract,
        "runner_readiness": runner_readiness,
        "visual_state": visual_state,
        "gates": gates,
        "gate_events": gate_events,
        "worker_replacement_drill": worker_replacement_drill,
    }


def test_detonation_preflight_allows_passed_and_pending_safe_checks(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    provider_strategies = fusekit / "provider_strategies.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
    runner_readiness = fusekit / "runner_readiness.json"
    gates = fusekit / "gates.json"
    gate_events = fusekit / "gate_events.jsonl"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[],"raw_secrets_exposed":0}', encoding="utf-8")
    _write_preflight_evidence_files(fusekit)
    report_checks = list(_verification_report_checks())
    report_checks[3] = {
        "provider": "cloudflare",
        "check": "dns_record_exists",
        "status": "pending",
        "details": {"pending_safe": True},
    }
    report.write_text(json.dumps({"checks": report_checks}), encoding="utf-8")
    provider_strategies.write_text(json.dumps(_provider_strategies()), encoding="utf-8")
    rollback.write_text(
        '{"rollback":[{"action":"rollback.github.secret","status":"planned"}]}',
        encoding="utf-8",
    )
    runner_readiness.write_text(json.dumps(_runner_readiness()), encoding="utf-8")
    gates.write_text(json.dumps(_provider_gates()), encoding="utf-8")
    gate_events.write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in _gate_events()) + "\n",
        encoding="utf-8",
    )
    payload = _run_record_payload()
    verifier_summary = payload["verifiers"]
    assert isinstance(verifier_summary, dict)
    verifier_checks = verifier_summary["checks"]
    assert isinstance(verifier_checks, list)
    verifier_checks[3] = {
        "provider": "cloudflare",
        "check": "dns_record_exists",
        "status": "pending_safe",
        "pending_safe": True,
    }
    counts = verifier_summary["counts"]
    assert isinstance(counts, dict)
    counts["passed"] = 4
    counts["pending_safe"] = 1
    embedded_verification = payload["verification"]
    assert isinstance(embedded_verification, dict)
    embedded_verification["checks"] = report_checks
    run_record.write_text(json.dumps(payload), encoding="utf-8")
    _write_llm_contract(run_record.with_name("llm_contract.json"))

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        provider_strategies=provider_strategies,
        rollback_metadata=rollback,
        run_record=run_record,
        runner_readiness=runner_readiness,
        gates=gates,
        gate_events=gate_events,
    )

    assert result.ok


def test_detonation_preflight_rejects_duplicate_verification_checks() -> None:
    report = {
        "checks": [
            {"provider": "resend", "check": "domain_verified", "status": "passed"},
            {"provider": "resend", "check": "domain_verified", "status": "passed"},
        ]
    }

    assert verification_report_failures(report) == [
        "resend.domain_verified is duplicated"
    ]


def test_detonation_preflight_rejects_anonymous_verification_checks() -> None:
    report = {
        "checks": [
            {"provider": "resend", "status": "passed"},
            {"check": "deployment_url_exists", "status": "passed"},
            {"provider": "live_app", "check": "health"},
        ]
    }

    assert verification_report_failures(report) == [
        "verification report checks[0].check is missing",
        "verification report checks[1].provider is missing",
        "verification report checks[2].status is missing",
    ]


def test_detonation_preflight_rejects_loose_verification_report_rows() -> None:
    report = {
        "checks": [
            {
                "provider": " resend ",
                "check": " domain_verified ",
                "status": " passed ",
                "summary": " Verified through Resend. ",
                "repair": "",
                "details": "ok",
                "private_note": "sidecar verifier detail",
            },
        ]
    }

    assert verification_report_failures(report) == [
        "verification report checks[0] has unexpected fields: private_note",
        "verification report checks[0].provider must not have surrounding whitespace",
        "verification report checks[0].check must not have surrounding whitespace",
        "verification report checks[0].status must not have surrounding whitespace",
        "verification report checks[0].summary must not have surrounding whitespace",
        "verification report checks[0].repair must not be empty",
        "verification report checks[0].details must be an object",
    ]


def test_detonation_preflight_rejects_truthy_pending_safe_verification() -> None:
    report = {
        "checks": [
            {
                "provider": "resend",
                "check": "api_health",
                "status": "pending",
                "details": {"pending_safe": "true"},
            },
            {
                "provider": "vercel",
                "check": "env_vars_configured",
                "status": "pending",
                "details": {"details": {"pending_safe": 1}},
            },
        ]
    }

    assert verification_report_failures(report) == [
        "resend.api_health is pending",
        "vercel.env_vars_configured is pending",
    ]


def test_detonation_preflight_requires_central_run_record(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[],"raw_secrets_exposed":0}', encoding="utf-8")
    report.write_text(
        '{"checks":[{"provider":"github","check":"repo_secret_exists","status":"passed"}]}',
        encoding="utf-8",
    )
    rollback.write_text(
        '{"rollback":[{"action":"rollback.github.secret","status":"planned"}]}',
        encoding="utf-8",
    )

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
        run_record=run_record,
    )

    assert not result.ok
    assert any("missing central run record" in failure for failure in result.failures)


def test_detonation_preflight_requires_embedded_acceptance_summary(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload.pop("acceptance")
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record acceptance is missing" in result.failures


def test_detonation_preflight_rejects_loose_run_record_envelope(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["private_note"] = "sidecar run record proof"
    payload["created_at"] = True
    payload["updated_at"] = "later"
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record has unexpected fields: private_note" in result.failures
    assert "central run record created_at must be a non-negative number" in result.failures
    assert "central run record updated_at must be a non-negative number" in result.failures


def test_detonation_preflight_rejects_hollow_run_record_proof_sections(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["vault"] = {}
    payload["provider_playbook"] = {}
    payload["runner_profile"] = {}
    payload["worker_replacement_drill"] = {}
    payload["artifacts"] = []
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record is missing vault" in result.failures
    assert "central run record is missing provider_playbook" in result.failures
    assert "central run record is missing runner_profile" in result.failures
    assert "central run record is missing worker_replacement_drill" in result.failures
    assert "central run record is missing artifacts" in result.failures


def test_detonation_preflight_rejects_unshaped_acceptance_summary(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["acceptance"] = {
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
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record acceptance has unexpected fields: private_note" in (
        result.failures
    )
    assert "central run record acceptance.mode must be live or rehearsal" in result.failures
    assert "central run record acceptance.launch_ready must be boolean" in result.failures
    assert "central run record acceptance.public_launch_ready must be boolean" in result.failures
    assert "central run record acceptance.remote_artifacts_ready must be boolean" in (
        result.failures
    )
    assert "central run record acceptance.recording_proof_ready must be boolean" in (
        result.failures
    )
    assert "central run record acceptance.missing must be a list" in result.failures
    assert "central run record acceptance.blockers must be a list" in result.failures
    assert "central run record acceptance.error must be a string" in result.failures


def test_detonation_preflight_rejects_stale_acceptance_summary(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["acceptance"] = {
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
    payload["errors"] = [
        {
            "source": "verification",
            "id": "live_url_healthy",
            "detail": "Live URL verification is not ready.",
        }
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record acceptance.mode must be live or rehearsal" in (
        result.failures
    )
    assert (
        "central run record acceptance.public_launch_ready must equal live launch_ready"
        in result.failures
    )
    assert (
        "central run record acceptance.public_launch_ready must require launch_ready"
        in result.failures
    )
    assert (
        "central run record acceptance.public_launch_ready must require live mode"
        in result.failures
    )
    assert (
        "central run record acceptance.recording_ready must require live mode"
        in result.failures
    )
    assert (
        "central run record acceptance.blockers[0] must be an object"
        in result.failures
    )
    assert (
        "central run record acceptance.blockers must be empty when readiness is true"
        in result.failures
    )
    assert (
        "central run record acceptance.missing must be empty when readiness is true"
        in result.failures
    )
    assert (
        "central run record acceptance.error must be empty when readiness is true"
        in result.failures
    )
    assert (
        "central run record acceptance readiness must be false when errors are present"
        in result.failures
    )
    assert (
        "central run record acceptance.recording_proof_ready must match "
        "recording_contract.recording_ready"
        in result.failures
    )

    payload["acceptance"] = {
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
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record acceptance.public_launch_ready must equal live launch_ready"
        in result.failures
    )

    payload["acceptance"] = {
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
    payload["errors"] = []
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record acceptance.error must not have surrounding whitespace" in (
        result.failures
    )

    payload["acceptance"]["error"] = "   "
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record acceptance.error must be empty or non-empty text" in (
        result.failures
    )

    payload["acceptance"] = {
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
    payload["errors"] = [
        {
            "source": "verification",
            "id": "live_app",
            "detail": "Live app verification is unresolved.",
        }
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record acceptance readiness must be false when errors are present"
        in result.failures
    )
    assert (
        "central run record acceptance.recording_ready must be false when errors are present"
        not in result.failures
    )

    payload["acceptance"] = {
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
    payload["errors"] = []
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record acceptance.missing[0] must not have surrounding whitespace" in (
        result.failures
    )
    assert "central run record acceptance.missing[1] must be non-empty" in (
        result.failures
    )
    assert (
        "central run record acceptance.missing[0] has no matching blocker item "
        "verified live URL"
        in result.failures
    )
    assert (
        "central run record acceptance.missing[2] duplicates acceptance missing proof "
        "verified live URL"
        in result.failures
    )

    payload["acceptance"] = {
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
    payload["errors"] = []
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record acceptance.blockers[0].category is missing" in (
        result.failures
    )
    assert (
        "central run record acceptance.blockers[1].item must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record acceptance.blockers[1].item duplicates acceptance blocker vault"
        in
        result.failures
    )
    assert (
        "central run record acceptance.blockers[1] has unexpected fields: private_note"
        in result.failures
    )
    assert "central run record acceptance.blockers[2].next_action is missing" in (
        result.failures
    )
    assert "central run record acceptance.blockers[2].detail must be a string" in (
        result.failures
    )
    assert (
        "central run record acceptance.blockers[3].detail must be non-empty when present"
        in result.failures
    )

    payload["acceptance"] = {
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
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record acceptance.recording_ready must equal "
        "public_launch_ready and remote_artifacts_ready and recording_proof_ready"
        in result.failures
    )

    payload["acceptance"] = {
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
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record acceptance.recording_ready must equal "
        "public_launch_ready and remote_artifacts_ready and recording_proof_ready"
        in result.failures
    )
    assert (
        "central run record acceptance.recording_ready must require remote_artifacts_ready"
        in result.failures
    )


def test_detonation_preflight_requires_provider_strategy_survivor(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["provider_strategies"].unlink()

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any("missing provider strategies" in failure for failure in result.failures)


def test_detonation_preflight_requires_runner_readiness_survivor(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["runner_readiness"].unlink()

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any("missing runner readiness" in failure for failure in result.failures)


def test_detonation_preflight_requires_visual_state_survivor(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["visual_state"].unlink()

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any("missing visual state" in failure for failure in result.failures)


def test_detonation_preflight_requires_gate_survivors(tmp_path) -> None:
    for key, expected in (
        ("gates", "missing provider gates"),
        ("gate_events", "missing gate events"),
    ):
        fusekit = tmp_path / key / ".fusekit"
        fusekit.mkdir(parents=True)
        survivors = _write_preflight_survivors(fusekit)
        survivors[key].unlink()

        result = run_detonation_preflight(root=fusekit.parent, **survivors)

        assert not result.ok, key
        assert any(expected in failure for failure in result.failures)


def test_detonation_preflight_requires_worker_replacement_drill_when_requested(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    drill = survivors.pop("worker_replacement_drill")
    drill.unlink()

    result = run_detonation_preflight(
        root=tmp_path,
        worker_replacement_drill=drill,
        **survivors,
    )

    assert not result.ok
    assert any("worker replacement drill" in failure for failure in result.failures)


def test_detonation_preflight_rejects_duplicate_worker_replacement_sources(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    drill = build_passed_worker_replacement_drill()
    drill["restored_from"].append(drill["restored_from"][0])
    survivors["worker_replacement_drill"].write_text(json.dumps(drill), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "worker replacement drill restore sources must be unique" in result.failures


def test_detonation_preflight_rejects_loose_worker_replacement_drill_survivor(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    drill = build_passed_worker_replacement_drill()
    drill["private_note"] = "sidecar drill note"
    drill["schema_version"] = " fusekit.worker-replacement-drill.v1 "
    drill["status"] = " passed "
    drill["restored_from"][0] = f" {drill['restored_from'][0]} "
    drill["pending_reason"] = " already passed "
    drill["statement"] = f" {drill['statement']} "
    survivors["worker_replacement_drill"].write_text(json.dumps(drill), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "worker replacement drill has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "worker replacement drill schema_version must be trimmed" in result.failures
    )
    assert "worker replacement drill has unsupported schema" in result.failures
    assert "worker replacement drill status must be trimmed" in result.failures
    assert "worker replacement drill did not pass" in result.failures
    assert (
        "worker replacement drill restored_from[0] must be trimmed"
        in result.failures
    )
    assert (
        "worker replacement drill restore sources must match durable source ids"
        in result.failures
    )
    assert "worker replacement drill pending_reason must be trimmed" in result.failures
    assert "worker replacement drill statement must be trimmed" in result.failures


def test_detonation_preflight_rejects_host_machine_state_dependency(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[],"raw_secrets_exposed":0}', encoding="utf-8")
    report.write_text(
        '{"checks":[{"provider":"github","check":"repo_secret_exists","status":"passed"}]}',
        encoding="utf-8",
    )
    rollback.write_text(
        '{"rollback":[{"action":"rollback.github.secret","status":"planned"}]}',
        encoding="utf-8",
    )
    _write_run_record(run_record, host_machine_state_required=True)

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
        run_record=run_record,
    )

    assert not result.ok
    assert any("requires host-machine state" in failure for failure in result.failures)


def test_detonation_preflight_rejects_durable_source_path_drift(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    durable_state = payload["durable_state"]
    assert isinstance(durable_state, dict)
    sources = durable_state["sources"]
    assert isinstance(sources, list)
    run_state_source = next(
        source
        for source in sources
        if isinstance(source, dict) and source.get("id") == "run_state"
    )
    assert isinstance(run_state_source, dict)
    run_state_source["path"] = "survivors/run_state.json"
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record durable_state sources[2].path must be run_state.json"
        in result.failures
    )


def test_detonation_preflight_requires_full_worker_replacement_contract(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    durable_state = payload["durable_state"]
    assert isinstance(durable_state, dict)
    durable_state["statement"] = "durable files exist"
    scope = durable_state["detonation_scope"]
    assert isinstance(scope, dict)
    scope["no_trace_statement"] = "cleanup ran"
    replacement = durable_state["worker_replacement_contract"]
    assert isinstance(replacement, dict)
    replacement["required_runner_profile"] = "ad-hoc-runner"
    replacement["state_owner"] = "local-browser-profile"
    replacement["volatile_surfaces"] = ["worker"]
    replacement["statement"] = "resume from saved state"
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record durable_state detonation_scope "
        "no_trace_statement is incomplete"
        in result.failures
    )
    assert (
        "central run record durable_state statement is missing durable-worker guidance"
        in result.failures
    )
    assert (
        "central run record durable_state worker_replacement_contract "
        "required_runner_profile is unsupported"
        in result.failures
    )
    assert (
        "central run record durable_state worker_replacement_contract "
        "state_owner is unsupported"
        in result.failures
    )
    assert (
        "central run record durable_state worker_replacement_contract "
        "volatile_surfaces must cover volatile_worker_surfaces"
        in result.failures
    )
    assert (
        "central run record durable_state worker_replacement_contract "
        "statement is incomplete"
        in result.failures
    )


def test_detonation_preflight_requires_model_inference_in_run_record(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload.pop("model_inference")
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record is missing model_inference" in result.failures


def test_detonation_preflight_requires_ready_encrypted_model_inference(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["model_inference"] = {
        "schema_version": "fusekit.model-inference-summary.v1",
        "provider": "openai",
        "model": "gpt-5.5",
        "api_key_env": "OPENAI_API_KEY",
        "auth_mode": "auto",
        "status": "needs_openclaw_or_api_key",
        "ready": False,
        "next_action": "Use the OpenClaw/OpenAI human-gated authorization step.",
        "statement": "Waiting for model authorization.",
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record model inference has no encrypted API key or OpenClaw auth"
        in result.failures
    )
    assert "central run record model inference is not ready" in result.failures
    assert (
        "central run record model inference statement is missing secret-boundary proof"
        in result.failures
    )


def test_detonation_preflight_requires_llm_contract_in_run_record(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload.pop("llm_contract")
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record is missing llm_contract" in result.failures


def test_detonation_preflight_requires_llm_contract_artifact(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["llm_contract"].unlink()

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any(
        "missing model/inference contract" in failure for failure in result.failures
    )


def test_detonation_preflight_requires_llm_contract_artifact_to_match_run_record(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    artifact = json.loads(survivors["llm_contract"].read_text(encoding="utf-8"))
    artifact["model"] = "stale-model"
    survivors["llm_contract"].write_text(json.dumps(artifact), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record LLM contract does not match llm_contract.json artifact"
        in result.failures
    )


def test_detonation_preflight_requires_shaped_llm_contract_lanes(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    model = payload["model_inference"]
    assert isinstance(model, dict)
    model["provider"] = " openai "
    model["next_action"] = "Continue at https://provider.example/callback"
    model["required"] = "true"
    model["can_proceed_without_api_key"] = 1
    model["lane_count"] = True
    model["private_note"] = "sidecar model proof"
    contract = payload["llm_contract"]
    assert isinstance(contract, dict)
    contract["provider"] = " openai "
    contract["record_id"] = " llm.openai.api_key "
    contract["required"] = "true"
    contract["can_proceed_without_api_key"] = 1
    contract["default_lane"] = "missing-lane"
    contract["private_note"] = "sidecar LLM contract proof"
    security = contract["security"]
    assert isinstance(security, dict)
    security["storage"] = " encrypted vault only "
    security["public_surfaces"] = "Review https://provider.example/callback"
    security["private_note"] = "sidecar security proof"
    contract["lanes"] = [
        "not-a-lane",
        {
            "id": "",
            "label": "",
            "available": "yes",
            "requires_user_action": 0,
            "description": "",
        },
        {
            "id": "openclaw-openai",
            "label": "OpenClaw OpenAI authorization",
            "available": True,
            "requires_user_action": False,
            "description": "Continue at https://provider.example/callback",
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
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")
    survivors["llm_contract"].write_text(json.dumps(contract), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record model inference has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record model inference provider must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record model inference next_action contains unsafe public text"
        in result.failures
    )
    assert (
        "central run record model inference required must be boolean"
        in result.failures
    )
    assert (
        "central run record model inference can_proceed_without_api_key must be boolean"
        in result.failures
    )
    assert (
        "central run record model inference lane_count must be integer"
        in result.failures
    )
    assert "central run record LLM contract has unexpected fields: private_note" in (
        result.failures
    )
    assert (
        "central run record LLM contract provider must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record LLM contract record_id must not have surrounding whitespace"
        in result.failures
    )
    assert "central run record LLM contract required must be boolean" in result.failures
    assert (
        "central run record LLM contract can_proceed_without_api_key must be boolean"
        in result.failures
    )
    assert (
        "central run record LLM contract security has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record LLM contract security storage must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record LLM contract security public_surfaces contains unsafe public text"
        in result.failures
    )
    assert "central run record LLM contract lanes[0] is not an object" in result.failures
    assert "central run record LLM contract lanes[1].id is missing" in result.failures
    assert "central run record LLM contract lanes[1].label is missing" in result.failures
    assert (
        "central run record LLM contract lanes[1].available must be boolean"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes[1].requires_user_action must be boolean"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes[1].description is missing"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes[2].description contains unsafe public text"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes[2] has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes[3].id must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes[3].id duplicates LLM contract lane "
        "openclaw-openai"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes[3].label must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes[3].description must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record LLM contract default_lane must match lanes"
        in result.failures
    )
    assert "central run record LLM contract lanes must include api-key" in result.failures


def test_detonation_preflight_requires_ready_default_and_status_llm_lanes(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    model = payload["model_inference"]
    assert isinstance(model, dict)
    model["default_lane"] = "api-key"
    contract = payload["llm_contract"]
    assert isinstance(contract, dict)
    contract["default_lane"] = "api-key"
    lanes = contract["lanes"]
    assert isinstance(lanes, list)
    api_key_lane = lanes[0]
    assert isinstance(api_key_lane, dict)
    api_key_lane["available"] = False
    api_key_lane["requires_user_action"] = True
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")
    survivors["llm_contract"].write_text(json.dumps(contract), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record LLM contract default_lane must be available"
        in result.failures
    )
    assert (
        "central run record LLM contract default_lane must not require user "
        "action when ready"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes must mark api-key available"
        in result.failures
    )
    assert (
        "central run record LLM contract lanes must mark api-key ready without "
        "user action"
        in result.failures
    )


def test_detonation_preflight_requires_model_inference_to_match_llm_contract(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    contract = payload["llm_contract"]
    assert isinstance(contract, dict)
    contract["model"] = "other-model"
    contract["base_url"] = "https://llm.example/v1"
    contract["required"] = False
    contract["can_proceed_without_api_key"] = False
    contract["default_lane"] = "api-key"
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record model inference does not match LLM contract: "
        "base_url, can_proceed_without_api_key, default_lane, model, required"
        in result.failures
    )


def test_detonation_preflight_requires_control_room_security_proof(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["control_room_security"] = {
        "schema_version": "fusekit.control-room-security-surface.v1",
        "routes": [],
        "state_changing_routes": [],
        "state_changing_route_count": 0,
        "required_post_protection": "action-token",
        "statement": "protected",
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any(
        "missing protected control-room mutation routes" in failure
        for failure in result.failures
    )
    assert any(
        "control-room POST protection is incomplete" in failure
        for failure in result.failures
    )
    assert any(
        "control-room no-CORS/action-token proof is incomplete" in failure
        for failure in result.failures
    )


def test_detonation_preflight_rejects_duplicate_control_room_routes(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    security = payload["control_room_security"]
    duplicate_route = dict(
        next(route for route in security["routes"] if route.get("state_change") is True)
    )
    security["routes"].append(duplicate_route)
    security["state_changing_routes"].append(duplicate_route["route"])
    security["state_changing_route_count"] += 1
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record control-room mutation routes are duplicated"
        in result.failures
    )


def test_detonation_preflight_rejects_loose_control_room_security_rows(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    security = payload["control_room_security"]
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
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record control-room security has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record control-room security "
        f"routes[{route_index}] has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record control-room security "
        f"routes[{route_index}].route must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record control-room security "
        f"routes[{route_index}].methods[0] must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record control-room security "
        f"routes[{route_index}].protection must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record control-room security state_changing_routes[0] "
        "must not have surrounding whitespace"
        in result.failures
    )


def test_detonation_preflight_rejects_placeholder_automation_boundary(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["automation_boundary"] = {"routes": [{"id": "github.repo-env"}]}
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record automation-boundary schema is unsupported"
        in result.failures
    )
    assert (
        "central run record automation-boundary status must be ready"
        in result.failures
    )
    assert (
        "central run record automation-boundary counts are missing"
        in result.failures
    )
    assert (
        "central run record automation-boundary post-gate automation is missing"
        in result.failures
    )


def test_detonation_preflight_rejects_loose_automation_boundary_rows(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    boundary = payload["automation_boundary"]
    assert isinstance(boundary, dict)

    boundary["private_note"] = "sidecar boundary note"
    boundary["status"] = " ready "
    boundary["statement"] = f" {boundary['statement']} "
    allowed = boundary["vnc_allowed_for"]
    assert isinstance(allowed, list)
    allowed[0] = " login "
    routes = boundary["routes"]
    assert isinstance(routes, list)
    first_route = routes[0]
    assert isinstance(first_route, dict)
    first_route["private_note"] = "sidecar route note"
    first_route["provider"] = " github "
    first_route["route"] = " local_vault "
    first_route["owner"] = " fusekit "
    counts = boundary["counts"]
    assert isinstance(counts, dict)
    counts["private_note"] = 1
    counts["blocked"] = False
    post_gate = boundary["post_gate_automation"]
    assert isinstance(post_gate, dict)
    post_gate["private_note"] = "sidecar post-gate note"
    api_or_cli = post_gate["api_or_cli_routes"]
    human_gate = post_gate["human_gate_routes"]
    assert isinstance(api_or_cli, list)
    assert isinstance(human_gate, list)
    api_or_cli[0] = " github:github-repo-env "
    human_gate[0] = " github:github-authorization "
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record automation-boundary has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record automation-boundary status must not have surrounding whitespace"
        in result.failures
    )
    assert "central run record automation-boundary status must be ready" in result.failures
    assert (
        "central run record automation-boundary statement "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record automation-boundary vnc_allowed_for[0] "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record automation-boundary routes[0] "
        "has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record automation-boundary routes[0].provider "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record automation-boundary routes[0].route "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record automation-boundary routes[0].owner "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record automation-boundary counts has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record automation-boundary blocked count must be an integer"
        in result.failures
    )
    assert (
        "central run record automation-boundary blocked count must be 0"
        in result.failures
    )
    assert (
        "central run record automation-boundary post-gate automation "
        "has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record automation-boundary api/cli routes[0] "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record automation-boundary human-gate routes[0] "
        "must not have surrounding whitespace"
        in result.failures
    )


def test_detonation_preflight_rejects_placeholder_vault_summary(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["vault"] = {
        "record_count": 3,
        "records": [
            {"id": "provider.github.token"},
            {
                "id": "provider.github.token",
                "kind": "provider_token",
                "provider": "github",
                "label": "GitHub token",
                "value": "redacted",
                "metadata": {"raw_value": "redacted"},
            },
        ],
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record vault record_count must match records"
        in result.failures
    )
    assert "central run record vault records[0].kind is missing" in result.failures
    assert "central run record vault records[0].provider is missing" in result.failures
    assert "central run record vault records[0].label is missing" in result.failures
    assert (
        "central run record vault records[1].id duplicates vault record "
        "provider.github.token"
    ) in result.failures
    assert "central run record vault records[1] exposes a raw value" in result.failures
    assert (
        "central run record vault records[1].metadata.raw_value exposes raw "
        "secret metadata"
    ) in result.failures


def test_detonation_preflight_rejects_loose_vault_summary_shape(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["vault"] = {
        "record_count": "2",
        "note": "sidecar vault proof",
        "records": [
            {
                "id": " provider.github.token",
                "kind": "provider_token",
                "provider": "github",
                "label": "GitHub token ",
                "note": "sidecar vault proof",
            },
            {
                "id": "provider.github.webhook",
                "kind": "provider_token",
                "provider": "github",
                "label": "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890",
            },
        ],
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record vault record_count must be a literal integer"
        in result.failures
    )
    assert "central run record vault has unexpected fields: note" in result.failures
    assert (
        "central run record vault records[0] has unexpected fields: note"
        in result.failures
    )
    assert "central run record vault records[0].id must be trimmed" in result.failures
    assert "central run record vault records[0].label must be trimmed" in result.failures
    assert (
        "central run record vault records[1].label contains credential-looking text"
        in result.failures
    )


def test_detonation_preflight_rejects_placeholder_timeline_entries(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["steps"] = [
        {
            "id": " setup.execute ",
            "label": " Setup ",
            "status": "passed",
            "detail": " captured token=leaked-value ",
            "updated_at": True,
            "private_note": "sidecar timeline note",
        },
        {
            "id": "setup.execute",
            "label": "Setup again",
            "status": "passed",
        },
    ]
    payload["checkpoints"] = [
        {
            "id": "vault",
            "label": "",
            "status": "passed",
            "mascot_state": " verify ",
            "resume_hint": " Stay in the control room. ",
            "updated_at": -1,
            "private_note": "sidecar checkpoint note",
        },
        {"id": "vault", "label": "Vault again", "status": "passed"},
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record steps[0] has unexpected fields: private_note" in (
        result.failures
    )
    assert "central run record steps[0].id must not have surrounding whitespace" in (
        result.failures
    )
    assert "central run record steps[0].label must not have surrounding whitespace" in (
        result.failures
    )
    assert "central run record steps[0].detail must not have surrounding whitespace" in (
        result.failures
    )
    assert (
        "central run record steps[0].detail contains credential-looking text"
        in result.failures
    )
    assert (
        "central run record steps[0].updated_at must be a non-negative number"
        in result.failures
    )
    assert (
        "central run record steps[1].id duplicates steps entry setup.execute"
        in result.failures
    )
    assert "central run record checkpoints[0] has unexpected fields: private_note" in (
        result.failures
    )
    assert "central run record checkpoints[0].label is missing" in result.failures
    assert (
        "central run record checkpoints[0].mascot_state must not have surrounding "
        "whitespace"
        in result.failures
    )
    assert (
        "central run record checkpoints[0].resume_hint must not have surrounding "
        "whitespace"
        in result.failures
    )
    assert (
        "central run record checkpoints[0].updated_at must be a non-negative number"
        in result.failures
    )
    assert (
        "central run record checkpoints[1].id duplicates checkpoints entry vault"
        in result.failures
    )


def test_detonation_preflight_rejects_stale_approval_summary(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["approvals"] = [
        {
            "id": " dns.stale.approval ",
            "provider": "",
            "status": " passed ",
            "reason": " approved with token=leaked-value ",
            "updated_at": True,
            "private_note": "sidecar approval note",
        },
        {
            "id": "provider.github.authorization",
            "provider": "github",
            "status": "resume_requested",
            "reason": "approval drifted from captured gate",
            "updated_at": 2.0,
        },
        {
            "id": "provider.github.authorization",
            "provider": "github",
            "status": "resume_requested",
            "reason": "duplicate approval",
            "updated_at": -1,
        },
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record approvals[0] has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record approvals[0].id must not have surrounding whitespace"
        in result.failures
    )
    assert "central run record approvals[0].provider is missing" in result.failures
    assert (
        "central run record approvals[0].status must not have surrounding whitespace"
        in result.failures
    )
    assert "central run record approvals[0].status is unsupported" in result.failures
    assert (
        "central run record approvals[0].reason must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record approvals[0].reason contains credential-looking text"
        in result.failures
    )
    assert (
        "central run record approvals[0].updated_at must be a non-negative number"
        in result.failures
    )
    assert (
        "central run record approvals[0].id must match provider_gates.records"
        in result.failures
    )
    assert (
        "central run record approvals[1].status must match provider_gates.records"
        in result.failures
    )
    assert (
        "central run record approvals[2].id duplicates approval summary for "
        "provider.github.authorization"
    ) in result.failures
    assert (
        "central run record approvals[2].updated_at must be a non-negative number"
        in result.failures
    )


def test_detonation_preflight_rejects_unshaped_error_summary(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["recording_contract"]["checks"]["errors_empty"] = False
    payload["errors"] = [
        "plain string error",
        {
            "source": "",
            "id": "verify.live",
            "detail": "Provider returned token=leaked-value",
        },
        {"source": "acceptance", "id": "", "detail": ""},
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record errors[0] is not an object" in result.failures
    assert "central run record errors[1].source is missing" in result.failures
    assert (
        "central run record errors[1].detail contains credential-looking text"
        in result.failures
    )
    assert "central run record errors[2].id is missing" in result.failures
    assert "central run record errors[2].detail is missing" in result.failures


def test_detonation_preflight_rejects_unshaped_run_record_identity(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload.pop("status")
    payload["runner"] = ""
    payload["app_path"] = str(tmp_path / "app")
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record is missing status" in result.failures
    assert "central run record is missing runner" in result.failures
    assert (
        "central run record app_path must be a public path label"
        in result.failures
    )


def test_detonation_preflight_rejects_unshaped_state_and_verification(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    state = _run_state()
    state["private_note"] = "sidecar state proof"
    state["detonation_safe"] = "true"
    state["workspace_detonated"] = "false"
    state["ready_to_detonate"] = 1
    state["updated_at"] = -1
    state["notes"] = [" recovery note "]
    state["missing_for_detonation"] = [" vault_created ", "unknown_field"]
    payload["state"] = state
    payload["verification"] = {
        "checks": [
            {"provider": "github", "check": "repo_secret_exists", "status": "failed"}
        ]
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record state has unexpected fields: private_note" in result.failures
    assert "central run record state.detonation_safe must be boolean" in result.failures
    assert (
        "central run record state.detonation_safe must be true"
        in result.failures
    )
    assert "central run record state.workspace_detonated must be boolean" in result.failures
    assert "central run record state.ready_to_detonate must be boolean" in result.failures
    assert (
        "central run record state.updated_at must be a non-negative number"
        in result.failures
    )
    assert (
        "central run record state.notes[0] must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record state.missing_for_detonation[0] "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record state.missing_for_detonation has unknown fields: unknown_field"
        in result.failures
    )
    assert "central run record github.repo_secret_exists is failed" in result.failures
    assert (
        "central run record verification must match verification_report.json"
        in result.failures
    )


def test_detonation_preflight_rejects_unshaped_detonation_summary(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["detonation"] = {
        "preflight_safe": "true",
        "workspace_detonated": "false",
        "private_note": "sidecar detonation proof",
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record detonation has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record detonation.preflight_safe must be true"
        in result.failures
    )
    assert (
        "central run record detonation.workspace_detonated must be boolean"
        in result.failures
    )


def test_detonation_preflight_rejects_float_control_room_route_counts(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    security = payload["control_room_security"]
    routes = security["routes"]
    state_routes = security["state_changing_routes"]
    assert isinstance(routes, list)
    assert isinstance(state_routes, list)
    security["route_count"] = float(len(routes))
    security["state_changing_route_count"] = float(len(state_routes))
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record control-room route counts drifted"
        in result.failures
    )


def test_detonation_preflight_requires_non_detonation_recording_proof(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    contract = payload["recording_contract"]
    assert isinstance(contract, dict)
    checks = contract["checks"]
    assert isinstance(checks, dict)
    checks["provider_playbook"] = False
    contract["blockers"] = ["detonation", "provider_playbook"]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record recording contract checks.provider_playbook must be true"
        in result.failures
    )
    assert (
        "central run record recording contract has non-detonation blockers: provider_playbook"
        in result.failures
    )


def test_detonation_preflight_rejects_hollow_recording_contract(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["recording_contract"] = {
        "recording_ready": False,
        "private_note": "sidecar recording proof",
        "checks": {"private_check": True},
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record recording contract has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record recording contract checks has unexpected fields: "
        "private_check"
        in result.failures
    )
    assert (
        "central run record recording contract schema is unsupported"
        in result.failures
    )
    assert any(
        failure.startswith("central run record recording contract checks missing")
        for failure in result.failures
    )


def test_detonation_preflight_rejects_loose_recording_contract_blockers(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    contract = payload["recording_contract"]
    assert isinstance(contract, dict)
    checks = contract["checks"]
    assert isinstance(checks, dict)
    checks["detonation"] = False
    contract["recording_ready"] = False
    contract["blockers"] = [" detonation", "detonation", "", 7]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record recording contract blockers[0] must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record recording contract blockers[1] duplicates recording "
        "contract blocker detonation"
        in result.failures
    )
    assert (
        "central run record recording contract blockers[2] must be non-empty"
        in result.failures
    )
    assert (
        "central run record recording contract blockers[3] must be a string"
        in result.failures
    )


def test_detonation_preflight_rejects_recording_contract_section_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload.pop("provider_playbook")
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record recording contract checks.provider_playbook "
        "has no provider_playbook proof"
        in result.failures
    )


def test_detonation_preflight_requires_embedded_worker_replacement_drill(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload.pop("worker_replacement_drill")
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record recording contract checks.worker_replacement "
        "has no worker_replacement_drill proof"
        in result.failures
    )


def test_detonation_preflight_rejects_pending_embedded_worker_replacement_drill(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["worker_replacement_drill"] = {
        "schema_version": "fusekit.worker-replacement-drill.v1",
        "status": "pending",
        "worker_destroyed": False,
        "replacement_runner_profile_ready": False,
        "control_room_reopened": False,
        "resume_checkpoint_restored": False,
        "gate_or_verifier_resumed": False,
        "host_machine_state_required": True,
        "volatile_state_reused": True,
        "restored_from": [],
        "statement": "Worker replacement is pending.",
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record worker replacement drill did not pass"
        in result.failures
    )
    assert (
        "central run record worker replacement drill requires host-machine state"
        in result.failures
    )


def test_detonation_preflight_rejects_loose_embedded_worker_replacement_drill(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    drill = payload["worker_replacement_drill"]
    assert isinstance(drill, dict)
    drill["private_note"] = "sidecar drill note"
    drill["schema_version"] = " fusekit.worker-replacement-drill.v1 "
    drill["status"] = " passed "
    restored_from = drill["restored_from"]
    assert isinstance(restored_from, list)
    restored_from[0] = f" {restored_from[0]} "
    drill["pending_reason"] = " already passed "
    drill["statement"] = f" {drill['statement']} "
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record worker replacement drill has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record worker replacement drill schema_version must be trimmed"
        in result.failures
    )
    assert (
        "central run record worker replacement drill has unsupported schema"
        in result.failures
    )
    assert (
        "central run record worker replacement drill status must be trimmed"
        in result.failures
    )
    assert (
        "central run record worker replacement drill did not pass"
        in result.failures
    )
    assert (
        "central run record worker replacement drill restored_from[0] must be trimmed"
        in result.failures
    )
    assert (
        "central run record worker replacement drill restore sources must match "
        "durable source ids"
        in result.failures
    )
    assert (
        "central run record worker replacement drill pending_reason must be trimmed"
        in result.failures
    )
    assert (
        "central run record worker replacement drill statement must be trimmed"
        in result.failures
    )


def test_detonation_preflight_rejects_scalar_recording_contract_section_proof(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["provider_playbook"] = "present"
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record recording contract checks.provider_playbook "
        "has no provider_playbook proof"
        in result.failures
    )


def test_detonation_preflight_rejects_placeholder_provider_playbook(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["provider_playbook"] = {"steps": [{"id": "github.capture_token"}]}
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record provider playbook schema is unsupported" in result.failures
    assert (
        "central run record provider playbook is missing public provider coverage: "
        "dns, github, resend, vercel"
        in result.failures
    )


def test_detonation_preflight_rejects_uncontrolled_provider_playbook(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    playbook = payload["provider_playbook"]
    assert isinstance(playbook, dict)
    steps = playbook["steps"]
    assert isinstance(steps, list)
    resend_capture = next(
        step
        for step in steps
        if isinstance(step, dict) and step.get("id") == "resend.capture_key"
    )
    resend_domain = next(
        step
        for step in steps
        if isinstance(step, dict) and step.get("id") == "resend.domain_api"
    )
    vercel_env = next(
        step
        for step in steps
        if isinstance(step, dict) and step.get("id") == "vercel.env_api"
    )
    dns_approval = next(
        step
        for step in steps
        if isinstance(step, dict) and step.get("id") == "dns.approval"
    )
    assert isinstance(resend_capture, dict)
    assert isinstance(resend_domain, dict)
    assert isinstance(vercel_env, dict)
    assert isinstance(dns_approval, dict)
    resend_capture["control"] = " Copy RESEND_API_KEY from VM clipboard "
    resend_capture["resume_event"] = "resume_requested"
    resend_capture["private_note"] = "sidecar route-plan note"
    resend_domain["instruction"] = "Click Add Domain in Resend."
    resend_domain["actor"] = "You"
    resend_domain["control"] = "I finished this step"
    resend_domain["proof_source"] = "gate_events.jsonl"
    dns_approval["actor"] = "FuseKit"
    dns_approval["control"] = "Manually apply DNS"
    steps.remove(dns_approval)
    steps.insert(2, dns_approval)
    safety_notes = playbook["safety_notes"]
    assert isinstance(safety_notes, list)
    safety_notes[0] = f" {safety_notes[0]} "
    safety_notes.append("Open the host browser and use Capture <TARGET> from VM clipboard.")
    safety_notes.append(safety_notes[1])
    strategies = payload["provider_strategies"]
    assert isinstance(strategies, dict)
    strategies["playbook"] = playbook
    artifact = dict(strategies)
    artifact["playbook"] = playbook
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")
    survivors["provider_strategies"].write_text(json.dumps(artifact), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record provider playbook steps[1].control must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[1] has unexpected fields: "
        "private_note"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[1].control must be an "
        "env-named Capture control"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[1].control must capture "
        "RESEND_API_KEY before Resend API setup"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[1].resume_event must be "
        "clipboard_captured -> resume_requested for capture routes"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[2].actor must be You for "
        "human_follow_me routes"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[3].actor must be FuseKit for "
        "api routes"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[3].instruction asks for "
        "unsafe provider work"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[3].control must be "
        "FuseKit API worker for api routes"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[3].proof_source must be "
        "setup_receipt.json for deterministic routes"
        in result.failures
    )
    assert (
        "central run record provider playbook steps[2].control must be a known "
        "follow-me control"
        in result.failures
    )
    assert (
        "central run record provider playbook steps must place "
        "resend.domain_api before dns.approval"
        in result.failures
    )
    assert (
        "central run record provider playbook safety_notes[3] uses placeholder "
        "Capture guidance"
        in result.failures
    )
    assert (
        "central run record provider playbook safety_notes[3] contains "
        "non-launcher wording: local browser/host browser"
        in result.failures
    )
    assert (
        "central run record provider playbook safety_notes[0] must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record provider playbook safety_notes[4] duplicates "
        "generated safety guidance"
        in result.failures
    )


def test_detonation_preflight_rejects_placeholder_provider_strategies(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    strategies = payload["provider_strategies"]
    assert isinstance(strategies, dict)
    providers = strategies["providers"]
    assert isinstance(providers, list)
    first_provider = providers[0]
    assert isinstance(first_provider, dict)
    strategy_rows = first_provider["strategies"]
    assert isinstance(strategy_rows, list)
    first_strategy = strategy_rows[0]
    assert isinstance(first_strategy, dict)
    first_strategy["recipe"] = ""
    decision = first_strategy["decision"]
    assert isinstance(decision, dict)
    selected = decision["selected"]
    assert isinstance(selected, dict)
    selected.pop("status")
    selected["deterministic"] = "false"
    selected.pop("implemented")
    selected["reason"] = ""
    decision["candidates"] = ["browser_guided", {"kind": "browser_guided"}]
    first_strategy.pop("follow_steps")
    first_strategy["next_action"] = ""
    first_strategy.pop("resume_hint")
    first_strategy["success_criteria"] = []
    first_strategy.pop("avoid_steps")
    artifact = dict(strategies)
    artifact["playbook"] = payload["provider_playbook"]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")
    survivors["provider_strategies"].write_text(json.dumps(artifact), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record provider_strategies providers[0].strategies[0].recipe is missing"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "decision.selected.status is missing"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "decision.selected.deterministic must be boolean"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "decision.selected.implemented must be boolean"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "decision.selected.reason is missing"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "decision.candidates[0] is not an object"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "decision.candidates[1].status is missing"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "follow_steps is missing"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "next_action is missing"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "resume_hint is missing"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "success_criteria is missing"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[0].strategies[0]."
        "avoid_steps is missing"
        in result.failures
    )


def test_detonation_preflight_rejects_resend_strategy_without_api_evidence(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    strategies = payload["provider_strategies"]
    assert isinstance(strategies, dict)
    providers = strategies["providers"]
    assert isinstance(providers, list)
    resend_provider = next(
        provider
        for provider in providers
        if isinstance(provider, dict) and provider.get("provider") == "resend"
    )
    assert isinstance(resend_provider, dict)
    strategy_rows = resend_provider["strategies"]
    assert isinstance(strategy_rows, list)
    resend_strategy = strategy_rows[0]
    assert isinstance(resend_strategy, dict)
    decision = resend_strategy["decision"]
    assert isinstance(decision, dict)
    selected = decision["selected"]
    assert isinstance(selected, dict)
    selected["evidence"] = {
        "api_owns": "manual-domain",
        "user_manual_domain_step": "true",
    }
    artifact = dict(strategies)
    artifact["playbook"] = payload["provider_playbook"]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")
    survivors["provider_strategies"].write_text(json.dumps(artifact), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record provider_strategies providers[1].strategies[0]."
        "decision.selected.evidence.api_owns must be domain"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[1].strategies[0]."
        "decision.selected.evidence.user_manual_domain_step must be false"
        in result.failures
    )
    assert (
        "central run record provider_strategies providers[1].strategies[0]."
        "decision.selected.evidence.downstream_order must be before_dns_apply"
        in result.failures
    )


def test_detonation_preflight_rejects_thin_verifier_summary(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["verifiers"] = {
        "schema_version": "fusekit.verifier-summary.v1",
        "overall": "passed",
        "all_passed_or_pending_safe": True,
        "counts": {
            "passed": 1,
            "pending_safe": 0,
            "skipped": 0,
            "pending": 0,
            "repairing": 0,
            "failed": 0,
            "needs_human_gate": 0,
            "unknown": 0,
        },
        "checks": [{"provider": "github", "check": "repo_secret_exists", "status": "passed"}],
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record verifier summary is missing public provider coverage: "
        "dns, resend, vercel"
        in result.failures
    )
    assert "central run record verifier summary is missing live_app coverage" in result.failures
    assert (
        "central run record verifier summary statement is missing live-verifier guidance"
        in result.failures
    )


def test_detonation_preflight_rejects_skipped_public_verifier_coverage(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    checks = payload["verifiers"]["checks"]
    assert isinstance(checks, list)
    vercel = next(check for check in checks if check["provider"] == "vercel")
    vercel["status"] = "skipped"
    counts = payload["verifiers"]["counts"]
    assert isinstance(counts, dict)
    counts["passed"] = 4
    counts["skipped"] = 1
    payload["verification"] = {"checks": checks}
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")
    survivors["verification_report"].write_text(
        json.dumps({"checks": checks}),
        encoding="utf-8",
    )

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record verifier summary is missing public provider coverage: vercel"
        in result.failures
    )
    assert (
        "central run record verifier summary statement must explain skipped "
        "verifier rows do not count as proof"
        in result.failures
    )


def test_detonation_preflight_rejects_loose_verifier_summary_rows(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    checks = payload["verifiers"]["checks"]
    assert isinstance(checks, list)
    first = checks[0]
    assert isinstance(first, dict)
    first["provider"] = " github "
    first["check"] = " repo_access "
    first["status"] = " passed "
    first["pending_safe"] = "false"
    first["private_note"] = "sidecar verifier note"
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record verifier summary checks[0].provider must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record verifier summary checks[0].check must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record verifier summary checks[0].status must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record verifier summary checks[0].pending_safe must be boolean"
        in result.failures
    )
    assert (
        "central run record verifier summary checks[0] has unexpected fields: "
        "private_note"
        in result.failures
    )


def test_detonation_preflight_rejects_skipped_rollback_proof(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["rollback_metadata"].write_text(
        json.dumps(
            {
                "rollback": [
                    {
                        "action": "rollback.github.secret",
                        "status": "skipped",
                        "detail": "missing repo or secret",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "rollback metadata has no provider rollback actions" in result.failures


def test_detonation_preflight_rejects_loose_rollback_metadata_shape(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["rollback_metadata"].write_text(
        json.dumps(
            {
                "rollback": [
                    {
                        "action": " rollback.github.secret ",
                        "status": "planned",
                        "detail": "provider-native rollback/revoke/delete where supported",
                        "private_note": "sidecar",
                    }
                ],
                "private_note": "sidecar",
            }
        ),
        encoding="utf-8",
    )

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "rollback metadata has unexpected fields: private_note" in result.failures
    assert (
        "rollback metadata.rollback[0] has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "rollback metadata.rollback[0].action must not have surrounding whitespace"
        in result.failures
    )


def test_detonation_preflight_rejects_verification_report_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    report = json.loads(survivors["verification_report"].read_text(encoding="utf-8"))
    checks = report["checks"]
    assert isinstance(checks, list)
    first = checks[0]
    assert isinstance(first, dict)
    first["check"] = "repo_exists"
    survivors["verification_report"].write_text(json.dumps(report), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record verifiers must match verification_report.json"
        in result.failures
    )
    assert (
        "central run record verification must match verification_report.json"
        in result.failures
    )


def test_detonation_preflight_rejects_non_object_json_survivor(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["verification_report"].write_text(
        json.dumps([{"checks": []}]),
        encoding="utf-8",
    )

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "verification report artifact must be a JSON object" in result.failures


def test_detonation_preflight_rejects_provider_strategy_route_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    strategies = json.loads(survivors["provider_strategies"].read_text(encoding="utf-8"))
    providers = strategies["providers"]
    assert isinstance(providers, list)
    first_provider = providers[0]
    assert isinstance(first_provider, dict)
    strategy_rows = first_provider["strategies"]
    assert isinstance(strategy_rows, list)
    first_strategy = strategy_rows[0]
    assert isinstance(first_strategy, dict)
    first_strategy["status"] = "stale"
    survivors["provider_strategies"].write_text(json.dumps(strategies), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record provider_strategies must match "
        "provider_strategies.json route decisions"
        in result.failures
    )


def test_detonation_preflight_rejects_provider_strategy_proof_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    strategies = json.loads(survivors["provider_strategies"].read_text(encoding="utf-8"))
    providers = strategies["providers"]
    assert isinstance(providers, list)
    first_provider = providers[0]
    assert isinstance(first_provider, dict)
    strategy_rows = first_provider["strategies"]
    assert isinstance(strategy_rows, list)
    first_strategy = strategy_rows[0]
    assert isinstance(first_strategy, dict)
    decision = first_strategy["decision"]
    assert isinstance(decision, dict)
    selected = decision["selected"]
    assert isinstance(selected, dict)
    selected["reason"] = "Stale launch proof only said a browser was available."
    first_strategy["follow_steps"] = ["Open a stale provider gate."]
    survivors["provider_strategies"].write_text(json.dumps(strategies), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record provider_strategies must match "
        "provider_strategies.json route decisions"
        in result.failures
    )


def test_detonation_preflight_rejects_loose_provider_strategy_artifact_shape(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    strategies = json.loads(survivors["provider_strategies"].read_text(encoding="utf-8"))
    strategies["private_note"] = "non-secret sidecar"
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
    playbook = strategies["playbook"]
    assert isinstance(playbook, dict)
    steps = playbook["steps"]
    assert isinstance(steps, list)
    first_step = steps[0]
    assert isinstance(first_step, dict)
    first_step["private_note"] = "sidecar"
    survivors["provider_strategies"].write_text(json.dumps(strategies), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "provider strategies has unexpected fields: private_note" in result.failures
    assert (
        "provider strategies.providers[0] has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "provider strategies.providers[0].strategies[0] has unexpected fields: "
        "private_note"
        in result.failures
    )
    assert (
        "provider strategies.providers[0].strategies[0].recipe must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "provider strategies.providers[0].strategies[0].decision has unexpected "
        "fields: private_note"
        in result.failures
    )
    assert (
        "provider strategies.providers[0].strategies[0].decision.selected has "
        "unexpected fields: private_note"
        in result.failures
    )
    assert (
        "provider strategies.providers[0].strategies[0].decision.candidates[0] "
        "has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "provider strategies.playbook steps[0] has unexpected fields: private_note"
        in result.failures
    )


def test_detonation_preflight_rejects_provider_playbook_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    strategies = json.loads(survivors["provider_strategies"].read_text(encoding="utf-8"))
    playbook = strategies["playbook"]
    assert isinstance(playbook, dict)
    steps = playbook["steps"]
    assert isinstance(steps, list)
    first_step = steps[0]
    assert isinstance(first_step, dict)
    first_step["instruction"] = "Stale instruction: open a host browser."
    survivors["provider_strategies"].write_text(json.dumps(strategies), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record provider_playbook must match "
        "provider_strategies.json playbook"
        in result.failures
    )


def test_detonation_preflight_rejects_incomplete_runner_readiness(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    readiness = _runner_readiness()
    checks = readiness["checks"]
    assert isinstance(checks, dict)
    checks["openclaw"] = False
    survivors["runner_readiness"].write_text(json.dumps(readiness), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "runner readiness openclaw must be true" in result.failures


def test_detonation_preflight_rejects_runner_readiness_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    readiness = _runner_readiness()
    observed = readiness["observed"]
    assert isinstance(observed, dict)
    observed["memory_mib"] = 16384
    survivors["runner_readiness"].write_text(json.dumps(readiness), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record runner_profile must match runner_readiness.json"
        in result.failures
    )


def test_detonation_preflight_rejects_loose_runner_readiness_artifact(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    readiness = _runner_readiness()
    readiness["private_note"] = "sidecar readiness note"
    readiness["status"] = " ready "
    checks = readiness["checks"]
    assert isinstance(checks, dict)
    checks["openclaw "] = True
    profile = readiness["profile_contract"]
    assert isinstance(profile, dict)
    profile["private_note"] = "sidecar profile note"
    browser_stack = profile["browser_stack"]
    assert isinstance(browser_stack, dict)
    browser_stack["private_note"] = "sidecar browser note"
    health_checks = profile["required_health_checks"]
    assert isinstance(health_checks, list)
    health_checks[0] = f" {health_checks[0]} "
    observed = readiness["observed"]
    assert isinstance(observed, dict)
    observed["private_note"] = "sidecar observed note"
    installed = readiness["installed_binaries"]
    assert isinstance(installed, dict)
    python_binary = installed["python"]
    assert isinstance(python_binary, dict)
    python_binary["private_note"] = "sidecar binary note"
    python_binary["path"] = f" {python_binary['path']} "
    survivors["runner_readiness"].write_text(json.dumps(readiness), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "runner readiness artifact has unexpected fields: private_note" in result.failures
    assert "runner readiness status must be trimmed" in result.failures
    assert "runner readiness checks.openclaw  must be trimmed" in result.failures
    assert (
        "runner readiness runner profile has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "runner readiness runner profile browser_stack has unexpected fields: "
        "private_note" in result.failures
    )
    assert (
        "runner readiness runner profile required_health_checks[0] must be trimmed"
        in result.failures
    )
    assert "runner readiness observed has unexpected fields: private_note" in result.failures
    assert (
        "runner readiness installed_binaries.python has unexpected fields: private_note"
        in result.failures
    )
    assert "runner readiness installed_binaries.python.path must be trimmed" in result.failures


def test_detonation_preflight_rejects_loose_visual_state_artifact(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    visual = _visual_state()
    visual["private_note"] = "sidecar visual proof"
    visual["status"] = " ready "
    visual["display"] = ":44"
    visual["novnc_url"] = (
        "http://93.184.216.34:6080/vnc.html?autoconnect=1&password=leaked"
    )
    visual["control_room_url"] = (
        "http://93.184.216.34:8765/callback"
        "?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
    )
    visual["notes"] = [
        "The browser is running on the disposable OCI VM.",
        " The browser is running on the disposable OCI VM. ",
    ]
    survivors["visual_state"].write_text(json.dumps(visual), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "visual state artifact has unexpected fields: private_note" in result.failures
    assert "visual state status must be trimmed" in result.failures
    assert "visual state status must be ready" in result.failures
    assert "visual state display must be :99" in result.failures
    assert "visual state novnc_url must be a safe public noVNC URL" in result.failures
    assert (
        "visual state control_room_url must be a safe public control-room URL"
        in result.failures
    )
    assert "visual state notes is duplicated" in result.failures
    assert "visual state notes must match generated visual-session guidance" in result.failures
    assert "visual state notes[1] must be trimmed" in result.failures
    assert (
        "central run record evidence inventory visual[0].path must exist in survivor artifacts"
        not in result.failures
    )


def test_detonation_preflight_rejects_placeholder_human_action_trace(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["human_actions"] = {
        "actions": [
            {
                "id": "human-github-token",
                "gate_id": " provider.github.authorization ",
            }
        ]
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record human action trace schema is unsupported" in result.failures
    assert "central run record human action trace total must match actions" in result.failures
    assert (
        "central run record human action trace counts.open_provider_gate "
        "must match actions"
        in result.failures
    )
    assert (
        "central run record human action trace actions[0].gate_id must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record human action trace actions[0] has unexpected fields: id"
        in result.failures
    )
    assert (
        "central run record human action trace statement is incomplete"
        in result.failures
    )


def test_detonation_preflight_rejects_rehearsal_review_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    review = payload["rehearsal_review"]
    assert isinstance(review, dict)
    review["reviewed_actions"] = [
        {
            "gate_id": "provider.other.authorization",
            "action": "capture_vm_clipboard",
            "visible_control": " Capture OTHER_TOKEN from VM clipboard ",
            "target": "OTHER_TOKEN",
            "matched": False,
            "proof_source": "gates.json",
            "private_note": "sidecar review note",
        }
    ]
    review["matched_control_count"] = 0
    review["requires_user_thinking"] = True
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record rehearsal review matched count must match human actions"
        in result.failures
    )
    assert "central run record rehearsal review must require no user thinking" in result.failures
    assert (
        "central run record rehearsal review reviewed_actions[0].gate_id "
        "must match human_actions.actions"
        in result.failures
    )
    assert (
        "central run record rehearsal review reviewed_actions[0].matched must be true"
        in result.failures
    )
    assert (
        "central run record rehearsal review reviewed_actions[0].visible_control "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record rehearsal review reviewed_actions[0] has unexpected "
        "fields: private_note"
        in result.failures
    )
    assert (
        "central run record rehearsal review reviewed_actions[0].proof_source "
        "must match the action"
        in result.failures
    )


def test_detonation_preflight_requires_human_actions_when_gates_exist(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["human_actions"] = {
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
    payload["rehearsal_review"] = {
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
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record human action trace actions are required when "
        "provider gates or wake events exist"
        in result.failures
    )
    assert (
        "central run record rehearsal review reviewed actions must include "
        "guided human actions when provider gates or wake events exist"
        in result.failures
    )


def test_detonation_preflight_rejects_placeholder_provider_gates(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["provider_gates"] = {"records": [{"id": "provider.github.authorization"}]}
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record provider gates statuses are missing" in result.failures
    assert "central run record provider gates providers are missing" in result.failures
    assert (
        "central run record provider gates total must be a literal integer"
        in result.failures
    )
    assert (
        "central run record provider gates records[0].status is missing"
        in result.failures
    )
    assert (
        "central run record provider gates records[0].provider is missing"
        in result.failures
    )


def test_detonation_preflight_rejects_float_provider_gate_counts(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    gates = payload["provider_gates"]
    assert isinstance(gates, dict)
    gates["total"] = 1.9
    statuses = gates["statuses"]
    assert isinstance(statuses, dict)
    statuses["captured"] = 1.9
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record provider gates total must be a literal integer"
        in result.failures
    )
    assert (
        "central run record provider gates statuses.captured must be a literal integer"
        in result.failures
    )
    assert (
        "central run record provider gates statuses.captured must match records"
        in result.failures
    )


def test_detonation_preflight_rejects_loose_provider_gate_shape(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["provider_gates"] = {
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
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record provider gates has unexpected fields: private_note"
        in result.failures
    )
    assert "central run record provider gates providers[0] must be trimmed" in (
        result.failures
    )
    assert "central run record provider gates statuses. captured  must be trimmed" in (
        result.failures
    )
    assert (
        "central run record provider gates records[0] has unexpected fields: "
        "private_note"
    ) in result.failures
    assert "central run record provider gates records[0].id must be trimmed" in (
        result.failures
    )
    assert "central run record provider gates records[0].target must be trimmed" in (
        result.failures
    )
    assert (
        "central run record provider gates records[0].captured_targets[0] must be trimmed"
        in result.failures
    )
    assert (
        "central run record provider gates records[0].follow_steps[0] must be trimmed"
        in result.failures
    )
    assert (
        "central run record provider gates records[0].attempts must be a "
        "non-negative integer"
    ) in result.failures
    assert (
        "central run record provider gates records[0].updated_at must be a "
        "non-negative timestamp"
    ) in result.failures


def test_detonation_preflight_rejects_wake_event_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["wake_events"] = {
        "total": 2,
        "event_counts": {"clipboard_captured": 2},
        "events": [
            {
                "id": "wake-github-token",
                "event": "clipboard_captured",
                "gate_id": "provider.github.authorization",
                "target": "OTHER_TOKEN",
            },
            {
                "id": "wake-github-token",
                "event": "clipboard_captured",
                "gate_id": "provider.github.authorization",
                "target": "OTHER_TOKEN",
            },
        ],
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record wake events[1].id is duplicated" in result.failures
    assert "central run record wake events[1] is duplicated" in result.failures
    assert (
        "central run record provider gate provider.github.authorization "
        "captured target GITHUB_TOKEN has no wake event"
        in result.failures
    )


def test_detonation_preflight_rejects_loose_wake_event_shape(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["wake_events"] = {
        "total": "1",
        "event_counts": {" clipboard_captured ": "1"},
        "private_note": "sidecar wake proof",
        "events": [
            {
                "schema_version": "fusekit.gate-wake.v1",
                "id": " wake-github-token",
                "event": "clipboard_captured",
                "gate_id": "provider.github.authorization",
                "provider": "github",
                "classification": "authorization",
                "status": "captured",
                "target": " GITHUB_TOKEN ",
                "target_count": "1",
                "captured_targets": [" GITHUB_TOKEN "],
                "created_at": -1,
                "private_note": "sidecar wake proof",
            }
        ],
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record wake events has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record wake events total must be a literal integer"
        in result.failures
    )
    assert (
        "central run record wake events[0] has unexpected fields: private_note"
        in result.failures
    )
    assert "central run record wake events[0].id must be trimmed" in result.failures
    assert "central run record wake events[0].target must be trimmed" in result.failures
    assert (
        "central run record wake events[0].target_count must be a non-negative integer"
        in result.failures
    )
    assert (
        "central run record wake events[0].captured_targets[0] must be trimmed"
        in result.failures
    )
    assert (
        "central run record wake events[0].created_at must be a non-negative timestamp"
        in result.failures
    )
    assert (
        "central run record wake event counts. clipboard_captured  must be trimmed"
        in result.failures
    )
    assert (
        "central run record wake event counts. clipboard_captured  "
        "must be a literal integer"
    ) in result.failures


def test_detonation_preflight_rejects_gates_artifact_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    gates = json.loads(survivors["gates"].read_text(encoding="utf-8"))
    gate_rows = gates["gates"]
    assert isinstance(gate_rows, list)
    first_gate = gate_rows[0]
    assert isinstance(first_gate, dict)
    first_gate["status"] = "waiting"
    survivors["gates"].write_text(json.dumps(gates), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record provider_gates must match gates.json" in result.failures


def test_detonation_preflight_rejects_loose_gates_artifact_shape(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    gates = _provider_gates()
    gates["sidecar"] = "loose provider gate proof"
    gate_rows = gates["gates"]
    assert isinstance(gate_rows, list)
    gate_rows[0]["id"] = " provider.github.authorization"
    gate_rows[0]["captured_targets"] = [" GITHUB_TOKEN "]
    gate_rows[0]["attempts"] = True
    gate_rows[0]["updated_at"] = -1
    gate_rows[0]["sidecar"] = "loose provider gate proof"
    survivors["gates"].write_text(json.dumps(gates), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "provider gates has unexpected fields: sidecar" in result.failures
    assert "provider gates.gates[0] has unexpected fields: sidecar" in result.failures
    assert "provider gates.gates[0].id must be trimmed" in result.failures
    assert "provider gates.gates[0].captured_targets[0] must be trimmed" in (
        result.failures
    )
    assert "provider gates.gates[0].attempts must be a non-negative integer" in (
        result.failures
    )
    assert "provider gates.gates[0].updated_at must be a non-negative timestamp" in (
        result.failures
    )


def test_detonation_preflight_rejects_gate_events_artifact_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    events = _gate_events()
    events[0]["target"] = "OTHER_TOKEN"
    survivors["gate_events"].write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record wake_events must match gate_events.jsonl" in result.failures


def test_detonation_preflight_rejects_loose_gate_events_artifact_shape(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    events = _gate_events()
    events[0]["id"] = " wake-github-token"
    events[0]["sidecar"] = "loose wake proof"
    survivors["gate_events"].write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "gate_events[1] has unexpected fields: sidecar" in result.failures


def test_detonation_preflight_rejects_empty_gate_events_artifact(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["gate_events"].write_text("", encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record wake_events must match gate_events.jsonl" in result.failures


def test_detonation_preflight_rejects_unsafe_artifact_rows(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["artifacts"] = [
        {"name": "audit", "path": "audit.jsonl", "exists": True},
        {"name": "audit", "path": "../audit.jsonl", "exists": "yes"},
        {"name": "debug?token=secret", "path": "debug.log?token=secret", "exists": True},
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record artifacts[1].name is duplicated" in result.failures
    assert "central run record artifacts[1].exists must be boolean" in result.failures
    assert "central run record artifacts[1].path must be public-relative" in result.failures
    assert (
        "central run record artifacts[2].name contains credential query text"
        in result.failures
    )
    assert (
        "central run record artifacts[2].path contains credential query text"
        in result.failures
    )


def test_detonation_preflight_rejects_loose_artifact_and_evidence_rows(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()

    artifacts = payload["artifacts"]
    assert isinstance(artifacts, list)
    artifact = artifacts[0]
    assert isinstance(artifact, dict)
    artifact["private_note"] = "sidecar artifact note"
    artifact["name"] = " run_record "
    artifact["path"] = " run_record.json "
    artifact["exists"] = 1

    evidence = payload["evidence"]
    assert isinstance(evidence, dict)
    evidence["private_note"] = "sidecar evidence note"
    evidence["schema_version"] = " fusekit.evidence-inventory.v1 "
    evidence["statement"] = f" {evidence['statement']} "
    counts = evidence["counts"]
    assert isinstance(counts, dict)
    counts["private_note"] = 1
    counts["logs"] = True
    logs = evidence["logs"]
    assert isinstance(logs, list)
    log = logs[0]
    assert isinstance(log, dict)
    log["private_note"] = "sidecar log note"
    log["path"] = " audit.jsonl "
    log["kind"] = " log "
    log["source"] = " known-proof "
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record artifacts[0] has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record artifacts[0].name must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record artifacts[0].path must not have surrounding whitespace"
        in result.failures
    )
    assert "central run record artifacts[0].exists must be boolean" in result.failures
    assert (
        "central run record evidence inventory has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record evidence inventory schema_version "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert "central run record evidence inventory schema is unsupported" in result.failures
    assert (
        "central run record evidence inventory statement "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record evidence inventory counts has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record evidence inventory logs count must be an integer"
        in result.failures
    )
    assert (
        "central run record evidence inventory logs[0] has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record evidence inventory logs[0].path "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record evidence inventory logs[0].kind "
        "must not have surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record evidence inventory logs[0].source "
        "must not have surrounding whitespace"
        in result.failures
    )


def test_detonation_preflight_rejects_invented_artifact_survivor_path(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    artifacts = payload["artifacts"]
    assert isinstance(artifacts, list)
    artifacts.append(
        {"name": "phantom_artifact", "path": "phantom.json", "exists": True}
    )
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record artifacts[4].path must exist in survivor artifacts"
        in result.failures
    )


def test_detonation_preflight_rejects_placeholder_evidence_inventory(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["evidence"] = {
        "logs": [{"path": "audit.jsonl", "kind": "receipt", "exists": True}],
        "screenshots": "missing",
        "visual": [{"path": "", "kind": "visual", "exists": False}],
        "receipts": [],
        "counts": {"logs": 2, "screenshots": 0, "visual": 1, "receipts": 0},
        "statement": "evidence files",
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "central run record evidence inventory schema is unsupported" in result.failures
    assert "central run record evidence inventory logs count must match rows" in result.failures
    assert "central run record evidence inventory logs[0].kind must be log" in result.failures
    assert "central run record evidence inventory screenshots are missing" in result.failures
    assert "central run record evidence inventory visual[0].path is missing" in result.failures
    assert "central run record evidence inventory visual[0].exists must be true" in result.failures
    assert "central run record evidence inventory must include receipts" in result.failures
    assert "central run record evidence inventory statement is incomplete" in result.failures


def test_detonation_preflight_rejects_invented_evidence_survivor_path(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    evidence = payload["evidence"]
    assert isinstance(evidence, dict)
    screenshots = evidence["screenshots"]
    assert isinstance(screenshots, list)
    screenshot = screenshots[0]
    assert isinstance(screenshot, dict)
    screenshot["path"] = "screenshots/missing-control-room.png"
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record evidence inventory screenshots[0].path "
        "must exist in survivor artifacts"
        in result.failures
    )


def test_detonation_preflight_requires_explicit_detonation_blocker(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    contract = payload["recording_contract"]
    assert isinstance(contract, dict)
    contract["blockers"] = []
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record recording contract must name detonation as "
        "the only preflight blocker"
        in result.failures
    )


def test_detonation_preflight_rejects_placeholder_audit_trail(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["audit_trail"] = {
        "schema_version": "fusekit.audit-trail.v1",
        "entry_count": 1,
        "counts": {"credential_capture": 0},
        "entries": [
            {
                "category": "credential_capture",
                "action": " control_room.capture_vm_clipboard ",
                "provider": "github",
                "target": "GITHUB_TOKEN",
                "status": " captured ",
                "source": "gate_events.jsonl",
                "summary": " Captured credential proof exists. ",
                "private_note": "sidecar audit note",
            }
        ],
        "statement": "Audit proof exists.",
    }
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record audit trail entries[0] has unexpected fields: private_note"
        in result.failures
    )
    assert (
        "central run record audit trail entries[0].action must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record audit trail entries[0].status must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record audit trail entries[0].summary must not have "
        "surrounding whitespace"
        in result.failures
    )
    assert (
        "central run record audit trail entries[0].wake_event_id is missing"
        in result.failures
    )
    assert (
        "central run record audit trail counts.credential_capture must match entries"
        in result.failures
    )
    assert "central run record audit trail statement is incomplete" in result.failures


def test_detonation_preflight_rejects_errors_empty_drift(
    tmp_path,
) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["errors"] = [
        {
            "source": "verification",
            "id": "resend.domain",
            "detail": "Resend domain verification still needs repair.",
        }
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert (
        "central run record recording contract checks.errors_empty must match errors"
        in result.failures
    )


def test_detonation_preflight_rejects_secret_text_in_run_record(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["errors"] = [
        {
            "id": "provider.callback",
            "detail": "Callback failed at https://provider.example/callback?code=secret-code",
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
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any("credential-looking text" in failure for failure in result.failures)
    assert (
        "central run record errors[1].source must not have surrounding whitespace"
        in result.failures
    )
    assert "central run record errors[1] has unexpected fields: private_note" in (
        result.failures
    )
    assert (
        "central run record errors[2] duplicates error verification:resend.domain"
        in result.failures
    )


def test_detonation_preflight_rejects_callback_url_in_run_record(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    payload["errors"] = [
        {
            "id": "provider.callback",
            "detail": "Provider returned https://provider.example/callback",
        }
    ]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any(
        "central run record.errors[0].detail contains callback URL" in failure
        for failure in result.failures
    )


def test_detonation_preflight_rejects_callback_urls_in_public_survivors(
    tmp_path,
) -> None:
    cases = (
        (
            "receipt",
            "redacted receipt.callback contains callback URL",
            lambda payload: payload.update({"callback": "https://provider.example/callback"}),
        ),
        (
            "verification_report",
            "verification report.checks[0].details.callback contains callback URL",
            lambda payload: payload["checks"][0].update(
                {"details": {"callback": "https://provider.example/callback"}}
            ),
        ),
        (
            "provider_strategies",
            "provider strategies.providers[0].strategies[0].callback contains callback URL",
            lambda payload: payload["providers"][0]["strategies"][0].update(
                {"callback": "https://provider.example/callback"}
            ),
        ),
        (
            "rollback_metadata",
            "rollback metadata.rollback[0].status contains callback URL",
            lambda payload: payload["rollback"][0].update(
                {"status": "planned after https://provider.example/callback"}
            ),
        ),
        (
            "llm_contract",
            "model/inference contract.callback contains callback URL",
            lambda payload: payload.update({"callback": "https://provider.example/callback"}),
        ),
        (
            "runner_readiness",
            "runner readiness.observed.callback contains callback URL",
            lambda payload: payload["observed"].update(
                {"callback": "https://provider.example/callback"}
            ),
        ),
        (
            "gates",
            "provider gates.gates[0].resume_url contains callback URL",
            lambda payload: payload["gates"][0].update(
                {"resume_url": "https://provider.example/callback"}
            ),
        ),
        (
            "worker_replacement_drill",
            "worker replacement drill.callback contains callback URL",
            lambda payload: payload.update({"callback": "https://provider.example/callback"}),
        ),
    )
    for case_name, expected, mutate in cases:
        fusekit = tmp_path / case_name / ".fusekit"
        fusekit.mkdir(parents=True)
        survivors = _write_preflight_survivors(fusekit)
        path = survivors[case_name]
        payload = json.loads(path.read_text(encoding="utf-8"))
        mutate(payload)
        path.write_text(json.dumps(payload), encoding="utf-8")

        result = run_detonation_preflight(root=fusekit.parent, **survivors)

        assert not result.ok, case_name
        assert any(expected in failure for failure in result.failures), result.failures


def test_detonation_preflight_rejects_callback_url_in_gate_events(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    events = _gate_events()
    events[0]["target"] = "https://provider.example/callback"
    survivors["gate_events"].write_text(
        "\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n",
        encoding="utf-8",
    )

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "gate_events[1].target contains callback URL" in result.failures


def test_detonation_preflight_requires_literal_zero_secret_receipt_count(
    tmp_path,
) -> None:
    for index, raw_secret_count in enumerate((None, 1, 0.1, "0", True)):
        fusekit = tmp_path / str(index) / ".fusekit"
        fusekit.mkdir(parents=True)
        survivors = _write_preflight_survivors(fusekit)
        receipt = {"actions": []}
        if raw_secret_count is not None:
            receipt["raw_secrets_exposed"] = raw_secret_count
        survivors["receipt"].write_text(json.dumps(receipt), encoding="utf-8")

        result = run_detonation_preflight(root=fusekit.parent, **survivors)

        assert not result.ok, raw_secret_count
        assert (
            "redacted receipt raw_secrets_exposed must be literal 0"
            in result.failures
        )


def test_detonation_preflight_rejects_loose_setup_receipt_shape(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    receipt = {
        "actions": [
            {
                "action": " github.secret.upsert ",
                "status": "ok",
                "details": {"provider": "github"},
                "private_note": "sidecar",
            }
        ],
        "raw_secrets_exposed": 0,
        "private_note": "sidecar",
    }
    survivors["receipt"].write_text(json.dumps(receipt), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "redacted receipt has unexpected fields: private_note" in result.failures
    assert (
        "redacted receipt.actions[0] has unexpected fields: private_note"
        in result.failures
    )
    assert "redacted receipt.actions[0].action must be trimmed" in result.failures


def test_detonation_preflight_rejects_callback_url_in_audit_log(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["audit"].write_text(
        json.dumps(
            {
                "event": "provider.callback",
                "detail": "Provider returned https://provider.example/callback",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any(
        "audit log[1].detail contains callback URL" in failure
        for failure in result.failures
    )


def test_detonation_preflight_rejects_malformed_audit_log(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["audit"].write_text('{"event":"ok"}\nnot-json\n[]\n', encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any("audit log line 2 is malformed JSON" in failure for failure in result.failures)
    assert any("audit log line 3 is not an object" in failure for failure in result.failures)


def test_detonation_preflight_rejects_empty_audit_log(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["audit"].write_text("\n\n", encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "audit log has no JSON object rows" in result.failures


def test_detonation_preflight_rejects_loose_audit_log_rows(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["audit"].write_text(
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

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert "audit log[1] has unexpected fields: private_note" in result.failures
    assert "audit log[1].event must be trimmed" in result.failures
    assert "audit log[1].data must be an object" in result.failures
    assert "audit log[1].ts must be a string" in result.failures
    assert "audit log[2].event is missing" in result.failures
    assert "audit log[2].ts must be trimmed" in result.failures


def test_detonation_preflight_rejects_plaintext_vault_survivor(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    survivors["vault"].write_text(
        "provider token=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
        encoding="utf-8",
    )

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert not result.ok
    assert any(
        "encrypted vault contains plaintext or credential-looking markers" in failure
        for failure in result.failures
    )


def test_detonation_preflight_allows_redacted_run_record_text(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    survivors = _write_preflight_survivors(fusekit)
    payload = _run_record_payload()
    state = payload["state"]
    assert isinstance(state, dict)
    state["notes"] = ["Provider callback code was [redacted]."]
    survivors["run_record"].write_text(json.dumps(payload), encoding="utf-8")

    result = run_detonation_preflight(root=tmp_path, **survivors)

    assert result.ok


def test_launch_progress_allows_nested_pending_safe_checks() -> None:
    assert verification_report_allows_launch_progress(
        {
            "checks": [
                {
                    "provider": "vercel",
                    "check": "live_url_healthy",
                    "status": "pending",
                    "details": {"details": {"pending_safe": True}},
                },
                {
                    "provider": "vercel",
                    "check": "env_vars_configured",
                    "status": "needs_human_gate",
                    "details": {"details": {"service_gate": True}},
                },
            ]
        }
    )


def test_detonation_preflight_blocks_human_gate_checks(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[],"raw_secrets_exposed":0}', encoding="utf-8")
    report.write_text(
        json.dumps(
            {
                "checks": [
                    {
                        "provider": "vercel",
                        "check": "project_exists",
                        "status": "needs_human_gate",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    rollback.write_text(
        '{"rollback":[{"action":"rollback.vercel.project","status":"planned"}]}',
        encoding="utf-8",
    )
    _write_run_record(run_record)

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
        run_record=run_record,
    )

    assert not result.ok


def test_detonation_preflight_blocks_failed_checks_and_missing_rollback(tmp_path) -> None:
    fusekit = tmp_path / ".fusekit"
    fusekit.mkdir()
    vault = fusekit / "fusekit.vault.json"
    audit = fusekit / "audit.jsonl"
    receipt = fusekit / "setup_receipt.json"
    report = fusekit / "verification_report.json"
    rollback = fusekit / "rollback_plan.json"
    run_record = fusekit / "run_record.json"
    vault.write_text("encrypted", encoding="utf-8")
    audit.write_text('{"event":"ok"}\n', encoding="utf-8")
    receipt.write_text('{"actions":[],"raw_secrets_exposed":0}', encoding="utf-8")
    report.write_text(
        '{"checks":[{"provider":"vercel","check":"env_vars_configured","status":"failed"}]}',
        encoding="utf-8",
    )
    _write_run_record(run_record)

    result = run_detonation_preflight(
        root=tmp_path,
        vault=vault,
        audit=audit,
        receipt=receipt,
        verification_report=report,
        rollback_metadata=rollback,
        run_record=run_record,
    )

    assert not result.ok
    assert any("missing rollback metadata" in failure for failure in result.failures)
    assert any("vercel.env_vars_configured is failed" in failure for failure in result.failures)
