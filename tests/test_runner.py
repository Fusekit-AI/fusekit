from __future__ import annotations

import base64
import http.client
import json
import os
import re
import shlex
import subprocess
import tarfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest
import yaml

from fusekit.audit import AuditLog
from fusekit.errors import FuseKitError, VaultError
from fusekit.rollback import execute_native_rollback, plan_rollback, start_over
from fusekit.runner.broker import resolve_runner
from fusekit.runner.cloud_shell import (
    build_cloud_shell_launch_plan,
    render_cloud_shell_launcher,
)
from fusekit.runner.control_room import (
    control_room_payload as static_control_room_payload,
)
from fusekit.runner.control_room import render_control_room
from fusekit.runner.control_room.events import SCRIPT
from fusekit.runner.control_room.server import (
    CONTROL_ROOM_ROUTE_SURFACE,
    _capture_button_labels,
    _control_room_action_token,
    _control_room_vault_passphrase,
    _trusted_browser_origin,
    _trusted_fetch_site,
    _validate_clipboard_capture_value,
    _visual_browser_binary,
    _visual_browser_env,
    _visual_display,
    _vm_clipboard_text,
)
from fusekit.runner.control_room.views import _render_acceptance_blockers
from fusekit.runner.gates import GateService
from fusekit.runner.job import JobState
from fusekit.runner.loop import run_remote_loop
from fusekit.runner.oci import (
    OciRunnerPlan,
    build_oci_runner_plan,
    capture_oci_api_key_profile,
    prepare_oci_api_signing_key,
)
from fusekit.runner.oci_live import (
    OciAuth,
    OciProvisioner,
    OciWorkspace,
    _load_oci_config_file,
    _oci_client_kwargs,
    _safe_oci_error,
    latest_workspace_from_vault,
    suppress_oci_http_debug_logging,
)
from fusekit.runner.remote import (
    _extract_artifacts,
    detonate_remote_worker,
    execute_remote_setup,
    remote_worker_cleanup_proof,
    render_cloud_init,
    should_include_app_path,
)
from fusekit.runner.run_record import (
    _human_action_trace,
    _recording_audit_trail_ready,
    _recording_automation_boundary_ready,
    _recording_detonation_ready,
    _recording_durable_state_ready,
    _recording_evidence_ready,
    _recording_human_actions_ready,
    _recording_provider_playbook_ready,
    _recording_verifiers_ready,
    _recording_worker_replacement_ready,
    write_run_record,
)
from fusekit.runner.run_state import LaunchRunState, update_run_state
from fusekit.runner.server import _handler, _is_loopback, control_room_payload, serve_control_room
from fusekit.security import scan_for_secret_leaks
from fusekit.vault import Vault

REMOTE_CONTROL_ROOM_TOKEN = "remote_control_room_token_abcdefghijklmnopqrstuvwxyz0123456789"


def _write_runner_readiness(root: Path, *, thin: bool = False) -> None:
    payload: dict[str, Any] = {
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
        "provider_browser_profile": ("/var/lib/fusekit-runner/visual/chrome-provider-profile"),
        "playwright_browsers_path": "/opt/fusekit-playwright-browsers",
    }
    if thin:
        payload["profile_contract"] = {
            "schema_version": "fusekit.runner-profile.v1",
            "name": "oci-visual-browser-x86_64",
        }
        payload["checks"] = {"x86_64_architecture": True}
        payload["provider_browser_profile"] = ""
        payload["playwright_browsers_path"] = ""
    (root / "runner_readiness.json").write_text(json.dumps(payload), encoding="utf-8")


def _control_room_post_headers(root: Path, **extra: str) -> dict[str, str]:
    token = (root / "control-room-action-token").read_text(encoding="utf-8").strip()
    return {
        "x-fusekit-control-room": "resume",
        "x-fusekit-action-token": token,
        **extra,
    }


def _control_room_cookie_from_token(port: int, token: str) -> tuple[str, int, str]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("GET", f"/?token={token}")
    response = connection.getresponse()
    headers = {key.lower(): value for key, value in response.getheaders()}
    response.read()
    connection.close()
    return headers["set-cookie"], response.status, headers.get("location", "")


def _assert_hardened_control_room_error_headers(response: HTTPError) -> None:
    headers = {key.lower(): value for key, value in response.headers.items()}
    assert headers["cache-control"] == "no-store"
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in headers["permissions-policy"]
    assert "microphone=()" in headers["permissions-policy"]
    assert "geolocation=()" in headers["permissions-policy"]
    assert "payment=()" in headers["permissions-policy"]
    assert "usb=()" in headers["permissions-policy"]
    assert "content-security-policy" in headers
    assert "access-control-allow-origin" not in headers
    assert "access-control-allow-methods" not in headers
    assert "access-control-allow-headers" not in headers


def _strategy_decision() -> dict[str, object]:
    return {
        "selected": {
            "kind": "api",
            "status": "available",
            "deterministic": True,
            "implemented": True,
            "reason": "deterministic provider API is available",
            "evidence": {},
        },
        "candidates": [
            {
                "kind": "api",
                "status": "available",
                "deterministic": True,
                "implemented": True,
                "reason": "deterministic provider API is available",
            }
        ],
    }


def test_control_room_capture_label_fallback_uses_active_gate_capture() -> None:
    label = _capture_button_labels(())

    assert "Capture <TARGET>" not in label
    assert "exact env-named Capture button shown on the active launcher gate" in label
    assert "Capture RESEND_API_KEY from VM clipboard" not in label


def test_runner_auto_uses_local_for_explicit_rehearsal(tmp_path) -> None:
    resolution = resolve_runner("auto", allow_incomplete=True, oci_config_file=tmp_path / "nope")

    assert resolution.selected == "local"
    assert resolution.reason == "explicit local rehearsal"


def test_runner_auto_selects_cloud_shell_when_no_config(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("OCI_CONFIG_FILE", raising=False)

    resolution = resolve_runner("auto", oci_config_file=tmp_path / "missing")

    assert resolution.selected == "oci-cloud-shell"


def test_runner_env_override_rejects_unknown_runner(monkeypatch) -> None:
    monkeypatch.setenv("FUSEKIT_RUNNER", "surprise-runner")

    with pytest.raises(FuseKitError, match="Unknown runner"):
        resolve_runner("auto")


def test_oci_runner_plan_defaults_to_x86_only() -> None:
    plan = build_oci_runner_plan(runner="oci")

    assert plan.shape == "VM.Standard.E5.Flex"
    assert plan.ocpus == 2
    assert plan.memory_gb == 24
    assert plan.fallback_shapes == (
        "VM.Standard.E5.Flex:2:24",
        "VM.Standard.E4.Flex:2:24",
        "VM.Standard3.Flex:2:24",
    )
    assert plan.compartment_mode == "root"
    assert plan.resources[0] == "existing_root_compartment"
    assert all("A1" not in fallback for fallback in plan.fallback_shapes)


def test_oci_runner_plan_rejects_isolated_compartment() -> None:
    with pytest.raises(FuseKitError, match="no longer creates OCI compartments"):
        build_oci_runner_plan(runner="oci", compartment_mode="isolated")


def test_oci_runner_plan_rejects_arm_shape() -> None:
    with pytest.raises(FuseKitError, match="ARM-based"):
        build_oci_runner_plan(runner="oci", shape="VM.Standard.A1.Flex")

    with pytest.raises(FuseKitError, match="ARM-based"):
        build_oci_runner_plan(runner="oci", shape="BM.Standard.A1.160")


def test_job_status_preserves_failure_after_cleanup_step(tmp_path) -> None:
    from fusekit.runner.job import JobState

    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "failed", "remote setup failed")
    job.mark("detonate.workspace", "done", "cleanup attempted")

    assert job.status == "failed"


def test_job_state_writes_recovery_checkpoints(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "provider token hidden prompt is open")
    job.upsert_checkpoint(
        "provider.resend.routes",
        "Provider route: resend",
        status="done",
        detail="resend-domain uses api (ok)",
        next_action="Nothing to do manually in Resend.",
        resume_hint="Resend records feed DNS approval.",
        mascot_state="verify",
    )
    job_path = tmp_path / "job.json"

    job.save(job_path)
    checkpoint_payload = json.loads((tmp_path / "checkpoints.json").read_text("utf-8"))

    assert "checkpoints" in job.to_dict()
    assert checkpoint_payload["job_id"] == "fk-test"
    setup = next(
        item for item in checkpoint_payload["checkpoints"] if item["id"] == "setup.execute"
    )
    assert setup["status"] == "running"
    assert setup["mascot_state"] == "privacy"
    assert "Human gates wait forever" in setup["resume_hint"]
    provider = next(
        item for item in checkpoint_payload["checkpoints"] if item["id"] == "provider.resend.routes"
    )
    assert provider["status"] == "done"
    assert provider["detail"] == "resend-domain uses api (ok)"
    assert "Resend records feed DNS approval" in provider["resume_hint"]


def test_run_record_centralizes_resume_audit_and_detonation_state(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci")
    job.mark("setup.execute", "waiting", "Cloudflare token gate is visible")
    (tmp_path / "audit.jsonl").write_text('{"event":"ok"}\n', encoding="utf-8")
    job.add_artifact("audit_log", tmp_path / "audit.jsonl")
    (tmp_path / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "action": "cloudflare.verify",
                        "status": "ok",
                        "details": {"provider": "cloudflare"},
                    }
                ]
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "visual").mkdir()
    (tmp_path / "visual" / "provider-gate.png").write_bytes(b"not-a-real-png")
    (tmp_path / "visual" / "control-room.log").write_text("ready\n", encoding="utf-8")
    (tmp_path / "fusekit.vault.json").write_text("encrypted", encoding="utf-8")
    update_run_state(
        tmp_path / "run_state.json",
        app_repo_known=True,
        runner_selected=True,
        vault_created=True,
        detonation_safe=True,
        workspace_detonated=True,
    )
    gate_service = GateService.load(tmp_path / "gates.json")
    gate_service.wait(
        "provider.cloudflare.authorization",
        provider="cloudflare",
        target="CLOUDFLARE_API_TOKEN",
        reason="Capture Cloudflare API token",
        resume_url="https://dash.cloudflare.com/profile/api-tokens",
    )
    gate_service.mark_opened(
        "provider.cloudflare.authorization",
        "https://dash.cloudflare.com/profile/api-tokens",
    )
    gate_service.mark_captured(
        "provider.cloudflare.authorization",
        "CLOUDFLARE_API_TOKEN",
    )
    (tmp_path / "provider_strategies.json").write_text(
        json.dumps(
            {
                "playbook": {
                    "schema_version": "fusekit.provider-playbook.v1",
                    "steps": [
                            {
                                "id": "cloudflare.capture_key",
                                "provider": "cloudflare",
                                "route": "browser_guided",
                                "control": "Capture CLOUDFLARE_API_TOKEN from VM clipboard",
                                "proof_source": "gate_events.jsonl",
                                "resume_event": "clipboard_captured -> resume_requested",
                                "instruction": (
                                    "Open the provider gate in the VM browser, copy the "
                                    "approved value there, then click Capture "
                                "CLOUDFLARE_API_TOKEN from VM clipboard."
                            ),
                        }
                    ],
                    "safety_notes": [
                        "Use the launcher and shared VM browser for provider gates.",
                        (
                            "Do not create Resend domains or audiences manually; "
                            "FuseKit owns those API setup steps."
                        ),
                        (
                            "Do not paste provider secrets into the host computer; "
                            "Capture reads the VM clipboard."
                        ),
                    ],
                },
                "providers": [{"provider": "cloudflare", "strategies": []}],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "verification_report.json").write_text(
        '{"checks":[{"provider":"cloudflare","status":"pending_safe"}]}',
        encoding="utf-8",
    )
    (tmp_path / "rollback_plan.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "provider": "cloudflare",
                        "action": "cloudflare.dns.rollback",
                        "status": "planned",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "visual.json").write_text(
        json.dumps({"runner": "novnc", "status": "ready"}),
        encoding="utf-8",
    )
    (tmp_path / "workspace_detonation.json").write_text(
        json.dumps(
            {
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
                    "missing": [],
                    "statement": (
                        "FuseKit detonation must remove the remote worker process state, "
                        "terminate the OCI VM, delete the boot volume, release the "
                        "ephemeral public IP, and delete "
                        "FuseKit-created network resources."
                    ),
                },
                "updated_at": 2.0,
            }
        ),
        encoding="utf-8",
    )
    _write_runner_readiness(tmp_path)
    job.save(tmp_path / "job.json")

    record_path = write_run_record(
        job,
        path=tmp_path / "run_record.json",
        vault_index=[
            {
                "id": "provider.cloudflare.token",
                "kind": "provider_token",
                "provider": "cloudflare",
                "label": "Cloudflare API token",
                "metadata": {"source": "vm-clipboard"},
            }
        ],
    )
    record = json.loads(record_path.read_text(encoding="utf-8"))

    assert record["schema_version"] == "fusekit.run-record.v1"
    assert record["id"] == "fk-test"
    assert record["state"]["workspace_detonated"] is True
    assert record["provider_gates"]["total"] == 1
    assert record["provider_gates"]["providers"] == ["cloudflare"]
    assert record["runner_profile"]["status"] == "ready"
    assert record["runner_profile"]["profile_contract"]["name"] == ("oci-visual-browser-x86_64")
    assert record["runner_profile"]["observed"]["memory_mib"] == 24576
    assert record["durable_state"]["schema_version"] == "fusekit.durable-state.v1"
    assert record["durable_state"]["resume_ready"] is True
    assert record["durable_state"]["missing"] == []
    assert record["durable_state"]["runner_profile_ready"] is True
    assert record["durable_state"]["runner_profile_failures"] == []
    assert {item["id"] for item in record["durable_state"]["sources"] if item["exists"]} >= {
        "encrypted_vault",
        "job_state",
        "run_state",
        "checkpoints",
        "gates",
        "gate_events",
        "provider_strategies",
        "runner_readiness",
    }
    assert "visual" in record["durable_state"]["volatile_worker_surfaces"]
    assert record["durable_state"]["detonation_scope"]["schema_version"] == (
        "fusekit.detonation-scope.v1"
    )
    assert record["durable_state"]["detonation_scope"]["mode"] == ("worker-and-oci-workspace")
    assert "provider-auth" in record["durable_state"]["detonation_scope"]["must_delete"]
    assert "run_record" in record["durable_state"]["detonation_scope"]["must_preserve"]
    assert "runner_readiness" in record["durable_state"]["detonation_scope"]["must_preserve"]
    assert record["durable_state"]["detonation_scope"]["resume_until_complete"] is True
    assert record["durable_state"]["detonation_scope"]["host_machine_state_required"] is False
    assert (
        "no FuseKit worker state remains"
        in record["durable_state"]["detonation_scope"]["no_trace_statement"]
    )
    assert record["durable_state"]["worker_replacement_contract"]["can_recreate_worker"] is True
    assert record["durable_state"]["worker_replacement_contract"]["runner_profile_ready"] is True
    assert (
        record["durable_state"]["worker_replacement_contract"]["required_runner_profile"]
        == "oci-visual-browser-x86_64"
    )
    assert (
        record["durable_state"]["worker_replacement_contract"]["host_machine_state_required"]
        is False
    )
    assert record["durable_state"]["worker_replacement_contract"]["runner_profile_failures"] == []
    assert (
        "provider-auth"
        in record["durable_state"]["worker_replacement_contract"]["volatile_surfaces"]
    )
    assert (
        "host clipboard history"
        in record["durable_state"]["worker_replacement_contract"]["statement"]
    )
    assert record["provider_playbook"]["schema_version"] == "fusekit.provider-playbook.v1"
    assert record["provider_playbook"]["step_count"] == 1
    assert "Capture CLOUDFLARE_API_TOKEN" in record["provider_playbook"]["steps"][0]["instruction"]
    assert record["provider_playbook"]["steps"][0]["proof_source"] == "gate_events.jsonl"
    assert record["provider_playbook"]["steps"][0]["resume_event"] == (
        "clipboard_captured -> resume_requested"
    )
    assert record["verifiers"]["schema_version"] == "fusekit.verifier-summary.v1"
    assert record["verifiers"]["all_passed_or_pending_safe"] is True
    assert record["verifiers"]["counts"]["pending_safe"] == 1
    assert record["verifiers"]["checks"][0]["provider"] == "cloudflare"
    assert record["verifiers"]["checks"][0]["status"] == "pending_safe"
    assert record["wake_events"]["total"] == 1
    assert record["wake_events"]["event_counts"] == {
        "clipboard_captured": 1,
    }
    assert record["wake_events"]["events"][0]["target"] == "CLOUDFLARE_API_TOKEN"
    assert record["human_actions"]["schema_version"] == "fusekit.human-action-trace.v1"
    assert record["human_actions"]["total"] == 2
    assert record["human_actions"]["counts"] == {
        "capture_vm_clipboard": 1,
        "open_provider_gate": 1,
    }
    assert record["human_actions"]["unguided"] == []
    controls = {item["visible_control"] for item in record["human_actions"]["actions"]}
    assert "Open provider gate in VM" in controls
    assert "Capture CLOUDFLARE_API_TOKEN from VM clipboard" in controls
    assert "https://dash.cloudflare.com" not in json.dumps(record["human_actions"])
    assert record["vault"]["record_count"] == 1
    assert record["vault"]["records"][0]["id"] == "provider.cloudflare.token"
    assert record["audit_trail"]["schema_version"] == "fusekit.audit-trail.v1"
    assert record["audit_trail"]["counts"]["credential_capture"] >= 1
    assert record["audit_trail"]["counts"]["provider_action"] >= 1
    assert record["audit_trail"]["counts"]["detonation"] == 1
    audit_categories = {entry["category"] for entry in record["audit_trail"]["entries"]}
    assert {"credential_capture", "provider_action", "detonation"} <= audit_categories
    capture_audit = next(
        entry
        for entry in record["audit_trail"]["entries"]
        if entry["action"] == "control_room.capture_vm_clipboard"
    )
    assert capture_audit["wake_event_id"] == record["wake_events"]["events"][0]["id"]
    assert "https://dash.cloudflare.com" not in json.dumps(record["audit_trail"])
    assert record["recording_contract"]["schema_version"] == ("fusekit.recording-contract.v1")
    assert record["recording_contract"]["recording_ready"] is True
    assert record["recording_contract"]["blockers"] == []
    assert record["recording_contract"]["checks"]["provider_playbook"] is True
    assert record["recording_contract"]["checks"]["detonation"] is True
    assert record["recording_contract"]["checks"]["errors_empty"] is True
    assert record["detonation"]["workspace_receipt"]["status"] == "complete"
    assert record["evidence"]["schema_version"] == "fusekit.evidence-inventory.v1"
    assert record["evidence"]["counts"]["logs"] >= 2
    assert record["evidence"]["counts"]["screenshots"] == 1
    assert record["evidence"]["counts"]["visual"] >= 2
    assert record["evidence"]["counts"]["receipts"] >= 2
    assert any(item["path"] == "audit.jsonl" for item in record["evidence"]["logs"])
    assert any(
        item["path"] == "visual/provider-gate.png" for item in record["evidence"]["screenshots"]
    )
    assert any(item["path"] == "visual.json" for item in record["evidence"]["visual"])
    assert "raw secrets are not embedded" in record["evidence"]["statement"]
    assert "not-a-real-png" not in json.dumps(record["evidence"])
    assert any(item["name"] == "audit_log" for item in record["artifacts"])


def test_run_record_redacts_error_details(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci")
    secret_url = (
        "https://provider.example/callback?"
        "code=secret-code-abcdefghijklmnopqrstuvwxyz&token=ghp_abcdefghijklmnopqrstuvwxyz"
    )
    job.mark("setup.execute", "failed", f"Provider callback failed: {secret_url}")
    job.save(tmp_path / "job.json")

    record_path = write_run_record(job, path=tmp_path / "run_record.json")
    record_text = record_path.read_text(encoding="utf-8")
    record = json.loads(record_text)

    assert record["errors"][0]["detail"] == "Provider callback failed: [redacted-url]"
    assert "secret-code" not in record_text
    assert "ghp_" not in record_text
    assert "https://provider.example" not in record_text


def test_recording_human_actions_require_exact_visible_controls() -> None:
    record = {
        "human_actions": {
            "schema_version": "fusekit.human-action-trace.v1",
            "total": 3,
            "counts": {
                "open_provider_gate": 1,
                "capture_vm_clipboard": 1,
                "confirm_gate_finished": 1,
            },
            "actions": [
                {
                    "gate_id": "provider.github.authorization",
                    "action": "open_provider_gate",
                    "visible_control": "Open provider page",
                    "guided": True,
                },
                {
                    "gate_id": "provider.github.authorization",
                    "action": "capture_vm_clipboard",
                    "visible_control": "Capture token",
                    "target": "GITHUB_TOKEN",
                    "guided": True,
                },
                {
                    "gate_id": "provider.github.callback",
                    "action": "confirm_gate_finished",
                    "visible_control": "Continue",
                    "guided": True,
                },
            ],
            "unguided": [],
        }
    }

    assert _recording_human_actions_ready(record) is False

    record["human_actions"]["actions"] = [
        {
            "gate_id": "provider.github.authorization",
            "action": "open_provider_gate",
            "visible_control": "Open provider gate in VM",
            "guided": True,
        },
        {
            "gate_id": "provider.github.authorization",
            "action": "capture_vm_clipboard",
            "visible_control": "Capture GITHUB_TOKEN from VM clipboard",
            "target": "GITHUB_TOKEN",
            "guided": True,
        },
        {
            "gate_id": "provider.github.callback",
            "action": "confirm_gate_finished",
            "visible_control": "I finished this step",
            "guided": True,
        },
    ]

    assert _recording_human_actions_ready(record) is True
    record["human_actions"]["counts"]["capture_vm_clipboard"] = 2
    assert _recording_human_actions_ready(record) is False
    record["human_actions"]["counts"]["capture_vm_clipboard"] = 1
    record["human_actions"]["schema_version"] = "legacy"
    assert _recording_human_actions_ready(record) is False
    record["human_actions"]["schema_version"] = "fusekit.human-action-trace.v1"
    record["human_actions"]["actions"][0]["gate_id"] = ""
    assert _recording_human_actions_ready(record) is False


def test_human_action_trace_requires_exact_approval_control_guidance() -> None:
    gates = [
        {
            "id": "dns.moonlite.rsvp.approval",
            "provider": "dns",
            "classification": "dns-approval",
            "next_action": "Review the DNS records and continue.",
            "resume_hint": "FuseKit will apply DNS after approval.",
            "follow_steps": ["Review the record list."],
            "success_criteria": [],
        }
    ]
    wake_events = [
        {
            "id": "wake-dns",
            "event": "resume_requested",
            "gate_id": "dns.moonlite.rsvp.approval",
            "provider": "dns",
            "classification": "dns-approval",
            "created_at": 1.0,
        }
    ]

    trace = _human_action_trace(gates, wake_events)

    assert trace["actions"][0]["visible_control"] == "Approve DNS apply"
    assert trace["actions"][0]["guided"] is False
    assert trace["unguided"] == [
        {
            "gate_id": "dns.moonlite.rsvp.approval",
            "action": "confirm_gate_finished",
            "reason": "resume click lacked exact finished/approval guidance",
        }
    ]
    gates[0]["next_action"] = "Click Approve DNS apply after reviewing the DNS changes."
    trace = _human_action_trace(gates, wake_events)

    assert trace["actions"][0]["guided"] is True
    assert trace["unguided"] == []


def test_recording_human_actions_required_when_gates_or_wakes_exist() -> None:
    record = {
        "provider_gates": {"total": 0},
        "wake_events": {"total": 0},
        "automation_boundary": {"counts": {"human_gate": 0}},
        "human_actions": {
            "schema_version": "fusekit.human-action-trace.v1",
            "total": 0,
            "counts": {},
            "actions": [],
            "unguided": [],
        },
    }

    assert _recording_human_actions_ready(record) is True

    record["provider_gates"]["total"] = 1
    assert _recording_human_actions_ready(record) is False
    record["provider_gates"]["total"] = 0
    record["wake_events"]["total"] = 1
    assert _recording_human_actions_ready(record) is False
    record["wake_events"]["total"] = 0
    record["automation_boundary"]["counts"]["human_gate"] = 1
    assert _recording_human_actions_ready(record) is False

    record["human_actions"] = {
        "schema_version": "fusekit.human-action-trace.v1",
        "total": 1,
        "counts": {"confirm_gate_finished": 1},
        "actions": [
            {
                "gate_id": "dns.example.com.approval",
                "action": "confirm_gate_finished",
                "visible_control": "Approve DNS apply",
                "target": "",
                "guided": True,
            }
        ],
        "unguided": [],
    }
    assert _recording_human_actions_ready(record) is True


def test_recording_automation_boundary_requires_complete_route_proof() -> None:
    record = {
        "automation_boundary": {
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
                {"owner": "fusekit", "route": "api"},
                {"owner": "human_gate", "route": "browser_guided"},
            ],
            "counts": {"fusekit_owned": 1, "human_gate": 1, "blocked": 0},
            "post_gate_automation": {
                "api_or_cli_routes": ["resend:resend-domain"],
                "human_gate_routes": ["resend:resend-api-key"],
            },
        }
    }

    assert _recording_automation_boundary_ready(record) is True

    record["automation_boundary"]["counts"]["human_gate"] = 0
    assert _recording_automation_boundary_ready(record) is False
    record["automation_boundary"]["counts"]["human_gate"] = 1
    record["automation_boundary"]["vnc_allowed_for"] = ["login"]
    assert _recording_automation_boundary_ready(record) is False
    record["automation_boundary"]["vnc_allowed_for"] = [
        "login",
        "mfa",
        "captcha",
        "consent",
        "payment",
        "copy_once_secret",
    ]
    record["automation_boundary"]["post_gate_automation"]["api_or_cli_routes"] = (
        "resend:resend-domain"
    )
    assert _recording_automation_boundary_ready(record) is False


def test_recording_verifiers_reject_hidden_blocking_checks() -> None:
    record = {
        "verifiers": {
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
                    "provider": "resend",
                    "check": "domain verified",
                    "status": "passed",
                    "pending_safe": False,
                },
                {
                    "provider": "cloudflare",
                    "check": "dns propagation",
                    "status": "pending_safe",
                    "pending_safe": True,
                },
            ],
        }
    }

    assert _recording_verifiers_ready(record) is True

    record["verifiers"]["checks"][1]["pending_safe"] = False
    assert _recording_verifiers_ready(record) is False
    record["verifiers"]["checks"][1]["pending_safe"] = True
    record["verifiers"]["checks"].append(
        {
            "provider": "vercel",
            "check": "deployment",
            "status": "failed",
            "pending_safe": False,
        }
    )
    assert _recording_verifiers_ready(record) is False
    record["verifiers"]["checks"].pop()
    record["verifiers"]["counts"]["failed"] = 1
    assert _recording_verifiers_ready(record) is False
    record["verifiers"]["counts"]["failed"] = 0
    record["verifiers"]["counts"]["passed"] = 2
    assert _recording_verifiers_ready(record) is False


def test_recording_evidence_requires_screenshot_for_visual_runner() -> None:
    record = {
        "runner_profile": {
            "profile_contract": {
                "name": "oci-visual-browser-x86_64",
                "browser_stack": {
                    "shared_provider_profile": (
                        "/var/lib/fusekit-runner/visual/chrome-provider-profile"
                    )
                },
            }
        },
        "evidence": {
            "counts": {
                "logs": 1,
                "screenshots": 0,
                "visual": 1,
                "receipts": 1,
            }
        },
    }

    assert _recording_evidence_ready(record) is False
    record["evidence"]["counts"]["screenshots"] = 1
    assert _recording_evidence_ready(record) is True
    record["runner_profile"]["profile_contract"] = {"name": "api-only"}
    record["evidence"]["counts"]["screenshots"] = 0
    assert _recording_evidence_ready(record) is True


def test_recording_audit_trail_requires_categories_for_observed_proof() -> None:
    record = {
        "wake_events": {
            "events": [
                {
                    "event": "clipboard_captured",
                    "gate_id": "provider.resend.authorization",
                    "target": "RESEND_API_KEY",
                },
                {
                    "event": "resume_requested",
                    "gate_id": "dns.moonlite.rsvp.approval",
                    "classification": "dns-approval",
                },
            ]
        },
        "approvals": [{"id": "dns.moonlite.rsvp.approval"}],
        "vault": {"record_count": 1},
        "detonation": {"workspace_detonated": True},
        "verification": {"checks": [{"provider": "resend", "status": "passed"}]},
        "audit_trail": {
            "entry_count": 3,
            "counts": {
                "credential_capture": 1,
                "provider_action": 1,
                "detonation": 1,
            },
            "entries": [
                {"category": "credential_capture", "source": "gate_events.jsonl"},
                {"category": "provider_action", "source": "setup_receipt.json"},
                {"category": "detonation", "source": "workspace_detonation.json"},
            ],
        },
    }

    assert _recording_audit_trail_ready(record) is False
    record["audit_trail"]["entry_count"] = 5
    record["audit_trail"]["counts"]["human_approval"] = 1
    record["audit_trail"]["counts"]["dns_write"] = 1
    record["audit_trail"]["entries"].extend(
        [
            {"category": "human_approval", "source": "gate_events.jsonl"},
            {"category": "dns_write", "source": "setup_receipt.json"},
        ]
    )
    assert _recording_audit_trail_ready(record) is True
    record["audit_trail"]["counts"]["dns_write"] = 0
    assert _recording_audit_trail_ready(record) is False
    record["audit_trail"]["counts"]["dns_write"] = 1
    record["audit_trail"]["entries"][-1]["source"] = "audit.jsonl"
    assert _recording_audit_trail_ready(record) is False


def test_recording_provider_playbook_requires_public_order() -> None:
    record: dict[str, Any] = {
        "provider_playbook": {
            "schema_version": "fusekit.provider-playbook.v1",
            "steps": [
                {
                    "id": "resend.capture_key",
                    "instruction": "Capture RESEND_API_KEY from VM clipboard.",
                },
                {
                    "id": "dns.approval",
                    "instruction": "Approve DNS apply.",
                },
                {
                    "id": "resend.domain_api",
                    "instruction": "FuseKit creates or reuses the Resend domain by API.",
                },
                {
                    "id": "vercel.env_api",
                    "instruction": "FuseKit writes required runtime variables into Vercel.",
                },
            ],
            "safety_notes": [
                "Use the launcher and shared VM browser for provider gates.",
                (
                    "Do not create Resend domains or audiences manually; FuseKit owns "
                    "those API setup steps."
                ),
                (
                    "Do not paste provider secrets into the host computer; "
                    "Capture reads the VM clipboard."
                ),
            ],
        }
    }

    assert _recording_provider_playbook_ready(record) is False

    record["provider_playbook"]["steps"] = [
        {
            "id": "resend.capture_key",
            "provider": "resend",
            "route": "browser_guided",
            "control": "Capture RESEND_API_KEY from VM clipboard",
            "proof_source": "gate_events.jsonl",
            "resume_event": "clipboard_captured -> resume_requested",
            "instruction": "Capture RESEND_API_KEY from VM clipboard.",
        },
        {
            "id": "resend.domain_api",
            "provider": "resend",
            "route": "api",
            "control": "FuseKit API worker",
            "proof_source": "setup_receipt.json",
            "resume_event": "provider_action_recorded",
            "instruction": "FuseKit creates or reuses the Resend domain by API.",
        },
        {
            "id": "vercel.env_api",
            "provider": "vercel",
            "route": "api",
            "control": "FuseKit API worker",
            "proof_source": "setup_receipt.json",
            "resume_event": "provider_action_recorded",
            "instruction": "FuseKit writes required runtime variables into Vercel.",
        },
        {
            "id": "dns.approval",
            "provider": "dns",
            "route": "human_follow_me",
            "control": "Approve DNS apply",
            "proof_source": "gate_events.jsonl",
            "resume_event": "dns_apply_approved -> resume_requested",
            "instruction": "Approve DNS apply.",
        },
    ]

    assert _recording_provider_playbook_ready(record) is True

    record["provider_playbook"]["safety_notes"].append(
        "If the VM browser is slow, use a local browser tab to finish provider setup."
    )
    assert _recording_provider_playbook_ready(record) is False

    record["provider_playbook"]["safety_notes"][-1] = (
        "Do not use a local browser tab for provider gates."
    )
    assert _recording_provider_playbook_ready(record) is True

    record["provider_playbook"]["safety_notes"][-1] = (
        "Use the visible Capture <TARGET> from VM clipboard button."
    )
    assert _recording_provider_playbook_ready(record) is False
    record["provider_playbook"]["safety_notes"].pop()

    record["provider_playbook"]["steps"][0]["control"] = (
        "Capture CLOUDFLARE_API_TOKEN from VM clipboard"
    )
    assert _recording_provider_playbook_ready(record) is False

    record["provider_playbook"]["steps"][0]["control"] = (
        "Capture RESEND_API_KEY from VM clipboard"
    )
    record["provider_playbook"]["steps"][1]["instruction"] = "Click Add domain in Resend."
    assert _recording_provider_playbook_ready(record) is False

    record["provider_playbook"]["steps"][1]["instruction"] = (
        "FuseKit creates or reuses the Resend domain by API."
    )
    record["provider_playbook"]["steps"][1]["id"] = ""
    assert _recording_provider_playbook_ready(record) is False


def test_run_record_recording_detonation_requires_deleted_resource_proof() -> None:
    receipt = {
        "status": "complete",
        "failures": {},
        "resource_summary": {
            "schema_version": "fusekit.workspace-detonation-resources.v1",
            "remote_worker": True,
            "remote_worker_cleanup": remote_worker_cleanup_proof(),
            "compute_instance": True,
            "boot_volume_deleted": False,
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
        },
    }
    record = {
        "detonation": {
            "preflight_safe": True,
            "workspace_detonated": True,
            "workspace_receipt": receipt,
        }
    }

    assert _recording_detonation_ready(record) is False
    receipt["resource_summary"]["boot_volume_deleted"] = True
    assert _recording_detonation_ready(record) is False
    receipt["deleted"] = [
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
    ]
    assert _recording_detonation_ready(record) is True


def test_run_record_recording_contract_blocks_missing_provider_playbook(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci")
    job.mark("setup.execute", "done", "provider setup finished")
    (tmp_path / "audit.jsonl").write_text('{"event":"ok"}\n', encoding="utf-8")
    job.add_artifact("audit_log", tmp_path / "audit.jsonl")
    (tmp_path / "fusekit.vault.json").write_text("encrypted", encoding="utf-8")
    (tmp_path / "provider_strategies.json").write_text(
        json.dumps({"providers": []}),
        encoding="utf-8",
    )
    (tmp_path / "gates.json").write_text(json.dumps({"gates": []}), encoding="utf-8")
    (tmp_path / "setup_receipt.json").write_text(
        json.dumps({"actions": [{"action": "resend.domain", "status": "passed"}]}),
        encoding="utf-8",
    )
    (tmp_path / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "resend", "status": "passed"}]}),
        encoding="utf-8",
    )
    (tmp_path / "rollback_plan.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "provider": "resend",
                        "action": "resend.domain.rollback",
                        "status": "planned",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "visual.json").write_text(
        json.dumps({"runner": "novnc", "status": "ready"}),
        encoding="utf-8",
    )
    visual_dir = tmp_path / "visual"
    visual_dir.mkdir()
    (visual_dir / "provider-gate.png").write_bytes(b"proof")
    _write_runner_readiness(tmp_path)
    (tmp_path / "workspace_detonation.json").write_text(
        json.dumps(
            {
                "status": "complete",
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
                    "missing": [],
                },
            }
        ),
        encoding="utf-8",
    )
    update_run_state(
        tmp_path / "run_state.json",
        app_repo_known=True,
        runner_selected=True,
        vault_created=True,
        detonation_safe=True,
        workspace_detonated=True,
    )
    (tmp_path / "gate_events.jsonl").write_text("", encoding="utf-8")
    job.save(tmp_path / "job.json")

    record_path = write_run_record(job, path=tmp_path / "run_record.json")
    record = json.loads(record_path.read_text(encoding="utf-8"))

    assert record["durable_state"]["resume_ready"] is True
    assert record["provider_playbook"]["step_count"] == 0
    assert _recording_durable_state_ready(record) is True
    assert _recording_worker_replacement_ready(record) is True
    assert record["recording_contract"]["checks"]["worker_replacement"] is True
    assert record["recording_contract"]["checks"]["provider_playbook"] is False
    assert record["recording_contract"]["recording_ready"] is False
    assert record["recording_contract"]["blockers"] == ["provider_playbook"]


def test_recording_contract_rejects_volatile_durable_state_survivors(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci")
    job.mark("setup.execute", "done", "provider setup finished")
    (tmp_path / "audit.jsonl").write_text('{"event":"ok"}\n', encoding="utf-8")
    job.add_artifact("audit_log", tmp_path / "audit.jsonl")
    (tmp_path / "fusekit.vault.json").write_text("encrypted", encoding="utf-8")
    (tmp_path / "provider_strategies.json").write_text(
        json.dumps({"providers": []}),
        encoding="utf-8",
    )
    (tmp_path / "gates.json").write_text(json.dumps({"gates": []}), encoding="utf-8")
    (tmp_path / "setup_receipt.json").write_text(
        json.dumps({"actions": [{"action": "resend.domain", "status": "passed"}]}),
        encoding="utf-8",
    )
    (tmp_path / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "resend", "status": "passed"}]}),
        encoding="utf-8",
    )
    (tmp_path / "rollback_plan.json").write_text(
        json.dumps(
            {
                "actions": [
                    {
                        "provider": "resend",
                        "action": "resend.domain.rollback",
                        "status": "planned",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "visual.json").write_text(
        json.dumps({"runner": "novnc", "status": "ready"}),
        encoding="utf-8",
    )
    _write_runner_readiness(tmp_path)
    (tmp_path / "workspace_detonation.json").write_text(
        json.dumps(
            {
                "status": "complete",
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
                    "missing": [],
                },
            }
        ),
        encoding="utf-8",
    )
    update_run_state(
        tmp_path / "run_state.json",
        app_repo_known=True,
        runner_selected=True,
        vault_created=True,
        detonation_safe=True,
        workspace_detonated=True,
    )
    (tmp_path / "gate_events.jsonl").write_text("", encoding="utf-8")
    job.save(tmp_path / "job.json")
    record = json.loads(
        write_run_record(job, path=tmp_path / "run_record.json").read_text(encoding="utf-8")
    )

    assert _recording_durable_state_ready(record) is True
    assert _recording_worker_replacement_ready(record) is True

    record["durable_state"]["detonation_scope"]["host_machine_state_required"] = True
    assert _recording_durable_state_ready(record) is False
    record["durable_state"]["detonation_scope"]["host_machine_state_required"] = False

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

    assert _recording_durable_state_ready(record) is False
    assert _recording_worker_replacement_ready(record) is False


def test_run_record_recording_contract_blocks_thin_runner_profile(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci")
    job.mark("setup.execute", "done", "provider setup finished")
    (tmp_path / "audit.jsonl").write_text('{"event":"ok"}\n', encoding="utf-8")
    job.add_artifact("audit_log", tmp_path / "audit.jsonl")
    (tmp_path / "fusekit.vault.json").write_text("encrypted", encoding="utf-8")
    (tmp_path / "provider_strategies.json").write_text(
        json.dumps(
            {
                "playbook": {
                    "schema_version": "fusekit.provider-playbook.v1",
                    "steps": [
                            {
                                "id": "resend.capture_key",
                                "provider": "resend",
                                "route": "browser_guided",
                                "control": "Capture RESEND_API_KEY from VM clipboard",
                                "proof_source": "gate_events.jsonl",
                                "resume_event": "clipboard_captured -> resume_requested",
                                "instruction": (
                                    "Open the provider gate in the VM browser, copy the "
                                    "approved value there, then click Capture "
                                "RESEND_API_KEY from VM clipboard."
                            ),
                        }
                    ],
                    "safety_notes": [
                        "Use the launcher and shared VM browser for provider gates.",
                        (
                            "Do not create Resend domains or audiences manually; "
                            "FuseKit owns those API setup steps."
                        ),
                        (
                            "Do not paste provider secrets into the host computer; "
                            "Capture reads the VM clipboard."
                        ),
                    ],
                },
                "providers": [],
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "gates.json").write_text(json.dumps({"gates": []}), encoding="utf-8")
    (tmp_path / "setup_receipt.json").write_text(
        json.dumps({"actions": [{"action": "resend.domain", "status": "passed"}]}),
        encoding="utf-8",
    )
    (tmp_path / "verification_report.json").write_text(
        json.dumps({"checks": [{"provider": "resend", "status": "passed"}]}),
        encoding="utf-8",
    )
    (tmp_path / "visual.json").write_text(
        json.dumps({"runner": "novnc", "status": "ready"}),
        encoding="utf-8",
    )
    visual_dir = tmp_path / "visual"
    visual_dir.mkdir()
    (visual_dir / "provider-gate.png").write_bytes(b"proof")
    _write_runner_readiness(tmp_path, thin=True)
    (tmp_path / "workspace_detonation.json").write_text(
        json.dumps(
            {
                "status": "complete",
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
                    "missing": [],
                },
            }
        ),
        encoding="utf-8",
    )
    update_run_state(
        tmp_path / "run_state.json",
        app_repo_known=True,
        runner_selected=True,
        vault_created=True,
        detonation_safe=True,
        workspace_detonated=True,
    )
    job.save(tmp_path / "job.json")

    record_path = write_run_record(job, path=tmp_path / "run_record.json")
    record = json.loads(record_path.read_text(encoding="utf-8"))

    assert record["durable_state"]["resume_ready"] is False
    assert record["durable_state"]["runner_profile_ready"] is False
    assert record["durable_state"]["worker_replacement_contract"]["can_recreate_worker"] is False
    assert record["recording_contract"]["checks"]["runner_profile"] is False
    assert record["recording_contract"]["checks"]["durable_state"] is False
    assert record["recording_contract"]["checks"]["worker_replacement"] is False
    assert record["recording_contract"]["checks"]["automation_boundary"] is False
    assert record["recording_contract"]["recording_ready"] is False
    assert record["recording_contract"]["blockers"] == [
        "durable_state",
        "worker_replacement",
        "runner_profile",
        "automation_boundary",
    ]


def test_run_record_retains_all_redacted_wake_events(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci")
    service = GateService.load(tmp_path / "gates.json")
    for index in range(55):
        gate_id = f"provider.demo.{index}"
        service.wait(gate_id, provider="demo", reason="approve provider gate")
        service.request_resume(gate_id)

    record_path = write_run_record(job, path=tmp_path / "run_record.json")
    record = json.loads(record_path.read_text(encoding="utf-8"))

    assert record["wake_events"]["total"] == 55
    assert len(record["wake_events"]["events"]) == 55
    assert record["wake_events"]["events"][0]["gate_id"] == "provider.demo.0"
    assert record["wake_events"]["events"][-1]["gate_id"] == "provider.demo.54"
    assert "secret" not in json.dumps(record["wake_events"]).lower()
    assert record["audit_trail"]["entry_count"] == 55
    assert len(record["audit_trail"]["entries"]) == 55
    assert record["audit_trail"]["counts"]["human_approval"] == 55
    assert (
        record["audit_trail"]["entries"][0]["wake_event_id"]
        == (record["wake_events"]["events"][0]["id"])
    )
    assert (
        record["audit_trail"]["entries"][-1]["wake_event_id"]
        == (record["wake_events"]["events"][-1]["id"])
    )
    assert "secret-token" not in json.dumps(record["audit_trail"]).lower()
    assert "bearer " not in json.dumps(record["audit_trail"]).lower()


def test_run_record_retains_all_redacted_audit_log_entries(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci")
    audit = AuditLog(tmp_path / "audit.jsonl")
    for index in range(55):
        audit.record(
            "provider.retry",
            {
                "attempt": index,
                "token": f"secret-token-{index}",
                "message": "retrying provider setup",
            },
        )

    record_path = write_run_record(job, path=tmp_path / "run_record.json")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    entries = [
        entry
        for entry in record["audit_trail"]["entries"]
        if entry["source"] == "audit.jsonl" and entry["action"] == "provider.retry"
    ]

    assert len(entries) == 55
    assert record["audit_trail"]["counts"]["provider_action"] == 55
    assert entries[0]["audit_log_index"] == 1
    assert entries[-1]["audit_log_index"] == 55
    assert "secret-token" not in json.dumps(record["audit_trail"]).lower()
    assert "retrying provider setup" not in json.dumps(record["audit_trail"]).lower()


def test_run_record_retains_all_redacted_receipt_actions(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci")
    actions = [
        {
            "action": "dns.apply",
            "status": "passed",
            "details": {
                "domain": "moonlite.rsvp",
                "token": f"secret-token-{index}",
                "record": f"example-{index}.moonlite.rsvp",
            },
        }
        for index in range(55)
    ]
    (tmp_path / "setup_receipt.json").write_text(
        json.dumps({"actions": actions}),
        encoding="utf-8",
    )

    record_path = write_run_record(job, path=tmp_path / "run_record.json")
    record = json.loads(record_path.read_text(encoding="utf-8"))
    entries = [
        entry
        for entry in record["audit_trail"]["entries"]
        if entry["source"] == "setup_receipt.json" and entry["action"] == "dns.apply"
    ]

    assert len(entries) == 55
    assert record["audit_trail"]["counts"]["dns_write"] == 55
    assert entries[0]["receipt_action_index"] == 1
    assert entries[-1]["receipt_action_index"] == 55
    audit_json = json.dumps(record["audit_trail"]).lower()
    assert "secret-token" not in audit_json
    assert "example-54.moonlite.rsvp" not in audit_json


def test_control_room_payload_includes_run_record(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    write_run_record(job, path=tmp_path / "run_record.json")
    job.add_artifact("run_record", tmp_path / "run_record.json")

    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["run_record"]["schema_version"] == "fusekit.run-record.v1"
    assert payload["run_record"]["id"] == "fk-test"


def test_control_room_renders_durable_state_from_run_record(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    run_record = tmp_path / "run_record.json"
    run_record.write_text(
        json.dumps(
            {
                "schema_version": "fusekit.run-record.v1",
                "id": "fk-test",
                "durable_state": {
                    "schema_version": "fusekit.durable-state.v1",
                    "resume_ready": True,
                    "sources": [
                        {
                            "id": "encrypted_vault",
                            "path": "fusekit.vault.json",
                            "role": "encrypted capability vault",
                            "secret_class": "encrypted",
                            "exists": True,
                        }
                    ],
                    "volatile_worker_surfaces": ["worker", "visual", "openclaw-state"],
                    "detonation_preserves": ["encrypted_vault", "run_record"],
                    "statement": (
                        "FuseKit can replace or detonate the disposable OCI worker "
                        "because encrypted/redacted state is the source of truth."
                    ),
                },
                "human_actions": {
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
                            "guidance_gap": "",
                            "created_at": 2.0,
                        }
                    ],
                    "unguided": [],
                    "statement": (
                        "Every recorded human action should map to one visible "
                        "control-room gate and its current follow-me instructions; "
                        "the trace contains no raw provider URLs."
                    ),
                },
                "automation_boundary": {
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
                        }
                    ],
                    "counts": {
                        "fusekit_owned": 1,
                        "human_gate": 0,
                        "blocked": 0,
                        "guided_human_actions": 1,
                    },
                    "post_gate_automation": {
                        "api_or_cli_routes": ["resend:resend-domain"],
                        "human_gate_routes": [],
                    },
                    "statement": (
                        "Humans use VNC only for provider gates. After capture, "
                        "FuseKit owns provider mutations by API and can detonate "
                        "the OCI worker."
                    ),
                },
                "verifiers": {
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
                    ],
                    "statement": (
                        "Live provider verifiers are summarized as green checks or "
                        "pending-safe checks before launch readiness is trusted."
                    ),
                },
                "audit_trail": {
                    "schema_version": "fusekit.audit-trail.v1",
                    "entry_count": 3,
                    "counts": {
                        "credential_capture": 1,
                        "provider_action": 1,
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
                            "summary": ("RESEND_API_KEY was captured from the VM clipboard."),
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
                            "category": "detonation",
                            "action": "oci.workspace.detonate",
                            "provider": "oci",
                            "status": "complete",
                            "source": "workspace_detonation.json",
                            "summary": (
                                "FuseKit recorded disposable OCI worker and workspace cleanup."
                            ),
                        },
                    ],
                    "statement": (
                        "Credential captures, provider actions, DNS writes, "
                        "human approvals, and detonation events are summarized "
                        "without storing raw secrets."
                    ),
                },
                "recording_contract": {
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
                        "A public demo is recordable only when durable OCI state, "
                        "worker replacement from encrypted/redacted sources, "
                        "ordered provider playbooks, guided human actions, live "
                        "provider verifiers, and no-trace detonation all agree."
                    ),
                },
                "detonation": {
                    "preflight_safe": True,
                    "workspace_detonated": True,
                    "workspace_receipt": {
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
                            "schema_version": ("fusekit.workspace-detonation-resources.v1"),
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
                            "missing": [],
                            "statement": (
                                "FuseKit detonation must remove the remote worker "
                                "process state, terminate the OCI VM, delete the boot "
                                "volume, and delete FuseKit-created network resources."
                            ),
                        },
                        "updated_at": 2.0,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    job.add_artifact("run_record", run_record)

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["run_record"]["durable_state"]["resume_ready"] is True
    assert "What survives detonation" in html
    assert "worker can be replaced" in html
    assert "host-machine browser profile or clipboard history" in html
    assert "is required to resume" in html
    assert 'data-durable-state-source="encrypted_vault"' in html
    assert "encrypted capability vault" in html
    assert payload["run_record"]["human_actions"]["total"] == 1
    assert "Human actions matched to gates" in html
    assert "Capture RESEND_API_KEY from VM clipboard" in html
    assert "all actions guided" in html
    assert payload["run_record"]["verifiers"]["all_passed_or_pending_safe"] is True
    assert "Provider checks are real" in html
    assert "all verifiers green or pending-safe" in html
    assert 'data-verifier-provider="resend"' in html
    assert "cloudflare · dns_propagated" in html
    assert "What FuseKit owns after gates" in html
    assert payload["run_record"]["audit_trail"]["entry_count"] == 3
    assert "Every important action is recorded" in html
    assert 'data-audit-category="credential_capture"' in html
    assert "RESEND_API_KEY was captured from the VM clipboard" in html
    assert payload["run_record"]["recording_contract"]["recording_ready"] is True
    assert "Ready to show the magic path" in html
    assert "recordable with no trace" in html
    assert 'data-recording-contract-check="detonation"' in html
    assert "OCI cleanup left no worker trace" in html
    assert "OCI VM detonated" in html
    assert 'data-detonation-resource="remote_worker_cleanup"' in html
    assert "Remote worker cleanup proof" in html
    assert "disposable VM paths" in html
    assert "host-machine state was not required" in html
    assert 'data-detonation-resource="compute_instance"' in html
    assert 'data-detonation-resource="boot_volume"' in html
    assert "Root tenancy or root compartment scope was preserved by design." in html


def test_control_room_names_durable_final_proof_blockers(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    run_record = tmp_path / "run_record.json"
    run_record.write_text(
        json.dumps(
            {
                "schema_version": "fusekit.run-record.v1",
                "id": "fk-test",
                "durable_state": {
                    "schema_version": "fusekit.durable-state.v1",
                    "resume_ready": True,
                    "missing": [],
                    "final_proof_missing": [
                        "rollback_plan",
                        "setup_receipt",
                        "verification_report",
                        "workspace_detonation",
                    ],
                    "sources": [
                        {
                            "id": "encrypted_vault",
                            "path": "fusekit.vault.json",
                            "role": "encrypted capability vault",
                            "secret_class": "encrypted",
                            "exists": True,
                        },
                        {
                            "id": "workspace_detonation",
                            "path": "workspace_detonation.json",
                            "role": "OCI workspace detonation receipt",
                            "secret_class": "non-secret",
                            "exists": False,
                        },
                    ],
                    "volatile_worker_surfaces": ["worker", "visual", "provider-auth"],
                },
                "recording_contract": {
                    "schema_version": "fusekit.recording-contract.v1",
                    "recording_ready": False,
                    "checks": {"durable_state": False, "worker_replacement": True},
                    "blockers": ["durable_state"],
                },
            }
        ),
        encoding="utf-8",
    )
    job.add_artifact("run_record", run_record)

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "worker replaceable; 4 final proofs pending" in html
    assert "Final public-recording proof is still waiting on" in html
    assert "rollback plan" in html
    assert "setup receipt" in html
    assert "verification report" in html
    assert "workspace detonation" in html
    assert "Waiting for this final proof artifact before public recording is ready" in html
    assert "worker can be replaced" in html.split("<script", 1)[1]
    assert "final_proof_missing" in html


def test_live_control_room_refreshes_all_run_record_proof_panels() -> None:
    for renderer, selector in (
        ("renderDurableState(job)", "data-durable-state-checks"),
        ("renderHumanActions(job)", "data-human-action-checks"),
        ("renderAutomationBoundary(job)", "data-automation-boundary-checks"),
        ("renderRunRecordVerifiers(job)", "data-verifier-checks"),
        ("renderAuditTrail(job)", "data-audit-trail-checks"),
        ("renderRecordingContract(job)", "data-recording-contract-checks"),
        ("renderDetonationReceipt(job)", "data-detonation-receipt-checks"),
        ("visualGateHint(job)", "data-visual-gate-hint"),
        ("controlRoomSuccessStatus(payload", "wakeEventId"),
        ("actionWakeProofLines(status)", "Resume wake proof"),
        ("remoteWorkerCleanupReady(workerCleanup)", "remote_worker_cleanup"),
    ):
        assert renderer in SCRIPT
        assert selector in SCRIPT


def test_control_room_event_script_is_valid_javascript(tmp_path) -> None:
    script_path = tmp_path / "control-room-events.js"
    script_path.write_text(SCRIPT, encoding="utf-8")

    try:
        result = subprocess.run(
            ["node", "--check", str(script_path)],
            capture_output=True,
            check=False,
            text=True,
        )
    except FileNotFoundError:
        pytest.skip("node is not installed")

    assert result.returncode == 0, result.stderr or result.stdout


def test_remote_bootstrap_checkpoint_keeps_recovery_in_launcher(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("remote.bootstrap", "running", "remote bootstrap is installing dependencies")

    bootstrap = next(item for item in job.checkpoints if item.id == "remote.bootstrap")
    html = render_control_room(job)

    assert bootstrap.status == "running"
    assert "launcher/control room" in bootstrap.resume_hint
    assert "next visible VM or provider gate" in bootstrap.resume_hint
    assert "rerun from the same encrypted vault and job state" not in bootstrap.resume_hint
    assert "launcher/control room" in html
    assert "next visible VM or provider gate" in html
    assert "rerun from the same encrypted vault and job state" not in html


def test_launch_run_state_contract_tracks_detonation_readiness(tmp_path) -> None:
    path = tmp_path / "run_state.json"

    state = update_run_state(
        path,
        app_repo_known=True,
        runner_selected=True,
        oci_ready=True,
        browser_ready=False,
        vault_created=True,
        secrets_captured=True,
        provider_checks_passed_or_pending_safe=False,
        receipt_written=True,
    )

    assert path.stat().st_mode & 0o777 == 0o600
    assert state.oci_ready is True
    assert state.browser_ready is False
    assert state.missing_for_detonation() == ["provider_checks_passed_or_pending_safe"]
    assert state.to_dict()["ready_to_detonate"] is False

    loaded = LaunchRunState.load(path)
    loaded.mark(provider_checks_passed_or_pending_safe=True, detonation_safe=True)

    assert loaded.missing_for_detonation() == []
    assert loaded.to_dict()["ready_to_detonate"] is True


def test_launch_run_state_notes_are_redacted(tmp_path) -> None:
    path = tmp_path / "run_state.json"
    state = LaunchRunState()
    fake_secret = "fake_test_secret_value_abcdefghijklmnopqrstuvwxyz"
    state.add_note(f"captured key={fake_secret}")
    state.save(path)

    payload = json.loads(path.read_text("utf-8"))

    assert fake_secret not in json.dumps(payload)
    assert "[redacted]" in json.dumps(payload)


def test_launch_run_state_recovers_from_corrupt_state(tmp_path) -> None:
    path = tmp_path / "run_state.json"
    path.write_text("{not-json", encoding="utf-8")

    state = update_run_state(path, runner_selected=True)
    payload = json.loads(path.read_text("utf-8"))

    assert state.runner_selected is True
    assert payload["runner_selected"] is True
    assert "rebuilt" in payload["notes"][0]


def test_launch_run_state_parses_false_strings_as_false(tmp_path) -> None:
    path = tmp_path / "run_state.json"
    path.write_text(
        json.dumps(
            {
                "app_repo_known": "false",
                "runner_selected": "true",
                "oci_ready": "0",
                "browser_ready": "1",
            }
        ),
        encoding="utf-8",
    )

    state = LaunchRunState.load(path)

    assert state.app_repo_known is False
    assert state.runner_selected is True
    assert state.oci_ready is False
    assert state.browser_ready is True


def test_cloud_shell_launcher_contains_deeplink_and_fallback_command() -> None:
    plan = build_cloud_shell_launch_plan(
        app_source="https://github.com/example/app.git",
        fusekit_package="git+https://github.com/example/fusekit.git",
        launch_args=(
            "--github-repo",
            "example/app",
            "--dns-zone",
            "example.com",
            "--infer-ui",
        ),
    )
    html = render_cloud_shell_launcher(plan)

    assert "cloud.oracle.com" in plan.deeplink_url
    assert plan.deeplink_url == "https://cloud.oracle.com/?cloudshell=true"
    assert "command=" not in plan.deeplink_url
    assert "fusekit launch" in plan.bootstrap_command
    assert "for candidate in python3.12 python3.11 python3.10 python3 python" in (
        plan.bootstrap_command
    )
    assert "sys.version_info >= (3, 10)" in plan.bootstrap_command
    assert "curl -LsSf https://astral.sh/uv/install.sh | sh" in plan.bootstrap_command
    assert "pip install --user --upgrade uv" not in plan.bootstrap_command
    assert '"$HOME/.local/bin/uv" python install 3.12' in plan.bootstrap_command
    assert '"$HOME/.local/bin/uv" venv --python 3.12' in plan.bootstrap_command
    assert "pip_target_flag=--user" in plan.bootstrap_command
    assert "pip_target_flag=" in plan.bootstrap_command
    assert 'export PATH="$work/python/bin:$PATH"' in plan.bootstrap_command
    assert "export FUSEKIT_OPENCLAW_HOME_MODE=default" in plan.bootstrap_command
    assert 'fusekit_install_flags="--upgrade --force-reinstall --no-cache-dir"' in (
        plan.bootstrap_command
    )
    assert '$fusekit_install_flags "$fusekit_package"' in plan.bootstrap_command
    assert "fusekit --version" in plan.bootstrap_command
    assert 'rm -rf "$HOME/.fusekit-runtime/openclaw"' in plan.bootstrap_command
    assert "Git is required in OCI Cloud Shell for git+ FuseKit packages" in plan.bootstrap_command
    assert "FuseKit will print the exact launch command below" in plan.bootstrap_command
    assert "run it in this same Cloud Shell after the app files are present" in (
        plan.bootstrap_command
    )
    assert "Then rerun the fusekit launch command printed below" not in plan.bootstrap_command
    assert "fusekit source fetch" in plan.bootstrap_command
    assert "--github-auth auto" in plan.bootstrap_command
    assert "--capture-stdin" in plan.bootstrap_command
    source_fetch_line = next(
        line for line in plan.bootstrap_command.splitlines() if "fusekit source fetch" in line
    )
    assert "--spine openclaw" not in source_fetch_line
    assert "--infer-ui" not in source_fetch_line
    assert "--no-bootstrap" in plan.bootstrap_command
    assert "--infer-ui" in plan.bootstrap_command
    assert '--vault "$vaultfile"' in plan.bootstrap_command
    assert "https://github.com/example/app.git" in plan.bootstrap_command
    assert "git+https://github.com/example/fusekit.git" in plan.bootstrap_command
    assert "--github-repo example/app" in plan.bootstrap_command
    assert "--dns-zone example.com" in plan.bootstrap_command
    assert "--infer-ui" in plan.bootstrap_command
    assert plan.launch_args[-1] == "--infer-ui"
    assert "SnowmanAI / FuseKit" in html
    assert "Privacy mode" in html
    assert (
        "exact env-named Capture buttons, for example Capture RESEND_API_KEY "
        "from VM clipboard, save directly to the encrypted vault" in html
    )
    assert "hidden Cloud Shell prompts" not in html
    assert "Copy Bootstrap Command" in html
    assert "command: command.value" not in html
    assert "openLink.href = initial.deeplink_url" in html
    assert 'role="status"' in html
    assert "navigator.clipboard.writeText" in html
    assert "function fallbackCopy(text)" in html
    assert "function sourceAssignment(appSource)" in html
    assert "TextEncoder" in html
    assert "base64 -d" in html
    assert "function shellQuote" not in html
    assert "document.createElement('textarea')" in html
    assert "document.execCommand('copy')" in html
    assert "Press Command+C" in html
    assert "Press Command+C or Ctrl+C" in html
    assert "FuseKit opened the backup command and selected it" in html
    assert "Open OCI Cloud Shell and paste it there" in html
    assert "command.select()" in html
    assert "command.closest('details').open = true" in html
    assert "command.value = buildCommand(source.value);" in html
    assert "Passphrase:" in plan.bootstrap_command
    assert "if [ -t 0 ]; then" in plan.bootstrap_command
    assert "stty -echo" in plan.bootstrap_command


def test_cloud_shell_launcher_source_update_keeps_shell_command_safe() -> None:
    plan = build_cloud_shell_launch_plan(
        app_source="https://github.com/example/app.git",
        launch_args=("--infer-ui",),
    )
    malicious_source = "https://github.com/example/app.git'; touch /tmp/fusekit-pwn #"
    encoded = base64.b64encode(malicious_source.encode("utf-8")).decode("ascii")
    updated = re.sub(
        r"^app_source=.*$",
        f'app_source="$(printf %s {encoded} | base64 -d)"',
        plan.bootstrap_command,
        flags=re.MULTILINE,
    )
    command = shlex.split(updated)

    result = subprocess.run(
        ["bash", "-n"],
        input=command[2],
        capture_output=True,
        check=False,
        text=True,
    )

    assert command[:2] == ["bash", "-lc"]
    assert result.returncode == 0, result.stderr
    assert malicious_source not in updated
    assert encoded in updated
    assert "touch /tmp/fusekit-pwn" not in updated


def test_cloud_shell_bootstrap_command_is_valid_shell() -> None:
    plan = build_cloud_shell_launch_plan(
        app_source="https://github.com/example/app.git",
        launch_args=("--infer-ui",),
    )
    command = shlex.split(plan.bootstrap_command)

    result = subprocess.run(
        ["bash", "-n"],
        input=command[2],
        capture_output=True,
        check=False,
        text=True,
    )

    assert command[:2] == ["bash", "-lc"]
    assert result.returncode == 0, result.stderr


def test_oci_api_key_profile_is_encrypted_vault_material() -> None:
    vault = Vault.empty()
    public_key = prepare_oci_api_signing_key(vault)
    returned_public_key = capture_oci_api_key_profile(
        vault,
        config_snippet=(
            "[DEFAULT]\n"
            "tenancy=ocid1.tenancy.oc1..example\n"
            "user=ocid1.user.oc1..example\n"
            "fingerprint=aa:bb\n"
            "region=us-ashburn-1\n"
        ),
    )

    assert returned_public_key == public_key
    assert "BEGIN PUBLIC KEY" in public_key
    assert vault.require("runner.oci.profile").metadata["auth_mode"] == "api-key-upload"
    private_record = vault.require("runner.oci.api_signing_key.private")
    assert "BEGIN RSA PRIVATE KEY" in private_record.value
    assert "BEGIN RSA PRIVATE KEY" not in str(vault.public_index())


def test_control_room_renders_job_without_secrets(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("oci.authorize", "waiting", "OCI login required")
    job_path = tmp_path / "job.json"
    job.save(job_path)

    html = render_control_room(job)
    payload = control_room_payload(job_path)

    assert "FuseKit Control Room" in html
    assert "OCI login required" in html
    assert "What you need to do" in html
    assert "Oracle Cloud is opening the clean room" in html
    assert "Recovery map" in html
    assert "Every step stays alive" in html
    assert "checkpoint-card" in html
    assert "waiting politely with a tiny access badge" in html
    assert (
        "Live refresh paused. Keep this control room open; FuseKit will keep trying to reconnect."
    ) in html
    assert "Reopen or restart the control-room server" not in html
    assert "Snapshot view. Serve the control room for live updates." in html
    assert "setRefreshStatus" in html
    assert "function copyText(text)" in html
    assert 'document.createElement("textarea")' in html
    assert 'document.execCommand("copy")' in html
    assert "function renderVisual(job)" in html
    assert "data-visual-session" in html
    assert "fk-test" in html
    assert payload["id"] == "fk-test"


def test_control_room_brand_and_snowman_markup_match_assets(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "remote setup is running")

    html = render_control_room(job)

    assert "mark-hat" in html
    assert "mark-node mark-node-a" in html
    assert "brand-copy" in html
    assert '<span class="snow-hat"></span>' in html
    assert '<span class="steam one"></span>' in html


def test_control_room_renders_launch_run_state_contract(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    update_run_state(
        tmp_path / "run_state.json",
        app_repo_known=True,
        runner_selected=True,
        vault_created=True,
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert "Launch contract" in html
    assert "What FuseKit knows" in html
    assert 'data-run-state-field="app_repo_known"' in html
    assert "renderRunState" in html
    assert payload["run_state"]["app_repo_known"] is True
    assert payload["run_state"]["vault_created"] is True


def test_control_room_payload_and_html_include_acceptance_blockers(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "blockers": [
                    {
                        "category": "Provider order",
                        "item": "Resend-before-DNS provider setup order",
                        "next_action": (
                            "Capture RESEND_API_KEY first, then let FuseKit create or "
                            "reuse the Resend domain by API before you approve DNS apply."
                        ),
                        "detail": (
                            "missing control_room.gate_open: provider.cloudflare.authorization"
                        ),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["acceptance"]["blockers"][0]["category"] == "Provider order"
    assert (
        payload["acceptance"]["blockers"][0]["detail"]
        == "missing control_room.gate_open: provider.cloudflare.authorization"
    )
    assert "Launch blockers" in html
    assert "What must be fixed before recording" in html
    assert "Provider order" in html
    assert "Resend-before-DNS provider setup order" in html
    assert "Capture RESEND_API_KEY first" in html
    assert "Resend domain by API" in html
    assert "approve DNS apply" in html
    assert "Run Resend domain setup before Cloudflare/DNS" not in html
    assert "missing control_room.gate_open" in html
    assert "provider.cloudflare.authorization" in html
    assert "card.detail" in html
    assert "renderAcceptance" in html


def test_control_room_renders_acceptance_missing_when_blockers_absent(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "missing": [
                    "audited human gate interventions",
                    "guided human gates",
                    "complete provider strategy evidence",
                    "complete provider strategy coverage",
                    "complete provider verification coverage",
                    "complete rollback coverage",
                    "Resend DNS records in receipt DNS proposal",
                    "Resend runtime env in Vercel receipt",
                    "detonated worker state",
                ],
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["acceptance"]["missing"] == [
        "audited human gate interventions",
        "guided human gates",
        "complete provider strategy evidence",
        "complete provider strategy coverage",
        "complete provider verification coverage",
        "complete rollback coverage",
        "Resend DNS records in receipt DNS proposal",
        "Resend runtime env in Vercel receipt",
        "detonated worker state",
    ]
    assert "Human gates" in html
    assert "audited human gate interventions" in html
    assert "matching gate card&#x27;s single visible next action" in html
    assert "Open provider gate in VM" in html
    assert "Capture the exact env-named value such as RESEND_API_KEY" in html
    assert "VM clipboard for copy-once secrets" in html
    assert "target-specific Capture from VM clipboard buttons" not in html
    assert "I finished this step only after a non-secret provider confirmation" in html
    assert "Use the visible launcher controls for every gate" not in html
    assert "or I finished this step" not in html
    assert "Open, capture, or resume each control-room gate" not in html
    assert "guided human gates" in html
    assert "live launcher/control room" in html
    assert "follow-me steps, next action, and resume hint" in html
    assert "Regenerate gate state" not in html
    assert "Provider routes" in html
    assert "complete provider strategy evidence" in html
    assert "selected provider route" in html
    assert "fallback candidates for every provider route" in html
    assert "Record selected-route" not in html
    assert "complete provider strategy coverage" in html
    assert "every manifest provider has provider-route proof" in html
    assert "Record provider strategy evidence" not in html
    assert "Verification" in html
    assert "complete provider verification coverage" in html
    assert "Let FuseKit verify every provider declared by the manifest before acceptance" in html
    assert "Record verification checks for every provider declared by the manifest" not in html
    assert "Rollback" in html
    assert "complete rollback coverage" in html
    assert "Let FuseKit write rollback actions for every provider declared by the manifest" in html
    assert "Record rollback metadata for every provider declared by the manifest" not in html
    assert "Provider order" in html
    assert "Resend DNS records in receipt DNS proposal" in html
    assert "Cloudflare receives the exact Resend records" in html
    assert "Deployment env" in html
    assert "Capture RESEND_API_KEY in the launcher" in html
    assert "create or reuse the Resend domain/audience values by API" in html
    assert "Capture or generate the required RESEND_* values" not in html
    assert "Detonation" in html
    assert "9 launch blockers" in html
    assert "acceptanceBlockers" in html
    assert "missingAcceptanceBlocker" in html


def test_control_room_encrypted_vault_missing_is_launcher_actionable(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "missing": ["encrypted vault"],
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "Vault" in html
    assert "encrypted vault" in html
    assert "live launcher/control room" in html
    assert "VM clipboard Capture controls" in html
    assert "encrypted vault proof" in html
    assert "Run the launcher with vault capture enabled" not in html


def test_control_room_provider_pack_and_leak_scan_missing_are_launcher_actionable(
    tmp_path,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "missing": ["validated provider capability packs", "clean leak scan"],
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "Provider packs" in html
    assert "validated provider capability packs" in html
    assert "loads and validates provider capability packs" in html
    assert "Regenerate provider capability packs" not in html
    assert "Security" in html
    assert "clean leak scan" in html
    assert "vault Capture/provider secret storage" in html
    assert "rerun the launch leak scan" not in html


def test_control_room_detonation_missing_is_launcher_actionable(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "missing": ["detonated worker state"],
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "Detonation" in html
    assert "detonated worker state" in html
    assert "launcher/control room open" in html
    assert "FuseKit detonates plaintext worker, browser, visual, provider-auth" in html
    assert "control-room, and gateway scratch state" in html
    assert "after encrypted proof is preserved" in html
    assert "Run detonation" not in html


def test_control_room_northstar_missing_items_are_launcher_actionable(
    tmp_path,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "missing": [
                    "central run record",
                    "provider playbook",
                    "provider route recovery checkpoints",
                    "safe visual session state",
                    "OCI workspace detonation receipt",
                ],
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "Run record" in html
    assert "central run record" in html
    assert "state, gates, provider routes, verifier checks" in html
    assert "Provider playbook" in html
    assert "ordered VM-browser actions" in html
    assert "exact Capture controls" in html
    assert "provider route recovery checkpoints" in html
    assert "next action and resume hint" in html
    assert "Visual session" in html
    assert "safe noVNC/control-room URLs" in html
    assert "OCI workspace detonation receipt" in html
    assert "VM, boot volume, ephemeral public IP" in html
    assert "remote worker cleanup were destroyed" in html
    assert "missingAcceptanceBlocker" in html
    dynamic_guidance = html.split("function missingAcceptanceBlocker", 1)[1]
    assert "OCI workspace detonation receipt" in dynamic_guidance
    assert "workspace detonation receipt proving the VM" in html
    assert "Repair this acceptance item" not in html


def test_control_room_missing_provider_route_blockers_are_launcher_actionable(
    tmp_path,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "missing": [
                    "provider strategy decisions",
                    "Resend-before-DNS provider setup order",
                    "provider contract-health receipt proof",
                ],
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "Provider routes" in html
    assert "provider strategy decisions" in html
    assert "live launcher/control room" in html
    assert "setup worker record" in html
    assert "Resend-before-DNS provider setup order" in html
    assert "Capture RESEND_API_KEY first" in html
    assert "Resend domain by API" in html
    assert "approve DNS apply" in html
    assert "Run Resend domain setup before Cloudflare/DNS" not in html
    assert "provider contract-health receipt proof" in html
    assert "read-only provider health check before mutation" in html
    assert "exact env-named Capture button" in html


def test_control_room_missing_receipt_blocker_is_launcher_actionable(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "missing": ["redacted setup receipt"],
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "redacted setup receipt" in html
    assert "live launcher/control room" in html
    assert "setup worker finish provider setup" in html
    assert "redacted receipt with no raw secrets" in html
    assert "Rerun setup so the worker writes a redacted setup receipt" not in html


def test_control_room_missing_verification_and_rollback_are_launcher_actionable(
    tmp_path,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "missing": ["safe verification report", "rollback metadata"],
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "safe verification report" in html
    assert "live launcher/control room" in html
    assert "VM-browser gates" in html
    assert "pending-safe only when they are safe to keep watching" in html
    assert "Run provider verification" not in html
    assert "rollback metadata" in html
    assert "provider rollback actions before launch" in html
    assert "Generate rollback metadata" not in html


def test_control_room_unknown_acceptance_missing_uses_launcher_controls(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "launch_ready": False,
                "missing": ["custom provider launch proof"],
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")
    acceptance_html = _render_acceptance_blockers(payload["acceptance"])

    assert payload["acceptance"]["missing"] == ["custom provider launch proof"]
    assert payload["acceptance"]["blockers"] == []
    assert "custom provider launch proof" in acceptance_html
    assert "Launch evidence" in acceptance_html
    assert "Keep the control room open" in acceptance_html
    assert "single highlighted next action" in acceptance_html
    assert "Open provider gate in VM" in acceptance_html
    assert "env-named Capture button" in acceptance_html
    assert "I finished this step" in acceptance_html
    assert "Approve DNS apply" in acceptance_html
    assert "Use any visible" not in acceptance_html
    assert "Capture RESEND_API_KEY from VM clipboard" not in acceptance_html
    assert "Repair this acceptance item" not in acceptance_html
    assert "Run acceptance again after fixing this" not in acceptance_html
    assert "rerun the same live launch/acceptance" not in acceptance_html
    assert "keep this live control room open while FuseKit rebuilds" in acceptance_html
    assert "unknownAcceptanceBlockerAction" in html


def test_control_room_acceptance_report_error_uses_launcher_controls(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text("{not json", encoding="utf-8")

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["acceptance"]["launch_ready"] is False
    assert payload["acceptance"]["public_launch_ready"] is False
    assert payload["acceptance"]["recording_ready"] is False
    assert payload["acceptance"]["error"] == "Acceptance report could not be read from report.json"
    assert "Acceptance report could not load" in html
    assert "Acceptance report could not be read from report.json" in html
    assert "live launcher/control room open" in html
    assert "visible provider, DNS approval, and" in html
    assert "Capture controls" in html
    assert "Rerun acceptance so FuseKit can rebuild launch-readiness proof" not in html


def test_control_room_rejects_legacy_live_acceptance_without_public_flags(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps({"mode": "live", "launch_ready": True, "blockers": []}),
        encoding="utf-8",
    )

    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["acceptance"]["launch_ready"] is True
    assert payload["acceptance"]["public_launch_ready"] is False
    assert payload["acceptance"]["recording_ready"] is False


def test_control_room_rejects_string_acceptance_ready_flags(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "mode": "live",
                "launch_ready": "true",
                "public_launch_ready": "true",
                "recording_ready": "true",
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["acceptance"]["launch_ready"] is False
    assert payload["acceptance"]["public_launch_ready"] is False
    assert payload["acceptance"]["recording_ready"] is False
    assert "Acceptance blockers are clear" not in html.split("<script", 1)[0]
    assert "Record the demo from this clean state." not in html.split("<script", 1)[0]


def test_control_room_renderer_rejects_malformed_public_ready_field() -> None:
    html = _render_acceptance_blockers(
        {
            "mode": "live",
            "launch_ready": True,
            "public_launch_ready": "true",
            "recording_ready": True,
            "blockers": [],
        }
    )

    assert "Acceptance blockers are clear" not in html
    assert "Record the demo from this clean state." not in html
    assert "Public launch proof is still required" in html


def test_control_room_renders_acceptance_ready_state(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "mode": "live",
                "launch_ready": True,
                "public_launch_ready": True,
                "recording_ready": True,
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["acceptance"]["launch_ready"] is True
    assert payload["acceptance"]["mode"] == "live"
    assert payload["acceptance"]["public_launch_ready"] is True
    assert payload["acceptance"]["recording_ready"] is True
    assert "Acceptance blockers are clear" in html
    assert "The live run has the required proof to be launch-ready." in html
    assert "launch-ready proof is clear" in html


def test_control_room_does_not_record_when_recording_proof_is_false(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "mode": "live",
                "launch_ready": True,
                "public_launch_ready": True,
                "recording_ready": False,
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")
    static_html = html.split("<script", 1)[0]

    assert payload["acceptance"]["public_launch_ready"] is True
    assert payload["acceptance"]["recording_ready"] is False
    assert "Acceptance blockers are clear" not in static_html
    assert "Record the demo from this clean state." not in static_html
    assert "Recording proof is still required" in html
    assert "recording proof still required" in html


def test_control_room_does_not_treat_rehearsal_ready_as_recordable(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps({"mode": "rehearsal", "launch_ready": True, "blockers": []}),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["acceptance"]["launch_ready"] is True
    assert payload["acceptance"]["mode"] == "rehearsal"
    assert payload["acceptance"]["public_launch_ready"] is False
    assert payload["acceptance"]["recording_ready"] is False
    static_html = html.split("<script", 1)[0]
    assert "Live acceptance is still required" in html
    assert "Local rehearsal proof is clear, but it is not live provider evidence." in html
    assert "Keep using the live launcher/control room for the provider run" in html
    assert "FuseKit must collect live provider evidence before recording." in html
    assert "live acceptance still required" in html
    assert "The live run has the required proof to be launch-ready." not in static_html
    assert "Record the demo from this clean state." not in static_html
    assert "Run live acceptance after the provider run before recording the demo." not in html
    assert 'mode === "live"' in html


def test_control_room_respects_explicit_public_launch_ready_flag(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    acceptance_dir = tmp_path / "acceptance"
    acceptance_dir.mkdir()
    (acceptance_dir / "report.json").write_text(
        json.dumps(
            {
                "mode": "live",
                "launch_ready": True,
                "public_launch_ready": False,
                "blockers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["acceptance"]["public_launch_ready"] is False
    assert payload["acceptance"]["recording_ready"] is False
    assert "Acceptance blockers are clear" not in html.split("<script", 1)[0]
    assert "Record the demo from this clean state." not in html.split("<script", 1)[0]
    assert "Public launch proof is still required" in html
    assert "public launch proof still required" in html


def test_control_room_renders_verification_trust_cards(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    report = tmp_path / "verification_report.json"
    report.write_text(
        json.dumps(
            {
                "overall": "pending",
                "checks": [
                    {
                        "provider": "resend",
                        "check": "auth_valid",
                        "status": "passed",
                        "summary": "resend auth valid passed.",
                        "repair": "Nothing needed.",
                    },
                    {
                        "provider": "cloudflare",
                        "check": "dns_verified",
                        "status": "pending",
                        "summary": "cloudflare dns verified is still pending.",
                        "repair": "Keep waiting for DNS propagation.",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    job.add_artifact("verification_report", report)

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert "Trust checks" in html
    assert "Proof it really works" in html
    assert "trust-snow state-passed" in html
    assert "trust-snow state-checking" in html
    assert payload["verification"]["overall"] == "pending"


def test_control_room_explains_pending_safe_dns_approval(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    report = tmp_path / "verification_report.json"
    report.write_text(
        json.dumps(
            {
                "overall": "pending-safe",
                "checks": [
                    {
                        "provider": "live_app",
                        "check": "live_url_healthy",
                        "status": "pending",
                        "summary": "live URL is still pending.",
                        "repair": "Keep waiting.",
                        "details": {
                            "pending_safe": True,
                            "reason": "custom DNS apply is waiting for approval or propagation",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    job.add_artifact("verification_report", report)

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "DNS changes are waiting for approval or propagation." in html
    assert "Approve/apply the exact DNS records in the setup plan" in html
    assert "trustCardCopy" in html


def test_control_room_reports_invalid_verification_report_as_failed(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    report = tmp_path / "verification_report.json"
    report.write_text("[]", encoding="utf-8")
    job.add_artifact("verification_report", report)

    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["verification"]["overall"] == "failed"
    assert "not a JSON object" in payload["verification"]["error"]


def test_control_room_payload_includes_active_gate_records(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "remote setup is running")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.vercel.authorization",
        provider="vercel",
        reason="vercel login/MFA/CAPTCHA/billing/consent/token creation",
        resume_url="https://vercel.com/account/tokens",
        classification="mfa",
        target="Continue",
        follow_steps=("Click Continue", "Finish the MFA prompt"),
        success_criteria=("Exact custom success marker",),
        avoid_steps=("Exact custom avoid marker",),
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = control_room_payload(job_path)

    assert payload["status"] == "running"
    assert payload["gates"][0]["provider"] == "vercel"
    assert payload["gates"][0]["status"] == "waiting"
    assert "token" in str(payload["gates"][0]["reason"])
    assert "next_action" in payload["gates"][0]
    assert "resume_hint" in payload["gates"][0]
    assert "vercel needs your approval" in html
    assert "Click Continue" in html
    assert "Snowman highlighted" in html
    assert "Exact custom success marker" in html
    assert "Exact custom avoid marker" in html
    assert "Next" in html
    assert "Finish the vercel login" in html
    assert "retry verification after you click" in html
    assert 'data-gate-pass="provider.vercel.authorization"' in html
    assert "Capture CONTINUE from VM clipboard" not in html
    assert "<strong data-count-waiting>1</strong> gates" in html


def test_control_room_uses_gate_provider_for_guidance_when_id_is_generic(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "remote setup is running")
    GateService.load(tmp_path / "gates.json").wait(
        "authorization",
        provider="resend",
        reason="provider authorization required",
        resume_url="https://resend.com/api-keys",
        classification="provider-authorization",
        target="RESEND_API_KEY",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    visible_html = html[: html.index("<script")]

    assert "Resend needs an email API key" in visible_html
    assert "before Cloudflare DNS" in visible_html
    assert "Success looks like" in visible_html
    assert "A raw Resend API key value is copied from a new one-time reveal screen." in visible_html
    assert "Avoid" in visible_html
    assert "Do not click Add domain when Resend says No domains yet." in visible_html
    assert "Open provider gate in VM" in visible_html
    assert "Capture RESEND_API_KEY from VM clipboard" in visible_html
    assert "Capture from VM clipboard" not in visible_html
    assert "Copy the provider value in the VM browser" in visible_html
    assert "resume automatically after every target is captured" in visible_html
    assert "VM clipboard Capture and vault encryption keep secrets yours." in visible_html
    assert "Hidden prompts and vault encryption keep secrets yours." not in visible_html
    assert 'data-gate-capture="authorization"' in html
    assert "gate-action-status" in html
    assert "data-gate-action-status-for" in html
    assert "Capturing ${target} from the VM clipboard into the encrypted vault" in html
    assert "step.provider ||" in html
    assert "renderGateCriteria" in html


def test_control_room_resend_setup_retry_uses_finished_button_not_capture(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "remote setup is running")
    GateService.load(tmp_path / "gates.json").wait(
        "provider.resend.domain-setup-retry",
        provider="resend",
        reason=(
            "Resend has a valid setup key, but the sending domain does not exist yet. "
            "FuseKit should create or reuse the domain through Resend's API before DNS is applied."
        ),
        resume_url="https://resend.com/api-keys",
        classification="provider-setup-retry",
        target="",
        follow_steps=(
            "No manual Resend domain or DNS step is needed here.",
            "Click I finished this step.",
        ),
        next_action=(
            "No manual Resend domain work is needed. Click I finished this step so "
            "FuseKit retries Resend domain setup through the API."
        ),
        resume_hint=(
            "FuseKit will rerun Resend API setup, pull the returned DNS records, "
            "and only then continue to Cloudflare DNS."
        ),
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "No manual Resend domain work is needed" in html
    assert "Click I finished this step" in html
    assert 'data-gate-pass="provider.resend.domain-setup-retry"' in html
    assert 'data-gate-capture="provider.resend.domain-setup-retry"' not in html
    assert 'data-gate-capture-target="RESEND_API_KEY"' not in html
    assert "Sending your approval so FuseKit can recheck" in html
    assert "Recheck requested" in html
    assert "FuseKit accepted this step and is rechecking the provider now" in html
    assert "Action status" in html


def test_control_room_gate_help_includes_resume_link_and_attempts(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "remote setup is running")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.vercel.authorization",
        provider="vercel",
        reason="vercel login/MFA/CAPTCHA/billing/consent/token creation",
        resume_url="https://vercel.com/account/tokens",
        classification="mfa",
        target="ref=7",
        follow_steps=("Use the highlighted MFA field.", "Click I finished this step."),
    )
    service.wait(
        "provider.vercel.authorization",
        provider="vercel",
        reason="vercel login/MFA/CAPTCHA/billing/consent/token creation",
        resume_url="https://vercel.com/account/tokens",
    )

    html = render_control_room(JobState.load(job_path), gate_path=tmp_path / "gates.json")

    assert "Open provider gate in VM" in html
    assert 'data-gate-open="provider.vercel.authorization"' in html
    assert "Opening the provider gate inside the shared VM browser" in html
    assert "gate-attempts" in html
    assert "https://vercel.com/account/tokens" in html
    assert '"attempts":2' in html or '"attempts": 2' in html
    assert "Use the highlighted MFA field." in html
    assert "I finished this step" in html
    assert "state-gate" in html


def test_control_room_dns_gate_uses_approval_button(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark("setup.execute", "running", "remote setup is running")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "dns.moonlite.rsvp.approval",
        provider="dns",
        reason="explicit DNS apply approval for moonlite.rsvp",
        classification="dns-approval",
        follow_steps=("Review the DNS records.", "Click Approve DNS apply."),
        next_action="Approve applying the DNS records for moonlite.rsvp.",
        resume_hint="FuseKit will apply and verify propagation.",
    )

    html = render_control_room(JobState.load(job_path), gate_path=tmp_path / "gates.json")

    assert 'data-gate-pass="dns.moonlite.rsvp.approval">Approve DNS apply</button>' in html
    assert "gateDoneLabel" in html
    assert "Approve DNS apply" in html
    GateService.load(tmp_path / "gates.json").request_resume("dns.moonlite.rsvp.approval")
    html = render_control_room(JobState.load(job_path), gate_path=tmp_path / "gates.json")
    assert "FuseKit is applying the approved DNS records now." in html
    assert "gateRetryDetail" in html


def test_control_room_renders_resume_requested_gate_as_rechecking(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.cloudflare.authorization",
        provider="cloudflare",
        reason="Cloudflare token creation",
        resume_url="https://dash.cloudflare.com/profile/api-tokens",
        success_criteria=("Exact recheck success marker",),
        avoid_steps=("Exact recheck avoid marker",),
    )
    service.request_resume("provider.cloudflare.authorization")

    html = render_control_room(JobState.load(job_path), gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["gates"][0]["status"] == "resume_requested"
    assert "cloudflare gate is being rechecked" in html.lower()
    assert "gate-rechecking" in html
    assert "FuseKit is rechecking now" in html
    assert "Success looks like" in html
    assert "Exact recheck success marker" in html
    assert "Avoid" in html
    assert "Exact recheck avoid marker" in html
    assert "retrying provider verification now" in html
    assert "next guided blocker or success state" in html
    assert 'data-gate-pass="provider.cloudflare.authorization"' not in html
    assert "FuseKit accepted this step and is rechecking the provider now" in html
    assert "Keep this control room open; the next step will appear here" in html
    assert "Snowman is rechecking the provider now" not in html
    assert "Could not record I finished this step from this control room" in html
    assert "FuseKit will keep waiting for the visible gate action" in html
    assert "from this snapshot" not in html
    assert "Could not mark the gate done" not in html
    assert "await refreshJob({ preserveStatus: true });" in html
    assert "function publicFailureReason" in html
    assert "Could not open the provider gate inside the VM automatically" in html
    assert "FuseKit will keep the gate visible for retry" in html
    assert "No VM browser binary" in html
    assert "Use Open live VM browser" not in html


def test_control_room_renders_vm_clipboard_capture_for_secret_gate(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.resend.api-key-domain-access",
        provider="resend",
        reason="Resend API key",
        classification="provider-authorization",
        target="RESEND_API_KEY",
        follow_steps=(
            "Copy the API key inside the VM.",
            "When Resend reveals it, paste it into FuseKit's hidden prompt.",
        ),
    )

    html = render_control_room(JobState.load(job_path), gate_path=tmp_path / "gates.json")
    visible_html = html[: html.index("<script")]

    assert "Safe secret capture" in visible_html
    assert "Copy the provider value inside the VM browser" in visible_html
    assert "Copy the provider value in the VM browser" in visible_html
    assert "click the matching" not in visible_html
    assert "Capture RESEND_API_KEY from VM clipboard below" in visible_html
    assert "click Capture RESEND_API_KEY from VM clipboard" in visible_html
    assert "Capture from VM clipboard button below" not in visible_html
    assert "target-specific Capture" not in visible_html
    assert "click Capture here" not in visible_html
    assert "FuseKit will resume automatically after every target is captured." in visible_html
    assert "reads only the VM clipboard" in visible_html
    assert "encrypted vault" in visible_html
    assert "Capture RESEND_API_KEY from VM clipboard" in visible_html
    assert 'data-gate-capture="provider.resend.api-key-domain-access"' in html
    assert 'data-gate-capture-target="RESEND_API_KEY"' in html
    assert 'data-gate-pass="provider.resend.api-key-domain-access"' not in html
    assert "await refreshJob({ preserveStatus: true });" in html
    assert "function refreshJob(options = {})" in html


def test_control_room_redacts_sensitive_gate_target_display(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    raw_code = "abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    target = f"https://provider.example/callback?code={raw_code}&state=visible"
    GateService.load(tmp_path / "gates.json").wait(
        "provider.generic.callback",
        provider="generic",
        reason="Provider callback requires review.",
        classification="provider-verification",
        target=target,
        follow_steps=("Review the highlighted callback.",),
    )

    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")
    html = render_control_room(JobState.load(job_path), gate_path=tmp_path / "gates.json")

    assert payload["gates"][0]["target"] == (
        "https://provider.example/callback?code=[redacted]&state=visible"
    )
    assert "code=[redacted]" in html
    assert "state=visible" in html
    assert raw_code not in json.dumps(payload)
    assert raw_code not in html
    assert "function publicTarget" in html


def test_control_room_post_requests_human_gate_resume(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    audit_path = tmp_path / "audit.jsonl"
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
        follow_steps=("Pass the provider MFA challenge.",),
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["ok"] is True
    assert payload["status"] == "resume_requested"
    assert payload["message"] == "FuseKit is retrying provider verification now."
    assert payload["wake_event"] == "resume_requested"
    assert payload["wake_event_id"]
    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "resume_requested"
    )
    events = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert events[-1]["event"] == "control_room.gate_resume_requested"
    assert events[-1]["data"]["gate_id"] == "provider.github.mfa.123"
    assert events[-1]["data"]["provider"] == "github"
    assert events[-1]["data"]["protected_action"] is True
    assert events[-1]["data"]["status"] == "resume_requested"
    assert events[-1]["data"]["wake_event_id"] == payload["wake_event_id"]


def test_control_room_post_pass_is_idempotent_for_already_resuming_gate(
    tmp_path,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    audit_path = tmp_path / "audit.jsonl"
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
        follow_steps=("Pass the provider MFA challenge.",),
    )
    service.request_resume("provider.github.mfa.123")
    gate_events_path = tmp_path / "gate_events.jsonl"
    original_gate_events = gate_events_path.read_text(encoding="utf-8")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["ok"] is True
    assert payload["status"] == "resume_requested"
    assert payload["message"] == (
        "Keep this control room open; the next guided blocker or success state "
        "will appear after the provider check finishes."
    )
    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "resume_requested"
    )
    assert gate_events_path.read_text(encoding="utf-8") == original_gate_events
    assert not audit_path.exists()


def test_control_room_post_pass_does_not_regress_passed_gate(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    audit_path = tmp_path / "audit.jsonl"
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.cloudflare.login",
        provider="cloudflare",
        reason="Login complete",
        classification="provider-verification",
        follow_steps=("Pass the Cloudflare login gate.",),
    )
    service.pass_gate("provider.cloudflare.login")
    gates_before = (tmp_path / "gates.json").read_text(encoding="utf-8")
    gate_events_path = tmp_path / "gate_events.jsonl"
    assert not gate_events_path.exists()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.cloudflare.login/pass"
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["ok"] is True
    assert payload["status"] == "passed"
    assert payload["message"] == "FuseKit verified this gate as passed."
    assert (
        GateService.load(tmp_path / "gates.json").records["provider.cloudflare.login"].status
        == "passed"
    )
    assert (tmp_path / "gates.json").read_text(encoding="utf-8") == gates_before
    assert not gate_events_path.exists()
    assert not audit_path.exists()


def test_control_room_post_dns_approval_reports_dns_apply(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    audit_path = tmp_path / "audit.jsonl"
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "dns.moonlite.rsvp.approval",
        provider="dns",
        reason="explicit DNS apply approval for moonlite.rsvp",
        classification="dns-approval",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/dns.moonlite.rsvp.approval/pass"
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["ok"] is True
    assert payload["status"] == "resume_requested"
    assert payload["message"] == "FuseKit is applying the approved DNS records now."
    assert "provider verification" not in json.dumps(payload)


def test_control_room_post_rejects_capture_gate_resume_before_capture(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.resend.api-key-domain-access",
        provider="resend",
        reason="Resend API key",
        classification="provider-authorization",
        target="RESEND_API_KEY",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.resend.api-key-domain-access/pass"
        )
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 400
    assert payload == {
        "error": "This gate needs safe secret capture before it can resume.",
        "gate_id": "provider.resend.api-key-domain-access",
        "missing_targets": ["RESEND_API_KEY"],
        "next_action": (
            "Click Capture RESEND_API_KEY from VM clipboard, then FuseKit will continue."
        ),
        "ok": False,
    }
    gate = GateService.load(tmp_path / "gates.json").records[
        "provider.resend.api-key-domain-access"
    ]
    assert gate.status == "waiting"


def test_control_room_post_rejects_multi_capture_gate_with_exact_copy(
    tmp_path,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.custom.tokens",
        provider="custom",
        reason="Provider keys",
        classification="provider-authorization",
        target="CUSTOM_API_KEY, CUSTOM_WEBHOOK_SECRET",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.custom.tokens/pass"
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 400
    assert payload["missing_targets"] == ["CUSTOM_API_KEY", "CUSTOM_WEBHOOK_SECRET"]
    assert "Click these exact Capture buttons" in payload["next_action"]
    assert "Capture CUSTOM_API_KEY from VM clipboard" in payload["next_action"]
    assert "Capture CUSTOM_WEBHOOK_SECRET from VM clipboard" in payload["next_action"]
    assert "Capture button from the VM clipboard" not in payload["next_action"]
    gate = GateService.load(tmp_path / "gates.json").records["provider.custom.tokens"]
    assert gate.captured_targets == ()


def test_control_room_clipboard_capture_rejects_wrong_target_with_exact_buttons(
    tmp_path,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.custom.tokens",
        provider="custom",
        reason="Provider keys",
        classification="provider-authorization",
        target="CUSTOM_API_KEY, CUSTOM_WEBHOOK_SECRET",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.custom.tokens/capture-clipboard"
        )
        request = Request(
            url,
            data=json.dumps({"target": "WRONG_TARGET"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(
                tmp_path,
                **{"content-type": "application/json"},
            ),
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 400
    assert payload["ok"] is False
    assert "Use the matching visible button" in payload["error"]
    assert "Capture CUSTOM_API_KEY from VM clipboard" in payload["error"]
    assert "Capture CUSTOM_WEBHOOK_SECRET from VM clipboard" in payload["error"]
    assert "Capture from VM clipboard button for" not in payload["error"]


def test_local_control_room_requires_action_token_for_gate_post(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        request = Request(
            url,
            method="POST",
            headers={"x-fusekit-control-room": "resume"},
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 403
    assert payload == {"error": "invalid action token", "ok": False}
    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "waiting"
    )


def test_control_room_rejects_encoded_slash_gate_route(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    unsafe_gate_id = "provider.github/mfa.123"
    GateService.load(tmp_path / "gates.json").wait(
        unsafe_gate_id,
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github%2Fmfa.123/pass"
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = exc.value.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert exc.value.code == 404
    assert payload == b""
    assert GateService.load(tmp_path / "gates.json").records[unsafe_gate_id].status == "waiting"


def test_control_room_reuses_action_token_with_owner_only_permissions(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    token_path = tmp_path / "control-room-action-token"
    existing = "A" * 32
    token_path.write_text(existing, encoding="utf-8")
    os.chmod(token_path, 0o644)

    token = _control_room_action_token(job_path)

    assert token == existing
    assert token_path.stat().st_mode & 0o777 == 0o600


def test_control_room_origin_check_rejects_spoofed_loopback_hosts(monkeypatch) -> None:
    monkeypatch.delenv("FUSEKIT_CONTROL_ROOM_TOKEN", raising=False)

    assert _trusted_browser_origin("http://127.0.0.1:8765", "127.0.0.1:8765")
    assert _trusted_browser_origin("http://localhost:8765", "localhost:8765")
    assert not _trusted_browser_origin(
        "http://127.0.0.1.attacker.example:8765",
        "127.0.0.1:8765",
    )
    assert not _trusted_browser_origin(
        "http://127.0.0.1@attacker.example:8765",
        "127.0.0.1:8765",
    )
    assert not _trusted_browser_origin(
        "http://attacker.example#127.0.0.1:8765",
        "127.0.0.1:8765",
    )
    assert not _trusted_browser_origin("file://127.0.0.1:8765", "127.0.0.1:8765")


def test_remote_control_room_origin_requires_same_host_with_access_token(
    monkeypatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", REMOTE_CONTROL_ROOM_TOKEN)

    assert _trusted_browser_origin("http://runner.example:8765", "runner.example:8765")
    assert not _trusted_browser_origin(
        "http://attacker.example:8765",
        "runner.example:8765",
    )
    assert not _trusted_browser_origin(
        "http://runner.example:9999",
        "runner.example:8765",
    )


def test_control_room_browser_metadata_policy_preserves_local_automation() -> None:
    assert _trusted_browser_origin(None, "127.0.0.1:8765") is True
    assert _trusted_fetch_site(None) is True
    assert _trusted_fetch_site("same-origin") is True
    assert _trusted_fetch_site("none") is True
    assert _trusted_fetch_site("same-site") is False
    assert _trusted_fetch_site("cross-site") is False


@pytest.mark.parametrize(
    ("gate_id", "route_suffix", "target", "resume_url"),
    (
        ("provider.github.mfa.123", "pass", "", ""),
        (
            "provider.cloudflare.authorization",
            "open",
            "",
            "https://dash.cloudflare.com/profile/api-tokens",
        ),
        ("provider.resend.api-key-domain-access", "capture-clipboard", "RESEND_API_KEY", ""),
    ),
)
def test_control_room_state_routes_require_action_token(
    tmp_path,
    gate_id: str,
    route_suffix: str,
    target: str,
    resume_url: str,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        gate_id,
        provider="resend" if target else "github",
        reason="Provider gate",
        resume_url=resume_url,
        classification="provider-authorization",
        target=target,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/{gate_id}/{route_suffix}"
        request = Request(
            url,
            data=json.dumps({"target": target}).encode("utf-8"),
            method="POST",
            headers={
                "x-fusekit-control-room": "resume",
                "content-type": "application/json",
            },
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 403
    assert payload == {"error": "invalid action token", "ok": False}
    gate = GateService.load(tmp_path / "gates.json").records[gate_id]
    assert gate.status == "waiting"
    assert gate.captured_targets == ()
    assert gate.last_opened_url == ""


@pytest.mark.parametrize(
    ("gate_id", "route_suffix", "target", "resume_url"),
    (
        ("provider.github.mfa.123", "pass", "", ""),
        (
            "provider.cloudflare.authorization",
            "open",
            "",
            "https://dash.cloudflare.com/profile/api-tokens",
        ),
        ("provider.resend.api-key-domain-access", "capture-clipboard", "RESEND_API_KEY", ""),
    ),
)
def test_control_room_state_routes_reject_cross_site_posts(
    tmp_path,
    gate_id: str,
    route_suffix: str,
    target: str,
    resume_url: str,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        gate_id,
        provider="resend" if target else "github",
        reason="Provider gate",
        resume_url=resume_url,
        classification="provider-authorization",
        target=target,
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/{gate_id}/{route_suffix}"
        request = Request(
            url,
            data=json.dumps({"target": target}).encode("utf-8"),
            method="POST",
            headers={
                **_control_room_post_headers(tmp_path),
                "content-type": "application/json",
                "Origin": "https://attacker.example",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 403
    assert payload == {"error": "untrusted origin", "ok": False}
    gate = GateService.load(tmp_path / "gates.json").records[gate_id]
    assert gate.status == "waiting"
    assert gate.captured_targets == ()
    assert gate.last_opened_url == ""


@pytest.mark.parametrize(
    ("case", "expected_error"),
    (
        ("missing-control-room-header", "missing control-room header"),
        ("untrusted-origin", "untrusted origin"),
        ("cross-site-fetch-site", "cross-site request"),
        ("invalid-action-token", "invalid action token"),
    ),
)
def test_control_room_gate_post_rejection_branches_keep_hardened_headers(
    tmp_path,
    case: str,
    expected_error: str,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        action_token = (tmp_path / "control-room-action-token").read_text(encoding="utf-8").strip()
        headers = {
            "x-fusekit-control-room": "resume",
            "x-fusekit-action-token": action_token,
        }
        if case == "missing-control-room-header":
            headers.pop("x-fusekit-control-room")
        elif case == "untrusted-origin":
            headers["Origin"] = "https://attacker.example"
        elif case == "cross-site-fetch-site":
            headers["Origin"] = base
            headers["Sec-Fetch-Site"] = "cross-site"
        elif case == "invalid-action-token":
            headers["x-fusekit-action-token"] = "wrong-action-token"
        url = f"{base}/api/gates/provider.github.mfa.123/pass"
        request = Request(url, method="POST", headers=headers)
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 403
    assert payload == {"error": expected_error, "ok": False}
    _assert_hardened_control_room_error_headers(exc.value)
    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "waiting"
    )


def test_control_room_post_opens_gate_inside_vm_browser(tmp_path, monkeypatch) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    audit_path = tmp_path / "audit.jsonl"
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    (tmp_path / "visual.json").write_text(json.dumps({"display": ":99"}), encoding="utf-8")
    GateService.load(tmp_path / "gates.json").wait(
        "provider.cloudflare.authorization",
        provider="cloudflare",
        reason="Cloudflare token creation",
        resume_url="https://dash.cloudflare.com/profile/api-tokens",
        classification="consent",
    )
    calls: list[dict[str, Any]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):  # type: ignore[no-untyped-def]
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_chrome.chmod(0o700)
    shared_profile = tmp_path / "shared-vm-profile"
    monkeypatch.setenv("FUSEKIT_VISUAL_BROWSER", str(fake_chrome))
    monkeypatch.setenv("FUSEKIT_PROVIDER_BROWSER_PROFILE", str(shared_profile))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    monkeypatch.setenv("FUSEKIT_PROVIDER_TOKEN", "provider-token")
    monkeypatch.setenv("FUSEKIT_VAULT_PASSPHRASE", "passphrase")
    monkeypatch.setenv("FUSEKIT_PROVIDER_SESSION_COOKIE", "provider-cookie")
    monkeypatch.setenv("FUSEKIT_VISUAL_SAFE_SETTING", "kept")
    monkeypatch.setenv("XAUTHORITY", "/tmp/fusekit-xauthority")
    monkeypatch.setattr("fusekit.runner.control_room.server.subprocess.Popen", fake_popen)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.cloudflare.authorization/open"
        )
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            second_payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["ok"] is True
    assert payload["reused"] is False
    assert payload["browser"] == fake_chrome.name
    assert str(tmp_path) not in payload["browser"]
    assert "shared VM browser" in payload["message"]
    assert second_payload["ok"] is True
    assert second_payload["reused"] is True
    assert "already open" in second_payload["message"]
    assert len(calls) == 1
    assert calls[0]["command"][-1] == "https://dash.cloudflare.com/profile/api-tokens"
    assert f"--user-data-dir={shared_profile}" in calls[0]["command"]
    assert calls[0]["env"]["DISPLAY"] == ":99"
    assert calls[0]["env"]["FUSEKIT_VISUAL_SAFE_SETTING"] == "kept"
    assert calls[0]["env"]["XAUTHORITY"] == "/tmp/fusekit-xauthority"
    assert "OPENAI_API_KEY" not in calls[0]["env"]
    assert "RESEND_API_KEY" not in calls[0]["env"]
    assert "FUSEKIT_PROVIDER_TOKEN" not in calls[0]["env"]
    assert "FUSEKIT_VAULT_PASSPHRASE" not in calls[0]["env"]
    assert "FUSEKIT_PROVIDER_SESSION_COOKIE" not in calls[0]["env"]
    assert calls[0]["command"][0] == str(fake_chrome)
    gate = GateService.load(tmp_path / "gates.json").records["provider.cloudflare.authorization"]
    assert gate.last_opened_url == "https://dash.cloudflare.com/profile/api-tokens"
    assert gate.last_opened_at > 0
    events = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert [event["event"] for event in events[-2:]] == [
        "control_room.gate_open",
        "control_room.gate_open",
    ]
    assert events[-2]["data"]["protected_action"] is True
    assert events[-1]["data"]["protected_action"] is True
    assert events[-2]["data"]["reused"] is False
    assert events[-1]["data"]["reused"] is True
    assert events[-1]["data"]["has_resume_url"] is True
    assert "dash.cloudflare.com" not in audit_path.read_text(encoding="utf-8")


def test_control_room_post_open_is_idempotent_for_already_resuming_gate(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    audit_path = tmp_path / "audit.jsonl"
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.cloudflare.authorization",
        provider="cloudflare",
        reason="Cloudflare token creation",
        resume_url="https://dash.cloudflare.com/profile/api-tokens",
        classification="consent",
    )
    service.request_resume("provider.cloudflare.authorization")
    gates_before = (tmp_path / "gates.json").read_text(encoding="utf-8")
    gate_events_before = (tmp_path / "gate_events.jsonl").read_text(encoding="utf-8")
    calls: list[object] = []
    monkeypatch.setattr(
        "fusekit.runner.control_room.server.subprocess.Popen",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.cloudflare.authorization/open"
        )
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["ok"] is True
    assert payload["status"] == "resume_requested"
    assert payload["browser"] == ""
    assert payload["reused"] is True
    assert "next guided blocker" in payload["message"]
    assert calls == []
    assert (tmp_path / "gates.json").read_text(encoding="utf-8") == gates_before
    assert (tmp_path / "gate_events.jsonl").read_text(encoding="utf-8") == gate_events_before
    assert not audit_path.exists()


def test_control_room_post_open_does_not_reopen_passed_gate(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    audit_path = tmp_path / "audit.jsonl"
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.cloudflare.authorization",
        provider="cloudflare",
        reason="Cloudflare token creation",
        resume_url="https://dash.cloudflare.com/profile/api-tokens",
        classification="consent",
    )
    service.pass_gate("provider.cloudflare.authorization")
    gates_before = (tmp_path / "gates.json").read_text(encoding="utf-8")
    calls: list[object] = []
    monkeypatch.setattr(
        "fusekit.runner.control_room.server.subprocess.Popen",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.cloudflare.authorization/open"
        )
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["ok"] is True
    assert payload["status"] == "passed"
    assert payload["browser"] == ""
    assert payload["reused"] is True
    assert payload["message"] == "FuseKit verified this gate as passed."
    assert calls == []
    assert (tmp_path / "gates.json").read_text(encoding="utf-8") == gates_before
    assert not (tmp_path / "gate_events.jsonl").exists()
    assert not audit_path.exists()


def test_control_room_visual_browser_env_strips_secrets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", "remote-control-room-token")
    monkeypatch.setenv("FUSEKIT_VAULT_PASSPHRASE", "passphrase")
    monkeypatch.setenv("FUSEKIT_PROVIDER_SESSION_COOKIE", "provider-cookie")
    monkeypatch.setenv("FUSEKIT_VISUAL_SAFE_SETTING", "kept")
    monkeypatch.setenv("XAUTHORITY", "/tmp/fusekit-xauthority")

    env = _visual_browser_env(":99")

    assert env["DISPLAY"] == ":99"
    assert env["FUSEKIT_VISUAL_SAFE_SETTING"] == "kept"
    assert env["XAUTHORITY"] == "/tmp/fusekit-xauthority"
    assert "OPENAI_API_KEY" not in env
    assert "RESEND_API_KEY" not in env
    assert "FUSEKIT_CONTROL_ROOM_TOKEN" not in env
    assert "FUSEKIT_VAULT_PASSPHRASE" not in env
    assert "FUSEKIT_PROVIDER_SESSION_COOKIE" not in env


def test_control_room_vm_clipboard_read_strips_secret_env(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "visual.json").write_text(json.dumps({"display": ":99"}), encoding="utf-8")

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("RESEND_API_KEY", "re_test")
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", "remote-control-room-token")
    monkeypatch.setenv("FUSEKIT_VAULT_PASSPHRASE", "passphrase")
    monkeypatch.setenv("FUSEKIT_PROVIDER_SESSION_COOKIE", "provider-cookie")
    monkeypatch.setenv("FUSEKIT_VISUAL_SAFE_SETTING", "kept")
    monkeypatch.setenv("XAUTHORITY", "/tmp/fusekit-xauthority")
    monkeypatch.setattr(
        "fusekit.runner.control_room.server.shutil.which",
        lambda name: "/usr/bin/xclip" if name == "xclip" else None,
    )
    calls: list[dict[str, Any]] = []

    def fake_run(command, **kwargs):  # type: ignore[no-untyped-def]
        calls.append({"command": command, **kwargs})
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="clipboard-value\n",
            stderr="",
        )

    monkeypatch.setattr("fusekit.runner.control_room.server.subprocess.run", fake_run)

    assert _vm_clipboard_text(job_path) == "clipboard-value\n"
    assert calls
    env = calls[0]["env"]
    assert calls[0]["command"] == ("xclip", "-selection", "clipboard", "-o")
    assert env["DISPLAY"] == ":99"
    assert env["FUSEKIT_VISUAL_SAFE_SETTING"] == "kept"
    assert env["XAUTHORITY"] == "/tmp/fusekit-xauthority"
    assert "OPENAI_API_KEY" not in env
    assert "RESEND_API_KEY" not in env
    assert "FUSEKIT_CONTROL_ROOM_TOKEN" not in env
    assert "FUSEKIT_VAULT_PASSPHRASE" not in env
    assert "FUSEKIT_PROVIDER_SESSION_COOKIE" not in env


def test_control_room_open_reuses_active_gate_even_after_debounce_window(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.cloudflare.authorization",
        provider="cloudflare",
        reason="Cloudflare token creation",
        resume_url="https://dash.cloudflare.com/profile/api-tokens",
        classification="provider-authorization",
    )
    calls: list[list[str]] = []

    class FakeProcess:
        pass

    def fake_popen(command, **kwargs):  # type: ignore[no-untyped-def]
        del kwargs
        calls.append(command)
        return FakeProcess()

    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_chrome.chmod(0o700)
    monkeypatch.setenv("FUSEKIT_VISUAL_BROWSER", str(fake_chrome))
    monkeypatch.setattr("fusekit.runner.control_room.server.subprocess.Popen", fake_popen)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.cloudflare.authorization/open"
        )
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            first_payload = json.loads(response.read().decode("utf-8"))
        service = GateService.load(tmp_path / "gates.json")
        gate = service.records["provider.cloudflare.authorization"]
        gate.last_opened_at = 1.0
        service.save()
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with urlopen(request, timeout=5) as response:
            second_payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert first_payload["reused"] is False
    assert second_payload["reused"] is True
    assert "Use the live VM browser" in second_payload["message"]
    assert "browser surface" not in second_payload["message"]
    assert len(calls) == 1


def test_control_room_open_rejects_unsafe_gate_url_before_browser_launch(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.cloudflare.authorization",
        provider="cloudflare",
        reason="Cloudflare token creation",
        resume_url="javascript:alert(1)",
        classification="consent",
    )
    monkeypatch.setenv("FUSEKIT_VISUAL_BROWSER", "/usr/bin/fake-chrome")
    monkeypatch.setattr(
        "fusekit.runner.control_room.server.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("unsafe gate URL must not launch a browser"),
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.cloudflare.authorization/open"
        )
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 400
    assert payload == {"error": "Provider gate URL must include a host.", "ok": False}
    gate = GateService.load(tmp_path / "gates.json").records["provider.cloudflare.authorization"]
    assert gate.last_opened_url == ""
    assert gate.status == "waiting"


def test_control_room_open_rejects_local_network_gate_url_before_browser_launch(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.custom.authorization",
        provider="custom",
        reason="Custom token creation",
        resume_url="https://127.0.0.1:8765/admin",
        classification="consent",
    )
    monkeypatch.setenv("FUSEKIT_VISUAL_BROWSER", "/usr/bin/fake-chrome")
    monkeypatch.setattr(
        "fusekit.runner.control_room.server.subprocess.Popen",
        lambda *args, **kwargs: pytest.fail("local gate URL must not launch a browser"),
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.custom.authorization/open"
        request = Request(url, method="POST", headers=_control_room_post_headers(tmp_path))
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 400
    assert payload == {
        "error": "Provider gate URL must not target local or private network hosts.",
        "ok": False,
    }
    gate = GateService.load(tmp_path / "gates.json").records["provider.custom.authorization"]
    assert gate.last_opened_url == ""
    assert gate.status == "waiting"


def test_control_room_visual_browser_requires_profile_capable_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FUSEKIT_VISUAL_BROWSER", raising=False)
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setattr("fusekit.runner.control_room.server.Path.glob", lambda *_args: [])
    monkeypatch.setattr(
        "fusekit.runner.control_room.server.shutil.which",
        lambda name: "/usr/bin/xdg-open" if name == "xdg-open" else None,
    )

    assert _visual_browser_binary() == ""


def test_control_room_visual_browser_rejects_configured_non_browser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_VISUAL_BROWSER", "/tmp/not-a-browser")
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setattr("fusekit.runner.control_room.server.Path.glob", lambda *_args: [])
    monkeypatch.setattr("fusekit.runner.control_room.server.shutil.which", lambda _name: None)

    assert _visual_browser_binary() == ""


def test_control_room_visual_browser_rejects_nonexecutable_configured_browser(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_chrome.chmod(0o600)
    monkeypatch.setenv("FUSEKIT_VISUAL_BROWSER", str(fake_chrome))
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setattr("fusekit.runner.control_room.server.Path.glob", lambda *_args: [])
    monkeypatch.setattr("fusekit.runner.control_room.server.shutil.which", lambda _name: None)

    assert _visual_browser_binary() == ""


def test_control_room_visual_browser_accepts_executable_configured_browser(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_chrome = tmp_path / "fake-chrome"
    fake_chrome.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_chrome.chmod(0o700)
    monkeypatch.setenv("FUSEKIT_VISUAL_BROWSER", str(fake_chrome))
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setattr("fusekit.runner.control_room.server.Path.glob", lambda *_args: [])
    monkeypatch.setattr("fusekit.runner.control_room.server.shutil.which", lambda _name: None)

    assert _visual_browser_binary() == str(fake_chrome)


def test_control_room_visual_browser_prefers_chrome_family_binary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("FUSEKIT_VISUAL_BROWSER", raising=False)
    monkeypatch.delenv("PLAYWRIGHT_BROWSERS_PATH", raising=False)
    monkeypatch.setattr("fusekit.runner.control_room.server.Path.glob", lambda *_args: [])

    def fake_which(name: str) -> str | None:
        if name == "google-chrome-stable":
            return "/usr/bin/google-chrome-stable"
        if name == "xdg-open":
            return "/usr/bin/xdg-open"
        return None

    monkeypatch.setattr("fusekit.runner.control_room.server.shutil.which", fake_which)

    assert _visual_browser_binary() == "/usr/bin/google-chrome-stable"


def test_control_room_visual_display_rejects_corrupt_display_values(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "visual.json").write_text(
        json.dumps({"display": ":99\x00--bad"}),
        encoding="utf-8",
    )
    monkeypatch.setenv("FUSEKIT_VISUAL_DISPLAY", "$(touch /tmp/bad)")

    assert _visual_display(job_path) == ":99"


def test_control_room_visual_display_accepts_expected_display(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "visual.json").write_text(json.dumps({"display": ":44.0"}), encoding="utf-8")
    monkeypatch.setenv("FUSEKIT_VISUAL_DISPLAY", ":99")

    assert _visual_display(job_path) == ":44.0"


def test_control_room_post_captures_vm_clipboard_into_vault(tmp_path, monkeypatch) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    vault_path = tmp_path / "fusekit.vault.json"
    audit_path = tmp_path / "audit.jsonl"
    passphrase_path = tmp_path / "passphrase"
    passphrase_path.write_text("passphrase\n", encoding="utf-8")
    Vault.empty().save(vault_path, "passphrase")
    job.add_artifact("vault", vault_path)
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.resend.api-key-domain-access",
        provider="resend",
        reason="Resend API key",
        classification="provider-authorization",
        target="RESEND_API_KEY",
    )
    monkeypatch.setenv("FUSEKIT_PASSPHRASE_FILE", str(passphrase_path))
    monkeypatch.setattr(
        "fusekit.runner.control_room.server._vm_clipboard_text",
        lambda job_state: "re_live_secret_from_vm_clipboard\n",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.resend.api-key-domain-access/capture-clipboard"
        )
        request = Request(
            url,
            data=json.dumps({"target": "RESEND_API_KEY"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload == {
        "captured_targets": ["RESEND_API_KEY"],
        "gate_id": "provider.resend.api-key-domain-access",
        "message": (
            "RESEND_API_KEY was captured into the encrypted vault. FuseKit will "
            "create or reuse the Resend sending domain by API, collect the returned "
            "DNS records, and keep Cloudflare DNS waiting until those records are ready."
        ),
        "ok": True,
        "record_id": "provider.resend.resend_api_key",
        "capture_wake_event_id": payload["capture_wake_event_id"],
        "resume_wake_event_id": payload["resume_wake_event_id"],
        "status": "resume_requested",
        "target": "RESEND_API_KEY",
    }
    assert payload["capture_wake_event_id"]
    assert payload["resume_wake_event_id"]
    assert payload["capture_wake_event_id"] != payload["resume_wake_event_id"]
    vault = Vault.open(vault_path, "passphrase")
    record = vault.require("provider.resend.resend_api_key")
    assert record.value == "re_live_secret_from_vm_clipboard"
    assert record.metadata["env"] == "RESEND_API_KEY"
    canonical = vault.require("provider.resend.token")
    assert canonical.value == "re_live_secret_from_vm_clipboard"
    assert canonical.metadata["alias_of"] == "provider.resend.resend_api_key"
    gate = GateService.load(tmp_path / "gates.json").records[
        "provider.resend.api-key-domain-access"
    ]
    assert gate.status == "resume_requested"
    assert gate.captured_targets == ("RESEND_API_KEY",)
    events = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert events[-1]["event"] == "control_room.clipboard_capture"
    assert events[-1]["data"]["gate_id"] == "provider.resend.api-key-domain-access"
    assert events[-1]["data"]["target"] == "RESEND_API_KEY"
    assert events[-1]["data"]["record_id"] == "provider.resend.resend_api_key"
    assert events[-1]["data"]["protected_action"] is True
    assert events[-1]["data"]["source"] == "vm-clipboard"
    assert events[-1]["data"]["storage"] == "encrypted-vault"
    assert events[-1]["data"]["capture_wake_event_id"] == payload["capture_wake_event_id"]
    assert events[-1]["data"]["resume_wake_event_id"] == payload["resume_wake_event_id"]
    assert "re_live_secret" not in json.dumps(payload)
    assert "re_live_secret" not in audit_path.read_text(encoding="utf-8")


def test_control_room_capture_canonicalizes_known_provider_token_targets(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    vault_path = tmp_path / "fusekit.vault.json"
    passphrase_path = tmp_path / "passphrase"
    passphrase_path.write_text("passphrase\n", encoding="utf-8")
    Vault.empty().save(vault_path, "passphrase")
    job.add_artifact("vault", vault_path)
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.dns.cloudflare-token",
        provider="dns",
        reason="Cloudflare DNS token",
        classification="provider-authorization",
        target="CLOUDFLARE_API_TOKEN",
    )
    monkeypatch.setenv("FUSEKIT_PASSPHRASE_FILE", str(passphrase_path))
    monkeypatch.setattr(
        "fusekit.runner.control_room.server._vm_clipboard_text",
        lambda job_state: "cf_live_secret_from_vm_clipboard\n",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.dns.cloudflare-token/capture-clipboard"
        )
        request = Request(
            url,
            data=json.dumps({"target": "CLOUDFLARE_API_TOKEN"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["record_id"] == "provider.cloudflare.cloudflare_api_token"
    vault = Vault.open(vault_path, "passphrase")
    record = vault.require("provider.cloudflare.cloudflare_api_token")
    assert record.value == "cf_live_secret_from_vm_clipboard"
    canonical = vault.require("provider.cloudflare.token")
    assert canonical.value == "cf_live_secret_from_vm_clipboard"
    assert canonical.metadata["alias_of"] == "provider.cloudflare.cloudflare_api_token"
    with pytest.raises(VaultError):
        vault.require("provider.dns.token")


def test_control_room_clipboard_capture_rejects_wrong_token_clipboard_value(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    vault_path = tmp_path / "fusekit.vault.json"
    audit_path = tmp_path / "audit.jsonl"
    passphrase_path = tmp_path / "passphrase"
    passphrase_path.write_text("passphrase\n", encoding="utf-8")
    Vault.empty().save(vault_path, "passphrase")
    job.add_artifact("vault", vault_path)
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.resend.api-key-domain-access",
        provider="resend",
        reason="Resend API key",
        classification="provider-authorization",
        target="RESEND_API_KEY",
    )
    monkeypatch.setenv("FUSEKIT_PASSPHRASE_FILE", str(passphrase_path))
    monkeypatch.setattr(
        "fusekit.runner.control_room.server._vm_clipboard_text",
        lambda job_state: "https://resend.com/api-keys\n",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.resend.api-key-domain-access/capture-clipboard"
        )
        request = Request(
            url,
            data=json.dumps({"target": "RESEND_API_KEY"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 400
    assert payload == {
        "error": (
            "RESEND_API_KEY looks like a URL. Copy only the provider key value inside "
            "the VM browser, then click Capture RESEND_API_KEY from VM clipboard again."
        ),
        "ok": False,
    }
    gate = GateService.load(tmp_path / "gates.json").records[
        "provider.resend.api-key-domain-access"
    ]
    assert gate.status == "waiting"
    assert gate.captured_targets == ()
    vault = Vault.open(vault_path, "passphrase")
    with pytest.raises(VaultError):
        vault.require("provider.resend.resend_api_key")
    assert not audit_path.exists()


@pytest.mark.parametrize(
    ("target", "value"),
    [
        ("RESEND_API_KEY", "re_1234567890abcdef"),
        ("GITHUB_TOKEN", "github_pat_1234567890abcdef"),
        ("GITHUB_TOKEN", "ghp_1234567890abcdef"),
        ("OPENAI_API_KEY", "sk-proj-1234567890abcdef"),
        ("CLOUDFLARE_API_TOKEN", "cf_1234567890abcdef"),
        ("VERCEL_TOKEN", "vercel_1234567890abcdef"),
    ],
)
def test_control_room_clipboard_capture_accepts_expected_token_shapes(
    target: str,
    value: str,
) -> None:
    _validate_clipboard_capture_value(target, value)


@pytest.mark.parametrize(
    ("target", "value"),
    [
        ("CLOUDFLARE_API_TOKEN", "abcdefghijklmnopqrstuvwxyz123456"),
        ("VERCEL_TOKEN", "abcdefghijklmnopqrstuvwxyz123456"),
    ],
)
def test_control_room_clipboard_capture_does_not_require_unguaranteed_prefixes(
    target: str,
    value: str,
) -> None:
    _validate_clipboard_capture_value(target, value)


@pytest.mark.parametrize(
    ("target", "value", "message"),
    [
        (
            "RESEND_API_KEY",
            "ghp_1234567890abcdef",
            "Copy the value that starts with re_ inside the VM browser, then click "
            "Capture RESEND_API_KEY from VM clipboard again.",
        ),
        (
            "GITHUB_TOKEN",
            "re_1234567890abcdef",
            "Copy the value that starts with",
        ),
        (
            "OPENAI_API_KEY",
            "re_1234567890abcdef",
            "Copy the value that starts with sk- inside the VM browser, then click "
            "Capture OPENAI_API_KEY from VM clipboard again.",
        ),
        (
            "CLOUDFLARE_API_TOKEN",
            "github_pat_1234567890abcdef",
            "CLOUDFLARE_API_TOKEN looks like a GITHUB token. Copy the value from the "
            "provider page named by this gate inside the VM browser, then click Capture "
            "CLOUDFLARE_API_TOKEN from VM clipboard again.",
        ),
        (
            "VERCEL_TOKEN",
            "sk-proj-1234567890abcdef",
            "VERCEL_TOKEN looks like a OPENAI token. Copy the value from the provider "
            "page named by this gate inside the VM browser, then click Capture VERCEL_TOKEN "
            "from VM clipboard again.",
        ),
    ],
)
def test_control_room_clipboard_capture_rejects_cross_provider_token_shapes(
    target: str,
    value: str,
    message: str,
) -> None:
    with pytest.raises(FuseKitError, match=re.escape(message)):
        _validate_clipboard_capture_value(target, value)


@pytest.mark.parametrize(
    ("target", "value", "message"),
    [
        (
            "RESEND_API_KEY",
            "re_token with spaces",
            "Capture RESEND_API_KEY from VM clipboard again",
        ),
        (
            "RESEND_API_KEY",
            "re_",
            "Copy only the full provider token inside the VM browser",
        ),
        (
            "RESEND_FROM_EMAIL",
            "not-an-email",
            "Capture RESEND_FROM_EMAIL from VM clipboard again",
        ),
        (
            "RESEND_AUDIENCE_ID",
            "ab",
            "Capture RESEND_AUDIENCE_ID from VM clipboard again",
        ),
    ],
)
def test_control_room_clipboard_capture_validation_names_launcher_recovery_action(
    target: str,
    value: str,
    message: str,
) -> None:
    with pytest.raises(FuseKitError, match=re.escape(message)):
        _validate_clipboard_capture_value(target, value)


@pytest.mark.parametrize(
    "value",
    [
        '{"api_key":"custom_secret_value"}',
        '["custom_secret_value"]',
        "<html>custom_secret_value</html>",
    ],
)
def test_control_room_clipboard_capture_rejects_structured_token_blobs(value: str) -> None:
    with pytest.raises(
        FuseKitError,
        match=re.escape(
            "CUSTOM_API_KEY looks like copied page or response text, not a token. "
            "Copy only the copy-once token value inside the VM browser, then click "
            "Capture CUSTOM_API_KEY from VM clipboard again."
        ),
    ):
        _validate_clipboard_capture_value("CUSTOM_API_KEY", value)


@pytest.mark.parametrize(
    "value",
    [
        "undefined",
        "********",
        "xxxxxxxx",
        "\u2022\u2022\u2022\u2022\u2022\u2022",
        "redacted",
    ],
)
def test_control_room_clipboard_capture_rejects_placeholder_tokens(value: str) -> None:
    with pytest.raises(
        FuseKitError,
        match=re.escape(
            "CUSTOM_API_KEY looks like a placeholder or masked value, not a "
            "copy-once token. Copy only the real token value inside the VM browser, "
            "then click Capture CUSTOM_API_KEY from VM clipboard again."
        ),
    ):
        _validate_clipboard_capture_value("CUSTOM_API_KEY", value)


@pytest.mark.parametrize(
    "value",
    ["HTTPS://provider.example/token", "token-one,token-two", "token-one;token-two"],
)
def test_control_room_clipboard_capture_rejects_urls_and_multi_token_blobs(value: str) -> None:
    with pytest.raises(FuseKitError) as exc:
        _validate_clipboard_capture_value("CUSTOM_API_KEY", value)

    message = str(exc.value)
    assert "Capture CUSTOM_API_KEY from VM clipboard again" in message
    assert "looks like a URL" in message or "looks like multiple copied values" in message


@pytest.mark.parametrize(
    "value",
    [
        "RESEND_API_KEY=re_1234567890abcdef",
        "api_key=re_1234567890abcdef",
        "Authorization:Bearer re_1234567890abcdef",
    ],
)
def test_control_room_clipboard_capture_rejects_assignment_or_header_blobs(
    value: str,
) -> None:
    with pytest.raises(FuseKitError) as exc:
        _validate_clipboard_capture_value("RESEND_API_KEY", value)

    assert str(exc.value) == (
        "RESEND_API_KEY looks like a copied assignment or header, not one raw token value. "
        "Copy only the single provider token inside the VM browser, then click "
        "Capture RESEND_API_KEY from VM clipboard again."
    )


def test_control_room_passphrase_uses_job_artifact(tmp_path, monkeypatch) -> None:
    job = JobState.create("fk-test", tmp_path, "source-fetch")
    job_path = tmp_path / "source-fetch-job.json"
    passphrase_path = tmp_path / "passphrase.txt"
    passphrase_path.write_text("passphrase\n", encoding="utf-8")
    job.add_artifact("passphrase_file", passphrase_path)
    job.save(job_path)
    monkeypatch.delenv("FUSEKIT_PASSPHRASE_FILE", raising=False)

    assert _control_room_vault_passphrase(job_path) == "passphrase"


def test_control_room_rejects_stale_capture_after_gate_resumes(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    vault_path = tmp_path / "fusekit.vault.json"
    passphrase_path = tmp_path / "passphrase"
    passphrase_path.write_text("passphrase\n", encoding="utf-8")
    Vault.empty().save(vault_path, "passphrase")
    job.add_artifact("vault", vault_path)
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.resend.api-key-domain-access",
        provider="resend",
        reason="Resend API key",
        classification="provider-authorization",
        target="RESEND_API_KEY",
    )
    clipboard = {"value": "re_first_secret_from_vm_clipboard\n"}
    monkeypatch.setenv("FUSEKIT_PASSPHRASE_FILE", str(passphrase_path))
    monkeypatch.setattr(
        "fusekit.runner.control_room.server._vm_clipboard_text",
        lambda job_state: clipboard["value"],
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.resend.api-key-domain-access/capture-clipboard"
        )
        request = Request(
            url,
            data=json.dumps({"target": "RESEND_API_KEY"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        clipboard["value"] = "re_second_secret_should_not_overwrite\n"
        stale_request = Request(
            url,
            data=json.dumps({"target": "RESEND_API_KEY"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(stale_request, timeout=5)
        stale_payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["status"] == "resume_requested"
    assert payload["capture_wake_event_id"]
    assert payload["resume_wake_event_id"]
    assert payload["capture_wake_event_id"] != payload["resume_wake_event_id"]
    assert exc.value.code == 400
    assert stale_payload == {
        "error": (
            "Gate already captured all required values and is waiting for verification. "
            "Wait for FuseKit to continue or follow the next guided gate."
        ),
        "ok": False,
    }
    assert (
        GateService.load(tmp_path / "gates.json")
        .records["provider.resend.api-key-domain-access"]
        .status
        == "resume_requested"
    )
    vault = Vault.open(vault_path, "passphrase")
    assert vault.require("provider.resend.resend_api_key").value == (
        "re_first_secret_from_vm_clipboard"
    )
    assert vault.require("provider.resend.token").value == "re_first_secret_from_vm_clipboard"


def test_control_room_duplicate_final_capture_repairs_missing_resume(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    vault_path = tmp_path / "fusekit.vault.json"
    audit_path = tmp_path / "audit.jsonl"
    passphrase_path = tmp_path / "passphrase"
    passphrase_path.write_text("passphrase\n", encoding="utf-8")
    vault = Vault.empty()
    vault.put(
        "provider.resend.resend_api_key",
        "provider_token",
        "resend",
        "RESEND_API_KEY",
        "re_recovered_secret",
        {"env": "RESEND_API_KEY", "source": "vm-clipboard"},
    )
    vault.save(vault_path, "passphrase")
    job.add_artifact("vault", vault_path)
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    service = GateService.load(tmp_path / "gates.json")
    service.wait(
        "provider.resend.api-key-domain-access",
        provider="resend",
        reason="Resend API key",
        classification="provider-authorization",
        target="RESEND_API_KEY",
    )
    capture_wake_event_id = GateService.load(tmp_path / "gates.json").mark_captured(
        "provider.resend.api-key-domain-access",
        "RESEND_API_KEY",
    )
    gate_events_before = (tmp_path / "gate_events.jsonl").read_text(encoding="utf-8")
    monkeypatch.setenv("FUSEKIT_PASSPHRASE_FILE", str(passphrase_path))
    monkeypatch.setattr(
        "fusekit.runner.control_room.server._vm_clipboard_text",
        lambda job_state: pytest.fail("resume repair reread the VM clipboard"),
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.resend.api-key-domain-access/capture-clipboard"
        )
        request = Request(
            url,
            data=json.dumps({"target": "RESEND_API_KEY"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload == {
        "captured_targets": ["RESEND_API_KEY"],
        "gate_id": "provider.resend.api-key-domain-access",
        "message": (
            "RESEND_API_KEY was captured into the encrypted vault. FuseKit will "
            "create or reuse the Resend sending domain by API, collect the returned "
            "DNS records, and keep Cloudflare DNS waiting until those records are ready."
        ),
        "ok": True,
        "record_id": "provider.resend.resend_api_key",
        "capture_wake_event_id": capture_wake_event_id,
        "resume_wake_event_id": payload["resume_wake_event_id"],
        "status": "resume_requested",
        "target": "RESEND_API_KEY",
    }
    assert payload["resume_wake_event_id"]
    gate = GateService.load(tmp_path / "gates.json").records[
        "provider.resend.api-key-domain-access"
    ]
    assert gate.status == "resume_requested"
    assert gate.last_wake_event_id == payload["resume_wake_event_id"]
    gate_events_after = (tmp_path / "gate_events.jsonl").read_text(encoding="utf-8")
    assert gate_events_after.startswith(gate_events_before)
    event_names = [
        json.loads(line)["event"]
        for line in gate_events_after.splitlines()
        if line.strip()
    ]
    assert event_names == ["clipboard_captured", "resume_requested"]
    audit_events = [
        json.loads(line)
        for line in audit_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert audit_events[-1]["event"] == "control_room.clipboard_capture"
    assert audit_events[-1]["data"]["capture_wake_event_id"] == capture_wake_event_id
    assert audit_events[-1]["data"]["resume_wake_event_id"] == payload["resume_wake_event_id"]
    assert Vault.open(vault_path, "passphrase").require(
        "provider.resend.resend_api_key"
    ).value == "re_recovered_secret"


def test_control_room_capture_is_idempotent_for_already_captured_target(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    vault_path = tmp_path / "fusekit.vault.json"
    audit_path = tmp_path / "audit.jsonl"
    passphrase_path = tmp_path / "passphrase"
    passphrase_path.write_text("passphrase\n", encoding="utf-8")
    Vault.empty().save(vault_path, "passphrase")
    job.add_artifact("vault", vault_path)
    job.add_artifact("audit_log", audit_path)
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.custom.tokens",
        provider="custom",
        reason="Custom provider tokens",
        classification="provider-authorization",
        target="CUSTOM_API_KEY,CUSTOM_WEBHOOK_SECRET",
    )
    monkeypatch.setenv("FUSEKIT_PASSPHRASE_FILE", str(passphrase_path))
    monkeypatch.setattr(
        "fusekit.runner.control_room.server._vm_clipboard_text",
        lambda job_state: "custom_first_secret\n",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.custom.tokens/capture-clipboard"
        request = Request(
            url,
            data=json.dumps({"target": "CUSTOM_API_KEY"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with urlopen(request, timeout=5) as response:
            first_payload = json.loads(response.read().decode("utf-8"))
        original_gate_events = (tmp_path / "gate_events.jsonl").read_text(encoding="utf-8")
        original_audit = audit_path.read_text(encoding="utf-8")
        monkeypatch.setattr(
            "fusekit.runner.control_room.server._vm_clipboard_text",
            lambda job_state: pytest.fail("duplicate capture reread the VM clipboard"),
        )
        duplicate_request = Request(
            url,
            data=json.dumps({"target": "CUSTOM_API_KEY"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with urlopen(duplicate_request, timeout=5) as response:
            duplicate_payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert first_payload["status"] == "captured"
    assert first_payload["captured_targets"] == ["CUSTOM_API_KEY"]
    assert duplicate_payload == {
        "captured_targets": ["CUSTOM_API_KEY"],
        "gate_id": "provider.custom.tokens",
        "message": (
            "CUSTOM_API_KEY is already captured in the encrypted vault. "
            "Click Capture CUSTOM_WEBHOOK_SECRET from VM clipboard for the remaining value."
        ),
        "ok": True,
        "record_id": "provider.custom.custom_api_key",
        "status": "captured",
        "target": "CUSTOM_API_KEY",
    }
    gate = GateService.load(tmp_path / "gates.json").records["provider.custom.tokens"]
    assert gate.status == "waiting"
    assert gate.captured_targets == ("CUSTOM_API_KEY",)
    assert (tmp_path / "gate_events.jsonl").read_text(encoding="utf-8") == original_gate_events
    assert audit_path.read_text(encoding="utf-8") == original_audit
    vault = Vault.open(vault_path, "passphrase")
    assert vault.require("provider.custom.custom_api_key").value == "custom_first_secret"
    assert vault.require("provider.custom.token").value == "custom_first_secret"


def test_control_room_clipboard_capture_waits_for_multi_value_gate(
    tmp_path,
    monkeypatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    vault_path = tmp_path / "fusekit.vault.json"
    passphrase_path = tmp_path / "passphrase"
    passphrase_path.write_text("passphrase\n", encoding="utf-8")
    Vault.empty().save(vault_path, "passphrase")
    job.add_artifact("vault", vault_path)
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.custom.runtime-values",
        provider="custom",
        reason="Custom runtime values",
        classification="provider-runtime-values",
        target="CUSTOM_API_KEY,CUSTOM_TOKEN",
    )
    monkeypatch.setenv("FUSEKIT_PASSPHRASE_FILE", str(passphrase_path))
    clipboard = {"value": "custom_key_12345\n"}
    monkeypatch.setattr(
        "fusekit.runner.control_room.server._vm_clipboard_text",
        lambda job_state: clipboard["value"],
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.custom.runtime-values/capture-clipboard"
        )
        request = Request(
            url,
            data=json.dumps({"target": "CUSTOM_API_KEY"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        html = render_control_room(JobState.load(job_path), gate_path=tmp_path / "gates.json")
        clipboard["value"] = "custom_token_12345\n"
        request = Request(
            url,
            data=json.dumps({"target": "CUSTOM_TOKEN"}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with urlopen(request, timeout=5) as response:
            second_payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert payload["status"] == "captured"
    assert payload["captured_targets"] == ["CUSTOM_API_KEY"]
    assert payload["message"] == (
        "CUSTOM_API_KEY captured into the encrypted vault. "
        "Capture the remaining required values to continue."
    )
    assert "1/2 captured" in html
    assert "Captured CUSTOM_API_KEY" in html
    assert "these exact Capture buttons" in html
    assert "each target-specific button below" not in html
    assert "Capture CUSTOM_API_KEY from VM clipboard" in html
    assert "Capture CUSTOM_TOKEN from VM clipboard" in html
    assert 'data-gate-capture-target="CUSTOM_API_KEY" disabled' in html
    gate = GateService.load(tmp_path / "gates.json").records["provider.custom.runtime-values"]
    assert gate.status == "resume_requested"
    assert gate.captured_targets == ("CUSTOM_API_KEY", "CUSTOM_TOKEN")
    assert second_payload["status"] == "resume_requested"
    assert second_payload["captured_targets"] == [
        "CUSTOM_API_KEY",
        "CUSTOM_TOKEN",
    ]
    assert "All required values were captured" in second_payload["message"]


@pytest.mark.parametrize(
    ("classification", "target", "record_id"),
    [
        ("provider-runtime-values", "RESEND_FROM_EMAIL", "app.resend.resend_from_email"),
        ("provider-authorization", "RESEND_FROM_EMAIL", "app.resend.resend_from_email"),
        ("provider-domain", "RESEND_AUDIENCE_ID", "app.resend.resend_audience_id"),
        ("", "RESEND_AUDIENCE_ID", "app.resend.resend_audience_id"),
    ],
)
def test_control_room_clipboard_capture_rejects_stale_resend_generated_value_gate(
    tmp_path,
    monkeypatch,
    classification: str,
    target: str,
    record_id: str,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    vault_path = tmp_path / "fusekit.vault.json"
    passphrase_path = tmp_path / "passphrase"
    passphrase_path.write_text("passphrase\n", encoding="utf-8")
    Vault.empty().save(vault_path, "passphrase")
    job.add_artifact("vault", vault_path)
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.resend.runtime-values",
        provider="resend",
        reason="Stale Resend generated value capture",
        classification=classification,
        target=target,
    )
    monkeypatch.setenv("FUSEKIT_PASSPHRASE_FILE", str(passphrase_path))
    monkeypatch.setattr(
        "fusekit.runner.control_room.server._vm_clipboard_text",
        lambda job_state: "rsvp@example.com\n",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.resend.runtime-values/capture-clipboard"
        )
        request = Request(
            url,
            data=json.dumps({"target": target}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 400
    assert payload["ok"] is False
    assert f"{target} is generated by Resend API setup" in payload["error"]
    assert "Capture only RESEND_API_KEY from VM clipboard" in payload["error"]
    assert "from the VM clipboard" not in payload["error"]
    assert "Do not create Resend domains or audiences by hand" in payload["error"]
    gate = GateService.load(tmp_path / "gates.json").records["provider.resend.runtime-values"]
    assert gate.status == "waiting"
    vault = Vault.open(vault_path, "passphrase")
    with pytest.raises(FuseKitError):
        vault.require(record_id)


def test_control_room_clipboard_capture_requires_json_content_type(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.resend.api-key-domain-access",
        provider="resend",
        reason="Resend API key",
        classification="provider-authorization",
        target="RESEND_API_KEY",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.resend.api-key-domain-access/capture-clipboard"
        )
        request = Request(
            url,
            data=b"target=RESEND_API_KEY",
            method="POST",
            headers=_control_room_post_headers(
                tmp_path,
                **{"content-type": "application/x-www-form-urlencoded"},
            ),
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 400
    assert payload == {
        "error": "Control-room request body must use application/json.",
        "ok": False,
    }
    gate = GateService.load(tmp_path / "gates.json").records[
        "provider.resend.api-key-domain-access"
    ]
    assert gate.status == "waiting"
    assert gate.captured_targets == ()


def test_control_room_clipboard_capture_rejects_large_json_body(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.resend.api-key-domain-access",
        provider="resend",
        reason="Resend API key",
        classification="provider-authorization",
        target="RESEND_API_KEY",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            "/api/gates/provider.resend.api-key-domain-access/capture-clipboard"
        )
        request = Request(
            url,
            data=json.dumps({"target": "RESEND_API_KEY", "padding": "x" * 5000}).encode("utf-8"),
            method="POST",
            headers=_control_room_post_headers(tmp_path, **{"content-type": "application/json"}),
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 400
    assert payload == {
        "error": "Control-room request body is too large.",
        "ok": False,
    }
    gate = GateService.load(tmp_path / "gates.json").records[
        "provider.resend.api-key-domain-access"
    ]
    assert gate.status == "waiting"
    assert gate.captured_targets == ()


def test_control_room_post_rejects_cross_site_gate_pass(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        with pytest.raises(HTTPError):
            urlopen(Request(url, method="POST"), timeout=5)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "waiting"
    )


def test_security_surface_map_documents_control_room_state_routes() -> None:
    text = Path("docs/security-surface-map.md").read_text(encoding="utf-8")
    route_rows: dict[str, list[str]] = {}
    for line in text.splitlines():
        if not line.startswith("| "):
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) != 4 or cells[0] in {"Route", "---"}:
            continue
        route_label = cells[0].strip("`")
        route_rows[route_label] = cells

    mapped_routes = {str(item["route"]) for item in CONTROL_ROOM_ROUTE_SURFACE}
    assert mapped_routes == {
        "/",
        "/index.html",
        "/api/job",
        "/api/gates/<gate_id>/pass",
        "/api/gates/<gate_id>/open",
        "/api/gates/<gate_id>/capture-clipboard",
        "unknown",
    }
    state_changing_routes = {
        str(item["route"]) for item in CONTROL_ROOM_ROUTE_SURFACE if item["state_change"] is True
    }
    assert state_changing_routes == {
        "/api/gates/<gate_id>/pass",
        "/api/gates/<gate_id>/open",
        "/api/gates/<gate_id>/capture-clipboard",
    }
    for surface in CONTROL_ROOM_ROUTE_SURFACE:
        route = str(surface["route"])
        route_label = "Unknown routes" if route == "unknown" else route
        assert route_label in route_rows
        methods_cell = route_rows[route_label][1]
        for method in cast(tuple[str, ...], surface["methods"]):
            assert f"`{method}`" in methods_cell
        protection = str(surface["protection"])
        assert protection in text
        if surface["state_change"] is True:
            assert "State-changing:" in route_rows[route_label][2]
            assert protection == "control-room-header-origin-fetch-site-action-token"
        else:
            assert "State-changing:" not in route_rows[route_label][2]
    assert "State-changing POSTs reject `?token=` authentication in the URL" in text
    assert "cleaned control-room cookie or bearer token plus the per-page" in text
    assert "`CONTROL_ROOM_ROUTE_SURFACE`" in text
    assert "control-room-header-origin-fetch-site-action-token" in text
    assert "security-headers-no-cors-posts-auth-before-404" in text
    serialized_surface = json.dumps(CONTROL_ROOM_ROUTE_SURFACE).lower()
    assert "shell" not in serialized_surface
    assert "admin" not in serialized_surface
    assert "account" not in serialized_surface
    assert "x-fusekit-control-room: resume" in text
    assert "x-fusekit-action-token" in text
    assert "every state-changing POST must echo the page's per-control-room" in text
    assert "resume_requested" in text
    assert "protected control-room approval signal" in text
    assert "Setup-plan and DNS approvals use the same protected `/pass` route" in text
    assert "accepts arbitrary commands" in text
    assert "require_safe_url" in text
    assert "target must match the gate's env-style allowlist" in text
    assert "never raw secret text" in text
    assert "state is sanitized before the browser payload sees it" in text
    assert "clipboard-enabled arbitrary iframe" in text
    assert "expected noVNC query keys and generated values are preserved" in text
    assert "action token is stored owner-only" in text
    assert "permissions repaired before reuse" in text
    assert "Malformed token cookie headers are treated as absent credentials" in text
    assert "normal invalid-token response" in text
    assert "Public guided runs use exact env-target buttons" in text
    assert "Capture RESEND_API_KEY from VM clipboard" in text
    assert (
        "Public guided runs use `Capture from VM clipboard` buttons for approved env targets"
        not in text
    )
    assert "must not ship placeholder `Capture <TARGET> from VM clipboard`" in text
    assert "CLI-only fallback can use a non-echoing prompt or env handoff" in text
    assert "local/host browser-tab side channels" in text
    assert "redirect back to the same route without the token query parameter" in text
    assert "does not stay in the address bar" in text
    assert "per-response nonces instead of broad `unsafe-inline`" in text
    assert "inline style/script attributes disabled" in text
    assert "Permissions-Policy" in text
    assert "camera, microphone, geolocation, payment" in text
    assert "USB/HID/serial/Bluetooth" in text
    assert "emits no `Access-Control-Allow-Origin`" in text
    assert "`Access-Control-Allow-Methods`" in text
    assert "`Access-Control-Allow-Headers`" in text
    assert "Unknown POST first passes the same control-room header" in text
    assert "attacker-origin or tokenless unknown POSTs fail before route handling" in text


def test_control_room_preflight_and_rejected_posts_emit_no_cors_allow_headers(
    tmp_path,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        options = Request(
            url,
            method="OPTIONS",
            headers={
                "Origin": "https://attacker.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": ("x-fusekit-control-room,x-fusekit-action-token"),
            },
        )
        with pytest.raises(HTTPError) as options_exc:
            urlopen(options, timeout=5)
        post = Request(
            url,
            method="POST",
            headers={
                "Origin": "https://attacker.example",
                "Sec-Fetch-Site": "cross-site",
                "x-fusekit-control-room": "resume",
                "x-fusekit-action-token": (tmp_path / "control-room-action-token")
                .read_text(encoding="utf-8")
                .strip(),
            },
        )
        with pytest.raises(HTTPError) as post_exc:
            urlopen(post, timeout=5)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert options_exc.value.code == 405
    assert post_exc.value.code == 403
    for response in (options_exc.value, post_exc.value):
        headers = {key.lower(): value for key, value in response.headers.items()}
        assert "access-control-allow-origin" not in headers
        assert "access-control-allow-methods" not in headers
        assert "access-control-allow-headers" not in headers
    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "waiting"
    )


def test_threat_model_documents_control_room_state_route_defenses() -> None:
    text = Path("docs/threat-model.md").read_text(encoding="utf-8")

    for route in (
        "/api/gates/<gate_id>/pass",
        "/api/gates/<gate_id>/open",
        "/api/gates/<gate_id>/capture-clipboard",
    ):
        assert route in text
    assert "x-fusekit-control-room: resume" in text
    assert "x-fusekit-action-token" in text
    assert "Origin" in text
    assert "Sec-Fetch-Site" in text
    assert "no permissive CORS preflight response" in text
    assert "remote access disabled unless an explicit generated remote token is configured" in text
    assert "at least 32 URL-safe characters" in text
    assert "Permissions-Policy" in text
    assert "camera," in text
    assert "USB/HID/serial/Bluetooth" in text
    assert "must never expose a route" in text
    assert "arbitrary shell" in text
    assert "creates OS or application admin accounts" in text
    assert "installs persistence" in text
    assert "fixed argv execution rather than shell-evaluated strings" in text
    assert "reject copied page URLs or multi-token blobs" in text
    assert "audit fingerprints instead of raw secret text" in text


def test_control_room_post_rejects_untrusted_origin(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        request = Request(
            url,
            method="POST",
            headers=_control_room_post_headers(
                tmp_path,
                **{"Origin": "https://evil.example"},
            ),
        )
        with pytest.raises(HTTPError):
            urlopen(request, timeout=5)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "waiting"
    )


def test_control_room_post_rejects_cross_site_fetch_metadata(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        request = Request(
            url,
            method="POST",
            headers=_control_room_post_headers(
                tmp_path,
                **{"Sec-Fetch-Site": "cross-site"},
            ),
        )
        with pytest.raises(HTTPError):
            urlopen(request, timeout=5)
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "waiting"
    )


def test_control_room_rejects_cors_preflight_without_cors_headers(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request(
            "OPTIONS",
            "/api/gates/provider.github.mfa.123/pass",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "x-fusekit-control-room",
            },
        )
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        response.read()
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)

    assert response.status == 405
    assert "access-control-allow-origin" not in headers
    assert headers["x-frame-options"] == "DENY"
    assert "camera=()" in headers["permissions-policy"]
    assert "microphone=()" in headers["permissions-policy"]
    assert "geolocation=()" in headers["permissions-policy"]


def test_control_room_unknown_routes_keep_security_headers(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", "/missing")
        get_response = connection.getresponse()
        get_headers = {key.lower(): value for key, value in get_response.getheaders()}
        get_response.read()

        connection.request(
            "POST",
            "/api/unknown",
            body=b"{}",
            headers={
                **_control_room_post_headers(tmp_path),
                "content-type": "application/json",
            },
        )
        post_response = connection.getresponse()
        post_headers = {key.lower(): value for key, value in post_response.getheaders()}
        post_response.read()
    finally:
        connection.close()
        server.shutdown()
        thread.join(timeout=5)

    assert get_response.status == 404
    assert post_response.status == 404
    for headers in (get_headers, post_headers):
        assert headers["content-length"] == "0"
        assert headers["cache-control"] == "no-store"
        assert headers["x-frame-options"] == "DENY"
        assert headers["x-content-type-options"] == "nosniff"
        assert "camera=()" in headers["permissions-policy"]
        assert "microphone=()" in headers["permissions-policy"]
        assert "payment=()" in headers["permissions-policy"]
        assert "content-security-policy" in headers
        assert "access-control-allow-origin" not in headers


def test_control_room_unknown_post_rejects_cross_site_before_404(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/unknown"
        request = Request(
            url,
            data=b"{}",
            method="POST",
            headers={
                **_control_room_post_headers(
                    tmp_path,
                    **{
                        "Origin": "https://evil.example",
                        "Sec-Fetch-Site": "cross-site",
                    },
                ),
                "content-type": "application/json",
            },
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert exc.value.code == 403
    assert payload == {"error": "untrusted origin", "ok": False}


def test_control_room_uses_privacy_mascot_for_secret_gates(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.mark(
        "provider.resend.authorization",
        "waiting",
        "Resend API key token is ready; paste it into FuseKit's hidden prompt.",
    )

    html = render_control_room(job)
    visible_html = html[: html.index("<script")]

    assert "state-privacy" in visible_html
    assert "privacy-mitten" in visible_html
    assert "covering his eyes while secrets stay private" in visible_html
    assert "isPrivacyStep" in html
    assert (
        "copy it inside the VM browser, then click the exact env-named "
        "Capture button shown on the active launcher gate" in visible_html
    )
    assert "visible env-named Capture from VM clipboard button" not in visible_html
    assert "target-specific Capture" not in visible_html
    assert "click the matching Capture from VM clipboard button" not in visible_html
    assert "click Capture in FuseKit" not in visible_html
    assert "paste it into FuseKit&#x27;s hidden prompt" not in visible_html


def test_control_room_payload_reports_corrupt_gate_state(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "gates.json").write_text("{not json", encoding="utf-8")

    payload = control_room_payload(job_path)

    assert payload["gates"] == []
    assert "Gate state could not be read" in str(payload["gate_state_error"])


def test_control_room_payload_and_html_include_visual_session(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "authorization",
        provider="resend",
        reason="provider authorization required",
        resume_url="https://resend.com/api-keys",
        classification="provider-authorization",
        target="RESEND_API_KEY",
    )
    (tmp_path / "visual.json").write_text(
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
        encoding="utf-8",
    )

    payload = control_room_payload(job_path)
    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert payload["visual"]["runner"] == "novnc"
    assert payload["visual"]["provider_browser_profile"] == (
        "/var/lib/fusekit-runner/visual/chrome-provider-profile"
    )
    assert "Live VM browser" in html
    assert "viewer-password" in html
    assert 'class="visual-frame"' in html
    assert "Current gate" in html
    assert "resend needs your approval" in html
    assert "Copy inside VM, then capture" in html
    assert "Copy the provider value in the VM browser" in html
    assert (
        'sandbox="allow-scripts allow-same-origin allow-forms allow-pointer-lock allow-modals"'
        in html
    )
    assert 'aria-label="noVNC password"' in html
    assert 'data-copy-label="password"' in html
    assert "Open live VM browser" in html
    assert "Copy live VM browser link" in html
    assert "Open live control room" in html
    assert 'data-copy-label="live VM browser link"' in html
    assert "http://93.184.216.34:6080/vnc.html?autoconnect=1" in html
    assert "password=viewer-password" in html
    assert (
        'href="http://93.184.216.34:6080/vnc.html?autoconnect=1&amp;password=viewer-password"'
        in html
    )
    assert (
        'data-copy="http://93.184.216.34:6080/vnc.html?autoconnect=1&amp;password=viewer-password"'
        in html
    )
    assert 'withQueryParam(novncUrl, "password", password)' in html
    assert '<a href="${escapeAttr(iframeUrl)}" target="_blank" rel="noreferrer">' in html
    assert 'data-copy="${escapeAttr(iframeUrl)}"' in html
    assert 'data-copy-label="live VM browser link"' in html
    assert "data-visual-status" in html
    assert "sameVisualSession" in html
    assert "root.dataset.novncUrl" in html
    assert "press Command+C or Ctrl+C to copy it" in html
    assert "FuseKit left the ${copyLabel} visible" in html
    assert "novncPassword" not in html


def test_control_room_rejects_unsafe_visual_session_iframe_url(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "visual.json").write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "novnc_url": "https://attacker.example/phish.html?autoconnect=1",
                "control_room_url": "https://attacker.example/?token=stolen",
                "novnc_password": "viewer-password",
            }
        ),
        encoding="utf-8",
    )

    payload = control_room_payload(job_path)
    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert payload["visual"] == {
        "status": "unavailable",
        "error": "Visual session noVNC URL was not safe to embed.",
    }
    assert "attacker.example" not in html
    assert "viewer-password" not in html
    assert "Visual session noVNC URL was not safe to embed." in html


def test_control_room_rejects_visual_session_hostname_and_private_ip(tmp_path) -> None:
    for host in ("attacker.example", "10.0.0.5", "127.0.0.1"):
        job_root = tmp_path / host.replace(".", "-")
        job = JobState.create("fk-test", job_root, "oci-free")
        job_path = job_root / "job.json"
        job.save(job_path)
        (job_root / "visual.json").write_text(
            json.dumps(
                {
                    "runner": "novnc",
                    "status": "ready",
                    "novnc_url": f"http://{host}:6080/vnc.html?autoconnect=1",
                    "control_room_url": (
                        f"http://{host}:8765/"
                        "?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
                    ),
                    "novnc_password": "viewer-password",
                }
            ),
            encoding="utf-8",
        )

        payload = control_room_payload(job_path)
        html = render_control_room(job, gate_path=job_root / "gates.json")

        assert payload["visual"] == {
            "status": "unavailable",
            "error": "Visual session noVNC URL was not safe to embed.",
        }
        assert host not in html
        assert "viewer-password" not in html


def test_control_room_rejects_visual_session_wrong_ports(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "visual.json").write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "novnc_url": "http://93.184.216.34:4444/vnc.html?autoconnect=1",
                "control_room_url": (
                    "http://93.184.216.34:8766/"
                    "?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
                ),
                "novnc_password": "viewer-password",
            }
        ),
        encoding="utf-8",
    )

    payload = control_room_payload(job_path)
    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert payload["visual"] == {
        "status": "unavailable",
        "error": "Visual session noVNC URL was not safe to embed.",
    }
    assert "93.184.216.34:4444" not in html
    assert "93.184.216.34:8766" not in html
    assert "viewer-password" not in html


def test_control_room_sanitizes_visual_session_urls_and_password(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "visual.json").write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "novnc_url": (
                    "http://93.184.216.34:6080/vnc.html?autoconnect=1"
                    "&resize=scale&password=leaked#frag"
                ),
                "control_room_url": (
                    "http://10.0.0.5:8765/?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
                ),
                "novnc_password": "bad\npassword",
                "provider_browser_profile": "/tmp/disconnected-profile",
            }
        ),
        encoding="utf-8",
    )

    payload = control_room_payload(job_path)
    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert payload["visual"]["novnc_url"] == (
        "http://93.184.216.34:6080/vnc.html?autoconnect=1&resize=scale"
    )
    assert "control_room_url" not in payload["visual"]
    assert "novnc_password" not in payload["visual"]
    assert "provider_browser_profile" not in payload["visual"]
    assert "password=leaked" not in html
    assert "bad\npassword" not in html
    assert "disconnected-profile" not in html
    assert "10.0.0.5" not in html


def test_control_room_rejects_unexpected_visual_session_query_values(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "visual.json").write_text(
        json.dumps(
            {
                "runner": "novnc",
                "status": "ready",
                "novnc_url": (
                    "http://93.184.216.34:6080/vnc.html?autoconnect=javascript&resize=evil"
                ),
                "control_room_url": (
                    "http://93.184.216.34:8765/"
                    "?token=viewer_token_abcdefghijklmnopqrstuvwxyz0123456789"
                ),
                "novnc_password": "viewer-password",
            }
        ),
        encoding="utf-8",
    )

    payload = control_room_payload(job_path)
    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert payload["visual"] == {
        "status": "unavailable",
        "error": "Visual session noVNC URL was not safe to embed.",
    }
    assert "javascript" not in html
    assert "viewer-password" not in html


def test_control_room_payload_and_html_include_provider_strategy_routes(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    (tmp_path / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "github",
                        "strategies": [
                            {
                                "recipe": "github-deploy-key",
                                "status": "needs_human_gate",
                                "strategy": "browser_guided",
                                "target": "GITHUB_TOKEN",
                                "next_action": (
                                    "Click Open provider gate in VM, create the setup token, "
                                    "then click Capture from VM clipboard."
                                ),
                                "resume_hint": (
                                    "FuseKit will retry this provider route after capture."
                                ),
                                "follow_steps": [
                                    (
                                        "Click Open provider gate in VM so GitHub opens "
                                        "in the VM browser."
                                    ),
                                    "Create the fine-grained FuseKit setup token.",
                                    (
                                        "After copying the token, click the matching "
                                        "Capture from VM clipboard button."
                                    ),
                                ],
                                "decision": {
                                    "selected": {
                                        "kind": "browser_guided",
                                        "deterministic": False,
                                        "implemented": False,
                                        "reason": "Provider token is missing.",
                                    }
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")
    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert payload["provider_strategies"]["providers"][0]["provider"] == "github"
    assert "Provider routes" in html
    assert "How FuseKit is connecting services" in html
    assert "github-deploy-key" in html
    assert "browser guided" in html
    assert "VM follow-me" in html
    assert "provider-owned gates" in html
    assert "providerStrategyRouteSummary" in html
    assert "Provider token is missing." in html
    strategy_start = html.index("github-deploy-key")
    strategy_html = html[strategy_start : html.index("</article>", strategy_start)]
    assert "Click Open provider gate in VM, create the setup token" in strategy_html
    assert "then click Capture GITHUB_TOKEN from VM clipboard" in strategy_html
    assert "Create the fine-grained FuseKit setup token." in strategy_html
    assert "After copying the token, click Capture GITHUB_TOKEN from VM clipboard." in strategy_html
    assert "the matching Capture from VM clipboard button" not in strategy_html
    assert "then click Capture from VM clipboard." not in strategy_html
    assert "Route plan" in html
    assert "First, if a provider token gate appears, click Open provider gate in VM" in html
    assert "copy the value inside the shared VM browser" in html
    assert "Capture GITHUB_TOKEN from VM clipboard" in html


def test_control_room_renders_provider_playbook_checklist(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.save(tmp_path / "job.json")
    (tmp_path / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "playbook": {
                    "schema_version": "fusekit.provider-playbook.v1",
                    "steps": [
                        {
                            "id": "resend.capture_key",
                            "provider": "resend",
                            "route": "browser_guided",
                            "control": "Capture RESEND_API_KEY from VM clipboard",
                            "proof_source": "gate_events.jsonl",
                            "resume_event": "clipboard_captured -> resume_requested",
                            "instruction": (
                                "Capture RESEND_API_KEY from VM clipboard if the "
                                "Resend API route is not already authorized."
                            ),
                        },
                        {
                            "id": "resend.domain_api",
                            "provider": "resend",
                            "route": "api",
                            "control": "FuseKit API worker",
                            "proof_source": "setup_receipt.json",
                            "resume_event": "provider_action_recorded",
                            "instruction": (
                                "FuseKit creates or reuses the Resend sending domain "
                                "through the Resend API."
                            ),
                        },
                        {
                            "id": "vercel.env_api",
                            "provider": "vercel",
                            "route": "api",
                            "control": "FuseKit API worker",
                            "proof_source": "setup_receipt.json",
                            "resume_event": "provider_action_recorded",
                            "instruction": (
                                "FuseKit writes required runtime variables into Vercel "
                                "after upstream provider values exist."
                            ),
                        },
                        {
                            "id": "dns.approval",
                            "provider": "dns",
                            "route": "human_follow_me",
                            "control": "Approve DNS apply",
                            "proof_source": "gate_events.jsonl",
                            "resume_event": "dns_apply_approved -> resume_requested",
                            "instruction": (
                                "FuseKit carries app and provider-generated DNS records "
                                "into the DNS approval gate before apply."
                            ),
                        },
                    ],
                    "safety_notes": [
                        "Use the launcher and shared VM browser for provider gates.",
                        (
                            "Do not create Resend domains or audiences manually; "
                            "FuseKit owns those API setup steps."
                        ),
                        (
                            "Do not paste provider secrets into the host computer; "
                            "Capture reads the VM clipboard."
                        ),
                    ],
                },
                "providers": [],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")
    payload = static_control_room_payload(job, gate_path=tmp_path / "gates.json")

    assert payload["provider_strategies"]["playbook"]["schema_version"] == (
        "fusekit.provider-playbook.v1"
    )
    assert "Provider playbook" in html
    assert "Follow this in the shared VM browser" in html
    assert "Capture RESEND_API_KEY from VM clipboard" in html
    assert "FuseKit creates or reuses the Resend sending domain" in html
    assert "proof: gate_events.jsonl / clipboard_captured -&gt; resume_requested" in html
    assert "proof: setup_receipt.json / provider_action_recorded" in html
    assert "Approve DNS apply" in html
    assert "FuseKit writes required runtime variables into Vercel" in html
    assert "Do not create Resend domains or audiences manually" in html
    assert "Do not paste provider secrets into the host computer" in html
    assert "Click Add domain" not in html


def test_control_room_route_plan_names_human_gate_controls(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.save(tmp_path / "job.json")
    (tmp_path / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-consent",
                                "status": "needs_human_gate",
                                "strategy": "human_follow_me",
                                "next_action": (
                                    "Click Open provider gate in VM and approve only the "
                                    "named zone."
                                ),
                                "decision": {
                                    "selected": {
                                        "kind": "human_follow_me",
                                        "deterministic": False,
                                        "implemented": False,
                                        "reason": "Cloudflare needs account consent.",
                                    }
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "Route plan" in html
    assert "For provider-owned login, MFA, consent, or billing gates" in html
    assert "click Open provider gate in VM" in html
    assert "finish the prompt in the shared VM browser" in html
    assert "click the visible I finished this step button in the control room" in html
    assert "click I finished this step only after the provider confirms" not in html


def test_control_room_explains_deterministic_provider_route(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.save(tmp_path / "job.json")
    (tmp_path / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "status": "ok",
                                "strategy": "api",
                                "decision": {
                                    "selected": {
                                        "kind": "api",
                                        "deterministic": True,
                                        "implemented": True,
                                        "reason": (
                                            "RESEND_API_KEY is available; FuseKit will create "
                                            "or reuse the sending domain through Resend's API "
                                            "and hand DNS records to DNS."
                                        ),
                                        "evidence": {
                                            "api_owns": "domain",
                                            "downstream_order": "before_dns_apply",
                                            "token_available": "true",
                                            "user_manual_domain_step": "false",
                                        },
                                    }
                                },
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "resend-domain" in html
    assert "api · ok" in html
    assert "Route plan" in html
    assert "What happens in order" in html
    assert "First, FuseKit creates or reuses the Resend sending domain by API" in html
    assert "do not click Add domain in Resend" in html
    assert "unless FuseKit asks" not in html
    assert "FuseKit creates or reuses the Resend domain" in html
    assert "downstream Vercel env wiring" in html
    assert "complete record set" in html
    assert "collects DNS records, then waits for DNS approval" not in html
    assert "hand DNS records to DNS" in html


def test_control_room_route_plan_explains_resend_dns_and_vercel_order(tmp_path) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job.save(tmp_path / "job.json")
    (tmp_path / "provider_strategies.json").write_text(
        json.dumps(
            {
                "schema_version": "fusekit.provider-strategies.v1",
                "providers": [
                    {
                        "provider": "resend",
                        "strategies": [
                            {
                                "recipe": "resend-domain",
                                "status": "ok",
                                "strategy": "api",
                                "decision": {
                                    "selected": {
                                        "kind": "api",
                                        "deterministic": True,
                                        "implemented": True,
                                        "reason": "Resend domain setup is API owned.",
                                        "evidence": {
                                            "api_owns": "domain",
                                            "downstream_order": "before_dns_apply",
                                            "user_manual_domain_step": "false",
                                        },
                                    }
                                },
                            }
                        ],
                    },
                    {
                        "provider": "vercel",
                        "strategies": [
                            {
                                "recipe": "vercel-env",
                                "status": "ok",
                                "strategy": "api",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                    {
                        "provider": "cloudflare",
                        "strategies": [
                            {
                                "recipe": "cloudflare-dns",
                                "status": "ok",
                                "strategy": "api",
                                "decision": _strategy_decision(),
                            }
                        ],
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    html = render_control_room(job, gate_path=tmp_path / "gates.json")

    assert "Route plan" in html
    assert "First, FuseKit creates or reuses the Resend sending domain by API" in html
    assert "Then FuseKit writes the required RESEND_* runtime variables into Vercel" in html
    assert "after Resend domain/audience values exist" in html
    assert "Then FuseKit carries the Resend DNS records and app records" in html
    assert (
        html.index("First, FuseKit creates or reuses the Resend sending domain by API")
        < html.index("Then FuseKit writes the required RESEND_* runtime variables into Vercel")
        < html.index("Then FuseKit carries the Resend DNS records and app records")
    )
    assert "Then FuseKit writes the required RESEND_* runtime variables into Vercel" in SCRIPT
    assert "Then FuseKit carries the Resend DNS records and app records" in SCRIPT
    assert SCRIPT.index(
        "Then FuseKit writes the required RESEND_* runtime variables into Vercel"
    ) < SCRIPT.index("Then FuseKit carries the Resend DNS records and app records")
    assert "Capture or generate the required RESEND_* values" not in html


def test_control_room_server_uses_local_only_and_security_headers(tmp_path) -> None:
    assert _is_loopback("127.0.0.1")
    assert _is_loopback("localhost")
    assert not _is_loopback("0.0.0.0")

    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=5) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            body = response.read().decode("utf-8")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert headers["cache-control"] == "no-store"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert "camera=()" in headers["permissions-policy"]
    assert "microphone=()" in headers["permissions-policy"]
    assert "geolocation=()" in headers["permissions-policy"]
    assert "payment=()" in headers["permissions-policy"]
    assert "usb=()" in headers["permissions-policy"]
    csp = headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "object-src 'none'" in csp
    assert "style-src-attr 'none'" in csp
    assert "script-src-attr 'none'" in csp
    assert "'unsafe-inline'" not in csp
    nonce_match = re.search(r"script-src 'nonce-([^']+)'", csp)
    assert nonce_match is not None
    nonce = nonce_match.group(1)
    assert f"style-src 'nonce-{nonce}'" in csp
    assert body.count(f'nonce="{nonce}"') == 3
    assert "<style" in body
    assert '<script nonce="' in body
    assert "style=" not in body


def test_control_room_server_requires_remote_token(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", REMOTE_CONTROL_ROOM_TOKEN)
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with pytest.raises(HTTPError):
            urlopen(f"{base}/", timeout=5)
        cookie, redirect_status, redirect_location = _control_room_cookie_from_token(
            server.server_port, REMOTE_CONTROL_ROOM_TOKEN
        )
        request = Request(f"{base}/", headers={"Cookie": cookie})
        with urlopen(request, timeout=5) as response:
            html = response.read().decode("utf-8")
        request = Request(f"{base}/api/job", headers={"Cookie": cookie})
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert redirect_status == 303
    assert redirect_location == "/"
    assert "FuseKit Control Room" in html
    assert f"fusekit_control_room={REMOTE_CONTROL_ROOM_TOKEN}" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert "Path=/" in cookie
    assert "Max-Age=28800" in cookie
    assert payload["id"] == "fk-test"


def test_control_room_does_not_cookie_unsafe_remote_token(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", "token with spaces")
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with pytest.raises(HTTPError) as exc:
            urlopen(f"{base}/?token=token%20with%20spaces", timeout=5)
        headers = {key.lower(): value for key, value in exc.value.headers.items()}
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert exc.value.code == 403
    assert payload == {
        "error": (
            "Remote control room token must be generated with secrets.token_urlsafe "
            "and contain at least 32 URL-safe characters."
        ),
        "ok": False,
    }
    assert "set-cookie" not in headers


def test_tokenized_control_room_ignores_malformed_cookie_header(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", REMOTE_CONTROL_ROOM_TOKEN)
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)

    class BrokenCookie:
        def load(self, value: str) -> None:
            from http.cookies import CookieError

            raise CookieError("malformed cookie")

    monkeypatch.setattr("fusekit.runner.control_room.server.SimpleCookie", BrokenCookie)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        request = Request(
            f"{base}/api/job",
            headers={"Cookie": f"fusekit_control_room={REMOTE_CONTROL_ROOM_TOKEN}"},
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        headers = {key.lower(): value for key, value in exc.value.headers.items()}
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert exc.value.code == 403
    assert payload == {"error": "invalid control-room token", "ok": False}
    assert "set-cookie" not in headers


def test_tokenized_control_room_cleans_query_token_on_api_get(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", REMOTE_CONTROL_ROOM_TOKEN)
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = None
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
        connection.request("GET", f"/api/job?token={REMOTE_CONTROL_ROOM_TOKEN}&view=compact")
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        response.read()
    finally:
        if connection is not None:
            connection.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert response.status == 303
    assert headers["location"] == "/api/job?view=compact"
    assert REMOTE_CONTROL_ROOM_TOKEN not in headers["location"]
    assert f"fusekit_control_room={REMOTE_CONTROL_ROOM_TOKEN}" in headers["set-cookie"]
    assert "Max-Age=28800" in headers["set-cookie"]


def test_tokenized_control_room_rejects_cross_site_gate_post(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", REMOTE_CONTROL_ROOM_TOKEN)
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/api/gates/provider.github.mfa.123/pass"
        request = Request(
            url,
            method="POST",
            headers={
                "Authorization": f"Bearer {REMOTE_CONTROL_ROOM_TOKEN}",
                "x-fusekit-control-room": "resume",
                "x-fusekit-action-token": (tmp_path / "control-room-action-token")
                .read_text(encoding="utf-8")
                .strip(),
                "Origin": "https://evil.example",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        with pytest.raises(HTTPError):
            urlopen(request, timeout=5)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "waiting"
    )


def test_tokenized_control_room_rejects_query_token_gate_post(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", REMOTE_CONTROL_ROOM_TOKEN)
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = (
            f"http://127.0.0.1:{server.server_port}"
            f"/api/gates/provider.github.mfa.123/pass?token={REMOTE_CONTROL_ROOM_TOKEN}"
        )
        request = Request(
            url,
            method="POST",
            headers=_control_room_post_headers(tmp_path),
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        headers = {key.lower(): value for key, value in exc.value.headers.items()}
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert exc.value.code == 403
    assert payload == {
        "error": "control-room token query is not accepted for POST",
        "ok": False,
    }
    assert "set-cookie" not in headers
    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "waiting"
    )


def test_tokenized_control_room_requires_action_token_for_gate_post(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", REMOTE_CONTROL_ROOM_TOKEN)
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        cookie, redirect_status, redirect_location = _control_room_cookie_from_token(
            server.server_port, REMOTE_CONTROL_ROOM_TOKEN
        )
        with urlopen(Request(f"{base}/", headers={"Cookie": cookie}), timeout=5) as response:
            html = response.read().decode("utf-8")
        url = f"{base}/api/gates/provider.github.mfa.123/pass"
        request = Request(
            url,
            method="POST",
            headers={
                "Cookie": cookie,
                "x-fusekit-control-room": "resume",
                "Origin": base,
                "Sec-Fetch-Site": "same-origin",
            },
        )
        with pytest.raises(HTTPError) as exc:
            urlopen(request, timeout=5)
        payload = json.loads(exc.value.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert redirect_status == 303
    assert redirect_location == "/"
    assert "controlRoomActionToken" in html
    assert "x-fusekit-action-token" in html
    assert 'URLSearchParams(window.location.search).get("token")' not in html
    assert exc.value.code == 403
    assert payload == {"error": "invalid action token", "ok": False}
    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "waiting"
    )


def test_control_room_client_does_not_use_remote_token_as_action_token(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", REMOTE_CONTROL_ROOM_TOKEN)
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        cookie, redirect_status, redirect_location = _control_room_cookie_from_token(
            server.server_port, REMOTE_CONTROL_ROOM_TOKEN
        )
        with urlopen(Request(f"{base}/", headers={"Cookie": cookie}), timeout=5) as response:
            html = response.read().decode("utf-8")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert redirect_status == 303
    assert redirect_location == "/"
    assert REMOTE_CONTROL_ROOM_TOKEN not in html
    assert "control_room_action_token" in html
    assert 'URLSearchParams(window.location.search).get("token")' not in html


def test_tokenized_control_room_accepts_action_token_for_gate_post(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", REMOTE_CONTROL_ROOM_TOKEN)
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    GateService.load(tmp_path / "gates.json").wait(
        "provider.github.mfa.123",
        provider="github",
        reason="MFA required",
        classification="mfa",
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(job_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        cookie, redirect_status, redirect_location = _control_room_cookie_from_token(
            server.server_port, REMOTE_CONTROL_ROOM_TOKEN
        )
        url = f"{base}/api/gates/provider.github.mfa.123/pass"
        request = Request(
            url,
            method="POST",
            headers={
                "Cookie": cookie,
                "x-fusekit-control-room": "resume",
                "x-fusekit-action-token": (tmp_path / "control-room-action-token")
                .read_text(encoding="utf-8")
                .strip(),
                "Origin": base,
                "Sec-Fetch-Site": "same-origin",
            },
        )
        with urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert redirect_status == 303
    assert redirect_location == "/"
    assert payload["ok"] is True
    assert payload["status"] == "resume_requested"
    assert (
        GateService.load(tmp_path / "gates.json").records["provider.github.mfa.123"].status
        == "resume_requested"
    )


def test_control_room_remote_bind_requires_allow_flag_and_token(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = JobState.create("fk-test", tmp_path, "oci-free")
    job_path = tmp_path / "job.json"
    job.save(job_path)
    monkeypatch.delenv("FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM", raising=False)
    monkeypatch.delenv("FUSEKIT_CONTROL_ROOM_TOKEN", raising=False)

    with pytest.raises(FuseKitError, match="local-only"):
        serve_control_room(job_path, host="0.0.0.0", port=0)

    monkeypatch.setenv("FUSEKIT_ALLOW_REMOTE_CONTROL_ROOM", "1")
    with pytest.raises(FuseKitError, match="requires FUSEKIT_CONTROL_ROOM_TOKEN"):
        serve_control_room(job_path, host="0.0.0.0", port=0)

    monkeypatch.setenv("FUSEKIT_CONTROL_ROOM_TOKEN", "short")
    with pytest.raises(FuseKitError, match="secrets.token_urlsafe"):
        serve_control_room(job_path, host="0.0.0.0", port=0)


def test_remote_bootstrap_artifacts_are_self_contained() -> None:
    cloud_init = render_cloud_init(openclaw_install_url="https://openclaw.ai/install-cli.sh")
    git_cloud_init = render_cloud_init(
        fusekit_wheel_url="git+https://github.com/example/fusekit.git",
        openclaw_install_url="https://openclaw.ai/install-cli.sh",
    )

    assert isinstance(yaml.safe_load(cloud_init), dict)
    assert isinstance(yaml.safe_load(git_cloud_init), dict)
    assert 'Acquire::ForceIPv4 "true";' in cloud_init
    assert "http://archive.ubuntu.com/ubuntu" in cloud_init
    assert "http://security.ubuntu.com/ubuntu" in cloud_init
    assert "package_update:" not in cloud_init
    assert "\npackages:\n" not in cloud_init
    assert "/usr/local/sbin/fusekit-retry apt-get -o Acquire::ForceIPv4=true update" in cloud_init
    assert "DEBIAN_FRONTEND=noninteractive /usr/local/sbin/fusekit-retry apt-get" in cloud_init
    assert "-o Acquire::ForceIPv4=true install -y python3 python3-pip python3-venv" in cloud_init
    assert "iptables -I INPUT -p tcp --dport 8765 -j ACCEPT" in cloud_init
    assert "iptables -I INPUT -p tcp --dport 6080 -j ACCEPT" in cloud_init
    assert "python3-venv" in cloud_init
    assert "printf '%s\\n' \"$FUSEKIT_VISUAL_PASSWORD\"" in cloud_init
    assert (
        "/usr/local/sbin/fusekit-retry "
        "/opt/fusekit-python/bin/python -m pip install --upgrade fusekit" in cloud_init
    )
    assert (
        "/usr/local/sbin/fusekit-retry "
        "/opt/fusekit-python/bin/python -m pip install "
        "--upgrade --force-reinstall --no-cache-dir "
        "git+https://github.com/example/fusekit.git"
    ) in git_cloud_init
    assert "PLAYWRIGHT_BROWSERS_PATH=/opt/fusekit-playwright-browsers" in cloud_init
    assert 'case "$(uname -m)" in' in cloud_init
    assert "FuseKit runner requires x86_64 architecture" in cloud_init
    assert "test -x /usr/local/sbin/fusekit-runner-loop-once" in cloud_init
    assert "test -x /usr/local/sbin/fusekit-visual-start" in cloud_init
    assert "for command in Xvfb x11vnc fluxbox" in cloud_init
    assert "FuseKit runner requires websockify or novnc_proxy for noVNC." in cloud_init
    assert "mkdir -p /var/lib/fusekit-runner/visual/chrome-provider-profile" in cloud_init
    assert (
        "/usr/local/sbin/fusekit-retry "
        "env PLAYWRIGHT_BROWSERS_PATH=/opt/fusekit-playwright-browsers "
        "/opt/fusekit-python/bin/python -m playwright install --with-deps chromium"
    ) in cloud_init
    assert "chromium-browser" not in cloud_init
    assert "sync_playwright" in cloud_init
    assert "fusekit.runner-readiness.v1" in cloud_init
    assert "fusekit.runner-profile.v1" in cloud_init
    assert "oci-visual-browser-x86_64" in cloud_init
    assert "min_memory_mib = 15360" in cloud_init
    assert "FuseKit runner requires at least 16 GB RAM" in cloud_init
    assert "openclaw_gateway_loopback=19002" in cloud_init
    assert "/var/lib/fusekit-runner/runner-readiness.json" in cloud_init
    assert "playwright_chromium" in cloud_init
    assert "shared_provider_browser_profile" in cloud_init
    assert "xvfb fluxbox x11vnc novnc websockify xterm" in cloud_init
    assert "fusekit-visual-start" in cloud_init
    assert 'websockify --web "$novnc_web" 0.0.0.0:6080 localhost:5900' in cloud_init
    assert 'x11vnc -display "$display" -localhost' in cloud_init
    assert "openclaw browser status --json" not in cloud_init
    assert (
        "/usr/local/sbin/fusekit-retry "
        "env OPENCLAW_HOME=/var/lib/fusekit-runner/openclaw-state "
        "bash /opt/fusekit-openclaw/install-openclaw.sh"
    ) in cloud_init
    assert 'chown -R "$runner_user:$runner_user" /var/lib/fusekit-runner' in cloud_init
    assert "fusekit-runner-verify" in cloud_init
    assert cloud_init.rindex(
        'chown -R "$runner_user:$runner_user" /var/lib/fusekit-runner'
    ) > cloud_init.rindex("OPENCLAW_HOME=/var/lib/fusekit-runner/openclaw-state")
    assert "/usr/local/sbin/fusekit-retry" in cloud_init
    assert "export PATH=/opt/fusekit-python/bin:/opt/fusekit-openclaw/bin:$PATH" in cloud_init
    assert "FUSEKIT_OPENCLAW_BIN=/opt/fusekit-openclaw/bin/openclaw" in cloud_init
    assert "ln -sf /opt/fusekit-python/bin/fusekit /usr/local/bin/fusekit" in cloud_init
    assert "ln -sf /opt/fusekit-openclaw/bin/openclaw /usr/local/bin/openclaw" in cloud_init
    assert "  - |\n    python3 - <<'PY'" in cloud_init
    assert "/opt/fusekit-openclaw/openclaw/bin" not in cloud_init
    assert should_include_app_path(Path("src/index.js"))
    assert not should_include_app_path(Path(".env"))
    assert not should_include_app_path(Path(".env.production"))
    assert not should_include_app_path(Path(".npmrc"))
    assert not should_include_app_path(Path(".vercel/project.json"))
    assert not should_include_app_path(Path("id_ed25519"))
    assert not should_include_app_path(Path("service.credentials.json"))
    assert not should_include_app_path(Path(".fusekit/fusekit.vault.json"))


def test_remote_artifact_extract_rejects_unsafe_paths(tmp_path) -> None:
    archive = tmp_path / "artifacts.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        payload = tmp_path / "payload.txt"
        payload.write_text("bad", encoding="utf-8")
        tar.add(payload, arcname="../escape.txt")

    with pytest.raises(FuseKitError, match="unsafe paths"):
        _extract_artifacts(archive, tmp_path / "out")


def test_remote_artifact_extract_rejects_empty_archives(tmp_path) -> None:
    archive = tmp_path / "artifacts.tar.gz"
    with tarfile.open(archive, "w:gz"):
        pass

    with pytest.raises(FuseKitError, match="did not contain files"):
        _extract_artifacts(archive, tmp_path / "out")


def test_remote_artifact_bundle_requires_survivor_files(tmp_path) -> None:
    from fusekit.runner.remote import _validate_artifact_bundle

    (tmp_path / ".fusekit").mkdir()
    (tmp_path / ".fusekit" / "job.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".fusekit" / "checkpoints.json").write_text("{}", encoding="utf-8")

    with pytest.raises(FuseKitError, match="fusekit.vault.json"):
        _validate_artifact_bundle(tmp_path)

    for name in (
        "fusekit.vault.json",
        "audit.jsonl",
        "setup_receipt.json",
        "job.json",
        "checkpoints.json",
        "run_record.json",
        "verification_report.json",
        "rollback_plan.json",
        "provider_strategies.json",
    ):
        (tmp_path / ".fusekit" / name).write_text("{}", encoding="utf-8")

    with pytest.raises(FuseKitError, match="runner_readiness.json"):
        _validate_artifact_bundle(tmp_path)


def test_latest_workspace_round_trips_from_vault() -> None:
    vault = Vault.empty()
    workspace = OciWorkspace(
        id="fusekit-test",
        compartment_id="ocid1.tenancy.oc1..example",
        availability_domain="AD-1",
        shape="VM.Standard3.Flex",
        public_ip="203.0.113.10",
        resource_ids={"instance": "ocid1.instance.oc1..example"},
    )
    vault.put(
        "runner.oci.fusekit-test.workspace",
        "runner_workspace",
        "oci",
        "workspace",
        json.dumps(workspace.to_dict()),
    )

    loaded = latest_workspace_from_vault(vault)

    assert loaded.shape == "VM.Standard3.Flex"
    assert loaded.ssh_user == "opc"
    assert loaded.public_ip == "203.0.113.10"


def test_oci_detonation_reports_provider_delete_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailedDelete(Exception):
        status = 409
        code = "Conflict"

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class FakeCompute:
        def terminate_instance(self, instance_id: str, *, preserve_boot_volume: bool) -> None:
            assert instance_id == "ocid1.instance.oc1..example"
            assert preserve_boot_volume is False

        def list_vnic_attachments(self, *, compartment_id: str, instance_id: str) -> Response:
            assert compartment_id == "ocid1.tenancy.oc1..example"
            assert instance_id == "ocid1.instance.oc1..example"
            return Response([])

    class FakeNetwork:
        def __init__(self) -> None:
            self.deleted: list[str] = []

        def delete_subnet(self, resource_id: str) -> None:
            raise FailedDelete(resource_id)

        def delete_network_security_group(self, resource_id: str) -> None:
            self.deleted.append("network_security_group")
            return None

        def delete_security_list(self, resource_id: str) -> None:
            self.deleted.append("security_list")
            return None

        def delete_route_table(self, resource_id: str) -> None:
            self.deleted.append("route_table")
            return None

        def delete_internet_gateway(self, resource_id: str) -> None:
            self.deleted.append("internet_gateway")
            return None

        def delete_vcn(self, resource_id: str) -> None:
            self.deleted.append("vcn")
            return None

    class FakeIdentity:
        def delete_compartment(self, resource_id: str) -> None:
            raise FailedDelete(resource_id)

    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    provisioner = object.__new__(OciProvisioner)
    provisioner.compute = FakeCompute()
    network = FakeNetwork()
    provisioner.network = network
    provisioner.identity = FakeIdentity()
    workspace = OciWorkspace(
        id="fusekit-test",
        compartment_id="ocid1.tenancy.oc1..example",
        availability_domain="AD-1",
        shape="VM.Standard3.Flex",
        public_ip="203.0.113.10",
        resource_ids={
            "instance": "ocid1.instance.oc1..example",
            "subnet": "ocid1.subnet.oc1..example",
            "network_security_group": "ocid1.nsg.oc1..example",
            "security_list": "ocid1.securitylist.oc1..example",
            "route_table": "ocid1.routetable.oc1..example",
            "internet_gateway": "ocid1.ig.oc1..example",
            "vcn": "ocid1.vcn.oc1..example",
            "compartment": "ocid1.compartment.oc1..example",
        },
    )

    deleted = provisioner.detonate(workspace)

    assert deleted["instance"] == "ocid1.instance.oc1..example"
    assert deleted["boot_volume"] == "delete-on-terminate"
    assert deleted["ephemeral_public_ip"] == "203.0.113.10"
    assert deleted["failed.subnet"] == "409 Conflict"
    assert deleted["failed.compartment"] == "409 Conflict"
    assert network.deleted == [
        "route_table",
        "internet_gateway",
        "network_security_group",
        "security_list",
        "vcn",
    ]


def test_oci_provision_cleans_partial_workspace_when_readiness_fails() -> None:
    class Created:
        def __init__(self, resource_id: str) -> None:
            self.id = resource_id

    class FakeProvisioner(OciProvisioner):
        def __init__(self) -> None:
            self.auth = type("Auth", (), {"config": {"tenancy": "ocid1.tenancy.example"}})()
            self.deleted: OciWorkspace | None = None

        def _availability_domains(self, compartment_id: str) -> tuple[str, ...]:
            return ("AD-1",)

        def _create_vcn(self, compartment_id: str, run_id: str, tags: dict[str, str]) -> Created:
            return Created("ocid1.vcn.example")

        def _create_internet_gateway(
            self,
            compartment_id: str,
            vcn_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            return Created("ocid1.ig.example")

        def _create_route_table(
            self,
            compartment_id: str,
            vcn_id: str,
            gateway_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            return Created("ocid1.route.example")

        def _create_security_list(
            self,
            compartment_id: str,
            vcn_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            return Created("ocid1.security-list.example")

        def _create_nsg(
            self,
            compartment_id: str,
            vcn_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            return Created("ocid1.nsg.example")

        def _create_subnet(
            self,
            compartment_id: str,
            vcn_id: str,
            route_table_id: str,
            security_list_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> Created:
            assert security_list_id == "ocid1.security-list.example"
            return Created("ocid1.subnet.example")

        def _emit_capacity_report(
            self,
            root_compartment_id: str,
            availability_domains: tuple[str, ...],
            plan: OciRunnerPlan,
        ) -> None:
            pass

        def _launch_with_capacity_fallback(
            self, **kwargs: object
        ) -> tuple[Created, object, str, str]:
            return Created("ocid1.instance.example"), kwargs["base_plan"], "ubuntu", "AD-1"

        def _public_ip(
            self,
            compartment_id: str,
            instance_id: str,
            nsg_id: str,
            run_id: str,
            tags: dict[str, str],
        ) -> str:
            return ""

        def detonate(self, workspace: OciWorkspace) -> dict[str, str]:
            self.deleted = workspace
            return {"instance": workspace.resource_ids.get("instance", "")}

    vault = Vault.empty()
    plan = build_oci_runner_plan(runner="oci", fusekit_package="fusekit")
    provisioner = FakeProvisioner()

    with pytest.raises(FuseKitError, match="public IP"):
        provisioner.provision(plan, vault)

    assert provisioner.deleted is not None
    ssh_record = vault.require(f"runner.oci.{provisioner.deleted.id}.ssh.private")
    assert ssh_record.value.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert ssh_record.metadata["fingerprint"].startswith("rsa:")
    assert provisioner.deleted.resource_ids["instance"] == "ocid1.instance.example"
    assert provisioner.deleted.resource_ids["security_list"] == "ocid1.security-list.example"
    assert provisioner.deleted.resource_ids["root_compartment"] == "ocid1.tenancy.example"
    assert provisioner.deleted.ssh_user == "ubuntu"


def test_oci_latest_image_prefers_ubuntu_lts_for_runner_bootstrap() -> None:
    class Image:
        def __init__(
            self,
            image_id: str,
            *,
            operating_system: str = "Canonical Ubuntu",
            operating_system_version: str = "24.04",
            display_name: str = "Canonical-Ubuntu-24.04-2026.05.30-0",
        ) -> None:
            self.id = image_id
            self.operating_system = operating_system
            self.operating_system_version = operating_system_version
            self.display_name = display_name

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class FakeCompute:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str]] = []

        def list_images(
            self,
            *,
            compartment_id: str,
            operating_system: str,
            operating_system_version: str = "",
            shape: str,
            sort_by: str,
            sort_order: str,
        ) -> Response:
            assert compartment_id == "ocid1.compartment.example"
            assert shape == "VM.Standard.E5.Flex"
            assert sort_by == "TIMECREATED"
            assert sort_order == "DESC"
            self.requests.append((operating_system, operating_system_version))
            if operating_system == "Canonical Ubuntu" and operating_system_version == "24.04":
                return Response([Image("ocid1.image.ubuntu-24-04")])
            return Response([Image("ocid1.image.oraclelinux")])

    provisioner = object.__new__(OciProvisioner)
    provisioner.compute = FakeCompute()
    progress: list[str] = []
    provisioner._progress = progress.append

    image_id, ssh_user = provisioner._latest_image(
        "ocid1.compartment.example",
        "VM.Standard.E5.Flex",
    )

    assert image_id == "ocid1.image.ubuntu-24-04"
    assert ssh_user == "ubuntu"
    assert provisioner.compute.requests == [("Canonical Ubuntu", "24.04")]
    assert any("Canonical Ubuntu 24.04" in item for item in progress)
    assert any("for SSH user ubuntu" in item for item in progress)


def test_oci_latest_image_falls_back_to_ubuntu_2204_before_oracle_linux() -> None:
    class Image:
        def __init__(self, image_id: str) -> None:
            self.id = image_id

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class FakeCompute:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str]] = []

        def list_images(
            self,
            *,
            compartment_id: str,
            operating_system: str,
            operating_system_version: str = "",
            shape: str,
            sort_by: str,
            sort_order: str,
        ) -> Response:
            self.requests.append((operating_system, operating_system_version))
            if operating_system == "Canonical Ubuntu" and operating_system_version == "22.04":
                return Response([Image("ocid1.image.ubuntu-22-04")])
            return Response([])

    provisioner = object.__new__(OciProvisioner)
    provisioner.compute = FakeCompute()

    image_id, ssh_user = provisioner._latest_image(
        "ocid1.compartment.example",
        "VM.Standard.E5.Flex",
    )

    assert image_id == "ocid1.image.ubuntu-22-04"
    assert ssh_user == "ubuntu"
    assert provisioner.compute.requests == [
        ("Canonical Ubuntu", "24.04"),
        ("Canonical Ubuntu", "22.04"),
    ]


def test_oci_launch_instance_matches_console_recommended_options() -> None:
    class Details:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class FakeModels:
        LaunchInstanceShapeConfigDetails = Details
        CreateVnicDetails = Details
        InstanceSourceViaImageDetails = Details
        InstanceOptions = Details
        LaunchInstanceAvailabilityConfigDetails = Details
        LaunchInstanceDetails = Details

    class FakeOci:
        class core:
            models = FakeModels

    class FakeCompute:
        def __init__(self) -> None:
            self.details: object | None = None

        def launch_instance(self, details: object) -> Response:
            self.details = details
            return Response(Details(id="ocid1.instance.example"))

    plan = build_oci_runner_plan(runner="oci")
    provisioner = object.__new__(OciProvisioner)
    provisioner.oci = FakeOci()
    provisioner.compute = FakeCompute()

    instance = provisioner._launch_instance(
        compartment_id="ocid1.compartment.example",
        availability_domain="AD-1",
        image_id="ocid1.image.example",
        subnet_id="ocid1.subnet.example",
        nsg_id="ocid1.nsg.example",
        plan=plan,
        run_id="fusekit-test",
        ssh_public_key="ssh-rsa test",
        cloud_init="#cloud-config",
        tags={"fusekit": "true"},
    )

    details = cast(Any, provisioner.compute.details)
    assert instance.id == "ocid1.instance.example"
    assert details.shape == "VM.Standard.E5.Flex"
    assert details.shape_config.ocpus == 2
    assert details.shape_config.memory_in_gbs == 24
    assert not hasattr(details.shape_config, "baseline_ocpu_utilization")
    assert details.create_vnic_details.assign_public_ip is False
    assert details.create_vnic_details.hostname_label == "runner"
    assert not hasattr(details.create_vnic_details, "nsg_ids")
    assert details.instance_options.are_legacy_imds_endpoints_disabled is True
    assert details.availability_config.recovery_action == "RESTORE_INSTANCE"
    assert details.is_pv_encryption_in_transit_enabled is True


def test_oci_capacity_report_uses_root_compartment_and_shape_config() -> None:
    class Details:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class FakeModels:
        CreateComputeCapacityReportDetails = Details
        CreateCapacityReportShapeAvailabilityDetails = Details
        CapacityReportInstanceShapeConfig = Details

    class FakeOci:
        class core:
            models = FakeModels

    class FakeCompute:
        def __init__(self) -> None:
            self.details: object | None = None

        def create_compute_capacity_report(self, details: object) -> Response:
            self.details = details
            return Response(
                Details(
                    shape_availabilities=[
                        Details(
                            instance_shape="VM.Standard.E5.Flex",
                            availability_status="AVAILABLE",
                        )
                    ]
                )
            )

    progress: list[str] = []
    provisioner = object.__new__(OciProvisioner)
    provisioner.oci = FakeOci()
    provisioner.compute = FakeCompute()
    provisioner._progress = progress.append
    plan = build_oci_runner_plan(runner="oci")

    provisioner._emit_capacity_report(
        "ocid1.tenancy.example",
        ("AD-1",),
        plan,
    )

    details = cast(Any, provisioner.compute.details)
    shape_availability = details.shape_availabilities[0]
    assert details.compartment_id == "ocid1.tenancy.example"
    assert details.availability_domain == "AD-1"
    assert shape_availability.instance_shape == "VM.Standard.E5.Flex"
    assert shape_availability.instance_shape_config.ocpus == 2
    assert shape_availability.instance_shape_config.memory_in_gbs == 24
    assert any("AVAILABLE" in item for item in progress)


def test_oci_public_ip_is_assigned_after_private_vnic_launch() -> None:
    class Details:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class FakeModels:
        CreatePublicIpDetails = Details

    class FakeOci:
        class core:
            models = FakeModels

    class FakeNetwork:
        def __init__(self) -> None:
            self.details: object | None = None

        def list_private_ips(self, *, vnic_id: str) -> Response:
            assert vnic_id == "ocid1.vnic.example"
            return Response([Details(id="ocid1.privateip.example")])

        def create_public_ip(self, details: object) -> Response:
            self.details = details
            return Response(Details(ip_address="203.0.113.44"))

    provisioner = object.__new__(OciProvisioner)
    provisioner.oci = FakeOci()
    provisioner.network = FakeNetwork()

    public_ip = provisioner._assign_public_ip(
        "ocid1.tenancy.example",
        "ocid1.vnic.example",
        "fusekit-test",
        {"fusekit": "true"},
    )

    details = cast(Any, provisioner.network.details)
    assert public_ip == "203.0.113.44"
    assert details.compartment_id == "ocid1.tenancy.example"
    assert details.lifetime == "EPHEMERAL"
    assert details.private_ip_id == "ocid1.privateip.example"


def test_oci_public_ip_attaches_runner_nsg_after_launch() -> None:
    class Details:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class FakeModels:
        UpdateVnicDetails = Details

    class FakeOci:
        class core:
            models = FakeModels

    class FakeCompute:
        def list_vnic_attachments(self, *, compartment_id: str, instance_id: str) -> Response:
            assert compartment_id == "ocid1.tenancy.example"
            assert instance_id == "ocid1.instance.example"
            return Response([Details(vnic_id="ocid1.vnic.example")])

    class FakeNetwork:
        def __init__(self) -> None:
            self.update_details: object | None = None

        def update_vnic(self, vnic_id: str, details: object) -> Response:
            assert vnic_id == "ocid1.vnic.example"
            self.update_details = details
            return Response(None)

        def get_vnic(self, vnic_id: str) -> Response:
            assert vnic_id == "ocid1.vnic.example"
            return Response(Details(public_ip="203.0.113.45"))

    provisioner = object.__new__(OciProvisioner)
    provisioner.oci = FakeOci()
    provisioner.compute = FakeCompute()
    provisioner.network = FakeNetwork()

    public_ip = provisioner._public_ip(
        "ocid1.tenancy.example",
        "ocid1.instance.example",
        "ocid1.nsg.example",
        "fusekit-test",
        {"fusekit": "true"},
    )

    update_details = cast(Any, provisioner.network.update_details)
    assert public_ip == "203.0.113.45"
    assert update_details.nsg_ids == ["ocid1.nsg.example"]


def test_oci_create_nsg_wraps_security_rules_for_sdk_request() -> None:
    class Details:
        def __init__(self, **kwargs: object) -> None:
            self.__dict__.update(kwargs)

    class Created:
        def __init__(self, resource_id: str) -> None:
            self.id = resource_id

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class FakeModels:
        CreateNetworkSecurityGroupDetails = Details
        AddSecurityRuleDetails = Details
        TcpOptions = Details
        PortRange = Details
        AddNetworkSecurityGroupSecurityRulesDetails = Details

    class FakeOci:
        class core:
            models = FakeModels

    class FakeNetwork:
        def __init__(self) -> None:
            self.added: tuple[str, object] | None = None

        def create_network_security_group(self, details: object) -> Response:
            assert cast(Any, details).display_name == "fusekit-test-nsg"
            return Response(Created("ocid1.nsg.example"))

        def add_network_security_group_security_rules(self, nsg_id: str, details: object) -> None:
            self.added = (nsg_id, details)

    provisioner = object.__new__(OciProvisioner)
    provisioner.oci = FakeOci()
    provisioner.network = FakeNetwork()

    nsg = provisioner._create_nsg(
        "ocid1.compartment.example",
        "ocid1.vcn.example",
        "fusekit-test",
        {"fusekit": "true"},
    )

    assert nsg.id == "ocid1.nsg.example"
    assert provisioner.network.added is not None
    nsg_id, details = provisioner.network.added
    assert nsg_id == "ocid1.nsg.example"
    assert not isinstance(details, list)
    assert len(details.security_rules) == 4
    assert details.security_rules[0].direction == "INGRESS"
    assert details.security_rules[0].tcp_options.destination_port_range.min == 22
    assert details.security_rules[1].direction == "INGRESS"
    assert details.security_rules[1].tcp_options.destination_port_range.min == 8765
    assert details.security_rules[2].direction == "INGRESS"
    assert details.security_rules[2].tcp_options.destination_port_range.min == 6080
    assert details.security_rules[3].direction == "EGRESS"


def test_oci_availability_domains_use_runner_region_identity() -> None:
    class Domain:
        def __init__(self, name: str) -> None:
            self.name = name

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class RegionalIdentity:
        def list_availability_domains(self, compartment_id: str) -> Response:
            assert compartment_id == "ocid1.tenancy.example"
            return Response([Domain("regional-ad-1"), Domain("regional-ad-2")])

    provisioner = object.__new__(OciProvisioner)
    provisioner.identity = RegionalIdentity()

    domains = provisioner._availability_domains("ocid1.tenancy.example")

    assert domains == ("regional-ad-1", "regional-ad-2")


def test_oci_availability_domains_reports_unsubscribed_region() -> None:
    class FakeOciError(Exception):
        status = 404
        code = "EntityNotFound"
        request_id = "region-request"

    class RegionalIdentity:
        def list_availability_domains(self, compartment_id: str) -> object:
            raise FakeOciError("tenancy not found")

    provisioner = object.__new__(OciProvisioner)
    provisioner.identity = RegionalIdentity()
    provisioner.auth = type("Auth", (), {"config": {"region": "us-ashburn-1"}})()

    with pytest.raises(FuseKitError) as exc_info:
        provisioner._availability_domains("ocid1.tenancy.example")

    message = str(exc_info.value)
    assert "could not list availability domains in us-ashburn-1" in message
    assert "not subscribed to that region" in message
    assert "region-request" in message


def test_oci_availability_domains_retries_transient_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Domain:
        def __init__(self, name: str) -> None:
            self.name = name

    class Response:
        def __init__(self, data: object) -> None:
            self.data = data

    class TransientAuthError(Exception):
        status = 401
        code = "NotAuthenticated"

    class RegionalIdentity:
        calls = 0

        def list_availability_domains(self, compartment_id: str) -> Response:
            assert compartment_id == "ocid1.tenancy.example"
            self.calls += 1
            if self.calls == 1:
                raise TransientAuthError("identity auth is settling")
            return Response([Domain("regional-ad-1")])

    sleeps: list[int] = []
    monkeypatch.setattr(time, "sleep", sleeps.append)
    provisioner = object.__new__(OciProvisioner)
    provisioner.identity = RegionalIdentity()
    provisioner._progress = lambda message: None

    domains = provisioner._availability_domains("ocid1.tenancy.example")

    assert domains == ("regional-ad-1",)
    assert sleeps == [10]


def test_oci_launch_retries_transient_not_authorized_or_not_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Created:
        def __init__(self, resource_id: str) -> None:
            self.id = resource_id

    class FakeOciError(Exception):
        status = 404
        code = "NotAuthorizedOrNotFound"
        request_id = "request-1"

    progress: list[str] = []
    sleeps: list[int] = []
    plan = build_oci_runner_plan(runner="oci", fusekit_package="fusekit")
    provisioner = object.__new__(OciProvisioner)
    provisioner._progress = progress.append
    attempts = 0

    def launch(**kwargs: object) -> Created:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise FakeOciError("not ready")
        return Created("ocid1.instance.example")

    provisioner._launch_instance = launch
    monkeypatch.setattr(time, "sleep", sleeps.append)

    instance = provisioner._launch_instance_with_iam_retries(
        compartment_id="ocid1.compartment.example",
        availability_domain="AD-1",
        image_id="ocid1.image.example",
        subnet_id="ocid1.subnet.example",
        nsg_id="ocid1.nsg.example",
        plan=plan,
        run_id="fusekit-test",
        ssh_public_key="ssh-rsa test",
        cloud_init="#cloud-config",
        tags={"fusekit": "true"},
    )

    assert instance.id == "ocid1.instance.example"
    assert attempts == 3
    assert sleeps == [20, 40]
    assert any("waiting for OCI IAM/resource propagation" in item for item in progress)


def test_oci_launch_not_authorized_or_not_found_reports_actionable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeOciError(Exception):
        status = 404
        code = "NotAuthorizedOrNotFound"
        request_id = "request-final"

    progress: list[str] = []
    plan = build_oci_runner_plan(runner="oci", fusekit_package="fusekit")
    provisioner = object.__new__(OciProvisioner)
    provisioner._progress = progress.append
    monkeypatch.setattr(time, "sleep", lambda seconds: None)
    monkeypatch.setattr(
        provisioner,
        "_latest_image",
        lambda compartment_id, shape: (f"ocid1.image.{shape}", "ubuntu"),
    )

    def launch(**kwargs: object) -> object:
        raise FakeOciError("no launch permission")

    provisioner._launch_instance = launch

    with pytest.raises(FuseKitError) as exc_info:
        provisioner._launch_with_capacity_fallback(
            base_plan=plan,
            compartment_id="ocid1.compartment.example",
            availability_domain="AD-1",
            subnet_id="ocid1.subnet.example",
            nsg_id="ocid1.nsg.example",
            run_id="fusekit-test",
            ssh_public_key="ssh-rsa test",
            cloud_init="#cloud-config",
            tags={"fusekit": "true"},
        )

    message = str(exc_info.value)
    assert "404 NotAuthorizedOrNotFound" in message
    assert "permission to manage instances" in message
    assert "request-final" in message
    assert any("trying next x86 option" in item for item in progress)


def test_oci_launch_fallback_checks_all_availability_domains(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Created:
        def __init__(self, resource_id: str) -> None:
            self.id = resource_id

    class FakeCapacityError(Exception):
        pass

    progress: list[str] = []
    attempts: list[tuple[str, str]] = []
    plan = build_oci_runner_plan(runner="oci", fusekit_package="fusekit")
    provisioner = object.__new__(OciProvisioner)
    provisioner._progress = progress.append
    monkeypatch.setattr(
        provisioner,
        "_latest_image",
        lambda compartment_id, shape: (f"ocid1.image.{shape}", "ubuntu"),
    )

    def launch(**kwargs: object) -> Created:
        candidate = cast(OciRunnerPlan, kwargs["plan"])
        domain = cast(str, kwargs["availability_domain"])
        attempts.append((domain, candidate.shape))
        if domain == "AD-1":
            raise FakeCapacityError("capacity unavailable")
        return Created("ocid1.instance.example")

    provisioner._launch_instance_with_iam_retries = launch

    instance, selected_plan, ssh_user, selected_domain = provisioner._launch_with_capacity_fallback(
        base_plan=plan,
        compartment_id="ocid1.compartment.example",
        availability_domains=("AD-1", "AD-2"),
        subnet_id="ocid1.subnet.example",
        nsg_id="ocid1.nsg.example",
        run_id="fusekit-test",
        ssh_public_key="ssh-rsa test",
        cloud_init="#cloud-config",
        tags={"fusekit": "true"},
    )

    assert instance.id == "ocid1.instance.example"
    assert selected_plan.shape == "VM.Standard.E5.Flex"
    assert ssh_user == "ubuntu"
    assert selected_domain == "AD-2"
    assert ("AD-1", "VM.Standard.E5.Flex") in attempts
    assert ("AD-2", "VM.Standard.E5.Flex") in attempts
    assert any("launch inputs shape=VM.Standard.E5.Flex" in item for item in progress)
    assert any("public_ip=post-launch nsg=post-launch" in item for item in progress)
    assert any("checking availability domain AD-2" in item for item in progress)


def test_oci_launch_limit_exceeded_reports_account_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeLimitExceededError(Exception):
        status = 400
        code = "LimitExceeded"
        message = (
            "Your resource creation limit has been reached. To unblock resource "
            "creation, please upgrade to a Pay As You Go or Oracle Universal Credits "
            "account, or delete resources to restore your resource creation capability."
        )
        request_id = "limit-request-123"

    progress: list[str] = []
    plan = build_oci_runner_plan(runner="oci", fusekit_package="fusekit")
    provisioner = object.__new__(OciProvisioner)
    provisioner._progress = progress.append
    monkeypatch.setattr(
        provisioner,
        "_latest_image",
        lambda compartment_id, shape: (f"ocid1.image.{shape}", "ubuntu"),
    )

    def launch(**kwargs: object) -> object:
        raise FakeLimitExceededError()

    provisioner._launch_instance_with_iam_retries = launch

    with pytest.raises(FuseKitError) as exc_info:
        provisioner._launch_with_capacity_fallback(
            base_plan=plan,
            compartment_id="ocid1.compartment.example",
            availability_domains=("AD-1", "AD-2"),
            subnet_id="ocid1.subnet.example",
            nsg_id="ocid1.nsg.example",
            run_id="fusekit-test",
            ssh_public_key="ssh-rsa test",
            cloud_init="#cloud-config",
            tags={"fusekit": "true"},
        )

    message = str(exc_info.value)
    assert "resource creation limit" in message
    assert "Pay As You Go" in message
    assert "limit-request-123" in message
    assert any("account resource limit reached" in item for item in progress)
    assert not any("capacity unavailable" in item for item in progress)


def test_oci_error_summary_includes_message_and_request_id() -> None:
    class FakeOciError(Exception):
        status = 500
        code = "InternalError"
        message = "Out of host capacity."
        request_id = "oci-request-123"

    summary = _safe_oci_error(FakeOciError())

    assert "500" in summary
    assert "InternalError" in summary
    assert "Out of host capacity" in summary
    assert "oci-request-123" in summary


def test_oci_debug_logging_is_suppressed(monkeypatch: pytest.MonkeyPatch) -> None:
    original_http_level = http.client.HTTPConnection.debuglevel
    original_https_level = http.client.HTTPSConnection.debuglevel
    try:
        monkeypatch.setenv("OCI_PYTHON_SDK_DEBUG", "1")
        monkeypatch.setenv("OCI_SDK_DEBUG", "1")
        http.client.HTTPConnection.debuglevel = 1
        http.client.HTTPSConnection.debuglevel = 1
        suppress_oci_http_debug_logging()

        assert http.client.HTTPConnection.debuglevel == 0
        assert http.client.HTTPSConnection.debuglevel == 0
        assert "OCI_PYTHON_SDK_DEBUG" not in os.environ
        assert "OCI_SDK_DEBUG" not in os.environ

        connection = object.__new__(http.client.HTTPConnection)
        http.client.HTTPConnection.set_debuglevel(connection, 1)
        assert connection.debuglevel == 0
    finally:
        http.client.HTTPConnection.debuglevel = original_http_level
        http.client.HTTPSConnection.debuglevel = original_https_level


def test_remote_setup_uploads_executes_and_downloads_without_secret_paths(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "index.js").write_text("console.log('ok')", encoding="utf-8")
    (app / ".env").write_text("SECRET=value", encoding="utf-8")
    vault = Vault.empty()
    vault.put(
        "runner.oci.fusekit-test.ssh.private",
        "ssh_private_key",
        "oci",
        "runner key",
        "PRIVATE KEY",
    )
    workspace = OciWorkspace(
        id="fusekit-test",
        compartment_id="tenancy",
        availability_domain="AD-1",
        shape="VM.Standard3.Flex",
        ssh_user="ubuntu",
        public_ip="203.0.113.10",
    )
    calls: list[list[str]] = []

    def runner(
        command: list[str],
        *,
        input_text: str | None = None,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert input_text != "secret-passphrase" or "cat >" in command[-1]
        if stdout_path is not None:
            archive = tarfile.open(stdout_path, "w:gz")
            payload = tmp_path / "job.json"
            gates = tmp_path / "gates.json"
            gate_events = tmp_path / "gate_events.jsonl"
            checkpoints = tmp_path / "checkpoints.json"
            run_record = tmp_path / "run_record.json"
            vault_file = tmp_path / "fusekit.vault.json"
            audit = tmp_path / "audit.jsonl"
            receipt = tmp_path / "setup_receipt.json"
            verification = tmp_path / "verification_report.json"
            rollback = tmp_path / "rollback_plan.json"
            strategies = tmp_path / "provider_strategies.json"
            runner_readiness = tmp_path / "runner_readiness.json"
            payload.write_text("{}", encoding="utf-8")
            gates.write_text('{"gates":[]}', encoding="utf-8")
            gate_events.write_text(
                '{"event":"resume_requested","gate_id":"provider.test"}\n',
                encoding="utf-8",
            )
            checkpoints.write_text('{"checkpoints":[]}', encoding="utf-8")
            run_record.write_text(
                '{"schema_version":"fusekit.run-record.v1","id":"fk-test"}',
                encoding="utf-8",
            )
            vault_file.write_text("encrypted", encoding="utf-8")
            audit.write_text('{"event":"ok"}\n', encoding="utf-8")
            receipt.write_text('{"actions":[]}', encoding="utf-8")
            verification.write_text('{"checks":[]}', encoding="utf-8")
            rollback.write_text(
                '{"rollback":[{"action":"rollback.test","status":"planned"}]}',
                encoding="utf-8",
            )
            strategies.write_text('{"providers":[]}', encoding="utf-8")
            runner_readiness.write_text(
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
                encoding="utf-8",
            )
            archive.add(payload, arcname=".fusekit/job.json")
            archive.add(gates, arcname=".fusekit/gates.json")
            archive.add(gate_events, arcname=".fusekit/gate_events.jsonl")
            archive.add(checkpoints, arcname=".fusekit/checkpoints.json")
            archive.add(run_record, arcname=".fusekit/run_record.json")
            archive.add(vault_file, arcname=".fusekit/fusekit.vault.json")
            archive.add(audit, arcname=".fusekit/audit.jsonl")
            archive.add(receipt, arcname=".fusekit/setup_receipt.json")
            archive.add(verification, arcname=".fusekit/verification_report.json")
            archive.add(rollback, arcname=".fusekit/rollback_plan.json")
            archive.add(strategies, arcname=".fusekit/provider_strategies.json")
            archive.add(runner_readiness, arcname=".fusekit/runner_readiness.json")
            archive.close()
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    result = execute_remote_setup(
        workspace=workspace,
        vault=vault,
        app_path=app,
        local_output_dir=tmp_path / "out",
        passphrase="secret-passphrase",
        launch_args=("--github-repo", "owner/repo", "--infer-ui", "--visual-runner", "novnc"),
        runner=runner,
    )

    assert result["output_dir"] == str(tmp_path / "out")
    assert result["artifact_status"] == "complete"
    assert result["control_room_url"].startswith("http://203.0.113.10:8765/?token=")
    assert result["novnc_url"].startswith("http://203.0.113.10:6080/vnc.html?")
    assert "password=" not in result["novnc_url"]
    assert any(command[0] == "scp" for command in calls)
    assert any("ubuntu@203.0.113.10" in command for command in calls)
    assert not any("opc@203.0.113.10" in command for command in calls)
    assert any(command[0] == "ssh" and command[-1] == "true" for command in calls)
    assert any("IdentitiesOnly=yes" in command for command in calls if command[0] == "ssh")
    assert not any(
        option.startswith("PubkeyAcceptedAlgorithms=")
        for command in calls
        if command[0] == "ssh"
        for option in command
    )
    assert any(
        "cloud-init did not finish before FuseKit runner readiness timeout." in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any("cloud-init-output tail" in command[-1] for command in calls if command[0] == "ssh")
    assert any(
        "fusekit-runner-verify missing; cloud-init bootstrap did not install runner helpers."
        in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        "[ ! -x /usr/local/sbin/fusekit-runner-verify ]" in command[-1]
        and "/usr/local/sbin/fusekit-runner-verify" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        command[0] == "scp" and command[-1].endswith("/.fusekit/fusekit.vault.json")
        for command in calls
    )
    assert any(
        command[0] == "ssh"
        and "runner-readiness.json" in command[-1]
        and ".fusekit/runner_readiness.json" in command[-1]
        for command in calls
    )
    assert any("fusekit launch . --runner local --yes" in command[-1] for command in calls)
    assert any(
        "--github-repo owner/repo --infer-ui --visual-runner novnc" in command[-1]
        for command in calls
    )
    assert any("/usr/local/sbin/fusekit-visual-start" in command[-1] for command in calls)
    assert any(
        "FUSEKIT_PROVIDER_BROWSER_PROFILE=/var/lib/fusekit-runner/visual/chrome-provider-profile"
        in command[-1]
        and "/usr/local/sbin/fusekit-visual-start" in command[-1]
        and "fusekit control-room --serve" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        "FUSEKIT_PROVIDER_BROWSER_PROFILE=/var/lib/fusekit-runner/visual/chrome-provider-profile"
        in command[-1]
        and "fusekit launch . --runner local --yes" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        "curl -fsS http://127.0.0.1:6080/vnc.html" in command[-1] and "exit 45" in command[-1]
        for command in calls
    )
    assert any("fusekit control-room --serve" in command[-1] for command in calls)
    assert any("export DISPLAY=:99" in command[-1] for command in calls)
    assert any(
        "trap 'rm -f /var/lib/fusekit-runner/passphrase' EXIT" in command[-1] for command in calls
    )
    assert any(
        "FUSEKIT_OPENCLAW_BIN=/opt/fusekit-openclaw/bin/openclaw" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        "FUSEKIT_HOME=/var/lib/fusekit-runner/fusekit-runtime" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        "FUSEKIT_OPENCLAW_HOME_MODE=default" in command[-1] and "unset OPENCLAW_HOME" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        "openclaw config set browser.executablePath" in command[-1]
        and "openclaw gateway run --allow-unconfigured --auth none --bind loopback --port 19002"
        in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        '"status": "ready"' in command[-1]
        and '"provider_browser_profile": "/var/lib/fusekit-runner/visual/chrome-provider-profile"'
        in command[-1]
        and "/var/lib/fusekit-runner/app/.fusekit/visual.json" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert not any(
        "openclaw gateway run" in command[-1] and "--bind 0.0.0.0" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert (tmp_path / "out" / ".fusekit" / "gates.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "gate_events.jsonl").exists()
    assert (tmp_path / "out" / ".fusekit" / "checkpoints.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "run_record.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "fusekit.vault.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "audit.jsonl").exists()
    assert (tmp_path / "out" / ".fusekit" / "setup_receipt.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "verification_report.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "rollback_plan.json").exists()
    assert (tmp_path / "out" / ".fusekit" / "provider_strategies.json").exists()
    assert any(".fusekit/gates.json" in command[-1] for command in calls if command[0] == "ssh")
    assert any(
        ".fusekit/gate_events.jsonl" in command[-1] for command in calls if command[0] == "ssh"
    )
    assert any(
        ".fusekit/checkpoints.json" in command[-1] for command in calls if command[0] == "ssh"
    )
    assert any(
        ".fusekit/run_record.json" in command[-1] for command in calls if command[0] == "ssh"
    )
    assert any(
        ".fusekit/verification_report.json" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert any(
        ".fusekit/rollback_plan.json" in command[-1] for command in calls if command[0] == "ssh"
    )
    assert any(
        ".fusekit/provider_strategies.json" in command[-1]
        for command in calls
        if command[0] == "ssh"
    )
    assert not any(
        ".fusekit/visual.json" in command[-1]
        for command in calls
        if command[0] == "ssh" and "tar -czf -" in command[-1]
    )
    assert any('[ -n "$existing" ] || exit 44' in command[-1] for command in calls)


def test_remote_detonation_cleans_visual_and_control_processes() -> None:
    vault = Vault.empty()
    vault.put(
        "runner.oci.fusekit-test.ssh.private",
        "ssh_private_key",
        "oci",
        "runner key",
        "PRIVATE KEY",
    )
    workspace = OciWorkspace(
        id="fusekit-test",
        compartment_id="tenancy",
        availability_domain="AD-1",
        shape="VM.Standard3.Flex",
        ssh_user="ubuntu",
        public_ip="203.0.113.10",
    )
    calls: list[list[str]] = []

    def runner(
        command: list[str],
        *,
        input_text: str | None = None,
        stdout_path: Path | None = None,
    ) -> subprocess.CompletedProcess[str]:
        assert input_text is None
        assert stdout_path is None
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    proof = detonate_remote_worker(workspace=workspace, vault=vault, runner=runner)

    assert len(calls) == 1
    command = calls[0][-1]
    assert proof["schema_version"] == "fusekit.remote-worker-cleanup.v1"
    assert proof["status"] == "detonated"
    assert proof["host_machine_state_required"] is False
    assert "/var/lib/fusekit-runner/app" in proof["paths"]
    assert "/var/lib/fusekit-runner/visual" in proof["paths"]
    assert "[o]penclaw gateway run.*19002" in proof["process_patterns"]
    assert "sudo -n sh -c" in command
    assert "|| sh -c" in command
    assert "[f]usekit control-room --serve" in command
    assert "[o]penclaw gateway run.*19002" in command
    assert "[c]hrome-linux.*/chrome" in command
    assert "[w]ebsockify.*6080" in command
    assert "[x]11vnc.*5900" in command
    assert "[X]vfb :99" in command
    assert "/var/lib/fusekit-runner/visual" in command
    assert "/var/lib/fusekit-runner/control-room.log" in command
    assert "/var/lib/fusekit-runner/openclaw-gateway.log" in command


def test_remote_artifact_extraction_rejects_invalid_archive(tmp_path) -> None:
    from fusekit.errors import FuseKitError
    from fusekit.runner.remote import _extract_artifacts

    archive = tmp_path / "bad.tar.gz"
    archive.write_text("not a tarball", encoding="utf-8")

    try:
        _extract_artifacts(archive, tmp_path / "out")
    except FuseKitError as exc:
        assert "archive could not be read" in str(exc)
    else:
        raise AssertionError("invalid remote artifact archive should fail")


def test_remote_artifact_bundle_requires_detonation_survivors(tmp_path) -> None:
    from fusekit.errors import FuseKitError
    from fusekit.runner.remote import _validate_artifact_bundle

    fusekit_dir = tmp_path / ".fusekit"
    fusekit_dir.mkdir()
    for name in (
        "fusekit.vault.json",
        "job.json",
        "checkpoints.json",
        "verification_report.json",
        "rollback_plan.json",
        "provider_strategies.json",
    ):
        (fusekit_dir / name).write_text("{}", encoding="utf-8")

    with pytest.raises(FuseKitError, match="audit.jsonl"):
        _validate_artifact_bundle(tmp_path)


def test_cloud_shell_style_oci_config_uses_delegation_token_signer(
    tmp_path,
    monkeypatch,
) -> None:
    import oci

    class FakeSigner:
        tenancy_id = "ocid1.tenancy.oc1..cloudshell"
        region = "us-ashburn-1"

    def local_from_file(path: str) -> dict[str, str]:
        assert path == str(tmp_path / "config")
        return {
            "authentication_type": "instance_principal",
            "delegation_token_file": str(tmp_path / "delegation-token"),
            "region": "us-ashburn-1",
        }

    def local_get_signer_from_authentication_type(config: dict[str, str]) -> FakeSigner:
        assert config["authentication_type"] == "instance_principal"
        return FakeSigner()

    monkeypatch.setattr(oci.config, "from_file", local_from_file)
    monkeypatch.setattr(
        oci.util,
        "get_signer_from_authentication_type",
        local_get_signer_from_authentication_type,
    )

    auth = _load_oci_config_file(tmp_path / "config")

    assert auth.config["tenancy"] == "ocid1.tenancy.oc1..cloudshell"
    assert auth.config["region"] == "us-ashburn-1"
    assert isinstance(auth.signer, FakeSigner)


def test_oci_config_loader_drops_none_pass_phrase(
    tmp_path,
    monkeypatch,
) -> None:
    import oci

    def local_from_file(path: str) -> dict[str, object]:
        assert path == str(tmp_path / "config")
        return {
            "user": "ocid1.user.oc1..example",
            "fingerprint": "aa:bb",
            "tenancy": "ocid1.tenancy.oc1..example",
            "region": "us-phoenix-1",
            "key_file": str(tmp_path / "key.pem"),
            "pass_phrase": None,
        }

    monkeypatch.setattr(oci.config, "from_file", local_from_file)

    auth = _load_oci_config_file(tmp_path / "config")

    assert auth.config["key_file"] == str(tmp_path / "key.pem")
    assert "pass_phrase" not in auth.config


def test_oci_client_kwargs_omits_absent_signer() -> None:
    signer = object()

    assert _oci_client_kwargs(OciAuth({"region": "us-phoenix-1"})) == {}
    assert _oci_client_kwargs(OciAuth({"region": "us-phoenix-1"}, signer)) == {"signer": signer}


def test_secret_leak_scanner_reports_locations_without_values(tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    secret = "redaction_sentinel_value_abcdefghijklmnopqrstuvwxyz123456"
    (app / "config.txt").write_text(f"API_KEY={secret}\n", encoding="utf-8")

    findings = scan_for_secret_leaks(app)

    assert findings[0].path == "config.txt"
    assert findings[0].line == 1
    assert secret not in str([finding.to_dict() for finding in findings])


def test_secret_leak_scanner_ignores_references_but_keeps_strong_signatures(
    tmp_path,
) -> None:
    app = tmp_path / "app"
    app.mkdir()
    (app / "references.txt").write_text(
        "\n".join(
            (
                "export const secret = process.env.WEBHOOK_SECRET;",
                "--secret APP_API_KEY=env:APP_API_KEY",
                "token = os.environ.get('GITHUB_TOKEN')",
                "fixture_secret = 'hidden-test-placeholder'",
            )
        ),
        encoding="utf-8",
    )
    (app / "real.txt").write_text(
        "\n".join(
            (
                "API_KEY=live_plaintext_value_abcdefghijklmnopqrstuvwxyz",
                "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456",
            )
        ),
        encoding="utf-8",
    )

    findings = scan_for_secret_leaks(app)

    assert [finding.path for finding in findings] == ["real.txt", "real.txt"]
    assert {finding.kind for finding in findings} == {"secret_assignment", "github_token"}


def test_rollback_and_start_over_are_redacted_and_preserve_vault(tmp_path) -> None:
    app = tmp_path / "app"
    fusekit = app / ".fusekit"
    fusekit.mkdir(parents=True)
    (fusekit / "setup_receipt.json").write_text(
        json.dumps(
            {
                "actions": [
                    {"action": "github.secret", "status": "ok"},
                    {"action": "vercel.env", "status": "ok"},
                    {"action": "resend.domain", "status": "ok"},
                    {"action": "dns.propose", "status": "ok"},
                    {"action": "dns.apply", "status": "ok"},
                ]
            }
        ),
        encoding="utf-8",
    )
    (fusekit / "job.json").write_text("{}", encoding="utf-8")
    (fusekit / "fusekit.vault.json").write_text("encrypted", encoding="utf-8")

    rollback = plan_rollback(fusekit / "setup_receipt.json")
    result = start_over(app)

    assert any(action.action == "rollback.github.secret" for action in rollback)
    assert any(action.action == "rollback.resend.domain" for action in rollback)
    assert any(action.action == "rollback.cloudflare.dns" for action in rollback)
    assert sum(action.action == "rollback.cloudflare.dns" for action in rollback) == 1
    assert "job.json" in " ".join(result["removed"])
    assert (fusekit / "fusekit.vault.json").exists()


def test_remote_loop_marks_job_done(monkeypatch, tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    fusekit = app / ".fusekit"
    fusekit.mkdir()
    (fusekit / "verification_report.json").write_text(
        '{"checks":[{"provider":"live_app","check":"live_url_healthy","status":"passed"}]}',
        encoding="utf-8",
    )
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("passphrase", encoding="utf-8")
    job_path = tmp_path / "job.json"

    def local_run(
        command: list[str],
        *,
        capture_output: bool,
        check: bool,
        text: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", local_run)

    assert run_remote_loop(app_path=app, job_state=job_path, passphrase_file=passphrase) == 0
    job = JobState.load(job_path)
    assert any(step.id == "setup.execute" and step.status == "done" for step in job.steps)
    assert any(step.id == "verify.live" and step.status == "done" for step in job.steps)


def test_remote_loop_rejects_missing_safe_verification(monkeypatch, tmp_path) -> None:
    app = tmp_path / "app"
    app.mkdir()
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("passphrase", encoding="utf-8")
    job_path = tmp_path / "job.json"

    def local_run(
        command: list[str],
        *,
        capture_output: bool,
        check: bool,
        text: bool,
        timeout: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", local_run)

    with pytest.raises(FuseKitError, match="safe verification"):
        run_remote_loop(app_path=app, job_state=job_path, passphrase_file=passphrase)
    job = JobState.load(job_path)
    assert any(step.id == "verify.live" and step.status == "failed" for step in job.steps)


def test_execute_native_rollback_calls_provider_deletes(monkeypatch, tmp_path) -> None:
    receipt = tmp_path / "receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "actions": [
                    {"action": "github.secret", "details": {"repo": "o/r", "secret": "APP_KEY"}},
                    {"action": "github.deploy_key", "details": {"repo": "o/r", "key_id": "42"}},
                ]
            }
        ),
        encoding="utf-8",
    )
    vault = Vault.empty()
    vault.put(
        "provider.github.token",
        "provider_token",
        "github",
        "token",
        "test-github-token-hidden",
    )
    calls: list[tuple[str, str, str]] = []

    class FakeGitHubProvider:
        def __init__(self, token: str) -> None:
            assert token == "test-github-token-hidden"

        def delete_repo_secret(self, repo: str, name: str) -> dict[str, object]:
            calls.append(("secret", repo, name))
            return {}

        def delete_deploy_key(self, repo: str, key_id: str) -> dict[str, object]:
            calls.append(("key", repo, key_id))
            return {}

    monkeypatch.setattr("fusekit.providers.github.GitHubProvider", FakeGitHubProvider)

    actions = execute_native_rollback(receipt, vault)

    assert ("secret", "o/r", "APP_KEY") in calls
    assert ("key", "o/r", "42") in calls
    assert any(action.status == "done" for action in actions)
