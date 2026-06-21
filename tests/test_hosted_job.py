from __future__ import annotations

import json
import re

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted import (
    advance_hosted_launch_job,
    apply_hosted_worker_proof,
    build_hosted_launch_job,
    build_hosted_worker_contract,
    claim_hosted_launch_job,
    create_hosted_job_token,
    hosted_job_action_receipt,
    hosted_launch_job_from_dict,
    hosted_proof_receipt,
    hosted_worker_claim_receipt,
    hosted_worker_proof_receipt,
    hosted_worker_request,
    render_hosted_control_room,
    render_hosted_proof_receipt,
    verify_hosted_job_token,
)
from fusekit.hosted.launcher import build_hosted_launch_plan
from fusekit.manifest import ServiceRequirement, SetupManifest


def _plan():
    manifest = SetupManifest(
        app_name="job-demo",
        required_env=("RESEND_API_KEY",),
        services=(
            ServiceRequirement(
                provider="github",
                kind="repository",
                name="source",
                capabilities=("repo_secrets", "deploy_keys"),
                secrets=("GITHUB_TOKEN",),
            ),
            ServiceRequirement(
                provider="vercel",
                kind="deployment",
                name="web",
                capabilities=("project", "env", "deploy"),
                secrets=("VERCEL_TOKEN",),
            ),
        ),
    )
    return build_hosted_launch_plan(manifest, github_source="https://github.com/example/job-demo")


def test_hosted_launch_job_is_public_safe_and_trust_complete() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    serialized = json.dumps(payload)

    assert payload["schema_version"] == "fusekit.hosted-job.v1"
    assert payload["job_id"] == "hosted-test"
    assert payload["status"] == "waiting_for_worker"
    assert "Live URL verification" in payload["proof"]
    assert "Show rollback metadata before risky changes." in payload["rollback"]
    assert "Write detonation receipt before launch is considered complete." in payload["detonation"]
    assert payload["worker_contract"]["schema_version"] == "fusekit.hosted-worker-contract.v1"
    assert payload["worker_contract"]["lane"] == "hosted-fusekit-worker"
    assert payload["worker_contract"]["github_installation_id"] is None
    assert "contents:read" in " ".join(payload["worker_contract"]["permission_boundary"])
    assert ".fusekit/run_record.json" in payload["worker_contract"]["required_artifacts"]
    assert ".fusekit/workspace_detonation.json" in payload["worker_contract"]["required_artifacts"]
    assert any(step["id"] == "provider.gates" for step in payload["steps"])
    assert any(step["id"] == "detonate.worker" for step in payload["steps"])
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_proof_receipt_is_redacted_and_not_prematurely_complete() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    receipt = hosted_proof_receipt(job)
    html = render_hosted_proof_receipt(job, job_token="signed-public-job")
    serialized = json.dumps(receipt) + html

    assert receipt["schema_version"] == "fusekit.hosted-proof-receipt.v1"
    assert receipt["completion_ready"] is False
    assert "Completion is not yet proven" in receipt["completion_statement"]
    assert ".fusekit/run_record.json" in receipt["required_artifacts"]
    assert ".fusekit/workspace_detonation.json" in receipt["required_artifacts"]
    assert any("MFA" in gate for gate in receipt["provider_gates"])
    assert any("contents:read" in item for item in receipt["permission_boundary"])
    assert "github.authorize" in receipt["approved_actions"]
    assert any("Request rollback" in item["control"] for item in receipt["reversal_playbook"])
    assert any("Request detonation" in item["control"] for item in receipt["reversal_playbook"])
    assert any(
        "GitHub App installation" in item["control"]
        for item in receipt["reversal_playbook"]
    )
    assert "Proof receipt." in html
    assert "Permission boundary" in html
    assert "contents:read" in html
    assert "Approved actions" in html
    assert "vercel.deploy_verify" in html
    assert "fresh visible plan" in html
    assert "Provider gates" in html
    assert "These gates stay provider-owned and human-approved" in html
    assert "MFA" in html
    assert "Reversible setup" in html
    assert "Reversal playbook" in html
    assert "Request rollback" in html
    assert "Request detonation" in html
    assert "GitHub App installation" in html
    assert "Back to control room" in html
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_request_binds_live_acceptance_and_no_secret_policy() -> None:
    job = build_hosted_launch_job(
        _plan(),
        github_installation_id=42,
        job_id="hosted-test",
        now=1_700_000_000,
    )
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    request = hosted_worker_request(started, now=1_700_000_002)
    serialized = json.dumps(request)

    assert request["schema_version"] == "fusekit.hosted-worker-request.v1"
    assert request["job_id"] == "hosted-test"
    assert request["github_source"] == "https://github.com/example/job-demo"
    assert request["claim_policy"]["runner"] == "hosted-fusekit-worker"
    assert request["claim_policy"]["github_installation_id"] == 42
    assert request["claim_policy"]["mode"] == "live"
    assert request["claim_policy"]["remote_artifacts_required"] is True
    assert request["claim_policy"]["recording_required"] is True
    assert request["acceptance_gate"] == {
        "mode": "live",
        "remote_artifacts": ".fusekit/remote-artifacts",
        "require_recording": True,
        "command": (
            "fusekit acceptance run <app> --mode live "
            "--remote-artifacts <app>/.fusekit/remote-artifacts --require-recording"
        ),
    }
    assert "retrieved_remote_artifacts" in request["completion_requires"]
    assert "detonation_receipt" in request["completion_requires"]
    assert ".fusekit/run_record.json" in request["required_artifacts"]
    assert ".fusekit/workspace_detonation.json" in request["required_artifacts"]
    assert any("Do not bypass MFA" in item for item in request["prohibited"])
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "VERCEL_TOKEN" not in serialized


def test_hosted_worker_claim_updates_job_and_writes_redacted_receipt() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(
        started,
        worker_id="worker-01<script>",
        now=1_700_000_002,
    )
    receipt = hosted_worker_claim_receipt(
        claimed,
        worker_id="worker-01<script>",
        now=1_700_000_003,
    )
    steps = {step["id"]: step for step in claimed.to_dict()["steps"]}
    serialized = json.dumps(receipt) + json.dumps(claimed.to_dict())

    assert claimed.status == "worker_claimed"
    assert steps["worker.prepare"]["status"] == "done"
    assert "worker-01script" in steps["worker.prepare"]["proof"]
    assert steps["provider.gates"]["status"] == "waiting"
    assert steps["setup.execute"]["status"] == "waiting"
    assert receipt["schema_version"] == "fusekit.hosted-worker-claim.v1"
    assert receipt["job_id"] == "hosted-test"
    assert receipt["worker_id"] == "worker-01script"
    assert "provider_gate_events" in receipt["next_required_proof"]
    assert "detonation_receipt" in receipt["next_required_proof"]
    assert "<script>" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "ghs_" not in serialized


def test_hosted_worker_claim_rejects_unstarted_or_terminal_jobs() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)

    with pytest.raises(ValueError):
        claim_hosted_launch_job(job, worker_id="worker-01")

    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    rollback = advance_hosted_launch_job(started, "rollback", now=1_700_000_002)
    with pytest.raises(ValueError):
        claim_hosted_launch_job(rollback, worker_id="worker-01")


def _proof_payload(
    *,
    complete: bool,
    note: str = "",
    completed_artifacts: list[str] | None = None,
) -> dict[str, object]:
    evidence = {
        "live_url": complete,
        "provider_verifiers": complete,
        "dns_propagation": complete,
        "rollback_metadata": complete,
        "retrieved_remote_artifacts": complete,
        "run_record": complete,
        "detonation_receipt": complete,
        "live_acceptance_report": complete,
        "recording": complete,
    }
    return {
        "schema_version": "fusekit.hosted-worker-proof.v1",
        "evidence": evidence,
        "completed_artifacts": completed_artifacts or [],
        "note": note,
    }


def test_hosted_worker_proof_submission_updates_partial_job_without_completion() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="worker-01", now=1_700_000_002)
    updated, receipt = apply_hosted_worker_proof(
        claimed,
        _proof_payload(
            complete=False,
            completed_artifacts=[
                ".fusekit/job.json",
                ".fusekit/run_record.json",
            ],
            note="Provider gates are waiting.",
        ),
        worker_id="worker-01",
        now=1_700_000_003,
    )
    steps = {step["id"]: step for step in updated.to_dict()["steps"]}
    serialized = json.dumps(receipt) + json.dumps(updated.to_dict())

    assert updated.status == "proof_submitted"
    assert receipt["schema_version"] == "fusekit.hosted-worker-proof-receipt.v1"
    assert receipt["completion_ready"] is False
    assert ".fusekit/acceptance_report.json" in receipt["missing_artifacts"]
    assert steps["setup.execute"]["status"] == "running"
    assert steps["proof.collect"]["status"] == "waiting"
    assert steps["rollback.ready"]["status"] == "waiting"
    assert steps["detonate.worker"]["status"] == "waiting"
    assert "Provider gates are waiting." in receipt["note"]
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_proof_submission_can_mark_complete_only_with_full_evidence() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="worker-01", now=1_700_000_002)
    updated, receipt = apply_hosted_worker_proof(
        claimed,
        _proof_payload(
            complete=True,
            completed_artifacts=list(claimed.worker_contract.required_artifacts),
            note="Live proof passed.",
        ),
        worker_id="worker-01",
        now=1_700_000_003,
    )
    proof_receipt = hosted_proof_receipt(updated)
    steps = {step["id"]: step for step in updated.to_dict()["steps"]}

    assert updated.status == "complete"
    assert receipt["completion_ready"] is True
    assert receipt["missing_artifacts"] == []
    assert proof_receipt["completion_ready"] is True
    assert steps["provider.gates"]["status"] == "done"
    assert steps["setup.execute"]["status"] == "done"
    assert steps["proof.collect"]["status"] == "done"
    assert steps["rollback.ready"]["status"] == "done"
    assert steps["detonate.worker"]["status"] == "done"


def test_hosted_worker_proof_rejects_unknown_artifact_and_secret_text() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    claimed = claim_hosted_launch_job(started, worker_id="worker-01", now=1_700_000_002)

    with pytest.raises(ValueError):
        hosted_worker_proof_receipt(
            claimed,
            _proof_payload(complete=False, completed_artifacts=[".fusekit/not-real.json"]),
            worker_id="worker-01",
        )

    with pytest.raises(ValueError):
        hosted_worker_proof_receipt(
            claimed,
            _proof_payload(
                complete=False,
                note="Authorization: Bearer raw-provider-token",
            ),
            worker_id="worker-01",
        )


def test_hosted_control_room_embeds_redacted_job_json() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    action_receipt = hosted_job_action_receipt(started, action="start", now=1_700_000_002)
    html = render_hosted_control_room(
        started,
        action_receipt=action_receipt,
        dispatch_receipt={
            "schema_version": "fusekit.hosted-worker-dispatch.v1",
            "action": "start",
            "dispatched": False,
            "reason": "worker_dispatch_url_not_configured",
        },
    )
    match = re.search(
        r'<script id="fusekit-hosted-job" type="application/json">(.*?)</script>',
        html,
        flags=re.DOTALL,
    )

    assert "Hosted launch control room." in html
    assert "Worker contract" in html
    assert "Redacted proof" in html
    assert "Reversible setup" in html
    assert "Request rollback" in html
    assert "Request detonation" in html
    assert "GitHub App installation" in html
    assert "Permission boundary" in html
    assert "backend worker" in html
    assert "Approved actions" in html
    assert "github.authorize" in html
    assert "drift requires a fresh approval" in html
    assert "Provider gates" in html
    assert "human-owned" in html
    assert ".fusekit/run_record.json" in html
    assert ".fusekit/workspace_detonation.json" in html
    assert "Latest protected action: start" in html
    assert "Next proof required" in html
    assert "Worker dispatch: not configured" in html
    assert "Detonation" in html
    assert match is not None
    payload = json.loads(match.group(1).replace("&quot;", '"'))
    assert payload["schema_version"] == "fusekit.hosted-job.v1"
    assert payload["latest_action_receipt"]["action"] == "start"
    assert payload["worker_dispatch"]["reason"] == "worker_dispatch_url_not_configured"
    assert any("Request rollback" in item["control"] for item in payload["reversal_playbook"])
    assert any(
        "GitHub App installation" in item["control"]
        for item in payload["reversal_playbook"]
    )
    assert any(
        "selected repository" in item
        for item in payload["worker_contract"]["permission_boundary"]
    )
    assert "vercel.deploy_verify" in payload["worker_contract"]["approved_actions"]
    assert any("MFA" in gate for gate in payload["worker_contract"]["gates"])
    assert payload["worker_contract"]["schema_version"] == "fusekit.hosted-worker-contract.v1"
    assert "ghs_" not in json.dumps(payload)


def test_hosted_launch_job_actions_record_truthful_waiting_states() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)

    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    rollback = advance_hosted_launch_job(started, "rollback", now=1_700_000_002)
    detonation = advance_hosted_launch_job(rollback, "detonate", now=1_700_000_003)
    steps = {step["id"]: step for step in detonation.to_dict()["steps"]}

    assert started.status == "waiting_for_provider_gates"
    assert rollback.status == "rollback_requested"
    assert detonation.status == "detonation_requested"
    assert steps["provider.gates"]["status"] == "waiting"
    assert steps["rollback.ready"]["status"] == "waiting"
    assert steps["detonate.worker"]["status"] == "waiting"
    assert "waiting" in steps["detonate.worker"]["proof"].lower()
    assert detonation.worker_contract == job.worker_contract


def test_hosted_job_action_receipts_are_redacted_and_proof_oriented() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    rollback = advance_hosted_launch_job(started, "rollback", now=1_700_000_002)
    detonation = advance_hosted_launch_job(rollback, "detonate", now=1_700_000_003)

    start_receipt = hosted_job_action_receipt(started, action="start", now=1_700_000_004)
    rollback_receipt = hosted_job_action_receipt(
        rollback,
        action="rollback",
        now=1_700_000_005,
    )
    detonation_receipt = hosted_job_action_receipt(
        detonation,
        action="detonate",
        now=1_700_000_006,
    )
    serialized = (
        json.dumps(start_receipt)
        + json.dumps(rollback_receipt)
        + json.dumps(detonation_receipt)
    )

    assert start_receipt["schema_version"] == "fusekit.hosted-job-action-receipt.v1"
    assert start_receipt["next_required_proof"] == [
        "worker_claim",
        "provider_gate_events",
        "live_acceptance_report",
        "retrieved_remote_artifacts",
        "rollback_metadata",
        "detonation_receipt",
    ]
    assert rollback_receipt["status"] == "rollback_requested"
    assert "rollback_execution_receipt" in rollback_receipt["next_required_proof"]
    assert detonation_receipt["status"] == "detonation_requested"
    assert "scratch_state_destroyed" in detonation_receipt["next_required_proof"]
    assert "MFA" in rollback_receipt["safeguards"][0]
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "VERCEL_TOKEN" not in serialized


def test_hosted_worker_contract_is_public_and_binds_approved_plan() -> None:
    contract = build_hosted_worker_contract(_plan(), github_installation_id=42)
    payload = contract.to_dict()
    serialized = json.dumps(payload)

    assert payload["schema_version"] == "fusekit.hosted-worker-contract.v1"
    assert payload["github_source"] == "https://github.com/example/job-demo"
    assert payload["github_installation_id"] == 42
    assert "Installation tokens are never embedded" in payload["source_token_policy"]
    assert payload["providers"] == ["github", "vercel"]
    assert payload["required_env"] == ["RESEND_API_KEY"]
    assert any("contents:read" in item for item in payload["permission_boundary"])
    assert any("backend worker" in item for item in payload["permission_boundary"])
    assert payload["approved_actions"]
    assert ".fusekit/acceptance_report.json" in payload["required_artifacts"]
    assert any("Live acceptance" in guarantee for guarantee in payload["guarantees"])
    assert any("MFA" in gate for gate in payload["gates"])
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "VERCEL_TOKEN" not in serialized


def test_hosted_worker_contract_decodes_older_public_payload_without_boundary() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    payload = job.to_dict()
    worker_contract = payload["worker_contract"]
    assert isinstance(worker_contract, dict)
    worker_contract.pop("permission_boundary")

    decoded = hosted_launch_job_from_dict(payload)

    assert decoded.worker_contract.permission_boundary == ()


def test_hosted_job_token_round_trips_redacted_public_job() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    token = create_hosted_job_token("job-secret", job, now=1_700_000_001)
    verified = verify_hosted_job_token("job-secret", token, now=1_700_000_002)
    decoded = hosted_launch_job_from_dict(job.to_dict())
    serialized = json.dumps(verified.to_dict())

    assert verified == job
    assert decoded == job
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_job_token_rejects_tampering_and_expiry() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    token = create_hosted_job_token("job-secret", job, now=1_700_000_001)
    payload, signature = token.split(".", 1)

    with pytest.raises(FuseKitError):
        verify_hosted_job_token("job-secret", f"{payload}x.{signature}", now=1_700_000_002)

    with pytest.raises(FuseKitError):
        verify_hosted_job_token(
            "job-secret",
            token,
            now=1_700_100_000,
            ttl_seconds=60,
        )
