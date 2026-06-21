from __future__ import annotations

import json
import re

import pytest

from fusekit.errors import FuseKitError
from fusekit.hosted import (
    advance_hosted_launch_job,
    build_hosted_launch_job,
    build_hosted_worker_contract,
    create_hosted_job_token,
    hosted_launch_job_from_dict,
    hosted_proof_receipt,
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
    assert "Proof receipt." in html
    assert "Reversible setup" in html
    assert "Back to control room" in html
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized


def test_hosted_worker_request_binds_live_acceptance_and_no_secret_policy() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    started = advance_hosted_launch_job(job, "start", now=1_700_000_001)
    request = hosted_worker_request(started, now=1_700_000_002)
    serialized = json.dumps(request)

    assert request["schema_version"] == "fusekit.hosted-worker-request.v1"
    assert request["job_id"] == "hosted-test"
    assert request["github_source"] == "https://github.com/example/job-demo"
    assert request["claim_policy"]["runner"] == "hosted-fusekit-worker"
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


def test_hosted_control_room_embeds_redacted_job_json() -> None:
    job = build_hosted_launch_job(_plan(), job_id="hosted-test", now=1_700_000_000)
    html = render_hosted_control_room(job)
    match = re.search(
        r'<script id="fusekit-hosted-job" type="application/json">(.*?)</script>',
        html,
        flags=re.DOTALL,
    )

    assert "Hosted launch control room." in html
    assert "Worker contract" in html
    assert "Redacted proof" in html
    assert "Reversible setup" in html
    assert ".fusekit/run_record.json" in html
    assert ".fusekit/workspace_detonation.json" in html
    assert "Detonation" in html
    assert match is not None
    payload = json.loads(match.group(1).replace("&quot;", '"'))
    assert payload["schema_version"] == "fusekit.hosted-job.v1"
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


def test_hosted_worker_contract_is_public_and_binds_approved_plan() -> None:
    contract = build_hosted_worker_contract(_plan())
    payload = contract.to_dict()
    serialized = json.dumps(payload)

    assert payload["schema_version"] == "fusekit.hosted-worker-contract.v1"
    assert payload["github_source"] == "https://github.com/example/job-demo"
    assert payload["providers"] == ["github", "vercel"]
    assert payload["required_env"] == ["RESEND_API_KEY"]
    assert payload["approved_actions"]
    assert ".fusekit/acceptance_report.json" in payload["required_artifacts"]
    assert any("Live acceptance" in guarantee for guarantee in payload["guarantees"])
    assert any("MFA" in gate for gate in payload["gates"])
    assert "ghs_" not in serialized
    assert "PRIVATE KEY" not in serialized
    assert "VERCEL_TOKEN" not in serialized


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
